"""Ollama Redaction Boundary Verification Runner for PRIVGUARD AI.

Moon Sanctum Labs - Decode. Build. Evolve.
Lead Developer: ANIKET NANDI (Kolkata, IST)

Demonstrates that when PRIVGUARD connects to a real local LLM (Ollama llama3.2:3b),
the actual HTTP request crossing the network socket into Ollama is completely redacted:
1. Client -> Gateway (:gateway_port)
2. Gateway -> Capturing Proxy (:proxy_port) -> Ollama (:11434)
3. Capturing Proxy inspects and asserts exact raw payload delivered to Ollama.
4. Ollama generates completion with llama3.2:3b.
5. Gateway inspects model response and returns to client.
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("privguard.ollama_boundary")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"

TEST_API_KEY = "pg_live_ollama_boundary_test_key"
OLLAMA_REAL_URL = "http://127.0.0.1:11434"
TARGET_MODEL = "llama3.2:3b"


def find_free_port() -> int:
    """Finds an unused TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s.getsockname()[1]


def wait_for_url(url: str, timeout_seconds: float = 15.0) -> bool:
    """Polls a URL until it responds with HTTP 200 or timeout is reached."""
    start = time.time()
    while time.time() - start < timeout_seconds:
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.get(url)
                if res.status_code == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


async def seed_test_database(db_url: str):
    """Initializes schema and seeds test application record."""
    sys.path.insert(0, str(BACKEND_DIR))
    from app.core.security import hash_api_key
    from app.database.connection import AsyncSessionLocal, init_db
    from app.database.models import Application

    await init_db()
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        stmt = select(Application).where(Application.id == "ollama_qual_app")
        res = await db.execute(stmt)
        if not res.scalar_one_or_none():
            app_rec = Application(
                id="ollama_qual_app",
                name="Ollama Boundary Qualification App",
                api_key_hash=hash_api_key(TEST_API_KEY),
                tenant_id="msl_ollama_tenant",
                is_active=True,
            )
            db.add(app_rec)
            await db.commit()


# Helper script for capturing proxy
PROXY_SCRIPT_CODE = '''"""Inline capturing reverse proxy between Gateway and Ollama."""
import argparse
import json
import logging
from typing import Any, Dict, List
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CAPTURING_PROXY] %(message)s")
logger = logging.getLogger("capturing_proxy")

app = FastAPI(title="PRIVGUARD Ollama Capturing Test Proxy")
captured_payloads: List[Dict[str, Any]] = []
TARGET_OLLAMA = "http://127.0.0.1:11434"

@app.get("/health")
async def health():
    return {"status": "HEALTHY"}

@app.get("/captured")
async def get_captured():
    return JSONResponse(content={"payloads": captured_payloads, "count": len(captured_payloads)})

@app.post("/v1/chat/completions")
async def proxy_completions(request: Request):
    body = await request.json()
    captured_payloads.append(body)
    logger.info("CAPTURED HTTP REQUEST TO OLLAMA: %d messages", len(body.get("messages", [])))

    # Relay to real Ollama service
    async with httpx.AsyncClient(timeout=45.0) as client:
        ollama_res = await client.post(
            f"{TARGET_OLLAMA}/v1/chat/completions",
            json=body,
            headers={"Content-Type": "application/json"},
        )
        return Response(
            content=ollama_res.content,
            status_code=ollama_res.status_code,
            headers=dict(ollama_res.headers),
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
'''


def run_ollama_redaction_boundary_test() -> Dict[str, Any]:
    logger.info("================================================================================")
    logger.info("  PRIVGUARD AI — OLLAMA REDACTION BOUNDARY QUALIFICATION")
    logger.info("  Agency: Moon Sanctum Labs — Decode. Build. Evolve.")
    logger.info("================================================================================")

    # 1. Verify Ollama availability
    logger.info("Probing local Ollama service at %s...", OLLAMA_REAL_URL)
    try:
        with httpx.Client(timeout=3.0) as client:
            tags_res = client.get(f"{OLLAMA_REAL_URL}/api/tags")
            if tags_res.status_code != 200:
                logger.error("Ollama responded with HTTP %d: %s", tags_res.status_code, tags_res.text)
                return {"status": "NOT VERIFIED", "reason": f"Ollama HTTP {tags_res.status_code}"}
            models = [m.get("name", "") for m in tags_res.json().get("models", [])]
            if not any(TARGET_MODEL in m for m in models):
                logger.error("Required model '%s' not found in Ollama models: %s", TARGET_MODEL, models)
                return {"status": "NOT VERIFIED", "reason": f"Model {TARGET_MODEL} not installed"}
    except Exception as ex:
        logger.error("Failed to connect to local Ollama daemon: %s", ex)
        return {"status": "NOT VERIFIED", "reason": f"Ollama connection error: {ex}"}

    logger.info("Ollama is active with model '%s'. Proceeding with boundary test.", TARGET_MODEL)

    proxy_port = find_free_port()
    gateway_port = find_free_port()
    db_file = REPO_ROOT / "test_ollama_qual.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    proxy_script = REPO_ROOT / "examples" / "phase_1_mvp_demo" / "capturing_proxy_tmp.py"

    with open(proxy_script, "w", encoding="utf-8") as f:
        f.write(PROXY_SCRIPT_CODE)

    os.environ["DATABASE_URL"] = db_url
    os.environ["UPSTREAM_LLM_BASE_URL"] = f"http://127.0.0.1:{proxy_port}/v1"
    os.environ["UPSTREAM_LLM_API_KEY"] = "ollama"
    os.environ["PRIVGUARD_MASTER_KEY"] = "msl-qual-master-secret-key-32-chars-ok"

    asyncio.run(seed_test_database(db_url))

    proxy_proc: Optional[subprocess.Popen] = None
    gateway_proc: Optional[subprocess.Popen] = None
    python_exe = sys.executable

    test_outcome: Dict[str, Any] = {}

    try:
        # 2. Launch Capturing Reverse Proxy
        logger.info("Starting Capturing Test Proxy on port %d...", proxy_port)
        proxy_proc = subprocess.Popen(
            [python_exe, str(proxy_script), "--port", str(proxy_port)],
        )
        assert wait_for_url(f"http://127.0.0.1:{proxy_port}/health", timeout_seconds=10.0), "Proxy failed to start."
        logger.info("Capturing Test Proxy is ready.")

        # 3. Launch PRIVGUARD Gateway pointing to Proxy
        logger.info("Starting PRIVGUARD Gateway on port %d...", gateway_port)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(BACKEND_DIR) + os.pathsep + env.get("PYTHONPATH", "")

        gateway_proc = subprocess.Popen(
            [
                python_exe,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(gateway_port),
            ],
            cwd=str(BACKEND_DIR),
            env=env,
        )
        assert wait_for_url(f"http://127.0.0.1:{gateway_port}/health", timeout_seconds=15.0), "Gateway failed to start."
        logger.info("PRIVGUARD Gateway is ready.")

        # 4. Dispatch live completion request with synthetic PII
        synthetic_email = "oliver.thorne@synthetic-msl-audit.net"
        synthetic_phone = "+1-555-019-2834"
        prompt_text = (
            f"Please draft a one-sentence welcome email for our new teammate {synthetic_email} "
            f"or ask them to call the helpdesk at {synthetic_phone}."
        )

        headers = {"X-API-Key": TEST_API_KEY, "Content-Type": "application/json"}
        gateway_url = f"http://127.0.0.1:{gateway_port}"

        logger.info("Sending request with synthetic PII through PRIVGUARD Gateway...")
        with httpx.Client(base_url=gateway_url, headers=headers, timeout=60.0) as client:
            res = client.post(
                "/v1/chat/completions",
                json={
                    "model": TARGET_MODEL,
                    "messages": [{"role": "user", "content": prompt_text}],
                },
            )
            assert res.status_code == 200, f"Gateway request failed: {res.status_code} {res.text}"
            res_body = res.json()
            completion_text = res_body["choices"][0]["message"]["content"]
            logger.info("Received completion from Ollama via Gateway:\n\"%s\"", completion_text.strip())

        # 5. Retrieve captured payload from Proxy
        with httpx.Client(timeout=5.0) as client:
            cap_res = client.get(f"http://127.0.0.1:{proxy_port}/captured")
            assert cap_res.status_code == 200
            payloads = cap_res.json()["payloads"]
            assert len(payloads) >= 1, "Capturing proxy recorded zero payloads!"
            captured_body = payloads[-1]

        captured_str = json.dumps(captured_body)
        logger.info("\n--- CAPTURED REQUEST RECEIVED AT OLLAMA BOUNDARY ---")
        logger.info(json.dumps(captured_body, indent=2))

        # 6. Rigorous Redaction Boundary Assertions
        assert synthetic_email not in captured_str, f"LEAK DETECTED: Raw email reached Ollama boundary! Body: {captured_str}"
        assert synthetic_phone not in captured_str, f"LEAK DETECTED: Raw phone reached Ollama boundary! Body: {captured_str}"
        assert "<EMAIL_1>" in captured_str, f"Expected <EMAIL_1> token missing at Ollama boundary: {captured_str}"
        assert "<PHONE_NUMBER_1>" in captured_str, f"Expected <PHONE_NUMBER_1> token missing at Ollama boundary: {captured_str}"
        assert "redaction_mapping" not in captured_str, f"Mapping leaked to Ollama: {captured_str}"
        assert "synthetic-msl-audit.net" not in captured_str, f"Domain leaked: {captured_str}"

        test_outcome = {
            "status": "PASS",
            "model": TARGET_MODEL,
            "raw_email_absent": True,
            "raw_phone_absent": True,
            "tokens_present": ["<EMAIL_1>", "<PHONE_NUMBER_1>"],
            "mapping_isolated": True,
            "inference_succeeded": True,
            "completion_preview": completion_text[:100],
        }

        print("\n" + "=" * 80)
        print("         OLLAMA REDACTION BOUNDARY VERIFICATION: PASS")
        print("=" * 80)
        print("✓ Raw Synthetic Email Absent at Socket Boundary:   CONFIRMED")
        print("✓ Raw Synthetic Phone Absent at Socket Boundary:   CONFIRMED")
        print("✓ Placeholder Tokens Sent to Ollama (<EMAIL_1>):    CONFIRMED")
        print("✓ Placeholder Tokens Sent to Ollama (<PHONE_1>):    CONFIRMED")
        print("✓ Redaction Mapping Kept Confidential on Gateway:  CONFIRMED")
        print("✓ Real Llama 3.2 3B Inference Executed over HTTP:  CONFIRMED")
        print("=" * 80 + "\n")

    finally:
        logger.info("Cleaning up verification processes...")
        if gateway_proc:
            try:
                gateway_proc.terminate()
                gateway_proc.wait(timeout=3)
            except Exception:
                gateway_proc.kill()
        if proxy_proc:
            try:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=3)
            except Exception:
                proxy_proc.kill()
        if proxy_script.exists():
            try:
                proxy_script.unlink()
            except Exception:
                pass
        if db_file.exists():
            try:
                db_file.unlink()
            except Exception:
                pass
        logger.info("Cleanup completed.")

    return test_outcome


if __name__ == "__main__":
    outcome = run_ollama_redaction_boundary_test()
    out_file = REPO_ROOT / "docs" / "ollama_boundary_qualification.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(outcome, f, indent=2)
    logger.info("Results saved to %s", out_file)

