# PRIVGUARD AI — Phase 1 Local-First Deployment Guide

Organization: Moon Sanctum Labs  
Motto: *Decode. Build. Evolve.*  
Date: November 2026

---

## 1. Overview & Architecture

PRIVGUARD AI is designed to run completely local-first. In Phase 1, developers can deploy the entire security gateway, PostgreSQL database, Redis state cache, and Next.js Control Center on a single local machine without requiring external cloud accounts or third-party paid AI services.

```
                                  [Developer Machine]
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   +-----------------------+              +-------------------------------------------+  |
|   |   AI Application      |              |   Next.js Control Center                  |  |
|   |   (Client / SDK)      |              |   http://localhost:3000                   |  |
|   +-----------+-----------+              +---------------------+---------------------+  |
|               |                                                |                        |
|               | (OpenAI HTTP /v1/chat/completions)             | (REST Management API)  |
|               v                                                v                        |
|   +----------------------------------------------------------------------------------+  |
|   |                     PRIVGUARD SECURITY GATEWAY (Port 8000)                       |  |
|   |                                                                                  |  |
|   |  - PII Detection & Redaction            - Content-Free Activity Logging          |  |
|   |  - Secret Interception                  - Server-Side Tool Execution Broker      |  |
|   |  - Prompt Injection Defense             - User-Defined Security Policies         |  |
|   +-------------------+----------------------------------------+---------------------+  |
|                       |                                        |                        |
|                       | (Forward Sanitized Prompt)             | (State & Persistence)  |
|                       v                                        v                        |
|       +-------------------------------+            +-----------------------+            |
|       |    INFERENCE ENDPOINT         |            | PostgreSQL 16 & Redis |            |
|       |                               |            | (Docker Container)    |            |
|       | Mode A: Deterministic Mock    |            +-----------------------+            |
|       | Mode B: Local Ollama / vLLM   |                                                 |
|       | Mode C: Optional Cloud Model  |                                                 |
|       +-------------------------------+                                                 |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Quickstart Deployment (Docker Compose)

### Step 1: Clone and Initialize Secrets
```bash
git clone https://github.com/MoonSanctumLabs/privguard-ai.git
cd privguard-ai

# Generate cryptographically secure local secrets (Master Key, DB password, Admin API key)
python scripts/init_secrets.py --dir ./secrets
```

### Step 2: Launch the Local Stack
```bash
docker compose up -d --build
```

### Step 3: Verify Service Health
```bash
# Verify Backend Security Gateway
curl -s http://localhost:8000/v1/health | jq .

# Expected Output:
# {
#   "status": "HEALTHY",
#   "service": "privguard",
#   "environment": "production",
#   "database": "CONNECTED",
#   "redis": "CONNECTED"
# }
```
Access the Control Center at: `http://localhost:3000`

---

## 3. Inference Connection Modes

### Mode A: Deterministic Mock Model (Zero-Dependency Offline Testing)
Included in the repository for automated CI, reproducible demonstrations, and offline verification:
```bash
# Run local mock model on port 8001
python examples/phase_1_mvp_demo/mock_model_server.py --port 8001
```
Set in `.env`:
```env
UPSTREAM_OPENAI_BASE_URL=http://localhost:8001/v1
UPSTREAM_OPENAI_API_KEY=mock-dev-key
```

### Mode B: Real Local Inference via Ollama
To run real AI inference with zero data leaving your machine:
1. Install [Ollama](https://ollama.com/) and verify your local model:
   ```bash
   ollama list
   # e.g., llama3.2:3b or qwen2.5:3b
   ```
2. Configure PRIVGUARD to point to your Ollama instance:
   - **Direct Windows/macOS Uvicorn**:
     ```env
     UPSTREAM_LLM_BASE_URL=http://127.0.0.1:11434/v1
     UPSTREAM_LLM_API_KEY=ollama
     ```
   - **Docker Desktop Backend Container**:
     ```env
     UPSTREAM_LLM_BASE_URL=http://host.docker.internal:11434/v1
     UPSTREAM_LLM_API_KEY=ollama
     ```
   > [!IMPORTANT]  
   > Server-side SSRF protections remain strictly enforced in both modes. Client applications cannot specify arbitrary remote URLs; endpoints are resolved strictly through server-side environment configurations.

3. Requests sent to `http://localhost:8000/v1/chat/completions` will be inspected, redacted, and forwarded to Ollama locally.

### Mode C: Optional Cloud Model Providers
Cloud providers remain strictly optional. If configured:
```env
UPSTREAM_OPENAI_BASE_URL=https://api.openai.com/v1
UPSTREAM_OPENAI_API_KEY=sk-proj-...
```

---

## 4. Local Python Development Mode (No Docker)

For fast local development without Docker:
```bash
# 1. Activate virtual environment
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# 2. Start PostgreSQL / SQLite development mode
export ENVIRONMENT=development

# 3. Start Backend
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# 4. Start Frontend
cd frontend
npm run dev
```
Interactive OpenAPI documentation will be accessible at: `http://127.0.0.1:8000/docs`.

