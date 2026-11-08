"""Basic connection and health check example using PRIVGUARD Python SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import os

from privguard_sdk import PrivGuardClient, PrivGuardError


def main() -> None:
    # 1. Initialize client with explicit or environment credentials
    base_url = os.getenv("PRIVGUARD_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.getenv("PRIVGUARD_API_KEY", "pg_live_test_api_key_valid_99999")
    tenant_id = os.getenv("PRIVGUARD_TENANT_ID", "tenant_alpha")

    print("Connecting to PRIVGUARD instance:", base_url)
    client = PrivGuardClient(
        base_url=base_url,
        api_key=api_key,
        tenant_id=tenant_id,
    )

    # Note: repr(client) masks the API key
    print("Client initialized:", repr(client))

    try:
        # 2. Check liveness
        liveness = client.health.check()
        print(f"\n[+] Liveness Check: {liveness.status.upper()}")
        print(f"    Service: {liveness.service} v{liveness.version} ({liveness.environment})")

        # 3. Check readiness
        readiness = client.health.ready()
        print(f"\n[+] Readiness Check: {readiness.status.upper()}")
        print(f"    Checks: {readiness.checks}")

    except PrivGuardError as exc:
        print(f"\n[-] PRIVGUARD Error: {exc}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
