"""Personal AI Memory Vault lifecycle example using PRIVGUARD Python SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import os

from privguard_sdk import PrivGuardClient, PrivGuardError


def main() -> None:
    base_url = os.getenv("PRIVGUARD_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.getenv("PRIVGUARD_API_KEY", "pg_live_test_api_key_valid_99999")
    user_id = "user_corp_developer_01"

    with PrivGuardClient(base_url=base_url, api_key=api_key, user_id=user_id) as client:
        try:
            # 1. Directly store user preference memory
            print("[*] Storing encrypted memory item...")
            stored = client.memory.store(
                key="preferred_model_tier",
                value="prefer gpt-4o for code review, fast models for summarization",
                category="USER_PREFERENCES",
            )
            print(f"[+] Memory Stored: Key='{stored.key}', Version={stored.version}")

            # 2. Retrieve and verify decryption
            retrieved = client.memory.retrieve(key="preferred_model_tier")
            print(f"[+] Memory Retrieved & Decrypted: '{retrieved.value}'")

            # 3. Privacy-preserving search
            print("[*] Searching memory vault...")
            search_res = client.memory.search(query="model tier", limit=5)
            print(f"[+] Found {search_res.count} matching item(s):")
            for item in search_res.items:
                print(f"    - {item.key}: {item.value}")

            # 4. Irreversible Cryptographic DEK Erasure (Right to Erasure)
            print("[*] Performing cryptographic erasure on specific key...")
            erasure_res = client.memory.cryptographic_erasure(key="preferred_model_tier")
            print(f"[+] Erasure Result: {erasure_res.message} (Erased count: {erasure_res.erased_count})")

        except PrivGuardError as exc:
            print("[-] Memory operation failed:", exc)


if __name__ == "__main__":
    main()
