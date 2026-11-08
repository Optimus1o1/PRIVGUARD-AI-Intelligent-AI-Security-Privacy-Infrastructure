"""Compliance evidence collection and export snapshot example.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import os

from privguard_sdk import PrivGuardClient, PrivGuardError


def main() -> None:
    base_url = os.getenv("PRIVGUARD_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.getenv("PRIVGUARD_API_KEY", "pg_live_test_api_key_valid_99999")
    tenant_id = os.getenv("PRIVGUARD_TENANT_ID", "tenant_alpha")

    with PrivGuardClient(base_url=base_url, api_key=api_key, tenant_id=tenant_id) as client:
        try:
            # 1. Discover registered compliance frameworks
            print("[*] Querying compliance frameworks...")
            frameworks = client.compliance.list_frameworks()
            for fw in frameworks:
                print(f"    - {fw.id}: {fw.name} ({fw.coverage_percentage}% coverage)")

            # 2. Trigger automated evidence collection
            print("\n[*] Triggering automated evidence collection across subsystems...")
            res = client.compliance.collect_evidence()
            print(f"[+] Evidence Collection: {res.get('status')} ({res.get('records_created')} records)")

            # 3. Create a cryptographically signed ZIP export snapshot
            print("\n[*] Creating signed compliance audit snapshot...")
            export_resp = client.compliance.create_export(
                format="ZIP",
                include_artifacts=True,
            )
            print(f"[+] Export Created: {export_resp.export_id}")
            print(f"    Manifest Digest: {export_resp.manifest.get('export_id')}")

            # 4. Download audit bundle
            out_file = "audit_package_download.zip"
            print(f"\n[*] Downloading audit bundle to '{out_file}'...")
            client.compliance.download_export(export_resp.export_id, out_file)
            print(f"[+] Successfully saved bundle to {out_file} ({os.path.getsize(out_file)} bytes)")

        except PrivGuardError as exc:
            print("[-] Compliance operation failed:", exc)


if __name__ == "__main__":
    main()
