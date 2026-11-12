"""Offline cryptographic verification of an exported compliance audit ZIP bundle.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import sys

from privguard_sdk import verify_export_package


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python evidence_verification.py <path_to_audit_package.zip> [trusted_public_key_pem]")
        sys.exit(1)

    zip_path = sys.argv[1]
    trusted_key = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Verifying compliance evidence package: {zip_path}")
    if trusted_key:
        print(f"Using trusted public key: {trusted_key}")
    else:
        print("Verifying using embedded public key with security warning (allow_embedded_key=True)...")

    result = verify_export_package(
        zip_path_or_bytes=zip_path,
        trusted_public_key=trusted_key,
        allow_embedded_key=(trusted_key is None),
    )

    print("\n--- Verification Report ---")
    print(result)

    if result.is_valid:
        print("\n[+] SUCCESS: Package integrity and Ed25519 signature are cryptographically valid.")
        sys.exit(0)
    else:
        print("\n[-] FAILURE: Verification failed! The package may have been tampered with or corrupted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
