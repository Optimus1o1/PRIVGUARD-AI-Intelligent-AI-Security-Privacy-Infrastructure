#!/usr/bin/env python3
"""PRIVGUARD AI - Production Secret Initialization Script.
Moon Sanctum Labs - Decode. Build. Evolve.

Generates cryptographically secure 256-bit secrets for production deployment.
Writes secrets to files with restricted permissions (0600 on POSIX).
NEVER prints secret values to stdout/stderr.
Prompts or checks flags before overwriting existing files.
"""

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SECRET_FILES = {
    "privguard_master_key.txt": lambda: secrets.token_urlsafe(48),
    "postgres_password.txt": lambda: secrets.token_urlsafe(32),
    "migration_password.txt": lambda: secrets.token_urlsafe(32),
    "redis_password.txt": lambda: secrets.token_urlsafe(32),
    "privguard_admin_api_key.txt": lambda: f"pg_live_{secrets.token_hex(24)}",
}


def secure_write_file(path: Path, content: str, force: bool = False) -> bool:
    """Writes secret string to a file with restrictive permissions."""
    if path.exists() and not force:
        print(f"[SKIP] {path.name} already exists. Pass --force to overwrite.", file=sys.stderr)
        return False

    # Write secret
    path.write_text(content.strip(), encoding="utf-8")

    # Set restricted permissions on POSIX systems (chmod 600)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass  # Windows file permissions

    print(f"[CREATED] {path.name} (cryptographically secure)", file=sys.stderr)
    return True


def init_secrets(target_dir: Path, force: bool = False) -> None:
    """Initializes all standard secrets and asymmetric signing keys."""
    target_dir.mkdir(parents=True, exist_ok=True)

    print(f"Initializing PRIVGUARD deployment secrets in: {target_dir}", file=sys.stderr)

    # 1. Symmetric secrets
    for filename, generator in SECRET_FILES.items():
        dest = target_dir / filename
        secure_write_file(dest, generator(), force=force)

    # 2. Ed25519 Policy Signing Keypair
    priv_key_path = target_dir / "ed25519_policy_signing.key"
    pub_key_path = target_dir / "ed25519_policy_signing.pub"

    if (not priv_key_path.exists() and not pub_key_path.exists()) or force:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        secure_write_file(priv_key_path, priv_bytes.decode("utf-8"), force=force)
        secure_write_file(pub_key_path, pub_bytes.decode("utf-8"), force=force)
    else:
        print("[SKIP] Ed25519 signing keypair already exists.", file=sys.stderr)

    print("Secret initialization complete. Secure your backup of this directory.", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Initialize PRIVGUARD production secrets.")
    parser.add_argument(
        "--dir",
        type=str,
        default="secrets",
        help="Target secrets directory (default: ./secrets)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing secret files (use with extreme caution!)",
    )
    args = parser.parse_args()

    init_secrets(Path(args.dir), force=args.force)
