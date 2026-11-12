"""File-based secrets provider for Docker and Kubernetes secrets."""

import os
from pathlib import Path
from typing import Optional


class DockerSecretProvider:
    """Reads secrets securely from /run/secrets/ or a configurable directory."""

    def __init__(self, secrets_dir: str = "/run/secrets") -> None:
        self.secrets_dir = Path(secrets_dir)

    def get_secret(self, name: str) -> Optional[str]:
        """Reads secret from file with path traversal defense."""
        # Sanitize filename
        safe_name = os.path.basename(name)
        file_path = self.secrets_dir / safe_name
        if file_path.is_file():
            try:
                return file_path.read_text(encoding="utf-8").strip()
            except Exception:
                return None
        return None

    def secret_exists(self, name: str) -> bool:
        safe_name = os.path.basename(name)
        return (self.secrets_dir / safe_name).is_file()
