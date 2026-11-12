"""Environment variable secrets provider (for development only)."""

import os
from typing import Optional


class EnvironmentSecretProvider:
    """Reads secrets from system environment variables."""

    def get_secret(self, name: str) -> Optional[str]:
        return os.getenv(name)

    def secret_exists(self, name: str) -> bool:
        return name in os.environ
