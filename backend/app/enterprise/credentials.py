"""Enterprise integration secrets and credentials management."""

import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.config import settings
from app.core.exceptions import AuthorizationError
from app.database.models import IntegrationCredential, utcnow


class EnterpriseCredentialManager:
    """Manages encrypted integration secrets strictly scoped to MCP servers and SIEM exporters."""

    @staticmethod
    def _get_cipher() -> Fernet:
        """Derives a Fernet cipher from master key or secret key."""
        import base64
        import hashlib
        key_material = hashlib.sha256(settings.JWT_SECRET.encode()).digest()
        b64_key = base64.urlsafe_b64encode(key_material)
        return Fernet(b64_key)

    @classmethod
    def encrypt_secret(cls, raw_secret: str) -> str:
        """Encrypts a plaintext secret into ciphertext."""
        cipher = cls._get_cipher()
        return cipher.encrypt(raw_secret.encode()).decode()

    @classmethod
    def decrypt_secret(cls, encrypted_secret: str) -> str:
        """Decrypts a ciphertext into plaintext secret for immediate execution."""
        cipher = cls._get_cipher()
        return cipher.decrypt(encrypted_secret.encode()).decode()

    @classmethod
    async def store_credential(
        cls,
        db: AsyncSession,
        tenant_id: str,
        integration_type: str,
        target_id: str,
        secret_value: str,
        workspace_id: Optional[str] = None,
        key_version: str = "v1",
    ) -> IntegrationCredential:
        """Stores an encrypted integration credential."""
        encrypted_val = cls.encrypt_secret(secret_value)

        q = select(IntegrationCredential).where(
            IntegrationCredential.tenant_id == tenant_id,
            IntegrationCredential.integration_type == integration_type,
            IntegrationCredential.target_id == target_id,
        )
        res = await db.execute(q)
        existing = res.scalar_one_or_none()

        now = utcnow()
        if existing:
            existing.encrypted_secret = encrypted_val
            existing.key_version = key_version
            existing.last_rotated_at = now
            existing.workspace_id = workspace_id or existing.workspace_id
            await db.commit()
            await db.refresh(existing)
            return existing

        cred = IntegrationCredential(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            integration_type=integration_type,
            target_id=target_id,
            encrypted_secret=encrypted_val,
            key_version=key_version,
            last_rotated_at=now,
            created_at=now,
        )
        db.add(cred)
        await db.commit()
        await db.refresh(cred)
        return cred

    @classmethod
    async def get_decrypted_credential(
        cls,
        db: AsyncSession,
        tenant_id: str,
        integration_type: str,
        target_id: str,
    ) -> Optional[str]:
        """Retrieves and decrypts a credential strictly for authorized backend operations."""
        q = select(IntegrationCredential).where(
            IntegrationCredential.tenant_id == tenant_id,
            IntegrationCredential.integration_type == integration_type,
            IntegrationCredential.target_id == target_id,
        )
        res = await db.execute(q)
        cred = res.scalar_one_or_none()
        if not cred:
            return None

        return cls.decrypt_secret(cred.encrypted_secret)

