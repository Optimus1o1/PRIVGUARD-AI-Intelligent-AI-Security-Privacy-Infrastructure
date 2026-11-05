"""Emergency cryptographic key compromise response and incident remediation engine."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.exceptions import PrivGuardException
from app.database.models import KeyVersion, ManagedKey, MemoryRecord, PolicyBundle, utcnow
from app.key_management.base import KeyStatus
from app.key_management.manager import KMSManager, kms_manager as default_kms_manager
from app.key_management.rotation import KeyRotationEngine, key_rotation_engine as default_rotation_engine
from app.key_management.signing import SigningKeyManager, signing_key_manager as default_signing_manager
from app.memory.crypto import EnvelopeEncryption, envelope_encryption as default_envelope_encryption


class CompromiseSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CompromiseType(str, Enum):
    DEK_COMPROMISE = "DEK_COMPROMISE"
    KEK_COMPROMISE = "KEK_COMPROMISE"
    POLICY_SIGNING_KEY_COMPROMISE = "POLICY_SIGNING_KEY_COMPROMISE"
    APPROVAL_HMAC_KEY_COMPROMISE = "APPROVAL_HMAC_KEY_COMPROMISE"
    PROVIDER_CREDENTIAL_COMPROMISE = "PROVIDER_CREDENTIAL_COMPROMISE"


class KeyCompromiseManager:
    """
    Coordinates emergency containment, revocation, key replacement, and re-encryption
    during cryptographic incident response.
    """

    def __init__(
        self,
        kms_mgr: Optional[KMSManager] = None,
        rotation_engine: Optional[KeyRotationEngine] = None,
        signing_mgr: Optional[SigningKeyManager] = None,
        crypto_engine: Optional[EnvelopeEncryption] = None,
    ) -> None:
        self.kms_manager = kms_mgr or default_kms_manager
        self.rotation_engine = rotation_engine or default_rotation_engine
        self.signing_manager = signing_mgr or default_signing_manager
        self.crypto_engine = crypto_engine or default_envelope_encryption

    async def handle_dek_compromise(
        self,
        db: AsyncSession,
        memory_id: str,
        tenant_id: str = "default_tenant",
    ) -> Dict[str, Any]:
        """
        Remediates a compromised memory DEK:
        1. Decrypts plaintext using current envelope.
        2. Generates a fresh 256-bit DEK.
        3. Completely re-encrypts memory payload with fresh nonce and DEK.
        4. Re-wraps fresh DEK under active KEK.
        """
        q = select(MemoryRecord).where(MemoryRecord.id == memory_id, MemoryRecord.tenant_id == tenant_id)
        res = await db.execute(q)
        record = res.scalar_one_or_none()
        if not record:
            raise PrivGuardException(f"Memory record '{memory_id}' not found.", status_code=404)

        from app.memory.crypto import EncryptedMemoryPayload
        payload = EncryptedMemoryPayload(
            ciphertext_b64=record.encrypted_content,
            nonce_b64=record.nonce,
            wrapped_dek_b64=record.wrapped_dek,
            dek_nonce_b64=record.dek_nonce,
            key_version=record.key_version,
            content_fingerprint=record.content_fingerprint,
            encryption_format=record.encryption_format or "V1",
            key_id=record.key_id,
        )

        # Decrypt existing plaintext
        plaintext = self.crypto_engine.decrypt(
            payload=payload,
            owner_id=record.owner_id,
            memory_id=record.id,
            category=record.category,
            tenant_id=record.tenant_id,
        )

        # Encrypt with fresh DEK using active V2 KMS format
        fresh_payload = self.crypto_engine.encrypt(
            plaintext=plaintext,
            owner_id=record.owner_id,
            memory_id=record.id,
            category=record.category,
            tenant_id=record.tenant_id,
            encryption_format="V2",
            key_id=record.key_id,
        )

        record.encrypted_content = fresh_payload.ciphertext_b64
        record.nonce = fresh_payload.nonce_b64
        record.wrapped_dek = fresh_payload.wrapped_dek_b64
        record.dek_nonce = fresh_payload.dek_nonce_b64
        record.key_version = fresh_payload.key_version
        record.encryption_format = "V2"
        record.version += 1
        record.updated_at = utcnow()

        await db.commit()
        return {
            "status": "CONTAINED",
            "incident_type": CompromiseType.DEK_COMPROMISE.value,
            "memory_id": memory_id,
            "action": "PAYLOAD_RE_ENCRYPTED_WITH_FRESH_DEK",
            "timestamp": utcnow().isoformat(),
        }

    async def handle_kek_compromise(
        self,
        db: AsyncSession,
        key_id: str,
        tenant_id: str = "default_tenant",
    ) -> Dict[str, Any]:
        """
        Remediates a compromised KEK:
        1. Immediately marks the compromised key version as COMPROMISED.
        2. Initiates emergency rotation, provisioning a fresh active KEK version.
        3. Spawns rotation job to rewrap all dependent DEKs.
        """
        q = select(ManagedKey).where(ManagedKey.id == key_id, ManagedKey.tenant_id == tenant_id)
        res = await db.execute(q)
        mkey = res.scalar_one_or_none()
        if not mkey:
            raise PrivGuardException(f"Managed key '{key_id}' not found.", status_code=404)

        old_ver_id = mkey.active_version_id

        # Execute emergency rotation to create fresh version
        job = await self.rotation_engine.initiate_rotation(db, key_id, mode="EMERGENCY")

        # Ensure compromised version is flagged as COMPROMISED
        if old_ver_id:
            vq = select(KeyVersion).where(KeyVersion.id == old_ver_id)
            vres = await db.execute(vq)
            kver = vres.scalar_one_or_none()
            if kver:
                kver.status = KeyStatus.COMPROMISED.value
                await db.commit()

        return {
            "status": "ROTATING",
            "incident_type": CompromiseType.KEK_COMPROMISE.value,
            "key_id": key_id,
            "rotation_job_id": job.id,
            "records_to_rewrap": job.records_total,
            "timestamp": utcnow().isoformat(),
        }

    async def handle_policy_signing_key_compromise(
        self,
        db: AsyncSession,
        signing_key_id: str,
        tenant_id: str = "default_tenant",
    ) -> Dict[str, Any]:
        """
        Remediates a compromised Ed25519 policy signing key:
        1. Marks the compromised key version REVOKED / COMPROMISED.
        2. Generates a fresh Ed25519 keypair.
        3. Re-signs all active policy bundles using the new keypair.
        """
        q = select(KeyVersion).where(KeyVersion.id == signing_key_id)
        res = await db.execute(q)
        kver = res.scalar_one_or_none()
        if kver:
            kver.status = KeyStatus.COMPROMISED.value

        # Generate fresh signing keypair
        priv_hex, pub_hex = self.signing_manager.generate_ed25519_keypair()

        # Update active policy bundle signatures
        from app.policies.signing import canonical_json_bytes
        import json

        bq = select(PolicyBundle).where(PolicyBundle.organization_id == tenant_id, PolicyBundle.status == "ACTIVE")
        bres = await db.execute(bq)
        active_bundles = bres.scalars().all()

        re_signed_count = 0
        for bundle in active_bundles:
            bundle_dict = json.loads(bundle.bundle_json)
            new_sig = self.signing_manager.sign_policy(canonical_json_bytes(bundle_dict), priv_hex)
            bundle.signature_ed25519 = new_sig
            bundle.signing_key_id = f"ed25519_kver_{utcnow().strftime('%Y%m%d%H%M%S')}"
            re_signed_count += 1

        await db.commit()
        return {
            "status": "CONTAINED",
            "incident_type": CompromiseType.POLICY_SIGNING_KEY_COMPROMISE.value,
            "compromised_key_id": signing_key_id,
            "bundles_re_signed": re_signed_count,
            "timestamp": utcnow().isoformat(),
        }

    def handle_hmac_key_compromise(self, kid: str) -> Dict[str, Any]:
        """
        Remediates a compromised approval HMAC secret:
        1. Revokes the compromised key identifier.
        2. Rotates to a fresh high-entropy HMAC secret.
        """
        self.signing_manager.revoke_hmac_key(kid)
        new_kid = self.signing_manager.rotate_hmac_key()
        return {
            "status": "CONTAINED",
            "incident_type": CompromiseType.APPROVAL_HMAC_KEY_COMPROMISE.value,
            "revoked_kid": kid,
            "active_kid": new_kid,
            "timestamp": utcnow().isoformat(),
        }


# Global singleton instance
key_compromise_manager = KeyCompromiseManager()
