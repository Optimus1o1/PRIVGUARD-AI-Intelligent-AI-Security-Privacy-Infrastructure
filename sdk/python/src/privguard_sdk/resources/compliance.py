"""Compliance evidence engine resource."""

from typing import Any

from privguard_sdk.models.compliance import (
    ComplianceControlResponse,
    ComplianceEvidenceRecordResponse,
    ComplianceFrameworkResponse,
    ComplianceGapAnalysisResponse,
    EvidenceExportRequest,
    EvidenceExportResponse,
    EvidencePublicKeyResponse,
)
from privguard_sdk.resources.base import AsyncResource, SyncResource
from privguard_sdk.types import ExportFormat
from privguard_sdk.verification.evidence import VerificationResult, verify_export_package


class ComplianceResource(SyncResource):
    """Synchronous Compliance Evidence Engine endpoints."""

    def get_public_signing_key(self, kid: str | None = None) -> EvidencePublicKeyResponse:
        """Retrieves active Ed25519 public key metadata for third-party package verification."""
        params = {}
        if kid:
            params["kid"] = kid
        data = self._transport.request("GET", "/v1/compliance/signing-keys/public", params=params)
        return EvidencePublicKeyResponse.model_validate(data)

    def list_frameworks(self) -> list[ComplianceFrameworkResponse]:
        """Lists statutory and security compliance frameworks with coverage scores."""
        data = self._transport.request("GET", "/v1/compliance/frameworks")
        return [ComplianceFrameworkResponse.model_validate(item) for item in data]

    def get_framework(self, framework_id: str) -> dict[str, Any]:
        """Retrieves detailed framework specification with statutory clauses and phases."""
        return self._transport.request("GET", f"/v1/compliance/frameworks/{framework_id}")

    def list_controls(self, domain: str | None = None) -> list[ComplianceControlResponse]:
        """Lists standardized PRIVGUARD internal controls (PG-CONTROL-001..035)."""
        params = {}
        if domain:
            params["domain"] = domain
        data = self._transport.request("GET", "/v1/compliance/controls", params=params)
        return [ComplianceControlResponse.model_validate(item) for item in data]

    def get_control(self, control_id: str) -> dict[str, Any]:
        """Retrieves control definition, mapping crosswalks, and latest evidence."""
        return self._transport.request("GET", f"/v1/compliance/controls/{control_id}")

    def list_mappings(
        self,
        control_id: str | None = None,
        requirement_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Lists bi-directional crosswalk mappings between internal controls and regulations."""
        params = {}
        if control_id:
            params["control_id"] = control_id
        if requirement_id:
            params["requirement_id"] = requirement_id
        return self._transport.request("GET", "/v1/compliance/mappings", params=params)

    def collect_evidence(
        self,
        collector_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Triggers automated evidence collection across authoritative subsystems."""
        req = {"collector_names": collector_names} if collector_names else {}
        return self._transport.request("POST", "/v1/compliance/evidence/collect", json_data=req)

    def list_evidence(
        self,
        control_id: str | None = None,
    ) -> list[ComplianceEvidenceRecordResponse]:
        """Lists collected compliance evidence records."""
        params = {}
        if control_id:
            params["control_id"] = control_id
        data = self._transport.request("GET", "/v1/compliance/evidence", params=params)
        return [ComplianceEvidenceRecordResponse.model_validate(item) for item in data]

    def get_gap_analysis(self, framework_id: str) -> ComplianceGapAnalysisResponse:
        """Runs gap analysis for a framework, identifying missing or stale controls."""
        data = self._transport.request("GET", "/v1/compliance/gaps", params={"framework_id": framework_id})
        return ComplianceGapAnalysisResponse.model_validate(data)

    def create_export(
        self,
        format: ExportFormat | str = ExportFormat.ZIP,
        framework_ids: list[str] | None = None,
        include_artifacts: bool = True,
    ) -> EvidenceExportResponse:
        """Requests creation of a cryptographically signed compliance export snapshot."""
        fmt_enum = ExportFormat(format) if isinstance(format, str) else format
        req = EvidenceExportRequest(
            format=fmt_enum,
            framework_ids=framework_ids,
            include_artifacts=include_artifacts,
        )
        data = self._transport.request("POST", "/v1/compliance/exports", json_data=req)
        return EvidenceExportResponse.model_validate(data)

    def download_export(self, export_id: str, destination_path: str) -> str:
        """Downloads an exported compliance bundle and saves it locally."""
        raw_bytes = self._transport.request("GET", f"/v1/compliance/exports/{export_id}/download")
        with open(destination_path, "wb") as f:
            if isinstance(raw_bytes, str):
                f.write(raw_bytes.encode("utf-8"))
            else:
                f.write(raw_bytes)
        return destination_path

    def verify_local_package(
        self,
        zip_path: str,
        trusted_public_key: str | bytes | None = None,
        allow_embedded_key: bool = False,
    ) -> VerificationResult:
        """Locally verifies artifact SHA-256 digests and Ed25519 signature of an export bundle."""
        return verify_export_package(
            zip_path_or_bytes=zip_path,
            trusted_public_key=trusted_public_key,
            allow_embedded_key=allow_embedded_key,
        )


class AsyncComplianceResource(AsyncResource):
    """Asynchronous Compliance Evidence Engine endpoints."""

    async def get_public_signing_key(self, kid: str | None = None) -> EvidencePublicKeyResponse:
        """Retrieves active Ed25519 public key metadata asynchronously."""
        params = {}
        if kid:
            params["kid"] = kid
        data = await self._transport.request("GET", "/v1/compliance/signing-keys/public", params=params)
        return EvidencePublicKeyResponse.model_validate(data)

    async def list_frameworks(self) -> list[ComplianceFrameworkResponse]:
        """Lists compliance frameworks asynchronously."""
        data = await self._transport.request("GET", "/v1/compliance/frameworks")
        return [ComplianceFrameworkResponse.model_validate(item) for item in data]

    async def get_framework(self, framework_id: str) -> dict[str, Any]:
        """Retrieves framework specification asynchronously."""
        return await self._transport.request("GET", f"/v1/compliance/frameworks/{framework_id}")

    async def list_controls(self, domain: str | None = None) -> list[ComplianceControlResponse]:
        """Lists standardized PRIVGUARD controls asynchronously."""
        params = {}
        if domain:
            params["domain"] = domain
        data = await self._transport.request("GET", "/v1/compliance/controls", params=params)
        return [ComplianceControlResponse.model_validate(item) for item in data]

    async def get_control(self, control_id: str) -> dict[str, Any]:
        """Retrieves control definition asynchronously."""
        return await self._transport.request("GET", f"/v1/compliance/controls/{control_id}")

    async def list_mappings(
        self,
        control_id: str | None = None,
        requirement_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Lists crosswalk mappings asynchronously."""
        params = {}
        if control_id:
            params["control_id"] = control_id
        if requirement_id:
            params["requirement_id"] = requirement_id
        return await self._transport.request("GET", "/v1/compliance/mappings", params=params)

    async def collect_evidence(
        self,
        collector_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Triggers automated evidence collection asynchronously."""
        req = {"collector_names": collector_names} if collector_names else {}
        return await self._transport.request("POST", "/v1/compliance/evidence/collect", json_data=req)

    async def list_evidence(
        self,
        control_id: str | None = None,
    ) -> list[ComplianceEvidenceRecordResponse]:
        """Lists collected compliance evidence records asynchronously."""
        params = {}
        if control_id:
            params["control_id"] = control_id
        data = await self._transport.request("GET", "/v1/compliance/evidence", params=params)
        return [ComplianceEvidenceRecordResponse.model_validate(item) for item in data]

    async def get_gap_analysis(self, framework_id: str) -> ComplianceGapAnalysisResponse:
        """Runs gap analysis asynchronously."""
        data = await self._transport.request("GET", "/v1/compliance/gaps", params={"framework_id": framework_id})
        return ComplianceGapAnalysisResponse.model_validate(data)

    async def create_export(
        self,
        format: ExportFormat | str = ExportFormat.ZIP,
        framework_ids: list[str] | None = None,
        include_artifacts: bool = True,
    ) -> EvidenceExportResponse:
        """Requests creation of a compliance export snapshot asynchronously."""
        fmt_enum = ExportFormat(format) if isinstance(format, str) else format
        req = EvidenceExportRequest(
            format=fmt_enum,
            framework_ids=framework_ids,
            include_artifacts=include_artifacts,
        )
        data = await self._transport.request("POST", "/v1/compliance/exports", json_data=req)
        return EvidenceExportResponse.model_validate(data)

    async def download_export(self, export_id: str, destination_path: str) -> str:
        """Downloads an exported compliance bundle asynchronously."""
        raw_bytes = await self._transport.request("GET", f"/v1/compliance/exports/{export_id}/download")
        with open(destination_path, "wb") as f:
            if isinstance(raw_bytes, str):
                f.write(raw_bytes.encode("utf-8"))
            else:
                f.write(raw_bytes)
        return destination_path

    def verify_local_package(
        self,
        zip_path: str,
        trusted_public_key: str | bytes | None = None,
        allow_embedded_key: bool = False,
    ) -> VerificationResult:
        """Locally verifies artifact digests and signature of an export bundle."""
        return verify_export_package(
            zip_path_or_bytes=zip_path,
            trusted_public_key=trusted_public_key,
            allow_embedded_key=allow_embedded_key,
        )
