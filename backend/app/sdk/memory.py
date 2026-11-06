"""PRIVGUARD AI - Personal AI Memory Vault Python SDK Client.
Allows AI agent frameworks and backend services to interact securely with the PRIVGUARD Memory Vault.
"""

from typing import Any, Dict, List, Optional
import httpx


class PrivGuardMemoryClient:
    """Client for PRIVGUARD Personal AI Memory Vault."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        owner_id: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.owner_id = owner_id
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if self.owner_id:
            headers["X-User-ID"] = self.owner_id
        return headers

    # --- Async Client Methods ---

    async def propose(
        self,
        key: str,
        value: str,
        category: str,
        agent_id: str,
        task_id: str,
        ttl_seconds: int = 86400,
    ) -> Dict[str, Any]:
        """Proposes candidate memory awaiting user consent."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/memory/proposals",
                headers=self._get_headers(),
                json={
                    "proposed_key": key,
                    "proposed_value": value,
                    "category": category,
                    "agent_id": agent_id,
                    "task_id": task_id,
                    "ttl_seconds": ttl_seconds,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_proposals(self, status: str = "PROPOSED") -> List[Dict[str, Any]]:
        """Lists pending candidate memory proposals."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/memory/proposals",
                headers=self._get_headers(),
                params={"status": status},
            )
            resp.raise_for_status()
            return resp.json()

    async def approve_proposal(
        self,
        proposal_id: str,
        retention_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Approves a proposal, moving it to encrypted active memory."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload = {"retention_days": retention_days} if retention_days else {}
            resp = await client.post(
                f"{self.base_url}/v1/memory/proposals/{proposal_id}/approve",
                headers=self._get_headers(),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def reject_proposal(
        self,
        proposal_id: str,
        reason: str = "User rejected",
    ) -> Dict[str, Any]:
        """Rejects a memory proposal."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/memory/proposals/{proposal_id}/reject",
                headers=self._get_headers(),
                json={"reason": reason},
            )
            resp.raise_for_status()
            return resp.json()

    async def create(
        self,
        key: str,
        value: str,
        category: str = "USER_PREFERENCES",
        retention_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Directly creates and encrypts a verified memory entry."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/memory",
                headers=self._get_headers(),
                json={
                    "key": key,
                    "value": value,
                    "category": category,
                    "retention_days": retention_days,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list(
        self,
        category: Optional[str] = None,
        status: str = "ACTIVE",
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists stored memory metadata in vault (no plaintext)."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            params: Dict[str, Any] = {"status": status, "limit": limit, "offset": offset}
            if category:
                params["category"] = category
            resp = await client.get(
                f"{self.base_url}/v1/memory",
                headers=self._get_headers(),
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    async def get(self, memory_id: str) -> Dict[str, Any]:
        """Retrieves and decrypts a specific memory entry."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/memory/{memory_id}",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def update(
        self,
        memory_id: str,
        new_value: str,
        expected_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Atomically updates memory content using optimistic CAS."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload: Dict[str, Any] = {"new_value": new_value}
            if expected_version is not None:
                payload["expected_version"] = expected_version
            resp = await client.patch(
                f"{self.base_url}/v1/memory/{memory_id}",
                headers=self._get_headers(),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def delete(self, memory_id: str) -> bool:
        """Cryptographically erases a memory entry."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.delete(
                f"{self.base_url}/v1/memory/{memory_id}",
                headers=self._get_headers(),
            )
            return resp.status_code == 204

    async def revoke(self, memory_id: str) -> Dict[str, Any]:
        """Soft-revokes a memory, hiding it from retrieval."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/memory/{memory_id}/revoke",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def retrieve(
        self,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        capability_token: Optional[str] = None,
        query: Optional[str] = None,
        categories: Optional[List[str]] = None,
        limit: int = 5,
    ) -> Dict[str, Any]:
        """Executes bounded, authorized retrieval of personal memories."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload: Dict[str, Any] = {"limit": limit}
            if agent_id:
                payload["agent_id"] = agent_id
            if task_id:
                payload["task_id"] = task_id
            if capability_token:
                payload["capability_token"] = capability_token
            if query:
                payload["query"] = query
            if categories:
                payload["categories"] = categories

            resp = await client.post(
                f"{self.base_url}/v1/memory/retrieve",
                headers=self._get_headers(),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def grant_permission(
        self,
        agent_id: str,
        operation: str,
        category: Optional[str] = None,
        memory_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Grants granular memory operation permission to an agent."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/memory/permissions",
                headers=self._get_headers(),
                json={
                    "agent_id": agent_id,
                    "operation": operation,
                    "category": category,
                    "memory_id": memory_id,
                    "ttl_seconds": ttl_seconds,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_permissions(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists active agent permissions."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            params = {"agent_id": agent_id} if agent_id else {}
            resp = await client.get(
                f"{self.base_url}/v1/memory/permissions",
                headers=self._get_headers(),
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    async def rotate_key(self) -> Dict[str, Any]:
        """Rotates user KEK and re-wraps active DEKs."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/memory/key/rotate",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def purge_vault(self) -> Dict[str, Any]:
        """Cryptographically purges all user personal memories."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/memory/purge",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def get_retention(self) -> Dict[str, Any]:
        """Gets memory retention metrics and category breakdown."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/memory/retention",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def get_audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Gets content-free audit trail."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/memory/audit",
                headers=self._get_headers(),
                params={"limit": limit},
            )
            resp.raise_for_status()
            return resp.json()
