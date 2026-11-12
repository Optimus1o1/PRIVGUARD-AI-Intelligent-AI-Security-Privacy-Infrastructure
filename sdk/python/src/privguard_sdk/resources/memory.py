"""Personal AI Memory Vault resource."""

from typing import Any

from privguard_sdk.models.memory import (
    MemoryErasureRequest,
    MemoryErasureResponse,
    MemoryItemResponse,
    MemoryItemStoreRequest,
    MemorySearchRequest,
    MemorySearchResult,
    ProposalCreateRequest,
    ProposalResponse,
)
from privguard_sdk.resources.base import AsyncResource, SyncResource
from privguard_sdk.types import MemoryCategory


class MemoryResource(SyncResource):
    """Synchronous Personal AI Memory Vault endpoints."""

    def propose(
        self,
        proposed_key: str,
        proposed_value: str,
        agent_id: str,
        task_id: str,
        category: MemoryCategory | str = MemoryCategory.USER_PREFERENCES,
        ttl_seconds: int | None = 86400,
    ) -> ProposalResponse:
        """Stages a personal memory proposal for human consent."""
        cat_enum = MemoryCategory(category) if isinstance(category, str) else category
        req = ProposalCreateRequest(
            proposed_key=proposed_key,
            proposed_value=proposed_value,
            category=cat_enum,
            agent_id=agent_id,
            task_id=task_id,
            ttl_seconds=ttl_seconds,
        )
        data = self._transport.request("POST", "/v1/memory/proposals", json_data=req)
        return ProposalResponse.model_validate(data)

    def list_pending_proposals(self) -> list[ProposalResponse]:
        """Lists memory proposals awaiting human consent."""
        data = self._transport.request("GET", "/v1/memory/proposals/pending")
        return [ProposalResponse.model_validate(item) for item in data]

    def consent_proposal(self, proposal_id: str) -> ProposalResponse:
        """Consents to a staged memory proposal and encrypts into the vault."""
        data = self._transport.request("POST", f"/v1/memory/proposals/{proposal_id}/consent")
        return ProposalResponse.model_validate(data)

    def reject_proposal(self, proposal_id: str) -> ProposalResponse:
        """Rejects a staged memory proposal."""
        data = self._transport.request("POST", f"/v1/memory/proposals/{proposal_id}/reject")
        return ProposalResponse.model_validate(data)

    def store(
        self,
        key: str,
        value: str,
        category: MemoryCategory | str = MemoryCategory.USER_PREFERENCES,
        ttl_seconds: int | None = None,
    ) -> MemoryItemResponse:
        """Directly encrypts and stores personal memory (authorized user/app action)."""
        cat_enum = MemoryCategory(category) if isinstance(category, str) else category
        req = MemoryItemStoreRequest(
            key=key,
            value=value,
            category=cat_enum,
            ttl_seconds=ttl_seconds,
        )
        data = self._transport.request("POST", "/v1/memory/items", json_data=req)
        return MemoryItemResponse.model_validate(data)

    def retrieve(self, key: str) -> MemoryItemResponse:
        """Retrieves and decrypts a personal memory item."""
        data = self._transport.request("GET", f"/v1/memory/items/{key}")
        return MemoryItemResponse.model_validate(data)

    def list_items(self, category: str | None = None) -> list[MemoryItemResponse]:
        """Lists stored memory keys in the caller's vault."""
        params = {}
        if category:
            params["category"] = category
        data = self._transport.request("GET", "/v1/memory/items", params=params)
        return [MemoryItemResponse.model_validate(item) for item in data]

    def delete(self, key: str) -> dict[str, Any]:
        """Soft-deletes a memory item."""
        return self._transport.request("DELETE", f"/v1/memory/items/{key}")

    def search(
        self,
        query: str,
        category: MemoryCategory | str | None = None,
        limit: int = 10,
    ) -> MemorySearchResult:
        """Performs privacy-preserving search over caller's memory vault."""
        cat_enum = MemoryCategory(category) if isinstance(category, str) else category
        req = MemorySearchRequest(query=query, category=cat_enum, limit=limit)
        data = self._transport.request("POST", "/v1/memory/search", json_data=req)
        return MemorySearchResult.model_validate(data)

    def cryptographic_erasure(
        self,
        key: str | None = None,
        purge_all: bool = False,
    ) -> MemoryErasureResponse:
        """Destroys Data Encryption Keys (DEKs) to achieve statutory cryptographic erasure."""
        req = MemoryErasureRequest(key=key, purge_all=purge_all)
        data = self._transport.request("POST", "/v1/memory/erasure", json_data=req)
        return MemoryErasureResponse.model_validate(data)


class AsyncMemoryResource(AsyncResource):
    """Asynchronous Personal AI Memory Vault endpoints."""

    async def propose(
        self,
        proposed_key: str,
        proposed_value: str,
        agent_id: str,
        task_id: str,
        category: MemoryCategory | str = MemoryCategory.USER_PREFERENCES,
        ttl_seconds: int | None = 86400,
    ) -> ProposalResponse:
        """Stages a personal memory proposal asynchronously."""
        cat_enum = MemoryCategory(category) if isinstance(category, str) else category
        req = ProposalCreateRequest(
            proposed_key=proposed_key,
            proposed_value=proposed_value,
            category=cat_enum,
            agent_id=agent_id,
            task_id=task_id,
            ttl_seconds=ttl_seconds,
        )
        data = await self._transport.request("POST", "/v1/memory/proposals", json_data=req)
        return ProposalResponse.model_validate(data)

    async def list_pending_proposals(self) -> list[ProposalResponse]:
        """Lists pending memory proposals asynchronously."""
        data = await self._transport.request("GET", "/v1/memory/proposals/pending")
        return [ProposalResponse.model_validate(item) for item in data]

    async def consent_proposal(self, proposal_id: str) -> ProposalResponse:
        """Consents to a staged memory proposal asynchronously."""
        data = await self._transport.request("POST", f"/v1/memory/proposals/{proposal_id}/consent")
        return ProposalResponse.model_validate(data)

    async def reject_proposal(self, proposal_id: str) -> ProposalResponse:
        """Rejects a staged memory proposal asynchronously."""
        data = await self._transport.request("POST", f"/v1/memory/proposals/{proposal_id}/reject")
        return ProposalResponse.model_validate(data)

    async def store(
        self,
        key: str,
        value: str,
        category: MemoryCategory | str = MemoryCategory.USER_PREFERENCES,
        ttl_seconds: int | None = None,
    ) -> MemoryItemResponse:
        """Directly stores memory asynchronously."""
        cat_enum = MemoryCategory(category) if isinstance(category, str) else category
        req = MemoryItemStoreRequest(
            key=key,
            value=value,
            category=cat_enum,
            ttl_seconds=ttl_seconds,
        )
        data = await self._transport.request("POST", "/v1/memory/items", json_data=req)
        return MemoryItemResponse.model_validate(data)

    async def retrieve(self, key: str) -> MemoryItemResponse:
        """Retrieves and decrypts a memory item asynchronously."""
        data = await self._transport.request("GET", f"/v1/memory/items/{key}")
        return MemoryItemResponse.model_validate(data)

    async def list_items(self, category: str | None = None) -> list[MemoryItemResponse]:
        """Lists stored memory keys asynchronously."""
        params = {}
        if category:
            params["category"] = category
        data = await self._transport.request("GET", "/v1/memory/items", params=params)
        return [MemoryItemResponse.model_validate(item) for item in data]

    async def delete(self, key: str) -> dict[str, Any]:
        """Soft-deletes a memory item asynchronously."""
        return await self._transport.request("DELETE", f"/v1/memory/items/{key}")

    async def search(
        self,
        query: str,
        category: MemoryCategory | str | None = None,
        limit: int = 10,
    ) -> MemorySearchResult:
        """Performs search asynchronously."""
        cat_enum = MemoryCategory(category) if isinstance(category, str) else category
        req = MemorySearchRequest(query=query, category=cat_enum, limit=limit)
        data = await self._transport.request("POST", "/v1/memory/search", json_data=req)
        return MemorySearchResult.model_validate(data)

    async def cryptographic_erasure(
        self,
        key: str | None = None,
        purge_all: bool = False,
    ) -> MemoryErasureResponse:
        """Cryptographically erases memory asynchronously."""
        req = MemoryErasureRequest(key=key, purge_all=purge_all)
        data = await self._transport.request("POST", "/v1/memory/erasure", json_data=req)
        return MemoryErasureResponse.model_validate(data)
