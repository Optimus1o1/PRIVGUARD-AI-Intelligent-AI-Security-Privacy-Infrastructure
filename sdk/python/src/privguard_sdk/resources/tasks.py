"""Task session resource."""

from privguard_sdk.models.tasks import CreateTaskRequest, TaskResponse
from privguard_sdk.resources.base import AsyncResource, SyncResource


class TasksResource(SyncResource):
    """Synchronous Task Session endpoints."""

    def create(
        self,
        agent_id: str,
        description: str | None = None,
        ttl_seconds: int = 600,
        max_steps: int | None = None,
    ) -> TaskResponse:
        """Initializes a new task session bound to an active agent."""
        req = CreateTaskRequest(
            agent_id=agent_id,
            description=description,
            ttl_seconds=ttl_seconds,
            max_steps=max_steps,
        )
        data = self._transport.request("POST", "/v1/tasks", json_data=req)
        return TaskResponse.model_validate(data)

    def get(self, task_id: str) -> TaskResponse:
        """Retrieves details of a task session."""
        data = self._transport.request("GET", f"/v1/tasks/{task_id}")
        return TaskResponse.model_validate(data)

    def list(self, agent_id: str | None = None, limit: int = 50) -> list[TaskResponse]:
        """Lists task sessions."""
        params = {"limit": limit}
        if agent_id:
            params["agent_id"] = agent_id
        data = self._transport.request("GET", "/v1/tasks", params=params)
        return [TaskResponse.model_validate(item) for item in data]


class AsyncTasksResource(AsyncResource):
    """Asynchronous Task Session endpoints."""

    async def create(
        self,
        agent_id: str,
        description: str | None = None,
        ttl_seconds: int = 600,
        max_steps: int | None = None,
    ) -> TaskResponse:
        """Initializes a new task session asynchronously."""
        req = CreateTaskRequest(
            agent_id=agent_id,
            description=description,
            ttl_seconds=ttl_seconds,
            max_steps=max_steps,
        )
        data = await self._transport.request("POST", "/v1/tasks", json_data=req)
        return TaskResponse.model_validate(data)

    async def get(self, task_id: str) -> TaskResponse:
        """Retrieves details of a task session asynchronously."""
        data = await self._transport.request("GET", f"/v1/tasks/{task_id}")
        return TaskResponse.model_validate(data)

    async def list(self, agent_id: str | None = None, limit: int = 50) -> list[TaskResponse]:
        """Lists task sessions asynchronously."""
        params = {"limit": limit}
        if agent_id:
            params["agent_id"] = agent_id
        data = await self._transport.request("GET", "/v1/tasks", params=params)
        return [TaskResponse.model_validate(item) for item in data]
