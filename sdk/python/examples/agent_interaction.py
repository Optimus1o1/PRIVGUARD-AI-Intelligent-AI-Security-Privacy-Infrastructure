"""Agent security, capability token request, and brokered tool execution example.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import os

from privguard_sdk import PrivGuardClient, PrivGuardError


def main() -> None:
    base_url = os.getenv("PRIVGUARD_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.getenv("PRIVGUARD_API_KEY", "pg_live_test_api_key_valid_99999")

    with PrivGuardClient(base_url=base_url, api_key=api_key) as client:
        try:
            # 1. Register an Agent
            agent = client.agents.register(
                name="ResearchAgent-Alpha",
                description="Performs literature search and report generation",
                allowed_tools=["search_web", "read_file"],
            )
            print(f"[+] Agent Registered: {agent.name} (ID: {agent.id})")

            # 2. Create a bounded Task session
            task = client.tasks.create(
                agent_id=agent.id,
                description="Research AI Act compliance",
                ttl_seconds=300,
                max_steps=20,
            )
            print(f"[+] Task Session Created: {task.id} (Status: {task.status})")

            # 3. Request a scoped Capability Token
            cap = client.capabilities.request(
                agent_id=agent.id,
                task_id=task.id,
                tool_name="search_web",
                max_uses=5,
            )
            print(f"[+] Capability Token Issued: {cap.id} (Max Uses: {cap.max_uses})")
            token = cap.capability_token

            # 4. Execute tool through the Broker
            print("[*] Executing tool via Security Broker...")
            result = client.tools.execute(
                tool_name="search_web",
                agent_id=agent.id,
                task_id=task.id,
                capability_token=token,
                parameters={"query": "EU AI Act high risk requirements"},
            )
            print(f"[+] Execution Succeeded in {result.duration_ms:.2f}ms:")
            print(f"    Output: {result.output}")

        except PrivGuardError as exc:
            print("[-] Agent execution error:", exc)


if __name__ == "__main__":
    main()
