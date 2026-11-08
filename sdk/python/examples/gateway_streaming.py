"""Secure chat completion and streaming example with PRIVGUARD Python SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
import os

from privguard_sdk import AsyncPrivGuardClient, PrivGuardError


async def main() -> None:
    base_url = os.getenv("PRIVGUARD_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.getenv("PRIVGUARD_API_KEY", "pg_live_test_api_key_valid_99999")

    async with AsyncPrivGuardClient(base_url=base_url, api_key=api_key) as client:
        messages = [
            {"role": "system", "content": "You are a helpful enterprise assistant."},
            {"role": "user", "content": "Draft an executive summary of our AI security posture."},
        ]

        print("--- 1. Non-Streaming Request ---")
        try:
            res = await client.gateway.create(
                model="gpt-4o",
                messages=messages,
                temperature=0.5,
            )
            print("Response ID:", res.id)
            print("Content:", res.choices[0].message.get("content"))
            print("PRIVGUARD Metadata:", res.privguard_meta)
        except PrivGuardError as exc:
            print("Gateway call failed:", exc)

        print("\n--- 2. Secure SSE Streaming ---")
        try:
            print("Streaming tokens: ", end="", flush=True)
            async for chunk in client.gateway.stream(
                model="gpt-4o",
                messages=messages,
            ):
                if chunk.choices and "delta" in chunk.choices[0]:
                    delta = chunk.choices[0]["delta"].get("content", "")
                    print(delta, end="", flush=True)
            print("\n[Stream Complete]")
        except PrivGuardError as exc:
            print("\nStreaming failed:", exc)


if __name__ == "__main__":
    asyncio.run(main())
