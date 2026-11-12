# PRIVGUARD AI — Python SDK SSE Streaming Specification

**Organization**: Moon Sanctum Labs  
**Motto**: Decode. Build. Evolve.  
**Package**: `privguard-sdk` (import: `privguard_sdk`)  
**Specification Version**: 1.0.0 (SDK Version: 0.1.0)  

---

## 1. Overview & Streaming Protocol

The PRIVGUARD AI Gateway supports real-time token streaming using standard Server-Sent Events (SSE) over HTTP/1.1 and HTTP/2. The SDK encapsulates line parsing, buffering, and JSON deserialization into high-level generator interfaces:

- Synchronous: `Iterator[ChatCompletionChunk]`
- Asynchronous: `AsyncIterator[ChatCompletionChunk]`

### Wire Format

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream; charset=utf-8
Cache-Control: no-cache
Connection: keep-alive

data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}

data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Hello"}}]}

data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":" world"}}]}

data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]

```

---

## 2. Models & Data Structures

Each event is deserialized into a `ChatCompletionChunk`:

```python
class ChatCompletionChunkDelta(BaseModel):
    role: str | None = None
    content: str | None = None

class ChatCompletionChunkChoice(BaseModel):
    index: int = 0
    delta: ChatCompletionChunkDelta = Field(default_factory=ChatCompletionChunkDelta)
    finish_reason: str | None = None

class ChatCompletionChunk(BaseModel):
    id: str
    object: str = "chat.completion.chunk"
    created: int | None = None
    model: str | None = None
    choices: list[ChatCompletionChunkChoice] = Field(default_factory=list)
```

---

## 3. Streaming Usage Examples

### Synchronous Streaming

```python
import sys
from privguard_sdk import PrivGuardClient

client = PrivGuardClient()

chunks = client.gateway.stream(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a helpful and privacy-aware assistant."},
        {"role": "user", "content": "Summarize the key requirements of DPDP 2023."},
    ],
    temperature=0.7,
)

print("Streaming response: ", end="")
for chunk in chunks:
    if chunk.choices and chunk.choices[0].delta.content:
        content = chunk.choices[0].delta.content
        sys.stdout.write(content)
        sys.stdout.flush()
print()
```

### Asynchronous Streaming

```python
import sys
import asyncio
from privguard_sdk import AsyncPrivGuardClient

async def stream_response():
    async with AsyncPrivGuardClient() as client:
        stream = client.gateway.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Draft an incident response checklist."}],
        )
        
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                sys.stdout.write(chunk.choices[0].delta.content)
                sys.stdout.flush()
        print()

asyncio.run(stream_response())
```

---

## 4. Connection Lifecycle & Error Boundaries

1. **Premature Disconnections**:  
   If the HTTP connection terminates before a `[DONE]` signal is received or a valid `finish_reason` is encountered, the SDK raises a `StreamingError(message="Connection closed prematurely")`.
2. **Buffer Management**:  
   The underlying transport processes incoming byte chunks dynamically without buffering the entire response payload into memory, enabling unbounded stream lengths with constant client memory footprint.
3. **HTTP Error Handling**:  
   If the server responds with a non-200 status code upon initial connection (e.g. `401 Unauthorized` or `429 Rate Limited`), the transport immediately consumes the error payload and raises the appropriate typed exception (`AuthenticationError`, `RateLimitError`) rather than entering the streaming generator.

