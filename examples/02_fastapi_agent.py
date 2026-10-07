"""
FastAPI agent — PRE-AMPI raw-framework pattern.

For new code, prefer the declarative AMPI framework (see
examples/41_ampi_quickstart.py). This file is retained as a reference
for the underlying wire mechanics — how the envelope, capability set,
and streaming events look when wired into FastAPI by hand.

02 — FastAPI Agent (Level 3: Messaging + Tools + Streaming)

A more complete agent with tools, streaming, and health endpoint.

Run:
    pip install git+https://github.com/agentmeshpro/agent-mesh-protocol.git fastapi uvicorn
    uvicorn examples.02_fastapi_agent:app --port 8000
"""

# requires: fastapi  (tests/test_examples_run.py skips this example if missing)
from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import StreamingResponse

from ampro import (
    AgentMessage,
    CapabilityGroup,
    CapabilitySet,
    HealthResponse,
    StreamingEvent,
    StreamingEventType,
    validate_body,
)

app = FastAPI(title="FastAPI Agent")

CAPS = CapabilitySet(groups={
    CapabilityGroup.MESSAGING,
    CapabilityGroup.TOOLS,
    CapabilityGroup.STREAMING,
})

# Simple tool registry
TOOLS = {
    "echo": {"description": "Echo back the input", "parameters": {"text": "string"}},
    "add": {"description": "Add two numbers", "parameters": {"a": "number", "b": "number"}},
}


@app.get("/.well-known/agent.json")
async def agent_json():
    return {
        "protocol_version": "1.0.0",
        "identifiers": ["agent://fastapi-agent.local"],
        "endpoint": "http://localhost:8000/agent/message",
        "capabilities": CAPS.to_agent_json(),
        "constraints": {
            "max_concurrent_tasks": 10,
            "max_message_size_bytes": 1_048_576,
            "timeout_seconds": 30,
            "rate_limit_rpm": 60,
        },
        "security": {"auth_methods": ["jwt"], "api_key_allowed": False},
        "billing": {"model": "owner_pays", "quote_required": False},
        "streaming": {"replay_buffer_size": 100, "heartbeat_interval_seconds": 15},
        "languages": ["en"],
        "ttl_seconds": 3600,
    }


@app.get("/agent/health")
async def health():
    return HealthResponse(status="healthy", protocol_version="1.0.0").model_dump()


@app.get("/agent/tools")
async def list_tools():
    return {"tools": [{"name": k, **v} for k, v in TOOLS.items()]}


@app.post("/agent/message")
async def receive_message(msg: AgentMessage):
    # Validate body against schema
    try:
        validated = validate_body(msg.body_type, msg.body if isinstance(msg.body, dict) else {})
    except Exception as e:
        return {"body_type": "task.error", "body": {"reason": "unprocessable", "detail": str(e), "retry_eligible": False}}

    # Handle different body types
    if msg.body_type == "message":
        return {
            "sender": "agent://fastapi-agent.local",
            "recipient": msg.sender,
            "id": str(uuid4()),
            "body_type": "task.response",
            "headers": {"Protocol-Version": "1.0.0", "In-Reply-To": msg.id},
            "body": {"text": f"Got your message: {validated.text}"},
        }

    if msg.body_type == "task.create":
        return {
            "sender": "agent://fastapi-agent.local",
            "recipient": msg.sender,
            "id": str(uuid4()),
            "body_type": "task.acknowledge",
            "headers": {"Protocol-Version": "1.0.0", "In-Reply-To": msg.id},
            "body": {"task_id": msg.id, "estimated_duration_seconds": 5},
        }

    return {
        "sender": "agent://fastapi-agent.local",
        "recipient": msg.sender,
        "id": str(uuid4()),
        "body_type": "task.reject",
        "headers": {"Protocol-Version": "1.0.0", "In-Reply-To": msg.id},
        "body": {"task_id": msg.id, "reason": "unprocessable", "detail": f"Unknown body_type: {msg.body_type}"},
    }


@app.get("/agent/stream")
async def stream():
    async def events():
        for i, (etype, data) in enumerate([
            (StreamingEventType.THINKING, {"step": "analyzing request"}),
            (StreamingEventType.TOOL_CALL, {"tool": "echo", "input": {"text": "hello"}}),
            (StreamingEventType.TOOL_RESULT, {"tool": "echo", "output": "hello"}),
            (StreamingEventType.TEXT_DELTA, {"text": "Based on my analysis..."}),
            (StreamingEventType.DONE, {"finish_reason": "complete"}),
        ], 1):
            yield StreamingEvent(type=etype, seq=i, id=f"s:{i}", data=data).to_sse()

    return StreamingResponse(events(), media_type="text/event-stream")
