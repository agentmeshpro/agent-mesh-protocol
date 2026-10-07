"""
42 — AMPI: tools, middleware, and session-start hooks

Three decorators on top of 41_ampi_quickstart:

  @agent.tool(name)          — register a named callable. The server
                               surfaces tools via capability negotiation;
                               handlers can invoke them directly.

  @agent.middleware          — wrap every handler call. Middleware runs
                               in registration order (first registered =
                               outermost). Signature: (msg, ctx, next).

  @agent.on_session_start    — fired once per new session handshake.
                               Useful for per-session warmup or logging.

Run:
    ampro-server examples.42_ampi_with_tools:agent --port 8000
"""
from __future__ import annotations

from ampro.ampi.app import AgentApp
from ampro.ampi.context import AMPContext
from ampro.core.envelope import AgentMessage

agent = AgentApp(
    agent_id="agent://tools-bot.example.com",
    endpoint="http://localhost:8000/agent/message",
    capabilities=["messaging", "tools"],
)


@agent.tool("analyze_sentiment")
async def analyze_sentiment(text: str, ctx: AMPContext) -> dict:
    """Toy sentiment tool — returns a score and label."""
    score = 0.9 if "good" in text.lower() else -0.5
    return {"score": score, "label": "positive" if score > 0 else "negative"}


@agent.middleware
async def log_requests(msg: AgentMessage, ctx: AMPContext, next_handler):
    print(f"request received: body_type={msg.body_type} from={ctx.sender_address}")
    result = await next_handler(msg, ctx)
    print(f"response sent:    request_id={ctx.request_id}")
    return result


@agent.on_session_start
async def greet_session(session) -> None:
    session_id = getattr(session, "session_id", "?")
    print(f"session started: {session_id}")


@agent.on("task.create")
async def handle(msg: AgentMessage, ctx: AMPContext) -> dict:
    text = (msg.body or {}).get("text", "")
    sentiment = await analyze_sentiment(text, ctx)
    return {"sentiment": sentiment}
