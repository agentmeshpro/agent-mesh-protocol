# Agent Mesh Protocol (AMP) -- HTTP Wire Binding Specification

    Version: 1.0.0
    Status: Normative
    Date: 2026-10-07 (security revision for ampro 0.4.0)
    Authors: AMP Contributors
    Specification URI: https://amp-protocol.dev/spec/wire-binding/1.0

## Abstract

This document specifies the HTTP wire binding for the Agent Mesh Protocol
(AMP). It defines how AMP messages are transported over HTTP, including
endpoint structure, request and response formats, error handling, streaming,
session management, security, and compliance. An implementer reading this
document alone MUST be able to build an interoperable AMP-compliant agent in
any programming language without reference to any specific implementation.

## Status of This Document

This is a normative specification. Implementations claiming AMP conformance
MUST implement the mandatory portions (Level 0) and SHOULD implement
higher levels as declared in their agent.json document.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Conventions and Terminology](#2-conventions-and-terminology)
3. [Transport Requirements](#3-transport-requirements)
4. [Discovery -- Level 0 (MANDATORY)](#4-discovery----level-0-mandatory)
5. [Messaging -- Level 1](#5-messaging----level-1)
6. [Response Semantics](#6-response-semantics)
7. [Error Format](#7-error-format)
8. [Streaming](#8-streaming)
9. [Sessions](#9-sessions)
10. [Tools -- Level 2](#10-tools----level-2)
11. [Task Lifecycle -- Level 3](#11-task-lifecycle----level-3)
12. [Security](#12-security)
13. [Compliance](#13-compliance)
14. [Standard Headers](#14-standard-headers)
15. [Status Codes](#15-status-codes)
16. [Body Types](#16-body-types)
17. [Capability Levels](#17-capability-levels)
18. [Extensibility](#18-extensibility)
19. [Configuration Defaults](#19-configuration-defaults)
20. [Conformance](#20-conformance)
21. [References](#21-references)

---

## 1. Introduction

### 1.1 Purpose

The Agent Mesh Protocol (AMP) enables autonomous software agents to
discover, authenticate, and communicate with one another across
organizational and platform boundaries. This document specifies how AMP
messages are encoded, transported, and interpreted over HTTP.

AMP is transport-agnostic by design. This document defines the HTTP
binding -- the primary and RECOMMENDED transport. Future documents MAY
define bindings for other transports (e.g., gRPC, WebSocket).

### 1.2 Design Philosophy

AMP follows the same philosophy as HTTP itself:

- **Minimal mandatory surface.** The only mandatory requirement is
  serving a static JSON file at a well-known URL (Level 0). Everything
  else is opt-in.
- **Progressive capability.** Agents declare what they support. Callers
  adapt. An agent on a Raspberry Pi and an agent backed by a
  hyperscaler cluster speak the same protocol at different levels.
- **Forward compatibility.** Unknown headers MUST be ignored. Unknown
  body types MUST be accepted. This guarantees that agents built today
  will not break when the protocol evolves.
- **Single endpoint core.** All message types flow through one POST
  endpoint. The `body_type` field is the semantic routing key, not the
  HTTP method or URL path.

### 1.3 Conformance Levels

AMP defines six progressive conformance levels:

| Level | Name        | Mandatory | Summary                                      |
|-------|-------------|-----------|----------------------------------------------|
| 0     | Discovery   | YES       | Serve `agent.json`, respond to health checks |
| 1     | Messaging   | No        | Accept and process messages                  |
| 2     | Tools       | No        | Expose and invoke callable tools             |
| 3     | Streaming   | No        | Real-time event delivery via SSE             |
| 4     | Identity    | No        | Sessions, handshake, delegation, events      |
| 5     | Full        | No        | All 8 capability groups                      |

Only Level 0 is MANDATORY. An implementation that serves a valid
`agent.json` document and responds to health checks is a conforming
AMP agent, even if it accepts no messages.

### 1.4 Scope

This specification covers:

- HTTP endpoints, methods, and URL structure
- Request and response envelope formats (JSON)
- Error encoding (RFC 7807)
- Server-Sent Events (SSE) streaming
- Session handshake and binding
- Tool discovery and invocation
- Task lifecycle state transitions
- Authentication and trust tier resolution
- Compliance headers and erasure flows
- Standard headers and their semantics
- Extensibility and versioning

This specification does NOT cover:

- Internal agent architecture or runtime design
- Specific cryptographic library choices
- Registry federation governance
- Business logic for task routing
- NAT traversal, relay infrastructure, or tunneling

---

## 2. Conventions and Terminology

### 2.1 Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all
capitals, as shown here.

### 2.2 Definitions

- **Agent**: An autonomous software entity that communicates via AMP.
- **Sender**: The agent originating a message.
- **Receiver**: The agent processing an incoming message.
- **Envelope**: The `AgentMessage` JSON object that wraps all communication.
- **Body type**: A dot-namespaced string (e.g., `task.create`) that
  determines the semantic meaning of the message body.
- **Trust tier**: One of four relationship levels (internal, owner,
  verified, external) that determines which security checks apply.
- **Capability group**: One of eight functional areas an agent MAY
  support (messaging, streaming, tools, identity, session, delegation,
  presence, events).
- **Capability level**: An integer (0--5) auto-computed from the set of
  active capability groups.

### 2.3 URI Notation

Throughout this document, `{base}` refers to the agent's base URL as
declared in the `endpoint` field of its `agent.json` document. For
example, if `endpoint` is `https://acme.example.com/agent/message`,
then `{base}` is `https://acme.example.com`.

Path-based endpoints are relative to `{base}` unless stated otherwise.

---

## 3. Transport Requirements

### 3.1 Protocol

The HTTP binding uses HTTPS (HTTP over TLS) as the underlying transport.

- Implementations MUST use HTTPS for production deployments.
- Implementations MAY use plain HTTP for development and testing
  environments.
- Implementations SHOULD support HTTP/2 for performance.
- Implementations MAY support HTTP/3 (QUIC).

### 3.2 Content Type

- Implementations MUST support `application/json` as the content type
  for request and response bodies.
- Implementations MAY support additional content types (e.g.,
  `application/cbor`, `application/msgpack`) as extensions.
- If a request does not include a `Content-Type` header, the receiver
  MUST assume `application/json`.

### 3.3 Character Encoding

- All JSON payloads MUST be encoded in UTF-8 [RFC 3629].
- Implementations MUST NOT use a byte-order mark (BOM).

### 3.4 Message Size

- Implementations MUST accept messages up to 10 MiB (10,485,760 bytes).
- Implementations MAY accept larger messages.
- Implementations MUST reject messages exceeding their configured limit
  with HTTP 413 (Payload Too Large) and an error response per Section 7.

### 3.5 TLS Requirements

For production deployments:

- Implementations MUST use TLS 1.2 or higher.
- Implementations SHOULD use TLS 1.3.
- Implementations MUST present a valid X.509 certificate for the
  agent's hostname.
- Implementations SHOULD support certificate transparency (CT) logs.

### 3.6 Connection Management

- Implementations SHOULD use persistent connections (HTTP keep-alive).
- Implementations SHOULD set reasonable timeouts:
  - Connect timeout: 10 seconds (RECOMMENDED)
  - Read timeout: 30 seconds (RECOMMENDED)
  - Streaming read timeout: none (kept alive by heartbeats)

---

## 4. Discovery -- Level 0 (MANDATORY)

Level 0 is the only MANDATORY conformance level. Every AMP agent MUST
implement the two endpoints defined in this section.

### 4.1 Agent Identity Document

```
GET /.well-known/agent.json
```

This endpoint returns the agent's identity document -- a JSON object
describing who the agent is, what it can do, and how to reach it. The
URL follows the Well-Known URIs pattern [RFC 8615].

#### 4.1.1 Request

No request body. No required headers.

```http
GET /.well-known/agent.json HTTP/1.1
Host: bakery.example.com
Accept: application/json
```

#### 4.1.2 Response

The response MUST be a JSON object with `Content-Type: application/json`.

**Required fields** (MUST be present):

| Field              | Type     | Description                                        |
|--------------------|----------|----------------------------------------------------|
| `protocol_version` | string   | Semantic version of the AMP protocol (e.g., `"1.0.0"`) |
| `identifiers`      | string[] | All `agent://` URIs for this agent                 |
| `endpoint`         | string   | HTTPS URL for `POST /agent/message`                |

**Optional fields** (MAY be present):

| Field               | Type     | Description                                              |
|----------------------|----------|----------------------------------------------------------|
| `jwks_url`           | string   | URL to the agent's JWKS endpoint for key discovery       |
| `capabilities`       | object   | Capability groups and computed level (see Section 17)    |
| `constraints`        | object   | Resource constraints (max message size, rate limits)     |
| `security`           | object   | Authentication methods, trust requirements               |
| `billing`            | object   | Cost model and payment information                       |
| `streaming`          | object   | Streaming configuration (heartbeat interval, etc.)       |
| `compliance`         | object   | Jurisdiction, retention, and data handling policies      |
| `languages`          | string[] | BCP 47 language tags the agent supports                  |
| `ttl_seconds`        | integer  | Cache lifetime in seconds (RECOMMENDED default: 3600)    |
| `visibility`         | object   | Visibility level and contact policy                      |
| `supported_schemas`  | string[] | Context schema URNs the agent understands                |
| `status`             | string   | Lifecycle status: `active`, `deactivating`, `decommissioned` |
| `moved_to`           | string   | `agent://` URI this agent has migrated to                |
| `certifications`     | object[] | Compliance certifications (SOC2, ISO 27001, etc.)        |

Implementations MUST allow unknown fields in `agent.json`. Consumers
MUST ignore fields they do not understand.

#### 4.1.3 Example: Minimal Agent

```json
{
  "protocol_version": "1.0.0",
  "identifiers": ["agent://bakery.example.com"],
  "endpoint": "https://bakery.example.com/agent/message"
}
```

#### 4.1.4 Example: Full-Featured Agent

```json
{
  "protocol_version": "1.0.0",
  "identifiers": [
    "agent://bakery.example.com",
    "agent://bakery@registry.example.com"
  ],
  "endpoint": "https://bakery.example.com/agent/message",
  "jwks_url": "https://bakery.example.com/.well-known/agent-keys.json",
  "capabilities": {
    "groups": ["messaging", "tools", "streaming", "delegation"],
    "level": 3
  },
  "constraints": {
    "max_message_bytes": 10485760,
    "max_concurrent_tasks": 50,
    "max_delegation_depth": 5
  },
  "security": {
    "auth_methods": ["jwt", "api_key"],
    "require_auth_for": ["tools", "delegation"]
  },
  "billing": {
    "model": "per_task",
    "currency": "USD"
  },
  "streaming": {
    "heartbeat_interval_seconds": 15,
    "max_channels": 10
  },
  "compliance": {
    "jurisdiction": "US",
    "frameworks": ["SOC2"],
    "retention": {
      "messages": "30d",
      "task_history": "90d",
      "audit_logs": "365d"
    }
  },
  "languages": ["en", "es"],
  "ttl_seconds": 3600,
  "visibility": {
    "level": "public",
    "contact_policy": "open"
  },
  "supported_schemas": [
    "urn:schema:purchase-order:v1",
    "urn:schema:invoice:v2"
  ],
  "status": "active",
  "certifications": [
    {
      "type": "SOC2",
      "url": "https://bakery.example.com/compliance/soc2",
      "valid_until": "2027-01-15"
    }
  ]
}
```

#### 4.1.5 Caching

- `agent.json` SHOULD include a `ttl_seconds` field indicating how long
  consumers MAY cache the document.
- If `ttl_seconds` is absent, consumers SHOULD assume a default TTL of
  3600 seconds (1 hour).
- Consumers SHOULD cache `agent.json` and MUST NOT fetch it on every
  message.
- Implementations SHOULD set appropriate HTTP `Cache-Control` headers
  consistent with `ttl_seconds`.

#### 4.1.6 Conditional Serving

Implementations MAY serve different versions of `agent.json` based on
the caller's trust tier. For example:

- **PUBLIC visibility**: Return full document to all callers.
- **AUTHENTICATED visibility**: Return full document to verified
  callers; return a stub (only `protocol_version`, `identifiers`,
  `endpoint`, `visibility`) to unauthenticated callers.
- **PRIVATE visibility**: Return full document to internal/owner
  callers; return HTTP 401 to others.
- **HIDDEN visibility**: Return full document to internal/owner
  callers; return HTTP 404 to others.

When conditional serving is in use, the server SHOULD examine the
`Authorization` header of the `GET /.well-known/agent.json` request
to determine the caller's trust tier.

#### 4.1.7 Agent Lifecycle

The `status` field indicates the agent's lifecycle state:

| Status           | Meaning                                                |
|------------------|--------------------------------------------------------|
| `active`         | Agent is operational and accepting messages            |
| `deactivating`   | Agent is winding down; new tasks SHOULD NOT be sent    |
| `decommissioned` | Agent is permanently offline; `moved_to` MAY be set    |

When `status` is `decommissioned` and `moved_to` is present, consumers
SHOULD follow the `moved_to` URI. Consumers MUST validate that
`moved_to` is a well-formed `agent://` URI before following it.

### 4.2 Health Check

```
GET /agent/health
```

This endpoint returns the agent's operational status. It is intended for
monitoring, load balancers, and liveness probes.

#### 4.2.1 Request

No request body. No required headers.

```http
GET /agent/health HTTP/1.1
Host: bakery.example.com
Accept: application/json
```

#### 4.2.2 Response

The response MUST be a JSON object with `Content-Type: application/json`.

**Required fields** (MUST be present):

| Field              | Type   | Description                                    |
|--------------------|--------|------------------------------------------------|
| `status`           | string | `"healthy"` or `"unhealthy"`                   |
| `protocol_version` | string | Semantic version of the AMP protocol in use    |

**Optional fields** (MAY be present):

| Field            | Type    | Description                                      |
|------------------|---------|--------------------------------------------------|
| `uptime_seconds` | integer | Seconds since the agent process started          |
| `current_tasks`  | integer | Number of tasks currently being processed        |
| `max_tasks`      | integer | Maximum concurrent tasks the agent supports      |

#### 4.2.3 Example

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "healthy",
  "protocol_version": "1.0.0",
  "uptime_seconds": 86400,
  "current_tasks": 3,
  "max_tasks": 50
}
```

#### 4.2.4 Status Codes

| Code | Condition                                    |
|------|----------------------------------------------|
| 200  | Agent is healthy                             |
| 503  | Agent is unhealthy or temporarily unavailable |

### 4.3 JWKS Endpoint

```
GET /.well-known/agent-keys.json
```

If the agent's `agent.json` includes a `jwks_url` field, that URL MUST
serve a JSON Web Key Set [RFC 7517] containing the agent's public keys.

This endpoint is OPTIONAL. It is REQUIRED only for agents that
authenticate via JWT or sign delegation chains.

#### 4.3.1 Example

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      "kid": "key-2026-04",
      "use": "sig"
    }
  ]
}
```

#### 4.3.2 Key Rotation

- Implementations SHOULD serve both the current and previous key to
  allow for rotation lag.
- Consumers SHOULD cache JWKS responses for the duration indicated by
  HTTP `Cache-Control` headers.
- Consumers SHOULD refresh the JWKS if signature verification fails
  with the cached key set.

---

## 5. Messaging -- Level 1

Level 1 agents accept and process messages via a single HTTP endpoint.

### 5.1 The Message Endpoint

```
POST /agent/message
```

This is the primary communication endpoint. ALL AMP message types are
delivered as POST requests to this single URL. The `body_type` field
within the JSON envelope determines the semantic meaning.

#### 5.1.1 Request Format

The request body MUST be a JSON object conforming to the `AgentMessage`
envelope schema:

| Field       | Type   | Required | Description                                          |
|-------------|--------|----------|------------------------------------------------------|
| `sender`    | string | YES      | Agent address of the sender (`agent://` URI, `@slug`, or URL) |
| `recipient` | string | YES      | Agent address of the intended recipient              |
| `id`        | string | YES      | Unique message identifier (UUID v4 RECOMMENDED)      |
| `body_type` | string | YES      | Dot-namespaced type string (e.g., `"message"`, `"task.create"`) |
| `headers`   | object | NO       | Extensible key-value headers (see Section 14)        |
| `body`      | any    | NO       | Message payload, structure determined by `body_type` |

#### 5.1.2 Request Example

```http
POST /agent/message HTTP/1.1
Host: bakery.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJFZERTQSJ9...

{
  "sender": "agent://alice@registry.example.com",
  "recipient": "agent://bakery.example.com",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "body_type": "task.create",
  "headers": {
    "Protocol-Version": "1.0.0",
    "Priority": "normal",
    "Callback-URL": "https://alice.example.com/callbacks/task-result",
    "Nonce": "a1b2c3d4e5f6",
    "Trace-Id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "Span-Id": "00f067aa0ba902b7"
  },
  "body": {
    "description": "Find the nearest open bakery and order 2 croissants",
    "priority": "normal",
    "timeout_seconds": 300,
    "context": {
      "location": "40.7128,-74.0060",
      "dietary": "no-gluten"
    }
  }
}
```

#### 5.1.3 Envelope Rules

1. The `sender` field MUST contain a valid agent address. Within a
   platform boundary, bare slugs (`@alice`) are acceptable. For
   cross-platform communication, senders MUST use full `agent://` URIs.

2. The `recipient` field MUST match one of the receiving agent's
   declared identifiers.

3. The `id` field MUST be unique per sender. Implementations SHOULD use
   UUID v4. Receivers SHOULD use this field for deduplication (see
   Section 12.5).

4. The `body_type` field determines which schema applies to the `body`.
   See Section 16 for the canonical body type registry.

5. The `headers` field is an open-ended key-value map. Receivers MUST
   ignore headers they do not understand. This is the primary
   extensibility mechanism.

6. The `body` field MAY be any JSON value (object, array, string,
   number, boolean, or null). Its structure is determined by the
   `body_type`. For unknown body types, receivers MUST accept the body
   without schema validation.

#### 5.1.4 Unknown Body Types

Receivers MUST accept messages with unknown `body_type` values. The
receiver MAY:

- Pass the message through to a handler that understands it
- Store the message for later processing
- Return a `task.reject` response indicating the body type is not
  supported
- Silently acknowledge receipt

Receivers MUST NOT reject unknown body types at the transport level
(i.e., MUST NOT return HTTP 400 solely because the body type is
unrecognized).

#### 5.1.5 Unknown Headers

Receivers MUST ignore headers they do not understand. This rule is
critical for forward compatibility. A sender using protocol version
1.2 that sends a header introduced in 1.2 MUST NOT cause a version 1.0
receiver to fail.

### 5.2 Response Format

The response to `POST /agent/message` indicates whether the message was
accepted for processing. The response body MAY contain a synchronous
reply or an asynchronous acknowledgment.

#### 5.2.1 Synchronous Response (200 OK)

When the receiver can produce a complete result immediately:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "sender": "agent://bakery.example.com",
  "recipient": "agent://alice@registry.example.com",
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "body_type": "task.complete",
  "headers": {
    "In-Reply-To": "550e8400-e29b-41d4-a716-446655440000",
    "Protocol-Version": "1.0.0"
  },
  "body": {
    "task_id": "550e8400-e29b-41d4-a716-446655440000",
    "result": {
      "bakery": "La Boulangerie",
      "order_id": "ORD-2026-0410-001",
      "items": [{"item": "croissant", "qty": 2}],
      "total_usd": 7.50
    },
    "duration_seconds": 2.3,
    "cost_usd": 0.002
  }
}
```

#### 5.2.2 Asynchronous Acknowledgment (202 Accepted)

When the receiver cannot produce an immediate result:

```http
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "sender": "agent://bakery.example.com",
  "recipient": "agent://alice@registry.example.com",
  "id": "660e8400-e29b-41d4-a716-446655440002",
  "body_type": "task.acknowledge",
  "headers": {
    "In-Reply-To": "550e8400-e29b-41d4-a716-446655440000",
    "Protocol-Version": "1.0.0",
    "Poll-Interval": "5"
  },
  "body": {
    "task_id": "550e8400-e29b-41d4-a716-446655440000",
    "estimated_duration_seconds": 60,
    "message": "Looking for bakeries near your location"
  }
}
```

#### 5.2.3 Rejection (200 OK with task.reject)

When the receiver declines to process the message:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "sender": "agent://bakery.example.com",
  "recipient": "agent://alice@registry.example.com",
  "id": "660e8400-e29b-41d4-a716-446655440003",
  "body_type": "task.reject",
  "headers": {
    "In-Reply-To": "550e8400-e29b-41d4-a716-446655440000"
  },
  "body": {
    "task_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "Bakery is closed",
    "detail": "All bakeries within 5km radius are closed at this hour",
    "retry_eligible": true,
    "retry_after_seconds": 28800
  }
}
```

---

## 6. Response Semantics

### 6.1 Delivery Mechanisms

When a receiver returns HTTP 202 (Accepted), the eventual result MUST
be delivered through one of three mechanisms. The SENDER chooses the
mechanism; the receiver MUST support at least one.

#### 6.1.1 Callback (Push)

The sender includes a `Callback-URL` header in the original message.
The receiver delivers the result by POSTing an `AgentMessage` envelope
to that URL.

**Sender requirements:**
- The `Callback-URL` MUST be an HTTPS URL.
- The sender MUST accept POST requests at the callback URL.
- The sender SHOULD keep the callback URL valid for at least the
  duration of the task timeout.

**Receiver requirements:**
- The receiver MUST validate the callback URL before accepting the
  message (see Section 12.8).
- The receiver MUST deliver the result as a POST request containing an
  `AgentMessage` envelope.
- The receiver SHOULD retry delivery on failure using exponential
  backoff: 1 second, 5 seconds, 25 seconds (3 attempts total).
- The receiver MUST perform SSRF validation on the callback URL. The
  URL MUST NOT resolve to a private, loopback, or link-local IP
  address.
- The receiver SHOULD pin DNS resolution on the first attempt and reuse
  the resolved IP for all retry attempts to prevent DNS rebinding
  attacks.

**Callback delivery example:**

```http
POST /callbacks/task-result HTTP/1.1
Host: alice.example.com
Content-Type: application/json

{
  "sender": "agent://bakery.example.com",
  "recipient": "agent://alice@registry.example.com",
  "id": "770e8400-e29b-41d4-a716-446655440004",
  "body_type": "task.complete",
  "headers": {
    "In-Reply-To": "550e8400-e29b-41d4-a716-446655440000"
  },
  "body": {
    "task_id": "550e8400-e29b-41d4-a716-446655440000",
    "result": {"bakery": "La Boulangerie", "order_id": "ORD-001"}
  }
}
```

#### 6.1.2 Polling (Pull)

The sender polls the receiver for the task status using the task ID.

```
GET /agent/tasks/{task_id}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "processing",
  "progress": {
    "percentage": 45,
    "message": "Found 3 bakeries, checking availability"
  },
  "created_at": "2026-04-10T14:30:00Z",
  "updated_at": "2026-04-10T14:30:05Z"
}
```

When the task is complete:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "result": {
    "sender": "agent://bakery.example.com",
    "recipient": "agent://alice@registry.example.com",
    "id": "770e8400-e29b-41d4-a716-446655440004",
    "body_type": "task.complete",
    "headers": {
      "In-Reply-To": "550e8400-e29b-41d4-a716-446655440000"
    },
    "body": {
      "task_id": "550e8400-e29b-41d4-a716-446655440000",
      "result": {"bakery": "La Boulangerie", "order_id": "ORD-001"}
    }
  },
  "created_at": "2026-04-10T14:30:00Z",
  "completed_at": "2026-04-10T14:30:12Z"
}
```

**Polling guidance:**
- The receiver SHOULD include a `Poll-Interval` header in the 202
  response indicating the RECOMMENDED polling interval in seconds.
- The sender SHOULD NOT poll more frequently than the indicated
  interval.
- If no `Poll-Interval` is provided, the sender SHOULD default to
  5-second intervals.

#### 6.1.3 Streaming (Push via SSE)

The sender opens an SSE connection to receive real-time updates. See
Section 8 for full streaming semantics.

### 6.2 Result Delivery Selection

The sender indicates its preferred delivery mechanism through headers:

| Header         | Mechanism                                       |
|----------------|-------------------------------------------------|
| `Callback-URL` | Result delivered via POST to the callback URL   |
| (none)         | Sender will poll `GET /agent/tasks/{task_id}`   |

If the sender includes `Callback-URL`, the receiver MUST attempt
callback delivery. If callback delivery fails after all retries, the
result MUST still be available via polling.

Streaming is an additional channel that operates independently. The
sender MAY use streaming AND callback/polling simultaneously.

---

## 7. Error Format

### 7.1 Problem Details (RFC 7807)

All error responses MUST use the Problem Details format defined in
RFC 7807 [RFC 7807]. The `Content-Type` for error responses MUST be
`application/problem+json`.

#### 7.1.1 Error Object Schema

| Field      | Type    | Required | Description                                  |
|------------|---------|----------|----------------------------------------------|
| `type`     | string  | YES      | URI identifying the error type               |
| `title`    | string  | YES      | Short human-readable summary                 |
| `status`   | integer | YES      | HTTP status code                             |
| `detail`   | string  | NO       | Human-readable explanation specific to this occurrence |
| `instance` | string  | NO       | URI identifying the specific occurrence      |

Implementations MAY include additional fields as extension members.

#### 7.1.2 Error Type URIs

Error type URIs MUST use the `urn:amp:error:` prefix for standard AMP
errors. Implementations MAY define custom error types using
reverse-domain notation (e.g., `urn:com.example:error:custom`).

### 7.2 Standard Error Types

The following error types are defined by this specification:

#### 7.2.1 400 -- Invalid Message

```json
{
  "type": "urn:amp:error:invalid-message",
  "title": "Invalid Message",
  "status": 400,
  "detail": "Field 'sender' is required but was not provided",
  "instance": "/agent/message"
}
```

Returned when the request body fails envelope validation. The `detail`
field SHOULD indicate which field or constraint was violated.

#### 7.2.2 401 -- Unauthorized

```json
{
  "type": "urn:amp:error:unauthorized",
  "title": "Unauthorized",
  "status": 401,
  "detail": "No valid authentication credentials provided"
}
```

Returned when the agent requires authentication but the request lacks
valid credentials. The response SHOULD include a `WWW-Authenticate`
header indicating the accepted authentication methods.

#### 7.2.3 403 -- Forbidden

```json
{
  "type": "urn:amp:error:forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "Contact policy 'verified_only' requires verified trust tier"
}
```

Returned when the sender's trust tier is insufficient for the requested
operation.

#### 7.2.4 404 -- Not Found

```json
{
  "type": "urn:amp:error:not-found",
  "title": "Not Found",
  "status": 404,
  "detail": "No agent exists at this address"
}
```

Returned when the requested resource does not exist, or when an agent
with HIDDEN visibility denies the existence of the resource.

#### 7.2.5 406 -- Version Mismatch

```json
{
  "type": "urn:amp:error:version-mismatch",
  "title": "Protocol Version Not Supported",
  "status": 406,
  "detail": "Requested version '2.0.0' is not supported. Supported: 1.0.0, 0.1.0",
  "supported_versions": ["1.0.0", "0.1.0"]
}
```

Returned when the `Accept-Version` header requests a protocol version
the receiver does not support.

#### 7.2.6 408 -- Timeout

```json
{
  "type": "urn:amp:error:timeout",
  "title": "Request Timeout",
  "status": 408,
  "detail": "Task did not complete within the 300-second deadline"
}
```

Returned when a synchronous request exceeds the timeout.

#### 7.2.7 409 -- Conflict

```json
{
  "type": "urn:amp:error:nonce-replay",
  "title": "Nonce Already Used",
  "status": 409,
  "detail": "Nonce 'a1b2c3d4e5f6' has already been seen within the replay window"
}
```

Returned when a nonce has been replayed, or when a message ID has
already been processed (deduplication conflict).

#### 7.2.8 410 -- Session Expired

```json
{
  "type": "urn:amp:error:session-expired",
  "title": "Session Expired",
  "status": 410,
  "detail": "Session 'sess-001' has expired or been closed"
}
```

Returned when a message references a session that no longer exists.

#### 7.2.9 413 -- Payload Too Large

```json
{
  "type": "urn:amp:error:payload-too-large",
  "title": "Payload Too Large",
  "status": 413,
  "detail": "Message size 15728640 bytes exceeds maximum of 10485760 bytes",
  "max_bytes": 10485760
}
```

Returned when the request body exceeds the agent's maximum message size.

#### 7.2.10 429 -- Rate Limited

```json
{
  "type": "urn:amp:error:rate-limited",
  "title": "Rate Limited",
  "status": 429,
  "detail": "Sender exceeded 60 requests per minute",
  "retry_after_seconds": 30
}
```

Returned when the sender has exceeded the rate limit. The response
MUST include a `Retry-After` HTTP header and SHOULD include
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`
headers.

#### 7.2.11 500 -- Internal Error

```json
{
  "type": "urn:amp:error:internal-error",
  "title": "Internal Error",
  "status": 500,
  "detail": "An unexpected error occurred while processing the message"
}
```

Returned when the receiver encounters an unrecoverable internal error.
The `detail` field SHOULD NOT expose implementation details that could
be exploited.

#### 7.2.12 501 -- Not Implemented

```json
{
  "type": "urn:amp:error:not-implemented",
  "title": "Not Implemented",
  "status": 501,
  "detail": "This agent does not support the 'delegation' capability group"
}
```

Returned when a message requires a capability the agent has not
implemented.

#### 7.2.13 503 -- Unavailable

```json
{
  "type": "urn:amp:error:unavailable",
  "title": "Service Unavailable",
  "status": 503,
  "detail": "Agent is temporarily overloaded",
  "retry_after_seconds": 60
}
```

Returned when the agent is temporarily unable to process requests.
The response SHOULD include a `Retry-After` HTTP header.

---

## 8. Streaming

### 8.1 Overview

AMP streaming uses Server-Sent Events (SSE) [W3C SSE] to deliver
real-time processing updates from a receiver to a sender. Streaming
is OPTIONAL (Level 3+).

### 8.2 Stream Endpoint

```
GET /agent/stream
```

#### 8.2.1 Request

```http
GET /agent/stream?session_id=sess-001&task_id=task-001 HTTP/1.1
Host: bakery.example.com
Accept: text/event-stream
Authorization: Bearer eyJhbGciOiJFZERTQSJ9...
```

**Query parameters** (all OPTIONAL):

| Parameter    | Description                                    |
|--------------|------------------------------------------------|
| `session_id` | Filter events to a specific session           |
| `task_id`    | Filter events to a specific task              |
| `channel_id` | Filter events to a specific multiplexed channel |
| `last_seq`   | Resume from a specific sequence number        |

#### 8.2.2 Response Headers

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no
```

### 8.3 Event Format

Each event follows the SSE specification:

```
id: <event_id>
event: <event_type>
data: <json_payload>

```

Events are separated by a blank line. The `data` field MUST be a
JSON-encoded object.

#### 8.3.1 Event Fields

| Field   | Required | Description                                     |
|---------|----------|-------------------------------------------------|
| `id`    | NO       | Event ID for reconnection via `Last-Event-ID`   |
| `event` | YES      | One of the 17 defined event types (see 8.4)     |
| `data`  | YES      | JSON object with event-specific payload         |

All events carry a `seq` field within the `data` payload -- a
monotonically increasing integer starting at 1 for each stream
connection.

### 8.4 Event Types

| Event Type             | Description                                | Category     |
|------------------------|--------------------------------------------|--------------|
| `thinking`             | Agent is reasoning                         | Processing   |
| `tool_call`            | Agent is invoking a tool                   | Processing   |
| `tool_result`          | Tool returned a result                     | Processing   |
| `text_delta`           | Partial text response (streaming output)   | Processing   |
| `state_change`         | Task status changed                        | Lifecycle    |
| `agent_call`           | Agent is delegating to another agent       | Delegation   |
| `agent_result`         | Delegated agent returned a result          | Delegation   |
| `error`                | An error occurred                          | Error        |
| `heartbeat`            | Keepalive (no payload required)            | Control      |
| `done`                 | Final event -- stream complete             | Control      |
| `stream.ack`           | Client acknowledges processed events       | Backpressure |
| `stream.pause`         | Server pauses the stream                   | Backpressure |
| `stream.resume`        | Client signals readiness for more events   | Backpressure |
| `stream.channel_open`  | Open a logical multiplexed channel         | Multiplexing |
| `stream.channel_close` | Close a logical multiplexed channel        | Multiplexing |
| `stream.checkpoint`    | Periodic state snapshot for reconnection   | Reliability  |
| `stream.auth_refresh`  | Mid-stream token renewal                   | Security     |

#### 8.4.1 Processing Events

**thinking**

```
event: thinking
data: {"seq": 1, "message": "Searching for bakeries near the specified location"}

```

**tool_call**

```
event: tool_call
data: {"seq": 2, "tool": "geocode_search", "parameters": {"query": "bakery", "lat": 40.7128, "lon": -74.006, "radius_km": 5}}

```

**tool_result**

```
event: tool_result
data: {"seq": 3, "tool": "geocode_search", "result": {"matches": 3, "nearest": "La Boulangerie"}}

```

**text_delta**

```
event: text_delta
data: {"seq": 4, "delta": "I found La Boulangerie, "}

event: text_delta
data: {"seq": 5, "delta": "which is 0.8km from your location."}

```

**state_change**

```
event: state_change
data: {"seq": 6, "task_id": "task-001", "from": "processing", "to": "completed"}

```

#### 8.4.2 Control Events

**heartbeat**

```
event: heartbeat
data: {"seq": 7}

```

Heartbeats MUST be sent at a regular interval to keep the connection
alive. The RECOMMENDED interval is 15 seconds. The actual interval is
implementation-defined and SHOULD be declared in the `streaming`
section of `agent.json`.

**done**

```
event: done
data: {"seq": 8, "task_id": "task-001"}

```

The `done` event signals that no more events will be emitted for the
indicated task (or for the entire stream if `task_id` is absent).
After receiving `done`, the client MAY close the connection.

### 8.5 Reconnection

Clients SHOULD implement automatic reconnection using the SSE
`Last-Event-ID` mechanism:

1. The client records the `id` field of the last received event.
2. On disconnection, the client reconnects with:
   ```
   Last-Event-ID: <last_event_id>
   ```
3. The server resumes the stream from the event after the specified ID.

If the server cannot resume (e.g., events have been purged), it MUST
start a fresh stream and SHOULD emit a `stream.checkpoint` event with
the current state.

### 8.6 Backpressure

Backpressure prevents a fast producer from overwhelming a slow consumer.

#### 8.6.1 Stream Acknowledgment

The client sends `stream.ack` events to indicate which events have been
processed:

```json
{
  "last_seq": 42,
  "timestamp": "2026-04-10T14:30:15Z"
}
```

The client SHOULD send an acknowledgment at least every 10 events or
every 5 seconds, whichever comes first.

#### 8.6.2 Stream Pause

When the server detects the client is falling behind (e.g., no `ack`
for 30+ events), it emits a `stream.pause` event:

```
event: stream.pause
data: {"reason": "client_behind", "resume_after_ack": 42}

```

The server MUST stop emitting new events (except heartbeats) until the
client catches up.

#### 8.6.3 Stream Resume

The client signals readiness by sending a `stream.resume`:

```json
{
  "from_seq": 42,
  "buffer_capacity": 100
}
```

The backpressure implementation strategy (ACK frequency, buffer sizing,
pause thresholds) is guidance. Implementations MAY use different
strategies as long as the event types are respected.

### 8.7 Channel Multiplexing

A single SSE connection MAY carry events for multiple logical channels
(e.g., multiple concurrent tasks).

#### 8.7.1 Opening a Channel

```
event: stream.channel_open
data: {"channel_id": "ch-001", "task_id": "task-001", "created_at": "2026-04-10T14:30:00Z"}

```

All subsequent events for the channel include the `channel_id` in
the `Stream-Channel` header of the envelope or as a field in the
event data.

#### 8.7.2 Closing a Channel

```
event: stream.channel_close
data: {"channel_id": "ch-001", "reason": "complete"}

```

Valid close reasons: `complete`, `error`, `timeout`.

### 8.8 Checkpointing

The server SHOULD periodically emit `stream.checkpoint` events to
enable efficient reconnection:

```
event: stream.checkpoint
data: {"checkpoint_id": "cp-042", "seq": 100, "state_snapshot": {"active_tasks": ["task-001"], "channels": ["ch-001"]}, "timestamp": "2026-04-10T14:35:00Z"}

```

When reconnecting, clients MAY provide the checkpoint ID instead of a
sequence number. The server resumes from the checkpoint state rather
than replaying individual events.

### 8.9 Stream Authentication Refresh

For long-lived streams, authentication tokens may expire. The
`stream.auth_refresh` event signals that the client should provide a
new token:

```
event: stream.auth_refresh
data: {"reason": "token_expiring", "expires_in_seconds": 60}

```

The client SHOULD disconnect and reconnect with a fresh token before
the existing token expires.

---

## 9. Sessions

### 9.1 Overview

Sessions provide stateful context across multiple messages between two
agents. Sessions are OPTIONAL (Level 4+).

Sessions may be established in two ways:

1. **Explicit handshake**: A three-phase protocol that negotiates
   capabilities and establishes cryptographic binding.
2. **Implicit sessions**: The sender includes a `Session-Id` header
   without a prior handshake. The receiver MAY accept or reject the
   implicit session.

### 9.2 Three-Phase Handshake

#### 9.2.1 Phase 1: Init

The client sends a `session.init` message to propose a new session:

```http
POST /agent/message HTTP/1.1
Host: bakery.example.com
Content-Type: application/json

{
  "sender": "agent://alice@registry.example.com",
  "recipient": "agent://bakery.example.com",
  "id": "msg-init-001",
  "body_type": "session.init",
  "headers": {
    "Protocol-Version": "1.0.0"
  },
  "body": {
    "proposed_capabilities": ["messaging", "tools", "streaming"],
    "proposed_version": "1.0.0",
    "client_nonce": "8f5d0e1c8e2cd9f75cc226ba5bd868d8323fde87fa49fa1008738307507a5bfe",
    "client_ephemeral_key": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
    "conversation_id": "conv-bakery-order-001",
    "previous_session_id": null
  }
}
```

**`client_nonce` requirements:**
- MUST be a 256-bit (64 hex character) cryptographically random value.
- MUST be globally unique.
- Implementations SHOULD use `secrets.token_hex(32)` or equivalent.

**`client_ephemeral_key` requirements:**
- The client's ephemeral X25519 public key (RFC 7748): the raw 32-byte
  key, base64url-encoded without padding (43 characters).
- MUST be generated fresh for every handshake, and the private half
  MUST NOT be reused or persisted.
- REQUIRED for an explicit handshake. A server MUST reject a
  `session.init` that lacks a valid `client_ephemeral_key` (in the
  reference implementation, `server_accept_init` raises
  `SessionBindingError`).

The handshake examples in this section use the values from
`tests/vectors/session_binding.json`, so every derived value below can
be checked.

#### 9.2.2 Phase 2: Established

The server responds with a `session.established` message:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "sender": "agent://bakery.example.com",
  "recipient": "agent://alice@registry.example.com",
  "id": "msg-est-001",
  "body_type": "session.established",
  "headers": {
    "In-Reply-To": "msg-init-001",
    "Session-Id": "sess-a1b2c3d4"
  },
  "body": {
    "session_id": "sess-a1b2c3d4",
    "negotiated_capabilities": ["messaging", "tools"],
    "negotiated_version": "1.0.0",
    "trust_tier": "verified",
    "trust_score": 650,
    "session_ttl_seconds": 3600,
    "server_nonce": "e9aed25045fd43347c57f716a640e6508743d63c8a09e9c94d7401d7e8032af6",
    "server_ephemeral_key": "Ykayyx5HGJDopXZqR3IAG3CRGLqBwERP782mxog3gls",
    "confirm_nonce": "88f0ced1ef92f170bf4375795c8d8181",
    "resumed": false
  }
}
```

The `negotiated_capabilities` field contains the intersection of the
client's proposed capabilities and the server's supported capabilities.

The server:

- MUST generate a fresh `server_nonce` (256-bit, 64 hex characters).
- MUST generate a fresh ephemeral X25519 key pair and send the public
  key as `server_ephemeral_key` (raw 32 bytes, base64url without
  padding).
- MUST issue a single-use, unpredictable `confirm_nonce`. The reference
  implementation uses 128 bits, as 32 hex characters.
- MUST derive the binding key itself (Section 9.3.1) and MUST NOT send
  it.

`binding_token` is a **deprecated** field. It used to carry the binding
secret in the clear. Servers MUST NOT send it, and clients MUST ignore
it if it is present.

Clients MUST refuse a `session.established` that has no
`server_ephemeral_key`, and MUST abort the handshake. Such a response
comes from an unbound or legacy cleartext-token server.

#### 9.2.3 Phase 3: Confirm

The client derives the binding key (Section 9.3.1) and proves that it
holds the key:

```http
POST /agent/message HTTP/1.1
Host: bakery.example.com
Content-Type: application/json

{
  "sender": "agent://alice@registry.example.com",
  "recipient": "agent://bakery.example.com",
  "id": "msg-confirm-001",
  "body_type": "session.confirm",
  "headers": {
    "Session-Id": "sess-a1b2c3d4"
  },
  "body": {
    "session_id": "sess-a1b2c3d4",
    "binding_proof": "fc57566f1a61e05b450302906987f4961d1ebea4db7fc887fb5f0f68f39a0f1c",
    "confirm_nonce": "88f0ced1ef92f170bf4375795c8d8181"
  }
}
```

`session.confirm` MUST echo the `confirm_nonce` from
`session.established`. Before the session moves to CONFIRMED, the
server MUST check, in this order:

1. `session_id` equals the session it established.
2. `confirm_nonce` equals the nonce it issued for this session.
3. `binding_proof` verifies (Section 9.3.1), compared in constant time.
4. The confirm nonce has not been consumed before. The server then
   consumes it, so that it can never be used again.

If any check fails, the server MUST reject the confirm and MUST NOT
advance the session. A replayed or unknown `confirm_nonce` is a replay
attempt. A session MUST NOT become ACTIVE without a verified
`binding_proof`.

### 9.3 Session Binding (X25519 + HKDF-SHA256 + HMAC-SHA256)

Session binding prevents session hijacking. Knowing the session ID is
not enough to send messages in the session. Because the binding key is
agreed with ephemeral X25519 and never sent, a passive observer of the
handshake cannot compute it either, even without TLS.

The key agreement itself is unauthenticated. To stop an active
man-in-the-middle, the handshake messages MUST be authenticated, either
by the transport (TLS with a verified server certificate, Section 3.5)
or by message signatures (Section 12.15).

Notation in this section:

- `||` is concatenation.
- `0x00` is a single NUL byte.
- Every string is encoded as UTF-8.
- `client_pub` and `server_pub` are `client_ephemeral_key` and
  `server_ephemeral_key` exactly as sent, as base64url strings.

#### 9.3.1 Binding Key and Binding Proof

Each peer computes the X25519 shared secret from its own ephemeral
private key and the peer's ephemeral public key. It then derives the
binding key:

```
shared = X25519(own_private_key, peer_public_key)       ; 32 bytes
key    = lowercase-hex( HKDF-SHA256(
           ikm  = shared,
           salt = client_nonce || 0x00 || server_nonce,
           info = "ampro-session-binding-v1" || 0x00 || session_id || 0x00 ||
                  client_pub || 0x00 || server_pub,
           L    = 32) )                                  ; 64 hex characters
```

Peers MUST reject:

- a peer public key that does not decode to exactly 32 bytes;
- an all-zero shared secret, which comes from a low-order point.

The key is never transmitted.

The client proves possession of the key in `session.confirm`:

```
binding_proof = lowercase-hex( HMAC-SHA256(
  key = UTF-8(key),                 ; the 64-character hex string, not the raw 32 bytes
  msg = "ampro-session-confirm-v1" || 0x00 || session_id || 0x00 ||
        client_nonce || 0x00 || server_nonce || 0x00 || confirm_nonce || 0x00 ||
        client_pub || 0x00 || server_pub ) )
```

The server MUST recompute this value and verify it before CONFIRMED
(Section 9.2.3). For the example handshake above, the binding key is
`3f866e202d33baa56a5c45282fee3a3ede673b6043ea1b5c2bacce0e76602007`.

Note on pre-shared keys: deployments that already share a secret
out-of-band MAY derive a token as
`HMAC-SHA256(psk, client_nonce || 0x00 || server_nonce || 0x00 || session_id)`
(reference: `derive_binding_token`). This derivation is not part of the
handshake, and it is only as secret as the PSK.

#### 9.3.2 Per-Message Binding

Every message within a bound session includes a `Session-Binding`
header:

```
Session-Binding = lowercase-hex( HMAC-SHA256(
  key = UTF-8(key),
  msg = session_id || 0x00 || message_id || 0x00 ||
        lowercase-hex( SHA-256( canonical_json(body) ) ) ) )
```

- `message_id` is the envelope `id`.
- `body` is the envelope `body` as sent. A `null` or absent body hashes
  as the four bytes `null`.
- `canonical_json` sorts object keys and uses the separators `,` and `:`
  with no other whitespace.
- Non-ASCII characters are emitted as raw UTF-8, not `\u` escapes.
- `NaN` and `Infinity` are not allowed.

Because the body digest is covered, a captured `Session-Binding` value
cannot be reused with a different body.

The receiver MUST verify this HMAC using constant-time comparison. It
MUST reject a message in a bound session whose `Session-Binding` is
missing or invalid.

### 9.4 Session State Machine

Sessions follow a well-defined state machine:

```
                  send_init / receive_init
    IDLE ────────────────────────────────────── INIT_SENT / INIT_RECEIVED
                                                        │
                  send_established / receive_established │
                                                        ▼
                                                   ESTABLISHED
                                                        │
                  send_confirm / receive_confirm         │
                                                        ▼
                                                    CONFIRMED
                                                        │
                                       activate         │
                                                        ▼
                    ┌───── pause ──────  ACTIVE  ─────── close ──────┐
                    │                     ▲                          │
                    ▼                     │                          ▼
                  PAUSED ──── resume ─────┘                       CLOSED
                    │                                               ▲
                    └─────────────────── close ──────────────────────┘
```

Valid transitions:

| From          | Event               | To             |
|---------------|----------------------|----------------|
| IDLE          | send_init            | INIT_SENT      |
| IDLE          | receive_init         | INIT_RECEIVED  |
| INIT_SENT     | receive_established  | ESTABLISHED    |
| INIT_RECEIVED | send_established     | ESTABLISHED    |
| ESTABLISHED   | receive_confirm      | CONFIRMED      |
| ESTABLISHED   | send_confirm         | CONFIRMED      |
| CONFIRMED     | activate             | ACTIVE         |
| ACTIVE        | pause                | PAUSED         |
| PAUSED        | resume               | ACTIVE         |
| ACTIVE        | close                | CLOSED         |
| PAUSED        | close                | CLOSED         |
| ESTABLISHED   | close                | CLOSED         |
| CONFIRMED     | close                | CLOSED         |

Implementations MUST reject transitions not listed in this table.

### 9.5 Session Keepalive

Active sessions are kept alive via ping/pong messages:

**Ping:**
```json
{
  "body_type": "session.ping",
  "body": {
    "session_id": "sess-a1b2c3d4",
    "timestamp": "2026-04-10T14:45:00Z"
  }
}
```

**Pong:**
```json
{
  "body_type": "session.pong",
  "body": {
    "session_id": "sess-a1b2c3d4",
    "timestamp": "2026-04-10T14:45:00Z",
    "active_tasks": 2
  }
}
```

### 9.6 Session Pause and Resume

**Pause:**
```json
{
  "body_type": "session.pause",
  "body": {
    "session_id": "sess-a1b2c3d4",
    "reason": "Client going offline temporarily",
    "resume_token": "rt-xyz-789"
  }
}
```

**Resume:**
```json
{
  "body_type": "session.resume",
  "body": {
    "session_id": "sess-a1b2c3d4",
    "resume_token": "rt-xyz-789"
  }
}
```

If a `resume_token` was issued during pause, it MUST be provided
during resume. Implementations MUST reject resume attempts without a
valid token when one was issued.

Resume tokens:

- MUST expire. The default maximum age is 3,600 s (1 hour) from
  creation. Tokens whose creation time is more than 30 s in the future
  MUST also be rejected.
- MUST be integrity-protected with a key held only by the server. The
  reference tokens are HMAC-SHA256 signed, and unsigned tokens are
  rejected unless explicitly enabled for tests.
- MUST stay server-side. The reference `create_resume_token` embeds the
  session binding key in its payload, which is signed but not
  encrypted. Servers MUST NOT send such a token to the peer or log it.
  The `resume_token` value on the wire SHOULD be an opaque random
  handle that the server maps to the stored token.

### 9.7 Session Close

```json
{
  "body_type": "session.close",
  "body": {
    "session_id": "sess-a1b2c3d4",
    "reason": "Task complete, ending conversation"
  }
}
```

After close, the session ID MUST NOT be reused. Any messages referencing
a closed session MUST be rejected with HTTP 410 (Gone).

### 9.8 Implicit Sessions

A sender MAY include a `Session-Id` header on any message without
performing a handshake. This creates an implicit session with the
following properties:

- No capability negotiation (sender assumes the receiver supports
  the required capabilities).
- No cryptographic binding (session ID alone is the session token).
- No guaranteed session TTL.

Receivers MAY accept or reject implicit sessions. If the receiver
requires explicit handshake, it MUST respond with a `task.reject`
body containing `"reason": "handshake_required"`.

---

## 10. Tools -- Level 2

Level 2 agents expose callable tools that other agents can discover
and invoke.

### 10.1 Tool Discovery

```
GET /agent/tools
```

Returns the list of tools the agent exposes.

#### 10.1.1 Request

```http
GET /agent/tools HTTP/1.1
Host: bakery.example.com
Accept: application/json
Authorization: Bearer eyJhbGciOiJFZERTQSJ9...
```

#### 10.1.2 Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "tools": [
    {
      "name": "search_bakeries",
      "description": "Search for bakeries by location and criteria",
      "consent_required": false,
      "parameters": {
        "type": "object",
        "properties": {
          "latitude": {"type": "number"},
          "longitude": {"type": "number"},
          "radius_km": {"type": "number", "default": 5},
          "dietary": {"type": "string", "enum": ["any", "no-gluten", "vegan"]}
        },
        "required": ["latitude", "longitude"]
      },
      "category": "search",
      "tags": ["bakery", "food", "location"]
    },
    {
      "name": "place_order",
      "description": "Place an order at a bakery",
      "consent_required": true,
      "consent_scopes": ["payment:authorize", "order:create"],
      "parameters": {
        "type": "object",
        "properties": {
          "bakery_id": {"type": "string"},
          "items": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "item": {"type": "string"},
                "qty": {"type": "integer", "minimum": 1}
              }
            }
          }
        },
        "required": ["bakery_id", "items"]
      },
      "category": "commerce",
      "tags": ["bakery", "order", "payment"]
    }
  ]
}
```

#### 10.1.3 Tool Schema

Each tool object contains:

| Field              | Type     | Required | Description                                      |
|--------------------|----------|----------|--------------------------------------------------|
| `name`             | string   | YES      | Unique tool name                                 |
| `description`      | string   | YES      | Human-readable description                       |
| `consent_required` | boolean  | NO       | Whether explicit consent is needed (default: false) |
| `consent_scopes`   | string[] | NO       | Scopes required for this tool                    |
| `parameters`       | object   | NO       | JSON Schema for tool input parameters            |
| `category`         | string   | NO       | Tool category for organization                   |
| `tags`             | string[] | NO       | Searchable tags                                  |

### 10.2 Tool Invocation

```
POST /agent/tools/{name}
```

#### 10.2.1 Request

```http
POST /agent/tools/search_bakeries HTTP/1.1
Host: bakery.example.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJFZERTQSJ9...

{
  "latitude": 40.7128,
  "longitude": -74.006,
  "radius_km": 5,
  "dietary": "no-gluten"
}
```

#### 10.2.2 Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "result": {
    "bakeries": [
      {"name": "La Boulangerie", "distance_km": 0.8, "rating": 4.7},
      {"name": "Gluten-Free Heaven", "distance_km": 1.2, "rating": 4.5}
    ]
  }
}
```

#### 10.2.3 Tool Not Found

```http
HTTP/1.1 404 Not Found
Content-Type: application/problem+json

{
  "type": "urn:amp:error:not-found",
  "title": "Tool Not Found",
  "status": 404,
  "detail": "No tool named 'unknown_tool' exists"
}
```

### 10.3 Tool Consent

Tools with `consent_required: true` MUST NOT be invoked without a
prior consent grant.

#### 10.3.1 Consent Request

Sent via `POST /agent/message` with body type `tool.consent_request`:

```json
{
  "body_type": "tool.consent_request",
  "body": {
    "tool_name": "place_order",
    "scopes": ["payment:authorize", "order:create"],
    "reason": "Need to place a bakery order on behalf of the user",
    "session_id": "sess-a1b2c3d4",
    "ttl_seconds": 3600
  }
}
```

#### 10.3.2 Consent Grant

```json
{
  "body_type": "tool.consent_grant",
  "body": {
    "tool_name": "place_order",
    "scopes": ["payment:authorize", "order:create"],
    "grant_id": "grant-xyz-001",
    "valid_for_session": "sess-a1b2c3d4",
    "expires_at": "2026-04-10T15:30:00Z",
    "restrictions": {
      "max_invocations": 3,
      "max_amount_usd": 50.00
    }
  }
}
```

#### 10.3.3 Consent Semantics

- A grant is scoped to a specific session (`valid_for_session`).
- A grant has an expiration time (`expires_at`).
- A grant MAY include `restrictions` limiting how the tool can be used.
- Once a grant expires or the session closes, the grant is void.
- The granting agent MAY revoke consent at any time using
  `data.consent_revoke`.

### 10.4 Tool Detail

```
GET /agent/tools/{name}
```

Returns the full schema for a single tool. Response format is the same
as a single element of the `tools` array from `GET /agent/tools`.

---

## 11. Task Lifecycle -- Level 3

Tasks are the primary unit of work in AMP. A task progresses through a
well-defined set of states, each communicated via a specific body type.

### 11.1 Task State Diagram

```
           task.create / task.delegate
                     │
                     ▼
    ┌── task.acknowledge ──── ACCEPTED ───────────────────────┐
    │                              │                           │
    │                    task.progress (0..N)                   │
    │                              │                           │
    │                    task.input_required ──┐               │
    │                              │           │               │
    │                    (input provided)◄─────┘               │
    │                              │                           │
    │                              ▼                           │
    │              ┌─── task.complete ───── COMPLETED          │
    │              │                                           │
    │              ├─── task.error ──────── FAILED             │
    │              │                                           │
    │              ├─── task.escalate ───── ESCALATED          │
    │              │                                           │
    │              ├─── task.reroute ────── CANCELLED /        │
    │              │                       REDIRECTED          │
    │              │                                           │
    │              └─── task.transfer ──── TRANSFERRED         │
    │                                                          │
    └── task.reject ──────────────────── REJECTED ─────────────┘
```

### 11.2 Creating Tasks

Tasks are created by sending a `task.create` or `task.delegate` message
via `POST /agent/message`:

```json
{
  "body_type": "task.create",
  "body": {
    "description": "Find the nearest open bakery",
    "priority": "normal",
    "timeout_seconds": 300,
    "tools_required": ["search_bakeries"],
    "context": {
      "location": "40.7128,-74.006"
    }
  }
}
```

The receiver responds with one of:

| Response Body Type   | HTTP Status | Meaning                       |
|----------------------|-------------|-------------------------------|
| `task.acknowledge`   | 202         | Task accepted for processing  |
| `task.complete`      | 200         | Task completed synchronously  |
| `task.reject`        | 200         | Task declined                 |
| `task.error`         | 200         | Task failed immediately       |

### 11.3 Progress Updates

While processing, the receiver sends `task.progress` messages to report
incremental status:

```json
{
  "body_type": "task.progress",
  "body": {
    "task_id": "task-001",
    "percentage": 45,
    "message": "Found 3 bakeries, checking availability",
    "estimated_remaining_seconds": 15
  }
}
```

Progress updates are delivered via the callback URL, streaming, or
queued for polling.

### 11.4 Input Required

If the receiver needs additional information to proceed:

```json
{
  "body_type": "task.input_required",
  "body": {
    "task_id": "task-001",
    "reason": "Multiple bakeries found",
    "prompt": "Which bakery would you prefer?",
    "options": ["La Boulangerie", "Gluten-Free Heaven", "Corner Bakery"],
    "timeout_seconds": 120
  }
}
```

The sender responds with a `task.response`:

```json
{
  "body_type": "task.response",
  "body": {
    "task_id": "task-001",
    "text": "La Boulangerie"
  }
}
```

### 11.5 Task Completion

```json
{
  "body_type": "task.complete",
  "body": {
    "task_id": "task-001",
    "result": {
      "bakery": "La Boulangerie",
      "order_id": "ORD-001",
      "items": [{"item": "croissant", "qty": 2}],
      "total_usd": 7.50
    },
    "duration_seconds": 12.3,
    "cost_usd": 0.002,
    "cost_receipt": {
      "agent": "agent://bakery.example.com",
      "cost_usd": 0.002,
      "breakdown": {"llm_tokens": 1500, "tool_calls": 2}
    }
  }
}
```

### 11.6 Task Error

```json
{
  "body_type": "task.error",
  "body": {
    "task_id": "task-001",
    "reason": "bakery_closed",
    "detail": "La Boulangerie is closed on Sundays",
    "retry_eligible": true,
    "retry_after_seconds": 86400,
    "partial_result": {
      "bakeries_checked": 3
    }
  }
}
```

### 11.7 Task Polling

```
GET /agent/tasks/{task_id}
```

Returns the current state of a task:

```json
{
  "task_id": "task-001",
  "status": "processing",
  "body_type": "task.progress",
  "progress": {
    "percentage": 75,
    "message": "Placing order at La Boulangerie"
  },
  "created_at": "2026-04-10T14:30:00Z",
  "updated_at": "2026-04-10T14:30:08Z"
}
```

### 11.8 Task Cancellation

The sender cancels a task using `task.reroute` with `action: "cancel"`:

```json
{
  "body_type": "task.reroute",
  "body": {
    "task_id": "task-001",
    "action": "cancel",
    "reason": "User changed their mind"
  }
}
```

### 11.9 Task Escalation

The receiver escalates a task when it cannot complete it:

```json
{
  "body_type": "task.escalate",
  "body": {
    "task_id": "task-001",
    "escalate_to": "sender_human",
    "reason": "Payment requires human authorization",
    "partial_result": {
      "bakery": "La Boulangerie",
      "items_selected": [{"item": "croissant", "qty": 2}]
    }
  }
}
```

Escalation targets:

| Value           | Meaning                                        |
|-----------------|------------------------------------------------|
| `sender_human`  | Route to the sender's human operator           |
| `local_human`   | Route to the receiver's human operator         |
| `specific`      | Route to a specific agent (set `target` field) |

### 11.10 Task Transfer

Transfers task ownership to another agent:

```json
{
  "body_type": "task.transfer",
  "body": {
    "task_id": "task-001",
    "transfer_to": "agent://specialty-bakery.example.com",
    "reason": "Specialized gluten-free agent can handle this better",
    "context": {"dietary": "no-gluten"},
    "partial_result": {"bakeries_checked": 2}
  }
}
```

### 11.11 Task Delegation

Delegation creates a chain of trust where agents delegate work to
sub-agents:

```json
{
  "body_type": "task.delegate",
  "body": {
    "task_id": "task-002",
    "description": "Search for bakeries within 5km",
    "delegation_chain": [
      {
        "delegator": "agent://owner.example.com",
        "delegate": "agent://manager.example.com",
        "scopes": ["task:*", "data:read"],
        "max_depth": 3,
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "max_fan_out": 3,
        "trust_tier": "verified",
        "jwks_url": "https://owner.example.com/.well-known/jwks.json",
        "chain_budget": "remaining=5.00USD;max=5.00USD",
        "signature": "1JGqdDKauHr2uaNhTzcC9irBaGzTFAA8jmO6ZifwHQoBErLhfcQBh+J6Jwv9LLdv3QyP58GNUAxAhj7N7ipkBQ=="
      }
    ]
  }
}
```

This link is the root of the second case in
`tests/vectors/delegation_chain.json`. It is signed with the RFC 8032
TEST 1 key.

A link has the following fields. Defaults apply when a field is absent,
and the defaults are signed too:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `delegator` | string | required | Agent granting authority (signs the link) |
| `delegate` | string | required | Agent receiving authority |
| `scopes` | string[] | required | Granted scopes |
| `max_depth` | integer | `3` | Maximum number of links, including this one, from this link onward |
| `created_at` | RFC 3339 timestamp | required | MUST carry `Z` or an explicit offset |
| `expires_at` | RFC 3339 timestamp | required | MUST carry `Z` or an explicit offset |
| `max_fan_out` | integer 1..10 | `3` | Maximum sub-delegations issued under this link |
| `trust_tier` | string | `"external"` | Effective trust tier at this link |
| `jwks_url` | string | `""` | Where the delegator's key is published |
| `chain_budget` | string | `""` | `remaining=<n>USD;max=<n>USD`, or empty for no budget |
| `signature` | string | `""` | Standard base64 (with padding) Ed25519 signature by the delegator |

Unknown fields are ignored and are **not** covered by the signature.

#### 11.11.1 Delegation Chain Validation

**Canonical form.** The delegator signs, with Ed25519, the UTF-8 bytes
of a canonical JSON object. That object contains every field in the
table above except `signature`, with defaults filled in, plus:

- `parent_delegate`: the `delegate` of the previous link, or `null` for
  the root link. This binds the signature to one position in one chain,
  so a link cannot be moved into another chain.

The object is serialised as follows:

- Keys are sorted, and the separators are `,` and `:` with no other
  whitespace.
- Non-ASCII characters are emitted as raw UTF-8, not `\u` escapes.
- `scopes` is sorted lexicographically.
- `created_at` and `expires_at` are converted to UTC and rendered as
  `YYYY-MM-DDTHH:MM:SSZ`. When the microsecond component is not zero,
  they are rendered as `YYYY-MM-DDTHH:MM:SS.ffffffZ` (exactly 6
  fractional digits).

Timestamps without a UTC offset (naive timestamps) MUST be rejected.

The verifier rebuilds these bytes from the link it received. The exact
signed strings for every vector case are in `signed_canonical`.

Receivers MUST reject an empty chain, and MUST reject a chain with more
links than the **root** link's `max_depth`. They MUST then validate each
link, in order, and reject the chain at the first failure:

1. **Self-delegation**: `delegator` MUST differ from `delegate`.
2. **Public key lookup**: The delegator's public key MUST be available
   (via JWKS or pre-registered).
3. **Signature verification**: The signature MUST verify over the
   canonical form above.
4. **Expiry check**: `expires_at` MUST be later than now minus 30 s, and
   `created_at` MUST NOT be later than now plus 30 s (30 s is the clock
   skew tolerance).
5. **Depth check**: `max_depth` MUST be at least 1. Every child link MUST
   have `max_depth` ≤ the parent's `max_depth` − 1.
6. **Scope narrowing**: Each child scope MUST be allowed by the parent's
   scopes. A parent scope `*` allows any scope. A parent scope
   `prefix:*` allows any scope that starts with `prefix:`. Any other
   parent scope allows only an exact match. A child link MUST have at
   least one scope. Parent and child scope lists are each limited to
   100 entries.
7. **Chain continuity**: Each link's `delegator` MUST equal the
   previous link's `delegate`.
8. **Temporal nesting**: A child's `created_at` MUST NOT be more than
   30 s earlier than its parent's. A child's `expires_at` MUST NOT be
   more than 30 s later than its parent's.
9. **Fan-out**: A receiver that records how many sub-delegations have
   been issued under each link MUST reject the chain when any
   non-terminal link's count is already ≥ its `max_fan_out`. After
   accepting the chain, it increments the count. The reference
   implementation keys counts by `delegation_link_id`: SHA-256 over the
   root-position canonical bytes || `0x00` || signature. A stateless
   validator cannot enforce fan-out.
10. **Budget**: A non-empty `chain_budget` MUST match the regular
    expression `remaining=(\d+(?:\.\d+)?)USD;max=(\d+(?:\.\d+)?)USD`
    in full, with no prefix or suffix. It MUST satisfy
    0 < `remaining` ≤ `max`. Along the chain, a child's `remaining` MUST
    NOT exceed its parent's `remaining`, and a child's `max` MUST NOT
    exceed its parent's `max`. Once a link carries a budget, every
    descendant MUST carry one, so a child cannot drop its parent's
    budget.

`tests/vectors/delegation_chain.json` has a case for each rule.

### 11.12 Task Redirect

The receiver redirects the sender to a different agent:

```json
{
  "body_type": "task.redirect",
  "body": {
    "task_id": "task-001",
    "redirect_to": "agent://specialty-bakery.example.com",
    "reason": "This agent specializes in gluten-free orders"
  }
}
```

### 11.13 Task Revocation

The delegator revokes a previously delegated task:

```json
{
  "body_type": "task.revoke",
  "body": {
    "task_id": "task-002",
    "reason": "Delegation authority expired",
    "revoked_by": "agent://alice@registry.example.com"
  }
}
```

---

## 12. Security

### 12.1 Authentication

Authentication is OPTIONAL. An agent with no authentication requirement
treats all senders as EXTERNAL trust tier.

Implementations that require authentication MUST support at least one
of the following methods, or the RFC 9421 HTTP message signatures in
Section 12.15.

A credential that is present but invalid MUST cause the request to be
rejected with HTTP 401. It MUST NOT be silently downgraded to an
anonymous EXTERNAL caller.

#### 12.1.1 Bearer JWT

```http
Authorization: Bearer eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

- The JWT MUST be signed using an algorithm supported by the receiver
  (Ed25519/EdDSA is RECOMMENDED).
- The JWT SHOULD include `iss` (issuer), `sub` (subject), `exp`
  (expiration), and `iat` (issued at) claims.
- The receiver MUST verify the signature against the sender's JWKS.
- Valid JWT authentication resolves to trust tier OWNER.

#### 12.1.2 DID Proof

```http
Authorization: DID <base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

The credential is a compact JWS signed by the key of a `did:key` DID.

- The header MUST contain `"alg": "EdDSA"`.
- The signature is Ed25519 over the ASCII bytes of
  `<header_b64> "." <payload_b64>`, and MUST verify under the Ed25519
  public key embedded in the DID. The DID uses multibase `z` (base58btc)
  followed by the multicodec prefix `0xed 0x01` and the 32-byte key.
- The payload MUST contain these claims:

| Claim | Requirement |
|-------|-------------|
| `did` | The `did:key` DID being proven. Other DID methods are not supported and resolve to EXTERNAL. |
| `aud` | The receiving agent's identifier, as a string or an array that contains it. A receiver with no configured audience MUST reject every DID proof. |
| `iat`, `exp` | Numeric Unix timestamps. `exp` ≥ `iat`, and `exp` − `iat` ≤ 300 s. Rejected if `exp` + 30 s is in the past, or if `iat` is more than 30 s in the future. |
| `jti` | A non-empty string, accepted once per `(did, jti)`. Receivers MUST remember it for at least the proof lifetime plus the skew allowance. The reference implementation keeps it for 360 s. |

- The DID MUST be bound to the envelope `sender`. Either the sender is
  that DID (`did:key:…` or `agent://did:key:…`), or the sender is a
  non-DID address whose DIDs the receiver has verified out of band
  (for example through an `identity.link_proof`) and the proof's DID is
  among them.
- A bare DID with no proof (`Authorization: DID did:key:…`) proves
  nothing and resolves to EXTERNAL.
- The `jti` is recorded only after every other check has passed.
- Valid DID authentication resolves to trust tier VERIFIED. A
  DID-authenticated principal is bound to the sender address, and the
  sender-binding check in Appendix D applies.

#### 12.1.3 API Key

```http
Authorization: ApiKey sk-abc123def456
```

- API keys MUST be transmitted only over HTTPS.
- Keys are allow-listed out of band. In the reference implementation,
  keys are registered with `register_api_key`, or a host store
  implementing `ApiKeyValidator` is injected.
- Receivers MUST store only a hash of each key (the reference stores
  the SHA-256 digest), and MUST compare keys in constant time.
- An API key MUST NOT confer a trust tier above VERIFIED. Registering a
  key at OWNER or INTERNAL is an error.
- Receivers SHOULD throttle failed attempts per client address. The
  reference blocks an address for 900 s after 10 failures.
- An API key authenticates the caller but not the envelope `sender`
  field.

#### 12.1.4 Mutual TLS (mTLS)

- The client presents a certificate during the TLS handshake. No
  `Authorization` header is needed.
- The identity MUST come only from a client certificate that the
  transport (TLS terminator or server) has verified. The transport
  passes this identity to the application out of band. The reference
  implementation reads it from `HTTPRequest.client_cert_identity`.
- Receivers MUST NOT derive an mTLS identity from request headers or
  from any other value the client controls.
- Valid mTLS authentication resolves to at least trust tier VERIFIED.
  The certificate identity becomes the principal and is bound to the
  envelope `sender`.

#### 12.1.5 No Authentication

If no `Authorization` header is present and no mTLS certificate is
presented, the sender is assigned trust tier EXTERNAL.

### 12.2 Trust Tiers

Every message is processed within a trust context. The trust tier
determines which security checks apply.

| Tier       | Description                                      | Resolution                     |
|------------|--------------------------------------------------|--------------------------------|
| INTERNAL   | Same organization, same platform                 | Platform-internal mechanism    |
| OWNER      | The agent's registered owner/operator            | Valid JWT from registered owner |
| VERIFIED   | Authenticated agent, not owner                   | Valid DID proof, API key, mTLS, or RFC 9421 signature |
| EXTERNAL   | Unknown or unauthenticated agent                 | No valid credentials           |

#### 12.2.1 Trust Tier Properties

| Property              | INTERNAL | OWNER | VERIFIED | EXTERNAL |
|-----------------------|----------|-------|----------|----------|
| Requires auth check   | No       | No    | No       | Yes      |
| Requires rate limit   | No       | No    | Yes      | Yes      |
| Requires content filter | No     | No    | No       | Yes      |
| Requires budget check | No       | Yes   | Yes      | Yes      |
| Requires loop detection | No     | No    | Yes      | Yes      |
| Can delegate          | Yes      | Yes   | Yes      | No       |

### 12.3 Trust Scoring

In addition to categorical trust tiers, AMP defines a numeric trust
score (0--1000) computed from five independent factors:

| Factor              | Max Points | Description                                |
|---------------------|------------|--------------------------------------------|
| AGE                 | 200        | How long the agent has existed             |
| TRACK_RECORD        | 200        | Number of successful interactions          |
| CLEAN_HISTORY       | 200        | Absence of incidents (penalty-based)       |
| ENDORSEMENTS        | 200        | Peer endorsements received                 |
| IDENTITY_STRENGTH   | 200        | Cryptographic identity method strength     |

**Identity method scores:**

| Method     | Points |
|------------|--------|
| `did:key`  | 50     |
| `did:web`  | 100    |
| `jwt`      | 150    |
| `mtls`     | 200    |

**Score-to-tier mapping:**

| Score Range | Tier       | Rate Limit (req/min) | Content Filter |
|-------------|------------|----------------------|----------------|
| 800--1000   | internal   | 1000                 | Off            |
| 400--799    | verified   | 100                  | Off            |
| 100--399    | external   | 10                   | On             |
| 0--99       | external   | 1                    | On             |

Note: The OWNER tier is assigned by the trust resolver based on
registration metadata, not by the numeric score.

The trust score is communicated via the `Trust-Score` header.

### 12.4 Rate Limiting

Implementations SHOULD enforce rate limits on EXTERNAL and VERIFIED
tier senders.

- The RECOMMENDED default rate limit is 60 requests per minute per
  sender.
- Rate limit state MUST be communicated via response headers:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1712765400
```

- When the limit is exceeded, the response MUST be HTTP 429 with a
  `Retry-After` header and an error body per Section 7.2.10.

### 12.5 Message Deduplication

Implementations SHOULD track message IDs for deduplication.

- The dedup key MUST include the **authenticated caller**: the
  principal established by Section 12.1 or 12.15, or, for an anonymous
  caller, a shared anonymous identity. The reference key is
  `principal_id || 0x00 || sender || 0x00 || id`.
- Deduplication MUST run **after** authentication (Appendix D).
- The RECOMMENDED dedup window is 300 seconds.
- The RECOMMENDED maximum tracked IDs is 100,000.
- When a duplicate from the same caller is detected, the implementation
  SHOULD return the original response rather than reprocessing.
- A duplicate that arrives while the first copy is still being
  processed SHOULD receive HTTP 409.
- Responses with a 5xx status SHOULD NOT be cached, so that a retry is
  processed again.
- Implementations MUST NOT reject a message solely because the dedup
  store is full. When the store is full, the oldest entries SHOULD be
  evicted.

### 12.6 Nonce Replay Protection

Implementations SHOULD track nonces for replay protection.

- The nonce window MUST be at least as long as the freshness window of
  the artefact that carries the nonce. That window is 300 s for RFC 9421
  signatures and federation proofs, and the proof lifetime plus clock
  skew for DID proofs. The reference RFC 9421 tracker keeps nonces for
  3,600 s.
- Nonces MUST be recorded only after the signature that carries them
  has verified. Otherwise a forged request could burn a legitimate
  nonce.
- When the RFC 9421 nonce tracker is full, it evicts expired entries
  first and then the oldest live entry, so it does not fail closed. Size
  it for at least the peak verified-request rate × 300 s. The
  federation nonce cache is the exception: when it is full of live
  entries it rejects new proofs.
- A replayed nonce in a message signature fails authentication (HTTP
  401, Section 12.15). For other nonce-bearing artefacts, the
  implementation MUST reject the message, with HTTP 409 and an error
  body per Section 7.2.7.

### 12.7 Sender Tracking

Implementations SHOULD track sender behavior to detect abuse.

- The RECOMMENDED failure threshold is 3 consecutive failures before
  temporary blocking.
- Blocked senders SHOULD receive HTTP 429 responses.
- Implementations SHOULD automatically unblock senders after a
  cooldown period.

### 12.8 Callback URL Validation

When a message includes a `Callback-URL` header:

1. The URL MUST use the HTTPS scheme.
2. The URL MUST NOT resolve to a private (RFC 1918), loopback, or
   link-local IP address.
3. The implementation SHOULD perform a HEAD request to verify
   reachability before accepting the message.
4. The implementation SHOULD pin DNS resolution on the first lookup and
   reuse the resolved IP for all delivery attempts.

### 12.9 Circuit Breaker

Implementations SHOULD implement circuit breaker patterns for outbound
calls (callbacks, delegation, federation):

- **CLOSED**: Normal operation.
- **OPEN**: All calls fail-fast. Set after consecutive failures exceed
  a threshold.
- **HALF_OPEN**: Allow a probe request. If it succeeds, transition to
  CLOSED; if it fails, return to OPEN.

Circuit state MAY be communicated via the `X-Circuit-State`,
`X-Circuit-Failures`, and `X-Circuit-Reset-At` headers.

### 12.10 Concurrency Limiting

Implementations SHOULD limit the number of concurrent tasks being
processed.

- The RECOMMENDED default limit is 50 concurrent tasks.
- When the limit is reached, new tasks SHOULD be rejected with HTTP 503
  and a `Retry-After` header.
- The agent's `constraints.max_concurrent_tasks` field in `agent.json`
  declares this limit.

### 12.11 End-to-End Encryption

AMP supports end-to-end encryption of message bodies using JWE
(JSON Web Encryption).

When the `Content-Encryption` header is present, the `body` field of
the `AgentMessage` envelope contains an `EncryptedBody` object:

```json
{
  "body": {
    "ciphertext": "base64-encoded-encrypted-payload",
    "iv": "base64-encoded-initialization-vector",
    "tag": "base64-encoded-authentication-tag",
    "algorithm": "A256GCM",
    "recipient_key_id": "key-2026-04"
  }
}
```

- The `recipient_key_id` MUST reference a key in the recipient's JWKS.
- The `algorithm` MUST be a registered JWE encryption algorithm.
- The receiver MUST decrypt the body before processing the `body_type`.

### 12.12 Key Revocation

Agents MAY revoke compromised keys by sending a `key.revocation`
message:

```json
{
  "body_type": "key.revocation",
  "body": {
    "agent_id": "agent://compromise-victim@registry.amp-protocol.dev",
    "revoked_key_id": "kid-ed25519-2026-04-01",
    "revoked_at": "2026-04-09T14:30:00Z",
    "reason": "key_compromise",
    "replacement_key_id": "kid-ed25519-2026-04-09",
    "jwks_url": "https://registry.amp-protocol.dev/.well-known/jwks.json",
    "signature": "W8kMAdUC98k2Tq44G_DjAIMvU_iWMjzQlo7FRCV-V5JuIHGYq5hvoaUI3UlUY8LQR5OfnYfyOATxlzM55hM1BQ"
  }
}
```

Revocation reasons: `key_compromise`, `key_rotation`,
`agent_decommissioned`. `replacement_key_id` and `jwks_url` are
optional.

`signature` is an Ed25519 signature, base64url-encoded without padding,
by the revoking agent's key. It is computed over a canonical JSON
object with these properties:

- It contains every body field except `signature`.
- Absent optional fields are included as `null`.
- Keys are sorted, the separators are `,` and `:`, and non-ASCII
  characters are escaped as `\uXXXX`.

For the example above, the signed string is:

```
{"agent_id":"agent://compromise-victim@registry.amp-protocol.dev","jwks_url":"https://registry.amp-protocol.dev/.well-known/jwks.json","reason":"key_compromise","replacement_key_id":"kid-ed25519-2026-04-09","revoked_at":"2026-04-09T14:30:00Z","revoked_key_id":"kid-ed25519-2026-04-01"}
```

This example is signed with the RFC 8032 TEST 1 key (see
`tests/vectors/key_revocation.json`).

The receiver MUST verify the signature against a non-revoked key of
`agent_id` before acting on the revocation, and MUST discard unverified
revocations. Once a key is revoked, verifiers MUST stop accepting it
immediately, including from caches (Section 12.15).

### 12.13 Anti-Abuse Challenges

Implementations MAY challenge suspicious senders before processing
their messages:

**Challenge:**
```json
{
  "body_type": "task.challenge",
  "body": {
    "challenge_type": "proof_of_work",
    "challenge_data": "solve-this-hash-prefix",
    "expires_at": "2026-04-10T14:35:00Z"
  }
}
```

**Response:**
```json
{
  "body_type": "task.challenge_response",
  "body": {
    "challenge_type": "proof_of_work",
    "solution": "nonce-that-produces-required-prefix"
  }
}
```

Challenge reasons: `rate_exceeded`, `new_sender`, `suspicious_pattern`,
`high_value_operation`.

The RECOMMENDED challenge expiry is 300 seconds.

### 12.14 Distributed Tracing

AMP supports W3C Trace Context-inspired tracing across agent
boundaries.

| Header          | Format              | Description                     |
|-----------------|---------------------|---------------------------------|
| `Trace-Id`      | 32 hex chars (128-bit) | Trace identifier              |
| `Span-Id`       | 16 hex chars (64-bit)  | Span identifier               |
| `Parent-Span-Id` | 16 hex chars (64-bit) | Parent span identifier (optional) |

- When receiving a message with `Trace-Id` and `Span-Id`, the receiver
  SHOULD create a new span with the received span as parent.
- When initiating a message with no existing trace context, the sender
  SHOULD generate new trace and span IDs.

### 12.15 HTTP Message Signatures (RFC 9421 Profile)

This section is NORMATIVE for every implementation that authenticates
requests with HTTP message signatures. It profiles RFC 9421 and
RFC 9530. The reference implementation is `ampro.security.rfc9421`
(`sign_request` and `verify_request`), wired into the reference server
by `ampro.server.auth.SignatureAuthenticator`. Conformance vectors:
`tests/vectors/rfc9421.json`.

#### 12.15.1 Headers

```http
Content-Digest: sha-256=:fAkuZwvuyUURsjOnGP7aJHj1SMThvo6KzjGOQF5HoH8=:
Signature-Input: sig1=("@method" "@target-uri" "@authority" "content-digest" "content-type");created=1775743200;keyid="agent://alice.example.com#key-1";alg="ed25519";nonce="n-7f3c1a9e5b2d4c60"
Signature: sig1=:hmmboKHLvPhvwTpoDfk3F9gXHKOxWXnV3bSRLGcinaM4YO/yG/0Q1YtVBra367TrNVFctOB6tKYSSwOFlGP0DQ==:
```

- The signature label is `sig1`.
- `Signature-Input` lists the covered components and then the
  parameters, in this order: `created` (integer Unix seconds), `keyid`
  (quoted string), `alg` (quoted string), and `nonce` (quoted string).
- `Signature` carries the standard base64 encoding of the 64-byte
  Ed25519 signature, between colons.
- **Algorithm**: `alg` MUST be `"ed25519"` (Ed25519, RFC 8032).
  Verifiers MUST reject any other value, which prevents algorithm
  confusion.
- **Required parameters**: `created`, `keyid`, and `nonce` are all
  REQUIRED. A signature without `nonce` MUST be rejected.

#### 12.15.2 Covered Components

- Signers MUST cover `@method`, `@target-uri`, and `@authority`.
- When the request has a body, signers MUST cover `content-digest`.
- When a `content-type` header is present, signers SHOULD cover it.
- Component names are lowercase.
- Verifiers MUST reject a signature whose covered components omit
  `@method`, `@target-uri`, or `@authority`.

- **Content-Digest (RFC 9530)**: the header value is
  `sha-256=:<base64(SHA-256(body))>:`.
- When the request body is non-empty, verifiers MUST reject the request
  unless `content-digest` is covered **and** equals the digest of the
  body actually received.
- When `content-digest` is covered and the body is empty, the digest
  MUST still match.
- A covered header that is absent from the request MUST cause
  verification to fail. An absent header is not treated as an empty
  string.

#### 12.15.3 Signature Base

The signature base follows RFC 9421 section 2.5:

- It has one line per covered component, in the order listed, of the
  form `"<component>": <value>`.
- The last line is
  `"@signature-params": (<components>);created=<created>;keyid="<keyid>";alg="ed25519";nonce="<nonce>"`.
- Lines are joined with a single LF, with no trailing newline.

Component values:

| Component | Value |
|-----------|-------|
| `@method` | The request method, uppercased |
| `@target-uri` | The full request URL as the client addressed it |
| `@authority` | See below |
| header fields | The header value as received (header names are matched case-insensitively) |

`@authority` is built from the target URI:

- Take the host, lowercase it, and drop any userinfo.
- Keep IPv6 literals in brackets.
- Append `:<port>` only when the port is not the scheme's default (80
  for `http`, 443 for `https`).

For example, `https://user@API.Example.com:443/x` gives
`api.example.com`, and `https://API.Example.com:8443/x` gives
`api.example.com:8443`.

Target URIs that contain CR, LF, `%0a`, `%0d`, U+2028, U+2029, or NUL
MUST be rejected.

The reference server rebuilds `@target-uri` from its configured public
base URL plus the request path and query. Signers MUST therefore sign
the externally visible URL, not an internal one behind a proxy.

The example in 12.15.1 is the `post-json-body` vector. Its signature
base is:

```
"@method": POST
"@target-uri": https://bakery.example.com/agent/message
"@authority": bakery.example.com
"content-digest": sha-256=:fAkuZwvuyUURsjOnGP7aJHj1SMThvo6KzjGOQF5HoH8=:
"content-type": application/json
"@signature-params": ("@method" "@target-uri" "@authority" "content-digest" "content-type");created=1775743200;keyid="agent://alice.example.com#key-1";alg="ed25519";nonce="n-7f3c1a9e5b2d4c60"
```

#### 12.15.4 Freshness and Replay

- **Max age**: verifiers MUST reject a signature when
  |now − `created`| > 300 s. This bound applies in both directions:
  signatures too far in the past and too far in the future are both
  rejected.
- **Replay**: after the signature has verified, and never before,
  verifiers MUST record the pair `(keyid, nonce)` and MUST reject any
  later request that presents the same pair while it is remembered.
  Nonces are scoped per `keyid`. The replay cache window MUST be at
  least the 300 s freshness window. When the cache is full it evicts
  rather than rejecting (Section 12.6).
- Malformed input never raises. It fails verification.

#### 12.15.5 Keys and Outcome

- `keyid` is resolved to a raw 32-byte Ed25519 public key through a
  host-registered resolver. An unknown or revoked key MUST fail
  verification. Verifiers MUST consult the revocation store on every
  lookup, including cache hits.
- If the revocation store errors, the key MUST be treated as revoked.
- When `keyid` is owned by an agent address, the envelope `sender` MUST
  equal that address, or the request is rejected with HTTP 403
  (sender binding, Appendix D).
- A request that carries `Signature` / `Signature-Input` but fails any
  check in this section MUST be rejected with HTTP 401.
- A successful verification resolves to trust tier VERIFIED, unless the
  deployment configures a different tier.

### 12.16 Registry Federation

Registries federate by exchanging signed messages. The body schemas are
listed in Section 16.1.10, and the sync and conflict semantics are in
`docs/PROTOCOL-CONTRACTS.md` section 4. Conformance vectors:
`tests/vectors/registry_federation.json`.

Common rules for the signed messages below:

- Signatures are Ed25519, encoded as standard base64.
- The receiver resolves the signer's public key from an out-of-band
  trust source, such as a signed federation directory or a DNS-anchored
  key list. A receiver with no key source MUST reject every federation
  signature.
- Timestamps in the signed payloads are rendered as RFC 3339 UTC with
  `Z`. A fraction is included only when it is non-zero, and then with
  exactly 6 digits.
- Canonical JSON means sorted keys, the separators `,` and `:`, and
  UTF-8 with no `\u` escaping.

#### 12.16.1 Federation Request (Trust Proof)

```json
{
  "body_type": "registry.federation_request",
  "body": {
    "registry_id": "agent://registry.alpha.example.com",
    "capabilities": ["resolve", "search"],
    "audience": "agent://registry.home.example.com",
    "issued_at": "2026-04-09T14:00:00Z",
    "nonce": "fed-nonce-01-k3Jp9wQz",
    "trust_proof": "hbjqUEdqaI0FzWLxsik8/JgzvyELRM5dPP9MssTebHCNvejbEH1Pkype2c7jyuxyRm33WPA07TgyZ07v/uOBDA=="
  }
}
```

Field limits:

- `capabilities`: 1 to 64 entries. Each entry is 1 to 128 characters,
  with no control characters.
- `nonce`: 16 to 256 characters.
- `trust_proof`: at least 64 characters.

`trust_proof` is the signature by `registry_id`'s key over canonical
JSON of these fields:

```
{"audience":"agent://registry.home.example.com","capabilities":["resolve","search"],"issued_at":"2026-04-09T14:00:00Z","nonce":"fed-nonce-01-k3Jp9wQz","registry_id":"agent://registry.alpha.example.com","type":"ampro.registry.federation_request.v1"}
```

In general, the signed object is
`{type: "ampro.registry.federation_request.v1", registry_id, audience,
issued_at, nonce, capabilities}`, with `capabilities` sorted.

The receiver MUST accept the request only when all of the following
hold:

1. `audience` equals the receiver's own registry URI. A receiver that
   does not know its own URI MUST reject.
2. `issued_at` is within ±300 s of the receiver's clock.
3. The signature verifies.
4. The nonce has not been seen before from this `registry_id`. The
   receiver records the nonce only after the signature verifies, and
   keeps it for at least 600 s.

A request without `audience`, `issued_at`, or `nonce` MUST be rejected.

#### 12.16.2 Federation Revoke

```json
{
  "body_type": "registry.federation_revoke",
  "body": {
    "revoking_registry": "agent://registry.alpha.example.com",
    "revoked_registry": "agent://registry.home.example.com",
    "reason": "key compromise suspected",
    "effective_at": "2026-04-09T15:00:00Z",
    "signature": "kIgfeDWkm+JbtW4+ghkIm0qnZIlA7ZL/Paz2MzchfFx74OrQTeLf1lheHxiSGYBUovbQ2ow5rsRfumKnpzP4DQ=="
  }
}
```

`signature` is the signature by `revoking_registry`'s key over the
compact canonical JSON of these fields:

```
{"effective_at":"2026-04-09T15:00:00Z","reason":"key compromise suspected","revoked_registry":"agent://registry.home.example.com","revoking_registry":"agent://registry.alpha.example.com","type":"ampro.registry.federation_revoke.v1"}
```

In general, the signed object is
`{type: "ampro.registry.federation_revoke.v1", revoking_registry,
revoked_registry, reason, effective_at}`. `reason` is at most 1,024
characters. `effective_at` is canonicalised to UTC with `Z`, so
`2026-04-09T17:00:00+02:00` is signed as `2026-04-09T15:00:00Z`.

The receiver MUST check that `revoked_registry` is its own URI and that
the signature verifies before tearing down the federation.

#### 12.16.3 Conflict Resolution

When the same `agent_uri` is known locally and from a peer, the
precedence is: trust, then recency, then the lexicographically smallest
registry URI. A remote record that wins MUST have its `trust_tier`
capped at the local tier. The full rules are in PROTOCOL-CONTRACTS
section 4.

---

## 13. Compliance

### 13.1 Content Classification

Messages MAY include a `Content-Classification` header indicating the
sensitivity of the content:

| Classification  | Description                                      |
|-----------------|--------------------------------------------------|
| `public`        | No restrictions on handling                      |
| `internal`      | Organization-internal, not for public disclosure |
| `pii`           | Contains personally identifiable information     |
| `sensitive-pii` | Contains sensitive PII (health, financial, etc.) |
| `confidential`  | Highest sensitivity, restricted access           |

Receivers SHOULD enforce handling rules appropriate to the
classification. For example, `pii` and `sensitive-pii` content
SHOULD be subject to retention policies and erasure requirements.

### 13.2 Erasure

AMP supports GDPR-style erasure requests:

#### 13.2.1 Erasure Request

```json
{
  "body_type": "data.erasure_request",
  "body": {
    "subject_id": "user-12345",
    "subject_proof": "signed-identity-token",
    "scope": "all",
    "reason": "user_request",
    "deadline": "2026-05-10T00:00:00Z",
    "callback_url": "https://controller.example.com/erasure-callback"
  }
}
```

| Field           | Description                                              |
|-----------------|----------------------------------------------------------|
| `subject_id`    | Unique identifier of the data subject                    |
| `subject_proof` | Proof of identity (signed token)                         |
| `scope`         | `all`, `conversations`, `tasks`, or `tools`              |
| `reason`        | `user_request`, `account_deletion`, `consent_withdrawn`, `legal_order` |
| `deadline`      | ISO 8601 deadline for completion                         |
| `callback_url`  | URL to notify when erasure is complete (OPTIONAL)        |

#### 13.2.2 Erasure Response

```json
{
  "body_type": "data.erasure_response",
  "body": {
    "subject_id": "user-12345",
    "status": "completed",
    "records_deleted": 47,
    "categories_deleted": ["messages", "task_history", "tool_logs"],
    "retained": [
      {
        "category": "audit_logs",
        "reason": "Legal retention requirement (SOC2)",
        "retention_until": "2027-04-10T00:00:00Z"
      }
    ],
    "completed_at": "2026-04-11T08:00:00Z"
  }
}
```

Erasure status: `completed`, `partial`, `failed`.

#### 13.2.3 Erasure Propagation

When an agent delegates tasks to sub-agents, erasure requests MUST be
propagated through the delegation chain. The propagation status is
communicated via `erasure.propagation_status`:

```json
{
  "body_type": "erasure.propagation_status",
  "body": {
    "original_request_id": "erasure-001",
    "status": "propagating",
    "agents_notified": 3,
    "agents_completed": 1,
    "agents_failed": 0
  }
}
```

### 13.3 Consent Management

#### 13.3.1 Consent Request

```json
{
  "body_type": "data.consent_request",
  "body": {
    "requester": "agent://bakery.example.com",
    "target": "agent://alice@registry.example.com",
    "scopes": ["read:order_history", "write:preferences"],
    "reason": "To personalize bakery recommendations",
    "ttl_seconds": 86400
  }
}
```

#### 13.3.2 Consent Response

```json
{
  "body_type": "data.consent_response",
  "body": {
    "grant_id": "consent-grant-001",
    "requester": "agent://bakery.example.com",
    "target": "agent://alice@registry.example.com",
    "scopes": ["read:order_history"],
    "approved": true,
    "expires_at": "2026-04-11T14:30:00Z"
  }
}
```

#### 13.3.3 Consent Revocation

```json
{
  "body_type": "data.consent_revoke",
  "body": {
    "grant_id": "consent-grant-001",
    "reason": "User withdrew consent"
  }
}
```

### 13.4 Data Export

```json
{
  "body_type": "data.export_request",
  "body": {
    "subject_id": "user-12345",
    "subject_proof": "signed-identity-token",
    "scope": "all",
    "format": "json",
    "callback_url": "https://controller.example.com/export-callback"
  }
}
```

### 13.5 Jurisdiction

The `Jurisdiction` header declares the legal jurisdiction governing the
message:

```
Jurisdiction: US
```

The value MUST be an ISO 3166-1 alpha-2 country code.

When sender and receiver are in different jurisdictions, implementations
SHOULD evaluate whether the data exchange complies with applicable
cross-border transfer regulations.

### 13.6 Data Residency

The `Data-Residency` header declares the required data residency region:

```
Data-Residency: EU
```

Receivers MUST NOT store data outside the declared residency region if
one is specified.

### 13.7 Audit Attestation

Agents MAY publish attestation records for audit purposes:

```json
{
  "body_type": "audit.attestation",
  "body": {
    "attestation_type": "processing_record",
    "period_start": "2026-04-01T00:00:00Z",
    "period_end": "2026-04-10T00:00:00Z",
    "summary": {
      "messages_processed": 15000,
      "erasure_requests_completed": 3,
      "consent_grants_active": 42
    },
    "signed_by": "key-2026-04"
  }
}
```

---

## 14. Standard Headers

The following headers are defined by this specification. Receivers MUST
ignore headers they do not understand (forward compatibility).

### 14.1 Core Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Protocol-Version`  | Both      | NO       | Semver string   | AMP protocol version (e.g., `"1.0.0"`) |
| `Accept-Version`    | Request   | NO       | Comma-separated semver | Client's preferred protocol versions |
| `Content-Type`      | Both      | NO       | MIME type       | Payload content type (default: `application/json`) |
| `Authorization`     | Request   | NO       | Scheme + token  | Authentication credentials |
| `In-Reply-To`       | Response  | NO       | Message ID      | ID of the message being replied to |

### 14.2 Identity and Trust Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Trust-Tier`        | Response  | NO       | Enum string     | Trust tier resolved for this sender: `internal`, `owner`, `verified`, `external` |
| `Trust-Score`       | Response  | NO       | Integer 0--1000 | Numeric trust score |
| `Trust-Upgrade`     | Both      | NO       | String          | Trust tier upgrade request or grant |
| `Identity-Context`  | Request   | NO       | String          | Additional identity context for trust resolution |
| `Anonymous-Sender-Hint` | Request | NO    | String          | Hint for anonymous sender handling |

### 14.3 Session Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Session-Id`        | Both      | NO       | String          | Session identifier |
| `Session-Binding`   | Request   | NO       | Hex HMAC        | Per-message HMAC proof of session binding |
| `X-Session-Restarted` | Response | NO     | Boolean string  | Indicates session was restarted |

### 14.4 Capability Negotiation Headers

| Header                    | Direction | Required | Format              | Description |
|---------------------------|-----------|----------|---------------------|-------------|
| `Capabilities`            | Request   | NO       | Comma-separated     | Client's capability groups |
| `Accept-Capabilities`     | Request   | NO       | Comma-separated     | Capabilities the client desires |
| `Negotiated-Capabilities` | Response  | NO       | Comma-separated     | Agreed capability groups (intersection) |
| `Negotiated-Level`        | Response  | NO       | Integer 0--5        | Computed capability level |
| `Downgrade-Warning`       | Response  | NO       | Semicolon-separated | Warnings about unsupported capabilities |

### 14.5 Messaging Control Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Priority`          | Request   | NO       | Enum string     | Message priority: `batch`, `normal`, `priority`, `urgent`, `critical` |
| `Nonce`             | Request   | NO       | String          | One-time value for replay protection |
| `Timeout`           | Request   | NO       | Integer (seconds) | Maximum time for synchronous processing |
| `Hop-Timeout`       | Request   | NO       | Integer (seconds) | Timeout for this specific hop in a delegation chain |
| `Callback-URL`      | Request   | NO       | HTTPS URL       | URL for asynchronous result delivery |
| `Callback-Events`   | Request   | NO       | Comma-separated | Event types to deliver to callback URL |
| `Poll-Interval`     | Response  | NO       | Integer (seconds) | Recommended polling interval for async tasks |
| `Retry-After`       | Response  | NO       | Integer (seconds) | Seconds to wait before retrying |
| `Content-Language`   | Both     | NO       | BCP 47 tag      | Language of the message content |
| `Accept-Language`    | Request  | NO       | BCP 47 tags     | Client's preferred languages |

### 14.6 Delegation Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Delegation-Depth`  | Request   | NO       | Integer         | Current depth in the delegation chain |
| `Visited-Agents`    | Request   | NO       | Comma-separated | Agent URIs already visited (loop detection) |
| `Chain-Budget`      | Request   | NO       | Budget string   | Remaining and max budget (e.g., `remaining=3.50USD;max=5.00USD`) |
| `Via`               | Both      | NO       | Comma-separated | Intermediaries the message passed through |
| `Transaction-Id`    | Both      | NO       | String          | Transaction identifier for correlated operations |
| `Correlation-Group` | Both      | NO       | String          | Groups related messages together |
| `Commitment-Level`  | Request   | NO       | String          | Level of commitment expected (informational, binding, etc.) |

### 14.7 Rate Limiting and Circuit Breaker Headers

| Header                | Direction | Required | Format          | Description |
|-----------------------|-----------|----------|-----------------|-------------|
| `X-RateLimit-Limit`   | Response  | NO       | Integer         | Maximum requests per window |
| `X-RateLimit-Remaining` | Response | NO     | Integer         | Requests remaining in current window |
| `X-RateLimit-Reset`   | Response  | NO       | Unix timestamp  | When the rate limit window resets |
| `X-Circuit-State`     | Response  | NO       | Enum string     | Circuit breaker state: `closed`, `open`, `half_open` |
| `X-Circuit-Failures`  | Response  | NO       | Integer         | Number of consecutive failures |
| `X-Circuit-Reset-At`  | Response  | NO       | Unix timestamp  | When the circuit breaker will reset |
| `X-Load-Level`        | Response  | NO       | Float 0.0--1.0  | Current load level for routing decisions |

### 14.8 Streaming Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Stream-Channel`    | Both      | NO       | String          | Logical stream channel identifier |

### 14.9 Security Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Content-Encryption` | Request  | NO       | Algorithm string | Indicates end-to-end encrypted body |
| `Key-Revoked-At`    | Both      | NO       | ISO 8601        | Timestamp when a key was revoked |

### 14.10 Compliance Headers

| Header                   | Direction | Required | Format       | Description |
|--------------------------|-----------|----------|--------------|-------------|
| `Content-Classification` | Both      | NO       | Enum string  | Data sensitivity: `public`, `internal`, `pii`, `sensitive-pii`, `confidential` |
| `Jurisdiction`           | Both      | NO       | ISO 3166-1   | Legal jurisdiction governing this message |
| `Data-Residency`         | Both      | NO       | Region code  | Required data residency region |

### 14.11 Tracing Headers

| Header            | Direction | Required | Format        | Description |
|-------------------|-----------|----------|---------------|-------------|
| `Trace-Id`        | Both      | NO       | 32 hex chars  | Distributed trace identifier (128-bit) |
| `Span-Id`         | Both      | NO       | 16 hex chars  | Span identifier (64-bit) |

### 14.12 Context Headers

| Header              | Direction | Required | Format          | Description |
|---------------------|-----------|----------|-----------------|-------------|
| `Context-Schema`    | Request   | NO       | Schema URN      | URN of the context schema in use |

### 14.13 Header Count

This specification defines 51 standard headers. All are OPTIONAL.
Implementations MUST ignore headers not listed here. Custom headers
SHOULD use the `X-` prefix (see Section 18.2).

---

## 15. Status Codes

AMP uses HTTP status codes with the following protocol-specific
interpretations:

### 15.1 Informational (1xx)

| Code | AMP Name          | Description                                  |
|------|--------------------|----------------------------------------------|
| 100  | RECEIVED           | Message received, processing has not started |
| 101  | PROCESSING         | Message is being processed                   |
| 102  | INPUT_REQUIRED     | Additional input is needed                   |

### 15.2 Success (2xx)

| Code | AMP Name | Description                                           |
|------|----------|-------------------------------------------------------|
| 200  | OK       | Request processed successfully, response body included |
| 201  | CREATED  | Resource created (task, session, order)                |
| 202  | ACCEPTED | Accepted for asynchronous processing                  |

### 15.3 Redirection (3xx)

| Code | AMP Name  | Description                                        |
|------|-----------|----------------------------------------------------|
| 301  | MOVED     | Agent has moved to a new address permanently       |
| 302  | REFER     | Try a different agent for this request             |
| 303  | ESCALATED | Request has been escalated to a human or supervisor |

When returning 301 or 302, the response MUST include a `Location`
header with the new agent's endpoint URL.

### 15.4 Client Error (4xx)

| Code | AMP Name          | Description                                    |
|------|--------------------|-------------------------------------------------|
| 400  | INVALID            | Malformed message or invalid body              |
| 401  | UNAUTHORIZED       | Authentication required but not provided       |
| 403  | FORBIDDEN          | Authenticated but insufficient permissions     |
| 404  | NOT_FOUND          | Agent, task, tool, or session not found         |
| 408  | TIMEOUT            | Request timed out                               |
| 409  | CONFLICT           | Nonce replay, dedup conflict, or race condition |
| 413  | PAYLOAD_TOO_LARGE  | Message exceeds maximum size                    |
| 429  | RATE_LIMITED       | Too many requests from this sender              |

### 15.5 Server Error (5xx)

| Code | AMP Name          | Description                                   |
|------|--------------------|------------------------------------------------|
| 500  | ERROR              | Internal error in the receiver                |
| 501  | NOT_IMPLEMENTED    | Requested capability is not implemented       |
| 503  | UNAVAILABLE        | Agent is temporarily unavailable              |

---

## 16. Body Types

### 16.1 Body Type Registry

The `body_type` field of the `AgentMessage` envelope determines the
semantic meaning and expected schema of the `body`. The following body
types are defined by this specification.

#### 16.1.1 Messaging (POST semantics)

| Body Type        | Description                                    | Idempotent |
|------------------|------------------------------------------------|------------|
| `message`        | Free-form message with optional attachments    | No         |
| `notification`   | Push notification to an agent                  | No         |

#### 16.1.2 Task Creation (POST semantics)

| Body Type        | Description                                    | Idempotent |
|------------------|------------------------------------------------|------------|
| `task.create`    | Create a new task                              | No         |
| `task.assign`    | Assign a task to a specific agent              | Yes        |
| `task.delegate`  | Delegate a task with delegation chain          | No         |
| `task.spawn`     | Spawn a child task from a parent               | No         |
| `task.quote`     | Non-binding cost/time estimate                 | Yes        |

#### 16.1.3 Task Lifecycle (PATCH semantics)

| Body Type            | Description                                | Idempotent |
|----------------------|--------------------------------------------|------------|
| `task.acknowledge`   | Accept a task for processing               | Yes        |
| `task.reject`        | Decline a task                             | Yes        |
| `task.progress`      | Report incremental progress                | No         |
| `task.input_required` | Request additional input from sender      | No         |
| `task.escalate`      | Escalate to human or another agent         | No         |
| `task.reroute`       | Cancel or redirect a task                  | No         |
| `task.transfer`      | Transfer task ownership                    | No         |
| `task.complete`      | Signal successful completion               | Yes        |
| `task.error`         | Report terminal failure                    | Yes        |
| `task.redirect`      | Redirect sender to another agent           | Yes        |
| `task.revoke`        | Revoke a delegated task                    | Yes        |

#### 16.1.4 Task Response (PUT semantics)

| Body Type        | Description                                    | Idempotent |
|------------------|------------------------------------------------|------------|
| `task.response`  | Structured reply to a task or input request    | Yes        |

#### 16.1.5 Session Management

| Body Type              | Description                              | Idempotent |
|------------------------|------------------------------------------|------------|
| `session.init`         | Propose a new session                    | No         |
| `session.established`  | Accept session, return negotiated params | Yes        |
| `session.confirm`      | Confirm session binding                  | Yes        |
| `session.ping`         | Keepalive ping                           | Yes        |
| `session.pong`         | Keepalive pong response                  | Yes        |
| `session.pause`        | Temporarily suspend session              | No         |
| `session.resume`       | Resume a paused session                  | No         |
| `session.close`        | Gracefully close session                 | Yes        |

#### 16.1.6 Consent and Compliance

| Body Type                    | Description                            | Idempotent |
|------------------------------|----------------------------------------|------------|
| `data.consent_request`       | Request consent for scoped access      | No         |
| `data.consent_response`      | Grant or deny consent                  | Yes        |
| `data.consent_revoke`        | Revoke previously granted consent      | Yes        |
| `data.erasure_request`       | Request data erasure (GDPR)            | No         |
| `data.erasure_response`      | Confirm erasure outcome                | Yes        |
| `data.export_request`        | Request data export                    | No         |
| `data.export_response`       | Provide export download                | Yes        |
| `erasure.propagation_status` | Erasure propagation across agents      | Yes        |

#### 16.1.7 Trust and Security

| Body Type                  | Description                              | Idempotent |
|----------------------------|------------------------------------------|------------|
| `trust.upgrade_request`    | Request a trust tier upgrade             | No         |
| `trust.upgrade_response`   | Grant or deny trust upgrade              | Yes        |
| `trust.proof`              | Provide proof for trust assertion         | Yes        |
| `key.revocation`           | Revoke a compromised key                 | Yes        |
| `task.challenge`           | Anti-abuse challenge                     | No         |
| `task.challenge_response`  | Response to anti-abuse challenge         | Yes        |
| `tool.consent_request`     | Request consent for specific tool        | No         |
| `tool.consent_grant`       | Grant consent for specific tool          | Yes        |

#### 16.1.8 Agent Lifecycle

| Body Type                    | Description                            | Idempotent |
|------------------------------|----------------------------------------|------------|
| `agent.deactivation_notice`  | Agent going offline permanently        | Yes        |

#### 16.1.9 Identity

| Body Type              | Description                                | Idempotent |
|------------------------|--------------------------------------------|------------|
| `identity.link_proof`  | Proof linking multiple identities          | Yes        |
| `identity.migration`   | Agent migrating to a new address           | Yes        |

#### 16.1.10 Registry Federation

| Body Type                      | Description                          | Idempotent |
|--------------------------------|--------------------------------------|------------|
| `registry.federation_request`  | Request cross-registry federation (signed, Section 12.16.1) | No |
| `registry.federation_response` | Respond to federation request        | Yes        |
| `registry.federation_revoke`   | Tear down a federation link (signed, Section 12.16.2) | Yes |
| `registry.federation_sync`     | Request a delta from a peer registry | Yes        |
| `registry.federation_sync_response` | Delta of agent-record changes plus cursor | Yes |

#### 16.1.11 Audit

| Body Type            | Description                                  | Idempotent |
|----------------------|----------------------------------------------|------------|
| `audit.attestation`  | Compliance attestation record                | Yes        |

### 16.2 Request-Response Pairs

Certain body types form request-response pairs. When the sender sends
the request type, the receiver MUST respond with one of the listed
response types:

| Request Body Type              | Valid Response Body Types                              |
|--------------------------------|--------------------------------------------------------|
| `session.init`                 | `session.established`, `task.reject`                   |
| `task.create`                  | `task.acknowledge`, `task.complete`, `task.reject`, `task.error` |
| `task.delegate`                | `task.acknowledge`, `task.complete`, `task.reject`, `task.error` |
| `task.input_required`          | `task.response`                                        |
| `data.consent_request`         | `data.consent_response`                                |
| `data.erasure_request`         | `data.erasure_response`                                |
| `data.export_request`          | `data.export_response`                                 |
| `trust.upgrade_request`        | `trust.upgrade_response`                               |
| `tool.consent_request`         | `tool.consent_grant`, `task.reject`                    |
| `task.challenge`               | `task.challenge_response`                              |
| `registry.federation_request`  | `registry.federation_response`                         |

---

## 17. Capability Levels

### 17.1 Capability Groups

AMP defines 8 capability groups:

| Group       | Description                                        |
|-------------|----------------------------------------------------|
| `messaging` | Send and receive messages                          |
| `streaming` | Real-time processing events via SSE                |
| `tools`     | Discover and invoke callable tools                 |
| `identity`  | Handshake, verify, consent, revoke                 |
| `session`   | Start, resume, end, inject context                 |
| `delegation` | Delegate, progress, escalate, complete, abort     |
| `presence`  | Ping, status, capabilities advertisement           |
| `events`    | Notify, subscribe, unsubscribe, publish            |

### 17.2 Level Requirements

Each level requires specific capability groups:

| Level | Required Groups                                                    |
|-------|--------------------------------------------------------------------|
| 0     | (none)                                                             |
| 1     | `messaging`                                                        |
| 2     | `messaging`, `tools`                                               |
| 3     | `messaging`, `tools`, `streaming`                                  |
| 4     | `messaging`, `tools`, `streaming`, `identity`, `session`, `delegation`, `events` |
| 5     | All 8 groups                                                       |

The level is computed automatically: the highest level whose required
groups are all present in the agent's declared capabilities.

### 17.3 Level-Endpoint Mapping

| Level | Endpoints Unlocked                                               |
|-------|------------------------------------------------------------------|
| 0     | `GET /.well-known/agent.json`, `GET /agent/health`              |
| 1     | `POST /agent/message`                                           |
| 2     | `GET /agent/tools`, `GET /agent/tools/{name}`, `POST /agent/tools/{name}` |
| 3     | `GET /agent/stream`, `GET /agent/tasks/{task_id}`               |
| 4     | Session handshake, identity verification, consent, delegation   |
| 5     | Presence, audit, registry, federation                           |

### 17.4 Capability Negotiation

During session handshake (Section 9.2), the client proposes capabilities
and the server responds with the intersection.

Without a session, capability negotiation MAY occur per-request via
headers:

1. Client sends `Capabilities: messaging,tools,streaming`.
2. Server responds with `Negotiated-Capabilities: messaging,tools` and
   `Negotiated-Level: 2`.
3. If capabilities were downgraded, server includes
   `Downgrade-Warning: Server supports 'streaming' but client does not`.

---

## 18. Extensibility

### 18.1 Custom Body Types

Implementations MAY define custom body types using reverse-domain
notation:

```
com.acme.custom.order_confirmation
org.openai.function_call
io.anthropic.tool_use
```

Custom body types MUST NOT use the bare dot-notation reserved for
protocol-defined types (e.g., `task.*`, `session.*`, `data.*`).

Receivers that do not understand a custom body type MUST NOT reject the
message at the transport level. They SHOULD accept the message and MAY
respond with `task.reject` indicating the body type is unsupported.

### 18.2 Custom Headers

Custom headers SHOULD use the `X-` prefix:

```
X-Acme-Request-Id: req-12345
X-Custom-Priority: platinum
```

Receivers MUST ignore custom headers they do not understand.

### 18.3 Extension Capabilities

The `capabilities` section of `agent.json` MAY include custom
capability groups using reverse-domain notation:

```json
{
  "capabilities": {
    "groups": ["messaging", "tools", "com.acme.custom.payments"],
    "level": 2
  }
}
```

Custom capability groups do not affect the computed level (only standard
groups are considered).

### 18.4 Versioning

- The protocol version is declared in `agent.json` and communicated
  via the `Protocol-Version` header.
- Clients request a specific version via the `Accept-Version` header.
- The server MUST respond with the negotiated version in the
  `Protocol-Version` response header.
- If no `Accept-Version` is provided, the server uses its current
  default version. For the reference implementation this is `1.0.0`
  (`ampro.core.versioning.CURRENT_VERSION`).
- Receivers MUST accept any well-formed SemVer 2.0.0 version
  (`MAJOR.MINOR.PATCH`, with optional `-pre-release` and `+build`)
  whose MAJOR matches a version they support.
  - If that exact version is supported, the server speaks it.
  - Otherwise, the server speaks the highest supported version with the
    same MAJOR.
  - A receiver MUST NOT reject a version solely because of its MINOR,
    PATCH, pre-release, or build component.
- If the requested version is malformed, or its MAJOR matches no
  supported version, the server MUST return HTTP 406 (see Section
  7.2.5).
- Version negotiation supports comma-separated preference lists, for
  example `Accept-Version: 1.0.0, 0.1.0`. The server walks the list in
  the client's order.
  - It picks the first entry that it supports exactly.
  - If no entry is supported exactly, it picks the highest supported
    version that shares a MAJOR with the first well-formed entry whose
    MAJOR it supports.

### 18.5 Sunset Header

When a protocol version is deprecated, the server SHOULD include a
`Sunset` header per RFC 7231:

```http
Sunset: Thu, 15 Jan 2027 00:00:00 GMT
```

---

## 19. Configuration Defaults

The following values are RECOMMENDED defaults. Implementations MAY use
different values and SHOULD declare their configuration in `agent.json`
under the `constraints` field.

| Parameter                  | Default    | Description                                  |
|----------------------------|------------|----------------------------------------------|
| Rate limit                 | 60 rpm     | Maximum requests per minute per sender       |
| Dedup window               | 300 s      | How long to track message IDs                |
| Dedup max entries          | 100,000    | Maximum tracked message IDs                  |
| Nonce window               | 3,600 s    | How long to track nonces for replay protection |
| Message size limit         | 10 MiB     | Maximum request body size                    |
| Session TTL                | 3,600 s    | Default session time-to-live                 |
| Heartbeat interval         | 15 s       | SSE heartbeat frequency                      |
| Delegation depth           | 5          | Maximum delegation chain depth               |
| Max concurrent tasks       | 50         | Maximum tasks processing simultaneously      |
| Challenge expiry           | 300 s      | Time limit for anti-abuse challenge response |
| Callback retry count       | 3          | Maximum callback delivery attempts           |
| Callback retry delays      | 1, 5, 25 s | Exponential backoff for callback retries    |
| Connect timeout            | 10 s       | TCP connection timeout                       |
| Read timeout               | 30 s       | HTTP read timeout                            |
| Clock skew tolerance       | 30 s       | Tolerance for cross-region timestamp comparison |
| Sender failure threshold   | 3          | Consecutive failures before blocking sender  |
| Max visited agents         | 20         | Maximum agents in loop-detection chain       |
| Max delegation fan-out     | 3          | Maximum parallel sub-delegations per link    |
| Polling interval           | 5 s        | Default polling interval for async tasks     |
| Backpressure ACK frequency | 10 events or 5 s | When to send stream acknowledgments    |

---

## 20. Conformance

### 20.1 Level 0 Conformance (MANDATORY)

An implementation claiming Level 0 conformance MUST:

1. Serve a valid JSON document at `GET /.well-known/agent.json`
   containing at minimum `protocol_version`, `identifiers`, and
   `endpoint`.
2. Respond to `GET /agent/health` with a JSON object containing at
   minimum `status` and `protocol_version`.
3. Use HTTPS in production environments.
4. Return `Content-Type: application/json` for all JSON responses.

### 20.2 Level 1 Conformance

In addition to Level 0, an implementation claiming Level 1 conformance
MUST:

1. Accept `POST /agent/message` requests with
   `Content-Type: application/json`.
2. Parse the `AgentMessage` envelope (sender, recipient, id, body_type,
   headers, body).
3. Ignore unknown headers without error.
4. Accept unknown body types without returning a transport-level error.
5. Return responses as `AgentMessage` envelopes.
6. Return error responses using RFC 7807 Problem Details format.

### 20.3 Level 2 Conformance

In addition to Level 1, an implementation claiming Level 2 conformance
MUST:

1. Serve a tool list at `GET /agent/tools`.
2. Accept tool invocations at `POST /agent/tools/{name}`.
3. Return 404 for unknown tool names.
4. Enforce tool consent when `consent_required` is true.

### 20.4 Level 3 Conformance

In addition to Level 2, an implementation claiming Level 3 conformance
MUST:

1. Serve an SSE stream at `GET /agent/stream`.
2. Emit events using the defined event types (Section 8.4).
3. Include monotonically increasing `seq` values in event data.
4. Send heartbeat events at a regular interval.
5. Support reconnection via `Last-Event-ID`.
6. Serve task status at `GET /agent/tasks/{task_id}`.

### 20.5 Level 4 Conformance

In addition to Level 3, an implementation claiming Level 4 conformance
MUST:

1. Support the three-phase session handshake (Section 9.2).
2. Enforce session state machine transitions (Section 9.4).
3. Validate delegation chains per Section 11.11.1.
4. Support at least one authentication method (Section 12.1).
5. Resolve trust tiers from authentication credentials.

### 20.6 Level 5 Conformance

In addition to Level 4, an implementation claiming Level 5 conformance
MUST support all 8 capability groups (Section 17.1).

### 20.7 Testing Conformance

Conformance testing uses the JSON vector files in `tests/vectors/` of
the reference repository. Their format, the fixed test keys, and the way
to run them from another language are described in
`tests/vectors/README.md`. The vectors cover:

- schema acceptance and rejection for every body type and envelope
  rule;
- byte-exact canonical forms and deterministic Ed25519 signatures for
  every signed artefact: RFC 9421 requests, delegation links, key
  revocations, cost receipts, and federation proofs and revokes;
- the session-binding key agreement and HMACs.

Implementations SHOULD pass all test vectors for their declared
conformance level. Implementations that sign or verify any of the
artefacts above MUST reproduce the canonical bytes exactly.

---

## 21. References

### 21.1 Normative References

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC 3629]** Yergeau, F., "UTF-8, a transformation format of
  ISO 10646", STD 63, RFC 3629, November 2003.
- **[RFC 7231]** Fielding, R., Ed. and J. Reschke, Ed.,
  "Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content",
  RFC 7231, June 2014.
- **[RFC 7517]** Jones, M., "JSON Web Key (JWK)", RFC 7517,
  May 2015.
- **[RFC 7807]** Nottingham, M. and E. Wilde, "Problem Details for
  HTTP APIs", RFC 7807, March 2016.
- **[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in
  RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC 8615]** Nottingham, M., "Well-Known Uniform Resource
  Identifiers (URIs)", RFC 8615, May 2019.
- **[RFC 5869]** Krawczyk, H. and P. Eronen, "HMAC-based
  Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869,
  May 2010.
- **[RFC 7748]** Langley, A., Hamburg, M., and S. Turner, "Elliptic
  Curves for Security", RFC 7748, January 2016.
- **[RFC 8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital
  Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- **[RFC 9421]** Backman, A. and J. Richer, "HTTP Message
  Signatures", RFC 9421, February 2024.
- **[RFC 9530]** Polli, R. and L. Pardue, "Digest Fields", RFC 9530,
  February 2024.
- **[W3C SSE]** Hickson, I., "Server-Sent Events", W3C
  Recommendation, February 2015.

### 21.2 Informative References

- **[W3C DID]** Sporny, M. et al., "Decentralized Identifiers
  (DIDs) v1.0", W3C Recommendation, July 2022.
- **[W3C Trace Context]** Kanzhelev, S. et al., "Trace Context",
  W3C Recommendation, February 2020.

---

## Appendix A: Complete Endpoint Summary

| Method | Path                            | Level | Auth Required | Description                      |
|--------|---------------------------------|-------|---------------|----------------------------------|
| GET    | `/.well-known/agent.json`       | 0     | No            | Agent identity document          |
| GET    | `/.well-known/agent-keys.json`  | 0     | No            | JWKS public keys                 |
| GET    | `/agent/health`                 | 0     | No            | Health check                     |
| POST   | `/agent/message`                | 1     | Optional      | Primary message endpoint         |
| GET    | `/agent/tools`                  | 2     | Optional      | List available tools             |
| GET    | `/agent/tools/{name}`           | 2     | Optional      | Get tool detail                  |
| POST   | `/agent/tools/{name}`           | 2     | Optional      | Invoke a tool                    |
| GET    | `/agent/stream`                 | 3     | Optional      | SSE event stream                 |
| GET    | `/agent/tasks/{task_id}`        | 3     | Optional      | Poll task status                 |
| GET    | `/agent/resolve/{slug}`         | 5     | No            | Registry slug resolution         |

---

## Appendix B: AgentMessage JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AgentMessage",
  "description": "Universal message envelope for AMP agent communication",
  "type": "object",
  "required": ["sender", "recipient", "id", "body_type"],
  "properties": {
    "sender": {
      "type": "string",
      "description": "Agent address of the sender"
    },
    "recipient": {
      "type": "string",
      "description": "Agent address of the recipient"
    },
    "id": {
      "type": "string",
      "description": "Unique message identifier (UUID v4 recommended)"
    },
    "body_type": {
      "type": "string",
      "description": "Dot-namespaced type string determining body semantics"
    },
    "headers": {
      "type": "object",
      "description": "Extensible key-value headers",
      "additionalProperties": true
    },
    "body": {
      "description": "Message payload, structure determined by body_type"
    }
  },
  "additionalProperties": false
}
```

---

## Appendix C: Agent.json JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AgentJson",
  "description": "Agent identity document served at /.well-known/agent.json",
  "type": "object",
  "required": ["protocol_version", "identifiers", "endpoint"],
  "properties": {
    "protocol_version": {
      "type": "string",
      "description": "Semantic version of the AMP protocol"
    },
    "identifiers": {
      "type": "array",
      "items": {"type": "string"},
      "minItems": 1,
      "description": "All agent:// URIs for this agent"
    },
    "endpoint": {
      "type": "string",
      "format": "uri",
      "description": "HTTPS URL for POST /agent/message"
    },
    "jwks_url": {
      "type": "string",
      "format": "uri",
      "description": "URL to the agent's JWKS endpoint"
    },
    "capabilities": {
      "type": "object",
      "properties": {
        "groups": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["messaging", "streaming", "tools", "identity",
                     "session", "delegation", "presence", "events"]
          }
        },
        "level": {
          "type": "integer",
          "minimum": 0,
          "maximum": 5
        }
      }
    },
    "constraints": {"type": "object"},
    "security": {"type": "object"},
    "billing": {"type": "object"},
    "streaming": {"type": "object"},
    "compliance": {"type": "object"},
    "languages": {
      "type": "array",
      "items": {"type": "string"}
    },
    "ttl_seconds": {
      "type": "integer",
      "minimum": 1,
      "default": 3600
    },
    "visibility": {
      "type": "object",
      "properties": {
        "level": {
          "type": "string",
          "enum": ["public", "authenticated", "private", "hidden"]
        },
        "contact_policy": {
          "type": "string",
          "enum": ["open", "handshake_required", "verified_only",
                   "delegation_only", "explicit_invite"]
        }
      }
    },
    "supported_schemas": {
      "type": "array",
      "items": {"type": "string"}
    },
    "status": {
      "type": "string",
      "enum": ["active", "deactivating", "decommissioned"],
      "default": "active"
    },
    "moved_to": {
      "type": "string",
      "description": "agent:// URI this agent has migrated to"
    },
    "certifications": {
      "type": "array",
      "items": {"type": "object"}
    }
  },
  "additionalProperties": true
}
```

---

## Appendix D: Security Pipeline Order

When processing an incoming `POST /agent/message` request,
implementations MUST respect the ordering constraints below and SHOULD
otherwise follow the order of the reference server.

**Normative ordering constraints**

- The message size limit MUST be enforced before the body is parsed.
- **Authentication MUST run before deduplication, and deduplication
  MUST be keyed by the authenticated caller** (Section 12.5).

  A dedup store returns the *cached response* for a repeated message
  ID. If deduplication ran before authentication, or were keyed only by
  the `sender` and `id` fields that the client chooses, then anyone who
  learns a message ID could submit an unauthenticated or differently
  authenticated envelope with that ID and receive the original caller's
  reply. Message IDs are not secrets: they appear in logs, in
  `In-Reply-To` headers, and in traces. Keying the cache by the
  authenticated principal means a replayed ID only ever returns a
  response to the caller that earned it.

  Anonymous callers, where the deployment admits them, share one
  principal identity. Deployments that must keep anonymous replies
  confidential MUST require authentication.
- Envelope and body validation, sender binding, and the recipient check
  SHOULD run before deduplication, so that rejected envelopes never
  occupy dedup capacity or get a cached rejection.
- Rate limiting SHOULD run immediately after authentication, before
  expensive validation. It is keyed by principal, or by peer address
  for anonymous callers.
- Nonces MUST be recorded only after the signature that carries them
  verifies (Sections 12.6 and 12.15).

**Reference server order** (`AgentServer.handle`,
`_handle_message_request` and `_handle_message` in
`ampro/server/core.py`; policy in `ampro/server/security.py`):

1. **Message size** -- A body over `max_message_bytes` (default
   10 MiB) is rejected with 413. This check runs for every route.
2. **Authentication** -- The configured authenticators run in order,
   and the first principal wins. The authenticators are RFC 9421
   signatures (Section 12.15), and JWT, DID proof, API key or mTLS
   credentials (Section 12.1).
   - A presented but invalid credential is rejected with 401 and
     `WWW-Authenticate`.
   - With no credential, the request is rejected with 401 if the policy
     requires authentication. Otherwise the caller is anonymous at tier
     EXTERNAL.
3. **Rate limiting** -- The limit is applied per principal, or per peer
   address for anonymous callers. An exceeded limit gets 429 with
   `Retry-After` and the `X-RateLimit-*` headers.
4. **Envelope and schema validation** -- A body that is not JSON, an
   invalid `AgentMessage`, or a body that fails its `body_type` schema
   is rejected with 400. Unknown body types pass through (Section
   5.1.4).
5. **Sender binding** -- If the principal is cryptographically bound to
   an agent address (an RFC 9421 key with a known owner, a DID proof, or
   an mTLS identity), the envelope `sender` MUST equal that address, or
   the request is rejected with 403.
6. **Recipient check** -- The envelope `recipient` (normalised) MUST be
   one of this agent's identifiers or configured aliases, or the request
   is rejected with 400. This stops a message signed for agent A from
   being replayed against agent B.
7. **Loop detection** -- A `Visited-Agents` header with more than 20
   entries, or one that already contains this agent, is rejected with
   409.
8. **Handler lookup** -- A body type with no handler gets 501.
9. **Deduplication** -- The key is
   `principal_id || 0x00 || sender || 0x00 || id`.
   - For a completed duplicate, the server returns the cached response.
   - For a duplicate still in flight, it returns 409.
   - Responses with a status of 500 or above are not cached.
10. **Concurrency** -- Requests are limited per principal (or per
    sender for anonymous callers) and in total. A request over the
    limit gets 503 with `Retry-After`.
11. **Dispatch with timeout** -- The handler runs under the configured
    timeout. A timeout returns 408.

Implementations that also perform the checks below SHOULD place them
after step 6 and before dispatch:

- version negotiation (406);
- session validation (410), with session binding verified per Section
  9.3.2 (403);
- delegation-chain validation (Section 11.11.1);
- compliance and contact-policy checks (403).

The reference server leaves these checks to handlers and middleware.

---

## Appendix E: Addressing

### E.1 The `agent://` URI Scheme

Every AMP agent has a canonical address using the `agent://` scheme.
Three address forms are defined:

#### E.1.1 Direct Host

```
agent://bakery.example.com
agent://192.168.1.50:8080
```

Resolution: Fetch `https://{host}/.well-known/agent.json`.

#### E.1.2 Registry Slug

```
agent://sales@acme.example.com
agent://my-bot@registry.example.com
```

Resolution: `GET https://{registry}/agent/resolve/{slug}`.

#### E.1.3 DID

```
agent://did:web:acme.example.com
agent://did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

Resolution: W3C DID resolution per the DID specification.

### E.2 Parsing Rules

```
agent://{authority}

If authority contains "did:" → DID resolution
If authority contains "@"   → split into {slug}@{registry}, registry resolution
Otherwise                   → direct host resolution
```

### E.3 Internal Shorthand

Within a platform's boundary, bare slugs (`@data-processor`) are
acceptable as internal shorthand. They MUST be normalized to full
`agent://` URIs before cross-platform communication:

| Shorthand             | Normalized Form                          |
|-----------------------|------------------------------------------|
| `@alice`              | `agent://alice@{default_registry}`       |
| `https://example.com` | `agent://example.com`                    |
| `example.com`         | `agent://example.com`                    |

---

*End of specification.*
