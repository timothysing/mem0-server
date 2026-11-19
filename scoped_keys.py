"""Per-key scopes for the self-hosted Mem0 REST server (local patch, timothysing/mem0-server).

Upstream has exactly two trust levels: `ADMIN_API_KEY` (full access to every endpoint,
including `/reset`, delete-all and `/configure`) and per-user DB API keys tied to a `User`
row. Neither can express the only thing a shared memory needs:

    "this client may write ONLY agent_id=phyllis for user_id in {tim,dee,eva,gabe},
     may read ONLY those user_ids and only its own (or family-scoped) rows,
     and may never list everything, delete everything, reset or re-configure."

Phyllis's input is untrusted family/child speech, so she must never hold the admin key.
This middleware adds that layer in front of the FastAPI app as a **pure ASGI middleware**:
it runs before the app's own auth, rewrites the request where needed (the server-chosen
`agent_id` always wins over whatever the client sent) and filters read responses, so no
endpoint can be talked into leaking another agent's rows.

Config: env `MEM0_SCOPED_KEYS`, a JSON object keyed by the **sha256 hex of the key**:

    {"<sha256hex>": {"name": "phyllis",
                     "write_agent_id": "phyllis",
                     "read_user_ids": ["tim", "dee", "eva", "gabe"],
                     "read_agent_ids": ["phyllis"],
                     "allow_family_scope": true}}

A request whose `X-API-Key` / `Bearer` token hashes to one of those entries is a scoped
request; anything else (the admin key, JWTs, unauthenticated) is passed through untouched.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("mem0.scoped_keys")

# Family-safe rows any scoped reader with allow_family_scope may see.
FAMILY_SCOPE = "family"

_ID = r"[^/]+"
_PUBLIC_PATHS = {"/api/health", "/health"}

# Request-body keys a scoped client is never allowed to set: `prompt` would let untrusted
# speech rewrite the fact-extraction prompt, `memory_type` can create non-standard rows.
_FORBIDDEN_BODY_KEYS = ("prompt", "memory_type")


@dataclass(frozen=True)
class Scope:
    name: str
    write_agent_id: Optional[str] = None
    read_user_ids: Tuple[str, ...] = ()
    read_agent_ids: Tuple[str, ...] = ()
    allow_family_scope: bool = False

    @property
    def write_user_ids(self) -> Tuple[str, ...]:
        # Writes are confined to exactly the identities the key may also read back.
        return self.read_user_ids


@dataclass
class Decision:
    """What the middleware should do with one scoped request."""

    status: int = 200
    detail: str = ""
    new_body: Optional[bytes] = None
    filter_read: bool = False
    precheck_id: Optional[str] = None

    @property
    def denied(self) -> bool:
        return self.status != 200


def load_scopes(raw: Optional[str]) -> Dict[str, Scope]:
    """Parse MEM0_SCOPED_KEYS. A malformed value is fatal: failing open would hand an
    untrusted client admin access, so the deployment must not start."""
    if not raw or not raw.strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("MEM0_SCOPED_KEYS must be a JSON object keyed by sha256 hex")
    scopes: Dict[str, Scope] = {}
    for key_hash, spec in parsed.items():
        digest = str(key_hash).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("MEM0_SCOPED_KEYS keys must be sha256 hex digests of the API key")
        if not isinstance(spec, dict):
            raise ValueError("MEM0_SCOPED_KEYS values must be objects")
        scopes[digest] = Scope(
            name=str(spec.get("name") or "scoped"),
            write_agent_id=(str(spec["write_agent_id"]) if spec.get("write_agent_id") else None),
            read_user_ids=_tuple(spec.get("read_user_ids")),
            read_agent_ids=_tuple(spec.get("read_agent_ids")),
            allow_family_scope=bool(spec.get("allow_family_scope")),
        )
    return scopes


def _tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        return tuple(str(v) for v in value)
    raise ValueError("expected a list of strings")


def key_digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def can_read(record: Any, scope: Scope) -> bool:
    """True when a single memory row is inside the scope's read window.

    The rule is `user_id in read_user_ids AND (agent_id in read_agent_ids OR
    metadata.scope == "family")` — the OR is why reads are filtered on the way out
    instead of being pushed into the store's filters, which can only AND.
    """
    if not isinstance(record, dict):
        return False
    user_id = record.get("user_id")
    if user_id is None or str(user_id) not in scope.read_user_ids:
        return False
    agent_id = record.get("agent_id")
    if agent_id is not None and str(agent_id) in scope.read_agent_ids:
        return True
    metadata = record.get("metadata")
    if scope.allow_family_scope and isinstance(metadata, dict):
        if str(metadata.get("scope")) == FAMILY_SCOPE:
            return True
    return False


def filter_payload(payload: Any, scope: Scope) -> Any:
    """Drop every row the scope may not read, from any of the shapes the server returns."""
    if isinstance(payload, list):
        return [item for item in payload if can_read(item, scope)]
    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            out = dict(payload)
            out["results"] = [item for item in payload["results"] if can_read(item, scope)]
            return out
        if "memory" in payload or "user_id" in payload or "agent_id" in payload:
            return payload if can_read(payload, scope) else None
    return payload


def _norm(path: str) -> str:
    return path[:-1] if len(path) > 1 and path.endswith("/") else path


def check_request(
    method: str,
    path: str,
    query: Dict[str, List[str]],
    body: Optional[bytes],
    scope: Scope,
) -> Decision:
    """Decide one scoped request. Pure function — the middleware only does I/O."""
    method = method.upper()
    path = _norm(path)

    if path in _PUBLIC_PATHS:
        return Decision()

    # ---- write ------------------------------------------------------------------
    if method == "POST" and path == "/memories":
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            return Decision(400, "body must be JSON")
        if not isinstance(payload, dict):
            return Decision(400, "body must be a JSON object")
        user_id = payload.get("user_id")
        if user_id is None or str(user_id) not in scope.write_user_ids:
            return Decision(403, "user_id is outside this key's scope")
        payload["user_id"] = str(user_id)
        # The server owns agent_id: a spoofed value is overwritten, never honoured.
        if scope.write_agent_id:
            payload["agent_id"] = scope.write_agent_id
        else:
            payload.pop("agent_id", None)
        for forbidden in _FORBIDDEN_BODY_KEYS:
            payload.pop(forbidden, None)
        return Decision(new_body=json.dumps(payload).encode("utf-8"))

    # ---- search -----------------------------------------------------------------
    if method == "POST" and path == "/search":
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            return Decision(400, "body must be JSON")
        if not isinstance(payload, dict):
            return Decision(400, "body must be a JSON object")
        filters = payload.get("filters")
        filters = dict(filters) if isinstance(filters, dict) else {}
        user_id = payload.get("user_id") or filters.get("user_id")
        if user_id is None or str(user_id) not in scope.read_user_ids:
            return Decision(403, "user_id is required and must be inside this key's scope")
        filters["user_id"] = str(user_id)
        payload.pop("user_id", None)
        payload["filters"] = filters
        return Decision(new_body=json.dumps(payload).encode("utf-8"), filter_read=True)

    # ---- scoped list ------------------------------------------------------------
    if method == "GET" and path == "/memories":
        user_id = (query.get("user_id") or [None])[0]
        if user_id is None or str(user_id) not in scope.read_user_ids:
            return Decision(403, "user_id is required and must be inside this key's scope")
        return Decision(filter_read=True)

    # ---- single row -------------------------------------------------------------
    m = re.fullmatch(rf"/memories/({_ID})", path)
    if m:
        if method == "GET":
            return Decision(filter_read=True)
        if method in ("PUT", "DELETE"):
            return Decision(precheck_id=m.group(1))
        return Decision(403, "not permitted for this key")

    m = re.fullmatch(rf"/memories/({_ID})/history", path)
    if m and method == "GET":
        return Decision(precheck_id=m.group(1))

    # Everything else — list-all, delete-all, /reset, /configure, /entities,
    # /api-keys, /auth, /generate-instructions — is admin-only territory.
    return Decision(403, "not permitted for this key")


def _default_fetch_memory(memory_id: str) -> Any:
    from server_state import get_memory_instance  # imported lazily: only needed in-process

    return get_memory_instance().get(memory_id)


class ScopedKeyMiddleware:
    """Pure-ASGI middleware enforcing `MEM0_SCOPED_KEYS` (see module docstring)."""

    def __init__(
        self,
        app: Callable,
        scopes: Optional[Dict[str, Scope]] = None,
        admin_api_key: Optional[str] = None,
        fetch_memory: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.app = app
        self.scopes = scopes if scopes is not None else load_scopes(os.environ.get("MEM0_SCOPED_KEYS"))
        self.admin_api_key = (
            admin_api_key if admin_api_key is not None else os.environ.get("ADMIN_API_KEY", "")
        )
        self.fetch_memory = fetch_memory or _default_fetch_memory
        if self.scopes:
            logger.info("scoped keys active: %s", ", ".join(sorted(s.name for s in self.scopes.values())))

    # ----------------------------------------------------------------- helpers
    def _match(self, headers: List[Tuple[bytes, bytes]]) -> Optional[Scope]:
        presented: List[str] = []
        for name, value in headers:
            lowered = name.lower()
            if lowered == b"x-api-key":
                presented.append(value.decode("latin-1"))
            elif lowered == b"authorization":
                raw = value.decode("latin-1")
                presented.append(re.sub(r"^Bearer\s+", "", raw, flags=re.I))
        for key in presented:
            scope = self.scopes.get(key_digest(key.strip()))
            if scope is not None:
                return scope
        return None

    def _admin_headers(self, headers: List[Tuple[bytes, bytes]], body_len: Optional[int]) -> List[Tuple[bytes, bytes]]:
        """Replace the scoped credential with the admin key so the app's own auth passes,
        and never forward the scoped key or a stray Authorization header downstream."""
        out = [
            (n, v)
            for n, v in headers
            if n.lower() not in (b"x-api-key", b"authorization", b"content-length")
        ]
        out.append((b"x-api-key", self.admin_api_key.encode("latin-1")))
        if body_len is not None:
            out.append((b"content-length", str(body_len).encode("latin-1")))
        return out

    async def __call__(self, scope_dict, receive, send):  # noqa: C901 - one ASGI dispatch
        if scope_dict.get("type") != "http" or not self.scopes:
            return await self.app(scope_dict, receive, send)

        headers: List[Tuple[bytes, bytes]] = list(scope_dict.get("headers") or [])
        key_scope = self._match(headers)
        if key_scope is None:
            return await self.app(scope_dict, receive, send)

        method = scope_dict.get("method", "GET")
        path = scope_dict.get("path", "/")
        query = _parse_query(scope_dict.get("query_string", b""))

        body = b""
        if method in ("POST", "PUT", "PATCH"):
            body = await _read_body(receive)

        decision = check_request(method, path, query, body, key_scope)
        if decision.denied:
            logger.warning(
                "scoped key %s denied %s %s: %s", key_scope.name, method, path, decision.detail
            )
            return await _json_response(send, decision.status, {"detail": decision.detail})

        if decision.precheck_id:
            try:
                record = self.fetch_memory(decision.precheck_id)
            except Exception:  # pragma: no cover - store failure
                return await _json_response(send, 502, {"detail": "memory lookup failed"})
            if not can_read(record, key_scope):
                logger.warning(
                    "scoped key %s denied %s %s: row outside scope", key_scope.name, method, path
                )
                return await _json_response(send, 404, {"detail": "Memory not found"})

        forwarded_body = decision.new_body if decision.new_body is not None else body
        new_scope = dict(scope_dict)
        new_scope["headers"] = self._admin_headers(
            headers, len(forwarded_body) if method in ("POST", "PUT", "PATCH") else None
        )

        downstream_receive = _replay(forwarded_body) if method in ("POST", "PUT", "PATCH") else receive
        if not decision.filter_read:
            return await self.app(new_scope, downstream_receive, send)

        return await self.app(new_scope, downstream_receive, _FilteringSend(send, key_scope).send)


def _parse_query(query_string: bytes) -> Dict[str, List[str]]:
    from urllib.parse import parse_qs

    return parse_qs(query_string.decode("latin-1"), keep_blank_values=True)


async def _read_body(receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        body += message.get("body", b"") or b""
        if not message.get("more_body"):
            break
    return body


def _replay(body: bytes):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


async def _json_response(send, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class _FilteringSend:
    """Buffer a JSON read response and remove rows outside the scope before it goes out."""

    def __init__(self, send, scope: Scope) -> None:
        self._send = send
        self._scope = scope
        self._start: Optional[dict] = None
        self._chunks: List[bytes] = []

    async def send(self, message) -> None:
        kind = message["type"]
        if kind == "http.response.start":
            self._start = message
            return
        if kind != "http.response.body":
            return await self._send(message)

        self._chunks.append(message.get("body", b"") or b"")
        if message.get("more_body"):
            return
        await self._flush()

    async def _flush(self) -> None:
        start = self._start or {"type": "http.response.start", "status": 200, "headers": []}
        body = b"".join(self._chunks)
        status = start.get("status", 200)
        headers = [(n, v) for n, v in start.get("headers", []) if n.lower() != b"content-length"]

        if 200 <= status < 300 and body:
            try:
                payload = json.loads(body)
            except ValueError:
                payload = None
            if payload is not None:
                filtered = filter_payload(payload, self._scope)
                if filtered is None:
                    return await _json_response(self._send, 404, {"detail": "Memory not found"})
                body = json.dumps(filtered).encode("utf-8")

        headers.append((b"content-length", str(len(body)).encode("latin-1")))
        await self._send({**start, "headers": headers})
        await self._send({"type": "http.response.body", "body": body, "more_body": False})
