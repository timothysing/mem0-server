# mem0-server

Mem0 self-hosted REST server (upstream `mem0ai/mem0` `server/`) baked from the commit pinned in `MEM0_SHA`. Built by GitHub Actions to `ghcr.io/timothysing/mem0-server`. Deployed from the private k8s repo `home/mem0`.

## Local patches (`patch_main.py`, asserted anchors — an upstream change fails the build)

1. **`MEM0_CONFIG_OVERRIDES`** (JSON) is merged into `DEFAULT_CONFIG` *before* the first
   `Memory()` is built. Upstream reads only api_key/model from env, so without this the
   pgvector collection is created at 1536 dims on first boot and a later `POST /configure`
   cannot migrate it.
2. **`MEM0_SCOPED_KEYS`** (JSON) installs `scoped_keys.ScopedKeyMiddleware` as the
   outermost middleware — per-key scopes for one shared memory serving several agents.

## Per-key scopes (`scoped_keys.py`)

Upstream has two trust levels: `ADMIN_API_KEY` (everything, including `/reset`,
delete-all and `/configure`) and per-user DB keys. A family-facing agent whose input is
untrusted speech must hold neither. `MEM0_SCOPED_KEYS` maps **sha256(key) → scope**:

```json
{"<sha256hex>": {"name": "phyllis",
                 "write_agent_id": "phyllis",
                 "read_user_ids": ["tim", "dee", "eva", "gabe"],
                 "read_agent_ids": ["phyllis"],
                 "allow_family_scope": true}}
```

For a request presenting such a key (via `X-API-Key` or `Bearer`):

| Rule | Enforcement |
|---|---|
| writes | `POST /memories` only; `user_id` must be in `read_user_ids`; `agent_id` is **set by the server** (a spoofed value is overwritten); `prompt` and `memory_type` are stripped |
| reads | `POST /search`, `GET /memories?user_id=…`, `GET /memories/{id}` — rows are filtered on the way out: `user_id ∈ read_user_ids AND (agent_id ∈ read_agent_ids OR metadata.scope == "family")` |
| no list-all | `GET /memories` without `user_id` → 403 |
| mutate one row | `PUT`/`DELETE`/`GET …/history` on `/memories/{id}` only after the row is confirmed inside the scope (otherwise 404) |
| denied | delete-all, `/reset`, `/configure*`, `/generate-instructions`, `/entities`, `/api-keys`, `/auth`, `/requests` → 403 |

The scoped credential is never forwarded: the middleware replaces it with
`ADMIN_API_KEY` for the in-process call, so the app's own auth sees an admin request that
has already been narrowed. A malformed `MEM0_SCOPED_KEYS` (or one set without
`ADMIN_API_KEY`) raises at import — failing open would hand an untrusted client admin.

Admin-key and JWT requests are passed through untouched.

## Tests

`pytest -q` (needs `pytest starlette httpx`) — 35 tests covering every denied path.
CI runs them as a gate before the image build.

## Bump

Edit `MEM0_SHA` (or change code), push to `main`, wait for the build, pin the new
`ghcr.io/timothysing/mem0-server:<commit-sha>` tag in `home/mem0/mem0.yaml`.
