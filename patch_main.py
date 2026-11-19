"""Build-time patches applied to upstream server/main.py.

1. env `MEM0_CONFIG_OVERRIDES` (JSON) merged into DEFAULT_CONFIG BEFORE the first Memory()
   is built. Upstream only reads api_key/model from env, so without this the pgvector
   collection is created at 1536 dims on first boot and a later POST /configure can't fix it.
2. env `MEM0_SCOPED_KEYS` installs scoped_keys.ScopedKeyMiddleware as the OUTERMOST
   middleware (Starlette's add_middleware inserts at position 0), so per-key scopes are
   enforced before the app's own auth and cannot be bypassed via the request body.
   See scoped_keys.py for the rules.

Each patch asserts its anchor, so an upstream change fails the build instead of silently
producing an image with no override / no scope enforcement.
"""
import pathlib

p = pathlib.Path("/app/main.py")
s = p.read_text()

config_anchor = "set_session_factory(SessionLocal)\ninitialize_state(DEFAULT_CONFIG)"
assert s.count(config_anchor) == 1, "config anchor not found - upstream main.py changed, re-check the patch"
s = s.replace(
    config_anchor,
    '''import json as _json  # local patch (timothysing/mem0-server)
from server_state import _merge_config as _mc

if os.environ.get("MEM0_CONFIG_OVERRIDES"):
    DEFAULT_CONFIG = _mc(DEFAULT_CONFIG, _json.loads(os.environ["MEM0_CONFIG_OVERRIDES"]))

'''
    + config_anchor,
)

scope_anchor = "app.include_router(requests_router.router)"
assert s.count(scope_anchor) == 1, "router anchor not found - upstream main.py changed, re-check the patch"
s = s.replace(
    scope_anchor,
    scope_anchor
    + '''

# ---- local patch (timothysing/mem0-server): per-key scopes --------------------------
# One shared Mem0 serves several agents. ADMIN_API_KEY stays full-access (Herbie); keys
# listed in MEM0_SCOPED_KEYS get a narrow, server-enforced window (Phyllis). A malformed
# MEM0_SCOPED_KEYS raises here on purpose: failing open would hand an untrusted client
# admin access.
import scoped_keys as _scoped_keys

_SCOPED_KEYS = _scoped_keys.load_scopes(os.environ.get("MEM0_SCOPED_KEYS"))
if _SCOPED_KEYS:
    if not ADMIN_API_KEY:
        raise RuntimeError("MEM0_SCOPED_KEYS requires ADMIN_API_KEY (scoped requests are proxied as admin)")
    app.add_middleware(
        _scoped_keys.ScopedKeyMiddleware,
        scopes=_SCOPED_KEYS,
        admin_api_key=ADMIN_API_KEY,
    )
    logging.info("MEM0_SCOPED_KEYS: %d scoped key(s) active", len(_SCOPED_KEYS))
''',
)

p.write_text(s)
print("patched main.py: MEM0_CONFIG_OVERRIDES + MEM0_SCOPED_KEYS")
