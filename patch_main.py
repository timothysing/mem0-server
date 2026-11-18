"""Build-time patch: let the deployment override DEFAULT_CONFIG from env MEM0_CONFIG_OVERRIDES (JSON),
merged BEFORE the first Memory() is built. Upstream only reads api_key/model from env, so without this the
pgvector collection is created at 1536 dims on first boot and a later POST /configure can't fix it."""
import pathlib

p = pathlib.Path("/app/main.py")
s = p.read_text()
anchor = "set_session_factory(SessionLocal)\ninitialize_state(DEFAULT_CONFIG)"
assert s.count(anchor) == 1, "anchor not found - upstream main.py changed, re-check the patch"
s = s.replace(anchor, '''import json as _json  # local patch (timothysing/mem0-server)
from server_state import _merge_config as _mc

if os.environ.get("MEM0_CONFIG_OVERRIDES"):
    DEFAULT_CONFIG = _mc(DEFAULT_CONFIG, _json.loads(os.environ["MEM0_CONFIG_OVERRIDES"]))

''' + anchor)
p.write_text(s)
print("patched main.py: MEM0_CONFIG_OVERRIDES")
