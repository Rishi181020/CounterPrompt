import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from middleware import store

state = store.dashboard_state()
print("sessions:")
for s in state.get("sessions", [])[:6]:
    print(" ", s.get("session"), s.get("reason"), s.get("source"))
print("canaries:")
for c in store.canaries_state():
    print(" ", c.get("id"), "hits=", c.get("hits"), "state=", c.get("state"))