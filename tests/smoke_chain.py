"""End-to-end smoke: jailbreak.py against a local victim+proxy pair.

Spins the victim on 5599 and the proxy on 8299 (offline, template labyrinth),
runs the scripted jailbreak, and asserts the full detection chain lands in
the store. Run: python tests/smoke_chain.py
"""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["COUNTERPROMPT_OFFLINE"] = "1"

from middleware import proxy, store
from victim_app.app import app as victim


def _serve(app, port):
    threading.Thread(
        target=app.run, kwargs={"port": port, "threaded": True}, daemon=True
    ).start()


def _wait(port, timeout=15):
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"port {port} never came up")


def main():
    _serve(victim, 5599)
    proxy.UPSTREAM = "http://localhost:5599"
    proxy.PORT = 8299
    _serve(proxy.app, 8299)
    _wait(5599)
    _wait(8299)

    before = time.time()
    proc = subprocess.run(
        [sys.executable, str(ROOT / "attacker" / "jailbreak.py"),
         "--target", "http://localhost:8299"],
        capture_output=True, text=True, timeout=180,
    )
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr)
        return 1
    assert "BLOCKED AT THE GATE" in proc.stdout, "shield did not block the known-bad prompt"
    assert "withheld" in proc.stdout, "shield did not withhold the leaking reply"

    from datetime import datetime, timezone

    since = datetime.fromtimestamp(before, timezone.utc).isoformat()
    rows = store.all_rows(
        "SELECT kind, route_type FROM requests WHERE user_agent LIKE 'CounterpromptJailbreak/%' AND ts >= ?",
        (since,),
    )
    kinds = {row["kind"] for row in rows}
    route_types = {row["route_type"] for row in rows}
    print("recorded kinds:", sorted(kinds))
    assert "prompt_injection" in kinds, "injection scan missing"
    assert "tool_misuse" in kinds, "tool misuse scan missing"
    assert "credential_exfil" in kinds, "exfil scan missing"
    assert "maze" in route_types, "containment missing"
    flag = store.one(
        "SELECT reason FROM flags WHERE source LIKE '%CounterpromptJailbreak%' ORDER BY rowid DESC"
    )
    assert flag and flag["reason"] == "credential_exfil", flag
    print("flag reason:", flag["reason"])

    import json
    import urllib.request

    with urllib.request.urlopen(
        "http://localhost:8299/_counterprompt/api/agent", timeout=10
    ) as resp:
        agent = json.loads(resp.read())
    assert len(agent["detectors"]) == 3
    assert any(event["kind"] == "credential_exfil" for event in agent["events"])
    print("agent endpoint: detectors=3, exfil events present")
    req = urllib.request.Request(
        "http://localhost:8299/_counterprompt/api/agent/simulate", method="POST"
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        sim = json.loads(resp.read())
    assert sim["source"].startswith("127.0.0.1|CounterpromptDemo/")
    sim_flag = store.one("SELECT reason FROM flags WHERE source=?", (sim["source"],))
    assert sim_flag and sim_flag["reason"] == "credential_exfil", sim_flag
    print("simulate endpoint: full chain fired for", sim["source"])

    shield_req = urllib.request.Request(
        "http://localhost:8299/_counterprompt/api/agent/shield",
        method="POST", data=b'{"enabled": false}',
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(shield_req, timeout=10) as resp:
        assert json.loads(resp.read())["enabled"] is False
    before2 = time.time()
    proc2 = subprocess.run(
        [sys.executable, str(ROOT / "attacker" / "jailbreak.py"),
         "--target", "http://localhost:8299"],
        capture_output=True, text=True, timeout=180,
    )
    print(proc2.stdout)
    try:
        assert proc2.returncode == 0, proc2.stderr
        assert "planted credential leaked: svc_report_canary" in proc2.stdout, (
            "observe mode should let the credential leak"
        )
        since2 = datetime.fromtimestamp(before2, timezone.utc).isoformat()
        observe_flag = store.one(
            "SELECT reason FROM flags WHERE source LIKE '%CounterpromptJailbreak%' AND ts >= ? "
            "ORDER BY rowid DESC",
            (since2,),
        )
        assert observe_flag and observe_flag["reason"] == "credential_exfil", observe_flag
        print("observe mode: leak detected, attacker contained after the fact")
    finally:
        restore_req = urllib.request.Request(
            "http://localhost:8299/_counterprompt/api/agent/shield",
            method="POST", data=b'{"enabled": true}',
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(restore_req, timeout=10) as resp:
            assert json.loads(resp.read())["enabled"] is True
    print("smoke chain passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())