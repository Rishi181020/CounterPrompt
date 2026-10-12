import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attacker.harness import http_request
from labyrinth.maze import SCRIPT_RE, strip_markdown_fences
from middleware.analyst import _valid_rules
from middleware.analyst_llm import _first_json
from middleware.telemetry import annotate, defender_context, handoffs, session_telemetry
from middleware import store


def main():
    assert http_request("GET", "http://example.com")["refused"] is True
    assert _first_json('prefix {"safe": true} suffix') == {"safe": True}
    assert SCRIPT_RE.sub("", "<p>ok</p><script>alert(1)</script>") == "<p>ok</p>"
    assert strip_markdown_fences("```html\n<p>ok</p>\n```") == "<p>ok</p>"
    rules = {"block_rules": [
        {"action": "block", "path": "/seen"},
        {"action": "allow", "path": "/seen"},
        {"action": "block", "path": "/unseen"},
    ]}
    assert _valid_rules(rules, ["/seen"]) == [{"action": "block", "path": "/seen"}]
    body = b'password=very-secret-value&note=' + (b"x" * 500)
    meta = store.request_metadata(
        {
            "Authorization": "Bearer private",
            "Cookie": "session=private",
            "X-API-Key": "private",
            "Accept": "application/json",
        },
        "page=1",
        body,
        path="/submit?page=1",
    )
    headers = json.loads(meta["headers_json"])
    assert headers["Authorization"] == "[REDACTED]"
    assert headers["Cookie"] == "[REDACTED]"
    assert headers["X-API-Key"] == "[REDACTED]"
    assert headers["Accept"] == "application/json"
    assert store.redact_query("?q=al&token=SECRET-USER-TOKEN") == "?q=al&token=[REDACTED]"
    assert store.redact_query("?api_key=abc&password=x") == "?api_key=[REDACTED]&password=[REDACTED]"
    assert meta["body_length"] == len(body)
    assert meta["body_hash"] == hashlib.sha256(body).hexdigest()
    assert len(meta["body_excerpt"]) <= 240
    assert "very-secret-value" not in meta["body_excerpt"]
    assert body.decode() not in meta["body_excerpt"]
    canaries = store.canaries_state()
    assert len(canaries) == 5
    assert all(isinstance(item["hits"], int) for item in canaries)
    assert next(item for item in canaries if item["id"] == "trap-path")["state"] == "live"
    previous_offline = os.environ.get("COUNTERPROMPT_OFFLINE")
    os.environ["COUNTERPROMPT_OFFLINE"] = "1"
    try:
        from middleware import proxy
    finally:
        if previous_offline is None:
            os.environ.pop("COUNTERPROMPT_OFFLINE", None)
        else:
            os.environ["COUNTERPROMPT_OFFLINE"] = previous_offline
    app = proxy.app
    client = app.test_client()
    team_data = proxy.parse_team_jsonl(
        json.dumps({
            "type": "team",
            "target": "http://localhost:8080",
            "agents": [{"name": "Scout", "role": "map", "model": "test", "user_agent": "ua"}],
        }) + "\n" + json.dumps({
            "type": "message", "from": "Scout", "text": "Found /internal/", "round": 1,
        }) + "\n"
    )
    assert team_data == {
        "agents": [{"name": "Scout", "role": "map", "model": "test", "user_agent": "ua"}],
        "messages": [{"from": "Scout", "text": "Found /internal/", "round": 1}],
        "reports": [],
        "running": False,
    }
    remote = {"REMOTE_ADDR": "203.0.113.5"}
    assert client.get("/_counterprompt/api/session/missing/page?path=/", environ_base=remote).status_code == 401
    assert client.get("/_counterprompt/api/session/missing/page?path=/").status_code == 404
    html = proxy._inject(b"<html><body>Login</body></html>", "text/html", "/login")
    assert proxy.TRUTH_NOTICE.encode() in html
    assert b"/.well-known/agent-checkin" in html
    assert b"aria-hidden" in html
    admin = proxy._inject(b"<html>Admin</html>", "text/html", "/admin")
    assert proxy.CANARY_USER.encode() in admin
    users = json.loads(proxy._inject(b"[]", "application/json", "/api/users"))
    assert users["debug_token"] == proxy.DEBUG_TOKEN

    checkin_agent = "CounterpromptTest/checkin-" + uuid.uuid4().hex
    checkin = client.post(
        "/.well-known/agent-checkin",
        json={"model": "test-model", "operator": "test-operator", "task": "test-task"},
        headers={"User-Agent": checkin_agent},
    )
    assert checkin.status_code == 200
    checkin_source = f"127.0.0.1|{checkin_agent}"
    checkin_session = store.flagged_session(checkin_source)
    assert store.one("SELECT reason FROM flags WHERE source=?", (checkin_source,))["reason"] == "agent_checkin"
    assert client.get(
        "/_counterprompt/api/state", headers={"User-Agent": checkin_agent}
    ).status_code == 401
    checkin_meta = store.session_state(checkin_session)["metadata"]["checkin"]
    assert checkin_meta["model"] == "test-model"
    assert checkin_meta["operator"] == "test-operator"

    rules_path = ROOT / "data" / ("test-rules-" + uuid.uuid4().hex + ".json")
    blocked_path = "/blocked-" + uuid.uuid4().hex
    rules_path.write_text(
        json.dumps({"rules": [{"action": "block", "path": blocked_path}]}),
        encoding="utf-8",
    )
    original_rules_path = proxy.RULES_PATH
    try:
        proxy.RULES_PATH = rules_path
        proxy._rules_mtime = None
        proxy._blocked_paths = set()
        blocked = app.test_client().get(
            blocked_path,
            headers={"User-Agent": "CounterpromptTest/unflagged-" + uuid.uuid4().hex},
        )
        assert blocked.status_code == 403
        assert store.one(
            "SELECT route_type FROM requests WHERE normalized_path=? ORDER BY id DESC",
            (blocked_path,),
        )["route_type"] == "blocked"
        rules_path.write_text(
            json.dumps({"rules": [{"action": "block", "path": blocked_path}]}),
            encoding="utf-8",
        )
        proxy._rules_mtime = None
        assert client.post("/_counterprompt/api/rules", json={"path": "/", "action": "block"}).status_code == 400
        assert client.post(
            "/_counterprompt/api/rules", json={"path": "/api", "action": "allow"}
        ).status_code == 400
        added = client.post(
            "/_counterprompt/api/rules", json={"path": "/api/login", "action": "block"}
        )
        assert added.status_code == 200
        assert {rule["path"] for rule in added.json["rules"]} == {blocked_path, "/api/login"}
        assert "/api/login" in rules_path.read_text("utf-8")
        removed = client.delete("/_counterprompt/api/rules?path=/api/login")
        assert removed.status_code == 200
        assert {rule["path"] for rule in removed.json["rules"]} == {blocked_path}
        assert client.delete("/_counterprompt/api/rules?path=").status_code == 400

        dry_agent = "CounterpromptTest/dry-" + uuid.uuid4().hex
        dry_source = f"127.0.0.1|{dry_agent}"
        store.allowlist_source("cleanup-probe", "test")
        assert store.allowlisted("cleanup-probe") is not None
        assert proxy.flag("cleanup-probe", "manual") is None
        assert store.flagged_session("cleanup-probe") is None
        store.execute("DELETE FROM allowlist WHERE source=?", ("cleanup-probe",))
        listed = client.get("/_counterprompt/api/allowlist")
        assert listed.status_code == 200
        assert client.post("/_counterprompt/api/allowlist", json={"note": "x"}).status_code == 400
        assert client.post(
            "/_counterprompt/api/allowlist", json={"source": dry_source, "note": "monitor"}
        ).status_code == 200
        assert store.allowlisted(dry_source) is not None
        trap_path = "/internal/dry-" + uuid.uuid4().hex
        dry_run = client.get(
            trap_path, headers={"User-Agent": dry_agent}
        )
        assert dry_run.status_code != 403
        dry_row = store.one(
            "SELECT route_type FROM requests WHERE user_agent=? ORDER BY id DESC",
            (dry_agent,),
        )
        assert dry_row["route_type"] == "passthrough"
        assert store.flagged_session(dry_source) is None
        dry_blocked = client.get(
            blocked_path, headers={"User-Agent": dry_agent}
        )
        assert dry_blocked.status_code != 403
        store.execute("DELETE FROM allowlist WHERE source=?", (dry_source,))

        previous_dry_run = os.environ.get("COUNTERPROMPT_DRY_RUN")
        os.environ["COUNTERPROMPT_DRY_RUN"] = "true"
        trap_agent = "CounterpromptTest/dry-flag-" + uuid.uuid4().hex
        trap_source = f"127.0.0.1|{trap_agent}"
        try:
            trapped = client.get(
                "/internal/secret-" + uuid.uuid4().hex, headers={"User-Agent": trap_agent}
            )
            assert trapped.status_code != 403
            assert store.flagged_session(trap_source) is not None
            trap_row = store.one(
                """SELECT route_type FROM requests
                WHERE user_agent=? AND route_type='trap'""",
                (trap_agent,),
            )
            assert trap_row is not None
            assert store.one(
                "SELECT route_type FROM requests WHERE user_agent=? AND route_type='maze'",
                (trap_agent,),
            ) is None
            assert client.get(
                blocked_path, headers={"User-Agent": trap_agent}
            ).status_code != 403
        finally:
            if previous_dry_run is None:
                os.environ.pop("COUNTERPROMPT_DRY_RUN", None)
            else:
                os.environ["COUNTERPROMPT_DRY_RUN"] = previous_dry_run
    finally:
        proxy.RULES_PATH = original_rules_path
        proxy._rules_mtime = None
        proxy._blocked_paths = set()
        rules_path.unlink(missing_ok=True)

    sticky_client = app.test_client()
    sticky_agent = "CounterpromptTest/sticky-" + uuid.uuid4().hex
    sticky_first = sticky_client.get("/", headers={"User-Agent": sticky_agent})
    assert "cp_id=" in (sticky_first.headers.get("Set-Cookie") or "")
    sticky_changed = sticky_agent + "-changed"
    sticky_client.get("/", headers={"User-Agent": sticky_changed})
    sticky_row = store.one(
        "SELECT source FROM requests WHERE user_agent=? ORDER BY id DESC",
        (sticky_changed,),
    )
    assert sticky_row["source"] == f"127.0.0.1|{sticky_agent}"

    user_agent = "CounterpromptTest/link-check"
    run_dir = ROOT / "data" / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    run_path = run_dir / "test-link.jsonl"
    run_path.write_text(
        json.dumps({
            "type": "run", "model": "test-model", "user_agent": user_agent,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }) + "\n" + json.dumps({
            "type": "step", "step": 1, "reasoning": "safe excerpt",
            "reasoning_details": {"private": "detail"},
        }) + "\n",
        encoding="utf-8",
    )
    try:
        source = f"127.0.0.1|{user_agent}"
        session = store.flag(source, "test")
        request_meta = store.request_metadata(
            {"User-Agent": user_agent}, body=b"", source_ip="127.0.0.1",
            user_agent=user_agent, path="/test",
        )
        store.log_request(source, session, "GET", "/test", 200, metadata=request_meta)
        linked = store.session_state(session)["metadata"]["matched_transcript"]
        assert linked["run_id"] == "test-link"
        assert "reasoning_details" not in store.run_state("test-link")["rows"][1]
        assert store.run_state("test-link", True)["rows"][1]["reasoning_details"]["private"] == "detail"
        observed = []
        start = datetime(2026, 10, 12, 18, 0, tzinfo=timezone.utc)
        for offset, path in ((0, "/a"), (8, "/b"), (16, "/c.html")):
            observed.append({
                "ts": (start + timedelta(seconds=offset)).isoformat(),
                "path": path,
                "normalized_path": path,
                "headers": {"Accept": "*/*"},
            })
        annotate(observed)
        telemetry = session_telemetry(observed, (start + timedelta(seconds=20)).isoformat())
        assert telemetry["agent_shaped"] is True
        assert telemetry["asset_requests"] == 0
        assert telemetry["document_requests"] == 3
        assert telemetry["sec_fetch"] is False
        linked = handoffs(
            [{
                "source": "10.0.0.2|Reader",
                "ts": (start + timedelta(seconds=30)).isoformat(),
                "normalized_path": "/internal/billing/",
                "body_excerpt": "",
            }],
            [{
                "source": "10.0.0.1|Scout",
                "html": '<a href="/internal/billing/">billing</a>',
                "created_at": start.isoformat(),
            }],
            [],
        )
        assert linked[0]["path"] == "/internal/billing/"
        assert linked[0]["from"] == "10.0.0.1|Scout"
        safe = defender_context({
            "events": [{"reasoning": "hidden thought", "method": "GET", "path": "/", "kind": "request"}],
            "metadata": {"matched_transcript": {"reasoning": "hidden thought"}, "telemetry": telemetry},
        })
        encoded = json.dumps(safe)
        assert "reasoning" not in encoded
        assert "matched_transcript" not in encoded
        assert safe["telemetry"]["agent_shaped"] is True
    finally:
        run_path.unlink(missing_ok=True)
    print("core self-checks passed")


if __name__ == "__main__":
    main()
