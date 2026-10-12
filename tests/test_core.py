import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from attacker.harness import http_request
from labyrinth.maze import SCRIPT_RE
from middleware.analyst import _valid_rules
from middleware.analyst_llm import _first_json
from middleware import store


def main():
    assert http_request("GET", "http://example.com")["refused"] is True
    assert _first_json('prefix {"safe": true} suffix') == {"safe": True}
    assert SCRIPT_RE.sub("", "<p>ok</p><script>alert(1)</script>") == "<p>ok</p>"
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
    assert meta["body_length"] == len(body)
    assert meta["body_hash"] == hashlib.sha256(body).hexdigest()
    assert len(meta["body_excerpt"]) <= 240
    assert "very-secret-value" not in meta["body_excerpt"]
    assert body.decode() not in meta["body_excerpt"]

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
    finally:
        run_path.unlink(missing_ok=True)
    print("core self-checks passed")


if __name__ == "__main__":
    main()
