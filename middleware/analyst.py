import json
import threading
import time
from pathlib import Path

from middleware import store
from middleware.analyst_llm import analyze_session

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "middleware" / "rules.json"
_working = set()
_lock = threading.Lock()


def _valid_rules(result, paths):
    requested = set(paths)
    return [
        {"action": "block", "path": rule["path"]}
        for rule in result.get("block_rules", [])
        if isinstance(rule, dict)
        and rule.get("action") == "block"
        and rule.get("path") in requested
    ]


def run_analysis(session):
    with _lock:
        if session in _working:
            return
        _working.add(session)
    try:
        rows = store.all_rows(
            """SELECT id,ts,source,method,path,status,kind,detail,query_string,
            body_length,body_hash,body_excerpt,response_bytes,latency_ms,route_type,
            source_ip,user_agent,normalized_path
            FROM requests WHERE session=? ORDER BY id""",
            (session,),
        )
        if not rows:
            return
        paths = [row["path"] for row in rows]
        result, provider = analyze_session(rows)
        rules = _valid_rules(result, paths)
        result["block_rules"] = rules
        for spec in result.get("next_bait", [])[:3]:
            if isinstance(spec, dict) and str(spec.get("path", "")).startswith("/"):
                store.execute(
                    "INSERT OR REPLACE INTO bait(session,path,spec) VALUES(?,?,?)",
                    (session, spec["path"], json.dumps(spec)),
                )
        temporary = RULES_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps({"rules": rules}, indent=2), encoding="utf-8")
        temporary.replace(RULES_PATH)
        store.execute(
            "INSERT INTO analyses(session,created_at,analyst,json) VALUES(?,?,?,?)",
            (session, store.now(), provider, json.dumps(result)),
        )
    finally:
        with _lock:
            _working.discard(session)


def maybe_analyze(session):
    count = store.one("SELECT COUNT(*) n FROM requests WHERE session=?", (session,))["n"]
    done = store.one("SELECT id FROM analyses WHERE session=?", (session,))
    if count >= 10 and not done:
        threading.Thread(target=run_analysis, args=(session,), daemon=True).start()


def idle_loop():
    while True:
        sessions = store.all_rows(
            """SELECT f.session,MAX(r.ts) last_ts,COUNT(r.id) n
            FROM flags f JOIN requests r ON r.session=f.session
            GROUP BY f.session"""
        )
        now_epoch = time.time()
        for item in sessions:
            try:
                last = __import__("datetime").datetime.fromisoformat(item["last_ts"]).timestamp()
            except Exception:
                continue
            if now_epoch - last >= 30 and not store.one(
                "SELECT id FROM analyses WHERE session=?", (item["session"],)
            ):
                threading.Thread(target=run_analysis, args=(item["session"],), daemon=True).start()
        time.sleep(5)


def start_worker():
    threading.Thread(target=idle_loop, daemon=True).start()
