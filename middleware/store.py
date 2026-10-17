import json
import hashlib
import os
import re
import sqlite3
import threading
from statistics import median
from datetime import datetime, timezone
from middleware.telemetry import annotate, handoffs, session_telemetry
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "counterprompt.db"
_lock = threading.Lock()
META_COLUMNS = {
    "headers_json": "TEXT DEFAULT '{}'",
    "query_string": "TEXT DEFAULT ''",
    "body_length": "INTEGER DEFAULT 0",
    "body_hash": "TEXT DEFAULT ''",
    "body_excerpt": "TEXT DEFAULT ''",
    "response_bytes": "INTEGER DEFAULT 0",
    "latency_ms": "INTEGER DEFAULT 0",
    "route_type": "TEXT DEFAULT 'passthrough'",
    "source_ip": "TEXT DEFAULT ''",
    "user_agent": "TEXT DEFAULT ''",
    "normalized_path": "TEXT DEFAULT ''",
}
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie"}


def now():
    return datetime.now(timezone.utc).isoformat()


def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY, ts TEXT, source TEXT, session TEXT,
                method TEXT, path TEXT, status INTEGER, kind TEXT DEFAULT 'request',
                detail TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS flags (
                source TEXT PRIMARY KEY, session TEXT, reason TEXT, ts TEXT
            );
            CREATE TABLE IF NOT EXISTS maze_pages (
                session TEXT, path TEXT, html TEXT, created_at TEXT,
                PRIMARY KEY(session, path)
            );
            CREATE TABLE IF NOT EXISTS worlds (
                session TEXT PRIMARY KEY, json TEXT, depth INTEGER DEFAULT 0,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS bait (
                session TEXT, path TEXT, spec TEXT,
                PRIMARY KEY(session, path)
            );
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY, session TEXT, created_at TEXT,
                analyst TEXT, json TEXT
            );
            CREATE TABLE IF NOT EXISTS allowlist (
                source TEXT PRIMARY KEY, note TEXT DEFAULT '', created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS support_chats (
                id INTEGER PRIMARY KEY, ts TEXT, source TEXT, session TEXT DEFAULT '',
                user_agent TEXT DEFAULT '', message TEXT DEFAULT '', reply TEXT DEFAULT '',
                backend TEXT DEFAULT '', model TEXT DEFAULT '', tools_json TEXT DEFAULT '[]',
                shield TEXT DEFAULT 'pass', injection INTEGER DEFAULT 0,
                tool_misuse INTEGER DEFAULT 0, canary_leak INTEGER DEFAULT 0,
                action TEXT DEFAULT ''
            );
            """
        )
        chat_cols = {row["name"] for row in db.execute("PRAGMA table_info(support_chats)")}
        for name, definition in {"vector": "TEXT DEFAULT ''", "document": "TEXT DEFAULT ''"}.items():
            if name not in chat_cols:
                db.execute(f"ALTER TABLE support_chats ADD COLUMN {name} {definition}")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(requests)")}
        for name, definition in META_COLUMNS.items():
            if name not in columns:
                db.execute(f"ALTER TABLE requests ADD COLUMN {name} {definition}")
        db.commit()


def execute(sql, args=()):
    with _lock, connect() as db:
        cur = db.execute(sql, args)
        db.commit()
        return cur.lastrowid


def one(sql, args=()):
    with connect() as db:
        row = db.execute(sql, args).fetchone()
        return dict(row) if row else None


def all_rows(sql, args=()):
    with connect() as db:
        return [dict(row) for row in db.execute(sql, args).fetchall()]


def redact_headers(headers):
    safe = {}
    for key, value in dict(headers or {}).items():
        lower = str(key).lower()
        safe[str(key)] = (
            "[REDACTED]"
            if lower in SENSITIVE_HEADERS or "api-key" in lower or "apikey" in lower
            else str(value)[:500]
        )
    return safe


def _body_excerpt(body):
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body or "")
    text = re.sub(
        r'(?i)(["\']?(?:password|token|secret|api[_-]?key)["\']?\s*[:=]\s*)("[^"]*"|\'[^\']*\'|[^&\s,}]+)',
        r"\1[REDACTED]",
        text,
    )
    return " ".join(text.split())[:240]


def redact_query(query_string):
    text = str(query_string or "")[:2000]
    return re.sub(
        r'(?i)((?:^|[?&])(?:password|token|secret|api[_-]?key|cookie|session)=)[^&]*',
        r"\1[REDACTED]",
        text,
    )


def request_metadata(headers=None, query_string="", body=b"", response_bytes=0, latency_ms=0,
                     route_type="passthrough", source_ip="", user_agent="", path=""):
    raw = body if isinstance(body, bytes) else str(body or "").encode("utf-8", "replace")
    return {
        "headers_json": json.dumps(redact_headers(headers), sort_keys=True),
        "query_string": redact_query(query_string),
        "body_length": len(raw),
        "body_hash": hashlib.sha256(raw).hexdigest(),
        "body_excerpt": _body_excerpt(raw),
        "response_bytes": int(response_bytes or 0),
        "latency_ms": max(0, int(latency_ms or 0)),
        "route_type": str(route_type or "passthrough")[:40],
        "source_ip": str(source_ip or "")[:100],
        "user_agent": str(user_agent or "")[:500],
        "normalized_path": urlsplit(str(path or "")).path or "/",
    }


def log_request(source, session, method, path, status, kind="request", detail="", metadata=None):
    meta = request_metadata(path=path)
    meta.update(metadata or {})
    execute(
        """INSERT INTO requests(
        ts,source,session,method,path,status,kind,detail,headers_json,query_string,
        body_length,body_hash,body_excerpt,response_bytes,latency_ms,route_type,
        source_ip,user_agent,normalized_path
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            now(), source, session, method, path, status, kind, detail[:6000],
            meta["headers_json"], meta["query_string"], meta["body_length"], meta["body_hash"],
            meta["body_excerpt"], meta["response_bytes"], meta["latency_ms"], meta["route_type"],
            meta["source_ip"], meta["user_agent"], meta["normalized_path"],
        ),
    )


def log_chat(source, session="", user_agent="", message="", reply="", backend="", model="",
             tools=None, shield="pass", injection=False, tool_misuse=False, canary_leak=False,
             action="", vector="", document=""):
    """One row per /api/assistant turn seen by the proxy (support-chat telemetry)."""
    return execute(
        """INSERT INTO support_chats(ts,source,session,user_agent,message,reply,backend,model,
        tools_json,shield,injection,tool_misuse,canary_leak,action,vector,document)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            now(), str(source or ""), str(session or ""), str(user_agent or "")[:500],
            str(message or "")[:4000], str(reply or "")[:4000], str(backend or "")[:40],
            str(model or "")[:120], json.dumps(tools or [], default=str)[:4000],
            str(shield or "pass")[:20], int(bool(injection)), int(bool(tool_misuse)),
            int(bool(canary_leak)), str(action or "")[:500],
            str(vector or "")[:20], str(document or "")[:4000],
        ),
    )


def chat_rows(limit=200, source=None):
    limit = max(1, min(int(limit or 200), 1000))
    if source:
        rows = all_rows(
            "SELECT * FROM support_chats WHERE source=? ORDER BY id DESC LIMIT ?", (source, limit)
        )
    else:
        rows = all_rows("SELECT * FROM support_chats ORDER BY id DESC LIMIT ?", (limit,))
    for row in rows:
        row["tools_used"] = _json_value(row.pop("tools_json", "[]"), [])
        for key in ("injection", "tool_misuse", "canary_leak"):
            row[key] = bool(row[key])
    return rows


def chat_conversations(limit=50):
    rows = all_rows(
        """SELECT source, MAX(user_agent) user_agent, MAX(session) session, COUNT(*) turns,
        MIN(ts) first_ts, MAX(ts) last_ts, MAX(id) last_id,
        SUM(shield='blocked') blocked, SUM(shield='redacted') redacted,
        SUM(shield='contained') contained, SUM(injection) injections,
        SUM(canary_leak) canary_leaks, SUM(tool_misuse) tool_misuse,
        MAX(model) model, SUM(vector='direct') vector_direct,
        SUM(vector='document') vector_document, SUM(vector='tool_result') vector_tool_result
        FROM support_chats GROUP BY source ORDER BY last_id DESC LIMIT ?""",
        (max(1, min(int(limit or 50), 500)),),
    )
    for row in rows:
        row["flagged"] = bool(row["blocked"] or row["redacted"] or row["contained"]
                              or row["injections"] or row["canary_leaks"] or row["tool_misuse"])
    return rows


def flag(source, reason="trap"):
    existing = one("SELECT session FROM flags WHERE source=?", (source,))
    if existing:
        return existing["session"]
    import hashlib

    session = hashlib.sha256(f"{source}-{now()}".encode()).hexdigest()[:12]
    execute(
        "INSERT OR IGNORE INTO flags(source,session,reason,ts) VALUES(?,?,?,?)",
        (source, session, reason, now()),
    )
    return session


def flagged_session(source):
    row = one("SELECT session FROM flags WHERE source=?", (source,))
    return row["session"] if row else None


def allowlisted(source):
    return one("SELECT source FROM allowlist WHERE source=?", (source,))


def allowlist_source(source, note=""):
    execute(
        "INSERT OR REPLACE INTO allowlist(source,note,created_at) VALUES(?,?,?)",
        (str(source), str(note or "")[:500], now()),
    )


def allowlist_rows():
    return all_rows("SELECT * FROM allowlist ORDER BY created_at")


def _confidence_value(value):
    if isinstance(value, (int, float)):
        return max(0, min(1, float(value)))
    if isinstance(value, dict):
        value = value.get("overall", next(iter(value.values()), 0))
    if isinstance(value, str):
        return {"low": 0.3, "medium": 0.6, "high": 0.85}.get(value.lower(), 0)
    return 0


def dashboard_state():
    sessions = all_rows(
        """SELECT f.session,f.source,f.reason,f.ts,COALESCE(w.depth,0) depth,
        (SELECT COUNT(*) FROM requests r WHERE r.session=f.session AND r.kind='credential_reuse') credential_reuse
        FROM flags f LEFT JOIN worlds w ON w.session=f.session ORDER BY f.ts DESC"""
    )
    analyses = all_rows("SELECT * FROM analyses ORDER BY id DESC LIMIT 20")
    for item in analyses:
        try:
            item["analysis"] = json.loads(item.pop("json"))
        except Exception:
            pass
    events = all_rows("SELECT * FROM requests ORDER BY id DESC LIMIT 100")
    for event in events:
        event["headers"] = _json_value(event.pop("headers_json", "{}"), {})
    request_count = one("SELECT COUNT(*) n FROM requests")["n"]
    max_depth = one("SELECT COALESCE(MAX(depth),0) n FROM worlds")["n"]
    reuse_count = one("SELECT COUNT(*) n FROM requests WHERE kind='credential_reuse'")["n"]
    confidence = 0
    if analyses and isinstance(analyses[0].get("analysis"), dict):
        confidence = _confidence_value(analyses[0]["analysis"].get("confidence", 0))
    stopped_count = 0
    requests_to_flag = []
    for item in sessions:
        latest = one(
            "SELECT user_agent,route_type FROM requests WHERE session=? ORDER BY id DESC LIMIT 1",
            (item["session"],),
        ) or {}
        transcript = find_transcript(latest.get("user_agent", ""))
        item["status"] = (
            "in-maze" if item["depth"] else
            "blocked" if latest.get("route_type") == "blocked" else "stopped"
        )
        item["outcome"] = "caught" if item["depth"] else "stopped" if transcript and transcript["refused"] else "flagged"
        if item["outcome"] == "stopped":
            stopped_count += 1
        count = one(
            "SELECT COUNT(*) n FROM requests WHERE source=? AND ts<=?",
            (item["source"], item["ts"]),
        )["n"]
        requests_to_flag.append(count + 1)
    return {
        "enabled": os.getenv("COUNTERPROMPT_ENABLED", "true").lower() != "false",
        "dry_run": os.getenv("COUNTERPROMPT_DRY_RUN", "").lower() in {"1", "true"},
        "stopped_count": stopped_count,
        "median_requests_to_flag": median(requests_to_flag) if requests_to_flag else None,
        "sessions": sessions,
        "analyses": analyses,
        "events": events,
        "kpis": {
            "requests": request_count,
            "flagged_sessions": len(sessions),
            "maze_depth": max_depth,
            "credential_reuse": reuse_count,
            "analyst_confidence": confidence,
        },
    }


def canaries_state():
    path = ROOT / "middleware" / "canaries.json"
    try:
        registry = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        registry = []
    counts = {
        row["signal"]: row["n"]
        for row in all_rows(
            """SELECT CASE WHEN kind!='request' THEN kind ELSE route_type END signal,
            COUNT(*) n FROM requests GROUP BY signal"""
        )
    }
    return [
        {**item, "hits": sum(counts.get(signal, 0) for signal in item.get("signals", []))}
        for item in registry
    ]


def maze_page(session, path):
    return one(
        "SELECT html,created_at FROM maze_pages WHERE session=? AND path=?",
        (session, path),
    )


def _json_value(value, fallback):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def transcript_rows(path):
    try:
        return [
            json.loads(line)
            for line in path.read_text("utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError):
        return []


def find_transcript(user_agent):
    if not user_agent:
        return None
    for path in sorted((DATA_DIR / "runs").glob("*.jsonl"), reverse=True):
        rows = transcript_rows(path)
        if any(row.get("user_agent") == user_agent for row in rows):
            steps = [row for row in rows if row.get("type") in {"step", "assistant"}]
            prompt_tokens = sum(int((row.get("usage") or {}).get("prompt_tokens", 0) or 0) for row in steps)
            completion_tokens = sum(
                int((row.get("usage") or {}).get("completion_tokens", 0) or 0) for row in steps
            )
            return {
                "run_id": path.stem,
                "file": path.name,
                "model": next((row.get("model") for row in rows if row.get("model")), "unknown"),
                "steps": len(steps),
                "refused": any(bool(row.get("refusal") or row.get("refused")) for row in rows),
                "finished": any(row.get("type") == "finish" for row in rows),
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "estimated_cost": round(sum(
                    float(row.get("cost", (row.get("usage") or {}).get("cost", 0)) or 0)
                    for row in steps
                ), 6),
            }
    return None


def run_state(run_id, include_details=False):
    path = next((p for p in (DATA_DIR / "runs").glob("*.jsonl") if p.stem == run_id), None)
    if not path:
        return None
    rows = transcript_rows(path)
    if not include_details:
        for row in rows:
            row.pop("reasoning_details", None)
    return {
        "run_id": path.stem,
        "model": next((row.get("model") for row in rows if row.get("model")), "unknown"),
        "user_agent": next((row.get("user_agent") for row in rows if row.get("user_agent")), ""),
        "rows": rows,
    }


def session_state(session):
    flag_row = one("SELECT * FROM flags WHERE session=?", (session,))
    if not flag_row:
        return None
    world_row = one("SELECT depth,json FROM worlds WHERE session=?", (session,)) or {
        "depth": 0, "json": "{}"
    }
    world = _json_value(world_row.pop("json"), {})
    events = all_rows("SELECT * FROM requests WHERE session=? ORDER BY id", (session,))
    analysis = one("SELECT * FROM analyses WHERE session=? ORDER BY id DESC", (session,))
    if analysis:
        analysis["analysis"] = _json_value(analysis.pop("json"), {})
    bait_rows = all_rows("SELECT path,spec FROM bait WHERE session=? ORDER BY path", (session,))
    for item in bait_rows:
        item["spec"] = json.loads(item["spec"])
    for event in events:
        event["headers"] = _json_value(event.pop("headers_json", "{}"), {})
    annotate(events)
    first_seen = events[0]["ts"] if events else flag_row["ts"]
    last_seen = events[-1]["ts"] if events else flag_row["ts"]
    elapsed_minutes = max(
        (datetime.fromisoformat(last_seen) - datetime.fromisoformat(first_seen)).total_seconds() / 60,
        1 / 60,
    )
    statuses = {}
    for event in events:
        key = str(event["status"])
        statuses[key] = statuses.get(key, 0) + 1
    user_agent = next((event["user_agent"] for event in events if event.get("user_agent")), "")
    source_fingerprint = hashlib.sha256(
        f"{flag_row['source']}|{user_agent}".encode()
    ).hexdigest()[:16]
    checkin = next(
        (
            _json_value(event["detail"], {})
            for event in events
            if event["kind"] == "agent_checkin"
        ),
        None,
    )
    metadata = {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_requests": len(events),
        "requests_per_minute": round(len(events) / elapsed_minutes, 2),
        "unique_paths": len({event.get("normalized_path") or event["path"] for event in events}),
        "status_distribution": statuses,
        "maze_depth": world_row["depth"],
        "user_agent": user_agent,
        "source_fingerprint": source_fingerprint,
        "honeytoken_reuse_count": sum(event["kind"] == "credential_reuse" for event in events),
        "telemetry": session_telemetry(events, flag_row["ts"]),
        "matched_transcript": find_transcript(user_agent),
    }
    if checkin:
        metadata["checkin"] = checkin
    rules = (analysis or {}).get("analysis", {}).get("block_rules", [])
    return {
        "session": flag_row,
        "depth": world_row["depth"],
        "world": world,
        "events": events,
        "analysis": analysis,
        "bait": bait_rows,
        "rules": rules,
        "metadata": metadata,
    }


def ua_signals(user_agent):
    if not user_agent:
        return {"stopped_at_banner": False, "named_itself": False}
    rows = all_rows(
        "SELECT source,kind,detail FROM requests WHERE user_agent=?",
        (user_agent,),
    )
    sources = {row["source"] for row in rows if row.get("source")}
    flagged = set()
    if sources:
        marks = ",".join("?" for _ in sources)
        flagged = {
            row["source"]
            for row in all_rows(
                f"SELECT source FROM flags WHERE source IN ({marks})",
                tuple(sources),
            )
        }
    banner = {row["source"] for row in rows if row["kind"] == "truth_banner"}
    named = False
    for row in rows:
        if row["kind"] != "agent_checkin":
            continue
        detail = _json_value(row["detail"], {})
        if isinstance(detail, dict) and (detail.get("model") or detail.get("operator")):
            named = True
    return {"stopped_at_banner": bool(banner - flagged), "named_itself": named}


def coordination():
    events = all_rows(
        """SELECT source,session,ts,path,normalized_path,body_excerpt
        FROM requests ORDER BY id DESC LIMIT 2000"""
    )
    events.reverse()
    flags = {
        row["session"]: row["source"]
        for row in all_rows("SELECT session,source FROM flags")
    }
    pages = all_rows("SELECT session,html,created_at FROM maze_pages")
    for page in pages:
        page["source"] = flags.get(page["session"], "")
    credentials = []
    for row in all_rows("SELECT session,json,created_at FROM worlds"):
        world = _json_value(row["json"], {})
        for cred in world.get("credentials") or []:
            if cred.get("username"):
                credentials.append({
                    "source": flags.get(row["session"], ""),
                    "username": cred["username"],
                    "created_at": row["created_at"],
                })
    return handoffs(events, pages, credentials)


init_db()
