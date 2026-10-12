import re
from datetime import datetime
from statistics import median
from urllib.parse import urlsplit

ASSET_RE = re.compile(r"\.(css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map)$", re.I)
LINK_RE = re.compile(r"""href=["']([^"'#?\s]+)""", re.I)
WINDOW_S = 900


def _when(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def is_asset(path):
    return bool(ASSET_RE.search(urlsplit(str(path or "")).path))


def annotate(events):
    previous = None
    for event in events:
        path = event.get("normalized_path") or event.get("path")
        event["asset"] = is_asset(path)
        current = _when(event.get("ts"))
        event["gap_s"] = round((current - previous).total_seconds(), 2) if current and previous else None
        previous = current or previous
        headers = event.get("headers") or {}
        lower = {str(key).lower() for key in headers}
        event["has_accept"] = "accept" in lower
        event["has_sec_fetch"] = any(key.startswith("sec-fetch-") for key in lower)
    return events


def session_telemetry(events, flagged_at=None):
    deltas = [event["gap_s"] for event in events if event.get("gap_s") is not None]
    documents = sum(not event.get("asset") for event in events)
    assets = sum(bool(event.get("asset")) for event in events)
    first = _when(events[0].get("ts")) if events else None
    flagged = _when(flagged_at)
    detected = max(0.0, round((flagged - first).total_seconds(), 1)) if first and flagged else None
    spread = 0
    if len(deltas) >= 3:
        mid = median(deltas)
        spread = (sum((item - mid) ** 2 for item in deltas) / len(deltas)) ** 0.5
        mechanical = 0.3 <= mid <= 30 and spread <= max(0.5, mid * 0.35)
    else:
        mechanical = False
    return {
        "time_to_detect_s": detected,
        "median_gap_s": round(median(deltas), 2) if deltas else None,
        "mechanical": mechanical,
        "document_requests": documents,
        "asset_requests": assets,
        "agent_shaped": documents >= 3 and assets == 0,
        "sec_fetch": any(event.get("has_sec_fetch") for event in events),
        "accept": any(event.get("has_accept") for event in events),
    }


def handoffs(events, pages, credentials, window=WINDOW_S):
    served = []
    for page in pages:
        opened = _when(page.get("created_at"))
        if not opened or not page.get("source"):
            continue
        for link in LINK_RE.findall(page.get("html") or ""):
            if link.startswith("/"):
                served.append({
                    "source": page["source"],
                    "path": urlsplit(link).path,
                    "at": opened,
                })
    found = []
    seen = set()

    def add(origin, target, label, gap, kind):
        key = (origin, target, label, kind)
        if origin == target or key in seen or gap < 0 or gap > window:
            return
        seen.add(key)
        found.append({
            "from": origin,
            "to": target,
            "path": label,
            "gap_s": round(gap, 1),
            "kind": kind,
        })

    for event in events:
        opened = _when(event.get("ts"))
        path = urlsplit(str(event.get("normalized_path") or event.get("path") or "")).path
        if not opened or not path or not event.get("source"):
            continue
        for item in served:
            if item["path"] == path:
                add(item["source"], event["source"], path, (opened - item["at"]).total_seconds(), "path")
        excerpt = event.get("body_excerpt") or ""
        for cred in credentials:
            username = str(cred.get("username") or "")
            cred_at = _when(cred.get("created_at"))
            if len(username) >= 4 and cred_at and username in excerpt:
                add(cred.get("source", ""), event["source"], username, (opened - cred_at).total_seconds(), "credential")
    return found


def defender_context(state):
    events = []
    canaries = []
    for event in (state.get("events") or [])[-80:]:
        events.append({
            "ts": event.get("ts"),
            "method": event.get("method"),
            "path": event.get("normalized_path") or event.get("path"),
            "status": event.get("status"),
            "route_type": event.get("route_type"),
            "kind": event.get("kind"),
            "latency_ms": event.get("latency_ms"),
            "gap_s": event.get("gap_s"),
            "asset": event.get("asset"),
            "has_accept": event.get("has_accept"),
            "has_sec_fetch": event.get("has_sec_fetch"),
        })
        if event.get("kind") not in {None, "", "request"}:
            canaries.append({"kind": event.get("kind"), "path": event.get("path")})
    metadata = state.get("metadata") or {}
    analysis = (state.get("analysis") or {}).get("analysis") or {}
    return {
        "session": state.get("session"),
        "telemetry": metadata.get("telemetry"),
        "checkin": metadata.get("checkin"),
        "events": events,
        "canary_hits": canaries,
        "analysis_summary": analysis.get("summary") if isinstance(analysis, dict) else "",
    }
