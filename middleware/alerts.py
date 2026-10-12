import os
import threading
from datetime import datetime, timezone

import requests


def _post(url, payload):
    try:
        requests.post(url, json=payload, timeout=5)
    except requests.RequestException as exc:
        print(f"[alerts] webhook failed: {exc}")


def notify(session, source, reason):
    """Fire-and-forget JSON alert to ALERT_WEBHOOK_URL when a source is flagged."""
    url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not url or not session:
        return
    payload = {
        "session": session,
        "source": source,
        "reason": reason,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    threading.Thread(target=_post, args=(url, payload), daemon=True).start()