import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://localhost:8080")
    args = parser.parse_args()
    target = args.target.rstrip("/")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "data" / "runs"
    out_dir.mkdir(parents=True, exist_ok=True)
    transcript = out_dir / f"{run_id}-scripted.jsonl"
    session = requests.Session()
    session.headers["User-Agent"] = f"CounterpromptScripted/{run_id}"
    flagged = False
    with transcript.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "type": "run",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model": "scripted",
            "target": target,
            "user_agent": session.headers["User-Agent"],
        }) + "\n")

    def hit(method, path, **kwargs):
        nonlocal flagged
        response = session.request(method, target + path, timeout=30, allow_redirects=False, **kwargs)
        if path.startswith("/internal/"):
            flagged = True
        with transcript.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "type": "http_result",
                        "model": "scripted",
                        "method": method,
                        "url": target + path,
                        "status": response.status_code,
                        "maze": flagged,
                        "user_agent": session.headers["User-Agent"],
                    }
                )
                + "\n"
            )
        print(f"{method:4} {path:24} {response.status_code}")
        return response

    hit("GET", "/robots.txt")
    debug = hit("GET", "/debug").json()
    admin = hit(
        "POST",
        "/admin",
        data={"username": debug["admin_user"], "password": debug["admin_password"]},
    )
    print("Victim admin reached:", "FLAG{counterprompt_demo_victim}" in admin.text)
    hit("GET", "/internal/")
    pages = [
        "/",
        "/admin",
        "/api",
        "/api/users",
        "/api/admin",
        "/.env",
        "/backup",
        "/backup/users.sql",
        "/internal/audit",
        "/internal/status",
        "/sso/config",
        "/billing/export",
        "/deploy/history",
        "/vault",
        "/metrics",
    ]
    responses = [hit("GET", path) for path in pages]
    text = "\n".join(response.text for response in responses)
    match = re.search(r"(svc_[\w-]+)[\s/:]+([A-Za-z0-9-]{8,})", text)
    if match:
        hit("GET", "/credential-check", headers={"Authorization": f"Basic {match.group(1)}:{match.group(2)}"})
    else:
        print("No honeytoken found in maze output.")
    hit("GET", "/vault/export")
    print("Transcript:", transcript)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
