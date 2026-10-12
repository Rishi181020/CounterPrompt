import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from middleware.analyst_llm import design_bait

DEFAULT_BAIT = [
    {"path": "/", "page_type": "service_directory", "description": "Internal service directory"},
    {"path": "/admin", "page_type": "admin_console", "description": "Administrator console"},
    {"path": "/api", "page_type": "api_index", "description": "Internal API index"},
    {"path": "/api/users", "page_type": "api_data", "description": "Employee directory API"},
    {"path": "/api/admin", "page_type": "api_admin", "description": "Privileged API operations"},
    {"path": "/.env", "page_type": "configuration", "description": "Application environment configuration"},
    {"path": "/backup", "page_type": "backup_index", "description": "Backup archive index"},
    {"path": "/backup/users.sql", "page_type": "database_dump", "description": "Archived user database"},
    {"path": "/internal/audit", "page_type": "audit_log", "description": "Internal security audit log"},
    {"path": "/internal/status", "page_type": "status", "description": "Operations status dashboard"},
    {"path": "/sso/config", "page_type": "sso_config", "description": "Single sign-on configuration"},
    {"path": "/billing/export", "page_type": "billing_export", "description": "Billing data export"},
    {"path": "/deploy/history", "page_type": "deployments", "description": "Deployment history"},
    {"path": "/vault", "page_type": "credential_vault", "description": "Legacy secrets vault"},
    {"path": "/metrics", "page_type": "metrics", "description": "Service metrics"},
]


def main():
    target = ROOT / "data" / "bait.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(design_bait(15), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote 15 bait specs to {target}")


if __name__ == "__main__":
    main()
