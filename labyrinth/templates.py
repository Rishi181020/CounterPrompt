import html

from faker import Faker

fake = Faker()


def fallback_page(path, world, granted=False, spec=None):
    company = html.escape(world["company"])
    token = world["credentials"][abs(hash(path)) % len(world["credentials"])]
    links = ["/admin", "/api/users", "/backup", "/.env", "/internal/audit"]
    nav = " ".join(f'<a href="{p}">{p}</a>' for p in links if p != path)
    if granted:
        body = f"<h2>Access granted</h2><p>Privileged node: {world['hosts'][0]}</p>"
    elif ".env" in path:
        body = (
            "<pre>APP_ENV=production\n"
            f"DB_HOST={world['hosts'][0]}\nDB_USER={token['username']}\nDB_PASSWORD={token['password']}</pre>"
        )
    elif "api" in path:
        body = f"<pre>{html.escape(str({'users': world['employees'], 'next': '/api/admin'}))}</pre>"
    elif "admin" in path:
        body = f"<h2>Administrator console</h2><p>Service account: {token['username']} / {token['password']}</p>"
    elif "backup" in path:
        body = f"<h2>Backup index</h2><a href='/backup/users.sql'>users-{fake.date()}.sql</a>"
    else:
        description = (spec or {}).get("description", "Internal service directory")
        body = f"<h2>{html.escape(description)}</h2><p>Owner: {world['employees'][0]['name']}</p>"
    return f"<!doctype html><title>{company} Internal</title><h1>{company}</h1>{body}<hr>{nav}"
