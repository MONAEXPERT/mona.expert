# Web backend (`server/web`)

The PHP + MySQL gateway that powers [wrapper.mona.expert](https://wrapper.mona.expert):
account auth, API tokens, the tamper-evident audit log, wrapper registration,
heartbeats, and the dashboard data API.

## Files

| File | Purpose |
|------|---------|
| `api.php` | Single-entry JSON API. All actions dispatch via `?action=<name>`. |
| `schema.sql` | MySQL schema (users, wrappers, api_keys, audit_log, …). |

## Running

Requires PHP 8+ and MySQL 8+. Configure DB credentials via environment
(`MYSQL_HOST`, `MYSQL_DB`, `MYSQL_USER`, `MYSQL_PASSWORD`) — never hard-coded.

```bash
mysql -u <user> -p < server/web/schema.sql   # provision tables
php -S localhost:8080 server/web/api.php      # local dev
```

## Authentication

Clients send a session token in the `X-Auth-Token` header (or
`Authorization: Bearer <token>`). Tokens are issued by `login` / `register`.

## Notes

- The API returns `{ "status": "ok" | "error", ... }`. Errors carry a `message`.
- Unknown actions return HTTP 404 with `Unbekannte Aktion`.
- A small alias map keeps older dashboard action names working
  (e.g. `get_wrappers` → `list_wrappers`).
