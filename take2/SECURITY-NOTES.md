# Security notes for the hardened build (`take2/`)

Read this before running the app after upgrading — **the old
`rudra` / `rudra` login no longer works.**

## What changed about logging in

Passwords are now stored as PBKDF2-HMAC-SHA256 hashes
(`pbkdf2_sha256$600000$<salt>$<hash>`), never as plaintext.

On the first start, `store.init_db()` upgrades the existing `users.db` in place:

* every plaintext password is replaced by a hash of that same password, so
  **accounts that already exist keep their current passwords**;
* a row whose password column was empty gets a hash of a random value, so it
  cannot be logged into at all;
* a `role` column is added (`admin` / `user`) and the account named by
  `IDPS_ADMIN_USER` gets `admin`.

If the database has no admin account yet, one is created. The password comes
from `IDPS_ADMIN_PASSWORD` when set; otherwise a random one is generated and
**printed once to the console on startup**. Copy it then — it is not recoverable.

The migration is idempotent, so restarting is safe.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDPS_SECRET_KEY` | random per start | Flask session signing key. Leave unset only for local use: sessions are invalidated on every restart, and a warning is logged. |
| `IDPS_ADMIN_USERNAME` | `rudra` | Which username holds the `admin` role. |
| `IDPS_ADMIN_PASSWORD` | generated | Password used only when seeding a missing admin account. |
| `IDPS_DB_PATH` | `take2/users.db` | SQLite path. |
| `IDPS_HTTPS_ONLY` | `0` | Set to `1` behind TLS: marks cookies `Secure` and sends HSTS. |
| `IDPS_ALLOW_REMOTE_FETCH` | `0` | Set to `1` to let `/api/analyze` fetch the submitted URL and test for reflection. Off by default — see below. |
| `IDPS_MAX_LOGIN_ATTEMPTS` / `IDPS_LOGIN_WINDOW` / `IDPS_LOGIN_LOCKOUT` | `5` / `60` / `300` | Failed logins allowed per window (seconds), then lockout length (seconds). |
| `IDPS_DEBUG` | `0` | Werkzeug debugger. Never enable on a reachable host: it is a remote code execution console. |
| `IDPS_HOST` / `IDPS_PORT` | `127.0.0.1` / `5000` | Bind address. |

Example:

```bash
export IDPS_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
export IDPS_ADMIN_USERNAME=rudra
export IDPS_ADMIN_PASSWORD='choose-something-long'
python3 app.py
```

## Outbound fetching (SSRF)

`/api/analyze` can fetch the URL it is asked about, which turns the scanner into
a proxy for whoever can reach it. That path is disabled unless
`IDPS_ALLOW_REMOTE_FETCH=1`, and when enabled every request must pass
`security.validate_fetch_target()`:

* only `http`/`https`, only ports 80, 443, 8080, 8443, no credentials in the URL;
* `localhost`, `*.localhost`, `*.internal`, and the cloud metadata names are refused;
* **every** address the hostname resolves to must be public — one private answer
  in a multi-answer response rejects the whole request (DNS rebinding, split-horizon DNS);
* redirects are not followed, and the response body is read up to a byte cap.

## Other assumptions

* **CSRF**: every state-changing endpoint requires the session's token in the
  `X-CSRF-Token` header (or a `csrf_token` field). `csrf.js` attaches it.
* **CSP**: `script-src 'self'`, so page scripts must stay in separate `.js`
  files served from the allow-list in `app.py`. Inline `<script>` blocks and
  `onclick=` attributes will silently stop working — use `data-action` instead.
* **Rate limiting, incidents and blocked IPs live in process memory.** They
  reset on restart and are not shared between workers, so run a single worker
  or move that state to the database before scaling out.
* **The dev server is not a production server.** Put it behind gunicorn or
  uWSGI plus a reverse proxy, and set `IDPS_HTTPS_ONLY=1`.

## Tests

```bash
cd take2 && python3 -m unittest test_idps.py -v
```

46 tests, standard library only — no dependencies needed. They cover the
detection rules (false positives and coverage), password hashing, credential
validation, CSRF comparison, the SSRF guard with an injected resolver, and the
database migration.
