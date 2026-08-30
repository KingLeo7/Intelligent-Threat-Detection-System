"""Web-based Intrusion Detection & Prevention System.

Run with:
    export IDPS_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
    export IDPS_ADMIN_PASSWORD="something-long"
    python3 app.py

Detection rules live in detection.py; password hashing, CSRF tokens and the SSRF
guard live in security.py. Both are plain standard-library modules with no Flask
imports so they can be tested on their own.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from collections import defaultdict
from functools import wraps

from flask import Flask, g, jsonify, redirect, request, send_from_directory, session

import detection
import security
import store

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("IDPS_DB_PATH", os.path.join(BASE_DIR, "users.db"))

app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "static"))

_SECRET_KEY, _SECRET_IS_EPHEMERAL = security.load_secret_key()
app.secret_key = _SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,                                   # no JS access
    SESSION_COOKIE_SAMESITE="Lax",                                  # blocks cross-site sends
    SESSION_COOKIE_SECURE=security.env_flag("IDPS_HTTPS_ONLY"),     # set behind TLS
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
    MAX_CONTENT_LENGTH=256 * 1024,
    JSON_SORT_KEYS=False,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("idps")

if _SECRET_IS_EPHEMERAL:
    log.warning(
        "IDPS_SECRET_KEY is not set - generated a temporary key. Sessions will be "
        "invalidated on restart. Set it before deploying."
    )

# Outbound fetching is opt-in. Left off, /api/analyze inspects the submitted
# string only and the server never makes a request on a user's behalf.
ALLOW_REMOTE_FETCH = security.env_flag("IDPS_ALLOW_REMOTE_FETCH", default=False)

ADMIN_USERNAME = os.environ.get("IDPS_ADMIN_USERNAME", "rudra").strip() or "rudra"

# ─────────────────────────────────────────
# Login throttling
# ─────────────────────────────────────────
MAX_ATTEMPTS = int(os.environ.get("IDPS_MAX_LOGIN_ATTEMPTS", "5"))
WINDOW = int(os.environ.get("IDPS_LOGIN_WINDOW", "60"))        # seconds
LOCKOUT = int(os.environ.get("IDPS_LOGIN_LOCKOUT", "300"))     # seconds

_login_attempts: dict[str, list[float]] = defaultdict(list)
_lockout_until: dict[str, float] = {}


def _recent_failures(ip: str) -> int:
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < WINDOW]
    return len(_login_attempts[ip])


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    unlock_at = _lockout_until.get(ip)
    if unlock_at is not None:
        if now < unlock_at:
            return True
        del _lockout_until[ip]
        _login_attempts[ip] = []
    _recent_failures(ip)
    return False


def record_failed_login(ip: str) -> None:
    _login_attempts[ip].append(time.time())
    if _recent_failures(ip) >= MAX_ATTEMPTS:
        _lockout_until[ip] = time.time() + LOCKOUT
        log.warning("locked out %s after %s failed logins", ip, MAX_ATTEMPTS)


def clear_failed_logins(ip: str) -> None:
    _login_attempts.pop(ip, None)
    _lockout_until.pop(ip, None)


def brute_force_signals(ip: str) -> list[detection.RuntimeSignal]:
    """Turn the real failed-login counter into evidence for the rule engine.

    Brute force is a property of a sequence of requests, not of a URL string, so
    this is the only trustworthy source for it.
    """
    signals: list[detection.RuntimeSignal] = []
    if ip in _lockout_until and time.time() < _lockout_until[ip]:
        signals.append(detection.RuntimeSignal(
            category=detection.BRUTE, id="brute-runtime-lockout", weight=5,
            severity="high", note=f"{ip} is locked out for repeated login failures",
        ))
        return signals
    failures = _recent_failures(ip)
    if failures >= max(2, MAX_ATTEMPTS // 2):
        signals.append(detection.RuntimeSignal(
            category=detection.BRUTE, id="brute-runtime-failures", weight=4,
            severity="medium",
            note=f"{failures} failed logins from {ip} in the last {WINDOW}s",
        ))
    return signals


# ─────────────────────────────────────────
# Database
# ─────────────────────────────────────────
def get_db_connection() -> sqlite3.Connection:
    """One connection per request, closed by teardown_appcontext."""
    conn = getattr(g, "_db", None)
    if conn is None:
        conn = store.connect(DB_PATH)
        g._db = conn
    return conn


@app.teardown_appcontext
def _close_db(exception=None):
    conn = getattr(g, "_db", None)
    if conn is not None:
        conn.close()
        g._db = None


def init_db() -> None:
    """Create/upgrade the schema and seed the admin account (see store.init_db)."""
    report = store.init_db(
        DB_PATH,
        admin_username=ADMIN_USERNAME,
        admin_password=os.environ.get("IDPS_ADMIN_PASSWORD"),
    )
    if report["migrated"]:
        log.warning(
            "migrated %s plaintext password(s) to PBKDF2 hashes", report["migrated"]
        )
    if report["generated_password"]:
        # Shown once and never stored in plaintext. The old build shipped a
        # published default credential (rudra/rudra) instead.
        log.warning(
            "seeded admin '%s' with generated password: %s  (set IDPS_ADMIN_PASSWORD "
            "to choose your own)", ADMIN_USERNAME, report["generated_password"],
        )
    elif report["created_admin"]:
        log.info("seeded admin '%s' from IDPS_ADMIN_PASSWORD", ADMIN_USERNAME)


def current_user() -> sqlite3.Row | None:
    username = session.get("username")
    if not username:
        return None
    return get_db_connection().execute(
        "SELECT id, username, role FROM users WHERE username = ?", (username,)
    ).fetchone()


# ─────────────────────────────────────────
# Access control
# ─────────────────────────────────────────
def _wants_json() -> bool:
    return request.path.startswith("/api/") or request.is_json


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            if _wants_json():
                return jsonify({"error": "authentication required"}), 401
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """Authorise on the stored role, not on a hardcoded username."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            if _wants_json():
                return jsonify({"error": "authentication required"}), 401
            return redirect("/")
        if user["role"] != "admin":
            log.warning("denied admin access to '%s'", user["username"])
            if _wants_json():
                return jsonify({"error": "administrator role required"}), 403
            return "Access denied", 403
        return f(*args, **kwargs)
    return wrapper


def csrf_protect(f):
    """Require the session's CSRF token on state-changing requests.

    SameSite=Lax already blocks cross-site form posts in current browsers; this
    is the second layer, and it is what stops a cross-origin fetch from wiping
    the logs or deleting accounts.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        expected = session.get("csrf_token")
        provided = request.headers.get(security.CSRF_HEADER) or request.form.get(
            security.CSRF_FIELD
        )
        if not provided and request.is_json:
            provided = (request.get_json(silent=True) or {}).get(security.CSRF_FIELD)
        if not security.csrf_tokens_match(expected, provided):
            log.warning("rejected %s %s: bad CSRF token", request.method, request.path)
            return jsonify({"error": "invalid or missing CSRF token"}), 403
        return f(*args, **kwargs)
    return wrapper


def ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = security.new_csrf_token()
        session["csrf_token"] = token
    return token


# ─────────────────────────────────────────
# In-memory incident store
# ─────────────────────────────────────────
MAX_LOGS = 200
logs: list[dict] = []
blocked_ips: list[str] = []
stats = {"requests": 0, "attacks": 0, "blocked": 0}

# Values are stored raw and escaped at render time by the page scripts. Escaping
# on the way in (as the previous version did) means anything re-serialised to
# JSON is double-escaped and shows up as `&amp;lt;script&amp;gt;`.


def determine_action(result: detection.AnalysisResult) -> str:
    if result.safe:
        return "No action needed"
    primary = result.categories[0]
    return {
        detection.SQL: "Blocked request and blacklisted IP",
        detection.CMDI: "Blocked request and blacklisted IP",
        detection.RFI: "Blocked external payload and blacklisted IP",
        detection.LFI: "Blocked path traversal attempt",
        detection.XSS: "Filtered payload and blocked request",
        detection.CSRF: "Dropped request and invalidated token",
        detection.BRUTE: "Blocked request and rate-limited IP",
    }.get(primary, "Blocked request and blacklisted IP")


def record_incident(url: str, result: detection.AnalysisResult, check_type: str,
                    ip: str, fetch_note: str, fetch_status) -> dict:
    stats["requests"] += 1
    action = determine_action(result)
    if not result.safe:
        stats["attacks"] += 1
        if ip not in blocked_ips:
            blocked_ips.append(ip)
            stats["blocked"] += 1
        log.warning("%s from %s -> %s (%s)", result.summary, ip, action, url[:200])

    entry = {
        "url": url[:500],
        "result": result.summary,
        "safe": result.safe,
        "severity": result.severity,
        "type": check_type,
        "action": action,
        "user": session.get("username", "anonymous"),
        "ip": ip,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": [f.to_dict() for f in result.findings],
        "fetch_status": fetch_status,
        "fetch_note": fetch_note,
    }
    logs.insert(0, entry)
    del logs[MAX_LOGS:]
    return entry


def fetch_for_reflection(url: str) -> tuple[str, str, int | None]:
    """Optionally fetch ``url`` so reflected payloads can be spotted.

    Returns ``(body, note, status)``. Disabled unless IDPS_ALLOW_REMOTE_FETCH is
    set, and every target goes through the SSRF guard first.
    """
    if not ALLOW_REMOTE_FETCH:
        return "", "remote fetch disabled (set IDPS_ALLOW_REMOTE_FETCH=1 to enable)", None
    if not url.lower().startswith(("http://", "https://")):
        # Nothing is fetched for file://, gopher:// and friends. Say so rather
        # than returning a blank note, so the dashboard can explain the gap.
        return "", "fetch skipped: only http and https targets are fetched", None

    decision = security.validate_fetch_target(url)
    if not decision.allowed:
        log.warning("refused outbound fetch of %s: %s", url[:200], decision.reason)
        return "", f"fetch refused: {decision.reason}", None

    try:
        import requests
    except ImportError:
        return "", "fetch skipped: requests is not installed", None

    response = None
    try:
        response = requests.get(
            url,
            timeout=security.FETCH_TIMEOUT_SECONDS,
            allow_redirects=False,            # a redirect can point back at localhost
            stream=True,
            headers={"User-Agent": "IDPS-Scanner/2.0", "Accept": "text/html,text/plain"},
        )
        body = response.raw.read(security.MAX_FETCH_BYTES, decode_content=True) or b""
        return body.decode("utf-8", "replace"), "", response.status_code
    except Exception as exc:                  # network failures must not 500 the scan
        log.info("fetch of %s failed: %s", url[:200], exc.__class__.__name__)
        return "", f"fetch failed: {exc.__class__.__name__}", None
    finally:
        if response is not None:
            response.close()


# ─────────────────────────────────────────
# Pages
# ─────────────────────────────────────────
def _page(name: str):
    return send_from_directory(BASE_DIR, name)


@app.route("/")
def index():
    if session.get("username"):
        return redirect("/admin" if _is_admin() else "/dashboard")
    return _page("login.html")


def _is_admin() -> bool:
    user = current_user()
    return bool(user and user["role"] == "admin")


@app.route("/dashboard")
@login_required
def dashboard():
    return _page("dashboard.html")


@app.route("/logs")
@login_required
def logs_page():
    return _page("logs.html")


@app.route("/blocked")
@login_required
def blocked_page():
    return _page("blocked.html")


@app.route("/settings")
@login_required
def settings_page():
    return _page("settings.html")


@app.route("/admin")
@login_required
@admin_required
def admin_page():
    return _page("admin.html")


# Page scripts. Served explicitly so the CSP can stay at script-src 'self' with
# no inline script anywhere; the old build set that header and then relied on
# inline <script> blocks, which browsers refused to run.
_SCRIPTS = ("dashboard.js", "logs.js", "blocked.js", "settings.js", "admin.js", "csrf.js")


@app.route("/<script_name>.js")
def page_script(script_name: str):
    filename = f"{script_name}.js"
    if filename not in _SCRIPTS:
        return "Not found", 404
    return send_from_directory(BASE_DIR, filename, mimetype="application/javascript")


# ─────────────────────────────────────────
# API — analysis
# ─────────────────────────────────────────
@app.route("/api/csrf-token")
@login_required
def csrf_token():
    return jsonify({"csrf_token": ensure_csrf_token()})


@app.route("/api/rules")
@login_required
def api_rules():
    """Rule inventory, so the UI can explain *why* something was flagged."""
    return jsonify({"rules": detection.describe_rules(), "thresholds": detection.THRESHOLDS})


@app.route("/api/analyze", methods=["POST"])
@login_required
@csrf_protect
def analyze():
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", ""))[:4096].strip()
    check_type = str(payload.get("type", "full")).strip().lower()
    if not url:
        return jsonify({"error": "a url is required"}), 400

    ip = request.remote_addr or "unknown"
    body, fetch_note, fetch_status = fetch_for_reflection(url)
    result = detection.evaluate(
        url,
        body=body,
        only=check_type,
        runtime_signals=brute_force_signals(ip),
    )
    entry = record_incident(url, result, check_type, ip, fetch_note, fetch_status)

    return jsonify({
        "result": result.summary,
        "safe": result.safe,
        "severity": result.severity,
        "details": result.categories,
        "findings": entry["findings"],
        "scan": check_type,
        "action": entry["action"],
        "fetch_status": fetch_status,
        "fetch_note": fetch_note,
    })


@app.route("/api/data")
@login_required
def get_data():
    return jsonify({
        "stats": stats,
        "logs": logs[:20],
        "blocked_ips": blocked_ips[-25:],
        "user": session.get("username"),
        "is_admin": _is_admin(),
    })


# These three wipe state, so they need a session and a CSRF token. Previously
# any unauthenticated visitor - or any other website - could clear the evidence.
@app.route("/api/clear-logs", methods=["POST"])
@login_required
@csrf_protect
def clear_logs():
    logs.clear()
    log.info("logs cleared by %s", session.get("username"))
    return jsonify({"success": True})


@app.route("/api/clear-blocked", methods=["POST"])
@login_required
@csrf_protect
def clear_blocked():
    blocked_ips.clear()
    stats["blocked"] = 0
    return jsonify({"success": True})


@app.route("/api/reset-stats", methods=["POST"])
@login_required
@csrf_protect
def reset_stats():
    stats.update({"requests": 0, "attacks": 0, "blocked": 0})
    return jsonify({"success": True})


# ─────────────────────────────────────────
# API — admin
# ─────────────────────────────────────────
@app.route("/api/admin/vulnerabilities")
@login_required
@admin_required
def admin_vulnerabilities():
    counts: dict[str, int] = {}
    severities: dict[str, int] = {}
    for entry in logs:
        if entry["safe"]:
            continue
        for category in entry["result"].split(", "):
            counts[category] = counts.get(category, 0) + 1
        severities[entry["severity"]] = severities.get(entry["severity"], 0) + 1
    return jsonify({
        "counts": counts,
        "severities": severities,
        "recent_logs": [e for e in logs if not e["safe"]][:10],
        "stats": stats,
        "blocked_ips": blocked_ips,
    })


@app.route("/api/admin/users")
@login_required
@admin_required
def admin_users():
    rows = store.list_users(get_db_connection())
    users = [dict(row) for row in rows]
    history = {
        row["username"]: [e for e in logs if e["user"] == row["username"]][:10]
        for row in rows
    }
    return jsonify({"users": users, "history": history})


@app.route("/api/admin/users/clear", methods=["POST"])
@login_required
@admin_required
@csrf_protect
def clear_non_admin_users():
    deleted = store.delete_non_admins(get_db_connection())
    log.warning("%s deleted %s non-admin account(s)", session.get("username"), deleted)
    return jsonify({"success": True, "deleted": deleted})


# ─────────────────────────────────────────
# Auth
# ─────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return _page("login.html")

    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        retry_after = int(_lockout_until.get(ip, time.time()) - time.time())
        return (
            "Too many failed attempts. Try again later.",
            429,
            {"Retry-After": str(max(retry_after, 1))},
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    row = store.find_user(get_db_connection(), username)

    if row is None:
        # Spend the same work as a real verification so timing does not reveal
        # whether the username exists.
        security.waste_time_like_a_real_check()
        authenticated = False
    else:
        authenticated = security.verify_password(password, row["password"])

    if not authenticated:
        record_failed_login(ip)
        log.info("failed login for '%s' from %s", username[:64], ip)
        return "Invalid credentials", 401

    if security.needs_rehash(row["password"]):
        store.set_password(get_db_connection(), row["id"], password)

    clear_failed_logins(ip)
    session.clear()                      # new session id on login: no fixation
    session["username"] = row["username"]
    session.permanent = True
    ensure_csrf_token()
    log.info("login: %s (%s)", row["username"], row["role"])
    return redirect("/admin" if row["role"] == "admin" else "/dashboard")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return _page("register.html")

    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        return "Too many attempts. Try again later.", 429

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    error = security.validate_credentials(username, password)
    if error:
        return error, 400

    conn = get_db_connection()
    try:
        store.create_user(conn, username, password)
    except sqlite3.IntegrityError:
        return "Username already exists", 409

    log.info("registered new user '%s' from %s", username, ip)
    return redirect("/")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/")


# ─────────────────────────────────────────
# Response hardening
# ─────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "          # every page script is an external file
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(404)
def not_found(_error):
    if _wants_json():
        return jsonify({"error": "not found"}), 404
    return "Not found", 404


@app.errorhandler(500)
def server_error(_error):
    log.exception("unhandled error on %s %s", request.method, request.path)
    return jsonify({"error": "internal server error"}), 500


init_db()

if __name__ == "__main__":
    # debug=True exposes the Werkzeug console, which is remote code execution for
    # anyone who can reach it. Off unless IDPS_DEBUG is set explicitly.
    app.run(
        host=os.environ.get("IDPS_HOST", "127.0.0.1"),
        port=int(os.environ.get("IDPS_PORT", "5000")),
        debug=security.env_flag("IDPS_DEBUG", default=False),
    )
