from flask import Flask, request, jsonify, send_from_directory, redirect
import re
import sqlite3

app = Flask(__name__)

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Simple in-memory storage
logs = []

blocked_ips = []

stats = {"requests": 0, "attacks": 0, "blocked": 0}

# users = []  # Simple in-memory user storage - removed, using database now


def check_sql(url):
    patterns = [
        r"\b(select|union|insert|delete|update|drop|alter|create|exec|execute|declare|cast|sleep|benchmark|load_file|outfile|xp_cmdshell|information_schema)\b",
        r"('\s*(or|and)\s+[\w\d]+\s*=\s*[\w\d]+)",
        r'"\s*(or|and)\s+[\w\d]+\s*=\s*[\w\d]+',
        r"\b1\s*=\s*1\b",
        r"\b0\s*=\s*0\b",
        r"--",
        r"#",
        r"/\*",
        r"\*/",
        r"\bor\b\s+\d+\s*=\s*\d+",
        r"\band\b\s+\d+\s*=\s*\d+",
        r"admin'--",
        r"' or '1'='1",
        r"';\s*drop\s+table",
        r"script>",
    ]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "SQL Injection"
    return None


def check_xss(url):
    patterns = [
        r"<script",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"onmouseover=",
        r"onclick=",
        r"onfocus=",
        r"onblur=",
        r"onmouseenter=",
        r"<img",
        r"<iframe",
        r"<object",
        r"<embed",
        r"<svg",
        r"<math",
        r"<body",
        r"<video",
        r"<audio",
        r"alert\(",
        r"confirm\(",
        r"prompt\(",
        r"eval\(",
        r"document\.cookie",
        r"document\.location",
        r"window\.location",
        r"innerHTML",
        r"outerHTML",
        r"expression\(",
        r"style=\".*expression\(",
    ]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "XSS Attack"
    return None


def check_brute(url):
    patterns = [
        r"\b(login|admin|passwd|password|auth|signin|logon)\b",
        r"\b(retry|attempt|failed|error|invalid)\b",
        r"\b(brute|force|attack|bot|scanner)\b",
        r"\b(multiple|repeated|consecutive)\b",
        r"\b(lockout|blocked|captcha|bypass)\b",
        r"\b(credential|credential stuffing|password spray)\b",
    ]
    score = sum(1 for p in patterns if re.search(p, url, re.IGNORECASE))
    if score >= 2:
        return "Brute Force"
    return None


def check_csrf(url):
    patterns = [
        r"\bcsrf\b",
        r"\btoken\b",
        r"cross\.site\.request\.forgery",
        r"\breferer\b",
        r"\borigin\b",
        r"\bsecure\b",
        r"\bread\b",
    ]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "CSRF Attack"
    return None


def check_rfi(url):
    patterns = [
        r"http://",
        r"https://",
        r"ftp://",
        r"file://",
        r"php://",
        r"data://",
        r"include\b",
        r"require\b",
        r"remote\.file\.inclusion",
        r"\b(url|path)=.*(http|ftp|php|data):",
    ]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "Remote File Inclusion"
    return None


def check_lfi(url):
    patterns = [
        r"\.\./",
        r"\.\.\\",
        r"etc/passwd",
        r"boot\.ini",
        r"\b\./\b",
        r"\b\../\b",
        r"\b\..\\\b",
        r"local\.file\.inclusion",
        r"directory\.traversal",
    ]
    for p in patterns:
        if re.search(p, url, re.IGNORECASE):
            return "Local File Inclusion"
    return None


def determine_action(detections, ip):
    if not detections:
        return "No action needed"

    if "Brute Force" in detections:
        return "Blocked request and rate-limited IP"
    if "SQL Injection" in detections:
        return "Blocked request and blacklisted IP"
    if "XSS Attack" in detections:
        return "Filtered payload and blocked request"
    if "CSRF Attack" in detections:
        return "Dropped request and invalidated token"
    if "Remote File Inclusion" in detections:
        return "Blocked external payload and blacklisted IP"
    if "Local File Inclusion" in detections:
        return "Blocked path traversal attempt"

    return "Blocked request and blacklisted IP"


@app.route("/")
def index():
    return send_from_directory(".", "login.html")


@app.route("/dashboard")
def dashboard():
    return send_from_directory(".", "dashboard.html")


@app.route("/logs")
def logs_page():
    return send_from_directory(".", "logs.html")


@app.route("/blocked")
def blocked_page():
    return send_from_directory(".", "blocked.html")


@app.route("/settings")
def settings_page():
    return send_from_directory(".", "settings.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.json
    url = data.get("url", "")
    check_type = data.get("type", "full")

    if check_type == "sql":
        matches = [check_sql(url)]
    elif check_type == "xss":
        matches = [check_xss(url)]
    elif check_type == "brute":
        matches = [check_brute(url)]
    elif check_type == "csrf":
        matches = [check_csrf(url)]
    elif check_type == "rfi":
        matches = [check_rfi(url)]
    elif check_type == "lfi":
        matches = [check_lfi(url)]
    else:  # full scan
        matches = [
            check_sql(url),
            check_xss(url),
            check_brute(url),
            check_csrf(url),
            check_rfi(url),
            check_lfi(url),
        ]

    results = [m for m in matches if m]
    safe = len(results) == 0
    summary = "Safe"
    if not safe:
        summary = ", ".join(sorted(set(results)))

    # Update stats
    stats["requests"] += 1
    ip = request.remote_addr or "unknown"
    action = determine_action(results, ip)
    if not safe:
        stats["attacks"] += 1
        if ip not in blocked_ips:
            blocked_ips.append(ip)
            stats["blocked"] += 1

    # Add to logs
    logs.insert(0, {"url": url, "result": summary, "safe": safe, "type": check_type, "action": action})
    if len(logs) > 20:
        logs.pop()

    return jsonify({"result": summary, "safe": safe, "details": results, "scan": check_type, "action": action})


@app.route("/api/data")
def get_data():
    return jsonify({
        "stats": stats,
        "logs": logs[:8],
        "blocked_ips": blocked_ips[-5:]
    })


@app.route("/api/clear-logs", methods=["POST"])
def clear_logs():
    global logs
    logs = []
    return jsonify({"success": True})


@app.route("/api/clear-blocked", methods=["POST"])
def clear_blocked():
    global blocked_ips
    blocked_ips = []
    return jsonify({"success": True})


@app.route("/api/reset-stats", methods=["POST"])
def reset_stats():
    global stats
    stats = {"requests": 0, "attacks": 0, "blocked": 0}
    return jsonify({"success": True})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            return redirect('/dashboard')
        else:
            return "Invalid credentials"
    return send_from_directory(".", "login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        finally:
            conn.close()
        
        return send_from_directory(".", "login.html")  # redirect to login
    return send_from_directory(".", "register.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
