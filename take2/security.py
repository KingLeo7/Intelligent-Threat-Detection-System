"""Security primitives for the IDPS: password hashing, CSRF tokens, SSRF guard.

Everything here is standard library only and free of Flask imports, so each
function can be exercised directly without booting a web server.

On the choice of KDF: passwords are stretched with ``hashlib.pbkdf2_hmac``
(SHA-256, per-password salt, constant-time comparison) rather than a third-party
helper. That keeps the security-critical path dependency-free and testable in
isolation, and PBKDF2-HMAC-SHA256 is the same primitive the usual Flask helper
used before it moved to scrypt.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# ─────────────────────────────────────────
# Password hashing
# ─────────────────────────────────────────
_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 600_000          # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16
_HASH_FORMAT = re.compile(r"^pbkdf2_sha256\$(\d+)\$([0-9a-f]+)\$([0-9a-f]+)$")

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_USERNAME_LENGTH = 64
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,64}$")


def hash_password(password: str, *, iterations: int = _ITERATIONS) -> str:
    """Return ``pbkdf2_sha256$iterations$salt$hash``."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def looks_hashed(stored: str) -> bool:
    """True when ``stored`` is already in this module's hash format."""
    return bool(stored) and bool(_HASH_FORMAT.match(str(stored)))


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of ``password`` against a stored hash.

    Returns False for empty input or a malformed/legacy plaintext value, so a
    row that somehow escaped migration cannot be logged into with its plaintext.
    """
    if not password or not stored:
        return False
    match = _HASH_FORMAT.match(str(stored))
    if not match:
        return False
    iterations, salt_hex, expected_hex = match.groups()
    try:
        salt = binascii.unhexlify(salt_hex)
        expected = binascii.unhexlify(expected_hex)
    except (binascii.Error, ValueError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, int(iterations), dklen=len(expected)
    )
    return hmac.compare_digest(candidate, expected)


def needs_rehash(stored: str, *, iterations: int = _ITERATIONS) -> bool:
    """True when a valid hash was made with a weaker iteration count."""
    match = _HASH_FORMAT.match(str(stored or ""))
    return bool(match) and int(match.group(1)) < iterations


# A pre-computed hash of a random value. Verifying against it when the username
# does not exist keeps the failed-login response time in the same ballpark as a
# real check, so response timing does not reveal which usernames are registered.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


def waste_time_like_a_real_check() -> None:
    verify_password("not-the-password", _DUMMY_HASH)


def validate_credentials(username: str, password: str) -> str | None:
    """Return an error message, or None when the pair is acceptable."""
    username = (username or "").strip()
    if not username or not password:
        return "Username and password are required."
    if len(username) > MAX_USERNAME_LENGTH:
        return f"Username must be at most {MAX_USERNAME_LENGTH} characters."
    if not USERNAME_PATTERN.match(username):
        return "Username may only contain letters, numbers, dot, underscore and hyphen."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    if password.lower() in _COMMON_PASSWORDS:
        return "That password is too common. Choose something less predictable."
    if password.strip().lower() == username.lower():
        return "Password must not be the same as the username."
    return None


_COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "letmein", "welcome1", "admin123", "iloveyou", "abc12345",
    "changeme", "passw0rd", "football", "baseball", "sunshine", "princess",
    "trustno1", "dragon123", "monkey123", "qwertyuiop", "1qaz2wsx",
})


# ─────────────────────────────────────────
# CSRF tokens
# ─────────────────────────────────────────
CSRF_HEADER = "X-CSRF-Token"
CSRF_FIELD = "csrf_token"


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_tokens_match(expected: str | None, provided: str | None) -> bool:
    if not expected or not provided:
        return False
    return hmac.compare_digest(str(expected), str(provided))


# ─────────────────────────────────────────
# SSRF guard for the URL scanner
# ─────────────────────────────────────────
# /api/analyze optionally fetches the URL it was given. Without a guard that is
# a server-side request forgery primitive: anyone who can reach the scanner can
# make the server fetch http://127.0.0.1:5000/api/admin/users, a cloud metadata
# endpoint, or anything else inside the network perimeter, and the response body
# is echoed back in the log entry.
ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
BLOCKED_HOSTNAMES = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal", "metadata.goog",
    "instance-data", "instance-data.ec2.internal",
})
MAX_FETCH_BYTES = 256 * 1024      # 256 KiB is plenty to spot a reflected payload
FETCH_TIMEOUT_SECONDS = 5


@dataclass
class FetchDecision:
    allowed: bool
    reason: str = ""
    host: str = ""
    port: int = 0
    addresses: list[str] = field(default_factory=list)


def _address_is_public(raw: str) -> bool:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


def validate_fetch_target(url: str, resolver=None) -> FetchDecision:
    """Decide whether the scanner may issue an outbound request to ``url``.

    Every address the hostname resolves to must be publicly routable -- checking
    only the first one leaves the door open to a DNS entry that returns both a
    public and a loopback address. ``resolver`` is injectable so this can be
    tested without DNS.
    """
    resolve = resolver or _default_resolver
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return FetchDecision(False, "URL could not be parsed")

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return FetchDecision(False, f"scheme '{scheme or 'none'}' is not fetchable")
    if parts.username or parts.password:
        return FetchDecision(False, "credentials in the URL are not allowed")

    try:
        host = (parts.hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return FetchDecision(False, "URL host could not be parsed")
    if not host:
        return FetchDecision(False, "URL has no host")
    if host in BLOCKED_HOSTNAMES or host.endswith(".localhost") or host.endswith(".internal"):
        return FetchDecision(False, f"host '{host}' is a loopback or metadata name")

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return FetchDecision(False, "URL port is not a number")
    if port not in ALLOWED_PORTS:
        return FetchDecision(False, f"port {port} is not in the allow-list")

    # A literal IP still has to be public.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not _address_is_public(host):
            return FetchDecision(False, f"{host} is not a public address", host, port, [host])
        return FetchDecision(True, "", host, port, [host])

    try:
        addresses = resolve(host, port)
    except OSError as exc:
        return FetchDecision(False, f"host '{host}' did not resolve ({exc.__class__.__name__})", host, port)
    if not addresses:
        return FetchDecision(False, f"host '{host}' did not resolve", host, port)
    for address in addresses:
        if not _address_is_public(address):
            return FetchDecision(
                False, f"{host} resolves to non-public address {address}", host, port, addresses
            )
    return FetchDecision(True, "", host, port, addresses)


# ─────────────────────────────────────────
# Configuration helpers
# ─────────────────────────────────────────
def load_secret_key(env_var: str = "IDPS_SECRET_KEY") -> tuple[str, bool]:
    """Return ``(secret_key, is_ephemeral)``.

    A hardcoded key lets anyone who has seen the source forge a session cookie
    and log in as the admin, so the key comes from the environment. When it is
    absent a random key is generated: sessions then drop on restart, which is an
    inconvenience in development and a loud hint to set the variable in
    production.
    """
    from_env = os.environ.get(env_var, "").strip()
    if from_env:
        return from_env, False
    return secrets.token_urlsafe(48), True


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
