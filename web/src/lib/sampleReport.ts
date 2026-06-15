import type { ScanResult } from "./types";

// A realistic sample (shape matches the live engine output against the demo app),
// used by Demo Mode so the whole console is explorable without a backend running.
export const SAMPLE_RESULT: ScanResult = {
  grade: "F",
  score: 6,
  coverage: {
    endpoints_total: 21,
    endpoints_attacked: 21,
    requests_sent: 642,
    attack_classes: [
      "broken_auth", "idor", "mass_assignment", "sqli", "xss", "stored_xss",
      "path_traversal", "authz_matrix", "jwt_attacks", "cors_misconfig",
      "security_headers", "open_redirect", "ssti", "command_injection",
      "secrets_exposure", "graphql_introspection",
    ],
    identities: ["anon (anonymous)", "admin (admin)", "user (user)", "jwtuser (user)"],
    authed_identities: 3,
    allow_writes: true,
    qa_crawl: false,
    degraded: [],
    low_coverage: false,
  },
  report_markdown: `# 🛡️ Security & QA Report

**Target:** https://demo.yourapp.dev

## Executive summary
- **Overall grade: F** (score 6/100)
- **Confirmed issues:** 14 (🔴 7 critical · 🟠 4 high · 🟡 3 medium)
- **Needs review:** 1

**Top priorities**
1. Any visitor can read every user's profile (IDOR on \`GET /users/{id}\`).
2. A regular user can grant themselves admin (mass assignment on \`PUT /users/{id}\`).
3. The orders endpoint trusts any token — authentication is effectively off.

This is an illustrative sample rendered in **Demo Mode**.`,
  findings: [
    {
      vuln_class: "idor",
      severity: "critical",
      confidence: "high",
      title: "IDOR / broken object-level authorization on GET /users/{user_id}",
      endpoint_key: "GET /users/{user_id}",
      identity: "anon",
      source: "idor",
      detail:
        "By changing `user_id` from 1 to 2, the caller (unauthenticated) reads another record's sensitive fields (email). Records are not scoped to their owner.",
      explanation:
        "Anyone can view any user's profile just by changing the number in the URL — no login needed.",
      impact:
        "An attacker can harvest every user's personal information without any credentials, exposing your entire user base.",
      fix:
        "Enforce object-level authorization: verify the logged-in user owns (or may access) the requested record before returning it.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/users/2", headers: {}, label: "user_id=2" },
        response: { status: 200, note: "foreign record returned" },
        baseline_request: { method: "GET", url: "https://demo.yourapp.dev/users/1", label: "user_id=1" },
        baseline_response: { status: 200 },
        note: "own record (user_id=1) vs foreign record (user_id=2)",
      },
    },
    {
      vuln_class: "mass_assignment",
      severity: "critical",
      confidence: "high",
      title: "Mass assignment / privilege escalation on PUT /users/{user_id}",
      endpoint_key: "PUT /users/{user_id}",
      identity: "user",
      source: "mass_assignment",
      detail:
        "A write including privileged fields was accepted and applied (role=admin). The endpoint does not restrict which fields a client may set.",
      explanation:
        "A normal user can promote themselves to administrator just by adding a `role` field to a profile update.",
      impact:
        "Any user can seize full administrative control of the application and its data.",
      fix:
        "Whitelist editable fields server-side. Never bind request bodies directly to your data model; ignore privileged fields like role/is_admin.",
      evidence: {
        request: {
          method: "PUT",
          url: "https://demo.yourapp.dev/users/2",
          headers: { Cookie: "session=…" },
          body: { username: "bob", role: "admin", is_admin: true },
          content_type: "json",
          label: "privileged-fields",
        },
        response: { status: 200, note: "role=admin persisted" },
        note: "privileged fields persisted (confirmed on read-back)",
      },
    },
    {
      vuln_class: "broken_auth",
      severity: "critical",
      confidence: "high",
      title: "Broken authentication on GET /orders/{order_id}",
      endpoint_key: "GET /orders/{order_id}",
      identity: "anon",
      source: "broken_auth",
      detail:
        "Requests with no credentials are rejected (401), but a clearly-invalid credential is ACCEPTED (200) and returns data. The endpoint checks that a credential is present, not that it is valid.",
      explanation:
        "The orders page asks for a token but never checks whether it's real — any made-up token works.",
      impact:
        "An attacker can read any customer's orders by sending a random token.",
      fix:
        "Validate the credential (verify the session/JWT signature and expiry), not merely its presence.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/orders/1", headers: { Authorization: "Bearer invalid_token_qa_probe" }, label: "invalid-credential" },
        response: { status: 200, note: "accepted an invalid token" },
        baseline_request: { method: "GET", url: "https://demo.yourapp.dev/orders/1", label: "no-credentials" },
        baseline_response: { status: 401 },
        note: "no-credentials baseline (rejected) vs invalid-credential (accepted)",
      },
    },
    {
      vuln_class: "authz",
      severity: "critical",
      confidence: "high",
      title: "Privilege escalation: non-admin can access GET /admin/users",
      endpoint_key: "GET /admin/users",
      identity: "user",
      source: "authz_matrix",
      detail:
        "This endpoint looks admin-restricted, but the non-admin user 'user' (role: user) received 200 with data.",
      explanation:
        "A regular user can open the admin-only user list.",
      impact: "Non-privileged users can view and potentially manage all accounts.",
      fix: "Add a role check (not just 'is logged in') on every admin route.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/admin/users", headers: { Cookie: "session=…" }, label: "as user" },
        response: { status: 200 },
        note: "non-admin 'user' accessed an admin endpoint",
      },
    },
    {
      vuln_class: "authz",
      severity: "high",
      confidence: "high",
      title: "Broken object-level auth: user can read admin's notes via GET /notes/{note_id}",
      endpoint_key: "GET /notes/{note_id}",
      identity: "user",
      source: "authz_matrix",
      detail:
        "User 'user' (role: user) retrieved note #1, which belongs to 'admin'. Object ownership is not enforced for logged-in users.",
      explanation: "One logged-in user can read another user's private notes.",
      impact: "Cross-tenant data leak — users can read each other's private content.",
      fix: "Scope every record query by the authenticated owner; reject access to records you don't own.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/notes/1", headers: { Cookie: "session=…" }, label: "as user" },
        response: { status: 200 },
        baseline_request: { method: "GET", url: "https://demo.yourapp.dev/notes/1", label: "owner admin" },
        baseline_response: { status: 200 },
        note: "user retrieved admin's record",
      },
    },
    {
      vuln_class: "sqli",
      severity: "critical",
      confidence: "high",
      title: "Blind SQL injection (time-based) on GET /search (parameter `q`)",
      endpoint_key: "GET /search",
      identity: "anon",
      source: "sqli",
      detail:
        "A time-delay payload in `q` made the server pause ~5.0s (control ~12ms), reproduced on re-test — the input is executed by the database.",
      explanation:
        "Search text is run directly as part of a database query, so an attacker can manipulate or dump the database.",
      impact: "Full database compromise: read, modify, or delete any data.",
      fix: "Use parameterized queries / prepared statements. Never build SQL by concatenating user input.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/search?q=%27%20OR%20SLEEP(5)--%20-", label: "time-based" },
        response: { status: 200, latency_ms: 5012, note: "delay reproduced" },
        baseline_request: { method: "GET", url: "https://demo.yourapp.dev/search?q=1" },
        baseline_response: { status: 200, latency_ms: 12 },
        note: "time-based blind SQLi (delay reproduced)",
      },
    },
    {
      vuln_class: "ssti",
      severity: "critical",
      confidence: "high",
      title: "Server-side template injection on GET /greet (parameter `name`)",
      endpoint_key: "GET /greet",
      identity: "anon",
      source: "ssti",
      detail:
        "The template expression `{{1337*1331}}` was EVALUATED server-side (the response contains its computed result 1779547).",
      explanation:
        "Text you send is run as a server template, which usually means an attacker can run code on your server.",
      impact: "Remote code execution — full server takeover.",
      fix: "Never render user input as a template. Use a sandboxed engine and pass data as variables, not template source.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/greet?name=%7B%7B1337*1331%7D%7D", label: "ssti" },
        response: { status: 200, note: "expression evaluated to 1779547" },
        note: "expression evaluated to 1779547",
      },
    },
    {
      vuln_class: "command_injection",
      severity: "critical",
      confidence: "high",
      title: "OS command injection (time-based) on GET /ping (parameter `host`)",
      endpoint_key: "GET /ping",
      identity: "anon",
      source: "command_injection",
      detail:
        "A shell payload in `host` caused a reproducible ~5s delay (control ~9ms), proving the input is passed to a system shell.",
      explanation: "Input is passed to a system command, letting an attacker run shell commands on your server.",
      impact: "Remote code execution on the host.",
      fix: "Avoid shelling out with user input. Use language-native APIs; if you must, pass args as an array and never via a shell string.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/ping?host=qa%3B%20sleep%205", label: "cmd" },
        response: { status: 200, latency_ms: 5008, note: "delay reproduced" },
        baseline_response: { status: 200, latency_ms: 9 },
        note: "time-based command injection (delay reproduced)",
      },
    },
    {
      vuln_class: "xss",
      severity: "high",
      confidence: "high",
      title: "Stored XSS: input to POST /notes is rendered unescaped on GET /notes",
      endpoint_key: "POST /notes",
      identity: "user",
      source: "stored_xss",
      detail:
        "A script payload submitted via POST /notes is later rendered UN-escaped inside the HTML of GET /notes — it will execute in the browser of anyone who views that page.",
      explanation: "A note can contain a script that runs in every viewer's browser.",
      impact: "Account takeover of any user who views the page (session theft, actions on their behalf).",
      fix: "Escape/encode all user content on output (context-aware), and add a Content-Security-Policy.",
      evidence: {
        request: { method: "POST", url: "https://demo.yourapp.dev/notes", headers: { Cookie: "session=…" }, body: { text: "<script>…</script>" }, content_type: "form", label: "stored-xss-write" },
        response: { status: 200, note: "payload persisted and reflected unescaped" },
        note: "payload persisted and reflected unescaped on /notes",
      },
    },
    {
      vuln_class: "xss",
      severity: "high",
      confidence: "high",
      title: "Reflected XSS on GET /greet (parameter `name`)",
      endpoint_key: "GET /greet",
      identity: "anon",
      source: "xss",
      detail:
        "The payload injected into `name` is reflected un-encoded inside an HTML response, so an attacker-controlled script would execute in a victim's browser.",
      explanation: "A crafted link can run a script in your users' browsers.",
      impact: "Phishing and session/account theft via a malicious link.",
      fix: "HTML-encode user input on output; add a Content-Security-Policy.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/greet?name=%22%3E%3Cscript%3E…", label: "xss:query:name" },
        response: { status: 200, note: "unencoded reflection in HTML response" },
        note: "unencoded reflection in HTML response",
      },
    },
    {
      vuln_class: "data_exposure",
      severity: "high",
      confidence: "high",
      title: "Sensitive data exposure on GET /config: AWS access key id",
      endpoint_key: "GET /config",
      identity: "anon",
      source: "secrets_exposure",
      detail: "The response from GET /config contains what looks like an AWS access key id.",
      explanation: "A configuration endpoint is leaking what looks like a cloud secret to anyone.",
      impact: "Leaked cloud credentials can give an attacker access to your infrastructure.",
      fix: "Never return secrets to clients. Remove them from API responses and rotate any exposed keys.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/config", label: "secrets-scan" },
        response: { status: 200, note: "matched: AWS access key id" },
        note: "matched: AWS access key id",
      },
    },
    {
      vuln_class: "cors",
      severity: "high",
      confidence: "high",
      title: "CORS misconfiguration on GET /api/data",
      endpoint_key: "GET /api/data",
      identity: "anon",
      source: "cors_misconfig",
      detail:
        "The endpoint reflects an arbitrary Origin (https://qa-evil.example.com) in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.",
      explanation: "Any website can read this endpoint's data on behalf of your logged-in users.",
      impact: "A malicious site can steal authenticated data from your users.",
      fix: "Allow only a strict list of trusted origins; never reflect the request Origin when credentials are allowed.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/api/data", headers: { Origin: "https://qa-evil.example.com" }, label: "cors-probe" },
        response: { status: 200, note: "ACAO=https://qa-evil.example.com ACAC=true" },
        note: "ACAO reflected with credentials",
      },
    },
    {
      vuln_class: "open_redirect",
      severity: "medium",
      confidence: "high",
      title: "Open redirect on GET /go (parameter `url`)",
      endpoint_key: "GET /go",
      identity: "anon",
      source: "open_redirect",
      detail:
        "The `url` parameter controls a redirect target without validation: a request was 3xx-redirected to the attacker-controlled host qa-evil.example.com.",
      explanation: "A link on your domain can silently bounce users to an attacker's site.",
      impact: "Convincing phishing and OAuth token theft using your trusted domain.",
      fix: "Allow redirects only to a known allowlist of paths/hosts; reject absolute external URLs.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev/go?url=https://qa-evil.example.com/", label: "url" },
        response: { status: 302, note: "Location: https://qa-evil.example.com/" },
        note: "redirected off-host",
      },
    },
    {
      vuln_class: "data_exposure",
      severity: "medium",
      confidence: "high",
      title: "GraphQL introspection enabled on POST /graphql",
      endpoint_key: "POST /graphql",
      identity: "anon",
      source: "graphql_introspection",
      detail:
        "The GraphQL endpoint answers introspection queries (it disclosed 3 schema types) to an anonymous caller.",
      explanation: "Your GraphQL API hands out its full schema map to anyone who asks.",
      impact: "Gives attackers a complete map of your API to plan further attacks.",
      fix: "Disable introspection in production.",
      evidence: {
        request: { method: "POST", url: "https://demo.yourapp.dev/graphql", body: { query: "{ __schema { types { name } } }" }, content_type: "json", label: "graphql-introspection" },
        response: { status: 200, note: "data.__schema returned to anon" },
        note: "introspection enabled",
      },
    },
    {
      vuln_class: "security_headers",
      severity: "low",
      confidence: "high",
      title: "Missing HTTP security headers",
      endpoint_key: "https://demo.yourapp.dev",
      identity: "anon",
      source: "security_headers",
      detail:
        "The site is missing recommended hardening headers: Content-Security-Policy; X-Content-Type-Options: nosniff; X-Frame-Options; Strict-Transport-Security (HSTS).",
      explanation: "A few defensive HTTP headers that make common attacks harder are missing.",
      impact: "Makes XSS, clickjacking and protocol-downgrade attacks easier to pull off.",
      fix: "Add CSP, X-Content-Type-Options, X-Frame-Options and HSTS at your web server / framework.",
      evidence: {
        request: { method: "GET", url: "https://demo.yourapp.dev" },
        response: { status: 200, note: "headers absent on the main response" },
        note: "headers absent",
      },
    },
  ],
};
