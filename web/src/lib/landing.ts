// Static content for the landing surface — the 16 effect-oracle detectors and
// the three-step "how it works" story. Kept out of components so copy is in one place.

export interface Detector {
  key: string;
  label: string;
  blurb: string;
}

/** The 16 detectors the v2.1 engine ships — each backed by an effect oracle. */
export const DETECTORS: Detector[] = [
  { key: "broken_auth", label: "Broken Auth", blurb: "Endpoints that forget to check who's asking." },
  { key: "idor", label: "IDOR", blurb: "One user reading another's records by changing an id." },
  { key: "mass_assignment", label: "Mass Assignment", blurb: "Smuggling role=admin into a profile update." },
  { key: "sqli", label: "SQL Injection", blurb: "Time-based & differential payloads, confirmed twice." },
  { key: "stored_xss", label: "Stored XSS", blurb: "Payloads that persist and fire on read-back." },
  { key: "xss", label: "Reflected XSS", blurb: "Inputs echoed into the page unescaped." },
  { key: "authz_matrix", label: "Authorization", blurb: "Vertical & horizontal access across every role." },
  { key: "jwt_attacks", label: "JWT", blurb: "alg=none, weak secrets, unverified signatures." },
  { key: "ssti", label: "Template Injection", blurb: "{{7*7}} rendered server-side." },
  { key: "command_injection", label: "Command Injection", blurb: "Shell metacharacters reaching the OS." },
  { key: "path_traversal", label: "Path Traversal", blurb: "../ tricks that escape the intended folder." },
  { key: "cors_misconfig", label: "CORS", blurb: "Origins reflected with credentials allowed." },
  { key: "open_redirect", label: "Open Redirect", blurb: "Redirects an attacker can point anywhere." },
  { key: "secrets_exposure", label: "Secrets Exposure", blurb: "Keys & tokens leaking in responses." },
  { key: "graphql_introspection", label: "GraphQL", blurb: "Introspection left open to the world." },
  { key: "security_headers", label: "Security Headers", blurb: "Missing HSTS, CSP, frame protections." },
];

export interface Step {
  n: string;
  title: string;
  body: string;
}

export const STEPS: Step[] = [
  {
    n: "01",
    title: "Point it at your app",
    body: "Just a URL. Optionally add a one-line description, an OpenAPI spec, or logins to test behind auth — everything else is auto-discovered.",
  },
  {
    n: "02",
    title: "It explores, then attacks",
    body: "It crawls like a QA engineer — pages, forms, journeys — then runs 16 effect-oracle detectors across every role, proving each issue by real exploitation, not a status code.",
  },
  {
    n: "03",
    title: "Read a founder-grade report",
    body: "An A–F grade, every finding in plain language, why it matters, how to fix it, and a copy-paste repro you can verify yourself. No security background required.",
  },
];
