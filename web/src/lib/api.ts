import type { JobState, ScanRequest, ScanResult, Finding } from "./types";
import { SAMPLE_RESULT } from "./sampleReport";

// API lives under the app base: "/api" in dev, "/intent-aware/api" when deployed
// under the sub-path. Vite proxies it in dev; nginx proxies it in prod.
const API_BASE = import.meta.env.BASE_URL.replace(/\/$/, "") + "/api";

const CRED_HEADERS = new Set([
  "authorization",
  "cookie",
  "x-api-key",
  "x-auth-token",
  "x-access-token",
  "x-session-token",
  "api-key",
  "x-csrf-token",
]);

/** Reconstruct a copy-pasteable, credential-redacted curl from a finding's request evidence. */
export function buildCurl(f: Finding): string {
  const req = f.evidence?.request;
  if (!req || !req.url) return f.curl || "";
  const method = (req.method || "GET").toUpperCase();
  const parts = ["curl", "-i", "-X", method];
  for (const [k, v] of Object.entries(req.headers || {})) {
    const val = CRED_HEADERS.has(k.toLowerCase()) ? "<redacted>" : String(v);
    parts.push("-H", `'${k}: ${val}'`);
  }
  const hasBody = req.body != null && method !== "GET" && method !== "HEAD";
  if (hasBody) {
    if (req.content_type === "form" && typeof req.body === "object") {
      const enc = Object.entries(req.body as Record<string, unknown>)
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v ?? ""))}`)
        .join("&");
      parts.push("-H", "'Content-Type: application/x-www-form-urlencoded'", "--data", `'${enc}'`);
    } else {
      const data = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
      parts.push("-H", "'Content-Type: application/json'", "--data", `'${data}'`);
    }
  }
  parts.push(`'${req.url}'`);
  return parts.join(" ");
}

export function enrichFindings(result: ScanResult): ScanResult {
  return {
    ...result,
    findings: result.findings.map((f) => ({ ...f, curl: buildCurl(f) })),
  };
}

export async function launchScan(req: ScanRequest): Promise<string> {
  const body: Record<string, unknown> = {
    base_url: req.base_url,
    spec_url: req.spec_url || "",
    description: req.description || "",
    crawl_ui: !!req.crawl_ui,
    allow_writes: !!req.allow_writes,
    max_requests: req.max_requests ?? 400,
    max_pages: req.max_pages ?? 20,
  };
  if (req.extra_hosts?.length) body.extra_hosts = req.extra_hosts;
  if (req.auth_identities?.length) body.auth_identities = req.auth_identities;

  const r = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`Launch failed (${r.status}): ${await r.text()}`);
  const data = (await r.json()) as { job_id: string };
  return data.job_id;
}

export async function pollStatus(jobId: string): Promise<JobState> {
  const r = await fetch(`${API_BASE}/status/${jobId}`);
  if (!r.ok) throw new Error(`Status failed (${r.status})`);
  return (await r.json()) as JobState;
}

export interface RunHandlers {
  signal?: AbortSignal;
  onTick?: (elapsedMs: number) => void;
}

/** Launch a scan and poll to completion (tolerant of transient blips, with a deadline). */
export async function runScan(req: ScanRequest, h: RunHandlers = {}): Promise<ScanResult> {
  const jobId = await launchScan(req);
  const started = Date.now();
  const deadline = started + 12 * 60 * 1000; // 12-minute ceiling
  let fails = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (h.signal?.aborted) throw new DOMException("aborted", "AbortError");
    if (Date.now() > deadline) throw new Error("Scan timed out — the API stopped responding.");
    await new Promise((res) => setTimeout(res, 1500));
    h.onTick?.(Date.now() - started);
    let state;
    try {
      state = await pollStatus(jobId);
    } catch {
      if (++fails > 4) throw new Error("Lost connection to the API while scanning.");
      continue; // transient network blip — keep polling
    }
    fails = 0;
    if (state.status === "completed" && state.results) return enrichFindings(state.results);
    if (state.status === "failed") throw new Error(state.error || "Scan failed");
  }
}

/** Demo mode — resolve the bundled sample after a short, animated delay. */
export async function runDemo(h: RunHandlers = {}): Promise<ScanResult> {
  const total = 5200;
  const started = Date.now();
  while (Date.now() - started < total) {
    if (h.signal?.aborted) throw new DOMException("aborted", "AbortError");
    await new Promise((res) => setTimeout(res, 220));
    h.onTick?.(Date.now() - started);
  }
  return enrichFindings(structuredClone(SAMPLE_RESULT));
}
