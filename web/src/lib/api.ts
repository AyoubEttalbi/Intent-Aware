import type { JobState, JobProgress, ScanRequest, ScanResult, Finding } from "./types";
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
    max_pages: req.max_pages ?? 0,   // 0 = no page cap: crawl until the frontier is exhausted
  };
  if (req.extra_hosts?.length) body.extra_hosts = req.extra_hosts;
  if (req.auth_identities?.length) body.auth_identities = req.auth_identities;
  if (req.model) body.model = req.model;
  if (req.effort) body.effort = req.effort;

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
  onProgress?: (p: JobProgress | null) => void;
}

/** A finished run + the job id that owns it (null for the bundled demo, which has no server job → no chat). */
export interface RunResult {
  result: ScanResult;
  jobId: string | null;
}

/** Launch a scan and poll to completion. NO time cap — polls until the scan
 *  finishes server-side, the user cancels, or the API actually stops responding
 *  (5 consecutive failed polls). Long authenticated scans can run a while. */
export async function runScan(req: ScanRequest, h: RunHandlers = {}): Promise<RunResult> {
  const jobId = await launchScan(req);
  const started = Date.now();
  let fails = 0;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (h.signal?.aborted) throw new DOMException("aborted", "AbortError");
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
    h.onProgress?.(state.progress ?? null);
    if (state.status === "completed" && state.results) return { result: enrichFindings(state.results), jobId };
    if (state.status === "failed") throw new Error(state.error || "Scan failed");
  }
}

/** Demo mode — resolve the bundled sample after a short, animated delay. */
export async function runDemo(h: RunHandlers = {}): Promise<RunResult> {
  const total = 5200;
  const started = Date.now();
  while (Date.now() - started < total) {
    if (h.signal?.aborted) throw new DOMException("aborted", "AbortError");
    await new Promise((res) => setTimeout(res, 220));
    h.onTick?.(Date.now() - started);
  }
  return { result: enrichFindings(structuredClone(SAMPLE_RESULT)), jobId: null };
}

// ── Per-test chat ───────────────────────────────────────────────────────────
export interface ChatReply {
  reply: string;
  session_id: string;
  idle_seconds: number;
  fresh: boolean;
}

/** Ask a question in a finished scan's own context. */
export async function sendChat(
  jobId: string,
  message: string,
  opts: { model?: string; effort?: string } = {}
): Promise<ChatReply> {
  const r = await fetch(`${API_BASE}/chat/${jobId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, model: opts.model, effort: opts.effort }),
  });
  if (!r.ok) throw new Error(`Chat failed (${r.status}): ${(await r.text()).slice(0, 200)}`);
  return (await r.json()) as ChatReply;
}

/** End a test's chat session server-side (frees the stored session). Best-effort. */
export async function closeChat(jobId: string): Promise<void> {
  try {
    await fetch(`${API_BASE}/chat/${jobId}/close`, { method: "POST" });
  } catch {
    /* ignore — the idle TTL will reap it anyway */
  }
}
