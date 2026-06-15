// Mirrors the Intent-Aware FastAPI contract (agent/engine.py -> _finding_dict, coverage).

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Grade = "A" | "B" | "C" | "D" | "F";

export interface ReqEvidence {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: unknown;
  label?: string;
  content_type?: string;
}

export interface RespEvidence {
  status?: number;
  latency_ms?: number;
  note?: string;
}

export interface Evidence {
  request?: ReqEvidence | null;
  response?: RespEvidence | null;
  baseline_request?: ReqEvidence | null;
  baseline_response?: RespEvidence | null;
  note?: string;
  page_url?: string;
  steps?: string[];
  expected?: string;
  actual?: string;
  screenshot?: string;
}

export interface Finding {
  vuln_class: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  endpoint_key: string;
  identity: string;
  detail: string;
  explanation: string;
  impact: string;
  fix: string;
  source: string;
  evidence: Evidence;
  /** repro curl — added client-side from evidence when present */
  curl?: string;
}

export interface Coverage {
  endpoints_total: number;
  endpoints_attacked: number;
  requests_sent: number;
  attack_classes: string[];
  identities: string[];
  authed_identities: number;
  allow_writes: boolean;
  qa_crawl: boolean;
  degraded: string[];
  low_coverage: boolean;
}

export interface ScanResult {
  findings: Finding[];
  coverage: Coverage;
  grade: Grade;
  score: number;
  report_markdown: string;
  context?: unknown;
}

export type AuthAdapterType =
  | "form"
  | "bearer"
  | "api_key"
  | "header"
  | "session"
  | "token_exchange";

export interface AuthIdentity {
  type: AuthAdapterType;
  name: string;
  role: string;
  // form
  username?: string;
  password?: string;
  login_url?: string;
  // bearer
  token?: string;
  // api_key
  key?: string;
  header?: string;
  // token_exchange
  token_url?: string;
  token_path?: string;
  content_type?: string;
  // session
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
  owned_resource_ids?: Record<string, string[]>;
}

export interface ScanRequest {
  base_url: string;
  spec_url?: string;
  description?: string;
  crawl_ui?: boolean;
  allow_writes?: boolean;
  extra_hosts?: string[];
  max_requests?: number;
  max_pages?: number;
  auth_identities?: AuthIdentity[];
}

export type JobStatus = "pending" | "running" | "completed" | "failed";

export interface JobState {
  job_id: string;
  status: JobStatus;
  results?: ScanResult | null;
  error?: string | null;
}
