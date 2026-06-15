import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Severity, Grade } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META: Record<
  Severity,
  { label: string; hex: string; ring: string; text: string; bg: string; dot: string }
> = {
  critical: { label: "Critical", hex: "#F43F5E", ring: "ring-sev-critical/40", text: "text-sev-critical", bg: "bg-sev-critical/12", dot: "bg-sev-critical" },
  high: { label: "High", hex: "#FB923C", ring: "ring-sev-high/40", text: "text-sev-high", bg: "bg-sev-high/12", dot: "bg-sev-high" },
  medium: { label: "Medium", hex: "#FBBF24", ring: "ring-sev-medium/40", text: "text-sev-medium", bg: "bg-sev-medium/12", dot: "bg-sev-medium" },
  low: { label: "Low", hex: "#38BDF8", ring: "ring-sev-low/40", text: "text-sev-low", bg: "bg-sev-low/12", dot: "bg-sev-low" },
  info: { label: "Info", hex: "#94A3B8", ring: "ring-sev-info/40", text: "text-sev-info", bg: "bg-sev-info/12", dot: "bg-sev-info" },
};

export const GRADE_META: Record<Grade, { hex: string; label: string }> = {
  A: { hex: "#34D399", label: "Strong" },
  B: { hex: "#A3E635", label: "Good" },
  C: { hex: "#FBBF24", label: "Needs work" },
  D: { hex: "#FB923C", label: "At risk" },
  F: { hex: "#F43F5E", label: "Critical" },
};

const VULN_LABELS: Record<string, string> = {
  idor: "IDOR",
  broken_auth: "Broken Auth",
  mass_assignment: "Mass Assignment",
  sqli: "SQL Injection",
  xss: "XSS",
  authz: "Authorization",
  path_traversal: "Path Traversal",
  ssrf: "SSRF",
  csrf: "CSRF",
  jwt: "JWT",
  cors: "CORS",
  open_redirect: "Open Redirect",
  ssti: "SSTI",
  command_injection: "Command Injection",
  data_exposure: "Data Exposure",
  security_headers: "Security Headers",
  rate_limit: "Rate Limiting",
  undocumented_endpoint: "Undocumented Endpoint",
  functional: "Functional",
  validation: "Validation",
  broken_link: "Broken Link",
  js_error: "JS Error",
  server_error: "Server Error",
};

export function vulnLabel(v: string): string {
  return VULN_LABELS[v] || v.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function prettyMs(ms?: number): string {
  if (!ms && ms !== 0) return "";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}
