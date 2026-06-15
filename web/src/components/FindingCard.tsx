import { useState, forwardRef } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, AlertTriangle, ShieldCheck, Wrench, Terminal, User } from "lucide-react";
import type { Finding } from "../lib/types";
import { SEVERITY_META, vulnLabel, prettyMs, cn } from "../lib/ui";
import { SeverityChip, CopyButton } from "./ui/Primitives";

const FindingCard = forwardRef<HTMLDivElement, { finding: Finding; index: number }>(
  ({ finding, index }, ref) => {
    const [open, setOpen] = useState(false);
    const m = SEVERITY_META[finding.severity];
    const ev = finding.evidence || {};

    return (
      <motion.div
        ref={ref}
        layout
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: Math.min(index * 0.04, 0.4), duration: 0.4 }}
        className={cn("glass overflow-hidden border-l-2", open && "shadow-glow")}
        style={{ borderLeftColor: m.hex }}
      >
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex w-full items-start gap-4 p-4 text-left transition-colors duration-150 hover:bg-ink-600/30"
          aria-expanded={open}
          aria-controls={`finding-panel-${index}`}
        >
          <div className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-lg" style={{ background: `${m.hex}1a` }}>
            <AlertTriangle size={18} style={{ color: m.hex }} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip severity={finding.severity} />
              <span className="chip">{vulnLabel(finding.vuln_class)}</span>
              {finding.confidence === "high" ? (
                <span className="chip text-ok/90">confirmed</span>
              ) : (
                <span className="chip">needs review</span>
              )}
              {finding.identity && finding.identity !== "anon" && (
                <span className="chip">
                  <User size={11} /> {finding.identity}
                </span>
              )}
            </div>
            <h4 className="mt-2 font-display text-[15px] font-semibold leading-snug text-fg">
              {finding.title}
            </h4>
            <code className="mt-1 block truncate font-mono text-xs text-fg-muted">{finding.endpoint_key}</code>
          </div>
          <ChevronDown
            size={18}
            className={cn("mt-1 shrink-0 text-fg-subtle transition-transform", open && "rotate-180")}
          />
        </button>

        <AnimatePresence initial={false}>
          {open && (
            <motion.div
              id={`finding-panel-${index}`}
              role="region"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3, ease: "easeInOut" }}
              className="overflow-hidden"
            >
              <div className="space-y-4 border-t border-line p-4 pt-4">
                <Row icon={<AlertTriangle size={15} className="text-sev-high" />} title="What we found">
                  {finding.explanation || finding.detail}
                </Row>
                {finding.impact && (
                  <Row icon={<ShieldCheck size={15} className="text-sev-critical" />} title="Why it matters">
                    {finding.impact}
                  </Row>
                )}
                {finding.fix && (
                  <Row icon={<Wrench size={15} className="text-ok" />} title="How to fix">
                    {finding.fix}
                  </Row>
                )}

                {/* evidence: differential baseline vs attack */}
                {(ev.baseline_response || ev.response) && (
                  <div className="grid gap-2 sm:grid-cols-2">
                    {ev.baseline_response && (
                      <EvidenceBox
                        tone="muted"
                        label="Baseline"
                        status={ev.baseline_response.status}
                        url={ev.baseline_request?.url}
                        latency={ev.baseline_response.latency_ms}
                      />
                    )}
                    {ev.response && (
                      <EvidenceBox
                        tone="bad"
                        label="Attack"
                        status={ev.response.status}
                        url={ev.request?.url}
                        latency={ev.response.latency_ms}
                        note={ev.note}
                      />
                    )}
                  </div>
                )}

                {/* repro */}
                {finding.curl && (
                  <div>
                    <div className="mb-1.5 flex items-center justify-between">
                      <span className="label mb-0 flex items-center gap-1.5">
                        <Terminal size={12} /> Reproduce
                      </span>
                      <CopyButton text={finding.curl} label="Copy curl" />
                    </div>
                    <pre className="max-h-40 overflow-auto rounded-lg border border-line bg-ink-900/80 p-3 font-mono text-[11.5px] leading-relaxed text-fg-muted">
                      {finding.curl}
                    </pre>
                  </div>
                )}

                {/* QA-style steps */}
                {ev.steps && ev.steps.length > 0 && (
                  <Row icon={<Terminal size={15} className="text-brand-cyan" />} title="Steps to reproduce">
                    <ol className="list-decimal space-y-0.5 pl-4">
                      {ev.steps.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ol>
                  </Row>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    );
  }
);
FindingCard.displayName = "FindingCard";

function Row({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2.5">
      <div className="mt-0.5 shrink-0">{icon}</div>
      <div className="min-w-0">
        <div className="text-xs font-semibold uppercase tracking-wider text-fg-subtle">{title}</div>
        <div className="mt-0.5 text-sm leading-relaxed text-fg-muted">{children}</div>
      </div>
    </div>
  );
}

function EvidenceBox({
  tone,
  label,
  status,
  url,
  latency,
  note,
}: {
  tone: "muted" | "bad";
  label: string;
  status?: number;
  url?: string;
  latency?: number;
  note?: string;
}) {
  return (
    <div className={cn("rounded-lg border p-2.5", tone === "bad" ? "border-sev-critical/30 bg-sev-critical/5" : "border-line bg-ink-800/60")}>
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-subtle">{label}</span>
        <span className={cn("font-mono text-xs font-semibold", tone === "bad" ? "text-sev-critical" : "text-fg-muted")}>
          {status ?? "—"}
          {latency ? ` · ${prettyMs(latency)}` : ""}
        </span>
      </div>
      {url && <code className="mt-1 block truncate font-mono text-[11px] text-fg-muted">{url}</code>}
      {note && <div className="mt-1 text-[11px] text-fg-subtle">{note}</div>}
    </div>
  );
}

export default FindingCard;
