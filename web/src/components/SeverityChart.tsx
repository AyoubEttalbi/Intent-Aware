import { motion } from "framer-motion";
import type { Finding, Severity } from "../lib/types";
import { SEVERITY_META, SEVERITY_ORDER } from "../lib/ui";

export default function SeverityChart({ findings }: { findings: Finding[] }) {
  const counts = SEVERITY_ORDER.reduce(
    (acc, s) => ({ ...acc, [s]: findings.filter((f) => f.severity === s).length }),
    {} as Record<Severity, number>
  );
  const total = findings.length || 1;
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s]));
  const confirmed = findings.filter((f) => f.confidence === "high").length;

  return (
    <div className="glass p-5">
      <div className="mb-4 flex items-baseline justify-between">
        <h3 className="font-display text-sm font-semibold text-fg">Severity breakdown</h3>
        <span className="text-xs text-fg-muted">
          <span className="font-semibold text-fg">{confirmed}</span> confirmed ·{" "}
          {findings.length - confirmed} needs review
        </span>
      </div>
      <div className="space-y-2.5">
        {SEVERITY_ORDER.map((s, i) => {
          const m = SEVERITY_META[s];
          const c = counts[s];
          return (
            <div key={s} className="flex items-center gap-3">
              <div className="flex w-20 items-center gap-2 text-xs font-medium" style={{ color: m.hex }}>
                <span className="h-2 w-2 rounded-full" style={{ background: m.hex }} />
                {m.label}
              </div>
              <div className="relative h-2.5 flex-1 overflow-hidden rounded-full bg-ink-500">
                <motion.div
                  className="absolute inset-y-0 left-0 rounded-full"
                  style={{ background: m.hex }}
                  initial={{ width: 0 }}
                  animate={{ width: `${(c / max) * 100}%` }}
                  transition={{ delay: 0.1 + i * 0.07, duration: 0.7, ease: "easeOut" }}
                />
              </div>
              <div className="w-6 text-right text-sm font-semibold tnum text-fg">{c}</div>
            </div>
          );
        })}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-line pt-3 text-xs text-fg-muted">
        <span>Total findings</span>
        <span className="font-display text-lg font-semibold tnum text-fg">{findings.length}</span>
      </div>
      {/* proportion bar */}
      <div className="mt-3 flex h-1.5 overflow-hidden rounded-full">
        {SEVERITY_ORDER.map((s) =>
          counts[s] ? (
            <div
              key={s}
              style={{ width: `${(counts[s] / total) * 100}%`, background: SEVERITY_META[s].hex }}
            />
          ) : null
        )}
      </div>
    </div>
  );
}
