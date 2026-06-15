import { motion } from "framer-motion";
import { AlertOctagon, Boxes, Radio, Users, Send, PenLine } from "lucide-react";
import type { Coverage } from "../lib/types";
import { vulnLabel } from "../lib/ui";

export default function CoveragePanel({ coverage }: { coverage: Coverage }) {
  const stats = [
    { icon: <Boxes size={15} />, label: "Endpoints", value: coverage.endpoints_total },
    { icon: <Send size={15} />, label: "Requests", value: coverage.requests_sent },
    { icon: <Radio size={15} />, label: "Attack classes", value: coverage.attack_classes.length },
    { icon: <Users size={15} />, label: "Identities", value: coverage.identities.length },
  ];

  return (
    <div className="glass p-5">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="font-display text-sm font-semibold text-fg">Coverage</h3>
        {coverage.allow_writes && (
          <span className="chip text-sev-high ring-1 ring-sev-high/30 bg-sev-high/10">
            <PenLine size={11} /> writes enabled
          </span>
        )}
      </div>

      {coverage.low_coverage && (
        <div className="mb-4 flex gap-2.5 rounded-xl border border-sev-high/30 bg-sev-high/10 p-3">
          <AlertOctagon size={16} className="mt-0.5 shrink-0 text-sev-high" />
          <div className="text-xs leading-relaxed text-fg">
            <span className="font-semibold text-sev-high">Low coverage — results not conclusive.</span> The
            scanner couldn't exercise enough of this app to vouch for it.
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
        {stats.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06 }}
            className="glass-soft px-3 py-2.5 transition-colors duration-200 hover:border-brand-cyan/25 hover:bg-ink-600/60"
          >
            <div className="flex items-center gap-1.5 text-fg-subtle">{s.icon}</div>
            <div className="mt-1 font-display text-xl font-semibold tnum text-fg">{s.value}</div>
            <div className="text-[11px] text-fg-muted">{s.label}</div>
          </motion.div>
        ))}
      </div>

      <div className="mt-4">
        <div className="label">Roles tested</div>
        <div className="flex flex-wrap gap-1.5">
          {coverage.identities.map((id) => (
            <span key={id} className="chip">
              {id}
            </span>
          ))}
        </div>
      </div>

      <div className="mt-4">
        <div className="label">Attack classes run</div>
        <div className="flex flex-wrap gap-1.5">
          {coverage.attack_classes.map((c) => (
            <span key={c} className="chip text-fg-muted">
              {vulnLabel(c.replace(/_(matrix|misconfig|introspection|exposure|attacks)$/, ""))}
            </span>
          ))}
        </div>
      </div>

      {coverage.degraded?.length > 0 && (
        <div className="mt-4">
          <div className="label">What we couldn't fully test</div>
          <ul className="space-y-1 text-xs text-fg-muted">
            {coverage.degraded.map((d, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-sev-high">·</span>
                {d}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
