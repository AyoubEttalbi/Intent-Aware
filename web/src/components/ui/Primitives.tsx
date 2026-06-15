import { useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { Check, Copy } from "lucide-react";
import type { Severity } from "../../lib/types";
import { SEVERITY_META, cn } from "../../lib/ui";

export function SeverityChip({ severity, className }: { severity: Severity; className?: string }) {
  const m = SEVERITY_META[severity];
  return (
    <span className={cn("chip border-transparent ring-1", m.bg, m.text, m.ring, className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", m.dot)} />
      {m.label}
    </span>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="glass-soft px-4 py-3 transition-colors duration-200 hover:border-brand-cyan/25 hover:bg-ink-600/60">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-0.5 text-2xl font-display font-semibold tnum text-fg">{value}</div>
      {hint && <div className="text-xs text-fg-muted">{hint}</div>}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1400);
        } catch {
          /* clipboard blocked */
        }
      }}
      className="btn-ghost px-2.5 py-1.5 text-xs"
      aria-label={copied ? "Copied" : label}
    >
      {copied ? <Check size={14} className="text-ok" /> : <Copy size={14} />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function Toggle({
  checked,
  onChange,
  tone = "brand",
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  tone?: "brand" | "danger";
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative h-6 w-11 shrink-0 rounded-full border transition-colors duration-200",
        checked
          ? tone === "danger"
            ? "bg-danger/80 border-danger"
            : "bg-brand-cyan/80 border-brand-cyan"
          : "bg-ink-500 border-line"
      )}
    >
      <motion.span
        layout
        transition={{ type: "spring", stiffness: 500, damping: 32 }}
        className={cn("absolute top-[3px] rounded-full bg-white shadow", checked ? "right-[3px]" : "left-[3px]")}
        style={{ height: 18, width: 18 }}
      />
    </button>
  );
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="inline-flex rounded-xl border border-line bg-surface p-1">
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            onClick={() => onChange(o.value)}
            className="relative px-3 py-1.5 text-xs font-semibold transition-colors"
          >
            {active && (
              <motion.span
                layoutId="seg-active"
                className="absolute inset-0 rounded-lg bg-accent"
                transition={{ type: "spring", stiffness: 400, damping: 32 }}
              />
            )}
            <span className={cn("relative z-10", active ? "text-accent-fg" : "text-fg-muted")}>
              {o.label}
            </span>
          </button>
        );
      })}
    </div>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <span
      className="inline-block animate-spin rounded-full border-2 border-current border-t-transparent"
      style={{ width: size, height: size }}
    />
  );
}
