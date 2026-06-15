import { useMemo, useRef, useState, useImperativeHandle, forwardRef } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Search, SlidersHorizontal, ShieldCheck } from "lucide-react";
import type { Finding, Severity } from "../lib/types";
import { SEVERITY_META, SEVERITY_ORDER, vulnLabel, cn } from "../lib/ui";
import FindingCard from "./FindingCard";

export interface FindingsListHandle {
  focusEndpoint: (endpointKey: string) => void;
}

const FindingsList = forwardRef<FindingsListHandle, { findings: Finding[] }>(({ findings }, ref) => {
  const [active, setActive] = useState<Set<Severity>>(new Set());
  const [query, setQuery] = useState("");
  const cardRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  useImperativeHandle(ref, () => ({
    focusEndpoint(key: string) {
      const scroll = (el: HTMLDivElement) => {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        el.animate(
          [{ boxShadow: "0 0 0 2px rgba(110,121,229,0.75)" }, { boxShadow: "0 0 0 0 rgba(110,121,229,0)" }],
          { duration: 1400 }
        );
      };
      const el = cardRefs.current.get(key);
      if (el && el.isConnected) {
        scroll(el);
      } else {
        // the target is filtered out — clear filters, then scroll once it re-mounts
        setActive(new Set());
        requestAnimationFrame(() =>
          requestAnimationFrame(() => {
            const re = cardRefs.current.get(key);
            if (re && re.isConnected) scroll(re);
          })
        );
      }
    },
  }));

  const counts = useMemo(
    () =>
      SEVERITY_ORDER.reduce(
        (acc, s) => ({ ...acc, [s]: findings.filter((f) => f.severity === s).length }),
        {} as Record<Severity, number>
      ),
    [findings]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings
      .filter((f) => (active.size === 0 ? true : active.has(f.severity)))
      .filter((f) =>
        q
          ? `${f.title} ${f.endpoint_key} ${vulnLabel(f.vuln_class)} ${f.vuln_class}`
              .toLowerCase()
              .includes(q)
          : true
      )
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  }, [findings, active, query]);

  const toggle = (s: Severity) =>
    setActive((prev) => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });

  return (
    <div>
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <h2 className="flex items-center gap-2 font-display text-lg font-semibold text-fg">
          <SlidersHorizontal size={18} className="text-brand-cyan" />
          Findings
          <span className="chip ml-1">{filtered.length}</span>
        </h2>
        <div className="relative w-full sm:w-64">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-subtle" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter findings…"
            className="input pl-9"
            aria-label="Filter findings"
          />
        </div>
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => {
          const m = SEVERITY_META[s];
          const on = active.has(s);
          return (
            <button
              key={s}
              type="button"
              onClick={() => toggle(s)}
              aria-pressed={on}
              aria-label={`${m.label}, ${counts[s]} findings`}
              className={cn(
                "chip transition-[background-color,color,box-shadow] duration-150",
                on ? cn("ring-1", m.bg, m.text, m.ring) : "border-line text-fg-muted hover:border-brand-cyan/30 hover:text-fg"
              )}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: m.hex }} />
              {m.label}
              <span className="tnum">{counts[s]}</span>
            </button>
          );
        })}
        {active.size > 0 && (
          <button type="button" onClick={() => setActive(new Set())} className="chip hover:text-fg">
            Clear
          </button>
        )}
      </div>

      <div className="space-y-3">
        <AnimatePresence mode="popLayout">
          {filtered.map((f, i) => (
            <FindingCard
              key={`${f.vuln_class}-${f.endpoint_key}-${f.identity}-${i}`}
              finding={f}
              index={i}
              ref={(el) => {
                if (el) cardRefs.current.set(f.endpoint_key, el);
                else cardRefs.current.delete(f.endpoint_key);
              }}
            />
          ))}
        </AnimatePresence>
        {filtered.length === 0 &&
          (findings.length === 0 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              className="glass grid place-items-center gap-2 p-12 text-center"
            >
              <ShieldCheck size={28} className="text-ok" />
              <div className="font-display text-lg font-semibold text-fg">No issues found</div>
              <div className="max-w-sm text-sm text-fg-muted">
                Every endpoint we exercised passed its effect-oracle checks. Check Coverage to see what was tested.
              </div>
            </motion.div>
          ) : (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass grid place-items-center p-10 text-center">
              <div className="text-fg-muted">No findings match your filters.</div>
            </motion.div>
          ))}
      </div>
    </div>
  );
});
FindingsList.displayName = "FindingsList";

export default FindingsList;
