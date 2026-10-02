import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  Brain,
  Check,
  Compass,
  Flag,
  KeyRound,
  Loader2,
  Radar,
  Search,
  Sparkles,
  Swords,
  X,
} from "lucide-react";
import { cn } from "../lib/ui";
import type { JobProgress } from "../lib/types";
import CrawlVisualizer, { parseCrawlTrail, isFindingLine } from "./CrawlVisualizer";

// Backend phase -> which of the 5 visible stages is "active".
const PHASE_TO_STAGE: Record<string, number> = {
  discover: 0,
  crawl: 0,
  identities: 1,
  attack: 2,
  verify: 3,
  report: 4,
};

const STAGES = [
  { key: "discover", label: "Discovering surface", detail: "OpenAPI + UI crawl + GraphQL" },
  { key: "identities", label: "Establishing identities", detail: "logins · owned resources" },
  { key: "attack", label: "Running attack matrix", detail: "16 detectors × roles" },
  { key: "detect", label: "Verifying with effect oracles", detail: "differential · time · read-back" },
  { key: "report", label: "Writing founder report", detail: "plain-language explain" },
];

const LOG_LINES = [
  "🔍 fetching /openapi.json …",
  "✅ 21 endpoint(s) discovered",
  "🔑 logging in: admin, user",
  "   harvested ids for: users(3), notes(2)",
  "→ broken_auth: probing GET /orders/{id}",
  "🚩 idor: foreign record leaked on /users/{id}",
  "→ sqli: time-based on /search?q …",
  "🚩 sqli: 5.0s delay reproduced",
  "→ jwt: forging alg=none token",
  "🚩 mass_assignment: role=admin persisted",
  "→ cors: reflecting Origin …",
  "🚩 ssti: {{1337*1331}} = 1779547",
  "✨ scoring + explaining findings",
];

export default function ScanProgress({
  elapsedMs,
  onCancel,
  target,
  demo,
  progress,
}: {
  elapsedMs: number;
  onCancel: () => void;
  target: string;
  demo: boolean;
  progress?: JobProgress | null;
}) {
  // Prefer REAL backend progress when the server reports it; fall back to a
  // time-driven estimate only until the first real update arrives (and for demo).
  const hasReal = !demo && !!progress && progress.lines.length > 0;
  const cycle = demo ? 5200 : 60000;
  const timePct = Math.min(0.985, elapsedMs / cycle);
  const barPct = hasReal ? Math.min(0.985, Math.max(0.02, progress!.pct)) : timePct;
  const activeStage = hasReal
    ? PHASE_TO_STAGE[progress!.phase] ?? Math.min(STAGES.length - 1, Math.floor(timePct * STAGES.length))
    : Math.min(STAGES.length - 1, Math.floor(timePct * STAGES.length));

  const [log, setLog] = useState<string[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const idx = useRef(0);

  useEffect(() => {
    const t = setInterval(() => {
      setLog((prev) => {
        if (idx.current >= LOG_LINES.length) return prev;
        const next = [...prev, LOG_LINES[idx.current]];
        idx.current += 1;
        return next.slice(-9);
      });
    }, demo ? 380 : 1500);
    return () => clearInterval(t);
  }, [demo]);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [log, progress?.lines.length]);

  const seconds = useMemo(() => (elapsedMs / 1000).toFixed(1), [elapsedMs]);
  // Real engine lines once the server reports them; the canned reel only animates pre-first-poll / demo.
  // Show the FULL real history (scrollable) so no activity disappears mid-test; the
  // canned demo reel stays trimmed since it's only a placeholder animation.
  const shownLog = hasReal ? progress!.lines : log.slice(-9);
  const findingCount = useMemo(
    () => (hasReal ? progress!.lines.filter(isFindingLine).length : 0),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [hasReal, progress?.lines]
  );

  // Live crawl trail, parsed from the real engine lines. Visible ONLY while the
  // backend phase is "crawl" — it unmounts (with exit animation) the moment
  // crawling ends, the scan finishes, or the run was a demo.
  const trail = useMemo(
    () => parseCrawlTrail(hasReal ? progress!.lines : []),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [hasReal, progress?.lines.length]
  );
  const showCrawl = hasReal && progress!.phase === "crawl";

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      className="glass w-full max-w-2xl p-6 sm:p-8"
    >
      <div className="mb-6 flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <div className="relative grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-brand-cyan/10">
            <Radar size={20} className="text-brand-cyan" />
            <span className="absolute inset-0 rounded-xl ring-1 ring-brand-cyan/40 animate-pulse-ring" />
          </div>
          <div className="min-w-0">
            <div className="font-display text-base font-semibold text-fg">Scanning target</div>
            <code className="block max-w-[55vw] truncate font-mono text-xs text-fg-muted sm:max-w-xs">{target}</code>
          </div>
        </div>
        <div className="shrink-0 text-right">
          <div className="font-display text-2xl font-semibold tnum text-brand-cyan">{seconds}s</div>
          <button onClick={onCancel} className="btn-ghost mt-1 px-2 py-1 text-xs">
            <X size={12} /> Cancel
          </button>
        </div>
      </div>

      {/* progress bar */}
      <div className="relative mb-6 h-1.5 overflow-hidden rounded-full bg-ink-500">
        <motion.div
          className="relative h-full overflow-hidden rounded-full bg-accent"
          animate={{ width: `${barPct * 100}%` }}
          transition={{ duration: 0.5, ease: "easeOut" }}
        >
          <span className="absolute inset-y-0 left-0 w-1/2 -skew-x-12 bg-gradient-to-r from-transparent via-white/40 to-transparent animate-shimmer" />
        </motion.div>
      </div>

      {/* stages */}
      <div className="space-y-2.5">
        {STAGES.map((s, i) => {
          const done = i < activeStage;
          const active = i === activeStage;
          return (
            <div
              key={s.key}
              className={cn(
                "flex items-center gap-3 rounded-xl border px-3 py-2.5 transition-colors",
                active ? "border-brand-cyan/40 bg-brand-cyan/5" : "border-line",
                done && "opacity-70"
              )}
            >
              <div
                className={cn(
                  "grid h-7 w-7 shrink-0 place-items-center rounded-full transition-all duration-200",
                  done ? "bg-ok/20 text-ok" : active ? "bg-brand-cyan/20 text-brand-cyan" : "bg-ink-500 text-fg-subtle"
                )}
              >
                {done ? <Check size={15} /> : active ? <Loader2 size={15} className="animate-spin" /> : i + 1}
              </div>
              <div className="min-w-0 flex-1">
                <div className={cn("text-sm font-medium", active || done ? "text-fg" : "text-fg-muted")}>
                  {s.label}
                </div>
                <div className="text-xs text-fg-subtle">{s.detail}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* live crawl activity — mounts during the crawl phase only */}
      <AnimatePresence>{showCrawl && <CrawlVisualizer key="crawl" trail={trail} />}</AnimatePresence>

      {/* live log */}
      <div className="mt-5 overflow-hidden rounded-xl border border-line bg-ink-900/80">
        <div className="flex items-center justify-between border-b border-line px-3 py-2">
          <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-fg-subtle">
            Live activity
          </span>
          {findingCount > 0 && (
            <span className="rounded-md border border-sev-high/40 bg-sev-high/10 px-1.5 py-0.5 font-mono text-[11px] text-sev-high">
              {findingCount} issue{findingCount === 1 ? "" : "s"}
            </span>
          )}
        </div>
        <div
          ref={logRef}
          role="log"
          aria-live="polite"
          aria-label="Live scan activity"
          className="h-64 overflow-auto p-3 font-mono text-[11.5px] leading-relaxed text-fg-muted"
        >
          {shownLog.map((l, i) => {
            const tone = lineTone(l);
            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                className={cn("flex items-start gap-2", tone.cls)}
              >
                {tone.icon && <span className="mt-0.5 shrink-0">{tone.icon}</span>}
                <span className="min-w-0 flex-1 break-words">{l}</span>
              </motion.div>
            );
          })}
          <span className="inline-block h-3 w-1.5 animate-pulse bg-brand-cyan/70 align-middle" />
        </div>
      </div>
    </motion.div>
  );
}

/** Map an engine log line to its icon + tint. Pure — cheap per render. */
function lineTone(l: string): { icon: ReactNode; cls: string } {
  const t = l.trimStart();
  if (t.startsWith("🚩")) {
    const cls = /critical/i.test(t)
      ? "text-sev-critical"
      : /high/i.test(t)
        ? "text-sev-high"
        : /medium/i.test(t)
          ? "text-sev-medium"
          : /low/i.test(t)
            ? "text-sev-low"
            : "text-sev-high";
    return { icon: <Flag size={12} />, cls };
  }
  if (t.startsWith("✅")) return { icon: <Check size={12} />, cls: "text-ok" };
  if (t.startsWith("⚠️") || t.startsWith("⚠"))
    return { icon: <AlertTriangle size={12} />, cls: "text-sev-medium" };
  if (t.startsWith("🧠")) return { icon: <Brain size={12} />, cls: "text-brand-cyan" };
  if (t.startsWith("🔍")) return { icon: <Search size={12} />, cls: "text-fg" };
  if (t.startsWith("🧭") || t.startsWith("🔎") || t.startsWith("🧪"))
    return { icon: <Compass size={12} />, cls: "text-fg-muted" };
  if (t.startsWith("⚔️") || t.startsWith("⚔"))
    return { icon: <Swords size={12} />, cls: "text-fg-muted" };
  if (t.startsWith("✨")) return { icon: <Sparkles size={12} />, cls: "text-brand-cyan" };
  if (t.startsWith("🔑") || t.startsWith("🔓") || t.startsWith("🔐"))
    return { icon: <KeyRound size={12} />, cls: "text-fg-muted" };
  return { icon: null, cls: "" };
}
