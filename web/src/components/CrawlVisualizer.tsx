import { motion } from "framer-motion";
import { Footprints, Globe } from "lucide-react";
import { cn } from "../lib/ui";

export interface CrawlPage {
  n: number;
  cap: string;
  authed: boolean;
  url: string;
}

export interface CrawlTrail {
  pages: CrawlPage[];
  journeys: string[];
  pageErrors: number;
  findings: number;
}

// Matches the QA crawler's log lines (qa/crawler.py):
//   "🔎 QA page {n}/{cap}[ (auth)]: {url}"   (cap may be a number, ∞ or ?)
const PAGE_RE = /^🔎 QA page (\d+)\/([^\s]+)( \(auth\))?: (.+)$/;
const JOURNEY_RE = /^\s*🧪 E2E journey:\s*(.+?)\s*$/;

/** A finding line (🚩) in engine log lines or the crawl trail. */
export function isFindingLine(l: string): boolean {
  return /^\s*🚩/.test(l);
}

/** Fold raw engine log lines into a structured crawl trail. Pure — safe to
 *  recompute on every progress poll. */
export function parseCrawlTrail(lines: string[]): CrawlTrail {
  const pages: CrawlPage[] = [];
  const journeys: string[] = [];
  let pageErrors = 0;
  let findings = 0;
  for (const line of lines) {
    const m = line.match(PAGE_RE);
    if (m) {
      pages.push({ n: Number(m[1]), cap: m[2], authed: m[3] !== undefined, url: m[4].trim() });
      continue;
    }
    const j = line.match(JOURNEY_RE);
    if (j) {
      journeys.push(j[1]);
      continue;
    }
    if (line.includes("page error on")) pageErrors += 1;
    else if (isFindingLine(line)) findings += 1;
  }
  return { pages: pages.slice(-30), journeys: journeys.slice(-6), pageErrors, findings };
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search || "/";
  } catch {
    return url;
  }
}

/** Live crawl activity card. Rendered only while the backend phase is "crawl";
 *  the parent unmounts it (with exit animation) the moment crawling ends. */
export default function CrawlVisualizer({ trail }: { trail: CrawlTrail }) {
  const pages = trail.pages;
  const current = pages[pages.length - 1];
  const countable = !!current && /^\d+$/.test(current.cap);
  const recent = pages.slice(-8);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.25, ease: "easeOut" }}
      role="status"
      aria-live="polite"
      aria-label="Live crawl activity"
      className="mt-5 rounded-xl border border-line bg-ink-900/60 p-4"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand-cyan opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-brand-cyan" />
          </span>
          <span className="truncate text-sm font-medium text-fg">Crawling the app</span>
        </div>
        <div className="shrink-0 font-mono text-xs text-fg-muted">
          {current ? (
            <>
              page <span className="text-fg">{current.n}</span>
              {countable && <span>/{current.cap}</span>}
              {current.authed && (
                <span className="ml-1.5 rounded border border-line px-1 py-px text-[10px] uppercase tracking-wide text-fg-subtle">
                  auth
                </span>
              )}
            </>
          ) : (
            "starting…"
          )}
        </div>
      </div>

      {current && (
        <div className="mt-2.5 flex min-w-0 items-center gap-2 rounded-lg border border-line bg-ink-900/80 px-2.5 py-2">
          <Globe size={13} className="shrink-0 text-brand-cyan" />
          <code title={current.url} className="min-w-0 flex-1 truncate font-mono text-xs text-fg">
            {shortUrl(current.url)}
          </code>
        </div>
      )}

      {recent.length > 1 && (
        <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
          <Footprints size={13} className="shrink-0 text-fg-subtle" />
          {recent.map((p, i) => {
            const last = i === recent.length - 1;
            return (
              <span
                key={`${p.n}-${p.url}`}
                title={p.url}
                className={cn(
                  "rounded-md border px-1.5 py-0.5 font-mono text-[10.5px]",
                  last
                    ? "border-brand-cyan/50 bg-brand-cyan/10 text-fg"
                    : "border-line text-fg-subtle opacity-70"
                )}
              >
                {p.n}
              </span>
            );
          })}
        </div>
      )}

      {(trail.journeys.length > 0 || trail.findings > 0 || trail.pageErrors > 0) && (
        <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-subtle">
          {trail.journeys.length > 0 && <span>E2E journeys: {trail.journeys.length}</span>}
          {trail.findings > 0 && <span className="text-sev-high">issues spotted: {trail.findings}</span>}
          {trail.pageErrors > 0 && <span>page errors: {trail.pageErrors}</span>}
        </div>
      )}
    </motion.div>
  );
}
