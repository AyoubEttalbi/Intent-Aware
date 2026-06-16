import { Suspense, lazy, useRef } from "react";
import { motion } from "framer-motion";
import { Boxes, RotateCcw } from "lucide-react";
import type { ScanResult } from "../lib/types";
import { GRADE_META } from "../lib/ui";
import GradeRing from "./GradeRing";
import SeverityChart from "./SeverityChart";
import CoveragePanel from "./CoveragePanel";
import FindingsList, { type FindingsListHandle } from "./FindingsList";

const AttackSurface3D = lazy(() => import("./AttackSurface3D"));
import ReportView from "./ReportView";
import TestChat from "./TestChat";
import { Stat } from "./ui/Primitives";

const fade = {
  initial: { opacity: 0, y: 18 },
  animate: { opacity: 1, y: 0 },
};

export default function ResultsView({
  result,
  target,
  jobId,
  onNewScan,
}: {
  result: ScanResult;
  target: string;
  jobId: string | null;
  onNewScan: () => void;
}) {
  const listRef = useRef<FindingsListHandle>(null);
  const grade = GRADE_META[result.grade];
  const crit = result.findings.filter((f) => f.severity === "critical").length;
  const high = result.findings.filter((f) => f.severity === "high").length;

  return (
    <div className="mx-auto max-w-6xl px-4 pb-24 pt-8 sm:px-6">
      {/* hero summary */}
      <motion.div {...fade} transition={{ duration: 0.5 }} className="glass relative overflow-hidden p-6 sm:p-8">
        <div
          className="absolute -right-10 -top-10 h-44 w-44 rounded-full blur-3xl"
          style={{ background: `${grade.hex}22` }}
        />
        <div className="flex flex-col items-center gap-8 sm:flex-row sm:items-center sm:gap-10">
          <GradeRing grade={result.grade} score={result.score} />
          <div className="flex-1">
            <div className="text-xs font-semibold uppercase tracking-widest text-fg-subtle">Security posture</div>
            <h1 className="mt-1 font-display text-2xl font-semibold text-fg sm:text-3xl">
              {result.findings.length} issues found —{" "}
              <span style={{ color: grade.hex }}>{grade.label.toLowerCase()}</span>
            </h1>
            <p className="mt-1.5 max-w-lg text-sm text-fg-muted">
              Scanned <code className="font-mono text-fg-muted">{target}</code>. Each finding below is proven
              by an effect oracle — copy the repro and verify it yourself.
            </p>
            <div className="mt-4 grid grid-cols-2 gap-2.5 sm:max-w-md sm:grid-cols-3">
              <Stat label="Critical" value={<span className="text-sev-critical">{crit}</span>} />
              <Stat label="High" value={<span className="text-sev-high">{high}</span>} />
              <Stat label="Requests" value={result.coverage.requests_sent} />
            </div>
            <button onClick={onNewScan} className="btn-ghost mt-5 text-sm">
              <RotateCcw size={15} /> Run another scan
            </button>
          </div>
        </div>
      </motion.div>

      {/* charts row */}
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <motion.div {...fade} transition={{ duration: 0.5, delay: 0.05 }}>
          <SeverityChart findings={result.findings} />
        </motion.div>
        <motion.div {...fade} transition={{ duration: 0.5, delay: 0.1 }}>
          <CoveragePanel coverage={result.coverage} />
        </motion.div>
      </div>

      {/* attack surface 3D */}
      {result.findings.length > 0 && (
        <motion.div {...fade} transition={{ duration: 0.5, delay: 0.12 }} className="glass mt-6 p-5">
          <h3 className="mb-1 flex items-center gap-2 font-display text-sm font-semibold text-fg">
            <Boxes size={16} className="text-brand-violet" /> Attack surface
          </h3>
          <p className="mb-2 text-xs text-fg-muted">
            Every affected endpoint, sized & coloured by its worst issue. Click a node to jump to its findings.
          </p>
          <Suspense
            fallback={<div className="grid h-[340px] place-items-center text-sm text-fg-subtle">Rendering map…</div>}
          >
            <AttackSurface3D
              findings={result.findings}
              onSelect={(k) => listRef.current?.focusEndpoint(k)}
            />
          </Suspense>
        </motion.div>
      )}

      {/* findings */}
      <motion.div {...fade} transition={{ duration: 0.5, delay: 0.15 }} className="mt-10">
        <FindingsList ref={listRef} findings={result.findings} />
      </motion.div>

      {/* report */}
      <motion.div {...fade} transition={{ duration: 0.5, delay: 0.2 }} className="mt-6">
        <ReportView markdown={result.report_markdown} />
      </motion.div>

      {/* chat with this test's own session */}
      <motion.div {...fade} transition={{ duration: 0.5, delay: 0.24 }} className="mt-6">
        {jobId ? (
          <TestChat jobId={jobId} />
        ) : (
          <div className="surface p-6 text-center text-sm text-fg-muted">
            Chatting with the results is available after a real scan — the demo has no live session.
          </div>
        )}
      </motion.div>
    </div>
  );
}
