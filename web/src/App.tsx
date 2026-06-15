import { Suspense, lazy, useCallback, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion, type Variants } from "framer-motion";
import { Sparkles } from "lucide-react";
import type { SceneMode } from "./components/Background3D";
import Header from "./components/Header";
import { useTheme } from "./lib/theme";
import SafeBoundary from "./components/SafeBoundary";

// Three.js is heavy — stream it in after the shell paints (CSS gradient covers the gap).
const Background3D = lazy(() => import("./components/Background3D"));
import ScanForm from "./components/ScanForm";
import ScanProgress from "./components/ScanProgress";
import ResultsView from "./components/ResultsView";
import {
  DetectorMarquee,
  StatStrip,
  HowItWorks,
  WhatItCatches,
  TrustRow,
  Footer,
} from "./components/Landing";
import { runScan, runDemo } from "./lib/api";
import type { ScanRequest, ScanResult } from "./lib/types";

type Phase = "idle" | "scanning" | "results";

export default function App() {
  const reduce = useReducedMotion();
  const { isDark } = useTheme();
  const heroContainer: Variants = {
    hidden: {},
    show: { transition: { staggerChildren: reduce ? 0 : 0.08, delayChildren: reduce ? 0 : 0.05 } },
  };
  const heroItem: Variants = {
    hidden: { opacity: 0, y: reduce ? 0 : 14 },
    show: { opacity: 1, y: 0, transition: { duration: reduce ? 0 : 0.5, ease: [0.22, 0.61, 0.36, 1] } },
  };
  const [phase, setPhase] = useState<Phase>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [target, setTarget] = useState("");
  const [demo, setDemo] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);

  const start = useCallback(async (req: ScanRequest | null) => {
    setError(null);
    setElapsed(0);
    setDemo(!req);
    setTarget(req?.base_url ?? "https://demo.yourapp.dev");
    setPhase("scanning");
    abort.current = new AbortController();
    const handlers = { signal: abort.current.signal, onTick: setElapsed };
    try {
      const res = req ? await runScan(req, handlers) : await runDemo(handlers);
      setResult(res);
      setPhase("results");
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (e) {
      if ((e as Error).name === "AbortError") {
        setPhase("idle");
        return;
      }
      setError(
        `${(e as Error).message}. Is the Intent-Aware API running on :8000? You can still explore "Try a demo".`
      );
      setPhase("idle");
    }
  }, []);

  const cancel = useCallback(() => {
    abort.current?.abort();
    setPhase("idle");
  }, []);

  const reset = useCallback(() => {
    setPhase("idle");
    setResult(null);
    setError(null);
  }, []);

  const mode: SceneMode = phase === "scanning" ? "scanning" : "idle";

  return (
    <div className="relative min-h-dvh">
      <Header onNewScan={reset} scanned={phase === "results"} />

      <AnimatePresence mode="wait">
        {phase === "results" && result ? (
          <motion.main key="results" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <ResultsView result={result} target={target} onNewScan={reset} />
            <Footer />
          </motion.main>
        ) : (
          <motion.main key="landing" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            {/* ── First view: the 3D "intent core" backs the hero / live scan ── */}
            <section className="relative isolate flex min-h-[calc(100dvh-3.5rem)] flex-col items-center justify-center overflow-hidden px-4 py-16 sm:px-6">
              <SafeBoundary>
                <Suspense fallback={null}>
                  <Background3D mode={mode} isDark={isDark} />
                </Suspense>
              </SafeBoundary>
              <div className="scangrid pointer-events-none absolute inset-0 -z-[5]" aria-hidden />

              <div className="relative z-10 flex w-full max-w-2xl flex-col items-center">
                <AnimatePresence mode="wait">
                  {phase === "scanning" ? (
                    <ScanProgress key="prog" elapsedMs={elapsed} onCancel={cancel} target={target} demo={demo} />
                  ) : (
                    <motion.div
                      key="hero"
                      initial={{ opacity: 0, y: 16 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -16 }}
                      className="flex w-full flex-col items-center"
                    >
                      <motion.div variants={heroContainer} initial="hidden" animate="show" className="mb-7 text-center">
                        <motion.span variants={heroItem} className="chip mb-5">
                          <span className="h-1.5 w-1.5 rounded-full bg-accent" />
                          Autonomous QA&nbsp;+&nbsp;Security
                        </motion.span>
                        <motion.h1
                          variants={heroItem}
                          className="track-display mx-auto max-w-3xl font-display text-[2.6rem] font-semibold leading-[1.04] text-fg sm:text-6xl"
                        >
                          Point it at any app.
                          <br />
                          Ship with <span className="text-accent">conviction</span>.
                        </motion.h1>
                        <motion.p
                          variants={heroItem}
                          className="track-tight mx-auto mt-5 max-w-xl text-pretty text-base leading-relaxed text-fg-muted sm:text-lg"
                        >
                          It explores like a QA engineer, attacks like a pentester, and explains every bug in
                          plain language — with a copy-paste repro you can verify.
                        </motion.p>
                      </motion.div>

                      <motion.div
                        variants={heroItem}
                        initial="hidden"
                        animate="show"
                        className="mb-6 w-full max-w-xl"
                      >
                        <DetectorMarquee />
                      </motion.div>

                      <motion.div
                        initial={{ opacity: 0, y: reduce ? 0 : 18 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: reduce ? 0 : 0.35, duration: 0.5 }}
                        className="w-full"
                      >
                        <ScanForm onLaunch={(r) => start(r)} onDemo={() => start(null)} busy={false} />
                      </motion.div>

                      {error && (
                        <motion.div
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          className="mt-4 flex max-w-2xl items-start gap-2.5 rounded-xl border border-sev-high/30 bg-sev-high/10 px-4 py-3 text-sm text-fg"
                        >
                          <Sparkles size={16} className="mt-0.5 shrink-0 text-sev-high" />
                          {error}
                        </motion.div>
                      )}

                      <p className="mt-6 text-center text-xs text-fg-subtle">
                        Only scan apps you own or are authorized to test.
                      </p>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </section>

            {/* ── Story sections (idle only — hidden while a scan runs) ── */}
            {phase === "idle" && (
              <>
                <div className="mx-auto max-w-content space-y-24 px-4 pb-10 sm:px-6">
                  <StatStrip />
                  <HowItWorks />
                  <WhatItCatches />
                  <TrustRow />
                </div>
                <Footer />
              </>
            )}
          </motion.main>
        )}
      </AnimatePresence>
    </div>
  );
}
