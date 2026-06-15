import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import type { Grade } from "../lib/types";
import { GRADE_META } from "../lib/ui";

export default function GradeRing({ grade, score }: { grade: Grade; score: number }) {
  const reduce = useReducedMotion();
  const { hex, label } = GRADE_META[grade];
  const size = 184;
  const stroke = 12;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;

  const [display, setDisplay] = useState(reduce ? score : 0);
  useEffect(() => {
    if (reduce) {
      setDisplay(score);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const dur = 1100;
    const tick = (t: number) => {
      const k = Math.min(1, (t - start) / dur);
      const eased = 1 - Math.pow(1 - k, 3);
      setDisplay(Math.round(eased * score));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [score, reduce]);

  return (
    <div className="relative grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(148,163,184,0.12)" strokeWidth={stroke} fill="none" />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={hex}
          strokeWidth={stroke}
          strokeLinecap="round"
          fill="none"
          strokeDasharray={circ}
          initial={{ strokeDashoffset: reduce ? circ * (1 - pct) : circ }}
          animate={{ strokeDashoffset: circ * (1 - pct) }}
          transition={{ duration: reduce ? 0 : 1.2, ease: [0.22, 0.61, 0.36, 1] }}
          style={{ filter: `drop-shadow(0 0 10px ${hex}66)` }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <motion.div
          initial={{ scale: reduce ? 1 : 0.6, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.15, type: "spring", stiffness: 260, damping: 18 }}
          className="text-center"
        >
          <div className="font-display text-6xl font-bold leading-none" style={{ color: hex }}>
            {grade}
          </div>
          <div className="mt-1 text-sm font-semibold tnum text-fg">{display}/100</div>
          <div className="text-[11px] uppercase tracking-widest text-fg-subtle">{label}</div>
        </motion.div>
      </div>
    </div>
  );
}
