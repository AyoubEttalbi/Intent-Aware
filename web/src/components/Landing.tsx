import {
  ShieldCheck,
  Crosshair,
  FileText,
  Lock,
  Eye,
  Gauge,
  Github,
  ArrowUpRight,
} from "lucide-react";
import { DETECTORS, STEPS } from "../lib/landing";
import { Reveal, CountUp } from "./ui/Motion";

/* ── Detector marquee — an infinite, edge-faded ticker of what it catches.
      Linear's "customer logos" rhythm, repurposed for detectors. ───────── */
export function DetectorMarquee() {
  const row = [...DETECTORS, ...DETECTORS];
  return (
    <div className="mask-x relative w-full overflow-hidden py-1">
      <div className="flex w-max animate-marquee gap-2.5 will-change-transform hover:[animation-play-state:paused]">
        {row.map((d, i) => (
          <span
            key={`${d.key}-${i}`}
            className="inline-flex shrink-0 items-center gap-2 rounded-full border border-line bg-surface/70 px-3 py-1.5 text-xs font-medium text-fg-muted"
          >
            <span className="h-1.5 w-1.5 rounded-full bg-accent" />
            {d.label}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ── Headline stat strip — count-up numbers that earn trust. ───────────── */
export function StatStrip() {
  const stats = [
    { value: <CountUp to={16} />, label: "Effect-oracle detectors" },
    { value: <CountUp to={0} />, label: "False positives on the gate" },
    { value: "A–F", label: "Founder-grade verdict" },
    { value: <CountUp to={5} />, label: "Viewport breakpoints tested" },
  ];
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-4">
      {stats.map((s, i) => (
        <Reveal key={s.label} delay={i * 0.06} className="bg-bg">
          <div className="px-4 py-5 text-center">
            <div className="font-display text-3xl font-semibold tnum text-fg track-tight">{s.value}</div>
            <div className="mt-1 text-[12px] leading-snug text-fg-subtle">{s.label}</div>
          </div>
        </Reveal>
      ))}
    </div>
  );
}

/* ── How it works — three steps, hairline cards, numbered. ─────────────── */
export function HowItWorks() {
  const icons = [Crosshair, ShieldCheck, FileText];
  return (
    <section className="w-full">
      <Reveal className="mb-10 text-center">
        <h2 className="mx-auto max-w-2xl font-display text-3xl font-semibold leading-tight text-fg track-display sm:text-[2.6rem]">
          From a URL to a verdict in one run.
        </h2>
      </Reveal>
      <div className="grid gap-4 md:grid-cols-3">
        {STEPS.map((s, i) => {
          const Icon = icons[i];
          return (
            <Reveal key={s.n} delay={i * 0.08}>
              <div className="panel-lift group h-full p-6 transition-colors duration-200 hover:bg-surface-2">
                <div className="flex items-center justify-between">
                  <span className="grid h-10 w-10 place-items-center rounded-lg border border-line bg-surface text-accent">
                    <Icon size={18} />
                  </span>
                  <span className="font-mono text-xs font-medium tracking-widest text-fg-subtle">{s.n}</span>
                </div>
                <h3 className="mt-4 font-display text-lg font-semibold text-fg track-tight">{s.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-fg-muted">{s.body}</p>
              </div>
            </Reveal>
          );
        })}
      </div>
    </section>
  );
}

/* ── What it catches — the 16 detectors as a hover-lift grid. ──────────── */
export function WhatItCatches() {
  return (
    <section className="w-full">
      <Reveal className="mb-10 text-center">
        <h2 className="mx-auto max-w-2xl font-display text-3xl font-semibold leading-tight text-fg track-display sm:text-[2.6rem]">
          Sixteen detectors. Every one proves itself.
        </h2>
        <p className="mx-auto mt-4 max-w-xl text-pretty text-[15px] leading-relaxed text-fg-muted">
          No detector ships a finding on a status code alone. Each one confirms real exploitation with a
          differential baseline, a marker reflection, a timing delay, or a persisted read-back.
        </p>
      </Reveal>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {DETECTORS.map((d, i) => (
          <Reveal key={d.key} delay={Math.min(i * 0.03, 0.3)}>
            <div className="group relative h-full overflow-hidden rounded-xl border border-line bg-surface p-4 transition-all duration-200 hover:-translate-y-0.5 hover:border-line-strong hover:bg-surface-2">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-accent transition-transform duration-200 group-hover:scale-150" />
                <span className="font-display text-sm font-semibold text-fg">{d.label}</span>
              </div>
              <p className="mt-1.5 font-mono text-[12px] leading-relaxed text-fg-subtle">{d.blurb}</p>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  );
}

/* ── Trust row — three quiet promises under the form. ──────────────────── */
export function TrustRow() {
  const items = [
    { icon: Lock, t: "Read-only by default", d: "write probes are opt-in, staging-only" },
    { icon: Eye, t: "Host-scoped", d: "never wanders off the target you name" },
    { icon: Gauge, t: "Budgeted", d: "hard ceilings on requests & model calls" },
  ];
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      {items.map((it, i) => (
        <Reveal key={it.t} delay={i * 0.06}>
          <div className="flex items-start gap-3 rounded-xl border border-line bg-surface/60 p-4">
            <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-surface text-accent">
              <it.icon size={15} />
            </span>
            <div>
              <div className="text-sm font-semibold text-fg">{it.t}</div>
              <div className="text-xs text-fg-subtle">{it.d}</div>
            </div>
          </div>
        </Reveal>
      ))}
    </div>
  );
}

/* ── Footer — Linear-style dense, quiet, hairline-topped. ──────────────── */
export function Footer() {
  return (
    <footer className="mt-24 border-t border-line">
      <div className="mx-auto flex max-w-content flex-col gap-6 px-4 py-10 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div className="flex items-center gap-2.5">
          <span className="grid h-7 w-7 place-items-center rounded-lg bg-accent">
            <ShieldCheck size={15} className="text-accent-fg" />
          </span>
          <span className="font-display text-sm font-semibold tracking-tight text-fg">
            Intent<span className="text-accent">·</span>Aware
          </span>
          <span className="text-xs text-fg-subtle">Autonomous QA + Security</span>
        </div>
        <div className="flex items-center gap-5 text-xs text-fg-subtle">
          <span>Only scan apps you own or are authorized to test.</span>
          <a
            href="https://github.com"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-fg-muted transition-colors hover:text-fg"
          >
            <Github size={13} /> Source <ArrowUpRight size={12} />
          </a>
        </div>
      </div>
    </footer>
  );
}
