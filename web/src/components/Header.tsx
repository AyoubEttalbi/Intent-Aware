import { motion } from "framer-motion";
import { ShieldCheck, Github, Sun, Moon } from "lucide-react";
import { useTheme } from "../lib/theme";

function ThemeToggle() {
  const { isDark, toggle } = useTheme();
  return (
    <button
      onClick={toggle}
      className="btn-ghost h-8 w-8 p-0"
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      title={isDark ? "Light mode" : "Dark mode"}
    >
      <motion.span
        key={isDark ? "moon" : "sun"}
        initial={{ rotate: -90, opacity: 0, scale: 0.6 }}
        animate={{ rotate: 0, opacity: 1, scale: 1 }}
        transition={{ duration: 0.2 }}
        className="grid place-items-center"
      >
        {isDark ? <Moon size={15} /> : <Sun size={15} />}
      </motion.span>
    </button>
  );
}

export default function Header({ onNewScan, scanned }: { onNewScan: () => void; scanned: boolean }) {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-bg/80 backdrop-blur-xl">
      <div className="mx-auto flex h-14 max-w-content items-center justify-between px-4 sm:px-6">
        <button onClick={onNewScan} className="group flex items-center gap-2.5" aria-label="Home">
          <motion.span
            whileHover={{ rotate: -6, scale: 1.04 }}
            className="grid h-8 w-8 place-items-center rounded-lg bg-accent shadow-[0_6px_18px_-6px_rgb(var(--accent)/0.8)]"
          >
            <ShieldCheck size={17} className="text-accent-fg" />
          </motion.span>
          <span className="font-display text-[15px] font-semibold tracking-tight text-fg">
            Intent<span className="text-accent">·</span>Aware
          </span>
          <span className="hidden rounded-md border border-line px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-fg-subtle sm:inline">
            v2.1
          </span>
        </button>

        <div className="flex items-center gap-2">
          {scanned && (
            <button onClick={onNewScan} className="btn-ghost px-3 py-1.5 text-xs">
              New scan
            </button>
          )}
          <ThemeToggle />
          <a
            href="https://github.com"
            target="_blank"
            rel="noreferrer"
            className="btn-ghost h-8 w-8 p-0"
            aria-label="Source"
          >
            <Github size={15} />
          </a>
        </div>
      </div>
    </header>
  );
}
