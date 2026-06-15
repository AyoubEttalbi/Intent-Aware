import { useSyncExternalStore } from "react";

export type Theme = "light" | "dark";
const KEY = "ia-theme";

/** <html> is the single source of truth (seeded pre-paint by the boot script). */
function current(): Theme {
  if (typeof document === "undefined") return "dark";
  return document.documentElement.classList.contains("light") ? "light" : "dark";
}

const listeners = new Set<() => void>();
function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/** Commit a theme to <html> (class + color-scheme), persist, and notify subscribers. */
export function setTheme(theme: Theme) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.classList.toggle("light", theme === "light");
  root.style.colorScheme = theme;
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* private mode — ignore */
  }
  listeners.forEach((l) => l());
}

export function toggleTheme() {
  setTheme(current() === "dark" ? "light" : "dark");
}

/**
 * Shared theme via an external store — every consumer re-renders together when
 * the theme flips. Implemented WITHOUT a per-component effect so it stays safe
 * to read from any tree (the 3D canvas chunk must not call React-DOM hooks).
 */
export function useTheme() {
  const theme = useSyncExternalStore(subscribe, current, () => "dark" as Theme);
  return { theme, isDark: theme === "dark", toggle: toggleTheme, set: setTheme };
}
