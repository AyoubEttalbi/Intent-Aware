/** @type {import('tailwindcss').Config} */

// Every color resolves through a CSS variable (RGB triplet) so a single class set
// serves both themes. Light = `:root`, Dark = `.dark` — see src/index.css.
const v = (name) => `rgb(var(${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // --- semantic surfaces & text -------------------------------------
        bg: v("--bg"),
        surface: v("--surface"),
        "surface-2": v("--surface-2"),
        "surface-3": v("--surface-3"),
        fg: {
          DEFAULT: v("--fg"),
          muted: v("--fg-muted"),
          subtle: v("--fg-subtle"),
        },
        // single signal-red accent (the whole identity)
        accent: {
          DEFAULT: v("--accent"),
          strong: v("--accent-strong"),
          fg: v("--accent-fg"), // text that sits ON the accent
        },
        // severity / state — theme-aware (brighter on black, deeper on white)
        sev: {
          critical: v("--sev-critical"),
          high: v("--sev-high"),
          medium: v("--sev-medium"),
          low: v("--sev-low"),
          info: v("--sev-info"),
        },
        ok: v("--ok"),
        warn: v("--sev-medium"),
        danger: v("--accent"),

        // --- backward-compat aliases (old class names → new theme) ---------
        // Brand cyan/violet/etc. all collapse to the red accent so legacy
        // `text-brand-cyan`, `border-brand-cyan/40`, `bg-brand-violet` re-skin
        // automatically without touching every component.
        brand: {
          cyan: v("--accent"),
          sky: v("--accent"),
          indigo: v("--accent"),
          violet: v("--accent"),
        },
        // Old near-black `ink` scale → layered surfaces (theme-aware).
        ink: {
          900: v("--ink-900"),
          800: v("--bg"),
          700: v("--surface"),
          600: v("--surface-2"),
          500: v("--surface-3"),
          400: v("--surface-3"),
        },
      },
      // hairline borders use the same token at low alpha
      borderColor: {
        DEFAULT: "rgb(var(--border) / 0.10)",
        line: "rgb(var(--border) / 0.10)",
        "line-strong": "rgb(var(--border) / 0.16)",
      },
      backgroundColor: {
        line: "rgb(var(--border) / 0.06)",
      },
      fontFamily: {
        // Linear runs a single voice from display to body — Inter (its closest
        // free substitute) at 500–700 with tight negative tracking on display.
        display: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      borderRadius: { xl2: "1.1rem" },
      maxWidth: { content: "1200px" },
      boxShadow: {
        // restrained, theme-aware elevation (no neon glow)
        card: "0 1px 2px rgb(var(--border) / 0.04), 0 8px 30px -16px rgb(var(--shadow) / 0.55)",
        pop: "0 12px 40px -12px rgb(var(--shadow) / 0.5)",
        // legacy alias kept tasteful: a tight accent ring, not a glow blob
        glow: "0 0 0 1px rgb(var(--accent) / 0.30)",
      },
      keyframes: {
        shimmer: { "100%": { transform: "translateX(100%)" } },
        "pulse-ring": {
          "0%": { transform: "scale(0.92)", opacity: "0.5" },
          "100%": { transform: "scale(1.7)", opacity: "0" },
        },
        float: {
          "0%,100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-6px)" },
        },
        "grid-pan": { "100%": { backgroundPosition: "48px 48px" } },
        "sweep": { "0%": { transform: "translateY(-120%)" }, "100%": { transform: "translateY(120%)" } },
        marquee: { "0%": { transform: "translateX(0)" }, "100%": { transform: "translateX(-50%)" } },
        "float-slow": {
          "0%,100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-10px)" },
        },
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(10px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        shimmer: "shimmer 1.8s infinite",
        "pulse-ring": "pulse-ring 2.6s cubic-bezier(0.2,0.6,0.3,1) infinite",
        float: "float 6s ease-in-out infinite",
        "float-slow": "float-slow 9s ease-in-out infinite",
        "grid-pan": "grid-pan 9s linear infinite",
        sweep: "sweep 2.4s ease-in-out infinite",
        marquee: "marquee 38s linear infinite",
      },
    },
  },
  plugins: [],
};
