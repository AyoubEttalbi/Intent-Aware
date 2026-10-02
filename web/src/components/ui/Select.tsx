import { useEffect, useRef, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "../../lib/ui";

export interface SelectOption<T extends string> {
  value: T;
  label: string;
  hint?: string;
}

/** Monochrome popover select — hairline, accent-free, keyboard-dismissable.
 *  Reused for the brain model + effort pickers. */
export function Select<T extends string>({
  value,
  options,
  onChange,
  label,
  icon,
  className,
  align = "left",
  disabled,
}: {
  value: T;
  options: ReadonlyArray<SelectOption<T>>;
  onChange: (v: T) => void;
  label?: string;
  icon?: ReactNode;
  className?: string;
  align?: "left" | "right";
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = options.find((o) => o.value === value) ?? options[0];

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className={cn("relative", className)}>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-2 rounded-lg border border-line bg-surface px-3 py-2 text-sm text-fg transition-colors hover:border-line-strong hover:bg-surface-2 disabled:opacity-40 disabled:pointer-events-none"
      >
        <span className="flex min-w-0 items-center gap-2">
          {icon && <span className="text-fg-subtle">{icon}</span>}
          {label && <span className="shrink-0 text-fg-subtle">{label}</span>}
          <span className="truncate font-medium">{current?.label}</span>
        </span>
        <ChevronDown
          size={15}
          className={cn("shrink-0 text-fg-subtle transition-transform", open && "rotate-180")}
        />
      </button>

      <AnimatePresence>
        {open && (
          <motion.ul
            role="listbox"
            initial={{ opacity: 0, y: -4, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.98 }}
            transition={{ duration: 0.14, ease: [0.22, 0.61, 0.36, 1] }}
            className={cn(
              "absolute z-50 mt-1.5 max-h-72 w-max min-w-full overflow-auto rounded-xl border border-line bg-bg p-1 shadow-pop",
              align === "right" ? "right-0" : "left-0"
            )}
          >
            {options.map((o) => {
              const sel = o.value === value;
              return (
                <li key={o.value} role="option" aria-selected={sel}>
                  <button
                    type="button"
                    onClick={() => {
                      onChange(o.value);
                      setOpen(false);
                    }}
                    className={cn(
                      "flex w-full items-start gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm transition-colors",
                      sel ? "bg-surface-2 text-fg" : "text-fg-muted hover:bg-surface-2 hover:text-fg"
                    )}
                  >
                    <Check size={15} className={cn("mt-0.5 shrink-0", sel ? "text-fg" : "text-transparent")} />
                    <span className="min-w-0">
                      <span className="block font-medium leading-tight">{o.label}</span>
                      {o.hint && <span className="mt-0.5 block text-xs text-fg-subtle">{o.hint}</span>}
                    </span>
                  </button>
                </li>
              );
            })}
          </motion.ul>
        )}
      </AnimatePresence>
    </div>
  );
}

// NOTE: brain model/effort options are NOT hardcoded here anymore — they come
// from the backend catalog (GET /models) via web/src/lib/models.ts.
