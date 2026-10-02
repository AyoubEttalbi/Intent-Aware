import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { MessageSquareText, Send, X, Clock, Cpu, Gauge, Sparkles } from "lucide-react";
import type { ChatMessage } from "../lib/types";
import { sendChat, closeChat } from "../lib/api";
import { cn } from "../lib/ui";
import { Spinner } from "./ui/Primitives";
import { Select } from "./ui/Select";
import { useBrainModels, effortOptionsFor, preferredEffort, FALLBACK_DEFAULT_MODEL } from "../lib/models";

const SUGGESTIONS = [
  "What should I fix first?",
  "Explain the worst issue in plain English",
  "Give me a prioritized fix checklist",
  "How serious is this overall?",
];

function fmtClock(s: number): string {
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

export default function TestChat({
  jobId,
  model: model0 = FALLBACK_DEFAULT_MODEL,
  effort: effort0 = "medium",
}: {
  jobId: string;
  model?: string;
  effort?: string;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const { modelOptions, variantsById, defaultModel, ready } = useBrainModels();
  const [model, setModel] = useState<string>(model0);
  const [effort, setEffort] = useState<string | undefined>(effort0);
  const [closed, setClosed] = useState(false);
  const [idleSeconds, setIdleSeconds] = useState(600);
  const [idleLeft, setIdleLeft] = useState<number | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const taRef = useRef<HTMLTextAreaElement>(null);

  const live = messages.length > 0 && !closed;

  useEffect(() => {
    if (!ready) return;
    const ids = new Set(modelOptions.map((o) => o.value));
    const m = ids.has(model) ? model : defaultModel;
    if (m !== model) setModel(m);
    const vs = variantsById[m] ?? [];
    setEffort((e) => (e !== undefined && vs.includes(e) ? e : preferredEffort(vs)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready]);

  function pickModel(v: string) {
    setModel(v);
    setEffort(preferredEffort(variantsById[v]));
  }

  const effortOpts = effortOptionsFor(variantsById[model]);

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  const handleClose = useCallback(
    async (auto = false) => {
      setClosed(true);
      setIdleLeft(null);
      await closeChat(jobId);
      if (auto)
        setMessages((m) => [
          ...m,
          { role: "assistant", content: "_Session closed after inactivity. Send a message to start a fresh one._" },
        ]);
    },
    [jobId]
  );

  // Idle countdown — resets on every exchange; auto-closes the session at zero.
  useEffect(() => {
    if (!live || idleLeft === null) return;
    if (idleLeft <= 0) {
      void handleClose(true);
      return;
    }
    const t = setTimeout(() => setIdleLeft((s) => (s === null ? s : s - 1)), 1000);
    return () => clearTimeout(t);
  }, [live, idleLeft, handleClose]);

  const send = useCallback(
    async (text: string) => {
      const msg = text.trim();
      if (!msg || busy) return;
      setClosed(false);
      setInput("");
      setMessages((m) => [...m, { role: "user", content: msg }, { role: "assistant", content: "", pending: true }]);
      setBusy(true);
      try {
        const r = await sendChat(jobId, msg, { model, effort });
        setIdleSeconds(r.idle_seconds || 600);
        setIdleLeft(r.idle_seconds || 600);
        setMessages((m) => {
          const c = [...m];
          c[c.length - 1] = { role: "assistant", content: r.reply };
          return c;
        });
      } catch (e) {
        setMessages((m) => {
          const c = [...m];
          c[c.length - 1] = { role: "assistant", content: (e as Error).message, error: true };
          return c;
        });
      } finally {
        setBusy(false);
        taRef.current?.focus();
      }
    },
    [busy, jobId, model, effort]
  );

  const startNew = useCallback(() => {
    setMessages([]);
    setClosed(false);
    setIdleLeft(null);
  }, []);

  return (
    <div className="surface overflow-hidden">
      {/* header */}
      <div className="flex flex-wrap items-center gap-3 border-b border-line p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2.5">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line bg-surface-2 text-fg">
            <MessageSquareText size={16} />
          </span>
          <div className="min-w-0">
            <h3 className="font-display text-sm font-semibold text-fg">Chat with this scan</h3>
            <p className="truncate text-xs text-fg-subtle">
              Its own session, seeded with these findings · ask for fixes or priorities
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Select<string>
            value={model}
            onChange={pickModel}
            options={modelOptions}
            icon={<Cpu size={14} />}
            align="right"
          />
          <Select<string>
            value={effort ?? ""}
            onChange={(v) => setEffort(v || undefined)}
            options={effortOpts.length ? effortOpts : [{ value: "", label: "N/A" }]}
            disabled={!effortOpts.length}
            icon={<Gauge size={14} />}
            align="right"
          />
          {live && (
            <>
              <span
                className="hidden items-center gap-1 rounded-lg border border-line px-2 py-1.5 text-xs tabular-nums text-fg-subtle sm:flex"
                title="Session closes automatically after this much inactivity"
              >
                <Clock size={13} />
                {idleLeft !== null ? fmtClock(idleLeft) : fmtClock(idleSeconds)}
              </span>
              <button
                type="button"
                onClick={() => handleClose(false)}
                className="btn-ghost px-2.5 py-1.5 text-xs"
                aria-label="End chat session"
                title="End the session now"
              >
                <X size={14} /> End
              </button>
            </>
          )}
        </div>
      </div>

      {/* messages */}
      <div ref={listRef} className="max-h-[460px] min-h-[150px] overflow-y-auto p-4">
        {messages.length === 0 ? (
          <div className="grid place-items-center gap-4 py-8 text-center">
            <Sparkles size={22} className="text-fg-subtle" />
            <p className="max-w-sm text-sm text-fg-muted">
              Ask anything about this scan. The assistant sees its findings and answers in plain language.
            </p>
            <div className="flex max-w-lg flex-wrap justify-center gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => send(s)}
                  className="rounded-lg border border-line bg-surface px-3 py-2 text-xs text-fg-muted transition-colors hover:border-line-strong hover:bg-surface-2 hover:text-fg"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <AnimatePresence initial={false}>
              {messages.map((m, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25 }}
                  className={cn("flex", m.role === "user" ? "justify-end" : "justify-start")}
                >
                  <div
                    className={cn(
                      "max-w-[85%] rounded-xl px-3.5 py-2.5 text-sm leading-relaxed",
                      m.role === "user"
                        ? "bg-accent text-accent-fg"
                        : m.error
                          ? "border border-sev-high/30 bg-sev-high/10 text-fg"
                          : "border border-line bg-surface-2 text-fg"
                    )}
                  >
                    {m.pending ? (
                      <span className="flex items-center gap-2 text-fg-subtle">
                        <Spinner size={14} /> thinking…
                      </span>
                    ) : m.role === "assistant" ? (
                      <div className="prose-report text-sm [&_p]:my-1 [&_p:first-child]:mt-0 [&_p:last-child]:mb-0">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{m.content}</ReactMarkdown>
                      </div>
                    ) : (
                      m.content
                    )}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>

      {/* closed banner */}
      {closed && messages.length > 0 && (
        <div className="flex items-center justify-between gap-3 border-t border-line bg-surface-2/50 px-4 py-2.5 text-xs text-fg-subtle">
          <span>Session ended.</span>
          <button type="button" onClick={startNew} className="btn-ghost px-2.5 py-1 text-xs">
            New chat
          </button>
        </div>
      )}

      {/* composer */}
      <div className="border-t border-line p-3">
        <div className="flex items-end gap-2">
          <textarea
            ref={taRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send(input);
              }
            }}
            rows={1}
            placeholder="Ask about this scan…"
            className="max-h-32 min-h-[2.75rem] flex-1 resize-none rounded-lg border border-line bg-surface px-3.5 py-2.5 text-sm text-fg placeholder:text-fg-subtle outline-none transition focus:border-accent/60 focus:ring-2 focus:ring-accent/20"
          />
          <button
            type="button"
            onClick={() => send(input)}
            disabled={busy || !input.trim()}
            className="btn-primary h-[2.75rem] px-4"
            aria-label="Send"
          >
            {busy ? <Spinner size={16} /> : <Send size={16} />}
          </button>
        </div>
      </div>
    </div>
  );
}
