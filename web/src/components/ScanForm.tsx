import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Play, Sparkles, ChevronDown, ShieldAlert, Plus, Trash2, KeyRound, Cpu, Gauge } from "lucide-react";
import type { ScanRequest, AuthIdentity, AuthAdapterType } from "../lib/types";
import { cn } from "../lib/ui";
import { Toggle, Spinner } from "./ui/Primitives";
import { Select } from "./ui/Select";
import { useBrainModels, effortOptionsFor, preferredEffort, FALLBACK_DEFAULT_MODEL } from "../lib/models";

const ADAPTER_TYPES: { value: AuthAdapterType; label: string }[] = [
  { value: "form", label: "Form login" },
  { value: "bearer", label: "Bearer token" },
  { value: "api_key", label: "API key" },
  { value: "session", label: "Session cookie" },
  { value: "token_exchange", label: "Token exchange" },
];

export default function ScanForm({
  onLaunch,
  onDemo,
  busy,
}: {
  onLaunch: (req: ScanRequest) => void;
  onDemo: () => void;
  busy: boolean;
}) {
  const [baseUrl, setBaseUrl] = useState("");
  const [specUrl, setSpecUrl] = useState("");
  const [description, setDescription] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [crawlUi, setCrawlUi] = useState(false);
  const [watchBrowser, setWatchBrowser] = useState(false);
  const [allowWrites, setAllowWrites] = useState(false);
  const [extraHosts, setExtraHosts] = useState("");
  const [maxRequests, setMaxRequests] = useState(400);
  const [identities, setIdentities] = useState<AuthIdentity[]>([]);
  const { modelOptions, variantsById, defaultModel, ready } = useBrainModels();
  const [model, setModel] = useState<string>(FALLBACK_DEFAULT_MODEL);
  const [effort, setEffort] = useState<string | undefined>("medium");
  const [err, setErr] = useState("");

  // Snap to the catalog default once it loads, and keep effort inside the
  // selected model's declared variants (undefined = model takes no effort).
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

  function submit(e: React.FormEvent) {
    e.preventDefault();
    let url = baseUrl.trim();
    if (!url) return setErr("Enter the URL of the app to test.");
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;
    try {
      new URL(url);
    } catch {
      return setErr("That doesn't look like a valid URL.");
    }
    setErr("");
    onLaunch({
      base_url: url,
      spec_url: specUrl.trim() || undefined,
      description: description.trim() || undefined,
      crawl_ui: crawlUi,
      watch_browser: watchBrowser && crawlUi,
      allow_writes: allowWrites,
      extra_hosts: extraHosts.trim() ? extraHosts.split(",").map((h) => h.trim()).filter(Boolean) : undefined,
      max_requests: maxRequests,
      auth_identities: identities.length ? identities : undefined,
      model,
      effort,
    });
  }

  function addIdentity() {
    setIdentities((p) => [...p, { type: "bearer", name: `role${p.length + 1}`, role: "user" }]);
  }
  function updateIdentity(i: number, patch: Partial<AuthIdentity>) {
    setIdentities((p) => p.map((id, idx) => (idx === i ? { ...id, ...patch } : id)));
  }
  function removeIdentity(i: number) {
    setIdentities((p) => p.filter((_, idx) => idx !== i));
  }

  return (
    <form onSubmit={submit} className="glass mx-auto w-full max-w-2xl p-6 sm:p-7">
      <div className="mb-5">
        <label className="label" htmlFor="base_url">
          App URL <span className="text-sev-critical">*</span>
        </label>
        <input
          id="base_url"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          placeholder="https://yourapp.com"
          className="input text-base"
          autoComplete="off"
          spellCheck={false}
        />
        <p className="mt-1.5 text-xs text-fg-subtle">
          That's all it needs. The spec, description and login below are optional.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="spec_url">
            OpenAPI / Swagger URL
          </label>
          <input
            id="spec_url"
            value={specUrl}
            onChange={(e) => setSpecUrl(e.target.value)}
            placeholder="auto-discovered if blank"
            className="input"
            spellCheck={false}
          />
        </div>
        <div>
          <label className="label" htmlFor="desc">
            What is the app?
          </label>
          <input
            id="desc"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="e.g. a notes app; users see only their own notes"
            className="input"
          />
        </div>
      </div>

      {/* Advanced */}
      <button
        type="button"
        onClick={() => setAdvanced((a) => !a)}
        aria-expanded={advanced}
        aria-controls="advanced-panel"
        className="mt-5 flex items-center gap-1.5 text-xs font-semibold text-fg-muted hover:text-fg"
      >
        <ChevronDown size={14} className={cn("transition-transform", advanced && "rotate-180")} />
        Advanced · auth, scope & safety
      </button>

      <AnimatePresence initial={false}>
        {advanced && (
          <motion.div
            id="advanced-panel"
            role="region"
            aria-label="Advanced scan options"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="overflow-hidden"
          >
            <div className="mt-4 space-y-4 rounded-xl border border-line bg-ink-800/40 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium text-fg">Crawl the UI</div>
                  <div className="text-xs text-fg-subtle">Explore pages & forms like a human QA</div>
                </div>
                <Toggle checked={crawlUi} onChange={setCrawlUi} label="Crawl the UI" />
              </div>
              {crawlUi && (
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-fg">Watch browser</div>
                    <div className="text-xs text-fg-subtle">Pop a visible Chrome window and watch the crawl live</div>
                  </div>
                  <Toggle checked={watchBrowser} onChange={setWatchBrowser} label="Watch browser" />
                </div>
              )}

              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-1.5 text-sm font-medium text-sev-high">
                    <ShieldAlert size={14} /> Allow write probes
                  </div>
                  <div className="text-xs text-fg-subtle">Mutating tests — staging / disposable targets only</div>
                </div>
                <Toggle checked={allowWrites} onChange={setAllowWrites} tone="danger" label="Allow write probes (staging only)" />
              </div>
              {allowWrites && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="rounded-lg border border-sev-high/30 bg-sev-high/10 p-2.5 text-xs text-fg"
                >
                  These probes create data, persist payloads and may modify records. Never run against production.
                </motion.div>
              )}

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="hosts">
                    Extra in-scope hosts
                  </label>
                  <input
                    id="hosts"
                    value={extraHosts}
                    onChange={(e) => setExtraHosts(e.target.value)}
                    placeholder="api.yourapp.com, auth.yourapp.com"
                    className="input"
                    spellCheck={false}
                  />
                </div>
                <div>
                  <label className="label" htmlFor="maxreq">
                    Request budget
                  </label>
                  <input
                    id="maxreq"
                    type="number"
                    min={50}
                    max={5000}
                    step={50}
                    value={maxRequests}
                    onChange={(e) => setMaxRequests(Number(e.target.value))}
                    className="input tnum"
                  />
                </div>
              </div>

              {/* Identities */}
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-sm font-medium text-fg">
                    <KeyRound size={14} className="text-brand-cyan" /> Test behind login
                  </div>
                  <button type="button" onClick={addIdentity} className="btn-ghost px-2 py-1 text-xs">
                    <Plus size={13} /> Add role
                  </button>
                </div>
                <div className="space-y-2">
                  {identities.map((id, i) => (
                    <IdentityRow
                      key={i}
                      id={id}
                      onChange={(p) => updateIdentity(i, p)}
                      onRemove={() => removeIdentity(i)}
                    />
                  ))}
                  {identities.length === 0 && (
                    <p className="text-xs text-fg-subtle">
                      Add bearer / API-key / form logins to test access control across roles.
                    </p>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* brain controls — model + reasoning effort for this scan */}
      <div className="mt-5 flex flex-wrap items-center gap-2">
        <span className="mr-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-fg-subtle">Brain</span>
        <Select<string>
          value={model}
          onChange={pickModel}
          label="Model"
          icon={<Cpu size={14} />}
          options={modelOptions}
        />
        <Select<string>
          value={effort ?? ""}
          onChange={(v) => setEffort(v || undefined)}
          label="Effort"
          icon={<Gauge size={14} />}
          options={effortOpts.length ? effortOpts : [{ value: "", label: "N/A" }]}
          disabled={!effortOpts.length}
        />
        {!effortOpts.length && (
          <span className="text-xs text-fg-subtle">this model takes no effort level</span>
        )}
      </div>

      {err && <p className="mt-4 text-sm text-sev-critical">{err}</p>}

      <div className="mt-6 flex flex-col gap-3 sm:flex-row">
        <button type="submit" disabled={busy} className="btn-primary flex-1 py-3 text-base">
          {busy ? <Spinner /> : <Play size={18} />}
          {busy ? "Scanning…" : "Run security scan"}
        </button>
        <button type="button" onClick={onDemo} disabled={busy} className="btn-secondary py-3">
          <Sparkles size={16} className="text-accent" /> Try a demo
        </button>
      </div>
    </form>
  );
}

function IdentityRow({
  id,
  onChange,
  onRemove,
}: {
  id: AuthIdentity;
  onChange: (p: Partial<AuthIdentity>) => void;
  onRemove: () => void;
}) {
  return (
    <div className="rounded-lg border border-line bg-ink-900/40 p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={id.name}
          onChange={(e) => onChange({ name: e.target.value })}
          placeholder="name"
          aria-label="identity name"
          className="input min-w-0 flex-1 px-2 py-1.5 text-xs sm:w-24 sm:flex-none"
        />
        <input
          value={id.role}
          onChange={(e) => onChange({ role: e.target.value })}
          placeholder="role"
          aria-label="identity role"
          className="input min-w-0 flex-1 px-2 py-1.5 text-xs sm:w-20 sm:flex-none"
        />
        <select
          value={id.type}
          onChange={(e) => onChange({ type: e.target.value as AuthAdapterType })}
          aria-label="auth type"
          className="input min-w-0 flex-1 basis-full px-2 py-1.5 text-xs sm:basis-auto"
        >
          {ADAPTER_TYPES.map((t) => (
            <option key={t.value} value={t.value} className="bg-ink-700">
              {t.label}
            </option>
          ))}
        </select>
        <button type="button" onClick={onRemove} className="btn-ghost min-h-[2.5rem] px-2.5 py-1.5" aria-label="Remove role">
          <Trash2 size={13} className="text-sev-critical" />
        </button>
      </div>
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        {id.type === "bearer" && (
          <input value={id.token || ""} onChange={(e) => onChange({ token: e.target.value })} placeholder="JWT / bearer token" className="input px-2 py-1.5 text-xs sm:col-span-2" spellCheck={false} />
        )}
        {id.type === "api_key" && (
          <>
            <input value={id.header || ""} onChange={(e) => onChange({ header: e.target.value })} placeholder="header (X-API-Key)" className="input px-2 py-1.5 text-xs" spellCheck={false} />
            <input value={id.key || ""} onChange={(e) => onChange({ key: e.target.value })} placeholder="key value" className="input px-2 py-1.5 text-xs" spellCheck={false} />
          </>
        )}
        {id.type === "form" && (
          <>
            <input value={id.username || ""} onChange={(e) => onChange({ username: e.target.value })} placeholder="email or username" className="input px-2 py-1.5 text-xs" />
            <input value={id.password || ""} onChange={(e) => onChange({ password: e.target.value })} placeholder="password" type="password" className="input px-2 py-1.5 text-xs" />
            <input value={id.login_url || ""} onChange={(e) => onChange({ login_url: e.target.value })} placeholder="login URL (optional)" className="input px-2 py-1.5 text-xs sm:col-span-2" spellCheck={false} />
          </>
        )}
        {id.type === "token_exchange" && (
          <>
            <input value={id.token_url || ""} onChange={(e) => onChange({ token_url: e.target.value })} placeholder="token URL (/api/login)" className="input px-2 py-1.5 text-xs" spellCheck={false} />
            <input value={id.token_path || ""} onChange={(e) => onChange({ token_path: e.target.value })} placeholder="token path (access_token)" className="input px-2 py-1.5 text-xs" spellCheck={false} />
            <input value={id.username || ""} onChange={(e) => onChange({ username: e.target.value })} placeholder="email or username" className="input px-2 py-1.5 text-xs" />
            <input value={id.password || ""} onChange={(e) => onChange({ password: e.target.value })} placeholder="password" type="password" className="input px-2 py-1.5 text-xs" />
          </>
        )}
        {id.type === "session" && (
          <input
            onChange={(e) => {
              const cookies: Record<string, string> = {};
              e.target.value.split(";").forEach((pair) => {
                const [k, ...v] = pair.split("=");
                if (k?.trim()) cookies[k.trim()] = v.join("=").trim();
              });
              onChange({ ...({ cookies } as Partial<AuthIdentity>) });
            }}
            placeholder="cookie: session=abc; other=xyz"
            className="input px-2 py-1.5 text-xs sm:col-span-2"
            spellCheck={false}
          />
        )}
      </div>
    </div>
  );
}
