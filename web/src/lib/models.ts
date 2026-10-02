import { useEffect, useState } from "react";
import type { SelectOption } from "../components/ui/Select";

export interface BrainModelEntry {
  id: string;
  name: string;
  family: string;
  variants: string[];
}

interface CatalogResponse {
  provider: string;
  default: string;
  models: BrainModelEntry[];
}

const API_BASE = import.meta.env.BASE_URL.replace(/\/$/, "") + "/api";

export const FALLBACK_DEFAULT_MODEL =
  "fireworks-ai/accounts/fireworks/routers/qwen-max-latest";

/** Brain models straight from the backend catalog (`GET /models`, parsed from
 *  `opencode models --verbose`) — never hardcoded. Falls back to the default
 *  model alone when the catalog is unreachable. */
export function useBrainModels() {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  useEffect(() => {
    let live = true;
    fetch(`${API_BASE}/models`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (live && d && Array.isArray(d.models)) setCatalog(d as CatalogResponse);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, []);
  const models: BrainModelEntry[] = catalog?.models?.length
    ? catalog.models
    : [{ id: FALLBACK_DEFAULT_MODEL, name: "Qwen Max", family: "", variants: [] }];
  const defaultModel = catalog?.default ?? FALLBACK_DEFAULT_MODEL;
  const variantsById: Record<string, string[]> = {};
  const modelOptions: SelectOption<string>[] = models.map((m) => {
    variantsById[m.id] = m.variants ?? [];
    return { value: m.id, label: m.name, hint: m.family || undefined };
  });
  return { modelOptions, variantsById, defaultModel, ready: catalog !== null };
}

/** Effort options for one model. Empty = the model takes no --variant. */
export function effortOptionsFor(variants: string[] | undefined): SelectOption<string>[] {
  return (variants ?? []).map((v) => ({
    value: v,
    label: v.charAt(0).toUpperCase() + v.slice(1),
  }));
}

/** Preferred effort for a model: medium when supported, else first variant. */
export function preferredEffort(variants: string[] | undefined): string | undefined {
  const vs = variants ?? [];
  if (vs.includes("medium")) return "medium";
  return vs[0];
}
