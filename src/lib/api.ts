import type {
  AIAnalysisResult,
  CVERecord,
  FeedCounts,
  OllamaModel,
  OssMailingSignal,
} from "./types";
import { getAuthHeaders } from "./auth";

export interface AggregateResult {
  records: CVERecord[];
  ossMailing: OssMailingSignal[];
  errors: string[];
  fetchedAt: string | null;
  counts?: FeedCounts;
  backendOnline: boolean;
  building?: boolean;
}

export interface SearchResult {
  records: CVERecord[];
  source: "cve-id" | "keyword" | "empty";
}

/**
 * Live search against the backend's /api/search endpoint. Used by the
 * TopBar global search. Returns enriched CVE records (NVD + PoCs + EPSS)
 * regardless of whether they are in the rolling 60-day store yet.
 */
export async function searchRemote(
  query: string,
  limit = 12,
  signal?: AbortSignal
): Promise<SearchResult> {
  const q = query.trim();
  if (!q) return { records: [], source: "empty" };
  const url = `/api/search?q=${encodeURIComponent(q)}&limit=${limit}`;
  const res = await fetch(url, { signal, headers: { Accept: "application/json", ...getAuthHeaders() } });
  if (!res.ok) throw new Error(`search ${res.status}`);
  const data = await res.json();
  return {
    records: data.records ?? [],
    source: data.source ?? "keyword",
  };
}

export async function listOllamaModels(): Promise<string[]> {
  const res = await fetch("/api/ai/models", {
    headers: { Accept: "application/json", ...getAuthHeaders() },
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error ?? "Unable to list Ollama models");
  }
  const data = await res.json();
  return Array.isArray(data.models) ? data.models : [];
}

export async function askAiAboutCve(options: {
  cve: CVERecord;
  question?: string;
  model?: string;
}): Promise<AIAnalysisResult> {
  const payload = {
    cveId: options.cve.id,
    model: options.model,
    question: options.question ?? "Explain this CVE for a security operator in plain English.",
    record: options.cve,
  };
  const res = await fetch("/api/ai/explain", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...getAuthHeaders(),
    },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error ?? "AI analysis failed");
  }
  return {
    model: data.model ?? options.model ?? "local model",
    cveId: data.cveId ?? options.cve.id,
    response: data.response ?? "No response returned.",
    generatedAt: data.generatedAt ?? new Date().toISOString(),
  };
}

const NVD_BASE = "/api/nvd/rest/json/cves/2.0";
const OSV_BASE = "/api/osv/v1";
const KEV_URL =
  "/api/kev/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/**
 * Primary path: ZorroSOC Grid backend (server/index.mjs).
 * The backend correlates NVD + OSV + CISA KEV + GitHub PoCs + Exploit-DB +
 * inthewild.io and computes a zero-day score per CVE.
 *
 * If the backend isn't running, we fall back to a CORS-friendly browser-only
 * fetch (NVD + OSV + KEV). PoCs / Exploit-DB / 0-day scoring will be empty
 * in that mode because those sources can't be reached from a browser.
 */
export async function fetchAllSources(): Promise<AggregateResult> {
  try {
    const res = await fetch("/api/feed", {
      headers: { Accept: "application/json", ...getAuthHeaders() },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const data = await res.json();
      const errors = Object.entries(data.errors ?? {}).map(
        ([k, v]) => `${k}: ${v}`
      );
      return {
        records: data.records ?? [],
        ossMailing: data.ossMailing ?? [],
        errors,
        fetchedAt: data.fetchedAt ?? null,
        counts: data.counts,
        backendOnline: true,
        building: data.building ?? false,
      };
    }
  } catch {
    /* fall through to browser-only path */
  }
  return fetchBrowserFallback();
}

// -------- Browser-only fallback (no PoCs / no Exploit-DB) ----------

function severityFromCvss(score: number | null) {
  if (score == null) return "NONE" as const;
  if (score >= 9) return "CRITICAL" as const;
  if (score >= 7) return "HIGH" as const;
  if (score >= 4) return "MEDIUM" as const;
  if (score > 0) return "LOW" as const;
  return "NONE" as const;
}

function inferCategory(text: string): string {
  const t = text.toLowerCase();
  if (/linux kernel|kernel\b/.test(t)) return "linux-kernel";
  if (/openssh|ssh\b/.test(t)) return "linux-service";
  if (/apache|nginx|httpd/.test(t)) return "web-server";
  if (/openssl|libssl|gnutls/.test(t)) return "crypto-lib";
  if (/docker|kubernetes|containerd|k8s/.test(t)) return "container";
  if (/windows|microsoft/.test(t)) return "windows";
  if (/cisco|fortinet|palo alto|juniper|router|firewall/.test(t)) return "network";
  return "general";
}

function nvdMap(v: any): CVERecord {
  const cve = v.cve ?? v;
  const desc =
    cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "";
  const m =
    cve.metrics?.cvssMetricV31?.[0] ??
    cve.metrics?.cvssMetricV30?.[0] ??
    cve.metrics?.cvssMetricV2?.[0];
  const cvss = m?.cvssData?.baseScore ?? null;
  const cpe = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria as
    | string
    | undefined;
  const parts = cpe ? cpe.split(":") : [];
  return {
    id: cve.id,
    description: desc,
    published: cve.published,
    modified: cve.lastModified,
    cvss,
    cvssVector: m?.cvssData?.vectorString,
    severity:
      (m?.cvssData?.baseSeverity?.toUpperCase() as any) ?? severityFromCvss(cvss),
    vendor: parts[3],
    product: parts[4],
    references: (cve.references ?? []).map((r: any) => r.url).slice(0, 6),
    source: "NVD",
    category: inferCategory(`${desc} ${parts[4] ?? ""}`),
    tags: [parts[3], parts[4]].filter(Boolean) as string[],
    pocs: [],
    exploits: [],
    inTheWild: [],
  };
}

async function fetchBrowserFallback(): Promise<AggregateResult> {
  const errors: string[] = [
    "backend offline — PoC / Exploit-DB / ITW unavailable. Run `npm run dev:server`.",
  ];
  const records: CVERecord[] = [];

  try {
    const end = new Date();
    const start = new Date(end.getTime() - 1000 * 60 * 60 * 24 * 7);
    const url = `${NVD_BASE}?resultsPerPage=60&lastModStartDate=${start.toISOString()}&lastModEndDate=${end.toISOString()}`;
    const r = await fetch(url);
    if (r.ok) {
      const j = await r.json();
      records.push(...(j.vulnerabilities ?? []).map(nvdMap));
    }
  } catch (e: any) {
    errors.push("NVD: " + (e?.message ?? e));
  }

  try {
    const r = await fetch(KEV_URL);
    if (r.ok) {
      const j = await r.json();
      const kevIds = new Set<string>(
        (j.vulnerabilities ?? []).map((k: any) => k.cveID)
      );
      for (const rec of records) {
        if (kevIds.has(rec.id)) rec.exploited = true;
      }
    }
  } catch (e: any) {
    errors.push("KEV: " + (e?.message ?? e));
  }

  try {
    const r = await fetch(`${OSV_BASE}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: { ecosystem: "Ubuntu:22.04" } }),
    });
    if (r.ok) {
      const j = await r.json();
      for (const v of (j.vulns ?? []).slice(0, 40)) {
        const s = v.severity?.[0]?.score;
        const score = s ? parseFloat(s) : null;
        records.push({
          id: v.id,
          description: v.summary ?? v.details ?? "",
          published: v.published ?? new Date().toISOString(),
          modified: v.modified ?? v.published ?? new Date().toISOString(),
          cvss: score,
          severity: severityFromCvss(score),
          source: "OSV",
          category: inferCategory(v.summary ?? ""),
          references: (v.references ?? []).map((x: any) => x.url).slice(0, 5),
          pocs: [],
          exploits: [],
          inTheWild: [],
        });
      }
    }
  } catch (e: any) {
    errors.push("OSV: " + (e?.message ?? e));
  }

  for (const r of records) {
    r.epss = r.epss ?? Math.min(0.99, Math.max(0.01, (r.cvss ?? 5) / 12));
    r.exploitAvailable = false;
    r.zeroDayScore = 0;
    r.isZeroDay = false;
  }
  records.sort(
    (a, b) => new Date(b.modified).getTime() - new Date(a.modified).getTime()
  );

  return {
    records,
    ossMailing: [],
    errors,
    fetchedAt: new Date().toISOString(),
    backendOnline: false,
  };
}
