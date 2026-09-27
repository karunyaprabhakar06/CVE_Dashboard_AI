// NVD recent CVE feed (last 7 days by lastModified) + optional keyword sweep.
import { withCache, getCached, setCached } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";

function inferCategory(text) {
  const t = (text || "").toLowerCase();
  if (/linux kernel|kernel\b/.test(t)) return "linux-kernel";
  if (/openssh|ssh\b/.test(t)) return "linux-service";
  if (/apache|nginx|httpd/.test(t)) return "web-server";
  if (/openssl|libssl|gnutls/.test(t)) return "crypto-lib";
  if (/docker|kubernetes|containerd|k8s/.test(t)) return "container";
  if (/windows|microsoft/.test(t)) return "windows";
  if (/android|ios|macos/.test(t)) return "mobile-os";
  if (/cisco|fortinet|palo alto|juniper|router|firewall/.test(t)) return "network";
  if (/wordpress|joomla|drupal|php/.test(t)) return "cms";
  if (/sql injection|xss|csrf|rce|deserialization/.test(t)) return "web-app";
  return "general";
}

function severityFromCvss(score) {
  if (score == null) return "NONE";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

function mapItem(v) {
  const cve = v.cve ?? v;
  const id = cve.id;
  const desc =
    cve.descriptions?.find((d) => d.lang === "en")?.value ??
    cve.descriptions?.[0]?.value ??
    "";
  const metrics = cve.metrics ?? {};
  const m =
    metrics.cvssMetricV31?.[0] ??
    metrics.cvssMetricV30?.[0] ??
    metrics.cvssMetricV2?.[0];
  const cvss = m?.cvssData?.baseScore ?? null;
  const vector = m?.cvssData?.vectorString;
  const severity =
    m?.cvssData?.baseSeverity?.toUpperCase() ?? severityFromCvss(cvss);

  const cpe = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria;
  let vendor, product;
  if (cpe) {
    const parts = cpe.split(":");
    vendor = parts[3];
    product = parts[4];
  }

  return {
    id,
    description: desc,
    published: cve.published,
    modified: cve.lastModified,
    vulnStatus: cve.vulnStatus,
    cvss,
    cvssVector: vector,
    severity,
    vendor,
    product,
    references: (cve.references ?? []).map((r) => r.url).slice(0, 8),
    source: "NVD",
    category: inferCategory(`${desc} ${product ?? ""}`),
    tags: [vendor, product].filter(Boolean),
  };
}

async function callNvd(params) {
  const url = new URL(NVD);
  for (const [k, v] of Object.entries(params))
    url.searchParams.set(k, String(v));

  const headers = { Accept: "application/json", "User-Agent": "ZorroSOCGrid/0.1" };
  if (process.env.NVD_API_KEY) headers["apiKey"] = process.env.NVD_API_KEY;

  const res = await fetchWithTimeout(url, { headers });
  if (!res.ok) throw new Error(`NVD ${res.status}`);
  const json = await res.json();
  return {
    items: (json.vulnerabilities ?? []).map(mapItem),
    totalResults: json.totalResults ?? 0,
    resultsPerPage: json.resultsPerPage ?? 0,
    startIndex: json.startIndex ?? 0,
  };
}

/**
 * Fetch every CVE modified in [sinceIso, untilIso], paginated.
 * NVD enforces a maximum 120-day window per request and a 2000-record page.
 * With NVD_API_KEY: 50 req / 30s. Without: 5 req / 30s — so we sleep between
 * pages on the unauth path.
 */
export async function fetchNVDWindow(sinceIso, untilIso) {
  const hasKey = !!process.env.NVD_API_KEY;
  const PAGE = 2000;
  const SLEEP_MS = hasKey ? 250 : 6_500;
  const all = [];
  let startIndex = 0;
  for (;;) {
    let res;
    try {
      res = await callNvd({
        resultsPerPage: PAGE,
        startIndex,
        lastModStartDate: sinceIso,
        lastModEndDate: untilIso,
      });
    } catch (e) {
      // Bail on this slice rather than hanging the whole refresh
      console.warn(`[nvd] window page failed @${startIndex}:`, e?.message ?? e);
      break;
    }
    all.push(...res.items);
    const next = startIndex + (res.resultsPerPage || res.items.length);
    if (next >= res.totalResults || res.items.length === 0) break;
    startIndex = next;
    if (SLEEP_MS) await new Promise((r) => setTimeout(r, SLEEP_MS));
  }
  return all;
}

/**
 * Fetch every CVE *published* in the last `daysBack` days using NVD's
 * pubStartDate filter. This is required because lastModStartDate only catches
 * CVEs whose status changed; brand-new CVEs that are still in Awaiting /
 * Undergoing Analysis can sit for days without being modified, and would
 * otherwise be invisible in our feed.
 *
 * NVD's pubStartDate window is also capped at 120 days; we keep it small.
 * Note: small resultsPerPage values are buggy on this endpoint (NVD returns
 * resultsPerPage:0 even though totalResults>0). Letting the API choose the
 * page size avoids that quirk.
 */
export async function fetchNVDPublished(daysBack = 7) {
  const hasKey = !!process.env.NVD_API_KEY;
  const SLEEP_MS = hasKey ? 250 : 6_500;
  const end = new Date();
  const start = new Date(end.getTime() - 1000 * 60 * 60 * 24 * daysBack);
  const startIso = start.toISOString();
  const endIso = end.toISOString();
  const all = [];
  let startIndex = 0;
  for (;;) {
    let res;
    try {
      res = await callNvd({
        startIndex,
        pubStartDate: startIso,
        pubEndDate: endIso,
      });
    } catch (e) {
      console.warn(`[nvd] published page failed @${startIndex}:`, e?.message ?? e);
      break;
    }
    all.push(...res.items);
    const pageLen = res.resultsPerPage || res.items.length;
    const next = startIndex + pageLen;
    if (pageLen === 0 || next >= res.totalResults) break;
    startIndex = next;
    if (SLEEP_MS) await new Promise((r) => setTimeout(r, SLEEP_MS));
  }
  return all;
}

export async function fetchNVDRecent() {
  return withCache("nvd-recent", 150_000, async () => {
    const end = new Date();
    const start = new Date(end.getTime() - 1000 * 60 * 60 * 24 * 7);
    const r = await callNvd({
      resultsPerPage: 80,
      lastModStartDate: start.toISOString(),
      lastModEndDate: end.toISOString(),
    });
    return r.items;
  });
}

export async function fetchNVDLinuxKernel() {
  return withCache("nvd-linux", 150_000, async () => {
    const end = new Date();
    const start = new Date(end.getTime() - 1000 * 60 * 60 * 24 * 14);
    const r = await callNvd({
      resultsPerPage: 40,
      keywordSearch: "linux kernel",
      lastModStartDate: start.toISOString(),
      lastModEndDate: end.toISOString(),
    });
    return r.items;
  });
}

/**
 * Free-text keyword search over NVD. Returns up to `limit` records.
 * Used by the on-demand /api/search endpoint.
 */
export async function fetchNVDKeyword(query, limit = 25) {
  if (!query) return [];
  const r = await callNvd({
    resultsPerPage: Math.min(limit, 50),
    keywordSearch: query,
  });
  return r.items.slice(0, limit);
}

/**
 * Look up a single CVE by ID. Returns the mapped record or `null` if NVD has
 * no entry (reserved / not yet published). Cached 24h per ID.
 */
export async function fetchNVDByCveId(cveId) {
  if (!/^CVE-\d{4}-\d+$/.test(cveId)) return null;
  // Peek the cache. We deliberately do NOT use withCache here so transient
  // network failures aren't persisted for 24h (the comment below used to lie
  // — the previous implementation cached the {__error} sentinel and blocked
  // the id from ever resolving).
  const cacheKey = `nvd-detail:${cveId}`;
  const cached = await getCached(cacheKey);
  // Treat any leftover error sentinel (from older buggy code paths) as a
  // miss so we retry instead of being permanently poisoned for 24h.
  if (cached !== null && !(cached && typeof cached === "object" && cached.__error)) return cached;
  try {
    const r = await callNvd({ cveId });
    const value = r.items[0] ?? null;
    await setCached(cacheKey, value, 24 * 60 * 60_000);
    return value;
  } catch (e) {
    // Transient — do not poison the cache. Caller treats as "try again later".
    return { __error: String(e?.message ?? e) };
  }
}

