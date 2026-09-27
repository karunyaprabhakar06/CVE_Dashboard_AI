// MITRE CVE.org fallback via the official CVE List V5 GitHub mirror.
//
// Why: NVD frequently returns `resultsPerPage:0` with a non-zero totalResults,
// effectively withholding the payload for newly-published CVEs (observed on
// CVE-2026-9277 among many). The CVE List V5 repo is the authoritative source
// MITRE publishes itself; it updates every ~7 minutes and includes a
// `deltaLog.json` covering the last ~30 days, plus per-CVE JSON files.
//
// Endpoints used (no auth required):
//   - https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json
//   - <githubLink>  (per-record JSON in the V5 schema)

import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const DELTA_LOG =
  "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json";
const UA = { "User-Agent": "ZorroSOCGrid/0.1", Accept: "application/json" };

function severityFromCvss(score) {
  if (score == null) return "NONE";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

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

function pickCvss(cna) {
  const metrics = cna?.metrics ?? [];
  for (const m of metrics) {
    const c = m.cvssV4_0 ?? m.cvssV3_1 ?? m.cvssV3_0 ?? m.cvssV2_0;
    if (c?.baseScore != null) {
      return {
        score: c.baseScore,
        vector: c.vectorString,
        sev: (c.baseSeverity || "").toUpperCase(),
      };
    }
  }
  return { score: null, vector: undefined, sev: "" };
}

function mapV5Record(raw) {
  const meta = raw?.cveMetadata ?? {};
  const cna = raw?.containers?.cna ?? {};
  const id = meta.cveId;
  if (!id) return null;
  if (meta.state && meta.state !== "PUBLISHED") return null;
  const desc =
    cna?.descriptions?.find((d) => d.lang?.startsWith("en"))?.value ??
    cna?.descriptions?.[0]?.value ??
    "";
  const { score, vector, sev } = pickCvss(cna);
  const severity = sev || severityFromCvss(score);
  const affected = cna?.affected?.[0] ?? {};
  const vendor = affected.vendor;
  const product = affected.product;
  const references = (cna?.references ?? [])
    .map((r) => r.url)
    .filter(Boolean)
    .slice(0, 8);
  const assigner = meta.assignerShortName;
  return {
    id,
    description: desc,
    published: meta.datePublished,
    modified: meta.dateUpdated ?? meta.datePublished,
    vulnStatus: meta.state || "PUBLISHED",
    cvss: score,
    cvssVector: vector,
    severity,
    vendor,
    product,
    references,
    source: "MITRE",
    category: inferCategory(`${desc} ${product ?? ""}`),
    tags: [
      vendor,
      product,
      assigner ? `assigner:${assigner}` : null,
      "mitre-direct",
    ].filter(Boolean),
  };
}

async function fetchJson(url, timeoutMs = 6_000) {
  const res = await fetchWithTimeout(url, { headers: UA }, timeoutMs);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * Walk deltaLog.json and return entries whose `fetchTime` is within the last
 * `daysBack` days. Each entry has `new` and `updated` arrays of
 * { cveId, githubLink, dateUpdated }.
 */
async function listChangedRecords(daysBack = 7) {
  let log;
  try {
    log = await fetchJson(DELTA_LOG);
  } catch (e) {
    console.warn("[mitre] deltaLog fetch failed:", e?.message ?? e);
    return [];
  }
  if (!Array.isArray(log)) return [];
  const cutoff = Date.now() - daysBack * 86_400_000;
  const seen = new Map(); // cveId -> {cveId, githubLink, dateUpdated}
  for (const entry of log) {
    const t = new Date(entry?.fetchTime ?? 0).getTime();
    if (!Number.isFinite(t) || t < cutoff) continue;
    for (const arr of [entry.new ?? [], entry.updated ?? []]) {
      for (const r of arr) {
        if (!r?.cveId || !r?.githubLink) continue;
        const prev = seen.get(r.cveId);
        if (
          !prev ||
          new Date(r.dateUpdated ?? 0) > new Date(prev.dateUpdated ?? 0)
        ) {
          seen.set(r.cveId, r);
        }
      }
    }
  }
  return [...seen.values()];
}

// Hard cap: never fetch more than this many individual records per call.
// The deltaLog can list thousands of entries; without a cap this becomes
// hours of sequential GitHub raw fetches.
const MITRE_ENTRY_CAP = 300;

async function fetchRecordsForEntries(entries, { concurrency = 8, excludeIds } = {}) {
  let targets = excludeIds
    ? entries.filter((e) => !excludeIds.has(e.cveId))
    : entries;
  if (targets.length > MITRE_ENTRY_CAP) {
    console.log(`[mitre] capping ${targets.length} entries to ${MITRE_ENTRY_CAP}`);
    targets = targets.slice(0, MITRE_ENTRY_CAP);
  }
  const out = [];
  let i = 0;
  async function worker() {
    while (i < targets.length) {
      const idx = i++;
      const e = targets[idx];
      try {
        const raw = await fetchJson(e.githubLink, 6_000);
        const rec = mapV5Record(raw);
        if (rec) out.push(rec);
      } catch {
        // ignore individual failures
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return out;
}

/**
 * Public: pull every CVE that MITRE recorded as new/updated in the last
 * `daysBack` days. Pass `excludeIds` (Set of cveIds already in the store)
 * to limit work to the gap. Returns an array of internal CVERecord objects
 * with source="MITRE".
 */
export async function fetchMITRERecent(daysBack = 7, { excludeIds } = {}) {
  const entries = await listChangedRecords(daysBack);
  if (!entries.length) return [];
  const records = await fetchRecordsForEntries(entries, { excludeIds });
  return records;
}
