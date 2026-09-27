import { fetchNVDByCveId } from "./sources/nvd.mjs";
import { getCached } from "./cache.mjs";
import { fetchKEV } from "./sources/kev.mjs";
import { fetchOSVLinux } from "./sources/osv.mjs";
import { fetchGitHubPoCs } from "./sources/github-pocs.mjs";
import { fetchTrickestPoCs } from "./sources/trickest.mjs";
import { fetchExploitDB } from "./sources/exploitdb.mjs";
import { fetchInTheWild } from "./sources/inthewild.mjs";
import { fetchNucleiTemplates } from "./sources/nuclei.mjs";
import { fetchEPSS } from "./sources/epss.mjs";
import { fetchOssSecurityRecent, fetchOssSecuritySignals } from "./sources/oss-security.mjs";
import { fetchRedHatRecent } from "./sources/redhat.mjs";
import { fetchUbuntuUsnRecent } from "./sources/ubuntu-usn.mjs";
import { refreshStore, getAllRecords, RETENTION_DAYS } from "./store.mjs";

const SOURCE_PRIORITY = {
  NVD: 4,
  MITRE: 3.5,
  OSV: 3,
  KEV: 2.8,
  REDHAT: 2.6,
  "UBUNTU-USN": 2.4,
  "OSS-SEC": 2.2,
};

function isNvdPlaceholderRecord(r) {
  if (!r || r.source !== "NVD") return false;
  const d = String(r.description ?? "").toLowerCase();
  return d.includes("not yet published in nvd");
}

function pickPreferredRecord(a, b) {
  if (!a) return b;
  if (!b) return a;

  const aPlaceholder = isNvdPlaceholderRecord(a);
  const bPlaceholder = isNvdPlaceholderRecord(b);
  if (aPlaceholder !== bPlaceholder) return aPlaceholder ? b : a;

  const ap = SOURCE_PRIORITY[a.source] ?? 0;
  const bp = SOURCE_PRIORITY[b.source] ?? 0;
  return ap >= bp ? a : b;
}

function daysBetween(a, b) {
  return Math.abs(new Date(a).getTime() - new Date(b).getTime()) / 86_400_000;
}

/**
 * Heuristic zero-day score (0-100). Based on real signals:
 *  - KEV listed AND added within 14 days of CVE publication       +35
 *  - Public PoC exists AND PoC repo created before CVE published  +30
 *  - CVSS >= 9                                                    +15
 *  - In-the-wild exploitation event                                +20
 *  - vulnStatus == "Awaiting Analysis" or "Received"               +10
 *  - Reserved/empty description but has PoC                        +25
 *  - Cap at 100. Anything >= 60 is flagged.
 */
function zeroDayScore(r) {
  let s = 0;
  const pocs = r.pocs ?? [];
  const itw = r.inTheWild ?? [];
  const confirmedItw = itw.filter((e) => e?.confirmed === true).length;
  const otherItw = itw.length - confirmedItw;
  const hasPoc = pocs.length > 0;

  if (r.kev) {
    const gap = daysBetween(r.kev.dateAdded, r.published);
    if (gap <= 14) s += 35;
    else s += 15;
  }

  if (hasPoc) {
    const earliest = pocs
      .map((p) => p.createdAt)
      .filter(Boolean)
      .sort()[0];
    if (earliest && r.published && new Date(earliest) <= new Date(r.published))
      s += 30;
    else s += 12;
  }

  if ((r.cvss ?? 0) >= 9) s += 15;
  // Confirmed in-the-wild reports (inthewild.io) weight ~2x heavier than the
  // weaponised-scanner-template proxy.
  if (confirmedItw > 0) s += 25;
  else if (otherItw > 0) s += 12;
  if (["Awaiting Analysis", "Received"].includes(r.vulnStatus)) s += 10;
  if (hasPoc && (!r.description || r.description.length < 30)) s += 25;

  return Math.min(100, s);
}

export async function buildFeed() {
  const startedAt = Date.now();

  // 1) Refresh the rolling 60-day NVD store (delta if warm, full backfill if cold).
  let storeStats = null;
  let storeError = null;
  try {
    storeStats = await refreshStore();
  } catch (e) {
    storeError = String(e?.message ?? e);
  }
  const baseRecords = await getAllRecords();

  // 2) Pull all enrichment / supplementary sources in parallel.
  const results = await Promise.allSettled([
    fetchKEV(),
    fetchOSVLinux(),
    fetchGitHubPoCs(),
    fetchTrickestPoCs(),
    fetchExploitDB(),
    fetchInTheWild(),
    fetchNucleiTemplates(),
    fetchOssSecurityRecent(14),
    fetchOssSecuritySignals(21),
    fetchRedHatRecent(14),
    fetchUbuntuUsnRecent(14),
  ]);

  const names = [
    "kev",
    "osv-linux",
    "github-pocs",
    "trickest-pocs",
    "exploitdb",
    "inthewild",
    "nuclei-templates",
    "oss-security",
    "oss-security-signals",
    "redhat",
    "ubuntu-usn",
  ];
  const errors = {};
  if (storeError) errors["nvd-store"] = storeError;
  // Pull each settled result and coerce it to the expected shape (array | map).
  // Any rejection, an `{__error}` sentinel, or a value of the wrong shape
  // falls back to the supplied default so the rest of the pipeline can never
  // crash with "X is not iterable".
  const get = (i, fallback) => {
    const r = results[i];
    if (r.status !== "fulfilled") {
      errors[names[i]] = String(r.reason?.message ?? r.reason);
      return fallback;
    }
    const v = r.value;
    if (v && typeof v === "object" && v.__error) {
      errors[names[i]] = v.__error;
      return fallback;
    }
    if (v && typeof v === "object" && v.__degraded) {
      errors[names[i]] = v.__degraded;
    }
    if (Array.isArray(fallback) && !Array.isArray(v)) return fallback;
    if (!Array.isArray(fallback) && (v == null || typeof v !== "object")) return fallback;
    return v;
  };

  const kev = get(0, []);
  const osv = get(1, []);
  const pocMap = get(2, {});
  const trickestMap = get(3, {});
  const edbMap = get(4, {});
  const itwMap = get(5, {});
  const nucleiMap = get(6, {});
  const ossSec = get(7, []);
  const ossSignals = get(8, []);
  const redhat = get(9, []);
  const ubuntuUsn = get(10, []);
  // Merge the two PoC indices. Dedupe by URL, keep the entry with the
  // most metadata (GitHub repos from nomi-sec carry stars/forks/dates;
  // trickest fills in non-GitHub PoC hosts).
  const mergedPocs = {};
  const allCveIds = new Set([
    ...Object.keys(pocMap).filter((k) => k !== "__error"),
    ...Object.keys(trickestMap).filter((k) => k !== "__error"),
  ]);
  for (const cve of allCveIds) {
    const byUrl = new Map();
    for (const p of pocMap[cve] ?? []) byUrl.set(p.url, p);
    for (const p of trickestMap[cve] ?? []) {
      if (!byUrl.has(p.url)) byUrl.set(p.url, p);
    }
    mergedPocs[cve] = [...byUrl.values()].sort(
      (a, b) => (b.stars ?? 0) - (a.stars ?? 0)
    );
  }

  // Merge CVE records (dedup by id, prefer richer source)
  const merged = new Map();
  for (const r of [...baseRecords, ...osv, ...kev, ...ossSec, ...redhat, ...ubuntuUsn]) {
    const existing = merged.get(r.id);
    if (!existing) {
      merged.set(r.id, { ...r });
    } else {
      const preferred = pickPreferredRecord(existing, r);
      const other = preferred === existing ? r : existing;
      const winner = { ...other, ...preferred };
      // Preserve enrichment fields from both
      winner.exploited = existing.exploited || r.exploited;
      winner.kev = existing.kev ?? r.kev;
      merged.set(r.id, winner);
    }
  }

  // KEV-only IDs (not present in NVD/OSV merge) — keep them too
  for (const k of kev) {
    if (!merged.has(k.id)) merged.set(k.id, { ...k });
  }

  // Stand-alone PoC entries for CVEs we don't have anywhere else.
  // For each, try a real NVD lookup so we get the correct published date,
  // description, vendor, etc. If NVD has no record (CVE reserved or rejected),
  // fall back to an honest stub keyed off the CVE year + earliest PoC commit.
  const pocOnlyIds = [];
  for (const cveId of Object.keys(mergedPocs)) {
    if (!/^CVE-\d{4}-\d+$/.test(cveId)) continue;
    if (!merged.has(cveId)) pocOnlyIds.push(cveId);
  }

  // Limit concurrent NVD lookups so we don't hammer the public rate limit.
  // With NVD_API_KEY: 50 req / 30s. Without: 5 req / 30s.
  // Strategy: every PoC-only id whose NVD detail we've *already cached* gets
  // resolved instantly (no network). For ids not in cache, take a fresh batch
  // up to the cap — across successive refresh cycles every id eventually
  // gets resolved, instead of permanently re-stubbing the same first-N keys.
  const NVD_LOOKUP_CAP = process.env.NVD_API_KEY ? 100 : 8;
  const nvdDetails = new Map();
  const uncachedIds = [];
  for (const id of pocOnlyIds) {
    const hit = await getCached(`nvd-detail:${id}`);
    if (hit !== null) {
      if (hit && !hit.__error) nvdDetails.set(id, hit);
    } else {
      uncachedIds.push(id);
    }
  }
  const idsToLookup = uncachedIds.slice(0, NVD_LOOKUP_CAP);
  const lookupResults = await Promise.allSettled(
    idsToLookup.map((id) => fetchNVDByCveId(id))
  );
  for (let i = 0; i < idsToLookup.length; i++) {
    const res = lookupResults[i];
    if (res.status === "fulfilled" && res.value && !res.value.__error) {
      nvdDetails.set(idsToLookup[i], res.value);
    }
  }

  for (const cveId of pocOnlyIds) {
    const year = Number(cveId.split("-")[1]);
    const detail = nvdDetails.get(cveId);

    if (detail) {
      // Use the real NVD record but preserve the POC-ONLY source signal
      // by keeping the original source field as "NVD" (so date/desc are real)
      // — the PoC presence is already conveyed through r.pocs[].
      merged.set(cveId, { ...detail });
      continue;
    }

    // No NVD record. The "published" date should reflect when the CVE ID was
    // reserved (year encoded in the ID). The "modified" date can be the most
    // recent PoC activity. Never let a recent GitHub repo creation date
    // override a years-old CVE ID — that produced nonsense like a 2013 CVE
    // showing today as its publish date.
    const pocDates = (mergedPocs[cveId] ?? [])
      .map((p) => p.updatedAt || p.createdAt)
      .filter(Boolean)
      .sort();
    const yearFloor = new Date(Date.UTC(year, 0, 1)).toISOString();
    const latestPoc = pocDates[pocDates.length - 1];
    const modified =
      latestPoc && new Date(latestPoc).getTime() > new Date(yearFloor).getTime()
        ? latestPoc
        : yearFloor;

    // Multi-source enrichment fallback: NVD/MITRE have nothing for this id,
    // so synthesise the best description we can from PoC/Exploit-DB/Nuclei/ITW.
    const altSources = [];
    let altDescription = null;
    let altVendor = null;
    let altProduct = null;

    const topPoc = (mergedPocs[cveId] ?? [])[0];
    if (topPoc) {
      altSources.push({
        type: "github-poc",
        label: topPoc.owner && topPoc.name
          ? `${topPoc.owner}/${topPoc.name.replace(/^.*\//, "")}`
          : "GitHub PoC",
        url: topPoc.url,
        description: topPoc.description ?? null,
        stars: topPoc.stars ?? 0,
      });
      if (topPoc.description && topPoc.description.length > 15) {
        altDescription = topPoc.description.trim();
      }
    }

    const edb = (edbMap[cveId] ?? [])[0];
    if (edb) {
      altSources.push({
        type: "exploit-db",
        label: `Exploit-DB ${edb.edbId}`,
        url: edb.url,
        description: edb.title ?? null,
        platform: edb.platform ?? null,
      });
      if (!altDescription && edb.title) altDescription = edb.title.trim();
    }

    const nuc = (nucleiMap[cveId] ?? [])[0];
    if (nuc) {
      altSources.push({
        type: "nuclei",
        label: `Nuclei: ${nuc.name ?? nuc.templateId}`,
        url: nuc.url ?? null,
        description: nuc.description ?? nuc.name ?? null,
        severity: nuc.severity ?? null,
      });
      if (!altDescription && nuc.description) altDescription = nuc.description.trim();
    }

    const itw = (itwMap[cveId] ?? [])[0];
    if (itw) {
      altSources.push({
        type: "in-the-wild",
        label: `inthewild.io${itw.source ? ` · ${itw.source}` : ""}`,
        url: itw.referenceURL ?? null,
      });
    }

    const sourceLabels = altSources.map((s) => s.label).join(", ");
    const banner = altSources.length
      ? `⚠️ Not yet published in NVD or MITRE — details sourced from alternate references: ${sourceLabels}.`
      : `${cveId} is referenced by a public proof-of-concept on GitHub / trickest but does not yet appear in NVD or the MITRE CVE list. The identifier may still be pending CNA assignment, or the PoC author may be tracking it ahead of formal disclosure.`;
    const description = altDescription
      ? `${banner}\n\n${altDescription}`
      : banner;

    merged.set(cveId, {
      id: cveId,
      description,
      published: yearFloor,
      modified,
      cvss: null,
      severity: "HIGH",
      source: "POC-ONLY",
      category: "general",
      tags: ["poc-leaked", "nvd-missing", ...(altSources.length ? ["alt-sourced"] : [])],
      vulnStatus: "Reserved",
      vendor: altVendor,
      product: altProduct,
      enrichmentSources: altSources,
    });
  }

  // Resolve REAL EPSS, but cap the lookup to the most-relevant subset so we
  // don't fire ~1.5k FIRST.org requests every refresh when the rolling store
  // holds 100k+ CVEs. Pick the freshest + highest-impact records first; the
  // rest keep the heuristic EPSS until they enter the top-N window.
  const EPSS_CAP = 5000;
  const sevWeight = (s) =>
    s === "CRITICAL" ? 4 : s === "HIGH" ? 3 : s === "MEDIUM" ? 2 : s === "LOW" ? 1 : 0;
  const epssTargets = [...merged.values()]
    .sort((a, b) => {
      const sa = sevWeight(a.severity) + (a.exploited ? 2 : 0);
      const sb = sevWeight(b.severity) + (b.exploited ? 2 : 0);
      if (sa !== sb) return sb - sa;
      return new Date(b.modified ?? 0).getTime() - new Date(a.modified ?? 0).getTime();
    })
    .slice(0, EPSS_CAP)
    .map((r) => r.id);

  let epssMap = {};
  try {
    const r = await fetchEPSS(epssTargets);
    if (r && r.__error) errors["epss"] = r.__error;
    else epssMap = r || {};
  } catch (e) {
    errors["epss"] = String(e?.message ?? e);
  }

  // Enrich every record with PoCs / exploits / ITW / real EPSS / zeroDayScore
  const records = [];
  for (const r of merged.values()) {
    r.pocs = mergedPocs[r.id] ?? [];
    r.exploits = edbMap[r.id] ?? [];
    r.inTheWild = (itwMap[r.id] ?? []).filter((e) => e && typeof e === "object");
    r.nucleiTemplates = nucleiMap[r.id] ?? [];
    // Confirmed exploitation = KEV listing OR a real inthewild.io report
    // (nuclei-templates alone is a "scanner exists" signal, not a confirmed
    // exploitation event).
    r.confirmedExploited =
      !!r.exploited || r.inTheWild.some((e) => e?.confirmed === true);
    r.exploitAvailable =
      r.pocs.length > 0 ||
      r.exploits.length > 0 ||
      r.nucleiTemplates.length > 0;

    const epss = epssMap[r.id];
    if (epss && Number.isFinite(epss.epss)) {
      r.epss = epss.epss;
      r.epssPercentile = epss.percentile;
      r.epssDate = epss.date;
      r.epssSource = "FIRST.org";
    } else {
      // Fallback heuristic only when FIRST has no entry (reserved / very new).
      r.epss = Math.min(
        0.99,
        Math.max(
          0.01,
          (r.cvss ?? 5) / 12 +
            (r.exploited ? 0.2 : 0) +
            (r.pocs.length > 0 ? 0.1 : 0) +
            (r.inTheWild.length > 0 ? 0.15 : 0)
        )
      );
      r.epssSource = "heuristic";
    }

    r.zeroDayScore = zeroDayScore(r);
    r.isZeroDay = r.zeroDayScore >= 60;

    records.push(r);
  }

  records.sort(
    (a, b) => new Date(b.modified).getTime() - new Date(a.modified).getTime()
  );

  return {
    records,
    ossMailing: ossSignals,
    fetchedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    errors,
    store: {
      retentionDays: RETENTION_DAYS,
      total: storeStats?.total ?? baseRecords.length,
      lastRefreshAt: storeStats?.lastRefreshAt ?? null,
      pruned: storeStats?.pruned ?? 0,
      added: storeStats?.added ?? 0,
      updated: storeStats?.updated ?? 0,
    },
    counts: {
      total: records.length,
      pocTracked: records.filter((r) => r.pocs.length > 0).length,
      exploitDb: records.filter((r) => r.exploits.length > 0).length,
      inTheWild: records.filter((r) => r.inTheWild.length > 0).length,
      inTheWildConfirmed: records.filter((r) =>
        r.inTheWild.some((e) => e?.confirmed === true)
      ).length,
      confirmedExploited: records.filter((r) => r.confirmedExploited).length,
      nucleiTemplates: records.filter((r) => r.nucleiTemplates.length > 0).length,
      zeroDay: records.filter((r) => r.isZeroDay).length,
      kev: records.filter((r) => r.exploited).length,
      epssReal: records.filter((r) => r.epssSource === "FIRST.org").length,
    },
  };
}
