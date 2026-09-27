// On-demand CVE search used by /api/search (TopBar dropdown).
//
// Strategy:
//   1. If query is an exact CVE-ID -> hit NVD by ID, plus raw fetch of
//      nomi-sec & trickest PoC indexes for that ID.
//   2. Else (keyword) -> NVD keywordSearch + a simple substring scan of
//      the in-memory 60-day store as a fast local hit.
//   3. Enrich any results with EPSS in one batch call.
//   4. Upsert into the rolling store so subsequent /api/feed calls include
//      them and they survive until pruned.
import { fetchNVDByCveId, fetchNVDKeyword } from "./sources/nvd.mjs";
import { fetchEPSS } from "./sources/epss.mjs";
import { upsertExternalRecords, getAllRecords } from "./store.mjs";

const CVE_RE = /^CVE-\d{4}-\d+$/i;

const POC_RAW = {
  "nomi-sec":
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master",
  trickest: "https://raw.githubusercontent.com/trickest/cve/main",
};

async function fetchPocsForCveDirect(cveId) {
  const year = cveId.split("-")[1];
  const pocs = [];

  // nomi-sec: YYYY/CVE-YYYY-NNNN.json -> array of GH repo objects
  try {
    const r = await fetch(`${POC_RAW["nomi-sec"]}/${year}/${cveId}.json`);
    if (r.ok) {
      const arr = await r.json();
      for (const p of arr ?? []) {
        pocs.push({
          name: p.name,
          url: p.html_url,
          owner: p.owner?.login,
          stars: p.stargazers_count ?? 0,
          forks: p.forks_count ?? 0,
          createdAt: p.created_at,
          updatedAt: p.updated_at,
          description: p.description,
          source: "nomi-sec",
        });
      }
    }
  } catch {
    /* ignore */
  }

  // trickest: YYYY/CVE-YYYY-NNNN.md -> markdown with GitHub URLs
  try {
    const r = await fetch(`${POC_RAW.trickest}/${year}/${cveId}.md`);
    if (r.ok) {
      const md = await r.text();
      const urls = [
        ...new Set(
          [
            ...md.matchAll(
              /https:\/\/github\.com\/([\w.-]+\/[\w.-]+?)(?=[\s)\]"]|$)/gm
            ),
          ].map((m) => m[1])
        ),
      ].filter(
        (slug) =>
          !slug.startsWith("trickest/") &&
          !slug.startsWith("CVEProject/") &&
          slug.split("/").length === 2
      );
      const seen = new Set(pocs.map((p) => p.url));
      for (const slug of urls.slice(0, 12)) {
        const url = `https://github.com/${slug}`;
        if (seen.has(url)) continue;
        pocs.push({
          name: slug,
          url,
          owner: slug.split("/")[0],
          stars: 0,
          forks: 0,
          source: "trickest",
        });
      }
    }
  } catch {
    /* ignore */
  }

  return pocs;
}

async function enrichWithEpss(records) {
  if (!records.length) return;
  try {
    const epssMap = await fetchEPSS(records.map((r) => r.id));
    if (!epssMap || epssMap.__error) return;
    for (const r of records) {
      const e = epssMap[r.id];
      if (e && Number.isFinite(e.epss)) {
        r.epss = e.epss;
        r.epssPercentile = e.percentile;
        r.epssDate = e.date;
        r.epssSource = "FIRST.org";
      }
    }
  } catch {
    /* ignore */
  }
}

/**
 * Main search entry. Returns up to `limit` enriched CVERecord-shaped objects.
 */
export async function searchCves(query, limit = 15) {
  const q = (query ?? "").trim();
  if (!q) return { records: [], source: "empty" };

  const out = [];
  const seen = new Set();

  if (CVE_RE.test(q)) {
    const id = q.toUpperCase();
    let nvd = null;
    try {
      const v = await fetchNVDByCveId(id);
      if (v && !v.__error) nvd = v;
    } catch {
      /* ignore */
    }
    const pocs = await fetchPocsForCveDirect(id);
    const rec = nvd
      ? { ...nvd, pocs }
      : {
          id,
          description: `${id} is not yet published in NVD. ${
            pocs.length
              ? `${pocs.length} public PoC reference(s) found via curated indexes.`
              : "No public PoCs found via curated indexes either."
          }`,
          published: new Date(
            Date.UTC(Number(id.split("-")[1]), 0, 1)
          ).toISOString(),
          modified: new Date().toISOString(),
          cvss: null,
          severity: pocs.length ? "HIGH" : "NONE",
          source: pocs.length ? "POC-ONLY" : "NVD",
          category: "general",
          tags: pocs.length ? ["poc-leaked", "nvd-missing"] : ["reserved"],
          vulnStatus: "Reserved",
          pocs,
        };
    rec.exploits = rec.exploits ?? [];
    rec.inTheWild = rec.inTheWild ?? [];
    rec.nucleiTemplates = rec.nucleiTemplates ?? [];
    rec.exploitAvailable = (rec.pocs?.length ?? 0) > 0;
    out.push(rec);
    seen.add(rec.id);
  } else {
    // Keyword search: local store first (fast), then NVD live.
    const ql = q.toLowerCase();
    const local = await getAllRecords();
    const localHits = local
      .filter((r) => {
        const hay = `${r.id} ${r.description ?? ""} ${r.vendor ?? ""} ${
          r.product ?? ""
        } ${(r.tags ?? []).join(" ")}`.toLowerCase();
        return hay.includes(ql);
      })
      .sort(
        (a, b) => new Date(b.modified).getTime() - new Date(a.modified).getTime()
      )
      .slice(0, limit);
    for (const r of localHits) {
      out.push(r);
      seen.add(r.id);
    }
    if (out.length < limit) {
      try {
        const remote = await fetchNVDKeyword(q, limit);
        for (const r of remote) {
          if (seen.has(r.id)) continue;
          r.pocs = r.pocs ?? [];
          r.exploits = r.exploits ?? [];
          r.inTheWild = r.inTheWild ?? [];
          r.nucleiTemplates = r.nucleiTemplates ?? [];
          out.push(r);
          seen.add(r.id);
          if (out.length >= limit) break;
        }
      } catch {
        /* ignore */
      }
    }
  }

  await enrichWithEpss(out);

  // Persist into the rolling store so the in-panel table also gets them.
  try {
    await upsertExternalRecords(out);
  } catch {
    /* ignore */
  }

  return { records: out.slice(0, limit), source: CVE_RE.test(q) ? "cve-id" : "keyword" };
}
