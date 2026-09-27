// trickest/cve — a curated CVE -> PoC URL index, sister project to
// nomi-sec/PoC-in-GitHub. Different coverage (often includes ExploitDB,
// PacketStorm, vendor advisories, and non-GitHub PoC hosts) so merging both
// gives substantially richer PoC visibility.
//
// Structure: github.com/trickest/cve/{YYYY}/CVE-YYYY-NNNN.json
// File body: { "cve": "CVE-…", "poc": ["https://…", "https://…"] }
//
// We pull recent commits to detect newly-touched files, then fetch raw JSON.
import { withCache } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const REPO = "trickest/cve";
const COMMITS_URL = `https://api.github.com/repos/${REPO}/commits?per_page=100`;
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/main`;

function ghHeaders() {
  const h = {
    Accept: "application/vnd.github+json",
    "User-Agent": "ZorroSOCGrid/0.1",
  };
  if (process.env.GITHUB_TOKEN)
    h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

async function fetchRecentCvePaths() {
  let resolvedHeaders = ghHeaders();
  let res = await fetchWithTimeout(COMMITS_URL, { headers: resolvedHeaders });
  if (res.status === 401) {
    console.warn("[trickest] GITHUB_TOKEN rejected (401) — retrying without auth");
    resolvedHeaders = { Accept: "application/vnd.github+json", "User-Agent": "ZorroSOCGrid/0.1" };
    res = await fetchWithTimeout(COMMITS_URL, { headers: resolvedHeaders });
  }
  if (!res.ok) throw new Error(`GH commits ${res.status}`);
  const commits = await res.json();
  const paths = new Set();

  // Cap at 10 commits (was 20). Each commit on a busy repo can modify
  // hundreds of files; 10 commits is plenty for recent PoC coverage.
  await Promise.all(
    commits.slice(0, 10).map(async (c) => {
      try {
        const d = await fetchWithTimeout(
          `https://api.github.com/repos/${REPO}/commits/${c.sha}`,
          { headers: resolvedHeaders }
        );
        if (!d.ok) return;
        const json = await d.json();
        for (const f of json.files ?? []) {
          if (/^\d{4}\/CVE-\d{4}-\d+\.json$/.test(f.filename))
            paths.add(f.filename);
        }
      } catch {
        /* ignore */
      }
    })
  );

  // Hard cap to prevent unbounded raw-file fetches.
  return Array.from(paths).slice(0, 300);
}

function nameFromUrl(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    if (u.hostname === "github.com" && parts.length >= 2) {
      return { owner: parts[0], name: parts[1] };
    }
    return { owner: u.hostname.replace(/^www\./, ""), name: parts.pop() ?? u.hostname };
  } catch {
    return { owner: "external", name: url.slice(0, 60) };
  }
}

async function fetchPocFile(path) {
  const res = await fetchWithTimeout(`${RAW_BASE}/${path}`);
  if (!res.ok) return null;
  try {
    const data = await res.json();
    const cveId = data.cve ?? path.split("/").pop().replace(".json", "");
    const urls = Array.isArray(data.poc) ? data.poc : [];
    return {
      cveId,
      pocs: urls.map((u) => {
        const { owner, name } = nameFromUrl(u);
        return {
          name,
          url: u,
          owner,
          stars: 0,
          forks: 0,
          source: "trickest",
        };
      }),
    };
  } catch {
    return null;
  }
}

/**
 * Returns Map<cveId, pocEntry[]> from trickest/cve. Cached 10m.
 */
export async function fetchTrickestPoCs() {
  return withCache("trickest-pocs", 150_000, async () => {
    try {
      const paths = await fetchRecentCvePaths();
      // Bounded concurrency pool (20) instead of unbounded Promise.all.
      const results = [];
      let cursor = 0;
      async function worker() {
        while (cursor < paths.length) {
          const i = cursor++;
          const r = await fetchPocFile(paths[i]);
          if (r) results.push(r);
        }
      }
      await Promise.all(Array.from({ length: 20 }, worker));
      const map = {};
      for (const e of results) {
        map[e.cveId] = e.pocs;
      }
      return map;
    } catch (e) {
      return { __error: String(e?.message ?? e) };
    }
  });
}
