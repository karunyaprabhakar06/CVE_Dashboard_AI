// nomi-sec/PoC-in-GitHub is a community-maintained index that maps
// CVE-IDs -> array of GitHub PoC repositories (name, url, stars, created/updated).
//
// PRIMARY path:   GitHub API recent commits (best, but rate-limited to 60/hr
//                 without GITHUB_TOKEN -> set the env var).
// FALLBACK path:  trickest/cve mirror publishes one markdown file per year
//                 listing every CVE-XXXX-NNNN that has a PoC, served from
//                 raw.githubusercontent.com which has no API rate limit.
import { withCache, getCached, setCached } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const REPO = "nomi-sec/PoC-in-GitHub";
const COMMITS_URL = `https://api.github.com/repos/${REPO}/commits?per_page=100`;
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/master`;
const TRICKEST_BASE = "https://raw.githubusercontent.com/trickest/cve/main";

function ghHeaders() {
  const h = {
    Accept: "application/vnd.github+json",
    "User-Agent": "ZorroSOCGrid/0.1",
  };
  if (process.env.GITHUB_TOKEN)
    h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

// undici's fetch throws a generic TypeError("fetch failed") and tucks the
// real network error onto `.cause`. Unwrap it so partial-error logs are
// actually actionable.
function describeFetchError(e) {
  const cause = e?.cause;
  if (cause) {
    const code = cause.code ? `${cause.code} ` : "";
    return `${code}${cause.message ?? cause}`.trim();
  }
  return String(e?.message ?? e);
}

async function fetchWithRetry(url, init = {}, tries = 3) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      return await fetchWithTimeout(url, {
        ...init,
      }, 15_000);
    } catch (e) {
      lastErr = e;
      // Backoff: 250ms, 750ms
      await new Promise((r) => setTimeout(r, 250 * (i + 1) ** 2));
    }
  }
  throw lastErr;
}

async function fetchRecentCvePaths() {
  // Resolve which headers work: try with token, fall back to unauthed on 401.
  // All commit detail calls in this function reuse the same resolved headers
  // so they don't silently 401 after the initial retry succeeded.
  let resolvedHeaders = ghHeaders();
  let res = await fetchWithRetry(COMMITS_URL, { headers: resolvedHeaders });
  if (res.status === 401) {
    console.warn("[github-pocs] GITHUB_TOKEN rejected (401) — retrying without auth");
    resolvedHeaders = { Accept: "application/vnd.github+json", "User-Agent": "ZorroSOCGrid/0.1" };
    res = await fetchWithRetry(COMMITS_URL, { headers: resolvedHeaders });
  }
  if (!res.ok) {
    if (res.status === 403 || res.status === 429) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      throw new Error(
        `GH commits ${res.status} (rate-limit, remaining=${remaining ?? "?"})`
      );
    }
    throw new Error(`GH commits ${res.status}`);
  }
  const commits = await res.json();
  const paths = new Set();

  // Fetch detail for the 10 most-recent commits (was 25 — busy repos can
  // have 100s of files per commit, making the path set explode).
  await Promise.all(
    commits.slice(0, 10).map(async (c) => {
      try {
        const d = await fetchWithRetry(
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

  // Hard cap: never fire more than 300 raw-file fetches per refresh.
  return Array.from(paths).slice(0, 300);
}

async function fetchPocFile(path) {
  try {
    const res = await fetchWithRetry(`${RAW_BASE}/${path}`);
    if (!res.ok) return null;
    const arr = await res.json();
    const cveId = path.split("/").pop().replace(".json", "");
    return {
      cveId,
      pocs: (arr ?? []).map((p) => ({
        name: p.name,
        url: p.html_url,
        owner: p.owner?.login,
        stars: p.stargazers_count ?? 0,
        forks: p.forks_count ?? 0,
        createdAt: p.created_at,
        updatedAt: p.updated_at,
        description: p.description,
      })),
    };
  } catch {
    return null;
  }
}

/**
 * Fallback path that never touches the GitHub REST API (so it survives
 * rate-limiting). Chain:
 *   1. atom feed lists the most-recent commits to trickest/cve.
 *   2. each commit's .patch URL on github.com (NOT api.github.com) lists every
 *      CVE-YYYY-NNNN.md file modified in that commit.
 *   3. each .md is fetched from raw.githubusercontent.com -- no rate limit --
 *      and grep'd for github.com/owner/repo PoC URLs.
 */
async function fetchTrickestFallback() {
  const ATOM = "https://github.com/trickest/cve/commits/main.atom";
  const RAW = "https://raw.githubusercontent.com/trickest/cve/main";

  const ua = { "User-Agent": "ZorroSOCGrid/0.1" };

  // (1) atom feed -> recent commit SHAs
  const atomRes = await fetchWithTimeout(ATOM, { headers: ua });
  if (!atomRes.ok) throw new Error(`trickest atom ${atomRes.status}`);
  const atomXml = await atomRes.text();
  const shas = [
    ...new Set(
      [...atomXml.matchAll(/Grit::Commit\/([a-f0-9]{40})/g)].map((m) => m[1])
    ),
  ].slice(0, 3); // 3 most recent commits is plenty

  // (2) commit .patch -> CVE filenames
  const cveSet = new Set();
  await Promise.all(
    shas.map(async (sha) => {
      try {
        const r = await fetchWithTimeout(
          `https://github.com/trickest/cve/commit/${sha}.patch`,
          { headers: ua }
        );
        if (!r.ok) return;
        const t = await r.text();
        for (const m of t.matchAll(/CVE-(\d{4})-(\d+)\.md/g)) {
          cveSet.add(`${m[1]}/CVE-${m[1]}-${m[2]}`);
        }
      } catch {
        /* skip */
      }
    })
  );

  // (3) raw .md per CVE -> github PoC URLs
  const paths = [...cveSet].slice(0, 250); // hard cap for safety
  const map = {};
  const CONCURRENCY = 16;
  let cursor = 0;
  async function worker() {
    while (cursor < paths.length) {
      const idx = cursor++;
      const p = paths[idx];
      const cveId = p.split("/").pop();
      try {
        const r = await fetchWithTimeout(`${RAW}/${p}.md`, { headers: ua });
        if (!r.ok) continue;
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
        if (urls.length === 0) continue;
        map[cveId] = urls.slice(0, 8).map((slug) => ({
          name: slug,
          url: `https://github.com/${slug}`,
          owner: slug.split("/")[0],
          stars: 0,
          forks: 0,
          createdAt: null,
          updatedAt: null,
          description: "Listed in trickest/cve PoC index (no-auth fallback).",
        }));
      } catch {
        /* skip */
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return map;
}

/**
 * Returns a Map<cveId, pocEntry[]> of *recently-updated* CVE PoCs from
 * GitHub. This is the same index ThreatTracer-style aggregators rely on.
 */
export async function fetchGitHubPoCs() {
  // Serve from the long-lived in-process / on-disk cache when fresh.
  const cached = await getCached("github-pocs");
  if (cached !== null) return cached;

  let map = null;
  let degraded = null;

  // 1) Try the high-quality nomi-sec path (needs GitHub API).
  try {
    const paths = await fetchRecentCvePaths();
    // Use a bounded worker pool (20 concurrent) instead of unbounded Promise.all.
    // Unbounded on a busy repo can fire 1000+ simultaneous raw-file requests.
    const pocResults = [];
    let cursor = 0;
    async function pocWorker() {
      while (cursor < paths.length) {
        const i = cursor++;
        const r = await fetchPocFile(paths[i]);
        if (r) pocResults.push(r);
      }
    }
    await Promise.all(Array.from({ length: 20 }, pocWorker));
    const m = {};
    for (const e of pocResults) m[e.cveId] = e.pocs.sort((a, b) => b.stars - a.stars);
    if (Object.keys(m).length > 0) map = m;
    else degraded = `nomi-sec returned 0 entries from ${paths.length} paths`;
  } catch (e) {
    degraded = `nomi-sec: ${describeFetchError(e)}`;
  }

  // 2) Fallback: trickest/cve raw markdown index (no API rate limit).
  if (!map) {
    try {
      const m = await fetchTrickestFallback();
      if (Object.keys(m).length > 0) {
        map = m;
        degraded = degraded
          ? `${degraded}; using trickest fallback`
          : "using trickest fallback";
      }
    } catch (e) {
      degraded = `${degraded ?? ""} trickest: ${String(e?.message ?? e)}`.trim();
    }
  }

  // 3) Final fallback: last-good copy stored from a prior successful run.
  if (!map) {
    const lastGood = await getCached("github-pocs-lastgood");
    if (lastGood && Object.keys(lastGood).length > 0) {
      map = { ...lastGood };
      degraded = degraded ? `${degraded}; serving last-good` : "serving last-good";
    }
  }

  if (!map) {
    // Don't cache total failure -- let the next refresh retry sooner.
    return { __error: degraded ?? "github-pocs unavailable" };
  }

  if (degraded) map.__degraded = degraded;
  // Cache the successful (or degraded-but-usable) map for 30 minutes
  // and persist the clean copy as last-good for 7 days.
  await setCached("github-pocs", map, 150_000);
  const clean = { ...map };
  delete clean.__degraded;
  await setCached("github-pocs-lastgood", clean, 7 * 24 * 60 * 60_000);
  return map;
}
