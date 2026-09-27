// FIRST.org EPSS — Exploit Prediction Scoring System.
// Real, daily-published probability that a CVE will be exploited in the next
// 30 days. Replaces the heuristic EPSS we were computing client-side.
//
// API: https://api.first.org/data/v1/epss?cve=CVE-2024-1,CVE-2024-2
// - Accepts comma-separated CVE list, ~100 IDs per request keeps URL safe.
// - Returns { data: [{ cve, epss, percentile, date }, ...] }
// - No auth required. Generous public rate limits.
import { withCache } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const ENDPOINT = "https://api.first.org/data/v1/epss";

async function fetchBatch(ids) {
  const url = `${ENDPOINT}?cve=${ids.join(",")}`;
  const res = await fetchWithTimeout(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "ZorroSOCGrid/0.1",
    },
  });
  if (!res.ok) throw new Error(`EPSS ${res.status}`);
  const json = await res.json();
  const map = {};
  for (const row of json.data ?? []) {
    map[row.cve] = {
      epss: parseFloat(row.epss),
      percentile: parseFloat(row.percentile),
      date: row.date,
    };
  }
  return map;
}

/**
 * Resolve real EPSS scores for a list of CVE IDs.
 * Cached for 6h (FIRST publishes once per day).
 * Returns { [cveId]: { epss, percentile, date } }
 */
export async function fetchEPSS(cveIds) {
  const filtered = [
    ...new Set(cveIds.filter((id) => /^CVE-\d{4}-\d+$/.test(id))),
  ];
  if (filtered.length === 0) return {};

  const cacheKey = `epss-${hash(filtered)}`;
  return withCache(cacheKey, 150_000, async () => {
    const result = {};
    const batches = [];
    for (let i = 0; i < filtered.length; i += 100) {
      batches.push(filtered.slice(i, i + 100));
    }
    // Run 5 batches at a time instead of one-by-one (50 serial = slow).
    const CONCURRENCY = 5;
    for (let i = 0; i < batches.length; i += CONCURRENCY) {
      const chunk = batches.slice(i, i + CONCURRENCY);
      const settled = await Promise.allSettled(chunk.map(fetchBatch));
      for (const r of settled) {
        if (r.status === "fulfilled" && r.value && !r.value.__error) {
          Object.assign(result, r.value);
        }
      }
    }
    return result;
  });
}

function hash(arr) {
  // Cheap stable hash so cache keys are short.
  let h = 0;
  const s = arr.join(",");
  for (let i = 0; i < s.length; i++) {
    h = (h * 31 + s.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}
