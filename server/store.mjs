// Rolling 60-day CVE store. Holds every NVD/OSV/KEV record whose `modified`
// timestamp falls within the last RETENTION_DAYS days. Persists to disk
// (via cache.mjs primitives) so a restart doesn't trigger a full backfill.
//
// Refresh strategy:
//   - First boot (or cache miss): pull the full 60-day NVD window in
//     paginated slices.
//   - Subsequent refreshes: delta — pull only CVEs modified since
//     `lastSuccessfulRefresh - 30min` and upsert.
//   - After every refresh: prune anything with modified < now - 60d.
import { getCached, setCached } from "./cache.mjs";
import { fetchNVDWindow, fetchNVDPublished } from "./sources/nvd.mjs";
import { fetchMITRERecent } from "./sources/mitre.mjs";

export const RETENTION_DAYS = 60;
const STORE_KEY = "rolling-cve-store-v1";
const STORE_TTL_MS = 7 * 24 * 60 * 60_000; // 7d on-disk validity

// in-memory: Map<cveId, CVERecord>
let store = new Map();
let lastRefreshAt = null;
let loaded = false;

function cutoffIso() {
  return new Date(Date.now() - RETENTION_DAYS * 86_400_000).toISOString();
}

function prune() {
  const cutoff = cutoffIso();
  let removed = 0;
  for (const [id, r] of store) {
    if (!r.modified || r.modified < cutoff) {
      store.delete(id);
      removed++;
    }
  }
  return removed;
}

async function loadFromDisk() {
  if (loaded) return;
  loaded = true;
  try {
    const snap = await getCached(STORE_KEY);
    if (snap && Array.isArray(snap.records)) {
      for (const r of snap.records) store.set(r.id, r);
      lastRefreshAt = snap.lastRefreshAt ?? null;
      prune();
      console.log(
        `[store] loaded ${store.size} records from disk (lastRefresh=${lastRefreshAt})`
      );
    }
  } catch (e) {
    console.warn("[store] disk load failed:", e?.message ?? e);
  }
}

async function persistToDisk() {
  try {
    await setCached(
      STORE_KEY,
      { records: [...store.values()], lastRefreshAt },
      STORE_TTL_MS
    );
  } catch (e) {
    console.warn("[store] persist failed:", e?.message ?? e);
  }
}

function upsertMany(records) {
  let added = 0;
  let updated = 0;
  for (const r of records) {
    if (!r?.id) continue;
    if (store.has(r.id)) {
      // Merge: prefer the newer `modified` timestamp's payload, but keep
      // enrichment fields from whichever record has them.
      const prev = store.get(r.id);
      const merged = { ...prev, ...r };
      // Don't clobber enrichments with empty arrays from a fresher base record
      merged.pocs = (r.pocs?.length ? r.pocs : prev.pocs) ?? [];
      merged.exploits = (r.exploits?.length ? r.exploits : prev.exploits) ?? [];
      merged.inTheWild = (r.inTheWild?.length ? r.inTheWild : prev.inTheWild) ?? [];
      merged.nucleiTemplates =
        (r.nucleiTemplates?.length ? r.nucleiTemplates : prev.nucleiTemplates) ?? [];
      merged.kev = r.kev ?? prev.kev;
      merged.exploited = r.exploited || prev.exploited;
      store.set(r.id, merged);
      updated++;
    } else {
      store.set(r.id, r);
      added++;
    }
  }
  return { added, updated };
}

/**
 * Pull all NVD records modified in [sinceIso, untilIso] using paginated calls.
 * NVD allows max 120-day windows per request; we already stay within 60d.
 * Page size: 2000 (max allowed), looped via startIndex.
 */
async function backfillRange(sinceIso, untilIso) {
  const records = await fetchNVDWindow(sinceIso, untilIso);
  const { added, updated } = upsertMany(records);
  return { fetched: records.length, added, updated };
}

/**
 * Refresh the store. On first call (empty store), does a full 60-day backfill
 * in 14-day slices to stay polite. On subsequent calls, delta-refreshes
 * from (lastRefreshAt - 30min).
 */
export async function refreshStore() {
  await loadFromDisk();
  const now = new Date();
  const stats = { fetched: 0, added: 0, updated: 0, pruned: 0 };

  if (store.size === 0 || !lastRefreshAt) {
    // Cold start: fetch only the last 7 days so the feed is usable in ~30s.
    // Delta refreshes every 3 minutes keep adding new CVEs from that point on.
    const COLD_DAYS = 7;
    const coldStart = new Date(now.getTime() - COLD_DAYS * 86_400_000);
    try {
      const s = await backfillRange(coldStart.toISOString(), now.toISOString());
      stats.fetched += s.fetched;
      stats.added += s.added;
      stats.updated += s.updated;
      console.log(`[store] cold-start (${COLD_DAYS}d): +${s.added} new, ~${s.updated} updated`);
    } catch (e) {
      console.warn(`[store] cold-start fetch failed:`, e?.message ?? e);
    }
  } else {
    // Delta refresh
    const since = new Date(
      new Date(lastRefreshAt).getTime() - 30 * 60_000
    ).toISOString();
    try {
      const s = await backfillRange(since, now.toISOString());
      stats.fetched = s.fetched;
      stats.added = s.added;
      stats.updated = s.updated;
    } catch (e) {
      console.warn(`[store] delta refresh failed:`, e?.message ?? e);
    }
  }

  // Supplement with NVD's pubStartDate window so brand-new CVEs that haven't
  // been re-modified yet (vulnStatus = Awaiting Analysis / Received) still
  // land in the store. lastModStartDate alone misses them for days.
  try {
    const fresh = await fetchNVDPublished(7);
    if (fresh.length) {
      const u = upsertMany(fresh);
      stats.fetched += fresh.length;
      stats.added += u.added;
      stats.updated += u.updated;
      console.log(
        `[store] pubStartDate backfill (7d): +${u.added} new, ~${u.updated} updated (fetched=${fresh.length})`
      );
    }
  } catch (e) {
    console.warn(`[store] pubStart backfill failed:`, e?.message ?? e);
  }

  // MITRE CVE List V5 fallback. Catches CVEs that exist in NVD's index but
  // whose payloads NVD currently refuses to deliver (recurring
  // resultsPerPage:0 glitch), plus CVEs assigned by CNAs that NVD hasn't
  // ingested yet. We only fetch IDs not already in our store to bound work.
  try {
    const haveIds = new Set(store.keys());
    const mitre = await fetchMITRERecent(7, { excludeIds: haveIds });
    if (mitre.length) {
      const u = upsertMany(mitre);
      stats.fetched += mitre.length;
      stats.added += u.added;
      stats.updated += u.updated;
      console.log(
        `[store] MITRE V5 backfill (7d): +${u.added} new, ~${u.updated} updated (fetched=${mitre.length})`
      );
    }
  } catch (e) {
    console.warn(`[store] MITRE backfill failed:`, e?.message ?? e);
  }

  stats.pruned = prune();
  lastRefreshAt = now.toISOString();
  await persistToDisk();
  return { ...stats, total: store.size, lastRefreshAt };
}

export async function getAllRecords() {
  await loadFromDisk();
  return [...store.values()];
}

export async function upsertExternalRecords(records) {
  await loadFromDisk();
  return upsertMany(records);
}

export async function getStoreMeta() {
  await loadFromDisk();
  return { total: store.size, lastRefreshAt, retentionDays: RETENTION_DAYS };
}
