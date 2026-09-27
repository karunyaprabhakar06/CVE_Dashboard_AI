import { withCache } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const OSV = "https://api.osv.dev/v1/query";

function severityFromCvss(score) {
  if (score == null) return "NONE";
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

async function queryOsv(body) {
  const res = await fetchWithTimeout(OSV, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.vulns ?? [];
}

export async function fetchOSVLinux() {
  return withCache("osv-linux", 150_000, async () => {
    const ecosystems = ["Debian:12", "Ubuntu:22.04", "Alpine:v3.19"];
    const all = [];
    for (const eco of ecosystems) {
      const vulns = await queryOsv({ package: { ecosystem: eco } }).catch(() => []);
      for (const v of vulns.slice(0, 60)) {
        const sev = v.severity?.[0];
        const score = sev?.score ? parseFloat(sev.score) : null;
        all.push({
          id: v.id,
          description: v.summary ?? v.details ?? "",
          published: v.published ?? new Date().toISOString(),
          modified: v.modified ?? v.published ?? new Date().toISOString(),
          cvss: score,
          severity: severityFromCvss(score),
          source: "OSV",
          tags: (v.aliases ?? []).slice(0, 4),
          references: (v.references ?? []).map((r) => r.url).slice(0, 6),
          aliases: v.aliases ?? [],
        });
      }
    }
    const map = new Map();
    for (const r of all) map.set(r.id, r);
    return Array.from(map.values());
  });
}
