import { withCache } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const RH_CVE_LIST =
  "https://access.redhat.com/hydra/rest/securitydata/cve.json";

function severityFromString(s) {
  const x = String(s ?? "").toUpperCase();
  if (x === "CRITICAL") return "CRITICAL";
  if (x === "IMPORTANT" || x === "HIGH") return "HIGH";
  if (x === "MODERATE" || x === "MEDIUM") return "MEDIUM";
  if (x === "LOW") return "LOW";
  return "NONE";
}

function inferCategory(text) {
  const t = (text || "").toLowerCase();
  if (/linux kernel|kernel\b/.test(t)) return "linux-kernel";
  if (/http\/2|nginx|apache|httpd|envoy/.test(t)) return "web-server";
  if (/openssh|ssh\b|systemd|glibc|sudo|polkit/.test(t)) return "linux-service";
  if (/docker|kubernetes|containerd|k8s/.test(t)) return "container";
  if (/openssl|libssl|gnutls/.test(t)) return "crypto-lib";
  return "general";
}

export async function fetchRedHatRecent(daysBack = 14) {
  return withCache("redhat-recent", 170_000, async () => {
    const since = new Date(Date.now() - daysBack * 86_400_000)
      .toISOString()
      .slice(0, 10);
    const url = new URL(RH_CVE_LIST);
    url.searchParams.set("after", since);
    url.searchParams.set("per_page", "1000");

    const res = await fetchWithTimeout(url, {
      headers: { "User-Agent": "ZorroSOCGrid/0.1", Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`redhat ${res.status}`);

    let arr;
    try {
      arr = await res.json();
    } catch (e) {
      throw new Error(`redhat bad json: ${e?.message ?? e}`);
    }
    if (!Array.isArray(arr)) return [];

    return arr
      .filter((r) => /^CVE-\d{4}-\d{3,7}$/.test(r?.CVE ?? ""))
      .map((r) => {
        const cvss = r?.cvss_score != null ? Number(r.cvss_score) : null;
        const sev = severityFromString(r?.threat_severity || r?.severity);
        const refs = [];
        if (Array.isArray(r?.advisories)) refs.push(...r.advisories.filter(Boolean));
        if (r?.bugzilla) {
          refs.push(`https://bugzilla.redhat.com/show_bug.cgi?id=${r.bugzilla}`);
        }
        const desc =
          r?.bugzilla_description ||
          r?.statement ||
          `Red Hat advisory for ${r.CVE}`;
        const published = r?.public_date || new Date().toISOString();
        return {
          id: r.CVE,
          description: desc,
          published,
          modified: published,
          vulnStatus: "Reported",
          cvss,
          severity: sev === "NONE" && cvss != null ? (cvss >= 7 ? "HIGH" : cvss >= 4 ? "MEDIUM" : "LOW") : sev,
          source: "REDHAT",
          vendor: "redhat",
          references: [...new Set(refs)].slice(0, 8),
          category: inferCategory(desc),
          tags: ["redhat", "vendor-advisory"],
        };
      });
  });
}
