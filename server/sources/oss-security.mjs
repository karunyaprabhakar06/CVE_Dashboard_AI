import { withCache } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const ROOT = "https://www.openwall.com/lists/oss-security/";
const CVE_RE = /CVE-\d{4}-\d{3,7}/gi;

function decodeHtml(s) {
  return String(s ?? "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&hellip;/g, "...")
    .replace(/&#64;/g, "@");
}

function stripTags(s) {
  return decodeHtml(String(s ?? "").replace(/<[^>]*>/g, " "))
    .replace(/\s+/g, " ")
    .trim();
}

function inferCategory(text) {
  const t = (text || "").toLowerCase();
  if (/linux kernel|kernel\b/.test(t)) return "linux-kernel";
  if (/openssh|ssh\b|systemd|glibc|sudo|polkit|keepalived|puppet/.test(t)) return "linux-service";
  if (/http\/2|https\b|nginx|apache|httpd|envoy/.test(t)) return "web-server";
  if (/openssl|libssl|gnutls|\btls\b/.test(t)) return "crypto-lib";
  if (/docker|kubernetes|containerd|k8s/.test(t)) return "container";
  if (/wordpress|joomla|drupal|php/.test(t)) return "cms";
  if (/sql injection|xss|csrf|rce|deserialization/.test(t)) return "web-app";
  return "general";
}

function severityFromSubject(subject) {
  const s = (subject || "").toLowerCase();
  if (/rce|remote code execution|unauth|critical/.test(s)) return "CRITICAL";
  if (/privilege escalation|uaf|use-after-free|overflow|dos|denial of service/.test(s))
    return "HIGH";
  return "MEDIUM";
}

async function fetchMonth(year, month) {
  const mm = String(month).padStart(2, "0");
  const url = `${ROOT}${year}/${mm}/`;
  const res = await fetchWithTimeout(url, {
    headers: { "User-Agent": "ZorroSOCGrid/0.1", Accept: "text/html" },
  });
  if (!res.ok) throw new Error(`oss-security ${res.status}`);
  const html = await res.text();

  const out = [];
  const re = /<li>\s*<a href="([^"]+)">([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const href = m[1];
    const subject = stripTags(m[2]);
    if (!subject) continue;
    const cves = [...new Set(subject.match(CVE_RE) ?? [])].map((x) => x.toUpperCase());

    const abs = new URL(href, url).toString();
    const dayMatch = href.match(/^(\d{2})\//);
    const idxMatch = href.match(/^\d{2}\/(\d+)$/);
    const day = dayMatch ? Number(dayMatch[1]) : 1;
    const msgIndex = idxMatch ? Number(idxMatch[1]) : 0;
    const published = new Date(Date.UTC(year, month - 1, day, 12, 0, 0)).toISOString();
    out.push({ subject, link: abs, published, cves, msgIndex });
  }
  return out;
}

function isLikelyLinuxServiceSubject(subject) {
  const s = String(subject ?? "").toLowerCase();
  return /linux|kernel|http\/2|https\b|\btls\b|httpd|apache|nginx|envoy|ssh|openssl|glibc|systemd|sudo|polkit|keepalived|puppet|containerd|docker|kubernetes|k8s|xen|qemu|libvirt|perl|python|cpython|ruby|php|node(?:js)?|java|jvm|golang|go\b|rust|dbi|airflow|postgres|mysql|redis|mongodb|rabbitmq|kafka|bird|bgp/.test(
    s
  );
}

export async function fetchOssSecuritySignals(daysBack = 14) {
  return withCache("oss-security-signals", 170_000, async () => {
    const now = new Date();
    const months = [{ y: now.getUTCFullYear(), m: now.getUTCMonth() + 1 }];
    const prev = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
    months.push({ y: prev.getUTCFullYear(), m: prev.getUTCMonth() + 1 });

    const rows = [];
    for (const mo of months) {
      try {
        rows.push(...(await fetchMonth(mo.y, mo.m)));
      } catch {
        // keep best-effort behavior; one month failing should not poison feed
      }
    }

    const cutoff = Date.now() - daysBack * 86_400_000;
    return rows
      .filter((r) => {
        const ts = new Date(r.published).getTime();
        return Number.isFinite(ts) && ts >= cutoff;
      })
      .map((r) => ({
        id: `oss-${Buffer.from(r.link).toString("base64url")}`,
        published: r.published,
        subject: r.subject,
        link: r.link,
        cveIds: r.cves,
        msgIndex: r.msgIndex ?? 0,
        severity: severityFromSubject(r.subject),
        category: inferCategory(r.subject),
        likelyLinux: isLikelyLinuxServiceSubject(r.subject),
      }))
      .sort((a, b) => {
        const td = new Date(b.published).getTime() - new Date(a.published).getTime();
        if (td !== 0) return td;
        return (b.msgIndex ?? 0) - (a.msgIndex ?? 0);
      })
      .slice(0, 120);
  });
}

export async function fetchOssSecurityRecent(daysBack = 14) {
  return withCache("oss-security-recent", 170_000, async () => {
    const rows = await fetchOssSecuritySignals(daysBack);
    const byId = new Map();
    for (const r of rows) {
      for (const id of r.cveIds) {
        const prevRow = byId.get(id);
        if (!prevRow || new Date(r.published) > new Date(prevRow.published)) {
          byId.set(id, { ...r, cveId: id });
        }
      }
    }

    return [...byId.values()].map((r) => ({
      id: r.cveId,
      description: `oss-security: ${r.subject}`,
      published: r.published,
      modified: r.published,
      vulnStatus: "Reported",
      cvss: null,
      severity: severityFromSubject(r.subject),
      source: "OSS-SEC",
      category: inferCategory(r.subject),
      references: [r.link],
      tags: ["oss-security", "linux-early-warning"],
    }));
  });
}
