import { withCache } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const USN_RSS = "https://ubuntu.com/security/notices/rss.xml";

function stripTags(s) {
  return String(s ?? "")
    .replace(/<[^>]*>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, " ")
    .trim();
}

function inferCategory(text) {
  const t = (text || "").toLowerCase();
  if (/linux kernel|kernel\b/.test(t)) return "linux-kernel";
  if (/http\/2|nginx|apache|httpd/.test(t)) return "web-server";
  if (/openssh|ssh\b|systemd|glibc|sudo|polkit/.test(t)) return "linux-service";
  if (/docker|kubernetes|containerd|k8s/.test(t)) return "container";
  if (/openssl|libssl|gnutls/.test(t)) return "crypto-lib";
  if (/wordpress|joomla|drupal|php/.test(t)) return "cms";
  return "general";
}

export async function fetchUbuntuUsnRecent(daysBack = 14) {
  return withCache("ubuntu-usn-recent", 170_000, async () => {
    const res = await fetchWithTimeout(USN_RSS, {
      headers: { "User-Agent": "ZorroSOCGrid/0.1", Accept: "application/rss+xml,text/xml" },
    });
    if (!res.ok) throw new Error(`ubuntu-usn ${res.status}`);
    const xml = await res.text();

    const items = [];
    const itemRe = /<item>([\s\S]*?)<\/item>/gi;
    let m;
    while ((m = itemRe.exec(xml)) !== null) {
      const block = m[1];
      const title = stripTags((block.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || "");
      const link = stripTags((block.match(/<link>([\s\S]*?)<\/link>/i) || [])[1] || "");
      const pubDateRaw = stripTags((block.match(/<pubDate>([\s\S]*?)<\/pubDate>/i) || [])[1] || "");
      const desc = stripTags((block.match(/<description>([\s\S]*?)<\/description>/i) || [])[1] || "");
      const ts = new Date(pubDateRaw).getTime();
      if (!Number.isFinite(ts)) continue;
      items.push({ title, link, desc, published: new Date(ts).toISOString() });
    }

    const cutoff = Date.now() - daysBack * 86_400_000;
    const byId = new Map();
    for (const it of items) {
      if (new Date(it.published).getTime() < cutoff) continue;
      const cves = [...new Set(`${it.title} ${it.desc}`.match(/CVE-\d{4}-\d{3,7}/gi) ?? [])].map((x) =>
        x.toUpperCase()
      );
      for (const id of cves) {
        const prev = byId.get(id);
        if (!prev || new Date(it.published) > new Date(prev.published)) {
          byId.set(id, it);
        }
      }
    }

    return [...byId.entries()].map(([id, it]) => ({
      id,
      description: `Ubuntu USN: ${it.title}`,
      published: it.published,
      modified: it.published,
      vulnStatus: "Reported",
      cvss: null,
      severity: "MEDIUM",
      source: "UBUNTU-USN",
      vendor: "ubuntu",
      references: it.link ? [it.link] : [],
      category: inferCategory(`${it.title} ${it.desc}`),
      tags: ["ubuntu", "usn", "vendor-advisory"],
    }));
  });
}
