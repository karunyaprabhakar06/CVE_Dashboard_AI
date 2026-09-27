import { withCache } from "../cache.mjs";
import { fetchWithTimeout } from "./fetch-with-timeout.mjs";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export async function fetchKEV() {
  return withCache("kev", 150_000, async () => {
    const res = await fetchWithTimeout(KEV_URL, {
      headers: { "User-Agent": "ZorroSOCGrid/0.1" },
    });
    if (!res.ok) throw new Error(`KEV ${res.status}`);
    const json = await res.json();
    const items = json.vulnerabilities ?? [];
    return items.map((k) => ({
      id: k.cveID,
      description: k.shortDescription,
      published: k.dateAdded,
      modified: k.dateAdded,
      cvss: null,
      severity: "CRITICAL",
      exploited: true,
      vendor: k.vendorProject,
      product: k.product,
      source: "KEV",
      tags: [
        k.vendorProject,
        k.product,
        k.knownRansomwareCampaignUse === "Known" ? "ransomware" : undefined,
      ].filter(Boolean),
      kev: {
        dateAdded: k.dateAdded,
        dueDate: k.dueDate,
        ransomware: k.knownRansomwareCampaignUse === "Known",
        requiredAction: k.requiredAction,
        vulnName: k.vulnerabilityName,
      },
    }));
  });
}
