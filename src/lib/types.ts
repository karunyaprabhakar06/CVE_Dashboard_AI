export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export interface PocRepo {
  name: string;
  url: string;
  owner?: string;
  stars: number;
  forks: number;
  createdAt?: string;
  updatedAt?: string;
  description?: string;
  source?: "nomi-sec" | "trickest" | string;
}

export interface ExploitDBEntry {
  edbId: string;
  title: string;
  author?: string;
  type?: string;
  platform?: string;
  date?: string;
  url: string;
}

export interface ITWEvent {
  referenceURL?: string;
  source?: string;
  timestamp?: string;
  type?: string;
  name?: string;
  confirmed?: boolean;
}

export interface NucleiTemplate {
  templateId: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | "unknown";
  tags: string[];
  filePath: string;
  url: string;
  author?: string | null;
}

export interface KEVMeta {
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
  requiredAction?: string;
  vulnName?: string;
}

export interface CVERecord {
  id: string;
  description: string;
  published: string;
  modified: string;
  vulnStatus?: string;
  cvss: number | null;
  cvssVector?: string;
  severity: Severity;
  epss?: number;
  epssPercentile?: number;
  epssDate?: string;
  epssSource?: "FIRST.org" | "heuristic";
  exploited?: boolean;
  exploitAvailable?: boolean;
  confirmedExploited?: boolean;
  vendor?: string;
  product?: string;
  references?: string[];
  source:
    | "NVD"
    | "MITRE"
    | "OSV"
    | "KEV"
    | "REDHAT"
    | "TENABLE"
    | "UBUNTU-USN"
    | "OSS-SEC"
    | "POC-ONLY";
  category?: string;
  tags?: string[];
  pocs?: PocRepo[];
  exploits?: ExploitDBEntry[];
  inTheWild?: ITWEvent[];
  nucleiTemplates?: NucleiTemplate[];
  kev?: KEVMeta;
  zeroDayScore?: number;
  isZeroDay?: boolean;
  enrichmentSources?: EnrichmentSource[];
}

export interface EnrichmentSource {
  type: "github-poc" | "exploit-db" | "nuclei" | "in-the-wild" | string;
  label: string;
  url?: string | null;
  description?: string | null;
  stars?: number;
  platform?: string | null;
  severity?: string | null;
}

export interface ThreatFeedItem {
  id: string;
  ts: string;
  title: string;
  severity: Severity;
  source: string;
}

export interface FeedCounts {
  total: number;
  pocTracked: number;
  exploitDb: number;
  inTheWild: number;
  inTheWildConfirmed?: number;
  confirmedExploited?: number;
  zeroDay: number;
  kev: number;
  epssReal?: number;
  nucleiTemplates?: number;
}

export interface OssMailingSignal {
  id: string;
  published: string;
  subject: string;
  link: string;
  cveIds: string[];
  severity: Severity;
  category: string;
  likelyLinux: boolean;
}

export interface OllamaModel {
  name: string;
  size?: number;
  modified_at?: string;
  digest?: string;
}

export interface AIAnalysisResult {
  model: string;
  cveId: string;
  response: string;
  generatedAt: string;
}
