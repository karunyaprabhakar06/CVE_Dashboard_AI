import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildFeed } from "./merger.mjs";
import { searchCves } from "./search.mjs";
import { getCached, setCached } from "./cache.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 8787;
const REFRESH_INTERVAL_MS = 3 * 60_000;
const FEED_CACHE_KEY = "built-feed-v1";
const FEED_CACHE_TTL_MS = 24 * 60 * 60_000; // 24h disk validity

// ─── Encrypted secrets ────────────────────────────────────────────────────
const KEY_FILE  = path.join(__dirname, ".secret-key");
const SECS_FILE = path.join(__dirname, "secrets.enc");

async function loadSecrets() {
  const keyStat  = await fs.stat(KEY_FILE).catch(() => null);
  const secsStat = await fs.stat(SECS_FILE).catch(() => null);

  if (keyStat?.isFile() && secsStat?.isFile()) {
    try {
      const key     = Buffer.from((await fs.readFile(KEY_FILE, "utf8")).trim(), "hex");
      const stored  = JSON.parse(await fs.readFile(SECS_FILE, "utf8"));
      const loaded  = [];
      for (const [name, val] of Object.entries(stored)) {
        const dec = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(val.iv, "hex"));
        dec.setAuthTag(Buffer.from(val.tag, "hex"));
        process.env[name] = Buffer.concat([
          dec.update(Buffer.from(val.enc, "hex")),
          dec.final(),
        ]).toString("utf8");
        loaded.push(name);
      }
      console.log(`[secrets] decrypted → ${loaded.join(", ")}`);
    } catch (e) {
      console.error("[secrets] decryption failed:", e.message);
    }
    return;
  }

  // Fallback: plaintext env vars (local dev / legacy)
  const via = [
    process.env.NVD_API_KEY  && "NVD_API_KEY",
    process.env.GITHUB_TOKEN && "GITHUB_TOKEN",
  ].filter(Boolean);
  if (via.length) {
    console.log(`[secrets] using plaintext env vars: ${via.join(", ")} — consider running setup-secrets.mjs`);
  } else {
    console.log("[secrets] no keys configured — NVD + GitHub will run at unauthenticated rate limits");
  }
}
// ──────────────────────────────────────────────────────────────────────────

// ─── Auth ─────────────────────────────────────────────────────────────────
const SESSION_TTL_MS = 2 * 24 * 60 * 60_000; // 48 hours
const CREDS_FILE = path.join(__dirname, "credentials.json");

// Loaded once at startup from credentials.json (created by setup-creds.mjs).
// Never holds a plaintext password — only the salt + PBKDF2 hash.
let authCreds = null;

async function loadCredentials() {
  try {
    const stat = await fs.stat(CREDS_FILE).catch(() => null);
    if (!stat) {
      console.error(
        "[auth] credentials.json not found.\n" +
        "       Run:  node server/setup-creds.mjs\n" +
        "       Login is disabled until credentials are configured."
      );
      return;
    }
    if (!stat.isFile()) {
      // Docker bind-mounts a directory when the source file doesn't exist at
      // compose-up time. This catches that case with a clear message.
      console.error(
        "[auth] credentials.json is a directory, not a file.\n" +
        "       This usually means you ran 'docker compose up' before running\n" +
        "       'node server/setup-creds.mjs' on the host.\n" +
        "       Fix:\n" +
        "         1. docker compose down\n" +
        "         2. rm -rf ./server/credentials.json\n" +
        "         3. node server/setup-creds.mjs\n" +
        "         4. docker compose up -d"
      );
      return;
    }
    const raw = await fs.readFile(CREDS_FILE, "utf8");
    authCreds = JSON.parse(raw);
    console.log(`[auth] credentials loaded for user "${authCreds.username}"`);
  } catch (e) {
    console.error("[auth] failed to load credentials:", e.message);
  }
}

function pbkdf2Verify(password, salt, iterations, digest, storedHash) {
  return new Promise((resolve, reject) =>
    crypto.pbkdf2(password, salt, iterations, 64, digest, (err, key) =>
      err ? reject(err) : resolve(key.toString("hex") === storedHash)
    )
  );
}

async function verifyCredentials(username, password) {
  if (!authCreds) return false;
  if (username !== authCreds.username) return false;
  return pbkdf2Verify(password, authCreds.salt, authCreds.iterations, authCreds.digest, authCreds.hash);
}

// In-memory session store: token → { username, expiresAt }
const sessions = new Map();

// Prune expired sessions every hour
setInterval(() => {
  const now = Date.now();
  for (const [tok, s] of sessions) if (s.expiresAt <= now) sessions.delete(tok);
}, 60 * 60_000).unref();

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function validateSession(req) {
  const auth = req.headers["authorization"] ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return null;
  const sess = sessions.get(token);
  if (!sess) return null;
  if (Date.now() >= sess.expiresAt) { sessions.delete(token); return null; }
  return sess;
}

async function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => { data += c; });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
    req.on("error", () => resolve({}));
  });
}

async function callOllama(prompt, modelName) {
  const baseUrl = (process.env.OLLAMA_BASE_URL || "http://localhost:11434").replace(/\/$/, "");
  const model = modelName || process.env.OLLAMA_MODEL || "llama3.2";
  const res = await fetch(`${baseUrl}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      stream: false,
      options: { temperature: 0.2 },
      messages: [
        {
          role: "system",
          content:
            "You are a senior cybersecurity analyst. Give concise, operator-friendly guidance. Focus on impact, exploitability, urgency, recommended remediation, and tradeoffs. Do not speculate beyond the provided data.",
        },
        { role: "user", content: prompt },
      ],
    }),
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Ollama error ${res.status}: ${text || "request failed"}`);
  }

  const data = JSON.parse(text || "{}");
  const content = data?.message?.content ?? "";
  if (!content) throw new Error("Ollama returned no content");
  return { model, content };
}

function buildAiPrompt(record, question) {
  const summary = {
    id: record?.id ?? "unknown",
    description: record?.description ?? "",
    severity: record?.severity ?? "NONE",
    cvss: record?.cvss ?? null,
    epss: record?.epss ?? null,
    vendor: record?.vendor ?? "unknown",
    product: record?.product ?? "unknown",
    source: record?.source ?? "unknown",
    category: record?.category ?? "unknown",
    published: record?.published ?? null,
    modified: record?.modified ?? null,
    exploited: !!record?.exploited,
    exploitAvailable: !!record?.exploitAvailable,
    kev: !!record?.kev,
    inTheWild: Array.isArray(record?.inTheWild) ? record.inTheWild.length : 0,
    pocs: Array.isArray(record?.pocs) ? record.pocs.length : 0,
    nucleiTemplates: Array.isArray(record?.nucleiTemplates) ? record.nucleiTemplates.length : 0,
    zeroDayScore: record?.zeroDayScore ?? 0,
    refs: Array.isArray(record?.references) ? record.references.slice(0, 8) : [],
  };

  return `CVE context:\n${JSON.stringify(summary, null, 2)}\n\nUser question:\n${question}\n\nPlease answer in plain English with: 1) a concise risk assessment, 2) why it matters operationally, 3) likely exposure/impact, and 4) recommended next steps for a SOC / platform owner.`;
}
// ──────────────────────────────────────────────────────────────────────────

let latest = null;
let building = null;

async function loadLatestFromDisk() {
  try {
    const snap = await getCached(FEED_CACHE_KEY);
    if (snap && Array.isArray(snap.records)) {
      latest = {
        ...snap,
        ossMailing: Array.isArray(snap.ossMailing) ? snap.ossMailing : [],
      };
      console.log(
        `[feed] restored from disk: ${snap.counts?.total ?? snap.records.length} records (built ${snap.fetchedAt})`
      );
    }
  } catch (e) {
    console.warn("[feed] disk restore failed:", e?.message ?? e);
  }
}

async function persistLatestToDisk(feed) {
  try {
    await setCached(FEED_CACHE_KEY, feed, FEED_CACHE_TTL_MS);
  } catch (e) {
    console.warn("[feed] persist failed:", e?.message ?? e);
  }
}

const BUILD_TIMEOUT_MS = 10 * 60_000; // 10 minutes max per build cycle

async function refresh() {
  if (building) return building;
  const timeoutGuard = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("build timed out after 5 min")), BUILD_TIMEOUT_MS)
  );
  building = Promise.race([buildFeed(), timeoutGuard])
    .then(async (feed) => {
      latest = feed;
      console.log(
        `[feed] refreshed: ${feed.counts.total} records · ${feed.counts.pocTracked} PoCs · ${feed.counts.exploitDb} ExploitDB · ${feed.counts.inTheWild} ITW · ${feed.counts.nucleiTemplates ?? 0} Nuclei · ${feed.counts.epssReal ?? 0} EPSS · ${feed.counts.zeroDay} 0-day-grade · ${feed.durationMs}ms`
      );
      if (Object.keys(feed.errors).length)
        console.warn("[feed] partial errors:", feed.errors);
      await persistLatestToDisk(feed);
      return feed;
    })
    .catch((e) => {
      console.error("[feed] build failed", e);
      return latest;
    })
    .finally(() => {
      building = null;
    });
  return building;
}

// Decrypt API keys → inject into process.env before any source fetcher runs.
await loadSecrets();
// Load hashed credentials, then restore feed cache, then start refreshing.
await loadCredentials();
await loadLatestFromDisk();
refresh(); // background; serves cached data while running
setInterval(refresh, REFRESH_INTERVAL_MS);

function send(res, status, body, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Cache-Control": "no-store",
  });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") return send(res, 204, "");

  const url = new URL(req.url, `http://${req.headers.host}`);

  // ─── Auth endpoints (public) ───────────────────────────────────────────
  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    const body = await readBody(req);
    if (!authCreds) return send(res, 503, { error: "Auth not configured — run setup-creds.mjs" });
    const ok = await verifyCredentials(body.username ?? "", body.password ?? "");
    if (ok) {
      const token = generateToken();
      const expiresAt = Date.now() + SESSION_TTL_MS;
      sessions.set(token, { username: body.username, expiresAt });
      return send(res, 200, { token, expiresAt, username: body.username });
    }
    return send(res, 401, { error: "Invalid credentials" });
  }

  if (url.pathname === "/api/auth/logout" && req.method === "POST") {
    const auth = req.headers["authorization"] ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (token) sessions.delete(token);
    return send(res, 200, { ok: true });
  }

  // ─── Token guard for all other /api/* routes ───────────────────────────
  if (url.pathname.startsWith("/api/")) {
    if (!validateSession(req)) {
      return send(res, 401, { error: "Unauthorized — session expired or missing" });
    }
  }

  if (url.pathname === "/api/health") {
    return send(res, 200, {
      ok: true,
      hasFeed: !!latest,
      lastBuiltAt: latest?.fetchedAt ?? null,
      counts: latest?.counts ?? null,
      store: latest?.store ?? null,
    });
  }

  if (url.pathname === "/api/feed") {
    if (!latest && !building) refresh(); // ensure a build is in flight
    if (!latest) {
      // Still building — respond immediately so the client can poll
      return send(res, 200, { records: [], ossMailing: [], errors: {}, building: true, fetchedAt: null });
    }
    return send(res, 200, {
      ...latest,
      ossMailing: Array.isArray(latest.ossMailing) ? latest.ossMailing : [],
      building: false,
    });
  }

  if (url.pathname === "/api/feed/refresh") {
    const feed = await refresh();
    return send(res, 200, { ok: true, counts: feed?.counts ?? null });
  }

  if (url.pathname === "/api/search") {
    const q = url.searchParams.get("q") ?? "";
    const limit = Math.min(Number(url.searchParams.get("limit") ?? 15) || 15, 50);
    try {
      const result = await searchCves(q, limit);
      return send(res, 200, result);
    } catch (e) {
      return send(res, 500, { error: String(e?.message ?? e), records: [] });
    }
  }

  if (url.pathname === "/api/ai/models" && req.method === "GET") {
    try {
      const baseUrl = (process.env.OLLAMA_BASE_URL || "http://localhost:11434").replace(/\/$/, "");
      const tagsRes = await fetch(`${baseUrl}/api/tags`);
      if (!tagsRes.ok) {
        return send(res, 503, { error: "Ollama isn't responding on the local endpoint. Start `ollama serve` and pull a model such as `llama3.2`.", models: [] });
      }
      const tags = await tagsRes.json().catch(() => ({ models: [] }));
      const names = (tags.models ?? []).map((m) => m.name).filter(Boolean);
      return send(res, 200, { models: names });
    } catch (e) {
      return send(res, 503, { error: String(e?.message ?? e), models: [] });
    }
  }

  if ((url.pathname === "/api/ai/chat" || url.pathname === "/api/ai/explain") && req.method === "POST") {
    const body = await readBody(req);
    const record = body.record ?? null;
    const cveId = String(body.cveId ?? record?.id ?? "").trim();
    const model = String(body.model || process.env.OLLAMA_MODEL || "llama3.2").trim();
    const question = String(body.question || "Explain this CVE for a security operator in plain English.").trim();

    if (!record && !cveId) {
      return send(res, 400, { error: "A CVE record or cveId is required." });
    }

    try {
      const prompt = record ? buildAiPrompt(record, question) : `CVE: ${cveId}\nQuestion: ${question}`;
      const result = await callOllama(prompt, model);
      return send(res, 200, {
        ok: true,
        model: result.model,
        cveId,
        response: result.content,
        generatedAt: new Date().toISOString(),
      });
    } catch (e) {
      return send(res, 503, {
        error: `AI analysis failed: ${String(e?.message ?? e)}. Start Ollama locally with \`ollama serve\` and ensure the model is pulled.`,
      });
    }
  }

  send(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  // Don't print any prefix/suffix of the secret — just whether it's set.
  // Screenshots, log shipping, and CI capture would otherwise leak partial
  // material from these otherwise-helpful boot lines.
  const mask = (v) => (v ? `set (${v.length} chars)` : "not set");
  console.log(`ZorroSOC Grid backend listening on http://localhost:${PORT}`);
  console.log(
    `  GET /api/health · /api/feed · /api/feed/refresh · /api/search?q=…`
  );
  console.log(`  NVD_API_KEY: ${mask(process.env.NVD_API_KEY)}`);
  console.log(`  GITHUB_TOKEN: ${mask(process.env.GITHUB_TOKEN)}`);
  if (!process.env.NVD_API_KEY)
    console.log(
      `  ⚠ Without NVD_API_KEY the backfill crawls (5 req / 30s) and POC-only lookups are capped at 8.`
    );
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    console.log(`\n[server] ${sig} received — closing port ${PORT}`);
    server.close(() => process.exit(0));
    // Hard-exit fallback if connections stall
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
