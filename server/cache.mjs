// Tiny on-disk + in-memory cache. Keyed by string. TTL in ms.
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CACHE_DIR = join(__dirname, ".cache");

const mem = new Map(); // key -> { value, expiresAt }

async function ensureDir() {
  if (!existsSync(CACHE_DIR)) await mkdir(CACHE_DIR, { recursive: true });
}

function fileFor(key) {
  return join(CACHE_DIR, `${key.replace(/[^a-z0-9_-]/gi, "_")}.json`);
}

export async function getCached(key) {
  const m = mem.get(key);
  if (m && m.expiresAt > Date.now()) return m.value;
  try {
    const raw = await readFile(fileFor(key), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed.expiresAt > Date.now()) {
      mem.set(key, parsed);
      return parsed.value;
    }
  } catch {
    /* miss */
  }
  return null;
}

export async function setCached(key, value, ttlMs) {
  const entry = { value, expiresAt: Date.now() + ttlMs };
  mem.set(key, entry);
  await ensureDir();
  await writeFile(fileFor(key), JSON.stringify(entry), "utf8").catch(() => {});
}

export async function withCache(key, ttlMs, loader) {
  const hit = await getCached(key);
  if (hit !== null) return hit;
  const value = await loader();
  await setCached(key, value, ttlMs);
  return value;
}
