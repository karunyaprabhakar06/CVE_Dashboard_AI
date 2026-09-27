#!/usr/bin/env node
/**
 * One-time API key setup.
 * Run: node server/setup-secrets.mjs
 *
 * Encrypts NVD_API_KEY and GITHUB_TOKEN with AES-256-GCM and writes:
 *   server/.secret-key   — the AES key  (never commit this)
 *   server/secrets.enc   — the ciphertext (never commit this)
 *
 * Plaintext keys are never written to disk.
 * Re-run to rotate any key; leave a field blank to keep the existing value.
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import readline from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KEY_FILE = path.join(__dirname, ".secret-key");
const SECRETS_FILE = path.join(__dirname, "secrets.enc");

function ask(question, hidden = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    if (hidden) {
      rl._writeToOutput = (s) => {
        if (s.trimEnd() === question.trimEnd()) process.stdout.write(question);
        // swallow echoed chars — key stays invisible
      };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stdout.write("\n");
      resolve(answer);
    });
  });
}

function encryptValue(plaintext, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    iv: iv.toString("hex"),
    enc: enc.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
  };
}

function decryptValue(stored, key) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(stored.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(stored.tag, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(stored.enc, "hex")),
    decipher.final(),
  ]).toString("utf8");
}

// ─── Load existing state ───────────────────────────────────────────────────
console.log("\n=== CVE Dashboard — API Key Setup ===\n");

let key;
const existingPlain = {};

const keyExists = await fs.stat(KEY_FILE).then((s) => s.isFile()).catch(() => false);
if (keyExists) {
  key = Buffer.from((await fs.readFile(KEY_FILE, "utf8")).trim(), "hex");
  console.log("Existing key found — leave a field blank to keep its current value.\n");

  const secsExists = await fs.stat(SECRETS_FILE).then((s) => s.isFile()).catch(() => false);
  if (secsExists) {
    try {
      const stored = JSON.parse(await fs.readFile(SECRETS_FILE, "utf8"));
      for (const [name, val] of Object.entries(stored)) {
        existingPlain[name] = decryptValue(val, key);
      }
    } catch {
      console.warn("  Warning: could not decrypt existing secrets — they will be overwritten.\n");
    }
  }
} else {
  key = crypto.randomBytes(32);
  console.log("No existing key — generating a new AES-256 key.\n");
}

// ─── Prompt ────────────────────────────────────────────────────────────────
const KEYS = [
  { name: "NVD_API_KEY",   label: "NVD API Key  " },
  { name: "GITHUB_TOKEN",  label: "GitHub Token " },
];

const results = {};

for (const { name, label } of KEYS) {
  const hint = existingPlain[name] ? " (hidden · Enter to keep existing)" : " (hidden · Enter to skip)";
  const raw = await ask(`${label}${hint}: `, true);
  const trimmed = raw.trim();
  const value = trimmed || existingPlain[name] || "";
  if (value) results[name] = value;
}

if (Object.keys(results).length === 0) {
  console.log("\nNo keys provided — nothing saved.");
  process.exit(0);
}

// ─── Encrypt & save ────────────────────────────────────────────────────────
const encrypted = {};
for (const [name, value] of Object.entries(results)) {
  encrypted[name] = encryptValue(value, key);
}

await fs.writeFile(KEY_FILE, key.toString("hex") + "\n", { mode: 0o644 });
await fs.writeFile(SECRETS_FILE, JSON.stringify(encrypted, null, 2) + "\n", { mode: 0o644 });

console.log("\n✓ Saved:");
console.log(`  server/.secret-key  (AES-256 encryption key)`);
console.log(`  server/secrets.enc  (encrypted ciphertext — unreadable without the key)`);
console.log();
for (const name of Object.keys(results)) {
  console.log(`  ${name}: set`);
}
console.log();
console.log("You can now remove NVD_API_KEY and GITHUB_TOKEN from your .env file.");
console.log("Docker: mount both files read-only and the server decrypts them at boot.\n");
