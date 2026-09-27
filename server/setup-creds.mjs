#!/usr/bin/env node
/**
 * One-time credential setup.
 * Run: node server/setup-creds.mjs
 *
 * Hashes your password with PBKDF2-SHA512 (100k rounds) and writes
 * server/credentials.json  (mode 0600 — owner read/write only).
 * The plaintext password is never stored.
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import readline from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CREDS_FILE = path.join(__dirname, "credentials.json");
const ITERATIONS = 100_000;
const KEYLEN = 64;
const DIGEST = "sha512";

function ask(question, hidden = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    if (hidden) {
      rl._writeToOutput = (s) => {
        if (s.trimEnd() === question.trimEnd()) process.stdout.write(question);
        // swallow echoed chars so the password stays invisible
      };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stdout.write("\n");
      resolve(answer);
    });
  });
}

async function pbkdf2(password, salt) {
  return new Promise((resolve, reject) =>
    crypto.pbkdf2(password, salt, ITERATIONS, KEYLEN, DIGEST, (err, key) =>
      err ? reject(err) : resolve(key.toString("hex"))
    )
  );
}

console.log("\n=== CVE Dashboard — Credential Setup ===\n");

try {
  // Check if file already exists
  const exists = await fs.access(CREDS_FILE).then(() => true).catch(() => false);
  if (exists) {
    const overwrite = await ask("credentials.json already exists. Overwrite? [y/N] ");
    if (overwrite.trim().toLowerCase() !== "y") {
      console.log("Aborted.");
      process.exit(0);
    }
  }

  const username = (await ask("Username: ")).trim();
  if (!username) { console.error("Error: username cannot be empty."); process.exit(1); }

  const password = await ask("Password (hidden): ", true);
  if (password.length < 8) { console.error("Error: password must be at least 8 characters."); process.exit(1); }

  const confirm = await ask("Confirm password (hidden): ", true);
  if (password !== confirm) { console.error("Error: passwords do not match."); process.exit(1); }

  process.stdout.write("Hashing… ");
  const salt = crypto.randomBytes(32).toString("hex");
  const hash = await pbkdf2(password, salt);
  process.stdout.write("done.\n");

  const creds = { username, salt, hash, iterations: ITERATIONS, digest: DIGEST };
  await fs.writeFile(CREDS_FILE, JSON.stringify(creds, null, 2) + "\n", { mode: 0o644 });

  console.log(`\n✓ Saved: ${CREDS_FILE}  (permissions 600 — owner-only)`);
  console.log("  The plaintext password is NOT stored anywhere.\n");
  console.log("To use with Docker, make sure your docker-compose.yml mounts the file:");
  console.log("  volumes:");
  console.log("    - ./server/credentials.json:/app/server/credentials.json:ro\n");
} catch (e) {
  console.error("\nFailed:", e.message);
  process.exit(1);
}
