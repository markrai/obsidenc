#!/usr/bin/env node
/**
 * @deprecated Use repo-root scripts/sync-versions.js (source of truth: Cargo.toml).
 *
 * Kept for backward compatibility when run from gui/:
 *   node scripts/sync-version.js
 */
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..", "..");
const script = path.join(repoRoot, "scripts", "sync-versions.js");
console.warn("sync-version.js: delegating to scripts/sync-versions.js (root Cargo.toml is source of truth)");
const result = spawnSync(process.execPath, [script], { stdio: "inherit", cwd: repoRoot });
process.exit(result.status ?? 1);
