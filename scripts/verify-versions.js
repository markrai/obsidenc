#!/usr/bin/env node
/**
 * Fail if version strings diverge across release surfaces.
 *
 * Usage (from repo root):
 *   node scripts/verify-versions.js
 */
const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..");
const rootCargoPath = path.join(repoRoot, "Cargo.toml");
const tauriConfPath = path.join(repoRoot, "gui", "src-tauri", "tauri.conf.json");
const guiCargoPath = path.join(repoRoot, "gui", "src-tauri", "Cargo.toml");
const readmePath = path.join(repoRoot, "README.md");

function readRootVersion() {
  const cargo = fs.readFileSync(rootCargoPath, { encoding: "utf8" });
  const match = cargo.match(/^\s*version\s*=\s*"([^"]+)"/m);
  if (!match) {
    console.error(`No package version in ${rootCargoPath}`);
    process.exit(1);
  }
  return match[1];
}

function readGuiCargoVersion() {
  const cargo = fs.readFileSync(guiCargoPath, { encoding: "utf8" });
  const match = cargo.match(/^\s*version\s*=\s*"([^"]+)"/m);
  return match ? match[1] : null;
}

function readTauriVersion() {
  const cfg = JSON.parse(fs.readFileSync(tauriConfPath, { encoding: "utf8" }));
  return cfg.version || null;
}

function readReadmeVersion() {
  const raw = fs.readFileSync(readmePath, { encoding: "utf8" });
  const match = raw.match(/^# obsidenc v(\d+\.\d+\.\d+)\s*$/m);
  return match ? match[1] : null;
}

const expected = readRootVersion();
const checks = [
  ["gui/src-tauri/tauri.conf.json", readTauriVersion()],
  ["gui/src-tauri/Cargo.toml", readGuiCargoVersion()],
  ["README.md title", readReadmeVersion()],
];

let failed = false;
for (const [label, actual] of checks) {
  if (actual !== expected) {
    console.error(`version mismatch: ${label} is ${actual ?? "missing"}, expected ${expected}`);
    failed = true;
  }
}

if (failed) {
  console.error("Run: node scripts/sync-versions.js");
  process.exit(1);
}

console.log(`verify-versions: all surfaces at ${expected}`);
