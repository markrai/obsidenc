#!/usr/bin/env node
/**
 * Propagate version from root Cargo.toml to all release surfaces.
 *
 * Usage (from repo root):
 *   node scripts/sync-versions.js
 *
 * Source of truth: Cargo.toml [package].version
 * Updates: gui/src-tauri/tauri.conf.json, gui/src-tauri/Cargo.toml, README title
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
  const version = match[1];
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error(`Invalid semver in ${rootCargoPath}: ${version}`);
    process.exit(1);
  }
  return version;
}

function updatePackageVersion(cargoPath, version) {
  const lines = fs.readFileSync(cargoPath, { encoding: "utf8" }).split(/\r?\n/);
  const pkgIdx = lines.findIndex((l) => l.trim() === "[package]");
  if (pkgIdx === -1) {
    console.error(`No [package] section in ${cargoPath}`);
    process.exit(1);
  }
  let updated = false;
  for (let i = pkgIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith("[")) break;
    if (/^\s*version\s*=\s*"/.test(line) && !/^\s*rust-version\s*=/.test(line)) {
      lines[i] = line.replace(/"[^"]*"/, `"${version}"`);
      updated = true;
      break;
    }
  }
  if (!updated) {
    console.error(`Failed to find package version line in ${cargoPath}`);
    process.exit(1);
  }
  fs.writeFileSync(cargoPath, lines.join("\n"), { encoding: "utf8" });
}

function updateTauriConf(version) {
  const raw = fs.readFileSync(tauriConfPath, { encoding: "utf8" });
  const cfg = JSON.parse(raw);
  cfg.version = version;
  fs.writeFileSync(tauriConfPath, JSON.stringify(cfg, null, 2) + "\n", { encoding: "utf8" });
}

function updateReadmeTitle(version) {
  const raw = fs.readFileSync(readmePath, { encoding: "utf8" });
  const titleRe = /^# obsidenc v\d+\.\d+\.\d+\s*$/m;
  if (!titleRe.test(raw)) {
    console.error(`README title line not found in ${readmePath}`);
    process.exit(1);
  }
  const next = raw.replace(titleRe, `# obsidenc v${version}`);
  if (next !== raw) {
    fs.writeFileSync(readmePath, next, { encoding: "utf8" });
  }
}

const version = readRootVersion();
updateTauriConf(version);
updatePackageVersion(guiCargoPath, version);
updateReadmeTitle(version);
console.log(`sync-versions: propagated ${version} from Cargo.toml to GUI config and README`);
