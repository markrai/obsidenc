# Changelog

## v1.0.4

- **Cross-platform GUI build:** Replaced PowerShell-based Tauri hooks with Node.js scripts (`gui/scripts/build-sidecar.js`, `gui/scripts/dev.js`) so `cargo tauri dev` / `cargo tauri build` work on Windows, macOS, and Linux when Node is on `PATH`. End users of release installers do not need Node.
- **Version source of truth:** GUI version is defined in `gui/src-tauri/tauri.conf.json`. From `gui/`, run `node scripts/sync-version.js` after bumping it to align `gui/src-tauri/Cargo.toml` with `CARGO_PKG_VERSION` / `get_version`. Version is not mutated implicitly during build.
- **README:** Clarifies that Node.js is required only for development and packaging, not for running a shipped build.
- **Locale fix (French UI):** Allow locale JSON fetch in CSP (`connect-src 'self'` plus dev-server origins). Harden locale loading with HTTP checks; preferences modal no longer freezes when a language switch fails; saved French preference is no longer silently reset to English on load failure. Removed temporary locale debug logging.

## v1.0.3

- **GUI i18n:** Added English/Français UI localization with a Preferences modal. On first run, the app now defaults to system locale (`fr` -> French, otherwise English), then preserves explicit user choice via `localStorage`.
- **Windows NSIS installer:** Configured one installer artifact to include English and French language resources (`bundle.windows.nsis.languages`) with language selector disabled (`displayLanguageSelector: false`).
- **Verification status:** Build-time configuration is applied and NSIS packaging is generated; runtime installer language rendering on French/English Windows environments must be validated before claiming full installer UX verification.
