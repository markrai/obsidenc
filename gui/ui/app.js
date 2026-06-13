const LOCALE_STORAGE_KEY = "obsidenc-locale";
let strings = {};
let currentLocale = "en";

function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element: ${id}`);
  return el;
}

function t(key, params) {
  let s = strings[key];
  if (typeof s !== "string") return key;
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      s = s.replace(new RegExp("{{" + k + "}}", "g"), String(v));
    }
  }
  return s;
}

async function loadLocale(locale) {
  const r = await fetch("./locales/" + locale + ".json");
  if (!r.ok) {
    throw new Error(`Failed to load locale "${locale}": HTTP ${r.status}`);
  }
  strings = await r.json();
}

async function initLocale(preferred, { persist = true } = {}) {
  try {
    await loadLocale(preferred);
    applyLocale(preferred);
    if (persist) {
      localStorage.setItem(LOCALE_STORAGE_KEY, preferred);
    }
    return preferred;
  } catch (_) {
    if (preferred !== "en") {
      try {
        await loadLocale("en");
        applyLocale("en");
        return "en";
      } catch (_) {
        return preferred;
      }
    }
    return preferred;
  }
}

function getSupportedLocaleFromSystem() {
  const raw = navigator.languages?.[0] || navigator.language || "en";
  const base = raw.toLowerCase().split("-")[0];
  if (base === "fr") return "fr";
  return "en";
}

function getValidatedSavedLocale() {
  const saved = localStorage.getItem(LOCALE_STORAGE_KEY);
  if (saved === "en" || saved === "fr") return saved;
  return null;
}

function applyLocale(locale) {
  document.documentElement.lang = locale === "fr" ? "fr" : "en";
  currentLocale = locale;

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key) el.textContent = t(key);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) el.placeholder = t(key);
  });
  document.querySelectorAll("[data-i18n-alt]").forEach((el) => {
    const key = el.getAttribute("data-i18n-alt");
    if (key) el.alt = t(key);
  });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((el) => {
    const key = el.getAttribute("data-i18n-aria-label");
    if (key) el.setAttribute("aria-label", t(key));
  });

  const subtitleEl = document.getElementById("subtitle");
  if (subtitleEl && subtitleEl.hasAttribute("data-i18n-html")) {
    const raw = t("subtitle");
    subtitleEl.innerHTML = raw.replace("obsidenc.exe", "<code>obsidenc.exe</code>");
  }

  const titleEl = document.querySelector("title");
  if (titleEl) titleEl.textContent = t("title");
}

function setStatus(message, kind = "") {
  const status = $("status");
  status.textContent = message;
  status.className = `status${kind ? ` ${kind}` : ""}`;
  if (message) {
    try {
      status.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (_) {}
  }
}

function appendLog(line) {
  const out = $("log-output");
  out.textContent += line + "\n";
  out.scrollTop = out.scrollHeight;
}

function clearLogs() {
  $("log-output").textContent = "";
}

function validateAbsolutePath(fieldKey, value) {
  if (!value || value.trim() === "") return t("validation." + fieldKey + "Required");
  const v = value.trim();
  const isWindowsAbs = /^[a-zA-Z]:\\/.test(v) || /^\\\\/.test(v);
  const isUnixAbs = v.startsWith("/");
  if (!isWindowsAbs && !isUnixAbs) {
    return t(fieldKey === "keyfile" ? "validation.keyfileAbsolute" : "validation." + fieldKey + "Absolute");
  }
  return null;
}

function validatePassword(value) {
  if (!value) return t("validation.passwordRequired");
  if (value.includes("\n") || value.includes("\r") || value.includes("\0")) return t("validation.passwordInvalidChars");
  if ([...value].length < 20) return t("validation.passwordMinLength");
  return null;
}

async function main() {
  const TAURI = window.__TAURI__;
  if (!TAURI || !TAURI.core || !TAURI.event) {
    setStatus(t("status.tauriUnavailable"), "error");
    return;
  }

  let activeOpId = null;
  let busy = false;

  try {
    const info = await TAURI.core.invoke("get_version");
    if (info && typeof info.gui === "string") {
      const el = document.getElementById("version-label");
      if (el) el.textContent = "v" + info.gui;
    }
  } catch (_) {}

  await TAURI.event.listen("obsidenc/log", (event) => {
    const payload = event.payload;
    if (!payload) return;
    if (activeOpId === null) activeOpId = payload.id;
    if (payload.id !== activeOpId) return;
    appendLog(`[${payload.stream}] ${payload.line}`);
  });

  for (const btn of document.querySelectorAll(".tab")) {
    btn.addEventListener("click", () => {
      if (!btn.dataset.tab) return;
      for (const b of document.querySelectorAll(".tab")) b.classList.remove("active");
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      for (const panel of document.querySelectorAll(".panel")) panel.classList.remove("active");
      $(tab).classList.add("active");
      setStatus("");
    });
  }

  $("clear-logs").addEventListener("click", () => {
    clearLogs();
    setStatus("");
  });

  const overlay = document.getElementById("preferences-overlay");
  const prefsBtn = document.getElementById("preferences-btn");
  const prefsClose = document.getElementById("prefs-close");
  const prefsLanguage = document.getElementById("prefs-language");

  function openPreferences() {
    if (prefsLanguage) prefsLanguage.value = currentLocale;
    if (overlay) {
      overlay.setAttribute("aria-hidden", "false");
      prefsClose && prefsClose.focus();
    }
  }

  function closePreferences() {
    if (overlay) overlay.setAttribute("aria-hidden", "true");
    prefsBtn && prefsBtn.focus();
  }

  async function savePreferencesAndClose() {
    const next = prefsLanguage ? prefsLanguage.value : currentLocale;
    if (next && next !== currentLocale) {
      try {
        await loadLocale(next);
        applyLocale(next);
        localStorage.setItem(LOCALE_STORAGE_KEY, next);
      } catch (_) {
        if (prefsLanguage) prefsLanguage.value = currentLocale;
        setStatus(t("status.localeLoadFailed"), "error");
      } finally {
        closePreferences();
      }
    } else {
      closePreferences();
    }
  }

  if (prefsBtn) prefsBtn.addEventListener("click", openPreferences);
  if (prefsClose) prefsClose.addEventListener("click", savePreferencesAndClose);
  if (overlay) {
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) savePreferencesAndClose();
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && overlay && overlay.getAttribute("aria-hidden") === "false") {
      savePreferencesAndClose();
    }
  });

  const vaultBrowseBtn = document.getElementById("enc-vault-browse");
  if (vaultBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    vaultBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: t("dialog.selectVaultDir"),
          directory: true,
          multiple: false,
        });
        if (typeof selected === "string" && selected) {
          $("enc-vault-dir").value = selected;
          setStatus("");
        }
      } catch (err) {
        setStatus(String(err), "error");
      }
    });
  }

  const outputBrowseBtn = document.getElementById("enc-output-browse");
  if (outputBrowseBtn && TAURI.dialog && (TAURI.dialog.save || TAURI.dialog.open)) {
    outputBrowseBtn.addEventListener("click", async () => {
      try {
        let selected;
        if (TAURI.dialog.save) {
          selected = await TAURI.dialog.save({ title: t("dialog.chooseOutputFile") });
        } else {
          selected = await TAURI.dialog.open({
            title: t("dialog.selectOutputFile"),
            directory: false,
            multiple: false,
          });
        }
        if (typeof selected === "string" && selected) {
          $("enc-output-file").value = selected;
          setStatus("");
        }
      } catch (err) {
        setStatus(String(err), "error");
      }
    });
  }

  const keyfileBrowseBtn = document.getElementById("enc-keyfile-browse");
  if (keyfileBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    keyfileBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: t("dialog.selectKeyfile"),
          directory: false,
          multiple: false,
        });
        if (typeof selected === "string" && selected) {
          $("enc-keyfile").value = selected;
          setStatus("");
        }
      } catch (err) {
        setStatus(String(err), "error");
      }
    });
  }

  const decInputBrowseBtn = document.getElementById("dec-input-browse");
  if (decInputBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    decInputBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: t("dialog.selectInputFile"),
          directory: false,
          multiple: false,
        });
        if (typeof selected === "string" && selected) {
          $("dec-input-file").value = selected;
          setStatus("");
        }
      } catch (err) {
        setStatus(String(err), "error");
      }
    });
  }

  const decOutputBrowseBtn = document.getElementById("dec-output-browse");
  if (decOutputBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    decOutputBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: t("dialog.selectOutputDir"),
          directory: true,
          multiple: false,
        });
        if (typeof selected === "string" && selected) {
          $("dec-output-dir").value = selected;
          setStatus("");
        }
      } catch (err) {
        setStatus(String(err), "error");
      }
    });
  }

  const decKeyfileBrowseBtn = document.getElementById("dec-keyfile-browse");
  if (decKeyfileBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    decKeyfileBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: t("dialog.selectKeyfile"),
          directory: false,
          multiple: false,
        });
        if (typeof selected === "string" && selected) {
          $("dec-keyfile").value = selected;
          setStatus("");
        }
      } catch (err) {
        setStatus(String(err), "error");
      }
    });
  }

  function setBusy(next) {
    busy = next;
    $("enc-run").disabled = busy;
    $("dec-run").disabled = busy;
  }

  $("encrypt-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (busy) return;

    clearLogs();
    setStatus(t("status.encrypting"));
    activeOpId = null;

    const vault_dir = $("enc-vault-dir").value;
    const output_file = $("enc-output-file").value;
    const keyfile = $("enc-keyfile").value;
    const force = $("enc-force").checked;

    let password = $("enc-password").value;
    let password_confirm = $("enc-password-confirm").value;

    const err1 = validateAbsolutePath("vaultDir", vault_dir);
    const err2 = validateAbsolutePath("outputFile", output_file);
    const err3 = keyfile ? validateAbsolutePath("keyfile", keyfile) : null;
    const errP = validatePassword(password);
    const errPC = validatePassword(password_confirm);
    if (err1 || err2 || err3 || errP || errPC) {
      setStatus(err1 || err2 || err3 || errP || errPC, "error");
      return;
    }
    if (password !== password_confirm) {
      setStatus(t("validation.passwordsNoMatch"), "error");
      return;
    }

    $("enc-password").value = "";
    $("enc-password-confirm").value = "";

    setBusy(true);
    try {
      const result = await TAURI.core.invoke("encrypt_vault", {
        req: {
          vault_dir,
          output_file,
          keyfile: keyfile || null,
          force,
          password,
          password_confirm,
        },
      });

      activeOpId = result.id;
      if (result.exit_code === 0) {
        setStatus(t("status.encryptionSuccess", { path: result.resolved_output }), "ok");
      } else {
        setStatus(t("status.encryptionFailed", { code: result.exit_code ?? "unknown" }), "error");
      }
    } catch (err) {
      setStatus(String(err), "error");
    } finally {
      password = "";
      password_confirm = "";
      setBusy(false);
    }
  });

  $("decrypt-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (busy) return;

    clearLogs();
    setStatus(t("status.decrypting"));
    activeOpId = null;

    const input_file = $("dec-input-file").value;
    const output_dir = $("dec-output-dir").value;
    const keyfile = $("dec-keyfile").value;
    const force = $("dec-force").checked;
    const secure_delete = $("dec-secure-delete").checked;

    let password = $("dec-password").value;

    const err1 = validateAbsolutePath("inputFile", input_file);
    const err2 = validateAbsolutePath("outputDir", output_dir);
    const err3 = keyfile ? validateAbsolutePath("keyfile", keyfile) : null;
    const errP = validatePassword(password);
    if (err1 || err2 || err3 || errP) {
      setStatus(err1 || err2 || err3 || errP, "error");
      return;
    }

    $("dec-password").value = "";

    setBusy(true);
    try {
      const result = await TAURI.core.invoke("decrypt_vault", {
        req: {
          input_file,
          output_dir,
          keyfile: keyfile || null,
          force,
          secure_delete,
          password,
        },
      });

      activeOpId = result.id;
      if (result.exit_code === 0) {
        setStatus(t("status.decryptionSuccess", { path: result.resolved_output }), "ok");
      } else {
        setStatus(t("status.decryptionFailed", { code: result.exit_code ?? "unknown" }), "error");
      }
    } catch (err) {
      setStatus(String(err), "error");
    } finally {
      password = "";
      setBusy(false);
    }
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  let locale = getValidatedSavedLocale();
  const isFirstRun = !locale;
  if (!locale) {
    locale = getSupportedLocaleFromSystem();
  }
  await initLocale(locale, { persist: isFirstRun });
  const mainEl = document.getElementById("main-app");
  if (mainEl) mainEl.classList.add("ready");
  main().catch((e) => setStatus(String(e), "error"));
});
