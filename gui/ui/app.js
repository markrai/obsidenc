function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element: ${id}`);
  return el;
}

function setStatus(message, kind = "") {
  const status = $("status");
  status.textContent = message;
  status.className = `status${kind ? ` ${kind}` : ""}`;
}

function appendLog(line) {
  const out = $("log-output");
  out.textContent += line + "\n";
  out.scrollTop = out.scrollHeight;
}

function clearLogs() {
  $("log-output").textContent = "";
}

function validateAbsolutePath(label, value) {
  if (!value || value.trim() === "") return `${label} is required`;
  const v = value.trim();
  const isWindowsAbs = /^[a-zA-Z]:\\/.test(v) || /^\\\\/.test(v);
  const isUnixAbs = v.startsWith("/");
  if (!isWindowsAbs && !isUnixAbs) return `${label} must be an absolute path`;
  return null;
}

function validatePassword(value) {
  if (!value) return "Password is required";
  if (value.includes("\n") || value.includes("\r") || value.includes("\0")) return "Password contains invalid characters";
  if ([...value].length < 20) return "Password must be at least 20 characters";
  return null;
}

async function main() {
  const TAURI = window.__TAURI__;
  if (!TAURI || !TAURI.core || !TAURI.event) {
    setStatus("Tauri API not available (withGlobalTauri must be enabled).", "error");
    return;
  }

  let activeOpId = null;
  let busy = false;

  await TAURI.event.listen("obsidenc/log", (event) => {
    const payload = event.payload;
    if (!payload) return;
    if (activeOpId === null) activeOpId = payload.id;
    if (payload.id !== activeOpId) return;
    appendLog(`[${payload.stream}] ${payload.line}`);
  });

  for (const btn of document.querySelectorAll(".tab")) {
    btn.addEventListener("click", () => {
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

  // Browse for vault directory (encrypt)
  const vaultBrowseBtn = document.getElementById("enc-vault-browse");
  if (vaultBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    vaultBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: "Select vault directory",
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

  // Browse for output file (encrypt)
  const outputBrowseBtn = document.getElementById("enc-output-browse");
  if (outputBrowseBtn && TAURI.dialog && (TAURI.dialog.save || TAURI.dialog.open)) {
    outputBrowseBtn.addEventListener("click", async () => {
      try {
        // Prefer the native 'save' dialog when available so the user can
        // choose both folder and filename for a new archive.
        let selected;
        if (TAURI.dialog.save) {
          selected = await TAURI.dialog.save({
            title: "Choose output file",
          });
        } else {
          // Fallback to open dialog if save is not available
          selected = await TAURI.dialog.open({
            title: "Select output file",
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

  // Browse for keyfile (encrypt)
  const keyfileBrowseBtn = document.getElementById("enc-keyfile-browse");
  if (keyfileBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    keyfileBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: "Select keyfile",
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

  // Browse for input file (decrypt)
  const decInputBrowseBtn = document.getElementById("dec-input-browse");
  if (decInputBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    decInputBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: "Select input file",
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

  // Browse for output directory (decrypt)
  const decOutputBrowseBtn = document.getElementById("dec-output-browse");
  if (decOutputBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    decOutputBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: "Select output directory",
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

  // Browse for keyfile (decrypt)
  const decKeyfileBrowseBtn = document.getElementById("dec-keyfile-browse");
  if (decKeyfileBrowseBtn && TAURI.dialog && TAURI.dialog.open) {
    decKeyfileBrowseBtn.addEventListener("click", async () => {
      try {
        const selected = await TAURI.dialog.open({
          title: "Select keyfile",
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
    setStatus("Encrypting…");
    activeOpId = null;

    const vault_dir = $("enc-vault-dir").value;
    const output_file = $("enc-output-file").value;
    const keyfile = $("enc-keyfile").value;
    const force = $("enc-force").checked;

    let password = $("enc-password").value;
    let password_confirm = $("enc-password-confirm").value;

    const err1 = validateAbsolutePath("Vault directory", vault_dir);
    const err2 = validateAbsolutePath("Output file", output_file);
    const err3 = keyfile ? validateAbsolutePath("Keyfile", keyfile) : null;
    const errP = validatePassword(password);
    const errPC = validatePassword(password_confirm);
    if (err1 || err2 || err3 || errP || errPC) {
      setStatus(err1 || err2 || err3 || errP || errPC, "error");
      return;
    }
    if (password !== password_confirm) {
      setStatus("Passwords did not match.", "error");
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
        setStatus(`Encryption successful: ${result.resolved_output}`, "ok");
      } else {
        setStatus(`Encryption failed (exit code: ${result.exit_code ?? "unknown"})`, "error");
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
    setStatus("Decrypting…");
    activeOpId = null;

    const input_file = $("dec-input-file").value;
    const output_dir = $("dec-output-dir").value;
    const keyfile = $("dec-keyfile").value;
    const force = $("dec-force").checked;
    const secure_delete = $("dec-secure-delete").checked;

    let password = $("dec-password").value;

    const err1 = validateAbsolutePath("Input file", input_file);
    const err2 = validateAbsolutePath("Output directory", output_dir);
    const err3 = keyfile ? validateAbsolutePath("Keyfile", keyfile) : null;
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
        setStatus(`Decryption successful: ${result.resolved_output}`, "ok");
      } else {
        setStatus(`Decryption failed (exit code: ${result.exit_code ?? "unknown"})`, "error");
      }
    } catch (err) {
      setStatus(String(err), "error");
    } finally {
      password = "";
      setBusy(false);
    }
  });
}

window.addEventListener("DOMContentLoaded", () => {
  main().catch((e) => setStatus(String(e), "error"));
});

