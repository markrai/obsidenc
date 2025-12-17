use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use tauri::{
    async_runtime::{channel, Mutex, Sender},
    AppHandle, Emitter, State,
};
use zeroize::Zeroizing;

const MIN_PASSWORD_CHARS: usize = 20;

#[derive(Default)]
pub struct ObsidencState {
    op_lock: Mutex<()>,
    next_id: AtomicU64,
}

#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub vault_dir: String,
    pub output_file: String,
    pub keyfile: Option<String>,
    pub force: bool,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    pub input_file: String,
    pub output_dir: String,
    pub keyfile: Option<String>,
    pub force: bool,
    pub secure_delete: bool,
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    pub id: u64,
    pub stream: String,
    pub line: String,
}

#[derive(Debug, Serialize)]
pub struct RunResult {
    pub id: u64,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub resolved_output: String,
}

#[derive(Debug)]
enum ProcEvent {
    Stdout(String),
    Stderr(String),
    Error(String),
    Terminated(Option<i32>),
}

fn validate_no_nul_or_newlines(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} is required"));
    }
    if value.contains('\0') {
        return Err(format!("{field} contains NUL"));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("{field} contains a newline"));
    }
    Ok(())
}

fn validate_password(field: &str, password: &str) -> Result<(), String> {
    validate_no_nul_or_newlines(field, password)?;
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "{} must be at least {} characters",
            field, MIN_PASSWORD_CHARS
        ));
    }
    Ok(())
}

fn require_absolute_path(field: &str, path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{field} must be an absolute path"));
    }
    Ok(())
}

fn reject_symlink(field: &str, path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("failed to stat {field}: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{field} must not be a symlink"));
    }
    Ok(())
}

fn sanitize_existing_dir(field: &str, raw: &str) -> Result<PathBuf, String> {
    validate_no_nul_or_newlines(field, raw)?;
    let path = PathBuf::from(raw);
    require_absolute_path(field, &path)?;
    reject_symlink(field, &path)?;
    let meta = fs::metadata(&path).map_err(|e| format!("failed to stat {field}: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("{field} must be a directory"));
    }
    fs::canonicalize(&path).map_err(|e| format!("failed to canonicalize {field}: {e}"))
}

fn sanitize_existing_file(field: &str, raw: &str) -> Result<PathBuf, String> {
    validate_no_nul_or_newlines(field, raw)?;
    let path = PathBuf::from(raw);
    require_absolute_path(field, &path)?;
    reject_symlink(field, &path)?;
    let meta = fs::metadata(&path).map_err(|e| format!("failed to stat {field}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{field} must be a regular file"));
    }
    fs::canonicalize(&path).map_err(|e| format!("failed to canonicalize {field}: {e}"))
}

fn sanitize_output_path(field: &str, raw: &str) -> Result<PathBuf, String> {
    validate_no_nul_or_newlines(field, raw)?;
    let raw = raw.trim_end_matches(|c| c == '\\' || c == '/');
    if raw.is_empty() {
        return Err(format!("{field} is required"));
    }
    let path = PathBuf::from(raw);
    require_absolute_path(field, &path)?;

    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{field} must include a final path component"))?
        .to_owned();
    if file_name == "." || file_name == ".." {
        return Err(format!("{field} must not end with '.' or '..'"));
    }

    let parent = path
        .parent()
        .ok_or_else(|| format!("{field} must have a parent directory"))?;
    reject_symlink(&format!("{field} parent"), parent)?;
    let meta = fs::metadata(parent).map_err(|e| format!("failed to stat {field} parent: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("{field} parent must be a directory"));
    }

    let canonical_parent = fs::canonicalize(parent)
        .map_err(|e| format!("failed to canonicalize {field} parent: {e}"))?;
    Ok(canonical_parent.join(file_name))
}

fn ensure_oen_extension(output_file: &mut PathBuf) {
    let has_oen = output_file
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("oen"));
    if !has_oen {
        output_file.set_extension("oen");
    }
}

fn append_limited(buf: &mut String, chunk: &str, max: usize) {
    if buf.len() >= max {
        return;
    }
    let remaining = max - buf.len();
    if chunk.len() <= remaining {
        buf.push_str(chunk);
    } else {
        buf.push_str(&chunk[..remaining]);
    }
}

fn sidecar_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("failed to resolve current_exe: {e}"))?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| "current_exe has no parent directory".to_string())?;
    let mut sidecar = exe_dir.join("obsidenc");
    if cfg!(windows) {
        sidecar.set_extension("exe");
    }
    Ok(sidecar)
}

fn spawn_pipe_reader<F>(reader: impl Read + Send + 'static, tx: Sender<ProcEvent>, wrap: F)
where
    F: Fn(String) -> ProcEvent + Send + Copy + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    if buf.last() == Some(&b'\n') {
                        buf.pop();
                        if buf.last() == Some(&b'\r') {
                            buf.pop();
                        }
                    }
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    let _ = tx.blocking_send(wrap(line));
                }
                Err(e) => {
                    let _ = tx.blocking_send(ProcEvent::Error(format!(
                        "I/O error reading child output: {e}"
                    )));
                    break;
                }
            }
        }
    });
}

async fn run_obsidenc(
    app: &AppHandle,
    id: u64,
    args: Vec<std::ffi::OsString>,
    stdin_bytes: Zeroizing<Vec<u8>>,
    resolved_output: String,
) -> Result<RunResult, String> {
    let sidecar = sidecar_path()?;
    let meta = fs::metadata(&sidecar)
        .map_err(|e| format!("obsidenc sidecar not found at {}: {e}", sidecar.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "obsidenc sidecar is not a file: {}",
            sidecar.display()
        ));
    }

    let mut command = Command::new(&sidecar);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn obsidenc sidecar: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_bytes.as_slice())
            .map_err(|e| format!("failed to write to obsidenc stdin: {e}"))?;
    } else {
        return Err("failed to open obsidenc stdin".into());
    }
    drop(stdin_bytes);

    let stdout_pipe = child.stdout.take().ok_or("failed to capture stdout")?;
    let stderr_pipe = child.stderr.take().ok_or("failed to capture stderr")?;

    let (tx, mut rx) = channel::<ProcEvent>(100);
    spawn_pipe_reader(stdout_pipe, tx.clone(), ProcEvent::Stdout);
    spawn_pipe_reader(stderr_pipe, tx.clone(), ProcEvent::Stderr);

    thread::spawn(move || {
        let status = child.wait();
        let _ = match status {
            Ok(s) => tx.blocking_send(ProcEvent::Terminated(s.code())),
            Err(e) => tx.blocking_send(ProcEvent::Error(format!("failed waiting for child: {e}"))),
        };
    });

    const MAX_CAPTURE: usize = 256 * 1024;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code = None;

    while let Some(event) = rx.recv().await {
        match event {
            ProcEvent::Stdout(text) => {
                let _ = app.emit(
                    "obsidenc/log",
                    LogEvent {
                        id,
                        stream: "stdout".into(),
                        line: text.clone(),
                    },
                );
                append_limited(&mut stdout, &text, MAX_CAPTURE);
                append_limited(&mut stdout, "\n", MAX_CAPTURE);
            }
            ProcEvent::Stderr(text) => {
                let _ = app.emit(
                    "obsidenc/log",
                    LogEvent {
                        id,
                        stream: "stderr".into(),
                        line: text.clone(),
                    },
                );
                append_limited(&mut stderr, &text, MAX_CAPTURE);
                append_limited(&mut stderr, "\n", MAX_CAPTURE);
            }
            ProcEvent::Error(message) => {
                let _ = app.emit(
                    "obsidenc/log",
                    LogEvent {
                        id,
                        stream: "error".into(),
                        line: message.clone(),
                    },
                );
                append_limited(&mut stderr, &message, MAX_CAPTURE);
                append_limited(&mut stderr, "\n", MAX_CAPTURE);
            }
            ProcEvent::Terminated(code) => {
                exit_code = code;
            }
        }
    }

    Ok(RunResult {
        id,
        exit_code,
        stdout,
        stderr,
        resolved_output,
    })
}

#[tauri::command]
pub async fn encrypt_vault(
    app: AppHandle,
    state: State<'_, ObsidencState>,
    mut req: EncryptRequest,
) -> Result<RunResult, String> {
    let _guard = state.op_lock.lock().await;
    let id = state.next_id.fetch_add(1, Ordering::Relaxed) + 1;

    let password = Zeroizing::new(std::mem::take(&mut req.password));
    let password_confirm = Zeroizing::new(std::mem::take(&mut req.password_confirm));

    validate_password("password", password.as_str())?;
    validate_password("password_confirm", password_confirm.as_str())?;
    if password.as_str() != password_confirm.as_str() {
        return Err("passwords did not match".into());
    }

    let vault_dir = sanitize_existing_dir("vault_dir", &req.vault_dir)?;
    let mut output_file = sanitize_output_path("output_file", &req.output_file)?;
    ensure_oen_extension(&mut output_file);

    if output_file.starts_with(&vault_dir) {
        return Err("output_file must not be inside vault_dir".into());
    }
    if output_file.exists() && !req.force {
        return Err("output_file already exists (enable force to overwrite)".into());
    }

    let keyfile = match req.keyfile.as_deref() {
        Some(k) if !k.is_empty() => Some(sanitize_existing_file("keyfile", k)?),
        _ => None,
    };

    let mut stdin_vec = Vec::with_capacity(password.len() + password_confirm.len() + 2);
    stdin_vec.extend_from_slice(password.as_bytes());
    stdin_vec.push(b'\n');
    stdin_vec.extend_from_slice(password_confirm.as_bytes());
    stdin_vec.push(b'\n');

    let mut args: Vec<std::ffi::OsString> = Vec::new();
    args.push("--password-stdin".into());
    args.push("encrypt".into());
    if req.force {
        args.push("--force".into());
    }
    if let Some(k) = keyfile {
        args.push("--keyfile".into());
        args.push(k.into_os_string());
    }
    args.push("--".into());
    args.push(vault_dir.into_os_string());
    args.push(output_file.clone().into_os_string());

    run_obsidenc(
        &app,
        id,
        args,
        Zeroizing::new(stdin_vec),
        output_file.to_string_lossy().into_owned(),
    )
    .await
}

#[tauri::command]
pub async fn decrypt_vault(
    app: AppHandle,
    state: State<'_, ObsidencState>,
    mut req: DecryptRequest,
) -> Result<RunResult, String> {
    let _guard = state.op_lock.lock().await;
    let id = state.next_id.fetch_add(1, Ordering::Relaxed) + 1;

    let password = Zeroizing::new(std::mem::take(&mut req.password));
    validate_password("password", password.as_str())?;

    let input_file = sanitize_existing_file("input_file", &req.input_file)?;
    let output_dir = sanitize_output_path("output_dir", &req.output_dir)?;

    if output_dir.exists() && !req.force {
        let is_empty_dir = output_dir.is_dir()
            && fs::read_dir(&output_dir)
                .map_err(|e| format!("failed to read output_dir: {e}"))?
                .next()
                .is_none();
        if !is_empty_dir {
            return Err("output_dir already exists (enable force to overwrite)".into());
        }
    }

    let keyfile = match req.keyfile.as_deref() {
        Some(k) if !k.is_empty() => Some(sanitize_existing_file("keyfile", k)?),
        _ => None,
    };

    let mut stdin_vec = Vec::with_capacity(password.len() + 1);
    stdin_vec.extend_from_slice(password.as_bytes());
    stdin_vec.push(b'\n');

    let mut args: Vec<std::ffi::OsString> = Vec::new();
    args.push("--password-stdin".into());
    args.push("decrypt".into());
    if req.force {
        args.push("--force".into());
    }
    if req.secure_delete {
        args.push("--secure-delete".into());
    }
    if let Some(k) = keyfile {
        args.push("--keyfile".into());
        args.push(k.into_os_string());
    }
    args.push("--".into());
    args.push(input_file.into_os_string());
    args.push(output_dir.clone().into_os_string());

    run_obsidenc(
        &app,
        id,
        args,
        Zeroizing::new(stdin_vec),
        output_dir.to_string_lossy().into_owned(),
    )
    .await
}
