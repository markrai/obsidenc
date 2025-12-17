use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

#[test]
fn encrypt_then_decrypt_mock_roundtrip() {
    // This test:
    // 1. Encrypts the files in test/mock into test/test.oen
    // 2. Decrypts test/test.oen into test/decrypt
    // 3. Verifies that all files in test/mock match the corresponding files in test/decrypt
    //
    // It never modifies the original mock data under test/mock.

    let root = project_root();
    let mock_dir = root.join("test").join("mock");
    assert!(
        mock_dir.is_dir(),
        "expected mock directory at {}",
        mock_dir.display()
    );

    let test_dir = root.join("test");
    let enc_file = test_dir.join("test.oen");
    let decrypt_dir = test_dir.join("decrypt");

    // Clean up any previous artifacts
    let _ = fs::remove_file(&enc_file);
    let _ = fs::remove_dir_all(&decrypt_dir);

    let password = "this is a very long password 12345";
    let bin = env!("CARGO_BIN_EXE_obsidenc");

    // 1. Encrypt mock_dir -> enc_file
    {
        let mut child = Command::new(bin)
            .arg("--password-stdin")
            .arg("encrypt")
            .arg(&mock_dir)
            .arg(&enc_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn obsidenc encrypt");

        {
            let mut stdin = child.stdin.take().expect("failed to open stdin");
            writeln!(stdin, "{password}").expect("failed to write password");
            writeln!(stdin, "{password}").expect("failed to write password confirmation");
        }

        let status = child.wait().expect("failed to wait on encrypt process");
        assert!(
            status.success(),
            "encrypt command failed with status {status}"
        );
        assert!(
            enc_file.is_file(),
            "expected encrypted file to be created at {}",
            enc_file.display()
        );
    }

    // 2. Decrypt enc_file -> decrypt_dir
    {
        let mut child = Command::new(bin)
            .arg("--password-stdin")
            .arg("decrypt")
            .arg(&enc_file)
            .arg(&decrypt_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn obsidenc decrypt");

        {
            let mut stdin = child.stdin.take().expect("failed to open stdin");
            writeln!(stdin, "{password}").expect("failed to write password");
        }

        let status = child.wait().expect("failed to wait on decrypt process");
        assert!(
            status.success(),
            "decrypt command failed with status {status}"
        );
        assert!(
            decrypt_dir.is_dir(),
            "expected decrypt directory to be created at {}",
            decrypt_dir.display()
        );
    }

    // 3. Compare files in mock_dir and decrypt_dir
    for entry in fs::read_dir(&mock_dir).expect("failed to read mock_dir") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.is_dir() {
            continue; // current mock data is flat; skip nested dirs just in case
        }

        let rel = path.strip_prefix(&mock_dir).expect("strip_prefix failed");
        let dec_path = decrypt_dir.join(rel);

        assert!(
            dec_path.is_file(),
            "expected decrypted file for {} at {}",
            rel.display(),
            dec_path.display()
        );

        let orig_bytes = read_file(&path);
        let dec_bytes = read_file(&dec_path);
        assert_eq!(
            orig_bytes, dec_bytes,
            "mismatch between original {} and decrypted {}",
            path.display(),
            dec_path.display()
        );
    }

    // 4. Clean up the encrypted artifact; keep mock and decrypt for inspection if needed.
    if let Err(e) = fs::remove_file(&enc_file) {
        eprintln!(
            "warning: failed to remove test artifact {}: {e}",
            enc_file.display()
        );
    }
}


