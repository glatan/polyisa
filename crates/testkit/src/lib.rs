// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! テスト用の部品。擬似乱数、性質テストの実行器、SHA-256、オラクル呼び出し。
//!
//! 本番コードからは `dev-dependencies` でのみ使う。外部クレートに依存しない。

#![forbid(unsafe_code)]

pub mod rng;
pub mod sha256;

use std::path::Path;

/// テストベクタのバイト列を読み込む。存在しないときはエラーを返す。
pub fn load_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

/// ファイルの SHA-256 が期待値と一致することを確かめる。
pub fn verify_sha256(path: &Path, expected_hex: &str) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let got = sha256::digest(&data);
    let got_hex = hex(&got);
    if got_hex == expected_hex.to_ascii_lowercase() {
        Ok(())
    } else {
        Err(format!(
            "{}: sha256 mismatch: got {got_hex}, want {expected_hex}",
            path.display()
        ))
    }
}

/// バイト列を小文字の 16 進文字列にする。
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// 外部ツールを別プロセスで実行する。オラクル用途に限る。
/// ツールが存在しないときは `Err` を返し、呼び出し側がテストを「未実行」にする。
pub fn run_oracle(
    program: &str,
    args: &[&str],
    stdin_bytes: &[u8],
) -> Result<std::process::Output, String> {
    use std::io::Write as _;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| format!("{program}: no stdin"))?
        .write_all(stdin_bytes)
        .map_err(|e| format!("{program}: stdin: {e}"))?;
    child
        .wait_with_output()
        .map_err(|e| format!("{program}: {e}"))
}

/// 性質テストを指定の種と件数で実行する。失敗した事例番号を返す。
pub fn run_property<F>(seed: u64, cases: u32, mut f: F) -> Vec<u32>
where
    F: FnMut(&mut rng::Rng, u32) -> bool,
{
    let mut rng = rng::Rng::new(seed);
    let mut failed = Vec::new();
    for i in 0..cases {
        if !f(&mut rng, i) {
            failed.push(i);
        }
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_cases() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0xff, 0xab]), "00ffab");
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(&sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn run_oracle_missing_tool_is_err() {
        let r = run_oracle("polyisa-no-such-tool-xyz", &[], b"");
        assert!(r.is_err());
    }

    #[test]
    fn run_oracle_true() {
        let out = run_oracle("true", &[], b"").expect("true should exist");
        assert!(out.status.success());
    }
}
