// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-objdump とのデコーダ差分（層4・oracle）。
//!
//! 手順は検証戦略の層4に従う。llvm-mc で組み立てた命令語を
//! polyisa のデコーダで読み、有効な命令になることを確かめる。
//! ニーモニックの厳密な一致は逆アセンブラの operand 対応の後に行う。
//! ツールがなければスキップして通す（オラクル不足は未実行扱い）。
//!
//! 使う外部ツールは台帳 TOOL-LLVM（用途X・確認済み）。
//! テストデータは使わない.

use std::process::{Command, Stdio};

fn bin(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

/// llvm-mc の `--show-encoding` 出力から `encoding: [...]` のバイト列を取り出す.
fn mc_encode(mc: &str, asm: &str) -> Option<Vec<u8>> {
    let mut child = Command::new(mc)
        .args([
            "--arch=riscv64",
            "--mattr=+m,+a,+f,+d,+c",
            "--show-encoding",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    use std::io::Write as _;
    child.stdin.as_mut()?.write_all(asm.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let start = text.find("encoding: [")?;
    let rest = &text[start + "encoding: [".len()..];
    let end = rest.find(']')?;
    let mut bytes = Vec::new();
    for tok in rest[..end].split(',') {
        let tok = tok.trim().trim_start_matches("0x");
        if tok.is_empty() {
            continue;
        }
        bytes.push(u8::from_str_radix(tok, 16).ok()?);
    }
    if bytes.is_empty() { None } else { Some(bytes) }
}

#[test]
fn llvm_oracle_spot_checks() {
    let Some(mc) = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"]) else {
        eprintln!("skip: llvm-mc がないため未実行");
        return;
    };
    // 代表命令。いずれも RV64GC で有効なはずである。
    for asm in [
        "add x1, x2, x3\n",
        "lw x1, 0(x2)\n",
        "fld f1, 0(x2)\n",
        "c.addi x1, 1\n",
    ] {
        let Some(bytes) = mc_encode(&mc, asm) else {
            eprintln!("skip: 組み立てに失敗 ({asm:?})");
            return;
        };
        let (w, len) = if bytes.len() == 2 {
            (u16::from_le_bytes([bytes[0], bytes[1]]) as u128, 16)
        } else if bytes.len() == 4 {
            (
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u128,
                32,
            )
        } else {
            eprintln!("skip: 想定外の長さ ({asm:?} len={})", bytes.len());
            return;
        };
        assert!(
            polyisa_guest_riscv::decode(w, len).is_some(),
            "llvm は有効だが polyisa が無効: {asm:?} word={w:#x}"
        );
    }
}
