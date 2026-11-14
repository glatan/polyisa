// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-objdump とのデコーダ差分（層4・oracle）。
//!
//! 手順は検証戦略の層4に従う。llvm-mc で組み立てた命令語を
//! polyisa のデコーダで読み、有効な命令になることを確かめる。
//! ニーモニックの厳密な一致は逆アセンブラの operand 対応の後に行う。
//! ツールがなければ `devtool test:plan` がこのバイナリを実行対象から外す。
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
        .args(["--arch=aarch64", "--show-encoding"])
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
    let mc = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"])
        .expect("llvm-mc がない（未実行の決定は devtool test:plan が担う）");
    // 代表命令。いずれも Armv8.0-A の整数命令で有効なはずである。
    for asm in [
        "add x1, x2, x3\n",
        "add w4, w5, w6, lsl #8\n",
        "sub x7, x8, x9\n",
        "subs x10, x11, #0x123\n",
        "and x12, x13, #0xff00ff00ff00ff00\n",
        "orr w14, w15, #0xffff0000\n",
        "movz x16, #0x1234, lsl #16\n",
        "movn w17, #0x5\n",
        "movk x18, #0x9abc\n",
        "adr x19, #0x40\n",
        "adrp x20, #0x1000\n",
        "b #0x20\n",
        "bl #0x24\n",
        "b.eq #0x28\n",
        "cbz x21, #0x2c\n",
        "cbnz w22, #0x30\n",
        "tbz x23, #5, #0x34\n",
        "tbnz w24, #7, #0x38\n",
        "ret\n",
        "br x25\n",
        "blr x26\n",
        "csel x27, x28, x29, ne\n",
        "cset w30, eq\n",
        "madd x1, x2, x3, x4\n",
        "mul x5, x6, x7\n",
        "sdiv x8, x9, x10\n",
        "udiv w11, w12, w13\n",
        "ubfx x14, x15, #4, #12\n",
        "sbfiz x16, x17, #8, #16\n",
        "extr x18, x19, x20, #6\n",
        "lsl x21, x22, x23\n",
        "lsr w24, w25, w26\n",
        "ldr x27, [x28, #8]\n",
        "ldr w29, [x30, #4]\n",
        "ldrb w1, [x2, x3]\n",
        "str x4, [sp, #-16]!\n",
        "ldr x5, [x6], #8\n",
        "ldp x7, x8, [x9, #16]\n",
        "stp x10, x11, [sp, #-32]!\n",
        "ldxr x12, [x13]\n",
        "stxr w14, x15, [x16]\n",
        "cmp x17, x18\n",
        "ccmp x19, x20, #0x5, lt\n",
        "svc #0\n",
        "nop\n",
        "mrs x21, tpidr_el0\n",
    ] {
        let Some(bytes) = mc_encode(&mc, asm) else {
            panic!("llvm-mc での組み立てに失敗 ({asm:?})");
        };
        assert_eq!(bytes.len(), 4, "A64 の命令は 4 バイト ({asm:?})");
        let w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert!(
            polyisa_guest_aarch64::decode(u128::from(w), 32).is_some(),
            "llvm は有効だが polyisa が無効: {asm:?} word={w:#x}"
        );
    }
}
