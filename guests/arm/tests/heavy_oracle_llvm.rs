// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-mc とのデコーダ差分（層4・oracle、S7-3）。
//!
//! llvm-mc で組み立てた命令語を polyisa のデコーダで読み、有効な
//! 命令になることを確かめる。デコーダは領域の粗分類なので、一部は
//! Insn の領域まで突き合わせる。
//! ツールがなければ `devtool test:plan` がこのバイナリを実行対象から外す。
//!
//! 使う外部ツールは台帳 TOOL-LLVM（用途X・確認済み）。
//! テストデータは使わない。

use std::process::{Command, Stdio};

fn bin(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

/// llvm-mc の `--show-encoding` 出力から `encoding: [...]` のバイト列を取り出す。
fn mc_encode(mc: &str, asm: &str) -> Option<Vec<u8>> {
    let mut child = Command::new(mc)
        .args(["-triple=armv7", "--show-encoding"])
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

fn word_of(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[test]
fn llvm_oracle_spot_checks() {
    let mc = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"])
        .expect("llvm-mc がない（未実行の決定は devtool test:plan が担う）");
    // 代表命令。有効な語が領域のデコーダで受理されることを見る。
    for (asm, want) in [
        ("mov r0, r1\n", Some(polyisa_guest_arm::Insn::DpReg)),
        ("mov r0, #0x2a\n", Some(polyisa_guest_arm::Insn::DpImm)),
        (
            "add r1, r2, r3, lsl #4\n",
            Some(polyisa_guest_arm::Insn::DpReg),
        ),
        (
            "add r1, r2, r3, lsr r4\n",
            Some(polyisa_guest_arm::Insn::DpSreg),
        ),
        (
            "subeq r5, r6, #0x100\n",
            Some(polyisa_guest_arm::Insn::DpImm),
        ),
        ("cmp r7, r8\n", Some(polyisa_guest_arm::Insn::DpReg)),
        ("tst r9, #0xff\n", Some(polyisa_guest_arm::Insn::DpImm)),
        ("mul r0, r1, r2\n", Some(polyisa_guest_arm::Insn::Mul)),
        ("mla r0, r1, r2, r3\n", Some(polyisa_guest_arm::Insn::Mul)),
        (
            "umull r0, r1, r2, r3\n",
            Some(polyisa_guest_arm::Insn::Mull),
        ),
        (
            "smull r0, r1, r2, r3\n",
            Some(polyisa_guest_arm::Insn::Mull),
        ),
        ("swp r0, r1, [r2]\n", Some(polyisa_guest_arm::Insn::Swp)),
        ("ldrex r0, [r1]\n", Some(polyisa_guest_arm::Insn::Excl)),
        ("strex r0, r1, [r2]\n", Some(polyisa_guest_arm::Insn::Excl)),
        ("ldr r0, [r1, #4]\n", Some(polyisa_guest_arm::Insn::LsImm)),
        (
            "ldr r0, [r1, r2, lsl #2]\n",
            Some(polyisa_guest_arm::Insn::LsReg),
        ),
        ("str r0, [r1, #-8]!\n", Some(polyisa_guest_arm::Insn::LsImm)),
        ("ldrb r0, [r1], #2\n", Some(polyisa_guest_arm::Insn::LsImm)),
        ("ldrh r0, [r1, #2]\n", Some(polyisa_guest_arm::Insn::ElsH)),
        ("ldrsh r0, [r1]\n", Some(polyisa_guest_arm::Insn::ElsH)),
        ("ldrd r0, [r1, #8]\n", Some(polyisa_guest_arm::Insn::ElsD)),
        ("strh r0, [r1, #-4]!\n", Some(polyisa_guest_arm::Insn::ElsH)),
        (
            "ldmia r1!, {r0, r2, r4}\n",
            Some(polyisa_guest_arm::Insn::LdmStm),
        ),
        (
            "stmdb sp!, {r4, lr}\n",
            Some(polyisa_guest_arm::Insn::LdmStm),
        ),
        ("push {r0, lr}\n", Some(polyisa_guest_arm::Insn::LdmStm)),
        ("pop {r0, pc}\n", Some(polyisa_guest_arm::Insn::LdmStm)),
        ("b #0x20\n", Some(polyisa_guest_arm::Insn::B)),
        ("bl #0x24\n", Some(polyisa_guest_arm::Insn::Bl)),
        ("beq #0x28\n", Some(polyisa_guest_arm::Insn::B)),
        ("svc #0\n", Some(polyisa_guest_arm::Insn::Svc)),
        ("clz r0, r1\n", Some(polyisa_guest_arm::Insn::DpSreg)),
        ("bx lr\n", Some(polyisa_guest_arm::Insn::DpSreg)),
        ("blx r0\n", Some(polyisa_guest_arm::Insn::DpSreg)),
        ("movw r0, #0x1234\n", Some(polyisa_guest_arm::Insn::DpImm)),
        ("movt r0, #0x5678\n", Some(polyisa_guest_arm::Insn::DpImm)),
        ("uxtb r0, r1\n", Some(polyisa_guest_arm::Insn::Media)),
        (
            "ubfx r0, r1, #4, #8\n",
            Some(polyisa_guest_arm::Insn::Media),
        ),
        ("bfi r0, r1, #8, #8\n", Some(polyisa_guest_arm::Insn::Media)),
        ("nop\n", Some(polyisa_guest_arm::Insn::DpImm)),
        ("mrs r0, cpsr\n", Some(polyisa_guest_arm::Insn::DpReg)),
        ("msr cpsr_f, r0\n", Some(polyisa_guest_arm::Insn::DpReg)),
        ("vldr d0, [r1, #8]\n", Some(polyisa_guest_arm::Insn::CpLs)),
        ("vstr s0, [r1]\n", Some(polyisa_guest_arm::Insn::CpLs)),
        ("vldmia r1!, {d0-d3}\n", Some(polyisa_guest_arm::Insn::CpLs)),
        ("vpush {d0-d2}\n", Some(polyisa_guest_arm::Insn::CpLs)),
        ("vadd.f64 d0, d1, d2\n", Some(polyisa_guest_arm::Insn::CpDp)),
        ("vmul.f32 s0, s1, s2\n", Some(polyisa_guest_arm::Insn::CpDp)),
        ("vmov r0, s0\n", Some(polyisa_guest_arm::Insn::CpDp)),
        // MCRR（レジスタ対転送）は 110 帯の粗分類に入る。
        ("vmov d0, r0, r1\n", Some(polyisa_guest_arm::Insn::CpLs)),
        ("vcvt.f64.s32 d0, s0\n", Some(polyisa_guest_arm::Insn::CpDp)),
        ("vmrs r0, fpscr\n", Some(polyisa_guest_arm::Insn::CpDp)),
        (
            "mcr p15, 0, r0, c7, c10, 5\n",
            Some(polyisa_guest_arm::Insn::CpDp),
        ),
        (
            "mrc p15, 0, r0, c13, c0, 3\n",
            Some(polyisa_guest_arm::Insn::CpDp),
        ),
        // UDF は恒久的に未定義だが、粗分類ではメディア領域に入る。
        ("udf #0\n", Some(polyisa_guest_arm::Insn::Media)),
    ] {
        let Some(bytes) = mc_encode(&mc, asm) else {
            panic!("llvm-mc での組み立てに失敗 ({asm:?})");
        };
        assert_eq!(bytes.len(), 4, "A32 の命令は 4 バイト ({asm:?})");
        let w = word_of(&bytes);
        let got = polyisa_guest_arm::decode(u128::from(w), 32);
        assert_eq!(got, want, "{asm:?} word={w:#x}");
    }
}
