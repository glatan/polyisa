// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-mc とのデコーダ差分（層4・oracle、S11-3）。
//!
//! llvm-mc（systemz ターゲット）で組み立てた命令語を polyisa の
//! デコーダで読み、正しいクラス/名前の Insn になることを確かめる。
//! B2/B3/B9/E3/E5/EB/EC/ED のプレフィックス族は主オペコードの粗分類で、
//! 機能コードの細分は意味論側の仕事。
//! ツールがなければ `devtool test:plan` がこのバイナリを実行対象
//! から外す。
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
        .args(["-triple=s390x-ibm-linux", "--show-encoding"])
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

/// s390 の命令はメモリではビッグエンディアン。実行側と同じく
/// 右詰め u64 に畳んで `decode_model_ex` に渡す。
fn decode(bytes: &[u8]) -> Option<polyisa_guest_s390::Insn> {
    let mut word = 0u64;
    for &x in bytes {
        word = (word << 8) | u64::from(x);
    }
    polyisa_guest_s390::decode_model_ex(u128::from(word), (bytes.len() * 8) as u32, true, 0)
}

#[test]
fn llvm_oracle_spot_checks() {
    let mc = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"])
        .expect("llvm-mc がない（未実行の決定は devtool test:plan が担う）");
    use polyisa_guest_s390::Insn::*;
    // 代表命令。リロケーションを含まない絶対オペランドだけ使う。
    for (asm, want) in [
        ("ar %r2,%r3\n", Ar),
        ("sr %r2,%r3\n", Sr),
        ("cr %r2,%r3\n", Cr),
        ("clr %r2,%r3\n", Clr),
        ("lr %r2,%r3\n", Lr),
        ("nr %r2,%r3\n", Nr),
        ("or %r2,%r3\n", Or),
        ("xr %r2,%r3\n", Xr),
        ("alr %r2,%r3\n", Alr),
        ("slr %r2,%r3\n", Slr),
        ("mr %r2,%r3\n", Mr),
        ("dr %r2,%r3\n", Dr),
        ("balr %r14,%r7\n", Balr),
        ("basr %r14,%r7\n", Basr),
        ("bctr %r2,%r3\n", Bctr),
        ("bcr 15,%r14\n", Bcr),
        ("lpr %r2,%r3\n", Lpr),
        ("lcr %r2,%r3\n", Lcr),
        ("ltr %r2,%r3\n", Ltr),
        ("ldr %f0,%f2\n", Ldr),
        ("ler %f0,%f2\n", Ler),
        ("lcdbr %f0,%f2\n", B3),
        ("lpdbr %f0,%f2\n", B3),
        ("ltdbr %f0,%f2\n", B3),
        ("lcdr %f0,%f2\n", Lcdr),
        ("lpdr %f0,%f2\n", Lpdr),
        ("ltdr %f0,%f2\n", Ltdr),
        ("ldxr %f0,%f4\n", Ldxr),
        ("svc 0\n", Svc),
        ("mvcl %r2,%r4\n", Mvcl),
        ("clcl %r2,%r4\n", Clcl),
        ("spm %r2\n", Spm),
        // RX。
        ("l %r2,0(%r3)\n", L),
        ("st %r2,4(%r3)\n", St),
        ("lh %r2,0(%r3)\n", Lh),
        ("sth %r2,0(%r3)\n", Sth),
        ("ic %r2,0(%r3)\n", Ic),
        ("stc %r2,0(%r3)\n", Stc),
        ("la %r2,8(%r3,%r4)\n", La),
        ("c %r2,0(%r3)\n", C),
        ("cl %r2,0(%r3)\n", Cl),
        ("a %r2,0(%r3)\n", A),
        ("s %r2,0(%r3)\n", S),
        ("al %r2,0(%r3)\n", Al),
        ("sl %r2,0(%r3)\n", Sl),
        ("n %r2,0(%r3)\n", N),
        ("o %r2,0(%r3)\n", O),
        ("x %r2,0(%r3)\n", X),
        ("mh %r2,0(%r3)\n", Mh),
        ("ah %r2,0(%r3)\n", Ah),
        ("sh %r2,0(%r3)\n", Sh),
        ("ms %r2,0(%r3)\n", Ms),
        ("d %r2,0(%r3)\n", D),
        ("bct %r2,0(%r3)\n", Bct),
        ("bc 15,0(%r3)\n", Bc),
        ("bal %r14,0(%r3)\n", Bal),
        ("bas %r14,0(%r3)\n", Bas),
        ("ld %f0,0(%r3)\n", Ld),
        ("std %f0,0(%r3)\n", Std),
        ("le %f0,0(%r3)\n", Le),
        ("ste %f0,0(%r3)\n", Ste),
        // SI/RS/SS。
        ("cli 0(%r3),7\n", Cli),
        ("mvi 0(%r3),7\n", Mvi),
        ("ni 0(%r3),7\n", Ni),
        ("oi 0(%r3),7\n", Oi),
        ("xi 0(%r3),7\n", Xi),
        ("tm 0(%r3),7\n", Tm),
        ("stm %r2,%r5,0(%r3)\n", Stm),
        ("lm %r2,%r5,0(%r3)\n", Lm),
        ("icm %r2,10,0(%r3)\n", Icm),
        ("stcm %r2,10,0(%r3)\n", Stcm),
        ("clm %r2,10,0(%r3)\n", Clm),
        ("cs %r2,%r5,0(%r3)\n", Cs),
        ("mvc 0(8,%r3),0(%r4)\n", Mvc),
        ("clc 0(8,%r3),0(%r4)\n", Clc),
        ("oc 0(8,%r3),0(%r4)\n", Oc),
        ("xc 0(8,%r3),0(%r4)\n", Xc),
        ("nc 0(8,%r3),0(%r4)\n", Nc),
        ("tr 0(8,%r3),0(%r4)\n", Tr),
        ("mvn 0(8,%r3),0(%r4)\n", Mvn),
        // RI/RIL。
        ("lhi %r2,7\n", Lhi),
        ("lghi %r2,7\n", Lghi),
        ("ahi %r2,7\n", Ahi),
        ("aghi %r2,7\n", Aghi),
        ("chi %r2,7\n", Chi),
        ("cghi %r2,7\n", Cghi),
        ("mhi %r2,7\n", Mhi),
        ("mghi %r2,7\n", Mghi),
        ("brct %r2,0x100\n", Brct),
        ("brctg %r2,0x100\n", Brctg),
        ("larl %r2,0x100\n", Larl),
        ("brcl 15,0x100\n", Brcl),
        ("brasl %r14,0x100\n", Brasl),
        ("lgfi %r2,7\n", Lgfi),
        ("msgfi %r2,7\n", Msgfi),
        ("msfi %r2,7\n", Msfi),
        ("nilf %r2,15\n", Nilf),
        ("oill %r2,15\n", Oill),
        ("xilf %r2,15\n", Xilf),
        ("llilf %r2,15\n", Llilf),
        ("llihf %r2,15\n", Llihf),
        // プレフィックス族。
        ("lgr %r2,%r3\n", B9),
        ("lgfr %r2,%r3\n", B9),
        ("lmg %r2,%r5,0(%r3)\n", Eb),
        ("stmg %r2,%r5,0(%r3)\n", Eb),
        ("lg %r2,0(%r3)\n", E3),
        ("stg %r2,0(%r3)\n", E3),
        ("llgc %r2,0(%r3)\n", E3),
        ("llgh %r2,0(%r3)\n", E3),
        ("lay %r2,0(%r3)\n", E3),
        ("adbr %f0,%f2\n", B3),
        ("sdbr %f0,%f2\n", B3),
        ("mdbr %f0,%f2\n", B3),
        ("ddbr %f0,%f2\n", B3),
        ("cdbr %f0,%f2\n", B3),
        ("cdgbr %f0,%r2\n", B3),
        ("cgdbr %r2,5,%f0\n", B3),
        ("lgdr %r2,%f0\n", B3),
        ("ldgr %f0,%r2\n", B3),
        ("madbr %f0,%f2,%f4\n", B3),
        ("adb %f0,0(%r3)\n", Rxe),
        ("mdb %f0,0(%r3)\n", Rxe),
        ("cpsdr %f0,%f2,%f4\n", B3),
    ] {
        let enc = mc_encode(&mc, asm).unwrap_or_else(|| panic!("llvm-mc が {asm:?} を組めない"));
        let got = decode(&enc).unwrap_or_else(|| panic!("{asm:?} 非受理: {enc:?}"));
        assert_eq!(got, want, "{asm:?} -> {got:?} want {want:?}");
    }
}

#[test]
fn instruction_lengths_from_first_byte() {
    // 先頭バイトの上位 2 ビットで長さが決まる（00→2B, 01→4B, 10→4B, 11→6B）。
    // デコーダが渡すビット数の規約を、実際のエンコードで確認する。
    let mc = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"]).unwrap();
    for (asm, len) in [
        ("ar %r2,%r3\n", 2u8),
        ("l %r2,0(%r3)\n", 4),
        ("lghi %r2,7\n", 4),
        ("larl %r2,0x100\n", 6),
        ("stg %r2,0(%r3)\n", 6),
        ("mvc 0(8,%r3),0(%r4)\n", 6),
    ] {
        let enc = mc_encode(&mc, asm).unwrap();
        assert_eq!(enc.len() as u8, len, "{asm:?}");
        let want = match enc[0] >> 6 {
            0 => 2,
            1 | 2 => 4,
            _ => 6,
        };
        assert_eq!(want, len, "{asm:?} 先頭バイトの長さ規約");
    }
}
