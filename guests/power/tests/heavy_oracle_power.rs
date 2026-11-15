// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-mc とのデコーダ差分（層4・oracle、S8-3）。
//!
//! llvm-mc で組み立てた命令語を polyisa のデコーダで読み、正しい
//! 主オペコード領域の Insn になることを確かめる。デコーダは主
//! オペコードの粗分類で、XO・拡張ビットの細分は意味論側の仕事。
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
/// fixup を含む行は `0bAAAA...` を返すので None にして外す。
fn mc_encode(mc: &str, asm: &str) -> Option<Vec<u8>> {
    let mut child = Command::new(mc)
        .args(["-triple=powerpc64le", "--show-encoding"])
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

/// ppc64le の命令語はメモリではリトルエンディアン。
fn word_of(bytes: &[u8]) -> u32 {
    assert_eq!(bytes.len(), 4, "Power は固定 32 ビット");
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[test]
fn llvm_oracle_spot_checks() {
    let mc = bin(&["llvm-mc", "/usr/sbin/llvm-mc", "/usr/bin/llvm-mc"])
        .expect("llvm-mc がない（未実行の決定は devtool test:plan が担う）");
    use polyisa_guest_power::Insn::*;
    // 代表命令。組み立てた語が対応する領域で受理されることを見る。
    // `b 0x10`・`bfa` は絶対番地（fixup なし）で出す。相対分岐は
    // リロケーションが残りバイト列が確定しないので対象外。
    for (asm, want) in [
        ("tdi 0, 3, 4\n", Tdi),
        ("twi 0, 3, 4\n", Twi),
        ("vperm 0,1,2,3\n", X4),
        ("mulli 3,4,5\n", Mulli),
        ("subfic 3,4,5\n", Subfic),
        ("cmpldi 3,5\n", Cmpli),
        ("cmpdi 3,5\n", Cmpwi),
        ("addic 3,4,5\n", Addic),
        ("addic. 3,4,5\n", AddicRc),
        ("addi 3,4,5\n", Addi),
        ("addis 3,4,5\n", Addis),
        ("bfa 10, 0x10\n", Bc),
        ("sc\n", Sc),
        ("b 0x10\n", B),
        ("blr\n", X19),
        ("bctr\n", X19),
        ("crand 4,5,6\n", X19),
        ("isync\n", X19),
        ("mcrf 2,3\n", X19),
        ("rlwimi 3,4,8,16,23\n", Rlwimi),
        ("rlwinm 3,4,8,0,31\n", Rlwinm),
        ("rlwnm 3,4,5,0,31\n", Rlwnm),
        ("ori 3,4,5\n", Ori),
        ("oris 3,4,5\n", Oris),
        ("xori 3,4,5\n", Xori),
        ("xoris 3,4,5\n", Xoris),
        ("andi. 3,4,5\n", AndiRc),
        ("andis. 3,4,5\n", AndisRc),
        ("rldicl 3,4,8,0\n", X30),
        ("rldicr 3,4,8,63\n", X30),
        ("rldimi 3,4,8,16\n", X30),
        ("add 3,4,5\n", X31),
        ("subf 3,4,5\n", X31),
        ("lwzx 3,4,5\n", X31),
        ("stwx 3,4,5\n", X31),
        ("lwarx 3,4,5\n", X31),
        ("stwcx. 3,4,5\n", X31),
        ("mfctr 3\n", X31),
        ("mfcr 3\n", X31),
        ("dcbz 4,5\n", X31),
        ("ldarx 3,4,5\n", X31),
        ("sync 0\n", X31),
        ("cmp 0,0,3,4\n", X31),
        ("cmpl 0,1,3,4\n", X31),
        ("mulld 3,4,5\n", X31),
        ("divd 3,4,5\n", X31),
        ("mtfprd 1, 3\n", X31),
        ("lxvd2x 34, 4, 5\n", X31),
        ("lxvw4x 34, 4, 5\n", X31),
        ("stxvd2x 34, 4, 5\n", X31),
        ("lxvrbx 34, 4, 5\n", X31),
        ("stxvb16x 34, 4, 5\n", X31),
        ("lwz 3,8(4)\n", Lwz),
        ("lwzu 3,8(4)\n", Lwzu),
        ("lbz 3,8(4)\n", Lbz),
        ("lbzu 3,8(4)\n", Lbzu),
        ("stw 3,8(4)\n", Stw),
        ("stwu 3,8(4)\n", Stwu),
        ("stb 3,8(4)\n", Stb),
        ("stbu 3,8(4)\n", Stbu),
        ("lhz 3,8(4)\n", Lhz),
        ("lhzu 3,8(4)\n", Lhzu),
        ("lha 3,8(4)\n", Lha),
        ("lhau 3,8(4)\n", Lhau),
        ("sth 3,8(4)\n", Sth),
        ("sthu 3,8(4)\n", Sthu),
        ("lmw 3,8(4)\n", Lmw),
        ("stmw 3,8(4)\n", Stmw),
        ("lfs 1,8(4)\n", Lfs),
        ("lfsu 1,8(4)\n", Lfsu),
        ("lfd 1,8(4)\n", Lfd),
        ("lfdu 1,8(4)\n", Lfdu),
        ("stfs 1,8(4)\n", Stfs),
        ("stfsu 1,8(4)\n", Stfsu),
        ("stfd 1,8(4)\n", Stfd),
        ("stfdu 1,8(4)\n", Stfdu),
        ("ld 3,8(4)\n", X58),
        ("ldu 3,8(4)\n", X58),
        ("lwa 3,8(4)\n", X58),
        ("fadds 1,2,3\n", X59),
        ("fsubs 1,2,3\n", X59),
        ("xsadddp 1,2,3\n", X60),
        ("xxlor 1,2,3\n", X60),
        ("xxpermdi 34, 35, 36, 0\n", X60),
        ("xxspltw 34, 35, 2\n", X60),
        ("xscvdpsp 34, 35\n", X60),
        ("xsmaxjdp 34, 35, 36\n", X60),
        ("std 3,8(4)\n", X62),
        ("stdu 3,8(4)\n", X62),
        ("stq 4,8(4)\n", X62), // stq は偶数レジスタ指定。
        ("fadd 1,2,3\n", X63),
        ("fmadd 1,2,3,4\n", X63),
        ("mffs 1\n", X63),
        ("fcmpu 2,1,3\n", X63),
        ("fctid 1,2\n", X63),
    ] {
        let bytes = mc_encode(&mc, asm).unwrap_or_else(|| panic!("llvm-mc が {asm:?} を組めない"));
        let word = word_of(&bytes);
        let got = polyisa_guest_power::decode(u128::from(word), 32);
        assert_eq!(
            got,
            Some(want),
            "{asm:?}（語 {word:#010x}）のデコードが食い違う"
        );
    }
}

/// llvm-mc 23 は `lxv`/`stxv`（op61）と `lq`（op56）のニーモニックを
/// 出せないので、これらは主オペコードを手で立てた語で領域だけ確かめる。
#[test]
fn hand_words_cover_regions_llvm_cannot_emit() {
    use polyisa_guest_power::Insn::*;
    for (word, want) in [
        (56u32 << 26, X56), // lq 相当の領域。
        (61u32 << 26, X61), // lxv/stxv 相当の領域。
    ] {
        let got = polyisa_guest_power::decode(u128::from(word), 32);
        assert_eq!(got, Some(want), "語 {word:#010x} のデコードが食い違う");
    }
}
