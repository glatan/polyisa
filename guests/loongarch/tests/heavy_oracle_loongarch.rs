// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-objdump とのデコード差分（層4・oracle、S19-3）。
//!
//! `.testdata/bin-distro-loongarch/bin/busybox`（Alpine 3.24
//! loongarch64 の動的リンク BusyBox、実在のコンパイラ出力）の
//! `.text` を llvm-objdump で逆アセンブルし、各行の命令語を
//! polyisa のデコーダ（la464 相当: la32+la64+lsx）で読んで
//! 正規形同士を照合する。
//!
//! 正規化の規則（テスト内コメントの表で固定）:
//! - レジスタ名はアーキ番号へ: `$a0`→`$r4` … `$s8`→`$r31`、
//!   `$fa0`→`$f0` … `$fs7`→`$f31`。
//! - エイリアス展開: `ret`→`jirl $r0, $r1, 0`、
//!   `jr $x`→`jirl $r0, $x, 0`、`move`→`or $rd, $rj, $r0`、
//!   `nop`→`andi $r0, $r0, 0`、
//!   `bltz/bgez/bgtz/blez`→`blt/bge/bgt/ble $rj, $r0, off`。
//! - 分岐即値はバイト単位（offs16 は語オフセットを <<2）。
//! - ll/sc/ldptr/stptr の si14 もバイト単位（<<2）。
//! - pcaddi/pcalau12i/pcaddu12i/lu12i/lu32i の si20 は
//!   符号付きフィールド値のまま。
//! - 分岐行の `<symbol+off>` 注記は捨てる。
//!
//! 使う外部ツールは台帳 TOOL-LLVM（用途X・確認済み）。
//! ツールがなければ devtool test:plan がこのバイナリを外す。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-loongarch/bin/busybox");
    assert!(
        p.is_file(),
        "BIN-DISTRO-LOONGARCH の busybox を {} に置く。リポジトリには含めない。",
        p.display()
    );
    p
}

fn objdump() -> String {
    for c in [
        "llvm-objdump",
        "/usr/sbin/llvm-objdump",
        "/usr/bin/llvm-objdump",
    ] {
        if Command::new(c).arg("--version").output().is_ok() {
            return c.to_string();
        }
    }
    panic!("llvm-objdump がない（未実行の決定は devtool test:plan が担う）");
}

/// `(語, ニーモニック, オペランド列)` を llvm-objdump から拾う。
fn objdump_lines(bin: &str, path: &PathBuf) -> Vec<(u32, String, String)> {
    let out = Command::new(bin)
        .arg("-d")
        .arg(path)
        .output()
        .expect("llvm-objdump を起動");
    assert!(out.status.success(), "llvm-objdump が失敗");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        // "   5c20: 2e 1d 00 1c  \tpcaddu12i\t$t2, 233" の形。
        let Some(colon) = line.find(':') else {
            continue;
        };
        if !line[..colon].trim().chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let rest = &line[colon + 1..];
        let mut it = rest.split_whitespace();
        let mut bytes = Vec::new();
        while let Some(tok) = it.next() {
            if tok.len() == 2 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
                bytes.push(u8::from_str_radix(tok, 16).unwrap());
            } else {
                // 命令の表記開始。残り全部がニーモニック＋オペランド。
                let tail: Vec<&str> = std::iter::once(tok).chain(it).collect();
                let insn_text = tail.join(" ");
                let (mn, ops) = match insn_text.split_once(char::is_whitespace) {
                    Some((m, o)) => (m.trim().to_string(), o.trim().to_string()),
                    None => (insn_text.clone(), String::new()),
                };
                if bytes.len() == 4 {
                    let w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    rows.push((w, mn, ops));
                }
                break;
            }
        }
    }
    rows
}

/// 汎用レジスタの ABI 別名 → 番号。
fn gr_alias(name: &str) -> Option<u64> {
    Some(match name {
        "zero" => 0,
        "ra" => 1,
        "tp" => 2,
        "sp" => 3,
        "a0" => 4,
        "a1" => 5,
        "a2" => 6,
        "a3" => 7,
        "a4" => 8,
        "a5" => 9,
        "a6" => 10,
        "a7" => 11,
        "t0" => 12,
        "t1" => 13,
        "t2" => 14,
        "t3" => 15,
        "t4" => 16,
        "t5" => 17,
        "t6" => 18,
        "t7" => 19,
        "t8" => 20,
        "x" => 21,
        "fp" => 22,
        "s0" => 23,
        "s1" => 24,
        "s2" => 25,
        "s3" => 26,
        "s4" => 27,
        "s5" => 28,
        "s6" => 29,
        "s7" => 30,
        "s8" => 31,
        _ => return None,
    })
}

/// FP レジスタの ABI 別名 → 番号（fa0-7=f0-7、ft0-15=f8-23、fs0-7=f24-31）。
fn fpr_alias(name: &str) -> Option<u64> {
    let parse = |prefix: &str| -> Option<u64> { name.strip_prefix(prefix)?.parse().ok() };
    let (p, n): (&str, u64) = parse("fa")
        .map(|n| ("fa", n))
        .or_else(|| parse("ft").map(|n| ("ft", n)))
        .or_else(|| parse("fs").map(|n| ("fs", n)))?;
    Some(match p {
        "fa" if n < 8 => n,
        "ft" if n < 16 => 8 + n,
        "fs" if n < 8 => 24 + n,
        _ => return None,
    })
}

/// `$xxx` オペランドを polyisa 側の `$r/$f/$vr/$fcc/$fcsr` 番号表記へ。
fn norm_reg(tok: &str) -> String {
    let body = tok.strip_prefix('$').unwrap_or(tok);
    // 条件フラグと FCSR は専用接頭辞をそのまま通す。
    if body.starts_with("fcc") || body.starts_with("fcsr") {
        return format!("${body}");
    }
    if let Some(n) = body.strip_prefix('r').and_then(|s| s.parse::<u64>().ok()) {
        return format!("$r{n}");
    }
    if let Some(n) = body.strip_prefix('f').and_then(|s| s.parse::<u64>().ok()) {
        return format!("$f{n}");
    }
    if let Some(n) = gr_alias(body) {
        return format!("$r{n}");
    }
    if let Some(n) = fpr_alias(body) {
        return format!("$f{n}");
    }
    format!("${body}")
}

/// オペランド文字列を正規化してベクタにする。
fn norm_ops(ops: &str) -> Vec<String> {
    if ops.is_empty() {
        return Vec::new();
    }
    ops.split(',')
        .map(|t| {
            let t = t.trim();
            // 分岐行の `<sym+off>` 注記は捨てる。
            let t = t.split('<').next().unwrap_or(t).trim();
            if t.starts_with('$') {
                norm_reg(t)
            } else {
                // 整数は decimal へ（llvm は既に decimal がほぼ全て）。
                let v = t
                    .strip_prefix("0x")
                    .map(|h| i64::from_str_radix(h, 16).ok())
                    .unwrap_or_else(|| t.parse::<i64>().ok())
                    .unwrap_or(0);
                format!("{v}")
            }
        })
        .collect()
}

/// llvm のニーモニック行を正規形 `(mnemonic, [ops])` へ。
fn norm_llvm(mn: &str, ops: &str) -> Option<(String, Vec<String>)> {
    let o = norm_ops(ops);
    match mn {
        "ret" => Some((
            "jirl".to_string(),
            vec!["$r0".into(), "$r1".into(), "0".into()],
        )),
        "jr" => {
            let mut v = vec!["$r0".to_string()];
            v.extend(o);
            if v.len() == 2 {
                v.push("0".into());
            }
            Some(("jirl".to_string(), v))
        }
        "move" => Some((
            "or".to_string(),
            vec![o[0].clone(), o[1].clone(), "$r0".into()],
        )),
        "nop" => Some((
            "andi".to_string(),
            vec!["$r0".into(), "$r0".into(), "0".into()],
        )),
        "bltz" => Some((
            "blt".to_string(),
            vec![o[0].clone(), "$r0".into(), o[1].clone()],
        )),
        "bgez" => Some((
            "bge".to_string(),
            vec![o[0].clone(), "$r0".into(), o[1].clone()],
        )),
        // bgtz/blez は $zero との大小比較で、実命令は blt/bge の
        // オペランド交換（`blt $zero, rj`）。
        "bgtz" => Some((
            "blt".to_string(),
            vec!["$r0".into(), o[0].clone(), o[1].clone()],
        )),
        "blez" => Some((
            "bge".to_string(),
            vec!["$r0".into(), o[0].clone(), o[1].clone()],
        )),
        // LLVM は比較対象が $zero のとき擬似名 bgt/ble に書き換える。
        // 実命令は blt/bge のオペランド交換なので戻す。
        "bgt" => Some((
            "blt".to_string(),
            vec![o[1].clone(), o[0].clone(), o[2].clone()],
        )),
        "ble" => Some((
            "bge".to_string(),
            vec![o[1].clone(), o[0].clone(), o[2].clone()],
        )),
        _ => Some((mn.to_string(), o)),
    }
}

fn sext(v: u64, bits: u32) -> i64 {
    let sh = 64 - bits;
    ((v << sh) as i64) >> sh
}

use polyisa_guest_loongarch::{FEAT_LA32, FEAT_LA64, FEAT_LSX, Insn};

/// polyisa 側の正規形を組み立てる。`disasm` のテンプレートの
/// `{name}` を `extract_ops` の値で順に置き換える。
/// FCMP の cond[4:1] → 基本比較名（cond[0] が S=signaling）。
/// Ref: SPEC-LOONGARCH-RM §FCMP.cond（cond の表）。
const FCMP_BASE: [&str; 16] = [
    "af", "lt", "eq", "le", "un", "ult", "ueq", "ule", "ne", "?", "or", "?", "une", "?", "?", "?",
];

fn render_poly(insn: Insn, word: u64) -> Option<String> {
    let ops = polyisa_guest_loongarch::extract_ops(insn, u128::from(word));
    // fcmp.cond.{s,d} は cond 値を接尾辞へ展開する。
    if matches!(insn, Insn::FcmpCondS | Insn::FcmpCondD) {
        let cond = ops[3];
        let base = FCMP_BASE[(cond >> 1) as usize];
        if base == "?" {
            return None;
        }
        let s = if insn == Insn::FcmpCondS { "s" } else { "d" };
        let cs = if cond & 1 == 0 { "c" } else { "s" };
        return Some(format!(
            "fcmp.{cs}{base}.{s} $fcc{}, $f{}, $f{}",
            ops[0], ops[1], ops[2]
        ));
    }
    let t = polyisa_guest_loongarch::disasm(insn);
    let mut s = t.to_string();
    let mut i = 0usize;
    let mut nth = 0usize;
    while let Some(st) = s[i..].find('{') {
        let st = i + st;
        let en = s[st..].find('}')? + st;
        let name = &s[st + 1..en];
        let v = *ops.get(nth)?;
        nth += 1;
        let rep = match name {
            "rd" | "rj" | "rk" | "ra" => format!("$r{v}"),
            "fd" | "fj" | "fk" | "fa" => format!("$f{v}"),
            "vd" | "vj" | "vk" => format!("$vr{v}"),
            "cd" | "cj" | "ca" => format!("$fcc{v}"),
            "fcsr" | "fcsrd" | "fcsrj" => format!("$fcsr{v}"),
            "si12" => format!("{}", sext(v, 12)),
            "si13" => format!("{}", sext(v, 13)),
            "si14" => format!("{}", sext(v, 14) << 2),
            "si16" => format!("{}", sext(v, 16)),
            "si20" => format!("{}", sext(v, 20)),
            // ALSL の sa は建築上 sa+1 がシフト量で、LLVM はその値を出す。
            "sa2" | "sa3" if matches!(insn, Insn::AlslW | Insn::AlslD | Insn::AlslWu) => {
                format!("{}", v + 1)
            }
            // jirl/beq 系の offs は語オフセット→バイト、
            // beqz/bnez/b/bl は zfill 済みのバイト値。
            "offs" => match insn {
                Insn::Beqz | Insn::Bnez | Insn::Bceqz | Insn::Bcnez => {
                    format!("{}", sext(v, 23))
                }
                Insn::B | Insn::Bl => format!("{}", sext(v, 28)),
                _ => format!("{}", sext(v, 16) << 2),
            },
            _ => format!("{v}"),
        };
        s = format!("{}{}{}", &s[..st], rep, &s[en + 1..]);
        i = st + rep.len();
    }
    // テンプレートは "{mn} {ops}" で ops が空のときもある。
    let mut it = s.splitn(2, char::is_whitespace);
    let mn = it.next()?;
    let rest = it.next().unwrap_or("").trim();
    if rest.is_empty() {
        Some(mn.to_string())
    } else {
        let ops: Vec<String> = rest.split(',').map(|x| x.trim().to_string()).collect();
        Some(format!("{} {}", mn, ops.join(", ")))
    }
}

#[test]
fn disasm_matches_llvm_on_busybox() {
    let rows = objdump_lines(&objdump(), &busybox());
    assert!(!rows.is_empty(), "llvm-objdump の行が取れていない");
    let feats = FEAT_LA32 | FEAT_LA64 | FEAT_LSX;
    let mut total = 0usize;
    let mut decoded = 0usize;
    let mut agreed = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    let mut undecoded: BTreeMap<String, usize> = BTreeMap::new();
    for (w, mn, ops) in &rows {
        total += 1;
        let Some(insn) = polyisa_guest_loongarch::decode_model_ex(u128::from(*w), 32, true, feats)
        else {
            *undecoded.entry(mn.clone()).or_default() += 1;
            continue;
        };
        decoded += 1;
        let Some(poly) = render_poly(insn, u64::from(*w)) else {
            *undecoded.entry(format!("render:{mn}")).or_default() += 1;
            continue;
        };
        let Some((lmn, lops)) = norm_llvm(mn, ops) else {
            continue;
        };
        let llvm = if lops.is_empty() {
            lmn
        } else {
            format!("{} {}", lmn, lops.join(", "))
        };
        if poly == llvm {
            agreed += 1;
        } else if mismatches.len() < 30 {
            mismatches.push(format!("{w:08x}: polyisa={poly:?} llvm={llvm:?}"));
        }
    }
    if !mismatches.is_empty() {
        panic!(
            "デコード一致しない行が {} 件以上ある（先頭 30 件）:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }
    // 実装部分集合の外にある語は decode 不可として数える。
    // 正規 musl/BusyBox の .text は実装済みスカラ+FPU+LSX部分集合で
    // ほぼ全量覆えるはず。
    assert_eq!(
        agreed, decoded,
        "render に失敗した命令がある: {undecoded:?}"
    );
    assert!(
        agreed * 100 >= total * 95,
        "decode 網羅率が低い: {agreed}/{total}（未デコード {undecoded:?}）"
    );
}
