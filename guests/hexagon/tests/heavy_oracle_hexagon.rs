// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-objdump とのデコード差分（層4・oracle、S22-3）。
//!
//! `.testdata/bin-distro-hexagon/bin/busybox` の `.text` 全語を
//! llvm-objdump の逆アセンブル結果と突き合わせる。比較は生の
//! ニーモニック文字列ではなく、(a) 命令同一性（Insn 対応表）、
//! (b) オペランドのレジスタ番号、(c) 述語選択と否定/.new
//! qualifier、(d) 分岐ヒント桁、(e) 分岐先アドレス、
//! (f) パケット属性（duplex 構成・endloop）で行う。
//! polyisa の canonical 表記（対レジスタの偶数側畳み、`memx`
//! 汎用名、j4/dx 部分集合レジスタの生符号、implicit な
//! r29/r30 表示）は正規化側で吸収する。
//!
//! 既知の未対応語彙は GAP-0074（df/sf 変換・演算群）だけを
//! 形状一致で許容する。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use polyisa_guest_hexagon::{
    FEAT_V5, FEAT_V55, FEAT_V60, FEAT_V62, FEAT_V65, FEAT_V66, FEAT_V67, FEAT_V68, FEAT_V69,
    FEAT_V71, FEAT_V73, Insn, decode_model_ex, disasm_word_ex, extract_ops, packet,
};

/// 配布物が要求する V73 系の機能旗（版旗は線形の含意）。
const FEATS: u128 = FEAT_V5
    | FEAT_V55
    | FEAT_V60
    | FEAT_V62
    | FEAT_V65
    | FEAT_V66
    | FEAT_V67
    | FEAT_V68
    | FEAT_V69
    | FEAT_V71
    | FEAT_V73;

/// GAP-0074: 倍精度/単精度 FP の未対応語彙。llvm 形状テキスト
/// に現れる接頭/包含パターン（形状正規化済みの小文字形）。
const GAP_FP: &[&str] = &[
    "df", "sf", "convert_", "dfmpy", "dfadd", "dfsub", "dfmin", "dfmax", "dfclass",
];

fn busybox() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    let p = p.join(".testdata/bin-distro-hexagon/bin/busybox");
    assert!(p.is_file(), "BIN-DISTRO-HEXAGON の busybox がない");
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
    panic!("llvm-objdump がない");
}

/// llvm-objdump の 1 行ぶん。
struct Row {
    addr: u32,
    word: u32,
    /// 命令テキスト（duplex/複合形は 2 つ）。
    subs: Vec<String>,
    /// パケット開始語なら真（llvm の `{`）。
    begin: bool,
    /// `:endloopN` 注記が付いていれば真（パケット属性）。
    endloop: bool,
}

fn objdump_rows(bin: &str, path: &PathBuf) -> Vec<Row> {
    let out = Command::new(bin)
        .args(["-d", "--mcpu=hexagonv73"])
        .arg(path)
        .output()
        .expect("llvm-objdump を起動");
    assert!(out.status.success(), "llvm-objdump が失敗");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        // "   4bb90:\t02 c0 00 58\t5800c004 { \tjump 0x4bb68 <_start+0x8> }"
        let Some(colon) = line.find(':') else {
            continue;
        };
        if !line[..colon].trim().chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(addr) = u32::from_str_radix(line[..colon].trim(), 16) else {
            continue;
        };
        let rest = &line[colon + 1..];
        let mut it = rest.split_whitespace();
        let mut n_bytes = 0usize;
        let mut word = 0u32;
        let mut text = String::new();
        while let Some(tok) = it.next() {
            if tok.len() == 2 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
                n_bytes += 1;
            } else {
                if tok.len() == 8 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
                    word = u32::from_str_radix(tok, 16).unwrap();
                    text = it.collect::<Vec<_>>().join(" ");
                }
                break;
            }
        }
        if n_bytes == 4 && !text.is_empty() {
            let begin = text.contains('{');
            let endloop = text.contains(":endloop");
            let t = text.replace(['{', '}'], " ");
            let subs: Vec<String> = t
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            rows.push(Row {
                addr,
                word,
                subs,
                begin,
                endloop,
            });
        }
    }
    rows
}

/// llvm 記法テキストを形状キーへ正規化する（GAP 分類と報告用。
/// 等価判定には使わない）。
fn shape_of(t: &str) -> String {
    let mut s = t.trim().to_string();
    if let Some(lt) = s.find('<')
        && s.ends_with('>')
        && !s[..lt].trim_end().ends_with("<<")
    {
        s.truncate(lt);
    }
    let mut out = String::with_capacity(s.len());
    let b: Vec<char> = s.trim().chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '#' {
            while i + 1 < b.len() && b[i + 1] == '#' {
                i += 1;
            }
            out.push('#');
            i += 1;
        } else if c == '0' && i + 1 < b.len() && b[i + 1] == 'x' {
            i += 2;
            while i < b.len() && b[i].is_ascii_hexdigit() {
                i += 1;
            }
            out.push('#');
        } else if c.is_ascii_digit() {
            let prev = i.checked_sub(1).map(|j| b[j]);
            if matches!(prev, Some(p) if p.is_ascii_alphanumeric() || p == '.' || p == '_') {
                out.push(c);
            } else {
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                out.push('#');
                continue;
            }
            i += 1;
        } else if c == 'r' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i < b.len() && b[i] == ':' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                out.push_str("R:R");
            } else {
                out.push('R');
            }
        } else if c == 'p'
            && i + 1 < b.len()
            && b[i + 1].is_ascii_digit()
            && !matches!(i.checked_sub(1).map(|j| b[j]), Some(p) if p.is_ascii_alphanumeric() || p == '_')
        {
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i < b.len() && b[i] == ':' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                out.push_str("P:P");
            } else {
                out.push('P');
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// テキストから参照レジスタの多重集合を拾う。
/// `rA:B`（対）は偶数側 B に畳み、`rN.new`/`pN.new`（Nt 距離の
/// 生産値・polyisa は番号を出さない）は除外する。
fn regs_of(t: &str) -> (Vec<u32>, Vec<u32>) {
    let b: Vec<char> = t.chars().collect();
    let mut r = Vec::new();
    let mut p = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if (c == 'r' || c == 'p')
            && i + 1 < b.len()
            && b[i + 1].is_ascii_digit()
            && !matches!(i.checked_sub(1).map(|j| b[j]), Some(q) if q.is_ascii_alphanumeric() || q == '_' || q == '.')
        {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let mut n: u32 = b[i + 1..j].iter().collect::<String>().parse().unwrap();
            if j < b.len() && b[j] == ':' && j + 1 < b.len() && b[j + 1].is_ascii_digit() {
                let mut k = j + 1;
                while k < b.len() && b[k].is_ascii_digit() {
                    k += 1;
                }
                n = b[j + 1..k].iter().collect::<String>().parse().unwrap();
                j = k;
            }
            if b[j..].starts_with(&['.', 'n', 'e', 'w']) {
                i = j + 4;
                continue;
            }
            if c == 'r' {
                r.push(n);
            } else {
                p.push(n);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    r.sort_unstable();
    p.sort_unstable();
    (r, p)
}

/// 生符号（4 ビット部分集合）→ 実レジスタ番号（dxr と同じ
/// 規則: 0-7 は r0-7、8-15 は r16-23）。
fn dxr(c: u32) -> u32 {
    if c < 8 { c } else { c + 8 }
}

/// j4/j4t 部分集合符号の生値をレジスタとして出す Insn。
/// polyisa はレンダリングに符号値をそのまま出す
/// （GAP-0069 と同系の表記差）。
fn is_subset_reg(insn: Insn) -> bool {
    use Insn::*;
    matches!(
        insn,
        TjI | TjR | CjEqi | CjGti | CjGtui | CjEqi1 | CjGti1 | CjTst | CjEqr | CjGtr | CjGtur
    )
}

/// llvm が省略する implicit レジスタを polyisa が表示する形。
/// allocframe の r29 と dealloc 系の r30/r31:30。
fn implicit_regs(insn: Insn) -> &'static [u32] {
    use Insn::*;
    match insn {
        Allocframe => &[29],
        Deallocframe | Deallocret | DeallocretPq | DeallocretPqn => &[30, 30],
        _ => &[],
    }
}

/// dot-if 形（extract_ops 末尾 2 つが (p, q)。q = {bit1=.new,
/// bit0=否定}）。`run::cond_of` と同じ一覧。
fn is_dotif(insn: Insn) -> bool {
    use Insn::*;
    matches!(
        insn,
        LdPq | LdPqPi
            | LdPqRo
            | LdPqAbs
            | StPq
            | StPqPi
            | StPqRo
            | StPqAbs
            | StIp
            | StPqNt
            | StPqPiNt
            | StPqRoNt
            | StPqAbsNt
            | CandRr
            | CorRr
            | CxorRr
            | CaddRr
            | CsubRr
            | CcombRr
            | CaddRi
            | CmovI
    )
}

/// qualifier のビット順が逆の dot-if（q = {bit1=否定,
/// bit0=.new}。条件付き sign/zero-extend）。
fn is_dotif_swapped(insn: Insn) -> bool {
    matches!(insn, Insn::Czxtb | Insn::Czxth | Insn::Csxtb | Insn::Csxth)
}

/// `if ([!]Pu[.new])` 分岐形（extract_ops 末尾 2 つが (p, 否定)、
/// `.new` は Insn 名の Pqn 接尾）。
fn is_branch_pq(insn: Insn) -> bool {
    use Insn::*;
    matches!(
        insn,
        JumpPq | JumpPqn | CallPq | JumprPq | JumprPqn | CallrPq | DeallocretPq | DeallocretPqn
    )
}

/// 複合 compare-jump（`pX = cmp.* ; if ([!]pX.new) jump` が
/// 1 命令）。llvm は 2 テキストに分けて表示する。
fn is_cj(insn: Insn) -> bool {
    use Insn::*;
    matches!(
        insn,
        CjEqi | CjGti | CjGtui | CjEqi1 | CjGti1 | CjTst | CjEqr | CjGtr | CjGtur
    )
}

/// new-value compare-jump（`if ([!]cmp.*(r.new,…)) jump` が
/// 1 命令・llvm も 1 テキスト）。オペランド末尾は
/// (nt/t, 否定, target)。
fn is_nvj(insn: Insn) -> bool {
    use Insn::*;
    matches!(
        insn,
        NvjEqr
            | NvjGtr
            | NvjGtur
            | NvjGtrr
            | NvjGturr
            | NvjEqi
            | NvjGti
            | NvjGtui
            | NvjTst
            | NvjEqi1
            | NvjGti1
    )
}

/// llvm の `if (...)` 前置を (否定, 本体開始位置) へ。
/// 述語形なら Some((p, neg, new))、そうでなければ Some(None)。
fn llvm_pred(t: &str) -> Option<Option<(u32, bool, bool)>> {
    let t = t.trim_start();
    if !t.starts_with("if") {
        return Some(None);
    }
    let inner = t.strip_prefix("if")?.trim_start();
    let inner = inner.strip_prefix('(')?;
    let end = inner.find(')')?;
    let c = inner[..end].trim();
    let (neg, c) = match c.strip_prefix('!') {
        Some(r) => (true, r.trim()),
        None => (false, c),
    };
    let (new, c) = match c.strip_suffix(".new") {
        Some(r) => (true, r),
        None => (false, c),
    };
    let c = c.trim();
    if c.len() == 2 && c.starts_with('p') {
        let p: u32 = c[1..].parse().ok()?;
        Some(Some((p, neg, new)))
    } else {
        None
    }
}

/// llvm テキストから `#` 接頭の即値列を拾う（符号付き。
/// `##` 併合値はそのまま 1 個の即値として読める）。
fn imms_of(t: &str) -> Vec<i64> {
    let b: Vec<char> = t.chars().collect();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '#' {
            while i + 1 < b.len() && b[i + 1] == '#' {
                i += 1;
            }
            i += 1;
            let neg = i < b.len() && b[i] == '-';
            if neg {
                i += 1;
            }
            let hex = i + 1 < b.len() && b[i] == '0' && b[i + 1] == 'x';
            if hex {
                i += 2;
            }
            let s = i;
            while i < b.len() && (b[i].is_ascii_digit() || (hex && b[i].is_ascii_hexdigit())) {
                i += 1;
            }
            if s < i {
                let t: String = b[s..i].iter().collect();
                let n = if hex {
                    i64::from_str_radix(&t, 16).unwrap_or(0)
                } else {
                    t.parse().unwrap_or(0)
                };
                v.push(if neg { -n } else { n });
            }
        } else {
            i += 1;
        }
    }
    v
}

/// Cj*/Nvj*/Tj* の分岐先検証。r9 = {bits[21:20]}+{bits[7:1]}
/// の 9 ビット符号 ×4 をパケット先頭に加える。extender 直後は
/// ext26<<6 | r9 の下位 6 ビット（byte オフセットのまま）。
fn branch_target_ok(word: u32, ext: Option<u32>, pkt_pc: u32, llvm_target: u32) -> bool {
    let r9 = (((word >> 20) & 0x3) << 7) | ((word >> 1) & 0x7f);
    let off = match ext {
        Some(e) => (e << 6) | (r9 & 0x3f),
        None => {
            let o = r9 << 2;
            if o & 0x400 != 0 {
                o.wrapping_sub(0x800)
            } else {
                o
            }
        }
    };
    pkt_pc.wrapping_add(off) == llvm_target
}

/// immext 語の 26 ビット即値（{bits[27:16]}+{bits[13:0]}）。
fn ext26(w: u32) -> u32 {
    (((w >> 16) & 0xfff) << 14) | (w & 0x3fff)
}

/// polyisa 側 1 スロットぶん。
struct Poly {
    insn: Insn,
    text: String,
    ops: Vec<u64>,
}

/// 分岐ヒント桁の有無（:t/:nt）。
#[derive(Default)]
struct Hint {
    llvm_t: bool,
    llvm_nt: bool,
}

fn hint_of(t: &str) -> Hint {
    Hint {
        llvm_t: t.contains("jump:t") || t.contains("dealloc_return:t"),
        llvm_nt: t.contains("jump:nt") || t.contains("dealloc_return:nt"),
    }
}

fn main_loop(report_path: Option<&str>) {
    let rows = objdump_rows(&objdump(), &busybox());
    assert!(rows.len() > 100_000, "llvm-objdump の出力が薄い");

    let mut pairs: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut undecoded: BTreeMap<String, usize> = BTreeMap::new();
    let mut gap_fp = 0usize;
    let mut bad_undec: BTreeMap<String, usize> = BTreeMap::new();
    let mut slot_bad: BTreeMap<String, usize> = BTreeMap::new();
    let mut reg_bad: BTreeMap<String, usize> = BTreeMap::new();
    let mut pq_bad: BTreeMap<String, usize> = BTreeMap::new();
    let mut hint_bad: BTreeMap<String, usize> = BTreeMap::new();
    let mut tgt_bad: BTreeMap<String, usize> = BTreeMap::new();
    let mut cj_merged = 0usize;
    let mut endloop_bad = 0usize;
    let mut unknowns = 0usize;
    let mut decoded_words = 0usize;
    let mut slots = 0usize;

    // パケット状態（行はアドレス順・パケット内順）。
    let mut pkt_pc = 0u32;
    let mut prev_ext: Option<u32> = None;
    let mut pkt_has_pb2 = false;
    let mut pkt_has_endloop = false;
    let mut in_pkt = false;

    let flush_pkt =
        |in_pkt: &mut bool, has_pb2: &mut bool, has_endloop: &mut bool, bad: &mut usize| {
            if *in_pkt && (*has_pb2 != *has_endloop) {
                *bad += 1;
            }
            *in_pkt = false;
            *has_pb2 = false;
            *has_endloop = false;
        };

    for row in &rows {
        if row.begin {
            flush_pkt(
                &mut in_pkt,
                &mut pkt_has_pb2,
                &mut pkt_has_endloop,
                &mut endloop_bad,
            );
            in_pkt = true;
            pkt_pc = row.addr;
            prev_ext = None;
        }
        pkt_has_pb2 |= (row.word >> 14) & 3 == 2;
        pkt_has_endloop |= row.endloop;
        let ext = prev_ext;
        prev_ext = if row.word & 0xf000_0000 == 0 {
            Some(ext26(row.word))
        } else {
            None
        };

        if row.subs.iter().any(|s| s.contains("<unknown>")) {
            unknowns += 1;
            continue;
        }

        // polyisa 側のスロット列。
        let mut poly: Vec<(Insn, u128, u32, u128)> = Vec::new();
        if (row.word >> 14) & 3 == 0 {
            if let Some((gl, gh)) = packet::duplex_groups(row.word) {
                let (lo, hi) = packet::duplex_subs(row.word);
                for (g, s) in [(gl, lo), (gh, hi)] {
                    if let Some(i) = packet::decode_sub(g, s, FEATS) {
                        poly.push((i, u128::from(s), 13, FEATS | packet::group_feat(g)));
                    }
                }
            }
        } else if let Some(i) = decode_model_ex(u128::from(row.word), 32, true, FEATS) {
            poly.push((i, u128::from(row.word), 32, FEATS));
        }

        if poly.is_empty() {
            for s in &row.subs {
                let sh = shape_of(s);
                // GAP-0074: FP 語彙のみ許容。
                if GAP_FP.iter().any(|k| sh.to_lowercase().contains(k)) {
                    gap_fp += 1;
                } else {
                    *bad_undec.entry(sh.clone()).or_default() += 1;
                }
                *undecoded.entry(sh).or_default() += 1;
            }
            continue;
        }
        decoded_words += 1;

        // テキスト生成（`;` 複合形を割る）。
        let mut polys: Vec<Poly> = Vec::new();
        for (insn, w, len, f) in &poly {
            let text = disasm_word_ex(*w, *len, true, *f).unwrap_or_default();
            let ops = extract_ops(*insn, *w);
            for p in text.split(';') {
                polys.push(Poly {
                    insn: *insn,
                    text: p.trim().to_string(),
                    ops: ops.clone(),
                });
            }
        }

        // Cj 複合 compare-jump: poly 1 命令に対し llvm は
        // `pN = cmp.*` と `if ([!]pN.new) jump` の 2 テキスト。
        // check_cj が詳細照合を済ませたので後段の汎用照合は
        // スキップする（`pN =` の述語宛先は poly 記法に出ない）。
        if polys.len() == 1 && row.subs.len() == 2 && is_cj(polys[0].insn) {
            cj_merged += 1;
            slots += 1;
            let name = format!("{:?}", polys[0].insn);
            *pairs
                .entry((
                    name,
                    format!("{} ; {}", shape_of(&row.subs[0]), shape_of(&row.subs[1])),
                ))
                .or_default() += 1;
            check_cj(
                &polys[0],
                &row.subs,
                Ctx {
                    word: row.word,
                    ext,
                    pkt_pc,
                },
                &mut reg_bad,
                &mut pq_bad,
                &mut hint_bad,
                &mut tgt_bad,
            );
            continue;
        }
        let subs = &row.subs;

        if polys.len() != subs.len() {
            *slot_bad
                .entry(format!(
                    "{:08x} {:08x} poly={} llvm={} {:?}",
                    row.addr,
                    row.word,
                    polys.len(),
                    subs.len(),
                    subs
                ))
                .or_default() += 1;
            continue;
        }

        slots += polys.len();
        for (po, lt) in polys.iter().zip(subs.iter()) {
            let name = format!("{:?}", po.insn);
            *pairs.entry((name.clone(), shape_of(lt))).or_default() += 1;
            let lt_body = if is_dotif(po.insn) || is_dotif_swapped(po.insn) || is_branch_pq(po.insn)
            {
                match llvm_pred(lt) {
                    Some(Some(_)) => lt[lt.find(')').unwrap() + 1..].to_string(),
                    _ => lt.clone(),
                }
            } else {
                lt.clone()
            };
            let (lr, lp) = regs_of(&lt_body);
            let (mut pr, pp) = regs_of(&po.text);
            if name.starts_with("Dx") {
                // duplex subinsn は 4 ビット部分集合符号の生値
                // （GAP-0069 に記録済みの表記差）。
            } else {
                if is_subset_reg(po.insn) {
                    pr = pr.iter().map(|&r| dxr(r)).collect();
                }
                for imp in implicit_regs(po.insn) {
                    if let Some(pos) = pr.iter().position(|&r| r == *imp) {
                        pr.remove(pos);
                    }
                }
                if lr != pr || lp != pp {
                    *reg_bad
                        .entry(format!(
                            "{name} | poly={pr:?} {pp:?} | llvm={lr:?} {lp:?} | {lt:?} vs {:?}",
                            po.text
                        ))
                        .or_default() += 1;
                }
            }

            // 述語選択・否定・.new の照合。
            if let Some(Some((lp_, lneg, lnew))) = llvm_pred(lt) {
                let n = po.ops.len();
                let got = if (is_dotif(po.insn)
                    || is_dotif_swapped(po.insn)
                    || is_branch_pq(po.insn)
                    || is_cj(po.insn)
                    || is_nvj(po.insn))
                    && n >= 2
                {
                    let q = po.ops[n - 1];
                    let (pneg, pnew) = if is_dotif_swapped(po.insn) {
                        (q & 2 != 0, q & 1 != 0)
                    } else if is_branch_pq(po.insn) {
                        (q != 0, name.ends_with('n'))
                    } else if is_cj(po.insn) || is_nvj(po.insn) {
                        (po.ops[n - 2] != 0, true)
                    } else {
                        (q & 1 != 0, q & 2 != 0)
                    };
                    let pp_ = if is_cj(po.insn) || is_nvj(po.insn) {
                        po.ops[usize::max(0, n.saturating_sub(3))] as u32
                    } else {
                        po.ops[n - 2] as u32
                    };
                    Some((pp_, pneg, pnew))
                } else {
                    None
                };
                if let Some((pp_, pneg, pnew)) = got
                    && (pp_, pneg, pnew) != (lp_, lneg, lnew)
                {
                    *pq_bad
                        .entry(format!(
                            "{name} ops={:?} llvm=({lp_},{lneg},{lnew}) {lt:?}",
                            po.ops
                        ))
                        .or_default() += 1;
                }
            }

            // 分岐ヒント桁: Cj/Nvj は bit13、JumpPqn 系は bit12。
            let hint = hint_of(lt);
            if is_cj(po.insn) || is_nvj(po.insn) {
                let want_t = (row.word >> 13) & 1 != 0;
                if (hint.llvm_t && !want_t) || (hint.llvm_nt && want_t) {
                    *hint_bad
                        .entry(format!("{name} {:08x} {lt:?}", row.word))
                        .or_default() += 1;
                }
            } else if matches!(po.insn, Insn::JumpPqn) {
                let want_t = (row.word >> 12) & 1 != 0;
                if (hint.llvm_t && !want_t) || (hint.llvm_nt && want_t) {
                    *hint_bad
                        .entry(format!("{name} {:08x} {lt:?}", row.word))
                        .or_default() += 1;
                }
            }

            // Nvj の分岐先（Cj は check_cj で照合済み）。
            if is_nvj(po.insn)
                && let Some(tgt) = llvm_target(lt)
                && !branch_target_ok(row.word, ext, pkt_pc, tgt)
            {
                *tgt_bad
                    .entry(format!("{name} {:08x} {lt:?}", row.word))
                    .or_default() += 1;
            }
        }
    }
    flush_pkt(
        &mut in_pkt,
        &mut pkt_has_pb2,
        &mut pkt_has_endloop,
        &mut endloop_bad,
    );

    let mut report = String::new();
    report.push_str(&format!(
        "words={} decoded={decoded_words} slots={slots} cj_merged={cj_merged} gap_fp={gap_fp} unknown={unknowns} endloop_bad={endloop_bad}\n",
        rows.len()
    ));
    report.push_str(&format!("\n== BAD UNDECODED ({})\n", bad_undec.len()));
    for (s, c) in &bad_undec {
        report.push_str(&format!("{c:6} {s}\n"));
    }
    report.push_str(&format!("\n== SLOT MISMATCH ({})\n", slot_bad.len()));
    for (s, c) in slot_bad.iter().take(20) {
        report.push_str(&format!("{c:6} {s}\n"));
    }
    report.push_str(&format!("\n== REG MISMATCH ({})\n", reg_bad.len()));
    for (s, c) in reg_bad.iter().take(30) {
        report.push_str(&format!("{c:6} {s}\n"));
    }
    report.push_str(&format!("\n== PQ MISMATCH ({})\n", pq_bad.len()));
    for (s, c) in pq_bad.iter().take(20) {
        report.push_str(&format!("{c:6} {s}\n"));
    }
    report.push_str(&format!("\n== HINT MISMATCH ({})\n", hint_bad.len()));
    for (s, c) in hint_bad.iter().take(20) {
        report.push_str(&format!("{c:6} {s}\n"));
    }
    report.push_str(&format!("\n== TARGET MISMATCH ({})\n", tgt_bad.len()));
    for (s, c) in tgt_bad.iter().take(20) {
        report.push_str(&format!("{c:6} {s}\n"));
    }
    report.push_str(&format!("\n== PAIRS ({})\n", pairs.len()));
    for ((i, s), c) in &pairs {
        report.push_str(&format!("{c:6} {i:24} {s}\n"));
    }
    report.push_str(&format!("\n== GAP-0074 UNDECODED ({})\n", undecoded.len()));
    for (s, c) in &undecoded {
        report.push_str(&format!("{c:6} {s}\n"));
    }
    if let Some(p) = report_path {
        std::fs::write(p, &report).unwrap();
    }
    let bad_total: usize = bad_undec.values().sum();
    let slot_total: usize = slot_bad.values().sum();
    let reg_total: usize = reg_bad.values().sum();
    let pq_total: usize = pq_bad.values().sum();
    let hint_total: usize = hint_bad.values().sum();
    let tgt_total: usize = tgt_bad.values().sum();
    println!("{report}");
    assert_eq!(bad_total, 0, "未対応の未知語彙がある");
    assert_eq!(slot_total, 0, "スロット数の不一致がある");
    assert_eq!(reg_total, 0, "レジスタ不一致がある");
    assert_eq!(pq_total, 0, "述語/否定/.new の不一致がある");
    assert_eq!(hint_total, 0, "分岐ヒント桁の不一致がある");
    assert_eq!(tgt_total, 0, "分岐先の不一致がある");
    assert_eq!(endloop_bad, 0, "endloop 属性の不一致がある");
    // カバレッジ: 146,803 語中 FP-GAP 215 + <unknown> 1 を除き
    // 全てデコードできること。
    assert!(gap_fp >= 200, "FP GAP が急減した（期待する語彙が消えた）");
    assert_eq!(unknowns, 1);
    assert!(decoded_words >= rows.len() - 300, "デコード率が低い");
}

/// llvm の分岐テキストから対象アドレスを拾う。
/// `<symbol+off>` 注記は落としてから最後の 0x 数を取る。
fn llvm_target(t: &str) -> Option<u32> {
    let t = t.split('<').next().unwrap_or(t);
    let m = t.rfind("0x")?;
    let hex: String = t[m + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    u32::from_str_radix(&hex, 16).ok()
}

/// Cj 複合 compare-jump（poly 1 命令 = llvm 2 テキスト）の
/// 詳細照合。op 種・オペランド値・述語宛先・否定・ヒント桁・
/// 分岐先を確認する。
/// 分岐先照合に要るパケット文脈。
struct Ctx {
    word: u32,
    ext: Option<u32>,
    pkt_pc: u32,
}

fn check_cj(
    po: &Poly,
    subs: &[String],
    ctx: Ctx,
    reg_bad: &mut BTreeMap<String, usize>,
    pq_bad: &mut BTreeMap<String, usize>,
    hint_bad: &mut BTreeMap<String, usize>,
    tgt_bad: &mut BTreeMap<String, usize>,
) {
    let Ctx { word, ext, pkt_pc } = ctx;
    let name = format!("{:?}", po.insn);
    let expected = match po.insn {
        Insn::CjEqi | Insn::CjEqi1 | Insn::CjEqr => "cmp.eq",
        Insn::CjGti | Insn::CjGti1 | Insn::CjGtr => "cmp.gt",
        Insn::CjGtui | Insn::CjGtur => "cmp.gtu",
        _ => "tstbit",
    };
    // sub[0]: `pN = OP(a,b)`
    let s0 = &subs[0];
    let (lr, lp) = regs_of(s0);
    let limms = imms_of(s0);
    // poly 側の参照レジスタ（j4 部分集合 → dxr 変換）。
    let (mut pr, mut pp) = regs_of(&po.text);
    pr = pr.iter().map(|&r| dxr(r)).collect();
    // cmp の宛先述語は poly のレンダリングに出ない
    // （`cmp.eq(...)/jump` 形）。llvm 側の pN は ops[2]。
    // 述語宛先は末尾から数えて target/neg を除いた位置
    // （*i は [s,u,pd,neg,tgt]、*1/*r は [s,(u,)pd,neg,tgt]）。
    let pd_ok = lp.first().copied() == po.ops.get(po.ops.len() - 3).map(|v| *v as u32);
    pp.clear(); // poly は cmp 宛先述語を表示しない
    let op_ok = s0.contains(expected) || s0.contains("tstbit") && expected == "tstbit";
    if !pd_ok || !op_ok || lr != pr {
        *reg_bad
            .entry(format!(
                "{name} cj-cmp | poly={pr:?} llvm={lr:?}/{lp:?} ops={:?} | {s0:?} vs {:?}",
                po.ops, po.text
            ))
            .or_default() += 1;
    }
    // 即値引数: *i は ops[1]（u5）、*1 は固定 -1/#0、*r は無し。
    use Insn::*;
    let imm_ok = match po.insn {
        CjEqi | CjGti | CjGtui => limms.len() == 1 && limms[0] == po.ops[1] as i64,
        CjEqi1 | CjGti1 => limms.len() == 1 && limms[0] == -1,
        CjTst => limms.len() == 1 && limms[0] == 0,
        _ => limms.is_empty(),
    };
    if !imm_ok {
        *reg_bad
            .entry(format!(
                "{name} cj-imm | llvm={limms:?} ops={:?} | {s0:?}",
                po.ops
            ))
            .or_default() += 1;
    }
    // sub[1]: `if ([!]pN.new) jump[:t|:nt] 0xTARGET`
    let s1 = &subs[1];
    if let Some(Some((lp_, lneg, lnew))) = llvm_pred(s1) {
        let n = po.ops.len();
        let pd = po.ops[n - 3] as u32; // [s,(u|t),pd,neg,target]
        let neg = po.ops[n - 2] != 0;
        if (pd, neg, true) != (lp_, lneg, lnew) {
            *pq_bad
                .entry(format!(
                    "{name} cj | ops={:?} llvm=({lp_},{lneg},{lnew}) {s1:?}",
                    po.ops
                ))
                .or_default() += 1;
        }
    }
    let hint = hint_of(s1);
    let want_t = (word >> 13) & 1 != 0;
    if (hint.llvm_t && !want_t) || (hint.llvm_nt && want_t) || !(hint.llvm_t || hint.llvm_nt) {
        *hint_bad
            .entry(format!("{name} {word:08x} {s1:?}"))
            .or_default() += 1;
    }
    if let Some(tgt) = llvm_target(s1)
        && !branch_target_ok(word, ext, pkt_pc, tgt)
    {
        *tgt_bad
            .entry(format!("{name} {word:08x} {s1:?}"))
            .or_default() += 1;
    }
}

#[test]
fn heavy_oracle_hexagon() {
    main_loop(None);
}
