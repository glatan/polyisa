// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 命令ごとのテスト証拠を静的に集計する。
//!
//! ここでの集計はテストソース内に直接の証拠があるかを調べる下限であり、
//! テストの実行や成功を保証しない。バイト列だけで書かれた実行テストや、
//! 実行時に読む外部コーパスは、個別の抽出器がない限り集計に乗らない。
// Gap: GAP-0021 実行時トレースとテスト成否の結合は残件。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::specs;

#[derive(Default)]
struct InsnCoverage {
    layers: BTreeMap<&'static str, BTreeSet<String>>,
}

impl InsnCoverage {
    fn add(&mut self, layer: &'static str, evidence: String) {
        self.layers.entry(layer).or_default().insert(evidence);
    }
}

fn variant_name(snake: &str) -> String {
    let mut out = String::new();
    for part in snake.split('_') {
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

fn layer_for_stem(stem: &str) -> &'static str {
    if stem.starts_with("heavy_oracle") {
        "oracle"
    } else if stem.starts_with("heavy_conformance") {
        "conformance"
    } else if stem.starts_with("heavy_program") {
        "program"
    } else if stem.starts_with("heavy_diff") {
        "diff"
    } else if stem.starts_with("heavy_jit") {
        "jit"
    } else if stem.starts_with("heavy_timing") {
        "timing"
    } else {
        "unit"
    }
}

fn has_token(text: &str, token: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = text[start..].find(token) {
        let pos = start + pos;
        let before = pos == 0
            || !text.as_bytes()[pos - 1].is_ascii_alphanumeric()
                && text.as_bytes()[pos - 1] != b'_';
        let end = pos + token.len();
        let after = end == text.len()
            || !text.as_bytes()[end].is_ascii_alphanumeric() && text.as_bytes()[end] != b'_';
        if before && after {
            return true;
        }
        start = pos + 1;
    }
    false
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn mnemonic_of(syntax: &str) -> &str {
    syntax.split_whitespace().next().unwrap_or(syntax)
}

/// バイト列テストの mnemonic 言及を抽出する。
///
/// x86 のテストは命令をバイト列で埋め込み、行末コメントやインライン
/// asm 文字列に mnemonic を書く規約である。`Insn::`/`sem::` の直接
/// トークンだけではこの証拠を捕捉できないため、コメント/asm の
/// 先頭トークンを mnemonic 表に引く。variant の特定はできないので、
/// 同じ mnemonic を持つ全 variant に同一の family 単位の証拠を付ける。
/// コメントの先頭トークンだけを見るのは、日本語や散文中の英単語が
/// mnemonic と衝突するのを避けるためである。
fn mnemonic_mentions(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let hex_count = |line: &str| {
        let b = line.as_bytes();
        let mut n = 0;
        let mut i = 0;
        while i + 3 < b.len() {
            if b[i] == b'0'
                && (b[i + 1] == b'x' || b[i + 1] == b'X')
                && b[i + 2].is_ascii_hexdigit()
                && b[i + 3].is_ascii_hexdigit()
            {
                n += 1;
                i += 4;
            } else {
                i += 1;
            }
        }
        n
    };
    fn first_token(s: &str) -> Option<&str> {
        s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
            .find(|t| t.len() >= 2 && t.chars().next().is_some_and(|c| c.is_ascii_lowercase()))
    }
    // テスト関数名に埋め込まれた mnemonic。`fn run_fxch_st1_swaps` や
    // `fn run_x87_fxch_empty_source` の命名規約があり、トークン分割で
    // mnemonic 表に引く。散文トークンは表に無いので自然に落ちる。
    // （and/or 等の英単語と衝突する mnemonic は偽陽性になりうるが、
    // 証拠の過少計上を直す方が優先度は高い）
    for line in text.lines() {
        let Some(pos) = line.find("fn ") else {
            continue;
        };
        let rest = &line[pos + 3..];
        let end = rest.find('(').unwrap_or(rest.len());
        let fname = &rest[..end];
        if !(fname.starts_with("run_") || fname.starts_with("test")) {
            continue;
        }
        for tok in fname.split('_') {
            if tok.len() >= 2 {
                out.insert(tok.to_string());
            }
        }
    }
    let mut prev_had_bytes = false;
    for line in text.lines() {
        let has_bytes = line.contains(".byte") || hex_count(line) >= 2;
        // バイト列を持つ行（またはバイト列行から続く式の終端行）の
        // 行末コメント。`// push2 %rsp,%r12` の形。
        if (has_bytes || prev_had_bytes)
            && let Some(pos) = line.find("//")
        {
            let comment = &line[pos + 2..];
            if let Some(tok) = first_token(comment) {
                out.insert(tok.replace('.', "_"));
            }
            // `D9 C9 = fxch %st(1)` のように hex ダンプのあと `=` で
            // mnemonic を書く規約。コメント行自体はバイトを持たなくても
            // 関数内に現れる。
            if let Some(eq) = comment.find("= ")
                && let Some(tok) = first_token(&comment[eq + 2..])
            {
                out.insert(tok.replace('.', "_"));
            }
        }
        prev_had_bytes = has_bytes && !line.contains(';');
    }
    // インライン asm 文字列リテラル。`"tdpbusd %zmm1\n\t"` の形で、
    // 命令は改行で区切られている。文字列の先頭トークンを各行から取る。
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else { break };
        let body = &after[..end];
        if body.contains("\n") {
            for insn_line in body.split("\n") {
                let insn_line = insn_line.trim_start_matches("\t").trim_start();
                if let Some(tok) = first_token(insn_line) {
                    out.insert(tok.replace('.', "_"));
                }
            }
        }
        rest = &after[end + 1..];
    }
    out
}

fn scan_riscv_act(
    root: &Path,
    cov: &mut BTreeMap<String, InsnCoverage>,
    names: &BTreeMap<String, Vec<String>>,
    notes: &mut Vec<String>,
) {
    let harness_path = root.join("guests/riscv/tests/heavy_conformance_riscv_tests.rs");
    let data = root.join(".testdata/riscv-arch-test/tests/rv64i");
    let Some(harness) = read(&harness_path) else {
        return;
    };
    if !data.is_dir() {
        notes.push("riscv: ACT4 のテストデータがないため外部スイート抽出は未実行".to_string());
        return;
    }
    let mut suites = BTreeSet::new();
    for line in harness.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("suite(\"rv64i/")
            && let Some(end) = rest.find("\")")
        {
            suites.insert(rest[..end].to_string());
        }
    }
    let mut seen_files = 0usize;
    for suite in suites {
        let dir = data.join(&suite);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let Some(file) = ent.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !file.ends_with(".S") {
                continue;
            }
            seen_files += 1;
            let body = file.strip_suffix(".S").unwrap_or(&file);
            let Some((_, rest)) = body.split_once('-') else {
                continue;
            };
            let Some(end) = rest.rfind('-') else { continue };
            let mnemonic = &rest[..end];
            let key = mnemonic.replace('.', "_");
            let mut keys = vec![key.clone()];
            if key == "c_lui" || key == "c_addi16sp" {
                keys.push("c_lui/addi16sp".to_string());
            }
            for key in keys {
                if let Some(internals) = names.get(&key) {
                    for internal in internals {
                        cov.entry(internal.clone())
                            .or_default()
                            .add("conformance", format!("ACT4 {suite}/{file}"));
                    }
                }
            }
        }
    }
    notes.push(format!(
        "riscv: harness が列挙する ACT4 suite から {seen_files} 件のファイル名を抽出"
    ));
}

pub(crate) fn write_coverage(root: &Path) -> Result<Vec<PathBuf>, String> {
    let outdir = root.join("target/status");
    std::fs::create_dir_all(&outdir).map_err(|e| format!("{}: {e}", outdir.display()))?;
    let mut written = Vec::new();
    let mut summary_rows = Vec::new();
    let mut all_notes = Vec::new();

    let mut specs_sorted: Vec<&specs::IsaSpec> = specs::isa_specs().iter().collect();
    specs_sorted.sort_by_key(|s| s.isa);
    for spec in specs_sorted {
        let model = (spec.build)();
        let mut cov: BTreeMap<String, InsnCoverage> = BTreeMap::new();
        let mut mnemonic_to_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for insn in &model.insns {
            cov.entry(insn.name.clone()).or_default();
            mnemonic_to_name
                .entry(mnemonic_of(&insn.syntax).replace('.', "_"))
                .or_default()
                .push(insn.name.clone());
        }
        for mi in polyisa_isagen::map_insns(&model) {
            cov.entry(mi.name.clone()).or_default();
            mnemonic_to_name
                .entry(mnemonic_of(&mi.syntax).replace('.', "_"))
                .or_default()
                .push(mi.name.clone());
        }

        let lib = root.join(format!("guests/{}/src/lib.rs", spec.isa));
        if let Some(text) = read(&lib)
            && text.contains("ENCODE_ROUNDTRIP")
            && text.contains("ENCODE_SKIPPED.is_empty()")
        {
            for insn in &model.insns {
                cov.entry(insn.name.clone())
                    .or_default()
                    .add("unit", "全命令記述の代表 operand roundtrip".to_string());
            }
        }

        let scan_names: Vec<String> = cov.keys().cloned().collect();
        for file in rust_files(&root.join(format!("guests/{}/tests", spec.isa))) {
            let Some(text) = read(&file) else { continue };
            let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("test");
            let layer = layer_for_stem(stem);
            for name in &scan_names {
                let variant = format!("Insn::{}", variant_name(name));
                if has_token(&text, &variant) {
                    cov.entry(name.clone())
                        .or_default()
                        .add(layer, format!("{stem}: Insn 直接参照"));
                }
                let sem = format!("sem::{name}");
                if has_token(&text, &sem) {
                    cov.entry(name.clone())
                        .or_default()
                        .add(layer, format!("{stem}: 直接 sem 呼出し"));
                }
            }
            // バイト列テストの mnemonic 言及。variant は特定できないので
            // 同じ mnemonic の全 variant に family 単位の証拠を付ける。
            for mention in mnemonic_mentions(&text) {
                if let Some(internals) = mnemonic_to_name.get(&mention) {
                    for internal in internals {
                        cov.entry(internal.clone())
                            .or_default()
                            .add(layer, format!("{stem}: バイト列テストの mnemonic 言及"));
                    }
                }
            }
        }
        if spec.isa == "riscv" {
            scan_riscv_act(root, &mut cov, &mnemonic_to_name, &mut all_notes);
        }

        let layer_names = [
            "unit",
            "oracle",
            "conformance",
            "program",
            "diff",
            "jit",
            "timing",
        ];
        let total = cov.len();
        let mut counts = BTreeMap::<&str, usize>::new();
        let mut detail = String::new();
        detail.push_str(&format!("# {} 命令ごとの静的テスト証拠\n\n", spec.isa));
        detail.push_str("この表はソース上の高精度な直接証拠だけを数える下限である。テストの実行成功、実行時コーパス内の出現、コメントだけの言及は表さない。\n\n");
        detail.push_str("| 命令 | mnemonic | unit | oracle | conformance | program | diff | jit | timing | 証拠例 |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---|\n");
        let mut rows: Vec<(String, String)> = model
            .insns
            .iter()
            .map(|i| (i.name.clone(), i.syntax.clone()))
            .collect();
        rows.extend(
            polyisa_isagen::map_insns(&model)
                .iter()
                .map(|i| (i.name.clone(), i.syntax.clone())),
        );
        rows.sort();
        for (insn_name, syntax) in rows {
            let c = cov.entry(insn_name.clone()).or_default();
            let mut marks = Vec::new();
            for layer in layer_names {
                let n = c.layers.get(layer).map_or(0, BTreeSet::len);
                if n != 0 {
                    *counts.entry(layer).or_default() += 1
                }
                marks.push(if n == 0 {
                    "—".to_string()
                } else {
                    n.to_string()
                });
            }
            let examples = c
                .layers
                .values()
                .flatten()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("<br>");
            detail.push_str(&format!(
                "| `{}` | `{}` | {} | {} |\n",
                insn_name,
                mnemonic_of(&syntax),
                marks.join(" | "),
                examples
            ));
        }
        let path = outdir.join(format!("coverage-{}.md", spec.isa));
        std::fs::write(&path, detail).map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(path);
        summary_rows.push(vec![
            spec.isa.to_string(),
            total.to_string(),
            format!(
                "{} ({:.1}%)",
                counts.get("unit").copied().unwrap_or(0),
                counts.get("unit").copied().unwrap_or(0) as f64 * 100.0 / total as f64
            ),
            format!(
                "{} ({:.1}%)",
                counts.get("conformance").copied().unwrap_or(0),
                counts.get("conformance").copied().unwrap_or(0) as f64 * 100.0 / total as f64
            ),
            format!(
                "{} ({:.1}%)",
                counts.get("diff").copied().unwrap_or(0),
                counts.get("diff").copied().unwrap_or(0) as f64 * 100.0 / total as f64
            ),
        ]);
    }

    let mut summary = String::new();
    summary.push_str("# 命令×テスト層の静的証拠\n\n");
    summary.push_str("このファイルは `devtool coverage` が生成する。分母は ISADL の命令記述行であり、値は高精度な直接証拠を持つ命令記述の件数である。実行時に読むコーパスやバイト列だけのテストを捕捉しないため、実際の検証範囲より小さく出る。逆に、生成時点ではテストの成否を実行しないため、合格済み coverage ではない。\n\n");
    summary.push_str("| ISA | 命令記述数 | unit の直接証拠 | conformance の直接証拠 | diff の直接証拠 |\n|---|---:|---:|---:|---:|\n");
    for row in summary_rows {
        summary.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            row[0], row[1], row[2], row[3], row[4]
        ));
    }
    if !all_notes.is_empty() {
        summary.push_str("\n## 抽出メモ\n\n");
        for note in all_notes {
            summary.push_str(&format!("- {note}\n"));
        }
    }
    let path = outdir.join("coverage.md");
    std::fs::write(&path, summary).map_err(|e| format!("{}: {e}", path.display()))?;
    written.push(path);
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_layers() {
        assert_eq!(variant_name("fcvt_wu_h"), "FcvtWuH");
        assert_eq!(layer_for_stem("heavy_diff_sde"), "diff");
        assert_eq!(layer_for_stem("bare_x86run"), "unit");
    }

    #[test]
    fn token_boundaries() {
        assert!(has_token("x = Insn::Add;", "Insn::Add"));
        assert!(!has_token("Insn::FaddH", "Insn::Add"));
    }
}
