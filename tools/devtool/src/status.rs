// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 追跡しているファイルから `docs/status/` を生成し、鮮度を検査する。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use polyisa_isadl::model::MapItem;
use polyisa_isadl::{Model, Pred};

use crate::specs;

const NOTICE: &str = "このファイルは `task status` が生成する。手で編集しない。";

pub(crate) fn write_status(root: &Path) -> Result<Vec<PathBuf>, String> {
    let files = generate_status(root)?;
    let dir = root.join("docs/status");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !files.contains_key(&name) && entry.path().is_file() {
                std::fs::remove_file(entry.path())
                    .map_err(|e| format!("{}: {e}", entry.path().display()))?;
            }
        }
    }
    let mut written = Vec::new();
    for (name, body) in &files {
        let path = dir.join(name);
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

pub(crate) fn check_fresh(root: &Path) -> Result<(), String> {
    let generated = generate_status(root)?;
    let actual = read_status_dir(&root.join("docs/status"));
    let violations = freshness_violations(&generated, &actual);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

pub(crate) fn generate_status(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let roadmap = read_to_string(&root.join("docs/design/roadmap.md"))?;
    let gaps = read_to_string(&root.join("docs/gaps.md"))?;
    let syscalls = load_syscall_tables(root)?;
    let mut models = BTreeMap::new();
    for spec in specs::isa_specs() {
        models.insert(spec.isa, (spec.build)());
    }
    Ok(render_status(
        &models,
        specs::isa_specs(),
        &roadmap,
        &gaps,
        &syscalls,
    ))
}

pub(crate) fn check_syscall_tables(root: &Path) -> Result<(), String> {
    load_syscall_tables(root).map(|_| ())
}

fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_status_dir(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                out.insert(format!("{name}/"), String::new());
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.insert(name.to_string(), text);
        }
    }
    out
}

pub(crate) fn freshness_violations(
    generated: &BTreeMap<String, String>,
    actual: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for name in generated.keys() {
        match actual.get(name) {
            None => violations.push(format!(
                "docs/status/{name}: ない。go-task status を実行する"
            )),
            Some(body) if body != generated.get(name).expect("key") => violations.push(format!(
                "docs/status/{name}: 内容が生成結果と異なる。go-task status を実行する"
            )),
            Some(_) => {}
        }
    }
    for name in actual.keys() {
        if !generated.contains_key(name) {
            violations.push(format!(
                "docs/status/{name}: 生成しないファイルがある。go-task status を実行する"
            ));
        }
    }
    violations
}

struct IndexedModel<'a> {
    isa: &'a str,
    rel_paths: &'a [&'a str],
    model: &'a Model,
}

pub(crate) fn render_status(
    models: &BTreeMap<&str, Model>,
    specs: &[specs::IsaSpec],
    roadmap: &str,
    gaps: &str,
    syscalls: &[GuestSyscalls],
) -> BTreeMap<String, String> {
    let mut indexed = Vec::new();
    for spec in specs {
        if let Some(model) = models.get(spec.isa) {
            indexed.push(IndexedModel {
                isa: spec.isa,
                rel_paths: spec.rel_paths,
                model,
            });
        }
    }
    indexed.sort_by_key(|m| m.isa);
    let mut files = BTreeMap::new();
    files.insert(
        "README.md".to_string(),
        render_index(&indexed, roadmap, gaps, syscalls),
    );
    for item in &indexed {
        files.insert(format!("isa-{}.md", item.isa), render_isa(item));
    }
    files.insert("syscalls.md".to_string(), render_syscalls(syscalls));
    files
}

fn render_index(
    models: &[IndexedModel<'_>],
    roadmap: &str,
    gaps: &str,
    syscalls: &[GuestSyscalls],
) -> String {
    let mut s = String::new();
    push_generated_heading(&mut s, "# 実装状況");
    s.push_str(
        "生成の元は、ISADL の記述（`guests/*/spec/`）、ロードマップの完了条件、設計との差の台帳、システムコールの表（`crates/os-linux/src/rv64/sys.rs` の `RV64_SYSCALLS`、`crates/os-linux/src/x86/sys.rs` の `X86_64_SYSCALLS` と `X86_32_SYSCALLS`、`crates/os-linux/src/mips_o32.rs`・`mips_n32.rs`・`mips_n64.rs`・`aarch64.rs`・`power.rs` の各 `SYSCALLS`）である。テストの結果は含めない。\n\n",
    );
    s.push_str("## 段階の完了条件\n\n");
    s.push_str("条件の文言は [ロードマップ](../design/roadmap.md) にある。\n\n");
    s.push_str(&md_table(
        &["ID", "判定"],
        &completion_rows(roadmap)
            .into_iter()
            .map(|(id, judgment)| vec![id, judgment])
            .collect::<Vec<_>>(),
    ));
    s.push_str("\n## ISA\n\n");
    let isa_rows: Vec<Vec<String>> = models
        .iter()
        .map(|item| {
            let attrs = insn_attrs(item.model);
            let mnemonics = mnemonic_rows(&attrs);
            let models = item
                .model
                .models
                .iter()
                .map(|m| m.name.as_str())
                .collect::<Vec<_>>()
                .join("、");
            vec![
                item.isa.to_string(),
                attrs.len().to_string(),
                distinct_mnemonics(&mnemonics).to_string(),
                models,
                format!("[isa-{}.md](isa-{}.md)", item.isa, item.isa),
            ]
        })
        .collect();
    s.push_str(&md_table(
        &["ISA", "命令の記述", "ニーモニック", "CPU モデル", "詳細"],
        &isa_rows,
    ));
    s.push_str("\n## システムコール\n\n");
    let sys_rows: Vec<Vec<String>> = syscalls
        .iter()
        .map(|table| {
            vec![
                table.abi.to_string(),
                table.names.len().to_string(),
                "[syscalls.md](syscalls.md)".to_string(),
            ]
        })
        .collect();
    s.push_str(&md_table(
        &["ゲスト ABI", "処理するシステムコール", "詳細"],
        &sys_rows,
    ));
    s.push_str("\n## 設計との差\n\n");
    let gap_rows = gap_rows(gaps);
    s.push_str(&format!(
        "台帳は [設計との差の台帳](../gaps.md) にある。{}\n\n",
        kind_counts(&gap_rows)
    ));
    let listed: Vec<Vec<String>> = gap_rows
        .into_iter()
        .map(|(id, design, kind)| vec![id, kind, rewrite_links(&design)])
        .collect();
    s.push_str(&md_table(&["ID", "区分", "設計"], &listed));
    s
}

fn render_isa(item: &IndexedModel<'_>) -> String {
    let mut s = String::new();
    push_generated_heading(&mut s, &format!("# 実装状況：{}", item.isa));
    s.push_str(&format!(
        "生成の元は `{}` である。\n\n",
        item.rel_paths.join("`・`")
    ));
    s.push_str("## CPU モデル\n\n");
    let mut cpu = item.model.models.clone();
    cpu.sort_by(|a, b| a.name.cmp(&b.name));
    let cpu_rows: Vec<Vec<String>> = cpu
        .iter()
        .map(|m| {
            vec![
                m.name.clone(),
                m.parent.clone(),
                m.add_features.join("、"),
                m.remove_features.join("、"),
            ]
        })
        .collect();
    s.push_str(&md_table(
        &["名前", "親", "足す機能", "除く機能"],
        &cpu_rows,
    ));
    s.push_str("\n## 機能\n\n");
    let mut features: Vec<&str> = item
        .model
        .features
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    features.sort_unstable();
    if features.is_empty() {
        s.push_str("機能の宣言はない。\n");
    } else {
        for name in features {
            s.push_str(&format!("- {name}\n"));
        }
    }
    s.push_str("\n## 命令\n\n");
    let rows = mnemonic_rows(&insn_attrs(item.model));
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            vec![
                row.mnemonic.clone(),
                row.names.join("、"),
                row.condition.clone(),
                row.timing.clone(),
            ]
        })
        .collect();
    s.push_str(&md_table(
        &["ニーモニック", "記述", "条件", "タイミング"],
        &table_rows,
    ));
    s
}

struct MnemonicRow {
    mnemonic: String,
    names: Vec<String>,
    condition: String,
    timing: String,
}

/// ニーモニックを `syntax` から取る。
/// 先頭の述語の前置き（`(` で始まり `)` で終わる語）を除く。
/// 残りが空白を含まない左辺と `=` と右辺なら、右辺の先頭（`(` か空白の前まで）を取る。
/// それ以外は最初の語を取る。空、または取り出した語が ASCII の英字で始まらなければ、記述の名前を使う。
pub(crate) fn mnemonic_of(syntax: &str, name: &str) -> String {
    let mut words: Vec<&str> = syntax.split_whitespace().collect();
    while words
        .first()
        .is_some_and(|word| word.starts_with('(') && word.ends_with(')'))
    {
        words.remove(0);
    }
    if words.is_empty() {
        return name.to_string();
    }
    let rest = words.join(" ");
    let token = if let Some((lhs, rhs)) = rest.split_once(" = ")
        && !lhs.chars().any(char::is_whitespace)
    {
        let ident: String = rhs
            .chars()
            .take_while(|c| *c != '(' && !c.is_whitespace())
            .collect();
        if ident.is_empty() {
            words[0].to_string()
        } else {
            ident
        }
    } else {
        words[0].to_string()
    };
    match token.chars().next() {
        // `{0}` はオペコード表の記述でニーモニックを置く占位子。
        // 記述名は `{ニーモニック}_{形}` なので先頭の区切りを取る。
        Some('{') => name.split('_').next().unwrap_or(name).to_string(),
        Some(c) if c.is_ascii_alphabetic() => token,
        _ => name.to_string(),
    }
}

pub(crate) fn pred_string(pred: &Pred) -> String {
    fmt_pred(pred, 0)
}

fn fmt_pred(pred: &Pred, prec: u8) -> String {
    match pred {
        Pred::True => "真".to_string(),
        Pred::False => "偽".to_string(),
        Pred::Flag(name) => name.clone(),
        Pred::Not(inner) => format!("!{}", fmt_pred(inner, 2)),
        Pred::All(ps) if ps.is_empty() => "真".to_string(),
        Pred::Any(ps) if ps.is_empty() => "偽".to_string(),
        Pred::All(ps) => {
            let body = ps
                .iter()
                .map(|p| fmt_pred(p, 1))
                .collect::<Vec<_>>()
                .join(" && ");
            if prec > 1 { format!("({body})") } else { body }
        }
        Pred::Any(ps) => {
            let body = ps
                .iter()
                .map(|p| fmt_pred(p, 0))
                .collect::<Vec<_>>()
                .join(" || ");
            if prec > 0 { format!("({body})") } else { body }
        }
    }
}

/// 命令の表に載せる属性。`Insn`（バイト列照合の記述）と
/// `MapInsn`（オペコード表の記述）の両方から取る。
type InsnAttr<'a> = (&'a str, &'a str, &'a Pred, &'a str);

fn insn_attrs(model: &Model) -> Vec<InsnAttr<'_>> {
    model
        .insns
        .iter()
        .map(|i| {
            (
                i.name.as_str(),
                i.syntax.as_str(),
                &i.when,
                i.timing.as_str(),
            )
        })
        .chain(model.maps.iter().flat_map(|m| {
            m.items.iter().filter_map(|it| match it {
                MapItem::Insn(_, mi) => Some((
                    mi.name.as_str(),
                    mi.syntax.as_str(),
                    &mi.when,
                    mi.timing.as_str(),
                )),
                MapItem::Map(_, _) => None,
            })
        }))
        .collect()
}

fn mnemonic_rows(insns: &[InsnAttr<'_>]) -> Vec<MnemonicRow> {
    let mut groups: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
    for (name, syntax, when, timing) in insns {
        let key = (
            mnemonic_of(syntax, name),
            pred_string(when),
            (*timing).to_string(),
        );
        groups.entry(key).or_default().insert((*name).to_string());
    }
    groups
        .into_iter()
        .map(|((mnemonic, condition, timing), names)| MnemonicRow {
            mnemonic,
            names: names.into_iter().collect(),
            condition,
            timing,
        })
        .collect()
}

fn distinct_mnemonics(rows: &[MnemonicRow]) -> usize {
    rows.iter()
        .map(|r| r.mnemonic.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn kind_counts(rows: &[(String, String, String)]) -> String {
    let mut counts = BTreeMap::new();
    for (_, _, kind) in rows {
        *counts.entry(kind.as_str()).or_insert(0usize) += 1;
    }
    let n = |k: &str| counts.get(k).copied().unwrap_or(0);
    format!(
        "未着手は {} 件、代替は {} 件、対象外は {} 件である。",
        n("未着手"),
        n("代替"),
        n("対象外")
    )
}

fn completion_rows(text: &str) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        let t = line.trim();
        if !t.starts_with('|') {
            in_table = false;
            continue;
        }
        let cols = split_row(t);
        if cols.len() >= 5 && cols[1] == "ID" && cols[2] == "条件" && cols[3] == "判定" {
            in_table = true;
            continue;
        }
        if !in_table || is_separator(&cols) {
            continue;
        }
        rows.push((cell(&cols, 1), cell(&cols, 3)));
    }
    rows
}

fn gap_rows(text: &str) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        let t = line.trim();
        if !t.starts_with('|') {
            in_table = false;
            continue;
        }
        let cols = split_row(t);
        if cols.len() >= 7
            && cols[1] == "ID"
            && cols[2] == "設計"
            && cols[3] == "現在の実装"
            && cols[4] == "区分"
            && cols[5] == "解消の条件"
        {
            in_table = true;
            continue;
        }
        if !in_table || is_separator(&cols) {
            continue;
        }
        rows.push((cell(&cols, 1), cell(&cols, 2), cell(&cols, 4)));
    }
    rows
}

fn split_row(line: &str) -> Vec<String> {
    line.split('|').map(|c| c.trim().to_string()).collect()
}

fn cell(cols: &[String], index: usize) -> String {
    cols.get(index).cloned().unwrap_or_default()
}

fn is_separator(cols: &[String]) -> bool {
    cols.get(1)
        .is_some_and(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

pub(crate) fn rewrite_links(cell: &str) -> String {
    let mut out = String::new();
    let mut rest = cell;
    while let Some(i) = rest.find("](") {
        out.push_str(&rest[..i + 2]);
        rest = &rest[i + 2..];
        let Some(end) = rest.find(')') else {
            break;
        };
        let path = &rest[..end];
        if path.starts_with("http://")
            || path.starts_with("https://")
            || path.starts_with('#')
            || path.starts_with("../")
        {
            out.push_str(path);
        } else {
            out.push_str("../");
            out.push_str(path);
        }
        out.push(')');
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

fn push_generated_heading(out: &mut String, heading: &str) {
    out.push_str(heading);
    out.push_str("\n\n");
    out.push_str(NOTICE);
    out.push_str("\n\n");
}

pub(crate) struct GuestSyscalls {
    abi: &'static str,
    names: Vec<String>,
}

fn load_syscall_tables(root: &Path) -> Result<Vec<GuestSyscalls>, String> {
    let rv = read_to_string(&root.join("crates/os-linux/src/rv64/sys.rs"))?;
    let x86 = read_to_string(&root.join("crates/os-linux/src/x86/sys.rs"))?;
    let mips = read_to_string(&root.join("crates/os-linux/src/mips_o32.rs"))?;
    let mips_n32 = read_to_string(&root.join("crates/os-linux/src/mips_n32.rs"))?;
    let mips_n64 = read_to_string(&root.join("crates/os-linux/src/mips_n64.rs"))?;
    let aarch64 = read_to_string(&root.join("crates/os-linux/src/aarch64.rs"))?;
    let power = read_to_string(&root.join("crates/os-linux/src/power.rs"))?;
    Ok(vec![
        GuestSyscalls {
            abi: "rv64",
            names: parse_sys_table(&rv, "RV64_SYSCALLS", "crates/os-linux/src/rv64/sys.rs")?,
        },
        GuestSyscalls {
            abi: "x86_64",
            names: parse_sys_table(&x86, "X86_64_SYSCALLS", "crates/os-linux/src/x86/sys.rs")?,
        },
        GuestSyscalls {
            abi: "x86_32",
            names: parse_sys_table(&x86, "X86_32_SYSCALLS", "crates/os-linux/src/x86/sys.rs")?,
        },
        GuestSyscalls {
            abi: "mips_o32",
            names: parse_sys_table(&mips, "SYSCALLS", "crates/os-linux/src/mips_o32.rs")?,
        },
        GuestSyscalls {
            abi: "mips_n32",
            names: parse_sys_table(&mips_n32, "SYSCALLS", "crates/os-linux/src/mips_n32.rs")?,
        },
        GuestSyscalls {
            abi: "mips_n64",
            names: parse_sys_table(&mips_n64, "SYSCALLS", "crates/os-linux/src/mips_n64.rs")?,
        },
        GuestSyscalls {
            abi: "aarch64",
            names: parse_sys_table(&aarch64, "SYSCALLS", "crates/os-linux/src/aarch64.rs")?,
        },
        GuestSyscalls {
            abi: "power",
            names: parse_sys_table(&power, "SYSCALLS", "crates/os-linux/src/power.rs")?,
        },
    ])
}

fn parse_sys_table(src: &str, const_name: &str, origin: &str) -> Result<Vec<String>, String> {
    let marker = format!("const {const_name}");
    let Some(at) = src.find(&marker) else {
        return Err(format!("{origin}: {const_name} がない"));
    };
    let rest = &src[at..];
    let Some(open) = rest.find("= &[") else {
        return Err(format!("{origin}: {const_name} の開始がない"));
    };
    let after = &rest[open + 4..];
    let Some(end) = after.find("];") else {
        return Err(format!("{origin}: {const_name} の終わりがない"));
    };
    let mut names = Vec::new();
    for raw in after[..end].lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let Some(name) = syscall_entry_name(line) else {
            return Err(format!("{origin}: {const_name}: 行の形が違う: {line}"));
        };
        names.push(name);
    }
    if names.is_empty() {
        return Err(format!("{origin}: {const_name} が空"));
    }
    Ok(names)
}

/// `("名前", sys_名前),` の名前。関数名が名前と違う行は受け付けない。
fn syscall_entry_name(line: &str) -> Option<String> {
    // (番号, "名前"), の形も受け付ける。
    if let Some(rest) = line.strip_prefix('(')
        && let Some((num, rest)) = rest.split_once(',')
        && num.trim().chars().all(|c| c.is_ascii_digit())
    {
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('"')?;
        let (name, rest) = rest.split_once('"')?;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return None;
        }
        rest.trim_start().strip_prefix("),")?;
        return Some(name.to_string());
    }
    let rest = line.strip_prefix("(\"")?;
    let (name, rest) = rest.split_once('"')?;
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    let rest = rest.trim_start().strip_prefix(',')?.trim_start();
    let rest = rest.strip_prefix("sys_")?;
    let rest = rest.strip_suffix("),")?;
    if rest != name {
        return None;
    }
    Some(name.to_string())
}

fn render_syscalls(tables: &[GuestSyscalls]) -> String {
    let mut s = String::new();
    push_generated_heading(&mut s, "# 実装状況：システムコール");
    s.push_str(
        "生成の元は `crates/os-linux/src/rv64/sys.rs` の `RV64_SYSCALLS` と、`crates/os-linux/src/x86/sys.rs` の `X86_64_SYSCALLS`、`X86_32_SYSCALLS`、`crates/os-linux/src/mips_o32.rs`・`mips_n32.rs`・`mips_n64.rs`・`aarch64.rs`・`power.rs` の各 `SYSCALLS` である。\n\n",
    );
    for table in tables {
        s.push_str(&format!("## {}\n\n", table.abi));
        let mut names = table.names.clone();
        names.sort();
        for name in names {
            s.push_str(&format!("- {name}\n"));
        }
        s.push('\n');
    }
    s
}

fn md_table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut s = String::new();
    s.push('|');
    for h in header {
        s.push(' ');
        s.push_str(h);
        s.push_str(" |");
    }
    s.push_str("\n|");
    for _ in header {
        s.push_str("---|");
    }
    s.push('\n');
    for row in rows {
        s.push('|');
        for cell in row {
            s.push(' ');
            s.push_str(cell);
            s.push_str(" |");
        }
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_isadl::model::Insn;

    fn sample_insn(name: &str, syntax: &str, when: Pred, timing: &str) -> Insn {
        Insn {
            name: name.to_string(),
            format: "F".to_string(),
            pattern: polyisa_isadl::Pattern::parse("0").expect("pattern"),
            when,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        }
    }

    #[test]
    fn same_input_renders_twice_identically() {
        let root = crate::workspace_root();
        let a = generate_status(&root).expect("first");
        let b = generate_status(&root).expect("second");
        assert_eq!(a, b);
    }

    #[test]
    fn fresh_tree_matches_when_generated() {
        check_fresh(&crate::workspace_root()).expect("fresh");
    }

    #[test]
    fn content_diff_is_detected() {
        let mut generated = BTreeMap::new();
        generated.insert("README.md".to_string(), "a\n".to_string());
        let mut actual = generated.clone();
        actual.insert("README.md".to_string(), "b\n".to_string());
        let v = freshness_violations(&generated, &actual);
        assert!(
            v.iter().any(|s| s.contains("内容が生成結果と異なる")),
            "{v:?}"
        );
        assert!(v.iter().any(|s| s.contains("go-task status")), "{v:?}");
    }

    #[test]
    fn missing_file_is_detected() {
        let mut generated = BTreeMap::new();
        generated.insert("README.md".to_string(), "a\n".to_string());
        let v = freshness_violations(&generated, &BTreeMap::new());
        assert!(v.iter().any(|s| s.contains("ない")), "{v:?}");
    }

    #[test]
    fn extra_file_is_detected() {
        let generated = BTreeMap::new();
        let mut actual = BTreeMap::new();
        actual.insert("notes.md".to_string(), "x\n".to_string());
        let v = freshness_violations(&generated, &actual);
        assert!(v.iter().any(|s| s.contains("生成しないファイル")), "{v:?}");
    }

    #[test]
    fn mnemonic_groups_by_first_word_and_splits_conditions() {
        let insns = [
            sample_insn("add_rm", "add r/m, {imm}", Pred::True, "alu"),
            sample_insn("add_r", "add r, {imm}", Pred::True, "alu"),
            sample_insn(
                "add_rv32",
                "add rd, rs",
                Pred::Flag("rv32".to_string()),
                "alu",
            ),
            sample_insn("jump", "", Pred::True, "jump"),
            sample_insn("sub", "r{rd} = sub(r{rs1}, r{rs2})", Pred::True, "alu"),
        ];
        let attrs: Vec<InsnAttr> = insns
            .iter()
            .map(|i| {
                (
                    i.name.as_str(),
                    i.syntax.as_str(),
                    &i.when,
                    i.timing.as_str(),
                )
            })
            .collect();
        let rows = mnemonic_rows(&attrs);
        let add_true = rows
            .iter()
            .find(|r| r.mnemonic == "add" && r.condition == "真")
            .expect("add");
        assert_eq!(
            add_true.names,
            vec!["add_r".to_string(), "add_rm".to_string()]
        );
        assert!(
            rows.iter()
                .any(|r| r.mnemonic == "add" && r.condition == "rv32")
        );
        assert!(
            rows.iter()
                .any(|r| r.mnemonic == "jump" && r.names == ["jump"])
        );
        assert!(rows.iter().any(|r| r.mnemonic == "sub"));
        assert_eq!(distinct_mnemonics(&rows), 3);
    }

    #[test]
    fn mnemonic_strips_predicate_and_reads_assignment() {
        assert_eq!(mnemonic_of("(p0) add r{rd} = r{r1}, r{r2}", "add"), "add");
        assert_eq!(
            mnemonic_of("(qp) add r{rd} = r{r1}, r{r2}", "add_pred"),
            "add"
        );
        assert_eq!(
            mnemonic_of("(p0) add.rot r{rd} = r{r1}, r{r2}", "add_rot"),
            "add.rot"
        );
        assert_eq!(mnemonic_of("nop", "nop"), "nop");
        assert_eq!(mnemonic_of("br {imm}", "br"), "br");
        assert_eq!(mnemonic_of("r{rd} = add(r{rs1}, r{rs2})", "add"), "add");
        assert_eq!(mnemonic_of("r{rd} = sub(r{rs1}, r{rs2})", "sub"), "sub");
        assert_eq!(mnemonic_of("r{rd} = #{imm}", "mov_imm"), "mov_imm");
        assert_eq!(mnemonic_of("jump {imm}", "jump"), "jump");
        assert_eq!(mnemonic_of("", "jump"), "jump");
        assert_eq!(mnemonic_of("(p0)", "bare"), "bare");
    }

    #[test]
    fn mnemonic_without_ascii_letter_uses_the_description_name() {
        assert_eq!(mnemonic_of("r{rd} = #{imm}", "mov_imm"), "mov_imm");
        assert_eq!(mnemonic_of("r{rd} = add(r{rs1}, r{rs2})", "add"), "add");
    }

    #[test]
    fn syscall_table_rejects_a_broken_line() {
        let src = "const X86_64_SYSCALLS: &[(&str, SysFn)] = &[\n    (\"read\", sys_read),\n    read,\n];\n";
        let err = parse_sys_table(src, "X86_64_SYSCALLS", "x86/sys.rs").unwrap_err();
        assert!(err.contains("行の形が違う"), "{err}");
    }

    #[test]
    fn syscall_table_rejects_a_missing_const() {
        let err = parse_sys_table("", "RV64_SYSCALLS", "rv64/sys.rs").unwrap_err();
        assert!(err.contains("がない"), "{err}");
    }

    #[test]
    fn predicate_uses_source_operators() {
        let pred = Pred::All(vec![
            Pred::Flag("rv64".to_string()),
            Pred::Not(Box::new(Pred::Flag("mips_r6".to_string()))),
        ]);
        assert_eq!(pred_string(&pred), "rv64 && !mips_r6");
        let any = Pred::Any(vec![
            Pred::Flag("a".to_string()),
            Pred::All(vec![
                Pred::Flag("b".to_string()),
                Pred::Not(Box::new(Pred::Flag("c".to_string()))),
            ]),
        ]);
        assert_eq!(pred_string(&any), "a || b && !c");
        assert_eq!(pred_string(&Pred::True), "真");
    }

    #[test]
    fn design_links_are_relative_to_status() {
        let cell = "[節](design/user-mode.md#構成)、[ADR](../adr/0014-statfs-number-table-only.md)";
        let got = rewrite_links(cell);
        assert!(got.contains("](../design/user-mode.md#構成)"), "{got}");
        assert!(
            got.contains("](../adr/0014-statfs-number-table-only.md)"),
            "{got}"
        );
        assert!(!got.contains("](../../adr/"), "{got}");
    }
}
