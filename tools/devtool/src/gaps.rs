// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 設計との差の台帳と、ロードマップの完了条件を検査する。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

struct GapRow {
    line: usize,
    id: String,
    design: String,
    kind: String,
    resolution: String,
}

struct GapNote {
    file: String,
    line: usize,
    id: String,
}

struct CompletionRow {
    line: usize,
    id: String,
    judgment: String,
}

pub(crate) fn check_gaps(root: &Path) -> Result<(), String> {
    let text = read_to_string(&root.join("docs/gaps.md"))?;
    let rows = parse_gap_table(&text);
    let notes = scan_gap_notes(root);
    let roadmap = read_to_string(&root.join("docs/design/roadmap.md")).unwrap_or_default();
    let references = read_to_string(&root.join("docs/references.md")).unwrap_or_default();
    let completion = completion_id_set(&roadmap);
    let adrs = adr_ids(root);
    let registers = register_ids(&references);
    let violations = gap_violations(&rows, &notes, &completion, &adrs, &registers, |path| {
        root.join("docs").join(path).is_file()
    });
    finish(violations)
}

pub(crate) fn check_completion(root: &Path) -> Result<(), String> {
    let text = read_to_string(&root.join("docs/design/roadmap.md"))?;
    let rows = parse_completion_table(&text);
    let violations = completion_violations(&rows, |name| test_binary_exists(root, name));
    finish(violations)
}

fn finish(violations: Vec<String>) -> Result<(), String> {
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn gap_violations<F>(
    rows: &[GapRow],
    notes: &[GapNote],
    completion: &BTreeSet<String>,
    adrs: &BTreeSet<String>,
    registers: &BTreeSet<String>,
    design_exists: F,
) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    let mut violations = Vec::new();
    if rows.is_empty() {
        violations.push("台帳の表がない".to_string());
        return violations;
    }
    let all_ids: BTreeSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for row in rows {
        if !valid_gap_id(&row.id) {
            violations.push(format!(
                "{} 行: ID が GAP- と 4 桁の数字ではない ({})",
                row.line, row.id
            ));
        }
        if let Some(prev) = seen.insert(row.id.as_str(), row.line) {
            violations.push(format!(
                "{}: ID が重複している（{prev} 行と {} 行）",
                row.id, row.line
            ));
        }
        if !matches!(row.kind.as_str(), "未着手" | "代替" | "対象外") {
            violations.push(format!(
                "{}: 区分が未着手・代替・対象外のどれでもない ({})",
                row.id, row.kind
            ));
        }
        if row.resolution.trim().is_empty() {
            violations.push(format!("{}: 解消の条件が空", row.id));
        }
        let mentioned = tracked_ids(&row.resolution);
        for id in &mentioned {
            if valid_gap_id(id) && !all_ids.contains(id.as_str()) {
                violations.push(format!("{}: 解消の条件の {id} が台帳にない", row.id));
            } else if valid_adr_id(id) && !adrs.contains(id) {
                violations.push(format!("{}: 解消の条件の {id} が ADR にない", row.id));
            } else if valid_completion_id(id) && !completion.contains(id) {
                violations.push(format!("{}: 解消の条件の {id} が完了条件にない", row.id));
            } else if is_register_token(id) && !registers.contains(id) {
                violations.push(format!(
                    "{}: 解消の条件の {id} が参照資料の台帳にない",
                    row.id
                ));
            }
        }
        if row.kind == "対象外" && !mentioned.iter().any(|id| valid_adr_id(id)) {
            violations.push(format!("{}: 解消の条件が ADR の番号を含まない", row.id));
        }
        for path in link_paths(&row.design) {
            if !design_exists(&path) {
                violations.push(format!("{}: 設計のリンク先がない ({path})", row.id));
            }
        }
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for note in notes {
        if !all_ids.contains(note.id.as_str()) {
            violations.push(format!(
                "{}:{}: 台帳にない ID {}",
                note.file, note.line, note.id
            ));
        }
        *counts.entry(note.id.as_str()).or_default() += 1;
    }
    for row in rows {
        if row.kind == "代替" && counts.get(row.id.as_str()).copied().unwrap_or(0) == 0 {
            violations.push(format!("{}: 区分が代替だが注記がない", row.id));
        }
    }
    violations
}

fn completion_violations<F>(rows: &[CompletionRow], test_exists: F) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    let mut violations = Vec::new();
    if rows.is_empty() {
        violations.push("完了条件の表がない".to_string());
        return violations;
    }
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for row in rows {
        if !valid_completion_id(&row.id) {
            violations.push(format!(
                "{} 行: ID が S<数>-<数> でも SC-<数> でもない ({})",
                row.line, row.id
            ));
        }
        if let Some(prev) = seen.insert(row.id.as_str(), row.line) {
            violations.push(format!(
                "{}: ID が重複している（{prev} 行と {} 行）",
                row.id, row.line
            ));
        }
        match parse_judgment(&row.judgment) {
            None => violations.push(format!(
                "{}: 判定の形がテスト・所有者・未整備のどれでもない ({})",
                row.id, row.judgment
            )),
            Some(Judgment::Owner | Judgment::Unprepared) => {}
            Some(Judgment::Tests(names)) => {
                for name in names {
                    if !test_exists(&name) {
                        violations.push(format!("{}: 判定のテスト {name} がない", row.id));
                    }
                }
            }
        }
    }
    violations
}

enum Judgment {
    Owner,
    Unprepared,
    Tests(Vec<String>),
}

fn parse_judgment(cell: &str) -> Option<Judgment> {
    let cell = cell.trim();
    if cell == "所有者" {
        return Some(Judgment::Owner);
    }
    if cell == "未整備" {
        return Some(Judgment::Unprepared);
    }
    let rest = cell.strip_prefix("テスト：")?.trim();
    if rest.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    for part in rest.split('、') {
        let part = part.trim();
        let name = part.strip_prefix('`')?.strip_suffix('`')?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        names.push(name.to_string());
    }
    if names.is_empty() {
        None
    } else {
        Some(Judgment::Tests(names))
    }
}

fn parse_gap_table(text: &str) -> Vec<GapRow> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if !t.starts_with('|') {
            in_table = false;
            continue;
        }
        let cols = split_row(t);
        if is_gap_header(&cols) {
            in_table = true;
            continue;
        }
        if !in_table || is_separator(&cols) {
            continue;
        }
        rows.push(GapRow {
            line: i + 1,
            id: cell(&cols, 1),
            design: cell(&cols, 2),
            kind: cell(&cols, 4),
            resolution: cell(&cols, 5),
        });
    }
    rows
}

fn parse_completion_table(text: &str) -> Vec<CompletionRow> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if !t.starts_with('|') {
            in_table = false;
            continue;
        }
        let cols = split_row(t);
        if is_completion_header(&cols) {
            in_table = true;
            continue;
        }
        if !in_table || is_separator(&cols) {
            continue;
        }
        rows.push(CompletionRow {
            line: i + 1,
            id: cell(&cols, 1),
            judgment: cell(&cols, 3),
        });
    }
    rows
}

fn completion_id_set(text: &str) -> BTreeSet<String> {
    parse_completion_table(text)
        .into_iter()
        .map(|r| r.id)
        .filter(|id| valid_completion_id(id))
        .collect()
}

fn split_row(line: &str) -> Vec<String> {
    line.split('|').map(|c| c.trim().to_string()).collect()
}

fn cell(cols: &[String], index: usize) -> String {
    cols.get(index).cloned().unwrap_or_default()
}

fn is_gap_header(cols: &[String]) -> bool {
    cols.len() >= 7
        && cols[1] == "ID"
        && cols[2] == "設計"
        && cols[3] == "現在の実装"
        && cols[4] == "区分"
        && cols[5] == "解消の条件"
}

fn is_completion_header(cols: &[String]) -> bool {
    cols.len() >= 5 && cols[1] == "ID" && cols[2] == "条件" && cols[3] == "判定"
}

fn is_separator(cols: &[String]) -> bool {
    cols.get(1)
        .is_some_and(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

fn valid_gap_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("GAP-") else {
        return false;
    };
    rest.len() == 4 && rest.bytes().all(|c| c.is_ascii_digit())
}

fn valid_adr_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("ADR-") else {
        return false;
    };
    rest.len() == 4 && rest.bytes().all(|c| c.is_ascii_digit())
}

fn valid_completion_id(id: &str) -> bool {
    if let Some(rest) = id.strip_prefix("SC-") {
        return !rest.is_empty() && rest.bytes().all(|c| c.is_ascii_digit());
    }
    let Some(rest) = id.strip_prefix('S') else {
        return false;
    };
    let Some((a, b)) = rest.split_once('-') else {
        return false;
    };
    !a.is_empty()
        && !b.is_empty()
        && a.bytes().all(|c| c.is_ascii_digit())
        && b.bytes().all(|c| c.is_ascii_digit())
}

fn is_register_token(id: &str) -> bool {
    const PREFIXES: [&str; 6] = ["SPEC-", "SRC-", "TEST-", "BIN-", "MEAS-", "TOOL-"];
    PREFIXES.iter().any(|p| {
        let Some(rest) = id.strip_prefix(p) else {
            return false;
        };
        !rest.is_empty()
            && rest
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'-')
    })
}

fn tracked_ids(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        if !is_id_char(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_id_char(chars[i]) {
            i += 1;
        }
        let token: String = chars[start..i].iter().collect();
        if valid_gap_id(&token)
            || valid_adr_id(&token)
            || valid_completion_id(&token)
            || is_register_token(&token)
        {
            out.push(token);
        }
    }
    out
}

fn is_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn link_paths(cell: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = cell;
    while let Some(pos) = rest.find("](") {
        rest = &rest[pos + 2..];
        let Some(end) = rest.find(')') else {
            break;
        };
        let raw = &rest[..end];
        let path = raw.split('#').next().unwrap_or(raw).trim();
        if !path.is_empty() {
            out.push(path.to_string());
        }
        rest = &rest[end + 1..];
    }
    out
}

fn adr_ids(root: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(rd) = std::fs::read_dir(root.join("docs/adr")) else {
        return set;
    };
    for entry in rd.flatten() {
        let os_name = entry.file_name();
        let Some(name) = os_name.to_str() else {
            continue;
        };
        if name.len() < 8 || !name.ends_with(".md") {
            continue;
        }
        let num = &name[..4];
        if name.as_bytes()[4] == b'-' && num.bytes().all(|c| c.is_ascii_digit()) {
            set.insert(format!("ADR-{num}"));
        }
    }
    set
}

fn register_ids(text: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        if !t.starts_with('|') {
            continue;
        }
        let cols = split_row(t);
        if cols.len() >= 2 && is_register_token(&cols[1]) {
            set.insert(cols[1].clone());
        }
    }
    set
}

fn test_binary_exists(root: &Path, name: &str) -> bool {
    for top in ["crates", "guests"] {
        let Ok(rd) = std::fs::read_dir(root.join(top)) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path().join("tests").join(format!("{name}.rs"));
            if path.is_file() {
                return true;
            }
        }
    }
    false
}

fn scan_gap_notes(root: &Path) -> Vec<GapNote> {
    let mut notes = Vec::new();
    let slash = slash_marker();
    for base in ["crates", "guests", "tools"] {
        let mut files = Vec::new();
        collect_files(&root.join(base), &mut files);
        files.sort();
        for file in files {
            if file.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            push_notes(&file, root, &slash, &mut notes);
        }
    }
    let hash = hash_marker();
    push_notes(&root.join("Taskfile.yml"), root, &hash, &mut notes);
    let config = root.join(".config");
    if let Ok(rd) = std::fs::read_dir(&config) {
        let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        for file in files {
            if file.extension().and_then(|s| s.to_str()) == Some("toml") {
                push_notes(&file, root, &hash, &mut notes);
            }
        }
    }
    notes
}

fn push_notes(file: &Path, root: &Path, marker: &str, out: &mut Vec<GapNote>) {
    let Ok(text) = std::fs::read_to_string(file) else {
        return;
    };
    let rel = file
        .strip_prefix(root)
        .unwrap_or(file)
        .display()
        .to_string();
    for (i, line) in text.lines().enumerate() {
        for id in ids_after(line, marker) {
            out.push(GapNote {
                file: rel.clone(),
                line: i + 1,
                id,
            });
        }
    }
}

fn ids_after(line: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(pos) = rest.find(marker) {
        rest = &rest[pos + marker.len()..];
        let token: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if !token.is_empty() {
            out.push(token);
        }
    }
    out
}

fn slash_marker() -> String {
    ["// Ga", "p:"].concat()
}

fn hash_marker() -> String {
    ["# Ga", "p:"].concat()
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str())
                && (name == "target" || name == ".testdata")
            {
                continue;
            }
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, kind: &str, resolution: &str) -> GapRow {
        GapRow {
            line: 1,
            id: id.to_string(),
            design: "[a](design/user-mode.md#構成)".to_string(),
            kind: kind.to_string(),
            resolution: resolution.to_string(),
        }
    }

    fn exists_design(path: &str) -> bool {
        path == "design/user-mode.md"
    }

    #[test]
    fn current_tree_passes() {
        let root = crate::workspace_root();
        check_gaps(&root).expect("gaps");
        check_completion(&root).expect("completion");
    }

    #[test]
    fn unknown_note_id_is_a_violation() {
        let rows = vec![row("GAP-0001", "未着手", "済")];
        let notes = vec![GapNote {
            file: "a.rs".to_string(),
            line: 3,
            id: ["GAP-", "9999"].concat(),
        }];
        let v = gap_violations(
            &rows,
            &notes,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            exists_design,
        );
        let missing = ["GAP-", "9999"].concat();
        assert!(v.iter().any(|s| s.contains(&missing)), "{v:?}");
    }

    #[test]
    fn alternative_without_note_is_a_violation() {
        let rows = vec![row("GAP-0001", "代替", "済")];
        let v = gap_violations(
            &rows,
            &[],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            exists_design,
        );
        assert!(v.iter().any(|s| s.contains("注記がない")), "{v:?}");
    }

    #[test]
    fn excluded_without_adr_is_a_violation() {
        let rows = vec![row("GAP-0004", "対象外", "番号表のままにする")];
        let v = gap_violations(
            &rows,
            &[],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            exists_design,
        );
        assert!(v.iter().any(|s| s.contains("ADR")), "{v:?}");
    }

    #[test]
    fn missing_completion_id_is_a_violation() {
        let rows = vec![row("GAP-0001", "未着手", "S9-9")];
        let v = gap_violations(
            &rows,
            &[],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            exists_design,
        );
        assert!(v.iter().any(|s| s.contains("S9-9")), "{v:?}");
    }

    #[test]
    fn duplicate_gap_id_is_a_violation() {
        let rows = vec![
            row("GAP-0001", "未着手", "済"),
            row("GAP-0001", "未着手", "済"),
        ];
        let v = gap_violations(
            &rows,
            &[],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            exists_design,
        );
        assert!(v.iter().any(|s| s.contains("重複")), "{v:?}");
    }

    #[test]
    fn missing_test_binary_is_a_violation() {
        let rows = vec![CompletionRow {
            line: 2,
            id: "S0-1".to_string(),
            judgment: format!("テスト：`{}`", ["not_a_real", "_test"].concat()),
        }];
        let v = completion_violations(&rows, |_| false);
        assert!(v.iter().any(|s| s.contains("テスト")), "{v:?}");
    }

    #[test]
    fn empty_gap_table_is_a_violation() {
        let text = [
            "| ID | 設計 | 実装 | 区分 | 解消の条件 |",
            "|---|---|---|---|---|",
            "| GAP-0001 | [a](design/user-mode.md) | 差 | 未着手 | 済 |",
        ]
        .join("\n");
        let rows = parse_gap_table(&text);
        assert!(rows.is_empty());
        let v = gap_violations(
            &rows,
            &[],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            exists_design,
        );
        assert!(v.iter().any(|s| s.contains("台帳の表がない")), "{v:?}");
    }

    #[test]
    fn empty_completion_table_is_a_violation() {
        let text = [
            "| ID | 内容 | 判定 |",
            "|---|---|---|",
            "| S0-1 | 条件 | 所有者 |",
        ]
        .join("\n");
        let rows = parse_completion_table(&text);
        assert!(rows.is_empty());
        let v = completion_violations(&rows, |_| true);
        assert!(v.iter().any(|s| s.contains("完了条件の表がない")), "{v:?}");
    }

    #[test]
    fn duplicate_completion_id_is_a_violation() {
        let rows = vec![
            CompletionRow {
                line: 2,
                id: "SC-1".to_string(),
                judgment: "所有者".to_string(),
            },
            CompletionRow {
                line: 3,
                id: "SC-1".to_string(),
                judgment: "所有者".to_string(),
            },
        ];
        let v = completion_violations(&rows, |_| true);
        assert!(v.iter().any(|s| s.contains("重複")), "{v:?}");
    }
}
