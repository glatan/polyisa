// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 横断課題一覧（`docs/known-issues.md`）とコード中の注記を検査する。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) struct IssueRow {
    pub line: usize,
    pub id: String,
    pub related: String,
    pub kind: String,
    pub resolution: String,
}

struct GapNote {
    file: String,
    line: usize,
    id: String,
}

pub(crate) fn check_issues(root: &Path) -> Result<(), String> {
    let text = read_to_string(&root.join("docs/known-issues.md"))?;
    let rows = parse_issue_table(&text);
    let notes = scan_gap_notes(root);
    let references = read_to_string(&root.join("docs/references.md")).unwrap_or_default();
    let registers = register_ids(&references);
    let violations = issue_violations(&rows, &notes, &registers, |path| {
        root.join("docs").join(path).is_file()
    });
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

pub(crate) fn parse_issue_table(text: &str) -> Vec<IssueRow> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if !t.starts_with('|') {
            in_table = false;
            continue;
        }
        let cols = split_row(t);
        if is_issue_header(&cols) {
            in_table = true;
            continue;
        }
        if !in_table || is_separator(&cols) {
            continue;
        }
        rows.push(IssueRow {
            line: i + 1,
            id: cell(&cols, 1),
            related: cell(&cols, 2),
            kind: cell(&cols, 4),
            resolution: cell(&cols, 5),
        });
    }
    rows
}

fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn issue_violations<F>(
    rows: &[IssueRow],
    notes: &[GapNote],
    registers: &BTreeSet<String>,
    doc_exists: F,
) -> Vec<String>
where
    F: Fn(&str) -> bool,
{
    let mut violations = Vec::new();
    if rows.is_empty() {
        violations.push("課題の表がない".to_string());
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
        if !matches!(row.kind.as_str(), "未着手" | "暫定") {
            violations.push(format!(
                "{}: 区分が未着手・暫定のどちらでもない ({})",
                row.id, row.kind
            ));
        }
        if row.resolution.trim().is_empty() {
            violations.push(format!("{}: 解消の条件が空", row.id));
        }
        for id in tracked_ids(&row.resolution) {
            if valid_gap_id(&id) && !all_ids.contains(id.as_str()) {
                violations.push(format!("{}: 解消の条件の {id} が一覧にない", row.id));
            } else if is_register_token(&id) && !registers.contains(&id) {
                violations.push(format!(
                    "{}: 解消の条件の {id} が参照資料の台帳にない",
                    row.id
                ));
            }
        }
        for path in link_paths(&row.related) {
            if !doc_exists(&path) {
                violations.push(format!("{}: 関連文書のリンク先がない ({path})", row.id));
            }
        }
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for note in notes {
        if !all_ids.contains(note.id.as_str()) {
            violations.push(format!(
                "{}:{}: docs/known-issues.md にない ID {}",
                note.file, note.line, note.id
            ));
        }
        *counts.entry(note.id.as_str()).or_default() += 1;
    }
    for row in rows {
        if row.kind == "暫定" && counts.get(row.id.as_str()).copied().unwrap_or(0) == 0 {
            violations.push(format!("{}: 区分が暫定だがコード注記がない", row.id));
        }
    }
    violations
}

fn split_row(line: &str) -> Vec<String> {
    line.split('|').map(|c| c.trim().to_string()).collect()
}

fn cell(cols: &[String], index: usize) -> String {
    cols.get(index).cloned().unwrap_or_default()
}

fn is_issue_header(cols: &[String]) -> bool {
    cols.len() >= 7
        && cols[1] == "ID"
        && cols[2] == "関連文書"
        && cols[3] == "内容"
        && cols[4] == "区分"
        && cols[5] == "解消の条件"
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
        if valid_gap_id(&token) || is_register_token(&token) {
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

    fn row(id: &str, kind: &str, resolution: &str) -> IssueRow {
        IssueRow {
            line: 1,
            id: id.to_string(),
            related: "[OS 層](architecture/os-layer.md)".to_string(),
            kind: kind.to_string(),
            resolution: resolution.to_string(),
        }
    }

    fn exists_doc(path: &str) -> bool {
        path == "architecture/os-layer.md"
    }

    #[test]
    fn current_tree_passes() {
        let root = crate::workspace_root();
        check_issues(&root).expect("known-issues");
    }

    #[test]
    fn unknown_note_id_is_a_violation() {
        let rows = vec![row("GAP-0001", "未着手", "済")];
        let notes = vec![GapNote {
            file: "a.rs".to_string(),
            line: 3,
            id: ["GAP-", "9999"].concat(),
        }];
        let v = issue_violations(&rows, &notes, &BTreeSet::new(), exists_doc);
        let missing = ["GAP-", "9999"].concat();
        assert!(v.iter().any(|s| s.contains(&missing)), "{v:?}");
    }

    #[test]
    fn provisional_without_note_is_a_violation() {
        let rows = vec![row("GAP-0001", "暫定", "済")];
        let v = issue_violations(&rows, &[], &BTreeSet::new(), exists_doc);
        assert!(v.iter().any(|s| s.contains("コード注記がない")), "{v:?}");
    }

    #[test]
    fn duplicate_gap_id_is_a_violation() {
        let rows = vec![
            row("GAP-0001", "未着手", "済"),
            row("GAP-0001", "未着手", "済"),
        ];
        let v = issue_violations(&rows, &[], &BTreeSet::new(), exists_doc);
        assert!(v.iter().any(|s| s.contains("重複")), "{v:?}");
    }

    #[test]
    fn empty_issue_table_is_a_violation() {
        let text = [
            "| ID | 設計 | 実装 | 区分 | 解消の条件 |",
            "|---|---|---|---|---|",
            "| GAP-0001 | [a](architecture/os-layer.md) | 差 | 未着手 | 済 |",
        ]
        .join("\n");
        let rows = parse_issue_table(&text);
        assert!(rows.is_empty());
        let v = issue_violations(&rows, &[], &BTreeSet::new(), exists_doc);
        assert!(v.iter().any(|s| s.contains("課題の表がない")), "{v:?}");
    }
}
