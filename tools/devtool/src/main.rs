// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 開発作業のコマンド。成果物に含まれない。外部クレートに依存しない。
//!
//! タスクから呼ぶ薄い入口にし、条件分岐とデータ処理はここに書く.

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage_and_exit());
    let code = match cmd.as_str() {
        "check" => cmd_check(),
        "refs:check" => cmd_refs_check(),
        "doctor" => cmd_doctor(),
        "testdata:fetch" => cmd_testdata_fetch(),
        "hooks:install" => cmd_hooks_install(),
        _ => {
            eprintln!("unknown subcommand: {cmd}");
            eprintln!("usage: devtool <check|refs:check|doctor|testdata:fetch|hooks:install>");
            1
        }
    };
    std::process::exit(code);
}

fn usage_and_exit() -> ! {
    eprintln!("usage: devtool <check|refs:check|doctor|testdata:fetch|hooks:install>");
    std::process::exit(2);
}

/// ワークスペースのルート（`docs/references.md` を持つ祖先）を探す。
fn workspace_root() -> std::path::PathBuf {
    let mut dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    loop {
        if dir.join("docs/references.md").exists() {
            return dir;
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => return std::path::PathBuf::from("."),
        }
    }
}

/// `task check` のうち devtool が担う規則の検査。
fn cmd_check() -> i32 {
    let mut failed = false;
    if let Err(e) = check_no_external_crates() {
        eprintln!("check: 外部依存の禁止: {e}");
        failed = true;
    }
    if let Err(e) = check_dep_rules() {
        eprintln!("check: 依存規則: {e}");
        failed = true;
    }
    if let Err(e) = check_cfg_rules() {
        eprintln!("check: cfg の規則: {e}");
        failed = true;
    }
    if let Err(e) = check_refs_full() {
        eprintln!("check: 台帳の検査: {e}");
        failed = true;
    }
    if failed {
        1
    } else {
        println!("check: ok");
        0
    }
}

/// `task refs:check` の実体。台帳の表が読めることを確かめる。
fn cmd_refs_check() -> i32 {
    let count = match check_refs_register() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("refs:check: {e}");
            return 1;
        }
    };
    match check_refs_full() {
        Ok(()) => {
            println!("refs:check: ok ({count} ids)");
            0
        }
        Err(e) => {
            eprintln!("refs:check: {e}");
            1
        }
    }
}

/// 外部ツールとターゲットの有無と版を表示する。失敗しても exit 0。
fn cmd_doctor() -> i32 {
    for tool in [
        "rustc",
        "cargo",
        "go-task",
        "task",
        "cargo-nextest",
        "curl",
        "git",
    ] {
        match std::process::Command::new(tool).arg("--version").output() {
            Ok(out) => {
                let v = String::from_utf8_lossy(&out.stdout);
                let v = v.lines().next().unwrap_or("").trim();
                println!("{tool}: {v}");
            }
            Err(_) => println!("{tool}: not found"),
        }
    }
    match std::process::Command::new("rustup")
        .arg("target")
        .arg("list")
        .arg("--installed")
        .output()
    {
        Ok(out) => {
            println!("targets:");
            print!("{}", String::from_utf8_lossy(&out.stdout));
        }
        Err(_) => println!("targets: rustup not found"),
    }
    0
}

/// テストデータの取得。`tools/testdata/manifest.txt` の定義に従い、
/// 取得先がなければ `git clone` して版を合わせ、あれば版の一致を確かめる。
/// 未確認項目の取得はしない（manifest に載せない）。
fn cmd_testdata_fetch() -> i32 {
    let manifest = workspace_root().join("tools/testdata/manifest.txt");
    let body = match std::fs::read_to_string(&manifest) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("testdata:fetch: manifest.txt が読めない: {e}");
            return 1;
        }
    };
    let mut failed = false;
    for (lineno, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (id, url, rev, dest) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), Some(d)) if parts.next().is_none() => (a, b, c, d),
            _ => {
                eprintln!(
                    "testdata:fetch: {}行目: 形式が違う（ID URL 版 配置先の4項目）",
                    lineno + 1
                );
                failed = true;
                continue;
            }
        };
        if id.is_empty() || url.is_empty() || rev.is_empty() || dest.is_empty() {
            eprintln!("testdata:fetch: {}行目: 空の項目がある", lineno + 1);
            failed = true;
            continue;
        }
        if dest.split('/').any(|c| c == "..") {
            eprintln!(
                "testdata:fetch: {}行目: 配置先に `..` は使えない",
                lineno + 1
            );
            failed = true;
            continue;
        }
        let dir = workspace_root().join(dest);
        if !dir.join(".git").exists() {
            println!("testdata:fetch: {id} を取得する ({url} {rev})");
            if let Err(e) = fetch_clone(url, rev, &dir) {
                eprintln!("testdata:fetch: {id}: {e}");
                // 中途半端な複製を残さない。次回は最初からやり直す。
                let _ = std::fs::remove_dir_all(&dir);
                failed = true;
            }
            continue;
        }
        match git_head(&dir) {
            Ok(h) if h.starts_with(rev) || rev.starts_with(&h) => {
                println!("testdata:fetch: {id} は版が一致する ({h})");
            }
            Ok(h) => {
                eprintln!(
                    "testdata:fetch: {id}: 版が違う（取得定義 {rev}、現物 {h}）。手で合わせること"
                );
                failed = true;
            }
            Err(e) => {
                eprintln!("testdata:fetch: {id}: 版の確認に失敗: {e}");
                failed = true;
            }
        }
    }
    i32::from(failed)
}

/// 空の場所に複製し、指定の版に合わせる。
fn fetch_clone(url: &str, rev: &str, dir: &std::path::Path) -> Result<(), String> {
    let dir_s = dir.to_string_lossy().to_string();
    let run_in = |dir_arg: &str, args: &[&str]| -> Result<String, String> {
        let out = std::process::Command::new("git")
            .args(["-C", dir_arg])
            .args(args)
            .output()
            .map_err(|e| format!("git の起動に失敗: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git -C {dir_arg} {} が失敗: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("作成に失敗: {e}"))?;
    }
    let run = |args: &[&str]| -> Result<String, String> {
        let out = std::process::Command::new("git")
            .args(args)
            .output()
            .map_err(|e| format!("git の起動に失敗: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {} が失敗: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    run(&["clone", url, &dir_s])?;
    run_in(&dir_s, &["checkout", rev]).map(|_| ())
}

/// 配置先の HEAD を読む。
fn git_head(dir: &std::path::Path) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .args(["-C"])
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("git の起動に失敗: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "rev-parse が失敗: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `.git/hooks/pre-commit` に `task check` を実行するフックを入れる。
fn cmd_hooks_install() -> i32 {
    let hook = workspace_root().join(".git/hooks/pre-commit");
    let body = "#!/bin/sh\n# polyisa: generated by `devtool hooks:install`. Do not use --no-verify.\nset -eu\nif command -v task >/dev/null 2>&1; then\n  task check\nelse\n  go-task check\nfi\n";
    match std::fs::write(&hook, body) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mut p = std::fs::metadata(&hook)
                    .expect("hook metadata")
                    .permissions();
                p.set_mode(0o755);
                std::fs::set_permissions(&hook, p).expect("hook chmod");
            }
            println!("hooks:install: wrote {}", hook.display());
            0
        }
        Err(e) => {
            eprintln!("hooks:install: {e}");
            1
        }
    }
}

/// Cargo.lock にワークスペース外のパッケージがないことを確かめる。
/// Cargo.lock がまだない（依存なしの）状態は成功とする。
fn check_no_external_crates() -> Result<(), String> {
    let root = workspace_root();
    let lock = root.join("Cargo.lock");
    if !lock.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(lock).map_err(|e| e.to_string())?;
    let workspace = workspace_package_names().map_err(|e| e.to_string())?;
    let mut external = Vec::new();
    for block in text.split("[[package]]").skip(1) {
        let Some(name) = block.lines().find_map(|l| l.strip_prefix("name = ")) else {
            continue;
        };
        let name = name.trim().trim_matches('"');
        if !workspace.iter().any(|w| w == name) {
            external.push(name.to_string());
        }
    }
    if external.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "external packages in Cargo.lock: {}",
            external.join(", ")
        ))
    }
}

/// クレート間の依存規則を検査する。許可表は `docs/design/workspace.md` の「依存規則」による。
fn check_dep_rules() -> Result<(), String> {
    let violations = dep_violations(&workspace_root());
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

/// ホスト依存の分離を検査する。`crates/` では `host` と `jit` だけが
/// `cfg(target_*)` と `std::os::` の OS 固有モジュールを使える。
fn check_cfg_rules() -> Result<(), String> {
    let violations = cfg_violations(&workspace_root());
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

/// 台帳の表が読め、ID が `^(SPEC|SRC|TEST|BIN|MEAS|TOOL)-` に従うことを確かめる。
/// 内容の確認（利用条件の妥当性）は所有者が行い、ここでは書式だけを見る。
fn check_refs_register() -> Result<usize, String> {
    let path = workspace_root().join("docs/references.md");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let table = parse_register(&text);
    if table.is_empty() {
        return Err("no register IDs found".to_string());
    }
    Ok(table.len())
}

/// `refs:check` の本体。文書の「機械的な検査」の 1〜4 を行う。5 は `check` で行う。
fn check_refs_full() -> Result<(), String> {
    let root = workspace_root();
    let text =
        std::fs::read_to_string(root.join("docs/references.md")).map_err(|e| e.to_string())?;
    let table = parse_register(&text);
    if table.is_empty() {
        return Err("no register IDs found".to_string());
    }
    let mut violations = Vec::new();

    // 1・2：固定書式の注記の走査。`// Ref: ID`（Rust）、`reference ID;` と `ref ID`（ISADL）。
    for hit in scan_notations(&root) {
        match table.get(&hit.id) {
            None => violations.push(format!("{}:{}: unknown ID {}", hit.file, hit.line, hit.id)),
            Some(entry) => {
                if !entry.confirmed {
                    violations.push(format!(
                        "{}:{}: {} is unconfirmed",
                        hit.file, hit.line, hit.id
                    ));
                } else if !entry.uses.iter().any(|u| u == &hit.need) {
                    violations.push(format!(
                        "{}:{}: {} lacks {:?}",
                        hit.file, hit.line, hit.id, hit.need
                    ));
                }
            }
        }
    }

    // 取得定義の突合せ。`T` が要る。
    let manifest = root.join("tools/testdata/manifest.txt");
    if manifest.exists() {
        let text = std::fs::read_to_string(&manifest).map_err(|e| e.to_string())?;
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let id = line.split_whitespace().next().unwrap_or("");
            match table.get(id) {
                None => violations.push(format!("manifest.txt:{}: unknown ID {id}", i + 1)),
                Some(entry) => {
                    if !entry.confirmed {
                        violations.push(format!("manifest.txt:{}: {id} is unconfirmed", i + 1));
                    } else if !entry.uses.iter().any(|u| u == "T") {
                        violations.push(format!("manifest.txt:{}: {id} lacks 'T'", i + 1));
                    }
                }
            }
        }
    }

    // 3：`.testdata/` の除外。`.gitignore` と `git ls-files` の両方を見る。
    if let Err(e) = check_testdata_untracked(&root) {
        violations.push(e);
    }

    // 4：著作権表示と SPDX 識別子の走査。台帳は対象外。
    violations.extend(scan_notices(&root));

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations.join("; "))
    }
}

/// 台帳の項目。用途は `R,F,T,X` の列、確認は日付の有無だけを見る。
struct RegisterEntry {
    uses: Vec<String>,
    confirmed: bool,
}

/// 台帳の表を読む。`用途` と `確認` の列だけを使う。
fn parse_register(text: &str) -> std::collections::BTreeMap<String, RegisterEntry> {
    let mut table = std::collections::BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if !line.starts_with("| ") {
            continue;
        }
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        // `| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |` の 9 列。
        if cols.len() < 10 {
            continue;
        }
        let (id, uses, confirmed_cell) = (cols[1], cols[7], cols[8]);
        if !is_register_id(id) {
            continue;
        }
        let uses = uses
            .split(',')
            .map(str::trim)
            .filter(|u| !u.is_empty() && *u != "—")
            .map(str::to_string)
            .collect();
        table.insert(
            id.to_string(),
            RegisterEntry {
                uses,
                confirmed: is_confirmed(confirmed_cell),
            },
        );
    }
    table
}

/// 確認の欄が `YYYY-MM-DD 確認者名` の形かどうか。
fn is_confirmed(cell: &str) -> bool {
    let b = cell.as_bytes();
    cell.len() >= 10
        && b[0..4].iter().all(|c| c.is_ascii_digit())
        && b[4] == b'-'
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[7] == b'-'
        && b[8..10].iter().all(|c| c.is_ascii_digit())
}

/// 固定書式の注記の1件。`need` は参照の場所に応じた用途。
struct NotationHit {
    file: String,
    line: usize,
    id: String,
    need: String,
}

/// 成果物の注記を集める。対象は `crates/`、`guests/`、`tools/`。
/// Rust では `// Ref: ID`、ISADL では `reference ID;` と `ref ID` を拾う。
fn scan_notations(root: &std::path::Path) -> Vec<NotationHit> {
    let mut out = Vec::new();
    for base in ["crates", "guests", "tools"] {
        let mut files = Vec::new();
        collect_files(&root.join(base), &mut files);
        files.sort();
        for f in files {
            let ext = f.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext != "rs" && ext != "isadl" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
            for (i, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                // Rust の注記はコメントで書くので、元の行から探す。
                for id in find_ids(line, "// Ref:") {
                    out.push(NotationHit {
                        file: rel.clone(),
                        line: i + 1,
                        id,
                        need: "F".to_string(),
                    });
                }
                if ext == "isadl" {
                    for id in find_ids(code, "reference") {
                        out.push(NotationHit {
                            file: rel.clone(),
                            line: i + 1,
                            id,
                            need: "F".to_string(),
                        });
                    }
                    for id in find_ids(code, "ref") {
                        out.push(NotationHit {
                            file: rel.clone(),
                            line: i + 1,
                            id,
                            need: "F".to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

/// 行から接頭辞の直後の ID を拾う。
fn find_ids(line: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(pos) = rest.find(marker) {
        rest = &rest[pos + marker.len()..];
        let token: String = rest
            .chars()
            .skip_while(|c| !c.is_ascii_alphanumeric())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if is_register_id(&token) {
            out.push(token);
        }
    }
    out
}

fn collect_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            // 生成物と取得物は走査しない。
            if let Some(name) = p.file_name().and_then(|s| s.to_str())
                && (name == "target" || name == ".testdata")
            {
                continue;
            }
            collect_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// `.testdata/` が追跡対象外かどうか。`.gitignore` と `git ls-files` を見る。
fn check_testdata_untracked(root: &std::path::Path) -> Result<(), String> {
    let ignore = std::fs::read_to_string(root.join(".gitignore")).unwrap_or_default();
    if !ignore.lines().any(|l| l.trim() == ".testdata/") {
        return Err(".testdata/ is not in .gitignore".to_string());
    }
    let out = std::process::Command::new("git")
        .args(["ls-files", ".testdata/"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err("git ls-files failed".to_string());
    }
    let tracked = String::from_utf8_lossy(&out.stdout);
    if tracked.lines().next().is_some() {
        return Err(".testdata/ is tracked by git".to_string());
    }
    Ok(())
}

/// 1行が第三者の著作権表示・ライセンス識別子に当たるかどうか。
/// 自前のデュアルライセンス表示と自前の著作権行は許可する。
fn notice_violation(line: &str) -> bool {
    // 検査自身のソースに文字列が現れないよう、動的に組み立てる。
    let copy: String = ["Copy", "right"].concat();
    let spdx: String = ["SPDX-", "License-Identifier"].concat();
    // 自前の表示は許可する。第三者の同表記ファイルの素通りは受容する（同条件のため実害なし）。
    let own_copy: String = ["polyisa contri", "butors"].concat();
    if line.contains(&spdx) {
        // 自前のデュアルライセンスの表示は許可する。
        return !line.contains("MIT OR Apache-2.0");
    }
    if line.contains(&copy) || line.contains('\u{a9}') {
        return !line.contains(&own_copy);
    }
    false
}

/// 著作権表示と SPDX 識別子の走査。`docs/references.md` は対象外。
fn scan_notices(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut files = Vec::new();
    collect_files(root, &mut files);
    files.sort();
    for f in files {
        let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
        if rel == "docs/references.md" {
            continue;
        }
        if rel == "LICENSE-MIT" || rel == "LICENSE-APACHE" {
            continue;
        }
        if rel.starts_with(".git/") || rel.contains("/target/") || rel.starts_with(".testdata/") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if notice_violation(line) {
                out.push(format!("{}:{}: third-party notice?", rel, i + 1));
            }
        }
    }
    out
}

fn is_register_id(id: &str) -> bool {
    const PREFIXES: [&str; 6] = ["SPEC-", "SRC-", "TEST-", "BIN-", "MEAS-", "TOOL-"];
    PREFIXES.iter().any(|p| id.starts_with(p))
}

/// 依存してよい相手の表。`docs/design/workspace.md` の「依存規則」による。
/// 殻の段階では `cli` を最小の依存に絞っている（全依存は後の段階で戻す）。
fn allowed_deps(pkg: &str) -> Option<&'static [&'static str]> {
    Some(match pkg {
        "polyisa-bits" => &[],
        "polyisa-softfloat" => &["polyisa-bits"],
        "polyisa-decimal" => &["polyisa-bits"],
        "polyisa-diag" => &[],
        "polyisa-isadl" => &[],
        "polyisa-isagen" => &["polyisa-isadl"],
        "polyisa-mem" => &["polyisa-bits"],
        "polyisa-sem" => &["polyisa-bits", "polyisa-mem"],
        "polyisa-guest" => &["polyisa-bits", "polyisa-sem", "polyisa-timing"],
        "polyisa-timing" => &["polyisa-bits"],
        "polyisa-engine" => &[
            "polyisa-bits",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
            "polyisa-softfloat",
        ],
        "polyisa-ir" => &["polyisa-sem", "polyisa-guest", "polyisa-mem"],
        "polyisa-jit" => &["polyisa-ir", "polyisa-host"],
        "polyisa-loader" => &["polyisa-bits", "polyisa-mem"],
        "polyisa-kernel" => &[
            "polyisa-mem",
            "polyisa-engine",
            "polyisa-guest",
            "polyisa-timing",
            "polyisa-host",
        ],
        "polyisa-os-linux" => &[
            "polyisa-kernel",
            "polyisa-loader",
            "polyisa-engine",
            "polyisa-guest",
        ],
        "polyisa-os-wasi" => &["polyisa-kernel", "polyisa-engine", "polyisa-guest"],
        "polyisa-host" => &[],
        "polyisa-trace" => &["polyisa-engine", "polyisa-guest"],
        "polyisa-gdbstub" => &["polyisa-engine", "polyisa-guest"],
        "polyisa-cli" => &[
            "polyisa-engine",
            "polyisa-guest",
            "polyisa-guest-riscv",
            "polyisa-guest-x86",
            "polyisa-host",
            "polyisa-kernel",
            "polyisa-loader",
            "polyisa-mem",
            "polyisa-os-linux",
            "polyisa-sem",
            "polyisa-trace",
        ],
        "polyisa-testkit" => &["polyisa-bits"],
        "polyisa-devtool" => &[
            "polyisa-testkit",
            "polyisa-isadl",
            "polyisa-isagen",
            "polyisa-trace",
        ],
        "polyisa-guest-riscv" => &[
            "polyisa-bits",
            "polyisa-softfloat",
            "polyisa-decimal",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
        ],
        "polyisa-guest-sparc" => &[
            "polyisa-bits",
            "polyisa-softfloat",
            "polyisa-decimal",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
        ],
        "polyisa-guest-mips" => &[
            "polyisa-bits",
            "polyisa-softfloat",
            "polyisa-decimal",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
        ],
        "polyisa-guest-x86" => &[
            "polyisa-bits",
            "polyisa-softfloat",
            "polyisa-decimal",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
        ],
        "polyisa-guest-wasm" => &[
            "polyisa-bits",
            "polyisa-softfloat",
            "polyisa-decimal",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
        ],
        "polyisa-guest-hexagon" => &[
            "polyisa-bits",
            "polyisa-softfloat",
            "polyisa-decimal",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
        ],
        "polyisa-guest-ia64" => &[
            "polyisa-bits",
            "polyisa-softfloat",
            "polyisa-decimal",
            "polyisa-mem",
            "polyisa-sem",
            "polyisa-guest",
            "polyisa-timing",
        ],
        _ => return None,
    })
}

/// 各メンバーの `Cargo.toml` を読み、許可表にない依存を列挙する。
fn dep_violations(root: &std::path::Path) -> Vec<String> {
    let members = workspace_members(root);
    let mut out = Vec::new();
    for (dir, pkg) in &members {
        let text = match std::fs::read_to_string(root.join(format!("{dir}/Cargo.toml"))) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let Some(allowed) = allowed_deps(pkg) else {
            continue;
        };
        for dep in workspace_dep_names(&text) {
            if !allowed.contains(&dep.as_str()) {
                out.push(format!("{pkg} -> {dep}"));
            }
        }
    }
    out
}

/// `crates/` の Rust ソースからホスト分離の違反を集める。
/// `host` と `jit` 以外での `cfg(target_*)` と `std::os::` の使用を違反とする。
fn cfg_violations(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let crates = root.join("crates");
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&crates) {
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                dirs.push(e.path());
            }
        }
    }
    dirs.sort();
    for dir in dirs {
        let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // `host` と JIT のホストバックエンド（`jit`）は例外。
        if name == "host" || name == "jit" {
            continue;
        }
        let mut files = Vec::new();
        collect_rs(&dir, &mut files);
        files.sort();
        for f in files {
            let text = match std::fs::read_to_string(&f) {
                Ok(t) => t,
                Err(_) => continue,
            };
            for (i, line) in text.lines().enumerate() {
                // コメント行は検査の対象外にする。
                let code = line.split("//").next().unwrap_or("");
                if code.contains("cfg(target_os")
                    || code.contains("cfg(target_arch")
                    || code.contains("cfg(target_endian")
                    || code.contains("cfg(target_pointer_width")
                    || code.contains("std::os::")
                {
                    let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
                    out.push(format!("{}:{}: {}", rel, i + 1, code.trim()));
                }
            }
        }
    }
    out
}

fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// ルートの `Cargo.toml` から `(dir, package)` を集める。
fn workspace_members(root: &std::path::Path) -> Vec<(String, String)> {
    let Ok(root_text) = std::fs::read_to_string(root.join("Cargo.toml")) else {
        return Vec::new();
    };
    let mut members = Vec::new();
    let mut in_members = false;
    for line in root_text.lines() {
        let t = line.trim();
        if t.starts_with("members") {
            in_members = true;
            for part in t.split('"').skip(1).step_by(2) {
                members.push(part.to_string());
            }
            if t.contains(']') {
                in_members = false;
            }
            continue;
        }
        if in_members {
            for part in t.split('"').skip(1).step_by(2) {
                members.push(part.to_string());
            }
            if t.contains(']') {
                in_members = false;
            }
        }
    }
    let mut out = Vec::new();
    for m in members {
        let Ok(text) = std::fs::read_to_string(root.join(format!("{m}/Cargo.toml"))) else {
            continue;
        };
        if let Some(pkg) = package_name_of(&text) {
            out.push((m, pkg));
        }
    }
    out
}

/// `[package] name = "..."` を読む。
fn package_name_of(text: &str) -> Option<String> {
    let mut in_package = false;
    for line in text.lines() {
        let t = line.trim();
        if t == "[package]" {
            in_package = true;
            continue;
        }
        if t.starts_with('[') {
            in_package = false;
            continue;
        }
        if in_package
            && let Some(v) = t.strip_prefix("name")
            && let Some(q1) = v.find('"')
            && let Some(q2) = v[q1 + 1..].find('"')
        {
            return Some(v[q1 + 1..q1 + 1 + q2].to_string());
        }
    }
    None
}

/// `[dependencies]` の `polyisa-*` を集める。
fn workspace_dep_names(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_deps = t == "[dependencies]";
            continue;
        }
        if !in_deps {
            continue;
        }
        let t = t.split('#').next().unwrap_or("").trim();
        if let Some(name) = t.split(['=', ' ']).next()
            && name.starts_with("polyisa-")
        {
            out.push(name.to_string());
        }
    }
    out
}

/// ワークスペースのメンバーのパッケージ名を `cargo metadata` なしで集める。
/// devtool 自体が外部クレート禁止のため、`cargo metadata` の JSON を読まず各 Cargo.toml を直接読む。
fn workspace_package_names() -> Result<Vec<String>, String> {
    let root = workspace_root();
    let root_text = std::fs::read_to_string(root.join("Cargo.toml")).map_err(|e| e.to_string())?;
    let mut members = Vec::new();
    let mut in_members = false;
    for line in root_text.lines() {
        let t = line.trim();
        if t.starts_with("members") {
            in_members = true;
            // `members = ["a", "b"]` の一行形に対応する。
            for part in t.split('"').skip(1).step_by(2) {
                members.push(part.to_string());
            }
            if t.contains(']') {
                in_members = false;
            }
            continue;
        }
        if in_members {
            for part in t.split('"').skip(1).step_by(2) {
                members.push(part.to_string());
            }
            if t.contains(']') {
                in_members = false;
            }
        }
    }
    let mut names = Vec::new();
    for m in members {
        let path = root.join(format!("{m}/Cargo.toml"));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut in_package = false;
        for line in text.lines() {
            let t = line.trim();
            if t == "[package]" {
                in_package = true;
                continue;
            }
            if t.starts_with('[') {
                in_package = false;
                continue;
            }
            if in_package && let Some(v) = t.strip_prefix("name") {
                // `name = "foo"` の形だけを読む。
                if let Some(q1) = v.find('"')
                    && let Some(q2) = v[q1 + 1..].find('"')
                {
                    names.push(v[q1 + 1..q1 + 1 + q2].to_string());
                    break;
                }
            }
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_id_prefixes() {
        assert!(is_register_id("SPEC-RISCV-UNPRIV"));
        assert!(is_register_id("TOOL-RUST"));
        assert!(!is_register_id("FOO-BAR"));
        assert!(!is_register_id("| ID |"));
    }

    #[test]
    fn refs_register_is_readable() {
        let n = check_refs_register().expect("references.md should parse");
        assert!(n > 60, "expected many IDs, got {n}");
    }

    #[test]
    fn refs_full_passes_on_current_tree() {
        // 成果物に固定書式の注記はなく、`.testdata` も追跡外のため通る。
        assert!(check_refs_full().is_ok());
    }

    #[test]
    fn confirmed_format() {
        assert!(is_confirmed("2026-11-08 owner"));
        assert!(!is_confirmed("未確認"));
        assert!(!is_confirmed("—"));
        assert!(!is_confirmed("2026/11/08 owner"));
    }

    #[test]
    fn register_uses_parsed() {
        let text = "| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |\n\
                    |---|---|---|---|---|---|---|---|---|\n\
                    | SPEC-FOO | x | y | — | z | w | R,F | 2026-11-08 owner | |\n\
                    | TOOL-BAR | x | y | — | z | w | — | 未確認 | |";
        let t = parse_register(text);
        assert_eq!(t["SPEC-FOO"].uses, vec!["R".to_string(), "F".to_string()]);
        assert!(t["SPEC-FOO"].confirmed);
        assert!(t["TOOL-BAR"].uses.is_empty());
        assert!(!t["TOOL-BAR"].confirmed);
    }

    #[test]
    fn notation_ids_found() {
        // 検査対象の書式を直接書くと走査に拾われるため、動的に組み立てる。
        let marker: String = ["/", "/ Ref:"].concat();
        let line = format!("{marker} SPEC-RISCV-UNPRIV §2.4");
        assert_eq!(
            find_ids(&line, &marker),
            vec!["SPEC-RISCV-UNPRIV".to_string()]
        );
        assert!(find_ids("// just a comment", &marker).is_empty());
    }

    #[test]
    fn notice_allowlist() {
        // 走査対象の文字列を直接書くと走査に拾われるため、動的に組み立てる。
        let spdx: String = ["SPDX-", "License-Identifier"].concat();
        let copy: String = ["Copy", "right"].concat();
        let own_copy: String = ["polyisa contri", "butors"].concat();
        assert!(!notice_violation(&format!("// {spdx}: MIT OR Apache-2.0")));
        assert!(notice_violation(&format!("// {spdx}: GPL-3.0-only")));
        assert!(!notice_violation(&format!("// {copy} (c) {own_copy}")));
        assert!(notice_violation(&format!("// {copy} (c) someone-else")));
        assert!(notice_violation(&format!("{} 2026 someone", '\u{a9}')));
    }

    #[test]
    fn dep_rules_hold() {
        assert!(check_dep_rules().is_ok());
    }

    #[test]
    fn cfg_rules_hold() {
        assert!(check_cfg_rules().is_ok());
    }

    #[test]
    fn dep_names_parsed() {
        let manifest = "[dependencies]\npolyisa-bits = { path = \"../bits\" }\nserde = \"1\"\n";
        assert_eq!(
            workspace_dep_names(manifest),
            vec!["polyisa-bits".to_string()]
        );
        assert_eq!(allowed_deps("polyisa-mem"), Some(&["polyisa-bits"][..]));
        assert_eq!(allowed_deps("no-such-crate"), None);
    }
}
