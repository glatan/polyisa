// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! リポジトリの追跡対象ファイルから `docs/status.md` を生成し、鮮度を検査する。
//! `--dump` 指定時は ISA ごとの命令・モデル詳細を `target/status/` へ書き出す。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use polyisa_isadl::model::MapItem;
use polyisa_isadl::{Model, Pred};

use crate::{gaps, specs};

const NOTICE: &str = "このファイルは `task status` が自動生成する。手で編集しない。";

pub(crate) fn write_status(root: &Path) -> Result<PathBuf, String> {
    let body = generate_status_md(root)?;
    let path = root.join("docs/status.md");
    std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

pub(crate) fn check_status_fresh(root: &Path) -> Result<(), String> {
    let expected = generate_status_md(root)?;
    let path = root.join("docs/status.md");
    let actual = std::fs::read_to_string(&path)
        .map_err(|e| format!("{}: {e}（task status で生成する）", path.display()))?;
    if actual == expected {
        Ok(())
    } else {
        Err("docs/status.md が最新ではない（task status で再生成する）".to_string())
    }
}

pub(crate) fn write_dump(root: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = root.join("target/status");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut written = Vec::new();
    let mut specs_sorted: Vec<&specs::IsaSpec> = specs::isa_specs().iter().collect();
    specs_sorted.sort_by_key(|s| s.isa);
    for spec in specs_sorted {
        let model = (spec.build)();
        let path = dir.join(format!("isa-{}.md", spec.isa));
        let body = render_isa_dump(spec.isa, spec.rel_paths, &model);
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

pub(crate) fn generate_status_md(root: &Path) -> Result<String, String> {
    let cli_main = read_to_string(&root.join("crates/cli/src/main.rs"))?;
    let taskfile = read_to_string(&root.join("Taskfile.yml"))?;
    let issues_text = read_to_string(&root.join("docs/known-issues.md"))?;
    let issues = gaps::parse_issue_table(&issues_text);
    let cli_tests = list_test_stems(&root.join("crates/cli/tests"));
    let os_linux_tests = list_test_stems(&root.join("crates/os-linux/tests"));

    let mut specs_sorted: Vec<&specs::IsaSpec> = specs::isa_specs().iter().collect();
    specs_sorted.sort_by_key(|s| s.isa);

    let mut isa_rows = Vec::new();
    for spec in &specs_sorted {
        let isa = spec.isa;
        let model = (spec.build)();
        let models_count = model.models.len().to_string();
        let features_count = model.features.len().to_string();
        let cli_info = detect_cli_support(isa, &cli_main);
        let os_list = detect_os_personalities(root, isa);
        let jit = if has_jit_runner(root, isa) {
            "対応"
        } else {
            "—"
        };
        let timing = detect_timing(root, isa, &model);
        let gdb = if root.join(format!("crates/cli/src/gdb_{isa}.rs")).is_file() {
            "対応"
        } else {
            "—"
        };
        let layers = detect_test_layers(root, isa, &cli_tests, &os_linux_tests);
        let detail = format!("[{isa}.md](guests/{isa}.md)");
        isa_rows.push(vec![
            isa.to_string(),
            models_count,
            features_count,
            cli_info,
            os_list,
            jit.to_string(),
            timing,
            gdb.to_string(),
            layers,
            detail,
        ]);
    }

    let linux_rows = collect_linux_abi_rows(root, &cli_tests, &os_linux_tests);
    let other_os_rows = collect_other_os_rows(root, &cli_tests);
    let target_rows = collect_host_target_rows(root, &taskfile, &cli_tests);

    let mut s = String::new();
    s.push_str("# 実装状況\n\n");
    s.push_str(NOTICE);
    s.push_str("\n\n");
    s.push_str(
        "各表は ISADL の仕様定義（`guests/*/spec/`）、OS パーソナリティの実装（`crates/os-*`）、CLI ランナ（`crates/cli`）、テストバイナリ（`crates/*/tests/`・`guests/*/tests/`）、`Taskfile.yml`、`docs/known-issues.md` から機械的に集計した現在地を示す。命令単位の詳細一覧と機能旗ごとのカバレッジ（`when` 条件での使用数とモデル参照数）は `task status:dump` で、命令×テスト層の静的証拠は `cargo run -p polyisa-devtool -- coverage` で `target/status/` に書き出せる。\n\n",
    );

    s.push_str("## ISA 対応マトリクス\n\n");
    s.push_str(&md_table(
        &[
            "ISA",
            "モデル数",
            "機能数",
            "CLI 実行",
            "対応 OS",
            "JIT",
            "タイミング",
            "GDB",
            "テスト層",
            "詳細",
        ],
        &isa_rows,
    ));

    s.push_str("\n## OS パーソナリティ（Linux）\n\n");
    s.push_str(&md_table(
        &[
            "ISA / ABI",
            "ソケット共通層",
            "待ち合わせ共通層",
            "ABI 照合テスト",
            "プログラムテスト",
        ],
        &linux_rows,
    ));

    s.push_str("\n## その他の OS パーソナリティ\n\n");
    s.push_str(&md_table(
        &["クレート", "対象 OS", "対象 ISA", "プログラムテスト"],
        &other_os_rows,
    ));

    s.push_str("\n## ホストターゲット\n\n");
    s.push_str(&md_table(
        &["ターゲット", "検査経路", "JIT", "ホストテスト"],
        &target_rows,
    ));

    s.push_str("\n## 横断課題の要約\n\n");
    let mut unstarted = 0usize;
    let mut provisional = 0usize;
    for r in &issues {
        match r.kind.as_str() {
            "未着手" => unstarted += 1,
            "暫定" => provisional += 1,
            _ => {}
        }
    }
    s.push_str(&format!(
        "詳細は [横断的な未実装・暫定課題](known-issues.md) にある。未着手は {unstarted} 件、暫定は {provisional} 件である。\n\n"
    ));
    let issue_rows: Vec<Vec<String>> = issues
        .iter()
        .map(|r| vec![r.id.clone(), r.kind.clone(), r.related.clone()])
        .collect();
    s.push_str(&md_table(&["ID", "区分", "関連文書"], &issue_rows));

    Ok(s)
}

fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn list_test_stems(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut stems = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            stems.push(stem.to_string());
        }
    }
    stems.sort();
    stems
}

fn detect_cli_support(isa: &str, cli_main: &str) -> String {
    let format = match isa {
        "pdp11" | "vax" => "a.out",
        "wasm" => "Wasm",
        _ => "ELF",
    };
    let in_cpus = cli_main.contains(&format!("polyisa_guest_{isa}::MODELS"));
    if in_cpus {
        format.to_string()
    } else {
        format!("{format}（`cpus`未掲載）")
    }
}

fn detect_os_personalities(root: &Path, isa: &str) -> String {
    let mut list = Vec::new();
    let linux_dir = if isa == "riscv" { "rv64" } else { isa };
    if root
        .join(format!("crates/os-linux/src/{linux_dir}/sys.rs"))
        .is_file()
    {
        list.push("Linux");
    }
    if isa == "pdp11" && root.join("crates/os-v7/src/pdp11/sys.rs").is_file() {
        list.push("Unix V7");
    }
    if isa == "vax" && root.join("crates/os-bsd/src/vax/sys.rs").is_file() {
        list.push("4.3BSD");
    }
    if isa == "wasm" && root.join("crates/os-wasi/src/host.rs").is_file() {
        list.push("WASI");
    }
    if matches!(isa, "aarch64" | "arm" | "riscv")
        && root.join("crates/os-semihost/src/lib.rs").is_file()
    {
        list.push("Semihosting");
    }
    if list.is_empty() {
        "—".to_string()
    } else {
        list.join("・")
    }
}

fn has_jit_runner(root: &Path, isa: &str) -> bool {
    let path = root.join(format!("crates/cli/src/run_{isa}.rs"));
    std::fs::read_to_string(path)
        .map(|s| s.contains("polyisa_jit::Jit"))
        .unwrap_or(false)
}

fn detect_timing(root: &Path, isa: &str, model: &Model) -> String {
    let mut fidelities = BTreeSet::new();
    for m in &model.models {
        if let Some(t) = &m.timing {
            fidelities.insert(t.fidelity.clone());
        }
    }
    let has_timing_mod = root.join(format!("guests/{isa}/src/timing.rs")).is_file();
    let has_timing_tests = list_test_stems(&root.join(format!("guests/{isa}/tests")))
        .iter()
        .any(|t| t.starts_with("heavy_timing_"));
    if !fidelities.is_empty() {
        let joined: Vec<String> = fidelities.into_iter().collect();
        joined.join("・")
    } else if has_timing_tests {
        "専用モデル（検証あり）".to_string()
    } else if has_timing_mod {
        "専用モデル（未較正）".to_string()
    } else {
        "—".to_string()
    }
}

fn detect_test_layers(
    root: &Path,
    isa: &str,
    cli_tests: &[String],
    os_linux_tests: &[String],
) -> String {
    let guest_tests = list_test_stems(&root.join(format!("guests/{isa}/tests")));
    let mut layers = BTreeSet::new();

    for t in &guest_tests {
        if t.starts_with("bare_")
            || t == "sem"
            || t == "sem_unit"
            || t == "decode"
            || t == "model_diff"
            || t.starts_with("sem_")
        {
            layers.insert("bare");
        } else if t.starts_with("heavy_conformance_") {
            layers.insert("conformance");
        } else if t.starts_with("heavy_oracle_") {
            layers.insert("oracle");
        } else if t.starts_with("heavy_diff_") {
            layers.insert("diff");
        } else if t.starts_with("heavy_timing_") {
            layers.insert("timing");
        } else if t.starts_with("heavy_program_") {
            layers.insert("program");
        }
    }

    for t in cli_tests {
        if cli_test_matches_isa(t, isa) {
            if t.starts_with("heavy_program_") {
                layers.insert("program");
            } else if t.starts_with("heavy_abi_") {
                layers.insert("abi");
            } else if t.starts_with("heavy_diff_") {
                layers.insert("diff");
            }
        }
    }

    for t in os_linux_tests {
        if os_linux_test_matches_isa(t, isa) {
            layers.insert("abi");
        }
    }

    if has_jit_runner(root, isa) && cli_tests.iter().any(|t| t == "heavy_jit_diff") {
        layers.insert("jit");
    }

    let order = [
        "bare",
        "conformance",
        "oracle",
        "abi",
        "program",
        "diff",
        "jit",
        "timing",
    ];
    let out: Vec<&str> = order.into_iter().filter(|l| layers.contains(l)).collect();
    if out.is_empty() {
        "—".to_string()
    } else {
        out.join("・")
    }
}

fn cli_test_matches_isa(test: &str, isa: &str) -> bool {
    match isa {
        "x86" => matches!(
            test,
            "heavy_program_busybox"
                | "heavy_program_busybox_i386"
                | "heavy_program_i386_applet_probe"
                | "heavy_program_x32"
                | "heavy_program_x86ext"
                | "heavy_program_net"
        ),
        "riscv" => matches!(test, "heavy_program_gdbstub" | "heavy_program_semihosting"),
        "aarch64" => matches!(
            test,
            "heavy_program_aarch64" | "heavy_program_semihosting" | "heavy_program_net"
        ),
        "arm" => matches!(test, "heavy_program_arm" | "heavy_program_semihosting"),
        "pdp11" => test == "heavy_program_unixv7",
        "vax" => test == "heavy_program_bsdvax",
        "wasm" => matches!(test, "heavy_program_wasi" | "heavy_diff_wasmtime"),
        _ => test == format!("heavy_program_{isa}") || test == format!("heavy_abi_{isa}"),
    }
}

fn os_linux_test_matches_isa(test: &str, isa: &str) -> bool {
    match isa {
        "x86" | "riscv" | "mips" => test == "heavy_abi_uapi",
        _ => test == format!("heavy_abi_{isa}"),
    }
}

fn collect_linux_abi_rows(
    root: &Path,
    cli_tests: &[String],
    os_linux_tests: &[String],
) -> Vec<Vec<String>> {
    const LINUX_ISAS: &[(&str, &str)] = &[
        ("aarch64", "aarch64 (LP64 LE/BE)"),
        ("alpha", "alpha"),
        ("arm", "arm (EABI)"),
        ("hexagon", "hexagon"),
        ("ia64", "ia64"),
        ("loongarch", "loongarch (LA64)"),
        ("m68k", "m68k"),
        ("mips", "mips (o32 / n32 / n64)"),
        ("openrisc", "openrisc (or1k)"),
        ("parisc", "parisc (hppa32)"),
        ("power", "power (ppc64le)"),
        ("rv64", "riscv (RV64)"),
        ("s390", "s390 (s390x)"),
        ("sparc", "sparc (sparc32 / sparc64)"),
        ("superh", "superh (sh4 LE/BE)"),
        ("x86", "x86 (x86_64 / i386 / x32)"),
    ];
    let mut rows = Vec::new();
    for &(dir, label) in LINUX_ISAS {
        let sys_path = root.join(format!("crates/os-linux/src/{dir}/sys.rs"));
        let src = std::fs::read_to_string(&sys_path).unwrap_or_default();
        let sock = if src.contains("crate::sock") {
            "接続済み"
        } else {
            "—"
        };
        let wait = if src.contains("crate::wait") {
            "接続済み"
        } else {
            "—"
        };
        let isa_key = if dir == "rv64" { "riscv" } else { dir };
        let abi_test = os_linux_tests
            .iter()
            .find(|t| os_linux_test_matches_isa(t, isa_key))
            .or_else(|| {
                cli_tests
                    .iter()
                    .find(|t| *t == &format!("heavy_abi_{isa_key}"))
            })
            .map(|t| format!("`{t}`"))
            .unwrap_or_else(|| "—".to_string());
        let prog_tests = collect_linux_prog_tests(root, isa_key, cli_tests);
        rows.push(vec![
            label.to_string(),
            sock.to_string(),
            wait.to_string(),
            abi_test,
            prog_tests,
        ]);
    }
    rows
}

fn collect_linux_prog_tests(root: &Path, isa: &str, cli_tests: &[String]) -> String {
    let mut found = Vec::new();
    for t in cli_tests {
        if t.starts_with("heavy_program_")
            && cli_test_matches_isa(t, isa)
            && t != "heavy_program_semihosting"
        {
            found.push(format!("`{t}`"));
        }
    }
    for t in list_test_stems(&root.join(format!("guests/{isa}/tests"))) {
        if t.starts_with("heavy_program_") {
            found.push(format!("`{t}`"));
        }
    }
    if found.is_empty() {
        "—".to_string()
    } else {
        found.join("、")
    }
}

fn collect_other_os_rows(root: &Path, cli_tests: &[String]) -> Vec<Vec<String>> {
    let specs: &[(&str, &str, &str, &str)] = &[
        ("os-v7", "Unix V7", "pdp11", "heavy_program_unixv7"),
        ("os-bsd", "4.3BSD-Reno", "vax", "heavy_program_bsdvax"),
        ("os-wasi", "WASI preview1", "wasm", "heavy_program_wasi"),
        (
            "os-semihost",
            "Semihosting 2.0",
            "aarch64・arm・riscv",
            "heavy_program_semihosting",
        ),
    ];
    specs
        .iter()
        .filter(|(krate, _, _, _)| root.join(format!("crates/{krate}/Cargo.toml")).is_file())
        .map(|&(krate, os_name, isa, test)| {
            let test_col = if cli_tests.iter().any(|t| t == test) {
                format!("`{test}`")
            } else {
                "—".to_string()
            };
            vec![
                format!("`{krate}`"),
                os_name.to_string(),
                isa.to_string(),
                test_col,
            ]
        })
        .collect()
}

fn collect_host_target_rows(root: &Path, taskfile: &str, cli_tests: &[String]) -> Vec<Vec<String>> {
    let mut rows = vec![vec![
        "x86_64-unknown-linux-gnu（主ホスト）".to_string(),
        "`task check` / `task test`".to_string(),
        "対応（x86-64 バックエンド）".to_string(),
        "`heavy_jit_diff` ほか全テスト".to_string(),
    ]];
    for line in taskfile.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("- cargo check --workspace --target ") else {
            continue;
        };
        let target = rest.trim();
        let host_test = if target.starts_with("wasm32-wasi")
            && cli_tests.iter().any(|c| c == "heavy_host_wasi")
        {
            "`heavy_host_wasi`".to_string()
        } else {
            "—".to_string()
        };
        let jit = if target == "x86_64-unknown-linux-gnu" {
            "対応"
        } else {
            "インタプリタのみ"
        };
        rows.push(vec![
            format!("`{target}`"),
            "`task check:targets`".to_string(),
            jit.to_string(),
            host_test,
        ]);
    }
    let _ = root;
    rows
}

fn render_isa_dump(isa: &str, rel_paths: &[&str], model: &Model) -> String {
    let mut s = String::new();
    s.push_str(&format!("# 命令・モデル詳細：{isa}\n\n"));
    s.push_str("このファイルは `task status:dump` が生成する。\n\n");
    s.push_str(&format!("生成元：`{}`\n\n", rel_paths.join("`・`")));
    s.push_str("## CPU モデル\n\n");
    let mut cpu = model.models.clone();
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
        &["名前", "親", "追加機能", "除外機能"],
        &cpu_rows,
    ));
    s.push_str("\n## 機能旗のカバレッジ\n\n");
    s.push_str(
        "命令の `when` 条件に現れる回数とモデルからの参照数を機能旗ごとに数えたもの。\
        「ゲート」は条件中で旗を肯定して使う命令記述の件数、「否定」は `!旗` として使う件数である。\
        「モデル参照」はモデルの追加・除外欄に直接書かれた件数で、親からの継承や `implies` による\
        波及は数えない。ゲート・否定がともに 0 の旗は命令の利用可否に効かない\
        （識別情報の導出や意味論の実行時参照で使われる場合はある。Hexagon の `dx_*` や\
        IA-64 の `unit_*` のようなデコード文脈旗は、モデルから参照されないのが正しい形である）。\n\n",
    );
    s.push_str(&md_table(
        &["機能旗", "ゲート", "否定", "モデル参照", "識別ビット"],
        &feature_coverage_rows(model),
    ));
    s.push_str("\n## 命令\n\n");
    let rows = mnemonic_rows(&insn_attrs(model));
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
                MapItem::Map(..) => None,
            })
        }))
        .collect()
}

/// 述語に現れる旗を肯定・否定の別に集める。`Any`/`All` の内側まで
/// 再帰的にたどり、言及があれば極性ごとに一度だけ数える。
fn collect_flag_polarity(
    pred: &Pred,
    polarity: bool,
    pos: &mut BTreeSet<String>,
    neg: &mut BTreeSet<String>,
) {
    match pred {
        Pred::True | Pred::False => {}
        Pred::Flag(name) => {
            if polarity {
                pos.insert(name.clone());
            } else {
                neg.insert(name.clone());
            }
        }
        Pred::Not(inner) => collect_flag_polarity(inner, !polarity, pos, neg),
        Pred::All(ps) | Pred::Any(ps) => {
            for p in ps {
                collect_flag_polarity(p, polarity, pos, neg);
            }
        }
    }
}

/// 機能旗ごとのカバレッジ行（ゲート命令数・否定での言及数・
/// モデル参照数・識別ビット数）を作る。
fn feature_coverage_rows(model: &Model) -> Vec<Vec<String>> {
    let mut pos_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut neg_count: BTreeMap<String, usize> = BTreeMap::new();
    for (_, _, when, _) in insn_attrs(model) {
        let mut pos = BTreeSet::new();
        let mut neg = BTreeSet::new();
        collect_flag_polarity(when, true, &mut pos, &mut neg);
        for f in pos {
            *pos_count.entry(f).or_insert(0) += 1;
        }
        for f in neg {
            *neg_count.entry(f).or_insert(0) += 1;
        }
    }
    let mut model_refs: BTreeMap<&str, usize> = BTreeMap::new();
    for def in &model.models {
        for f in def.add_features.iter().chain(def.remove_features.iter()) {
            *model_refs.entry(f.as_str()).or_insert(0) += 1;
        }
    }
    let mut ident_count: BTreeMap<&str, usize> = BTreeMap::new();
    for bit in &model.ident_bits {
        *ident_count.entry(bit.feature.as_str()).or_insert(0) += 1;
    }
    let or_dash = |n: usize| {
        if n == 0 {
            "—".to_string()
        } else {
            n.to_string()
        }
    };
    model
        .features
        .iter()
        .map(|f| {
            let name = f.name.as_str();
            vec![
                name.to_string(),
                or_dash(pos_count.get(name).copied().unwrap_or(0)),
                or_dash(neg_count.get(name).copied().unwrap_or(0)),
                or_dash(model_refs.get(name).copied().unwrap_or(0)),
                or_dash(ident_count.get(name).copied().unwrap_or(0)),
            ]
        })
        .collect()
}

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
        let a = generate_status_md(&root).expect("first");
        let b = generate_status_md(&root).expect("second");
        assert_eq!(a, b);
    }

    #[test]
    fn committed_status_is_fresh() {
        let root = crate::workspace_root();
        check_status_fresh(&root).expect("status.md fresh");
    }

    #[test]
    fn mnemonic_strips_predicate_and_reads_assignment() {
        assert_eq!(mnemonic_of("(p0) add r{rd} = r{r1}, r{r2}", "add"), "add");
        assert_eq!(mnemonic_of("nop", "nop"), "nop");
        assert_eq!(mnemonic_of("r{rd} = add(r{rs1}, r{rs2})", "add"), "add");
        assert_eq!(mnemonic_of("r{rd} = #{imm}", "mov_imm"), "mov_imm");
        assert_eq!(mnemonic_of("", "jump"), "jump");
    }

    #[test]
    fn mnemonic_groups_by_first_word() {
        let insns = [
            sample_insn("add_rm", "add r/m, {imm}", Pred::True, "alu"),
            sample_insn("add_r", "add r, {imm}", Pred::True, "alu"),
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
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].names, vec!["add_r", "add_rm"]);
    }

    #[test]
    fn predicate_uses_source_operators() {
        let pred = Pred::All(vec![
            Pred::Flag("rv64".to_string()),
            Pred::Not(Box::new(Pred::Flag("mips_r6".to_string()))),
        ]);
        assert_eq!(pred_string(&pred), "rv64 && !mips_r6");
    }

    #[test]
    fn feature_coverage_counts_polarity_and_model_refs() {
        let mut model = Model::new();
        for name in ["alpha_feat", "beta_feat", "dead_feat"] {
            model.features.push(polyisa_isadl::model::Feature {
                name: name.to_string(),
                implies: vec![],
                conflicts: vec![],
            });
        }
        model.insns.push(sample_insn(
            "gated_pos",
            "gated_pos",
            Pred::Flag("alpha_feat".to_string()),
            "alu",
        ));
        model.insns.push(sample_insn(
            "gated_neg",
            "gated_neg",
            Pred::Not(Box::new(Pred::Flag("alpha_feat".to_string()))),
            "alu",
        ));
        model.insns.push(sample_insn(
            "gated_all",
            "gated_all",
            Pred::All(vec![
                Pred::Flag("alpha_feat".to_string()),
                Pred::Not(Box::new(Pred::Flag("beta_feat".to_string()))),
            ]),
            "alu",
        ));
        model.models.push(polyisa_isadl::model::ModelDef {
            name: "m1".to_string(),
            parent: String::new(),
            add_features: vec!["alpha_feat".to_string()],
            remove_features: vec!["beta_feat".to_string()],
            params: vec![],
            ident: vec![],
            timing: None,
        });
        model.ident_bit("alpha_feat", 1, 0, "edx", 0);

        let rows = feature_coverage_rows(&model);
        assert_eq!(rows.len(), 3);
        // alpha_feat: 肯定 2 件（gated_pos・gated_all）、否定 1 件、
        // モデル参照 1 件、識別ビット 1 件。
        assert_eq!(
            rows[0],
            ["alpha_feat", "2", "1", "1", "1"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        // beta_feat: 否定 1 件とモデル参照 1 件のみ。
        assert_eq!(
            rows[1],
            ["beta_feat", "—", "1", "1", "—"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        // dead_feat: どこからも参照されない。
        assert_eq!(
            rows[2],
            ["dead_feat", "—", "—", "—", "—"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }
}
