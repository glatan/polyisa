// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly 仕様テストスイート（層5・conformance）。
//!
//! `.testdata/wasm-spec/test/core` の `.wast` を走らせる。段階 12 の範囲は
//! 1.0/2.0 のコア命令なので、3.0 以降の提案（例外、GC、関数参照、tail-call、
//! memory64、マルチメモリ、SIMD）はランナー側で skip に数える。
//! データがなければ `devtool test:plan` がこのバイナリを実行対象から外す。
//!
//! 対象データは台帳 TEST-WASM-SPEC.
//! Ref: TEST-WASM-SPEC, SPEC-WASM-CORE.

use std::path::{Path, PathBuf};

use polyisa_guest_wasm::wast::Runner;

fn suite_root() -> PathBuf {
    // ワークスペースルートは環境変数か、このファイルの位置から辿る。
    if let Ok(p) = std::env::var("POLYISA_ROOT") {
        return Path::new(&p).join(".testdata/wasm-spec/test");
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.testdata/wasm-spec/test")
        .canonicalize()
        .expect("wasm-spec testsuite dir")
}

/// 実行対象の .wast を列挙する。core の直下と bulk-memory のみ
/// （3.0 提案のサブディレクトリは範囲外）。
fn list_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let core = root.join("core");
    let mut push_dir = |dir: &Path| {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "wast") {
                out.push(p);
            }
        }
    };
    push_dir(&core);
    push_dir(&core.join("bulk-memory"));
    out.sort();
    out
}

#[test]
fn spec_suite_core_2_0() {
    let root = suite_root();
    let mut files = list_files(&root);
    if let Ok(only) = std::env::var("WAST_ONLY") {
        files.retain(|f| f.file_name().unwrap().to_string_lossy().contains(&only));
    }
    assert!(!files.is_empty(), "no .wast under {}", root.display());
    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut total_skip = 0usize;
    let mut bad_files: Vec<String> = Vec::new();
    for f in &files {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        eprintln!(">> {name}");
        let src = std::fs::read_to_string(f).expect("read wast");
        let mut r = Runner::new();
        let st = r.run_str(&src);
        eprintln!(
            "{name:36} pass={:5} fail={:4} skip={:4}",
            st.passed, st.failed, st.skipped
        );
        if st.failed != 0 {
            for m in &st.failures {
                eprintln!("  !! {m}");
            }
            bad_files.push(format!("{name} ({} failures)", st.failed));
        }
        total_pass += st.passed;
        total_fail += st.failed;
        total_skip += st.skipped;
    }
    eprintln!(
        "TOTAL: pass={total_pass} fail={total_fail} skip={total_skip} files={}",
        files.len()
    );
    assert!(
        bad_files.is_empty(),
        "spec failures in {} file(s): {bad_files:?}",
        bad_files.len()
    );
}
