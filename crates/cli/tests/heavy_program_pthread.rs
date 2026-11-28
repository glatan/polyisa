// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! musl 静的リンクの pthread バイナリによるフェーズ 1 の完了条件テスト。
//!
//! バイナリは .testdata/pthread-musl/pthread_test に置く。生成手順は
//! .testdata/pthread-musl/BUILD.md に記す。リポジトリには含めない。

use std::path::PathBuf;

fn binary() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.join(".testdata/pthread-musl/pthread_test")
}

#[test]
fn pthread_create_join_mutex_cond() {
    let path = binary();
    assert!(
        path.is_file(),
        "musl 静的 pthread バイナリを {} に置く",
        path.display()
    );
    let argv: Vec<String> = vec!["pthread_test".to_string()];
    let (code, out) =
        polyisa_cli::run_x86::run_elf_x86_64_captured(path.to_str().expect("utf-8"), &argv)
            .unwrap_or_else(|e| panic!("pthread_test: {e}"));
    assert_eq!(
        String::from_utf8_lossy(&out),
        "PTHREAD-TEST-PASS\n",
        "code={code}"
    );
    assert_eq!(code, 0);
}

#[test]
fn root_pthread_exit_keeps_worker_alive() {
    let path = binary().with_file_name("pthread_exit_test");
    assert!(path.is_file(), "{} を置く", path.display());
    let argv: Vec<String> = vec!["pthread_exit_test".to_string()];
    let (_code, out) =
        polyisa_cli::run_x86::run_elf_x86_64_captured(path.to_str().expect("utf-8"), &argv)
            .unwrap_or_else(|e| panic!("pthread_exit_test: {e}"));
    assert_eq!(
        String::from_utf8_lossy(&out),
        "WORKER-SURVIVED\n",
        "main の pthread_exit 後も worker が走り切る"
    );
}
