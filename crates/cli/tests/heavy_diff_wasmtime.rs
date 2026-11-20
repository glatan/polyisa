// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wasmtime を参照実装とする差分テスト（層6・diff）。
//!
//! 同じ `.wasm` を `wasmtime run` と polyisa の WASI ホストで動かし、
//! stdout と終了コードを比較する。`wasmtime` バイナリがなければ
//! devtool test:plan がこのバイナリを対象から外す（Req::Tool）。
//! wasmtime は実行比較のオラクル（用途X）。Ref: SPEC-WASI-P1.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

use polyisa_cli::run_wasm::run_wasm_bytes;
use polyisa_os_wasi::WasiCtx;

/// fd_write + proc_exit + args + path_open を一度に通す差分対象。
/// stdout に "hi\n" と argv の個数、ファイルの中身を出す。
const SRC: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_sizes_get"
    (func $asz (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory 1)
  (export "memory" (memory 0))
  (export "_start" (func $start))
  (func $start
    (i32.store (i32.const 0) (i32.const 64))
    (i32.store (i32.const 4) (i32.const 3))
    (drop (call $fd_write
      (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
    ;; argc を '0'+argc の1桁として書き出す。
    (drop (call $asz (i32.const 32) (i32.const 36)))
    (i32.store8 (i32.const 128)
      (i32.add (i32.const 48) (i32.load (i32.const 32))))
    (i32.store (i32.const 12) (i32.const 128))
    (i32.store (i32.const 16) (i32.const 2))
    (i32.store8 (i32.const 129) (i32.const 10))
    (drop (call $fd_write
      (i32.const 1) (i32.const 12) (i32.const 1) (i32.const 20)))
    (call $proc_exit (i32.const 5)))
  (data (i32.const 64) "hi\n"))
"#;

fn wasmtime_bin() -> Option<PathBuf> {
    for c in ["wasmtime", "/usr/sbin/wasmtime", "/usr/bin/wasmtime"] {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(PathBuf::from(c));
        }
    }
    None
}

/// `wasmtime run` の (stdout, exit code)。
fn run_wasmtime(bin: &Path, wasm: &Path, args: &[&str]) -> (Vec<u8>, i32) {
    let out = Command::new(bin)
        .arg("run")
        .arg(wasm)
        .args(args)
        .output()
        .expect("wasmtime run");
    (out.stdout, out.status.code().unwrap_or(-1))
}

#[test]
fn fd_write_args_proc_exit_match_wasmtime() {
    let Some(wt) = wasmtime_bin() else {
        eprintln!("wasmtime がないので差分を省略");
        return;
    };
    let bytes = polyisa_guest_wasm::wat::module_from_str(SRC).expect("wat assemble");
    let dir = std::env::temp_dir().join("polyisa-diff-wasmtime");
    std::fs::create_dir_all(&dir).unwrap();
    let wasm = dir.join("diff.wasm");
    std::fs::write(&wasm, &bytes).unwrap();

    let (wt_out, wt_code) = run_wasmtime(&wt, &wasm, &["x", "yy"]);

    let mut c = WasiCtx::new();
    c.echo_stdio = false;
    c.args = vec![
        wasm.to_string_lossy().into_owned(),
        "x".to_string(),
        "yy".to_string(),
    ];
    let ctx = Rc::new(RefCell::new(c));
    let code = run_wasm_bytes(&bytes, Rc::clone(&ctx))
        .unwrap_or_else(|e| panic!("polyisa wasi: {e}")) as i32;

    assert_eq!(code, wt_code, "exit code (wasmtime={wt_code})");
    assert_eq!(ctx.borrow().io.stdout, wt_out, "stdout mismatch");
    assert_eq!(ctx.borrow().io.stdout, b"hi\n3\n");
}
