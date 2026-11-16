// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WASI preview1 のホスト関数を通す実プログラム実行（層7・program）。
//!
//! wasi-sdk/clang（wasm32-wasip1 + wasm-ld + sysroot）は環境にない
//! ため、`.wasm` は `polyisa_guest_wasm::wat` のテキスト→バイナリ
//! アセンブラで手組みする。fd_write + proc_exit、args_get、
//! path_open + fd_read を stdout と終了コードで検査する。
//! Ref: SPEC-WASI-P1 (wasi_snapshot_preview1).

use std::cell::RefCell;
use std::rc::Rc;

use polyisa_cli::run_wasm::run_wasm_bytes;
use polyisa_os_wasi::WasiCtx;

/// `fd_write(1, "hi\n")` して `proc_exit(7)` するコマンドモジュール。
const SRC_HI: &str = r#"
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory 1)
  (export "memory" (memory 0))
  (export "_start" (func $start))
  (func $start
    ;; iovec {buf=64, len=3}、書き出し数は 8 に置く。
    (i32.store (i32.const 0) (i32.const 64))
    (i32.store (i32.const 4) (i32.const 3))
    (drop (call $fd_write
      (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
    ;; nwritten は 3 のはず（8 に 3 が書かれた）。
    (if (i32.ne (i32.load (i32.const 8)) (i32.const 3))
      (then (call $proc_exit (i32.const 90))))
    (call $proc_exit (i32.const 7)))
  (data (i32.const 64) "hi\n"))
"#;

/// `args_sizes_get`/`args_get` で argv を数え、argc を終了コードにする。
const SRC_ARGC: &str = r#"
(module
  (import "wasi_snapshot_preview1" "args_sizes_get"
    (func $asz (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "args_get"
    (func $aget (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory 1)
  (export "memory" (memory 0))
  (export "_start" (func $start))
  (func $start
    ;; argc を 0、buf サイズを 4 に置く。
    (drop (call $asz (i32.const 0) (i32.const 4)))
    ;; ポインタ表は 16、文字列は 256 から。
    (drop (call $aget (i32.const 16) (i32.const 256)))
    (call $proc_exit (i32.load (i32.const 0)))))
"#;

/// プリオープン `/` から `data/hello.txt` を `path_open` + `fd_read`
/// で読み、内容を stdout に写して終了コード 0 で終わる。
const SRC_CAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open
      (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))
  (memory 1)
  (export "memory" (memory 0))
  (export "_start" (func $start))
  (func $start
    ;; 開いた fd は 2048 に置く。rights_base = FD_READ|FD_SEEK = 0x6。
    (drop (call $path_open
      (i32.const 3)              ;; dirfd（プリオープン "/"）
      (i32.const 0)              ;; dirflags
      (i32.const 512) (i32.const 14) ;; "data/hello.txt"
      (i32.const 0)              ;; oflags
      (i64.const 6) (i64.const 0) ;; rights base/inheriting
      (i32.const 0)              ;; fdflags
      (i32.const 2048)))
    (if (i32.eqz (i32.load (i32.const 2048)))
      (then (call $proc_exit (i32.const 91))))
    ;; iovec {buf=4096, len=4096} で読み、読んだ数を 2052 に。
    (i32.store (i32.const 16) (i32.const 4096))
    (i32.store (i32.const 20) (i32.const 4096))
    (drop (call $fd_read
      (i32.load (i32.const 2048))
      (i32.const 16) (i32.const 1) (i32.const 2052)))
    ;; 読んだ分だけ stdout へ。
    (i32.store (i32.const 24) (i32.const 4096))
    (i32.store (i32.const 28) (i32.load (i32.const 2052)))
    (drop (call $fd_write
      (i32.const 1) (i32.const 24) (i32.const 1) (i32.const 2056)))
    (call $proc_exit (i32.const 0)))
  (data (i32.const 512) "data/hello.txt"))
"#;

fn build(src: &str) -> Vec<u8> {
    polyisa_guest_wasm::wat::module_from_str(src).expect("wat assemble")
}

fn quiet_ctx() -> Rc<RefCell<WasiCtx>> {
    let mut ctx = WasiCtx::new();
    ctx.echo_stdio = false;
    Rc::new(RefCell::new(ctx))
}

#[test]
fn wasi_fd_write_and_proc_exit() {
    let bytes = build(SRC_HI);
    let ctx = quiet_ctx();
    let code = run_wasm_bytes(&bytes, Rc::clone(&ctx)).unwrap_or_else(|e| panic!("wasi run: {e}"));
    assert_eq!(code, 7);
    assert_eq!(ctx.borrow().io.stdout, b"hi\n");
}

#[test]
fn wasi_args_roundtrip() {
    let bytes = build(SRC_ARGC);
    let mut c = WasiCtx::new();
    c.echo_stdio = false;
    c.args = vec!["prog.wasm".to_string(), "a".to_string(), "bb".to_string()];
    let ctx = Rc::new(RefCell::new(c));
    let code = run_wasm_bytes(&bytes, Rc::clone(&ctx)).unwrap_or_else(|e| panic!("wasi args: {e}"));
    assert_eq!(code, 3);
}

#[test]
fn wasi_path_open_read_file() {
    let dir = std::env::temp_dir().join("polyisa-heavy-wasi");
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("hello.txt"), "from-preopen\n").unwrap();

    let bytes = build(SRC_CAT);
    let mut c = WasiCtx::new();
    c.echo_stdio = false;
    c.preopen("/", dir.to_str().unwrap());
    let ctx = Rc::new(RefCell::new(c));
    let code =
        run_wasm_bytes(&bytes, Rc::clone(&ctx)).unwrap_or_else(|e| panic!("wasi path_open: {e}"));
    assert_eq!(code, 0);
    assert_eq!(ctx.borrow().io.stdout, b"from-preopen\n");
}
