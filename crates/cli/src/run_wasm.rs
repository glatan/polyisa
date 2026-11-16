// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly モジュール（`\0asm`）の実行。`wasi_snapshot_preview1`
//! のコマンドモジュール（`_start`）またはリアクター（`_initialize`）
//! を `polyisa_os_wasi::Wasi` のホスト関数で動かす。
//!
//! `--root <dir>` は WASI のプリオープンとして `/` に割り当てる
//! （wasmtime の `--dir` に相当）。モジュールファイル自体はホストの
//! パスから読む。`proc_exit` は終了コードとして返る。
//! Ref: SPEC-WASI-P1 (wasi_snapshot_preview1).

use std::cell::RefCell;
use std::rc::Rc;

use polyisa_guest_wasm::exec::{self, ExternVal, Store, TrapKind};
use polyisa_os_wasi::WasiCtx;

/// wasm バイナリを `ctx` で実行する。`_start`/`_initialize` を呼び、
/// `proc_exit` のコードを返す。トラップ・リンク失敗は Err。
pub fn run_wasm_bytes(bytes: &[u8], ctx: Rc<RefCell<WasiCtx>>) -> Result<u64, String> {
    let v = polyisa_guest_wasm::compile(bytes).map_err(|e| format!("wasm: {}", e.msg()))?;
    let mut store = Store::default();
    let host = polyisa_os_wasi::Wasi::shared(Rc::clone(&ctx));
    let inst = match exec::instantiate(&mut store, Rc::new(v), &exec::Registry::new(), &host) {
        Ok(i) => i,
        Err(exec::Error::Trap(t)) if matches!(t.kind, TrapKind::Exited(_)) => {
            // start セクションの中で proc_exit した。
            let TrapKind::Exited(c) = t.kind else {
                unreachable!()
            };
            return Ok(u64::from(c));
        }
        Err(e) => return Err(format!("wasm instantiate: {}", e.msg())),
    };
    // コマンドモジュールは _start、リアクターは _initialize。
    let entry = inst.export("_start").or_else(|| inst.export("_initialize"));
    let Some(ExternVal::Func(f)) = entry else {
        return Err("wasm: _start/_initialize のエクスポートがない".to_string());
    };
    match exec::invoke(&mut store, f, &[]) {
        Ok(_) => Ok(0),
        Err(t) => match t.kind {
            TrapKind::Exited(c) => Ok(u64::from(c)),
            _ => Err(format!("wasm trap: {}", t.msg())),
        },
    }
}

/// 読み込み済みの `bytes` を実行する。`prog` は `args[0]` に置く
/// 表示名、`argv` はその後ろに並ぶ。`root` があればプリオープン
/// `/` → `root` を用意する。
pub fn run_wasm_prog(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    root: Option<&str>,
) -> Result<u64, String> {
    let mut ctx = WasiCtx::new();
    ctx.args = std::iter::once(prog.to_string())
        .chain(argv.iter().cloned())
        .collect();
    if let Some(r) = root {
        ctx.preopen("/", r);
    }
    run_wasm_bytes(bytes, Rc::new(RefCell::new(ctx)))
}

/// `path` の wasm を実行する。`argv` は `args[0]` の後ろに並ぶ。
/// `root` があればプリオープン `/` → `root` を用意する。
pub fn run_wasm(path: &str, argv: &[String], root: Option<&str>) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    run_wasm_prog(&bytes, path, argv, root)
}
