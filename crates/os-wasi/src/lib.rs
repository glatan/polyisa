// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WASI パーソナリティ。WebAssembly ゲストのインポートに
//! `wasi_snapshot_preview1`（preview1）のホスト関数を提供する。
//!
//! 構成:
//! - `abi`: preview1 の errno・filetype・フラグ・rights・構造体配置。
//! - `ctx`: `WasiCtx`。fd 表（`kernel::FdTable` とスロットを共用）、
//!   プリオープン、args/env、標準入出力、時計、乱数と各関数の実体。
//! - `host`: `Wasi`。`polyisa_guest_wasm::exec::Host` を実装し、
//!   インポート名を `WasiCtx` の処理へ繋ぐ。`proc_exit` は
//!   `TrapKind::Exited` として上がる。
//!
//! パスの閉じ込めは字句正規化と実要素の検査で行う。プリオープン根
//! からの `..` 脱出・絶対パス・根の外を指すシンボリックリンクは
//! ENOTCAPABLE にし、最終要素のリンクは LOOKUP_SYMLINK_FOLLOW の
//! ときだけ辿る。ファイルの `ino` は移植面で取れず 0 にする
//! （GAP 候補）。
//! Ref: SPEC-WASI-P1 (wasi_snapshot_preview1).

#![forbid(unsafe_code)]

pub mod abi;
pub mod ctx;
pub mod host;

pub use ctx::{WasiCtx, WasiIo};
pub use host::Wasi;
