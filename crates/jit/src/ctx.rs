// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 生成コードと Rust の間の実行時コンテキスト。
//!
//! ブロック呼び出しは `RtCtx` へのポインタ 1 つを取る。
//! 出口の種類・例外の情報・次の番地をここに書き戻す。
//! 配置は `#[repr(C)]` で、コード生成は `offset_of!` で番地を求める。

use polyisa_sem::{ExceptionKind, GuestException};

/// 実行時コンテキスト。全フィールド 8 バイトの素直な配置。
#[repr(C)]
pub struct RtCtx {
    /// `InterpBackend` へのポインタ。実行中だけ有効。
    pub backend: usize,
    /// `backend.state` の先頭。生成コードはここから状態を読み書きする。
    pub state: usize,
    /// 出口が決めた次の番地。
    pub pc: u64,
    /// トラップ処理の既定の再開点（例外を起こした命令の直後）。
    pub next: u64,
    /// 出口の種類。0=継続、1=例外、2=未実装。
    pub code: u64,
    /// `ExceptionKind` の番号。
    pub exc_kind: u64,
    /// ISA 固有の例外コード。
    pub exc_code: u64,
    /// bit0: `exc_addr` が有効、bit1: 遅延スロット内。
    pub exc_flags: u64,
    /// 例外の関係するアドレス。
    pub exc_addr: u64,
    /// コードのページに書き込んだ（ブロックの破棄要求）。
    pub invalidate: u64,
}

/// 例外を起こした命令の情報を `RtCtx` に書く。
pub fn write_exc(ctx: &mut RtCtx, e: GuestException) {
    ctx.exc_kind = kind_code(e.kind);
    ctx.exc_code = e.code;
    ctx.exc_flags = u64::from(e.addr.is_some()) | (u64::from(e.in_delay_slot) << 1);
    ctx.exc_addr = e.addr.unwrap_or(0);
}

/// `RtCtx` の例外フィールドから `GuestException` を戻す。
pub fn read_exc(ctx: &RtCtx) -> GuestException {
    GuestException {
        kind: code_kind(ctx.exc_kind),
        code: ctx.exc_code,
        addr: (ctx.exc_flags & 1 != 0).then_some(ctx.exc_addr),
        in_delay_slot: ctx.exc_flags & 2 != 0,
    }
}

/// `ExceptionKind` の番号（生成コードに焼くため固定で振る）。
fn kind_code(k: ExceptionKind) -> u64 {
    match k {
        ExceptionKind::Undefined => 0,
        ExceptionKind::PageFault => 1,
        ExceptionKind::Align => 2,
        ExceptionKind::DivZero => 3,
        ExceptionKind::Fp => 4,
        ExceptionKind::Break => 5,
        ExceptionKind::Trap => 6,
    }
}

fn code_kind(c: u64) -> ExceptionKind {
    match c {
        1 => ExceptionKind::PageFault,
        2 => ExceptionKind::Align,
        3 => ExceptionKind::DivZero,
        4 => ExceptionKind::Fp,
        5 => ExceptionKind::Break,
        6 => ExceptionKind::Trap,
        _ => ExceptionKind::Undefined,
    }
}
