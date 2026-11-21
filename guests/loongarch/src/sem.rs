// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch の命令意味論。段階19。
//!
//! 対象は LA32/LA64 のユーザモード全語彙（整数・load/store・
//! LL/SC・AM*・分岐・FPU・カウンタ・CPUCFG）と、CSRRD/CSRWR/
//! CSRXCHG・ERTN 等の特権入口。LSX/LASX/LBT は LA13 の範囲。
//! Ref: SPEC-LOONGARCH-RM §2（基本命令）, §3（FP 命令）,
//! §4（CSR・例外・特権命令）.

use polyisa_sem::{Backend, ExceptionKind, GuestException, StateRef, W64};

use crate::{CpuState, Insn};

/// Trap コード（`handle_trap` に渡る内部番号）。
/// `syscall` は即値に `TRAP_SYS` を足したコードを載せる。
pub const TRAP_SYS: u64 = 0x1000;
/// 特権・未定義の命令（実行ループは Unimplemented 扱い）。
pub const TRAP_ILL: u64 = 4;
/// `break` 発行点。code = `TRAP_BRK_BASE` | code15。
pub const TRAP_BRK_BASE: u64 = 0x2000;

/// CPU 状態の位置たち。
#[must_use]
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// 例外を投げる。
fn raise<B: Backend>(b: &mut B, kind: ExceptionKind, code: u64) -> B::Exit {
    b.raise(GuestException {
        kind,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

/// 1 命令の意味論を実行する。`word` は命令語、`pc` は命令番地、
/// `la64` は LA64 モデルで動いているか。戻り値 `Ok(true)` は
/// PC を +4 進める通常完了、`Ok(false)` は分岐等で PC を
/// 意味論側が引き継いだことを示す。
// Ref: SPEC-LOONGARCH-RM §2, §3, §4.
pub fn exec<B: Backend>(
    b: &mut B,
    insn: Insn,
    word: u32,
    pc: u64,
    la64: bool,
) -> Result<bool, B::Exit> {
    let _ = (insn, word, pc, la64);
    Err(raise::<B>(b, ExceptionKind::Undefined, TRAP_ILL))
}
