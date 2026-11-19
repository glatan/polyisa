// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k 最小の命令単位のテスト。裸実行環境で骨格の振り分けを検査する。
//! 出典は SPEC-M68K-PRM (M68000PM/AD Rev 1) である。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_m68k::{CpuState, Insn, sem};

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

#[test]
fn nop_executes() {
    let mut env = env();
    env.step(|b| sem::exec(b, Insn::Nop, 0x4E71, 0)).unwrap();
}

#[test]
fn illegal_raises_vector4() {
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Illegal, 0x4AFC, 0))
        .expect_err("illegal は例外");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 4),
        other => panic!("unexpected exit: {other:?}"),
    }
}

#[test]
fn unimplemented_is_undefined() {
    let mut env = env();
    let e = env
        .step(|b| sem::exec(b, Insn::Rts, 0x4E75, 0))
        .expect_err("rts は未実装");
    match e {
        InterpExit::Exception(x) => assert_eq!(x.code, 0x4E75),
        other => panic!("unexpected exit: {other:?}"),
    }
}
