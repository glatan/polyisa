// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly 最小の命令単位のテスト。裸実行環境でスタックとトラップを検査する.
//! 出典は SPEC-WASM-CORE 3.0 (Release 3.0) である.
//! Ref: SPEC-WASM-CORE (3.0).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_wasm::CpuState;
use polyisa_guest_wasm::sem;
use polyisa_guest_wasm::validate::{self, Op, Reject};
use polyisa_sem::Backend as _;

fn env() -> BareEnv {
    BareEnv::new(core::mem::size_of::<CpuState>())
}

fn sp(env: &mut BareEnv) -> u32 {
    env.backend.get(sem::sp_ref())
}

#[test]
fn const_add_drop() {
    let mut env = env();
    env.step(|b| sem::i32_const(b, 40)).unwrap();
    env.step(|b| sem::i32_const(b, 2)).unwrap();
    assert_eq!(sp(&mut env), 2);
    env.step(sem::i32_add).unwrap();
    assert_eq!(sp(&mut env), 1);
    // 結果は 42 である。
    env.step(|b| sem::local_set(b, 0)).unwrap();
    assert_eq!(sp(&mut env), 0);
    env.step(|b| sem::local_get(b, 0)).unwrap();
    assert_eq!(sp(&mut env), 1);
    env.step(sem::drop).unwrap();
    assert_eq!(sp(&mut env), 0);
    // もう一度積んで取り出し、中身を確認する。
    env.step(|b| sem::i32_const(b, 7)).unwrap();
    env.step(|b| sem::i32_const(b, 35)).unwrap();
    env.step(sem::i32_add).unwrap();
    let mut v = 0;
    env.step(|b| {
        v = sem::pop(b)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(v, 42);
    assert_eq!(sp(&mut env), 0);
}

#[test]
fn wrap_add() {
    let mut env = env();
    env.step(|b| sem::i32_const(b, 0xffff_ffff)).unwrap();
    env.step(|b| sem::i32_const(b, 1)).unwrap();
    env.step(sem::i32_add).unwrap();
    let mut v = 0;
    env.step(|b| {
        v = sem::pop(b)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(v, 0);
}

#[test]
fn locals_roundtrip() {
    let mut env = env();
    env.step(|b| sem::i32_const(b, 123)).unwrap();
    env.step(|b| sem::local_set(b, 3)).unwrap();
    env.step(|b| sem::local_get(b, 3)).unwrap();
    let mut v = 0;
    env.step(|b| {
        v = sem::pop(b)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(v, 123);
}

#[test]
fn unreachable_traps() {
    use polyisa_engine::interp::InterpExit;
    let mut env = env();
    let r = env.step(|b| sem::unreachable(b, 16));
    assert!(matches!(r, Err(InterpExit::Exception(_))));
}

#[test]
fn br_moves_offset_only() {
    let mut env = env();
    env.backend.set(sem::func_ref(), 3);
    env.backend.set(sem::off_ref(), 10);
    env.step(|b| sem::br(b, 40)).unwrap();
    // func は変えず off だけ進む（非線形PCの trial）。
    assert_eq!(env.backend.get(sem::func_ref()), 3);
    assert_eq!(env.backend.get(sem::off_ref()), 40);
}

#[test]
fn validate_accepts_balanced_void_body() {
    let ops = [Op::I32Const, Op::I32Const, Op::I32Add, Op::LocalSet(0)];
    assert_eq!(validate::validate(4, &ops), Ok(()));
}

#[test]
fn validate_rejects_underflow_and_local_and_leftover() {
    assert_eq!(
        validate::validate(4, &[Op::I32Add]),
        Err(Reject::StackUnderflow)
    );
    assert_eq!(
        validate::validate(4, &[Op::LocalGet(4)]),
        Err(Reject::LocalRange)
    );
    assert_eq!(
        validate::validate(4, &[Op::I32Const]),
        Err(Reject::StackLeft)
    );
}

#[test]
fn validate_unreachable_makes_stack_polymorphic() {
    // unreachable の後の add は、スタックが空でも拒否しない。終わりも合う。
    let ops = [Op::Unreachable, Op::I32Add];
    assert_eq!(validate::validate(1, &ops), Ok(()));
}
