// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly 最小の命令単位のテスト。裸実行環境でスタックとトラップを検査する.
//! 出典は SPEC-WASM-CORE 3.0 (Release 3.0) である.
//! Ref: SPEC-WASM-CORE (3.0).

use polyisa_engine::bare::BareEnv;
use polyisa_guest_wasm::CpuState;
use polyisa_guest_wasm::sem;
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

/// `(func ...)` だけのモジュールをテキストから組み立てて検証する。
fn validate_body(body: &str) -> Result<(), String> {
    let src = format!("(module (func {body}))");
    let bytes = polyisa_guest_wasm::wat::module_from_str(&src).map_err(|e| e.0)?;
    polyisa_guest_wasm::compile(&bytes)
        .map(|_| ())
        .map_err(|e| e.msg())
}

#[test]
fn validate_accepts_balanced_void_body() {
    let r = validate_body("(local i32) i32.const 1 i32.const 2 i32.add local.set 0");
    assert_eq!(r, Ok(()));
}

#[test]
fn validate_rejects_underflow_and_local_and_leftover() {
    // 空スタックの i32.add は型不一致（underflow）。
    let e = validate_body("i32.add").unwrap_err();
    assert!(e.contains("type mismatch"), "{e}");
    // ローカル 4 は存在しない。
    let e = validate_body("local.get 4").unwrap_err();
    assert!(e.contains("unknown local"), "{e}");
    // i32 を残したまま終わるのは型不一致。
    let e = validate_body("i32.const 1").unwrap_err();
    assert!(e.contains("type mismatch"), "{e}");
}

#[test]
fn validate_unreachable_makes_stack_polymorphic() {
    // unreachable の後の pop はボトム型として許す。ただし push した
    // 値は実在するので、結果を残しすぎると型不一致になる。
    assert_eq!(validate_body("unreachable i32.add drop"), Ok(()));
    let e = validate_body("unreachable i32.add").unwrap_err();
    assert!(e.contains("type mismatch"), "{e}");
}
