// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly 最小の命令意味論。バックエンドに対して総称的に書く.
//!
//! オペランドスタックとローカル変数はフレーム基底からの動かない参照として扱う。
//! （本格実装では検証済みの位置を使う動的な参照になる。）
//! 線形メモリ・テーブル・グローバル・呼び出し・GC は本格実装で足す。
//!
//! 出典は SPEC-WASM-CORE 3.0 (Release 3.0) である。
//! Ref: SPEC-WASM-CORE (3.0).

use polyisa_sem::{Backend, ExceptionKind, Flow, GuestException, StateArray, StateRef, W32};

use super::CpuState;

/// オペランドスタックを指す。
pub fn stack_array() -> StateArray<W32> {
    StateArray::<W32>::from_layout(core::mem::offset_of!(CpuState, stack), 4)
}

/// ローカル変数を指す。
pub fn locals_array() -> StateArray<W32> {
    StateArray::<W32>::from_layout(core::mem::offset_of!(CpuState, locals), 4)
}

/// sp を指す。
pub fn sp_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, sp))
}

/// off を指す。
pub fn off_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, off))
}

/// func を指す。
pub fn func_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, func))
}

/// push。スタックあふれの検査は本格実装で足す（試作の64段を超えない前提）。
pub fn push<B: Backend>(b: &mut B, v: u32) -> Flow<B> {
    let sp: B::V<W32> = b.get(sp_ref());
    let vv = b.konst::<W32>(v);
    b.set_indexed(stack_array(), sp, vv);
    let one = b.konst::<W32>(1);
    let next = b.add::<W32>(sp, one);
    b.set(sp_ref(), next);
    Ok(())
}

/// pop。空の検査は本格実装で足す。
pub fn pop<B: Backend>(b: &mut B) -> Result<B::V<W32>, B::Exit> {
    let sp: B::V<W32> = b.get(sp_ref());
    let one = b.konst::<W32>(1);
    let prev = b.sub::<W32>(sp, one);
    b.set(sp_ref(), prev);
    Ok(b.get_indexed(stack_array(), prev))
}

/// NOP。何もしない。
pub fn nop<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// UNREACHABLE。トラップとして退出する。
pub fn unreachable<B: Backend>(b: &mut B, off: u32) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 0,
        addr: Some(off as u64),
        in_delay_slot: false,
    }))
}

/// DROP。スタックの先頭を捨てる。
pub fn drop<B: Backend>(b: &mut B) -> Flow<B> {
    let _ = pop(b)?;
    Ok(())
}

/// LOCAL.GET。ローカルをスタックに積む。
pub fn local_get<B: Backend>(b: &mut B, idx: u32) -> Flow<B> {
    let i = b.konst::<W32>(idx);
    let v: B::V<W32> = b.get_indexed(locals_array(), i);
    push_inner(b, v)
}

/// LOCAL.SET。スタックの先頭をローカルに書く。
pub fn local_set<B: Backend>(b: &mut B, idx: u32) -> Flow<B> {
    let v = pop(b)?;
    let i = b.konst::<W32>(idx);
    b.set_indexed(locals_array(), i, v);
    Ok(())
}

/// I32.CONST。定数をスタックに積む。
pub fn i32_const<B: Backend>(b: &mut B, v: u32) -> Flow<B> {
    push(b, v)
}

/// I32.ADD。下位32ビットで包む（WRAP）。
pub fn i32_add<B: Backend>(b: &mut B) -> Flow<B> {
    let y = pop(b)?;
    let x = pop(b)?;
    let s = b.add::<W32>(x, y);
    push_inner(b, s)
}

/// BR。関数内オフセットに飛ぶ（func は変えない）。
/// 実SPECの labelidx ではなく絶対 off を取る試作の簡略化である。
pub fn br<B: Backend>(b: &mut B, target: u32) -> Flow<B> {
    let t = b.konst::<W32>(target);
    b.set(off_ref(), t);
    Ok(())
}

fn push_inner<B: Backend>(b: &mut B, v: B::V<W32>) -> Flow<B> {
    let sp: B::V<W32> = b.get(sp_ref());
    b.set_indexed(stack_array(), sp, v);
    let one = b.konst::<W32>(1);
    let next = b.add::<W32>(sp, one);
    b.set(sp_ref(), next);
    Ok(())
}
