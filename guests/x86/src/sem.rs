// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小の命令意味論。バックエンドに対して総称的に書く.
//!
//! EAX 系の整数演算のみ持つ。EFLAGS の更新（遅延フラグは本格実装）、
//! ModRM/SIB、セグメント、64ビット拡張は本格実装で足す。
//!
//! 出典は SPEC-X86-INTEL-SDM Combined v093 (2026-09-24) である。
//! Ref: SPEC-X86-INTEL-SDM (v093).

use polyisa_sem::{Backend, Flow, StateRef, W32};

use super::CpuState;

/// 汎用レジスタ番号。0=EAX である。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// EAX を指す。
    pub fn eax() -> Self {
        Self(0)
    }

    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, g) + (self.0 as usize) * 4)
    }
}

/// eip を指す。
pub fn eip_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, eip))
}

fn read<B: Backend>(b: &mut B, r: Gpr) -> B::V<W32> {
    b.get(r.state())
}

fn write<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W32>) {
    b.set(rd.state(), v);
}

/// NOP。何もしない。
pub fn nop<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// INC EAX。32ビットで包む（EFLAGS 更新は本格実装で足す）。
pub fn inc_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read(b, Gpr::eax());
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    write(b, Gpr::eax(), v);
    Ok(())
}

/// DEC EAX。32ビットで包む。
pub fn dec_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read(b, Gpr::eax());
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    write(b, Gpr::eax(), v);
    Ok(())
}

/// ADD EAX, imm32。32ビットで包む。
pub fn add_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr::eax());
    let y = b.konst::<W32>(imm);
    let v = b.add::<W32>(x, y);
    write(b, Gpr::eax(), v);
    Ok(())
}

/// MOV EAX, imm32。
pub fn mov_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let v = b.konst::<W32>(imm);
    write(b, Gpr::eax(), v);
    Ok(())
}

/// JMP rel8。eip からの相対（呼び出し側が eip+2 基準の完成形を渡す）。
pub fn jmp8<B: Backend>(b: &mut B, target: u32) -> Flow<B> {
    let t = b.konst::<W32>(target);
    b.set(eip_ref(), t);
    Ok(())
}
