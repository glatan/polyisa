// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC V8 試作の命令意味論。バックエンドに対して総称的に書く.
//!
//! 段階2の目的は遅延スロットのステップ構成を確かめることである。
//! 分岐は即時に飛ばず npc だけを書き換え、遅延スロットの1命令を実行してから
//! `commit` で pc を npc に進める。レジスタウィンドウと annul の取り消しは
//! 本格実装で足す（annul は保持のみ）。
//!
//! 出典は SPEC-SPARC-V8 (Version 8, 1992) である。
//! Ref: SPEC-SPARC-V8 (Version 8).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Flow, StateRef, W32, W64};

use super::CpuState;

/// 整数レジスタ番号。`g0` は読むと 0、書き込みは捨てる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, g) + (self.0 as usize) * 8)
    }

    /// `g0` かどうか。
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// pc を指す。
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// npc を指す。
pub fn npc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, npc))
}

fn read<B: Backend>(b: &mut B, r: Gpr) -> B::V<W64> {
    if r.is_zero() {
        b.konst::<W64>(0)
    } else {
        b.get(r.state())
    }
}

fn write<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W64>) {
    if !rd.is_zero() {
        b.set(rd.state(), v);
    }
}

fn const_w64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

const DATA_READ: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

const DATA_WRITE: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataWrite,
};

/// ADD。32ビット演算として下位32ビットで包む（V8 は32ビット）。
pub fn add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.add::<W64>(x, y);
    // 上位を捨てずに置く試作の単純化：下位32ビットで包む。
    let lo = b.konst::<W64>(0xffff_ffff);
    let masked = b.and::<W64>(s, lo);
    write(b, rd, masked);
    Ok(())
}

/// SUB。
pub fn sub<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.sub::<W64>(x, y);
    let lo = b.konst::<W64>(0xffff_ffff);
    let masked = b.and::<W64>(s, lo);
    write(b, rd, masked);
    Ok(())
}

/// AND。
pub fn and<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let v = b.and::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// OR。
pub fn or<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let v = b.or::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// SLL。SPARC は下位5ビットだけ使う。
pub fn sll<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let mask = b.konst::<W64>(31);
    let n = b.and::<W64>(y, mask);
    let v = b.shl::<W64>(x, n);
    write(b, rd, v);
    Ok(())
}

/// SETHI。imm22 を上位に置く。
pub fn sethi<B: Backend>(b: &mut B, rd: Gpr, imm22: u32) -> Flow<B> {
    let v = const_w64(b, (imm22 as u64) << 10);
    write(b, rd, v);
    Ok(())
}

/// LD。BE・整列要求。
pub fn ld<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let base = read(b, rs1);
    let off = read(b, rs2);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let w = b.zext::<W32, W64>(v);
    write(b, rd, w);
    Ok(())
}

/// ST。BE・整列要求。
pub fn st<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let base = read(b, rs1);
    let off = read(b, rs2);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = read(b, rd);
    let lo: B::V<W32> = b.trunc::<W64, W32>(v);
    b.store::<W32>(addr, lo, DATA_WRITE)?;
    Ok(())
}

/// JMPL。遅延スロット付きの間接分岐。npc だけを書き換え、遅延スロットの後に `commit` する。
pub fn jmpl<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, pc: u64) -> Flow<B> {
    let base = read(b, rs1);
    let off = read(b, rs2);
    let target = b.add::<W64>(base, off);
    // 戻りを rd に書く（g0 なら捨てる）。
    let ret = const_w64(b, pc);
    write(b, rd, ret);
    b.set(npc_ref(), target);
    Ok(())
}

/// BA。常に成立する分岐。遅延スロットの1命令は必ず実行する。
pub fn ba_delay<B: Backend>(b: &mut B, target: u64) -> Flow<B> {
    let t = const_w64(b, target);
    b.set(npc_ref(), t);
    Ok(())
}

/// 遅延スロットの実行後に pc を npc に進め、npc を +4 する。
pub fn commit<B: Backend>(b: &mut B) -> Flow<B> {
    let npc: B::V<W64> = b.get(npc_ref());
    b.set(pc_ref(), npc);
    let four = b.konst::<W64>(4);
    let next = b.add::<W64>(npc, four);
    b.set(npc_ref(), next);
    Ok(())
}
