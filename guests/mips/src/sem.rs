// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I 試作の命令意味論。バックエンドに対して総称的に書く.
//!
//! 遅延スロットは pc/npc の組で表す。分岐・ジャンプは npc だけを書き換え、
//! 遅延スロットの1命令を実行してから `commit` で pc を進める。
//! HI/LO、FPU、R6、両エンディアン切り替えは本格実装で足す。
//!
//! 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) である。
//! Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Flow, StateRef, W32, W64};

use super::CpuState;

/// 整数レジスタ番号。`$0` は読むと 0、書き込みは捨てる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, g) + (self.0 as usize) * 8)
    }

    /// `$0` かどうか。
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

/// ADDU。32ビットで包む（trap なし。ADD/SUB の trap は本格実装で足す）。
pub fn addu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let s = b.add::<W64>(x, y);
    let lo = b.konst::<W64>(0xffff_ffff);
    let masked = b.and::<W64>(s, lo);
    write(b, rd, masked);
    Ok(())
}

/// SUBU。32ビットで包む（trap なし）。
pub fn subu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let s = b.sub::<W64>(x, y);
    let lo = b.konst::<W64>(0xffff_ffff);
    let masked = b.and::<W64>(s, lo);
    write(b, rd, masked);
    Ok(())
}

/// AND。
pub fn and<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.and::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// OR。
pub fn or<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.or::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// SLL。shamt は下位5ビットだけ使う。
pub fn sll<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, shamt: u32) -> Flow<B> {
    let y = read(b, rt);
    let n = b.konst::<W64>((shamt & 31) as u64);
    let v = b.shl::<W64>(y, n);
    let lo = b.konst::<W64>(0xffff_ffff);
    let masked = b.and::<W64>(v, lo);
    write(b, rd, masked);
    Ok(())
}

/// LW。BE・整列要求。
pub fn lw<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let w = b.zext::<W32, W64>(v);
    write(b, rt, w);
    Ok(())
}

/// SW。BE・整列要求。
pub fn sw<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = read(b, rt);
    let lo: B::V<W32> = b.trunc::<W64, W32>(v);
    b.store::<W32>(addr, lo, DATA_WRITE)?;
    Ok(())
}

/// BEQ。遅延スロット付き。成立時のみ npc を書き換える。
/// fallthrough は pc+8 を内部で計算する（呼び出し側の事前設定に依存しない）。
pub fn beq_delay<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let eq = b.cmp::<W64>(polyisa_sem::Cmp::Eq, x, y);
    let target = pc
        .wrapping_add(4)
        .wrapping_add((disp as i64 as u64).wrapping_mul(4));
    let t = const_w64(b, target);
    let fall = const_w64(b, pc.wrapping_add(8));
    let chosen = b.select::<W64>(eq, t, fall);
    b.set(npc_ref(), chosen);
    Ok(())
}

/// J。遅延スロット付きの無条件ジャンプ。
/// target は (PC+4)[31:28] 合成済みの完成形を呼び出し側が渡す（本格実装で合成する）。
pub fn j_delay<B: Backend>(b: &mut B, target: u64) -> Flow<B> {
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
