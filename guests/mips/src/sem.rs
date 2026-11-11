// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I 試作の命令意味論。バックエンドに対して総称的に書く.
//!
//! 遅延スロットは pc/npc の組で表す。分岐・ジャンプは npc だけを書き換え、
//! 遅延スロットの1命令を実行してから `commit` で pc を進める。
//! FPU、R6 の残り（BOVC/BEQC 等）、両エンディアン切り替えは本格実装で足す（HI/LO 乗除算は
//! pre-R6 のみで有効な本格相当の最小形）。
//!
//! 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) である。
//! Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, Flow, StateRef, W32, W64};

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

/// HI を指す。
pub fn hi_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, hi))
}

/// LO を指す。
pub fn lo_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, lo))
}

/// 0 除算で HI/LO に 0 を書くかの旗。0 は保つ。
pub fn div_zero_writes_zero_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, div_zero_writes_zero))
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

/// MULT。32ビット符号付き積の64ビット結果を HI:LO に置く。
pub fn mult<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let x32: B::V<W32> = b.trunc::<W64, W32>(x);
    let y32: B::V<W32> = b.trunc::<W64, W32>(y);
    let a: B::V<W64> = b.sext::<W32, W64>(x32);
    let c: B::V<W64> = b.sext::<W32, W64>(y32);
    let p = b.mul::<W64>(a, c);
    let shift = b.konst::<W64>(32);
    let hi64 = b.shr_l::<W64>(p, shift);
    let hi32: B::V<W32> = b.trunc::<W64, W32>(hi64);
    let lo32: B::V<W32> = b.trunc::<W64, W32>(p);
    let hi = b.zext::<W32, W64>(hi32);
    let lo = b.zext::<W32, W64>(lo32);
    b.set(hi_ref(), hi);
    b.set(lo_ref(), lo);
    Ok(())
}

/// MULTU。32ビット符号なし積の64ビット結果を HI:LO に置く。
pub fn multu<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let x32: B::V<W32> = b.trunc::<W64, W32>(x);
    let y32: B::V<W32> = b.trunc::<W64, W32>(y);
    let a: B::V<W64> = b.zext::<W32, W64>(x32);
    let c: B::V<W64> = b.zext::<W32, W64>(y32);
    let p = b.mul::<W64>(a, c);
    let shift = b.konst::<W64>(32);
    let hi64 = b.shr_l::<W64>(p, shift);
    let hi32: B::V<W32> = b.trunc::<W64, W32>(hi64);
    let lo32: B::V<W32> = b.trunc::<W64, W32>(p);
    let hi = b.zext::<W32, W64>(hi32);
    let lo = b.zext::<W32, W64>(lo32);
    b.set(hi_ref(), hi);
    b.set(lo_ref(), lo);
    Ok(())
}

// Gap: GAP-0013
/// DIV。LO=商、HI=剰余。0 除算は `div_zero_writes_zero` が 0 なら HI/LO を保ち、
/// 0 以外なら HI と LO に 0 を書く。
pub fn div<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let x32: B::V<W32> = b.trunc::<W64, W32>(x);
    let y32: B::V<W32> = b.trunc::<W64, W32>(y);
    let zero32 = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y32, zero32);
    let one32 = b.konst::<W32>(1);
    let safe = b.select::<W32>(is_zero, one32, y32);
    let a: B::V<W64> = b.sext::<W32, W64>(x32);
    let c: B::V<W64> = b.sext::<W32, W64>(safe);
    let q64 = b.sdiv::<W64>(a, c);
    let r64 = b.srem::<W64>(a, c);
    let q32: B::V<W32> = b.trunc::<W64, W32>(q64);
    let r32: B::V<W32> = b.trunc::<W64, W32>(r64);
    let new_lo = b.zext::<W32, W64>(q32);
    let new_hi = b.zext::<W32, W64>(r32);
    let old_lo: B::V<W64> = b.get(lo_ref());
    let old_hi: B::V<W64> = b.get(hi_ref());
    let (fin_lo, fin_hi) = div_zero_result(b, is_zero, old_lo, old_hi, new_lo, new_hi);
    b.set(lo_ref(), fin_lo);
    b.set(hi_ref(), fin_hi);
    Ok(())
}

/// DIVU。LO=商、HI=剰余。0 除算は `div_zero_writes_zero` に従う。
pub fn divu<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let x32: B::V<W32> = b.trunc::<W64, W32>(x);
    let y32: B::V<W32> = b.trunc::<W64, W32>(y);
    let zero32 = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y32, zero32);
    let one32 = b.konst::<W32>(1);
    let safe = b.select::<W32>(is_zero, one32, y32);
    let a: B::V<W64> = b.zext::<W32, W64>(x32);
    let c: B::V<W64> = b.zext::<W32, W64>(safe);
    let q64 = b.udiv::<W64>(a, c);
    let r64 = b.urem::<W64>(a, c);
    let q32: B::V<W32> = b.trunc::<W64, W32>(q64);
    let r32: B::V<W32> = b.trunc::<W64, W32>(r64);
    let new_lo = b.zext::<W32, W64>(q32);
    let new_hi = b.zext::<W32, W64>(r32);
    let old_lo: B::V<W64> = b.get(lo_ref());
    let old_hi: B::V<W64> = b.get(hi_ref());
    let (fin_lo, fin_hi) = div_zero_result(b, is_zero, old_lo, old_hi, new_lo, new_hi);
    b.set(lo_ref(), fin_lo);
    b.set(hi_ref(), fin_hi);
    Ok(())
}

/// MFHI。HI の下位32ビットを rd に書く。
pub fn mfhi<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let v: B::V<W64> = b.get(hi_ref());
    write(b, rd, v);
    Ok(())
}

/// MFLO。LO の下位32ビットを rd に書く。
pub fn mflo<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let v: B::V<W64> = b.get(lo_ref());
    write(b, rd, v);
    Ok(())
}

/// MTHI。rs の下位32ビットを HI に書く。
pub fn mthi<B: Backend>(b: &mut B, rs: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let x32: B::V<W32> = b.trunc::<W64, W32>(x);
    let v = b.zext::<W32, W64>(x32);
    b.set(hi_ref(), v);
    Ok(())
}

/// MTLO。rs の下位32ビットを LO に書く。
pub fn mtlo<B: Backend>(b: &mut B, rs: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let x32: B::V<W32> = b.trunc::<W64, W32>(x);
    let v = b.zext::<W32, W64>(x32);
    b.set(lo_ref(), v);
    Ok(())
}

/// ADDI。32ビットで包む（trap は WRAP で代用し本格実装で足す）。
pub fn addi<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let s = b.add::<W64>(base, off);
    let lo = b.konst::<W64>(0xffff_ffff);
    let masked = b.and::<W64>(s, lo);
    write(b, rt, masked);
    Ok(())
}

/// ADDIU。trap なしで 32 ビットに包む。R6 でも有効である。
pub fn addiu<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let s = b.add::<W64>(base, off);
    let lo = b.konst::<W64>(0xffff_ffff);
    let masked = b.and::<W64>(s, lo);
    write(b, rt, masked);
    Ok(())
}

/// BEQZALC。R6 の遅延スロットなし分岐・リンク。rt==0 のときだけ分岐し、
/// $31 へのリンク（pc+4）は無条件に行う。1 命令で終わり commit は不要。
pub fn beqzalc<B: Backend>(b: &mut B, _rs: Gpr, rt: Gpr, pc: u64, disp: i32) -> Flow<B> {
    // デコードが rs==0 を保証する。分岐条件 rt==0 はここで調べる。
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(polyisa_sem::Cmp::Eq, y, zero);
    let ret = const_w64(b, pc.wrapping_add(4));
    write(b, Gpr(31), ret);
    let target = pc
        .wrapping_add(4)
        .wrapping_add((disp as i64 as u64).wrapping_mul(4));
    let t = const_w64(b, target);
    b.if_then(take, |b| {
        b.set(pc_ref(), t);
        Ok(())
    })?;
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

fn div_zero_result<B: Backend>(
    b: &mut B,
    is_zero: B::B,
    old_lo: B::V<W64>,
    old_hi: B::V<W64>,
    new_lo: B::V<W64>,
    new_hi: B::V<W64>,
) -> (B::V<W64>, B::V<W64>) {
    let flag: B::V<W64> = b.get(div_zero_writes_zero_ref());
    let zero = b.konst::<W64>(0);
    let clear = b.cmp::<W64>(Cmp::Ne, flag, zero);
    let kept_lo = b.select::<W64>(clear, zero, old_lo);
    let kept_hi = b.select::<W64>(clear, zero, old_hi);
    let lo = b.select::<W64>(is_zero, kept_lo, new_lo);
    let hi = b.select::<W64>(is_zero, kept_hi, new_hi);
    (lo, hi)
}

mod sem_int;
pub use sem_int::*;
