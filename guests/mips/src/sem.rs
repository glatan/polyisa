// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS I 試作の命令意味論。バックエンドに対して総称的に書く.
//!
//! 遅延スロットは pc/npc の組で表す。分岐・ジャンプは npc だけを書き換え、
//! 遅延スロットの1命令を実行してから `commit` で pc を進める。
//! 語のロードとストアはエンディアンを引数に取る。引数なしの `lw` と `sw` はビッグエンディアン。
//!
//! 出典は SPEC-MIPS-IV Rev 3.2 (1995-09) である。
//! Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64};

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

/// ユーザーモードの HW レジスタ `hwr[i]` を指す（RDHWR $0〜$3）。
pub fn hwr_ref(i: u8) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, hwr) + usize::from(i) * 8)
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

fn word_read(endian: Endian) -> Access {
    Access {
        endian,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    }
}

fn word_write(endian: Endian) -> Access {
    Access {
        endian,
        align: Align::Natural,
        kind: AccessKind::DataWrite,
    }
}

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

/// BEQZALC。R6 の遅延スロットなし分岐・リンク。rt==0 のときだけ飛び、
/// $31 へのリンク（pc+4）は無条件に書く。不成立でも pc は次の命令へ進む。
/// npc は変えない。
pub fn beqzalc<B: Backend>(b: &mut B, _rs: Gpr, rt: Gpr, pc: u64, disp: i32) -> Flow<B> {
    // デコードが rs==0 を保証する。分岐条件 rt==0 はここで調べる。
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(polyisa_sem::Cmp::Eq, y, zero);
    let fall = const_w64(b, pc.wrapping_add(4));
    write(b, Gpr(31), fall);
    let target = pc
        .wrapping_add(4)
        .wrapping_add((disp as i64 as u64).wrapping_mul(4));
    let dest = const_w64(b, target);
    let next = b.select::<W64>(take, dest, fall);
    b.set(pc_ref(), next);
    Ok(())
}

/// LW。ビッグエンディアン・整列要求。既存の呼び出し向け。
pub fn lw<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    lw_endian(b, rt, rs, imm, Endian::Be)
}

/// LW。エンディアンはモデルが渡す。
pub fn lw_endian<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W32> = b.load::<W32>(addr, word_read(endian))?;
    let w = b.zext::<W32, W64>(v);
    write(b, rt, w);
    Ok(())
}

/// SW。ビッグエンディアン・整列要求。既存の呼び出し向け。
pub fn sw<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    sw_endian(b, rt, rs, imm, Endian::Be)
}

/// SW。エンディアンはモデルが渡す。
pub fn sw_endian<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = read(b, rt);
    let lo: B::V<W32> = b.trunc::<W64, W32>(v);
    b.store::<W32>(addr, lo, word_write(endian))?;
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

fn mask32<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let lo = b.konst::<W64>(0xffff_ffff);
    b.and::<W64>(v, lo)
}

fn sext32<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let w: B::V<W32> = b.trunc::<W64, W32>(v);
    b.sext::<W32, W64>(w)
}

fn set01<B: Backend>(b: &mut B, rd: Gpr, cond: B::B) {
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
    let chosen = b.select::<W64>(cond, one, zero);
    write(b, rd, chosen);
}

fn raise_trap<B: Backend>(b: &mut B) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 0,
        addr: None,
        in_delay_slot: false,
    }))
}

fn add_overflow<B: Backend>(b: &mut B, x: B::V<W64>, y: B::V<W64>, sum: B::V<W64>) -> Flow<B> {
    let sign = b.konst::<W64>(0x8000_0000);
    let sx = b.and::<W64>(x, sign);
    let sy = b.and::<W64>(y, sign);
    let ss = b.and::<W64>(sum, sign);
    let same = b.cmp::<W64>(Cmp::Eq, sx, sy);
    let differ = b.cmp::<W64>(Cmp::Ne, sx, ss);
    b.if_then(same, |b| {
        b.if_then(differ, |b| raise_trap(b))?;
        Ok(())
    })
}

fn sub_overflow<B: Backend>(b: &mut B, x: B::V<W64>, y: B::V<W64>, diff: B::V<W64>) -> Flow<B> {
    let sign = b.konst::<W64>(0x8000_0000);
    let sx = b.and::<W64>(x, sign);
    let sy = b.and::<W64>(y, sign);
    let ss = b.and::<W64>(diff, sign);
    let differ_in = b.cmp::<W64>(Cmp::Ne, sx, sy);
    let differ_out = b.cmp::<W64>(Cmp::Ne, sx, ss);
    b.if_then(differ_in, |b| {
        b.if_then(differ_out, |b| raise_trap(b))?;
        Ok(())
    })
}

/// ADD。符号付き 32 ビットの溢れはトラップし、宛先は変えない。
pub fn add<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let x = mask32(b, x);
    let y = read(b, rt);
    let y = mask32(b, y);
    let sum = b.add::<W64>(x, y);
    let sum = mask32(b, sum);
    add_overflow(b, x, y, sum)?;
    write(b, rd, sum);
    Ok(())
}

/// SUB。符号付き 32 ビットの溢れはトラップする。
pub fn sub<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let x = mask32(b, x);
    let y = read(b, rt);
    let y = mask32(b, y);
    let diff = b.sub::<W64>(x, y);
    let diff = mask32(b, diff);
    sub_overflow(b, x, y, diff)?;
    write(b, rd, diff);
    Ok(())
}

/// XOR。
pub fn xor<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.xor::<W64>(x, y);
    let v = mask32(b, v);
    write(b, rd, v);
    Ok(())
}

/// NOR。
pub fn nor<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let either = b.or::<W64>(x, y);
    let v = b.not::<W64>(either);
    let v = mask32(b, v);
    write(b, rd, v);
    Ok(())
}

/// SLT。真なら 1。
pub fn slt<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let x = sext32(b, x);
    let y = read(b, rt);
    let y = sext32(b, y);
    let cond = b.cmp::<W64>(Cmp::LtS, x, y);
    set01(b, rd, cond);
    Ok(())
}

/// SLTU。
pub fn sltu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let x = mask32(b, x);
    let y = read(b, rt);
    let y = mask32(b, y);
    let cond = b.cmp::<W64>(Cmp::LtU, x, y);
    set01(b, rd, cond);
    Ok(())
}

/// SRL。論理右シフト。shamt の下位 5 ビット。
pub fn srl<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, shamt: u32) -> Flow<B> {
    let y = read(b, rt);
    let y = mask32(b, y);
    let n = b.konst::<W64>((shamt & 31) as u64);
    let v = b.shr_l::<W64>(y, n);
    write(b, rd, v);
    Ok(())
}

/// SRA。算術右シフト。32 ビットで符号を伸ばす。
pub fn sra<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, shamt: u32) -> Flow<B> {
    let y = read(b, rt);
    let y: B::V<W32> = b.trunc::<W64, W32>(y);
    let n = b.konst::<W32>(shamt & 31);
    let shifted: B::V<W32> = b.shr_a::<W32>(y, n);
    let v = b.zext::<W32, W64>(shifted);
    write(b, rd, v);
    Ok(())
}

fn shift_var<B: Backend>(b: &mut B, rs: Gpr) -> B::V<W64> {
    let amount = read(b, rs);
    let amount = mask32(b, amount);
    let five = b.konst::<W64>(31);
    b.and::<W64>(amount, five)
}

/// SLLV。
pub fn sllv<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, rs: Gpr) -> Flow<B> {
    let y = read(b, rt);
    let y = mask32(b, y);
    let n = shift_var(b, rs);
    let v = b.shl::<W64>(y, n);
    let v = mask32(b, v);
    write(b, rd, v);
    Ok(())
}

/// SRLV。
pub fn srlv<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, rs: Gpr) -> Flow<B> {
    let y = read(b, rt);
    let y = mask32(b, y);
    let n = shift_var(b, rs);
    let v = b.shr_l::<W64>(y, n);
    write(b, rd, v);
    Ok(())
}

/// SRAV。
pub fn srav<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, rs: Gpr) -> Flow<B> {
    let y = read(b, rt);
    let y: B::V<W32> = b.trunc::<W64, W32>(y);
    let n = shift_var(b, rs);
    let n: B::V<W32> = b.trunc::<W64, W32>(n);
    let shifted: B::V<W32> = b.shr_a::<W32>(y, n);
    let v = b.zext::<W32, W64>(shifted);
    write(b, rd, v);
    Ok(())
}

fn delay_branch<B: Backend>(b: &mut B, pc: u64, disp: i32, take: B::B, link: bool) -> Flow<B> {
    if link {
        let linked = const_w64(b, pc.wrapping_add(8));
        write(b, Gpr(31), linked);
    }
    let target = pc
        .wrapping_add(4)
        .wrapping_add((disp as i64 as u64).wrapping_mul(4));
    let taken = const_w64(b, target);
    let fall = const_w64(b, pc.wrapping_add(8));
    let chosen = b.select::<W64>(take, taken, fall);
    b.set(npc_ref(), chosen);
    Ok(())
}

fn cmp_regs<B: Backend>(b: &mut B, op: Cmp, rs: Gpr, rt: Gpr) -> B::B {
    match op {
        Cmp::LtS | Cmp::GtS | Cmp::LeS | Cmp::GeS => {
            let x = read(b, rs);
            let x = sext32(b, x);
            let y = read(b, rt);
            let y = sext32(b, y);
            b.cmp::<W64>(op, x, y)
        }
        _ => {
            let x = read(b, rs);
            let x = mask32(b, x);
            let y = read(b, rt);
            let y = mask32(b, y);
            b.cmp::<W64>(op, x, y)
        }
    }
}

fn cmp_zero<B: Backend>(b: &mut B, op: Cmp, rs: Gpr) -> B::B {
    let x = read(b, rs);
    let x = sext32(b, x);
    let zero = b.konst::<W64>(0);
    b.cmp::<W64>(op, x, zero)
}

/// BNE。遅延スロット付き。
pub fn bne_delay<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_regs(b, Cmp::Ne, rs, rt);
    delay_branch(b, pc, disp, take, false)
}

/// BLEZ。
pub fn blez_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::LeS, rs);
    delay_branch(b, pc, disp, take, false)
}

/// BGTZ。
pub fn bgtz_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::GtS, rs);
    delay_branch(b, pc, disp, take, false)
}

/// BLTZ。
pub fn bltz_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::LtS, rs);
    delay_branch(b, pc, disp, take, false)
}

/// BGEZ。
pub fn bgez_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::GeS, rs);
    delay_branch(b, pc, disp, take, false)
}

/// BLTZAL。リンクは遅延スロットの次（pc+8）。
pub fn bltzal_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::LtS, rs);
    delay_branch(b, pc, disp, take, true)
}

/// BGEZAL。
pub fn bgezal_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::GeS, rs);
    delay_branch(b, pc, disp, take, true)
}

/// JAL。リンクは pc+8。
pub fn jal_delay<B: Backend>(b: &mut B, pc: u64, target: u64) -> Flow<B> {
    let linked = const_w64(b, pc.wrapping_add(8));
    write(b, Gpr(31), linked);
    let dest = const_w64(b, target);
    b.set(npc_ref(), dest);
    Ok(())
}

/// JR。飛び先は rs の下位 32 ビットを語境界に揃えた値。
pub fn jr_delay<B: Backend>(b: &mut B, rs: Gpr) -> Flow<B> {
    let dest = read(b, rs);
    let dest = mask32(b, dest);
    let align = b.konst::<W64>(0xffff_fffc);
    let target = b.and::<W64>(dest, align);
    b.set(npc_ref(), target);
    Ok(())
}

/// JALR。リンクは pc+8。飛び先は書き込み前の rs を語境界に揃えた値。
pub fn jalr_delay<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, pc: u64) -> Flow<B> {
    let dest = read(b, rs);
    let dest = mask32(b, dest);
    let align = b.konst::<W64>(0xffff_fffc);
    let target = b.and::<W64>(dest, align);
    let linked = const_w64(b, pc.wrapping_add(8));
    write(b, rd, linked);
    b.set(npc_ref(), target);
    Ok(())
}

fn raise_code<B: Backend>(b: &mut B, code: u64) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Break,
        code,
        addr: None,
        in_delay_slot: false,
    }))
}

/// SYSCALL。番号の解釈は呼び出し側。ここでは終了の印だけを返す。
pub fn syscall<B: Backend>(b: &mut B) -> Flow<B> {
    raise_code(b, 1)
}

/// BREAK。
pub fn break_<B: Backend>(b: &mut B) -> Flow<B> {
    raise_code(b, 2)
}

/// SLTI。即値は符号拡張。
pub fn slti<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let x = sext32(b, x);
    let imm_v = b.konst::<W64>(imm as i64 as u64);
    let imm_v = sext32(b, imm_v);
    let cond = b.cmp::<W64>(Cmp::LtS, x, imm_v);
    set01(b, rt, cond);
    Ok(())
}

/// SLTIU。即値は符号拡張してから、32 ビット符号なしで比べる。
pub fn sltiu<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let x = mask32(b, x);
    let imm_v = b.konst::<W64>(imm as i64 as u64);
    let imm_v = mask32(b, imm_v);
    let cond = b.cmp::<W64>(Cmp::LtU, x, imm_v);
    set01(b, rt, cond);
    Ok(())
}

/// ANDI。即値はゼロ拡張。
pub fn andi<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, uimm: u32) -> Flow<B> {
    let x = read(b, rs);
    let x = mask32(b, x);
    let imm = b.konst::<W64>(u64::from(uimm & 0xffff));
    let v = b.and::<W64>(x, imm);
    write(b, rt, v);
    Ok(())
}

/// ORI。即値はゼロ拡張。
pub fn ori<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, uimm: u32) -> Flow<B> {
    let x = read(b, rs);
    let x = mask32(b, x);
    let imm = b.konst::<W64>(u64::from(uimm & 0xffff));
    let v = b.or::<W64>(x, imm);
    write(b, rt, v);
    Ok(())
}

/// XORI。即値はゼロ拡張。
pub fn xori<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, uimm: u32) -> Flow<B> {
    let x = read(b, rs);
    let x = mask32(b, x);
    let imm = b.konst::<W64>(u64::from(uimm & 0xffff));
    let v = b.xor::<W64>(x, imm);
    let v = mask32(b, v);
    write(b, rt, v);
    Ok(())
}

/// LUI。即値を 16 ビット左へ置く。rs は見ない。
pub fn lui<B: Backend>(b: &mut B, rt: Gpr, uimm: u32) -> Flow<B> {
    let v = b.konst::<W64>(u64::from(uimm & 0xffff) << 16);
    write(b, rt, v);
    Ok(())
}

fn ea<B: Backend>(b: &mut B, rs: Gpr, imm: i32) -> B::V<W64> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    b.add::<W64>(base, off)
}

fn data_acc(endian: Endian, align: Align, kind: AccessKind) -> Access {
    Access {
        endian,
        align,
        kind,
    }
}

/// LB。符号拡張して下位 32 ビットに置く。
pub fn lb<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let addr = ea(b, rs, imm);
    let acc = data_acc(endian, Align::Unaligned, AccessKind::DataRead);
    let v: B::V<W8> = b.load(addr, acc)?;
    let s: B::V<W32> = b.sext::<W8, W32>(v);
    let wide = b.zext::<W32, W64>(s);
    write(b, rt, wide);
    Ok(())
}

/// LBU。
pub fn lbu<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let addr = ea(b, rs, imm);
    let acc = data_acc(endian, Align::Unaligned, AccessKind::DataRead);
    let v: B::V<W8> = b.load(addr, acc)?;
    let wide = b.zext::<W8, W64>(v);
    write(b, rt, wide);
    Ok(())
}

/// LH。
pub fn lh<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let addr = ea(b, rs, imm);
    let acc = data_acc(endian, Align::Natural, AccessKind::DataRead);
    let v: B::V<W16> = b.load(addr, acc)?;
    let s: B::V<W32> = b.sext::<W16, W32>(v);
    let wide = b.zext::<W32, W64>(s);
    write(b, rt, wide);
    Ok(())
}

/// LHU。
pub fn lhu<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let addr = ea(b, rs, imm);
    let acc = data_acc(endian, Align::Natural, AccessKind::DataRead);
    let v: B::V<W16> = b.load(addr, acc)?;
    let wide = b.zext::<W16, W64>(v);
    write(b, rt, wide);
    Ok(())
}

/// SB。
pub fn sb<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let addr = ea(b, rs, imm);
    let src = read(b, rt);
    let lo: B::V<W8> = b.trunc::<W64, W8>(src);
    let acc = data_acc(endian, Align::Unaligned, AccessKind::DataWrite);
    b.store(addr, lo, acc)?;
    Ok(())
}

/// SH。
pub fn sh<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let addr = ea(b, rs, imm);
    let src = read(b, rt);
    let lo: B::V<W16> = b.trunc::<W64, W16>(src);
    let acc = data_acc(endian, Align::Natural, AccessKind::DataWrite);
    b.store(addr, lo, acc)?;
    Ok(())
}

fn word_parts<B: Backend>(b: &mut B, rs: Gpr, imm: i32) -> (B::V<W64>, B::V<W64>) {
    let addr = ea(b, rs, imm);
    let mask = b.konst::<W64>(3);
    let low = b.and::<W64>(addr, mask);
    let align = b.konst::<W64>(0xffff_fffc);
    let aligned = b.and::<W64>(addr, align);
    (low, aligned)
}

fn load_aligned_word<B: Backend>(
    b: &mut B,
    aligned: B::V<W64>,
    endian: Endian,
) -> Result<B::V<W64>, B::Exit> {
    let acc = data_acc(endian, Align::Natural, AccessKind::DataRead);
    let word: B::V<W32> = b.load(aligned, acc)?;
    Ok(b.zext::<W32, W64>(word))
}

fn shift8<B: Backend>(b: &mut B, low: B::V<W64>) -> B::V<W64> {
    let eight = b.konst::<W64>(8);
    b.mul::<W64>(low, eight)
}

fn keep_low<B: Backend>(b: &mut B, bits: B::V<W64>) -> B::V<W64> {
    let one = b.konst::<W64>(1);
    let shifted = b.shl::<W64>(one, bits);
    b.sub::<W64>(shifted, one)
}

/// LWL。エンディアンで「左」の向きが変わる。
pub fn lwl<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let (low, aligned) = word_parts(b, rs, imm);
    let word = load_aligned_word(b, aligned, endian)?;
    let old = read(b, rt);
    let old = mask32(b, old);
    let off8 = shift8(b, low);
    let shift = match endian {
        Endian::Be => off8,
        Endian::Le => {
            let three = b.konst::<W64>(3);
            let from_right = b.sub::<W64>(three, low);
            shift8(b, from_right)
        }
    };
    let shifted = b.shl::<W64>(word, shift);
    let kept_mask = keep_low(b, shift);
    let kept = b.and::<W64>(old, kept_mask);
    let merged = b.or::<W64>(shifted, kept);
    let merged = mask32(b, merged);
    write(b, rt, merged);
    Ok(())
}

/// LWR。
pub fn lwr<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let (low, aligned) = word_parts(b, rs, imm);
    let word = load_aligned_word(b, aligned, endian)?;
    let old = read(b, rt);
    let old = mask32(b, old);
    let one = b.konst::<W64>(1);
    let three = b.konst::<W64>(3);
    let four = b.konst::<W64>(4);
    let (right, nbytes) = match endian {
        Endian::Be => {
            let right = b.sub::<W64>(three, low);
            let nbytes = b.add::<W64>(low, one);
            (right, nbytes)
        }
        Endian::Le => {
            let nbytes = b.sub::<W64>(four, low);
            (low, nbytes)
        }
    };
    let right_bits = shift8(b, right);
    let low_bits = shift8(b, nbytes);
    let lowmask = keep_low(b, low_bits);
    let not_low = b.not::<W64>(lowmask);
    let highmask = mask32(b, not_low);
    let shifted = b.shr_l::<W64>(word, right_bits);
    let kept = b.and::<W64>(old, highmask);
    let written = b.and::<W64>(shifted, lowmask);
    let merged = b.or::<W64>(kept, written);
    let merged = mask32(b, merged);
    write(b, rt, merged);
    Ok(())
}

fn store_aligned_word<B: Backend>(
    b: &mut B,
    aligned: B::V<W64>,
    value: B::V<W64>,
    endian: Endian,
) -> Flow<B> {
    let lo: B::V<W32> = b.trunc::<W64, W32>(value);
    let acc = data_acc(endian, Align::Natural, AccessKind::DataWrite);
    b.store(aligned, lo, acc)?;
    Ok(())
}

/// SWL。
pub fn swl<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let (low, aligned) = word_parts(b, rs, imm);
    let old = load_aligned_word(b, aligned, endian)?;
    let src = read(b, rt);
    let src = mask32(b, src);
    let off8 = shift8(b, low);
    let n = match endian {
        Endian::Be => off8,
        Endian::Le => {
            let three = b.konst::<W64>(3);
            let from_right = b.sub::<W64>(three, low);
            shift8(b, from_right)
        }
    };
    let thirty_two = b.konst::<W64>(32);
    let down = b.sub::<W64>(thirty_two, n);
    let ones = b.konst::<W64>(0xffff_ffff);
    let shifted_ones = b.shr_l::<W64>(ones, down);
    let mask_old = b.shl::<W64>(shifted_ones, down);
    let rt_part = b.shr_l::<W64>(src, n);
    let kept = b.and::<W64>(old, mask_old);
    let not_mask = b.not::<W64>(mask_old);
    let not_mask = mask32(b, not_mask);
    let written = b.and::<W64>(rt_part, not_mask);
    let merged = b.or::<W64>(kept, written);
    store_aligned_word(b, aligned, merged, endian)
}

/// SWR。
pub fn swr<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let (low, aligned) = word_parts(b, rs, imm);
    let old = load_aligned_word(b, aligned, endian)?;
    let src = read(b, rt);
    let src = mask32(b, src);
    let shift_left = match endian {
        Endian::Be => {
            let three = b.konst::<W64>(3);
            let from_left = b.sub::<W64>(three, low);
            shift8(b, from_left)
        }
        Endian::Le => shift8(b, low),
    };
    let mask_old = keep_low(b, shift_left);
    let rt_part = b.shl::<W64>(src, shift_left);
    let kept = b.and::<W64>(old, mask_old);
    let not_mask = b.not::<W64>(mask_old);
    let not_mask = mask32(b, not_mask);
    let written = b.and::<W64>(rt_part, not_mask);
    let merged = b.or::<W64>(kept, written);
    store_aligned_word(b, aligned, merged, endian)
}
