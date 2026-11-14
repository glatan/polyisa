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
use polyisa_sem::{
    Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64, Width,
};

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

/// branch-likely の遅延スロット無効化フラグを指す。
pub fn nullify_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, nullify))
}

/// 64 ビットモデルかどうかのフラグを指す。
pub fn is64_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, is64))
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
    let masked = mask32(b, s);
    write(b, rd, masked);
    Ok(())
}

/// SUBU。32ビットで包む（trap なし）。
pub fn subu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let s = b.sub::<W64>(x, y);
    let masked = mask32(b, s);
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
    let masked = mask32(b, v);
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
    let masked = mask32(b, s);
    write(b, rt, masked);
    Ok(())
}

/// ADDIU。trap なしで 32 ビットに包む。R6 でも有効である。
pub fn addiu<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let s = b.add::<W64>(base, off);
    let masked = mask32(b, s);
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
    // is64 では 32 ビットロード結果は符号拡張の規約。
    let w = mask32(b, w);
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

/// 32 ビット命令の結果をレジスタ約束に正規化する。
/// 64 ビットモデルでは MIPS64 の規約どおり符号拡張、
/// 32 ビットモデルでは従来どおり下位 32 ビットのゼロ拡張。
fn mask32<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let s = sext32(b, v);
    let lo = b.konst::<W64>(0xffff_ffff);
    let z = b.and::<W64>(v, lo);
    let flag: B::V<W64> = b.get(is64_ref());
    let zero = b.konst::<W64>(0);
    let is64 = b.cmp::<W64>(Cmp::Ne, flag, zero);
    b.select::<W64>(is64, s, z)
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
            let y = read(b, rt);
            // 64 ビットモデルはレジスタが正規化済みなので生の比較が HW と一致する。
            // 32 ビットモデルは下位 32 ビットで比較する。
            let flag: B::V<W64> = b.get(is64_ref());
            let zero = b.konst::<W64>(0);
            let is64 = b.cmp::<W64>(Cmp::Ne, flag, zero);
            let xm = mask32(b, x);
            let ym = mask32(b, y);
            let xsel = b.select::<W64>(is64, x, xm);
            let ysel = b.select::<W64>(is64, y, ym);
            b.cmp::<W64>(op, xsel, ysel)
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

/// branch-likely の共通処理。成立すれば遅延スロットを実行して target へ、
/// 不成立なら遅延スロットを無効化して pc+8 へ進む。
/// `link` が立つ *all 形式は成立・不成立にかかわらず ra=pc+8 にリンクする。
fn likely_delay<B: Backend>(b: &mut B, pc: u64, disp: i32, take: B::B, link: bool) -> Flow<B> {
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
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
    let flag = b.select::<W64>(take, zero, one);
    b.set(nullify_ref(), flag);
    Ok(())
}

/// BEQL。不成立なら遅延スロットを無効化する。
pub fn beql_delay<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_regs(b, Cmp::Eq, rs, rt);
    likely_delay(b, pc, disp, take, false)
}

/// BNEL。
pub fn bnel_delay<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_regs(b, Cmp::Ne, rs, rt);
    likely_delay(b, pc, disp, take, false)
}

/// BLEZL。rs<=0 で成立。
pub fn blezl_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::LeS, rs);
    likely_delay(b, pc, disp, take, false)
}

/// BGTZL。rs>0 で成立。
pub fn bgtzl_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::GtS, rs);
    likely_delay(b, pc, disp, take, false)
}

/// BLTZL。
pub fn bltzl_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::LtS, rs);
    likely_delay(b, pc, disp, take, false)
}

/// BGEZL。
pub fn bgezl_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::GeS, rs);
    likely_delay(b, pc, disp, take, false)
}

/// BLTZALL。成立・不成立にかかわらずリンクする。
pub fn bltzall_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::LtS, rs);
    likely_delay(b, pc, disp, take, true)
}

/// BGEZALL。
pub fn bgezall_delay<B: Backend>(b: &mut B, rs: Gpr, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::GeS, rs);
    likely_delay(b, pc, disp, take, true)
}

/// JR。32 ビットモデルでは飛び先は rs の下位 32 ビットを語境界に揃えた値、
/// 64 ビットモデルでは rs 全体を語境界に揃えた値。
pub fn jr_delay<B: Backend>(b: &mut B, rs: Gpr, is64: bool) -> Flow<B> {
    let dest = read(b, rs);
    let dest = if is64 { dest } else { mask32(b, dest) };
    let align = b.konst::<W64>(if is64 {
        0xffff_ffff_ffff_fffc
    } else {
        0xffff_fffc
    });
    let target = b.and::<W64>(dest, align);
    b.set(npc_ref(), target);
    Ok(())
}

/// JALR。リンクは pc+8。飛び先は書き込み前の rs を語境界に揃えた値。
/// `is64` では rs 全体を使う。
pub fn jalr_delay<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, pc: u64, is64: bool) -> Flow<B> {
    let dest = read(b, rs);
    let dest = if is64 { dest } else { mask32(b, dest) };
    let align = b.konst::<W64>(if is64 {
        0xffff_ffff_ffff_fffc
    } else {
        0xffff_fffc
    });
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
    let wide = mask32(b, wide);
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
    let wide = mask32(b, wide);
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
    let align = b.konst::<W64>(0xffff_ffff_ffff_fffc);
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

// ---- MIPS32r2 / MIPS64 / Release 6 の追加命令 ----
// 符号化の根拠は SPEC-MIPS32R2・SPEC-MIPS64・SPEC-MIPS-R6。
// 32 ビット命令の結果は MIPS64 の規則どおり符号拡張する。
// Ref: SPEC-MIPS-IV (Rev 3.2).
// Ref: SPEC-MIPS-R6 (Rev 6.06).

/// NOP。
pub fn nop<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// MOVZ rd,rs,rt。
pub fn movz<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::Eq, y, zero);
    let x = read(b, rs);
    let old = read(b, rd);
    let v = b.select::<W64>(take, x, old);
    write(b, rd, v);
    Ok(())
}

/// MOVN rd,rs,rt。
pub fn movn<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::Ne, y, zero);
    let x = read(b, rs);
    let old = read(b, rd);
    let v = b.select::<W64>(take, x, old);
    write(b, rd, v);
    Ok(())
}

/// MUL rd,rs,rt（SPECIAL2/R6 共通）。下位 32 ビットを符号拡張。HI/LO は変えない。
pub fn mul<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let p = b.mul::<W64>(x, y);
    let v = sext32(b, p);
    write(b, rd, v);
    Ok(())
}

/// MADD rs,rt。
pub fn madd<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    madd_inner(b, rs, rt, false, false)
}

/// MADDU。
pub fn maddu<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    madd_inner(b, rs, rt, false, true)
}

/// MSUB。
pub fn msub<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    madd_inner(b, rs, rt, true, false)
}

/// MSUBU。
pub fn msubu<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    madd_inner(b, rs, rt, true, true)
}

fn madd_inner<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, negate: bool, unsigned: bool) -> Flow<B> {
    let xr = read(b, rs);
    let xw: B::V<W32> = b.trunc::<W64, W32>(xr);
    let x: B::V<W64> = if unsigned {
        b.zext::<W32, W64>(xw)
    } else {
        b.sext::<W32, W64>(xw)
    };
    let yr = read(b, rt);
    let yw: B::V<W32> = b.trunc::<W64, W32>(yr);
    let y: B::V<W64> = if unsigned {
        b.zext::<W32, W64>(yw)
    } else {
        b.sext::<W32, W64>(yw)
    };
    let p = b.mul::<W64>(x, y);
    let hi: B::V<W64> = b.get(hi_ref());
    let lo: B::V<W64> = b.get(lo_ref());
    let k32 = b.konst::<W64>(32);
    let hi_sh = b.shl::<W64>(hi, k32);
    let lo_w: B::V<W32> = b.trunc::<W64, W32>(lo);
    let lo_z = b.zext::<W32, W64>(lo_w);
    let acc = b.or::<W64>(hi_sh, lo_z);
    let sum = if negate {
        b.sub::<W64>(acc, p)
    } else {
        b.add::<W64>(acc, p)
    };
    let new_hi_raw = b.shr_l::<W64>(sum, k32);
    let new_lo_w: B::V<W32> = b.trunc::<W64, W32>(sum);
    let new_hi = sext32(b, new_hi_raw);
    let new_lo = b.sext::<W32, W64>(new_lo_w);
    b.set(hi_ref(), new_hi);
    b.set(lo_ref(), new_lo);
    Ok(())
}

/// CLZ rd,rs。
pub fn clz<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr) -> Flow<B> {
    cl_inner(b, rd, rs, true, false)
}

/// CLO rd,rs。
pub fn clo<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr) -> Flow<B> {
    cl_inner(b, rd, rs, false, false)
}

/// DCLZ rd,rs。
pub fn dclz<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr) -> Flow<B> {
    cl_inner(b, rd, rs, true, true)
}

/// DCLO rd,rs。
pub fn dclo<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr) -> Flow<B> {
    cl_inner(b, rd, rs, false, true)
}

fn cl_inner<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, zeros: bool, wide: bool) -> Flow<B> {
    if wide {
        let v = read(b, rs);
        let src = if zeros { v } else { b.not::<W64>(v) };
        let c = clz_count::<B, W64>(b, src);
        write(b, rd, c);
    } else {
        let v = read(b, rs);
        let w: B::V<W32> = b.trunc::<W64, W32>(v);
        let src = if zeros { w } else { b.not::<W32>(w) };
        let c = clz_count::<B, W32>(b, src);
        let z = b.zext::<W32, W64>(c);
        write(b, rd, z);
    }
    Ok(())
}

/// 先頭の連続する 0 ビット数を二分探索で数える。src==0 のとき語幅を返す。
fn clz_count<B: Backend, W: Width>(b: &mut B, x0: B::V<W>) -> B::V<W> {
    let bits = (core::mem::size_of::<W::Repr>() * 8) as u64;
    let mut x = x0;
    let zero = b.konst::<W>(W::from_u128(0));
    let mut c = zero;
    let mut sh = bits / 2;
    while sh > 0 {
        let mask = (!0u128) << (bits - sh);
        let m = b.konst::<W>(W::from_u128(mask));
        let top = b.and::<W>(x, m);
        let isz = b.cmp::<W>(Cmp::Eq, top, zero);
        let k = b.konst::<W>(W::from_u128(u128::from(sh)));
        let shifted = b.shl::<W>(x, k);
        x = b.select::<W>(isz, shifted, x);
        let c2 = b.add::<W>(c, k);
        c = b.select::<W>(isz, c2, c);
        sh /= 2;
    }
    c
}

/// SEB rd,rt。
pub fn seb<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr) -> Flow<B> {
    let v = read(b, rt);
    let w: B::V<W32> = b.trunc::<W64, W32>(v);
    let k8 = b.konst::<W32>(0xff);
    let byte = b.and::<W32>(w, k8);
    let k24 = b.konst::<W32>(24);
    let e = b.shl::<W32>(byte, k24);
    let s = b.shr_a::<W32>(e, k24);
    let z = b.sext::<W32, W64>(s);
    write(b, rd, z);
    Ok(())
}

/// SEH rd,rt。
pub fn seh<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr) -> Flow<B> {
    let v = read(b, rt);
    let w: B::V<W32> = b.trunc::<W64, W32>(v);
    let m = b.konst::<W32>(0xffff);
    let h = b.and::<W32>(w, m);
    let k16 = b.konst::<W32>(16);
    let e = b.shl::<W32>(h, k16);
    let s = b.shr_a::<W32>(e, k16);
    let z = b.sext::<W32, W64>(s);
    write(b, rd, z);
    Ok(())
}

/// WSBH rd,rt。各半語内のバイトを入れ替える。
pub fn wsbh<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr) -> Flow<B> {
    let v = read(b, rt);
    let w: B::V<W32> = b.trunc::<W64, W32>(v);
    let m = b.konst::<W32>(0x00ff_00ff);
    let k8 = b.konst::<W32>(8);
    let lo = b.and::<W32>(w, m);
    let up = b.shl::<W32>(lo, k8);
    let down = b.shr_l::<W32>(w, k8);
    let dn = b.and::<W32>(down, m);
    let r = b.or::<W32>(up, dn);
    let z = b.sext::<W32, W64>(r);
    write(b, rd, z);
    Ok(())
}

/// EXT rt,rs,pos,size。`lsb`=位置(10:6)、`msbd`=size-1(15:11)。
pub fn ext<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, lsb: u32, msbd: u32) -> Flow<B> {
    let size = u64::from(msbd) + 1;
    let mask: u64 = if size >= 32 {
        0xffff_ffff
    } else {
        (1u64 << size) - 1
    };
    let v = read(b, rs);
    let n = b.konst::<W64>(u64::from(lsb));
    let sh = b.shr_l::<W64>(v, n);
    let mk = b.konst::<W64>(mask);
    let m = b.and::<W64>(sh, mk);
    let z = sext32(b, m);
    write(b, rt, z);
    Ok(())
}

/// INS rt,rs,pos,size。`lsb`=位置(10:6)、`msb`=pos+size-1(15:11)。
pub fn ins<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, lsb: u32, msb: u32) -> Flow<B> {
    let size = u64::from(msb) + 1 - u64::from(lsb);
    let mask: u64 = if size >= 32 {
        0xffff_ffff
    } else {
        (1u64 << size) - 1
    };
    let src = read(b, rs);
    let mk = b.konst::<W64>(mask);
    let field = b.and::<W64>(src, mk);
    let n = b.konst::<W64>(u64::from(lsb));
    let shifted = b.shl::<W64>(field, n);
    let keep: u64 = !(mask << lsb) & 0xffff_ffff;
    let old = read(b, rt);
    let kk = b.konst::<W64>(keep);
    let kept = b.and::<W64>(old, kk);
    let merged = b.or::<W64>(kept, shifted);
    let z = sext32(b, merged);
    write(b, rt, z);
    Ok(())
}

/// RDHWR rt,rd。ユーザーの HW レジスタを読む。
/// rd=0〜3 は HWREna 対応の hwr[rd]、rd=29 は ULR（TLS ポインタ）で、
/// `set_thread_area` が hwr[3] に置く値を返す。rd=30/31 は 0 を返す。
pub fn rdhwr<B: Backend>(b: &mut B, rt: Gpr, rd: u32) -> Flow<B> {
    let raw: B::V<W64> = match rd {
        0..=3 => b.get(hwr_ref(rd as u8)),
        // $29 (ULR) は TLS ポインタ。64 ビットモデルでは全幅で返す。
        29 => b.get(hwr_ref(3)),
        _ => b.konst::<W64>(0),
    };
    let v = if rd <= 3 { sext32(b, raw) } else { raw };
    write(b, rt, v);
    Ok(())
}

/// SYNC。インタプリタは逐次なので順序づけだけが残り、何もしない。
pub fn sync<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// PREF。プリフェッチは性能ヒントなので何もしない。
pub fn pref<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// LL rt,off(rs)。排他制御は持たずロードとして振る舞う。
pub fn ll<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    lw_endian(b, rt, rs, imm, endian)
}

/// SC rt,off(rs)。ストアして rt に 1 を返す（単一スレッドなので常に成功）。
pub fn sc<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = read(b, rt);
    let w: B::V<W32> = b.trunc::<W64, W32>(v);
    b.store::<W32>(addr, w, word_write(endian))?;
    let one = const_w64(b, 1);
    write(b, rt, one);
    Ok(())
}

/// LLE rt,off(rs)。EVA 版 LL。ユーザモードでは LL と同義。
pub fn lle<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    ll(b, rt, rs, imm, endian)
}

/// SCE rt,off(rs)。EVA 版 SC。ユーザモードでは SC と同義。
pub fn sce<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    sc(b, rt, rs, imm, endian)
}

/// LLWP rt,rd,(rs)。語対の排他ロード。オフセットはなく、
/// rt に下位語、rd に上位語を 32 ビット符号拡張で書く。
/// 排他制御は持たずロードとして振る舞う。
pub fn llwp<B: Backend>(b: &mut B, rt: Gpr, rd: Gpr, rs: Gpr, endian: Endian) -> Flow<B> {
    let addr = read(b, rs);
    let v: B::V<W64> = b.load::<W64>(addr, word_read(endian))?;
    let lo: B::V<W32> = b.trunc::<W64, W32>(v);
    let shift = b.konst::<W64>(32);
    let hi64 = b.shr_l::<W64>(v, shift);
    let hi: B::V<W32> = b.trunc::<W64, W32>(hi64);
    let rt_v = b.sext::<W32, W64>(lo);
    let rd_v = b.sext::<W32, W64>(hi);
    write(b, rt, rt_v);
    write(b, rd, rd_v);
    Ok(())
}

/// SCWP rt,rd,(rs)。語対の排他ストア。{rt,rd} の下位 32 ビットを
/// 語対として書き、rt に 1 を返す（単一スレッドなので常に成功）。
pub fn scwp<B: Backend>(b: &mut B, rt: Gpr, rd: Gpr, rs: Gpr, endian: Endian) -> Flow<B> {
    let addr = read(b, rs);
    let rt_v = read(b, rt);
    let rd_v = read(b, rd);
    let lo32: B::V<W32> = b.trunc::<W64, W32>(rt_v);
    let hi32: B::V<W32> = b.trunc::<W64, W32>(rd_v);
    let lo: B::V<W64> = b.zext::<W32, W64>(lo32);
    let hi: B::V<W64> = b.zext::<W32, W64>(hi32);
    let shift = b.konst::<W64>(32);
    let hi_sh = b.shl::<W64>(hi, shift);
    let v = b.or::<W64>(lo, hi_sh);
    b.store::<W64>(addr, v, word_write(endian))?;
    let one = const_w64(b, 1);
    write(b, rt, one);
    Ok(())
}

/// TEQ rs,rt。等しければトラップ。
pub fn teq<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let eq = b.cmp::<W64>(Cmp::Eq, x, y);
    b.if_then(eq, |b| raise_trap(b))
}

// ---- MIPS64 ----

/// DADDU rd,rs,rt。
pub fn daddu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.add::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// DSUBU rd,rs,rt。
pub fn dsubu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.sub::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// DADD rd,rs,rt。64 ビットの符号付き溢れはトラップ。
pub fn dadd<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let s = b.add::<W64>(x, y);
    doverflow(b, x, y, s, false)?;
    write(b, rd, s);
    Ok(())
}

/// DSUB rd,rs,rt。
pub fn dsub<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let d = b.sub::<W64>(x, y);
    doverflow(b, x, y, d, true)?;
    write(b, rd, d);
    Ok(())
}

fn doverflow<B: Backend>(
    b: &mut B,
    x: B::V<W64>,
    y: B::V<W64>,
    r: B::V<W64>,
    sub: bool,
) -> Flow<B> {
    let sign = b.konst::<W64>(0x8000_0000_0000_0000);
    let sx = b.and::<W64>(x, sign);
    let sy = b.and::<W64>(y, sign);
    let ss = b.and::<W64>(r, sign);
    let pre = if sub {
        b.cmp::<W64>(Cmp::Ne, sx, sy)
    } else {
        b.cmp::<W64>(Cmp::Eq, sx, sy)
    };
    let post = b.cmp::<W64>(Cmp::Ne, sx, ss);
    b.if_then(pre, |b| {
        b.if_then(post, |b| raise_trap(b))?;
        Ok(())
    })
}

/// DADDIU rt,rs,imm。
pub fn daddiu<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.add::<W64>(x, y);
    write(b, rt, v);
    Ok(())
}

/// DMULT rs,rt。HI<-上位、LO<-下位。
pub fn dmult<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let lo = b.mul::<W64>(x, y);
    let hi = b.mulh::<W64>(x, y);
    b.set(hi_ref(), hi);
    b.set(lo_ref(), lo);
    Ok(())
}

/// DMULTU。
pub fn dmultu<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let lo = b.mul::<W64>(x, y);
    let hi = b.mulhu::<W64>(x, y);
    b.set(hi_ref(), hi);
    b.set(lo_ref(), lo);
    Ok(())
}

/// DDIV rs,rt。LO<-商、HI<-剰余。0 除算は div_zero_writes_zero に従う。
pub fn ddiv<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    ddiv_inner(b, rs, rt, false)
}

/// DDIVU。
pub fn ddivu<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> Flow<B> {
    ddiv_inner(b, rs, rt, true)
}

fn ddiv_inner<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, unsigned: bool) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let dz = b.cmp::<W64>(Cmp::Eq, y, zero);
    b.if_then(dz, |b| {
        let flag: B::V<W64> = b.get(div_zero_writes_zero_ref());
        let z0 = b.konst::<W64>(0);
        let nz = b.cmp::<W64>(Cmp::Ne, flag, z0);
        b.if_then(nz, |b| {
            let z = b.konst::<W64>(0);
            b.set(hi_ref(), z);
            b.set(lo_ref(), z);
            Ok(())
        })
    })?;
    let nz = b.cmp::<W64>(Cmp::Ne, y, zero);
    b.if_then(nz, |b| {
        let (q, r) = if unsigned {
            (b.udiv::<W64>(x, y), b.urem::<W64>(x, y))
        } else {
            (b.sdiv::<W64>(x, y), b.srem::<W64>(x, y))
        };
        b.set(lo_ref(), q);
        b.set(hi_ref(), r);
        Ok(())
    })
}

/// DSLL rd,rt,sa。
pub fn dsll<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    dshift_imm(b, rd, rt, sa, Shift::Left)
}

/// DSRL rd,rt,sa。
pub fn dsrl<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    dshift_imm(b, rd, rt, sa, Shift::RightL)
}

/// DSRA rd,rt,sa。
pub fn dsra<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    dshift_imm(b, rd, rt, sa, Shift::RightA)
}

/// DSLL32 rd,rt,sa（sa+32）。
pub fn dsll32<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    dshift_imm(b, rd, rt, sa + 32, Shift::Left)
}

/// DSRL32 rd,rt,sa。
pub fn dsrl32<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    dshift_imm(b, rd, rt, sa + 32, Shift::RightL)
}

/// DSRA32 rd,rt,sa。
pub fn dsra32<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    dshift_imm(b, rd, rt, sa + 32, Shift::RightA)
}

/// DSLLV rd,rt,rs。
pub fn dsllv<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, rs: Gpr) -> Flow<B> {
    dshift_var(b, rd, rt, rs, Shift::Left)
}

/// DSRLV。
pub fn dsrlv<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, rs: Gpr) -> Flow<B> {
    dshift_var(b, rd, rt, rs, Shift::RightL)
}

/// DSRAV。
pub fn dsrav<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, rs: Gpr) -> Flow<B> {
    dshift_var(b, rd, rt, rs, Shift::RightA)
}

enum Shift {
    Left,
    RightL,
    RightA,
}

fn dshift_imm<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, sa: u32, dir: Shift) -> Flow<B> {
    let v = read(b, rt);
    let n = b.konst::<W64>(u64::from(sa));
    let r = match dir {
        Shift::Left => b.shl::<W64>(v, n),
        Shift::RightL => b.shr_l::<W64>(v, n),
        Shift::RightA => b.shr_a::<W64>(v, n),
    };
    write(b, rd, r);
    Ok(())
}

fn dshift_var<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr, rs: Gpr, dir: Shift) -> Flow<B> {
    let v = read(b, rt);
    let s = read(b, rs);
    let m = b.konst::<W64>(63);
    let n = b.and::<W64>(s, m);
    let r = match dir {
        Shift::Left => b.shl::<W64>(v, n),
        Shift::RightL => b.shr_l::<W64>(v, n),
        Shift::RightA => b.shr_a::<W64>(v, n),
    };
    write(b, rd, r);
    Ok(())
}

/// LD rt,off(rs)。
pub fn ld<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = b.load::<W64>(addr, word_read(endian))?;
    write(b, rt, v);
    Ok(())
}

/// LWU rt,off(rs)。
pub fn lwu<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W32> = b.load::<W32>(addr, word_read(endian))?;
    let z = b.zext::<W32, W64>(v);
    write(b, rt, z);
    Ok(())
}

/// LLD。
pub fn lld<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    ld(b, rt, rs, imm, endian)
}

/// SCD。ストアして rt に 1 を返す。
pub fn scd<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = read(b, rt);
    b.store::<W64>(addr, v, word_write(endian))?;
    let one = const_w64(b, 1);
    write(b, rt, one);
    Ok(())
}

/// SD rt,off(rs)。
pub fn sd<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = read(b, rt);
    b.store::<W64>(addr, v, word_write(endian))?;
    Ok(())
}

/// LDL/LDR/SDR/SDL。部分レジスタ結合の非整列アクセス。
/// 現在は非整列幅全体アクセスとして近似する（精度の上限はメモ参照）。
pub fn ldl<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    ld_unaligned(b, rt, rs, imm, endian)
}

/// LDR。
pub fn ldr<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    ld_unaligned(b, rt, rs, imm, endian)
}

fn ld_unaligned<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let ac = Access {
        endian,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    };
    let v: B::V<W64> = b.load::<W64>(addr, ac)?;
    write(b, rt, v);
    Ok(())
}

/// SDL。
pub fn sdl<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    sd_unaligned(b, rt, rs, imm, endian)
}

/// SDR。
pub fn sdr<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    sd_unaligned(b, rt, rs, imm, endian)
}

fn sd_unaligned<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32, endian: Endian) -> Flow<B> {
    let base = read(b, rs);
    let off = b.konst::<W64>(imm as i64 as u64);
    let addr = b.add::<W64>(base, off);
    let ac = Access {
        endian,
        align: Align::Unaligned,
        kind: AccessKind::DataWrite,
    };
    let v: B::V<W64> = read(b, rt);
    b.store::<W64>(addr, v, ac)?;
    Ok(())
}

/// DEXT rt,rs,pos,size。
pub fn dext<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, lsb: u32, msbd: u32) -> Flow<B> {
    let size = u64::from(msbd) + 1;
    let mask: u64 = if size >= 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    };
    let v = read(b, rs);
    let n = b.konst::<W64>(u64::from(lsb));
    let sh = b.shr_l::<W64>(v, n);
    let mk = b.konst::<W64>(mask);
    let m = b.and::<W64>(sh, mk);
    write(b, rt, m);
    Ok(())
}

/// DINS rt,rs,pos,size。
pub fn dins<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, lsb: u32, msb: u32) -> Flow<B> {
    let size = u64::from(msb) + 1 - u64::from(lsb);
    let mask: u64 = if size >= 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    };
    let src = read(b, rs);
    let mk = b.konst::<W64>(mask);
    let field = b.and::<W64>(src, mk);
    let n = b.konst::<W64>(u64::from(lsb));
    let shifted = b.shl::<W64>(field, n);
    let keep: u64 = !(mask << lsb);
    let old = read(b, rt);
    let kk = b.konst::<W64>(keep);
    let kept = b.and::<W64>(old, kk);
    let merged = b.or::<W64>(kept, shifted);
    write(b, rt, merged);
    Ok(())
}

/// DSBH rd,rt。各半語内のバイトを入れ替える。
pub fn dsbh<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr) -> Flow<B> {
    let v = read(b, rt);
    let m = b.konst::<W64>(0x00ff_00ff_00ff_00ff);
    let k8 = b.konst::<W64>(8);
    let lo = b.and::<W64>(v, m);
    let up = b.shl::<W64>(lo, k8);
    let down = b.shr_l::<W64>(v, k8);
    let dn = b.and::<W64>(down, m);
    let r = b.or::<W64>(up, dn);
    write(b, rd, r);
    Ok(())
}

/// DSHD rd,rt。各 32 ビット語内で半語を入れ替える。
pub fn dshd<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr) -> Flow<B> {
    let v = read(b, rt);
    let m = b.konst::<W64>(0x0000_ffff_0000_ffff);
    let k16 = b.konst::<W64>(16);
    let lo = b.and::<W64>(v, m);
    let up = b.shl::<W64>(lo, k16);
    let down = b.shr_l::<W64>(v, k16);
    let dn = b.and::<W64>(down, m);
    let r = b.or::<W64>(up, dn);
    write(b, rd, r);
    Ok(())
}

// ---- Release 6 ----

/// SELEQZ rd,rs,rt。
pub fn seleqz<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::Eq, y, zero);
    let x = read(b, rs);
    let z = b.konst::<W64>(0);
    let v = b.select::<W64>(take, x, z);
    write(b, rd, v);
    Ok(())
}

/// SELNEZ。
pub fn selnez<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::Ne, y, zero);
    let x = read(b, rs);
    let z = b.konst::<W64>(0);
    let v = b.select::<W64>(take, x, z);
    write(b, rd, v);
    Ok(())
}

/// MULU（R6）。
pub fn mulu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    mul(b, rd, rs, rt)
}

/// MUH rd,rs,rt。符号付き積の上位 32 ビット。
pub fn muh<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    muh_inner(b, rd, rs, rt, false, false)
}

/// MUHU。
pub fn muhu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    muh_inner(b, rd, rs, rt, false, true)
}

/// DMUL。
pub fn dmul<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.mul::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// DMULU。
pub fn dmulu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    dmul(b, rd, rs, rt)
}

/// DMUH。
pub fn dmuh<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.mulh::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

/// DMUHU。
pub fn dmuhu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let v = b.mulhu::<W64>(x, y);
    write(b, rd, v);
    Ok(())
}

fn muh_inner<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs: Gpr,
    rt: Gpr,
    wide: bool,
    unsigned: bool,
) -> Flow<B> {
    let xr = read(b, rs);
    let xw: B::V<W32> = b.trunc::<W64, W32>(xr);
    let x: B::V<W64> = if wide { xr } else { b.sext::<W32, W64>(xw) };
    let yr = read(b, rt);
    let yw: B::V<W32> = b.trunc::<W64, W32>(yr);
    let y: B::V<W64> = if wide { yr } else { b.sext::<W32, W64>(yw) };
    let hi = if unsigned {
        b.mulhu::<W64>(x, y)
    } else {
        b.mulh::<W64>(x, y)
    };
    let r = if wide { hi } else { sext32(b, hi) };
    write(b, rd, r);
    Ok(())
}

/// DIV（R6）rd,rs,rt。0 除算の結果は未定義（アーキテクチャが結果を規定しない）。
pub fn div_r6<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, false, false, false)
}

/// MOD。
pub fn mod_<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, true, false, false)
}

/// DIVU（R6）。
pub fn divu_r6<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, false, true, false)
}

/// MODU。
pub fn modu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, true, true, false)
}

/// DDIV（R6）。
pub fn ddiv_r6<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, false, false, true)
}

/// DMOD。
pub fn dmod<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, true, false, true)
}

/// DDIVU（R6）。
pub fn ddivu_r6<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, false, true, true)
}

/// DMODU。
pub fn dmodu<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr) -> Flow<B> {
    r6_div(b, rd, rs, rt, true, true, true)
}

fn r6_div<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs: Gpr,
    rt: Gpr,
    rem: bool,
    unsigned: bool,
    wide: bool,
) -> Flow<B> {
    let xr = read(b, rs);
    let xw: B::V<W32> = b.trunc::<W64, W32>(xr);
    let x: B::V<W64> = if wide { xr } else { b.sext::<W32, W64>(xw) };
    let yr = read(b, rt);
    let yw: B::V<W32> = b.trunc::<W64, W32>(yr);
    let y: B::V<W64> = if wide { yr } else { b.sext::<W32, W64>(yw) };
    let r = match (rem, unsigned) {
        (false, false) => b.sdiv::<W64>(x, y),
        (true, false) => b.srem::<W64>(x, y),
        (false, true) => b.udiv::<W64>(x, y),
        (true, true) => b.urem::<W64>(x, y),
    };
    let out = if wide { r } else { sext32(b, r) };
    write(b, rd, out);
    Ok(())
}

/// LSA rd,rs,rt,sa。rd <- (rs << sa) + rt。sa は実シフト量（符号化値+1 は呼び出し側）。
pub fn lsa<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    let x = read(b, rs);
    let n = b.konst::<W64>(u64::from(sa));
    let sh = b.shl::<W64>(x, n);
    let y = read(b, rt);
    let v = b.add::<W64>(sh, y);
    let z = sext32(b, v);
    write(b, rd, z);
    Ok(())
}

/// DLSA。
pub fn dlsa<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr, sa: u32) -> Flow<B> {
    let x = read(b, rs);
    let n = b.konst::<W64>(u64::from(sa));
    let sh = b.shl::<W64>(x, n);
    let y = read(b, rt);
    let v = b.add::<W64>(sh, y);
    write(b, rd, v);
    Ok(())
}

/// AUIPC rd,imm16。rd <- pc + (imm16 << 16)。
pub fn auipc<B: Backend>(b: &mut B, rd: Gpr, imm: i32, pc: u64) -> Flow<B> {
    let off = (imm as i64 as u64) << 16;
    let a = const_w64(b, pc.wrapping_add(off));
    let z = sext32(b, a);
    write(b, rd, z);
    Ok(())
}

/// ALUIPC rd,imm16。rd <- (pc + (imm16 << 16)) & ~0xffff。
pub fn aluipc<B: Backend>(b: &mut B, rd: Gpr, imm: i32, pc: u64) -> Flow<B> {
    let off = (imm as i64 as u64) << 16;
    let a = pc.wrapping_add(off) & !0xffffu64;
    let v = const_w64(b, a);
    let z = sext32(b, v);
    write(b, rd, z);
    Ok(())
}

/// ADDIUPC rd,imm19。rd <- pc + (imm19 << 2)。
pub fn addiupc<B: Backend>(b: &mut B, rd: Gpr, imm: i32, pc: u64) -> Flow<B> {
    let off = (imm as i64 as u64) << 2;
    let a = const_w64(b, pc.wrapping_add(off));
    let z = sext32(b, a);
    write(b, rd, z);
    Ok(())
}

/// LWPC rt,off19。pc 相対の 32 ビットロード。
pub fn lwpc<B: Backend>(b: &mut B, rt: Gpr, imm19: u32, endian: Endian, pc: u64) -> Flow<B> {
    let off = (((imm19 as i32) << 13) >> 13) as i64 as u64;
    let addr = pc.wrapping_add(off << 2).wrapping_add(4);
    let a = const_w64(b, addr);
    let v: B::V<W32> = b.load::<W32>(a, word_read(endian))?;
    let z = b.sext::<W32, W64>(v);
    write(b, rt, z);
    Ok(())
}

/// LWUPC。ゼロ拡張版。
pub fn lwupc<B: Backend>(b: &mut B, rt: Gpr, imm19: u32, endian: Endian, pc: u64) -> Flow<B> {
    let off = (((imm19 as i32) << 13) >> 13) as i64 as u64;
    let addr = pc.wrapping_add(off << 2).wrapping_add(4);
    let a = const_w64(b, addr);
    let v: B::V<W32> = b.load::<W32>(a, word_read(endian))?;
    let z = b.zext::<W32, W64>(v);
    write(b, rt, z);
    Ok(())
}

/// LDPC rt,off18。pc 相対の 64 ビットロード。
pub fn ldpc<B: Backend>(b: &mut B, rt: Gpr, imm18: u32, endian: Endian, pc: u64) -> Flow<B> {
    let off = (((imm18 as i32) << 14) >> 14) as i64 as u64;
    let addr = pc.wrapping_add(off << 3).wrapping_add(4);
    let a = const_w64(b, addr);
    let v: B::V<W64> = b.load::<W64>(a, word_read(endian))?;
    write(b, rt, v);
    Ok(())
}

/// ALIGN rd,rs,rt,bp。{rs:rt} を右に 8*bp シフトし下位 32 ビットを取る。bp=0 は rd<-rt。
pub fn align<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr, bp: u32) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    if bp == 0 {
        let z = sext32(b, y);
        write(b, rd, z);
        return Ok(());
    }
    let k = u64::from(bp) * 8;
    let n1 = b.konst::<W64>(k);
    let down = b.shr_l::<W64>(y, n1);
    let n2 = b.konst::<W64>(32 - k);
    let up = b.shl::<W64>(x, n2);
    let v = b.or::<W64>(down, up);
    let z = sext32(b, v);
    write(b, rd, z);
    Ok(())
}

/// DALIGN rd,rs,rt,bp。{rs:rt} を右に 8*bp シフトし下位 64 ビットを取る。bp=0 は rd<-rt。
pub fn dalign<B: Backend>(b: &mut B, rd: Gpr, rs: Gpr, rt: Gpr, bp: u32) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let bp = bp & 7;
    if bp == 0 {
        write(b, rd, y);
        return Ok(());
    }
    let k = u64::from(bp) * 8;
    let n1 = b.konst::<W64>(k);
    let down = b.shr_l::<W64>(y, n1);
    let n2 = b.konst::<W64>(64 - k);
    let up = b.shl::<W64>(x, n2);
    let v = b.or::<W64>(down, up);
    write(b, rd, v);
    Ok(())
}

/// BITSWAP rd,rt。各バイト内のビット順を反転する。
pub fn bitswap<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr) -> Flow<B> {
    let v = read(b, rt);
    let w: B::V<W32> = b.trunc::<W64, W32>(v);
    let r = bswap_bits32(b, w);
    let z = b.sext::<W32, W64>(r);
    write(b, rd, z);
    Ok(())
}

/// DBITSWAP。
pub fn dbitswap<B: Backend>(b: &mut B, rd: Gpr, rt: Gpr) -> Flow<B> {
    let v = read(b, rt);
    let lo: B::V<W32> = b.trunc::<W64, W32>(v);
    let k32 = b.konst::<W64>(32);
    let hv = b.shr_l::<W64>(v, k32);
    let hi: B::V<W32> = b.trunc::<W64, W32>(hv);
    let l = bswap_bits32(b, lo);
    let h = bswap_bits32(b, hi);
    let lz = b.zext::<W32, W64>(l);
    let hz = b.zext::<W32, W64>(h);
    let hs = b.shl::<W64>(hz, k32);
    let r = b.or::<W64>(hs, lz);
    write(b, rd, r);
    Ok(())
}

fn bswap_bits32<B: Backend>(b: &mut B, w: B::V<W32>) -> B::V<W32> {
    let m1 = b.konst::<W32>(0x5555_5555);
    let m2 = b.konst::<W32>(0x3333_3333);
    let m4 = b.konst::<W32>(0x0f0f_0f0f);
    let k1 = b.konst::<W32>(1);
    let k2 = b.konst::<W32>(2);
    let k4 = b.konst::<W32>(4);
    let a1 = b.and::<W32>(w, m1);
    let a2 = b.shl::<W32>(a1, k1);
    let n1 = b.not::<W32>(m1);
    let a3 = b.and::<W32>(w, n1);
    let a4 = b.shr_l::<W32>(a3, k1);
    let a = b.or::<W32>(a2, a4);
    let c1 = b.and::<W32>(a, m2);
    let c2 = b.shl::<W32>(c1, k2);
    let n2 = b.not::<W32>(m2);
    let c3 = b.and::<W32>(a, n2);
    let c4 = b.shr_l::<W32>(c3, k2);
    let c = b.or::<W32>(c2, c4);
    let e1 = b.and::<W32>(c, m4);
    let e2 = b.shl::<W32>(e1, k4);
    let n3 = b.not::<W32>(m4);
    let e3 = b.and::<W32>(c, n3);
    let e4 = b.shr_l::<W32>(e3, k4);
    b.or::<W32>(e2, e4)
}

/// BC off26。遅延スロットなしの無条件分岐。pc を直接書き換える。
pub fn bc<B: Backend>(b: &mut B, target: u64) -> Flow<B> {
    let t = const_w64(b, target);
    b.set(pc_ref(), t);
    Ok(())
}

/// BALC off26。リンク（pc+4）して飛ぶ。
pub fn balc<B: Backend>(b: &mut B, pc: u64, target: u64) -> Flow<B> {
    let l = const_w64(b, pc.wrapping_add(4));
    write(b, Gpr(31), l);
    let t = const_w64(b, target);
    b.set(pc_ref(), t);
    Ok(())
}

/// JIC rt,off。遅延スロットなしのレジスタジャンプ（pc<-rt+off）。
pub fn jic<B: Backend>(b: &mut B, rt: Gpr, off: i32) -> Flow<B> {
    let v = read(b, rt);
    let o = b.konst::<W64>(off as i64 as u64);
    let t = b.add::<W64>(v, o);
    b.set(pc_ref(), t);
    Ok(())
}

/// JIALC rt,off。リンクして飛ぶ。
pub fn jialc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, off: i32) -> Flow<B> {
    let l = const_w64(b, pc.wrapping_add(4));
    write(b, Gpr(31), l);
    let v = read(b, rt);
    let o = b.konst::<W64>(off as i64 as u64);
    let t = b.add::<W64>(v, o);
    b.set(pc_ref(), t);
    Ok(())
}

/// BEQZC rs,off21。遅延スロットなし。rs==0 で飛ぶ。
pub fn beqzc<B: Backend>(b: &mut B, rs: Gpr, pc: u64, target: u64) -> Flow<B> {
    let v = read(b, rs);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::Eq, v, zero);
    let fall = const_w64(b, pc.wrapping_add(4));
    let t = const_w64(b, target);
    let n = b.select::<W64>(take, t, fall);
    b.set(pc_ref(), n);
    Ok(())
}

/// BNEZC。
pub fn bnezc<B: Backend>(b: &mut B, rs: Gpr, pc: u64, target: u64) -> Flow<B> {
    let v = read(b, rs);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::Ne, v, zero);
    let fall = const_w64(b, pc.wrapping_add(4));
    let t = const_w64(b, target);
    let n = b.select::<W64>(take, t, fall);
    b.set(pc_ref(), n);
    Ok(())
}

/// DADDI rt,rs,imm。64 ビットの符号付き溢れはトラップ。
pub fn daddi<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let y = b.konst::<W64>(imm as i64 as u64);
    let s = b.add::<W64>(x, y);
    doverflow(b, x, y, s, false)?;
    write(b, rt, s);
    Ok(())
}

// ---- R6 のコンパクト分岐（比較・リンク・ゼロ比較）----
// フィールド値の分解（rs==0 / rs==rt / rs<rt 等）はデコードで保証される。
// pc に次の実行先を直接置き、npc は変えない（step が npc=pc+4 を張る）。
// Ref: SPEC-MIPS-R6 (Rev 6.06).

/// 条件 take なら target、不成立なら pc+4。link は無条件に $31=pc+4。
fn cbranch<B: Backend>(b: &mut B, take: B::B, pc: u64, target: u64, link: bool) -> Flow<B> {
    let fall = const_w64(b, pc.wrapping_add(4));
    if link {
        write(b, Gpr(31), fall);
    }
    let t = const_w64(b, target);
    let n = b.select::<W64>(take, t, fall);
    b.set(pc_ref(), n);
    Ok(())
}

/// BEQC。rs==rt で飛ぶ。
pub fn beqc<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let take = b.cmp::<W64>(Cmp::Eq, x, y);
    cbranch(b, take, pc, target, false)
}

/// BNEC。rs!=rt で飛ぶ。
pub fn bnec<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let take = b.cmp::<W64>(Cmp::Ne, x, y);
    cbranch(b, take, pc, target, false)
}

/// 32 ビット加算の符号付き溢れ。低 32 ビットの和が i32 に収まらなければ真。
fn ovf32<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr) -> B::B {
    let x = read(b, rs);
    let y = read(b, rt);
    let sx = sext32(b, x);
    let sy = sext32(b, y);
    let ss = b.add::<W64>(sx, sy);
    let back = sext32(b, ss);
    b.cmp::<W64>(Cmp::Ne, ss, back)
}

/// BOVC。rs+rt が 32 ビット符号付き溢れなら飛ぶ。
pub fn bovc<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let take = ovf32(b, rs, rt);
    cbranch(b, take, pc, target, false)
}

/// BNVC。溢れなければ飛ぶ。
pub fn bnvc<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let sx = sext32(b, x);
    let sy = sext32(b, y);
    let ss = b.add::<W64>(sx, sy);
    let back = sext32(b, ss);
    let take = b.cmp::<W64>(Cmp::Eq, ss, back);
    cbranch(b, take, pc, target, false)
}

/// BNEZALC。rt!=0 でリンクして飛ぶ。
pub fn bnezalc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::Ne, y, zero);
    cbranch(b, take, pc, target, true)
}

/// BLEZALC。rt<=0（符号付き）でリンクして飛ぶ。
pub fn blezalc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::LeS, y, zero);
    cbranch(b, take, pc, target, true)
}

/// BGEZALC。rt>=0 でリンクして飛ぶ。
pub fn bgezalc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::GeS, y, zero);
    cbranch(b, take, pc, target, true)
}

/// BGEUC。rs>=rt（符号なし）で飛ぶ。
pub fn bgeuc<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let take = b.cmp::<W64>(Cmp::GeU, x, y);
    cbranch(b, take, pc, target, false)
}

/// BGTZALC。rt>0 でリンクして飛ぶ。
pub fn bgtzalc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::GtS, y, zero);
    cbranch(b, take, pc, target, true)
}

/// BLTZALC。rt<0 でリンクして飛ぶ。
pub fn bltzalc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::LtS, y, zero);
    cbranch(b, take, pc, target, true)
}

/// BLTUC。rs<rt（符号なし）で飛ぶ。
pub fn bltuc<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let take = b.cmp::<W64>(Cmp::LtU, x, y);
    cbranch(b, take, pc, target, false)
}

/// BLEZC。rt<=0 で飛ぶ。
pub fn blezc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::LeS, y, zero);
    cbranch(b, take, pc, target, false)
}

/// BGEZC。rt>=0 で飛ぶ。
pub fn bgezc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::GeS, y, zero);
    cbranch(b, take, pc, target, false)
}

/// BGEC。rs>=rt（符号付き）で飛ぶ。
pub fn bgec<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let take = b.cmp::<W64>(Cmp::GeS, x, y);
    cbranch(b, take, pc, target, false)
}

/// BGTZC。rt>0 で飛ぶ。
pub fn bgtzc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::GtS, y, zero);
    cbranch(b, take, pc, target, false)
}

/// BLTZC。rt<0 で飛ぶ。
pub fn bltzc<B: Backend>(b: &mut B, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let y = read(b, rt);
    let zero = b.konst::<W64>(0);
    let take = b.cmp::<W64>(Cmp::LtS, y, zero);
    cbranch(b, take, pc, target, false)
}

/// BLTC。rs<rt（符号付き）で飛ぶ。
pub fn bltc<B: Backend>(b: &mut B, rs: Gpr, rt: Gpr, pc: u64, target: u64) -> Flow<B> {
    let x = read(b, rs);
    let y = read(b, rt);
    let take = b.cmp::<W64>(Cmp::LtS, x, y);
    cbranch(b, take, pc, target, false)
}

// ---- R6 の REGIMM 系（NAL/BAL/DAHI/DATI）と上位即値（AUI/DAUI）----
// Ref: SPEC-MIPS-R6 (Rev 6.06).

/// BAL。常に飛ぶリンク分岐（遅延スロット付き）。BGEZAL $0 と同じ意味論。
pub fn bal_delay<B: Backend>(b: &mut B, pc: u64, disp: i32) -> Flow<B> {
    let take = cmp_zero(b, Cmp::GeS, Gpr(0));
    delay_branch(b, pc, disp, take, true)
}

/// NAL。リンクのみ（$31=pc+8）。分岐しない。
pub fn nal<B: Backend>(b: &mut B, pc: u64) -> Flow<B> {
    let linked = const_w64(b, pc.wrapping_add(8));
    write(b, Gpr(31), linked);
    Ok(())
}

/// AUI rt,rs,imm。rt = sext32(rs + sext(imm)<<16)。
pub fn aui<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let y = b.konst::<W64>(((imm as i64) << 16) as u64);
    let s = b.add::<W64>(x, y);
    let s = sext32(b, s);
    write(b, rt, s);
    Ok(())
}

/// DAUI rt,rs,imm。rt = rs + sext(imm)<<16（64 ビット）。
pub fn daui<B: Backend>(b: &mut B, rt: Gpr, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let y = b.konst::<W64>(((imm as i64) << 16) as u64);
    let s = b.add::<W64>(x, y);
    write(b, rt, s);
    Ok(())
}

/// DAHI rs,imm。rs += sext(imm)<<32。
pub fn dahi<B: Backend>(b: &mut B, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let y = b.konst::<W64>(((imm as i64) << 32) as u64);
    let s = b.add::<W64>(x, y);
    write(b, rs, s);
    Ok(())
}

/// DATI rs,imm。rs += sext(imm)<<48。
pub fn dati<B: Backend>(b: &mut B, rs: Gpr, imm: i32) -> Flow<B> {
    let x = read(b, rs);
    let y = b.konst::<W64>(((imm as i64) << 48) as u64);
    let s = b.add::<W64>(x, y);
    write(b, rs, s);
    Ok(())
}

/// SYNCI。命令キャッシュの同期ヒント。ユーザモードでは何もしない。
pub fn synci<B: Backend>(_b: &mut B, _rs: Gpr, _imm: i32) -> Flow<B> {
    Ok(())
}
