// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小の命令意味論。バックエンドに対して総称的に書く.
//!
//! 整数演算と SYSCALL/CPUID の最小形のみ持つ。EFLAGS の更新
//! （遅延フラグは本格実装）、ModRM/SIB、セグメント、64ビット拡張、
//! CPUID の機能導出は本格実装で足す。
//!
//! 出典は SPEC-X86-INTEL-SDM Combined v093 (2026-09-24) である。
//! Ref: SPEC-X86-INTEL-SDM (v093).

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W32, W64, Width};

use super::CpuState;

/// 汎用レジスタ番号。0-7=EAX..EDI、8-15=R8D..R15D である。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// EAX を指す。
    pub fn eax() -> Self {
        Self(0)
    }

    /// CPU 状態の対応する要素を指す。8 以上は拡張レジスタの下位32ビットを指す。
    pub fn state(self) -> StateRef<W32> {
        if self.0 < 8 {
            StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, g) + (self.0 as usize) * 4)
        } else {
            StateRef::<W32>::from_offset(
                core::mem::offset_of!(CpuState, x) + ((self.0 - 8) as usize) * 8,
            )
        }
    }
}

/// eip を指す。
pub fn eip_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, eip))
}

/// eflags を指す。
pub fn eflags_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, eflags))
}

/// 汎用レジスタの上位32ビットを指す（x86-64 用、0-7 のみ）。
pub fn hi_ref(r: Gpr) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, h) + (r.0 as usize) * 4)
}

/// 拡張レジスタ R8-R15 を指す。
pub fn x_ref(r: Gpr) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, x) + ((r.0 - 8) as usize) * 8)
}

/// 64ビットレジスタを読む（0-7 は上位 h と下位 g を結合し、8-15 は x を読む）。
pub fn read64<B: Backend>(b: &mut B, r: Gpr) -> B::V<W64> {
    if r.0 < 8 {
        let lo32 = read(b, r);
        let lo = b.zext::<W32, W64>(lo32);
        let hi32 = b.get(hi_ref(r));
        let hi = b.zext::<W32, W64>(hi32);
        let n = b.konst::<W64>(32);
        let hi_sh = b.shl::<W64>(hi, n);
        b.or::<W64>(hi_sh, lo)
    } else {
        b.get(x_ref(r))
    }
}

/// 64ビットレジスタに書く（0-7 は上位 h と下位 g に分割し、8-15 は x に書く）。
pub fn write64<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W64>) {
    if rd.0 < 8 {
        let lo: B::V<W32> = b.trunc::<W64, W32>(v);
        write(b, rd, lo);
        let n = b.konst::<W64>(32);
        let hi64 = b.shr_l::<W64>(v, n);
        let hi: B::V<W32> = b.trunc::<W64, W32>(hi64);
        b.set(hi_ref(rd), hi);
    } else {
        b.set(x_ref(rd), v);
    }
}

/// 32ビット書き込みのゼロ拡張（x86-64 で下位32ビット書き込みは上位を消す）。
pub fn clear_hi<B: Backend>(b: &mut B, rd: Gpr) {
    if rd.0 < 8 {
        let zero = b.konst::<W32>(0);
        b.set(hi_ref(rd), zero);
    } else {
        let cur: B::V<W64> = b.get(x_ref(rd));
        let mask = b.konst::<W64>(0xffff_ffff);
        let cleared = b.and::<W64>(cur, mask);
        b.set(x_ref(rd), cleared);
    }
}

/// EFLAGS のビット位置（i386）。
const FLAG_CF: u32 = 0x1;
const FLAG_PF: u32 = 0x4;
const FLAG_AF: u32 = 0x10;
const FLAG_ZF: u32 = 0x40;
const FLAG_SF: u32 = 0x80;
const FLAG_OF: u32 = 0x800;
/// ADD/SUB/CMP と論理演算で更新する 6 旗のマスク（遅延評価は本格実装で足す）。
const FLAG_OSZPCA: u32 = FLAG_OF | FLAG_SF | FLAG_ZF | FLAG_AF | FLAG_PF | FLAG_CF;
/// シフトで更新する 5 旗のマスク（AF は不定のため触らない）。
const FLAG_OSZPC: u32 = FLAG_OF | FLAG_SF | FLAG_ZF | FLAG_PF | FLAG_CF;

/// 条件の真偽でビット値（bit / 0）を選ぶ。
fn pick<B: Backend>(b: &mut B, c: B::B, bit: u32) -> B::V<W32> {
    let t = b.konst::<W32>(bit);
    let f = b.konst::<W32>(0);
    b.select::<W32>(c, t, f)
}

/// 低8ビットの偶パリティで PF bit を作る。
fn pf_bit<B: Backend, W: Width>(b: &mut B, v: B::V<W>) -> B::V<W32> {
    let ff = b.konst::<W>(W::from_u128(0xff));
    let mut x = b.and::<W>(v, ff);
    for s in [4u32, 2, 1] {
        let n = b.konst::<W>(W::from_u128(s as u128));
        let y = b.shr_l::<W>(x, n);
        x = b.xor::<W>(x, y);
    }
    let one = b.konst::<W>(W::from_u128(1));
    let x1 = b.and::<W>(x, one);
    let zero = b.konst::<W>(W::from_u128(0));
    let even = b.cmp::<W>(Cmp::Eq, x1, zero);
    pick(b, even, FLAG_PF)
}

/// 結果値から SF/ZF/PF の 3 ビット分を作る。
fn szp_bits<B: Backend, W: Width>(b: &mut B, v: B::V<W>) -> B::V<W32> {
    let top_mask = b.konst::<W>(W::from_u128(1u128 << (W::BITS - 1)));
    let top = b.and::<W>(v, top_mask);
    let zero = b.konst::<W>(W::from_u128(0));
    let sf_take = b.cmp::<W>(Cmp::Ne, top, zero);
    let sf = pick(b, sf_take, FLAG_SF);
    let zf_take = b.cmp::<W>(Cmp::Eq, v, zero);
    let zf = pick(b, zf_take, FLAG_ZF);
    let pf = pf_bit(b, v);
    let t = b.or::<W32>(sf, zf);
    b.or::<W32>(t, pf)
}

/// (x OP y) の補助キャリ（bit4）から AF bit を作る。ADD/SUB/CMP 共通式。
fn af_bit<B: Backend, W: Width>(b: &mut B, x: B::V<W>, y: B::V<W>, v: B::V<W>) -> B::V<W32> {
    let t = b.xor::<W>(x, y);
    let u = b.xor::<W>(t, v);
    let af_mask = b.konst::<W>(W::from_u128(FLAG_AF as u128));
    let nib = b.and::<W>(u, af_mask);
    let zero = b.konst::<W>(W::from_u128(0));
    let take = b.cmp::<W>(Cmp::Ne, nib, zero);
    pick(b, take, FLAG_AF)
}

/// ADD 系の 6 旗を更新する。CF=繰り上がり、OF=符号あふれ。
fn update_add_flags<B: Backend, W: Width>(b: &mut B, x: B::V<W>, y: B::V<W>, v: B::V<W>) {
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W>(W::from_u128(0));
    let cf_take = b.cmp::<W>(Cmp::LtU, v, x);
    let cf = pick(b, cf_take, FLAG_CF);
    let a = b.xor::<W>(x, v);
    let c = b.xor::<W>(y, v);
    let s = b.and::<W>(a, c);
    let n_top = b.konst::<W>(W::from_u128((W::BITS - 1) as u128));
    let s_top = b.shr_l::<W>(s, n_top);
    let of_take = b.cmp::<W>(Cmp::Ne, s_top, zero);
    let of = pick(b, of_take, FLAG_OF);
    let af = af_bit(b, x, y, v);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPCA);
    let mut f = b.and::<W32>(old, clear_mask);
    f = b.or::<W32>(f, cf);
    f = b.or::<W32>(f, of);
    f = b.or::<W32>(f, af);
    f = b.or::<W32>(f, szp);
    b.set(eflags_ref(), f);
}

/// SUB/CMP 系の 6 旗を更新する。CF=借り、OF=符号あふれ。
fn update_sub_flags<B: Backend, W: Width>(b: &mut B, x: B::V<W>, y: B::V<W>, v: B::V<W>) {
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W>(W::from_u128(0));
    let cf_take = b.cmp::<W>(Cmp::LtU, x, y);
    let cf = pick(b, cf_take, FLAG_CF);
    let a = b.xor::<W>(x, y);
    let c = b.xor::<W>(x, v);
    let s = b.and::<W>(a, c);
    let n_top = b.konst::<W>(W::from_u128((W::BITS - 1) as u128));
    let s_top = b.shr_l::<W>(s, n_top);
    let of_take = b.cmp::<W>(Cmp::Ne, s_top, zero);
    let of = pick(b, of_take, FLAG_OF);
    let af = af_bit(b, x, y, v);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPCA);
    let mut f = b.and::<W32>(old, clear_mask);
    f = b.or::<W32>(f, cf);
    f = b.or::<W32>(f, of);
    f = b.or::<W32>(f, af);
    f = b.or::<W32>(f, szp);
    b.set(eflags_ref(), f);
}

/// 論理演算の 5 旗を更新する（CF=0、OF=0、AF は不定のため保存）。
fn update_logic_flags<B: Backend, W: Width>(b: &mut B, v: B::V<W>) {
    let old: B::V<W32> = b.get(eflags_ref());
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let cleared = b.and::<W32>(old, clear_mask);
    let f = b.or::<W32>(cleared, szp);
    b.set(eflags_ref(), f);
}

/// CF を読む。
fn read_cf<B: Backend>(b: &mut B) -> B::B {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(0x1);
    let masked = b.and::<W32>(flags, mask);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

fn read_zf<B: Backend>(b: &mut B) -> B::B {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(FLAG_ZF);
    let masked = b.and::<W32>(flags, mask);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

/// CMP EAX, imm32。EAX は変えず 6 旗を更新する。
pub fn cmp_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// TEST EAX, EAX。AND 結果で 5 旗を更新する（CF=0、OF=0）。
/// EAX 自身は変えない。
pub fn test_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read(b, Gpr(0));
    let v = b.and::<W32>(x, x);
    update_logic_flags(b, v);
    Ok(())
}

/// JE rel8。ZF=1 なら eip+2+disp に飛ぶ。
pub fn je<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let zf = read_zf(b);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(zf, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// CF を 0/1 の値として読む。
fn cf_num<B: Backend>(b: &mut B) -> B::V<W32> {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(0x1);
    let masked = b.and::<W32>(flags, mask);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, masked, zero);
    b.select::<W32>(take, one, zero)
}

/// ZF を 0/1 の値として読む。
fn zf_num<B: Backend>(b: &mut B) -> B::V<W32> {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(FLAG_ZF);
    let masked = b.and::<W32>(flags, mask);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, masked, zero);
    b.select::<W32>(take, one, zero)
}

/// SF を 0/1 の値として読む。
fn sf_num<B: Backend>(b: &mut B) -> B::V<W32> {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(FLAG_SF);
    let masked = b.and::<W32>(flags, mask);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, masked, zero);
    b.select::<W32>(take, one, zero)
}

/// OF を 0/1 の値として読む。
fn of_num<B: Backend>(b: &mut B) -> B::V<W32> {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(FLAG_OF);
    let masked = b.and::<W32>(flags, mask);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, masked, zero);
    b.select::<W32>(take, one, zero)
}

/// JB rel8。CF=1 なら eip+2+disp に飛ぶ。
pub fn jb<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let cf = read_cf(b);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(cf, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JAE rel8。CF=0 なら eip+2+disp に飛ぶ。
pub fn jae<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let cf = read_cf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let cf_is_set = b.select::<W32>(cf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, cf_is_set, zero);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JBE rel8。CF=1 または ZF=1 なら eip+2+disp に飛ぶ。
pub fn jbe<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JA rel8。CF=0 かつ ZF=0 なら eip+2+disp に飛ぶ。
pub fn ja<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Eq, either, zero);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JL rel8。SF!=OF なら eip+2+disp に飛ぶ（符号付き小なり）。
pub fn jl<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let sf = sf_num(b);
    let of = of_num(b);
    let take = b.cmp::<W32>(Cmp::Ne, sf, of);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JGE rel8。SF==OF なら eip+2+disp に飛ぶ（符号付き以上）。
pub fn jge<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let sf = sf_num(b);
    let of = of_num(b);
    let take = b.cmp::<W32>(Cmp::Eq, sf, of);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JLE rel8。ZF=1 または SF!=OF なら eip+2+disp に飛ぶ（符号付き以下）。
pub fn jle<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let zf = zf_num(b);
    let sf = sf_num(b);
    let of = of_num(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let ne = b.cmp::<W32>(Cmp::Ne, sf, of);
    let ne_n = b.select::<W32>(ne, one, zero);
    let either = b.or::<W32>(zf, ne_n);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JG rel8。ZF=0 かつ SF==OF なら eip+2+disp に飛ぶ（符号付き大なり）。
pub fn jg<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let zf = zf_num(b);
    let sf = sf_num(b);
    let of = of_num(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let eq = b.cmp::<W32>(Cmp::Eq, sf, of);
    let eq_n = b.select::<W32>(eq, one, zero);
    let zf_is_clear = b.cmp::<W32>(Cmp::Eq, zf, zero);
    let zf_ok = b.select::<W32>(zf_is_clear, one, zero);
    let both = b.and::<W32>(eq_n, zf_ok);
    let take = b.cmp::<W32>(Cmp::Ne, both, zero);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JNE rel8。ZF=0 なら eip+2+disp に飛ぶ。
/// if_then は肯定分岐のみのため、ZF の否定は select で作る。
pub fn jne<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let zf = read_zf(b);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_num = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_num, zero);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
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

/// INC r32。32ビットで包む。CF 以外の 5 旗を更新する（CF は保存）。
pub fn inc_r32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let x = read(b, rd);
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    write(b, rd, v);
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC EAX。32ビットで包む。CF 以外の 5 旗を更新する（CF は保存）。
pub fn inc_eax<B: Backend>(b: &mut B) -> Flow<B> {
    inc_r32(b, Gpr::eax())
}

/// DEC r32。32ビットで包む。CF 以外の 5 旗を更新する（CF は保存）。
pub fn dec_r32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let x = read(b, rd);
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    write(b, rd, v);
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC EAX。32ビットで包む。
pub fn dec_eax<B: Backend>(b: &mut B) -> Flow<B> {
    dec_r32(b, Gpr::eax())
}

/// ADD EAX, imm32。32ビットで包み、6 旗を更新する。
pub fn add_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr::eax());
    let y = b.konst::<W32>(imm);
    let v = b.add::<W32>(x, y);
    write(b, Gpr::eax(), v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r/m32, r32 (ModRM register-direct 01 /r、mod=11)。
/// 方向は dst=rm、src=reg。6 旗を更新する。
pub fn add_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// MOV r32, r/m32 (ModRM register-direct 8B /r、mod=11)。
/// 方向は dst=reg、src=rm。
pub fn mov_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let v = read(b, src);
    write(b, dst, v);
    Ok(())
}

const DATA_READ: Access = Access {
    endian: Endian::Le,
    // x86 は非整列アクセスを許す。
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};

const DATA_WRITE: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataWrite,
};

/// ベース + disp8 の実効アドレスを 64ビットで求める（disp8 は符号付き）。
/// 32ビット時は上位がゼロのため従来と等価である。
fn eff_addr<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> B::V<W64> {
    let r = read64(b, base);
    let d = b.konst::<W64>(disp as i64 as u64);
    b.add::<W64>(r, d)
}

/// MOV EAX, [EBX+disp8] (ModRM mod=01 の最小形)。
/// SIB・disp32・絶対番地は本格実装で足す。
pub fn mov_eax_mem<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, Gpr(3), disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV EAX, [EBX+ESI] (SIB mod=00 base+index の最小形)。
/// スケール・disp・絶対番地・SIB 拡張は本格実装で足す。
pub fn mov_eax_sib<B: Backend>(b: &mut B) -> Flow<B> {
    let base = read64(b, Gpr(3));
    let idx = read64(b, Gpr(6));
    let addr = b.add::<W64>(base, idx);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV EAX, [EBX+ESI+disp8] (SIB mod=01 base+index+disp8)。
/// スケール・disp32・絶対番地・SIB 拡張は本格実装で足す。
pub fn mov_eax_sibd<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let base = read64(b, Gpr(3));
    let idx = read64(b, Gpr(6));
    let sum = b.add::<W64>(base, idx);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(sum, d);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI+disp8], EAX (SIB mod=01 base+index+disp8)。
pub fn mov_sibd_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let base = read64(b, Gpr(3));
    let idx = read64(b, Gpr(6));
    let sum = b.add::<W64>(base, idx);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(sum, d);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SIB base+index にスケールと disp を足した実効アドレス（64ビット）。
fn sib_addr_scaled<B: Backend>(b: &mut B, shift: u32, disp: i32) -> B::V<W64> {
    let base = read64(b, Gpr(3));
    let idx = read64(b, Gpr(6));
    let n = b.konst::<W64>(shift as u64);
    let scaled = b.shl::<W64>(idx, n);
    let sum = b.add::<W64>(base, scaled);
    let d = b.konst::<W64>(disp as i64 as u64);
    b.add::<W64>(sum, d)
}

/// SIB 直接番地 base にスケール付き index と disp32 を足した実効アドレス。
/// mod=00 base=101（base なし）の形。
fn sib_addr_scaled_abs<B: Backend>(b: &mut B, shift: u32, disp: i32) -> B::V<W64> {
    let idx = read64(b, Gpr(6));
    let n = b.konst::<W64>(shift as u64);
    let scaled = b.shl::<W64>(idx, n);
    let d = b.konst::<W64>(disp as i64 as u64);
    b.add::<W64>(scaled, d)
}

/// MOV EAX, [EBX+ESI*2+disp8]。
pub fn mov_eax_sib_s2<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, 1, disp as i32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*2+disp8], EAX。
pub fn mov_sib_s2_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, 1, disp as i32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*4+disp8]。
pub fn mov_eax_sib_s4<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, 2, disp as i32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*4+disp8], EAX。
pub fn mov_sib_s4_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, 2, disp as i32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*8+disp8]。
pub fn mov_eax_sib_s8<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, 3, disp as i32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*8+disp8], EAX。
pub fn mov_sib_s8_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, 3, disp as i32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*2] (SIB mod=00 base+index*2)。
pub fn mov_eax_sib_s2nd<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = sib_addr_scaled(b, 1, 0);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*2], EAX (SIB mod=00 base+index*2)。
pub fn mov_sib_s2nd_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = sib_addr_scaled(b, 1, 0);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*4] (SIB mod=00 base+index*4)。
pub fn mov_eax_sib_s4nd<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = sib_addr_scaled(b, 2, 0);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*4], EAX (SIB mod=00 base+index*4)。
pub fn mov_sib_s4nd_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = sib_addr_scaled(b, 2, 0);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*8] (SIB mod=00 base+index*8)。
pub fn mov_eax_sib_s8nd<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = sib_addr_scaled(b, 3, 0);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*8], EAX (SIB mod=00 base+index*8)。
pub fn mov_sib_s8nd_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = sib_addr_scaled(b, 3, 0);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*2+disp32] (SIB mod=10 base+index*2)。
pub fn mov_eax_sib_s2d32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled(b, 1, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*2+disp32], EAX。
pub fn mov_sib_s2d32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled(b, 1, disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*4+disp32] (SIB mod=10 base+index*4)。
pub fn mov_eax_sib_s4d32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled(b, 2, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*4+disp32], EAX。
pub fn mov_sib_s4d32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled(b, 2, disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*8+disp32] (SIB mod=10 base+index*8)。
pub fn mov_eax_sib_s8d32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled(b, 3, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*8+disp32], EAX。
pub fn mov_sib_s8d32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled(b, 3, disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [ESI*2+disp32] (SIB mod=00 base=直接番地)。
pub fn mov_eax_sib_s2a32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, 1, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [ESI*2+disp32], EAX。
pub fn mov_sib_s2a32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, 1, disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [ESI*4+disp32] (SIB mod=00 base=直接番地)。
pub fn mov_eax_sib_s4a32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, 2, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [ESI*4+disp32], EAX。
pub fn mov_sib_s4a32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, 2, disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [ESI*8+disp32] (SIB mod=00 base=直接番地)。
pub fn mov_eax_sib_s8a32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, 3, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [ESI*8+disp32], EAX。
pub fn mov_sib_s8a32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, 3, disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV [EBX+ESI], EAX (SIB mod=00 base+index の最小形)。
/// スケール・disp・絶対番地・SIB 拡張は本格実装で足す。
pub fn mov_sib_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let base = read64(b, Gpr(3));
    let idx = read64(b, Gpr(6));
    let addr = b.add::<W64>(base, idx);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV [EBX+disp8], EAX (ModRM mod=01 の最小形)。
pub fn mov_mem_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, Gpr(3), disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX] (ModRM mod=00 rm=011 の最小形)。
/// gas は disp8=0 を mod=00 に畳むため実バイナリで頻出する。
pub fn mov_eax_memnd<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = read64(b, Gpr(3));
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX], EAX (ModRM mod=00 rm=011 の最小形)。
pub fn mov_memnd_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let addr = read64(b, Gpr(3));
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// ベース + disp32 の実効アドレスを求める（disp32 は符号付き）。
fn eff_addr32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> B::V<W64> {
    let r = read64(b, base);
    let d = b.konst::<W64>(disp as i64 as u64);
    b.add::<W64>(r, d)
}

/// MOV EAX, [EBX+disp32] (ModRM mod=10 の最小形)。
pub fn mov_eax_memd32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, Gpr(3), disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+disp32], EAX (ModRM mod=10 の最小形)。
pub fn mov_memd32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, Gpr(3), disp);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [disp32] (絶対番地、mod=00 rm=101)。
pub fn mov_eax_abs<B: Backend>(b: &mut B, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [disp32], EAX (絶対番地、mod=00 rm=101)。
pub fn mov_abs_eax<B: Backend>(b: &mut B, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SUB EAX, imm32。結果を書き、6 旗を更新する。
pub fn sub_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    write(b, Gpr(0), v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// LEAVE (C9)。ESP=EBP として POP EBP と等価。
pub fn leave<B: Backend>(b: &mut B) -> Flow<B> {
    let ebp = read(b, Gpr(5));
    b.set(esp_ref(), ebp);
    pop_reg(b, Gpr(5))
}

/// AND EAX, imm32。結果を書き、5 旗を更新する（CF=0、OF=0）。
pub fn and_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    write(b, Gpr(0), v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR EAX, imm32。結果を書き、5 旗を更新する（CF=0、OF=0）。
pub fn or_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    write(b, Gpr(0), v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR EAX, imm32。結果を書き、5 旗を更新する（CF=0、OF=0）。
pub fn xor_imm<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.xor::<W32>(x, y);
    write(b, Gpr(0), v);
    update_logic_flags(b, v);
    Ok(())
}

/// SHL EAX, imm8。カウントは下位5ビットだけ使う。
/// カウント 0 では何も変えない。CF=追い出されたビット、OF=カウント1のときのみ更新、
/// SF/ZF/PF=結果から、AF は不定のため保存。
pub fn shl_eax<B: Backend>(b: &mut B, n: u8) -> Flow<B> {
    let x = read(b, Gpr(0));
    let count = b.konst::<W32>((n & 31) as u32);
    let v = b.shl::<W32>(x, count);
    write(b, Gpr(0), v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    // 追い出されたビット = (x << (count-1)) の最上位。count=0 では使わない。
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shl::<W32>(x, safe_c1);
    let top_mask = b.konst::<W32>(0x8000_0000);
    let top = b.and::<W32>(shifted, top_mask);
    let cf_take = b.cmp::<W32>(Cmp::Ne, top, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    // OF（count=1）= 結果の最上位 XOR CF。
    let n31 = b.konst::<W32>(31);
    let v_top = b.shr_l::<W32>(v, n31);
    let v31 = b.and::<W32>(v_top, one);
    let out_top = b.shr_l::<W32>(shifted, n31);
    let cf01 = b.and::<W32>(out_top, one);
    let of_raw = b.cmp::<W32>(Cmp::Ne, v31, cf01);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let is_one = b.cmp::<W32>(Cmp::Eq, count, one);
    let of = b.select::<W32>(is_one, of_new, old_of);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of);
    new_flags = b.or::<W32>(new_flags, szp);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// SHR EAX, imm8。論理右シフト。カウントは下位5ビットだけ使う。
/// カウント 0 では何も変えない。CF=追い出されたビット、OF=カウント1のとき旧最上位、
/// SF/ZF/PF=結果から、AF は不定のため保存。
pub fn shr_eax<B: Backend>(b: &mut B, n: u8) -> Flow<B> {
    let x = read(b, Gpr(0));
    let count = b.konst::<W32>((n & 31) as u32);
    let v = b.shr_l::<W32>(x, count);
    write(b, Gpr(0), v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    // 追い出されたビット = (x >> (count-1)) の最下位。count=0 では使わない。
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shr_l::<W32>(x, safe_c1);
    let low = b.and::<W32>(shifted, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    // OF（count=1）= シフト前の最上位。
    let n31 = b.konst::<W32>(31);
    let x_top = b.shr_l::<W32>(x, n31);
    let x31 = b.and::<W32>(x_top, one);
    let of_raw = b.cmp::<W32>(Cmp::Ne, x31, zero);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let is_one = b.cmp::<W32>(Cmp::Eq, count, one);
    let of = b.select::<W32>(is_one, of_new, old_of);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of);
    new_flags = b.or::<W32>(new_flags, szp);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// LEA r32, [EBX+disp8]。メモリに触れず実効アドレスを dst に入れる。
pub fn lea_m8<B: Backend>(b: &mut B, dst: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, Gpr(3), disp);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [EBX+disp32]。
pub fn lea_m32<B: Backend>(b: &mut B, dst: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, Gpr(3), disp);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [disp32] (絶対番地)。
pub fn lea_abs<B: Backend>(b: &mut B, dst: Gpr, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [EBX+ESI]。
pub fn lea_sib<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let base = read64(b, Gpr(3));
    let idx = read64(b, Gpr(6));
    let addr = b.add::<W64>(base, idx);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [EBX+ESI+disp8]。
pub fn lea_sibd<B: Backend>(b: &mut B, dst: Gpr, disp: i8) -> Flow<B> {
    let base = read64(b, Gpr(3));
    let idx = read64(b, Gpr(6));
    let sum = b.add::<W64>(base, idx);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(sum, d);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [EBX+ESI*scale+disp8]。scale は 1/2/4/8 のいずれか。
fn lea_sib_scaled<B: Backend>(b: &mut B, dst: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [EBX+ESI*2+disp8]。
pub fn lea_sib_s2<B: Backend>(b: &mut B, dst: Gpr, disp: i8) -> Flow<B> {
    lea_sib_scaled(b, dst, 1, disp as i32)
}

/// LEA r32, [EBX+ESI*4+disp8]。
pub fn lea_sib_s4<B: Backend>(b: &mut B, dst: Gpr, disp: i8) -> Flow<B> {
    lea_sib_scaled(b, dst, 2, disp as i32)
}

/// LEA r32, [EBX+ESI*8+disp8]。
pub fn lea_sib_s8<B: Backend>(b: &mut B, dst: Gpr, disp: i8) -> Flow<B> {
    lea_sib_scaled(b, dst, 3, disp as i32)
}

/// LEA r32, [EBX+ESI*2] (disp なし)。
pub fn lea_sib_s2nd<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    lea_sib_scaled(b, dst, 1, 0)
}

/// LEA r32, [EBX+ESI*4] (disp なし)。
pub fn lea_sib_s4nd<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    lea_sib_scaled(b, dst, 2, 0)
}

/// LEA r32, [EBX+ESI*8] (disp なし)。
pub fn lea_sib_s8nd<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    lea_sib_scaled(b, dst, 3, 0)
}

/// LEA r32, [EBX+ESI*2+disp32]。
pub fn lea_sib_s2d32<B: Backend>(b: &mut B, dst: Gpr, disp: i32) -> Flow<B> {
    lea_sib_scaled(b, dst, 1, disp)
}

/// LEA r32, [EBX+ESI*4+disp32]。
pub fn lea_sib_s4d32<B: Backend>(b: &mut B, dst: Gpr, disp: i32) -> Flow<B> {
    lea_sib_scaled(b, dst, 2, disp)
}

/// LEA r32, [EBX+ESI*8+disp32]。
pub fn lea_sib_s8d32<B: Backend>(b: &mut B, dst: Gpr, disp: i32) -> Flow<B> {
    lea_sib_scaled(b, dst, 3, disp)
}

/// LEA r32, [ESI*scale+disp32] (直接番地 base)。scale は 1/2/4/8 のいずれか。
fn lea_sib_scaled_abs<B: Backend>(b: &mut B, dst: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [ESI*2+disp32]。
pub fn lea_sib_s2a32<B: Backend>(b: &mut B, dst: Gpr, disp: i32) -> Flow<B> {
    lea_sib_scaled_abs(b, dst, 1, disp)
}

/// LEA r32, [ESI*4+disp32]。
pub fn lea_sib_s4a32<B: Backend>(b: &mut B, dst: Gpr, disp: i32) -> Flow<B> {
    lea_sib_scaled_abs(b, dst, 2, disp)
}

/// LEA r32, [ESI*8+disp32]。
pub fn lea_sib_s8a32<B: Backend>(b: &mut B, dst: Gpr, disp: i32) -> Flow<B> {
    lea_sib_scaled_abs(b, dst, 3, disp)
}

/// CMP r/m32, r32。dst は変えず 6 旗を更新する。
/// 方向は x=rm、y=reg。
pub fn cmp_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// AND r/m32, r32。結果を dst に書き、5 旗を更新する（CF=0、OF=0）。
pub fn and_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r/m32, r32。結果を dst に書き、5 旗を更新する（CF=0、OF=0）。
pub fn or_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// SUB r/m32, r32。結果を dst に書き、6 旗を更新する。
pub fn sub_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// XOR r/m32, r32。結果を dst に書き、5 旗を更新する（CF=0、OF=0）。
/// 31 C0（XOR EAX,EAX のゼロ化イディオム）はこの汎用形で扱う。
pub fn xor_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// MOV r/m32, r32 (ModRM register-direct 89 /r、mod=11)。
/// 方向は dst=rm、src=reg。89 E5（MOV EBP,ESP）はこの汎用形で扱う。
pub fn mov_mr32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let v = read(b, src);
    write(b, dst, v);
    Ok(())
}

/// MOV r/m64, imm32 (REX.W + C7 /0)。imm32 は符号拡張する。
pub fn mov_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let y = b.konst::<W32>(imm);
    let v = b.sext::<W32, W64>(y);
    write64(b, dst, v);
    Ok(())
}

/// MOV r64, r/m64 (REX.W + 8B /r)。方向は dst=reg、src=rm。
pub fn mov_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let v = read64(b, src);
    write64(b, dst, v);
    Ok(())
}

/// MOV r/m64, r64 (REX.W + 89 /r)。方向は dst=rm、src=reg。
pub fn mov_mr64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let v = read64(b, src);
    write64(b, dst, v);
    Ok(())
}

/// MOV r/m32, imm32 (C7 /0)。フラグは変えない。
pub fn mov_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let v = b.konst::<W32>(imm);
    write(b, dst, v);
    Ok(())
}

/// AND r/m32, imm8。imm8 は符号拡張する。5 旗を更新する（CF=0、OF=0）。
pub fn and_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r/m64, imm8。imm8 は符号拡張する。5 旗を更新する（CF=0、OF=0）。
pub fn and_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// MOV EAX, [RIP+disp32] (64ビットの mod=00 rm=101)。
pub fn mov_eax_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [RIP+disp32], EAX (64ビットの mod=00 rm=101)。
pub fn mov_rip_eax<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// ADD r/m64, r64 (REX.W + 01 /r)。6 旗を更新する。
pub fn add_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// SUB r/m64, r64 (REX.W + 29 /r)。6 旗を更新する。
pub fn sub_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, r64 (REX.W + 39 /r)。dst は変えず 6 旗を更新する。
pub fn cmp_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// LEA r64, [RIP+disp32] (REX.W + 8D 05)。RIP は次命令先頭を指す。
pub fn lea_rip64<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    write64(b, dst, addr);
    Ok(())
}

/// MUL EAX, ECX。符号なし積の下位32ビットを EAX、上位を EDX に置く。
/// EFLAGS 更新は本格実装で足す。
pub fn mul_rm32<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = read(b, Gpr(1));
    let x64 = b.zext::<W32, W64>(x);
    let y64 = b.zext::<W32, W64>(y);
    let p = b.mul::<W64>(x64, y64);
    let lo32: B::V<W32> = b.trunc::<W64, W32>(p);
    write(b, Gpr(0), lo32);
    let shift = b.konst::<W64>(32);
    let hi64 = b.shr_l::<W64>(p, shift);
    let hi32: B::V<W32> = b.trunc::<W64, W32>(hi64);
    write(b, Gpr(2), hi32);
    Ok(())
}

/// DIV EAX, ECX。EDX:EAX を符号なし除算し、商を EAX、剰余を EDX に置く。
/// 0 除算と商あふれは実機の #DE に相当する DivZero で退出する。
pub fn div_rm32<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let y = read(b, Gpr(1));
    let hi64 = b.zext::<W32, W64>(hi);
    let shift = b.konst::<W64>(32);
    let hi_sh = b.shl::<W64>(hi64, shift);
    let lo64 = b.zext::<W32, W64>(lo);
    let dvd = b.or::<W64>(hi_sh, lo64);
    let dvs = b.zext::<W32, W64>(y);
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, dvs, zero64);
    b.if_then(is_zero, |b| Err(div0(b, eip)))?;
    let q64 = b.udiv::<W64>(dvd, dvs);
    let r64 = b.urem::<W64>(dvd, dvs);
    let qhi = b.shr_l::<W64>(q64, shift);
    let over = b.cmp::<W64>(Cmp::Ne, qhi, zero64);
    b.if_then(over, |b| Err(div0(b, eip)))?;
    let q32: B::V<W32> = b.trunc::<W64, W32>(q64);
    let r32: B::V<W32> = b.trunc::<W64, W32>(r64);
    write(b, Gpr(0), q32);
    write(b, Gpr(2), r32);
    Ok(())
}

/// IDIV EAX, ECX。EDX:EAX を符号付き除算し、商を EAX、剰余を EDX に置く。
/// 0 除算と INT_MIN/(-1) の商あふれは DivZero で退出する。
pub fn idiv_rm32<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let y = read(b, Gpr(1));
    let hi64 = b.sext::<W32, W64>(hi);
    let shift = b.konst::<W64>(32);
    let hi_sh = b.shl::<W64>(hi64, shift);
    let lo64 = b.zext::<W32, W64>(lo);
    let dvd = b.or::<W64>(hi_sh, lo64);
    let y64 = b.sext::<W32, W64>(y);
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y64, zero64);
    b.if_then(is_zero, |b| Err(div0(b, eip)))?;
    let q64 = b.sdiv::<W64>(dvd, y64);
    // 商が 32 ビット符号付きに収まらなければ #DE と同じ扱いにする。
    // INT32_MIN / -1（商 +2^31）などがここに当たる。
    let q32x: B::V<W32> = b.trunc::<W64, W32>(q64);
    let qfull = b.sext::<W32, W64>(q32x);
    let over = b.cmp::<W64>(Cmp::Ne, qfull, q64);
    b.if_then(over, |b| Err(div0(b, eip)))?;
    let r64 = b.srem::<W64>(dvd, y64);
    let q32: B::V<W32> = b.trunc::<W64, W32>(q64);
    let r32: B::V<W32> = b.trunc::<W64, W32>(r64);
    write(b, Gpr(0), q32);
    write(b, Gpr(2), r32);
    Ok(())
}

/// 実機の #DE（0 除算・商あふれ）に相当する退出。
fn div0<B: Backend>(b: &mut B, eip: u32) -> B::Exit {
    b.raise(GuestException {
        kind: ExceptionKind::DivZero,
        code: 0,
        addr: Some(eip as u64),
        in_delay_slot: false,
    })
}

/// MOV EAX, imm32。
pub fn mov_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let v = b.konst::<W32>(imm);
    write(b, Gpr::eax(), v);
    Ok(())
}

/// INT 0x80。i386 のシステムコール命令。OS パーソナリティが処理する退出を返す。
/// 呼び出し規約は eax=番号・ebx,ecx,edx,esi,edi,ebp=引数、戻りは eax（負が errno）。
/// IDT 経由のベクタ分岐と特権検査は本格実装で足す。
pub fn int80<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 0x80,
        addr: Some(eip as u64),
        in_delay_slot: false,
    }))
}

/// SYSCALL。OS パーソナリティが処理する退出を返す（番号・規約は本格実装で足す）。
pub fn syscall<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 0,
        addr: Some(eip as u64),
        in_delay_slot: false,
    }))
}

/// CPUID。leaf 0 のベンダIDのみ返す（機能導出は本格実装で足す）。
/// TODO(本格実装): leaf 1+ はゼロでなく版数・機能ビットを返す。
/// EAX=最大leaf、EBX="Genu"、EDX="ineI"、ECX="ntel"。
pub fn cpuid<B: Backend>(b: &mut B) -> Flow<B> {
    // レジスタ番号は EAX=0, ECX=1, EDX=2, EBX=3 である。
    let leaf = read(b, Gpr(0));
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, leaf, zero);
    let max = b.konst::<W32>(1);
    let new_eax = b.select::<W32>(is_zero, max, zero);
    write(b, Gpr(0), new_eax);
    let ebx_v = b.konst::<W32>(0x756e_6547);
    let new_ebx = b.select::<W32>(is_zero, ebx_v, zero);
    write(b, Gpr(3), new_ebx);
    let ecx_v = b.konst::<W32>(0x6c65_746e);
    let new_ecx = b.select::<W32>(is_zero, ecx_v, zero);
    write(b, Gpr(1), new_ecx);
    let edx_v = b.konst::<W32>(0x4965_6e69);
    let new_edx = b.select::<W32>(is_zero, edx_v, zero);
    write(b, Gpr(2), new_edx);
    Ok(())
}

/// PUSH r32。ESP を 4 減じてから積む（x86 は下向きスタック）。
/// PUSH ESP は減算前の値を積むため、先に値を読む。
pub fn push_reg<B: Backend>(b: &mut B, rs: Gpr) -> Flow<B> {
    let v: B::V<W32> = read(b, rs);
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let addr = b.zext::<W32, W64>(next);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// POP r32。読んでから ESP を 4 進める。
/// POP ESP の行き先は加算結果ではなく取り出した値そのものである（実機通り）。
pub fn pop_reg<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let esp = read(b, Gpr(4));
    let addr = b.zext::<W32, W64>(esp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    if rd.0 == 4 {
        b.set(esp_ref(), v);
    } else {
        write(b, rd, v);
        let four = b.konst::<W32>(4);
        let next = b.add::<W32>(esp, four);
        b.set(esp_ref(), next);
    }
    Ok(())
}

/// CALL rel32。戻り（eip+5）を積み、eip+5+disp に飛ぶ。
pub fn call_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let ret_addr = eip.wrapping_add(5);
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let addr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(addr, ret, DATA_WRITE)?;
    let target = ret_addr.wrapping_add(disp as u32);
    let t = b.konst::<W32>(target);
    b.set(eip_ref(), t);
    let tj = b.konst::<W64>(target as u64);
    b.jump(tj);
    Ok(())
}

/// RET。スタック先頭を eip に戻す。
pub fn ret<B: Backend>(b: &mut B) -> Flow<B> {
    let esp = read(b, Gpr(4));
    let addr = b.zext::<W32, W64>(esp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    b.set(eip_ref(), v);
    let w = b.zext::<W32, W64>(v);
    b.jump(w);
    let four = b.konst::<W32>(4);
    let next = b.add::<W32>(esp, four);
    b.set(esp_ref(), next);
    Ok(())
}

pub fn esp_ref() -> StateRef<W32> {
    Gpr(4).state()
}

/// PUSH r64。RSP を 8 減じてから積む。
pub fn push_reg64<B: Backend>(b: &mut B, rs: Gpr) -> Flow<B> {
    let v = read64(b, rs);
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    b.store::<W64>(next, v, DATA_WRITE)?;
    Ok(())
}

/// POP r64。読んでから RSP を 8 進める。
pub fn pop_reg64<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let rsp = read64(b, Gpr(4));
    let v: B::V<W64> = b.load::<W64>(rsp, DATA_READ)?;
    if rd.0 == 4 {
        write64(b, Gpr(4), v);
    } else {
        write64(b, rd, v);
        let eight = b.konst::<W64>(8);
        let next = b.add::<W64>(rsp, eight);
        write64(b, Gpr(4), next);
    }
    Ok(())
}

/// CALL rel32 (64ビット)。戻り（RIP+5）を積み、RIP+5+disp に飛ぶ。
/// RIP は 4GB 未満を想定し、下位で eip を更新する。
pub fn call_rel64<B: Backend>(b: &mut B, rip: u64, disp: i32) -> Flow<B> {
    let ret_addr = rip.wrapping_add(5);
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let target = ret_addr.wrapping_add(disp as i64 as u64);
    let t = b.konst::<W32>(target as u32);
    b.set(eip_ref(), t);
    let tj = b.konst::<W64>(target);
    b.jump(tj);
    Ok(())
}

/// RET (64ビット)。スタック先頭を RIP に戻す。
pub fn ret64<B: Backend>(b: &mut B) -> Flow<B> {
    let rsp = read64(b, Gpr(4));
    let v: B::V<W64> = b.load::<W64>(rsp, DATA_READ)?;
    let lo: B::V<W32> = b.trunc::<W64, W32>(v);
    b.set(eip_ref(), lo);
    b.jump(v);
    let eight = b.konst::<W64>(8);
    let next = b.add::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    Ok(())
}

/// LEAVE (64ビット)。RSP=RBP として POP RBP と等価。
pub fn leave64<B: Backend>(b: &mut B) -> Flow<B> {
    let rbp = read64(b, Gpr(5));
    write64(b, Gpr(4), rbp);
    pop_reg64(b, Gpr(5))
}

/// LOOP rel8。ECX を 1 減じ、0 でなければ eip+2+disp に飛ぶ。
/// busybox の繰り返しに使う最小形である。EFLAGS には影響しない（SDM 通り）。
pub fn loop_rel8<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let ecx = read(b, Gpr(1));
    let one = b.konst::<W32>(1);
    let next = b.sub::<W32>(ecx, one);
    write(b, Gpr(1), next);
    let zero = b.konst::<W32>(0);
    let again = b.cmp::<W32>(Cmp::Ne, next, zero);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(again, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JMP rel32。eip+5+disp32 に飛ぶ。
pub fn jmp_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let target = eip.wrapping_add(5).wrapping_add(disp as u32);
    let t = b.konst::<W32>(target);
    b.set(eip_ref(), t);
    let tj = b.konst::<W64>(target as u64);
    b.jump(tj);
    Ok(())
}

/// JMP rel8。eip からの相対（呼び出し側が eip+2 基準の完成形を渡す）。
pub fn jmp8<B: Backend>(b: &mut B, target: u32) -> Flow<B> {
    let t = b.konst::<W32>(target);
    b.set(eip_ref(), t);
    let tj = b.konst::<W64>(target as u64);
    b.jump(tj);
    Ok(())
}
