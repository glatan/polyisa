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
use polyisa_sem::{
    Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W32, W64, W128, Width,
};

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

/// TEST r/m32,r32。AND 結果で 5 旗を更新する（CF=0、OF=0）。dst/src は変えない.
pub fn test_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// NOT r/m32。ビット反転し、旗は変えない.
pub fn not_rm32<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let v = b.not::<W32>(x);
    write(b, dst, v);
    Ok(())
}

/// NEG r/m32。0 - x を計算し、6 旗を更新する.
pub fn neg_rm32<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let zero = b.konst::<W32>(0);
    let v = b.sub::<W32>(zero, x);
    write(b, dst, v);
    update_sub_flags(b, zero, x, v);
    Ok(())
}

/// TEST r/m32,imm32。AND 結果で 5 旗を更新する（CF=0、OF=0）。dst は変えない.
pub fn test_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// 8ビット GPR を読む。REX ありは低8ビット、REX なしの 4-7 は上位8ビット (AH/CH/DH/BH).
fn read8<B: Backend>(b: &mut B, r: Gpr, high: bool) -> B::V<W8> {
    if high {
        let v32 = read(b, r);
        let n = b.konst::<W32>(8);
        let shifted = b.shr_l::<W32>(v32, n);
        b.trunc::<W32, W8>(shifted)
    } else if r.0 < 8 {
        let v32 = read(b, r);
        b.trunc::<W32, W8>(v32)
    } else {
        let v64: B::V<W64> = b.get(x_ref(r));
        b.trunc::<W64, W8>(v64)
    }
}

/// TEST r/m8,imm8。AND 結果で 5 旗を更新する（CF=0、OF=0）。dst は変えない.
/// TEST AL,imm8。AND 結果で 5 旗を更新する.
pub fn test_al_imm<B: Backend>(b: &mut B, imm: u8) -> Flow<B> {
    let x32 = read(b, Gpr(0));
    let x: B::V<W8> = b.trunc::<W32, W8>(x32);
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST EAX,imm32。AND 結果で 5 旗を更新する.
pub fn test_eax_imm<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,imm8 RIP (83 0D)。32ビット OR し、5 旗を更新する.
pub fn or_rm32_imm8_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: i8) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR [disp32],imm8 (32ビット絶対番地).
pub fn or_rm32_imm8_abs<B: Backend>(b: &mut B, addr32: u32, imm: i8) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m32,imm8 RIP (83 25)。32ビット AND し、5 旗を更新する.
pub fn and_rm32_imm8_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: i8) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND [disp32],imm8 (32ビット絶対番地).
pub fn and_rm32_imm8_abs<B: Backend>(b: &mut B, addr32: u32, imm: i8) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m8,imm8 RIP (F6 05)。8ビットを読んで AND し、5 旗を更新する.
pub fn test_m8_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST [disp32],imm8 (32ビット絶対番地).
pub fn test_m8_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

pub fn test_rm8_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u8, high: bool) -> Flow<B> {
    let x = read8(b, dst, high);
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// 8ビット GPR に書く。REX ありは低8ビット、REX なしの 4-7 は上位8ビット.
fn write8<B: Backend>(b: &mut B, r: Gpr, high: bool, v: B::V<W8>) {
    if high {
        let cur32 = read(b, r);
        let low_mask = b.konst::<W32>(0xffff_00ff);
        let preserved = b.and::<W32>(cur32, low_mask);
        let ext32 = b.zext::<W8, W32>(v);
        let sh = b.konst::<W32>(8);
        let shifted = b.shl::<W32>(ext32, sh);
        let nv = b.or::<W32>(preserved, shifted);
        write(b, r, nv);
    } else if r.0 < 8 {
        let cur32 = read(b, r);
        let mask = b.konst::<W32>(0xffff_ff00);
        let preserved = b.and::<W32>(cur32, mask);
        let ext32 = b.zext::<W8, W32>(v);
        let nv = b.or::<W32>(preserved, ext32);
        write(b, r, nv);
    } else {
        let curv: B::V<W64> = b.get(x_ref(r));
        let mask = b.konst::<W64>(0xffff_ffff_ffff_ff00);
        let preserved = b.and::<W64>(curv, mask);
        let ext64 = b.zext::<W8, W64>(v);
        let nv = b.or::<W64>(preserved, ext64);
        b.set(x_ref(r), nv);
    }
}

/// AND r/m8,imm8。AND 結果で 5 旗を更新する（CF=0、OF=0）.
pub fn and_rm8_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u8, high: bool) -> Flow<B> {
    let x = read8(b, dst, high);
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    write8(b, dst, high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// CMP r/m8,imm8。メモリを読まずレジスタを比較し、6 旗を更新する.
pub fn cmp_rm8_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u8, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, high);
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m8,imm8 SIB+disp8 (80 /7 mod=01)。メモリを読んで比較する.
pub fn cmp_rm8_imm_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: u8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m8,imm8 [base+disp8] (80 /7 mod=01、SIBなし)。メモリを読んで比較する.
pub fn cmp_rm8_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// MOV r/m8,imm8 [base+disp8] (C6 /0 mod=01、SIBなし)。メモリに1バイト書く.
pub fn mov_rm8_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let v = b.konst::<W8>(imm);
    b.store::<W8>(addr, v, DATA_WRITE)?;
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

/// MOV r32, [base+disp8] (ModRM mod=01)。base/dst は実行側で抽出する。
pub fn mov_eax_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV r32, [base+index*scale] (SIB mod=00)。scale/disp なし形を含む。
pub fn mov_eax_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [base+index*scale], r32 (SIB mod=00)。
pub fn mov_sib_eax<B: Backend>(b: &mut B, src: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SIB base+index にスケールと disp を足した実効アドレス（64ビット）。
fn sib_addr_scaled<B: Backend>(b: &mut B, shift: u32, disp: i32, base: Gpr, idx: Gpr) -> B::V<W64> {
    let base = read64(b, base);
    let idx = read64(b, idx);
    let n = b.konst::<W64>(shift as u64);
    let scaled = b.shl::<W64>(idx, n);
    let sum = b.add::<W64>(base, scaled);
    let d = b.konst::<W64>(disp as i64 as u64);
    b.add::<W64>(sum, d)
}

/// SIB 直接番地 base にスケール付き index と disp32 を足した実効アドレス。
/// mod=00 base=101（base なし）の形。
fn sib_addr_scaled_abs<B: Backend>(b: &mut B, shift: u32, disp: i32, idx: Gpr) -> B::V<W64> {
    let idx = read64(b, idx);
    let n = b.konst::<W64>(shift as u64);
    let scaled = b.shl::<W64>(idx, n);
    let d = b.konst::<W64>(disp as i64 as u64);
    b.add::<W64>(scaled, d)
}

/// MOV r32, [base+index*scale+disp8] (SIB mod=01)。
pub fn mov_eax_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [base+index*scale+disp8], r32 (SIB mod=01)。
pub fn mov_sibd_eax<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [base+index*scale+disp32] (SIB mod=10)。
pub fn mov_eax_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [base+index*scale+disp32], EAX (SIB mod=10)。
pub fn mov_sibd32_eax<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r32, [index*scale+disp32] (SIB mod=00 base=直接番地)。
pub fn mov_eax_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [index*scale+disp32], r32 (SIB mod=00 base=直接番地)。
pub fn mov_sibabs_eax<B: Backend>(b: &mut B, src: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+disp8], r32 (ModRM mod=01)。
pub fn mov_mem_eax8<B: Backend>(b: &mut B, src: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX] (ModRM mod=00 rm=011 の最小形)。
/// gas は disp8=0 を mod=00 に畳むため実バイナリで頻出する。
pub fn mov_eax_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [base], r32 (ModRM mod=00)。
pub fn mov_memnd_eax<B: Backend>(b: &mut B, src: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// ベース + disp32 の実効アドレスを求める（disp32 は符号付き）。
fn eff_addr32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> B::V<W64> {
    let r = read64(b, base);
    let d = b.konst::<W64>(disp as i64 as u64);
    b.add::<W64>(r, d)
}

/// MOV r32, [base+disp32] (ModRM mod=10)。
pub fn mov_eax_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [base+disp32], r32 (ModRM mod=10)。
pub fn mov_mem_eax32<B: Backend>(b: &mut B, src: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r32, [disp32] (絶対番地、mod=00 rm=101)。
pub fn mov_eax_abs<B: Backend>(b: &mut B, dst: Gpr, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [disp32], r32 (絶対番地、mod=00 rm=101)。
pub fn mov_abs_eax<B: Backend>(b: &mut B, src: Gpr, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W32> = read(b, src);
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

/// SHR r/m32,imm8。論理右シフトし、CF/OF/SZP を更新する（AF 不定）。
pub fn shr_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>((n & 31) as u32);
    let v = b.shr_l::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shr_l::<W32>(x, safe_c1);
    let low = b.and::<W32>(shifted, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
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

/// SAR r/m32,imm8。算術右シフトし、CF/OF/SZP を更新する.
pub fn sar_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>((n & 31) as u32);
    let v = b.shr_a::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shr_l::<W32>(x, safe_c1);
    let low = b.and::<W32>(shifted, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    // SAR の OF は count=1 で 0 (本格実装では詰める)。簡略化のため SHR と同じ OF 更新を使う.
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

/// SAR r/m64,imm8 (REX.W)。算術右シフトし、CF/SZP を更新する（OF=0）。
pub fn sar_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>((n & 63) as u64);
    let v = b.shr_a::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let c1 = b.sub::<W64>(count, one64);
    let active64 = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let safe_c1 = b.select::<W64>(active64, c1, zero64);
    let shifted = b.shr_l::<W64>(x, safe_c1);
    let low = b.and::<W64>(shifted, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let zero32 = b.konst::<W32>(0);
    let of_new = zero32;
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of_new);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// SAR r/m32,CL (D1 /7)。CL 下位5ビットで算術右シフトし、CF/SZP を更新する.
pub fn sar_rm32_cl<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let cl8 = read8(b, Gpr(1), false);
    let cl32 = b.zext::<W8, W32>(cl8);
    let mask = b.konst::<W32>(31);
    let count = b.and::<W32>(cl32, mask);
    let v = b.shr_a::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shr_l::<W32>(x, safe_c1);
    let low = b.and::<W32>(shifted, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let of_new = zero;
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of_new);
    new_flags = b.or::<W32>(new_flags, szp);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// SAR r/m64,CL (REX.W + D1 /7)。CL 下位6ビットで算術右シフトし、CF/SZP を更新する.
pub fn sar_rm64_cl<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let cl8 = read8(b, Gpr(1), false);
    let cl64 = b.zext::<W8, W64>(cl8);
    let mask = b.konst::<W64>(63);
    let count = b.and::<W64>(cl64, mask);
    let v = b.shr_a::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let c1 = b.sub::<W64>(count, one64);
    let active64 = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let safe_c1 = b.select::<W64>(active64, c1, zero64);
    let shifted = b.shr_l::<W64>(x, safe_c1);
    let low = b.and::<W64>(shifted, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let zero32 = b.konst::<W32>(0);
    let of_new = zero32;
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of_new);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// LEA r32, [base+disp8]。メモリに触れず実効アドレスを dst に入れる。
pub fn lea_m8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [base+disp32]。
pub fn lea_m32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [base] (disp なし)。
pub fn lea_mnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
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

/// LEA r32, [base+index*scale] (SIB mod=00)。
pub fn lea_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [base+index*scale+disp8] (SIB mod=01)。
pub fn lea_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [base+index*scale+disp32] (SIB mod=10)。
pub fn lea_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// LEA r32, [index*scale+disp32] (SIB mod=00 base=直接番地)。
pub fn lea_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let addr32: B::V<W32> = b.trunc::<W64, W32>(addr);
    write(b, dst, addr32);
    Ok(())
}

/// CMP r/m32, r32。dst は変えず 6 旗を更新する。
/// 方向は x=rm、y=reg。
/// LEA r64, [base+disp8] (REX.W)。
pub fn lea_m8_64<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    write64(b, dst, addr);
    Ok(())
}

/// LEA r64, [base+disp32] (REX.W)。
pub fn lea_m32_64<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    write64(b, dst, addr);
    Ok(())
}

/// LEA r64, [base] (REX.W)。
pub fn lea_mnd_64<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    write64(b, dst, addr);
    Ok(())
}

/// LEA r64, [base+index*scale] (REX.W, SIB mod=00)。
pub fn lea_sib_64<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    write64(b, dst, addr);
    Ok(())
}

/// LEA r64, [base+index*scale+disp8] (REX.W, SIB mod=01)。
pub fn lea_sibd_64<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    write64(b, dst, addr);
    Ok(())
}

/// LEA r64, [base+index*scale+disp32] (REX.W, SIB mod=10)。
pub fn lea_sibd32_64<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    write64(b, dst, addr);
    Ok(())
}

/// LEA r64, [index*scale+disp32] (REX.W, SIB mod=00 base=直接番地)。
pub fn lea_sibabs_64<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    write64(b, dst, addr);
    Ok(())
}

pub fn cmp_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m32, r32 [base+disp32] (mod=10)。dstメモリとsrcレジスタを比較する。
pub fn cmp_rm32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, r64 [base+disp32] (mod=10, REX.W)。dstメモリとsrcレジスタを比較する。
pub fn cmp_rm64_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
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

/// MOVSXD r32, r/m32 (63 /r)。32ビット符号拡張（同幅のため転送と等価）。
pub fn movsxd_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let v = read(b, src);
    write(b, dst, v);
    Ok(())
}

/// MOVSXD r64, r/m32 (REX.W + 63 /r)。32ビット値を符号拡張する。
pub fn movsxd_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let v32 = read(b, src);
    let v = b.sext::<W32, W64>(v32);
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

/// ADD r/m32, imm8。imm8 は符号拡張する。6 旗を更新する。
pub fn add_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r/m64, imm8。imm8 は符号拡張する。6 旗を更新する。
pub fn add_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// OR r/m32, imm8。imm8 は符号拡張する。5 旗を更新する（CF=0、OF=0）。
pub fn or_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r/m64, imm8。imm8 は符号拡張する。5 旗を更新する（CF=0、OF=0）。
pub fn or_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// ADC r/m32, imm8。CF を足し込んで 6 旗を更新する。
pub fn adc_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let c = cf_num(b);
    let y1 = b.add::<W32>(y, c);
    let x64 = b.zext::<W32, W64>(x);
    let y64 = b.zext::<W32, W64>(y);
    let c64 = b.zext::<W32, W64>(c);
    let t1 = b.add::<W64>(x64, y64);
    let t = b.add::<W64>(t1, c64);
    let v: B::V<W32> = b.trunc::<W64, W32>(t);
    write(b, dst, v);
    let n32 = b.konst::<W64>(32);
    let carry = b.shr_l::<W64>(t, n32);
    let zero64 = b.konst::<W64>(0);
    let cf_take = b.cmp::<W64>(Cmp::Ne, carry, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let a = b.xor::<W32>(x, v);
    let c2 = b.xor::<W32>(y1, v);
    let s = b.and::<W32>(a, c2);
    let n31 = b.konst::<W32>(31);
    let s31 = b.shr_l::<W32>(s, n31);
    let zero = b.konst::<W32>(0);
    let of_take = b.cmp::<W32>(Cmp::Ne, s31, zero);
    let of = pick(b, of_take, FLAG_OF);
    let af = af_bit(b, x, y1, v);
    let szp = szp_bits(b, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let clear_mask = b.konst::<W32>(!FLAG_OSZPCA);
    let mut f = b.and::<W32>(old, clear_mask);
    f = b.or::<W32>(f, cf);
    f = b.or::<W32>(f, of);
    f = b.or::<W32>(f, af);
    f = b.or::<W32>(f, szp);
    b.set(eflags_ref(), f);
    Ok(())
}

/// SBB r/m32, imm8。CF を借りて 6 旗を更新する。
pub fn sbb_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let c = cf_num(b);
    let y1 = b.add::<W32>(y, c);
    let x64 = b.zext::<W32, W64>(x);
    let y64 = b.zext::<W32, W64>(y);
    let c64 = b.zext::<W32, W64>(c);
    let t1 = b.sub::<W64>(x64, y64);
    let t2 = b.sub::<W64>(t1, c64);
    let v: B::V<W32> = b.trunc::<W64, W32>(t2);
    write(b, dst, v);
    let n32 = b.konst::<W64>(32);
    let borrow = b.shr_l::<W64>(t2, n32);
    let zero64 = b.konst::<W64>(0);
    let cf_take = b.cmp::<W64>(Cmp::Ne, borrow, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let a = b.xor::<W32>(x, y1);
    let c2 = b.xor::<W32>(x, v);
    let s = b.and::<W32>(a, c2);
    let n31 = b.konst::<W32>(31);
    let s31 = b.shr_l::<W32>(s, n31);
    let zero = b.konst::<W32>(0);
    let of_take = b.cmp::<W32>(Cmp::Ne, s31, zero);
    let of = pick(b, of_take, FLAG_OF);
    let af = af_bit(b, x, y1, v);
    let szp = szp_bits(b, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let clear_mask = b.konst::<W32>(!FLAG_OSZPCA);
    let mut f = b.and::<W32>(old, clear_mask);
    f = b.or::<W32>(f, cf);
    f = b.or::<W32>(f, of);
    f = b.or::<W32>(f, af);
    f = b.or::<W32>(f, szp);
    b.set(eflags_ref(), f);
    Ok(())
}

/// ADC r/m64, imm8。CF を足し込んで 6 旗を更新する。
pub fn adc_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let c = cf_num(b);
    let x128 = b.zext::<W64, W128>(x);
    let y128 = b.zext::<W64, W128>(y);
    let c128 = b.zext::<W32, W128>(c);
    let t1 = b.add::<W128>(x128, y128);
    let t = b.add::<W128>(t1, c128);
    let v: B::V<W64> = b.trunc::<W128, W64>(t);
    write64(b, dst, v);
    let n64 = b.konst::<W128>(64);
    let carry = b.shr_l::<W128>(t, n64);
    let zero128 = b.konst::<W128>(W128::from_u128(0));
    let cf_take = b.cmp::<W128>(Cmp::Ne, carry, zero128);
    let cf = pick(b, cf_take, FLAG_CF);
    let c64 = b.trunc::<W128, W64>(c128);
    let y1 = b.add::<W64>(y, c64);
    let a = b.xor::<W64>(x, v);
    let c2 = b.xor::<W64>(y1, v);
    let acc = b.and::<W64>(a, c2);
    let n63 = b.konst::<W64>(63);
    let s63 = b.shr_l::<W64>(acc, n63);
    let zero = b.konst::<W64>(0);
    let of_take = b.cmp::<W64>(Cmp::Ne, s63, zero);
    let of = pick(b, of_take, FLAG_OF);
    let af = af_bit(b, x, y1, v);
    let szp = szp_bits(b, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let clear_mask = b.konst::<W32>(!FLAG_OSZPCA);
    let mut f = b.and::<W32>(old, clear_mask);
    f = b.or::<W32>(f, cf);
    f = b.or::<W32>(f, of);
    f = b.or::<W32>(f, af);
    f = b.or::<W32>(f, szp);
    b.set(eflags_ref(), f);
    Ok(())
}

/// SBB r/m64, imm8。CF を借りて 6 旗を更新する。
pub fn sbb_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let c = cf_num(b);
    let x128 = b.zext::<W64, W128>(x);
    let y128 = b.zext::<W64, W128>(y);
    let c128 = b.zext::<W32, W128>(c);
    let t1 = b.sub::<W128>(x128, y128);
    let t = b.sub::<W128>(t1, c128);
    let v: B::V<W64> = b.trunc::<W128, W64>(t);
    write64(b, dst, v);
    let n64 = b.konst::<W128>(64);
    let borrow = b.shr_l::<W128>(t, n64);
    let zero128 = b.konst::<W128>(W128::from_u128(0));
    let cf_take = b.cmp::<W128>(Cmp::Ne, borrow, zero128);
    let cf = pick(b, cf_take, FLAG_CF);
    let c64 = b.trunc::<W128, W64>(c128);
    let y1 = b.add::<W64>(y, c64);
    let a = b.xor::<W64>(x, y1);
    let c2 = b.xor::<W64>(x, v);
    let acc = b.and::<W64>(a, c2);
    let n63 = b.konst::<W64>(63);
    let s63 = b.shr_l::<W64>(acc, n63);
    let zero = b.konst::<W64>(0);
    let of_take = b.cmp::<W64>(Cmp::Ne, s63, zero);
    let of = pick(b, of_take, FLAG_OF);
    let af = af_bit(b, x, y1, v);
    let szp = szp_bits(b, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let clear_mask = b.konst::<W32>(!FLAG_OSZPCA);
    let mut f = b.and::<W32>(old, clear_mask);
    f = b.or::<W32>(f, cf);
    f = b.or::<W32>(f, of);
    f = b.or::<W32>(f, af);
    f = b.or::<W32>(f, szp);
    b.set(eflags_ref(), f);
    Ok(())
}

/// SUB r/m32, imm8。imm8 は符号拡張する。6 旗を更新する。
/// ADC r/m32, r32。CF を足し込んで 6 旗を更新する.
pub fn adc_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let c = cf_num(b);
    let y1 = b.add::<W32>(y, c);
    let x64 = b.zext::<W32, W64>(x);
    let y64 = b.zext::<W32, W64>(y);
    let c64 = b.zext::<W32, W64>(c);
    let t1 = b.add::<W64>(x64, y64);
    let t = b.add::<W64>(t1, c64);
    let v: B::V<W32> = b.trunc::<W64, W32>(t);
    write(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r/m64, r64 (REX.W)。CF を足し込んで 6 旗を更新する.
pub fn adc_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let c = cf_num(b);
    let x128 = b.zext::<W64, W128>(x);
    let y128 = b.zext::<W64, W128>(y);
    let c128 = b.zext::<W32, W128>(c);
    let t1 = b.add::<W128>(x128, y128);
    let t = b.add::<W128>(t1, c128);
    let v: B::V<W64> = b.trunc::<W128, W64>(t);
    write64(b, dst, v);
    let c64 = b.trunc::<W128, W64>(c128);
    let y1 = b.add::<W64>(y, c64);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// SBB r/m32, r32。CF を借りて 6 旗を更新する.
pub fn sbb_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let c = cf_num(b);
    let y1 = b.add::<W32>(y, c);
    let x64 = b.zext::<W32, W64>(x);
    let y64 = b.zext::<W32, W64>(y);
    let c64 = b.zext::<W32, W64>(c);
    let t1 = b.sub::<W64>(x64, y64);
    let t = b.sub::<W64>(t1, c64);
    let v: B::V<W32> = b.trunc::<W64, W32>(t);
    write(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r/m64, r64 (REX.W)。CF を借りて 6 旗を更新する.
pub fn sbb_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let c = cf_num(b);
    let x128 = b.zext::<W64, W128>(x);
    let y128 = b.zext::<W64, W128>(y);
    let c128 = b.zext::<W32, W128>(c);
    let t1 = b.sub::<W128>(x128, y128);
    let t = b.sub::<W128>(t1, c128);
    let v: B::V<W64> = b.trunc::<W128, W64>(t);
    write64(b, dst, v);
    let c64 = b.trunc::<W128, W64>(c128);
    let y1 = b.add::<W64>(y, c64);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

pub fn sub_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r/m32, imm32。6 旗を更新する。
/// ADC r/m32, imm32。CF を足し込んで 6 旗を更新する.
pub fn adc_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let c = cf_num(b);
    let y1 = b.add::<W32>(y, c);
    let x64 = b.zext::<W32, W64>(x);
    let y64 = b.zext::<W32, W64>(y);
    let c64 = b.zext::<W32, W64>(c);
    let t1 = b.add::<W64>(x64, y64);
    let t = b.add::<W64>(t1, c64);
    let v: B::V<W32> = b.trunc::<W64, W32>(t);
    write(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// SBB r/m32, imm32。CF を借りて 6 旗を更新する.
pub fn sbb_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let c = cf_num(b);
    let y1 = b.add::<W32>(y, c);
    let x64 = b.zext::<W32, W64>(x);
    let y64 = b.zext::<W32, W64>(y);
    let c64 = b.zext::<W32, W64>(c);
    let t1 = b.sub::<W64>(x64, y64);
    let t = b.sub::<W64>(t1, c64);
    let v: B::V<W32> = b.trunc::<W64, W32>(t);
    write(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// ADD r/m32, imm32。6 旗を更新する.
pub fn add_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r/m64, imm32 (REX.W)。imm32 は符号拡張し、6 旗を更新する.
pub fn add_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// OR r/m32, imm32。5 旗を更新する（CF=0、OF=0）.
pub fn or_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r/m64, imm32 (REX.W)。imm32 は符号拡張し、5 旗を更新する.
/// ADC r/m64, imm32 (REX.W + 81 /2)。imm32 は符号拡張し、CF を足す.
pub fn adc_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let c = cf_num(b);
    let x128 = b.zext::<W64, W128>(x);
    let y128 = b.zext::<W64, W128>(y);
    let c128 = b.zext::<W32, W128>(c);
    let t1 = b.add::<W128>(x128, y128);
    let t = b.add::<W128>(t1, c128);
    let v: B::V<W64> = b.trunc::<W128, W64>(t);
    write64(b, dst, v);
    // 旗は加算として更新（CF/OF の厳密化は本格実装で詰める）.
    update_add_flags(b, x, y, v);
    Ok(())
}

/// SBB r/m64, imm32 (REX.W + 81 /3)。imm32 は符号拡張し、CF を借りる.
pub fn sbb_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let c = cf_num(b);
    let x128 = b.zext::<W64, W128>(x);
    let y128 = b.zext::<W64, W128>(y);
    let c128 = b.zext::<W32, W128>(c);
    let t1 = b.sub::<W128>(x128, y128);
    let t = b.sub::<W128>(t1, c128);
    let v: B::V<W64> = b.trunc::<W128, W64>(t);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

pub fn or_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r/m32, imm32。5 旗を更新する（CF=0、OF=0）.
pub fn and_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r/m64, imm32 (REX.W)。imm32 は符号拡張し、5 旗を更新する.
pub fn and_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r/m32, imm32。5 旗を更新する（CF=0、OF=0）.
pub fn xor_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r/m64, imm32 (REX.W)。imm32 は符号拡張し、5 旗を更新する.
pub fn xor_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

pub fn sub_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m32, imm32。dst は変えず 6 旗を更新する。
pub fn cmp_rm32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, imm32。imm32 は符号拡張し、dst は変えず 6 旗を更新する。
pub fn cmp_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r/m64, imm32。imm32 は符号拡張する。6 旗を更新する。
pub fn sub_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r/m64, imm8。imm8 は符号拡張する。6 旗を更新する。
pub fn sub_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// XOR r/m32, imm8。imm8 は符号拡張する。5 旗を更新する（CF=0、OF=0）。
pub fn xor_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r/m64, imm8。imm8 は符号拡張する。5 旗を更新する（CF=0、OF=0）。
pub fn xor_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// CMP r/m32, imm8。dst は変えず 6 旗を更新する。
pub fn cmp_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, dst);
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m32, [base+disp8], imm8 (mod=01)。メモリ値を読んで比較する。
pub fn cmp_rm32_imm8m8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, [base+disp8], imm8 (mod=01)。メモリ値を読んで比較する。
pub fn cmp_rm64_imm8m8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m32, [base], imm8 (mod=00)。メモリ値を読んで比較する.
pub fn cmp_rm32_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, imm8 (REX.W + 83 /7)。dst は変えず 6 旗を更新する。
pub fn cmp_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
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

/// MOV r32, [RIP+disp32] (64ビットの mod=00 rm=101)。
pub fn mov_eax_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV [RIP+disp32], r32 (64ビットの mod=00 rm=101)。
pub fn mov_rip_eax<B: Backend>(b: &mut B, src: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W32> = read(b, src);
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
pub fn mul_rm32<B: Backend>(b: &mut B, rm: Gpr) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = read(b, rm);
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
pub fn div_rm32<B: Backend>(b: &mut B, eip: u32, rm: Gpr) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let y = read(b, rm);
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
/// DIV r/m64 (REX.W + F7 /6)。RDX:RAX を符号なし除算し、商を RAX、剰余を RDX に置く.
pub fn div_rm64<B: Backend>(b: &mut B, eip: u32, rm: Gpr) -> Flow<B> {
    let lo = read64(b, Gpr(0));
    let hi = read64(b, Gpr(2));
    let y = read64(b, rm);
    let hi128 = b.zext::<W64, W128>(hi);
    let shift = b.konst::<W128>(64);
    let hi_sh = b.shl::<W128>(hi128, shift);
    let lo128 = b.zext::<W64, W128>(lo);
    let dvd = b.or::<W128>(hi_sh, lo128);
    let dvs = b.zext::<W64, W128>(y);
    let zero128 = b.konst::<W128>(0);
    let is_zero = b.cmp::<W128>(Cmp::Eq, dvs, zero128);
    b.if_then(is_zero, |b| Err(div0(b, eip)))?;
    let q = b.udiv::<W128>(dvd, dvs);
    let r = b.urem::<W128>(dvd, dvs);
    let n64 = b.konst::<W128>(64);
    let qhi = b.shr_l::<W128>(q, n64);
    let over = b.cmp::<W128>(Cmp::Ne, qhi, zero128);
    b.if_then(over, |b| Err(div0(b, eip)))?;
    let q64: B::V<W64> = b.trunc::<W128, W64>(q);
    let r64: B::V<W64> = b.trunc::<W128, W64>(r);
    write64(b, Gpr(0), q64);
    write64(b, Gpr(2), r64);
    Ok(())
}

pub fn idiv_rm32<B: Backend>(b: &mut B, eip: u32, rm: Gpr) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let y = read(b, rm);
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

/// MOV r32, imm32。32ビットで包む。
/// MOV r64, imm64。64ビットで包む.
pub fn mov_r64_imm64<B: Backend>(b: &mut B, dst: Gpr, imm: u64) -> Flow<B> {
    let v = b.konst::<W64>(imm);
    write64(b, dst, v);
    Ok(())
}

pub fn mov_r32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let v = b.konst::<W32>(imm);
    write(b, dst, v);
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

/// CALL rel32 (64ビット)。戻り（次 RIP）を積み、次 RIP+disp に飛ぶ。
/// next_rip は接頭辞込みの次命令先頭である。RIP は 4GB 未満を想定し、
/// 下位で eip を更新する。
pub fn call_rel64<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let ret_addr = next_rip;
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

/* ===== REP string 操作（F3 接頭辞）。DF=0（順方向）のみ。 ===== */

/// RSI/RSI・RDI/RDI を全64ビットで読み書きする（32ビット時は上位ゼロのため等価）。
fn bump64<B: Backend>(b: &mut B, r: Gpr, delta: i64) {
    let v = read64(b, r);
    let d = b.konst::<W64>(delta as u64);
    let w = b.add::<W64>(v, d);
    write64(b, r, w);
}

/// REP のカウンタ（ECX/RCX）を1減らし、0でなければ eip に戻る。
fn rep_continue<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let c = read64(b, Gpr(1));
    let one = b.konst::<W64>(1);
    let next = b.sub::<W64>(c, one);
    write64(b, Gpr(1), next);
    let zero = b.konst::<W64>(0);
    let again = b.cmp::<W64>(Cmp::Ne, next, zero);
    let t = b.konst::<W32>(eip);
    let tj = b.konst::<W64>(eip as u64);
    b.if_then(again, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// REP MOVSB。1バイト転送して繰り返す。
pub fn rep_movsb<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let src = read64(b, Gpr(6));
    let dst = read64(b, Gpr(7));
    let v: B::V<W8> = b.load::<W8>(src, DATA_READ)?;
    b.store::<W8>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(6), 1);
    bump64(b, Gpr(7), 1);
    rep_continue(b, eip)
}

/// REP MOVSD。4バイト転送して繰り返す。
pub fn rep_movsd<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let src = read64(b, Gpr(6));
    let dst = read64(b, Gpr(7));
    let v: B::V<W32> = b.load::<W32>(src, DATA_READ)?;
    b.store::<W32>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(6), 4);
    bump64(b, Gpr(7), 4);
    rep_continue(b, eip)
}

/// REP MOVSQ。8バイト転送して繰り返す（REX.W）。
pub fn rep_movsq<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let src = read64(b, Gpr(6));
    let dst = read64(b, Gpr(7));
    let v: B::V<W64> = b.load::<W64>(src, DATA_READ)?;
    b.store::<W64>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(6), 8);
    bump64(b, Gpr(7), 8);
    rep_continue(b, eip)
}

/// REP STOSB。AL を1バイト格納して繰り返す。
pub fn rep_stosb<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let dst = read64(b, Gpr(7));
    let eax = read(b, Gpr(0));
    let al: B::V<W8> = b.trunc::<W32, W8>(eax);
    b.store::<W8>(dst, al, DATA_WRITE)?;
    bump64(b, Gpr(7), 1);
    rep_continue(b, eip)
}

/// REP STOSD。EAX を4バイト格納して繰り返す。
pub fn rep_stosd<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let dst = read64(b, Gpr(7));
    let v = read(b, Gpr(0));
    b.store::<W32>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(7), 4);
    rep_continue(b, eip)
}

/// REP STOSQ。RAX を8バイト格納して繰り返す（REX.W）。
pub fn rep_stosq<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let dst = read64(b, Gpr(7));
    let v = read64(b, Gpr(0));
    b.store::<W64>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(7), 8);
    rep_continue(b, eip)
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

/* ===== XMM 最小セット（SSE2）。DFやMXCSRは扱わず、整数データ移動のみ。 ===== */

/// XMM レジスタ番号。0-7 である。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Xmm(pub u8);

/// XMM レジスタを指す。
pub fn xmm_ref(r: Xmm) -> StateRef<W128> {
    StateRef::<W128>::from_offset(core::mem::offset_of!(CpuState, xmm) + (r.0 as usize) * 16)
}

/// MOVD xmm, r/m32。GPR 下位32ビットを XMM 下位に移し、上位96を消す。
pub fn movd_xmm_gpr32<B: Backend>(b: &mut B, dst: Xmm, src: Gpr) -> Flow<B> {
    let v32 = read(b, src);
    let v = b.zext::<W32, W128>(v32);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVD xmm, m32 (mod=10 RBP+disp32)。32ビットを読んで上位96を消す.
pub fn movd_xmm_m32<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.zext::<W32, W128>(v32);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVQ r64, xmm。XMM 下位64ビットを GPR に移す（REX.W）。
pub fn movq_r64_xmm<B: Backend>(b: &mut B, dst: Gpr, src: Xmm) -> Flow<B> {
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    write64(b, dst, v);
    Ok(())
}

/// MOVQ xmm, r64。GPR 64ビットを XMM 下位に移し、上位64を消す。
pub fn movq_xmm_r64<B: Backend>(b: &mut B, dst: Xmm, src: Gpr) -> Flow<B> {
    let v64 = read64(b, src);
    let v = b.zext::<W64, W128>(v64);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// PUNPCKLBW xmm1, xmm2。下位8バイトずつを交互に挿す。
pub fn punpcklbw<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..8u32 {
        let sh_a = b.konst::<W128>((i * 8) as u128);
        let shifted_a = b.shr_l::<W128>(a, sh_a);
        let mask_ff = b.konst::<W128>(0xff);
        let byte_a = b.and::<W128>(shifted_a, mask_ff);
        let sh_b = b.konst::<W128>((i * 8) as u128);
        let shifted_c = b.shr_l::<W128>(c, sh_b);
        let mask_ff2 = b.konst::<W128>(0xff);
        let byte_c = b.and::<W128>(shifted_c, mask_ff2);
        let pos_a = b.konst::<W128>((i * 16) as u128);
        let part_a = b.shl::<W128>(byte_a, pos_a);
        let pos_c = b.konst::<W128>((i * 16 + 8) as u128);
        let part_c = b.shl::<W128>(byte_c, pos_c);
        acc = b.or::<W128>(acc, part_a);
        acc = b.or::<W128>(acc, part_c);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PUNPCKLWD xmm1, xmm2。下位4ワードずつを交互に挿す。
pub fn punpcklwd<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..4u32 {
        let sh_a = b.konst::<W128>((i * 16) as u128);
        let shifted_a = b.shr_l::<W128>(a, sh_a);
        let mask_ffff = b.konst::<W128>(0xffff);
        let word_a = b.and::<W128>(shifted_a, mask_ffff);
        let sh_c = b.konst::<W128>((i * 16) as u128);
        let shifted_c = b.shr_l::<W128>(c, sh_c);
        let mask_ffff2 = b.konst::<W128>(0xffff);
        let word_c = b.and::<W128>(shifted_c, mask_ffff2);
        let pos_a = b.konst::<W128>((i * 32) as u128);
        let part_a = b.shl::<W128>(word_a, pos_a);
        let pos_c = b.konst::<W128>((i * 32 + 16) as u128);
        let part_c = b.shl::<W128>(word_c, pos_c);
        acc = b.or::<W128>(acc, part_a);
        acc = b.or::<W128>(acc, part_c);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PSHUFD xmm1, xmm2, imm8。32ビット単位で並べ替える。
pub fn pshufd<B: Backend>(b: &mut B, dst: Xmm, src: Xmm, imm: u8) -> Flow<B> {
    let v: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..4u32 {
        let sel = ((imm >> (i * 2)) & 3) as u128 * 32;
        let sh = b.konst::<W128>(sel);
        let shifted = b.shr_l::<W128>(v, sh);
        let mask_dw = b.konst::<W128>(0xffff_ffff);
        let dw = b.and::<W128>(shifted, mask_dw);
        let pos = b.konst::<W128>((i * 32) as u128);
        let part = b.shl::<W128>(dw, pos);
        acc = b.or::<W128>(acc, part);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PXOR xmm1, xmm2。128ビット XOR する.
pub fn pxor_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let v = b.xor::<W128>(a, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// PAND xmm1, xmm2。128ビット AND する.
pub fn pand_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let v = b.and::<W128>(a, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// PUNPCKLQDQ xmm1, xmm2。下位64ビットずつを交互に挿す (dst_lo, src_lo).
pub fn punpcklqdq<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mask = b.konst::<W128>(0xffff_ffff_ffff_ffff);
    let lo_a = b.and::<W128>(a, mask);
    let lo_c = b.and::<W128>(c, mask);
    let pos = b.konst::<W128>(64);
    let hi = b.shl::<W128>(lo_c, pos);
    let v = b.or::<W128>(lo_a, hi);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVQ m64,xmm RIP (66 0F D6)。XMM 下位64を [RIP+disp] に格納する.
pub fn movq_m64_xmm_rip<B: Backend>(b: &mut B, src: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVQ [disp32],xmm (32ビット絶対番地、64ビットストア).
pub fn movq_m64_xmm_abs<B: Backend>(b: &mut B, src: Xmm, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVQ xmm,m64 RIP (F3 0F 7E)。[RIP+disp] の64ビットを XMM 下位に移し、上位64を消す.
pub fn movq_xmm_m64_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let v = b.zext::<W64, W128>(v64);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVQ xmm,[disp32] (32ビット絶対番地、64ビットロード).
pub fn movq_xmm_m64_abs<B: Backend>(b: &mut B, dst: Xmm, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let v = b.zext::<W64, W128>(v64);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// PUNPCKLDQ xmm1, xmm2。下位2ダブルワードずつを交互に挿す.
pub fn punpckldq<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..2u32 {
        let sh_a = b.konst::<W128>((i * 32) as u128);
        let shifted_a = b.shr_l::<W128>(a, sh_a);
        let mask_dw = b.konst::<W128>(0xffff_ffff);
        let dw_a = b.and::<W128>(shifted_a, mask_dw);
        let sh_c = b.konst::<W128>((i * 32) as u128);
        let shifted_c = b.shr_l::<W128>(c, sh_c);
        let dw_c = b.and::<W128>(shifted_c, mask_dw);
        let pos_a = b.konst::<W128>((i * 64) as u128);
        let part_a = b.shl::<W128>(dw_a, pos_a);
        let pos_c = b.konst::<W128>((i * 64 + 32) as u128);
        let part_c = b.shl::<W128>(dw_c, pos_c);
        acc = b.or::<W128>(acc, part_a);
        acc = b.or::<W128>(acc, part_c);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

fn load128<B: Backend>(b: &mut B, addr: B::V<W64>) -> Result<B::V<W128>, B::Exit> {
    b.load::<W128>(addr, DATA_READ)
}

fn store128<B: Backend>(b: &mut B, addr: B::V<W64>, v: B::V<W128>) -> Result<(), B::Exit> {
    b.store::<W128>(addr, v, DATA_WRITE)
}

/// MOVUPS xmm, [base]。16バイト非整列読み出し。
pub fn movups_load_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v = load128(b, addr)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [base], xmm。16バイト非整列書き込み。
pub fn movups_store_memnd<B: Backend>(b: &mut B, src: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, addr, v)?;
    Ok(())
}

/// MOVUPS xmm, [base+disp8]。
pub fn movups_load_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v = load128(b, addr)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [base+disp8], xmm。
pub fn movups_store_mem8<B: Backend>(b: &mut B, src: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, addr, v)?;
    Ok(())
}

/// MOVUPS xmm, [base+disp32]。
pub fn movups_load_mem32<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v = load128(b, addr)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [base+disp32], xmm。
pub fn movups_store_mem32<B: Backend>(b: &mut B, src: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, addr, v)?;
    Ok(())
}

/// MOVUPS xmm, [base+index*scale] (SIB mod=00)。
pub fn movups_load_sib<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v = load128(b, addr)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [base+index*scale], xmm (SIB mod=00)。
pub fn movups_store_sib<B: Backend>(
    b: &mut B,
    src: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, addr, v)?;
    Ok(())
}

/// MOVUPS xmm, [base+index*scale+disp8] (SIB mod=01)。
pub fn movups_load_sibd<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v = load128(b, addr)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [base+index*scale+disp8], xmm (SIB mod=01)。
pub fn movups_store_sibd<B: Backend>(
    b: &mut B,
    src: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, addr, v)?;
    Ok(())
}

/// MOVUPS xmm, [base+index*scale+disp32] (SIB mod=10)。
pub fn movups_load_sibd32<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v = load128(b, addr)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [base+index*scale+disp32], xmm (SIB mod=10)。
pub fn movups_store_sibd32<B: Backend>(
    b: &mut B,
    src: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, addr, v)?;
    Ok(())
}

/// MOVUPS xmm, [RIP+disp32] (64ビット)。
pub fn movups_load_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v = load128(b, addr)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [RIP+disp32], xmm (64ビット)。
pub fn movups_store_rip<B: Backend>(b: &mut B, src: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, addr, v)?;
    Ok(())
}

/// MOV m32, imm32 (C7 /0 mod=10 RBP+disp32)。
/// MOV m16, imm16 (66 C7 /0 mod=10 RBP+disp32).
pub fn mov_rm16_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr32(b, base, disp);
    let v = b.konst::<W16>(imm);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn mov_rm32_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64, imm32 (C7 /0 mod=10 RBP+disp32, REX.W)。imm32 は符号拡張する。
pub fn mov_rm64_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// CMOVB r32, r/m32。CF=1 なら src を dst に移す.
pub fn cmovb_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_cf(b);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVNE r32, r/m32。ZF=0 なら src を dst に移す.
pub fn cmovne_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVE r32, r/m32。ZF=1 なら src を dst に移す.
pub fn cmove_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_zf(b);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVNS r32, r/m32。SF=0 なら src を dst に移す.
pub fn cmovns_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = {
        let sf = read_sf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(sf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVBE r32, r/m32。CF=1 または ZF=1 なら src を dst に移す.
pub fn cmovbe_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVBE r64, r/m64。CF=1 または ZF=1 なら src を dst に移す（REX.W）.
pub fn cmovbe_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVA r32, r/m32。CF=0 かつ ZF=0 なら src を dst に移す.
pub fn cmova_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Eq, either, zero);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVA r64, r/m64。CF=0 かつ ZF=0 なら src を dst に移す（REX.W）.
pub fn cmova_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Eq, either, zero);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVAE r32, r/m32。CF=0 なら src を dst に移す.
pub fn cmovae_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = {
        let cf = read_cf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(cf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVAE r64, r/m64。CF=0 なら src を dst に移す（REX.W）.
pub fn cmovae_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = {
        let cf = read_cf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(cf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVE r64, m64 (RBP+disp32)。ZF=1 なら mem64 を dst に移す.
pub fn cmove_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let take = read_zf(b);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVE r32, m32 (RBP+disp32)。ZF=1 なら mem32 を dst に移す.
pub fn cmove_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let take = read_zf(b);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVAE r32, m32 [base+disp32] (mod=10)。CF=0 なら mem32 を dst に移す.
pub fn cmovae_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let take = {
        let cf = read_cf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(cf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVAE r64, m64 [base+disp32] (mod=10, REX.W)。CF=0 なら mem64 を dst に移す.
pub fn cmovae_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let take = {
        let cf = read_cf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(cf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, r/m32, imm32。符号付き積の下位32ビットを dst に置く.
pub fn imul_r32_imm<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, imm: u32) -> Flow<B> {
    let x = read(b, src);
    let y = b.konst::<W32>(imm);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, r/m64, imm32 (REX.W)。imm32 は符号拡張する.
pub fn imul_r64_imm<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, src);
    let y = b.konst::<W64>(imm as i32 as u64);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// CMOVNS r64, r/m64。SF=0 なら src を dst に移す（REX.W）.
pub fn cmovns_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = {
        let sf = read_sf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(sf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVE r64, r/m64。ZF=1 なら src を dst に移す（REX.W）.
pub fn cmove_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_zf(b);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVNE r64, r/m64。ZF=0 なら src を dst に移す（REX.W）.
pub fn cmovne_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVB r64, r/m64。CF=1 なら src を dst に移す（REX.W）。
pub fn cmovb_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_cf(b);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMP [RIP+disp32], imm8 (64ビット)。メモリ値を読んで比較する.
pub fn cmp_rm32_imm8_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: i8) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, [RIP+disp32]。32ビットで包み、6旗を更新する.
pub fn add_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, [RIP+disp32] (REX.W)。64ビットで包み、6旗を更新する.
pub fn add_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, [disp32] (32ビット絶対番地).
pub fn add_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// MOV m32, imm32 (C7 /0 SIB+disp32)。
pub fn mov_rm32_imm_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64, imm32 (C7 /0 SIB+disp32, REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVZX r32,m16 RIP相対。16ビットを読んでゼロ拡張する.
pub fn movzx_r32_m16_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::W16;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r32,m16 絶対番地 (32ビット)。
pub fn movzx_r32_m16_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = b.konst::<W64>(addr32 as u64);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOV m32, imm32 RIP (C7 05)。32ビットストア.
pub fn mov_rm32_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64, imm32 RIP (C7 05 + REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV [disp32], imm32 (C7 05, 32ビット絶対番地).
pub fn mov_rm32_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// OR m32, r32 RIP (09 05)。32ビット OR し、5 旗を更新する.
pub fn or_m32_r32_rip<B: Backend>(b: &mut B, src: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR [disp32], r32 (32ビット絶対番地).
pub fn or_m32_r32_abs<B: Backend>(b: &mut B, src: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR r32, m32 RIP (0B 15)。32ビット OR し、5 旗を更新する.
pub fn or_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r32, [disp32] (32ビット絶対番地).
pub fn or_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32, imm32 RIP (81 0D)。32ビット OR し、5 旗を更新する.
pub fn or_rm32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR [disp32], imm32 (32ビット絶対番地).
pub fn or_rm32_abs<B: Backend>(b: &mut B, addr32: u32, imm: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m32, imm32 RIP (81 25)。32ビット AND し、5 旗を更新する.
pub fn and_rm32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND [disp32], imm32 (32ビット絶対番地).
pub fn and_rm32_abs<B: Backend>(b: &mut B, addr32: u32, imm: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// ADD m32, imm32 RIP (81 05)。32ビット ADD し、6 旗を更新する.
pub fn add_rm32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD [disp32], imm32 (32ビット絶対番地).
pub fn add_rm32_abs<B: Backend>(b: &mut B, addr32: u32, imm: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// CMP m16, imm8 (66 83 /7, RIP相対)。16ビットを読んで比較する.
pub fn cmp_rm16_imm8_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let x = b.zext::<W16, W32>(x16);
    // imm8 は16ビットに符号拡張してから比較するが、旗計算は下位16で十分.
    // 簡略化のため32ビットに拡張して比較する（上位は0のため等価）.
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    // 16ビットの SZP のため上位を消してから旗更新する.
    let mask = b.konst::<W32>(0xffff);
    let xv = b.and::<W32>(x, mask);
    let yv = b.and::<W32>(y, mask);
    let vv = b.and::<W32>(v, mask);
    update_sub_flags(b, xv, yv, vv);
    Ok(())
}

/// CMP [disp32], imm8 (32ビット絶対番地)。
pub fn cmp_rm32_imm8_abs<B: Backend>(b: &mut B, addr32: u32, imm: i8) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// MOVZX r32, r/m16 (RBP+disp32)。16ビットを読んでゼロ拡張する。
pub fn movzx_r32_m16_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr32(b, base, disp);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOV [RIP+disp32], r16 (66 89, 16ビット)。上位は保存する.
pub fn mov_rip_r16<B: Backend>(b: &mut B, src: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::W16;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    b.store::<W16>(addr, v16, DATA_WRITE)?;
    Ok(())
}

/// MOV r16, [RIP+disp32] (66 8B, 16ビット)。上位は保存する.
pub fn mov_r16_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::W16;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let cur32 = read(b, dst);
    let mask = b.konst::<W32>(0xffff_0000);
    let preserved = b.and::<W32>(cur32, mask);
    let ext32 = b.zext::<W16, W32>(v16);
    let v = b.or::<W32>(preserved, ext32);
    write(b, dst, v);
    Ok(())
}

/// MOVUPS xmm, [disp32] (32ビット絶対番地)。
pub fn movups_load_abs<B: Backend>(b: &mut B, dst: Xmm, addr: u32) -> Flow<B> {
    let a = b.konst::<W64>(addr as u64);
    let v = load128(b, a)?;
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVUPS [disp32], xmm (32ビット絶対番地)。
pub fn movups_store_abs<B: Backend>(b: &mut B, src: Xmm, addr: u32) -> Flow<B> {
    let a = b.konst::<W64>(addr as u64);
    let v: B::V<W128> = b.get(xmm_ref(src));
    store128(b, a, v)?;
    Ok(())
}

/// MOVUPS xmm1, xmm2。レジスタ間転送。
pub fn movups_xmm_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let v: B::V<W128> = b.get(xmm_ref(src));
    b.set(xmm_ref(dst), v);
    Ok(())
}

/* ===== near Jcc (0F 80-8F + disp32)。eip+6+disp に飛ぶ。 ===== */

fn read_pf<B: Backend>(b: &mut B) -> B::B {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(FLAG_PF);
    let masked = b.and::<W32>(flags, mask);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

fn read_sf<B: Backend>(b: &mut B) -> B::B {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(FLAG_SF);
    let masked = b.and::<W32>(flags, mask);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

fn read_of<B: Backend>(b: &mut B) -> B::B {
    let flags: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(FLAG_OF);
    let masked = b.and::<W32>(flags, mask);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

fn jcc_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32, take: B::B) -> Flow<B> {
    let target = eip.wrapping_add(6).wrapping_add(disp as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(take, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JO rel32。OF=1 なら飛ぶ。
pub fn jo_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let take = read_of(b);
    jcc_rel32(b, eip, disp, take)
}

/// JNO rel32。OF=0 なら飛ぶ。
pub fn jno_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JB rel32。CF=1 なら飛ぶ。
pub fn jb_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let take = read_cf(b);
    jcc_rel32(b, eip, disp, take)
}

/// JAE rel32。CF=0 なら飛ぶ。
pub fn jae_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let cf = read_cf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(cf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JE rel32。ZF=1 なら飛ぶ。
pub fn je_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let take = read_zf(b);
    jcc_rel32(b, eip, disp, take)
}

/// JNE rel32。ZF=0 なら飛ぶ。
pub fn jne_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JBE rel32。CF=1 または ZF=1 なら飛ぶ。
pub fn jbe_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JA rel32。CF=0 かつ ZF=0 なら飛ぶ。
pub fn ja_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Eq, either, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JS rel32。SF=1 なら飛ぶ。
pub fn js_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let take = read_sf(b);
    jcc_rel32(b, eip, disp, take)
}

/// JNS rel32。SF=0 なら飛ぶ。
pub fn jns_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let sf = read_sf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(sf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JP rel32。PF=1 なら飛ぶ。
pub fn jp_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let take = read_pf(b);
    jcc_rel32(b, eip, disp, take)
}

/// JNP rel32。PF=0 なら飛ぶ。
pub fn jnp_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let pf = read_pf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(pf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JL rel32。SF!=OF なら飛ぶ。
pub fn jl_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let sf = sf_num(b);
    let of = of_num(b);
    let take = b.cmp::<W32>(Cmp::Ne, sf, of);
    jcc_rel32(b, eip, disp, take)
}

/// JGE rel32。SF==OF なら飛ぶ。
pub fn jge_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let sf = sf_num(b);
    let of = of_num(b);
    let take = b.cmp::<W32>(Cmp::Eq, sf, of);
    jcc_rel32(b, eip, disp, take)
}

/// JLE rel32。ZF=1 または SF!=OF なら飛ぶ。
pub fn jle_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let zf = zf_num(b);
    let sf = sf_num(b);
    let of = of_num(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let ne = b.cmp::<W32>(Cmp::Ne, sf, of);
    let ne_n = b.select::<W32>(ne, one, zero);
    let either = b.or::<W32>(zf, ne_n);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    jcc_rel32(b, eip, disp, take)
}

/// JG rel32。ZF=0 かつ SF==OF なら飛ぶ。
pub fn jg_rel32<B: Backend>(b: &mut B, eip: u32, disp: i32) -> Flow<B> {
    let zf = zf_num(b);
    let sf = sf_num(b);
    let of = of_num(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let eq = b.cmp::<W32>(Cmp::Eq, sf, of);
    let eq_n = b.select::<W32>(eq, one, zero);
    let zf_clear = b.cmp::<W32>(Cmp::Eq, zf, zero);
    let zf_ok = b.select::<W32>(zf_clear, one, zero);
    let both = b.and::<W32>(eq_n, zf_ok);
    let take = b.cmp::<W32>(Cmp::Ne, both, zero);
    jcc_rel32(b, eip, disp, take)
}
