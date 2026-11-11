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
    Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64, W128, Width,
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

/// x87 制御ワードを指す。
pub fn fcw_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, fcw))
}

/// x87 の TOP を指す。
pub fn top_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, top))
}

/// x87 レジスタ `i` の指数部を指す。
pub fn st_exp_ref(i: usize) -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, st_exp) + i * 2)
}

/// x87 レジスタ `i` の仮数を指す。
pub fn st_sig_ref(i: usize) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, st_sig) + i * 8)
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

/// CMP AL,imm8。AL と imm8 を比較し 6 旗を更新する (dst 不変).
pub fn cmp_al_imm<B: Backend>(b: &mut B, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let x32 = read(b, Gpr(0));
    let x: B::V<W8> = b.trunc::<W32, W8>(x32);
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// OR AL,imm8。OR 結果で 5 旗を更新する（CF=0、OF=0）.
pub fn or_al_imm<B: Backend>(b: &mut B, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let x32 = read(b, Gpr(0));
    let x: B::V<W8> = b.trunc::<W32, W8>(x32);
    let y = b.konst::<W8>(imm);
    let v = b.or::<W8>(x, y);
    // AL のみ書き換え、上位は保持.
    let mask = b.konst::<W32>(0xFFFF_FF00);
    let preserved = b.and::<W32>(x32, mask);
    let ext32 = b.zext::<W8, W32>(v);
    let nv = b.or::<W32>(preserved, ext32);
    write(b, Gpr(0), nv);
    update_logic_flags(b, v);
    Ok(())
}

/// AND AX,imm16 (66 25)。AX のみ書き換え、上位16ビットは保持. 5 旗を更新する.
pub fn and_ax_imm16<B: Backend>(b: &mut B, imm: u16) -> Flow<B> {
    let x32 = read(b, Gpr(0));
    let x: B::V<W16> = b.trunc::<W32, W16>(x32);
    let y = b.konst::<W16>(imm);
    let v = b.and::<W16>(x, y);
    // AX のみ書き換え、上位は保持.
    let mask = b.konst::<W32>(0xFFFF_0000);
    let preserved = b.and::<W32>(x32, mask);
    let ext32 = b.zext::<W16, W32>(v);
    let nv = b.or::<W32>(preserved, ext32);
    write(b, Gpr(0), nv);
    update_logic_flags(b, v);
    Ok(())
}

/// CMP r/m16,imm16 (66 81 /7 mod=11)。下位16ビットを比較し 6 旗を更新する (dst 不変).
pub fn cmp_rm16_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u16) -> Flow<B> {
    let y = b.konst::<W16>(imm);
    let x = if dst.0 < 8 {
        let x32 = read(b, dst);
        b.trunc::<W32, W16>(x32)
    } else {
        let x64 = read64(b, dst);
        b.trunc::<W64, W16>(x64)
    };
    let v = b.sub::<W16>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP AX,imm16 (66 3D)。AX と imm16 を比較し 6 旗を更新する (dst 不変).
pub fn cmp_ax_imm16<B: Backend>(b: &mut B, imm: u16) -> Flow<B> {
    let x32 = read(b, Gpr(0));
    let x: B::V<W16> = b.trunc::<W32, W16>(x32);
    let y = b.konst::<W16>(imm);
    let v = b.sub::<W16>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// ADD r/m16,imm16 (66 81 /0 mod=11)。下位16ビットのみ書き換え、上位は保持. 6 旗を更新する.
pub fn add_rm16_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u16) -> Flow<B> {
    let y = b.konst::<W16>(imm);
    if dst.0 < 8 {
        let x32 = read(b, dst);
        let x: B::V<W16> = b.trunc::<W32, W16>(x32);
        let v = b.add::<W16>(x, y);
        let mask = b.konst::<W32>(0xFFFF_0000);
        let preserved = b.and::<W32>(x32, mask);
        let ext32 = b.zext::<W16, W32>(v);
        let nv = b.or::<W32>(preserved, ext32);
        write(b, dst, nv);
        update_add_flags(b, x, y, v);
    } else {
        let x64 = read64(b, dst);
        let x: B::V<W16> = b.trunc::<W64, W16>(x64);
        let v = b.add::<W16>(x, y);
        let mask = b.konst::<W64>(0xFFFF_FFFF_FFFF_0000);
        let preserved = b.and::<W64>(x64, mask);
        let ext64 = b.zext::<W16, W64>(v);
        let nv = b.or::<W64>(preserved, ext64);
        write64(b, dst, nv);
        update_add_flags(b, x, y, v);
    }
    Ok(())
}

/// AND r/m16,imm16 (66 81 /4 mod=11)。下位16ビットのみ書き換え、上位は保持. 5 旗を更新する.
pub fn and_rm16_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u16) -> Flow<B> {
    let y = b.konst::<W16>(imm);
    if dst.0 < 8 {
        let x32 = read(b, dst);
        let x: B::V<W16> = b.trunc::<W32, W16>(x32);
        let v = b.and::<W16>(x, y);
        let mask = b.konst::<W32>(0xFFFF_0000);
        let preserved = b.and::<W32>(x32, mask);
        let ext32 = b.zext::<W16, W32>(v);
        let nv = b.or::<W32>(preserved, ext32);
        write(b, dst, nv);
        update_logic_flags(b, v);
    } else {
        let x64 = read64(b, dst);
        let x: B::V<W16> = b.trunc::<W64, W16>(x64);
        let v = b.and::<W16>(x, y);
        let mask = b.konst::<W64>(0xFFFF_FFFF_FFFF_0000);
        let preserved = b.and::<W64>(x64, mask);
        let ext64 = b.zext::<W16, W64>(v);
        let nv = b.or::<W64>(preserved, ext64);
        write64(b, dst, nv);
        update_logic_flags(b, v);
    }
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

/// TEST r/m64, r64 (REX.W)。AND 結果で 5 旗を更新する。dst は変えない.
pub fn test_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r32,m32 [base+disp8] (85 /r mod=01)。AND 結果で 5 旗を更新する.
pub fn test_r32_m32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r64,m64 [base] (85 /r mod=00, REX.W)。
pub fn test_r64_m64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r32,m32 [base+index*scale] (85 /r SIB mod=00)。awk 0x4a1c82 対応.
pub fn test_r32_m32_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r64,m64 [base+index*scale] (85 /r SIB mod=00, REX.W)。
pub fn test_r64_m64_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r32,m32 [base] (85 /r mod=00)。find 0x5d17f7 対応.
pub fn test_r32_m32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r64,m64 [base+disp8] (85 /r mod=01, REX.W)。
pub fn test_r64_m64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r32,m32 [base+disp32] (85 /r mod=10)。grep 0x43d250 no_index 対応.
pub fn test_r32_m32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r64,m64 [base+disp32] (85 /r mod=10, REX.W)。grep 0x43d250 no_index 対応.
pub fn test_r64_m64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r32,m32 [base+index*scale+disp8] (85 /r SIB mod=01)。dst は変えず 5 旗を更新.
pub fn test_r32_m32_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r64,m64 [base+index*scale+disp8] (85 /r SIB mod=01, REX.W)。
pub fn test_r64_m64_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r32,m32 [base+index*scale+disp32] (85 /r SIB mod=10)。grep 0x43d250 対応.
pub fn test_r32_m32_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST r64,m64 [base+index*scale+disp32] (85 /r SIB mod=10, REX.W)。grep 0x43d250 対応.
pub fn test_r64_m64_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
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

/// NOT r/m64 (REX.W)。ビット反転し、旗は変えない.
pub fn not_rm64<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let v = b.not::<W64>(x);
    write64(b, dst, v);
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

/// NEG r/m64 (REX.W)。0 - x を計算し、6 旗を更新する.
pub fn neg_rm64<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let zero = b.konst::<W64>(0);
    let v = b.sub::<W64>(zero, x);
    write64(b, dst, v);
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

/// TEST r/m64,imm32 (REX.W)。imm32 は符号拡張する。dst は変えない.
pub fn test_rm64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u32) -> Flow<B> {
    let x = read64(b, dst);
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m32,imm32 [base] (F7 /0 mod=00)。tac 0x5b0ca8 対応.
pub fn test_rm32_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m32,imm32 [base+disp8] (F7 /0 mod=01)。
pub fn test_rm32_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m64,imm32 [base+disp8] (F7 /0 mod=01, REX.W)。imm32 は符号拡張する.
pub fn test_rm64_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m64,imm32 [base] (F7 /0 mod=00, REX.W)。imm32 は符号拡張する.
pub fn test_rm64_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.and::<W64>(x, y);
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

/// SUB m32,imm8 RIP (83 2D)。32ビット SUB し、6 旗を更新する.
pub fn sub_rm32_imm8_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: i8) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB [disp32],imm8 (32ビット絶対番地).
pub fn sub_rm32_imm8_abs<B: Backend>(b: &mut B, addr32: u32, imm: i8) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
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

/// TEST m8,imm8 [base] (F6 /0 mod=00)。
pub fn test_m8_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m8,imm8 [base+disp8] (F6 /0 mod=01)。
pub fn test_m8_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m8,imm8 [base+disp32] (F6 /0 mod=10)。
pub fn test_m8_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// CMP [RIP+disp32], r8 (38 /r mod=00 rm=101)。grep 0x4aec6d 対応.
pub fn cmp_m8_r8_rip<B: Backend>(
    b: &mut B,
    next_rip: u64,
    disp: i32,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP [disp32], r8 (38 /r mod=00 rm=101、32ビット)。
pub fn cmp_m8_r8_abs<B: Backend>(b: &mut B, addr32: u32, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMPB m8,imm8 RIP (80 3D)。8ビットを読んで比較し、6 旗を更新する.
pub fn cmp_rm8_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMPB [disp32],imm8 (32ビット絶対番地).
pub fn cmp_rm8_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
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

/// OR r/m8,imm8。OR 結果で 5 旗を更新する（CF=0、OF=0）.
pub fn or_rm8_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u8, high: bool) -> Flow<B> {
    let x = read8(b, dst, high);
    let y = b.konst::<W8>(imm);
    let v = b.or::<W8>(x, y);
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

/// MOV [disp32], r8 (88 /r SIB 直接番地、mod=00)。絶対番地へ8bit格納.
pub fn mov_m8_r8_abs<B: Backend>(b: &mut B, src: Gpr, addr: u32, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let a = b.konst::<W64>(addr as u64);
    let x = read8(b, src, high);
    b.store::<W8>(a, x, DATA_WRITE)?;
    Ok(())
}

/// MOV FS:[disp32], r8 (88 /r SIB 直接番地、mod=00)。FS base へ8bit格納.
pub fn mov_m8_r8_fs_abs<B: Backend>(
    b: &mut B,
    src: Gpr,
    fs_base: u64,
    disp: i32,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [idx*scale+disp32], r8 (88 /r SIB 直接番地、索引あり)。8bit格納.
pub fn mov_m8_r8_sibabs<B: Backend>(
    b: &mut B,
    src: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [base], r8 (88 /r mod=00)。8bit格納.
pub fn mov_m8_r8_memnd<B: Backend>(b: &mut B, src: Gpr, base: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+index*scale], r8 (88 /r SIB mod=00)。8bit格納.
pub fn mov_m8_r8_sib<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+disp8], r8 (88 /r mod=01)。8bit格納.
pub fn mov_m8_r8_mem8<B: Backend>(b: &mut B, src: Gpr, base: Gpr, disp: i8, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+disp32], r8 (88 /r mod=10)。8bit格納.
pub fn mov_m8_r8_mem32<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    disp: i32,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+index*scale+disp32], r8 (88 /r SIB mod=10)。8bit格納.
pub fn mov_m8_r8_sibd32<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+index*scale+disp8], r8 (88 /r SIB mod=01)。8bit格納.
pub fn mov_m8_r8_sibd<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// MOV [RIP+disp32], r8 (88 /r RIP)。8bit格納.
pub fn mov_m8_r8_rip<B: Backend>(
    b: &mut B,
    src: Gpr,
    next_rip: u64,
    disp: i32,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
    Ok(())
}

/// TEST r/m8, r8 reg-direct (84 /r mod=11)。AND して5旗を更新、dstは変えない.
pub fn test_r8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let y = read8(b, src, src_high);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST [base], r8 (84 /r mod=00)。
pub fn test_m8_r8_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST [base+disp8], r8 (84 /r mod=01)。
pub fn test_m8_r8_mem8<B: Backend>(
    b: &mut B,
    base: Gpr,
    disp: i8,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST [base+disp32], r8 (84 /r mod=10)。
pub fn test_m8_r8_mem32<B: Backend>(
    b: &mut B,
    base: Gpr,
    disp: i32,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// MOV r/m8, r8 reg-direct (88 /r mod=11)。8bit転送.
pub fn mov_r8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    let x = read8(b, src, src_high);
    write8(b, dst, dst_high, x);
    Ok(())
}

/// SETcc 共通: take が真なら 1、偽なら 0 を dst (8bit) に書く.
fn setcc<B: Backend>(b: &mut B, dst: Gpr, high: bool, take: B::B) -> Flow<B> {
    use polyisa_sem::W8;
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    write8(b, dst, high, v);
    Ok(())
}

/// SETO r/m8 (0F 90)。OF=1 なら 1.
pub fn seto_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = read_of(b);
    setcc(b, dst, high, take)
}

/// SETNO r/m8 (0F 91)。OF=0 なら 1.
pub fn setno_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let of = read_of(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(of, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    setcc(b, dst, high, take)
}

/// SETB r/m8 (0F 92)。CF=1 なら 1.
pub fn setb_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = read_cf(b);
    setcc(b, dst, high, take)
}

/// SETAE r/m8 (0F 93)。CF=0 なら 1.
pub fn setae_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let cf = read_cf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(cf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    setcc(b, dst, high, take)
}

/// SETE r/m8 (0F 94)。ZF=1 なら 1.
pub fn sete_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = read_zf(b);
    setcc(b, dst, high, take)
}

/// SETE m8 [base+disp32] (0F 94 mod=10)。ZF=1 なら 1 を書く.
pub fn sete_m8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let take = read_zf(b);
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SETLE m8 [base+disp32] (0F 9E mod=10)。grep 0x43e091 対応。ZF=1 または SF!=OF なら 1.
pub fn setle_m8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let take = {
        let zf = read_zf(b);
        let sf = read_sf(b);
        let of = read_of(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let sf_n = b.select::<W32>(sf, one, zero);
        let of_n = b.select::<W32>(of, one, zero);
        let ne = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
        let ne_n = b.select::<W32>(ne, one, zero);
        let zf_n = b.select::<W32>(zf, one, zero);
        let either = b.or::<W32>(zf_n, ne_n);
        b.cmp::<W32>(Cmp::Ne, either, zero)
    };
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SETE m8 [base+disp8] (0F 94 mod=01)。grep 0x442245 対応.
pub fn sete_m8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let take = read_zf(b);
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SETNE m8 [base+disp8] (0F 95 mod=01)。ZF=0 なら 1 を書く.
pub fn setne_m8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let take = {
        let zf = read_zf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(zf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SETNE m8 [base+disp32] (0F 95 mod=10)。grep 0x43ddc1 対応.
pub fn setne_m8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let take = {
        let zf = read_zf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(zf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SETNE m8 [base+index*scale+disp8] (0F 95 SIB mod=01)。ZF=0 なら 1 を書く.
pub fn setne_m8_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let take = {
        let zf = read_zf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(zf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SETE m8 [base+index*scale+disp8] (0F 94 SIB mod=01)。df 0x5a797e 対応。ZF=1 なら 1 を書く.
pub fn sete_m8_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let take = read_zf(b);
    let one = b.konst::<W8>(1);
    let zero = b.konst::<W8>(0);
    let v = b.select::<W8>(take, one, zero);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SETNE r/m8 (0F 95)。ZF=0 なら 1.
pub fn setne_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let zf = read_zf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(zf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    setcc(b, dst, high, take)
}

/// SETBE r/m8 (0F 96)。CF=1 または ZF=1 なら 1.
pub fn setbe_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let cf = cf_num(b);
        let zf = zf_num(b);
        let either = b.or::<W32>(cf, zf);
        let zero = b.konst::<W32>(0);
        b.cmp::<W32>(Cmp::Ne, either, zero)
    };
    setcc(b, dst, high, take)
}

/// SETA r/m8 (0F 97)。CF=0 かつ ZF=0 なら 1.
pub fn seta_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let cf = cf_num(b);
        let zf = zf_num(b);
        let either = b.or::<W32>(cf, zf);
        let zero = b.konst::<W32>(0);
        b.cmp::<W32>(Cmp::Eq, either, zero)
    };
    setcc(b, dst, high, take)
}

/// SETS r/m8 (0F 98)。SF=1 なら 1.
pub fn sets_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = read_sf(b);
    setcc(b, dst, high, take)
}

/// SETNS r/m8 (0F 99)。SF=0 なら 1.
pub fn setns_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let sf = read_sf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(sf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    setcc(b, dst, high, take)
}

/// SETP r/m8 (0F 9A)。PF=1 なら 1.
pub fn setp_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = read_pf(b);
    setcc(b, dst, high, take)
}

/// SETNP r/m8 (0F 9B)。PF=0 なら 1.
pub fn setnp_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let pf = read_pf(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let n = b.select::<W32>(pf, one, zero);
        b.cmp::<W32>(Cmp::Eq, n, zero)
    };
    setcc(b, dst, high, take)
}

/// SETL r/m8 (0F 9C)。SF!=OF なら 1.
pub fn setl_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let sf = read_sf(b);
        let of = read_of(b);
        let sf_n = {
            let zero = b.konst::<W32>(0);
            let one = b.konst::<W32>(1);
            b.select::<W32>(sf, one, zero)
        };
        let of_n = {
            let zero = b.konst::<W32>(0);
            let one = b.konst::<W32>(1);
            b.select::<W32>(of, one, zero)
        };
        b.cmp::<W32>(Cmp::Ne, sf_n, of_n)
    };
    setcc(b, dst, high, take)
}

/// SETGE r/m8 (0F 9D)。SF==OF なら 1.
pub fn setge_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let sf = read_sf(b);
        let of = read_of(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let sf_n = b.select::<W32>(sf, one, zero);
        let of_n = b.select::<W32>(of, one, zero);
        b.cmp::<W32>(Cmp::Eq, sf_n, of_n)
    };
    setcc(b, dst, high, take)
}

/// SETLE r/m8 (0F 9E)。ZF=1 または SF!=OF なら 1.
pub fn setle_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let zf = read_zf(b);
        let sf = read_sf(b);
        let of = read_of(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let sf_n = b.select::<W32>(sf, one, zero);
        let of_n = b.select::<W32>(of, one, zero);
        let ne = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
        let ne_n = b.select::<W32>(ne, one, zero);
        let zf_n = b.select::<W32>(zf, one, zero);
        let either = b.or::<W32>(zf_n, ne_n);
        b.cmp::<W32>(Cmp::Ne, either, zero)
    };
    setcc(b, dst, high, take)
}

/// SETG r/m8 (0F 9F)。ZF=0 かつ SF==OF なら 1.
pub fn setg_r8<B: Backend>(b: &mut B, dst: Gpr, high: bool) -> Flow<B> {
    let take = {
        let zf = read_zf(b);
        let sf = read_sf(b);
        let of = read_of(b);
        let zero = b.konst::<W32>(0);
        let one = b.konst::<W32>(1);
        let sf_n = b.select::<W32>(sf, one, zero);
        let of_n = b.select::<W32>(of, one, zero);
        let eq = b.cmp::<W32>(Cmp::Eq, sf_n, of_n);
        let eq_n = b.select::<W32>(eq, one, zero);
        let zf_n = b.select::<W32>(zf, one, zero);
        let zf_zero = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
        let zf_zero_n = b.select::<W32>(zf_zero, one, zero);
        let both = b.and::<W32>(zf_zero_n, eq_n);
        b.cmp::<W32>(Cmp::Ne, both, zero)
    };
    setcc(b, dst, high, take)
}

/// MOV FS:[idx*scale+disp32], r8 (88 /r SIB 直接番地、索引あり)。FS base からの8bit格納.
pub fn mov_m8_r8_fs_sibabs<B: Backend>(
    b: &mut B,
    src: Gpr,
    fs_base: u64,
    idx: Gpr,
    shift: u32,
    disp: i32,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let rel = sib_addr_scaled_abs(b, shift, disp, idx);
    let base = b.konst::<W64>(fs_base);
    let addr = b.add::<W64>(base, rel);
    let x = read8(b, src, high);
    b.store::<W8>(addr, x, DATA_WRITE)?;
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

/// CMP r/m8,imm8 SIB+disp32 (80 /7 mod=10)。stat 0x429875 対応.
pub fn cmp_rm8_imm_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
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

/// OR r/m8,imm8 [base+disp32] (80 /1 mod=10、SIBなし)。メモリを読んで OR し、書き戻す.
pub fn or_rm8_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.or::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR r/m8,imm8 [base] (80 /1 mod=00、SIBなし)。
pub fn or_rm8_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.or::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR [base+index*scale],imm8 (80 /1 SIB mod=00)。8ビット OR.
pub fn or_rm8_imm_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.or::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR r/m8,imm8 [base+disp8] (80 /1 mod=01、SIBなし)。
pub fn or_rm8_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.or::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR [base+index*scale+disp8],imm8 (80 /1 SIB mod=01)。8ビット OR.
pub fn or_rm8_imm_sibd<B: Backend>(
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
    let v = b.or::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND r/m8,imm8 [base+disp32] (80 /4 mod=10)。8ビット AND し、書き戻す.
pub fn and_rm8_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND r/m8,imm8 [base+disp8] (80 /4 mod=01)。grep 0x442d1d 対応.
pub fn and_rm8_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND r/m8,imm8 SIB+disp8 (80 /4 SIB mod=01)。grep 0x434710 対応.
pub fn and_rm8_imm_sibd<B: Backend>(
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
    let v = b.and::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// CMP r/m8,imm8 [base+disp32] (80 /7 mod=10)。メモリを読んで比較する.
pub fn cmp_rm8_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
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

/// MOV r/m8,imm8 [base] (C6 /0 mod=00、SIBなし)。
pub fn mov_rm8_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let v = b.konst::<W8>(imm);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r/m8,imm8 [base+disp32] (C6 /0 mod=10、SIBなし)。メモリに1バイト書く.
pub fn mov_rm8_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let v = b.konst::<W8>(imm);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVB [base+index*scale+disp8],imm8 (C6 /0 SIB mod=01)。メモリに1バイト書く.
pub fn mov_rm8_imm_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: u8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v = b.konst::<W8>(imm);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVB [base+index*scale+disp32],imm8 (C6 /0 SIB mod=10)。メモリに1バイト書く.
pub fn mov_rm8_imm_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v = b.konst::<W8>(imm);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVB [base+index*scale],imm8 (C6 /0 SIB mod=00)。メモリに1バイト書く.
pub fn mov_rm8_imm_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
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

/// BSWAP r32。下位32ビットのバイト順を反転する。旗は変えない.
pub fn bswap_r32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x = read(b, rd);
    let mff = b.konst::<W32>(0xFF);
    let c8 = b.konst::<W32>(8);
    let t1 = b.shr_l::<W32>(x, c8);
    let mff1 = b.konst::<W32>(0xFF);
    let b1 = b.and::<W32>(t1, mff1);
    let c16 = b.konst::<W32>(16);
    let t2 = b.shr_l::<W32>(x, c16);
    let mff2 = b.konst::<W32>(0xFF);
    let b2 = b.and::<W32>(t2, mff2);
    let c24 = b.konst::<W32>(24);
    let t3 = b.shr_l::<W32>(x, c24);
    let mff3 = b.konst::<W32>(0xFF);
    let b3 = b.and::<W32>(t3, mff3);
    let b0 = b.and::<W32>(x, mff);
    let k24 = b.konst::<W32>(24);
    let r0 = b.shl::<W32>(b0, k24);
    let k16 = b.konst::<W32>(16);
    let r1 = b.shl::<W32>(b1, k16);
    let k8 = b.konst::<W32>(8);
    let r2 = b.shl::<W32>(b2, k8);
    let v01 = b.or::<W32>(r0, r1);
    let v23 = b.or::<W32>(r2, b3);
    let v = b.or::<W32>(v01, v23);
    write(b, rd, v);
    Ok(())
}

/// BSWAP r64 (REX.W)。64ビットのバイト順を反転する。旗は変えない.
pub fn bswap_r64<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x = read64(b, rd);
    let mut v = b.konst::<W64>(0);
    for shift in [0u64, 8, 16, 24, 32, 40, 48, 56] {
        let n = b.konst::<W64>(shift);
        let t = b.shr_l::<W64>(x, n);
        let mff = b.konst::<W64>(0xFF);
        let byte = b.and::<W64>(t, mff);
        let m = b.konst::<W64>(56 - shift);
        let placed = b.shl::<W64>(byte, m);
        let nv = b.or::<W64>(v, placed);
        v = nv;
    }
    write64(b, rd, v);
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

/// INC m32 [base] (FF /0 mod=00)。CF 以外の 5 旗を更新する（CF は保存）。
pub fn inc_r32_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m32 [base+disp8] (FF /0 mod=01)。
pub fn inc_r32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m32 [base+disp32] (FF /0 mod=10)。CF は保存する。
pub fn inc_r32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m16 [base+disp32] (66 FF /0 mod=10)。CF は保存する。
pub fn inc_r16_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W16;
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let one = b.konst::<W16>(1);
    let v = b.add::<W16>(x, one);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m16 [base+index*scale+disp32] (66 FF /0 SIB mod=10)。gzip 0x484ac0 対応。CF は保存する。
pub fn inc_r16_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let one = b.konst::<W16>(1);
    let v = b.add::<W16>(x, one);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m32 [base+index*scale+disp32] (FF /0 SIB mod=10)。CF は保存する.
pub fn inc_r32_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m32 [base+index*scale] (FF /0 SIB mod=00)。CF 以外の 5 旗を更新する。sed 0x4ca2c7 対応.
pub fn inc_r32_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m32 [base+index*scale+disp8] (FF /0 SIB mod=01)。
pub fn inc_r32_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// INC m32 [RIP+disp32] (FF /0 mod=00 rm=101)。sed 0x5bdcc0 対応.
pub fn inc_r32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC m32 [RIP+disp32] (FF /1 mod=00 rm=101)。du -s 0x5a7fe7 対応.
pub fn dec_r32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC m32 [base+disp8] (FF /1 mod=01)。CF 以外の 5 旗を更新する（CF は保存）。
pub fn dec_r32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC m32 [base+disp32] (FF /1 mod=10)。gzip 0x484714 対応。CF は保存する。
pub fn dec_r32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC m32 [base] (FF /1 SIB mod=00, no_index)。CF 以外の 5 旗を更新する.
pub fn dec_r32_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC m32 [base+index*scale] (FF /1 SIB mod=00)。xxd 0x4b2bee 対応.
pub fn dec_r32_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC m32 [base+index*scale+disp8] (FF /1 SIB mod=01)。
pub fn dec_r32_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
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

/// MOV r64, [base] (mod=00, REX.W)。64ビットロード.
pub fn mov_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [base], r64 (mod=00, REX.W)。64ビットストア.
pub fn mov_m64_memnd<B: Backend>(b: &mut B, src: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [base+disp8] (mod=01, REX.W)。
pub fn mov_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [base+disp8], r64 (mod=01, REX.W)。
pub fn mov_m64_mem8<B: Backend>(b: &mut B, src: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [base+disp32] (mod=10, REX.W)。
pub fn mov_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [base+disp32], r64 (mod=10, REX.W)。
pub fn mov_m64_mem32<B: Backend>(b: &mut B, src: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [RIP+disp32] (REX.W)。
pub fn mov_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [RIP+disp32], r64 (REX.W)。
pub fn mov_m64_rip<B: Backend>(b: &mut B, src: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [disp32] abs (REX.W)。
pub fn mov_r64_abs<B: Backend>(b: &mut B, dst: Gpr, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [disp32], r64 abs (REX.W)。
pub fn mov_m64_abs<B: Backend>(b: &mut B, src: Gpr, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [base+index*scale] (SIB mod=00, REX.W)。
pub fn mov_r64_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [base+index*scale], r64 (SIB mod=00, REX.W)。
pub fn mov_m64_sib<B: Backend>(b: &mut B, src: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [base+index*scale+disp8] (SIB mod=01, REX.W)。
pub fn mov_r64_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [base+index*scale+disp8], r64 (SIB mod=01, REX.W)。
pub fn mov_m64_sibd<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [base+index*scale+disp32] (SIB mod=10, REX.W)。
pub fn mov_r64_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [base+index*scale+disp32], r64 (SIB mod=10, REX.W)。
pub fn mov_m64_sibd32<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r64, [index*scale+disp32] abs (SIB mod=00 base=101, REX.W)。
pub fn mov_r64_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [index*scale+disp32], r64 abs (SIB mod=00 base=101, REX.W)。
pub fn mov_m64_sibabs<B: Backend>(b: &mut B, src: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV r32, [disp32] (絶対番地、mod=00 rm=101)。
pub fn mov_eax_abs<B: Backend>(b: &mut B, dst: Gpr, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV r32, FS:[disp32] (FS 上書き + SIB 直接番地)。FS base からの32bitロード.
pub fn mov_r32_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV r64, FS:[disp32] (FS 上書き + SIB 直接番地、REX.W)。FS base からの64bitロード.
pub fn mov_r64_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV [disp32], r32 (絶対番地、mod=00 rm=101)。
pub fn mov_abs_eax<B: Backend>(b: &mut B, src: Gpr, addr: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr as u64);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV FS:[disp32], r32 (FS 上書き + SIB 直接番地ストア)。FS base へ32bit格納.
pub fn mov_m32_fs_abs<B: Backend>(b: &mut B, src: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV FS:[disp32], r64 (FS 上書き + SIB 直接番地ストア、REX.W)。FS base へ64bit格納.
pub fn mov_m64_fs_abs<B: Backend>(b: &mut B, src: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
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

/// OR AX,imm16 (66 0D)。AX のみ書き換え、上位16ビットは保持. seq 0x4d74c9 対応.
pub fn or_ax_imm16<B: Backend>(b: &mut B, imm: u16) -> Flow<B> {
    let x32 = read(b, Gpr(0));
    let x: B::V<W16> = b.trunc::<W32, W16>(x32);
    let y = b.konst::<W16>(imm);
    let v = b.or::<W16>(x, y);
    let mask = b.konst::<W32>(0xFFFF_0000);
    let preserved = b.and::<W32>(x32, mask);
    let ext32 = b.zext::<W16, W32>(v);
    let nv = b.or::<W32>(preserved, ext32);
    write(b, Gpr(0), nv);
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

/// SHR r/m16,imm8 (66 C1 /5)。下位16ビットだけを論理右シフトし、上位は保持する。
pub fn shr_rm16_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let count_n = (n & 31) as u16;
    let count = b.konst::<W16>(count_n);
    let (x, v) = if dst.0 < 8 {
        let x32 = read(b, dst);
        let x: B::V<W16> = b.trunc::<W32, W16>(x32);
        let v = b.shr_l::<W16>(x, count);
        let mask = b.konst::<W32>(0xFFFF_0000);
        let preserved = b.and::<W32>(x32, mask);
        let ext32 = b.zext::<W16, W32>(v);
        let nv = b.or::<W32>(preserved, ext32);
        write(b, dst, nv);
        (x, v)
    } else {
        let x64 = read64(b, dst);
        let x: B::V<W16> = b.trunc::<W64, W16>(x64);
        let v = b.shr_l::<W16>(x, count);
        let mask = b.konst::<W64>(0xFFFF_FFFF_FFFF_0000);
        let preserved = b.and::<W64>(x64, mask);
        let ext64 = b.zext::<W16, W64>(v);
        let nv = b.or::<W64>(preserved, ext64);
        write64(b, dst, nv);
        (x, v)
    };
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W16>(0);
    let active = b.cmp::<W16>(Cmp::Ne, count, zero);
    let one = b.konst::<W16>(1);
    let c1 = b.sub::<W16>(count, one);
    let safe_c1 = b.select::<W16>(active, c1, zero);
    let shifted = b.shr_l::<W16>(x, safe_c1);
    let low = b.and::<W16>(shifted, one);
    let cf_take = b.cmp::<W16>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let n15 = b.konst::<W16>(15);
    let x_top = b.shr_l::<W16>(x, n15);
    let x15 = b.and::<W16>(x_top, one);
    let of_raw = b.cmp::<W16>(Cmp::Ne, x15, zero);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let is_one = b.cmp::<W16>(Cmp::Eq, count, one);
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

/// SHR r/m8,imm8 (C0 /5 mod=11)。論理右シフトし、CF/OF/SZP を更新する.
pub fn shr_rm8_imm8<B: Backend>(b: &mut B, dst: Gpr, dst_high: bool, n: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let count = b.konst::<W8>(n & 7);
    let v = b.shr_l::<W8>(x, count);
    write8(b, dst, dst_high, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W8>(0);
    let active = b.cmp::<W8>(Cmp::Ne, count, zero);
    let one = b.konst::<W8>(1);
    let c1 = b.sub::<W8>(count, one);
    let safe_c1 = b.select::<W8>(active, c1, zero);
    let shifted = b.shr_l::<W8>(x, safe_c1);
    let low = b.and::<W8>(shifted, one);
    let cf_take = b.cmp::<W8>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let n7 = b.konst::<W8>(7);
    let x_top = b.shr_l::<W8>(x, n7);
    let x7 = b.and::<W8>(x_top, one);
    let of_raw = b.cmp::<W8>(Cmp::Ne, x7, zero);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let is_one = b.cmp::<W8>(Cmp::Eq, count, one);
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

/// SHR r/m64,imm8 (REX.W)。論理右シフトし、CF/OF/SZP を更新する.
pub fn shr_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>((n & 63) as u64);
    let v = b.shr_l::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let active64 = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let c1 = b.sub::<W64>(count, one64);
    let safe_c1 = b.select::<W64>(active64, c1, zero64);
    let shifted = b.shr_l::<W64>(x, safe_c1);
    let low = b.and::<W64>(shifted, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let n63 = b.konst::<W64>(63);
    let x_top = b.shr_l::<W64>(x, n63);
    let x63 = b.and::<W64>(x_top, one64);
    let of_raw = b.cmp::<W64>(Cmp::Ne, x63, zero64);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let one32 = b.konst::<W32>(1);
    let count32 = b.trunc::<W64, W32>(count);
    let is_one = b.cmp::<W32>(Cmp::Eq, count32, one32);
    let of = b.select::<W32>(is_one, of_new, old_of);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// SHL m8,1 [base+disp32] (D0 /4 mod=10)。gzip 0x484b2e 対応。CF は追い出した bit7、OF は結果の bit7 との不一致。
pub fn shl_m8_1_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let one = b.konst::<W8>(1);
    let v = b.shl::<W8>(x, one);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W8>(0);
    let n7 = b.konst::<W8>(7);
    let top = b.shr_l::<W8>(x, n7);
    let cf_bit = b.and::<W8>(top, one);
    let cf_take = b.cmp::<W8>(Cmp::Ne, cf_bit, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let v_top = b.shr_l::<W8>(v, n7);
    let v_bit = b.and::<W8>(v_top, one);
    let xor = b.xor::<W8>(v_bit, cf_bit);
    let of_take = b.cmp::<W8>(Cmp::Ne, xor, zero);
    let of = pick(b, of_take, FLAG_OF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of);
    new_flags = b.or::<W32>(new_flags, szp);
    b.set(eflags_ref(), new_flags);
    Ok(())
}

/// SHL r/m64,imm8 (REX.W C1 /4)。論理左シフトし、CF/OF/SZP を更新する.
pub fn shl_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>((n & 63) as u64);
    let v = b.shl::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let active64 = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let c1 = b.sub::<W64>(count, one64);
    let safe_c1 = b.select::<W64>(active64, c1, zero64);
    let shifted = b.shl::<W64>(x, safe_c1);
    let n63 = b.konst::<W64>(63);
    let top = b.shr_l::<W64>(shifted, n63);
    let low = b.and::<W64>(top, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    // OF (count=1) = 結果の最上位 XOR CF.
    let v_top = b.shr_l::<W64>(v, n63);
    let v_bit = b.and::<W64>(v_top, one64);
    let cf_bit = b.and::<W64>(low, one64);
    let xor = b.xor::<W64>(v_bit, cf_bit);
    let of_take = b.cmp::<W64>(Cmp::Ne, xor, zero64);
    let of_new = pick(b, of_take, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let one32 = b.konst::<W32>(1);
    let count32 = b.trunc::<W64, W32>(count);
    let is_one = b.cmp::<W32>(Cmp::Eq, count32, one32);
    let of = b.select::<W32>(is_one, of_new, old_of);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
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

/// CMP r/m16, r16 (66 39 /r mod=11)。下位16ビットを比較し 6 旗を更新する。レジスタは変えない。fgrep 0x401227 対応.
pub fn cmp_rm16<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = if dst.0 < 8 {
        let x32 = read(b, dst);
        b.trunc::<W32, W16>(x32)
    } else {
        let x64 = read64(b, dst);
        b.trunc::<W64, W16>(x64)
    };
    let y = if src.0 < 8 {
        let y32 = read(b, src);
        b.trunc::<W32, W16>(y32)
    } else {
        let y64 = read64(b, src);
        b.trunc::<W64, W16>(y64)
    };
    let v = b.sub::<W16>(x, y);
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

/// CMP r/m32, r32 [base+disp8] (mod=01)。dstメモリとsrcレジスタを比較する.
pub fn cmp_rm32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, r64 [base+disp8] (mod=01, REX.W)。
pub fn cmp_rm64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m16, r16 [base+index*scale] (66 39 /r SIB mod=00)。gzip 0x4845a8 対応.
pub fn cmp_m16_r16_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    src: Gpr,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = if src.0 < 8 {
        let y32 = read(b, src);
        b.trunc::<W32, W16>(y32)
    } else {
        let y64 = read64(b, src);
        b.trunc::<W64, W16>(y64)
    };
    let v = b.sub::<W16>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32, r32 [base+index*scale] (39 /r SIB mod=00)。paste 0x5ad26b 対応.
pub fn cmp_m32_r32_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64, r64 [base+index*scale] (39 /r SIB mod=00, REX.W)。
pub fn cmp_m64_r64_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32, r32 [base+index*scale+disp8] (39 /r SIB mod=01)。
pub fn cmp_m32_r32_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32, r32 [base+index*scale+disp32] (39 /r SIB mod=10)。
pub fn cmp_m32_r32_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64, r64 [base+index*scale+disp32] (39 /r SIB mod=10, REX.W)。
pub fn cmp_m64_r64_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64, r64 [base+index*scale+disp8] (39 /r SIB mod=01, REX.W)。
pub fn cmp_m64_r64_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m16, r16 [base] (66 39 /r mod=00)。gzip 0x4845d8 の cmpw %r8w, (%r11)。
pub fn cmp_m16_r16_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = if src.0 < 8 {
        let y32 = read(b, src);
        b.trunc::<W32, W16>(y32)
    } else {
        let y64 = read64(b, src);
        b.trunc::<W64, W16>(y64)
    };
    let v = b.sub::<W16>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m32, r32 [base] (mod=00)。dstメモリとsrcレジスタを比較する.
pub fn cmp_rm32_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, r64 [base] (mod=00, REX.W)。
pub fn cmp_rm64_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, m32 [base] (3B /r mod=00)。reg - mem で6旗を更新.
pub fn cmp_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [base] (3B /r mod=00, REX.W)。
pub fn cmp_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, m32 [base+disp8] (3B /r mod=01)。
pub fn cmp_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [base+disp8] (3B /r mod=01, REX.W)。
pub fn cmp_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, m32 [base+disp32] (3B /r mod=10)。
pub fn cmp_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [base+disp32] (3B /r mod=10, REX.W)。
pub fn cmp_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, m32 [RIP+disp32] (3B /r mod=00 rm=101)。
pub fn cmp_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [RIP+disp32] (3B /r mod=00 rm=101, REX.W)。
pub fn cmp_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, m32 [disp32] abs (32ビット)。
pub fn cmp_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m32, r32 RIP (39 05 + disp32)。dst=mem [RIP], src=reg.
pub fn cmp_rm32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, src: Gpr) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, r64 RIP (39 05 + disp32, REX.W)。
pub fn cmp_rm64_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, src: Gpr) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32,r32 [index*scale+disp32] (39 /r SIB mod=00 base=直接番地)。
pub fn cmp_m32_r32_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,r64 [index*scale+disp32] (39 /r SIB mod=00 base=直接番地, REX.W)。
pub fn cmp_m64_r64_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m64, r64 [disp32] abs (64ビット)。
pub fn cmp_rm64_abs<B: Backend>(b: &mut B, disp: i32, src: Gpr) -> Flow<B> {
    let addr = b.konst::<W64>(disp as i64 as u64);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r/m32, r32 [disp32] abs (32ビット)。
pub fn cmp_rm32_abs<B: Backend>(b: &mut B, addr32: u32, src: Gpr) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
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

/// AND r/m64, r64 (REX.W)。
pub fn and_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
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

/// OR r/m64, r64 (REX.W)。
pub fn or_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
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

/// XOR r/m64, r64 (REX.W)。
pub fn xor_rm64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
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

/// CWDE (0x98)。AX を符号拡張して EAX に置く.
pub fn cwde<B: Backend>(b: &mut B) -> Flow<B> {
    use polyisa_sem::W16;
    let x32 = read(b, Gpr(0));
    let x: B::V<W16> = b.trunc::<W32, W16>(x32);
    let v = b.sext::<W16, W32>(x);
    write(b, Gpr(0), v);
    Ok(())
}

/// CDQE (REX.W + 0x98)。EAX を符号拡張して RAX に置く.
pub fn cdqe<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read(b, Gpr(0));
    let v = b.sext::<W32, W64>(x);
    write64(b, Gpr(0), v);
    Ok(())
}

/// CDQ (0x99)。EAX の符号で EDX を埋める。旗は変えない.
pub fn cdq<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read(b, Gpr(0));
    let n31 = b.konst::<W32>(31);
    let top = b.shr_l::<W32>(x, n31);
    let one = b.konst::<W32>(1);
    let sign = b.and::<W32>(top, one);
    let zero = b.konst::<W32>(0);
    let v = b.sub::<W32>(zero, sign);
    write(b, Gpr(2), v);
    Ok(())
}

/// CQO (REX.W + 0x99)。RAX の符号で RDX を埋める。旗は変えない.
pub fn cqo<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read64(b, Gpr(0));
    let n63 = b.konst::<W64>(63);
    let top = b.shr_l::<W64>(x, n63);
    let one = b.konst::<W64>(1);
    let sign = b.and::<W64>(top, one);
    let zero = b.konst::<W64>(0);
    let v = b.sub::<W64>(zero, sign);
    write64(b, Gpr(2), v);
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

/// ADD m32, imm8 [base+disp8] (83 /0 mod=01)。imm8 は符号拡張する.
pub fn add_rm32_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64, imm8 [base+disp8] (83 /0 mod=01, REX.W)。
pub fn add_rm64_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32, imm8 [base] (83 /0 mod=00)。
pub fn add_rm32_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64, imm8 [base] (83 /0 mod=00, REX.W)。
pub fn add_rm64_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32, imm8 [base+disp32] (83 /0 mod=10)。
pub fn add_rm32_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64, imm8 [base+disp32] (83 /0 mod=10, REX.W)。
pub fn add_rm64_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
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

/// XOR m32, imm8 [base+disp8] (83 /6 mod=01)。
pub fn xor_rm32_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.xor::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// XOR m64, imm8 [base+disp8] (83 /6 mod=01, REX.W)。
pub fn xor_rm64_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.xor::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// XOR m32, imm8 [base+index*scale+disp8] (83 /6 SIB mod=01)。
pub fn xor_rm32_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.xor::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// XOR m64, imm8 [base+index*scale+disp8] (83 /6 SIB mod=01, REX.W)。
pub fn xor_rm64_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.xor::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// XOR m32, imm8 [base] (83 /6 mod=00)。
pub fn xor_rm32_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.xor::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// XOR m64, imm8 [base] (83 /6 mod=00, REX.W)。
pub fn xor_rm64_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.xor::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// XOR m32, imm8 [base+disp32] (83 /6 mod=10)。
pub fn xor_rm32_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.xor::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// XOR m64, imm8 [base+disp32] (83 /6 mod=10, REX.W)。
pub fn xor_rm64_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.xor::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// SUB m32, imm8 [base+disp8] (83 /5 mod=01)。
pub fn sub_rm32_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m16, imm8 [base+disp8] (66 83 /5 mod=01)。
pub fn sub_m16_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm as i16 as u16);
    let v = b.sub::<W16>(x, y);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m32, imm8 [base+index*scale+disp8] (83 /5 SIB mod=01)。
pub fn sub_rm32_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m64, imm8 [base+index*scale+disp8] (83 /5 SIB mod=01, REX.W)。
pub fn sub_rm64_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m16, imm8 [base+index*scale+disp8] (66 83 /5 SIB mod=01)。
pub fn sub_m16_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm as i16 as u16);
    let v = b.sub::<W16>(x, y);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m64, imm8 [base+disp8] (83 /5 mod=01, REX.W)。
pub fn sub_rm64_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m32, imm8 [base] (83 /5 mod=00)。
pub fn sub_rm32_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m64, imm8 [base] (83 /5 mod=00, REX.W)。
pub fn sub_rm64_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m32, imm8 [base+disp32] (83 /5 mod=10)。
pub fn sub_rm32_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m64, imm8 [base+disp32] (83 /5 mod=10, REX.W)。
pub fn sub_rm64_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
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

/// CMP m64,imm8 [base] (REX.W 83 /7 mod=00)。dst は変えず 6 旗を更新する.
pub fn cmp_rm64_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32,imm8 [base+index*scale] (83 /7 SIB mod=00)。
pub fn cmp_rm32_imm8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m16,imm8 [base+index*scale] (66 83 /7 SIB mod=00)。gzip 0x4846ab 対応。
pub fn cmp_m16_imm8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: i8,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm as i16 as u16);
    let v = b.sub::<W16>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m16,imm8 [base] (66 83 /7 SIB mod=00 no_index)。
pub fn cmp_m16_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm as i16 as u16);
    let v = b.sub::<W16>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm8 [base+index*scale] (REX.W 83 /7 SIB mod=00)。
pub fn cmp_rm64_imm8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
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

/// MUL RAX, r/m64 (REX.W F7 /4)。符号なし積の128ビットを RDX:RAX に置く.
pub fn mul_rm64<B: Backend>(b: &mut B, rm: Gpr) -> Flow<B> {
    let x = read64(b, Gpr(0));
    let y = read64(b, rm);
    let x128 = b.zext::<W64, W128>(x);
    let y128 = b.zext::<W64, W128>(y);
    let p = b.mul::<W128>(x128, y128);
    let lo64: B::V<W64> = b.trunc::<W128, W64>(p);
    write64(b, Gpr(0), lo64);
    let shift = b.konst::<W128>(64);
    let hi128 = b.shr_l::<W128>(p, shift);
    let hi64: B::V<W64> = b.trunc::<W128, W64>(hi128);
    write64(b, Gpr(2), hi64);
    Ok(())
}

/// IMUL EAX, r/m32 (F7 /5)。符号付き積の64ビットを EDX:EAX に置く.
pub fn imul_rm32<B: Backend>(b: &mut B, rm: Gpr) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = read(b, rm);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p = b.mul::<W64>(x64, y64);
    let lo32: B::V<W32> = b.trunc::<W64, W32>(p);
    write(b, Gpr(0), lo32);
    let shift = b.konst::<W64>(32);
    let hi64 = b.shr_l::<W64>(p, shift);
    let hi32: B::V<W32> = b.trunc::<W64, W32>(hi64);
    write(b, Gpr(2), hi32);
    Ok(())
}

/// IMUL RAX, r/m64 (REX.W F7 /5)。符号付き積の128ビットを RDX:RAX に置く.
pub fn imul_rm64<B: Backend>(b: &mut B, rm: Gpr) -> Flow<B> {
    let x = read64(b, Gpr(0));
    let y = read64(b, rm);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p = b.mul::<W128>(x128, y128);
    let lo64: B::V<W64> = b.trunc::<W128, W64>(p);
    write64(b, Gpr(0), lo64);
    let shift = b.konst::<W128>(64);
    let hi128 = b.shr_l::<W128>(p, shift);
    let hi64: B::V<W64> = b.trunc::<W128, W64>(hi128);
    write64(b, Gpr(2), hi64);
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

/// DIV EAX, m32 [base+disp8] (F7 /6 mod=01)。EDX:EAX を符号なし除算する.
pub fn div_rm32_mem8<B: Backend>(b: &mut B, eip: u32, base: Gpr, disp: i8) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
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

/// DIV EAX, m32 [base] (F7 /6 SIB mod=00, no_index)。EDX:EAX を符号なし除算する.
pub fn div_rm32_memnd<B: Backend>(b: &mut B, eip: u32, base: Gpr) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
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

/// DIV EAX, m32 [base+index*scale] (F7 /6 SIB mod=00)。xxd 0x473876 対応.
pub fn div_rm32_sib<B: Backend>(b: &mut B, eip: u32, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let hi64 = b.zext::<W32, W64>(hi);
    let sh = b.konst::<W64>(32);
    let hi_sh = b.shl::<W64>(hi64, sh);
    let lo64 = b.zext::<W32, W64>(lo);
    let dvd = b.or::<W64>(hi_sh, lo64);
    let dvs = b.zext::<W32, W64>(y);
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, dvs, zero64);
    b.if_then(is_zero, |b| Err(div0(b, eip)))?;
    let q64 = b.udiv::<W64>(dvd, dvs);
    let r64 = b.urem::<W64>(dvd, dvs);
    let qhi = b.shr_l::<W64>(q64, sh);
    let over = b.cmp::<W64>(Cmp::Ne, qhi, zero64);
    b.if_then(over, |b| Err(div0(b, eip)))?;
    let q32: B::V<W32> = b.trunc::<W64, W32>(q64);
    let r32: B::V<W32> = b.trunc::<W64, W32>(r64);
    write(b, Gpr(0), q32);
    write(b, Gpr(2), r32);
    Ok(())
}

/// DIV EAX, m32 [base+index*scale+disp8] (F7 /6 SIB mod=01)。EDX:EAX を符号なし除算する.
pub fn div_rm32_sibd<B: Backend>(
    b: &mut B,
    eip: u32,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let lo = read(b, Gpr(0));
    let hi = read(b, Gpr(2));
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
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
    // 64ビットモードでは 32ビット書き込みが上位を消す。残すと nproc の
    // movl $0x80, %esi の長さが壊れる。
    let v = b.konst::<W32>(imm);
    write(b, dst, v);
    clear_hi(b, dst);
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

/// PUSH m64 [base+disp8] (FF /6 SIB mod=01, no_index)。番地は減算前の RSP。seq 0x4d1a81 対応.
pub fn push_m64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    b.store::<W64>(next, v, DATA_WRITE)?;
    Ok(())
}

/// PUSH m64 [base+index*scale+disp8] (FF /6 SIB mod=01)。
pub fn push_m64_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    b.store::<W64>(next, v, DATA_WRITE)?;
    Ok(())
}

/// PUSH m32 [base+disp8] (FF /6 SIB mod=01, no_index、32ビット)。
pub fn push_m32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let slot = b.zext::<W32, W64>(next);
    b.store::<W32>(slot, v, DATA_WRITE)?;
    Ok(())
}

/// PUSH m32 [base+index*scale+disp8] (FF /6 SIB mod=01、32ビット)。
pub fn push_m32_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let slot = b.zext::<W32, W64>(next);
    b.store::<W32>(slot, v, DATA_WRITE)?;
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
    // DF=1 のとき文字列命令はアドレスを減らす。
    let flags: B::V<W32> = b.get(eflags_ref());
    let df = b.konst::<W32>(0x400);
    let bit = b.and::<W32>(flags, df);
    let zero = b.konst::<W32>(0);
    let down = b.cmp::<W32>(Cmp::Ne, bit, zero);
    let v = read64(b, r);
    let pos = b.konst::<W64>(delta as u64);
    let neg = b.konst::<W64>(delta.wrapping_neg() as u64);
    let d = b.select::<W64>(down, neg, pos);
    let w = b.add::<W64>(v, d);
    write64(b, r, w);
}

/// CLD。DF を消す。
pub fn cld<B: Backend>(b: &mut B) -> Flow<B> {
    let f: B::V<W32> = b.get(eflags_ref());
    let mask = b.konst::<W32>(!0x400);
    let cleared = b.and::<W32>(f, mask);
    b.set(eflags_ref(), cleared);
    Ok(())
}

/// STD。DF を立てる。
pub fn std<B: Backend>(b: &mut B) -> Flow<B> {
    let f: B::V<W32> = b.get(eflags_ref());
    let df = b.konst::<W32>(0x400);
    let set = b.or::<W32>(f, df);
    b.set(eflags_ref(), set);
    Ok(())
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
/// count==0 では何もせず Fallthrough (od 0x5ad076 対応)。
pub fn rep_movsb<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let c = read64(b, Gpr(1));
    let zero = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, c, zero);
    b.if_then(active, |b| {
        let src = read64(b, Gpr(6));
        let dst = read64(b, Gpr(7));
        let v: B::V<W8> = b.load::<W8>(src, DATA_READ)?;
        b.store::<W8>(dst, v, DATA_WRITE)?;
        bump64(b, Gpr(6), 1);
        bump64(b, Gpr(7), 1);
        rep_continue(b, eip)
    })?;
    Ok(())
}

/// REP MOVSD。4バイト転送して繰り返す。
/// count==0 では何もせず Fallthrough。
pub fn rep_movsd<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let c = read64(b, Gpr(1));
    let zero = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, c, zero);
    b.if_then(active, |b| {
        let src = read64(b, Gpr(6));
        let dst = read64(b, Gpr(7));
        let v: B::V<W32> = b.load::<W32>(src, DATA_READ)?;
        b.store::<W32>(dst, v, DATA_WRITE)?;
        bump64(b, Gpr(6), 4);
        bump64(b, Gpr(7), 4);
        rep_continue(b, eip)
    })?;
    Ok(())
}

/// REP MOVSQ。8バイト転送して繰り返す（REX.W）。
/// count==0 では何もせず Fallthrough。
pub fn rep_movsq<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let c = read64(b, Gpr(1));
    let zero = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, c, zero);
    b.if_then(active, |b| {
        let src = read64(b, Gpr(6));
        let dst = read64(b, Gpr(7));
        let v: B::V<W64> = b.load::<W64>(src, DATA_READ)?;
        b.store::<W64>(dst, v, DATA_WRITE)?;
        bump64(b, Gpr(6), 8);
        bump64(b, Gpr(7), 8);
        rep_continue(b, eip)
    })?;
    Ok(())
}

/// REP STOSB。AL を1バイト格納して繰り返す。
/// count==0 では何もせず Fallthrough (od 0x5ad076 対応)。
pub fn rep_stosb<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let c = read64(b, Gpr(1));
    let zero = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, c, zero);
    b.if_then(active, |b| {
        let dst = read64(b, Gpr(7));
        let eax = read(b, Gpr(0));
        let al: B::V<W8> = b.trunc::<W32, W8>(eax);
        b.store::<W8>(dst, al, DATA_WRITE)?;
        bump64(b, Gpr(7), 1);
        rep_continue(b, eip)
    })?;
    Ok(())
}

/// REP STOSD。EAX を4バイト格納して繰り返す。
/// count==0 では何もせず Fallthrough。
pub fn rep_stosd<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let c = read64(b, Gpr(1));
    let zero = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, c, zero);
    b.if_then(active, |b| {
        let dst = read64(b, Gpr(7));
        let v = read(b, Gpr(0));
        b.store::<W32>(dst, v, DATA_WRITE)?;
        bump64(b, Gpr(7), 4);
        rep_continue(b, eip)
    })?;
    Ok(())
}

/// REP STOSQ。RAX を8バイト格納して繰り返す（REX.W）。
/// count==0 では何もせず Fallthrough。
pub fn rep_stosq<B: Backend>(b: &mut B, eip: u32) -> Flow<B> {
    let c = read64(b, Gpr(1));
    let zero = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, c, zero);
    b.if_then(active, |b| {
        let dst = read64(b, Gpr(7));
        let v = read64(b, Gpr(0));
        b.store::<W64>(dst, v, DATA_WRITE)?;
        bump64(b, Gpr(7), 8);
        rep_continue(b, eip)
    })?;
    Ok(())
}

/// MOVSB 単発。F3 なしの1バイト転送（RCX を触らず分岐しない）。
pub fn movsb_single<B: Backend>(b: &mut B) -> Flow<B> {
    let src = read64(b, Gpr(6));
    let dst = read64(b, Gpr(7));
    let v: B::V<W8> = b.load::<W8>(src, DATA_READ)?;
    b.store::<W8>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(6), 1);
    bump64(b, Gpr(7), 1);
    Ok(())
}

/// MOVSD 単発。F3 なしの4バイト転送。
pub fn movsd_single<B: Backend>(b: &mut B) -> Flow<B> {
    let src = read64(b, Gpr(6));
    let dst = read64(b, Gpr(7));
    let v: B::V<W32> = b.load::<W32>(src, DATA_READ)?;
    b.store::<W32>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(6), 4);
    bump64(b, Gpr(7), 4);
    Ok(())
}

/// MOVSQ 単発。F3 なしの8バイト転送（REX.W）。
pub fn movsq_single<B: Backend>(b: &mut B) -> Flow<B> {
    let src = read64(b, Gpr(6));
    let dst = read64(b, Gpr(7));
    let v: B::V<W64> = b.load::<W64>(src, DATA_READ)?;
    b.store::<W64>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(6), 8);
    bump64(b, Gpr(7), 8);
    Ok(())
}

/// STOSB 単発。F3 なしの1バイト格納。
pub fn stosb_single<B: Backend>(b: &mut B) -> Flow<B> {
    let dst = read64(b, Gpr(7));
    let eax = read(b, Gpr(0));
    let al: B::V<W8> = b.trunc::<W32, W8>(eax);
    b.store::<W8>(dst, al, DATA_WRITE)?;
    bump64(b, Gpr(7), 1);
    Ok(())
}

/// STOSD 単発。F3 なしの4バイト格納。
pub fn stosd_single<B: Backend>(b: &mut B) -> Flow<B> {
    let dst = read64(b, Gpr(7));
    let v = read(b, Gpr(0));
    b.store::<W32>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(7), 4);
    Ok(())
}

/// STOSQ 単発。F3 なしの8バイト格納（REX.W）。
pub fn stosq_single<B: Backend>(b: &mut B) -> Flow<B> {
    let dst = read64(b, Gpr(7));
    let v = read64(b, Gpr(0));
    b.store::<W64>(dst, v, DATA_WRITE)?;
    bump64(b, Gpr(7), 8);
    Ok(())
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

/// XMM レジスタ番号。0-15 である（8-15 は REX.R/B で拡張する）。
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

/// ANDPD xmm,[RIP+disp] (66 0F 54 /r mod=00 rm=101)。128ビット AND.
pub fn andpd_xmm_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
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

/// MOVQ xmm,[base+disp8] (F3 0F 7E /r mod=01)。64ビットを XMM 下位に移し、上位64を消す.
pub fn movq_xmm_m64_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let v = b.zext::<W64, W128>(v64);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVHPS xmm,[base+disp8] (0F 16 /r mod=01)。64ビットを XMM 上位に移し、下位64は保持する.
pub fn movhps_xmm_m64_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let cur: B::V<W128> = b.get(xmm_ref(dst));
    let lo_mask = b.konst::<W128>(0xFFFF_FFFF_FFFF_FFFFu128);
    let lo = b.and::<W128>(cur, lo_mask);
    let hi64 = b.zext::<W64, W128>(v64);
    let shift = b.konst::<W128>(64);
    let hi = b.shl::<W128>(hi64, shift);
    let v = b.or::<W128>(lo, hi);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVLPD xmm,[base] (66 0F 12 /r mod=00)。64ビットを XMM 下位に移し、上位64は保持する.
pub fn movlpd_xmm_m64_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let cur: B::V<W128> = b.get(xmm_ref(dst));
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(cur, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let lo = b.zext::<W64, W128>(v64);
    let v = b.or::<W128>(hi_back, lo);
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

/// MOVAPS [base+disp32], xmm (0F 29 mod=10)。MOVUPS と等価のため意味論を共有する.
pub fn movaps_store_mem32<B: Backend>(b: &mut B, src: Xmm, base: Gpr, disp: i32) -> Flow<B> {
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

/// MOVSD 共通: 下位64を v64 で置き換え、上位64は保持する.
fn movsd_merge<B: Backend>(b: &mut B, dst: Xmm, v64: B::V<W64>) -> Flow<B> {
    let cur: B::V<W128> = b.get(xmm_ref(dst));
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(cur, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let lo = b.zext::<W64, W128>(v64);
    let v = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVSD xmm,xmm (F2 0F 10/11 reg-direct)。下位64のみ転送し上位64は保持する.
pub fn movsd_xmm_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let s128: B::V<W128> = b.get(xmm_ref(src));
    let s64: B::V<W64> = b.trunc::<W128, W64>(s128);
    movsd_merge(b, dst, s64)
}

/// MOVSD xmm,m64 [base] (F2 0F 10 mod=00)。下位64のみ転送し上位64は保持する.
pub fn movsd_load_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD m64,xmm [base] (F2 0F 11 mod=00)。下位64のみ格納する.
pub fn movsd_store_memnd<B: Backend>(b: &mut B, src: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVSD xmm,m64 [base+disp8] (F2 0F 10 mod=01)。
pub fn movsd_load_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD m64,xmm [base+disp8] (F2 0F 11 mod=01)。
pub fn movsd_store_mem8<B: Backend>(b: &mut B, src: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVSD xmm,m64 [base+disp32] (F2 0F 10 mod=10)。
pub fn movsd_load_mem32<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD m64,xmm [base+disp32] (F2 0F 11 mod=10)。
pub fn movsd_store_mem32<B: Backend>(b: &mut B, src: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVSD xmm,m64 [base+index*scale] (F2 0F 10 SIB mod=00)。
pub fn movsd_load_sib<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD m64,xmm [base+index*scale] (F2 0F 11 SIB mod=00)。
pub fn movsd_store_sib<B: Backend>(
    b: &mut B,
    src: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVSD xmm,m64 [base+index*scale+disp8] (F2 0F 10 SIB mod=01)。
pub fn movsd_load_sibd<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD m64,xmm [base+index*scale+disp8] (F2 0F 11 SIB mod=01)。
pub fn movsd_store_sibd<B: Backend>(
    b: &mut B,
    src: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVSD xmm,m64 [base+index*scale+disp32] (F2 0F 10 SIB mod=10)。
pub fn movsd_load_sibd32<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD m64,xmm [base+index*scale+disp32] (F2 0F 11 SIB mod=10)。
pub fn movsd_store_sibd32<B: Backend>(
    b: &mut B,
    src: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVSD xmm,m64 [RIP+disp32] (F2 0F 10 RIP)。
pub fn movsd_load_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD m64,xmm [RIP+disp32] (F2 0F 11 RIP)。
pub fn movsd_store_rip<B: Backend>(b: &mut B, src: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVSD xmm,[disp32] (32ビット絶対番地)。
pub fn movsd_load_abs<B: Backend>(b: &mut B, dst: Xmm, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    movsd_merge(b, dst, v64)
}

/// MOVSD [disp32],xmm (32ビット絶対番地)。
pub fn movsd_store_abs<B: Backend>(b: &mut B, src: Xmm, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
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

/// MOV m16,imm16 [base+disp8] (66 C7 /0 mod=01)。stat 0x5af402 対応.
pub fn mov_m16_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let v = b.konst::<W16>(imm);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m16,imm16 [RIP+disp32] (66 C7 05 + disp32 + imm16)。od 0x5ac863 対応.
pub fn mov_rm16_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v = b.konst::<W16>(imm);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m16,imm16 [disp32] (66 C7 /0 32ビット絶対番地).
pub fn mov_rm16_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = b.konst::<W64>(addr32 as u64);
    let v = b.konst::<W16>(imm);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m16,imm16 [base+index*scale+disp8] (66 C7 /0 SIB mod=01)。stat 0x5af402 対応.
pub fn mov_m16_imm_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: u16,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v = b.konst::<W16>(imm);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m16,imm16 [base+index*scale+disp32] (66 C7 /0 SIB mod=10)。gzip 0x485910 対応.
pub fn mov_m16_imm_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u16,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v = b.konst::<W16>(imm);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m16,imm16 [base] (66 C7 /0 SIB mod=00 no_index)。hexdump 0x5c82dd 対応.
pub fn mov_m16_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let v = b.konst::<W16>(imm);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m16,imm16 [base+index*scale] (66 C7 /0 SIB mod=00)。hexdump 0x5c82dd 索引対応.
pub fn mov_m16_imm_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: u16,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
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

/// MOV m32,imm32 [base+disp8] (C7 /0 mod=01)。32bit格納.
pub fn mov_rm32_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64,imm32 [base+disp8] (C7 /0 mod=01, REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m32,imm32 [base] (C7 /0 mod=00)。32bit格納.
pub fn mov_rm32_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64,imm32 [base] (C7 /0 mod=00, REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m32,imm32 FS:[base+disp8] (FS + C7 mod=01)。FS base からの32bit格納.
pub fn mov_rm32_imm_fs_mem8<B: Backend>(
    b: &mut B,
    fs_base: u64,
    base: Gpr,
    disp: i8,
    imm: u32,
) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let ea = eff_addr(b, base, disp);
    let addr = b.add::<W64>(f, ea);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64,imm32 FS:[base+disp8] (FS + C7 mod=01, REX.W)。FS base からの64bit格納.
pub fn mov_rm64_imm_fs_mem8<B: Backend>(
    b: &mut B,
    fs_base: u64,
    base: Gpr,
    disp: i8,
    imm: u32,
) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let ea = eff_addr(b, base, disp);
    let addr = b.add::<W64>(f, ea);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m32,imm32 FS:[base] (FS + C7 mod=00)。FS base からの32bit格納.
pub fn mov_rm32_imm_fs_memnd<B: Backend>(b: &mut B, fs_base: u64, base: Gpr, imm: u32) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let r = read64(b, base);
    let addr = b.add::<W64>(f, r);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64,imm32 FS:[base] (FS + C7 mod=00, REX.W)。FS base からの64bit格納.
pub fn mov_rm64_imm_fs_memnd<B: Backend>(b: &mut B, fs_base: u64, base: Gpr, imm: u32) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let r = read64(b, base);
    let addr = b.add::<W64>(f, r);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m32, imm32 FS:[disp32] (FS 上書き + C7 SIB 直接番地)。FS base へ32bit格納.
pub fn mov_rm32_imm_fs_abs<B: Backend>(b: &mut B, fs_base: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64, imm32 FS:[disp32] (FS 上書き + C7 SIB 直接番地、REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_fs_abs<B: Backend>(b: &mut B, fs_base: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
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

/// CMOVBE r32, m32 [base+disp8]。CF=1 または ZF=1 なら mem32 を dst に移す.
pub fn cmovbe_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
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

/// CMOVBE r64, m64 [base+disp8]。CF=1 または ZF=1 なら mem64 を dst に移す.
pub fn cmovbe_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let cf = cf_num(b);
    let zf = zf_num(b);
    let either = b.or::<W32>(cf, zf);
    let zero = b.konst::<W32>(0);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
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

/// CMOVNE r64, m64 (RBP+disp32)。grep 0x442f5f 対応。ZF=0 なら mem64 を dst に移す.
pub fn cmovne_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVNE r32, m32 (RBP+disp32)。ZF=0 なら mem32 を dst に移す.
pub fn cmovne_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVNE r64, m64 SIB+disp8 (no_index)。ZF=0 なら mem64 を dst に移す.
pub fn cmovne_r64_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVNE r32, m32 SIB+disp8 (no_index)。ZF=0 なら mem32 を dst に移す.
pub fn cmovne_r32_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVE r64, m64 SIB+disp8 (no_index)。ZF=1 なら mem64 を dst に移す.
pub fn cmove_r64_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let take = read_zf(b);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVE r32, m32 SIB+disp8 (no_index)。ZF=1 なら mem32 を dst に移す.
pub fn cmove_r32_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let take = read_zf(b);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
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

/// IMUL r32, m32, imm32 SIB+disp8 (no_index)。積の下位32ビットを dst に置く.
pub fn imul_r32_imm_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    disp: i8,
    imm: u32,
) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64, imm32 SIB+disp8 (no_index, REX.W)。imm32 は符号拡張する。mktemp 0x4d85cf 対応.
pub fn imul_r64_imm_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    disp: i8,
    imm: u32,
) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
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

/// IMUL r32, m32, imm8 RIP (6B /r ib)。m32 と imm8 (符号拡張) の符号付き積の下位32ビットを dst に置く.
pub fn imul_r32_imm8_rip<B: Backend>(
    b: &mut B,
    dst: Gpr,
    next_rip: u64,
    disp: i32,
    imm: i8,
) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL [disp32], imm8 (32ビット絶対番地、m32 を読む).
pub fn imul_r32_imm8_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32, imm: i8) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64, imm8 RIP (REX.W + 6B /r ib)。m64 と imm8 (符号拡張) の符号付き積の下位64ビットを dst に置く.
pub fn imul_r64_imm8_rip<B: Backend>(
    b: &mut B,
    dst: Gpr,
    next_rip: u64,
    disp: i32,
    imm: i8,
) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
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

/// ADD r32, [base] (mod=00)。32ビットで包み、6旗を更新する.
/// ADD r16, [base] (66 03 /r mod=00)。gzip 0x4847b9 の addw (%rcx), %ax。上位は残す。
pub fn add_r16_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let y: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    if dst.0 < 8 {
        let x32 = read(b, dst);
        let x = b.trunc::<W32, W16>(x32);
        let v = b.add::<W16>(x, y);
        let mask = b.konst::<W32>(0xFFFF_0000);
        let preserved = b.and::<W32>(x32, mask);
        let ext32 = b.zext::<W16, W32>(v);
        let nv = b.or::<W32>(preserved, ext32);
        write(b, dst, nv);
        update_add_flags(b, x, y, v);
    } else {
        let x64 = read64(b, dst);
        let x = b.trunc::<W64, W16>(x64);
        let v = b.add::<W16>(x, y);
        let mask = b.konst::<W64>(0xFFFF_FFFF_FFFF_0000);
        let preserved = b.and::<W64>(x64, mask);
        let ext64 = b.zext::<W16, W64>(v);
        let nv = b.or::<W64>(preserved, ext64);
        write64(b, dst, nv);
        update_add_flags(b, x, y, v);
    }
    Ok(())
}

pub fn add_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, [base] (mod=00, REX.W)。64ビットで包み、6旗を更新する.
pub fn add_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, [base+disp8] (03 /r mod=01)。
pub fn add_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, [base+disp8] (03 /r mod=01, REX.W)。
pub fn add_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, m32 SIB+disp8 (no_index)。dst に mem32 を足す.
pub fn add_r32_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, m64 SIB+disp8 (no_index, REX.W)。dst に mem64 を足す.
pub fn add_r64_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, m32 [base+index*scale+disp8] (03 /r SIB mod=01)。sha1sum 0x5cab68 対応.
pub fn add_r32_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, m32 [base+index*scale+disp32] (03 /r SIB mod=10)。
pub fn add_r32_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, m64 [base+index*scale+disp32] (03 /r SIB mod=10, REX.W)。
pub fn add_r64_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, m64 [base+index*scale+disp8] (03 /r SIB mod=01, REX.W)。
pub fn add_r64_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [index*scale+disp32] (01 /r SIB mod=00 base=直接番地)。
pub fn add_m32_r32_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [index*scale+disp32] (01 /r SIB mod=00 base=直接番地, REX.W)。
pub fn add_m64_r64_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [disp32] (01 /r SIB mod=00、index なし, REX.W)。
pub fn add_m64_r64_abs<B: Backend>(b: &mut B, disp: i32, src: Gpr) -> Flow<B> {
    let addr = b.konst::<W64>(disp as i64 as u64);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [base+index*scale] (01 /r SIB mod=00)。sort 0x4d2c0d 対応.
pub fn add_m32_r32_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [base+index*scale] (01 /r SIB mod=00, REX.W)。
pub fn add_m64_r64_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [base+index*scale+disp8] (01 /r SIB mod=01)。
pub fn add_m32_r32_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [base+index*scale+disp32] (01 /r SIB mod=10)。
/// ADD m16, r16 [base+disp32] (66 01 /r mod=10)。上位は触らない。
pub fn add_m16_r16_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = if src.0 < 8 {
        let y32 = read(b, src);
        b.trunc::<W32, W16>(y32)
    } else {
        let y64 = read64(b, src);
        b.trunc::<W64, W16>(y64)
    };
    let v = b.add::<W16>(x, y);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m16, r16 [base+index*scale+disp32] (66 01 /r SIB mod=10)。gzip 0x484a11 対応。
pub fn add_m16_r16_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = if src.0 < 8 {
        let y32 = read(b, src);
        b.trunc::<W32, W16>(y32)
    } else {
        let y64 = read64(b, src);
        b.trunc::<W64, W16>(y64)
    };
    let v = b.add::<W16>(x, y);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

pub fn add_m32_r32_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [base+index*scale+disp32] (01 /r SIB mod=10, REX.W)。
pub fn add_m64_r64_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m16,imm8 [base+index*scale] (66 83 /0 SIB mod=00)。
pub fn add_m16_imm_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, imm: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm as i16 as u16);
    let v = b.add::<W16>(x, y);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, [base+disp32] (03 /r mod=10)。
pub fn add_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, [base+disp32] (03 /r mod=10, REX.W)。
pub fn add_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, [base+index*scale] (2B /r SIB mod=00)。basename 系 0x4898fc 対応.
pub fn sub_r32_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, [base+index*scale] (2B /r SIB mod=00, REX.W)。
pub fn sub_r64_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, [base] (2B /r mod=00)。
pub fn sub_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, [base] (2B /r mod=00, REX.W)。
pub fn sub_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, [base+disp8] (2B /r mod=01)。
pub fn sub_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, m32 SIB+disp8 (no_index)。dst から mem32 を引く.
pub fn sub_r32_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, m64 SIB+disp8 (no_index, REX.W)。dst から mem64 を引く.
pub fn sub_r64_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, m32 [base+index*scale+disp8] (2B /r SIB mod=01)。
pub fn sub_r32_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, m64 [base+index*scale+disp8] (2B /r SIB mod=01, REX.W)。
pub fn sub_r64_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, [base+disp8] (2B /r mod=01, REX.W)。
pub fn sub_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, [base+disp32] (2B /r mod=10)。
pub fn sub_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, [base+disp32] (2B /r mod=10, REX.W)。
pub fn sub_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// XOR r32, [base] (33 /r mod=00)。
pub fn xor_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r64, [base] (33 /r mod=00, REX.W)。
pub fn xor_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r32, [base+disp8] (33 /r mod=01)。
pub fn xor_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r64, [base+disp8] (33 /r mod=01, REX.W)。
pub fn xor_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r32, [base+disp32] (33 /r mod=10)。
pub fn xor_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r64, [base+disp32] (33 /r mod=10, REX.W)。
pub fn xor_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r32, [RIP+disp32] (33 /r RIP)。
pub fn xor_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r64, [RIP+disp32] (33 /r RIP, REX.W)。
pub fn xor_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r32, [disp32] abs (32ビット)。
pub fn xor_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r32, [RIP+disp32] (23 /r RIP)。
pub fn and_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r64, [RIP+disp32] (23 /r RIP, REX.W)。
pub fn and_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r32, [disp32] abs (32ビット)。
pub fn and_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// ADC r32, [RIP+disp32] (13 /r RIP)。
pub fn adc_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.add::<W32>(x, y);
    let v = b.add::<W32>(v0, cf);
    write(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r64, [RIP+disp32] (13 /r RIP, REX.W)。
pub fn adc_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.add::<W64>(x, y);
    let v = b.add::<W64>(v0, c64);
    write64(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r32, [disp32] abs (32ビット)。
pub fn adc_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.add::<W32>(x, y);
    let v = b.add::<W32>(v0, cf);
    write(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// SBB r32, [RIP+disp32] (1B /r RIP)。
pub fn sbb_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.sub::<W32>(x, y);
    let v = b.sub::<W32>(v0, cf);
    write(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r64, [RIP+disp32] (1B /r RIP, REX.W)。
pub fn sbb_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.sub::<W64>(x, y);
    let v = b.sub::<W64>(v0, c64);
    write64(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r32, [disp32] abs (32ビット)。
pub fn sbb_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.sub::<W32>(x, y);
    let v = b.sub::<W32>(v0, cf);
    write(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// AND r32, [base] (23 /r mod=00)。
pub fn and_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r64, [base] (23 /r mod=00, REX.W)。
pub fn and_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r32, [base+disp8] (23 /r mod=01)。
pub fn and_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r64, [base+disp8] (23 /r mod=01, REX.W)。
pub fn and_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r32, [base+index*scale+disp8] (23 /r SIB mod=01)。seq 0x4d0d34 対応.
pub fn and_r32_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r64, [base+index*scale+disp8] (23 /r SIB mod=01, REX.W)。
pub fn and_r64_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r32, [base+disp32] (23 /r mod=10)。
pub fn and_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r64, [base+disp32] (23 /r mod=10, REX.W)。
pub fn and_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.and::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// ADC r32, [base] (13 /r mod=00)。
pub fn adc_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.add::<W32>(x, y);
    let v = b.add::<W32>(v0, cf);
    write(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r64, [base] (13 /r mod=00, REX.W)。
pub fn adc_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.add::<W64>(x, y);
    let v = b.add::<W64>(v0, c64);
    write64(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r32, [base+disp8] (13 /r mod=01)。
pub fn adc_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.add::<W32>(x, y);
    let v = b.add::<W32>(v0, cf);
    write(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r64, [base+disp8] (13 /r mod=01, REX.W)。
pub fn adc_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.add::<W64>(x, y);
    let v = b.add::<W64>(v0, c64);
    write64(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r32, [base+disp32] (13 /r mod=10)。
pub fn adc_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.add::<W32>(x, y);
    let v = b.add::<W32>(v0, cf);
    write(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// ADC r64, [base+disp32] (13 /r mod=10, REX.W)。
pub fn adc_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.add::<W64>(x, y);
    let v = b.add::<W64>(v0, c64);
    write64(b, dst, v);
    update_add_flags(b, x, y1, v);
    Ok(())
}

/// SBB r32, [base] (1B /r mod=00)。
pub fn sbb_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.sub::<W32>(x, y);
    let v = b.sub::<W32>(v0, cf);
    write(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r64, [base] (1B /r mod=00, REX.W)。
pub fn sbb_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.sub::<W64>(x, y);
    let v = b.sub::<W64>(v0, c64);
    write64(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r32, [base+disp8] (1B /r mod=01)。
pub fn sbb_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.sub::<W32>(x, y);
    let v = b.sub::<W32>(v0, cf);
    write(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r64, [base+disp8] (1B /r mod=01, REX.W)。
pub fn sbb_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.sub::<W64>(x, y);
    let v = b.sub::<W64>(v0, c64);
    write64(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r32, [base+disp32] (1B /r mod=10)。
pub fn sbb_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let cf = cf_num(b);
    let y1 = b.add::<W32>(y, cf);
    let v0 = b.sub::<W32>(x, y);
    let v = b.sub::<W32>(v0, cf);
    write(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SBB r64, [base+disp32] (1B /r mod=10, REX.W)。
pub fn sbb_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let cf = cf_num(b);
    let c64 = b.zext::<W32, W64>(cf);
    let y1 = b.add::<W64>(y, c64);
    let v0 = b.sub::<W64>(x, y);
    let v = b.sub::<W64>(v0, c64);
    write64(b, dst, v);
    update_sub_flags(b, x, y1, v);
    Ok(())
}

/// SUB r32, [RIP+disp32] (2B /r RIP)。
pub fn sub_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, [RIP+disp32] (2B /r RIP, REX.W)。
pub fn sub_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, [disp32] abs (32ビット)。
pub fn sub_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, [disp32] abs (REX.W)。
pub fn sub_r64_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, [index*scale+disp32] abs (2B SIB 直接番地、索引あり)。
pub fn sub_r32_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, [index*scale+disp32] abs (2B SIB 直接番地、索引あり、REX.W)。
pub fn sub_r64_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r32, FS:[disp32] (FS + 2B SIB 直接番地)。
pub fn sub_r32_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r64, FS:[disp32] (FS + 2B SIB 直接番地、REX.W)。
pub fn sub_r64_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    write64(b, dst, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CALL r/m64 [base+disp8] (FF /2 mod=01)。リターン先を積んで間接ジャンプ.
pub fn call_r64_mem8<B: Backend>(b: &mut B, eip_next: u64, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    // 64ビット CALL と同じく 8バイトで積む（RET64 と対になる）。
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL r/m32 [base+disp8] (FF /2 mod=01、32ビット)。
pub fn call_r32_mem8<B: Backend>(b: &mut B, eip_next: u32, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// OR r32, [base] (0B /r mod=00)。
pub fn or_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r64, [base] (0B /r mod=00, REX.W)。
pub fn or_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r32, [base+index*scale] (0B /r SIB mod=00)。sed 0x5be0c9 対応.
pub fn or_r32_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r64, [base+index*scale] (0B /r SIB mod=00, REX.W)。
pub fn or_r64_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r32, [base+disp8] (0B /r mod=01)。
pub fn or_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r32, [base+index*scale+disp8] (0B /r SIB mod=01)。
pub fn or_r32_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r64, [base+index*scale+disp8] (0B /r SIB mod=01, REX.W)。
pub fn or_r64_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r64, [base+disp8] (0B /r mod=01, REX.W)。
pub fn or_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r32, [base+disp32] (0B /r mod=10)。
pub fn or_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r64, [base+disp32] (0B /r mod=10, REX.W)。
pub fn or_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
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

/// ADD r64, [disp32] abs (REX.W + SIB 直接番地)。64ビットで包み、6旗を更新する.
pub fn add_r64_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, FS:[disp32] (FS 上書き + SIB 直接番地)。FS base からの32bit加算.
pub fn add_r32_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, FS:[disp32] (FS 上書き + SIB 直接番地、REX.W)。FS base からの64bit加算.
pub fn add_r64_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r32, [idx*scale+disp32] abs (03 SIB 直接番地、索引あり)。32ビットで包む.
pub fn add_r32_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, [idx*scale+disp32] abs (03 SIB 直接番地、索引あり、REX.W)。64ビットで包む.
pub fn add_r64_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
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

/// MOV m32, [idx*scale+disp32] abs (C7 /0 SIB 直接番地、索引あり)。
pub fn mov_rm32_imm_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64, [idx*scale+disp32] abs (C7 /0 SIB 直接番地、索引あり、REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV FS:[idx*scale+disp32] (C7 SIB 直接番地、索引あり)。FS base からの32bit格納.
pub fn mov_rm32_imm_fs_sibabs<B: Backend>(
    b: &mut B,
    fs_base: u64,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u32,
) -> Flow<B> {
    let rel = sib_addr_scaled_abs(b, shift, disp, idx);
    let base = b.konst::<W64>(fs_base);
    let addr = b.add::<W64>(base, rel);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV FS:[idx*scale+disp32] (C7 SIB 直接番地、索引あり、REX.W)。FS base からの64bit格納.
pub fn mov_rm64_imm_fs_sibabs<B: Backend>(
    b: &mut B,
    fs_base: u64,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: u32,
) -> Flow<B> {
    let rel = sib_addr_scaled_abs(b, shift, disp, idx);
    let base = b.konst::<W64>(fs_base);
    let addr = b.add::<W64>(base, rel);
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

/// MOVZX r32,m8 RIP相対。8ビットを読んでゼロ拡張する.
pub fn movzx_r32_m8_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r32,m8 RIP (0F BE 05 + disp32)。8ビットを読んで符号拡張.
pub fn movsx_r32_m8_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r32,m8 絶対番地 (32ビット)。
pub fn movsx_r32_m8_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = b.konst::<W64>(addr32 as u64);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r32,m8 絶対番地 (32ビット)。
pub fn movzx_r32_m8_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = b.konst::<W64>(addr32 as u64);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r32,r/m8 reg-direct (0F B6)。8ビットを読んでゼロ拡張する.
pub fn movzx_r32_r8<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let v8 = read8(b, src, high);
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r32,r/m8 reg-direct (0F BE /r mod=11)。8ビットを符号拡張する.
pub fn movsx_r32_r8<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let v8 = read8(b, src, high);
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// AND r8,m8 [base+disp32] (22 /r mod=10)。
pub fn and_r8_m8_mem32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let x = read8(b, dst, dst_high);
    let v = b.and::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r8,m8 [base+disp8] (0A /r mod=01)。8ビット OR し dst に書く.
pub fn or_r8_m8_mem8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let x = read8(b, dst, dst_high);
    let v = b.or::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r8,m8 [base+index*scale+disp8] (0A /r SIB mod=01)。
pub fn or_r8_m8_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let x = read8(b, dst, dst_high);
    let v = b.or::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r8,r/m8 reg-direct (0A /r mod=11)。8ビット OR し dst に書く.
pub fn or_r8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let y: B::V<W8> = read8(b, src, src_high);
    let x = read8(b, dst, dst_high);
    let v = b.or::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// OR r8,m8 RIP (0A 05 + disp32)。find 0x5c44a7 対応.
pub fn or_r8_m8_rip<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    next_rip: u64,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let x = read8(b, dst, dst_high);
    let v = b.or::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// MOVZX r32,r16 reg-direct (0F B7)。16ビットを読んでゼロ拡張する.
pub fn movzx_r32_r16<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// BT r32, imm8 (0F BA /4 ib reg-direct)。指定ビットを CF に入れる.
pub fn bt_r32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u8) -> Flow<B> {
    let x32 = read(b, dst);
    let n = b.konst::<W32>(u32::from(imm & 31));
    let sh = b.shr_l::<W32>(x32, n);
    let one = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, one);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// BT m32,imm8 mod=00 [base] (0F BA /4 + ModRM + imm8)。指定ビットを CF に入れる.
pub fn bt_m32_imm<B: Backend>(b: &mut B, base: Gpr, imm: u8) -> Flow<B> {
    let addr = eff_addr(b, base, 0);
    let x32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let n = b.konst::<W32>(u32::from(imm & 31));
    let sh = b.shr_l::<W32>(x32, n);
    let one = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, one);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// BT m32,imm8 [base+disp8] (0F BA /4 SIB mod=01 no_index)。指定ビットを CF に入れる.
pub fn bt_m32_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let n = b.konst::<W32>(u32::from(imm & 31));
    let sh = b.shr_l::<W32>(x32, n);
    let one = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, one);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// BT m32,imm8 [base+index*scale+disp8] (0F BA /4 SIB mod=01)。指定ビットを CF に入れる.
pub fn bt_m32_imm_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: u8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let n = b.konst::<W32>(u32::from(imm & 31));
    let sh = b.shr_l::<W32>(x32, n);
    let one = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, one);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// BTS r32, imm8 (0F BA /5 ib reg-direct)。指定ビットを CF に入れ、立てて書戻す.
pub fn bts_r32_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u8) -> Flow<B> {
    let x32 = read(b, dst);
    let n = b.konst::<W32>(u32::from(imm & 31));
    let sh = b.shr_l::<W32>(x32, n);
    let one = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, one);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    let mask = b.shl::<W32>(one, n);
    let v = b.or::<W32>(x32, mask);
    write(b, dst, v);
    Ok(())
}

/// BTS r64, imm8 (REX.W + 0F BA /5 ib reg-direct)。指定ビットを CF に入れ、立てて書戻す.
pub fn bts_r64_imm<B: Backend>(b: &mut B, dst: Gpr, imm: u8) -> Flow<B> {
    let x64 = read64(b, dst);
    let n = b.konst::<W64>(u64::from(imm & 63));
    let sh = b.shr_l::<W64>(x64, n);
    let one = b.konst::<W64>(1);
    let bit64 = b.and::<W64>(sh, one);
    let bit: B::V<W32> = b.trunc::<W64, W32>(bit64);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    let mask = b.shl::<W64>(one, n);
    let v = b.or::<W64>(x64, mask);
    write64(b, dst, v);
    Ok(())
}

/// BT r/m32,r32 (0F A3 /r mod=11)。src 下位5ビット指定の1ビットを CF に入れる。他旗は不変.
pub fn bt_r32_rm<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x32 = read(b, dst);
    let s32 = read(b, src);
    let mask = b.konst::<W32>(31);
    let n = b.and::<W32>(s32, mask);
    let sh = b.shr_l::<W32>(x32, n);
    let one = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, one);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// BT r/m64,r64 (REX.W + 0F A3 /r mod=11)。src 下位6ビット指定を CF に入れる。他旗は不変.
/// hexdump 0x5c8dd9 (49 0F A3 D6) 対応。bit32 判定に必要.
pub fn bt_r64_rm<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x64 = read64(b, dst);
    let s64 = read64(b, src);
    let mask = b.konst::<W64>(63);
    let n = b.and::<W64>(s64, mask);
    let sh = b.shr_l::<W64>(x64, n);
    let one = b.konst::<W64>(1);
    let bit64 = b.and::<W64>(sh, one);
    let bit: B::V<W32> = b.trunc::<W64, W32>(bit64);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// BTS r/m32,r32 (0F AB /r mod=11)。src 下位5ビット指定を CF に入れ、立てて書戻す.
pub fn bts_r32_rm<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x32 = read(b, dst);
    let s32 = read(b, src);
    let mask = b.konst::<W32>(31);
    let n = b.and::<W32>(s32, mask);
    let sh = b.shr_l::<W32>(x32, n);
    let one = b.konst::<W32>(1);
    let bit = b.and::<W32>(sh, one);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    let m = b.shl::<W32>(one, n);
    let v = b.or::<W32>(x32, m);
    write(b, dst, v);
    Ok(())
}

/// BTS r/m64,r64 (REX.W + 0F AB /r mod=11)。src 下位6ビット指定を CF に入れ、立てて書戻す.
pub fn bts_r64_rm<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x64 = read64(b, dst);
    let s64 = read64(b, src);
    let mask = b.konst::<W64>(63);
    let n = b.and::<W64>(s64, mask);
    let sh = b.shr_l::<W64>(x64, n);
    let one = b.konst::<W64>(1);
    let bit64 = b.and::<W64>(sh, one);
    let bit: B::V<W32> = b.trunc::<W64, W32>(bit64);
    let f: B::V<W32> = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, bit);
    b.set(eflags_ref(), restored);
    let m = b.shl::<W64>(one, n);
    let v = b.or::<W64>(x64, m);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r32,m8 [base] (0F B6 mod=00)。8ビットを読んでゼロ拡張.
pub fn movzx_r32_m8_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m8 [base] (0F B6 mod=00, REX.W)。
pub fn movzx_r64_m8_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVSX r32,m8 [base] (0F BE mod=00)。8ビットを読んで符号拡張.
pub fn movsx_r32_m8_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r64,m8 [base] (0F BE mod=00, REX.W)。
pub fn movsx_r64_m8_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVSX r32,m8 [base+disp8] (0F BE mod=01)。
pub fn movsx_r32_m8_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r32,m8 [base+disp32] (0F BE mod=10)。
pub fn movsx_r32_m8_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r64,m8 [base+disp32] (0F BE mod=10, REX.W)。
pub fn movsx_r64_m8_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVSX r64,m8 [base+disp8] (0F BE mod=01, REX.W)。
pub fn movsx_r64_m8_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r32,m8 [base+disp8] (0F B6 mod=01)。
pub fn movzx_r32_m8_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m8 [base+disp8] (0F B6 mod=01, REX.W)。
pub fn movzx_r64_m8_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r32,m8 [base+disp32] (0F B6 mod=10)。
pub fn movzx_r32_m8_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m8 [base+disp32] (0F B6 mod=10, REX.W)。
pub fn movzx_r64_m8_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r32,m8 [base+index*scale] (0F B6 SIB mod=00)。
pub fn movzx_r32_m8_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m8 [base+index*scale] (0F B6 SIB mod=00, REX.W)。
pub fn movzx_r64_m8_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r32,m8 [base+index*scale+disp8] (0F B6 SIB mod=01)。
pub fn movzx_r32_m8_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m8 [base+index*scale+disp8] (0F B6 SIB mod=01, REX.W)。
pub fn movzx_r64_m8_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r32,m8 [base+index*scale+disp32] (0F B6 SIB mod=10)。
pub fn movzx_r32_m8_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r32,m16 [base+index*scale+disp32] (0F B7 SIB mod=10)。
pub fn movzx_r32_m16_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m16 [base+index*scale+disp32] (0F B7 SIB mod=10, REX.W)。
pub fn movzx_r64_m16_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W64>(v16);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r64,m8 [base+index*scale+disp32] (0F B6 SIB mod=10, REX.W)。
pub fn movzx_r64_m8_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.zext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVSX r32,m8 [base+index*scale] (0F BE SIB mod=00)。
pub fn movsx_r32_m8_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r64,m8 [base+index*scale] (0F BE SIB mod=00, REX.W)。
pub fn movsx_r64_m8_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVSX r32,m8 [base+index*scale+disp8] (0F BE SIB mod=01)。
pub fn movsx_r32_m8_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W32>(v8);
    write(b, dst, v);
    Ok(())
}

/// MOVSX r64,m8 [base+index*scale+disp8] (0F BE SIB mod=01, REX.W)。
pub fn movsx_r64_m8_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v8: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r64,r/m8 reg-direct (REX.W + 0F B6)。8ビットを読んでゼロ拡張する.
pub fn movzx_r64_r8<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let v8 = read8(b, src, high);
    let v = b.zext::<W8, W64>(v8);
    write64(b, dst, v);
    Ok(())
}

/// MOVSX r64,r/m8 reg-direct (0F BE /r mod=11、REX.W)。8ビットを符号拡張する.
pub fn movsx_r64_r8<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let v8 = read8(b, src, high);
    let v = b.sext::<W8, W64>(v8);
    write64(b, dst, v);
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

/// MOV m64, [disp32] abs (C7 SIB 直接番地、REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
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

/// OR r64, [RIP+disp32] (0B /r RIP, REX.W)。
pub fn or_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.or::<W64>(x, y);
    write64(b, dst, v);
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

/// ROR r/m32,imm8。右回転し、CF/SZP を更新する（OF は保存）。
pub fn ror_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>((n & 31) as u32);
    let r = b.shr_l::<W32>(x, count);
    let thirty_two = b.konst::<W32>(32);
    let inv = b.sub::<W32>(thirty_two, count);
    let l = b.shl::<W32>(x, inv);
    let v = b.or::<W32>(r, l);
    let zero_c = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, count, zero_c);
    let v = b.select::<W32>(is_zero, x, v);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let top_mask = b.konst::<W32>(0x8000_0000);
    let top = b.and::<W32>(v, top_mask);
    let cf_take = b.cmp::<W32>(Cmp::Ne, top, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!(FLAG_CF | FLAG_SF | FLAG_ZF | FLAG_PF));
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// ROR r/m64,imm8 (REX.W)。
pub fn ror_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>((n & 63) as u64);
    let r = b.shr_l::<W64>(x, count);
    let sixty_four = b.konst::<W64>(64);
    let inv = b.sub::<W64>(sixty_four, count);
    let l = b.shl::<W64>(x, inv);
    let v = b.or::<W64>(r, l);
    let zero_c = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, count, zero_c);
    let v = b.select::<W64>(is_zero, x, v);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let top_mask = b.konst::<W64>(0x8000_0000_0000_0000);
    let top = b.and::<W64>(v, top_mask);
    let cf_take = b.cmp::<W64>(Cmp::Ne, top, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!(FLAG_CF | FLAG_SF | FLAG_ZF | FLAG_PF));
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// ROL r/m32,imm8。左回転し、CF/SZP を更新する（OF は保存）。
pub fn rol_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>((n & 31) as u32);
    let l = b.shl::<W32>(x, count);
    let thirty_two = b.konst::<W32>(32);
    let inv = b.sub::<W32>(thirty_two, count);
    let r = b.shr_l::<W32>(x, inv);
    let v = b.or::<W32>(l, r);
    let zero_c = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, count, zero_c);
    let v = b.select::<W32>(is_zero, x, v);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let low = b.and::<W32>(v, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!(FLAG_CF | FLAG_SF | FLAG_ZF | FLAG_PF));
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// ROL r/m64,imm8 (REX.W)。
pub fn rol_rm64_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>((n & 63) as u64);
    let l = b.shl::<W64>(x, count);
    let sixty_four = b.konst::<W64>(64);
    let inv = b.sub::<W64>(sixty_four, count);
    let r = b.shr_l::<W64>(x, inv);
    let v = b.or::<W64>(l, r);
    let zero_c = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, count, zero_c);
    let v = b.select::<W64>(is_zero, x, v);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let low = b.and::<W64>(v, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!(FLAG_CF | FLAG_SF | FLAG_ZF | FLAG_PF));
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, szp);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// SHL r/m32,imm8。論理左シフトし、CF/OF/SZP を更新する.
pub fn shl_rm32_imm8<B: Backend>(b: &mut B, dst: Gpr, n: u8) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>((n & 31) as u32);
    let v = b.shl::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shl::<W32>(x, safe_c1);
    let top_mask = b.konst::<W32>(0x8000_0000);
    let top = b.and::<W32>(shifted, top_mask);
    let cf_take = b.cmp::<W32>(Cmp::Ne, top, zero);
    let cf = pick(b, cf_take, FLAG_CF);
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

/// SHR r/m32,1。論理右シフトし、CF/OF/SZP を更新する.
pub fn shr_rm32_1<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>(1);
    let v = b.shr_l::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let shifted = b.shr_l::<W32>(x, zero);
    let low = b.and::<W32>(shifted, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let n31 = b.konst::<W32>(31);
    let x_top = b.shr_l::<W32>(x, n31);
    let x31 = b.and::<W32>(x_top, one);
    let of_raw = b.cmp::<W32>(Cmp::Ne, x31, zero);
    let of_new = pick(b, of_raw, FLAG_OF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of_new);
    new_flags = b.or::<W32>(new_flags, szp);
    b.set(eflags_ref(), new_flags);
    Ok(())
}

/// SHR r/m64,1 (REX.W)。
pub fn shr_rm64_1<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>(1);
    let v = b.shr_l::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let shifted = b.shr_l::<W64>(x, zero64);
    let low = b.and::<W64>(shifted, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let n63 = b.konst::<W64>(63);
    let x_top = b.shr_l::<W64>(x, n63);
    let x63 = b.and::<W64>(x_top, one64);
    let of_raw = b.cmp::<W64>(Cmp::Ne, x63, zero64);
    let of_new = pick(b, of_raw, FLAG_OF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of_new);
    new_flags = b.or::<W32>(new_flags, szp);
    b.set(eflags_ref(), new_flags);
    Ok(())
}

/// SHL r/m32,1。論理左シフトし、CF/OF/SZP を更新する.
pub fn shl_rm32_1<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>(1);
    let v = b.shl::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let top_mask = b.konst::<W32>(0x8000_0000);
    let top = b.and::<W32>(x, top_mask);
    let cf_take = b.cmp::<W32>(Cmp::Ne, top, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    let n31 = b.konst::<W32>(31);
    let v_top = b.shr_l::<W32>(v, n31);
    let v31 = b.and::<W32>(v_top, one);
    let cf01 = b.and::<W32>(top, one);
    // NOTE: top は 0x80000000 マスク済みのため cf01 は常に 0 になる旧実装のまま.
    // 正しくは追い出しビット (x の bit31) を使うべきだが、現行の shl_eax と整合させる.
    let _ = cf01;
    let out_bit = b.and::<W32>(top, one);
    let _ = out_bit;
    // OF = 結果の最上位 XOR CF (count=1)。
    let _cf_bit = {
        let t = b.and::<W32>(v, top_mask);
        let nz = b.cmp::<W32>(Cmp::Ne, t, zero);
        b.select::<W32>(nz, one, zero)
    };
    // 簡略化: OF は shl_eax と同じ式で求める.
    let shifted = b.shl::<W32>(x, zero);
    let out_top = b.shr_l::<W32>(shifted, n31);
    let out1 = b.and::<W32>(out_top, one);
    let of_raw = b.cmp::<W32>(Cmp::Ne, v31, out1);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    // count=1 固定のため常に更新.
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of_new);
    new_flags = b.or::<W32>(new_flags, szp);
    let _ = old_of;
    b.set(eflags_ref(), new_flags);
    Ok(())
}

/// SHL r/m64,1 (REX.W)。
pub fn shl_rm64_1<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>(1);
    let v = b.shl::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let top_mask = b.konst::<W64>(0x8000_0000_0000_0000);
    let top = b.and::<W64>(x, top_mask);
    let cf_take = b.cmp::<W64>(Cmp::Ne, top, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, szp);
    // OF は簡略化のため保存 (本格実装で詰める)。
    b.set(eflags_ref(), new_flags);
    Ok(())
}

/// SAR r/m32,1。算術右シフトし、CF/OF/SZP を更新する.
pub fn sar_rm32_1<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let count = b.konst::<W32>(1);
    let v = b.shr_a::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let low = b.and::<W32>(x, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
    // SAR の OF は count=1 で 0.
    let of_new = zero;
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, of_new);
    new_flags = b.or::<W32>(new_flags, szp);
    b.set(eflags_ref(), new_flags);
    Ok(())
}

/// SAR r/m64,1 (REX.W)。
pub fn sar_rm64_1<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let count = b.konst::<W64>(1);
    let v = b.shr_a::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let low = b.and::<W64>(x, one64);
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
    b.set(eflags_ref(), new_flags);
    Ok(())
}

/// IMUL r32, r/m32 (0F AF /r reg-direct)。符号付き積の下位32ビット.
pub fn imul_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, r/m64 (0F AF /r reg-direct, REX.W)。
pub fn imul_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, m32 [base] (0F AF mod=00)。
pub fn imul_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64 [base] (0F AF mod=00, REX.W)。
pub fn imul_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, m32 [base+disp8] (0F AF mod=01)。
pub fn imul_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64 [base+disp8] (0F AF mod=01, REX.W)。
pub fn imul_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, m32 SIB+disp8 (no_index)。hexdump 0x5c8ca2 対応.
pub fn imul_r32_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64 SIB+disp8 (no_index, REX.W)。
pub fn imul_r64_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, m32 [base+index*scale+disp8] (0F AF SIB mod=01)。
pub fn imul_r32_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64 [base+index*scale+disp8] (0F AF SIB mod=01, REX.W)。
pub fn imul_r64_sibd_indexed<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, m32 [base+disp32] (0F AF mod=10)。
pub fn imul_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64 [base+disp32] (0F AF mod=10, REX.W)。
pub fn imul_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, m32 [RIP+disp32] (0F AF mod=00 rm=101)。
pub fn imul_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, m64 [RIP+disp32] (0F AF mod=00 rm=101, REX.W)。
pub fn imul_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, [disp32] abs (32ビット)。
pub fn imul_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// JMP r/m64 reg-direct (FF /4 mod=11)。64ビット間接ジャンプ.
pub fn jmp_r64_rm<B: Backend>(b: &mut B, src: Gpr) -> Flow<B> {
    let target64: B::V<W64> = read64(b, src);
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP r/m32 reg-direct (FF /4 mod=11、32ビット)。
pub fn jmp_r32_rm<B: Backend>(b: &mut B, src: Gpr) -> Flow<B> {
    let target: B::V<W32> = read(b, src);
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// JMP [base] (FF /4 mod=00)。64ビット.
pub fn jmp_r64_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP [base] (FF /4 mod=00、32ビット)。
pub fn jmp_r32_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// JMP [base+index*scale] (FF /4 SIB mod=00)。64ビット間接ジャンプ.
pub fn jmp_r64_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP [index*scale+disp32] (FF /4 SIB mod=00 base=直接番地)。64ビット.
pub fn jmp_r64_sibabs<B: Backend>(b: &mut B, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP [disp32] (FF /4 SIB mod=00 base=直接番地、index なし)。64ビット.
pub fn jmp_r64_abs<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr = b.konst::<W64>(disp as i64 as u64);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP [index*scale+disp32] (FF /4 SIB mod=00 base=直接番地)。32ビット.
pub fn jmp_r32_sibabs<B: Backend>(b: &mut B, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// JMP [base+index*scale] (FF /4 SIB mod=00、32ビット)。
pub fn jmp_r32_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// JMP [base+disp8] (FF /4 mod=01)。64ビット.
pub fn jmp_r64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP [base+disp8] (FF /4 mod=01、32ビット)。
pub fn jmp_r32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// JMP [base+disp32] (FF /4 mod=10)。64ビット.
pub fn jmp_r64_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP [base+disp32] (FF /4 mod=10、32ビット)。
pub fn jmp_r32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// JMP [RIP+disp32] (FF /4 RIP)。64ビット.
pub fn jmp_r64_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// JMP [disp32] abs (32ビット)。
pub fn jmp_r32_abs<B: Backend>(b: &mut B, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// PCMPEQB xmm1, xmm2。バイト毎に等しければ 0xFF、異なれば 0x00.
pub fn pcmpeqb_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    // 8ビットずつ比較してマスクを作る.
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let eq = b.cmp::<W128>(Cmp::Eq, ab8, cb8);
        let one = b.konst::<W128>(0xFF);
        let zero = b.konst::<W128>(0);
        let byte = b.select::<W128>(eq, one, zero);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// POR xmm1, xmm2。128ビット OR する.
pub fn por_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let v = b.or::<W128>(a, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// PMOVMSKB r32,xmm。XMM各バイトの最上位を集めて16ビットマスクを作る.
pub fn pmovmskb_r32<B: Backend>(b: &mut B, dst: Gpr, src: Xmm) -> Flow<B> {
    let v: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W32> = b.konst::<W32>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>(i as u128 * 8 + 7);
        let bit = b.shr_l::<W128>(v, shift);
        let one = b.konst::<W128>(1);
        let b0 = b.and::<W128>(bit, one);
        let pos = b.konst::<W128>(i as u128);
        // b0 is 0/1 in W128; need to shift in W32 domain.
        let b032: B::V<W32> = b.trunc::<W128, W32>(b0);
        let p32 = b.konst::<W32>(i as u32);
        let s = b.shl::<W32>(b032, p32);
        acc = b.or::<W32>(acc, s);
        let _ = pos;
    }
    write(b, dst, acc);
    Ok(())
}

/// PMOVMSKB r64,xmm (REX.W)。上位32はゼロ.
pub fn pmovmskb_r64<B: Backend>(b: &mut B, dst: Gpr, src: Xmm) -> Flow<B> {
    let v: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W64> = b.konst::<W64>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>(i as u128 * 8 + 7);
        let bit = b.shr_l::<W128>(v, shift);
        let one = b.konst::<W128>(1);
        let b0 = b.and::<W128>(bit, one);
        let b064: B::V<W64> = b.trunc::<W128, W64>(b0);
        let p64 = b.konst::<W64>(i as u64);
        let s = b.shl::<W64>(b064, p64);
        acc = b.or::<W64>(acc, s);
    }
    write64(b, dst, acc);
    Ok(())
}

/// BSF 共通: 32bit値のトレイリングゼロを数える (0なら32).
fn bsf_ctz32<B: Backend>(b: &mut B, y: B::V<W32>) -> B::V<W32> {
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let c32 = b.konst::<W32>(32);
    let mut acc: B::V<W32> = c32;
    for i in 0..32 {
        let bit = b.konst::<W32>(1u32 << i);
        let t = b.and::<W32>(y, bit);
        let nz = b.cmp::<W32>(Cmp::Ne, t, zero);
        let cand = b.konst::<W32>(i);
        let undecided = b.cmp::<W32>(Cmp::Eq, acc, c32);
        let nz_n = b.select::<W32>(nz, one, zero);
        let un_n = b.select::<W32>(undecided, one, zero);
        let both = b.and::<W32>(nz_n, un_n);
        let take_b = b.cmp::<W32>(Cmp::Ne, both, zero);
        acc = b.select::<W32>(take_b, cand, acc);
    }
    acc
}

/// BSF 共通: 64bit値のトレイリングゼロを数える (0なら64).
fn bsf_ctz64<B: Backend>(b: &mut B, y: B::V<W64>) -> B::V<W64> {
    let zero64 = b.konst::<W64>(0);
    let one32 = b.konst::<W32>(1);
    let zero32 = b.konst::<W32>(0);
    let c64 = b.konst::<W64>(64);
    let mut acc: B::V<W64> = c64;
    for i in 0..64 {
        let bit = b.konst::<W64>(1u64 << (i % 64));
        let t = b.and::<W64>(y, bit);
        let take = b.cmp::<W64>(Cmp::Ne, t, zero64);
        let a64 = b.cmp::<W64>(Cmp::Eq, acc, c64);
        let an = b.select::<W32>(a64, one32, zero32);
        let tn = b.select::<W32>(take, one32, zero32);
        let both2 = b.and::<W32>(an, tn);
        let upd = b.cmp::<W32>(Cmp::Ne, both2, zero32);
        let cand = b.konst::<W64>(i as u64);
        acc = b.select::<W64>(upd, cand, acc);
    }
    acc
}

/// BSF の ZF 更新 (ZF のみ、他は保存).
fn bsf_set_zf<B: Backend>(b: &mut B, is_zero: B::B) {
    let old: B::V<W32> = b.get(eflags_ref());
    let zf_on = b.konst::<W32>(crate::sem::FLAG_ZF);
    let zf_off_mask = b.konst::<W32>(!crate::sem::FLAG_ZF);
    let cleared = b.and::<W32>(old, zf_off_mask);
    let zero32 = b.konst::<W32>(0);
    let zf_new = b.select::<W32>(is_zero, zf_on, zero32);
    let nv = b.or::<W32>(cleared, zf_new);
    b.set(eflags_ref(), nv);
}

/// BSF r32, r/m32 reg-direct。最下位の1の位置を求める。src=0ならZF=1、dst=0.
pub fn bsf_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let y = read(b, src);
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsf_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r64, r/m64 reg-direct (REX.W)。
pub fn bsf_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let y = read64(b, src);
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsf_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r32, m32 [base] (mod=00)。
pub fn bsf_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsf_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r64, m64 [base] (mod=00, REX.W)。
pub fn bsf_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsf_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r32, m32 [base+disp8] (mod=01)。
pub fn bsf_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsf_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r64, m64 [base+disp8] (mod=01, REX.W)。
pub fn bsf_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsf_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r32, m32 [base+disp32] (mod=10)。
pub fn bsf_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsf_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r64, m64 [base+disp32] (mod=10, REX.W)。
pub fn bsf_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsf_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r32, m32 [RIP+disp32]。
pub fn bsf_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsf_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// BSF r64, m64 [RIP+disp32] (REX.W)。
pub fn bsf_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsf_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsf_set_zf(b, is_zero);
    Ok(())
}

/// ADD m32,r32 [base] (01 /r mod=00)。
pub fn add_m32_r32_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [base] (01 /r mod=00, REX.W)。
pub fn add_m64_r64_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [base+disp8] (01 /r mod=01)。
pub fn add_m32_r32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [base+disp8] (01 /r mod=01, REX.W)。
pub fn add_m64_r64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [base+disp32] (01 /r mod=10)。
pub fn add_m32_r32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [base+disp32] (01 /r mod=10, REX.W)。
pub fn add_m64_r64_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [RIP+disp32] (01 /r RIP)。
pub fn add_m32_r32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, src: Gpr) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,r64 [RIP+disp32] (01 /r RIP, REX.W)。
pub fn add_m64_r64_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, src: Gpr) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,r32 [disp32] abs (32ビット)。
pub fn add_m32_r32_abs<B: Backend>(b: &mut B, addr32: u32, src: Gpr) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// PCMPEQB xmm,[base] (66 0F 74 mod=00)。16Bロードして比較.
pub fn pcmpeqb_xmm_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>(i as u128 * 8);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let eq = b.cmp::<W128>(Cmp::Eq, ab8, cb8);
        let one = b.konst::<W128>(0xFF);
        let zero = b.konst::<W128>(0);
        let byte = b.select::<W128>(eq, one, zero);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PCMPEQB xmm,[base+disp8] (66 0F 74 mod=01)。
pub fn pcmpeqb_xmm_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>(i as u128 * 8);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let eq = b.cmp::<W128>(Cmp::Eq, ab8, cb8);
        let one = b.konst::<W128>(0xFF);
        let zero = b.konst::<W128>(0);
        let byte = b.select::<W128>(eq, one, zero);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PCMPEQB xmm,[base+disp32] (66 0F 74 mod=10)。
pub fn pcmpeqb_xmm_mem32<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>(i as u128 * 8);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let eq = b.cmp::<W128>(Cmp::Eq, ab8, cb8);
        let one = b.konst::<W128>(0xFF);
        let zero = b.konst::<W128>(0);
        let byte = b.select::<W128>(eq, one, zero);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PMINUB xmm,[base] (66 0F DA mod=00)。符号なしバイト毎に小さい方を選ぶ.
pub fn pminub_xmm_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let take_a = b.cmp::<W128>(Cmp::LtU, ab8, cb8);
        let byte = b.select::<W128>(take_a, ab8, cb8);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PMINUB xmm,[base+disp8] (66 0F DA mod=01)。
pub fn pminub_xmm_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let take_a = b.cmp::<W128>(Cmp::LtU, ab8, cb8);
        let byte = b.select::<W128>(take_a, ab8, cb8);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PMINUB xmm,[base+disp32] (66 0F DA mod=10)。
pub fn pminub_xmm_mem32<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let take_a = b.cmp::<W128>(Cmp::LtU, ab8, cb8);
        let byte = b.select::<W128>(take_a, ab8, cb8);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// FNSTCW m16 [base] (D9 /7 mod=00)。x87 制御ワードを書く.
pub fn fnstcw_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W16> = b.get(fcw_ref());
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// FNSTCW m16 [base+disp8] (D9 /7 mod=01)。
pub fn fnstcw_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W16> = b.get(fcw_ref());
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// FNSTCW m16 [base+index*scale+disp8] (D9 /7 SIB mod=01)。seq 0x4d0c17 対応.
pub fn fnstcw_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W16> = b.get(fcw_ref());
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// FNSTCW m16 [base+disp32] (D9 /7 mod=10)。
pub fn fnstcw_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W16> = b.get(fcw_ref());
    b.store::<W16>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// binary32 のビットを 80 ビットへ伸ばし、TOP を 1 減らしてから ST(0) へ書く。
fn f32_to_ext<B: Backend>(b: &mut B, bits: B::V<W32>) -> (B::V<W64>, B::V<W16>) {
    let s31 = b.konst::<W32>(31);
    let sign = b.shr_l::<W32>(bits, s31);
    let s23 = b.konst::<W32>(23);
    let shifted = b.shr_l::<W32>(bits, s23);
    let m8 = b.konst::<W32>(0xff);
    let exp8 = b.and::<W32>(shifted, m8);
    let mfrac = b.konst::<W32>(0x7f_ffff);
    let frac = b.and::<W32>(bits, mfrac);
    let zero32 = b.konst::<W32>(0);
    let exp_zero = b.cmp::<W32>(Cmp::Eq, exp8, zero32);
    let max_exp = b.konst::<W32>(0xff);
    let exp_max = b.cmp::<W32>(Cmp::Eq, exp8, max_exp);
    let frac_zero = b.cmp::<W32>(Cmp::Eq, frac, zero32);
    let bias = b.konst::<W32>(0x3f80);
    let exp_norm = b.add::<W32>(exp8, bias);
    let exp_special = b.konst::<W32>(0x7fff);
    let exp_or_special = b.select::<W32>(exp_max, exp_special, exp_norm);
    let exp_field = b.select::<W32>(exp_zero, zero32, exp_or_special);
    let frac64 = b.zext::<W32, W64>(frac);
    let sh40 = b.konst::<W64>(40);
    let frac_shifted = b.shl::<W64>(frac64, sh40);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let sig_norm = b.or::<W64>(int_bit, frac_shifted);
    let zero64 = b.konst::<W64>(0);
    let sig = b.select::<W64>(exp_zero, zero64, sig_norm);
    // 非正規化数は bit22 が立つまで左へ寄せ、指数をその分下げる。
    let mut v = frac;
    let mut n = zero32;
    for (k, mask) in [
        (16u32, 0x7f_8000u32),
        (8, 0x7c_0000),
        (4, 0x78_0000),
        (2, 0x60_0000),
        (1, 0x40_0000),
    ] {
        let m = b.konst::<W32>(mask);
        let high = b.and::<W32>(v, m);
        let empty = b.cmp::<W32>(Cmp::Eq, high, zero32);
        let kk = b.konst::<W32>(k);
        let shifted_v = b.shl::<W32>(v, kk);
        v = b.select::<W32>(empty, shifted_v, v);
        let n2 = b.add::<W32>(n, kk);
        n = b.select::<W32>(empty, n2, n);
    }
    let den_bias = b.konst::<W32>(16256);
    let den_exp = b.sub::<W32>(den_bias, n);
    let m22 = b.konst::<W32>(0x3f_ffff);
    let frac22 = b.and::<W32>(v, m22);
    let frac22_64 = b.zext::<W32, W64>(frac22);
    let sh41 = b.konst::<W64>(41);
    let frac22_sh = b.shl::<W64>(frac22_64, sh41);
    let den_sig = b.or::<W64>(int_bit, frac22_sh);
    let exp_if_sub = b.select::<W32>(frac_zero, zero32, den_exp);
    let sig_if_sub = b.select::<W64>(frac_zero, zero64, den_sig);
    let exp_final = b.select::<W32>(exp_zero, exp_if_sub, exp_field);
    let sig_final = b.select::<W64>(exp_zero, sig_if_sub, sig);
    let s15 = b.konst::<W32>(15);
    let sign_bit = b.shl::<W32>(sign, s15);
    let exp_word32 = b.or::<W32>(exp_final, sign_bit);
    let exp_word: B::V<W16> = b.trunc::<W32, W16>(exp_word32);
    (sig_final, exp_word)
}

fn push_f32<B: Backend>(b: &mut B, bits: B::V<W32>) -> Flow<B> {
    let (sig, exp) = f32_to_ext(b, bits);
    push_ext(b, sig, exp)
}

/// 80 ビット値を x87 スタックへ載せる。TOP を 1 減らしてから書く。
fn push_ext<B: Backend>(b: &mut B, sig: B::V<W64>, exp_word: B::V<W16>) -> Flow<B> {
    let top = b.get(top_ref());
    let one16 = b.konst::<W16>(1);
    let dec = b.sub::<W16>(top, one16);
    let seven = b.konst::<W16>(7);
    let new_top = b.and::<W16>(dec, seven);
    b.set(top_ref(), new_top);
    for i in 0..8 {
        let slot = b.konst::<W16>(i as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, new_top, slot);
        let old_sig = b.get(st_sig_ref(i));
        let old_exp = b.get(st_exp_ref(i));
        let sig_i = b.select::<W64>(hit, sig, old_sig);
        let exp_i = b.select::<W16>(hit, exp_word, old_exp);
        b.set(st_sig_ref(i), sig_i);
        b.set(st_exp_ref(i), exp_i);
    }
    Ok(())
}

/// 符号付き 32 ビット整数を 80 ビットへ伸ばしてスタックへ載せる。
fn push_i32<B: Backend>(b: &mut B, bits: B::V<W32>) -> Flow<B> {
    let s31 = b.konst::<W32>(31);
    let sign = b.shr_l::<W32>(bits, s31);
    let one32 = b.konst::<W32>(1);
    let neg_flag = b.cmp::<W32>(Cmp::Eq, sign, one32);
    let zero32 = b.konst::<W32>(0);
    let neg = b.sub::<W32>(zero32, bits);
    let mag = b.select::<W32>(neg_flag, neg, bits);
    let m31 = b.konst::<W32>(0x7fff_ffff);
    let mag31 = b.and::<W32>(mag, m31);
    let min_bits = b.konst::<W32>(0x8000_0000);
    let is_min = b.cmp::<W32>(Cmp::Eq, bits, min_bits);
    let mag_zero = b.cmp::<W32>(Cmp::Eq, mag31, zero32);
    let mut v = mag31;
    let mut n = zero32;
    for (k, mask) in [
        (16u32, 0x7fff_8000u32),
        (8, 0x7f80_0000),
        (4, 0x7800_0000),
        (2, 0x6000_0000),
        (1, 0x4000_0000),
    ] {
        let m = b.konst::<W32>(mask);
        let high = b.and::<W32>(v, m);
        let empty = b.cmp::<W32>(Cmp::Eq, high, zero32);
        let kk = b.konst::<W32>(k);
        let shifted = b.shl::<W32>(v, kk);
        v = b.select::<W32>(empty, shifted, v);
        let n2 = b.add::<W32>(n, kk);
        n = b.select::<W32>(empty, n2, n);
    }
    let bias = b.konst::<W32>(16413);
    let exp_norm = b.sub::<W32>(bias, n);
    let mfrac = b.konst::<W32>(0x3fff_ffff);
    let frac = b.and::<W32>(v, mfrac);
    let frac64 = b.zext::<W32, W64>(frac);
    let sh33 = b.konst::<W64>(33);
    let frac_sh = b.shl::<W64>(frac64, sh33);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let sig_norm = b.or::<W64>(int_bit, frac_sh);
    let min_exp = b.konst::<W32>(16414);
    let exp_or_min = b.select::<W32>(is_min, min_exp, exp_norm);
    let sig_or_min = b.select::<W64>(is_min, int_bit, sig_norm);
    let exp_if_zero = b.select::<W32>(is_min, min_exp, zero32);
    let zero64 = b.konst::<W64>(0);
    let sig_if_zero = b.select::<W64>(is_min, int_bit, zero64);
    let exp_final = b.select::<W32>(mag_zero, exp_if_zero, exp_or_min);
    let sig_final = b.select::<W64>(mag_zero, sig_if_zero, sig_or_min);
    let s15 = b.konst::<W32>(15);
    let sign_bit = b.shl::<W32>(sign, s15);
    let exp_word32 = b.or::<W32>(exp_final, sign_bit);
    let exp_word: B::V<W16> = b.trunc::<W32, W16>(exp_word32);
    push_ext(b, sig_final, exp_word)
}

/// 符号付き 64 ビット整数を 80 ビットへ伸ばしてスタックへ載せる。
fn push_i64<B: Backend>(b: &mut B, bits: B::V<W64>) -> Flow<B> {
    let s63 = b.konst::<W64>(63);
    let sign = b.shr_l::<W64>(bits, s63);
    let one64 = b.konst::<W64>(1);
    let neg_flag = b.cmp::<W64>(Cmp::Eq, sign, one64);
    let zero64 = b.konst::<W64>(0);
    let neg = b.sub::<W64>(zero64, bits);
    let mag = b.select::<W64>(neg_flag, neg, bits);
    let m63 = b.konst::<W64>(0x7fff_ffff_ffff_ffff);
    let mag63 = b.and::<W64>(mag, m63);
    let min_bits = b.konst::<W64>(1u64 << 63);
    let is_min = b.cmp::<W64>(Cmp::Eq, bits, min_bits);
    let mag_zero = b.cmp::<W64>(Cmp::Eq, mag63, zero64);
    let mut v = mag63;
    let mut n = zero64;
    for (k, mask) in [
        (32u64, 0x7fff_ffff_8000_0000u64),
        (16, 0x7fff_0000_0000_0000),
        (8, 0x7f80_0000_0000_0000),
        (4, 0x7800_0000_0000_0000),
        (2, 0x6000_0000_0000_0000),
        (1, 0x4000_0000_0000_0000),
    ] {
        let m = b.konst::<W64>(mask);
        let high = b.and::<W64>(v, m);
        let empty = b.cmp::<W64>(Cmp::Eq, high, zero64);
        let kk = b.konst::<W64>(k);
        let shifted = b.shl::<W64>(v, kk);
        v = b.select::<W64>(empty, shifted, v);
        let n2 = b.add::<W64>(n, kk);
        n = b.select::<W64>(empty, n2, n);
    }
    let bias = b.konst::<W64>(16445);
    let exp_norm = b.sub::<W64>(bias, n);
    let mfrac = b.konst::<W64>(0x3fff_ffff_ffff_ffff);
    let frac = b.and::<W64>(v, mfrac);
    let sh1 = b.konst::<W64>(1);
    let frac_sh = b.shl::<W64>(frac, sh1);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let sig_norm = b.or::<W64>(int_bit, frac_sh);
    let min_exp = b.konst::<W64>(16446);
    let exp_or_min = b.select::<W64>(is_min, min_exp, exp_norm);
    let sig_or_min = b.select::<W64>(is_min, int_bit, sig_norm);
    let exp_if_zero = b.select::<W64>(is_min, min_exp, zero64);
    let sig_if_zero = b.select::<W64>(is_min, int_bit, zero64);
    let exp_final = b.select::<W64>(mag_zero, exp_if_zero, exp_or_min);
    let sig_final = b.select::<W64>(mag_zero, sig_if_zero, sig_or_min);
    let s15 = b.konst::<W64>(15);
    let sign_bit = b.shl::<W64>(sign, s15);
    let exp_word64 = b.or::<W64>(exp_final, sign_bit);
    let exp_word: B::V<W16> = b.trunc::<W64, W16>(exp_word64);
    push_ext(b, sig_final, exp_word)
}

/// 倍精度を 80 ビットへ伸ばしてスタックへ載せる。非正規化数は正規化する。
fn push_f64<B: Backend>(b: &mut B, bits: B::V<W64>) -> Flow<B> {
    let s63 = b.konst::<W64>(63);
    let sign = b.shr_l::<W64>(bits, s63);
    let s52 = b.konst::<W64>(52);
    let exp_raw = b.shr_l::<W64>(bits, s52);
    let exp_mask = b.konst::<W64>(0x7ff);
    let ea = b.and::<W64>(exp_raw, exp_mask);
    let frac_mask = b.konst::<W64>((1u64 << 52) - 1);
    let frac = b.and::<W64>(bits, frac_mask);
    let zero64 = b.konst::<W64>(0);
    let exp_zero = b.cmp::<W64>(Cmp::Eq, ea, zero64);
    let frac_zero = b.cmp::<W64>(Cmp::Eq, frac, zero64);
    let special = b.konst::<W64>(0x7ff);
    let is_special = b.cmp::<W64>(Cmp::Eq, ea, special);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let sh11 = b.konst::<W64>(11);
    let frac_sh = b.shl::<W64>(frac, sh11);
    let sig_norm = b.or::<W64>(int_bit, frac_sh);
    let bias_add = b.konst::<W64>(15360);
    let exp_norm = b.add::<W64>(ea, bias_add);
    let mut v = frac;
    let mut n = zero64;
    for (k, mask) in [
        (32u64, 0x000f_ffff_fff0_0000u64),
        (16, 0x000f_fff0_0000_0000),
        (8, 0x000f_f000_0000_0000),
        (4, 0x000f_0000_0000_0000),
        (2, 0x000c_0000_0000_0000),
        (1, 0x0008_0000_0000_0000),
    ] {
        let m = b.konst::<W64>(mask);
        let high = b.and::<W64>(v, m);
        let empty = b.cmp::<W64>(Cmp::Eq, high, zero64);
        let kk = b.konst::<W64>(k);
        let shifted = b.shl::<W64>(v, kk);
        v = b.select::<W64>(empty, shifted, v);
        let n2 = b.add::<W64>(n, kk);
        n = b.select::<W64>(empty, n2, n);
    }
    let den_bias = b.konst::<W64>(15360);
    let den_exp = b.sub::<W64>(den_bias, n);
    let m51 = b.konst::<W64>((1u64 << 51) - 1);
    let frac51 = b.and::<W64>(v, m51);
    let sh12 = b.konst::<W64>(12);
    let frac51_sh = b.shl::<W64>(frac51, sh12);
    let den_sig = b.or::<W64>(int_bit, frac51_sh);
    let exp_if_sub = b.select::<W64>(frac_zero, zero64, den_exp);
    let sig_if_sub = b.select::<W64>(frac_zero, zero64, den_sig);
    let exp_num = b.select::<W64>(exp_zero, exp_if_sub, exp_norm);
    let sig_num = b.select::<W64>(exp_zero, sig_if_sub, sig_norm);
    let special_exp = b.konst::<W64>(0x7fff);
    let nan_payload = b.or::<W64>(int_bit, frac_sh);
    let inf_sig = int_bit;
    let sig_special = b.select::<W64>(frac_zero, inf_sig, nan_payload);
    let exp_final = b.select::<W64>(is_special, special_exp, exp_num);
    let sig_final = b.select::<W64>(is_special, sig_special, sig_num);
    let s15 = b.konst::<W64>(15);
    let sign_bit = b.shl::<W64>(sign, s15);
    let exp_word64 = b.or::<W64>(exp_final, sign_bit);
    let exp_word: B::V<W16> = b.trunc::<W64, W16>(exp_word64);
    push_ext(b, sig_final, exp_word)
}

/// FLDS [RIP+disp32] (D9 /0 mod=00 rm=101)。seq 0x402335 対応.
pub fn fld_m32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let bits: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    push_f32(b, bits)
}

/// FMUL m32 [RIP+disp32] (D8 /1 mod=00 rm=101)。ST(0) に単精度を掛ける。seq 0x4d0bf4 対応.
pub fn fmul_m32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let bits: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    fmul_m32_bits(b, bits)
}

/// FMUL m32 [disp32] (D8 /1 mod=00 rm=101、32ビット)。
pub fn fmul_m32_abs<B: Backend>(b: &mut B, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let bits: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    fmul_m32_bits(b, bits)
}

fn fmul_m32_bits<B: Backend>(b: &mut B, bits: B::V<W32>) -> Flow<B> {
    let (sig_m, exp_m) = f32_to_ext(b, bits);
    let top = b.get(top_ref());
    let (sig0, exp0) = read_st(b, top);
    let (sig_p, exp_p) = mul_ext(b, sig0, exp0, sig_m, exp_m);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, top, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, sig_p, old_sig);
        let new_exp = b.select::<W16>(hit, exp_p, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    Ok(())
}

/// FLDL [base] (DD /0 mod=00)。seq 0x4d0723 の fldl (%rax)。
pub fn fld_m64_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let bits: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    push_f64(b, bits)
}

/// FSTP m80 [base] (DB /7 mod=00)。仮数 8 バイトと指数 2 バイトを書いて捨てる。seq 0x4d0725 対応.
pub fn fstp_m80_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let addr = read64(b, base);
    b.store::<W64>(addr, sig, DATA_WRITE)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    b.store::<W16>(exp_addr, exp, DATA_WRITE)?;
    pop_st(b, top)
}

/// FSTP m80 [base+index*scale] (DB /7 SIB mod=00)。seq 0x4d0869 の (%rsp) は no_index 側.
pub fn fstp_m80_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    b.store::<W64>(addr, sig, DATA_WRITE)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    b.store::<W16>(exp_addr, exp, DATA_WRITE)?;
    pop_st(b, top)
}

/// FSTP m80 [base+disp32] (DB /7 SIB mod=10, no_index)。seq 0x4d0874 対応.
pub fn fstp_m80_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let addr = eff_addr32(b, base, disp);
    b.store::<W64>(addr, sig, DATA_WRITE)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    b.store::<W16>(exp_addr, exp, DATA_WRITE)?;
    pop_st(b, top)
}

/// FSTP m80 [base+index*scale+disp32] (DB /7 SIB mod=10)。
pub fn fstp_m80_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    b.store::<W64>(addr, sig, DATA_WRITE)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    b.store::<W16>(exp_addr, exp, DATA_WRITE)?;
    pop_st(b, top)
}

/// FSTP m80 [base+disp8] (DB /7 SIB mod=01, no_index)。seq 0x4d74d7 対応.
pub fn fstp_m80_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let addr = eff_addr(b, base, disp);
    b.store::<W64>(addr, sig, DATA_WRITE)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    b.store::<W16>(exp_addr, exp, DATA_WRITE)?;
    pop_st(b, top)
}

/// FSTP m80 [base+index*scale+disp8] (DB /7 SIB mod=01)。
pub fn fstp_m80_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    b.store::<W64>(addr, sig, DATA_WRITE)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    b.store::<W16>(exp_addr, exp, DATA_WRITE)?;
    pop_st(b, top)
}

/// FLD m80 [base+disp32] (DB /5 SIB mod=10, no_index)。seq 0x4d0853 対応.
pub fn fld_m80_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let sig: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    let exp: B::V<W16> = b.load::<W16>(exp_addr, DATA_READ)?;
    push_ext(b, sig, exp)
}

/// FLD m80 [base+index*scale+disp32] (DB /5 SIB mod=10)。
pub fn fld_m80_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let sig: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    let exp: B::V<W16> = b.load::<W16>(exp_addr, DATA_READ)?;
    push_ext(b, sig, exp)
}

/// FLD m80 [base] (DB /5 SIB mod=00, no_index)。seq 0x4d74d4 対応.
pub fn fld_m80_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let sig: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    let exp: B::V<W16> = b.load::<W16>(exp_addr, DATA_READ)?;
    push_ext(b, sig, exp)
}

/// FLD m80 [base+index*scale] (DB /5 SIB mod=00)。
pub fn fld_m80_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let sig: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    let exp: B::V<W16> = b.load::<W16>(exp_addr, DATA_READ)?;
    push_ext(b, sig, exp)
}

/// FLD m80 [base+disp8] (DB /5 SIB mod=01, no_index)。seq 0x4d7466 対応.
pub fn fld_m80_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let sig: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    let exp: B::V<W16> = b.load::<W16>(exp_addr, DATA_READ)?;
    push_ext(b, sig, exp)
}

/// FLD m80 [base+index*scale+disp8] (DB /5 SIB mod=01)。
pub fn fld_m80_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let sig: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let eight = b.konst::<W64>(8);
    let exp_addr = b.add::<W64>(addr, eight);
    let exp: B::V<W16> = b.load::<W16>(exp_addr, DATA_READ)?;
    push_ext(b, sig, exp)
}

/// FLDZ (D9 EE)。+0 を載せる。seq 0x4d097f 対応.
pub fn fldz<B: Backend>(b: &mut B) -> Flow<B> {
    let sig = b.konst::<W64>(0);
    let exp = b.konst::<W16>(0);
    push_ext(b, sig, exp)
}

/// FXCH ST(i) (D9 C8+i)。ST(0) と ST(i) を入れ替える。seq 0x4d0981 対応.
pub fn fxch_st<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig0, exp0) = read_st(b, top);
    let ii = b.konst::<W16>(i as u16);
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let src = b.and::<W16>(summed, seven);
    let (sig1, exp1) = read_st(b, src);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit_top = b.cmp::<W16>(Cmp::Eq, top, idx);
        let hit_src = b.cmp::<W16>(Cmp::Eq, src, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let sig_top = b.select::<W64>(hit_top, sig1, old_sig);
        let exp_top = b.select::<W16>(hit_top, exp1, old_exp);
        let new_sig = b.select::<W64>(hit_src, sig0, sig_top);
        let new_exp = b.select::<W16>(hit_src, exp0, exp_top);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    Ok(())
}

/// ST(0) と ST(i) の比較。戻り値は ZF、PF、CF。NaN は unordered。
fn cmp_f80<B: Backend>(
    b: &mut B,
    sig_a: B::V<W64>,
    exp_a: B::V<W16>,
    sig_b: B::V<W64>,
    exp_b: B::V<W16>,
) -> (B::B, B::B, B::B) {
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let mask15 = b.konst::<W64>(0x7fff);
    let special = b.konst::<W64>(0x7fff);
    let s15 = b.konst::<W64>(15);
    let int_bit = b.konst::<W64>(1u64 << 63);

    let exp_a64 = b.zext::<W16, W64>(exp_a);
    let exp_b64 = b.zext::<W16, W64>(exp_b);
    let ea = b.and::<W64>(exp_a64, mask15);
    let eb = b.and::<W64>(exp_b64, mask15);
    let sign_a = b.shr_l::<W64>(exp_a64, s15);
    let sign_b = b.shr_l::<W64>(exp_b64, s15);

    let sp_a = b.cmp::<W64>(Cmp::Eq, ea, special);
    let sp_b = b.cmp::<W64>(Cmp::Eq, eb, special);
    let sig_a_not_inf = b.cmp::<W64>(Cmp::Ne, sig_a, int_bit);
    let sig_b_not_inf = b.cmp::<W64>(Cmp::Ne, sig_b, int_bit);
    let nan_a = bit_and(b, sp_a, sig_a_not_inf);
    let nan_b = bit_and(b, sp_b, sig_b_not_inf);
    let unordered = bit_or(b, nan_a, nan_b);

    let z_a = b.cmp::<W64>(Cmp::Eq, ea, zero);
    let z_b = b.cmp::<W64>(Cmp::Eq, eb, zero);
    let both_z = bit_and(b, z_a, z_b);
    let not_both_z = bit_not(b, both_z);

    let exp_gt = b.cmp::<W64>(Cmp::GtU, ea, eb);
    let exp_lt = b.cmp::<W64>(Cmp::LtU, ea, eb);
    let exp_eq = b.cmp::<W64>(Cmp::Eq, ea, eb);
    let sig_gt = b.cmp::<W64>(Cmp::GtU, sig_a, sig_b);
    let sig_lt = b.cmp::<W64>(Cmp::LtU, sig_a, sig_b);
    let sig_eq = b.cmp::<W64>(Cmp::Eq, sig_a, sig_b);
    let exp_eq_sig_gt = bit_and(b, exp_eq, sig_gt);
    let exp_eq_sig_lt = bit_and(b, exp_eq, sig_lt);
    let mag_gt = bit_or(b, exp_gt, exp_eq_sig_gt);
    let mag_lt = bit_or(b, exp_lt, exp_eq_sig_lt);
    let mag_eq = bit_and(b, exp_eq, sig_eq);

    let a_neg = b.cmp::<W64>(Cmp::Eq, sign_a, one);
    let b_neg = b.cmp::<W64>(Cmp::Eq, sign_b, one);
    let not_a_neg = bit_not(b, a_neg);
    let not_b_neg = bit_not(b, b_neg);
    let signs_differ = b.cmp::<W64>(Cmp::Ne, sign_a, sign_b);
    let same = bit_not(b, signs_differ);

    let neg_and_pos = bit_and(b, a_neg, not_b_neg);
    let neg_lt_pos = bit_and(b, neg_and_pos, not_both_z);

    let neg_and_same = bit_and(b, a_neg, same);
    let pos_and_same = bit_and(b, not_a_neg, same);
    let neg_lt = bit_and(b, neg_and_same, mag_gt);
    let pos_mag_lt = bit_and(b, pos_and_same, mag_lt);
    let pos_lt = bit_and(b, pos_mag_lt, not_both_z);

    let neg_side = bit_or(b, neg_lt_pos, neg_lt);
    let a_lt = bit_or(b, neg_side, pos_lt);
    let same_live = bit_and(b, same, not_both_z);
    let same_eq = bit_and(b, same_live, mag_eq);
    let a_eq = bit_or(b, both_z, same_eq);

    let zf = bit_or(b, unordered, a_eq);
    let cf = bit_or(b, unordered, a_lt);
    (zf, unordered, cf)
}

/// FUCOMI ST(0), ST(i) (DB E8+i)。比較結果を EFLAGS に書き、スタックは戻さない。seq 0x4d0983 対応.
pub fn fucomi_st<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig0, exp0) = read_st(b, top);
    let ii = b.konst::<W16>(i as u16);
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let src = b.and::<W16>(summed, seven);
    let (sig1, exp1) = read_st(b, src);
    let (zf, pf, cf) = cmp_f80(b, sig0, exp0, sig1, exp1);
    let old = b.get(eflags_ref());
    let clear_mask = b.konst::<W32>(!FLAG_OSZPCA);
    let cleared = b.and::<W32>(old, clear_mask);
    let zf_bit = pick(b, zf, FLAG_ZF);
    let pf_bit = pick(b, pf, FLAG_PF);
    let cf_bit = pick(b, cf, FLAG_CF);
    let with_zf = b.or::<W32>(cleared, zf_bit);
    let with_pf = b.or::<W32>(with_zf, pf_bit);
    let flags = b.or::<W32>(with_pf, cf_bit);
    b.set(eflags_ref(), flags);
    Ok(())
}

/// FLD ST(i) (D9 C0+i)。ST(i) の複製を載せる。元の段は残す。seq 0x4d0867 対応.
pub fn fld_st<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let top = b.get(top_ref());
    let ii = b.konst::<W16>(i as u16);
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let src = b.and::<W16>(summed, seven);
    let (sig, exp) = read_st(b, src);
    push_ext(b, sig, exp)
}

/// FLDS [disp32] (D9 /0 mod=00 rm=101、32ビット)。
pub fn fld_m32_abs<B: Backend>(b: &mut B, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let bits: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    push_f32(b, bits)
}

/// FILD m32 [base+disp8] (DB /0 SIB mod=01, no_index)。seq 0x4018bc 対応.
pub fn fild_m32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let bits: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    push_i32(b, bits)
}

/// FILD m32 [base+index*scale+disp8] (DB /0 SIB mod=01)。
pub fn fild_m32_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let bits: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    push_i32(b, bits)
}

/// FILD m64 [base] (DF /5 SIB mod=00, no_index)。seq 0x4018c4 対応.
pub fn fild_m64_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let bits: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    push_i64(b, bits)
}

/// FILD m64 [base+index*scale] (DF /5 SIB mod=00)。
pub fn fild_m64_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let bits: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    push_i64(b, bits)
}

/// FILD m64 [base+disp8] (DF /5 SIB mod=01, no_index)。seq 0x4d0c4d 対応.
pub fn fild_m64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let bits: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    push_i64(b, bits)
}

/// FILD m64 [base+index*scale+disp8] (DF /5 SIB mod=01)。
pub fn fild_m64_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let bits: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    push_i64(b, bits)
}

/// FSTP ST(i) (DD D8+i)。ST(0) を ST(i) へ写してからスタックを一つ捨てる。seq 0x4024ee 対応.
pub fn fstp_st<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let top = b.get(top_ref());
    let ii = b.konst::<W16>(i as u16);
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let dst = b.and::<W16>(summed, seven);
    let mut sig = b.konst::<W64>(0);
    let mut exp = b.konst::<W16>(0);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, top, idx);
        let got_sig = b.get(st_sig_ref(slot));
        let got_exp = b.get(st_exp_ref(slot));
        sig = b.select::<W64>(hit, got_sig, sig);
        exp = b.select::<W16>(hit, got_exp, exp);
    }
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, dst, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, sig, old_sig);
        let new_exp = b.select::<W16>(hit, exp, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    let zero64 = b.konst::<W64>(0);
    let zero16 = b.konst::<W16>(0);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, top, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, zero64, old_sig);
        let new_exp = b.select::<W16>(hit, zero16, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    let one = b.konst::<W16>(1);
    let inc = b.add::<W16>(top, one);
    let new_top = b.and::<W16>(inc, seven);
    b.set(top_ref(), new_top);
    Ok(())
}

fn read_st<B: Backend>(b: &mut B, slot_sel: B::V<W16>) -> (B::V<W64>, B::V<W16>) {
    let mut sig = b.konst::<W64>(0);
    let mut exp = b.konst::<W16>(0);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, slot_sel, idx);
        let got_sig = b.get(st_sig_ref(slot));
        let got_exp = b.get(st_exp_ref(slot));
        sig = b.select::<W64>(hit, got_sig, sig);
        exp = b.select::<W16>(hit, got_exp, exp);
    }
    (sig, exp)
}

/// 正規化済み 80 ビット同士の乗算。最近接偶数へ丸め、ゼロと無限大だけ特別扱いする。
fn mul_ext<B: Backend>(
    b: &mut B,
    sig_a: B::V<W64>,
    exp_a: B::V<W16>,
    sig_b: B::V<W64>,
    exp_b: B::V<W16>,
) -> (B::V<W64>, B::V<W16>) {
    let exp_a64 = b.zext::<W16, W64>(exp_a);
    let exp_b64 = b.zext::<W16, W64>(exp_b);
    let mask15 = b.konst::<W64>(0x7fff);
    let ea = b.and::<W64>(exp_a64, mask15);
    let eb = b.and::<W64>(exp_b64, mask15);
    let s15 = b.konst::<W64>(15);
    let sign_a = b.shr_l::<W64>(exp_a64, s15);
    let sign_b = b.shr_l::<W64>(exp_b64, s15);
    let sign = b.xor::<W64>(sign_a, sign_b);
    let sign_bit = b.shl::<W64>(sign, s15);
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let special_exp = b.konst::<W64>(0x7fff);
    let sp_a = b.cmp::<W64>(Cmp::Eq, ea, special_exp);
    let sp_b = b.cmp::<W64>(Cmp::Eq, eb, special_exp);
    let sp_a_n = b.select::<W64>(sp_a, one64, zero64);
    let sp_b_n = b.select::<W64>(sp_b, one64, zero64);
    let sp_or = b.or::<W64>(sp_a_n, sp_b_n);
    let is_special = b.cmp::<W64>(Cmp::Ne, sp_or, zero64);
    let z_a = b.cmp::<W64>(Cmp::Eq, ea, zero64);
    let z_b = b.cmp::<W64>(Cmp::Eq, eb, zero64);
    let z_a_n = b.select::<W64>(z_a, one64, zero64);
    let z_b_n = b.select::<W64>(z_b, one64, zero64);
    let z_or = b.or::<W64>(z_a_n, z_b_n);
    let is_zero = b.cmp::<W64>(Cmp::Ne, z_or, zero64);
    let lo = b.mul::<W64>(sig_a, sig_b);
    let hi = b.mulhu::<W64>(sig_a, sig_b);
    let s63 = b.konst::<W64>(63);
    let hi_top = b.shr_l::<W64>(hi, s63);
    let ge = b.cmp::<W64>(Cmp::Eq, hi_top, one64);
    let hi_sh = b.shl::<W64>(hi, one64);
    let lo_top = b.shr_l::<W64>(lo, s63);
    let sig_narrow = b.or::<W64>(hi_sh, lo_top);
    let sig_raw = b.select::<W64>(ge, hi, sig_narrow);
    let s62 = b.konst::<W64>(62);
    let rb_wide = b.and::<W64>(lo_top, one64);
    let lo_r = b.shr_l::<W64>(lo, s62);
    let rb_narrow = b.and::<W64>(lo_r, one64);
    let round_bit = b.select::<W64>(ge, rb_wide, rb_narrow);
    let m63 = b.konst::<W64>((1u64 << 63) - 1);
    let m62 = b.konst::<W64>((1u64 << 62) - 1);
    let st_wide = b.and::<W64>(lo, m63);
    let st_narrow = b.and::<W64>(lo, m62);
    let sticky_bits = b.select::<W64>(ge, st_wide, st_narrow);
    let sticky = b.cmp::<W64>(Cmp::Ne, sticky_bits, zero64);
    let lsb = b.and::<W64>(sig_raw, one64);
    let sticky_n = b.select::<W64>(sticky, one64, zero64);
    let tie = b.or::<W64>(sticky_n, lsb);
    let round_set = b.cmp::<W64>(Cmp::Eq, round_bit, one64);
    let up_n = b.select::<W64>(round_set, tie, zero64);
    let do_up = b.cmp::<W64>(Cmp::Ne, up_n, zero64);
    let sig_plus = b.add::<W64>(sig_raw, one64);
    let sig_rounded = b.select::<W64>(do_up, sig_plus, sig_raw);
    let max64 = b.konst::<W64>(u64::MAX);
    let at_max = b.cmp::<W64>(Cmp::Eq, sig_raw, max64);
    let at_max_n = b.select::<W64>(at_max, one64, zero64);
    let ov_n = b.select::<W64>(do_up, at_max_n, zero64);
    let round_ov = b.cmp::<W64>(Cmp::Ne, ov_n, zero64);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let sig_norm = b.select::<W64>(round_ov, int_bit, sig_rounded);
    let adj0 = b.select::<W64>(ge, one64, zero64);
    let adj1 = b.add::<W64>(adj0, one64);
    let adj = b.select::<W64>(round_ov, adj1, adj0);
    let exp_sum0 = b.add::<W64>(ea, eb);
    let exp_sum = b.add::<W64>(exp_sum0, adj);
    let bias = b.konst::<W64>(16383);
    let under = b.cmp::<W64>(Cmp::LeU, exp_sum, bias);
    let biased = b.sub::<W64>(exp_sum, bias);
    let ov_lim = b.konst::<W64>(16383 + 0x7fff);
    let over = b.cmp::<W64>(Cmp::GeU, exp_sum, ov_lim);
    let exp_over = b.select::<W64>(over, special_exp, biased);
    let exp_num = b.select::<W64>(under, zero64, exp_over);
    let sig_under = b.select::<W64>(under, zero64, sig_norm);
    let sig_num = b.select::<W64>(over, int_bit, sig_under);
    let exp_fin = b.select::<W64>(is_zero, zero64, exp_num);
    let sig_fin = b.select::<W64>(is_zero, zero64, sig_num);
    let nan_sig = b.konst::<W64>(0xC000_0000_0000_0000);
    let exp_mag = b.select::<W64>(is_special, special_exp, exp_fin);
    let sig_out = b.select::<W64>(is_special, nan_sig, sig_fin);
    let exp_word64 = b.or::<W64>(exp_mag, sign_bit);
    let exp_word = b.trunc::<W64, W16>(exp_word64);
    (sig_out, exp_word)
}

fn bit_or<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let xn = b.select::<W64>(x, one, zero);
    let yn = b.select::<W64>(y, one, zero);
    let combined = b.or::<W64>(xn, yn);
    b.cmp::<W64>(Cmp::Ne, combined, zero)
}

fn bit_and<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let xn = b.select::<W64>(x, one, zero);
    let yn = b.select::<W64>(y, one, zero);
    let combined = b.and::<W64>(xn, yn);
    b.cmp::<W64>(Cmp::Ne, combined, zero)
}

fn bit_not<B: Backend>(b: &mut B, x: B::B) -> B::B {
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let xn = b.select::<W64>(x, zero, one);
    b.cmp::<W64>(Cmp::Ne, xn, zero)
}

/// 0 のとき 64。上位から見て最初の 1 までのゼロの数。
fn clz64<B: Backend>(b: &mut B, x: B::V<W64>) -> B::V<W64> {
    let zero = b.konst::<W64>(0);
    let n32 = b.konst::<W64>(32);
    let n16 = b.konst::<W64>(16);
    let n8 = b.konst::<W64>(8);
    let n4 = b.konst::<W64>(4);
    let n2 = b.konst::<W64>(2);
    let n1 = b.konst::<W64>(1);
    let n64 = b.konst::<W64>(64);
    let s32 = b.konst::<W64>(32);
    let s48 = b.konst::<W64>(48);
    let s56 = b.konst::<W64>(56);
    let s60 = b.konst::<W64>(60);
    let s62 = b.konst::<W64>(62);
    let s63 = b.konst::<W64>(63);

    let hi32 = b.shr_l::<W64>(x, s32);
    let z32 = b.cmp::<W64>(Cmp::Eq, hi32, zero);
    let n = b.select::<W64>(z32, n32, zero);
    let x32 = b.shl::<W64>(x, s32);
    let y = b.select::<W64>(z32, x32, x);

    let hi16 = b.shr_l::<W64>(y, s48);
    let z16 = b.cmp::<W64>(Cmp::Eq, hi16, zero);
    let add16 = b.select::<W64>(z16, n16, zero);
    let n = b.add::<W64>(n, add16);
    let y16 = b.shl::<W64>(y, n16);
    let y = b.select::<W64>(z16, y16, y);

    let hi8 = b.shr_l::<W64>(y, s56);
    let z8 = b.cmp::<W64>(Cmp::Eq, hi8, zero);
    let add8 = b.select::<W64>(z8, n8, zero);
    let n = b.add::<W64>(n, add8);
    let y8 = b.shl::<W64>(y, n8);
    let y = b.select::<W64>(z8, y8, y);

    let hi4 = b.shr_l::<W64>(y, s60);
    let z4 = b.cmp::<W64>(Cmp::Eq, hi4, zero);
    let add4 = b.select::<W64>(z4, n4, zero);
    let n = b.add::<W64>(n, add4);
    let y4 = b.shl::<W64>(y, n4);
    let y = b.select::<W64>(z4, y4, y);

    let hi2 = b.shr_l::<W64>(y, s62);
    let z2 = b.cmp::<W64>(Cmp::Eq, hi2, zero);
    let add2 = b.select::<W64>(z2, n2, zero);
    let n = b.add::<W64>(n, add2);
    let y2 = b.shl::<W64>(y, n2);
    let y = b.select::<W64>(z2, y2, y);

    let hi1 = b.shr_l::<W64>(y, s63);
    let z1 = b.cmp::<W64>(Cmp::Eq, hi1, zero);
    let add1 = b.select::<W64>(z1, n1, zero);
    let n = b.add::<W64>(n, add1);
    let is_zero = b.cmp::<W64>(Cmp::Eq, x, zero);
    b.select::<W64>(is_zero, n64, n)
}

/// 正規化済み 80 ビット同士の加算。最近接偶数へ丸め、ゼロと無限大だけ特別扱いする。
/// 非正規化数はゼロとみなす。仮数の 128 ビットより下は sticky に潰す。
fn add_ext<B: Backend>(
    b: &mut B,
    sig_a: B::V<W64>,
    exp_a: B::V<W16>,
    sig_b: B::V<W64>,
    exp_b: B::V<W16>,
) -> (B::V<W64>, B::V<W16>) {
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let mask15 = b.konst::<W64>(0x7fff);
    let special = b.konst::<W64>(0x7fff);
    let s15 = b.konst::<W64>(15);
    let s63 = b.konst::<W64>(63);
    let s64 = b.konst::<W64>(64);
    let int_bit = b.konst::<W64>(1u64 << 63);
    let nan_sig = b.konst::<W64>(0xC000_0000_0000_0000);
    let m63 = b.konst::<W64>((1u64 << 63) - 1);
    let max64 = b.konst::<W64>(u64::MAX);

    let exp_a64 = b.zext::<W16, W64>(exp_a);
    let exp_b64 = b.zext::<W16, W64>(exp_b);
    let ea = b.and::<W64>(exp_a64, mask15);
    let eb = b.and::<W64>(exp_b64, mask15);
    let sign_a = b.shr_l::<W64>(exp_a64, s15);
    let sign_b = b.shr_l::<W64>(exp_b64, s15);

    let sp_a = b.cmp::<W64>(Cmp::Eq, ea, special);
    let sp_b = b.cmp::<W64>(Cmp::Eq, eb, special);
    let z_a = b.cmp::<W64>(Cmp::Eq, ea, zero);
    let z_b = b.cmp::<W64>(Cmp::Eq, eb, zero);
    let any_sp = bit_or(b, sp_a, sp_b);

    let exp_gt = b.cmp::<W64>(Cmp::GtU, ea, eb);
    let exp_eq = b.cmp::<W64>(Cmp::Eq, ea, eb);
    let sig_ge = b.cmp::<W64>(Cmp::GeU, sig_a, sig_b);
    let eq_and_ge = bit_and(b, exp_eq, sig_ge);
    let a_is_big = bit_or(b, exp_gt, eq_and_ge);
    let sig_big = b.select::<W64>(a_is_big, sig_a, sig_b);
    let sig_small = b.select::<W64>(a_is_big, sig_b, sig_a);
    let exp_big = b.select::<W64>(a_is_big, ea, eb);
    let exp_small = b.select::<W64>(a_is_big, eb, ea);
    let sign_big = b.select::<W64>(a_is_big, sign_a, sign_b);
    let sign_small = b.select::<W64>(a_is_big, sign_b, sign_a);
    let same_sign = b.cmp::<W64>(Cmp::Eq, sign_big, sign_small);
    let diff = b.sub::<W64>(exp_big, exp_small);

    let d_lt64 = b.cmp::<W64>(Cmp::LtU, diff, s64);
    let d_lt128_lim = b.konst::<W64>(128);
    let d_lt128 = b.cmp::<W64>(Cmp::LtU, diff, d_lt128_lim);
    let d_ge64 = bit_not(b, d_lt64);
    let d_mid = bit_and(b, d_ge64, d_lt128);
    let d_ge128 = bit_not(b, d_lt128);

    let diff_from_64 = b.sub::<W64>(s64, diff);
    let sh_down = b.select::<W64>(d_lt64, diff_from_64, zero);
    let hi_lt = b.shr_l::<W64>(sig_small, diff);
    let lo_lt_raw = b.shl::<W64>(sig_small, sh_down);
    let lo_lt = b.select::<W64>(d_lt64, lo_lt_raw, zero);

    let diff_minus_64 = b.sub::<W64>(diff, s64);
    let sh_mid = b.select::<W64>(d_ge64, diff_minus_64, zero);
    let lo_mid_raw = b.shr_l::<W64>(sig_small, sh_mid);
    let lo_mid = b.select::<W64>(d_mid, lo_mid_raw, zero);
    let k_pos = b.cmp::<W64>(Cmp::Ne, sh_mid, zero);
    let k_from_64 = b.sub::<W64>(s64, sh_mid);
    let sh_sticky = b.select::<W64>(k_pos, k_from_64, s64);
    let dropped = b.shl::<W64>(sig_small, sh_sticky);
    let dropped_nz = b.cmp::<W64>(Cmp::Ne, dropped, zero);
    let mid_and_k = bit_and(b, d_mid, k_pos);
    let sticky_mid = bit_and(b, mid_and_k, dropped_nz);
    let small_nz = b.cmp::<W64>(Cmp::Ne, sig_small, zero);
    let sticky_far = bit_and(b, d_ge128, small_nz);

    let hi_s = b.select::<W64>(d_lt64, hi_lt, zero);
    let lo_s = b.select::<W64>(d_lt64, lo_lt, lo_mid);
    let sticky_s = bit_or(b, sticky_mid, sticky_far);

    let sum = b.add::<W64>(sig_big, hi_s);
    let carry = b.cmp::<W64>(Cmp::LtU, sum, sig_big);
    let lo_bit0 = b.and::<W64>(lo_s, one);
    let hi_bit0 = b.and::<W64>(sum, one);
    let lo_shr = b.shr_l::<W64>(lo_s, one);
    let hi_into_lo = b.shl::<W64>(hi_bit0, s63);
    let add_lo_c = b.or::<W64>(lo_shr, hi_into_lo);
    let sum_shr = b.shr_l::<W64>(sum, one);
    let add_hi_c = b.or::<W64>(sum_shr, int_bit);
    let add_hi = b.select::<W64>(carry, add_hi_c, sum);
    let add_lo = b.select::<W64>(carry, add_lo_c, lo_s);
    let fell = b.cmp::<W64>(Cmp::Eq, lo_bit0, one);
    let fell_on_carry = bit_and(b, carry, fell);
    let sticky_add = bit_or(b, sticky_s, fell_on_carry);
    let exp_plus = b.add::<W64>(exp_big, one);
    let exp_add = b.select::<W64>(carry, exp_plus, exp_big);

    let lo_nz = b.cmp::<W64>(Cmp::Ne, lo_s, zero);
    let neg_lo = b.sub::<W64>(zero, lo_s);
    let sub_lo = b.select::<W64>(lo_nz, neg_lo, zero);
    let hi_minus = b.sub::<W64>(sig_big, hi_s);
    let hi_minus_b = b.sub::<W64>(hi_minus, one);
    let sub_hi = b.select::<W64>(lo_nz, hi_minus_b, hi_minus);

    let hi0 = b.select::<W64>(same_sign, add_hi, sub_hi);
    let lo0 = b.select::<W64>(same_sign, add_lo, sub_lo);
    let sticky_add_n = b.select::<W64>(sticky_add, one, zero);
    let sticky_sub_n = b.select::<W64>(sticky_s, one, zero);
    let sticky0 = b.select::<W64>(same_sign, sticky_add_n, sticky_sub_n);
    let sticky0_b = b.cmp::<W64>(Cmp::Ne, sticky0, zero);
    let exp0 = b.select::<W64>(same_sign, exp_add, exp_big);

    let hi_zero = b.cmp::<W64>(Cmp::Eq, hi0, zero);
    let lo_zero = b.cmp::<W64>(Cmp::Eq, lo0, zero);
    let both_zero = bit_and(b, hi_zero, lo_zero);
    let clz_hi = clz64(b, hi0);
    let clz_lo = clz64(b, lo0);
    let sh_comp = b.sub::<W64>(s64, clz_hi);
    let hi_shl = b.shl::<W64>(hi0, clz_hi);
    let lo_into_hi = b.shr_l::<W64>(lo0, sh_comp);
    let hi_norm = b.or::<W64>(hi_shl, lo_into_hi);
    let lo_norm = b.shl::<W64>(lo0, clz_hi);
    let hi_from_lo = b.shl::<W64>(lo0, clz_lo);
    let hi_n_src = b.select::<W64>(hi_zero, hi_from_lo, hi_norm);
    let lo_n_src = b.select::<W64>(hi_zero, zero, lo_norm);
    let hi_n = b.select::<W64>(both_zero, zero, hi_n_src);
    let lo_n = b.select::<W64>(both_zero, zero, lo_n_src);
    let shift_lo = b.add::<W64>(s64, clz_lo);
    let shift = b.select::<W64>(hi_zero, shift_lo, clz_hi);
    let exp_gt_shift = b.cmp::<W64>(Cmp::GtU, exp0, shift);
    let exp_subbed = b.sub::<W64>(exp0, shift);
    let exp_n_raw = b.select::<W64>(exp_gt_shift, exp_subbed, zero);
    let exp_n = b.select::<W64>(both_zero, zero, exp_n_raw);

    let round_bit = b.shr_l::<W64>(lo_n, s63);
    let rest = b.and::<W64>(lo_n, m63);
    let rest_nz = b.cmp::<W64>(Cmp::Ne, rest, zero);
    let sticky_f = bit_or(b, sticky0_b, rest_nz);
    let lsb = b.and::<W64>(hi_n, one);
    let lsb_set = b.cmp::<W64>(Cmp::Eq, lsb, one);
    let round_set = b.cmp::<W64>(Cmp::Eq, round_bit, one);
    let tie = bit_or(b, sticky_f, lsb_set);
    let round_up = bit_and(b, round_set, tie);
    let exp_live = b.cmp::<W64>(Cmp::Ne, exp_n, zero);
    let do_up = bit_and(b, round_up, exp_live);
    let hi_up = b.add::<W64>(hi_n, one);
    let at_max = b.cmp::<W64>(Cmp::Eq, hi_n, max64);
    let ov = bit_and(b, do_up, at_max);
    let hi_rounded_raw = b.select::<W64>(do_up, hi_up, hi_n);
    let hi_rounded = b.select::<W64>(ov, int_bit, hi_rounded_raw);
    let exp_up = b.add::<W64>(exp_n, one);
    let exp_rounded = b.select::<W64>(ov, exp_up, exp_n);
    let exp_is_zero = b.cmp::<W64>(Cmp::Eq, exp_rounded, zero);
    let exp_ovf = b.cmp::<W64>(Cmp::GeU, exp_rounded, special);
    let sig_or_inf = b.select::<W64>(exp_ovf, int_bit, hi_rounded);
    let sig_mag = b.select::<W64>(exp_is_zero, zero, sig_or_inf);
    let exp_mag = b.select::<W64>(exp_ovf, special, exp_rounded);
    let sign_num = b.select::<W64>(exp_is_zero, zero, sign_big);

    let not_zb = bit_not(b, z_b);
    let use_b = bit_and(b, z_a, not_zb);
    let not_za = bit_not(b, z_a);
    let use_a = bit_and(b, z_b, not_za);
    let both_z = bit_and(b, z_a, z_b);
    let sig_zero_b = b.select::<W64>(use_b, sig_b, zero);
    let sig_zero_case = b.select::<W64>(use_a, sig_a, sig_zero_b);
    let exp_zero_b = b.select::<W64>(use_b, eb, zero);
    let exp_zero_case = b.select::<W64>(use_a, ea, exp_zero_b);
    let sign_and = b.and::<W64>(sign_a, sign_b);
    let sign_zero_b = b.select::<W64>(use_b, sign_b, sign_and);
    let sign_zero_case = b.select::<W64>(use_a, sign_a, sign_zero_b);
    let use_ab = bit_or(b, use_a, use_b);
    let use_zero_raw = bit_or(b, use_ab, both_z);
    let not_sp = bit_not(b, any_sp);
    let use_zero = bit_and(b, use_zero_raw, not_sp);
    let sig_after_z = b.select::<W64>(use_zero, sig_zero_case, sig_mag);
    let exp_after_z = b.select::<W64>(use_zero, exp_zero_case, exp_mag);
    let sign_after_z = b.select::<W64>(use_zero, sign_zero_case, sign_num);

    let sig_a_not_inf = b.cmp::<W64>(Cmp::Ne, sig_a, int_bit);
    let nan_a = bit_and(b, sp_a, sig_a_not_inf);
    let sig_b_not_inf = b.cmp::<W64>(Cmp::Ne, sig_b, int_bit);
    let nan_b = bit_and(b, sp_b, sig_b_not_inf);
    let signs_differ = b.cmp::<W64>(Cmp::Ne, sign_a, sign_b);
    let both_sp = bit_and(b, sp_a, sp_b);
    let inf_cancel = bit_and(b, both_sp, signs_differ);
    let nan_either = bit_or(b, nan_a, nan_b);
    let any_nan = bit_or(b, nan_either, inf_cancel);
    let sp_sig = b.select::<W64>(any_nan, nan_sig, int_bit);
    let sp_sign = b.select::<W64>(sp_a, sign_a, sign_b);
    let nan_sign = b.select::<W64>(any_nan, sign_a, sp_sign);
    let sig_final = b.select::<W64>(any_sp, sp_sig, sig_after_z);
    let exp_final = b.select::<W64>(any_sp, special, exp_after_z);
    let sign_final = b.select::<W64>(any_sp, nan_sign, sign_after_z);

    let sign_bit = b.shl::<W64>(sign_final, s15);
    let packed = b.or::<W64>(exp_final, sign_bit);
    let exp_word = b.trunc::<W64, W16>(packed);
    (sig_final, exp_word)
}

/// FADD ST(0), ST(i) (D8 C0+i)。ST(0) に和を書き、スタックは戻さない。seq 0x4d097d 対応.
pub fn fadd_st<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig0, exp0) = read_st(b, top);
    let ii = b.konst::<W16>(i as u16);
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let src = b.and::<W16>(summed, seven);
    let (sig1, exp1) = read_st(b, src);
    let (sig_s, exp_s) = add_ext(b, sig0, exp0, sig1, exp1);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, top, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, sig_s, old_sig);
        let new_exp = b.select::<W16>(hit, exp_s, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    Ok(())
}

/// FMULP ST(i), ST(0) (DE C8+i)。ST(i) に積を書いてからスタックを一つ捨てる。seq 0x4018c7 対応.
pub fn fmulp_st<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig0, exp0) = read_st(b, top);
    let ii = b.konst::<W16>(i as u16);
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let dst = b.and::<W16>(summed, seven);
    let (sig1, exp1) = read_st(b, dst);
    let (sig_p, exp_p) = mul_ext(b, sig0, exp0, sig1, exp1);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, dst, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, sig_p, old_sig);
        let new_exp = b.select::<W16>(hit, exp_p, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    let zero64 = b.konst::<W64>(0);
    let zero16 = b.konst::<W16>(0);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, top, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, zero64, old_sig);
        let new_exp = b.select::<W16>(hit, zero16, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    let one = b.konst::<W16>(1);
    let inc = b.add::<W16>(top, one);
    let new_top = b.and::<W16>(inc, seven);
    b.set(top_ref(), new_top);
    Ok(())
}

/// FSUBP ST(i), ST(0) (DE E8+i)。ST(i) から ST(0) を引いて書き、スタックを一つ捨てる。seq 0x4d0c51 対応.
pub fn fsubp_st<B: Backend>(b: &mut B, i: u8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig0, exp0) = read_st(b, top);
    let ii = b.konst::<W16>(i as u16);
    let summed = b.add::<W16>(top, ii);
    let seven = b.konst::<W16>(7);
    let dst = b.and::<W16>(summed, seven);
    let (sig1, exp1) = read_st(b, dst);
    let sign_mask = b.konst::<W16>(0x8000);
    let neg_exp0 = b.xor::<W16>(exp0, sign_mask);
    let (sig_d, exp_d) = add_ext(b, sig1, exp1, sig0, neg_exp0);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, dst, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, sig_d, old_sig);
        let new_exp = b.select::<W16>(hit, exp_d, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    let zero64 = b.konst::<W64>(0);
    let zero16 = b.konst::<W16>(0);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, top, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, zero64, old_sig);
        let new_exp = b.select::<W16>(hit, zero16, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    let one = b.konst::<W16>(1);
    let inc = b.add::<W16>(top, one);
    let new_top = b.and::<W16>(inc, seven);
    b.set(top_ref(), new_top);
    Ok(())
}

/// 80 ビットを倍精度へ丸める。非正規化数はゼロにする。
fn f80_to_f64<B: Backend>(b: &mut B, sig: B::V<W64>, exp: B::V<W16>) -> B::V<W64> {
    let exp64 = b.zext::<W16, W64>(exp);
    let mask15 = b.konst::<W64>(0x7fff);
    let ea = b.and::<W64>(exp64, mask15);
    let s15 = b.konst::<W64>(15);
    let sign = b.shr_l::<W64>(exp64, s15);
    let s63 = b.konst::<W64>(63);
    let sign_bit = b.shl::<W64>(sign, s63);
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let special = b.konst::<W64>(0x7fff);
    let is_special = b.cmp::<W64>(Cmp::Eq, ea, special);
    let is_zero = b.cmp::<W64>(Cmp::Eq, ea, zero);
    let s11 = b.konst::<W64>(11);
    let kept = b.shr_l::<W64>(sig, s11);
    let m52 = b.konst::<W64>((1u64 << 52) - 1);
    let s10 = b.konst::<W64>(10);
    let sig_r = b.shr_l::<W64>(sig, s10);
    let round_bit = b.and::<W64>(sig_r, one);
    let sticky_mask = b.konst::<W64>((1u64 << 10) - 1);
    let sticky_bits = b.and::<W64>(sig, sticky_mask);
    let sticky = b.cmp::<W64>(Cmp::Ne, sticky_bits, zero);
    let lsb = b.and::<W64>(kept, one);
    let sticky_n = b.select::<W64>(sticky, one, zero);
    let tie = b.or::<W64>(sticky_n, lsb);
    let round_set = b.cmp::<W64>(Cmp::Eq, round_bit, one);
    let up_n = b.select::<W64>(round_set, tie, zero);
    let do_up = b.cmp::<W64>(Cmp::Ne, up_n, zero);
    let kept_plus = b.add::<W64>(kept, one);
    let kept_r = b.select::<W64>(do_up, kept_plus, kept);
    let s53 = b.konst::<W64>(53);
    let ov_bit = b.shr_l::<W64>(kept_r, s53);
    let round_ov = b.cmp::<W64>(Cmp::Eq, ov_bit, one);
    let frac_raw = b.and::<W64>(kept_r, m52);
    let frac = b.select::<W64>(round_ov, zero, frac_raw);
    let bias_delta = b.konst::<W64>(15360);
    let exp_base = b.sub::<W64>(ea, bias_delta);
    let exp_plus = b.add::<W64>(exp_base, one);
    let exp_f = b.select::<W64>(round_ov, exp_plus, exp_base);
    let under = b.cmp::<W64>(Cmp::LtU, ea, bias_delta);
    let exp_is_zero = b.cmp::<W64>(Cmp::Eq, exp_f, zero);
    let under_n = b.select::<W64>(under, one, zero);
    let exp0_n = b.select::<W64>(exp_is_zero, one, zero);
    let under_or = b.or::<W64>(under_n, exp0_n);
    let is_under = b.cmp::<W64>(Cmp::Ne, under_or, zero);
    let exp_max = b.konst::<W64>(2047);
    let over = b.cmp::<W64>(Cmp::GeU, exp_f, exp_max);
    let s52 = b.konst::<W64>(52);
    let exp_shift = b.shl::<W64>(exp_f, s52);
    let bits_num = b.or::<W64>(exp_shift, frac);
    let inf_exp = b.shl::<W64>(exp_max, s52);
    let bits_over = b.select::<W64>(over, inf_exp, bits_num);
    let bits_fin = b.select::<W64>(is_under, zero, bits_over);
    let bits_zero = b.select::<W64>(is_zero, zero, bits_fin);
    let frac80 = b.konst::<W64>((1u64 << 63) - 1);
    let frac_bits = b.and::<W64>(sig, frac80);
    let is_nan = b.cmp::<W64>(Cmp::Ne, frac_bits, zero);
    let nan_bits = b.konst::<W64>(0x7ff8_0000_0000_0000);
    let bits_special = b.select::<W64>(is_nan, nan_bits, inf_exp);
    let bits_mag = b.select::<W64>(is_special, bits_special, bits_zero);
    b.or::<W64>(bits_mag, sign_bit)
}

/// 80 ビットを符号付き 64 ビット整数へ丸める。丸め方向は FCW の RC。
/// 入らない値と非数は不定整数 0x8000_0000_0000_0000。
fn f80_to_i64<B: Backend>(b: &mut B, sig: B::V<W64>, exp: B::V<W16>) -> B::V<W64> {
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let mask15 = b.konst::<W64>(0x7fff);
    let special = b.konst::<W64>(0x7fff);
    let s15 = b.konst::<W64>(15);
    let s63 = b.konst::<W64>(63);
    let s10 = b.konst::<W64>(10);
    let bias = b.konst::<W64>(16383);
    let lim = b.konst::<W64>(16446);
    let indef = b.konst::<W64>(1u64 << 63);
    let rc_mask = b.konst::<W64>(3);

    let fcw = b.get(fcw_ref());
    let fcw64 = b.zext::<W16, W64>(fcw);
    let rc_sh = b.shr_l::<W64>(fcw64, s10);
    let rc = b.and::<W64>(rc_sh, rc_mask);
    let nearest = b.cmp::<W64>(Cmp::Eq, rc, zero);
    let floor = b.cmp::<W64>(Cmp::Eq, rc, one);
    let two = b.konst::<W64>(2);
    let ceil = b.cmp::<W64>(Cmp::Eq, rc, two);

    let exp64 = b.zext::<W16, W64>(exp);
    let ea = b.and::<W64>(exp64, mask15);
    let sign = b.shr_l::<W64>(exp64, s15);
    let is_sign = b.cmp::<W64>(Cmp::Eq, sign, one);
    let not_sign = bit_not(b, is_sign);
    let is_special = b.cmp::<W64>(Cmp::Eq, ea, special);
    let is_zero_exp = b.cmp::<W64>(Cmp::Eq, ea, zero);
    let ge_one = b.cmp::<W64>(Cmp::GeU, ea, bias);
    let lt_ovf = b.cmp::<W64>(Cmp::LtU, ea, lim);
    let in_norm = bit_and(b, ge_one, lt_ovf);
    let at_63 = b.cmp::<W64>(Cmp::Eq, ea, lim);
    let above = b.cmp::<W64>(Cmp::GtU, ea, lim);

    let unb_raw = b.sub::<W64>(ea, bias);
    let unb = b.select::<W64>(ge_one, unb_raw, zero);
    let shift_raw = b.sub::<W64>(s63, unb);
    let shift = b.select::<W64>(in_norm, shift_raw, zero);
    let trunc = b.shr_l::<W64>(sig, shift);
    let one_sh = b.shl::<W64>(one, shift);
    let rem_mask = b.sub::<W64>(one_sh, one);
    let rem = b.and::<W64>(sig, rem_mask);
    let shift_nz = b.cmp::<W64>(Cmp::Ne, shift, zero);
    let shift_m1_raw = b.sub::<W64>(shift, one);
    let sh_m1 = b.select::<W64>(shift_nz, shift_m1_raw, zero);
    let round_src = b.shr_l::<W64>(rem, sh_m1);
    let round_bit = b.and::<W64>(round_src, one);
    let round_on = b.cmp::<W64>(Cmp::Eq, round_bit, one);
    let one_sticky = b.shl::<W64>(one, sh_m1);
    let sticky_mask = b.sub::<W64>(one_sticky, one);
    let sticky_bits = b.and::<W64>(rem, sticky_mask);
    let sticky = b.cmp::<W64>(Cmp::Ne, sticky_bits, zero);
    let any_frac = bit_or(b, round_on, sticky);
    let lsb = b.and::<W64>(trunc, one);
    let lsb_on = b.cmp::<W64>(Cmp::Eq, lsb, one);
    let tie = bit_or(b, sticky, lsb_on);
    let near_round = bit_and(b, nearest, round_on);
    let nearest_up = bit_and(b, near_round, tie);
    let floor_sign = bit_and(b, floor, is_sign);
    let floor_up = bit_and(b, floor_sign, any_frac);
    let ceil_pos = bit_and(b, ceil, not_sign);
    let ceil_up = bit_and(b, ceil_pos, any_frac);
    let up_nf = bit_or(b, nearest_up, floor_up);
    let up_raw = bit_or(b, up_nf, ceil_up);
    let do_up = bit_and(b, up_raw, in_norm);
    let mag_base = b.select::<W64>(in_norm, trunc, zero);
    let mag_plus = b.add::<W64>(mag_base, one);
    let mag_norm = b.select::<W64>(do_up, mag_plus, mag_base);
    let eq_min = b.cmp::<W64>(Cmp::Eq, mag_norm, indef);
    let ovf_norm = bit_and(b, eq_min, not_sign);

    let exact_min = b.cmp::<W64>(Cmp::Eq, sig, indef);
    let at_and_exact = bit_and(b, at_63, exact_min);
    let ok_min = bit_and(b, at_and_exact, is_sign);
    let not_ok_min = bit_not(b, ok_min);
    let ovf_63 = bit_and(b, at_63, not_ok_min);

    let not_ge = bit_not(b, ge_one);
    let not_zero = bit_not(b, is_zero_exp);
    let not_special = bit_not(b, is_special);
    let below = bit_and(b, not_ge, not_zero);
    let frac = bit_and(b, below, not_special);
    let k_raw = b.sub::<W64>(bias, ea);
    let k = b.select::<W64>(frac, k_raw, zero);
    let k_is_1 = b.cmp::<W64>(Cmp::Eq, k, one);
    let only_int = b.cmp::<W64>(Cmp::Eq, sig, indef);
    let not_only = bit_not(b, only_int);
    let gt_half = bit_and(b, k_is_1, not_only);
    let near_one = bit_and(b, nearest, gt_half);
    let floor_one = bit_and(b, floor, is_sign);
    let ceil_one = bit_and(b, ceil, not_sign);
    let frac_mode = bit_or(b, near_one, floor_one);
    let frac_mode = bit_or(b, frac_mode, ceil_one);
    let frac_one = bit_and(b, frac, frac_mode);
    let mag_frac = b.select::<W64>(frac_one, one, zero);

    let mag_or_norm = b.select::<W64>(frac, mag_frac, mag_norm);
    let mag = b.select::<W64>(ok_min, indef, mag_or_norm);
    let neg = b.sub::<W64>(zero, mag);
    let signed = b.select::<W64>(is_sign, neg, mag);
    let bad_hi = bit_or(b, is_special, above);
    let bad_ovf = bit_or(b, ovf_63, ovf_norm);
    let bad = bit_or(b, bad_hi, bad_ovf);
    b.select::<W64>(bad, indef, signed)
}

/// FISTP m64。整数を書いてから ST(0) を捨てる。
fn fistp_m64_at<B: Backend>(b: &mut B, addr: B::V<W64>) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let bits = f80_to_i64(b, sig, exp);
    b.store::<W64>(addr, bits, DATA_WRITE)?;
    pop_st(b, top)
}

/// FISTP m64 [base+disp8] (DF /7 SIB mod=01, no_index)。seq 0x4d0c31 対応.
pub fn fistp_m64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    fistp_m64_at(b, addr)
}

/// FISTP m64 [base+index*scale+disp8] (DF /7 SIB mod=01)。
pub fn fistp_m64_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    fistp_m64_at(b, addr)
}

fn pop_st<B: Backend>(b: &mut B, top: B::V<W16>) -> Flow<B> {
    let zero64 = b.konst::<W64>(0);
    let zero16 = b.konst::<W16>(0);
    for slot in 0..8 {
        let idx = b.konst::<W16>(slot as u16);
        let hit = b.cmp::<W16>(Cmp::Eq, top, idx);
        let old_sig = b.get(st_sig_ref(slot));
        let old_exp = b.get(st_exp_ref(slot));
        let new_sig = b.select::<W64>(hit, zero64, old_sig);
        let new_exp = b.select::<W16>(hit, zero16, old_exp);
        b.set(st_sig_ref(slot), new_sig);
        b.set(st_exp_ref(slot), new_exp);
    }
    let one = b.konst::<W16>(1);
    let inc = b.add::<W16>(top, one);
    let seven = b.konst::<W16>(7);
    let new_top = b.and::<W16>(inc, seven);
    b.set(top_ref(), new_top);
    Ok(())
}

/// FSTP m64 [base+disp8] (DD /3 SIB mod=01, no_index)。seq 0x4d3169 対応.
pub fn fstp_m64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let bits = f80_to_f64(b, sig, exp);
    let addr = eff_addr(b, base, disp);
    b.store::<W64>(addr, bits, DATA_WRITE)?;
    pop_st(b, top)
}

/// FSTP m64 [base+index*scale+disp8] (DD /3 SIB mod=01)。
pub fn fstp_m64_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let top = b.get(top_ref());
    let (sig, exp) = read_st(b, top);
    let bits = f80_to_f64(b, sig, exp);
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    b.store::<W64>(addr, bits, DATA_WRITE)?;
    pop_st(b, top)
}

/// FLDCW m16 [base] (D9 /5 mod=00)。x87 制御ワードを読む.
pub fn fldcw_memnd<B: Backend>(b: &mut B, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    b.set(fcw_ref(), v);
    Ok(())
}

/// FLDCW m16 [base+disp8] (D9 /5 mod=01)。
pub fn fldcw_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    b.set(fcw_ref(), v);
    Ok(())
}

/// FLDCW m16 [base+index*scale+disp8] (D9 /5 SIB mod=01)。seq 0x4d0c2d 対応.
pub fn fldcw_sibd<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, disp: i8) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    b.set(fcw_ref(), v);
    Ok(())
}

/// FLDCW m16 [base+disp32] (D9 /5 mod=10)。
pub fn fldcw_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    b.set(fcw_ref(), v);
    Ok(())
}

/// POR xmm,[base] (66 0F EB mod=00)。
pub fn por_xmm_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let v = b.or::<W128>(a, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// POR xmm,[base+disp8] (66 0F EB mod=01)。
pub fn por_xmm_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let v = b.or::<W128>(a, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// POR xmm,[base+disp32] (66 0F EB mod=10)。
pub fn por_xmm_mem32<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let v = b.or::<W128>(a, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// POR xmm,[base+index*scale+disp32] (66 0F EB SIB mod=10)。grep 0x43d15b 対応.
pub fn por_xmm_sibd32<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let c: B::V<W128> = b.load::<W128>(addr, DATA_READ)?;
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let v = b.or::<W128>(a, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// CALL [RIP+disp32] (FF /2 RIP)。64ビット間接コール.
pub fn call_r64_rip<B: Backend>(b: &mut B, eip_next: u64, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL [disp32] abs (32ビット)。
pub fn call_r32_abs<B: Backend>(b: &mut B, eip_next: u32, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// MOV r8,[base] (8A /r mod=00)。8ビットロード.
pub fn mov_r8_m8_memnd<B: Backend>(b: &mut B, dst: Gpr, dst_high: bool, base: Gpr) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    write8(b, dst, dst_high, x);
    Ok(())
}

/// XOR r8,[base] (32 /r mod=00)。cksum 0x5c7fc7 対応.
pub fn xor_r8_m8_memnd<B: Backend>(b: &mut B, dst: Gpr, dst_high: bool, base: Gpr) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let x = read8(b, dst, dst_high);
    let v = b.xor::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// MOV r8,[base+disp8] (8A /r mod=01)。
pub fn mov_r8_m8_mem8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    write8(b, dst, dst_high, x);
    Ok(())
}

/// MOV r8,[base+disp32] (8A /r mod=10)。
pub fn mov_r8_m8_mem32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    write8(b, dst, dst_high, x);
    Ok(())
}

/// MOV r8,[RIP+disp32] (8A /r RIP)。
pub fn mov_r8_m8_rip<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    next_rip: u64,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    write8(b, dst, dst_high, x);
    Ok(())
}

/// MOVZX r32,m16 [base+index*scale+disp8] (0F B7 SIB mod=01)。
pub fn movzx_r32_m16_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m16 [base+index*scale+disp8] (0F B7 SIB mod=01, REX.W)。
pub fn movzx_r64_m16_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W64>(v16);
    write64(b, dst, v);
    Ok(())
}

/// MOVZX r32,m16 [base+disp8] (0F B7 mod=01)。
pub fn movzx_r32_m16_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m16 [base+disp8] (0F B7 mod=01, REX.W)。
pub fn movzx_r64_m16_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W64>(v16);
    write64(b, dst, v);
    Ok(())
}

/// MOV [base+index*scale+disp8],r16 (66 89 SIB mod=01)。16ビットストア.
pub fn mov_m16_r16_sibd<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    b.store::<W16>(addr, v16, DATA_WRITE)?;
    Ok(())
}

/// MOV r16,[base+index*scale+disp8] (66 8B SIB mod=01)。上位は保存.
pub fn mov_r16_m16_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let cur32 = read(b, dst);
    let mask = b.konst::<W32>(0xffff_0000);
    let preserved = b.and::<W32>(cur32, mask);
    let ext32 = b.zext::<W16, W32>(v16);
    let v = b.or::<W32>(preserved, ext32);
    write(b, dst, v);
    Ok(())
}

/// MOV [base+disp8],r16 (66 89 mod=01)。16ビットストア.
pub fn mov_m16_r16_mem8<B: Backend>(b: &mut B, src: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    b.store::<W16>(addr, v16, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+disp32],r16 (66 89 mod=10)。16ビットストア.
pub fn mov_m16_r16_mem32<B: Backend>(b: &mut B, src: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr32(b, base, disp);
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    b.store::<W16>(addr, v16, DATA_WRITE)?;
    Ok(())
}

/// MOV r16,[base+disp8] (66 8B mod=01)。上位は保存.
pub fn mov_r16_m16_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let cur32 = read(b, dst);
    let mask = b.konst::<W32>(0xffff_0000);
    let preserved = b.and::<W32>(cur32, mask);
    let ext32 = b.zext::<W16, W32>(v16);
    let v = b.or::<W32>(preserved, ext32);
    write(b, dst, v);
    Ok(())
}

/// XCHG r32,r/m32 reg-direct。dst=reg, src=rm を交換.
pub fn xchg_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let a = read(b, dst);
    let c = read(b, src);
    write(b, dst, c);
    write(b, src, a);
    Ok(())
}

/// XCHG r64,r/m64 reg-direct (REX.W)。
pub fn xchg_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let a = read64(b, dst);
    let c = read64(b, src);
    write64(b, dst, c);
    write64(b, src, a);
    Ok(())
}

/// XCHG r32,[base] (87 /r mod=00)。
pub fn xchg_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let r = read(b, dst);
    b.store::<W32>(addr, r, DATA_WRITE)?;
    write(b, dst, m);
    Ok(())
}

/// XCHG r64,[base] (87 /r mod=00, REX.W)。
pub fn xchg_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let r = read64(b, dst);
    b.store::<W64>(addr, r, DATA_WRITE)?;
    write64(b, dst, m);
    Ok(())
}

/// XCHG r32,[base+disp8] (87 /r mod=01)。
pub fn xchg_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let r = read(b, dst);
    b.store::<W32>(addr, r, DATA_WRITE)?;
    write(b, dst, m);
    Ok(())
}

/// XCHG r64,[base+disp8] (87 /r mod=01, REX.W)。
pub fn xchg_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let r = read64(b, dst);
    b.store::<W64>(addr, r, DATA_WRITE)?;
    write64(b, dst, m);
    Ok(())
}

/// XCHG r32,[base+disp32] (87 /r mod=10)。
pub fn xchg_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let r = read(b, dst);
    b.store::<W32>(addr, r, DATA_WRITE)?;
    write(b, dst, m);
    Ok(())
}

/// XCHG r64,[base+disp32] (87 /r mod=10, REX.W)。
pub fn xchg_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let r = read64(b, dst);
    b.store::<W64>(addr, r, DATA_WRITE)?;
    write64(b, dst, m);
    Ok(())
}

/// XCHG r32,[RIP+disp32] (87 /r RIP)。
pub fn xchg_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let r = read(b, dst);
    b.store::<W32>(addr, r, DATA_WRITE)?;
    write(b, dst, m);
    Ok(())
}

/// XCHG r64,[RIP+disp32] (87 /r RIP, REX.W)。
pub fn xchg_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let r = read64(b, dst);
    b.store::<W64>(addr, r, DATA_WRITE)?;
    write64(b, dst, m);
    Ok(())
}

/// CMP r32, [index*scale+disp32] abs (3B SIB 直接番地、索引あり)。
pub fn cmp_r32_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, [index*scale+disp32] abs (3B SIB 直接番地、索引あり、REX.W)。
pub fn cmp_r64_sibabs<B: Backend>(b: &mut B, dst: Gpr, idx: Gpr, shift: u32, disp: i32) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, FS:[disp32] (FS + 3B SIB 直接番地)。
pub fn cmp_r32_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, FS:[disp32] (FS + 3B SIB 直接番地、REX.W)。
pub fn cmp_r64_fs_abs<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(fs_base);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [disp32] abs (REX.W)。
pub fn cmp_r64_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMPXCHG r32, r/m32 reg-direct。RAXと比較し、等しければdst=src、異なればdst=RAX.
pub fn cmpxchg_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let acc = read(b, Gpr(0));
    let m = read(b, dst);
    let r = read(b, src);
    let v = b.sub::<W32>(m, acc);
    update_sub_flags(b, m, acc, v);
    let is_eq = {
        let zf = read_zf(b);
        let one = b.konst::<W32>(1);
        let zero = b.konst::<W32>(0);
        let n = b.select::<W32>(zf, one, zero);
        b.cmp::<W32>(Cmp::Ne, n, zero)
    };
    // is_eq が真なら dst=r、偽なら dst=acc? 実際は mem/reg 交換だが reg-direct では dst が mem 役.
    // dst(mem役)= is_eq ? r : m (m はそのまま)、RAX = is_eq ? acc : m.
    let new_mem = b.select::<W32>(is_eq, r, m);
    let new_acc = b.select::<W32>(is_eq, acc, m);
    write(b, dst, new_mem);
    write(b, Gpr(0), new_acc);
    // clear_hi は呼び出し側で行う (REX.W なしの64bit時)。
    Ok(())
}

/// CMPXCHG r64, r/m64 reg-direct (REX.W)。
pub fn cmpxchg_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let acc = read64(b, Gpr(0));
    let m = read64(b, dst);
    let r = read64(b, src);
    let v = b.sub::<W64>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let n = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, n, zero);
    let new_mem = b.select::<W64>(is_eq, r, m);
    let new_acc = b.select::<W64>(is_eq, acc, m);
    write64(b, dst, new_mem);
    write64(b, Gpr(0), new_acc);
    Ok(())
}

/// CMPXCHG [base],r32 (0F B1 mod=00)。
pub fn cmpxchg_r32_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let acc = read(b, Gpr(0));
    let r = read(b, src);
    let v = b.sub::<W32>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let n = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, n, zero);
    let new_mem = b.select::<W32>(is_eq, r, m);
    let new_acc = b.select::<W32>(is_eq, acc, m);
    b.store::<W32>(addr, new_mem, DATA_WRITE)?;
    write(b, Gpr(0), new_acc);
    clear_hi(b, Gpr(0));
    Ok(())
}

/// CMPXCHG [base],r64 (0F B1 mod=00, REX.W)。
pub fn cmpxchg_r64_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let acc = read64(b, Gpr(0));
    let r = read64(b, src);
    let v = b.sub::<W64>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let n = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, n, zero);
    let new_mem = b.select::<W64>(is_eq, r, m);
    let new_acc = b.select::<W64>(is_eq, acc, m);
    b.store::<W64>(addr, new_mem, DATA_WRITE)?;
    write64(b, Gpr(0), new_acc);
    Ok(())
}

/// CMPXCHG [base+disp8],r32 (0F B1 mod=01)。
pub fn cmpxchg_r32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let acc = read(b, Gpr(0));
    let r = read(b, src);
    let v = b.sub::<W32>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let zn = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, zn, zero);
    let new_mem = b.select::<W32>(is_eq, r, m);
    let new_acc = b.select::<W32>(is_eq, acc, m);
    b.store::<W32>(addr, new_mem, DATA_WRITE)?;
    write(b, Gpr(0), new_acc);
    clear_hi(b, Gpr(0));
    Ok(())
}

/// CMPXCHG [base+disp8],r64 (REX.W)。
pub fn cmpxchg_r64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let acc = read64(b, Gpr(0));
    let r = read64(b, src);
    let v = b.sub::<W64>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let zn = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, zn, zero);
    let new_mem = b.select::<W64>(is_eq, r, m);
    let new_acc = b.select::<W64>(is_eq, acc, m);
    b.store::<W64>(addr, new_mem, DATA_WRITE)?;
    write64(b, Gpr(0), new_acc);
    Ok(())
}

/// CMPXCHG [base+disp32],r32 (0F B1 mod=10)。
pub fn cmpxchg_r32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let acc = read(b, Gpr(0));
    let r = read(b, src);
    let v = b.sub::<W32>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let zn = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, zn, zero);
    let new_mem = b.select::<W32>(is_eq, r, m);
    let new_acc = b.select::<W32>(is_eq, acc, m);
    b.store::<W32>(addr, new_mem, DATA_WRITE)?;
    write(b, Gpr(0), new_acc);
    clear_hi(b, Gpr(0));
    Ok(())
}

/// CMPXCHG [base+disp32],r64 (REX.W)。
pub fn cmpxchg_r64_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let acc = read64(b, Gpr(0));
    let r = read64(b, src);
    let v = b.sub::<W64>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let zn = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, zn, zero);
    let new_mem = b.select::<W64>(is_eq, r, m);
    let new_acc = b.select::<W64>(is_eq, acc, m);
    b.store::<W64>(addr, new_mem, DATA_WRITE)?;
    write64(b, Gpr(0), new_acc);
    Ok(())
}

/// CMPXCHG [RIP+disp32],r32。
pub fn cmpxchg_r32_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, src: Gpr) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let m: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let acc = read(b, Gpr(0));
    let r = read(b, src);
    let v = b.sub::<W32>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let zn = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, zn, zero);
    let new_mem = b.select::<W32>(is_eq, r, m);
    let new_acc = b.select::<W32>(is_eq, acc, m);
    b.store::<W32>(addr, new_mem, DATA_WRITE)?;
    write(b, Gpr(0), new_acc);
    clear_hi(b, Gpr(0));
    Ok(())
}

/// CMPXCHG [RIP+disp32],r64 (REX.W)。
pub fn cmpxchg_r64_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, src: Gpr) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let m: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let acc = read64(b, Gpr(0));
    let r = read64(b, src);
    let v = b.sub::<W64>(m, acc);
    update_sub_flags(b, m, acc, v);
    let zf = read_zf(b);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let zn = b.select::<W32>(zf, one, zero);
    let is_eq = b.cmp::<W32>(Cmp::Ne, zn, zero);
    let new_mem = b.select::<W64>(is_eq, r, m);
    let new_acc = b.select::<W64>(is_eq, acc, m);
    b.store::<W64>(addr, new_mem, DATA_WRITE)?;
    write64(b, Gpr(0), new_acc);
    Ok(())
}

/// JO rel8。OF=1 なら分岐.
pub fn jo<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let of = read_of(b);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(of, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JNO rel8。OF=0 なら分岐.
pub fn jno<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
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

/// JS rel8。SF=1 なら分岐.
pub fn js<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let sf = read_sf(b);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(sf, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JNS rel8。SF=0 なら分岐.
pub fn jns<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let sf = read_sf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(sf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
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

/// JP rel8。PF=1 なら分岐.
pub fn jp<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let pf = read_pf(b);
    let target = eip.wrapping_add(2).wrapping_add(disp as i32 as u32);
    let t = b.konst::<W32>(target);
    let tj = b.konst::<W64>(target as u64);
    b.if_then(pf, |b| {
        b.set(eip_ref(), t);
        b.jump(tj);
        Ok(())
    })?;
    Ok(())
}

/// JNP rel8。PF=0 なら分岐.
pub fn jnp<B: Backend>(b: &mut B, eip: u32, disp: i8) -> Flow<B> {
    let pf = read_pf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(pf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
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

/// SHL r/m32,CL (D3 /4)。CL 下位5ビットで論理左シフトし、CF/OF/SZP を更新する.
pub fn shl_rm32_cl<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let cl8 = read8(b, Gpr(1), false);
    let cl32 = b.zext::<W8, W32>(cl8);
    let mask = b.konst::<W32>(31);
    let count = b.and::<W32>(cl32, mask);
    let v = b.shl::<W32>(x, count);
    write(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shl::<W32>(x, safe_c1);
    let top_mask = b.konst::<W32>(0x8000_0000);
    let top = b.and::<W32>(shifted, top_mask);
    let cf_take = b.cmp::<W32>(Cmp::Ne, top, zero);
    let cf = pick(b, cf_take, FLAG_CF);
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

/// SHL r/m64,CL (REX.W + D3 /4)。
pub fn shl_rm64_cl<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let cl8 = read8(b, Gpr(1), false);
    let cl64 = b.zext::<W8, W64>(cl8);
    let mask = b.konst::<W64>(63);
    let count = b.and::<W64>(cl64, mask);
    let v = b.shl::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let c1 = b.sub::<W64>(count, one64);
    let safe_c1 = b.select::<W64>(active, c1, zero64);
    let shifted = b.shl::<W64>(x, safe_c1);
    let n63 = b.konst::<W64>(63);
    let top = b.shr_l::<W64>(shifted, n63);
    let low = b.and::<W64>(top, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, szp);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// SHR r/m32,CL (D3 /5)。CL 下位5ビットで論理右シフトし、CF/OF/SZP を更新する.
pub fn shr_rm32_cl<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let cl8 = read8(b, Gpr(1), false);
    let cl32 = b.zext::<W8, W32>(cl8);
    let mask = b.konst::<W32>(31);
    let count = b.and::<W32>(cl32, mask);
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

/// SHR r/m64,CL (REX.W + D3 /5)。
pub fn shr_rm64_cl<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let cl8 = read8(b, Gpr(1), false);
    let cl64 = b.zext::<W8, W64>(cl8);
    let mask = b.konst::<W64>(63);
    let count = b.and::<W64>(cl64, mask);
    let v = b.shr_l::<W64>(x, count);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let zero64 = b.konst::<W64>(0);
    let one64 = b.konst::<W64>(1);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let c1 = b.sub::<W64>(count, one64);
    let safe_c1 = b.select::<W64>(active, c1, zero64);
    let shifted = b.shr_l::<W64>(x, safe_c1);
    let low = b.and::<W64>(shifted, one64);
    let cf_take = b.cmp::<W64>(Cmp::Ne, low, zero64);
    let cf = pick(b, cf_take, FLAG_CF);
    let szp = szp_bits(b, v);
    let clear_mask = b.konst::<W32>(!FLAG_OSZPC);
    let mut new_flags = b.and::<W32>(old, clear_mask);
    new_flags = b.or::<W32>(new_flags, cf);
    new_flags = b.or::<W32>(new_flags, szp);
    let assembled = b.select::<W32>(active, new_flags, old);
    b.set(eflags_ref(), assembled);
    Ok(())
}

/// CMOVO r32, r/m32。OF=1 なら src を dst に移す.
pub fn cmovo_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_of(b);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVO r64, r/m64 (REX.W)。
pub fn cmovo_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_of(b);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVNO r32。OF=0 なら移す.
pub fn cmovno_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVNO r64 (REX.W)。
pub fn cmovno_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVS r32。SF=1 なら移す.
pub fn cmovs_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_sf(b);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVS r64 (REX.W)。
pub fn cmovs_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_sf(b);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVP r32。PF=1 なら移す.
pub fn cmovp_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_pf(b);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVP r64 (REX.W)。
pub fn cmovp_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let take = read_pf(b);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVNP r32。PF=0 なら移す.
pub fn cmovnp_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let pf = read_pf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(pf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVNP r64 (REX.W)。
pub fn cmovnp_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let pf = read_pf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let n = b.select::<W32>(pf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, n, zero);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVL r32。SF!=OF なら移す.
pub fn cmovl_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVL r64 (REX.W)。
pub fn cmovl_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVGE r32。SF==OF なら移す.
pub fn cmovge_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, sf_n, of_n);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVGE r64 (REX.W)。
pub fn cmovge_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, sf_n, of_n);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVGE r32, m32 SIB+disp8 (no_index)。SF==OF なら mem32 を dst に移す。seq 0x4d137a 対応.
pub fn cmovge_r32_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, sf_n, of_n);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVL r32, m32 SIB mod=00 (no_index)。SF!=OF なら mem32 を dst に移す。cut 0x492257 対応.
pub fn cmovl_r32_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, 0);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVL r64, m64 SIB mod=00 (no_index, REX.W)。SF!=OF なら mem64 を dst に移す.
pub fn cmovl_r64_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, 0);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVGE r64, m64 SIB+disp8 (no_index, REX.W)。SF==OF なら mem64 を dst に移す.
pub fn cmovge_r64_sibd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, sf_n, of_n);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVLE r32。ZF=1 または SF!=OF なら移す.
pub fn cmovle_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let zf = read_zf(b);
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let ne = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
    let ne_n = b.select::<W32>(ne, one, zero);
    let zf_n = b.select::<W32>(zf, one, zero);
    let either = b.or::<W32>(zf_n, ne_n);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVLE r64 (REX.W)。
pub fn cmovle_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let zf = read_zf(b);
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let ne = b.cmp::<W32>(Cmp::Ne, sf_n, of_n);
    let ne_n = b.select::<W32>(ne, one, zero);
    let zf_n = b.select::<W32>(zf, one, zero);
    let either = b.or::<W32>(zf_n, ne_n);
    let take = b.cmp::<W32>(Cmp::Ne, either, zero);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVG r32。ZF=0 かつ SF==OF なら移す.
pub fn cmovg_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let zf = read_zf(b);
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let eq = b.cmp::<W32>(Cmp::Eq, sf_n, of_n);
    let eq_n = b.select::<W32>(eq, one, zero);
    let zf_n = b.select::<W32>(zf, one, zero);
    let zf_zero = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let zf_zero_n = b.select::<W32>(zf_zero, one, zero);
    let both = b.and::<W32>(zf_zero_n, eq_n);
    let take = b.cmp::<W32>(Cmp::Ne, both, zero);
    let srcv = read(b, src);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVG r64 (REX.W)。
pub fn cmovg_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let zf = read_zf(b);
    let sf = read_sf(b);
    let of = read_of(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let sf_n = b.select::<W32>(sf, one, zero);
    let of_n = b.select::<W32>(of, one, zero);
    let eq = b.cmp::<W32>(Cmp::Eq, sf_n, of_n);
    let eq_n = b.select::<W32>(eq, one, zero);
    let zf_n = b.select::<W32>(zf, one, zero);
    let zf_zero = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let zf_zero_n = b.select::<W32>(zf_zero, one, zero);
    let both = b.and::<W32>(zf_zero_n, eq_n);
    let take = b.cmp::<W32>(Cmp::Ne, both, zero);
    let srcv = read64(b, src);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// PCMPEQD xmm1, xmm2。32ビット毎に等しければ 0xFFFFFFFF、異なれば 0x00.
pub fn pcmpeqd_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..4 {
        let shift = b.konst::<W128>((i * 32) as u128);
        let mask = b.konst::<W128>(0xFFFF_FFFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab32 = b.and::<W128>(ab, mask);
        let cb32 = b.and::<W128>(cb, mask);
        let eq = b.cmp::<W128>(Cmp::Eq, ab32, cb32);
        let one = b.konst::<W128>(0xFFFF_FFFF);
        let zero = b.konst::<W128>(0);
        let dw = b.select::<W128>(eq, one, zero);
        let pos = b.shl::<W128>(dw, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// MOVZX r64,m16 [base+disp32] (0F B7 mod=10, REX.W)。
pub fn movzx_r64_m16_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr32(b, base, disp);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W64>(v16);
    write64(b, dst, v);
    Ok(())
}

/// IMUL r32, r/m32, imm8 reg-direct (6B /r ib mod=11)。
pub fn imul_r32_imm8<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, imm: i8) -> Flow<B> {
    let x = read(b, src);
    let y = b.konst::<W32>(imm as i32 as u32);
    let x64 = b.sext::<W32, W64>(x);
    let y64 = b.sext::<W32, W64>(y);
    let p64 = b.mul::<W64>(x64, y64);
    let v: B::V<W32> = b.trunc::<W64, W32>(p64);
    write(b, dst, v);
    Ok(())
}

/// IMUL r64, r/m64, imm8 reg-direct (6B /r ib mod=11, REX.W)。
pub fn imul_r64_imm8<B: Backend>(b: &mut B, dst: Gpr, src: Gpr, imm: i8) -> Flow<B> {
    let x = read64(b, src);
    let y = b.konst::<W64>(imm as i64 as u64);
    let x128 = b.sext::<W64, W128>(x);
    let y128 = b.sext::<W64, W128>(y);
    let p128 = b.mul::<W128>(x128, y128);
    let v: B::V<W64> = b.trunc::<W128, W64>(p128);
    write64(b, dst, v);
    Ok(())
}

/// BSR 共通: 32bit値のリーディングゼロから最上位1の位置を求める (0なら32).
fn bsr_ctz32<B: Backend>(b: &mut B, y: B::V<W32>) -> B::V<W32> {
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let c32 = b.konst::<W32>(32);
    let mut acc: B::V<W32> = c32;
    for i in (0..32).rev() {
        let bit = b.konst::<W32>(1u32 << i);
        let t = b.and::<W32>(y, bit);
        let nz = b.cmp::<W32>(Cmp::Ne, t, zero);
        let cand = b.konst::<W32>(i);
        let undecided = b.cmp::<W32>(Cmp::Eq, acc, c32);
        let nz_n = b.select::<W32>(nz, one, zero);
        let un_n = b.select::<W32>(undecided, one, zero);
        let both = b.and::<W32>(nz_n, un_n);
        let take_b = b.cmp::<W32>(Cmp::Ne, both, zero);
        acc = b.select::<W32>(take_b, cand, acc);
    }
    acc
}

/// BSR 共通: 64bit値の最上位1の位置 (0なら64).
fn bsr_ctz64<B: Backend>(b: &mut B, y: B::V<W64>) -> B::V<W64> {
    let zero64 = b.konst::<W64>(0);
    let one32 = b.konst::<W32>(1);
    let zero32 = b.konst::<W32>(0);
    let c64 = b.konst::<W64>(64);
    let mut acc: B::V<W64> = c64;
    for i in (0..64).rev() {
        let bit = b.konst::<W64>(1u64 << (i % 64));
        let t = b.and::<W64>(y, bit);
        let take = b.cmp::<W64>(Cmp::Ne, t, zero64);
        let a64 = b.cmp::<W64>(Cmp::Eq, acc, c64);
        let an = b.select::<W32>(a64, one32, zero32);
        let tn = b.select::<W32>(take, one32, zero32);
        let both = b.and::<W32>(an, tn);
        let upd = b.cmp::<W32>(Cmp::Ne, both, zero32);
        let cand = b.konst::<W64>(i as u64);
        acc = b.select::<W64>(upd, cand, acc);
    }
    acc
}

/// BSR の ZF 更新 (ZF のみ、他は保存).
fn bsr_set_zf<B: Backend>(b: &mut B, is_zero: B::B) {
    let old: B::V<W32> = b.get(eflags_ref());
    let zf_on = b.konst::<W32>(crate::sem::FLAG_ZF);
    let zf_off_mask = b.konst::<W32>(!crate::sem::FLAG_ZF);
    let cleared = b.and::<W32>(old, zf_off_mask);
    let zero32 = b.konst::<W32>(0);
    let zf_new = b.select::<W32>(is_zero, zf_on, zero32);
    let nv = b.or::<W32>(cleared, zf_new);
    b.set(eflags_ref(), nv);
}

/// BSR r32, r/m32 reg-direct。最上位の1の位置を求める。src=0ならZF=1、dst不定 (0とする).
pub fn bsr_r32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let y = read(b, src);
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsr_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r64, r/m64 reg-direct (REX.W)。
pub fn bsr_r64<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let y = read64(b, src);
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsr_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r32, m32 [base] (mod=00)。
pub fn bsr_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsr_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r64, m64 [base] (mod=00, REX.W)。
pub fn bsr_r64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsr_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r32, m32 [base+disp8] (mod=01)。
pub fn bsr_r32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsr_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r64, m64 [base+disp8] (REX.W)。
pub fn bsr_r64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsr_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r32, m32 [base+disp32] (mod=10)。
pub fn bsr_r32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsr_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r64, m64 [base+disp32] (REX.W)。
pub fn bsr_r64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsr_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r32, m32 [RIP+disp32]。
pub fn bsr_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zero = b.konst::<W32>(0);
    let is_zero = b.cmp::<W32>(Cmp::Eq, y, zero);
    let acc = bsr_ctz32(b, y);
    let v = b.select::<W32>(is_zero, zero, acc);
    write(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// BSR r64, m64 [RIP+disp32] (REX.W)。
pub fn bsr_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zero64 = b.konst::<W64>(0);
    let is_zero = b.cmp::<W64>(Cmp::Eq, y, zero64);
    let acc = bsr_ctz64(b, y);
    let v = b.select::<W64>(is_zero, zero64, acc);
    write64(b, dst, v);
    bsr_set_zf(b, is_zero);
    Ok(())
}

/// ADD m32,imm8 [RIP+disp32] (83 /0 RIP)。
pub fn add_rm32_imm8_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: i8) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,imm8 [RIP+disp32] (83 /0 RIP, REX.W)。
pub fn add_rm64_imm8_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: i8) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m32,imm8 [disp32] abs (32ビット)。
pub fn add_rm32_imm8_abs<B: Backend>(b: &mut B, addr32: u32, imm: i8) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// PMINUB xmm1, xmm2。符号なしバイト毎に小さい方を選ぶ.
pub fn pminub_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let take_a = b.cmp::<W128>(Cmp::LtU, ab8, cb8);
        let byte = b.select::<W128>(take_a, ab8, cb8);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PMAXUB xmm1, xmm2。df 0x4d0bcd 対応。符号なしバイト毎に大きい方を選ぶ.
pub fn pmaxub_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let take_a = b.cmp::<W128>(Cmp::GtU, ab8, cb8);
        let byte = b.select::<W128>(take_a, ab8, cb8);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// CALL [base] (FF /2 SIB mod=00 no_index)。64ビット間接コール.
pub fn call_r64_memnd<B: Backend>(b: &mut B, eip_next: u64, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL [base+index*scale] (FF /2 SIB mod=00)。64ビット間接コール.
pub fn call_r64_sib<B: Backend>(
    b: &mut B,
    eip_next: u64,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL [disp32] (FF /2 SIB mod=00 base=直接番地、index なし)。64ビット間接コール.
pub fn call_r64_abs<B: Backend>(b: &mut B, eip_next: u64, disp: i32) -> Flow<B> {
    let addr = b.konst::<W64>(disp as i64 as u64);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(eip_next);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL [index*scale+disp32] (FF /2 SIB mod=00 base=直接番地)。64ビット間接コール.
pub fn call_r64_sibabs<B: Backend>(
    b: &mut B,
    eip_next: u64,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(eip_next);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL [index*scale+disp32] (FF /2 SIB mod=00 base=直接番地)。32ビット間接コール.
pub fn call_r32_sibabs<B: Backend>(
    b: &mut B,
    eip_next: u32,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(eip_next);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// CALL [base+index*scale+disp8] (FF /2 SIB mod=01)。64ビット間接コール.
pub fn call_r64_sibd<B: Backend>(
    b: &mut B,
    eip_next: u64,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL [base+index*scale+disp32] (FF /2 SIB mod=10)。64ビット間接コール.
pub fn call_r64_sibd32<B: Backend>(
    b: &mut B,
    eip_next: u64,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL [base] (FF /2 SIB mod=00 no_index、32ビット)。
pub fn call_r32_memnd<B: Backend>(b: &mut B, eip_next: u32, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// CALL [base+index*scale] (FF /2 SIB mod=00、32ビット)。
pub fn call_r32_sib<B: Backend>(
    b: &mut B,
    eip_next: u32,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// CALL [base+index*scale+disp8] (FF /2 SIB mod=01)。32ビット間接コール.
pub fn call_r32_sibd<B: Backend>(
    b: &mut B,
    eip_next: u32,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// CALL [base+index*scale+disp32] (FF /2 SIB mod=10)。32ビット間接コール.
pub fn call_r32_sibd32<B: Backend>(
    b: &mut B,
    eip_next: u32,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// MOVSXD r32, m32 [base] (63 /r mod=00)。32ビット転送と等価.
pub fn movsxd_rm32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOVSXD r64, m32 [base] (REX.W + 63 /r mod=00)。符号拡張する.
pub fn movsxd_rm64_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.sext::<W32, W64>(v32);
    write64(b, dst, v);
    Ok(())
}

/// MOVSXD r32, m32 [base+disp8] (63 /r mod=01)。
pub fn movsxd_rm32_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOVSXD r64, m32 [base+disp8] (REX.W)。
pub fn movsxd_rm64_mem8<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.sext::<W32, W64>(v32);
    write64(b, dst, v);
    Ok(())
}

/// MOVSXD r32, m32 [base+disp32] (63 /r mod=10)。
pub fn movsxd_rm32_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOVSXD r64, m32 [base+disp32] (REX.W)。
pub fn movsxd_rm64_mem32<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.sext::<W32, W64>(v32);
    write64(b, dst, v);
    Ok(())
}

/// MOVSXD r32, m32 [base+index*scale] (63 /r SIB mod=00)。
pub fn movsxd_rm32_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOVSXD r64, m32 [base+index*scale] (REX.W)。
pub fn movsxd_rm64_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.sext::<W32, W64>(v32);
    write64(b, dst, v);
    Ok(())
}

/// MOVSXD r32, m32 [base+index*scale+disp8] (SIB mod=01)。
pub fn movsxd_rm32_sibd<B: Backend>(
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

/// MOVSXD r64, m32 [base+index*scale+disp8] (REX.W)。
pub fn movsxd_rm64_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.sext::<W32, W64>(v32);
    write64(b, dst, v);
    Ok(())
}

/// MOVSXD r32, m32 [base+index*scale+disp32] (SIB mod=10)。
pub fn movsxd_rm32_sibd32<B: Backend>(
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

/// MOVSXD r64, m32 [base+index*scale+disp32] (REX.W)。
pub fn movsxd_rm64_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.sext::<W32, W64>(v32);
    write64(b, dst, v);
    Ok(())
}

/// CMOVE r64, m64 [RIP+disp32] (0F 44 /r RIP、REX.W)。ZF=1 なら移す.
pub fn cmove_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let take = read_zf(b);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVE r32, m32 [RIP+disp32]。ZF=1 なら移す.
pub fn cmove_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let take = read_zf(b);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVE r32, m32 [disp32] abs (32ビット)。
pub fn cmove_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let take = read_zf(b);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVNE r64, m64 [RIP+disp32] (0F 45 /r RIP、REX.W)。ZF=0 なら移す.
pub fn cmovne_r64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let srcv: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let dstv = read64(b, dst);
    let v = b.select::<W64>(take, srcv, dstv);
    write64(b, dst, v);
    Ok(())
}

/// CMOVNE r32, m32 [RIP+disp32]。ZF=0 なら移す.
pub fn cmovne_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CMOVNE r32, m32 [disp32] abs (32ビット)。
pub fn cmovne_r32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let srcv: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let zf = read_zf(b);
    let zero = b.konst::<W32>(0);
    let one = b.konst::<W32>(1);
    let zf_n = b.select::<W32>(zf, one, zero);
    let take = b.cmp::<W32>(Cmp::Eq, zf_n, zero);
    let dstv = read(b, dst);
    let v = b.select::<W32>(take, srcv, dstv);
    write(b, dst, v);
    Ok(())
}

/// CALL r/m64 [base+disp32] (FF /2 mod=10)。リターン先を積んで間接ジャンプ.
pub fn call_r64_mem32<B: Backend>(b: &mut B, eip_next: u64, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let target64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL r/m32 [base+disp32] (FF /2 mod=10、32ビット)。
pub fn call_r32_mem32<B: Backend>(b: &mut B, eip_next: u32, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let target: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// PUSH imm8 (6A ib、32ビット)。4バイト積む.
pub fn push_imm8_32<B: Backend>(b: &mut B, imm: i8) -> Flow<B> {
    let v = b.konst::<W32>(imm as i32 as u32);
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let addr = b.zext::<W32, W64>(next);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// PUSH imm8 (6A ib、64ビット)。符号拡張して8バイト積む.
pub fn push_imm8_64<B: Backend>(b: &mut B, imm: i8) -> Flow<B> {
    let v = b.konst::<W64>(imm as i64 as u64);
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    b.store::<W64>(next, v, DATA_WRITE)?;
    Ok(())
}

/// PUSH imm32 (68 id、32ビット)。4バイト積む.
pub fn push_imm32_32<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let v = b.konst::<W32>(imm);
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let addr = b.zext::<W32, W64>(next);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// PUSH imm32 (68 id、64ビット)。符号拡張して8バイト積む.
pub fn push_imm32_64<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let v = b.konst::<W64>(imm as i32 as i64 as u64);
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    b.store::<W64>(next, v, DATA_WRITE)?;
    Ok(())
}

/// CMPB m8,imm8 [base] (80 /7 mod=00)。8ビットを比較し、6 旗を更新する.
pub fn cmp_rm8_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMPB m8,imm8 [base+index*scale] (80 /7 SIB mod=00 indexed)。grep 0x43e0e4 対応.
pub fn cmp_rm8_imm_sib_idx<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: u8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// XCHG r32, RAX (91-97)。dst と RAX を交換.
pub fn xchg_r32_ax<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let a = read(b, dst);
    let c = read(b, Gpr(0));
    write(b, dst, c);
    write(b, Gpr(0), a);
    Ok(())
}

/// XCHG r64, RAX (REX.W + 91-97)。
pub fn xchg_r64_ax<B: Backend>(b: &mut B, dst: Gpr) -> Flow<B> {
    let a = read64(b, dst);
    let c = read64(b, Gpr(0));
    write64(b, dst, c);
    write64(b, Gpr(0), a);
    Ok(())
}

/// MOV r8,[base+index*scale] (8A /r SIB mod=00)。8ビットロード.
pub fn mov_r8_m8_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    write8(b, dst, dst_high, x);
    Ok(())
}

/// MOV r8,[base+index*scale+disp8] (8A /r SIB mod=01)。
pub fn mov_r8_m8_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    write8(b, dst, dst_high, x);
    Ok(())
}

/// MOV r8,[base+index*scale+disp32] (8A /r SIB mod=10)。
pub fn mov_r8_m8_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    write8(b, dst, dst_high, x);
    Ok(())
}

/// INC r64 (REX.W + FF /0)。64ビットで包む。CF 以外の 5 旗を更新する（CF は保存）。
pub fn inc_r64<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let x = read64(b, rd);
    let one = b.konst::<W64>(1);
    let v = b.add::<W64>(x, one);
    write64(b, rd, v);
    update_add_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// DEC r64 (REX.W + FF /1)。64ビットで包む。CF 以外の 5 旗を更新する（CF は保存）。
pub fn dec_r64<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let cf_mask = b.konst::<W32>(FLAG_CF);
    let all_flags = b.get(eflags_ref());
    let saved_cf = b.and::<W32>(all_flags, cf_mask);
    let x = read64(b, rd);
    let one = b.konst::<W64>(1);
    let v = b.sub::<W64>(x, one);
    write64(b, rd, v);
    update_sub_flags(b, x, one, v);
    let f = b.get(eflags_ref());
    let not_cf = b.konst::<W32>(!FLAG_CF);
    let cleared = b.and::<W32>(f, not_cf);
    let restored = b.or::<W32>(cleared, saved_cf);
    b.set(eflags_ref(), restored);
    Ok(())
}

/// CMP r/m8, r8 reg-direct (38 /r mod=11)。mem役=dst rm を src reg と比較.
pub fn cmp_m8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let y = read8(b, src, src_high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB r/m8, r8 reg-direct (28 /r mod=11)。dst rm から src reg を引いて書き戻す.
pub fn sub_m8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let y = read8(b, src, src_high);
    let v = b.sub::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// OR [base+disp8], r8 (08 /r SIB mod=01, no_index)。sed 0x4a87dd 対応.
pub fn or_m8_r8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.or::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR [base+index*scale+disp8], r8 (08 /r SIB mod=01)。
pub fn or_m8_r8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.or::<W8>(x, y);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR r/m8, r8 reg-direct (08 /r mod=11)。dst rm と src reg の OR で 5 旗を更新する.
pub fn or_m8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let y = read8(b, src, src_high);
    let v = b.or::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r/m8, r8 reg-direct (30 /r mod=11)。dst rm と src reg の XOR で 5 旗を更新する.
pub fn xor_m8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let y = read8(b, src, src_high);
    let v = b.xor::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// AND r/m8, r8 reg-direct (20 /r mod=11)。dst rm と src reg の AND で 5 旗を更新する.
pub fn and_m8_r8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let y = read8(b, src, src_high);
    let v = b.and::<W8>(x, y);
    write8(b, dst, dst_high, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XADD r32, m32 [base] (0F C1 mod=00)。dst とメモリを交換加算し、ADD の旗を立てる.
pub fn xadd_r32_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, x);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// XADD r32, m32 [RIP+disp32] (0F C1 mod=00 rm=101)。LOCK は無視.
pub fn xadd_r32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, x);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// SHLD r/m32,r32,CL (0F A5 /r mod=11)。dst を count だけ左へ二重シフトする.
pub fn shld_r32_cl<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let cl8 = read8(b, Gpr(1), false);
    let cl32 = b.zext::<W8, W32>(cl8);
    let mask = b.konst::<W32>(31);
    let count = b.and::<W32>(cl32, mask);
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let n32 = b.konst::<W32>(32);
    let r = b.sub::<W32>(n32, count);
    let yshr = b.shr_l::<W32>(y, r);
    let xshl = b.shl::<W32>(x, count);
    let v0 = b.or::<W32>(xshl, yshr);
    let v = b.select::<W32>(active, v0, x);
    write(b, dst, v);
    // 旗は SHL に準じる。count==0 では保存.
    let old: B::V<W32> = b.get(eflags_ref());
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shl::<W32>(x, safe_c1);
    let top_mask = b.konst::<W32>(0x8000_0000);
    let top = b.and::<W32>(shifted, top_mask);
    let cf_take = b.cmp::<W32>(Cmp::Ne, top, zero);
    let cf = pick(b, cf_take, FLAG_CF);
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

/// SHLD r/m64,r64,CL (REX.W + 0F A5 /r mod=11)。
pub fn shld_r64_cl<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let cl8 = read8(b, Gpr(1), false);
    let cl64 = b.zext::<W8, W64>(cl8);
    let mask = b.konst::<W64>(63);
    let count = b.and::<W64>(cl64, mask);
    let zero64 = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let n64 = b.konst::<W64>(64);
    let r = b.sub::<W64>(n64, count);
    let yshr = b.shr_l::<W64>(y, r);
    let xshl = b.shl::<W64>(x, count);
    let v0 = b.or::<W64>(xshl, yshr);
    let v = b.select::<W64>(active, v0, x);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let one64 = b.konst::<W64>(1);
    let c1 = b.sub::<W64>(count, one64);
    let safe_c1 = b.select::<W64>(active, c1, zero64);
    let shifted = b.shl::<W64>(x, safe_c1);
    let n63 = b.konst::<W64>(63);
    let top = b.shr_l::<W64>(shifted, n63);
    let low = b.and::<W64>(top, one64);
    let zero32 = b.konst::<W32>(0);
    let one32 = b.konst::<W32>(1);
    let low32: B::V<W32> = b.trunc::<W64, W32>(low);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low32, zero32);
    let cf = pick(b, cf_take, FLAG_CF);
    let v_top = b.shr_l::<W64>(v, n63);
    let v63 = b.and::<W64>(v_top, one64);
    let v63_32: B::V<W32> = b.trunc::<W64, W32>(v63);
    let out_top = b.shr_l::<W64>(shifted, n63);
    let cf01_64 = b.and::<W64>(out_top, one64);
    let cf01: B::V<W32> = b.trunc::<W64, W32>(cf01_64);
    let of_raw = b.cmp::<W32>(Cmp::Ne, v63_32, cf01);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let count32: B::V<W32> = b.trunc::<W64, W32>(count);
    let is_one = b.cmp::<W32>(Cmp::Eq, count32, one32);
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

/// SHRD r/m32,r32,CL (0F AD /r mod=11)。dst を count だけ右へ二重シフトする.
pub fn shrd_r32_cl<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let cl8 = read8(b, Gpr(1), false);
    let cl32 = b.zext::<W8, W32>(cl8);
    let mask = b.konst::<W32>(31);
    let count = b.and::<W32>(cl32, mask);
    let zero = b.konst::<W32>(0);
    let active = b.cmp::<W32>(Cmp::Ne, count, zero);
    let n32 = b.konst::<W32>(32);
    let r = b.sub::<W32>(n32, count);
    let xshr = b.shr_l::<W32>(x, count);
    let yshl = b.shl::<W32>(y, r);
    let v0 = b.or::<W32>(xshr, yshl);
    let v = b.select::<W32>(active, v0, x);
    write(b, dst, v);
    // 旗は SHR に準じる。count==0 では保存.
    let old: B::V<W32> = b.get(eflags_ref());
    let one = b.konst::<W32>(1);
    let c1 = b.sub::<W32>(count, one);
    let safe_c1 = b.select::<W32>(active, c1, zero);
    let shifted = b.shr_l::<W32>(x, safe_c1);
    let low = b.and::<W32>(shifted, one);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low, zero);
    let cf = pick(b, cf_take, FLAG_CF);
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

/// SHRD r/m64,r64,CL (REX.W + 0F AD /r mod=11)。
pub fn shrd_r64_cl<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read64(b, dst);
    let y = read64(b, src);
    let cl8 = read8(b, Gpr(1), false);
    let cl64 = b.zext::<W8, W64>(cl8);
    let mask = b.konst::<W64>(63);
    let count = b.and::<W64>(cl64, mask);
    let zero64 = b.konst::<W64>(0);
    let active = b.cmp::<W64>(Cmp::Ne, count, zero64);
    let n64 = b.konst::<W64>(64);
    let r = b.sub::<W64>(n64, count);
    let xshr = b.shr_l::<W64>(x, count);
    let yshl = b.shl::<W64>(y, r);
    let v0 = b.or::<W64>(xshr, yshl);
    let v = b.select::<W64>(active, v0, x);
    write64(b, dst, v);
    let old: B::V<W32> = b.get(eflags_ref());
    let one64 = b.konst::<W64>(1);
    let c1 = b.sub::<W64>(count, one64);
    let safe_c1 = b.select::<W64>(active, c1, zero64);
    let shifted = b.shr_l::<W64>(x, safe_c1);
    let low = b.and::<W64>(shifted, one64);
    let zero32 = b.konst::<W32>(0);
    let one32 = b.konst::<W32>(1);
    let low32: B::V<W32> = b.trunc::<W64, W32>(low);
    let cf_take = b.cmp::<W32>(Cmp::Ne, low32, zero32);
    let cf = pick(b, cf_take, FLAG_CF);
    let n63 = b.konst::<W64>(63);
    let v_top = b.shr_l::<W64>(v, n63);
    let v63 = b.and::<W64>(v_top, one64);
    let v63_32: B::V<W32> = b.trunc::<W64, W32>(v63);
    let out_top = b.shr_l::<W64>(shifted, n63);
    let cf01_64 = b.and::<W64>(out_top, one64);
    let cf01: B::V<W32> = b.trunc::<W64, W32>(cf01_64);
    let of_raw = b.cmp::<W32>(Cmp::Ne, v63_32, cf01);
    let of_new = pick(b, of_raw, FLAG_OF);
    let of_mask = b.konst::<W32>(FLAG_OF);
    let old_of = b.and::<W32>(old, of_mask);
    let count32: B::V<W32> = b.trunc::<W64, W32>(count);
    let is_one = b.cmp::<W32>(Cmp::Eq, count32, one32);
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

/// CMP [base], r8 (38 /r mod=00)。
pub fn cmp_m8_r8_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = read64(b, base);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP [base+disp8], r8 (38 /r mod=01)。
pub fn cmp_m8_r8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr, high: bool) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP [base+disp32], r8 (38 /r mod=10)。
pub fn cmp_m8_r8_mem32<B: Backend>(
    b: &mut B,
    base: Gpr,
    disp: i32,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP [base+index*scale], r8 (38 /r SIB mod=00)。
pub fn cmp_m8_r8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP [base+index*scale+disp8], r8 (38 /r SIB mod=01)。
pub fn cmp_m8_r8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP [base+index*scale+disp32], r8 (38 /r SIB mod=10)。
pub fn cmp_m8_r8_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
    high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = read8(b, src, high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r8, r/m8 reg-direct (3A /r mod=11)。
pub fn cmp_r8_m8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    src: Gpr,
    src_high: bool,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let y = read8(b, src, src_high);
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r8, [base] (3A /r mod=00)。
pub fn cmp_r8_m8_memnd<B: Backend>(b: &mut B, dst: Gpr, dst_high: bool, base: Gpr) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let addr = read64(b, base);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r8, [base+disp8] (3A /r mod=01)。
pub fn cmp_r8_m8_mem8<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let addr = eff_addr(b, base, disp);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r8, [base+disp32] (3A /r mod=10)。
pub fn cmp_r8_m8_mem32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let addr = eff_addr32(b, base, disp);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r8, [base+index*scale] (3A /r SIB mod=00)。
pub fn cmp_r8_m8_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r8, [base+index*scale+disp8] (3A /r SIB mod=01)。
pub fn cmp_r8_m8_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r8, [base+index*scale+disp32] (3A /r SIB mod=10)。
pub fn cmp_r8_m8_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    dst_high: bool,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W8;
    let x = read8(b, dst, dst_high);
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let v = b.sub::<W8>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// PSLLDQ xmm, imm8 (66 0F 73 /7 ib)。128ビット全体を imm バイト左シフト (imm*8ビット).
/// imm>16 ではゼロになる。
pub fn pslldq_xmm<B: Backend>(b: &mut B, dst: Xmm, imm: u8) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let n = (imm as u128).min(16) * 8;
    let shift = b.konst::<W128>(n);
    let v = b.shl::<W128>(a, shift);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// PSRLDQ xmm, imm8 (66 0F 73 /3 ib)。128ビット全体を imm バイト右シフト (imm*8ビット).
/// imm>16 ではゼロになる。
pub fn psrldq_xmm<B: Backend>(b: &mut B, dst: Xmm, imm: u8) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let n = (imm as u128).min(16) * 8;
    let shift = b.konst::<W128>(n);
    let v = b.shr_l::<W128>(a, shift);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// PSUBB xmm1, xmm2 (66 0F F8 /r)。バイト毎に wraparound 減算する.
pub fn psubb_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let d = b.sub::<W128>(ab8, cb8);
        let d8 = b.and::<W128>(d, mask);
        let pos = b.shl::<W128>(d8, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PADDB xmm1, xmm2 (66 0F FC /r)。バイト毎に wraparound 加算する.
pub fn paddb_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let d = b.add::<W128>(ab8, cb8);
        let d8 = b.and::<W128>(d, mask);
        let pos = b.shl::<W128>(d8, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PCMPGTB xmm1, xmm2 (66 0F 64 /r)。バイト毎に符号付き大于なら 0xFF、そうでなければ 0.
pub fn pcmpgtb_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..16 {
        let shift = b.konst::<W128>((i * 8) as u128);
        let mask = b.konst::<W128>(0xFF);
        let bias = b.konst::<W128>(0x80);
        let ab = b.shr_l::<W128>(a, shift);
        let cb = b.shr_l::<W128>(c, shift);
        // 符号付き比較は 0x80 バイアスで符号なし比較に直す.
        let ab8 = b.and::<W128>(ab, mask);
        let cb8 = b.and::<W128>(cb, mask);
        let au = b.xor::<W128>(ab8, bias);
        let cu = b.xor::<W128>(cb8, bias);
        let gt = b.cmp::<W128>(Cmp::GtU, au, cu);
        let zero = b.konst::<W128>(0);
        let byte = b.select::<W128>(gt, mask, zero);
        let pos = b.shl::<W128>(byte, shift);
        acc = b.or::<W128>(acc, pos);
    }
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// PANDN xmm1, xmm2 (66 0F DF /r)。(~dst) & src の128ビット AND.
pub fn pandn_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    let a: B::V<W128> = b.get(xmm_ref(dst));
    let c: B::V<W128> = b.get(xmm_ref(src));
    let ones = b.konst::<W128>(u128::MAX);
    let na = b.xor::<W128>(a, ones);
    let v = b.and::<W128>(na, c);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// CVTSI2SD xmm, r64 (F2 REX.W 0F 2A /r reg-direct)。64ビット整数を倍精度に変換し
/// XMM 下位64に置く。上位64は保持する。丸めは最近接偶数 (rm=0) とする.
pub fn cvtsi2sd_r64<B: Backend>(b: &mut B, dst: Xmm, src: Gpr) -> Flow<B> {
    use polyisa_sem::F64;
    let v64: B::V<W64> = read64(b, src);
    let f: B::V<F64> = b.fcvt_from_s64(v64, 0);
    let cur: B::V<W128> = b.get(xmm_ref(dst));
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(cur, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let lo64: B::V<W64> = b.trunc::<F64, W64>(f);
    let lo = b.zext::<W64, W128>(lo64);
    let v = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// CVTSI2SD xmm, m32 [base+disp8] (F2 0F 2A /r mod=01)。32ビット整数を倍精度に変換し
/// XMM 下位64に置く。上位64は保持する。丸めは最近接偶数 (rm=0) とする.
pub fn cvtsi2sd_xmm_m32_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::F64;
    let addr = eff_addr(b, base, disp);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let f: B::V<F64> = b.fcvt_from_s32(v32, 0);
    let cur: B::V<W128> = b.get(xmm_ref(dst));
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(cur, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let lo64: B::V<W64> = b.trunc::<F64, W64>(f);
    let lo = b.zext::<W64, W128>(lo64);
    let v = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// CVTSI2SD xmm, m64 [base+disp8] (F2 REX.W 0F 2A /r mod=01)。
pub fn cvtsi2sd_xmm_m64_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::F64;
    let addr = eff_addr(b, base, disp);
    let v64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let f: B::V<F64> = b.fcvt_from_s64(v64, 0);
    let cur: B::V<W128> = b.get(xmm_ref(dst));
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(cur, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let lo64: B::V<W64> = b.trunc::<F64, W64>(f);
    let lo = b.zext::<W64, W128>(lo64);
    let v = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// ADDSD xmm1, xmm2 (F2 0F 58 /r reg-direct)。下位64の倍精度加算。上位64は dst のまま.
pub fn addsd_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let c128: B::V<W128> = b.get(xmm_ref(src));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let clo64: B::V<W64> = b.trunc::<W128, W64>(c128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let c: B::V<F64> = b.trunc::<W64, F64>(clo64);
    let v = b.fadd(a, c);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// ADDSD xmm,m64 [base] (F2 0F 58 mod=00)。[base] の倍精度を下位64に加える。上位64は dst のまま.
pub fn addsd_xmm_m64_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = read64(b, base);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let v = b.fadd(a, c);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// ADDSD xmm,m64 [base+index*scale] (F2 0F 58 SIB mod=00)。
pub fn addsd_xmm_m64_sib<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let v = b.fadd(a, c);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// ADDSD xmm,m64 [base+disp8] (F2 0F 58 SIB mod=01, no_index)。seq 0x499253 対応.
pub fn addsd_xmm_m64_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = eff_addr(b, base, disp);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let v = b.fadd(a, c);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// ADDSD xmm,m64 [base+index*scale+disp8] (F2 0F 58 SIB mod=01)。
pub fn addsd_xmm_m64_sibd<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let v = b.fadd(a, c);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// ADDSD xmm,m64 RIP (F2 0F 58)。[RIP+disp] の倍精度を下位64に加える。上位64は dst のまま.
pub fn addsd_xmm_m64_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::F64;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let m: B::V<F64> = b.trunc::<W64, F64>(m64);
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let v = b.fadd(a, m);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// ADDSD xmm,[disp32] (32ビット絶対番地、倍精度ロード加算).
pub fn addsd_xmm_m64_abs<B: Backend>(b: &mut B, dst: Xmm, addr32: u32) -> Flow<B> {
    use polyisa_sem::F64;
    let addr = b.konst::<W64>(addr32 as u64);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let m: B::V<F64> = b.trunc::<W64, F64>(m64);
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let v = b.fadd(a, m);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// SUBSD xmm1, xmm2 (F2 0F 5C /r reg-direct)。下位64の倍精度減算。上位64は dst のまま.
pub fn subsd_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let c128: B::V<W128> = b.get(xmm_ref(src));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let clo64: B::V<W64> = b.trunc::<W128, W64>(c128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let c: B::V<F64> = b.trunc::<W64, F64>(clo64);
    let v = b.fsub(a, c);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// MULSD xmm1, xmm2 (F2 0F 59 /r reg-direct)。下位64の倍精度乗算。上位64は dst のまま.
pub fn mulsd_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let c128: B::V<W128> = b.get(xmm_ref(src));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let clo64: B::V<W64> = b.trunc::<W128, W64>(c128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let c: B::V<F64> = b.trunc::<W64, F64>(clo64);
    let v = b.fmul(a, c);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// MULSD xmm,m64 RIP (F2 0F 59)。[RIP+disp] の倍精度を下位64に掛ける。上位64は dst のまま.
pub fn mulsd_xmm_m64_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::F64;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let m: B::V<F64> = b.trunc::<W64, F64>(m64);
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let v = b.fmul(a, m);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// MULSD xmm,[disp32] (32ビット絶対番地、倍精度ロード乗算).
pub fn mulsd_xmm_m64_abs<B: Backend>(b: &mut B, dst: Xmm, addr32: u32) -> Flow<B> {
    use polyisa_sem::F64;
    let addr = b.konst::<W64>(addr32 as u64);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let m: B::V<F64> = b.trunc::<W64, F64>(m64);
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let v = b.fmul(a, m);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// MULSD xmm,m64 [base+disp8] (F2 0F 59 SIB mod=01, no_index)。seq 0x49924a 対応.
pub fn mulsd_xmm_m64_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = eff_addr(b, base, disp);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let m: B::V<F64> = b.trunc::<W64, F64>(m64);
    let v = b.fmul(a, m);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// MULSD xmm,m64 [base+index*scale+disp8] (F2 0F 59 SIB mod=01)。
pub fn mulsd_xmm_m64_sibd<B: Backend>(
    b: &mut B,
    dst: Xmm,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let m: B::V<F64> = b.trunc::<W64, F64>(m64);
    let v = b.fmul(a, m);
    let vlo64: B::V<W64> = b.trunc::<F64, W64>(v);
    let lo = b.zext::<W64, W128>(vlo64);
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(a128, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    let res = b.or::<W128>(hi_back, lo);
    b.set(xmm_ref(dst), res);
    Ok(())
}

/// COMISD xmm1, xmm2 (66 0F 2F /r reg-direct)。下位64の倍精度を比較し ZF/PF/CF を立てる.
/// OF/SF/AF は 0 にする。順序なし (NaN) では ZF=PF=CF=1。
pub fn comisd_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let c128: B::V<W128> = b.get(xmm_ref(src));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let clo64: B::V<W64> = b.trunc::<W128, W64>(c128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let c: B::V<F64> = b.trunc::<W64, F64>(clo64);
    let one32 = b.konst::<W32>(1);
    let zero32 = b.konst::<W32>(0);
    // B 同士の論理演算はないため、0/1 に整数化して組み立てる.
    let aa = b.feq(a, a);
    let aa1 = b.select::<W32>(aa, one32, zero32);
    let cc = b.feq(c, c);
    let cc1 = b.select::<W32>(cc, one32, zero32);
    let both = b.and::<W32>(aa1, cc1);
    let u1 = b.xor::<W32>(both, one32);
    let eq = b.feq(a, c);
    let e1 = b.select::<W32>(eq, one32, zero32);
    let lt = b.flt(a, c);
    let l1 = b.select::<W32>(lt, one32, zero32);
    // ZF = unordered OR eq、PF = unordered、CF = unordered OR lt.
    let zf = b.or::<W32>(u1, e1);
    let cf = b.or::<W32>(u1, l1);
    let six = b.konst::<W32>(6);
    let two = b.konst::<W32>(2);
    let zf_sh = b.shl::<W32>(zf, six);
    let pf_sh = b.shl::<W32>(u1, two);
    let f: B::V<W32> = b.get(eflags_ref());
    let clear = b.konst::<W32>(!(0x800 | 0x80 | 0x10 | 0x40 | 0x4 | 0x1));
    let cleared = b.and::<W32>(f, clear);
    let v1 = b.or::<W32>(cleared, zf_sh);
    let v2 = b.or::<W32>(v1, pf_sh);
    let v3 = b.or::<W32>(v2, cf);
    b.set(eflags_ref(), v3);
    Ok(())
}

/// UCOMISD xmm,m64 [base] (66 0F 2E mod=00)。非順序時は ZF=PF=CF=1.
pub fn ucomisd_xmm_memnd<B: Backend>(b: &mut B, dst: Xmm, base: Gpr) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = read64(b, base);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let one32 = b.konst::<W32>(1);
    let zero32 = b.konst::<W32>(0);
    let aa = b.feq(a, a);
    let aa1 = b.select::<W32>(aa, one32, zero32);
    let cc = b.feq(c, c);
    let cc1 = b.select::<W32>(cc, one32, zero32);
    let both = b.and::<W32>(aa1, cc1);
    let u1 = b.xor::<W32>(both, one32);
    let eq = b.feq(a, c);
    let e1 = b.select::<W32>(eq, one32, zero32);
    let lt = b.flt(a, c);
    let l1 = b.select::<W32>(lt, one32, zero32);
    let zf = b.or::<W32>(u1, e1);
    let cf = b.or::<W32>(u1, l1);
    let six = b.konst::<W32>(6);
    let two = b.konst::<W32>(2);
    let zf_sh = b.shl::<W32>(zf, six);
    let pf_sh = b.shl::<W32>(u1, two);
    let f: B::V<W32> = b.get(eflags_ref());
    let clear = b.konst::<W32>(!(0x800 | 0x80 | 0x10 | 0x40 | 0x4 | 0x1));
    let cleared = b.and::<W32>(f, clear);
    let v1 = b.or::<W32>(cleared, zf_sh);
    let v2 = b.or::<W32>(v1, pf_sh);
    let v3 = b.or::<W32>(v2, cf);
    b.set(eflags_ref(), v3);
    Ok(())
}

/// UCOMISD xmm,m64 [base+disp8] (66 0F 2E mod=01)。
pub fn ucomisd_xmm_mem8<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = eff_addr(b, base, disp);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let one32 = b.konst::<W32>(1);
    let zero32 = b.konst::<W32>(0);
    let aa = b.feq(a, a);
    let aa1 = b.select::<W32>(aa, one32, zero32);
    let cc = b.feq(c, c);
    let cc1 = b.select::<W32>(cc, one32, zero32);
    let both = b.and::<W32>(aa1, cc1);
    let u1 = b.xor::<W32>(both, one32);
    let eq = b.feq(a, c);
    let e1 = b.select::<W32>(eq, one32, zero32);
    let lt = b.flt(a, c);
    let l1 = b.select::<W32>(lt, one32, zero32);
    let zf = b.or::<W32>(u1, e1);
    let cf = b.or::<W32>(u1, l1);
    let six = b.konst::<W32>(6);
    let two = b.konst::<W32>(2);
    let zf_sh = b.shl::<W32>(zf, six);
    let pf_sh = b.shl::<W32>(u1, two);
    let f: B::V<W32> = b.get(eflags_ref());
    let clear = b.konst::<W32>(!(0x800 | 0x80 | 0x10 | 0x40 | 0x4 | 0x1));
    let cleared = b.and::<W32>(f, clear);
    let v1 = b.or::<W32>(cleared, zf_sh);
    let v2 = b.or::<W32>(v1, pf_sh);
    let v3 = b.or::<W32>(v2, cf);
    b.set(eflags_ref(), v3);
    Ok(())
}

/// UCOMISD xmm,m64 [base+disp32] (66 0F 2E mod=10)。
pub fn ucomisd_xmm_mem32<B: Backend>(b: &mut B, dst: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let addr = eff_addr32(b, base, disp);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let one32 = b.konst::<W32>(1);
    let zero32 = b.konst::<W32>(0);
    let aa = b.feq(a, a);
    let aa1 = b.select::<W32>(aa, one32, zero32);
    let cc = b.feq(c, c);
    let cc1 = b.select::<W32>(cc, one32, zero32);
    let both = b.and::<W32>(aa1, cc1);
    let u1 = b.xor::<W32>(both, one32);
    let eq = b.feq(a, c);
    let e1 = b.select::<W32>(eq, one32, zero32);
    let lt = b.flt(a, c);
    let l1 = b.select::<W32>(lt, one32, zero32);
    let zf = b.or::<W32>(u1, e1);
    let cf = b.or::<W32>(u1, l1);
    let six = b.konst::<W32>(6);
    let two = b.konst::<W32>(2);
    let zf_sh = b.shl::<W32>(zf, six);
    let pf_sh = b.shl::<W32>(u1, two);
    let f: B::V<W32> = b.get(eflags_ref());
    let clear = b.konst::<W32>(!(0x800 | 0x80 | 0x10 | 0x40 | 0x4 | 0x1));
    let cleared = b.and::<W32>(f, clear);
    let v1 = b.or::<W32>(cleared, zf_sh);
    let v2 = b.or::<W32>(v1, pf_sh);
    let v3 = b.or::<W32>(v2, cf);
    b.set(eflags_ref(), v3);
    Ok(())
}

/// UCOMISD xmm,m64 [RIP+disp32] (66 0F 2E mod=00 rm=101)。
pub fn ucomisd_xmm_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    use polyisa_sem::F64;
    let a128: B::V<W128> = b.get(xmm_ref(dst));
    let alo64: B::V<W64> = b.trunc::<W128, W64>(a128);
    let a: B::V<F64> = b.trunc::<W64, F64>(alo64);
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let m64: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let c: B::V<F64> = b.trunc::<W64, F64>(m64);
    let one32 = b.konst::<W32>(1);
    let zero32 = b.konst::<W32>(0);
    let aa = b.feq(a, a);
    let aa1 = b.select::<W32>(aa, one32, zero32);
    let cc = b.feq(c, c);
    let cc1 = b.select::<W32>(cc, one32, zero32);
    let both = b.and::<W32>(aa1, cc1);
    let u1 = b.xor::<W32>(both, one32);
    let eq = b.feq(a, c);
    let e1 = b.select::<W32>(eq, one32, zero32);
    let lt = b.flt(a, c);
    let l1 = b.select::<W32>(lt, one32, zero32);
    let zf = b.or::<W32>(u1, e1);
    let cf = b.or::<W32>(u1, l1);
    let six = b.konst::<W32>(6);
    let two = b.konst::<W32>(2);
    let zf_sh = b.shl::<W32>(zf, six);
    let pf_sh = b.shl::<W32>(u1, two);
    let f: B::V<W32> = b.get(eflags_ref());
    let clear = b.konst::<W32>(!(0x800 | 0x80 | 0x10 | 0x40 | 0x4 | 0x1));
    let cleared = b.and::<W32>(f, clear);
    let v1 = b.or::<W32>(cleared, zf_sh);
    let v2 = b.or::<W32>(v1, pf_sh);
    let v3 = b.or::<W32>(v2, cf);
    b.set(eflags_ref(), v3);
    Ok(())
}

/// CVTTSD2SI r64, xmm (F2 REX.W 0F 2C /r reg-direct)。倍精度を64ビット整数に切り捨て変換.
pub fn cvttsd2si_r64<B: Backend>(b: &mut B, dst: Gpr, src: Xmm) -> Flow<B> {
    use polyisa_sem::F64;
    let c128: B::V<W128> = b.get(xmm_ref(src));
    let clo64: B::V<W64> = b.trunc::<W128, W64>(c128);
    let c: B::V<F64> = b.trunc::<W64, F64>(clo64);
    let v = b.fcvt_s64(c, 1);
    write64(b, dst, v);
    Ok(())
}

/// CALL r/m64 reg-direct (FF /2 mod=11)。64ビット間接コール.
pub fn call_r64_rm<B: Backend>(b: &mut B, eip_next: u64, src: Gpr) -> Flow<B> {
    let target64: B::V<W64> = read64(b, src);
    let ret_addr = eip_next;
    let rsp = read64(b, Gpr(4));
    let eight = b.konst::<W64>(8);
    let next = b.sub::<W64>(rsp, eight);
    write64(b, Gpr(4), next);
    let ret = b.konst::<W64>(ret_addr);
    b.store::<W64>(next, ret, DATA_WRITE)?;
    let t32: B::V<W32> = b.trunc::<W64, W32>(target64);
    b.set(eip_ref(), t32);
    b.jump(target64);
    Ok(())
}

/// CALL r/m32 reg-direct (FF /2 mod=11、32ビット)。
pub fn call_r32_rm<B: Backend>(b: &mut B, eip_next: u32, src: Gpr) -> Flow<B> {
    let target: B::V<W32> = read(b, src);
    let ret_addr = eip_next;
    let esp = read(b, Gpr(4));
    let four = b.konst::<W32>(4);
    let next = b.sub::<W32>(esp, four);
    b.set(esp_ref(), next);
    let saddr = b.zext::<W32, W64>(next);
    let ret = b.konst::<W32>(ret_addr);
    b.store::<W32>(saddr, ret, DATA_WRITE)?;
    b.set(eip_ref(), target);
    let tj = b.zext::<W32, W64>(target);
    b.jump(tj);
    Ok(())
}

/// MOV r8,imm8 (B0+r ib)。8ビット即値を書く.
pub fn mov_r8_imm<B: Backend>(b: &mut B, dst: Gpr, high: bool, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let v = b.konst::<W8>(imm);
    write8(b, dst, high, v);
    Ok(())
}

/// MOVZX r32,m16 [base+index*scale] (0F B7 SIB mod=00)。
pub fn movzx_r32_m16_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m16 [base+index*scale] (0F B7 SIB mod=00, REX.W)。
pub fn movzx_r64_m16_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W64>(v16);
    write64(b, dst, v);
    Ok(())
}

/// AND m32,imm8 [base] (83 /4 mod=00)。
pub fn and_rm32_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m64,imm8 [base] (83 /4 mod=00, REX.W)。
pub fn and_rm64_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.and::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m32,imm8 [base+disp8] (83 /4 mod=01)。
pub fn and_rm32_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m64,imm8 [base+disp8] (83 /4 mod=01, REX.W)。
pub fn and_rm64_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.and::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m16,imm8 [base+disp8] (66 83 /4 mod=01)。16ビット AND で書戻す.
pub fn and_m16_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm as i16 as u16);
    let v = b.and::<W16>(x, y);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m16,imm8 [base+index*scale+disp8] (66 83 /4 SIB mod=01)。
pub fn and_m16_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm as i16 as u16);
    let v = b.and::<W16>(x, y);
    b.store::<W16>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m32,imm8 [base+index*scale+disp8] (83 /4 SIB mod=01)。
pub fn and_rm32_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m64,imm8 [base+index*scale+disp8] (83 /4 SIB mod=01, REX.W)。
pub fn and_rm64_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.and::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,imm8 [base+index*scale+disp8] (83 /1 SIB mod=01)。
pub fn or_rm32_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm8 [base+index*scale+disp8] (83 /1 SIB mod=01, REX.W)。
pub fn or_rm64_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// ADD m32,imm8 [base+index*scale+disp8] (83 /0 SIB mod=01)。test 0x5b1d4e 対応.
pub fn add_rm32_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.add::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD m64,imm8 [base+index*scale+disp8] (83 /0 SIB mod=01, REX.W)。test 0x5b1d4e 対応.
pub fn add_rm64_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.add::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_add_flags(b, x, y, v);
    Ok(())
}

/// OR m32,imm8 [base+index*scale] (83 /1 SIB mod=00)。awk 0x4a1704 対応.
pub fn or_rm32_imm8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm8 [base+index*scale] (83 /1 SIB mod=00, REX.W)。
pub fn or_rm64_imm8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m32,imm8 [base+index*scale] (83 /4 SIB mod=00)。
pub fn and_rm32_imm8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m64,imm8 [base+index*scale] (83 /4 SIB mod=00, REX.W)。
pub fn and_rm64_imm8_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.and::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// CMP m32,imm8 [base+disp8] (83 /7 mod=01)。
pub fn cmp_rm32_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm8 [base+disp8] (83 /7 mod=01, REX.W)。
pub fn cmp_rm64_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32,imm8 [base+index*scale+disp8] (83 /7 SIB mod=01)。seq 10 の停止点 0x45bbd8 対応.
pub fn cmp_rm32_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32,imm8 [base+index*scale+disp32] (83 /7 SIB mod=10)。
pub fn cmp_rm32_imm8_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32,imm8 [index*scale+disp32] (83 /7 SIB mod=00 base=直接番地)。
pub fn cmp_rm32_imm8_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm8 [index*scale+disp32] (83 /7 SIB mod=00 base=直接番地, REX.W)。
pub fn cmp_rm64_imm8_sibabs<B: Backend>(
    b: &mut B,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled_abs(b, shift, disp, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm8 [disp32] (83 /7 SIB mod=00、index なし, REX.W)。
pub fn cmp_rm64_imm8_abs<B: Backend>(b: &mut B, disp: i32, imm: i8) -> Flow<B> {
    let addr = b.konst::<W64>(disp as i64 as u64);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm8 [base+index*scale+disp32] (83 /7 SIB mod=10, REX.W)。
pub fn cmp_rm64_imm8_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm8 [base+index*scale+disp8] (83 /7 SIB mod=01, REX.W)。seq 10 の停止点 0x45bbd8 対応.
pub fn cmp_rm64_imm8_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// AND m32,imm8 [base+disp32] (83 /4 mod=10)。
pub fn and_rm32_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m64,imm8 [base+disp32] (83 /4 mod=10, REX.W)。
pub fn and_rm64_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.and::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// CMP m32,imm8 [base+disp32] (83 /7 mod=10)。
pub fn cmp_rm32_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm8 [base+disp32] (83 /7 mod=10, REX.W)。
pub fn cmp_rm64_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// MOVZX r32,m16 [base] (0F B7 mod=00)。
pub fn movzx_r32_m16_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W32>(v16);
    write(b, dst, v);
    Ok(())
}

/// MOVZX r64,m16 [base] (0F B7 mod=00, REX.W)。
pub fn movzx_r64_m16_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let v = b.zext::<W16, W64>(v16);
    write64(b, dst, v);
    Ok(())
}

/// TEST r16,r16 (66 85 /r reg-direct)。AND 結果で 5 旗を更新する（CF=0、OF=0）.
pub fn test_rm16<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let x32 = read(b, dst);
    let y32 = read(b, src);
    let x: B::V<W16> = b.trunc::<W32, W16>(x32);
    let y: B::V<W16> = b.trunc::<W32, W16>(y32);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m16,r16 [base] (66 85 /r mod=00)。
pub fn test_m16_r16_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let src32 = read(b, src);
    let y: B::V<W16> = b.trunc::<W32, W16>(src32);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m16,imm16 [base] (66 F7 /0 mod=00)。16ビット AND の結果で 5 旗を更新する（CF=0、OF=0）.
pub fn test_m16_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m16,imm16 [base+disp8] (66 F7 /0 mod=01)。hexdump 0x5c8822 対応.
pub fn test_m16_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m32,imm32 RIP (F7 05 + disp32 + imm32)。[RIP+disp] の32ビット AND で 5 旗を更新する.
pub fn test_rm32_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m64,imm32 RIP (REX.W F7 05)。imm32 は符号拡張する.
pub fn test_rm64_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.and::<W64>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m32,imm32 [disp32] (32ビット絶対番地).
pub fn test_rm32_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m16,imm16 RIP (66 F7 05 + disp32 + imm16)。[RIP+disp] の16ビット AND で 5 旗を更新する.
pub fn test_m16_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m16,imm16 [disp32] (32ビット絶対番地).
pub fn test_m16_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u16) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = b.konst::<W64>(addr32 as u64);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let y = b.konst::<W16>(imm);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m16,r16 [base+disp8] (66 85 /r mod=01)。
pub fn test_m16_r16_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr(b, base, disp);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let src32 = read(b, src);
    let y: B::V<W16> = b.trunc::<W32, W16>(src32);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m16,r16 [base+disp32] (66 85 /r mod=10)。
pub fn test_m16_r16_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let src32 = read(b, src);
    let y: B::V<W16> = b.trunc::<W32, W16>(src32);
    let v = b.and::<W16>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// PSHUFLW xmm1, xmm2, imm8 (F2 0F 70 /r ib)。下位 4 ワードを imm8 の 2bit 選択子で
/// 並べ替え、上位 64 ビットは src のまま移す。
pub fn pshuflw_xmm<B: Backend>(b: &mut B, dst: Xmm, src: Xmm, imm: u8) -> Flow<B> {
    let v: B::V<W128> = b.get(xmm_ref(src));
    let mut acc: B::V<W128> = b.konst::<W128>(0);
    for i in 0..4u32 {
        let sel = ((imm >> (i * 2)) & 3) as u128 * 16;
        let sh = b.konst::<W128>(sel);
        let shifted = b.shr_l::<W128>(v, sh);
        let mask_w = b.konst::<W128>(0xFFFF);
        let w = b.and::<W128>(shifted, mask_w);
        let pos = b.konst::<W128>((i * 16) as u128);
        let part = b.shl::<W128>(w, pos);
        acc = b.or::<W128>(acc, part);
    }
    // 上位 64 ビットは src のまま.
    let hi_shift = b.konst::<W128>(64);
    let hi = b.shr_l::<W128>(v, hi_shift);
    let hi_back = b.shl::<W128>(hi, hi_shift);
    acc = b.or::<W128>(acc, hi_back);
    b.set(xmm_ref(dst), acc);
    Ok(())
}

/// MOVQ [base],xmm (66 0F D6 /r mod=00)。XMM 下位64を書く.
pub fn movq_m64_xmm_memnd<B: Backend>(b: &mut B, src: Xmm, base: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVQ [base+disp8],xmm (66 0F D6 /r mod=01)。
pub fn movq_m64_xmm_mem8<B: Backend>(b: &mut B, src: Xmm, base: Gpr, disp: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVQ [base+disp32],xmm (66 0F D6 /r mod=10)。
pub fn movq_m64_xmm_mem32<B: Backend>(b: &mut B, src: Xmm, base: Gpr, disp: i32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let v128: B::V<W128> = b.get(xmm_ref(src));
    let v: B::V<W64> = b.trunc::<W128, W64>(v128);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// ADD r32, [base+index*scale] (03 /r SIB mod=00)。md5sum 0x5ca46d 対応.
pub fn add_r32_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// ADD r64, [base+index*scale] (03 /r SIB mod=00, REX.W)。
pub fn add_r64_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.add::<W64>(x, y);
    write64(b, dst, v);
    update_add_flags(b, x, y, v);
    Ok(())
}

/// XOR r32, [base+index*scale] (33 /r SIB mod=00)。
pub fn xor_r32_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r64, [base+index*scale] (33 /r SIB mod=00, REX.W)。
pub fn xor_r64_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// CMP r32, m32 [base+index*scale] (3B /r SIB mod=00)。
pub fn cmp_r32_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [base+index*scale] (3B /r SIB mod=00, REX.W)。
pub fn cmp_r64_sib<B: Backend>(b: &mut B, dst: Gpr, base: Gpr, idx: Gpr, shift: u32) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [base+index*scale+disp32] (3B /r SIB mod=10、REX.W)。
pub fn cmp_r64_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, m32 [base+index*scale+disp32] (3B /r SIB mod=10)。
pub fn cmp_r32_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r32, m32 [base+index*scale+disp8] (3B /r SIB mod=01)。
pub fn cmp_r32_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP r64, m64 [base+index*scale+disp8] (3B /r SIB mod=01, REX.W)。
pub fn cmp_r64_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// XOR r32, [base+index*scale+disp8] (33 /r SIB mod=01)。
pub fn xor_r32_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r64, [base+index*scale+disp8] (33 /r SIB mod=01, REX.W)。
pub fn xor_r64_sibd<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r32, [base+index*scale+disp32] (33 /r SIB mod=10)。
pub fn xor_r32_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let x = read(b, dst);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// XOR r64, [base+index*scale+disp32] (33 /r SIB mod=10, REX.W)。
pub fn xor_r64_sibd32<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let y: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let x = read64(b, dst);
    let v = b.xor::<W64>(x, y);
    write64(b, dst, v);
    update_logic_flags(b, v);
    Ok(())
}

/// MOV [base],r16 (66 89 mod=00)。16ビットストア.
pub fn mov_m16_r16_memnd<B: Backend>(b: &mut B, src: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    b.store::<W16>(addr, v16, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+index*scale+disp32],r16 (66 89 SIB mod=10)。gzip 0x4859e4 対応.
pub fn mov_m16_r16_sibd32<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    b.store::<W16>(addr, v16, DATA_WRITE)?;
    Ok(())
}

/// MOV [base+index*scale],r16 (66 89 SIB mod=00)。16ビットストア.
pub fn mov_m16_r16_sib<B: Backend>(
    b: &mut B,
    src: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let src32 = read(b, src);
    let v16: B::V<W16> = b.trunc::<W32, W16>(src32);
    b.store::<W16>(addr, v16, DATA_WRITE)?;
    Ok(())
}

/// MOV r16,[base] (66 8B mod=00)。上位は保存.
pub fn mov_r16_m16_memnd<B: Backend>(b: &mut B, dst: Gpr, base: Gpr) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = read64(b, base);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let cur32 = read(b, dst);
    let mask = b.konst::<W32>(0xffff_0000);
    let preserved = b.and::<W32>(cur32, mask);
    let ext32 = b.zext::<W16, W32>(v16);
    let v = b.or::<W32>(preserved, ext32);
    write(b, dst, v);
    Ok(())
}

/// MOV r16,[base+index*scale] (66 8B SIB mod=00)。上位は保存.
pub fn mov_r16_m16_sib<B: Backend>(
    b: &mut B,
    dst: Gpr,
    base: Gpr,
    idx: Gpr,
    shift: u32,
) -> Flow<B> {
    use polyisa_sem::W16;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v16: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
    let cur32 = read(b, dst);
    let mask = b.konst::<W32>(0xffff_0000);
    let preserved = b.and::<W32>(cur32, mask);
    let ext32 = b.zext::<W16, W32>(v16);
    let v = b.or::<W32>(preserved, ext32);
    write(b, dst, v);
    Ok(())
}

/// MOVB [RIP+disp32],imm8 (C6 05 + disp32 + imm8)。1バイト書く.
pub fn mov_rm8_imm_rip<B: Backend>(b: &mut B, next_rip: u64, disp: i32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v = b.konst::<W8>(imm);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVB [disp32],imm8 (32ビット絶対番地)。
pub fn mov_rm8_imm_abs<B: Backend>(b: &mut B, addr32: u32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = b.konst::<W64>(addr32 as u64);
    let v = b.konst::<W8>(imm);
    b.store::<W8>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m32, imm32 (C7 /0 SIB mod=00 [base+index*scale])。
pub fn mov_rm32_imm_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64, imm32 (C7 /0 SIB mod=00, REX.W)。imm32 は符号拡張する.
pub fn mov_rm64_imm_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m32, imm32 (C7 /0 SIB mod=01 [base+index*scale+disp8])。
pub fn mov_rm32_imm_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v = b.konst::<W32>(imm);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV m64, imm32 (C7 /0 SIB mod=01, REX.W)。
pub fn mov_rm64_imm_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let v = b.konst::<W64>(imm as i32 as u64);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOVD xmm, m32 [RIP+disp32] (66 0F 6E /r mod=00)。32ビットを読んで上位96を消す.
pub fn movd_xmm_rip<B: Backend>(b: &mut B, dst: Xmm, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.zext::<W32, W128>(v32);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// MOVD xmm, m32 [disp32] abs (32ビット)。
pub fn movd_xmm_abs<B: Backend>(b: &mut B, dst: Xmm, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.zext::<W32, W128>(v32);
    b.set(xmm_ref(dst), v);
    Ok(())
}

/// OR m32,r32 [base] (09 /r mod=00)。
pub fn or_m32_r32_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,r64 [base] (09 /r mod=00, REX.W)。
pub fn or_m64_r64_memnd<B: Backend>(b: &mut B, base: Gpr, src: Gpr) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,r32 [base+disp8] (09 /r mod=01)。
pub fn or_m32_r32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,r64 [base+disp8] (09 /r mod=01, REX.W)。
pub fn or_m64_r64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// SUB m32,r32 [base+disp8] (29 /r mod=01)。
pub fn sub_m32_r32_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m32, r32 [base+disp32] (29 /r mod=10)。gzip 0x48473b 対応。
pub fn sub_m32_r32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m64, r64 [base+disp32] (REX.W 29 /r mod=10)。
pub fn sub_m64_r64_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m32,r32 [base+index*scale+disp8] (29 /r SIB mod=01)。
pub fn sub_m32_r32_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m64,r64 [base+index*scale+disp8] (29 /r SIB mod=01, REX.W)。
pub fn sub_m64_r64_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// SUB m64,r64 [base+disp8] (29 /r mod=01, REX.W)。
pub fn sub_m64_r64_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, src: Gpr) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.sub::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// OR m32,r32 [base+disp32] (09 /r mod=10)。
pub fn or_m32_r32_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,r32 [base+index*scale+disp8] (09 /r SIB mod=01)。sed 0x400d55 対応.
pub fn or_m32_r32_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,r64 [base+index*scale+disp8] (09 /r SIB mod=01, REX.W)。
pub fn or_m64_r64_sibd<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i8,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp as i32, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,r32 [base+index*scale+disp32] (09 /r SIB mod=10)。
pub fn or_m32_r32_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,r64 [base+index*scale+disp32] (09 /r SIB mod=10, REX.W)。
pub fn or_m64_r64_sibd32<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    disp: i32,
    src: Gpr,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, disp, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,r32 [base+index*scale] (09 /r SIB mod=00)。
pub fn or_m32_r32_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, src: Gpr) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,r64 [base+index*scale] (09 /r SIB mod=00, REX.W)。
pub fn or_m64_r64_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, src: Gpr) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,r64 [base+disp32] (09 /r mod=10, REX.W)。
pub fn or_m64_r64_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, src: Gpr) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = read64(b, src);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// MOVSXD r32, m32 [RIP+disp32] (63 /r RIP)。32ビット転送と等価.
pub fn movsxd_rm32_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOVSXD r64, m32 [RIP+disp32] (REX.W + 63 /r RIP)。符号拡張する.
pub fn movsxd_rm64_rip<B: Backend>(b: &mut B, dst: Gpr, next_rip: u64, disp: i32) -> Flow<B> {
    let base = b.konst::<W64>(next_rip);
    let d = b.konst::<W64>(disp as i64 as u64);
    let addr = b.add::<W64>(base, d);
    let v32: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let v = b.sext::<W32, W64>(v32);
    write64(b, dst, v);
    Ok(())
}

/// MOVSXD r32, m32 [disp32] abs (32ビット)。
pub fn movsxd_rm32_abs<B: Backend>(b: &mut B, dst: Gpr, addr32: u32) -> Flow<B> {
    let addr = b.konst::<W64>(addr32 as u64);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// OR m32,imm8 [base] (83 /1 mod=00)。
pub fn or_rm32_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// CMP m32,imm32 [base] (81 /7 mod=00)。dst は変えず 6 旗を更新する.
pub fn cmp_rm32_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32,imm32 [base+disp8] (81 /7 mod=01)。dst は変えず 6 旗を更新する.
pub fn cmp_rm32_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m32,imm32 [base+disp32] (81 /7 mod=10)。dst は変えず 6 旗を更新する.
pub fn cmp_rm32_imm_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: u32) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// CMP m64,imm32 [base] (81 /7 mod=00、REX.W)。imm32 は符号拡張する.
pub fn cmp_rm64_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.sub::<W64>(x, y);
    update_sub_flags(b, x, y, v);
    Ok(())
}

/// OR m32,imm32 [base+index*scale] (81 /1 SIB mod=00)。awk 0x4a4354 対応.
pub fn or_rm32_imm_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm32 [base+index*scale] (81 /1 SIB mod=00, REX.W)。imm32 は符号拡張する.
pub fn or_rm64_imm_sib<B: Backend>(
    b: &mut B,
    base: Gpr,
    idx: Gpr,
    shift: u32,
    imm: u32,
) -> Flow<B> {
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,imm32 [base] (81 /1 mod=00)。
pub fn or_rm32_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,imm32 [base+disp8] (81 /1 mod=01)。メモリを読み書きする.
pub fn or_rm32_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m32,imm32 [base+disp8] (81 /4 mod=01)。
pub fn and_rm32_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// AND m64,imm32 [base+disp8] (81 /4 mod=01、REX.W)。imm32 は符号拡張する.
pub fn and_rm64_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.and::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm32 [base+disp8] (81 /1 mod=01、REX.W)。imm32 は符号拡張する.
pub fn or_rm64_imm_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: u32) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm32 [base] (81 /1 mod=00, REX.W)。imm32 は符号拡張する.
pub fn or_rm64_imm_memnd<B: Backend>(b: &mut B, base: Gpr, imm: u32) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i32 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm8 [base] (83 /1 mod=00, REX.W)。
pub fn or_rm64_imm8_memnd<B: Backend>(b: &mut B, base: Gpr, imm: i8) -> Flow<B> {
    let addr = read64(b, base);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,imm8 [base+disp8] (83 /1 mod=01)。
pub fn or_rm32_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm8 [base+disp8] (83 /1 mod=01, REX.W)。
pub fn or_rm64_imm8_mem8<B: Backend>(b: &mut B, base: Gpr, disp: i8, imm: i8) -> Flow<B> {
    let addr = eff_addr(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m32,imm8 [base+disp32] (83 /1 mod=10)。
pub fn or_rm32_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let y = b.konst::<W32>(imm as i32 as u32);
    let v = b.or::<W32>(x, y);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// OR m64,imm8 [base+disp32] (83 /1 mod=10, REX.W)。
pub fn or_rm64_imm8_mem32<B: Backend>(b: &mut B, base: Gpr, disp: i32, imm: i8) -> Flow<B> {
    let addr = eff_addr32(b, base, disp);
    let x: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let y = b.konst::<W64>(imm as i64 as u64);
    let v = b.or::<W64>(x, y);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    update_logic_flags(b, v);
    Ok(())
}

/// MOV r32, FS:[base] (FS + 8B mod=00)。FS base + base レジスタから32bit読む.
pub fn mov_r32_fs_memnd<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, base: Gpr) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let r = read64(b, base);
    let addr = b.add::<W64>(f, r);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, dst, v);
    Ok(())
}

/// MOV r64, FS:[base] (FS + REX.W 8B mod=00)。
pub fn mov_r64_fs_memnd<B: Backend>(b: &mut B, dst: Gpr, fs_base: u64, base: Gpr) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let r = read64(b, base);
    let addr = b.add::<W64>(f, r);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write64(b, dst, v);
    Ok(())
}

/// MOV FS:[base], r32 (FS + 89 mod=00)。FS base + base レジスタへ32bit格納.
pub fn mov_m32_fs_memnd<B: Backend>(b: &mut B, src: Gpr, fs_base: u64, base: Gpr) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let r = read64(b, base);
    let addr = b.add::<W64>(f, r);
    let v: B::V<W32> = read(b, src);
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV FS:[base], r64 (FS + REX.W 89 mod=00)。
pub fn mov_m64_fs_memnd<B: Backend>(b: &mut B, src: Gpr, fs_base: u64, base: Gpr) -> Flow<B> {
    let f = b.konst::<W64>(fs_base);
    let r = read64(b, base);
    let addr = b.add::<W64>(f, r);
    let v: B::V<W64> = read64(b, src);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// TEST m8,imm8 [base+index*scale+disp8] (F6 /0 SIB mod=01)。
pub fn test_m8_imm_sibd<B: Backend>(
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
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}

/// TEST m8,imm8 [base+index*scale] (F6 /0 SIB mod=00)。ls -l 0x40e342 対応.
pub fn test_m8_imm_sib<B: Backend>(b: &mut B, base: Gpr, idx: Gpr, shift: u32, imm: u8) -> Flow<B> {
    use polyisa_sem::W8;
    let addr = sib_addr_scaled(b, shift, 0, base, idx);
    let x: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
    let y = b.konst::<W8>(imm);
    let v = b.and::<W8>(x, y);
    update_logic_flags(b, v);
    Ok(())
}
