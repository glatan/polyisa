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
use polyisa_sem::{Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W32, W64};

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

/// eflags を指す。
pub fn eflags_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, eflags))
}

/// ZF（bit6）と CF（bit0）を更新する。遅延評価は本格実装で足す。
fn update_zf_cf<B: Backend>(b: &mut B, x: B::V<W32>, y: B::V<W32>) {
    let flags: B::V<W32> = b.get(eflags_ref());
    let zf_mask = b.konst::<W32>(0xffff_ffbf);
    let cleared_zf = b.and::<W32>(flags, zf_mask);
    let eq = b.cmp::<W32>(Cmp::Eq, x, y);
    let zf_on = b.konst::<W32>(0x40);
    let zf_off = b.konst::<W32>(0);
    let zf_bit = b.select::<W32>(eq, zf_on, zf_off);
    let e1 = b.or::<W32>(cleared_zf, zf_bit);
    b.set(eflags_ref(), e1);
    let flags2: B::V<W32> = b.get(eflags_ref());
    let cf_mask = b.konst::<W32>(0xffff_fffe);
    let cleared_cf = b.and::<W32>(flags2, cf_mask);
    let lt = b.cmp::<W32>(Cmp::LtU, x, y);
    let cf_on = b.konst::<W32>(1);
    let cf_off = b.konst::<W32>(0);
    let cf_bit = b.select::<W32>(lt, cf_on, cf_off);
    let e2 = b.or::<W32>(cleared_cf, cf_bit);
    b.set(eflags_ref(), e2);
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
    let mask = b.konst::<W32>(0x40);
    let masked = b.and::<W32>(flags, mask);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

/// CMP EAX, imm32。EAX は変えず ZF/CF だけ更新する。
pub fn cmp_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    update_zf_cf(b, x, y);
    Ok(())
}

/// TEST EAX, EAX。AND 結果で ZF/CF を更新する（CF=0）。
/// EAX 自身は変えない。
pub fn test_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let x = read(b, Gpr(0));
    let v = b.and::<W32>(x, x);
    let zero = b.konst::<W32>(0);
    update_zf_cf(b, v, zero);
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
    let mask = b.konst::<W32>(0x40);
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

/// INC r32。32ビットで包む（EFLAGS 更新は本格実装で足す）。
pub fn inc_r32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x = read(b, rd);
    let one = b.konst::<W32>(1);
    let v = b.add::<W32>(x, one);
    write(b, rd, v);
    Ok(())
}

/// INC EAX。32ビットで包む（EFLAGS 更新は本格実装で足す）。
pub fn inc_eax<B: Backend>(b: &mut B) -> Flow<B> {
    inc_r32(b, Gpr::eax())
}

/// DEC r32。32ビットで包む（EFLAGS 更新は本格実装で足す）。
pub fn dec_r32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x = read(b, rd);
    let one = b.konst::<W32>(1);
    let v = b.sub::<W32>(x, one);
    write(b, rd, v);
    Ok(())
}

/// DEC EAX。32ビットで包む。
pub fn dec_eax<B: Backend>(b: &mut B) -> Flow<B> {
    dec_r32(b, Gpr::eax())
}

/// ADD EAX, imm32。32ビットで包む。
pub fn add_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr::eax());
    let y = b.konst::<W32>(imm);
    let v = b.add::<W32>(x, y);
    write(b, Gpr::eax(), v);
    Ok(())
}

/// ADD r/m32, r32 (ModRM register-direct 01 /r、mod=11)。
/// 方向は dst=rm、src=reg。SIB/disp/メモリ形式と Rust フックは本格実装で足す。
pub fn add_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.add::<W32>(x, y);
    write(b, dst, v);
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

/// ベース + disp8 の実効アドレスを求める（disp8 は符号付き）。
fn eff_addr<B: Backend>(b: &mut B, base: Gpr, disp: i8) -> B::V<W32> {
    let r = read(b, base);
    let d = b.konst::<W32>(disp as i32 as u32);
    b.add::<W32>(r, d)
}

/// MOV EAX, [EBX+disp8] (ModRM mod=01 の最小形)。
/// SIB・disp32・絶対番地は本格実装で足す。
pub fn mov_eax_mem<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = eff_addr(b, Gpr(3), disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV EAX, [EBX+ESI] (SIB mod=00 base+index の最小形)。
/// スケール・disp・絶対番地・SIB 拡張は本格実装で足す。
pub fn mov_eax_sib<B: Backend>(b: &mut B) -> Flow<B> {
    let base = read(b, Gpr(3));
    let idx = read(b, Gpr(6));
    let addr32 = b.add::<W32>(base, idx);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV EAX, [EBX+ESI+disp8] (SIB mod=01 base+index+disp8)。
/// スケール・disp32・絶対番地・SIB 拡張は本格実装で足す。
pub fn mov_eax_sibd<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let base = read(b, Gpr(3));
    let idx = read(b, Gpr(6));
    let sum = b.add::<W32>(base, idx);
    let d = b.konst::<W32>(disp as i32 as u32);
    let addr32 = b.add::<W32>(sum, d);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI+disp8], EAX (SIB mod=01 base+index+disp8)。
pub fn mov_sibd_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let base = read(b, Gpr(3));
    let idx = read(b, Gpr(6));
    let sum = b.add::<W32>(base, idx);
    let d = b.konst::<W32>(disp as i32 as u32);
    let addr32 = b.add::<W32>(sum, d);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SIB base+index にスケールと disp を足した実効アドレス。
fn sib_addr_scaled<B: Backend>(b: &mut B, shift: u32, disp: i32) -> B::V<W32> {
    let base = read(b, Gpr(3));
    let idx = read(b, Gpr(6));
    let n = b.konst::<W32>(shift);
    let scaled = b.shl::<W32>(idx, n);
    let sum = b.add::<W32>(base, scaled);
    let d = b.konst::<W32>(disp as u32);
    b.add::<W32>(sum, d)
}

/// SIB 直接番地 base にスケール付き index と disp32 を足した実効アドレス。
/// mod=00 base=101（base なし）の形。
fn sib_addr_scaled_abs<B: Backend>(b: &mut B, shift: u32, disp: i32) -> B::V<W32> {
    let idx = read(b, Gpr(6));
    let n = b.konst::<W32>(shift);
    let scaled = b.shl::<W32>(idx, n);
    let d = b.konst::<W32>(disp as u32);
    b.add::<W32>(scaled, d)
}

/// MOV EAX, [EBX+ESI*2+disp8]。
pub fn mov_eax_sib_s2<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 1, disp as i32);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*2+disp8], EAX。
pub fn mov_sib_s2_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 1, disp as i32);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*4+disp8]。
pub fn mov_eax_sib_s4<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 2, disp as i32);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*4+disp8], EAX。
pub fn mov_sib_s4_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 2, disp as i32);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*8+disp8]。
pub fn mov_eax_sib_s8<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 3, disp as i32);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*8+disp8], EAX。
pub fn mov_sib_s8_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 3, disp as i32);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*2] (SIB mod=00 base+index*2)。
pub fn mov_eax_sib_s2nd<B: Backend>(b: &mut B) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 1, 0);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*2], EAX (SIB mod=00 base+index*2)。
pub fn mov_sib_s2nd_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 1, 0);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*4] (SIB mod=00 base+index*4)。
pub fn mov_eax_sib_s4nd<B: Backend>(b: &mut B) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 2, 0);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*4], EAX (SIB mod=00 base+index*4)。
pub fn mov_sib_s4nd_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 2, 0);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*8] (SIB mod=00 base+index*8)。
pub fn mov_eax_sib_s8nd<B: Backend>(b: &mut B) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 3, 0);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*8], EAX (SIB mod=00 base+index*8)。
pub fn mov_sib_s8nd_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 3, 0);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*2+disp32] (SIB mod=10 base+index*2)。
pub fn mov_eax_sib_s2d32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 1, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*2+disp32], EAX。
pub fn mov_sib_s2d32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 1, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*4+disp32] (SIB mod=10 base+index*4)。
pub fn mov_eax_sib_s4d32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 2, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*4+disp32], EAX。
pub fn mov_sib_s4d32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 2, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [EBX+ESI*8+disp32] (SIB mod=10 base+index*8)。
pub fn mov_eax_sib_s8d32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 3, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+ESI*8+disp32], EAX。
pub fn mov_sib_s8d32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled(b, 3, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [ESI*2+disp32] (SIB mod=00 base=直接番地)。
pub fn mov_eax_sib_s2a32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled_abs(b, 1, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [ESI*2+disp32], EAX。
pub fn mov_sib_s2a32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled_abs(b, 1, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [ESI*4+disp32] (SIB mod=00 base=直接番地)。
pub fn mov_eax_sib_s4a32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled_abs(b, 2, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [ESI*4+disp32], EAX。
pub fn mov_sib_s4a32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled_abs(b, 2, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [ESI*8+disp32] (SIB mod=00 base=直接番地)。
pub fn mov_eax_sib_s8a32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled_abs(b, 3, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [ESI*8+disp32], EAX。
pub fn mov_sib_s8a32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = sib_addr_scaled_abs(b, 3, disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV [EBX+ESI], EAX (SIB mod=00 base+index の最小形)。
/// スケール・disp・絶対番地・SIB 拡張は本格実装で足す。
pub fn mov_sib_eax<B: Backend>(b: &mut B) -> Flow<B> {
    let base = read(b, Gpr(3));
    let idx = read(b, Gpr(6));
    let addr32 = b.add::<W32>(base, idx);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV [EBX+disp8], EAX (ModRM mod=01 の最小形)。
pub fn mov_mem_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = eff_addr(b, Gpr(3), disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// ベース + disp32 の実効アドレスを求める（disp32 は符号付き）。
fn eff_addr32<B: Backend>(b: &mut B, base: Gpr, disp: i32) -> B::V<W32> {
    let r = read(b, base);
    let d = b.konst::<W32>(disp as u32);
    b.add::<W32>(r, d)
}

/// MOV EAX, [EBX+disp32] (ModRM mod=10 の最小形)。
pub fn mov_eax_memd32<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = eff_addr32(b, Gpr(3), disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [EBX+disp32], EAX (ModRM mod=10 の最小形)。
pub fn mov_memd32_eax<B: Backend>(b: &mut B, disp: i32) -> Flow<B> {
    let addr32 = eff_addr32(b, Gpr(3), disp);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// MOV EAX, [disp32] (絶対番地、mod=00 rm=101)。
pub fn mov_eax_abs<B: Backend>(b: &mut B, addr: u32) -> Flow<B> {
    let addr32 = b.konst::<W32>(addr);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    write(b, Gpr(0), v);
    Ok(())
}

/// MOV [disp32], EAX (絶対番地、mod=00 rm=101)。
pub fn mov_abs_eax<B: Backend>(b: &mut B, addr: u32) -> Flow<B> {
    let addr32 = b.konst::<W32>(addr);
    let addr = b.zext::<W32, W64>(addr32);
    let v: B::V<W32> = read(b, Gpr(0));
    b.store::<W32>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// SUB EAX, imm32。結果を書き、ZF/CF を更新する。
pub fn sub_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.sub::<W32>(x, y);
    write(b, Gpr(0), v);
    update_zf_cf(b, x, y);
    Ok(())
}

/// LEAVE (C9)。ESP=EBP として POP EBP と等価。
pub fn leave<B: Backend>(b: &mut B) -> Flow<B> {
    let ebp = read(b, Gpr(5));
    b.set(esp_ref(), ebp);
    pop_reg(b, Gpr(5))
}

/// AND EAX, imm32。結果を書き、ZF/CF を更新する。
pub fn and_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.and::<W32>(x, y);
    write(b, Gpr(0), v);
    let zero = b.konst::<W32>(0);
    update_zf_cf(b, v, zero);
    Ok(())
}

/// OR EAX, imm32。結果を書き、ZF/CF を更新する。
pub fn or_eax<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.or::<W32>(x, y);
    write(b, Gpr(0), v);
    let zero = b.konst::<W32>(0);
    update_zf_cf(b, v, zero);
    Ok(())
}

/// XOR EAX, imm32。結果を書き、ZF/CF を更新する。
pub fn xor_imm<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    let x = read(b, Gpr(0));
    let y = b.konst::<W32>(imm);
    let v = b.xor::<W32>(x, y);
    write(b, Gpr(0), v);
    let zero = b.konst::<W32>(0);
    update_zf_cf(b, v, zero);
    Ok(())
}

/// SHL EAX, imm8。カウントは下位5ビットだけ使う。EFLAGS 更新は本格実装で足す。
pub fn shl_eax<B: Backend>(b: &mut B, n: u8) -> Flow<B> {
    let x = read(b, Gpr(0));
    let count = b.konst::<W32>((n & 31) as u32);
    let v = b.shl::<W32>(x, count);
    write(b, Gpr(0), v);
    Ok(())
}

/// SHR EAX, imm8。論理右シフト。カウントは下位5ビットだけ使う。EFLAGS 更新は本格実装で足す。
pub fn shr_eax<B: Backend>(b: &mut B, n: u8) -> Flow<B> {
    let x = read(b, Gpr(0));
    let count = b.konst::<W32>((n & 31) as u32);
    let v = b.shr_l::<W32>(x, count);
    write(b, Gpr(0), v);
    Ok(())
}

/// LEA EAX, [EBX+disp8]。メモリに触れず実効アドレスを入れる。
pub fn lea_eax<B: Backend>(b: &mut B, disp: i8) -> Flow<B> {
    let addr32 = eff_addr(b, Gpr(3), disp);
    write(b, Gpr(0), addr32);
    Ok(())
}

/// CMP r/m32, r32。dst は変えず ZF/CF だけ更新する。
/// 方向は x=rm、y=reg。
pub fn cmp_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    update_zf_cf(b, x, y);
    Ok(())
}

/// AND r/m32, r32。結果を dst に書き、ZF/CF を更新する（CF=0）。
pub fn and_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.and::<W32>(x, y);
    write(b, dst, v);
    let zero = b.konst::<W32>(0);
    update_zf_cf(b, v, zero);
    Ok(())
}

/// OR r/m32, r32。結果を dst に書き、ZF/CF を更新する（CF=0）。
pub fn or_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.or::<W32>(x, y);
    write(b, dst, v);
    let zero = b.konst::<W32>(0);
    update_zf_cf(b, v, zero);
    Ok(())
}

/// SUB r/m32, r32。結果を dst に書き、ZF/CF を更新する。
pub fn sub_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.sub::<W32>(x, y);
    write(b, dst, v);
    update_zf_cf(b, x, y);
    Ok(())
}

/// XOR r/m32, r32。結果を dst に書き、ZF/CF を更新する（CF=0）。
/// 31 C0（XOR EAX,EAX のゼロ化イディオム）はこの汎用形で扱う。
pub fn xor_rm32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let x = read(b, dst);
    let y = read(b, src);
    let v = b.xor::<W32>(x, y);
    write(b, dst, v);
    let zero = b.konst::<W32>(0);
    update_zf_cf(b, v, zero);
    Ok(())
}

/// MOV r/m32, r32 (ModRM register-direct 89 /r、mod=11)。
/// 方向は dst=rm、src=reg。89 E5（MOV EBP,ESP）はこの汎用形で扱う。
pub fn mov_mr32<B: Backend>(b: &mut B, dst: Gpr, src: Gpr) -> Flow<B> {
    let v = read(b, src);
    write(b, dst, v);
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
