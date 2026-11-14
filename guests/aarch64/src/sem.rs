// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A64 の命令意味論。バックエンドに対して総称的に書く。
//!
//! デコード済みのオペランドは Rust の値で受け、実行時の値は `B::V` で扱う。
//! 出典の版は SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09) である。
//!
//! - レジスタ番号 31 は命令形式で SP と ZR に分かれる。読み書きの helper が
//!   `use_sp` で切り替える。
//! - W（32 ビット）形式は読み出しを W32 に切り詰め、書き込みは W64 へ
//!   ゼロ拡張する。
//! - NZCV は `CpuState::nzcv` の下位 4 ビットに N<<3|Z<<2|C<<1|V で保持する。

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{
    Backend, Cmp, ExceptionKind, Flow, GuestException, StateRef, W8, W16, W32, W64, W128, Width,
};

use super::CpuState;

/// 整数レジスタ番号。31 は形式によって SP か ZR。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, x) + (self.0 as usize) * 8)
    }
}

/// SP の状態参照。
pub fn sp_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, sp))
}

/// PC の状態参照。
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// NZCV の状態参照。
pub fn nzcv_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, nzcv))
}

/// FPCR の状態参照。
pub fn fpcr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fpcr))
}

/// FPSR の状態参照。
pub fn fpsr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fpsr))
}

/// TPIDR_EL0 の状態参照。
pub fn tpidr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, tpidr))
}

const DATA_READ: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};

const DATA_WRITE: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataWrite,
};

const LR_ACC: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::LoadReserved,
};

const SC_ACC: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::StoreConditional,
};

fn data_read(endian: Endian) -> Access {
    Access {
        endian,
        ..DATA_READ
    }
}

fn data_write(endian: Endian) -> Access {
    Access {
        endian,
        ..DATA_WRITE
    }
}

fn lr_acc(endian: Endian) -> Access {
    Access { endian, ..LR_ACC }
}

fn sc_acc(endian: Endian) -> Access {
    Access { endian, ..SC_ACC }
}

// ---- レジスタの読み書き ----

/// `r` を読む。31 は `use_sp` が真なら SP、偽なら 0。
pub fn read<B: Backend>(b: &mut B, r: Gpr, use_sp: bool) -> B::V<W64> {
    if r.0 == 31 {
        if use_sp {
            b.get(sp_ref())
        } else {
            b.konst::<W64>(0)
        }
    } else {
        b.get(r.state())
    }
}

/// `r` の W 値（下位 32 ビット）。
pub fn read_w<B: Backend>(b: &mut B, r: Gpr, use_sp: bool) -> B::V<W32> {
    let v = read(b, r, use_sp);
    b.trunc::<W64, W32>(v)
}

/// `r` に書く。31 は `use_sp` が真なら SP、偽なら捨てる。
pub fn write<B: Backend>(b: &mut B, r: Gpr, v: B::V<W64>, use_sp: bool) {
    if r.0 == 31 {
        if use_sp {
            b.set(sp_ref(), v);
        }
    } else {
        b.set(r.state(), v);
    }
}

/// `r` に W 値を書く（W64 へゼロ拡張）。
pub fn write_w<B: Backend>(b: &mut B, r: Gpr, v: B::V<W32>, use_sp: bool) {
    let e = b.zext::<W32, W64>(v);
    write(b, r, e, use_sp);
}

fn k64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

fn k32<B: Backend>(b: &mut B, v: u32) -> B::V<W32> {
    b.konst::<W32>(v)
}

fn k16<B: Backend>(b: &mut B, v: u16) -> B::V<W16> {
    b.konst::<W16>(v)
}

fn k<B: Backend, W: Width>(b: &mut B, v: u128) -> B::V<W> {
    b.konst::<W>(W::from_u128(v))
}

fn true_b<B: Backend>(b: &mut B) -> B::B {
    let t = k64(b, 1);
    let z = k64(b, 0);
    b.cmp::<W64>(Cmp::Ne, t, z)
}

fn false_b<B: Backend>(b: &mut B) -> B::B {
    let t = k64(b, 0);
    let z = k64(b, 0);
    b.cmp::<W64>(Cmp::Ne, t, z)
}

fn inv<B: Backend>(b: &mut B, c: B::B) -> B::B {
    let t = k64(b, 1);
    let f = k64(b, 0);
    let s = b.select::<W64>(c, f, t);
    let z = k64(b, 0);
    b.cmp::<W64>(Cmp::Ne, s, z)
}

fn bor<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let t = k64(b, 1);
    let f = k64(b, 0);
    let sy = b.select::<W64>(y, t, f);
    let r = b.select::<W64>(x, t, sy);
    let z = k64(b, 0);
    b.cmp::<W64>(Cmp::Ne, r, z)
}

fn band<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let t = k64(b, 1);
    let f = k64(b, 0);
    let sy = b.select::<W64>(y, t, f);
    let r = b.select::<W64>(x, sy, f);
    let z = k64(b, 0);
    b.cmp::<W64>(Cmp::Ne, r, z)
}

// ---- NZCV ----

fn nzcv_bits<B: Backend>(b: &mut B, n: B::B, z: B::B, c: B::B, v: B::B) -> B::V<W64> {
    let eight = k64(b, 8);
    let four = k64(b, 4);
    let two = k64(b, 2);
    let one = k64(b, 1);
    let zero = k64(b, 0);
    let n8 = b.select::<W64>(n, eight, zero);
    let z8 = b.select::<W64>(z, four, zero);
    let c8 = b.select::<W64>(c, two, zero);
    let v8 = b.select::<W64>(v, one, zero);
    let t = b.or(n8, z8);
    let u = b.or(c8, v8);
    b.or(t, u)
}

fn get_nzcv<B: Backend>(b: &mut B) -> B::V<W64> {
    b.get(nzcv_ref())
}

fn set_nzcv_arith<B: Backend, W: Width>(b: &mut B, res: B::V<W>, carry: B::B, ovf: B::B) {
    let msb = k::<B, W>(b, 1u128 << (W::BITS - 1));
    let zero = k::<B, W>(b, 0);
    let masked = b.and(res, msb);
    let n = b.cmp::<W>(Cmp::Ne, masked, zero);
    let z = b.cmp::<W>(Cmp::Eq, res, zero);
    let bits = nzcv_bits(b, n, z, carry, ovf);
    b.set(nzcv_ref(), bits);
}

fn set_nzcv_logic<B: Backend, W: Width>(b: &mut B, res: B::V<W>) {
    let msb = k::<B, W>(b, 1u128 << (W::BITS - 1));
    let zero = k::<B, W>(b, 0);
    let masked = b.and(res, msb);
    let n = b.cmp::<W>(Cmp::Ne, masked, zero);
    let z = b.cmp::<W>(Cmp::Eq, res, zero);
    let f = false_b(b);
    let bits = nzcv_bits(b, n, z, f, f);
    b.set(nzcv_ref(), bits);
}

/// 条件コードを評価する。cond: eq=0,ne=1,cs=2,cc=3,mi=4,pl=5,vs=6,vc=7,
/// hi=8,ls=9,ge=a,lt=b,gt=c,le=d,al/nv=e/f。
/// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09) C1.2.3.
fn cond_eval<B: Backend>(b: &mut B, cond: u32) -> B::B {
    let nzcv = get_nzcv(b);
    let eight = k64(b, 8);
    let four = k64(b, 4);
    let two = k64(b, 2);
    let one = k64(b, 1);
    let zero = k64(b, 0);
    let mn = b.and(nzcv, eight);
    let n = b.cmp::<W64>(Cmp::Ne, mn, zero);
    let mz = b.and(nzcv, four);
    let z = b.cmp::<W64>(Cmp::Ne, mz, zero);
    let mc = b.and(nzcv, two);
    let c = b.cmp::<W64>(Cmp::Ne, mc, zero);
    let mv = b.and(nzcv, one);
    let v = b.cmp::<W64>(Cmp::Ne, mv, zero);
    match cond {
        0 => z,
        1 => inv(b, z),
        2 => c,
        3 => inv(b, c),
        4 => n,
        5 => inv(b, n),
        6 => v,
        7 => inv(b, v),
        8 => {
            // hi: C=1 && Z=0
            let nz = inv(b, z);
            band(b, c, nz)
        }
        9 => {
            // ls: C=0 || Z=1
            let nc = inv(b, c);
            bor(b, nc, z)
        }
        10 => {
            // ge: N==V
            let t = k64(b, 1);
            let f = k64(b, 0);
            let x = b.select::<W64>(n, t, f);
            let y = b.select::<W64>(v, t, f);
            b.cmp::<W64>(Cmp::Eq, x, y)
        }
        11 => {
            // lt: N!=V
            let t = k64(b, 1);
            let f = k64(b, 0);
            let x = b.select::<W64>(n, t, f);
            let y = b.select::<W64>(v, t, f);
            b.cmp::<W64>(Cmp::Ne, x, y)
        }
        12 => {
            // gt: Z==0 && N==V
            let t = k64(b, 1);
            let f = k64(b, 0);
            let x = b.select::<W64>(n, t, f);
            let y = b.select::<W64>(v, t, f);
            let eq = b.cmp::<W64>(Cmp::Eq, x, y);
            let nz = inv(b, z);
            band(b, nz, eq)
        }
        13 => {
            // le: Z==1 || N!=V
            let t = k64(b, 1);
            let f = k64(b, 0);
            let x = b.select::<W64>(n, t, f);
            let y = b.select::<W64>(v, t, f);
            let ne = b.cmp::<W64>(Cmp::Ne, x, y);
            bor(b, z, ne)
        }
        _ => true_b(b),
    }
}

// ---- 制御 ----

/// B。target は組み立て済みの PC 相対目標。
pub fn b_<B: Backend>(b: &mut B, target: u64) -> Flow<B> {
    let t = k64(b, target);
    b.jump(t);
    Ok(())
}

/// BL。x30 に PC+4 を入れて飛ぶ。
pub fn bl<B: Backend>(b: &mut B, pc: u64, target: u64) -> Flow<B> {
    let ret = k64(b, pc.wrapping_add(4));
    b.set(Gpr(30).state(), ret);
    b_(b, target)
}

/// B.cond。
pub fn b_cond<B: Backend>(b: &mut B, target: u64, cond: u32) -> Flow<B> {
    let c = cond_eval(b, cond);
    b.branch(c, target);
    Ok(())
}

/// CBZ/CBNZ。`is64` で W/X の幅を選ぶ。`nz` は CBNZ か。
pub fn cbz<B: Backend>(b: &mut B, rt: Gpr, target: u64, is64: bool, nz: bool) -> Flow<B> {
    let c = if is64 {
        let v = read(b, rt, false);
        let zero = k64(b, 0);
        let z = b.cmp::<W64>(Cmp::Eq, v, zero);
        if nz { inv(b, z) } else { z }
    } else {
        let v = read_w(b, rt, false);
        let zero = k32(b, 0);
        let z = b.cmp::<W32>(Cmp::Eq, v, zero);
        if nz { inv(b, z) } else { z }
    };
    b.branch(c, target);
    Ok(())
}

/// TBZ/TBNZ。`bit` は組み立て済みの位置（0-63）。
pub fn tbz<B: Backend>(b: &mut B, rt: Gpr, target: u64, bit: u32, nz: bool) -> Flow<B> {
    let v = read(b, rt, false);
    let mk = k64(b, 1u64 << bit);
    let m = b.and(v, mk);
    let zero = k64(b, 0);
    let z = b.cmp::<W64>(Cmp::Eq, m, zero);
    let c = if nz { inv(b, z) } else { z };
    b.branch(c, target);
    Ok(())
}

/// BR。rn=31 は ZR として読む（ARM ARM: レジスタ分岐は ZR 解釈）。
pub fn br<B: Backend>(b: &mut B, rn: Gpr) -> Flow<B> {
    let t = read(b, rn, false);
    b.jump(t);
    Ok(())
}

/// BLR。
pub fn blr<B: Backend>(b: &mut B, rn: Gpr, pc: u64) -> Flow<B> {
    let t = read(b, rn, false);
    let ret = k64(b, pc.wrapping_add(4));
    b.set(Gpr(30).state(), ret);
    b.jump(t);
    Ok(())
}

/// RET。
pub fn ret<B: Backend>(b: &mut B, rn: Gpr) -> Flow<B> {
    br(b, rn)
}

// ---- 例外生成・システム ----

/// SVC。OS パーソナリティへ委ねる印として Trap を上げる。
/// `code` は命令の imm16。
pub fn svc<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: u64::from(imm),
        addr: None,
        in_delay_slot: false,
    }))
}

/// HVC/SMC。ユーザーモードでは受理しない。
pub fn hvc_smc<B: Backend>(b: &mut B) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Undefined,
        code: 0,
        addr: None,
        in_delay_slot: false,
    }))
}

/// BRK/HLT。
pub fn brk<B: Backend>(b: &mut B, imm: u32) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Break,
        code: u64::from(imm),
        addr: None,
        in_delay_slot: false,
    }))
}

/// SYS（ヒント・バリア・IC/DC）。ユーザーモードでは何もしない。
pub fn sys_op<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// SYSL（AT 命令の結果読み出し）。ユーザーモードでは受理しない。
pub fn sysl<B: Backend>(b: &mut B) -> Flow<B> {
    Err(b.raise(GuestException {
        kind: ExceptionKind::Undefined,
        code: 0,
        addr: None,
        in_delay_slot: false,
    }))
}

/// MRS。ユーザー空間から読めるシステムレジスタの値を返す。
/// `sysop` は op0<<14|op1<<11|crn<<7|crm<<3|op2 に畳んだ番号。
/// 知らない番号は 0 を返す（Linux のエミュレーションと同じ緩さ）。
/// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09), SRC-LINUX (7.3)。
pub fn mrs<B: Backend>(b: &mut B, rt: Gpr, sysop: u32) -> Flow<B> {
    let v: u64 = match sysop {
        // TPIDR_EL0 = S3_3_C13_C0_2
        0xDE82 => {
            let t = b.get(tpidr_ref());
            write(b, rt, t, false);
            return Ok(());
        }
        // FPCR = S3_3_C4_C4_0
        0xD861 => {
            let t = b.get(fpcr_ref());
            write(b, rt, t, false);
            return Ok(());
        }
        // FPSR = S3_3_C4_C4_1
        0xD869 => {
            let t = b.get(fpsr_ref());
            write(b, rt, t, false);
            return Ok(());
        }
        // CNTFRQ_EL0 = S3_3_C14_C0_0: 1 MHz とする
        0xE001 => 1_000_000,
        // CNTVCT_EL0 = S3_3_C14_C0_2: 0 を返す（正確な時計は後の段階）
        0xE002 => 0,
        // DCZID_EL0 = S3_3_C0_C0_7: DZP=1（EL0 で DC ZVA 禁止）にし、
        // libc に ZVA 経路を選ばせない（SYS の cache op は no-op のため
        // ゼロ化されず壊れる）。
        0xC007 => 0x10,
        // CTR_EL0 = S3_3_C0_C0_1: IminLine/DminLine=4（64 バイト）他 0
        0xC001 => 0x8444_c004,
        // ---- ID レジスタ群。EL0 からの読み出しは OS がエミュレートする
        // 領分で、ここでは「この実装が持つ機能」を正直に返す。
        // MIDR_EL1 = S3_0_C0_C0_0: Implementer='A'(Arm)、Cortex-A53 相当。
        0xC000 => 0x410f_d034,
        // MPIDR_EL1 = S3_0_C0_C0_5: U=1（単一スレッド）。
        0xC005 => 0x8000_0000,
        // ID_AA64PFR0_EL1 = S3_0_C0_C4_0: EL0 は AArch64 のみ（2）、
        // FP と AdvSIMD は実装済み（0）。EL1 以上・SVE・RAS 等はなし。
        0xC020 => 0x2,
        // MVFR0_EL1 = S3_0_C0_C3_0: 128 ビット SIMD レジスタ 32 本、
        // 単/倍精度・除算・平方根・最近接丸めあり、トラップなし。
        0xC018 => 0x1011_0112,
        // MVFR1_EL1 = S3_0_C0_C3_1: FMAC/SP/整数/ロードストアあり、
        // 半精度 SIMD はなし、NaN 伝播・FtZ 対応。
        0xC019 => 0x1011_1011,
        // その他の ID（PFR1/ZFR0/DFR/AFR/ISAR/MMFR/MVFR2/REVIDR）は
        // オプション機能を実装していないため 0。
        _ => 0,
    };
    let kv = k64(b, v);
    write(b, rt, kv, false);
    Ok(())
}

/// MSR。書けるシステムレジスタだけを受ける。
pub fn msr<B: Backend>(b: &mut B, rt: Gpr, sysop: u32) -> Flow<B> {
    let v = read(b, rt, false);
    match sysop {
        0xDE82 => b.set(tpidr_ref(), v),
        0xD861 => b.set(fpcr_ref(), v),
        0xD869 => b.set(fpsr_ref(), v),
        _ => {}
    }
    Ok(())
}

// ---- データ処理（即値）----

/// 加減算即値。`imm` は sh<<12 済みの非負値。rn/rd は SP 文脈。
pub fn add_imm<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rn: Gpr,
    imm: u64,
    is64: bool,
    sub: bool,
    flags: bool,
) -> Flow<B> {
    // S 形式（cmp/cmn 相当を含む）は ZR 文脈、非 S 形式は SP 文脈。
    // flags でも rd への書き戻しは起きる（rd=31 は ZR として捨てる）。
    let use_sp = !flags;
    if is64 {
        let x = read(b, rn, use_sp);
        let (res, cry, ovf) = if sub {
            let iv = k64(b, imm);
            let y = b.not(iv);
            let c = true_b(b);
            b.add_with_carry(x, y, c)
        } else {
            let y = k64(b, imm);
            let c = false_b(b);
            b.add_with_carry(x, y, c)
        };
        if flags {
            set_nzcv_arith::<B, W64>(b, res, cry, ovf);
        }
        write(b, rd, res, use_sp);
    } else {
        let x = read_w(b, rn, use_sp);
        let (res, cry, ovf) = if sub {
            let iv = k32(b, imm as u32);
            let y = b.not(iv);
            let c = true_b(b);
            b.add_with_carry(x, y, c)
        } else {
            let y = k32(b, imm as u32);
            let c = false_b(b);
            b.add_with_carry(x, y, c)
        };
        if flags {
            set_nzcv_arith::<B, W32>(b, res, cry, ovf);
        }
        write_w(b, rd, res, use_sp);
    }
    Ok(())
}

/// Arm ARM `DecodeBitMasks`（wmask のみ使う）。`len` は N:~imms の最上位セット
/// ビット。即値論理では imms==levels は予約。
/// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09) shared/functions。
pub fn decode_bit_masks(n: u32, imms: u32, immr: u32, is64: bool) -> Option<u64> {
    let m: u32 = if is64 { 64 } else { 32 };
    let concat = ((n << 6) | (!imms & 0x3f)) & 0x7f;
    if concat == 0 {
        return None;
    }
    let len = 31 - concat.leading_zeros();
    if len < 1 || m < (1u32 << len) {
        return None;
    }
    let levels = (1u32 << len) - 1;
    if (imms & levels) == levels {
        return None;
    }
    let s = imms & levels;
    let r = immr & levels;
    let esize = 1u64 << len;
    // esize ビット幅の要素マスク。esize=64 のとき全ビット。
    let emask = if esize >= 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    };
    let welem = if s >= 63 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };
    let wrot = if r == 0 {
        welem
    } else {
        ((welem >> r) | (welem << (esize as u32 - r))) & emask
    };
    let mut out = 0u64;
    let mut pos = 0u32;
    while pos < m {
        out |= wrot << pos;
        pos += esize as u32;
    }
    Some(out)
}

/// 論理即値。`mask` はビットマスク即値の展開済み（exec が DecodeBitMasks で計算）。
/// op: 0=and,1=orr,2=eor,3=ands。
pub fn log_imm<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, mask: u64, op: u32, is64: bool) -> Flow<B> {
    if is64 {
        let x = read(b, rn, false);
        let m = k64(b, mask);
        let res = match op {
            0 | 3 => b.and(x, m),
            1 => b.or(x, m),
            _ => b.xor(x, m),
        };
        if op == 3 {
            set_nzcv_logic::<B, W64>(b, res);
        }
        write(b, rd, res, false);
    } else {
        let x = read_w(b, rn, false);
        let m = k32(b, mask as u32);
        let res = match op {
            0 | 3 => b.and(x, m),
            1 => b.or(x, m),
            _ => b.xor(x, m),
        };
        if op == 3 {
            set_nzcv_logic::<B, W32>(b, res);
        }
        write_w(b, rd, res, false);
    }
    Ok(())
}

/// MOVZ。`imm << (16*hw)` を rd に置く（ほかは 0）。
pub fn movz<B: Backend>(b: &mut B, rd: Gpr, imm: u64, is64: bool) -> Flow<B> {
    if is64 {
        let v = k64(b, imm);
        write(b, rd, v, false);
    } else {
        let v = k32(b, imm as u32);
        write_w(b, rd, v, false);
    }
    Ok(())
}

/// MOVN。`~(imm << (16*hw))` を rd に置く。
pub fn movn<B: Backend>(b: &mut B, rd: Gpr, imm: u64, is64: bool) -> Flow<B> {
    if is64 {
        let v = k64(b, !imm);
        write(b, rd, v, false);
    } else {
        let v = k32(b, !(imm as u32));
        write_w(b, rd, v, false);
    }
    Ok(())
}

/// MOVK。`imm` を `16*hw` の位置に入れ、ほかは保持する。
pub fn movk<B: Backend>(b: &mut B, rd: Gpr, imm: u64, hw: u32, is64: bool) -> Flow<B> {
    let pos = 16 * hw;
    if is64 {
        let keep = !(0xffffu64 << pos);
        let cur = read(b, rd, false);
        let ins = k64(b, imm << pos);
        let m = k64(b, keep);
        let a = b.and(cur, m);
        let res = b.or(a, ins);
        write(b, rd, res, false);
    } else {
        let keep = !(0xffffu32 << pos);
        let cur = read_w(b, rd, false);
        let ins = k32(b, (imm as u32) << pos);
        let m = k32(b, keep);
        let a = b.and(cur, m);
        let res = b.or(a, ins);
        write_w(b, rd, res, false);
    }
    Ok(())
}

/// ADR/ADRP。`off` は組み立て済みの符号付きオフセット。
pub fn adr<B: Backend>(b: &mut B, rd: Gpr, pc: u64, off: i64) -> Flow<B> {
    let t = k64(b, pc.wrapping_add(off as u64));
    write(b, rd, t, false);
    Ok(())
}

fn ror64<B: Backend>(b: &mut B, v: B::V<W64>, n: u32) -> B::V<W64> {
    if n == 0 {
        v
    } else {
        let s1 = k64(b, u64::from(n));
        let lo = b.shr_l(v, s1);
        let s2 = k64(b, u64::from(64 - n));
        let hi = b.shl(v, s2);
        b.or(lo, hi)
    }
}

fn ror32<B: Backend>(b: &mut B, v: B::V<W32>, n: u32) -> B::V<W32> {
    if n == 0 {
        v
    } else {
        let s1 = k32(b, n);
        let lo = b.shr_l(v, s1);
        let s2 = k32(b, 32 - n);
        let hi = b.shl(v, s2);
        b.or(lo, hi)
    }
}

/// ビットフィールド。`op`: 0=sbfm,1=bfm,2=ubfm。
/// 即値 immr/imms と幅は exec が展開する。
pub fn bitfield<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rn: Gpr,
    immr: u32,
    imms: u32,
    op: u32,
    is64: bool,
) -> Flow<B> {
    if is64 {
        bitfield64(b, rd, rn, immr, imms, op);
    } else {
        bitfield32(b, rd, rn, immr, imms, op);
    }
    Ok(())
}

/// UBFM/SBFM/BFM の wmask。`immr <= imms` は抽出形（ubfx/lsr/uxt*）、
/// `immr > imms` は左挿入形（lsl/ubfiz）。Ref: SPEC-A64-ISA（UBFM/SBFM/BFM）。
fn bfm_mask(immr: u32, imms: u32, esize: u32) -> u64 {
    let ones = |w: u32| -> u64 { if w >= 64 { u64::MAX } else { (1u64 << w) - 1 } };
    let m = if immr <= imms {
        ones(imms - immr + 1)
    } else {
        ones(imms + 1) << (esize - immr)
    };
    m & ones(esize)
}

fn bitfield64<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, immr: u32, imms: u32, op: u32) {
    let src = read(b, rn, false);
    let r = ror64(b, src, immr);
    let maskv = bfm_mask(immr, imms, 64);
    let m = k64(b, maskv);
    match op {
        2 => {
            let res = b.and(r, m);
            write(b, rd, res, false);
        }
        1 => {
            let cur = read(b, rd, false);
            let nm = b.not(m);
            let keep = b.and(cur, nm);
            let ins = b.and(r, m);
            let res = b.or(keep, ins);
            write(b, rd, res, false);
        }
        _ => {
            // 符号は「ローテート前」の src<imms> で決める。
            let low = b.and(r, m);
            let sp = k64(b, 1u64 << imms);
            let s = b.and(src, sp);
            let zero = k64(b, 0);
            let is_neg = b.cmp::<W64>(Cmp::Ne, s, zero);
            let ext = k64(b, !maskv);
            let hi = b.or(low, ext);
            let res = b.select::<W64>(is_neg, hi, low);
            write(b, rd, res, false);
        }
    }
}

fn bitfield32<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, immr: u32, imms: u32, op: u32) {
    let src = read_w(b, rn, false);
    let r = ror32(b, src, immr);
    let maskv = bfm_mask(immr, imms, 32);
    let m = k32(b, maskv as u32);
    match op {
        2 => {
            let res = b.and(r, m);
            write_w(b, rd, res, false);
        }
        1 => {
            let cur = read_w(b, rd, false);
            let nm = b.not(m);
            let keep = b.and(cur, nm);
            let ins = b.and(r, m);
            let res = b.or(keep, ins);
            write_w(b, rd, res, false);
        }
        _ => {
            let low = b.and(r, m);
            let sp = k32(b, 1u32 << imms);
            let s = b.and(src, sp);
            let zero = k32(b, 0);
            let is_neg = b.cmp::<W32>(Cmp::Ne, s, zero);
            let ext = k32(b, !(maskv as u32));
            let hi = b.or(low, ext);
            let res = b.select::<W32>(is_neg, hi, low);
            write_w(b, rd, res, false);
        }
    }
}

/// EXTR。`{rn:rm}` を右に imms シフトした低位を取る。
/// rn==rm は ROR の別名。
pub fn extr<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, rm: Gpr, imms: u32, is64: bool) -> Flow<B> {
    if is64 {
        let lo = read(b, rm, false);
        let res = if rn == rm {
            ror64(b, lo, imms)
        } else {
            let hi = read(b, rn, false);
            let s1 = k64(b, u64::from(imms));
            let l = b.shr_l(lo, s1);
            let s2 = k64(b, u64::from(64 - imms));
            let h = b.shl(hi, s2);
            b.or(l, h)
        };
        write(b, rd, res, false);
    } else {
        let lo = read_w(b, rm, false);
        let res = if rn == rm {
            ror32(b, lo, imms)
        } else {
            let hi = read_w(b, rn, false);
            let s1 = k32(b, imms);
            let l = b.shr_l(lo, s1);
            let s2 = k32(b, 32 - imms);
            let h = b.shl(hi, s2);
            b.or(l, h)
        };
        write_w(b, rd, res, false);
    }
    Ok(())
}

// ---- データ処理（レジスタ）----

fn shifted64<B: Backend>(b: &mut B, rm: Gpr, shift: u32, imm6: u32) -> B::V<W64> {
    let v = read(b, rm, false);
    let n = k64(b, u64::from(imm6));
    match shift {
        1 => b.shr_l(v, n),
        2 => b.shr_a(v, n),
        3 => ror64(b, v, imm6),
        _ => b.shl(v, n),
    }
}

fn shifted32<B: Backend>(b: &mut B, rm: Gpr, shift: u32, imm6: u32) -> B::V<W32> {
    let v = read_w(b, rm, false);
    let n = k32(b, imm6);
    match shift {
        1 => b.shr_l(v, n),
        2 => b.shr_a(v, n),
        3 => ror32(b, v, imm6),
        _ => b.shl(v, n),
    }
}

/// 論理シフト。`opc`: 0=and,1=orr,2=eor,3=ands。`neg` は N（bic/orn/eon/bics）。
#[allow(clippy::too_many_arguments)]
pub fn log_sh<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rn: Gpr,
    rm: Gpr,
    shift: u32,
    imm6: u32,
    opc: u32,
    neg: bool,
    is64: bool,
) -> Flow<B> {
    if is64 {
        let x = read(b, rn, false);
        let y0 = shifted64(b, rm, shift, imm6);
        let y = if neg { b.not(y0) } else { y0 };
        let res = match opc {
            0 | 3 => b.and(x, y),
            1 => b.or(x, y),
            _ => b.xor(x, y),
        };
        if opc == 3 {
            set_nzcv_logic::<B, W64>(b, res);
        }
        write(b, rd, res, false);
    } else {
        let x = read_w(b, rn, false);
        let y0 = shifted32(b, rm, shift, imm6);
        let y = if neg { b.not(y0) } else { y0 };
        let res = match opc {
            0 | 3 => b.and(x, y),
            1 => b.or(x, y),
            _ => b.xor(x, y),
        };
        if opc == 3 {
            set_nzcv_logic::<B, W32>(b, res);
        }
        write_w(b, rd, res, false);
    }
    Ok(())
}

/// 加減算シフト。rn/rd は ZR 文脈（SP ではない）。
#[allow(clippy::too_many_arguments)]
pub fn add_sh<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rn: Gpr,
    rm: Gpr,
    shift: u32,
    imm6: u32,
    is64: bool,
    sub: bool,
    flags: bool,
) -> Flow<B> {
    if is64 {
        let x = read(b, rn, false);
        let y0 = shifted64(b, rm, shift, imm6);
        let (res, cry, ovf) = if sub {
            let y = b.not(y0);
            let c = true_b(b);
            b.add_with_carry(x, y, c)
        } else {
            let c = false_b(b);
            b.add_with_carry(x, y0, c)
        };
        if flags {
            set_nzcv_arith::<B, W64>(b, res, cry, ovf);
        }
        write(b, rd, res, false);
    } else {
        let x = read_w(b, rn, false);
        let y0 = shifted32(b, rm, shift, imm6);
        let (res, cry, ovf) = if sub {
            let y = b.not(y0);
            let c = true_b(b);
            b.add_with_carry(x, y, c)
        } else {
            let c = false_b(b);
            b.add_with_carry(x, y0, c)
        };
        if flags {
            set_nzcv_arith::<B, W32>(b, res, cry, ovf);
        }
        write_w(b, rd, res, false);
    }
    Ok(())
}

/// 拡張したオペランド 2。option: 0=uxtb,1=uxth,2=uxtw,3=uxtx(sf),
/// 4=sxtb,5=sxth,6=sxtw,7=sxtx。W 形式では option>=4 は 32 ビット符号。
fn extend64<B: Backend>(b: &mut B, rm: Gpr, option: u32, imm3: u32) -> B::V<W64> {
    let v = read(b, rm, false);
    let e = match option {
        0 => {
            let t = b.trunc::<W64, W8>(v);
            b.zext::<W8, W64>(t)
        }
        1 => {
            let t = b.trunc::<W64, W16>(v);
            b.zext::<W16, W64>(t)
        }
        2 => {
            let t = b.trunc::<W64, W32>(v);
            b.zext::<W32, W64>(t)
        }
        3 => v,
        4 => {
            let t = b.trunc::<W64, W8>(v);
            b.sext::<W8, W64>(t)
        }
        5 => {
            let t = b.trunc::<W64, W16>(v);
            b.sext::<W16, W64>(t)
        }
        6 => {
            let t = b.trunc::<W64, W32>(v);
            b.sext::<W32, W64>(t)
        }
        _ => v,
    };
    if imm3 == 0 {
        e
    } else {
        let s = k64(b, u64::from(imm3));
        b.shl(e, s)
    }
}

/// 加減算拡張。rn/rd は SP 文脈。
#[allow(clippy::too_many_arguments)]
pub fn add_ext<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rn: Gpr,
    rm: Gpr,
    option: u32,
    imm3: u32,
    is64: bool,
    sub: bool,
    flags: bool,
) -> Flow<B> {
    let y = extend64(b, rm, option, imm3);
    // 拡張レジスタ形式では rn は常に SP 文脈（S ビットと無関係）。
    // rd は非 S 形式のみ SP 文脈（S 形式は ZR=捨てる）。
    if is64 {
        let x = read(b, rn, true);
        let (res, cry, ovf) = if sub {
            let ny = b.not(y);
            let c = true_b(b);
            b.add_with_carry(x, ny, c)
        } else {
            let c = false_b(b);
            b.add_with_carry(x, y, c)
        };
        if flags {
            set_nzcv_arith::<B, W64>(b, res, cry, ovf);
        }
        write(b, rd, res, !flags);
    } else {
        let x = read_w(b, rn, true);
        let yw = b.trunc::<W64, W32>(y);
        let (res, cry, ovf) = if sub {
            let ny = b.not(yw);
            let c = true_b(b);
            b.add_with_carry(x, ny, c)
        } else {
            let c = false_b(b);
            b.add_with_carry(x, yw, c)
        };
        if flags {
            set_nzcv_arith::<B, W32>(b, res, cry, ovf);
        }
        write_w(b, rd, res, !flags);
    }
    Ok(())
}

/// 条件選択。op2: 0=csel,1=csinc,2=csinv,3=csneg。
pub fn csel<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rn: Gpr,
    rm: Gpr,
    cond: u32,
    op2: u32,
    is64: bool,
) -> Flow<B> {
    let c = cond_eval(b, cond);
    if is64 {
        let x = read(b, rn, false);
        let y = read(b, rm, false);
        let one = k64(b, 1);
        let y2 = match op2 {
            1 => b.add(y, one),
            2 => b.not(y),
            3 => {
                let n = b.not(y);
                b.add(n, one)
            }
            _ => y,
        };
        let res = b.select::<W64>(c, x, y2);
        write(b, rd, res, false);
    } else {
        let x = read_w(b, rn, false);
        let y = read_w(b, rm, false);
        let one = k32(b, 1);
        let y2 = match op2 {
            1 => b.add(y, one),
            2 => b.not(y),
            3 => {
                let n = b.not(y);
                b.add(n, one)
            }
            _ => y,
        };
        let res = b.select::<W32>(c, x, y2);
        write_w(b, rd, res, false);
    }
    Ok(())
}

/// 条件比較。op: ccmn=false（加算）/ccmp=true（減算）。
#[allow(clippy::too_many_arguments)]
pub fn ccmp<B: Backend>(
    b: &mut B,
    rn: Gpr,
    rm: Gpr,
    imm: u64,
    nzcv: u32,
    cond: u32,
    is64: bool,
    is_imm: bool,
    cmp_sub: bool,
) -> Flow<B> {
    let c = cond_eval(b, cond);
    let taken = k64(b, u64::from(nzcv));
    if is64 {
        let x = read(b, rn, false);
        let y = if is_imm {
            k64(b, imm)
        } else {
            read(b, rm, false)
        };
        let (res, cry, ovf) = if cmp_sub {
            let ny = b.not(y);
            let i = true_b(b);
            b.add_with_carry(x, ny, i)
        } else {
            let i = false_b(b);
            b.add_with_carry(x, y, i)
        };
        let msb = k64(b, 1u64 << 63);
        let zero = k64(b, 0);
        let masked = b.and(res, msb);
        let n = b.cmp::<W64>(Cmp::Ne, masked, zero);
        let z = b.cmp::<W64>(Cmp::Eq, res, zero);
        let bits = nzcv_bits(b, n, z, cry, ovf);
        let out = b.select::<W64>(c, bits, taken);
        b.set(nzcv_ref(), out);
    } else {
        let x = read_w(b, rn, false);
        let y = if is_imm {
            k32(b, imm as u32)
        } else {
            read_w(b, rm, false)
        };
        let (res, cry, ovf) = if cmp_sub {
            let ny = b.not(y);
            let i = true_b(b);
            b.add_with_carry(x, ny, i)
        } else {
            let i = false_b(b);
            b.add_with_carry(x, y, i)
        };
        let msb = k32(b, 1u32 << 31);
        let zero = k32(b, 0);
        let masked = b.and(res, msb);
        let n = b.cmp::<W32>(Cmp::Ne, masked, zero);
        let z = b.cmp::<W32>(Cmp::Eq, res, zero);
        let bits = nzcv_bits(b, n, z, cry, ovf);
        let out = b.select::<W64>(c, bits, taken);
        b.set(nzcv_ref(), out);
    }
    Ok(())
}

// ---- 2/1/3 オペランド ----

/// 2 オペランド。op: 0=udiv,1=sdiv,2=lslv,3=lsrv,4=asrv,5=rorv。
pub fn dp2<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, rm: Gpr, op: u32, is64: bool) -> Flow<B> {
    if is64 {
        let x = read(b, rn, false);
        let y = read(b, rm, false);
        let res = match op {
            0 => {
                let zero = k64(b, 0);
                let z = b.cmp::<W64>(Cmp::Eq, y, zero);
                let q = b.udiv(x, y);
                b.select::<W64>(z, zero, q)
            }
            1 => {
                let zero = k64(b, 0);
                let z = b.cmp::<W64>(Cmp::Eq, y, zero);
                let q = b.sdiv(x, y);
                b.select::<W64>(z, zero, q)
            }
            2 => {
                let m = k64(b, 63);
                let n = b.and(y, m);
                b.shl(x, n)
            }
            3 => {
                let m = k64(b, 63);
                let n = b.and(y, m);
                b.shr_l(x, n)
            }
            4 => {
                let m = k64(b, 63);
                let n = b.and(y, m);
                b.shr_a(x, n)
            }
            _ => {
                let m = k64(b, 63);
                let n = b.and(y, m);
                let lo = b.shr_l(x, n);
                let w = k64(b, 64);
                let r = b.sub(w, n);
                let hi = b.shl(x, r);
                let rr = b.or(lo, hi);
                let zero = k64(b, 0);
                let z0 = b.cmp::<W64>(Cmp::Eq, n, zero);
                b.select::<W64>(z0, x, rr)
            }
        };
        write(b, rd, res, false);
    } else {
        let x = read_w(b, rn, false);
        let y = read_w(b, rm, false);
        let res = match op {
            0 => {
                let zero = k32(b, 0);
                let z = b.cmp::<W32>(Cmp::Eq, y, zero);
                let q = b.udiv(x, y);
                b.select::<W32>(z, zero, q)
            }
            1 => {
                let zero = k32(b, 0);
                let z = b.cmp::<W32>(Cmp::Eq, y, zero);
                let q = b.sdiv(x, y);
                b.select::<W32>(z, zero, q)
            }
            2 => {
                let m = k32(b, 31);
                let n = b.and(y, m);
                b.shl(x, n)
            }
            3 => {
                let m = k32(b, 31);
                let n = b.and(y, m);
                b.shr_l(x, n)
            }
            4 => {
                let m = k32(b, 31);
                let n = b.and(y, m);
                b.shr_a(x, n)
            }
            _ => {
                let m = k32(b, 31);
                let n = b.and(y, m);
                let lo = b.shr_l(x, n);
                let w = k32(b, 32);
                let r = b.sub(w, n);
                let hi = b.shl(x, r);
                let rr = b.or(lo, hi);
                let zero = k32(b, 0);
                let z0 = b.cmp::<W32>(Cmp::Eq, n, zero);
                b.select::<W32>(z0, x, rr)
            }
        };
        write_w(b, rd, res, false);
    }
    Ok(())
}

fn bswap32<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W32> {
    let m0 = k32(b, 0xff);
    let m1 = k32(b, 0xff00);
    let m2 = k32(b, 0x00ff_0000);
    let b0 = b.and(v, m0);
    let b1 = b.and(v, m1);
    let b2 = b.and(v, m2);
    let s24 = k32(b, 24);
    let s8 = k32(b, 8);
    let b3 = b.shr_l(v, s24);
    let t0 = b.shl(b0, s24);
    let t1 = b.shl(b1, s8);
    let t2 = b.shr_l(b2, s8);
    let a = b.or(t0, t1);
    let c = b.or(t2, b3);
    b.or(a, c)
}

fn bswap64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let lo = b.trunc::<W64, W32>(v);
    let s32 = k64(b, 32);
    let hiv = b.shr_l(v, s32);
    let hi = b.trunc::<W64, W32>(hiv);
    let lo_s = bswap32(b, lo);
    let hi_s = bswap32(b, hi);
    let lo64 = b.zext::<W32, W64>(lo_s);
    let hi64 = b.zext::<W32, W64>(hi_s);
    let top = b.shl(lo64, s32);
    b.or(top, hi64)
}

fn bitrev64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let mut x = v;
    for &(s, m) in &[
        (1u64, 0x5555_5555_5555_5555u64),
        (2, 0x3333_3333_3333_3333),
        (4, 0x0f0f_0f0f_0f0f_0f0f),
        (8, 0x00ff_00ff_00ff_00ff),
        (16, 0x0000_ffff_0000_ffff),
        (32, 0x0000_0000_ffff_ffff),
    ] {
        let mm = k64(b, m);
        let ss = k64(b, s);
        let lo = b.and(x, mm);
        let h = b.shr_l(x, ss);
        let hi = b.and(h, mm);
        let l2 = b.shl(lo, ss);
        x = b.or(l2, hi);
    }
    x
}

fn bitrev32<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W32> {
    let mut x = v;
    for &(s, m) in &[
        (1u32, 0x5555_5555u32),
        (2, 0x3333_3333),
        (4, 0x0f0f_0f0f),
        (8, 0x00ff_00ff),
        (16, 0x0000_ffff),
    ] {
        let mm = k32(b, m);
        let ss = k32(b, s);
        let lo = b.and(x, mm);
        let h = b.shr_l(x, ss);
        let hi = b.and(h, mm);
        let l2 = b.shl(lo, ss);
        x = b.or(l2, hi);
    }
    x
}

fn clz64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let mut count = k64(b, 64);
    let mut rem = v;
    for w in [32u64, 16, 8, 4, 2] {
        let wv = k64(b, w);
        let hi = b.shr_l(rem, wv);
        let zero = k64(b, 0);
        let nz = b.cmp::<W64>(Cmp::Ne, hi, zero);
        let sub = b.sub(count, wv);
        count = b.select::<W64>(nz, sub, count);
        rem = b.select::<W64>(nz, hi, rem);
    }
    // 残り 2 ビットの最終段は別扱い：rem>>1≠0 なら count-2、
    // そうでなければ count-rem（rem は 0 か 1）。
    let one = k64(b, 1);
    let hi = b.shr_l(rem, one);
    let zero = k64(b, 0);
    let nz = b.cmp::<W64>(Cmp::Ne, hi, zero);
    let two = k64(b, 2);
    let a = b.sub(count, two);
    let e = b.sub(count, rem);
    b.select::<W64>(nz, a, e)
}

fn clz32<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W32> {
    let mut count = k32(b, 32);
    let mut rem = v;
    for w in [16u32, 8, 4, 2] {
        let wv = k32(b, w);
        let hi = b.shr_l(rem, wv);
        let zero = k32(b, 0);
        let nz = b.cmp::<W32>(Cmp::Ne, hi, zero);
        let sub = b.sub(count, wv);
        count = b.select::<W32>(nz, sub, count);
        rem = b.select::<W32>(nz, hi, rem);
    }
    let one = k32(b, 1);
    let hi = b.shr_l(rem, one);
    let zero = k32(b, 0);
    let nz = b.cmp::<W32>(Cmp::Ne, hi, zero);
    let two = k32(b, 2);
    let a = b.sub(count, two);
    let e = b.sub(count, rem);
    b.select::<W32>(nz, a, e)
}

fn cls64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let s63 = k64(b, 63);
    let sign = b.shr_a(v, s63);
    let m1 = k64(b, -1i64 as u64);
    let m = b.cmp::<W64>(Cmp::Eq, sign, m1);
    let nv = b.not(v);
    let x = b.select::<W64>(m, nv, v);
    let c = clz64(b, x);
    let one = k64(b, 1);
    b.sub(c, one)
}

fn cls32<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W32> {
    let s31 = k32(b, 31);
    let sign = b.shr_a(v, s31);
    let m1 = k32(b, -1i32 as u32);
    let m = b.cmp::<W32>(Cmp::Eq, sign, m1);
    let nv = b.not(v);
    let x = b.select::<W32>(m, nv, v);
    let c = clz32(b, x);
    let one = k32(b, 1);
    b.sub(c, one)
}

/// 1 オペランド。op: 0=rbit,1=rev16,2=rev/rev32,3=rev64,4=clz,5=cls。
/// W 形式の `rev`（全バイト反転）は op=2 と is64=false の組み合わせ。
pub fn dp1<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, op: u32, is64: bool) -> Flow<B> {
    if is64 {
        let x = read(b, rn, false);
        let res = match op {
            0 => bitrev64(b, x),
            1 => {
                // REV16: 各半語内でバイトを反転。
                let lo = b.trunc::<W64, W16>(x);
                let m8 = k16(b, 0xff);
                let s8 = k16(b, 8);
                let b0 = b.and(lo, m8);
                let b1 = b.shr_l(lo, s8);
                let bl = b.shl(b0, s8);
                let sw0 = b.or(bl, b1);
                let s16 = k64(b, 16);
                let hiv = b.shr_l(x, s16);
                let h16 = b.trunc::<W64, W16>(hiv);
                let h0 = b.and(h16, m8);
                let h1 = b.shr_l(h16, s8);
                let hl = b.shl(h0, s8);
                let sw1 = b.or(hl, h1);
                let lo64 = b.zext::<W16, W64>(sw0);
                let hi64 = b.zext::<W16, W64>(sw1);
                let top = b.shl(hi64, s16);
                b.or(lo64, top)
            }
            2 => {
                // REV32: 各 32 ビット内でバイトを反転。
                let v = b.trunc::<W64, W32>(x);
                let r = bswap32(b, v);
                let lo = b.zext::<W32, W64>(r);
                let s32 = k64(b, 32);
                let hiv = b.shr_l(x, s32);
                let hv = b.trunc::<W64, W32>(hiv);
                let hr = bswap32(b, hv);
                let hi = b.zext::<W32, W64>(hr);
                let top = b.shl(hi, s32);
                b.or(lo, top)
            }
            3 => bswap64(b, x),
            4 => clz64(b, x),
            _ => cls64(b, x),
        };
        write(b, rd, res, false);
    } else {
        let x = read_w(b, rn, false);
        let res = match op {
            0 => bitrev32(b, x),
            1 => {
                // W の REV16。
                let m8 = k32(b, 0xff);
                let m8h = k32(b, 0xff00);
                let s8 = k32(b, 8);
                let s16 = k32(b, 16);
                let b0 = b.and(x, m8);
                let b1 = b.and(x, m8h);
                let bl = b.shl(b0, s8);
                let br = b.shr_l(b1, s8);
                let lo16 = b.or(bl, br);
                let hiv = b.shr_l(x, s16);
                let h0 = b.and(hiv, m8);
                let h1 = b.and(hiv, m8h);
                let hl = b.shl(h0, s8);
                let hr = b.shr_l(h1, s8);
                let hi16 = b.or(hl, hr);
                let mf = k32(b, 0xffff);
                let lo32 = b.and(lo16, mf);
                let hi32 = b.shl(hi16, s16);
                b.or(lo32, hi32)
            }
            2 => bswap32(b, x),
            4 => clz32(b, x),
            _ => cls32(b, x),
        };
        write_w(b, rd, res, false);
    }
    Ok(())
}

/// 3 オペランド（積和）。sub: msub。
pub fn madd<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rn: Gpr,
    rm: Gpr,
    ra: Gpr,
    sub: bool,
    is64: bool,
) -> Flow<B> {
    if is64 {
        let x = read(b, rn, false);
        let y = read(b, rm, false);
        let p = b.mul(x, y);
        let a = read(b, ra, false);
        let res = if sub { b.sub(a, p) } else { b.add(a, p) };
        write(b, rd, res, false);
    } else {
        let x = read_w(b, rn, false);
        let y = read_w(b, rm, false);
        let p = b.mul(x, y);
        let a = read_w(b, ra, false);
        let res = if sub { b.sub(a, p) } else { b.add(a, p) };
        write_w(b, rd, res, false);
    }
    Ok(())
}

/// 64x32 の積和。op: 0=smaddl,1=smsubl,2=umaddl,3=umsubl。
pub fn maddl<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, rm: Gpr, ra: Gpr, op: u32) -> Flow<B> {
    let x = read_w(b, rn, false);
    let y = read_w(b, rm, false);
    let (px, py) = if op < 2 {
        (b.sext::<W32, W64>(x), b.sext::<W32, W64>(y))
    } else {
        (b.zext::<W32, W64>(x), b.zext::<W32, W64>(y))
    };
    let p = b.mul(px, py);
    let a = read(b, ra, false);
    let res = if op % 2 == 1 {
        b.sub(a, p)
    } else {
        b.add(a, p)
    };
    write(b, rd, res, false);
    Ok(())
}

/// 上位積。signed: smulh=true で符号付き。
pub fn mulh<B: Backend>(b: &mut B, rd: Gpr, rn: Gpr, rm: Gpr, signed: bool) -> Flow<B> {
    let x = read(b, rn, false);
    let y = read(b, rm, false);
    let res = if signed { b.mulh(x, y) } else { b.mulhu(x, y) };
    write(b, rd, res, false);
    Ok(())
}

// ---- ロード・ストア ----

fn addr_of<B: Backend>(b: &mut B, rn: Gpr, off: i64) -> B::V<W64> {
    let base = read(b, rn, true);
    let o = k64(b, off as u64);
    b.add(base, o)
}

fn do_load<B: Backend>(
    b: &mut B,
    rt: Gpr,
    addr: B::V<W64>,
    size: u32,
    sign: bool,
    to64: bool,
    endian: Endian,
) -> Flow<B> {
    let acc = data_read(endian);
    match (size, sign, to64) {
        (1, false, false) => {
            let v: B::V<W8> = b.load(addr, acc)?;
            let e = b.zext::<W8, W32>(v);
            write_w(b, rt, e, false);
        }
        (1, false, true) => {
            let v: B::V<W8> = b.load(addr, acc)?;
            let e = b.zext::<W8, W64>(v);
            write(b, rt, e, false);
        }
        (1, true, false) => {
            let v: B::V<W8> = b.load(addr, acc)?;
            let e = b.sext::<W8, W64>(v);
            let t = b.trunc::<W64, W32>(e);
            write_w(b, rt, t, false);
        }
        (1, true, true) => {
            let v: B::V<W8> = b.load(addr, acc)?;
            let e = b.sext::<W8, W64>(v);
            write(b, rt, e, false);
        }
        (2, false, false) => {
            let v: B::V<W16> = b.load(addr, acc)?;
            let e = b.zext::<W16, W32>(v);
            write_w(b, rt, e, false);
        }
        (2, false, true) => {
            let v: B::V<W16> = b.load(addr, acc)?;
            let e = b.zext::<W16, W64>(v);
            write(b, rt, e, false);
        }
        (2, true, false) => {
            let v: B::V<W16> = b.load(addr, acc)?;
            let e = b.sext::<W16, W64>(v);
            let t = b.trunc::<W64, W32>(e);
            write_w(b, rt, t, false);
        }
        (2, true, true) => {
            let v: B::V<W16> = b.load(addr, acc)?;
            let e = b.sext::<W16, W64>(v);
            write(b, rt, e, false);
        }
        (4, false, _) => {
            let v: B::V<W32> = b.load(addr, acc)?;
            write_w(b, rt, v, false);
        }
        (4, true, true) => {
            let v: B::V<W32> = b.load(addr, acc)?;
            let e = b.sext::<W32, W64>(v);
            write(b, rt, e, false);
        }
        (8, _, _) => {
            let v: B::V<W64> = b.load(addr, acc)?;
            write(b, rt, v, false);
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn do_store<B: Backend>(b: &mut B, rt: Gpr, addr: B::V<W64>, size: u32, endian: Endian) -> Flow<B> {
    let acc = data_write(endian);
    let v = read(b, rt, false);
    b.probe(addr, size, acc)?;
    match size {
        1 => {
            let t = b.trunc::<W64, W8>(v);
            b.store(addr, t, acc)?
        }
        2 => {
            let t = b.trunc::<W64, W16>(v);
            b.store(addr, t, acc)?
        }
        4 => {
            let t = b.trunc::<W64, W32>(v);
            b.store(addr, t, acc)?
        }
        _ => b.store(addr, v, acc)?,
    }
    Ok(())
}

/// unsigned 即値ロード/ストア。`imm` は size でスケール済み。
#[allow(clippy::too_many_arguments)]
pub fn ls_unsigned<B: Backend>(
    b: &mut B,
    rt: Gpr,
    rn: Gpr,
    imm: i64,
    size: u32,
    store: bool,
    sign: bool,
    to64: bool,
    endian: Endian,
) -> Flow<B> {
    let addr = addr_of(b, rn, imm);
    if store {
        do_store(b, rt, addr, size, endian)
    } else {
        do_load(b, rt, addr, size, sign, to64, endian)
    }
}

/// imm9 ロード/ストア。mode: 0=unscaled, 1=post, 3=pre。
#[allow(clippy::too_many_arguments)]
pub fn ls_imm9<B: Backend>(
    b: &mut B,
    rt: Gpr,
    rn: Gpr,
    imm: i64,
    size: u32,
    store: bool,
    sign: bool,
    to64: bool,
    mode: u32,
    endian: Endian,
) -> Flow<B> {
    let base = read(b, rn, true);
    match mode {
        1 => {
            let res = if store {
                do_store(b, rt, base, size, endian)
            } else {
                do_load(b, rt, base, size, sign, to64, endian)
            };
            let cur = read(b, rn, true);
            let o = k64(b, imm as u64);
            let nb = b.add(cur, o);
            write(b, rn, nb, true);
            res
        }
        3 => {
            let o = k64(b, imm as u64);
            let addr = b.add(base, o);
            write(b, rn, addr, true);
            if store {
                do_store(b, rt, addr, size, endian)
            } else {
                do_load(b, rt, addr, size, sign, to64, endian)
            }
        }
        _ => {
            let o = k64(b, imm as u64);
            let addr = b.add(base, o);
            if store {
                do_store(b, rt, addr, size, endian)
            } else {
                do_load(b, rt, addr, size, sign, to64, endian)
            }
        }
    }
}

/// レジスタオフセット。`amount` は S*log2(size) のシフト量。
#[allow(clippy::too_many_arguments)]
pub fn ls_regoff<B: Backend>(
    b: &mut B,
    rt: Gpr,
    rn: Gpr,
    rm: Gpr,
    option: u32,
    amount: u32,
    size: u32,
    store: bool,
    sign: bool,
    to64: bool,
    endian: Endian,
) -> Flow<B> {
    let v = read(b, rm, false);
    let e = match option {
        0 => {
            let t = b.trunc::<W64, W8>(v);
            b.zext::<W8, W64>(t)
        }
        1 => {
            let t = b.trunc::<W64, W16>(v);
            b.zext::<W16, W64>(t)
        }
        2 => {
            let t = b.trunc::<W64, W32>(v);
            b.zext::<W32, W64>(t)
        }
        3 => v,
        4 => {
            let t = b.trunc::<W64, W8>(v);
            b.sext::<W8, W64>(t)
        }
        5 => {
            let t = b.trunc::<W64, W16>(v);
            b.sext::<W16, W64>(t)
        }
        6 => {
            let t = b.trunc::<W64, W32>(v);
            b.sext::<W32, W64>(t)
        }
        _ => v,
    };
    let off = if amount == 0 {
        e
    } else {
        let s = k64(b, u64::from(amount));
        b.shl(e, s)
    };
    let base = read(b, rn, true);
    let addr = b.add(base, off);
    if store {
        do_store(b, rt, addr, size, endian)
    } else {
        do_load(b, rt, addr, size, sign, to64, endian)
    }
}

/// リテラルロード。`target` は pc + sext(imm19<<2)。
pub fn ls_lit<B: Backend>(
    b: &mut B,
    rt: Gpr,
    target: u64,
    size: u32,
    sign: bool,
    to64: bool,
    endian: Endian,
) -> Flow<B> {
    let addr = k64(b, target);
    do_load(b, rt, addr, size, sign, to64, endian)
}

/// PRFM。実行器では何もしない。
pub fn prfm<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// ペアロード/ストア。idx: 1=post,2=off,3=pre。
#[allow(clippy::too_many_arguments)]
pub fn ls_pair<B: Backend>(
    b: &mut B,
    rt: Gpr,
    rt2: Gpr,
    rn: Gpr,
    imm: i64,
    size: u32,
    store: bool,
    idx: u32,
    endian: Endian,
) -> Flow<B> {
    let base = read(b, rn, true);
    let io = k64(b, imm as u64);
    let addr = if idx == 1 { base } else { b.add(base, io) };
    if store {
        b.probe(addr, size * 2, data_write(endian))?;
        do_store(b, rt, addr, size, endian)?;
        let sz = k64(b, u64::from(size));
        let a2 = b.add(addr, sz);
        do_store(b, rt2, a2, size, endian)?;
    } else {
        do_load(b, rt, addr, size, false, size == 8, endian)?;
        let sz = k64(b, u64::from(size));
        let a2 = b.add(addr, sz);
        do_load(b, rt2, a2, size, false, size == 8, endian)?;
    }
    // 書き戻し: ポスト(1) は base+imm、プレ(3) は addr=base+imm そのもの。
    if idx == 1 {
        let wb = b.add(base, io);
        write(b, rn, wb, true);
    } else if idx == 3 {
        write(b, rn, addr, true);
    }
    Ok(())
}

/// 排他ロード。
pub fn ldxr<B: Backend>(b: &mut B, rt: Gpr, rn: Gpr, size: u32, endian: Endian) -> Flow<B> {
    let addr = read(b, rn, true);
    let acc = lr_acc(endian);
    match size {
        1 => {
            let v: B::V<W8> = b.load_reserved(addr, acc)?;
            let e = b.zext::<W8, W32>(v);
            write_w(b, rt, e, false);
        }
        2 => {
            let v: B::V<W16> = b.load_reserved(addr, acc)?;
            let e = b.zext::<W16, W32>(v);
            write_w(b, rt, e, false);
        }
        4 => {
            let v: B::V<W32> = b.load_reserved(addr, acc)?;
            write_w(b, rt, v, false);
        }
        _ => {
            let v: B::V<W64> = b.load_reserved(addr, acc)?;
            write(b, rt, v, false);
        }
    }
    Ok(())
}

/// 排他ストア。成功すると rs に 0 を書く。
pub fn stxr<B: Backend>(
    b: &mut B,
    rs: Gpr,
    rt: Gpr,
    rn: Gpr,
    size: u32,
    endian: Endian,
) -> Flow<B> {
    let addr = read(b, rn, true);
    let acc = sc_acc(endian);
    let v = read(b, rt, false);
    let ok = match size {
        1 => {
            let t = b.trunc::<W64, W8>(v);
            b.store_conditional(addr, t, acc)?
        }
        2 => {
            let t = b.trunc::<W64, W16>(v);
            b.store_conditional(addr, t, acc)?
        }
        4 => {
            let t = b.trunc::<W64, W32>(v);
            b.store_conditional(addr, t, acc)?
        }
        _ => b.store_conditional(addr, v, acc)?,
    };
    let z0 = k32(b, 0);
    let o1 = k32(b, 1);
    let code = b.select::<W32>(ok, z0, o1);
    write_w(b, rs, code, false);
    Ok(())
}

// ---- FP/SIMD ----

/// FP/SIMD レジスタ v0〜v31。B/H/S/D/Q は値の下位ビットに対応し、
/// 書き込みはレジスタ全体を置き換える（スカラー書き込みの上位ゼロ規則）。
fn vref(r: u8) -> StateRef<W128> {
    StateRef::<W128>::from_offset(core::mem::offset_of!(CpuState, v) + usize::from(r) * 16)
}

/// FP/SIMD 単一ロード。size バイトを読み、上位は 0 で埋める。
fn vdo_load<B: Backend>(b: &mut B, vt: u8, addr: B::V<W64>, size: u32, endian: Endian) -> Flow<B> {
    let acc = data_read(endian);
    let v: B::V<W128> = match size {
        1 => {
            let t: B::V<W8> = b.load(addr, acc)?;
            b.zext::<W8, W128>(t)
        }
        2 => {
            let t: B::V<W16> = b.load(addr, acc)?;
            b.zext::<W16, W128>(t)
        }
        4 => {
            let t: B::V<W32> = b.load(addr, acc)?;
            b.zext::<W32, W128>(t)
        }
        8 => {
            let t: B::V<W64> = b.load(addr, acc)?;
            b.zext::<W64, W128>(t)
        }
        _ => b.load(addr, acc)?,
    };
    b.set(vref(vt), v);
    Ok(())
}

/// FP/SIMD 単一ストア。レジスタの下位 size バイトを書く。
fn vdo_store<B: Backend>(b: &mut B, vt: u8, addr: B::V<W64>, size: u32, endian: Endian) -> Flow<B> {
    let acc = data_write(endian);
    let v: B::V<W128> = b.get(vref(vt));
    b.probe(addr, size, acc)?;
    match size {
        1 => {
            let t = b.trunc::<W128, W8>(v);
            b.store(addr, t, acc)?
        }
        2 => {
            let t = b.trunc::<W128, W16>(v);
            b.store(addr, t, acc)?
        }
        4 => {
            let t = b.trunc::<W128, W32>(v);
            b.store(addr, t, acc)?
        }
        8 => {
            let t = b.trunc::<W128, W64>(v);
            b.store(addr, t, acc)?
        }
        _ => b.store(addr, v, acc)?,
    }
    Ok(())
}

/// FP/SIMD unsigned 即値ロード/ストア。`imm` はスケール済み。
pub fn vls_unsigned<B: Backend>(
    b: &mut B,
    rt: u8,
    rn: Gpr,
    imm: i64,
    size: u32,
    store: bool,
    endian: Endian,
) -> Flow<B> {
    let addr = addr_of(b, rn, imm);
    if store {
        vdo_store(b, rt, addr, size, endian)
    } else {
        vdo_load(b, rt, addr, size, endian)
    }
}

/// FP/SIMD imm9 ロード/ストア。mode: 0=unscaled, 1=post, 3=pre。
#[allow(clippy::too_many_arguments)]
pub fn vls_imm9<B: Backend>(
    b: &mut B,
    rt: u8,
    rn: Gpr,
    imm: i64,
    size: u32,
    store: bool,
    mode: u32,
    endian: Endian,
) -> Flow<B> {
    let base = read(b, rn, true);
    match mode {
        1 => {
            let res = if store {
                vdo_store(b, rt, base, size, endian)
            } else {
                vdo_load(b, rt, base, size, endian)
            };
            let cur = read(b, rn, true);
            let o = k64(b, imm as u64);
            let nb = b.add(cur, o);
            write(b, rn, nb, true);
            res
        }
        3 => {
            let o = k64(b, imm as u64);
            let addr = b.add(base, o);
            write(b, rn, addr, true);
            if store {
                vdo_store(b, rt, addr, size, endian)
            } else {
                vdo_load(b, rt, addr, size, endian)
            }
        }
        _ => {
            let o = k64(b, imm as u64);
            let addr = b.add(base, o);
            if store {
                vdo_store(b, rt, addr, size, endian)
            } else {
                vdo_load(b, rt, addr, size, endian)
            }
        }
    }
}

/// FP/SIMD ペアロード/ストア。idx: 1=post,2=off,3=pre。
#[allow(clippy::too_many_arguments)]
pub fn vls_pair<B: Backend>(
    b: &mut B,
    rt: u8,
    rt2: u8,
    rn: Gpr,
    imm: i64,
    size: u32,
    store: bool,
    idx: u32,
    endian: Endian,
) -> Flow<B> {
    let base = read(b, rn, true);
    let io = k64(b, imm as u64);
    let addr = if idx == 1 { base } else { b.add(base, io) };
    if store {
        b.probe(addr, size * 2, data_write(endian))?;
    }
    if store {
        vdo_store(b, rt, addr, size, endian)?;
    } else {
        vdo_load(b, rt, addr, size, endian)?;
    }
    let sz = k64(b, u64::from(size));
    let a2 = b.add(addr, sz);
    if store {
        vdo_store(b, rt2, a2, size, endian)?;
    } else {
        vdo_load(b, rt2, a2, size, endian)?;
    }
    if idx == 1 {
        let wb = b.add(base, io);
        write(b, rn, wb, true);
    } else if idx == 3 {
        write(b, rn, addr, true);
    }
    Ok(())
}

/// DUP（汎用レジスタ → 全レーン）。`esz` は log2(要素バイト数)（0=B,1=H,2=S,3=D）。
/// `q` が真なら 128 ビット分、偽なら下位 64 ビット分だけ複製する。
/// Ref: SPEC-ARM-ARM-A の DUP (general register)。
pub fn vdup_gpr<B: Backend>(b: &mut B, rd: u8, rn: Gpr, esz: u32, q: bool) -> Flow<B> {
    let ebits = 8u32 << esz;
    let lanes = if q { 128 } else { 64 } / ebits;
    let g = read(b, rn, false);
    let e = b.zext::<W64, W128>(g);
    let m = b.konst::<W128>((1u128 << ebits) - 1);
    let mut v = b.and(e, m);
    for i in 1..lanes {
        let sh = b.konst::<W128>(u128::from(i * ebits));
        let y = b.shl(v, sh);
        v = b.or(v, y);
    }
    b.set(vref(rd), v);
    Ok(())
}

/// UMOV（レーン → 汎用、ゼロ拡張）。`mov Wd/Xd, Vn.T[i]` の別名。
/// Ref: SPEC-ARM-ARM-A の UMOV。
pub fn vext_gpr<B: Backend>(b: &mut B, rd: Gpr, rn: u8, esz: u32, idx: u32) -> Flow<B> {
    let ebits = 8u32 << esz;
    let v: B::V<W128> = b.get(vref(rn));
    let sh = b.konst::<W128>(u128::from(idx * ebits));
    let x = b.shr_l::<W128>(v, sh);
    let m = b.konst::<W128>((1u128 << ebits) - 1);
    let x = b.and(x, m);
    let x64 = b.trunc::<W128, W64>(x);
    write(b, rd, x64, false);
    Ok(())
}

/// INS（汎用 → レーン）。`mov Vd.T[i], Rn` の別名。
/// Ref: SPEC-ARM-ARM-A の INS (general register)。
pub fn vins_gpr<B: Backend>(b: &mut B, rd: u8, rn: Gpr, esz: u32, idx: u32) -> Flow<B> {
    let ebits = 8u32 << esz;
    let lane: u128 = ((1u128 << ebits) - 1) << (idx * ebits);
    let cur: B::V<W128> = b.get(vref(rd));
    let nm = b.konst::<W128>(!lane);
    let v0 = b.and(cur, nm);
    let g = read(b, rn, false);
    let e = b.zext::<W64, W128>(g);
    let em = b.konst::<W128>((1u128 << ebits) - 1);
    let e = b.and(e, em);
    let sh = b.konst::<W128>(u128::from(idx * ebits));
    let e = b.shl(e, sh);
    let v = b.or(v0, e);
    b.set(vref(rd), v);
    Ok(())
}

/// FMOV（汎用 → FP/SIMD レジスタ）。`bits` は転送幅（32/64）。
/// `hi` が真なら V の上位 64 ビット（D[1]）を書き、下位を保持する。
/// スカラー S/D への書き込みは上位ビットを 0 にする。
pub fn fmov_to_v<B: Backend>(b: &mut B, rd: u8, rn: Gpr, bits: u32, hi: bool) -> Flow<B> {
    let g = read(b, rn, false);
    let e = b.zext::<W64, W128>(g);
    let e = if bits == 32 {
        let m = b.konst::<W128>(0xffff_ffff);
        b.and(e, m)
    } else {
        e
    };
    let v = if hi {
        let cur: B::V<W128> = b.get(vref(rd));
        let keep = b.konst::<W128>(0xffff_ffff_ffff_ffff);
        let lo = b.and(cur, keep);
        let sh = b.konst::<W128>(64);
        let e2 = b.shl(e, sh);
        b.or(lo, e2)
    } else {
        e
    };
    b.set(vref(rd), v);
    Ok(())
}

/// AdvSIMD 修飾即値（MOVI/MVNI/ORR/BIC の即値形式）。`cmode` が要素幅と
/// 操作を選ぶ。`op` は movi/orr なら偽、mvni/bic なら真。`q` 偽は 64 ビット。
/// cmode 12（shifting ones）と 15（fmov 即値）は未実装で Undefined を返す。
/// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM) AdvSIMDExpandImm。
pub fn mod_imm<B: Backend>(b: &mut B, rd: u8, q: bool, op: bool, cmode: u32, imm8: u64) -> Flow<B> {
    // (要素ビット幅, imm8 の左シフト量, 合成方法 0=上書き, 1=orr, 2=bic)
    let (ebits, shift, acc) = match cmode {
        0..=3 => (32u32, 8 * cmode, 0u32),
        4..=7 => (32, 8 * (cmode - 4), if op { 2 } else { 1 }),
        8 | 9 => (16, 8 * (cmode - 8), 0),
        10 | 11 => (16, 8 * (cmode - 10), if op { 2 } else { 1 }),
        13 => (8, 0, 0),
        14 => (8, 0, if op { 2 } else { 1 }),
        _ => {
            return Err(b.raise(GuestException {
                kind: ExceptionKind::Undefined,
                code: u64::from(cmode),
                addr: None,
                in_delay_slot: false,
            }));
        }
    };
    let lane_mask = (1u128 << ebits) - 1;
    let mut lane = u128::from(imm8) << shift;
    if acc == 0 && op {
        lane = !lane;
    }
    lane &= lane_mask;
    // レーンを全要素分だけ繰り返す。
    let mut pat = 0u128;
    let mut off = 0u32;
    while off < 128 {
        pat |= lane << off;
        off += ebits;
    }
    let low64 = b.konst::<W128>(u128::from(u64::MAX));
    let p = b.konst::<W128>(pat);
    let v = match acc {
        1 | 2 => {
            let cur: B::V<W128> = b.get(vref(rd));
            let cur = if q { cur } else { b.and(cur, low64) };
            if acc == 1 {
                b.or(cur, p)
            } else {
                let np = b.not(p);
                b.and(cur, np)
            }
        }
        _ => p,
    };
    let v = if q { v } else { b.and(v, low64) };
    b.set(vref(rd), v);
    Ok(())
}

/// FMOV（FP/SIMD → 汎用）。`hi` が真なら V の上位 64 ビットを読む。
/// Wd 宛ては下位 32 ビットのゼロ拡張。
pub fn fmov_to_g<B: Backend>(b: &mut B, rd: Gpr, rn: u8, is64: bool, hi: bool) -> Flow<B> {
    let v: B::V<W128> = b.get(vref(rn));
    let x = if hi {
        let sh = b.konst::<W128>(64);
        b.shr_l::<W128>(v, sh)
    } else {
        v
    };
    let x64 = b.trunc::<W128, W64>(x);
    if is64 {
        write(b, rd, x64, false);
    } else {
        let t = b.trunc::<W64, W32>(x64);
        write_w(b, rd, t, false);
    }
    Ok(())
}
