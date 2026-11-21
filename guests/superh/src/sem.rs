// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH の命令意味論。
//!
//! 段階18-6（SH4 行）で実行ループが必要とする最小集合から、整数の
//! 全基本語彙を実装した:
//! - 転送: `mov` の全 16 ビット形式（レジスタ・即値・間接・前後
//!   インクリメント・インデックス・disp4・GBR・PC 相対）と
//!   SH-2A の disp12 系・`movi20`/`movi20s`・`movu.*`・`movua.l`・
//!   `movml`/`movmu`、`mova`/`movt`/`movrt`/`swap`/`xtrct`/
//!   `ext[us]`/`nott`
//! - 算術: `add`/`addc`/`addv`/`sub`/`subc`/`subv`/`neg`/`negc`/
//!   `cmp` 系/`dt`、`muls`/`mulu`/`mul.l`/`dmuls`/`dmulu`/
//!   `mac.w`/`mac.l`/`clrmac`、`div0s`/`div0u`/`div1`、
//!   SH-2A の `divs`/`divu`/`mulr`/`clips`/`clipu`
//! - 論理・ビット: `and`/`or`/`xor`/`not`/`tst`/`tas.b` と SH-2A の
//!   `bclr`/`bst`/`bld`/`band`/`bor`/`bxor`/`b*not`（レジスタ・
//!   メモリ両形式）
//! - シフト: `shl/shr` 系、`rot` 系、動的 `shad`/`shld`
//! - 分岐: `bra`/`bsr`/`braf`/`bsrf`/`bf`/`bt`/`bf.s`/`bt.s`/
//!   `jmp`/`jsr`/`rts` と SH-2A の非遅延 `rts/n`/`rtv/n`/`jsr/n`。
//!   遅延スロット自体の実行は `run_superh` 側（分岐は `Ctrl::Jump`
//!   として報告するだけ）
//! - 制御: `ldc`/`stc`/`lds`/`sts`（SR/GBR/VBR/SSR/SPC/SGR/DBR/
//!   TBR/R_BANK と MACH/MACL/PR/FPSCR/FPUL）、`clrt`/`sett`/
//!   `clrs`/`sets`
//! - トラップ・同期: `trapa`、SH-4A の `movli`/`movco`、J-core の
//!   `cas.l`
//! - `sleep`/`rte`/`ldtlb`/`resbank` は特権例外として Trap。
//!   `pref`/`ocb*`/`icbi`/`prefi`/`synco` はキャッシュ系で、
//!   このモデルでは no-op。`movca` は 32B アラインのストア。
//! - FP: `fmov.s` 系（間接・前後インクリメント・R0 インデックス・
//!   SH-2A disp12）、`fmov`、単/倍精度（FPSCR.PR）の `fadd`/`fsub`/
//!   `fmul`/`fdiv`/`fcmp`/`fmac`/`fneg`/`fabs`/`fsqrt`/`fldi`、
//!   FPUL との `fsts`/`flds`/`float`/`ftrc`。FPSCR.SZ の対転送、
//!   FPSCR.FR の FR/XF 切替、FSCA/FSRRA/FIPR/FTRV/FRCHG/FPCHG/
//!   FSCHG/FCNVDS/FCNVSD も実装済み。特殊関数は数値近似
//!   （Gap: GAP-0059）。
//!
//! 遅延スロットの扱い: SH の遅延分岐は `bra`/`bsr`/`jmp`/`jsr`/
//! `rts`/`braf`/`bsrf`/`bf.s`/`bt.s` で、スロット（`pc+2`）は常に
//! 実行される（annul は無い）。`bf`/`bt` は遅延スロットを持たない。
//! 遅延スロット中の分岐は slot-illegal で、`run_superh` が `Insn`
//! を見て `Unimplemented` に畳む。
//! Ref: SPEC-SUPERH-SH2, SPEC-SUPERH-SH3, SPEC-SUPERH-SH4,
//! SPEC-SUPERH-SH2A, SPEC-SUPERH-SH4A, SPEC-SUPERH-JCORE.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{
    Backend, Cmp, ExceptionKind, F32, F64, GuestException, StateRef, W8, W16, W32, W64,
};

use super::{CpuState, Insn, extract_ops};

/// 汎用レジスタ参照。SH の R0-R15 は全て通常の読み書きレジスタ
/// （SH にはゼロ結線のレジスタはない）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct R(pub u8);

impl R {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, r) + (self.0 as usize) * 4)
    }

    /// 読み出し。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W32> {
        b.get(self.state())
    }

    /// 書き込み。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W32>) {
        b.set(self.state(), v);
    }
}

/// SR のビット。ユーザ面で立つ T/S/IMASK/Q/M/FD/RC/BL/RB/MD。
/// Ref: SPEC-SUPERH-SH4 §2.4.
pub const SR_T: u32 = 0x1;
pub const SR_S: u32 = 0x2;
pub const SR_IMASK: u32 = 0xf0;
pub const SR_Q: u32 = 0x100;
pub const SR_M: u32 = 0x200;
pub const SR_FD: u32 = 0x8000;
pub const SR_RC: u32 = 0x0fff_0000;
pub const SR_BL: u32 = 0x1000_0000;
pub const SR_RB: u32 = 0x2000_0000;
pub const SR_MD: u32 = 0x4000_0000;

/// FPSCR のビット。RM(0-1)・DN(18)・PR(19)・SZ(20)・FR(21)。
/// PR=倍精度モード、SZ=対転送モード、FR=FP バンク選択。
/// Ref: SPEC-SUPERH-SH4 §6（FPSCR 構成）.
pub const FPSCR_RM: u32 = 0x3;
pub const FPSCR_DN: u32 = 0x4_0000;
pub const FPSCR_PR: u32 = 0x8_0000;
pub const FPSCR_SZ: u32 = 0x10_0000;
pub const FPSCR_FR: u32 = 0x20_0000;

/// Trap コード（`handle_trap` に渡る内部番号）。
/// `trapa` は即値をそのまま code に載せる。
pub const TRAP_PRIV: u64 = 3;
/// 遅延スロット内の分岐（slot-illegal）など不正命令。
pub const TRAP_ILL: u64 = 4;

/// CPU 状態の位置たち。
#[must_use]
pub fn pc_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pc))
}

#[must_use]
pub fn pr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, pr))
}

#[must_use]
pub fn sr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, sr))
}

#[must_use]
pub fn gbr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, gbr))
}

#[must_use]
pub fn vbr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, vbr))
}

#[must_use]
pub fn mach_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, mach))
}

#[must_use]
pub fn macl_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, macl))
}

#[must_use]
pub fn fpul_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, fpul))
}

#[must_use]
pub fn fpscr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, fpscr))
}

#[must_use]
pub fn sgr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, sgr))
}

#[must_use]
pub fn ssr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, ssr))
}

#[must_use]
pub fn spc_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, spc))
}

#[must_use]
pub fn dbr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, dbr))
}

#[must_use]
pub fn tbr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, tbr))
}

/// SH-4 の R_BANK の位置。
#[must_use]
pub fn rbank_ref(i: u8) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, rbank) + (i as usize) * 4)
}

/// FR の位置。
#[must_use]
pub fn fr_ref(i: u8) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, fr) + (i as usize) * 4)
}

/// XF の位置。
#[must_use]
pub fn xf_ref(i: u8) -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, xf) + (i as usize) * 4)
}

// ----------------------------------------------------------------
// V<u32>/V<u64> の定数・演算ヘルパ（`b.` 呼出は全て文単位で行い、
// 引数への入れ子を避ける）
// ----------------------------------------------------------------

fn k<B: Backend>(b: &mut B, v: u64) -> B::V<W32> {
    b.konst::<W32>(v as u32)
}

fn k64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

fn rget<B: Backend>(b: &mut B, i: u64) -> B::V<W32> {
    R(i as u8).get(b)
}

fn rset<B: Backend>(b: &mut B, i: u64, v: B::V<W32>) {
    R(i as u8).set(b, v);
}

fn and_n<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let c = k(b, u64::from(n));
    b.and(x, c)
}

fn or_n<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let c = k(b, u64::from(n));
    b.or(x, c)
}

fn add_n<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let c = k(b, u64::from(n));
    b.add(x, c)
}

fn sub_n<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let c = k(b, u64::from(n));
    b.sub(x, c)
}

fn shl_n<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let c = k(b, u64::from(n));
    b.shl(x, c)
}

fn shr_n<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let c = k(b, u64::from(n));
    b.shr_l(x, c)
}

fn sra_n<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let c = k(b, u64::from(n));
    b.shr_a(x, c)
}

/// `bits` ビット符号拡張。
fn sext_bits<B: Backend>(b: &mut B, x: B::V<W32>, bits: u32) -> B::V<W32> {
    let t = shl_n(b, x, 32 - bits);
    sra_n(b, t, 32 - bits)
}

/// `B::B` を V<u32> の 0/1 にする。
fn bval<B: Backend>(b: &mut B, c: B::B) -> B::V<W32> {
    let zero = k(b, 0);
    let one = k(b, 1);
    b.select::<W32>(c, one, zero)
}

/// `B::B` の否定。
fn bnot<B: Backend>(b: &mut B, c: B::B) -> B::B {
    let zero = k(b, 0);
    let one = k(b, 1);
    let v = b.select::<W32>(c, zero, one);
    b.cmp(Cmp::Ne, v, zero)
}

/// `c ? t : f`。
fn selv<B: Backend>(b: &mut B, c: B::B, t: B::V<W32>, f: B::V<W32>) -> B::V<W32> {
    b.select::<W32>(c, t, f)
}

// ----------------------------------------------------------------
// SR の T/S/Q/M
// ----------------------------------------------------------------

fn get_sr<B: Backend>(b: &mut B) -> B::V<W32> {
    b.get(sr_ref())
}

fn set_sr<B: Backend>(b: &mut B, v: B::V<W32>) {
    b.set(sr_ref(), v);
}

/// `mask` のビットを LSB 起算で読む（単一ビットのフラグ用）。
fn get_flag<B: Backend>(b: &mut B, mask: u32) -> B::V<W32> {
    let sr = get_sr(b);
    let m = and_n(b, sr, mask);
    shr_n(b, m, mask.trailing_zeros())
}

/// `mask` の最下位位置に `v`（0/1）を書く。
fn set_flag<B: Backend>(b: &mut B, mask: u32, v: B::V<W32>) {
    let sr = get_sr(b);
    let sr = and_n(b, sr, !mask);
    let vv = and_n(b, v, 1);
    let vv = shl_n(b, vv, mask.trailing_zeros());
    let sr = b.or(sr, vv);
    set_sr(b, sr);
}

fn get_t<B: Backend>(b: &mut B) -> B::V<W32> {
    get_flag(b, SR_T)
}

fn set_t<B: Backend>(b: &mut B, v: B::V<W32>) {
    set_flag(b, SR_T, v);
}

/// T に比較結果を書く。
fn set_t_cmp<B: Backend>(b: &mut B, c: B::B) {
    let v = bval(b, c);
    set_t(b, v);
}

// ----------------------------------------------------------------
// FPSCR と FP レジスタバンク
// ----------------------------------------------------------------

fn get_fpscr<B: Backend>(b: &mut B) -> B::V<W32> {
    b.get(fpscr_ref())
}

/// `mask` の FPSCR ビットを 0/1 で読む。
fn get_fpscr_bit<B: Backend>(b: &mut B, mask: u32) -> B::V<W32> {
    let v = get_fpscr(b);
    let m = and_n(b, v, mask);
    shr_n(b, m, mask.trailing_zeros())
}

/// `mask` の FPSCR ビットに `v`（0/1）を書く。
fn set_fpscr_bit<B: Backend>(b: &mut B, mask: u32, v: B::V<W32>) {
    let f = get_fpscr(b);
    let f = and_n(b, f, !mask);
    let vv = and_n(b, v, 1);
    let vv = shl_n(b, vv, mask.trailing_zeros());
    let f = b.or(f, vv);
    b.set(fpscr_ref(), f);
}

/// 建築上の FRn の読み出し。FPSCR.FR=0 は fr[]、1 は xf[] を指す。
/// Ref: SPEC-SUPERH-SH4 §6（FR バンク選択）.
fn afr_get<B: Backend>(b: &mut B, i: u64) -> B::V<W32> {
    let sel = get_fpscr_bit(b, FPSCR_FR);
    let a = b.get(fr_ref(i as u8));
    let x = b.get(xf_ref(i as u8));
    let zz = k(b, 0);
    let s = b.cmp(Cmp::Ne, sel, zz);
    selv(b, s, x, a)
}

/// 建築上の FRn への書き込み（`if_then_else` の Exit が伝搬する）。
fn afr_set<B: Backend>(b: &mut B, i: u64, v: B::V<W32>) -> Result<(), B::Exit> {
    let sel = get_fpscr_bit(b, FPSCR_FR);
    let zz = k(b, 0);
    let s = b.cmp(Cmp::Ne, sel, zz);
    b.if_then_else(
        s,
        |b| {
            b.set(xf_ref(i as u8), v);
            Ok(())
        },
        |b| {
            b.set(fr_ref(i as u8), v);
            Ok(())
        },
    )
}

/// 建築上の XDn（FR バンクと逆の側）の読み出し。FTRV の行列バンク。
fn axd_get<B: Backend>(b: &mut B, i: u64) -> B::V<W32> {
    let sel = get_fpscr_bit(b, FPSCR_FR);
    let a = b.get(fr_ref(i as u8));
    let x = b.get(xf_ref(i as u8));
    let zz = k(b, 0);
    let s = b.cmp(Cmp::Ne, sel, zz);
    selv(b, s, a, x)
}

/// DR ペアを F64 のビット列にする。DRn = FR[n]（上位）:FR[n+1]（下位）、
/// `i` は偶数のペア基底（`n & 14`）。
/// Ref: SPEC-SUPERH-SH4 §6（DR レジスタ）.
fn dr_get<B: Backend>(b: &mut B, i: u64) -> B::V<F64> {
    let hi = afr_get(b, i);
    let lo = afr_get(b, i + 1);
    let h64 = b.zext::<W32, W64>(hi);
    let l64 = b.zext::<W32, W64>(lo);
    let c32 = k64(b, 32);
    let hs = b.shl(h64, c32);
    let w = b.or(hs, l64);
    b.trunc::<W64, F64>(w)
}

/// F64 ビット列を DR ペアに書く。
fn dr_set<B: Backend>(b: &mut B, i: u64, v: B::V<F64>) -> Result<(), B::Exit> {
    let w: B::V<W64> = b.trunc::<F64, W64>(v);
    let c32 = k64(b, 32);
    let hs = b.shr_l(w, c32);
    let hi = b.trunc::<W64, W32>(hs);
    let lo = b.trunc::<W64, W32>(w);
    afr_set(b, i, hi)?;
    afr_set(b, i + 1, lo)
}

/// `c` が非ゼロか（V32 の真偽値化）。
fn nz<B: Backend>(b: &mut B, v: B::V<W32>) -> B::B {
    let zz = k(b, 0);
    b.cmp(Cmp::Ne, v, zz)
}

/// f32 ビット列の定数。
fn kf<B: Backend>(b: &mut B, bits: u32) -> B::V<F32> {
    b.konst::<F32>(bits)
}

/// FVn（FR バンクの 4 連）の i 番目を f32 で読む。
fn fv_get<B: Backend>(b: &mut B, base: u64, i: u64) -> B::V<F32> {
    let w = afr_get(b, base + i);
    b.trunc(w)
}

/// 2 語ロードの結果（SZ=1 の対転送。上位語・下位語）。
type Word2<B> = (<B as Backend>::V<W32>, <B as Backend>::V<W32>);

/// 2 語ロード（SZ=1 の対転送。ea/ea+4）。
fn load2<B: Backend>(b: &mut B, ea: B::V<W32>, endian: Endian) -> Result<Word2<B>, B::Exit> {
    let hi = load_s(b, ea, 4, false, endian)?;
    let ea2 = add_n(b, ea, 4);
    let lo = load_s(b, ea2, 4, false, endian)?;
    Ok((hi, lo))
}

// ----------------------------------------------------------------
// メモリアクセスの属性
// ----------------------------------------------------------------

// データアクセスの整列属性は Unaligned にする。SH-4 Linux の
// カーネルはユーザの非整列アクセスを unaligned fixup で透過的に
// 処理し、glibc の SH-4 memcpy/memset 系はこれを前提に非整列の
// mov.l を使う。整列例外の検出はこのモデルの対象外。
// Ref: SRC-LINUX — arch/sh/kernel/traps.c（unaligned fixup）.
fn data_read(endian: Endian) -> Access {
    Access {
        endian,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    }
}

fn data_write(endian: Endian) -> Access {
    Access {
        endian,
        align: Align::Unaligned,
        kind: AccessKind::DataWrite,
    }
}

/// `movli`/`movco` と `cas.l` の不可分アクセス。
fn atomic_rw(endian: Endian) -> Access {
    Access {
        endian,
        align: Align::Natural,
        kind: AccessKind::AtomicRw,
    }
}

/// 例外を投げる。
fn raise<B: Backend>(b: &mut B, kind: ExceptionKind, code: u64) -> B::Exit {
    b.raise(GuestException {
        kind,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

// ----------------------------------------------------------------
// 意味論の部品
// ----------------------------------------------------------------

/// `v`（W32）を W64 に 0 拡張してメモリ番地にする。
fn ea64<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W64> {
    b.zext::<W32, W64>(v)
}

/// サイズ `size`（1/2/4）のロード（`sign` で符号拡張）。
fn load_s<B: Backend>(
    b: &mut B,
    ea: B::V<W32>,
    size: u32,
    sign: bool,
    endian: Endian,
) -> Result<B::V<W32>, B::Exit> {
    let a = ea64(b, ea);
    let v = match size {
        1 => {
            let v: B::V<W8> = b.load(a, data_read(endian))?;
            if sign {
                b.sext::<W8, W32>(v)
            } else {
                b.zext::<W8, W32>(v)
            }
        }
        2 => {
            let v: B::V<W16> = b.load(a, data_read(endian))?;
            if sign {
                b.sext::<W16, W32>(v)
            } else {
                b.zext::<W16, W32>(v)
            }
        }
        _ => {
            let v: B::V<W32> = b.load(a, data_read(endian))?;
            v
        }
    };
    Ok(v)
}

/// サイズ `size` のストア。
fn store_s<B: Backend>(
    b: &mut B,
    ea: B::V<W32>,
    v: B::V<W32>,
    size: u32,
    endian: Endian,
) -> Result<(), B::Exit> {
    let a = ea64(b, ea);
    match size {
        1 => {
            let t: B::V<W8> = b.trunc::<W32, W8>(v);
            b.store::<W8>(a, t, data_write(endian))
        }
        2 => {
            let t: B::V<W16> = b.trunc::<W32, W16>(v);
            b.store::<W16>(a, t, data_write(endian))
        }
        _ => b.store::<W32>(a, v, data_write(endian)),
    }
}

/// pc+disp*2 の 32 ビット折返し（SH の分岐ターゲット規則。
/// ターゲット = pc + 4 + sext(disp)*2。pc は分岐命令の番地）。
// Ref: SPEC-SUPERH-SH2 §6.4（分岐先計算）.
fn rel_target(pc: u64, disp: i64) -> u64 {
    pc.wrapping_add(4).wrapping_add(disp.wrapping_mul(2) as u64) & 0xffff_ffff
}

/// `t` を W64 の分岐ターゲットにする。
fn jump32<B: Backend>(b: &mut B, t: B::V<W32>) {
    let a = ea64(b, t);
    b.jump(a);
}

/// フィールド値の符号拡張（ホスト側計算）。
fn sext(v: u64, bits: u32) -> i64 {
    let sh = 64 - bits;
    ((v << sh) as i64) >> sh
}

/// MAC（mach:macl の 64 ビット）に `p`（W64）を足す。
/// S ビットの飽和は段階18 の範囲外（Gap: GAP-0059）。
fn mac_add<B: Backend>(b: &mut B, p: B::V<W64>) {
    let hi = b.get(mach_ref());
    let lo = b.get(macl_ref());
    let c32 = k64(b, 32);
    let h = b.zext::<W32, W64>(hi);
    let l = b.zext::<W32, W64>(lo);
    let hsh = b.shl(h, c32);
    let cur = b.or(hsh, l);
    let sum = b.add(cur, p);
    let c32b = k64(b, 32);
    let s_hi = b.shr_l(sum, c32b);
    let new_hi = b.trunc::<W64, W32>(s_hi);
    let new_lo = b.trunc::<W64, W32>(sum);
    b.set(mach_ref(), new_hi);
    b.set(macl_ref(), new_lo);
}

// ----------------------------------------------------------------
// エントリ
// ----------------------------------------------------------------

/// 命令 1 個の実行。`word` は 16 ビット命令ならその語、
/// SH-2A の 32 ビット命令なら先頭パーセルを上位に置いた 32 ビット語。
/// `Ok(true)` = 実行した、`Ok(false)` = 未実装（呼び出し側の
/// `handle_unimpl` 経路へ）。`pc` は命令番地。
/// `endian` はデータアクセスのエンディアン。
#[allow(clippy::too_many_lines)]
pub fn exec<B: Backend>(
    b: &mut B,
    insn: Insn,
    word: u32,
    pc: u64,
    endian: Endian,
) -> Result<bool, B::Exit> {
    let ops = extract_ops(insn, u128::from(word));
    match insn {
        // ---- 転送 ----
        Insn::MovImm => {
            let v = k(b, sext(ops[1], 8) as u64 & 0xffff_ffff);
            rset(b, ops[0], v);
        }
        Insn::MovReg => {
            let v = rget(b, ops[1]);
            rset(b, ops[0], v);
        }
        Insn::MovWPcl | Insn::MovLPcl => {
            let size = if insn == Insn::MovWPcl { 2 } else { 4 };
            let base = if size == 2 {
                pc.wrapping_add(4)
            } else {
                pc.wrapping_add(4) & !3
            };
            let ea = k(b, base.wrapping_add(ops[1] * u64::from(size)) & 0xffff_ffff);
            let v = load_s(b, ea, size, true, endian)?;
            rset(b, ops[0], v);
        }
        Insn::MovBLd | Insn::MovWLd | Insn::MovLLd => {
            let size = match insn {
                Insn::MovBLd => 1,
                Insn::MovWLd => 2,
                _ => 4,
            };
            let ea = rget(b, ops[1]);
            let v = load_s(b, ea, size, true, endian)?;
            rset(b, ops[0], v);
        }
        Insn::MovBLdp | Insn::MovWLdp | Insn::MovLLdp => {
            let size = match insn {
                Insn::MovBLdp => 1,
                Insn::MovWLdp => 2,
                _ => 4,
            };
            let m = ops[1] as u8;
            let ea = R(m).get(b);
            let v = load_s(b, ea, size, true, endian)?;
            // @Rm+,Rn の事後更新。m==n のときロード結果が優先される
            // （SH の規約）。Ref: SPEC-SUPERH-SH2 §6.2.
            if ops[0] as u8 != m {
                let inc = add_n(b, ea, size);
                R(m).set(b, inc);
            }
            rset(b, ops[0], v);
        }
        Insn::MovBSt | Insn::MovWSt | Insn::MovLSt => {
            let size = match insn {
                Insn::MovBSt => 1,
                Insn::MovWSt => 2,
                _ => 4,
            };
            let ea = rget(b, ops[0]);
            let v = rget(b, ops[1]);
            store_s(b, ea, v, size, endian)?;
        }
        Insn::MovBStp | Insn::MovWStp | Insn::MovLStp => {
            let size = match insn {
                Insn::MovBStp => 1,
                Insn::MovWStp => 2,
                _ => 4,
            };
            let n = ops[0] as u8;
            let ea_src = R(n).get(b);
            let ea = sub_n(b, ea_src, size);
            R(n).set(b, ea);
            let v = rget(b, ops[1]);
            store_s(b, ea, v, size, endian)?;
        }
        Insn::MovBIdxLd | Insn::MovWIdxLd | Insn::MovLIdxLd => {
            let size = match insn {
                Insn::MovBIdxLd => 1,
                Insn::MovWIdxLd => 2,
                _ => 4,
            };
            let base = rget(b, ops[1]);
            let i0 = R(0).get(b);
            let ea = b.add(base, i0);
            let v = load_s(b, ea, size, true, endian)?;
            rset(b, ops[0], v);
        }
        Insn::MovBIdxSt | Insn::MovWIdxSt | Insn::MovLIdxSt => {
            let size = match insn {
                Insn::MovBIdxSt => 1,
                Insn::MovWIdxSt => 2,
                _ => 4,
            };
            let base = rget(b, ops[0]);
            let i0 = R(0).get(b);
            let ea = b.add(base, i0);
            let v = rget(b, ops[1]);
            store_s(b, ea, v, size, endian)?;
        }
        Insn::MovBR0St | Insn::MovWR0St => {
            let size = if insn == Insn::MovBR0St { 1 } else { 2 };
            let base = rget(b, ops[0]);
            let ea = add_n(b, base, ops[1] as u32 * size);
            let v = R(0).get(b);
            store_s(b, ea, v, size, endian)?;
        }
        Insn::MovBR0Ld | Insn::MovWR0Ld => {
            let size = if insn == Insn::MovBR0Ld { 1 } else { 2 };
            let base = rget(b, ops[0]);
            let ea = add_n(b, base, ops[1] as u32 * size);
            let v = load_s(b, ea, size, true, endian)?;
            R(0).set(b, v);
        }
        Insn::MovLStD | Insn::MovLLdD => {
            let base_i = if insn == Insn::MovLStD { 0 } else { 1 };
            let base = rget(b, ops[base_i]);
            let ea = add_n(b, base, ops[2] as u32 * 4);
            if insn == Insn::MovLStD {
                let v = rget(b, ops[1]);
                store_s(b, ea, v, 4, endian)?;
            } else {
                let v = load_s(b, ea, 4, true, endian)?;
                rset(b, ops[0], v);
            }
        }
        Insn::MovBGbrSt | Insn::MovWGbrSt | Insn::MovLGbrSt => {
            let size = match insn {
                Insn::MovBGbrSt => 1,
                Insn::MovWGbrSt => 2,
                _ => 4,
            };
            let g = b.get(gbr_ref());
            let ea = add_n(b, g, ops[0] as u32 * size);
            let v = R(0).get(b);
            store_s(b, ea, v, size, endian)?;
        }
        Insn::MovBGbrLd | Insn::MovWGbrLd | Insn::MovLGbrLd => {
            let size = match insn {
                Insn::MovBGbrLd => 1,
                Insn::MovWGbrLd => 2,
                _ => 4,
            };
            let g = b.get(gbr_ref());
            let ea = add_n(b, g, ops[0] as u32 * size);
            let v = load_s(b, ea, size, true, endian)?;
            R(0).set(b, v);
        }
        Insn::Mova => {
            // R0 = (PC+4)&~3 + imm*4。
            let v = k(
                b,
                (pc.wrapping_add(4) & !3).wrapping_add(ops[0] * 4) & 0xffff_ffff,
            );
            R(0).set(b, v);
        }
        Insn::Movt => {
            let t = get_t(b);
            rset(b, ops[0], t);
        }
        Insn::Movrt => {
            let t = get_t(b);
            let one = k(b, 1);
            let v = b.xor(t, one);
            rset(b, ops[0], v);
        }
        Insn::Nott => {
            let t = get_t(b);
            let one = k(b, 1);
            let v = b.xor(t, one);
            set_t(b, v);
        }
        Insn::SwapB => {
            let x = rget(b, ops[1]);
            let hi = and_n(b, x, 0xffff_0000);
            let lo0 = and_n(b, x, 0xff);
            let lo = shl_n(b, lo0, 8);
            let md0 = and_n(b, x, 0xff00);
            let md = shr_n(b, md0, 8);
            let t1 = b.or(hi, lo);
            let v = b.or(t1, md);
            rset(b, ops[0], v);
        }
        Insn::SwapW => {
            let x = rget(b, ops[1]);
            let lo = shl_n(b, x, 16);
            let hi = shr_n(b, x, 16);
            let v = b.or(lo, hi);
            rset(b, ops[0], v);
        }
        Insn::Xtrct => {
            let m0 = rget(b, ops[1]);
            let n0 = rget(b, ops[0]);
            let lo = shl_n(b, m0, 16);
            let hi = shr_n(b, n0, 16);
            let v = b.or(lo, hi);
            rset(b, ops[0], v);
        }
        Insn::ExtuB | Insn::ExtuW | Insn::ExtsB | Insn::ExtsW => {
            let x = rget(b, ops[1]);
            let bits = if matches!(insn, Insn::ExtuB | Insn::ExtsB) {
                8
            } else {
                16
            };
            let v = if matches!(insn, Insn::ExtuB | Insn::ExtuW) {
                and_n(b, x, if bits == 8 { 0xff } else { 0xffff })
            } else {
                sext_bits(b, x, bits)
            };
            rset(b, ops[0], v);
        }
        // ---- SH-2A の転送追加 ----
        Insn::MovBR0Stp | Insn::MovWR0Stp | Insn::MovLR0Stp => {
            let size = match insn {
                Insn::MovBR0Stp => 1,
                Insn::MovWR0Stp => 2,
                _ => 4,
            };
            let n = ops[0] as u8;
            let ea = R(n).get(b);
            let v = R(0).get(b);
            store_s(b, ea, v, size, endian)?;
            let inc = add_n(b, ea, size);
            R(n).set(b, inc);
        }
        Insn::MovBR0Ldp | Insn::MovWR0Ldp | Insn::MovLR0Ldp => {
            let size = match insn {
                Insn::MovBR0Ldp => 1,
                Insn::MovWR0Ldp => 2,
                _ => 4,
            };
            let m = ops[0] as u8;
            let ea_src = R(m).get(b);
            let ea = sub_n(b, ea_src, size);
            R(m).set(b, ea);
            let v = load_s(b, ea, size, true, endian)?;
            R(0).set(b, v);
        }
        Insn::MovBD12St | Insn::MovWD12St | Insn::MovLD12St => {
            let size = match insn {
                Insn::MovBD12St => 1,
                Insn::MovWD12St => 2,
                _ => 4,
            };
            let base = rget(b, ops[0]);
            let ea = add_n(b, base, ops[2] as u32 * size);
            let v = rget(b, ops[1]);
            store_s(b, ea, v, size, endian)?;
        }
        Insn::MovBD12Ld | Insn::MovWD12Ld | Insn::MovLD12Ld => {
            let size = match insn {
                Insn::MovBD12Ld => 1,
                Insn::MovWD12Ld => 2,
                _ => 4,
            };
            let base = rget(b, ops[1]);
            let ea = add_n(b, base, ops[2] as u32 * size);
            let v = load_s(b, ea, size, true, endian)?;
            rset(b, ops[0], v);
        }
        Insn::MovuBD12 | Insn::MovuWD12 => {
            let size = if insn == Insn::MovuBD12 { 1 } else { 2 };
            let base = rget(b, ops[1]);
            let ea = add_n(b, base, ops[2] as u32 * size);
            let v = load_s(b, ea, size, false, endian)?;
            rset(b, ops[0], v);
        }
        Insn::MovuaL | Insn::MovuaLPost => {
            // MOVUA.L はアライン無しの 32 ビットロード。
            // Ref: SPEC-SUPERH-SH2A §5（MOVUA）.
            let m = ops[0] as u8;
            let ea = R(m).get(b);
            let a = ea64(b, ea);
            let acc = Access {
                endian,
                align: Align::Unaligned,
                kind: AccessKind::DataRead,
            };
            let v: B::V<W32> = b.load(a, acc)?;
            R(0).set(b, v);
            if insn == Insn::MovuaLPost {
                let inc = add_n(b, ea, 4);
                R(m).set(b, inc);
            }
        }
        Insn::Movi20 => {
            let v = k(b, sext((ops[1] << 16) | ops[2], 20) as u64 & 0xffff_ffff);
            rset(b, ops[0], v);
        }
        Insn::Movi20s => {
            let v = k(
                b,
                (sext((ops[1] << 16) | ops[2], 20) << 8) as u64 & 0xffff_ffff,
            );
            rset(b, ops[0], v);
        }
        Insn::MovmlSt => {
            // for i=m down to 0: R15-=4; mem[R15] = (i==15 ? PR : R[i])。
            // Ref: SPEC-SUPERH-SH2A §6.3.23.
            for i in (0..=ops[0]).rev() {
                let ea_src = R(15).get(b);
                let ea = sub_n(b, ea_src, 4);
                let v = if i == 15 {
                    b.get(pr_ref())
                } else {
                    R(i as u8).get(b)
                };
                store_s(b, ea, v, 4, endian)?;
                R(15).set(b, ea);
            }
        }
        Insn::MovmlLd => {
            // for i=0 to n: (i==15 ? PR : R[i]) = mem[R15]; R15+=4。
            for i in 0..=ops[0] {
                let ea = R(15).get(b);
                let v = load_s(b, ea, 4, true, endian)?;
                if i == 15 {
                    b.set(pr_ref(), v);
                } else {
                    R(i as u8).set(b, v);
                }
                let inc = add_n(b, ea, 4);
                R(15).set(b, inc);
            }
        }
        Insn::MovmuSt => {
            // mem[R15-4] = PR; R15-=4; for i=14 down to m: 同じ。
            let ea_src = R(15).get(b);
            let ea = sub_n(b, ea_src, 4);
            let pr = b.get(pr_ref());
            store_s(b, ea, pr, 4, endian)?;
            R(15).set(b, ea);
            for i in (ops[0]..=14).rev() {
                let ea_src = R(15).get(b);
                let ea = sub_n(b, ea_src, 4);
                let v = R(i as u8).get(b);
                store_s(b, ea, v, 4, endian)?;
                R(15).set(b, ea);
            }
        }
        Insn::MovmuLd => {
            // for i=n to 14: R[i] = mem[R15]; R15+=4; PR = mem[R15]; R15+=4。
            for i in ops[0]..=14 {
                let ea = R(15).get(b);
                let v = load_s(b, ea, 4, true, endian)?;
                R(i as u8).set(b, v);
                let inc = add_n(b, ea, 4);
                R(15).set(b, inc);
            }
            let ea = R(15).get(b);
            let v = load_s(b, ea, 4, true, endian)?;
            b.set(pr_ref(), v);
            let inc = add_n(b, ea, 4);
            R(15).set(b, inc);
        }
        // ---- 算術 ----
        Insn::AddImm => {
            let x = rget(b, ops[0]);
            let v = add_n(b, x, sext(ops[1], 8) as u32);
            rset(b, ops[0], v);
        }
        Insn::Add => {
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let v = b.add(x, y);
            rset(b, ops[0], v);
        }
        Insn::Addc => {
            let rn = rget(b, ops[0]);
            let rm = rget(b, ops[1]);
            let t = get_t(b);
            let s1 = b.add(rn, rm);
            let c1 = b.cmp(Cmp::GtU, rn, s1);
            let s2 = b.add(s1, t);
            let c2 = b.cmp(Cmp::GtU, s1, s2);
            let c1v = bval(b, c1);
            let c2v = bval(b, c2);
            let cv = b.or(c1v, c2v);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, cv, zz);
            rset(b, ops[0], s2);
            set_t_cmp(b, c);
        }
        Insn::Addv => {
            let rn = rget(b, ops[0]);
            let rm = rget(b, ops[1]);
            let s = b.add(rn, rm);
            rset(b, ops[0], s);
            // 被演算子の符号が同じで結果と異なればオーバーフロー。
            let zero = k(b, 0);
            let d = b.xor(rn, rm);
            let dif = b.cmp(Cmp::LtS, d, zero);
            let e = b.xor(s, rn);
            let chg = b.cmp(Cmp::LtS, e, zero);
            let nd = bnot(b, dif);
            let samev = bval(b, nd);
            let chgv = bval(b, chg);
            let both = b.and(samev, chgv);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, both, zz);
            set_t_cmp(b, c);
        }
        Insn::Sub => {
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let v = b.sub(x, y);
            rset(b, ops[0], v);
        }
        Insn::Subc => {
            let rn = rget(b, ops[0]);
            let rm = rget(b, ops[1]);
            let t = get_t(b);
            let s1 = b.sub(rn, rm);
            let c1 = b.cmp(Cmp::GtU, s1, rn);
            let s2 = b.sub(s1, t);
            let c2 = b.cmp(Cmp::GtU, s2, s1);
            let c1v = bval(b, c1);
            let c2v = bval(b, c2);
            let cv = b.or(c1v, c2v);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, cv, zz);
            rset(b, ops[0], s2);
            set_t_cmp(b, c);
        }
        Insn::Subv => {
            let rn = rget(b, ops[0]);
            let rm = rget(b, ops[1]);
            let s = b.sub(rn, rm);
            rset(b, ops[0], s);
            let zero = k(b, 0);
            let d = b.xor(rn, rm);
            let dif = b.cmp(Cmp::LtS, d, zero);
            let e = b.xor(s, rn);
            let chg = b.cmp(Cmp::LtS, e, zero);
            let difv = bval(b, dif);
            let chgv = bval(b, chg);
            let both = b.and(difv, chgv);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, both, zz);
            set_t_cmp(b, c);
        }
        Insn::Neg => {
            let zero = k(b, 0);
            let x = rget(b, ops[1]);
            let v = b.sub(zero, x);
            rset(b, ops[0], v);
        }
        Insn::Negc => {
            let rm = rget(b, ops[1]);
            let t = get_t(b);
            let sum = b.add(rm, t);
            let zz = k(b, 0);
            let bor = b.cmp(Cmp::Ne, sum, zz);
            let v = b.sub(zz, sum);
            rset(b, ops[0], v);
            set_t_cmp(b, bor);
        }
        Insn::CmpEqImm => {
            let r0 = R(0).get(b);
            let c = k(b, sext(ops[0], 8) as u64 & 0xffff_ffff);
            let c = b.cmp(Cmp::Eq, r0, c);
            set_t_cmp(b, c);
        }
        Insn::CmpEq | Insn::CmpHs | Insn::CmpGe | Insn::CmpHi | Insn::CmpGt => {
            let rn = rget(b, ops[0]);
            let rm = rget(b, ops[1]);
            let op = match insn {
                Insn::CmpEq => Cmp::Eq,
                Insn::CmpHs => Cmp::GeU,
                Insn::CmpGe => Cmp::GeS,
                Insn::CmpHi => Cmp::GtU,
                _ => Cmp::GtS,
            };
            let c = b.cmp(op, rn, rm);
            set_t_cmp(b, c);
        }
        Insn::CmpPl => {
            let x = rget(b, ops[0]);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::GtS, x, zz);
            set_t_cmp(b, c);
        }
        Insn::CmpPz => {
            let x = rget(b, ops[0]);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::GeS, x, zz);
            set_t_cmp(b, c);
        }
        Insn::CmpStr => {
            let rn = rget(b, ops[0]);
            let rm = rget(b, ops[1]);
            let x = b.xor(rn, rm);
            let zz = k(b, 0);
            let b0 = and_n(b, x, 0xff);
            let s8 = shr_n(b, x, 8);
            let b1 = and_n(b, s8, 0xff);
            let s16 = shr_n(b, x, 16);
            let b2 = and_n(b, s16, 0xff);
            let b3 = shr_n(b, x, 24);
            let e0 = b.cmp(Cmp::Eq, b0, zz);
            let e1 = b.cmp(Cmp::Eq, b1, zz);
            let e2 = b.cmp(Cmp::Eq, b2, zz);
            let e3 = b.cmp(Cmp::Eq, b3, zz);
            let v0 = bval(b, e0);
            let v1 = bval(b, e1);
            let v2 = bval(b, e2);
            let v3 = bval(b, e3);
            let t01 = b.or(v0, v1);
            let t23 = b.or(v2, v3);
            let acc = b.or(t01, t23);
            set_t(b, acc);
        }
        Insn::Div0s => {
            // Q=MSB(Rn)、M=MSB(Rm)、T=!(Q==M)。
            // Ref: SPEC-SUPERH-SH2A §6.4.
            let rn = rget(b, ops[0]);
            let rm = rget(b, ops[1]);
            let q0 = shr_n(b, rn, 31);
            let q = and_n(b, q0, 1);
            let m0 = shr_n(b, rm, 31);
            let mm = and_n(b, m0, 1);
            set_flag(b, SR_Q, q);
            set_flag(b, SR_M, mm);
            let x = b.xor(q, mm);
            set_t(b, x);
        }
        Insn::Div0u => {
            let z0 = k(b, 0);
            let z1 = k(b, 0);
            let z2 = k(b, 0);
            set_flag(b, SR_M, z0);
            set_flag(b, SR_Q, z1);
            set_t(b, z2);
        }
        Insn::Div1 => {
            // SPEC-SUPERH-SH2A §6.4.18 の手続き。
            let rm = rget(b, ops[1]);
            let old_q = get_flag(b, SR_Q);
            let mbit = get_flag(b, SR_M);
            let rn = rget(b, ops[0]);
            let nq0 = shr_n(b, rn, 31);
            let new_q = and_n(b, nq0, 1);
            let t = get_t(b);
            let rns = shl_n(b, rn, 1);
            let rn2 = b.or(rns, t);
            // old_q==M → sub 系、それ以外 → add 系。
            let sub_case = b.cmp(Cmp::Eq, old_q, mbit);
            let sub = b.sub(rn2, rm);
            let add = b.add(rn2, rm);
            let after = selv(b, sub_case, sub, add);
            // cb: sub 系は (after > rn2)（borrow）、add 系は
            // (after < rn2)（carry）。
            let sc = b.cmp(Cmp::GtU, after, rn2);
            let ac = b.cmp(Cmp::GtU, rn2, after);
            let scv = bval(b, sc);
            let acv = bval(b, ac);
            let cb = selv(b, sub_case, scv, acv);
            // Q' = new_q ⊕ M ⊕ cb（Ref: SPEC-SUPERH-JCORE —
            // datapath.vhm の `a_msb xor sr_in.m xor co_or_borrow`）。
            let qm = b.xor(new_q, mbit);
            let qf = b.xor(qm, cb);
            rset(b, ops[0], after);
            set_flag(b, SR_Q, qf);
            // T = (Q == M)。
            let eq = b.cmp(Cmp::Eq, qf, mbit);
            let v = bval(b, eq);
            set_t(b, v);
        }
        Insn::Dt => {
            let dtx = rget(b, ops[0]);
            let v = sub_n(b, dtx, 1);
            rset(b, ops[0], v);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Eq, v, zz);
            set_t_cmp(b, c);
        }
        Insn::MulsW => {
            let x0src = rget(b, ops[0]);
            let x0 = and_n(b, x0src, 0xffff);
            let y0src = rget(b, ops[1]);
            let y0 = and_n(b, y0src, 0xffff);
            let x = sext_bits(b, x0, 16);
            let y = sext_bits(b, y0, 16);
            let p = b.mul(x, y);
            b.set(macl_ref(), p);
        }
        Insn::MuluW => {
            let xsrc = rget(b, ops[0]);
            let x = and_n(b, xsrc, 0xffff);
            let ysrc = rget(b, ops[1]);
            let y = and_n(b, ysrc, 0xffff);
            let p = b.mul(x, y);
            b.set(macl_ref(), p);
        }
        Insn::MulL => {
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let p = b.mul(x, y);
            b.set(macl_ref(), p);
        }
        Insn::Dmuls => {
            let dxsrc = rget(b, ops[0]);
            let x = b.sext::<W32, W64>(dxsrc);
            let dysrc = rget(b, ops[1]);
            let y = b.sext::<W32, W64>(dysrc);
            let p = b.mul(x, y);
            let c32 = k64(b, 32);
            let s = b.shr_l(p, c32);
            let hi = b.trunc::<W64, W32>(s);
            let lo = b.trunc::<W64, W32>(p);
            b.set(mach_ref(), hi);
            b.set(macl_ref(), lo);
        }
        Insn::Dmulu => {
            let dxsrc = rget(b, ops[0]);
            let x = b.zext::<W32, W64>(dxsrc);
            let dysrc = rget(b, ops[1]);
            let y = b.zext::<W32, W64>(dysrc);
            let p = b.mul(x, y);
            let c32 = k64(b, 32);
            let s = b.shr_l(p, c32);
            let hi = b.trunc::<W64, W32>(s);
            let lo = b.trunc::<W64, W32>(p);
            b.set(mach_ref(), hi);
            b.set(macl_ref(), lo);
        }
        Insn::MacW => {
            // MAC += sext16(mem16[Rm]) * sext16(mem16[Rn]);
            // Rm+=2, Rn+=2。S ビットの飽和は近似（Gap: GAP-0059）。
            let a = rget(b, ops[1]);
            let xv = load_s(b, a, 2, false, endian)?;
            let x0 = and_n(b, xv, 0xffff);
            let x = sext_bits(b, x0, 16);
            let ea2 = rget(b, ops[0]);
            let yv = load_s(b, ea2, 2, false, endian)?;
            let y0 = and_n(b, yv, 0xffff);
            let y = sext_bits(b, y0, 16);
            let x64 = b.sext::<W32, W64>(x);
            let y64 = b.sext::<W32, W64>(y);
            let p = b.mul(x64, y64);
            mac_add(b, p);
            let am = add_n(b, a, 2);
            rset(b, ops[1], am);
            let an = add_n(b, ea2, 2);
            rset(b, ops[0], an);
        }
        Insn::MacL => {
            let a = rget(b, ops[1]);
            let x = load_s(b, a, 4, true, endian)?;
            let ea2 = rget(b, ops[0]);
            let y = load_s(b, ea2, 4, true, endian)?;
            let x64 = b.sext::<W32, W64>(x);
            let y64 = b.sext::<W32, W64>(y);
            let p = b.mul(x64, y64);
            mac_add(b, p);
            let am = add_n(b, a, 4);
            rset(b, ops[1], am);
            let an = add_n(b, ea2, 4);
            rset(b, ops[0], an);
        }
        Insn::Clrmac => {
            let z0 = k(b, 0);
            let z1 = k(b, 0);
            b.set(mach_ref(), z0);
            b.set(macl_ref(), z1);
        }
        Insn::Mulr => {
            let x = R(0).get(b);
            let y = rget(b, ops[0]);
            let p = b.mul(x, y);
            rset(b, ops[0], p);
        }
        Insn::Divs => {
            // Rn = Rn / R0（符号付き、0 除算では T=1）。
            // Ref: SPEC-SUPERH-SH2A §6.4.
            let rn = rget(b, ops[0]);
            let d = R(0).get(b);
            let zz = k(b, 0);
            let z = b.cmp(Cmp::Eq, d, zz);
            let q = b.sdiv(rn, d);
            let one = k(b, 1);
            let v = selv(b, z, one, q);
            rset(b, ops[0], v);
            let tv = bval(b, z);
            set_t(b, tv);
        }
        Insn::Divu => {
            let rn = rget(b, ops[0]);
            let d = R(0).get(b);
            let zz = k(b, 0);
            let z = b.cmp(Cmp::Eq, d, zz);
            let q = b.udiv(rn, d);
            let one = k(b, 1);
            let v = selv(b, z, one, q);
            rset(b, ops[0], v);
            let tv = bval(b, z);
            set_t(b, tv);
        }
        Insn::ClipsB | Insn::ClipsW | Insn::ClipuB | Insn::ClipuW => {
            let x = rget(b, ops[0]);
            let (lo, hi, signed) = match insn {
                Insn::ClipsB => (-0x80i64, 0x7f, true),
                Insn::ClipsW => (-0x8000, 0x7fff, true),
                Insn::ClipuB => (0, 0xff, false),
                _ => (0, 0xffff, false),
            };
            let lov = k(b, lo as u64 & 0xffff_ffff);
            let hiv = k(b, hi as u64);
            let below = if signed {
                b.cmp(Cmp::LtS, x, lov)
            } else {
                b.cmp(Cmp::LtU, x, lov)
            };
            let above = if signed {
                b.cmp(Cmp::GtS, x, hiv)
            } else {
                b.cmp(Cmp::GtU, x, hiv)
            };
            let v0 = selv(b, below, lov, x);
            let v = selv(b, above, hiv, v0);
            let changed = b.cmp(Cmp::Ne, v, x);
            rset(b, ops[0], v);
            set_t_cmp(b, changed);
        }
        // ---- 論理 ----
        Insn::And => {
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let v = b.and(x, y);
            rset(b, ops[0], v);
        }
        Insn::AndImm => {
            let x = R(0).get(b);
            let v = and_n(b, x, ops[0] as u32);
            R(0).set(b, v);
        }
        Insn::AndBImm | Insn::OrBImm | Insn::XorBImm | Insn::TstBImm => {
            let g = b.get(gbr_ref());
            let r0 = R(0).get(b);
            let ea = b.add(g, r0);
            let v = load_s(b, ea, 1, false, endian)?;
            let imm = k(b, ops[0]);
            if insn == Insn::TstBImm {
                let x = b.and(v, imm);
                let zz = k(b, 0);
                let c = b.cmp(Cmp::Eq, x, zz);
                set_t_cmp(b, c);
            } else {
                let nv = match insn {
                    Insn::AndBImm => b.and(v, imm),
                    Insn::OrBImm => b.or(v, imm),
                    _ => b.xor(v, imm),
                };
                store_s(b, ea, nv, 1, endian)?;
            }
        }
        Insn::Not => {
            let x = rget(b, ops[1]);
            let v = b.not(x);
            rset(b, ops[0], v);
        }
        Insn::Or => {
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let v = b.or(x, y);
            rset(b, ops[0], v);
        }
        Insn::OrImm => {
            let x = R(0).get(b);
            let v = or_n(b, x, ops[0] as u32);
            R(0).set(b, v);
        }
        Insn::Xor => {
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let v = b.xor(x, y);
            rset(b, ops[0], v);
        }
        Insn::XorImm => {
            let x = R(0).get(b);
            let imm = k(b, ops[0]);
            let v = b.xor(x, imm);
            R(0).set(b, v);
        }
        Insn::TasB => {
            let ea = rget(b, ops[0]);
            let v = load_s(b, ea, 1, false, endian)?;
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Eq, v, zz);
            let nv = or_n(b, v, 0x80);
            store_s(b, ea, nv, 1, endian)?;
            set_t_cmp(b, c);
        }
        Insn::Tst => {
            let x = rget(b, ops[0]);
            let y = rget(b, ops[1]);
            let v = b.and(x, y);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Eq, v, zz);
            set_t_cmp(b, c);
        }
        Insn::TstImm => {
            let x = R(0).get(b);
            let v = and_n(b, x, ops[0] as u32);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Eq, v, zz);
            set_t_cmp(b, c);
        }
        // ---- ビット命令（レジスタ形式） ----
        Insn::BclrReg | Insn::BstReg | Insn::BldReg => {
            let n = ops[0] as u8;
            let bit = ops[1] as u32;
            let x = R(n).get(b);
            let one = k(b, 1);
            let bc = k(b, u64::from(bit));
            let bmask = b.shl(one, bc);
            match insn {
                Insn::BclrReg => {
                    let inv = b.not(bmask);
                    let v = b.and(x, inv);
                    R(n).set(b, v);
                }
                Insn::BstReg => {
                    let t = get_t(b);
                    let zz = k(b, 0);
                    let sel = b.cmp(Cmp::Ne, t, zz);
                    let orv = b.or(x, bmask);
                    let v = selv(b, sel, orv, x);
                    R(n).set(b, v);
                }
                _ => {
                    // BLD: T = (Rn >> bit) & 1。
                    let s = shr_n(b, x, bit);
                    let v = and_n(b, s, 1);
                    set_t(b, v);
                }
            }
        }
        // ---- ビット命令（メモリ形式・SH-2A） ----
        Insn::BclrD12
        | Insn::BstD12
        | Insn::BldD12
        | Insn::BandD12
        | Insn::BorD12
        | Insn::BxorD12
        | Insn::BldnotD12
        | Insn::BandnotD12
        | Insn::BornotD12 => {
            let base = rget(b, ops[0]);
            let ea = add_n(b, base, ops[2] as u32);
            let bit = ops[1] as u32;
            let v = load_s(b, ea, 1, false, endian)?;
            let sv = shr_n(b, v, bit);
            let bsel = and_n(b, sv, 1);
            match insn {
                Insn::BclrD12 => {
                    let one = k(b, 1);
                    let bc = k(b, u64::from(bit));
                    let m = b.shl(one, bc);
                    let inv = b.not(m);
                    let nv = b.and(v, inv);
                    store_s(b, ea, nv, 1, endian)?;
                }
                Insn::BstD12 => {
                    let t = get_t(b);
                    let m = shl_n(b, t, bit);
                    let keep = and_n(b, v, !(1u32 << bit));
                    let nv = b.or(keep, m);
                    store_s(b, ea, nv, 1, endian)?;
                }
                Insn::BldD12 | Insn::BldnotD12 => {
                    let vv = if insn == Insn::BldD12 {
                        bsel
                    } else {
                        let one = k(b, 1);
                        b.xor(bsel, one)
                    };
                    set_t(b, vv);
                }
                Insn::BandD12 | Insn::BandnotD12 => {
                    let t = get_t(b);
                    let vv = if insn == Insn::BandD12 {
                        bsel
                    } else {
                        let one = k(b, 1);
                        b.xor(bsel, one)
                    };
                    let nv = b.and(t, vv);
                    set_t(b, nv);
                }
                Insn::BorD12 | Insn::BornotD12 => {
                    let t = get_t(b);
                    let vv = if insn == Insn::BorD12 {
                        bsel
                    } else {
                        let one = k(b, 1);
                        b.xor(bsel, one)
                    };
                    let nv = b.or(t, vv);
                    set_t(b, nv);
                }
                _ => {
                    // BXOR: T = T ^ bit。
                    let t = get_t(b);
                    let nv = b.xor(t, bsel);
                    set_t(b, nv);
                }
            }
        }
        // ---- シフト・ローテート ----
        Insn::Shal | Insn::Shll => {
            let x = rget(b, ops[0]);
            let hb = and_n(b, x, 0x8000_0000);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, hb, zz);
            let v = shl_n(b, x, 1);
            rset(b, ops[0], v);
            set_t_cmp(b, c);
        }
        Insn::Shar => {
            let x = rget(b, ops[0]);
            let lb = and_n(b, x, 1);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, lb, zz);
            let v = sra_n(b, x, 1);
            rset(b, ops[0], v);
            set_t_cmp(b, c);
        }
        Insn::Shlr => {
            let x = rget(b, ops[0]);
            let lb = and_n(b, x, 1);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, lb, zz);
            let v = shr_n(b, x, 1);
            rset(b, ops[0], v);
            set_t_cmp(b, c);
        }
        Insn::Shll2 | Insn::Shll8 | Insn::Shll16 => {
            let n = match insn {
                Insn::Shll2 => 2,
                Insn::Shll8 => 8,
                _ => 16,
            };
            let shx = rget(b, ops[0]);
            let v = shl_n(b, shx, n);
            rset(b, ops[0], v);
        }
        Insn::Shlr2 | Insn::Shlr8 | Insn::Shlr16 => {
            let n = match insn {
                Insn::Shlr2 => 2,
                Insn::Shlr8 => 8,
                _ => 16,
            };
            let shx = rget(b, ops[0]);
            let v = shr_n(b, shx, n);
            rset(b, ops[0], v);
        }
        Insn::Rotl => {
            let x = rget(b, ops[0]);
            let hb = and_n(b, x, 0x8000_0000);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, hb, zz);
            let l = shl_n(b, x, 1);
            let h = shr_n(b, x, 31);
            let v = b.or(l, h);
            rset(b, ops[0], v);
            set_t_cmp(b, c);
        }
        Insn::Rotr => {
            let x = rget(b, ops[0]);
            let lb = and_n(b, x, 1);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, lb, zz);
            let r = shr_n(b, x, 1);
            let l = shl_n(b, x, 31);
            let v = b.or(r, l);
            rset(b, ops[0], v);
            set_t_cmp(b, c);
        }
        Insn::Rotcl => {
            let x = rget(b, ops[0]);
            let t = get_t(b);
            let hb = and_n(b, x, 0x8000_0000);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, hb, zz);
            let l = shl_n(b, x, 1);
            let v = b.or(l, t);
            rset(b, ops[0], v);
            set_t_cmp(b, c);
        }
        Insn::Rotcr => {
            let x = rget(b, ops[0]);
            let t = get_t(b);
            let lb = and_n(b, x, 1);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, lb, zz);
            let r = shr_n(b, x, 1);
            let ts = shl_n(b, t, 31);
            let v = b.or(r, ts);
            rset(b, ops[0], v);
            set_t_cmp(b, c);
        }
        Insn::Shad | Insn::Shld => {
            // 動的シフト。Rm の下位 6 ビットを符号付き量として
            // 正なら左、負なら右（shad=算術、shld=論理）。
            // Ref: SPEC-SUPERH-SH3 §7.12.
            let x = rget(b, ops[0]);
            let m = rget(b, ops[1]);
            let cnt = and_n(b, m, 0x1f);
            let nb = and_n(b, m, 0x20);
            let zz = k(b, 0);
            let neg = b.cmp(Cmp::Ne, nb, zz);
            let left = b.shl(x, cnt);
            // 右側: cnt==0 のときシフト量 32 → shad は全符号、
            // shld は 0。
            let isz = b.cmp(Cmp::Eq, cnt, zz);
            let c32 = k(b, 32);
            let csh = b.sub(c32, cnt);
            let shifted = if insn == Insn::Shad {
                b.shr_a(x, csh)
            } else {
                b.shr_l(x, csh)
            };
            let fill = if insn == Insn::Shad {
                sra_n(b, x, 31)
            } else {
                k(b, 0)
            };
            let rz = selv(b, isz, fill, shifted);
            let v = selv(b, neg, rz, left);
            rset(b, ops[0], v);
        }
        // ---- 分岐（遅延スロットの実行は run_superh 側） ----
        Insn::Bra => {
            let t = rel_target(pc, sext(ops[0], 12));
            let tv = k(b, t);
            jump32(b, tv);
        }
        Insn::Bsr => {
            let t = rel_target(pc, sext(ops[0], 12));
            let pr = k(b, (pc + 4) & 0xffff_ffff);
            b.set(pr_ref(), pr);
            let tv = k(b, t);
            jump32(b, tv);
        }
        Insn::Braf => {
            let base = k(b, (pc + 4) & 0xffff_ffff);
            let off = rget(b, ops[0]);
            let t = b.add(base, off);
            jump32(b, t);
        }
        Insn::Bsrf => {
            let base = k(b, (pc + 4) & 0xffff_ffff);
            b.set(pr_ref(), base);
            let off = rget(b, ops[0]);
            let t = b.add(base, off);
            jump32(b, t);
        }
        Insn::Bf | Insn::Bfs => {
            let t = get_t(b);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Eq, t, zz);
            b.branch(c, rel_target(pc, sext(ops[0], 8)));
        }
        Insn::Bt | Insn::Bts => {
            let t = get_t(b);
            let zz = k(b, 0);
            let c = b.cmp(Cmp::Ne, t, zz);
            b.branch(c, rel_target(pc, sext(ops[0], 8)));
        }
        Insn::Jmp => {
            let t = rget(b, ops[0]);
            jump32(b, t);
        }
        Insn::Jsr => {
            let pr = k(b, (pc + 4) & 0xffff_ffff);
            b.set(pr_ref(), pr);
            let t = rget(b, ops[0]);
            jump32(b, t);
        }
        Insn::Rts => {
            let t = b.get(pr_ref());
            jump32(b, t);
        }
        Insn::Rtsn => {
            let t = b.get(pr_ref());
            jump32(b, t);
        }
        Insn::Rtvn => {
            // RTV/N Rm: PC = PR、R0 = Rm。
            let v = rget(b, ops[0]);
            R(0).set(b, v);
            let t = b.get(pr_ref());
            jump32(b, t);
        }
        Insn::JsrnMem => {
            let pr = k(b, (pc + 2) & 0xffff_ffff);
            b.set(pr_ref(), pr);
            let t = rget(b, ops[0]);
            jump32(b, t);
        }
        Insn::JsrnTbr => {
            // JSR/N @@(disp8,TBR): ターゲットは mem32[TBR+disp*4]。
            let pr = k(b, (pc + 2) & 0xffff_ffff);
            b.set(pr_ref(), pr);
            let tbr = b.get(tbr_ref());
            let ea = add_n(b, tbr, ops[0] as u32 * 4);
            let t = load_s(b, ea, 4, false, endian)?;
            jump32(b, t);
        }
        // ---- トラップ・制御 ----
        Insn::Trapa => {
            return Err(raise::<B>(b, ExceptionKind::Trap, ops[0]));
        }
        Insn::Nop => {}
        Insn::Clrt => {
            let z = k(b, 0);
            set_t(b, z);
        }
        Insn::Sett => {
            let z = k(b, 1);
            set_t(b, z);
        }
        Insn::Clrs => {
            let z = k(b, 0);
            set_flag(b, SR_S, z);
        }
        Insn::Sets => {
            let z = k(b, 1);
            set_flag(b, SR_S, z);
        }
        Insn::Rte | Insn::Sleep | Insn::Ldtlb | Insn::Resbank => {
            return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_PRIV));
        }
        // ---- 制御レジスタ ----
        Insn::StcSr
        | Insn::StcGbr
        | Insn::StcVbr
        | Insn::StcSsr
        | Insn::StcSpc
        | Insn::StcSgr
        | Insn::StcDbr
        | Insn::StcTbr => {
            let v = match insn {
                Insn::StcSr => get_sr(b),
                Insn::StcGbr => b.get(gbr_ref()),
                Insn::StcVbr => b.get(vbr_ref()),
                Insn::StcSsr => b.get(ssr_ref()),
                Insn::StcSpc => b.get(spc_ref()),
                Insn::StcSgr => b.get(sgr_ref()),
                Insn::StcDbr => b.get(dbr_ref()),
                _ => b.get(tbr_ref()),
            };
            rset(b, ops[0], v);
        }
        Insn::StcRbank => {
            let v = b.get(rbank_ref(ops[1] as u8));
            rset(b, ops[0], v);
        }
        Insn::StsMach | Insn::StsMacl | Insn::StsPr | Insn::StsFpscr | Insn::StsFpul => {
            let v = match insn {
                Insn::StsMach => b.get(mach_ref()),
                Insn::StsMacl => b.get(macl_ref()),
                Insn::StsPr => b.get(pr_ref()),
                Insn::StsFpscr => b.get(fpscr_ref()),
                _ => b.get(fpul_ref()),
            };
            rset(b, ops[0], v);
        }
        Insn::LdcSr
        | Insn::LdcGbr
        | Insn::LdcVbr
        | Insn::LdcSsr
        | Insn::LdcSpc
        | Insn::LdcSgr
        | Insn::LdcDbr
        | Insn::LdcTbr => {
            let v = rget(b, ops[0]);
            match insn {
                Insn::LdcSr => set_sr(b, v),
                Insn::LdcGbr => b.set(gbr_ref(), v),
                Insn::LdcVbr => b.set(vbr_ref(), v),
                Insn::LdcSsr => b.set(ssr_ref(), v),
                Insn::LdcSpc => b.set(spc_ref(), v),
                Insn::LdcSgr => b.set(sgr_ref(), v),
                Insn::LdcDbr => b.set(dbr_ref(), v),
                _ => b.set(tbr_ref(), v),
            }
        }
        Insn::LdcRbank => {
            let v = rget(b, ops[0]);
            b.set(rbank_ref(ops[1] as u8), v);
        }
        Insn::LdsMach | Insn::LdsMacl | Insn::LdsPr | Insn::LdsFpscr | Insn::LdsFpul => {
            let v = rget(b, ops[0]);
            match insn {
                Insn::LdsMach => b.set(mach_ref(), v),
                Insn::LdsMacl => b.set(macl_ref(), v),
                Insn::LdsPr => b.set(pr_ref(), v),
                Insn::LdsFpscr => b.set(fpscr_ref(), v),
                _ => b.set(fpul_ref(), v),
            }
        }
        Insn::StcmSr
        | Insn::StcmGbr
        | Insn::StcmVbr
        | Insn::StcmSsr
        | Insn::StcmSpc
        | Insn::StcmSgr
        | Insn::StcmDbr => {
            let v = match insn {
                Insn::StcmSr => get_sr(b),
                Insn::StcmGbr => b.get(gbr_ref()),
                Insn::StcmVbr => b.get(vbr_ref()),
                Insn::StcmSsr => b.get(ssr_ref()),
                Insn::StcmSpc => b.get(spc_ref()),
                Insn::StcmSgr => b.get(sgr_ref()),
                _ => b.get(dbr_ref()),
            };
            let n = ops[0] as u8;
            let ea_src = R(n).get(b);
            let ea = sub_n(b, ea_src, 4);
            R(n).set(b, ea);
            store_s(b, ea, v, 4, endian)?;
        }
        Insn::StcmRbank => {
            let v = b.get(rbank_ref(ops[1] as u8));
            let n = ops[0] as u8;
            let ea_src = R(n).get(b);
            let ea = sub_n(b, ea_src, 4);
            R(n).set(b, ea);
            store_s(b, ea, v, 4, endian)?;
        }
        Insn::StsmMach | Insn::StsmMacl | Insn::StsmPr | Insn::StsmFpscr | Insn::StsmFpul => {
            let v = match insn {
                Insn::StsmMach => b.get(mach_ref()),
                Insn::StsmMacl => b.get(macl_ref()),
                Insn::StsmPr => b.get(pr_ref()),
                Insn::StsmFpscr => b.get(fpscr_ref()),
                _ => b.get(fpul_ref()),
            };
            let n = ops[0] as u8;
            let ea_src = R(n).get(b);
            let ea = sub_n(b, ea_src, 4);
            R(n).set(b, ea);
            store_s(b, ea, v, 4, endian)?;
        }
        Insn::LdcmSr
        | Insn::LdcmGbr
        | Insn::LdcmVbr
        | Insn::LdcmSsr
        | Insn::LdcmSpc
        | Insn::LdcmSgr
        | Insn::LdcmDbr => {
            let m = ops[0] as u8;
            let ea = R(m).get(b);
            let v = load_s(b, ea, 4, true, endian)?;
            let inc = add_n(b, ea, 4);
            R(m).set(b, inc);
            match insn {
                Insn::LdcmSr => set_sr(b, v),
                Insn::LdcmGbr => b.set(gbr_ref(), v),
                Insn::LdcmVbr => b.set(vbr_ref(), v),
                Insn::LdcmSsr => b.set(ssr_ref(), v),
                Insn::LdcmSpc => b.set(spc_ref(), v),
                Insn::LdcmSgr => b.set(sgr_ref(), v),
                _ => b.set(dbr_ref(), v),
            }
        }
        Insn::LdcmRbank => {
            let m = ops[0] as u8;
            let ea = R(m).get(b);
            let v = load_s(b, ea, 4, true, endian)?;
            let inc = add_n(b, ea, 4);
            R(m).set(b, inc);
            b.set(rbank_ref(ops[1] as u8), v);
        }
        Insn::LdsmMach | Insn::LdsmMacl | Insn::LdsmPr | Insn::LdsmFpscr | Insn::LdsmFpul => {
            let m = ops[0] as u8;
            let ea = R(m).get(b);
            let v = load_s(b, ea, 4, true, endian)?;
            let inc = add_n(b, ea, 4);
            R(m).set(b, inc);
            match insn {
                Insn::LdsmMach => b.set(mach_ref(), v),
                Insn::LdsmMacl => b.set(macl_ref(), v),
                Insn::LdsmPr => b.set(pr_ref(), v),
                Insn::LdsmFpscr => b.set(fpscr_ref(), v),
                _ => b.set(fpul_ref(), v),
            }
        }
        // ---- キャッシュ・特権近似 ----
        Insn::Pref
        | Insn::Ocbi
        | Insn::Ocbp
        | Insn::Ocbwb
        | Insn::Icbi
        | Insn::Prefi
        | Insn::Synco => {}
        Insn::Movca => {
            // R0 を (Rn & ~31) に書くキャッシュ行割当。データを
            // 32 バイトアラインで書くだけの近似。
            let x = rget(b, ops[0]);
            let ea = and_n(b, x, !31);
            let v = R(0).get(b);
            store_s(b, ea, v, 4, endian)?;
        }
        Insn::Movli => {
            let ea = rget(b, ops[0]);
            let a = ea64(b, ea);
            let v: B::V<W32> = b.load_reserved(a, atomic_rw(endian))?;
            R(0).set(b, v);
        }
        Insn::Movco => {
            let ea = rget(b, ops[0]);
            let a = ea64(b, ea);
            let v = R(0).get(b);
            let ok = b.store_conditional(a, v, atomic_rw(endian))?;
            let tv = bval(b, ok);
            set_t(b, tv);
        }
        Insn::CasL => {
            // CAS.L Rm,Rn,@R0: *Rn と R0 を比較し、等しければ *Rn=Rm、
            // 異なれば R0=読み値。T=成功か。
            // Ref: SPEC-SUPERH-JCORE.
            let ea = rget(b, ops[0]);
            let a = ea64(b, ea);
            let old: B::V<W32> = b.load(a, atomic_rw(endian))?;
            let expect = R(0).get(b);
            let eq = b.cmp(Cmp::Eq, old, expect);
            let newv = rget(b, ops[1]);
            // 等しければ newv を書き、異なれば R0 に読み値を戻す。
            let r0v = selv(b, eq, expect, old);
            let write = bval(b, eq);
            b.if_then(eq, |b| store_s(b, ea, newv, 4, endian))?;
            R(0).set(b, r0v);
            set_t(b, write);
        }
        Insn::Ldbank | Insn::Stbank => {
            // R0-R7 の退避/復帰（SH-2A の LDBANK/STBANK。
            // Rm/Rn が指す先に R0-R7 を 8 ワード置く近似。
            // Ref: SPEC-SUPERH-SH2A §6.3.
            let base = rget(b, ops[0]);
            for i in 0..8u32 {
                let ea = add_n(b, base, i * 4);
                if insn == Insn::Stbank {
                    let v = R(i as u8).get(b);
                    store_s(b, ea, v, 4, endian)?;
                } else {
                    let v = load_s(b, ea, 4, true, endian)?;
                    R(i as u8).set(b, v);
                }
            }
        }
        // ---- FP ----
        // fr[]/xf[] はビットイメージ。F32/F64 への解釈は trunc の
        // 再解釈で行う。FPSCR.FR で FR/XD バンクが入れ替わり、
        // SZ=1 で FMOV 系は 8 バイトの対転送、PR=1 で算術・比較・
        // FLOAT/FTRC/FNEG/FABS/FSQRT/FLDI 系は DR ペアの倍精度として
        // 再解釈される（同一符号化の実行モード。独立符号化ではない）。
        // Ref: SPEC-SUPERH-SH4 §6.
        Insn::FmovSLd | Insn::FmovSLdp | Insn::FmovSIdxLd => {
            // fmov.s @Rm,FRn / @Rm+,FRn / @(R0,Rm),FRn。
            // ops = [n(FR), m(ベースR)]。SZ=1 は対転送（DR ペア）。
            let base = rget(b, ops[1]);
            let ea = if insn == Insn::FmovSIdxLd {
                let r0 = R(0).get(b);
                b.add(base, r0)
            } else {
                base
            };
            let sz_v = get_fpscr_bit(b, FPSCR_SZ);
            let sz = nz(b, sz_v);
            b.if_then_else(
                sz,
                |b| {
                    let dr = ops[0] & 14;
                    let (hi, lo) = load2(b, ea, endian)?;
                    afr_set(b, dr, hi)?;
                    afr_set(b, dr + 1, lo)
                },
                |b| {
                    let v = load_s(b, ea, 4, true, endian)?;
                    afr_set(b, ops[0], v)
                },
            )?;
            if insn == Insn::FmovSLdp {
                let bump = add_n(b, ea, 4);
                rset(b, ops[1], bump);
            }
        }
        Insn::FmovSSt | Insn::FmovSStp | Insn::FmovSIdxSt => {
            // fmov.s FRm,@Rn / FRm,@-Rn / FRm,@(R0,Rn)。
            // ops = [n(ベースR), m(FR)]。
            let base = rget(b, ops[0]);
            let ea = if insn == Insn::FmovSIdxSt {
                let r0 = R(0).get(b);
                b.add(base, r0)
            } else if insn == Insn::FmovSStp {
                add_n(b, base, (-4i32) as u32)
            } else {
                base
            };
            let sz_v = get_fpscr_bit(b, FPSCR_SZ);
            let sz = nz(b, sz_v);
            b.if_then_else(
                sz,
                |b| {
                    let dr = ops[1] & 14;
                    let hi = afr_get(b, dr);
                    let lo = afr_get(b, dr + 1);
                    store_s(b, ea, hi, 4, endian)?;
                    let ea2 = add_n(b, ea, 4);
                    store_s(b, ea2, lo, 4, endian)
                },
                |b| {
                    let v = afr_get(b, ops[1]);
                    store_s(b, ea, v, 4, endian)
                },
            )?;
            if insn == Insn::FmovSStp {
                rset(b, ops[0], ea);
            }
        }
        Insn::FmovSD12Ld | Insn::FmovSD12St => {
            // SH-2A FPU の disp12 形式。disp は 4 倍スケール。
            // St: ops = [n(ベースR), m(FR), d]。Ld: ops = [n(FR),
            // m(ベースR), d]。
            let (fr_i, base_i) = if insn == Insn::FmovSD12Ld {
                (0usize, 1usize)
            } else {
                (1usize, 0usize)
            };
            let base = rget(b, ops[base_i]);
            let ea = add_n(b, base, ops[2] as u32 * 4);
            let sz_v = get_fpscr_bit(b, FPSCR_SZ);
            let sz = nz(b, sz_v);
            if insn == Insn::FmovSD12Ld {
                b.if_then_else(
                    sz,
                    |b| {
                        let dr = ops[fr_i] & 14;
                        let (hi, lo) = load2(b, ea, endian)?;
                        afr_set(b, dr, hi)?;
                        afr_set(b, dr + 1, lo)
                    },
                    |b| {
                        let v = load_s(b, ea, 4, true, endian)?;
                        afr_set(b, ops[fr_i], v)
                    },
                )?;
            } else {
                b.if_then_else(
                    sz,
                    |b| {
                        let dr = ops[fr_i] & 14;
                        let hi = afr_get(b, dr);
                        let lo = afr_get(b, dr + 1);
                        store_s(b, ea, hi, 4, endian)?;
                        let ea2 = add_n(b, ea, 4);
                        store_s(b, ea2, lo, 4, endian)
                    },
                    |b| {
                        let v = afr_get(b, ops[fr_i]);
                        store_s(b, ea, v, 4, endian)
                    },
                )?;
            }
        }
        Insn::FmovReg => {
            // fmov FRm,FRn — ビット転送。SZ=1 は対転送（FRn/FRn+1 の
            // 両方を動かす）。fmov 系の転送幅は SZ だけで決まり
            // PR は参照しない（SPEC-SUPERH-SH4 §6 fmov 項）。
            let sz_v = get_fpscr_bit(b, FPSCR_SZ);
            let pair = nz(b, sz_v);
            b.if_then_else(
                pair,
                |b| {
                    let n = ops[0] & 14;
                    let m = ops[1] & 14;
                    let hi = afr_get(b, m);
                    let lo = afr_get(b, m + 1);
                    afr_set(b, n, hi)?;
                    afr_set(b, n + 1, lo)
                },
                |b| {
                    let v = afr_get(b, ops[1]);
                    afr_set(b, ops[0], v)
                },
            )?;
        }
        Insn::Fadd | Insn::Fsub | Insn::Fmul | Insn::Fdiv => {
            // ops = [n, m]。PR=1 は DR ペアの倍精度（n/m は偶数基底
            // n&14）。それ以外は単精度。
            let pr_v = get_fpscr_bit(b, FPSCR_PR);
            let pr = nz(b, pr_v);
            b.if_then_else(
                pr,
                |b| {
                    let n = ops[0] & 14;
                    let m = ops[1] & 14;
                    let an = dr_get(b, n);
                    let am = dr_get(b, m);
                    let r = match insn {
                        Insn::Fadd => b.fadd::<F64>(an, am),
                        Insn::Fsub => b.fsub::<F64>(an, am),
                        Insn::Fmul => b.fmul::<F64>(an, am),
                        _ => b.fdiv::<F64>(an, am),
                    };
                    dr_set(b, n, r)
                },
                |b| {
                    let an_v = afr_get(b, ops[0]);
                    let am_v = afr_get(b, ops[1]);
                    let an: B::V<F32> = b.trunc(an_v);
                    let am: B::V<F32> = b.trunc(am_v);
                    let r = match insn {
                        Insn::Fadd => b.fadd::<F32>(an, am),
                        Insn::Fsub => b.fsub::<F32>(an, am),
                        Insn::Fmul => b.fmul::<F32>(an, am),
                        _ => b.fdiv::<F32>(an, am),
                    };
                    let v: B::V<W32> = b.zext(r);
                    afr_set(b, ops[0], v)
                },
            )?;
        }
        Insn::Fmac => {
            // FMAC は単精度固定（FRn += FR0*FRm。PR=1 でも単精度）。
            let an_v = afr_get(b, ops[0]);
            let am_v = afr_get(b, ops[1]);
            let a0v = afr_get(b, 0);
            let an: B::V<F32> = b.trunc(an_v);
            let am: B::V<F32> = b.trunc(am_v);
            let a0: B::V<F32> = b.trunc(a0v);
            let r = b.fmadd::<F32>(a0, am, an);
            let v: B::V<W32> = b.zext(r);
            afr_set(b, ops[0], v)?;
        }
        Insn::FcmpEq | Insn::FcmpGt => {
            // T = (Rn == Rm) / (Rn > Rm)。PR=1 は DR 比較。
            let pr_v = get_fpscr_bit(b, FPSCR_PR);
            let pr = nz(b, pr_v);
            let c = if_then_w(
                b,
                pr,
                |b| {
                    let an = dr_get(b, ops[0] & 14);
                    let am = dr_get(b, ops[1] & 14);
                    let cc = if insn == Insn::FcmpEq {
                        b.feq::<F64>(an, am)
                    } else {
                        b.flt::<F64>(am, an)
                    };
                    bval(b, cc)
                },
                |b| {
                    let an_v = afr_get(b, ops[0]);
                    let am_v = afr_get(b, ops[1]);
                    let an: B::V<F32> = b.trunc(an_v);
                    let am: B::V<F32> = b.trunc(am_v);
                    let cc = if insn == Insn::FcmpEq {
                        b.feq::<F32>(an, am)
                    } else {
                        b.flt::<F32>(am, an)
                    };
                    bval(b, cc)
                },
            );
            set_t(b, c);
        }
        Insn::Fsts => {
            // fsts fpul,FRn — FPUL を FRn へビット転送（単精度固定）。
            let v = b.get(fpul_ref());
            afr_set(b, ops[0], v)?;
        }
        Insn::Flds => {
            // flds FRm,fpul。
            let v = afr_get(b, ops[0]);
            b.set(fpul_ref(), v);
        }
        Insn::Float => {
            // float fpul,FRn。PR=1 は FPUL(i32)→DRn(倍精度)。
            let pr_v = get_fpscr_bit(b, FPSCR_PR);
            let pr = nz(b, pr_v);
            let x = b.get(fpul_ref());
            b.if_then_else(
                pr,
                |b| {
                    let r = b.fcvt_from_s32::<F64>(x, 0);
                    dr_set(b, ops[0] & 14, r)
                },
                |b| {
                    let r = b.fcvt_from_s32::<F32>(x, 0);
                    let v: B::V<W32> = b.zext(r);
                    afr_set(b, ops[0], v)
                },
            )?;
        }
        Insn::Ftrc => {
            // ftrc FRm,fpul（ゼロ方向切捨て）。PR=1 は DRm→i32。
            let pr_v = get_fpscr_bit(b, FPSCR_PR);
            let pr = nz(b, pr_v);
            let v = if_then_w(
                b,
                pr,
                |b| {
                    let a = dr_get(b, ops[0] & 14);
                    b.fcvt_s32::<F64>(a, 1)
                },
                |b| {
                    let av = afr_get(b, ops[0]);
                    let a: B::V<F32> = b.trunc(av);
                    b.fcvt_s32::<F32>(a, 1)
                },
            );
            b.set(fpul_ref(), v);
        }
        Insn::Fneg | Insn::Fabs | Insn::Fsqrt | Insn::Fldi0 | Insn::Fldi1 => {
            // PR=1 は DR ペア上の単項演算（FLDI は倍精度定数）。
            let pr_v = get_fpscr_bit(b, FPSCR_PR);
            let pr = nz(b, pr_v);
            b.if_then_else(
                pr,
                |b| {
                    let n = ops[0] & 14;
                    match insn {
                        Insn::Fldi0 => {
                            let z = k64(b, 0);
                            let r: B::V<F64> = b.trunc(z);
                            dr_set(b, n, r)
                        }
                        Insn::Fldi1 => {
                            let w = k64(b, 0x3ff0_0000_0000_0000);
                            let r: B::V<F64> = b.trunc(w);
                            dr_set(b, n, r)
                        }
                        Insn::Fneg => {
                            let w64: B::V<W64> = {
                                let v = dr_get(b, n);
                                b.trunc(v)
                            };
                            let sgn = k64(b, 0x8000_0000_0000_0000);
                            let v = b.xor(w64, sgn);
                            let r: B::V<F64> = b.trunc(v);
                            dr_set(b, n, r)
                        }
                        Insn::Fabs => {
                            let w64: B::V<W64> = {
                                let v = dr_get(b, n);
                                b.trunc(v)
                            };
                            let msk = k64(b, 0x7fff_ffff_ffff_ffff);
                            let v = b.and(w64, msk);
                            let r: B::V<F64> = b.trunc(v);
                            dr_set(b, n, r)
                        }
                        _ => {
                            let a = dr_get(b, n);
                            let r = b.fsqrt::<F64>(a);
                            dr_set(b, n, r)
                        }
                    }
                },
                |b| {
                    let v: B::V<W32> = match insn {
                        Insn::Fldi0 => k(b, 0),
                        Insn::Fldi1 => k(b, 0x3f80_0000),
                        Insn::Fneg => {
                            let a = afr_get(b, ops[0]);
                            let sgn = k(b, 0x8000_0000);
                            b.xor(a, sgn)
                        }
                        Insn::Fabs => {
                            let a = afr_get(b, ops[0]);
                            and_n(b, a, 0x7fff_ffff)
                        }
                        _ => {
                            let av = afr_get(b, ops[0]);
                            let a: B::V<F32> = b.trunc(av);
                            let r = b.fsqrt::<F32>(a);
                            b.zext(r)
                        }
                    };
                    afr_set(b, ops[0], v)
                },
            )?;
        }
        // ---- FP 特殊・変換 ----
        Insn::Fschg => {
            // FPSCR.SZ の反転（対転送モードの切替）。
            let sz = get_fpscr_bit(b, FPSCR_SZ);
            let one = k(b, 1);
            let v = b.xor(sz, one);
            set_fpscr_bit(b, FPSCR_SZ, v);
        }
        Insn::Fpchg => {
            // FPSCR.PR の反転（単/倍精度モード切替。SH-4A）。
            let pr = get_fpscr_bit(b, FPSCR_PR);
            let one = k(b, 1);
            let v = b.xor(pr, one);
            set_fpscr_bit(b, FPSCR_PR, v);
        }
        Insn::Frchg => {
            // FPSCR.FR の反転（FR↔XD バンクの切替）。
            let fr = get_fpscr_bit(b, FPSCR_FR);
            let one = k(b, 1);
            let v = b.xor(fr, one);
            set_fpscr_bit(b, FPSCR_FR, v);
        }
        Insn::Fcnvsd => {
            // fcnvsd fpul,DRn — FPUL の f32 を倍精度へ変換。
            // ops = [n3（DR 基底 = n3*2）]。
            let w = b.get(fpul_ref());
            let s: B::V<F32> = b.trunc(w);
            let d = b.fcvt_ff::<F32, F64>(s, 0);
            dr_set(b, ops[0] * 2, d)?;
        }
        Insn::Fcnvds => {
            // fcnvds DRn,fpul — 倍精度を f32 へ変換して FPUL へ。
            let d = dr_get(b, ops[0] * 2);
            let s = b.fcvt_ff::<F64, F32>(d, 0);
            let v: B::V<W32> = b.zext(s);
            b.set(fpul_ref(), v);
        }
        Insn::Fsca => {
            // fsca fpul,DRn — FPUL[15:0] を角度（1 周=65536）として
            // FR[2*n3]=sin、FR[2*n3+1]=cos（二つの単精度）。
            // Ref: SPEC-SUPERH-SH4 §10（FSCA）。
            // sin/cos は範囲折り畳み＋minimax 近似（Gap: GAP-0059 —
            // 専用ユニットの精度・速度は近似的）。
            let x = b.get(fpul_ref());
            let a = and_n(b, x, 0xffff);
            let af = b.fcvt_from_u32::<F32>(a, 0);
            // θ = a * (2π/65536)。
            let scale = kf(b, 0x38c9_0fdb); // 2π/65536 = 9.5874e-5
            let th = b.fmul::<F32>(af, scale);
            let (sn, cs) = fsca_sincos(b, th);
            let base = ops[0] * 2;
            let sv: B::V<W32> = b.zext(sn);
            let cv: B::V<W32> = b.zext(cs);
            afr_set(b, base, sv)?;
            afr_set(b, base + 1, cv)?;
        }
        Insn::Fsrra => {
            // fsrra FRn — 1/√FRn（単精度。FRn>0 前提）。
            let av = afr_get(b, ops[0]);
            let a: B::V<F32> = b.trunc(av);
            let one = kf(b, 0x3f80_0000);
            let s = b.fsqrt::<F32>(a);
            let r = b.fdiv::<F32>(one, s);
            let v: B::V<W32> = b.zext(r);
            afr_set(b, ops[0], v)?;
        }
        Insn::Fipr => {
            // fipr FVm,FVn — 内積を FVn[3] へ。ops=[fvn, fvm]
            // （2 ビット番号、基底は *4）。
            let n = ops[0] * 4;
            let m = ops[1] * 4;
            let a0 = fv_get(b, n, 0);
            let b0 = fv_get(b, m, 0);
            let a1 = fv_get(b, n, 1);
            let b1 = fv_get(b, m, 1);
            let a2 = fv_get(b, n, 2);
            let b2 = fv_get(b, m, 2);
            let a3 = fv_get(b, n, 3);
            let b3 = fv_get(b, m, 3);
            let q01 = b.fmul::<F32>(a1, b1);
            let p = b.fmadd::<F32>(a0, b0, q01);
            let p2 = b.fmadd::<F32>(a2, b2, p);
            let r = b.fmadd::<F32>(a3, b3, p2);
            let v: B::V<W32> = b.zext(r);
            afr_set(b, n + 3, v)?;
        }
        Insn::Ftrv => {
            // ftrv xmtrx,FVn — XD バンクの 4×4 行列（列優先）で
            // FVn を変換。ops=[fvn]。out[i] = Σ_j M[i+4j]·v[j]。
            // Ref: SPEC-SUPERH-SH4 §10（FTRV は XD0-15 の行列）。
            let n = ops[0] * 4;
            let v0 = fv_get(b, n, 0);
            let v1 = fv_get(b, n, 1);
            let v2 = fv_get(b, n, 2);
            let v3 = fv_get(b, n, 3);
            for i in 0..4u64 {
                let m0w = axd_get(b, i);
                let m1w = axd_get(b, i + 4);
                let m2w = axd_get(b, i + 8);
                let m3w = axd_get(b, i + 12);
                let m0: B::V<F32> = b.trunc(m0w);
                let m1: B::V<F32> = b.trunc(m1w);
                let m2: B::V<F32> = b.trunc(m2w);
                let m3: B::V<F32> = b.trunc(m3w);
                let q01 = b.fmul::<F32>(m1, v1);
                let p = b.fmadd::<F32>(m0, v0, q01);
                let p2 = b.fmadd::<F32>(m2, v2, p);
                let r = b.fmadd::<F32>(m3, v3, p2);
                let w: B::V<W32> = b.zext(r);
                afr_set(b, n + i, w)?;
            }
        }
    }
    Ok(true)
}

/// FSCA の sin/cos（θ ∈ [0, 2π)）。`backend` の実数演算だけで構成する:
/// θ を [-π/2, π/2] に折り畳んで cephes 系の minimax 多項式で近似する。
/// （専用ユニットの精密さではなく数値近似 — Gap: GAP-0059）
// Ref: SPEC-SUPERH-SH4 §10.
fn fsca_sincos<B: Backend>(b: &mut B, th: B::V<F32>) -> (B::V<F32>, B::V<F32>) {
    // 定数群（f32 ビット列）。
    const PI_2: u32 = 0x3fc9_0fdb; // π/2
    const PI: u32 = 0x4049_0fdb; // π
    const PI3_2: u32 = 0x4096_cbe4; // 3π/2
    const PI2: u32 = 0x40c9_0fdb; // 2π
    let hpi2 = kf(b, PI_2);
    let hpi = kf(b, PI);
    let h3pi2 = kf(b, PI3_2);
    let h2pi = kf(b, PI2);
    // θ' の区画: q0 = θ<π/2, q1 = θ<3π/2。
    let q0 = b.flt::<F32>(th, hpi2);
    let q1 = b.flt::<F32>(th, h3pi2);
    // x = θ≤π/2 ? θ : (θ≤3π/2 ? π-θ : θ-2π)。
    let x_mid = b.fsub::<F32>(hpi, th);
    let x_hi = b.fsub::<F32>(th, h2pi);
    let x = if_then_f(b, q0, |_| th, |b| if_then_f(b, q1, |_| x_mid, |_| x_hi));
    // sin の minimax: x + x³·(c1 + x²(c2 + x²(c3 + x²c4)))
    // （cephes — 係数は SPEC-SUPERH ではなく汎用の近似式。Gap: GAP-0059）
    let c1 = kf(b, 0xbe2a_aaab); // -0.16666667
    let c2 = kf(b, 0x3c08_89cd); // 0.00833216
    let c3 = kf(b, 0xb94c_cce7); // -0.00019515296
    let c4 = kf(b, 0x35de_6f97); // 4.0599948e-6
    let x2 = b.fmul::<F32>(x, x);
    let p = b.fmadd::<F32>(x2, c4, c3);
    let p2 = b.fmadd::<F32>(x2, p, c2);
    let p3 = b.fmadd::<F32>(x2, p2, c1);
    let x3 = b.fmul::<F32>(x2, x);
    let sn = b.fmadd::<F32>(x3, p3, x);
    // cos = sin(θ + π/2) を同じ折り畳みで。
    let th2 = b.fadd::<F32>(th, hpi2);
    // th2 を [0,2π) に畳む（th2≥2π なら引く）。θ<3π/2 では th2<2π。
    let wrap = b.flt::<F32>(th, h3pi2);
    let th2 = if_then_f(b, wrap, |_| th2, |b| b.fsub::<F32>(th2, h2pi));
    let cq0 = b.flt::<F32>(th2, hpi2);
    let cq1 = b.flt::<F32>(th2, h3pi2);
    let cx_mid = b.fsub::<F32>(hpi, th2);
    let cx_hi = b.fsub::<F32>(th2, h2pi);
    let cx = if_then_f(
        b,
        cq0,
        |_| th2,
        |b| if_then_f(b, cq1, |_| cx_mid, |_| cx_hi),
    );
    let cx2 = b.fmul::<F32>(cx, cx);
    let c4b = kf(b, 0x35de_6f97);
    let c3b = kf(b, 0xb94c_cce7);
    let c2b = kf(b, 0x3c08_89cd);
    let c1b = kf(b, 0xbe2a_aaab);
    let cp = b.fmadd::<F32>(cx2, c4b, c3b);
    let cp2 = b.fmadd::<F32>(cx2, cp, c2b);
    let cp3 = b.fmadd::<F32>(cx2, cp2, c1b);
    let cx3 = b.fmul::<F32>(cx2, cx);
    let cs = b.fmadd::<F32>(cx3, cp3, cx);
    (sn, cs)
}

/// `c ? f() : g()` — F32 版の 2 路選択。
fn if_then_f<B: Backend>(
    b: &mut B,
    c: B::B,
    f: impl FnOnce(&mut B) -> B::V<F32>,
    g: impl FnOnce(&mut B) -> B::V<F32>,
) -> B::V<F32> {
    let tv = f(b);
    let gv = g(b);
    b.select::<F32>(c, tv, gv)
}

/// `c ? f() : g()` — W32 版の 2 路選択。
fn if_then_w<B: Backend>(
    b: &mut B,
    c: B::B,
    f: impl FnOnce(&mut B) -> B::V<W32>,
    g: impl FnOnce(&mut B) -> B::V<W32>,
) -> B::V<W32> {
    let tv = f(b);
    let gv = g(b);
    b.select::<W32>(c, tv, gv)
}
