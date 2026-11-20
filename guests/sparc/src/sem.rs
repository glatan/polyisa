// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC の命令意味論。バックエンドに対して総称的に書く。
//!
//! 分岐は即時に飛ばず npc だけを書き換え、遅延スロットの1命令を
//! 実行してから `commit` で pc を npc に進める。遅延スロットの命令は
//! 分岐命令の pc + 4 からフェッチする（npc からではない）。分岐の
//! annul が立っているときは、`delay_slot` が遅延スロットの命令を
//! 実行しない。遅延スロット内の例外の `in_delay_slot` 修正は
//! 実行ループ側の責務で、ここでは `false` を置くだけである。
//! 見える out/local/in は CWP と `nwindows` パラメータで
//! レジスタファイル上の位置が変わる。SAVE は V7/V8 では CWP を
//! 1 減らし、V9 では 1 増やす（RESTORE はその逆）。ウィンドウの
//! あふれと不足は OS パーソナリティが再現する（段階 15 の SP12）。
//! V7/V8 は整数レジスタの演算を 32 ビットで、V9 は 64 ビットで行う
//! （`word64` パラメータ）。
//!
//! 出典は SPEC-SPARC-V7 (Solbourne 101482-00)、SPEC-SPARC-V8
//! (Version 8)、SPEC-SPARC-V9 (SAV09R1459912) である。
//! Ref: SPEC-SPARC-V7.
//! Ref: SPEC-SPARC-V8 (Version 8).
//! Ref: SPEC-SPARC-V9.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, F32, F64, Flow, StateArray, StateRef, W8, W16, W32, W64, Width};

use super::{CpuState, Insn};

/// 整数レジスタ番号。`g0`（番号 0）は読むと 0、書き込みは捨てる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。ウィンドウ内のレジスタは
    /// `phys_index` で物理番号を求めてから使う。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, g) + (self.0 as usize) * 8)
    }

    /// `g0` かどうか。
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// 浮動小数点レジスタ番号。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpr(pub u8);

impl Fpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + (self.0 as usize) * 8)
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

/// cwp を指す。
pub fn cwp_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cwp))
}

/// annul ビットを指す。1 のとき、次の遅延スロットは実行しない。
pub fn annul_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, annul))
}

/// V7/V8 の PSR を指す。
pub fn psr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, psr))
}

/// V9 の TSTATE を指す。
pub fn tstate_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, tstate))
}

/// V7/V8 の Y レジスタを指す。
pub fn y_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, y))
}

/// FSR を指す。
pub fn fsr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fsr))
}

/// V9 の GSR を指す。
pub fn gsr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, gsr))
}

/// V9 の %asi を指す。
pub fn asi_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, asi))
}

/// V9 の %fprs を指す。
pub fn fprs_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fprs))
}

/// 退避不要で進めるウィンドウ数（V9 CANSAVE 相当）を指す。
pub fn cansave_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cansave))
}

/// 復帰先があるウィンドウ数（V9 CANRESTORE 相当）を指す。
pub fn canrestore_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, canrestore))
}

/// V9 の %tick 基準を指す。
pub fn tick_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, tick))
}

/// トラップ種別（TBR.tt 相当）を指す。OS パーソナリティが
/// トラップ番号を読む場所。
pub fn tt_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, tt))
}

/// V9 の %ccr を指す。
pub fn ccr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ccr))
}

fn reg_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, g), 8)
}

/// `nwindows` パラメータの値。`Backend::param` が流し込まれていなければ
/// 宣言の既定値（8）になる。仕様上の範囲は 2 から 32 で、ここでは
/// ファイルが巡回する前提なので下限を確かめる。
/// Ref: SPEC-SPARC-V8 (Version 8) §The Windowed Integer Registers.
fn nwindows<B: Backend>(b: &mut B) -> u64 {
    let nw = u64::from(b.param::<super::NwindowsParam>());
    assert!(nw >= 2, "nwindows must be at least 2, got {nw}");
    nw
}

/// 見えるレジスタ番号を、CWP でずらした物理番号にする。0〜7 は
/// グローバル。in は次のウィンドウの out への別名なので、物理位置は
/// `cwp*16 + (reg-8)` を `nwindows*16` で折り返した場所にある。
/// V9 は SAVE で CWP が増えるため、ウィンドウ番号の向きを反転して
/// (`(nw-cwp) mod nw` を基底に) 同じ別名関係を保つ。
/// Ref: SPEC-SPARC-V8 (Version 8) §The Windowed Integer Registers;
///      SPEC-SPARC-V9 §The Windowed Integer Registers.
fn phys_index<B: Backend>(b: &mut B, reg: u8) -> B::V<W32> {
    if reg < 8 {
        return b.konst::<W32>(u32::from(reg));
    }
    let nw = nwindows(b);
    let cwp: B::V<W64> = b.get(cwp_ref());
    let off = b.konst::<W64>(u64::from(reg) - 8);
    let sixteen = b.konst::<W64>(16);
    let base = if b.param::<super::Word64Param>() {
        let nwv = b.konst::<W64>(nw);
        let rem = b.urem::<W64>(cwp, nwv);
        let rev = b.sub::<W64>(nwv, rem);
        let rev = b.urem::<W64>(rev, nwv);
        b.mul::<W64>(rev, sixteen)
    } else {
        b.mul::<W64>(cwp, sixteen)
    };
    let sum = b.add::<W64>(base, off);
    let span = b.konst::<W64>(nw * 16);
    let wrapped = b.urem::<W64>(sum, span);
    let eight = b.konst::<W64>(8);
    let phys = b.add::<W64>(eight, wrapped);
    b.trunc::<W64, W32>(phys)
}

/// 整数レジスタの読み出し。
fn read<B: Backend>(b: &mut B, r: Gpr) -> B::V<W64> {
    if r.is_zero() {
        b.konst::<W64>(0)
    } else {
        let idx = phys_index(b, r.0);
        b.get_indexed(reg_array(), idx)
    }
}

/// 整数レジスタの書き込み。`g0` への書き込みは捨てる。
fn write<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W64>) {
    if !rd.is_zero() {
        let idx = phys_index(b, rd.0);
        b.set_indexed(reg_array(), idx, v);
    }
}

/// 演算結果をモデルの語幅に包む。V7/V8 は 32 ビット、V9 は 64 ビット。
/// Ref: SPEC-SPARC-V9 §Integer Register Usage.
fn wmask<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    if b.param::<super::Word64Param>() {
        v
    } else {
        let lo = b.konst::<W64>(0xffff_ffff);
        b.and::<W64>(v, lo)
    }
}

/// 符号付き 32 ビット演算の結果を rd の値に包む。V7/V8 では下位
/// 32 ビット、V9 では符号拡張して 64 ビットの rd に書く。
/// 符号なし 32 ビット結果は `zmask`、全幅演算は `wmask` を使う。
/// Ref: SPEC-SPARC-V9 §Integer Register Usage.
fn emask<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    if b.param::<super::Word64Param>() {
        let lo = b.trunc::<W64, W32>(v);
        b.sext::<W32, W64>(lo)
    } else {
        wmask(b, v)
    }
}

/// 符号なし 32 ビット演算の結果を rd の値に包む。V7/V8 では下位
/// 32 ビット、V9 ではゼロ拡張して 64 ビットの rd に書く。
/// Ref: SPEC-SPARC-V9 §Integer Register Usage.
fn zmask<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    if b.param::<super::Word64Param>() {
        let lo = b.trunc::<W64, W32>(v);
        b.zext::<W32, W64>(lo)
    } else {
        wmask(b, v)
    }
}

/// CWP を `delta` 進め、ウィンドウ枚数で折り返す。
fn step_cwp<B: Backend>(b: &mut B, delta: u64) {
    let nw = nwindows(b);
    let cwp = b.get(cwp_ref());
    let d = b.konst::<W64>(delta);
    let sum = b.add::<W64>(cwp, d);
    let span = b.konst::<W64>(nw);
    let next = b.urem::<W64>(sum, span);
    b.set(cwp_ref(), next);
}

fn const_w64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

/// simm13 の符号拡張。
fn sext13(v: u64) -> i64 {
    sext(v, 13)
}

/// n ビット即値の符号拡張。
fn sext(v: u64, bits: u32) -> i64 {
    ((v as i64) << (64 - bits)) >> (64 - bits)
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

/// LDSTUB と SWAP の不可分アクセス。
const ATOMIC_RW: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::AtomicRw,
};

/// 3 オペランド形の第 2 ソース。レジスタ（i=0）か即値（i=1）。
#[derive(Clone, Copy)]
pub enum Src2 {
    /// `rs2` レジスタを読む。
    Reg(Gpr),
    /// 符号拡張済みの即値。
    Imm(i64),
}

fn src2<B: Backend>(b: &mut B, s: Src2) -> B::V<W64> {
    match s {
        Src2::Reg(r) => read(b, r),
        Src2::Imm(v) => const_w64(b, v as u64),
    }
}

fn false_b<B: Backend>(b: &mut B) -> B::B {
    let z = b.konst::<W64>(0);
    b.cmp::<W64>(Cmp::Ne, z, z)
}

fn inv_b<B: Backend>(b: &mut B, c: B::B) -> B::B {
    let t = b.konst::<W64>(1);
    let f = b.konst::<W64>(0);
    let s = b.select::<W64>(c, f, t);
    let z = b.konst::<W64>(0);
    b.cmp::<W64>(Cmp::Ne, s, z)
}

/// ICC の指定ビットが立っているか。`n` は PSR ICC のビット番号
/// （N=23, Z=22, V=21, C=20）。V9 では %ccr.icc の対応ビット
/// （N=3, Z=2, V=1, C=0）を読む。
fn icc_bit<B: Backend>(b: &mut B, n: u32) -> B::B {
    if b.param::<super::Word64Param>() {
        let ccr = b.get(ccr_ref());
        let m = b.konst::<W64>(1u64 << (n - 20));
        let masked = b.and::<W64>(ccr, m);
        let zero = b.konst::<W64>(0);
        return b.cmp::<W64>(Cmp::Ne, masked, zero);
    }
    let psr = b.get(psr_ref());
    let m = b.konst::<W32>(1u32 << n);
    let masked = b.and::<W32>(psr, m);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

/// ICC を更新する。N,Z は `res`（W32 の演算結果）から、V,C は引数の
/// 判定値から取る。V9 の XCC 更新は `set_cc` が併せて行う。
/// Ref: SPEC-SPARC-V8 (Version 8) §Processor Status Register.
fn set_icc<B: Backend>(b: &mut B, res: B::V<W32>, v: B::B, c: B::B) {
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let sh31 = b.konst::<W32>(31);
    let ns = b.shr_l::<W32>(res, sh31);
    let n = b.and::<W32>(ns, one);
    let isz = b.cmp::<W32>(Cmp::Eq, res, zero);
    let z = b.select::<W32>(isz, one, zero);
    let vv = b.select::<W32>(v, one, zero);
    let cv = b.select::<W32>(c, one, zero);
    let psr = b.get(psr_ref());
    let keep = b.konst::<W32>(0xFF0F_FFFF);
    let base = b.and::<W32>(psr, keep);
    let s23 = b.konst::<W32>(23);
    let s22 = b.konst::<W32>(22);
    let s21 = b.konst::<W32>(21);
    let s20 = b.konst::<W32>(20);
    let n23 = b.shl::<W32>(n, s23);
    let z22 = b.shl::<W32>(z, s22);
    let v21 = b.shl::<W32>(vv, s21);
    let c20 = b.shl::<W32>(cv, s20);
    let a = b.or::<W32>(n23, z22);
    let b2 = b.or::<W32>(v21, c20);
    let lo = b.or::<W32>(a, b2);
    let psr2 = b.or::<W32>(base, lo);
    b.set(psr_ref(), psr2);
}

/// cc 更新の共通処理。`res` は演算の全 64 ビット結果（rd に書く
/// 符号拡張後の値ではなく、拡張前の生の結果）。`v32`/`c32` は
/// 32 ビット演算の V/C、`v64`/`c64` は 64 ビット演算の V/C。
/// V7/V8 では PSR ICC に 32 ビット側を書く。V9 では %ccr の
/// ICC（下位 4 ビット、32 ビット演算の旗）と XCC（上位 4 ビット、
/// 64 ビット演算の旗）を両方更新する。
/// Ref: SPEC-SPARC-V9 §Condition Codes.
fn set_cc<B: Backend>(b: &mut B, res: B::V<W64>, v32: B::B, c32: B::B, v64: B::B, c64: B::B) {
    if !b.param::<super::Word64Param>() {
        let res32 = b.trunc::<W64, W32>(res);
        set_icc(b, res32, v32, c32);
        return;
    }
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
    // ICC の N,Z は下位 32 ビット、XCC の N,Z は全 64 ビットから。
    let r32 = b.trunc::<W64, W32>(res);
    let s31 = b.konst::<W32>(31);
    let ns = b.shr_l::<W32>(r32, s31);
    let one32 = b.konst::<W32>(1);
    let n32 = b.and::<W32>(ns, one32);
    let zero32 = b.konst::<W32>(0);
    let isz32 = b.cmp::<W32>(Cmp::Eq, r32, zero32);
    let z32 = b.select::<W32>(isz32, one32, zero32);
    let s63 = b.konst::<W64>(63);
    let ns64 = b.shr_l::<W64>(res, s63);
    let n64 = b.and::<W64>(ns64, one);
    let isz64 = b.cmp::<W64>(Cmp::Eq, res, zero);
    let z64 = b.select::<W64>(isz64, one, zero);
    let vv32 = b.select::<W64>(v32, one, zero);
    let cc32 = b.select::<W64>(c32, one, zero);
    let vv64 = b.select::<W64>(v64, one, zero);
    let cc64 = b.select::<W64>(c64, one, zero);
    let n32e = b.zext::<W32, W64>(n32);
    let z32e = b.zext::<W32, W64>(z32);
    // n64<<7 | z64<<6 | v64<<5 | c64<<4 | n32<<3 | z32<<2 | v32<<1 | c32
    let ccr = b.konst::<W64>(0);
    let or1 = |bb: &mut B, a: B::V<W64>, x: B::V<W64>, s: u64| -> B::V<W64> {
        let sh = bb.konst::<W64>(s);
        let t = bb.shl::<W64>(x, sh);
        bb.or::<W64>(a, t)
    };
    let a = or1(b, ccr, n64, 7);
    let a = or1(b, a, z64, 6);
    let a = or1(b, a, vv64, 5);
    let a = or1(b, a, cc64, 4);
    let a = or1(b, a, n32e, 3);
    let a = or1(b, a, z32e, 2);
    let a = or1(b, a, vv32, 1);
    let a = b.or::<W64>(a, cc32);
    b.set(ccr_ref(), a);
}

/// 加算の共通処理。`carry` が立っていれば ICC の C を足す（ADDX 系）。
/// `cc` が立っていれば N,Z,V,C を ICC に書く。V9 では XCC も更新
/// する（V/C は 64 ビット側で計算する）。
/// Ref: SPEC-SPARC-V8 (Version 8) §ADD, §ADDcc, §ADDX, §ADDXcc.
fn add_common<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, cc: bool, carry: bool) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let cin = if carry { icc_bit(b, 20) } else { false_b(b) };
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
    let cv = b.select::<W64>(cin, one, zero);
    let t = b.add::<W64>(x, y);
    let sum = b.add::<W64>(t, cv);
    let v = wmask(b, sum);
    write(b, rd, v);
    if cc {
        let x32 = b.trunc::<W64, W32>(x);
        let y32 = b.trunc::<W64, W32>(y);
        let (_r, cry, ovf) = b.add_with_carry::<W32>(x32, y32, cin);
        // XCC の V/C はオペランド全 64 ビットで計算する。
        let (_r, cry64, ovf64) = b.add_with_carry::<W64>(x, y, cin);
        set_cc(b, sum, ovf, cry, ovf64, cry64);
    }
    Ok(())
}

/// 減算の共通処理。`carry` が立っていれば ICC の C を借りる（SUBX 系）。
/// 旗は `x + !y + !C` の繰り上がりで求める。
/// Ref: SPEC-SPARC-V8 (Version 8) §SUB, §SUBcc, §SUBX, §SUBXcc.
fn sub_common<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, cc: bool, carry: bool) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let bin = if carry { icc_bit(b, 20) } else { false_b(b) };
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
    let bv = b.select::<W64>(bin, one, zero);
    let d = b.sub::<W64>(x, y);
    let diff = b.sub::<W64>(d, bv);
    let v = wmask(b, diff);
    write(b, rd, v);
    if cc {
        let nb = inv_b(b, bin);
        let x32 = b.trunc::<W64, W32>(x);
        let y32 = b.trunc::<W64, W32>(y);
        let iy = b.not::<W32>(y32);
        let (_r, cry, ovf) = b.add_with_carry::<W32>(x32, iy, nb);
        let borrow = inv_b(b, cry);
        // XCC の V/C はオペランド全 64 ビットで計算する。
        let iy64 = b.not::<W64>(y);
        let (_r, cry64, ovf64) = b.add_with_carry::<W64>(x, iy64, nb);
        let borrow64 = inv_b(b, cry64);
        set_cc(b, diff, ovf, borrow, ovf64, borrow64);
    }
    Ok(())
}

/// 論理演算の共通処理。`cc` 形は V,C を 0 にして N,Z を更新する。
/// Ref: SPEC-SPARC-V8 (Version 8) §AND, §ANDcc, §ANDN, §ANDNcc,
/// §OR, §ORcc, §ORN, §ORNcc, §XOR, §XORcc, §XNOR, §XNORcc.
#[derive(Clone, Copy)]
enum LOp {
    And,
    Andn,
    Or,
    Orn,
    Xor,
    Xnor,
}

fn logic_common<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, op: LOp, cc: bool) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let ny = b.not::<W64>(y);
    let t = match op {
        LOp::And => b.and::<W64>(x, y),
        LOp::Andn => b.and::<W64>(x, ny),
        LOp::Or => b.or::<W64>(x, y),
        LOp::Orn => b.or::<W64>(x, ny),
        LOp::Xor => b.xor::<W64>(x, y),
        LOp::Xnor => {
            let t = b.xor::<W64>(x, y);
            b.not::<W64>(t)
        }
    };
    let v = wmask(b, t);
    write(b, rd, v);
    if cc {
        let f = false_b(b);
        set_cc(b, t, f, f, f, f);
    }
    Ok(())
}

/// シフトの共通処理。rs1 の 32 ビットを下位 5 ビットの量で動かす。
/// レジスタ形・即値形のどちらでも量は 5 ビット。V9 でも 32 ビット
/// シフトはこの動作で、bit12 の x 桁は 0 に固定している。
/// Ref: SPEC-SPARC-V8 (Version 8) §SLL, §SRL, §SRA.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sh {
    Ll,
    Rl,
    Ra,
}

fn shift_common<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, sh: Sh) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let x32 = b.trunc::<W64, W32>(x);
    let m = b.konst::<W64>(31);
    let n = b.and::<W64>(y, m);
    let n32 = b.trunc::<W64, W32>(n);
    let r = match sh {
        Sh::Ll => b.shl::<W32>(x32, n32),
        Sh::Rl => b.shr_l::<W32>(x32, n32),
        Sh::Ra => b.shr_a::<W32>(x32, n32),
    };
    // V9 でも 32 ビットシフトは 32 ビット結果。sll/srl はゼロ拡張、
    // sra は符号拡張で rd に入る（QEMU translate.c の ext32u/ext32s
    // の使い分けに合わせる）。
    let e = if sh == Sh::Ra {
        b.sext::<W32, W64>(r)
    } else {
        b.zext::<W32, W64>(r)
    };
    let v = wmask(b, e);
    write(b, rd, v);
    Ok(())
}

/// 64 ビットシフトの共通処理（V9 の SLLX/SRLX/SRAX）。シフト量は
/// 下位 6 ビットで、即値形は shcnt6 桁がそのまま量になる。
/// Ref: SPEC-SPARC-V9 §Shift Instructions.
fn shiftx_common<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, sh: Sh) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let m = b.konst::<W64>(63);
    let n = b.and::<W64>(y, m);
    let r = match sh {
        Sh::Ll => b.shl::<W64>(x, n),
        Sh::Rl => b.shr_l::<W64>(x, n),
        Sh::Ra => b.shr_a::<W64>(x, n),
    };
    let v = wmask(b, r);
    write(b, rd, v);
    Ok(())
}

/// 乗算の共通処理。積の下位 32 ビットを rd、上位 32 ビットを Y に書く。
/// `signed` で SMUL/UMUL を分ける。`cc` 形は N,Z を更新し V,C を 0 にする。
/// Ref: SPEC-SPARC-V8 (Version 8) §UMUL, §SMUL, §UMULcc, §SMULcc.
fn mul_common<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs1: Gpr,
    s: Src2,
    signed: bool,
    cc: bool,
) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    if b.param::<super::Word64Param>() {
        // V9: rd には全 64 ビット積、Y には積の bit63-32 が入る。
        // Ref: SPEC-SPARC-V9 §UMUL §SMUL, QEMU translate.c gen_op_multiply.
        let x32 = b.trunc::<W64, W32>(x);
        let y32 = b.trunc::<W64, W32>(y);
        let (xe, ye) = if signed {
            (b.sext::<W32, W64>(x32), b.sext::<W32, W64>(y32))
        } else {
            (b.zext::<W32, W64>(x32), b.zext::<W32, W64>(y32))
        };
        let p = b.mul::<W64>(xe, ye);
        write(b, rd, p);
        let sh = b.konst::<W64>(32);
        let yv = b.shr_l::<W64>(p, sh);
        b.set(y_ref(), yv);
        if cc {
            let f = false_b(b);
            set_cc(b, p, f, f, f, f);
        }
        return Ok(());
    }
    let x32 = b.trunc::<W64, W32>(x);
    let y32 = b.trunc::<W64, W32>(y);
    let lo = b.mul::<W32>(x32, y32);
    let hi = if signed {
        b.mulh::<W32>(x32, y32)
    } else {
        b.mulhu::<W32>(x32, y32)
    };
    let e = b.sext::<W32, W64>(lo);
    let v = wmask(b, e);
    write(b, rd, v);
    let h64 = b.zext::<W32, W64>(hi);
    let hv = wmask(b, h64);
    b.set(y_ref(), hv);
    if cc {
        // XCC の N,Z は積全体（64 ビット）から取る。
        let l64 = b.zext::<W32, W64>(lo);
        let sh32 = b.konst::<W64>(32);
        let hs = b.shl::<W64>(h64, sh32);
        let p64 = b.or::<W64>(hs, l64);
        let f = false_b(b);
        set_cc(b, p64, f, f, f, f);
    }
    Ok(())
}

/// 除算の共通処理。被除数は {Y, rs1} の 64 ビット。商を rd に書く。
/// 仕様では除算後の Y は不定だが、本実装は剰余を格納する実装任意の
/// 選択肢を取る。`signed` で SDIV/UDIV を分ける。0 除算は division by
/// zero トラップ（V8 の 0x2a、V9 の 0x28）。`cc` 形は N,Z を商から、V を商の
/// オーバーフローから更新し、C を 0 にする。
/// Ref: SPEC-SPARC-V8 (Version 8) §UDIV, §SDIV, §UDIVcc, §SDIVcc.
fn div_common<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs1: Gpr,
    s: Src2,
    signed: bool,
    cc: bool,
) -> Flow<B> {
    let yv = src2(b, s);
    let dv = b.trunc::<W64, W32>(yv);
    let zero = b.konst::<W32>(0);
    let isz = b.cmp::<W32>(Cmp::Eq, dv, zero);
    let v9 = b.param::<super::Word64Param>();
    let code = if v9 { 0x28 } else { 0x2a };
    b.if_then(isz, |bb| {
        // division_by_zero。tt は V8 の 0x2a、V9 の 0x28。
        let tt = bb.konst::<W64>(code);
        bb.set(tt_ref(), tt);
        Err(bb.raise(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Trap,
            code,
            addr: None,
            in_delay_slot: false,
        }))
    })?;
    let x = read(b, rs1);
    let x32 = b.trunc::<W64, W32>(x);
    let yw = b.get(y_ref());
    let y32 = b.trunc::<W64, W32>(yw);
    let d64 = if signed {
        b.sext::<W32, W64>(dv)
    } else {
        b.zext::<W32, W64>(dv)
    };
    let x64 = b.zext::<W32, W64>(x32);
    let hi = if signed {
        b.sext::<W32, W64>(y32)
    } else {
        b.zext::<W32, W64>(y32)
    };
    let sh = b.konst::<W64>(32);
    let hi64 = b.shl::<W64>(hi, sh);
    let dvd = b.or::<W64>(hi64, x64);
    let (q, r) = if signed {
        (b.sdiv::<W64>(dvd, d64), b.srem::<W64>(dvd, d64))
    } else {
        (b.udiv::<W64>(dvd, d64), b.urem::<W64>(dvd, d64))
    };
    // 商が 32 ビットを超えるときは飽和させる。INT64_MIN / -1 は
    // バックエンドでは最小値に折り返すので、飽和方向は商の符号
    // （被除数と除数の符号が同じなら正）で決める。
    // Ref: SPEC-SPARC-V8 (Version 8) §SDIV §UDIV (overflow).
    let q32 = b.trunc::<W64, W32>(q);
    let back = if signed {
        b.sext::<W32, W64>(q32)
    } else {
        b.zext::<W32, W64>(q32)
    };
    let fits = b.cmp::<W64>(Cmp::Eq, q, back);
    let sat = if signed {
        let sh63 = b.konst::<W64>(63);
        let sd = b.shr_l::<W64>(dvd, sh63);
        let sr = b.shr_l::<W64>(d64, sh63);
        let same = b.cmp::<W64>(Cmp::Eq, sd, sr);
        let pos = b.konst::<W64>(0x7fff_ffff);
        let neg = b.konst::<W64>(0xffff_ffff_8000_0000);
        b.select::<W64>(same, pos, neg)
    } else {
        b.konst::<W64>(0xffff_ffff)
    };
    let qsat = b.select::<W64>(fits, q, sat);
    let v = if signed {
        emask(b, qsat)
    } else {
        zmask(b, qsat)
    };
    write(b, rd, v);
    let rm = wmask(b, r);
    b.set(y_ref(), rm);
    if cc {
        // V は商が 32 ビットに収まらないとき立つ。N,Z は格納した
        // （飽和後の）商から取る。
        let ovf = inv_b(b, fits);
        let f = false_b(b);
        set_cc(b, v, ovf, f, ovf, f);
    }
    Ok(())
}

/// MULScc。ソフトウェア乗算の 1 ステップ。op1 は rs1 を右に 1 シフトし
/// 最上位に (N xor V) を挿入したもの、op2 は Y<0> が立っていれば
/// operand2、そうでなければ 0。rd は op1 + op2。Y は rs1<0> を最上位に
/// 入れて右に 1 シフトしたもの。ICC は N,Z を結果から、V を加算の
/// オーバーフロー、C を繰り上がりから更新する。
/// Ref: SPEC-SPARC-V8 (Version 8) §MULScc.
pub fn mulscc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let x32 = b.trunc::<W64, W32>(x);
    let y32 = b.trunc::<W64, W32>(y);
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let sh31 = b.konst::<W32>(31);
    // op1 = r[rs1]<31:1> concat... ではなく (n XOR v) CONCAT r[rs1]<31:1>。
    let n = icc_bit(b, 23);
    let v = icc_bit(b, 21);
    let nb = b.select::<W32>(n, one, zero);
    let vb = b.select::<W32>(v, one, zero);
    let nv = b.xor::<W32>(nb, vb);
    let top = b.shl::<W32>(nv, sh31);
    let half = b.shr_l::<W32>(x32, one);
    let op1 = b.or::<W32>(half, top);
    // op2 = Y<0> が立っていれば operand2。
    let yw = b.get(y_ref());
    let yw32 = b.trunc::<W64, W32>(yw);
    let yl = b.and::<W32>(yw32, one);
    let useop = b.cmp::<W32>(Cmp::Ne, yl, zero);
    let op2 = b.select::<W32>(useop, y32, zero);
    let f0 = false_b(b);
    let (res, cry, ovf) = b.add_with_carry::<W32>(op1, op2, f0);
    let e = b.sext::<W32, W64>(res);
    let res64 = wmask(b, e);
    write(b, rd, res64);
    // Y = r[rs1]<0> CONCAT Y<31:1>
    let lsb = b.and::<W32>(x32, one);
    let top2 = b.shl::<W32>(lsb, sh31);
    let rest = b.shr_l::<W32>(yw32, one);
    let ny = b.or::<W32>(top2, rest);
    let ny64 = b.zext::<W32, W64>(ny);
    let nyv = wmask(b, ny64);
    b.set(y_ref(), nyv);
    set_cc(b, res64, ovf, cry, ovf, cry);
    Ok(())
}

/// ADD。
pub fn add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    add_common(b, rd, rs1, s, false, false)
}

/// ADDcc。
pub fn addcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    add_common(b, rd, rs1, s, true, false)
}

/// ADDX（キャリーイン付き加算）。
pub fn addx<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    add_common(b, rd, rs1, s, false, true)
}

/// ADDXcc。
pub fn addxcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    add_common(b, rd, rs1, s, true, true)
}

/// SUB。
pub fn sub<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    sub_common(b, rd, rs1, s, false, false)
}

/// SUBcc。
pub fn subcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    sub_common(b, rd, rs1, s, true, false)
}

/// SUBX（キャリーイン付き減算）。
pub fn subx<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    sub_common(b, rd, rs1, s, false, true)
}

/// SUBXcc。
pub fn subxcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    sub_common(b, rd, rs1, s, true, true)
}

/// AND。
pub fn and<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::And, false)
}

/// ANDcc。
pub fn andcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::And, true)
}

/// ANDN。
pub fn andn<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Andn, false)
}

/// ANDNcc。
pub fn andncc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Andn, true)
}

/// OR。
pub fn or<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Or, false)
}

/// ORcc。
pub fn orcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Or, true)
}

/// ORN。
pub fn orn<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Orn, false)
}

/// ORNcc。
pub fn orncc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Orn, true)
}

/// XOR。
pub fn xor<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Xor, false)
}

/// XORcc。
pub fn xorcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Xor, true)
}

/// XNOR。
pub fn xnor<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Xnor, false)
}

/// XNORcc。
pub fn xnorcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    logic_common(b, rd, rs1, s, LOp::Xnor, true)
}

/// UMUL（V8）。積の上位 32 ビットを Y に書く。
pub fn umul<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    mul_common(b, rd, rs1, s, false, false)
}

/// UMULcc（V8）。
pub fn umulcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    mul_common(b, rd, rs1, s, false, true)
}

/// SMUL（V8）。積の上位 32 ビットを Y に書く。
pub fn smul<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    mul_common(b, rd, rs1, s, true, false)
}

/// SMULcc（V8）。
pub fn smulcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    mul_common(b, rd, rs1, s, true, true)
}

/// UDIV（V8）。被除数は {Y, rs1}。剰余を Y に書く。
pub fn udiv<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    div_common(b, rd, rs1, s, false, false)
}

/// UDIVcc（V8）。
pub fn udivcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    div_common(b, rd, rs1, s, false, true)
}

/// SDIV（V8）。被除数は {Y, rs1}。剰余を Y に書く。
pub fn sdiv<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    div_common(b, rd, rs1, s, true, false)
}

/// SDIVcc（V8）。
pub fn sdivcc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    div_common(b, rd, rs1, s, true, true)
}

/// SLL。
pub fn sll<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    shift_common(b, rd, rs1, s, Sh::Ll)
}

/// SRL。
pub fn srl<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    shift_common(b, rd, rs1, s, Sh::Rl)
}

/// SRA。
pub fn sra<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    shift_common(b, rd, rs1, s, Sh::Ra)
}

/// SETHI。imm22 を上位に置く（rd = imm22 << 10）。V9 は 32 ビット目の
/// imm22 << 10 を書き、上位 32 ビットは 0 で埋める。分岐の
/// disp22 と違い sethi の定数は符号拡張しない。ゼロ拡張しないと
/// `sethi %hi(x)` で上位ビットを持つ 32 ビット定数を作れない。
/// Ref: SPEC-SPARC-V8 (Version 8) §SETHI.
/// Ref: SPEC-SPARC-V9 §SETHI.
pub fn sethi<B: Backend>(b: &mut B, rd: Gpr, imm22: u64) -> Flow<B> {
    let v32 = b.konst::<W32>((imm22 << 10) as u32);
    let s = b.zext::<W32, W64>(v32);
    let v = wmask(b, s);
    write(b, rd, v);
    Ok(())
}

/// 実効アドレス。rs1 + src2 をモデルの語幅で包む。V7/V8 のデータ
/// アクセスも 32 ビットアドレスなので `wmask` をかける。V9 では
/// PSTATE.AM のアドレスマスクも効く。
/// Ref: SPEC-SPARC-V8 (Version 8) §Load/Store Instructions.
fn eff_addr<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> B::V<W64> {
    let base = read(b, rs1);
    let off = src2(b, s);
    let sum = b.add::<W64>(base, off);
    let a = wmask(b, sum);
    amask(b, a)
}

/// ロードの共通処理。`se` が立っていれば符号拡張する。
/// Ref: SPEC-SPARC-V8 (Version 8) §Load Instructions.
fn ld_common<B: Backend, W: Width>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, se: bool) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    let v: B::V<W> = b.load::<W>(addr, DATA_READ)?;
    let w = if se {
        b.sext::<W, W64>(v)
    } else {
        b.zext::<W, W64>(v)
    };
    let m = wmask(b, w);
    write(b, rd, m);
    Ok(())
}

/// ストアの共通処理。rd の下位をそのまま格納する。
/// Ref: SPEC-SPARC-V8 (Version 8) §Store Instructions.
fn st_common<B: Backend, W: Width>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    let v = read(b, rd);
    let lo = b.trunc::<W64, W>(v);
    b.store::<W>(addr, lo, DATA_WRITE)?;
    Ok(())
}

/// LD（word。BE・自然整列）。
pub fn ld<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    ld_common::<B, W32>(b, rd, rs1, s, false)
}

/// LDUB（符号なしバイト）。
pub fn ldub<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    ld_common::<B, W8>(b, rd, rs1, s, false)
}

/// LDSB（符号付きバイト）。
pub fn ldsb<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    ld_common::<B, W8>(b, rd, rs1, s, true)
}

/// LDUH（符号なしハーフワード）。
pub fn lduh<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    ld_common::<B, W16>(b, rd, rs1, s, false)
}

/// LDSH（符号付きハーフワード）。
pub fn ldsh<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    ld_common::<B, W16>(b, rd, rs1, s, true)
}

/// LDD（ダブルワード。rd には上位（アドレス側）、rd2 には下位）。
/// rd は偶数でなければならない。奇数は illegal instruction として
/// 扱う（QEMU の gen_align_check と同じ）。
/// Ref: SPEC-SPARC-V8 (Version 8) §LDD.
pub fn ldd<B: Backend>(b: &mut B, rd: Gpr, rd2: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    if rd.0 & 1 != 0 {
        return Err(unimp(b, 0));
    }
    let addr = eff_addr(b, rs1, s);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    let sh32 = b.konst::<W64>(32);
    let hi = b.shr_l::<W64>(v, sh32);
    let mhi = wmask(b, hi);
    write(b, rd, mhi);
    // V9 でも各半分は 32 ビットワードとしてレジスタに入るので、
    // 語幅に関係なく 32 ビットで切って拡張する。
    let lo32 = b.trunc::<W64, W32>(v);
    let e = b.zext::<W32, W64>(lo32);
    let mlo = wmask(b, e);
    write(b, rd2, mlo);
    Ok(())
}

/// ST（word）。
pub fn st<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    st_common::<B, W32>(b, rd, rs1, s)
}

/// STB（バイト）。
pub fn stb<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    st_common::<B, W8>(b, rd, rs1, s)
}

/// STH（ハーフワード）。
pub fn sth<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    st_common::<B, W16>(b, rd, rs1, s)
}

/// STD（ダブルワード。rd が上位（アドレス側）、rd2 が下位）。
/// Ref: SPEC-SPARC-V8 (Version 8) §STD.
pub fn std<B: Backend>(b: &mut B, rd: Gpr, rd2: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    if rd.0 & 1 != 0 {
        return Err(unimp(b, 0));
    }
    let addr = eff_addr(b, rs1, s);
    let hi = read(b, rd);
    let hi32 = wmask(b, hi);
    let sh32 = b.konst::<W64>(32);
    let h = b.shl::<W64>(hi32, sh32);
    // V9 でも各半分は 32 ビットワードなので、rd2 の上位は捨てる。
    let lo = read(b, rd2);
    let lo32 = b.trunc::<W64, W32>(lo);
    let l = b.zext::<W32, W64>(lo32);
    let v = b.or::<W64>(h, l);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// LDSTUB。バイトを読み 0xFF を書き戻す不可分操作。
/// Ref: SPEC-SPARC-V8 (Version 8) §LDSTUB.
pub fn ldstub<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    b.probe(addr, 1, ATOMIC_RW)?;
    let v: B::V<W8> = b.load::<W8>(addr, ATOMIC_RW)?;
    let ff = b.konst::<W8>(0xff);
    b.store::<W8>(addr, ff, ATOMIC_RW)?;
    let w = b.zext::<W8, W64>(v);
    let m = wmask(b, w);
    write(b, rd, m);
    Ok(())
}

/// SWAP。メモリのワードと rd の下位 32 ビットを交換する不可分操作。
/// Ref: SPEC-SPARC-V8 (Version 8) §SWAP.
pub fn swap<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    b.probe(addr, 4, ATOMIC_RW)?;
    let v: B::V<W32> = b.load::<W32>(addr, ATOMIC_RW)?;
    let rv = read(b, rd);
    let rv32 = b.trunc::<W64, W32>(rv);
    b.store::<W32>(addr, rv32, ATOMIC_RW)?;
    let w = b.zext::<W32, W64>(v);
    let m = wmask(b, w);
    write(b, rd, m);
    Ok(())
}

/// LDSW（V9。符号付きワード → 64 ビット符号拡張）。
/// Ref: SPEC-SPARC-V9 §LDSW.
pub fn ldsw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    ld_common::<B, W32>(b, rd, rs1, s, true)
}

/// LDX（V9。ダブルワード、全 64 ビット）。
/// Ref: SPEC-SPARC-V9 §LDX.
pub fn ldx<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    write(b, rd, v);
    Ok(())
}

/// STX（V9。ダブルワード、全 64 ビット）。
/// Ref: SPEC-SPARC-V9 §STX.
pub fn stx<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    let v = read(b, rd);
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// JMPL。遅延スロット付きの間接分岐。戻り（pc）を `rd` に書き、
/// npc だけを書き換える。飛び先が 4 の倍数でないときの
/// mem_address_not_aligned トラップは後続ステップで検出する。
/// Ref: SPEC-SPARC-V8 (Version 8) §JMPL.
pub fn jmpl<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, pc: u64) -> Flow<B> {
    let base = read(b, rs1);
    let off = src2(b, s);
    let sum = b.add::<W64>(base, off);
    let m = wmask(b, sum);
    let target = amask(b, m);
    // PSTATE.AM 有効時は rd に書く戻り PC も上位 32 ビットが落ちる
    // (UltraSPARC impdep#125)。
    let ret = const_w64(b, pc);
    let ret = amask(b, ret);
    write(b, rd, ret);
    b.set(npc_ref(), target);
    Ok(())
}

/// CALL。遅延スロット付きの直接呼び出し。戻り（pc）を %o7 に書く。
/// `target` は pc + sign_extend(disp30 << 2)。
/// Ref: SPEC-SPARC-V8 (Version 8) §CALL.
pub fn call<B: Backend>(b: &mut B, pc: u64, target: u64) -> Flow<B> {
    let ret = const_w64(b, pc);
    let ret = amask(b, ret);
    write(b, Gpr(15), ret);
    let k = const_w64(b, target);
    let t = wmask(b, k);
    let t = amask(b, t);
    b.set(npc_ref(), t);
    Ok(())
}

/// 分岐の共通部。`val` は条件の評価値（0/1）。成立すれば npc は
/// `target`（pc + sign_extend(disp << 2)）、不成立なら pc + 8。
/// 不成立でも npc を進めるのは、遅延スロットが pc + 4 にあって
/// commit が pc を npc に写すためで、書き換えないと遅延スロットの
/// 命令を二度実行することになる。
/// `a` が立っているときの取り消し（annul）規則は 2 通りある。
/// 条件分岐は不成立のときだけ遅延スロットを取り消し、成立したら
/// `a` にかかわらず実行する。`always`（BA/BPA/FBA）は常に成立
/// するので `a` が立てば常に遅延スロットを取り消す。
/// Ref: SPEC-SPARC-V8 (Version 8) §Bicc; SPEC-SPARC-V9 §Branch.
fn branch_to<B: Backend>(
    b: &mut B,
    a: u8,
    val: B::V<W64>,
    always: bool,
    pc: u64,
    target: u64,
) -> Flow<B> {
    let zero = b.konst::<W64>(0);
    let taken = b.cmp::<W64>(Cmp::Ne, val, zero);
    let t = const_w64(b, target);
    let fall = const_w64(b, pc.wrapping_add(8));
    let s = b.select::<W64>(taken, t, fall);
    let npc = wmask(b, s);
    let npc = amask(b, npc);
    b.set(npc_ref(), npc);
    if a != 0 {
        // always は成立が確定しているので、annul の条件として
        // `taken`（常に真）をそのまま使う。それ以外は不成立のときだけ。
        let annul = if always {
            taken
        } else {
            b.cmp::<W64>(Cmp::Eq, val, zero)
        };
        b.if_then(annul, |bb| {
            let one = bb.konst::<W64>(1);
            bb.set(annul_ref(), one);
            Ok(())
        })?;
    }
    Ok(())
}

/// Bicc。ICC を評価して npc を書き換える。
/// Ref: SPEC-SPARC-V8 (Version 8) §Bicc.
pub fn bicc<B: Backend>(b: &mut B, a: u8, cond: u8, pc: u64, target: u64) -> Flow<B> {
    let val = cond_val(b, cond);
    branch_to(b, a, val, cond == 0b1000, pc, target)
}

/// BPcc。`cc` のビット 1（ビット 21）で XCC/ICC を選ぶ。
/// Ref: SPEC-SPARC-V9 §BPcc.
pub fn bpcc<B: Backend>(b: &mut B, a: u8, cond: u8, cc: u8, pc: u64, target: u64) -> Flow<B> {
    let val = cond_val_cc(b, cond, cc & 0b10 != 0);
    branch_to(b, a, val, cond == 0b1000, pc, target)
}

/// BPr。rs1 を符号付き 64 ビットの値として評価する。rcond は
/// 001=brz, 010=brlez, 011=brlz, 101=brnz, 110=brgz, 111=brgez。
/// 000/100 は予約で illegal instruction。
/// Ref: SPEC-SPARC-V9 §BPr.
pub fn bpr<B: Backend>(b: &mut B, a: u8, rcond: u8, rs1: Gpr, pc: u64, target: u64) -> Flow<B> {
    let r = read(b, rs1);
    let zero = b.konst::<W64>(0);
    let t = match rcond {
        0b001 => b.cmp::<W64>(Cmp::Eq, r, zero),
        0b010 => b.cmp::<W64>(Cmp::LeS, r, zero),
        0b011 => b.cmp::<W64>(Cmp::LtS, r, zero),
        0b101 => b.cmp::<W64>(Cmp::Ne, r, zero),
        0b110 => b.cmp::<W64>(Cmp::GtS, r, zero),
        0b111 => b.cmp::<W64>(Cmp::GeS, r, zero),
        _ => return Err(unimp(b, u64::from(rcond))),
    };
    let one = b.konst::<W64>(1);
    let val = b.select::<W64>(t, one, zero);
    branch_to(b, a, val, false, pc, target)
}

/// FBfcc。fcc0 を評価する。Bicc と同じ annul 規則。
/// Ref: SPEC-SPARC-V8 (Version 8) §FBfcc.
pub fn fbfcc<B: Backend>(b: &mut B, a: u8, cond: u8, pc: u64, target: u64) -> Flow<B> {
    let val = cond_val_f(b, cond, 0);
    branch_to(b, a, val, cond == 0b1000, pc, target)
}

/// FBPfcc。`bfcc`（0-3）が選ぶ fcc を評価する。
/// Ref: SPEC-SPARC-V9 §FBPfcc.
pub fn fbpfcc<B: Backend>(b: &mut B, a: u8, cond: u8, fcc: u8, pc: u64, target: u64) -> Flow<B> {
    let val = cond_val_f(b, cond, fcc);
    branch_to(b, a, val, cond == 0b1000, pc, target)
}

/// (n, z, v, c) の並び。
type CcBits<B> = (
    <B as Backend>::V<W64>,
    <B as Backend>::V<W64>,
    <B as Backend>::V<W64>,
    <B as Backend>::V<W64>,
);

/// 整数条件コードの (n, z, v, c) ビット。`xcc` が真なら V9 の
/// %ccr.xcc（ビット 7-4）、偽なら ICC。ICC は V9 では %ccr の
/// ビット 3-0、V7/V8 では PSR の ICC（23-20）を読む。
/// Ref: SPEC-SPARC-V9 §Condition Codes.
fn cc_bits<B: Backend>(b: &mut B, xcc: bool) -> CcBits<B> {
    let bit = |bb: &mut B, v: B::V<W64>, s: u64| -> B::V<W64> {
        let sh = bb.konst::<W64>(s);
        let one = bb.konst::<W64>(1);
        let x = bb.shr_l::<W64>(v, sh);
        bb.and::<W64>(x, one)
    };
    if xcc {
        let ccr = b.get(ccr_ref());
        (
            bit(b, ccr, 7),
            bit(b, ccr, 6),
            bit(b, ccr, 5),
            bit(b, ccr, 4),
        )
    } else if b.param::<super::Word64Param>() {
        let ccr = b.get(ccr_ref());
        (
            bit(b, ccr, 3),
            bit(b, ccr, 2),
            bit(b, ccr, 1),
            bit(b, ccr, 0),
        )
    } else {
        let psr = b.get(psr_ref());
        let p64 = b.zext::<W32, W64>(psr);
        (
            bit(b, p64, 23),
            bit(b, p64, 22),
            bit(b, p64, 21),
            bit(b, p64, 20),
        )
    }
}

/// 条件の評価値（ICC 選択）。0/1 の値で、0 なら不成立。
/// Ref: SPEC-SPARC-V8 (Version 8) §Instruction Descriptions (Bicc).
fn cond_val<B: Backend>(b: &mut B, cond: u8) -> B::V<W64> {
    cond_val_cc(b, cond, false)
}

/// 条件の評価値。`xcc` で V9 の XCC/ICC を選ぶ。各条件は値演算で
/// 組み立てる。
/// Ref: SPEC-SPARC-V8 (Version 8) §Instruction Descriptions (Bicc);
/// SPEC-SPARC-V9 §Condition Codes.
fn cond_val_cc<B: Backend>(b: &mut B, cond: u8, xcc: bool) -> B::V<W64> {
    let (n, z, v, c) = cc_bits(b, xcc);
    let one = b.konst::<W64>(1);
    let inv = |x: B::V<W64>, bb: &mut B| -> B::V<W64> {
        let o = bb.konst::<W64>(1);
        bb.xor::<W64>(x, o)
    };
    let zero = b.konst::<W64>(0);
    let nxv = b.xor::<W64>(n, v);
    let nz = b.not::<W64>(z); // 下位ビット以外も立つので and で 1 に留める
    let not_z = b.and::<W64>(nz, one);
    let nc = b.not::<W64>(c);
    let not_c = b.and::<W64>(nc, one);
    let not_nxv = inv(nxv, b);
    let not_n = inv(n, b);
    let not_v = inv(v, b);
    let le = b.or::<W64>(nxv, z);
    let bleu = b.or::<W64>(z, c);
    let g = b.and::<W64>(not_nxv, not_z);
    let gu = b.and::<W64>(not_c, not_z);
    match cond {
        0b0000 => zero,    // bn
        0b0001 => z,       // be
        0b0010 => le,      // ble
        0b0011 => nxv,     // bl
        0b0100 => bleu,    // bleu
        0b0101 => c,       // bcs
        0b0110 => n,       // bneg
        0b0111 => v,       // bvs
        0b1000 => one,     // ba
        0b1001 => not_z,   // bne
        0b1010 => g,       // bg
        0b1011 => not_nxv, // bge
        0b1100 => gu,      // bgu
        0b1101 => not_c,   // bcc
        0b1110 => not_n,   // bpos
        _ => not_v,        // bvc
    }
}

/// FCC の評価値。`fcc` は使用する条件コード（0-3 で fcc0-3）。
/// FCC は FSR のビット 10-11（fcc0）と 32-37（fcc1-3）。FCC 値は
/// 0=等しい、1=小さい、2=大きい、3=順序なし。`fcond` の下位 3 ビットで
/// 関係を選び、ビット 3 で否定する。FPU 演算は未実装だが FCC 桁は
/// 状態としてあるので評価だけは正確に行う。
/// Ref: SPEC-SPARC-V9 §Floating-Point Condition Codes.
fn cond_val_f<B: Backend>(b: &mut B, fcond: u8, fcc: u8) -> B::V<W64> {
    let fsr = b.get(fsr_ref());
    let sel = if fcc == 0 {
        10
    } else {
        30 + u64::from(fcc) * 2
    };
    let sh = b.konst::<W64>(sel);
    let x = b.shr_l::<W64>(fsr, sh);
    let three = b.konst::<W64>(3);
    let f = b.and::<W64>(x, three);
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let two = b.konst::<W64>(2);
    let fm1 = b.sub::<W64>(f, one);
    let fand1 = b.and::<W64>(f, one);
    let t = match fcond & 7 {
        0 => false_b(b),
        1 => b.cmp::<W64>(Cmp::Ne, f, zero),     // fne: f != 0
        2 => b.cmp::<W64>(Cmp::LeU, fm1, one),   // flg: f in {1,2}
        3 => b.cmp::<W64>(Cmp::Ne, fand1, zero), // ful: f in {1,3}
        4 => b.cmp::<W64>(Cmp::Eq, f, one),      // fl:  f == 1
        5 => b.cmp::<W64>(Cmp::GeU, f, two),     // fug: f in {2,3}
        6 => b.cmp::<W64>(Cmp::Eq, f, two),      // fg:  f == 2
        _ => b.cmp::<W64>(Cmp::Eq, f, three),    // fu:  f == 3
    };
    let t = if fcond & 8 == 0 { t } else { inv_b(b, t) };
    b.select::<W64>(t, one, zero)
}

/// V9 の PSTATE.AM（TSTATE ビット 11）が立っていればアドレスの
/// 上位 32 ビットを落とす。命令・データのどちらの仮想アドレスにも
/// 効く。V7/V8 では 32 ビットアドレスなので変化なし。
/// Ref: SPEC-SPARC-V9 §PSTATE.
fn amask<B: Backend>(b: &mut B, addr: B::V<W64>) -> B::V<W64> {
    if !b.param::<super::Word64Param>() {
        return addr;
    }
    let ts = b.get(tstate_ref());
    let sh = b.konst::<W64>(11);
    let s = b.shr_l::<W64>(ts, sh);
    let one = b.konst::<W64>(1);
    let am = b.and::<W64>(s, one);
    // am==1 なら 0xffffffff、0 なら全ビットのマスクをかける。
    let lo = b.konst::<W64>(0xffff_ffff);
    let amm1 = b.sub::<W64>(am, one);
    let m = b.or::<W64>(lo, amm1);
    b.and::<W64>(addr, m)
}
/// ウィンドウあふれ・不足トラップを上げる。tt は
/// V8 の window_overflow=0x05 / window_underflow=0x06、
/// V9 の spill_0_normal=0x80 / fill_0_normal=0xc0 とする。
/// WSTATE/OTHERWIN の区別は持たず、パーソナリティは tt の
/// 範囲（V9 では 0x80-0x9f / 0xc0-0xdf）で判定する。
/// Ref: SPEC-SPARC-V8 (Version 8) §Trap Type;
/// SPEC-SPARC-V9 §Trap Type.
fn window_trap<B: Backend>(b: &mut B, tt: u64) -> B::Exit {
    let v = b.konst::<W64>(tt);
    b.set(tt_ref(), v);
    b.raise(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Trap,
        code: tt,
        addr: None,
        in_delay_slot: false,
    })
}

/// ウィンドウカウンタを読み、0 のとき `tt` のトラップを上げる。
fn window_guard<B: Backend>(b: &mut B, counter: StateRef<W64>, tt: u64) -> Flow<B> {
    let n = b.get(counter);
    let zero = b.konst::<W64>(0);
    let empty = b.cmp::<W64>(Cmp::Eq, n, zero);
    b.if_then(empty, |bb| Err(window_trap(bb, tt)))?;
    Ok(())
}

/// ウィンドウカウンタを `delta` だけ増減する。
fn step_counter<B: Backend>(b: &mut B, counter: StateRef<W64>, delta: i64) {
    let n = b.get(counter);
    let d = b.konst::<W64>(delta as u64);
    let v = b.add::<W64>(n, d);
    b.set(counter, v);
}

/// SAVE。現ウィンドウで加算してから次のウィンドウへ移り、
/// 結果は移った先の rd へ書く。CANSAVE が 0 なら CWP を動かす前に
/// window_overflow（V9 では spill_*_normal）トラップを上げ、
/// 退避したパーソナリティが PC を戻して再実行する。
/// CWP の進行方向はモデルで逆で、V7/V8 では SAVE で減少、
/// V9 では SAVE で増加する。
/// Ref: SPEC-SPARC-V8 (Version 8) §SAVE; SPEC-SPARC-V9 §SAVE.
pub fn save<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let v9 = b.param::<super::Word64Param>();
    window_guard(b, cansave_ref(), if v9 { 0x80 } else { 0x05 })?;
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    let nw = nwindows(b);
    let delta = if v9 { 1 } else { nw - 1 };
    step_cwp(b, delta);
    step_counter(b, cansave_ref(), -1);
    step_counter(b, canrestore_ref(), 1);
    write(b, rd, v);
    Ok(())
}

/// RESTORE。現ウィンドウで加算し、CWP を SAVE とは逆方向に 1 進めて
/// から戻ったウィンドウへ書く（V7/V8 では増加、V9 では減少）。
/// CANRESTORE が 0 なら window_underflow（V9 では fill_*_normal）
/// トラップを上げる。
/// Ref: SPEC-SPARC-V8 (Version 8) §RESTORE; SPEC-SPARC-V9 §RESTORE.
pub fn restore<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let v9 = b.param::<super::Word64Param>();
    window_guard(b, canrestore_ref(), if v9 { 0xc0 } else { 0x06 })?;
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    let nw = nwindows(b);
    let delta = if v9 { nw - 1 } else { 1 };
    step_cwp(b, delta);
    step_counter(b, canrestore_ref(), -1);
    step_counter(b, cansave_ref(), 1);
    write(b, rd, v);
    Ok(())
}

/// SAVED。窓の退避を終えたことをカーネルが知らせる命令で、
/// CANSAVE を 1 増やし CANRESTORE を 1 減らす（otherwin は
/// モデルしないので常に 0 扱い）。
/// Ref: SPEC-SPARC-V9 §SAVED.
pub fn saved<B: Backend>(b: &mut B) -> Flow<B> {
    step_counter(b, cansave_ref(), 1);
    step_counter(b, canrestore_ref(), -1);
    Ok(())
}

/// RESTORED。窓の埋め戻しを終えたことをカーネルが知らせる命令で、
/// CANRESTORE を 1 増やし CANSAVE を 1 減らす。
/// Ref: SPEC-SPARC-V9 §RESTORED.
pub fn restored<B: Backend>(b: &mut B) -> Flow<B> {
    step_counter(b, canrestore_ref(), 1);
    step_counter(b, cansave_ref(), -1);
    Ok(())
}

/// UNIMP。illegal instruction トラップとして表す。
/// tt は V8 の 2、V9 の 0x10。code にはオペランドの imm22 を載せる。
/// Ref: SPEC-SPARC-V8 (Version 8) §UNIMP; SPEC-SPARC-V9 §Trap Type.
pub fn unimp<B: Backend>(b: &mut B, imm22: u64) -> B::Exit {
    let v9 = b.param::<super::Word64Param>();
    let two = b.konst::<W64>(if v9 { 0x10 } else { 2 });
    b.set(tt_ref(), two);
    b.raise(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Trap,
        code: u64::from(imm22 as u32),
        addr: None,
        in_delay_slot: false,
    })
}

/// Ticc。条件が成立すれば trap_instruction。トラップ番号は
/// 128 + ((rs1 + operand2) & 0x7f) で、実機では TBR の tt
/// フィールドに積まれる（V9 の Tcc は 0x100 + N）。例外の code は
/// 定数しか持てないため、番号は `tt` 状態に置いてから Trap を
/// 上げる。遅延スロットは持たない。
/// Ref: SPEC-SPARC-V8 (Version 8) §Ticc; SPEC-SPARC-V9 §Tcc.
pub fn ticc<B: Backend>(b: &mut B, cond: u8, xcc: bool, rs1: Gpr, s: Src2) -> Flow<B> {
    let val = cond_val_cc(b, cond, xcc);
    let zero = b.konst::<W64>(0);
    let taken = b.cmp::<W64>(Cmp::Ne, val, zero);
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let m = b.konst::<W64>(0x7f);
    let num = b.and::<W64>(sum, m);
    let v9 = b.param::<super::Word64Param>();
    let base = b.konst::<W64>(if v9 { 0x100 } else { 0x80 });
    let tt = b.add::<W64>(base, num);
    b.if_then(taken, |bb| {
        bb.set(tt_ref(), tt);
        Err(bb.raise(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Trap,
            code: 0,
            addr: None,
            in_delay_slot: false,
        }))
    })
}

/// RDY（rd %y, rd）。Y は 32 ビット。
/// Ref: SPEC-SPARC-V8 (Version 8) §RDY.
pub fn rdy<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let y = b.get(y_ref());
    let m = wmask(b, y);
    write(b, rd, m);
    Ok(())
}

/// WRY（wr rs1, operand2, %y）。書き込み値は XOR。Y は 32 ビット。
/// Ref: SPEC-SPARC-V8 (Version 8) §WRY.
pub fn wry<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let xored = b.xor::<W64>(x, y);
    let lo = b.trunc::<W64, W32>(xored);
    let v = b.zext::<W32, W64>(lo);
    b.set(y_ref(), v);
    Ok(())
}

/// RDCCR（rd %ccr, rd）。%ccr は 8 ビット（XCC+ICC）。
/// Ref: SPEC-SPARC-V9 §RDASR.
pub fn rdccr<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let c = b.get(ccr_ref());
    let m = b.konst::<W64>(0xff);
    let v = b.and::<W64>(c, m);
    write(b, rd, v);
    Ok(())
}

/// WRCCR（wr rs1, operand2, %ccr）。書き込み値は XOR の下位 8 ビット。
/// Ref: SPEC-SPARC-V9 §WRASR.
pub fn wrccr<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let xored = b.xor::<W64>(x, y);
    let m = b.konst::<W64>(0xff);
    let v = b.and::<W64>(xored, m);
    b.set(ccr_ref(), v);
    Ok(())
}

/// RDPC（rd %pc, rd）。命令自身の番地を rd に書く。
/// Ref: SPEC-SPARC-V9 §RDASR.
pub fn rdpc<B: Backend>(b: &mut B, rd: Gpr, pc: u64) -> Flow<B> {
    let v = const_w64(b, pc);
    let v = amask(b, v);
    write(b, rd, v);
    Ok(())
}

/// MULX。64 ビット積の下位 64 ビットを rd に書く。Y は使わない。
/// Ref: SPEC-SPARC-V9 §MULX.
pub fn mulx<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let p = b.mul::<W64>(x, y);
    let v = wmask(b, p);
    write(b, rd, v);
    Ok(())
}

/// V9 の 64 ビット除算。被除数は rs1（Y は使わない）。0 除算は
/// division_by_zero=0x28。`signed` で SDIVX/UDIVX を分ける。
/// Ref: SPEC-SPARC-V9 §UDIVX, §SDIVX.
fn divx_common<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, signed: bool) -> Flow<B> {
    let dv = src2(b, s);
    let zero = b.konst::<W64>(0);
    let isz = b.cmp::<W64>(Cmp::Eq, dv, zero);
    b.if_then(isz, |bb| {
        let tt = bb.konst::<W64>(0x28);
        bb.set(tt_ref(), tt);
        Err(bb.raise(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Trap,
            code: 0x28,
            addr: None,
            in_delay_slot: false,
        }))
    })?;
    let x = read(b, rs1);
    let q = if signed {
        b.sdiv::<W64>(x, dv)
    } else {
        b.udiv::<W64>(x, dv)
    };
    let v = wmask(b, q);
    write(b, rd, v);
    Ok(())
}

/// UDIVX。
pub fn udivx<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    divx_common(b, rd, rs1, s, false)
}

/// SDIVX。オーバーフロー時（2^63 / -1）の商はバックエンドの
/// 折り返し（2^63）がそのまま効く。
pub fn sdivx<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    divx_common(b, rd, rs1, s, true)
}

/// MOVcc。整数条件コード（cc=0 は ICC、cc=1 は XCC）で条件評価し、
/// 成立すれば operand2 を rd に転送する。オペランドは全幅。
/// Ref: SPEC-SPARC-V9 §MOVcc.
fn movcc<B: Backend>(b: &mut B, rd: Gpr, cond: u8, cc: u8, s: Src2) -> Flow<B> {
    let val = cond_val_cc(b, cond, cc != 0);
    let y = src2(b, s);
    let zero = b.konst::<W64>(0);
    let t = b.cmp::<W64>(Cmp::Ne, val, zero);
    let cur = read(b, rd);
    let v = b.select::<W64>(t, y, cur);
    write(b, rd, v);
    Ok(())
}

/// MOVfcc。浮動小数点条件コード（fcc0-3、2 ビットの `fcc` で選択）
/// で条件評価し、成立すれば operand2 を rd に転送する。
/// Ref: SPEC-SPARC-V9 §MOVfcc.
fn movfcc<B: Backend>(b: &mut B, rd: Gpr, fcond: u8, fcc: u8, s: Src2) -> Flow<B> {
    let val = cond_val_f(b, fcond, fcc);
    let y = src2(b, s);
    let zero = b.konst::<W64>(0);
    let t = b.cmp::<W64>(Cmp::Ne, val, zero);
    let cur = read(b, rd);
    let v = b.select::<W64>(t, y, cur);
    write(b, rd, v);
    Ok(())
}

/// MOVr/FMOVr の rcond 評価。`x` と 0 の比較。rcond:
/// 1=RZ, 2=RLEZ, 3=RLZ, 5=RNZ, 6=RGZ, 7=RGEZ。
/// Ref: SPEC-SPARC-V9 §MOVr.
fn rcond_cmp<B: Backend>(b: &mut B, x: B::V<W64>, rcond: u8) -> B::B {
    let zero = b.konst::<W64>(0);
    match rcond {
        1 => b.cmp::<W64>(Cmp::Eq, x, zero),
        2 => b.cmp::<W64>(Cmp::LeS, x, zero),
        3 => b.cmp::<W64>(Cmp::LtS, x, zero),
        5 => b.cmp::<W64>(Cmp::Ne, x, zero),
        6 => b.cmp::<W64>(Cmp::GtS, x, zero),
        _ => b.cmp::<W64>(Cmp::GeS, x, zero),
    }
}

/// MOVr。rs1 と 0 の比較結果で転送する。
/// rcond の 0 と 4 は予約で、exec 側で illegal instruction トラップに振る。
/// Ref: SPEC-SPARC-V9 §MOVr.
fn movr<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rcond: u8, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let t = rcond_cmp(b, x, rcond);
    let y = src2(b, s);
    let cur = read(b, rd);
    let v = b.select::<W64>(t, y, cur);
    write(b, rd, v);
    Ok(())
}

/// POPC。被演算子の立っているビット数を数える。
/// Ref: SPEC-SPARC-V9 §POPC.
fn popc<B: Backend>(b: &mut B, rd: Gpr, s: Src2) -> Flow<B> {
    let mut x = src2(b, s);
    // SWAR で 64 ビットを数える。
    let m55 = b.konst::<W64>(0x5555_5555_5555_5555);
    let one = b.konst::<W64>(1);
    let sh1 = b.shr_l::<W64>(x, one);
    let a = b.and::<W64>(sh1, m55);
    x = b.sub::<W64>(x, a);
    let m33 = b.konst::<W64>(0x3333_3333_3333_3333);
    let two = b.konst::<W64>(2);
    let sh2 = b.shr_l::<W64>(x, two);
    let lo = b.and::<W64>(x, m33);
    let hi = b.and::<W64>(sh2, m33);
    x = b.add::<W64>(lo, hi);
    let four = b.konst::<W64>(4);
    let sh4 = b.shr_l::<W64>(x, four);
    let s = b.add::<W64>(x, sh4);
    let m0f = b.konst::<W64>(0x0f0f_0f0f_0f0f_0f0f);
    x = b.and::<W64>(s, m0f);
    let mul = b.konst::<W64>(0x0101_0101_0101_0101);
    let p = b.mul::<W64>(x, mul);
    let s56 = b.konst::<W64>(56);
    let cnt = b.shr_l::<W64>(p, s56);
    write(b, rd, cnt);
    Ok(())
}

/// CASA/CASXA の共通処理。rd が比較値、rs2 が新値。メモリの値が
/// rd と等しければ rs2 を書き込み、rd には常に旧値が戻る。
/// ASI 指定形と %asi 形とも、本モデルのアドレス空間は一つしか
/// ないので通常空間へのアクセスに畳み込む（%asi レジスタは
/// ユーザーモードから書けず既定値に留まるため）。
/// Ref: SPEC-SPARC-V9 §CASA, §CASXA.
fn cas_common<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, wide: bool) -> Flow<B> {
    let base = read(b, rs1);
    let a = wmask(b, base);
    let addr = amask(b, a);
    // CAS の比較値は rs2、格納する新値は rd。rd にはメモリの
    // 旧値を返す。Ref: SPEC-SPARC-V9 §CASA/CASXA.
    let cmp = read(b, rs2);
    let newv = read(b, rd);
    if wide {
        b.probe(addr, 8, ATOMIC_RW)?;
        let old: B::V<W64> = b.load::<W64>(addr, ATOMIC_RW)?;
        let eq = b.cmp::<W64>(Cmp::Eq, old, cmp);
        b.if_then(eq, |bb| bb.store::<W64>(addr, newv, ATOMIC_RW))?;
        write(b, rd, old);
    } else {
        b.probe(addr, 4, ATOMIC_RW)?;
        let old: B::V<W32> = b.load::<W32>(addr, ATOMIC_RW)?;
        let c32 = b.trunc::<W64, W32>(cmp);
        let eq = b.cmp::<W32>(Cmp::Eq, old, c32);
        let n32 = b.trunc::<W64, W32>(newv);
        b.if_then(eq, |bb| bb.store::<W32>(addr, n32, ATOMIC_RW))?;
        let e = b.zext::<W32, W64>(old);
        let m = wmask(b, e);
        write(b, rd, m);
    }
    Ok(())
}

/// V9 の RETURN。JMPL と同じく rs1 + operand2 へ飛ぶ遅延スロット
/// 付き CTI だが、rd への戻り書き込みはしない。非特権命令。
/// Ref: SPEC-SPARC-V9 §RETURN.
pub fn ret<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> Flow<B> {
    // V9 の RETURN は RESTORE を内蔵する（遅延スロットは戻った窓で
    // 実行される）。CANRESTORE が 0 なら window_underflow（fill_*_normal）
    // トラップを上げる。
    // Ref: SPEC-SPARC-V9 §RETURN; QEMU translate.c do_return.
    window_guard(b, canrestore_ref(), 0xc0)?;
    let base = read(b, rs1);
    let off = src2(b, s);
    let sum = b.add::<W64>(base, off);
    let m = wmask(b, sum);
    let target = amask(b, m);
    let nw = nwindows(b);
    step_cwp(b, nw - 1);
    step_counter(b, canrestore_ref(), -1);
    step_counter(b, cansave_ref(), 1);
    b.set(npc_ref(), target);
    Ok(())
}

/// 観測可能な効果のない命令群。no-op で済ませる。
/// STBAR/MEMBAR は本モデルのストアが常に順序どおり見えるため、
/// FLUSH は命令キャッシュを持たないため、SAVED/RESTORED は
/// ウィンドウの帳尻管理が OS 側の約束で観測不能なため、
/// FLUSHW はウィンドウのメモリ退避をモデル化していないため、
/// いずれも状態を動かさない。
/// Ref: SPEC-SPARC-V9 §STBAR, §MEMBAR, §FLUSH, §SAVED, §FLUSHW.
pub fn nop<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

// ---- SP10: 浮動小数点 ----

/// FP が有効か確かめる。V7/V8 は PSR.EF（ビット 12）、V9 は
/// PSTATE.PEF（PSTATE 桁のビット 4、TSTATE ではビット 12）を見る。
/// 無効なら fp_disabled トラップ（V8 の 0x04、V9 の 0x20）。
/// FSR の cexc/aexc/tem による IEEE 例外機構は持たない。
/// Ref: SPEC-SPARC-V8 (Version 8) §The Floating-point Unit;
/// SPEC-SPARC-V9 §PSTATE, §Trap Type.
fn fp_check<B: Backend>(b: &mut B) -> Flow<B> {
    let v9 = b.param::<super::Word64Param>();
    let en = if v9 {
        // PEF（TSTATE bit12）と FPRS.FEF（bit2）の両方が要る。
        let ts = b.get(tstate_ref());
        let sh = b.konst::<W64>(12);
        let s = b.shr_l::<W64>(ts, sh);
        let one = b.konst::<W64>(1);
        let m = b.and::<W64>(s, one);
        let zero = b.konst::<W64>(0);
        let pef = b.cmp::<W64>(Cmp::Ne, m, zero);
        let fprs = b.get(fprs_ref());
        let fm = b.konst::<W64>(0b100);
        let f = b.and::<W64>(fprs, fm);
        let fef = b.cmp::<W64>(Cmp::Ne, f, zero);
        // FEF=0 なら fp_disabled。
        let fef_dis = inv_b(b, fef);
        b.if_then(fef_dis, |bb| {
            let tt = bb.konst::<W64>(0x20);
            bb.set(tt_ref(), tt);
            Err(bb.raise(polyisa_sem::GuestException {
                kind: polyisa_sem::ExceptionKind::Trap,
                code: 0x20,
                addr: None,
                in_delay_slot: false,
            }))
        })?;
        pef
    } else {
        let psr = b.get(psr_ref());
        let m = b.konst::<W32>(1 << 12);
        let masked = b.and::<W32>(psr, m);
        let zero = b.konst::<W32>(0);
        b.cmp::<W32>(Cmp::Ne, masked, zero)
    };
    let dis = inv_b(b, en);
    let code = if v9 { 0x20 } else { 0x04 };
    b.if_then(dis, |bb| {
        let tt = bb.konst::<W64>(code);
        bb.set(tt_ref(), tt);
        Err(bb.raise(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Trap,
            code,
            addr: None,
            in_delay_slot: false,
        }))
    })?;
    Ok(())
}

/// d 形命令の rd/rs 桁を f 配列のスロット番号に写す。
/// f 配列は 32 個の倍精度スロットを持ち、rd 桁の bit0 は番号の
/// bit4 を担う（%f32-%f62 偶数は bit0=1 の rd=1,3,...,31）。
/// 番号は (x>>1)|((x&1)<<4)。V8 は 16 スロットのみ有効。
/// Ref: SRC-QEMU extract_dfpreg, SPEC-SPARC-V9 §F Registers.
fn dreg_num<B: Backend>(b: &mut B, x: u8) -> u8 {
    if b.param::<super::Word64Param>() {
        (x >> 1) | ((x & 1) << 4)
    } else {
        (x >> 1) & 0xf
    }
}

/// 単精度 %fN の読み出し。スロット N>>1 の半分（N 偶数=上位
/// 32 ビット、奇数=下位 32 ビット）をゼロ拡張して返す。
/// Ref: SRC-QEMU gen_offset_fpr_F.
fn fget_single<B: Backend>(b: &mut B, n: u8) -> Result<B::V<W64>, B::Exit> {
    let v: B::V<W64> = b.get(Fpr(n >> 1).state());
    if n & 1 == 0 {
        let sh = b.konst::<W64>(32);
        Ok(b.shr_l::<W64>(v, sh))
    } else {
        let m = b.konst::<W64>(0xffff_ffff);
        Ok(b.and::<W64>(v, m))
    }
}

/// FPRS.DL（bit0）を立てる（QEMU gen_update_fprs_dirty）。
fn fprs_dl<B: Backend>(b: &mut B) {
    let f = b.get(fprs_ref());
    let one = b.konst::<W64>(1);
    let f = b.or::<W64>(f, one);
    b.set(fprs_ref(), f);
}

/// d 形命令の 64 ビット読み出し。`x` は rd/rs 桁の生の値。
/// Ref: SPEC-SPARC-V9 §Floating-Point Data Types.
fn fgetw64<B: Backend>(b: &mut B, x: u8) -> Result<B::V<W64>, B::Exit> {
    let d = dreg_num::<B>(b, x);
    Ok(b.get(Fpr(d).state()))
}

fn fputw64<B: Backend>(b: &mut B, x: u8, v: B::V<W64>) -> Result<(), B::Exit> {
    let d = dreg_num::<B>(b, x);
    b.set(Fpr(d).state(), v);
    fprs_dl(b);
    Ok(())
}

/// 単精度 %fN の書き込み。スロット N>>1 の半分だけを差し替える
/// （N 偶数=上位、奇数=下位）。FPRS.DL（bit0）を立てる
/// （QEMU gen_update_fprs_dirty）。
/// Ref: SRC-QEMU gen_offset_fpr_F.
fn fput_slot<B: Backend>(b: &mut B, n: u8, v: B::V<W64>) {
    let old = b.get(Fpr(n >> 1).state());
    let m32 = b.konst::<W64>(0xffff_ffff);
    let v32 = b.and::<W64>(v, m32);
    let (keep, hi) = if n & 1 == 0 {
        (0xffff_ffffu64, true)
    } else {
        (0xffff_ffff_0000_0000u64, false)
    };
    let kk = b.konst::<W64>(keep);
    let kept = b.and::<W64>(old, kk);
    let vv = if hi {
        let sh = b.konst::<W64>(32);
        b.shl::<W64>(v32, sh)
    } else {
        v32
    };
    let w = b.or::<W64>(kept, vv);
    b.set(Fpr(n >> 1).state(), w);
    fprs_dl(b);
}

/// f レジスタの読み出し。F32 は単精度 %fN の半分、F64 は
/// d 形の番号変換を通したスロット全体。
fn fget<B: Backend, F: Width>(b: &mut B, r: u8) -> Result<B::V<F>, B::Exit> {
    if F::BITS == 32 {
        let v = fget_single::<B>(b, r)?;
        Ok(b.trunc::<W64, F>(v))
    } else {
        let v = fgetw64(b, r)?;
        Ok(b.trunc::<W64, F>(v))
    }
}

fn fput<B: Backend, F: Width>(b: &mut B, r: u8, v: B::V<F>) -> Result<(), B::Exit> {
    let w = b.zext::<F, W64>(v);
    if F::BITS == 32 {
        fput_slot(b, r, w);
        Ok(())
    } else {
        fputw64(b, r, w)
    }
}

/// FCMP。fcc（eq=0, lt=1, gt=2, unordered=3）を FSR の fccN に
/// 書く。`sel` は V9 の fcc 番号（0-3）。V8 で sel が 0 でなければ
/// illegal instruction（fccn 桁は V8 では予約）。
/// fcmpE は unordered のとき fp_exception を起こすが、本モデルは
/// 例外フラグを持たないので fcc=3 を書くだけに畳む。
/// Ref: SPEC-SPARC-V8 (Version 8) §FCMP, §FCMPE; SPEC-SPARC-V9 §FCMP.
fn fcmp_common<B: Backend, F: Width>(b: &mut B, fs1: u8, fs2: u8, sel: u8) -> Flow<B> {
    if !b.param::<super::Word64Param>() && sel != 0 {
        return Err(unimp(b, 0));
    }
    fp_check(b)?;
    let a = fget::<B, F>(b, fs1)?;
    let c = fget::<B, F>(b, fs2)?;
    let eq = b.feq::<F>(a, c);
    let le = b.fle::<F>(a, c);
    let ge = b.fle::<F>(c, a);
    let zero = b.konst::<W64>(0);
    let one = b.konst::<W64>(1);
    let two = b.konst::<W64>(2);
    let three = b.konst::<W64>(3);
    // fcc = le ? (eq ? 0 : 1) : (ge ? 2 : 3)
    let lo = b.select::<W64>(eq, zero, one);
    let hi = b.select::<W64>(ge, two, three);
    let fcc = b.select::<W64>(le, lo, hi);
    // 書き込み位置。fcc0 は FSR ビット 10-11、V9 の fccN は
    // 30+2N（fcc1=32-33, fcc2=34-35, fcc3=36-37）。
    let pos = if b.param::<super::Word64Param>() && sel != 0 {
        u64::from(sel) * 2 + 30
    } else {
        10
    };
    let fsr = b.get(fsr_ref());
    let pm = b.konst::<W64>(0b11 << pos);
    let npm = b.not::<W64>(pm);
    let cleared = b.and::<W64>(fsr, npm);
    let pk = b.konst::<W64>(pos);
    let ins = b.shl::<W64>(fcc, pk);
    let m = b.or::<W64>(cleared, ins);
    b.set(fsr_ref(), m);
    Ok(())
}

/// 二項 FP 演算の選択肢。
#[derive(Clone, Copy)]
enum Fp3 {
    Add,
    Sub,
    Mul,
    Div,
}

/// FADDS/FADDD/FSUBS/FSUBD/FMULS/FMULD/FDIVS/FDIVD の共通処理。
/// 丸めはバックエンドの最近接偶数固定（FSR.RD の動的丸めは
/// バックエンドが静的な rm しか取れないため畳む）。
/// Ref: SPEC-SPARC-V8 (Version 8) §Floating-Point Add/Subtract/
/// Multiply/Divide.
fn fp3<B: Backend, F: Width>(b: &mut B, rd: u8, rs1: u8, rs2: u8, op: Fp3) -> Flow<B> {
    fp_check(b)?;
    let a = fget::<B, F>(b, rs1)?;
    let c = fget::<B, F>(b, rs2)?;
    let v = match op {
        Fp3::Add => b.fadd::<F>(a, c),
        Fp3::Sub => b.fsub::<F>(a, c),
        Fp3::Mul => b.fmul::<F>(a, c),
        Fp3::Div => b.fdiv::<F>(a, c),
    };
    fput::<B, F>(b, rd, v)?;
    Ok(())
}

/// FMOVS。単精度 %fN の 32 ビットをそのままコピーする。
/// Ref: SPEC-SPARC-V8 (Version 8) §FMOVS.
fn fmovs<B: Backend>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let v = fget_single::<B>(b, rs2)?;
    fput_slot(b, rd, v);
    Ok(())
}

/// FMOVD（V9）。スロット 2 個をコピーする。
/// Ref: SPEC-SPARC-V9 §FMOV.
fn fmovd<B: Backend>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let v = fgetw64(b, rs2)?;
    fputw64(b, rd, v)?;
    Ok(())
}

/// FNEGS/FABSS（`double`=false）と FNEGD/FABSD（`double`=true）。
/// 符号ビットは単精度なら値のビット 31、倍精度ならスロットの
/// ビット 63。`neg` なら反転、さもなくば消去。
/// Ref: SPEC-SPARC-V8 (Version 8) §FNEGS, §FABSS; SPEC-SPARC-V9 §FNEG, §FABS.
fn fsgn<B: Backend>(b: &mut B, rd: u8, rs2: u8, neg: bool, double: bool) -> Flow<B> {
    fp_check(b)?;
    if double {
        let v = fgetw64(b, rs2)?;
        let s = b.konst::<W64>(0x8000_0000_0000_0000);
        let w = if neg {
            b.xor::<W64>(v, s)
        } else {
            let n = b.not::<W64>(s);
            b.and::<W64>(v, n)
        };
        fputw64(b, rd, w)
    } else {
        let v = fget_single::<B>(b, rs2)?;
        let s = b.konst::<W64>(0x8000_0000);
        let w = if neg {
            b.xor::<W64>(v, s)
        } else {
            let n = b.not::<W64>(s);
            b.and::<W64>(v, n)
        };
        fput_slot(b, rd, w);
        Ok(())
    }
}

/// FSQRTS/FSQRTD。
/// Ref: SPEC-SPARC-V8 (Version 8) §FSQRTS, §FSQRTD.
fn fsqrt<B: Backend, F: Width>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fget::<B, F>(b, rs2)?;
    let v = b.fsqrt::<F>(a);
    fput::<B, F>(b, rd, v)?;
    Ok(())
}

/// 整数→浮動小数点（fitos/fitod/fxtos/fxtod）。ソースは f レジスタの
/// 生の整数値。FSR.RD の動的丸めはバックエンドの制約で
/// 最近接偶数に畳む。
/// Ref: SPEC-SPARC-V8 (Version 8) §Convert Integer to Floating;
/// SPEC-SPARC-V9 §Convert Integer to Floating.
fn i2f_common<B: Backend, F: Width>(b: &mut B, rd: u8, rs2: u8, wide: bool) -> Flow<B> {
    fp_check(b)?;
    let v = if wide {
        let w = fgetw64(b, rs2)?;
        b.fcvt_from_s64::<F>(w, 0)
    } else {
        let x = fget_single::<B>(b, rs2)?;
        let x32 = b.trunc::<W64, W32>(x);
        b.fcvt_from_s32::<F>(x32, 0)
    };
    fput::<B, F>(b, rd, v)
}

/// 浮動小数点→整数（fstoi/fdtoi/fstox/fdtox）。常に 0 方向丸め。
/// Ref: SPEC-SPARC-V8 (Version 8) §Convert Floating to Integer;
/// SPEC-SPARC-V9 §Convert Floating to Integer.
fn f2i_common<B: Backend, F: Width>(b: &mut B, rd: u8, rs2: u8, wide: bool) -> Flow<B> {
    fp_check(b)?;
    let a = fget::<B, F>(b, rs2)?;
    if wide {
        let v = b.fcvt_s64::<F>(a, 1);
        fputw64(b, rd, v)?;
    } else {
        let v = b.fcvt_s32::<F>(a, 1);
        let w = b.zext::<W32, W64>(v);
        fput_slot(b, rd, w);
    }
    Ok(())
}

/// 浮動小数点間変換（fstod/fdtos）。FSR.RD は最近接偶数に畳む。
/// Ref: SPEC-SPARC-V8 (Version 8) §Convert Between Floating-Point Formats.
fn f2f_common<B: Backend, F: Width, T: Width>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fget::<B, F>(b, rs2)?;
    let v = b.fcvt_ff::<F, T>(a, 0);
    fput::<B, T>(b, rd, v)?;
    Ok(())
}

/// FSMULD。単精度同士の積を倍精度で返す（精度ロスなし）。
/// Ref: SPEC-SPARC-V8 (Version 8) §FsMULd.
fn fsmuld<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fget::<B, F32>(b, rs1)?;
    let c = fget::<B, F32>(b, rs2)?;
    let a64 = b.fcvt_ff::<F32, F64>(a, 0);
    let c64 = b.fcvt_ff::<F32, F64>(c, 0);
    let v = b.fmul::<F64>(a64, c64);
    fput::<B, F64>(b, rd, v)?;
    Ok(())
}

/// 条件付き f レジスタコピーの共通処理。`t` が真なら rs2 の値を
/// rd に写し、偽なら rd を保つ。
fn fsel<B: Backend, F: Width>(b: &mut B, rd: u8, rs2: u8, t: B::B) -> Result<(), B::Exit> {
    let y = fget::<B, F>(b, rs2)?;
    let cur = fget::<B, F>(b, rd)?;
    let v = b.select::<F>(t, y, cur);
    fput::<B, F>(b, rd, v)
}

/// FMOVscc/FMOVdcc。整数条件コード（xcc=0 で ICC、1 で XCC）で
/// 条件評価して転送する。
/// Ref: SPEC-SPARC-V9 §FMOVcc.
fn fmovcc_common<B: Backend, F: Width>(b: &mut B, rd: u8, cond: u8, xcc: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let val = cond_val_cc(b, cond, xcc != 0);
    let zero = b.konst::<W64>(0);
    let t = b.cmp::<W64>(Cmp::Ne, val, zero);
    fsel::<B, F>(b, rd, rs2, t)
}

/// FMOVsfcc/FMOVdfcc。浮動小数点条件コードで評価して転送する。
/// Ref: SPEC-SPARC-V9 §FMOVfcc.
fn fmovfcc_common<B: Backend, F: Width>(b: &mut B, rd: u8, fcond: u8, fcc: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let val = cond_val_f(b, fcond, fcc);
    let zero = b.konst::<W64>(0);
    let t = b.cmp::<W64>(Cmp::Ne, val, zero);
    fsel::<B, F>(b, rd, rs2, t)
}

/// FMOVrs/FMOVrd。整数レジスタ rs1 を rcond で 0 と比較して転送する。
/// Ref: SPEC-SPARC-V9 §FMOVr.
fn fmovr_common<B: Backend, F: Width>(b: &mut B, rd: u8, rs1: u8, rcond: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let x = read(b, Gpr(rs1));
    let t = rcond_cmp(b, x, rcond);
    fsel::<B, F>(b, rd, rs2, t)
}

/// LDF。32 ビットを f レジスタへ読む。
/// Ref: SPEC-SPARC-V8 (Version 8) §LDF.
fn ldf<B: Backend>(b: &mut B, fd: u8, rs1: Gpr, s: Src2) -> Flow<B> {
    fp_check(b)?;
    let addr = eff_addr(b, rs1, s);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let w = b.zext::<W32, W64>(v);
    fput_slot(b, fd, w);
    Ok(())
}

/// LDDF。64 ビットを読み、上位ワードを偶数側（fd）、下位を fd+1
/// のスロットへ置く。
/// Ref: SPEC-SPARC-V8 (Version 8) §LDDF.
fn lddf<B: Backend>(b: &mut B, fd: u8, rs1: Gpr, s: Src2) -> Flow<B> {
    fp_check(b)?;
    let addr = eff_addr(b, rs1, s);
    let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    fputw64(b, fd, v)
}

/// STF。f レジスタの下位 32 ビットを書き出す。
/// Ref: SPEC-SPARC-V8 (Version 8) §STF.
fn stf<B: Backend>(b: &mut B, fs: u8, rs1: Gpr, s: Src2) -> Flow<B> {
    fp_check(b)?;
    let addr = eff_addr(b, rs1, s);
    let v = fget_single::<B>(b, fs)?;
    let w = b.trunc::<W64, W32>(v);
    b.store::<W32>(addr, w, DATA_WRITE)?;
    Ok(())
}

/// STDF。スロット 2 個を連結した 64 ビットを書き出す。
/// Ref: SPEC-SPARC-V8 (Version 8) §STDF.
fn stdf<B: Backend>(b: &mut B, fs: u8, rs1: Gpr, s: Src2) -> Flow<B> {
    fp_check(b)?;
    let addr = eff_addr(b, rs1, s);
    let v = fgetw64(b, fs)?;
    b.store::<W64>(addr, v, DATA_WRITE)?;
    Ok(())
}

/// LDFSR/LDXFSR。メモリから FSR を読む（ldfsr は 32 ビット、
/// V9 の ldxfsr は 64 ビット）。
/// Ref: SPEC-SPARC-V8 (Version 8) §LDFSR; SPEC-SPARC-V9 §LDXFSR.
fn ldfsr<B: Backend>(b: &mut B, rs1: Gpr, s: Src2, wide: bool) -> Flow<B> {
    fp_check(b)?;
    let addr = eff_addr(b, rs1, s);
    if wide {
        let v: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
        b.set(fsr_ref(), v);
    } else {
        let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
        let w = b.zext::<W32, W64>(v);
        // V9 の LDFSR は FSR[63:32]（fcc1-fcc3）を更新しない。
        let val = if b.param::<super::Word64Param>() {
            let cur = b.get(fsr_ref());
            let keep = b.konst::<W64>(0xffff_ffff_0000_0000);
            let upper = b.and::<W64>(cur, keep);
            b.or::<W64>(w, upper)
        } else {
            w
        };
        b.set(fsr_ref(), val);
    }
    Ok(())
}

/// STFSR/STXFSR。FSR をメモリへ書く。
/// Ref: SPEC-SPARC-V8 (Version 8) §STFSR; SPEC-SPARC-V9 §STXFSR.
fn stfsr<B: Backend>(b: &mut B, rs1: Gpr, s: Src2, wide: bool) -> Flow<B> {
    fp_check(b)?;
    let addr = eff_addr(b, rs1, s);
    let v = b.get(fsr_ref());
    if wide {
        b.store::<W64>(addr, v, DATA_WRITE)?;
    } else {
        let w = b.trunc::<W64, W32>(v);
        b.store::<W32>(addr, w, DATA_WRITE)?;
    }
    Ok(())
}

/// 特権系トラップの送出。V8 ではすべて privileged_instruction=3。
/// V9 は `action` で分け、特権命令の実行は privileged_opcode=0x11、
/// ユーザーモードからの特権操作（restricted ASI アクセスなど）は
/// privileged_action=0x37 を使う。
/// Ref: SPEC-SPARC-V8 (Version 8) §Trap Categories;
/// SPEC-SPARC-V9 §Trap Type.
fn privileged_trap<B: Backend>(b: &mut B, action: bool) -> B::Exit {
    let v9 = b.param::<super::Word64Param>();
    let code = if v9 {
        if action { 0x37 } else { 0x11 }
    } else {
        3
    };
    let t = b.konst::<W64>(code);
    b.set(tt_ref(), t);
    b.raise(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Trap,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

/// 特権命令をユーザーモードで実行したときの privileged トラップ。
/// tt は V8 の privileged_instruction=3、V9 の
/// privileged_opcode=0x11。このモデルはユーザーモードだけを扱うので、
/// rd/wr psr・wim・tbr、rett、V9 の done/retry は無条件にここへ来る。
/// Ref: SPEC-SPARC-V8 (Version 8) §Privileged Instructions;
/// SPEC-SPARC-V9 §Trap Type.
pub fn privileged<B: Backend>(b: &mut B) -> B::Exit {
    privileged_trap(b, false)
}

/// 特権レベルの判定。V7/V8 は PSR.S（ビット 7）、V9 は PSTATE.PRIV
/// （tstate ビット 10）を見る。非特権なら privileged トラップを上げる
/// （V8 の privileged_instruction=3、V9 の privileged_action=0x37）。
/// ASI 指定形が使う。
/// Ref: SPEC-SPARC-V8 (Version 8) §Privileged Instructions;
/// SPEC-SPARC-V9 §PSTATE.
fn privileged_check<B: Backend>(b: &mut B) -> Flow<B> {
    let sup = if b.param::<super::Word64Param>() {
        // TSTATE: GL|CCR|ASI|pil|PSTATE|CWP で、PSTATE.PRIV は
        // TSTATE ビット 10（PSTATE 桁のビット 2）にある。
        let ts = b.get(tstate_ref());
        let sh = b.konst::<W64>(10);
        let s = b.shr_l::<W64>(ts, sh);
        let one = b.konst::<W64>(1);
        b.and::<W64>(s, one)
    } else {
        let p = b.get(psr_ref());
        let p64 = b.zext::<W32, W64>(p);
        let sh = b.konst::<W64>(7);
        let s = b.shr_l::<W64>(p64, sh);
        let one = b.konst::<W64>(1);
        b.and::<W64>(s, one)
    };
    let zero = b.konst::<W64>(0);
    let user = b.cmp::<W64>(Cmp::Eq, sup, zero);
    b.if_then(user, |bb| Err(privileged_trap(bb, true)))
}

/// ASI 指定形の権限判定。V7/V8 はすべて特権。V9 は ASI が 0x80
/// 未満（restricted）のときだけ特権が要り、0x80 以上の
/// nonrestricted ASI はユーザーモードでもアクセスできる。
/// Ref: SPEC-SPARC-V9 §Address Space Identifiers.
fn asi_priv_check<B: Backend>(b: &mut B, asi: B::V<W64>) -> Flow<B> {
    if !b.param::<super::Word64Param>() {
        return privileged_check(b);
    }
    let lim = b.konst::<W64>(0x80);
    let restr = b.cmp::<W64>(Cmp::LtU, asi, lim);
    b.if_then(restr, |bb| privileged_check(bb))
}

/// 遅延スロット 1 命令ぶん。annul が 0 のときだけ `slot` を実行する。
/// annul ビットは実行前に消費するため、スロットが制御転送命令の
/// ときにその命令自身が立てる annul（DCTI couple）が残る。
/// commit は呼び出し側が行う。
pub fn delay_slot_exec<B: Backend>(b: &mut B, slot: impl FnOnce(&mut B) -> Flow<B>) -> Flow<B> {
    let annul = b.get(annul_ref());
    let zero = b.konst::<W64>(0);
    let run = b.cmp::<W64>(Cmp::Eq, annul, zero);
    b.set(annul_ref(), zero);
    b.if_then(run, slot)
}

/// 遅延スロットのステップ。annul が 0 のときだけ `slot` を実行し、
/// commit する。
pub fn delay_slot<B: Backend>(b: &mut B, slot: impl FnOnce(&mut B) -> Flow<B>) -> Flow<B> {
    delay_slot_exec(b, slot)?;
    commit(b)
}

/// 遅延スロットの実行後に pc を npc に進め、npc を +4 する。
pub fn commit<B: Backend>(b: &mut B) -> Flow<B> {
    let npc: B::V<W64> = b.get(npc_ref());
    b.set(pc_ref(), npc);
    let four = b.konst::<W64>(4);
    let sum = b.add::<W64>(npc, four);
    let m = wmask(b, sum);
    let next = amask(b, m);
    b.set(npc_ref(), next);
    Ok(())
}

/// デコードした命令の意味論。実行ループは `extract_ops` で得た
/// オペランド値を `exec` が語から取り出し、個別の意味論に振る。
/// `pc` は命令自身の pc（JMPL の戻りと分岐の基準）。
/// Ref: SPEC-SPARC-V8 (Version 8) §Instruction Descriptions.
pub fn exec<B: Backend>(b: &mut B, insn: Insn, word: u32, pc: u64) -> Flow<B> {
    let o = super::extract_ops(insn, u128::from(word));
    match insn {
        Insn::Add
        | Insn::Addcc
        | Insn::Addx
        | Insn::Addxcc
        | Insn::And
        | Insn::Andcc
        | Insn::Andn
        | Insn::Andncc
        | Insn::Or
        | Insn::Orcc
        | Insn::Orn
        | Insn::Orncc
        | Insn::Xor
        | Insn::Xorcc
        | Insn::Xnor
        | Insn::Xnorcc
        | Insn::Sub
        | Insn::Subcc
        | Insn::Subx
        | Insn::Subxcc
        | Insn::Umul
        | Insn::Umulcc
        | Insn::Smul
        | Insn::Smulcc
        | Insn::Udiv
        | Insn::Udivcc
        | Insn::Sdiv
        | Insn::Sdivcc
        | Insn::Mulscc
        | Insn::Sll
        | Insn::Srl
        | Insn::Sra
        | Insn::Mulx
        | Insn::Udivx
        | Insn::Sdivx
        | Insn::Sllx
        | Insn::Srlx
        | Insn::Srax
        | Insn::Jmpl
        | Insn::Save
        | Insn::Restore
        | Insn::Ld
        | Insn::Ldub
        | Insn::Ldsb
        | Insn::Lduh
        | Insn::Ldsh
        | Insn::Ldd
        | Insn::Ldstub
        | Insn::Swap
        | Insn::Ldsw
        | Insn::Ldx
        | Insn::Stx
        | Insn::St
        | Insn::Stb
        | Insn::Sth
        | Insn::Std => dispatch3(
            b,
            insn,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Src2::Reg(Gpr(o[2] as u8)),
            pc,
        ),
        Insn::AddI
        | Insn::AddccI
        | Insn::AddxI
        | Insn::AddxccI
        | Insn::AndI
        | Insn::AndccI
        | Insn::AndnI
        | Insn::AndnccI
        | Insn::OrI
        | Insn::OrccI
        | Insn::OrnI
        | Insn::OrnccI
        | Insn::XorI
        | Insn::XorccI
        | Insn::XnorI
        | Insn::XnorccI
        | Insn::SubI
        | Insn::SubccI
        | Insn::SubxI
        | Insn::SubxccI
        | Insn::UmulI
        | Insn::UmulccI
        | Insn::SmulI
        | Insn::SmulccI
        | Insn::UdivI
        | Insn::UdivccI
        | Insn::SdivI
        | Insn::SdivccI
        | Insn::MulsccI
        | Insn::SllI
        | Insn::SrlI
        | Insn::SraI
        | Insn::MulxI
        | Insn::UdivxI
        | Insn::SdivxI
        | Insn::SllxI
        | Insn::SrlxI
        | Insn::SraxI
        | Insn::JmplI
        | Insn::SaveI
        | Insn::RestoreI
        | Insn::LdI
        | Insn::LdubI
        | Insn::LdsbI
        | Insn::LduhI
        | Insn::LdshI
        | Insn::LddI
        | Insn::LdstubI
        | Insn::SwapI
        | Insn::LdswI
        | Insn::LdxI
        | Insn::StxI
        | Insn::StI
        | Insn::StbI
        | Insn::SthI
        | Insn::StdI => dispatch3(
            b,
            insn,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Src2::Imm(sext13(o[2])),
            pc,
        ),
        Insn::Sethi => sethi(b, Gpr(o[0] as u8), o[1]),
        Insn::Call => {
            // disp30 は符号拡張して <<2 の PC 相対。
            let disp = ((o[0] as i64) << 34) >> 34;
            let target = pc.wrapping_add((disp << 2) as u64);
            call(b, pc, target)
        }
        Insn::Bicc => {
            let a = o[0] as u8;
            let cond = o[1] as u8;
            let disp22 = ((o[2] as i64) << 42) >> 42;
            let target = pc.wrapping_add((disp22 << 2) as u64);
            bicc(b, a, cond, pc, target)
        }
        Insn::Bpcc => {
            // オペランドは (a, cond, cc, disp19)。
            let a = o[0] as u8;
            let cond = o[1] as u8;
            let cc = o[2] as u8;
            let disp19 = ((o[3] as i64) << 45) >> 45;
            let target = pc.wrapping_add((disp19 << 2) as u64);
            bpcc(b, a, cond, cc, pc, target)
        }
        Insn::Bpr => {
            // オペランドは (a, rcond, d16hi, rs1, d16lo)。
            let a = o[0] as u8;
            let rcond = o[1] as u8;
            let d16 = ((o[2] << 14) | o[4]) as i64;
            let disp16 = (d16 << 48) >> 48;
            let target = pc.wrapping_add((disp16 << 2) as u64);
            bpr(b, a, rcond, Gpr(o[3] as u8), pc, target)
        }
        Insn::Fbfcc => {
            let a = o[0] as u8;
            let cond = o[1] as u8;
            let disp22 = ((o[2] as i64) << 42) >> 42;
            let target = pc.wrapping_add((disp22 << 2) as u64);
            fbfcc(b, a, cond, pc, target)
        }
        Insn::Fbpfcc => {
            // オペランドは (a, cond, bfcc, disp19)。
            let a = o[0] as u8;
            let cond = o[1] as u8;
            let fcc = o[2] as u8;
            let disp19 = ((o[3] as i64) << 45) >> 45;
            let target = pc.wrapping_add((disp19 << 2) as u64);
            fbpfcc(b, a, cond, fcc, pc, target)
        }
        // ASI 指定形。オペランドは (rd, rs1, asi, rs2)。V8 では特権
        // 命令、V9 は ASI が 0x80 未満のときだけ特権が要る。
        // アドレス空間の選択は後続ステップで扱うため、ここでは
        // 通常空間へのアクセスに畳み込む。
        Insn::Lda
        | Insn::Lduba
        | Insn::Lduha
        | Insn::Ldda
        | Insn::Ldsba
        | Insn::Ldsha
        | Insn::Ldstuba
        | Insn::Ldswa
        | Insn::Ldxa
        | Insn::Stxa
        | Insn::Prefetch
        | Insn::Sta
        | Insn::Stba
        | Insn::Stha
        | Insn::Stda
        | Insn::Swapa => {
            let rd = Gpr(o[0] as u8);
            let rs1 = Gpr(o[1] as u8);
            let s = Src2::Reg(Gpr(o[3] as u8));
            let asi = const_w64(b, o[2]);
            asi_access(b, insn, rd, rs1, s, asi)
        }
        // FPU の ASI 指定形。rd は f レジスタ番号。
        Insn::Ldfa | Insn::Ldqfa | Insn::Lddfa | Insn::Stfa | Insn::Stqfa | Insn::Stdfa => {
            let fd = o[0] as u8;
            let rs1 = Gpr(o[1] as u8);
            let s = Src2::Reg(Gpr(o[3] as u8));
            let asi = const_w64(b, o[2]);
            fasi_access(b, insn, fd, rs1, s, asi)
        }
        // V9 の %asi 指定形（i=1。ASI は %asi レジスタから読む）。
        Insn::LdaI
        | Insn::LdubaI
        | Insn::LduhaI
        | Insn::LddaI
        | Insn::LdsbaI
        | Insn::LdshaI
        | Insn::LdstubaI
        | Insn::LdswaI
        | Insn::LdxaI
        | Insn::StxaI
        | Insn::PrefetchI
        | Insn::StaI
        | Insn::StbaI
        | Insn::SthaI
        | Insn::StdaI
        | Insn::SwapaI => {
            let rd = Gpr(o[0] as u8);
            let rs1 = Gpr(o[1] as u8);
            let s = Src2::Imm(sext13(o[2]));
            let asi = b.get(asi_ref());
            asi_access(b, insn, rd, rs1, s, asi)
        }
        // FPU の %asi 指定形。rd は f レジスタ番号。
        Insn::LdfaI | Insn::LdqfaI | Insn::LddfaI | Insn::StfaI | Insn::StqfaI | Insn::StdfaI => {
            let fd = o[0] as u8;
            let rs1 = Gpr(o[1] as u8);
            let s = Src2::Imm(sext13(o[2]));
            let asi = b.get(asi_ref());
            fasi_access(b, insn, fd, rs1, s, asi)
        }
        // Ticc/Tcc。オペランドは (cond, rs1, src2)。xcc 桁で
        // V9 の XCC を選ぶ形を分ける。
        Insn::Ticc => ticc(
            b,
            o[0] as u8,
            false,
            Gpr(o[1] as u8),
            Src2::Reg(Gpr(o[2] as u8)),
        ),
        Insn::TiccI => ticc(
            b,
            o[0] as u8,
            false,
            Gpr(o[1] as u8),
            Src2::Imm(sext(o[2], 7)),
        ),
        Insn::TccI => ticc(
            b,
            o[0] as u8,
            false,
            Gpr(o[1] as u8),
            Src2::Imm(sext(o[2], 7)),
        ),
        Insn::Tccx => ticc(
            b,
            o[0] as u8,
            true,
            Gpr(o[1] as u8),
            Src2::Reg(Gpr(o[2] as u8)),
        ),
        Insn::TccxI => ticc(
            b,
            o[0] as u8,
            true,
            Gpr(o[1] as u8),
            Src2::Imm(sext(o[2], 8)),
        ),
        // MOVcc（cc で ICC/XCC）と MOVfcc（fcc0-3）。
        // オペランドは (rd, cond, cc, src)。
        Insn::Movcc => movcc(
            b,
            Gpr(o[0] as u8),
            o[1] as u8,
            o[2] as u8,
            Src2::Reg(Gpr(o[3] as u8)),
        ),
        Insn::MovccI => movcc(
            b,
            Gpr(o[0] as u8),
            o[1] as u8,
            o[2] as u8,
            Src2::Imm(sext(o[3], 11)),
        ),
        Insn::Movfcc => movfcc(
            b,
            Gpr(o[0] as u8),
            o[1] as u8,
            o[2] as u8,
            Src2::Reg(Gpr(o[3] as u8)),
        ),
        Insn::MovfccI => movfcc(
            b,
            Gpr(o[0] as u8),
            o[1] as u8,
            o[2] as u8,
            Src2::Imm(sext(o[3], 11)),
        ),
        // MOVr。オペランドは (rd, rs1, rcond, src)。rcond 0/4 は
        // 予約で illegal instruction トラップ。
        Insn::Movr | Insn::MovrI => {
            let rcond = o[2] as u8;
            if !matches!(rcond, 1 | 2 | 3 | 5 | 6 | 7) {
                return Err(unimp(b, 0));
            }
            let s = if matches!(insn, Insn::MovrI) {
                Src2::Imm(sext(o[3], 10))
            } else {
                Src2::Reg(Gpr(o[3] as u8))
            };
            movr(b, Gpr(o[0] as u8), Gpr(o[1] as u8), rcond, s)
        }
        // POPC。被演算子は rs2 または simm13（rs1 桁は 0 固定）。
        Insn::Popc => popc(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::PopcI => popc(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        // CASA/CASXA。レジスタ形のオペランドは (rd, rs1, asi, rs2)、
        // %asi 形は (rd, rs1, rs2)。
        Insn::Casa => {
            let asi = const_w64(b, o[2]);
            asi_priv_check(b, asi)?;
            cas_common(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[3] as u8), false)
        }
        Insn::CasaI => {
            let asi = b.get(asi_ref());
            asi_priv_check(b, asi)?;
            cas_common(
                b,
                Gpr(o[0] as u8),
                Gpr(o[1] as u8),
                Gpr((o[2] & 0x1f) as u8),
                false,
            )
        }
        Insn::Casxa => {
            let asi = const_w64(b, o[2]);
            asi_priv_check(b, asi)?;
            cas_common(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[3] as u8), true)
        }
        Insn::CasxaI => {
            let asi = b.get(asi_ref());
            asi_priv_check(b, asi)?;
            cas_common(
                b,
                Gpr(o[0] as u8),
                Gpr(o[1] as u8),
                Gpr((o[2] & 0x1f) as u8),
                true,
            )
        }
        // V9 の RETURN。オペランドは (rs1, src2)。
        Insn::Return => ret(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::ReturnI => ret(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        // 観測可能な効果のない命令群。
        Insn::Stbar | Insn::Membar | Insn::Flush | Insn::FlushI => nop(b),
        // FLUSHW（命令）は V9 では特権。ユーザーモードで使う
        // flushw は `ta 3`（ST_FLUSH_WINDOWS トラップ）で、
        // パーソナリティが退避を再現する。
        Insn::Flushw => Err(privileged(b)),
        // SAVED/RESTORED は V9 では特権命令。ユーザーモードでは
        // privileged_opcode（0x11）。パーソナリティは `saved`/
        // `restored` を直接呼んで窓カウンタを戻す。
        Insn::Saved | Insn::Restored => Err(privileged(b)),
        // FP ロード/ストア。オペランドは (fd, rs1, src2)。
        Insn::Ldf => ldf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Reg(Gpr(o[2] as u8))),
        Insn::LdfI => ldf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Imm(sext13(o[2]))),
        Insn::Lddf => lddf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Reg(Gpr(o[2] as u8))),
        Insn::LddfI => lddf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Imm(sext13(o[2]))),
        Insn::Stf => stf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Reg(Gpr(o[2] as u8))),
        Insn::StfI => stf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Imm(sext13(o[2]))),
        Insn::Stdf => stdf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Reg(Gpr(o[2] as u8))),
        Insn::StdfI => stdf(b, o[0] as u8, Gpr(o[1] as u8), Src2::Imm(sext13(o[2]))),
        // FSR のロード/ストア。オペランドは (rs1, src2)。
        Insn::Ldfsr => ldfsr(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8)), false),
        Insn::LdfsrI => ldfsr(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1])), false),
        Insn::Ldxfsr => ldfsr(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8)), true),
        Insn::LdxfsrI => ldfsr(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1])), true),
        Insn::Stfsr => stfsr(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8)), false),
        Insn::StfsrI => stfsr(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1])), false),
        Insn::Stxfsr => stfsr(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8)), true),
        Insn::StxfsrI => stfsr(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1])), true),
        // FPop1 単項形。オペランドは (fd, fs2)。
        Insn::Fmovs => fmovs(b, o[0] as u8, o[1] as u8),
        Insn::Fmovd => fmovd(b, o[0] as u8, o[1] as u8),
        Insn::Fnegs => fsgn(b, o[0] as u8, o[1] as u8, true, false),
        Insn::Fnegd => fsgn(b, o[0] as u8, o[1] as u8, true, true),
        Insn::Fabss => fsgn(b, o[0] as u8, o[1] as u8, false, false),
        Insn::Fabsd => fsgn(b, o[0] as u8, o[1] as u8, false, true),
        Insn::Fsqrts => fsqrt::<B, F32>(b, o[0] as u8, o[1] as u8),
        Insn::Fsqrtd => fsqrt::<B, F64>(b, o[0] as u8, o[1] as u8),
        Insn::Fitos => i2f_common::<B, F32>(b, o[0] as u8, o[1] as u8, false),
        Insn::Fitod => i2f_common::<B, F64>(b, o[0] as u8, o[1] as u8, false),
        Insn::Fxtos => i2f_common::<B, F32>(b, o[0] as u8, o[1] as u8, true),
        Insn::Fxtod => i2f_common::<B, F64>(b, o[0] as u8, o[1] as u8, true),
        Insn::Fstoi => f2i_common::<B, F32>(b, o[0] as u8, o[1] as u8, false),
        Insn::Fdtoi => f2i_common::<B, F64>(b, o[0] as u8, o[1] as u8, false),
        Insn::Fstox => f2i_common::<B, F32>(b, o[0] as u8, o[1] as u8, true),
        Insn::Fdtox => f2i_common::<B, F64>(b, o[0] as u8, o[1] as u8, true),
        Insn::Fstod => f2f_common::<B, F32, F64>(b, o[0] as u8, o[1] as u8),
        Insn::Fdtos => f2f_common::<B, F64, F32>(b, o[0] as u8, o[1] as u8),
        // FPop1 二項形。オペランドは (fd, fs1, fs2)。
        Insn::Fadds => fp3::<B, F32>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Add),
        Insn::Faddd => fp3::<B, F64>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Add),
        Insn::Fsubs => fp3::<B, F32>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Sub),
        Insn::Fsubd => fp3::<B, F64>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Sub),
        Insn::Fmuls => fp3::<B, F32>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Mul),
        Insn::Fmuld => fp3::<B, F64>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Mul),
        Insn::Fdivs => fp3::<B, F32>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Div),
        Insn::Fdivd => fp3::<B, F64>(b, o[0] as u8, o[1] as u8, o[2] as u8, Fp3::Div),
        Insn::Fsmuld => fsmuld(b, o[0] as u8, o[1] as u8, o[2] as u8),
        // FCMP。オペランドは (fccn, fs1, fs2)。fcmpE も fcc を書くだけ。
        Insn::Fcmps | Insn::Fcmpes => fcmp_common::<B, F32>(b, o[1] as u8, o[2] as u8, o[0] as u8),
        Insn::Fcmpd | Insn::Fcmped => fcmp_common::<B, F64>(b, o[1] as u8, o[2] as u8, o[0] as u8),
        // V9 の FMOVcc/FMOVfcc。オペランドは (fd, cond, cc, fs2)。
        Insn::Fmovscc => fmovcc_common::<B, F32>(b, o[0] as u8, o[1] as u8, o[2] as u8, o[3] as u8),
        Insn::Fmovdcc => fmovcc_common::<B, F64>(b, o[0] as u8, o[1] as u8, o[2] as u8, o[3] as u8),
        Insn::Fmovsfcc => {
            fmovfcc_common::<B, F32>(b, o[0] as u8, o[1] as u8, o[2] as u8, o[3] as u8)
        }
        Insn::Fmovdfcc => {
            fmovfcc_common::<B, F64>(b, o[0] as u8, o[1] as u8, o[2] as u8, o[3] as u8)
        }
        // FMOVr。オペランドは (fd, rs1, rcond, fs2)。rcond 0/4 は予約。
        Insn::Fmovrs | Insn::Fmovrd => {
            let rcond = o[2] as u8;
            if !matches!(rcond, 1 | 2 | 3 | 5 | 6 | 7) {
                return Err(unimp(b, 0));
            }
            if matches!(insn, Insn::Fmovrs) {
                fmovr_common::<B, F32>(b, o[0] as u8, o[1] as u8, rcond, o[3] as u8)
            } else {
                fmovr_common::<B, F64>(b, o[0] as u8, o[1] as u8, rcond, o[3] as u8)
            }
        }
        // ---- VIS: 整数 3 項形（edge/array/alignaddr/bmask）。
        Insn::Edge8cc => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            8,
            false,
            true,
        ),
        Insn::Edge8lcc => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            8,
            true,
            true,
        ),
        Insn::Edge16cc => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            16,
            false,
            true,
        ),
        Insn::Edge16lcc => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            16,
            true,
            true,
        ),
        Insn::Edge32cc => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            32,
            false,
            true,
        ),
        Insn::Edge32lcc => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            32,
            true,
            true,
        ),
        Insn::Edge8n => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            8,
            false,
            false,
        ),
        Insn::Edge8ln => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            8,
            true,
            false,
        ),
        Insn::Edge16n => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            16,
            false,
            false,
        ),
        Insn::Edge16ln => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            16,
            true,
            false,
        ),
        Insn::Edge32n => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            32,
            false,
            false,
        ),
        Insn::Edge32ln => edge(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Gpr(o[2] as u8),
            32,
            true,
            false,
        ),
        Insn::Array8 => array(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8), 0),
        Insn::Array16 => array(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8), 1),
        Insn::Array32 => array(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8), 2),
        Insn::Alignaddr => alignaddr(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8), false),
        Insn::Alignaddrl => alignaddr(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8), true),
        Insn::Bmask => bmask(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8)),
        // ピクセル比較。オペランドは (gpr rd, f rs1, f rs2)。
        Insn::Fpcmple16 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 16, Cmp::LeS),
        Insn::Fpcmpne16 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 16, Cmp::Ne),
        Insn::Fpcmple32 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 32, Cmp::LeS),
        Insn::Fpcmpne32 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 32, Cmp::Ne),
        Insn::Fpcmpgt16 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 16, Cmp::GtS),
        Insn::Fpcmpeq16 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 16, Cmp::Eq),
        Insn::Fpcmpgt32 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 32, Cmp::GtS),
        Insn::Fpcmpeq32 => fpcmp(b, Gpr(o[0] as u8), o[1] as u8, o[2] as u8, 32, Cmp::Eq),
        // 乗算・パック・その他。オペランドはすべて f 番号。
        Insn::Fmul8x16 => fmul8x16(b, o[0] as u8, o[1] as u8, o[2] as u8),
        Insn::Fmul8x16au => fmul8x16a(b, o[0] as u8, o[1] as u8, o[2] as u8, true),
        Insn::Fmul8x16al => fmul8x16a(b, o[0] as u8, o[1] as u8, o[2] as u8, false),
        Insn::Fmul8sux16 => fmul8sux16(b, o[0] as u8, o[1] as u8, o[2] as u8, true),
        Insn::Fmul8ulx16 => fmul8sux16(b, o[0] as u8, o[1] as u8, o[2] as u8, false),
        Insn::Fmuld8sux16 => fmuld8x16(b, o[0] as u8, o[1] as u8, o[2] as u8, true),
        Insn::Fmuld8ulx16 => fmuld8x16(b, o[0] as u8, o[1] as u8, o[2] as u8, false),
        Insn::Fpack32 => fpack32(b, o[0] as u8, o[1] as u8, o[2] as u8),
        Insn::Fpack16 => fpack16(b, o[0] as u8, o[1] as u8),
        Insn::Fpackfix => fpackfix(b, o[0] as u8, o[1] as u8),
        Insn::Pdist => pdist(b, o[0] as u8, o[1] as u8, o[2] as u8),
        Insn::Faligndata => faligndata(b, o[0] as u8, o[1] as u8, o[2] as u8),
        Insn::Fpmerge => fpmerge(b, o[0] as u8, o[1] as u8, o[2] as u8),
        Insn::Fexpand => fexpand(b, o[0] as u8, o[1] as u8),
        Insn::Bshuffle => bshuffle(b, o[0] as u8, o[1] as u8, o[2] as u8),
        // 並列加減算。
        Insn::Fpadd16 => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 16, false, false),
        Insn::Fpadd16s => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 16, false, true),
        Insn::Fpadd32 => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 32, false, false),
        Insn::Fpadd32s => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 32, false, true),
        Insn::Fpsub16 => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 16, true, false),
        Insn::Fpsub16s => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 16, true, true),
        Insn::Fpsub32 => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 32, true, false),
        Insn::Fpsub32s => vparith(b, o[0] as u8, o[1] as u8, o[2] as u8, 32, true, true),
        // 論理演算・単項・定数。
        Insn::Fzero => vconst(b, o[0] as u8, false, false),
        Insn::Fzeros => vconst(b, o[0] as u8, false, true),
        Insn::Fone => vconst(b, o[0] as u8, true, false),
        Insn::Fones => vconst(b, o[0] as u8, true, true),
        Insn::Fsrc1 => vunary1(b, o[0] as u8, o[1] as u8, false, false),
        Insn::Fsrc1s => vunary1(b, o[0] as u8, o[1] as u8, false, true),
        Insn::Fnot1 => vunary1(b, o[0] as u8, o[1] as u8, true, false),
        Insn::Fnot1s => vunary1(b, o[0] as u8, o[1] as u8, true, true),
        Insn::Fsrc2 => vunary2(b, o[0] as u8, o[1] as u8, false, false),
        Insn::Fsrc2s => vunary2(b, o[0] as u8, o[1] as u8, false, true),
        Insn::Fnot2 => vunary2(b, o[0] as u8, o[1] as u8, true, false),
        Insn::Fnot2s => vunary2(b, o[0] as u8, o[1] as u8, true, true),
        Insn::Fnor => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Nor, false),
        Insn::Fnors => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Nor, true),
        Insn::Fandnot2 => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::AndNot2, false),
        Insn::Fandnot2s => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::AndNot2, true),
        Insn::Fandnot1 => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::AndNot1, false),
        Insn::Fandnot1s => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::AndNot1, true),
        Insn::Fxor => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Xor, false),
        Insn::Fxors => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Xor, true),
        Insn::Fnand => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Nand, false),
        Insn::Fnands => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Nand, true),
        Insn::Fand => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::And, false),
        Insn::Fands => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::And, true),
        Insn::Fxnor => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Xnor, false),
        Insn::Fxnors => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Xnor, true),
        Insn::Fornot2 => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::OrNot2, false),
        Insn::Fornot2s => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::OrNot2, true),
        Insn::Fornot1 => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::OrNot1, false),
        Insn::Fornot1s => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::OrNot1, true),
        Insn::For => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Or, false),
        Insn::Fors => vlogic(b, o[0] as u8, o[1] as u8, o[2] as u8, VLog::Or, true),
        // ASR。読み出し形のオペランドは rd、書き込み形は (rs1, src2)。
        Insn::Rdy => rdy(b, Gpr(o[0] as u8)),
        Insn::Wry => wry(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::WryI => wry(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        Insn::Wrasi => wrasi(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::WrasiI => wrasi(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        Insn::Wrfprs => wrfprs(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::WrfprsI => wrfprs(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        Insn::Wrgsr => wrgsr(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::WrgsrI => wrgsr(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        Insn::Rdasi => rdasi(b, Gpr(o[0] as u8)),
        Insn::Rdfprs => rdfprs(b, Gpr(o[0] as u8)),
        Insn::Rdgsr => rdgsr(b, Gpr(o[0] as u8)),
        Insn::Rdccr => rdccr(b, Gpr(o[0] as u8)),
        Insn::Wrccr => wrccr(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::WrccrI => wrccr(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        Insn::Rdpc => rdpc(b, Gpr(o[0] as u8), pc),
        // 特権命令はユーザーモードでは privileged_instruction トラップ。
        Insn::Rdpsr
        | Insn::Rdwim
        | Insn::Rdtbr
        | Insn::Wrpsr
        | Insn::WrpsrI
        | Insn::Wrwim
        | Insn::WrwimI
        | Insn::Wrtbr
        | Insn::WrtbrI
        | Insn::Rett
        | Insn::RettI
        | Insn::Done
        | Insn::Retry
        | Insn::Allclean
        | Insn::Otherw
        | Insn::Normalw
        | Insn::Invalw
        | Insn::Rdpr
        | Insn::Wrpr
        | Insn::WrprI => Err(privileged(b)),
        Insn::Unimp => Err(unimp(b, o[0])),
    }
}

fn dispatch3<B: Backend>(b: &mut B, insn: Insn, rd: Gpr, rs1: Gpr, s: Src2, pc: u64) -> Flow<B> {
    match insn {
        Insn::Add | Insn::AddI => add(b, rd, rs1, s),
        Insn::Addcc | Insn::AddccI => addcc(b, rd, rs1, s),
        Insn::Addx | Insn::AddxI => addx(b, rd, rs1, s),
        Insn::Addxcc | Insn::AddxccI => addxcc(b, rd, rs1, s),
        Insn::And | Insn::AndI => and(b, rd, rs1, s),
        Insn::Andcc | Insn::AndccI => andcc(b, rd, rs1, s),
        Insn::Andn | Insn::AndnI => andn(b, rd, rs1, s),
        Insn::Andncc | Insn::AndnccI => andncc(b, rd, rs1, s),
        Insn::Or | Insn::OrI => or(b, rd, rs1, s),
        Insn::Orcc | Insn::OrccI => orcc(b, rd, rs1, s),
        Insn::Orn | Insn::OrnI => orn(b, rd, rs1, s),
        Insn::Orncc | Insn::OrnccI => orncc(b, rd, rs1, s),
        Insn::Xor | Insn::XorI => xor(b, rd, rs1, s),
        Insn::Xorcc | Insn::XorccI => xorcc(b, rd, rs1, s),
        Insn::Xnor | Insn::XnorI => xnor(b, rd, rs1, s),
        Insn::Xnorcc | Insn::XnorccI => xnorcc(b, rd, rs1, s),
        Insn::Sub | Insn::SubI => sub(b, rd, rs1, s),
        Insn::Subcc | Insn::SubccI => subcc(b, rd, rs1, s),
        Insn::Subx | Insn::SubxI => subx(b, rd, rs1, s),
        Insn::Subxcc | Insn::SubxccI => subxcc(b, rd, rs1, s),
        Insn::Umul | Insn::UmulI => umul(b, rd, rs1, s),
        Insn::Umulcc | Insn::UmulccI => umulcc(b, rd, rs1, s),
        Insn::Smul | Insn::SmulI => smul(b, rd, rs1, s),
        Insn::Smulcc | Insn::SmulccI => smulcc(b, rd, rs1, s),
        Insn::Udiv | Insn::UdivI => udiv(b, rd, rs1, s),
        Insn::Udivcc | Insn::UdivccI => udivcc(b, rd, rs1, s),
        Insn::Sdiv | Insn::SdivI => sdiv(b, rd, rs1, s),
        Insn::Sdivcc | Insn::SdivccI => sdivcc(b, rd, rs1, s),
        Insn::Mulscc | Insn::MulsccI => mulscc(b, rd, rs1, s),
        Insn::Sll | Insn::SllI => sll(b, rd, rs1, s),
        Insn::Srl | Insn::SrlI => srl(b, rd, rs1, s),
        Insn::Sra | Insn::SraI => sra(b, rd, rs1, s),
        Insn::Mulx | Insn::MulxI => mulx(b, rd, rs1, s),
        Insn::Udivx | Insn::UdivxI => udivx(b, rd, rs1, s),
        Insn::Sdivx | Insn::SdivxI => sdivx(b, rd, rs1, s),
        Insn::Sllx | Insn::SllxI => shiftx_common(b, rd, rs1, s, Sh::Ll),
        Insn::Srlx | Insn::SrlxI => shiftx_common(b, rd, rs1, s, Sh::Rl),
        Insn::Srax | Insn::SraxI => shiftx_common(b, rd, rs1, s, Sh::Ra),
        Insn::Jmpl | Insn::JmplI => jmpl(b, rd, rs1, s, pc),
        Insn::Save | Insn::SaveI => save(b, rd, rs1, s),
        Insn::Restore | Insn::RestoreI => restore(b, rd, rs1, s),
        Insn::Ld | Insn::LdI => ld(b, rd, rs1, s),
        Insn::Ldub | Insn::LdubI => ldub(b, rd, rs1, s),
        Insn::Ldsb | Insn::LdsbI => ldsb(b, rd, rs1, s),
        Insn::Lduh | Insn::LduhI => lduh(b, rd, rs1, s),
        Insn::Ldsh | Insn::LdshI => ldsh(b, rd, rs1, s),
        Insn::Ldd | Insn::LddI => {
            let rd2 = Gpr(rd.0.wrapping_add(1) & 31);
            ldd(b, rd, rd2, rs1, s)
        }
        Insn::Ldsw | Insn::LdswI => ldsw(b, rd, rs1, s),
        Insn::Ldx | Insn::LdxI => ldx(b, rd, rs1, s),
        Insn::Stx | Insn::StxI => stx(b, rd, rs1, s),
        Insn::Ldstub | Insn::LdstubI => ldstub(b, rd, rs1, s),
        Insn::Swap | Insn::SwapI => swap(b, rd, rs1, s),
        Insn::St | Insn::StI => st(b, rd, rs1, s),
        Insn::Stb | Insn::StbI => stb(b, rd, rs1, s),
        Insn::Sth | Insn::SthI => sth(b, rd, rs1, s),
        Insn::Std | Insn::StdI => {
            let rd2 = Gpr(rd.0.wrapping_add(1) & 31);
            std(b, rd, rd2, rs1, s)
        }
        _ => unreachable!(),
    }
}

// ---- SP11: ユーザ ASI・VIS ----

/// ASI 指定形の共通処理。権限判定のあと、対応する通常形と同じ
/// 意味論を走らせる。アドレス空間の区別は後続ステップで扱う。
fn asi_access<B: Backend>(
    b: &mut B,
    insn: Insn,
    rd: Gpr,
    rs1: Gpr,
    s: Src2,
    asi: B::V<W64>,
) -> Flow<B> {
    asi_priv_check(b, asi)?;
    let rd2 = Gpr(rd.0.wrapping_add(1) & 31);
    match insn {
        Insn::Lda | Insn::LdaI => ld(b, rd, rs1, s),
        Insn::Lduba | Insn::LdubaI => ldub(b, rd, rs1, s),
        Insn::Lduha | Insn::LduhaI => lduh(b, rd, rs1, s),
        Insn::Ldda | Insn::LddaI => ldd(b, rd, rd2, rs1, s),
        Insn::Ldsba | Insn::LdsbaI => ldsb(b, rd, rs1, s),
        Insn::Ldsha | Insn::LdshaI => ldsh(b, rd, rs1, s),
        Insn::Ldstuba | Insn::LdstubaI => ldstub(b, rd, rs1, s),
        Insn::Ldswa | Insn::LdswaI => ldsw(b, rd, rs1, s),
        Insn::Ldxa | Insn::LdxaI => ldx(b, rd, rs1, s),
        Insn::Stxa | Insn::StxaI => stx(b, rd, rs1, s),
        Insn::Sta | Insn::StaI => st(b, rd, rs1, s),
        Insn::Stba | Insn::StbaI => stb(b, rd, rs1, s),
        Insn::Stha | Insn::SthaI => sth(b, rd, rs1, s),
        Insn::Stda | Insn::StdaI => std(b, rd, rd2, rs1, s),
        Insn::Swapa | Insn::SwapaI => swap(b, rd, rs1, s),
        Insn::Prefetch | Insn::PrefetchI => nop(b),
        _ => unreachable!(),
    }
}

/// 64 ビット値のバイト反転。
fn bswap64<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let mut out = b.konst::<W64>(0);
    let m = b.konst::<W64>(0xff);
    for i in 0..8u64 {
        let sh = b.konst::<W64>(i * 8);
        let byte = b.shr_l::<W64>(v, sh);
        let byte = b.and::<W64>(byte, m);
        let shl = b.konst::<W64>((7 - i) * 8);
        let w = b.shl::<W64>(byte, shl);
        out = b.or::<W64>(out, w);
    }
    out
}

/// BLK 系 ASI かどうかの判定。QEMU resolve_asi の一覧と同じ
/// 集合 {0x16,0x17,0x1e,0x1f,0x70,0x71,0x78,0x79,0xe0,0xe2,
/// 0xf0,0xf1,0xf8,0xf9} に絞る。
/// Ref: SPEC-SPARC-V9 §Block Load and Store, SRC-QEMU.
fn is_blk_asi<B: Backend>(b: &mut B, asi: B::V<W64>) -> B::B {
    let one = b.konst::<W64>(1);
    let z = b.konst::<W64>(0);
    // (asi & 0xf6) == {0x70,0xf0,0x16} で BLK/リトル形/4V 形を
    // 拾う。bit0・bit3 を落とした共通部分。
    let m = b.konst::<W64>(0xf6);
    let m = b.and::<W64>(asi, m);
    let mut acc = z;
    for k in [0x70u64, 0xf0, 0x16] {
        let k = b.konst::<W64>(k);
        let c = b.cmp::<W64>(Cmp::Eq, m, k);
        let v = b.select::<W64>(c, one, z);
        acc = b.or::<W64>(acc, v);
    }
    // BLK_COMMIT は {0xe0,0xe2}。bit1 だけを落とす。
    let m2 = b.konst::<W64>(0xfd);
    let m2 = b.and::<W64>(asi, m2);
    let ke0 = b.konst::<W64>(0xe0);
    let c = b.cmp::<W64>(Cmp::Eq, m2, ke0);
    let v = b.select::<W64>(c, one, z);
    let acc = b.or::<W64>(acc, v);
    b.cmp::<W64>(Cmp::Ne, acc, z)
}

/// LDDFA/STDFA の BLK 系 ASI 転送（64 バイト）。fd 桁は
/// extract_dfpreg（QEMU）で d 番号 R = (fd&0x1e)|((fd&1)<<5)
/// に写す。転送は連続する 8 個の倍精度スロット f[R/2 .. R/2+7]
/// なので、R は 8 の倍数かつ R ≤ 48（%d48 まで。%d56 から始めると
/// 8 個目が %d70 となり範囲を超える）でなければならない。
/// リトル ASI（asi の bit3）は各ダブルワードをバイト反転する。
/// Ref: SPEC-SPARC-V9 §Block Load and Store, SRC-QEMU.
fn fasi_blk<B: Backend>(
    b: &mut B,
    insn: Insn,
    fd: u8,
    rs1: Gpr,
    s: Src2,
    asi: B::V<W64>,
) -> Flow<B> {
    let r = if b.param::<super::Word64Param>() {
        (fd & 0x1e) | ((fd & 1) << 5)
    } else {
        fd & 0x1e
    };
    if r & 7 != 0 || r > 48 {
        return Err(unimp(b, 0));
    }
    let d0 = r >> 1;
    let addr = eff_addr(b, rs1, s);
    // ブロック転送は 64 バイト整列が要る（QEMU の
    // gen_check_align）。メモリ層の自然整列検査では 8 バイトまで
    // しか見ないので、ここで 64 バイト境界を確かめる。
    let m = b.konst::<W64>(0x3f);
    let mis = b.and::<W64>(addr, m);
    let z0 = b.konst::<W64>(0);
    let bad = b.cmp::<W64>(Cmp::Ne, mis, z0);
    b.if_then(bad, |bb| {
        Err(bb.raise(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Align,
            code: 0,
            addr: None,
            in_delay_slot: false,
        }))
    })?;
    let eight = b.konst::<W64>(8);
    let lit = b.and::<W64>(asi, eight);
    let z = b.konst::<W64>(0);
    let little = b.cmp::<W64>(Cmp::Ne, lit, z);
    match insn {
        Insn::Lddfa | Insn::LddfaI => {
            for i in 0..8u8 {
                let off = b.konst::<W64>(u64::from(i) * 8);
                let a = b.add::<W64>(addr, off);
                let v: B::V<W64> = b.load::<W64>(a, DATA_READ)?;
                let sw = bswap64(b, v);
                let v = b.select::<W64>(little, sw, v);
                b.set(Fpr(d0 + i).state(), v);
            }
            fprs_dl(b);
            Ok(())
        }
        Insn::Stdfa | Insn::StdfaI => {
            for i in 0..8u8 {
                let v: B::V<W64> = b.get(Fpr(d0 + i).state());
                let sw = bswap64(b, v);
                let v = b.select::<W64>(little, sw, v);
                let off = b.konst::<W64>(u64::from(i) * 8);
                let a = b.add::<W64>(addr, off);
                b.store::<W64>(a, v, DATA_WRITE)?;
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}

/// FL8 系 SHORT ASI 転送。LDDFA/STDFA 限定で f[fd] の最下位
/// 1 バイトだけを転送する。1 バイトなのでリトル形でも同じ。
/// Ref: SPEC-SPARC-V9 §Partial and Short Load/Store, SRC-QEMU.
fn fasi_short8<B: Backend>(b: &mut B, insn: Insn, fd: u8, rs1: Gpr, s: Src2) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    match insn {
        Insn::Lddfa | Insn::LddfaI => {
            let v: B::V<W8> = b.load::<W8>(addr, DATA_READ)?;
            let v64 = b.zext::<W8, W64>(v);
            fputw64(b, fd, v64)
        }
        Insn::Stdfa | Insn::StdfaI => {
            let v64 = fgetw64(b, fd)?;
            let v = b.trunc::<W64, W8>(v64);
            b.store::<W8>(addr, v, DATA_WRITE)
        }
        _ => unreachable!(),
    }
}

/// FL16 系 SHORT ASI 転送。LDDFA/STDFA 限定で f[fd] の最下位
/// 2 バイトだけを転送する。リトル ASI ではハーフワードを
/// バイト反転する。
/// Ref: SPEC-SPARC-V9 §Partial and Short Load/Store, SRC-QEMU.
fn fasi_short16<B: Backend>(
    b: &mut B,
    insn: Insn,
    fd: u8,
    rs1: Gpr,
    s: Src2,
    asi: B::V<W64>,
) -> Flow<B> {
    let addr = eff_addr(b, rs1, s);
    let eight = b.konst::<W64>(8);
    let lit = b.and::<W64>(asi, eight);
    let z = b.konst::<W64>(0);
    let little = b.cmp::<W64>(Cmp::Ne, lit, z);
    let bswap = |b: &mut B, v: B::V<W16>| {
        let k = b.konst::<W16>(8);
        let lo = b.shl::<W16>(v, k);
        let hi = b.shr_l::<W16>(v, k);
        b.or::<W16>(hi, lo)
    };
    match insn {
        Insn::Lddfa | Insn::LddfaI => {
            let v: B::V<W16> = b.load::<W16>(addr, DATA_READ)?;
            let sw = bswap(b, v);
            let v = b.select::<W16>(little, sw, v);
            let v64 = b.zext::<W16, W64>(v);
            fputw64(b, fd, v64)
        }
        Insn::Stdfa | Insn::StdfaI => {
            let v64 = fgetw64(b, fd)?;
            let v = b.trunc::<W64, W16>(v64);
            let sw = bswap(b, v);
            let v = b.select::<W16>(little, sw, v);
            b.store::<W16>(addr, v, DATA_WRITE)
        }
        _ => unreachable!(),
    }
}

/// FPU の ASI 指定アクセス。BLK 系 ASI では 64 バイト転送、
/// FL8/FL16 系では 1/2 バイト転送、それ以外は
/// ldf/lddf/stf/stdf/ldqf/stqf と同じ。
/// Ref: SPEC-SPARC-V9 §Alternate Space Floating-Point
///      Load/Store Instructions, SRC-QEMU.
fn fasi_access<B: Backend>(
    b: &mut B,
    insn: Insn,
    fd: u8,
    rs1: Gpr,
    s: Src2,
    asi: B::V<W64>,
) -> Flow<B> {
    asi_priv_check(b, asi)?;
    fp_check(b)?;
    // SHORT ASI。bit0=S、bit3=L を落として
    // (asi & 0xf4) == 0xd0 で FL8（0xd0-0xd1,0xd8-0xd9）と
    // FL16（0xd2-0xd3,0xda-0xdb）の両方を拾う。
    let m = b.konst::<W64>(0xf4);
    let m = b.and::<W64>(asi, m);
    let k = b.konst::<W64>(0xd0);
    let is_short = b.cmp::<W64>(Cmp::Eq, m, k);
    // FL16 だけ bit1 が立つ。
    let m2 = b.konst::<W64>(2);
    let m2 = b.and::<W64>(asi, m2);
    let z = b.konst::<W64>(0);
    let is16 = b.cmp::<W64>(Cmp::Ne, m2, z);
    if !matches!(
        insn,
        Insn::Lddfa | Insn::LddfaI | Insn::Stdfa | Insn::StdfaI
    ) {
        // BLK/SHORT ASI は lddfa/stdfa だけが使う。それ以外の
        // FP-ASI 命令で指定すると illegal instruction。
        // Ref: SRC-QEMU gen_ldf_asi (GET_ASI_BLOCK/SHORT → TT_ILL_INSN).
        let blk = is_blk_asi(b, asi);
        return b.if_then_else(
            blk,
            |bb| Err(unimp(bb, 0)),
            |bb| {
                bb.if_then_else(
                    is_short,
                    |bbb| Err(unimp(bbb, 0)),
                    |bbb| match insn {
                        Insn::Ldfa | Insn::LdfaI => ldf(bbb, fd, rs1, s),
                        Insn::Stfa | Insn::StfaI => stf(bbb, fd, rs1, s),
                        Insn::Ldqfa | Insn::LdqfaI => ldqf(bbb, fd, rs1, s),
                        Insn::Stqfa | Insn::StqfaI => stqf(bbb, fd, rs1, s),
                        _ => unreachable!(),
                    },
                )
            },
        );
    }
    let is_blk = is_blk_asi(b, asi);
    b.if_then_else(
        is_blk,
        |bb| fasi_blk(bb, insn, fd, rs1, s, asi),
        |bb| {
            bb.if_then_else(
                is_short,
                |bbb| {
                    bbb.if_then_else(
                        is16,
                        |c| fasi_short16(c, insn, fd, rs1, s, asi),
                        |c| fasi_short8(c, insn, fd, rs1, s),
                    )
                },
                |bbb| {
                    if matches!(insn, Insn::Lddfa | Insn::LddfaI) {
                        lddf(bbb, fd, rs1, s)
                    } else {
                        stdf(bbb, fd, rs1, s)
                    }
                },
            )
        },
    )
}

/// LDQFA。16 バイト。q 番号（extract_qfpreg）は 4 の倍数で
/// なければならない。連続する 2 スロットへ書く。
/// Ref: SPEC-SPARC-V9 §Alternate Space Floating-Point
///      Load/Store Instructions.
fn ldqf<B: Backend>(b: &mut B, fd: u8, rs1: Gpr, s: Src2) -> Flow<B> {
    // fd の bit1（R の bit1）が立つと 4 の倍数にならない。
    if fd & 2 != 0 {
        return Err(unimp(b, 0));
    }
    let rq = if b.param::<super::Word64Param>() {
        (fd & 0x1c) | ((fd & 1) << 5)
    } else {
        fd & 0x1c
    };
    let q0 = rq >> 1;
    let addr = eff_addr(b, rs1, s);
    let hi: B::V<W64> = b.load::<W64>(addr, DATA_READ)?;
    b.set(Fpr(q0).state(), hi);
    let eight = b.konst::<W64>(8);
    let a2 = b.add::<W64>(addr, eight);
    let lo: B::V<W64> = b.load::<W64>(a2, DATA_READ)?;
    b.set(Fpr(q0 + 1).state(), lo);
    fprs_dl(b);
    Ok(())
}

/// STQFA。16 バイト。q 番号の制約は LDQFA と同じ。
/// Ref: SPEC-SPARC-V9 §Alternate Space Floating-Point
///      Load/Store Instructions.
fn stqf<B: Backend>(b: &mut B, fd: u8, rs1: Gpr, s: Src2) -> Flow<B> {
    if fd & 2 != 0 {
        return Err(unimp(b, 0));
    }
    let rq = if b.param::<super::Word64Param>() {
        (fd & 0x1c) | ((fd & 1) << 5)
    } else {
        fd & 0x1c
    };
    let q0 = rq >> 1;
    let addr = eff_addr(b, rs1, s);
    let hi: B::V<W64> = b.get(Fpr(q0).state());
    b.store::<W64>(addr, hi, DATA_WRITE)?;
    let eight = b.konst::<W64>(8);
    let a2 = b.add::<W64>(addr, eight);
    let lo: B::V<W64> = b.get(Fpr(q0 + 1).state());
    b.store::<W64>(a2, lo, DATA_WRITE)
}

/// RDASI/WRASI（V9、非特権）。%asi は 8 ビット。
/// Ref: SPEC-SPARC-V9 §Read/Write Ancillary State Register.
fn rdasi<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let v = b.get(asi_ref());
    write(b, rd, v);
    Ok(())
}

fn wrasi<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let v = b.xor::<W64>(x, y);
    let m = b.konst::<W64>(0xff);
    let w = b.and::<W64>(v, m);
    b.set(asi_ref(), w);
    Ok(())
}

/// RDGSR/WRGSR（V9、非特権）。FPU 無効時は fp_disabled
/// （QEMU は rdgsr/wrgsr で gen_trap_ifnofpu を呼ぶ）。
fn rdgsr<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    fp_check(b)?;
    let v = b.get(gsr_ref());
    write(b, rd, v);
    Ok(())
}

fn wrgsr<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> Flow<B> {
    fp_check(b)?;
    let x = read(b, rs1);
    let y = src2(b, s);
    let v = b.xor::<W64>(x, y);
    b.set(gsr_ref(), v);
    Ok(())
}

/// RDFPRS/WRFPRS。FPRS は 3 ビット（DU|DL|FEF）。
fn rdfprs<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let v = b.get(fprs_ref());
    write(b, rd, v);
    Ok(())
}

fn wrfprs<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let v = b.xor::<W64>(x, y);
    // QEMU は下位 32 ビットをそのまま保持する。定義ビットは
    // DU|DL|FEF の 3 ビットだけだが、読み戻し互換のためマスクは
    // 32 ビットに留める。
    let m = b.konst::<W64>(0xffff_ffff);
    let w = b.and::<W64>(v, m);
    b.set(fprs_ref(), w);
    Ok(())
}

/// EDGE8/EDGE16/EDGE32 系。s1 の要素位置から s2 の要素位置までの
/// マスクを作る。同じアライン 8 バイト内なら left & right、
/// さもなくば left だけ。cc 形は s1-s2 で ICC/XCC を更新する。
/// Ref: SPEC-SPARC-V9 §Edge Mask Instructions.
fn edge<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs1: Gpr,
    rs2: Gpr,
    sz: u8,
    little: bool,
    cc: bool,
) -> Flow<B> {
    let a = read(b, rs1);
    let c = read(b, rs2);
    // 要素内位置 l と右端までの距離 r。
    let (l, r, m) = match sz {
        16 => {
            let one = b.konst::<W64>(1);
            let m3 = b.konst::<W64>(3);
            let lt = b.shr_l::<W64>(a, one);
            let l = b.and::<W64>(lt, m3);
            let rt = b.shr_l::<W64>(c, one);
            let rt = b.and::<W64>(rt, m3);
            let r = b.xor::<W64>(rt, m3);
            (l, r, 0xfu64)
        }
        32 => {
            let two = b.konst::<W64>(2);
            let m1 = b.konst::<W64>(1);
            let lt = b.shr_l::<W64>(a, two);
            let l = b.and::<W64>(lt, m1);
            let rt = b.shr_l::<W64>(c, two);
            let rt = b.and::<W64>(rt, m1);
            let r = b.xor::<W64>(rt, m1);
            (l, r, 0x3)
        }
        _ => {
            let m7 = b.konst::<W64>(7);
            let l = b.and::<W64>(a, m7);
            let rt = b.and::<W64>(c, m7);
            let r = b.xor::<W64>(rt, m7);
            (l, r, 0xff)
        }
    };
    let mk = b.konst::<W64>(m);
    let (left, right) = if little {
        let t = b.shl::<W64>(mk, l);
        let left = b.and::<W64>(t, mk);
        let right = b.shr_l::<W64>(mk, r);
        (left, right)
    } else {
        let left = b.shr_l::<W64>(mk, l);
        let t = b.shl::<W64>(mk, r);
        let right = b.and::<W64>(t, mk);
        (left, right)
    };
    let comb = b.and::<W64>(left, right);
    // s1 と s2 が同じ 8 バイトブロック内か。比較マスクは
    // PSTATE.AM の影響を受ける（QEMU address_mask_i(-8)）。
    let x = b.xor::<W64>(a, c);
    let am = b.konst::<W64>(!7u64);
    let am = amask(b, am);
    let t = b.and::<W64>(x, am);
    let zero = b.konst::<W64>(0);
    let same = b.cmp::<W64>(Cmp::Eq, t, zero);
    let v = b.select::<W64>(same, comb, left);
    write(b, rd, v);
    if cc {
        // s1 - s2 で ICC/XCC を更新する（subcc 相当）。
        let diff = b.sub::<W64>(a, c);
        let fb = false_b(b);
        let tb = inv_b(b, fb);
        let a32 = b.trunc::<W64, W32>(a);
        let c32 = b.trunc::<W64, W32>(c);
        let ic = b.not::<W32>(c32);
        let (_r, cry, ovf) = b.add_with_carry::<W32>(a32, ic, tb);
        let borrow = inv_b(b, cry);
        let ic64 = b.not::<W64>(c);
        let (_r, cry64, ovf64) = b.add_with_carry::<W64>(a, ic64, tb);
        let borrow64 = inv_b(b, cry64);
        set_cc(b, diff, ovf, borrow, ovf64, borrow64);
    }
    Ok(())
}

/// ARRAY8/ARRAY16/ARRAY32。rs1 のアドレスフィールドを並べ替えて
/// 要素サイズ（1/2/4 = `elem_log` だけ左シフト）を掛ける。
/// Ref: SPEC-SPARC-V9 §Array Addressing Instructions.
fn array<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, elem_log: u64) -> Flow<B> {
    let a = read(b, rs1);
    let c = read(b, rs2);
    // n = min(rs2 & 7, 5)。6/7 は 5 に畳むのが慣行。
    let m7 = b.konst::<W64>(7);
    let n7 = b.and::<W64>(c, m7);
    let five = b.konst::<W64>(5);
    let small = b.cmp::<W64>(Cmp::LtU, n7, five);
    let n = b.select::<W64>(small, n7, five);
    let m7ff = b.konst::<W64>(0x7ff);
    let s11 = b.konst::<W64>(11);
    let s33 = b.konst::<W64>(33);
    let s55 = b.konst::<W64>(55);
    let xt = b.shr_l::<W64>(a, s11);
    let x = b.and::<W64>(xt, m7ff);
    let yt = b.shr_l::<W64>(a, s33);
    let y = b.and::<W64>(yt, m7ff);
    let z = b.shr_l::<W64>(a, s55);
    let m3 = b.konst::<W64>(3);
    let m1 = b.konst::<W64>(1);
    let mf = b.konst::<W64>(15);
    let two = b.konst::<W64>(2);
    let lx = b.and::<W64>(x, m3);
    let ly = b.and::<W64>(y, m3);
    let lz = b.and::<W64>(z, m1);
    let xt2 = b.shr_l::<W64>(x, two);
    let mx = b.and::<W64>(xt2, mf);
    let yt2 = b.shr_l::<W64>(y, two);
    let my = b.and::<W64>(yt2, mf);
    let zt = b.shr_l::<W64>(z, m1);
    let mz = b.and::<W64>(zt, mf);
    let one = b.konst::<W64>(1);
    let pow = b.shl::<W64>(one, n);
    let unm = b.sub::<W64>(pow, one);
    let six = b.konst::<W64>(6);
    let xt6 = b.shr_l::<W64>(x, six);
    let ux = b.and::<W64>(xt6, unm);
    let yt6 = b.shr_l::<W64>(y, six);
    let uy = b.and::<W64>(yt6, unm);
    let uz = b.shr_l::<W64>(z, five);
    // シフト量 17、17+n、17+2n は n に依存するので可変シフト。
    let s17 = b.konst::<W64>(17);
    let sh_y = b.add::<W64>(s17, n);
    let sh_z = b.add::<W64>(sh_y, n);
    let uz_p = b.shl::<W64>(uz, sh_z);
    let uy_p = b.shl::<W64>(uy, sh_y);
    let ux_p = b.shl::<W64>(ux, s17);
    let s13 = b.konst::<W64>(13);
    let s9 = b.konst::<W64>(9);
    let s5 = b.konst::<W64>(5);
    let s4 = b.konst::<W64>(4);
    let s2k = b.konst::<W64>(2);
    let mz_p = b.shl::<W64>(mz, s13);
    let my_p = b.shl::<W64>(my, s9);
    let mx_p = b.shl::<W64>(mx, s5);
    let lz_p = b.shl::<W64>(lz, s4);
    let ly_p = b.shl::<W64>(ly, s2k);
    let v0 = b.or::<W64>(uz_p, uy_p);
    let v1 = b.or::<W64>(v0, ux_p);
    let v2 = b.or::<W64>(v1, mz_p);
    let v3 = b.or::<W64>(v2, my_p);
    let v4 = b.or::<W64>(v3, mx_p);
    let v5 = b.or::<W64>(v4, lz_p);
    let v6 = b.or::<W64>(v5, ly_p);
    let v7 = b.or::<W64>(v6, lx);
    let esh = b.konst::<W64>(elem_log);
    let v = b.shl::<W64>(v7, esh);
    write(b, rd, v);
    Ok(())
}

/// ALIGNADDR/ALIGNADDRL。rd = (rs1+rs2) & ~8、GSR.align =
/// （little なら反転した）和の下位 3 ビット。
/// Ref: SPEC-SPARC-V9 §Align Address Instructions.
fn alignaddr<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, little: bool) -> Flow<B> {
    let a = read(b, rs1);
    let c = read(b, rs2);
    let t = b.add::<W64>(a, c);
    let m8 = b.konst::<W64>(!7u64);
    let v = b.and::<W64>(t, m8);
    write(b, rd, v);
    let al = if little {
        let z = b.konst::<W64>(0);
        b.sub::<W64>(z, t)
    } else {
        t
    };
    let m7 = b.konst::<W64>(7);
    let bits = b.and::<W64>(al, m7);
    let g = b.get(gsr_ref());
    let nm = b.konst::<W64>(!7u64);
    let g1 = b.and::<W64>(g, nm);
    let g2 = b.or::<W64>(g1, bits);
    b.set(gsr_ref(), g2);
    Ok(())
}

/// BMASK（VIS2）。rd = rs1+rs2、GSR[63:32] に和の下位 32 ビット。
/// Ref: SPEC-SPARC-V9 §Byte Mask and Shuffle.
fn bmask<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let a = read(b, rs1);
    let c = read(b, rs2);
    let t = b.add::<W64>(a, c);
    write(b, rd, t);
    let m32 = b.konst::<W64>(0xffff_ffff);
    let low = b.and::<W64>(t, m32);
    let s32 = b.konst::<W64>(32);
    let hi = b.shl::<W64>(low, s32);
    let g = b.get(gsr_ref());
    let g1 = b.and::<W64>(g, m32);
    let g2 = b.or::<W64>(g1, hi);
    b.set(gsr_ref(), g2);
    Ok(())
}

/// レーン抽出して符号拡張。`w` はレーン幅（8/16/32）。
fn lane_s<B: Backend>(b: &mut B, v: B::V<W64>, w: u8, i: u8) -> B::V<W64> {
    let sh = b.konst::<W64>((w * i) as u64);
    let t = b.shr_l::<W64>(v, sh);
    let up = b.konst::<W64>((64 - w) as u64);
    let t = b.shl::<W64>(t, up);
    b.shr_a::<W64>(t, up)
}

/// FPCMP 系。レーンごとの符号付き比較の結果を整数 rd の
/// ビットマスクにする（ビット i = レーン i）。
/// Ref: SPEC-SPARC-V9 §Partitioned Compare Instructions.
fn fpcmp<B: Backend>(b: &mut B, rd: Gpr, rs1: u8, rs2: u8, w: u8, op: Cmp) -> Flow<B> {
    fp_check(b)?;
    let a = fgetw64(b, rs1)?;
    let c = fgetw64(b, rs2)?;
    let nlanes = 64 / w;
    let mut acc = b.konst::<W64>(0);
    for i in 0..nlanes {
        let la = lane_s::<B>(b, a, w, i);
        let lc = lane_s::<B>(b, c, w, i);
        let t = b.cmp::<W64>(op, la, lc);
        let one = b.konst::<W64>(1);
        let zero = b.konst::<W64>(0);
        let bit0 = b.select::<W64>(t, one, zero);
        let sh = b.konst::<W64>(i as u64);
        let bit = b.shl::<W64>(bit0, sh);
        acc = b.or::<W64>(acc, bit);
    }
    write(b, rd, acc);
    Ok(())
}

/// FMUL8x16。rs1 の下位 32 ビット中の 4 個の符号なしバイトと
/// rs2 の 4 個の符号付き 16 ビットの積を (x + 0x80) >> 8 する。
/// Ref: SPEC-SPARC-V9 §FMUL8x16.
fn fmul8x16<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fget_single::<B>(b, rs1)?;
    let c = fgetw64(b, rs2)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u8 {
        let u = lane_s::<B>(b, a, 8, i);
        let m8 = b.konst::<W64>(0xff);
        let u = b.and::<W64>(u, m8);
        let w = lane_s::<B>(b, c, 16, i);
        let p = b.mul::<W64>(u, w);
        let r = b.konst::<W64>(0x80);
        let p = b.add::<W64>(p, r);
        let s8 = b.konst::<W64>(8);
        let p = b.shr_a::<W64>(p, s8);
        let m16 = b.konst::<W64>(0xffff);
        let p = b.and::<W64>(p, m16);
        let sh = b.konst::<W64>(16 * i as u64);
        let p = b.shl::<W64>(p, sh);
        acc = b.or::<W64>(acc, p);
    }
    fputw64(b, rd, acc)
}

/// FMUL8x16AU/AL。rs1（32 ビット）の 4 バイトに、rs2 の上位
/// （au）または下位（al）16 ビットの定数を掛ける。
/// Ref: SPEC-SPARC-V9 §FMUL8x16AU, §FMUL8x16AL.
fn fmul8x16a<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8, upper: bool) -> Flow<B> {
    fp_check(b)?;
    let a = fget_single::<B>(b, rs1)?;
    let s2 = fget_single::<B>(b, rs2)?;
    let t = if upper {
        // AU は 32 ビット値の上位半分を符号付きで使う
        // （QEMU は 32 ビットの sari）。s2[31:16] を符号拡張する。
        let s32 = b.konst::<W64>(32);
        let t = b.shl::<W64>(s2, s32);
        let s48 = b.konst::<W64>(48);
        b.shr_a::<W64>(t, s48)
    } else {
        let s48 = b.konst::<W64>(48);
        let t = b.shl::<W64>(s2, s48);
        b.shr_a::<W64>(t, s48)
    };
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u8 {
        let u = lane_s::<B>(b, a, 8, i);
        let m8 = b.konst::<W64>(0xff);
        let u = b.and::<W64>(u, m8);
        let p = b.mul::<W64>(u, t);
        let r = b.konst::<W64>(0x80);
        let p = b.add::<W64>(p, r);
        let s8 = b.konst::<W64>(8);
        let p = b.shr_a::<W64>(p, s8);
        let m16 = b.konst::<W64>(0xffff);
        let p = b.and::<W64>(p, m16);
        let sh = b.konst::<W64>(16 * i as u64);
        let p = b.shl::<W64>(p, sh);
        acc = b.or::<W64>(acc, p);
    }
    fputw64(b, rd, acc)
}

/// FMUL8SUx16 / FMUL8ULx16。rs1 の各 16 ビット語の上位バイト
/// （su = 符号付き）または下位バイト（ul = 符号なし）と rs2 の
/// 符号付き 16 ビットの積。
/// Ref: SPEC-SPARC-V9 §FMUL8SUx16, §FMUL8ULx16.
fn fmul8sux16<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8, upper: bool) -> Flow<B> {
    fp_check(b)?;
    let a = fgetw64(b, rs1)?;
    let c = fgetw64(b, rs2)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u8 {
        let bo = if upper { 16 * i + 8 } else { 16 * i };
        let sh = b.konst::<W64>(bo as u64);
        let bt = b.shr_l::<W64>(a, sh);
        let m8 = b.konst::<W64>(0xff);
        let bt = b.and::<W64>(bt, m8);
        // su はバイトを符号拡張。
        let u = if upper {
            let s56 = b.konst::<W64>(56);
            let t = b.shl::<W64>(bt, s56);
            b.shr_a::<W64>(t, s56)
        } else {
            bt
        };
        let w = lane_s::<B>(b, c, 16, i);
        let p = b.mul::<W64>(u, w);
        let (add, shv) = if upper { (0x80u64, 8u64) } else { (0x8000, 16) };
        let r = b.konst::<W64>(add);
        let p = b.add::<W64>(p, r);
        let sk = b.konst::<W64>(shv);
        let p = b.shr_a::<W64>(p, sk);
        let m16 = b.konst::<W64>(0xffff);
        let p = b.and::<W64>(p, m16);
        let sk2 = b.konst::<W64>(16 * i as u64);
        let p = b.shl::<W64>(p, sk2);
        acc = b.or::<W64>(acc, p);
    }
    fputw64(b, rd, acc)
}

/// FMULD8SUx16 / FMULD8ULx16。rs1（32 ビット）の各 16 ビット語の
/// 上位（su = 符号付きで左 8 シフト相当）または下位（ul = 符号
/// なし）バイトと rs2 の符号付き 16 ビットの積。結果は 32 ビット
/// レーンに入る。
/// Ref: SPEC-SPARC-V9 §FMULD8SUx16, §FMULD8ULx16.
fn fmuld8x16<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8, upper: bool) -> Flow<B> {
    fp_check(b)?;
    let a = fget_single::<B>(b, rs1)?;
    let s2 = fget_single::<B>(b, rs2)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..2u8 {
        let w0 = lane_s::<B>(b, a, 16, i);
        let w1 = lane_s::<B>(b, s2, 16, i);
        let u = if upper {
            // 上位バイトの符号付き積の <<8 は、下位バイトを消すのと
            // 等しい（(sext16 & ~0xff) = 上位バイト << 8）。
            let m = b.konst::<W64>(!0xffu64);
            b.and::<W64>(w0, m)
        } else {
            let m8 = b.konst::<W64>(0xff);
            b.and::<W64>(w0, m8)
        };
        let p = b.mul::<W64>(u, w1);
        let m32 = b.konst::<W64>(0xffff_ffff);
        let p = b.and::<W64>(p, m32);
        let sh = b.konst::<W64>(32 * i as u64);
        let p = b.shl::<W64>(p, sh);
        acc = b.or::<W64>(acc, p);
    }
    fputw64(b, rd, acc)
}

/// パック用のクリップ。`v`（符号付き）を [lo, hi] に飽和する。
fn clip64<B: Backend>(b: &mut B, v: B::V<W64>, lo: i64, hi: i64) -> B::V<W64> {
    let lv = b.konst::<W64>(lo as u64);
    let hv = b.konst::<W64>(hi as u64);
    let t = b.cmp::<W64>(Cmp::LtS, v, lv);
    let v = b.select::<W64>(t, lv, v);
    let t = b.cmp::<W64>(Cmp::GtS, v, hv);
    b.select::<W64>(t, hv, v)
}

/// FPACK16。rs2 の 4 個の符号付き 16 ビットを GSR.scale でスケール
/// し、>> 7 のあと符号なし 8 ビットに飽和する。結果は 32 ビット。
/// Ref: SPEC-SPARC-V9 §FPACK16.
fn fpack16<B: Backend>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let c = fgetw64(b, rs2)?;
    let g = b.get(gsr_ref());
    let s3 = b.konst::<W64>(3);
    let sc = b.shr_l::<W64>(g, s3);
    let mf = b.konst::<W64>(0xf);
    let scale = b.and::<W64>(sc, mf);
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u8 {
        let w = lane_s::<B>(b, c, 16, i);
        let t = b.shl::<W64>(w, scale);
        let s7 = b.konst::<W64>(7);
        let t = b.shr_a::<W64>(t, s7);
        let t = clip64::<B>(b, t, 0, 255);
        let sh = b.konst::<W64>(8 * i as u64);
        let t = b.shl::<W64>(t, sh);
        acc = b.or::<W64>(acc, t);
    }
    // 結果は 32 ビットの単精度スロット。
    fput_slot(b, rd, acc);
    Ok(())
}

/// FPACK32。rd[63:32] = rs1 << 8（新バイトを残す）、rs2 の 2 個の
/// 符号付き 32 ビットをスケール → >> 23 → 符号なし 8 ビット飽和で
/// 各ワードの最下位バイトに入れる。
/// Ref: SPEC-SPARC-V9 §FPACK32.
fn fpack32<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fgetw64(b, rs1)?;
    let c = fgetw64(b, rs2)?;
    let s8 = b.konst::<W64>(8);
    let t = b.shl::<W64>(a, s8);
    let km = b.konst::<W64>(!0x0000_00ff_0000_00ffu64);
    let mut acc = b.and::<W64>(t, km);
    let g = b.get(gsr_ref());
    let s3 = b.konst::<W64>(3);
    let sc = b.shr_l::<W64>(g, s3);
    let m1f = b.konst::<W64>(0x1f);
    let scale = b.and::<W64>(sc, m1f);
    for i in 0..2u8 {
        let w = lane_s::<B>(b, c, 32, i);
        let t = b.shl::<W64>(w, scale);
        let s23 = b.konst::<W64>(23);
        let t = b.shr_a::<W64>(t, s23);
        let t = clip64::<B>(b, t, 0, 255);
        let sh = b.konst::<W64>(32 * i as u64);
        let t = b.shl::<W64>(t, sh);
        acc = b.or::<W64>(acc, t);
    }
    fputw64(b, rd, acc)
}

/// FPACKFIX。rs2 の 2 個の符号付き 32 ビットをスケール → >> 16
/// → 符号付き 16 ビット飽和。結果は 32 ビット。
/// Ref: SPEC-SPARC-V9 §FPACKFIX.
fn fpackfix<B: Backend>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let c = fgetw64(b, rs2)?;
    let g = b.get(gsr_ref());
    let s3 = b.konst::<W64>(3);
    let sc = b.shr_l::<W64>(g, s3);
    let m1f = b.konst::<W64>(0x1f);
    let scale = b.and::<W64>(sc, m1f);
    let mut acc = b.konst::<W64>(0);
    for i in 0..2u8 {
        let w = lane_s::<B>(b, c, 32, i);
        let t = b.shl::<W64>(w, scale);
        let s16 = b.konst::<W64>(16);
        let t = b.shr_a::<W64>(t, s16);
        let t = clip64::<B>(b, t, -32768, 32767);
        let m16 = b.konst::<W64>(0xffff);
        let t = b.and::<W64>(t, m16);
        let sh = b.konst::<W64>(16 * i as u64);
        let t = b.shl::<W64>(t, sh);
        acc = b.or::<W64>(acc, t);
    }
    fput_slot(b, rd, acc);
    Ok(())
}

/// PDIST。rs1 と rs2 の対応する 8 バイトの絶対差の和を rd（累積
/// レジスタ）に加える。
/// Ref: SPEC-SPARC-V9 §PDIST.
fn pdist<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fgetw64(b, rs1)?;
    let c = fgetw64(b, rs2)?;
    let mut sum = fgetw64(b, rd)?;
    for i in 0..8u8 {
        let ua = lane_s::<B>(b, a, 8, i);
        let m8 = b.konst::<W64>(0xff);
        let ua = b.and::<W64>(ua, m8);
        let uc = lane_s::<B>(b, c, 8, i);
        let uc = b.and::<W64>(uc, m8);
        let d = b.sub::<W64>(ua, uc);
        let z = b.konst::<W64>(0);
        let neg = b.cmp::<W64>(Cmp::LtS, d, z);
        let nd = b.sub::<W64>(z, d);
        let d = b.select::<W64>(neg, nd, d);
        sum = b.add::<W64>(sum, d);
    }
    fputw64(b, rd, sum)
}

/// FALIGNDATA。GSR.align × 8 ビットだけ (rs1:rs2) の連結をずらす。
/// align=0 なら rs1。
/// Ref: SPEC-SPARC-V9 §FALIGNDATA.
fn faligndata<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fgetw64(b, rs1)?;
    let c = fgetw64(b, rs2)?;
    let g = b.get(gsr_ref());
    let m7 = b.konst::<W64>(7);
    let al = b.and::<W64>(g, m7);
    let s3 = b.konst::<W64>(3);
    let sh = b.shl::<W64>(al, s3);
    let t1 = b.shl::<W64>(a, sh);
    // 右側は s2 >> (64 - sh)。sh=0 のとき s1 を選ぶ。
    let s64 = b.konst::<W64>(64);
    let rsh = b.sub::<W64>(s64, sh);
    let m63 = b.konst::<W64>(63);
    let rsh = b.and::<W64>(rsh, m63);
    // sh=0 のとき rsh は 0 ではなく 64→63 に畳むと s2>>63 が残る。
    // sh==0 は a を返すので、ここでは (sh!=0) の値だけ正確でよい。
    let t2 = b.shr_l::<W64>(c, rsh);
    let zk = b.konst::<W64>(0);
    let is0 = b.cmp::<W64>(Cmp::Eq, sh, zk);
    let comb = b.or::<W64>(t1, t2);
    let v = b.select::<W64>(is0, a, comb);
    fputw64(b, rd, v)
}

/// FPMERGE。rs1・rs2 の下位 32 ビットのバイトを交互に連結する。
/// Ref: SPEC-SPARC-V9 §FPMERGE.
fn fpmerge<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fget_single::<B>(b, rs1)?;
    let c = fget_single::<B>(b, rs2)?;
    let mut acc = b.konst::<W64>(0);
    // 結果の上位から s1.b3, s2.b3, s1.b2, s2.b2, s1.b1, s2.b1,
    // s1.b0, s2.b0。バイト位置 8i はレーン i（下位から）に対応。
    for i in 0..4u8 {
        // 結果のバイト (2i) = s2 のバイト i、バイト (2i+1) = s1 のバイト i。
        let sh = b.konst::<W64>(8 * i as u64);
        let m8 = b.konst::<W64>(0xff);
        let t = b.shr_l::<W64>(a, sh);
        let b1 = b.and::<W64>(t, m8);
        let t = b.shr_l::<W64>(c, sh);
        let b2 = b.and::<W64>(t, m8);
        let sh2 = b.konst::<W64>(8 * (2 * i) as u64);
        let b2p = b.shl::<W64>(b2, sh2);
        acc = b.or::<W64>(acc, b2p);
        let sh1 = b.konst::<W64>(8 * (2 * i + 1) as u64);
        let b1p = b.shl::<W64>(b1, sh1);
        acc = b.or::<W64>(acc, b1p);
    }
    fputw64(b, rd, acc)
}

/// FEXPAND。rs2 の下位 32 ビットの各バイトを <<4 した 16 ビットに
/// 展開する。
/// Ref: SPEC-SPARC-V9 §FEXPAND.
fn fexpand<B: Backend>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let c = fget_single::<B>(b, rs2)?;
    let mut acc = b.konst::<W64>(0);
    for i in 0..4u8 {
        let sh = b.konst::<W64>(8 * i as u64);
        let t = b.shr_l::<W64>(c, sh);
        let m8 = b.konst::<W64>(0xff);
        let t = b.and::<W64>(t, m8);
        let s4 = b.konst::<W64>(4);
        let t = b.shl::<W64>(t, s4);
        let sh2 = b.konst::<W64>(16 * i as u64);
        let t = b.shl::<W64>(t, sh2);
        acc = b.or::<W64>(acc, t);
    }
    fputw64(b, rd, acc)
}

/// BSHUFFLE（VIS2）。GSR[63:32] のニブルが選ぶバイトを並べる。
/// ニブル 0-7 は rs2 のバイト、8-15 は rs1 のバイト。
/// Ref: SPEC-SPARC-V9 §Byte Mask and Shuffle.
fn bshuffle<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let a = fgetw64(b, rs1)?;
    let c = fgetw64(b, rs2)?;
    let g = b.get(gsr_ref());
    let s32 = b.konst::<W64>(32);
    let mask = b.shr_l::<W64>(g, s32);
    let mut acc = b.konst::<W64>(0);
    for i in 0..8u8 {
        // 結果のバイト i（下位から）に入るのは、マスクの上位側から
        // 数えたニブル e = mask[31-4i : 28-4i]。e < 8 は rs1 の
        // バイト (7-e)、e >= 8 は rs2 のバイト (15-e) を選ぶ。
        let sh = b.konst::<W64>((28 - 4 * i) as u64);
        let t = b.shr_l::<W64>(mask, sh);
        let mf = b.konst::<W64>(0xf);
        let e = b.and::<W64>(t, mf);
        let e7 = b.konst::<W64>(7);
        let e3 = b.and::<W64>(e, e7);
        let seven = b.konst::<W64>(7);
        let idx = b.sub::<W64>(seven, e3);
        let s8 = b.konst::<W64>(8);
        let bsh = b.mul::<W64>(idx, s8);
        let t = b.shr_l::<W64>(a, bsh);
        let m8 = b.konst::<W64>(0xff);
        let from1 = b.and::<W64>(t, m8);
        let t = b.shr_l::<W64>(c, bsh);
        let from2 = b.and::<W64>(t, m8);
        let e8 = b.and::<W64>(e, s8);
        let z = b.konst::<W64>(0);
        let upper = b.cmp::<W64>(Cmp::Ne, e8, z);
        let byte = b.select::<W64>(upper, from2, from1);
        let sh2 = b.konst::<W64>(8 * i as u64);
        let byte = b.shl::<W64>(byte, sh2);
        acc = b.or::<W64>(acc, byte);
    }
    fputw64(b, rd, acc)
}

/// レーン幅 `w` の並列加減算（mod 2^w）。`single` ならスロットの
/// 下位 32 ビットだけを読み書きする（s 形）。
/// 加算: (a&lo)+(c&lo) に符号ビットを xor で加える。
/// 減算: d=(a|hi)-(c&lo) の下位と、bit(w-1)=~(a^c^d) を合成する。
/// Ref: SPEC-SPARC-V9 §Partitioned Add/Subtract.
fn vparith<B: Backend>(
    b: &mut B,
    rd: u8,
    rs1: u8,
    rs2: u8,
    w: u8,
    sub: bool,
    single: bool,
) -> Flow<B> {
    fp_check(b)?;
    let (a, c) = if single {
        (fget_single::<B>(b, rs1)?, fget_single::<B>(b, rs2)?)
    } else {
        (fgetw64(b, rs1)?, fgetw64(b, rs2)?)
    };
    let (hi, lo) = if w == 16 {
        (0x8000_8000_8000_8000u64, 0x7fff_7fff_7fff_7fffu64)
    } else {
        (0x8000_0000_8000_0000u64, 0x7fff_ffff_7fff_ffffu64)
    };
    let hk = b.konst::<W64>(hi);
    let lk = b.konst::<W64>(lo);
    let v = if sub {
        let ah = b.or::<W64>(a, hk);
        let cl = b.and::<W64>(c, lk);
        let d = b.sub::<W64>(ah, cl);
        let x = b.xor::<W64>(a, c);
        let x2 = b.xor::<W64>(x, d);
        let nx = b.not::<W64>(x2);
        let sign = b.and::<W64>(nx, hk);
        let dl = b.and::<W64>(d, lk);
        b.or::<W64>(dl, sign)
    } else {
        let al = b.and::<W64>(a, lk);
        let cl = b.and::<W64>(c, lk);
        let s = b.add::<W64>(al, cl);
        let x = b.xor::<W64>(a, c);
        let sn = b.and::<W64>(x, hk);
        b.xor::<W64>(s, sn)
    };
    if single {
        let m32 = b.konst::<W64>(0xffff_ffff);
        let v = b.and::<W64>(v, m32);
        fput_slot(b, rd, v);
        Ok(())
    } else {
        fputw64(b, rd, v)
    }
}

/// VIS の論理演算の選択肢。
#[derive(Clone, Copy)]
enum VLog {
    And,
    Or,
    Xor,
    Nor,
    Nand,
    Xnor,
    /// ~rs1 & rs2
    AndNot1,
    /// rs1 & ~rs2
    AndNot2,
    /// ~rs1 | rs2
    OrNot1,
    /// rs1 | ~rs2
    OrNot2,
}

/// VIS の論理演算。d 形は 64 ビットペア、s 形は下位 32 ビット。
/// Ref: SPEC-SPARC-V9 §Logical Operations.
fn vlogic<B: Backend>(b: &mut B, rd: u8, rs1: u8, rs2: u8, op: VLog, single: bool) -> Flow<B> {
    fp_check(b)?;
    let (a, c) = if single {
        let x = fget_single::<B>(b, rs1)?;
        let y = fget_single::<B>(b, rs2)?;
        (x, y)
    } else {
        (fgetw64(b, rs1)?, fgetw64(b, rs2)?)
    };
    let v = match op {
        VLog::And => b.and::<W64>(a, c),
        VLog::Or => b.or::<W64>(a, c),
        VLog::Xor => b.xor::<W64>(a, c),
        VLog::Nor => {
            let t = b.or::<W64>(a, c);
            b.not::<W64>(t)
        }
        VLog::Nand => {
            let t = b.and::<W64>(a, c);
            b.not::<W64>(t)
        }
        VLog::Xnor => {
            let t = b.xor::<W64>(a, c);
            b.not::<W64>(t)
        }
        VLog::AndNot1 => {
            let t = b.not::<W64>(a);
            b.and::<W64>(t, c)
        }
        VLog::AndNot2 => {
            let t = b.not::<W64>(c);
            b.and::<W64>(a, t)
        }
        VLog::OrNot1 => {
            let t = b.not::<W64>(a);
            b.or::<W64>(t, c)
        }
        VLog::OrNot2 => {
            let t = b.not::<W64>(c);
            b.or::<W64>(a, t)
        }
    };
    if single {
        let m32 = b.konst::<W64>(0xffff_ffff);
        let v = b.and::<W64>(v, m32);
        fput_slot(b, rd, v);
        Ok(())
    } else {
        fputw64(b, rd, v)
    }
}

/// FSRC1/FNOT1。rs1 桁の値をそのまま／反転して写す。
/// Ref: SPEC-SPARC-V9 §Logical Operations.
fn vunary1<B: Backend>(b: &mut B, rd: u8, rs1: u8, neg: bool, single: bool) -> Flow<B> {
    fp_check(b)?;
    let a = if single {
        fget_single::<B>(b, rs1)?
    } else {
        fgetw64(b, rs1)?
    };
    let v = if neg { b.not::<W64>(a) } else { a };
    if single {
        let m32 = b.konst::<W64>(0xffff_ffff);
        let v = b.and::<W64>(v, m32);
        fput_slot(b, rd, v);
        Ok(())
    } else {
        fputw64(b, rd, v)
    }
}

/// FSRC2/FNOT2。rs2 桁の値をそのまま／反転して写す。
fn vunary2<B: Backend>(b: &mut B, rd: u8, rs2: u8, neg: bool, single: bool) -> Flow<B> {
    vunary1(b, rd, rs2, neg, single)
}

/// FZERO/FONE。
fn vconst<B: Backend>(b: &mut B, rd: u8, one: bool, single: bool) -> Flow<B> {
    fp_check(b)?;
    let v = b.konst::<W64>(if one { !0u64 } else { 0 });
    if single {
        let m32 = b.konst::<W64>(0xffff_ffff);
        let v = b.and::<W64>(v, m32);
        fput_slot(b, rd, v);
        Ok(())
    } else {
        fputw64(b, rd, v)
    }
}
