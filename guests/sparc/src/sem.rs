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

/// 32 ビット演算の結果を rd の値に包む。V7/V8 では下位 32 ビット、
/// V9 では 32 ビット演算の結果を符号拡張して 64 ビットの rd に書く。
/// アドレス計算など全幅演算は `wmask` の方を使う。
/// Ref: SPEC-SPARC-V9 §Integer Register Usage.
fn emask<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    if b.param::<super::Word64Param>() {
        let lo = b.trunc::<W64, W32>(v);
        b.sext::<W32, W64>(lo)
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
    let v = emask(b, sum);
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
    let v = emask(b, diff);
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
    let v = emask(b, t);
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
#[derive(Clone, Copy)]
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
    let e = b.sext::<W32, W64>(r);
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
    let v = emask(b, qsat);
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
/// 符号を上位 32 ビットへ拡張する。V7/V8 は `wmask` で上位を捨てる。
/// Ref: SPEC-SPARC-V8 (Version 8) §SETHI.
/// Ref: SPEC-SPARC-V9 §SETHI.
pub fn sethi<B: Backend>(b: &mut B, rd: Gpr, imm22: u64) -> Flow<B> {
    let v32 = b.konst::<W32>((imm22 << 10) as u32);
    let s = b.sext::<W32, W64>(v32);
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
/// V8 では rd は偶数でなければならない。奇数のときの結果は不定で、
/// 本実装は隣接レジスタへの書き込みとして進める。
/// Ref: SPEC-SPARC-V8 (Version 8) §LDD.
pub fn ldd<B: Backend>(b: &mut B, rd: Gpr, rd2: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
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

/// Bicc。ICC を評価して npc を書き換える。成立すれば npc は
/// `target`（pc + sign_extend(disp22 << 2)）、不成立なら pc + 8。
/// 不成立でも npc を進めるのは、遅延スロットが pc + 4 にあって
/// commit が pc を npc に写すためで、書き換えないと遅延スロットの
/// 命令を二度実行することになる。
/// `a` が立っているときの取り消し（annul）規則は 2 通りある。
/// 条件分岐は不成立のときだけ遅延スロットを取り消し、成立したら
/// `a` にかかわらず実行する。BA（cond=8）は常に成立するので
/// `a` が立てば常に遅延スロットを取り消す。
/// Ref: SPEC-SPARC-V8 (Version 8) §Bicc.
pub fn bicc<B: Backend>(b: &mut B, a: u8, cond: u8, pc: u64, target: u64) -> Flow<B> {
    let val = cond_val(b, cond);
    let zero = b.konst::<W64>(0);
    let taken = b.cmp::<W64>(Cmp::Ne, val, zero);
    let t = const_w64(b, target);
    let fall = const_w64(b, pc.wrapping_add(8));
    let s = b.select::<W64>(taken, t, fall);
    let npc = wmask(b, s);
    let npc = amask(b, npc);
    b.set(npc_ref(), npc);
    if a != 0 {
        // BA は成立が確定しているので、annul の条件として `taken`
        // （常に真）をそのまま使う。それ以外は不成立のときだけ。
        let annul = if cond == 0b1000 {
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
/// ウィンドウあふれの検出は OS パーソナリティが再現するため、
/// ここではファイル内を巡回するだけである。CWP の進行方向は
/// モデルで逆で、V7/V8 では SAVE で減少、V9 では SAVE で増加する。
/// Ref: SPEC-SPARC-V8 (Version 8) §SAVE; SPEC-SPARC-V9 §SAVE.
pub fn save<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    let nw = nwindows(b);
    let delta = if b.param::<super::Word64Param>() {
        1
    } else {
        nw - 1
    };
    step_cwp(b, delta);
    write(b, rd, v);
    Ok(())
}

/// RESTORE。現ウィンドウで加算し、CWP を SAVE とは逆方向に 1 進めて
/// から戻ったウィンドウへ書く（V7/V8 では増加、V9 では減少）。
/// Ref: SPEC-SPARC-V8 (Version 8) §RESTORE; SPEC-SPARC-V9 §RESTORE.
pub fn restore<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    let nw = nwindows(b);
    let delta = if b.param::<super::Word64Param>() {
        nw - 1
    } else {
        1
    };
    step_cwp(b, delta);
    write(b, rd, v);
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
    let cmp = read(b, rd);
    let newv = read(b, rs2);
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
    let base = read(b, rs1);
    let off = src2(b, s);
    let sum = b.add::<W64>(base, off);
    let m = wmask(b, sum);
    let target = amask(b, m);
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
/// V9 の FPRS.FEF（ASR6）は本モデルに無く、PEF だけを条件にする。
/// FSR の cexc/aexc/tem による IEEE 例外機構も持たない。
/// Ref: SPEC-SPARC-V8 (Version 8) §The Floating-point Unit;
/// SPEC-SPARC-V9 §PSTATE, §Trap Type.
fn fp_check<B: Backend>(b: &mut B) -> Flow<B> {
    let v9 = b.param::<super::Word64Param>();
    let en = if v9 {
        let ts = b.get(tstate_ref());
        let sh = b.konst::<W64>(12);
        let s = b.shr_l::<W64>(ts, sh);
        let one = b.konst::<W64>(1);
        let m = b.and::<W64>(s, one);
        let zero = b.konst::<W64>(0);
        b.cmp::<W64>(Cmp::Ne, m, zero)
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

/// 倍精度ペアの基底スロット。V9 では奇数フィールドが上位倍精度
/// バンク %d32-%d62 を指すが、本モデルはバンクを持たないので
/// illegal instruction とする。V8 では奇数フィールドは予約で
/// あり、QEMU と同様に偶数へ畳む。フィールド 31 は f[32] が
/// 存在しないためどちらの場合でもここで遮断される。
/// Ref: SPEC-SPARC-V9 §5.1.4.1.
fn fpair_base<B: Backend>(b: &mut B, r: u8) -> Result<u8, B::Exit> {
    if r & 1 == 0 {
        Ok(r)
    } else if b.param::<super::Word64Param>() {
        Err(unimp(b, 0))
    } else {
        Ok(r & !1)
    }
}

/// スロット r,r+1 を連結した生の 64 ビット。倍精度（d レジスタ）は
/// 偶数 r のスロット r が上位ワード、r+1 が下位ワードを持つ。
/// %f(2n) が %dn の上位 32 ビットになる配置である。
/// Ref: SPEC-SPARC-V8 (Version 8) §Floating-Point Data Types.
fn fgetw64<B: Backend>(b: &mut B, r: u8) -> Result<B::V<W64>, B::Exit> {
    let r = fpair_base(b, r)?;
    let hi: B::V<W64> = b.get(Fpr(r).state());
    let lo: B::V<W64> = b.get(Fpr(r + 1).state());
    let sh = b.konst::<W64>(32);
    let h = b.shl::<W64>(hi, sh);
    let m = b.konst::<W64>(0xffff_ffff);
    let l = b.and::<W64>(lo, m);
    Ok(b.or::<W64>(h, l))
}

fn fputw64<B: Backend>(b: &mut B, r: u8, v: B::V<W64>) -> Result<(), B::Exit> {
    let r = fpair_base(b, r)?;
    let sh = b.konst::<W64>(32);
    let hi = b.shr_l::<W64>(v, sh);
    let m = b.konst::<W64>(0xffff_ffff);
    let lo = b.and::<W64>(v, m);
    b.set(Fpr(r).state(), hi);
    b.set(Fpr(r + 1).state(), lo);
    Ok(())
}

/// f レジスタの読み出し。F32 はスロット r の下位 32 ビット。
fn fget<B: Backend, F: Width>(b: &mut B, r: u8) -> Result<B::V<F>, B::Exit> {
    if F::BITS == 32 {
        let v: B::V<W64> = b.get(Fpr(r).state());
        Ok(b.trunc::<W64, F>(v))
    } else {
        let v = fgetw64(b, r)?;
        Ok(b.trunc::<W64, F>(v))
    }
}

fn fput<B: Backend, F: Width>(b: &mut B, r: u8, v: B::V<F>) -> Result<(), B::Exit> {
    let w = b.zext::<F, W64>(v);
    if F::BITS == 32 {
        b.set(Fpr(r).state(), w);
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

/// FMOVS。スロットの下位 32 ビットをそのままコピーする。
/// Ref: SPEC-SPARC-V8 (Version 8) §FMOVS.
fn fmovs<B: Backend>(b: &mut B, rd: u8, rs2: u8) -> Flow<B> {
    fp_check(b)?;
    let v: B::V<W64> = b.get(Fpr(rs2).state());
    b.set(Fpr(rd).state(), v);
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

/// FNEGS/FABSS と FNEGD/FABSD。符号ビットはスロットのビット 31
/// （倍精度では上位ワード側スロットのビット 31）で、どちらの精度
/// でも同じ位置にある。`neg` なら反転、さもなくば消去。
/// Ref: SPEC-SPARC-V8 (Version 8) §FNEGS, §FABSS; SPEC-SPARC-V9 §FNEG, §FABS.
fn fsgn<B: Backend>(b: &mut B, rd: u8, rs2: u8, neg: bool) -> Flow<B> {
    fp_check(b)?;
    let v: B::V<W64> = b.get(Fpr(rs2).state());
    let s = b.konst::<W64>(0x8000_0000);
    let w = if neg {
        b.xor::<W64>(v, s)
    } else {
        let n = b.not::<W64>(s);
        b.and::<W64>(v, n)
    };
    b.set(Fpr(rd).state(), w);
    Ok(())
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
        let x: B::V<W64> = b.get(Fpr(rs2).state());
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
        b.set(Fpr(rd).state(), w);
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
    b.set(Fpr(fd).state(), w);
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
    let v: B::V<W64> = b.get(Fpr(fs).state());
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
        // ASI 指定形。オペランドは (rd, rs1, asi, rs2)。V8 では特権
        // 命令なので先に権限を確かめる。アドレス空間の選択は
        // 後続ステップで扱うため、ここでは通常空間へのアクセスに
        // 畳み込む。
        Insn::Lda
        | Insn::Lduba
        | Insn::Lduha
        | Insn::Ldda
        | Insn::Ldsba
        | Insn::Ldsha
        | Insn::Ldstuba
        | Insn::Sta
        | Insn::Stba
        | Insn::Stha
        | Insn::Stda
        | Insn::Swapa => {
            let rd = Gpr(o[0] as u8);
            let rs1 = Gpr(o[1] as u8);
            let s = Src2::Reg(Gpr(o[3] as u8));
            let rd2 = Gpr(rd.0.wrapping_add(1) & 31);
            privileged_check(b)?;
            match insn {
                Insn::Lda => ld(b, rd, rs1, s),
                Insn::Lduba => ldub(b, rd, rs1, s),
                Insn::Lduha => lduh(b, rd, rs1, s),
                Insn::Ldda => ldd(b, rd, rd2, rs1, s),
                Insn::Ldsba => ldsb(b, rd, rs1, s),
                Insn::Ldsha => ldsh(b, rd, rs1, s),
                Insn::Ldstuba => ldstub(b, rd, rs1, s),
                Insn::Sta => st(b, rd, rs1, s),
                Insn::Stba => stb(b, rd, rs1, s),
                Insn::Stha => sth(b, rd, rs1, s),
                Insn::Stda => std(b, rd, rd2, rs1, s),
                Insn::Swapa => swap(b, rd, rs1, s),
                _ => unreachable!(),
            }
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
        Insn::Casa => cas_common(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[3] as u8), false),
        Insn::CasaI => cas_common(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8), false),
        Insn::Casxa => cas_common(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[3] as u8), true),
        Insn::CasxaI => cas_common(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Gpr(o[2] as u8), true),
        // V9 の RETURN。オペランドは (rs1, src2)。
        Insn::Return => ret(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::ReturnI => ret(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
        // 観測可能な効果のない命令群。
        Insn::Stbar
        | Insn::Membar
        | Insn::Flush
        | Insn::FlushI
        | Insn::Saved
        | Insn::Restored
        | Insn::Flushw => nop(b),
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
        Insn::Fnegs | Insn::Fnegd => fsgn(b, o[0] as u8, o[1] as u8, true),
        Insn::Fabss | Insn::Fabsd => fsgn(b, o[0] as u8, o[1] as u8, false),
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
        // ASR。読み出し形のオペランドは rd、書き込み形は (rs1, src2)。
        Insn::Rdy => rdy(b, Gpr(o[0] as u8)),
        Insn::Wry => wry(b, Gpr(o[0] as u8), Src2::Reg(Gpr(o[1] as u8))),
        Insn::WryI => wry(b, Gpr(o[0] as u8), Src2::Imm(sext13(o[1]))),
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
