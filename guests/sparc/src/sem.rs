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
//! レジスタファイル上の位置が変わる。SAVE は CWP を 1 減らし、
//! RESTORE は 1 増やす。ウィンドウのあふれと不足は OS パーソナリティ
//! が再現する（段階 15 の SP12）。
//! V7/V8 は整数レジスタの演算を 32 ビットで、V9 は 64 ビットで行う
//! （`word64` パラメータ）。
//!
//! 出典は SPEC-SPARC-V7 (Solbourne 101482-00)、SPEC-SPARC-V8
//! (Version 8)、SPEC-SPARC-V9 (SAV09R1459912) である。
//! Ref: SPEC-SPARC-V7.
//! Ref: SPEC-SPARC-V8 (Version 8).
//! Ref: SPEC-SPARC-V9.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, Flow, StateArray, StateRef, W8, W16, W32, W64, Width};

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
/// Ref: SPEC-SPARC-V8 (Version 8) §The Windowed Integer Registers.
fn phys_index<B: Backend>(b: &mut B, reg: u8) -> B::V<W32> {
    if reg < 8 {
        return b.konst::<W32>(u32::from(reg));
    }
    let nw = nwindows(b);
    let cwp: B::V<W64> = b.get(cwp_ref());
    let off = b.konst::<W64>(u64::from(reg) - 8);
    let sixteen = b.konst::<W64>(16);
    let base = b.mul::<W64>(cwp, sixteen);
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
    ((v as i64) << 51) >> 51
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

/// ICC の指定ビット（N=23, Z=22, V=21, C=20）が立っているか。
fn icc_bit<B: Backend>(b: &mut B, n: u32) -> B::B {
    let psr = b.get(psr_ref());
    let m = b.konst::<W32>(1u32 << n);
    let masked = b.and::<W32>(psr, m);
    let zero = b.konst::<W32>(0);
    b.cmp::<W32>(Cmp::Ne, masked, zero)
}

/// ICC を更新する。N,Z は `res`（W32 の演算結果）から、V,C は引数の
/// 判定値から取る。V9 の xcc への対応は後続ステップ（SP9）で扱う。
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

/// 加算の共通処理。`carry` が立っていれば ICC の C を足す（ADDX 系）。
/// `cc` が立っていれば N,Z,V,C を ICC に書く。V8 では 32 ビット側で
/// 旗を計算する。
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
        let res32 = b.trunc::<W64, W32>(v);
        set_icc(b, res32, ovf, cry);
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
        let x32 = b.trunc::<W64, W32>(x);
        let y32 = b.trunc::<W64, W32>(y);
        let iy = b.not::<W32>(y32);
        let nb = inv_b(b, bin);
        let (_r, cry, ovf) = b.add_with_carry::<W32>(x32, iy, nb);
        let res32 = b.trunc::<W64, W32>(v);
        let borrow = inv_b(b, cry);
        set_icc(b, res32, ovf, borrow);
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
        let res32 = b.trunc::<W64, W32>(v);
        let f = false_b(b);
        set_icc(b, res32, f, f);
    }
    Ok(())
}

/// シフトの共通処理。V7/V8 では rs1 の 32 ビットを下位 5 ビットの量で
/// 動かす。V9 の 64 ビットシフト（sllx/srlx/srax）は SP9 で扱う。
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
        let f = false_b(b);
        set_icc(b, lo, f, f);
    }
    Ok(())
}

/// 除算の共通処理。被除数は {Y, rs1} の 64 ビット。商を rd に書く。
/// 仕様では除算後の Y は不定だが、本実装は剰余を格納する実装任意の
/// 選択肢を取る。`signed` で SDIV/UDIV を分ける。0 除算は division by
/// zero トラップ（tt = 0x2A）。`cc` 形は N,Z を商から、V を商の
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
    b.if_then(isz, |bb| {
        Err(bb.raise(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Trap,
            code: 0x2A,
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
    let v = wmask(b, qsat);
    write(b, rd, v);
    let rm = wmask(b, r);
    b.set(y_ref(), rm);
    if cc {
        // V は商が 32 ビットに収まらないとき立つ。N,Z は格納した
        // （飽和後の）商から取る。
        let res32 = b.trunc::<W64, W32>(qsat);
        let ovf = inv_b(b, fits);
        let f = false_b(b);
        set_icc(b, res32, ovf, f);
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
    set_icc(b, res, ovf, cry);
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
/// アクセスも 32 ビットアドレスなので `wmask` をかける。
/// Ref: SPEC-SPARC-V8 (Version 8) §Load/Store Instructions.
fn eff_addr<B: Backend>(b: &mut B, rs1: Gpr, s: Src2) -> B::V<W64> {
    let base = read(b, rs1);
    let off = src2(b, s);
    let sum = b.add::<W64>(base, off);
    wmask(b, sum)
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
    let target = wmask(b, sum);
    let ret = const_w64(b, pc);
    write(b, rd, ret);
    b.set(npc_ref(), target);
    Ok(())
}

/// CALL。遅延スロット付きの直接呼び出し。戻り（pc）を %o7 に書く。
/// `target` は pc + sign_extend(disp30 << 2)。
/// Ref: SPEC-SPARC-V8 (Version 8) §CALL.
pub fn call<B: Backend>(b: &mut B, pc: u64, target: u64) -> Flow<B> {
    let ret = const_w64(b, pc);
    write(b, Gpr(15), ret);
    let k = const_w64(b, target);
    let t = wmask(b, k);
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

/// 条件の評価値。ICC は PSR の N(23) Z(22) V(21) C(20)。
/// 返り値は 0/1 の値で、0 なら不成立。各条件は値演算で組み立てる。
/// V9 の条件コード（%ccr）は TSTATE 側にあり、ここでは V7/V8 の
/// ICC だけを読む。V9 の Bicc/FBfcc 差分は後続ステップで扱う。
/// Ref: SPEC-SPARC-V8 (Version 8) §Instruction Descriptions (Bicc).
fn cond_val<B: Backend>(b: &mut B, cond: u8) -> B::V<W64> {
    let psr = b.get(psr_ref());
    let p64 = b.zext::<W32, W64>(psr);
    let bit = |bb: &mut B, n: u64| -> B::V<W64> {
        let sh = bb.konst::<W64>(n);
        let one = bb.konst::<W64>(1);
        let s = bb.shr_l::<W64>(p64, sh);
        bb.and::<W64>(s, one)
    };
    let n = bit(b, 23);
    let z = bit(b, 22);
    let v = bit(b, 21);
    let c = bit(b, 20);
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

/// SAVE。旧ウィンドウで加算し、CWP を 1 減らしてから新ウィンドウへ書く。
/// ウィンドウあふれの検出は OS パーソナリティが再現するため、
/// ここではファイル内を巡回するだけである。
/// Ref: SPEC-SPARC-V8 (Version 8) §SAVE.
pub fn save<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    let nw = nwindows(b);
    step_cwp(b, nw - 1);
    write(b, rd, v);
    Ok(())
}

/// RESTORE。現ウィンドウで加算し、CWP を 1 増やしてから戻った
/// ウィンドウへ書く。
/// Ref: SPEC-SPARC-V8 (Version 8) §RESTORE.
pub fn restore<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    step_cwp(b, 1);
    write(b, rd, v);
    Ok(())
}

/// UNIMP。illegal instruction トラップとして表す。
// Ref: SPEC-SPARC-V8 (Version 8) §UNIMP.
pub fn unimp<B: Backend>(b: &mut B, imm22: u64) -> B::Exit {
    b.raise(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Trap,
        code: u64::from(imm22 as u32),
        addr: None,
        in_delay_slot: false,
    })
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
    let next = wmask(b, sum);
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
        // 命令だが、空間選択と特権トラップは SP8 で扱うため、ここでは
        // 通常空間へのアクセスに畳み込む。
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
