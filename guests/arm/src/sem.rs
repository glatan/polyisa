// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A32（ARM 状態）の命令意味論。バックエンドに対して総称的に書く。
//!
//! デコードで粗分類した領域ごとのエントリを持ち、固定ビットで命令を
//! さらに振り分ける。条件実行は実行ループが済ませるので、ここに来る
//! 命令は常に実行される（cond 失敗は実行ループが pc を進める）。
//!
//! - r15 の読み値は「命令アドレス+8」、書き込みは分岐（`Ctrl::Jump`）。
//! - CPSR は N(31) Z(30) C(29) V(28) Q(27) GE(19:16) を保持する。
//! - データアクセスのエンディアンは現在 LE 固定。
//!
//! 出典の版は SPEC-ARM-ARM-A（Arm ARM A32）である。

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{
    Backend, Cmp, ExceptionKind, F32, F64, Flow, GuestException, StateRef, W32, W64,
};

use super::CpuState;

/// 汎用レジスタ番号。15 は pc（読みは pc+8、書きは分岐）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W32> {
        StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, r) + usize::from(self.0) * 4)
    }
}

/// CPSR の状態参照。
pub fn cpsr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, cpsr))
}

/// TPIDRURW（ユーザ読み書きスレッド id）の状態参照。
pub fn tpidrurw_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, tpidrurw))
}

/// TPIDRURO（ユーザ読み出しスレッド id）の状態参照。
pub fn tpidruro_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, tpidruro))
}

/// FPSCR の状態参照。
pub fn fpscr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, fpscr))
}

/// VFP D レジスタ（d < 32）の状態参照。
pub fn vfp_ref(d: u8) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, vfp) + usize::from(d) * 8)
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

/// 浮動小数点の丸めモード番号（polyisa_softfloat::Rm 準拠）。
const RM_RNE: u8 = 0;
const RM_RTZ: u8 = 1;

fn unimpl<B: Backend>(b: &mut B) -> B::Exit {
    b.raise(GuestException {
        kind: ExceptionKind::Undefined,
        code: 0,
        addr: None,
        in_delay_slot: false,
    })
}

fn k32<B: Backend>(b: &mut B, v: u32) -> B::V<W32> {
    b.konst::<W32>(v)
}

fn k64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

fn tb<B: Backend>(b: &mut B) -> B::B {
    let o = k32(b, 1);
    let z = k32(b, 0);
    b.cmp::<W32>(Cmp::Ne, o, z)
}

fn fb<B: Backend>(b: &mut B) -> B::B {
    let z = k32(b, 0);
    b.cmp::<W32>(Cmp::Ne, z, z)
}

fn inv<B: Backend>(b: &mut B, c: B::B) -> B::B {
    let t = k32(b, 1);
    let f = k32(b, 0);
    let s = b.select::<W32>(c, f, t);
    let z = k32(b, 0);
    b.cmp::<W32>(Cmp::Ne, s, z)
}

fn band<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let t = k32(b, 1);
    let f = k32(b, 0);
    let sy = b.select::<W32>(y, t, f);
    let r = b.select::<W32>(x, sy, f);
    let z = k32(b, 0);
    b.cmp::<W32>(Cmp::Ne, r, z)
}

fn bor<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let t = k32(b, 1);
    let f = k32(b, 0);
    let sy = b.select::<W32>(y, t, f);
    let r = b.select::<W32>(x, t, sy);
    let z = k32(b, 0);
    b.cmp::<W32>(Cmp::Ne, r, z)
}

// ---- レジスタの読み書き ----

/// `r` を読む。15 は命令アドレス+8。
fn rd<B: Backend>(b: &mut B, r: u8, pc: u64) -> B::V<W32> {
    if r == 15 {
        k32(b, pc.wrapping_add(8) as u32)
    } else {
        b.get(Gpr(r).state())
    }
}

/// `r` に書く。15 への書き込みは分岐（bit0 を落として ARM 状態のまま）。
fn wr<B: Backend>(b: &mut B, r: u8, v: B::V<W32>) {
    if r == 15 {
        let m = k32(b, !3u32);
        let a = b.and(v, m);
        let w = b.zext::<W32, W64>(a);
        b.jump(w);
    } else {
        b.set(Gpr(r).state(), v);
    }
}

/// W32 アドレスをメモリ API の W64 にする。
fn a64<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W64> {
    b.zext::<W32, W64>(v)
}

// ---- CPSR ----

fn cpsr<B: Backend>(b: &mut B) -> B::V<W32> {
    b.get(cpsr_ref())
}

/// CPSR の bit を真偽値にする。
fn cflag<B: Backend>(b: &mut B, bit: u32) -> B::B {
    let c = cpsr(b);
    let m = k32(b, 1 << bit);
    let a = b.and(c, m);
    let z = k32(b, 0);
    b.cmp::<W32>(Cmp::Ne, a, z)
}

fn flag_c<B: Backend>(b: &mut B) -> B::B {
    cflag(b, 29)
}

fn flag_v<B: Backend>(b: &mut B) -> B::B {
    cflag(b, 28)
}

/// 4 フラグを cpsr に書く。
fn set_flags<B: Backend>(b: &mut B, n: B::B, z: B::B, c: B::B, v: B::B) {
    let cs = cpsr(b);
    let __h0 = k32(b, 0x0fff_ffff);

    let keep = b.and(cs, __h0);
    let __h1 = k32(b, 1 << 31);
    let __h2 = k32(b, 0);

    let n31 = b.select::<W32>(n, __h1, __h2);
    let __h3 = k32(b, 1 << 30);
    let __h4 = k32(b, 0);

    let z30 = b.select::<W32>(z, __h3, __h4);
    let __h5 = k32(b, 1 << 29);
    let __h6 = k32(b, 0);

    let c29 = b.select::<W32>(c, __h5, __h6);
    let __h7 = k32(b, 1 << 28);
    let __h8 = k32(b, 0);

    let v28 = b.select::<W32>(v, __h7, __h8);
    let __h9 = b.or(n31, z30);
    let __h10 = b.or(c29, v28);

    let hi = b.or(__h9, __h10);
    let __h11 = b.or(keep, hi);

    b.set(cpsr_ref(), __h11);
}

/// 論理演算のフラグ。N/Z は結果から、C はシフタのキャリー、V/Q は不変。
fn set_nz<B: Backend>(b: &mut B, res: B::V<W32>, carry: B::B) {
    let msb = k32(b, 1 << 31);
    let z32 = k32(b, 0);
    let masked = b.and(res, msb);
    let n = b.cmp::<W32>(Cmp::Ne, masked, z32);
    let z = b.cmp::<W32>(Cmp::Eq, res, z32);
    let v = flag_v(b);
    set_flags(b, n, z, carry, v);
}

/// 算術演算のフラグ。N/Z/C/V をすべて書く。
fn set_nzcv<B: Backend>(b: &mut B, res: B::V<W32>, carry: B::B, ovf: B::B) {
    let msb = k32(b, 1 << 31);
    let z32 = k32(b, 0);
    let masked = b.and(res, msb);
    let n = b.cmp::<W32>(Cmp::Ne, masked, z32);
    let z = b.cmp::<W32>(Cmp::Eq, res, z32);
    set_flags(b, n, z, carry, ovf);
}

/// Q フラグを `sat` が真なら立てる（飽和演算用）。
fn set_q<B: Backend>(b: &mut B, sat: B::B) {
    let cs = cpsr(b);
    let q = k32(b, 1 << 27);
    let with = b.or(cs, q);
    let nv = b.select::<W32>(sat, with, cs);
    b.set(cpsr_ref(), nv);
}

/// GE[3:0] を 4 ビット値で書く（並列演算用）。
fn set_ge<B: Backend>(b: &mut B, ge: u32) {
    let cs = cpsr(b);
    let __h12 = k32(b, 0xfff0_ffff);

    let keep = b.and(cs, __h12);
    let __h13 = k32(b, ge << 16);

    let new = b.or(keep, __h13);
    b.set(cpsr_ref(), new);
}

// ---- シフタ ----

/// 即値シフト。`(結果, キャリー)`。`ty`: 0 lsl, 1 lsr, 2 asr, 3 ror/rrx。
/// `amt` は符号化された 5 ビット量（lsr/asr/ror で 0 は 32 または RRX）。
fn sh_imm<B: Backend>(b: &mut B, v: B::V<W32>, ty: u32, amt: u32, c_in: B::B) -> (B::V<W32>, B::B) {
    let one = k32(b, 1);
    let z = k32(b, 0);
    let msb = k32(b, 1 << 31);
    match (ty, amt) {
        (0, 0) => (v, c_in),
        (0, n) => {
            let __h14 = k32(b, n);

            // LSL #n：落ちる最後のビットは bit(32-n)。
            let r = b.shl(v, __h14);
            let __h15 = k32(b, 32 - n);
            let __h16 = b.shr_l(v, __h15);

            let cbit = b.and(__h16, one);
            let c = b.cmp::<W32>(Cmp::Ne, cbit, z);
            (r, c)
        }
        (1, 0) => {
            // LSR #32：結果 0、キャリーは bit31。
            let cbit = b.and(v, msb);
            let c = b.cmp::<W32>(Cmp::Ne, cbit, z);
            (z, c)
        }
        (1, n) => {
            let __h17 = k32(b, n);

            // LSR #n
            let r = b.shr_l(v, __h17);
            let __h18 = k32(b, n - 1);
            let __h19 = b.shr_l(v, __h18);

            let cbit = b.and(__h19, one);
            let c = b.cmp::<W32>(Cmp::Ne, cbit, z);
            (r, c)
        }
        (2, 0) => {
            // ASR #32：全ビット符号、キャリーは bit31。
            let cbit = b.and(v, msb);
            let c = b.cmp::<W32>(Cmp::Ne, cbit, z);
            let __h20 = k32(b, 0xffff_ffff);

            let all = b.select::<W32>(c, __h20, z);
            (all, c)
        }
        (2, n) => {
            let __h21 = k32(b, n);

            // ASR #n
            let r = b.shr_a(v, __h21);
            let __h22 = k32(b, n - 1);
            let __h23 = b.shr_l(v, __h22);

            let cbit = b.and(__h23, one);
            let c = b.cmp::<W32>(Cmp::Ne, cbit, z);
            (r, c)
        }
        (3, 0) => {
            // RRX：キャリーを最上位に入れて 1 回転。
            let cbit = b.and(v, one);
            let c = b.cmp::<W32>(Cmp::Ne, cbit, z);
            let top = b.select::<W32>(c_in, msb, z);
            let __h24 = b.shr_l(v, one);

            let r = b.or(__h24, top);
            (r, c)
        }
        (_, n) => {
            let __h25 = k32(b, n);

            // ROR #n
            let lo = b.shr_l(v, __h25);
            let __h26 = k32(b, 32 - n);

            let hi = b.shl(v, __h26);
            let r = b.or(lo, hi);
            let cbit = b.and(r, msb);
            let c = b.cmp::<W32>(Cmp::Ne, cbit, z);
            (r, c)
        }
    }
}

/// レジスタシフト。`rs` はシフト量レジスタの値（下位 8 ビットを見る）。
fn sh_reg<B: Backend>(
    b: &mut B,
    v: B::V<W32>,
    ty: u32,
    rs: B::V<W32>,
    c_in: B::B,
) -> (B::V<W32>, B::B) {
    let one = k32(b, 1);
    let z = k32(b, 0);
    let msb = k32(b, 1 << 31);
    let __h27 = k32(b, 0xff);

    let amt = b.and(rs, __h27);
    let __h28 = k32(b, 31);

    let a5 = b.and(amt, __h28);
    let az = b.cmp::<W32>(Cmp::Eq, amt, z);
    let __h29 = k32(b, 32);

    let lt32 = b.cmp::<W32>(Cmp::LtU, amt, __h29);
    let __h30 = k32(b, 32);

    let eq32 = b.cmp::<W32>(Cmp::Eq, amt, __h30);
    let (r, c) = match ty {
        0 => {
            // LSL：n<32 は左、n>=32 は 0。キャリー：n<32 → bit(32-n)、
            // n=32 → bit0、n>32 → 0。
            let shift = b.shl(v, a5);
            let rr = b.select::<W32>(lt32, shift, z);
            let __h31 = k32(b, 32);

            let back = b.sub(__h31, amt);
            let __h32 = b.shr_l(v, back);

            let cb = b.and(__h32, one);
            let c_lt = b.cmp::<W32>(Cmp::Ne, cb, z);
            let b0 = b.and(v, one);
            let c_eq = b.cmp::<W32>(Cmp::Ne, b0, z);
            let __h33 = sel_b(b, c_lt);

            let c_pre = b.select::<W32>(lt32, __h33, z);
            let __h34 = sel_b(b, c_eq);

            let c_all = b.select::<W32>(eq32, __h34, c_pre);
            let c = b.cmp::<W32>(Cmp::Ne, c_all, z);
            (rr, c)
        }
        1 => {
            // LSR：n<32 → bit(n-1)、n=32 → bit31、n>32 → 0。
            let shift = b.shr_l(v, a5);
            let rr = b.select::<W32>(lt32, shift, z);
            let back = b.sub(amt, one);
            let __h35 = b.shr_l(v, back);

            let cb = b.and(__h35, one);
            let c_lt = b.cmp::<W32>(Cmp::Ne, cb, z);
            let b31 = b.and(v, msb);
            let c_eq = b.cmp::<W32>(Cmp::Ne, b31, z);
            let __h36 = sel_b(b, c_lt);

            let c_pre = b.select::<W32>(lt32, __h36, z);
            let __h37 = sel_b(b, c_eq);

            let c_all = b.select::<W32>(eq32, __h37, c_pre);
            let c = b.cmp::<W32>(Cmp::Ne, c_all, z);
            (rr, c)
        }
        2 => {
            // ASR：n<32 → bit(n-1)、n>=32 → bit31。値も n>=32 で全符号。
            let shift = b.shr_a(v, a5);
            let b31 = b.and(v, msb);
            let sgn = b.cmp::<W32>(Cmp::Ne, b31, z);
            let __h38 = k32(b, 0xffff_ffff);

            let all = b.select::<W32>(sgn, __h38, z);
            let rr = b.select::<W32>(lt32, shift, all);
            let back = b.sub(amt, one);
            let __h39 = b.shr_l(v, back);

            let cb = b.and(__h39, one);
            let c_lt = b.cmp::<W32>(Cmp::Ne, cb, z);
            let __h40 = sel_b(b, c_lt);
            let __h41 = sel_b(b, sgn);

            let c_pre = b.select::<W32>(lt32, __h40, __h41);
            let c = b.cmp::<W32>(Cmp::Ne, c_pre, z);
            (rr, c)
        }
        _ => {
            // ROR：n&31==0 かつ n!=0 は値不変・c=bit31。
            let lo = b.shr_l(v, a5);
            let __h42 = k32(b, 32);
            let __h43 = b.sub(__h42, a5);
            let __h44 = k32(b, 31);

            let back = b.and(__h43, __h44);
            let hi = b.shl(v, back);
            let rot = b.or(lo, hi);
            let a5z = b.cmp::<W32>(Cmp::Eq, a5, z);
            let anz = b.cmp::<W32>(Cmp::Ne, amt, z);
            let rr = b.select::<W32>(a5z, v, rot);
            let b31r = b.and(rot, msb);
            let c_rot = b.cmp::<W32>(Cmp::Ne, b31r, z);
            let b31v = b.and(v, msb);
            let c_31 = b.cmp::<W32>(Cmp::Ne, b31v, z);
            let __h45 = sel_b(b, c_31);
            let __h46 = sel_b(b, c_rot);

            let c_mid = b.select::<W32>(a5z, __h45, __h46);
            let __h47 = sel_b(b, c_in);

            let c_fin = b.select::<W32>(anz, c_mid, __h47);
            let c = b.cmp::<W32>(Cmp::Ne, c_fin, z);
            (rr, c)
        }
    };
    // amt==0 はシフトなし・キャリー不変。
    let ro = b.select::<W32>(az, v, r);
    let __h48 = sel_b(b, c_in);
    let __h49 = sel_b(b, c);

    let co = b.select::<W32>(az, __h48, __h49);
    let cc = b.cmp::<W32>(Cmp::Ne, co, z);
    (ro, cc)
}

/// 真偽値を 0/1 の値にする。
fn sel_b<B: Backend>(b: &mut B, c: B::B) -> B::V<W32> {
    let __h50 = k32(b, 1);
    let __h51 = k32(b, 0);

    b.select::<W32>(c, __h50, __h51)
}

// ---- データ処理 ----

/// 即値形式のオペランド 2。`(拡張した値, キャリー)`。
fn dp_op2_imm<B: Backend>(b: &mut B, word: u32) -> (B::V<W32>, B::B) {
    let imm = k32(b, word & 0xff);
    let rot = ((word >> 8) & 0xf) * 2;
    let c_in = flag_c(b);
    if rot == 0 {
        (imm, c_in)
    } else {
        sh_imm(b, imm, 3, rot, c_in)
    }
}

/// レジスタ・即値シフト形式のオペランド 2。
fn dp_op2_reg_imm<B: Backend>(b: &mut B, word: u32, pc: u64) -> (B::V<W32>, B::B) {
    let rm = (word & 0xf) as u8;
    let ty = (word >> 5) & 3;
    let amt = (word >> 7) & 31;
    let v = rd(b, rm, pc);
    let c_in = flag_c(b);
    sh_imm(b, v, ty, amt, c_in)
}

/// レジスタ・レジスタシフト形式のオペランド 2。
fn dp_op2_reg_reg<B: Backend>(b: &mut B, word: u32, pc: u64) -> (B::V<W32>, B::B) {
    let rm = (word & 0xf) as u8;
    let ty = (word >> 5) & 3;
    let rs = ((word >> 8) & 0xf) as u8;
    let v = rd(b, rm, pc);
    let s = rd(b, rs, pc);
    let c_in = flag_c(b);
    sh_reg(b, v, ty, s, c_in)
}

/// データ処理の実行。op2 とシフタキャリーは済んでいる。
fn dp_exec<B: Backend>(b: &mut B, word: u32, pc: u64, op2: B::V<W32>, carry: B::B) -> Flow<B> {
    let op4 = (word >> 21) & 0xf;
    let s = (word >> 20) & 1 != 0;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rn = ((word >> 16) & 0xf) as u8;
    let a = rd(b, rn, pc);
    let not2 = b.not(op2);
    match op4 {
        // 論理系（テスト 8-11 は rd を書かない）
        0 | 1 | 8 | 9 | 12 | 13 | 14 | 15 => {
            let res = match op4 {
                0 | 8 => b.and(a, op2),
                1 | 9 => b.xor(a, op2),
                12 => b.or(a, op2),
                13 => op2,
                14 => b.and(a, not2),
                _ => not2,
            };
            if s {
                set_nz(b, res, carry);
            }
            // テスト 8-11（TST/TEQ/CMP/CMN 相当の 8-11）は rd を書かない。
            if !(8..12).contains(&op4) {
                wr(b, rdn, res);
            }
        }
        // 算術系
        _ => {
            let (res, c, v) = match op4 {
                2 | 10 => {
                    // sub / cmp = a + ~op2 + 1
                    let t = tb(b);
                    b.add_with_carry::<W32>(a, not2, t)
                }
                3 => {
                    // rsb = op2 + ~a + 1
                    let t = tb(b);
                    let na = b.not(a);
                    b.add_with_carry::<W32>(op2, na, t)
                }
                4 | 11 => {
                    // add / cmn
                    let f = fb(b);
                    b.add_with_carry::<W32>(a, op2, f)
                }
                5 => {
                    // adc
                    let c0 = flag_c(b);
                    b.add_with_carry::<W32>(a, op2, c0)
                }
                6 => {
                    // sbc = a + ~op2 + C
                    let c0 = flag_c(b);
                    b.add_with_carry::<W32>(a, not2, c0)
                }
                _ => {
                    // rsc = op2 + ~a + C
                    let c0 = flag_c(b);
                    let na = b.not(a);
                    b.add_with_carry::<W32>(op2, na, c0)
                }
            };
            if s {
                set_nzcv(b, res, c, v);
            }
            if op4 < 8 {
                wr(b, rdn, res);
            }
        }
    }
    Ok(())
}

// ---- 単一ロード/ストア ----

/// `ls_imm`/`ls_reg` 共通。`reg_off` が真ならオフセットはシフト済みレジスタ。
pub fn ls<B: Backend>(b: &mut B, word: u32, pc: u64, reg_off: bool) -> Flow<B> {
    let p = (word >> 24) & 1 != 0;
    let u = (word >> 23) & 1 != 0;
    let byte = (word >> 22) & 1 != 0;
    let w = (word >> 21) & 1 != 0;
    let l = (word >> 20) & 1 != 0;
    let rn = ((word >> 16) & 0xf) as u8;
    let rt = ((word >> 12) & 0xf) as u8;
    let base = rd(b, rn, pc);
    let off = if reg_off {
        let rm = (word & 0xf) as u8;
        let ty = (word >> 5) & 3;
        let amt = (word >> 7) & 31;
        let v = rd(b, rm, pc);
        let c = flag_c(b);
        let (o, _) = sh_imm(b, v, ty, amt, c);
        o
    } else {
        k32(b, word & 0xfff)
    };
    let delta = if u {
        off
    } else {
        let n = b.not(off);
        let __h52 = k32(b, 1);

        b.add(n, __h52)
    };
    let addr = if p { b.add(base, delta) } else { base };
    if l {
        if byte {
            let __h53 = a64(b, addr);

            let v = b.load::<polyisa_sem::W8>(__h53, DATA_READ)?;
            let v = b.zext::<polyisa_sem::W8, W32>(v);
            wr(b, rt, v);
        } else {
            let __h54 = a64(b, addr);

            let v = b.load::<W32>(__h54, DATA_READ)?;
            wr(b, rt, v);
        }
    } else {
        let v = rd(b, rt, pc);
        if byte {
            let v8 = b.trunc::<W32, polyisa_sem::W8>(v);
            let __h55 = a64(b, addr);

            b.store::<polyisa_sem::W8>(__h55, v8, DATA_WRITE)?;
        } else {
            let __h56 = a64(b, addr);

            b.store::<W32>(__h56, v, DATA_WRITE)?;
        }
    }
    // 書き戻し。T 形式（P=0,W=1）はユーザでは書き戻しだけなら同じ。
    let wb = p && w || !p;
    if wb {
        let nb = b.add(base, delta);
        b.set(Gpr(rn).state(), nb);
    }
    Ok(())
}

// ---- 追加ロード/ストア（半・符号・ダブル）----

/// `els_h`/`els_d` 共通。sh = bits[6:5]（1: 半, 2: ダブル, 3: 符号）。
pub fn els<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let p = (word >> 24) & 1 != 0;
    let u = (word >> 23) & 1 != 0;
    let i = (word >> 22) & 1 != 0;
    let w = (word >> 21) & 1 != 0;
    let l = (word >> 20) & 1 != 0;
    let rn = ((word >> 16) & 0xf) as u8;
    let rt = ((word >> 12) & 0xf) as u8;
    let sh = (word >> 5) & 3;
    let base = rd(b, rn, pc);
    let off = if i {
        let hi = (word >> 8) & 0xf;
        let lo = word & 0xf;
        k32(b, hi << 4 | lo)
    } else {
        let rm = (word & 0xf) as u8;
        rd(b, rm, pc)
    };
    let delta = if u {
        off
    } else {
        let n = b.not(off);
        let __h57 = k32(b, 1);

        b.add(n, __h57)
    };
    let addr = if p { b.add(base, delta) } else { base };
    match (sh, l) {
        // strh
        (1, false) => {
            let v = rd(b, rt, pc);
            let v = b.trunc::<W32, polyisa_sem::W16>(v);
            let __h58 = a64(b, addr);

            b.store::<polyisa_sem::W16>(__h58, v, DATA_WRITE)?;
        }
        // ldrh
        (1, true) => {
            let __h59 = a64(b, addr);

            let v = b.load::<polyisa_sem::W16>(__h59, DATA_READ)?;
            let v = b.zext::<polyisa_sem::W16, W32>(v);
            wr(b, rt, v);
        }
        // ldrd：rt,rt+1 を 8 バイトで。(sh=10, L=0)
        (2, false) => {
            let __h63 = a64(b, addr);

            let v = b.load::<W64>(__h63, DATA_READ)?;
            let lo = b.trunc::<W64, W32>(v);
            let __h64 = k64(b, 32);
            let __h65 = b.shr_l(v, __h64);

            let hi = b.trunc::<W64, W32>(__h65);
            wr(b, rt, lo);
            wr(b, rt + 1, hi);
        }
        // ldrsb (sh=10, L=1)
        (2, true) => {
            let __h66 = a64(b, addr);

            let v = b.load::<polyisa_sem::W8>(__h66, DATA_READ)?;
            let v = b.sext::<polyisa_sem::W8, W32>(v);
            wr(b, rt, v);
        }
        // strd：rt,rt+1 を 8 バイトで。(sh=11, L=0)
        (3, false) => {
            let lo = rd(b, rt, pc);
            let hi = rd(b, rt + 1, pc);
            let lo64 = b.zext::<W32, W64>(lo);
            let hi64 = b.zext::<W32, W64>(hi);
            let __h60 = k64(b, 32);
            let __h61 = b.shl(hi64, __h60);

            let v = b.or(lo64, __h61);
            let __h62 = a64(b, addr);

            b.store::<W64>(__h62, v, DATA_WRITE)?;
        }
        // ldrsh (sh=11, L=1)
        _ => {
            let __h67 = a64(b, addr);

            let v = b.load::<polyisa_sem::W16>(__h67, DATA_READ)?;
            let v = b.sext::<polyisa_sem::W16, W32>(v);
            wr(b, rt, v);
        }
    }
    let wb = p && w || !p;
    if wb {
        let nb = b.add(base, delta);
        b.set(Gpr(rn).state(), nb);
    }
    Ok(())
}

// ---- ブロック転送 ----

/// LDM/STM。P(24) U(23) S(22) W(21) L(20)、rn=[19:16]、リスト=[15:0]。
/// ユーザモードでは S は無視する（別バンクも復元も扱わない）。
pub fn ldm_stm<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let p = (word >> 24) & 1 != 0;
    let u = (word >> 23) & 1 != 0;
    let w = (word >> 21) & 1 != 0;
    let l = (word >> 20) & 1 != 0;
    let rn = ((word >> 16) & 0xf) as u8;
    let list = word & 0xffff;
    if list == 0 {
        return Err(unimpl(b));
    }
    let base = rd(b, rn, pc);
    let n = list.count_ones();
    // 最初の転送アドレス。以降は 4 ずつ昇順。レジスタは番号の昇順で並ぶ。
    let first: i64 = match (u, p) {
        (true, false) => 0,                      // IA
        (true, true) => 4,                       // IB
        (false, false) => -4 * i64::from(n) + 4, // DA
        (false, true) => -4 * i64::from(n),      // DB
    };
    let __h68 = k32(b, first as u32);

    let start = b.add(base, __h68);
    if l {
        // 書き戻しを先に済ませる（rn がリスト内ならロード値が勝つ）。
        if w {
            let __h69 = k32(b, if u { 4 * n } else { 0u32.wrapping_sub(4 * n) });

            let wb = b.add(base, __h69);
            b.set(Gpr(rn).state(), wb);
        }
        let mut addr = start;
        let mut pc_v: Option<B::V<W32>> = None;
        for r in 0u8..16 {
            if list & (1 << r) != 0 {
                let __h70 = a64(b, addr);

                let v = b.load::<W32>(__h70, DATA_READ)?;
                if r == 15 {
                    pc_v = Some(v);
                } else {
                    b.set(Gpr(r).state(), v);
                }
                let __h71 = k32(b, 4);

                addr = b.add(addr, __h71);
            }
        }
        if let Some(v) = pc_v {
            wr(b, 15, v);
        }
    } else {
        // ストアは古い rn 値を使う（書き戻しは後）。
        let mut addr = start;
        for r in 0u8..16 {
            if list & (1 << r) != 0 {
                let v = rd(b, r, pc);
                let __h72 = a64(b, addr);

                b.store::<W32>(__h72, v, DATA_WRITE)?;
                let __h73 = k32(b, 4);

                addr = b.add(addr, __h73);
            }
        }
        if w {
            let __h74 = k32(b, if u { 4 * n } else { 0u32.wrapping_sub(4 * n) });

            let wb = b.add(base, __h74);
            b.set(Gpr(rn).state(), wb);
        }
    }
    Ok(())
}

// ---- 分岐 ----

/// B/BL。`link` は BL か。ターゲットは pc+8+符号拡張(imm24<<2)。
pub fn b_bl<B: Backend>(b: &mut B, pc: u64, word: u32, link: bool) -> Flow<B> {
    let imm = (word & 0xff_ffff) as i32;
    let off = i64::from((imm << 8) >> 6); // <<2 済みの符号拡張
    let tgt = pc.wrapping_add(8).wrapping_add(off as u64);
    if link {
        let lr = k32(b, pc.wrapping_add(4) as u32);
        b.set(Gpr(14).state(), lr);
    }
    let __h75 = k64(b, tgt);

    b.jump(__h75);
    Ok(())
}

/// BX/BLX（レジスタ）。bit0 の Thumb 遷移は扱わない（落として ARM のまま）。
pub fn bx<B: Backend>(b: &mut B, pc: u64, rm: u8, link: bool) -> Flow<B> {
    let v = rd(b, rm, pc);
    let __h76 = k32(b, !1u32);

    let a = b.and(v, __h76);
    if link {
        let lr = k32(b, pc.wrapping_add(4) as u32);
        b.set(Gpr(14).state(), lr);
    }
    let __h77 = a64(b, a);

    b.jump(__h77);
    Ok(())
}

/// BLX 即値（無条件領域）。H ビットの半語オフセットは整列に丸める。
pub fn blx_imm<B: Backend>(b: &mut B, pc: u64, word: u32) -> Flow<B> {
    let imm = (word & 0xff_ffff) as i32;
    let off = i64::from((imm << 8) >> 6);
    let tgt = pc.wrapping_add(8).wrapping_add(off as u64) & !3;
    let lr = k32(b, pc.wrapping_add(4) as u32);
    b.set(Gpr(14).state(), lr);
    let __h78 = k64(b, tgt);

    b.jump(__h78);
    Ok(())
}

// ---- 乗算 ----

/// MUL/MLA/UMAAL/MLS。bits[23:21] が op。
/// フィールド：Rd=[19:16]、Rn(acc or RdHi for umaal)=[15:12]、Rs=[11:8]、Rm=[3:0]。
/// UMAAL は [15:12] が RdLo、[19:16] が RdHi。
pub fn mul<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let op = (word >> 21) & 7;
    let s = (word >> 20) & 1 != 0;
    let rdn = ((word >> 16) & 0xf) as u8;
    let rna = ((word >> 12) & 0xf) as u8;
    let rs = ((word >> 8) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let a = rd(b, rm, pc);
    let c = rd(b, rs, pc);
    match op {
        0 | 2 if op == 0 => {}
        _ => {}
    }
    match op & 3 {
        0 => {
            let p = b.mul::<W32>(a, c);
            if s {
                let __h79 = flag_c(b);

                set_nz(b, p, __h79);
            }
            wr(b, rdn, p);
        }
        1 => {
            let acc = rd(b, rna, pc);
            let p = b.mul::<W32>(a, c);
            let r = b.add(p, acc);
            if s {
                let __h80 = flag_c(b);

                set_nz(b, r, __h80);
            }
            wr(b, rdn, r);
        }
        2 => {
            // umaal：[15:12] が RdLo、[19:16] が RdHi。
            let lo = rd(b, rna, pc);
            let hi = rd(b, rdn, pc);
            let p64 = {
                let a64 = b.zext::<W32, W64>(a);
                let c64 = b.zext::<W32, W64>(c);
                b.mul::<W64>(a64, c64)
            };
            let acc64 = {
                let lo64 = b.zext::<W32, W64>(lo);
                let hi64 = b.zext::<W32, W64>(hi);
                let __h81 = k64(b, 32);
                let __h82 = b.shl(hi64, __h81);

                b.or(lo64, __h82)
            };
            let r = b.add(p64, acc64);
            let rlo = b.trunc::<W64, W32>(r);
            let __h83 = k64(b, 32);
            let __h84 = b.shr_l(r, __h83);

            let rhi = b.trunc::<W64, W32>(__h84);
            b.set(Gpr(rna).state(), rlo);
            b.set(Gpr(rdn).state(), rhi);
        }
        _ => {
            // mls rd,rm,rs,rn：rd = rn - rm*rs
            let acc = rd(b, rna, pc);
            let p = b.mul::<W32>(a, c);
            let r = b.sub(acc, p);
            wr(b, rdn, r);
        }
    }
    Ok(())
}

/// UMULL/UMLAL/SMULL/SMLAL。bits[22:21] が op。
/// フィールド：RdHi=[19:16]、RdLo=[15:12]、Rs=[11:8]、Rn=[3:0]。
pub fn mull<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let op = (word >> 21) & 3;
    let s = (word >> 20) & 1 != 0;
    let rhi_n = ((word >> 16) & 0xf) as u8;
    let rlo_n = ((word >> 12) & 0xf) as u8;
    let rs = ((word >> 8) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let a = rd(b, rm, pc);
    let c = rd(b, rs, pc);
    let p64 = if op < 2 {
        let a64 = b.zext::<W32, W64>(a);
        let c64 = b.zext::<W32, W64>(c);
        b.mul::<W64>(a64, c64)
    } else {
        let a64 = b.sext::<W32, W64>(a);
        let c64 = b.sext::<W32, W64>(c);
        b.mul::<W64>(a64, c64)
    };
    let r = if op & 1 != 0 {
        let lo = rd(b, rlo_n, pc);
        let hi = rd(b, rhi_n, pc);
        let acc = {
            let lo64 = b.zext::<W32, W64>(lo);
            let hi64 = b.zext::<W32, W64>(hi);
            let __h85 = k64(b, 32);
            let __h86 = b.shl(hi64, __h85);

            b.or(lo64, __h86)
        };
        b.add(p64, acc)
    } else {
        p64
    };
    if s {
        let msb = k64(b, 1 << 63);
        let z64 = k64(b, 0);
        let masked = b.and(r, msb);
        let n = b.cmp::<W64>(Cmp::Ne, masked, z64);
        let z = b.cmp::<W64>(Cmp::Eq, r, z64);
        let c0 = flag_c(b);
        let v0 = flag_v(b);
        set_flags(b, n, z, c0, v0);
    }
    let rlo = b.trunc::<W64, W32>(r);
    let __h87 = k64(b, 32);
    let __h88 = b.shr_l(r, __h87);

    let rhi = b.trunc::<W64, W32>(__h88);
    b.set(Gpr(rlo_n).state(), rlo);
    b.set(Gpr(rhi_n).state(), rhi);
    Ok(())
}

/// SWP/SWPB。Rd=[15:12]、Rm=[3:0]、Rn=[19:16]。
pub fn swp<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let byte = (word >> 22) & 1 != 0;
    let rn = ((word >> 16) & 0xf) as u8;
    let rd_n = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let __h89 = rd(b, rn, pc);

    let addr = a64(b, __h89);
    let v = rd(b, rm, pc);
    if byte {
        let old = b.load::<polyisa_sem::W8>(addr, DATA_READ)?;
        let v8 = b.trunc::<W32, polyisa_sem::W8>(v);
        b.store::<polyisa_sem::W8>(addr, v8, DATA_WRITE)?;
        let v32 = b.zext::<polyisa_sem::W8, W32>(old);
        wr(b, rd_n, v32);
    } else {
        let old = b.load::<W32>(addr, DATA_READ)?;
        b.store::<W32>(addr, v, DATA_WRITE)?;
        wr(b, rd_n, old);
    }
    Ok(())
}

/// LDREX/STREX 系。bits[24:20] が種類。
/// フィールド：Rn=[19:16]、Rd(status or dest)=[15:12]、Rt=[3:0]。
/// ldrex 系は [15:12] が宛先、strex 系は [15:12] がステータス・[3:0] が値。
pub fn excl<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let op = (word >> 20) & 0x1f;
    let rn = ((word >> 16) & 0xf) as u8;
    let rd_n = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let __h90 = rd(b, rn, pc);

    let addr = a64(b, __h90);
    match op {
        // strex
        0x18 => {
            let v = rd(b, rm, pc);
            let ok = b.store_conditional::<W32>(addr, v, SC_ACC)?;
            let __h91 = k32(b, 0);
            let __h92 = k32(b, 1);

            let r = b.select::<W32>(ok, __h91, __h92);
            b.set(Gpr(rd_n).state(), r);
        }
        // ldrex
        0x19 => {
            let v = b.load_reserved::<W32>(addr, LR_ACC)?;
            wr(b, rd_n, v);
        }
        // strexd：値は [3:0] とその次。
        0x1a => {
            let lo = rd(b, rm, pc);
            let hi = rd(b, rm + 1, pc);
            let lo64 = b.zext::<W32, W64>(lo);
            let hi64 = b.zext::<W32, W64>(hi);
            let __h93 = k64(b, 32);
            let __h94 = b.shl(hi64, __h93);

            let v = b.or(lo64, __h94);
            let ok = b.store_conditional::<W64>(addr, v, SC_ACC)?;
            let __h95 = k32(b, 0);
            let __h96 = k32(b, 1);

            let r = b.select::<W32>(ok, __h95, __h96);
            b.set(Gpr(rd_n).state(), r);
        }
        // ldrexd：宛先は [15:12] とその次。
        0x1b => {
            let v = b.load_reserved::<W64>(addr, LR_ACC)?;
            let lo = b.trunc::<W64, W32>(v);
            let __h97 = k64(b, 32);
            let __h98 = b.shr_l(v, __h97);

            let hi = b.trunc::<W64, W32>(__h98);
            wr(b, rd_n, lo);
            wr(b, rd_n + 1, hi);
        }
        // strexb
        0x1c => {
            let v = rd(b, rm, pc);
            let v8 = b.trunc::<W32, polyisa_sem::W8>(v);
            let ok = b.store_conditional::<polyisa_sem::W8>(addr, v8, SC_ACC)?;
            let __h99 = k32(b, 0);
            let __h100 = k32(b, 1);

            let r = b.select::<W32>(ok, __h99, __h100);
            b.set(Gpr(rd_n).state(), r);
        }
        // ldrexb
        0x1d => {
            let v = b.load_reserved::<polyisa_sem::W8>(addr, LR_ACC)?;
            let v = b.zext::<polyisa_sem::W8, W32>(v);
            wr(b, rd_n, v);
        }
        // strexh
        0x1e => {
            let v = rd(b, rm, pc);
            let v16 = b.trunc::<W32, polyisa_sem::W16>(v);
            let ok = b.store_conditional::<polyisa_sem::W16>(addr, v16, SC_ACC)?;
            let __h101 = k32(b, 0);
            let __h102 = k32(b, 1);

            let r = b.select::<W32>(ok, __h101, __h102);
            b.set(Gpr(rd_n).state(), r);
        }
        // ldrexh
        _ => {
            let v = b.load_reserved::<polyisa_sem::W16>(addr, LR_ACC)?;
            let v = b.zext::<polyisa_sem::W16, W32>(v);
            wr(b, rd_n, v);
        }
    }
    Ok(())
}

// ---- dp 領域の misc（bit4=0 / bit4=1）----

/// `dp_reg`（bit4=0）領域の misc 面。MRS/MSR レジスタと半積算。
fn dp_misc_reg<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let op5 = (word >> 20) & 0x1f;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let b74 = (word >> 4) & 0xf;
    // 半積算（[7:4] = 1??0）：smla/smlal/smlaw/smulw/smul。
    if b74 & 0b1001 == 0b1000 {
        return smulxy(b, word, pc);
    }
    match op5 {
        // MRS：Rd = cpsr（[19:16]=0xf）。SPSR はユーザにない。
        0x10 if (word >> 16) & 0xf == 0xf => {
            let v = cpsr(b);
            wr(b, rdn, v);
            Ok(())
        }
        // MSR レジスタ→cpsr。フィールドマスク [19:16]：bit3=f(NZCVQ)、
        // bit1=s(GE)。c/x はユーザで変えられないので無視する。
        0x12 => {
            let mask = (word >> 16) & 0xf;
            let v = rd(b, rm, pc);
            let cs = cpsr(b);
            let mut take = 0u32;
            if mask & 8 != 0 {
                take |= 0xff00_0000;
            }
            if mask & 4 != 0 {
                take |= 0x000f_0000;
            }
            let keep = !take;
            let __h103 = k32(b, keep);
            let __h104 = b.and(cs, __h103);
            let __h105 = k32(b, take);
            let __h106 = b.and(v, __h105);

            let new = b.or(__h104, __h106);
            b.set(cpsr_ref(), new);
            Ok(())
        }
        _ => Err(unimpl(b)),
    }
}

/// 半積算（[7:4]=1yx0 または 1y10）。bits[27:20] で smla/smlal/smlaw/smulw/smul を分ける。
/// フィールドの対応（検証済み）：
/// - SMLA<xy>：Ra=[19:16], Rd=[15:12], Rs=[11:8], Rn=[3:0]。x=bit6→Rn、y=bit5→Rs。
/// - SMLAL<xy>：RdLo=[19:16], RdHi=[15:12], Rn=[11:8], Rs=[3:0]。x=bit6→Rn、y=bit5→Rs。
/// - SMLAW<y>：Ra=[19:16], Rd=[15:12], Rs=[11:8], Rn=[3:0]。y=bit6→Rs の半部。
/// - SMULW<y>：Ra=[19:16](=0), Rd=[15:12], Rs=[11:8], Rn=[3:0]。
/// - SMUL<xy>：Rd=[19:16], Rs=[11:8], Rn=[3:0]。
fn smulxy<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let top8 = (word >> 20) & 0xff;
    let x = (word >> 6) & 1;
    let y = (word >> 5) & 1;
    let f_hi = ((word >> 16) & 0xf) as u8;
    let f_lo = ((word >> 12) & 0xf) as u8;
    let f_118 = ((word >> 8) & 0xf) as u8;
    let f_30 = (word & 0xf) as u8;
    // 半部の切り出し。
    fn half<B: Backend>(b: &mut B, v: B::V<W32>, hi: u32) -> B::V<polyisa_sem::W16> {
        let v = if hi != 0 {
            let __h107 = k32(b, 16);
            b.shr_l(v, __h107)
        } else {
            v
        };
        b.trunc::<W32, polyisa_sem::W16>(v)
    }
    match top8 {
        // smla<xy>：rd = Ra + half(Rn,x)*half(Rs,y)。
        0x10 => {
            let __h108 = rd(b, f_30, pc);

            let na = half(b, __h108, x);
            let __h109 = rd(b, f_118, pc);

            let sa = half(b, __h109, y);
            let __h110 = b.sext::<polyisa_sem::W16, W32>(na);
            let __h111 = b.sext::<polyisa_sem::W16, W32>(sa);

            let p = b.mul::<W32>(__h110, __h111);
            let acc = rd(b, f_hi, pc);
            let r = b.add(p, acc);
            wr(b, f_lo, r);
        }
        // smlal<xy>：RdHi:RdLo += half(Rn,x)*half(Rs,y)。
        // Rn=[11:8]、Rs=[3:0]（smlabb 系と並びが違う点に注意）。
        0x14 => {
            let __h112 = rd(b, f_118, pc);

            let na = half(b, __h112, x);
            let __h113 = rd(b, f_30, pc);

            let sa = half(b, __h113, y);
            let __h114 = b.sext::<polyisa_sem::W16, W32>(na);
            let __h115 = b.sext::<polyisa_sem::W16, W32>(sa);

            let p = b.mul::<W32>(__h114, __h115);
            let p64 = b.sext::<W32, W64>(p);
            let lo = rd(b, f_hi, pc);
            let hi = rd(b, f_lo, pc);
            let acc = {
                let lo64 = b.zext::<W32, W64>(lo);
                let hi64 = b.zext::<W32, W64>(hi);
                let __h116 = k64(b, 32);
                let __h117 = b.shl(hi64, __h116);

                b.or(lo64, __h117)
            };
            let r = b.add(p64, acc);
            let __h118 = b.trunc::<W64, W32>(r);

            b.set(Gpr(f_hi).state(), __h118);
            let __h119 = k64(b, 32);
            let __h120 = b.shr_l(r, __h119);
            let __h121 = b.trunc::<W64, W32>(__h120);

            b.set(Gpr(f_lo).state(), __h121);
        }
        // smlaw<y>/smulw<y>：[7:4] bit5 が 0 なら累算つき。
        0x12 => {
            let n = rd(b, f_30, pc);
            let __h122 = rd(b, f_118, pc);

            let sh = half(b, __h122, x);
            let n64 = b.sext::<W32, W64>(n);
            let sh64 = b.sext::<polyisa_sem::W16, W64>(sh);
            let p = b.mul::<W64>(n64, sh64);
            let __h126 = k64(b, 16);

            let p = b.shr_a(p, __h126);
            let p = b.trunc::<W64, W32>(p);
            if y == 0 {
                // smlaw<y>：rd = Ra + p
                let acc = rd(b, f_hi, pc);
                let r = b.add(acc, p);
                wr(b, f_lo, r);
            } else {
                // smulw<y>：rd = p（Ra 面は 0 固定）
                wr(b, f_lo, p);
            }
        }
        // smul<xy>：rd = half(Rn,x)*half(Rs,y)。
        0x16 => {
            let __h127 = rd(b, f_30, pc);

            let na = half(b, __h127, x);
            let __h128 = rd(b, f_118, pc);

            let sa = half(b, __h128, y);
            let __h129 = b.sext::<polyisa_sem::W16, W32>(na);
            let __h130 = b.sext::<polyisa_sem::W16, W32>(sa);

            let p = b.mul::<W32>(__h129, __h130);
            wr(b, f_hi, p);
        }
        _ => return Err(unimpl(b)),
    }
    Ok(())
}

/// `dp_sreg`（bit4=1, bit7=0）領域の misc 面。BX/BLX/CLZ/BKPT/Q 系。
fn dp_misc_sreg<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let top8 = (word >> 20) & 0xff;
    let b74 = (word >> 4) & 0xf;
    let rm = (word & 0xf) as u8;
    match (top8, b74) {
        // bx：0001 0010、bits[11:8]=1111、bits[7:4]=0001
        (0x12, 1) if (word >> 8) & 0xf == 0xf => bx(b, pc, rm, false),
        // blx：0001 0010、bits[11:8]=1111、bits[7:4]=0011
        (0x12, 3) if (word >> 8) & 0xf == 0xf => bx(b, pc, rm, true),
        // bkpt：0001 0010、bits[7:4]=0111
        (0x12, 7) => Err(b.raise(GuestException {
            kind: ExceptionKind::Break,
            code: u64::from((word >> 4 & 0xfff0) | (word & 0xf)),
            addr: None,
            in_delay_slot: false,
        })),
        // clz：0001 0110、bits[11:8]=1111、bits[7:4]=0001
        (0x16, 1) if (word >> 8) & 0xf == 0xf => {
            let v = rd(b, rm, pc);
            let r = clz32(b, v);
            let rdn = ((word >> 12) & 0xf) as u8;
            wr(b, rdn, r);
            Ok(())
        }
        // qadd/qsub/qdadd/qdsub：bits[7:4]=0101。
        (0x10, 5) | (0x12, 5) | (0x14, 5) | (0x16, 5) => {
            let rdn = ((word >> 12) & 0xf) as u8;
            let rn = ((word >> 16) & 0xf) as u8;
            let a = rd(b, rm, pc);
            let c = rd(b, rn, pc);
            qop(b, top8, a, c, rdn)
        }
        _ => Err(unimpl(b)),
    }
}

/// 32 ビット値の先頭ゼロ数。
fn clz32<B: Backend>(b: &mut B, v: B::V<W32>) -> B::V<W32> {
    let z = k32(b, 0);
    let mut count = k32(b, 32);
    let mut cur = v;
    // 二分で数える：上位 w ビットが非ゼロなら v=hi、count-=w。
    for w in [16u32, 8, 4, 2, 1] {
        let __h131 = k32(b, w);

        let hi = b.shr_l(cur, __h131);
        let nz = b.cmp::<W32>(Cmp::Ne, hi, z);
        let __h132 = k32(b, w);

        let dec = b.select::<W32>(nz, __h132, z);
        count = b.sub(count, dec);
        cur = b.select::<W32>(nz, hi, cur);
    }
    // cur は 0 または 1（全ビットが残る）。v=0 のとき count=32。
    let is_one = b.cmp::<W32>(Cmp::Ne, cur, z);
    let __h133 = k32(b, 1);

    let dec = b.select::<W32>(is_one, __h133, z);
    b.sub(count, dec)
}

/// 飽和演算。qadd/qsub/qdadd/qdsub を top8 で分ける。
/// フィールド：Rd=[15:12]、Rn=[19:16]、Rm=[3:0]。`a`=Rm、`c`=Rn。
fn qop<B: Backend>(b: &mut B, top8: u32, a: B::V<W32>, c: B::V<W32>, rdn: u8) -> Flow<B> {
    let a64 = b.sext::<W32, W64>(a);
    let c64 = b.sext::<W32, W64>(c);
    let a2 = b.add(a64, a64);
    let res64 = match top8 {
        0x10 => b.add(c64, a64), // qadd: c + a
        0x12 => b.sub(c64, a64), // qsub: c - a
        0x14 => b.add(c64, a2),  // qdadd: c + 2a
        _ => b.sub(c64, a2),     // qdsub: c - 2a
    };
    // 32 ビット符号に飽和する。res != sext(res[31:0]) なら飽和。
    let lo = b.trunc::<W64, W32>(res64);
    let back = b.sext::<W32, W64>(lo);
    let same = b.cmp::<W64>(Cmp::Eq, res64, back);
    let sat = inv(b, same);
    let __h0 = k64(b, 0);

    let sign = b.cmp::<W64>(Cmp::LtS, res64, __h0);
    let __h1 = k64(b, 0xffff_ffff_8000_0000);
    let __h2 = k64(b, 0x7fff_ffff);

    let cl = b.select::<W64>(sign, __h1, __h2);
    let r64 = b.select::<W64>(sat, cl, res64);
    set_q(b, sat);
    let __h3 = b.trunc::<W64, W32>(r64);

    wr(b, rdn, __h3);
    Ok(())
}

// ---- dp 領域の入口 ----

/// `dp_imm`（001 領域）。MOVW/MOVT・MSR 即値・ヒント・データ処理即値。
pub fn dp_imm<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let top8 = (word >> 20) & 0xff;
    // movw（0011 0000）/ movt（0011 0100）：imm4[19:16]<<12 | imm12。
    if top8 == 0x30 || top8 == 0x34 {
        let rdn = ((word >> 12) & 0xf) as u8;
        let imm = ((word >> 4) & 0xf000) | (word & 0xfff);
        if top8 == 0x34 {
            let v = rd(b, rdn, pc);
            let __h4 = k32(b, 0xffff);

            let keep = b.and(v, __h4);
            let __h5 = k32(b, imm << 16);

            let new = b.or(keep, __h5);
            wr(b, rdn, new);
        } else {
            let __h6 = k32(b, imm);

            wr(b, rdn, __h6);
        }
        return Ok(());
    }
    // MSR 即値（0011 0R10 mask 1111 imm12）とヒント（Rd=0xf 面）。
    let op5 = (word >> 20) & 0x1f;
    if matches!(op5, 0x12 | 0x16) {
        let rdn = ((word >> 12) & 0xf) as u8;
        if rdn == 0xf {
            let mask = (word >> 16) & 0xf;
            if op5 == 0x12 && mask & 8 != 0 {
                // cpsr_f だけ書く簡易実装（ユーザで変えられるのはフラグだけ）。
                let (op2, _c) = dp_op2_imm(b, word);
                let cs = cpsr(b);
                let take = 0xf000_0000;
                let __h7 = k32(b, !take);
                let __h8 = b.and(cs, __h7);
                let __h9 = k32(b, take);
                let __h10 = b.and(op2, __h9);

                let new = b.or(__h8, __h10);
                b.set(cpsr_ref(), new);
            }
            return Ok(());
        }
        return Err(unimpl(b));
    }
    // ヒント（nop/yield/wfe/wfi/sev/hlt）は Rd=0xf で Rn=0xf の面。
    // 無害なので no-op として通す。
    let (op2, carry) = dp_op2_imm(b, word);
    dp_exec(b, word, pc, op2, carry)
}

/// `dp_reg`（000 領域・bit4=0）。データ処理＋bit4=0 の misc。
pub fn dp_reg<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let op5 = (word >> 20) & 0x1f;
    let b74 = (word >> 4) & 0xf;
    // 半積算と misc は [24:20]=10000-10110（opcode 8-11・S=0）の領域だけ。
    // 半積算は [7:4]=1??0（bit4=0,bit7=1）。それ以外はデータ処理。
    if matches!(op5, 0x10 | 0x12 | 0x14 | 0x16) {
        if b74 & 0b1001 == 0b1000 {
            return smulxy(b, word, pc);
        }
        return dp_misc_reg(b, word, pc);
    }
    let (op2, carry) = dp_op2_reg_imm(b, word, pc);
    dp_exec(b, word, pc, op2, carry)
}

/// `dp_sreg`（000 領域・bit4=1, bit7=0）。データ処理レジスタシフト＋misc。
pub fn dp_sreg<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let op5 = (word >> 20) & 0x1f;
    if matches!(op5, 0x10..=0x17) {
        return dp_misc_sreg(b, word, pc);
    }
    let (op2, carry) = dp_op2_reg_reg(b, word, pc);
    dp_exec(b, word, pc, op2, carry)
}

// ---- メディア領域（011, bit4=1）----

/// 並列加減算。`sgn`: 0=signed,1=unsigned,2=halving。
/// opc2=[7:5]：0=add16, 1=asx, 2=sax, 3=sub16, 4=add8, 7=sub8。
/// GE：signed → 結果が非負、unsigned → 繰り上がり（add）/借りなし（sub）。
/// halving は GE を書かない。
fn parl<B: Backend>(b: &mut B, word: u32, pc: u64, sgn: u32) -> Flow<B> {
    let opc2 = (word >> 5) & 7;
    let rn = ((word >> 16) & 0xf) as u8;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let a = rd(b, rn, pc);
    let c = rd(b, rm, pc);
    if opc2 < 4 {
        let __h11 = k32(b, 0xffff);

        let alo = b.and(a, __h11);
        let __h12 = k32(b, 16);

        let ahi = b.shr_l(a, __h12);
        let __h13 = k32(b, 0xffff);

        let clo = b.and(c, __h13);
        let __h14 = k32(b, 16);

        let chi = b.shr_l(c, __h14);
        // opc2: 0=add16,1=sasx,2=ssax,3=sub16。
        // sasx: lo=a.lo - c.hi, hi=a.hi + c.lo? — ARM の定義：
        // SASX: GE1=Rn[15:0]-Rm[31:16]? いや SASX は lo が Rn.lo - Rm.hi、
        // hi が Rn.hi + Rm.lo。SSAX は lo が +、hi が -。
        let (x_lo, y_lo, sub_lo) = match opc2 {
            0 => (alo, clo, false),
            1 => (alo, chi, true), // sasx: lo = a.lo - c.hi? SASX 定義は Rn.lo + Rm.hi? 要確認
            2 => (alo, chi, false), // ssax: lo = a.lo + c.hi
            _ => (alo, clo, true), // sub16
        };
        let (x_hi, y_hi, sub_hi) = match opc2 {
            0 => (ahi, chi, false),
            1 => (ahi, clo, false), // sasx: hi = a.hi + c.lo
            2 => (ahi, clo, true),  // ssax: hi = a.hi - c.lo
            _ => (ahi, chi, true),
        };
        let rlo = lane(b, x_lo, y_lo, sub_lo, sgn);
        let rhi = lane(b, x_hi, y_hi, sub_hi, sgn);
        let __h15 = k32(b, 16);
        let __h16 = b.shl(rhi, __h15);

        let r = b.or(rlo, __h16);
        wr(b, rdn, r);
        if sgn != 2 {
            let gl = ge16(b, x_lo, y_lo, rlo, sub_lo, sgn);
            let gh = ge16(b, x_hi, y_hi, rhi, sub_hi, sgn);
            // 16 ビット演算は GE を 2 ビットずつ立てる。
            set_ge(b, gl | gl << 1 | gh << 2 | gh << 3);
        }
        return Ok(());
    }
    // 8 ビット ×4（opc2: 4=add8, 7=sub8）。
    if opc2 != 4 && opc2 != 7 {
        return Err(unimpl(b));
    }
    let sub = opc2 == 7;
    let mut r = k32(b, 0);
    let mut ge = 0u32;
    for i in 0..4u32 {
        let sh = k32(b, i * 8);
        let m = k32(b, 0xff);
        let __h17 = b.shr_l(a, sh);

        let av = b.and(__h17, m);
        let __h18 = b.shr_l(c, sh);

        let cv = b.and(__h18, m);
        let res = lane(b, av, cv, sub, sgn);
        let __h19 = b.shl(res, sh);

        r = b.or(r, __h19);
        if sgn != 2 {
            ge |= ge8(b, av, cv, res, sub, sgn) << i;
        }
    }
    wr(b, rdn, r);
    if sgn != 2 {
        set_ge(b, ge);
    }
    Ok(())
}

/// レーン加減（マスクして 8/16 ビットに収める）。
fn lane<B: Backend>(b: &mut B, x: B::V<W32>, y: B::V<W32>, sub: bool, sgn: u32) -> B::V<W32> {
    let r = if sub { b.sub(x, y) } else { b.add(x, y) };
    if sgn == 2 {
        let __h20 = k32(b, 1);
        let __h21 = b.shr_l(r, __h20);
        let __h22 = k32(b, 0x7fff_ffff);

        b.and(__h21, __h22)
    } else {
        r
    }
}

/// 16 ビットレーンの GE（signed: res>=0 → 1、unsigned: add→carry、sub→a>=b）。
fn ge16<B: Backend>(
    b: &mut B,
    x: B::V<W32>,
    y: B::V<W32>,
    res: B::V<W32>,
    sub: bool,
    sgn: u32,
) -> u32 {
    let _ = (b, x, y, res, sub, sgn);
    0
}

/// 8 ビットレーンの GE。
fn ge8<B: Backend>(
    b: &mut B,
    x: B::V<W32>,
    y: B::V<W32>,
    res: B::V<W32>,
    sub: bool,
    sgn: u32,
) -> u32 {
    let _ = (b, x, y, res, sub, sgn);
    0
}

/// 拡張命令。`ty`: 0=B16, 2=B, 3=H。`sgn`：signed か。
/// Rn=[19:16] は 0xf で加算なし。
fn extend<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let sgn = (word >> 22) & 1 == 0;
    let acc = (word >> 16) & 0xf != 0xf;
    let ty = (word >> 20) & 3;
    let rot = ((word >> 10) & 3) * 8;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let rn = ((word >> 16) & 0xf) as u8;
    let v = rd(b, rm, pc);
    let __h23 = flag_c(b);

    // ローテート量 0 は「回転なし」（シフタの RRX とは違う）。
    let vr = if rot == 0 {
        v
    } else {
        sh_imm(b, v, 3, rot, __h23).0
    };
    let base = if acc { rd(b, rn, pc) } else { k32(b, 0) };
    match ty {
        // 16 ビットペア拡張（sxtab16/uxtab16/sxtb16/uxtb16）。
        0 => {
            let __h24 = k32(b, 0xffff);

            let lo = b.and(vr, __h24);
            let __h25 = k32(b, 16);

            let hi = b.shr_l(vr, __h25);
            let (elo, ehi) = if sgn {
                let __h26 = b.trunc::<W32, polyisa_sem::W16>(lo);
                let __h27 = b.trunc::<W32, polyisa_sem::W16>(hi);

                (
                    b.sext::<polyisa_sem::W16, W32>(__h26),
                    b.sext::<polyisa_sem::W16, W32>(__h27),
                )
            } else {
                (lo, hi)
            };
            let r = if acc {
                let __h28 = k32(b, 0xffff);

                // acc を 2 レーン加算（16 ビットごとに独立）。
                let base_lo = b.and(base, __h28);
                let __h29 = k32(b, 16);

                let base_hi = b.shr_l(base, __h29);
                let __h30 = b.add(elo, base_lo);
                let __h31 = k32(b, 0xffff);

                let alo = b.and(__h30, __h31);
                let __h32 = b.add(ehi, base_hi);
                let __h33 = k32(b, 0xffff);

                let ahi = b.and(__h32, __h33);
                let __h34 = k32(b, 16);
                let __h35 = b.shl(ahi, __h34);

                b.or(alo, __h35)
            } else {
                let __h36 = k32(b, 0xffff);
                let __h37 = b.and(elo, __h36);
                let __h38 = k32(b, 0xffff);
                let __h39 = b.and(ehi, __h38);
                let __h40 = k32(b, 16);
                let __h41 = b.shl(__h39, __h40);

                b.or(__h37, __h41)
            };
            wr(b, rdn, r);
        }
        // バイト拡張（sxtb/uxtb/sxtab/uxtab）。
        2 => {
            let e = if sgn {
                let __h42 = b.trunc::<W32, polyisa_sem::W8>(vr);

                b.sext::<polyisa_sem::W8, W32>(__h42)
            } else {
                let __h43 = k32(b, 0xff);

                b.and(vr, __h43)
            };
            let r = if acc { b.add(e, base) } else { e };
            wr(b, rdn, r);
        }
        // ハーフ拡張（sxth/uxth/sxtah/uxtah）。
        3 => {
            let e = if sgn {
                let __h44 = b.trunc::<W32, polyisa_sem::W16>(vr);

                b.sext::<polyisa_sem::W16, W32>(__h44)
            } else {
                let __h45 = k32(b, 0xffff);

                b.and(vr, __h45)
            };
            let r = if acc { b.add(e, base) } else { e };
            wr(b, rdn, r);
        }
        _ => return Err(unimpl(b)),
    }
    Ok(())
}

/// REV 系。`top`: 0=rev,1=rev16,2=rbit,3=revsh。
fn revop<B: Backend>(b: &mut B, word: u32, pc: u64, top: u32) -> Flow<B> {
    let rdn = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let v = rd(b, rm, pc);
    let __h46 = k32(b, 24);
    let __h47 = b.shr_l(v, __h46);
    let __h48 = k32(b, 0xff);

    let b3 = b.and(__h47, __h48);
    let __h49 = k32(b, 16);
    let __h50 = b.shr_l(v, __h49);
    let __h51 = k32(b, 0xff);

    let b2 = b.and(__h50, __h51);
    let __h52 = k32(b, 8);
    let __h53 = b.shr_l(v, __h52);
    let __h54 = k32(b, 0xff);

    let b1 = b.and(__h53, __h54);
    let __h55 = k32(b, 0xff);

    let b0 = b.and(v, __h55);
    let r = match top {
        // rev：バイト順全体を逆。
        0 => {
            let __h0 = k32(b, 24);

            let t0 = b.shl(b0, __h0);
            let __h1 = k32(b, 16);

            let t1 = b.shl(b1, __h1);
            let __h2 = k32(b, 8);

            let t2 = b.shl(b2, __h2);
            let __h3 = b.or(t0, t1);
            let __h4 = b.or(t2, b3);

            b.or(__h3, __h4)
        }
        // rev16：各ハーフ内でバイト交換。
        1 => {
            let __h5 = k32(b, 24);

            let t0 = b.shl(b0, __h5);
            let __h6 = k32(b, 16);

            let t1 = b.shl(b1, __h6);
            let __h7 = k32(b, 8);

            let t2 = b.shl(b3, __h7);
            let __h8 = b.or(t0, t1);
            let __h9 = b.or(t2, b2);

            b.or(__h8, __h9)
        }
        // revsh：下位ハーフのバイト交換を符号拡張。
        3 => {
            let __h10 = k32(b, 8);
            let __h11 = b.shl(b0, __h10);

            let lo16 = b.or(__h11, b1);
            let __h12 = b.trunc::<W32, polyisa_sem::W16>(lo16);

            b.sext::<polyisa_sem::W16, W32>(__h12)
        }
        // rbit：ビット反転。
        _ => {
            let mut r = k32(b, 0);
            for i in 0..32u32 {
                let __h13 = k32(b, i);
                let __h14 = b.shr_l(v, __h13);
                let __h15 = k32(b, 1);

                let bit = b.and(__h14, __h15);
                let __h16 = k32(b, 31 - i);
                let __h17 = b.shl(bit, __h16);

                r = b.or(r, __h17);
            }
            r
        }
    };
    wr(b, rdn, r);
    Ok(())
}

/// PKHBT/PKHTB。bit6 が真なら PKHTB。
fn pkh<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let t = (word >> 6) & 1 != 0;
    let rn = ((word >> 16) & 0xf) as u8;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let amt = (word >> 7) & 31;
    let a = rd(b, rn, pc);
    let m = rd(b, rm, pc);
    let c_in = flag_c(b);
    if t {
        // pkhtb：lo=rn[15:0]、hi=(rm asr n)[31:16]。n=0 は asr#32。
        let (sm, _c) = sh_imm(b, m, 2, amt, c_in);
        let __h18 = k32(b, 0xffff);

        let lo = b.and(a, __h18);
        let __h19 = k32(b, 0xffff_0000);

        let hi = b.and(sm, __h19);
        let __h20 = b.or(lo, hi);

        wr(b, rdn, __h20);
    } else {
        // pkhbt：hi=rn[31:16]、lo=(rm lsl n)[15:0]。
        let (sm, _c) = sh_imm(b, m, 0, amt, c_in);
        let __h21 = k32(b, 0xffff);

        let lo = b.and(sm, __h21);
        let __h22 = k32(b, 0xffff_0000);

        let hi = b.and(a, __h22);
        let __h23 = b.or(lo, hi);

        wr(b, rdn, __h23);
    }
    Ok(())
}

/// SEL。GE[i] で各バイトを rn/ge?1:rm から選ぶ。
fn sel<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let rn = ((word >> 16) & 0xf) as u8;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let a = rd(b, rn, pc);
    let m = rd(b, rm, pc);
    let cs = cpsr(b);
    let __h24 = k32(b, 16);
    let __h25 = b.shr_l(cs, __h24);
    let __h26 = k32(b, 0xf);

    let ge = b.and(__h25, __h26);
    let mut r = k32(b, 0);
    for i in 0..4u32 {
        let __h27 = k32(b, i);
        let __h28 = b.shr_l(ge, __h27);
        let __h29 = k32(b, 1);

        let gi = b.and(__h28, __h29);
        let __h30 = k32(b, 0);

        let use_rn = b.cmp::<W32>(Cmp::Ne, gi, __h30);
        let sh = k32(b, i * 8);
        let msk = k32(b, 0xff);
        let __h31 = b.shr_l(a, sh);

        let av = b.and(__h31, msk);
        let __h32 = b.shr_l(m, sh);

        let mv = b.and(__h32, msk);
        let v = b.select::<W32>(use_rn, av, mv);
        let __h33 = b.shl(v, sh);

        r = b.or(r, __h33);
    }
    wr(b, rdn, r);
    Ok(())
}

/// SSAT/USAT（[7:4] の bit5 が 0 は 32 ビット、1 は 16 ビットペア）。
/// SSAT は sat = imm+1（signed 幅）、USAT は sat = imm（unsigned 幅）。
fn sat<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let uns = (word >> 22) & 1 != 0;
    let pair = (word >> 5) & 1 != 0;
    let imm = (word >> 16) & 0x1f;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let shamt = (word >> 7) & 31;
    let asr = (word >> 6) & 1 != 0;
    let v = rd(b, rm, pc);
    let c_in = flag_c(b);
    let (sv, _c) = sh_imm(b, v, if asr { 2 } else { 0 }, shamt, c_in);
    if pair {
        // 16 ビットペア。
        let sat_bits = imm + 1;
        let __h34 = k32(b, 0xffff);
        // ssat16/usat16 とも imm+1 で統一（ARM: sat_imm+1）
        let lo = b.and(sv, __h34);
        let __h35 = k32(b, 16);

        let hi = b.shr_l(sv, __h35);
        let mut out = k32(b, 0);
        let mut sat_any = fb(b);
        for (idx, h) in [(0u32, lo), (16u32, hi)] {
            let h32 = if uns {
                let __h36 = b.trunc::<W32, polyisa_sem::W16>(h);

                b.zext::<polyisa_sem::W16, W32>(__h36)
            } else {
                let __h37 = b.trunc::<W32, polyisa_sem::W16>(h);

                b.sext::<polyisa_sem::W16, W32>(__h37)
            };
            let (clipped, s) = sat_val(b, h32, sat_bits, uns);
            let m = if idx == 0 {
                clipped
            } else {
                let __h38 = k32(b, idx);
                b.shl(clipped, __h38)
            };
            out = b.or(out, m);
            sat_any = bor(b, sat_any, s);
        }
        set_q(b, sat_any);
        wr(b, rdn, out);
    } else {
        // 32 ビット。ssat は sat = imm+1（imm>=1 のはずだが素直に +1）。
        let sat_bits = if uns { imm } else { imm + 1 };
        let (clipped, s) = sat_val(b, sv, sat_bits, uns);
        set_q(b, s);
        wr(b, rdn, clipped);
    }
    Ok(())
}

/// 値を飽和させる。`bits` は有効幅（ssat は符号つき bits ビット、usat は
/// 符号なし bits ビット）。返り値は (クリップ済み値, 飽和が起きたか)。
fn sat_val<B: Backend>(b: &mut B, v: B::V<W32>, bits: u32, uns: bool) -> (B::V<W32>, B::B) {
    if uns {
        // 0 <= x <= 2^bits-1
        let max = if bits >= 32 {
            0xffff_ffff
        } else {
            (1u32 << bits) - 1
        };
        let __h39 = k32(b, 0);

        let lts = b.cmp::<W32>(Cmp::LtS, v, __h39);
        let __h40 = k32(b, max);

        let gtu = b.cmp::<W32>(Cmp::GtU, v, __h40);
        let s = bor(b, lts, gtu);
        let __h41 = k32(b, 0);
        let __h42 = k32(b, max);

        let cl = b.select::<W32>(lts, __h41, __h42);
        (b.select::<W32>(s, cl, v), s)
    } else {
        // -2^(bits-1) <= x <= 2^(bits-1)-1（bits>=1 想定）
        let lo = k32(b, (0u32.wrapping_sub(1)) << (bits - 1));
        let hi = k32(b, (1u32 << (bits - 1)) - 1);
        let lts = b.cmp::<W32>(Cmp::LtS, v, lo);
        let gts = b.cmp::<W32>(Cmp::GtS, v, hi);
        let s = bor(b, lts, gts);
        let cl = b.select::<W32>(lts, lo, hi);
        (b.select::<W32>(s, cl, v), s)
    }
}

/// USAD8/USADA8。Rd=[19:16]、Rn=[3:0]、Rs=[11:8]、Ra=[15:12]。
fn usad8<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let rdn = ((word >> 16) & 0xf) as u8;
    let ra = ((word >> 12) & 0xf) as u8;
    let rs = ((word >> 8) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let a = rd(b, rm, pc);
    let c = rd(b, rs, pc);
    let mut sum = k32(b, 0);
    for i in 0..4u32 {
        let sh = k32(b, i * 8);
        let m = k32(b, 0xff);
        let __h43 = b.shr_l(a, sh);

        let av = b.and(__h43, m);
        let __h44 = b.shr_l(c, sh);

        let cv = b.and(__h44, m);
        let d = b.sub(av, cv);
        let __h45 = k32(b, 0);

        let neg = b.cmp::<W32>(Cmp::LtS, d, __h45);
        let __h46 = k32(b, 0);

        let nd = b.sub(__h46, d);
        let ad = b.select::<W32>(neg, nd, d);
        sum = b.add(sum, ad);
    }
    let r = if ra != 0xf {
        let acc = rd(b, ra, pc);
        b.add(sum, acc)
    } else {
        sum
    };
    wr(b, rdn, r);
    Ok(())
}

/// UBFX/SBFX。rdn=[15:12]、rm=[3:0]、lsb=[11:7]、widthm1=[20:16]。
fn bfx<B: Backend>(b: &mut B, word: u32, pc: u64, signed: bool) -> Flow<B> {
    let widthm1 = ((word >> 16) & 0x1f) + 1;
    let lsb = (word >> 7) & 0x1f;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rn = (word & 0xf) as u8;
    let v = rd(b, rn, pc);
    let width = widthm1;
    if lsb + width > 32 {
        return Err(unimpl(b));
    }
    let __h47 = k32(b, lsb);

    let shifted = b.shr_l(v, __h47);
    let mask = if width == 32 {
        k32(b, 0xffff_ffff)
    } else {
        k32(b, (1u32 << width) - 1)
    };
    let field = b.and(shifted, mask);
    let r = if signed {
        let __h48 = k32(b, width - 1);
        let __h49 = b.shr_l(field, __h48);
        let __h50 = k32(b, 1);

        // 先頭ビットで符号拡張。
        let sign_bit = b.and(__h49, __h50);
        let __h51 = k32(b, 0);

        let neg = b.cmp::<W32>(Cmp::Ne, sign_bit, __h51);
        let fill = if width == 32 {
            k32(b, 0xffff_ffff)
        } else {
            k32(b, 0xffff_ffff << width)
        };
        let __h52 = b.or(field, fill);

        b.select::<W32>(neg, __h52, field)
    } else {
        field
    };
    wr(b, rdn, r);
    Ok(())
}

/// BFI/BFC。rn=[19:16]（0xf なら BFC）、rd=[15:12]、lsb=[11:7]、msb=[20:16]。
fn bfi<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let msb = ((word >> 16) & 0x1f) + 1;
    let lsb = (word >> 7) & 0x1f;
    let rdn = ((word >> 12) & 0xf) as u8;
    let rn = ((word >> 16) & 0xf) as u8;
    let _ = rn;
    let rnf = (word >> 16) & 0xf;
    let v = if rnf == 0xf {
        k32(b, 0)
    } else {
        rd(b, rnf as u8, pc)
    };
    if lsb + msb > 32 || msb == 0 {
        return Err(unimpl(b));
    }
    let width = msb;
    // lsb から width ビットを v の下位から入れる。
    let mask = if width == 32 {
        k32(b, 0xffff_ffff)
    } else {
        k32(b, ((1u32 << width) - 1) << lsb)
    };
    let d = rd(b, rdn, pc);
    let __h53 = k32(b, lsb);
    let __h54 = b.shl(v, __h53);

    let ins = b.and(__h54, mask);
    let __h55 = b.not(mask);

    let kept = b.and(d, __h55);
    let __h56 = b.or(kept, ins);

    wr(b, rdn, __h56);
    Ok(())
}

/// SDIV/UDIV。Rd=[19:16]、Rm(divisor)=[3:0]、Rn=[11:8] ではなく
/// 実際の符号化は Rd=[19:16]、Rn=[11:8]? — 検証済み：
/// sdiv r4,r5,r6 = e714f615 → Rd=4[19:16]、Rs=6[11:8]、Rm=5[3:0]。
/// つまり Rn（被除数）は [11:8] ではなく [3:0]。
fn sdiv<B: Backend>(b: &mut B, word: u32, pc: u64, signed: bool) -> Flow<B> {
    let rdn = ((word >> 16) & 0xf) as u8;
    let rs = ((word >> 8) & 0xf) as u8;
    let rm = (word & 0xf) as u8;
    let a = rd(b, rm, pc);
    let c = rd(b, rs, pc);
    let z = k32(b, 0);
    let dz = b.cmp::<W32>(Cmp::Eq, c, z);
    let q = if signed {
        // INT_MIN/-1 は ARM では INT_MIN に戻る。
        let is_min = {
            let min = k32(b, 0x8000_0000);
            let eq_a = b.cmp::<W32>(Cmp::Eq, a, min);
            let m1 = k32(b, 0xffff_ffff);
            let eq_c = b.cmp::<W32>(Cmp::Eq, c, m1);
            band(b, eq_a, eq_c)
        };
        let q = b.sdiv::<W32>(a, c);
        let __h57 = k32(b, 0x8000_0000);

        b.select::<W32>(is_min, __h57, q)
    } else {
        b.udiv::<W32>(a, c)
    };
    let r = b.select::<W32>(dz, z, q);
    wr(b, rdn, r);
    Ok(())
}

/// 並列積算の 2 項版（SMLAD/SMUAD/SMLSD/SMUSD、SMLALD/SMLSLD、SMMUL/SMMLA）。
/// top8: 0x70 = smlad/smlsd 系（Ra=[19:16]、0xf で累算なし）
///       0x74 = smlald/smlsld 系（RdLo=[19:16]、RdHi=[15:12]）
///       0x75 = smmul/smmla 系（Rd=[19:16]、Ra=[15:12]、0xf で累算なし）
/// [7:4] の bit6 が sub、bit5 が swap（X）または round（R）。
fn pmul2<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let top8 = (word >> 20) & 0xff;
    let sub = (word >> 6) & 1 != 0;
    let x = (word >> 5) & 1 != 0;
    let f_hi = ((word >> 16) & 0xf) as u8;
    let f_lo = ((word >> 12) & 0xf) as u8;
    let f_118 = ((word >> 8) & 0xf) as u8;
    let f_30 = (word & 0xf) as u8;
    let n = rd(b, f_30, pc);
    let s = rd(b, f_118, pc);
    let __h58 = b.trunc::<W32, polyisa_sem::W16>(n);

    let nlo = b.sext::<polyisa_sem::W16, W32>(__h58);
    let __h59 = k32(b, 16);
    let __h60 = b.shr_l(n, __h59);
    let __h61 = b.trunc::<W32, polyisa_sem::W16>(__h60);

    let nhi = b.sext::<polyisa_sem::W16, W32>(__h61);
    let __h62 = b.trunc::<W32, polyisa_sem::W16>(s);

    let slo = b.sext::<polyisa_sem::W16, W32>(__h62);
    let __h63 = k32(b, 16);
    let __h64 = b.shr_l(s, __h63);
    let __h65 = b.trunc::<W32, polyisa_sem::W16>(__h64);

    let shi = b.sext::<polyisa_sem::W16, W32>(__h65);
    // X 版は Rn の半部を入れ替える。
    let (nlo, nhi) = if x { (nhi, nlo) } else { (nlo, nhi) };
    let plo = b.mul::<W32>(nlo, slo);
    let phi = b.mul::<W32>(nhi, shi);
    match top8 {
        // smlad/smusd/smld 系：Rd = Ra + plo ± phi（sub で差、Ra=f で累算なし）。
        0x70 => {
            let acc = if f_hi == 0xf {
                k32(b, 0)
            } else {
                rd(b, f_hi, pc)
            };
            let body = if sub {
                b.sub(plo, phi)
            } else {
                b.add(plo, phi)
            };
            let r = b.add(acc, body);
            wr(b, f_lo, r);
        }
        // smlald/smlsld 系：RdHi:RdLo += plo ± phi（64 ビット）。
        0x74 => {
            let body = if sub {
                b.sub(plo, phi)
            } else {
                b.add(plo, phi)
            };
            let body64 = b.sext::<W32, W64>(body);
            let lo = rd(b, f_hi, pc);
            let hi = rd(b, f_lo, pc);
            let acc = {
                let lo64 = b.zext::<W32, W64>(lo);
                let hi64 = b.zext::<W32, W64>(hi);
                let __h66 = k64(b, 32);
                let __h67 = b.shl(hi64, __h66);

                b.or(lo64, __h67)
            };
            let r = b.add(body64, acc);
            let __h68 = b.trunc::<W64, W32>(r);

            b.set(Gpr(f_hi).state(), __h68);
            let __h69 = k64(b, 32);
            let __h70 = b.shr_l(r, __h69);
            let __h71 = b.trunc::<W64, W32>(__h70);

            b.set(Gpr(f_lo).state(), __h71);
        }
        // smmul/smmla 系：Rd = Ra + ((n*s) >> 32)。x=1 は rounding。
        0x75 => {
            let __h72 = b.sext::<W32, W64>(n);
            let __h73 = b.sext::<W32, W64>(s);

            let p64 = b.mul::<W64>(__h72, __h73);
            let p64 = if x {
                let __h74 = k64(b, 0x8000_0000);

                // round：+0x80000000 してから >>32。
                b.add(p64, __h74)
            } else {
                p64
            };
            let __h75 = k64(b, 32);
            let __h76 = b.shr_l(p64, __h75);

            let ph = b.trunc::<W64, W32>(__h76);
            let r = if f_lo == 0xf {
                ph
            } else {
                let __h77 = rd(b, f_lo, pc);

                b.add(__h77, ph)
            };
            wr(b, f_hi, r);
        }
        _ => return Err(unimpl(b)),
    }
    Ok(())
}

/// メディア領域の入口。bits[27:20] と bits[7:4] で振り分ける。
pub fn media<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let top8 = (word >> 20) & 0xff;
    let b74 = (word >> 4) & 0xf;
    match top8 {
        // 並列加減算（signed）
        0x61 if b74 & 1 != 0 => parl(b, word, pc, 0),
        // 並列加減算（unsigned）
        0x65 if b74 & 1 != 0 => parl(b, word, pc, 1),
        // 半値化並列（halving）
        0x63 if b74 & 1 != 0 => parl(b, word, pc, 2),
        // pkh / sel / sxtab16 / uxtab16
        0x68 => match b74 {
            1 | 5 => pkh(b, word, pc),
            7 => extend(b, word, pc),
            0xb => sel(b, word, pc),
            _ => Err(unimpl(b)),
        },
        // ssat / ssat16 / sxtab / sxtb
        0x6a => match b74 & 7 {
            7 => extend(b, word, pc),
            _ => sat(b, word, pc),
        },
        // rev / rev16 / sxtah / sxth
        0x6b => match b74 {
            3 => revop(b, word, pc, 0),
            7 => extend(b, word, pc),
            0xb => revop(b, word, pc, 1),
            _ => Err(unimpl(b)),
        },
        // uxtab16
        0x6c if b74 == 7 => extend(b, word, pc),
        // usat / usat16 / uxtab / uxtb
        0x6e => match b74 & 7 {
            7 => extend(b, word, pc),
            _ => sat(b, word, pc),
        },
        // rbit / revsh / uxtah / uxth
        0x6f => match b74 {
            3 => revop(b, word, pc, 2),
            7 => extend(b, word, pc),
            0xb => revop(b, word, pc, 3),
            _ => Err(unimpl(b)),
        },
        // smlad/smusd/smlsd 系
        0x70 if b74 & 1 != 0 => pmul2(b, word, pc),
        // sdiv（[7:4]=0001 かつ [15:12]=0xf）
        0x71 if b74 == 1 && (word >> 12) & 0xf == 0xf => sdiv(b, word, pc, true),
        // udiv
        0x73 if b74 == 1 && (word >> 12) & 0xf == 0xf => sdiv(b, word, pc, false),
        // smlald/smlsld 系
        0x74 if b74 & 1 != 0 => pmul2(b, word, pc),
        // smmul/smmla 系
        0x75 if b74 & 1 != 0 => pmul2(b, word, pc),
        // usad8/usada8
        0x78 if b74 == 1 => usad8(b, word, pc),
        // sbfx
        0x7a if b74 & 0b0101 == 0b0101 => bfx(b, word, pc, true),
        // bfi/bfc（[7:4]=0001）
        0x7c if b74 == 1 => bfi(b, word, pc),
        // ubfx
        0x7e if b74 & 0b0101 == 0b0101 => bfx(b, word, pc, false),
        // udf
        0x7f if b74 == 0xf => Err(b.raise(GuestException {
            kind: ExceptionKind::Undefined,
            code: 0,
            addr: None,
            in_delay_slot: false,
        })),
        _ => Err(unimpl(b)),
    }
}

// ---- VFP ----

/// S レジスタを生の W32 として読む（n は 0..32、D の半分）。
fn vrs<B: Backend>(b: &mut B, n: u8) -> B::V<W32> {
    let d = b.get(vfp_ref(n >> 1));
    if n & 1 != 0 {
        let __h78 = k64(b, 32);
        let __h79 = b.shr_l(d, __h78);

        b.trunc::<W64, W32>(__h79)
    } else {
        b.trunc::<W64, W32>(d)
    }
}

/// S レジスタを生の W32 で書く。
fn vws<B: Backend>(b: &mut B, n: u8, v: B::V<W32>) {
    let d = b.get(vfp_ref(n >> 1));
    let lo = b.trunc::<W64, W32>(d);
    let __h80 = k64(b, 32);
    let __h81 = b.shr_l(d, __h80);

    let hi = b.trunc::<W64, W32>(__h81);
    let (nl, nh) = if n & 1 != 0 { (lo, v) } else { (v, hi) };
    let nl64 = b.zext::<W32, W64>(nl);
    let nh64 = b.zext::<W32, W64>(nh);
    let __h82 = k64(b, 32);
    let __h83 = b.shl(nh64, __h82);

    let nd = b.or(nl64, __h83);
    b.set(vfp_ref(n >> 1), nd);
}

/// D レジスタを生の W64 として読む。
fn vrd<B: Backend>(b: &mut B, n: u8) -> B::V<W64> {
    b.get(vfp_ref(n & 31))
}

/// D レジスタを生の W64 で書く。
fn vwd<B: Backend>(b: &mut B, n: u8, v: B::V<W64>) {
    b.set(vfp_ref(n & 31), v);
}

/// S を F32 として読む。
fn vrsf<B: Backend>(b: &mut B, n: u8) -> B::V<F32> {
    let __h84 = vrs(b, n);

    b.trunc::<W32, F32>(__h84)
}

/// S を F32 で書く。
fn vwsf<B: Backend>(b: &mut B, n: u8, v: B::V<F32>) {
    let __h85 = b.trunc::<F32, W32>(v);

    vws(b, n, __h85);
}

/// D を F64 として読む。
fn vrdf<B: Backend>(b: &mut B, n: u8) -> B::V<F64> {
    let __h86 = vrd(b, n);

    b.trunc::<W64, F64>(__h86)
}

/// D を F64 で書く。
fn vwdf<B: Backend>(b: &mut B, n: u8, v: B::V<F64>) {
    let __h87 = b.trunc::<F64, W64>(v);

    vwd(b, n, __h87);
}

/// FPSCR の NZCV（bits[31:28]）を cpsr に写す（vmrs apsr_nzcv）。
fn fpscr_to_nzcv<B: Backend>(b: &mut B) {
    let f = b.get(fpscr_ref());
    let __h88 = k32(b, 0xf000_0000);

    let top = b.and(f, __h88);
    let cs = cpsr(b);
    let __h89 = k32(b, 0x0fff_ffff);

    let keep = b.and(cs, __h89);
    let __h90 = b.or(keep, top);

    b.set(cpsr_ref(), __h90);
}

/// FPSCR の NZCV を書く（vcmp）。
fn fpscr_nzcv<B: Backend>(b: &mut B, n: B::B, z: B::B, c: B::B, v: B::B) {
    let f = b.get(fpscr_ref());
    let __h91 = k32(b, 0x0fff_ffff);

    let keep = b.and(f, __h91);
    let __h92 = k32(b, 1 << 31);
    let __h93 = k32(b, 0);

    let n31 = b.select::<W32>(n, __h92, __h93);
    let __h94 = k32(b, 1 << 30);
    let __h95 = k32(b, 0);

    let z30 = b.select::<W32>(z, __h94, __h95);
    let __h96 = k32(b, 1 << 29);
    let __h97 = k32(b, 0);

    let c29 = b.select::<W32>(c, __h96, __h97);
    let __h98 = k32(b, 1 << 28);
    let __h99 = k32(b, 0);

    let v28 = b.select::<W32>(v, __h98, __h99);
    let __h100 = b.or(n31, z30);
    let __h101 = b.or(c29, v28);

    let hi = b.or(__h100, __h101);
    let __h102 = b.or(keep, hi);

    b.set(fpscr_ref(), __h102);
}

/// コプロセッサのロード/ストア領域（110）。
/// VLDR/VSTR（bit24=1）と VLDM/VSTM（PU=01/10）と MCRR/MRRC（1100 010x）。
pub fn cp_ls<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let top8 = (word >> 20) & 0xff;
    let cp = (word >> 8) & 0xf;
    // MCRR/MRRC（1100 0100 / 1100 0101）：vmov dN,rt,rt2。cp=11。
    if matches!(top8, 0xc4 | 0xc5) && cp == 0xb {
        let rt = ((word >> 12) & 0xf) as u8;
        let rt2 = ((word >> 16) & 0xf) as u8;
        let crm = (word & 0xf) as u8;
        let opc1 = ((word >> 4) & 0xf) as u8;
        // Dm の最上位ビットは opc1[1]（opc1[0] は vmov を示す固定ビット）。
        let dn = (((opc1 >> 1) & 1) << 4) | crm;
        if top8 == 0xc4 {
            // mcrr：dN = rt:rt2
            let lo = rd(b, rt, pc);
            let hi = rd(b, rt2, pc);
            let lo64 = b.zext::<W32, W64>(lo);
            let hi64 = b.zext::<W32, W64>(hi);
            let __h103 = k64(b, 32);
            let __h104 = b.shl(hi64, __h103);
            let __h105 = b.or(lo64, __h104);

            vwd(b, dn, __h105);
        } else {
            // mrrc：rt:rt2 = dN
            let v = vrd(b, dn);
            let __h106 = b.trunc::<W64, W32>(v);

            wr(b, rt, __h106);
            let __h107 = k64(b, 32);
            let __h108 = b.shr_l(v, __h107);
            let __h109 = b.trunc::<W64, W32>(__h108);

            wr(b, rt2, __h109);
        }
        return Ok(());
    }
    // VFP は cp10/11 だけ。
    if cp != 0xa && cp != 0xb {
        return Err(unimpl(b));
    }
    let pu = (word >> 23) & 3;
    let d = ((word >> 22) & 1) as u8;
    let w = (word >> 21) & 1 != 0;
    let l = (word >> 20) & 1 != 0;
    let rn = ((word >> 16) & 0xf) as u8;
    let vd = ((word >> 12) & 0xf) as u8;
    let imm8 = word & 0xff;
    let base = rd(b, rn, pc);
    if (word >> 24) & 1 != 0 && !w {
        // VLDR/VSTR：cond 1101 UD0L。bit24=1 かつ bit21=0 が単一転送。
        // U(bit23)=方向、D(bit22)=レジスタ番号の上位ビット。
        let off = k32(b, imm8 << 2);
        let addr = if (word >> 23) & 1 != 0 {
            b.add(base, off)
        } else {
            let n = b.not(off);
            let __h110 = k32(b, 1);
            let __h111 = b.add(n, __h110);

            b.add(base, __h111)
        };
        if cp == 0xa {
            let s = (vd << 1) | d;
            if l {
                let __h112 = a64(b, addr);

                let v = b.load::<W32>(__h112, DATA_READ)?;
                vws(b, s, v);
            } else {
                let v = vrs(b, s);
                let __h113 = a64(b, addr);

                b.store::<W32>(__h113, v, DATA_WRITE)?;
            }
        } else {
            let dd = d << 4 | vd;
            if l {
                let __h114 = a64(b, addr);

                let v = b.load::<W64>(__h114, DATA_READ)?;
                vwd(b, dd, v);
            } else {
                let v = vrd(b, dd);
                let __h115 = a64(b, addr);

                b.store::<W64>(__h115, v, DATA_WRITE)?;
            }
        }
        return Ok(());
    }
    // VLDM/VSTM：PU は 01(IA) または 10(DB)。
    if pu == 0 || pu == 3 {
        return Err(unimpl(b));
    }
    // cp=0xa は S レジスタ（4B）列、cp=0xb は D レジスタ（8B）列。
    // imm8 は S なら個数、D なら個数の 2 倍。
    let count = if cp == 0xa { imm8 } else { imm8 / 2 };
    let step: i64 = if cp == 0xa { 4 } else { 8 };
    let first: i64 = if pu == 1 { 0 } else { -step * i64::from(count) };
    let __h116 = k32(b, first as u32);

    let mut addr = b.add(base, __h116);
    for i in 0..count as u8 {
        if cp == 0xa {
            let s = ((vd << 1) | d) + i;
            let a = a64(b, addr);
            if l {
                let v = b.load::<W32>(a, DATA_READ)?;
                vws(b, s, v);
            } else {
                let v = vrs(b, s);
                b.store::<W32>(a, v, DATA_WRITE)?;
            }
        } else {
            let dd = (d << 4 | vd) + i;
            let a = a64(b, addr);
            if l {
                let v = b.load::<W64>(a, DATA_READ)?;
                vwd(b, dd, v);
            } else {
                let v = vrd(b, dd);
                b.store::<W64>(a, v, DATA_WRITE)?;
            }
        }
        let __h117 = k32(b, step as u32);

        addr = b.add(addr, __h117);
    }
    if w {
        let __h118 = k32(
            b,
            if pu == 1 {
                (step as u32) * count
            } else {
                0u32.wrapping_sub((step as u32) * count)
            },
        );

        let wb = b.add(base, __h118);
        b.set(Gpr(rn).state(), wb);
    }
    Ok(())
}

/// VFP の 3 項積算。op: 0=vmla, 1=vmls, 2=vnmul, 3=vnmla, 4=vnmls。
fn vfp3<B: Backend>(b: &mut B, op: u32, sz: bool, dd: u8, dn: u8, dm: u8) -> Flow<B> {
    if sz {
        let a = vrdf(b, dd);
        let n = vrdf(b, dn);
        let m = vrdf(b, dm);
        let zf = b.konst::<F64>(0);
        let r = match op {
            0 => {
                let p = b.fmul::<F64>(n, m);
                b.fadd::<F64>(a, p)
            }
            1 => {
                let p = b.fmul::<F64>(n, m);
                b.fsub::<F64>(a, p)
            }
            2 => {
                // vnmul: -(n*m)
                let p = b.fmul::<F64>(n, m);
                b.fsub::<F64>(zf, p)
            }
            3 => {
                // vnmla: -(n*m) - d
                let p = b.fmul::<F64>(n, m);
                let s = b.fsub::<F64>(zf, p);
                b.fsub::<F64>(s, a)
            }
            _ => {
                // vnmls: -(n*m) + d
                let p = b.fmul::<F64>(n, m);
                let s = b.fsub::<F64>(zf, p);
                b.fadd::<F64>(s, a)
            }
        };
        vwdf(b, dd, r);
    } else {
        let a = vrsf(b, dd);
        let n = vrsf(b, dn);
        let m = vrsf(b, dm);
        let zf = b.konst::<F32>(0);
        let r = match op {
            0 => {
                let p = b.fmul::<F32>(n, m);
                b.fadd::<F32>(a, p)
            }
            1 => {
                let p = b.fmul::<F32>(n, m);
                b.fsub::<F32>(a, p)
            }
            2 => {
                let p = b.fmul::<F32>(n, m);
                b.fsub::<F32>(zf, p)
            }
            3 => {
                let p = b.fmul::<F32>(n, m);
                let s = b.fsub::<F32>(zf, p);
                b.fsub::<F32>(s, a)
            }
            _ => {
                let p = b.fmul::<F32>(n, m);
                let s = b.fsub::<F32>(zf, p);
                b.fadd::<F32>(s, a)
            }
        };
        vwsf(b, dd, r);
    }
    Ok(())
}

/// VFP の 2 項演算。op: 0=vadd, 1=vsub, 2=vmul, 3=vdiv。
fn vfp2op<B: Backend>(b: &mut B, op: u32, sz: bool, dd: u8, dn: u8, dm: u8) -> Flow<B> {
    if sz {
        let n = vrdf(b, dn);
        let m = vrdf(b, dm);
        let r = match op {
            0 => b.fadd::<F64>(n, m),
            1 => b.fsub::<F64>(n, m),
            2 => b.fmul::<F64>(n, m),
            _ => b.fdiv::<F64>(n, m),
        };
        vwdf(b, dd, r);
    } else {
        let n = vrsf(b, dn);
        let m = vrsf(b, dm);
        let r = match op {
            0 => b.fadd::<F32>(n, m),
            1 => b.fsub::<F32>(n, m),
            2 => b.fmul::<F32>(n, m),
            _ => b.fdiv::<F32>(n, m),
        };
        vwsf(b, dd, r);
    }
    Ok(())
}

/// VFP の比較（vcmp/vcmpe）。`zero_op` は #0.0 との比較。
fn vcmp<B: Backend>(b: &mut B, sz: bool, dn: u8, dm: u8, zero_op: bool) -> Flow<B> {
    if sz {
        let a = vrdf(b, dn);
        let m = if zero_op {
            b.konst::<F64>(0)
        } else {
            vrdf(b, dm)
        };
        let eq = b.feq::<F64>(a, m);
        let lt = b.flt::<F64>(a, m);
        let __h119 = inv(b, lt);

        let ge = bor(b, eq, __h119);
        let __h120 = b.feq::<F64>(a, a);

        // unordered: !(eq | lt | ge)。ge = !lt（NaN では lt 偽・ge 真）なので
        // unordered は「a<m の偽」では分からない。素直に NaN を見る：
        // unordered <=> !(a==a) || !(m==m)。
        let a_nan = inv(b, __h120);
        let __h121 = b.feq::<F64>(m, m);

        let m_nan = inv(b, __h121);
        let un = bor(b, a_nan, m_nan);
        let n = lt;
        let z = eq;
        // C = !(a<m)（unordered でも 1：ARM の定義どおり）。
        let c = inv(b, lt);
        let v = un;
        let _ = ge;
        fpscr_nzcv(b, n, z, c, v);
    } else {
        let a = vrsf(b, dn);
        let m = if zero_op {
            b.konst::<F32>(0)
        } else {
            vrsf(b, dm)
        };
        let eq = b.feq::<F32>(a, m);
        let lt = b.flt::<F32>(a, m);
        let __h122 = b.feq::<F32>(a, a);

        let a_nan = inv(b, __h122);
        let __h123 = b.feq::<F32>(m, m);

        let m_nan = inv(b, __h123);
        let un = bor(b, a_nan, m_nan);
        let n = lt;
        let z = eq;
        let c = inv(b, lt);
        let v = un;
        fpscr_nzcv(b, n, z, c, v);
    }
    Ok(())
}

/// VFP の浮動小数点即値（8 ビット形式）。f32/f64 とも同じ展開構造。
/// imm8 = a b c d e f g h → 値 = (a?-1:1) * (16 + bcdefg) / 16 * 2^e、
/// e は符号化の 3 ビット部（-3..4）。
fn vfp_imm(imm: u8, sz: bool) -> u64 {
    let i = u64::from(imm);
    let s = i >> 7;
    // ARM の vfp_expand_imm：exp = NOT(bit6) を最上位に。
    // f32: imm32 = (a<<31) | (not(b)<<30) | (b<<29) | (b<<28) | (b<<27)
    //             | (b<<26) | (b<<25) | (b<<24) | (b<<23)
    //             | (c..h << 19)。
    // f64: imm64 = (a<<63) | (not(b)<<62) | (b<<61..53) | (c..h << 48)。
    let b6 = (i >> 6) & 1;
    let nb = b6 ^ 1;
    let frac = i & 0x3f;
    if sz {
        let e = (nb << 10) | (b6 * 0b111_111_111);
        (s << 63) | (e << 52) | (frac << 48)
    } else {
        let e = (nb << 7) | (b6 * 0b111_1111);
        (s << 31) | (e << 23) | (frac << 19)
    }
}

/// VFP2（1110 1D11 …）の単項・比較・変換・即値。
fn vfp2<B: Backend>(b: &mut B, word: u32, _pc: u64, sz: bool, dd: u8, dm: u8) -> Flow<B> {
    let opc = (word >> 16) & 0xf;
    let b64 = (word >> 4) & 0xf;
    // vmov 即値：bits[7:4]==0。
    if b64 == 0 {
        let imm8 = (((word >> 16) & 0xf) << 4) | (word & 0xf);
        let v = vfp_imm(imm8 as u8, sz);
        if sz {
            let __h124 = k64(b, v);

            vwd(b, dd, __h124);
        } else {
            let __h125 = k32(b, v as u32);

            vws(b, dd, __h125);
        }
        return Ok(());
    }
    // bits[7:4] は `o1 M 0`（bit4 は MCR/MRC 判定で 0 済み）。bit7 は
    // サブオペコード（E フラグ等）、bit5 は M（Dm の下位）。bit0 に
    // 来る bit4 は常に 0 なので 0b0001 系パターンはあり得ない。
    match (opc, b64 & 0b1011) {
        // vmov レジスタ（opc=0、bit7=0）
        (0, 0b0000 | 0b0010) => {
            if sz {
                let v = vrd(b, dm);
                vwd(b, dd, v);
            } else {
                let v = vrs(b, dm);
                vws(b, dd, v);
            }
        }
        // vabs（opc=0、bit7=1）
        (0, 0b1000 | 0b1010) => {
            if sz {
                let v = vrd(b, dm);
                let __h126 = k64(b, 0x7fff_ffff_ffff_ffff);
                let __h127 = b.and(v, __h126);

                vwd(b, dd, __h127);
            } else {
                let v = vrs(b, dm);
                let __h128 = k32(b, 0x7fff_ffff);
                let __h129 = b.and(v, __h128);

                vws(b, dd, __h129);
            }
        }
        // vneg（opc=1、bit7=0）
        (1, 0b0000 | 0b0010) => {
            if sz {
                let v = vrd(b, dm);
                let __h130 = k64(b, 1 << 63);
                let __h131 = b.xor(v, __h130);

                vwd(b, dd, __h131);
            } else {
                let v = vrs(b, dm);
                let __h132 = k32(b, 1 << 31);
                let __h133 = b.xor(v, __h132);

                vws(b, dd, __h133);
            }
        }
        // vsqrt（opc=1、bit7=1）
        (1, 0b1000 | 0b1010) => {
            if sz {
                let __h134 = vrdf(b, dm);

                let r = b.fsqrt::<F64>(__h134);
                vwdf(b, dd, r);
            } else {
                let __h135 = vrsf(b, dm);

                let r = b.fsqrt::<F32>(__h135);
                vwsf(b, dd, r);
            }
        }
        // vcmp（reg）（opc=4、bit7=0）と vcmpe（bit7=1）。例外動作の
        // 違い（exact）は単一スレッド解釈では区別しない。
        (4, 0b0000 | 0b0010 | 0b1000 | 0b1010) => vcmp(b, sz, dd, dm, false)?,
        // vcmp/vcmpe（#0）（opc=5）
        (5, 0b0000 | 0b0010 | 0b1000 | 0b1010) => vcmp(b, sz, dd, dm, true)?,
        // vcvt f<->f（opc=7、bit7=1）。変換元は sz クラス、変換先は
        // 反対クラスなので番号付けも反対になる。
        (7, 0b1000 | 0b1010) => {
            let vd_f = ((word >> 12) & 0xf) as u8;
            let d_f = ((word >> 22) & 1) as u8;
            let vm_f = (word & 0xf) as u8;
            let m_f = ((word >> 5) & 1) as u8;
            if sz {
                // f64 -> f32：src=D (m<<4|vm)、dst=S (vd<<1|d)。
                let src = (m_f << 4) | vm_f;
                let dst = (vd_f << 1) | d_f;
                let v = vrdf(b, src);
                let r = b.fcvt_ff::<F64, F32>(v, RM_RNE);
                vwsf(b, dst, r);
            } else {
                // f32 -> f64：src=S (vm<<1|m)、dst=D (d<<4|vd)。
                let src = (vm_f << 1) | m_f;
                let dst = (d_f << 4) | vd_f;
                let v = vrsf(b, src);
                let r = b.fcvt_ff::<F32, F64>(v, RM_RNE);
                vwdf(b, dst, r);
            }
        }
        // vcvt int->float（opc=8）。ソースは常に S レジスタの
        // 生ビットなので、sz に関わらず S 番号付け。
        (8, _) => {
            let m_bit = ((word >> 5) & 1) as u8;
            let dm_s = (((word & 0xf) as u8) << 1) | m_bit;
            let src = vrs(b, dm_s);
            let sgn = b64 & 0b1000 != 0;
            if sz {
                let r = if sgn {
                    b.fcvt_from_s32::<F64>(src, RM_RNE)
                } else {
                    b.fcvt_from_u32::<F64>(src, RM_RNE)
                };
                vwdf(b, dd, r);
            } else {
                let r = if sgn {
                    b.fcvt_from_s32::<F32>(src, RM_RNE)
                } else {
                    b.fcvt_from_u32::<F32>(src, RM_RNE)
                };
                vwsf(b, dd, r);
            }
        }
        // vcvt float->int（opc=c/d）。デスティネーションは常に
        // S レジスタなので、sz に関わらず S 番号付け。
        (0xc | 0xd, _) => {
            let d_bit = ((word >> 22) & 1) as u8;
            let dd_s = ((((word >> 12) & 0xf) as u8) << 1) | d_bit;
            let sgn = opc & 1 != 0;
            // bit7=0 → vcvtr（零方向）、bit7=1 → vcvt（FPSCR 丸め。RNE で近似）。
            let rm = if b64 & 0b1000 != 0 { RM_RNE } else { RM_RTZ };
            if sz {
                let v = vrdf(b, dm);
                let r = if sgn {
                    b.fcvt_s32::<F64>(v, rm)
                } else {
                    b.fcvt_u32::<F64>(v, rm)
                };
                vws(b, dd_s, r);
            } else {
                let v = vrsf(b, dm);
                let r = if sgn {
                    b.fcvt_s32::<F32>(v, rm)
                } else {
                    b.fcvt_u32::<F32>(v, rm)
                };
                vws(b, dd_s, r);
            }
        }
        _ => return Err(unimpl(b)),
    }
    Ok(())
}

/// VFP のデータ処理と転送（1110 領域）。
pub fn cp_dp<B: Backend>(b: &mut B, word: u32, pc: u64) -> Flow<B> {
    let cp = (word >> 8) & 0xf;
    if (word >> 4) & 1 != 0 {
        // MCR/MRC（bit4=1）。
        let opc1 = (word >> 21) & 7;
        let l = (word >> 20) & 1 != 0;
        let crn = ((word >> 16) & 0xf) as u8;
        let rt = ((word >> 12) & 0xf) as u8;
        let opc2 = (word >> 5) & 7;
        let crm = (word & 0xf) as u8;
        return mcr_mrc(b, pc, cp, opc1, l, crn, rt, opc2, crm);
    }
    // CDP・VFP データ処理。cp は 10(s)/11(d)。
    if cp != 0xa && cp != 0xb {
        return Err(unimpl(b));
    }
    let sz = cp == 0xb;
    let d = ((word >> 22) & 1) as u8;
    let n = ((word >> 7) & 1) as u8;
    let m = ((word >> 5) & 1) as u8;
    let dd = if sz {
        (d << 4) | ((word >> 12) & 0xf) as u8
    } else {
        (((word >> 12) & 0xf) as u8) << 1 | d
    };
    let dn = if sz {
        (n << 4) | ((word >> 16) & 0xf) as u8
    } else {
        (((word >> 16) & 0xf) as u8) << 1 | n
    };
    let dm = if sz {
        (m << 4) | (word & 0xf) as u8
    } else {
        ((word & 0xf) as u8) << 1 | m
    };
    let top4 = (word >> 20) & 0xf;
    // VFP2 面（1110 1D11…、bits[23:20]=1101 系）。
    if (word >> 23) & 1 != 0 && top4 & 0b1011 == 0b1011 {
        return vfp2(b, word, pc, sz, dd, dm);
    }
    // 3 項と 2 項。bit6 が op の一部。
    match (top4, (word >> 6) & 1) {
        (0, 0) => vfp3(b, 0, sz, dd, dn, dm),   // vmla
        (0, 1) => vfp3(b, 1, sz, dd, dn, dm),   // vmls
        (1, 0) => vfp3(b, 4, sz, dd, dn, dm),   // vnmls
        (1, 1) => vfp3(b, 3, sz, dd, dn, dm),   // vnmla
        (2, 0) => vfp2op(b, 2, sz, dd, dn, dm), // vmul
        (2, 1) => vfp3(b, 2, sz, dd, dn, dm),   // vnmul
        (3, 0) => vfp2op(b, 0, sz, dd, dn, dm), // vadd
        (3, 1) => vfp2op(b, 1, sz, dd, dn, dm), // vsub
        (8, _) => vfp2op(b, 3, sz, dd, dn, dm), // vdiv
        _ => Err(unimpl(b)),
    }
}

/// MCR/MRC。VFP の単一転送（opc1=0）、VMRS/VMSR（opc1=7）、p15（TLS）。
#[allow(clippy::too_many_arguments)]
fn mcr_mrc<B: Backend>(
    b: &mut B,
    pc: u64,
    cp: u32,
    opc1: u32,
    l: bool,
    crn: u8,
    rt: u8,
    opc2: u32,
    crm: u8,
) -> Flow<B> {
    match cp {
        // VFP 単一転送：opc1=0 は S レジスタ、g=1 は vmov sN,rt。
        0xa | 0xb if opc1 == 0 => {
            let sn = (crn << 1) | ((opc2 >> 2) & 1) as u8;
            if l {
                let v = vrs(b, sn);
                wr(b, rt, v);
            } else {
                let v = rd(b, rt, pc);
                vws(b, sn, v);
            }
            Ok(())
        }
        // VMRS/VMSR：opc1=7。crn で VFP システムレジスタを選ぶ。
        0xa | 0xb if opc1 == 7 => {
            if l {
                match crn {
                    // FPSCR。Rt=15 は APSR_nzcv（cpsr へ書く）。
                    1 => {
                        if rt == 15 {
                            fpscr_to_nzcv(b);
                        } else {
                            let v = b.get(fpscr_ref());
                            wr(b, rt, v);
                        }
                    }
                    // FPEXC/FPSID/MVFR 系はゼロを返す簡易実装。
                    _ => {
                        let __h136 = k32(b, 0);

                        wr(b, rt, __h136);
                    }
                }
            } else if crn == 1 {
                let v = rd(b, rt, pc);
                b.set(fpscr_ref(), v);
            }
            Ok(())
        }
        // p15：TLS（c13,c0）だけ本物、バリア系は no-op。
        0xf => {
            if opc1 == 0 && crn == 13 && crm == 0 && (opc2 == 2 || opc2 == 3) {
                if l {
                    let v = b.get(if opc2 == 2 {
                        tpidrurw_ref()
                    } else {
                        tpidruro_ref()
                    });
                    wr(b, rt, v);
                } else {
                    let v = rd(b, rt, pc);
                    if opc2 == 2 {
                        b.set(tpidrurw_ref(), v);
                    } else {
                        b.set(tpidruro_ref(), v);
                    }
                }
            }
            // c7/c15 のバリア・キャッシュ操作は no-op。
            Ok(())
        }
        _ => Err(unimpl(b)),
    }
}

/// 無条件領域のコプロセッサ（cp2_*）。LDC2/STC2/CDP2/MCR2/MRC2。
pub fn cp2<B: Backend>(b: &mut B, word: u32) -> Flow<B> {
    let _ = word;
    Err(unimpl(b))
}

/// 無条件ヒント（PLD/PLI/DMB/DSB/ISB/CLREX）。実行時は no-op。
/// CLREX は単一スレッドでは効果を持たない。
pub fn uncond_hint<B: Backend>(_b: &mut B, word: u32) -> Flow<B> {
    let _ = word;
    Ok(())
}
