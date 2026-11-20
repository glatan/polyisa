// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha AXP の命令意味論。
//!
//! 段階16-4 の範囲は実行ループが必要とする最小集合:
//! `lda`/`ldah`（アドレス形成＝定数ロード）、無条件の制御移譲
//! （`br`/`bsr`/`jmp`/`jsr`/`jsr_coroutine`/`ret`）、`call_pal` の
//! トラップ発生、PAL 予約オペコードの Undefined 例外。
//! 段階16-5 で整数 Operate 系（算術・論理・比較・cmov・シフト・
//! バイト操作・`mb`/`wmb`・`rpcc`/`rc`/`rs`）を足した。
//! 段階16-6 で乗算と拡張命令（BWX/CIX/MVI。FIX は FP 側の世代
//! ゲートのみで整数意味論を持たない）を足した。Alpha に整数
//! 除算命令はない。
//! 段階16-7 で整数 load/store（ldq_u/stq_u・ldl_l/ldq_l/
//! stl_c/stq_c を含む）を足した。
//! 段階16-8 で整数・FP の条件分岐を足した（jmp/jsr/ret と
//! br/bsr は段階16-4 で実装済み）。FP 有効フラグ（FEN）の検査は
//! 段階16-9 で FPCR まわりと一緒に扱う。
//! （それ以外の命令は `Ok(false)` を返し、呼び出し側が未実装と
//! して扱う）。
//!
//! 出典は SPEC-ALPHA-ARM。ext/ins/msk/zap と cmpbge・/v 修飾の
//! 細部は QEMU（SRC-QEMU）と照合済み。
//! Ref: SPEC-ALPHA-ARM, SRC-QEMU.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, GuestException, StateRef, W8, W16, W32, W64};

use super::{
    CpuState, Insn, ops_fbrr, ops_fbrw, ops_ffb, ops_fmbr, ops_fmfcw, ops_fmld, ops_fopl,
    ops_foplz, ops_fopr, ops_foprz, ops_fpal, ops_fret,
};

/// 整数レジスタ参照。r31 は読み出しで常に 0、書き込みは破棄される。
// Ref: SPEC-ALPHA-ARM §Integer registers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, r) + (self.0 as usize) * 8)
    }

    /// 読み出し。r31 はハード的に 0 を返す。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W64> {
        if self.0 == 31 {
            b.konst::<W64>(0)
        } else {
            b.get(self.state())
        }
    }

    /// 書き込み。r31 への書き込みは捨てる。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W64>) {
        if self.0 != 31 {
            b.set(self.state(), v);
        }
    }
}

/// FP レジスタ参照。f31 は読み出しで常に 0（書き込みは破棄）。
// Ref: SPEC-ALPHA-ARM §Floating-point registers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpr(pub u8);

impl Fpr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + (self.0 as usize) * 8)
    }

    /// 読み出し。f31 はハード的に +0.0（全ビット 0）を返す。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W64> {
        if self.0 == 31 {
            b.konst::<W64>(0)
        } else {
            b.get(self.state())
        }
    }

    /// 書き込み。f31 への書き込みは捨てる。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W64>) {
        if self.0 != 31 {
            b.set(self.state(), v);
        }
    }
}

/// プログラムカウンタの状態位置。
#[must_use]
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// FPCR の状態位置。
#[must_use]
pub fn fpcr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fpcr))
}

/// PAL の rduniq/wruniq が転送するユニーク値の状態位置。
#[must_use]
pub fn uniq_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, uniq))
}

/// `rpcc` が読む簡易サイクルカウンタの状態位置。
#[must_use]
pub fn cycle_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cycle))
}

/// `rc`/`rs` が読み書きする RX フラグバイトの状態位置。
#[must_use]
pub fn rx_flag_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, rx_flag))
}

/// `disp16` の符号拡張値。
fn sext16(v: u32) -> i64 {
    i64::from(v as u16 as i16)
}

/// `disp21` の符号拡張値。分岐変位はさらに左2シフトして使う。
fn sext21(v: u32) -> i64 {
    i64::from(v) << 43 >> 43
}

// ---- 段階16-5: 整数 OPERATE のヘルパ ----

/// `zap`/`ext`/`msk`/`ins` 系のバイト選択マスク（bit i = バイト i の
/// 有効性）を 64 ビットマスクへ広げる。QEMU の `zapnot_mask` と同じ。
// Ref: SRC-QEMU (target/alpha/translate.c zapnot_mask).
fn zap_mask(m8: u8) -> u64 {
    let mut m = 0u64;
    for i in 0..8 {
        if m8 >> i & 1 != 0 {
            m |= 0xff << (i * 8);
        }
    }
    m
}

/// `v` の下位 8 ビットをバイト選択マスクとして動的に広げる
/// （`zap`/`zapnot` 用）。
fn zap_mask_of<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let mut m = b.konst::<W64>(0);
    for i in 0..8u64 {
        let ik = b.konst::<W64>(i);
        let bit = b.shr_l(v, ik);
        let one = b.konst::<W64>(1);
        let bit = b.and(bit, one);
        let wk = b.konst::<W64>(0xffu64 << (i * 8));
        let w = b.mul(bit, wk);
        m = b.or(m, w);
    }
    m
}

/// W32 への切り詰めと符号拡張（*l 系命令は結果を符号拡張する）。
// Ref: SPEC-ALPHA-ARM §4.7.1 (longword results are sign-extended).
fn sext_w32<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    let t = b.trunc::<W64, W32>(v);
    b.sext::<W32, W64>(t)
}

/// 定数右論理シフト。
fn shr_n<B: Backend>(b: &mut B, v: B::V<W64>, n: u64) -> B::V<W64> {
    let k = b.konst::<W64>(n);
    b.shr_l(v, k)
}

/// 定数左シフト。
fn shl_n<B: Backend>(b: &mut B, v: B::V<W64>, n: u64) -> B::V<W64> {
    let k = b.konst::<W64>(n);
    b.shl(v, k)
}

/// 定数 AND。
fn and_k<B: Backend>(b: &mut B, v: B::V<W64>, k: u64) -> B::V<W64> {
    let kk = b.konst::<W64>(k);
    b.and(v, kk)
}

/// 比較結果を 0/1 の整数値にする。
fn cmp_to_int<B: Backend>(b: &mut B, op: Cmp, a: B::V<W64>, v: B::V<W64>) -> B::V<W64> {
    let c = b.cmp(op, a, v);
    let one = b.konst::<W64>(1);
    let zero = b.konst::<W64>(0);
    b.select(c, one, zero)
}

/// FOPR/FOPL オペランドを (ra値, 第2ソース値, rc) にほぐす。
/// bit12=1 のリテラル形では第2ソースが lit8 のゼロ拡張。
fn opr_ops<B: Backend>(b: &mut B, word: u32) -> (B::V<W64>, B::V<W64>, Gpr) {
    if word & 0x1000 != 0 {
        let o = ops_fopl(u128::from(word));
        let a = Gpr(o.ra as u8).get(b);
        let v = b.konst::<W64>(u64::from(o.lit8));
        (a, v, Gpr(o.rc as u8))
    } else {
        let o = ops_fopr(u128::from(word));
        let a = Gpr(o.ra as u8).get(b);
        let v = Gpr(o.rb as u8).get(b);
        (a, v, Gpr(o.rc as u8))
    }
}

/// `cmpbge`: バイトごとの unsigned 比較で、バイト i の結果が結果の
/// bit i に入る。16 ビットレーンの SWAR（QEMU helper_cmpbge と同じ
/// 手順）: (a|0x100) - b のレーン内差分で、借りなしなら bit8 が残る。
// Ref: SRC-QEMU (helper_cmpbge).
fn cmpbge<B: Backend>(b: &mut B, a: B::V<W64>, v: B::V<W64>) -> B::V<W64> {
    let lane = 0x00ff_00ff_00ff_00ff;
    let carry = 0x0100_0100_0100_0100;
    let al = and_k(b, a, lane);
    let bl = and_k(b, v, lane);
    let a8 = shr_n(b, a, 8);
    let v8 = shr_n(b, v, 8);
    let ah = and_k(b, a8, lane);
    let bh = and_k(b, v8, lane);
    let cl = {
        let t = or_k(b, al, carry);
        let d = b.sub(t, bl);
        and_k(b, d, carry)
    };
    let ch = {
        let t = or_k(b, ah, carry);
        let d = b.sub(t, bh);
        and_k(b, d, carry)
    };
    // レーン k の借りなしビットは位置 8+16k。結果ビット 2k に集める。
    let gather = |b: &mut B, x: B::V<W64>| {
        let g0 = {
            let t = shr_n(b, x, 8);
            and_k(b, t, 0x01)
        };
        let g1 = {
            let t = shr_n(b, x, 22);
            and_k(b, t, 0x04)
        };
        let g2 = {
            let t = shr_n(b, x, 36);
            and_k(b, t, 0x10)
        };
        let g3 = {
            let t = shr_n(b, x, 50);
            and_k(b, t, 0x40)
        };
        let lo = b.or(g0, g1);
        let hi = b.or(g2, g3);
        b.or(lo, hi)
    };
    let lo = gather(b, cl);
    let hi = gather(b, ch);
    let hi1 = shl_n(b, hi, 1);
    b.or(lo, hi1)
}

fn or_k<B: Backend>(b: &mut B, v: B::V<W64>, k: u64) -> B::V<W64> {
    let kk = b.konst::<W64>(k);
    b.or(v, kk)
}

/// 算術シフト（定数）。
fn sra_n<B: Backend>(b: &mut B, v: B::V<W64>, n: u64) -> B::V<W64> {
    let k = b.konst::<W64>(n);
    b.shr_a(v, k)
}

/// SWAR のポップカウント（Hacker's Delight の定番手順）。
// Ref: SPEC-ALPHA-ARM §4.7.6 ctpop; 手順は Hacker's Delight.
fn ctpop64<B: Backend>(b: &mut B, x: B::V<W64>) -> B::V<W64> {
    let t = {
        let s = shr_n(b, x, 1);
        and_k(b, s, 0x5555_5555_5555_5555)
    };
    let x = b.sub(x, t);
    let x = {
        let lo = and_k(b, x, 0x3333_3333_3333_3333);
        let s = shr_n(b, x, 2);
        let hi = and_k(b, s, 0x3333_3333_3333_3333);
        b.add(lo, hi)
    };
    let x = {
        let s = shr_n(b, x, 4);
        let t = b.add(x, s);
        and_k(b, t, 0x0f0f_0f0f_0f0f_0f0f)
    };
    let m = b.konst::<W64>(0x0101_0101_0101_0101);
    let x = b.mul(x, m);
    shr_n(b, x, 56)
}

/// 64 ビットの先頭ゼロ数（CIX の ctlz）。x=0 なら 64。
// Ref: SPEC-ALPHA-ARM §4.7.6 ctlz.
fn ctlz64<B: Backend>(b: &mut B, x: B::V<W64>) -> B::V<W64> {
    // 最上位の立っているビット以下を全て 1 に畳んでから ~x の
    // popcount を取る。
    let mut y = x;
    for s in [1u64, 2, 4, 8, 16, 32] {
        let t = shr_n(b, y, s);
        y = b.or(y, t);
    }
    let nx = b.not(y);
    ctpop64(b, nx)
}

/// 64 ビットの後端ゼロ数（CIX の cttz）。x=0 なら 64。
// Ref: SPEC-ALPHA-ARM §4.7.6 cttz.
fn cttz64<B: Backend>(b: &mut B, x: B::V<W64>) -> B::V<W64> {
    // (~x) & (x-1) は最下位の立っているビットの下側が全て 1。
    // x=0 では (~0)&(0-1) = 全 1 → 64。
    let nx = b.not(x);
    let one = b.konst::<W64>(1);
    let xm1 = b.sub(x, one);
    let t = b.and(nx, xm1);
    ctpop64(b, t)
}

/// バイト/ワードごとの SIMD min/max（MVI）。
/// lanes = 8（バイト）または 4（ワード）。signed で符号付き比較。
// Ref: SRC-QEMU (helper_min*/helper_max*).
fn simd_minmax<B: Backend>(
    b: &mut B,
    a: B::V<W64>,
    v: B::V<W64>,
    lanes: u64,
    signed: bool,
    is_min: bool,
) -> B::V<W64> {
    let bits = 64 / lanes;
    let lane_mask = (1u64 << bits) - 1;
    let mut res = b.konst::<W64>(0);
    for i in 0..lanes {
        let sh = i * bits;
        let x = {
            let t = shr_n(b, a, sh);
            and_k(b, t, lane_mask)
        };
        let y = {
            let t = shr_n(b, v, sh);
            and_k(b, t, lane_mask)
        };
        let (xe, ye) = if signed {
            (sext_lane(b, x, bits), sext_lane(b, y, bits))
        } else {
            (x, y)
        };
        let op = match (signed, is_min) {
            (true, true) => Cmp::LtS,
            (true, false) => Cmp::GtS,
            (false, true) => Cmp::LtU,
            (false, false) => Cmp::GtU,
        };
        let c = b.cmp(op, xe, ye);
        let m = b.select(c, x, y);
        let t = shl_n(b, m, sh);
        res = b.or(res, t);
    }
    res
}

/// レーン値を 64 ビットへ符号拡張する。
fn sext_lane<B: Backend>(b: &mut B, x: B::V<W64>, bits: u64) -> B::V<W64> {
    let t = shl_n(b, x, 64 - bits);
    sra_n(b, t, 64 - bits)
}

/// メモリアクセスの属性。Alpha はリトルエンディアン。
/// 整列 ldl/ldq/stl/stq は自然境界を要求し、違反は例外になる
/// （カーネルが補完するのが Alpha の流儀）。
/// ldq_u/stq_u は意味論側でアドレスを整列させるので同じ属性でよい。
// Ref: SPEC-ALPHA-ARM §4.8.
const DATA_READ: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

const DATA_WRITE: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
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

/// 整数オーバーフロー例外。`/v` 修飾の算術が使う。
/// code=1 は polyisa 内部の算術例外識別子（Alpha の整数
/// オーバーフロー = QEMU の EXC_M_IOV マスク位に対応するが、
/// ここの値は内部コードであり UAPI/ARM の定数ではない）。
// Ref: SRC-QEMU (arith_excp / EXC_M_IOV).
fn overflow<B: Backend>(b: &mut B) -> B::Exit {
    b.raise(GuestException {
        kind: ExceptionKind::Trap,
        code: 1,
        addr: None,
        in_delay_slot: false,
    })
}

/// pos=0 で「64 ビット右シフト → 0」を表すため、QEMU と同じ二段
/// シフト（`>>(~pos8 & 63)` のあと `>>1`）で 64-pos*8 右に寄せる。
// Ref: SRC-QEMU (gen_ins_h/gen_msk_h).
fn h_shr<B: Backend>(b: &mut B, x: B::V<W64>, pos8: B::V<W64>) -> B::V<W64> {
    let n = b.not(pos8);
    let s1 = and_k(b, n, 63);
    let t = b.shr_l(x, s1);
    let one = b.konst::<W64>(1);
    b.shr_l(t, one)
}

/// 整数 OPERATE（段階16-5）。オペランド形式は FOPR/FOPL の対で、
/// bit12=1 がリテラル形。各バリアントの意味は SPEC-ALPHA-ARM
/// §4.7、細部は QEMU と照合済み。
// Ref: SPEC-ALPHA-ARM, SRC-QEMU (target/alpha/translate.c).
fn operate<B: Backend>(b: &mut B, insn: Insn, word: u32) -> Result<bool, B::Exit> {
    let (a, v, rc) = opr_ops(b, word);
    let zero = b.konst::<W64>(0);
    // _h 形のバイト操作で使う位置量（pos = 第2ソースの下位3ビット）。
    // pos8 = pos*8、h_left = (64-pos*8) & 63、h_shr は pos8 版の
    // 二段右シフト（pos=0 → 結果 0）。
    let pos8 = {
        let t = and_k(b, v, 7);
        shl_n(b, t, 3)
    };
    let h_left = {
        let n = b.sub(zero, pos8);
        and_k(b, n, 63)
    };
    let res = match insn {
        // ---- 0x10: 算術・比較 ----
        // *l 系は低 32 ビット演算の結果を符号拡張して格納する。
        // Ref: SPEC-ALPHA-ARM §4.7.1.
        Insn::Addl | Insn::AddlI => {
            let t = b.add(a, v);
            sext_w32(b, t)
        }
        Insn::Subl | Insn::SublI => {
            let t = b.sub(a, v);
            sext_w32(b, t)
        }
        Insn::S4addl | Insn::S4addlI => {
            let s = shl_n(b, a, 2);
            let t = b.add(s, v);
            sext_w32(b, t)
        }
        Insn::S4subl | Insn::S4sublI => {
            let s = shl_n(b, a, 2);
            let t = b.sub(s, v);
            sext_w32(b, t)
        }
        Insn::S8addl | Insn::S8addlI => {
            let s = shl_n(b, a, 3);
            let t = b.add(s, v);
            sext_w32(b, t)
        }
        Insn::S8subl | Insn::S8sublI => {
            let s = shl_n(b, a, 3);
            let t = b.sub(s, v);
            sext_w32(b, t)
        }
        Insn::Addq | Insn::AddqI => b.add(a, v),
        Insn::Subq | Insn::SubqI => b.sub(a, v),
        Insn::S4addq | Insn::S4addqI => {
            let s = shl_n(b, a, 2);
            b.add(s, v)
        }
        Insn::S4subq | Insn::S4subqI => {
            let s = shl_n(b, a, 2);
            b.sub(s, v)
        }
        Insn::S8addq | Insn::S8addqI => {
            let s = shl_n(b, a, 3);
            b.add(s, v)
        }
        Insn::S8subq | Insn::S8subqI => {
            let s = shl_n(b, a, 3);
            b.sub(s, v)
        }
        Insn::Cmpbge | Insn::CmpbgeI => cmpbge(b, a, v),
        Insn::Cmpult | Insn::CmpultI => cmp_to_int(b, Cmp::LtU, a, v),
        Insn::Cmpule | Insn::CmpuleI => cmp_to_int(b, Cmp::LeU, a, v),
        Insn::Cmpeq | Insn::CmpeqI => cmp_to_int(b, Cmp::Eq, a, v),
        Insn::Cmplt | Insn::CmpltI => cmp_to_int(b, Cmp::LtS, a, v),
        Insn::Cmple | Insn::CmpleI => cmp_to_int(b, Cmp::LeS, a, v),
        // ---- 0x11: 論理・条件移動 ----
        Insn::And | Insn::AndI => b.and(a, v),
        Insn::Bis | Insn::BisI => b.or(a, v),
        Insn::Xor | Insn::XorI => b.xor(a, v),
        Insn::Bic | Insn::BicI => {
            let n = b.not(v);
            b.and(a, n)
        }
        Insn::Ornot | Insn::OrnotI => {
            let n = b.not(v);
            b.or(a, n)
        }
        Insn::Eqv | Insn::EqvI => {
            let x = b.xor(a, v);
            b.not(x)
        }
        // cmov は条件が偽なら rc の元値を保持する。
        Insn::Cmovlbs
        | Insn::CmovlbsI
        | Insn::Cmovlbc
        | Insn::CmovlbcI
        | Insn::Cmoveq
        | Insn::CmoveqI
        | Insn::Cmovne
        | Insn::CmovneI
        | Insn::Cmovlt
        | Insn::CmovltI
        | Insn::Cmovge
        | Insn::CmovgeI
        | Insn::Cmovle
        | Insn::CmovleI
        | Insn::Cmovgt
        | Insn::CmovgtI => {
            let cond = match insn {
                Insn::Cmovlbs | Insn::CmovlbsI => {
                    let t = and_k(b, a, 1);
                    b.cmp(Cmp::Ne, t, zero)
                }
                Insn::Cmovlbc | Insn::CmovlbcI => {
                    let t = and_k(b, a, 1);
                    b.cmp(Cmp::Eq, t, zero)
                }
                Insn::Cmoveq | Insn::CmoveqI => b.cmp(Cmp::Eq, a, zero),
                Insn::Cmovne | Insn::CmovneI => b.cmp(Cmp::Ne, a, zero),
                Insn::Cmovlt | Insn::CmovltI => b.cmp(Cmp::LtS, a, zero),
                Insn::Cmovge | Insn::CmovgeI => b.cmp(Cmp::GeS, a, zero),
                Insn::Cmovle | Insn::CmovleI => b.cmp(Cmp::LeS, a, zero),
                _ => b.cmp(Cmp::GtS, a, zero),
            };
            let old = rc.get(b);
            b.select(cond, v, old)
        }
        // ---- 0x12: バイト操作・シフト ----
        // pos = 第2ソースの下位 3 ビット（即値形も同じ）。
        // Ref: SPEC-ALPHA-ARM §4.7.5.
        Insn::Srl | Insn::SrlI => {
            let n = and_k(b, v, 63);
            b.shr_l(a, n)
        }
        Insn::Sll | Insn::SllI => {
            let n = and_k(b, v, 63);
            b.shl(a, n)
        }
        Insn::Sra | Insn::SraI => {
            let n = and_k(b, v, 63);
            b.shr_a(a, n)
        }
        // zap はマスクの立つバイトを消し、zapnot は残す。
        Insn::Zap | Insn::ZapI => {
            let nv = b.not(v);
            let m = zap_mask_of(b, nv);
            b.and(a, m)
        }
        Insn::Zapnot | Insn::ZapnotI => {
            let m = zap_mask_of(b, v);
            b.and(a, m)
        }
        // ext_l: フィールドを下に引き下ろして下位を取る。
        Insn::Extbl
        | Insn::ExtblI
        | Insn::Extwl
        | Insn::ExtwlI
        | Insn::Extll
        | Insn::ExtllI
        | Insn::Extql
        | Insn::ExtqlI => {
            let m8 = match insn {
                Insn::Extbl | Insn::ExtblI => 0x01,
                Insn::Extwl | Insn::ExtwlI => 0x03,
                Insn::Extll | Insn::ExtllI => 0x0f,
                _ => 0xff,
            };
            let m = b.konst::<W64>(zap_mask(m8));
            let t = b.shr_l(a, pos8);
            b.and(t, m)
        }
        // ext_h: 高位側フィールド = va << (64-pos*8) の下位マスク分。
        Insn::Extwh | Insn::ExtwhI | Insn::Extlh | Insn::ExtlhI | Insn::Extqh | Insn::ExtqhI => {
            let m8 = match insn {
                Insn::Extwh | Insn::ExtwhI => 0x03,
                Insn::Extlh | Insn::ExtlhI => 0x0f,
                _ => 0xff,
            };
            let m = b.konst::<W64>(zap_mask(m8));
            let t = b.shl(a, h_left);
            b.and(t, m)
        }
        Insn::Insbl
        | Insn::InsblI
        | Insn::Inswl
        | Insn::InswlI
        | Insn::Insll
        | Insn::InsllI
        | Insn::Insql
        | Insn::InsqlI => {
            let m8 = match insn {
                Insn::Insbl | Insn::InsblI => 0x01,
                Insn::Inswl | Insn::InswlI => 0x03,
                Insn::Insll | Insn::InsllI => 0x0f,
                _ => 0xff,
            };
            let m = b.konst::<W64>(zap_mask(m8));
            let t = b.and(a, m);
            b.shl(t, pos8)
        }
        Insn::Inswh | Insn::InswhI | Insn::Inslh | Insn::InslhI | Insn::Insqh | Insn::InsqhI => {
            let m8 = match insn {
                Insn::Inswh | Insn::InswhI => 0x03,
                Insn::Inslh | Insn::InslhI => 0x0f,
                _ => 0xff,
            };
            let m = b.konst::<W64>(zap_mask(m8));
            let t = b.and(a, m);
            h_shr(b, t, pos8)
        }
        // msk はフィールド分を消す（a & ~shifted_mask）。
        Insn::Mskbl
        | Insn::MskblI
        | Insn::Mskwl
        | Insn::MskwlI
        | Insn::Mskll
        | Insn::MskllI
        | Insn::Mskql
        | Insn::MskqlI => {
            let m8 = match insn {
                Insn::Mskbl | Insn::MskblI => 0x01,
                Insn::Mskwl | Insn::MskwlI => 0x03,
                Insn::Mskll | Insn::MskllI => 0x0f,
                _ => 0xff,
            };
            let m = b.konst::<W64>(zap_mask(m8));
            let s = b.shl(m, pos8);
            let n = b.not(s);
            b.and(a, n)
        }
        Insn::Mskwh | Insn::MskwhI | Insn::Msklh | Insn::MsklhI | Insn::Mskqh | Insn::MskqhI => {
            let m8 = match insn {
                Insn::Mskwh | Insn::MskwhI => 0x03,
                Insn::Msklh | Insn::MsklhI => 0x0f,
                _ => 0xff,
            };
            let m = b.konst::<W64>(zap_mask(m8));
            let s = h_shr(b, m, pos8);
            let n = b.not(s);
            b.and(a, n)
        }
        _ => unreachable!("operate called for non-operate insn"),
    };
    rc.set(b, res);
    Ok(true)
}

/// `/v` 修飾の算術（オーバーフローで整数オーバーフロー例外）。
/// 符号付き加減算の桁あふれを検査し、あれば rc を書かず例外を
/// 上げる。
// Ref: SPEC-ALPHA-ARM §4.7.1 (/v qualifier), SRC-QEMU (check_overflow).
fn operate_v<B: Backend>(b: &mut B, insn: Insn, word: u32) -> Result<bool, B::Exit> {
    let (a, v, rc) = opr_ops(b, word);
    let is_long = matches!(
        insn,
        Insn::AddlV | Insn::AddlVI | Insn::SublV | Insn::SublVI
    );
    let is_sub = matches!(
        insn,
        Insn::SublV | Insn::SublVI | Insn::SubqV | Insn::SubqVI
    );
    // *l 形はオペランドをまず符号拡張してから 64 ビットで演算する。
    let (aa, vv) = if is_long {
        (sext_w32(b, a), sext_w32(b, v))
    } else {
        (a, v)
    };
    let r = if is_sub { b.sub(aa, vv) } else { b.add(aa, vv) };
    // オーバーフロー条件（QEMU check_overflow と同じ意味）:
    //   *l 形: 32 ビット符号付き演算 — 結果が sext32 で復元できない
    //          （sext32(r) != r）なら桁あふれ。
    //   *q 形: 64 ビット — add は両オペランドの符号が同じ（~(a^v) の
    //          MSB）で結果の符号が a と違う（(a^r) の MSB）。sub は
    //          オペランドの符号が違い、結果の符号が a と違う。
    let ovf = if is_long {
        let r32 = sext_w32(b, r);
        b.cmp(Cmp::Ne, r32, r)
    } else {
        let x1 = b.xor(aa, vv);
        let x2 = b.xor(aa, r);
        let m = if is_sub {
            b.and(x1, x2)
        } else {
            let n = b.not(x1);
            b.and(n, x2)
        };
        let bit = shr_n(b, m, 63);
        let zero = b.konst::<W64>(0);
        b.cmp(Cmp::Ne, bit, zero)
    };
    b.if_then(ovf, |b| Err(overflow(b)))?;
    let res = if is_long { sext_w32(b, r) } else { r };
    rc.set(b, res);
    Ok(true)
}

/// 乗算命令（opcode 0x13、FOPR/FOPL）。Alpha に整数除算命令はなく
/// （ソフトウェアで合成する）、乗算と UMULH だけが存在する。
// Ref: SPEC-ALPHA-ARM §4.7.4, SRC-QEMU (translate.c case 0x13).
fn operate_mul<B: Backend>(b: &mut B, insn: Insn, word: u32) -> Result<bool, B::Exit> {
    let (a, v, rc) = opr_ops(b, word);
    match insn {
        Insn::Mull | Insn::MullI => {
            let t = b.mul(a, v);
            let r = sext_w32(b, t);
            rc.set(b, r);
        }
        Insn::Mulq | Insn::MulqI => {
            let t = b.mul(a, v);
            rc.set(b, t);
        }
        // umulh: unsigned 64×64 の上位 64 ビット。
        Insn::Umulh | Insn::UmulhI => {
            let t = b.mulhu(a, v);
            rc.set(b, t);
        }
        // mull/v: sext32 したオペランドの積が 32 ビットに収まることを
        // 要する（sext32(r) != r で例外）。
        Insn::MullV | Insn::MullVI => {
            let aa = sext_w32(b, a);
            let vv = sext_w32(b, v);
            let r = b.mul(aa, vv);
            let r32 = sext_w32(b, r);
            let ovf = b.cmp(Cmp::Ne, r32, r);
            b.if_then(ovf, |b| Err(overflow(b)))?;
            rc.set(b, r32);
        }
        // mulq/v: 積の上位 64 が下位の符号拡張と一致しないなら
        // 桁あふれ（QEMU check_overflow(hi, sar(lo,63)) と同じ）。
        Insn::MulqV | Insn::MulqVI => {
            let lo = b.mul(a, v);
            let hi = b.mulh(a, v);
            let s = sra_n(b, lo, 63);
            let ovf = b.cmp(Cmp::Ne, hi, s);
            b.if_then(ovf, |b| Err(overflow(b)))?;
            rc.set(b, lo);
        }
        _ => unreachable!("operate_mul called for non-mul insn"),
    }
    Ok(true)
}

/// 拡張命令の 2 入力形（0x1C の FOPR/FOPL。MVI の perr/min/max）。
// Ref: SPEC-ALPHA-ARM §4.7.6, SRC-QEMU (int_helper.c).
fn operate_mvi<B: Backend>(b: &mut B, insn: Insn, word: u32) -> Result<bool, B::Exit> {
    let (a, v, rc) = opr_ops(b, word);
    let res = match insn {
        // perr: バイトごとの絶対差の和（pixel error = SAD）。
        // Ref: SRC-QEMU (helper_perr).
        Insn::Perr => {
            let mut res = b.konst::<W64>(0);
            for i in 0..8u64 {
                let sh = i * 8;
                let x = {
                    let t = shr_n(b, a, sh);
                    and_k(b, t, 0xff)
                };
                let y = {
                    let t = shr_n(b, v, sh);
                    and_k(b, t, 0xff)
                };
                let d = b.sub(x, y);
                // |d| = (d ^ sign) - sign。
                let s = sra_n(b, d, 63);
                let x2 = b.xor(d, s);
                let ad = b.sub(x2, s);
                res = b.add(res, ad);
            }
            res
        }
        Insn::Minsb8 | Insn::Minsb8I => simd_minmax(b, a, v, 8, true, true),
        Insn::Minub8 | Insn::Minub8I => simd_minmax(b, a, v, 8, false, true),
        Insn::Minsw4 | Insn::Minsw4I => simd_minmax(b, a, v, 4, true, true),
        Insn::Minuw4 | Insn::Minuw4I => simd_minmax(b, a, v, 4, false, true),
        Insn::Maxsb8 | Insn::Maxsb8I => simd_minmax(b, a, v, 8, true, false),
        Insn::Maxub8 | Insn::Maxub8I => simd_minmax(b, a, v, 8, false, false),
        Insn::Maxsw4 | Insn::Maxsw4I => simd_minmax(b, a, v, 4, true, false),
        Insn::Maxuw4 | Insn::Maxuw4I => simd_minmax(b, a, v, 4, false, false),
        _ => unreachable!("operate_mvi called for non-mvi insn"),
    };
    rc.set(b, res);
    Ok(true)
}

/// 拡張命令の 1 入力形（0x1C の FOPRZ。BWX/CIX/MVI）。
// Ref: SPEC-ALPHA-ARM §4.7.5/§4.7.6, SRC-QEMU (translate.c case 0x1C).
fn operate_z<B: Backend>(b: &mut B, insn: Insn, word: u32) -> Result<bool, B::Exit> {
    // リテラル形は sextb/sextw のみ存在する（他の 0x1C 命令は
    // REQUIRE_NO_LIT 相当でリテラル形を持たない）。
    if matches!(insn, Insn::SextbI | Insn::SextwI) {
        let o = ops_foplz(u128::from(word));
        let v = b.konst::<W64>(u64::from(o.lit8));
        let res = if insn == Insn::SextbI {
            let t = shl_n(b, v, 56);
            sra_n(b, t, 56)
        } else {
            let t = shl_n(b, v, 48);
            sra_n(b, t, 48)
        };
        Gpr(o.rc as u8).set(b, res);
        return Ok(true);
    }
    let o = ops_foprz(u128::from(word));
    let v = Gpr(o.rb as u8).get(b);
    let res = match insn {
        // sextb/sextw（BWX）: 下位バイト/ワードの符号拡張。
        Insn::Sextb => {
            let t = shl_n(b, v, 56);
            sra_n(b, t, 56)
        }
        Insn::Sextw => {
            let t = shl_n(b, v, 48);
            sra_n(b, t, 48)
        }
        // ctpop/ctlz/cttz（CIX）。
        Insn::Ctpop => ctpop64(b, v),
        Insn::Ctlz => ctlz64(b, v),
        Insn::Cttz => cttz64(b, v),
        // unpkbw（MVI）: バイト 0-3 をワード 0-3 へゼロ拡張で展開。
        Insn::Unpkbw => {
            let b0 = and_k(b, v, 0xff);
            let b1 = {
                let t = and_k(b, v, 0xff00);
                shl_n(b, t, 8)
            };
            let b2 = {
                let t = and_k(b, v, 0xff_0000);
                shl_n(b, t, 16)
            };
            let b3 = {
                let t = and_k(b, v, 0xff00_0000);
                shl_n(b, t, 24)
            };
            let lo = b.or(b0, b1);
            let hi = b.or(b2, b3);
            b.or(lo, hi)
        }
        // unpkbl: バイト 0 → ロングワード 0、バイト 1 → ロングワード 1。
        Insn::Unpkbl => {
            let lo = and_k(b, v, 0xff);
            let t = and_k(b, v, 0xff00);
            let hi = shl_n(b, t, 24);
            b.or(lo, hi)
        }
        // pkwb: 各ワードの下位バイトを下位 4 バイトへ詰める。
        Insn::Pkwb => {
            let b0 = and_k(b, v, 0xff);
            let b1 = {
                let t = shr_n(b, v, 8);
                and_k(b, t, 0xff00)
            };
            let b2 = {
                let t = shr_n(b, v, 16);
                and_k(b, t, 0xff_0000)
            };
            let b3 = {
                let t = shr_n(b, v, 24);
                and_k(b, t, 0xff00_0000)
            };
            let lo = b.or(b0, b1);
            let hi = b.or(b2, b3);
            b.or(lo, hi)
        }
        // pklb: 各ロングワードの下位バイトを下位 2 バイトへ。
        Insn::Pklb => {
            let lo = and_k(b, v, 0xff);
            let t = shr_n(b, v, 24);
            let hi = and_k(b, t, 0xff00);
            b.or(lo, hi)
        }
        _ => unreachable!("operate_z called for non-z insn"),
    };
    Gpr(o.rc as u8).set(b, res);
    Ok(true)
}

/// 整数条件分岐（0x38-0x3F）。ra を符号付き/ビット0 で試す。
/// リンクは書かない。条件が真なら pc+4+sext(disp21)<<2 へ。
// Ref: SPEC-ALPHA-ARM §4.3, SRC-QEMU (gen_bcond).
fn bcond<B: Backend>(b: &mut B, insn: Insn, word: u32, pc: u64) -> Result<bool, B::Exit> {
    let o = ops_fbrr(u128::from(word));
    let v = Gpr(o.ra as u8).get(b);
    let z = b.konst::<W64>(0);
    let c = match insn {
        // blbc/blbs は最下位ビットだけを試す。
        Insn::Blbc => {
            let t = and_k(b, v, 1);
            b.cmp(Cmp::Eq, t, z)
        }
        Insn::Blbs => {
            let t = and_k(b, v, 1);
            b.cmp(Cmp::Ne, t, z)
        }
        Insn::Beq => b.cmp(Cmp::Eq, v, z),
        Insn::Bne => b.cmp(Cmp::Ne, v, z),
        Insn::Blt => b.cmp(Cmp::LtS, v, z),
        Insn::Ble => b.cmp(Cmp::LeS, v, z),
        Insn::Bge => b.cmp(Cmp::GeS, v, z),
        Insn::Bgt => b.cmp(Cmp::GtS, v, z),
        _ => unreachable!("bcond called for non-branch insn"),
    };
    let target = pc
        .wrapping_add(4)
        .wrapping_add((sext21(o.disp21) << 2) as u64);
    b.branch(c, target);
    Ok(true)
}

/// FP 条件分岐（0x31-0x37）。レジスタをビット列として試す
/// （FP 比較ではない）。-0.0 は符号で負だが値としては 0 なので、
/// lt/ge は -0.0 を +0.0 に畳み、eq/ne は符号桁を除いて比べる
/// （QEMU の gen_fold_mzero と同じ）。le/gt は生の符号比較で
/// -0.0 も「0 以下」に入る。
// Ref: SPEC-ALPHA-ARM §4.3, SRC-QEMU (gen_fbcond/gen_fold_mzero).
fn fbcond<B: Backend>(b: &mut B, insn: Insn, word: u32, pc: u64) -> Result<bool, B::Exit> {
    let o = ops_ffb(u128::from(word));
    let v = Fpr(o.fa as u8).get(b);
    let z = b.konst::<W64>(0);
    let c = match insn {
        // eq/ne: 符号桁を除いた全桁が 0 か。
        Insn::Fbeq => {
            let t = and_k(b, v, 0x7fff_ffff_ffff_ffff);
            b.cmp(Cmp::Eq, t, z)
        }
        Insn::Fbne => {
            let t = and_k(b, v, 0x7fff_ffff_ffff_ffff);
            b.cmp(Cmp::Ne, t, z)
        }
        // lt/ge: -0.0（=INT64_MIN のビット列）を +0.0 に畳んでから
        // 符号付き比較。
        Insn::Fblt | Insn::Fbge => {
            let mz = b.konst::<W64>(i64::MIN as u64);
            let is_mz = b.cmp(Cmp::Eq, v, mz);
            let f = b.select(is_mz, z, v);
            b.cmp(
                if insn == Insn::Fblt {
                    Cmp::LtS
                } else {
                    Cmp::GeS
                },
                f,
                z,
            )
        }
        // le/gt: -0.0 はそのまま符号比較に入る。
        Insn::Fble => b.cmp(Cmp::LeS, v, z),
        Insn::Fbgt => b.cmp(Cmp::GtS, v, z),
        _ => unreachable!("fbcond called for non-branch insn"),
    };
    let target = pc
        .wrapping_add(4)
        .wrapping_add((sext21(o.disp21) << 2) as u64);
    b.branch(c, target);
    Ok(true)
}

/// メモリ命令（段階16-7）。`ld ra, disp16(rb)` / `st ra, disp16(rb)`。
/// ra=31 を宛てとする load は prefetch/UNOP でフォールトしない
/// （QEMU の gen_load_int と同じ扱い）。
// Ref: SPEC-ALPHA-ARM §4.8, SRC-QEMU (gen_load_int/gen_store_int).
fn mem<B: Backend>(b: &mut B, insn: Insn, word: u32) -> Result<bool, B::Exit> {
    // FMLD/FMST/FMSTC は桁配置（ra/rb/disp16）が同じなので
    // ops_fmld で兼ねる。
    let o = ops_fmld(u128::from(word));
    // ra=31 宛ての load はプリフェッチ/UNOP。アドレス計算も
    // 読み出しも行わない（QEMU の gen_load_int と同じ扱い）。
    if o.ra == 31
        && matches!(
            insn,
            Insn::Ldbu | Insn::Ldwu | Insn::Ldl | Insn::Ldq | Insn::LdqU | Insn::LdlL | Insn::LdqL
        )
    {
        return Ok(true);
    }
    // ldq_u/stq_u は下位 3 ビットを落とした整列 quadword アクセス。
    // 非整列の実データ受け渡しは ext/ins/msk（段階16-5）との組で行う。
    let ea = {
        let base = Gpr(o.rb as u8).get(b);
        let d = b.konst::<W64>((o.disp16 as i16) as i64 as u64);
        let a = b.add(base, d);
        if matches!(insn, Insn::LdqU | Insn::StqU) {
            and_k(b, a, !7u64)
        } else {
            a
        }
    };
    let ra = Gpr(o.ra as u8);
    match insn {
        Insn::Ldbu => {
            let v: B::V<W8> = b.load(ea, DATA_READ)?;
            let v = b.zext::<W8, W64>(v);
            ra.set(b, v);
        }
        Insn::Ldwu => {
            let v: B::V<W16> = b.load(ea, DATA_READ)?;
            let v = b.zext::<W16, W64>(v);
            ra.set(b, v);
        }
        // ldl は符号拡張して 64 ビットに入れる。
        Insn::Ldl => {
            let v: B::V<W32> = b.load(ea, DATA_READ)?;
            let v = b.sext::<W32, W64>(v);
            ra.set(b, v);
        }
        Insn::Ldq | Insn::LdqU => {
            let v: B::V<W64> = b.load(ea, DATA_READ)?;
            ra.set(b, v);
        }
        Insn::LdlL => {
            let v: B::V<W32> = b.load_reserved(ea, LR_ACC)?;
            let v = b.sext::<W32, W64>(v);
            ra.set(b, v);
        }
        Insn::LdqL => {
            let v: B::V<W64> = b.load_reserved(ea, LR_ACC)?;
            ra.set(b, v);
        }
        Insn::Stb => {
            let v = ra.get(b);
            let v = b.trunc::<W64, W8>(v);
            b.store(ea, v, DATA_WRITE)?;
        }
        Insn::Stw => {
            let v = ra.get(b);
            let v = b.trunc::<W64, W16>(v);
            b.store(ea, v, DATA_WRITE)?;
        }
        Insn::Stl => {
            let v = ra.get(b);
            let v = b.trunc::<W64, W32>(v);
            b.store(ea, v, DATA_WRITE)?;
        }
        Insn::Stq | Insn::StqU => {
            let v = ra.get(b);
            b.store(ea, v, DATA_WRITE)?;
        }
        // st*_c は成否を ra に返す（1=成功）。ra は読み・書き両方。
        // 予約は load_reserved が立てる番地+幅と厳密一致するとき
        // だけ成功する（別サイズの LL/SC 混在は失敗側。ARM は実装
        // 依存なので保守的に扱う）。自分自身の store でも予約は
        // 解除される（interp バックエンドの規約）。
        Insn::StlC => {
            let v = ra.get(b);
            let v = b.trunc::<W64, W32>(v);
            let ok = b.store_conditional(ea, v, SC_ACC)?;
            let one = b.konst::<W64>(1);
            let zero = b.konst::<W64>(0);
            let f = b.select(ok, one, zero);
            ra.set(b, f);
        }
        Insn::StqC => {
            let v = ra.get(b);
            let ok = b.store_conditional(ea, v, SC_ACC)?;
            let one = b.konst::<W64>(1);
            let zero = b.konst::<W64>(0);
            let f = b.select(ok, one, zero);
            ra.set(b, f);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// 命令の意味論。`Ok(true)` は実行完了、`Ok(false)` はこの段階では
/// 未実装（呼び出し側が `Outcome::Unimplemented` に写す）。
/// `pc` はこの命令の番地。
// Ref: SPEC-ALPHA-ARM.
pub fn exec<B: Backend>(b: &mut B, insn: Insn, word: u32, pc: u64) -> Result<bool, B::Exit> {
    match insn {
        // lda ra, disp(rb): ra = rb + sext(disp16)。
        // ldah ra, disp(rb): ra = rb + (sext(disp16) << 16)。
        // rb=31 なら定数ロードとして働く（実行ループの最小命令）。
        // Ref: SPEC-ALPHA-ARM §4.3 lda/ldah.
        Insn::Lda | Insn::Ldah => {
            let o = ops_fmld(u128::from(word));
            let rb = Gpr(o.rb as u8).get(b);
            // ldah は変位だけを 65536 倍してから加える（rb はシフトしない）。
            let disp = sext16(o.disp16) << if insn == Insn::Ldah { 16 } else { 0 };
            let d = b.konst::<W64>(disp as u64);
            let v = b.add(rb, d);
            Gpr(o.ra as u8).set(b, v);
            Ok(true)
        }
        // br ra, disp / bsr ra, disp。ra = pc+4 へリンクして
        // pc+4+sext(disp21)<<2 へ飛ぶ。br の ra=31 は hint だけなので
        // 同じコードで処理できる。
        // Ref: SPEC-ALPHA-ARM §4.3 br/bsr.
        Insn::Br | Insn::Bsr => {
            let o = ops_fbrw(u128::from(word));
            let link = b.konst::<W64>(pc + 4);
            Gpr(o.ra as u8).set(b, link);
            let target = pc
                .wrapping_add(4)
                .wrapping_add((sext21(o.disp21) << 2) as u64);
            let target = b.konst::<W64>(target);
            b.jump(target);
            Ok(true)
        }
        // jmp/jsr/jsr_coroutine ra, (rb), hint。
        // ra = pc+4 を保持して (rb & ~3) へ飛ぶ。hint は予測の手掛かり
        // で、インタプリタでは使わない。
        // Ref: SPEC-ALPHA-ARM §4.3 jmp/jsr/jsr_coroutine.
        Insn::Jmp | Insn::Jsr | Insn::JsrCoroutine => {
            let o = ops_fmbr(u128::from(word));
            let rb = Gpr(o.rb as u8).get(b);
            let mask = b.konst::<W64>(!3);
            let target = b.and(rb, mask);
            let link = b.konst::<W64>(pc + 4);
            Gpr(o.ra as u8).set(b, link);
            b.jump(target);
            Ok(true)
        }
        // ---- 段階16-8: 条件分岐 ----
        Insn::Blbc
        | Insn::Beq
        | Insn::Blt
        | Insn::Ble
        | Insn::Blbs
        | Insn::Bne
        | Insn::Bge
        | Insn::Bgt => bcond(b, insn, word, pc),
        Insn::Fbeq | Insn::Fblt | Insn::Fble | Insn::Fbne | Insn::Fbge | Insn::Fbgt => {
            fbcond(b, insn, word, pc)
        }
        // ret zero, (rb), hint: (rb & ~3) へ飛ぶ（ra を書かない）。
        // Ref: SPEC-ALPHA-ARM §4.3 ret.
        Insn::Ret => {
            let o = ops_fret(u128::from(word));
            let rb = Gpr(o.rb as u8).get(b);
            let mask = b.konst::<W64>(!3);
            let target = b.and(rb, mask);
            b.jump(target);
            Ok(true)
        }
        // call_pal: PALcode 呼び出し。OS パーソナリティが機能番号で
        // 振り分けるため、code に palfn を載せて Trap を上げる。
        // Ref: SPEC-ALPHA-ARM §4.11 call_pal.
        Insn::CallPal => {
            let o = ops_fpal(u128::from(word));
            Err(b.raise(polyisa_sem::GuestException {
                kind: polyisa_sem::ExceptionKind::Trap,
                code: u64::from(o.palfn),
                addr: None,
                in_delay_slot: false,
            }))
        }
        // PAL 予約オペコード（0x19/0x1B/0x1D/0x1E/0x1F）は
        // Reserved Instruction Fault。Undefined として上げる。
        // Ref: SPEC-ALPHA-ARM §4.11.
        Insn::Pal19 | Insn::Pal1b | Insn::Pal1d | Insn::Pal1e | Insn::Pal1f => {
            Err(b.raise(polyisa_sem::GuestException {
                kind: polyisa_sem::ExceptionKind::Undefined,
                code: u64::from(word),
                addr: None,
                in_delay_slot: false,
            }))
        }
        // ---- 段階16-5: 整数 OPERATE ----
        // /v 修飾（オーバーフロー検査付き）。
        Insn::AddlV
        | Insn::AddlVI
        | Insn::SublV
        | Insn::SublVI
        | Insn::AddqV
        | Insn::AddqVI
        | Insn::SubqV
        | Insn::SubqVI => operate_v(b, insn, word),
        // 算術・論理・比較・cmov・シフト・バイト操作。
        Insn::Addl
        | Insn::AddlI
        | Insn::Subl
        | Insn::SublI
        | Insn::S4addl
        | Insn::S4addlI
        | Insn::S4subl
        | Insn::S4sublI
        | Insn::S8addl
        | Insn::S8addlI
        | Insn::S8subl
        | Insn::S8sublI
        | Insn::Addq
        | Insn::AddqI
        | Insn::Subq
        | Insn::SubqI
        | Insn::S4addq
        | Insn::S4addqI
        | Insn::S4subq
        | Insn::S4subqI
        | Insn::S8addq
        | Insn::S8addqI
        | Insn::S8subq
        | Insn::S8subqI
        | Insn::Cmpbge
        | Insn::CmpbgeI
        | Insn::Cmpult
        | Insn::CmpultI
        | Insn::Cmpule
        | Insn::CmpuleI
        | Insn::Cmpeq
        | Insn::CmpeqI
        | Insn::Cmplt
        | Insn::CmpltI
        | Insn::Cmple
        | Insn::CmpleI
        | Insn::And
        | Insn::AndI
        | Insn::Bis
        | Insn::BisI
        | Insn::Xor
        | Insn::XorI
        | Insn::Bic
        | Insn::BicI
        | Insn::Ornot
        | Insn::OrnotI
        | Insn::Eqv
        | Insn::EqvI
        | Insn::Cmovlbs
        | Insn::CmovlbsI
        | Insn::Cmovlbc
        | Insn::CmovlbcI
        | Insn::Cmoveq
        | Insn::CmoveqI
        | Insn::Cmovne
        | Insn::CmovneI
        | Insn::Cmovlt
        | Insn::CmovltI
        | Insn::Cmovge
        | Insn::CmovgeI
        | Insn::Cmovle
        | Insn::CmovleI
        | Insn::Cmovgt
        | Insn::CmovgtI
        | Insn::Srl
        | Insn::SrlI
        | Insn::Sll
        | Insn::SllI
        | Insn::Sra
        | Insn::SraI
        | Insn::Zap
        | Insn::ZapI
        | Insn::Zapnot
        | Insn::ZapnotI
        | Insn::Extbl
        | Insn::ExtblI
        | Insn::Extwl
        | Insn::ExtwlI
        | Insn::Extll
        | Insn::ExtllI
        | Insn::Extql
        | Insn::ExtqlI
        | Insn::Extwh
        | Insn::ExtwhI
        | Insn::Extlh
        | Insn::ExtlhI
        | Insn::Extqh
        | Insn::ExtqhI
        | Insn::Insbl
        | Insn::InsblI
        | Insn::Inswl
        | Insn::InswlI
        | Insn::Insll
        | Insn::InsllI
        | Insn::Insql
        | Insn::InsqlI
        | Insn::Inswh
        | Insn::InswhI
        | Insn::Inslh
        | Insn::InslhI
        | Insn::Insqh
        | Insn::InsqhI
        | Insn::Mskbl
        | Insn::MskblI
        | Insn::Mskwl
        | Insn::MskwlI
        | Insn::Mskll
        | Insn::MskllI
        | Insn::Mskql
        | Insn::MskqlI
        | Insn::Mskwh
        | Insn::MskwhI
        | Insn::Msklh
        | Insn::MsklhI
        | Insn::Mskqh
        | Insn::MskqhI => operate(b, insn, word),
        // ---- 段階16-6: 乗算と拡張命令 ----
        // 乗算（0x13）。Alpha に整数除算命令はない。
        Insn::Mull
        | Insn::MullI
        | Insn::Mulq
        | Insn::MulqI
        | Insn::Umulh
        | Insn::UmulhI
        | Insn::MullV
        | Insn::MullVI
        | Insn::MulqV
        | Insn::MulqVI => operate_mul(b, insn, word),
        // MVI の 2 入力形（perr/min/max。0x1C の FOPR/FOPL）。
        Insn::Perr
        | Insn::Minsb8
        | Insn::Minsb8I
        | Insn::Minub8
        | Insn::Minub8I
        | Insn::Minsw4
        | Insn::Minsw4I
        | Insn::Minuw4
        | Insn::Minuw4I
        | Insn::Maxsb8
        | Insn::Maxsb8I
        | Insn::Maxub8
        | Insn::Maxub8I
        | Insn::Maxsw4
        | Insn::Maxsw4I
        | Insn::Maxuw4
        | Insn::Maxuw4I => operate_mvi(b, insn, word),
        // BWX/CIX/MVI の 1 入力形（0x1C の FOPRZ/FOPLZ）。
        Insn::Sextb
        | Insn::SextbI
        | Insn::Sextw
        | Insn::SextwI
        | Insn::Ctpop
        | Insn::Ctlz
        | Insn::Cttz
        | Insn::Unpkbw
        | Insn::Unpkbl
        | Insn::Pkwb
        | Insn::Pklb => operate_z(b, insn, word),
        // ---- 段階16-7: load/store ----
        Insn::Ldbu
        | Insn::Ldwu
        | Insn::Ldl
        | Insn::Ldq
        | Insn::LdqU
        | Insn::LdlL
        | Insn::LdqL
        | Insn::Stb
        | Insn::Stw
        | Insn::Stl
        | Insn::Stq
        | Insn::StqU
        | Insn::StlC
        | Insn::StqC => mem(b, insn, word),
        // ---- 段階16-5: MISC ----
        // バリアとトラップバリア。順序付き実行のインタプリタでは
        // mb/wmb/trapb/excb は何もしない（trapb の実確定は PAL
        // 実装時）。
        // Ref: SPEC-ALPHA-ARM §4.7.6.
        Insn::Trapb | Insn::Excb | Insn::Mb | Insn::Wmb => Ok(true),
        // プリフェッチ/キャッシュ制御ヒント。性能ヒントなので無視
        // してよい（EV5+ の wh64/ecb/wh64en も同じ扱い）。
        // Ref: SPEC-ALPHA-ARM §4.7.6.
        Insn::Fetch | Insn::FetchM | Insn::Ecb | Insn::Wh64 | Insn::Wh64en => Ok(true),
        // rpcc ra: プロセスサイクルカウンタを読む。実時間ではなく
        // 実行ループが1命令ごとに進める疑似カウンタを返す。
        // Ref: SPEC-ALPHA-ARM §4.11.5.
        Insn::Rpcc => {
            let o = ops_fmfcw(u128::from(word));
            let c = b.get(cycle_ref());
            Gpr(o.ra as u8).set(b, c);
            Ok(true)
        }
        // rc ra / rs ra: rx_flag を読み出し、rc は 0、rs は 1 に
        // する（クリティカルセクションのフラグ。単一スレッドでは
        // 通常 0 のまま遷移する）。
        // Ref: SPEC-ALPHA-ARM §4.11.5.
        Insn::Rc | Insn::Rs => {
            let o = ops_fmfcw(u128::from(word));
            let f = b.get(rx_flag_ref());
            Gpr(o.ra as u8).set(b, f);
            let nv = b.konst::<W64>(u64::from(insn == Insn::Rs));
            b.set(rx_flag_ref(), nv);
            Ok(true)
        }
        _ => Ok(false),
    }
}
