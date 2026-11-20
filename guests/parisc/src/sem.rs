// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC の命令意味論。
//!
//! 段階17-2 は骨格のみ。段階17-4 で実行ループ（PR4）が必要とする
//! 最小集合を実装した:
//! - 定数形成: `ldil`/`addil`/`ldo`
//! - 整数算術・論理: `add`/`add,l`/`add,tsv`/`add,c`/`sub` 系、
//!   `addi`/`subi`/`cmpiclr` 系、`and`/`andcm`/`or`/`xor`/`uxor`/
//!   `uaddcm`/`cmpclr`（条件完語つき。`,`l` 以外はキャリを PSW の
//!   内部ビットに保存する）
//! - オフセット・短即値・インデックス形式の整数 load/store と
//!   `ldcw`（非分割の load+store0 で近似）
//! - 分岐: `b`/`bl`/`gate`/`bl,push`/`bl.long`/`blr`/`bv`/`bve` と
//!   `be`/`ble`（間接）と条件分岐 `comb`/`comib`/`addb`/`addib`/
//!   `movb`/`movib`/`bb` 系。`,`n` 完語と条件成立時の無効化
//!   （PSW.N）を扱う
//! - 特権系のうちユーザが使えるもの: `mfctl`/`mtctl`（SAR 等）・
//!   `mfsp`/`mtsp`/`mtsm`/`mtsarcm`/`mfia`/`ldsid`・`sync` と
//!   `fdc`/`fic`/`pdc` 系の nop 化。それ以外の特権命令は Trap。
//! - `ble` は gateway アドレスへの普通の間接分岐として実行し、
//!   ゲートウェイ判定（trap 化）はフェッチ側（`run_parisc`）で
//!   行う。QEMU の `do_page_zero` と同じタイミングで、分岐遅延
//!   スロット中の `ldi %r20` が syscall 番号を置ける。
//!
//! 条件コードは 32 ビット（d=0）と 64 ビット（d=1）の両方を
//! 評価する。PSW の C/V/B 更新は簡約してあり、`dcor`/`ds`/
//! `hadd` 等の MAX/十進補正や FP は未実装（`Ok(false)`）。
//!
//! 出典は SPEC-PARISC-11・SPEC-PARISC-20。遅延分岐・無効化・
//! 条件・即値復元の細部は QEMU（SRC-QEMU: target/hppa/
//! translate.c）と照合済み。
//! Ref: SPEC-PARISC-11, SPEC-PARISC-20, SRC-QEMU.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, ExceptionKind, GuestException, StateRef, W8, W16, W32, W64};

use super::{CpuState, Insn, extract_ops};

/// 汎用レジスタ参照。r0 は読み出しで常に 0、書き込みは破棄される。
// Ref: SPEC-PARISC-11 §2.2（r0 はソースで 0 を供給する。
// 実機でも書き込みは格納されるが、参照は常に 0 を返す契約に揃える）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gr(pub u8);

impl Gr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, gr) + (self.0 as usize) * 8)
    }

    /// 読み出し。r0 はハード的に 0 を返す。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W64> {
        if self.0 == 0 {
            b.konst::<W64>(0)
        } else {
            b.get(self.state())
        }
    }

    /// 書き込み。r0 への書き込みは捨てる。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W64>) {
        if self.0 != 0 {
            b.set(self.state(), v);
        }
    }
}

/// FP レジスタ参照。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpr(pub u8);

impl Fpr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + (self.0 as usize) * 8)
    }
}

/// 制御レジスタ参照。cr11 = SAR、cr26/cr27 はユーザから読める。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cr(pub u8);

impl Cr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cr) + (self.0 as usize) * 8)
    }

    /// 読み出し。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W64> {
        b.get(self.state())
    }

    /// 書き込み。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W64>) {
        b.set(self.state(), v);
    }
}

/// 空間レジスタ参照。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sr(pub u8);

impl Sr {
    /// 状態の位置。
    #[must_use]
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, sr) + (self.0 as usize) * 8)
    }

    /// 読み出し。
    pub fn get<B: Backend>(self, b: &mut B) -> B::V<W64> {
        b.get(self.state())
    }

    /// 書き込み。
    pub fn set<B: Backend>(self, b: &mut B, v: B::V<W64>) {
        b.set(self.state(), v);
    }
}

/// PSW の位置。QEMU のユーザモード並びを使う（ssm/rsm の HW 番号
/// とは別。N=bit5, B=bit3, W=bit11）。上位 32 ビットはアーキテクト
/// されないので add/sub のキャリ保持に使う（PSW.CB の簡約版。
/// `add,c`/`sub,b` の carry-in はこの 2 ビットだけを見る）。
// Ref: SRC-QEMU target/hppa/cpu.h (PSW_*).
pub const PSW_B: u64 = 0x0000_0008;
pub const PSW_N: u64 = 0x0000_0020;
pub const PSW_W: u64 = 0x0000_0800;
/// 32 ビット演算のキャリアウト（cb の bit32）を保持する内部ビット。
pub const PSW_CARRY32: u64 = 1 << 40;
/// 64 ビット演算のキャリアウト（cb_msb）を保持する内部ビット。
pub const PSW_CARRY64: u64 = 1 << 41;

/// PSW の位置。
#[must_use]
pub fn psw_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, psw))
}

/// IAOQ front（現在実行中の命令番地）の位置。
#[must_use]
pub fn iaoq_f_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, iaoq_f))
}

/// IAOQ back（次の命令番地）の位置。
#[must_use]
pub fn iaoq_b_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, iaoq_b))
}

/// IASQ front/back の位置（ユーザモードでは参照されないが配置の
/// ため公開する）。
#[must_use]
pub fn iasq_f_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, iasq_f))
}

/// IASQ back の位置。
#[must_use]
pub fn iasq_b_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, iasq_b))
}

/// Trap コード。`/run_parisc` の `handle_trap` に渡る内部番号。
/// QEMU の EXCP_* とは別系統。ゲートウェイ分岐（0x100 等）は
/// アドレスそのものを code として渡す（`run_parisc` 側）。
pub const TRAP_COND: u64 = 1;
/// `,tsv` の符号付きオーバーフロー。
pub const TRAP_OVERFLOW: u64 = 2;
/// ユーザから触れない特権レジスタ・命令（EXCP_PRIV_REG/OPR 相当）。
pub const TRAP_PRIV: u64 = 3;
/// 不正命令（delay slot 内の gate など）。
pub const TRAP_ILL: u64 = 4;

/// メモリアクセスの属性。PA-RISC はビッグエンディアン。
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

// ----------------------------------------------------------------
// 即値・変位の復元。生成デコーダは生のフィールドを渡すので、
// QEMU の assemble_* / expand_* と同じ並べ直しをここで行う。
// Ref: SRC-QEMU translate.c (assemble_21, expand_16, ...).
// ----------------------------------------------------------------

/// `ldil`/`addil` の 21 ビット即値（`%assemble_21`＋`expand_shl11`）。
/// レイアウト: bit0=符号, bits1-11→im[20:9], bits14-15→im[8:7],
/// bits16-20→im[6:2], bits12-13→im[1:0]。全体を <<11。
fn assemble_21(v: u64) -> u64 {
    let mut i = ((-((v & 1) as i64)) as u64) << 20;
    i |= ((v >> 1) & 0x7ff) << 9;
    i |= ((v >> 14) & 0x3) << 7;
    i |= ((v >> 16) & 0x1f) << 2;
    i |= (v >> 12) & 0x3;
    let i = ((i << 11) & 0xffff_ffff) as i32;
    i as u64
}

/// `%expand_16`（14 ビット符号付き変位。bit0=符号、bits1-13=大きさ。
/// bits14-15 は sp 桁。PSW.W=0 の hppa32 では s 桁は無視）。
fn expand_16(v: u64) -> u64 {
    let i = ((-((v & 1) as i64)) as u64) << 13 | ((v >> 1) & 0x1fff);
    (i & 0x3fff) as u16 as i16 as i64 as u64
}

/// `%im5_16`/`%im5_0`：符号がフィールド bit0 の 5 ビット即値。
fn im5(v: u64) -> u64 {
    ((-((v & 1) as i64)) as u64) << 4 | ((v >> 1) & 0xf)
}

/// `%lowsign_11`（addi/subi の 11 ビット即値。bit0=符号）。
fn lowsign_11(v: u64) -> u64 {
    ((-((v & 1) as i64)) as u64) << 10 | ((v >> 1) & 0x3ff)
}

/// 分岐変位 12 ビット（`%assemble_12`）。ops の packed 値は
/// bit0=符号、bit1=w（insn bit2）、bits2-11=w1（insn bits3-12）。
fn disp12(packed: u64) -> u64 {
    let mut i = ((packed >> 1) & 1) << 10 | ((packed >> 2) & 0x3ff);
    if packed & 1 != 0 {
        i |= !0u64 << 11;
    }
    i.wrapping_shl(2)
}

/// 分岐変位 17 ビット（`%assemble_17`）。`w5` は ops の別桁
/// （insn bits16-20）。packed は disp12 と同じ並び。
fn disp17(w5: u64, packed: u64) -> u64 {
    let mut i = (w5 & 0x1f) << 11 | ((packed >> 1) & 1) << 10 | ((packed >> 2) & 0x3ff);
    if packed & 1 != 0 {
        i |= !0u64 << 16;
    }
    i.wrapping_shl(2)
}

/// `bl.long` の 22 ビット変位（`%assemble_22`）。`w10` は ops[0]
/// （insn bits16-25）。
fn disp22(w10: u64, packed: u64) -> u64 {
    let mut i = (w10 & 0x3ff) << 11 | ((packed >> 1) & 1) << 10 | ((packed >> 2) & 0x3ff);
    if packed & 1 != 0 {
        i |= !0u64 << 21;
    }
    i.wrapping_shl(2)
}

/// `@ldstim12m` の変位（`%assemble_12a`＋`expand_12a`）。
/// PSW.W=0 では s 桁（val bits12-13）は無視。
fn expand_12a(word: u64) -> u64 {
    let im11a = (word >> 4) & 0x7ff;
    ((-((word & 1) as i64)) as u64) << 13 | im11a << 2
}

/// `%ma_to_m`：m(bit5)<<1|a(bit13) の 2 ビットから modify 値。
/// 0/1→0、2→+1（事後: EA=base, base+=ofs）、3→-1（事前: EA=ofs,
/// base+=ofs）。
fn ma_to_m(ma: u64) -> i64 {
    if ma & 2 != 0 {
        if ma & 1 != 0 { -1 } else { 1 }
    } else {
        0
    }
}

/// `%neg_to_m`：ディスプレースメントの符号で pre/post を決める
/// （ldwm/stwm。1→-1 事前、0→+1 事後）。
fn neg_to_m(v: u64) -> i64 {
    if v != 0 { -1 } else { 1 }
}

/// `%pos_to_m`（ldwm2/stwm2。1→+1 事後、0→-1 事前）。
fn pos_to_m(v: u64) -> i64 {
    if v != 0 { 1 } else { -1 }
}

// ----------------------------------------------------------------
// V<u64> の定数・演算ヘルパ
// ----------------------------------------------------------------

fn k<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

fn and_n<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let c = k(b, n);
    b.and(x, c)
}

fn or_n<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let c = k(b, n);
    b.or(x, c)
}

fn add_n<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let c = k(b, n);
    b.add(x, c)
}

fn shl_n<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let c = k(b, n);
    b.shl(x, c)
}

fn shr_n<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let c = k(b, n);
    b.shr_l(x, c)
}

fn sra_n<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let c = k(b, n);
    b.shr_a(x, c)
}

fn sext_bits<B: Backend>(b: &mut B, x: B::V<W64>, bits: u64) -> B::V<W64> {
    let t = shl_n(b, x, 64 - bits);
    sra_n(b, t, 64 - bits)
}

/// `B::B` の否定。`select(c,0,1)` を作って比較する。
fn bnot<B: Backend>(b: &mut B, c: B::B) -> B::B {
    let zero = k(b, 0);
    let one = k(b, 1);
    let v = b.select::<W64>(c, zero, one);
    b.cmp(Cmp::Ne, v, zero)
}

/// `B::B` を V<u64> の 0/1 にする。
fn bval<B: Backend>(b: &mut B, c: B::B) -> B::V<W64> {
    let zero = k(b, 0);
    let one = k(b, 1);
    b.select::<W64>(c, one, zero)
}

/// 32 ビット（d=false）か 64 ビットかで「ゼロか」を評価する。
/// 32 ビット条件は結果の下位 32 ビットだけを見る。
fn is_zero<B: Backend>(b: &mut B, x: B::V<W64>, d: bool) -> B::B {
    let zero = k(b, 0);
    if d {
        b.cmp(Cmp::Eq, x, zero)
    } else {
        let lo = and_n(b, x, 0xffff_ffff);
        b.cmp(Cmp::Eq, lo, zero)
    }
}

/// 「負か」（符号ビット）。32 ビット条件は bit31、64 ビットは bit63。
fn is_neg<B: Backend>(b: &mut B, x: B::V<W64>, d: bool) -> B::B {
    let zero = k(b, 0);
    if d {
        b.cmp(Cmp::LtS, x, zero)
    } else {
        let s = and_n(b, x, 0x8000_0000);
        b.cmp(Cmp::Ne, s, zero)
    }
}

/// PSW.N（無効化フラグ）を書く。`v` は 0/1 の V。
fn set_psw_n<B: Backend>(b: &mut B, v: B::V<W64>) {
    let p = b.get(psw_ref());
    let p = and_n(b, p, !PSW_N);
    let n = shl_n(b, v, 5);
    let p = b.or(p, n);
    b.set(psw_ref(), p);
}

/// PSW.N を定数で書く。
fn set_psw_n_const<B: Backend>(b: &mut B, n: bool) {
    let p = b.get(psw_ref());
    let p = if n {
        or_n(b, p, PSW_N)
    } else {
        and_n(b, p, !PSW_N)
    };
    b.set(psw_ref(), p);
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
// PA 条件コード。QEMU の do_cond / do_sub_cond / do_log_cond /
// do_sed_cond / do_unit_zero_cond に対応。
// Ref: SRC-QEMU translate.c, SPEC-PARISC-11 §5.3 Table 5-1.
// ----------------------------------------------------------------

/// 算術・論理共通の条件（do_cond）。`cf` は 4 ビットの cf 桁
/// （cf>>1 が基底条件、cf&1 が反転）。`uv` は符号なし
/// オーバーフロー（0/1 の値）、`sv` は do_*_sv の値（符号ビット
/// を見る）。使わない側は 0 を渡す。
fn arith_cond<B: Backend>(
    b: &mut B,
    cf: u64,
    d: bool,
    res: B::V<W64>,
    uv: B::V<W64>,
    sv: B::V<W64>,
) -> B::B {
    let zero = k(b, 0);
    let c = match cf >> 1 {
        // never
        0 => return false_cond(b),
        // = / <>
        1 => is_zero(b, res, d),
        // < / >=  ((N^V)：res^sv の符号）
        2 => {
            let t = b.xor(res, sv);
            is_neg(b, t, d)
        }
        // <= / >  ((N^V)|Z)
        3 => {
            let t = b.xor(res, sv);
            let s = is_neg(b, t, d);
            let tmp = b.select::<W64>(s, zero, res);
            is_zero(b, tmp, d)
        }
        // NUV / UV（carry が立たない / 立つ）
        4 => b.cmp(Cmp::Eq, uv, zero),
        // ZNV / VNZ（!UV | Z / UV & !Z）
        5 => {
            let z = b.cmp(Cmp::Eq, uv, zero);
            let tmp = b.select::<W64>(z, zero, res);
            is_zero(b, tmp, d)
        }
        // SV / NSV
        6 => is_neg(b, sv, d),
        // OD / EV
        _ => {
            let t = and_n(b, res, 1);
            b.cmp(Cmp::Ne, t, zero)
        }
    };
    if cf & 1 != 0 { bnot(b, c) } else { c }
}

/// 偽の条件（TCG_COND_NEVER 相当）。
fn false_cond<B: Backend>(b: &mut B) -> B::B {
    let zero = k(b, 0);
    let one = k(b, 1);
    b.cmp(Cmp::Eq, one, zero)
}

/// 引き算の条件（do_sub_cond）。case1-5 は in1/in2 の直接比較、
/// それ以外は do_cond に回す。`res` = in1-in2。
fn sub_cond<B: Backend>(
    b: &mut B,
    cf: u64,
    d: bool,
    res: B::V<W64>,
    in1: B::V<W64>,
    in2: B::V<W64>,
    sv: B::V<W64>,
) -> B::B {
    // 32 ビット条件は下位 32 ビットで比較する。
    let (i1, i2) = if d {
        (in1, in2)
    } else {
        (and_n(b, in1, 0xffff_ffff), and_n(b, in2, 0xffff_ffff))
    };
    let (op, _) = match cf >> 1 {
        1 => (Cmp::Eq, true),  // = / <>
        2 => (Cmp::LtS, true), // < / >=
        3 => (Cmp::LeS, true), // <= / >
        4 => (Cmp::LtU, true), // << / >>=  （NUV 系は符号なし比較）
        5 => (Cmp::LeU, true), // <<= / >>
        _ => {
            // 0/6/7 は do_cond（sv を使う場合がある）。
            let zero = k(b, 0);
            return arith_cond(b, cf, d, res, zero, sv);
        }
    };
    let c = b.cmp(op, i1, i2);
    if cf & 1 != 0 { bnot(b, c) } else { c }
}

/// 論理命令の条件（do_log_cond）。undefined の case4-6 は
/// never/tr として扱う（QEMU と同じ）。
fn log_cond<B: Backend>(b: &mut B, cf: u64, d: bool, res: B::V<W64>) -> B::B {
    let c = match cf >> 1 {
        0 | 4 | 5 | 6 => {
            return if cf & 1 != 0 {
                true_cond(b)
            } else {
                false_cond(b)
            };
        }
        1 => is_zero(b, res, d),
        2 => is_neg(b, res, d),
        3 => {
            let zero = k(b, 0);
            if d {
                b.cmp(Cmp::LeS, res, zero)
            } else {
                let s = sext_bits(b, res, 32);
                b.cmp(Cmp::LeS, s, zero)
            }
        }
        _ => {
            let zero = k(b, 0);
            let t = and_n(b, res, 1);
            b.cmp(Cmp::Ne, t, zero)
        }
    };
    if cf & 1 != 0 { bnot(b, c) } else { c }
}

/// 真の条件。
fn true_cond<B: Backend>(b: &mut B) -> B::B {
    let zero = k(b, 0);
    b.cmp(Cmp::Eq, zero, zero)
}

/// シフト・dep/extr・movb 系の 3 ビット圧縮条件（do_sed_cond）。
fn sed_cond<B: Backend>(b: &mut B, orig: u64, d: bool, res: B::V<W64>) -> B::B {
    let mut c = orig & 3;
    if c == 3 {
        c = 7;
    }
    let f = (orig >> 2) & 1;
    log_cond(b, c * 2 + f, d, res)
}

/// uxor 等のユニット条件（do_unit_zero_cond）。d=false では
/// case1 は未定義。
fn unit_zero_cond<B: Backend>(b: &mut B, cf: u64, d: bool, res: B::V<W64>) -> B::B {
    let d_repl: u64 = if d { 0x0000_0001_0000_0001 } else { 1 };
    let (ones, sgns) = match cf >> 1 {
        1 => {
            // SBW/NBW：16 ビット語境界。32 ビットでは未定義。
            if d { (d_repl, d_repl << 31) } else { (0, 0) }
        }
        // SBZ/NBZ：8 ビット。
        2 => {
            let ones = d_repl.wrapping_mul(0x0101_0101);
            (ones, ones << 7)
        }
        // SHZ/NHZ：16 ビット。
        3 => {
            let ones = d_repl.wrapping_mul(0x0001_0001);
            (ones, ones << 15)
        }
        _ => (0, 0),
    };
    if ones == 0 {
        return if cf & 1 != 0 {
            true_cond(b)
        } else {
            false_cond(b)
        };
    }
    let o = k(b, ones);
    let g = k(b, sgns);
    let t = b.sub(res, o);
    let not_res = b.not(res);
    let t = b.and(t, not_res);
    let t = b.and(t, g);
    let zero = k(b, 0);
    if cf & 1 != 0 {
        b.cmp(Cmp::Eq, t, zero)
    } else {
        b.cmp(Cmp::Ne, t, zero)
    }
}

// ----------------------------------------------------------------
// add/sub のオーバーフロー・キャリ
// Ref: SRC-QEMU do_add_sv/do_add_uv/do_sub_sv/get_carry.
// ----------------------------------------------------------------

/// `add` の符号付きオーバーフロー。`in1` はシフト済み。
fn add_sv<B: Backend>(
    b: &mut B,
    res: B::V<W64>,
    in1: B::V<W64>,
    in2: B::V<W64>,
    orig_in1: B::V<W64>,
    shift: u64,
    d: bool,
) -> B::V<W64> {
    let mut sv = b.xor(res, in1);
    let t = b.xor(in1, in2);
    let t = b.not(t);
    sv = b.and(sv, t);
    match shift {
        0 => {}
        1 => {
            let t2 = b.add(orig_in1, orig_in1);
            let t2 = b.xor(t2, orig_in1);
            sv = b.or(sv, t2);
        }
        _ => {
            let sign_bit = if d { 63 } else { 31 };
            let s = sra_n(b, orig_in1, sign_bit);
            let t2 = b.xor(s, orig_in1);
            let t2 = shr_n(b, t2, sign_bit - shift);
            let t2 = and_n(b, t2, (1u64 << shift) - 1);
            let zero2 = k(b, 0);
            let nz = b.cmp(Cmp::Ne, t2, zero2);
            let all = k(b, !0);
            sv = b.select::<W64>(nz, all, sv);
        }
    }
    sv
}

/// `add` の符号なしオーバーフロー（キャリアウト 0/1）。
/// `carry` はシフト済み加算の d 幅キャリ（0/1）。
fn add_uv<B: Backend>(
    b: &mut B,
    carry: B::V<W64>,
    orig_in1: B::V<W64>,
    shift: u64,
    d: bool,
) -> B::V<W64> {
    if shift == 0 {
        carry
    } else {
        let sign_bit = if d { 63 } else { 31 };
        let t = shr_n(b, orig_in1, sign_bit - shift);
        let t = and_n(b, t, (1u64 << shift) - 1);
        b.or(t, carry)
    }
}

/// `sub` の符号付きオーバーフロー。
fn sub_sv<B: Backend>(b: &mut B, res: B::V<W64>, in1: B::V<W64>, in2: B::V<W64>) -> B::V<W64> {
    let sv = b.xor(res, in1);
    let t = b.xor(in1, in2);
    b.and(sv, t)
}

/// 64 ビット加算のキャリアウト（0/1）。dest = in1+in2+cin のあと
/// で呼ぶ（cin 込みの carry は呼び出し側が織り込む）。
fn carry64_of<B: Backend>(b: &mut B, res: B::V<W64>, in1: B::V<W64>) -> B::V<W64> {
    // res <u in1 なら繰り上がり。
    let c = b.cmp(Cmp::LtU, res, in1);
    bval(b, c)
}

/// 32 ビット加算のキャリアウト（0/1）。
fn carry32_of<B: Backend>(b: &mut B, in1: B::V<W64>, in2: B::V<W64>, cin: u64) -> B::V<W64> {
    let a = and_n(b, in1, 0xffff_ffff);
    let c = and_n(b, in2, 0xffff_ffff);
    let s = b.add(a, c);
    let s = add_n(b, s, cin);
    shr_n(b, s, 32)
}

/// `sub`（borrow なし＝キャリあり）の 32/64 ビット carry（0/1）。
/// dest = in1 - in2 で、in1 >= in2（幅内）なら 1。
fn sub_carry<B: Backend>(b: &mut B, in1: B::V<W64>, in2: B::V<W64>, d: bool) -> B::V<W64> {
    if d {
        let c = b.cmp(Cmp::GeU, in1, in2);
        bval(b, c)
    } else {
        let i1 = and_n(b, in1, 0xffff_ffff);
        let i2 = and_n(b, in2, 0xffff_ffff);
        let c = b.cmp(Cmp::GeU, i1, i2);
        bval(b, c)
    }
}

/// psw の内部キャリ（bit40=32 ビット、bit41=64 ビット）を保存する。
fn save_carry<B: Backend>(b: &mut B, c32: B::V<W64>, c64: B::V<W64>) {
    let p = b.get(psw_ref());
    let p = and_n(b, p, !(PSW_CARRY32 | PSW_CARRY64));
    let lo = shl_n(b, c32, 40);
    let p = b.or(p, lo);
    let hi = shl_n(b, c64, 41);
    let p = b.or(p, hi);
    b.set(psw_ref(), p);
}

/// `add,c`/`sub,b` の carry-in（0/1 の V）。
fn psw_carry<B: Backend>(b: &mut B, d: bool) -> B::V<W64> {
    let p = b.get(psw_ref());
    let bit = if d { PSW_CARRY64 } else { PSW_CARRY32 };
    let m = k(b, bit);
    let t = b.and(p, m);
    let zero = k(b, 0);
    let nz = b.cmp(Cmp::Ne, t, zero);
    bval(b, nz)
}

// ----------------------------------------------------------------
// 算術・論理命令の共通処理
// ----------------------------------------------------------------

/// QEMU `do_add`。dest = (in1 << shift) + in2 (+carry)。
/// `is_c` は `add,c`（psw キャリを足し込む）。
#[allow(clippy::too_many_arguments)]
fn do_add<B: Backend>(
    b: &mut B,
    rt: u64,
    orig_in1: B::V<W64>,
    in2: B::V<W64>,
    shift: u64,
    is_l: bool,
    is_tsv: bool,
    is_tc: bool,
    is_c: bool,
    cf: u64,
    d: bool,
) -> Result<(), B::Exit> {
    let in1 = if shift != 0 {
        let s = k(b, shift);
        b.shl(orig_in1, s)
    } else {
        orig_in1
    };
    let cin = if is_c { psw_carry(b, d) } else { k(b, 0) };
    let mut dest = b.add(in1, in2);
    if is_c {
        dest = b.add(dest, cin);
    }
    let c = cf >> 1;
    let need_sv = is_tsv || c == 2 || c == 3 || c == 6;
    let zero = k(b, 0);
    let mut sv = zero;
    if need_sv {
        sv = add_sv(b, dest, in1, in2, orig_in1, shift, d);
    }
    let uv = if c == 4 || c == 5 {
        // 幅内のキャリアウト。
        let carry = if d {
            // 64 ビット: dest <u in1 なら繰り上がり（cin の影響は
            // 近似として無視。QEMU は cb ベクトルから取る）。
            carry64_of(b, dest, in1)
        } else {
            carry32_of(b, in1, in2, 0)
        };
        add_uv(b, carry, orig_in1, shift, d)
    } else {
        zero
    };
    let cond = arith_cond(b, cf, d, dest, uv, sv);
    // 書き戻し（trap は insn 終端で発生するので先に行う）。
    if !is_l {
        // cb の保存（内部ビットへの簡約）。
        let c32 = carry32_of(b, in1, in2, 0);
        let c64 = carry64_of(b, dest, in1);
        save_carry(b, c32, c64);
    }
    Gr(rt as u8).set(b, dest);
    if is_tsv {
        // オーバーフローでトラップ。
        let over = is_neg(b, sv, d);
        b.if_then(over, |b| {
            Err(raise::<B>(b, ExceptionKind::Trap, TRAP_OVERFLOW))
        })?;
    }
    if is_tc {
        // 条件成立でトラップ。
        b.if_then(cond, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_COND)))?;
    } else if cf != 0 {
        // 条件完語は次命令を無効化する（PSW.N ← cond）。
        let condv = bval(b, cond);
        set_psw_n(b, condv);
    }
    Ok(())
}

/// QEMU `do_sub`。dest = in1 - in2（is_b なら -1+!borrow）。
#[allow(clippy::too_many_arguments)]
fn do_sub<B: Backend>(
    b: &mut B,
    rt: u64,
    in1: B::V<W64>,
    in2: B::V<W64>,
    is_tsv: bool,
    is_b: bool,
    is_tc: bool,
    cf: u64,
    d: bool,
) -> Result<(), B::Exit> {
    let cin = if is_b { psw_carry(b, d) } else { k(b, 0) };
    // in1 + ~in2 + (is_b ? cin : 1) = in1 - in2 - (is_b && !cin)
    let not2 = b.not(in2);
    let mut dest = b.add(in1, not2);
    dest = if is_b {
        b.add(dest, cin)
    } else {
        add_n(b, dest, 1)
    };
    let c = cf >> 1;
    let need_sv = is_tsv || c == 2 || c == 3 || c == 6;
    let sv = if need_sv {
        sub_sv(b, dest, in1, in2)
    } else {
        k(b, 0)
    };
    let cond = if is_b {
        // is_b: dest = in1 + ~in2 + cin → ボローは ~in2+cin への
        // 加算で見る。cin=1 は「キャリあり」=借りなし。
        let t = b.add(not2, cin);
        let uv = sub_carry(b, in1, t, d);
        arith_cond(b, cf, d, dest, uv, sv)
    } else {
        sub_cond(b, cf, d, dest, in1, in2, sv)
    };
    // cb の保存。
    let c32 = {
        // 32 ビットのキャリ（借りなし）。
        let i1 = and_n(b, in1, 0xffff_ffff);
        let i2 = and_n(b, in2, 0xffff_ffff);
        let t = b.cmp(Cmp::GeU, i1, i2);
        bval(b, t)
    };
    let c64 = sub_carry(b, in1, in2, true);
    save_carry(b, c32, c64);
    Gr(rt as u8).set(b, dest);
    if is_tsv {
        let over = is_neg(b, sv, d);
        b.if_then(over, |b| {
            Err(raise::<B>(b, ExceptionKind::Trap, TRAP_OVERFLOW))
        })?;
    }
    if is_tc {
        b.if_then(cond, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_COND)))?;
    } else if cf != 0 {
        let condv = bval(b, cond);
        set_psw_n(b, condv);
    }
    Ok(())
}

/// QEMU `do_cmpclr`：比較結果を条件に使い、rt は必ず 0 にする。
fn do_cmpclr<B: Backend>(
    b: &mut B,
    rt: u64,
    in1: B::V<W64>,
    in2: B::V<W64>,
    cf: u64,
    d: bool,
) -> Result<(), B::Exit> {
    let dest = b.sub(in1, in2);
    let sv = {
        let need = matches!(cf >> 1, 2 | 3 | 6);
        if need {
            sub_sv(b, dest, in1, in2)
        } else {
            k(b, 0)
        }
    };
    let cond = sub_cond(b, cf, d, dest, in1, in2, sv);
    let zero = k(b, 0);
    Gr(rt as u8).set(b, zero);
    if cf != 0 {
        let condv = bval(b, cond);
        set_psw_n(b, condv);
    }
    Ok(())
}

// ----------------------------------------------------------------
// 分岐。意味論は `b.jump`/`b.branch` で Ctrl を立てるだけで、
// キュー（iaoq_f/iaoq_b）の遷移と PSW.B は実行ループ側が行う。
// リンク値は iaoq_f+8（遅延スロットの次）。priv(=3) が下位 2 ビットに
// 乗っているのは iaoq 値全体の規約。
// ----------------------------------------------------------------

/// 直接分岐（do_dbranch）：target = iaoq_f + 8 + disp。
fn dbranch<B: Backend>(b: &mut B, pc: u64, disp: u64, link: u64, n: u64) {
    if link != 0 {
        let v = k(b, pc.wrapping_add(8));
        Gr(link as u8).set(b, v);
    }
    if n != 0 {
        set_psw_n_const(b, true);
    }
    let t = k(b, pc.wrapping_add(8).wrapping_add(disp));
    b.jump(t);
}

/// 間接分岐（do_ibranch）：target を V で受ける。priv は低 2 ビットを
/// `|3` して維持する（ユーザモード = do_ibranch_priv の case 3）。
fn ibranch<B: Backend>(b: &mut B, target: B::V<W64>, link: u64, n: u64, pc: u64) {
    if link != 0 {
        let v = k(b, pc.wrapping_add(8));
        Gr(link as u8).set(b, v);
    }
    if n != 0 {
        set_psw_n_const(b, true);
    }
    let t = or_n(b, target, 3);
    b.jump(t);
}

/// 条件分岐（do_cbranch）。`cond` 成立で taken。
/// `,n` の無効化は方向で変わる: taken で disp>=0、not-taken で
/// disp<0 のときだけ PSW.N を立てる。
fn cbranch<B: Backend>(b: &mut B, cond: B::B, pc: u64, disp: u64, n: u64) {
    let target = pc.wrapping_add(8).wrapping_add(disp);
    if n != 0 {
        let fwd = k(b, if (disp as i64) >= 0 { 1 } else { 0 });
        let back = k(b, if (disp as i64) < 0 { 1 } else { 0 });
        let nv = b.select::<W64>(cond, fwd, back);
        set_psw_n(b, nv);
    }
    b.branch(cond, target);
}

// ----------------------------------------------------------------
// ロード・ストアの共通処理（form_gva + do_load_32 等）
// ----------------------------------------------------------------

/// EA 計算＋ベース更新。`m`: 0=なし、+1=事後（EA=base）、-1=事前
/// （EA=base+ofs）。返り値は (EA, 新 base)。
fn gva<B: Backend>(b: &mut B, rb: u64, rx: B::V<W64>, disp: u64, m: i64) -> (B::V<W64>, B::V<W64>) {
    let base = Gr(rb as u8).get(b);
    let ofs = b.add(base, rx);
    let ofs = add_n(b, ofs, disp);
    let ea = if m <= 0 { ofs } else { base };
    (ea, ofs)
}

/// オフセット形式のロード（disp16 + m）。`size`: 0/1/2/3。
fn load_off<B: Backend>(
    b: &mut B,
    t: u64,
    rb: u64,
    disp: u64,
    m: i64,
    size: u64,
) -> Result<(), B::Exit> {
    let zero = k(b, 0);
    let (ea, new_base) = gva(b, rb, zero, disp, m);
    match size {
        0 => {
            let v: B::V<W8> = b.load(ea, DATA_READ)?;
            let v = b.zext::<W8, W64>(v);
            Gr(t as u8).set(b, v);
        }
        1 => {
            let v: B::V<W16> = b.load(ea, DATA_READ)?;
            let v = b.zext::<W16, W64>(v);
            Gr(t as u8).set(b, v);
        }
        2 => {
            let v: B::V<W32> = b.load(ea, DATA_READ)?;
            let v = b.zext::<W32, W64>(v);
            Gr(t as u8).set(b, v);
        }
        _ => {
            let v: B::V<W64> = b.load(ea, DATA_READ)?;
            Gr(t as u8).set(b, v);
        }
    }
    if m != 0 {
        Gr(rb as u8).set(b, new_base);
    }
    Ok(())
}

/// オフセット形式のストア。
fn store_off<B: Backend>(
    b: &mut B,
    r: u64,
    rb: u64,
    disp: u64,
    m: i64,
    size: u64,
) -> Result<(), B::Exit> {
    let zero = k(b, 0);
    let (ea, new_base) = gva(b, rb, zero, disp, m);
    let v = Gr(r as u8).get(b);
    match size {
        0 => {
            let t = b.trunc::<W64, W8>(v);
            b.store(ea, t, DATA_WRITE)?;
        }
        1 => {
            let t = b.trunc::<W64, W16>(v);
            b.store(ea, t, DATA_WRITE)?;
        }
        2 => {
            let t = b.trunc::<W64, W32>(v);
            b.store(ea, t, DATA_WRITE)?;
        }
        _ => b.store(ea, v, DATA_WRITE)?,
    }
    if m != 0 {
        Gr(rb as u8).set(b, new_base);
    }
    Ok(())
}

// ----------------------------------------------------------------
// エントリ
// ----------------------------------------------------------------

/// 命令 1 個の実行。`Ok(true)` = 実行した、`Ok(false)` = 未実装。
/// 呼び出し側は `pc` に `iaoq_f`（priv ビット込み）を渡す。
#[allow(clippy::too_many_lines)]
pub fn exec<B: Backend>(b: &mut B, insn: Insn, word: u32, pc: u64) -> Result<bool, B::Exit> {
    let ops = extract_ops(insn, u128::from(word));
    match insn {
        // ---- 即値 ----
        Insn::Ldil => {
            let v = k(b, assemble_21(ops[1]));
            Gr(ops[0] as u8).set(b, v);
        }
        Insn::Addil => {
            // addil i,r → r1 = gr[r] + i21。
            let src = Gr(ops[0] as u8).get(b);
            let im = k(b, assemble_21(ops[1]));
            let v = b.add(src, im);
            Gr(1).set(b, v);
        }
        Insn::Ldo => {
            let rb = ops[0];
            let i = expand_16(ops[2]);
            let v = if rb == 0 {
                k(b, i)
            } else {
                let src = Gr(rb as u8).get(b);
                let im = k(b, i);
                b.add(src, im)
            };
            Gr(ops[1] as u8).set(b, v);
        }
        // ---- FRRICD 即値算術 ----
        Insn::Addi | Insn::AddiTsv | Insn::AddiTc | Insn::AddiTcTsv => {
            let is_tsv = matches!(insn, Insn::AddiTsv | Insn::AddiTcTsv);
            let is_tc = matches!(insn, Insn::AddiTc | Insn::AddiTcTsv);
            if is_tc && ops[2] == 1 {
                // 無条件トラップ。
                return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_COND));
            }
            let im = k(b, lowsign_11(ops[3]));
            let r = Gr(ops[0] as u8).get(b);
            do_add(
                b, ops[1], im, r, 0, false, is_tsv, is_tc, false, ops[2], false,
            )?;
        }
        Insn::Subi | Insn::SubiTsv => {
            let im = k(b, lowsign_11(ops[3]));
            let r = Gr(ops[0] as u8).get(b);
            do_sub(
                b,
                ops[1],
                im,
                r,
                insn == Insn::SubiTsv,
                false,
                false,
                ops[2],
                false,
            )?;
        }
        Insn::Cmpiclr => {
            let im = k(b, lowsign_11(ops[4]));
            let r = Gr(ops[0] as u8).get(b);
            do_cmpclr(b, ops[1], im, r, ops[2], ops[3] != 0)?;
        }
        // ---- FRRICD 論理・補助 ----
        Insn::Andcm | Insn::And | Insn::Or | Insn::Xor | Insn::Uxor => {
            let r1 = Gr(ops[0] as u8).get(b);
            let r2 = Gr(ops[1] as u8).get(b);
            let (cf, d, t) = (ops[2], ops[3] != 0, ops[4]);
            let dest = match insn {
                Insn::Andcm => {
                    let n = b.not(r2);
                    b.and(r1, n)
                }
                Insn::And => b.and(r1, r2),
                Insn::Or => b.or(r1, r2),
                _ => b.xor(r1, r2),
            };
            Gr(t as u8).set(b, dest);
            if cf != 0 {
                let cond = if insn == Insn::Uxor {
                    unit_zero_cond(b, cf, d, dest)
                } else {
                    log_cond(b, cf, d, dest)
                };
                let condv = bval(b, cond);
                set_psw_n(b, condv);
            }
        }
        Insn::Cmpclr => {
            let r1 = Gr(ops[0] as u8).get(b);
            let r2 = Gr(ops[1] as u8).get(b);
            do_cmpclr(b, ops[4], r1, r2, ops[2], ops[3] != 0)?;
        }
        Insn::Uaddcm | Insn::UaddcmTc => {
            let r1 = Gr(ops[0] as u8).get(b);
            let r2 = Gr(ops[1] as u8).get(b);
            let (cf, d, t) = (ops[2], ops[3] != 0, ops[4]);
            if cf == 0 {
                // t = r1 + ~r2 = r1 - r2 - 1（r1==0 は ~r2）。
                let v = if ops[0] == 0 {
                    b.not(r2)
                } else {
                    let v = b.sub(r1, r2);
                    add_n(b, v, !0)
                };
                Gr(t as u8).set(b, v);
            } else {
                let n2 = b.not(r2);
                do_add(
                    b,
                    t,
                    r1,
                    n2,
                    0,
                    false,
                    false,
                    insn == Insn::UaddcmTc,
                    false,
                    cf,
                    d,
                )?;
            }
        }
        // ---- FRRICD sub ----
        Insn::Sub | Insn::SubTsv | Insn::SubTc | Insn::SubTsvTc => {
            let r1 = Gr(ops[0] as u8).get(b);
            let r2 = Gr(ops[1] as u8).get(b);
            do_sub(
                b,
                ops[4],
                r1,
                r2,
                insn == Insn::SubTsv || insn == Insn::SubTsvTc,
                false,
                insn == Insn::SubTc || insn == Insn::SubTsvTc,
                ops[2],
                ops[3] != 0,
            )?;
        }
        // ---- FRRCCDS add（sh 付き）----
        Insn::Add | Insn::AddL | Insn::AddTsv | Insn::AddC | Insn::AddCTsv => {
            let r1 = Gr(ops[0] as u8).get(b);
            let r2 = Gr(ops[1] as u8).get(b);
            do_add(
                b,
                ops[5],
                r1,
                r2,
                ops[3],
                insn == Insn::AddL,
                insn == Insn::AddTsv || insn == Insn::AddCTsv,
                false,
                insn == Insn::AddC || insn == Insn::AddCTsv,
                ops[2],
                ops[4] != 0,
            )?;
        }
        Insn::SubB | Insn::SubBTsv => {
            let r1 = Gr(ops[0] as u8).get(b);
            let r2 = Gr(ops[1] as u8).get(b);
            do_sub(
                b,
                ops[5],
                r1,
                r2,
                insn == Insn::SubBTsv,
                true,
                false,
                ops[2],
                ops[4] != 0,
            )?;
        }
        // ---- 分岐 ----
        Insn::Be | Insn::Ble => {
            // be/ble disp(sr,b)：間接。be は l=0、ble は l=r31。
            let link = if insn == Insn::Ble { 31 } else { 0 };
            let disp = disp17(ops[1], ops[3]);
            let base = Gr(ops[0] as u8).get(b);
            let di = k(b, disp);
            let t = b.add(base, di);
            ibranch(b, t, link, ops[4], pc);
        }
        Insn::Bl | Insn::BlPush | Insn::Gate => {
            // bl/gate/bl,push：直接。l=0 ならリンクなし。
            // gate は PSW.B なら不正（遅延スロット内 gate）。
            if insn == Insn::Gate {
                let p = b.get(psw_ref());
                let t = and_n(b, p, PSW_B);
                let z = k(b, 0);
                let has = b.cmp(Cmp::Ne, t, z);
                b.if_then(has, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_ILL)))?;
            }
            dbranch(b, pc, disp17(ops[1], ops[2]), ops[0], ops[3]);
        }
        Insn::BlLong => {
            // bl.long disp → リンクは r2。
            dbranch(b, pc, disp22(ops[0], ops[1]), 2, ops[2]);
        }
        Insn::Blr | Insn::BlrH => {
            // blr x,l：x!=0 → target = iaoq_f+8 + (x<<3)。x==0 は
            // pc+8 への直接分岐（link は常に pc+8）。
            if ops[1] != 0 {
                let x = Gr(ops[1] as u8).get(b);
                let t = shl_n(b, x, 3);
                let t = add_n(b, t, pc.wrapping_add(8));
                // blr は priv 変更なし（|3 は base 由来で維持）。
                if ops[0] != 0 {
                    let v = k(b, pc.wrapping_add(8));
                    Gr(ops[0] as u8).set(b, v);
                }
                if ops[2] != 0 {
                    set_psw_n_const(b, true);
                }
                b.jump(t);
            } else {
                dbranch(b, pc, 0, ops[0], ops[2]);
            }
        }
        Insn::Bv => {
            // bv x(b)：target = gr[b] (+x<<3)。
            let t = if ops[1] != 0 {
                let x = Gr(ops[1] as u8).get(b);
                let s = shl_n(b, x, 3);
                let base = Gr(ops[0] as u8).get(b);
                b.add(s, base)
            } else {
                Gr(ops[0] as u8).get(b)
            };
            ibranch(b, t, 0, ops[2], pc);
        }
        Insn::Bve | Insn::BveL => {
            // bve (b)：target = gr[b]。BveL はリンク r2。
            let link = if insn == Insn::BveL { 2 } else { 0 };
            let t = Gr(ops[0] as u8).get(b);
            ibranch(b, t, link, ops[1], pc);
        }
        Insn::Nopbts | Insn::Nopbts2 => {}
        // ---- 条件分岐 ----
        Insn::Cmpb | Insn::CmpbF | Insn::CmpbD | Insn::CmpbDf => {
            // comb,c(,f) r1,r2,disp → dest = r1 - r2 で比較。
            let f = matches!(insn, Insn::CmpbF | Insn::CmpbDf) as u64;
            let d = matches!(insn, Insn::CmpbD | Insn::CmpbDf);
            let r1 = Gr(ops[0] as u8).get(b);
            let r2 = Gr(ops[1] as u8).get(b);
            let dest = b.sub(r1, r2);
            let c3 = ops[2];
            let sv = if matches!(c3, 2 | 3 | 6) {
                sub_sv(b, dest, r1, r2)
            } else {
                k(b, 0)
            };
            let cond = sub_cond(b, c3 * 2 + f, d, dest, r1, r2, sv);
            cbranch(b, cond, pc, disp12(ops[3]), ops[4]);
        }
        Insn::Cmpbi | Insn::CmpbiF | Insn::CmpbiD => {
            // comib,c i,r,disp → dest = imm - gr[r]。
            let f = matches!(insn, Insn::CmpbiF | Insn::CmpbiD) as u64;
            let d = insn == Insn::CmpbiD;
            let im = k(b, im5(ops[1]));
            let r = Gr(ops[0] as u8).get(b);
            let dest = b.sub(im, r);
            // CmpbiD の c は 2 ビットの %cmpbid_c（0→4=*<<）。
            let c3 = if insn == Insn::CmpbiD {
                if ops[3] == 0 { 4 } else { ops[3] }
            } else {
                ops[2]
            };
            let sv = if matches!(c3, 2 | 3 | 6) {
                sub_sv(b, dest, im, r)
            } else {
                k(b, 0)
            };
            let cond = sub_cond(b, c3 * 2 + f, d, dest, im, r, sv);
            let (disp, n) = if insn == Insn::CmpbiD {
                (disp12(ops[4]), ops[5])
            } else {
                (disp12(ops[3]), ops[4])
            };
            cbranch(b, cond, pc, disp, n);
        }
        Insn::Movb | Insn::Movbi => {
            // movb,c r1,r2,disp / movib,c i,r,disp。
            let (c3, disp, n) = (ops[2], disp12(ops[3]), ops[4]);
            if insn == Insn::Movb {
                let v = Gr(ops[0] as u8).get(b);
                Gr(ops[1] as u8).set(b, v);
                let cond = sed_cond(b, c3, false, v);
                cbranch(b, cond, pc, disp, n);
            } else {
                let v = k(b, im5(ops[1]));
                Gr(ops[0] as u8).set(b, v);
                let cond = sed_cond(b, c3, false, v);
                cbranch(b, cond, pc, disp, n);
            }
        }
        Insn::Addb | Insn::AddbF | Insn::Addbi | Insn::AddbiF => {
            // addb(,f),c r1,r2 / addib(,f),c i,r：加算して条件分岐。
            let f = matches!(insn, Insn::AddbF | Insn::AddbiF) as u64;
            let c3 = ops[2];
            let (dest, in1, in2, rt);
            if matches!(insn, Insn::Addb | Insn::AddbF) {
                in1 = Gr(ops[0] as u8).get(b);
                in2 = Gr(ops[1] as u8).get(b);
                rt = ops[1];
            } else {
                in1 = k(b, im5(ops[1]));
                in2 = Gr(ops[0] as u8).get(b);
                rt = ops[0];
            };
            dest = b.add(in1, in2);
            Gr(rt as u8).set(b, dest);
            let zero = k(b, 0);
            let (uv, sv);
            if matches!(c3, 4 | 5) {
                let c = carry32_of(b, in1, in2, 0);
                uv = add_uv(b, c, in1, 0, false);
            } else {
                uv = zero;
            }
            if matches!(c3, 2 | 3 | 6) {
                sv = add_sv(b, dest, in1, in2, in1, 0, false);
            } else {
                sv = zero;
            }
            let cond = arith_cond(b, c3 * 2 + f, false, dest, uv, sv);
            cbranch(b, cond, pc, disp12(ops[3]), ops[4]);
        }
        Insn::BbSar => {
            // bb,<c> r,%sar,disp：bit pos = SAR（d=0 で 32 幅）。
            let r = Gr(ops[0] as u8).get(b);
            let sar = Cr(11).get(b);
            let d = ops[2] != 0;
            let s = if d { sar } else { or_n(b, sar, 32) };
            let tmp = b.shl(r, s);
            let zero = k(b, 0);
            let cond = if ops[1] != 0 {
                b.cmp(Cmp::GeS, tmp, zero)
            } else {
                b.cmp(Cmp::LtS, tmp, zero)
            };
            cbranch(b, cond, pc, disp12(ops[3]), ops[4]);
        }
        Insn::BbImm => {
            // bb p,r：d=0 で pos = p|32 → test bit (63-pos) = 31-p。
            let p = ops[0] | if ops[3] != 0 { 0 } else { 32 };
            let r = Gr(ops[1] as u8).get(b);
            let mask = k(b, 1u64 << (63 - p));
            let t = b.and(r, mask);
            let zero = k(b, 0);
            let cond = if ops[2] != 0 {
                b.cmp(Cmp::Eq, t, zero)
            } else {
                b.cmp(Cmp::Ne, t, zero)
            };
            cbranch(b, cond, pc, disp12(ops[4]), ops[5]);
        }
        // ---- オフセット形式 load/store ----
        Insn::Ldb | Insn::Ldh | Insn::Ldw | Insn::Ldd => {
            let size = match insn {
                Insn::Ldb => 0,
                Insn::Ldh => 1,
                Insn::Ldd => 3,
                _ => 2,
            };
            load_off(b, ops[1], ops[0], expand_16(ops[2]), 0, size)?;
        }
        Insn::Ldwm => {
            load_off(
                b,
                ops[1],
                ops[0],
                expand_16(ops[2]),
                neg_to_m(ops[2] & 1),
                2,
            )?;
        }
        Insn::Ldwm2 => {
            load_off(
                b,
                ops[1],
                ops[0],
                expand_12a(u64::from(word)),
                pos_to_m(u64::from(word) & 1),
                2,
            )?;
        }
        Insn::Stb | Insn::Sth | Insn::Stw | Insn::Std => {
            let size = match insn {
                Insn::Stb => 0,
                Insn::Sth => 1,
                Insn::Std => 3,
                _ => 2,
            };
            store_off(b, ops[1], ops[0], expand_16(ops[2]), 0, size)?;
        }
        Insn::Stwm => {
            store_off(
                b,
                ops[1],
                ops[0],
                expand_16(ops[2]),
                neg_to_m(ops[2] & 1),
                2,
            )?;
        }
        Insn::Stwm2 => {
            store_off(
                b,
                ops[1],
                ops[0],
                expand_12a(u64::from(word)),
                pos_to_m(u64::from(word) & 1),
                2,
            )?;
        }
        // ---- im5 / index 形式 ----
        Insn::Ldi | Insn::Ldcw | Insn::Ldcd => {
            // ldi: ops = [b, im5f, sp, size, ma, t]。
            // ldcw/ldcd: ops = [b, im5f, sp, ma, t]。
            let (size, m, t) = if insn == Insn::Ldi {
                (ops[3], ma_to_m(ops[4]), ops[5])
            } else {
                // ldcw = 32 ビット、ldcd = 64 ビット。
                (
                    if insn == Insn::Ldcd { 3 } else { 2 },
                    ma_to_m(ops[3]),
                    ops[4],
                )
            };
            let disp = im5(ops[1]);
            let zero = k(b, 0);
            let (ea, new_base) = gva(b, ops[0], zero, disp, m);
            match size {
                0 => {
                    let v: B::V<W8> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W8, W64>(v);
                    Gr(t as u8).set(b, v);
                }
                1 => {
                    let v: B::V<W16> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W16, W64>(v);
                    Gr(t as u8).set(b, v);
                }
                2 => {
                    let v: B::V<W32> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W32, W64>(v);
                    Gr(t as u8).set(b, v);
                }
                _ => {
                    let v: B::V<W64> = b.load(ea, DATA_READ)?;
                    Gr(t as u8).set(b, v);
                }
            }
            if insn != Insn::Ldi {
                // ldcw/ldcd: 読んだあと 0 を書き戻す（アトミック近似）。
                match size {
                    3 => {
                        let z = k(b, 0);
                        b.store(ea, z, DATA_WRITE)?;
                    }
                    _ => {
                        let z = k(b, 0);
                        let z = b.trunc::<W64, W32>(z);
                        b.store(ea, z, DATA_WRITE)?;
                    }
                }
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::Ldx | Insn::Ldcwx | Insn::Ldcdx => {
            // ops = [b, x, sp, scale, m, t]。index 形式の m は
            // bit5 のみ（post-modify; QEMU も ,mb を区別しない）。
            // scale はオペランドサイズ倍のシフト。
            let size: u64 = match insn {
                Insn::Ldx => (u64::from(word) >> 6) & 3,
                Insn::Ldcdx => 3,
                _ => 2,
            };
            let x = Gr(ops[1] as u8).get(b);
            let x = if ops[3] != 0 { shl_n(b, x, size) } else { x };
            let m: i64 = if ops[4] != 0 { 1 } else { 0 };
            let (ea, new_base) = gva(b, ops[0], x, 0, m);
            let t = ops[5];
            match size {
                0 => {
                    let v: B::V<W8> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W8, W64>(v);
                    Gr(t as u8).set(b, v);
                }
                1 => {
                    let v: B::V<W16> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W16, W64>(v);
                    Gr(t as u8).set(b, v);
                }
                3 => {
                    let v: B::V<W64> = b.load(ea, DATA_READ)?;
                    Gr(t as u8).set(b, v);
                }
                _ => {
                    let v: B::V<W32> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W32, W64>(v);
                    Gr(t as u8).set(b, v);
                }
            }
            if insn != Insn::Ldx {
                // ldcwx/ldcdx: 読んだあと 0 を書き戻す（アトミック近似）。
                let z = k(b, 0);
                b.store(ea, z, DATA_WRITE)?;
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::Sti => {
            // ops = [b, r, sp, size, ma, i5]。
            let (size, m, r) = (ops[3], ma_to_m(ops[4]), ops[1]);
            let disp = im5(ops[5]);
            let zero = k(b, 0);
            let (ea, new_base) = gva(b, ops[0], zero, disp, m);
            let v = Gr(r as u8).get(b);
            match size {
                0 => {
                    let t = b.trunc::<W64, W8>(v);
                    b.store(ea, t, DATA_WRITE)?;
                }
                1 => {
                    let t = b.trunc::<W64, W16>(v);
                    b.store(ea, t, DATA_WRITE)?;
                }
                2 => {
                    let t = b.trunc::<W64, W32>(v);
                    b.store(ea, t, DATA_WRITE)?;
                }
                _ => b.store(ea, v, DATA_WRITE)?,
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::Staw => {
            // ops = [b, r, sp, ma, i5]。32 ビットの atomic store
            // （ordered）は単純ストアで近似する。
            let (m, r) = (ma_to_m(ops[3]), ops[1]);
            let disp = im5(ops[4]);
            let zero = k(b, 0);
            let (ea, new_base) = gva(b, ops[0], zero, disp, m);
            let v = Gr(r as u8).get(b);
            let v = b.trunc::<W64, W32>(v);
            b.store(ea, v, DATA_WRITE)?;
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        // ---- システム系（ユーザが使えるもの）----
        Insn::Sync | Insn::Fdc => {}
        Insn::Fdcx | Insn::Fdce | Insn::Fic | Insn::Fic4f | Insn::Fice | Insn::Pdc => {
            // nop_addrx：メモリ管理命令は nop。`,m` でベース更新だけ。
            if ops[3] != 0 {
                let a = Gr(ops[0] as u8).get(b);
                let c = Gr(ops[1] as u8).get(b);
                let v = b.add(a, c);
                Gr(ops[0] as u8).set(b, v);
            }
        }
        Insn::Ldsid => {
            // ユーザモードでは空間番号は 0（QEMU と同じ）。
            let z = k(b, 0);
            Gr(ops[2] as u8).set(b, z);
        }
        Insn::Mfia => {
            // mfia t → iaoq_f & ~3（priv ビットを除く命令番地）。
            let v = k(b, pc & !3);
            Gr(ops[0] as u8).set(b, v);
        }
        Insn::Mfsp => {
            // mfsp sr,t → sr[sp] >> 32。
            let v = Sr(ops[0] as u8).get(b);
            let v = shr_n(b, v, 32);
            Gr(ops[1] as u8).set(b, v);
        }
        Insn::Mtsp => {
            // mtsp r,sr → sr[i] = r << 32。
            let s = Gr(ops[0] as u8).get(b);
            let v = shl_n(b, s, 32);
            Sr(ops[1] as u8).set(b, v);
        }
        Insn::Mtsm => {
            let v = Gr(ops[0] as u8).get(b);
            Cr(11).set(b, v);
        }
        Insn::Mtsarcm => {
            let s = Gr(ops[0] as u8).get(b);
            let n = b.not(s);
            let v = and_n(b, n, 31);
            Cr(11).set(b, v);
        }
        Insn::Mfctl => {
            // ops = [ctl, e(,w), t]。SAR は ,w なしで下位 5 ビットに
            // マスク。cr1（interval timer）・26/27 は読める。
            let (ctl, e, t) = (ops[0], ops[1] != 0, ops[2]);
            match ctl {
                11 => {
                    let v = Cr(11).get(b);
                    let v = if e { v } else { and_n(b, v, 31) };
                    Gr(t as u8).set(b, v);
                }
                1 | 26 | 27 => {
                    let v = Cr(ctl as u8).get(b);
                    Gr(t as u8).set(b, v);
                }
                _ => return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_PRIV)),
            }
        }
        Insn::Mtctl => {
            // ops = [ctl, r]。SAR だけユーザから書ける。
            let (ctl, r) = (ops[0], ops[1]);
            if ctl == 11 {
                let s = Gr(r as u8).get(b);
                let v = and_n(b, s, 31);
                Cr(11).set(b, v);
            } else {
                return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_PRIV));
            }
        }
        // ---- 特権・未対応の命令は Trap へ ----
        Insn::Rsm
        | Insn::Ssm
        | Insn::Rfi
        | Insn::RfiR
        | Insn::Halt
        | Insn::Reset
        | Insn::Getshadowregs
        | Insn::IxtlbxD
        | Insn::Ixtlbxf
        | Insn::IxtlbxfH
        | Insn::IxtlbxI
        | Insn::Ixtlbt
        | Insn::Pxtlb
        | Insn::PxtlbS
        | Insn::PxtlbL
        | Insn::PxtlbLs
        | Insn::Pxtlbe
        | Insn::PxtlbeS
        | Insn::Lpa
        | Insn::Lci => {
            return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_PRIV));
        }
        // break/diag などその他は未実装。
        _ => return Ok(false),
    }
    Ok(true)
}
