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
//!   行う。これは Linux ABI の合意に基づく設計判断で、分岐遅延
//!   スロット中の `ldi %r20` が syscall 番号を置けるように
//!   するためである。
//!
//! - シフト・抽出・挿入: `shrp`（SHRPW/SHRPD = VSHD/SHD、SAR/
//!   即値、32/64 ビット）、`extr`（EXTR*/EXTRD、SAR/即値、
//!   符号拡張選択）、`dep`/`depi`（DEP/DEPI/ZDEP/ZDEPI と
//!   DEPD/DEPW/DEPDI、SAR/即値、併合・零置換選択）。位置は
//!   HP の左端起算記法を LSB シフト量に換算して評価する。
//!
//! - 十進補正・除算ステップ: `dcor`/`dcor,i`（PSW[C/B] の桁
//!   キャリに従う BCD 訂正。桁キャリ列は `cb` 状態に保持）と
//!   `ds`（非回復除算の 1 ビットステップ。PSW.V と語の桁
//!   キャリ C/B{8} を更新する）。
//!
//! 条件コードは 32 ビット（d=0）と 64 ビット（d=1）の両方を
//! 評価する。`hadd` 等の MAX や FP 演算は未実装
//! （`Ok(false)`）。
//!
//! 出典は SPEC-PARISC-11・SPEC-PARISC-20 の一次資料のみ。
//! 条件評価は SPEC-PARISC-11 §5 Table 5-3 〜 5-7 および
//! SPEC-PARISC-20 付録 D Table D-3 〜 D-15 に従う。
//! Ref: SPEC-PARISC-11, SPEC-PARISC-20.

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

/// FPR の 32 ビット半分の読み出し。`r64` は L/R 選択付きの
/// 6 ビット番号（bit5=0 → 左半分＝64 ビットレジスタの上位
/// 32 ビット、bit5=1 → 右半分＝下位 32 ビット）。
/// Ref: SPEC-PARISC-20 §8（Table 8-1。frnL/frnR の命名規則）.
///
/// FLDW/FSTW では 0R・1L/1R・2L/2R・3L/3R（r64 ∈
/// {1,2,3,32,33,34,35}）の指定が未定義操作（undefined op）
/// だが、本モデルは半レジスタへの決定的なアクセスとして
/// 評価する。また fr0L へのロードが起こす「先行 FP 命令の
/// 完了強制」は FP パイプラインをモデル化していないため
/// 恒等的に不要（Status レジスタの T ビットを立てる値の
/// ロードも未定義だが検査しない）。
// Gap: GAP-0053
fn fpr_get_w<B: Backend>(b: &mut B, r64: u64) -> B::V<W64> {
    let d = b.get(Fpr((r64 & 31) as u8).state());
    if r64 & 32 != 0 {
        and_n(b, d, 0xffff_ffff)
    } else {
        shr_n(b, d, 32)
    }
}

/// FPR の 32 ビット半分への書き込み（`fpr_get_w` と同じ規則）。
fn fpr_set_w<B: Backend>(b: &mut B, r64: u64, v: B::V<W64>) {
    let st = Fpr((r64 & 31) as u8).state();
    let old = b.get(st);
    let new = if r64 & 32 != 0 {
        let hi = and_n(b, old, 0xffff_ffff_0000_0000);
        let lo = and_n(b, v, 0xffff_ffff);
        b.or(hi, lo)
    } else {
        let lo = and_n(b, old, 0xffff_ffff);
        let hi = shl_n(b, v, 32);
        b.or(hi, lo)
    };
    b.set(st, new);
}

/// PSW の位置。ユーザモードに必要なビットのみを管理する独自
/// レイアウト（ssm/rsm の HW 番号とは別。N=bit5, B=bit3,
/// V=bit6, W=bit11）。桁キャリ列 PSW[C/B] は別途 `cb` 状態に
/// 持ち、`add,c`/`sub,b`/`ds` が参照する。
// Ref: SPEC-PARISC-11 §3 (PSW).
pub const PSW_B: u64 = 0x0000_0008;
pub const PSW_N: u64 = 0x0000_0020;
/// DS（非回復除算の 1 ステップ）が更新する除算訂正ビット。
/// 内部レイアウトでは psw bit6 に置く。
/// Ref: SPEC-PARISC-11 §3 (PSW), SPEC-PARISC-20 §7-5.
pub const PSW_V: u64 = 0x0000_0040;
pub const PSW_W: u64 = 0x0000_0800;

/// PSW の位置。
#[must_use]
pub fn psw_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, psw))
}

/// PSW[C/B] 桁キャリベクトル（`CpuState::cb`）の位置。
/// bit 4j は桁 j のキャリアウト（HP 記法の C/B{15-j}）。
#[must_use]
pub fn cb_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cb))
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
/// ゲートウェイ分岐（0x100 等）はアドレスそのものを code
/// として渡す（`run_parisc` 側）。
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

/// LDCW 系の不可分アクセス（SPEC-PARISC-11 §LDCW：ロードと
/// クリアは不可分）。バックエンドは AtomicRw のロード・ストア
/// 対を不可分として扱う。
const ATOMIC_RW: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::AtomicRw,
};

// ----------------------------------------------------------------
// 即値・変位の復元。生成デコーダは生のフィールドを渡すので、
// SPEC-PARISC-11 §5.2（アセンブリ関数）の並べ直しをここで行う。
// Ref: SPEC-PARISC-11 §5.2, SPEC-PARISC-20 付録E.
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
/// `-(s) << 13` で bit13 から上が符号で埋まるので、そのまま
/// 返せば 64 ビット符号拡張済みの値になる。
fn expand_16(v: u64) -> u64 {
    ((-((v & 1) as i64)) as u64) << 13 | ((v >> 1) & 0x1fff)
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

/// ldwm2/stwm2（Format 2、opcode 0x17/0x1f）の変位
/// （`assemble_16a`）。`im11a` は語の bits13-3、bit0 が符号で、
/// 結果は `符号 ++ im11a << 2` の 16 ビット符号付き。
/// PSW.W=0 では s 桁（bits15-14）は無視。
/// Ref: SPEC-PARISC-20 付録E Table E-1 (assemble_16a).
fn expand_12a(word: u64) -> u64 {
    let im11a = (word >> 3) & 0x7ff;
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
// PA 条件コード。算術/加算/減算/論理/ユニット/シフト条件は
// SPEC-PARISC-11 §5.1 Table 5-3 〜 5-7 と SPEC-PARISC-20 付録D
// Table D-3 〜 D-15 に従う。
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
        // never / TR（f=1）
        0 => {
            return if cf & 1 != 0 {
                true_cond(b)
            } else {
                false_cond(b)
            };
        }
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
    // 32 ビット条件は下位 32 ビットで比較する。cf>>1==2/3 は
    // 符号付き大小（<,<=）、1/4/5 は等価・符号なし大小
    // （=,<<,<<=）なので、それぞれ ext32s/ext32u で揃える。
    // Ref: SPEC-PARISC-11 §5 Table 5-3.
    let signed = matches!(cf >> 1, 2 | 3);
    let (i1, i2) = if d {
        (in1, in2)
    } else if signed {
        (sext_bits(b, in1, 32), sext_bits(b, in2, 32))
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

/// DS の減算側（PSW.V=1）の条件解釈。c1..c3 は被演算子比較、
/// c4/5 は DS 定義の符号なしオーバーフロー（シフトアウト桁を
/// 含む）、c6/7 は結果の sv/奇偶。`opd1` はシフト済み値、
/// `opd2` は減数 GR[r2]（どちらも下位 32 ビットを見る）。
/// Ref: SPEC-PARISC-11 §5.1（DS の条件は V に応じ減算/加算条件に
/// 類似）および Table 5-3、SPEC-PARISC-20 §7-47/付録D Table D-3.
fn ds_sub_cond<B: Backend>(
    b: &mut B,
    cf: u64,
    res: B::V<W64>,
    opd1: B::V<W64>,
    opd2: B::V<W64>,
    uv: B::V<W64>,
    sv: B::V<W64>,
) -> B::B {
    let zero = k(b, 0);
    let c = match cf >> 1 {
        // never / TR（f=1）
        0 => {
            return if cf & 1 != 0 {
                true_cond(b)
            } else {
                false_cond(b)
            };
        }
        // =（opd1 == opd2 ⟺ 語の結果が 0）
        1 => is_zero(b, res, false),
        // < / <=（符号付き被演算子比較）
        2 | 3 => {
            let i1 = sext_bits(b, opd1, 32);
            let i2 = sext_bits(b, opd2, 32);
            if cf >> 1 == 2 {
                b.cmp(Cmp::LtS, i1, i2)
            } else {
                b.cmp(Cmp::LeS, i1, i2)
            }
        }
        // <<（UV：シフトアウト桁 | 語の borrow）
        4 => b.cmp(Cmp::Ne, uv, zero),
        // <<=（UV | 語の結果が 0）
        5 => {
            let u = b.cmp(Cmp::Ne, uv, zero);
            let u = bval(b, u);
            let z = is_zero(b, res, false);
            let z = bval(b, z);
            let t = b.or(u, z);
            b.cmp(Cmp::Ne, t, zero)
        }
        // SV
        6 => is_neg(b, sv, false),
        // OD
        _ => {
            let t = and_n(b, res, 1);
            b.cmp(Cmp::Ne, t, zero)
        }
    };
    if cf & 1 != 0 { bnot(b, c) } else { c }
}

/// 論理命令の条件。Table 5-5/D-9 で未定義の case4-6 は
/// never/tr として扱う（設計判断）。
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

/// ユニットゼロ検出の本体。`unit` は 8/16/32 ビット。`res` の
/// unit ビット単位のいずれかが 0 なら真を返す。
/// （(res - 1) & ~res & sign トリックを各ユニットに並列適用）。
fn unit_any_zero<B: Backend>(b: &mut B, res: B::V<W64>, unit: u64, d: bool) -> B::B {
    let d_repl: u64 = if d { 0x0000_0001_0000_0001 } else { 1 };
    let (ones, sgns) = match unit {
        32 => (d_repl, d_repl << 31),
        8 => {
            let ones = d_repl.wrapping_mul(0x0101_0101);
            (ones, ones << 7)
        }
        _ => {
            let ones = d_repl.wrapping_mul(0x0001_0001);
            (ones, ones << 15)
        }
    };
    let o = k(b, ones);
    let g = k(b, sgns);
    let t = b.sub(res, o);
    let not_res = b.not(res);
    let t = b.and(t, not_res);
    let t = b.and(t, g);
    let zero = k(b, 0);
    b.cmp(Cmp::Ne, t, zero)
}

/// uaddcm/uaddcmt のユニット条件（Table 5-6/D-11/D-12）。
/// `xsum` は in1 ^ in2 ^ res（各ビット位置へのキャリーインで、
/// ユニット境界ビットがユニットのキャリーアウトを表す）。
/// `cout` は最上位ユニットのキャリーアウト（0/1）。
/// c=1 は PA 2.0 の 32 ビット語単位の条件（64 ビット時のみ）。
/// 未定義の c（0,5）は never/tr。
fn unit_add_cond<B: Backend>(
    b: &mut B,
    cf: u64,
    d: bool,
    res: B::V<W64>,
    xsum: B::V<W64>,
    cout: B::V<W64>,
) -> B::B {
    let c = match cf >> 1 {
        // SWZ（d のみ）：32 ビット語のいずれかが 0。
        1 if d => unit_any_zero(b, res, 32, d),
        // SBZ：8 ビット単位。
        2 => unit_any_zero(b, res, 8, d),
        // SHZ：16 ビット単位。
        3 => unit_any_zero(b, res, 16, d),
        // キャリー系：ユニット境界（LSB 側 7/3/1 ビット）か最終
        // キャリーアウトのいずれかが立てば真。c=5 は dw のみ
        // （SWC）。d=false の c=5 は未定義 → never/tr。
        c @ (4..=7) => {
            let mask: u64 = match (c, d) {
                (4, true) => 0x1111_1111_1111_1110, // 4 ビット桁（16 桁中 15）
                (4, false) => 0x1111_1110,          // 4 ビット桁（8 桁中 7）
                (5, true) => 0x0000_0001_0000_0000, // 32 ビット語（2 中 1）
                (6, true) => 0x0101_0101_0101_0100, // バイト（8 中 7）
                (6, false) => 0x0101_0100,          // バイト（4 中 3）
                (7, true) => 0x0001_0001_0001_0000, // ハーフワード（4 中 3）
                (7, false) => 0x0001_0000,          // ハーフワード（2 中 1）
                _ => {
                    return if cf & 1 != 0 {
                        true_cond(b)
                    } else {
                        false_cond(b)
                    };
                }
            };
            let t = and_n(b, xsum, mask);
            let zero = k(b, 0);
            let any = b.cmp(Cmp::Ne, t, zero);
            let any = bval(b, any);
            let v = b.or(any, cout);
            b.cmp(Cmp::Ne, v, zero)
        }
        _ => {
            return if cf & 1 != 0 {
                true_cond(b)
            } else {
                false_cond(b)
            };
        }
    };
    if cf & 1 != 0 { bnot(b, c) } else { c }
}

// ----------------------------------------------------------------
// shift pair / extract / deposit の共通部品。
// HP の bit 記法（左端=0）の位置 pos は、LSB 起算では
// (31-pos) / (63-pos) のシフト量に対応する。
// Ref: SPEC-PARISC-11 §5-122〜5-135（VSHD/SHD/VEXTR*/EXTR*/
// VDEP*/DEP*/ZVDEP*/ZDEP*/VDEPI*/DEPI*/ZVDEPI/ZDEPI）、
// SPEC-PARISC-20 §7-38〜45（DEPD/DEPDI/DEPW/DEPWI）、
// §7-48〜50（EXTRD/EXTRW）、§7-122〜124（SHRPD/SHRPW）、
// 付録E Table E-1（assemble_6）。
// ----------------------------------------------------------------

/// `assemble_6(cl,clen)` = `32*cl + 32 - clen`。`len6` は
/// cat(cl,clen) の連結値（cl は len6 の bit5）。
/// Ref: SPEC-PARISC-20 付録E Table E-1.
fn assemble_6(len6: u64) -> u64 {
    32 * (len6 >> 5) + 32 - (len6 & 31)
}

/// `w` ビット分のマスク（w >= 64 は全 1）。
const fn mask64w(w: u64) -> u64 {
    if w >= 64 { !0 } else { (1u64 << w) - 1 }
}

/// extract 共通部。`tpos` は HP 位置の実行時値（可変形は SAR、
/// 固定形は語の pos 桁をそのまま）。`len` は復元済みの実長
/// （1..=64 のデコード時定数）。`se` は符号拡張選択。
/// `d`=false は 32 ビット形で結果を下位 32 ビットに揃える。
///
/// 可変形でフィールドが左端（HP bit0）を超える場合、
/// EXTR*/EXTRD,U 系は超えた分が 0 になり、EXTRS/EXTRD,S 系は
/// フィールド幅 `min(len, tpos+1)` の最上位ビットで符号拡張される
/// （SPEC-PARISC-20 EXTRD operation の `tlen` 処理。入力側の
/// 符号拡張と併せて、32 ビット形では sext64 入力→len 幅の抽出→
/// `pext = min(len-1, tpos)` からの再拡張で spec と同じ結果に
/// なる）。固定形の `pos < len-1` は未定義だが、同じ式の結果を
/// そのまま書く（切り詰めとして読める決定的な値）。
// Gap: GAP-0053
fn do_extr<B: Backend>(
    b: &mut B,
    r: B::V<W64>,
    tpos: B::V<W64>,
    len: u64,
    se: bool,
    d: bool,
) -> B::V<W64> {
    let msb: u64 = if d { 63 } else { 31 };
    let sh = {
        let m = k(b, msb);
        b.sub(m, tpos)
    };
    // 32 ビット形の符号付き可変抽出は、左端を超えた分に元語の
    // 符号ビットが入るので入力を先に 64 ビット符号拡張する
    // （SPEC-PARISC-11 VEXTRS operation の sign_ext_64 入力）。
    let src = if d {
        r
    } else if se {
        sext_bits(b, r, 32)
    } else {
        and_n(b, r, 0xffff_ffff)
    };
    let shifted = b.shr_l(src, sh);
    let field = and_n(b, shifted, mask64w(len));
    let res = if se {
        // 動的幅の符号拡張: フィールド最上位位置 pext =
        // min(len-1, tpos) を符号ビットとして上を埋める。
        // shl/sra の対で任意幅の符号拡張を作る。
        let l1 = k(b, len - 1);
        let lt = b.cmp(Cmp::LtU, tpos, l1);
        let pext = b.select::<W64>(lt, tpos, l1);
        let m63 = k(b, 63u64);
        let s = b.sub(m63, pext);
        let f = b.shl(field, s);
        b.shr_a(f, s)
    } else {
        field
    };
    if d { res } else { and_n(b, res, 0xffff_ffff) }
}

/// deposit 共通部。`old_t` は併合先（nz=1 のときだけ読む）、
/// `tpos` は HP 位置の実行時値、`src` は右詰めフィールド源
/// （depi は low_sign_ext 済みの 5 ビット即値）。`len` は実長。
/// `nz`=false（Z 完語）は `old_t` を 0 として併合する。
///
/// 可変形でフィールドが左端を超える場合は `tpos+1` ビットに
/// 切り詰めて最上端に置く（SPEC-PARISC-11 VDEP/VDEPI、
/// SPEC-PARISC-20 DEPD/DEPDI の `tpos-len+1 < 0` 側）。
/// 固定形の超過は未定義だが同じ式で決定的に評価する。
// Gap: GAP-0053
fn do_dep<B: Backend>(
    b: &mut B,
    old_t: B::V<W64>,
    tpos: B::V<W64>,
    src: B::V<W64>,
    len: u64,
    nz: bool,
    d: bool,
) -> B::V<W64> {
    let msb: u64 = if d { 63 } else { 31 };
    // 32 ビット形（DEPW/DEPWI と PA1.1 DEP/DEPI 系）の併合元は
    // 下位 32 ビットだけを見る（SPEC-PARISC-20 DEPW: 左半は
    // undeﬁned → zext32 を正準形として採用）。
    let base = if nz {
        if d {
            old_t
        } else {
            and_n(b, old_t, 0xffff_ffff)
        }
    } else {
        k(b, 0)
    };
    let shl = {
        let m = k(b, msb);
        b.sub(m, tpos)
    };
    let fmask = k(b, mask64w(len));
    // 通常側: len ビットを shl 位置へ挿入し、残りを base から残す。
    let src_f = b.and(src, fmask);
    let ins = b.shl(src_f, shl);
    let win = {
        let w = b.shl(fmask, shl);
        b.not(w)
    };
    let kept = b.and(base, win);
    let merged = b.or(kept, ins);
    // 上端はみ出し側（可変形のみ到達）: LSB 位置 shl より上を
    // `src` の右詰め tpos+1 ビットで、以下を base で埋める。
    // src の上位は 64 ビット境界で落ちるのでマスク不要。
    let l1 = k(b, len - 1);
    let over = b.cmp(Cmp::LtU, tpos, l1);
    let low_mask = {
        let all = k(b, !0u64);
        let s = b.shl(all, shl);
        b.not(s)
    };
    let low = b.and(base, low_mask);
    let hi = b.shl(src, shl);
    let over_res = b.or(low, hi);
    let res = b.select::<W64>(over, over_res, merged);
    if d { res } else { and_n(b, res, 0xffff_ffff) }
}

/// extract/deposit/shift の条件適用。c!=0 のときだけ PSW.N を
/// 結果に応じて立てる（N は消費済みで 0 から始まるので
/// `cond` 値の代入でよい）。`d` は条件表の幅選択
/// （SPEC-PARISC-11 Table 5-7 / SPEC-PARISC-20 Table D-13/D-14）。
fn sed_nullify<B: Backend>(b: &mut B, c: u64, d: bool, res: B::V<W64>) {
    if c != 0 {
        let cond = sed_cond(b, c, d, res);
        let cv = bval(b, cond);
        set_psw_n(b, cv);
    }
}

// ----------------------------------------------------------------
// add/sub のオーバーフロー・キャリ
// Ref: SPEC-PARISC-11 §5-2（carry_borrows ベクトルと SV/UV 条件）、
// SPEC-PARISC-20 付録E.
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

/// 64 ビット加算のキャリアウト（0/1）。res = in1+in2+cin（cin∈{0,1}）。
/// res <u in1 なら確定。cin=1 で res == in1 のときも繰り上がり
/// （この場合 in2+cin が 2^64 に達するので carry=1）。
fn carry64_cin<B: Backend>(b: &mut B, res: B::V<W64>, in1: B::V<W64>, cin: B::V<W64>) -> B::V<W64> {
    let lt = b.cmp(Cmp::LtU, res, in1);
    let lt = bval(b, lt);
    let eq = b.cmp(Cmp::Eq, res, in1);
    let eq = bval(b, eq);
    let eq = b.and(eq, cin);
    b.or(lt, eq)
}

/// 32 ビット加算のキャリアウト（0/1）。cin は V（0/1）。
fn carry32_cin<B: Backend>(b: &mut B, in1: B::V<W64>, in2: B::V<W64>, cin: B::V<W64>) -> B::V<W64> {
    let a = and_n(b, in1, 0xffff_ffff);
    let c = and_n(b, in2, 0xffff_ffff);
    let s = b.add(a, c);
    let s = b.add(s, cin);
    shr_n(b, s, 32)
}

/// PSW[C/B] の桁キャリベクトルを `cb` 状態へ保存する。
/// `x = in1 ^ in2 ^ dest` の bit i は「bit i へのキャリ」なので、
/// x を 4 ビット右シフト（`x >> 4`）すると各 4 ビット桁の出口
/// キャリが bit 4j（= C/B{15-j}）に揃う。bit60（C/B{0}）は全体の
/// キャリアウトを別計算で入れる。`in2` は実効の第 2 加数
/// （減算なら ~in2 + cin の ~in2 側）。
/// Ref: SPEC-PARISC-20 §7-5（C/B は各 BCD 桁のキャリ）.
fn save_carry<B: Backend>(
    b: &mut B,
    in1: B::V<W64>,
    in2: B::V<W64>,
    dest: B::V<W64>,
    c64: B::V<W64>,
) {
    let x = b.xor(in1, in2);
    let x = b.xor(x, dest);
    let xs = shr_n(b, x, 4);
    let cbv = and_n(b, xs, 0x1111_1111_1111_1111);
    let top = shl_n(b, c64, 60);
    let cbv = b.or(cbv, top);
    b.set(cb_ref(), cbv);
}

/// `add,c`/`sub,b`/`ds` が参照する語形・dw 形の桁キャリ
/// （0/1 の V）。d=false は C/B{8}（語のキャリ＝bit32 への
/// キャリ）、d=true は C/B{0}（64 ビットのキャリアウト）。
/// Ref: SPEC-PARISC-20 §7-5.
fn psw_carry<B: Backend>(b: &mut B, d: bool) -> B::V<W64> {
    let cbv = b.get(cb_ref());
    let sh = if d { 60 } else { 28 };
    let v = shr_n(b, cbv, sh);
    and_n(b, v, 1)
}

// ----------------------------------------------------------------
// 算術・論理命令の共通処理
// ----------------------------------------------------------------

/// dest = (in1 << shift) + in2 (+carry)。
/// `is_c` は `add,c`（psw キャリを足し込む）。
/// Ref: SPEC-PARISC-11 §ADD/ADDO/ADDC/SHnADD, SPEC-PARISC-20 付録D.
/// トラップは結果・キャリの公表より先に評価する（オーバーフロー
/// 形式・条件トラップ形式とも、トラップした命令は GR[t] も
/// PSW[C/B] も更新しない）。
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
    // cin 込みの幅内キャリアウト（0/1）。cb{0} に対応。
    let c32 = carry32_cin(b, in1, in2, cin);
    let c64 = carry64_cin(b, dest, in1, cin);
    let cout = if d { c64 } else { c32 };
    let uv = if c == 4 || c == 5 {
        add_uv(b, cout, orig_in1, shift, d)
    } else {
        zero
    };
    let cond = arith_cond(b, cf, d, dest, uv, sv);
    // トラップは結果・キャリの公表に先立つ。
    if is_tsv {
        let over = is_neg(b, sv, d);
        b.if_then(over, |b| {
            Err(raise::<B>(b, ExceptionKind::Trap, TRAP_OVERFLOW))
        })?;
    }
    if is_tc {
        b.if_then(cond, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_COND)))?;
    }
    if !is_l {
        // PSW[C/B] の桁キャリ列を保存。
        save_carry(b, in1, in2, dest, c64);
    }
    Gr(rt as u8).set(b, dest);
    if !is_tc && cf != 0 {
        // 条件完語は次命令を無効化する（PSW.N ← cond）。
        let condv = bval(b, cond);
        set_psw_n(b, condv);
    }
    Ok(())
}

/// dest = in1 - in2（is_b ならさらに !borrow を引く）。
/// spec: SUB は `GR[r1] + ~GR[r2] + 1`、SUBB は
/// `GR[r1] + ~GR[r2] + PSW[C/B]{0}`。
/// Ref: SPEC-PARISC-11 §SUB/SUBB, SPEC-PARISC-20 付録D.
/// トラップは結果・キャリの公表に先立つ。
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
    // cin_eff = is_b ? psw_carry : 1。dest = in1 + ~in2 + cin_eff。
    let cin = if is_b { psw_carry(b, d) } else { k(b, 1) };
    let not2 = b.not(in2);
    let dest = b.add(in1, not2);
    let dest = b.add(dest, cin);
    let c = cf >> 1;
    let need_sv = is_tsv || c == 2 || c == 3 || c == 6;
    let sv = if need_sv {
        sub_sv(b, dest, in1, in2)
    } else {
        k(b, 0)
    };
    // carry-out（借りなし=1）を cin 込みで計算。
    let c32 = carry32_cin(b, in1, not2, cin);
    let c64 = carry64_cin(b, dest, in1, cin);
    let cout = if d { c64 } else { c32 };
    let cond = if is_b {
        // SUBB の条件は、cin を含めた結果と cout で評価する。
        // Table 5-3/D-3 の字義は「opd1 vs opd2（GR の生値）」の
        // 被演算子比較だが、その表は cin=1 固定の SUB 系で書かれた
        // もので、cin=0（borrow 継続）の等号縁では字義とはずれる
        // （`=` が in1==in2+1、`<<` が in1<=in2 となる）。cin を含む
        // 実効減数で評価する読みは、多語の borrow 連鎖の条件として
        // 意味を持つ（`<<` が「この語でも借りが残る」を表す）唯一の
        // 読みで、spec 自身の `<<`＝「unsigned overflow（減算結果
        // が 0 未満）」の定義とも整合する。cin=1 では両読み一致。
        // Ref: SPEC-PARISC-11 §5 Table 5-3, SPEC-PARISC-20 付録D
        // Table D-3.
        // Gap: GAP-0054
        arith_cond(b, cf, d, dest, cout, sv)
    } else {
        sub_cond(b, cf, d, dest, in1, in2, sv)
    };
    if is_tsv {
        let over = is_neg(b, sv, d);
        b.if_then(over, |b| {
            Err(raise::<B>(b, ExceptionKind::Trap, TRAP_OVERFLOW))
        })?;
    }
    if is_tc {
        b.if_then(cond, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_COND)))?;
    }
    save_carry(b, in1, not2, dest, c64);
    Gr(rt as u8).set(b, dest);
    if !is_tc && cf != 0 {
        let condv = bval(b, cond);
        set_psw_n(b, condv);
    }
    Ok(())
}

/// COMCLR/COMICLR：比較結果を条件に使い、rt は必ず 0 にする。
/// PSW[C/B] は更新しない（SPEC-PARISC-11 §COMCLR）。
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

/// 間接分岐の共通処理。`base` はベースレジスタ（bv/be/bve の
/// GR[b]）の値で、IAOQ 下位2ビットの特権決定に使う。
/// SPEC-PARISC-20 §7（BV/BE/BVE 操作）: `IAOQ_Front{62..63}` が
/// `GR[b]{62..63}` より小さいときだけ新特権は `GR[b]` の下位2ビット、
/// さもなければ現特権を維持（特権は下げる方向にのみ変わる）。
/// `pc` は IAOQ_Front の値（下位2ビットが現特権）。
fn ibranch<B: Backend>(b: &mut B, target: B::V<W64>, base: B::V<W64>, link: u64, n: u64, pc: u64) {
    if link != 0 {
        let v = k(b, pc.wrapping_add(8));
        Gr(link as u8).set(b, v);
    }
    if n != 0 {
        set_psw_n_const(b, true);
    }
    let bp = and_n(b, base, 3);
    let fp = k(b, pc & 3);
    let demote = b.cmp(Cmp::GtU, bp, fp);
    let plvl = b.select::<W64>(demote, bp, fp);
    let hi = and_n(b, target, !3u64);
    let tgt = b.or(hi, plvl);
    b.jump(tgt);
}

/// 条件分岐（do_cbranch）。`cond` 成立で taken。
/// `,n` の無効化は方向で変わる: taken で disp>=0（前方）、
/// not-taken で disp<0（後方）のときだけ PSW.N を立てる
/// （仕様記述は `if (disp < 0) PSW[N] ← taken 側条件、
/// else PSW[N] ← !taken 側条件` で、disp=0 は前方扱い）。
/// Ref: SPEC-PARISC-11 §5 COMIBF Operation.
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
            // opd1 = GR[r1]（ops[1]）、opd2 = GR[r2]（ops[0]）。
            // ANDCM は GR[r1] AND ~GR[r2] で可換でないので注意。
            let r1 = Gr(ops[1] as u8).get(b);
            let r2 = Gr(ops[0] as u8).get(b);
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
            // COMCLR: opd1 = GR[r1]（ops[1]）、opd2 = GR[r2]（ops[0]）。
            let r1 = Gr(ops[1] as u8).get(b);
            let r2 = Gr(ops[0] as u8).get(b);
            do_cmpclr(b, ops[4], r1, r2, ops[2], ops[3] != 0)?;
        }
        Insn::Uaddcm | Insn::UaddcmTc => {
            // UADDCM: GR[t] ← GR[r1] + ~GR[r2]。条件はユニット条件
            // （Table 5-6/D-11：SBZ/SHZ/SDC/SBC/SHC とその否定）。
            // opd1 = GR[r1]（ops[1]）、opd2 = GR[r2]（ops[0]）。
            let r1 = Gr(ops[1] as u8).get(b);
            let r2 = Gr(ops[0] as u8).get(b);
            let (cf, d, t) = (ops[2], ops[3] != 0, ops[4]);
            let n2 = b.not(r2);
            let dest = b.add(r1, n2);
            // 条件・キャリ評価はトラップの前に行う（uaddcmt は
            // トラップしたら GR[t] を更新しない）。
            let cond = if cf != 0 {
                // xsum = in1 ^ ~in2 ^ dest = 各ビット位置への
                // キャリーイン。ユニット境界のビットがユニット
                // キャリーアウト。
                let xa = b.xor(r1, n2);
                let xsum = b.xor(xa, dest);
                let zero = k(b, 0);
                let cin = zero;
                let cout = if d {
                    carry64_cin(b, dest, r1, cin)
                } else {
                    carry32_cin(b, r1, n2, cin)
                };
                unit_add_cond(b, cf, d, dest, xsum, cout)
            } else {
                false_cond(b)
            };
            if insn == Insn::UaddcmTc {
                b.if_then(cond, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_COND)))?;
            }
            Gr(t as u8).set(b, dest);
            if insn != Insn::UaddcmTc && cf != 0 {
                let condv = bval(b, cond);
                set_psw_n(b, condv);
            }
        }
        Insn::Ds => {
            // DS,cond r1,r2,t：非回復除算の 1 ビットステップ。
            // ops = [r2, r1, cf, t]。
            //   partial = cat(lshift(GR[r1],1), PSW[C/B]{8})
            //   if (PSW[V]) GR[t] ← partial + ~GR[r2] + 1
            //   else        GR[t] ← partial + GR[r2]
            //   PSW[C/B] ← carry_borrows（本演算の桁キャリ列）
            //   PSW[V] ← xor(carry_borrows{8}, GR[r2]{32})
            // 商ビットが語の桁キャリ C/B{8} になる。
            // Ref: SPEC-PARISC-11 §5-111, SPEC-PARISC-20 §7-47.
            let r2 = Gr(ops[0] as u8).get(b);
            let r1 = Gr(ops[1] as u8).get(b);
            let (cf, t) = (ops[2], ops[3]);
            // シフトインする商ビット候補は語の桁キャリ C/B{8}。
            let cb8 = psw_carry(b, false);
            let r1s = shl_n(b, r1, 1);
            let partial = b.or(r1s, cb8);
            // 旧 PSW[V] で加算/減算を切り替える。
            let p = b.get(psw_ref());
            let pv = and_n(b, p, PSW_V);
            let zero = k(b, 0);
            let v_set = b.cmp(Cmp::Ne, pv, zero);
            let not2 = b.not(r2);
            let in2 = b.select::<W64>(v_set, not2, r2);
            let cin = bval(b, v_set);
            let dest = b.add(partial, in2);
            let dest = b.add(dest, cin);
            // 桁キャリ列（C/B{0..15}）と 64 ビットの出口キャリ。
            let c64 = carry64_cin(b, dest, partial, cin);
            save_carry(b, partial, in2, dest, c64);
            // PSW[V] ← carry_borrows{8}（語の出口キャリ＝
            // bit32 へのキャリ）xor GR[r2]{32}（語の符号 = LSB
            // bit31）。
            let x = b.xor(partial, in2);
            let x = b.xor(x, dest);
            let xs = shr_n(b, x, 32);
            let cb8_new = and_n(b, xs, 1);
            let r2sh = shr_n(b, r2, 31);
            let r2s = and_n(b, r2sh, 1);
            let vnew = b.xor(cb8_new, r2s);
            let p = and_n(b, p, !PSW_V);
            let vbit = shl_n(b, vnew, 6);
            let p = b.or(p, vbit);
            b.set(psw_ref(), p);
            Gr(t as u8).set(b, dest);
            if cf != 0 {
                // sv: 「シフトアウトした語最上位ビットとシフト後の
                // 語最上位ビットが異なる（r1{31} != r1{30}）」に
                // 加減算の通常の符号付きオーバーフローを OR したもの。
                // uv: 「語最上位のシフトアウトが 1」に語演算の
                // 符号なしオーバーフローを OR したもの。
                // 条件表は旧 PSW.V で切り替わる（V=0 は加算条件、
                // V=1 は減算条件。SPEC-PARISC-11 §5.1）。
                let sv = add_sv(b, dest, partial, in2, r1, 1, false);
                let carry32 = cb8_new;
                let r1m = shr_n(b, r1, 31);
                let shifted_out = and_n(b, r1m, 1);
                let uv_add = b.or(carry32, shifted_out);
                let one = k(b, 1);
                let borrow = b.xor(carry32, one);
                let uv_sub = b.or(borrow, shifted_out);
                let c_add = arith_cond(b, cf, false, dest, uv_add, sv);
                let c_sub = ds_sub_cond(b, cf, dest, partial, r2, uv_sub, sv);
                let c_add = bval(b, c_add);
                let c_sub = bval(b, c_sub);
                let c = b.select::<W64>(v_set, c_sub, c_add);
                set_psw_n(b, c);
            }
        }
        Insn::Dcor | Insn::DcorI => {
            // DCOR/DCOR,I：16 桁 BCD 訂正。ops = [r, cf, d, t]。
            // C/B{0..15} は cb 状態の bit4j ベクトル
            // （C/B{15-j} が bit4j）。中間訂正（dcor,i）は
            // C/B=1 の桁に +6、最終訂正（dcor）は C/B=0 の桁に -6
            // （cat の n 番目の 4 ビット項が C/B{n} 対応）。
            // sel<<1 | sel<<2 で各桁に 0x6 を立てる。
            // PSW[C/B] は更新しない。条件はユニット条件
            // （Table D-11/D-12）。
            // Ref: SPEC-PARISC-20 §7-36, SPEC-PARISC-11
            // §5-113/§5-114.
            let r = Gr(ops[0] as u8).get(b);
            let (cf, d, t) = (ops[1], ops[2] != 0, ops[3]);
            let cbv = b.get(cb_ref());
            let sel = and_n(b, cbv, 0x1111_1111_1111_1111);
            let (res, xsum, cout) = if insn == Insn::DcorI {
                let c1 = shl_n(b, sel, 1);
                let c2 = shl_n(b, sel, 2);
                let corr = b.or(c1, c2);
                let res = b.add(r, corr);
                let x = b.xor(r, corr);
                let x = b.xor(x, res);
                let zero = k(b, 0);
                let cout = carry64_cin(b, res, r, zero);
                (res, x, cout)
            } else {
                let nsel = b.not(sel);
                let nsel = and_n(b, nsel, 0x1111_1111_1111_1111);
                let c1 = shl_n(b, nsel, 1);
                let c2 = shl_n(b, nsel, 2);
                let corr = b.or(c1, c2);
                // res = r - corr = r + ~corr + 1
                let ncorr = b.not(corr);
                let res = b.add(r, ncorr);
                let one_v = k(b, 1);
                let res = b.add(res, one_v);
                let x = b.xor(r, ncorr);
                let x = b.xor(x, res);
                let cout = carry64_cin(b, res, r, one_v);
                (res, x, cout)
            };
            Gr(t as u8).set(b, res);
            if cf != 0 {
                let cond = unit_add_cond(b, cf, d, res, xsum, cout);
                let condv = bval(b, cond);
                set_psw_n(b, condv);
            }
        }
        // ---- FRRICD sub ----
        Insn::Sub | Insn::SubTsv | Insn::SubTc | Insn::SubTsvTc => {
            // SUB: GR[t] ← GR[r1] + ~GR[r2] + 1。opd1 = r1（ops[1]）、
            // opd2 = r2（ops[0]）。
            let r1 = Gr(ops[1] as u8).get(b);
            let r2 = Gr(ops[0] as u8).get(b);
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
            // SHnADD: GR[t] ← lshift(GR[r1], n) + GR[r2]。
            // opd1（シフトされる側）= r1（ops[1]）、opd2 = r2（ops[0]）。
            let r1 = Gr(ops[1] as u8).get(b);
            let r2 = Gr(ops[0] as u8).get(b);
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
            // SUBB: GR[t] ← GR[r1] + ~GR[r2] + PSW[C/B]{0}。
            // opd1 = r1（ops[1]）、opd2 = r2（ops[0]）。
            let r1 = Gr(ops[1] as u8).get(b);
            let r2 = Gr(ops[0] as u8).get(b);
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
            ibranch(b, t, base, link, ops[4], pc);
        }
        Insn::Bl | Insn::BlPush | Insn::Gate => {
            // bl/gate/bl,push：直接。l=0 ならリンクなし。
            // bl,push の BTS 投入は分岐予測器の内部状態で
            // アーキテクチャ的には不可視（PA2.0 §B,PUSH）。
            if insn == Insn::Gate {
                // gate は PSW.B なら不正（遅延スロット内 gate。
                // SPEC-PARISC-20 §B,GATE operation）。
                let p = b.get(psw_ref());
                let t = and_n(b, p, PSW_B);
                let z = k(b, 0);
                let has = b.cmp(Cmp::Ne, t, z);
                b.if_then(has, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_ILL)))?;
                // GR[t] ← cat(GR[t]{0..61}, IAOQ_Front{62..63})：
                // 上位 62 ビットは旧値のまま、下位 2 ビットに
                // IAOQ_Front の特権ビットを書く。
                let old = Gr(ops[0] as u8).get(b);
                let hi = and_n(b, old, !3u64);
                let privbits = k(b, pc & 3);
                let v = b.or(hi, privbits);
                Gr(ops[0] as u8).set(b, v);
                if ops[3] != 0 {
                    // `,n` は B,GATE,n として仕様の擬似命令表にも
                    // ある（SPEC-PARISC-20 擬似命令一覧）。
                    set_psw_n_const(b, true);
                }
                let disp = disp17(ops[1], ops[2]);
                // IAOQ_Next{62..63} ← priv。PSW[C]=0（本モデルの
                // 簡約）では priv=0 なのでターゲットの下位 2 ビット
                // は 0（SPEC-PARISC-20 §B,GATE Operation）。
                let target = pc.wrapping_add(8).wrapping_add(disp) & !3;
                let target = k(b, target);
                b.jump(target);
            } else {
                dbranch(b, pc, disp17(ops[1], ops[2]), ops[0], ops[3]);
            }
        }
        Insn::BlLong => {
            // bl.long disp → リンクは r2。
            dbranch(b, pc, disp22(ops[0], ops[1]), 2, ops[2]);
        }
        Insn::Blr => {
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
            // bv x(b)：target = GR[b] + (GR[x]<<3)（SPEC-PARISC-20
            // §7-20）。特権は GR[b] の下位2ビットで決まる。
            let base = Gr(ops[0] as u8).get(b);
            let t = if ops[1] != 0 {
                let x = Gr(ops[1] as u8).get(b);
                let s = shl_n(b, x, 3);
                b.add(s, base)
            } else {
                base
            };
            ibranch(b, t, base, 0, ops[2], pc);
        }
        Insn::Bve | Insn::BveL => {
            // bve (b)：target = gr[b]。BveL はリンク r2。
            let link = if insn == Insn::BveL { 2 } else { 0 };
            let t = Gr(ops[0] as u8).get(b);
            ibranch(b, t, t, link, ops[1], pc);
        }
        // ---- 条件分岐 ----
        Insn::Cmpb | Insn::CmpbF | Insn::CmpbD | Insn::CmpbDf => {
            // comb,c(,f) r1,r2,disp → dest = GR[r1] - GR[r2]。
            // フィールドは fa=r2, fb=r1（ops[1] が r1）。
            let f = matches!(insn, Insn::CmpbF | Insn::CmpbDf) as u64;
            let d = matches!(insn, Insn::CmpbD | Insn::CmpbDf);
            let r1 = Gr(ops[1] as u8).get(b);
            let r2 = Gr(ops[0] as u8).get(b);
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
            // f は COMIBT=0・COMIBF=1 の固定（taken の向き）だが、
            // COMIB,D では bit15 が条件表（Table D-5）の一部で、
            // FRIBD 形式の f 桁（ops[2]）から取る。
            let f = if insn == Insn::CmpbiD {
                ops[2]
            } else {
                matches!(insn, Insn::CmpbiF) as u64
            };
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
                // movb r1,r2,disp → GR[r2] ← GR[r1]（ops[0]=r2 が
                // 書き先、ops[1]=r1 が読み元）。
                let v = Gr(ops[1] as u8).get(b);
                Gr(ops[0] as u8).set(b, v);
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
                // addb r1,r2 → GR[r2] ← GR[r1] + GR[r2]（ops[0]=r2）。
                in1 = Gr(ops[1] as u8).get(b);
                in2 = Gr(ops[0] as u8).get(b);
                rt = ops[0];
            } else {
                // addib i,r → GR[r] ← im5 + GR[r]。
                in1 = k(b, im5(ops[1]));
                in2 = Gr(ops[0] as u8).get(b);
                rt = ops[0];
            };
            dest = b.add(in1, in2);
            Gr(rt as u8).set(b, dest);
            let zero = k(b, 0);
            let (uv, sv);
            if matches!(c3, 4 | 5) {
                let c = carry32_cin(b, in1, in2, zero);
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
        Insn::Ldb | Insn::Ldh | Insn::Ldw => {
            let size = match insn {
                Insn::Ldb => 0,
                Insn::Ldh => 1,
                _ => 2,
            };
            load_off(b, ops[1], ops[0], expand_16(ops[2]), 0, size)?;
        }
        Insn::Ldd => {
            // Format 3（SPEC-PARISC-20 §LDD）:
            //   `14 b t s im10a m a 0 i`
            //   bits15-14=s、bits13-4=im10a、bit3=m、bit2=a、
            //   bit0=i（変位の符号）。dx =
            //   sign_ext(assemble_16a(s,cat(im10a,0),i),16) で、
            //   PSW.W=0 では `符号(i) ++ im10a << 3` の 16 ビット。
            //   modify 完語は m(bit3)<<1|a(bit2) の生値を
            //   ma_to_m に渡す（a=0 事後、a=1 事前）。
            let w = u64::from(word);
            let i = w & 1;
            let im10a = (w >> 4) & 0x3ff;
            let d16 = (((-(i as i64)) as u64) << 13 | (im10a << 3)) as u16 as i16 as i64;
            let m = ma_to_m((w >> 2) & 3);
            load_off(b, ops[1], ops[0], d16 as u64, m, 3)?;
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
        Insn::Stb | Insn::Sth | Insn::Stw => {
            let size = match insn {
                Insn::Stb => 0,
                Insn::Sth => 1,
                _ => 2,
            };
            store_off(b, ops[1], ops[0], expand_16(ops[2]), 0, size)?;
        }
        Insn::Std => {
            // Format 3（SPEC-PARISC-20 §STD）: LDD と同じ
            // `1C b r s im10a m a 0 i` レイアウト。
            let w = u64::from(word);
            let i = w & 1;
            let im10a = (w >> 4) & 0x3ff;
            let d16 = (((-(i as i64)) as u64) << 13 | (im10a << 3)) as u16 as i16 as i64;
            let m = ma_to_m((w >> 2) & 3);
            store_off(b, ops[1], ops[0], d16 as u64, m, 3)?;
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
        Insn::Ldi | Insn::LdiD | Insn::Ldcw | Insn::Ldcd => {
            // ldi(,d): ops = [b, im5f, sp, size, ma, t]。
            // ldcw/ldcd: ops = [b, im5f, sp, ma, t]。
            let is_ldi = matches!(insn, Insn::Ldi | Insn::LdiD);
            let (size, m, t) = if is_ldi {
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
            if is_ldi {
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
            } else {
                // ldcw/ldcd: ロードと 0 クリアは不可分（SPEC-PARISC-11
                // §LDCW）。interp の予約機構（load_reserved /
                // store_conditional）で実現する。これは単一スレッド
                // 前提の近似で、競合で store_conditional が失敗した
                // 場合の再試行は意味論側にループを持てないため
                // 実装簡約としてトラップにする。
                // なお実効番地の 16 バイト整列要求（§LDCWX
                // "The address must be 16-byte aligned"）は検査
                // しない簡約とする。
                // Gap: GAP-0052
                match size {
                    3 => {
                        let v: B::V<W64> = b.load_reserved(ea, ATOMIC_RW)?;
                        let z = k(b, 0);
                        let ok: B::B = b.store_conditional::<W64>(ea, z, ATOMIC_RW)?;
                        let nok = bnot(b, ok);
                        b.if_then(nok, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_ILL)))?;
                        Gr(t as u8).set(b, v);
                    }
                    _ => {
                        let v: B::V<W32> = b.load_reserved(ea, ATOMIC_RW)?;
                        let z = k(b, 0);
                        let z = b.trunc::<W64, W32>(z);
                        let ok: B::B = b.store_conditional::<W32>(ea, z, ATOMIC_RW)?;
                        let nok = bnot(b, ok);
                        b.if_then(nok, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_ILL)))?;
                        let v = b.zext::<W32, W64>(v);
                        Gr(t as u8).set(b, v);
                    }
                }
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::Ldx | Insn::LdxD | Insn::Ldcwx | Insn::Ldcdx => {
            // ops = [b, x, sp, scale(u), m, t]。index 形式の completer
            // は u(,s 事前スケール)と m(,m 事後更新)の 2 桁:
            //   u=0,m=0 → EA = b + x
            //   u=1,m=0 → EA = b + (x << shift)
            //   u=0,m=1 → EA = b、書戻し b += x
            //   u=1,m=1 → EA = b、書戻し b += (x << shift)
            // m=1 は常に EA=base の事後更新で、ディスプレースメント
            // 系の ,ma/,mb とは規則が違う（SPEC-PARISC-11 §LDCWX
            // Operation, SPEC-PARISC-20 §LDD/LDW と表 H-3）。
            let size: u64 = match insn {
                Insn::Ldx | Insn::LdxD => (u64::from(word) >> 6) & 3,
                Insn::Ldcdx => 3,
                _ => 2,
            };
            // ,s のシフト量は ldx がオペランド幅（b=0,h=1,w=2,d=3）
            // なのに対し、ldcw/ldcd は幅に関係なく 3（LDCW は
            // 「index shift … shifts by three, not two」の注記）。
            // Ref: SPEC-PARISC-11 §LDCWX Notes.
            let shift = if matches!(insn, Insn::Ldx | Insn::LdxD) {
                size
            } else {
                3
            };
            let x = Gr(ops[1] as u8).get(b);
            let x = if ops[3] != 0 { shl_n(b, x, shift) } else { x };
            let m: i64 = if ops[4] != 0 { 1 } else { 0 };
            let (ea, new_base) = gva(b, ops[0], x, 0, m);
            let t = ops[5];
            if matches!(insn, Insn::Ldx | Insn::LdxD) {
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
            } else {
                // ldcwx/ldcdx: ロードと 0 クリアは不可分
                // （SPEC-PARISC-11 §LDCW）。im5 形式と同じく予約機構
                // を使う単一スレッド前提の近似。
                match size {
                    3 => {
                        let v: B::V<W64> = b.load_reserved(ea, ATOMIC_RW)?;
                        let z = k(b, 0);
                        let ok: B::B = b.store_conditional::<W64>(ea, z, ATOMIC_RW)?;
                        let nok = bnot(b, ok);
                        b.if_then(nok, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_ILL)))?;
                        Gr(t as u8).set(b, v);
                    }
                    _ => {
                        let v: B::V<W32> = b.load_reserved(ea, ATOMIC_RW)?;
                        let z = k(b, 0);
                        let z = b.trunc::<W64, W32>(z);
                        let ok: B::B = b.store_conditional::<W32>(ea, z, ATOMIC_RW)?;
                        let nok = bnot(b, ok);
                        b.if_then(nok, |b| Err(raise::<B>(b, ExceptionKind::Trap, TRAP_ILL)))?;
                        let v = b.zext::<W32, W64>(v);
                        Gr(t as u8).set(b, v);
                    }
                }
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::Sti | Insn::StiD => {
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
        // ---- STBY/STDBY（memcpy の端処理用の部分ストア）----
        Insn::Stby | Insn::Stdby => {
            // ops = [b, r, sp, a, m, disp]。a=0 は ,B（EA バイトから
            // そのワード/ダブルワードの末尾まで）、a=1 は ,E（ワード
            // 先頭から EA 直前まで）を BE 順で書く。m=1 は
            // GR[b] = (GR[b]+disp) & ~mask の更新で、B,M の EA は
            // 更新前の GR[b] そのもの。PSW.E=0（BE）側のみ実装
            // （hppa32 Linux は常に BE）。
            // Gap: GAP-0053
            // Ref: SPEC-PARISC-11 §STBYS, SPEC-PARISC-20 §STDBY.
            let is_d = insn == Insn::Stdby;
            let wmask: u64 = if is_d { 7 } else { 3 };
            let base = Gr(ops[0] as u8).get(b);
            let disp = im5(ops[5]);
            let a = ops[3];
            let m = ops[4];
            // B,M（a=0,m=1）だけ EA = 更新前の GR[b]。
            let off = if a == 0 && m != 0 {
                base
            } else {
                add_n(b, base, disp)
            };
            let j = and_n(b, off, wmask);
            let a_addr = and_n(b, off, !wmask);
            let r = Gr(ops[1] as u8).get(b);
            let n: u64 = if is_d { 8 } else { 4 };
            // ,E で j=0 のとき 1 バイトも書かないが、spec は
            // アライン済みワードへの保護検査（と dirty 記録）を
            // 要求する。バイトを書かずに検査だけする手段として
            // probe を使う（未写像は検出できるが書込許可自体の
            // 判定・dirty 記録は本メモリ抽象では表せない）。
            // Ref: SPEC-PARISC-20 §7-139 STDBY.
            // Gap: GAP-0053
            if a == 1 {
                let zero = k(b, 0);
                let jz = b.cmp(Cmp::Eq, j, zero);
                b.if_then(jz, |b| b.probe(a_addr, 1, DATA_WRITE))?;
            }
            // バイト k を書く条件: B は k>=j、E は k<j。
            // 部分書きなので W8 ストアを個数分だけ述語付きで並べる。
            for kk in 0..n {
                let kc = k(b, kk);
                let store_it = if a == 0 {
                    b.cmp(Cmp::GeU, kc, j)
                } else {
                    b.cmp(Cmp::LtU, kc, j)
                };
                let addr = b.add(a_addr, kc);
                let byte = shr_n(b, r, (n - 1 - kk) * 8);
                b.if_then(store_it, |b| {
                    let v = b.trunc::<W64, W8>(byte);
                    b.store(addr, v, DATA_WRITE)
                })?;
            }
            if m != 0 {
                // 更新後のベースはアライン済み。
                let nb = and_n(b, off, !wmask);
                // E,M / B,M ともに (GR[b]+disp) & ~mask。B,M は
                // off=GR[b] なので別計算。
                let nb = if a == 0 {
                    let t = add_n(b, base, disp);
                    and_n(b, t, !wmask)
                } else {
                    nb
                };
                Gr(ops[0] as u8).set(b, nb);
            }
        }
        // ---- FP load/store（ビット移動のみ。演算なし）----
        Insn::Fldwx | Insn::Fstwx | Insn::Flddx | Insn::FstdIdx => {
            // ops = [b, x, sp, u, m, t]。u(,s)はワード=<<2・
            // ダブルワード=<<3 の事前スケール。m(,m)は EA=base の
            // 事後更新（b += dx）。cc は無視。
            // Gap: GAP-0053
            // Ref: SPEC-PARISC-20 §FLDW/FSTW/FLDD/FSTD Operation.
            let is_d = matches!(insn, Insn::Flddx | Insn::FstdIdx);
            let x = Gr(ops[1] as u8).get(b);
            let dx = if ops[3] != 0 {
                shl_n(b, x, if is_d { 3 } else { 2 })
            } else {
                x
            };
            let m: i64 = if ops[4] != 0 { 1 } else { 0 };
            let (ea, new_base) = gva(b, ops[0], dx, 0, m);
            let t = ops[5];
            match insn {
                Insn::Fldwx => {
                    let v: B::V<W32> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W32, W64>(v);
                    fpr_set_w(b, t, v);
                }
                Insn::Fstwx => {
                    let v = fpr_get_w(b, t);
                    let v = b.trunc::<W64, W32>(v);
                    b.store(ea, v, DATA_WRITE)?;
                }
                Insn::Flddx => {
                    let v: B::V<W64> = b.load(ea, DATA_READ)?;
                    b.set(Fpr(t as u8).state(), v);
                }
                _ => {
                    let v = b.get(Fpr(t as u8).state());
                    b.store(ea, v, DATA_WRITE)?;
                }
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::Fldwi | Insn::Fstwi | Insn::Flddi | Insn::FstdIm5 => {
            // ops = [b, im5, sp, ma, t]。ma = m(bit5)<<1|a(bit13):
            // m=1 でベース更新（a=0 事後、a=1 事前）。
            let m = ma_to_m(ops[3]);
            let disp = im5(ops[1]);
            let zero = k(b, 0);
            let (ea, new_base) = gva(b, ops[0], zero, disp, m);
            let t = ops[4];
            match insn {
                Insn::Fldwi => {
                    let v: B::V<W32> = b.load(ea, DATA_READ)?;
                    let v = b.zext::<W32, W64>(v);
                    fpr_set_w(b, t, v);
                }
                Insn::Fstwi => {
                    let v = fpr_get_w(b, t);
                    let v = b.trunc::<W64, W32>(v);
                    b.store(ea, v, DATA_WRITE)?;
                }
                Insn::Flddi => {
                    let v: B::V<W64> = b.load(ea, DATA_READ)?;
                    b.set(Fpr(t as u8).state(), v);
                }
                _ => {
                    let v = b.get(Fpr(t as u8).state());
                    b.store(ea, v, DATA_WRITE)?;
                }
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::Fldd | Insn::Fstd => {
            // ops = [b, t, off]。Format 3/Format 43-44 系の長変位
            // （LDD/STD と同じ im10a+m+a+i レイアウト）。
            let w = u64::from(word);
            let i = w & 1;
            let im10a = (w >> 4) & 0x3ff;
            let d16 = (((-(i as i64)) as u64) << 13 | (im10a << 3)) as u16 as i16 as i64;
            let m = ma_to_m((w >> 2) & 3);
            let zero = k(b, 0);
            let (ea, new_base) = gva(b, ops[0], zero, d16 as u64, m);
            if insn == Insn::Fldd {
                let v: B::V<W64> = b.load(ea, DATA_READ)?;
                b.set(Fpr(ops[1] as u8).state(), v);
            } else {
                let v = b.get(Fpr(ops[1] as u8).state());
                b.store(ea, v, DATA_WRITE)?;
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        Insn::FldwO | Insn::FldwO0 | Insn::FstwO | Insn::FstwO0 => {
            // ops = [b, f, offa, a]。長変位のワード形。
            // FldwO0/FstwO0（Format 43、opcode 0x17/0x1f、bit2=0）
            // はベース更新なし。FldwO/FstwO（0x16/0x1e、Format 44）
            // は a=1 が事前、a=0 が事後。
            // Ref: SPEC-PARISC-20 §FLDW/FSTW（Formats 43/44）.
            let has_mod = matches!(insn, Insn::FldwO | Insn::FstwO);
            let m: i64 = if has_mod {
                if ops[3] != 0 { -1 } else { 1 }
            } else {
                0
            };
            let d16 = expand_12a(u64::from(word));
            let zero = k(b, 0);
            let (ea, new_base) = gva(b, ops[0], zero, d16, m);
            let t = ops[1];
            if matches!(insn, Insn::FldwO | Insn::FldwO0) {
                let v: B::V<W32> = b.load(ea, DATA_READ)?;
                let v = b.zext::<W32, W64>(v);
                fpr_set_w(b, t, v);
            } else {
                let v = fpr_get_w(b, t);
                let v = b.trunc::<W64, W32>(v);
                b.store(ea, v, DATA_WRITE)?;
            }
            if m != 0 {
                Gr(ops[0] as u8).set(b, new_base);
            }
        }
        // ---- shift pair（SHRPW/SHRPD = VSHD/SHD）----
        Insn::ShrpSar => {
            // ops = [r2, r1, c, d, t]。d=0 は 32 ビット形
            // （cat(GR[r1]{1..31},GR[r2]{32..63}) >> sar{0..4} の
            // 下位 32 ビット）、d=1 は SHRPD 可変
            // （cat(GR[r1]{1..63},GR[r2]) >> sar の下位 64 ビット）。
            // Ref: SPEC-PARISC-11 §VSHD, SPEC-PARISC-20 §SHRPD/SHRPW.
            let r2 = Gr(ops[0] as u8).get(b);
            let r1 = Gr(ops[1] as u8).get(b);
            let sar = Cr(11).get(b);
            if ops[3] == 0 {
                let sar5 = and_n(b, sar, 31);
                let hi = {
                    let m = and_n(b, r1, 0x7fff_ffff);
                    shl_n(b, m, 32)
                };
                let lo = and_n(b, r2, 0xffff_ffff);
                let cat = b.or(hi, lo);
                let v = b.shr_l(cat, sar5);
                let res = and_n(b, v, 0xffff_ffff);
                Gr(ops[4] as u8).set(b, res);
                sed_nullify(b, ops[2], false, res);
            } else {
                let sar6 = and_n(b, sar, 63);
                let hi = and_n(b, r1, 0x7fff_ffff_ffff_ffff);
                let z = k(b, 0);
                let is0 = b.cmp(Cmp::Eq, sar6, z);
                let s64 = {
                    let m = k(b, 64);
                    b.sub(m, sar6)
                };
                let h = b.shl(hi, s64);
                let l = b.shr_l(r2, sar6);
                let shifted = b.or(h, l);
                let res = b.select::<W64>(is0, r2, shifted);
                Gr(ops[4] as u8).set(b, res);
                sed_nullify(b, ops[2], true, res);
            }
        }
        Insn::ShrpImm => {
            // ops = [r2, r1, c, cpos, t]。SHD/SHRPW 固定:
            // sa = 31 - cpos（cpos は語の値のまま渡される）。
            let r2 = Gr(ops[0] as u8).get(b);
            let r1 = Gr(ops[1] as u8).get(b);
            let sh = 31 - ops[3];
            let hi = {
                let m = and_n(b, r1, 0x7fff_ffff);
                shl_n(b, m, 32)
            };
            let lo = and_n(b, r2, 0xffff_ffff);
            let cat = b.or(hi, lo);
            let v = shr_n(b, cat, sh);
            let res = and_n(b, v, 0xffff_ffff);
            Gr(ops[4] as u8).set(b, res);
            sed_nullify(b, ops[2], false, res);
        }
        Insn::ShrpImmD => {
            // ops = [r2, r1, c, cpos6, t]。SHRPD 固定:
            // sa = 63 - cpos6（cat(cp,cpos) = 63-sa の連結）。
            let r2 = Gr(ops[0] as u8).get(b);
            let r1 = Gr(ops[1] as u8).get(b);
            let sh = 63 - ops[3];
            let hi = and_n(b, r1, 0x7fff_ffff_ffff_ffff);
            let res = if sh == 0 {
                r2
            } else {
                let h = shl_n(b, hi, 64 - sh);
                let l = shr_n(b, r2, sh);
                b.or(h, l)
            };
            Gr(ops[4] as u8).set(b, res);
            sed_nullify(b, ops[2], true, res);
        }
        // ---- extract（EXTR*/EXTRD）----
        Insn::ExtrSar | Insn::ExtrSarD => {
            // ops = [r, t, c, se, clen]。可変形は pos = SAR
            // （32 ビット形は {1..5} の 5 ビットだけを見る）。
            let r = Gr(ops[0] as u8).get(b);
            let sar = Cr(11).get(b);
            let d = insn == Insn::ExtrSarD;
            let len = if d { assemble_6(ops[4]) } else { 32 - ops[4] };
            let pos = and_n(b, sar, if d { 63 } else { 31 });
            let res = do_extr(b, r, pos, len, ops[3] != 0, d);
            Gr(ops[1] as u8).set(b, res);
            sed_nullify(b, ops[2], d, res);
        }
        Insn::ExtrImm | Insn::ExtrImmD => {
            // ops = [r, t, c, se, pos, clen]。pos は HP 位置を
            // そのまま持つ（EXTR*/EXTRD 固定形は補数でない。
            // SPEC-PARISC-11 付録D Table D-8、SPEC-PARISC-20 §EXTRD）。
            let r = Gr(ops[0] as u8).get(b);
            let d = insn == Insn::ExtrImmD;
            let len = if d { assemble_6(ops[5]) } else { 32 - ops[5] };
            let pos = k(b, ops[4]);
            let res = do_extr(b, r, pos, len, ops[3] != 0, d);
            Gr(ops[1] as u8).set(b, res);
            sed_nullify(b, ops[2], d, res);
        }
        // ---- deposit（VDEP/DEP/ZVDEP/ZDEP、DEPD/DEPW）----
        Insn::DepSar | Insn::DepSarD => {
            // ops = [t, r, c, nz, clen]。可変形は tpos = SAR。
            // nz=0 は ZVDEP/ZDEP 系（併合先を先に 0 化）。
            let t = Gr(ops[0] as u8).get(b);
            let r = Gr(ops[1] as u8).get(b);
            let sar = Cr(11).get(b);
            let d = insn == Insn::DepSarD;
            let len = if d { assemble_6(ops[4]) } else { 32 - ops[4] };
            let tpos = and_n(b, sar, if d { 63 } else { 31 });
            let res = do_dep(b, t, tpos, r, len, ops[3] != 0, d);
            Gr(ops[0] as u8).set(b, res);
            sed_nullify(b, ops[2], d, res);
        }
        Insn::DepImm | Insn::DepImmD => {
            // ops = [t, r, c, nz, cpos, clen]。語の位置桁は
            // cp = 31-p / cat(cp,cpos) = 63-pos をそのまま持つので、
            // HP 位置へ戻すと LSB シフト量と一致する。
            let t = Gr(ops[0] as u8).get(b);
            let r = Gr(ops[1] as u8).get(b);
            let d = insn == Insn::DepImmD;
            let len = if d { assemble_6(ops[5]) } else { 32 - ops[5] };
            let tpos = k(b, if d { 63 - ops[4] } else { 31 - ops[4] });
            let res = do_dep(b, t, tpos, r, len, ops[3] != 0, d);
            Gr(ops[0] as u8).set(b, res);
            sed_nullify(b, ops[2], d, res);
        }
        Insn::DepiSar => {
            // ops = [t, i, c, nz, d, len6a]。d=0 は ZVDEPI/VDEPI
            // （32 ビット形）、d=1 は DEPDI 可変（len6a の cl が
            // 立つ）。i は im5_16 の low_sign_ext 即値。
            // 語形は `len ← assemble_6(0,clen)`（SPEC-PARISC-20
            // §DEPWI operation）なので len6a の cl 桁は見ない
            // （d=0 かつ cl=1 は未定義だが、spec 式どおり cl を
            // 無視する決定的な値として評価する）。
            // Ref: SPEC-PARISC-20 §7-43 DEPWI.
            let t = Gr(ops[0] as u8).get(b);
            let src = k(b, im5(ops[1]));
            let sar = Cr(11).get(b);
            let d = ops[4] != 0;
            let len = if d {
                assemble_6(ops[5])
            } else {
                32 - (ops[5] & 31)
            };
            let tpos = and_n(b, sar, if d { 63 } else { 31 });
            let res = do_dep(b, t, tpos, src, len, ops[3] != 0, d);
            Gr(ops[0] as u8).set(b, res);
            sed_nullify(b, ops[2], d, res);
        }
        Insn::DepiImm | Insn::DepiImmD => {
            // ops = [t, i, c, nz, cpos, clen]。ZDEPI/DEPI 系と
            // DEPDI 固定形。
            let t = Gr(ops[0] as u8).get(b);
            let src = k(b, im5(ops[1]));
            let d = insn == Insn::DepiImmD;
            let len = if d { assemble_6(ops[5]) } else { 32 - ops[5] };
            let tpos = k(b, if d { 63 - ops[4] } else { 31 - ops[4] });
            let res = do_dep(b, t, tpos, src, len, ops[3] != 0, d);
            Gr(ops[0] as u8).set(b, res);
            sed_nullify(b, ops[2], d, res);
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
            // LDSID: GR[t] ← space_select(s, GR[b])。s!=0 は
            // SR[s]、s=0 は GR[b] の上位 2 ビット + 4 の SR を読む。
            // PSW.W=0 モデルでは空間選択は 32 ビットオフセットの
            // 最上位 2 ビット（base{32..33}＝LSB 起算の bits30-31）
            // を見る（SPEC-PARISC-11 §space_select,
            // SPEC-PARISC-20 付録E space_select）。本モデルは
            // SR 上位 32 ビットに空間番号を格納する。
            let id = if ops[1] != 0 {
                Sr(ops[1] as u8).get(b)
            } else {
                let base = Gr(ops[0] as u8).get(b);
                let hi = shr_n(b, base, 30);
                let hi = and_n(b, hi, 3);
                let two = k(b, 2);
                let s4 = Sr(4).get(b);
                let s5 = Sr(5).get(b);
                let s6 = Sr(6).get(b);
                let s7 = Sr(7).get(b);
                let one = k(b, 1);
                let is1 = b.cmp(Cmp::Eq, hi, one);
                let lo = b.select::<W64>(is1, s5, s4);
                let three = k(b, 3);
                let is3 = b.cmp(Cmp::Eq, hi, three);
                let hi2 = b.select::<W64>(is3, s7, s6);
                let low = b.cmp(Cmp::LtU, hi, two);
                b.select::<W64>(low, lo, hi2)
            };
            let v = shr_n(b, id, 32);
            Gr(ops[2] as u8).set(b, v);
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
            // MTSM は PSW システムマスクへの移動で、SAR とは無関係。
            // 最上位特権のみ実行可のためユーザモデルでは privileged
            // operation trap とする（SPEC-PARISC-11 §MTSM:
            // `if (priv != 0) privileged_operation_trap`、
            // SPEC-PARISC-20 §MTSM 同文）。
            return Err(raise::<B>(b, ExceptionKind::Trap, TRAP_PRIV));
        }
        Insn::Mtsarcm => {
            // CR[11] ← ~GR[r]{26..31}：SAR は 6 ビットレジスタ。
            // Ref: SPEC-PARISC-20 §MTSARCM.
            let s = Gr(ops[0] as u8).get(b);
            let n = b.not(s);
            let v = and_n(b, n, 63);
            Cr(11).set(b, v);
        }
        Insn::Mfctl => {
            // ops = [ctl, e(,w), t]。SAR は ,w なしで 5 ビット形
            // `GR[t] ← CR[11]{1..5}`（6 ビット SAR の下位 5 ビット）、
            // ,w 付きでは SAR 全体を返す。cr1・26/27 は読める。
            // Ref: SPEC-PARISC-20 §MFCTL.
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
            // `CR[11] ← GR[r]{26..31}`：SAR は 6 ビットレジスタ。
            // PA 1.1 では SAR は 5 ビット（CR[11] ← GR[r]{27..31}）
            // だが、語形の読み手は全て下位 5 ビットだけ見るので、
            // 6 ビット格納でも PA 1.1 の観測可能な動作は変わらない。
            // Ref: SPEC-PARISC-20 §MTCTL, SPEC-PARISC-11 §MTCTL.
            let (ctl, r) = (ops[0], ops[1]);
            if ctl == 11 {
                let s = Gr(r as u8).get(b);
                let v = and_n(b, s, 63);
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
        | Insn::IxtlbxD
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
