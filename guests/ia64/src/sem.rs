// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 の命令意味論（段階21 IA5）。
//!
//! 具体値インタプリタ（`InterpBackend`）上で動く。IA5 は整数・
//! 比較・シフト・multimedia・述語テスト・レジスタ転送系を実装し、
//! メモリ系・FP・分岐（`br.cond.sptk.few` 以外）・RSE/ALAT 系は
//! 後段の段階に譲る。NaT は伝播だけを入れ、消費フォールトの
//! 本格対応は IA6 が担う（mov の AR/BR/PR 書き込みだけは建築の
//! 消費チェックに倣い `TRAP_NAT` を返す骨格を入れる）。
//! 対象は Linux ユーザモード。単一スレッド・コヒーレントモデル
//! なので `mf`/`srlz`/`sync.i`/`fc`/`fwb` は実効のない no-op として
//! 扱う。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::interp::{Ctrl, InterpBackend, InterpExit};
use polyisa_sem::{ExceptionKind, GuestException, StateRef, W64};

use crate::{CpuState, Insn, ar, extract_ops};

/// `handle_trap` に渡る内部番号。`break` は即値（immu21/imm62）を
/// そのまま code に載せるため、ぶつからない値を不正命令用に取る。
pub const TRAP_ILL: u64 = u64::MAX;
/// NaT 消費フォールトの仮内部番号。本格対応（フォールト種別の
/// 区別）は IA6 が担う。
pub const TRAP_NAT: u64 = u64::MAX - 1;

fn trap(code: u64) -> InterpExit {
    InterpExit::Exception(GuestException {
        kind: ExceptionKind::Trap,
        code,
        addr: None,
        in_delay_slot: false,
    })
}

/// 符号拡張（bits は元の幅）。
fn sext(v: u64, bits: u32) -> u64 {
    let sh = 64 - bits;
    (((v << sh) as i64) >> sh) as u64
}

/// 下位 bits ビットのマスク。
fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn get64(b: &InterpBackend, r: StateRef<W64>) -> u64 {
    let off = r.offset();
    u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"))
}

fn set64(b: &mut InterpBackend, r: StateRef<W64>, v: u64) {
    let off = r.offset();
    b.state[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// GR r_i の状態面。
#[must_use]
pub fn gr_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, gr) + (i as usize) * 8)
}

/// GR r_i の値。r0 は常に 0。
#[must_use]
pub fn gr_get(b: &InterpBackend, i: u32) -> u64 {
    if i == 0 { 0 } else { get64(b, gr_ref(i)) }
}

/// GR r_i への代入。r0 への書き込みは捨てる。
pub fn gr_set(b: &mut InterpBackend, i: u32, v: u64) {
    if i != 0 {
        set64(b, gr_ref(i), v);
    }
}

fn nat_off(i: u32) -> (usize, u64) {
    (
        core::mem::offset_of!(CpuState, gr_nat) + (i as usize / 64) * 8,
        1u64 << (i % 64),
    )
}

/// GR r_i の NaT ビット。
#[must_use]
pub fn nat_get(b: &InterpBackend, i: u32) -> bool {
    let (off, mask) = nat_off(i);
    let v = u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"));
    v & mask != 0
}

/// GR r_i の NaT ビットの代入。r0 分は値と同じく捨てる
/// （r0 は NaT を持たない）。
pub fn nat_set(b: &mut InterpBackend, i: u32, nat: bool) {
    if i == 0 {
        return;
    }
    let (off, mask) = nat_off(i);
    let mut v = u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"));
    if nat {
        v |= mask;
    } else {
        v &= !mask;
    }
    b.state[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// GR 値と NaT をまとめて書く。
fn wr_gr(b: &mut InterpBackend, i: u32, v: u64, nat: bool) {
    gr_set(b, i, v);
    nat_set(b, i, nat);
}

fn nat2(b: &InterpBackend, x: u32, y: u32) -> bool {
    nat_get(b, x) || nat_get(b, y)
}

/// 述語レジスタの面。
#[must_use]
pub fn pr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pr))
}

/// 述語レジスタのマスク。p0 は常に 1。
#[must_use]
pub fn pr_get(b: &InterpBackend) -> u64 {
    get64(b, pr_ref()) | 1
}

/// 述語レジスタの代入。p0 は常に 1。
pub fn pr_set(b: &mut InterpBackend, v: u64) {
    set64(b, pr_ref(), v | 1);
}

/// 述語 p_i の値。
#[must_use]
pub fn pred(b: &InterpBackend, i: u32) -> bool {
    (pr_get(b) >> i) & 1 != 0
}

/// 述語 p_i への代入（p0 は `pr_set` が 1 に保つ）。
fn pr_bit(b: &mut InterpBackend, i: u32, v: bool) {
    let mut p = pr_get(b);
    if v {
        p |= 1u64 << i;
    } else {
        p &= !(1u64 << i);
    }
    pr_set(b, p);
}

/// BR b_i の状態面。
#[must_use]
pub fn br_ref(i: u32) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, br) + (i as usize) * 8)
}

/// 命令ポインタの面。
#[must_use]
pub fn ip_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ip))
}

/// CFM の面。
#[must_use]
pub fn cfm_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cfm))
}

/// PSR{5:0}（ユーザマスク）の面。
#[must_use]
pub fn psr_um_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, psr_um))
}

/// AR 番号 → CpuState 面。ユーザ可視分だけを持つ（残りは後段の
/// 段階で拡張する）。
fn ar_ref(i: u64) -> Option<StateRef<W64>> {
    use core::mem::offset_of as off;
    let a = u8::try_from(i).ok()?;
    let off = match a {
        ar::RSC => off!(CpuState, rsc),
        ar::BSP => off!(CpuState, bsp),
        ar::BSPSTORE => off!(CpuState, bspstore),
        ar::RNAT => off!(CpuState, rnat),
        ar::CCV => off!(CpuState, ccv),
        ar::UNAT => off!(CpuState, unat),
        ar::FPSR => off!(CpuState, fpsr),
        ar::ITC => off!(CpuState, itc),
        ar::PFS => off!(CpuState, pfs),
        ar::LC => off!(CpuState, lc),
        ar::EC => off!(CpuState, ec),
        _ => return None,
    };
    Some(StateRef::<W64>::from_offset(off))
}

/// RSC.mode（rsc{1:0}）が非ゼロ。mode!=0 のとき bspstore/rnat の
/// 読み書きは不正命令（mov to/from AR の規則）。
fn rsc_mode_set(b: &InterpBackend) -> bool {
    get64(b, ar_ref(ar::RSC as u64).expect("rsc")) & 3 != 0
}

/// I 形式の mov to/from AR が触れる AR 集合（pfs/lc/ec）。
fn ar_i_ok(i: u64) -> bool {
    matches!(u8::try_from(i).ok(), Some(ar::PFS | ar::LC | ar::EC))
}

/// mov from AR。未収録・不正な AR は TRAP_ILL。
fn ar_read(b: &InterpBackend, i: u64, i_form: bool) -> Result<u64, InterpExit> {
    if i_form && !ar_i_ok(i) {
        return Err(trap(TRAP_ILL));
    }
    let a = u8::try_from(i).map_err(|_| trap(TRAP_ILL))?;
    // bspstore/rnat は RSC.mode!=0 で読み出し不可。
    if matches!(a, ar::BSPSTORE | ar::RNAT) && rsc_mode_set(b) {
        return Err(trap(TRAP_ILL));
    }
    match ar_ref(i) {
        Some(r) => Ok(get64(b, r)),
        None => Err(trap(TRAP_ILL)),
    }
}

/// mov to AR。itc は読み取り専用、rsc/bsp はカーネル AR（ユーザ
/// モードでは特権フォールト）、bspstore/rnat は RSC.mode!=0 で
/// 不正、bspstore への書き込みは bsp も更新する（rnat は建築上
/// 不定のため据え置き）。
fn ar_write(b: &mut InterpBackend, i: u64, v: u64, i_form: bool) -> Result<(), InterpExit> {
    if i_form && !ar_i_ok(i) {
        return Err(trap(TRAP_ILL));
    }
    let a = u8::try_from(i).map_err(|_| trap(TRAP_ILL))?;
    if matches!(a, ar::ITC | ar::RSC | ar::BSP) {
        return Err(trap(TRAP_ILL));
    }
    if matches!(a, ar::BSPSTORE | ar::RNAT) && rsc_mode_set(b) {
        return Err(trap(TRAP_ILL));
    }
    match ar_ref(i) {
        Some(r) => {
            set64(b, r, v);
            if a == ar::BSPSTORE {
                set64(b, ar_ref(ar::BSP as u64).expect("bsp"), v);
            }
            Ok(())
        }
        None => Err(trap(TRAP_ILL)),
    }
}

// ---- 並列要素演算の下ごしらえ ----

/// 要素 e（幅 bits、LSB 側が 0 番）を取り出す。
fn elem(v: u64, bits: u32, e: u32) -> u64 {
    (v >> (e * bits)) & mask(bits)
}

/// 幅 bits の並列写像。各要素に f(x_elem, y_elem) を適用する
/// （結果は要素幅に切る）。
fn pelem(x: u64, y: u64, bits: u32, f: impl Fn(u64, u64) -> u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0u32;
    while i < 64 {
        out |= (f(elem(x, bits, i / bits), elem(y, bits, i / bits)) & mask(bits)) << i;
        i += bits;
    }
    out
}

/// 要素値を符号つきで読む。
fn selem(v: u64, bits: u32, e: u32) -> i64 {
    sext(elem(v, bits, e), bits) as i64
}

/// 幅 bits の符号つき飽和。
fn sat(v: i64, bits: u32) -> u64 {
    let (lo, hi) = (-(1i64 << (bits - 1)), (1i64 << (bits - 1)) - 1);
    v.clamp(lo, hi) as u64 & mask(bits)
}

/// 幅 bits の符号なし飽和。
fn sat_u(v: i64, bits: u32) -> u64 {
    v.clamp(0, mask(bits) as i64) as u64
}

/// pack 用の飽和選択（.uss は符号なし、それ以外は符号つき）。
fn sat_or(v: i64, bits: u32, unsigned: bool) -> u64 {
    if unsigned {
        sat_u(v, bits)
    } else {
        sat(v, bits)
    }
}

/// mix: 幅 bits で x/y の奇数（.l、MSB 側ペア）・偶数（.r、LSB 側ペア）
/// 要素を y→x の順に交互に並べる。
fn pmix(x: u64, y: u64, bits: u32, odd: bool) -> u64 {
    let n = 64 / bits;
    let mut out = 0u64;
    for j in 0..n / 2 {
        let e = 2 * j + u32::from(odd);
        out |= elem(y, bits, e) << (bits * 2 * j);
        out |= elem(x, bits, e) << (bits * (2 * j + 1));
    }
    out
}

/// unpack: x/y の上半分（.h）または下半分（.l）の要素を交互に
/// 並べる。
fn punpack(x: u64, y: u64, bits: u32, hi: bool) -> u64 {
    let n = 64 / bits;
    let base = if hi { n / 2 } else { 0 };
    let mut out = 0u64;
    for j in 0..n / 2 {
        out |= elem(y, bits, base + j) << (bits * 2 * j);
        out |= elem(x, bits, base + j) << (bits * (2 * j + 1));
    }
    out
}

/// czx のスキャン方向のゼロ要素番号。左（MSB 側）から数えるか。
fn czx(v: u64, bits: u32, from_msb: bool) -> u64 {
    let n = 64 / bits;
    for j in 0..n {
        let e = if from_msb { n - 1 - j } else { j };
        if elem(v, bits, e) == 0 {
            return u64::from(j);
        }
    }
    u64::from(n)
}

/// addp4/shladdp4 の上位合成。下位 32 ビットに切り、r3 の
/// {31:30} を {62:61} に移す。
fn addp4_res(tmp: u64, r3: u64) -> u64 {
    (tmp & 0xffff_ffff) | ((r3 >> 30 & 3) << 61)
}

// ---- cmp/tbit/tnat/tf の述語更新 ----

/// 比較・テスト系の ctype（述語更新種別）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum CTy {
    /// 通常形（p1=rel, p2=!rel）。
    Norm,
    /// .unc（qp 偽でも p1=p2=0）。
    Unc,
    /// .and（rel 偽・NaT で両方 0、真で変更なし）。
    And,
    /// .or（rel 真で両方 1、偽・NaT で変更なし）。
    Or,
    /// .or.andcm（rel 真で p1=1,p2=0、偽・NaT で変更なし）。
    OrAndcm,
}

/// 整数比較の関係。leu/gtu/geu は建築に命令がなく
/// （leu ⇔ geu の入れ替え疑似形）、宣言もないため置かない。
#[derive(Clone, Copy)]
enum Rel {
    Eq,
    Ne,
    Lt,
    Ltu,
    Le,
    Gt,
    Ge,
}

/// 比較のソース形。
#[derive(Clone, Copy)]
enum CmpSrc {
    /// r2 対 r3。
    Reg,
    /// imm8 対 r3。
    Imm,
    /// r3 対 0（並列不等号形。関係名は正本 Table2-17 の
    /// 「a rel 0」疑似形式。例 `cmp.lt.and p1,p2 = r3, r0` は
    /// r3<0 を試す）。
    Zero,
}

fn rel_eval(rel: Rel, a: u64, b: u64, w4: bool) -> bool {
    if w4 {
        let (x, y) = (a as u32, b as u32);
        let (sx, sy) = (x as i32, y as i32);
        match rel {
            Rel::Eq => x == y,
            Rel::Ne => x != y,
            Rel::Lt => sx < sy,
            Rel::Ltu => x < y,
            Rel::Le => sx <= sy,
            Rel::Gt => sx > sy,
            Rel::Ge => sx >= sy,
        }
    } else {
        match rel {
            Rel::Eq => a == b,
            Rel::Ne => a != b,
            Rel::Lt => (a as i64) < (b as i64),
            Rel::Ltu => a < b,
            Rel::Le => (a as i64) <= (b as i64),
            Rel::Gt => (a as i64) > (b as i64),
            Rel::Ge => (a as i64) >= (b as i64),
        }
    }
}

/// cmp/cmp4 の（cmp4 か, 関係, ctype, ソース形）。
fn cmp_kind(i: Insn) -> Option<(bool, Rel, CTy, CmpSrc)> {
    use CmpSrc::*;
    use Insn::*;
    use Rel::*;
    Some(match i {
        // ---- op C: lt 系・.and 型。
        CmpLt => (false, Lt, CTy::Norm, Reg),
        CmpLtUnc => (false, Lt, CTy::Unc, Reg),
        CmpEqAnd => (false, Eq, CTy::And, Reg),
        CmpNeAnd => (false, Ne, CTy::And, Reg),
        CmpLtI => (false, Lt, CTy::Norm, Imm),
        CmpLtUncI => (false, Lt, CTy::Unc, Imm),
        CmpEqAndI => (false, Eq, CTy::And, Imm),
        CmpNeAndI => (false, Ne, CTy::And, Imm),
        Cmp4Lt => (true, Lt, CTy::Norm, Reg),
        Cmp4LtUnc => (true, Lt, CTy::Unc, Reg),
        Cmp4EqAnd => (true, Eq, CTy::And, Reg),
        Cmp4NeAnd => (true, Ne, CTy::And, Reg),
        Cmp4LtI => (true, Lt, CTy::Norm, Imm),
        Cmp4LtUncI => (true, Lt, CTy::Unc, Imm),
        Cmp4EqAndI => (true, Eq, CTy::And, Imm),
        Cmp4NeAndI => (true, Ne, CTy::And, Imm),
        // ---- op D: ltu 系・.or 型。
        CmpLtu => (false, Ltu, CTy::Norm, Reg),
        CmpLtuUnc => (false, Ltu, CTy::Unc, Reg),
        CmpEqOr => (false, Eq, CTy::Or, Reg),
        CmpNeOr => (false, Ne, CTy::Or, Reg),
        CmpLtuI => (false, Ltu, CTy::Norm, Imm),
        CmpLtuUncI => (false, Ltu, CTy::Unc, Imm),
        CmpEqOrI => (false, Eq, CTy::Or, Imm),
        CmpNeOrI => (false, Ne, CTy::Or, Imm),
        Cmp4Ltu => (true, Ltu, CTy::Norm, Reg),
        Cmp4LtuUnc => (true, Ltu, CTy::Unc, Reg),
        Cmp4EqOr => (true, Eq, CTy::Or, Reg),
        Cmp4NeOr => (true, Ne, CTy::Or, Reg),
        Cmp4LtuI => (true, Ltu, CTy::Norm, Imm),
        Cmp4LtuUncI => (true, Ltu, CTy::Unc, Imm),
        Cmp4EqOrI => (true, Eq, CTy::Or, Imm),
        Cmp4NeOrI => (true, Ne, CTy::Or, Imm),
        // ---- op E: eq 系・.or.andcm 型。
        CmpEq => (false, Eq, CTy::Norm, Reg),
        CmpEqUnc => (false, Eq, CTy::Unc, Reg),
        CmpEqOrAndcm => (false, Eq, CTy::OrAndcm, Reg),
        CmpNeOrAndcm => (false, Ne, CTy::OrAndcm, Reg),
        CmpEqI => (false, Eq, CTy::Norm, Imm),
        CmpEqUncI => (false, Eq, CTy::Unc, Imm),
        CmpEqOrAndcmI => (false, Eq, CTy::OrAndcm, Imm),
        CmpNeOrAndcmI => (false, Ne, CTy::OrAndcm, Imm),
        Cmp4Eq => (true, Eq, CTy::Norm, Reg),
        Cmp4EqUnc => (true, Eq, CTy::Unc, Reg),
        Cmp4EqOrAndcm => (true, Eq, CTy::OrAndcm, Reg),
        Cmp4NeOrAndcm => (true, Ne, CTy::OrAndcm, Reg),
        Cmp4EqI => (true, Eq, CTy::Norm, Imm),
        Cmp4EqUncI => (true, Eq, CTy::Unc, Imm),
        Cmp4EqOrAndcmI => (true, Eq, CTy::OrAndcm, Imm),
        Cmp4NeOrAndcmI => (true, Ne, CTy::OrAndcm, Imm),
        // ---- 並列形（r2=0 固定、「a rel 0」疑似形式の関係名）。
        CmpLtAnd => (false, Lt, CTy::And, Zero),
        CmpGeAnd => (false, Ge, CTy::And, Zero),
        CmpLeAnd => (false, Le, CTy::And, Zero),
        CmpGtAnd => (false, Gt, CTy::And, Zero),
        CmpLtOr => (false, Lt, CTy::Or, Zero),
        CmpGeOr => (false, Ge, CTy::Or, Zero),
        CmpLeOr => (false, Le, CTy::Or, Zero),
        CmpGtOr => (false, Gt, CTy::Or, Zero),
        CmpLtOrAndcm => (false, Lt, CTy::OrAndcm, Zero),
        CmpGeOrAndcm => (false, Ge, CTy::OrAndcm, Zero),
        CmpLeOrAndcm => (false, Le, CTy::OrAndcm, Zero),
        CmpGtOrAndcm => (false, Gt, CTy::OrAndcm, Zero),
        Cmp4LtAnd => (true, Lt, CTy::And, Zero),
        Cmp4GeAnd => (true, Ge, CTy::And, Zero),
        Cmp4LeAnd => (true, Le, CTy::And, Zero),
        Cmp4GtAnd => (true, Gt, CTy::And, Zero),
        Cmp4LtOr => (true, Lt, CTy::Or, Zero),
        Cmp4GeOr => (true, Ge, CTy::Or, Zero),
        Cmp4LeOr => (true, Le, CTy::Or, Zero),
        Cmp4GtOr => (true, Gt, CTy::Or, Zero),
        Cmp4LtOrAndcm => (true, Lt, CTy::OrAndcm, Zero),
        Cmp4GeOrAndcm => (true, Ge, CTy::OrAndcm, Zero),
        Cmp4LeOrAndcm => (true, Le, CTy::OrAndcm, Zero),
        Cmp4GtOrAndcm => (true, Gt, CTy::OrAndcm, Zero),
        _ => return None,
    })
}

/// テストビット系の対象。
#[derive(Clone, Copy)]
enum TKind {
    /// GR の指定位。
    Tbit,
    /// GR の NaT ビット。
    Tnat,
    /// cpuid[4] の feature ビット（32-63 は現状未定義で 0）。
    Tf,
}

/// tbit/tnat/tf の（対象, nz 極性, ctype）。非並列の z/.unc 形は
/// 極性 false で、並列形は c が z/nz。
fn test_kind(i: Insn) -> Option<(TKind, bool, CTy)> {
    use Insn::*;
    use TKind::*;
    Some(match i {
        TbitZ => (Tbit, false, CTy::Norm),
        TbitZUnc => (Tbit, false, CTy::Unc),
        TbitZAnd => (Tbit, false, CTy::And),
        TbitNzAnd => (Tbit, true, CTy::And),
        TbitZOr => (Tbit, false, CTy::Or),
        TbitNzOr => (Tbit, true, CTy::Or),
        TbitZOrAndcm => (Tbit, false, CTy::OrAndcm),
        TbitNzOrAndcm => (Tbit, true, CTy::OrAndcm),
        TnatZ => (Tnat, false, CTy::Norm),
        TnatZUnc => (Tnat, false, CTy::Unc),
        TnatZAnd => (Tnat, false, CTy::And),
        TnatNzAnd => (Tnat, true, CTy::And),
        TnatZOr => (Tnat, false, CTy::Or),
        TnatNzOr => (Tnat, true, CTy::Or),
        TnatZOrAndcm => (Tnat, false, CTy::OrAndcm),
        TnatNzOrAndcm => (Tnat, true, CTy::OrAndcm),
        TfZ => (Tf, false, CTy::Norm),
        TfZUnc => (Tf, false, CTy::Unc),
        TfZAnd => (Tf, false, CTy::And),
        TfNzAnd => (Tf, true, CTy::And),
        TfZOr => (Tf, false, CTy::Or),
        TfNzOr => (Tf, true, CTy::Or),
        TfZOrAndcm => (Tf, false, CTy::OrAndcm),
        TfNzOrAndcm => (Tf, true, CTy::OrAndcm),
        _ => return None,
    })
}

/// qp 偽でも p1=p2=0 に沈める .unc 型か。
fn is_unc(i: Insn) -> bool {
    matches!(
        i,
        Insn::CmpLtUnc
            | Insn::CmpLtuUnc
            | Insn::CmpEqUnc
            | Insn::Cmp4LtUnc
            | Insn::Cmp4LtuUnc
            | Insn::Cmp4EqUnc
            | Insn::CmpLtUncI
            | Insn::CmpLtuUncI
            | Insn::CmpEqUncI
            | Insn::Cmp4LtUncI
            | Insn::Cmp4LtuUncI
            | Insn::Cmp4EqUncI
            | Insn::TbitZUnc
            | Insn::TnatZUnc
            | Insn::TfZUnc
    )
}

/// cmp/tbit/tnat/tf の PR 対更新。`rel` は評価した関係の真偽、
/// `nat` はオペランドの NaT（and/or/or.andcm では結果を留める
/// 条件に入る）。
fn pr_pair_update(b: &mut InterpBackend, p1: u32, p2: u32, ty: CTy, rel: bool, nat: bool) {
    match ty {
        CTy::And => {
            if nat || !rel {
                pr_bit(b, p1, false);
                pr_bit(b, p2, false);
            }
        }
        CTy::Or => {
            if !nat && rel {
                pr_bit(b, p1, true);
                pr_bit(b, p2, true);
            }
        }
        CTy::OrAndcm => {
            if !nat && rel {
                pr_bit(b, p1, true);
                pr_bit(b, p2, false);
            }
        }
        CTy::Norm | CTy::Unc => {
            if nat {
                pr_bit(b, p1, false);
                pr_bit(b, p2, false);
            } else {
                pr_bit(b, p1, rel);
                pr_bit(b, p2, !rel);
            }
        }
    }
}

/// cmp/cmp4 の実行。ops は extract_ops の結果
/// （[qp, p1, p2, ソース…]）。
fn exec_cmp(
    b: &mut InterpBackend,
    k: (bool, Rel, CTy, CmpSrc),
    ops: &[u64],
) -> Result<(), InterpExit> {
    let (w4, rel, ty, src) = k;
    let (p1, p2) = (ops[1] as u32, ops[2] as u32);
    if p1 == p2 {
        return Err(trap(TRAP_ILL));
    }
    let (a, bv, nat) = match src {
        CmpSrc::Reg => (
            gr_get(b, ops[3] as u32),
            gr_get(b, ops[4] as u32),
            nat2(b, ops[3] as u32, ops[4] as u32),
        ),
        CmpSrc::Imm => (
            sext(ops[3], 8),
            gr_get(b, ops[4] as u32),
            nat_get(b, ops[4] as u32),
        ),
        CmpSrc::Zero => (gr_get(b, ops[3] as u32), 0, nat_get(b, ops[3] as u32)),
    };
    let r = rel_eval(rel, a, bv, w4);
    pr_pair_update(b, p1, p2, ty, r, nat);
    Ok(())
}

/// tbit/tnat/tf の実行。tbit は pos6 即値のビット、tnat は r3 の
/// NaT、tf は cpuid[4] の feature（32-63 は未定義で常に 0）。
fn exec_test(b: &mut InterpBackend, k: (TKind, bool, CTy), ops: &[u64]) -> Result<(), InterpExit> {
    let (kind, nz, ty) = k;
    let (p1, p2) = (ops[1] as u32, ops[2] as u32);
    if p1 == p2 {
        return Err(trap(TRAP_ILL));
    }
    let r3 = ops[3] as u32;
    let (bit, nat) = match kind {
        TKind::Tbit => ((gr_get(b, r3) >> ops[4]) & 1 != 0, nat_get(b, r3)),
        TKind::Tnat => (nat_get(b, r3), false),
        TKind::Tf => (false, false),
    };
    let r = if nz { bit } else { !bit };
    pr_pair_update(b, p1, p2, ty, r, nat);
    Ok(())
}

/// 1 スロットぶんの意味論。`ip` はこの命令の命令ポインタ（下位
/// 4 ビットがスロット番号）、`word` はスロット語（41 ビット。
/// X 系は 82 ビット）。修飾述語 qp（word[5:0]）が偽なら意味論を
/// 実行せず `Ok(false)` で進む。ただし .unc 型の比較・テスト系は
/// qp 偽でも p1=p2=0 に沈める（p1==p2 は不正命令）。
/// `Ok(true)` は意味論を実行したこと。
pub fn exec(b: &mut InterpBackend, insn: Insn, word: u128, ip: u64) -> Result<bool, InterpExit> {
    let ops = extract_ops(insn, word);
    if !pred(b, (word & 0x3f) as u32) {
        if is_unc(insn) {
            let (p1, p2) = (ops[1] as u32, ops[2] as u32);
            if p1 == p2 {
                return Err(trap(TRAP_ILL));
            }
            pr_bit(b, p1, false);
            pr_bit(b, p2, false);
            return Ok(true);
        }
        return Ok(false);
    }
    match insn {
        Insn::NopI
        | Insn::NopF
        | Insn::NopM
        | Insn::NopB
        | Insn::NopX
        | Insn::HintI
        | Insn::HintF
        | Insn::HintM
        | Insn::HintB
        | Insn::HintX => {}
        Insn::BreakI | Insn::BreakF | Insn::BreakM | Insn::BreakB | Insn::BreakX => {
            // code は即値。0x100000（__IA64_BREAK_SYSCALL）の意味は
            // OS パーソナリティ側（IA10/IA11）が解釈する。
            return Err(trap(ops[1]));
        }
        // ---- A1: 3 項 ALU・addp4。
        Insn::Add | Insn::Add1 | Insn::Sub | Insn::Sub1 | Insn::Addp4 => {
            let (x, y) = (gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32));
            let v = match insn {
                Insn::Add => x.wrapping_add(y),
                Insn::Add1 => x.wrapping_add(y).wrapping_add(1),
                Insn::Sub => x.wrapping_sub(y),
                Insn::Sub1 => x.wrapping_sub(y).wrapping_sub(1),
                _ => addp4_res(x.wrapping_add(y), y),
            };
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::And | Insn::Andcm | Insn::Or | Insn::Xor => {
            let (x, y) = (gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32));
            let v = match insn {
                Insn::And => x & y,
                Insn::Andcm => x & !y,
                Insn::Or => x | y,
                _ => x ^ y,
            };
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        // ---- A2: imm8 2 項。
        Insn::SubImm8 | Insn::AndImm8 | Insn::AndcmImm8 | Insn::OrImm8 | Insn::XorImm8 => {
            let x = sext(ops[2], 8);
            let y = gr_get(b, ops[3] as u32);
            let v = match insn {
                Insn::SubImm8 => x.wrapping_sub(y),
                Insn::AndImm8 => x & y,
                Insn::AndcmImm8 => x & !y,
                Insn::OrImm8 => x | y,
                _ => x ^ y,
            };
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[3] as u32));
        }
        // ---- A3/A5: imm14/imm22 加算。
        Insn::Adds | Insn::Addl => {
            let bits = if insn == Insn::Adds { 14 } else { 22 };
            let v = sext(ops[2], bits).wrapping_add(gr_get(b, ops[3] as u32));
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[3] as u32));
        }
        Insn::Addp4I => {
            let y = gr_get(b, ops[3] as u32);
            let v = addp4_res(sext(ops[2], 14).wrapping_add(y), y);
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[3] as u32));
        }
        // ---- A8: shladd / shladdp4。count2a は field+1。
        Insn::Shladd | Insn::Shladdp4 => {
            let x = gr_get(b, ops[2] as u32);
            let y = gr_get(b, ops[4] as u32);
            let t = (x << (ops[3] + 1)).wrapping_add(y);
            let v = if insn == Insn::Shladdp4 {
                addp4_res(t, y)
            } else {
                t
            };
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[4] as u32));
        }
        // ---- A9: multimedia ALU（並列加減算・平均・比較）。
        Insn::Padd1 | Insn::Padd2 | Insn::Padd4 | Insn::Psub1 | Insn::Psub2 | Insn::Psub4 => {
            let (bits, sub) = match insn {
                Insn::Padd1 => (8, false),
                Insn::Padd2 => (16, false),
                Insn::Padd4 => (32, false),
                Insn::Psub1 => (8, true),
                Insn::Psub2 => (16, true),
                _ => (32, true),
            };
            let f: fn(u64, u64) -> u64 = if sub {
                |a, c| a.wrapping_sub(c)
            } else {
                |a, c| a.wrapping_add(c)
            };
            let v = pelem(gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32), bits, f);
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pavg1 | Insn::Pavg2 | Insn::Pavg1Raz | Insn::Pavg2Raz => {
            let (bits, raz) = match insn {
                Insn::Pavg1 => (8, false),
                Insn::Pavg2 => (16, false),
                Insn::Pavg1Raz => (8, true),
                _ => (16, true),
            };
            let v = pelem(
                gr_get(b, ops[2] as u32),
                gr_get(b, ops[3] as u32),
                bits,
                move |a, c| {
                    if raz {
                        (a + c + 1) >> 1
                    } else {
                        ((a + c) >> 1) | ((a + c) & 1)
                    }
                },
            );
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pavgsub1 | Insn::Pavgsub2 => {
            let bits = if insn == Insn::Pavgsub1 { 8 } else { 16 };
            let v = pelem(
                gr_get(b, ops[2] as u32),
                gr_get(b, ops[3] as u32),
                bits,
                move |a, c| {
                    // 要素幅+1 ビットの符号つき差を半分にする。
                    let d = a.wrapping_sub(c) & mask(bits + 1);
                    (d >> 1) | (d & 1)
                },
            );
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pcmp1Eq
        | Insn::Pcmp2Eq
        | Insn::Pcmp4Eq
        | Insn::Pcmp1Gt
        | Insn::Pcmp2Gt
        | Insn::Pcmp4Gt => {
            let (bits, gt) = match insn {
                Insn::Pcmp1Eq => (8, false),
                Insn::Pcmp2Eq => (16, false),
                Insn::Pcmp4Eq => (32, false),
                Insn::Pcmp1Gt => (8, true),
                Insn::Pcmp2Gt => (16, true),
                _ => (32, true),
            };
            let v = pelem(
                gr_get(b, ops[2] as u32),
                gr_get(b, ops[3] as u32),
                bits,
                move |a, c| {
                    let hit = if gt {
                        (sext(a, bits) as i64) > (sext(c, bits) as i64)
                    } else {
                        a == c
                    };
                    if hit { u64::MAX } else { 0 }
                },
            );
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        // ---- A11: pshladd2/pshradd2（符号飽和つき。count2b=3 は
        // ReservedQP → 不正命令）。
        Insn::Pshladd2 | Insn::Pshradd2 => {
            if ops[3] == 3 {
                return Err(trap(TRAP_ILL));
            }
            let cnt = (ops[3] + 1) as i64;
            let left = insn == Insn::Pshladd2;
            let v = pelem(
                gr_get(b, ops[2] as u32),
                gr_get(b, ops[4] as u32),
                16,
                move |a, c| {
                    let x = sext(a, 16) as i64;
                    let t = if left {
                        // シフト結果をまず 16 ビット符号つき飽和。
                        sext(sat(x << cnt, 16), 16) as i64
                    } else {
                        x >> cnt
                    };
                    sat(t + sext(c, 16) as i64, 16)
                },
            );
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[4] as u32));
        }
        i if cmp_kind(i).is_some() => {
            exec_cmp(b, cmp_kind(i).expect("cmp"), &ops)?;
        }
        i if test_kind(i).is_some() => {
            exec_test(b, test_kind(i).expect("test"), &ops)?;
        }
        // ---- I 系: 拡張・桁操作。
        Insn::Zxt1 | Insn::Zxt2 | Insn::Zxt4 | Insn::Sxt1 | Insn::Sxt2 | Insn::Sxt4 => {
            let bits = match insn {
                Insn::Zxt1 | Insn::Sxt1 => 8,
                Insn::Zxt2 | Insn::Sxt2 => 16,
                _ => 32,
            };
            let v = gr_get(b, ops[2] as u32);
            let v = if matches!(insn, Insn::Zxt1 | Insn::Zxt2 | Insn::Zxt4) {
                v & mask(bits)
            } else {
                sext(v, bits)
            };
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[2] as u32));
        }
        Insn::Czx1L | Insn::Czx2L | Insn::Czx1R | Insn::Czx2R => {
            let (bits, msb) = match insn {
                Insn::Czx1L => (8, true),
                Insn::Czx2L => (16, true),
                Insn::Czx1R => (8, false),
                _ => (16, false),
            };
            let v = czx(gr_get(b, ops[2] as u32), bits, msb);
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[2] as u32));
        }
        Insn::Clz => {
            let v = gr_get(b, ops[2] as u32);
            wr_gr(
                b,
                ops[1] as u32,
                u64::from(v.leading_zeros()),
                nat_get(b, ops[2] as u32),
            );
        }
        Insn::Popcnt => {
            let v = gr_get(b, ops[2] as u32);
            wr_gr(
                b,
                ops[1] as u32,
                u64::from(v.count_ones()),
                nat_get(b, ops[2] as u32),
            );
        }
        // ---- I3/I4: mux。
        Insn::Mux1 | Insn::Mux2 => {
            let x = gr_get(b, ops[2] as u32);
            let sel = ops[3];
            let v = if insn == Insn::Mux1 {
                // mbtype4 は 5 種類の固定置換を選ぶ（それ以外は予約）。
                // 出力バイト番号は LSB→MSB 順（SDM Table 2-41）。
                const PERMS: [[u32; 8]; 5] = [
                    [0, 0, 0, 0, 0, 0, 0, 0], // 0x0 @brcst
                    [0, 4, 2, 6, 1, 5, 3, 7], // 0x8 @mix
                    [0, 4, 1, 5, 2, 6, 3, 7], // 0x9 @shuf
                    [0, 2, 4, 6, 1, 3, 5, 7], // 0xa @alt
                    [7, 6, 5, 4, 3, 2, 1, 0], // 0xb @rev
                ];
                let p = match sel {
                    0 => &PERMS[0],
                    8 => &PERMS[1],
                    9 => &PERMS[2],
                    0xa => &PERMS[3],
                    0xb => &PERMS[4],
                    _ => return Err(trap(TRAP_ILL)),
                };
                let mut out = 0u64;
                for (i, &e) in p.iter().enumerate() {
                    out |= elem(x, 8, e) << (8 * i as u32);
                }
                out
            } else {
                let mut out = 0u64;
                for i in 0..4u32 {
                    let e = (sel >> (2 * i)) & 3;
                    out |= elem(x, 16, e as u32) << (16 * i);
                }
                out
            };
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[2] as u32));
        }
        // ---- I1/I2: MM mix/pack/unpack/min/max/psad/mpy。
        Insn::Mix1R | Insn::Mix1L | Insn::Mix2R | Insn::Mix2L | Insn::Mix4R | Insn::Mix4L => {
            let (bits, odd) = match insn {
                Insn::Mix1R => (8, false),
                Insn::Mix1L => (8, true),
                Insn::Mix2R => (16, false),
                Insn::Mix2L => (16, true),
                Insn::Mix4R => (32, false),
                _ => (32, true),
            };
            let v = pmix(
                gr_get(b, ops[2] as u32),
                gr_get(b, ops[3] as u32),
                bits,
                odd,
            );
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pack2Uss | Insn::Pack2Sss | Insn::Pack4Sss => {
            // pack2 は r2/r3 の符号つき 16 ビット要素を 8 ビットに
            // 飽和、pack4 は符号つき 32 ビット要素を 16 ビットに飽和。
            // 下位半分が r3 側、上位半分が r2 側（concat は MSB 先頭）。
            let (sbits, dbits, unsigned) = match insn {
                Insn::Pack2Uss => (16, 8, true),
                Insn::Pack2Sss => (16, 8, false),
                _ => (32, 16, false),
            };
            let (x, y) = (gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32));
            let n = 64 / (2 * dbits);
            let mut v = 0u64;
            for j in 0..n {
                let lo = sat_or(selem(y, sbits, j), dbits, unsigned);
                let hi = sat_or(selem(x, sbits, j), dbits, unsigned);
                v |= lo << (dbits * j) | hi << (dbits * (j + n));
            }
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Unpack1H
        | Insn::Unpack1L
        | Insn::Unpack2H
        | Insn::Unpack2L
        | Insn::Unpack4H
        | Insn::Unpack4L => {
            let (bits, hi) = match insn {
                Insn::Unpack1H => (8, true),
                Insn::Unpack1L => (8, false),
                Insn::Unpack2H => (16, true),
                Insn::Unpack2L => (16, false),
                Insn::Unpack4H => (32, true),
                _ => (32, false),
            };
            let v = punpack(gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32), bits, hi);
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pmin1U | Insn::Pmax1U | Insn::Pmin2 | Insn::Pmax2 => {
            let (bits, signed, max) = match insn {
                Insn::Pmin1U => (8, false, false),
                Insn::Pmax1U => (8, false, true),
                Insn::Pmin2 => (16, true, false),
                _ => (16, true, true),
            };
            let v = pelem(
                gr_get(b, ops[2] as u32),
                gr_get(b, ops[3] as u32),
                bits,
                move |a, c| {
                    let take_a = if signed {
                        let (sa, sc) = (sext(a, bits) as i64, sext(c, bits) as i64);
                        if max { sa >= sc } else { sa <= sc }
                    } else if max {
                        a >= c
                    } else {
                        a <= c
                    };
                    if take_a { a } else { c }
                },
            );
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Psad1 => {
            let (x, y) = (gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32));
            let mut v = 0u64;
            for i in 0..8u32 {
                v += elem(x, 8, i).abs_diff(elem(y, 8, i));
            }
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        // pmpy2: 16 ビット要素 2 個の符号つき積を 32 ビットのまま
        // 置く（.r は要素 0/2、.l は要素 1/3）。
        Insn::Pmpy2R | Insn::Pmpy2L => {
            let base = if insn == Insn::Pmpy2R { 0 } else { 1 };
            let (x, y) = (gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32));
            let lo = selem(x, 16, base) * selem(y, 16, base);
            let hi = selem(x, 16, base + 2) * selem(y, 16, base + 2);
            let v = (lo as u64 & 0xffff_ffff) | ((hi as u64 & 0xffff_ffff) << 32);
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        // pmpyshr2: 16 ビット要素 4 個の積の {count+15:count} を
        // 詰める。count2 選択子は {0,7,15,16}。
        Insn::Pmpyshr2 | Insn::Pmpyshr2U => {
            const COUNTS: [u32; 4] = [0, 7, 15, 16];
            let cnt = COUNTS[ops[4] as usize & 3];
            let signed = insn == Insn::Pmpyshr2;
            let (x, y) = (gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32));
            let mut v = 0u64;
            for i in 0..4u32 {
                let p = if signed {
                    (selem(x, 16, i) * selem(y, 16, i)) as u32
                } else {
                    (elem(x, 16, i) * elem(y, 16, i)) as u32
                };
                v |= u64::from((p >> cnt) & 0xffff) << (16 * i);
            }
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        // mpy4/mpyshl4 は Poulson 追加（Rev 2.3 未収録）。
        Insn::Mpy4 | Insn::Mpyshl4 => {
            let v = pelem(
                gr_get(b, ops[2] as u32),
                gr_get(b, ops[3] as u32),
                32,
                |a, c| {
                    let p = a.wrapping_mul(c);
                    if insn == Insn::Mpyshl4 { p & !3 } else { p }
                },
            );
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        // ---- I5-I8: シフト（可変・即値）。
        Insn::Shl => {
            let cnt = gr_get(b, ops[3] as u32);
            let v = if cnt > 63 {
                0
            } else {
                gr_get(b, ops[2] as u32) << cnt
            };
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Shr | Insn::ShrU => {
            let cnt = gr_get(b, ops[2] as u32);
            let x = gr_get(b, ops[3] as u32);
            let v = if insn == Insn::Shr {
                ((x as i64) >> cnt.min(63)) as u64
            } else if cnt > 63 {
                0
            } else {
                x >> cnt
            };
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pshl2 | Insn::Pshl4 => {
            let bits = if insn == Insn::Pshl2 { 16 } else { 32 };
            let cnt = gr_get(b, ops[3] as u32).min(bits.into());
            let v = pelem(gr_get(b, ops[2] as u32), 0, bits, move |a, _| a << cnt);
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pshr2 | Insn::Pshr4 | Insn::Pshr2U | Insn::Pshr4U => {
            let (bits, signed) = match insn {
                Insn::Pshr2 => (16, true),
                Insn::Pshr4 => (32, true),
                Insn::Pshr2U => (16, false),
                _ => (32, false),
            };
            let cnt = gr_get(b, ops[2] as u32).min(bits.into());
            let v = pelem(gr_get(b, ops[3] as u32), 0, bits, move |a, _| {
                if signed {
                    ((sext(a, bits) as i64) >> cnt) as u64
                } else {
                    a >> cnt
                }
            });
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Pshl2I | Insn::Pshl4I => {
            let bits = if insn == Insn::Pshl2I { 16 } else { 32 };
            let cnt = 31 - ops[3];
            let v = pelem(gr_get(b, ops[2] as u32), 0, bits, move |a, _| a << cnt);
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[2] as u32));
        }
        Insn::Pshr2I | Insn::Pshr4I | Insn::Pshr2UI | Insn::Pshr4UI => {
            let (bits, signed) = match insn {
                Insn::Pshr2I => (16, true),
                Insn::Pshr4I => (32, true),
                Insn::Pshr2UI => (16, false),
                _ => (32, false),
            };
            let cnt = ops[3];
            let v = pelem(gr_get(b, ops[2] as u32), 0, bits, move |a, _| {
                if signed {
                    ((sext(a, bits) as i64) >> cnt) as u64
                } else {
                    a >> cnt
                }
            });
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[2] as u32));
        }
        // ---- I10-I15: shrp・extr・dep。
        Insn::Shrp => {
            let (x, y) = (gr_get(b, ops[2] as u32), gr_get(b, ops[3] as u32));
            let cnt = ops[4];
            let v = if cnt == 0 {
                y
            } else {
                (y >> cnt) | (x << (64 - cnt))
            };
            wr_gr(b, ops[1] as u32, v, nat2(b, ops[2] as u32, ops[3] as u32));
        }
        Insn::Extr | Insn::ExtrU => {
            let pos = ops[3];
            let len = (ops[4] + 1).min(64 - pos);
            let t = (gr_get(b, ops[2] as u32) >> pos) & mask(len as u32);
            let v = if insn == Insn::Extr {
                sext(t, len as u32)
            } else {
                t
            };
            wr_gr(b, ops[1] as u32, v, nat_get(b, ops[2] as u32));
        }
        Insn::DepZ | Insn::DepZImm => {
            let (src, nat) = if insn == Insn::DepZ {
                (gr_get(b, ops[2] as u32), nat_get(b, ops[2] as u32))
            } else {
                (sext(ops[2], 8), false)
            };
            let pos = 63 - ops[3];
            let len = (ops[4] + 1).min(64 - pos);
            let v = (src & mask(len as u32)) << pos;
            wr_gr(b, ops[1] as u32, v, nat);
        }
        Insn::Dep | Insn::DepImm => {
            let (src, len_f, nat) = if insn == Insn::Dep {
                (
                    gr_get(b, ops[2] as u32),
                    ops[5],
                    nat2(b, ops[2] as u32, ops[3] as u32),
                )
            } else {
                (sext(ops[2], 1), ops[5], nat_get(b, ops[3] as u32))
            };
            let pos = 63 - ops[4];
            let len = (len_f + 1).min(64 - pos);
            let m = mask(len as u32);
            let v = (gr_get(b, ops[3] as u32) & !(m << pos)) | ((src & m) << pos);
            wr_gr(b, ops[1] as u32, v, nat);
        }
        // ---- レジスタ転送。
        Insn::MovIp => {
            // 建築の IP はバンドルアドレス（下位 4 ビットは常に 0）。
            wr_gr(b, ops[1] as u32, ip & !0xf, false);
        }
        Insn::MovPr => {
            wr_gr(b, ops[1] as u32, pr_get(b), false);
        }
        Insn::MovFromBr => {
            wr_gr(b, ops[1] as u32, get64(b, br_ref(ops[2] as u32)), false);
        }
        Insn::MovBr | Insn::MovRet => {
            if nat_get(b, ops[2] as u32) {
                return Err(trap(TRAP_NAT));
            }
            set64(b, br_ref(ops[1] as u32), gr_get(b, ops[2] as u32));
        }
        Insn::MovIToAr | Insn::MovIArImm | Insn::MovMToAr | Insn::MovMArImm => {
            let i_form = matches!(insn, Insn::MovIToAr | Insn::MovIArImm);
            let v = if matches!(insn, Insn::MovIArImm | Insn::MovMArImm) {
                sext(ops[2], 8)
            } else {
                if nat_get(b, ops[2] as u32) {
                    return Err(trap(TRAP_NAT));
                }
                gr_get(b, ops[2] as u32)
            };
            ar_write(b, ops[1], v, i_form)?;
        }
        Insn::MovIFromAr | Insn::MovMFromAr => {
            let i_form = insn == Insn::MovIFromAr;
            let v = ar_read(b, ops[2], i_form)?;
            wr_gr(b, ops[1] as u32, v, false);
        }
        Insn::MovToPr => {
            if nat_get(b, ops[1] as u32) {
                return Err(trap(TRAP_NAT));
            }
            let src = gr_get(b, ops[1] as u32);
            let m = sext(ops[2], 17);
            for i in 1..64u32 {
                if (m >> i) & 1 != 0 {
                    pr_bit(b, i, (src >> i) & 1 != 0);
                }
            }
        }
        Insn::MovPrRot => {
            let src = sext(ops[1], 44);
            for i in 16..64u32 {
                pr_bit(b, i, (src >> i) & 1 != 0);
            }
        }
        Insn::MovPsrUm => {
            // PSR{5:0}（ユーザマスク）のゼロ拡張。
            wr_gr(b, ops[1] as u32, get64(b, psr_um_ref()) & 0x3f, false);
        }
        Insn::MovCpuid => {
            // cpuid 表は未持ち。tf が読む features 32-63 と同じく
            // 0 の最小構成とする実装選択（NaT は r3 から伝播）。
            wr_gr(b, ops[1] as u32, 0, nat_get(b, ops[2] as u32));
        }
        Insn::Sum | Insn::Rum => {
            // ユーザマスクは PSR{5:0}。immu24 の下位 6 ビットが効く。
            let m = ops[1] & 0x3f;
            let r = psr_um_ref();
            let v = get64(b, r);
            set64(b, r, if insn == Insn::Sum { v | m } else { v & !m } & 0x3f);
        }
        // ---- シリアライズ・キャッシュ系。単一スレッド・コヒーレント
        // モデルでは実効なし（invala だけ ALAT を空にする）。
        Insn::Invala => {
            set64(
                b,
                StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, alat_valid)),
                0,
            );
        }
        Insn::Fwb | Insn::Mf | Insn::MfA | Insn::SrlzD | Insn::SrlzI | Insn::SyncI | Insn::Fc => {}
        // ---- X 系。
        Insn::Movl => {
            wr_gr(b, ops[1] as u32, ops[2], false);
        }
        Insn::BrCondSptkFew => {
            // tgt25c は IP 相対（バンドルアドレス基準、下位 4 ビット 0）。
            b.ctrl = Ctrl::Jump((ip & !0xf).wrapping_add(sext(ops[1], 25)));
        }
        _ => return Err(InterpExit::Unimplemented(format!("{insn:?}"))),
    }
    Ok(true)
}
