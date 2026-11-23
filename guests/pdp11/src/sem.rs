// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の命令意味論（PD5 の整数群 + PD6 の論理・シフト・CC 操作
//! + PD7 のサブルーチン命令）。
//!
//! 指定子評価の実効版（`eval_op` — `specifier::eval` が返す EA と
//! オート増減の書き戻しに、間接形の指し先語の読み出しと byte/word
//! の読み書きを足す）と、整数命令群を実装する。二重オペランドは
//! mov/movb・cmp/cmpb・add・sub・bit/bitb・bic/bicb・bis/bisb、
//! 単一オペランドは clr/clrb・com/comb・inc/incb・dec/decb・
//! neg/negb・adc/adcb・sbc/sbcb・tst/tstb・ror/rorb・rol/rolb・
//! asr/asrb・asl/aslb・swab・sxt、レジスタ形は xor、条件コード操作は
//! ccc/scc（マスク <3:0> が NZVC に対応し複数桁を同時に消す/立てる）。
//! 条件コードの規則は命令ごとに ARCH83 第5章から写す（sbc の V は
//! 「dst が最大負」のみで C 入力を問わない、com は C=1、inc/dec は
//! C 不変、シフト・回転は C=シフトアウト桁で V=N xor C、sxt は N/C
//! 不変、swab は結果の下位バイトで N/Z を見て V/C は消える等）。
//! 分岐・jmp・トラップ命令は PD4 の形のまま、サブルーチン命令は
//! jsr（一時=宛先アドレス→link を -(SP) へ→link=次の命令→PC=一時）・
//! rts（PC=link→link=(SP)+）・sob（レジスタ減算・非零なら PC−2×off6）・
//! mark（SP=PC+2×nn→PC=r5→r5=(SP)+。rti 類似の手順除去）を持つ。
//! 特権・システム命令（rti/rtt・spl・mtps/mfps・mfpt・csm・
//! tstset/wrtlck）は PD8 が担う。
//!
//! ワードアクセスの奇数アドレスは `odd_addr_trap` パラメータに従う:
//! 立つモデルでは vector 004（バスエラー）に落ち、立たないモデル
//! （LSI-11・F-11・T-11 系 —— 付録 B 項目 15/21 の「奇数アドレス
//! トラップ未実装」）では偶数アドレスに揃えたワードサイクルとして
//! 振る舞う決定的な選択を取る。
//!
//! 例外の形は trap/fault で分ける（run 側の復帰先の規則）: trap
//! （emt/trap/bpt/iot）は命令が完結してから届き積む PC は次の命令、
//! fault（バスエラー・奇数アドレス・予約命令・違法な指定子）は
//! 中断した命令の先頭を積む。トラップの配送 `deliver` は実機の形
//! —— 古い PSW と PC をカーネルスタックに積み、ベクタの 2 語から
//! 新しい PC/PSW を読む。
//!
//! 出典は SPEC-PDP11-ARCH83（第4・5・8章・付録 A/B）である。
//! Ref: SPEC-PDP11-ARCH83.

use polyisa_engine::interp::{InterpBackend, InterpExit};
use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend as _, ExceptionKind, GuestException, StateRef, W16};

use crate::specifier::{self, Acc, Ea, Fetched, Legality, Spec, Width};
use crate::{
    CpuState, Insn, JMP_REG_TRAP_VEC004, JmpRegTrapParam, OddAddrTrapParam, ops_fcm, ops_fn6,
    ops_fr, ops_frd, ops_frn, psw, reg,
};

/// トラップベクタ（バイトアドレス）。EMT/TRAP のような命令由来と、
/// バスエラーのような fault 由来の双方が同じ配送経路を通る。
// Ref: SPEC-PDP11-ARCH83（付録 A アドレス/ベクタ割付）.
pub mod tv {
    /// バスエラー・奇数アドレス（004）。
    pub const BUS: u16 = 0o004;
    /// 違法・予約命令（010）。
    pub const ILL: u16 = 0o010;
    /// BPT・トレーストラップ（014）。
    pub const BPT: u16 = 0o014;
    /// IOT（020）。
    pub const IOT: u16 = 0o020;
    /// EMT（030）。
    pub const EMT: u16 = 0o030;
    /// TRAP（034）。
    pub const TRAP: u16 = 0o034;
}

/// データの読み出し・書き込みのアクセス属性。整列の規則は
/// PDP-11 自身の奇数アドレスエラーが担う（`waddr`）ので、mem 層
/// には整列を要求しない。
const DRD: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};
const DWR: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::DataWrite,
};

/// 命令語フェッチのアクセス属性。`AccessKind::Fetch` が I 空間、
/// `AccessKind::Data*` が D 空間を指す空間選択の口 —— PD4 は
/// 単一空間で、分離 I/D は PD12 が `mem` 側に拡張して実現する。
pub const FETCH: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::Fetch,
};

fn get16(b: &InterpBackend, r: StateRef<W16>) -> u16 {
    let off = r.offset();
    u16::from_le_bytes(b.state[off..off + 2].try_into().expect("w16"))
}

fn set16(b: &mut InterpBackend, r: StateRef<W16>, v: u16) {
    let off = r.offset();
    b.state[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// 汎用レジスタ r_i の状態面。
#[must_use]
pub fn r_ref(i: u8) -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, r) + usize::from(i) * 2)
}

/// 汎用レジスタ r_i の値。
#[must_use]
pub fn r_get(b: &InterpBackend, i: u8) -> u16 {
    get16(b, r_ref(i))
}

/// 汎用レジスタ r_i への代入。
pub fn r_set(b: &mut InterpBackend, i: u8, v: u16) {
    set16(b, r_ref(i), v);
}

/// PSW の状態面。
#[must_use]
pub fn psw_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, psw))
}

/// PSW の値。
#[must_use]
pub fn psw_get(b: &InterpBackend) -> u16 {
    get16(b, psw_ref())
}

/// PSW への代入。
pub fn psw_put(b: &mut InterpBackend, v: u16) {
    set16(b, psw_ref(), v);
}

/// PSW の 1 ビットを読む。
#[must_use]
pub fn psw_flag(b: &InterpBackend, bit: u16) -> bool {
    psw_get(b) & (1 << bit) != 0
}

/// PSW の 1 ビットを書く。
fn psw_flag_set(b: &mut InterpBackend, bit: u16, v: bool) {
    let p = psw_get(b);
    psw_put(b, if v { p | 1 << bit } else { p & !(1 << bit) });
}

/// カーネル SP 退避先（モード切替で r6 と入れ替わる）。
fn ksp_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, ksp))
}

/// スーパーバイザ SP 退避先。
fn ssp_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, ssp))
}

/// ユーザー SP 退避先。
fn usp_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, usp))
}

/// fault 系の例外（命令を中断。復帰先は命令先頭）。
/// code にはトラップベクタを載せる。
#[must_use]
pub fn fault(vec: u16) -> InterpExit {
    InterpExit::Exception(GuestException {
        kind: ExceptionKind::Undefined,
        code: u64::from(vec),
        addr: None,
        in_delay_slot: false,
    })
}

/// trap 系の例外（命令が完結してから届く。復帰先は次の命令）。
#[must_use]
pub fn trap(vec: u16) -> InterpExit {
    InterpExit::Exception(GuestException {
        kind: ExceptionKind::Trap,
        code: u64::from(vec),
        addr: None,
        in_delay_slot: false,
    })
}

/// ワードアクセスのアドレス検査。偶数は素通し。奇数は
/// `odd_addr_trap` が立つモデルではバスエラー fault（vector 004）、
/// 立たないモデルでは偶数に揃える（トラップ未実装のモデルの
/// 決定的な表現 —— LSI-11 系のワードサイクルは常に語境界で
/// 行われる。付録 B 項目 15/21）。
// Ref: SPEC-PDP11-ARCH83（付録 B）, SPEC-PDP11-LSI11.
fn waddr(b: &mut InterpBackend, a: u16) -> Result<u16, InterpExit> {
    if a & 1 == 0 {
        Ok(a)
    } else if b.param::<OddAddrTrapParam>() {
        Err(fault(tv::BUS))
    } else {
        Ok(a & !1)
    }
}

/// バイト読み出し。
pub fn load_b(b: &mut InterpBackend, a: u16) -> Result<u8, InterpExit> {
    b.load::<polyisa_sem::W8>(u64::from(a), DRD)
}

/// ワード読み出し（奇数アドレスは `waddr` の規則）。
pub fn load_w(b: &mut InterpBackend, a: u16) -> Result<u16, InterpExit> {
    let a = waddr(b, a)?;
    b.load::<W16>(u64::from(a), DRD)
}

/// バイト書き込み。
pub fn store_b(b: &mut InterpBackend, a: u16, v: u8) -> Result<(), InterpExit> {
    b.store::<polyisa_sem::W8>(u64::from(a), v, DWR)
}

/// ワード書き込み（奇数アドレスは `waddr` の規則）。
pub fn store_w(b: &mut InterpBackend, a: u16, v: u16) -> Result<(), InterpExit> {
    let a = waddr(b, a)?;
    b.store::<W16>(u64::from(a), v, DWR)
}

/// 命令語のフェッチ（I 空間。ワード整列は `waddr` の規則）。
pub fn fetch_w(b: &mut InterpBackend, a: u16) -> Result<u16, InterpExit> {
    let a = waddr(b, a)?;
    b.load::<W16>(u64::from(a), FETCH)
}

// ---- 条件コード ----

/// 幅の符号ビット（最大負 M.N.I.）と値マスク。最大正 M.P.I. は
/// `符号ビット - 1`、全 1 はマスクそのもので幅から導ける。
fn sign_mask(w: Width) -> (u16, u16) {
    if w == Width::B {
        (0x80, 0xff)
    } else {
        (0x8000, 0xffff)
    }
}

/// 結果の N（符号）と Z（零）を立てる。V・C は命令ごとの規則が
/// 追記する（保存を含む）。
fn cc_nz(b: &mut InterpBackend, v: u16, w: Width) {
    let (sign, mask) = sign_mask(w);
    psw_flag_set(b, psw::N, v & sign != 0);
    psw_flag_set(b, psw::Z, v & mask == 0);
}

/// 幅の値で mov 系の条件コードを立てる（N=符号・Z=零・V=0・C 保存）。
// Ref: SPEC-PDP11-ARCH83（第5章 mov の記述）.
fn cc_mov(b: &mut InterpBackend, v: u16, w: Width) {
    cc_nz(b, v, w);
    psw_flag_set(b, psw::V, false);
}

/// 幅の値を調べる命令の条件コード（N=符号・Z=零・V=0・C=0。
/// tst 系。clr は値を見ずに立てるので呼び出し側が定数を渡す）。
fn cc_tst(b: &mut InterpBackend, v: u16, w: Width) {
    cc_mov(b, v, w);
    psw_flag_set(b, psw::C, false);
}

// ---- オペランド指定子の実効評価 ----

/// 指定子評価の結果。`Reg` はレジスタ直接、`Mem` はオペランドの
/// 実効アドレス（間接形の指し先語は読み解き済み）、`Imm` は即値語
/// の値と位置（書き込み側の決定的な振る舞いと `jmp #x` の実効
/// アドレスに使う）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Loc {
    /// モード 0: レジスタ直接。
    Reg(u8),
    /// オペランドのバイトアドレス。
    Mem(u16),
    /// 即値語（モード 2 の PC 形）。`addr` は即値語の位置。
    Imm {
        /// 即値語そのもの（byte オペランドは下位バイトを使う）。
        v: u16,
        /// 即値語のアドレス。
        addr: u16,
    },
}

/// オペランド `i` の拡張語のアドレス（拡張語を持たない指定子では
/// 未使用。`Index` で r=PC の相対基準 `ext_addr + 2` に使う）。
fn ext_addr(f: &Fetched, pc0: u16, i: usize) -> u16 {
    let mut a = pc0.wrapping_add(2);
    for s in &f.ops[..i] {
        if matches!(
            s,
            Spec::Imm(_) | Spec::Abs(_) | Spec::Index { .. } | Spec::IndexDef { .. }
        ) {
            a = a.wrapping_add(2);
        }
    }
    a
}

/// オペランド `i` を評価して読み書き先を返す。オート増減の書き戻し
/// と間接形の指し先語の読み出しはここで起きる。アクセス型に合わ
/// ない指定子（A アクセスのモード 0）は `jmp_reg_trap` パラメータ
/// のベクタに fault。UNPREDICTABLE は受理し、自然な評価に従う。
// Ref: SPEC-PDP11-ARCH83（第4章・付録 B 項目 5）.
pub fn eval_op(b: &mut InterpBackend, f: &Fetched, pc0: u16, i: usize) -> Result<Loc, InterpExit> {
    let ty = specifier::insn_ops(f.insn)[i];
    let spec = &f.ops[i];
    if specifier::legality(spec, ty.acc) == Legality::Illegal {
        let vec = if b.param::<JmpRegTrapParam>() == JMP_REG_TRAP_VEC004 {
            tv::BUS
        } else {
            tv::ILL
        };
        return Err(fault(vec));
    }
    let ea = ext_addr(f, pc0, i);
    let regs: [u16; 8] = core::array::from_fn(|j| r_get(b, j as u8));
    let (ea_v, wb) = specifier::eval(spec, ty.width, ea, &regs);
    if let Some((n, v)) = wb {
        r_set(b, n, v);
    }
    Ok(match (ea_v, spec) {
        (Ea::Reg(n), _) => Loc::Reg(n),
        (Ea::Imm(v), _) => Loc::Imm { v, addr: ea },
        // 間接形の EA は指し先語のアドレス — その語（ワード）を読んで
        // オペランドアドレスにする。
        (Ea::Addr(a), Spec::AutoIncDef(_) | Spec::AutoDecDef(_) | Spec::IndexDef { .. }) => {
            Loc::Mem(load_w(b, a)?)
        }
        (Ea::Addr(a), _) => Loc::Mem(a),
    })
}

/// オペランドの読み出し（.r/.m）。byte はレジスタの下位バイト。
pub fn read(b: &mut InterpBackend, loc: &Loc, w: Width) -> Result<u16, InterpExit> {
    Ok(match (*loc, w) {
        (Loc::Reg(n), Width::B) => r_get(b, n) & 0xff,
        (Loc::Reg(n), _) => r_get(b, n),
        (Loc::Mem(a), Width::B) => u16::from(load_b(b, a)?),
        (Loc::Mem(a), _) => load_w(b, a)?,
        (Loc::Imm { v, .. }, Width::B) => v & 0xff,
        (Loc::Imm { v, .. }, _) => v,
    })
}

/// オペランドへの書き込み（.w/.m）。byte→レジスタは符号拡張
/// （モード 0 の書き込み規則）。即値への書き込みは建築上
/// UNPREDICTABLE — 即値語の位置への書き込みとして決定的に
/// 振る舞う（VAX の Loc::Val と同じ選択）。
// Ref: SPEC-PDP11-ARCH83（第5章）.
pub fn write(b: &mut InterpBackend, loc: &Loc, w: Width, v: u16) -> Result<(), InterpExit> {
    match (*loc, w) {
        (Loc::Reg(n), Width::B) => r_set(b, n, v as u8 as i8 as u16),
        (Loc::Reg(n), _) => r_set(b, n, v),
        (Loc::Mem(a), Width::B) => store_b(b, a, v as u8)?,
        (Loc::Mem(a), _) => store_w(b, a, v)?,
        (Loc::Imm { addr, .. }, Width::B) => store_b(b, addr, v as u8)?,
        (Loc::Imm { addr, .. }, _) => store_w(b, addr, v)?,
    }
    Ok(())
}

/// .a オペランドの実効アドレス（jmp/jsr。間接形は指し先語の値）。
#[must_use]
pub fn loc_addr(loc: &Loc) -> u16 {
    match *loc {
        Loc::Mem(a) => a,
        // `jmp #x` の実効アドレスは即値語の位置そのもの。
        Loc::Imm { addr, .. } => addr,
        Loc::Reg(_) => unreachable!("モード 0 の A アクセスは eval_op が弾く"),
    }
}

// ---- 整数演算 ----

/// 単一オペランド算術（com/inc/dec/neg/adc/sbc と byte 形）。
/// （結果, V, C）を返す。`None` はその条件コードを変えない
/// （inc/dec の C）。
// Ref: SPEC-PDP11-ARCH83（第5章 各命令の条件コード）.
fn alu1(insn: Insn, v: u16, w: Width, c: bool) -> (u16, Option<bool>, Option<bool>) {
    let (sgn, m) = sign_mask(w);
    let v = v & m;
    match insn {
        // 1 の補数。V=0・C=1。
        Insn::Com | Insn::Comb => (!v & m, Some(false), Some(true)),
        // V=旧値が最大正（M.P.I.）。C 不変。
        Insn::Inc | Insn::Incb => (v.wrapping_add(1) & m, Some(v == sgn - 1), None),
        // V=旧値が最大負（M.N.I.）。C 不変。
        Insn::Dec | Insn::Decb => (v.wrapping_sub(1) & m, Some(v == sgn), None),
        // 2 の補数。V=結果が最大負。C=結果が非零。
        Insn::Neg | Insn::Negb => {
            let r = (!v).wrapping_add(1) & m;
            (r, Some(r == sgn), Some(r != 0))
        }
        // C を足す。V=旧値が最大正かつ C 入力。C=旧値が全 1 かつ C 入力。
        Insn::Adc | Insn::Adcb => (
            v.wrapping_add(u16::from(c)) & m,
            Some(v == sgn - 1 && c),
            Some(v == m && c),
        ),
        // C を引く。V=旧値が最大負 —— C 入力の有無を問わない
        // （ARCH83 第5章の規則。C=0 のとき dst−0 で算術的な溢れは
        // ないが、V は dst=M.N.I. で立つ）。C=旧値が 0 かつ C 入力（借り）。
        Insn::Sbc | Insn::Sbcb => (
            v.wrapping_sub(u16::from(c)) & m,
            Some(v == sgn),
            Some(v == 0 && c),
        ),
        _ => unreachable!("alu1 の対象外"),
    }
}

/// 二重オペランドの演算結果と条件コード。`s`・`d` はソース・
/// 宛先の読み出し値。V は常に定まり（bit/bic/bis は 0）、
/// C の `None` は C 不変（bit/bic/bis）。sub は dst−src、
/// cmp は src−dst の向きで溢れと借りを見る（cmp は dst を書かない）。
// Ref: SPEC-PDP11-ARCH83（第5章 各命令の条件コード）.
fn alu2(insn: Insn, s: u16, d: u16, w: Width) -> (u16, bool, Option<bool>) {
    let (sgn, m) = sign_mask(w);
    let (s, d) = (s & m, d & m);
    match insn {
        // dst ← dst + src。V=同符号の被演算から異符号の結果へ。
        // C=最上位桁からの桁出し。
        Insn::Add => {
            let r = d.wrapping_add(s) & m;
            (
                r,
                (s ^ r) & (d ^ r) & sgn != 0,
                Some(u32::from(d) + u32::from(s) > u32::from(m)),
            )
        }
        // dst ← dst − src。V=被演算が異符号で結果が src の符号。
        // C=借り（dst + ~src + 1 < 2^幅 ⟺ dst < src）。
        Insn::Sub => {
            let r = d.wrapping_sub(s) & m;
            (r, (d ^ s) & (d ^ r) & sgn != 0, Some(d < s))
        }
        // src − dst を調べる（書き戻しなし）。V=被演算が異符号で
        // 結果が dst の符号。C=借り（src < dst）。
        Insn::Cmp | Insn::Cmpb => {
            let r = s.wrapping_sub(d) & m;
            (r, (s ^ d) & (s ^ r) & sgn != 0, Some(s < d))
        }
        // dst ← dst ∧ ~src。
        Insn::Bic | Insn::Bicb => (d & !s & m, false, None),
        // dst ← dst ∨ src。
        Insn::Bis | Insn::Bisb => (d | s, false, None),
        // src ∧ dst を調べる（書き戻しなし）。
        Insn::Bit | Insn::Bitb => (s & d, false, None),
        _ => unreachable!("alu2 の対象外"),
    }
}

/// 1 桁のシフト・回転。（結果, シフトアウトした桁 = 新しい C）を返す。
/// asr は右へ 1 桁シフトして符号桁を複写、asl は左へ 1 桁シフトして
/// 0 を挿入、ror/rol は C を桁列の一部に含む 17/9 桁の回転。
// Ref: SPEC-PDP11-ARCH83（第5章 各命令の条件コード）.
fn shift1(insn: Insn, v: u16, w: Width, c: bool) -> (u16, bool) {
    let (sgn, m) = sign_mask(w);
    let v = v & m;
    match insn {
        Insn::Asr | Insn::Asrb => (v >> 1 | v & sgn, v & 1 != 0),
        Insn::Asl | Insn::Aslb => (v << 1 & m, v & sgn != 0),
        Insn::Ror | Insn::Rorb => (v >> 1 | if c { sgn } else { 0 }, v & 1 != 0),
        Insn::Rol | Insn::Rolb => (v << 1 & m | u16::from(c), v & sgn != 0),
        _ => unreachable!("shift1 の対象外"),
    }
}

// ---- トラップ配送 ----

/// トラップの配送。古い PSW と PC を（この順に）カーネルスタックに
/// 積み、ベクタの 2 語から新しい PC/PSW を読む実機の形。
/// `stacked` は積む PC（trap は次の命令、fault は命令先頭 ——
/// 呼び出し側の規則）。
/// カーネルモード以外では、現在の SP をモードの退避先（usp/ssp）に
/// 保存してカーネル SP に切替える —— モード機構の最小形で、
/// MMU・3 モードの全面化は PD8/PD12 が担う。
// Ref: SPEC-PDP11-ARCH83（第8章 トラップと割込み）.
pub fn deliver(b: &mut InterpBackend, vec: u16, stacked: u16) -> Result<(), InterpExit> {
    let old_psw = psw_get(b);
    let mode = old_psw >> psw::CUR_MOD & psw::MOD_MASK;
    if mode != psw::KERNEL {
        let slot = if mode == psw::SUPERVISOR {
            ssp_ref()
        } else {
            usp_ref()
        };
        let sp = r_get(b, reg::SP as u8);
        set16(b, slot, sp);
        r_set(b, reg::SP as u8, get16(b, ksp_ref()));
    }
    // -(SP) ← PSW、-(SP) ← PC —— RTI が PC→PSW の順に戻す形。
    let mut sp = r_get(b, reg::SP as u8);
    sp = sp.wrapping_sub(2);
    r_set(b, reg::SP as u8, sp);
    store_w(b, sp, old_psw)?;
    sp = sp.wrapping_sub(2);
    r_set(b, reg::SP as u8, sp);
    store_w(b, sp, stacked)?;
    let new_pc = load_w(b, vec)?;
    let new_psw = load_w(b, vec.wrapping_add(2))?;
    r_set(b, reg::PC as u8, new_pc);
    psw_put(b, new_psw);
    Ok(())
}

// ---- 命令本体（PD4 の最小形）----

/// Bcc の条件。変位の解釈は呼び出し側。
fn bcc(b: &InterpBackend, insn: Insn) -> bool {
    let n = psw_flag(b, psw::N);
    let z = psw_flag(b, psw::Z);
    let v = psw_flag(b, psw::V);
    let c = psw_flag(b, psw::C);
    match insn {
        Insn::Br => true,
        Insn::Bne => !z,
        Insn::Beq => z,
        Insn::Bge => n == v,
        Insn::Blt => n != v,
        Insn::Bgt => !z && n == v,
        Insn::Ble => z || n != v,
        Insn::Bpl => !n,
        Insn::Bmi => n,
        Insn::Bhi => !c && !z,
        Insn::Blos => c || z,
        Insn::Bvc => !v,
        Insn::Bvs => v,
        Insn::Bcc => !c,
        Insn::Bcs => c,
        _ => unreachable!("bcc の対象外"),
    }
}

/// 命令 1 個の意味論。実行中の r7 は命令の終端（次の命令 —
/// 呼び出し側が `pc0 + f.len` に設定済み）。制御転送は r7 への
/// 書き込みとして表れ、呼び出し側が実行後の r7 を読む。
/// `pc0` は命令の先頭アドレス。
// Ref: SPEC-PDP11-ARCH83（第5章 各命令の意味論）.
pub fn exec(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    match f.insn {
        Insn::Nop => {}
        Insn::Mov | Insn::Movb => {
            let tys = specifier::insn_ops(f.insn);
            let s = eval_op(b, f, pc0, 0)?;
            let v = read(b, &s, tys[0].width)?;
            let d = eval_op(b, f, pc0, 1)?;
            write(b, &d, tys[1].width, v)?;
            cc_mov(b, v, tys[0].width);
        }
        Insn::Clr | Insn::Clrb => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let d = eval_op(b, f, pc0, 0)?;
            write(b, &d, w, 0)?;
            // N=0・Z=1・V=0・C=0。
            cc_tst(b, 0, w);
        }
        Insn::Tst | Insn::Tstb => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let s = eval_op(b, f, pc0, 0)?;
            let v = read(b, &s, w)?;
            cc_tst(b, v, w);
        }
        // 二重オペランド: ソースの評価・読み出しが宛先の評価に先立つ
        // （オート増減が同じレジスタに掛かるときの順序規則）。宛先が
        // 読み出し専用の cmp/bit は書き戻さない。
        Insn::Cmp
        | Insn::Cmpb
        | Insn::Bit
        | Insn::Bitb
        | Insn::Bic
        | Insn::Bicb
        | Insn::Bis
        | Insn::Bisb
        | Insn::Add
        | Insn::Sub => {
            let tys = specifier::insn_ops(f.insn);
            let s = eval_op(b, f, pc0, 0)?;
            let sv = read(b, &s, tys[0].width)?;
            let d = eval_op(b, f, pc0, 1)?;
            let dv = read(b, &d, tys[1].width)?;
            let (r, v_f, c_f) = alu2(f.insn, sv, dv, tys[1].width);
            if tys[1].acc == Acc::M {
                write(b, &d, tys[1].width, r)?;
            }
            cc_nz(b, r, tys[1].width);
            psw_flag_set(b, psw::V, v_f);
            if let Some(cf) = c_f {
                psw_flag_set(b, psw::C, cf);
            }
        }
        // 単一オペランド算術（adc/sbc は C を読み込む）。
        Insn::Com
        | Insn::Comb
        | Insn::Inc
        | Insn::Incb
        | Insn::Dec
        | Insn::Decb
        | Insn::Neg
        | Insn::Negb
        | Insn::Adc
        | Insn::Adcb
        | Insn::Sbc
        | Insn::Sbcb => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let d = eval_op(b, f, pc0, 0)?;
            let v = read(b, &d, w)?;
            let (r, v_f, c_f) = alu1(f.insn, v, w, psw_flag(b, psw::C));
            write(b, &d, w, r)?;
            cc_nz(b, r, w);
            if let Some(vf) = v_f {
                psw_flag_set(b, psw::V, vf);
            }
            if let Some(cf) = c_f {
                psw_flag_set(b, psw::C, cf);
            }
        }
        // シフト・回転: C = シフトアウトした桁、V = N xor C（新しい
        // 両ビット）。byte 形は下位バイトで演算し符号拡張で書き戻す。
        Insn::Asr
        | Insn::Asrb
        | Insn::Asl
        | Insn::Aslb
        | Insn::Ror
        | Insn::Rorb
        | Insn::Rol
        | Insn::Rolb => {
            let w = specifier::insn_ops(f.insn)[0].width;
            let d = eval_op(b, f, pc0, 0)?;
            let v = read(b, &d, w)?;
            let (r, cout) = shift1(f.insn, v, w, psw_flag(b, psw::C));
            write(b, &d, w, r)?;
            cc_nz(b, r, w);
            psw_flag_set(b, psw::C, cout);
            psw_flag_set(b, psw::V, psw_flag(b, psw::N) != cout);
        }
        // バイト交換（語専用）。N=結果の下位バイトの最上位桁、
        // Z=下位バイトが 0、V・C は消える。
        Insn::Swab => {
            let d = eval_op(b, f, pc0, 0)?;
            let v = read(b, &d, Width::W)?;
            let r = v.rotate_left(8);
            write(b, &d, Width::W, r)?;
            psw_flag_set(b, psw::N, r & 0x80 != 0);
            psw_flag_set(b, psw::Z, r & 0xff == 0);
            psw_flag_set(b, psw::V, false);
            psw_flag_set(b, psw::C, false);
        }
        // 符号拡張: N が立っていれば −1、消えていれば 0 を書く。
        // N・C は変えない。Z=N が消えている（結果が 0）と立ち、V=0。
        Insn::Sxt => {
            let d = eval_op(b, f, pc0, 0)?;
            let n = psw_flag(b, psw::N);
            write(b, &d, Width::W, if n { 0o177777 } else { 0 })?;
            psw_flag_set(b, psw::Z, !n);
            psw_flag_set(b, psw::V, false);
        }
        // 排他的論理和（レジスタ形）: dst ← reg ^ dst。V=0・C 不変。
        Insn::Xor => {
            let tys = specifier::insn_ops(f.insn);
            let n = ops_frd(u128::from(f.word)).reg as u8;
            let d = eval_op(b, f, pc0, 0)?;
            let dv = read(b, &d, tys[0].width)?;
            let r = r_get(b, n) ^ dv;
            write(b, &d, tys[0].width, r)?;
            cc_mov(b, r, tys[0].width);
        }
        // 条件コード操作: マスク <3:0> の各桁が NZVC に対応する。
        // ccc 族（000240+m）は選択桁を消し、scc 族（000260+m）は立てる
        // —— clc/sec などの個別名は m=1,2,4,8 の特例で、複数桁を一度に
        // 触れる。マスク 0（nop・scc+0）は何もしない。
        Insn::Ccc => {
            let m = ops_fcm(u128::from(f.word)).ccm as u16;
            psw_put(b, psw_get(b) & !m);
        }
        Insn::Scc => {
            let m = ops_fcm(u128::from(f.word)).ccm as u16;
            psw_put(b, psw_get(b) | m);
        }
        // 分岐: off8 は符号付き 8 ビットで語単位（×2）。基準は命令の
        // 次の語 —— 実行中の r7 はそこを指す。
        Insn::Br
        | Insn::Bne
        | Insn::Beq
        | Insn::Bge
        | Insn::Blt
        | Insn::Bgt
        | Insn::Ble
        | Insn::Bpl
        | Insn::Bmi
        | Insn::Bhi
        | Insn::Blos
        | Insn::Bvc
        | Insn::Bvs
        | Insn::Bcc
        | Insn::Bcs => {
            if bcc(b, f.insn) {
                let off = (f.word & 0xff) as i8 as i32 * 2;
                let t = (i32::from(r_get(b, reg::PC as u8) as i16) + off) as u16;
                r_set(b, reg::PC as u8, t);
            }
        }
        Insn::Jmp => {
            let d = eval_op(b, f, pc0, 0)?;
            r_set(b, reg::PC as u8, loc_addr(&d));
        }
        // SOB: reg ← reg − 1。結果が非零なら PC − 2×off6 へ（変位は
        // 語単位の正数で後方向きのみ。基準は次の語 —— 実行中の r7）。
        Insn::Sob => {
            let o = ops_frn(u128::from(f.word));
            let n = o.reg as u8;
            let v = r_get(b, n).wrapping_sub(1);
            r_set(b, n, v);
            if v != 0 {
                let pc = r_get(b, reg::PC as u8);
                r_set(b, reg::PC as u8, pc.wrapping_sub(2 * o.off6 as u16));
            }
        }
        // JSR: tmp ← dst（A アクセス — モード 0 は jmp_reg_trap に
        // fault）、-(SP) ← link、link ← PC（次の命令のアドレス）、
        // PC ← tmp。link が dst 評価のオート増減で変わるときは
        // 変更後の値を積む（jsr r5,@(r5)+ の規則 — 指定子評価の
        // 書き戻しが push の読み出しに先立つ）。link=PC は戻り
        // アドレスを積んで tmp へ跳ぶだけで、rts pc と対になる。
        Insn::Jsr => {
            let n = ops_frd(u128::from(f.word)).reg as u8;
            let d = eval_op(b, f, pc0, 0)?;
            let t = loc_addr(&d);
            let sp = r_get(b, reg::SP as u8).wrapping_sub(2);
            r_set(b, reg::SP as u8, sp);
            store_w(b, sp, r_get(b, n))?;
            r_set(b, n, r_get(b, reg::PC as u8));
            r_set(b, reg::PC as u8, t);
        }
        // RTS: PC ← reg、reg ← (SP)+。reg は SP 更新の前に読む
        // （reg=SP でも旧値が PC になる規則）。reg=PC（rts pc）は
        // 積まれた戻りアドレスがそのまま PC に入る。
        Insn::Rts => {
            let n = ops_fr(u128::from(f.word)).rreg as u8;
            let link = r_get(b, n);
            let sp = r_get(b, reg::SP as u8);
            let v = load_w(b, sp)?;
            r_set(b, reg::SP as u8, sp.wrapping_add(2));
            r_set(b, reg::PC as u8, link);
            r_set(b, n, v);
        }
        // MARK: SP ← PC + 2×nn（PC は mark の次の語 — 標準規約では
        // mark 語がスタック上に置かれるので、ここがスタック内の
        // 引数ブロックの先頭になる）、PC ← r5、r5 ← (SP)+
        // （新しい SP からの pop。rti 類似の手順除去形）。
        Insn::Mark => {
            let nn = ops_fn6(u128::from(f.word)).off6 as u16;
            let sp = r_get(b, reg::PC as u8).wrapping_add(2 * nn);
            r_set(b, reg::SP as u8, sp);
            r_set(b, reg::PC as u8, r_get(b, 5));
            let v = load_w(b, sp)?;
            r_set(b, reg::SP as u8, sp.wrapping_add(2));
            r_set(b, 5, v);
        }
        Insn::Bpt => return Err(trap(tv::BPT)),
        Insn::Iot => return Err(trap(tv::IOT)),
        Insn::Emt => return Err(trap(tv::EMT)),
        Insn::Trap => return Err(trap(tv::TRAP)),
        // halt は CPU 停止（カーネルモード）。停止状態の表現がない
        // 裸モデルでは実行の終端として Unimplemented に写す決定的な
        // 選択。wait は割込み待ち —— 割込みは裸実行で発生しない。
        Insn::Halt | Insn::Wait => {
            return Err(InterpExit::Unimplemented(format!("{:?}", f.insn)));
        }
        // 残りの命令本体は PD5 以降。
        _ => return Err(InterpExit::Unimplemented(format!("{:?}", f.insn))),
    }
    Ok(())
}
