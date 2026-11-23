// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の命令意味論（PD5 の整数群 + PD6 の論理・シフト・CC 操作
//! + PD7 のサブルーチン命令 + PD8 の特権・システム命令 + PD9 の
//! EIS/FIS）。
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
//! 特権・システム命令は rti/rtt（スタックからの PC/PSW 復元とモード
//! 切替、非カーネルの PSW 保護）・spl・mtps/mfps・mfpt（`mfpt_code`
//! のモデル値）・csm（MMR3<3> 条件のスーパーバイザ呼出）・
//! tstset/wrtlck（バスロックの単一スレッド近似）・reset（裸モデル
//! では NOP）を持つ。
//! EIS は mul（R,Rv1 の 32 ビット積・奇数 R は低位積のみ）・div
//! （商 R・剰余 Rv1・0 除算と商溢れの CC）・ash（符号付き 6 ビット
//! カウントの算術シフト）・ashc（R:R|1 の 32 ビット対シフト ——
//! 奇数 R の右シフトは回転）を持つ。FIS は 0750xR の fadd/fsub/
//! fmul/fdiv —— 汎用レジスタが指すフレームの A±B を A 位置へ
//! 格納して R+4、例外は vector 244 へ fault と CC の再解釈を
//! 行う（KEV11。FMUL/FDIV は R6 への作業語 push/pop つき）。
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
use polyisa_sem::{Backend as _, ExceptionKind, GuestException, StateRef, W16, W64};
use polyisa_softfloat::decfp::{FP_IOV, VaxDF, VaxF, VaxFF};
use polyisa_softfloat::{FP_DZ, FP_OF, FP_UF, Rm};

use crate::specifier::{self, Acc, Ea, Fetched, Legality, Spec, Width};
use crate::{
    CpuState, EA_FAULT_REG_KEEP, EaFaultRegParam, FEAT_ID_SPLIT, HALT_VEC_POWERUP, HALT_VEC_VEC004,
    HaltVecParam, Insn, JMP_REG_TRAP_VEC004, JmpRegTrapParam, MFP_SP2_USER, MODE_ENC_NONE,
    MTPS_MAP_MAPPED, MfpSp2Param, MfptCodeParam, ModeEncParam, MtpsMapParam, OPR_SAME_REG_INC,
    OddAddrTrapParam, OprSameRegParam, PC_STORED_PC2, PcStoredParam, SWAB_V_KEEP, SwabVParam,
    WAIT_T_SEQ, WaitTParam, cis, mmu, ops_fcm, ops_ff, ops_fn3, ops_fn6, ops_fr, ops_frd, ops_frn,
    psw, reg,
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
    /// 浮動例外（244。FP11 の浮動割込みと FIS のエラートラップが
    /// 同じ番号で経路は別 —— ARCH83 付録 A・付録 C）。
    pub const FPP: u16 = 0o244;
    /// メモリ管理 abort/trap（250。PAR/PDR の参照不可・長さ違反・
    /// read-only と、mm_trap モデルの trap 条件が届く）。
    pub const MMU: u16 = 0o250;
}

pub(crate) fn get16(b: &InterpBackend, r: StateRef<W16>) -> u16 {
    let off = r.offset();
    u16::from_le_bytes(b.state[off..off + 2].try_into().expect("w16"))
}

pub(crate) fn set16(b: &mut InterpBackend, r: StateRef<W16>, v: u16) {
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

/// モード値 <15:14> が選ぶ SP 退避先。値 2（予約）はカーネル枠に
/// 畳む決定的な選択。
pub(crate) fn mode_sp_ref(mode: u16) -> StateRef<W16> {
    if mode == psw::SUPERVISOR {
        ssp_ref()
    } else if mode == psw::USER {
        usp_ref()
    } else {
        ksp_ref()
    }
}

/// MFPx/MTPx の %6 が指す前モード SP のモード値。前モード値 2
/// （予約）は J-11 でユーザー、他モデルは不定 → カーネル枠に畳む
/// 決定的選択（付録 B 項目 52）。
fn sp_pm(b: &mut InterpBackend, pm: u16) -> u16 {
    if pm == 2 && b.param::<MfpSp2Param>() == MFP_SP2_USER {
        psw::USER
    } else {
        pm
    }
}

/// 第 2 レジスタセット r_i′ の状態面（dual_regset モデル）。
pub(crate) fn ralt_ref(i: u8) -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, ralt) + usize::from(i) * 2)
}

fn wb_reg_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, wb_reg))
}

fn wb_old_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, wb_old))
}

/// MMU 状態レジスタ MMR_i の値（mmu モデル。CSM は MMR3<3> が
/// 有効化を担う —— KDJ11-E UG）。
fn mmr_get(b: &InterpBackend, i: u8) -> u16 {
    get16(
        b,
        StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, mmr) + usize::from(i) * 2),
    )
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
pub(crate) fn waddr(b: &mut InterpBackend, a: u16) -> Result<u16, InterpExit> {
    if a & 1 == 0 {
        Ok(a)
    } else if b.param::<OddAddrTrapParam>() {
        Err(fault(tv::BUS))
    } else {
        Ok(a & !1)
    }
}

/// バイト読み出し（現モードのデータ空間 —— `mmu` が MMU 変換と
/// I/O ページ写像を担う）。
pub fn load_b(b: &mut InterpBackend, a: u16) -> Result<u8, InterpExit> {
    let mode = mmu::cur_mode(b);
    mmu::rd_b(b, a, mode, mmu::Space::D)
}

/// ワード読み出し（奇数アドレスは `waddr` の規則）。
pub fn load_w(b: &mut InterpBackend, a: u16) -> Result<u16, InterpExit> {
    let a = waddr(b, a)?;
    let mode = mmu::cur_mode(b);
    mmu::rd_w(b, a, mode, mmu::Space::D)
}

/// 現モード・空間を選ぶワード読み出し。MFPI/MFPD の前モード参照と
/// 間接指定子の指し先語（I 空間）が使う。
pub fn load_w_as(
    b: &mut InterpBackend,
    a: u16,
    mode: u16,
    sp: mmu::Space,
) -> Result<u16, InterpExit> {
    let a = waddr(b, a)?;
    mmu::rd_w(b, a, mode, sp)
}

/// バイト書き込み。
pub fn store_b(b: &mut InterpBackend, a: u16, v: u8) -> Result<(), InterpExit> {
    let mode = mmu::cur_mode(b);
    mmu::wr_b(b, a, mode, mmu::Space::D, v)
}

/// ワード書き込み（奇数アドレスは `waddr` の規則）。
pub fn store_w(b: &mut InterpBackend, a: u16, v: u16) -> Result<(), InterpExit> {
    let a = waddr(b, a)?;
    let mode = mmu::cur_mode(b);
    mmu::wr_w(b, a, mode, mmu::Space::D, v)
}

/// 現モード・空間を選ぶワード書き込み。トラップ配送のスタック
/// プッシュと MTPI/MTPD の前モード参照が使う。
pub fn store_w_as(
    b: &mut InterpBackend,
    a: u16,
    mode: u16,
    sp: mmu::Space,
    v: u16,
) -> Result<(), InterpExit> {
    let a = waddr(b, a)?;
    mmu::wr_w(b, a, mode, sp, v)
}

/// 命令語のフェッチ（現モードの I 空間。ワード整列は `waddr` の
/// 規則）。
pub fn fetch_w(b: &mut InterpBackend, a: u16) -> Result<u16, InterpExit> {
    let a = waddr(b, a)?;
    let mode = mmu::cur_mode(b);
    mmu::fetch(b, a, mode)
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
/// CIS の検査系が返す「TST R0」にも使う。
pub fn cc_tst(b: &mut InterpBackend, v: u16, w: Width) {
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
    // OPR %R,(R)+ / OPR %R,@(R)+（ソースと宛先が同じレジスタ）で
    // R を +2 してからソースとして読むモデル —— 宛先のオート増が
    // もう一度掛かるので R は計 +4 進む（付録 B 項目 1・2 の
    // inc 側）。読み出しは eval 済みの Loc::Reg 経由で起きるので
    // ここで進める。
    if i == 0
        && f.ops.len() == 2
        && b.param::<OprSameRegParam>() == OPR_SAME_REG_INC
        && let (Spec::Reg(r), Spec::AutoInc(d) | Spec::AutoIncDef(d)) = (&f.ops[0], &f.ops[1])
        && r == d
    {
        let v = r_get(b, *r);
        mmu::reg_wb(b, *r, v.wrapping_add(2), v);
    }
    eval_op_w(b, f, pc0, i, ty.width)
}

/// `eval_op` の幅指定版。FP11 オペランドは幅が FPS の FD/FL で
/// 決まる（指定子シグネチャはアクセス種別しか持てない）ので、
/// 呼び出し側が解決した幅を渡す。適合検査は行わず、オート増減
/// のステップは `w` に従う。
fn eval_op_w(
    b: &mut InterpBackend,
    f: &Fetched,
    pc0: u16,
    i: usize,
    w: Width,
) -> Result<Loc, InterpExit> {
    let spec = &f.ops[i];
    let ea = ext_addr(f, pc0, i);
    let regs: [u16; 8] = core::array::from_fn(|j| r_get(b, j as u8));
    let (ea_v, wb) = specifier::eval(spec, w, ea, &regs);
    // 直近のオート増減書き戻し控えを捨ててから今回分を記録する
    // （keep モデルだけ意味を持つ —— 付録 B 項目 29・30）。
    set16(b, wb_reg_ref(), 0o177777);
    if let Some((n, v)) = wb {
        mmu::reg_wb(b, n, v, regs[usize::from(n)]);
        if b.param::<EaFaultRegParam>() == EA_FAULT_REG_KEEP {
            set16(b, wb_reg_ref(), u16::from(n));
            set16(b, wb_old_ref(), regs[usize::from(n)]);
        }
    }
    Ok(match (ea_v, spec) {
        (Ea::Reg(n), _) => Loc::Reg(n),
        (Ea::Imm(v), _) => Loc::Imm { v, addr: ea },
        // 間接形の EA は指し先語のアドレス — その語（ワード）は
        // 現モードの I 空間から読んでオペランドアドレスにする
        // （ARCH83 第9章の deferred アクセス規則 —— simh の
        // GeteaW は isenable で読む）。
        (Ea::Addr(a), Spec::AutoIncDef(_) | Spec::AutoDecDef(_) | Spec::IndexDef { .. }) => {
            let mode = mmu::cur_mode(b);
            match load_w_as(b, a, mode, mmu::Space::I) {
                Ok(v) => Loc::Mem(v),
                Err(e) => {
                    wb_rollback(b);
                    return Err(e);
                }
            }
        }
        (Ea::Addr(a), _) => Loc::Mem(a),
    })
}

/// オペランドアクセスが fault したとき、控えのあるオート増減
/// 書き戻しを元値へ戻す（`ea_fault_reg`=keep モデルのみ控えが
/// ある —— 付録 B 項目 29・30「register is NOT incremented」側）。
fn wb_rollback(b: &mut InterpBackend) {
    let n = get16(b, wb_reg_ref());
    if n != 0o177777 {
        r_set(b, n as u8, get16(b, wb_old_ref()));
        set16(b, wb_reg_ref(), 0o177777);
    }
}

/// オペランドの読み出し（.r/.m）。byte はレジスタの下位バイト。
/// r7 をモード 0 で読むときは `pc_stored` パラメータ —— pc2 の
/// モデルは OPR+2（実行中の r7=命令終端から 2 戻る）を読む
/// （付録 B 項目 3）。メモリアクセスの失敗は `wb_rollback`。
pub fn read(b: &mut InterpBackend, loc: &Loc, w: Width) -> Result<u16, InterpExit> {
    Ok(match (*loc, w) {
        (Loc::Reg(n), Width::B) => r_get(b, n) & 0xff,
        (Loc::Reg(n), _) => {
            let v = r_get(b, n);
            if n == reg::PC as u8 && b.param::<PcStoredParam>() == PC_STORED_PC2 {
                v.wrapping_sub(2)
            } else {
                v
            }
        }
        (Loc::Mem(a), Width::B) => u16::from(load_b(b, a).inspect_err(|_| wb_rollback(b))?),
        (Loc::Mem(a), _) => load_w(b, a).inspect_err(|_| wb_rollback(b))?,
        (Loc::Imm { v, .. }, Width::B) => v & 0xff,
        (Loc::Imm { v, .. }, _) => v,
    })
}

/// オペランドへの書き込み（.w/.m）。byte→レジスタは符号拡張
/// （モード 0 の書き込み規則）。即値への書き込みは建築上
/// UNPREDICTABLE — 即値語の位置への書き込みとして決定的に
/// 振る舞う（VAX の Loc::Val と同じ選択）。メモリアクセスの
/// 失敗は `wb_rollback`。
// Ref: SPEC-PDP11-ARCH83（第5章）.
pub fn write(b: &mut InterpBackend, loc: &Loc, w: Width, v: u16) -> Result<(), InterpExit> {
    match (*loc, w) {
        (Loc::Reg(n), Width::B) => r_set(b, n, v as u8 as i8 as u16),
        (Loc::Reg(n), _) => r_set(b, n, v),
        (Loc::Mem(a), Width::B) => store_b(b, a, v as u8).inspect_err(|_| wb_rollback(b))?,
        (Loc::Mem(a), _) => store_w(b, a, v).inspect_err(|_| wb_rollback(b))?,
        (Loc::Imm { addr, .. }, Width::B) => {
            store_b(b, addr, v as u8).inspect_err(|_| wb_rollback(b))?
        }
        (Loc::Imm { addr, .. }, _) => store_w(b, addr, v).inspect_err(|_| wb_rollback(b))?,
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

// ---- EIS（PD9）----

/// ASH/ASHC のシフトカウント（src<5:0> を符号付き 6 ビットと
/// して読む、-32..+31。負=右・正=左）。
// Ref: SPEC-PDP11-ARCH83（第5章 ASH）.
fn shift_cnt(sv: u16) -> i32 {
    let c = i32::from(sv & 0x3f);
    if c & 0x20 != 0 { c - 0x40 } else { c }
}

/// `bits` 幅の算術シフトを 1 桁ずつ行う。`cnt` は符号付きで
/// 負=右（符号複写）・正=左（0 挿入）。（結果, 最後にシフト
/// アウトした桁, シフト中に符号桁が初期値と違ったことがあるか）。
// Ref: SPEC-PDP11-ARCH83（第5章 ASH/ASHC）.
fn ashift(v: u64, bits: u32, cnt: i32) -> (u64, bool, bool) {
    let mask = (1u64 << bits) - 1;
    let sign = 1u64 << (bits - 1);
    let mut v = v & mask;
    let sign0 = v & sign != 0;
    let mut cout = false;
    let mut schg = false;
    if cnt >= 0 {
        for _ in 0..cnt {
            cout = v & sign != 0;
            v = v << 1 & mask;
            schg |= (v & sign != 0) != sign0;
        }
    } else {
        for _ in 0..-cnt {
            cout = v & 1 != 0;
            v = v >> 1 | v & sign;
        }
    }
    (v, cout, schg)
}

// ---- FIS（PD9）----

/// FIS のオペランドフレームから F 形式 1 個を読む。メモリ配置は
/// 「+0 の語が符号・指数・仮数上位」（ARCH83 第3章 —— 浮動の
/// 「3412」語順）なので、2 語を 上位:下位 に並べると decfp の
/// 正準形（`bits()` の形）になる。
fn fis_f_get(b: &mut InterpBackend, a: u16) -> Result<VaxFF, InterpExit> {
    let hi = load_w(b, a)?;
    let lo = load_w(b, a.wrapping_add(2))?;
    Ok(VaxFF::from_bits(u128::from(hi) << 16 | u128::from(lo)))
}

/// FIS 命令本体。`n` はオペランドフレームを指すレジスタ:
/// (R)/(R+2) が B 引数、(R+4)/(R+6) が A 引数。結果は A 位置へ
/// 書き、成功なら R ← R+4（結果の上位語を指す）。
/// 例外（オーバーフロー・アンダーフロー・ゼロ除算）は条件コードを
/// 再解釈して vector 244 に fault —— 積む PC は命令先頭で、
/// R とオペランドは不変のまま再実行できる。例外時 CC:
/// overflow → V=1・Z=0、underflow → V=1・N=1・Z=0、
/// 0 除算 → V=1・N=1・C=1・Z=0。成功時は N=結果<0・Z=結果=0・
/// V=0・C=0。
// Ref: SPEC-PDP11-ARCH83（付録 C）.
// Gap: GAP-0082（指数 0 を零へ畳む選択・decfp VaxF の借用）
fn fis_exec(b: &mut InterpBackend, n: u8, insn: Insn) -> Result<(), InterpExit> {
    let r = r_get(b, n);
    let a = fis_f_get(b, r.wrapping_add(4))?;
    let bb = fis_f_get(b, r)?;
    // 指数部 0 のオペランドは符号・仮数を問わず 0（KE11-F の規則
    // —— decfp の予約オペランド（指数 0・符号 1）は FIS では零と
    // して読む決定的な選択。dirty zero は decfp が零として扱う）。
    let a = if a.is_reserved() { VaxFF::zero() } else { a };
    let bb = if bb.is_reserved() { VaxFF::zero() } else { bb };
    // FIS の丸めは「常に絶対値を増やす方向」（KE11-F —— ガード桁
    // が立っていれば仮数を丸め上げる `Rm::Rmm` と一致）。
    let (v, fl) = match insn {
        Insn::Fadd => a.add(bb, Rm::Rmm),
        Insn::Fsub => a.sub(bb, Rm::Rmm),
        Insn::Fmul => a.mul(bb, Rm::Rmm),
        Insn::Fdiv => a.div(bb, Rm::Rmm),
        _ => unreachable!("fis_exec の対象外"),
    };
    if fl & (FP_OF | FP_UF | FP_DZ) != 0 {
        // 例外 CC の再解釈。N=UF か 0 除算、C=0 除算のみ。
        let (nf, cf) = if fl & FP_DZ != 0 {
            (true, true)
        } else if fl & FP_UF != 0 {
            (true, false)
        } else {
            (false, false)
        };
        psw_flag_set(b, psw::V, true);
        psw_flag_set(b, psw::N, nf);
        psw_flag_set(b, psw::C, cf);
        psw_flag_set(b, psw::Z, false);
        return Err(fault(tv::FPP));
    }
    let bits = v.bits() as u32;
    store_w(b, r.wrapping_add(4), (bits >> 16) as u16)?;
    store_w(b, r.wrapping_add(6), bits as u16)?;
    r_set(b, n, r.wrapping_add(4));
    psw_flag_set(b, psw::N, v.is_neg());
    psw_flag_set(b, psw::Z, v.is_zero());
    psw_flag_set(b, psw::V, false);
    psw_flag_set(b, psw::C, false);
    Ok(())
}

// ---- FP11（PD10）----
//
// ARCH83 6章の浮動小数点オプション（17xxxx 空間。FIS とは両立
// しない —— 機能旗は `fp11`）。状態は CpuState の ac<5:0>・fps・
// fec・fea。AC の F 形式値は上位 32 ビットに左詰めで持つ（D は
// 64 ビット全部 —— 「32 ビットの演算は左の 32 ビットだけを使う」
// の実装形）。
//
// 番地指定は CPU と同じ 8 モードで、モード 0 は AC_n（AC6/7 は
// FP 違法オペコード = FEC 2）。メモリの F/D 形式は低番地語が
// 最上位語の 3412 配置。二オペランド命令の AC フィールド <8:6>
// は下位 2 ビットが実効で（bit8 は命令対の選択子）AC0-AC3 だけ
// 指せ、AC4/5 はモード 0 指定子と MOD の AC|1 経由でのみ届く
// （ARCH83 6章 FP アドレス指定）。
//
// 丸めは FT が選ぶ（消えていれば Rmm = 丸めビットが立てば増分、
// 立っていれば Rtz = 切捨て）。例外の形: OF/UF は割込み許可が
// あれば指数を 400₈ ずらした真の結果を AC に残して vector 244
// に trap、なければ真の零を格納。ゼロ除算と違法オペコードは
// 許可を問わず FER/FEC/FEA を立て、割込みの配送自体は FID が
// 全例外で抑止する。FIUV はメモリ由来の -0 で発火 —— LDF/演算/
// CMP/MOD/LDCFF 系は実行前、NEG/ABS/TST は実行後（FPJ11 は
// 実行後にも実行前に移したモデル差 —— PD13 が担う）。

/// FPS のビット（ARCH83 6章 Figure 6-3・KDJ11-E UG Table 9-1）。
mod fps {
    /// bit15: 浮動エラー。ゼロ除算・違法オペコード・許可された
    /// 例外で立ち、LDFPS でのみ消える。
    pub const FER: u16 = 15;
    /// bit14: 全浮動割込みの抑止（FEC/FEA の更新は止めない）。
    pub const FID: u16 = 14;
    /// bit11: メモリ由来 -0 オペランド（未定義変数）の割込み許可。
    pub const FIUV: u16 = 11;
    /// bit10: アンダーフロー割込み許可。
    pub const FIU: u16 = 10;
    /// bit9: オーバーフロー割込み許可。
    pub const FIV: u16 = 9;
    /// bit8: 整数変換エラー割込み許可。
    pub const FIC: u16 = 8;
    /// bit7: 倍精度モード。
    pub const FD: u16 = 7;
    /// bit6: 32 ビット整数モード。
    pub const FL: u16 = 6;
    /// bit5: 切捨て（chop）モード。
    pub const FT: u16 = 5;
    /// bit3: 負の条件コード。
    pub const FN: u16 = 3;
    /// bit2: 零の条件コード。
    pub const FZ: u16 = 2;
    /// bit1: オーバーフローの条件コード。
    pub const FV: u16 = 1;
    /// bit0: キャリーの条件コード。
    pub const FC: u16 = 0;
    /// STFPS で読み出せない予約桁（13・12・4）— LDFPS で消す
    /// （実機では桁自体が存在しない —— 0 として読む形で代替）。
    // Gap: GAP-0083
    pub const NOREC: u16 = 0o30020;
}

/// FEC の例外コード（ARCH83 6章・KDJ11-E UG Table 9-2）。
mod fec {
    /// 浮動オペコードエラー（AC6/7 指定・未割当の FP 語）。
    pub const OP: u16 = 0o2;
    /// 浮動ゼロ除算。
    pub const DZ: u16 = 0o4;
    /// 整数変換エラー。
    pub const CVT: u16 = 0o6;
    /// オーバーフロー。
    pub const OV: u16 = 0o10;
    /// アンダーフロー。
    pub const UN: u16 = 0o12;
    /// 未定義変数（メモリの -0 オペランド）。
    pub const UV: u16 = 0o14;
}

fn get64(b: &InterpBackend, r: StateRef<W64>) -> u64 {
    let off = r.offset();
    u64::from_le_bytes(b.state[off..off + 8].try_into().expect("w64"))
}

fn set64(b: &mut InterpBackend, r: StateRef<W64>, v: u64) {
    let off = r.offset();
    b.state[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// FPS の状態面。
fn fps_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, fps))
}

fn fps_get(b: &InterpBackend) -> u16 {
    get16(b, fps_ref())
}

fn fps_put(b: &mut InterpBackend, v: u16) {
    set16(b, fps_ref(), v);
}

fn fps_flag(b: &InterpBackend, bit: u16) -> bool {
    fps_get(b) & (1 << bit) != 0
}

fn fps_flag_set(b: &mut InterpBackend, bit: u16, v: bool) {
    let p = fps_get(b);
    fps_put(b, if v { p | 1 << bit } else { p & !(1 << bit) });
}

fn fec_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, fec))
}

fn fea_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, fea))
}

/// 浮動アキュムレータ AC_i の状態面。
fn ac_ref(i: u8) -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, ac) + usize::from(i) * 8)
}

/// AC_i の F/D 形式値（F は上位 32 ビット）。
fn fp_ac_get<const E: u32, const M: u32>(b: &InterpBackend, n: u8) -> VaxF<E, M> {
    let v = get64(b, ac_ref(n));
    VaxF::from_bits(u128::from(if M == 23 { v >> 32 } else { v }))
}

/// AC_i への F/D 形式値の格納（F は上位 32 ビットを書き下位は不変）。
fn fp_ac_set<const E: u32, const M: u32>(b: &mut InterpBackend, n: u8, v: VaxF<E, M>) {
    let bits = v.bits() as u64;
    let nv = if M == 23 {
        (bits << 32) | (get64(b, ac_ref(n)) & 0xffff_ffff)
    } else {
        bits
    };
    set64(b, ac_ref(n), nv);
}

/// FP 指定子の実効位置。モード 0 は AC_n、他は FP 形式の最上位語が
/// 置かれる番地（3412 配置）。即値は命令ストリームの FP 語の位置。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FpLoc {
    /// モード 0: AC_n。
    Ac(u8),
    /// F/D 形式の最上位語の番地。
    Mem(u16),
}

/// FP 指定子の幅（M=23 → F=4 バイト、M=55 → D=8 バイト）。
fn fp_w<const M: u32>() -> Width {
    if M == 23 { Width::F } else { Width::D }
}

/// FP 指定子の評価（モード 0 → AC_n の写像と AC6/7 の違法検査
/// 込み —— AC6/7 は FEC=2。FID で抑止されたときは `None` で
/// 命令を中止する）。
fn fp_loc<const M: u32>(
    b: &mut InterpBackend,
    f: &Fetched,
    pc0: u16,
) -> Result<Option<FpLoc>, InterpExit> {
    let loc = match eval_op_w(b, f, pc0, 0, fp_w::<M>())? {
        Loc::Reg(n) => FpLoc::Ac(n),
        Loc::Mem(a) => FpLoc::Mem(a),
        Loc::Imm { addr, .. } => FpLoc::Mem(addr),
    };
    if let FpLoc::Ac(n) = loc
        && n >= 6
    {
        fp_exc(b, pc0, fec::OP)?;
        return Ok(None);
    }
    Ok(Some(loc))
}

/// メモリの F/D 形式の読み出し（低番地語が最上位語）。
fn fp_mem_get<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    a: u16,
) -> Result<VaxF<E, M>, InterpExit> {
    let nw = if M == 23 { 2 } else { 4 };
    let mut bits = 0u64;
    for k in 0..nw {
        bits = bits << 16 | u64::from(load_w(b, a.wrapping_add(2 * k))?);
    }
    Ok(VaxF::from_bits(u128::from(bits)))
}

/// メモリへの F/D 形式の書き込み（低番地語が最上位語）。
fn fp_mem_set<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    a: u16,
    v: VaxF<E, M>,
) -> Result<(), InterpExit> {
    let nw = if M == 23 { 2 } else { 4 };
    for k in 0..nw {
        let w = (v.bits() as u64 >> (16 * (nw - 1 - k))) as u16;
        store_w(b, a.wrapping_add(2 * k), w)?;
    }
    Ok(())
}

/// FP オペランドの評価と読み出し。(位置, 値) —— -0（符号 1・
/// 指数 0）は値に残し、FIUV の扱い（実行前後のどちらで落ちるか）
/// は命令が決める。`None` は AC6/7 での中止。
fn fp_opnd<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    f: &Fetched,
    pc0: u16,
) -> Result<Option<(FpLoc, VaxF<E, M>)>, InterpExit> {
    let Some(loc) = fp_loc::<M>(b, f, pc0)? else {
        return Ok(None);
    };
    let v = match loc {
        FpLoc::Ac(n) => fp_ac_get::<E, M>(b, n),
        FpLoc::Mem(a) => fp_mem_get::<E, M>(b, a)?,
    };
    Ok(Some((loc, v)))
}

/// FP 例外の登録と割込み配送。FER=1・FEC=code・FEA=pc0 を立て、
/// FID が消えていれば vector 244 へ trap（積む PC は次の命令）。
/// FID でも FER/FEC/FEA は更新される（ARCH83 6章 FPS/FEC/FEA）。
// Gap: GAP-0083（FID の抑止を全例外型で一様に適用する選択）
fn fp_exc(b: &mut InterpBackend, pc0: u16, code: u16) -> Result<(), InterpExit> {
    fps_put(b, fps_get(b) | 1 << fps::FER);
    set16(b, fec_ref(), code);
    set16(b, fea_ref(), pc0);
    if fps_flag(b, fps::FID) {
        Ok(())
    } else {
        Err(trap(tv::FPP))
    }
}

/// fp11 機能を持つモデルで 17xxxx の語が命令表にないときの
/// 違法オペコード経路（FEC=2。run が予約命令の前に呼ぶ）。
/// FID で抑止されているときは `Ok` で命令を読み飛ばす。
pub fn fp11_illop(b: &mut InterpBackend, pc0: u16) -> Result<(), InterpExit> {
    fp_exc(b, pc0, fec::OP)
}

/// FPS の条件コード 4 桁（FN/FZ/FV/FC）をまとめて立てる。
fn fp_fcc(b: &mut InterpBackend, n: bool, z: bool, v: bool, c: bool) {
    let mut p = fps_get(b) & !0xF;
    p |= (n as u16) << fps::FN
        | (z as u16) << fps::FZ
        | (v as u16) << fps::FV
        | (c as u16) << fps::FC;
    fps_put(b, p);
}

/// 形式値からの (FN, FZ)。指数 0 は零扱いで FZ=1・FN=0（-0 や
/// dirty zero も零 —— ARCH83 6章の条件コード規則）。
fn fp_nz<const E: u32, const M: u32>(v: VaxF<E, M>) -> (bool, bool) {
    let bits = v.bits();
    let exp = (bits >> M) & ((1u128 << E) - 1);
    (v.is_neg(), exp == 0)
}

/// -0・dirty zero を真の零へ畳む（演算オペランドとしては指数 0 は
/// すべて正確な零 —— ARCH83 6章「指数部 0 のオペランドは零と
/// して扱う」）。
fn fp_clean<const E: u32, const M: u32>(v: VaxF<E, M>) -> VaxF<E, M> {
    if v.is_reserved() || v.is_zero() {
        VaxF::zero()
    } else {
        v
    }
}

/// 実行前の FIUV 検査（LDF・演算・CMP・MOD・LDCFF 系）。メモリ
/// 由来の -0 なら、CC を -0 の読み出しの形（FZ=1）に立ててから
/// FEC=14 の例外を出す。FID で抑止されたときは続行する（-0 は
/// 演算では零として扱われる）。
fn fp_iuv_pre<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    pc0: u16,
    loc: &FpLoc,
    v: VaxF<E, M>,
) -> Result<(), InterpExit> {
    if matches!(loc, FpLoc::Mem(_)) && v.is_reserved() && fps_flag(b, fps::FIUV) {
        fp_fcc(b, false, true, false, false);
        fp_exc(b, pc0, fec::UV)?;
    }
    Ok(())
}

/// 実行後の FIUV 検査（TST/ABS/NEG —— ARCH83 の FP11 の形。
/// FPJ11 は実行前に移したモデル差）。
// Gap: GAP-0083（FIUV 検査位置のモデル差は単一系で再現）
fn fp_iuv_post<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    pc0: u16,
    loc: &FpLoc,
    v: VaxF<E, M>,
) -> Result<(), InterpExit> {
    if matches!(loc, FpLoc::Mem(_)) && v.is_reserved() && fps_flag(b, fps::FIUV) {
        fp_exc(b, pc0, fec::UV)?;
    }
    Ok(())
}

/// FP 演算の結果格納と例外。decfp の fp11 形（値, フラグ）を受け、
/// OF/UF は割込み許可に応じて指数ずらし形か真の零を AC に格納
/// してから FCC を立て、許可された例外は vector 244 へ出る。
/// FP_DZ（ゼロ除算）は AC 不変の中止（許可を問わない例外）。
fn fp_result<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    pc0: u16,
    acn: u8,
    v: VaxF<E, M>,
    fl: u8,
) -> Result<(), InterpExit> {
    if fl & FP_DZ != 0 {
        return fp_exc(b, pc0, fec::DZ);
    }
    let (v2, exc, fv) = if fl & FP_OF != 0 {
        (
            if fps_flag(b, fps::FIV) {
                v
            } else {
                VaxF::zero()
            },
            fps_flag(b, fps::FIV).then_some(fec::OV),
            true,
        )
    } else if fl & FP_UF != 0 {
        (
            if fps_flag(b, fps::FIU) {
                v
            } else {
                VaxF::zero()
            },
            fps_flag(b, fps::FIU).then_some(fec::UN),
            false,
        )
    } else {
        (v, None, false)
    };
    fp_ac_set::<E, M>(b, acn, v2);
    let (n, z) = fp_nz(v2);
    fp_fcc(b, n, z, fv, false);
    if let Some(code) = exc {
        fp_exc(b, pc0, code)?;
    }
    Ok(())
}

/// FP 形式値の格納（AC またはメモリ —— メモリは 3412 配置）。
fn fp_store<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    loc: &FpLoc,
    v: VaxF<E, M>,
) -> Result<(), InterpExit> {
    match *loc {
        FpLoc::Ac(n) => {
            fp_ac_set::<E, M>(b, n, v);
            Ok(())
        }
        FpLoc::Mem(a) => fp_mem_set::<E, M>(b, a, v),
    }
}

/// 二オペランド FP 命令の AC フィールド（<8:6> の下位 2 ビット
/// が実効 —— bit8 は命令対の選択子なので AC0-AC3）。
fn fp_acn(f: &Fetched) -> u8 {
    (ops_frd(u128::from(f.word)).reg as u8) & 3
}

/// FT が選ぶ丸めモード（立っていれば切捨て Rtz、消えていれば
/// 丸め Rmm = 「丸めビットが立てば chopped を 1 LSB 増分」）。
fn fp_rm(b: &InterpBackend) -> Rm {
    if fps_flag(b, fps::FT) {
        Rm::Rtz
    } else {
        Rm::Rmm
    }
}

/// FD が選ぶ FP 形式の命令群の意味論。`<8,23>` は F、`<8,55>` は D。
fn fp_main<const E: u32, const M: u32>(
    b: &mut InterpBackend,
    f: &Fetched,
    pc0: u16,
) -> Result<(), InterpExit> {
    match f.insn {
        // データ移動: AC ← fsrc。-0 は FIUV で実行前に trap
        // （FID 抑止なら -0 のまま AC に入る）。dirty zero も
        // そのまま移動する。
        Insn::Ldf => {
            let acn = fp_acn(f);
            let Some((loc, src)) = fp_opnd::<E, M>(b, f, pc0)? else {
                return Ok(());
            };
            fp_iuv_pre::<E, M>(b, pc0, &loc, src)?;
            fp_ac_set::<E, M>(b, acn, src);
            let (n, z) = fp_nz(src);
            fp_fcc(b, n, z, false, false);
        }
        // fdst ← AC（-0 もそのまま書く。FCC は変わらない）。
        Insn::Stf => {
            let acn = fp_acn(f);
            let Some(loc) = fp_loc::<M>(b, f, pc0)? else {
                return Ok(());
            };
            let a = fp_ac_get::<E, M>(b, acn);
            fp_store::<E, M>(b, &loc, a)?;
        }
        Insn::Clrf => {
            let Some(loc) = fp_loc::<M>(b, f, pc0)? else {
                return Ok(());
            };
            fp_store::<E, M>(b, &loc, VaxF::zero())?;
            fp_fcc(b, false, true, false, false);
        }
        Insn::Tstf => {
            let Some((loc, v)) = fp_opnd::<E, M>(b, f, pc0)? else {
                return Ok(());
            };
            let (n, z) = fp_nz(v);
            fp_fcc(b, n, z, false, false);
            fp_iuv_post::<E, M>(b, pc0, &loc, v)?;
        }
        Insn::Absf => {
            let Some((loc, v)) = fp_opnd::<E, M>(b, f, pc0)? else {
                return Ok(());
            };
            let r = if v.is_neg() {
                v.neg()
            } else if v.is_zero() || v.is_reserved() {
                VaxF::zero()
            } else {
                v
            };
            fp_store::<E, M>(b, &loc, r)?;
            let (n, z) = fp_nz(r);
            fp_fcc(b, n, z, false, false);
            fp_iuv_post::<E, M>(b, pc0, &loc, v)?;
        }
        Insn::Negf => {
            let Some((loc, v)) = fp_opnd::<E, M>(b, f, pc0)? else {
                return Ok(());
            };
            // decfp の neg は指数 0（真の零・dirty zero・-0）を
            // 真の零に畳む —— 「EXP=0 なら正確な零を格納」の規則。
            let r = v.neg();
            fp_store::<E, M>(b, &loc, r)?;
            let (n, z) = fp_nz(r);
            fp_fcc(b, n, z, false, false);
            fp_iuv_post::<E, M>(b, pc0, &loc, v)?;
        }
        // (fsrc) - (AC) の比較。両方零なら AC ← 正確な零
        // （KDJ11-E UG の注記 —— dirty zero/-0 の掃除）。
        Insn::Cmpf => {
            let acn = fp_acn(f);
            let Some((loc, src)) = fp_opnd::<E, M>(b, f, pc0)? else {
                return Ok(());
            };
            fp_iuv_pre::<E, M>(b, pc0, &loc, src)?;
            let src = fp_clean::<E, M>(src);
            let a = fp_clean::<E, M>(fp_ac_get::<E, M>(b, acn));
            if src.is_zero() && a.is_zero() {
                fp_ac_set::<E, M>(b, acn, VaxF::zero());
            }
            let (n, z) = match src.cmp(a) {
                Some(0) => (false, true),
                Some(c) if c < 0 => (true, false),
                _ => (false, false),
            };
            fp_fcc(b, n, z, false, false);
        }
        Insn::Addf | Insn::Subf | Insn::Mulf | Insn::Divf => {
            let acn = fp_acn(f);
            let Some((loc, src)) = fp_opnd::<E, M>(b, f, pc0)? else {
                return Ok(());
            };
            fp_iuv_pre::<E, M>(b, pc0, &loc, src)?;
            let src = fp_clean::<E, M>(src);
            let a = fp_clean::<E, M>(fp_ac_get::<E, M>(b, acn));
            let rm = fp_rm(b);
            let (v, fl) = match f.insn {
                Insn::Addf => a.add_fp11(src, rm),
                Insn::Subf => a.sub_fp11(src, rm),
                Insn::Mulf => a.mul_fp11(src, rm),
                _ => a.div_fp11(src, rm),
            };
            return fp_result::<E, M>(b, pc0, acn, v, fl);
        }
        // N = |AC*fsrc| の整数部（AC|1 へ —— 奇数 AC では格納
        // しない）、g = 小数部（AC へ）。例外の格納規則は
        // 演算系と同じ（指数 ±400₈）。
        Insn::Modf => {
            let acn = fp_acn(f);
            let Some((loc, src)) = fp_opnd::<E, M>(b, f, pc0)? else {
                return Ok(());
            };
            fp_iuv_pre::<E, M>(b, pc0, &loc, src)?;
            let src = fp_clean::<E, M>(src);
            let a = fp_clean::<E, M>(fp_ac_get::<E, M>(b, acn));
            let (n, g, fl) = a.modf_fp11(src, fp_rm(b));
            if fl & FP_OF != 0 {
                // PROD のオーバーフロー: ACv1 ← N（指数 -400₈）・
                // AC ← 0。FIV 不許可なら双方真の零。
                let (nv, exc) = if fps_flag(b, fps::FIV) {
                    (n, true)
                } else {
                    (VaxF::zero(), false)
                };
                if acn & 1 == 0 {
                    fp_ac_set::<E, M>(b, acn | 1, nv);
                }
                fp_ac_set::<E, M>(b, acn, VaxF::zero());
                fp_fcc(b, false, true, true, false);
                if exc {
                    fp_exc(b, pc0, fec::OV)?;
                }
            } else if fl & FP_UF != 0 {
                // PROD のアンダーフロー: ACv1 ← 0・AC ← g（指数
                // +400₈）。FIU 不許可なら双方真の零。
                let (gv, exc) = if fps_flag(b, fps::FIU) {
                    (g, true)
                } else {
                    (VaxF::zero(), false)
                };
                if acn & 1 == 0 {
                    fp_ac_set::<E, M>(b, acn | 1, VaxF::zero());
                }
                fp_ac_set::<E, M>(b, acn, gv);
                let (n2, z2) = fp_nz(gv);
                fp_fcc(b, n2, z2, false, false);
                if exc {
                    fp_exc(b, pc0, fec::UN)?;
                }
            } else {
                if acn & 1 == 0 {
                    fp_ac_set::<E, M>(b, acn | 1, n);
                }
                fp_ac_set::<E, M>(b, acn, g);
                let (n2, z2) = fp_nz(g);
                fp_fcc(b, n2, z2, false, false);
            }
        }
        _ => unreachable!("fp_main の対象外"),
    }
    Ok(())
}

/// STCFD —— 方向が FD で決まるため専用の経路。
fn fp_stcfd(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    let acn = fp_acn(f);
    if !fps_flag(b, fps::FD) {
        // F → D: AC<63:32> を読んで D 形式へ（正確 —— 低位 32
        // ビットは 0）。AC が零なら正確な零を格納。
        let a = fp_ac_get::<8, 23>(b, acn);
        let Some(loc) = fp_loc::<55>(b, f, pc0)? else {
            return Ok(());
        };
        let a = fp_clean::<8, 23>(a);
        let (d, _) = a.widen_rm::<8, 55>(Rm::Rmm);
        fp_store::<8, 55>(b, &loc, d)?;
        let (n, z) = fp_nz::<8, 23>(a);
        fp_fcc(b, n, z, false, false);
    } else {
        // D → F: AC を読んで F 形式へ。丸めは FT。丸め上げで
        // オーバーフローしたら FIV 不許可は正確な零、許可は
        // 結果の ±0 を格納して trap。
        let a = fp_ac_get::<8, 55>(b, acn);
        let Some(loc) = fp_loc::<23>(b, f, pc0)? else {
            return Ok(());
        };
        let a = fp_clean::<8, 55>(a);
        let (v, fl) = a.widen_rm::<8, 23>(fp_rm(b));
        if fl & FP_OF != 0 {
            let z = if fps_flag(b, fps::FIV) {
                VaxFF::from_bits((a.is_neg() as u128) << 31)
            } else {
                VaxFF::zero()
            };
            fp_store::<8, 23>(b, &loc, z)?;
            fp_fcc(b, false, true, true, false);
            if fps_flag(b, fps::FIV) {
                fp_exc(b, pc0, fec::OV)?;
            }
        } else {
            fp_store::<8, 23>(b, &loc, v)?;
            let (n, z) = fp_nz::<8, 23>(v);
            fp_fcc(b, n, z, false, false);
        }
    }
    Ok(())
}

/// LDCFF —— 方向が FD で決まるため専用の経路（LDF に似るが
/// ソースは逆形式）。
fn fp_ldcff(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    let acn = fp_acn(f);
    if !fps_flag(b, fps::FD) {
        // ソースは D 形式 → F へ縮めて AC<63:32> へ。丸めは FT。
        let Some((loc, src)) = fp_opnd::<8, 55>(b, f, pc0)? else {
            return Ok(());
        };
        fp_iuv_pre::<8, 55>(b, pc0, &loc, src)?;
        let src = fp_clean::<8, 55>(src);
        let (v, fl) = src.widen_rm::<8, 23>(fp_rm(b));
        if fl & FP_OF != 0 {
            let z = if fps_flag(b, fps::FIV) {
                VaxFF::from_bits((src.is_neg() as u128) << 31)
            } else {
                VaxFF::zero()
            };
            fp_ac_set::<8, 23>(b, acn, z);
            fp_fcc(b, false, true, true, false);
            if fps_flag(b, fps::FIV) {
                fp_exc(b, pc0, fec::OV)?;
            }
        } else {
            fp_ac_set::<8, 23>(b, acn, v);
            let (n, z) = fp_nz::<8, 23>(v);
            fp_fcc(b, n, z, false, false);
        }
    } else {
        // ソースは F 形式 → D へ広げて AC 全体へ（正確）。
        let Some((loc, src)) = fp_opnd::<8, 23>(b, f, pc0)? else {
            return Ok(());
        };
        fp_iuv_pre::<8, 23>(b, pc0, &loc, src)?;
        let src = fp_clean::<8, 23>(src);
        let (d, _) = src.widen_rm::<8, 55>(Rm::Rmm);
        fp_ac_set::<8, 55>(b, acn, d);
        let (n, z) = fp_nz::<8, 55>(d);
        fp_fcc(b, n, z, false, false);
    }
    Ok(())
}

/// 整数オペランド（CPU 番地指定）の読み出し —— FL で I/L。
/// L 形式は低番地語が上位語の 3412 配置。モード 0・即値の
/// L 形は 16 ビット語を上位に左寄せ（残り 16 ビットは 0）。
fn fp_int_src(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<i32, InterpExit> {
    let long = fps_flag(b, fps::FL);
    let w = if long { Width::L } else { Width::W };
    let loc = eval_op_w(b, f, pc0, 0, w)?;
    Ok(match loc {
        Loc::Reg(n) if !long => r_get(b, n) as i16 as i32,
        Loc::Reg(n) => i32::from(r_get(b, n)) << 16,
        Loc::Mem(a) if !long => load_w(b, a)? as i16 as i32,
        Loc::Mem(a) => {
            let hi = load_w(b, a)?;
            let lo = load_w(b, a.wrapping_add(2))?;
            ((u32::from(hi) << 16) | u32::from(lo)) as i32
        }
        Loc::Imm { v, .. } if !long => v as i16 as i32,
        Loc::Imm { v, .. } => i32::from(v) << 16,
    })
}

/// 整数オペランド（CPU 番地指定）への書き込み —— L 形の
/// モード 0・即値は上位 16 ビットのみ書く。
fn fp_int_dst(b: &mut InterpBackend, f: &Fetched, pc0: u16, v: i32) -> Result<(), InterpExit> {
    let long = fps_flag(b, fps::FL);
    let w = if long { Width::L } else { Width::W };
    let loc = eval_op_w(b, f, pc0, 0, w)?;
    match loc {
        Loc::Reg(n) => {
            let wv = if long { (v >> 16) as u16 } else { v as u16 };
            r_set(b, n, wv);
        }
        Loc::Mem(a) if !long => store_w(b, a, v as u16)?,
        Loc::Mem(a) => {
            store_w(b, a, (v >> 16) as u16)?;
            store_w(b, a.wrapping_add(2), v as u16)?;
        }
        Loc::Imm { addr, .. } if !long => store_w(b, addr, v as u16)?,
        Loc::Imm { addr, .. } => store_w(b, addr, (v >> 16) as u16)?,
    }
    Ok(())
}

/// FP11 命令の意味論の総合口。`exec` から呼ぶ。
fn fp11_exec(b: &mut InterpBackend, f: &Fetched, pc0: u16) -> Result<(), InterpExit> {
    match f.insn {
        Insn::Cfcc => {
            // FPS<3:0> を PSW<3:0>（NZVC）へ写す。
            psw_put(b, psw_get(b) & !0xF | fps_get(b) & 0xF);
        }
        Insn::Setf => fps_flag_set(b, fps::FD, false),
        Insn::Setd => fps_flag_set(b, fps::FD, true),
        Insn::Seti => fps_flag_set(b, fps::FL, false),
        Insn::Setl => fps_flag_set(b, fps::FL, true),
        Insn::Ldfps => {
            let s = eval_op(b, f, pc0, 0)?;
            let v = read(b, &s, Width::W)?;
            // 桁 13・12・4 は STFPS で読み出せない —— 読み出し側
            // で 0 に見えるよう書き込み時に消す。
            fps_put(b, v & !fps::NOREC);
        }
        Insn::Stfps => {
            let d = eval_op(b, f, pc0, 0)?;
            write(b, &d, Width::W, fps_get(b))?;
        }
        // dst ← FEC、dst+2 ← FEA。モード 0・即値宛先は FEC のみ。
        Insn::Stst => {
            let d = eval_op(b, f, pc0, 0)?;
            write(b, &d, Width::W, get16(b, fec_ref()))?;
            if let Loc::Mem(a) = d {
                store_w(b, a.wrapping_add(2), get16(b, fea_ref()))?;
            }
        }
        // dst ← EXP[AC] - 200₈（AC の指数フィールドは F/D で同じ
        // 位置 AC<62:55> —— F が左詰めなので）。CPU CC と FPP CC
        // の双方を立てる。
        Insn::Stexp => {
            let acn = fp_acn(f);
            let e = (get64(b, ac_ref(acn)) >> 55) & 0xff;
            let v = (e as i32 - 0o200) as i16 as u16;
            let d = eval_op(b, f, pc0, 0)?;
            write(b, &d, Width::W, v)?;
            cc_tst(b, v, Width::W);
            fp_fcc(b, v & 0x8000 != 0, v == 0, false, false);
        }
        // EXP[AC] ← (src) + 200₈。src は CPU 番地の符号付き語で、
        // 範囲外（>177 はオーバーフロー、< -177 はアンダーフロー）
        // は許可があれば指数を 8 ビットに折り返して trap、なければ
        // 正確な零を AC に格納（FIV/FIU の規則と同じ）。
        Insn::Ldexp => {
            let acn = fp_acn(f);
            // src は常に 16 ビット語（FL は整数変換にだけ効く）。
            let loc = eval_op_w(b, f, pc0, 0, Width::W)?;
            let s = i32::from(read(b, &loc, Width::W)? as i16);
            let ac = get64(b, ac_ref(acn));
            let exc = if s > 0o177 {
                Some((fec::OV, fps::FIV))
            } else if s < -0o177 {
                Some((fec::UN, fps::FIU))
            } else {
                None
            };
            let nac = match exc {
                // 割込み不許可の範囲外指数 → AC ← 正確な零。
                Some((_, bit)) if !fps_flag(b, bit) => 0,
                // 範囲内、または許可された範囲外 → 8 ビットに
                // 折り返した指数フィールド。
                _ => (ac & !(0xffu64 << 55)) | ((((s + 0o200) & 0xff) as u64) << 55),
            };
            let fv = matches!(exc, Some((fec::OV, _)));
            set64(b, ac_ref(acn), nac);
            let (n, z) = {
                let bits = nac;
                let exp = (bits >> 55) & 0xff;
                (bits & (1u64 << 63) != 0 && exp != 0, exp == 0)
            };
            fp_fcc(b, n, z, fv, false);
            if let Some((code, bit)) = exc
                && fps_flag(b, bit)
            {
                fp_exc(b, pc0, code)?;
            }
        }
        // 整数 → 浮動（FL で I/L、FD で F/D）。L 形のモード 0・
        // 即値は 16 ビット語の左寄せ。丸めは FT（D なら常に正確）。
        Insn::Ldcif => {
            let acn = fp_acn(f);
            let v = fp_int_src(b, f, pc0)?;
            let rm = fp_rm(b);
            if fps_flag(b, fps::FD) {
                let d = VaxDF::from_i32(v, rm);
                fp_ac_set::<8, 55>(b, acn, d);
                let (n, z) = fp_nz::<8, 55>(d);
                fp_fcc(b, n, z, false, false);
            } else {
                let d = VaxFF::from_i32(v, rm);
                fp_ac_set::<8, 23>(b, acn, d);
                let (n, z) = fp_nz::<8, 23>(d);
                fp_fcc(b, n, z, false, false);
            }
        }
        // 浮動 → 整数（常に切捨て —— FT によらない）。範囲外は
        // dst ← 0・FC=1 で、FIC が立っていれば trap。CC は CPU
        // と FPP の双方に出る。
        Insn::Stcfi => {
            let acn = fp_acn(f);
            let a = if fps_flag(b, fps::FD) {
                fp_clean::<8, 55>(fp_ac_get::<8, 55>(b, acn)).to_i32(false)
            } else {
                fp_clean::<8, 23>(fp_ac_get::<8, 23>(b, acn)).to_i32(false)
            };
            let long = fps_flag(b, fps::FL);
            let ok = a.1 & FP_IOV == 0 && (long || i32::from(a.0 as i16) == a.0);
            let (stored, fail) = if ok { (a.0, false) } else { (0, true) };
            fp_int_dst(b, f, pc0, stored)?;
            let sv = if long {
                stored
            } else {
                i32::from(stored as i16)
            };
            let (n, z) = (sv < 0, sv == 0);
            psw_flag_set(b, psw::N, n);
            psw_flag_set(b, psw::Z, z);
            psw_flag_set(b, psw::V, false);
            psw_flag_set(b, psw::C, fail);
            fp_fcc(b, n, z, false, fail);
            if fail && fps_flag(b, fps::FIC) {
                fp_exc(b, pc0, fec::CVT)?;
            }
        }
        Insn::Stcfd => return fp_stcfd(b, f, pc0),
        Insn::Ldcff => return fp_ldcff(b, f, pc0),
        // F/D 形式の命令群 —— FD で形式を選んで fp_main へ。
        Insn::Ldf
        | Insn::Stf
        | Insn::Clrf
        | Insn::Tstf
        | Insn::Absf
        | Insn::Negf
        | Insn::Cmpf
        | Insn::Addf
        | Insn::Subf
        | Insn::Mulf
        | Insn::Divf
        | Insn::Modf => {
            return if fps_flag(b, fps::FD) {
                fp_main::<8, 55>(b, f, pc0)
            } else {
                fp_main::<8, 23>(b, f, pc0)
            };
        }
        _ => unreachable!("fp11_exec の対象外"),
    }
    Ok(())
}

/// FP 指定子が即値（モード 2 の PC 形）のとき命令が消費する
/// 追加の語 —— F/D オペランドは 4/8 バイトを命令ストリーム
/// から読むので、指定子デコードが見る 1 語を超える分を返す
/// （変換系はソースの形式が FD の逆になる）。整数・制御系の
/// オペランドと非即値指定子は 0。
pub fn fp_imm_extra(b: &InterpBackend, f: &Fetched) -> u16 {
    if !matches!(f.ops.first(), Some(Spec::Imm(_))) {
        return 0;
    }
    let fd = fps_flag(b, fps::FD);
    match f.insn {
        Insn::Ldf
        | Insn::Stf
        | Insn::Clrf
        | Insn::Tstf
        | Insn::Absf
        | Insn::Negf
        | Insn::Cmpf
        | Insn::Addf
        | Insn::Subf
        | Insn::Mulf
        | Insn::Divf
        | Insn::Modf => (if fd { 8 } else { 4 }) - 2,
        Insn::Ldcff | Insn::Stcfd => (if fd { 4 } else { 8 }) - 2,
        _ => 0,
    }
}

// ---- トラップ配送 ----

/// トラップの配送。古い PSW と PC を（この順に）ベクタの新 PSW が
/// 指すモードのスタックに積み、新しい PC/PSW を読む実機の形。
/// `stacked` は積む PC（trap は次の命令、fault は命令先頭 ——
/// 呼び出し側の規則）。ベクタの読み出しはカーネルデータ空間、
/// プッシュは新モードのデータ空間（`mmu` 経由 —— ARCH83 第9章の
/// メモリ管理制御下の割込み条件）。現在の SP は現モードの退避先へ
/// 保存してから新モードの退避先を読み、新 PSW の prev モードには
/// 旧モードを挿入する。モード値 2（予約）はカーネル枠に畳む
/// 決定的な選択。
// Ref: SPEC-PDP11-ARCH83（第8章 トラップと割込み・第9章 メモリ管理
// 制御下の割込み条件）.
pub fn deliver(b: &mut InterpBackend, vec: u16, stacked: u16) -> Result<(), InterpExit> {
    let old_psw = psw_get(b);
    // ベクタの 2 語はカーネルデータ空間から読む（MMR3<2> が立って
    // いれば D、無ければ I —— ARCH83 第9章・simh の calc_ds(K)）。
    let new_pc = mmu::rd_w(b, vec, psw::KERNEL, mmu::Space::D)?;
    let new_psw = mmu::rd_w(b, vec.wrapping_add(2), psw::KERNEL, mmu::Space::D)?;
    let old_mode = old_psw >> psw::CUR_MOD & psw::MOD_MASK;
    // モード桁を持たないモデル（mode_enc=none）ではベクタ PSW の
    // モード値も 0 に畳む —— モード切替自体が起きない。
    let new_mode = if b.param::<ModeEncParam>() == MODE_ENC_NONE {
        psw::KERNEL
    } else {
        new_psw >> psw::CUR_MOD & psw::MOD_MASK
    };
    set16(b, mode_sp_ref(old_mode), r_get(b, reg::SP as u8));
    r_set(b, reg::SP as u8, get16(b, mode_sp_ref(new_mode)));
    // -(SP) ← PSW、-(SP) ← PC —— 新モードのデータ空間に積む
    // （RTI が PC→PSW の順に戻す形）。
    let mut sp = r_get(b, reg::SP as u8);
    sp = sp.wrapping_sub(2);
    r_set(b, reg::SP as u8, sp);
    store_w_as(b, sp, new_mode, mmu::Space::D, old_psw)?;
    sp = sp.wrapping_sub(2);
    r_set(b, reg::SP as u8, sp);
    store_w_as(b, sp, new_mode, mmu::Space::D, stacked)?;
    r_set(b, reg::PC as u8, new_pc);
    // prev モードには旧モードを入れる（ベクタの PSW<13:12> は
    // 捨てる —— ARCH83 第8章・simh の PM 挿入規則）。
    let merged = (new_psw & !(psw::MOD_MASK << psw::PRV_MOD)) | old_mode << psw::PRV_MOD;
    let merged = if b.param::<ModeEncParam>() == MODE_ENC_NONE {
        merged & !0o17_0000
    } else {
        merged
    };
    psw_put(b, merged);
    if b.param::<crate::DualRegsetParam>() && (old_psw ^ merged) >> psw::RS & 1 != 0 {
        mmu::rs_swap(b);
    }
    // トラップ経路の MMU 簿記: 命令トラップ群（ILL/BPT/IOT/EMT/
    // TRAP）以外は MMR2 ← ベクタ・MMR1 ← 0（simh の
    // trap_load_mmr2 規則）。
    mmu::ops::trap_load(b, vec);
    // カーネルスタックのイエローゾーン —— プッシュで限界を割った
    // ら vector 004 を引き継ぐ（赤ゾーン化してもう一度踏んだら
    // 配送自体が失敗して終端する）。
    if vec != tv::BUS && new_mode == psw::KERNEL && mmu::stk_below(b) {
        return deliver(b, tv::BUS, stacked);
    }
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
/// `pc0` は命令の先頭アドレス。`feats` は生成デコーダの機能
/// ビット（命令の有無はデコード側が裁くので、ここでは同じ命令語が
/// モデルで振る舞いを分ける効果 —— RS 桁の実効 —— にだけ使う）。
// Ref: SPEC-PDP11-ARCH83（第5章 各命令の意味論）.
pub fn exec(b: &mut InterpBackend, f: &Fetched, pc0: u16, feats: u128) -> Result<(), InterpExit> {
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
            // V: ほとんどのモデルは 0 に消す。11/15・11/20 だけ保存
            // （付録 B 項目 6 —— 現モデル集合は全て clear）。
            if b.param::<SwabVParam>() != SWAB_V_KEEP {
                psw_flag_set(b, psw::V, false);
            }
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
        // ---- EIS（PD9）----
        // レジスタ対は R（上位）と Rv1 = R OR 1（下位）—— 奇数 R
        // では両者が同じレジスタになる（mul は「低位積のみ格納」に
        // 一致。div は偶数 R が建前で、奇数 R の Rv1=R 読みは文字
        // どおりの規則に沿う決定的な選択）。FRD 形の宛先スロット
        // にはソース指定子が入る（読み出し側）。
        // Ref: SPEC-PDP11-ARCH83（第5章 EIS）.
        Insn::Mul => {
            let n = ops_frd(u128::from(f.word)).reg as u8;
            let s = eval_op(b, f, pc0, 0)?;
            let sv = i32::from(read(b, &s, Width::W)? as i16);
            let prod = i32::from(r_get(b, n) as i16) * sv;
            // R ← 積の上位、Rv1 ← 下位（奇数 R では同じレジスタへ
            // 上位→下位の順に書くので下位が残る）。
            r_set(b, n, (prod >> 16) as u16);
            r_set(b, n | 1, prod as u16);
            // CC は R が奇数でも 32 ビット積全体で立つ。
            psw_flag_set(b, psw::N, prod < 0);
            psw_flag_set(b, psw::Z, prod == 0);
            psw_flag_set(b, psw::V, false);
            // C = 積が符号付き 16 ビットに収まらない。
            psw_flag_set(b, psw::C, !(-0x8000..0x8000).contains(&prod));
        }
        // Gap: GAP-0082（奇数 R・例外経路の不定域は決定的選択）
        Insn::Div => {
            let n = ops_frd(u128::from(f.word)).reg as u8;
            let s = eval_op(b, f, pc0, 0)?;
            let sv = i32::from(read(b, &s, Width::W)? as i16);
            let dvd = (u32::from(r_get(b, n)) << 16 | u32::from(r_get(b, n | 1))) as i32;
            if sv == 0 {
                // 0 除算: V=1・C=1。レジスタと N・Z は変えない。
                psw_flag_set(b, psw::V, true);
                psw_flag_set(b, psw::C, true);
            } else if let Some(q) = dvd
                .checked_div(sv)
                .filter(|q| (-0x8000..0x8000).contains(q))
            {
                // 商は 0 方向への切詰、剰余は被除数と同符号
                // （Rust の /・% と同じ向き）。i32::MIN / -1 は
                // Rust では panic する組 —— checked_div が None
                // を返しオーバーフロー経路に畳まれる。
                let rem = dvd % sv;
                // R ← 商、Rv1 ← 剰余（奇数 R では剰余が残る）。
                r_set(b, n, q as u16);
                r_set(b, n | 1, rem as u16);
                psw_flag_set(b, psw::N, q < 0);
                psw_flag_set(b, psw::Z, q == 0);
                psw_flag_set(b, psw::V, false);
                psw_flag_set(b, psw::C, false);
            } else {
                // 商が 16 ビット 2 の補数に収まらない → V=1・C=0
                // で命令は中断される。R,Rv1 と N・Z は不定 —
                // 変えない決定的な選択。
                psw_flag_set(b, psw::V, true);
                psw_flag_set(b, psw::C, false);
            }
        }
        Insn::Ash | Insn::Ashc => {
            let n = ops_frd(u128::from(f.word)).reg as u8;
            let s = eval_op(b, f, pc0, 0)?;
            let sv = read(b, &s, Width::W)?;
            let cnt = shift_cnt(sv);
            if f.insn == Insn::Ash {
                let (v, cout, schg) = ashift(u64::from(r_get(b, n)), 16, cnt);
                r_set(b, n, v as u16);
                cc_nz(b, v as u16, Width::W);
                // C=最後に出た桁、V=シフト中に符号が変わったか。
                // どちらも NN=0 では消える。
                psw_flag_set(b, psw::C, cnt != 0 && cout);
                psw_flag_set(b, psw::V, cnt != 0 && schg);
            } else {
                // 32 ビット対 R:R|1 をシフト。奇数 R では被演算が
                // R:R —— 右シフトは 16 ビットの回転になる規則と
                // 一致する（KE11-E/BLUEFISH の奇数 R 記述どおり）。
                let pair = u64::from(r_get(b, n)) << 16 | u64::from(r_get(b, n | 1));
                let (v, cout, schg) = ashift(pair, 32, cnt);
                // R ← 結果 <31:16>、次に Rv1 ← <15:0>（奇数 R では
                // 下位の書き込みが残る）。
                r_set(b, n, (v >> 16) as u16);
                r_set(b, n | 1, v as u16);
                // CC は常に 32 ビット結果で立つ。
                psw_flag_set(b, psw::N, v & 0x8000_0000 != 0);
                psw_flag_set(b, psw::Z, v == 0);
                psw_flag_set(b, psw::V, cnt != 0 && schg);
                psw_flag_set(b, psw::C, cnt != 0 && cout);
            }
        }
        // ---- FIS（PD9）----
        // 0750xR。汎用レジスタがフレームを指す（詳しくは fis_exec）。
        // FMUL/FDIV は実機（LSI-11 系 KEV11）で R6 スタックへ
        // 1 語 push/pop する —— SP は書き込み可能メモリを指す必要
        // がある（付録 C 注記・付録 B 項目 22）。中断の規則
        // （BR 要求で命令をやり直す）は裸実行では割込みが起きない。
        // Gap: GAP-0082（中断規則は push/pop のみ再現）
        Insn::Fadd | Insn::Fsub | Insn::Fmul | Insn::Fdiv => {
            let n = ops_ff(u128::from(f.word)).freg as u8;
            let scratch = matches!(f.insn, Insn::Fmul | Insn::Fdiv);
            if scratch {
                // -(SP) に作業語。書き込みを先に済ませてから SP を
                // 進める —— バスエラーなら SP は元のまま fault。
                let sp = r_get(b, reg::SP as u8).wrapping_sub(2);
                store_w(b, sp, 0)?;
                r_set(b, reg::SP as u8, sp);
            }
            let r = fis_exec(b, n, f.insn);
            if scratch {
                let sp = r_get(b, reg::SP as u8).wrapping_add(2);
                r_set(b, reg::SP as u8, sp);
            }
            r?;
        }
        // ---- FP11（PD10）----
        // 17xxxx 空間。状態・例外・丸めの規則は fp11_exec 周辺。
        Insn::Cfcc
        | Insn::Setf
        | Insn::Setd
        | Insn::Seti
        | Insn::Setl
        | Insn::Ldfps
        | Insn::Stfps
        | Insn::Stst
        | Insn::Clrf
        | Insn::Tstf
        | Insn::Absf
        | Insn::Negf
        | Insn::Mulf
        | Insn::Modf
        | Insn::Addf
        | Insn::Ldf
        | Insn::Subf
        | Insn::Cmpf
        | Insn::Stf
        | Insn::Divf
        | Insn::Stexp
        | Insn::Stcfi
        | Insn::Stcfd
        | Insn::Ldexp
        | Insn::Ldcif
        | Insn::Ldcff => return fp11_exec(b, f, pc0),
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
            mmu::ops::mmr1_raw(b, 0o366);
            mmu::ops::stk_chk(b);
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
            mmu::ops::mmr1_raw(b, 0o26);
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
        // RTI/RTT: (SP)+ → PC、(SP)+ → PSW でスタックから復元する。
        // カーネル以外で実行したときの PSW は保護規則が掛かる ——
        // 優先度 <7:5> は現値のまま、モード桁 <15:12> は旧値との OR
        // でしか下がらない（supervisor から kernel へは戻れない、
        // user からは user のみ）、RS <11> は消せない（ARCH83 第5章
        // RTI/RTT の記述）。モードが変われば SP もモード別退避先経由で
        // 切替わる。T ビットトラップの発火点は run 側が裁く（RTT は
        // 次の命令の実行後まで抑止、RTI は `rti_ttrap` パラメータ）。
        Insn::Rti | Insn::Rtt => {
            let old_psw = psw_get(b);
            let sp0 = r_get(b, reg::SP as u8);
            // pop は現モードのデータ空間（RTI は SP+4 を旧モード枠に
            // 退避してから切替える）。
            let new_pc = load_w(b, sp0)?;
            let new_psw = load_w(b, sp0.wrapping_add(2))?;
            mmu::ops::mmr1_raw(b, 0o26);
            mmu::ops::mmr1_raw(b, 0o26);
            let cur_mode = old_psw >> psw::CUR_MOD & psw::MOD_MASK;
            let merged = if cur_mode == psw::KERNEL {
                new_psw
            } else {
                // 非カーネルの PSW 書き込み保護（上記コメント）。
                (new_psw & !(psw::PRI_MASK | 0o17_0000 | 1 << psw::RS))
                    | (old_psw & psw::PRI_MASK)
                    | ((old_psw | new_psw) & (0o17_0000 | 1 << psw::RS))
            };
            r_set(b, reg::SP as u8, sp0.wrapping_add(4));
            mmu::psw_apply(b, merged);
            r_set(b, reg::PC as u8, new_pc);
        }
        // SPL: PSW<7:5> ← n3。カーネルモードでのみ効き、他のモードでは
        // NOP（CC は不変）。
        Insn::Spl => {
            if psw_get(b) >> psw::CUR_MOD & psw::MOD_MASK == psw::KERNEL {
                let n = ops_fn3(u128::from(f.word)).n3 as u16;
                psw_put(b, psw_get(b) & !psw::PRI_MASK | n << psw::PRI);
            }
        }
        // MTPS: PSW<7:0> ← src.byte。T <4> はこの命令では書けない
        // （保存 —— ARCH83 第5章 MTPS の記述・付録 B 項目 14）。カーネル
        // 以外では NZVC <3:0> だけが書き換わる。
        Insn::Mtps => {
            let s = eval_op(b, f, pc0, 0)?;
            let v = read(b, &s, Width::B)? & 0xff;
            let p = psw_get(b);
            let mode = p >> psw::CUR_MOD & psw::MOD_MASK;
            if b.param::<MtpsMapParam>() == MTPS_MAP_MAPPED && mode == psw::USER {
                // ユーザーモードの MTPS は PSW 写像（177776）経由の
                // バイト書き込み —— メモリ管理トラップを起こし得る。
                // 成立すれば PS<7:5>+<3:0> に効く（付録 B 項目 40。
                // 11/34 のみ）。
                mmu::psw_io(b, true)?;
                psw_put(b, p & !0o357 | v & 0o357);
            } else {
                psw_put(
                    b,
                    if mode == psw::KERNEL {
                        p & !(0xff & !(1 << psw::T)) | v & !(1 << psw::T)
                    } else {
                        p & !0xf | v & 0xf
                    },
                );
            }
        }
        // MFPI/MFPD: 前モード（PSW<13:12>）の空間から dst を読んで
        // 現スタックに -(SP) で積む。MFPI は前モード I 空間、MFPD は
        // 前モード D 空間 —— ただし前・現ともに user のとき MFPI は
        // user D 空間を読む（user から I 空間は見えない —
        // ARCH83 第9章 Table の注記。MTPI も同じ規則で D を書く）。
        // モード 0 の r6 は前モードの SP 退避先を指す。CC: N・Z
        // （値による）・V=0・C 不変。
        Insn::Mfpi | Insn::Mfpd => {
            // MFPD/MTPD は分離 I/D を持つモデルのみ（spec の注記 —
            // デコードは mmu 群として受けてからここで弾く）。
            if f.insn == Insn::Mfpd && feats & FEAT_ID_SPLIT == 0 {
                return Err(fault(tv::ILL));
            }
            let d = eval_op(b, f, pc0, 0)?;
            let (cm, pm) = (mmu::cur_mode(b), mmu::prev_mode(b));
            let d_space = f.insn == Insn::Mfpd || (cm == pm && pm == psw::USER);
            let v = match d {
                Loc::Reg(n) => {
                    if n == reg::SP as u8 && cm != pm {
                        // 前モード値 2（予約）は J-11 でユーザー
                        // スタック、他モデルは不定 → カーネル枠
                        // （付録 B 項目 52）。
                        let p = sp_pm(b, pm);
                        get16(b, mode_sp_ref(p))
                    } else {
                        r_get(b, n)
                    }
                }
                Loc::Mem(a) => load_w_as(
                    b,
                    a,
                    pm,
                    if d_space {
                        mmu::Space::D
                    } else {
                        mmu::Space::I
                    },
                )?,
                Loc::Imm { v, .. } => v,
            };
            let sp = r_get(b, reg::SP as u8).wrapping_sub(2);
            r_set(b, reg::SP as u8, sp);
            store_w(b, sp, v)?;
            mmu::ops::mmr1_raw(b, 0o366);
            mmu::ops::stk_chk(b);
            psw_flag_set(b, psw::N, v & 0o100000 != 0);
            psw_flag_set(b, psw::Z, v == 0);
            psw_flag_set(b, psw::V, false);
        }
        // MTPI/MTPD: (SP)+ で積まれた値を前モードの空間の dst へ
        // 書く。空間規則は MFPx と同じ（MFPI 対の user-user 特例を
        // MTPI も持つ —— ARCH83 第9章）。
        Insn::Mtpi | Insn::Mtpd => {
            if f.insn == Insn::Mtpd && feats & FEAT_ID_SPLIT == 0 {
                return Err(fault(tv::ILL));
            }
            let d = eval_op(b, f, pc0, 0)?;
            let (cm, pm) = (mmu::cur_mode(b), mmu::prev_mode(b));
            let d_space = f.insn == Insn::Mtpd || (cm == pm && pm == psw::USER);
            let sp0 = r_get(b, reg::SP as u8);
            let v = load_w(b, sp0)?;
            r_set(b, reg::SP as u8, sp0.wrapping_add(2));
            mmu::ops::mmr1_raw(b, 0o26);
            match d {
                Loc::Reg(n) => {
                    if n == reg::SP as u8 && cm != pm {
                        let p = sp_pm(b, pm);
                        set16(b, mode_sp_ref(p), v);
                    } else {
                        r_set(b, n, v);
                    }
                }
                Loc::Mem(a) | Loc::Imm { addr: a, .. } => store_w_as(
                    b,
                    a,
                    pm,
                    if d_space {
                        mmu::Space::D
                    } else {
                        mmu::Space::I
                    },
                    v,
                )?,
            }
            psw_flag_set(b, psw::N, v & 0o100000 != 0);
            psw_flag_set(b, psw::Z, v == 0);
            psw_flag_set(b, psw::V, false);
        }
        // MFPS: dst.byte ← PS<7:0>。N=PS bit7・Z=PS<7:0>=0・V=0・C 不変
        // （モード 0 宛ては bit7 の符号拡張 —— `write` の byte→レジスタ
        // 規則が担う）。
        Insn::Mfps => {
            let d = eval_op(b, f, pc0, 0)?;
            // mtps_map=mapped モデルのユーザーモード MFPS は PSW
            // 写像経由 —— MM トラップを起こし得る（付録 B 項目 41）。
            if b.param::<MtpsMapParam>() == MTPS_MAP_MAPPED && mmu::cur_mode(b) == psw::USER {
                mmu::psw_io(b, false)?;
            }
            let v = psw_get(b) & 0xff;
            write(b, &d, Width::B, v)?;
            cc_mov(b, v, Width::B);
        }
        // MFPT: R0 ← プロセッサ型番（`mfpt_code` パラメータ。上位バイトは
        // サブコードで現行全モデル 0 —— ARCH83 第5章 MFPT の記述）。
        Insn::Mfpt => {
            let code = b.param::<MfptCodeParam>() as u16;
            r_set(b, 0, code);
        }
        // CSM: MMR3<3> が立ち現モードがカーネル以外なら、スーパーバイザ
        // モードへ移って引数語呼出を行う（KDJ11-E UG 8.7.5・ARCH83 第5章
        // CSM の記述）。SSP ← 現 SP、積む PSW は CC 消し、prev ← cur、
        // cur ← supervisor、T ← 0、-(SP) に PSW・PC・(dst) の順、PC ← (10)。
        // 条件が合わなければ vector 010 に fault。
        Insn::Csm => {
            let mode = psw_get(b) >> psw::CUR_MOD & psw::MOD_MASK;
            if mode == psw::KERNEL || mmr_get(b, 3) & 0o10 == 0 {
                return Err(fault(tv::ILL));
            }
            let d = eval_op(b, f, pc0, 0)?;
            let dv = read(b, &d, Width::W)?;
            let p = psw_get(b);
            // 「supervisor SP ← 現モード SP」—— 呼出し側のスタックが
            // スーパーバイザスタックになる。モード切替の退避規則で現
            // モードの退避先にも同じ値を残す（RTI の復帰が取る面）。
            let sp = r_get(b, reg::SP as u8);
            set16(b, ssp_ref(), sp);
            set16(b, mode_sp_ref(mode), sp);
            let temp = p & 0o177_760;
            psw_put(
                b,
                p & !(0o17 << psw::PRV_MOD | 1 << psw::T)
                    | mode << psw::PRV_MOD
                    | psw::SUPERVISOR << psw::CUR_MOD,
            );
            // -(SP) ← temp(PSW 形)、-(SP) ← PC、-(SP) ← 引数語 ——
            // 復帰は引数語を捨ててから RTI（PC→PSW の順に pop）。
            let mut sp = r_get(b, reg::SP as u8);
            for v in [temp, r_get(b, reg::PC as u8), dv] {
                sp = sp.wrapping_sub(2);
                r_set(b, reg::SP as u8, sp);
                store_w(b, sp, v)?;
            }
            mmu::ops::stk_chk(b);
            let target = load_w(b, 0o10)?;
            r_set(b, reg::PC as u8, target);
        }
        // TSTSET: R0 ← (dst)、(dst) ← (dst) ∨ 1 の読み書き不可分
        // （バスロック —— 単一スレッド近似）。N・Z は読み出した値、
        // V=0、C=旧 dst の bit0。モード 0 は vector 010 に fault。
        // Gap: GAP-0081
        Insn::Tstset => {
            let d = eval_op(b, f, pc0, 0)?;
            if let Loc::Reg(_) = d {
                return Err(fault(tv::ILL));
            }
            let dv = read(b, &d, Width::W)?;
            r_set(b, 0, dv);
            write(b, &d, Width::W, dv | 1)?;
            cc_nz(b, dv, Width::W);
            psw_flag_set(b, psw::V, false);
            psw_flag_set(b, psw::C, dv & 1 != 0);
        }
        // WRTLCK: (dst) ← R0 の書き込みロック（読み側の語は捨てる。
        // 単一スレッド近似）。N・Z は R0 の値、V=0、C 不変。モード 0 は
        // vector 010 に fault。
        // Gap: GAP-0081
        Insn::Wrtlck => {
            let d = eval_op(b, f, pc0, 0)?;
            if let Loc::Reg(_) = d {
                return Err(fault(tv::ILL));
            }
            let v = r_get(b, 0);
            write(b, &d, Width::W, v)?;
            cc_mov(b, v, Width::W);
        }
        // RESET: システムバスへ INIT を出す（カーネルモード。他のモード
        // では NOP —— KDJ11-E UG）。バス装置を持たない裸モデルでは
        // 効果が起きないので NOP として決定的に振る舞う。
        // Gap: GAP-0081
        Insn::Reset => {}
        Insn::Bpt => return Err(trap(tv::BPT)),
        Insn::Iot => return Err(trap(tv::IOT)),
        Insn::Emt => return Err(trap(tv::EMT)),
        Insn::Trap => return Err(trap(tv::TRAP)),
        // halt は CPU 停止（カーネルモード）。停止状態の表現がない
        // 裸モデルでは実行の終端として Unimplemented に写す決定的な
        // 選択。スーパーバイザ・ユーザーモードでは location 4 に
        // トラップする（KDJ11-E UG 8.4.1）。wait は割込み待ち ——
        // 割込みは裸実行で発生しない。
        Insn::Halt => {
            if psw_get(b) >> psw::CUR_MOD & psw::MOD_MASK != psw::KERNEL {
                // 非カーネルの HALT はモデルでトラップ先が分かれる
                // （付録 B 項目 43）。powerup（T-11）は起動ベクタを
                // 持たない裸モデルでは終端に畳む。
                // Gap: GAP-0086
                return match b.param::<HaltVecParam>() {
                    HALT_VEC_VEC004 => Err(trap(tv::BUS)),
                    HALT_VEC_POWERUP => Err(InterpExit::Unimplemented(format!("{:?}", f.insn))),
                    _ => Err(trap(tv::ILL)),
                };
            }
            return Err(InterpExit::Unimplemented(format!("{:?}", f.insn)));
        }
        Insn::Wait => {
            // WAIT は割込み待ち —— 裸実行で割込みは来ないので止まる
            // 以外ない。ただし wait_t=seq のモデルで T が立つと
            // 命令として抜けて trace trap へ進む（付録 B 項目 13）。
            if b.param::<WaitTParam>() == WAIT_T_SEQ && psw_flag(b, psw::T) {
                return Ok(());
            }
            return Err(InterpExit::Unimplemented(format!("{:?}", f.insn)));
        }
        // LSI-11 の保守命令 00021x（付録 B 項目 33）。マイクロコード
        // 内部の診断動作で建築状態への効果は正本に未規定 —— NOP と
        // する決定的近似。
        // Gap: GAP-0086
        Insn::Maint => {}
        // CIS（PD11 —— 076nnn。記述子形と in-line 形の文字列・
        // 数値・パック文字列命令）。中断可能な命令は cis.rs 側で
        // 記述子の進行を書き戻して命令先頭へ再入する。
        Insn::L2d
        | Insn::L3d
        | Insn::Movc
        | Insn::Movrc
        | Insn::Movtc
        | Insn::Locc
        | Insn::Skpc
        | Insn::Scanc
        | Insn::Spanc
        | Insn::Cmpc
        | Insn::Matc
        | Insn::Addn
        | Insn::Subn
        | Insn::Cmpn
        | Insn::Cvtnl
        | Insn::Cvtpn
        | Insn::Cvtnp
        | Insn::Ashn
        | Insn::Cvtln
        | Insn::Addp
        | Insn::Subp
        | Insn::Cmpp
        | Insn::Cvtpl
        | Insn::Mulp
        | Insn::Divp
        | Insn::Ashp
        | Insn::Cvtlp
        | Insn::Movci
        | Insn::Movrci
        | Insn::Movtci
        | Insn::Locci
        | Insn::Skpci
        | Insn::Scanci
        | Insn::Spanci
        | Insn::Cmpci
        | Insn::Matci
        | Insn::Addni
        | Insn::Subni
        | Insn::Cmpni
        | Insn::Cvtnli
        | Insn::Cvtpni
        | Insn::Cvtnpi
        | Insn::Ashni
        | Insn::Cvtlni
        | Insn::Addpi
        | Insn::Subpi
        | Insn::Cmppi
        | Insn::Cvtpli
        | Insn::Mulpi
        | Insn::Divpi
        | Insn::Ashpi
        | Insn::Cvtlpi => return cis::exec(b, f, pc0),
        // 全 Insn に腕がある —— デコード表を将来拡げたときの予備
        // として残す（網羅なのでコンパイラは到達不能と警告する）。
        #[allow(unreachable_patterns)]
        _ => return Err(InterpExit::Unimplemented(format!("{:?}", f.insn))),
    }
    Ok(())
}
