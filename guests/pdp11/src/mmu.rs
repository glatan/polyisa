// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 のメモリ管理（MMU）と I/O ページのレジスタ写像。
//!
//! 16 ビット仮想アドレスは VA<15:13> のページ番号で選んだ
//! PAR/PDR 対で変換する: PAR は再配置基底（64 バイトブロック
//! 単位の物理ページフレーム）、PDR はアクセス制御（ACF）と
//! ページ長（PLF）・方向（ED）を持つ。変換は `xlate`、I/O
//! ページのレジスタ（PAR/PDR・MMR0-3・汎用レジスタ・スタック
//! 制限・PSW）の写像は `io_rd`/`io_wr` が担い、sem の全メモリ
//! アクセスはここの `rd_*`/`wr_*`/`fetch` を通る。
//!
//! I/D 分離は「ページ記述子の選択」として実装する（PD12 で確定
//! した代表形）: engine/mem の `AddressSpace` は物理メモリ 1
//! 枚のまま、アクセス種別ではなく PDP-11 独自の空間選択子
//! `Space` が kernel/supervisor/user ごとの 2×8 の APR セット
//! を選ぶ。命令フェッチは常に I 空間、データは MMR3 のモード別
//! D 空間許可桁が立つときだけ D 空間を使い、立たなければ I に
//! 畳む（`id_split`/`sel22` 系の規則 —— ARCH83 第9章）。
//!
//! abort（参照不可・長さ違反・read-only）は MMR0 に状態を残して
//! vector 250 の fault として返す。trap 条件（ACF 1/4/5）は
//! `mm_trap` モデル（11/45・11/70）だけが持ち、アクセスは通して
//! PDR<A>・MMR0<12> を立て `pendtrap` を予約する —— run の step
//! が命令の完結時に vector 250 の trap として届ける。非 mm_trap
//! モデルでは ACF の予約値は nonresident abort に畳む。
//!
//! 物理アドレス幅は `mmu_pa` パラメータ: off（MMU なし）・
//! p18（18 ビット固定）・p22（22 ビット固定）・sel22（MMR3<4>
//! が 22/18 を選ぶ）。再配置が効いていない間は 16 ビット
//! アドレスのまま、上位 8KB（16xxxx 以降）だけが物理空間先頭
//! の I/O ページに写る（18 ビットなら 76xxxx、22 ビットなら
//! 1776xxxx）。
//!
//! 出典は SPEC-PDP11-ARCH83 第9章・付録 A と SIMH（pdp11_cpu.c
//! の relocR/relocW・GeteaW の calc_is/calc_ds 規則）。
//! Ref: SPEC-PDP11-ARCH83.

use polyisa_engine::interp::{InterpBackend, InterpExit};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, StateRef, W16};

use crate::sem::{self, tv};
use crate::{
    CpuState, DualRegsetParam, GprMappedParam, MMU_PA_OFF, MMU_PA_P18, MMU_PA_P22, MMU_PA_SEL22,
    MmTrapParam, MmuPaParam, PswMappedParam, StackLimitParam, psw, reg,
};

/// アドレス空間の選択子。I は命令空間（フェッチ・間接指定子の
/// 指し先語・prev モード I 参照）、D はデータ空間。D は MMR3 の
/// モード別許可桁が立たなければ I と同一になる（`d_en`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Space {
    /// 命令空間（I 空間）。
    I,
    /// データ空間（D 空間）。
    D,
}

/// MMR0 のビット（MMU 搭載モデルの状態レジスタ。I/O ページ
/// 177572）。<15:13> が立つと <7:1>・MMR1・MMR2 は凍結し、
/// abort ハンドラが <15:12> を消すまで記録が保たれる
/// （ARCH83 第9章 MMR0 の記述）。
pub mod mmr0 {
    /// <0>: 再配置とアクセス検査の有効化。
    pub const ENABLE: u16 = 0o1;
    /// <6:1>: 直近異常のページ情報（モード<6:5>・空間<4>・ページ
    /// <3:1>）。書き込み可能だが凍結中は保持。
    pub const PAGE: u16 = 0o176;
    /// <7>: 命令完了。abort ではなく trap で割ったとき立つ。
    pub const IC: u16 = 0o200;
    /// <8>: メンテナンス/宛先モード（保持のみ。宛先だけを再配置
    /// する規則はモデルしない —— Gap: GAP-0085）。
    pub const MAINT: u16 = 0o400;
    /// <9>: メモリ管理トラップの許可。
    pub const TENB: u16 = 0o1000;
    /// <12>: メモリ管理トラップが起きた。
    pub const TRAP: u16 = 0o10000;
    /// <13>: read-only abort（ACF 1・2 への書き込み）。
    pub const RO: u16 = 0o20000;
    /// <14>: page-length abort（PLF 違反）。
    pub const PL: u16 = 0o40000;
    /// <15>: nonresident abort（ACF 0/3/7・予約 ACF・モード 2 の
    /// 再配置使用）。
    pub const NR: u16 = 0o100000;
    /// <15:13> のいずれか → MMR0<7:1>・MMR1・MMR2 が凍結。
    pub const FREEZE: u16 = 0o160000;
    /// 書き込み可能桁（<15:12>・<9:8>・<7:0>。<11:10> は常に 0）。
    pub const WR: u16 = 0o173777;
    /// 読み出し可能桁（<15:12>・<9>・<7>・<6:1>・<0>。<11:10>・
    /// <8> は 0 を返す —— ARCH83 第9章 MMR0 の記述）。
    pub const RD: u16 = 0o172377;
}

/// MMR3 のビット（22 ビット系と id_split 系の D 空間・CSM・
/// 22 ビット選択。I/O ページ 17772516 —— 1776xxxx からの
/// オフセット 12516）。
pub mod mmr3 {
    /// <0>: ユーザーモード D 空間有効。
    pub const UDS: u16 = 0o1;
    /// <1>: スーパーバイザモード D 空間有効。
    pub const SDS: u16 = 0o2;
    /// <2>: カーネルモード D 空間有効。
    pub const KDS: u16 = 0o4;
    /// <3>: CSM 有効。
    pub const CSM: u16 = 0o10;
    /// <4>: 22 ビット再配置（sel22 モデル。0 なら 18 ビット）。
    pub const M22E: u16 = 0o20;
    /// <5>: UNIBUS 写像有効（保持のみ —— バス写像はモデルしない）。
    pub const BME: u16 = 0o40;
}

/// PDR のビット。APR 書き込み時に <7:6>（A/W）は消える
/// （ARCH83 第9章 PDR の記述）。
pub mod pdr {
    /// <2:0>: アクセス制御フィールド。
    pub const ACF: u16 = 0o7;
    /// <3>: 拡張方向。立つとページは低番地側へ広がる
    /// （PLF 判定の比較方向が反転する）。
    pub const ED: u16 = 0o10;
    /// <6>: 書き込まれた（成功した書き込みで立つ。APR 書き込みで
    /// 消える）。
    pub const W: u16 = 0o100;
    /// <7>: アクセスされた/trap 条件で立つ（APR 書き込みで消える）。
    pub const A: u16 = 0o200;
    /// <14:8>: ページ長フィールドの最小桁位置。
    pub const PLF_V: u16 = 8;
    /// 書き込み可能桁（<15:8>・<3:0>。A/W は書き込みで消える）。
    pub const WR: u16 = 0o177417;
}

/// 現モード（PSW<15:14>）。
#[must_use]
pub fn cur_mode(b: &InterpBackend) -> u16 {
    sem::psw_get(b) >> psw::CUR_MOD & psw::MOD_MASK
}

/// 前モード（PSW<13:12>。MFPI/MTPI・RTI の参照先）。
#[must_use]
pub fn prev_mode(b: &InterpBackend) -> u16 {
    sem::psw_get(b) >> psw::PRV_MOD & psw::MOD_MASK
}

/// モード値の MMR3 D 空間許可桁。モード 2（予約）は 0 に畳む
/// （再配置使用自体が nonresident abort になる）。
fn d_bit(mode: u16) -> u16 {
    match mode {
        psw::KERNEL => mmr3::KDS,
        psw::SUPERVISOR => mmr3::SDS,
        psw::USER => mmr3::UDS,
        _ => 0,
    }
}

/// PAR/PDR の添字（`モード*16 + 空間*8 + ページ`）。CPU 状態面の
/// `par`/`pdr` 配列はこの規則で並ぶ。mode は配列添字のモード
/// （kernel=0・supervisor=1・user=2。PSW 値の user=3 とは違う）。
fn par_ref(i: usize) -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, par) + i * 2)
}

fn pdr_ref(i: usize) -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, pdr) + i * 2)
}

fn mmr_ref(i: usize) -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, mmr) + i * 2)
}

fn stklim_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, stklim))
}

fn pendtrap_ref() -> StateRef<W16> {
    StateRef::<W16>::from_offset(core::mem::offset_of!(CpuState, pendtrap))
}

/// MMR_i の読み出し（テスト・初期設定・内部アクセス用）。
#[must_use]
pub fn mmr_val(b: &InterpBackend, i: u8) -> u16 {
    sem::get16(b, mmr_ref(usize::from(i)))
}

/// MMR_i への直接書き込み（テスト・初期設定用。マスクなし）。
pub fn mmr_put(b: &mut InterpBackend, i: u8, v: u16) {
    sem::set16(b, mmr_ref(usize::from(i)), v);
}

/// PAR/PDR 対への直接書き込み（テスト・パーソナリティの初期設定
/// 用。`i` は `モード*16 + 空間*8 + ページ` の添字）。
pub fn apr_put(b: &mut InterpBackend, i: usize, par: u16, pdr_v: u16) {
    sem::set16(b, par_ref(i), par);
    sem::set16(b, pdr_ref(i), pdr_v);
}

/// APR 添字の合成（モード・空間・ページから）。
#[must_use]
pub fn apr_idx(mode: usize, space: Space, page: u16) -> usize {
    mode * 16 + usize::from(space == Space::D) * 8 + usize::from(page)
}

/// `mmu_pa` パラメータが示す搭載物理アドレス幅（off は 16）。
fn cap_bits(pa: u8) -> u32 {
    match pa {
        MMU_PA_P18 => 18,
        MMU_PA_P22 | MMU_PA_SEL22 => 22,
        _ => 16,
    }
}

/// 現在有効な物理アドレス幅。sel22 は MMR3<4> が 22/18 を選ぶ。
fn eff_bits(b: &mut InterpBackend, pa: u8) -> u32 {
    if pa == MMU_PA_SEL22 && mmr_val(b, 3) & mmr3::M22E == 0 {
        18
    } else {
        cap_bits(pa)
    }
}

/// MMR3 が存在するか（22 ビット系のみ。p18 は MMR3 を持たない —
/// ARCH83 第9章・KDJ11-E UG）。
fn has_mmr3(pa: u8) -> bool {
    pa == MMU_PA_P22 || pa == MMU_PA_SEL22
}

/// I/O ページの物理先頭アドレス。再配置が効いていない間は搭載幅
/// の最終 8KB、効いている間は有効幅の最終 8KB（sel22 で MMR3<4>
/// が消えていれば 18 ビット側の 76xxxx）。
fn io_base(b: &mut InterpBackend) -> u32 {
    let pa = b.param::<MmuPaParam>();
    let bits = if pa == MMU_PA_OFF || mmr_val(b, 0) & mmr0::ENABLE == 0 {
        cap_bits(pa)
    } else {
        eff_bits(b, pa)
    };
    (1u32 << bits) - 0o20000
}

/// abort の記録と送出。MMR0<15:13> が立っていれば <7:1>・MMR1・
/// MMR2 は凍結されているので触らない。返す例外は vector 250 の
/// fault（積む PC は命令先頭）。
fn abort(b: &mut InterpBackend, mode: u16, ds: bool, page: u16, err: u16) -> InterpExit {
    let m0 = mmr_val(b, 0);
    if m0 & mmr0::FREEZE == 0 {
        let info = (mode << 5) | (u16::from(ds) << 4) | (page << 1);
        sem::set16(b, mmr_ref(0), (m0 & !mmr0::PAGE) | info | err);
    }
    sem::fault(tv::MMU)
}

/// 命令完了時のトラップ予約（pendtrap）。MM トラップとイエロー
/// ゾーンが使う。同時成立は後勝ちの決定的選択（同命令に複数の
/// 遅延トラップが来る系では優先度順に step が消化する —— 現行は
/// 単一枠）。
fn pend(b: &mut InterpBackend, vec: u16) {
    sem::set16(b, pendtrap_ref(), vec);
}

/// step が命令の完結時に読む遅延トラップ。取り出すと消える。
#[must_use]
pub fn take_pendtrap(b: &mut InterpBackend) -> Option<u16> {
    let v = sem::get16(b, pendtrap_ref());
    if v != 0 {
        sem::set16(b, pendtrap_ref(), 0);
        Some(v)
    } else {
        None
    }
}

/// 命令がトラップ条件付きで完結したことを MMR0<7> に残す。
pub fn set_ic(b: &mut InterpBackend) {
    let m0 = mmr_val(b, 0);
    sem::set16(b, mmr_ref(0), m0 | mmr0::IC);
}

/// MMR1 の 8 ビット記録を積む（`((δ&0o37)<<3)|(r&7)`。最新が
/// 上位バイト、最初の記録が下位に残る —— simh の calc_MMR1 の
/// 形）。凍結中・MMU なし・r7 への書き戻しは記録しない。
fn mmr1_rec(b: &mut InterpBackend, n: u8, delta: u16) {
    let pa = b.param::<MmuPaParam>();
    if pa == MMU_PA_OFF || mmr_val(b, 0) & mmr0::FREEZE != 0 || n == 7 {
        return;
    }
    let rec = (((delta & 0o37) << 3) | u16::from(n & 7)) & 0xff;
    let m1 = mmr_val(b, 1);
    sem::set16(b, mmr_ref(1), (rec << 8) | (m1 & 0xff));
}

/// 8 ビットの MMR1 記録を直接積む（MFPI/MFPD の SP 変化 0o366・
/// MTPI/MTPD の 0o26 のように、規定済みの値を載せる箇所）。
fn mmr1_rec_raw(b: &mut InterpBackend, rec: u16) {
    let pa = b.param::<MmuPaParam>();
    if pa == MMU_PA_OFF || mmr_val(b, 0) & mmr0::FREEZE != 0 {
        return;
    }
    let m1 = mmr_val(b, 1);
    sem::set16(b, mmr_ref(1), ((rec & 0xff) << 8) | (m1 & 0xff));
}

/// 命令の先頭で行う MMU 簿記。MMR2 は命令の仮想 PC、MMR1 は 0、
/// MMR0<7>（IC）は 0 に戻す。<15:13> が立っていれば凍結なので
/// 触らない。`pendtrap` は前命令の残りを捨てる（配送済みか
/// abort 済み）。
pub fn step_begin(b: &mut InterpBackend, pc0: u16) {
    let pa = b.param::<MmuPaParam>();
    if pa != MMU_PA_OFF && mmr_val(b, 0) & mmr0::FREEZE == 0 {
        sem::set16(b, mmr_ref(1), 0);
        sem::set16(b, mmr_ref(2), pc0);
        let m0 = mmr_val(b, 0);
        sem::set16(b, mmr_ref(0), m0 & !mmr0::IC);
    }
    sem::set16(b, pendtrap_ref(), 0);
}

/// オート増減の書き戻しを登録する（eval_op_w から呼ぶ）。
/// SP の減少はイエローゾーン検査の対象。
pub fn reg_wb(b: &mut InterpBackend, n: u8, new_v: u16, old_v: u16) {
    sem::r_set(b, n, new_v);
    mmr1_rec(b, n, new_v.wrapping_sub(old_v));
    if n == reg::SP as u8 {
        stk_check(b);
    }
}

/// カーネルスタックがイエローゾーン（stklim+0o400 未満）に
/// 落ちているか（stack_limit モデルかつカーネルモードでのみ
/// 判定）。
pub fn stk_below(b: &mut InterpBackend) -> bool {
    if !b.param::<StackLimitParam>() || cur_mode(b) != psw::KERNEL {
        return false;
    }
    let lim = sem::get16(b, stklim_ref());
    sem::r_get(b, reg::SP as u8) < lim.wrapping_add(0o400)
}

/// オート増減・プッシュ後のイエローゾーン検査（スタックが限界を
/// 割ったら vector 004 を命令完了時に予約する。赤ゾーン ——
/// 配送のスタック自体が死ぬ状況 —— はモデルしない
/// （Gap: GAP-0085）。
fn stk_check(b: &mut InterpBackend) {
    if stk_below(b) {
        pend(b, tv::BUS);
    }
}

/// レジスタセットの交換（PSW<11> RS が変わったとき。`psw_apply`
/// と `deliver` が使う —— 呼び出し側が `dual_regset`
/// パラメータを見る）。
pub fn rs_swap(b: &mut InterpBackend) {
    for i in 0..6u8 {
        let t = sem::r_get(b, i);
        sem::r_set(b, i, sem::get16(b, sem::ralt_ref(i)));
        sem::set16(b, sem::ralt_ref(i), t);
    }
}

/// `mmr1_rec_raw` / `pend` / `stk_check` / トラップ配送の MMU
/// 簿記を命令意味論（sem・cis）から触るための公開形。
pub mod ops {
    use super::{InterpBackend, mmr_ref, mmr1_rec_raw, pend, stk_check};
    use crate::sem;
    use crate::{MMU_PA_OFF, MmuPaParam};
    use polyisa_sem::Backend as _;

    /// 既定値の MMR1 記録を積む（MFPI/MFPD=0o366・MTPI/MTPD=0o26）。
    pub fn mmr1_raw(b: &mut InterpBackend, rec: u16) {
        mmr1_rec_raw(b, rec);
    }

    /// 命令完了時のトラップを予約する。
    pub fn pend_trap(b: &mut InterpBackend, vec: u16) {
        pend(b, vec);
    }

    /// カーネルスタックのイエローゾーン検査。
    pub fn stk_chk(b: &mut InterpBackend) {
        stk_check(b);
    }

    /// トラップ配送の MMU 簿記。命令トラップ群（ILL/BPT/IOT/EMT/
    /// TRAP = 010/014/020/030/034）以外は MMR2 ← ベクタ・MMR1 ← 0
    /// （simh の trap_load_mmr2 規則 —— 配送側の書き込みは
    /// MMR0<15:13> の凍結に掛からない）。
    pub fn trap_load(b: &mut InterpBackend, vec: u16) {
        use crate::sem::tv;
        if b.param::<MmuPaParam>() == MMU_PA_OFF
            || matches!(vec, tv::ILL | tv::BPT | tv::IOT | tv::EMT | tv::TRAP)
        {
            return;
        }
        sem::set16(b, mmr_ref(1), 0);
        sem::set16(b, mmr_ref(2), vec);
    }
}

// ---- 仮想→物理変換 ----

/// VA を選ばれたモード・空間の APR で物理アドレスに変換する。
/// abort なら MMR0 を記録して vector 250 fault を返す。
/// `mode` は PSW 値（kernel=0・supervisor=1・user=3。予約の 2 は
/// nonresident abort）。`sp` == D で MMR3 の該当桁が立つときだけ
/// D 空間の APR を選ぶ。
// Gap: GAP-0085（I/D 分離の代表形・保守側の近似 —— 宛先モード・
// 赤ゾーン・MMR1 巻き戻しはモデルしない）。
fn xlate(
    b: &mut InterpBackend,
    va: u16,
    mode: u16,
    sp: Space,
    wr: bool,
) -> Result<u32, InterpExit> {
    let pa_kind = b.param::<MmuPaParam>();
    if pa_kind == MMU_PA_OFF || mmr_val(b, 0) & mmr0::ENABLE == 0 {
        // 再配置なし —— 16 ビットアドレスのまま。上位 8KB は搭載幅
        // 先頭の I/O ページに写る。
        return Ok(if va < 0o160000 {
            u32::from(va)
        } else {
            io_base(b) + u32::from(va & 0o17777)
        });
    }
    let page = va >> 13;
    let bn = (va >> 6) & 0o177;
    let ds = sp == Space::D && mmr_val(b, 3) & d_bit(mode) != 0;
    // モード値 2（予約）で再配置を使うと nonresident abort
    // （ARCH83 第9章「モード 2 は予約」の決定的表現）。
    if mode == 2 {
        return Err(abort(b, mode, ds, page, mmr0::NR));
    }
    let arr_mode = usize::from(if mode == psw::USER { 2 } else { mode });
    let idx = arr_mode * 16 + usize::from(ds) * 8 + usize::from(page);
    let par = sem::get16(b, par_ref(idx));
    let pdr_v = sem::get16(b, pdr_ref(idx));
    let acf = pdr_v & pdr::ACF;
    let mmtr = b.param::<MmTrapParam>();
    // ACF の参照可否。trap 条件は A・MMR0<12> を立てて予約してから
    // 通す。abort は後で PL 検査とまとめて記録する。
    let mut err = match (wr, acf, mmtr) {
        (false, 1 | 4, true) | (true, 4 | 5, true) => {
            // メモリ管理トラップ条件 —— アクセスは通し、A と
            // MMR0<12> を立てる。TENB が立ち未発火なら trap を予約。
            sem::set16(b, pdr_ref(idx), pdr_v | pdr::A);
            let m0 = mmr_val(b, 0);
            sem::set16(b, mmr_ref(0), m0 | mmr0::TRAP);
            if m0 & mmr0::TENB != 0 && m0 & mmr0::TRAP == 0 {
                pend(b, tv::MMU);
            }
            0
        }
        // 読み出し可（2=RO・5=R/W-trap write・6=R/W）・書き込み可
        // （6=R/W）。
        (false, 2 | 5 | 6, _) | (true, 6, _) => 0,
        // 書き込み不可の read-only（全モデル）。
        (true, 1 | 2, _) => mmr0::RO,
        // 残りは nonresident（0/3/7 全モデル・1/4/5 の予約解釈は
        // 非 mm_trap モデル）。
        _ => mmr0::NR,
    };
    // PLF 検査（PDR<14:8> の長さ・<3> の方向）。
    let plf = (pdr_v >> pdr::PLF_V) & 0x7f;
    if (pdr_v & pdr::ED == 0 && bn > plf) || (pdr_v & pdr::ED != 0 && bn < 0o177 - plf) {
        err |= mmr0::PL;
    }
    if err != 0 {
        return Err(abort(b, mode, ds, page, err));
    }
    if wr {
        // 成功した書き込みは PDR<6>（W）を立てる。trap 条件で
        // 立てた A を消さないよう現値に足す。
        let cur = sem::get16(b, pdr_ref(idx));
        sem::set16(b, pdr_ref(idx), cur | pdr::W);
    }
    // PA = (PAR + ブロック番号) << 6 | ブロック内変位、有効幅に畳む。
    let mask = (1u32 << eff_bits(b, pa_kind)) - 1;
    Ok((u32::from(par.wrapping_add(bn)) << 6 | u32::from(va & 0o77)) & mask)
}

// ---- I/O ページのレジスタ写像 ----

/// I/O ページ内オフセット → APR 添字と PDR 側かどうか。
/// supervisor=0o12200-0o12277・kernel=0o12300-0o12377・
/// user=0o17600-0o17677。各区間は PDR が先に 8 対並び、次が
/// I 空間 PAR、0o40 以降が D 空間 PAR —— ではなく、実機の配置は
/// PDR I8・PDR D8・PAR I8・PAR D8 の連続 32 語（simh の
/// IOPAGE 配置に従う）。
fn apr_io(off: u16) -> Option<(usize, bool)> {
    let (arr_mode, rel) = match off {
        0o12200..=0o12277 => (1, off - 0o12200),
        0o12300..=0o12377 => (0, off - 0o12300),
        0o17600..=0o17677 => (2, off - 0o17600),
        _ => return None,
    };
    // rel: <5> が PAR 側・<4> が D 空間・<3:1> がページ。
    let is_par = rel & 0o40 != 0;
    let ds = rel & 0o20 != 0;
    let page = usize::from(rel >> 1 & 7);
    Some((arr_mode * 16 + usize::from(ds) * 8 + page, !is_par))
}

/// 汎用レジスタの I/O ページ写像（177700-177717）。
/// 0-5 は現セットの r0-r5、6 は ksp、7 は r7、8-13 はもう一方の
/// セットの r0-r5、14 は ssp、15 は usp（simh の GeteaW
/// レジスタアクセス規則 —— RS が立つと 0-5/8-13 が入れ替わる）。
fn gpr_val(b: &InterpBackend, i: u16) -> u16 {
    let rs = sem::psw_get(b) >> psw::RS & 1 != 0;
    match i {
        0..=5 => {
            if rs {
                sem::get16(b, sem::ralt_ref(i as u8))
            } else {
                sem::r_get(b, i as u8)
            }
        }
        6 => sem::get16(b, sem::mode_sp_ref(psw::KERNEL)),
        7 => sem::r_get(b, reg::PC as u8),
        8..=13 => {
            if rs {
                sem::r_get(b, (i - 8) as u8)
            } else {
                sem::get16(b, sem::ralt_ref((i - 8) as u8))
            }
        }
        14 => sem::get16(b, sem::mode_sp_ref(psw::SUPERVISOR)),
        _ => sem::get16(b, sem::mode_sp_ref(psw::USER)),
    }
}

fn gpr_put(b: &mut InterpBackend, i: u16, v: u16) {
    let rs = sem::psw_get(b) >> psw::RS & 1 != 0;
    match i {
        0..=5 => {
            if rs {
                sem::set16(b, sem::ralt_ref(i as u8), v);
            } else {
                sem::r_set(b, i as u8, v);
            }
        }
        6 => sem::set16(b, sem::mode_sp_ref(psw::KERNEL), v),
        7 => sem::r_set(b, reg::PC as u8, v),
        8..=13 => {
            if rs {
                sem::r_set(b, (i - 8) as u8, v);
            } else {
                sem::set16(b, sem::ralt_ref((i - 8) as u8), v);
            }
        }
        14 => sem::set16(b, sem::mode_sp_ref(psw::SUPERVISOR), v),
        _ => sem::set16(b, sem::mode_sp_ref(psw::USER), v),
    }
}

/// PSW への代入（I/O ページからの書き込みと RTI・トラップ配送が
/// 共有する形）。モードが変われば現 SP を旧モードの退避先へ
/// 押し込んで新モードの退避先を読み、RS が変われば r0-r5 と
/// 第 2 セットを交換する（`dual_regset` パラメータのモデルのみ —
/// 無しモデルの PSW<11> は効かない）。
pub fn psw_apply(b: &mut InterpBackend, nv: u16) {
    let old = sem::psw_get(b);
    sem::psw_put(b, nv);
    let om = old >> psw::CUR_MOD & psw::MOD_MASK;
    let nm = nv >> psw::CUR_MOD & psw::MOD_MASK;
    if om != nm {
        sem::set16(b, sem::mode_sp_ref(om), sem::r_get(b, reg::SP as u8));
        sem::r_set(b, reg::SP as u8, sem::get16(b, sem::mode_sp_ref(nm)));
    }
    if b.param::<DualRegsetParam>() && (old ^ nv) >> psw::RS & 1 != 0 {
        for i in 0..6u8 {
            let t = sem::r_get(b, i);
            sem::r_set(b, i, sem::get16(b, sem::ralt_ref(i)));
            sem::set16(b, sem::ralt_ref(i), t);
        }
    }
}

/// I/O ページのワード読み出し。`off` は 0o17777 までの偶数。
/// `Some` なら写像がある（レジスタ）、`None` なら未写像 ——
/// 呼び出し側は物理メモリ（デバイス写像）を読みに行く。
fn io_rd(b: &mut InterpBackend, off: u16) -> Option<u16> {
    let pa_kind = b.param::<MmuPaParam>();
    if let Some((idx, is_pdr)) = apr_io(off) {
        if pa_kind == MMU_PA_OFF {
            return None;
        }
        return Some(if is_pdr {
            sem::get16(b, pdr_ref(idx))
        } else {
            sem::get16(b, par_ref(idx))
        });
    }
    match off {
        0o12516 if has_mmr3(pa_kind) => Some(mmr_val(b, 3)),
        0o17572 if pa_kind != MMU_PA_OFF => Some(mmr_val(b, 0) & mmr0::RD),
        0o17574 if pa_kind != MMU_PA_OFF => Some(mmr_val(b, 1)),
        0o17576 if pa_kind != MMU_PA_OFF => Some(mmr_val(b, 2)),
        0o17700..=0o17717 if b.param::<GprMappedParam>() => Some(gpr_val(b, off & 0o17)),
        0o17774 if b.param::<StackLimitParam>() => Some(sem::get16(b, stklim_ref())),
        0o17776 if b.param::<PswMappedParam>() => Some(sem::psw_get(b)),
        _ => None,
    }
}

/// I/O ページのワード書き込み。`off` は偶数。返値は写像が
/// あったか（`false` なら呼び出し側が物理メモリへ書く）。
fn io_wr(b: &mut InterpBackend, off: u16, v: u16) -> bool {
    let pa_kind = b.param::<MmuPaParam>();
    if let Some((idx, is_pdr)) = apr_io(off) {
        if pa_kind == MMU_PA_OFF {
            return false;
        }
        if is_pdr {
            // PDR は A/W（<7:6>）が書き込みで消える。PLF・ED・ACF は
            // 書き込み値を取る。
            sem::set16(b, pdr_ref(idx), v & pdr::WR);
        } else {
            sem::set16(b, par_ref(idx), v);
        }
        return true;
    }
    match off {
        0o12516 if has_mmr3(pa_kind) => {
            // MMR3 は <5:0> が書ける（UDS/SDS/KDS/CSM/M22E/BME）。
            sem::set16(b, mmr_ref(3), v & 0o77);
        }
        0o17572 if pa_kind != MMU_PA_OFF => {
            sem::set16(b, mmr_ref(0), v & mmr0::WR);
        }
        // MMR1・MMR2 は読み出し専用 —— 書き込みは無視される
        // （実機でも内容は CPU が管理する）。
        0o17574 | 0o17576 if pa_kind != MMU_PA_OFF => {}
        0o17700..=0o17717 if b.param::<GprMappedParam>() => {
            gpr_put(b, off & 0o17, v);
        }
        0o17774 if b.param::<StackLimitParam>() => {
            sem::set16(b, stklim_ref(), v & 0o177400);
        }
        0o17776 if b.param::<PswMappedParam>() => {
            let cur = sem::psw_get(b);
            let mode = cur >> psw::CUR_MOD & psw::MOD_MASK;
            let nv = if mode == psw::KERNEL {
                v
            } else {
                // 非カーネルの PSW 書き込み保護（RTI と同じ規則 —
                // 優先度は現値、モード・RS は下げられない）。
                (v & !(psw::PRI_MASK | 0o17_0000 | 1 << psw::RS))
                    | (cur & psw::PRI_MASK)
                    | ((cur | v) & (0o17_0000 | 1 << psw::RS))
            };
            psw_apply(b, nv);
        }
        _ => return false,
    }
    true
}

// ---- 物理アドレス層 ----

/// 物理アドレスのワード読み出し。I/O ページならレジスタ写像を
/// 優先し、未写像なら物理メモリへ進む（I/O ページ上のデバイス
/// 写像は `mem` のページが担う）。物理未写像はバスエラー fault
/// （vector 004 —— バスタイムアウト）。
fn pa_rd_w(b: &mut InterpBackend, pa: u32, acc: Access) -> Result<u16, InterpExit> {
    let io = io_base(b);
    if pa >= io {
        let off = (pa - io) as u16;
        if let Some(v) = io_rd(b, off & !1) {
            return Ok(if off & 1 == 0 { v } else { 0 });
        }
    }
    b.mem
        .read_value(VirtAddr(u64::from(pa)), 2, acc)
        .map(|v| v as u16)
        .map_err(|_| sem::fault(tv::BUS))
}

fn pa_rd_b(b: &mut InterpBackend, pa: u32, acc: Access) -> Result<u8, InterpExit> {
    let io = io_base(b);
    if pa >= io {
        let off = (pa - io) as u16;
        // 汎用レジスタはバイトアクセスが素のレジスタ境界を割る
        // （177700+n の n がそのままレジスタ番号）。
        if b.param::<GprMappedParam>() && (0o17700..=0o17717).contains(&off) {
            return Ok((gpr_val(b, off & 0o17) >> (8 * (off & 1))) as u8);
        }
        if let Some(v) = io_rd(b, off & !1) {
            return Ok((v >> (8 * (off & 1))) as u8);
        }
    }
    b.mem
        .read_value(VirtAddr(u64::from(pa)), 1, acc)
        .map(|v| v as u8)
        .map_err(|_| sem::fault(tv::BUS))
}

fn pa_wr_w(b: &mut InterpBackend, pa: u32, v: u16) -> Result<(), InterpExit> {
    let io = io_base(b);
    if pa >= io {
        let off = (pa - io) as u16;
        if off & 1 == 0 && io_wr(b, off, v) {
            return Ok(());
        }
    }
    b.mem
        .write_value(VirtAddr(u64::from(pa)), u64::from(v), 2, DWR)
        .map_err(|_| sem::fault(tv::BUS))
}

fn pa_wr_b(b: &mut InterpBackend, pa: u32, v: u8) -> Result<(), InterpExit> {
    let io = io_base(b);
    if pa >= io {
        let off = (pa - io) as u16;
        if b.param::<GprMappedParam>() && (0o17700..=0o17717).contains(&off) {
            let w = gpr_val(b, off & 0o17);
            let nv = (w & !(0xff << (8 * (off & 1)))) | u16::from(v) << (8 * (off & 1));
            gpr_put(b, off & 0o17, nv);
            return Ok(());
        }
        if let Some(w) = io_rd(b, off & !1) {
            let nv = (w & !(0xff << (8 * (off & 1)))) | u16::from(v) << (8 * (off & 1));
            if io_wr(b, off & !1, nv) {
                return Ok(());
            }
        }
    }
    b.mem
        .write_value(VirtAddr(u64::from(pa)), u64::from(v), 1, DWR)
        .map_err(|_| sem::fault(tv::BUS))
}

// ---- 仮想アドレス層（sem が使う）----

/// データ読み出し（モード・空間は呼び出し側が選ぶ —— 通常は
/// 現モード・D で、trap 配送のベクタ読みは kernel・D、prev 参照は
/// 前モード）。
pub fn rd_w(b: &mut InterpBackend, a: u16, mode: u16, sp: Space) -> Result<u16, InterpExit> {
    let pa = xlate(b, a, mode, sp, false)?;
    pa_rd_w(b, pa, DRD)
}

pub fn rd_b(b: &mut InterpBackend, a: u16, mode: u16, sp: Space) -> Result<u8, InterpExit> {
    let pa = xlate(b, a, mode, sp, false)?;
    pa_rd_b(b, pa, DRD)
}

/// データ書き込み（PDR の W 桁・read-only 検査込み）。
pub fn wr_w(b: &mut InterpBackend, a: u16, mode: u16, sp: Space, v: u16) -> Result<(), InterpExit> {
    let pa = xlate(b, a, mode, sp, true)?;
    pa_wr_w(b, pa, v)
}

pub fn wr_b(b: &mut InterpBackend, a: u16, mode: u16, sp: Space, v: u8) -> Result<(), InterpExit> {
    let pa = xlate(b, a, mode, sp, true)?;
    pa_wr_b(b, pa, v)
}

/// 命令語フェッチ（I 空間・Fetch 権限で物理メモリに当たる）。
pub fn fetch(b: &mut InterpBackend, a: u16, mode: u16) -> Result<u16, InterpExit> {
    let pa = xlate(b, a, mode, Space::I, false)?;
    pa_rd_w(b, pa, FETCH)
}

/// データアクセスの属性（整列の規則は PDP-11 自身の奇数アドレス
/// 規則が担うので mem 層には整列を要求しない）。
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
const FETCH: Access = Access {
    endian: Endian::Le,
    align: Align::Unaligned,
    kind: AccessKind::Fetch,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// PAR/PDR の I/O ページ配置（PDR I8・PDR D8・PAR I8・PAR D8 の
    /// 連続 32 語 ×3 モード）。
    #[test]
    fn apr_io_layout() {
        // kernel I PAR0 = 172340 → off 12340 → idx 0*16+0*8+0 = 0・PAR。
        assert_eq!(apr_io(0o12340), Some((0, false)));
        // kernel D PDR3 = 172326 → idx 0*16+8+3 = 11・PDR。
        assert_eq!(apr_io(0o12326), Some((11, true)));
        // supervisor I PAR2 = 172244 → idx 1*16+0+2 = 18。
        assert_eq!(apr_io(0o12244), Some((18, false)));
        // user D PAR7 = 177676 → idx 2*16+8+7 = 47。
        assert_eq!(apr_io(0o17676), Some((47, false)));
        // user I PDR0 = 177600 → idx 2*16 = 32・PDR。
        assert_eq!(apr_io(0o17600), Some((32, true)));
    }
}
