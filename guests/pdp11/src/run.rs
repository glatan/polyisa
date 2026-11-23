// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の実行ステップ。PC（r7）から 16 ビット語で命令を
//! フェッチして解読し、指定子を評価して意味論を実行する。
//!
//! 命令は先頭の命令語と、各指定子が消費する拡張語からなる。
//! 長さは `insn_words` が語内フィールドだけから決める（モード
//! 6/7 のインデックス語と PC 指定子の即値・絶対語）ので、
//! 過剰読みをしない —— 拡張語がページを跨いでも触れた分だけ
//! フェッチが失敗する。
//!
//! 例外の扱いは trap/fault の規則に従う（VAX の fault/trap と
//! 同型）: trap 系（emt/trap/bpt/iot）は復帰先が次の命令、
//! fault 系（バスエラー・奇数アドレス・予約命令・違法な指定子）
//! は命令先頭。まず OS パーソナリティの `handle_trap` がベクタ
//! 番号で受け、受けなければ `sem::deliver` が実機の形（ベクタの新
//! PSW が指すモードのスタックへの PC/PSW 積み・ベクタからの新
//! PC/PSW 読み出し）で配送する —— VAX の SCB/hook と同型の最小形。
//! T ビットの trace は命令フェッチ時の T を完了時に配送する内部
//! flag としてモデルする（RTT と `rti_ttrap`=next モデルの RTI は
//! 次の命令の完了時まで発火を遅らせる）。MMU abort と割込みは
//! PD12 が担う。
//! 配送中の二重 fault は実機では CPU 停止だが、このモデルでは
//! `Unimplemented` に写す。
//!
//! I/D 空間: PD4 は単一のアドレス空間で先行する。命令フェッチは
//! `AccessKind::Fetch`・データとベクタ・スタックは `AccessKind::
//! Data*` で区別するのが空間選択の口で、分離 I/D（I 空間と D
//! 空間の別写像）は PD12 が `mem` 側に拡張して実現する。
//! Ref: SPEC-PDP11-ARCH83（第4・5・8章・付録 B）.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_sem::{Backend, ExceptionKind, GuestException};

use crate::{
    FEAT_FP11, Insn, RTI_TTRAP_IMM, RtiTtrapParam, decode_model_ex, mmu, psw, reg, sem, specifier,
};

/// 例外をトラップ配送に写す。`vec` はベクタ（バイトアドレス）、
/// `stacked` は積む PC で、同時にハンドラが見る再開点になる
/// （Handled ならここから続く —— ハンドラが env.pc を書き換えた
/// 場合はその値）。配送は `sem::deliver` の実機の形。
// Ref: SPEC-PDP11-ARCH83（第8章）.
fn deliver(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    vec: u16,
    stacked: u16,
) -> Result<(), Outcome> {
    env.pc = u64::from(stacked);
    match sys.handle_trap(env, u32::from(vec)) {
        TrapOutcome::Handled => Ok(()),
        TrapOutcome::Exit(code) => Err(Outcome::Exit(u64::from(code))),
        TrapOutcome::Blocked => Err(Outcome::Deadlock),
        TrapOutcome::Unimplemented => {
            env.step(|b| sem::deliver(b, vec, stacked))
                .map_err(|_| Outcome::Unimplemented {
                    pc: u64::from(stacked),
                    word: u128::from(vec),
                })?;
            env.pc = u64::from(sem::r_get(&env.backend, reg::PC as u8));
            Ok(())
        }
    }
}

/// `InterpExit` の例外をベクタと積む PC に写して `deliver` へ渡す。
/// trap 系は復帰先が次の命令 `next`、fault 系は命令先頭 `pc0`。
/// code=0 のメモリ系例外（フェッチ・データアクセスの失敗）は
/// バスエラー（vector 004）に畳む。
fn dispatch_err(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    e: GuestException,
    pc0: u16,
    next: u16,
) -> Result<(), Outcome> {
    let (vec, stacked) = match e.kind {
        ExceptionKind::Trap | ExceptionKind::Break => (e.code as u16, next),
        _ => {
            let vec = if e.code == 0 {
                sem::tv::BUS
            } else {
                e.code as u16
            };
            (vec, pc0)
        }
    };
    deliver(env, sys, vec, stacked)
}

/// 1 命令ぶんのフェッチ・解読・意味論。`env.pc` は命令の先頭
/// アドレスで、命令の終端・制御転送・退出で止まる。
// Ref: SPEC-PDP11-ARCH83（第4・5章）.
pub fn step(env: &mut BareEnv, sys: &mut impl TrapHandler, feats: u128) -> Result<(), Outcome> {
    let pc = env.pc as u16;
    // 命令先頭の MMU 簿記: MMR2 ← 命令の仮想 PC・MMR1 ← 0・
    // MMR0<7>（IC）← 0。凍結中（MMR0<15:13> が立つ）は触らない。
    mmu::step_begin(&mut env.backend, pc);
    // 命令語フェッチ。奇数アドレス・未写像はバスエラー経路に乗る
    // （奇数アドレスの可否は `odd_addr_trap` パラメータ）。
    let w0 = match sem::fetch_w(&mut env.backend, pc) {
        Ok(w) => w,
        Err(InterpExit::Exception(e)) => return dispatch_err(env, sys, e, pc, pc),
        Err(InterpExit::Unimplemented(_)) => {
            return Err(Outcome::Unimplemented {
                pc: u64::from(pc),
                word: 0,
            });
        }
    };
    let Some(insn) = decode_model_ex(u128::from(w0), 16, false, feats) else {
        // fp11 モデルでは 17xxxx の未割当語は FP 違法オペコード
        // （FEC=2）— FID で抑止されていなければ vector 244 へ。
        // trap の規則（積む PC は次の語）で配送し、抑止時は
        // 読み飛ばす（ARCH83 6章の FP 例外）。
        if feats & FEAT_FP11 != 0 && w0 >= 0o170000 {
            match env.step(|b| sem::fp11_illop(b, pc)) {
                Ok(()) => {
                    env.pc = u64::from(pc.wrapping_add(2));
                    return Ok(());
                }
                Err(InterpExit::Exception(e)) => {
                    return dispatch_err(env, sys, e, pc, pc.wrapping_add(2));
                }
                Err(InterpExit::Unimplemented(_)) => {}
            }
        }
        // 予約・違法命令。OS パーソナリティの補完を先に試し、
        // 受けなければ vector 010 へ配送する。
        if sys.handle_unimpl(env, u64::from(pc), u64::from(w0)) == TrapOutcome::Handled {
            return Ok(());
        }
        return deliver(env, sys, sem::tv::ILL, pc);
    };
    // 命令語 + 各指定子の拡張語。語数は語内フィールドだけで決まる。
    let len = specifier::insn_words(insn, w0).expect("decoded insn has a length");
    let mut words = Vec::with_capacity((len / 2) as usize);
    words.push(w0);
    for i in 1..(len / 2) as u16 {
        match sem::fetch_w(&mut env.backend, pc.wrapping_add(2 * i)) {
            Ok(w) => words.push(w),
            Err(InterpExit::Exception(e)) => return dispatch_err(env, sys, e, pc, pc),
            Err(InterpExit::Unimplemented(_)) => {
                return Err(Outcome::Unimplemented {
                    pc: u64::from(pc),
                    word: u128::from(w0),
                });
            }
        }
    }
    let Some(f) = specifier::decode_insn_ex(&words, feats) else {
        // fetch 経路と完全デコードの不一致（内部不整合）。
        return Err(Outcome::Unimplemented {
            pc: u64::from(pc),
            word: u128::from(w0),
        });
    };
    // 実行中の r7 は命令の終端（次の命令）を指す。分岐変位・PC
    // 相対の基準と、実行後の次命令はここから決まる。FP11 の
    // 即値オペランド（F=4・D=8 バイト）は指定子デコードの 1 語を
    // 超えて命令ストリームを消費するので、その分を足す
    // （`sem::fp_imm_extra` —— 内容は意味論側がデータ読み出しで
    // 取る）。
    let next = pc.wrapping_add(f.len as u16 + sem::fp_imm_extra(&env.backend, &f));
    sem::r_set(&mut env.backend, reg::PC as u8, next);
    // フェッチ時の T ビットを標本化する —— これが立つ命令が「traced
    // な命令」で、実行で T を消しても完了時のトラップは発火する
    // （実機の内部 trace flag —— KDJ11-E UG 8.7.7 項目 1・2）。
    let traced = sem::psw_flag(&env.backend, psw::T);
    match env.step(|b| sem::exec(b, &f, pc, feats)) {
        Ok(()) => {
            // 制御転送（jmp・分岐・mov …,pc も）は r7 の書き込みと
            // して表れる。
            env.pc = u64::from(sem::r_get(&env.backend, reg::PC as u8));
            // メモリ管理トラップ（ACF 1/4/5 の trap 条件）と
            // スタックイエローゾーンは命令の完結時に届く —— T ビット
            // トラップより先に配送する（simh の trap_req 順）。
            if let Some(vec) = mmu::take_pendtrap(&mut env.backend) {
                mmu::set_ic(&mut env.backend);
                return deliver(env, sys, vec, env.pc as u16);
            }
            // T ビットトレーストラップ: traced な命令の完了、または
            // RTI が T を立てた直後の発火点（`rti_ttrap` = imm の
            // モデル）。next のモデルと RTT はこの境界では発火せず、
            // 次の命令がフェッチ時に T を標本化してその完了時に
            // トラップする（付録 B 項目 10・11 のモデル差・KDJ11-E
            // UG 8.7.7）。積む PC は次の命令（trap の規則）。
            let rti_imm = f.insn == Insn::Rti
                && env.backend.param::<RtiTtrapParam>() == RTI_TTRAP_IMM
                && sem::psw_flag(&env.backend, psw::T);
            if traced || rti_imm {
                return deliver(env, sys, sem::tv::BPT, env.pc as u16);
            }
            Ok(())
        }
        Err(InterpExit::Exception(e)) => dispatch_err(env, sys, e, pc, next),
        Err(InterpExit::Unimplemented(_)) => {
            // 意味論未実装の命令（halt を含む —— CPU 停止の表現が
            // ない裸モデルでは終端）。OS パーソナリティの補完を試す。
            if sys.handle_unimpl(env, u64::from(pc), u64::from(w0)) == TrapOutcome::Handled {
                return Ok(());
            }
            Err(Outcome::Unimplemented {
                pc: u64::from(pc),
                word: u128::from(w0),
            })
        }
    }
}
