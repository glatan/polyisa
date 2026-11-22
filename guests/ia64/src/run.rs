// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64 の実行ステップ。RIP（バンドルアドレス|スロット番号）から
//! 命令群の終わりまでを進める。
//!
//! 1 ステップは命令群 1 個: バンドルアドレス（16 バイト整列）から
//! 16 バイトを読み、テンプレートでスロット要求と stop を得て、
//! stop・バンドル末端・分岐成立（`Ctrl::Jump`）で群を切る。MLX の
//! L+X 命令はスロット 1-2 を一体で進め、IP のスロット番号は 1
//! （SRC-LINUX-66 arch/ia64/kernel/brl_emu.c が `ri == 1` で
//! L+X を判別する規約）。スロット 2 への進入は長命令の途中なので
//! 不正とする。`break` は即値を code に載せた Trap で OS
//! パーソナリティへ渡り、戻り先は次の命令位置（kernel/gate.S の
//! `__kernel_syscall_via_break` が同一群内の後続スロットへ
//! rfi で戻る規約）。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

use crate::{bundle, sem};

/// `baddr` のバンドル語（16 バイト）を読む。
fn fetch_bundle(env: &BareEnv, baddr: u64) -> Option<u128> {
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b = [0u8; 16];
    env.backend.mem.read(VirtAddr(baddr), &mut b, acc).ok()?;
    Some(u128::from_le_bytes(b))
}

/// `TrapOutcome` を `Outcome` 面へ写す。`ok` は Handled 時の
/// 継続処理（ip の前進など）。`pc` は報告用の命令ポインタ。
fn trap_result(
    env: &mut BareEnv,
    _sys: &mut impl TrapHandler,
    pc: u64,
    t: TrapOutcome,
    word: u128,
    ok: impl FnOnce(&mut BareEnv),
) -> Result<(), Outcome> {
    match t {
        TrapOutcome::Handled => {
            ok(env);
            Ok(())
        }
        TrapOutcome::Exit(code) => Err(Outcome::Exit(u64::from(code))),
        TrapOutcome::Blocked => Err(Outcome::Deadlock),
        TrapOutcome::Unimplemented => Err(Outcome::Unimplemented { pc, word }),
    }
}

/// 解読不能・未実装の命令を OS パーソナリティに報せる。
/// `next` は Handled 時の再開位置（次の命令。不明なら現行位置）。
fn unimpl_insn(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    pc: u64,
    next: u64,
    word: u128,
) -> Result<(), Outcome> {
    let t = sys.handle_trap(env, sem::TRAP_ILL as u32);
    trap_result(env, sys, pc, t, word, |env| env.pc = next)
}

/// 開始スロット `s` の命令の（要求ユニット, 終了スロット, スロット語）。
/// L は L+X 命令の開始で、X ユニットの 82 ビット語が終了スロット 2
/// までを占める。スロット 2 の X に直接当たる進入は長命令の途中
/// なので `None`（不正）。
fn slot_insn(
    desc: &bundle::TemplateDesc,
    bw: u128,
    s: usize,
) -> Option<(bundle::Unit, usize, u128)> {
    match desc.slots[s] {
        bundle::Unit::L => Some((bundle::Unit::X, 2, bundle::bundle_x_word(bw))),
        bundle::Unit::X => None,
        u => Some((u, s, u128::from(bundle::bundle_slot(bw, s)))),
    }
}

/// 1 命令群ぶんのフェッチ・解読・意味論。`env.pc` は ip
/// （バンドルアドレス|スロット番号）で、群の終わり・分岐成立・
/// 退出で止まる。
pub fn step(env: &mut BareEnv, sys: &mut impl TrapHandler, feats: u128) -> Result<(), Outcome> {
    let ip = env.pc;
    let baddr = ip & !0xf;
    let mut s = (ip & 0xf) as usize;
    // スロット番号は 0-2。それ以外の進入は不正。
    if s > 2 {
        return unimpl_insn(env, sys, ip, ip, 0);
    }
    let Some(bw) = fetch_bundle(env, baddr) else {
        return unimpl_insn(env, sys, ip, ip, 0);
    };
    let Some(desc) = bundle::template_desc(bw) else {
        return unimpl_insn(env, sys, ip, ip, bw & u128::from(u64::MAX));
    };
    // 各スロット後の命令群境界（slot2 後はバンドルのストップビット）。
    let stops = [
        desc.boundary == 1,
        desc.boundary == 2,
        bundle::bundle_stop(bw),
    ];
    loop {
        let Some((unit, end, word)) = slot_insn(desc, bw, s) else {
            return unimpl_insn(env, sys, ip, ip, 0);
        };
        let cur = baddr | s as u64;
        let Some(insn) = bundle::decode_slot(unit, word, feats) else {
            return unimpl_insn(env, sys, cur, cur, word);
        };
        // 次の命令位置。群境界かどうかにかかわらずスロットを 1 進める。
        let next = if end == 2 {
            baddr.wrapping_add(16)
        } else {
            baddr | (end as u64 + 1)
        };
        env.backend.set(sem::ip_ref(), cur);
        match env.step(|b| sem::exec(b, insn, word, cur)) {
            Ok(_) => {
                // 分岐成立なら群の後続スロットは実行しない。
                if let Ctrl::Jump(t) = env.backend.ctrl {
                    env.pc = t;
                    env.backend.set(sem::ip_ref(), t);
                    return Ok(());
                }
                if stops[end] || end == 2 {
                    env.pc = next;
                    env.backend.set(sem::ip_ref(), next);
                    return Ok(());
                }
                s = end + 1;
            }
            Err(InterpExit::Exception(e)) => {
                if e.kind == ExceptionKind::Trap {
                    // 戻り先は次の命令位置（break の規約）。
                    env.backend.set(sem::ip_ref(), next);
                    let t = sys.handle_trap(env, e.code as u32);
                    return trap_result(env, sys, cur, t, word, |env| env.pc = next);
                }
                return Err(Outcome::Unimplemented { pc: cur, word });
            }
            Err(InterpExit::Unimplemented(_)) => {
                return unimpl_insn(env, sys, cur, next, word);
            }
        }
    }
}
