// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon の実行ステップ。パケット（1–4 語のフェッチ・実行単位）
//! を切り出してスロット命令列として実行し、書き込みを終端で
//! まとめて commit する。
//!
//! 1 ステップは 1 パケット: PC から Parse 桁を追って語を読み
//! （終端語または 4 語で止まる）、`packet::split` でパケットを
//! 確定し、`packet::expand` で実行順の `SlotInsn` 列に展開する。
//! スロット命令は読みがパケット開始時点の値を見るよう、書き込み
//! を `CpuState::pkt_*` に溜めて終端の `sem::commit` で一括反映
//! する（同時発行）。`if ([!]pX[.new])` 条件はフェッチ層が述語
//! 選択桁から `sem::DotIf` に写す（ia64 の qp 抑制に相当）。
//! 制御転送は `Ctrl::Jump` で記録され、パケット内では先に記録
//! された側が勝つ（dual jump でも実行は最後まで続く）。
//! `trap0(#u6)` は即値を code に載せた Trap で OS パーソナリティ
//! へ渡る（ユーザモードの #1 が syscall、他の値・trap1/2 は OS
//! 側の裁量。trap1/2 は語彙未収録で現状は復号不能＝illegal）。
//! split/expand/decode の失敗は illegal パケットとして
//! `handle_trap(TRAP_ILL)` に畳む（ia64 の先例）。
//! Ref: SPEC-HEXAGON-PRM (V79) Section 10.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

use crate::{Insn, decode_model_ex, extract_ops, packet, sem};

/// `addr` の命令語（4 バイト LE）を読む。
fn fetch_word(env: &BareEnv, addr: u32) -> Option<u32> {
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(u64::from(addr)), &mut b, acc)
        .ok()?;
    Some(u32::from_le_bytes(b))
}

/// `TrapOutcome` を `Outcome` 面へ写す。`ok` は Handled 時の
/// 継続処理（pc の前進など）。`pc` は報告用のパケット先頭。
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

/// 解読不能・illegal パケット・未実装の命令を OS パーソナリティに
/// 報せる。実行途中なら残った未確定値を捨てる。`next` は Handled
/// 時の再開位置（次のパケット。不明なら現行位置）。
fn unimpl_insn(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    pc: u32,
    next: u32,
    word: u128,
) -> Result<(), Outcome> {
    sem::pkt_clear(&mut env.backend);
    let t = sys.handle_trap(env, sem::TRAP_ILL as u32);
    trap_result(env, sys, u64::from(pc), t, word, |env| {
        env.pc = u64::from(next)
    })
}

/// スロット命令の `if ([!]pX[.new])` 条件。duplex subinsn は述語
/// 選択桁（dprd/dprd3）から読む。32 ビット側の dot-if 形は HX7
/// で足す。
fn cond_of(si: &packet::SlotInsn, insn: Insn) -> Option<sem::DotIf> {
    let sel = match insn {
        // A-type 条件クリア（dprd: 4/5=p0.new/!p0.new、6/7=p0/!p0、
        // 0 は無条件の `Rd=#-1`）。
        Insn::DxAClr => extract_ops(insn, si.word)[1] as u8,
        // L2 jumpr/dealloc_return（dprd3: 4/5=p0/!p0、
        // 6/7=p0.new/!p0.new、0 は無条件）。
        Insn::DxL2Deallocret | Insn::DxL2Jumpr => extract_ops(insn, si.word)[0] as u8,
        _ => return None,
    };
    let (p, neg, new) = match insn {
        Insn::DxAClr => match sel {
            4 => (0, false, true),
            5 => (0, true, true),
            6 => (0, false, false),
            7 => (0, true, false),
            _ => return None,
        },
        _ => match sel {
            4 => (0, false, false),
            5 => (0, true, false),
            6 => (0, false, true),
            7 => (0, true, true),
            _ => return None,
        },
    };
    Some(sem::DotIf { p, neg, new })
}

/// 1 パケットぶんのフェッチ・解読・意味論。`env.pc` はパケット
/// 先頭アドレスで、終端・分岐成立・退出で止まる。
pub fn step(env: &mut BareEnv, sys: &mut impl TrapHandler, feats: u128) -> Result<(), Outcome> {
    let pc = env.pc as u32;
    // Parse 桁を追ってパケットの語を読む（終端語は必ず見つかる
    // か 4 語で打ち切る。後の split が Unterminated を弾く）。
    let mut words = [0u32; 4];
    let mut n = 0usize;
    loop {
        let Some(w) = fetch_word(env, pc.wrapping_add(4 * n as u32)) else {
            return unimpl_insn(env, sys, pc, pc, 0);
        };
        words[n] = w;
        n += 1;
        let pp = (w >> 14) & 3;
        if pp == crate::parse::END || pp == crate::parse::DUPLEX || n == 4 {
            break;
        }
    }
    let (pkt, used) = match packet::split(&words[..n]) {
        Ok(v) => v,
        Err(_) => return unimpl_insn(env, sys, pc, pc, u128::from(words[0])),
    };
    let slots = match packet::expand(&pkt) {
        Ok(v) => v,
        Err(_) => return unimpl_insn(env, sys, pc, pc, u128::from(words[0])),
    };
    let next = pc.wrapping_add(4 * used as u32);
    // CpuState.pc は常に実行中パケットの先頭（PC 相対・リンク値の
    // 基底）。split のループ終端標識も状態に転記する（LC/SA の
    // 処理自体は HX8）。
    env.backend.set(sem::pc_ref(), pc);
    env.backend.set(sem::endloop_ref(), u32::from(pkt.endloop));
    // パケット内の制御転送は先に記録された側が勝つ。
    let mut target = None;
    for si in &slots {
        let insn = match si.group {
            Some(g) => packet::decode_sub(g, si.word as u16, feats),
            None => decode_model_ex(si.word, si.len, true, feats),
        };
        // subinsn・32 ビット語とも復号できない語は illegal
        // パケットとして扱う（HX3 レビューの接続残件）。
        let Some(insn) = insn else {
            return unimpl_insn(env, sys, pc, next, si.word);
        };
        env.backend.ctrl = Ctrl::Fallthrough;
        let cx = sem::Ctx {
            cond: cond_of(si, insn),
            ext: si.ext,
            pc,
            next,
        };
        match sem::exec(&mut env.backend, insn, si.word, cx) {
            Ok(_) => {
                env.steps += 1;
                if let Ctrl::Jump(t) = env.backend.ctrl
                    && target.is_none()
                {
                    target = Some(t as u32);
                }
            }
            Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => {
                // パケットの生産値を確定してから OS パーソナリティへ。
                // 戻り先は次のパケット（分岐が記録されていればその
                // 着地点）。
                let _ = sem::commit(&mut env.backend);
                let dest = target.unwrap_or(next);
                env.pc = u64::from(dest);
                env.backend.set(sem::pc_ref(), dest);
                let t = sys.handle_trap(env, e.code as u32);
                return trap_result(env, sys, u64::from(pc), t, si.word, |env| {
                    env.pc = u64::from(dest);
                });
            }
            Err(_) => {
                // 未実装命令・その他の例外は illegal パケット扱い。
                return unimpl_insn(env, sys, pc, next, si.word);
            }
        }
    }
    if sem::commit(&mut env.backend).is_err() {
        return Err(Outcome::Unimplemented {
            pc: u64::from(pc),
            word: u128::from(words[0]),
        });
    }
    env.pc = u64::from(target.unwrap_or(next));
    env.backend.set(sem::pc_ref(), target.unwrap_or(next));
    Ok(())
}
