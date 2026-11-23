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
use polyisa_mem::{Access, AccessKind, Align, Endian, PAGE_SIZE, PageNo, Perms, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

use crate::{Insn, decode_model_ex, extract_ops, packet, sem};

/// ページフォルト駆動の lazymap 窓（Linux の GROWSDOWN・ヒープ
/// 事前張りの近似 — GAP-0073）。`[lo, hi)` 内の未写像アクセスは
/// ページを遅延割付してパケットをやり直す。
#[derive(Clone, Copy)]
pub struct Growth {
    /// 遅延割付の下限（elf 画像末端のページ）。
    pub lo: u64,
    /// 遅延割付の上限（スタック頂）。
    pub hi: u64,
}

/// `addr` のページを窓の中で遅延割付する。割付たら true。
fn grow(env: &mut BareEnv, g: Option<Growth>, addr: u64, exec: bool) -> bool {
    let Some(g) = g else { return false };
    if addr < g.lo || addr >= g.hi {
        return false;
    }
    let page = addr & !PAGE_SIZE.wrapping_sub(1);
    if env.backend.mem.is_mapped(PageNo(page / PAGE_SIZE)) {
        return false;
    }
    let p = if exec {
        Perms(Perms::RW.0 | Perms::X.0)
    } else {
        Perms::RW
    };
    env.backend.mem.map(VirtAddr(page), 1, p).is_ok()
}

/// 直近パケット PC のリングバッファ（POLYISA_HEX_TRACE 時のみ
/// illegal の直前経路を残す）。
use std::cell::RefCell;
thread_local! {
    static RING: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
}

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
        TrapOutcome::Exit(code) => {
            // デバッグ: POLYISA_HEX_TRACE 時は exit 直前の
            // パケット PC 列も残す（黙った早期終了の追跡用）。
            if std::env::var_os("POLYISA_HEX_TRACE").is_some() {
                RING.with(|r| {
                    let r = r.borrow();
                    eprintln!("exit({code}): last {} pcs:", r.len());
                    for p in r.iter().rev().take(48) {
                        eprintln!("  {p:#x}");
                    }
                });
            }
            Err(Outcome::Exit(u64::from(code)))
        }
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
/// 選択桁（dprd/dprd3）から読み、HX6 の述語付きメモリ形は
/// (p, q) オペランド末尾 2 つから読む（q = .new*2+否定）。
fn cond_of(si: &packet::SlotInsn, insn: Insn) -> Option<sem::DotIf> {
    match insn {
        // HX6 述語付き load/store。extract_ops の末尾 2 オペランド
        // は常に (述語番号 p, qualifier q)。q = {bit1=.new,
        // bit0=否定}（実符号は参照アセンブラの V73 プロファイルと照合済み）。
        Insn::LdPq
        | Insn::LdPqPi
        | Insn::LdPqRo
        | Insn::LdPqAbs
        | Insn::StPq
        | Insn::StPqPi
        | Insn::StPqRo
        | Insn::StPqAbs
        | Insn::StIp
        | Insn::StPqNt
        | Insn::StPqPiNt
        | Insn::StPqRoNt
        | Insn::StPqAbsNt
        // HX11: `if ([!]Pu[.new])` 条件付き ALU。末尾 2
        // オペランドは同じく (述語, qualifier)。
        | Insn::CandRr
        | Insn::CorRr
        | Insn::CxorRr
        | Insn::CaddRr
        | Insn::CsubRr
        | Insn::CcombRr
        | Insn::CaddRi
        | Insn::CmovI => {
            let ops = extract_ops(insn, si.word);
            let n = ops.len();
            let q = ops[n - 1];
            return Some(sem::DotIf {
                p: ops[n - 2] as u8,
                neg: q & 1 != 0,
                new: q & 2 != 0,
            });
        }
        _ => {}
    }
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
    step_inner(env, sys, feats, None)
}

/// `step` の lazymap 窓付き。窓 `[g.lo, g.hi)` 内の未写像への
/// データ・フェッチアクセスはページを遅延割付してパケットを
/// やり直す（Linux の GROWSDOWN・ヒープ近似 — GAP-0073）。
pub fn step_growth(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    feats: u128,
    g: Growth,
) -> Result<(), Outcome> {
    step_inner(env, sys, feats, Some(g))
}

fn step_inner(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    feats: u128,
    growth: Option<Growth>,
) -> Result<(), Outcome> {
    let pc = env.pc as u32;
    let trace = std::env::var_os("POLYISA_HEX_TRACE").is_some();
    if trace {
        RING.with(|r| {
            let mut r = r.borrow_mut();
            if r.len() >= 128 {
                r.remove(0);
            }
            r.push(pc);
        });
        if let Some(watches) = std::env::var_os("POLYISA_HEX_WATCH").map(|s| {
            s.to_str()
                .unwrap_or("")
                .split(',')
                .filter_map(|w| u32::from_str_radix(w, 16).ok())
                .collect::<Vec<u32>>()
        }) && watches.contains(&pc)
        {
            eprint!("watch pc={pc:#x}:");
            for i in 0..8 {
                eprint!(" r{i}={:#x}", sem::r_get(&env.backend, i));
            }
            eprintln!();
        }
    }
    // Parse 桁を追ってパケットの語を読む（終端語は必ず見つかる
    // か 4 語で打ち切る。後の split が Unterminated を弾く）。
    let mut words = [0u32; 4];
    let mut n = 0usize;
    loop {
        let a = pc.wrapping_add(4 * n as u32);
        let w = match fetch_word(env, a) {
            Some(w) => w,
            // フェッチも窓の中では遅延割付して一度だけ読み直す
            // （musl ldso が画像末端直後へ書く経路の近似）。
            None => {
                if grow(env, growth, u64::from(a), true)
                    && let Some(w) = fetch_word(env, a)
                {
                    w
                } else {
                    return unimpl_insn(env, sys, pc, pc, 0);
                }
            }
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
    // 基底）。split のループ終端標識も状態に転記する（commit が
    // LC 減算と SA 復帰を行う）。
    env.backend.set(sem::pc_ref(), pc);
    env.backend.set(sem::endloop_ref(), u32::from(pkt.endloop));
    // パケット内の制御転送は先に記録された側が勝つ。
    let mut target = None;
    // `.new` 述語の生成側を先行評価する（実機はパケット同時
    // 発行なので生成側は消費側より後に来てもよい — musl の
    // `if (p0.new) ...; p0 = cmp.eq(...)` 形）。pkt_pw は未確定
    // 域なので本パスの再評価は冪等。生成側同士の `.new` 依存を
    // 1 段まで許すため 2 回掃く（生成側は比較・述語演算だけで
    // メモリ・分岐・積算の副作用を持たない）。
    for _ in 0..2 {
        for si in &slots {
            if packet::pred_prod_cand(si.len, si.group, si.word).is_none() {
                continue;
            }
            let insn = match si.group {
                Some(g) => packet::decode_sub(g, si.word as u16, feats),
                None => decode_model_ex(si.word, si.len, true, feats),
            };
            let Some(insn) = insn else { continue };
            env.backend.ctrl = Ctrl::Fallthrough;
            let cx = sem::Ctx {
                cond: cond_of(si, insn),
                ext: si.ext,
                pc,
                next,
                pos: u32::from(si.pos),
                masked: false,
            };
            if sem::exec(&mut env.backend, insn, si.word, cx).is_err() {
                break;
            }
        }
    }
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
            pos: u32::from(si.pos),
            // dual jump: 先の分岐が確定したあとの分岐命令は
            // まるごと無視（call の LR・frame 復帰・pred も）。
            masked: target.is_some(),
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
            Err(InterpExit::Exception(e))
                if e.kind == ExceptionKind::PageFault
                    && e.addr.is_some_and(|a| grow(env, growth, a, false)) =>
            {
                // 窓内の未写像アクセス: ページを割付けてパケットを
                // やり直す（pkt の未確定値は捨てる。ストアの部分
                // 適用は冪等）。
                sem::pkt_clear(&mut env.backend);
                return Ok(());
            }
            Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => {
                // パケットの生産値を確定してから OS パーソナリティへ。
                // 戻り先は次のパケット（分岐が記録されていればその
                // 着地点。ループ終端なら SA 復帰もありうる）。
                let loop_dest = sem::commit(&mut env.backend).ok().flatten();
                let dest = target.or(loop_dest).unwrap_or(next);
                env.pc = u64::from(dest);
                env.backend.set(sem::pc_ref(), dest);
                let t = sys.handle_trap(env, e.code as u32);
                return trap_result(env, sys, u64::from(pc), t, si.word, |env| {
                    env.pc = u64::from(dest);
                });
            }
            Err(e) => {
                // 未実装命令・その他の例外は illegal パケット扱い。
                if std::env::var_os("POLYISA_HEX_TRACE").is_some() {
                    let kind = match &e {
                        InterpExit::Exception(x) => {
                            format!("{:?} code={:#x} addr={:?}", x.kind, x.code, x.addr)
                        }
                        other => format!("{other:?}"),
                    };
                    eprintln!(
                        "hexagon: illegal pc={pc:#x} word={:#x} insn={insn:?} {kind}",
                        si.word
                    );
                    for i in 0..32 {
                        eprint!("r{i}={:#x} ", sem::r_get(&env.backend, i));
                        if i % 8 == 7 {
                            eprintln!();
                        }
                    }
                    eprintln!();
                    RING.with(|r| {
                        let r = r.borrow();
                        eprintln!("last {} pcs:", r.len());
                        for p in r.iter().rev().take(48) {
                            eprintln!("  {p:#x}");
                        }
                    });
                }
                return unimpl_insn(env, sys, pc, next, si.word);
            }
        }
    }
    let loop_dest = match sem::commit(&mut env.backend) {
        Ok(t) => t,
        Err(_) => {
            return Err(Outcome::Unimplemented {
                pc: u64::from(pc),
                word: u128::from(words[0]),
            });
        }
    };
    // 明示の制御転送があればそちらが勝つ（正規のループ終端
    // パケットにはフロー命令は置けないので両立しない）。
    let dest = target.or(loop_dest).unwrap_or(next);
    env.pc = u64::from(dest);
    env.backend.set(sem::pc_ref(), dest);
    Ok(())
}
