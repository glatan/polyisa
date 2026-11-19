// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC のフェッチから次のフェッチまで。遅延スロットは分岐と同じステップで実行する。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する。
//! 分岐は `npc` だけを書き換え、pc+4 からフェッチした遅延スロットを実行してから
//! `commit` で pc を npc に進める。annul が立っていれば遅延スロットは実行しない。
//! 遅延スロット内の制御転送（DCTI couple）は、各 CTI の遅延スロットを順に
//! 実行し、最後の CTI が書いた npc を着地点とする連鎖として扱う（V9 準拠の
//! 実装選択。V8 では結果不定）。
//! Ref: SPEC-SPARC-V8 (Version 8).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_sparc::sem;
use polyisa_guest_sparc::{Insn, Params, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind, StateRef, W64};

// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct SparcModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
    /// 意味論が `b.param` で読む挙動パラメータ。
    pub params: Params,
    /// アドレスバスのマスク。SPARC32（V7/V8）は 32 ビット、V9 は 64 ビット。
    pub addr_mask: u64,
    /// `decode_model_ex` の 64 ビット指定。`word64` モデルで真。
    pub is64: bool,
}

impl SparcModel {
    /// SPARC V8 の既定モデル。
    #[must_use]
    pub const fn v8() -> Self {
        Self {
            feats: polyisa_guest_sparc::FEAT_V7 | polyisa_guest_sparc::FEAT_V8,
            params: polyisa_guest_sparc::DEFAULT_PARAMS,
            addr_mask: 0xFFFF_FFFF,
            is64: false,
        }
    }

    /// モデル名（`MODELS` のいずれか）から解決する。
    /// 未知の名前は既定パラメータのモデルになる。
    #[must_use]
    pub fn named(name: &str) -> Self {
        let params = polyisa_guest_sparc::model_params(name);
        Self {
            feats: polyisa_guest_sparc::model_feats(name),
            addr_mask: if params.word64 { u64::MAX } else { 0xFFFF_FFFF },
            is64: params.word64,
            params,
        }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: SparcModel,
    sys: &mut impl TrapHandler,
) -> Outcome {
    polyisa_guest_sparc::install_params(&mut env.backend, &model.params);
    env.backend.addr_mask = model.addr_mask;
    env.pc = entry;
    set_u64(env, sem::pc_ref().offset(), entry & model.addr_mask);
    set_u64(
        env,
        sem::npc_ref().offset(),
        entry.wrapping_add(4) & model.addr_mask,
    );
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| get_u64(env, sem::pc_ref().offset()),
        |env, sys| step(env, sys, model),
    )
}

/// 遅延スロットを持つ命令か。Bicc・CALL・JMPL が該当する。
/// Ref: SPEC-SPARC-V8 (Version 8) §Control-Transfer Instructions.
fn has_delay_slot(insn: Insn) -> bool {
    matches!(insn, Insn::Bicc | Insn::Call | Insn::Jmpl | Insn::JmplI)
}

/// 1 命令ぶんのフェッチ・解読・意味論。遅延スロットは分岐と同じ
/// 呼び出しの内側で実行する。
fn step(env: &mut BareEnv, sys: &mut impl TrapHandler, model: SparcModel) -> Result<(), Outcome> {
    let pc = get_u64(env, sem::pc_ref().offset()) & model.addr_mask;
    // 命令フェッチは 4 バイト整列。非整列の mem_address_not_aligned
    // トラップは後続ステップで配送する。
    if pc & 3 != 0 {
        return Err(Outcome::Unimplemented { pc, word: 0 });
    }
    let word = match fetch(env, pc) {
        Some(w) => w,
        None => {
            return Err(Outcome::Unimplemented {
                pc,
                word: 0xffff_ffff,
            });
        }
    };
    let Some(insn) = decode_model_ex(u128::from(word), 32, model.is64, model.feats) else {
        return Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        });
    };
    if let Err(e) = env.step(|b| sem::exec(b, insn, word, pc)) {
        return finish(env, sys, e, pc, word);
    }
    if has_delay_slot(insn) {
        return delay(env, sys, model, pc, word);
    }
    commit(env, pc, word)
}

/// 遅延スロットの実行。スロットの命令は pc+4 からフェッチし、
/// annul が立っていなければ実行してから commit する。スロット内の
/// 例外は `in_delay_slot` を立てて戻す。
/// スロットが制御転送命令（DCTI couple）のときは連鎖として扱う。
/// V8 は結果を不定とするので、V9 の pc/npc パイプラインに倣い、
/// 各 CTI の遅延スロットを順に実行し、最後の CTI が書いた npc を
/// 着地点とする定義済みの動作を選ぶ。
/// Ref: SPEC-SPARC-V9 (Version 9) Table "DCTI Couples".
fn delay(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: SparcModel,
    pc: u64,
    word: u32,
) -> Result<(), Outcome> {
    let mut slot_pc = pc.wrapping_add(4) & model.addr_mask;
    loop {
        // annul が立っていればスロットの命令自体を読まない。取り消された
        // 命令のフェッチや解読は実機でも起きないため、未写像や DCTI 語で
        // 止まってはいけない。
        if get_u64(env, sem::annul_ref().offset()) != 0 {
            return env.step(|b| sem::delay_slot(b, |_| Ok(()))).map_err(|_| {
                Outcome::Unimplemented {
                    pc,
                    word: u128::from(word),
                }
            });
        }
        let Some(slot_word) = fetch(env, slot_pc) else {
            return Err(Outcome::Unimplemented {
                pc: slot_pc,
                word: 0xffff_ffff,
            });
        };
        let Some(slot_insn) = decode_model_ex(u128::from(slot_word), 32, model.is64, model.feats)
        else {
            return Err(Outcome::Unimplemented {
                pc: slot_pc,
                word: u128::from(slot_word),
            });
        };
        let coupled = has_delay_slot(slot_insn);
        let r = env.step(|b| {
            sem::delay_slot_exec(b, |bb| {
                let r = sem::exec(bb, slot_insn, slot_word, slot_pc);
                if let Err(e) = &r
                    && let InterpExit::Exception(g) = e
                {
                    let mut g = *g;
                    g.in_delay_slot = true;
                    return Err(InterpExit::Exception(g));
                }
                r
            })
        });
        if let Err(e) = r {
            return finish(env, sys, e, pc, word);
        }
        // スロットが制御転送命令なら、その遅延スロットを次に実行する
        // 連鎖を続ける。そうでなければ 1 回だけ commit して終わる。
        if !coupled {
            return commit(env, pc, word);
        }
        slot_pc = slot_pc.wrapping_add(4) & model.addr_mask;
    }
}

/// 例外を OS パーソナリティか `Outcome` に写す。Trap 系は
/// `handle_trap` に委ね、それ以外は未実装として止める。
fn finish(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    e: InterpExit,
    pc: u64,
    word: u32,
) -> Result<(), Outcome> {
    if let InterpExit::Exception(g) = e
        && g.kind == ExceptionKind::Trap
    {
        match sys.handle_trap(env, g.code as u32) {
            // 処理済みの復帰 PC はハンドラが設定済みの契約。
            TrapOutcome::Handled => return Ok(()),
            TrapOutcome::Exit(code) => {
                if sys.take_exit(env, code) {
                    return Ok(());
                }
                return Err(Outcome::Exit(u64::from(code)));
            }
            TrapOutcome::Blocked => {
                if sys.on_block(env) {
                    return Ok(());
                }
                return Err(Outcome::Deadlock);
            }
            TrapOutcome::Unimplemented => {}
        }
    }
    Err(Outcome::Unimplemented {
        pc,
        word: u128::from(word),
    })
}

/// 遅延スロットのない命令の完了。pc を npc に進める。
fn commit(env: &mut BareEnv, pc: u64, word: u32) -> Result<(), Outcome> {
    match env.step(sem::commit) {
        Ok(()) => Ok(()),
        Err(_) => Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        }),
    }
}

/// 命令のフェッチ。BE・自然整列で 4 バイト読む。
fn fetch(env: &BareEnv, pc: u64) -> Option<u32> {
    let mut buf = [0u8; 4];
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    env.backend.mem.read(VirtAddr(pc), &mut buf, acc).ok()?;
    Some(u32::from_be_bytes(buf))
}

fn get_u64(env: &mut BareEnv, offset: usize) -> u64 {
    env.backend.get(StateRef::<W64>::from_offset(offset))
}

fn set_u64(env: &mut BareEnv, offset: usize, value: u64) {
    env.backend.set(StateRef::<W64>::from_offset(offset), value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_sparc::{CpuState, sem::Gpr};

    /// プログラム語列を `base` に置いた裸実行環境。
    fn env_at(base: u64, words: &[u32]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(VirtAddr(base & !0xFFF), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_be_bytes());
        }
        env.backend.mem.write(VirtAddr(base), &bytes).unwrap();
        env
    }

    /// 何もしないハンドラ。trap 委譲のない裸実行に使う。
    struct NoSys;

    impl TrapHandler for NoSys {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
    }

    fn g(env: &mut BareEnv, r: u8) -> u64 {
        env.backend.get(Gpr(r).state())
    }

    #[test]
    fn straight_line_runs_to_unimp() {
        // sethi 1,%g1; add %g1,3,%g2; unimp → g2=0x403 で未実装停止。
        let mut env = env_at(0x1000, &[0x0300_0001, 0x8400_6003, 0x0000_0000]);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x400);
        assert_eq!(g(&mut env, 2), 0x403);
    }

    #[test]
    fn branch_runs_delay_slot_then_jumps() {
        // ba +12: 遅延スロットの sethi は実行し、0x1008 の sethi %g3 は飛ばす。
        // 0x100c: add %g1,3,%g2; 0x1010: unimp。
        let mut env = env_at(
            0x1000,
            &[
                0x1080_0003, // ba +12
                0x0300_0001, // sethi 1,%g1（遅延スロット）
                0x0600_0009, // sethi 9,%g3（飛ばされる）
                0x8400_6003, // add %g1,3,%g2
                0x0000_0000, // unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1010),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x400);
        assert_eq!(g(&mut env, 2), 0x403);
        assert_eq!(g(&mut env, 3), 0);
    }

    #[test]
    fn annulled_branch_skips_delay_slot() {
        // ba,a +8: 遅延スロットの sethi は取り消される。
        let mut env = env_at(0x1000, &[0x3080_0002, 0x0300_0009, 0x0000_0000]);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0);
    }

    #[test]
    fn annulled_branch_never_fetches_slot() {
        // ba,a のスロットが未写像でも、取り消される命令は読まない。
        // ba,a を 0x1FFC（スロットは未写像の 0x2000）に置き、
        // 0x3000 の unimp へ飛ぶ。
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(VirtAddr(0x1000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .map(VirtAddr(0x3000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        // ba,a +0x1004（0x1FFC + 0x1004 = 0x3000）。
        env.backend
            .mem
            .write(VirtAddr(0x1FFC), &0x3080_0401u32.to_be_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x3000), &0x0000_0000u32.to_be_bytes())
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1FFC, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x3000),
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn not_taken_branch_falls_through_delay_slot() {
        // ICC=0 で be は不成立。遅延スロットは実行し pc+8 へ進む。
        let mut env = env_at(
            0x1000,
            &[0x0280_0002, 0x0300_0001, 0x8400_6003, 0x0000_0000],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x400);
        assert_eq!(g(&mut env, 2), 0x403);
    }

    #[test]
    fn annulled_cond_branch_not_taken_skips_slot() {
        // Z=0 で be,a は不成立。遅延スロットは取り消され pc+8 へ進む。
        let mut env = env_at(
            0x1000,
            &[
                0x2280_0002, // be,a +8
                0x0300_0009, // sethi 9,%g1（取り消される）
                0x0500_0001, // sethi 1,%g2
                0x0000_0000, // unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0);
        assert_eq!(g(&mut env, 2), 0x400);
    }

    #[test]
    fn annulled_cond_branch_taken_runs_slot() {
        // Z=1 で be,a は成立。成立時は a にかかわらずスロットを実行し、
        // 0x1020 へ飛ぶ。0x1008-0x101c の命令は実行されない。
        let mut env = env_at(
            0x1000,
            &[
                0x2280_0008, // be,a 0x1020
                0x0300_0009, // sethi 9,%g1（遅延スロット）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0900_0001, // 0x1020: sethi 1,%g4
                0x0000_0000, // 0x1024: unimp
            ],
        );
        env.backend.set(sem::psr_ref(), 1 << 22);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1024),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x2400);
        assert_eq!(g(&mut env, 4), 0x400);
    }

    #[test]
    fn call_writes_o7_and_jumps() {
        // call 0x1020。%o7 に戻り（0x1000）を書き、遅延スロット実行後
        // 0x1020 へ飛ぶ。
        let mut env = env_at(
            0x1000,
            &[
                0x4000_0008, // call 0x1020
                0x0300_0009, // sethi 9,%g1（遅延スロット）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000, // 0x1020: unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1020),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 15), 0x1000);
        assert_eq!(g(&mut env, 1), 0x2400);
    }

    #[test]
    fn jmpl_jumps_after_delay_slot() {
        // jmpl %g1, %g0 に %g1=0x1020 を仕込んで実行。間接飛び先へ
        // 遅延スロットを挟んで進む。
        let mut env = env_at(
            0x1000,
            &[
                0x81c0_6000, // jmpl %g1+0, %g0
                0x0500_0009, // sethi 9,%g2（遅延スロット）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000, // 0x1020: unimp
            ],
        );
        env.backend.set(Gpr(1).state(), 0x1020);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1020),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 2), 0x2400);
    }

    #[test]
    fn dcti_couple_chains_through_delay_slots() {
        // ba 0x1F00; ba 0x2000 の DCTI couple。V9 に倣い各遅延
        // スロットを実行し、npc は最後の CTI（0x2000）が効く。
        // 外側の飛び先 0x1F00 は実行されない。
        let mut words = vec![0x0000_0000u32; 0x400];
        words[0] = 0x1080_03c0; // 0x1000: ba 0x1F00
        words[1] = 0x1080_03ff; // 0x1004: ba 0x2000
        words[2] = 0x0300_0005; // 0x1008: sethi 5,%g1（内側のスロット）
        words[0x3c0] = 0x0500_0007; // 0x1F00: sethi 7,%g2（実行されない）
        let mut env = env_at(0x1000, &words);
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x2000), &0x0000_0000u32.to_be_bytes())
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x2000),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x1400);
        assert_eq!(g(&mut env, 2), 0);
    }

    #[test]
    fn dcti_couple_inner_annul_skips_its_slot() {
        // ba 0x1F00; ba,a 0x2000。内側の annul で 0x1008 は取り消され、
        // そのまま 0x2000 へ進む。
        let mut env = env_at(
            0x1000,
            &[
                0x1080_03c0, // 0x1000: ba 0x1F00
                0x3080_03ff, // 0x1004: ba,a 0x2000
                0x0300_0005, // 0x1008: sethi 5,%g1（取り消される）
            ],
        );
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x2000), &0x0000_0000u32.to_be_bytes())
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x2000),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0);
    }
}
