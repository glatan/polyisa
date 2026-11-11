// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS のフェッチから次のフェッチまで。遅延スロットは分岐と同じステップで実行する。
//!
//! 分岐とジャンプは `npc` だけを書き換え、スロットの命令を実行してから `commit` する。
//! スロット内の例外は `in_delay_slot` を立てて戻す。ロード遅延と o32 は後の回で足す。
//! Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_guest_mips::sem::{self, Gpr};
use polyisa_guest_mips::{Insn, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind, GuestException};

const STEP_LIMIT: u64 = 5_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct MipsModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u64,
    pub endian: Endian,
    /// R3000 のロード遅延。この回では false のまま使う。
    pub load_delay: bool,
}

impl MipsModel {
    /// ビッグエンディアンの MIPS I。ロード遅延はまだ無効。
    #[must_use]
    pub const fn mips1_be() -> Self {
        Self {
            feats: 0,
            endian: Endian::Be,
            load_delay: false,
        }
    }
}

/// ループの戻り。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MipsOutcome {
    Exit(u64),
    Unimplemented { pc: u64, word: u32 },
    StepLimit { pc: u64 },
    Exception(GuestException),
}

struct Effect {
    wrote: Option<u8>,
    delayed: Option<u64>,
}

enum Stop {
    Unimplemented { pc: u64, word: u32 },
    Exception(GuestException),
}

/// `entry` から `model` で実行する。`syscall` はまだ命令がないので来ない。
pub fn run(env: &mut BareEnv, entry: u64, model: MipsModel) -> MipsOutcome {
    set_u64(env, sem::pc_ref().offset(), entry);
    set_u64(env, sem::npc_ref().offset(), entry.wrapping_add(4));
    let mut pending: Option<(u8, u64)> = None;
    for _ in 0..STEP_LIMIT {
        let pc = get_u64(env, sem::pc_ref().offset());
        let word = match fetch(env, pc, model.endian, false) {
            Ok(w) => w,
            Err(Stop::Unimplemented { pc, word }) => {
                return MipsOutcome::Unimplemented { pc, word };
            }
            Err(Stop::Exception(e)) => return MipsOutcome::Exception(e),
        };
        let Some(insn) = decode_model_ex(u128::from(word), 32, true, model.feats) else {
            return MipsOutcome::Unimplemented { pc, word };
        };
        if has_delay_slot(insn) {
            let branch_effect = match exec(env, insn, word, pc, model, false) {
                Ok(effect) => effect,
                Err(stop) => return stop_outcome(stop),
            };
            pending = retire(env, pending, branch_effect);
            let slot_pc = pc.wrapping_add(4);
            let slot = match fetch(env, slot_pc, model.endian, true) {
                Ok(w) => w,
                Err(stop) => return stop_outcome(stop),
            };
            let Some(slot_insn) = decode_model_ex(u128::from(slot), 32, true, model.feats) else {
                return MipsOutcome::Unimplemented {
                    pc: slot_pc,
                    word: slot,
                };
            };
            if has_delay_slot(slot_insn) || slot_insn == Insn::Beqzalc {
                return MipsOutcome::Unimplemented {
                    pc: slot_pc,
                    word: slot,
                };
            }
            match exec(env, slot_insn, slot, slot_pc, model, true) {
                Ok(effect) => pending = retire(env, pending, effect),
                Err(stop) => return stop_outcome(stop),
            }
            if let Err(stop) = commit(env) {
                return stop_outcome(stop);
            }
            continue;
        }
        let direct = insn == Insn::Beqzalc;
        match exec(env, insn, word, pc, model, false) {
            Ok(effect) => pending = retire(env, pending, effect),
            Err(stop) => return stop_outcome(stop),
        }
        if direct {
            let now = get_u64(env, sem::pc_ref().offset());
            set_u64(env, sem::npc_ref().offset(), now.wrapping_add(4));
        } else if let Err(stop) = commit(env) {
            return stop_outcome(stop);
        }
    }
    MipsOutcome::StepLimit {
        pc: get_u64(env, sem::pc_ref().offset()),
    }
}

fn has_delay_slot(insn: Insn) -> bool {
    matches!(insn, Insn::Beq | Insn::J)
}

fn stop_outcome(stop: Stop) -> MipsOutcome {
    match stop {
        Stop::Unimplemented { pc, word } => MipsOutcome::Unimplemented { pc, word },
        Stop::Exception(e) => MipsOutcome::Exception(e),
    }
}

fn retire(env: &mut BareEnv, pending: Option<(u8, u64)>, effect: Effect) -> Option<(u8, u64)> {
    if let Some((reg, value)) = pending
        && effect.wrote != Some(reg)
    {
        set_reg(env, reg, value);
    }
    match (effect.wrote, effect.delayed) {
        (Some(reg), Some(value)) if reg != 0 => Some((reg, value)),
        _ => None,
    }
}

fn exec(
    env: &mut BareEnv,
    insn: Insn,
    word: u32,
    pc: u64,
    model: MipsModel,
    in_slot: bool,
) -> Result<Effect, Stop> {
    let rs = field_reg(word, 21);
    let rt = field_reg(word, 16);
    let rd = field_reg(word, 11);
    let imm = (word as i16) as i32;
    let shamt = (word >> 6) & 31;
    let none = Effect {
        wrote: None,
        delayed: None,
    };
    match insn {
        Insn::Addu => step(env, in_slot, |b| sem::addu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Subu => step(env, in_slot, |b| sem::subu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::And => step(env, in_slot, |b| sem::and(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Or => step(env, in_slot, |b| sem::or(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Sll => step(env, in_slot, |b| sem::sll(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Addi => step(env, in_slot, |b| sem::addi(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Addiu => step(env, in_slot, |b| sem::addiu(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Mult => step(env, in_slot, |b| sem::mult(b, rs, rt)).map(|()| none),
        Insn::Multu => step(env, in_slot, |b| sem::multu(b, rs, rt)).map(|()| none),
        Insn::Div => step(env, in_slot, |b| sem::div(b, rs, rt)).map(|()| none),
        Insn::Divu => step(env, in_slot, |b| sem::divu(b, rs, rt)).map(|()| none),
        Insn::Mfhi => step(env, in_slot, |b| sem::mfhi(b, rd)).map(|()| wrote(rd)),
        Insn::Mflo => step(env, in_slot, |b| sem::mflo(b, rd)).map(|()| wrote(rd)),
        Insn::Mthi => step(env, in_slot, |b| sem::mthi(b, rs)).map(|()| none),
        Insn::Mtlo => step(env, in_slot, |b| sem::mtlo(b, rs)).map(|()| none),
        Insn::Lw => load_word(env, rt, rs, imm, model, in_slot),
        Insn::Sw => step(env, in_slot, |b| sem::sw(b, rt, rs, imm)).map(|()| none),
        Insn::Beq => step(env, in_slot, |b| sem::beq_delay(b, rs, rt, pc, imm)).map(|()| none),
        Insn::J => {
            let target = j_target(pc, word);
            step(env, in_slot, |b| sem::j_delay(b, target)).map(|()| none)
        }
        Insn::Beqzalc => {
            step(env, in_slot, |b| sem::beqzalc(b, rs, rt, pc, imm)).map(|()| Effect {
                wrote: Some(31),
                delayed: None,
            })
        }
    }
}

fn load_word(
    env: &mut BareEnv,
    rt: Gpr,
    rs: Gpr,
    imm: i32,
    model: MipsModel,
    in_slot: bool,
) -> Result<Effect, Stop> {
    let old = reg(env, rt.0);
    step(env, in_slot, |b| sem::lw(b, rt, rs, imm))?;
    if model.load_delay && rt.0 != 0 {
        let new = reg(env, rt.0);
        set_reg(env, rt.0, old);
        Ok(Effect {
            wrote: Some(rt.0),
            delayed: Some(new),
        })
    } else {
        Ok(wrote(rt))
    }
}

fn wrote(rd: Gpr) -> Effect {
    Effect {
        wrote: if rd.0 == 0 { None } else { Some(rd.0) },
        delayed: None,
    }
}

fn commit(env: &mut BareEnv) -> Result<(), Stop> {
    step(env, false, sem::commit)
}

fn step<F>(env: &mut BareEnv, in_slot: bool, f: F) -> Result<(), Stop>
where
    F: FnOnce(&mut polyisa_engine::interp::InterpBackend) -> Result<(), InterpExit>,
{
    match env.step(f) {
        Ok(()) => Ok(()),
        Err(InterpExit::Exception(mut exception)) => {
            exception.in_delay_slot = in_slot;
            Err(Stop::Exception(exception))
        }
        Err(InterpExit::Unimplemented(_)) => Err(Stop::Unimplemented {
            pc: get_u64(env, sem::pc_ref().offset()),
            word: 0,
        }),
    }
}

fn fetch(env: &BareEnv, pc: u64, endian: Endian, in_slot: bool) -> Result<u32, Stop> {
    if !pc.is_multiple_of(4) {
        return Err(Stop::Exception(GuestException {
            kind: ExceptionKind::Align,
            code: 0,
            addr: Some(pc),
            in_delay_slot: in_slot,
        }));
    }
    let mut buf = [0u8; 4];
    let acc = Access {
        endian,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    if env.backend.mem.read(VirtAddr(pc), &mut buf, acc).is_err() {
        return Err(Stop::Unimplemented {
            pc,
            word: 0xffff_ffff,
        });
    }
    Ok(match endian {
        Endian::Be => u32::from_be_bytes(buf),
        Endian::Le => u32::from_le_bytes(buf),
    })
}

fn j_target(pc: u64, word: u32) -> u64 {
    let region = pc.wrapping_add(4) & 0xf000_0000;
    region | (u64::from(word & 0x03ff_ffff) << 2)
}

fn field_reg(word: u32, shift: u32) -> Gpr {
    Gpr(((word >> shift) & 31) as u8)
}

fn reg(env: &mut BareEnv, index: u8) -> u64 {
    if index == 0 {
        0
    } else {
        env.backend.get(Gpr(index).state())
    }
}

fn set_reg(env: &mut BareEnv, index: u8, value: u64) {
    if index != 0 {
        env.backend.set(Gpr(index).state(), value);
    }
}

fn get_u64(env: &mut BareEnv, offset: usize) -> u64 {
    env.backend
        .get(polyisa_sem::StateRef::<polyisa_sem::W64>::from_offset(
            offset,
        ))
}

fn set_u64(env: &mut BareEnv, offset: usize, value: u64) {
    env.backend.set(
        polyisa_sem::StateRef::<polyisa_sem::W64>::from_offset(offset),
        value,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_mem::Perms;

    fn env_at(base: u64) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_mips::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(base), 2, rwx).unwrap();
        env
    }

    fn poke(env: &mut BareEnv, addr: u64, word: u32) {
        env.backend
            .mem
            .write(VirtAddr(addr), &word.to_be_bytes())
            .unwrap();
    }

    fn mem_word(env: &BareEnv, addr: u64) -> u32 {
        let mut buf = [0u8; 4];
        let acc = Access {
            endian: Endian::Be,
            align: Align::Unaligned,
            kind: AccessKind::DataRead,
        };
        env.backend.mem.read(VirtAddr(addr), &mut buf, acc).unwrap();
        u32::from_be_bytes(buf)
    }

    #[test]
    fn taken_branch_runs_slot_store_then_target() {
        // 0x1000 beq r1, r2, +2
        // 0x1004 sw  r3, 0(r4)     遅延スロット。分岐先では実行しない。
        // 0x1008 addiu r5, zero, 1  成立時は飛ばす。
        // 0x100C addiu r6, zero, 2  飛び先。
        // 0x1010 未定義で停止。
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x1022_0002);
        poke(&mut env, 0x1004, 0xac83_0000);
        poke(&mut env, 0x1008, 0x2405_0001);
        poke(&mut env, 0x100c, 0x2406_0002);
        poke(&mut env, 0x1010, 0xffff_ffff);
        set_reg(&mut env, 1, 5);
        set_reg(&mut env, 2, 5);
        set_reg(&mut env, 3, 0x99);
        set_reg(&mut env, 4, 0x1800);
        let outcome = run(&mut env, 0x1000, MipsModel::mips1_be());
        assert_eq!(
            outcome,
            MipsOutcome::Unimplemented {
                pc: 0x1010,
                word: 0xffff_ffff,
            }
        );
        assert_eq!(mem_word(&env, 0x1800), 0x99);
        assert_eq!(reg(&mut env, 5), 0);
        assert_eq!(reg(&mut env, 6), 2);
        assert_eq!(get_u64(&mut env, sem::pc_ref().offset()), 0x1010);
    }

    #[test]
    fn untaken_branch_still_runs_slot_then_falls_through() {
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x1022_0002);
        poke(&mut env, 0x1004, 0xac83_0000);
        poke(&mut env, 0x1008, 0x2405_0001);
        poke(&mut env, 0x100c, 0x2406_0002);
        poke(&mut env, 0x1010, 0xffff_ffff);
        set_reg(&mut env, 1, 5);
        set_reg(&mut env, 2, 6);
        set_reg(&mut env, 3, 0x99);
        set_reg(&mut env, 4, 0x1800);
        let outcome = run(&mut env, 0x1000, MipsModel::mips1_be());
        assert!(matches!(
            outcome,
            MipsOutcome::Unimplemented { pc: 0x1010, .. }
        ));
        assert_eq!(mem_word(&env, 0x1800), 0x99);
        assert_eq!(reg(&mut env, 5), 1);
        assert_eq!(reg(&mut env, 6), 2);
    }

    #[test]
    fn misaligned_load_in_slot_reports_delay_slot() {
        // スロットの lw が非整列。分岐先は実行しない。
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x1022_0002);
        poke(&mut env, 0x1004, 0x8c83_0001);
        poke(&mut env, 0x1008, 0x2405_0001);
        set_reg(&mut env, 1, 1);
        set_reg(&mut env, 2, 1);
        set_reg(&mut env, 4, 0x1800);
        let outcome = run(&mut env, 0x1000, MipsModel::mips1_be());
        match outcome {
            MipsOutcome::Exception(exception) => {
                assert!(exception.in_delay_slot);
                assert_eq!(exception.kind, ExceptionKind::Align);
                assert_eq!(exception.addr, Some(0x1801));
            }
            other => panic!("expected exception, got {other:?}"),
        }
        assert_eq!(reg(&mut env, 5), 0);
    }
}
