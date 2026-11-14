// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! MIPS のフェッチから次のフェッチまで。遅延スロットは分岐と同じステップで実行する。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する（ADR-0016、GAP-0007）。
//! syscall の処理は `os-linux` の `mips::sys::Linux` に委譲する（GAP-0001）。
//!
//! 分岐とジャンプは `npc` だけを書き換え、スロットの命令を実行してから `commit` する。
//! スロット内の例外は `in_delay_slot` を立てて戻す。R3000 のロード遅延は
//! 命令のあとにレジスタを戻し、次の命令が古い値を読む。
//! Ref: SPEC-MIPS-IV (Rev 3.2).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
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
    /// R3000 だけが真。Release 2 と Release 6 は偽。
    pub load_delay: bool,
    /// n32/n64 の MIPS64 命令を有効にする。32 ビットモデルでは偽。
    pub is64: bool,
}

impl MipsModel {
    /// ビッグエンディアンの R3000。ロードの結果は次の命令には見えず、その次から見える。
    #[must_use]
    pub const fn mips1_be() -> Self {
        Self {
            feats: 0,
            endian: Endian::Be,
            load_delay: true,
            is64: false,
        }
    }

    /// リトルエンディアンの R3000。ロード遅延はビッグエンディアンと同じ。
    #[must_use]
    pub const fn mips1_le() -> Self {
        Self {
            feats: 0,
            endian: Endian::Le,
            load_delay: true,
            is64: false,
        }
    }

    /// MIPS32 Release 2。符号化は MIPS I に R2 追加命令を足したもの、ロード遅延はない。
    #[must_use]
    pub const fn mips32r2() -> Self {
        Self {
            feats: polyisa_guest_mips::FEAT_MIPS32R2 | polyisa_guest_mips::FEAT_FPU,
            endian: Endian::Le,
            load_delay: false,
            is64: false,
        }
    }

    /// Release 6。コンパクト分岐を復号し、ロード遅延はない。フェッチはリトルエンディアン。
    #[must_use]
    pub const fn r6() -> Self {
        Self {
            feats: polyisa_guest_mips::FEAT_MIPS32R2
                | polyisa_guest_mips::FEAT_MIPS_R6
                | polyisa_guest_mips::FEAT_FPU,
            endian: Endian::Le,
            load_delay: false,
            is64: false,
        }
    }

    /// MIPS64 Release 2（n32/n64 を走らせる 64 ビットモデル）。
    #[must_use]
    pub const fn mips64r2() -> Self {
        Self {
            feats: polyisa_guest_mips::FEAT_MIPS32R2
                | polyisa_guest_mips::FEAT_MIPS64
                | polyisa_guest_mips::FEAT_FPU,
            endian: Endian::Be,
            load_delay: false,
            is64: true,
        }
    }

    /// MIPS64 Release 6。
    #[must_use]
    pub const fn mips64r6() -> Self {
        Self {
            feats: polyisa_guest_mips::FEAT_MIPS32R2
                | polyisa_guest_mips::FEAT_MIPS64
                | polyisa_guest_mips::FEAT_MIPS_R6
                | polyisa_guest_mips::FEAT_FPU,
            endian: Endian::Be,
            load_delay: false,
            is64: true,
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

/// `engine::run::run` の `step` に渡す MIPS の状態。R3000 の
/// ロード遅延の保留と、最後の例外を覚える。
pub struct MipsStep {
    pub model: MipsModel,
    pending: Option<(u8, u64)>,
    last_exc: Option<GuestException>,
    trace: bool,
    hist: std::collections::VecDeque<u64>,
}

impl MipsStep {
    #[must_use]
    pub fn new(model: MipsModel) -> Self {
        Self {
            model,
            pending: None,
            last_exc: None,
            trace: std::env::var_os("POLYISA_MIPS_TRACE").is_some(),
            hist: std::collections::VecDeque::new(),
        }
    }

    /// 最後に起きたゲスト例外。`Outcome::Unimplemented` と同時に立つ。
    #[must_use]
    pub fn last_exception(&self) -> Option<GuestException> {
        self.last_exc
    }

    /// トレース有効時、直近の pc 履歴を標準エラーへ出す。
    pub fn dump_hist(&self) {
        if self.trace {
            let h: Vec<String> = self.hist.iter().map(|p| format!("{p:#x}")).collect();
            eprintln!("hist: {}", h.join(" "));
        }
    }

    /// トレース有効時、GPR 全体を標準エラーへ出す。
    pub fn dump_regs(&self, env: &mut BareEnv) {
        if self.trace {
            for r in 0u8..32 {
                let v = env
                    .backend
                    .get(polyisa_sem::StateRef::<polyisa_sem::W64>::from_offset(
                        Gpr(r).state().offset(),
                    ));
                eprintln!("  r{r}={v:#x}");
            }
        }
    }

    /// 1 ステップぶんのフェッチ・解読・意味論とトラップ境界の解決。
    /// 遅延スロットは分岐と同じ呼び出しの内側で実行する。
    pub fn step<H: ?Sized + TrapHandler>(
        &mut self,
        env: &mut BareEnv,
        sys: &mut H,
    ) -> Result<(), Outcome> {
        let model = self.model;
        let pc = get_u64(env, sem::pc_ref().offset());
        if self.trace {
            self.hist.push_back(pc);
            if self.hist.len() > 128 {
                self.hist.pop_front();
            }
        }
        let word = match fetch(env, pc, model.endian, false) {
            Ok(w) => w,
            Err(stop) => return Err(self.stop_outcome(stop)),
        };
        let Some(insn) = decode_model_ex(u128::from(word), 32, true, model.feats) else {
            return Err(Outcome::Unimplemented {
                pc,
                word: u128::from(word),
            });
        };
        if insn == Insn::Syscall {
            return self.syscall(env, sys, pc, word);
        }
        if has_delay_slot(insn) {
            let effect = match exec(env, insn, word, pc, model, false) {
                Ok(effect) => effect,
                Err(stop) => return Err(self.stop_outcome(stop)),
            };
            self.pending = retire(env, self.pending, effect);
            // branch-likely 不成立時は遅延スロットを実行せず pc+8 へ進む。
            if get_u64(env, sem::nullify_ref().offset()) != 0 {
                set_u64(env, sem::nullify_ref().offset(), 0);
                return match commit(env) {
                    Ok(()) => Ok(()),
                    Err(stop) => Err(self.stop_outcome(stop)),
                };
            }
            let slot_pc = pc.wrapping_add(4);
            let slot = match fetch(env, slot_pc, model.endian, true) {
                Ok(w) => w,
                Err(stop) => return Err(self.stop_outcome(stop)),
            };
            let Some(slot_insn) = decode_model_ex(u128::from(slot), 32, true, model.feats) else {
                return Err(Outcome::Unimplemented {
                    pc: slot_pc,
                    word: u128::from(slot),
                });
            };
            if has_delay_slot(slot_insn) || is_compact(slot_insn) {
                return Err(Outcome::Unimplemented {
                    pc: slot_pc,
                    word: u128::from(slot),
                });
            }
            if slot_insn == Insn::Syscall {
                return self.syscall(env, sys, slot_pc, slot);
            }
            match exec(env, slot_insn, slot, slot_pc, model, true) {
                Ok(effect) => self.pending = retire(env, self.pending, effect),
                Err(stop) => return Err(self.stop_outcome(stop)),
            }
            return match commit(env) {
                Ok(()) => Ok(()),
                Err(stop) => Err(self.stop_outcome(stop)),
            };
        }
        let direct = is_compact(insn);
        match exec(env, insn, word, pc, model, false) {
            Ok(effect) => self.pending = retire(env, self.pending, effect),
            Err(stop) => return Err(self.stop_outcome(stop)),
        }
        if direct {
            let now = get_u64(env, sem::pc_ref().offset());
            set_u64(env, sem::npc_ref().offset(), now.wrapping_add(4));
            return Ok(());
        }
        match commit(env) {
            Ok(()) => Ok(()),
            Err(stop) => Err(self.stop_outcome(stop)),
        }
    }

    /// syscall の処理。`TrapOutcome` を `Outcome` に写す。
    /// 処理に成功したときはロード遅延の保留を v0/a3 以外に反映する。
    fn syscall<H: ?Sized + TrapHandler>(
        &mut self,
        env: &mut BareEnv,
        sys: &mut H,
        pc: u64,
        word: u32,
    ) -> Result<(), Outcome> {
        match sys.handle_trap(env, word) {
            TrapOutcome::Handled => {
                self.pending = release_pending(env, self.pending, &[2, 7]);
                match commit(env) {
                    Ok(()) => Ok(()),
                    Err(stop) => Err(self.stop_outcome(stop)),
                }
            }
            TrapOutcome::Exit(code) => {
                if sys.take_exit(env, code) {
                    Ok(())
                } else {
                    Err(Outcome::Exit(u64::from(code)))
                }
            }
            TrapOutcome::Blocked => {
                if sys.on_block(env) {
                    Ok(())
                } else {
                    Err(Outcome::Deadlock)
                }
            }
            TrapOutcome::Unimplemented => Err(Outcome::Unimplemented {
                pc,
                word: u128::from(word),
            }),
        }
    }

    fn stop_outcome(&mut self, stop: Stop) -> Outcome {
        self.dump_hist();
        match stop {
            Stop::Unimplemented { pc, word } => Outcome::Unimplemented {
                pc,
                word: u128::from(word),
            },
            Stop::Exception(e) => {
                self.last_exc = Some(e);
                Outcome::Unimplemented {
                    pc: e.addr.unwrap_or(0),
                    word: 0,
                }
            }
        }
    }
}

struct Effect {
    wrote: Option<u8>,
    delayed: Option<u64>,
}

enum Stop {
    Unimplemented { pc: u64, word: u32 },
    Exception(GuestException),
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: MipsModel,
    sys: &mut impl TrapHandler,
) -> MipsOutcome {
    let limit = std::env::var("POLYISA_MIPS_LIMIT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(STEP_LIMIT);
    run_ex(env, entry, model, sys, limit)
}

/// `run` にステップ数の上限を渡す。
pub fn run_ex(
    env: &mut BareEnv,
    entry: u64,
    model: MipsModel,
    sys: &mut impl TrapHandler,
    limit: u64,
) -> MipsOutcome {
    set_u64(env, sem::pc_ref().offset(), entry);
    set_u64(env, sem::npc_ref().offset(), entry.wrapping_add(4));
    let mut st = MipsStep::new(model);
    let out = polyisa_engine::run::run(
        env,
        sys,
        limit,
        |env| get_u64(env, sem::pc_ref().offset()),
        |env, sys| st.step(env, sys),
    );
    match (out, st.last_exception()) {
        (_, Some(e)) => MipsOutcome::Exception(e),
        (Outcome::Exit(code), _) => MipsOutcome::Exit(code),
        (Outcome::Unimplemented { pc, word }, _) => {
            st.dump_regs(env);
            if st.trace {
                let f = get_u64(env, Gpr(16).state().offset());
                let mut buf = [0u8; 0xf0];
                let acc = polyisa_mem::Access::DATA_LE;
                if env
                    .backend
                    .mem
                    .read(polyisa_mem::VirtAddr(f), &mut buf, acc)
                    .is_ok()
                {
                    for (i, b) in buf.chunks(8).enumerate() {
                        eprintln!(
                            "  f+{:#04x}: {:#x}",
                            i * 8,
                            u64::from_be_bytes(b.try_into().unwrap())
                        );
                    }
                }
            }
            MipsOutcome::Unimplemented {
                pc,
                word: word as u32,
            }
        }
        (Outcome::StepLimit { pc }, _) => {
            st.dump_hist();
            st.dump_regs(env);
            MipsOutcome::StepLimit { pc }
        }
        (Outcome::Deadlock, _) => {
            st.dump_hist();
            st.dump_regs(env);
            MipsOutcome::StepLimit {
                pc: get_u64(env, sem::pc_ref().offset()),
            }
        }
    }
}

fn has_delay_slot(insn: Insn) -> bool {
    matches!(
        insn,
        Insn::Beq
            | Insn::Bne
            | Insn::Blez
            | Insn::Bgtz
            | Insn::Bltz
            | Insn::Bgez
            | Insn::Bltzal
            | Insn::Bgezal
            | Insn::Beql
            | Insn::Bnel
            | Insn::Blezl
            | Insn::Bgtzl
            | Insn::Bltzl
            | Insn::Bgezl
            | Insn::Bltzall
            | Insn::Bgezall
            | Insn::Bc1f
            | Insn::Bc1t
            | Insn::Bc1fl
            | Insn::Bc1tl
            | Insn::J
            | Insn::Jal
            | Insn::Jr
            | Insn::Jalr
            | Insn::Bal
            | Insn::Nal
    )
}

/// pc を直接書き換える遅延スロットなしの制御命令（Release 6）。
/// BEQZALC と同じく step が pc 更新後に npc=pc+4 を張る。
fn is_compact(insn: Insn) -> bool {
    matches!(
        insn,
        Insn::Beqzalc
            | Insn::Bnezalc
            | Insn::Bc
            | Insn::Balc
            | Insn::Jic
            | Insn::Jialc
            | Insn::Beqzc
            | Insn::Bnezc
            | Insn::Bovc
            | Insn::Bnvc
            | Insn::Beqc
            | Insn::Bnec
            | Insn::Bgeuc
            | Insn::Bltuc
            | Insn::Bgec
            | Insn::Bltc
            | Insn::Blezalc
            | Insn::Bgezalc
            | Insn::Bltzalc
            | Insn::Bgtzalc
            | Insn::Blezc
            | Insn::Bgtzc
            | Insn::Bgezc
            | Insn::Bltzc
    )
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
    let fs = ((word >> 11) & 31) as u8;
    let ft = ((word >> 16) & 31) as u8;
    let fd = ((word >> 6) & 31) as u8;
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
        Insn::Srl => step(env, in_slot, |b| sem::srl(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Sra => step(env, in_slot, |b| sem::sra(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Sllv => step(env, in_slot, |b| sem::sllv(b, rd, rt, rs)).map(|()| wrote(rd)),
        Insn::Srlv => step(env, in_slot, |b| sem::srlv(b, rd, rt, rs)).map(|()| wrote(rd)),
        Insn::Srav => step(env, in_slot, |b| sem::srav(b, rd, rt, rs)).map(|()| wrote(rd)),
        Insn::Add => step(env, in_slot, |b| sem::add(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Sub => step(env, in_slot, |b| sem::sub(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Xor => step(env, in_slot, |b| sem::xor(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Nor => step(env, in_slot, |b| sem::nor(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Slt => step(env, in_slot, |b| sem::slt(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Sltu => step(env, in_slot, |b| sem::sltu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Addi => step(env, in_slot, |b| sem::addi(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Addiu => step(env, in_slot, |b| sem::addiu(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Slti => step(env, in_slot, |b| sem::slti(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Sltiu => step(env, in_slot, |b| sem::sltiu(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Andi => {
            step(env, in_slot, |b| sem::andi(b, rt, rs, imm as u16 as u32)).map(|()| wrote(rt))
        }
        Insn::Ori => {
            step(env, in_slot, |b| sem::ori(b, rt, rs, imm as u16 as u32)).map(|()| wrote(rt))
        }
        Insn::Xori => {
            step(env, in_slot, |b| sem::xori(b, rt, rs, imm as u16 as u32)).map(|()| wrote(rt))
        }
        Insn::Lui => step(env, in_slot, |b| sem::lui(b, rt, imm as u16 as u32)).map(|()| wrote(rt)),
        Insn::Mult => step(env, in_slot, |b| sem::mult(b, rs, rt)).map(|()| none),
        Insn::Multu => step(env, in_slot, |b| sem::multu(b, rs, rt)).map(|()| none),
        Insn::Div => step(env, in_slot, |b| sem::div(b, rs, rt)).map(|()| none),
        Insn::Divu => step(env, in_slot, |b| sem::divu(b, rs, rt)).map(|()| none),
        Insn::Mfhi => step(env, in_slot, |b| sem::mfhi(b, rd)).map(|()| wrote(rd)),
        Insn::Mflo => step(env, in_slot, |b| sem::mflo(b, rd)).map(|()| wrote(rd)),
        Insn::Mthi => step(env, in_slot, |b| sem::mthi(b, rs)).map(|()| none),
        Insn::Mtlo => step(env, in_slot, |b| sem::mtlo(b, rs)).map(|()| none),
        Insn::Lw => load_word(env, rt, rs, imm, model, in_slot),
        Insn::Lb => load_gpr(env, rt, model, in_slot, |b| {
            sem::lb(b, rt, rs, imm, model.endian)
        }),
        Insn::Lbu => load_gpr(env, rt, model, in_slot, |b| {
            sem::lbu(b, rt, rs, imm, model.endian)
        }),
        Insn::Lh => load_gpr(env, rt, model, in_slot, |b| {
            sem::lh(b, rt, rs, imm, model.endian)
        }),
        Insn::Lhu => load_gpr(env, rt, model, in_slot, |b| {
            sem::lhu(b, rt, rs, imm, model.endian)
        }),
        Insn::Lwl => load_gpr(env, rt, model, in_slot, |b| {
            sem::lwl(b, rt, rs, imm, model.endian)
        }),
        Insn::Lwr => load_gpr(env, rt, model, in_slot, |b| {
            sem::lwr(b, rt, rs, imm, model.endian)
        }),
        Insn::Sw => step(env, in_slot, |b| {
            sem::sw_endian(b, rt, rs, imm, model.endian)
        })
        .map(|()| none),
        Insn::Sb => step(env, in_slot, |b| sem::sb(b, rt, rs, imm, model.endian)).map(|()| none),
        Insn::Sh => step(env, in_slot, |b| sem::sh(b, rt, rs, imm, model.endian)).map(|()| none),
        Insn::Swl => step(env, in_slot, |b| sem::swl(b, rt, rs, imm, model.endian)).map(|()| none),
        Insn::Swr => step(env, in_slot, |b| sem::swr(b, rt, rs, imm, model.endian)).map(|()| none),
        Insn::Beq => step(env, in_slot, |b| sem::beq_delay(b, rs, rt, pc, imm)).map(|()| none),
        Insn::Bne => step(env, in_slot, |b| sem::bne_delay(b, rs, rt, pc, imm)).map(|()| none),
        Insn::Blez => step(env, in_slot, |b| sem::blez_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bgtz => step(env, in_slot, |b| sem::bgtz_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bltz => step(env, in_slot, |b| sem::bltz_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bgez => step(env, in_slot, |b| sem::bgez_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bltzal => {
            step(env, in_slot, |b| sem::bltzal_delay(b, rs, pc, imm)).map(|()| wrote(Gpr(31)))
        }
        Insn::Beql => step(env, in_slot, |b| sem::beql_delay(b, rs, rt, pc, imm)).map(|()| none),
        Insn::Bnel => step(env, in_slot, |b| sem::bnel_delay(b, rs, rt, pc, imm)).map(|()| none),
        Insn::Blezl => step(env, in_slot, |b| sem::blezl_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bgtzl => step(env, in_slot, |b| sem::bgtzl_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bltzl => step(env, in_slot, |b| sem::bltzl_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bgezl => step(env, in_slot, |b| sem::bgezl_delay(b, rs, pc, imm)).map(|()| none),
        Insn::Bltzall => {
            step(env, in_slot, |b| sem::bltzall_delay(b, rs, pc, imm)).map(|()| wrote(Gpr(31)))
        }
        Insn::Bgezall => {
            step(env, in_slot, |b| sem::bgezall_delay(b, rs, pc, imm)).map(|()| wrote(Gpr(31)))
        }
        Insn::Bgezal => {
            step(env, in_slot, |b| sem::bgezal_delay(b, rs, pc, imm)).map(|()| wrote(Gpr(31)))
        }
        Insn::J => {
            let target = j_target(pc, word, model.is64);
            step(env, in_slot, |b| sem::j_delay(b, target)).map(|()| none)
        }
        Insn::Jal => {
            let target = j_target(pc, word, model.is64);
            step(env, in_slot, |b| sem::jal_delay(b, pc, target)).map(|()| wrote(Gpr(31)))
        }
        Insn::Jr => step(env, in_slot, |b| sem::jr_delay(b, rs, model.is64)).map(|()| none),
        Insn::Jalr => {
            step(env, in_slot, |b| sem::jalr_delay(b, rd, rs, pc, model.is64)).map(|()| wrote(rd))
        }
        Insn::Syscall => step(env, in_slot, sem::syscall).map(|()| none),
        Insn::Break => step(env, in_slot, sem::break_).map(|()| none),
        Insn::Beqzalc => {
            step(env, in_slot, |b| sem::beqzalc(b, rs, rt, pc, imm)).map(|()| Effect {
                wrote: Some(31),
                delayed: None,
            })
        }
        // ---- MIPS32r2 ----
        Insn::Movz => step(env, in_slot, |b| sem::movz(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Movn => step(env, in_slot, |b| sem::movn(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Teq => step(env, in_slot, |b| sem::teq(b, rs, rt)).map(|()| none),
        Insn::Sync => step(env, in_slot, sem::sync).map(|()| none),
        Insn::Pref => step(env, in_slot, sem::pref).map(|()| none),
        Insn::Seb => step(env, in_slot, |b| sem::seb(b, rd, rt)).map(|()| wrote(rd)),
        Insn::Seh => step(env, in_slot, |b| sem::seh(b, rd, rt)).map(|()| wrote(rd)),
        Insn::Wsbh => step(env, in_slot, |b| sem::wsbh(b, rd, rt)).map(|()| wrote(rd)),
        Insn::Ext => step(env, in_slot, |b| {
            sem::ext(b, rt, rs, shamt, field_u(word, 11))
        })
        .map(|()| wrote(rt)),
        Insn::Ins => step(env, in_slot, |b| {
            sem::ins(b, rt, rs, shamt, field_u(word, 11))
        })
        .map(|()| wrote(rt)),
        Insn::Rdhwr => step(env, in_slot, |b| sem::rdhwr(b, rt, rd.0.into())).map(|()| wrote(rt)),
        Insn::Ll => load_gpr(env, rt, model, in_slot, |b| {
            sem::ll(b, rt, rs, imm, model.endian)
        }),
        Insn::Sc => {
            step(env, in_slot, |b| sem::sc(b, rt, rs, imm, model.endian)).map(|()| wrote(rt))
        }
        Insn::MulR2 => step(env, in_slot, |b| sem::mul(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Madd => step(env, in_slot, |b| sem::madd(b, rs, rt)).map(|()| none),
        Insn::Maddu => step(env, in_slot, |b| sem::maddu(b, rs, rt)).map(|()| none),
        Insn::Msub => step(env, in_slot, |b| sem::msub(b, rs, rt)).map(|()| none),
        Insn::Msubu => step(env, in_slot, |b| sem::msubu(b, rs, rt)).map(|()| none),
        Insn::ClzR2 => step(env, in_slot, |b| sem::clz(b, rd, rs)).map(|()| wrote(rd)),
        Insn::CloR2 => step(env, in_slot, |b| sem::clo(b, rd, rs)).map(|()| wrote(rd)),
        // ---- MIPS64 ----
        Insn::Daddu => step(env, in_slot, |b| sem::daddu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Dsubu => step(env, in_slot, |b| sem::dsubu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Dadd => step(env, in_slot, |b| sem::dadd(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Dsub => step(env, in_slot, |b| sem::dsub(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Daddiu => step(env, in_slot, |b| sem::daddiu(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Daddi => step(env, in_slot, |b| sem::daddi(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Dmult => step(env, in_slot, |b| sem::dmult(b, rs, rt)).map(|()| none),
        Insn::Dmultu => step(env, in_slot, |b| sem::dmultu(b, rs, rt)).map(|()| none),
        Insn::Ddiv => step(env, in_slot, |b| sem::ddiv(b, rs, rt)).map(|()| none),
        Insn::Ddivu => step(env, in_slot, |b| sem::ddivu(b, rs, rt)).map(|()| none),
        Insn::Dsll => step(env, in_slot, |b| sem::dsll(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Dsrl => step(env, in_slot, |b| sem::dsrl(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Dsra => step(env, in_slot, |b| sem::dsra(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Dsll32 => step(env, in_slot, |b| sem::dsll32(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Dsrl32 => step(env, in_slot, |b| sem::dsrl32(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Dsra32 => step(env, in_slot, |b| sem::dsra32(b, rd, rt, shamt)).map(|()| wrote(rd)),
        Insn::Dsllv => step(env, in_slot, |b| sem::dsllv(b, rd, rt, rs)).map(|()| wrote(rd)),
        Insn::Dsrlv => step(env, in_slot, |b| sem::dsrlv(b, rd, rt, rs)).map(|()| wrote(rd)),
        Insn::Dsrav => step(env, in_slot, |b| sem::dsrav(b, rd, rt, rs)).map(|()| wrote(rd)),
        Insn::Ld => load_gpr(env, rt, model, in_slot, |b| {
            sem::ld(b, rt, rs, imm, model.endian)
        }),
        Insn::Lwu => load_gpr(env, rt, model, in_slot, |b| {
            sem::lwu(b, rt, rs, imm, model.endian)
        }),
        Insn::Lld => load_gpr(env, rt, model, in_slot, |b| {
            sem::lld(b, rt, rs, imm, model.endian)
        }),
        Insn::Sd => step(env, in_slot, |b| sem::sd(b, rt, rs, imm, model.endian)).map(|()| none),
        Insn::Scd => {
            step(env, in_slot, |b| sem::scd(b, rt, rs, imm, model.endian)).map(|()| wrote(rt))
        }
        Insn::Ldl => load_gpr(env, rt, model, in_slot, |b| {
            sem::ldl(b, rt, rs, imm, model.endian)
        }),
        Insn::Ldr => load_gpr(env, rt, model, in_slot, |b| {
            sem::ldr(b, rt, rs, imm, model.endian)
        }),
        Insn::Sdl => step(env, in_slot, |b| sem::sdl(b, rt, rs, imm, model.endian)).map(|()| none),
        Insn::Sdr => step(env, in_slot, |b| sem::sdr(b, rt, rs, imm, model.endian)).map(|()| none),
        Insn::Dext => step(env, in_slot, |b| {
            sem::dext(b, rt, rs, shamt, field_u(word, 11))
        })
        .map(|()| wrote(rt)),
        Insn::Dextm => step(env, in_slot, |b| {
            sem::dext(b, rt, rs, shamt, field_u(word, 11) + 32)
        })
        .map(|()| wrote(rt)),
        Insn::Dextu => step(env, in_slot, |b| {
            sem::dext(b, rt, rs, shamt + 32, field_u(word, 11))
        })
        .map(|()| wrote(rt)),
        Insn::Dins => step(env, in_slot, |b| {
            sem::dins(b, rt, rs, shamt, field_u(word, 11))
        })
        .map(|()| wrote(rt)),
        Insn::Dinsm => step(env, in_slot, |b| {
            sem::dins(b, rt, rs, shamt, field_u(word, 11) + 32)
        })
        .map(|()| wrote(rt)),
        Insn::Dinsu => step(env, in_slot, |b| {
            sem::dins(b, rt, rs, shamt + 32, field_u(word, 11))
        })
        .map(|()| wrote(rt)),
        Insn::DclzR2 | Insn::Dclz => {
            step(env, in_slot, |b| sem::dclz(b, rd, rs)).map(|()| wrote(rd))
        }
        Insn::DcloR2 | Insn::Dclo => {
            step(env, in_slot, |b| sem::dclo(b, rd, rs)).map(|()| wrote(rd))
        }
        Insn::Dsbh => step(env, in_slot, |b| sem::dsbh(b, rd, rt)).map(|()| wrote(rd)),
        Insn::Dshd => step(env, in_slot, |b| sem::dshd(b, rd, rt)).map(|()| wrote(rd)),
        // ---- Release 6 ----
        Insn::Seleqz => step(env, in_slot, |b| sem::seleqz(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Selnez => step(env, in_slot, |b| sem::selnez(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Mul | Insn::Mulu => {
            step(env, in_slot, |b| sem::mul(b, rd, rs, rt)).map(|()| wrote(rd))
        }
        Insn::Muh => step(env, in_slot, |b| sem::muh(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Muhu => step(env, in_slot, |b| sem::muhu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::DivR6 => step(env, in_slot, |b| sem::div_r6(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Mod => step(env, in_slot, |b| sem::mod_(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::DivuR6 => step(env, in_slot, |b| sem::divu_r6(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Modu => step(env, in_slot, |b| sem::modu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Dmul | Insn::Dmulu => {
            step(env, in_slot, |b| sem::dmul(b, rd, rs, rt)).map(|()| wrote(rd))
        }
        Insn::Dmuh => step(env, in_slot, |b| sem::dmuh(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Dmuhu => step(env, in_slot, |b| sem::dmuhu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::DdivR6 => step(env, in_slot, |b| sem::ddiv_r6(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Dmod => step(env, in_slot, |b| sem::dmod(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::DdivuR6 => step(env, in_slot, |b| sem::ddivu_r6(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Dmodu => step(env, in_slot, |b| sem::dmodu(b, rd, rs, rt)).map(|()| wrote(rd)),
        Insn::Lsa => {
            step(env, in_slot, |b| sem::lsa(b, rd, rs, rt, (shamt & 3) + 1)).map(|()| wrote(rd))
        }
        Insn::Dlsa => {
            step(env, in_slot, |b| sem::dlsa(b, rd, rs, rt, (shamt & 3) + 1)).map(|()| wrote(rd))
        }
        Insn::Clz => step(env, in_slot, |b| sem::clz(b, rd, rs)).map(|()| wrote(rd)),
        Insn::Clo => step(env, in_slot, |b| sem::clo(b, rd, rs)).map(|()| wrote(rd)),
        Insn::Auipc => step(env, in_slot, |b| sem::auipc(b, rs, imm, pc)).map(|()| wrote(rs)),
        Insn::Aluipc => step(env, in_slot, |b| sem::aluipc(b, rs, imm, pc)).map(|()| wrote(rs)),
        Insn::Addiupc => {
            let imm19 = sext_bits(word, 19);
            step(env, in_slot, |b| sem::addiupc(b, rs, imm19, pc)).map(|()| wrote(rs))
        }
        Insn::Lwpc => {
            let imm19 = word & 0x7_ffff;
            load_gpr(env, rs, model, in_slot, |b| {
                sem::lwpc(b, rs, imm19, model.endian, pc)
            })
        }
        Insn::Lwupc => {
            let imm19 = word & 0x7_ffff;
            load_gpr(env, rs, model, in_slot, |b| {
                sem::lwupc(b, rs, imm19, model.endian, pc)
            })
        }
        Insn::Ldpc => {
            let imm18 = word & 0x3_ffff;
            load_gpr(env, rs, model, in_slot, |b| {
                sem::ldpc(b, rs, imm18, model.endian, pc)
            })
        }
        Insn::Bitswap => step(env, in_slot, |b| sem::bitswap(b, rd, rt)).map(|()| wrote(rd)),
        Insn::Dbitswap => step(env, in_slot, |b| sem::dbitswap(b, rd, rt)).map(|()| wrote(rd)),
        Insn::Align => {
            step(env, in_slot, |b| sem::align(b, rd, rs, rt, shamt & 3)).map(|()| wrote(rd))
        }
        Insn::Dalign => {
            step(env, in_slot, |b| sem::dalign(b, rd, rs, rt, shamt & 7)).map(|()| wrote(rd))
        }
        Insn::Bc => {
            let target = pc
                .wrapping_add(4)
                .wrapping_add(((sext_bits(word, 26) as i64) << 2) as u64);
            step(env, in_slot, |b| sem::bc(b, target)).map(|()| none)
        }
        Insn::Balc => {
            let target = pc
                .wrapping_add(4)
                .wrapping_add(((sext_bits(word, 26) as i64) << 2) as u64);
            step(env, in_slot, |b| sem::balc(b, pc, target)).map(|()| wrote(Gpr(31)))
        }
        Insn::Jic => step(env, in_slot, |b| sem::jic(b, rs, imm)).map(|()| none),
        Insn::Jialc => step(env, in_slot, |b| sem::jialc(b, rs, pc, imm)).map(|()| wrote(Gpr(31))),
        Insn::Beqzc => {
            let target = pc
                .wrapping_add(4)
                .wrapping_add(((sext_bits(word, 21) as i64) << 2) as u64);
            step(env, in_slot, |b| sem::beqzc(b, rs, pc, target)).map(|()| none)
        }
        Insn::Bnezc => {
            let target = pc
                .wrapping_add(4)
                .wrapping_add(((sext_bits(word, 21) as i64) << 2) as u64);
            step(env, in_slot, |b| sem::bnezc(b, rs, pc, target)).map(|()| none)
        }
        // ---- R6 のコンパクト分岐（imm16 << 2 の pc 相対）----
        Insn::Bovc
        | Insn::Bnvc
        | Insn::Beqc
        | Insn::Bnec
        | Insn::Bgeuc
        | Insn::Bltuc
        | Insn::Bgec
        | Insn::Bltc
        | Insn::Blezalc
        | Insn::Bnezalc
        | Insn::Bgezalc
        | Insn::Bltzalc
        | Insn::Bgtzalc
        | Insn::Blezc
        | Insn::Bgtzc
        | Insn::Bgezc
        | Insn::Bltzc => {
            let target = pc.wrapping_add(4).wrapping_add(((imm as i64) << 2) as u64);
            let link = matches!(
                insn,
                Insn::Blezalc | Insn::Bnezalc | Insn::Bgezalc | Insn::Bltzalc | Insn::Bgtzalc
            );
            step(env, in_slot, |b| match insn {
                Insn::Bovc => sem::bovc(b, rs, rt, pc, target),
                Insn::Bnvc => sem::bnvc(b, rs, rt, pc, target),
                Insn::Beqc => sem::beqc(b, rs, rt, pc, target),
                Insn::Bnec => sem::bnec(b, rs, rt, pc, target),
                Insn::Bgeuc => sem::bgeuc(b, rs, rt, pc, target),
                Insn::Bltuc => sem::bltuc(b, rs, rt, pc, target),
                Insn::Bgec => sem::bgec(b, rs, rt, pc, target),
                Insn::Bltc => sem::bltc(b, rs, rt, pc, target),
                Insn::Blezalc => sem::blezalc(b, rt, pc, target),
                Insn::Bnezalc => sem::bnezalc(b, rt, pc, target),
                Insn::Bgezalc => sem::bgezalc(b, rt, pc, target),
                Insn::Bltzalc => sem::bltzalc(b, rt, pc, target),
                Insn::Bgtzalc => sem::bgtzalc(b, rt, pc, target),
                Insn::Blezc => sem::blezc(b, rt, pc, target),
                Insn::Bgtzc => sem::bgtzc(b, rt, pc, target),
                Insn::Bgezc => sem::bgezc(b, rt, pc, target),
                Insn::Bltzc => sem::bltzc(b, rt, pc, target),
                _ => unreachable!("compact branch arm"),
            })
            .map(|()| Effect {
                wrote: if link { Some(31) } else { None },
                delayed: None,
            })
        }
        // ---- R6 の SPECIAL3 LL/SC と REGIMM 系、上位即値 ----
        Insn::LlR6 => {
            let off = sext_bits(word >> 7, 9);
            load_gpr(env, rt, model, in_slot, |b| {
                sem::ll(b, rt, rs, off, model.endian)
            })
        }
        Insn::ScR6 => {
            let off = sext_bits(word >> 7, 9);
            step(env, in_slot, |b| sem::sc(b, rt, rs, off, model.endian)).map(|()| wrote(rt))
        }
        Insn::LldR6 => {
            let off = sext_bits(word >> 7, 9);
            load_gpr(env, rt, model, in_slot, |b| {
                sem::lld(b, rt, rs, off, model.endian)
            })
        }
        Insn::ScdR6 => {
            let off = sext_bits(word >> 7, 9);
            step(env, in_slot, |b| sem::scd(b, rt, rs, off, model.endian)).map(|()| wrote(rt))
        }
        Insn::Lle => {
            let off = sext_bits(word >> 7, 9);
            load_gpr(env, rt, model, in_slot, |b| {
                sem::lle(b, rt, rs, off, model.endian)
            })
        }
        Insn::Sce => {
            let off = sext_bits(word >> 7, 9);
            step(env, in_slot, |b| sem::sce(b, rt, rs, off, model.endian)).map(|()| wrote(rt))
        }
        // llwp/llwpe は R6 専用（ロード遅延を持つモデルでは復号しない）。
        // rt と rd の両方に書くが、遅延追跡が要るのは rt 側だけで足りる。
        Insn::Llwp | Insn::Llwpe => load_gpr(env, rt, model, in_slot, |b| {
            sem::llwp(b, rt, rd, rs, model.endian)
        }),
        Insn::Scwp | Insn::Scwpe => {
            step(env, in_slot, |b| sem::scwp(b, rt, rd, rs, model.endian)).map(|()| wrote(rt))
        }
        Insn::Lwc1 => step(env, in_slot, |b| {
            sem::lwc1(b, rt.0, rs, imm, model.endian, false)
        })
        .map(|()| none),
        Insn::Swc1 => step(env, in_slot, |b| {
            sem::swc1(b, rt.0, rs, imm, model.endian, false)
        })
        .map(|()| none),
        Insn::Ldc1 => step(env, in_slot, |b| {
            sem::lwc1(b, rt.0, rs, imm, model.endian, true)
        })
        .map(|()| none),
        Insn::Sdc1 => step(env, in_slot, |b| {
            sem::swc1(b, rt.0, rs, imm, model.endian, true)
        })
        .map(|()| none),
        Insn::Lwxc1 => step(env, in_slot, |b| {
            sem::lwxc1(b, rd.0, rs, rt, model.endian, false, false)
        })
        .map(|()| none),
        Insn::Ldxc1 => step(env, in_slot, |b| {
            sem::lwxc1(b, rd.0, rs, rt, model.endian, true, false)
        })
        .map(|()| none),
        Insn::Swxc1 => step(env, in_slot, |b| {
            sem::lwxc1(b, rd.0, rs, rt, model.endian, false, true)
        })
        .map(|()| none),
        Insn::Sdxc1 => step(env, in_slot, |b| {
            sem::lwxc1(b, rd.0, rs, rt, model.endian, true, true)
        })
        .map(|()| none),
        Insn::Mfc1 => step(env, in_slot, |b| sem::mfc1(b, rt, rd.0, false)).map(|()| wrote(rt)),
        Insn::Dmfc1 => step(env, in_slot, |b| sem::mfc1(b, rt, rd.0, true)).map(|()| wrote(rt)),
        Insn::Mtc1 => step(env, in_slot, |b| sem::mtc1(b, rt, rd.0, false)).map(|()| none),
        Insn::Dmtc1 => step(env, in_slot, |b| sem::mtc1(b, rt, rd.0, true)).map(|()| none),
        Insn::Mfhc1 => step(env, in_slot, |b| sem::mfhc1(b, rt, rd.0, false)).map(|()| wrote(rt)),
        Insn::Mthc1 => step(env, in_slot, |b| sem::mfhc1(b, rt, rd.0, true)).map(|()| none),
        Insn::Cfc1 => step(env, in_slot, |b| sem::cfc1(b, rt, rd.0)).map(|()| wrote(rt)),
        Insn::Ctc1 => step(env, in_slot, |b| sem::ctc1(b, rt, rd.0)).map(|()| none),
        Insn::Bc1f | Insn::Bc1t | Insn::Bc1fl | Insn::Bc1tl => {
            let cc = ((word >> 18) & 7) as u8;
            let tf = (word >> 16) & 1 != 0;
            let nd = (word >> 17) & 1 != 0;
            step(env, in_slot, |b| sem::bc1_delay(b, pc, imm, cc, tf, nd)).map(|()| none)
        }
        Insn::AddS => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 0, false)).map(|()| none),
        Insn::SubS => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 1, false)).map(|()| none),
        Insn::MulS => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 2, false)).map(|()| none),
        Insn::DivS => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 3, false)).map(|()| none),
        Insn::AddD => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 0, true)).map(|()| none),
        Insn::SubD => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 1, true)).map(|()| none),
        Insn::MulD => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 2, true)).map(|()| none),
        Insn::DivD => step(env, in_slot, |b| sem::fp3(b, fd, fs, ft, 3, true)).map(|()| none),
        Insn::SqrtS => step(env, in_slot, |b| sem::fp1(b, fd, fs, 4, false)).map(|()| none),
        Insn::SqrtD => step(env, in_slot, |b| sem::fp1(b, fd, fs, 4, true)).map(|()| none),
        Insn::AbsS => step(env, in_slot, |b| sem::fp1(b, fd, fs, 5, false)).map(|()| none),
        Insn::AbsD => step(env, in_slot, |b| sem::fp1(b, fd, fs, 5, true)).map(|()| none),
        Insn::MovS => step(env, in_slot, |b| sem::fp1(b, fd, fs, 6, false)).map(|()| none),
        Insn::MovD => step(env, in_slot, |b| sem::fp1(b, fd, fs, 6, true)).map(|()| none),
        Insn::NegS => step(env, in_slot, |b| sem::fp1(b, fd, fs, 7, false)).map(|()| none),
        Insn::NegD => step(env, in_slot, |b| sem::fp1(b, fd, fs, 7, true)).map(|()| none),
        Insn::RecipS => step(env, in_slot, |b| sem::fp1(b, fd, fs, 0x15, false)).map(|()| none),
        Insn::RecipD => step(env, in_slot, |b| sem::fp1(b, fd, fs, 0x15, true)).map(|()| none),
        Insn::RsqrtS => step(env, in_slot, |b| sem::fp1(b, fd, fs, 0x16, false)).map(|()| none),
        Insn::RsqrtD => step(env, in_slot, |b| sem::fp1(b, fd, fs, 0x16, true)).map(|()| none),
        Insn::RoundWS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 0, false, false)).map(|()| none)
        }
        Insn::TruncWS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 1, false, false)).map(|()| none)
        }
        Insn::CeilWS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 2, false, false)).map(|()| none)
        }
        Insn::FloorWS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 3, false, false)).map(|()| none)
        }
        Insn::RoundWD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 0, true, false)).map(|()| none)
        }
        Insn::TruncWD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 1, true, false)).map(|()| none)
        }
        Insn::CeilWD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 2, true, false)).map(|()| none)
        }
        Insn::FloorWD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 3, true, false)).map(|()| none)
        }
        Insn::RoundLS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 0, false, true)).map(|()| none)
        }
        Insn::TruncLS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 1, false, true)).map(|()| none)
        }
        Insn::CeilLS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 2, false, true)).map(|()| none)
        }
        Insn::FloorLS => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 3, false, true)).map(|()| none)
        }
        Insn::RoundLD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 0, true, true)).map(|()| none)
        }
        Insn::TruncLD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 1, true, true)).map(|()| none)
        }
        Insn::CeilLD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 2, true, true)).map(|()| none)
        }
        Insn::FloorLD => {
            step(env, in_slot, |b| sem::fp_round(b, fd, fs, 3, true, true)).map(|()| none)
        }
        Insn::MovcfS | Insn::MovcfD => {
            let cc = ((word >> 18) & 7) as u8;
            let tf = (word >> 16) & 1 != 0;
            let dbl = insn == Insn::MovcfD;
            step(env, in_slot, |b| {
                sem::fp_movc(b, fd, fs, cc, tf, rt, dbl, true)
            })
            .map(|()| none)
        }
        Insn::MovzS | Insn::MovnS | Insn::MovzD | Insn::MovnD => {
            let tf = matches!(insn, Insn::MovnS | Insn::MovnD);
            let dbl = matches!(insn, Insn::MovzD | Insn::MovnD);
            step(env, in_slot, |b| {
                sem::fp_movc(b, fd, fs, 0, tf, rt, dbl, false)
            })
            .map(|()| none)
        }
        Insn::CcondS => step(env, in_slot, |b| {
            sem::fp_cond(
                b,
                fs,
                ft,
                (word & 0xf) as u8,
                ((word >> 8) & 7) as u8,
                false,
            )
        })
        .map(|()| none),
        Insn::CcondD => step(env, in_slot, |b| {
            sem::fp_cond(b, fs, ft, (word & 0xf) as u8, ((word >> 8) & 7) as u8, true)
        })
        .map(|()| none),
        Insn::CvtSD
        | Insn::CvtSW
        | Insn::CvtSL
        | Insn::CvtDS
        | Insn::CvtDW
        | Insn::CvtDL
        | Insn::CvtWS
        | Insn::CvtWD
        | Insn::CvtWL
        | Insn::CvtLS
        | Insn::CvtLD
        | Insn::CvtLW => {
            let (src, dst) = match insn {
                Insn::CvtSD => (1, 0),
                Insn::CvtSW => (2, 0),
                Insn::CvtSL => (3, 0),
                Insn::CvtDS => (0, 1),
                Insn::CvtDW => (2, 1),
                Insn::CvtDL => (3, 1),
                Insn::CvtWS => (0, 2),
                Insn::CvtWD => (1, 2),
                Insn::CvtWL => (3, 2),
                Insn::CvtLS => (0, 3),
                Insn::CvtLD => (1, 3),
                Insn::CvtLW => (2, 3),
                _ => (0, 0),
            };
            let rm = (get_u64(env, sem::fcsr_ref().offset()) & 3) as u8;
            step(env, in_slot, |b| sem::fp_cvt(b, fd, fs, dst, src, rm)).map(|()| none)
        }
        Insn::MaddS
        | Insn::MaddD
        | Insn::MsubS
        | Insn::MsubD
        | Insn::NmaddS
        | Insn::NmaddD
        | Insn::NmsubS
        | Insn::NmsubD => {
            let dbl = matches!(
                insn,
                Insn::MaddD | Insn::MsubD | Insn::NmaddD | Insn::NmsubD
            );
            let sub = matches!(
                insn,
                Insn::MsubS | Insn::MsubD | Insn::NmsubS | Insn::NmsubD
            );
            let neg = matches!(
                insn,
                Insn::NmaddS | Insn::NmaddD | Insn::NmsubS | Insn::NmsubD
            );
            let fr = ((word >> 11) & 31) as u8;
            let fdst = ((word >> 6) & 31) as u8;
            step(env, in_slot, |b| {
                sem::fp_madd(b, fdst, fr, rs.0, rt.0, dbl, sub, neg)
            })
            .map(|()| none)
        }
        Insn::Nal => step(env, in_slot, |b| sem::nal(b, pc)).map(|()| wrote(Gpr(31))),
        Insn::Bal => step(env, in_slot, |b| sem::bal_delay(b, pc, imm)).map(|()| wrote(Gpr(31))),
        Insn::Dahi => step(env, in_slot, |b| sem::dahi(b, rs, imm)).map(|()| wrote(rs)),
        Insn::Dati => step(env, in_slot, |b| sem::dati(b, rs, imm)).map(|()| wrote(rs)),
        Insn::Aui => step(env, in_slot, |b| sem::aui(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Daui => step(env, in_slot, |b| sem::daui(b, rt, rs, imm)).map(|()| wrote(rt)),
        Insn::Synci => step(env, in_slot, |b| sem::synci(b, rs, imm)).map(|()| none),
    }
}

fn field_u(word: u32, shift: u32) -> u32 {
    (word >> shift) & 31
}

fn sext_bits(word: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((word << shift) as i32) >> shift
}

fn load_word(
    env: &mut BareEnv,
    rt: Gpr,
    rs: Gpr,
    imm: i32,
    model: MipsModel,
    in_slot: bool,
) -> Result<Effect, Stop> {
    load_gpr(env, rt, model, in_slot, |b| {
        sem::lw_endian(b, rt, rs, imm, model.endian)
    })
}

fn load_gpr<F>(
    env: &mut BareEnv,
    rt: Gpr,
    model: MipsModel,
    in_slot: bool,
    f: F,
) -> Result<Effect, Stop>
where
    F: FnOnce(&mut polyisa_engine::interp::InterpBackend) -> Result<(), InterpExit>,
{
    let old = reg(env, rt.0);
    step(env, in_slot, f)?;
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
            if std::env::var_os("POLYISA_MIPS_TRACE").is_some() {
                let pc = get_u64(env, sem::pc_ref().offset());
                eprintln!(
                    "exc {:?} addr={:?} slot={in_slot} pc={pc:#x}",
                    exception.kind, exception.addr
                );
                for r in 0u8..32 {
                    let v = get_u64(env, Gpr(r).state().offset());
                    eprintln!("  r{r}={v:#x}");
                }
                if let Some(a) = exception.addr {
                    let base = a & !0xfff;
                    for d in -4i64..4 {
                        let p = base.wrapping_add_signed(d * 0x1000);
                        eprintln!(
                            "  map {p:#x}: {}",
                            env.backend.mem.is_mapped(polyisa_mem::PageNo(p >> 12))
                        );
                    }
                }
            }
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

fn release_pending(
    env: &mut BareEnv,
    pending: Option<(u8, u64)>,
    keep: &[u8],
) -> Option<(u8, u64)> {
    if let Some((reg, value)) = pending
        && !keep.contains(&reg)
    {
        set_reg(env, reg, value);
    }
    None
}

fn j_target(pc: u64, word: u32, is64: bool) -> u64 {
    // J 型の飛び先は遅延スロットの PC 上位と instr_index<<2 の合成。
    // 32 ビットは (PC+4)[31:28]、64 ビットは (PC+4)[63:28] を使う。
    let region = if is64 {
        pc.wrapping_add(4) & !0x0fff_ffff
    } else {
        pc.wrapping_add(4) & 0xf000_0000
    };
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
    )
}

/// 静的な MIPS ELF を実行する。機械番号 8。モデルは `e_flags` のアーキテクチャとエンディアンから選ぶ。
pub fn run_elf_mips(path: &str, _argv: &[String]) -> Result<u64, String> {
    run_elf_mips_sel(path, _argv, None)
}

/// `run_elf_mips` に CPU モデルの選択を渡す（`--cpu` の配線）。
/// モデルは生成した `MODEL_DEFS` の名前で決め、ロード遅延の有無は
/// モデル名から取る。エンディアンは ELF のヘッダと一致させる。
pub fn run_elf_mips_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let class64 = match bytes.get(4) {
        Some(1) => false,
        Some(2) => true,
        _ => return Err("ehdr: 不明な EI_CLASS".to_string()),
    };
    let ehdr = if class64 {
        polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?
    } else {
        polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?
    };
    let model = match sel {
        Some(s) => {
            let (load_delay, is64) = match s.name.as_str() {
                "r3000" => (true, false),
                "mips32r2" | "r6" => (false, false),
                "mips64r2" | "mips64r6" => (false, true),
                name => return Err(format!("mips のモデル {name} は実行できない")),
            };
            MipsModel {
                feats: s.feats,
                endian: if ehdr.little { Endian::Le } else { Endian::Be },
                load_delay,
                is64,
            }
        }
        None => model_from_flags(ehdr.little, ehdr.flags)?,
    };
    run_loaded(&bytes, &ehdr, class64, model, path, argv)
}

/// ELF のクラスと `e_flags` からゲスト ABI を決める。
/// ELFCLASS64 は n64、ELFCLASS32 + EF_MIPS_ABI2 (0x20) は n32、それ以外は o32。
/// Ref: SPEC-MIPS-ABI（o32）と SRC-LINUX (7.3) の `arch/mips/kernel/elf.c`。
fn abi_from_elf(class64: bool, flags: u32) -> Result<polyisa_os_linux::mips::sys::Abi, String> {
    const EF_MIPS_ABI2: u32 = 0x20;
    // EF_MIPS_ABI マスク: o32=0x1000, o64=0x2000, eabi32=0x3000, eabi64=0x4000。
    // Ref: SRC-LINUX (7.3) と binutils elf/mips.h。
    match flags & 0xf000 {
        0x0000 | 0x1000 => {}
        abi => {
            return Err(format!("未対応の MIPS ABI フラグ: {abi:#x}"));
        }
    }
    Ok(if class64 {
        polyisa_os_linux::mips::sys::Abi::N64
    } else if flags & EF_MIPS_ABI2 != 0 {
        polyisa_os_linux::mips::sys::Abi::N32
    } else {
        polyisa_os_linux::mips::sys::Abi::O32
    })
}

/// `e_flags` の EF_MIPS_ARCH とエンディアンから CPU モデルを決める。
/// 値は binutils `include/elf/mips.h`（LLVM `BinaryFormat/ELF.h` と同じ）:
/// 0=MIPS1, 1-4=MIPS2/3/4/5, 5=MIPS32, 6=MIPS64, 7=MIPS32r2,
/// 8=MIPS64r2, 9=MIPS32r6, a=MIPS64r6。
/// Ref: SRC-LINUX (7.3)。
fn model_from_flags(little: bool, flags: u32) -> Result<MipsModel, String> {
    let arch = flags & 0xf000_0000;
    let mut model = match arch {
        0x0000_0000 => MipsModel::mips1_be(),
        // MIPS II は ll/sc まで入る 32 ビット拡張。r2 モデルで代用する。
        0x1000_0000 => MipsModel::mips32r2(),
        // MIPS III/IV/V は 64 ビット ISA の祖先。MIPS64r2 の下位集合なので
        // r2 モデルで代用する（r2 は上位互換）。
        0x2000_0000 | 0x3000_0000 | 0x4000_0000 => MipsModel::mips64r2(),
        // MIPS32/MIPS64 の r1 は r2 モデルで代用する（r2 は上位互換）。
        0x5000_0000 | 0x7000_0000 => MipsModel::mips32r2(),
        0x6000_0000 | 0x8000_0000 => MipsModel::mips64r2(),
        0x9000_0000 => MipsModel::r6(),
        0xa000_0000 => MipsModel::mips64r6(),
        _ => {
            return Err(format!("未対応の MIPS アーキテクチャフラグ: {arch:#x}"));
        }
    };
    model.endian = if little { Endian::Le } else { Endian::Be };
    Ok(model)
}

/// モデルを指定して静的な MIPS ELF を実行する。エンディアンはヘッダと一致させる。
pub fn run_elf_model(
    path: &str,
    model: MipsModel,
    sys: &mut polyisa_os_linux::mips::sys::Linux,
) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let class64 = matches!(bytes.get(4), Some(2));
    let ehdr = if class64 {
        polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?
    } else {
        polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?
    };
    run_loaded_sys(&bytes, &ehdr, class64, model, sys, path, &[])
}

fn run_loaded(
    bytes: &[u8],
    ehdr: &polyisa_loader::elf::Ehdr,
    class64: bool,
    model: MipsModel,
    prog: &str,
    argv: &[String],
) -> Result<u64, String> {
    let abi = abi_from_elf(class64, ehdr.flags)?;
    let is64abi = !matches!(abi, polyisa_os_linux::mips::sys::Abi::O32);
    if is64abi && !model.is64 {
        return Err("n32/n64 の ELF には 64 ビットモデルが要る".to_string());
    }
    let mut sys = polyisa_os_linux::mips::sys::Linux::new(abi, model.endian);
    sys.exe_path = String::new();
    run_loaded_sys(bytes, ehdr, class64, model, &mut sys, prog, argv)
}

fn run_loaded_sys(
    bytes: &[u8],
    ehdr: &polyisa_loader::elf::Ehdr,
    class64: bool,
    model: MipsModel,
    sys: &mut polyisa_os_linux::mips::sys::Linux,
    prog: &str,
    argv: &[String],
) -> Result<u64, String> {
    use polyisa_mem::{Perms, VirtAddr};

    // EM_MIPS = 8。Ref: SRC-LINUX (7.3).
    if ehdr.machine != 8 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let header_le = ehdr.little;
    let model_le = matches!(model.endian, Endian::Le);
    if header_le != model_le {
        return Err("ELF のエンディアンとモデルが違う".to_string());
    }
    let phdrs = if class64 {
        polyisa_loader::elf::parse_phdrs(bytes, ehdr).map_err(|e| format!("phdrs: {e:?}"))?
    } else {
        polyisa_loader::elf::parse_phdrs32(bytes, ehdr).map_err(|e| format!("phdrs: {e:?}"))?
    };
    if polyisa_loader::elf::parse_interp(bytes, &phdrs).is_some() {
        return Err("動的リンクは未対応".to_string());
    }
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_mips::CpuState>());
    let image_end = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr + p.memsz)
        .max()
        .unwrap_or(0);
    polyisa_loader::elf::load_segments(bytes, &phdrs, &mut env.backend.mem)
        .map_err(|e| format!("load: {e:?}"))?;
    sys.init_brk(image_end);
    set_u64(&mut env, sem::is64_ref().offset(), u64::from(model.is64));
    // 初期スタックを組む。エントリ幅は o32/n32 が 4 バイト、n64 が 8 バイト。
    // スタックは 8MB 確保する（x86 経路と同じ。RLIMIT_STACK 既定相当）。
    let top = 0x7fff_0000u64;
    let mut arg_bytes = vec![prog.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let (img, sp) = if class64 {
        polyisa_os_linux::build_initial_stack_endian(
            top,
            &arg_bytes,
            &[],
            &[(6, 0x1000)],
            model.endian,
        )
    } else {
        polyisa_os_linux::build_initial_stack32_endian(
            top,
            &arg_bytes,
            &[],
            &[(6, 0x1000)],
            model.endian,
        )
    };
    const STACK_SIZE: u64 = 8 * 1024 * 1024;
    let base = top - STACK_SIZE;
    let end = top.next_multiple_of(polyisa_mem::PAGE_SIZE);
    let count = (end - base) / polyisa_mem::PAGE_SIZE;
    env.backend
        .mem
        .map(VirtAddr(base), count, Perms(Perms::R.0 | Perms::W.0))
        .map_err(|e| format!("stack map: {e:?}"))?;
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|e| format!("stack write: {e:?}"))?;
    set_reg(&mut env, 29, sp);
    match run(&mut env, ehdr.entry, model, sys) {
        MipsOutcome::Exit(code) => Ok(code),
        MipsOutcome::Unimplemented { pc, word } => {
            Err(format!("unimplemented at {pc:#x}: {word:#x}"))
        }
        MipsOutcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        MipsOutcome::Exception(exception) => Err(format!("exception {exception:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_mem::Perms;

    /// OS なしの実行。テストが syscall を含まないときの簡便な起動。
    fn run_bare(env: &mut BareEnv, entry: u64, model: MipsModel) -> MipsOutcome {
        let mut sys = polyisa_os_linux::mips::sys::Linux::o32(model.endian);
        run(env, entry, model, &mut sys)
    }

    fn env_at(base: u64) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_mips::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(base), 2, rwx).unwrap();
        env
    }

    fn poke(env: &mut BareEnv, addr: u64, word: u32) {
        poke_endian(env, addr, word, Endian::Be);
    }

    fn poke_endian(env: &mut BareEnv, addr: u64, word: u32, endian: Endian) {
        let bytes = match endian {
            Endian::Be => word.to_be_bytes(),
            Endian::Le => word.to_le_bytes(),
        };
        env.backend.mem.write(VirtAddr(addr), &bytes).unwrap();
    }

    fn raw_word(env: &BareEnv, addr: u64) -> [u8; 4] {
        let mut buf = [0u8; 4];
        let acc = Access {
            endian: Endian::Be,
            align: Align::Unaligned,
            kind: AccessKind::DataRead,
        };
        env.backend.mem.read(VirtAddr(addr), &mut buf, acc).unwrap();
        buf
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
    fn dsll32_daddiu_materializes_int64_max() {
        // addiu $2,$0,-1 ; dsll32 $2,$2,31 ; daddiu $2,$2,-1 ; trap
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x2402_ffff);
        poke(&mut env, 0x1004, 0x0002_17fc);
        poke(&mut env, 0x1008, 0x6442_ffff);
        poke(&mut env, 0x100c, 0xffff_ffff);
        let _outcome = run_bare(&mut env, 0x1000, MipsModel::mips64r2());
        assert_eq!(get_u64(&mut env, Gpr(2).state().offset()), i64::MAX as u64);
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
        let outcome = run_bare(&mut env, 0x1000, MipsModel::mips1_be());
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
        let outcome = run_bare(&mut env, 0x1000, MipsModel::mips1_be());
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
        let outcome = run_bare(&mut env, 0x1000, MipsModel::mips1_be());
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

    #[test]
    fn jal_links_pc_plus_8_and_runs_the_slot() {
        // 0x1000 jal 0x100C。リンクはスロットの次。
        // 0x1004 addiu r2, zero, 1
        // 0x1008 addiu r3, zero, 7  実行しない。
        // 0x100C 未定義で停止。
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x0c00_0403);
        poke(&mut env, 0x1004, 0x2402_0001);
        poke(&mut env, 0x1008, 0x2403_0007);
        poke(&mut env, 0x100c, 0xffff_ffff);
        let outcome = run_bare(&mut env, 0x1000, MipsModel::mips1_be());
        assert_eq!(
            outcome,
            MipsOutcome::Unimplemented {
                pc: 0x100c,
                word: 0xffff_ffff,
            }
        );
        assert_eq!(reg(&mut env, 31), 0x1008);
        assert_eq!(reg(&mut env, 2), 1);
        assert_eq!(reg(&mut env, 3), 0);
    }

    fn be(mut model: MipsModel) -> MipsModel {
        model.endian = Endian::Be;
        model
    }

    #[test]
    fn r3000_load_is_invisible_to_the_next_instruction() {
        // 0x1000 lw r1, 0(r4)     メモリは 0x42。r1 の旧値は 7。
        // 0x1004 addiu r2, r1, 1  遅延スロット。R3000 は 7 を読む。
        // 0x1008 addiu r3, r1, 1  ここでは 0x42 が見える。
        let (r1, r2, r3) = load_then_use(MipsModel::mips1_be());
        assert_eq!(r1, 0x42);
        assert_eq!(r2, 8);
        assert_eq!(r3, 0x43);
        let (r1, r2, r3) = load_then_use(be(MipsModel::mips32r2()));
        assert_eq!(r1, 0x42);
        assert_eq!(r2, 0x43);
        assert_eq!(r3, 0x43);
    }

    #[test]
    fn r3000_discards_a_load_when_the_slot_writes_the_same_reg() {
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x8c81_0000);
        poke(&mut env, 0x1004, 0x2421_0001);
        poke(&mut env, 0x1008, 0x2422_0000);
        poke(&mut env, 0x100c, 0xffff_ffff);
        poke(&mut env, 0x1800, 0x42);
        set_reg(&mut env, 1, 7);
        set_reg(&mut env, 4, 0x1800);
        let outcome = run_bare(&mut env, 0x1000, MipsModel::mips1_be());
        assert!(matches!(
            outcome,
            MipsOutcome::Unimplemented { pc: 0x100c, .. }
        ));
        assert_eq!(reg(&mut env, 1), 8);
        assert_eq!(reg(&mut env, 2), 8);
    }

    #[test]
    fn r3000_branch_slot_sees_a_load_from_before_the_branch() {
        // lw の遅延スロットが beq。beq は r1 を書かないので、beq のスロットはロード値を読む。
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x8c81_0000);
        poke(&mut env, 0x1004, 0x1000_0001);
        poke(&mut env, 0x1008, 0x2422_0001);
        poke(&mut env, 0x100c, 0x2423_0001);
        poke(&mut env, 0x1010, 0xffff_ffff);
        poke(&mut env, 0x1800, 0x42);
        set_reg(&mut env, 1, 7);
        set_reg(&mut env, 4, 0x1800);
        let outcome = run_bare(&mut env, 0x1000, MipsModel::mips1_be());
        assert!(matches!(
            outcome,
            MipsOutcome::Unimplemented { pc: 0x1010, .. }
        ));
        assert_eq!(reg(&mut env, 2), 0x43);
        assert_eq!(reg(&mut env, 3), 0x43);
    }

    #[test]
    fn r6_compact_branch_sees_the_loaded_value() {
        // 0x1000 lw r1, 0(r4)          メモリは 0。r1 の旧値は 1。
        // 0x1004 beqzalc r1, +4        ロード値 0 を見て分岐する。
        // 0x1008 addiu r2, zero, 1     不成立のときだけ実行する。
        // 0x1018 addiu r3, zero, 2     飛び先。
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x8c81_0000);
        poke(&mut env, 0x1004, 0x2001_0004);
        poke(&mut env, 0x1008, 0x2402_0001);
        poke(&mut env, 0x1018, 0x2403_0002);
        poke(&mut env, 0x101c, 0xffff_ffff);
        poke(&mut env, 0x1800, 0);
        set_reg(&mut env, 1, 1);
        set_reg(&mut env, 4, 0x1800);
        let outcome = run_bare(&mut env, 0x1000, be(MipsModel::r6()));
        assert_eq!(
            outcome,
            MipsOutcome::Unimplemented {
                pc: 0x101c,
                word: 0xffff_ffff,
            }
        );
        assert_eq!(reg(&mut env, 1), 0);
        assert_eq!(reg(&mut env, 2), 0);
        assert_eq!(reg(&mut env, 3), 2);
        assert_eq!(reg(&mut env, 31), 0x1008);
        assert!(!MipsModel::mips32r2().load_delay);
        assert!(!MipsModel::r6().load_delay);
        assert!(MipsModel::mips1_be().load_delay);
    }

    #[test]
    fn untaken_beqzalc_advances_to_the_next_instruction() {
        // 0x1000 addiu r1, zero, 1
        // 0x1004 beqzalc r1, +4     r1 は 0 ではない。
        // 0x1008 addiu r2, zero, 9  これを実行して止まる。
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x2401_0001);
        poke(&mut env, 0x1004, 0x2001_0004);
        poke(&mut env, 0x1008, 0x2402_0009);
        poke(&mut env, 0x100c, 0xffff_ffff);
        let outcome = run_bare(&mut env, 0x1000, be(MipsModel::r6()));
        assert_eq!(
            outcome,
            MipsOutcome::Unimplemented {
                pc: 0x100c,
                word: 0xffff_ffff,
            }
        );
        assert_eq!(reg(&mut env, 2), 9);
        assert_eq!(reg(&mut env, 31), 0x1008);
    }

    #[test]
    fn the_same_bytes_decode_differently_by_endian() {
        // バイト列 24 02 00 01。BE は addiu r2, zero, 1。LE は beq。
        let mut be_env = env_at(0x1000);
        poke(&mut be_env, 0x1000, 0x2402_0001);
        poke(&mut be_env, 0x1004, 0xffff_ffff);
        let be = run_bare(&mut be_env, 0x1000, MipsModel::mips1_be());
        assert!(matches!(be, MipsOutcome::Unimplemented { pc: 0x1004, .. }));
        assert_eq!(reg(&mut be_env, 2), 1);

        let mut le_env = env_at(0x1000);
        poke(&mut le_env, 0x1000, 0x2402_0001);
        poke(&mut le_env, 0x1004, 0xffff_ffff);
        let le = run_bare(&mut le_env, 0x1000, MipsModel::mips1_le());
        assert!(matches!(le, MipsOutcome::Unimplemented { pc: 0x1004, .. }));
        assert_eq!(reg(&mut le_env, 2), 0);
    }

    #[test]
    fn lw_sw_roundtrip_follows_the_model_endian() {
        for model in [
            MipsModel::mips1_be(),
            MipsModel::mips1_le(),
            MipsModel::mips32r2(),
        ] {
            let mut env = env_at(0x1000);
            poke_endian(&mut env, 0x1000, 0xac82_0000, model.endian);
            poke_endian(&mut env, 0x1004, 0x8c83_0000, model.endian);
            poke_endian(&mut env, 0x1008, 0x0000_0000, model.endian);
            poke_endian(&mut env, 0x100c, 0xffff_ffff, model.endian);
            set_reg(&mut env, 2, 0x1122_3344);
            set_reg(&mut env, 4, 0x1800);
            let outcome = run_bare(&mut env, 0x1000, model);
            assert!(
                matches!(outcome, MipsOutcome::Unimplemented { pc: 0x100c, .. }),
                "{outcome:?} endian={:?}",
                model.endian
            );
            assert_eq!(reg(&mut env, 3), 0x1122_3344);
            let bytes = raw_word(&env, 0x1800);
            let expect = match model.endian {
                Endian::Be => [0x11, 0x22, 0x33, 0x44],
                Endian::Le => [0x44, 0x33, 0x22, 0x11],
            };
            assert_eq!(bytes, expect);
        }
    }

    fn load_then_use(model: MipsModel) -> (u64, u64, u64) {
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x8c81_0000);
        poke(&mut env, 0x1004, 0x2422_0001);
        poke(&mut env, 0x1008, 0x2423_0001);
        poke(&mut env, 0x100c, 0xffff_ffff);
        poke(&mut env, 0x1800, 0x42);
        set_reg(&mut env, 1, 7);
        set_reg(&mut env, 4, 0x1800);
        let outcome = run_bare(&mut env, 0x1000, model);
        assert!(matches!(
            outcome,
            MipsOutcome::Unimplemented { pc: 0x100c, .. }
        ));
        (reg(&mut env, 1), reg(&mut env, 2), reg(&mut env, 3))
    }

    fn write_then(exit: bool) -> (MipsOutcome, polyisa_os_linux::mips::sys::MipsIo) {
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x3405_1800);
        poke(&mut env, 0x1004, 0x2404_0001);
        poke(&mut env, 0x1008, 0x2406_0001);
        poke(&mut env, 0x100c, 0x2402_0fa4);
        poke(&mut env, 0x1010, 0x0000_000c);
        if exit {
            poke(&mut env, 0x1014, 0x90a4_0000);
            poke(&mut env, 0x1018, 0x0000_0000);
            poke(&mut env, 0x101c, 0x2402_0fa1);
            poke(&mut env, 0x1020, 0x0000_000c);
        } else {
            poke(&mut env, 0x1014, 0xffff_ffff);
        }
        env.backend.mem.write(VirtAddr(0x1800), &[7]).unwrap();
        let mut sys = polyisa_os_linux::mips::sys::Linux::o32(Endian::Be);
        let outcome = run(&mut env, 0x1000, MipsModel::mips1_be(), &mut sys);
        let io = std::mem::take(&mut sys.io);
        if !exit {
            assert_eq!(reg(&mut env, 2), 1);
            assert_eq!(reg(&mut env, 7), 0);
        }
        (outcome, io)
    }

    #[test]
    fn o32_write_sets_success_flag_and_exit_uses_that_byte() {
        let (stopped, io) = write_then(false);
        assert!(matches!(
            stopped,
            MipsOutcome::Unimplemented { pc: 0x1014, .. }
        ));
        assert_eq!(io.stdout, [7]);
        let (exited, io) = write_then(true);
        assert_eq!(exited, MipsOutcome::Exit(7));
        assert_eq!(io.stdout, [7]);
    }

    #[test]
    fn o32_unknown_number_returns_enosys_and_continues() {
        // 未実装の番号は ENOSYS（a3=1）を返して実行を続ける。
        // 設計: `docs/design/user-mode.md` の「未実装のシステムコール」。
        let mut env = env_at(0x1000);
        poke(&mut env, 0x1000, 0x2402_0063);
        poke(&mut env, 0x1004, 0x0000_000c);
        poke(&mut env, 0x1008, 0x2402_0fa1);
        poke(&mut env, 0x100c, 0x2404_0005);
        poke(&mut env, 0x1010, 0x0000_000c);
        let mut sys = polyisa_os_linux::mips::sys::Linux::o32(Endian::Be);
        let outcome = run(&mut env, 0x1000, MipsModel::mips1_be(), &mut sys);
        assert_eq!(outcome, MipsOutcome::Exit(5));
        // ENOSYS の失敗で立った a3=1 が残る。
        assert_eq!(reg(&mut env, 7), 1);
    }

    #[test]
    fn elf_mips_be_exits() {
        let code = [0x2402_0fa1u32, 0x2404_0003, 0x0000_000c];
        let mut file = vec![0u8; 84];
        file[0..4].copy_from_slice(&polyisa_loader::elf::MAGIC);
        file[4] = polyisa_loader::elf::CLASS_32;
        file[5] = polyisa_loader::elf::DATA_BE;
        file[6] = 1;
        let be32 = |file: &mut [u8], off: usize, v: u32| {
            file[off..off + 4].copy_from_slice(&v.to_be_bytes());
        };
        let be16 = |file: &mut [u8], off: usize, v: u16| {
            file[off..off + 2].copy_from_slice(&v.to_be_bytes());
        };
        be16(&mut file, 16, 2);
        be16(&mut file, 18, 8);
        be32(&mut file, 20, 1);
        be32(&mut file, 24, 0x1000);
        be32(&mut file, 28, 52);
        be16(&mut file, 40, 52);
        be16(&mut file, 42, 32);
        be16(&mut file, 44, 1);
        be32(&mut file, 52, 1);
        be32(&mut file, 56, 84);
        be32(&mut file, 60, 0x1000);
        be32(&mut file, 68, 12);
        be32(&mut file, 72, 12);
        be32(&mut file, 76, 5);
        be32(&mut file, 80, 0x1000);
        for word in code {
            file.extend(word.to_be_bytes());
        }
        let path = std::env::temp_dir().join("polyisa-mips-exit.elf");
        std::fs::write(&path, &file).unwrap();
        let code = run_elf_mips(path.to_str().unwrap(), &[]).unwrap();
        assert_eq!(code, 3);
    }

    fn elf_be(flags: u32, code: &[u32], memsz: u32) -> std::path::PathBuf {
        let mut file = vec![0u8; 84 + code.len() * 4];
        file[0..4].copy_from_slice(&polyisa_loader::elf::MAGIC);
        file[4] = polyisa_loader::elf::CLASS_32;
        file[5] = polyisa_loader::elf::DATA_BE;
        file[6] = 1;
        let be32 = |file: &mut [u8], off: usize, v: u32| {
            file[off..off + 4].copy_from_slice(&v.to_be_bytes());
        };
        let be16 = |file: &mut [u8], off: usize, v: u16| {
            file[off..off + 2].copy_from_slice(&v.to_be_bytes());
        };
        be16(&mut file, 16, 2);
        be16(&mut file, 18, 8);
        be32(&mut file, 20, 1);
        be32(&mut file, 24, 0x1000);
        be32(&mut file, 28, 52);
        be32(&mut file, 36, flags);
        be16(&mut file, 40, 52);
        be16(&mut file, 42, 32);
        be16(&mut file, 44, 1);
        be32(&mut file, 52, 1);
        be32(&mut file, 56, 84);
        be32(&mut file, 60, 0x1000);
        be32(&mut file, 68, (code.len() * 4) as u32);
        be32(&mut file, 72, memsz);
        be32(&mut file, 76, 5);
        be32(&mut file, 80, 0x1000);
        for (i, word) in code.iter().enumerate() {
            be32(&mut file, 84 + i * 4, *word);
        }
        let path = std::env::temp_dir().join(format!("polyisa-mips-{flags:x}.elf"));
        std::fs::write(&path, &file).unwrap();
        path
    }

    #[test]
    fn elf_flags_pick_load_delay() {
        // lw の直後にそのレジスタを足す。R3000 は旧値 7、Release 2 はロード値 0x42。
        let code = [
            0x3404_1100u32,
            0x2401_0007,
            0x2403_0042,
            0xac83_0000,
            0x8c81_0000,
            0x2428_0001,
            0x0100_2021,
            0x2402_0fa1,
            0x0000_000c,
        ];
        let r3000 = elf_be(0, &code, 0x200);
        assert_eq!(run_elf_mips(r3000.to_str().unwrap(), &[]).unwrap(), 8);
        let r2 = elf_be(0x7000_0000, &code, 0x200);
        assert_eq!(run_elf_mips(r2.to_str().unwrap(), &[]).unwrap(), 0x43);
        // MIPS32 (0x5) と MIPS II (0x1) は r2 モデルで代用して受理する。
        // addiu $a0,$0,0x42; addiu $v0,$0,4001; syscall → exit(0x42)。
        let mips32 = elf_be(0x5000_0000, &[0x2404_0042, 0x2402_0fa1, 0x0000_000c], 12);
        assert_eq!(run_elf_mips(mips32.to_str().unwrap(), &[]).unwrap(), 0x42);
        let mips2 = elf_be(0x1000_0000, &[0x2404_0042, 0x2402_0fa1, 0x0000_000c], 12);
        assert_eq!(run_elf_mips(mips2.to_str().unwrap(), &[]).unwrap(), 0x42);
    }

    #[test]
    fn elf_class_and_flags_pick_abi() {
        use polyisa_os_linux::mips::sys::Abi;
        // ELFCLASS64 → n64、ELFCLASS32 + EF_MIPS_ABI2 → n32、それ以外 → o32。
        assert!(matches!(abi_from_elf(true, 0x8000_0000).unwrap(), Abi::N64));
        assert!(matches!(
            abi_from_elf(false, 0x8000_0020).unwrap(),
            Abi::N32
        ));
        assert!(matches!(
            abi_from_elf(false, 0x7000_1000).unwrap(),
            Abi::O32
        ));
        // o64/eabi は未対応として落とす。
        assert!(abi_from_elf(false, 0x7000_2000).is_err());
        assert!(abi_from_elf(false, 0x7000_3000).is_err());
    }
}
