// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 最小の実行ループ（`cli run` の x86 版）。ゲストメモリからフェッチし、デコードして意味論を実行する。
//!
//! 可変長（1〜5バイト）の入口と eip の進行を受け持つ。imm32/disp32 は
//! リトルエンディアンの実バイト列から復元する（ISADL の word 組立は
//! opcode 上位詰めの試作規約のため、ここでバイト順を直す）。
//! SYSCALL と INT 0x80 はトラップとして呼び出し側に委ねる。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend, ExceptionKind};

use polyisa_guest_x86::sem;
use polyisa_guest_x86::{Insn, decode};

/// 実行の結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// 終了コード付きの正常終了。
    Exit(u32),
    /// 未実装の到達点。
    Unimplemented { eip: u32, word: u128 },
    /// 上限を超えた。
    StepLimit { eip: u32 },
}

/// トラップの処理結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrapOutcome {
    /// 処理して次の命令から続ける。
    Handled,
    /// 終了コード付きで抜ける。
    Exit(u32),
    /// 未実装として止める。
    Unimplemented,
}

/// SYSCALL と INT 0x80 を処理する。EAX などの読み書きはここで行う。
pub trait TrapHandler {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome;
}

fn acc_fetch() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    }
}

fn eip_of(env: &mut BareEnv) -> u32 {
    env.backend.get(polyisa_guest_x86::sem::eip_ref())
}

/// 先頭バイト（必要なら第2バイト）から命令長を決める。単位はバイト。
fn fetch_len(first: u8, second: Option<u8>) -> Option<u64> {
    match first {
        0x90 | 0x40..=0x4F | 0x50..=0x5F | 0xC3 | 0xC9 => Some(1),
        0xEB | 0x74 | 0x75 | 0xE2 | 0xCD | 0x85 | 0x0F => Some(2),
        0x05 | 0x2D | 0x3D | 0xB8 | 0xE8 | 0xE9 | 0x25 | 0x0D | 0x35 => Some(5),
        0x01 | 0x8B | 0x31 | 0x89 | 0xC1 => {
            let s = second?;
            if first == 0xC1 || s == 0x43 {
                Some(3)
            } else {
                Some(2)
            }
        }
        _ => None,
    }
}

/// eip から実行する。fallthrough は eip を命令長だけ進める。
pub fn run(env: &mut BareEnv, entry: u32, sys: &mut impl TrapHandler, limit: u64) -> Outcome {
    env.backend.set(polyisa_guest_x86::sem::eip_ref(), entry);
    for _ in 0..limit {
        let pc = eip_of(env) as u64;
        let mut head = [0u8; 1];
        if env
            .backend
            .mem
            .read(VirtAddr(pc), &mut head, acc_fetch())
            .is_err()
        {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word: 0,
            };
        }
        let mut peek = [0u8; 1];
        let second = if matches!(head[0], 0x01 | 0x8B | 0x31 | 0x89 | 0xC1) {
            if env
                .backend
                .mem
                .read(VirtAddr(pc + 1), &mut peek, acc_fetch())
                .is_err()
            {
                return Outcome::Unimplemented {
                    eip: pc as u32,
                    word: head[0] as u128,
                };
            }
            Some(peek[0])
        } else {
            None
        };
        let Some(nbytes) = fetch_len(head[0], second) else {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word: head[0] as u128,
            };
        };
        let mut bytes = [0u8; 5];
        bytes[0] = head[0];
        if nbytes >= 2 {
            // 長さ判定用のぞき見を使う。なければ読み直す。
            bytes[1] = second.unwrap_or(0);
        }
        for i in 1..nbytes {
            if i == 1 && second.is_some() {
                continue;
            }
            let mut b = [0u8; 1];
            if env
                .backend
                .mem
                .read(VirtAddr(pc + i), &mut b, acc_fetch())
                .is_err()
            {
                return Outcome::Unimplemented {
                    eip: pc as u32,
                    word: head[0] as u128,
                };
            }
            bytes[i as usize] = b[0];
        }
        // ISADL の word 組立（opcode 上位詰め）に合わせる。
        let mut word: u128 = 0;
        for i in 0..nbytes {
            word = (word << 8) | bytes[i as usize] as u128;
        }
        let len_bits = (nbytes * 8) as u32;
        let Some(insn) = decode(word, len_bits) else {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        };
        // imm/disp の取り出し。32ビット値は LE 実バイト列から復元する。
        let imm32 = || (word as u32).swap_bytes();
        let disp8 = || (word & 0xff) as u8 as i8;
        let eip = pc as u32;
        // 意味論が分岐を取ると backend.ctrl に Jump が残る（取らなければ
        // Fallthrough）。eip 等値での判定は自己ループで誤るため使わない。
        use polyisa_engine::interp::Ctrl;
        let r = env.step(|b| dispatch(b, insn, eip, word, imm32, disp8));
        match r {
            Ok(()) => match env.backend.ctrl {
                Ctrl::Jump(_) => {}
                Ctrl::Fallthrough => {
                    env.backend.set(
                        polyisa_guest_x86::sem::eip_ref(),
                        eip.wrapping_add(nbytes as u32),
                    );
                }
            },
            Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => {
                match sys.handle_trap(env, e.code as u32) {
                    TrapOutcome::Handled => {
                        // ハンドラが eip を動かさなければ次の命令へ進む。
                        if eip_of(env) == eip {
                            env.backend.set(
                                polyisa_guest_x86::sem::eip_ref(),
                                eip.wrapping_add(nbytes as u32),
                            );
                        }
                    }
                    TrapOutcome::Exit(code) => return Outcome::Exit(code),
                    TrapOutcome::Unimplemented => {
                        return Outcome::Unimplemented { eip, word };
                    }
                }
            }
            Err(_) => {
                return Outcome::Unimplemented { eip, word };
            }
        }
    }
    Outcome::StepLimit { eip: eip_of(env) }
}

#[allow(clippy::too_many_lines)]
fn dispatch<B: Backend>(
    b: &mut B,
    insn: Insn,
    eip: u32,
    word: u128,
    imm32: impl Fn() -> u32,
    disp8: impl Fn() -> i8,
) -> Result<(), B::Exit> {
    use polyisa_guest_x86::sem::Gpr;
    let disp32 = || imm32() as i32;
    match insn {
        Insn::Nop => sem::nop(b),
        Insn::IncEax => sem::inc_r32(b, Gpr(0)),
        Insn::IncEcx => sem::inc_r32(b, Gpr(1)),
        Insn::IncEdx => sem::inc_r32(b, Gpr(2)),
        Insn::IncEbx => sem::inc_r32(b, Gpr(3)),
        Insn::IncEsp => sem::inc_r32(b, Gpr(4)),
        Insn::IncEbp => sem::inc_r32(b, Gpr(5)),
        Insn::IncEsi => sem::inc_r32(b, Gpr(6)),
        Insn::IncEdi => sem::inc_r32(b, Gpr(7)),
        Insn::DecEax => sem::dec_r32(b, Gpr(0)),
        Insn::DecEcx => sem::dec_r32(b, Gpr(1)),
        Insn::DecEdx => sem::dec_r32(b, Gpr(2)),
        Insn::DecEbx => sem::dec_r32(b, Gpr(3)),
        Insn::DecEsp => sem::dec_r32(b, Gpr(4)),
        Insn::DecEbp => sem::dec_r32(b, Gpr(5)),
        Insn::DecEsi => sem::dec_r32(b, Gpr(6)),
        Insn::DecEdi => sem::dec_r32(b, Gpr(7)),
        Insn::AddEax => sem::add_eax(b, imm32()),
        Insn::Jmp8 => sem::jmp8(b, eip.wrapping_add(2).wrapping_add(disp8() as i32 as u32)),
        Insn::MovEax => sem::mov_eax(b, imm32()),
        Insn::Syscall => sem::syscall(b, eip),
        Insn::Cpuid => sem::cpuid(b),
        Insn::AddRm32 => sem::add_rm32(b),
        Insn::MovRm32 => sem::mov_rm32(b),
        Insn::MovEaxMem => sem::mov_eax_mem(b, disp8()),
        Insn::MovMemEax => sem::mov_mem_eax(b, disp8()),
        Insn::PushEax => sem::push_reg(b, Gpr(0)),
        Insn::PushEcx => sem::push_reg(b, Gpr(1)),
        Insn::PushEdx => sem::push_reg(b, Gpr(2)),
        Insn::PushEbx => sem::push_reg(b, Gpr(3)),
        Insn::PushEsp => sem::push_reg(b, Gpr(4)),
        Insn::PushEbp => sem::push_reg(b, Gpr(5)),
        Insn::PushEsi => sem::push_reg(b, Gpr(6)),
        Insn::PushEdi => sem::push_reg(b, Gpr(7)),
        Insn::PopEax => sem::pop_reg(b, Gpr(0)),
        Insn::PopEcx => sem::pop_reg(b, Gpr(1)),
        Insn::PopEdx => sem::pop_reg(b, Gpr(2)),
        Insn::PopEbx => sem::pop_reg(b, Gpr(3)),
        Insn::PopEsp => sem::pop_reg(b, Gpr(4)),
        Insn::PopEbp => sem::pop_reg(b, Gpr(5)),
        Insn::PopEsi => sem::pop_reg(b, Gpr(6)),
        Insn::PopEdi => sem::pop_reg(b, Gpr(7)),
        Insn::CallRel32 => sem::call_rel32(b, eip, disp32()),
        Insn::Ret => sem::ret(b),
        Insn::CmpEax => sem::cmp_eax(b, imm32()),
        Insn::TestEax => sem::test_eax(b),
        Insn::Je => sem::je(b, eip, disp8()),
        Insn::Jne => sem::jne(b, eip, disp8()),
        Insn::Loop => sem::loop_rel8(b, eip, disp8()),
        Insn::JmpRel32 => sem::jmp_rel32(b, eip, disp32()),
        Insn::XorEax => sem::xor_eax(b),
        Insn::SubEax => sem::sub_eax(b, imm32()),
        Insn::MovEbpEsp => sem::mov_ebp_esp(b),
        Insn::Leave => sem::leave(b),
        Insn::AndEax => sem::and_eax(b, imm32()),
        Insn::OrEax => sem::or_eax(b, imm32()),
        Insn::XorImm => sem::xor_imm(b, imm32()),
        Insn::ShlEax => sem::shl_eax(b, word as u8),
        Insn::ShrEax => sem::shr_eax(b, word as u8),
        Insn::Int80 => sem::int80(b, eip),
    }
}

/// ELF32 イメージを実行する。`run_elf` の x86 版であり、EM_386 の静的実行を
/// 受け持つ。番号表は i386 Linux のものを使う。
pub fn run_image_x86(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut impl TrapHandler,
) -> Result<u64, String> {
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_mem::{PAGE_SIZE, Perms};

    let ehdr = polyisa_loader::elf::parse_ehdr32(bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    if !ehdr.little {
        return Err("big-endian ELF は未対応".to_string());
    }
    // EM_386=3。Ref: SRC-LINUX (7.3).
    const EM_386: u16 = 3;
    if ehdr.machine != EM_386 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs32(bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
    polyisa_loader::elf::load_segments(bytes, &phdrs, &mut env.backend.mem)
        .map_err(|e| format!("load: {e:?}"))?;
    // 初期スタックを写像する。配置の規約は i386 psABI の確定を待つ試作であり、
    // RV64 と同じ LE 像を使う（動的リンクは後の段階）。
    let top = 0x7fff_0000u64;
    let mut arg_bytes = vec![prog.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let (img, sp) = polyisa_os_linux::build_initial_stack(top, &arg_bytes, &[], &[(6, 0x1000)]);
    let base = sp & !(PAGE_SIZE - 1);
    let end = top.next_multiple_of(PAGE_SIZE);
    let count = (end - base) / PAGE_SIZE;
    env.backend
        .mem
        .map(
            polyisa_mem::VirtAddr(base),
            count,
            Perms(Perms::R.0 | Perms::W.0),
        )
        .map_err(|e| format!("stack map: {e:?}"))?;
    env.backend
        .mem
        .write(polyisa_mem::VirtAddr(sp), &img)
        .map_err(|e| format!("stack write: {e:?}"))?;
    env.backend.set(Gpr(4).state(), sp as u32);
    match run(&mut env, ehdr.entry as u32, sys, 1_000_000) {
        Outcome::Exit(code) => Ok(code as u64),
        Outcome::Unimplemented { eip, word } => {
            Err(format!("unimplemented at {eip:#x}: {word:#x}"))
        }
        Outcome::StepLimit { eip } => Err(format!("step limit at {eip:#x}")),
    }
}

/// ELF ファイルを実行する。`run_elf` の x86 版である。
pub fn run_elf_x86(path: &str, argv: &[String]) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = CliX86::default();
    run_image_x86(&bytes, path, argv, &mut sys)
}

/// `cli run` の x86 用 ecall 処理。write（fd 1/2）と exit/exit_group を受け、
/// ほかは未対応として報告する。
#[derive(Default)]
pub struct CliX86 {
    reported: Vec<u64>,
}

impl TrapHandler for CliX86 {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        use polyisa_guest_x86::sem::Gpr;
        // INT 0x80 (code 0x80) と SYSCALL (code 0) のどちらも番号は EAX にある。
        let _ = code;
        let nr = env.backend.get(Gpr(0).state()) as u64;
        if nr == polyisa_os_linux::i386::WRITE {
            let fd = env.backend.get(Gpr(3).state());
            let buf = env.backend.get(Gpr(1).state()) as u64;
            let len = env.backend.get(Gpr(2).state()) as usize;
            let mut data = vec![0u8; len];
            let acc = polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            };
            if env.backend.mem.read(VirtAddr(buf), &mut data, acc).is_err() {
                return TrapOutcome::Unimplemented;
            }
            // EBX=1/2 のみ受け、EAX に書いたバイト数を返す。
            let done = match fd {
                1 => std::io::Write::write(&mut std::io::stdout(), &data).unwrap_or(0),
                2 => std::io::Write::write(&mut std::io::stderr(), &data).unwrap_or(0),
                _ => return TrapOutcome::Unimplemented,
            };
            env.backend.set(Gpr(0).state(), done as u32);
            return TrapOutcome::Handled;
        }
        if nr == polyisa_os_linux::i386::EXIT || nr == polyisa_os_linux::i386::EXIT_GROUP {
            return TrapOutcome::Exit(env.backend.get(Gpr(3).state()));
        }
        if !self.reported.contains(&nr) {
            self.reported.push(nr);
            let name = polyisa_os_linux::syscall_name(polyisa_os_linux::GuestAbi::I386Linux, nr);
            eprintln!("run: unhandled syscall {nr} ({})", name.unwrap_or("?"));
        }
        TrapOutcome::Unimplemented
    }
}
