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
        0xEB | 0x74 | 0x75 | 0xE2 | 0xCD | 0x85 | 0x0F | 0x39 | 0x21 | 0x0B | 0x09 | 0x72
        | 0x73 | 0x76 | 0x77 | 0xF7 => Some(2),
        0x05 | 0x2D | 0x3D | 0xB8 | 0xE8 | 0xE9 | 0x25 | 0x0D | 0x35 => Some(5),
        // 現サブセットの SIB+disp8 (mod=01、rm=100、s==0x44) は 8B/89 のみで 4B。
        // 0xC1 等の他 opcode との組み合わせや disp32 の 6B は本格実装で足す。
        0x01 | 0x8B | 0x29 | 0x31 | 0x89 | 0xC1 | 0x8D => {
            let s = second?;
            if (first == 0x8B || first == 0x89) && s == 0x44 {
                Some(4)
            } else if first == 0xC1 || s == 0x43 || s == 0x04 {
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
        let second = if matches!(
            head[0],
            0x01 | 0x8B | 0x29 | 0x31 | 0x89 | 0xC1 | 0x8D | 0xF7
        ) {
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
            // #DE 等の Trap 以外の退出（未実装命令を含む）は区別せず止める。
            // 本格実装では DivZero をシグナルに変える。
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
    // ModRM register-direct の reg/rm 抽出。word 下位8ビットが ModRM。
    let modrm = || (word & 0xff) as u8;
    let reg = || Gpr((modrm() >> 3) & 7);
    let rm = || Gpr(modrm() & 7);
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
        Insn::AddRm32 => sem::add_rm32(b, rm(), reg()),
        Insn::MovRm32 => sem::mov_rm32(b, reg(), rm()),
        Insn::MovEaxMem => sem::mov_eax_mem(b, disp8()),
        Insn::MovMemEax => sem::mov_mem_eax(b, disp8()),
        Insn::MovEaxSib => sem::mov_eax_sib(b),
        Insn::MovSibEax => sem::mov_sib_eax(b),
        Insn::MovEaxSibd => sem::mov_eax_sibd(b, disp8()),
        Insn::MovSibdEax => sem::mov_sibd_eax(b, disp8()),
        Insn::MovEaxSibS2 => sem::mov_eax_sib_s2(b, disp8()),
        Insn::MovSibS2Eax => sem::mov_sib_s2_eax(b, disp8()),
        Insn::MovEaxSibS4 => sem::mov_eax_sib_s4(b, disp8()),
        Insn::MovSibS4Eax => sem::mov_sib_s4_eax(b, disp8()),
        Insn::MovEaxSibS8 => sem::mov_eax_sib_s8(b, disp8()),
        Insn::MovSibS8Eax => sem::mov_sib_s8_eax(b, disp8()),
        Insn::MovEaxSibS2nd => sem::mov_eax_sib_s2nd(b),
        Insn::MovSibS2ndEax => sem::mov_sib_s2nd_eax(b),
        Insn::MovEaxSibS4nd => sem::mov_eax_sib_s4nd(b),
        Insn::MovSibS4ndEax => sem::mov_sib_s4nd_eax(b),
        Insn::MovEaxSibS8nd => sem::mov_eax_sib_s8nd(b),
        Insn::MovSibS8ndEax => sem::mov_sib_s8nd_eax(b),
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
        Insn::Jb => sem::jb(b, eip, disp8()),
        Insn::Jae => sem::jae(b, eip, disp8()),
        Insn::Jbe => sem::jbe(b, eip, disp8()),
        Insn::Ja => sem::ja(b, eip, disp8()),
        Insn::Loop => sem::loop_rel8(b, eip, disp8()),
        Insn::JmpRel32 => sem::jmp_rel32(b, eip, disp32()),
        Insn::SubEax => sem::sub_eax(b, imm32()),
        Insn::Leave => sem::leave(b),
        Insn::AndEax => sem::and_eax(b, imm32()),
        Insn::OrEax => sem::or_eax(b, imm32()),
        Insn::XorImm => sem::xor_imm(b, imm32()),
        Insn::ShlEax => sem::shl_eax(b, word as u8),
        Insn::ShrEax => sem::shr_eax(b, word as u8),
        Insn::Int80 => sem::int80(b, eip),
        Insn::LeaEax => sem::lea_eax(b, disp8()),
        Insn::CmpRm32 => sem::cmp_rm32(b, rm(), reg()),
        Insn::AndRm32 => sem::and_rm32(b, rm(), reg()),
        Insn::OrRm32 => sem::or_rm32(b, rm(), reg()),
        Insn::SubRm32 => sem::sub_rm32(b, rm(), reg()),
        Insn::XorRm32 => sem::xor_rm32(b, rm(), reg()),
        Insn::MovMr32 => sem::mov_mr32(b, rm(), reg()),
        Insn::MulRm32 => sem::mul_rm32(b),
        Insn::DivRm32 => sem::div_rm32(b, eip),
        Insn::IdivRm32 => sem::idiv_rm32(b, eip),
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

/// ゲストの NUL 終端文字列を読む。上限を超えるか読めなければ None。
fn guest_c_string(env: &mut BareEnv, addr: u64) -> Option<String> {
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut buf = vec![0u8; 4096];
    env.backend.mem.read(VirtAddr(addr), &mut buf, acc).ok()?;
    let end = buf.iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..end].to_vec()).ok()
}

/// `cli run` の x86 用 ecall 処理。openat/read/write/close と
/// exit/exit_group をホストに直結して受け、ほかは未対応として報告する。
///
/// 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
/// ここではホストのファイルに直接触る（裸実行の延長）。パスの隔離はしないので、
/// 信頼できないゲストバイナリには使わないこと。絶対パスの O_RDONLY のみ受け付け、
/// 1 回の転送は 64 KiB ずつに区切る。
#[derive(Default)]
pub struct CliX86 {
    reported: Vec<u64>,
    fds: Vec<Option<std::fs::File>>,
}

/// i386 の openat の引数。dirfd が -100 (AT_FDCWD) のときだけ受け付ける。
const AT_FDCWD_U32: u32 = 0xffff_ff9c;

/// O_CLOEXEC の値。無視してよい旗としてだけ扱う。
/// Ref: SRC-LINUX (7.3).
const O_CLOEXEC: u32 = 0x80000;

/// 1 回の read/write でホストに確保する上限（バイト）。ゲスト指定の
/// 長さが大きくても、この刻みで分割して転送する。
const IO_CHUNK: usize = 65536;

/// Linux 汎用の errno 番号の一部。負数で返す。
/// Ref: SRC-LINUX (7.3).
const ENOENT: u32 = 2;
const EBADF: u32 = 9;
const EACCES: u32 = 13;
const EINVAL: u32 = 22;

fn neg_errno(n: u32) -> u32 {
    (n as i32).wrapping_neg() as u32
}

fn data_access() -> polyisa_mem::Access {
    polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    }
}

impl TrapHandler for CliX86 {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        use polyisa_guest_x86::sem::Gpr;
        // INT 0x80 (code 0x80) と SYSCALL (code 0) のどちらも番号は EAX にある。
        let _ = code;
        let nr = env.backend.get(Gpr(0).state()) as u64;
        if nr == polyisa_os_linux::i386::OPENAT {
            let dirfd = env.backend.get(Gpr(3).state());
            let path_addr = env.backend.get(Gpr(1).state()) as u64;
            let flags = env.backend.get(Gpr(2).state());
            if dirfd != AT_FDCWD_U32 {
                env.backend.set(Gpr(0).state(), neg_errno(EINVAL));
                return TrapOutcome::Handled;
            }
            // O_RDONLY のみ受け付ける（O_CLOEXEC は無視する）。
            if flags & !O_CLOEXEC != 0 {
                env.backend.set(Gpr(0).state(), neg_errno(EINVAL));
                return TrapOutcome::Handled;
            }
            let path = match guest_c_string(env, path_addr) {
                Some(p) => p,
                None => return TrapOutcome::Unimplemented,
            };
            if !path.starts_with('/') {
                env.backend.set(Gpr(0).state(), neg_errno(EINVAL));
                return TrapOutcome::Handled;
            }
            return match std::fs::File::open(&path) {
                Ok(f) => {
                    self.fds.push(Some(f));
                    env.backend
                        .set(Gpr(0).state(), (3 + self.fds.len() - 1) as u32);
                    TrapOutcome::Handled
                }
                Err(e) => {
                    let no = match e.kind() {
                        std::io::ErrorKind::NotFound => ENOENT,
                        std::io::ErrorKind::PermissionDenied => EACCES,
                        _ => EINVAL,
                    };
                    env.backend.set(Gpr(0).state(), neg_errno(no));
                    TrapOutcome::Handled
                }
            };
        }
        if nr == polyisa_os_linux::i386::READ {
            let fd = env.backend.get(Gpr(3).state());
            let buf = env.backend.get(Gpr(1).state()) as u64;
            let mut left = env.backend.get(Gpr(2).state()) as usize;
            let slot = fd.wrapping_sub(3) as usize;
            let Some(slot) = self.fds.get_mut(slot).and_then(|f| f.as_mut()) else {
                // fd 0 (stdin) は空読みとして 0 を返す。
                if fd == 0 {
                    env.backend.set(Gpr(0).state(), 0);
                    return TrapOutcome::Handled;
                }
                env.backend.set(Gpr(0).state(), neg_errno(EBADF));
                return TrapOutcome::Handled;
            };
            let mut done = 0usize;
            let mut chunk = vec![0u8; IO_CHUNK];
            while left > 0 {
                let take = left.min(IO_CHUNK);
                let n = match std::io::Read::read(slot, &mut chunk[..take]) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if env
                    .backend
                    .mem
                    .write(VirtAddr(buf + done as u64), &chunk[..n])
                    .is_err()
                {
                    return TrapOutcome::Unimplemented;
                }
                done += n;
                left -= n;
                if n < take {
                    break;
                }
            }
            env.backend.set(Gpr(0).state(), done as u32);
            return TrapOutcome::Handled;
        }
        if nr == polyisa_os_linux::i386::CLOSE {
            let fd = env.backend.get(Gpr(3).state());
            let slot = fd.wrapping_sub(3) as usize;
            return match self.fds.get_mut(slot) {
                Some(f) if f.is_some() => {
                    *f = None;
                    env.backend.set(Gpr(0).state(), 0);
                    TrapOutcome::Handled
                }
                _ => {
                    env.backend.set(Gpr(0).state(), neg_errno(EBADF));
                    TrapOutcome::Handled
                }
            };
        }
        if nr == polyisa_os_linux::i386::WRITE {
            let fd = env.backend.get(Gpr(3).state());
            let buf = env.backend.get(Gpr(1).state()) as u64;
            let mut left = env.backend.get(Gpr(2).state()) as usize;
            if fd != 1 && fd != 2 {
                env.backend.set(Gpr(0).state(), neg_errno(EBADF));
                return TrapOutcome::Handled;
            }
            let mut done = 0usize;
            let mut chunk = vec![0u8; IO_CHUNK];
            while left > 0 {
                let take = left.min(IO_CHUNK);
                if env
                    .backend
                    .mem
                    .read(
                        VirtAddr(buf + done as u64),
                        &mut chunk[..take],
                        data_access(),
                    )
                    .is_err()
                {
                    return TrapOutcome::Unimplemented;
                }
                let n = match fd {
                    1 => std::io::Write::write(&mut std::io::stdout(), &chunk[..take]).unwrap_or(0),
                    _ => std::io::Write::write(&mut std::io::stderr(), &chunk[..take]).unwrap_or(0),
                };
                done += n;
                left -= n;
                if n < take {
                    break;
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_mem::{Perms, VirtAddr};

    fn bare() -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        env.backend.mem.map(VirtAddr(0), 2, Perms::RW).unwrap();
        env
    }

    fn set_regs(env: &mut BareEnv, nr: u32, a: u32, b: u32, c: u32) {
        env.backend.set(Gpr(0).state(), nr);
        env.backend.set(Gpr(3).state(), a);
        env.backend.set(Gpr(1).state(), b);
        env.backend.set(Gpr(2).state(), c);
    }

    #[test]
    fn write_stdout_and_bad_fd() {
        let mut sys = CliX86::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"hi").unwrap();
        // write(1, 0x100, 2) は受理し、書いたバイト数を返す。
        set_regs(&mut env, polyisa_os_linux::i386::WRITE as u32, 1, 0x100, 2);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 2);
        // 存在しない fd への write は EBADF。
        set_regs(&mut env, polyisa_os_linux::i386::WRITE as u32, 9, 0x100, 2);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
    }

    #[test]
    fn openat_missing_is_enoent() {
        let mut sys = CliX86::default();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/no/such/file\0")
            .unwrap();
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(ENOENT));
    }

    #[test]
    fn openat_rejects_bad_dirfd_and_flags() {
        let mut sys = CliX86::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/x\0").unwrap();
        // dirfd が AT_FDCWD ではない。
        set_regs(&mut env, polyisa_os_linux::i386::OPENAT as u32, 3, 0x100, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EINVAL));
        // O_WRONLY 相当の flags は受け付けない。
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            1,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EINVAL));
        // 相対パスは受け付けない。
        env.backend.mem.write(VirtAddr(0x100), b"rel\0").unwrap();
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EINVAL));
    }

    #[test]
    fn read_write_close_roundtrip() {
        let path = std::env::temp_dir().join(format!("polyisa-unit-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        let path_s = path.to_string_lossy().into_owned();
        let mut sys = CliX86::default();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        // openat -> fd 3。
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        // read(fd=3, buf=0x200, 64) -> 6。
        set_regs(&mut env, polyisa_os_linux::i386::READ as u32, 3, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        // close(3) -> 0、もう一度 close(3) -> EBADF。
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        // read(closed fd=3) -> EBADF。
        set_regs(&mut env, polyisa_os_linux::i386::READ as u32, 3, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        let _ = std::fs::remove_file(&path);
    }
}
