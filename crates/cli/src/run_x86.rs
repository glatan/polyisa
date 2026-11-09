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

/// 先頭バイト（必要なら第2・第3バイト）から命令長を決める。単位はバイト。
/// mod/rm による dispers 判定：mod=01→disp8、mod=10→disp32、mod=00 rm=101→disp32
/// （絶対番地）、mod=00 rm=100→SIB（base=101 のとき disp32）。
fn fetch_len(first: u8, second: Option<u8>, third: Option<u8>) -> Option<u64> {
    match first {
        0x90 | 0x40..=0x4F | 0x50..=0x5F | 0xC3 | 0xC9 => Some(1),
        0xEB | 0x74 | 0x75 | 0xE2 | 0xCD | 0x85 | 0x39 | 0x21 | 0x0B | 0x09 | 0x72 | 0x73
        | 0x76 | 0x77 | 0x7C | 0x7D | 0x7E | 0x7F | 0xF7 => Some(2),
        0x05 | 0x2D | 0x3D | 0xB8 | 0xE8 | 0xE9 | 0x25 | 0x0D | 0x35 => Some(5),
        // 0F 1E (ENDBR64) のみ 3B、ほかは 2B。
        0x0F => {
            let s = second?;
            if s == 0x1E { Some(3) } else { Some(2) }
        }
        // string 操作（A4/A5/AA/AB）は 1 バイト。繰り返しは実行側で回す。
        0xA4 | 0xA5 | 0xAA | 0xAB => Some(1),
        // 0x63 /r (MOVSXD)。register-direct のみ 2B で受け、メモリ形式は未対応。
        0x63 => {
            let s = second?;
            if s >> 6 == 3 { Some(2) } else { None }
        }
        // 0x83 /r ib (AND imm8 群)。register-direct のみ 3B で受け、メモリ形式は未対応。
        0x83 => {
            let s = second?;
            if s >> 6 == 3 { Some(3) } else { None }
        }
        // C7 /0 (MOV r/m,imm32 系)。register-direct のみ 6B で受け、メモリ形式は未対応。
        0xC7 => {
            let s = second?;
            if s >> 6 == 3 { Some(6) } else { None }
        }
        // register-direct のみ対応する opcode（メモリ形式は未対応）。
        // SIB を含むことはなく、0xC1（シフト）のみ imm8 で 3B になる。
        0x01 | 0x29 | 0x31 | 0xC1 => {
            let s = second?;
            if first == 0xC1 || s == 0x43 || s == 0x04 {
                Some(3)
            } else {
                Some(2)
            }
        }
        0x8B | 0x89 | 0x8D => {
            let s = second?;
            let modrm_mod = s >> 6;
            let modrm_rm = s & 7;
            if modrm_mod == 3 {
                // register-direct。
                Some(2)
            } else if modrm_rm == 4 {
                // SIB 付き。disp の有無は SIB base で決まる。
                let t = third?;
                let disp = match modrm_mod {
                    1 => 1,
                    2 => 4,
                    _ => {
                        if t & 7 == 5 {
                            4
                        } else {
                            0
                        }
                    }
                };
                Some(3 + disp)
            } else {
                let disp = match modrm_mod {
                    1 => 1,
                    2 => 4,
                    _ => {
                        if modrm_rm == 5 {
                            4
                        } else {
                            0
                        }
                    }
                };
                Some(2 + disp)
            }
        }
        _ => None,
    }
}

/// eip から実行する。fallthrough は eip を命令長だけ進める。
pub fn run(env: &mut BareEnv, entry: u32, sys: &mut impl TrapHandler, limit: u64) -> Outcome {
    run_mode(env, entry, sys, limit, false)
}

/// `is64` のとき REX 接頭辞を受け付ける実行ループ。
/// REX はデコード前に剥がし、レジスタ拡張と W ビットだけを意味論に渡す。
/// 64ビットのスタック・SIB・64ビットメモリ形式は逐次対応し、4GB 未満の静的バイナリを想定する。
pub fn run_mode(
    env: &mut BareEnv,
    entry: u32,
    sys: &mut impl TrapHandler,
    limit: u64,
    is64: bool,
) -> Outcome {
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
        // 接頭辞（F3・REX・0x67）をデコード前に剥がす。順不同に対応する。
        // 0x67 は 64ビットモードのみ受け付け、32ビットアドレス指定とみなす
        // （4GB 未満では u64 演算と等価のため意味論への影響はない）。
        // F3 は string 命令でのみ意味を持ち、ほかでは無視される。
        let mut off: u64 = 0;
        let mut rep = false;
        let mut rex: u8 = 0;
        loop {
            if head[0] == 0xF3 && !rep {
                rep = true;
            } else if is64 && (0x40..=0x4F).contains(&head[0]) && rex == 0 {
                rex = head[0];
            } else if is64 && head[0] == 0x67 {
                // アドレスサイズ接頭辞。複数あっても1バイトずつ剥がす。
            } else {
                break;
            }
            off += 1;
            if env
                .backend
                .mem
                .read(VirtAddr(pc + off), &mut head, acc_fetch())
                .is_err()
            {
                return Outcome::Unimplemented {
                    eip: pc as u32,
                    word: head[0] as u128,
                };
            }
        }
        let mut peek = [0u8; 1];
        let second = if matches!(
            head[0],
            0x01 | 0x8B | 0x29 | 0x31 | 0x89 | 0xC1 | 0xC7 | 0x83 | 0x63 | 0x8D | 0x0F | 0xF7
        ) {
            if env
                .backend
                .mem
                .read(VirtAddr(pc + off + 1), &mut peek, acc_fetch())
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
        // SIB 付き（mod≠11 かつ rm=100）は第3バイト（SIB）で長さが変わる。
        let third = if matches!(head[0], 0x8B | 0x89 | 0x8D)
            && matches!(second, Some(s) if s & 7 == 4 && s >> 6 != 3)
        {
            let mut sib = [0u8; 1];
            if env
                .backend
                .mem
                .read(VirtAddr(pc + off + 2), &mut sib, acc_fetch())
                .is_err()
            {
                return Outcome::Unimplemented {
                    eip: pc as u32,
                    word: head[0] as u128,
                };
            }
            Some(sib[0])
        } else {
            None
        };
        let Some(base) = fetch_len(head[0], second, third) else {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word: head[0] as u128,
            };
        };
        // 接頭辞付きの追随者は reg-direct 系・C7/83・string・0F・PUSH/POP・CALL/JMP のみ。
        // REX.SIB・REXメモリ形式は未対応。F3 付きは string・ENDBR64 のみ受け付ける。
        if off >= 1
            && !matches!(
                head[0],
                0x8B | 0x89
                    | 0x01
                    | 0x29
                    | 0x31
                    | 0x39
                    | 0x8D
                    | 0xC7
                    | 0x83
                    | 0x63
                    | 0x0F
                    | 0xA4
                    | 0xA5
                    | 0xAA
                    | 0xAB
                    | 0x50..=0x5F | 0xE8 | 0xE9
            )
        {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word: head[0] as u128,
            };
        }
        // REX はデコード前に剥がす。nbytes は eip 進行用に接頭辞を含む。
        let nbytes = base + off;
        let mut bytes = [0u8; 8];
        bytes[0] = head[0];
        if base >= 2 {
            // 長さ判定用のぞき見を使う。なければ読み直す。
            bytes[1] = second.unwrap_or(0);
        }
        if base >= 3 {
            bytes[2] = third.unwrap_or(0);
        }
        for i in 1..base {
            if i == 1 && second.is_some() {
                continue;
            }
            if i == 2 && third.is_some() {
                continue;
            }
            let mut b = [0u8; 1];
            if env
                .backend
                .mem
                .read(VirtAddr(pc + off + i), &mut b, acc_fetch())
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
        for i in 0..base {
            word = (word << 8) | bytes[i as usize] as u128;
        }
        let len_bits = (base * 8) as u32;
        let Some(insn) = decode(word, len_bits) else {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        };
        // 64ビットの mod=00 rm=101 は RIP 相対である。SIB 直接番地 base は
        // 絶対番地のまま（u64 アドレスで扱う）なので通す。
        // REX 拡張ビット付きのメモリ形式（SIB・LEA含む）は未対応。
        // reg-direct 形・C7/83・PUSH/POP・RIP相対のみ R8-R15 を受け付ける。
        if is64 && rex & 0x7 != 0 {
            match insn {
                Insn::MovRm32
                | Insn::MovMr32
                | Insn::AddRm32
                | Insn::SubRm32
                | Insn::AndRm32
                | Insn::OrRm32
                | Insn::XorRm32
                | Insn::Movsxd
                | Insn::CmpRm32
                | Insn::MovRmImm
                | Insn::AndRmImm8
                | Insn::PushEax
                | Insn::PushEcx
                | Insn::PushEdx
                | Insn::PushEbx
                | Insn::PushEsp
                | Insn::PushEbp
                | Insn::PushEsi
                | Insn::PushEdi
                | Insn::PopEax
                | Insn::PopEcx
                | Insn::PopEdx
                | Insn::PopEbx
                | Insn::PopEsp
                | Insn::PopEbp
                | Insn::PopEsi
                | Insn::PopEdi => {}
                _ => {
                    return Outcome::Unimplemented {
                        eip: pc as u32,
                        word,
                    };
                }
            }
        }
        // string 操作は F3 付きのみ受け付ける。
        if !rep && matches!(insn, Insn::Movsb | Insn::Movsd | Insn::Stosb | Insn::Stosd) {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        }
        // imm/disp の取り出し。32ビット値は LE 実バイト列から復元する。
        let imm32 = || (word as u32).swap_bytes();
        let disp8 = || (word & 0xff) as u8 as i8;
        let eip = pc as u32;
        // 意味論が分岐を取ると backend.ctrl に Jump が残る（取らなければ
        // Fallthrough）。eip 等値での判定は自己ループで誤るため使わない。
        use polyisa_engine::interp::Ctrl;
        let r = env.step(|b| dispatch(b, insn, eip, word, nbytes, off, is64, rex, imm32, disp8));
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

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn dispatch<B: Backend>(
    b: &mut B,
    insn: Insn,
    eip: u32,
    word: u128,
    nbytes: u64,
    off: u64,
    is64: bool,
    rex: u8,
    imm32: impl Fn() -> u32,
    disp8: impl Fn() -> i8,
) -> Result<(), B::Exit> {
    use polyisa_guest_x86::sem::Gpr;
    let disp32 = || imm32() as i32;
    // ModRM register-direct の reg/rm 抽出。ModRM は先頭から 2+off バイト目にあり、
    // word（opcode 上位詰め）内の位置は命令長で決まる。REX.R/B で 8-15 に拡張する。
    let modrm = || ((word >> ((nbytes - 2 - off) * 8)) & 0xff) as u8;
    let reg = || Gpr(((modrm() >> 3) & 7) | (((rex >> 2) & 1) << 3));
    let rm = || Gpr((modrm() & 7) | ((rex & 1) << 3));
    // PUSH/POP のレジスタは opcode 下位3ビット + REX.B。
    let push_r = || Gpr(((word as u8) & 7) | ((rex & 1) << 3));
    // REX.W の有無で 32/64ビット意味論を選ぶ。
    let rex_w = rex & 8 != 0;
    // SIB バイトと scale/index/base の抽出。SIB 付き命令でのみ呼ぶ。
    let sib = || ((word >> ((nbytes - 3 - off) * 8)) & 0xff) as u8;
    let sib_shift = || ((sib() >> 6) & 3) as u32;
    let sib_idx_raw = || (sib() >> 3) & 7;
    let sib_idx = || Gpr(sib_idx_raw() | (((rex >> 2) & 1) << 3));
    let sib_base = || Gpr((sib() & 7) | ((rex & 1) << 3));
    // SIB index なし（100 + REX.X なし）は base のみで扱う。
    let no_index = || sib_idx_raw() == 4 && (rex >> 2) & 1 == 0;
    let r: Result<(), B::Exit> = match insn {
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
        Insn::Endbr64 => sem::nop(b),
        Insn::AddRm32 => {
            if rex_w {
                sem::add_rm64(b, rm(), reg())
            } else {
                sem::add_rm32(b, rm(), reg())
            }
        }
        Insn::MovRm32 => {
            if rex_w {
                sem::mov_rm64(b, reg(), rm())
            } else {
                sem::mov_rm32(b, reg(), rm())
            }
        }
        Insn::MovEaxMem8 => sem::mov_eax_mem8(b, reg(), rm(), disp8()),
        Insn::MovMemEax8 => sem::mov_mem_eax8(b, reg(), rm(), disp8()),
        Insn::MovEaxMemnd => sem::mov_eax_memnd(b, reg(), rm()),
        Insn::MovMemndEax => sem::mov_memnd_eax(b, reg(), rm()),
        Insn::MovEaxMem32 => sem::mov_eax_mem32(b, reg(), rm(), disp32()),
        Insn::MovMemEax32 => sem::mov_mem_eax32(b, reg(), rm(), disp32()),
        Insn::MovEaxAbs => {
            if is64 {
                sem::mov_eax_rip(b, eip as u64 + nbytes, disp32())
            } else {
                sem::mov_eax_abs(b, Gpr(0), imm32())
            }
        }
        Insn::MovAbsEax => {
            if is64 {
                sem::mov_rip_eax(b, eip as u64 + nbytes, disp32())
            } else {
                sem::mov_abs_eax(b, Gpr(0), imm32())
            }
        }
        Insn::MovEaxSib => {
            if no_index() {
                sem::mov_eax_memnd(b, reg(), sib_base())
            } else {
                sem::mov_eax_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::MovSibEax => {
            if no_index() {
                sem::mov_memnd_eax(b, reg(), sib_base())
            } else {
                sem::mov_sib_eax(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::MovEaxSibd => {
            if no_index() {
                sem::mov_eax_mem8(b, reg(), sib_base(), disp8())
            } else {
                sem::mov_eax_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::MovSibdEax => {
            if no_index() {
                sem::mov_mem_eax8(b, reg(), sib_base(), disp8())
            } else {
                sem::mov_sibd_eax(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::MovEaxSibd32 => {
            if no_index() {
                sem::mov_eax_mem32(b, reg(), sib_base(), disp32())
            } else {
                sem::mov_eax_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovSibd32Eax => {
            if no_index() {
                sem::mov_mem_eax32(b, reg(), sib_base(), disp32())
            } else {
                sem::mov_sibd32_eax(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovEaxSibabs => {
            if no_index() {
                sem::mov_eax_abs(b, reg(), disp32() as u32)
            } else {
                sem::mov_eax_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovSibabsEax => {
            if no_index() {
                sem::mov_abs_eax(b, reg(), disp32() as u32)
            } else {
                sem::mov_sibabs_eax(b, reg(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::PushEax
        | Insn::PushEcx
        | Insn::PushEdx
        | Insn::PushEbx
        | Insn::PushEsp
        | Insn::PushEbp
        | Insn::PushEsi
        | Insn::PushEdi => {
            if is64 {
                sem::push_reg64(b, push_r())
            } else {
                sem::push_reg(b, push_r())
            }
        }
        Insn::PopEax
        | Insn::PopEcx
        | Insn::PopEdx
        | Insn::PopEbx
        | Insn::PopEsp
        | Insn::PopEbp
        | Insn::PopEsi
        | Insn::PopEdi => {
            if is64 {
                sem::pop_reg64(b, push_r())
            } else {
                sem::pop_reg(b, push_r())
            }
        }
        Insn::CallRel32 => {
            if is64 {
                sem::call_rel64(b, eip as u64 + nbytes, disp32())
            } else {
                sem::call_rel32(b, eip, disp32())
            }
        }
        Insn::Ret => {
            if is64 {
                sem::ret64(b)
            } else {
                sem::ret(b)
            }
        }
        Insn::CmpEax => sem::cmp_eax(b, imm32()),
        Insn::TestEax => sem::test_eax(b),
        Insn::Je => sem::je(b, eip, disp8()),
        Insn::Jne => sem::jne(b, eip, disp8()),
        Insn::Jb => sem::jb(b, eip, disp8()),
        Insn::Jae => sem::jae(b, eip, disp8()),
        Insn::Jbe => sem::jbe(b, eip, disp8()),
        Insn::Ja => sem::ja(b, eip, disp8()),
        Insn::Jl => sem::jl(b, eip, disp8()),
        Insn::Jge => sem::jge(b, eip, disp8()),
        Insn::Jle => sem::jle(b, eip, disp8()),
        Insn::Jg => sem::jg(b, eip, disp8()),
        Insn::Loop => sem::loop_rel8(b, eip, disp8()),
        Insn::JmpRel32 => sem::jmp_rel32(b, eip, disp32()),
        Insn::SubEax => sem::sub_eax(b, imm32()),
        Insn::Leave => {
            if is64 {
                sem::leave64(b)
            } else {
                sem::leave(b)
            }
        }
        Insn::AndEax => sem::and_eax(b, imm32()),
        Insn::OrEax => sem::or_eax(b, imm32()),
        Insn::XorImm => sem::xor_imm(b, imm32()),
        Insn::ShlEax => sem::shl_eax(b, word as u8),
        Insn::ShrEax => sem::shr_eax(b, word as u8),
        Insn::Int80 => sem::int80(b, eip),
        Insn::LeaM8 => sem::lea_m8(b, reg(), rm(), disp8()),
        Insn::LeaM32 => sem::lea_m32(b, reg(), rm(), disp32()),
        Insn::LeaMnd => sem::lea_mnd(b, reg(), rm()),
        Insn::LeaAbs => {
            if is64 {
                sem::lea_rip64(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::lea_abs(b, reg(), imm32())
            }
        }
        Insn::LeaSib => {
            if no_index() {
                sem::lea_mnd(b, reg(), sib_base())
            } else {
                sem::lea_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::LeaSibd => {
            if no_index() {
                sem::lea_m8(b, reg(), sib_base(), disp8())
            } else {
                sem::lea_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::LeaSibd32 => {
            if no_index() {
                sem::lea_m32(b, reg(), sib_base(), disp32())
            } else {
                sem::lea_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::LeaSibabs => {
            if no_index() {
                sem::lea_abs(b, reg(), disp32() as u32)
            } else {
                sem::lea_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovRmImm => {
            if rex_w {
                sem::mov_rm64_imm(b, rm(), imm32())
            } else {
                sem::mov_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::AndRmImm8 => {
            if rex_w {
                sem::and_rm64_imm8(b, rm(), disp8())
            } else {
                sem::and_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::Movsxd => {
            if rex_w {
                sem::movsxd_rm64(b, reg(), rm())
            } else {
                sem::movsxd_rm32(b, reg(), rm())
            }
        }
        Insn::CmpRm32 => {
            if rex_w {
                sem::cmp_rm64(b, rm(), reg())
            } else {
                sem::cmp_rm32(b, rm(), reg())
            }
        }
        Insn::AndRm32 => sem::and_rm32(b, rm(), reg()),
        Insn::OrRm32 => sem::or_rm32(b, rm(), reg()),
        Insn::SubRm32 => {
            if rex_w {
                sem::sub_rm64(b, rm(), reg())
            } else {
                sem::sub_rm32(b, rm(), reg())
            }
        }
        Insn::XorRm32 => sem::xor_rm32(b, rm(), reg()),
        Insn::MovMr32 => {
            if rex_w {
                sem::mov_mr64(b, rm(), reg())
            } else {
                sem::mov_mr32(b, rm(), reg())
            }
        }
        Insn::MulRm32 => sem::mul_rm32(b),
        Insn::DivRm32 => sem::div_rm32(b, eip),
        Insn::IdivRm32 => sem::idiv_rm32(b, eip),
        Insn::Movsb => sem::rep_movsb(b, eip),
        Insn::Movsd => {
            if rex_w {
                sem::rep_movsq(b, eip)
            } else {
                sem::rep_movsd(b, eip)
            }
        }
        Insn::Stosb => sem::rep_stosb(b, eip),
        Insn::Stosd => {
            if rex_w {
                sem::rep_stosq(b, eip)
            } else {
                sem::rep_stosd(b, eip)
            }
        }
    };
    if is64 {
        // 64ビットでの32ビット書き込みは上位をゼロ拡張する。
        let dst: Option<Gpr> = match insn {
            Insn::IncEax
            | Insn::DecEax
            | Insn::AddEax
            | Insn::MovEax
            | Insn::SubEax
            | Insn::AndEax
            | Insn::OrEax
            | Insn::XorImm
            | Insn::ShlEax
            | Insn::ShrEax
            | Insn::MovEaxMem8
            | Insn::MovEaxMemnd
            | Insn::MovEaxMem32
            | Insn::MovEaxSib
            | Insn::MovEaxSibd
            | Insn::MovEaxSibd32
            | Insn::MovEaxSibabs
            | Insn::PopEax => Some(Gpr(0)),
            Insn::IncEcx | Insn::DecEcx | Insn::PopEcx => Some(Gpr(1)),
            Insn::IncEdx | Insn::DecEdx | Insn::PopEdx => Some(Gpr(2)),
            Insn::IncEbx | Insn::DecEbx | Insn::PopEbx => Some(Gpr(3)),
            Insn::IncEsp | Insn::DecEsp | Insn::PopEsp => Some(Gpr(4)),
            Insn::IncEbp | Insn::DecEbp | Insn::PopEbp => Some(Gpr(5)),
            Insn::IncEsi | Insn::DecEsi | Insn::PopEsi => Some(Gpr(6)),
            Insn::IncEdi | Insn::DecEdi | Insn::PopEdi => Some(Gpr(7)),
            Insn::AddRm32
            | Insn::SubRm32
            | Insn::AndRm32
            | Insn::OrRm32
            | Insn::XorRm32
            | Insn::MovMr32
            | Insn::MovRmImm
            | Insn::AndRmImm8 => Some(rm()),
            Insn::MovRm32 | Insn::Movsxd => Some(reg()),
            Insn::LeaM8
            | Insn::LeaM32
            | Insn::LeaMnd
            | Insn::LeaAbs
            | Insn::LeaSib
            | Insn::LeaSibd
            | Insn::LeaSibd32
            | Insn::LeaSibabs => Some(reg()),
            _ => None,
        };
        if let Some(d) = dst {
            sem::clear_hi(b, d);
        }
        if matches!(insn, Insn::MulRm32 | Insn::DivRm32 | Insn::IdivRm32) {
            sem::clear_hi(b, Gpr(0));
            sem::clear_hi(b, Gpr(2));
        }
    }
    r
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
    let mut sys = CliLinux::i386();
    run_image_x86(&bytes, path, argv, &mut sys)
}

/// ELF64 イメージを実行する。EM_X86_64 の静的実行を受け持つ。
/// 番号表は x86-64 Linux のものを使う。4GB 未満の配置を想定し、
/// RIP 上位と 64ビットスタックは扱わない（静的・非PIE のみ）。
pub fn run_image_x86_64(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut impl TrapHandler,
) -> Result<u64, String> {
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_mem::{PAGE_SIZE, Perms};

    let ehdr = polyisa_loader::elf::parse_ehdr(bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    if !ehdr.little {
        return Err("big-endian ELF は未対応".to_string());
    }
    // EM_X86_64=62。Ref: SRC-LINUX (7.3).
    const EM_X86_64: u16 = 62;
    if ehdr.machine != EM_X86_64 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    if ehdr.entry > u64::from(u32::MAX) {
        return Err("64ビット entry は未対応".to_string());
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs(bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
    polyisa_loader::elf::load_segments(bytes, &phdrs, &mut env.backend.mem)
        .map_err(|e| format!("load: {e:?}"))?;
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
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), sp);
    match run_mode(&mut env, ehdr.entry as u32, sys, 1_000_000, true) {
        Outcome::Exit(code) => Ok(code as u64),
        Outcome::Unimplemented { eip, word } => {
            Err(format!("unimplemented at {eip:#x}: {word:#x}"))
        }
        Outcome::StepLimit { eip } => Err(format!("step limit at {eip:#x}")),
    }
}

/// ELF64 ファイルを実行する。`run_elf_x86` の x86-64 版である。
pub fn run_elf_x86_64(path: &str, argv: &[String]) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = CliLinux::x86_64();
    run_image_x86_64(&bytes, path, argv, &mut sys)
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

/// `cli run` の Linux 用 ecall 処理。openat/read/write/close と
/// exit/exit_group をホストに直結して受け、ほかは未対応として報告する。
/// i386（`is64=false`）と x86-64（`is64=true`）で番号表と引数レジスタが変わる。
/// x86-64 の引数は RDI/RSI/RDX（Gpr 7/6/2）、番号は RAX（Gpr 0）にある。
///
/// 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
/// ここではホストのファイルに直接触る（裸実行の延長）。パスの隔離はしないので、
/// 信頼できないゲストバイナリには使わないこと。絶対パスの O_RDONLY のみ受け付け、
/// 1 回の転送は 64 KiB ずつに区切る。
#[derive(Default)]
pub struct CliLinux {
    reported: Vec<u64>,
    fds: Vec<Option<std::fs::File>>,
    is64: bool,
}

impl CliLinux {
    /// i386 用ハンドラ。
    pub fn i386() -> Self {
        Self::default()
    }

    /// x86-64 用ハンドラ。
    pub fn x86_64() -> Self {
        Self {
            is64: true,
            ..Self::default()
        }
    }
}

/// 旧名。`CliLinux` を使うこと。
pub type CliX86 = CliLinux;

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

/// 64ビットの負 errno（符号拡張する）。
fn neg_errno64(n: u32) -> u64 {
    (n as i32) as i64 as u64
}

fn get64(env: &mut BareEnv, r: polyisa_guest_x86::sem::Gpr) -> u64 {
    polyisa_guest_x86::sem::read64(&mut env.backend, r)
}

fn set64(env: &mut BareEnv, r: polyisa_guest_x86::sem::Gpr, v: u64) {
    polyisa_guest_x86::sem::write64(&mut env.backend, r, v);
}

impl TrapHandler for CliLinux {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        use polyisa_guest_x86::sem::Gpr;
        // INT 0x80 (code 0x80) と SYSCALL (code 0) のどちらも番号は RAX/EAX にある。
        let _ = code;
        // 引数レジスタ：i386 は EBX/ECX/EDX、x86-64 は RDI/RSI/RDX。
        let (r_a, r_b, r_c) = if self.is64 {
            (Gpr(7), Gpr(6), Gpr(2))
        } else {
            (Gpr(3), Gpr(1), Gpr(2))
        };
        let (n_openat, n_read, n_close, n_write, n_exit, n_exit_group) = if self.is64 {
            use polyisa_os_linux::x86_64 as abi;
            (
                abi::OPENAT,
                abi::READ,
                abi::CLOSE,
                abi::WRITE,
                abi::EXIT,
                abi::EXIT_GROUP,
            )
        } else {
            use polyisa_os_linux::i386 as abi;
            (
                abi::OPENAT,
                abi::READ,
                abi::CLOSE,
                abi::WRITE,
                abi::EXIT,
                abi::EXIT_GROUP,
            )
        };
        let guest_abi = if self.is64 {
            polyisa_os_linux::GuestAbi::X86_64Linux
        } else {
            polyisa_os_linux::GuestAbi::I386Linux
        };
        // dirfd の AT_FDCWD：i386 は 32ビット、x86-64 は 64ビットの -100。
        let at_fdcwd: u64 = if self.is64 {
            0xffff_ffff_ffff_ff9c
        } else {
            u64::from(AT_FDCWD_U32)
        };
        // 戻り値の負 errno：x86-64 は 64ビット符号拡張、i386 は 32ビット。
        let neg = |n: u32| -> u64 {
            if self.is64 {
                neg_errno64(n)
            } else {
                u64::from(neg_errno(n))
            }
        };
        let nr = get64(env, Gpr(0));
        if nr == n_openat {
            let dirfd = get64(env, r_a);
            let path_addr = get64(env, r_b);
            let flags = get64(env, r_c) as u32;
            if dirfd != at_fdcwd {
                set64(env, Gpr(0), neg(EINVAL));
                return TrapOutcome::Handled;
            }
            // O_RDONLY のみ受け付ける（O_CLOEXEC は無視する）。
            if flags & !O_CLOEXEC != 0 {
                set64(env, Gpr(0), neg(EINVAL));
                return TrapOutcome::Handled;
            }
            let path = match guest_c_string(env, path_addr) {
                Some(p) => p,
                None => return TrapOutcome::Unimplemented,
            };
            if !path.starts_with('/') {
                set64(env, Gpr(0), neg(EINVAL));
                return TrapOutcome::Handled;
            }
            return match std::fs::File::open(&path) {
                Ok(f) => {
                    self.fds.push(Some(f));
                    set64(env, Gpr(0), (3 + self.fds.len() - 1) as u64);
                    TrapOutcome::Handled
                }
                Err(e) => {
                    let no = match e.kind() {
                        std::io::ErrorKind::NotFound => ENOENT,
                        std::io::ErrorKind::PermissionDenied => EACCES,
                        _ => EINVAL,
                    };
                    set64(env, Gpr(0), neg(no));
                    TrapOutcome::Handled
                }
            };
        }
        if nr == n_read {
            let fd = get64(env, r_a) as u32;
            let buf = get64(env, r_b);
            let mut left = get64(env, r_c);
            let slot = fd.wrapping_sub(3) as usize;
            let Some(slot) = self.fds.get_mut(slot).and_then(|f| f.as_mut()) else {
                // fd 0 (stdin) は空読みとして 0 を返す。
                if fd == 0 {
                    set64(env, Gpr(0), 0);
                    return TrapOutcome::Handled;
                }
                set64(env, Gpr(0), neg(EBADF));
                return TrapOutcome::Handled;
            };
            let mut done = 0u64;
            let mut chunk = vec![0u8; IO_CHUNK];
            while left > 0 {
                let take = left.min(IO_CHUNK as u64) as usize;
                let n = match std::io::Read::read(slot, &mut chunk[..take]) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if env
                    .backend
                    .mem
                    .write(VirtAddr(buf + done), &chunk[..n])
                    .is_err()
                {
                    return TrapOutcome::Unimplemented;
                }
                done += n as u64;
                left -= n as u64;
                if n < take {
                    break;
                }
            }
            set64(env, Gpr(0), done);
            return TrapOutcome::Handled;
        }
        if nr == n_close {
            let fd = get64(env, r_a) as u32;
            let slot = fd.wrapping_sub(3) as usize;
            return match self.fds.get_mut(slot) {
                Some(f) if f.is_some() => {
                    *f = None;
                    set64(env, Gpr(0), 0);
                    TrapOutcome::Handled
                }
                _ => {
                    set64(env, Gpr(0), neg(EBADF));
                    TrapOutcome::Handled
                }
            };
        }
        if nr == n_write {
            let fd = get64(env, r_a) as u32;
            let buf = get64(env, r_b);
            let mut left = get64(env, r_c);
            if fd != 1 && fd != 2 {
                set64(env, Gpr(0), neg(EBADF));
                return TrapOutcome::Handled;
            }
            let mut done = 0u64;
            let mut chunk = vec![0u8; IO_CHUNK];
            while left > 0 {
                let take = left.min(IO_CHUNK as u64) as usize;
                if env
                    .backend
                    .mem
                    .read(VirtAddr(buf + done), &mut chunk[..take], data_access())
                    .is_err()
                {
                    return TrapOutcome::Unimplemented;
                }
                let n = match fd {
                    1 => std::io::Write::write(&mut std::io::stdout(), &chunk[..take]).unwrap_or(0),
                    _ => std::io::Write::write(&mut std::io::stderr(), &chunk[..take]).unwrap_or(0),
                };
                done += n as u64;
                left -= n as u64;
                if n < take {
                    break;
                }
            }
            set64(env, Gpr(0), done);
            return TrapOutcome::Handled;
        }
        if nr == n_exit || nr == n_exit_group {
            return TrapOutcome::Exit(get64(env, r_a) as u32);
        }
        if !self.reported.contains(&nr) {
            self.reported.push(nr);
            let name = polyisa_os_linux::syscall_name(guest_abi, nr);
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
