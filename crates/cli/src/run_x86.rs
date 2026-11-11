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
use polyisa_guest_x86::sem::Gpr;
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
    /// 実行できるスレッドがない。待ちの対象は報告済み。
    Deadlock,
}

/// トラップの処理結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrapOutcome {
    /// 処理して次の命令から続ける。
    Handled,
    /// 終了コード付きで抜ける。
    Exit(u32),
    /// このスレッドは待っている。実行ループが他のスレッドへ切り替える。
    Blocked,
    /// 未実装として止める。
    Unimplemented,
}

/// SYSCALL と INT 0x80 を処理する。EAX などの読み書きはここで行う。
pub trait TrapHandler {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome;

    /// FS ベース（TLS）を返す。arch_prctl(ARCH_SET_FS) を処理する
    /// ハンドラ以外は 0 を返す。
    fn fs_base(&self) -> u64 {
        0
    }

    /// 1 命令を実行したあと。既定では何もしない。
    fn after_step(&mut self, _env: &mut BareEnv) {}

    /// 待っているスレッドから切り替える。切り替えたら真。
    fn on_block(&mut self, _env: &mut BareEnv) -> bool {
        false
    }

    /// 終了を別のスレッドの実行へ引き継ぐなら真。既定では終了で抜ける。
    fn take_exit(&mut self, _env: &mut BareEnv, _code: u32) -> bool {
        false
    }
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

fn fetch_len(
    first: u8,
    second: Option<u8>,
    third: Option<u8>,
    fourth: Option<u8>,
    has66: bool,
    rex_w: bool,
) -> Option<u64> {
    match first {
        0x90
        | 0x91..=0x97
        | 0x40..=0x4F
        | 0x50..=0x5F
        | 0xC3
        | 0xC9
        | 0x98
        | 0x99
        | 0xF4
        | 0xFC
        | 0xFD => Some(1),
        0x6A | 0xB0..=0xB7 => Some(2),
        0x68 => Some(5),
        0xEB | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7A
        | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F | 0xE2 | 0xCD | 0x3C | 0x0C => Some(2),
        0x05 | 0x2D | 0xE8 | 0xE9 | 0x35 | 0xA9 => Some(5),
        // 0x0D (OR EAX,imm32)。66 接頭辞では OR AX,imm16 (3B)。seq 0x4d74c9。
        0x0D => {
            if has66 {
                Some(3)
            } else {
                Some(5)
            }
        }
        // 0x25 (AND EAX,imm32)。66 接頭辞では AND AX,imm16 (3B)。
        0x25 => {
            if has66 {
                Some(3)
            } else {
                Some(5)
            }
        }
        // 0x3D (CMP EAX,imm32)。66 接頭辞では CMP AX,imm16 (3B)。
        0x3D => {
            if has66 {
                Some(3)
            } else {
                Some(5)
            }
        }
        0xB8..=0xBF => {
            if rex_w {
                Some(9)
            } else {
                Some(5)
            }
        }
        0xA8 => Some(2),
        // 0F 1E (ENDBR64) は 3B、0F 1F (NOP r/m) は ModRM で長さが決まる。
        // SIB 付き NOP は未対応。XMM・MOVUPS・near Jcc を受け付ける。
        // 2バイトオペコードでは second=opcode2、third=ModRM、fourth=SIB である。
        0x0F => {
            let s = second?;
            if s == 0x05 || s == 0xA2 {
                Some(2)
            } else if s == 0x1E {
                Some(3)
            } else if s == 0x1F {
                let m = third?;
                let (md, rm) = (m >> 6, m & 7);
                if rm == 4 {
                    let t = fourth?;
                    let disp = match md {
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
                    Some(4 + disp)
                } else {
                    Some(
                        3 + match md {
                            1 => 1,
                            2 => 4,
                            _ => {
                                if rm == 5 {
                                    4
                                } else {
                                    0
                                }
                            }
                        },
                    )
                }
            } else if (0x40..=0x4F).contains(&s) {
                // CMOVcc (0F 40-4F /r)。reg-direct 3B、mod=10 RBP+disp32 7B、mod=00 RIP 7B、
                // mod=01 SIB+disp8 no_index 5B.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if rm == 5 && (md == 2 || md == 0) {
                    Some(7)
                } else if md == 1 && rm == 4 {
                    let t = fourth?;
                    // no_index (index=100) のみ.
                    if (t >> 3) & 7 == 4 { Some(5) } else { None }
                } else if s == 0x46 && md == 1 && rm != 4 {
                    // CMOVBE [base+disp8] (test 0x4d2874)。
                    Some(4)
                } else {
                    None
                }
            } else if (0x90..=0x9F).contains(&s) {
                // SETcc r/m8 (0F 90-9F /r)。reg-direct 3B、94 mod=10 [base+disp32] 7B、
                // 94 mod=01 [base+disp8] 4B (grep 0x442245 対応)、95 mod=10 7B (grep 0x43ddc1 対応)、
                // 9E mod=10 [base+disp32] 7B (grep 0x43e091 対応)、
                // 94/95 SIB mod=01 [base+index*scale+disp8] 5B (df 0x5a797e・ls -l 対応).
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if s == 0x94 && md == 2 {
                    Some(7)
                } else if s == 0x94 && md == 1 && rm != 4 {
                    Some(4)
                } else if (s == 0x95 || s == 0x9E) && md == 2 && rm != 4 {
                    // 95 mod=10 (grep 0x43ddc1)、9E mod=10 (grep 0x43e091)。共に 7B.
                    Some(7)
                } else if (s == 0x94 || s == 0x95) && md == 1 && rm == 4 {
                    // 94 SIB mod=01 (df 0x5a797e)、95 SIB mod=01 (ls -l)。共に 5B.
                    let _ = fourth?;
                    Some(5)
                } else {
                    None
                }
            } else if s == 0x6E {
                // MOVD xmm,m32 (66 0F 6E /r)。reg-direct と mod=00/01/10 (SIBなし)、RIP 7B.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if rm == 4 {
                    None
                } else if md == 1 {
                    Some(4)
                } else if md == 2 || rm == 5 {
                    Some(7)
                } else {
                    Some(3)
                }
            } else if s == 0x6F {
                // MOVDQU xmm,m128 (F3 0F 6F /r) と MOVDQA xmm,m128 RIP (66 0F 6F)。
                // reg-direct と mod=00/01/10、SIB mod=00、RIP (mod=00 rm=101) 7B.
                // F3/66 接頭辞は剥がし済み。16B転送は MOVUPS と等価のため意味論を共有する.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if rm == 4 {
                    // SIB 付き。fourth が SIB バイトである.
                    let t = fourth?;
                    let disp = match md {
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
                    Some(4 + disp)
                } else if md == 1 {
                    Some(4)
                } else if md == 2 || rm == 5 {
                    // mod=10 base+disp32 7B、RIP 7B.
                    Some(7)
                } else {
                    Some(3)
                }
            } else if s == 0x7F {
                // MOVDQU m128,xmm (F3 0F 7F /r) と MOVDQA m128,xmm (66 0F 7F)。
                // reg-direct と mod=00/01/10、SIB mod=00。16B転送は MOVUPS と等価.
                // F3/66 接頭辞は剥がし済み。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if rm == 4 {
                    let t = fourth?;
                    let disp = match md {
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
                    Some(4 + disp)
                } else if md == 1 {
                    Some(4)
                } else if md == 2 || rm == 5 {
                    Some(7)
                } else {
                    Some(3)
                }
            } else if s == 0x2A {
                // CVTSI2SD xmm,m32 (F2 0F 2A /r mod=01 [base+disp8]、4B、SIBなし)。
                // reg-direct (3B) は Cvtsi2sdR64 が使う.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if md == 1 && rm != 4 {
                    Some(4)
                } else {
                    None
                }
            } else if matches!(
                s,
                0x60 | 0x61
                    | 0x62
                    | 0x64
                    | 0x6C
                    | 0xDB
                    | 0xDF
                    | 0xEF
                    | 0xD7
                    | 0x76
                    | 0x57
                    | 0xFC
                    | 0x2F
                    | 0x2C
                    | 0x5C
            ) {
                // XMM reg-direct のみ（66 接頭辞は剥がし済み）。
                let m = third?;
                if m >> 6 == 3 { Some(3) } else { None }
            } else if s == 0x58 {
                // ADDSD xmm,m64 RIP (F2 0F 58 05 + disp32、7B) と reg-direct (3B)、SIB mod=00 (4B、直接番地は disp32 付き 7B)。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if md == 0 && rm == 5 {
                    Some(7)
                } else if rm == 4 {
                    let t = fourth?;
                    if md == 0 {
                        if t & 7 == 5 { Some(7) } else { Some(4) }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else if s == 0x74 || s == 0xEB || s == 0xDA || s == 0xDE || s == 0x54 || s == 0x2E {
                // PCMPEQB/POR/PMINUB/PMAXUB/ANDPD/UCOMISD xmm,m (66 0F 74/EB/DA/DE/54/2E /r)。reg-direct と mod=00/01/10 (SIBなし).
                // POR SIB+disp32 (66 0F EB mod=10 rm=100) は grep 0x43d15b 対応で 8B.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if rm == 4 {
                    if s == 0xEB && md == 2 { Some(8) } else { None }
                } else if md == 1 {
                    Some(4)
                } else if md == 2 || rm == 5 {
                    Some(7)
                } else {
                    Some(3)
                }
            } else if s == 0x7E {
                // MOVQ r64,xmm (reg-direct) と MOVQ xmm,m64 RIP (mod=00 rm=101)、
                // MOVQ xmm,[base+disp8] (mod=01、4B)。
                // F3/66 接頭辞は剥がし済み。REX.W は dispatch で見る。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if md == 0 && rm == 5 {
                    Some(7)
                } else if md == 1 && rm != 4 {
                    // SIB (rm=100) は未対応.
                    Some(4)
                } else {
                    None
                }
            } else if s == 0x70 {
                // PSHUFD xmm,xmm,imm8 (66 0F 70 /r ib)。reg-direct のみ。
                let m = third?;
                if m >> 6 == 3 { Some(4) } else { None }
            } else if s == 0x73 {
                // PSLLDQ xmm,imm8 (66 0F 73 /7 ib) と PSRLDQ xmm,imm8 (66 0F 73 /3 ib)。
                // reg-direct のみ、reg=111 (/7) または reg=011 (/3)。
                let m = third?;
                let reg = (m >> 3) & 7;
                if m >> 6 == 3 && (reg == 7 || reg == 3) {
                    Some(4)
                } else {
                    None
                }
            } else if s == 0xF8 {
                // PSUBB xmm,xmm (66 0F F8 /r)。reg-direct のみ。
                let m = third?;
                if m >> 6 == 3 { Some(3) } else { None }
            } else if s == 0xD6 {
                // MOVQ m64,xmm (66 0F D6 /r)。mod=00/01/10 (SIBなし) と RIP。reg-direct/SIB は未対応.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 || rm == 4 {
                    None
                } else if md == 1 {
                    Some(4)
                } else if md == 2 || rm == 5 {
                    Some(7)
                } else {
                    Some(3)
                }
            } else if s == 0x16 {
                // MOVHPS xmm,m64 (0F 16 /r)。mod=01 [base+disp8] (4B) のみ。SIBなし.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 1 && rm != 4 { Some(4) } else { None }
            } else if s == 0x12 {
                // MOVLPD xmm,m64 (66 0F 12 /r)。mod=00 [base] (3B) のみ。SIB・RIPなし.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 0 && rm != 4 && rm != 5 {
                    Some(3)
                } else {
                    None
                }
            } else if s == 0x59 {
                // MULSD xmm,m64 RIP (F2 0F 59 05 + disp32、7B) と reg-direct (F2 0F 59 /r mod=11、4B)。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if md == 0 && rm == 5 {
                    Some(7)
                } else {
                    None
                }
            } else if s == 0xC1 {
                // XADD r32,m32 (0F C1 /r)。mod=00 [base] (3B) と RIP (7B)。SIBなし.
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 0 && rm == 5 {
                    Some(7)
                } else if md == 0 && rm != 4 && rm != 5 {
                    Some(3)
                } else {
                    None
                }
            } else if s == 0xA5 || s == 0xAD {
                // SHLD/SHRD r/m32,r32,CL (0F A5/AD /r mod=11)。REX.W で64ビット.
                let m = third?;
                if m >> 6 == 3 { Some(3) } else { None }
            } else if s == 0xA3 {
                // BT r/m32,r32 (0F A3 /r mod=11)。
                let m = third?;
                if m >> 6 == 3 { Some(3) } else { None }
            } else if s == 0xAB {
                // BTS r/m32,r32 (0F AB /r mod=11)。REX.W で64ビット.
                let m = third?;
                if m >> 6 == 3 { Some(3) } else { None }
            } else if s == 0xBA {
                // BT/BTS r32/r64,imm8 (0F BA /4 ib と /5 ib reg-direct、4B)。REX.W で64ビット.
                // BT m32,imm8 mod=00 [base] (0F BA /4 + ModRM + imm8、4B)。SIB/RIP 除外.
                // BT m32,imm8 SIB mod=01 [base+disp8] (0F BA /4 + ModRM + SIB + disp8 + imm8、6B).
                let m = third?;
                let md = m >> 6;
                let reg = (m >> 3) & 7;
                let rm = m & 7;
                if (md == 3 && (reg == 4 || reg == 5))
                    || (md == 0 && reg == 4 && rm != 4 && rm != 5)
                {
                    Some(4)
                } else if md == 1 && reg == 4 && rm == 4 {
                    Some(6)
                } else {
                    None
                }
            } else if s == 0x10
                || s == 0x11
                || s == 0x28
                || s == 0x29
                || s == 0xE7
                || s == 0xB6
                || s == 0xB7
                || s == 0xBE
                || s == 0xAF
                || s == 0xBC
                || s == 0xBD
                || s == 0xB1
            {
                // MOVUPS/MOVNTDQ。ModRM/SIB/disp で長さが決まる。
                // reg-direct は MOVUPS のみ（E7 は無効）。
                let m = third?;
                let (md, rm) = (m >> 6, m & 7);
                if md == 3 {
                    if s == 0xE7 { None } else { Some(3) }
                } else if rm == 4 {
                    // SIB 付き。fourth が SIB バイトである.
                    let t = fourth?;
                    let disp = match md {
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
                    Some(4 + disp)
                } else {
                    Some(
                        3 + match md {
                            1 => 1,
                            2 => 4,
                            _ => {
                                if rm == 5 {
                                    4
                                } else {
                                    0
                                }
                            }
                        },
                    )
                }
            } else if (0x80..=0x8F).contains(&s) {
                // near Jcc (0F 80-8F + disp32)。6バイト.
                Some(6)
            } else if (0xC8..=0xCF).contains(&s) {
                // BSWAP r32/r64 (0F C8+rd)。ModRMなし2B。REX.B/W は dispatch で見る.
                Some(2)
            } else {
                None
            }
        }
        // string 操作（A4/A5/AA/AB）は 1 バイト。繰り返しは実行側で回す。
        0xA4 | 0xA5 | 0xAA | 0xAB => Some(1),
        // 0x63 /r (MOVSXD)。reg-direct 2B、mod=00 base 2B / abs 6B、
        // mod=01 base+disp8 3B、mod=10 base+disp32 6B。
        // SIB 付きは disp で長さが変わる (mod=00 base=101 は disp32 付き 7B)。
        0x63 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 {
                let t = third?;
                let disp = match md {
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
            } else if md == 1 {
                Some(3)
            } else if md == 2 || rm == 5 {
                Some(6)
            } else {
                Some(2)
            }
        }
        // 0x69 /r id (IMUL r,r/m,imm32)。reg-direct のみ 6B.
        0x69 => {
            let s = second?;
            if s >> 6 == 3 { Some(6) } else { None }
        }
        // 0x6B /r ib (IMUL r,r/m,imm8)。reg-direct 3B、RIP 7B。SIB は未対応.
        0x6B => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(3)
            } else if rm == 4 {
                None
            } else if md == 0 && rm == 5 {
                Some(7)
            } else {
                None
            }
        }
        // 0x81 /r id (算術 imm32 群)。SIB 付きは未対応。
        // has66 (66 81) は imm16 のため 2B 短くなる.
        0x81 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            let sub = if has66 { 2 } else { 0 };
            if md == 3 {
                Some(6 - sub)
            } else if rm == 4 {
                // mod=00 SIB+imm32 (7B)。base=5 は disp32 が付く。awk 0x4a4354 対応.
                if has66 {
                    None
                } else {
                    let t = third?;
                    if md == 0 && t & 7 != 5 { Some(7) } else { None }
                }
            } else {
                Some(
                    2 + match md {
                        1 => 1,
                        2 => 4,
                        _ => {
                            if rm == 5 {
                                4
                            } else {
                                0
                            }
                        }
                    } + 4
                        - sub,
                )
            }
        }
        // 0x83 /r ib (算術 imm8 群)。SIB は mod=01 no_index の /4 AND のみ.
        0x83 => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if md == 3 {
                Some(3)
            } else if rm == 4 {
                if reg == 5 && md == 1 {
                    // SUB m32,imm8 SIB+disp8。seq 0x4d0bfa の 83 6C 24 58 1C。5B.
                    return Some(5);
                }
                // SIB 付き。mod=01 SIB+disp8+imm8 (5B) の /4 AND と /7 CMP と /1 OR と /0 ADD、
                // mod=00 SIB+imm8 (4B) の /4 AND と /7 CMP、66 mod=00 SIB+imm8 (4B) の /0 ADD のみ.
                let t = third?;
                if md == 2 && reg == 7 {
                    // mod=10 SIB+disp32+imm8 (8B)。true 0x4bed16 対応.
                    Some(8)
                } else if md == 0 && reg == 7 && t & 7 == 5 {
                    // mod=00 base=直接番地 + disp32 + imm8 (8B)。id 0x4c0a78 対応.
                    Some(8)
                } else if (reg == 4 || reg == 7 || reg == 1 || reg == 0)
                    && (md == 1 || (md == 0 && t & 7 != 5))
                {
                    // mod=01 の base=5 は %rbp。直接番地になるのは mod=00 だけ。
                    // sed 0x4c93bc の 83 7C 35 C8 00 は base=rbp。
                    Some(if md == 1 { 5 } else { 4 })
                } else if has66 && reg == 0 && md == 0 && t & 7 != 5 {
                    Some(4)
                } else {
                    None
                }
            } else {
                Some(
                    2 + match md {
                        1 => 1,
                        2 => 4,
                        _ => {
                            if rm == 5 {
                                4
                            } else {
                                0
                            }
                        }
                    } + 1,
                )
            }
        }
        // C6 /0 (MOV r/m8,imm8)。reg-direct 3B、mod=01 4B、mod=01 SIB+disp8 5B、mod=00 SIB 4B.
        0xC6 => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg != 0 {
                return None;
            }
            if md == 3 {
                return Some(3);
            }
            if rm == 4 {
                // SIB 付き。mod=01 SIB+disp8+imm8 (5B)、mod=00 SIB+imm8 (4B)、
                // mod=10 SIB+disp32+imm8 (8B: C6+ModRM+SIB+disp32+imm8).
                if md == 1 {
                    Some(5)
                } else if md == 0 {
                    Some(4)
                } else if md == 2 {
                    Some(8)
                } else {
                    None
                }
            } else if md == 1 {
                Some(4)
            } else if md == 0 && rm != 5 {
                // mod=00 [base],imm8 (3B).
                Some(3)
            } else if md == 0 && rm == 5 {
                // mod=00 RIP [RIP+disp32],imm8 (7B: C6 05 + disp32 + imm8).
                Some(7)
            } else if md == 2 {
                // mod=10 [base+disp32],imm8 (7B).
                Some(7)
            } else {
                None
            }
        }
        // 0x20 /r (AND r/m8,r8)、0x28 /r (SUB r/m8,r8) と 0x30 /r (XOR r/m8,r8)。reg-direct 2B のみ。
        0x20 | 0x28 | 0x30 => {
            let s = second?;
            if s >> 6 == 3 { Some(2) } else { None }
        }
        // 0x08 /r (OR r/m8,r8)。reg-direct 2B、SIB mod=01 +disp8 4B。sed 0x4a87dd 対応.
        0x08 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 && md == 1 {
                Some(4)
            } else {
                None
            }
        }
        // 0x88 /r (MOV r/m8,r8)。mod=00 SIB 直接番地 (base=101) のみ 7B。
        // reg-direct・mod=01/10・SIB index 付きは未対応。
        0x88 | 0x8A | 0x38 | 0x3A => {
            // 88/8A /r (MOV r/m8,r8 / MOV r8,r/m8)、38/3A /r (CMP r/m8,r8 / CMP r8,r/m8)。
            // reg-direct 2B、mod=00 base 2B / abs 6B、mod=01 base+disp8 3B、mod=10 base+disp32 6B。
            // SIB 付きは disp で長さが変わる (mod=00 base=101 は disp32 付き 7B)。
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 {
                let t = third?;
                let disp = match md {
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
            } else if md == 1 {
                Some(3)
            } else if md == 2 || rm == 5 {
                // mod=10 base+disp32 6B、mod=00 abs disp32 6B.
                Some(6)
            } else {
                Some(2)
            }
        }
        // 0x32 /r (XOR r8,r/m8)。mod=00 [base] 2B のみ。cksum 0x5c7fc7 対応.
        // reg-direct・SIB・RIP は未対応で None.
        0x32 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 0 && rm != 4 && rm != 5 {
                Some(2)
            } else {
                None
            }
        }
        // 0x0A /r (OR r8,r/m8)。reg-direct 2B、SIB mod=01 +disp8 4B、RIP 6B.
        0x0A => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if md == 1 && rm == 4 {
                Some(4)
            } else if md == 0 && rm == 5 {
                // OR r8,[RIP+disp32] (0A 05 + disp32)。find 0x5c44a7 対応.
                Some(6)
            } else {
                None
            }
        }
        // 0xC0 /r ib (シフト r/m8,imm8)。reg-direct 3B のみ。SIB・メモリは未対応.
        0xC0 => {
            let s = second?;
            if s >> 6 == 3 { Some(3) } else { None }
        }
        // 0xD0 /5 (SHR r/m8,1)。reg-direct 2B のみ。sed 0x5bdd7d 対応.
        0xD0 => {
            let s = second?;
            if s >> 6 == 3 { Some(2) } else { None }
        }
        // 0x84 /r (TEST r/m8,r8)。reg-direct 2B、mod=00 base 2B / abs 6B、
        // mod=01 base+disp8 3B、mod=10 base+disp32 6B。SIB は未対応で None.
        0x84 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 {
                None
            } else if md == 1 {
                Some(3)
            } else if md == 2 || rm == 5 {
                Some(6)
            } else {
                Some(2)
            }
        }
        // 0xD9 /5 (FLDCW m16)、/7 (FNSTCW m16)。mod=00 base 2B / disp32 6B、
        // mod=01 base+disp8 3B、mod=10 base+disp32 6B。reg-direct・SIB は未対応で None.
        0xD9 => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg == 0 && md == 0 && rm == 5 {
                // FLDS [RIP+disp32] (D9 /0)。seq 0x402335 対応。6B.
                return Some(6);
            }
            if reg == 0 && md == 3 {
                // FLD ST(i) (D9 C0+i)。seq 0x4d0867 の D9 C0。
                return Some(2);
            }
            if reg == 5 && md == 3 && rm == 6 {
                // FLDZ (D9 EE)。seq 0x4d097f。
                return Some(2);
            }
            if reg == 1 && md == 3 {
                // FXCH ST(i) (D9 C8+i)。seq 0x4d0981 の D9 C9。
                return Some(2);
            }
            if reg != 5 && reg != 7 {
                return None;
            }
            if md == 3 || rm == 4 {
                // reg-direct の x87 レジスタ操作と SIB は未対応.
                None
            } else if md == 1 {
                Some(3)
            } else if md == 2 || rm == 5 {
                Some(6)
            } else {
                Some(2)
            }
        }
        // DB /0 SIB mod=01 (FILD m32)。seq 0x4018bc の DB 44 24 20。4B.
        0xDB => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg == 5 && md == 3 {
                // FUCOMI ST(0), ST(i) (DB E8+i)。seq 0x4d0983 の DB E9。
                return Some(2);
            }
            if reg == 5 && md == 0 && rm == 4 {
                // FLD m80 SIB。seq 0x4d74d4 の DB 2C 24。base=5 は disp32。
                let sib = third?;
                if sib & 7 != 5 {
                    return Some(3);
                }
                return None;
            }
            if reg == 5 && md == 1 && rm == 4 {
                // FLD m80 SIB+disp8。seq 0x4d7466 の DB 6C 24 20。4B.
                return Some(4);
            }
            if reg == 5 && md == 2 && rm == 4 {
                // FLD m80 SIB+disp32。seq 0x4d0853 の DB AC 24 80 1D 00 00。7B.
                return Some(7);
            }
            if reg == 7 && md == 1 && rm == 4 {
                // FSTP m80 SIB+disp8。seq 0x4d74d7 の DB 7C 24 20。4B.
                return Some(4);
            }
            if reg == 7 && md == 2 && rm == 4 {
                // FSTP m80 SIB+disp32。seq 0x4d0874 の DB BC 24 80 1D 00 00。7B.
                return Some(7);
            }
            if reg == 7 && md == 0 && rm == 4 {
                // FSTP m80 SIB。seq 0x4d0869 の DB 3C 24。base=5 は disp32。
                let sib = third?;
                if sib & 7 != 5 {
                    return Some(3);
                }
                return None;
            }
            if reg == 7 && md == 0 && rm != 4 && rm != 5 {
                // FSTP m80 [base]。seq 0x4d0725 の DB 3F。
                Some(2)
            } else if reg == 0 && md == 1 && rm == 4 {
                Some(4)
            } else {
                None
            }
        }
        // D8 C0+i (FADD ST(0), ST(i))。reg-direct 2B のみ。seq 0x4d097d の D8 C0。
        // D8 /1 mod=00 rm=5 (FMUL m32 RIP)。seq 0x4d0bf4 の D8 0D。6B.
        0xD8 => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg == 1 && md == 0 && rm == 5 {
                return Some(6);
            }
            if md == 3 && reg == 0 { Some(2) } else { None }
        }
        // DE C8+i (FMULP ST(i))。reg-direct 2B のみ。seq 0x4018c7 の DE C9。
        0xDE => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            if md == 3 && reg == 1 { Some(2) } else { None }
        }
        // DF /5 SIB mod=00 (FILD m64)。seq 0x4018c4 の DF 2C 24。base=5 は disp32。
        0xDF => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg == 5 && md == 0 && rm == 4 {
                let sib = third?;
                if sib & 7 != 5 { Some(3) } else { None }
            } else {
                None
            }
        }
        // DD D8+i (FSTP ST(i))。reg-direct 2B のみ。seq 0x4024ee 対応.
        0xDD => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg == 0 && md == 0 && rm != 4 && rm != 5 {
                // FLDL [base] (DD /0)。seq 0x4d0723 の DD 00。
                Some(2)
            } else if md == 3 && reg == 3 {
                Some(2)
            } else if reg == 3 && md == 1 && rm == 4 {
                // FSTP m64 SIB+disp8。seq 0x4d3169 の DD 5C 24 08。
                Some(4)
            } else {
                None
            }
        }
        // C7 /0 (MOV r/m,imm32 系)。SIB mod=00 は直接番地 (base=101) のみ。
        // has66 (66 C7) は imm16 のため 2B 短くなる.
        0xC7 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            let sub = if has66 { 2 } else { 0 };
            if md == 3 {
                Some(6 - sub)
            } else if rm == 4 {
                // SIB 付き。mod=01 は disp8+imm (8B/6B)、mod=10 は disp32+imm (11B/9B)。
                // mod=00 は SIB base が直接番地 (101) のとき disp32+imm (11B/9B)、
                // それ以外は disp なし+imm (7B/5B)。
                if md == 1 {
                    Some(8 - sub)
                } else if md == 2 {
                    Some(11 - sub)
                } else {
                    let t = third?;
                    if t & 7 == 5 {
                        Some(11 - sub)
                    } else {
                        Some(7 - sub)
                    }
                }
            } else if md == 1 {
                Some(7 - sub)
            } else if md == 2 {
                Some(10 - sub)
            } else {
                // mod=00: rm=5 は disp32+imm (10B/8B)、それ以外は imm のみ (6B/4B)。
                if rm == 5 {
                    Some(10 - sub)
                } else {
                    Some(6 - sub)
                }
            }
        }
        // 80 /r ib (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m8,imm8)。
        // reg-direct: /4 AND と /7 CMP のみ 3B。mod=01: /7 CMP のみ 4B (SIB付きは 5B).
        0x80 => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if md == 3 {
                if reg == 1 || reg == 4 || reg == 7 {
                    Some(3)
                } else {
                    None
                }
            } else if rm == 4 {
                // SIB 付き。mod=01 SIB+disp8+imm8 (5B) の /7 CMP と /1 ORB と /4 ANDB、
                // mod=00 SIB [base] (no_index, non-abs) +imm8 (4B) の /1 ORB と /7 CMPB、
                // mod=10 SIB+disp32+imm8 (8B) の /7 CMPB (stat 0x429875 対応).
                if md == 1 && (reg == 7 || reg == 1 || reg == 4) {
                    Some(5)
                } else if md == 0 && (reg == 1 || reg == 7) {
                    let t = third?;
                    if t & 7 != 5 { Some(4) } else { None }
                } else if md == 2 && reg == 7 {
                    Some(8)
                } else {
                    None
                }
            } else if md == 1 && reg == 7 {
                // mod=01 [base+disp8],imm8 (4B) の /7 CMPB のみ (SIBなし).
                Some(4)
            } else if md == 1 && reg == 1 {
                // mod=01 [base+disp8],imm8 (4B) の /1 ORB。sed 0x5bde04 対応.
                Some(4)
            } else if md == 1 && reg == 4 {
                // mod=01 [base+disp8],imm8 (4B) の /4 ANDB。grep 0x442d1d 対応.
                Some(4)
            } else if md == 2 && reg == 1 {
                // mod=10 [base+disp32],imm8 (7B) の /1 ORB のみ.
                Some(7)
            } else if md == 2 && reg == 4 {
                // mod=10 [base+disp32],imm8 (7B) の /4 ANDB のみ.
                Some(7)
            } else if md == 2 && reg == 7 {
                // mod=10 [base+disp32],imm8 (7B) の /7 CMPB のみ.
                Some(7)
            } else if md == 0 && rm == 5 && reg == 7 {
                // mod=00 RIP [RIP+disp32],imm8 (7B) の /7 CMPB のみ.
                Some(7)
            } else if md == 0 && reg == 1 && rm != 4 && rm != 5 {
                // mod=00 [base],imm8 (3B) の /1 ORB のみ (SIBなし).
                Some(3)
            } else if md == 0 && reg == 7 && rm != 4 && rm != 5 {
                // mod=00 [base],imm8 (3B) の /7 CMPB のみ (SIBなし).
                Some(3)
            } else {
                None
            }
        }
        // F6 /0 (TEST r/m8,imm8)。reg-direct 3B、RIP 7B、SIB mod01 5B.
        0xF6 => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg != 0 {
                return None;
            }
            if md == 3 {
                Some(3)
            } else if md == 0 && rm == 5 {
                Some(7)
            } else if rm == 4 {
                // SIB 付き。mod=01 SIB+disp8+imm8 (5B) と mod=00 SIB+imm8 (4B) の /0 TEST.
                // mod=00 は base!=101 (non-abs) のみ。abs は disp32付き7Bで未対応.
                if md == 1 {
                    Some(5)
                } else if md == 0 {
                    let t = third?;
                    if t & 7 != 5 { Some(4) } else { None }
                } else {
                    None
                }
            } else if md == 1 {
                Some(4)
            } else if md == 0 {
                Some(3)
            } else {
                Some(7)
            }
        }
        // F7 /r (TEST/NOT/NEG/MUL/IMUL/DIV)。reg-direct のみ。
        // /0 TEST は imm32 付きで 6B、/2 NOT・/3 NEG・/4 MUL・/5 IMUL・/6 DIV・/7 IDIV は 2B.
        // 66 F7 /0 mod=00 [base] (TEST m16,imm16) は 66剥離後4B、
        // 66 F7 /0 RIP (TEST m16,imm16) は 66剥離後8B.
        0xF7 => {
            let s = second?;
            if s >> 6 != 3 {
                let md = s >> 6;
                let reg = (s >> 3) & 7;
                let rm = s & 7;
                if has66 && md == 0 && reg == 0 && rm != 4 && rm != 5 {
                    Some(4)
                } else if has66 && md == 1 && reg == 0 && rm != 4 {
                    // TEST m16,imm16 mod=01 [base+disp8] (66剥離後5B)。hexdump 0x5c8822 対応.
                    Some(5)
                } else if has66 && md == 0 && reg == 0 && rm == 5 {
                    Some(8)
                } else if md == 0 && reg == 0 && rm == 5 {
                    // TEST m32,imm32 RIP (F7 05 + disp32 + imm32、10B)。ls 0x4963b6 対応.
                    Some(10)
                } else if md == 0 && reg == 0 && rm != 4 && rm != 5 {
                    // TEST m32,imm32 mod=00 [base] (6B: F7 /0 + ModRM + imm32)。tac 0x5b0ca8 対応.
                    Some(6)
                } else if md == 1 && reg == 0 && rm != 4 {
                    // TEST m32,imm32 mod=01 [base+disp8] (7B)。echo 0x4bfb84 対応.
                    Some(7)
                } else if md == 1 && reg == 6 && rm != 4 {
                    // DIV r/m32 mod=01 [base+disp8] (3B: F7 /6 + ModRM + disp8).
                    Some(3)
                } else if md == 1 && reg == 6 && rm == 4 {
                    // DIV r/m32 SIB mod=01 [base+index*scale+disp8] (4B: F7 /6 + ModRM + SIB + disp8).
                    let _ = third?;
                    Some(4)
                } else if md == 0 && reg == 6 && rm == 4 {
                    // DIV r/m32 SIB mod=00 (3B)。base=5 は disp32。xxd 0x473876 対応.
                    let t = third?;
                    if t & 7 != 5 { Some(3) } else { None }
                } else {
                    None
                }
            } else {
                let reg = (s >> 3) & 7;
                if reg == 0 {
                    Some(6)
                } else if reg == 2 || reg == 3 || reg == 4 || reg == 5 || reg == 6 || reg == 7 {
                    Some(2)
                } else {
                    None
                }
            }
        }
        // 0x22 /r (AND r8,m8)。mod=10 [base+disp32] 6B のみ.
        0x22 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 2 && rm != 4 { Some(6) } else { None }
        }
        // 0x03 /r (ADD)、0x01 /r (ADD)、0x09 /r (OR)、0x0B /r (OR)、0x39 /r (CMP)、0x3B /r (CMP)、0x2B /r (SUB)、
        // 0x33 /r (XOR)、0x23 /r (AND)、0x13 /r (ADC)、0x1B /r (SBB)。
        // reg-direct 2B、mod=00 base 2B / RIP/abs 6B、mod=01 3B、mod=10 6B。
        // SIB は mod=00 直接番地のみ 7B.
        0x03 | 0x01 | 0x09 | 0x0B | 0x39 | 0x3B | 0x2B | 0x33 | 0x23 | 0x13 | 0x1B => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 {
                // SIB 付き。disp の有無は SIB base で決まる。
                let t = third?;
                let disp = match md {
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
            } else if md == 0 && rm == 5 {
                Some(6)
            } else if md == 0 {
                Some(2)
            } else if md == 1 {
                Some(3)
            } else {
                // mod=10 base+disp32 6B.
                Some(6)
            }
        }
        // 0xFF /r (INC/DEC/CALL/JMP)。/0 INC・/1 DEC・/2 CALL・/4 JMP のみ mod=00/01/10/11 (SIB直接番地含む).
        0xFF => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg == 6 && md == 1 && rm == 4 {
                // PUSH m SIB+disp8。seq 0x4d1a81 の FF 74 24 68。
                return Some(4);
            }
            if reg != 0 && reg != 1 && reg != 2 && reg != 4 {
                return None;
            }
            if md == 3 {
                Some(2)
            } else if rm == 4 {
                let t = third?;
                if md == 1 {
                    Some(4)
                } else if md == 2 || t & 7 == 5 {
                    // mod=10 SIB+disp32 7B、mod=00 SIB直接番地 7B.
                    Some(7)
                } else {
                    Some(3)
                }
            } else if md == 1 {
                Some(3)
            } else if md == 2 || rm == 5 {
                // mod=10 base+disp32 6B、mod=00 abs disp32 6B.
                Some(6)
            } else {
                Some(2)
            }
        }
        // register-direct と ModRMメモリ (SIBなし) に対応するALU opcode。
        // SIB付き (rm==4) は未対応で None。mod=01は+1、mod=10は+4、mod=00 rm=5は+4。
        0x29 | 0x31 | 0x21 | 0x11 | 0x19 | 0x87 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                return Some(2);
            }
            if rm == 4 {
                // SUB m,r SIB+disp8 (29 /r mod=01)。wc 0x49e1db 対応.
                // mod=01 は SIB の base に依らず disp8 が付く。
                if first == 0x29 && md == 1 {
                    return Some(4);
                }
                return None;
            }
            Some(
                2 + match md {
                    1 => 1,
                    2 => 4,
                    _ => {
                        if rm == 5 {
                            4
                        } else {
                            0
                        }
                    }
                },
            )
        }
        // 0x85 /r (TEST r,m)。reg-direct 2B、SIB mod=00 3B、SIB mod=01 +disp8 4B、SIB mod=10 +disp32 7B、
        // mod=01 base+disp8 3B、mod=10 base+disp32 6B、mod=00 base 2B / abs disp32 6B。SIB mod=00 base=5 は未対応.
        0x85 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 {
                if md == 1 {
                    Some(4)
                } else if md == 2 {
                    // SIB+disp32 (85 /r mod=10 rm=100)。grep 0x43d250 対応.
                    Some(7)
                } else {
                    // mod=00 SIB (3B)。base=5 は disp32。awk 0x4a1c82 対応.
                    let t = third?;
                    if t & 7 != 5 { Some(3) } else { None }
                }
            } else if md == 1 {
                Some(3)
            } else if md == 2 || rm == 5 {
                Some(6)
            } else {
                Some(2)
            }
        }
        // 0xC1 (シフト) は register-direct のみ 3B。
        0xC1 => {
            let s = second?;
            if s >> 6 == 3 { Some(3) } else { None }
        }
        // 0xD1 (CL シフト) は register-direct のみ 2B。/7 SAR のみ実装 (他は decode 失败)。
        0xD1 => {
            let s = second?;
            if s >> 6 == 3 { Some(2) } else { None }
        }
        0xD3 => {
            let s = second?;
            if s >> 6 == 3 { Some(2) } else { None }
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
// Gap: GAP-0007
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
    // 呼び出し前に wait4 で止まっていれば、子から再開する。
    let _ = sys.on_block(env);
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
        // 接頭辞（F0/F3・REX・0x66・0x67・セグメント）をデコード前に剥がす。順不同に対応する。
        // 0x67 は 64ビットモードのみ受け付け、32ビットアドレス指定とみなす
        // （4GB 未満では u64 演算と等価のため意味論への影響はない）。
        // F3 は string 命令でのみ意味を持つ。0x66 は NOP/XMM 系でのみ受け付ける。
        // F0 (LOCK) は単一スレッド試作として無視する。
        // FS 上書き（0x64）は記録し、対応するメモリ形式で FS ベースを加算する。
        // その他のセグメント上書き（2E/3E/26/65/36）は無視する（4GB 未満では等価）。
        let mut off: u64 = 0;
        let mut rep = false;
        let mut rex: u8 = 0;
        let mut has66 = false;
        let mut has_f2 = false;
        let mut has_fs = false;
        loop {
            if head[0] == 0xF3 && !rep {
                rep = true;
            } else if head[0] == 0xF2 && !has_f2 {
                // REPNE 接頭辞。string 反復と SSE (PSHUFLW) で使う.
                has_f2 = true;
            } else if head[0] == 0xF0 {
                // LOCK 接頭辞。単一スレッドのため無視する.
            } else if is64 && (0x40..=0x4F).contains(&head[0]) && rex == 0 {
                rex = head[0];
            } else if head[0] == 0x66 {
                // オペランドサイズ接頭辞。NOP/XMM 系でのみ受け付ける（追随者はゲートで絞る）。
                has66 = true;
            } else if is64 && head[0] == 0x67 {
                // アドレスサイズ接頭辞。複数あっても1バイトずつ剥がす。
            } else if head[0] == 0x64 && !has_fs {
                // FS 上書き。dispatch 側で FS ベースを加算する。
                has_fs = true;
            } else if matches!(head[0], 0x2E | 0x3E | 0x26 | 0x65 | 0x36) {
                // セグメント上書き。4GB 未満では無視してよい。
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
            0x01 | 0x8B
                | 0x29
                | 0x31
                | 0x39
                | 0x21
                | 0x85
                | 0x89
                | 0x03
                | 0x0B
                | 0x3B
                | 0x2B
                | 0x33
                | 0x23
                | 0x13
                | 0x1B
                | 0x87
                | 0xFF
                | 0x09
                | 0x11
                | 0x19
                | 0xC1
                | 0xD1
                | 0xD3
                | 0xC7
                | 0x81
                | 0x83
                | 0x63
                | 0x69
                | 0x6B
                | 0x8D
                | 0x0F
                | 0xF7
                | 0xF6
                | 0x80
                | 0xC6
                | 0x88
                | 0x8A
                | 0x38
                | 0x3A
                | 0x20
                | 0x28
                | 0x30
                | 0x32
                | 0x08
                | 0x22
                | 0x84
                | 0xD9
                | 0xDB
                | 0xDF
                | 0xDE
                | 0xD8
                | 0xDD
                | 0x0A
                | 0xC0
                | 0xD0
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
        // 2バイトオペコード（0F）では third=ModRM、fourth=SIB である。
        // C7/0x88/0x8A/0x38/0x3A は SIB の base で mod=00 の長さが変わるため同様に読む。
        let third = if (matches!(
            head[0],
            0x8B | 0x89
                | 0x8D
                | 0xC7
                | 0xC6
                | 0x88
                | 0x8A
                | 0x38
                | 0x3A
                | 0x87
                | 0x85
                | 0x83
                | 0x81
                | 0x63
                | 0x01
                | 0x03
                | 0x09
                | 0x0B
                | 0x39
                | 0x3B
                | 0x2B
                | 0x33
                | 0x23
                | 0x13
                | 0x1B
                | 0x80
                | 0xF6
                | 0xF7
                | 0xFF
                | 0xDB
                | 0xDF
        ) && matches!(second, Some(s) if s & 7 == 4 && s >> 6 != 3))
            || (head[0] == 0x0F
                && (matches!(
                    second,
                    Some(
                        0x1F | 0x6E
                            | 0x6F
                            | 0x7F
                            | 0x60
                            | 0x61
                            | 0x62
                            | 0x6C
                            | 0x70
                            | 0x73
                            | 0x74
                            | 0x64
                            | 0x76
                            | 0x12
                            | 0x16
                            | 0x57
                            | 0xDF
                            | 0xFC
                            | 0x2A
                            | 0x58
                            | 0x2E
                            | 0x2F
                            | 0x2C
                            | 0x54
                            | 0x5C
                            | 0x59
                            | 0xBA
                            | 0xC1
                            | 0x7E
                            | 0xD7
                            | 0xDA
                            | 0xDE
                            | 0xDB
                            | 0xEB
                            | 0xEF
                            | 0xF8
                            | 0xD6
                            | 0x10
                            | 0x11
                            | 0x28
                            | 0x29
                            | 0xE7
                            | 0xB6
                            | 0xB7
                            | 0xBE
                            | 0xAF
                            | 0xBC
                            | 0xBD
                            | 0xB1
                            | 0xA5
                            | 0xAD
                            | 0xA3
                            | 0xAB
                    )
                ) || matches!(second, Some(0x40..=0x4F))
                    || matches!(second, Some(0x90..=0x9F))))
        {
            let mut modrm = [0u8; 1];
            if env
                .backend
                .mem
                .read(VirtAddr(pc + off + 2), &mut modrm, acc_fetch())
                .is_err()
            {
                return Outcome::Unimplemented {
                    eip: pc as u32,
                    word: head[0] as u128,
                };
            }
            Some(modrm[0])
        } else {
            None
        };
        // 0F MOVUPS/MOVNTDQ/NOP の SIB 付きは第4バイト（SIB）で長さが変わる。
        let fourth = if head[0] == 0x0F
            && matches!(
                second,
                Some(
                    0x10 | 0x11
                        | 0x28
                        | 0x29
                        | 0x6F
                        | 0x7F
                        | 0x94
                        | 0x95
                        | 0xE7
                        | 0x1F
                        | 0xB6
                        | 0xB7
                        | 0xBE
                        | 0xAF
                        | 0xBC
                        | 0xBD
                        | 0xB1
                        | 0x58
                        | 0xEB
                )
            )
            || matches!(second, Some(0x40..=0x4F))
                && matches!(third, Some(m) if m & 7 == 4 && m >> 6 != 3)
        {
            let mut sib = [0u8; 1];
            if env
                .backend
                .mem
                .read(VirtAddr(pc + off + 3), &mut sib, acc_fetch())
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
        let rex_w = rex & 8 != 0;
        let Some(base) = fetch_len(head[0], second, third, fourth, has66, rex_w) else {
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
                    | 0x90
                    | 0x91
                    | 0x92
                    | 0x93
                    | 0x94
                    | 0x95
                    | 0x96
                    | 0x97
                    | 0x01
                    | 0x03
                    | 0x0B
                    | 0x3B
                    | 0x2B
                    | 0x33
                    | 0x23
                    | 0x22
                    | 0x13
                    | 0x1B
                    | 0xFF
                    | 0x11
                    | 0x19
                    | 0x29
                    | 0x31
                    | 0x39
                    | 0x21
                    | 0x09
                    | 0x85
                    | 0xF7
                    | 0xF6
                    | 0x80
                    | 0xC6
                    | 0x88
                    | 0x8A
                    | 0x38
                    | 0x3A
                    | 0x20
                    | 0x28
                    | 0x30
                    | 0x32
                    | 0x08
                    | 0x87
                    | 0x84
                    | 0xC0
                    | 0xD0
                    | 0xC1
                    | 0xD1
                    | 0xD3
                    | 0x05
                    | 0x2D
                    | 0x3D
                    | 0x25
                    | 0x0D
                    | 0x35
                    | 0x8D
                    | 0xC7
                    | 0x83
                    | 0x81
                    | 0x63
                    | 0x69
                    | 0x6B
                    | 0x98
                    | 0x99
                    | 0x0F
                    | 0xA4
                    | 0xA5
                    | 0xA9
                    | 0xAA
                    | 0xAB
                    | 0xB8..=0xBF
                    | 0xB0..=0xB7
                    | 0x6A
                    | 0x68
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
        let mut bytes = [0u8; 16];
        bytes[0] = head[0];
        if base >= 2 {
            // 長さ判定用のぞき見を使う。なければ読み直す。
            bytes[1] = second.unwrap_or(0);
        }
        if base >= 3 {
            bytes[2] = third.unwrap_or(0);
        }
        if base >= 4 {
            bytes[3] = fourth.unwrap_or(0);
        }
        for i in 1..base {
            if i == 1 && second.is_some() {
                continue;
            }
            if i == 2 && third.is_some() {
                continue;
            }
            if i == 3 && fourth.is_some() {
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
        // 0x66 接頭辞は XMM/NOP/16bit-RIP 系でのみ有効。それ以外は未対応。
        // 32ビットでの 0x66（16ビット動作）は未対応。Nopl のみ 32ビットでも通す。
        if has66 && !is64 && !matches!(insn, Insn::Nopl) {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        }
        if has66
            && !matches!(
                insn,
                Insn::Nop
                    | Insn::Nopl
                    | Insn::TestRm32
                    | Insn::TestM16ImmMemnd
                    | Insn::TestM16ImmMem8
                    | Insn::TestM16ImmRip
                    | Insn::MovlpdXmmM64Memnd
                    | Insn::MovdXmm
                    | Insn::MovdXmmM32
                    | Insn::MovdXmmRip
                    | Insn::Punpcklbw
                    | Insn::Punpcklwd
                    | Insn::Punpckldq
                    | Insn::MovqM64XmmRip
                    | Insn::MovqM64XmmMemnd
                    | Insn::MovqM64XmmMem8
                    | Insn::MovqM64XmmMem32
                    // MOVHPD (66 0F 16) は MOVHPS (0F 16) と等価のため Insn を共用する.
                    | Insn::MovhpsXmmM64Mem8
                    | Insn::Pshufd
                    | Insn::Pslldq
                    | Insn::Psrldq
                    | Insn::Psubb
                    | Insn::Paddb
                    | Insn::Pcmpgtb
                    | Insn::Pxor
                    | Insn::Pand
                    | Insn::Pandn
                    | Insn::Pminub
                    | Insn::Pmaxub
                    | Insn::Pcmpeqb
                    | Insn::Pcmpeqd
                    | Insn::Por
                    | Insn::Pmovmskb
                    | Insn::PcmpeqbMemnd
                    | Insn::PcmpeqbMem8
                    | Insn::PcmpeqbMem32
                    | Insn::PminubMemnd
                    | Insn::PminubMem8
                    | Insn::PminubMem32
                    | Insn::PorMemnd
                    | Insn::PorMem8
                    | Insn::PorMem32
                    | Insn::PorSibd32
                    | Insn::MovSibdEax
                    | Insn::MovEaxSibd
                    | Insn::Punpcklqdq
                    | Insn::MovqR64Xmm
                    | Insn::MovupsLoadXmm
                    | Insn::MovupsStoreXmm
                    // MOVAPD (66 0F 28) は MOVAPS と等価のため Insn を共用する.
                    | Insn::MovapsLoadXmm
                    | Insn::MovupsLoadMemnd
                    | Insn::MovupsStoreMemnd
                    | Insn::MovupsLoadMem8
                    | Insn::MovupsStoreMem8
                    | Insn::MovupsLoadMem32
                    | Insn::MovupsStoreMem32
                    | Insn::MovupsLoadSib
                    | Insn::MovupsStoreSib
                    | Insn::MovupsLoadSibd
                    | Insn::MovupsStoreSibd
                    | Insn::MovntdqStoreMemnd
                    | Insn::MovntdqStoreMem8
                    | Insn::MovapsStoreMemnd
                    | Insn::MovapsStoreMem8
                    | Insn::MovapsStoreMem32
                    | Insn::MovSibEax
                    | Insn::MovEaxSib
                    | Insn::NoplSib
                    | Insn::NoplSibd
                    | Insn::NoplSibd32
                    | Insn::MovupsLoadRip
                    | Insn::MovupsStoreRip
                    | Insn::MovdqaLoadRip
                    | Insn::Comisd
                    | Insn::Ucomisd
                    | Insn::UcomisdMemnd
                    | Insn::UcomisdMem8
                    | Insn::UcomisdMem32
                    | Insn::UcomisdRip
                    | Insn::Andpd
                    | Insn::AndpdRip
                    // MOV [base],r16 (66 89 mod=00) は MovMemndEax を共用する.
                    | Insn::MovMemndEax
                    | Insn::MovdquLoadXmm
                    | Insn::MovdquLoadMemnd
                    | Insn::MovdquLoadMem8
                    | Insn::MovdquLoadMem32
                    | Insn::MovdquLoadSib
                    | Insn::MovdquStoreXmm
                    | Insn::MovdquStoreMemnd
                    | Insn::MovdquStoreMem8
                    | Insn::MovdquStoreMem32
                    | Insn::MovdquStoreSib
                    | Insn::MovAbsEax
                    | Insn::MovEaxAbs
                    | Insn::MovRm16ImmM32
                    | Insn::MovRm16ImmMemnd
                    | Insn::MovRm16ImmMem8
                    | Insn::MovRm16ImmSibd
                    | Insn::MovRm16ImmSib
                    | Insn::MovRm16ImmRip
                    | Insn::AndAxImm16
                    | Insn::ShrRm32Imm8
                    | Insn::CmpAxImm16
                    | Insn::OrAxImm16
                    | Insn::AddRm16Imm
                    | Insn::AndRm16Imm
                    | Insn::CmpRm16Imm
                    | Insn::CmpRmImm8Rip
                    // MOV [base+disp32],r16 (66 89 mod=10) は MovMemEax32 を共用する.
                    | Insn::MovMemEax32
                    // MOV [base+disp8],r16 (66 89 mod=01) は MovMemEax8 を共用する.
                    | Insn::MovMemEax8
                    // ADD m16,imm8 SIB (66 83 /0 mod=00).
                    | Insn::AddM16ImmSib
                    // AND m16,imm8 SIB+disp8 (66 83 /4 mod=01).
                    | Insn::AndRmImm8Sibd
                    // SUB m16,imm8 SIB+disp8 (66 83 /5 mod=01).
                    | Insn::SubRmImm8Sibd
            )
        {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        }
        // XMM 系は 0x66 が必須（MOVUPS を除く）。剥がし忘れを防ぐ。
        // PSHUFD は F2 (PSHUFLW) でも有効のため、ここでは除いて後段で判定する.
        if !has66
            && matches!(
                insn,
                Insn::MovdXmm
                    | Insn::MovdXmmM32
                    | Insn::MovdXmmRip
                    | Insn::Punpcklbw
                    | Insn::Punpcklwd
                    | Insn::Punpckldq
                    | Insn::MovqM64XmmRip
                    | Insn::MovqM64XmmMemnd
                    | Insn::MovqM64XmmMem8
                    | Insn::MovqM64XmmMem32
                    | Insn::Pslldq
                    | Insn::Psrldq
                    | Insn::Psubb
                    | Insn::Pxor
                    | Insn::Pand
                    | Insn::Pminub
                    | Insn::Pmaxub
                    | Insn::Pcmpeqb
                    | Insn::Pcmpeqd
                    | Insn::Por
                    | Insn::Pmovmskb
                    | Insn::PcmpeqbMemnd
                    | Insn::PcmpeqbMem8
                    | Insn::PcmpeqbMem32
                    | Insn::PminubMemnd
                    | Insn::PminubMem8
                    | Insn::PminubMem32
                    | Insn::PorMemnd
                    | Insn::PorMem8
                    | Insn::PorMem32
                    | Insn::PorSibd32
                    | Insn::Punpcklqdq
                    | Insn::MovqR64Xmm
                    | Insn::MovRm16ImmM32
                    | Insn::MovRm16ImmMemnd
                    | Insn::MovRm16ImmMem8
                    | Insn::MovRm16ImmSibd
                    | Insn::MovRm16ImmSib
                    | Insn::MovRm16ImmRip
                    | Insn::MovntdqStoreMemnd
                    | Insn::MovntdqStoreMem8
                    | Insn::MovdqaLoadRip
            )
        {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        }
        // PSHUFD/PSHUFLW は 66/F2 のいずれかが必須。
        if matches!(insn, Insn::Pshufd) && !has66 && !has_f2 {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        }
        // CVTSI2SD (F2 0F 2A) と SUBPS (0F 2A) は符号化を共用する。F2 なしは未対応.
        if matches!(insn, Insn::Cvtsi2sdM32Mem8) && !has_f2 {
            return Outcome::Unimplemented {
                eip: pc as u32,
                word,
            };
        }
        // REX 拡張は reg/rm/SIB 抽出で対応済み (R/R/B/X)。W は rex_w で切替.
        let _ = rex;
        // FS 上書きの有無とベース。dispatch 側で FS 相対アドレッシングに使う.
        let fs = has_fs.then(|| sys.fs_base());
        // imm/disp の取り出し。32ビット値は LE 実バイト列から復元する。
        let imm32 = || (word as u32).swap_bytes();
        let disp8 = || (word & 0xff) as u8 as i8;
        let eip = pc as u32;
        // 意味論が分岐を取ると backend.ctrl に Jump が残る（取らなければ
        // Fallthrough）。eip 等値での判定は自己ループで誤るため使わない。
        use polyisa_engine::interp::Ctrl;
        let r = env.step(|b| {
            dispatch(
                b, insn, eip, word, nbytes, off, is64, rex, has66, has_f2, rep, fs, imm32, disp8,
            )
        });
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
                    TrapOutcome::Exit(code) => {
                        if !sys.take_exit(env, code) {
                            return Outcome::Exit(code);
                        }
                    }
                    TrapOutcome::Blocked => {
                        if !sys.on_block(env) {
                            return Outcome::Deadlock;
                        }
                    }
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
        sys.after_step(env);
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
    has66: bool,
    has_f2: bool,
    rep: bool,
    fs: Option<u64>,
    imm32: impl Fn() -> u32,
    disp8: impl Fn() -> i8,
) -> Result<(), B::Exit> {
    use polyisa_guest_x86::sem::{Gpr, Xmm};
    let disp32 = || imm32() as i32;
    // ModRM register-direct の reg/rm 抽出。ModRM は先頭から 2+off バイト目にあり、
    // word（opcode 上位詰め）内の位置は命令長で決まる。REX.R/B で 8-15 に拡張する。
    let modrm = || ((word >> ((nbytes - 2 - off) * 8)) & 0xff) as u8;
    let reg = || Gpr(((modrm() >> 3) & 7) | (((rex >> 2) & 1) << 3));
    let rm = || Gpr((modrm() & 7) | ((rex & 1) << 3));
    // 2バイトオペコード（0F）の ModRM 抽出。ModRM は先頭から 3+off バイト目にある。
    let modrm0f = || ((word >> ((nbytes - 3 - off) * 8)) & 0xff) as u8;
    let xmm_reg = || Xmm((modrm0f() >> 3) & 7);
    // REX.R/B で 8-15 に拡張する XMM 抽出（MOVDQA reg-direct 等で使う）。
    let xmm_reg_r = || Xmm(((modrm0f() >> 3) & 7) | (((rex >> 2) & 1) << 3));
    let xmm_rm_b = || Xmm((modrm0f() & 7) | ((rex & 1) << 3));
    let rm0f = || Gpr((modrm0f() & 7) | ((rex & 1) << 3));
    // 2バイトオペコードの SIB 抽出。SIB は先頭から 4+off バイト目にある。
    let sib0f = || ((word >> ((nbytes - 4 - off) * 8)) & 0xff) as u8;
    let sib0f_shift = || ((sib0f() >> 6) & 3) as u32;
    let sib0f_idx_raw = || (sib0f() >> 3) & 7;
    let sib0f_idx = || Gpr(sib0f_idx_raw() | (((rex >> 1) & 1) << 3));
    let sib0f_base = || Gpr((sib0f() & 7) | ((rex & 1) << 3));
    let sib0f_no_index = || sib0f_idx_raw() == 4 && (rex >> 1) & 1 == 0;
    let reg0f_as_gpr = || Gpr(((modrm0f() >> 3) & 7) | (((rex >> 2) & 1) << 3));
    // has66 は呼び出し側で検証済み（XMM/NOP 系のみ通過）。
    let _ = has66;
    // PUSH/POP のレジスタは opcode 下位3ビット + REX.B。
    let push_r = || Gpr(((word as u8) & 7) | ((rex & 1) << 3));
    // REX.W の有無で 32/64ビット意味論を選ぶ。
    let rex_w = rex & 8 != 0;
    // SIB バイトと scale/index/base の抽出。SIB 付き命令でのみ呼ぶ。
    let sib = || ((word >> ((nbytes - 3 - off) * 8)) & 0xff) as u8;
    let sib_shift = || ((sib() >> 6) & 3) as u32;
    let sib_idx_raw = || (sib() >> 3) & 7;
    let sib_idx = || Gpr(sib_idx_raw() | (((rex >> 1) & 1) << 3));
    let sib_base = || Gpr((sib() & 7) | ((rex & 1) << 3));
    // SIB index なし（100 + REX.X なし）は base のみで扱う。
    let no_index = || sib_idx_raw() == 4 && (rex >> 1) & 1 == 0;
    let r: Result<(), B::Exit> = match insn {
        Insn::Nop => {
            // 90 は NOP と共有。REX.B 付き (41 90/49 90) は XCHG RAX,R8 のため交換する.
            // 48 90 (W のみ) は XCHG RAX,RAX のため NOP と等価.
            if rex & 1 != 0 {
                let dst = Gpr(((word as u8) & 7) | ((rex & 1) << 3));
                if rex_w {
                    sem::xchg_r64_ax(b, dst)
                } else {
                    sem::xchg_r32_ax(b, dst)
                }
            } else {
                sem::nop(b)
            }
        }
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
        Insn::IncRm => {
            // FF /0 reg-direct。rm() が対象.
            if rex_w {
                sem::inc_r64(b, rm())
            } else {
                sem::inc_r32(b, rm())
            }
        }
        Insn::IncRmMemnd => {
            // FF /0 mod=00 [base]。CF 以外の 5 旗を更新する.
            sem::inc_r32_memnd(b, rm())
        }
        Insn::IncRmSib => {
            // FF /0 SIB mod=00 [base+index*scale]。sed 0x4ca2c7 対応。CF は残す.
            if no_index() {
                sem::inc_r32_memnd(b, sib_base())
            } else {
                sem::inc_r32_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::IncRmSibd => {
            // FF /0 SIB mod=01 [base+index*scale+disp8]。CF 以外の 5 旗を更新する.
            if no_index() {
                sem::inc_r32_mem8(b, sib_base(), disp8())
            } else {
                sem::inc_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::IncRmSibd32 => {
            // FF /0 SIB mod=10 [base+index*scale+disp32]。basename 0x4899d0 対応.
            if no_index() {
                sem::inc_r32_mem32(b, sib_base(), disp32())
            } else {
                sem::inc_r32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::DecRm => {
            // FF /1 reg-direct。
            if rex_w {
                sem::dec_r64(b, rm())
            } else {
                sem::dec_r32(b, rm())
            }
        }
        Insn::DecRmSib => {
            // FF /1 SIB mod=00 [base+index*scale]。xxd 0x4b2bee 対応。CF は残す.
            if no_index() {
                sem::dec_r32_memnd(b, sib_base())
            } else {
                sem::dec_r32_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::DecRmSibd => {
            // FF /1 SIB mod=01 [base+index*scale+disp8]。CF 以外の 5 旗を更新する.
            if no_index() {
                sem::dec_r32_mem8(b, sib_base(), disp8())
            } else {
                sem::dec_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::IncRmMem32 => {
            // FF /0 mod=10 [base+disp32]。uname 0x4b3c4a 対応.
            sem::inc_r32_mem32(b, rm(), disp32())
        }
        Insn::IncRmMem8 => {
            // FF /0 mod=01 [base+disp8] (SIBなし)。CF 以外の 5 旗を更新する.
            sem::inc_r32_mem8(b, rm(), disp8())
        }
        Insn::IncRmRip => {
            // FF /0 mod=00 rm=101 [RIP+disp32]。sed 0x5bdcc0 対応.
            sem::inc_r32_rip(b, eip as u64 + nbytes, disp32())
        }
        Insn::DecRmMem8 => {
            // FF /1 mod=01 [base+disp8] (SIBなし)。CF 以外の 5 旗を更新する.
            sem::dec_r32_mem8(b, rm(), disp8())
        }
        Insn::DecRmRip => {
            // FF /1 mod=00 rm=101 [RIP+disp32]。du -s 0x5a7fe7 対応.
            sem::dec_r32_rip(b, eip as u64 + nbytes, disp32())
        }
        Insn::AddEax => {
            if rex_w {
                sem::add_rm64_imm(b, Gpr(0), imm32())
            } else {
                sem::add_eax(b, imm32())
            }
        }
        Insn::Jmp8 => sem::jmp8(b, eip.wrapping_add(2).wrapping_add(disp8() as i32 as u32)),
        Insn::MovR32Imm => {
            // B8+r：dst は opcode 下3ビット（REX.B で拡張）。
            let dst = Gpr((((word >> 32) & 7) as u8) | ((rex & 1) << 3));
            if rex_w {
                sem::mov_rm64_imm(b, dst, imm32())
            } else {
                sem::mov_r32_imm(b, dst, imm32())
            }
        }
        Insn::MovR64Imm64 => {
            // B8+r + imm64 (REX.W MOVABS)。dst は opcode 下3ビット + REX.B、imm は最下位64 LE.
            let dst = Gpr((((word >> 64) & 7) as u8) | ((rex & 1) << 3));
            let imm = (word as u64).swap_bytes();
            sem::mov_r64_imm64(b, dst, imm)
        }
        Insn::MovR8Imm => {
            // B0+r ib: dst は opcode 下3ビット + REX.B。REX ありは低8、なしの4-7は上位8.
            let reg_f = ((word >> 8) & 7) as u8;
            let imm = (word & 0xff) as u8;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex & 1) << 3)), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::mov_r8_imm(b, dst, high, imm)
        }
        Insn::Syscall => sem::syscall(b, eip),
        Insn::Cpuid => sem::cpuid(b),
        Insn::Endbr64 => sem::nop(b),
        Insn::Hlt => sem::nop(b),
        Insn::Rdsspq => sem::nop(b),
        Insn::Nopl => sem::nop(b),
        Insn::NoplMem8 => sem::nop(b),
        Insn::NoplMem32 => sem::nop(b),
        Insn::AddRm32 => {
            if rex_w {
                sem::add_rm64(b, rm(), reg())
            } else {
                sem::add_rm32(b, rm(), reg())
            }
        }
        Insn::XchgRRm => {
            if rex_w {
                sem::xchg_r64(b, reg(), rm())
            } else {
                sem::xchg_r32(b, reg(), rm())
            }
        }
        Insn::XchgRMemnd => {
            if rex_w {
                sem::xchg_r64_memnd(b, reg(), rm())
            } else {
                sem::xchg_r32_memnd(b, reg(), rm())
            }
        }
        Insn::XchgRMem8 => {
            if rex_w {
                sem::xchg_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::xchg_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::XchgRMem32 => {
            if rex_w {
                sem::xchg_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::xchg_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::XchgRRip => {
            if rex_w {
                sem::xchg_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::xchg_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                // 32ビット絶対番地は未対応 (RIP 想定のため暫定)。
                sem::xchg_r32_memnd(b, reg(), rm())
            }
        }
        Insn::AddM32R32Memnd => {
            if rex_w {
                sem::add_m64_r64_memnd(b, rm(), reg())
            } else {
                sem::add_m32_r32_memnd(b, rm(), reg())
            }
        }
        Insn::AddM32R32Mem8 => {
            if rex_w {
                sem::add_m64_r64_mem8(b, rm(), disp8(), reg())
            } else {
                sem::add_m32_r32_mem8(b, rm(), disp8(), reg())
            }
        }
        Insn::CmpM32R32Sibabs => {
            // 39 /r SIB mod=00 base=101。id 0x4bfd44 対応.
            if no_index() {
                if rex_w {
                    sem::cmp_rm64_abs(b, disp32(), reg())
                } else {
                    sem::cmp_rm32_abs(b, disp32() as u32, reg())
                }
            } else if rex_w {
                sem::cmp_m64_r64_sibabs(b, sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::cmp_m32_r32_sibabs(b, sib_idx(), sib_shift(), disp32(), reg())
            }
        }
        Insn::AddM32R32Sibabs => {
            // 01 /r SIB mod=00 base=101。echo 0x4c08d1 対応.
            if no_index() {
                if rex_w {
                    sem::add_m64_r64_abs(b, disp32(), reg())
                } else {
                    sem::add_m32_r32_abs(b, disp32() as u32, reg())
                }
            } else if rex_w {
                sem::add_m64_r64_sibabs(b, sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::add_m32_r32_sibabs(b, sib_idx(), sib_shift(), disp32(), reg())
            }
        }
        Insn::AddM32R32Sibd32 => {
            // 01 /r SIB mod=10 [base+index*scale+disp32]。basename 0x48995c 対応.
            if no_index() {
                if rex_w {
                    sem::add_m64_r64_mem32(b, sib_base(), disp32(), reg())
                } else {
                    sem::add_m32_r32_mem32(b, sib_base(), disp32(), reg())
                }
            } else if rex_w {
                sem::add_m64_r64_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::add_m32_r32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            }
        }
        Insn::AddM32R32Sibd => {
            // 01 /r SIB mod=01 [base+index*scale+disp8] (32b)。src は reg フィールド.
            // SIB は (word>>8) 下位8、disp は最下位8.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx = Gpr(((sib_v >> 3) & 7) | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if no_index() {
                // no_index: base のみ + disp8.
                sem::add_m32_r32_mem8(b, base, d8, reg())
            } else {
                sem::add_m32_r32_sibd(b, base, idx, shift, d8, reg())
            }
        }
        Insn::SubMRSibd => {
            // 29 /r SIB mod=01 [base+index*scale+disp8]。wc 0x49e1db 対応.
            if no_index() {
                if rex_w {
                    sem::sub_m64_r64_mem8(b, sib_base(), disp8(), reg())
                } else {
                    sem::sub_m32_r32_mem8(b, sib_base(), disp8(), reg())
                }
            } else if rex_w {
                sem::sub_m64_r64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            } else {
                sem::sub_m32_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            }
        }
        Insn::SubM32R32Mem8 => {
            // 29 /r mod=01 [base+disp8]。src は reg フィールド.
            if rex_w {
                sem::sub_m64_r64_mem8(b, rm(), disp8(), reg())
            } else {
                sem::sub_m32_r32_mem8(b, rm(), disp8(), reg())
            }
        }
        Insn::AddM32R32Mem32 => {
            if rex_w {
                sem::add_m64_r64_mem32(b, rm(), disp32(), reg())
            } else {
                sem::add_m32_r32_mem32(b, rm(), disp32(), reg())
            }
        }
        Insn::AddM32R32Rip => {
            if rex_w {
                sem::add_m64_r64_rip(b, eip as u64 + nbytes, disp32(), reg())
            } else if is64 {
                sem::add_m32_r32_rip(b, eip as u64 + nbytes, disp32(), reg())
            } else {
                sem::add_m32_r32_abs(b, imm32(), reg())
            }
        }
        Insn::AdcRm32 => {
            if rex_w {
                sem::adc_rm64(b, rm(), reg())
            } else {
                sem::adc_rm32(b, rm(), reg())
            }
        }
        Insn::SbbRm32 => {
            if rex_w {
                sem::sbb_rm64(b, rm(), reg())
            } else {
                sem::sbb_rm32(b, rm(), reg())
            }
        }
        Insn::MovRm32 => {
            if rex_w {
                sem::mov_rm64(b, reg(), rm())
            } else {
                sem::mov_rm32(b, reg(), rm())
            }
        }
        Insn::MovEaxMem8 => {
            if rex_w {
                sem::mov_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::mov_eax_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::MovMemEax8 => {
            if has66 {
                // 66 89: 16ビット MOV [base+disp8],r16。
                sem::mov_m16_r16_mem8(b, reg(), rm(), disp8())
            } else if rex_w {
                sem::mov_m64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::mov_mem_eax8(b, reg(), rm(), disp8())
            }
        }
        Insn::MovEaxMemnd => {
            if let Some(base) = fs {
                if rex_w {
                    sem::mov_r64_fs_memnd(b, reg(), base, rm())
                } else {
                    sem::mov_r32_fs_memnd(b, reg(), base, rm())
                }
            } else if rex_w {
                sem::mov_r64_memnd(b, reg(), rm())
            } else {
                sem::mov_eax_memnd(b, reg(), rm())
            }
        }
        Insn::MovMemndEax => {
            if let Some(base) = fs {
                if rex_w {
                    sem::mov_m64_fs_memnd(b, reg(), base, rm())
                } else {
                    sem::mov_m32_fs_memnd(b, reg(), base, rm())
                }
            } else if has66 {
                // 66 89: 16ビット MOV [base],r16。dst は reg フィールド.
                sem::mov_m16_r16_memnd(b, reg(), rm())
            } else if rex_w {
                sem::mov_m64_memnd(b, reg(), rm())
            } else {
                sem::mov_memnd_eax(b, reg(), rm())
            }
        }
        Insn::MovEaxMem32 => {
            if rex_w {
                sem::mov_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::mov_eax_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::MovMemEax32 => {
            if has66 {
                // 66 89: 16ビット MOV [base+disp32],r16。
                sem::mov_m16_r16_mem32(b, reg(), rm(), disp32())
            } else if rex_w {
                sem::mov_m64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::mov_mem_eax32(b, reg(), rm(), disp32())
            }
        }
        Insn::MovEaxAbs => {
            if has66 {
                // 66 8B: 16ビット RIP相対ロード（64ビットのみ。32ビットは run 側で弾く）。
                sem::mov_r16_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if rex_w {
                sem::mov_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::mov_eax_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::mov_eax_abs(b, reg(), imm32())
            }
        }
        Insn::MovAbsEax => {
            if has66 {
                // 66 89: 16ビット RIP相対ストア（64ビットのみ。32ビットは run 側で弾く）。
                sem::mov_rip_r16(b, reg(), eip as u64 + nbytes, disp32())
            } else if rex_w {
                sem::mov_m64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::mov_rip_eax(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::mov_abs_eax(b, reg(), imm32())
            }
        }
        Insn::MovEaxSib => {
            if has66 {
                // 66 8B: 16ビット SIB ロード.
                if no_index() {
                    sem::mov_r16_m16_memnd(b, reg(), sib_base())
                } else {
                    sem::mov_r16_m16_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
                }
            } else if no_index() {
                if rex_w {
                    sem::mov_r64_memnd(b, reg(), sib_base())
                } else {
                    sem::mov_eax_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::mov_r64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::mov_eax_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::MovSibEax => {
            if has66 {
                // 66 89: 16ビット SIB ストア.
                if no_index() {
                    sem::mov_m16_r16_memnd(b, reg(), sib_base())
                } else {
                    sem::mov_m16_r16_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
                }
            } else if no_index() {
                if rex_w {
                    sem::mov_m64_memnd(b, reg(), sib_base())
                } else {
                    sem::mov_memnd_eax(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::mov_m64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::mov_sib_eax(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::MovEaxSibd => {
            if no_index() {
                if rex_w {
                    sem::mov_r64_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::mov_eax_mem8(b, reg(), sib_base(), disp8())
                }
            } else if rex_w {
                sem::mov_r64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::mov_eax_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::MovSibdEax => {
            if has66 {
                // 66 89: 16ビット SIB+disp8 ストア.
                if no_index() {
                    sem::mov_m16_r16_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::mov_m16_r16_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
                }
            } else if no_index() {
                if rex_w {
                    sem::mov_m64_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::mov_mem_eax8(b, reg(), sib_base(), disp8())
                }
            } else if rex_w {
                sem::mov_m64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::mov_sibd_eax(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::MovEaxSibd32 => {
            if no_index() {
                if rex_w {
                    sem::mov_r64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::mov_eax_mem32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::mov_r64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::mov_eax_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovSibd32Eax => {
            if no_index() {
                if rex_w {
                    sem::mov_m64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::mov_mem_eax32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::mov_m64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::mov_sibd32_eax(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovEaxSibabs => {
            if no_index() {
                match fs {
                    // FS 上書き + SIB 直接番地は FS:[disp32] とみなす。
                    Some(base) if is64 => {
                        if rex_w {
                            sem::mov_r64_fs_abs(b, reg(), base, disp32())
                        } else {
                            sem::mov_r32_fs_abs(b, reg(), base, disp32())
                        }
                    }
                    _ if rex_w => sem::mov_r64_abs(b, reg(), disp32() as u32),
                    _ => sem::mov_eax_abs(b, reg(), disp32() as u32),
                }
            } else if rex_w {
                sem::mov_r64_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::mov_eax_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovSibabsEax => {
            if no_index() {
                match fs {
                    // FS 上書き + SIB 直接番地は FS:[disp32] とみなす。
                    Some(base) if is64 => {
                        if rex_w {
                            sem::mov_m64_fs_abs(b, reg(), base, disp32())
                        } else {
                            sem::mov_m32_fs_abs(b, reg(), base, disp32())
                        }
                    }
                    _ if rex_w => sem::mov_m64_abs(b, reg(), disp32() as u32),
                    _ => sem::mov_abs_eax(b, reg(), disp32() as u32),
                }
            } else if rex_w {
                sem::mov_m64_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::mov_sibabs_eax(b, reg(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovSibabsR8 => {
            // 88 /r mod=00 SIB 直接番地。src は reg フィールド (REX.R で拡張)。
            // REX なしの reg 4-7 は上位8ビット (AH/CH/DH/BH)。
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                match fs {
                    Some(base) => sem::mov_m8_r8_fs_abs(b, src, base, disp32(), high),
                    None => sem::mov_m8_r8_abs(b, src, disp32() as u32, high),
                }
            } else if let Some(base) = fs {
                sem::mov_m8_r8_fs_sibabs(b, src, base, sib_idx(), sib_shift(), disp32(), high)
            } else {
                sem::mov_m8_r8_sibabs(b, src, sib_idx(), sib_shift(), disp32(), high)
            }
        }
        Insn::MovM8R8Memnd => {
            // 88 /r mod=00 [base],r8。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::mov_m8_r8_memnd(b, src, rm(), high)
        }
        Insn::MovM8R8Sib => {
            // 88 /r SIB mod=00 [base+index*scale] store。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::mov_m8_r8_memnd(b, src, sib_base(), high)
            } else {
                sem::mov_m8_r8_sib(b, src, sib_base(), sib_idx(), sib_shift(), high)
            }
        }
        Insn::MovM8R8Sibd => {
            // 88 /r SIB mod=01 [base+index*scale+disp8] store。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::mov_m8_r8_mem8(b, src, sib_base(), disp8(), high)
            } else {
                sem::mov_m8_r8_sibd(b, src, sib_base(), sib_idx(), sib_shift(), disp8(), high)
            }
        }
        Insn::MovM8R8Sibd32 => {
            // 88 /r SIB mod=10 [base+index*scale+disp32] store。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::mov_m8_r8_mem32(b, src, sib_base(), disp32(), high)
            } else {
                sem::mov_m8_r8_sibd32(b, src, sib_base(), sib_idx(), sib_shift(), disp32(), high)
            }
        }
        Insn::MovM8R8Mem8 => {
            // 88 /r mod=01 [base+disp8],r8。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::mov_m8_r8_mem8(b, src, rm(), disp8(), high)
        }
        Insn::MovM8R8Mem32 => {
            // 88 /r mod=10 [base+disp32],r8。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::mov_m8_r8_mem32(b, src, rm(), disp32(), high)
        }
        Insn::MovM8R8Rip => {
            // 88 /r mod=00 rm=101 RIP [RIP+disp32],r8。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if is64 {
                sem::mov_m8_r8_rip(b, src, eip as u64 + nbytes, disp32(), high)
            } else {
                sem::mov_m8_r8_abs(b, src, imm32(), high)
            }
        }
        Insn::MovM8R8 => {
            // 88 /r mod=11 reg-direct。dst は rm、src は reg.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (dst, dst_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::mov_r8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::MovR8M8Memnd => {
            // 8A /r mod=00 [base],r8 load。dst は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::mov_r8_m8_memnd(b, dst, high, rm())
        }
        Insn::XorR8M8Memnd => {
            // 32 /r mod=00 [base],r8 load。cksum 0x5c7fc7 対応. dst は reg フィールド.
            // REX なしの reg 4-7 は上位8ビット (AH/CH/DH/BH)。
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::xor_r8_m8_memnd(b, dst, high, rm())
        }
        Insn::MovR8M8Mem8 => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::mov_r8_m8_mem8(b, dst, high, rm(), disp8())
        }
        Insn::MovR8M8Mem32 => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::mov_r8_m8_mem32(b, dst, high, rm(), disp32())
        }
        Insn::MovR8M8Rip => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if is64 {
                sem::mov_r8_m8_rip(b, dst, high, eip as u64 + nbytes, disp32())
            } else {
                // 32ビット絶対番地は未対応 (8A は RIP 想定のため暫定)。
                sem::mov_r8_m8_memnd(b, dst, high, rm())
            }
        }
        Insn::MovR8M8Sib => {
            // 8A /r SIB mod=00 [base+index*scale] load。dst は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::mov_r8_m8_memnd(b, dst, high, sib_base())
            } else {
                sem::mov_r8_m8_sib(b, dst, high, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::MovR8M8Sibd => {
            // 8A /r SIB mod=01 [base+index*scale+disp8] load.
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::mov_r8_m8_mem8(b, dst, high, sib_base(), disp8())
            } else {
                sem::mov_r8_m8_sibd(b, dst, high, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::MovR8M8Sibd32 => {
            // 8A /r SIB mod=10 [base+index*scale+disp32] load.
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::mov_r8_m8_mem32(b, dst, high, sib_base(), disp32())
            } else {
                sem::mov_r8_m8_sibd32(b, dst, high, sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::MovR8M8 => {
            // 8A /r mod=11 reg-direct。dst は reg、src は rm.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (src, src_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::mov_r8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::CmpM8R8 => {
            // 38 /r mod=11 reg-direct。dst は rm、src は reg.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (dst, dst_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::cmp_m8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::SubM8R8 => {
            // 28 /r mod=11 reg-direct。dst は rm、src は reg.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (dst, dst_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::sub_m8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::AndR8M8Mem32 => {
            // 22 /r mod=10 [base+disp32]。dst は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::and_r8_m8_mem32(b, dst, dst_high, rm(), disp32())
        }
        Insn::OrM8R8 => {
            // 08 /r mod=11 reg-direct。dst は rm、src は reg.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (dst, dst_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::or_m8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::XorM8R8 => {
            // 30 /r mod=11 reg-direct。dst は rm、src は reg.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (dst, dst_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::xor_m8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::AndM8R8 => {
            // 20 /r mod=11 reg-direct。dst は rm、src は reg.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (dst, dst_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::and_m8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::FstpM64Sibd => {
            // DD /3 SIB mod=01。seq 0x4d3169 の fstpl 0x8(%rsp)。
            if no_index() {
                sem::fstp_m64_mem8(b, sib_base(), disp8())
            } else {
                sem::fstp_m64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::FaddSt => {
            // D8 C0+i。seq 0x4d097d の D8 C0 は FADD ST(0), ST(0)。
            sem::fadd_st(b, (word & 7) as u8)
        }
        Insn::FmulpSt => {
            // DE C8+i。seq 0x4018c7 の DE C9 は FMULP ST(1)。
            sem::fmulp_st(b, (word & 7) as u8)
        }
        Insn::FildM64Sib => {
            // DF /5 SIB mod=00 [base+index*scale]。seq 0x4018c4 の fildq (%rsp)。
            if no_index() {
                sem::fild_m64_memnd(b, sib_base())
            } else {
                sem::fild_m64_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::FildM32Sibd => {
            // DB /0 SIB mod=01 [base+index*scale+disp8]。seq 0x4018bc 対応.
            if no_index() {
                sem::fild_m32_mem8(b, sib_base(), disp8())
            } else {
                sem::fild_m32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::FstpSt => {
            // DD D8+i。seq 0x4024ee の DD D8 は FSTP ST(0)。
            sem::fstp_st(b, (word & 7) as u8)
        }
        Insn::FstpM80Sibd => {
            // DB /7 SIB mod=01。seq 0x4d74d7 の fstpt 0x20(%rsp)。
            if no_index() {
                sem::fstp_m80_mem8(b, sib_base(), disp8())
            } else {
                sem::fstp_m80_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::FstpM80Sibd32 => {
            // DB /7 SIB mod=10。seq 0x4d0874 の fstpt 0x1d80(%rsp)。
            if no_index() {
                sem::fstp_m80_mem32(b, sib_base(), disp32())
            } else {
                sem::fstp_m80_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::FstpM80Sib => {
            // DB /7 SIB mod=00。seq 0x4d0869 の fstpt (%rsp)。
            if no_index() {
                sem::fstp_m80_memnd(b, sib_base())
            } else {
                sem::fstp_m80_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::FstpM80Memnd => {
            // DB /7 mod=00 [base]。seq 0x4d0725 の fstpt (%rdi)。
            sem::fstp_m80_memnd(b, rm())
        }
        Insn::FldM64Memnd => {
            // DD /0 mod=00 [base]。seq 0x4d0723 の fldl (%rax)。
            sem::fld_m64_memnd(b, rm())
        }
        Insn::FldM32Rip => {
            // D9 /0 mod=00 rm=101 [RIP+disp32]。seq 0x402335 対応。disp は下位32 LE.
            let disp = (word as u32).swap_bytes() as i32;
            if is64 {
                sem::fld_m32_rip(b, eip as u64 + nbytes, disp)
            } else {
                sem::fld_m32_abs(b, (word as u32).swap_bytes())
            }
        }
        Insn::CmpM8R8Rip => {
            // 38 /r mod=00 rm=101 [RIP+disp32], r8。grep 0x4aec6d 対応.
            // disp は下位32 LE。src は reg フィールド。REX があると高位バイトは使わない.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let disp = (word as u32).swap_bytes() as i32;
            if is64 {
                sem::cmp_m8_r8_rip(b, eip as u64 + nbytes, disp, src, high)
            } else {
                sem::cmp_m8_r8_abs(b, (word as u32).swap_bytes(), src, high)
            }
        }
        Insn::CmpM8R8Memnd => {
            // 38 /r mod=00 [base],r8。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::cmp_m8_r8_memnd(b, rm(), src, high)
        }
        Insn::CmpM8R8Mem8 => {
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::cmp_m8_r8_mem8(b, rm(), disp8(), src, high)
        }
        Insn::CmpM8R8Mem32 => {
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::cmp_m8_r8_mem32(b, rm(), disp32(), src, high)
        }
        Insn::CmpM8R8Sib => {
            // 38 /r SIB mod=00 [base+index*scale],r8。
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::cmp_m8_r8_memnd(b, sib_base(), src, high)
            } else {
                sem::cmp_m8_r8_sib(b, sib_base(), sib_idx(), sib_shift(), src, high)
            }
        }
        Insn::OrM8R8Sibd => {
            // 08 /r SIB mod=01 [base+index*scale+disp8], r8。sed 0x4a87dd 対応.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::or_m8_r8_mem8(b, sib_base(), disp8(), src, high)
            } else {
                sem::or_m8_r8_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), src, high)
            }
        }
        Insn::CmpM8R8Sibd => {
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::cmp_m8_r8_mem8(b, sib_base(), disp8(), src, high)
            } else {
                sem::cmp_m8_r8_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), src, high)
            }
        }
        Insn::CmpM8R8Sibd32 => {
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::cmp_m8_r8_mem32(b, sib_base(), disp32(), src, high)
            } else {
                sem::cmp_m8_r8_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), src, high)
            }
        }
        Insn::CmpR8M8 => {
            // 3A /r mod=11 reg-direct。dst は reg、src は rm.
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (src, src_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::cmp_r8_m8(b, dst, dst_high, src, src_high)
        }
        Insn::CmpR8M8Memnd => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::cmp_r8_m8_memnd(b, dst, high, rm())
        }
        Insn::CmpR8M8Mem8 => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::cmp_r8_m8_mem8(b, dst, high, rm(), disp8())
        }
        Insn::CmpR8M8Mem32 => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::cmp_r8_m8_mem32(b, dst, high, rm(), disp32())
        }
        Insn::CmpR8M8Sib => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::cmp_r8_m8_memnd(b, dst, high, sib_base())
            } else {
                sem::cmp_r8_m8_sib(b, dst, high, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::CmpR8M8Sibd => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::cmp_r8_m8_mem8(b, dst, high, sib_base(), disp8())
            } else {
                sem::cmp_r8_m8_sibd(b, dst, high, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::CmpR8M8Sibd32 => {
            let reg_f = (modrm() >> 3) & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::cmp_r8_m8_mem32(b, dst, high, sib_base(), disp32())
            } else {
                sem::cmp_r8_m8_sibd32(b, dst, high, sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::TestR8R8 => {
            // 84 /r mod=11 reg-direct。dst は rm、src は reg (TEST は書換なし).
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (dst, dst_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::test_r8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::TestM8R8Memnd => {
            // 84 /r mod=00 [base],r8。src は reg フィールド.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::test_m8_r8_memnd(b, rm(), src, high)
        }
        Insn::TestM8R8Mem8 => {
            // 84 /r mod=01 [base+disp8],r8.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::test_m8_r8_mem8(b, rm(), disp8(), src, high)
        }
        Insn::TestM8R8Mem32 => {
            // 84 /r mod=10 [base+disp32],r8.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::test_m8_r8_mem32(b, rm(), disp32(), src, high)
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
        Insn::Fldz => {
            // D9 EE。seq 0x4d097f の fldz。
            sem::fldz(b)
        }
        Insn::FxchSt => {
            // D9 C8+i。seq 0x4d0981 の D9 C9 は FXCH ST(1)。
            sem::fxch_st(b, (word & 7) as u8)
        }
        Insn::FucomiSt => {
            // DB E8+i。seq 0x4d0983 の DB E9 は FUCOMI ST(0), ST(1)。
            sem::fucomi_st(b, (word & 7) as u8)
        }
        Insn::FmulM32Rip => {
            // D8 /1 mod=00 rm=101。seq 0x4d0bf4 の fmuls disp32(%rip)。
            let disp = (word as u32).swap_bytes() as i32;
            if is64 {
                sem::fmul_m32_rip(b, eip as u64 + nbytes, disp)
            } else {
                sem::fmul_m32_abs(b, (word as u32).swap_bytes())
            }
        }
        Insn::FldSt => {
            // D9 C0+i。seq 0x4d0867 の D9 C0 は FLD ST(0)。
            sem::fld_st(b, (word & 7) as u8)
        }
        Insn::FldM80Sib => {
            // DB /5 SIB mod=00。seq 0x4d74d4 の fldt (%rsp)。
            if no_index() {
                sem::fld_m80_memnd(b, sib_base())
            } else {
                sem::fld_m80_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::FldM80Sibd => {
            // DB /5 SIB mod=01。seq 0x4d7466 の fldt 0x20(%rsp)。
            if no_index() {
                sem::fld_m80_mem8(b, sib_base(), disp8())
            } else {
                sem::fld_m80_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::FldM80Sibd32 => {
            // DB /5 SIB mod=10。seq 0x4d0853 の fldt 0x1d80(%rsp)。
            if no_index() {
                sem::fld_m80_mem32(b, sib_base(), disp32())
            } else {
                sem::fld_m80_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::PushRmSibd => {
            // FF /6 SIB mod=01。seq 0x4d1a81 の pushq 0x68(%rsp)。番地は減算前。
            if no_index() {
                if is64 {
                    sem::push_m64_mem8(b, sib_base(), disp8())
                } else {
                    sem::push_m32_mem8(b, sib_base(), disp8())
                }
            } else if is64 {
                sem::push_m64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::push_m32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::PushImm8 => {
            let imm = (word & 0xff) as u8 as i8;
            if is64 {
                sem::push_imm8_64(b, imm)
            } else {
                sem::push_imm8_32(b, imm)
            }
        }
        Insn::PushImm32 => {
            if is64 {
                sem::push_imm32_64(b, imm32())
            } else {
                sem::push_imm32_32(b, imm32())
            }
        }
        Insn::XchgRcxAx
        | Insn::XchgRdxAx
        | Insn::XchgRbxAx
        | Insn::XchgRspAx
        | Insn::XchgRbpAx
        | Insn::XchgRsiAx
        | Insn::XchgRdiAx => {
            // 91-97: dst は opcode 下3ビット + REX.B、相手は RAX.
            let dst = Gpr(((word as u8) & 7) | ((rex & 1) << 3));
            if rex_w {
                sem::xchg_r64_ax(b, dst)
            } else {
                sem::xchg_r32_ax(b, dst)
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
        Insn::CallRMem8 => {
            // FF /2 mod=01 [base+disp8] 間接CALL。base は rm().
            if is64 {
                sem::call_r64_mem8(b, eip as u64 + nbytes, rm(), disp8())
            } else {
                sem::call_r32_mem8(b, eip.wrapping_add(nbytes as u32), rm(), disp8())
            }
        }
        Insn::CallRRm => {
            // FF /2 mod=11 reg-direct 間接CALL。src は rm().
            if is64 {
                sem::call_r64_rm(b, eip as u64 + nbytes, rm())
            } else {
                sem::call_r32_rm(b, eip.wrapping_add(nbytes as u32), rm())
            }
        }
        Insn::CallRMemnd => {
            // FF /2 mod=00 [base] 間接CALL.
            if is64 {
                sem::call_r64_memnd(b, eip as u64 + nbytes, rm())
            } else {
                sem::call_r32_memnd(b, eip.wrapping_add(nbytes as u32), rm())
            }
        }
        Insn::CallRMem32 => {
            // FF /2 mod=10 [base+disp32] 間接CALL.
            if is64 {
                sem::call_r64_mem32(b, eip as u64 + nbytes, rm(), disp32())
            } else {
                sem::call_r32_mem32(b, eip.wrapping_add(nbytes as u32), rm(), disp32())
            }
        }
        Insn::CallRSibd32 => {
            // FF /2 SIB mod=10 [base+index*scale+disp32] 間接CALL。no_index は [base+disp32].
            if no_index() {
                if is64 {
                    sem::call_r64_mem32(b, eip as u64 + nbytes, sib_base(), disp32())
                } else {
                    sem::call_r32_mem32(b, eip.wrapping_add(nbytes as u32), sib_base(), disp32())
                }
            } else if is64 {
                sem::call_r64_sibd32(
                    b,
                    eip as u64 + nbytes,
                    sib_base(),
                    sib_idx(),
                    sib_shift(),
                    disp32(),
                )
            } else {
                sem::call_r32_sibd32(
                    b,
                    eip.wrapping_add(nbytes as u32),
                    sib_base(),
                    sib_idx(),
                    sib_shift(),
                    disp32(),
                )
            }
        }
        Insn::CallRSibabs => {
            // FF /2 SIB mod=00 base=101 [index*scale+disp32]。true 0x403f86 対応.
            // index=100 かつ REX.X なしは disp32 だけ。
            if no_index() {
                if is64 {
                    sem::call_r64_abs(b, eip as u64 + nbytes, disp32())
                } else {
                    sem::call_r32_abs(b, eip.wrapping_add(nbytes as u32), disp32() as u32)
                }
            } else if is64 {
                sem::call_r64_sibabs(b, eip as u64 + nbytes, sib_idx(), sib_shift(), disp32())
            } else {
                sem::call_r32_sibabs(
                    b,
                    eip.wrapping_add(nbytes as u32),
                    sib_idx(),
                    sib_shift(),
                    disp32(),
                )
            }
        }
        Insn::CallRSib => {
            // FF /2 SIB mod=00 [base+index*scale] 間接CALL。no_index は [base].
            if no_index() {
                if is64 {
                    sem::call_r64_memnd(b, eip as u64 + nbytes, sib_base())
                } else {
                    sem::call_r32_memnd(b, eip.wrapping_add(nbytes as u32), sib_base())
                }
            } else if is64 {
                sem::call_r64_sib(b, eip as u64 + nbytes, sib_base(), sib_idx(), sib_shift())
            } else {
                sem::call_r32_sib(
                    b,
                    eip.wrapping_add(nbytes as u32),
                    sib_base(),
                    sib_idx(),
                    sib_shift(),
                )
            }
        }
        Insn::JmpRSibabs => {
            // FF /4 SIB mod=00 base=101。uname 0x4d05e8 対応.
            if no_index() {
                if is64 {
                    sem::jmp_r64_abs(b, disp32())
                } else {
                    sem::jmp_r32_abs(b, disp32() as u32)
                }
            } else if is64 {
                sem::jmp_r64_sibabs(b, sib_idx(), sib_shift(), disp32())
            } else {
                sem::jmp_r32_sibabs(b, sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::JmpRSib => {
            // FF /4 SIB mod=00 [base+index*scale] 間接JMP。no_index は [base].
            if no_index() {
                if is64 {
                    sem::jmp_r64_memnd(b, sib_base())
                } else {
                    sem::jmp_r32_memnd(b, sib_base())
                }
            } else if is64 {
                sem::jmp_r64_sib(b, sib_base(), sib_idx(), sib_shift())
            } else {
                sem::jmp_r32_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::CallRSibd => {
            // FF /2 SIB mod=01 [base+index*scale+disp8] 間接CALL。no_index は [base+disp8].
            let d8 = disp8();
            if no_index() {
                if is64 {
                    sem::call_r64_mem8(b, eip as u64 + nbytes, sib_base(), d8)
                } else {
                    sem::call_r32_mem8(b, eip.wrapping_add(nbytes as u32), sib_base(), d8)
                }
            } else if is64 {
                sem::call_r64_sibd(
                    b,
                    eip as u64 + nbytes,
                    sib_base(),
                    sib_idx(),
                    sib_shift(),
                    d8,
                )
            } else {
                sem::call_r32_sibd(
                    b,
                    eip.wrapping_add(nbytes as u32),
                    sib_base(),
                    sib_idx(),
                    sib_shift(),
                    d8,
                )
            }
        }
        Insn::CallRRip => {
            if is64 {
                sem::call_r64_rip(b, eip as u64 + nbytes, eip as u64 + nbytes, disp32())
            } else {
                sem::call_r32_abs(b, eip.wrapping_add(nbytes as u32), imm32())
            }
        }
        Insn::JmpRRm => {
            if is64 {
                sem::jmp_r64_rm(b, rm())
            } else {
                sem::jmp_r32_rm(b, rm())
            }
        }
        Insn::JmpRMemnd => {
            if is64 {
                sem::jmp_r64_memnd(b, rm())
            } else {
                sem::jmp_r32_memnd(b, rm())
            }
        }
        Insn::JmpRMem8 => {
            if is64 {
                sem::jmp_r64_mem8(b, rm(), disp8())
            } else {
                sem::jmp_r32_mem8(b, rm(), disp8())
            }
        }
        Insn::JmpRMem32 => {
            if is64 {
                sem::jmp_r64_mem32(b, rm(), disp32())
            } else {
                sem::jmp_r32_mem32(b, rm(), disp32())
            }
        }
        Insn::JmpRRip => {
            if is64 {
                sem::jmp_r64_rip(b, eip as u64 + nbytes, disp32())
            } else {
                sem::jmp_r32_abs(b, imm32())
            }
        }
        Insn::Ret => {
            if is64 {
                sem::ret64(b)
            } else {
                sem::ret(b)
            }
        }
        Insn::CmpEax => {
            if rex_w {
                sem::cmp_rm64_imm(b, Gpr(0), imm32())
            } else {
                sem::cmp_eax(b, imm32())
            }
        }
        Insn::CmpAlImm => sem::cmp_al_imm(b, (word & 0xff) as u8),
        Insn::OrAlImm => sem::or_al_imm(b, (word & 0xff) as u8),
        Insn::TestRm32 => {
            if has66 {
                // 66 85: 16ビット TEST。reg-direct のみ対応.
                if modrm() >> 6 == 3 {
                    sem::test_rm16(b, rm(), reg())
                } else {
                    let md = modrm() >> 6;
                    if md == 1 {
                        sem::test_m16_r16_mem8(b, rm(), disp8(), reg())
                    } else if md == 2 {
                        sem::test_m16_r16_mem32(b, rm(), disp32(), reg())
                    } else {
                        sem::test_m16_r16_memnd(b, rm(), reg())
                    }
                }
            } else if rex_w {
                sem::test_rm64(b, rm(), reg())
            } else {
                sem::test_rm32(b, rm(), reg())
            }
        }
        Insn::TestRMem8 => {
            // 85 /r mod=01 [base+disp8]。dst は reg フィールド.
            let d8 = disp8();
            if rex_w {
                sem::test_r64_m64_mem8(b, reg(), rm(), d8)
            } else {
                sem::test_r32_m32_mem8(b, reg(), rm(), d8)
            }
        }
        Insn::TestRm32Memnd => {
            // 85 /r mod=00 [base]。find 0x5d17f7 対応。dst は reg フィールド.
            // REX.W の64bit比較は32bitで代用する（試作）。
            sem::test_r32_m32_memnd(b, reg(), rm())
        }
        Insn::TestRSib => {
            // 85 /r SIB mod=00 [base+index*scale]。awk 0x4a1c82 対応。dst は reg.
            if no_index() {
                if rex_w {
                    sem::test_r64_m64_memnd(b, reg(), sib_base())
                } else {
                    sem::test_r32_m32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::test_r64_m64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::test_r32_m32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::TestRSibd => {
            // 85 /r SIB mod=01 [base+index*scale+disp8] (32b)。dst は reg フィールド.
            // disp は最下位8。no_index は base+disp8 のみ.
            let d8 = (word & 0xff) as u8 as i8;
            if no_index() {
                if rex_w {
                    sem::test_r64_m64_mem8(b, reg(), sib_base(), d8)
                } else {
                    sem::test_r32_m32_mem8(b, reg(), sib_base(), d8)
                }
            } else if rex_w {
                sem::test_r64_m64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), d8)
            } else {
                sem::test_r32_m32_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), d8)
            }
        }
        Insn::TestRSibd32 => {
            // 85 /r SIB mod=10 [base+index*scale+disp32] (56b)。grep 0x43d250 対応.
            // disp32 は末尾32 LE (swap 済み)。no_index は base+disp32 のみ.
            let disp = disp32();
            if no_index() {
                if rex_w {
                    sem::test_r64_m64_mem32(b, reg(), sib_base(), disp)
                } else {
                    sem::test_r32_m32_mem32(b, reg(), sib_base(), disp)
                }
            } else if rex_w {
                sem::test_r64_m64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp)
            } else {
                sem::test_r32_m32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp)
            }
        }
        Insn::TestRm32Imm => {
            if rex_w {
                sem::test_rm64_imm(b, rm(), imm32())
            } else {
                sem::test_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::TestRm32ImmMem8 => {
            // F7 /0 mod=01 [base+disp8],imm32。echo 0x4bfb84 対応.
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if rex_w {
                sem::test_rm64_imm_mem8(b, rm(), d8, imm)
            } else {
                sem::test_rm32_imm_mem8(b, rm(), d8, imm)
            }
        }
        Insn::TestRm32ImmMemnd => {
            // F7 /0 mod=00 [base],imm32 (48b)。tac 0x5b0ca8 対応. imm は最下位32 LE.
            if rex_w {
                sem::test_rm64_imm_memnd(b, rm(), imm32())
            } else {
                sem::test_rm32_imm_memnd(b, rm(), imm32())
            }
        }
        Insn::TestM16ImmMemnd => {
            // 66 F7 /0 mod=00 [base],imm16 (66剥離後4B)。imm は最下位16 LE.
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::test_m16_imm_memnd(b, rm(), imm)
        }
        Insn::TestM16ImmMem8 => {
            // 66 F7 /0 mod=01 [base+disp8],imm16 (66剥離後5B)。hexdump 0x5c8822 対応.
            // disp は (word>>16) 下位8、imm は最下位16 LE.
            let d8 = ((word >> 16) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::test_m16_imm_mem8(b, rm(), d8, imm)
        }
        Insn::TestRm32ImmRip => {
            // F7 05 + disp32 + imm32 (10B)。ls 0x4963b6 対応.
            // disp は (word>>32) 下位32 LE、imm は最下位32 LE.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            let imm = (word as u32).swap_bytes();
            if rex_w {
                sem::test_rm64_imm_rip(b, eip as u64 + nbytes, disp, imm)
            } else if is64 {
                sem::test_rm32_imm_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::test_rm32_imm_abs(b, ((word >> 32) as u32).swap_bytes(), imm)
            }
        }
        Insn::TestM16ImmRip => {
            // 66 F7 05 + disp32 + imm16 (66剥離後8B)。
            // disp は (word>>16) 下位32 LE、imm は最下位16 LE.
            let disp = ((word >> 16) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            if is64 {
                sem::test_m16_imm_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::test_m16_imm_abs(b, ((word >> 16) as u32).swap_bytes(), imm)
            }
        }
        Insn::NotRm32 => {
            if rex_w {
                sem::not_rm64(b, rm())
            } else {
                sem::not_rm32(b, rm())
            }
        }
        Insn::NegRm32 => {
            if rex_w {
                sem::neg_rm64(b, rm())
            } else {
                sem::neg_rm32(b, rm())
            }
        }
        Insn::TestRm8Imm => {
            // 8ビット ModRM: REXありは低8ビット、なしの4-7は上位8ビット.
            let rm_f = modrm() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::test_rm8_imm(b, dst, (word & 0xff) as u8, high)
        }
        Insn::AndRm8Imm => {
            let rm_f = modrm() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::and_rm8_imm(b, dst, (word & 0xff) as u8, high)
        }
        Insn::OrRm8Imm => {
            // 80 /1 reg-direct。REXありは低8ビット、なしの4-7は上位8ビット.
            let rm_f = modrm() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::or_rm8_imm(b, dst, (word & 0xff) as u8, high)
        }
        Insn::CmpRm8Imm => {
            let rm_f = modrm() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::cmp_rm8_imm(b, dst, (word & 0xff) as u8, high)
        }
        Insn::CmpRm8ImmSibd => {
            // 80 7C SIB disp8 imm8 (40b)。SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                // no_index: [base+disp8] として mem8 相当を呼ぶ.
                sem::cmp_rm8_imm_mem8(b, base, d8, imm)
            } else {
                sem::cmp_rm8_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::CmpRm8ImmSibd32 => {
            // 80 BC SIB disp32 imm8 (64b)。stat 0x429875 対応.
            // SIB は (word>>40) 下位8、disp32 は (word>>8) 下位32 LE、imm は最下位8.
            let sib_v = ((word >> 40) & 0xff) as u8;
            let disp = (((word >> 8) as u32).swap_bytes()) as i32;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::cmp_rm8_imm_mem32(b, base, disp, imm)
            } else {
                sem::cmp_rm8_imm_sibd32(b, base, idx, shift, disp, imm)
            }
        }
        Insn::CmpRm8ImmMem8 => {
            // 80 /7 mod=01 [base+disp8],imm8 (32b)。disp は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            sem::cmp_rm8_imm_mem8(b, rm(), d8, imm)
        }
        Insn::CmpRm8ImmMemnd => {
            // 80 /7 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8;
            sem::cmp_rm8_imm_memnd(b, rm(), imm)
        }
        Insn::CmpRm8ImmSib => {
            // 80 /7 SIB mod=00 [base+index*scale],imm8 (32b)。grep 0x43e0e4 対応.
            // SIB は (word>>8) 下位8、imm は最下位8。no_index は [base]。
            // REX.X/B で索引/ベース拡張.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::cmp_rm8_imm_memnd(b, base, imm)
            } else {
                sem::cmp_rm8_imm_sib_idx(b, base, idx, shift, imm)
            }
        }
        Insn::MovRm8ImmMem8 => {
            // C6 /0 mod=01 [base+disp8],imm8 (32b)。disp は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            sem::mov_rm8_imm_mem8(b, rm(), d8, imm)
        }
        Insn::MovRm8ImmMemnd => {
            // C6 /0 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8;
            sem::mov_rm8_imm_memnd(b, rm(), imm)
        }
        Insn::MovRm8ImmSib => {
            // C6 /0 SIB mod=00 [base+index*scale],imm8 (32b)。
            // SIB は (word>>8) 下位8、imm は最下位8。no_index は [base].
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::mov_rm8_imm_memnd(b, base, imm)
            } else {
                sem::mov_rm8_imm_sib(b, base, idx, shift, imm)
            }
        }
        Insn::MovRm8ImmSibd => {
            // C6 /0 SIB mod=01 [base+index*scale+disp8],imm8 (40b)。
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            // no_index は [base+disp8].
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::mov_rm8_imm_mem8(b, base, d8, imm)
            } else {
                sem::mov_rm8_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::MovRm8ImmSibd32 => {
            // C6 /0 SIB mod=10 [base+index*scale+disp32],imm8 (64b)。
            // disp は (word>>8) 下位32 LE、imm は最下位8。no_index は [base+disp32].
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            if no_index() {
                sem::mov_rm8_imm_mem32(b, sib_base(), disp, imm)
            } else {
                sem::mov_rm8_imm_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            }
        }
        Insn::MovRm8ImmMem32 => {
            // C6 /0 mod=10 [base+disp32],imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            sem::mov_rm8_imm_mem32(b, rm(), disp, imm)
        }
        Insn::MovRm8ImmRip => {
            // C6 05 + disp32 + imm8 (56b)。RIP 相対.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            if is64 {
                sem::mov_rm8_imm_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::mov_rm8_imm_abs(b, ((word >> 8) as u32).swap_bytes(), imm)
            }
        }
        Insn::OrRm8ImmMem32 => {
            // 80 /1 mod=10 [base+disp32],imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            sem::or_rm8_imm_mem32(b, rm(), disp, imm)
        }
        Insn::OrRm8ImmMemnd => {
            // 80 /1 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8;
            sem::or_rm8_imm_memnd(b, rm(), imm)
        }
        Insn::OrRm8ImmMem8 => {
            // 80 /1 mod=01 [base+disp8],imm8 (32b)。sed 0x5bde04 対応.
            // disp8 は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            sem::or_rm8_imm_mem8(b, rm(), d8, imm)
        }
        Insn::OrRm8ImmSib => {
            // 80 /1 mod=00 SIB [base] (no_index, non-abs) +imm8 (32b)。SIB は third.
            // 索引ありは SIB スケールで処理する.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::or_rm8_imm_memnd(b, base, imm)
            } else {
                sem::or_rm8_imm_sib(b, base, idx, shift, imm)
            }
        }
        Insn::OrRm8ImmSibd => {
            // 80 /1 mod=01 SIB [base+index*scale+disp8] +imm8 (40b)。
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::or_rm8_imm_mem8(b, base, d8, imm)
            } else {
                sem::or_rm8_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::OrR8M8Sibd => {
            // 0A /r SIB mod=01 [base+index*scale+disp8] (32b)。dst は reg フィールド.
            // SIB は (word>>8) 下位8、disp は最下位8.
            // REX なしの reg 4-7 は上位8ビット (AH/CH/DH/BH)。
            let reg_f = (modrm() >> 3) & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::or_r8_m8_mem8(b, dst, dst_high, base, d8)
            } else {
                sem::or_r8_m8_sibd(b, dst, dst_high, base, idx, shift, d8)
            }
        }
        Insn::OrR8M8Rip => {
            // 0A 05 + disp32 (48b)。find 0x5c44a7 対応。dst は reg フィールド.
            // REX なしの reg 4-7 は上位8ビット。
            let reg_f = (modrm() >> 3) & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::or_r8_m8_rip(b, dst, dst_high, eip as u64 + nbytes, disp32())
        }
        Insn::OrR8R8 => {
            // 0A /r mod=11 reg-direct。dst は reg、src は rm フィールド (REX.R/B で拡張)。
            // REX なしの 4-7 は上位8ビット (AH/CH/DH/BH)。
            let reg_f = (modrm() >> 3) & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let rm_f = modrm() & 7;
            let (src, src_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::or_r8_r8(b, dst, dst_high, src, src_high)
        }
        Insn::ShrRm8Imm8 => {
            // C0 /5 mod=11 reg-direct。dst は rm フィールド.
            // REX なしの rm 4-7 は上位8ビット (AH/CH/DH/BH)。
            let rm_f = modrm() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::shr_rm8_imm8(b, dst, high, word as u8)
        }
        Insn::ShrRm81 => {
            // D0 /5 mod=11 reg-direct。dst は rm フィールド、count=1.
            // REX.B で R8-R15 の下位8ビット。sed 0x5bdd7d (41 D0 ED) 対応.
            let rm_f = modrm() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::shr_rm8_imm8(b, dst, high, 1)
        }
        Insn::AndRm8ImmMem32 => {
            // 80 /4 mod=10 [base+disp32],imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            sem::and_rm8_imm_mem32(b, rm(), disp, imm)
        }
        Insn::AndRm8ImmMem8 => {
            // 80 /4 mod=01 [base+disp8],imm8 (32b)。grep 0x442d1d 対応.
            // disp8 は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            sem::and_rm8_imm_mem8(b, rm(), d8, imm)
        }
        Insn::AndRm8ImmSibd => {
            // 80 /4 SIB mod=01 [base+index*scale+disp8],imm8 (40b)。grep 0x434710 対応.
            // SIB は (word>>16) 下位8、disp8 は (word>>8) 下位8、imm は最下位8.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::and_rm8_imm_mem8(b, base, d8, imm)
            } else {
                sem::and_rm8_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::CmpRm8ImmMem32 => {
            // 80 /7 mod=10 [base+disp32],imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            sem::cmp_rm8_imm_mem32(b, rm(), disp, imm)
        }
        Insn::TestM8ImmRip => {
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            if is64 {
                sem::test_m8_imm_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::test_m8_imm_abs(b, ((word >> 8) as u32).swap_bytes(), imm)
            }
        }
        Insn::TestM8ImmMemnd => {
            // F6 /0 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8;
            sem::test_m8_imm_memnd(b, rm(), imm)
        }
        Insn::TestM8ImmMem8 => {
            // F6 /0 mod=01 [base+disp8],imm8 (32b)。
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            sem::test_m8_imm_mem8(b, rm(), d8, imm)
        }
        Insn::TestM8ImmMem32 => {
            // F6 /0 mod=10 [base+disp32],imm8 (56b)。
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            sem::test_m8_imm_mem32(b, rm(), disp, imm)
        }
        Insn::TestM8ImmSibd => {
            // F6 /0 SIB mod=01 [base+index*scale+disp8],imm8 (40b)。
            // disp8 は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            if no_index() {
                sem::test_m8_imm_mem8(b, sib_base(), d8, imm)
            } else {
                sem::test_m8_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), d8, imm)
            }
        }
        Insn::TestM8ImmSib => {
            // F6 /0 SIB mod=00 [base+index*scale],imm8 (32b)。ls -l 0x40e342 対応.
            // SIB は (word>>8) 下位8、imm は最下位8。REX.X/B で索引/ベース拡張.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::test_m8_imm_memnd(b, base, imm)
            } else {
                sem::test_m8_imm_sib(b, base, idx, shift, imm)
            }
        }
        Insn::CmpRm8ImmRip => {
            // 80 3D + disp32 + imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            if is64 {
                sem::cmp_rm8_imm_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::cmp_rm8_imm_abs(b, ((word >> 8) as u32).swap_bytes(), imm)
            }
        }
        Insn::TestAlImm => sem::test_al_imm(b, (word & 0xff) as u8),
        Insn::TestEaxImm => {
            if rex_w {
                sem::test_rm64_imm(b, Gpr(0), imm32())
            } else {
                sem::test_eax_imm(b, imm32())
            }
        }
        Insn::Je => sem::je(b, eip, disp8()),
        Insn::Jne => sem::jne(b, eip, disp8()),
        Insn::Jo => sem::jo(b, eip, disp8()),
        Insn::Jno => sem::jno(b, eip, disp8()),
        Insn::Jb => sem::jb(b, eip, disp8()),
        Insn::Jae => sem::jae(b, eip, disp8()),
        Insn::Jbe => sem::jbe(b, eip, disp8()),
        Insn::Ja => sem::ja(b, eip, disp8()),
        Insn::Jl => sem::jl(b, eip, disp8()),
        Insn::Jge => sem::jge(b, eip, disp8()),
        Insn::Jle => sem::jle(b, eip, disp8()),
        Insn::Jg => sem::jg(b, eip, disp8()),
        Insn::Js => sem::js(b, eip, disp8()),
        Insn::Jns => sem::jns(b, eip, disp8()),
        Insn::Jp => sem::jp(b, eip, disp8()),
        Insn::Jnp => sem::jnp(b, eip, disp8()),
        Insn::Loop => sem::loop_rel8(b, eip, disp8()),
        Insn::JmpRel32 => sem::jmp_rel32(b, eip, disp32()),
        Insn::SubEax => {
            if rex_w {
                sem::sub_rm64_imm(b, Gpr(0), imm32())
            } else {
                sem::sub_eax(b, imm32())
            }
        }
        Insn::Leave => {
            if is64 {
                sem::leave64(b)
            } else {
                sem::leave(b)
            }
        }
        Insn::AndEax => {
            if rex_w {
                sem::and_rm64_imm(b, Gpr(0), imm32())
            } else {
                sem::and_eax(b, imm32())
            }
        }
        Insn::AndAxImm16 => {
            // 66 25 + imm16 (24b、66 接頭辞は剥がし済み)。imm は最下位16 LE.
            sem::and_ax_imm16(b, ((word & 0xffff) as u16).swap_bytes())
        }
        Insn::CmpAxImm16 => {
            // 66 3D + imm16 (24b、66 接頭辞は剥がし済み)。imm は最下位16 LE.
            sem::cmp_ax_imm16(b, ((word & 0xffff) as u16).swap_bytes())
        }
        Insn::OrAxImm16 => {
            // 66 0D + imm16 (24b、66 接頭辞は剥がし済み)。seq 0x4d74c9 の orw $0x3ffe,%ax。
            sem::or_ax_imm16(b, ((word & 0xffff) as u16).swap_bytes())
        }
        Insn::AddRm16Imm => {
            // 66 81 /0 mod=11 + imm16 (32b、66 接頭辞は剥がし済み)。imm は最下位16 LE.
            sem::add_rm16_imm(b, rm(), ((word & 0xffff) as u16).swap_bytes())
        }
        Insn::AndRm16Imm => {
            // 66 81 /4 mod=11 + imm16 (32b、66 接頭辞は剥がし済み)。imm は最下位16 LE.
            sem::and_rm16_imm(b, rm(), ((word & 0xffff) as u16).swap_bytes())
        }
        Insn::CmpRm16Imm => {
            // 66 81 /7 mod=11 + imm16 (32b、66 接頭辞は剥がし済み)。basename 0x4bfaa8 対応.
            sem::cmp_rm16_imm(b, rm(), ((word & 0xffff) as u16).swap_bytes())
        }
        Insn::OrEax => {
            if rex_w {
                sem::or_rm64_imm(b, Gpr(0), imm32())
            } else {
                sem::or_eax(b, imm32())
            }
        }
        Insn::XorImm => {
            if rex_w {
                sem::xor_rm64_imm(b, Gpr(0), imm32())
            } else {
                sem::xor_imm(b, imm32())
            }
        }
        Insn::ShlRm32Imm8 => {
            if rex_w {
                sem::shl_rm64_imm8(b, rm(), word as u8)
            } else {
                sem::shl_rm32_imm8(b, rm(), word as u8)
            }
        }
        Insn::ShrRm32Imm8 => {
            if has66 {
                sem::shr_rm16_imm8(b, rm(), word as u8)
            } else if rex_w {
                sem::shr_rm64_imm8(b, rm(), word as u8)
            } else {
                sem::shr_rm32_imm8(b, rm(), word as u8)
            }
        }
        Insn::ShrRm321 => {
            if rex_w {
                sem::shr_rm64_imm8(b, rm(), 1)
            } else {
                sem::shr_rm32_imm8(b, rm(), 1)
            }
        }
        Insn::ShlRm321 => {
            if rex_w {
                sem::shl_rm64_imm8(b, rm(), 1)
            } else {
                sem::shl_rm32_imm8(b, rm(), 1)
            }
        }
        Insn::RolRm321 => {
            if rex_w {
                sem::rol_rm64_imm8(b, rm(), 1)
            } else {
                sem::rol_rm32_imm8(b, rm(), 1)
            }
        }
        Insn::SarRm321 => {
            if rex_w {
                sem::sar_rm64_imm8(b, rm(), 1)
            } else {
                sem::sar_rm32_imm8(b, rm(), 1)
            }
        }
        Insn::RorRm32Imm8 => {
            if rex_w {
                sem::ror_rm64_imm8(b, rm(), word as u8)
            } else {
                sem::ror_rm32_imm8(b, rm(), word as u8)
            }
        }
        Insn::RolRm32Imm8 => {
            if rex_w {
                sem::rol_rm64_imm8(b, rm(), word as u8)
            } else {
                sem::rol_rm32_imm8(b, rm(), word as u8)
            }
        }
        Insn::SarRm32Imm8 => {
            if rex_w {
                sem::sar_rm64_imm8(b, rm(), word as u8)
            } else {
                sem::sar_rm32_imm8(b, rm(), word as u8)
            }
        }
        Insn::SarRm32Cl => {
            if rex_w {
                sem::sar_rm64_cl(b, rm())
            } else {
                sem::sar_rm32_cl(b, rm())
            }
        }
        Insn::ShlRm32Cl => {
            if rex_w {
                sem::shl_rm64_cl(b, rm())
            } else {
                sem::shl_rm32_cl(b, rm())
            }
        }
        Insn::ShrRm32Cl => {
            if rex_w {
                sem::shr_rm64_cl(b, rm())
            } else {
                sem::shr_rm32_cl(b, rm())
            }
        }
        Insn::Int80 => sem::int80(b, eip),
        Insn::LeaM8 => {
            if rex_w {
                sem::lea_m8_64(b, reg(), rm(), disp8())
            } else {
                sem::lea_m8(b, reg(), rm(), disp8())
            }
        }
        Insn::LeaM32 => {
            if rex_w {
                sem::lea_m32_64(b, reg(), rm(), disp32())
            } else {
                sem::lea_m32(b, reg(), rm(), disp32())
            }
        }
        Insn::LeaMnd => {
            if rex_w {
                sem::lea_mnd_64(b, reg(), rm())
            } else {
                sem::lea_mnd(b, reg(), rm())
            }
        }
        Insn::LeaAbs => {
            if is64 {
                sem::lea_rip64(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::lea_abs(b, reg(), imm32())
            }
        }
        Insn::LeaSib => {
            if rex_w {
                if no_index() {
                    sem::lea_mnd_64(b, reg(), sib_base())
                } else {
                    sem::lea_sib_64(b, reg(), sib_base(), sib_idx(), sib_shift())
                }
            } else if no_index() {
                sem::lea_mnd(b, reg(), sib_base())
            } else {
                sem::lea_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::LeaSibd => {
            if rex_w {
                if no_index() {
                    sem::lea_m8_64(b, reg(), sib_base(), disp8())
                } else {
                    sem::lea_sibd_64(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
                }
            } else if no_index() {
                sem::lea_m8(b, reg(), sib_base(), disp8())
            } else {
                sem::lea_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::LeaSibd32 => {
            if rex_w {
                if no_index() {
                    sem::lea_m32_64(b, reg(), sib_base(), disp32())
                } else {
                    sem::lea_sibd32_64(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
                }
            } else if no_index() {
                sem::lea_m32(b, reg(), sib_base(), disp32())
            } else {
                sem::lea_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::LeaSibabs => {
            // SIB abs with REX.W is unimplemented (direct番地 + REX). Fall through to 32-bit for now.
            // 64-bit SIB abs (lea_sibabs_64) exists but dispatch keeps 32-bit for compatibility.
            // REX.W LEA SIB abs は未対応のため 32ビットで扱う (4GB 未満想定).
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
        Insn::AddRmImm8 => {
            if rex_w {
                sem::add_rm64_imm8(b, rm(), disp8())
            } else {
                sem::add_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::AddRmImm8Mem8 => {
            // 83 /0 mod=01 [base+disp8],imm8 (32b)。disp は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::add_rm64_imm8_mem8(b, rm(), d8, imm)
            } else {
                sem::add_rm32_imm8_mem8(b, rm(), d8, imm)
            }
        }
        Insn::AddRmImm8Memnd => {
            // 83 /0 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::add_rm64_imm8_memnd(b, rm(), imm)
            } else {
                sem::add_rm32_imm8_memnd(b, rm(), imm)
            }
        }
        Insn::AddRmImm8Mem32 => {
            // 83 /0 mod=10 [base+disp32],imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::add_rm64_imm8_mem32(b, rm(), disp, imm)
            } else {
                sem::add_rm32_imm8_mem32(b, rm(), disp, imm)
            }
        }
        Insn::AddRm32Imm8Rip => {
            // 83 05 + disp32 + imm8 (56b)。RIP 相対.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::add_rm64_imm8_rip(b, eip as u64 + nbytes, disp, imm)
            } else if is64 {
                sem::add_rm32_imm8_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::add_rm32_imm8_abs(b, ((word >> 8) as u32).swap_bytes(), imm)
            }
        }
        Insn::OrRmImm8 => {
            if rex_w {
                sem::or_rm64_imm8(b, rm(), disp8())
            } else {
                sem::or_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::OrRmImm8Memnd => {
            // 83 /1 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::or_rm64_imm8_memnd(b, rm(), imm)
            } else {
                sem::or_rm32_imm8_memnd(b, rm(), imm)
            }
        }
        Insn::OrRmImm8Mem8 => {
            // 83 /1 mod=01 [base+disp8],imm8 (32b)。
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::or_rm64_imm8_mem8(b, rm(), d8, imm)
            } else {
                sem::or_rm32_imm8_mem8(b, rm(), d8, imm)
            }
        }
        Insn::OrRmImm8Mem32 => {
            // 83 /1 mod=10 [base+disp32],imm8 (56b)。
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::or_rm64_imm8_mem32(b, rm(), disp, imm)
            } else {
                sem::or_rm32_imm8_mem32(b, rm(), disp, imm)
            }
        }
        Insn::AdcRmImm8 => {
            if rex_w {
                sem::adc_rm64_imm8(b, rm(), disp8())
            } else {
                sem::adc_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::SbbRmImm8 => {
            if rex_w {
                sem::sbb_rm64_imm8(b, rm(), disp8())
            } else {
                sem::sbb_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::SubRmImm8 => {
            if rex_w {
                sem::sub_rm64_imm8(b, rm(), disp8())
            } else {
                sem::sub_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::XorRmImm8 => {
            if rex_w {
                sem::xor_rm64_imm8(b, rm(), disp8())
            } else {
                sem::xor_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::XorRmImm8Mem8 => {
            // 83 /6 mod=01 [base+disp8],imm8 (32b)。disp は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::xor_rm64_imm8_mem8(b, rm(), d8, imm)
            } else {
                sem::xor_rm32_imm8_mem8(b, rm(), d8, imm)
            }
        }
        Insn::XorRmImm8Memnd => {
            // 83 /6 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::xor_rm64_imm8_memnd(b, rm(), imm)
            } else {
                sem::xor_rm32_imm8_memnd(b, rm(), imm)
            }
        }
        Insn::XorRmImm8Mem32 => {
            // 83 /6 mod=10 [base+disp32],imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::xor_rm64_imm8_mem32(b, rm(), disp, imm)
            } else {
                sem::xor_rm32_imm8_mem32(b, rm(), disp, imm)
            }
        }
        Insn::SubRmImm8Mem8 => {
            // 83 /5 mod=01 [base+disp8],imm8 (32b)。disp は (word>>8) 下位8、imm は最下位8.
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::sub_rm64_imm8_mem8(b, rm(), d8, imm)
            } else {
                sem::sub_rm32_imm8_mem8(b, rm(), d8, imm)
            }
        }
        Insn::SubRmImm8Memnd => {
            // 83 /5 mod=00 [base],imm8 (24b)。imm は最下位8.
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::sub_rm64_imm8_memnd(b, rm(), imm)
            } else {
                sem::sub_rm32_imm8_memnd(b, rm(), imm)
            }
        }
        Insn::SubRmImm8Mem32 => {
            // 83 /5 mod=10 [base+disp32],imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::sub_rm64_imm8_mem32(b, rm(), disp, imm)
            } else {
                sem::sub_rm32_imm8_mem32(b, rm(), disp, imm)
            }
        }
        Insn::SubRmImm8Sibd => {
            // 83 /5 SIB mod=01 [base+disp8],imm8 (40b)。seq 0x4d0bfa の subl $0x1c, 0x58(%rsp)。
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if has66 {
                    sem::sub_m16_imm8_mem8(b, base, d8, imm)
                } else if rex_w {
                    sem::sub_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::sub_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if has66 {
                sem::sub_m16_imm8_sibd(b, base, idx, shift, d8, imm)
            } else if rex_w {
                sem::sub_rm64_imm8_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::sub_rm32_imm8_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::AndRmImm8Mem8 => {
            // 83 /4 mod=01 [base+disp8],imm8 (32b)。
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::and_rm64_imm8_mem8(b, rm(), d8, imm)
            } else {
                sem::and_rm32_imm8_mem8(b, rm(), d8, imm)
            }
        }
        Insn::AndRmImm8Memnd => {
            // 83 /4 mod=00 [base],imm8 (24b)。
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::and_rm64_imm8_memnd(b, rm(), imm)
            } else {
                sem::and_rm32_imm8_memnd(b, rm(), imm)
            }
        }
        Insn::AndRmImm8Sibd => {
            // 83 /4 SIB mod=01 [base+disp8],imm8 (40b)。no_index は base のみ、索引ありは SIB スケール.
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if has66 {
                    sem::and_m16_imm8_mem8(b, base, d8, imm)
                } else if rex_w {
                    sem::and_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::and_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if has66 {
                sem::and_m16_imm8_sibd(b, base, idx, shift, d8, imm)
            } else if rex_w {
                sem::and_rm64_imm8_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::and_rm32_imm8_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::OrRmImm8Sibd => {
            // 83 /1 SIB mod=01 [base+disp8],imm8 (40b)。no_index は base のみ、索引ありは SIB スケール.
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            // REX.W で64bit、REX.X/B で索引/ベース拡張.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::or_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::or_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if rex_w {
                sem::or_rm64_imm8_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::or_rm32_imm8_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::AddRmImm8Sibd => {
            // 83 /0 SIB mod=01 [base+disp8],imm8 (40b)。test 0x5b1d4e 対応.
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            // REX.W で64bit、REX.X/B で索引/ベース拡張。no_index は base+disp8 のみ.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::add_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::add_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if rex_w {
                sem::add_rm64_imm8_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::add_rm32_imm8_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::CmpRmImm8Sibabs => {
            // 83 /7 SIB mod=00 base=101。id 0x4c0a78 対応.
            let sib_v = ((word >> 40) & 0xff) as u8;
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::cmp_rm64_imm8_abs(b, disp, imm)
                } else {
                    sem::cmp_rm32_imm8_abs(b, disp as u32, imm)
                }
            } else if rex_w {
                sem::cmp_rm64_imm8_sibabs(b, idx, shift, disp, imm)
            } else {
                sem::cmp_rm32_imm8_sibabs(b, idx, shift, disp, imm)
            }
        }
        Insn::CmpRmImm8Sibd32 => {
            // 83 /7 SIB mod=10 [base+index*scale+disp32],imm8。true 0x4bed16 対応.
            let sib_v = ((word >> 40) & 0xff) as u8;
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::cmp_rm64_imm8_mem32(b, base, disp, imm)
                } else {
                    sem::cmp_rm32_imm8_mem32(b, base, disp, imm)
                }
            } else if rex_w {
                sem::cmp_rm64_imm8_sibd32(b, base, idx, shift, disp, imm)
            } else {
                sem::cmp_rm32_imm8_sibd32(b, base, idx, shift, disp, imm)
            }
        }
        Insn::CmpRmImm8Sibd => {
            // 83 /7 SIB mod=01 [base+index*scale+disp8],imm8 (40b)。seq 10 の停止点 0x45bbd8 対応.
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            // REX.W で64bit、REX.X/B で索引/ベース拡張。no_index は base+disp8 のみ.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::cmp_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::cmp_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if rex_w {
                sem::cmp_rm64_imm8_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::cmp_rm32_imm8_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::OrRmImm8Sib => {
            // 83 /1 SIB mod=00 [base+index*scale],imm8。awk 0x4a1704 対応.
            // SIB は (word>>8) 下位8、imm は最下位8。base は SIB 下位3 + REX.B。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::or_rm64_imm8_memnd(b, base, imm)
                } else {
                    sem::or_rm32_imm8_memnd(b, base, imm)
                }
            } else if rex_w {
                sem::or_rm64_imm8_sib(b, base, idx, shift, imm)
            } else {
                sem::or_rm32_imm8_sib(b, base, idx, shift, imm)
            }
        }
        Insn::AndRmImm8Sib => {
            // 83 /4 SIB mod=00 [base],imm8 (32b)。no_index は base のみ、索引ありは SIB スケール.
            // SIB は (word>>8) 下位8、imm は最下位8。base は SIB 下位3 + REX.B。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::and_rm64_imm8_memnd(b, base, imm)
                } else {
                    sem::and_rm32_imm8_memnd(b, base, imm)
                }
            } else if rex_w {
                sem::and_rm64_imm8_sib(b, base, idx, shift, imm)
            } else {
                sem::and_rm32_imm8_sib(b, base, idx, shift, imm)
            }
        }
        Insn::AndRmImm8Mem32 => {
            // 83 /4 mod=10 [base+disp32],imm8 (56b)。
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::and_rm64_imm8_mem32(b, rm(), disp, imm)
            } else {
                sem::and_rm32_imm8_mem32(b, rm(), disp, imm)
            }
        }
        Insn::CmpRmImm8Mem32 => {
            // 83 /7 mod=10 [base+disp32],imm8 (56b)。
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::cmp_rm64_imm8_mem32(b, rm(), disp, imm)
            } else {
                sem::cmp_rm32_imm8_mem32(b, rm(), disp, imm)
            }
        }
        Insn::CmpRmImm8 => {
            if rex_w {
                sem::cmp_rm64_imm8(b, rm(), disp8())
            } else {
                sem::cmp_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::CmpRmImm8m8 => {
            // mod=01 m8 形：disp8 は下から2バイト目、imm8 は最下位。
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let i8 = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::cmp_rm64_imm8m8(b, rm(), d8, i8)
            } else {
                sem::cmp_rm32_imm8m8(b, rm(), d8, i8)
            }
        }
        Insn::CmpRmImm8Memnd => {
            // mod=00 m8 形：imm8 は最下位.
            let i8 = (word & 0xff) as u8 as i8;
            sem::cmp_rm32_imm8_memnd(b, rm(), i8)
        }
        Insn::CmpRmImm8Sib => {
            // 83 /7 SIB mod=00 [base],imm8 (32b)。no_index は base のみ、索引ありは SIB スケール.
            // SIB は (word>>8) 下位8、imm は最下位8。base は SIB 下位3 + REX.B。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::cmp_rm64_imm8_memnd(b, base, imm)
                } else {
                    sem::cmp_rm32_imm8_memnd(b, base, imm)
                }
            } else if rex_w {
                sem::cmp_rm64_imm8_sib(b, base, idx, shift, imm)
            } else {
                sem::cmp_rm32_imm8_sib(b, base, idx, shift, imm)
            }
        }
        Insn::AddM16ImmSib => {
            // 66 83 /0 SIB mod=00 [base+index*scale],imm8 (32b)。
            // SIB は (word>>8) 下位8、imm は最下位8.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx = Gpr(((sib_v >> 3) & 7) | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            sem::add_m16_imm_sib(b, base, idx, shift, imm)
        }
        Insn::SubRm32Imm => {
            if rex_w {
                sem::sub_rm64_imm(b, rm(), imm32())
            } else {
                sem::sub_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::SubRm64Imm => sem::sub_rm64_imm(b, rm(), imm32()),
        Insn::AddRm32Imm => {
            if rex_w {
                sem::add_rm64_imm(b, rm(), imm32())
            } else {
                sem::add_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::AddRm64Imm => sem::add_rm64_imm(b, rm(), imm32()),
        Insn::OrRm32Imm => {
            if rex_w {
                sem::or_rm64_imm(b, rm(), imm32())
            } else {
                sem::or_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::OrRm32ImmSib => {
            // 81 /1 SIB mod=00 [base+index*scale],imm32。awk 0x4a4354 対応。imm は下位32 LE.
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                if rex_w {
                    sem::or_rm64_imm_memnd(b, sib_base(), imm)
                } else {
                    sem::or_rm32_imm_memnd(b, sib_base(), imm)
                }
            } else if rex_w {
                sem::or_rm64_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm)
            } else {
                sem::or_rm32_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm)
            }
        }
        Insn::OrRm32ImmMemnd => {
            // 81 /1 mod=00 [base],imm32 (48b)。imm は下位32 LE.
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if rex_w {
                sem::or_rm64_imm_memnd(b, rm(), imm)
            } else {
                sem::or_rm32_imm_memnd(b, rm(), imm)
            }
        }
        Insn::AndRm32ImmMem8 => {
            // 81 /4 mod=01 [base+disp8],imm32。echo/id 0x4c08a2 対応.
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if rex_w {
                sem::and_rm64_imm_mem8(b, rm(), d8, imm)
            } else {
                sem::and_rm32_imm_mem8(b, rm(), d8, imm)
            }
        }
        Insn::OrRm32ImmMem8 => {
            // 81 /1 mod=01 [base+disp8],imm32 (56b)。disp は (word>>32) 下位8、imm は下位32 LE.
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if rex_w {
                sem::or_rm64_imm_mem8(b, rm(), d8, imm)
            } else {
                sem::or_rm32_imm_mem8(b, rm(), d8, imm)
            }
        }
        Insn::AdcRm32Imm => {
            if rex_w {
                sem::adc_rm64_imm(b, rm(), imm32())
            } else {
                sem::adc_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::SbbRm32Imm => {
            if rex_w {
                sem::sbb_rm64_imm(b, rm(), imm32())
            } else {
                sem::sbb_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::AndRm32Imm => {
            if rex_w {
                sem::and_rm64_imm(b, rm(), imm32())
            } else {
                sem::and_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::XorRm32Imm => {
            if rex_w {
                sem::xor_rm64_imm(b, rm(), imm32())
            } else {
                sem::xor_rm32_imm(b, rm(), imm32())
            }
        }
        Insn::OrRm32Rip => {
            // 81 0D + disp32 + imm32 (80b)。disp は (word>>32) 下位32 LE、imm は最下位32.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            if is64 {
                sem::or_rm32_rip(b, eip as u64 + nbytes, disp, imm32())
            } else {
                sem::or_rm32_abs(b, ((word >> 32) as u32).swap_bytes(), imm32())
            }
        }
        Insn::AndRm32Rip => {
            // 81 25 + disp32 + imm32 (80b)。disp は (word>>32) 下位32 LE、imm は最下位32.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            if is64 {
                sem::and_rm32_rip(b, eip as u64 + nbytes, disp, imm32())
            } else {
                sem::and_rm32_abs(b, ((word >> 32) as u32).swap_bytes(), imm32())
            }
        }
        Insn::AddRm32Rip => {
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            if is64 {
                sem::add_rm32_rip(b, eip as u64 + nbytes, disp, imm32())
            } else {
                sem::add_rm32_abs(b, ((word >> 32) as u32).swap_bytes(), imm32())
            }
        }
        Insn::CmpRm32Imm => sem::cmp_rm32_imm(b, rm(), imm32()),
        Insn::CmpRm64Imm => sem::cmp_rm64_imm(b, rm(), imm32()),
        Insn::CmpRm32ImmMemnd => {
            // 81 /7 mod=00 [base],imm32 (48b)。imm は下位32 LE.
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if rex_w {
                sem::cmp_rm64_imm_memnd(b, rm(), imm)
            } else {
                sem::cmp_rm32_imm_memnd(b, rm(), imm)
            }
        }
        Insn::CmpRm32ImmMem8 => {
            // 81 /7 mod=01 [base+disp8],imm32 (56b)。disp は (word>>32) 下位8、imm は下位32 LE.
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            // REX.W の64bit比較は未対応のため32bitで比較する（試作）。
            sem::cmp_rm32_imm_mem8(b, rm(), d8, imm)
        }
        Insn::CmpRm32ImmMem32 => {
            // 81 /7 mod=10 [base+disp32],imm32 (80b)。disp は (word>>32) 上位32 LE、imm は下位32 LE.
            // word組立は opcode上位詰めのため disp は上位32、imm は下位32.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            sem::cmp_rm32_imm_mem32(b, rm(), disp, imm)
        }
        Insn::AddRRip => {
            if rex_w {
                sem::add_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::add_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::add_r32_abs(b, reg(), imm32())
            }
        }
        Insn::AddRMemnd => {
            if rex_w {
                sem::add_r64_memnd(b, reg(), rm())
            } else {
                sem::add_r32_memnd(b, reg(), rm())
            }
        }
        Insn::AddRMem8 => {
            if rex_w {
                sem::add_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::add_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::AddRSibd32 => {
            // 03 /r SIB mod=10。id 0x4d31d6 対応.
            if no_index() {
                if rex_w {
                    sem::add_r64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::add_r32_mem32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::add_r64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::add_r32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::OrRSibd => {
            // 0B SIB mod=01 [base+index*scale+disp8]。sed 0x4c9424 対応.
            // SIB は (word>>8) 下位8、disp は最下位8。base は SIB 下位3 + REX.B。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::or_r64_mem8(b, reg(), base, d8)
                } else {
                    sem::or_r32_mem8(b, reg(), base, d8)
                }
            } else if rex_w {
                sem::or_r64_sibd_indexed(b, reg(), base, idx, shift, d8)
            } else {
                sem::or_r32_sibd_indexed(b, reg(), base, idx, shift, d8)
            }
        }
        Insn::AddRSibd => {
            // 03 SIB mod=01 [base+index*scale+disp8] (32b)。sha1sum 0x5cab68 対応.
            // no_index は base+disp8 のみ。SIB は (word>>8) 下位8、disp は最下位8.
            // base は SIB 下位3 + REX.B。dst は reg フィールド.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::add_r64_sibd(b, reg(), base, d8)
                } else {
                    sem::add_r32_sibd(b, reg(), base, d8)
                }
            } else if rex_w {
                sem::add_r64_sibd_indexed(b, reg(), base, idx, shift, d8)
            } else {
                sem::add_r32_sibd_indexed(b, reg(), base, idx, shift, d8)
            }
        }
        Insn::AddRMem32 => {
            if rex_w {
                sem::add_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::add_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::AddRSib => {
            // 03 /r SIB mod=00 [base+index*scale]。md5sum 0x5ca46d 対応. no_index は [base].
            if no_index() {
                if rex_w {
                    sem::add_r64_memnd(b, reg(), sib_base())
                } else {
                    sem::add_r32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::add_r64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::add_r32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::XorRMemnd => {
            if rex_w {
                sem::xor_r64_memnd(b, reg(), rm())
            } else {
                sem::xor_r32_memnd(b, reg(), rm())
            }
        }
        Insn::XorRMem8 => {
            if rex_w {
                sem::xor_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::xor_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::XorRMem32 => {
            if rex_w {
                sem::xor_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::xor_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::XorRSib => {
            // 33 /r SIB mod=00 [base+index*scale]。no_index は [base].
            if no_index() {
                if rex_w {
                    sem::xor_r64_memnd(b, reg(), sib_base())
                } else {
                    sem::xor_r32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::xor_r64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::xor_r32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::XorRSibd => {
            if no_index() {
                if rex_w {
                    sem::xor_r64_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::xor_r32_mem8(b, reg(), sib_base(), disp8())
                }
            } else if rex_w {
                sem::xor_r64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::xor_r32_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::XorRSibd32 => {
            if no_index() {
                if rex_w {
                    sem::xor_r64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::xor_r32_mem32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::xor_r64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::xor_r32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::XorRRip => {
            if rex_w {
                sem::xor_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::xor_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::xor_r32_abs(b, reg(), imm32())
            }
        }
        Insn::AndRMemnd => {
            if rex_w {
                sem::and_r64_memnd(b, reg(), rm())
            } else {
                sem::and_r32_memnd(b, reg(), rm())
            }
        }
        Insn::AndRMem8 => {
            if rex_w {
                sem::and_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::and_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::AndRMem32 => {
            if rex_w {
                sem::and_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::and_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::AndRRip => {
            if rex_w {
                sem::and_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::and_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::and_r32_abs(b, reg(), imm32())
            }
        }
        Insn::AdcRMemnd => {
            if rex_w {
                sem::adc_r64_memnd(b, reg(), rm())
            } else {
                sem::adc_r32_memnd(b, reg(), rm())
            }
        }
        Insn::AdcRMem8 => {
            if rex_w {
                sem::adc_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::adc_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::AdcRMem32 => {
            if rex_w {
                sem::adc_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::adc_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::AdcRRip => {
            if rex_w {
                sem::adc_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::adc_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::adc_r32_abs(b, reg(), imm32())
            }
        }
        Insn::SbbRMemnd => {
            if rex_w {
                sem::sbb_r64_memnd(b, reg(), rm())
            } else {
                sem::sbb_r32_memnd(b, reg(), rm())
            }
        }
        Insn::SbbRMem8 => {
            if rex_w {
                sem::sbb_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::sbb_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::SbbRMem32 => {
            if rex_w {
                sem::sbb_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::sbb_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::SbbRRip => {
            if rex_w {
                sem::sbb_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::sbb_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::sbb_r32_abs(b, reg(), imm32())
            }
        }
        Insn::SubRMemnd => {
            if rex_w {
                sem::sub_r64_memnd(b, reg(), rm())
            } else {
                sem::sub_r32_memnd(b, reg(), rm())
            }
        }
        Insn::SubRMem8 => {
            if rex_w {
                sem::sub_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::sub_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::SubRSib => {
            // 2B /r SIB mod=00 [base+index*scale]。basename 0x4898fc 対応. no_index は [base].
            if no_index() {
                if rex_w {
                    sem::sub_r64_memnd(b, reg(), sib_base())
                } else {
                    sem::sub_r32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::sub_r64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::sub_r32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::SubRSibd => {
            // 2B SIB mod=01 [base+index*scale+disp8] (32b)。no_index は base+disp8 のみ.
            // disp は最下位8。dst は reg フィールド.
            let d8 = (word & 0xff) as u8 as i8;
            if no_index() {
                if rex_w {
                    sem::sub_r64_sibd(b, reg(), sib_base(), d8)
                } else {
                    sem::sub_r32_sibd(b, reg(), sib_base(), d8)
                }
            } else if rex_w {
                sem::sub_r64_sibd_indexed(b, reg(), sib_base(), sib_idx(), sib_shift(), d8)
            } else {
                sem::sub_r32_sibd_indexed(b, reg(), sib_base(), sib_idx(), sib_shift(), d8)
            }
        }
        Insn::SubRMem32 => {
            if rex_w {
                sem::sub_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::sub_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::SubRRip => {
            if rex_w {
                sem::sub_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::sub_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::sub_r32_abs(b, reg(), imm32())
            }
        }
        Insn::OrRMemnd => {
            if rex_w {
                sem::or_r64_memnd(b, reg(), rm())
            } else {
                sem::or_r32_memnd(b, reg(), rm())
            }
        }
        Insn::OrRMem8 => {
            if rex_w {
                sem::or_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::or_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::OrRMem32 => {
            if rex_w {
                sem::or_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::or_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::OrRSib => {
            // 0B /r SIB mod=00 [base+index*scale]。sed 0x5be0c9 対応. no_index は [base].
            if no_index() {
                if rex_w {
                    sem::or_r64_memnd(b, reg(), sib_base())
                } else {
                    sem::or_r32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::or_r64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::or_r32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::AddRSibabs => {
            // 03 /r mod=00 SIB 直接番地 (7B)。disp32 は最下位32 LE。
            // no_index は [disp32]、索引ありは [idx*scale+disp32].
            // FS 上書きの有無でベースを切り替える（索引あり+FS は未対応のため FS を無視する）。
            let disp = disp32();
            let disp_le = imm32();
            if no_index() {
                match fs {
                    Some(base) if rex_w => sem::add_r64_fs_abs(b, reg(), base, disp),
                    Some(base) => sem::add_r32_fs_abs(b, reg(), base, disp),
                    None if rex_w => sem::add_r64_abs(b, reg(), disp_le),
                    None => sem::add_r32_abs(b, reg(), disp_le),
                }
            } else if rex_w {
                sem::add_r64_sibabs(b, reg(), sib_idx(), sib_shift(), disp)
            } else {
                sem::add_r32_sibabs(b, reg(), sib_idx(), sib_shift(), disp)
            }
        }
        Insn::SubRSibabs => {
            // 2B /r mod=00 SIB 直接番地 (7B)。ADD と同型.
            let disp = disp32();
            let disp_le = imm32();
            if no_index() {
                match fs {
                    Some(base) if rex_w => sem::sub_r64_fs_abs(b, reg(), base, disp),
                    Some(base) => sem::sub_r32_fs_abs(b, reg(), base, disp),
                    None if rex_w => sem::sub_r64_abs(b, reg(), disp_le),
                    None => sem::sub_r32_abs(b, reg(), disp_le),
                }
            } else if rex_w {
                sem::sub_r64_sibabs(b, reg(), sib_idx(), sib_shift(), disp)
            } else {
                sem::sub_r32_sibabs(b, reg(), sib_idx(), sib_shift(), disp)
            }
        }
        Insn::CmpRSibabs => {
            // 3B /r mod=00 SIB 直接番地 (7B)。ADD/SUB と同型.
            let disp = disp32();
            let disp_le = imm32();
            if no_index() {
                match fs {
                    Some(base) if rex_w => sem::cmp_r64_fs_abs(b, reg(), base, disp),
                    Some(base) => sem::cmp_r32_fs_abs(b, reg(), base, disp),
                    None if rex_w => sem::cmp_r64_abs(b, reg(), disp_le),
                    None => sem::cmp_r32_abs(b, reg(), disp_le),
                }
            } else if rex_w {
                sem::cmp_r64_sibabs(b, reg(), sib_idx(), sib_shift(), disp)
            } else {
                sem::cmp_r32_sibabs(b, reg(), sib_idx(), sib_shift(), disp)
            }
        }
        Insn::OrRRip => {
            if rex_w {
                sem::or_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::or_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::or_r32_abs(b, reg(), imm32())
            }
        }
        Insn::OrMRip => {
            if is64 {
                sem::or_m32_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::or_m32_r32_abs(b, reg(), imm32())
            }
        }
        Insn::Movsxd => {
            if rex_w {
                sem::movsxd_rm64(b, reg(), rm())
            } else {
                sem::movsxd_rm32(b, reg(), rm())
            }
        }
        Insn::MovsxdMemnd => {
            if rex_w {
                sem::movsxd_rm64_memnd(b, reg(), rm())
            } else {
                sem::movsxd_rm32_memnd(b, reg(), rm())
            }
        }
        Insn::MovsxdMem8 => {
            if rex_w {
                sem::movsxd_rm64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::movsxd_rm32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::MovsxdMem32 => {
            if rex_w {
                sem::movsxd_rm64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::movsxd_rm32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::MovsxdRip => {
            // 63 05 + disp32 (mod=00 RIP)。REX.W で64bit符号拡張.
            if is64 {
                if rex_w {
                    sem::movsxd_rm64_rip(b, reg(), eip as u64 + nbytes, disp32())
                } else {
                    sem::movsxd_rm32_rip(b, reg(), eip as u64 + nbytes, disp32())
                }
            } else {
                sem::movsxd_rm32_abs(b, reg(), imm32())
            }
        }
        Insn::MovsxdSib => {
            if no_index() {
                if rex_w {
                    sem::movsxd_rm64_memnd(b, reg(), sib_base())
                } else {
                    sem::movsxd_rm32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::movsxd_rm64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::movsxd_rm32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::MovsxdSibd => {
            if no_index() {
                if rex_w {
                    sem::movsxd_rm64_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::movsxd_rm32_mem8(b, reg(), sib_base(), disp8())
                }
            } else if rex_w {
                sem::movsxd_rm64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::movsxd_rm32_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::MovsxdSibd32 => {
            if no_index() {
                if rex_w {
                    sem::movsxd_rm64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::movsxd_rm32_mem32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::movsxd_rm64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::movsxd_rm32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::Cwde => {
            if rex_w {
                sem::cdqe(b)
            } else {
                sem::cwde(b)
            }
        }
        Insn::Cdq => {
            // CDQ/CQO (0x99)。od 0x5acde6 対応。REX.W で64ビット.
            if rex_w { sem::cqo(b) } else { sem::cdq(b) }
        }
        Insn::CmpRm32 => {
            if rex_w {
                sem::cmp_rm64(b, rm(), reg())
            } else {
                sem::cmp_rm32(b, rm(), reg())
            }
        }
        Insn::CmpRSib => {
            // 3B /r SIB mod=00 [base+index*scale] (24b)。mv 0x5ab8fb 対応. no_index は [base].
            // dst は reg フィールド.
            if no_index() {
                if rex_w {
                    sem::cmp_r64_memnd(b, reg(), sib_base())
                } else {
                    sem::cmp_r32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::cmp_r64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::cmp_r32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::CmpRSibd => {
            // 3B /r SIB mod=01 [base+index*scale+disp8] (32b)。dst は reg フィールド.
            // disp は最下位8。no_index は base+disp8 のみ.
            let d8 = (word & 0xff) as u8 as i8;
            if no_index() {
                if rex_w {
                    sem::cmp_r64_mem8(b, reg(), sib_base(), d8)
                } else {
                    sem::cmp_r32_mem8(b, reg(), sib_base(), d8)
                }
            } else if rex_w {
                sem::cmp_r64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), d8)
            } else {
                sem::cmp_r32_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), d8)
            }
        }
        Insn::CmpRSibd32 => {
            if no_index() {
                if rex_w {
                    sem::cmp_r64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::cmp_r32_mem32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::cmp_r64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::cmp_r32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::CmpRmMem32 => {
            if rex_w {
                sem::cmp_rm64_mem32(b, rm(), disp32(), reg())
            } else {
                sem::cmp_rm32_mem32(b, rm(), disp32(), reg())
            }
        }
        Insn::CmpRmRip => {
            if rex_w {
                sem::cmp_rm64_rip(b, eip as u64 + nbytes, disp32(), reg())
            } else if is64 {
                sem::cmp_rm32_rip(b, eip as u64 + nbytes, disp32(), reg())
            } else {
                sem::cmp_rm32_abs(b, imm32(), reg())
            }
        }
        Insn::CmpRmMem8 => {
            if rex_w {
                sem::cmp_rm64_mem8(b, rm(), disp8(), reg())
            } else {
                sem::cmp_rm32_mem8(b, rm(), disp8(), reg())
            }
        }
        Insn::CmpM32R32Sibd32 => {
            // 39 /r SIB mod=10 [base+index*scale+disp32]。true 0x4bed0c 対応.
            if no_index() {
                if rex_w {
                    sem::cmp_rm64_mem32(b, sib_base(), disp32(), reg())
                } else {
                    sem::cmp_rm32_mem32(b, sib_base(), disp32(), reg())
                }
            } else if rex_w {
                sem::cmp_m64_r64_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::cmp_m32_r32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            }
        }
        Insn::CmpM32R32Sibd => {
            // 39 /r SIB mod=01 [base+index*scale+disp8] (32b)。no_index は base+disp8 のみ.
            // SIB は (word>>8) 下位8、disp は最下位8。dst はメモリ、src は reg.
            let d8 = (word & 0xff) as u8 as i8;
            if no_index() {
                if rex_w {
                    sem::cmp_rm64_mem8(b, sib_base(), d8, reg())
                } else {
                    sem::cmp_rm32_mem8(b, sib_base(), d8, reg())
                }
            } else if rex_w {
                sem::cmp_m64_r64_sibd(b, sib_base(), sib_idx(), sib_shift(), d8, reg())
            } else {
                sem::cmp_m32_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), d8, reg())
            }
        }
        Insn::CmpM32R32Sib => {
            // 39 /r SIB mod=00 [base+index*scale]。paste 0x5ad26b 対応. no_index は [base].
            if no_index() {
                if rex_w {
                    sem::cmp_rm64_memnd(b, sib_base(), reg())
                } else {
                    sem::cmp_rm32_memnd(b, sib_base(), reg())
                }
            } else if rex_w {
                sem::cmp_m64_r64_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            } else {
                sem::cmp_m32_r32_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            }
        }
        Insn::CmpRmMemnd => {
            if rex_w {
                sem::cmp_rm64_memnd(b, rm(), reg())
            } else {
                sem::cmp_rm32_memnd(b, rm(), reg())
            }
        }
        Insn::CmpRMemnd => {
            if rex_w {
                sem::cmp_r64_memnd(b, reg(), rm())
            } else {
                sem::cmp_r32_memnd(b, reg(), rm())
            }
        }
        Insn::CmpRMem8 => {
            if rex_w {
                sem::cmp_r64_mem8(b, reg(), rm(), disp8())
            } else {
                sem::cmp_r32_mem8(b, reg(), rm(), disp8())
            }
        }
        Insn::CmpRMem32 => {
            if rex_w {
                sem::cmp_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::cmp_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::CmpRRip => {
            if rex_w {
                sem::cmp_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::cmp_r32_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::cmp_r32_abs(b, reg(), imm32())
            }
        }
        Insn::AndRm32 => {
            if rex_w {
                sem::and_rm64(b, rm(), reg())
            } else {
                sem::and_rm32(b, rm(), reg())
            }
        }
        Insn::OrRm32 => {
            if rex_w {
                sem::or_rm64(b, rm(), reg())
            } else {
                sem::or_rm32(b, rm(), reg())
            }
        }
        Insn::OrM32R32Memnd => {
            if rex_w {
                sem::or_m64_r64_memnd(b, rm(), reg())
            } else {
                sem::or_m32_r32_memnd(b, rm(), reg())
            }
        }
        Insn::OrM32R32Mem8 => {
            if rex_w {
                sem::or_m64_r64_mem8(b, rm(), disp8(), reg())
            } else {
                sem::or_m32_r32_mem8(b, rm(), disp8(), reg())
            }
        }
        Insn::OrM32R32Mem32 => {
            if rex_w {
                sem::or_m64_r64_mem32(b, rm(), disp32(), reg())
            } else {
                sem::or_m32_r32_mem32(b, rm(), disp32(), reg())
            }
        }
        Insn::OrM32R32Sibd => {
            // 09 /r SIB mod=01 [base+index*scale+disp8]。sed 0x400d55 対応.
            if no_index() {
                if rex_w {
                    sem::or_m64_r64_mem8(b, sib_base(), disp8(), reg())
                } else {
                    sem::or_m32_r32_mem8(b, sib_base(), disp8(), reg())
                }
            } else if rex_w {
                sem::or_m64_r64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            } else {
                sem::or_m32_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            }
        }
        Insn::OrM32R32Sibd32 => {
            // 09 /r SIB mod=10 [base+index*scale+disp32] (8B)。src は reg フィールド.
            if rex_w {
                sem::or_m64_r64_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::or_m32_r32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            }
        }
        Insn::OrM32R32Sib => {
            // 09 /r SIB mod=00 [base+index*scale] (24b)。src は reg フィールド.
            // SIB は最下位8。REX.B で base を拡張する。index=4 は基底だけ。seq 0x499151。
            if no_index() {
                if rex_w {
                    sem::or_m64_r64_memnd(b, sib_base(), reg())
                } else {
                    sem::or_m32_r32_memnd(b, sib_base(), reg())
                }
            } else if rex_w {
                sem::or_m64_r64_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            } else {
                sem::or_m32_r32_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            }
        }
        Insn::SubRm32 => {
            if rex_w {
                sem::sub_rm64(b, rm(), reg())
            } else {
                sem::sub_rm32(b, rm(), reg())
            }
        }
        Insn::XorRm32 => {
            if rex_w {
                sem::xor_rm64(b, rm(), reg())
            } else {
                sem::xor_rm32(b, rm(), reg())
            }
        }
        Insn::MovMr32 => {
            if rex_w {
                sem::mov_mr64(b, rm(), reg())
            } else {
                sem::mov_mr32(b, rm(), reg())
            }
        }
        Insn::MulRm32 => {
            if rex_w {
                sem::mul_rm64(b, rm())
            } else {
                sem::mul_rm32(b, rm())
            }
        }
        Insn::ImulRm32 => {
            // F7 /5 reg-direct。REX.W で64bit符号付き積を RDX:RAX に置く.
            if rex_w {
                sem::imul_rm64(b, rm())
            } else {
                sem::imul_rm32(b, rm())
            }
        }
        Insn::DivRm32 => {
            if rex_w {
                sem::div_rm64(b, eip, rm())
            } else {
                sem::div_rm32(b, eip, rm())
            }
        }
        Insn::DivRm32Mem8 => sem::div_rm32_mem8(b, eip, rm(), disp8()),
        Insn::DivRm32Sib => {
            // F7 /6 SIB mod=00 [base+index*scale]。xxd 0x473876 対応。no_index は [base].
            if no_index() {
                sem::div_rm32_memnd(b, eip, sib_base())
            } else {
                sem::div_rm32_sib(b, eip, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::DivRm32Sibd => {
            // F7 /6 SIB mod=01 [base+index*scale+disp8]。no_index は [base+disp8].
            if no_index() {
                sem::div_rm32_mem8(b, eip, sib_base(), disp8())
            } else {
                sem::div_rm32_sibd(b, eip, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::IdivRm32 => sem::idiv_rm32(b, eip, rm()),
        Insn::Cld => sem::cld(b),
        Insn::Std => sem::std(b),
        Insn::Movsb => {
            if rep {
                sem::rep_movsb(b, eip)
            } else {
                sem::movsb_single(b)
            }
        }
        Insn::Movsd => {
            if rep {
                if rex_w {
                    sem::rep_movsq(b, eip)
                } else {
                    sem::rep_movsd(b, eip)
                }
            } else if rex_w {
                sem::movsq_single(b)
            } else {
                sem::movsd_single(b)
            }
        }
        Insn::Stosb => {
            if rep {
                sem::rep_stosb(b, eip)
            } else {
                sem::stosb_single(b)
            }
        }
        Insn::Stosd => {
            if rep {
                if rex_w {
                    sem::rep_stosq(b, eip)
                } else {
                    sem::rep_stosd(b, eip)
                }
            } else if rex_w {
                sem::stosq_single(b)
            } else {
                sem::stosd_single(b)
            }
        }
        Insn::MovdXmm => {
            // 66 0F 6E /r reg-direct。REX.W では MOVQ xmm,r64 (64ビット) として振る舞う.
            // strtod が double ビット列を GPR 経由で XMM に組むのに使う.
            if rex_w {
                sem::movq_xmm_r64(b, xmm_reg_r(), rm0f())
            } else {
                sem::movd_xmm_gpr32(b, xmm_reg_r(), rm0f())
            }
        }
        Insn::MovdXmmM32 => {
            // 0F6E modrm + disp32 (mod=10 RBP)。disp は low32 LE? Actually word 56b: [0F][6E][modrm][disp0..3] (7B). disp = low32 LE? low32 = disp BE? Use disp32() which is (word as u32).swap? Wait word low32 = disp BE? For 56b word, low32 = disp (4B). disp32() = (word as u32).swap_bytes() as i32. Good (since low32 is disp). Good.
            sem::movd_xmm_m32(b, xmm_reg_r(), rm0f(), disp32())
        }
        Insn::MovdXmmRip => {
            // 66 0F 6E 05 + disp32 (mod=00 RIP)。dst は reg フィールド.
            if is64 {
                sem::movd_xmm_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::movd_xmm_abs(b, xmm_reg_r(), imm32())
            }
        }
        Insn::Punpcklbw => sem::punpcklbw(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Punpcklwd => sem::punpcklwd(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Punpckldq => sem::punpckldq(b, xmm_reg_r(), xmm_rm_b()),
        Insn::MovqM64XmmRip => {
            if is64 {
                sem::movq_m64_xmm_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::movq_m64_xmm_abs(b, xmm_reg_r(), imm32())
            }
        }
        Insn::MovqM64XmmMemnd => sem::movq_m64_xmm_memnd(b, xmm_reg_r(), rm0f()),
        Insn::MovqM64XmmMem8 => sem::movq_m64_xmm_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::MovqM64XmmMem32 => sem::movq_m64_xmm_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::MovqXmmM64Rip => {
            if is64 {
                sem::movq_xmm_m64_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::movq_xmm_m64_abs(b, xmm_reg_r(), imm32())
            }
        }
        // MOVQ xmm,[base+disp8] (F3 0F 7E mod=01、4B)。dst は reg フィールド.
        Insn::MovqXmmM64Mem8 => sem::movq_xmm_m64_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        // MOVHPS xmm,[base+disp8] (0F 16 mod=01、4B。66 付き MOVHPD と共用)。dst は reg フィールド.
        Insn::MovhpsXmmM64Mem8 => sem::movhps_xmm_m64_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        // MOVLPD xmm,[base] (66 0F 12 mod=00、3B)。dst は reg フィールド.
        Insn::MovlpdXmmM64Memnd => sem::movlpd_xmm_m64_memnd(b, xmm_reg_r(), rm0f()),
        Insn::Pshufd => {
            let imm = (word & 0xff) as u8;
            // F2 接頭辞では PSHUFLW として振る舞う (0F 70 共有のため Insn を共用).
            if has_f2 {
                sem::pshuflw_xmm(b, xmm_reg_r(), xmm_rm_b(), imm)
            } else {
                sem::pshufd(b, xmm_reg_r(), xmm_rm_b(), imm)
            }
        }
        Insn::Pslldq => {
            let imm = (word & 0xff) as u8;
            // 0F 73 /7: dst は rm フィールド (reg=111 は拡張子)。xmm_reg() は 7 になるため使わない.
            sem::pslldq_xmm(b, xmm_rm_b(), imm)
        }
        Insn::Psrldq => {
            let imm = (word & 0xff) as u8;
            // 0F 73 /3: dst は rm フィールド (reg=011 は拡張子)。
            sem::psrldq_xmm(b, xmm_rm_b(), imm)
        }
        Insn::Psubb => sem::psubb_xmm(b, xmm_reg_r(), xmm_rm_b()),
        // PADDB xmm,xmm (66 0F FC /r reg-direct)。REX.R/B で 8-15 に拡張する.
        Insn::Paddb => sem::paddb_xmm(b, xmm_reg_r(), xmm_rm_b()),
        // PCMPGTB xmm,xmm (66 0F 64 /r reg-direct)。REX.R/B で 8-15 に拡張する.
        Insn::Pcmpgtb => sem::pcmpgtb_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Pxor => sem::pxor_xmm(b, xmm_reg_r(), xmm_rm_b()),
        // XORPS xmm,xmm (0F 57 /r reg-direct)。PXOR と等価.
        Insn::Xorps => sem::pxor_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Pand => sem::pand_xmm(b, xmm_reg_r(), xmm_rm_b()),
        // ANDPD (66 0F 54) は PAND と等価のため意味論を共有する.
        Insn::Andpd => sem::pand_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::AndpdRip => sem::andpd_xmm_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32()),
        // PANDN xmm,xmm (66 0F DF /r reg-direct)。REX.R/B で 8-15 に拡張する.
        Insn::Pandn => sem::pandn_xmm(b, xmm_reg_r(), xmm_rm_b()),
        // CVTSI2SD xmm,r64 (F2 REX.W 0F 2A /r reg-direct)。F2 は剥がし済み.
        Insn::Cvtsi2sdR64 => sem::cvtsi2sd_r64(b, xmm_reg_r(), rm0f()),
        Insn::Cvtsi2sdM32Mem8 => {
            // CVTSI2SD xmm,m32/m64 [base+disp8] (F2 0F 2A mod=01)。F2 は剥がし済み.
            if rex_w {
                sem::cvtsi2sd_xmm_m64_mem8(b, xmm_reg_r(), rm0f(), disp8())
            } else {
                sem::cvtsi2sd_xmm_m32_mem8(b, xmm_reg_r(), rm0f(), disp8())
            }
        }
        // ADDSD xmm,xmm (F2 0F 58 /r reg-direct)。F2 は剥がし済み.
        Insn::Addsd => sem::addsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::AddsdM64Sib => {
            // F2 0F 58 SIB mod=00 [base+index*scale] (4B)。no_index は [base].
            if sib0f_no_index() {
                sem::addsd_xmm_m64_memnd(b, xmm_reg_r(), sib0f_base())
            } else {
                sem::addsd_xmm_m64_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::AddsdXmmM64Rip => {
            // F2 0F 58 05 + disp32 (mod=00 RIP)。F2 は剥がし済み.
            if is64 {
                sem::addsd_xmm_m64_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::addsd_xmm_m64_abs(b, xmm_reg_r(), imm32())
            }
        }
        // SUBSD xmm,xmm (F2 0F 5C /r reg-direct)。F2 は剥がし済み.
        Insn::Subsd => sem::subsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        // MULSD xmm,xmm (F2 0F 59 /r reg-direct)。F2 は剥がし済み.
        Insn::Mulsd => sem::mulsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::MulsdXmmM64Rip => {
            // F2 0F 59 05 + disp32 (mod=00 RIP)。F2 は剥がし済み.
            if is64 {
                sem::mulsd_xmm_m64_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::mulsd_xmm_m64_abs(b, xmm_reg_r(), imm32())
            }
        }
        // COMISD xmm,xmm (66 0F 2F /r reg-direct)。
        Insn::Comisd => sem::comisd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        // UCOMISD (66 0F 2E) は順序なしの旗が等価のため COMISD と意味論を共有する.
        Insn::Ucomisd => sem::comisd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::UcomisdMemnd => sem::ucomisd_xmm_memnd(b, xmm_reg_r(), rm0f()),
        Insn::UcomisdMem8 => sem::ucomisd_xmm_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::UcomisdMem32 => sem::ucomisd_xmm_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::UcomisdRip => sem::ucomisd_xmm_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32()),
        // CVTTSD2SI r64,xmm (F2 REX.W 0F 2C /r reg-direct)。F2 は剥がし済み.
        Insn::Cvttsd2siR64 => sem::cvttsd2si_r64(b, reg0f_as_gpr(), xmm_rm_b()),
        Insn::BtR32Imm => {
            // BT r32,imm8 (0F BA /4 ib reg-direct、4B)。imm は最下位8.
            let imm = (word & 0xff) as u8;
            sem::bt_r32_imm(b, rm0f(), imm)
        }
        Insn::BtM32Imm => {
            // BT m32,imm8 mod=00 [base] (0F BA /4 + ModRM + imm8、4B)。imm は最下位8.
            let imm = (word & 0xff) as u8;
            sem::bt_m32_imm(b, rm0f(), imm)
        }
        Insn::BtM32ImmSibd => {
            // BT m32,imm8 SIB mod=01 [base+disp8] (0F BA /4 + ModRM + SIB + disp8 + imm8、6B)。
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            // no_index は [base+disp8].
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::bt_m32_imm_mem8(b, base, d8, imm)
            } else {
                sem::bt_m32_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::BtsR32Imm => {
            // BTS r32/r64,imm8 (0F BA /5 ib reg-direct、4B)。imm は最下位8。REX.W で64ビット.
            let imm = (word & 0xff) as u8;
            if rex_w {
                sem::bts_r64_imm(b, rm0f(), imm)
            } else {
                sem::bts_r32_imm(b, rm0f(), imm)
            }
        }
        Insn::XaddR32Memnd => {
            // XADD r32,[base] (0F C1 mod=00、3B)。dst は reg フィールド.
            sem::xadd_r32_memnd(b, reg0f_as_gpr(), rm0f())
        }
        Insn::XaddR32Rip => {
            // XADD r32,[RIP+disp32] (0F C1 mod=00 rm=101)。LOCK は無視.
            sem::xadd_r32_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
        }
        Insn::ShldR32Cl => {
            // SHLD r/m32,r32,CL (0F A5 /r mod=11)。REX.W で64ビット.
            // 2バイトオペコードのため rm0f/reg0f で抽出する.
            if rex_w {
                sem::shld_r64_cl(b, rm0f(), reg0f_as_gpr())
            } else {
                sem::shld_r32_cl(b, rm0f(), reg0f_as_gpr())
            }
        }
        Insn::ShrdR32Cl => {
            // SHRD r/m32,r32,CL (0F AD /r mod=11)。seq 10 の停止点 0x4c4425 対応。REX.W で64ビット.
            // 2バイトオペコードのため rm0f/reg0f で抽出する.
            if rex_w {
                sem::shrd_r64_cl(b, rm0f(), reg0f_as_gpr())
            } else {
                sem::shrd_r32_cl(b, rm0f(), reg0f_as_gpr())
            }
        }
        Insn::BtR32Rm => {
            // BT r/m32,r32 (0F A3 /r mod=11)。dst は rm、src は reg (REX.B/R で拡張)。
            // REX.W で64ビット。hexdump 0x5c8dd9 (49 0F A3 D6) 対応.
            // 2バイトオペコードのため rm0f/reg0f で抽出する.
            if rex_w {
                sem::bt_r64_rm(b, rm0f(), reg0f_as_gpr())
            } else {
                sem::bt_r32_rm(b, rm0f(), reg0f_as_gpr())
            }
        }
        Insn::BtsR32Rm => {
            // BTS r/m32,r32 (0F AB /r mod=11)。dst は rm、src は reg (REX.B/R で拡張)。
            if rex_w {
                sem::bts_r64_rm(b, rm0f(), reg0f_as_gpr())
            } else {
                sem::bts_r32_rm(b, rm0f(), reg0f_as_gpr())
            }
        }
        Insn::Pminub => sem::pminub_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Pmaxub => sem::pmaxub_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::PminubMemnd => sem::pminub_xmm_memnd(b, xmm_reg_r(), rm0f()),
        Insn::PminubMem8 => sem::pminub_xmm_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::PminubMem32 => sem::pminub_xmm_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::FnstcwMemnd => sem::fnstcw_memnd(b, rm()),
        Insn::FnstcwMem8 => sem::fnstcw_mem8(b, rm(), disp8()),
        Insn::FnstcwMem32 => sem::fnstcw_mem32(b, rm(), disp32()),
        Insn::FldcwMemnd => sem::fldcw_memnd(b, rm()),
        Insn::FldcwMem8 => sem::fldcw_mem8(b, rm(), disp8()),
        Insn::FldcwMem32 => sem::fldcw_mem32(b, rm(), disp32()),
        Insn::Pcmpeqb => sem::pcmpeqb_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Pcmpeqd => sem::pcmpeqd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Por => sem::por_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::PcmpeqbMemnd => sem::pcmpeqb_xmm_memnd(b, xmm_reg_r(), rm0f()),
        Insn::PcmpeqbMem8 => sem::pcmpeqb_xmm_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::PcmpeqbMem32 => sem::pcmpeqb_xmm_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::PorMemnd => sem::por_xmm_memnd(b, xmm_reg_r(), rm0f()),
        Insn::PorMem8 => sem::por_xmm_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::PorMem32 => sem::por_xmm_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::PorSibd32 => {
            // POR xmm,m128 SIB+disp32 (66 0F EB mod=10 rm=100)。grep 0x43d15b 対応.
            if sib0f_no_index() {
                sem::por_xmm_mem32(b, xmm_reg_r(), sib0f_base(), disp32())
            } else {
                sem::por_xmm_sibd32(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            }
        }
        Insn::Pmovmskb => {
            if rex_w {
                sem::pmovmskb_r64(b, reg0f_as_gpr(), xmm_rm_b())
            } else {
                sem::pmovmskb_r32(b, reg0f_as_gpr(), xmm_rm_b())
            }
        }
        Insn::Punpcklqdq => sem::punpcklqdq(b, xmm_reg_r(), xmm_rm_b()),
        Insn::MovupsLoadSibd32 => {
            if has_f2 {
                if sib0f_no_index() {
                    sem::movsd_load_mem32(b, xmm_reg_r(), sib0f_base(), disp32())
                } else {
                    sem::movsd_load_sibd32(
                        b,
                        xmm_reg_r(),
                        sib0f_base(),
                        sib0f_idx(),
                        sib0f_shift(),
                        disp32(),
                    )
                }
            } else if sib0f_no_index() {
                sem::movups_load_mem32(b, xmm_reg_r(), sib0f_base(), disp32())
            } else {
                sem::movups_load_sibd32(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            }
        }
        Insn::MovupsStoreSibd32 => {
            if has_f2 {
                if sib0f_no_index() {
                    sem::movsd_store_mem32(b, xmm_reg_r(), sib0f_base(), disp32())
                } else {
                    sem::movsd_store_sibd32(
                        b,
                        xmm_reg_r(),
                        sib0f_base(),
                        sib0f_idx(),
                        sib0f_shift(),
                        disp32(),
                    )
                }
            } else if sib0f_no_index() {
                sem::movups_store_mem32(b, xmm_reg_r(), sib0f_base(), disp32())
            } else {
                sem::movups_store_sibd32(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            }
        }
        Insn::MovapsStoreSib => {
            // 0F 29 SIB mod=00。od 0x49788f 対応。MOVUPS と同じ 128 ビット転送.
            if sib0f_no_index() {
                sem::movups_store_memnd(b, xmm_reg_r(), sib0f_base())
            } else {
                sem::movups_store_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::MovapsStoreSibd => {
            // 0F 29 SIB mod=01。sed 0x400d19 対応.
            if sib0f_no_index() {
                sem::movups_store_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
            } else {
                sem::movups_store_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            }
        }
        Insn::MovapsStoreSibd32 => {
            if sib0f_no_index() {
                sem::movups_store_mem32(b, xmm_reg_r(), sib0f_base(), disp32())
            } else {
                sem::movups_store_sibd32(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            }
        }
        Insn::MovqR64Xmm => sem::movq_r64_xmm(b, rm0f(), xmm_reg_r()),
        // MOVSD (F2 0F 10/11) は下位64のみ転送し上位64は保持するため has_f2 で分岐する.
        Insn::MovupsLoadXmm => {
            if has_f2 {
                sem::movsd_xmm_xmm(b, xmm_reg_r(), xmm_rm_b())
            } else {
                sem::movups_xmm_xmm(b, xmm_reg_r(), xmm_rm_b())
            }
        }
        Insn::MovupsStoreXmm => {
            if has_f2 {
                sem::movsd_xmm_xmm(b, xmm_rm_b(), xmm_reg_r())
            } else {
                sem::movups_xmm_xmm(b, xmm_rm_b(), xmm_reg_r())
            }
        }
        Insn::MovupsLoadMemnd => {
            if has_f2 {
                sem::movsd_load_memnd(b, xmm_reg_r(), rm0f())
            } else {
                sem::movups_load_memnd(b, xmm_reg_r(), rm0f())
            }
        }
        Insn::MovupsStoreMemnd => {
            if has_f2 {
                sem::movsd_store_memnd(b, xmm_reg_r(), rm0f())
            } else {
                sem::movups_store_memnd(b, xmm_reg_r(), rm0f())
            }
        }
        Insn::MovupsLoadMem8 => {
            if has_f2 {
                sem::movsd_load_mem8(b, xmm_reg_r(), rm0f(), disp8())
            } else {
                sem::movups_load_mem8(b, xmm_reg_r(), rm0f(), disp8())
            }
        }
        Insn::MovupsStoreMem8 => {
            if has_f2 {
                sem::movsd_store_mem8(b, xmm_reg_r(), rm0f(), disp8())
            } else {
                sem::movups_store_mem8(b, xmm_reg_r(), rm0f(), disp8())
            }
        }
        Insn::MovupsLoadMem32 => {
            if has_f2 {
                sem::movsd_load_mem32(b, xmm_reg_r(), rm0f(), disp32())
            } else {
                sem::movups_load_mem32(b, xmm_reg_r(), rm0f(), disp32())
            }
        }
        Insn::MovupsStoreMem32 => {
            if has_f2 {
                sem::movsd_store_mem32(b, xmm_reg_r(), rm0f(), disp32())
            } else {
                sem::movups_store_mem32(b, xmm_reg_r(), rm0f(), disp32())
            }
        }
        // MOVDQU (F3 0F 6F) は16B非整列転送で MOVUPS と等価のため意味論を共有する.
        Insn::MovdquLoadXmm => sem::movups_xmm_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::MovdquLoadMem8 => sem::movups_load_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::MovdquLoadMemnd => sem::movups_load_memnd(b, xmm_reg_r(), rm0f()),
        Insn::MovdquLoadMem32 => sem::movups_load_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::MovdquLoadSib => {
            if sib0f_no_index() {
                sem::movups_load_memnd(b, xmm_reg_r(), sib0f_base())
            } else {
                sem::movups_load_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        // MOVDQU m128,xmm (F3 0F 7F) は16B非整列転送で MOVUPS と等価のため意味論を共有する.
        // MOVDQA m128,xmm (66 0F 7F) も等価のため共用する.
        Insn::MovdquStoreXmm => sem::movups_xmm_xmm(b, xmm_rm_b(), xmm_reg_r()),
        Insn::MovdquStoreMemnd => sem::movups_store_memnd(b, xmm_reg_r(), rm0f()),
        Insn::MovdquStoreMem8 => sem::movups_store_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::MovdquStoreMem32 => sem::movups_store_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::MovdquStoreSib => {
            if sib0f_no_index() {
                sem::movups_store_memnd(b, xmm_reg_r(), sib0f_base())
            } else {
                sem::movups_store_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        // MOVDQA (66 0F 6F) は16B転送で MOVUPS と等価のため意味論を共有する.
        // mod=00/01/10 は Movdqu とバイト列が同一のため decode は Movdqu 側に寄る.
        // 66 接頭辞の許可のみ行い、分岐は Movdqu 側で処理する.
        Insn::MovdqaLoadRip => sem::movups_load_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32()),
        Insn::MovupsLoadSib => {
            if has_f2 {
                if sib0f_no_index() {
                    sem::movsd_load_memnd(b, xmm_reg_r(), sib0f_base())
                } else {
                    sem::movsd_load_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
                }
            } else if sib0f_no_index() {
                sem::movups_load_memnd(b, xmm_reg_r(), sib0f_base())
            } else {
                sem::movups_load_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::MovupsStoreSib => {
            if has_f2 {
                if sib0f_no_index() {
                    sem::movsd_store_memnd(b, xmm_reg_r(), sib0f_base())
                } else {
                    sem::movsd_store_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
                }
            } else if sib0f_no_index() {
                sem::movups_store_memnd(b, xmm_reg_r(), sib0f_base())
            } else {
                sem::movups_store_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::MovupsLoadSibd => {
            if has_f2 {
                if sib0f_no_index() {
                    sem::movsd_load_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
                } else {
                    sem::movsd_load_sibd(
                        b,
                        xmm_reg_r(),
                        sib0f_base(),
                        sib0f_idx(),
                        sib0f_shift(),
                        disp8(),
                    )
                }
            } else if sib0f_no_index() {
                sem::movups_load_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
            } else {
                sem::movups_load_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            }
        }
        Insn::MovupsStoreSibd => {
            if has_f2 {
                if sib0f_no_index() {
                    sem::movsd_store_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
                } else {
                    sem::movsd_store_sibd(
                        b,
                        xmm_reg_r(),
                        sib0f_base(),
                        sib0f_idx(),
                        sib0f_shift(),
                        disp8(),
                    )
                }
            } else if sib0f_no_index() {
                sem::movups_store_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
            } else {
                sem::movups_store_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            }
        }
        Insn::MovntdqStoreMemnd => sem::movups_store_memnd(b, xmm_reg_r(), rm0f()),
        Insn::MovntdqStoreMem8 => sem::movups_store_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::MovRmImmM32 => {
            // C7 /0 + disp32 + imm32 (mod=10)。disp は上位32、imm は下位32。base 任意.
            let disp = (word >> 32) as u32;
            let disp = disp.swap_bytes() as i32;
            if rex_w {
                sem::mov_rm64_imm_mem32(b, rm(), disp, imm32())
            } else {
                sem::mov_rm32_imm_mem32(b, rm(), disp, imm32())
            }
        }
        Insn::MovRmImmM8 => {
            // C7 /0 mod=01 [base+disp8],imm32 (7B)。disp8 は (word>>32) 下位8、imm は最下位32.
            // FS 上書きでは FS_base + (base+disp8) に格納する.
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            match fs {
                Some(base) if rex_w => sem::mov_rm64_imm_fs_mem8(b, base, rm(), d8, imm32()),
                Some(base) => sem::mov_rm32_imm_fs_mem8(b, base, rm(), d8, imm32()),
                None if rex_w => sem::mov_rm64_imm_mem8(b, rm(), d8, imm32()),
                None => sem::mov_rm32_imm_mem8(b, rm(), d8, imm32()),
            }
        }
        Insn::MovRmImmMemnd => {
            // C7 /0 mod=00 [base],imm32 (6B)。imm は最下位32.
            // FS 上書きでは FS_base + base に格納する.
            match fs {
                Some(base) if rex_w => sem::mov_rm64_imm_fs_memnd(b, base, rm(), imm32()),
                Some(base) => sem::mov_rm32_imm_fs_memnd(b, base, rm(), imm32()),
                None if rex_w => sem::mov_rm64_imm_memnd(b, rm(), imm32()),
                None => sem::mov_rm32_imm_memnd(b, rm(), imm32()),
            }
        }
        Insn::MovRm16ImmM32 => {
            // 66 C7 85 + disp32 + imm16 (64b)。disp は (word>>16) 下位32 LE、imm は最下位16 LE.
            let disp = ((word >> 16) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::mov_rm16_imm_mem32(b, Gpr(5 | ((rex & 1) << 3)), disp, imm)
        }
        Insn::MovRm16ImmMemnd => {
            // 66 C7 /0 mod=00 [base],imm16。xxd 0x4b240f 対応。imm は最下位16 LE.
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::mov_m16_imm_memnd(b, rm(), imm)
        }
        Insn::MovRm16ImmMem8 => {
            // 66 C7 43 5C 01 01 [RBX+0x5C],imm16 (40b+66)。hexdump 0x5c84f9 対応.
            // disp は (word>>16) 下位8、imm は最下位16 LE.
            let d8 = ((word >> 16) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::mov_m16_imm_mem8(b, rm(), d8, imm)
        }
        Insn::MovRm16ImmSibd => {
            // 66 C7 44 24 11 53 00 SIB+disp8+imm16 (48b+66)。stat 0x5af402 対応.
            // SIB は (word>>24) 下位8、disp は (word>>16) 下位8、imm は最下位16 LE.
            let sib_v = ((word >> 24) & 0xff) as u8;
            let d8 = ((word >> 16) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::mov_m16_imm_mem8(b, base, d8, imm)
            } else {
                sem::mov_m16_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::MovRm16ImmSib => {
            // 66 C7 04 24 6C 6C SIB+imm16 (40b+66)。hexdump 0x5c82dd 対応.
            // SIB は (word>>16) 下位8、imm は最下位16 LE。no_index は [base].
            let sib_v = ((word >> 16) & 0xff) as u8;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::mov_m16_imm_memnd(b, base, imm)
            } else {
                sem::mov_m16_imm_sib(b, base, idx, shift, imm)
            }
        }
        Insn::MovRm16ImmRip => {
            // 66 C7 05 + disp32 + imm16 (64b+66)。od 0x5ac863 対応.
            // disp は (word>>16) 下位32 LE、imm は最下位16 LE.
            let disp = ((word >> 16) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            if is64 {
                sem::mov_rm16_imm_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::mov_rm16_imm_abs(b, ((word >> 16) as u32).swap_bytes(), imm)
            }
        }
        Insn::MovRmImmRip => {
            // C7 05 + disp32 + imm32 (mod=00 RIP)。disp は上位32、imm は下位32.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            if rex_w {
                sem::mov_rm64_imm_rip(b, eip as u64 + nbytes, disp, imm32())
            } else if is64 {
                sem::mov_rm32_imm_rip(b, eip as u64 + nbytes, disp, imm32())
            } else {
                sem::mov_rm32_imm_abs(b, ((word >> 32) as u32).swap_bytes(), imm32())
            }
        }
        Insn::MovRmImmSibd32 => {
            // C7 SIB+disp32+imm32 (11B)。disp は下から2番目の32、imm は最下位32.
            // no_index (idx=100) は base のみで扱う.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            if no_index() {
                if rex_w {
                    sem::mov_rm64_imm_mem32(b, sib_base(), disp, imm32())
                } else {
                    sem::mov_rm32_imm_mem32(b, sib_base(), disp, imm32())
                }
            } else if rex_w {
                sem::mov_rm64_imm_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp, imm32())
            } else {
                sem::mov_rm32_imm_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp, imm32())
            }
        }
        Insn::MovRmImmSibabs => {
            // C7 SIB 直接番地+disp32+imm32 (11B, mod=00)。disp は下から2番目の32、imm は最下位32.
            // SIB base=101 (直接番地)。idx=100 (no_index) 以外は sib_idx で扱う.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            let disp_le = ((word >> 32) as u32).swap_bytes();
            if no_index() {
                match fs {
                    Some(base) if rex_w => sem::mov_rm64_imm_fs_abs(b, base, disp, imm32()),
                    Some(base) => sem::mov_rm32_imm_fs_abs(b, base, disp, imm32()),
                    None if rex_w => sem::mov_rm64_imm_abs(b, disp_le, imm32()),
                    None => sem::mov_rm32_imm_abs(b, disp_le, imm32()),
                }
            } else if let Some(base) = fs {
                if rex_w {
                    sem::mov_rm64_imm_fs_sibabs(b, base, sib_idx(), sib_shift(), disp, imm32())
                } else {
                    sem::mov_rm32_imm_fs_sibabs(b, base, sib_idx(), sib_shift(), disp, imm32())
                }
            } else if rex_w {
                sem::mov_rm64_imm_sibabs(b, sib_idx(), sib_shift(), disp, imm32())
            } else {
                sem::mov_rm32_imm_sibabs(b, sib_idx(), sib_shift(), disp, imm32())
            }
        }
        Insn::MovRmImmSib => {
            // C7 /0 SIB mod=00 [base+index*scale]+imm32 (7B)。no_index は [base].
            // FS 上書きでは FS_base + 実効アドレスに格納する.
            if no_index() {
                match fs {
                    Some(base) if rex_w => sem::mov_rm64_imm_fs_memnd(b, base, sib_base(), imm32()),
                    Some(base) => sem::mov_rm32_imm_fs_memnd(b, base, sib_base(), imm32()),
                    None if rex_w => sem::mov_rm64_imm_memnd(b, sib_base(), imm32()),
                    None => sem::mov_rm32_imm_memnd(b, sib_base(), imm32()),
                }
            } else {
                // FS+SIB-indexed は非対応のため暫定で Unimplemented とせず FS 無視で扱う?
                // 既存の FS+SIB 暫定方針に合わせ、FS ありでも通常 SIB として扱う.
                if rex_w {
                    sem::mov_rm64_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm32())
                } else {
                    sem::mov_rm32_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm32())
                }
            }
        }
        Insn::MovRmImmSibd => {
            // C7 /0 SIB mod=01 [base+index*scale+disp8]+imm32 (8B)。disp8 は (word>>32) 下位8.
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            if no_index() {
                match fs {
                    Some(base) if rex_w => {
                        sem::mov_rm64_imm_fs_mem8(b, base, sib_base(), d8, imm32())
                    }
                    Some(base) => sem::mov_rm32_imm_fs_mem8(b, base, sib_base(), d8, imm32()),
                    None if rex_w => sem::mov_rm64_imm_mem8(b, sib_base(), d8, imm32()),
                    None => sem::mov_rm32_imm_mem8(b, sib_base(), d8, imm32()),
                }
            } else if rex_w {
                sem::mov_rm64_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), d8, imm32())
            } else {
                sem::mov_rm32_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), d8, imm32())
            }
        }
        Insn::MovapsStoreMemnd => sem::movups_store_memnd(b, xmm_reg_r(), rm0f()),
        Insn::MovapsStoreMem8 => sem::movups_store_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::MovapsStoreMem32 => sem::movaps_store_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::MovapsStoreRip => {
            sem::movups_store_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
        }
        Insn::MovapsLoadMemnd => sem::movups_load_memnd(b, xmm_reg_r(), rm0f()),
        Insn::MovapsLoadMem8 => sem::movups_load_mem8(b, xmm_reg_r(), rm0f(), disp8()),
        Insn::MovapsLoadMem32 => sem::movups_load_mem32(b, xmm_reg_r(), rm0f(), disp32()),
        Insn::MovapsLoadRip => sem::movups_load_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32()),
        Insn::MovapsLoadXmm => sem::movups_xmm_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::NoplSib => sem::nop(b),
        Insn::NoplSibd => sem::nop(b),
        Insn::NoplSibd32 => sem::nop(b),
        Insn::Cmovb => {
            if rex_w {
                sem::cmovb_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovb_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovne => {
            if rex_w {
                sem::cmovne_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovne_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmove => {
            if rex_w {
                sem::cmove_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmove_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovns => {
            if rex_w {
                sem::cmovns_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovns_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovbe => {
            if rex_w {
                sem::cmovbe_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovbe_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::CmovbeMem8 => {
            // 0F 46 mod=01 [base+disp8]。test 0x4d2874 対応.
            if rex_w {
                sem::cmovbe_r64_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::cmovbe_r32_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::Cmova => {
            if rex_w {
                sem::cmova_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmova_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovae => {
            if rex_w {
                sem::cmovae_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovae_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovo => {
            if rex_w {
                sem::cmovo_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovo_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovno => {
            if rex_w {
                sem::cmovno_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovno_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovs => {
            if rex_w {
                sem::cmovs_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovs_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovp => {
            if rex_w {
                sem::cmovp_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovp_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovnp => {
            if rex_w {
                sem::cmovnp_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovnp_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovl => {
            if rex_w {
                sem::cmovl_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovl_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovge => {
            if rex_w {
                sem::cmovge_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovge_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovle => {
            if rex_w {
                sem::cmovle_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovle_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Cmovg => {
            if rex_w {
                sem::cmovg_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovg_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::CmoveM64 => {
            if rex_w {
                sem::cmove_r64_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::cmove_r32_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::CmovneM64 => {
            // 0F 45 mod=10 [base+disp32]。grep 0x442f5f 対応.
            if rex_w {
                sem::cmovne_r64_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::cmovne_r32_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::CmovneR64Sibd => {
            // 0F 45 SIB mod=01 [base+disp8] no_index (40b)。
            // SIB は (word>>8) 下位8、disp は最下位8。base は SIB 下位3 + REX.B。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if rex_w {
                sem::cmovne_r64_sibd(b, reg0f_as_gpr(), base, d8)
            } else {
                sem::cmovne_r32_sibd(b, reg0f_as_gpr(), base, d8)
            }
        }
        Insn::CmoveR64Sibd => {
            // 0F 44 SIB mod=01 [base+disp8] no_index (40b)。
            // SIB は (word>>8) 下位8、disp は最下位8。base は SIB 下位3 + REX.B。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if rex_w {
                sem::cmove_r64_sibd(b, reg0f_as_gpr(), base, d8)
            } else {
                sem::cmove_r32_sibd(b, reg0f_as_gpr(), base, d8)
            }
        }
        Insn::CmoveRip => {
            if rex_w {
                sem::cmove_r64_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::cmove_r32_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::cmove_r32_abs(b, reg0f_as_gpr(), imm32())
            }
        }
        Insn::CmovneRip => {
            // CMOVNE r64/r32, m64/m32 [RIP+disp32] (0F 45 05 + disp32)。ln 0x5a9e44 対応.
            if rex_w {
                sem::cmovne_r64_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::cmovne_r32_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::cmovne_r32_abs(b, reg0f_as_gpr(), imm32())
            }
        }
        Insn::CmovaeM64 => {
            if rex_w {
                sem::cmovae_r64_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::cmovae_r32_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::ImulRImm => {
            if rex_w {
                sem::imul_r64_imm(b, reg(), rm(), imm32())
            } else {
                sem::imul_r32_imm(b, reg(), rm(), imm32())
            }
        }
        Insn::ImulRImm8 => {
            if rex_w {
                sem::imul_r64_imm8(b, reg(), rm(), disp8())
            } else {
                sem::imul_r32_imm8(b, reg(), rm(), disp8())
            }
        }
        Insn::ImulRRm => {
            // 0F AF /r reg-direct (dst=reg0f, src=rm0f).
            if rex_w {
                sem::imul_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::imul_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::ImulRMemnd => {
            if rex_w {
                sem::imul_r64_memnd(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::imul_r32_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::ImulRMem8 => {
            if rex_w {
                sem::imul_r64_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::imul_r32_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::ImulRMem32 => {
            if rex_w {
                sem::imul_r64_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::imul_r32_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::ImulRSibd => {
            // 0F AF SIB mod=01 [base+index*scale+disp8] (40b)。hexdump 0x5c8ca2 対応.
            // no_index は base+disp8 のみ。SIB は (word>>8) 下位8、disp は最下位8.
            // base は SIB 下位3 + REX.B。dst は reg0f フィールド.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::imul_r64_sibd(b, reg0f_as_gpr(), base, d8)
                } else {
                    sem::imul_r32_sibd(b, reg0f_as_gpr(), base, d8)
                }
            } else if rex_w {
                sem::imul_r64_sibd_indexed(b, reg0f_as_gpr(), base, idx, shift, d8)
            } else {
                sem::imul_r32_sibd_indexed(b, reg0f_as_gpr(), base, idx, shift, d8)
            }
        }
        Insn::ImulRRip => {
            if rex_w {
                sem::imul_r64_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::imul_r32_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::imul_r32_abs(b, reg0f_as_gpr(), imm32())
            }
        }
        Insn::BsfRRm => {
            if rex_w {
                sem::bsf_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::bsf_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::CmpxchgRRm => {
            // 0F B1 /r reg-direct (dst=rm/mem役, src=reg)。RAX 暗黙.
            if rex_w {
                sem::cmpxchg_r64(b, rm0f(), reg0f_as_gpr())
            } else {
                sem::cmpxchg_r32(b, rm0f(), reg0f_as_gpr())
            }
        }
        Insn::CmpxchgRMemnd => {
            if rex_w {
                sem::cmpxchg_r64_memnd(b, rm0f(), reg0f_as_gpr())
            } else {
                sem::cmpxchg_r32_memnd(b, rm0f(), reg0f_as_gpr())
            }
        }
        Insn::CmpxchgRMem8 => {
            if rex_w {
                sem::cmpxchg_r64_mem8(b, rm0f(), disp8(), reg0f_as_gpr())
            } else {
                sem::cmpxchg_r32_mem8(b, rm0f(), disp8(), reg0f_as_gpr())
            }
        }
        Insn::CmpxchgRMem32 => {
            if rex_w {
                sem::cmpxchg_r64_mem32(b, rm0f(), disp32(), reg0f_as_gpr())
            } else {
                sem::cmpxchg_r32_mem32(b, rm0f(), disp32(), reg0f_as_gpr())
            }
        }
        Insn::CmpxchgRRip => {
            if rex_w {
                sem::cmpxchg_r64_rip(b, eip as u64 + nbytes, disp32(), reg0f_as_gpr())
            } else if is64 {
                sem::cmpxchg_r32_rip(b, eip as u64 + nbytes, disp32(), reg0f_as_gpr())
            } else {
                sem::cmpxchg_r32_memnd(b, rm0f(), reg0f_as_gpr())
            }
        }
        Insn::BsfRMemnd => {
            if rex_w {
                sem::bsf_r64_memnd(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::bsf_r32_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::BsfRMem8 => {
            if rex_w {
                sem::bsf_r64_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::bsf_r32_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::BsfRMem32 => {
            if rex_w {
                sem::bsf_r64_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::bsf_r32_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::BsfRRip => {
            if rex_w {
                sem::bsf_r64_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::bsf_r32_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                // 32ビット絶対番地は未対応 (BSF は RIP 想定のため)。
                sem::bsf_r32_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::BsrRRm => {
            if rex_w {
                sem::bsr_r64(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::bsr_r32(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::BsrRMemnd => {
            if rex_w {
                sem::bsr_r64_memnd(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::bsr_r32_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::BsrRMem8 => {
            if rex_w {
                sem::bsr_r64_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::bsr_r32_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::BsrRMem32 => {
            if rex_w {
                sem::bsr_r64_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::bsr_r32_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::BsrRRip => {
            if rex_w {
                sem::bsr_r64_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::bsr_r32_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::bsr_r32_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::Bswap => {
            // BSWAP r32/r64 (0F C8+rd)。rd は opcode 下位3 + REX.B。REX.W で64bit.
            let rd = Gpr(((word as u8) & 7) | ((rex & 1) << 3));
            if rex_w {
                sem::bswap_r64(b, rd)
            } else {
                sem::bswap_r32(b, rd)
            }
        }
        Insn::ImulRImm8Rip => {
            // 6B /r ib + disp32 + imm8 (56b)。disp は (word>>8) 下位32 LE、imm は最下位8.
            let disp_le = ((word >> 8) as u32).swap_bytes();
            let disp = disp_le as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::imul_r64_imm8_rip(b, reg(), eip as u64 + nbytes, disp, imm)
            } else if is64 {
                sem::imul_r32_imm8_rip(b, reg(), eip as u64 + nbytes, disp, imm)
            } else {
                sem::imul_r32_imm8_abs(b, reg(), disp_le, imm)
            }
        }
        Insn::CmpRmImm8Rip => {
            // 83 3D + disp32 + imm8: word = [83][3D][disp0..3][imm] (56ビット)。
            // disp32 は (word>>8) の下位32を LE 復元する. imm は最下位.
            let disp_le = ((word >> 8) as u32).swap_bytes();
            let disp = disp_le as i32;
            let imm = (word & 0xff) as u8 as i8;
            if has66 {
                // 66 83: 16ビット CMP (64ビット RIP相対のみ).
                sem::cmp_rm16_imm8_rip(b, eip as u64 + nbytes, disp, imm)
            } else if is64 {
                sem::cmp_rm32_imm8_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::cmp_rm32_imm8_abs(b, disp_le, imm)
            }
        }
        Insn::OrRmImm8Rip => {
            // 83 0D + disp32 + imm8 (56ビット)。disp は (word>>8) 下位32 LE、imm は最下位.
            let disp_le = ((word >> 8) as u32).swap_bytes();
            let disp = disp_le as i32;
            let imm = (word & 0xff) as u8 as i8;
            if is64 {
                sem::or_rm32_imm8_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::or_rm32_imm8_abs(b, disp_le, imm)
            }
        }
        Insn::AndRmImm8Rip => {
            // 83 25 + disp32 + imm8 (56ビット)。disp は (word>>8) 下位32 LE、imm は最下位.
            let disp_le = ((word >> 8) as u32).swap_bytes();
            let disp = disp_le as i32;
            let imm = (word & 0xff) as u8 as i8;
            if is64 {
                sem::and_rm32_imm8_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::and_rm32_imm8_abs(b, disp_le, imm)
            }
        }
        Insn::SubRmImm8Rip => {
            // 83 2D + disp32 + imm8 (56ビット)。disp は (word>>8) 下位32 LE、imm は最下位.
            let disp_le = ((word >> 8) as u32).swap_bytes();
            let disp = disp_le as i32;
            let imm = (word & 0xff) as u8 as i8;
            if is64 {
                sem::sub_rm32_imm8_rip(b, eip as u64 + nbytes, disp, imm)
            } else {
                sem::sub_rm32_imm8_abs(b, disp_le, imm)
            }
        }
        Insn::MovzxR32M16Mem32 => {
            if rex_w {
                sem::movzx_r64_m16_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::movzx_r32_m16_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::MovzxR32M16Mem8 => {
            // 0F B7 mod=01 [base+disp8]。disp は最下位8.
            if rex_w {
                sem::movzx_r64_m16_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::movzx_r32_m16_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::MovzxR32M16Memnd => {
            // 0F B7 mod=00 [base]。ls -l 0x4824c4 対応.
            if rex_w {
                sem::movzx_r64_m16_memnd(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::movzx_r32_m16_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::MovzxR32M16Sibd32 => {
            // 0F B7 SIB mod=10。echo 0x4c05ba 対応.
            if sib0f_no_index() {
                if rex_w {
                    sem::movzx_r64_m16_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                } else {
                    sem::movzx_r32_m16_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                }
            } else if rex_w {
                sem::movzx_r64_m16_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            } else {
                sem::movzx_r32_m16_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            }
        }
        Insn::MovzxR32M16Sibd => {
            if sib0f_no_index() {
                if rex_w {
                    sem::movzx_r64_m16_mem8(b, reg0f_as_gpr(), sib0f_base(), disp8())
                } else {
                    sem::movzx_r32_m16_mem8(b, reg0f_as_gpr(), sib0f_base(), disp8())
                }
            } else if rex_w {
                sem::movzx_r64_m16_sibd(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            } else {
                sem::movzx_r32_m16_sibd(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            }
        }
        Insn::MovzxR32M16Rip => {
            // 0F B7 05 + disp32 (mod=00 RIP)。dst は reg フィールド.
            if is64 {
                sem::movzx_r32_m16_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::movzx_r32_m16_abs(b, reg0f_as_gpr(), imm32())
            }
        }
        Insn::MovzxR32R16 => {
            // 0F B7 /r mod=11 reg-direct。dst は reg、src は rm.
            sem::movzx_r32_r16(b, reg0f_as_gpr(), rm0f())
        }
        Insn::MovzxR32M16Sib => {
            // 0F B7 SIB mod=00 [base+index*scale]。no_index は [base].
            if sib0f_no_index() {
                if rex_w {
                    sem::movzx_r64_m16_memnd(b, reg0f_as_gpr(), sib0f_base())
                } else {
                    sem::movzx_r32_m16_memnd(b, reg0f_as_gpr(), sib0f_base())
                }
            } else if rex_w {
                sem::movzx_r64_m16_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            } else {
                sem::movzx_r32_m16_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::MovzxR32M8Rip => {
            // 0F B6 05 + disp32 (mod=00 RIP)。dst は reg フィールド.
            if is64 {
                sem::movzx_r32_m8_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::movzx_r32_m8_abs(b, reg0f_as_gpr(), imm32())
            }
        }
        Insn::MovsxR32M8Rip => {
            // 0F BE 05 + disp32 (mod=00 RIP)。dst は reg フィールド.
            if is64 {
                sem::movsx_r32_m8_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::movsx_r32_m8_abs(b, reg0f_as_gpr(), imm32())
            }
        }
        Insn::MovzxR32M8Memnd => {
            if rex_w {
                sem::movzx_r64_m8_memnd(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::movzx_r32_m8_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::MovsxR32M8Memnd => {
            // 0F BE mod=00 [base]。REX.W で64ビット符号拡張.
            if rex_w {
                sem::movsx_r64_m8_memnd(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::movsx_r32_m8_memnd(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::MovsxR32M8Mem32 => {
            // 0F BE mod=10 [base+disp32]。echo 0x4c00d6 対応.
            if rex_w {
                sem::movsx_r64_m8_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::movsx_r32_m8_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::MovsxR32M8Mem8 => {
            // 0F BE mod=01 [base+disp8]。REX.W で64ビット符号拡張.
            if rex_w {
                sem::movsx_r64_m8_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::movsx_r32_m8_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::MovsxR32M8Sib => {
            if sib0f_no_index() {
                if rex_w {
                    sem::movsx_r64_m8_memnd(b, reg0f_as_gpr(), sib0f_base())
                } else {
                    sem::movsx_r32_m8_memnd(b, reg0f_as_gpr(), sib0f_base())
                }
            } else if rex_w {
                sem::movsx_r64_m8_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            } else {
                sem::movsx_r32_m8_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::MovsxR32M8Sibd => {
            // 0F BE SIB mod=01 [base+index*scale+disp8] (40b)。no_index は [base+disp8].
            // SIB は (word>>8) 下位8、disp は最下位8。REX.W で64ビット符号拡張.
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::movsx_r64_m8_mem8(b, reg0f_as_gpr(), base, d8)
                } else {
                    sem::movsx_r32_m8_mem8(b, reg0f_as_gpr(), base, d8)
                }
            } else if rex_w {
                sem::movsx_r64_m8_sibd(b, reg0f_as_gpr(), base, idx, shift, d8)
            } else {
                sem::movsx_r32_m8_sibd(b, reg0f_as_gpr(), base, idx, shift, d8)
            }
        }
        Insn::MovzxR32M8Mem8 => {
            if rex_w {
                sem::movzx_r64_m8_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::movzx_r32_m8_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::MovzxR32M8Mem32 => {
            if rex_w {
                sem::movzx_r64_m8_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            } else {
                sem::movzx_r32_m8_mem32(b, reg0f_as_gpr(), rm0f(), disp32())
            }
        }
        Insn::MovzxR32M8Sib => {
            if sib0f_no_index() {
                if rex_w {
                    sem::movzx_r64_m8_memnd(b, reg0f_as_gpr(), sib0f_base())
                } else {
                    sem::movzx_r32_m8_memnd(b, reg0f_as_gpr(), sib0f_base())
                }
            } else if rex_w {
                sem::movzx_r64_m8_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            } else {
                sem::movzx_r32_m8_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::MovzxR32M8Sibd => {
            if sib0f_no_index() {
                if rex_w {
                    sem::movzx_r64_m8_mem8(b, reg0f_as_gpr(), sib0f_base(), disp8())
                } else {
                    sem::movzx_r32_m8_mem8(b, reg0f_as_gpr(), sib0f_base(), disp8())
                }
            } else if rex_w {
                sem::movzx_r64_m8_sibd(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            } else {
                sem::movzx_r32_m8_sibd(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            }
        }
        Insn::MovzxR32M8Sibd32 => {
            if sib0f_no_index() {
                if rex_w {
                    sem::movzx_r64_m8_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                } else {
                    sem::movzx_r32_m8_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                }
            } else if rex_w {
                sem::movzx_r64_m8_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            } else {
                sem::movzx_r32_m8_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            }
        }
        Insn::MovzxR32R8 => {
            // 0F B6 /r mod=11 reg-direct。src は rm フィールド (REX.B で拡張)。
            // REX なしの rm 4-7 は上位8ビット (AH/CH/DH/BH)。
            let rm_f = modrm0f() & 7;
            let (src, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            if rex_w {
                sem::movzx_r64_r8(b, reg0f_as_gpr(), src, high)
            } else {
                sem::movzx_r32_r8(b, reg0f_as_gpr(), src, high)
            }
        }
        Insn::MovsxR32R8 => {
            // 0F BE /r mod=11 reg-direct。src は rm フィールド (REX.B で拡張)。
            // REX なしの rm 4-7 は上位8ビット (AH/CH/DH/BH)。
            let rm_f = modrm0f() & 7;
            let (src, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            if rex_w {
                sem::movsx_r64_r8(b, reg0f_as_gpr(), src, high)
            } else {
                sem::movsx_r32_r8(b, reg0f_as_gpr(), src, high)
            }
        }
        // SETcc r/m8 reg-direct (0F 90-9F)。dst は rm フィールド (REX.B で拡張)。
        // REX なしの rm 4-7 は上位8ビット。REX.W は無視 (常に8bit)。
        Insn::Seto => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::seto_r8(b, dst, high)
        }
        Insn::Setno => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setno_r8(b, dst, high)
        }
        Insn::Setb => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setb_r8(b, dst, high)
        }
        Insn::Setae => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setae_r8(b, dst, high)
        }
        Insn::Sete => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::sete_r8(b, dst, high)
        }
        Insn::SeteM8Mem32 => {
            // 0F 94 mod=10 [base+disp32] (56b)。
            sem::sete_m8_mem32(b, rm0f(), disp32())
        }
        Insn::SeteM8Mem8 => {
            // 0F 94 mod=01 [base+disp8] (32b)。grep 0x442245 対応.
            sem::sete_m8_mem8(b, rm0f(), disp8())
        }
        Insn::SetneM8Mem32 => {
            // 0F 95 mod=10 [base+disp32] (56b)。grep 0x43ddc1 対応.
            sem::setne_m8_mem32(b, rm0f(), disp32())
        }
        Insn::SetleM8Mem32 => {
            // 0F 9E mod=10 [base+disp32] (56b)。grep 0x43e091 対応.
            sem::setle_m8_mem32(b, rm0f(), disp32())
        }
        Insn::SetneM8Sibd => {
            // 0F 95 SIB mod=01 [base+index*scale+disp8] (40b)。no_index は base のみ.
            if sib0f_no_index() {
                sem::setne_m8_mem8(b, sib0f_base(), disp8())
            } else {
                sem::setne_m8_sibd(b, sib0f_base(), sib0f_idx(), sib0f_shift(), disp8())
            }
        }
        Insn::SeteM8Sibd => {
            // 0F 94 SIB mod=01 [base+index*scale+disp8] (40b)。df 0x5a797e 対応.
            // no_index は [base+disp8] として mem8 相当を呼ぶ.
            if sib0f_no_index() {
                sem::sete_m8_mem8(b, sib0f_base(), disp8())
            } else {
                sem::sete_m8_sibd(b, sib0f_base(), sib0f_idx(), sib0f_shift(), disp8())
            }
        }
        Insn::Setne => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setne_r8(b, dst, high)
        }
        Insn::Setbe => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setbe_r8(b, dst, high)
        }
        Insn::Seta => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::seta_r8(b, dst, high)
        }
        Insn::Sets => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::sets_r8(b, dst, high)
        }
        Insn::Setns => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setns_r8(b, dst, high)
        }
        Insn::Setp => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setp_r8(b, dst, high)
        }
        Insn::Setnp => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setnp_r8(b, dst, high)
        }
        Insn::Setl => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setl_r8(b, dst, high)
        }
        Insn::Setge => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setge_r8(b, dst, high)
        }
        Insn::Setle => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setle_r8(b, dst, high)
        }
        Insn::Setg => {
            let rm_f = modrm0f() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::setg_r8(b, dst, high)
        }
        Insn::MovupsLoadRip => {
            if has_f2 {
                if is64 {
                    sem::movsd_load_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
                } else {
                    sem::movsd_load_abs(b, xmm_reg(), imm32())
                }
            } else if is64 {
                sem::movups_load_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::movups_load_abs(b, xmm_reg(), imm32())
            }
        }
        Insn::MovupsStoreRip => {
            if has_f2 {
                if is64 {
                    sem::movsd_store_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
                } else {
                    sem::movsd_store_abs(b, xmm_reg(), imm32())
                }
            } else if is64 {
                sem::movups_store_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::movups_store_abs(b, xmm_reg(), imm32())
            }
        }
        Insn::JoRel32 => sem::jo_rel32(b, eip, disp32()),
        Insn::JnoRel32 => sem::jno_rel32(b, eip, disp32()),
        Insn::JbRel32 => sem::jb_rel32(b, eip, disp32()),
        Insn::JaeRel32 => sem::jae_rel32(b, eip, disp32()),
        Insn::JeRel32 => sem::je_rel32(b, eip, disp32()),
        Insn::JneRel32 => sem::jne_rel32(b, eip, disp32()),
        Insn::JbeRel32 => sem::jbe_rel32(b, eip, disp32()),
        Insn::JaRel32 => sem::ja_rel32(b, eip, disp32()),
        Insn::JsRel32 => sem::js_rel32(b, eip, disp32()),
        Insn::JnsRel32 => sem::jns_rel32(b, eip, disp32()),
        Insn::JpRel32 => sem::jp_rel32(b, eip, disp32()),
        Insn::JnpRel32 => sem::jnp_rel32(b, eip, disp32()),
        Insn::JlRel32 => sem::jl_rel32(b, eip, disp32()),
        Insn::JgeRel32 => sem::jge_rel32(b, eip, disp32()),
        Insn::JleRel32 => sem::jle_rel32(b, eip, disp32()),
        Insn::JgRel32 => sem::jg_rel32(b, eip, disp32()),
    };
    if is64 && !rex_w {
        // 64ビットでの32ビット書き込みは上位をゼロ拡張する。
        // REX.W の64ビット書き込みは full64 のため消さない.
        // PUSH/POP は REX.W なしでも64ビットが既定のため消さない（0x5B 等）。
        let dst: Option<Gpr> = match insn {
            Insn::IncEax
            | Insn::DecEax
            | Insn::AddEax
            | Insn::SubEax
            | Insn::AndEax
            | Insn::OrEax
            | Insn::XorImm
            | Insn::Cwde => Some(Gpr(0)),
            Insn::IncEcx | Insn::DecEcx => Some(Gpr(1)),
            Insn::IncEdx | Insn::DecEdx | Insn::Cdq => Some(Gpr(2)),
            Insn::IncEbx | Insn::DecEbx => Some(Gpr(3)),
            Insn::IncEsp | Insn::DecEsp => Some(Gpr(4)),
            Insn::IncEbp | Insn::DecEbp => Some(Gpr(5)),
            Insn::IncEsi | Insn::DecEsi => Some(Gpr(6)),
            Insn::IncEdi | Insn::DecEdi => Some(Gpr(7)),
            Insn::AddRm32
            | Insn::AdcRm32
            | Insn::SbbRm32
            | Insn::SubRm32
            | Insn::AndRm32
            | Insn::OrRm32
            | Insn::XorRm32
            | Insn::MovMr32
            | Insn::MovRmImm
            | Insn::SubRm32Imm
            | Insn::AddRm32Imm
            | Insn::OrRm32Imm
            | Insn::AdcRm32Imm
            | Insn::SbbRm32Imm
            | Insn::AndRm32Imm
            | Insn::XorRm32Imm
            | Insn::CmpRm32Imm
            | Insn::AndRmImm8
            | Insn::AddRmImm8
            | Insn::OrRmImm8
            | Insn::AdcRmImm8
            | Insn::SbbRmImm8
            | Insn::SubRmImm8
            | Insn::XorRmImm8
            | Insn::CmpRmImm8
            | Insn::ShrRm32Imm8
            | Insn::ShrRm321
            | Insn::ShlRm32Imm8
            | Insn::ShlRm321
            | Insn::SarRm321
            | Insn::SarRm32Imm8
            | Insn::RorRm32Imm8
            | Insn::RolRm32Imm8
            | Insn::SarRm32Cl
            | Insn::ShlRm32Cl
            | Insn::ShrRm32Cl
            | Insn::NotRm32
            | Insn::NegRm32
            | Insn::IncRm
            | Insn::DecRm => Some(rm()),
            Insn::MovRm32
            | Insn::Movsxd
            | Insn::MovsxdMemnd
            | Insn::MovsxdMem8
            | Insn::MovsxdMem32
            | Insn::MovsxdRip
            | Insn::MovsxdSib
            | Insn::MovsxdSibd
            | Insn::MovsxdSibd32
            | Insn::ImulRImm
            | Insn::ImulRImm8
            | Insn::ImulRImm8Rip => Some(reg()),
            Insn::Cmovb
            | Insn::Cmovne
            | Insn::Cmove
            | Insn::Cmovns
            | Insn::Cmovbe
            | Insn::Cmova
            | Insn::Cmovae
            | Insn::Cmovo
            | Insn::Cmovno
            | Insn::Cmovs
            | Insn::Cmovp
            | Insn::Cmovnp
            | Insn::Cmovl
            | Insn::Cmovge
            | Insn::Cmovle
            | Insn::Cmovg
            | Insn::MovzxR32M16Mem32
            | Insn::MovzxR32M16Memnd
            | Insn::MovzxR32M16Sib
            | Insn::MovzxR32M16Sibd
            | Insn::MovzxR32M16Sibd32
            | Insn::MovsxR32M8Mem32
            | Insn::MovzxR32M16Rip
            | Insn::MovzxR32M8Rip
            | Insn::MovzxR32M8Memnd
            | Insn::MovzxR32M8Mem8
            | Insn::MovzxR32M8Mem32
            | Insn::MovzxR32M8Sib
            | Insn::MovzxR32M8Sibd
            | Insn::MovzxR32M8Sibd32
            | Insn::MovzxR32R8
            | Insn::ImulRRm
            | Insn::ImulRMemnd
            | Insn::ImulRMem8
            | Insn::ImulRMem32
            | Insn::ImulRSibd
            | Insn::ImulRRip
            | Insn::BsfRRm
            | Insn::BsfRMemnd
            | Insn::BsfRMem8
            | Insn::BsfRMem32
            | Insn::BsfRRip
            | Insn::BsrRRm
            | Insn::BsrRMemnd
            | Insn::BsrRMem8
            | Insn::BsrRMem32
            | Insn::BsrRRip => Some(reg0f_as_gpr()),
            Insn::XaddR32Memnd
            | Insn::XaddR32Rip
            | Insn::ShldR32Cl
            | Insn::ShrdR32Cl
            | Insn::BtsR32Rm
            | Insn::Pmovmskb => Some(reg0f_as_gpr()),
            Insn::AddRRip
            | Insn::AddRMemnd
            | Insn::AddRMem8
            | Insn::AddRMem32
            | Insn::AddRSib
            | Insn::AddRSibabs
            | Insn::SubRMemnd
            | Insn::SubRMem8
            | Insn::SubRMem32
            | Insn::SubRRip
            | Insn::XorRMemnd
            | Insn::XorRMem8
            | Insn::XorRMem32
            | Insn::XorRSib
            | Insn::XorRSibd
            | Insn::XorRSibd32
            | Insn::XorRRip
            | Insn::AndRMemnd
            | Insn::AndRMem8
            | Insn::AndRMem32
            | Insn::AndRRip
            | Insn::AdcRMemnd
            | Insn::AdcRMem8
            | Insn::AdcRMem32
            | Insn::AdcRRip
            | Insn::SbbRMemnd
            | Insn::SbbRMem8
            | Insn::SbbRMem32
            | Insn::SbbRRip
            | Insn::OrRRip
            | Insn::OrRMemnd
            | Insn::OrRMem8
            | Insn::OrRMem32
            | Insn::MovEaxMem8
            | Insn::MovEaxMemnd
            | Insn::MovEaxMem32
            | Insn::MovEaxAbs
            | Insn::MovEaxSib
            | Insn::MovEaxSibd
            | Insn::MovEaxSibd32
            | Insn::MovEaxSibabs
            | Insn::XchgRRm
            | Insn::XchgRMemnd
            | Insn::XchgRMem8
            | Insn::XchgRMem32
            | Insn::XchgRRip => Some(reg()),
            Insn::MovR32Imm => Some(Gpr((((word >> 32) & 7) as u8) | ((rex & 1) << 3))),
            // BSWAP r32 (0F C8+rd)。rd は opcode 下位3 + REX.B。32bit書込みはゼロ拡張.
            Insn::Bswap => Some(Gpr(((word as u8) & 7) | ((rex & 1) << 3))),
            Insn::XchgRcxAx
            | Insn::XchgRdxAx
            | Insn::XchgRbxAx
            | Insn::XchgRspAx
            | Insn::XchgRbpAx
            | Insn::XchgRsiAx
            | Insn::XchgRdiAx => Some(Gpr(((word as u8) & 7) | ((rex & 1) << 3))),
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
            // MOVSXD は REX.W 時に符号拡張の上位を保持するため clear_hi しない。
            // 32ビット時は下位書込みのゼロ拡張として clear_hi する。
            let skip = rex_w
                && matches!(
                    insn,
                    Insn::Movsxd
                        | Insn::MovsxdMemnd
                        | Insn::MovsxdMem8
                        | Insn::MovsxdMem32
                        | Insn::MovsxdRip
                        | Insn::MovsxdSib
                        | Insn::MovsxdSibd
                        | Insn::MovsxdSibd32
                );
            if !skip {
                sem::clear_hi(b, d);
            }
        }
        // 32ビット DIV/MUL/IMUL/IDIV のみゼロ拡張する。64ビット DIV (REX.W) は full64 のため消さない.
        if !rex_w
            && matches!(
                insn,
                Insn::MulRm32
                    | Insn::ImulRm32
                    | Insn::DivRm32
                    | Insn::IdivRm32
                    | Insn::DivRm32Mem8
                    | Insn::DivRm32Sib
                    | Insn::DivRm32Sibd
            )
        {
            sem::clear_hi(b, Gpr(0));
            sem::clear_hi(b, Gpr(2));
        }
        // 32ビット XCHG は dst と RAX の両方をゼロ拡張する。64ビット XCHG (REX.W) は full64.
        if !rex_w
            && matches!(
                insn,
                Insn::XchgRRm
                    | Insn::XchgRMemnd
                    | Insn::XchgRMem8
                    | Insn::XchgRMem32
                    | Insn::XchgRRip
                    | Insn::XchgRcxAx
                    | Insn::XchgRdxAx
                    | Insn::XchgRbxAx
                    | Insn::XchgRspAx
                    | Insn::XchgRbpAx
                    | Insn::XchgRsiAx
                    | Insn::XchgRdiAx
            )
        {
            sem::clear_hi(b, Gpr(0));
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
    // スタックは 8MB 確保する (Linux既定と同等)。sub $0x1000,%rsp等の拡張でPageFaultにならないため.
    const STACK_SIZE: u64 = 8 * 1024 * 1024;
    let base = top - STACK_SIZE;
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
    // x87 制御ワードの初期値（丸め最近接の 0x037F）。FNSTCW/FLDCW で使う.
    env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
    match run(&mut env, ehdr.entry as u32, sys, 1_000_000) {
        Outcome::Exit(code) => Ok(code as u64),
        Outcome::Unimplemented { eip, word } => {
            Err(format!("unimplemented at {eip:#x}: {word:#x}"))
        }
        Outcome::StepLimit { eip } => Err(format!("step limit at {eip:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
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
    sys: &mut CliLinux,
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
    // ヒープの初期ブレークは像末尾（PT_LOAD の最大到達）。brk(0) の問い合わせに答える。
    let mut image_end = 0u64;
    for ph in &phdrs {
        if ph.seg_type != 1 {
            continue;
        }
        image_end = image_end.max(ph.vaddr.saturating_add(ph.memsz));
    }
    sys.init_brk(image_end);
    sys.exe_path = prog.to_string();
    let top = 0x7fff_0000u64;
    let mut arg_bytes = vec![prog.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let (img, sp) = polyisa_os_linux::build_initial_stack(top, &arg_bytes, &[], &[(6, 0x1000)]);
    // スタックは 8MB 確保する (Linux既定と同等)。sub $0x1000,%rsp等の拡張でPageFaultにならないため.
    const STACK_SIZE: u64 = 8 * 1024 * 1024;
    let base = top - STACK_SIZE;
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
    // x87 制御ワードの初期値（丸め最近接の 0x037F）。FNSTCW/FLDCW で使う.
    env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
    match run_mode(&mut env, ehdr.entry as u32, sys, 30_000_000, true) {
        Outcome::Exit(code) => Ok(code as u64),
        Outcome::Unimplemented { eip, word } => {
            Err(format!("unimplemented at {eip:#x}: {word:#x}"))
        }
        Outcome::StepLimit { eip } => Err(format!("step limit at {eip:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
    }
}

/// ELF64 ファイルを実行する。`run_elf_x86` の x86-64 版である。
pub fn run_elf_x86_64(path: &str, argv: &[String]) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = CliLinux::x86_64();
    run_image_x86_64(&bytes, path, argv, &mut sys)
}

/// ELF64 を実行し、終了コードと fd 1 の出力を返す。ホストの stdout には書かない。
pub fn run_elf_x86_64_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = CliLinux::x86_64();
    sys.capture_out = Some(Vec::new());
    let code = run_image_x86_64(&bytes, path, argv, &mut sys)?;
    Ok((code, sys.capture_out.unwrap_or_default()))
}

/// ゲストの NUL 終端文字列を読む。上限を超えるか読めなければ None。
fn guest_c_string(env: &mut BareEnv, addr: u64) -> Option<String> {
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    // 1バイトずつ読む。まとめて読むと写像の境界で失敗するため.
    // 上限は 4096 バイト（NUL がなければ失敗扱い）。
    let mut buf = Vec::new();
    for i in 0..4096u64 {
        let mut b = [0u8; 1];
        env.backend.mem.read(VirtAddr(addr + i), &mut b, acc).ok()?;
        if b[0] == 0 {
            break;
        }
        buf.push(b[0]);
    }
    if buf.len() == 4096 {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// `cli run` の Linux 用 ecall 処理。openat/read/write/close と
/// exit/exit_group をホストに直結して受け、ほかは未対応として報告する。
/// i386（`is64=false`）と x86-64（`is64=true`）で番号表と引数レジスタが変わる。
/// x86-64 の引数は RDI/RSI/RDX（Gpr 7/6/2）、番号は RAX（Gpr 0）にある。
///
/// 試作の合意事項：仮想カーネル・VFS・ゲストルートの適用は後の段階である。
/// ここではホストのファイルに直接触る（裸実行の延長）。パスの隔離はしないので、
/// 信頼できないゲストバイナリには使わないこと。絶対パスはホストのパスとして開き、
/// 相対パスはプロセスの作業ディレクトリから開く。1 回の転送は 64 KiB ずつに区切る。
#[derive(Default)]
pub struct CliLinux {
    reported: Vec<u64>,
    fds: Vec<Option<std::fs::File>>,
    /// 標準 fd (0/1/2) の付け替え先。close 後に open したファイルが入る.
    /// uniq のように stdin をファイルに付け替える applet のため.
    /// 読取り用・書込み用いずれのファイルも入る.
    std_files: [Option<std::fs::File>; 3],
    /// 標準 fd の閉鎖状態。初期 (stdio 接続) は false。close で true になる.
    std_closed: [bool; 3],
    /// ファイル作成マスク。umask で更新する。初期値は 022.
    umask: u32,
    is64: bool,
    /// プログラムブレーク（ヒープ末尾）。0 は未初期化。
    /// `run_image_x86_64` がロード後に像末尾へ進める。
    heap_end: u64,
    /// FS ベース（TLS）。arch_prctl(ARCH_SET_FS) で記録する。
    /// FS 相対アドレッシングは未対応のため、値の保持のみ行う。
    fs_base: u64,
    /// robust futex リスト先頭。set_robust_list で記録する。
    /// 終了時の書き戻しは未対応のため、値の保持のみ行う。
    robust_head: u64,
    /// rseq 領域先頭。rseq で記録する。終了時の書き戻しは未対応.
    rseq_addr: u64,
    /// ゲスト実行ファイルのホストパス。/proc/self/exe の readlinkat に答える.
    exe_path: String,
    /// getdents64 で最後まで読んだ fd。次の呼び出しは 0 (EOF) を返す.
    dir_done: Vec<u32>,
    /// getdents64 の続き。fd と、次に返す名前の添字。
    dir_pos: Vec<(u32, usize)>,
    /// openat で開いたホストパス。ゲスト fd とホストの fd 番号は一致しない。
    fd_paths: Vec<Option<String>>,
    /// 標準 fd に付け替えたファイルのホストパス。
    std_paths: [Option<String>; 3],
    /// Some のとき、fd 1 の出力をここへ溜める。None のときはホストの stdout。
    capture_out: Option<Vec<u8>>,
    /// ゲストプロセス表。fork した子と共有する。
    procs: std::rc::Rc<std::cell::RefCell<polyisa_kernel::ProcessTable>>,
    /// 0 は未登録。最初のシステムコールか命令で 1 から採番する。
    pid: u64,
    /// このスレッドが実行した命令数。選択の正は `queue` のスケジューラ。
    steps: u64,
    /// `wait4` で待っているときの引数。
    wait: Option<WaitSlot>,
    /// 自分以外のスレッド。スケジューラと環境を共有する。
    queue: SharedQueue,
    /// プロセス間で共有するパイプ。
    pipes: SharedPipes,
    /// fd 3 以降のパイプ端。ホストのファイルと同時には持たない。
    pipe_ends: Vec<Option<PipeEnd>>,
    /// 空のパイプを読もうとして待っているパイプ。
    pipe_wait: Option<u64>,
    /// このプロセスの作業ディレクトリ。空はまだホストの作業ディレクトリを写していない。
    cwd: String,
}

/// `wait4` を完了するときに使う引数。
struct WaitSlot {
    which: i64,
    status_ptr: u64,
}

/// 今は走っていないスレッドの実行環境。
struct ParkedTask {
    env: BareEnv,
    linux: CliLinux,
}

/// ステップ数で選ぶスケジューラと、止まっている実行環境。
#[derive(Default)]
struct SchedQueue {
    meta: polyisa_kernel::GuestScheduler,
    parked: Vec<ParkedTask>,
}

#[derive(Clone)]
struct SharedQueue(std::rc::Rc<std::cell::RefCell<SchedQueue>>);

impl Default for SharedQueue {
    fn default() -> Self {
        Self(std::rc::Rc::new(std::cell::RefCell::new(
            SchedQueue::default(),
        )))
    }
}

/// この回数ごとに、ステップ数がより少ない実行可能なスレッドへ切り替える。
const SCHED_SLICE: u64 = 64;

/// パイプの端。バッファは `SharedPipes` が持つ。
#[derive(Clone, Copy)]
struct PipeEnd {
    id: u64,
    read: bool,
}

#[derive(Clone)]
struct SharedPipes(std::rc::Rc<std::cell::RefCell<polyisa_kernel::PipeTable>>);

impl Default for SharedPipes {
    fn default() -> Self {
        Self(std::rc::Rc::new(std::cell::RefCell::new(
            polyisa_kernel::PipeTable::default(),
        )))
    }
}

impl CliLinux {
    /// i386 用ハンドラ。
    pub fn i386() -> Self {
        Self {
            umask: 0o22,
            ..Self::default()
        }
    }

    /// x86-64 用ハンドラ。
    pub fn x86_64() -> Self {
        Self {
            is64: true,
            umask: 0o22,
            ..Self::default()
        }
    }

    /// プログラムブレークの初期値を置く。像末尾をページ境界に切り上げる。
    /// `run_image_x86_64` がセグメント配置の直後に呼ぶ。
    pub fn init_brk(&mut self, image_end: u64) {
        use polyisa_mem::PAGE_SIZE;
        self.heap_end = image_end.next_multiple_of(PAGE_SIZE);
    }

    /// fd に対応する開ファイルの参照。標準 fd の付け替え先も見る.
    fn file_ref(&self, fd: u32) -> Option<&std::fs::File> {
        if fd < 3 {
            self.std_files[fd as usize].as_ref()
        } else {
            self.fds
                .get(fd.wrapping_sub(3) as usize)
                .and_then(|f| f.as_ref())
        }
    }

    /// fd に対応する開ファイルの可変参照。標準 fd の付け替え先も見る.
    fn file_mut(&mut self, fd: u32) -> Option<&mut std::fs::File> {
        if fd < 3 {
            self.std_files[fd as usize].as_mut()
        } else {
            self.fds
                .get_mut(fd.wrapping_sub(3) as usize)
                .and_then(|f| f.as_mut())
        }
    }

    /// 真の標準入出力に繋がっているか（閉じても付け替えてもいない）。
    fn std_attached(&self, fd: u32) -> bool {
        fd < 3 && !self.std_closed[fd as usize] && self.std_files[fd as usize].is_none()
    }

    /// fcntl・dup2 の妥当性。接続中・付け替え中の標準 fd と opened fd が真.
    fn fd_valid(&self, fd: u32) -> bool {
        self.pipe_end(fd).is_some()
            || (fd < 3 && (!self.std_closed[fd as usize] || self.std_files[fd as usize].is_some()))
            || self
                .fds
                .get(fd.wrapping_sub(3) as usize)
                .and_then(|f| f.as_ref())
                .is_some()
    }

    fn pipe_end(&self, fd: u32) -> Option<PipeEnd> {
        if fd < 3 {
            return None;
        }
        self.pipe_ends
            .get(fd.wrapping_sub(3) as usize)
            .copied()
            .flatten()
    }

    fn alloc_pipe_fd(&mut self, end: PipeEnd) -> u32 {
        let hole = self.fds.iter().enumerate().position(|(idx, file)| {
            file.is_none() && self.pipe_ends.get(idx).is_none_or(|slot| slot.is_none())
        });
        if let Some(idx) = hole {
            while self.pipe_ends.len() <= idx {
                self.pipe_ends.push(None);
            }
            self.pipe_ends[idx] = Some(end);
            return (3 + idx) as u32;
        }
        self.fds.push(None);
        self.pipe_ends.push(Some(end));
        (3 + self.fds.len() - 1) as u32
    }

    fn close_pipe(&mut self, fd: u32) {
        let Some(idx) = fd.checked_sub(3).map(|n| n as usize) else {
            return;
        };
        let Some(end) = self.pipe_ends.get_mut(idx).and_then(|slot| slot.take()) else {
            return;
        };
        self.pipes.0.borrow_mut().close(end.id, end.read);
        if !end.read {
            self.wake_pipe(end.id);
        }
    }

    /// そのパイプの読みを待っているスレッドを実行可能に戻す。
    fn wake_pipe(&mut self, id: u64) {
        self.queue.0.borrow_mut().meta.unblock_pipe(id);
        let queue = self.queue.clone();
        for task in &mut queue.0.borrow_mut().parked {
            if task.linux.pipe_wait == Some(id) {
                task.linux.pipe_wait = None;
            }
        }
        if self.pipe_wait == Some(id) {
            self.pipe_wait = None;
        }
    }

    /// 実行できない理由を一度報告する。
    fn note_deadlock(&self) {
        eprintln!("run: deadlock");
        for (id, wait) in self.queue.0.borrow().meta.blocked() {
            match wait {
                polyisa_kernel::ThreadWait::Child { which } => {
                    eprintln!("run: pid {} waits for child {which}", id.0);
                }
                polyisa_kernel::ThreadWait::Pipe { id: pipe } => {
                    eprintln!("run: pid {} waits for pipe {pipe}", id.0);
                }
            }
        }
    }

    /// 止めたスレッドの実行環境を外し、パイプの端を閉じる。
    fn release_parked(&mut self, pid: u64) {
        let queue = self.queue.clone();
        let mut task = {
            let mut borrowed = queue.0.borrow_mut();
            let Some(idx) = borrowed
                .parked
                .iter()
                .position(|task| task.linux.pid == pid)
            else {
                return;
            };
            borrowed.parked.remove(idx)
        };
        let fds: Vec<u32> = task
            .linux
            .pipe_ends
            .iter()
            .enumerate()
            .filter_map(|(idx, end)| end.map(|_| (idx as u32) + 3))
            .collect();
        for fd in fds {
            task.linux.close_pipe(fd);
        }
    }

    /// この子を待っているスレッドを、再び実行できるようにする。
    fn wake_child_waiters(&mut self, child: polyisa_kernel::ProcessId) {
        let queue = self.queue.clone();
        let waiters: Vec<u64> = queue
            .0
            .borrow()
            .parked
            .iter()
            .filter_map(|task| {
                let which = task.linux.wait.as_ref().map(|wait| wait.which)?;
                if self.procs.borrow().waits_for(
                    polyisa_kernel::ProcessId(task.linux.pid),
                    which,
                    child,
                ) {
                    Some(task.linux.pid)
                } else {
                    None
                }
            })
            .collect();
        let mut queue = queue.0.borrow_mut();
        for pid in waiters {
            queue.meta.unblock(polyisa_kernel::ThreadId(pid));
        }
    }

    /// 最下位の空き番号を割り当てる。閉じた標準 fd・空きスロットを再利用する.
    fn alloc_fd(&mut self, f: std::fs::File) -> u32 {
        for (i, slot) in self.std_files.iter_mut().enumerate() {
            if slot.is_none() && self.std_closed[i] {
                *slot = Some(f);
                self.std_closed[i] = false;
                return i as u32;
            }
        }
        if let Some(idx) = self.fds.iter().enumerate().position(|(idx, file)| {
            file.is_none() && self.pipe_ends.get(idx).is_none_or(|slot| slot.is_none())
        }) {
            self.fds[idx] = Some(f);
            return (3 + idx) as u32;
        }
        self.fds.push(Some(f));
        (3 + self.fds.len() - 1) as u32
    }

    /// ゲスト fd に、openat が開いたホストパスを覚える。
    fn remember_path(&mut self, fd: u32, path: String) {
        if fd < 3 {
            self.std_paths[fd as usize] = Some(path);
            return;
        }
        let idx = fd.wrapping_sub(3) as usize;
        while self.fd_paths.len() <= idx {
            self.fd_paths.push(None);
        }
        self.fd_paths[idx] = Some(path);
    }

    /// ゲスト fd に覚えたホストパス。
    fn path_of(&self, fd: u32) -> Option<&str> {
        if fd < 3 {
            self.std_paths[fd as usize].as_deref()
        } else {
            self.fd_paths
                .get(fd.wrapping_sub(3) as usize)
                .and_then(|p| p.as_deref())
        }
    }

    /// ゲスト fd のパスと、getdents64 の読み終わり印を捨てる。
    fn forget_path(&mut self, fd: u32) {
        if fd < 3 {
            self.std_paths[fd as usize] = None;
        } else if let Some(slot) = self.fd_paths.get_mut(fd.wrapping_sub(3) as usize) {
            *slot = None;
        }
        self.dir_done.retain(|d| *d != fd);
        self.dir_pos.retain(|(id, _)| *id != fd);
    }

    /// getdents64 で次に返す名前の添字。記録がなければ先頭。
    fn dir_cursor(&self, fd: u32) -> usize {
        self.dir_pos
            .iter()
            .find(|(id, _)| *id == fd)
            .map(|(_, n)| *n)
            .unwrap_or(0)
    }

    /// getdents64 の続き位置を記録する。
    fn set_dir_cursor(&mut self, fd: u32, next: usize) {
        if let Some(slot) = self.dir_pos.iter_mut().find(|(id, _)| *id == fd) {
            slot.1 = next;
        } else {
            self.dir_pos.push((fd, next));
        }
    }

    /// fd 1 へ書く。capture_out があるときはそこへ溜める。
    fn write_fd1(&mut self, bytes: &[u8]) -> usize {
        if let Some(buf) = self.capture_out.as_mut() {
            buf.extend_from_slice(bytes);
            return bytes.len();
        }
        std::io::Write::write(&mut std::io::stdout(), bytes).unwrap_or(0)
    }

    /// 開ファイルを複製し、覚えてあるパスも返す。
    fn clone_open(&self, fd: u32) -> Option<(std::fs::File, Option<String>)> {
        let file = self.file_ref(fd)?.try_clone().ok()?;
        let path = self.path_of(fd).map(str::to_string);
        Some((file, path))
    }

    /// fd を閉じる。標準 fd の初回 close も成功させる。閉じたら真.
    fn close_fd(&mut self, fd: u32) -> bool {
        if fd < 3 {
            let i = fd as usize;
            if self.std_files[i].is_some() {
                self.std_files[i] = None;
                self.std_closed[i] = true;
                self.forget_path(fd);
                true
            } else if !self.std_closed[i] {
                self.std_closed[i] = true;
                true
            } else {
                false
            }
        } else {
            let idx = fd.wrapping_sub(3) as usize;
            if self.pipe_end(fd).is_some() {
                self.close_pipe(fd);
                if let Some(slot) = self.fds.get_mut(idx) {
                    *slot = None;
                }
                self.forget_path(fd);
                return true;
            }
            match self.fds.get_mut(idx) {
                Some(f) if f.is_some() => {
                    *f = None;
                    self.forget_path(fd);
                    true
                }
                _ => false,
            }
        }
    }

    /// start 以降で count ページ連続の空きを探す。見つからなければ None.
    /// brk 縮小で残った写像や固定写像の上書きを避ける first-fit.
    /// MAP_FIXED でない mmap は空きを選ぶ (Ref: SRC-LINUX (7.3))。
    fn find_free_run(&self, env: &BareEnv, start: u64, count: u64) -> Option<u64> {
        use polyisa_mem::{PAGE_SIZE, PageNo};
        // 走査上限（4GB 分）。通常は先頭で見つかる.
        const SCAN_CAP_PAGES: u64 = 1 << 20;
        let mut base = start.next_multiple_of(PAGE_SIZE);
        let mut scanned = 0u64;
        while scanned < SCAN_CAP_PAGES {
            let mut i = 0u64;
            while i < count {
                let page = (base / PAGE_SIZE).checked_add(i)?;
                if env.backend.mem.is_mapped(PageNo(page)) {
                    break;
                }
                i += 1;
            }
            if i == count {
                return Some(base);
            }
            base = base.checked_add((i + 1) * PAGE_SIZE)?;
            scanned += i + 1;
        }
        None
    }

    /// 未登録ならプロセス表とスケジューラへ載せる。
    fn ensure_self(&mut self) -> polyisa_kernel::ProcessId {
        if self.pid == 0 {
            let id = self.procs.borrow_mut().spawn(None);
            self.pid = id.0;
            self.queue
                .0
                .borrow_mut()
                .meta
                .insert(polyisa_kernel::ThreadId(id.0));
            id
        } else {
            let id = polyisa_kernel::ProcessId(self.pid);
            self.queue
                .0
                .borrow_mut()
                .meta
                .insert(polyisa_kernel::ThreadId(id.0));
            id
        }
    }

    /// 作業ディレクトリが空なら、ホストの現在位置を写す。
    fn ensure_cwd(&mut self) {
        if !self.cwd.is_empty() {
            return;
        }
        self.cwd = std::env::current_dir()
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
            .unwrap_or_else(|| "/".to_string());
    }

    /// ファイル記述子を複製した子の状態。プロセス表は共有し、止めた子は持たない。
    fn duplicate(&self) -> Self {
        let clone_file =
            |f: &Option<std::fs::File>| f.as_ref().and_then(|file| file.try_clone().ok());
        let child = Self {
            reported: self.reported.clone(),
            fds: self.fds.iter().map(clone_file).collect(),
            std_files: std::array::from_fn(|i| clone_file(&self.std_files[i])),
            std_closed: self.std_closed,
            umask: self.umask,
            is64: self.is64,
            heap_end: self.heap_end,
            fs_base: self.fs_base,
            robust_head: self.robust_head,
            rseq_addr: self.rseq_addr,
            exe_path: self.exe_path.clone(),
            dir_done: self.dir_done.clone(),
            dir_pos: self.dir_pos.clone(),
            fd_paths: self.fd_paths.clone(),
            std_paths: self.std_paths.clone(),
            capture_out: self.capture_out.clone(),
            procs: std::rc::Rc::clone(&self.procs),
            pid: self.pid,
            steps: 0,
            wait: None,
            queue: self.queue.clone(),
            pipes: self.pipes.clone(),
            pipe_ends: self.pipe_ends.clone(),
            pipe_wait: None,
            cwd: self.cwd.clone(),
        };
        for end in child.pipe_ends.iter().flatten() {
            child.pipes.0.borrow_mut().dup(end.id, end.read);
        }
        child
    }

    /// 止まっているスレッドの識別子。
    #[cfg(test)]
    fn task_pids(&self) -> Vec<u64> {
        self.queue
            .0
            .borrow()
            .parked
            .iter()
            .map(|task| task.linux.pid)
            .collect()
    }

    /// 1 命令を数え、区切りでより短いスレッドへ切り替える。
    fn step_and_maybe_preempt(&mut self, env: &mut BareEnv) {
        let id = self.ensure_self();
        let steps = {
            let mut queue = self.queue.0.borrow_mut();
            queue.meta.add_step(polyisa_kernel::ThreadId(id.0))
        };
        self.steps = steps;
        if steps.is_multiple_of(SCHED_SLICE) {
            let _ = self.preempt(env);
        }
    }

    /// 自分よりステップ数が少ない実行可能なスレッドと入れ替える。
    fn preempt(&mut self, env: &mut BareEnv) -> bool {
        let next = {
            let queue = self.queue.0.borrow();
            queue.meta.next(polyisa_kernel::ThreadId(self.pid))
        };
        let Some(next) = next else {
            return false;
        };
        self.swap_in(env, next.0)
    }

    fn swap_in(&mut self, env: &mut BareEnv, pid: u64) -> bool {
        let queue = self.queue.clone();
        let mut other = {
            let mut borrowed = queue.0.borrow_mut();
            let Some(idx) = borrowed
                .parked
                .iter()
                .position(|task| task.linux.pid == pid)
            else {
                return false;
            };
            borrowed.parked.remove(idx)
        };
        std::mem::swap(self, &mut other.linux);
        std::mem::swap(env, &mut other.env);
        let exited = queue
            .0
            .borrow()
            .meta
            .is_exited(polyisa_kernel::ThreadId(other.linux.pid));
        if !exited {
            queue.0.borrow_mut().parked.push(other);
        }
        true
    }

    /// 子の終了を記録し、親か残りの実行可能なスレッドへ戻る。
    /// 戻る相手がいるときだけ真。初期プロセスの終了は偽で、呼び出し側へ渡す。
    fn yield_on_exit(&mut self, env: &mut BareEnv, code: u32) -> bool {
        let me = self.ensure_self();
        self.procs.borrow_mut().exit(me, code);
        let root = self.procs.borrow().is_root(me);
        self.queue
            .0
            .borrow_mut()
            .meta
            .mark_exited(polyisa_kernel::ThreadId(me.0));
        if root {
            return false;
        }
        let target = {
            let queue = self.queue.0.borrow();
            let waiter = queue.parked.iter().find_map(|task| {
                let which = task.linux.wait.as_ref().map(|wait| wait.which)?;
                if self.procs.borrow().waits_for(
                    polyisa_kernel::ProcessId(task.linux.pid),
                    which,
                    me,
                ) {
                    Some(task.linux.pid)
                } else {
                    None
                }
            });
            waiter.or_else(|| queue.meta.least_runnable().map(|id| id.0))
        };
        let Some(pid) = target else {
            return false;
        };
        if !self.swap_in(env, pid) {
            return false;
        }
        if self.wait.is_some() {
            self.complete_wait(env);
        }
        true
    }

    /// 待っていた `wait4` を、記録済みの終了コードで完了する。
    fn complete_wait(&mut self, env: &mut BareEnv) {
        let Some(wait) = self.wait.take() else {
            return;
        };
        self.queue
            .0
            .borrow_mut()
            .meta
            .unblock(polyisa_kernel::ThreadId(self.pid));
        match self
            .procs
            .borrow_mut()
            .try_reap(polyisa_kernel::ProcessId(self.pid), wait.which)
        {
            polyisa_kernel::Reap::Exited { pid, code, signal } => {
                if wait.status_ptr != 0 {
                    let st = reap_status(code, signal);
                    if env
                        .backend
                        .mem
                        .write(VirtAddr(wait.status_ptr), &st.to_le_bytes())
                        .is_err()
                    {
                        self.set_errno(env, EFAULT);
                        self.advance_past_syscall(env);
                        return;
                    }
                }
                set64(env, Gpr(0), pid.0);
                self.advance_past_syscall(env);
            }
            polyisa_kernel::Reap::NoChild => {
                self.set_errno(env, ECHILD);
                self.advance_past_syscall(env);
            }
            polyisa_kernel::Reap::Pending => {
                let which = wait.which;
                self.wait = Some(wait);
                self.queue.0.borrow_mut().meta.block(
                    polyisa_kernel::ThreadId(self.pid),
                    polyisa_kernel::ThreadWait::Child { which },
                );
            }
        }
    }

    fn set_errno(&self, env: &mut BareEnv, errno: u32) {
        let value = if self.is64 {
            neg_errno64(errno)
        } else {
            u64::from(neg_errno(errno))
        };
        set64(env, Gpr(0), value);
    }

    /// SYSCALL と INT 0x80 は 2 バイト。完了した呼び出しの次へ進める。
    fn advance_past_syscall(&self, env: &mut BareEnv) {
        let eip = eip_of(env);
        env.backend
            .set(polyisa_guest_x86::sem::eip_ref(), eip.wrapping_add(2));
    }
}

/// 旧名。`CliLinux` を使うこと。
pub type CliX86 = CliLinux;

/// i386 の openat の引数。dirfd が -100 (AT_FDCWD) のときだけ受け付ける。
const AT_FDCWD_U32: u32 = 0xffff_ff9c;

/// 1 回の read/write でホストに確保する上限（バイト）。ゲスト指定の
/// 長さが大きくても、この刻みで分割して転送する。
const IO_CHUNK: usize = 65536;

/// Linux 汎用の errno 番号の一部。負数で返す。
/// Ref: SRC-LINUX (7.3).
const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const ESRCH: u32 = 3;
const ENOEXEC: u32 = 8;
const EBADF: u32 = 9;
const ECHILD: u32 = 10;
const EFAULT: u32 = 14;
const EACCES: u32 = 13;
const ENOMEM: u32 = 12;
const ENOTDIR: u32 = 20;
const EINVAL: u32 = 22;
const EPIPE: u32 = 32;
const ERANGE: u32 = 34;
const ENOTTY: u32 = 25;

fn reap_status(code: u32, signal: Option<u32>) -> u32 {
    match signal {
        Some(sig) => sig & 0x7f,
        None => polyisa_os_linux::exited_wait_status(code),
    }
}

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
    (n as i32).wrapping_neg() as i64 as u64
}

fn get64(env: &mut BareEnv, r: polyisa_guest_x86::sem::Gpr) -> u64 {
    polyisa_guest_x86::sem::read64(&mut env.backend, r)
}

fn set64(env: &mut BareEnv, r: polyisa_guest_x86::sem::Gpr, v: u64) {
    polyisa_guest_x86::sem::write64(&mut env.backend, r, v);
}

/// ホスト metadata から x86-64 struct stat (144B) を合成する。
/// 種別 (st_mode) と大きさ (st_size) のみ実値を入れ、残りは 0 とする.
/// レイアウトは musl/glibc 共通のカーネル ABI 由来である.
/// Ref: SRC-LINUX (7.3).
fn stat144(m: &std::fs::Metadata) -> [u8; 144] {
    let mut st = [0u8; 144];
    // S_IFDIR/S_IFREG/S_IFLNK。fifo 等の判別は可搬 API にないため、
    // ディレクトリでもシンボリックリンクでもなければ通常ファイルとみなす.
    // 許可ビットは所有者の読み書き実行を仮定する（試作）。
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;
    const S_IFLNK: u32 = 0o120000;
    let ft = m.file_type();
    let kind = if ft.is_dir() {
        S_IFDIR
    } else if ft.is_symlink() {
        S_IFLNK
    } else {
        S_IFREG
    };
    st[24..28].copy_from_slice(&(kind | 0o700).to_le_bytes());
    st[48..56].copy_from_slice(&(m.len() as i64).to_le_bytes());
    // 残り (st_dev/st_ino/st_nlink/st_uid/st_gid/st_rdev/時刻等) は 0 のまま.
    st
}

/// 1 回のシステムコールで共通に使う値。
struct SysCtx {
    r_a: Gpr,
    r_b: Gpr,
    r_c: Gpr,
    is64: bool,
    at_fdcwd: u64,
}

impl SysCtx {
    /// dirfd が AT_FDCWD か。x86-64 は下位 32 ビット、i386 は値そのものを比べる。
    fn is_at_fdcwd(&self, dirfd: u64) -> bool {
        if self.is64 {
            (dirfd as u32) == AT_FDCWD_U32
        } else {
            dirfd == self.at_fdcwd
        }
    }

    /// 戻り値の負 errno。x86-64 は 64 ビット符号拡張、i386 は 32 ビット。
    fn neg(&self, n: u32) -> u64 {
        if self.is64 {
            neg_errno64(n)
        } else {
            u64::from(neg_errno(n))
        }
    }
}

type SysFn = fn(&mut CliLinux, &mut BareEnv, &SysCtx) -> Option<TrapOutcome>;

const X86_64_SYSCALLS: &[(&str, SysFn)] = &[
    ("openat", sys_openat),
    ("open", sys_open),
    ("read", sys_read),
    ("close", sys_close),
    ("write", sys_write),
    ("writev", sys_writev),
    ("readv", sys_readv),
    ("exit", sys_exit),
    ("exit_group", sys_exit_group),
    ("clone", sys_clone),
    ("execve", sys_execve),
    ("wait4", sys_wait4),
    ("pipe2", sys_pipe2),
    ("setpgid", sys_setpgid),
    ("getpgid", sys_getpgid),
    ("chdir", sys_chdir),
    ("kill", sys_kill),
    ("mmap", sys_mmap),
    ("set_tid_address", sys_set_tid_address),
    ("gettid", sys_gettid),
    ("getpid", sys_getpid),
    ("uname", sys_uname),
    ("getuid", sys_getuid),
    ("geteuid", sys_geteuid),
    ("getgid", sys_getgid),
    ("getegid", sys_getegid),
    ("getcwd", sys_getcwd),
    ("getdents64", sys_getdents64),
    ("fstat", sys_fstat),
    ("stat", sys_stat),
    ("lstat", sys_lstat),
    ("newfstatat", sys_newfstatat),
    ("sendfile", sys_sendfile),
    ("lseek", sys_lseek),
    ("ftruncate", sys_ftruncate),
    ("getgroups", sys_getgroups),
    ("mprotect", sys_mprotect),
    ("munmap", sys_munmap),
    ("rt_sigaction", sys_rt_sigaction),
    ("rt_sigprocmask", sys_rt_sigprocmask),
    ("tgkill", sys_tgkill),
    ("set_robust_list", sys_set_robust_list),
    ("rseq", sys_rseq),
    ("getrandom", sys_getrandom),
    ("prlimit64", sys_prlimit64),
    ("time", sys_time),
    ("ioctl", sys_ioctl),
    ("clock_nanosleep", sys_clock_nanosleep),
    ("clock_gettime", sys_clock_gettime),
    ("readlinkat", sys_readlinkat),
    ("readlink", sys_readlink),
    ("arch_prctl", sys_arch_prctl),
    ("dup", sys_dup),
    ("dup2", sys_dup2),
    ("dup3", sys_dup3),
    ("mkdir", sys_mkdir),
    ("mkdirat", sys_mkdirat),
    ("rename", sys_rename),
    ("symlink", sys_symlink),
    ("rmdir", sys_rmdir),
    ("unlink", sys_unlink),
    ("unlinkat", sys_unlinkat),
    ("access", sys_access),
    ("faccessat", sys_faccessat),
    ("utimensat", sys_utimensat),
    ("chmod", sys_chmod),
    ("fchmod", sys_fchmod),
    ("fchmodat", sys_fchmodat),
    ("umask", sys_umask),
    ("fcntl", sys_fcntl),
    ("brk", sys_brk),
];

const I386_SYSCALLS: &[(&str, SysFn)] = &[
    ("openat", sys_openat),
    ("read", sys_read),
    ("close", sys_close),
    ("write", sys_write),
    ("writev", sys_writev),
    ("readv", sys_readv),
    ("exit", sys_exit),
    ("exit_group", sys_exit_group),
    ("gettid", sys_gettid),
    ("getpid", sys_getpid),
    ("uname", sys_uname),
    ("getuid", sys_getuid),
    ("geteuid", sys_geteuid),
    ("getgid", sys_getgid),
    ("getegid", sys_getegid),
    ("getcwd", sys_getcwd),
    ("ftruncate", sys_ftruncate),
    ("mprotect", sys_mprotect),
    ("munmap", sys_munmap),
    ("rt_sigaction", sys_rt_sigaction),
    ("rt_sigprocmask", sys_rt_sigprocmask),
    ("tgkill", sys_tgkill),
    ("readlinkat", sys_readlinkat),
    ("readlink", sys_readlink),
    ("dup", sys_dup),
    ("dup2", sys_dup2),
    ("dup3", sys_dup3),
    ("mkdir", sys_mkdir),
    ("mkdirat", sys_mkdirat),
    ("rename", sys_rename),
    ("symlink", sys_symlink),
    ("rmdir", sys_rmdir),
    ("unlink", sys_unlink),
    ("unlinkat", sys_unlinkat),
    ("access", sys_access),
    ("faccessat", sys_faccessat),
    ("utimensat", sys_utimensat),
    ("chmod", sys_chmod),
    ("fchmod", sys_fchmod),
    ("fchmodat", sys_fchmodat),
    ("umask", sys_umask),
    ("fcntl", sys_fcntl),
    ("brk", sys_brk),
];

fn sys_open(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // open は dirfd を持たない。パスは AT_FDCWD からの相対パスとして開く。
    let path_addr = get64(env, cx.r_a);
    let flags = get64(env, cx.r_b) as u32;
    open_at_cwd(sys, env, cx, path_addr, flags)
}

fn sys_openat(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // Gap: GAP-0002
    let dirfd = get64(env, cx.r_a);
    let path_addr = get64(env, cx.r_b);
    let flags = get64(env, cx.r_c) as u32;
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    open_at_cwd(sys, env, cx, path_addr, flags)
}

fn open_at_cwd(
    sys: &mut CliLinux,
    env: &mut BareEnv,
    cx: &SysCtx,
    path_addr: u64,
    flags: u32,
) -> Option<TrapOutcome> {
    // 書込み・生成・切詰めを受け付ける。O_NONBLOCK/O_CLOEXEC/O_DIRECTORY/O_NOFOLLOW 等は無視する。
    // truncate/cp/split が O_WRONLY|O_CREAT 等で開く。Ref: SRC-LINUX (7.3).
    const O_ACCMODE: u32 = 3;
    const O_CREAT: u32 = 0o100;
    const O_EXCL: u32 = 0o200;
    const O_TRUNC: u32 = 0o1000;
    const O_APPEND: u32 = 0o2000;
    let acc = flags & O_ACCMODE;
    if acc > 2 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    sys.ensure_cwd();
    let path = join_guest_path(&sys.cwd, &path);
    let want_write = acc != 0 || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0;
    let opened = if want_write {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(acc != 1);
        opts.write(true);
        if flags & O_CREAT != 0 {
            if flags & O_EXCL != 0 {
                opts.create_new(true);
            } else {
                opts.create(true);
            }
        }
        opts.truncate(flags & O_TRUNC != 0);
        opts.append(flags & O_APPEND != 0);
        opts.open(&path)
    } else {
        std::fs::File::open(&path)
    };
    Some(match opened {
        Ok(f) => {
            let fd = sys.alloc_fd(f);
            sys.remember_path(fd, path);
            set64(env, Gpr(0), fd as u64);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                std::io::ErrorKind::AlreadyExists => 17,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn pipe_read(
    sys: &mut CliLinux,
    env: &mut BareEnv,
    cx: &SysCtx,
    end: PipeEnd,
    buf: u64,
    left: u64,
) -> Option<TrapOutcome> {
    if !end.read {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if left == 0 {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    let max = usize::try_from(left.min(4096)).unwrap_or(0);
    let got = sys.pipes.0.borrow_mut().read(end.id, max);
    match got {
        polyisa_kernel::PipeRead::Bytes(bytes) => {
            if env.backend.mem.write(VirtAddr(buf), &bytes).is_err() {
                return Some(TrapOutcome::Unimplemented);
            }
            set64(env, Gpr(0), bytes.len() as u64);
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::PipeRead::Eof => {
            set64(env, Gpr(0), 0);
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::PipeRead::Empty => {
            let id = sys.ensure_self();
            sys.pipe_wait = Some(end.id);
            sys.queue.0.borrow_mut().meta.block(
                polyisa_kernel::ThreadId(id.0),
                polyisa_kernel::ThreadWait::Pipe { id: end.id },
            );
            Some(TrapOutcome::Blocked)
        }
    }
}

fn pipe_write(
    sys: &mut CliLinux,
    env: &mut BareEnv,
    cx: &SysCtx,
    end: PipeEnd,
    buf: u64,
    left: u64,
) -> Option<TrapOutcome> {
    if end.read {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if left == 0 {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    let take = usize::try_from(left.min(4096)).unwrap_or(0);
    let mut chunk = vec![0u8; take];
    if env
        .backend
        .mem
        .read(VirtAddr(buf), &mut chunk, data_access())
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    let wrote = sys.pipes.0.borrow_mut().write(end.id, &chunk);
    match wrote {
        None => {
            set64(env, Gpr(0), cx.neg(EPIPE));
            Some(TrapOutcome::Handled)
        }
        Some(n) => {
            sys.wake_pipe(end.id);
            set64(env, Gpr(0), n as u64);
            Some(TrapOutcome::Handled)
        }
    }
}

fn sys_pipe2(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let addr = get64(env, cx.r_a);
    let flags = get64(env, cx.r_b);
    if flags != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let id = sys.pipes.0.borrow_mut().open();
    let read_fd = sys.alloc_pipe_fd(PipeEnd { id, read: true });
    let write_fd = sys.alloc_pipe_fd(PipeEnd { id, read: false });
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&read_fd.to_le_bytes());
    bytes[4..].copy_from_slice(&write_fd.to_le_bytes());
    if env.backend.mem.write(VirtAddr(addr), &bytes).is_err() {
        sys.close_fd(read_fd);
        sys.close_fd(write_fd);
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_read(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let buf = get64(env, cx.r_b);
    let mut left = get64(env, cx.r_c);
    if let Some(end) = sys.pipe_end(fd) {
        return pipe_read(sys, env, cx, end, buf, left);
    }
    // 付け替えた標準 fd はファイルから読む。真の stdin は空読みのまま.
    let stdin_empty = fd == 0 && sys.std_attached(0);
    let Some(file) = sys.file_mut(fd) else {
        if stdin_empty {
            set64(env, Gpr(0), 0);
            return Some(TrapOutcome::Handled);
        }
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    while left > 0 {
        let take = left.min(IO_CHUNK as u64) as usize;
        let n = match std::io::Read::read(file, &mut chunk[..take]) {
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
            return Some(TrapOutcome::Unimplemented);
        }
        done += n as u64;
        left -= n as u64;
        if n < take {
            break;
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_close(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // 標準 fd の close も成功させる。uniq は stdin を閉じて開き直す.
    let fd = get64(env, cx.r_a) as u32;
    Some(if sys.close_fd(fd) {
        set64(env, Gpr(0), 0);
        TrapOutcome::Handled
    } else {
        set64(env, Gpr(0), cx.neg(EBADF));
        TrapOutcome::Handled
    })
}

fn sys_write(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let buf = get64(env, cx.r_b);
    let mut left = get64(env, cx.r_c);
    if let Some(end) = sys.pipe_end(fd) {
        return pipe_write(sys, env, cx, end, buf, left);
    }
    if (fd == 1 || fd == 2) && sys.std_files[fd as usize].is_none() {
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
                return Some(TrapOutcome::Unimplemented);
            }
            let n = match fd {
                1 => sys.write_fd1(&chunk[..take]),
                _ => std::io::Write::write(&mut std::io::stderr(), &chunk[..take]).unwrap_or(0),
            };
            done += n as u64;
            left -= n as u64;
            if n < take {
                break;
            }
        }
        set64(env, Gpr(0), done);
        return Some(TrapOutcome::Handled);
    }
    // 開ファイル (opened fd・付け替え先。dup2 で stdout に置いた出力先を含む)
    // への write はホストに書く。読取り専用で開いた場合は EBADF になる。
    let Some(file) = sys.file_mut(fd) else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    let mut err_no: Option<u32> = None;
    while left > 0 {
        let take = left.min(IO_CHUNK as u64) as usize;
        if env
            .backend
            .mem
            .read(VirtAddr(buf + done), &mut chunk[..take], data_access())
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
        match std::io::Write::write(file, &chunk[..take]) {
            Ok(0) => break,
            Ok(n) => {
                done += n as u64;
                left -= n as u64;
                if n < take {
                    break;
                }
            }
            Err(e) => {
                err_no = Some(match e.raw_os_error() {
                    Some(9) => EBADF,
                    Some(13) => EACCES,
                    _ => EINVAL,
                });
                break;
            }
        }
    }
    if done == 0 {
        if let Some(no) = err_no {
            set64(env, Gpr(0), cx.neg(no));
        } else {
            set64(env, Gpr(0), 0);
        }
    } else {
        set64(env, Gpr(0), done);
    }
    Some(TrapOutcome::Handled)
}

fn sys_writev(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // writev/readv (x86-64: 20/19, i386: 146/145)。iovec 配列を辿って転送する.
    // fd 1/2 (writev) と opened fd/stdin (readv) のみ受け付ける.
    let fd = get64(env, cx.r_a) as u32;
    let iov = get64(env, cx.r_b);
    let iovcnt = get64(env, cx.r_c);
    // 付け替えた標準 fd は読取り専用のため EBADF。
    if fd < 3 && sys.std_files[fd as usize].is_some() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if fd != 1 && fd != 2 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    const IOV_MAX: u64 = 1024;
    if iovcnt > IOV_MAX {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    for idx in 0..iovcnt {
        let (base, len) = if cx.is64 {
            let mut ent = [0u8; 16];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 16), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from_le_bytes(ent[..8].try_into().unwrap()),
                u64::from_le_bytes(ent[8..].try_into().unwrap()),
            )
        } else {
            let mut ent = [0u8; 8];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 8), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from(u32::from_le_bytes(ent[..4].try_into().unwrap())),
                u64::from(u32::from_le_bytes(ent[4..].try_into().unwrap())),
            )
        };
        let mut left = len;
        let mut off = 0u64;
        while left > 0 {
            let take = left.min(IO_CHUNK as u64) as usize;
            if env
                .backend
                .mem
                .read(VirtAddr(base + off), &mut chunk[..take], data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            let n = match fd {
                1 => sys.write_fd1(&chunk[..take]),
                _ => std::io::Write::write(&mut std::io::stderr(), &chunk[..take]).unwrap_or(0),
            };
            done += n as u64;
            left -= n as u64;
            off += n as u64;
            if n < take {
                break;
            }
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_readv(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let fd = get64(env, cx.r_a) as u32;
    let iov = get64(env, cx.r_b);
    let iovcnt = get64(env, cx.r_c);
    const IOV_MAX: u64 = 1024;
    if iovcnt > IOV_MAX {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 付け替えた標準 fd はファイルから読む。真の stdin は空読みのまま.
    let empty_stdin = fd == 0 && sys.std_attached(0);
    if !empty_stdin && sys.file_ref(fd).is_none() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    for idx in 0..iovcnt {
        let (base, len) = if cx.is64 {
            let mut ent = [0u8; 16];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 16), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from_le_bytes(ent[..8].try_into().unwrap()),
                u64::from_le_bytes(ent[8..].try_into().unwrap()),
            )
        } else {
            let mut ent = [0u8; 8];
            if env
                .backend
                .mem
                .read(VirtAddr(iov + idx * 8), &mut ent, data_access())
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            (
                u64::from(u32::from_le_bytes(ent[..4].try_into().unwrap())),
                u64::from(u32::from_le_bytes(ent[4..].try_into().unwrap())),
            )
        };
        let mut left = len;
        let mut off = 0u64;
        while left > 0 {
            let take = left.min(IO_CHUNK as u64) as usize;
            let n = if empty_stdin {
                0
            } else {
                let f = sys.file_mut(fd).unwrap();
                match std::io::Read::read(f, &mut chunk[..take]) {
                    Ok(0) => 0,
                    Ok(n) => n,
                    Err(_) => 0,
                }
            };
            if n == 0 {
                break;
            }
            if env
                .backend
                .mem
                .write(VirtAddr(base + off), &chunk[..n])
                .is_err()
            {
                return Some(TrapOutcome::Unimplemented);
            }
            done += n as u64;
            left -= n as u64;
            off += n as u64;
            if n < take {
                break;
            }
        }
        // 真の stdin は空読みとして次へ進む.
        if empty_stdin {
            continue;
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_exit(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let code = get64(env, cx.r_a) as u32;
    if sys.pid != 0 {
        sys.procs
            .borrow_mut()
            .exit(polyisa_kernel::ProcessId(sys.pid), code);
    }
    Some(TrapOutcome::Exit(code))
}

fn sys_exit_group(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_exit(sys, env, cx)
}

fn sys_mmap(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mmap(addr, len, prot, flags, fd, offset)。匿名のみ受け付ける.
    // ファイル-backed は未対応のため EINVAL.
    // prot は寛容に RW で写像する (PROT_NONE 予約後の mprotect 前でも動くため).
    use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
    let addr = get64(env, Gpr(7));
    let len = get64(env, Gpr(6));
    let _prot = get64(env, Gpr(2));
    let flags = get64(env, Gpr(10));
    let fd = get64(env, Gpr(8)) as i64;
    let offset = get64(env, Gpr(9));
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_FIXED: u64 = 0x10;
    if len == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if offset & (PAGE_SIZE - 1) != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if flags & MAP_ANONYMOUS == 0 && fd != -1 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 拡張しすぎは失敗扱い.
    const MAX_MMAP: u64 = 1024 * 1024 * 1024;
    if len > MAX_MMAP {
        set64(env, Gpr(0), cx.neg(ENOMEM));
        return Some(TrapOutcome::Handled);
    }
    let aligned_len = len.next_multiple_of(PAGE_SIZE);
    let count = aligned_len / PAGE_SIZE;
    if flags & MAP_FIXED != 0 {
        if addr & (PAGE_SIZE - 1) != 0 {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
        // MAP_FIXED は既存写像を置換する。先に外してから写像する.
        env.backend.mem.unmap(VirtAddr(addr), count);
        if env
            .backend
            .mem
            .map(VirtAddr(addr), count, Perms::RW)
            .is_err()
        {
            set64(env, Gpr(0), cx.neg(ENOMEM));
            return Some(TrapOutcome::Handled);
        }
        // heap_end より後ろに伸ばしたら追随する (brk との衝突回避).
        if sys.heap_end == 0 {
            sys.heap_end = (addr + aligned_len).next_multiple_of(PAGE_SIZE);
        } else {
            sys.heap_end = sys
                .heap_end
                .max((addr + aligned_len).next_multiple_of(PAGE_SIZE));
        }
        set64(env, Gpr(0), addr);
        return Some(TrapOutcome::Handled);
    }
    if addr == 0 {
        if sys.heap_end == 0 {
            sys.heap_end = 0x6000_0000;
        }
        // 縮小で残った写像を上書きしないよう空きを探す.
        let Some(base) = sys.find_free_run(env, sys.heap_end, count) else {
            set64(env, Gpr(0), cx.neg(ENOMEM));
            return Some(TrapOutcome::Handled);
        };
        if env
            .backend
            .mem
            .map(VirtAddr(base), count, Perms::RW)
            .is_err()
        {
            set64(env, Gpr(0), cx.neg(ENOMEM));
            return Some(TrapOutcome::Handled);
        }
        sys.heap_end = base + aligned_len;
        set64(env, Gpr(0), base);
        return Some(TrapOutcome::Handled);
    }
    // ヒント付き: 範囲全体が空きのときだけ要求番地に写像し、
    // 占有があれば heap_end から first-fit で取る (上書きしない).
    let hint = addr & !(PAGE_SIZE - 1);
    let hint_free = {
        use polyisa_mem::PageNo;
        let mut i = 0u64;
        while i < count {
            let page = (hint / PAGE_SIZE).checked_add(i);
            match page {
                Some(no) if !env.backend.mem.is_mapped(PageNo(no)) => i += 1,
                _ => break,
            }
        }
        i == count
    };
    if hint_free
        && env
            .backend
            .mem
            .map(VirtAddr(hint), count, Perms::RW)
            .is_ok()
    {
        if sys.heap_end == 0 {
            sys.heap_end = (hint + aligned_len).next_multiple_of(PAGE_SIZE);
        } else {
            sys.heap_end = sys
                .heap_end
                .max((hint + aligned_len).next_multiple_of(PAGE_SIZE));
        }
        set64(env, Gpr(0), hint);
        return Some(TrapOutcome::Handled);
    }
    if sys.heap_end == 0 {
        sys.heap_end = 0x6000_0000;
    }
    let Some(base) = sys.find_free_run(env, sys.heap_end, count) else {
        set64(env, Gpr(0), cx.neg(ENOMEM));
        return Some(TrapOutcome::Handled);
    };
    if env
        .backend
        .mem
        .map(VirtAddr(base), count, Perms::RW)
        .is_err()
    {
        set64(env, Gpr(0), cx.neg(ENOMEM));
        return Some(TrapOutcome::Handled);
    }
    sys.heap_end = base + aligned_len;
    set64(env, Gpr(0), base);
    Some(TrapOutcome::Handled)
}

/// ゲストのプロセス識別子。未登録ならプロセス表へ載せる。
fn guest_pid(sys: &mut CliLinux) -> u64 {
    sys.ensure_self().0
}

fn sys_set_tid_address(sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // 本物は clear_child_tid を記録し終了時に書き込む。試作は識別子の返却だけを行う。
    // 単一スレッドなので tid は pid と同じ値である。
    set64(env, Gpr(0), guest_pid(sys));
    Some(TrapOutcome::Handled)
}

fn sys_gettid(sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // 単一スレッドなので tid は pid と同じ値である。
    set64(env, Gpr(0), guest_pid(sys));
    Some(TrapOutcome::Handled)
}

fn sys_getpid(sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), guest_pid(sys));
    Some(TrapOutcome::Handled)
}

fn sys_setpgid(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let pid = get64(env, cx.r_a) as i64;
    let pgid = get64(env, cx.r_b) as i64;
    if pid < 0 || pgid < 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let me = sys.ensure_self();
    let target = polyisa_kernel::ProcessId(if pid == 0 { me.0 } else { pid as u64 });
    let group = if pgid == 0 { target.0 } else { pgid as u64 };
    if sys.procs.borrow().pgid(target).is_none() {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    if !sys.procs.borrow().owns(me, target) {
        set64(env, Gpr(0), cx.neg(EPERM));
        return Some(TrapOutcome::Handled);
    }
    sys.procs.borrow_mut().set_pgid(target, group);
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_getpgid(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let pid = get64(env, cx.r_a) as i64;
    if pid < 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let me = sys.ensure_self();
    let target = polyisa_kernel::ProcessId(if pid == 0 { me.0 } else { pid as u64 });
    match sys.procs.borrow().pgid(target) {
        Some(pgid) => set64(env, Gpr(0), pgid),
        None => set64(env, Gpr(0), cx.neg(ESRCH)),
    }
    Some(TrapOutcome::Handled)
}

fn sys_kill(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    const SIGKILL: i64 = 9;
    let pid = get64(env, cx.r_a) as i64;
    let sig = get64(env, cx.r_b) as i64;
    if sig != SIGKILL {
        return Some(TrapOutcome::Unimplemented);
    }
    if pid <= 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let me = sys.ensure_self();
    let target = polyisa_kernel::ProcessId(pid as u64);
    if sys.procs.borrow().pgid(target).is_none() {
        set64(env, Gpr(0), cx.neg(ESRCH));
        return Some(TrapOutcome::Handled);
    }
    sys.procs.borrow_mut().kill(target, SIGKILL as u32);
    sys.queue
        .0
        .borrow_mut()
        .meta
        .mark_exited(polyisa_kernel::ThreadId(target.0));
    if target != me {
        sys.release_parked(target.0);
    }
    sys.wake_child_waiters(target);
    if target == me {
        return Some(TrapOutcome::Exit(SIGKILL as u32));
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_uname(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // uname(buf)。struct utsname (65B x 5) を固定値で埋めて 0 を返す.
    // Ref: SRC-LINUX (7.3).
    let buf = get64(env, cx.r_a);
    let fields: [&[u8]; 5] = [b"Linux", b"localhost", b"6.0.0", b"#1", b"x86_64"];
    let mut out = [0u8; 65 * 5];
    for (i, f) in fields.iter().enumerate() {
        let base = i * 65;
        out[base..base + f.len()].copy_from_slice(f);
    }
    if env.backend.mem.write(VirtAddr(buf), &out).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_getuid(_sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // root として uid 0 を返す.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_geteuid(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_getuid(sys, env, cx)
}

fn sys_getgid(_sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_getegid(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_getgid(sys, env, cx)
}

fn join_guest_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') || cwd.is_empty() {
        return path.to_string();
    }
    if cwd == "/" {
        return format!("/{path}");
    }
    format!("{}/{}", cwd.trim_end_matches('/'), path)
}

fn sys_getcwd(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getcwd(buf, size)。プロセスの作業ディレクトリを返し、NUL 込み長さを返す.
    let buf = get64(env, cx.r_a);
    let size = get64(env, cx.r_b);
    if buf == 0 || size == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    sys.ensure_cwd();
    let bytes = sys.cwd.as_bytes();
    let need = (bytes.len() as u64) + 1;
    if size < need {
        set64(env, Gpr(0), cx.neg(ERANGE));
        return Some(TrapOutcome::Handled);
    }
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf), bytes)
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf + bytes.len() as u64), &[0u8])
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), need);
    Some(TrapOutcome::Handled)
}

fn sys_chdir(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let path_addr = get64(env, cx.r_a);
    let Some(path) = guest_c_string(env, path_addr) else {
        return Some(TrapOutcome::Unimplemented);
    };
    if path.is_empty() {
        set64(env, Gpr(0), cx.neg(ENOENT));
        return Some(TrapOutcome::Handled);
    }
    sys.ensure_cwd();
    let host = join_guest_path(&sys.cwd, &path);
    let errno = match std::fs::metadata(&host) {
        Ok(meta) if meta.is_dir() => {
            sys.cwd = host;
            set64(env, Gpr(0), 0);
            return Some(TrapOutcome::Handled);
        }
        Ok(_) => ENOTDIR,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NotFound => ENOENT,
            std::io::ErrorKind::PermissionDenied => EACCES,
            _ => ENOENT,
        },
    };
    set64(env, Gpr(0), cx.neg(errno));
    Some(TrapOutcome::Handled)
}

fn sys_getdents64(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getdents64(fd, dirp, count)。ホストのディレクトリ列挙を
    // linux_dirent64 形式で書く。入り切った分だけ返し、残りは次の呼び出しに残す。
    // 1 件も入らなければ EINVAL で、読み位置は進めない。最後まで読んだあとは 0 を返す。
    // d_ino は 0、d_off は累積オフセット、種別は dir/file/link のみ判別する.
    // Ref: SRC-LINUX (7.3).
    let fd = get64(env, cx.r_a) as u32;
    let dirp = get64(env, cx.r_b);
    let count = get64(env, cx.r_c);
    if sys.dir_done.contains(&fd) {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    // opened fd のみ受け付ける。stdin/stdout (0-2) は、パスを覚えていなければ EBADF。
    // ゲスト fd を /proc/self/fd のホスト fd とみなすと、別の記述子を開く。
    let Some(dir_path) = sys.path_of(fd).map(std::path::PathBuf::from) else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let rd = match std::fs::read_dir(&dir_path) {
        Ok(rd) => rd,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    // "." と ".." を先頭に置く（カーネルと同様）。
    let mut names: Vec<(Vec<u8>, u8)> = vec![(b".".to_vec(), 4), (b"..".to_vec(), 4)];
    for ent in rd.flatten() {
        let name = ent
            .file_name()
            .into_string()
            .unwrap_or_default()
            .into_bytes();
        if name.is_empty() {
            continue;
        }
        let ty = ent
            .file_type()
            .map(|t| {
                if t.is_dir() {
                    4u8
                } else if t.is_symlink() {
                    10u8
                } else {
                    8u8
                }
            })
            .unwrap_or(0);
        names.push((name, ty));
    }
    // 名前順に並べ替えて決定的にする（カーネルの順序は不定だが、ls は自前で整列する）。
    names[2..].sort_by(|a, b| a.0.cmp(&b.0));
    let start = sys.dir_cursor(fd);
    if start >= names.len() {
        if !sys.dir_done.contains(&fd) {
            sys.dir_done.push(fd);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut taken = 0usize;
    for (name, ty) in names.iter().skip(start) {
        let reclen = ((19 + name.len() + 1) as u64).next_multiple_of(8);
        if out.len() as u64 + reclen > count {
            break;
        }
        off += reclen;
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(*ty);
        out.extend_from_slice(name);
        out.push(0);
        while !(out.len() as u64).is_multiple_of(8) {
            out.push(0);
        }
        taken += 1;
    }
    if taken == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if env.backend.mem.write(VirtAddr(dirp), &out).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    let next = start + taken;
    if next >= names.len() {
        sys.dir_done.push(fd);
        sys.dir_pos.retain(|(id, _)| *id != fd);
    } else {
        sys.set_dir_cursor(fd, next);
    }
    set64(env, Gpr(0), out.len() as u64);
    Some(TrapOutcome::Handled)
}

fn sys_fstat(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // fstat(fd, struct stat *)。x86-64 struct stat (144B) を書く.
    // レイアウトは musl/glibc 共通のカーネル ABI 由来である.
    // ホスト依存の詳細は std の可搬 API だけでは取れないため、
    // 種別 (st_mode) と大きさ (st_size) のみ実値を入れ、残りは 0 とする.
    // Ref: SRC-LINUX (7.3).
    let fd = get64(env, cx.r_a) as u32;
    let stat_addr = get64(env, cx.r_b);
    let meta: std::io::Result<std::fs::Metadata> = if fd < 3 {
        // 付け替えた標準 fd はファイルのメタデータを返す。
        match sys.std_files[fd as usize].as_ref() {
            Some(f) => f.metadata(),
            None => std::fs::metadata(format!("/proc/self/fd/{fd}")),
        }
    } else {
        let slot = fd.wrapping_sub(3) as usize;
        match sys.fds.get(slot).and_then(|f| f.as_ref()) {
            Some(f) => f.metadata(),
            None => {
                set64(env, Gpr(0), cx.neg(EBADF));
                return Some(TrapOutcome::Handled);
            }
        }
    };
    let m = match meta {
        Ok(m) => m,
        Err(_) => {
            set64(env, Gpr(0), cx.neg(EBADF));
            return Some(TrapOutcome::Handled);
        }
    };
    let st = stat144(&m);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_stat(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // stat(path, statbuf)。作業ディレクトリから辿り、struct stat (144B) を書く.
    // シンボリックリンクは辿る。Ref: SRC-LINUX (7.3).
    let path_addr = get64(env, cx.r_a);
    let stat_addr = get64(env, cx.r_b);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    sys.ensure_cwd();
    let path = join_guest_path(&sys.cwd, &path);
    let m = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let st = stat144(&m);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_lstat(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // lstat(path, statbuf)。リンク自体の struct stat (144B) を書く.
    // Ref: SRC-LINUX (7.3).
    let path_addr = get64(env, cx.r_a);
    let stat_addr = get64(env, cx.r_b);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    sys.ensure_cwd();
    let path = join_guest_path(&sys.cwd, &path);
    let m = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let st = stat144(&m);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_newfstatat(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // newfstatat(dirfd, path, statbuf, flags)。AT_FDCWD+絶対パスのみ.
    // ホスト metadata から struct stat (144B) を書いて 0 を返す.
    // flags (AT_SYMLINK_NOFOLLOW 等) は無視してたどる.
    // Ref: SRC-LINUX (7.3).
    let dirfd = get64(env, Gpr(7));
    let path_addr = get64(env, Gpr(6));
    let stat_addr = get64(env, Gpr(2));
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    if !path.starts_with('/') {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let m = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            return Some(TrapOutcome::Handled);
        }
    };
    let st = stat144(&m);
    if env.backend.mem.write(VirtAddr(stat_addr), &st).is_err() {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_sendfile(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // sendfile(out_fd, in_fd, offset, count)。offset==NULL のみ受け付ける.
    // in_fd から読んで out_fd (1/2) へ書き、転送バイト数を返す.
    // Ref: SRC-LINUX (7.3).
    let out_fd = get64(env, Gpr(7)) as u32;
    let in_fd = get64(env, Gpr(6)) as u32;
    let offset = get64(env, Gpr(2));
    let mut left = get64(env, Gpr(10));
    if offset != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if out_fd != 1 && out_fd != 2 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    // 付け替えた標準出力は読取り専用のため EBADF。
    if sys.std_files[out_fd as usize].is_some() {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    // 付け替えた stdin はファイルから読む。真の stdin は空読みのまま.
    let in_empty = in_fd == 0 && sys.std_attached(0);
    if sys.file_ref(in_fd).is_none() {
        if in_empty {
            set64(env, Gpr(0), 0);
            return Some(TrapOutcome::Handled);
        }
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    let mut done = 0u64;
    let mut chunk = vec![0u8; IO_CHUNK];
    while left > 0 {
        let take = left.min(IO_CHUNK as u64) as usize;
        let n = {
            let Some(file) = sys.file_mut(in_fd) else {
                break;
            };
            match std::io::Read::read(file, &mut chunk[..take]) {
                Ok(n) => n,
                Err(_) => break,
            }
        };
        if n == 0 {
            break;
        }
        let w = match out_fd {
            1 => sys.write_fd1(&chunk[..n]),
            _ => std::io::Write::write(&mut std::io::stderr(), &chunk[..n]).unwrap_or(0),
        };
        done += n as u64;
        left -= n as u64;
        if n < take || w < n {
            break;
        }
    }
    set64(env, Gpr(0), done);
    Some(TrapOutcome::Handled)
}

fn sys_lseek(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // lseek(fd, offset, whence)。opened fd の位置を動かし、新位置を返す.
    // Ref: SRC-LINUX (7.3).
    use std::io::Seek;
    let fd = get64(env, Gpr(7)) as u32;
    let offset = get64(env, Gpr(6)) as i64;
    let whence = get64(env, Gpr(2)) as u32;
    let Some(file) = sys.file_mut(fd) else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    let pos = match whence {
        0 => std::io::SeekFrom::Start(offset as u64),
        1 => std::io::SeekFrom::Current(offset),
        2 => std::io::SeekFrom::End(offset),
        _ => {
            set64(env, Gpr(0), cx.neg(EINVAL));
            return Some(TrapOutcome::Handled);
        }
    };
    match file.seek(pos) {
        Ok(n) => set64(env, Gpr(0), n),
        Err(_) => set64(env, Gpr(0), cx.neg(EINVAL)),
    }
    Some(TrapOutcome::Handled)
}

fn sys_ftruncate(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // ftruncate(fd, length)。truncate -s で使う。ホストの set_len に直結する.
    let fd = get64(env, cx.r_a) as u32;
    let len = get64(env, cx.r_b);
    let Some(file) = sys.file_mut(fd) else {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    };
    Some(match file.set_len(len) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) if e.raw_os_error() == Some(EBADF as i32) => {
            set64(env, Gpr(0), cx.neg(EBADF));
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_getgroups(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getgroups(size, list)。所属グループは root (0) のみとみなす.
    // size==0 では必要数を返し、そうでなければ GID 0 を書く.
    // Ref: SRC-LINUX (7.3).
    let size = get64(env, cx.r_a);
    let list = get64(env, cx.r_b);
    if size == 0 {
        set64(env, Gpr(0), 1);
        return Some(TrapOutcome::Handled);
    }
    if list == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if env
        .backend
        .mem
        .write(VirtAddr(list), &0u32.to_le_bytes())
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), 1.min(size));
    Some(TrapOutcome::Handled)
}

fn sys_mprotect(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mprotect(addr, len, prot)。試作では権限変更を無視して 0 を返す.
    // addr/len の検証のみ行う (len==0 は EINVAL).
    let len = if cx.is64 {
        get64(env, Gpr(6))
    } else {
        u64::from(env.backend.get(Gpr(1).state()))
    };
    if len == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_munmap(_sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // munmap(addr, len)。試作では写像解除せず 0 を返す.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_rt_sigaction(_sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // シグナルハンドラ設定は無視して 0 を返す (試作はシグナルなし).
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_rt_sigprocmask(_sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // シグナルマスク変更は無視して 0 を返す.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_tgkill(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // tgkill(tgid, tid, sig)。単一スレッド試作として sig==0 は 0 を返す.
    // シグナル番号が範囲外なら EINVAL.
    let sig = if cx.is64 {
        get64(env, Gpr(2))
    } else {
        u64::from(env.backend.get(Gpr(2).state()))
    };
    if sig > 64 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // sig==0 は存在確認であり 0 を返す。他のシグナルは無視して 0 とする.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_set_robust_list(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // robust futex リスト先頭を記録して 0 を返す。
    // 長さは struct robust_list_head (24バイト) のはずであり、異なる場合は EINVAL.
    const ROBUST_LIST_HEAD_LEN: u64 = 24;
    if get64(env, cx.r_b) != ROBUST_LIST_HEAD_LEN {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    sys.robust_head = get64(env, cx.r_a);
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_rseq(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rseq 領域を記録して 0 を返す。署名検証はしない.
    // rseq_len は 32 (struct rseq) のはずであり、異なる場合は EINVAL.
    // flags は 0 のみ受け付ける.
    const RSEQ_LEN: u64 = 32;
    if get64(env, cx.r_b) != RSEQ_LEN || get64(env, cx.r_c) != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    sys.rseq_addr = get64(env, cx.r_a);
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_getrandom(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // getrandom(buf, len, flags)。試作では 0 埋めして len を返す.
    // flags は GRND_NONBLOCK(1)/GRND_RANDOM(2)/GRND_INSECURE(4) のみ受け付ける.
    let buf = get64(env, cx.r_a);
    let len = get64(env, cx.r_b);
    let flags = get64(env, cx.r_c);
    if flags & !7 != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 拡張しすぎは失敗扱い (0 を返す)。
    const MAX_GETRANDOM: u64 = 256 * 1024;
    if len > MAX_GETRANDOM {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let zeros = vec![0u8; len as usize];
    if len != 0
        && env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(buf), &zeros)
            .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), len);
    Some(TrapOutcome::Handled)
}

fn sys_prlimit64(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // prlimit64(pid, resource, new_limit, old_limit)。
    // 試作では new_limit の設定は無視し、old_limit には無制限を書く.
    // resource は 0..16 (RLIM_NLIMITS) のみ受け付ける.
    const RLIM_NLIMITS: u64 = 16;
    const RLIM_INFINITY: u64 = 0xffff_ffff_ffff_ffff;
    let resource = get64(env, cx.r_b);
    if resource >= RLIM_NLIMITS {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let old_limit = get64(env, Gpr(10));
    if old_limit != 0 {
        let buf = RLIM_INFINITY.to_le_bytes();
        // rlim_cur (8B) + rlim_max (8B) = 16B.
        let mut both = [0u8; 16];
        both[..8].copy_from_slice(&buf);
        both[8..].copy_from_slice(&buf);
        if env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(old_limit), &both)
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_time(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // time(tloc)。ホスト時刻の秒を返し、tloc!=NULL なら書き込む.
    // clock_gettime の ENOSYS フォールバックで呼ばれる.
    let tloc = get64(env, cx.r_a);
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if tloc != 0
        && env
            .backend
            .mem
            .write(VirtAddr(tloc), &secs.to_le_bytes())
            .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), secs as u64);
    Some(TrapOutcome::Handled)
}

fn sys_ioctl(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // ioctl(fd, request, ...)。試作では端末なしとして ENOTTY を返す.
    // ls の画面幅取得などは失敗扱いで継続する.
    // Ref: SRC-LINUX (7.3).
    set64(env, Gpr(0), cx.neg(ENOTTY));
    Some(TrapOutcome::Handled)
}

fn sys_clock_nanosleep(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // clock_nanosleep(clock_id, flags, req, rem)。試作では待たずに 0 を返す.
    // clock_id は CLOCK_REALTIME(0)/MONOTONIC(1) のみ受け付ける.
    let clock_id = get64(env, cx.r_a);
    if clock_id > 1 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_clock_gettime(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // clock_gettime(clk_id, tp)。ホスト時刻を書いて 0 を返す.
    // 0 固定では時刻待ちループが回り続けるため、実時刻を進める.
    let tp = get64(env, cx.r_b);
    if tp != 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mut both = [0u8; 16];
        both[..8].copy_from_slice(&(now.as_secs() as i64).to_le_bytes());
        both[8..].copy_from_slice(&(now.subsec_nanos() as i64).to_le_bytes());
        if env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(tp), &both)
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_readlinkat(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // readlinkat(dirfd, pathname, buf, bufsiz)。AT_FDCWD+絶対パスのみ.
    // ホストの read_link に直結し、切詰めて返す（NUL 終端なし）。
    let (dirfd, path_addr, buf, bufsiz) = if cx.is64 {
        (
            get64(env, Gpr(7)),
            get64(env, Gpr(6)),
            get64(env, Gpr(2)),
            get64(env, Gpr(10)),
        )
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
            u64::from(env.backend.get(Gpr(2).state())),
            u64::from(env.backend.get(Gpr(6).state())),
        )
    };
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if bufsiz == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    if !path.starts_with('/') {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // 拡張しすぎは失敗扱い.
    const MAX_READLINK: u64 = 4096;
    if bufsiz > MAX_READLINK {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    // /proc/self/exe はゲスト実行ファイル自身を返す (ホスト exe ではない).
    // 空の exe_path (単体テスト) ではホストに直結する.
    let target = if path == "/proc/self/exe" && !sys.exe_path.is_empty() {
        sys.exe_path.clone()
    } else {
        match std::fs::read_link(&path) {
            Ok(p) => p.into_os_string().into_string().unwrap_or_default(),
            Err(e) => {
                let no = match e.kind() {
                    std::io::ErrorKind::NotFound => ENOENT,
                    std::io::ErrorKind::PermissionDenied => EACCES,
                    _ => EINVAL,
                };
                set64(env, Gpr(0), cx.neg(no));
                return Some(TrapOutcome::Handled);
            }
        }
    };
    let bytes = target.as_bytes();
    let take = (bytes.len() as u64).min(bufsiz) as usize;
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf), &bytes[..take])
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), take as u64);
    Some(TrapOutcome::Handled)
}

fn sys_readlink(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // readlink(pathname, buf, bufsiz)。readlinkat から dirfd 検証を除いた形.
    let (path_addr, buf, bufsiz) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)), get64(env, Gpr(2)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
            u64::from(env.backend.get(Gpr(2).state())),
        )
    };
    if bufsiz == 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    const MAX_READLINK: u64 = 4096;
    if bufsiz > MAX_READLINK {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let target = if path == "/proc/self/exe" && !sys.exe_path.is_empty() {
        sys.exe_path.clone()
    } else {
        match std::fs::read_link(&path) {
            Ok(p) => p.into_os_string().into_string().unwrap_or_default(),
            Err(e) => {
                let no = match e.kind() {
                    std::io::ErrorKind::NotFound => ENOENT,
                    std::io::ErrorKind::PermissionDenied => EACCES,
                    _ => EINVAL,
                };
                set64(env, Gpr(0), cx.neg(no));
                return Some(TrapOutcome::Handled);
            }
        }
    };
    let bytes = target.as_bytes();
    let take = (bytes.len() as u64).min(bufsiz) as usize;
    if env
        .backend
        .mem
        .write(polyisa_mem::VirtAddr(buf), &bytes[..take])
        .is_err()
    {
        return Some(TrapOutcome::Unimplemented);
    }
    set64(env, Gpr(0), take as u64);
    Some(TrapOutcome::Handled)
}

fn sys_arch_prctl(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // arch_prctl (x86-64 のみ)。TLS の FS ベース設定を受け付ける。
    // Ref: SRC-LINUX (7.3) arch/x86/include/uapi/asm/prctl.h.
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    let op = get64(env, cx.r_a);
    if op == ARCH_SET_FS {
        sys.fs_base = get64(env, cx.r_b);
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    if op == ARCH_GET_FS {
        let base = sys.fs_base;
        let dst = get64(env, cx.r_b);
        let buf = base.to_le_bytes();
        if env
            .backend
            .mem
            .write(polyisa_mem::VirtAddr(dst), &buf)
            .is_err()
        {
            return Some(TrapOutcome::Unimplemented);
        }
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EINVAL));
    Some(TrapOutcome::Handled)
}

fn sys_dup(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // dup(oldfd)。開ファイルは try_clone して最下位空きに置く (freopen 対応)。
    // 真の 1/2 (ファイルなし) は旧来通り oldfd を返す.
    let oldfd = get64(env, cx.r_a) as u32;
    if !sys.fd_valid(oldfd) {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if let Some((cloned, path)) = sys.clone_open(oldfd) {
        if let Some(i) = (0..3).find(|&i| sys.std_files[i].is_none() && sys.std_closed[i]) {
            sys.std_files[i] = Some(cloned);
            sys.std_closed[i] = false;
            if let Some(p) = path {
                sys.remember_path(i as u32, p);
            }
            set64(env, Gpr(0), i as u64);
            return Some(TrapOutcome::Handled);
        }
        if let Some(idx) = sys.fds.iter().position(|f| f.is_none()) {
            sys.fds[idx] = Some(cloned);
            let fd = (3 + idx) as u32;
            if let Some(p) = path {
                sys.remember_path(fd, p);
            }
            set64(env, Gpr(0), fd as u64);
            return Some(TrapOutcome::Handled);
        }
        sys.fds.push(Some(cloned));
        let fd = (3 + sys.fds.len() - 1) as u32;
        if let Some(p) = path {
            sys.remember_path(fd, p);
        }
        set64(env, Gpr(0), fd as u64);
        return Some(TrapOutcome::Handled);
    }
    if oldfd == 1 || oldfd == 2 {
        set64(env, Gpr(0), oldfd as u64);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EBADF));
    Some(TrapOutcome::Handled)
}

fn sys_dup2(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // dup2(oldfd, newfd)。1/2 同士の複製は newfd を返して継続する.
    // --list の dup2(1,2) は出力先の付け替えだが、試作では写像せず継続する.
    let oldfd = get64(env, cx.r_a) as u32;
    let newfd = get64(env, cx.r_b) as u32;
    // 閉じた標準 fd は不正。接続中・付け替え中と opened fd が真.
    let valid = |fd: u32| sys.fd_valid(fd);
    if !valid(oldfd) || newfd > 1024 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if oldfd == newfd {
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    if let Some((cloned, path)) = sys.clone_open(oldfd) {
        if newfd < 3 {
            let i = newfd as usize;
            sys.std_files[i] = Some(cloned);
            sys.std_closed[i] = false;
        } else {
            let idx = newfd.wrapping_sub(3) as usize;
            while sys.fds.len() <= idx {
                sys.fds.push(None);
            }
            sys.fds[idx] = Some(cloned);
        }
        if let Some(p) = path {
            sys.remember_path(newfd, p);
        }
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    if (oldfd == 1 || oldfd == 2) && (newfd == 1 || newfd == 2) {
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EBADF));
    Some(TrapOutcome::Handled)
}

fn sys_dup3(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // dup3(oldfd, newfd, flags)。hexdump の libbb 準備で使う.
    // flags は O_CLOEXEC のみ無視して継続。oldfd==newfd は EINVAL.
    let oldfd = get64(env, cx.r_a) as u32;
    let newfd = get64(env, cx.r_b) as u32;
    let flags = get64(env, cx.r_c) as u32;
    const O_CLOEXEC: u32 = 0x80000;
    if flags & !O_CLOEXEC != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    if oldfd == newfd {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let valid = |fd: u32| sys.fd_valid(fd);
    if !valid(oldfd) || newfd > 1024 {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    if let Some((cloned, path)) = sys.clone_open(oldfd) {
        if newfd < 3 {
            let i = newfd as usize;
            sys.std_files[i] = Some(cloned);
            sys.std_closed[i] = false;
        } else {
            let idx = newfd.wrapping_sub(3) as usize;
            while sys.fds.len() <= idx {
                sys.fds.push(None);
            }
            sys.fds[idx] = Some(cloned);
        }
        if let Some(p) = path {
            sys.remember_path(newfd, p);
        }
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    if (oldfd == 1 || oldfd == 2) && (newfd == 1 || newfd == 2) {
        set64(env, Gpr(0), newfd as u64);
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), cx.neg(EBADF));
    Some(TrapOutcome::Handled)
}

fn sys_mkdir(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mkdir(path, mode)。ホストの create_dir に直結する.
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match std::fs::create_dir(&path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::AlreadyExists => 17,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_mkdirat(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // mkdirat(dirfd, path, mode)。AT_FDCWD+絶対/相対パスを受け付ける.
    let (dirfd, path_addr) = (get64(env, cx.r_a), get64(env, cx.r_b));
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match std::fs::create_dir(&path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::AlreadyExists => 17,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_rename(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rename(oldpath, newpath)。ホストの rename に直結する.
    let old_addr = get64(env, cx.r_a);
    let new_addr = get64(env, cx.r_b);
    let old_path = match guest_c_string(env, old_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let new_path = match guest_c_string(env, new_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match std::fs::rename(&old_path, &new_path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_symlink(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // symlink(oldpath, newpath)。`ln -s` で使う。
    // 可搬 API がないため実体はクリエート host の helper に置く。
    let old_addr = get64(env, cx.r_a);
    let new_addr = get64(env, cx.r_b);
    let old_path = match guest_c_string(env, old_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let new_path = match guest_c_string(env, new_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match polyisa_host::symlink(&old_path, &new_path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::AlreadyExists => 17,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_rmdir(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // rmdir(path)。ホストの remove_dir に直結する.
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match std::fs::remove_dir(&path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_unlink(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // unlink(path)。ホストの remove_file に直結する.
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match std::fs::remove_file(&path) {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_unlinkat(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // unlinkat(dirfd, path, flags)。AT_FDCWD のみ、flags は 0/AT_REMOVEDIR(0x200) を受け付ける.
    // ディレクトリ指定は remove_dir、以外は remove_file に直結する.
    let (dirfd, path_addr, flags) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)), get64(env, Gpr(2)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
            u64::from(env.backend.get(Gpr(2).state())),
        )
    };
    if !cx.is_at_fdcwd(dirfd) || flags & !0x200 != 0 {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    let res = if flags & 0x200 != 0 {
        std::fs::remove_dir(&path)
    } else {
        std::fs::remove_file(&path)
    };
    Some(match res {
        Ok(()) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_access(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // access(path, mode)。存在確認のみ行い、存在すれば 0 を返す.
    // X_OK 等の実行権限の厳密判定はしない（試作の割り切り）。
    let path_addr = get64(env, cx.r_a);
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match std::fs::metadata(&path) {
        Ok(_) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_faccessat(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // faccessat(dirfd, path, mode)。AT_FDCWD のみ、存在確認のみ行う.
    let (dirfd, path_addr) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
        )
    };
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    Some(match std::fs::metadata(&path) {
        Ok(_) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_utimensat(_sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // utimensat(dirfd, path, times, flags)。AT_FDCWD のみ受け付ける.
    // times==NULL は現在時刻のつもりで、存在すれば 0、なければ空作成して 0 を返す.
    // times!=NULL は無視して同様に扱う（touch の継続が目的の試作）。
    let (dirfd, path_addr) = if cx.is64 {
        (get64(env, Gpr(7)), get64(env, Gpr(6)))
    } else {
        (
            u64::from(env.backend.get(Gpr(3).state())),
            u64::from(env.backend.get(Gpr(1).state())),
        )
    };
    if !cx.is_at_fdcwd(dirfd) {
        set64(env, Gpr(0), cx.neg(EINVAL));
        return Some(TrapOutcome::Handled);
    }
    let path = match guest_c_string(env, path_addr) {
        Some(p) => p,
        None => return Some(TrapOutcome::Unimplemented),
    };
    if std::fs::metadata(&path).is_ok() {
        set64(env, Gpr(0), 0);
        return Some(TrapOutcome::Handled);
    }
    Some(match std::fs::File::create(&path) {
        Ok(_) => {
            set64(env, Gpr(0), 0);
            TrapOutcome::Handled
        }
        Err(e) => {
            let no = match e.kind() {
                std::io::ErrorKind::NotFound => ENOENT,
                std::io::ErrorKind::PermissionDenied => EACCES,
                _ => EINVAL,
            };
            set64(env, Gpr(0), cx.neg(no));
            TrapOutcome::Handled
        }
    })
}

fn sys_chmod(_sys: &mut CliLinux, env: &mut BareEnv, _cx: &SysCtx) -> Option<TrapOutcome> {
    // chmod/fchmod/fchmodat。試作では権限変更を無視して 0 を返す.
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_fchmod(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_chmod(sys, env, cx)
}

fn sys_fchmodat(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    sys_chmod(sys, env, cx)
}

fn sys_umask(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // umask(mask)。旧マスクを返して更新する。mkdir -p の保存・復元で使う.
    // ホストの umask は触らない.
    let mask = get64(env, cx.r_a) as u32 & 0o777;
    let old = sys.umask;
    sys.umask = mask;
    set64(env, Gpr(0), u64::from(old));
    Some(TrapOutcome::Handled)
}

fn sys_fcntl(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // fcntl(fd, cmd, ...)。接続中・付け替え中の標準 fd と opened fd に対して 0 を返す.
    // printf の stdout 設定などで呼ばれる。複製やロックは行わない.
    let fd = get64(env, cx.r_a) as u32;
    let valid = sys.fd_valid(fd);
    if !valid {
        set64(env, Gpr(0), cx.neg(EBADF));
        return Some(TrapOutcome::Handled);
    }
    set64(env, Gpr(0), 0);
    Some(TrapOutcome::Handled)
}

fn sys_brk(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
    let addr = get64(env, cx.r_a);
    // 未初期化の非常口：像末尾を知らないため要求値を切り上げて使う。
    // run_image 経由では init_brk 済みのため通常は通らない。
    if sys.heap_end == 0 {
        sys.heap_end = addr.next_multiple_of(PAGE_SIZE);
        set64(env, Gpr(0), sys.heap_end);
        return Some(TrapOutcome::Handled);
    }
    if addr == 0 {
        // brk(0) は問い合わせであり現ブレークを返す。
        set64(env, Gpr(0), sys.heap_end);
        return Some(TrapOutcome::Handled);
    }
    let aligned = addr.next_multiple_of(PAGE_SIZE);
    if aligned > sys.heap_end {
        // 拡張しすぎは失敗扱い（現ブレークを返す）。
        const MAX_GROW: u64 = 256 * 1024 * 1024;
        if aligned - sys.heap_end > MAX_GROW {
            set64(env, Gpr(0), sys.heap_end);
            return Some(TrapOutcome::Handled);
        }
        // 縮小で残った写像は消さず、欠けたページだけ足す。
        // 実 brk は縮小で内容を捨てないため、再拡張で上書きしない.
        use polyisa_mem::PageNo;
        let mut cur = sys.heap_end;
        while cur < aligned {
            if !env.backend.mem.is_mapped(PageNo(cur / PAGE_SIZE))
                && env.backend.mem.map(VirtAddr(cur), 1, Perms::RW).is_err()
            {
                set64(env, Gpr(0), sys.heap_end);
                return Some(TrapOutcome::Handled);
            }
            cur += PAGE_SIZE;
        }
        sys.heap_end = aligned;
    } else {
        // 縮小は受け付ける（写像は残す）。
        sys.heap_end = aligned;
    }
    set64(env, Gpr(0), sys.heap_end);
    Some(TrapOutcome::Handled)
}

/// プロセスの clone。アドレス空間を共有するフラグは受けない。
/// 子は実行可能なスレッドとして置き、親には子の識別子を返す。
fn sys_clone(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let flags = get64(env, cx.r_a);
    let stack = get64(env, cx.r_b);
    if flags & (polyisa_os_linux::clone_flag::VM | polyisa_os_linux::clone_flag::THREAD) != 0 {
        return Some(TrapOutcome::Unimplemented);
    }
    let parent = sys.ensure_self();
    let child_pid = sys.procs.borrow_mut().fork(parent);
    let mut child_env = env.clone();
    set64(&mut child_env, Gpr(0), 0);
    if stack != 0 {
        set64(&mut child_env, Gpr(4), stack);
    }
    // SYSCALL と INT 0x80 はどちらも 2 バイト。子は次の命令から始める。
    let eip = eip_of(&mut child_env);
    child_env
        .backend
        .set(polyisa_guest_x86::sem::eip_ref(), eip.wrapping_add(2));
    let mut child_linux = sys.duplicate();
    child_linux.pid = child_pid.0;
    child_linux.steps = 0;
    child_linux.wait = None;
    sys.queue
        .0
        .borrow_mut()
        .meta
        .insert(polyisa_kernel::ThreadId(child_pid.0));
    sys.queue.0.borrow_mut().parked.push(ParkedTask {
        env: child_env,
        linux: child_linux,
    });
    set64(env, Gpr(0), child_pid.0);
    Some(TrapOutcome::Handled)
}

fn sys_execve(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    let path_addr = get64(env, cx.r_a);
    let argv_addr = get64(env, cx.r_b);
    let envp_addr = get64(env, cx.r_c);
    let Some(path) = guest_c_string(env, path_addr) else {
        set64(env, Gpr(0), cx.neg(EFAULT));
        return Some(TrapOutcome::Handled);
    };
    let argv = match read_cstr_array(env, argv_addr) {
        Ok(v) => v,
        Err(()) => {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
    };
    let envp = match read_cstr_array(env, envp_addr) {
        Ok(v) => v,
        Err(()) => {
            set64(env, Gpr(0), cx.neg(EFAULT));
            return Some(TrapOutcome::Handled);
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            set64(env, Gpr(0), cx.neg(ENOENT));
            return Some(TrapOutcome::Handled);
        }
        Err(_) => {
            set64(env, Gpr(0), cx.neg(EACCES));
            return Some(TrapOutcome::Handled);
        }
    };
    match install_exec(sys, env, &bytes, &path, &argv, &envp) {
        Ok(()) => Some(TrapOutcome::Handled),
        Err(errno) => {
            set64(env, Gpr(0), cx.neg(errno));
            Some(TrapOutcome::Handled)
        }
    }
}

fn sys_wait4(sys: &mut CliLinux, env: &mut BareEnv, cx: &SysCtx) -> Option<TrapOutcome> {
    // WNOHANG。子がまだ終了していなければ 0 を返す。
    const WNOHANG: u64 = 1;
    let which = get64(env, cx.r_a) as i64;
    let status_ptr = get64(env, cx.r_b);
    let options = get64(env, cx.r_c);
    let wnohang = options & WNOHANG != 0;
    if sys.pid == 0 {
        set64(env, Gpr(0), cx.neg(ECHILD));
        return Some(TrapOutcome::Handled);
    }
    sys.wait = None;
    sys.queue
        .0
        .borrow_mut()
        .meta
        .unblock(polyisa_kernel::ThreadId(sys.pid));
    let parent = polyisa_kernel::ProcessId(sys.pid);
    match sys.procs.borrow_mut().try_reap(parent, which) {
        polyisa_kernel::Reap::Exited { pid, code, signal } => {
            if status_ptr != 0 {
                let st = reap_status(code, signal);
                if env
                    .backend
                    .mem
                    .write(VirtAddr(status_ptr), &st.to_le_bytes())
                    .is_err()
                {
                    set64(env, Gpr(0), cx.neg(EFAULT));
                    return Some(TrapOutcome::Handled);
                }
            }
            set64(env, Gpr(0), pid.0);
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::Reap::NoChild => {
            set64(env, Gpr(0), cx.neg(ECHILD));
            Some(TrapOutcome::Handled)
        }
        polyisa_kernel::Reap::Pending => {
            if wnohang {
                set64(env, Gpr(0), 0);
                Some(TrapOutcome::Handled)
            } else {
                sys.wait = Some(WaitSlot { which, status_ptr });
                sys.queue.0.borrow_mut().meta.block(
                    polyisa_kernel::ThreadId(sys.pid),
                    polyisa_kernel::ThreadWait::Child { which },
                );
                Some(TrapOutcome::Blocked)
            }
        }
    }
}

/// ゲストのポインタ配列を NUL 終端まで読む。失敗は `Err(())`。
fn read_cstr_array(env: &mut BareEnv, addr: u64) -> Result<Vec<Vec<u8>>, ()> {
    if addr == 0 {
        return Err(());
    }
    let acc = data_access();
    let mut out = Vec::new();
    for i in 0..64u64 {
        let mut word = [0u8; 8];
        if env
            .backend
            .mem
            .read(VirtAddr(addr + i * 8), &mut word, acc)
            .is_err()
        {
            return Err(());
        }
        let ptr = u64::from_le_bytes(word);
        if ptr == 0 {
            return Ok(out);
        }
        let Some(text) = guest_c_string(env, ptr) else {
            return Err(());
        };
        out.push(text.into_bytes());
    }
    Err(())
}

/// 現在のアドレス空間を静的 ELF で置き換え、入口へ eip を移す。
fn install_exec(
    sys: &mut CliLinux,
    env: &mut BareEnv,
    bytes: &[u8],
    path: &str,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
) -> Result<(), u32> {
    use polyisa_mem::{PAGE_SIZE, Perms};
    let ehdr = polyisa_loader::elf::parse_ehdr(bytes).map_err(|_| ENOEXEC)?;
    const EM_X86_64: u16 = 62;
    if !ehdr.little || ehdr.machine != EM_X86_64 || ehdr.entry > u64::from(u32::MAX) {
        return Err(ENOEXEC);
    }
    let phdrs = polyisa_loader::elf::parse_phdrs(bytes, &ehdr).map_err(|_| ENOEXEC)?;
    let mut mem = polyisa_mem::AddressSpace::new();
    polyisa_loader::elf::load_segments(bytes, &phdrs, &mut mem).map_err(|_| ENOEXEC)?;
    let mut image_end = 0u64;
    for ph in &phdrs {
        if ph.seg_type == 1 {
            image_end = image_end.max(ph.vaddr.saturating_add(ph.memsz));
        }
    }
    let top = 0x7fff_0000u64;
    let (img, sp) = polyisa_os_linux::build_initial_stack(top, argv, envp, &[(6, 0x1000)]);
    const STACK_SIZE: u64 = 8 * 1024 * 1024;
    let base = top - STACK_SIZE;
    let end = top.next_multiple_of(PAGE_SIZE);
    let count = (end - base) / PAGE_SIZE;
    mem.map(VirtAddr(base), count, Perms(Perms::R.0 | Perms::W.0))
        .map_err(|_| ENOMEM)?;
    mem.write(VirtAddr(sp), &img).map_err(|_| EFAULT)?;
    env.backend.mem = mem;
    env.backend.reservation = polyisa_mem::Reservation::empty();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), sp);
    set64(env, Gpr(0), 0);
    env.backend
        .set(polyisa_guest_x86::sem::eip_ref(), ehdr.entry as u32);
    sys.init_brk(image_end);
    sys.exe_path = path.to_string();
    sys.fs_base = 0;
    Ok(())
}

// Gap: GAP-0001
impl TrapHandler for CliLinux {
    fn fs_base(&self) -> u64 {
        self.fs_base
    }

    fn after_step(&mut self, env: &mut BareEnv) {
        self.step_and_maybe_preempt(env);
    }

    fn on_block(&mut self, env: &mut BareEnv) -> bool {
        let blocked = self.wait.is_some() || self.pipe_wait.is_some();
        if self.preempt(env) {
            return true;
        }
        if blocked {
            self.note_deadlock();
        }
        false
    }

    fn take_exit(&mut self, env: &mut BareEnv, code: u32) -> bool {
        self.yield_on_exit(env, code)
    }

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
        let guest_abi = if self.is64 {
            polyisa_os_linux::GuestAbi::X86_64Linux
        } else {
            polyisa_os_linux::GuestAbi::I386Linux
        };
        // dirfd の AT_FDCWD：i386 は 32ビット、x86-64 は 64ビットの -100。
        // 32ビット mov で設定された場合 (RDI=0xffffff9c) も受け付けるため下位32で比較する.
        let at_fdcwd: u64 = if self.is64 {
            0xffff_ffff_ffff_ff9c
        } else {
            u64::from(AT_FDCWD_U32)
        };
        let cx = SysCtx {
            r_a,
            r_b,
            r_c,
            is64: self.is64,
            at_fdcwd,
        };
        let nr = get64(env, Gpr(0));
        let name = polyisa_os_linux::syscall_name(guest_abi, nr);
        let table = if self.is64 {
            X86_64_SYSCALLS
        } else {
            I386_SYSCALLS
        };
        if let Some(name) = name
            && let Some((_, handler)) = table.iter().find(|(n, _)| *n == name)
            && let Some(out) = handler(self, env, &cx)
        {
            return out;
        }
        // Gap: GAP-0003
        if !self.reported.contains(&nr) {
            self.reported.push(nr);
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
    fn writev_two_iovecs() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"hi").unwrap();
        env.backend.mem.write(VirtAddr(0x110), b"!").unwrap();
        // iov[0]={0x100,2}, iov[1]={0x110,1} at 0x200.
        let mut iov = [0u8; 32];
        iov[..8].copy_from_slice(&0x100u64.to_le_bytes());
        iov[8..16].copy_from_slice(&2u64.to_le_bytes());
        iov[16..24].copy_from_slice(&0x110u64.to_le_bytes());
        iov[24..32].copy_from_slice(&1u64.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x200), &iov).unwrap();
        set64(&mut env, Gpr(0), abi::WRITEV);
        set64(&mut env, Gpr(7), 2);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // fd=9 は EBADF。
        set64(&mut env, Gpr(0), abi::WRITEV);
        set64(&mut env, Gpr(7), 9);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn mmap_anonymous_returns_addr() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        sys.heap_end = 0x6000_0000;
        let mut env = bare();
        // mmap(NULL, 0x1000, PROT_READ|WRITE, MAP_PRIVATE|ANONYMOUS, -1, 0).
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x1000);
        set64(&mut env, Gpr(2), 3);
        set64(&mut env, Gpr(10), 0x22);
        set64(&mut env, Gpr(8), 0xffff_ffff_ffff_ffff);
        set64(&mut env, Gpr(9), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let base = get64(&mut env, Gpr(0));
        assert_eq!(base, 0x6000_0000);
        // len=0 は EINVAL。
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn mmap_null_skips_mapped() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        sys.heap_end = 0x6000_0000;
        let mut env = bare();
        // 先に 0x60000000 を写像して内容を書く（縮小で残った写像を模す）。
        env.backend
            .mem
            .map(VirtAddr(0x6000_0000), 1, Perms::RW)
            .unwrap();
        env.backend.mem.write(VirtAddr(0x6000_0000), b"hi").unwrap();
        // mmap(NULL, 0x1000, ...) は占有を避けて次のページを返す。
        set64(&mut env, Gpr(0), abi::MMAP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x1000);
        set64(&mut env, Gpr(2), 3);
        set64(&mut env, Gpr(10), 0x22);
        set64(&mut env, Gpr(8), 0xffff_ffff_ffff_ffff);
        set64(&mut env, Gpr(9), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x6000_1000);
        // 既存内容は残っている。
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x6000_0000), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"hi");
    }

    #[test]
    fn openat_reads_string_near_map_edge() {
        // 写像の末尾近くに置いたパスも読める（まとめて読むと境界で失敗するため）。
        let mut sys = CliX86::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x1FFD), b"/x\0").unwrap();
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x1FFD,
            0,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        // /x は存在しないため ENOENT。読めなければ Unimplemented になる。
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(ENOENT));
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
    fn openat_rejects_bad_dirfd_and_relpath() {
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
    fn openat_creat_wronly_write_roundtrip() {
        // truncate/cp/split の前段: O_WRONLY|O_CREAT|O_TRUNC で作り、write して read で戻る.
        // O_EXCL 付きの既存作成は EEXIST(17)。旧実装は書込み系 flags を EINVAL で拒否した.
        let dir = std::env::temp_dir().join(format!("polyisa-unit-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path_s = dir.join("f.txt").to_string_lossy().into_owned();
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
        env.backend.mem.write(VirtAddr(0x200), b"abcdef").unwrap();
        // 存在しない path の O_WRONLY のみは ENOENT。
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
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(ENOENT));
        // O_WRONLY|O_CREAT|O_TRUNC (1|0o100|0o1000=0o1101) で作成 -> fd 3。
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0o1101,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        // write(3, 0x200, 6) -> 6。
        set_regs(&mut env, polyisa_os_linux::i386::WRITE as u32, 3, 0x200, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        // close(3) -> 0。
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // O_RDONLY で開き直して read -> "abcdef"。
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
        set_regs(&mut env, polyisa_os_linux::i386::READ as u32, 3, 0x300, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        let mut back = [0u8; 6];
        env.backend
            .mem
            .read(VirtAddr(0x300), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"abcdef");
        // O_RDWR で開いて追記位置を読書きできる。
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            2,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        // O_CREAT|O_EXCL の既存作成は EEXIST(17)。
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0o300,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(17));
        // O_TRUNC で空になる。
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0o1101,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        set_regs(&mut env, polyisa_os_linux::i386::READ as u32, 3, 0x300, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // 読取り専用 fd への write は EBADF。
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
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
        set_regs(&mut env, polyisa_os_linux::i386::WRITE as u32, 3, 0x200, 6);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn openat_accepts_o_directory() {
        // O_DIRECTORY 付きでも開ける（opendir が付ける旗）。
        let mut sys = CliX86::default();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/\0").unwrap();
        set_regs(
            &mut env,
            polyisa_os_linux::i386::OPENAT as u32,
            0xffff_ff9c,
            0x100,
            0x4000,
        );
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        // fd (3) が返る。ENOENT/EINVAL ではない。
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
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

    #[test]
    fn stdin_close_open_read_serves_file() {
        // uniq の stdin 付け替え回帰: close(0) -> 0、open -> 0、read(0) で内容が読める.
        // 旧実装は close(0) で EBADF、read(0) で空読み 0 を返した.
        let path = std::env::temp_dir().join(format!("polyisa-unit-stdin-{}", std::process::id()));
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
        // close(0) -> 0。
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 0, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // openat -> 最下位の空き 0。
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
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // read(0) -> 6（付け替えたファイルから読む）。
        set_regs(&mut env, polyisa_os_linux::i386::READ as u32, 0, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 6);
        // fcntl(0) -> 0（付け替え中は妥当）。
        set_regs(&mut env, polyisa_os_linux::i386::FCNTL as u32, 0, 3, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        // close(0) -> 0、read(0) -> EBADF、もう一度 close(0) -> EBADF。
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 0, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        set_regs(&mut env, polyisa_os_linux::i386::READ as u32, 0, 0x200, 64);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 0, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), neg_errno(EBADF));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_reuses_freed_slot() {
        // 最下位の空き番号を再利用する: open -> 3、close(3) -> 0、open -> 3.
        // 旧実装は常に末尾へ積み、2回目は 4 を返した.
        let path = std::env::temp_dir().join(format!("polyisa-unit-reuse-{}", std::process::id()));
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
        let openat = (polyisa_os_linux::i386::OPENAT as u32, 0xffff_ff9c, 0x100, 0);
        set_regs(&mut env, openat.0, openat.1, openat.2, openat.3);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        set_regs(&mut env, polyisa_os_linux::i386::CLOSE as u32, 3, 0, 0);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 0);
        set_regs(&mut env, openat.0, openat.1, openat.2, openat.3);
        assert!(matches!(
            sys.handle_trap(&mut env, 0x80),
            TrapOutcome::Handled
        ));
        assert_eq!(env.backend.get(Gpr(0).state()), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn brk_query_extend_shrink() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        sys.init_brk(0x1234);
        assert_eq!(sys.heap_end, 0x2000);
        let mut env = bare();
        // brk(0) は問い合わせであり現ブレークを返す。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        // brk(0x2100) は 0x3000 まで拡張する。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x3000);
        assert_eq!(sys.heap_end, 0x3000);
        // 拡張域は零初期化され、読み書きできる。
        env.backend.mem.write(VirtAddr(0x2FF0), b"hi").unwrap();
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x2FF0), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"hi");
        // 縮小は受け付ける。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        // 拡張しすぎは失敗扱い（現ブレークを返す）。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2000 + 256 * 1024 * 1024 + 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        assert_eq!(sys.heap_end, 0x2000);
    }

    #[test]
    fn brk_shrink_regrow_keeps_data() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        sys.init_brk(0x1234);
        let mut env = bare();
        // brk で 0x3000 まで拡張し、書き込んでから縮小・再拡張する。
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x3000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x3000);
        env.backend.mem.write(VirtAddr(0x2FF0), b"hi").unwrap();
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x2000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x2000);
        set64(&mut env, Gpr(0), abi::BRK);
        set64(&mut env, Gpr(7), 0x3000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0x3000);
        // 縮小前の内容が残っている（ゼロ化されない）。
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(VirtAddr(0x2FF0), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"hi");
    }

    #[test]
    fn arch_prctl_set_get_fs() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // ARCH_SET_FS(0x1002) は base を記録して 0 を返す。
        set64(&mut env, Gpr(0), abi::ARCH_PRCTL);
        set64(&mut env, Gpr(7), 0x1002);
        set64(&mut env, Gpr(6), 0x5000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(sys.fs_base, 0x5000);
        // ARCH_GET_FS(0x1003) は記録値を [addr] に書いて 0 を返す。
        set64(&mut env, Gpr(0), abi::ARCH_PRCTL);
        set64(&mut env, Gpr(7), 0x1003);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(u64::from_le_bytes(back), 0x5000);
        // 不明な op は EINVAL。
        set64(&mut env, Gpr(0), abi::ARCH_PRCTL);
        set64(&mut env, Gpr(7), 0x9999);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn set_tid_address_returns_tid() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SET_TID_ADDRESS);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
    }

    #[test]
    fn gettid_returns_tid() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETTID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
    }

    #[test]
    fn getdents64_lists_dir() {
        use polyisa_os_linux::x86_64 as abi;
        // 一時ディレクトリを作り、openat 経由で開いて列挙する。
        let dir = std::env::temp_dir().join(format!("polyisa-getdents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hi").unwrap();
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        let path = dir.to_str().unwrap().to_string() + "\0";
        env.backend
            .mem
            .write(VirtAddr(0x100), path.as_bytes())
            .unwrap();
        // openat(AT_FDCWD, dir, O_RDONLY) -> fd 3。
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // 1 件も入らない count は EINVAL。読み位置は進めない。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // "." 1 件だけ入る。残りは次の呼び出しに残る。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 24);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 24);
        // getdents64(3, 0x400, 0x500) は残りの件数を返す。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 0x500);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0));
        assert!(n > 0 && n < 0x1_0000, "getdents64 returned {n:#x}");
        let mut back = vec![0u8; n as usize];
        env.backend
            .mem
            .read(VirtAddr(0x400), &mut back, data_access())
            .unwrap();
        // "a.txt" が含まれること。
        assert!(back.windows(5).any(|w| w == b"a.txt"));
        // 2回目は 0 (EOF)。
        set64(&mut env, Gpr(0), abi::GETDENTS64);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 0x500);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn getpid_returns_pid() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETPID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
    }

    #[test]
    fn clone_pid_matches_getpid() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x1000);
        // 子は未実装命令で止まり、wait4 は子を戻す。
        env.backend.mem.write(VirtAddr(0x1002), &[0x06]).unwrap();
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        assert!(child > 1, "child pid {child}");
        set64(&mut env, Gpr(0), abi::GETPID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), sys.pid);
        assert_ne!(sys.pid, u64::from(std::process::id()));
        set64(&mut env, Gpr(0), abi::GETTID);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), sys.pid);
        // 子は終了しない。wait4 は子を残して待つ。
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Blocked));
        assert!(sys.task_pids().contains(&child));
    }

    #[test]
    fn wait4_wnohang_leaves_child_then_reaps() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), 0x1000);
        let child_code: &[u8] = &[
            0x48, 0xC7, 0xC0, 60, 0, 0, 0, // mov rax, 60
            0x48, 0xC7, 0xC7, 9, 0, 0, 0, // mov rdi, 9
            0x0F, 0x05, // syscall
        ];
        env.backend.mem.write(VirtAddr(0x1002), child_code).unwrap();
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        // WNOHANG では子を走らせず 0 を返す。ECHILD ではない。
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 0x1800);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(sys.task_pids().contains(&child));
        // ブロックする wait4 は、実行ループが子を走らせてから回収する。
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 0x1800);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Blocked));
        let entry = eip_of(&mut env);
        let _ = run_mode(&mut env, entry, &mut sys, 100, true);
        let mut st = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x1800), &mut st, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(st), 9 << 8);
        assert!(!sys.task_pids().contains(&child));
    }

    #[test]
    fn uname_writes_utsname() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::UNAME);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 65 * 5];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(&back[..6], b"Linux\0");
        assert_eq!(&back[65..75], b"localhost\0");
    }

    #[test]
    fn getuid_gid_return_zero() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        for nr in [abi::GETUID, abi::GETGID, abi::GETEUID, abi::GETEGID] {
            set64(&mut env, Gpr(0), nr);
            assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
            assert_eq!(get64(&mut env, Gpr(0)), 0);
        }
    }

    #[test]
    fn getcwd_returns_host_cwd() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0)) as usize;
        assert!(n > 1);
        let mut back = vec![0u8; n];
        env.backend
            .mem
            .read(
                VirtAddr(0x100),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back[n - 1], 0);
        // ERANGE: サイズ不足.
        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ERANGE));
    }

    #[test]
    fn chdir_updates_getcwd_and_relative_openat() {
        use polyisa_os_linux::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-chdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("note"), b"Q").unwrap();
        let path = dir.to_str().unwrap();

        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0)) as usize;
        let mut back = vec![0u8; n];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        let host = std::env::current_dir().unwrap();
        assert_eq!(&back[..n - 1], host.to_str().unwrap().as_bytes());

        env.backend
            .mem
            .write(VirtAddr(0x300), path.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x300 + path.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::CHDIR);
        set64(&mut env, Gpr(7), 0x300);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);

        set64(&mut env, Gpr(0), abi::GETCWD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0)) as usize;
        let mut back = vec![0u8; n];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(&back[..n - 1], path.as_bytes());

        env.backend.mem.write(VirtAddr(0x400), b"note\0").unwrap();
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), u64::from(AT_FDCWD_U32));
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let fd = get64(&mut env, Gpr(0));
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), fd);
        set64(&mut env, Gpr(6), 0x500);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut byte = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(0x500), &mut byte, data_access())
            .unwrap();
        assert_eq!(byte, *b"Q");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fstat_stdout_writes_stat() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // fstat(1, 0x100) は 0 を返し、struct stat (144B) を書く。
        set64(&mut env, Gpr(0), abi::FSTAT);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 144];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        // st_mode (オフセット 24) は何かしら非0のはず。
        assert_ne!(u32::from_le_bytes(back[24..28].try_into().unwrap()), 0);
        // 不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::FSTAT);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn sendfile_file_to_stdout() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        // /proc/self/exe を入力に積む（必ず存在する実行ファイル）。
        let f = std::fs::File::open("/proc/self/exe").unwrap();
        sys.fds.push(Some(f));
        let mut env = bare();
        // sendfile(1, 3, NULL, 16) は 16 を返して stdout に書く。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 3);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 16);
        // offset 非NULL は EINVAL。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 3);
        set64(&mut env, Gpr(2), 0x100);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // 不正な入力 fd は EBADF。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 99);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
        // stdin (0) は空読みとして 0 を返す。
        set64(&mut env, Gpr(0), abi::SENDFILE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn lseek_moves_position() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let f = std::fs::File::open("/proc/self/exe").unwrap();
        sys.fds.push(Some(f));
        let mut env = bare();
        // lseek(3, 16, SEEK_SET) は 16 を返す。
        set64(&mut env, Gpr(0), abi::LSEEK);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 16);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 16);
        // 不正な whence は EINVAL、不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::LSEEK);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 99);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        set64(&mut env, Gpr(0), abi::LSEEK);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn time_returns_host_secs() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // time(NULL) は 0 より大きい秒を返す。
        set64(&mut env, Gpr(0), abi::TIME);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let secs = get64(&mut env, Gpr(0));
        assert!(secs > 0);
        // time(0x100) は同じ秒を [0x100] に書く。
        set64(&mut env, Gpr(0), abi::TIME);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), secs);
        let mut back = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(i64::from_le_bytes(back) as u64, secs);
    }

    #[test]
    fn getgroups_returns_root() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // getgroups(0, NULL) は必要数 1 を返す。
        set64(&mut env, Gpr(0), abi::GETGROUPS);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        // getgroups(1, 0x100) は 1 を返し、GID 0 を書く。
        set64(&mut env, Gpr(0), abi::GETGROUPS);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back), 0);
    }

    #[test]
    fn clock_nanosleep_returns_zero() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // clock_nanosleep(0, 0, req, rem) は待たずに 0 を返す。
        set64(&mut env, Gpr(0), abi::CLOCK_NANOSLEEP);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0x100);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // 不正な clock_id は EINVAL。
        set64(&mut env, Gpr(0), abi::CLOCK_NANOSLEEP);
        set64(&mut env, Gpr(7), 99);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn ioctl_returns_enotty() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // ioctl(1, TIOCGWINSZ, ...) は端末なしとして ENOTTY を返す。
        set64(&mut env, Gpr(0), abi::IOCTL);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x5413);
        set64(&mut env, Gpr(2), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOTTY));
    }

    #[test]
    fn fcntl_stdout_returns_zero() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // fcntl(1, F_GETFL) は 0 を返して継続する。printf の stdout 設定で使う.
        set64(&mut env, Gpr(0), abi::FCNTL);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // 不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::FCNTL);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
    }

    #[test]
    fn stat_root_is_dir() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/\0").unwrap();
        // stat("/", 0x200) は 0 を返し、st_mode に S_IFDIR を書く。
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o040000);
        // 存在しないパスは ENOENT。
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/no/such/file\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
    }

    #[test]
    fn lstat_sees_the_link() {
        use polyisa_os_linux::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-lstat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let target = dir.join("file");
        let link = dir.join("link");
        std::fs::write(&target, b"ab").unwrap();
        polyisa_host::symlink(
            target.to_str().expect("utf-8"),
            link.to_str().expect("utf-8"),
        )
        .unwrap();
        let mut path = link.into_os_string().into_encoded_bytes();
        path.push(0);
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), &path).unwrap();
        set64(&mut env, Gpr(0), abi::LSTAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o120000);
        set64(&mut env, Gpr(0), abi::STAT);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o100000);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn newfstatat_root_is_dir() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        env.backend.mem.write(VirtAddr(0x100), b"/\0").unwrap();
        // newfstatat(AT_FDCWD, "/", 0x200, 0) は 0 を返し、st_mode に S_IFDIR を書く。
        set64(&mut env, Gpr(0), abi::NEWFSTATAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x218), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back) & 0o170000, 0o040000);
        // 存在しないパスは ENOENT。
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/no/such/file\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::NEWFSTATAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
    }

    #[test]
    fn mprotect_munmap_return_zero() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::MPROTECT);
        set64(&mut env, Gpr(6), 0x1000);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::MPROTECT);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        set64(&mut env, Gpr(0), abi::MUNMAP);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn rt_sig_returns_zero() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::RT_SIGACTION);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        set64(&mut env, Gpr(0), abi::RT_SIGPROCMASK);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn tgkill_zero_returns_zero() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::TGKILL);
        set64(&mut env, Gpr(7), 100);
        set64(&mut env, Gpr(6), 100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // sig 範囲外は EINVAL。
        set64(&mut env, Gpr(0), abi::TGKILL);
        set64(&mut env, Gpr(2), 100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn rseq_records_addr() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::RSEQ);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 32);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(sys.rseq_addr, 0x5000);
        // 長さが 32 でなければ EINVAL。
        set64(&mut env, Gpr(0), abi::RSEQ);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 16);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn getrandom_fills_zeros() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::GETRANDOM);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 8);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 8);
        let mut back = [0xFFu8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(back, [0u8; 8]);
        // 不明な flags は EINVAL。
        set64(&mut env, Gpr(0), abi::GETRANDOM);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 8);
        set64(&mut env, Gpr(2), 8);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn mkdir_rmdir_roundtrip() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_mkdir_{}", std::process::id());
        let _ = std::fs::remove_dir(&path);
        env.backend
            .mem
            .write(VirtAddr(0x100), path.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path.len() as u64), &[0])
            .unwrap();
        // mkdir(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::MKDIR);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o777);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(std::fs::metadata(&path).is_ok());
        // 二重作成は EEXIST (17).
        set64(&mut env, Gpr(0), abi::MKDIR);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o777);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(17));
        // rmdir(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::RMDIR);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn umask_roundtrip() {
        // umask(mask) は旧マスクを返して更新する。mkdir -p の保存・復元で使う.
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        sys.umask = 0o22;
        // umask(0o77) -> 0o22。
        set64(&mut env, Gpr(0), abi::UMASK);
        set64(&mut env, Gpr(7), 0o77);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0o22);
        // umask(0o22) -> 0o77。
        set64(&mut env, Gpr(0), abi::UMASK);
        set64(&mut env, Gpr(7), 0o22);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0o77);
    }

    #[test]
    fn ftruncate_roundtrip() {
        // ftruncate(fd, len) は長さを変えて 0 を返す。truncate -s で使う.
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_ftruncate_{}", std::process::id());
        std::fs::write(&path, b"abcdef").unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        sys.fds.push(Some(f));
        // ftruncate(3, 3) -> 0、大きさ 3.
        set64(&mut env, Gpr(0), abi::FTRUNCATE);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 3);
        // 不正 fd は EBADF。
        set64(&mut env, Gpr(0), abi::FTRUNCATE);
        set64(&mut env, Gpr(7), 99);
        set64(&mut env, Gpr(6), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EBADF));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn neg_errno_sign_extends() {
        // 負 errno は符号拡張する。x86-64 の誤り (+errno) を回帰で防ぐ.
        assert_eq!(neg_errno(22), 0xFFFF_FFEAu32);
        assert_eq!(neg_errno64(22), 0xFFFF_FFFF_FFFF_FFEAu64);
        assert_eq!(neg_errno64(0), 0);
    }

    #[test]
    fn rename_roundtrip() {
        // rename(old, new) は移動して 0 を返す。mv で使う.
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        let old = format!("/tmp/polyisa_rename_old_{}", std::process::id());
        let new = format!("/tmp/polyisa_rename_new_{}", std::process::id());
        let _ = std::fs::remove_file(&new);
        std::fs::write(&old, b"data").unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100), old.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + old.len() as u64), &[0])
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200), new.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200 + new.len() as u64), &[0])
            .unwrap();
        // rename(old, new) -> 0、old は消えて new ができる.
        set64(&mut env, Gpr(0), abi::RENAME);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(std::fs::metadata(&old).is_err());
        assert_eq!(std::fs::read(&new).unwrap(), b"data");
        // 存在しない old は ENOENT。
        let missing = format!("/tmp/polyisa_rename_missing_{}", std::process::id());
        env.backend
            .mem
            .write(VirtAddr(0x100), missing.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + missing.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::RENAME);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn symlink_roundtrip() {
        // symlink(old, new) はリンクを作って 0 を返す。`ln -s` で使う.
        // 実体は host helper のためここでは番号経路と結果の写像を確かめる.
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        let old = String::from("/tmp/symlink_target_exists");
        let new = format!("/tmp/polyisa_symlink_{}", std::process::id());
        let _ = std::fs::remove_file(&new);
        env.backend
            .mem
            .write(VirtAddr(0x100), old.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + old.len() as u64), &[0])
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200), new.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200 + new.len() as u64), &[0])
            .unwrap();
        // symlink(old, new) -> 0、new は old へのリンク.
        set64(&mut env, Gpr(0), abi::SYMLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(
            std::fs::read_link(&new).unwrap(),
            std::path::PathBuf::from(old.as_str())
        );
        // 同じ new の再作成は EEXIST(17)。
        set64(&mut env, Gpr(0), abi::SYMLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(17));
        // 存在しない親の下は ENOENT。
        let bad = format!("/tmp/polyisa_no_dir_{}/link", std::process::id());
        env.backend
            .mem
            .write(VirtAddr(0x200), bad.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x200 + bad.len() as u64), &[0])
            .unwrap();
        set64(&mut env, Gpr(0), abi::SYMLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn unlink_access_utimensat_roundtrip() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        let path = format!("/tmp/polyisa_utimens_{}", std::process::id());
        let _ = std::fs::remove_file(&path);
        env.backend
            .mem
            .write(VirtAddr(0x100), path.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path.len() as u64), &[0])
            .unwrap();
        // utimensat(AT_FDCWD, path) は空作成して 0 を返す.
        set64(&mut env, Gpr(0), abi::UTIMENSAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(std::fs::metadata(&path).is_ok());
        // access(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::ACCESS);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // unlink(path) は 0 を返す.
        set64(&mut env, Gpr(0), abi::UNLINK);
        set64(&mut env, Gpr(7), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // 存在しない access は ENOENT.
        set64(&mut env, Gpr(0), abi::ACCESS);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ENOENT));
    }

    #[test]
    fn dup2_std_alias_returns_newfd() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // dup2(1, 2) は 2 を返す (--list の画面幅取得の前段).
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 2);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 2);
        // chmod/fchmodat は無視して 0 を返す.
        set64(&mut env, Gpr(0), abi::CHMOD);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0o755);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
    }

    #[test]
    fn dup3_std_alias_returns_newfd() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        // dup3(1, 2, 0) は 2 を返す (hexdump の前段).
        set64(&mut env, Gpr(0), abi::DUP3);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 2);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 2);
        // oldfd==newfd は EINVAL.
        set64(&mut env, Gpr(0), abi::DUP3);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 1);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
        // 不正 flags は EINVAL.
        set64(&mut env, Gpr(0), abi::DUP3);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 2);
        set64(&mut env, Gpr(2), 0xFFFF);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn dup2_opened_fd_onto_stdin_serves_file() {
        // freopen 相当の付け替え回帰: open -> fd 3、close(0)、dup2(3, 0) -> 0、read(0) で読める.
        // hexdump の Bad file descriptor 対応。旧実装は opened fd の dup2 で EBADF.
        use polyisa_os_linux::x86_64 as abi;
        let path = std::env::temp_dir().join(format!("polyisa-unit-dup2-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        let path_s = path.to_string_lossy().into_owned();
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        // openat(AT_FDCWD, path, O_RDONLY) -> fd 3.
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), AT_FDCWD_U32 as u64);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // close(0) -> 0。
        set64(&mut env, Gpr(0), abi::CLOSE);
        set64(&mut env, Gpr(7), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // dup2(3, 0) -> 0。
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        // dup(3) -> 最下位空き 4。
        set64(&mut env, Gpr(0), abi::DUP);
        set64(&mut env, Gpr(7), 3);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 4);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_to_remapped_stdout_serves_file() {
        // split の出力 pattern: open(WRONLY|CREAT) -> fd、dup2(fd, 1)、write(1) で書ける.
        // 旧実装は付け替え後もホスト stdout に書いたため出力が空になった.
        use polyisa_os_linux::x86_64 as abi;
        let dir = std::env::temp_dir().join(format!("polyisa-unit-wstdout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path_s = dir.join("o.txt").to_string_lossy().into_owned();
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), path_s.as_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x100 + path_s.len() as u64), &[0])
            .unwrap();
        env.backend.mem.write(VirtAddr(0x200), b"abcdef").unwrap();
        // openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_TRUNC) -> fd 3.
        set64(&mut env, Gpr(0), abi::OPENAT);
        set64(&mut env, Gpr(7), AT_FDCWD_U32 as u64);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0o1101);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 3);
        // dup2(3, 1) -> 1。
        set64(&mut env, Gpr(0), abi::DUP2);
        set64(&mut env, Gpr(7), 3);
        set64(&mut env, Gpr(6), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        // write(1, 0x200, 6) -> 6。ホスト stdout ではなくファイルに書く。
        set64(&mut env, Gpr(0), abi::WRITE);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 6);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 6);
        assert_eq!(std::fs::read(dir.join("o.txt")).unwrap(), b"abcdef");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prlimit64_writes_infinity() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::PRLIMIT64);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 3);
        set64(&mut env, Gpr(2), 0);
        set64(&mut env, Gpr(10), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0u8; 16];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(back[..8].try_into().unwrap()),
            0xFFFF_FFFF_FFFF_FFFF
        );
        assert_eq!(
            u64::from_le_bytes(back[8..].try_into().unwrap()),
            0xFFFF_FFFF_FFFF_FFFF
        );
        // resource 範囲外は EINVAL。
        set64(&mut env, Gpr(0), abi::PRLIMIT64);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn clock_gettime_writes_zeros() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::CLOCK_GETTIME);
        set64(&mut env, Gpr(7), 1);
        set64(&mut env, Gpr(6), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut back = [0xFFu8; 16];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut back, data_access())
            .unwrap();
        // ホスト時刻が書かれる (0 固定ではない)。
        assert_ne!(back, [0u8; 16]);
        assert_ne!(back, [0xFFu8; 16]);
    }

    #[test]
    fn readlinkat_proc_self_exe() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/proc/self/exe\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::READLINKAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0));
        assert!(n > 0 && n < 0x100);
        let mut back = vec![0u8; n as usize];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut back, data_access())
            .unwrap();
        assert!(back.starts_with(b"/"));
        // bufsiz=0 は EINVAL。
        set64(&mut env, Gpr(0), abi::READLINKAT);
        set64(&mut env, Gpr(7), 0xffff_ffff_ffff_ff9c);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0x200);
        set64(&mut env, Gpr(10), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn readlink_proc_self_exe() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        sys.exe_path = "/tmp/opencode/work/busybox-1.37.0/busybox".to_string();
        let mut env = bare();
        env.backend
            .mem
            .write(VirtAddr(0x100), b"/proc/self/exe\0")
            .unwrap();
        set64(&mut env, Gpr(0), abi::READLINK);
        set64(&mut env, Gpr(7), 0x100);
        set64(&mut env, Gpr(6), 0x200);
        set64(&mut env, Gpr(2), 0x100);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let n = get64(&mut env, Gpr(0));
        assert_eq!(n, 0x29);
        let mut back = vec![0u8; n as usize];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut back, data_access())
            .unwrap();
        assert_eq!(&back, b"/tmp/opencode/work/busybox-1.37.0/busybox");
    }

    #[test]
    fn set_robust_list_records_head() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::SET_ROBUST_LIST);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 24);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert_eq!(sys.robust_head, 0x5000);
        // 長さが 24 でなければ EINVAL。
        set64(&mut env, Gpr(0), abi::SET_ROBUST_LIST);
        set64(&mut env, Gpr(7), 0x5000);
        set64(&mut env, Gpr(6), 16);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(EINVAL));
    }

    #[test]
    fn fs_relative_mov_sibabs() {
        // FS 上書き + REX.W 8B SIB直接番地 (MOV RDX,FS:[disp32]) を run する。
        // FS 絶対番地のため disp=target-fs_base=0x500 (RIP相対ではない)。
        // fs_base=0x1000、disp=0x500 で [0x1500] を読み、exit(低32)。
        let mut sys = CliLinux::x86_64();
        sys.fs_base = 0x1000;
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1500), &[0x78u8, 0x56, 0x34, 0x12, 0, 0, 0, 0])
            .unwrap();
        let prog: &[u8] = &[
            0x64, 0x48, 0x8B, 0x14, 0x25, 0x00, 0x05, 0x00,
            0x00, // mov rdx,FS:[0x500] ([0x1500])
            0x48, 0x89, 0xD7, // mov rdi,rdx
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x0F, 0x05, // syscall -> exit(0x12345678)
        ];
        env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 100, true);
        assert_eq!(out, Outcome::Exit(0x1234_5678));
    }

    #[test]
    fn fs_relative_mov_sibabs_store() {
        // FS 上書き + REX.W 89 SIB直接番地 (MOV FS:[disp32],RAX) を run する。
        // fs_base=0x1000、disp=0x500 で [0x1500] へ64bit格納し、exit(0)。
        let mut sys = CliLinux::x86_64();
        sys.fs_base = 0x1000;
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        let prog: &[u8] = &[
            0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, // movabs rax,0x1122334455667788
            0x64, 0x48, 0x89, 0x04, 0x25, 0x00, 0x05, 0x00, 0x00, // mov FS:[0x500],rax
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
            0x0F, 0x05, // syscall -> exit(0)
        ];
        env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 100, true);
        assert_eq!(out, Outcome::Exit(0));
        let mut back = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x1500), &mut back, data_access())
            .unwrap();
        assert_eq!(u64::from_le_bytes(back), 0x1122_3344_5566_7788);
    }

    #[test]
    fn fs_relative_mov_sibabs_store_imm32() {
        // FS 上書き + C7 SIB 直接番地 (MOV FS:[disp32],imm32) を run する。
        // fs_base=0x1000、disp=0x500 で [0x1500]=0x11223344 になり、exit(0)。
        // SIB=0x25 (no_index) の mod=00 形。fetch 長 11B+接頭辞の経路検証も兼ねる。
        let mut sys = CliLinux::x86_64();
        sys.fs_base = 0x1000;
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        let prog: &[u8] = &[
            0x64, 0xC7, 0x04, 0x25, 0x00, 0x05, 0x00, 0x00, 0x44, 0x33, 0x22,
            0x11, // movl $0x11223344,FS:[0x500]
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
            0x0F, 0x05, // syscall -> exit(0)
        ];
        env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 100, true);
        assert_eq!(out, Outcome::Exit(0));
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x1500), &mut back, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(back), 0x1122_3344);
    }

    #[test]
    fn fs_relative_mov_sibabs_store_imm8() {
        // FS 上書き + 88 SIB 直接番地 (MOV FS:[disp32],r8) を run する。
        // fs_base=0x1000、disp=0x611、AL=0x77 -> [0x1611]=0x77、exit(0)。
        let mut sys = CliLinux::x86_64();
        sys.fs_base = 0x1000;
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(Gpr(0).state(), 0x77);
        let prog: &[u8] = &[
            0x64, 0x88, 0x04, 0x25, 0x11, 0x06, 0x00, 0x00, // mov FS:[0x611],al
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
            0x0F, 0x05, // syscall -> exit(0)
        ];
        env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 100, true);
        assert_eq!(out, Outcome::Exit(0));
        let mut back = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(0x1611), &mut back, data_access())
            .unwrap();
        assert_eq!(back, [0x77u8]);
    }

    #[test]
    fn fs_relative_add_sibabs() {
        // FS 上書き + REX.W 03 SIB 直接番地 (ADD RDX,FS:[disp32]) を run する。
        // fs_base=0x1000、disp=0 として [0x1000]=0x40 を RDX=0x10 に加え、exit(0x50)。
        let mut sys = CliLinux::x86_64();
        sys.fs_base = 0x1000;
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x40u8, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        env.backend.set(Gpr(2).state(), 0x10);
        let prog: &[u8] = &[
            0x64, 0x48, 0x03, 0x14, 0x25, 0x00, 0x00, 0x00, 0x00, // add rdx,FS:[0x0]
            0x48, 0x89, 0xD7, // mov rdi,rdx
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x0F, 0x05, // syscall -> exit(0x50)
        ];
        env.backend.mem.write(VirtAddr(0x1010), prog).unwrap();
        let out = run_mode(&mut env, 0x1010, &mut sys, 100, true);
        assert_eq!(out, Outcome::Exit(0x50));
    }

    #[test]
    fn fs_relative_mov_eax_memnd() {
        // FS 上書き + 8B mod=00 [base] (MOV EAX,FS:[RAX]) を run する.
        let mut sys = CliLinux::x86_64();
        sys.fs_base = 0x1000;
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1500), &0x1234_5678u32.to_le_bytes())
            .unwrap();
        let prog: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x00, 0x05, 0x00, 0x00, // mov rax,0x500
            0x64, 0x8B, 0x00, // mov eax,FS:[rax]
            0x48, 0x89, 0xC7, // mov rdi,rax
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x0F, 0x05, // syscall -> exit
        ];
        env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 100, true);
        assert_eq!(out, Outcome::Exit(0x1234_5678));
    }

    #[test]
    fn pipe2_roundtrip_in_one_process() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::PIPE2);
        set64(&mut env, Gpr(7), 0x200);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        let mut fds = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x200), &mut fds, data_access())
            .unwrap();
        let read_fd = u32::from_le_bytes(fds[0..4].try_into().unwrap());
        let write_fd = u32::from_le_bytes(fds[4..8].try_into().unwrap());
        env.backend.mem.write(VirtAddr(0x300), b"Z").unwrap();
        set64(&mut env, Gpr(0), abi::WRITE);
        set64(&mut env, Gpr(7), write_fd.into());
        set64(&mut env, Gpr(6), 0x300);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        set64(&mut env, Gpr(0), abi::READ);
        set64(&mut env, Gpr(7), read_fd.into());
        set64(&mut env, Gpr(6), 0x400);
        set64(&mut env, Gpr(2), 1);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 1);
        let mut byte = [0u8; 1];
        env.backend
            .mem
            .read(VirtAddr(0x400), &mut byte, data_access())
            .unwrap();
        assert_eq!(byte, *b"Z");
    }

    #[test]
    fn child_blocks_on_pipe_until_parent_writes() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 2, rwx).unwrap();
        set64(&mut env, Gpr(0), abi::PIPE2);
        set64(&mut env, Gpr(7), 0x1800);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let mut fds = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x1800), &mut fds, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(fds[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(fds[4..8].try_into().unwrap()), 4);
        env.backend.mem.write(VirtAddr(0x1900), b"A").unwrap();

        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_at = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC7, 3);
        push_mov_imm(&mut code, 0xC6, 0x1810);
        push_mov_imm(&mut code, 0xC2, 1);
        push_mov_imm(&mut code, 0xC0, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x8B, 0x06, 0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);
        let parent_at = code.len();
        code[jnz_at + 1] = u8::try_from(parent_at - (jnz_at + 2)).unwrap();
        code.extend(std::iter::repeat_n(0x90, (SCHED_SLICE + 16) as usize));
        push_mov_imm(&mut code, 0xC7, 4);
        push_mov_imm(&mut code, 0xC6, 0x1900);
        push_mov_imm(&mut code, 0xC2, 1);
        push_mov_imm(&mut code, 0xC0, 1);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC7, u32::MAX);
        push_mov_imm(&mut code, 0xC6, 0x1A00);
        push_mov_imm(&mut code, 0xC2, 0);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05, 0x8B, 0x06, 0xC1, 0xE8, 0x08, 0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 8_000, true);
        assert_eq!(out, Outcome::Exit(u32::from(b'A')));
    }

    #[test]
    fn parent_sets_child_group_before_the_slice_ends() {
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_at = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 0);
        code.extend_from_slice(&[0x0F, 0x05]);
        let parent_at = code.len();
        code[jnz_at + 1] = u8::try_from(parent_at - (jnz_at + 2)).unwrap();
        code.extend_from_slice(&[0x48, 0x89, 0xC7, 0x48, 0x89, 0xC6]);
        push_mov_imm(&mut code, 0xC0, 109);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let fail_set = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC0, 121);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x89, 0xC3, 0x48, 0x89, 0xC6]);
        push_mov_imm(&mut code, 0xC7, 0);
        push_mov_imm(&mut code, 0xC0, 109);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let fail_join = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC7, 0);
        push_mov_imm(&mut code, 0xC0, 121);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x39, 0xD8]);
        let fail_cmp = code.len();
        code.extend_from_slice(&[0x75, 0]);
        code.extend_from_slice(&[0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);
        let fail_at = code.len();
        code[fail_set + 1] = u8::try_from(fail_at - (fail_set + 2)).unwrap();
        code[fail_join + 1] = u8::try_from(fail_at - (fail_join + 2)).unwrap();
        code[fail_cmp + 1] = u8::try_from(fail_at - (fail_cmp + 2)).unwrap();
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 1);
        code.extend_from_slice(&[0x0F, 0x05]);
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 8_000, true);
        assert_eq!(out, Outcome::Exit(2));
    }

    #[test]
    fn parent_sigkill_stops_a_looping_child() {
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_at = code.len();
        code.extend_from_slice(&[0x75, 0]);
        code.extend_from_slice(&[0xEB, 0xFE]);
        let parent_at = code.len();
        code[jnz_at + 1] = u8::try_from(parent_at - (jnz_at + 2)).unwrap();
        code.extend_from_slice(&[0x48, 0x89, 0xC7]);
        code.extend(std::iter::repeat_n(0x90, (SCHED_SLICE + 16) as usize));
        push_mov_imm(&mut code, 0xC6, 9);
        push_mov_imm(&mut code, 0xC0, 62);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC6, 0x1800);
        push_mov_imm(&mut code, 0xC2, 0);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05, 0x8B, 0x06, 0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 8_000, true);
        assert_eq!(out, Outcome::Exit(9));
    }

    #[test]
    fn kill_drops_the_parked_child() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        assert!(sys.task_pids().contains(&child));
        set64(&mut env, Gpr(0), abi::KILL);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 9);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        assert!(!sys.task_pids().contains(&child));
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), child);
        let mut status = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut status, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(status), 9);
    }

    #[test]
    fn wait4_zero_reaps_a_child_in_the_same_group() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = bare();
        set64(&mut env, Gpr(0), abi::CLONE);
        set64(&mut env, Gpr(7), 17);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let child = get64(&mut env, Gpr(0));
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), neg_errno64(ECHILD));
        set64(&mut env, Gpr(0), abi::SETPGID);
        set64(&mut env, Gpr(7), child);
        set64(&mut env, Gpr(6), sys.pid);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), 0);
        sys.procs
            .borrow_mut()
            .exit(polyisa_kernel::ProcessId(child), 4);
        set64(&mut env, Gpr(0), abi::WAIT4);
        set64(&mut env, Gpr(7), 0);
        set64(&mut env, Gpr(6), 0x100);
        set64(&mut env, Gpr(2), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(get64(&mut env, Gpr(0)), child);
        let mut status = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(0x100), &mut status, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(status), 4 << 8);
    }

    #[test]
    fn wait_and_empty_read_stop_as_deadlock() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        set64(&mut env, Gpr(0), abi::PIPE2);
        set64(&mut env, Gpr(7), 0x1800);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_at = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC7, 3);
        push_mov_imm(&mut code, 0xC6, 0x1810);
        push_mov_imm(&mut code, 0xC2, 1);
        push_mov_imm(&mut code, 0xC0, 0);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 0);
        code.extend_from_slice(&[0x0F, 0x05]);
        let parent_at = code.len();
        code[jnz_at + 1] = u8::try_from(parent_at - (jnz_at + 2)).unwrap();
        push_mov_imm(&mut code, 0xC7, u32::MAX);
        push_mov_imm(&mut code, 0xC6, 0);
        push_mov_imm(&mut code, 0xC2, 0);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 0);
        code.extend_from_slice(&[0x0F, 0x05]);
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 8_000, true);
        assert_eq!(out, Outcome::Deadlock);
    }

    #[test]
    fn sibling_kill_wakes_a_waiting_parent() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        set64(&mut env, Gpr(0), abi::PIPE2);
        set64(&mut env, Gpr(7), 0x1700);
        set64(&mut env, Gpr(6), 0);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_a = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC7, 3);
        push_mov_imm(&mut code, 0xC6, 0x1810);
        push_mov_imm(&mut code, 0xC2, 1);
        push_mov_imm(&mut code, 0xC0, 0);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 0);
        code.extend_from_slice(&[0x0F, 0x05]);
        let after_a = code.len();
        code[jnz_a + 1] = u8::try_from(after_a - (jnz_a + 2)).unwrap();
        code.extend_from_slice(&[0x48, 0x89, 0xC3]);
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_b = code.len();
        code.extend_from_slice(&[0x75, 0]);
        code.extend_from_slice(&[0x48, 0x89, 0xDF]);
        push_mov_imm(&mut code, 0xC6, 9);
        push_mov_imm(&mut code, 0xC0, 62);
        code.extend_from_slice(&[0x0F, 0x05, 0xEB, 0xFE]);
        let parent_at = code.len();
        code[jnz_b + 1] = u8::try_from(parent_at - (jnz_b + 2)).unwrap();
        push_mov_imm(&mut code, 0xC7, u32::MAX);
        push_mov_imm(&mut code, 0xC6, 0x1820);
        push_mov_imm(&mut code, 0xC2, 0);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05, 0x8B, 0x06, 0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 8_000, true);
        assert_eq!(out, Outcome::Exit(9));
    }

    #[test]
    fn child_runs_across_a_step_slice_before_wait() {
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_at = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 7);
        code.extend_from_slice(&[0x0F, 0x05]);
        let parent_at = code.len();
        code[jnz_at + 1] = u8::try_from(parent_at - (jnz_at + 2)).unwrap();
        code.extend_from_slice(&[0x48, 0x89, 0xC7]);
        code.extend(std::iter::repeat_n(0x90, (SCHED_SLICE + 16) as usize));
        push_mov_imm(&mut code, 0xC6, 0x1800);
        push_mov_imm(&mut code, 0xC2, 1);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jz_at = code.len();
        code.extend_from_slice(&[0x74, 0]);
        code.extend_from_slice(&[0x8B, 0x06, 0xC1, 0xE8, 0x08, 0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);
        let fail_at = code.len();
        code[jz_at + 1] = u8::try_from(fail_at - (jz_at + 2)).unwrap();
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 1);
        code.extend_from_slice(&[0x0F, 0x05]);
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 4_000, true);
        assert_eq!(out, Outcome::Exit(7));
    }

    #[test]
    fn parent_reaps_two_children() {
        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 3, rwx).unwrap();
        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_a = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 3);
        code.extend_from_slice(&[0x0F, 0x05]);
        let parent_a = code.len();
        code[jnz_a + 1] = u8::try_from(parent_a - (jnz_a + 2)).unwrap();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jnz_b = code.len();
        code.extend_from_slice(&[0x75, 0]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 4);
        code.extend_from_slice(&[0x0F, 0x05]);
        let parent_b = code.len();
        code[jnz_b + 1] = u8::try_from(parent_b - (jnz_b + 2)).unwrap();
        push_mov_imm(&mut code, 0xC7, u32::MAX);
        push_mov_imm(&mut code, 0xC6, 0x3100);
        push_mov_imm(&mut code, 0xC2, 0);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC7, u32::MAX);
        push_mov_imm(&mut code, 0xC6, 0x3104);
        push_mov_imm(&mut code, 0xC2, 0);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC7, 0);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 4_000, true);
        assert_eq!(out, Outcome::Exit(0));
        let mut st = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x3100), &mut st, data_access())
            .unwrap();
        assert_eq!(u32::from_le_bytes(st[0..4].try_into().unwrap()), 3 << 8);
        assert_eq!(u32::from_le_bytes(st[4..8].try_into().unwrap()), 4 << 8);
    }

    #[test]
    fn parent_receives_exec_child_exit_code() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("polyisa-exit42");
        std::fs::write(&file, exit_elf(42)).unwrap();
        let path = file.to_str().unwrap();

        let mut sys = CliLinux::x86_64();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 3, rwx).unwrap();

        let path_addr = 0x2000u64;
        let argv_addr = 0x2100u64;
        let envp_addr = 0x2200u64;
        let status_addr = 0x3000u64;
        env.backend
            .mem
            .write(VirtAddr(path_addr), path.as_bytes())
            .unwrap();
        let mut argv = [0u8; 16];
        argv[..8].copy_from_slice(&path_addr.to_le_bytes());
        env.backend.mem.write(VirtAddr(argv_addr), &argv).unwrap();
        env.backend
            .mem
            .write(VirtAddr(envp_addr), &[0u8; 8])
            .unwrap();

        let mut code = Vec::new();
        push_mov_imm(&mut code, 0xC0, 56);
        push_mov_imm(&mut code, 0xC7, 17);
        push_mov_imm(&mut code, 0xC6, 0);
        code.extend_from_slice(&[0x0F, 0x05, 0x48, 0x85, 0xC0]);
        let jne_at = code.len();
        code.extend_from_slice(&[0x75, 0]);
        let child_at = code.len();
        push_mov_imm(&mut code, 0xC0, 59);
        push_mov_imm(&mut code, 0xC7, path_addr as u32);
        push_mov_imm(&mut code, 0xC6, argv_addr as u32);
        push_mov_imm(&mut code, 0xC2, envp_addr as u32);
        code.extend_from_slice(&[0x0F, 0x05]);
        push_mov_imm(&mut code, 0xC0, 60);
        push_mov_imm(&mut code, 0xC7, 127);
        code.extend_from_slice(&[0x0F, 0x05]);
        let parent_at = code.len();
        code[jne_at + 1] = u8::try_from(parent_at - child_at).unwrap();
        code.extend_from_slice(&[0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC6, status_addr as u32);
        push_mov_imm(&mut code, 0xC2, 0);
        push_mov_imm(&mut code, 0xC0, 61);
        code.extend_from_slice(&[0x0F, 0x05, 0x8B, 0x06, 0xC1, 0xE8, 0x08, 0x48, 0x89, 0xC7]);
        push_mov_imm(&mut code, 0xC0, 60);
        code.extend_from_slice(&[0x0F, 0x05]);

        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 1000, true);
        assert_eq!(out, Outcome::Exit(42));
    }

    fn push_mov_imm(code: &mut Vec<u8>, modrm: u8, imm: u32) {
        code.extend_from_slice(&[0x48, 0xC7, modrm]);
        code.extend_from_slice(&imm.to_le_bytes());
    }

    /// 指定した終了コードで exit する x86_64 の静的 ELF。
    fn exit_elf(code: u32) -> Vec<u8> {
        let mut body = vec![0x48, 0xC7, 0xC0, 60, 0, 0, 0, 0x48, 0xC7, 0xC7];
        body.extend_from_slice(&code.to_le_bytes());
        body.extend_from_slice(&[0x0F, 0x05]);
        let mut file = vec![0u8; 120];
        file.extend_from_slice(&body);
        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&2u16.to_le_bytes());
        file[18..20].copy_from_slice(&62u16.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        let entry = 0x400000u64 + 120;
        file[24..32].copy_from_slice(&entry.to_le_bytes());
        file[32..40].copy_from_slice(&64u64.to_le_bytes());
        file[52..54].copy_from_slice(&64u16.to_le_bytes());
        file[54..56].copy_from_slice(&56u16.to_le_bytes());
        file[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64;
        file[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        file[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        file[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
        file[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
        let len = file.len() as u64;
        file[ph + 32..ph + 40].copy_from_slice(&len.to_le_bytes());
        file[ph + 40..ph + 48].copy_from_slice(&len.to_le_bytes());
        file[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        file
    }

    #[test]
    fn syscall_tables_are_unique_and_named_in_os_linux() {
        assert_syscall_table(X86_64_SYSCALLS, polyisa_os_linux::GuestAbi::X86_64Linux);
        assert_syscall_table(I386_SYSCALLS, polyisa_os_linux::GuestAbi::I386Linux);
    }

    fn assert_syscall_table(table: &[(&str, SysFn)], abi: polyisa_os_linux::GuestAbi) {
        let mut seen = std::collections::BTreeSet::new();
        let known = os_linux_names(abi);
        for (name, _) in table {
            assert!(seen.insert(*name), "名前が重複している: {name}");
            assert!(known.contains(name), "{name} は {abi:?} の番号表にない");
        }
    }

    fn os_linux_names(abi: polyisa_os_linux::GuestAbi) -> std::collections::BTreeSet<&'static str> {
        let mut names = std::collections::BTreeSet::new();
        for nr in 0..4096 {
            if let Some(name) = polyisa_os_linux::syscall_name(abi, nr) {
                names.insert(name);
            }
        }
        names
    }
}
