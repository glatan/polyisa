// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 の実行ループ（`cli run` の x86 版）。ゲストメモリからフェッチし、デコードして意味論を実行する。
//!
//! 可変長（1〜5バイト）の入口と eip の進行を受け持つ。imm32/disp32 は
//! リトルエンディアンの実バイト列から復元する（ISADL の word 組立は
//! opcode 上位詰めの試作規約のため、ここでバイト順を直す）。
//! SYSCALL と INT 0x80 はトラップとして呼び出し側に委ねる。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_os_linux::x86::Linux;
use polyisa_sem::{Backend, ExceptionKind};

use polyisa_guest_x86::sem;
use polyisa_guest_x86::{Insn, decode_model_ex};

pub use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};

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
    is64: bool,
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
        // RET imm16 (C2 iw)。i386 musl の stdcall 風呼出し.
        0xC2 => Some(3),
        0x68 => Some(5),
        0xEB | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0x79 | 0x7A
        | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F | 0xE2 | 0xE3 | 0xCD | 0x3C | 0x0C | 0x14 => Some(2),
        0x05 | 0x2D | 0xE8 | 0xE9 | 0x35 => Some(5),
        // MOV moffs (A0-A3)。i386 は moffs32 (5B)、x64 は moffs64 (9B)。i386 musl の a3 対応。
        0xA0..=0xA3 => {
            if is64 {
                Some(9)
            } else {
                Some(5)
            }
        }
        // 0xA9 (TEST EAX,imm32)。66 接頭辞では TEST AX,imm16 (3B)。blkid 0x47d8f3。
        0xA9 => {
            if has66 {
                Some(3)
            } else {
                Some(5)
            }
        }
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
                // mod=01 SIB+disp8 no_index 5B、mod=00 SIB no_index 4B.
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
                } else if md == 2 && rm == 4 {
                    let t = fourth?;
                    // CMOVNE SIB+disp32 no_index。free 0x44801c の cmovne 0x88(%rsp), %ecx。8B.
                    if (t >> 3) & 7 == 4 { Some(8) } else { None }
                } else if md == 0 && rm == 4 {
                    let t = fourth?;
                    // no_index かつ base≠5。cut 0x492257 の cmovll (%rsp), %r10d。4B.
                    if (t >> 3) & 7 == 4 && t & 7 != 5 {
                        Some(4)
                    } else {
                        None
                    }
                } else if (s == 0x46 || s == 0x45 || s == 0x43) && md == 1 && rm != 4 {
                    // CMOVBE / CMOVNE / CMOVAE [base+disp8]。dc 0x40bc13 の cmovae rax, [rsi+8]。
                    Some(4)
                } else if s == 0x46 && md == 0 && rm != 4 && rm != 5 {
                    // CMOVBE r, [base] (0F 46 mod=00)。gunzip 0x48a025 の cmovbe edx, [r8]。3B。
                    Some(3)
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
                } else if s == 0x94 && md == 0 && rm == 5 {
                    // SETE [rip+disp32]。hdparm 0x417940。
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
                } else if md == 1 && rm == 4 {
                    // ntpd 0x42cb2f の cvtsi2sdq 0x8(%rsp), %xmm0。SIB+disp8 で 5B。
                    Some(5)
                } else if md == 1 && rm != 4 {
                    Some(4)
                } else if md == 0 && rm == 4 {
                    // ntpd 0x42cb3e の cvtsi2sdq (%rsp), %xmm1。base=5 は disp32。
                    let t = fourth?;
                    if t & 7 == 5 { None } else { Some(4) }
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
            ) {
                // XMM reg-direct のみ（66 接頭辞は剥がし済み）。
                let m = third?;
                if m >> 6 == 3 { Some(3) } else { None }
            } else if s == 0x2C {
                // CVTTSD2SI r,m64。reg-direct 3B、SIB mod=00 は 4B。base=5 は disp32。
                // awk int 0x4a345e の cvttsd2si rax, QWORD PTR [rsp]。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if md == 0 && rm == 4 {
                    let t = fourth?;
                    if t & 7 != 5 { Some(4) } else { None }
                } else {
                    None
                }
            } else if s == 0x5A {
                // CVTSD2SS / CVTSS2SD (F2/F3 0F 5A /r)。reg-direct は 3B。
                // mod=00 で rm が 4/5 以外も 3B。od -tfF 0x4973b5 の cvtss2sd xmm0, [rbx]。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 || (md == 0 && rm != 4 && rm != 5) {
                    Some(3)
                } else {
                    None
                }
            } else if s == 0x51 {
                // SQRTSD xmm,xmm (F2 0F 51 /r reg-direct)。awk sqrt 0x4c1dd9 の sqrtsd xmm0,xmm0。
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
                } else if rm == 4 && md == 1 {
                    // ADDSD xmm,m64 SIB+disp8。seq 0x499253 の F2 0F 58 44 24 10。0F から 5B.
                    Some(5)
                } else if rm == 4 {
                    let t = fourth?;
                    if md == 0 {
                        if t & 7 == 5 { Some(7) } else { Some(4) }
                    } else {
                        None
                    }
                } else if md == 2 {
                    // ADDSD xmm,m64 [base+disp32]。awk log 0x4c163e の addsd xmm3, [rdx+disp32]。7B.
                    Some(7)
                } else if md == 1 && rm != 4 {
                    // ADDSD xmm,m64 [base+disp8]。ntpd の F2 0F 58 40 10。4B.
                    Some(4)
                } else if md == 0 && rm != 4 && rm != 5 {
                    // ADDSD xmm,m64 [base]。ntpd 0x42c1d3 の F2 0F 58 08。3B.
                    Some(3)
                } else {
                    None
                }
            } else if s == 0x5C {
                // SUBSD xmm,m64 RIP (F2 0F 5C 05 + disp32、7B) と reg-direct (3B)。
                // awk substr 0x4a3cbb の subsd xmm0, [rip+disp32]。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if md == 0 && rm == 5 {
                    Some(7)
                } else if md == 2 && rm != 4 {
                    // SUBSD xmm,m64 [base+disp32]。awk log 0x4c161e の subsd xmm2, [rcx+disp32]。7B.
                    Some(7)
                } else if rm == 4 && md == 2 {
                    // SUBSD xmm,m64 SIB+disp32。ntpd 0x42c207 の F2 0F 5C 94 07 80 00 00 00。8B.
                    Some(8)
                } else if rm == 4 && md == 1 {
                    // SUBSD xmm,m64 SIB+disp8。awk の 2^3 が 0x4c199c で使う subsd xmm0, [rsp+0x10]。5B.
                    Some(5)
                } else if md == 1 && rm != 4 {
                    // SUBSD xmm,m64 [base+disp8]。ntpd 0x42c1ce の F2 0F 5C 40 08。4B.
                    Some(4)
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
            } else if s == 0x5D {
                // MINSD xmm,xmm (F2 0F 5D /r mod=11、3B)。ping 0x42e6d9 の minsd xmm0, xmm1。
                let m = third?;
                if m >> 6 == 3 { Some(3) } else { None }
            } else if s == 0x5E {
                // DIVSD xmm,m64 RIP (F2 0F 5E 05 + disp32、7B)。dd 0x4928e8 対応.
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
            } else if s == 0x59 {
                // MULSD xmm,m64 RIP (F2 0F 59 05 + disp32、7B) と reg-direct (F2 0F 59 /r mod=11、4B)。
                let m = third?;
                let md = m >> 6;
                let rm = m & 7;
                if md == 3 {
                    Some(3)
                } else if md == 1 && rm == 4 {
                    // MULSD xmm,m64 SIB+disp8。seq 0x49924a の F2 0F 59 44 24 08。0F から 5B.
                    Some(5)
                } else if md == 0 && rm == 5 {
                    Some(7)
                } else if md == 0 && rm == 4 {
                    // MULSD xmm,m64 SIB。awk 乗算 0x4a327c の mulsd xmm1, [rsp]。base=5 は disp32。
                    let t = fourth?;
                    if t & 7 != 5 { Some(4) } else { None }
                } else if md == 2 && rm != 4 {
                    // MULSD xmm,m64 [base+disp32]。awk log 0x4c1636 の mulsd xmm2, [rdx+disp32]。7B.
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
            } else if s == 0xAC || s == 0xA4 {
                // SHRD/SHLD r/m32,r32,imm8 (0F AC/A4 /r ib mod=11)。i386 musl 0x80fe4f1。4B.
                let m = third?;
                if m >> 6 == 3 { Some(4) } else { None }
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
                } else if md == 0 && reg == 4 && rm == 4 {
                    // BT m32,imm8 SIB mod=00。tar 0x488fa7 の 41 0F BA 24 24 09。base=5 は disp32。
                    let t = fourth?;
                    if t & 7 == 5 { None } else { Some(5) }
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
                || s == 0xBF
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
        // 0x69 /r id (IMUL r,r/m,imm32)。reg-direct 6B、SIB+disp8 は 8B。
        // mod=00 SIB+imm32 は 7B。base=5 は disp32 が付く。dd 0x4067c3 対応。
        0x69 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(6)
            } else if rm == 4 {
                let t = third?;
                if md == 1 {
                    // mktemp 0x4d85cf の imulq $0x10001, 0x8(%rsp), %rax。
                    Some(8)
                } else if md == 0 && t & 7 != 5 {
                    Some(7)
                } else {
                    None
                }
            } else if md == 1 {
                // IMUL r, [base+disp8], imm32。ifplugd 0x4264b0 の 69 43 04。7B.
                Some(7)
            } else if md == 0 && rm == 5 {
                // IMUL r, [rip+disp32], imm32。nslookup 0x42bb05 の 69 05。10B.
                Some(10)
            } else {
                None
            }
        }
        // 0x6B /r ib (IMUL r,r/m,imm8)。reg-direct 3B、RIP 7B、SIB+disp8 は 5B、
        // [base+disp8]+imm8 は 4B (nmeter 0x44a5eb)。
        0x6B => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(3)
            } else if rm == 4 {
                // mod=01 は SIB+disp8+imm8 (5B)。mod=00 は SIB+imm8 (4B)。base=5 は disp32。
                if md == 1 {
                    Some(5)
                } else if md == 0 {
                    let t = third?;
                    if t & 7 == 5 { None } else { Some(4) }
                } else {
                    None
                }
            } else if md == 0 && rm == 5 {
                Some(7)
            } else if md == 1 {
                Some(4)
            } else if md == 2 && rm != 4 {
                // mod=10 [base+disp32]+imm8 (7B)。i386 iostat 0x808b648 対応.
                Some(7)
            } else {
                None
            }
        }
        // 0x8F /0 (POP m64)。mod=01 [base+disp8] は 3B。vi 0x4ce187 の popq 0x40(%rdi)。
        0x8F => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if reg == 0 && md == 1 && rm != 4 {
                Some(3)
            } else {
                None
            }
        }
        // 0x8E /r (MOV Sreg,r/m16)。mod=11 reg-direct のみ。GS ロードはフラットモデルで no-op。
        0x8E => {
            let s = second?;
            if s >> 6 == 3 { Some(2) } else { None }
        }
        // 0x81 /r id (算術 imm32 群)。
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
                // mod=01 は SIB+disp8+imm32 (8B)。bzip2 0x480dcd の addq $0x102, 0x28(%rsp)。
                if has66 {
                    None
                } else if md == 1 {
                    Some(8)
                } else if md == 2 {
                    // SIB+disp32+imm32 (11B)。i386 musl の 81 BC 24 対応。
                    Some(11)
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
                if reg == 3 && md == 1 {
                    // SBB m32,imm8 SIB+disp8。fsck 0x4d272f の 83 5C 24 14 FF。5B.
                    return Some(5);
                }
                if reg == 5 && md == 1 {
                    // SUB m32,imm8 SIB+disp8。seq 0x4d0bfa の 83 6C 24 58 1C。5B.
                    return Some(5);
                }
                if reg == 6 && md == 1 {
                    // XOR m64,imm8 SIB+disp8。sort 0x4d3045 の 48 83 74 24 10 07。5B.
                    return Some(5);
                }
                // SIB 付き。mod=01 SIB+disp8+imm8 (5B) の /4 AND と /7 CMP と /1 OR と /0 ADD、
                // mod=00 SIB+imm8 (4B) の /4 AND と /7 CMP、66 mod=00 SIB+imm8 (4B) の /0 ADD のみ.
                let t = third?;
                if md == 2 {
                    // mod=10 SIB+disp32+imm8 (8B)。/7 cmp は true 0x4bed16、/5 sub は i386 ls 0x810e732。
                    Some(8)
                } else if md == 0 && reg == 7 && t & 7 == 5 {
                    // mod=00 base=直接番地 + disp32 + imm8 (8B)。id 0x4c0a78 対応.
                    Some(8)
                } else if (reg == 4 || reg == 7 || reg == 1 || reg == 0 || reg == 2)
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
        // 0x20 /r (AND r/m8,r8)。reg-direct 2B、mod=01 [base+disp8] 3B（SIBなし）。
        // 0x28 /r (SUB r/m8,r8) は reg-direct 2B と、mod=00 SIB (3B、base=5 以外)。dc 0x40abb4。
        0x20 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if md == 1 && rm != 4 {
                // AND m8,r8 [base+disp8]。nologin 0x45a07d の and %al,-0x1(%rdi)。
                Some(3)
            } else {
                None
            }
        }
        0x28 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 && md == 0 {
                let t = third?;
                if t & 7 != 5 { Some(3) } else { None }
            } else {
                None
            }
        }
        0x30 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 && md == 0 {
                let t = third?;
                if t & 7 != 5 { Some(3) } else { None }
            } else {
                None
            }
        }
        // 0x08 /r (OR r/m8,r8)。reg-direct 2B、SIB mod=01 +disp8 4B。sed 0x4a87dd 対応.
        // mod=10 base+disp32 6B。udhcpc 0x44426d 対応.
        0x08 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 && md == 1 {
                Some(4)
            } else if md == 1 {
                // powertop 0x44c15c の orb %al, 0x18(%rbx)。
                Some(3)
            } else if md == 2 && rm != 4 {
                Some(6)
            } else if md == 0 && rm == 5 {
                // OR [rip+disp32], r8。hdparm 0x417721 の or byte [rip+disp32], al。
                Some(6)
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
            } else if md == 1 {
                // OR r8, [base+disp8] (0A /r mod=01、3B)。uudecode 0x49da3e の or sil, [rcx-1]。
                Some(3)
            } else if md == 0 && rm == 5 {
                // OR r8,[RIP+disp32] (0A 05 + disp32)。find 0x5c44a7 対応.
                Some(6)
            } else if md == 2 && rm == 4 {
                // OR r8,m8 SIB+disp32。tar -tf 0x48e5f4 の or al, [rsp+disp32]。7B.
                Some(7)
            } else if md == 2 && rm != 4 {
                // OR r8, [base+disp32] (0A /r mod=10、6B)。i386 showkey 0x810d301 対応.
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
        // 0xD0 /4 (SHL r/m8,1) と /5 (SHR r/m8,1)。
        // reg-direct は 2B。mod=10 のメモリは disp32 で 6B。gzip 0x484b2e の shlb。
        0xD0 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if md == 2 && rm != 4 {
                Some(6)
            } else {
                None
            }
        }
        // 0x84 /r (TEST r/m8,r8)。reg-direct 2B、mod=00 base 2B / abs 6B、
        // mod=01 base+disp8 3B、mod=10 base+disp32 6B。
        // SIB mod=01 は 4B。taskset 0x47c686 の 84 44 24 0c。
        0x84 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(2)
            } else if rm == 4 {
                if md == 1 { Some(4) } else { None }
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
            if reg == 7 && md == 1 && rm == 4 {
                // FNSTCW m16 SIB+disp8。seq 0x4d0c17 の D9 7C 24 4E。4B.
                return Some(4);
            }
            if reg == 5 && md == 1 && rm == 4 {
                // FLDCW m16 SIB+disp8。seq 0x4d0c2d の D9 6C 24 4C。4B.
                return Some(4);
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
            if reg == 5 && md == 0 && rm == 5 {
                // FLD m80 [RIP+disp32] (DB /5)。dd 0x4d0e58 の DB 2D。6B.
                return Some(6);
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
            if md == 3 && (reg == 1 || reg == 5) {
                Some(2)
            } else {
                None
            }
        }
        // DF /5 SIB mod=00 (FILD m64)。seq 0x4018c4 の DF 2C 24。base=5 は disp32。
        0xDF => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            if md == 3 && reg == 5 {
                // FUCOMIP ST(0), ST(i) (DF E8+i)。dd 0x4d0ea6 の DF E9。
                return Some(2);
            }
            if reg == 5 && md == 1 && rm == 4 {
                // FILD m64 SIB+disp8。seq 0x4d0c4d の DF 6C 24 30。4B.
                return Some(4);
            }
            if reg == 5 && md == 0 && rm == 4 {
                let sib = third?;
                if sib & 7 != 5 { Some(3) } else { None }
            } else if reg == 7 && md == 1 && rm == 4 {
                // FISTP m64 SIB+disp8。seq 0x4d0c31 の DF 7C 24 30。4B.
                Some(4)
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
            } else if reg == 0 && md == 0 && rm == 4 {
                // FLD m64 SIB。awk length 0x401b17 の DD 04 24。base=5 は disp32。
                let sib = third?;
                if sib & 7 != 5 { Some(3) } else { None }
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
                if reg == 1 || reg == 4 || reg == 6 || reg == 7 {
                    Some(3)
                } else {
                    None
                }
            } else if rm == 4 {
                // SIB 付き。mod=01 SIB+disp8+imm8 (5B) の /7 CMP と /1 ORB と /4 ANDB、
                // mod=00 SIB [base+index*scale] +imm8 (4B) の /0 ADDB と /1 ORB と /6 XORB と /7 CMPB。
                // base=5 は disp32 が付く。sha3sum 0x4b4f20 の addb $-128, (%rdi,%rax,1)。
                // mod=10 SIB+disp32+imm8 (8B) の /7 CMPB (stat 0x429875 対応).
                if md == 1 && (reg == 7 || reg == 6 || reg == 1 || reg == 4 || reg == 0) {
                    Some(5)
                } else if md == 0 && (reg == 0 || reg == 1 || reg == 6 || reg == 7) {
                    let t = third?;
                    if t & 7 != 5 { Some(4) } else { None }
                } else if md == 2 && (reg == 7 || reg == 4) {
                    // /7 CMPB と /4 ANDB。nologin 0x454247 の andb $imm,disp32(%r12)。
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
            } else if md == 2 && reg == 6 {
                // mod=10 [base+disp32],imm8 (7B) の /6 XORB。i386 iostat 0x808b743 対応.
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
            } else if md == 0 && reg == 6 && rm != 4 && rm != 5 {
                // mod=00 [base],imm8 (3B) の /6 XORB。nmeter 0x44a570 の xor BYTE PTR [rax], 0x1。
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
                if md == 3 && reg == 6 {
                    // DIV r/m8 (F6 /6 mod=11、2B)。lzcat 0x48b6ef の div dl。
                    return Some(2);
                }
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
                } else if md == 2 {
                    // mod=10 SIB+disp32+imm8 (8B)。ping 0x4c4288 の test BYTE PTR [rsp+disp32], imm8。
                    Some(8)
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
                } else if md == 0 && reg == 0 && rm == 4 {
                    // TEST m32,imm32 SIB mod=00 (F7 /0 + ModRM + SIB + imm32、7B)。i386 ls 0x80d11e0 対応.
                    let t = third?;
                    if t & 7 == 5 { None } else { Some(7) }
                } else if md == 1 && reg == 0 && rm == 4 {
                    // TEST m32,imm32 SIB mod=01 (+SIB+disp8+imm32、8B)。i386 musl 0x80fe3a9 対応.
                    let _ = third?;
                    Some(8)
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
                } else if reg != 0 {
                    // NOT/NEG/MUL/IMUL/DIV/IDIV (F7 /2-/7) のメモリ形。ModRM のみで imm は無い。
                    if rm == 4 {
                        let t = third?;
                        if md == 0 && t & 7 == 5 {
                            Some(7)
                        } else {
                            Some(3 + u64::from(md == 1) + u64::from(md == 2) * 4)
                        }
                    } else if md == 0 && rm == 5 {
                        Some(6)
                    } else {
                        Some(2 + u64::from(md == 1) + u64::from(md == 2) * 4)
                    }
                } else {
                    None
                }
            } else {
                let reg = (s >> 3) & 7;
                if reg == 0 {
                    if has66 {
                        // TEST r16,imm16 (66 F7 /0 mod=11、4B)。gunzip 0x48b06a の test r14w, 0x200。
                        Some(4)
                    } else {
                        Some(6)
                    }
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
            if reg == 6 && md == 1 && rm != 4 {
                // PUSH m [base+disp8]。vi 0x4ce196 の FF 73 40。
                return Some(3);
            }
            if reg == 6 && md == 0 {
                // PUSH m [base] 2B / SIB 3B / abs disp32 6B。i386 musl の FF 30。
                if rm == 4 {
                    let t = third?;
                    return if t & 7 == 5 { Some(7) } else { Some(3) };
                }
                return if rm == 5 { Some(6) } else { Some(2) };
            }
            if reg == 6 && md == 2 && rm != 4 {
                // PUSH m [base+disp32] 6B。
                return Some(6);
            }
            if reg == 6 && md == 2 && rm == 4 {
                // PUSH m64 SIB+disp32。top 0x44e0d6 の push qword [rsp+0x110]。
                return Some(7);
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
        0xFE => {
            let s = second?;
            let md = s >> 6;
            let reg = (s >> 3) & 7;
            let rm = s & 7;
            // INC/DEC r8 (FE /0,/1 mod=11)。dc 0x40efa1 の FE CA。
            if md == 3 && (reg == 0 || reg == 1) {
                Some(2)
            } else if md == 0 && reg == 1 && rm != 4 && rm != 5 {
                // DEC m8 [base]。dc 0x40abca の dec byte [rcx]。
                Some(2)
            } else if md == 0 && reg == 0 && rm == 5 {
                // INC m8 [RIP+disp32]。nologin 0x45972a の incb disp32(%rip)。
                Some(6)
            } else {
                None
            }
        }
        0x29 | 0x31 | 0x21 | 0x11 | 0x19 | 0x86 | 0x87 => {
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
                // XOR m,r SIB+disp8 (31 /r mod=01)。gunzip 0x48a1c3 の xor DWORD PTR [rsp+disp8], ecx。
                if first == 0x31 && md == 1 {
                    return Some(4);
                }
                // ADC/SBB m,r SIB+disp8 (11/19 /r mod=01)。i386 musl の 64bit 演算（wc 0x80dba0a）。
                if (first == 0x11 || first == 0x19) && md == 1 {
                    return Some(4);
                }
                // ADC m,r SIB+disp32 (11 /r mod=10)。i386 iostat 0x808b68d 対応。7B.
                if first == 0x11 && md == 2 {
                    return Some(7);
                }
                // SUB m,r SIB+disp32 (29 /r mod=10)。i386 deluser 0x804fce9 対応。7B.
                if first == 0x29 && md == 2 {
                    return Some(7);
                }
                // AND m,r SIB+disp8 (21 /r mod=01)。i386 nologin 0x80968e5 対応。4B.
                if first == 0x21 && md == 1 {
                    return Some(4);
                }
                // AND m,r SIB mod=00。bzip2 0x47f93d の 21 0C 94。base=5 は disp32。
                if first == 0x21 && md == 0 {
                    let t = third?;
                    return Some(if t & 7 == 5 { 7 } else { 3 });
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
        // 0x85 /r (TEST r,m)。reg-direct 2B、SIB mod=00 3B、SIB mod=00 base=5 +disp32 7B、
        // SIB mod=01 +disp8 4B、SIB mod=10 +disp32 7B、
        // mod=01 base+disp8 3B、mod=10 base+disp32 6B、mod=00 base 2B / abs disp32 6B。
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
                    // mod=00 SIB。base=5 は disp32 で 7B。lsattr 0x49f5e5 対応.
                    let t = third?;
                    if t & 7 != 5 { Some(3) } else { Some(7) }
                }
            } else if md == 1 {
                Some(3)
            } else if md == 2 || rm == 5 {
                Some(6)
            } else {
                Some(2)
            }
        }
        // 0xC1 (シフト)。reg-direct は 3B。mod=01 は disp8+imm8 で 4B。
        // bzip2 0x480237 の shll $8, 0x70(%rdi)。
        0xC1 => {
            let s = second?;
            let md = s >> 6;
            let rm = s & 7;
            if md == 3 {
                Some(3)
            } else if md == 1 && rm != 4 {
                Some(4)
            } else {
                None
            }
        }
        // 0xD1 (/n シフト 1) は register-direct のみ 2B。/0 ROL、/1 ROR、/4 SHL、/5 SHR、/7 SAR。
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
    run_mode_ex(
        env,
        entry,
        sys,
        limit,
        is64,
        polyisa_guest_x86::DEFAULT_FEATS,
        &polyisa_guest_x86::DEFAULT_PARAMS,
    )
}

/// `run_mode` に機能集合を渡す。`feats` は生成した `FEAT_*` のビット和で
/// `decode_model_ex` に渡る（ADR-0006、`--cpu` の配線）。
pub fn run_mode_ex(
    env: &mut BareEnv,
    entry: u32,
    sys: &mut impl TrapHandler,
    limit: u64,
    is64: bool,
    feats: u128,
    params: &polyisa_guest_x86::Params,
) -> Outcome {
    // 32 ビットゲストの実効アドレスは 32 ビットで折り返す。負のオフセットを含む
    // 加算が 4GiB を越えても未映射判定にならないよう、アクセス幅をここで絞る。
    let addr_mask = if is64 { u64::MAX } else { 0xffff_ffff };
    run_mode_go(
        env,
        entry,
        sys,
        limit,
        if is64 { 64 } else { 32 },
        addr_mask,
        feats,
        params,
    )
}

/// x32（ILP32）ABI の実行ループ。命令は x86-64 と同じ 64 ビットモードで
/// 動くが、ポインタは 32 ビットなので実効アドレスを 4GiB で折り返す。
pub fn run_mode_x32_ex(
    env: &mut BareEnv,
    entry: u32,
    sys: &mut impl TrapHandler,
    limit: u64,
    feats: u128,
    params: &polyisa_guest_x86::Params,
) -> Outcome {
    run_mode_go(env, entry, sys, limit, 64, 0xffff_ffff, feats, params)
}

/// `run_mode_ex`・`run_mode_x32_ex` の共有本体。`mode` は命令モード、
/// `addr_mask` は実効アドレスの折り返し幅。
#[allow(clippy::too_many_arguments)]
fn run_mode_go(
    env: &mut BareEnv,
    entry: u32,
    sys: &mut impl TrapHandler,
    limit: u64,
    mode: u8,
    addr_mask: u64,
    feats: u128,
    params: &polyisa_guest_x86::Params,
) -> Outcome {
    env.backend.set(polyisa_guest_x86::sem::eip_ref(), entry);
    env.backend.addr_mask = addr_mask;
    // 挙動パラメータをバックエンドの表に流し込む（意味論が `param` で読む）。
    polyisa_guest_x86::install_params(&mut env.backend, params);
    // 呼び出し前に wait4 で止まっていれば、子から再開する。
    let _ = sys.on_block(env);
    // 直近の eip を記録する（POLYISA_HIST でフェッチ失敗時に吐出す診断）。
    let mut hist = std::collections::VecDeque::<(u32, String)>::with_capacity(33);
    polyisa_engine::run::run(
        env,
        sys,
        limit,
        |env| u64::from(eip_of(env)),
        |env, sys| step_x86(env, sys, mode, feats, &mut hist),
    )
}

/// 16 ビット実モードの実行ループ。`eip` 状態は IP（16 ビット）、
/// セグメント基底はセレクタ<<4 で実モードの規則に従う。
pub fn run_m16(env: &mut BareEnv, entry: u32, sys: &mut impl TrapHandler, limit: u64) -> Outcome {
    // 既定は 8088 世代（SST 8088 の基準）。他世代は `run_m16_ex` に
    // モデルの機能・パラメータを渡す。
    run_m16_ex(
        env,
        entry,
        sys,
        limit,
        polyisa_guest_x86::model_feats("i8088"),
        &polyisa_guest_x86::model_params("i8088"),
    )
}

/// `run_m16` に機能集合を渡す（`--cpu` の配線）。
pub fn run_m16_ex(
    env: &mut BareEnv,
    entry: u32,
    sys: &mut impl TrapHandler,
    limit: u64,
    feats: u128,
    params: &polyisa_guest_x86::Params,
) -> Outcome {
    polyisa_guest_x86::install_params(&mut env.backend, params);
    env.backend.set(polyisa_guest_x86::sem::eip_ref(), entry);
    env.backend.addr_mask = match params.addr_wrap {
        polyisa_guest_x86::ADDR_WRAP_M20 => 0xF_FFFF,
        polyisa_guest_x86::ADDR_WRAP_M24 => 0xFF_FFFF,
        _ => u64::MAX,
    };
    let _ = sys.on_block(env);
    let mut hist = std::collections::VecDeque::<(u32, String)>::with_capacity(33);
    polyisa_engine::run::run(
        env,
        sys,
        limit,
        |env| u64::from(eip_of(env)),
        |env, sys| step_x86(env, sys, 16, feats, &mut hist),
    )
}

/// CPUID のリーフ表を機能名集合と識別情報から導出し、CPU 状態へ書き込む。
fn install_cpuid(
    env: &mut BareEnv,
    features: &std::collections::BTreeSet<String>,
    ident: &std::collections::BTreeMap<String, String>,
) {
    let tbl = polyisa_guest_x86::cpuid::derive(features, ident);
    for (i, regs) in tbl.iter().enumerate() {
        for (r, v) in regs.iter().enumerate() {
            env.backend.set(polyisa_guest_x86::sem::cpuid_ref(i, r), *v);
        }
    }
}

/// 1 命令ぶんのフェッチ・解読・意味論とトラップ境界の解決。
/// 継続なら `Ok(())`、退出なら退出理由を返す。
/// 命令長の判定（`fetch_len`）とオペランドの取り出し（`dispatch`）は
/// 手で書く。ISADL 側への乗せ換えは ADR-0018 で先送りした。
/// `step_x86` のフェッチ・接頭辞剥がし・長さ判定・`decode_model_ex` と
/// 接頭辞ゲートの結果。意味論に必要なものだけを運ぶ。
struct DecodedX86 {
    insn: Insn,
    word: u128,
    nbytes: u64,
    off: u64,
    rex: u8,
    has66: bool,
    has_f2: bool,
    rep: bool,
    has_fs: bool,
    has_gs: bool,
}

/// `pc` の命令をデコードする。接頭辞・長さ・モデルゲートの失敗は
/// `Outcome::Unimplemented`（`step_x86` と同じ報告）で返す。
/// `B: Backend` に依存しないので実行・記録の両方から呼べる。
// Ref: SPEC-ARM-ARM-A 相当の x86 側マニュアル Intel SDM.
#[allow(clippy::too_many_lines)]
fn decode_x86(
    mem: &polyisa_mem::AddressSpace,
    pc: u64,
    is64: bool,
    feats: u128,
    hist: &mut std::collections::VecDeque<(u32, String)>,
) -> Result<DecodedX86, Outcome> {
    let mut head = [0u8; 1];
    if mem.read(VirtAddr(pc), &mut head, acc_fetch()).is_err() {
        if std::env::var_os("POLYISA_HIST").is_some() {
            for (e, i) in hist.iter() {
                eprintln!("hist {e:#x} {i}");
            }
        }
        return Err(Outcome::Unimplemented { pc, word: 0 });
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
    let mut has_gs = false;
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
        } else if head[0] == 0x65 && !has_gs {
            // GS 上書き。i386 musl は GS を TLS に使う。
            has_gs = true;
        } else if matches!(head[0], 0x2E | 0x3E | 0x26 | 0x36) {
            // セグメント上書き。4GB 未満では無視してよい。
        } else {
            break;
        }
        off += 1;
        if mem
            .read(VirtAddr(pc + off), &mut head, acc_fetch())
            .is_err()
        {
            return Err(Outcome::Unimplemented {
                pc,
                word: head[0] as u128,
            });
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
            | 0x86
            | 0x8E
            | 0xFE
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
            | 0x8F
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
        if mem
            .read(VirtAddr(pc + off + 1), &mut peek, acc_fetch())
            .is_err()
        {
            return Err(Outcome::Unimplemented {
                pc,
                word: head[0] as u128,
            });
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
            | 0x69
            | 0x6B
            | 0x63
            | 0x01
            | 0x03
            | 0x09
            | 0x21
            | 0x0B
            | 0x39
            | 0x3B
            | 0x2B
            | 0x33
            | 0x23
            | 0x13
            | 0x1B
            | 0x80
            | 0x28
            | 0x30
            | 0xF6
            | 0xF7
            | 0xFF
            | 0xDB
            | 0xDD
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
                        | 0x51
                        | 0x5A
                        | 0x2E
                        | 0x2F
                        | 0x2C
                        | 0x54
                        | 0x5C
                        | 0x59
                        | 0x5D
                        | 0x5E
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
                        | 0xBF
                        | 0xAF
                        | 0xBC
                        | 0xBD
                        | 0xB1
                        | 0xA5
                        | 0xAD
                        | 0xAC
                        | 0xA4
                        | 0xA3
                        | 0xAB
                )
            ) || matches!(second, Some(0x40..=0x4F))
                || matches!(second, Some(0x90..=0x9F))))
    {
        let mut modrm = [0u8; 1];
        if mem
            .read(VirtAddr(pc + off + 2), &mut modrm, acc_fetch())
            .is_err()
        {
            return Err(Outcome::Unimplemented {
                pc,
                word: head[0] as u128,
            });
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
                    | 0xBF
                    | 0xAF
                    | 0xBC
                    | 0xBD
                    | 0xB1
                    | 0x58
                    | 0x59
                    | 0x2A
                    | 0x2C
                    | 0xEB
                    | 0xBA
            )
        )
        || matches!(second, Some(0x40..=0x4F))
            && matches!(third, Some(m) if m & 7 == 4 && m >> 6 != 3)
    {
        let mut sib = [0u8; 1];
        if mem
            .read(VirtAddr(pc + off + 3), &mut sib, acc_fetch())
            .is_err()
        {
            return Err(Outcome::Unimplemented {
                pc,
                word: head[0] as u128,
            });
        }
        Some(sib[0])
    } else {
        None
    };
    let rex_w = rex & 8 != 0;
    let Some(base) = fetch_len(head[0], second, third, fourth, has66, rex_w, is64) else {
        return Err(Outcome::Unimplemented {
            pc,
            word: head[0] as u128,
        });
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
                | 0xFE
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
                | 0x0A
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
                | 0x8F
                | 0xC7
                | 0x83
                | 0x81
                | 0x63
                | 0x69
                | 0x6B
                | 0x98
                | 0x99
                | 0x0F
                | 0xA0..=0xA3
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
        return Err(Outcome::Unimplemented {
            pc,
            word: head[0] as u128,
        });
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
        if mem
            .read(VirtAddr(pc + off + i), &mut b, acc_fetch())
            .is_err()
        {
            return Err(Outcome::Unimplemented {
                pc,
                word: head[0] as u128,
            });
        }
        bytes[i as usize] = b[0];
    }
    // ISADL の word 組立（opcode 上位詰め）に合わせる。
    let mut word: u128 = 0;
    for i in 0..base {
        word = (word << 8) | bytes[i as usize] as u128;
    }
    let len_bits = (base * 8) as u32;
    let Some(insn) = decode_model_ex(word, len_bits, true, feats) else {
        return Err(Outcome::Unimplemented { pc, word });
    };
    if std::env::var_os("POLYISA_HIST").is_some()
        && let Some(h) = hist.back_mut()
    {
        *h = (pc as u32, format!("{insn:?}"));
    }
    // 0x66 接頭辞は XMM/NOP/16bit-RIP 系でのみ有効。それ以外は未対応。
    // 32ビットでの 0x66 は operand-size override（16ビット動作）。
    // 16ビット意味論を持つ命令だけを通す。
    if has66
        && !is64
        && !matches!(
            insn,
            Insn::Nop
                | Insn::Nopl
                | Insn::TestRm32
                | Insn::TestRm16Imm
                | Insn::TestM16ImmMemnd
                | Insn::TestM16ImmMem8
                | Insn::TestM16ImmRip
                | Insn::TestAxImm16
                | Insn::AndAxImm16
                | Insn::CmpAxImm16
                | Insn::OrAxImm16
                | Insn::AddRm16Imm
                | Insn::AndRm16Imm
                | Insn::AndRm16ImmMemnd
                | Insn::CmpRm16Imm
                | Insn::CmpRm16ImmMem8
                | Insn::MovRm16ImmMemnd
                | Insn::MovRm16ImmMem8
                | Insn::MovRm16ImmSibd
                | Insn::MovRm16ImmSibd32
                | Insn::MovRm16ImmSib
                | Insn::MovRm16ImmRip
                | Insn::MovRm16ImmM32
                | Insn::MovRm16ImmDisp32
                | Insn::MovEaxSib
                | Insn::MovEaxSibd
                | Insn::MovEaxSibd32
                | Insn::MovSibEax
                | Insn::MovSibdEax
                | Insn::MovSibd32Eax
                | Insn::MovEaxMemnd
                | Insn::MovEaxMem8
                | Insn::MovEaxMem32
                | Insn::MovMemndEax
                | Insn::MovMemEax32
                | Insn::MovMemEax8
                | Insn::MovAbsEax
                | Insn::MovEaxAbs
                | Insn::CmpRm32
                | Insn::CmpRmMemnd
                | Insn::CmpRmImm8
                | Insn::CmpRmImm8Memnd
                | Insn::CmpRmImm8Rip
                | Insn::CmpRmImm8Sib
                | Insn::CmpRmImm8Sibd
                | Insn::CmpRmImm8Sibd32
                | Insn::CmpRmImm8m8
                | Insn::CmpM32R32Sib
                | Insn::AddRMemnd
                | Insn::AddRMem8
                | Insn::AddM32R32Sibd32
                | Insn::SubM32R32Mem8
                | Insn::SubRmImm8Sibd
                | Insn::AndRSibd32
                | Insn::AndRmImm8Sibd
                | Insn::XorRm32
                | Insn::RolRm32Imm8
                | Insn::ShrRm32Imm8
                | Insn::IncRmSibd32
                | Insn::IncRmMem32
        )
    {
        return Err(Outcome::Unimplemented { pc, word });
    }
    if has66
        && is64
        && !matches!(
            insn,
            Insn::Nop
                | Insn::Nopl
                | Insn::TestRm32
                | Insn::TestM16ImmMemnd
                | Insn::TestRm16Imm
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
                | Insn::MovSibd32Eax
                | Insn::IncRmSibd32
                | Insn::IncRmMem32
                | Insn::AddM32R32Sibd32
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
                | Insn::MovRm16ImmSibd32
                | Insn::MovRm16ImmDisp32
                | Insn::MovRm16ImmSib
                | Insn::MovRm16ImmRip
                | Insn::AndAxImm16
                | Insn::TestAxImm16
                | Insn::ShrRm32Imm8
                | Insn::CmpAxImm16
                | Insn::OrAxImm16
                | Insn::AddRm16Imm
                | Insn::AndRm16Imm
                | Insn::AndRm16ImmMemnd
                // AND r16, [base+index*scale+disp32] (66 23 /r SIB mod=10)。gunzip 0x48a957。
                | Insn::AndRSibd32
                | Insn::CmpRm16Imm
                | Insn::CmpRm16ImmMem8
                // ROL r16,imm8 (66 C1 /0)。httpd 0x4be767 の rol $8, %bp。
                | Insn::RolRm32Imm8
                // CMP r/m16, r16 (66 39 /r mod=11) は CmpRm32 を共用する.
                | Insn::CmpRm32
                // SUB m16, r16 (66 29 /r mod=01)。lpq 0x4c3385 の subw %bx, 0x52(%rbp)。
                | Insn::SubM32R32Mem8
                // XOR r16, r16 (66 31 /r mod=11)。pgrep 0x44b572 の xor %r13w, %r13w。
                | Insn::XorRm32
                | Insn::CmpRmImm8Rip
                // MOV [base+disp32],r16 (66 89 mod=10) は MovMemEax32 を共用する.
                | Insn::MovMemEax32
                // MOV [base+disp8],r16 (66 89 mod=01) は MovMemEax8 を共用する.
                | Insn::MovMemEax8
                // ADD m16,imm8 SIB (66 83 /0 mod=00).
                | Insn::AddM16ImmSib
                // CMP m16,imm8 SIB (66 83 /7 mod=00).
                | Insn::CmpRmImm8Sib
                // CMP r16,imm8 (66 83 /7 mod=11)。iostat 0x4bea1d の cmp $-1, %ax。
                | Insn::CmpRmImm8
                // CMP m16,imm8 SIB+disp32 (66 83 /7 mod=10).
                | Insn::CmpRmImm8Sibd32
                // CMP m16,imm8 SIB+disp8 (66 83 /7 mod=01)。rdev 0x4b3703 の cmpw $0x2e, 0x14(%r12)。
                | Insn::CmpRmImm8Sibd
                // CMP m16, r16 [base] (66 39 /r mod=00).
                | Insn::CmpRmMemnd
                // CMP m16, r16 SIB (66 39 /r mod=00).
                | Insn::CmpM32R32Sib
                // MOV r16, [base] (66 8B mod=00).
                | Insn::MovEaxMemnd
                // MOV r16, [base+disp8] (66 8B mod=01)。pgrep 0x44b629 の movw 0x12(%r14), %dx。
                | Insn::MovEaxMem8
                // CMP m16,imm8 [base] (66 83 /7 mod=00)。ping 0x4be1f1 の cmpw $2, (%rdi)。
                | Insn::CmpRmImm8Memnd
                // CMP m16,imm8 [base+disp8] (66 83 /7 mod=01)。ping 0x42e7b3 の cmpw $0xa, 0x4(%rbx)。
                | Insn::CmpRmImm8m8
                // ADD r16, [base] (66 03 /r mod=00).
                | Insn::AddRMemnd
                // AND m16,imm8 SIB+disp8 (66 83 /4 mod=01).
                | Insn::AndRmImm8Sibd
                // SUB m16,imm8 SIB+disp8 (66 83 /5 mod=01).
                | Insn::SubRmImm8Sibd
        )
    {
        return Err(Outcome::Unimplemented { pc, word });
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
                | Insn::MovRm16ImmSibd32
                | Insn::MovRm16ImmDisp32
                | Insn::MovRm16ImmSib
                | Insn::MovRm16ImmRip
                | Insn::MovntdqStoreMemnd
                | Insn::MovntdqStoreMem8
                | Insn::MovdqaLoadRip
        )
    {
        return Err(Outcome::Unimplemented { pc, word });
    }
    // PSHUFD/PSHUFLW は 66/F2 のいずれかが必須。
    if matches!(insn, Insn::Pshufd) && !has66 && !has_f2 {
        return Err(Outcome::Unimplemented { pc, word });
    }
    // CVTSI2SD (F2 0F 2A) と SUBPS (0F 2A) は符号化を共用する。F2 なしは未対応.
    // CVTSD2SS/CVTSS2SD (0F 5A mod=11) は F2/F3 のいずれかが必須。
    if matches!(
        insn,
        Insn::Cvtsi2sdM32Mem8
            | Insn::Cvtsi2sdM32Sibd
            | Insn::Cvtsi2sdM32Sib
            | Insn::DivsdXmmM64Rip
            | Insn::Divsd
            | Insn::Minsd
            | Insn::Sqrtsd
    ) && !has_f2
    {
        return Err(Outcome::Unimplemented { pc, word });
    }
    if matches!(insn, Insn::Cvtsd2ss) && !has_f2 && !rep {
        return Err(Outcome::Unimplemented { pc, word });
    }
    // 0F 5A mod=00 は F3 なら CVTSS2SD m32、F2 なら CVTSD2SS m64。接頭辞なしは CVTPS2PD。
    if matches!(insn, Insn::Cvtss2sdM32) && has_f2 == rep {
        return Err(Outcome::Unimplemented { pc, word });
    }
    let _ = rex;
    Ok(DecodedX86 {
        insn,
        word,
        nbytes,
        off,
        rex,
        has66,
        has_f2,
        rep,
        has_fs,
        has_gs,
    })
}

// ---- オペコード表（map）経路 ----

/// シフト群の操作。8086/8088 では /6 が undocumented な SETMO（全ビット
/// 1 を書き込む）になる。80186 以降は SHL の別名。
fn grp2_op(d: &polyisa_guest_x86::MapDec, mode: u8, feats: u128) -> polyisa_guest_x86::sem_ea::Sh {
    use polyisa_guest_x86::sem_ea::Sh;
    if mode == 16 && feats & polyisa_guest_x86::FEAT_I186 == 0 && (d.modrm >> 3) & 7 == 6 {
        Sh::Setmo
    } else {
        Sh::Shl
    }
}

/// IN/OUT の DX ポート番号（下位 16 ビット）。
fn dx_port<B: Backend>(b: &mut B) -> B::V<polyisa_sem::W64> {
    use polyisa_sem::{W32, W64};
    let dx: B::V<W32> = b.get(polyisa_guest_x86::sem::Gpr(2).state());
    let m = b.konst::<W32>(0xFFFF);
    let d16 = b.and::<W32>(dx, m);
    b.zext::<W32, W64>(d16)
}

/// map デコード結果を実行する。`Ok(true)` は実行済み、`Ok(false)` は
/// 未移行で、呼び出し側が旧デコード経路へフォールバックする。
// Ref: SPEC-X86-INTEL-SDM (v093).
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
fn dispatch_map<B: Backend>(
    b: &mut B,
    d: &polyisa_guest_x86::MapDec,
    eip: u32,
    next_rip: u64,
    seg: u64,
    seg_ss: bool,
    sseg: u64,
    es: u64,
    mode: u8,
    feats: u128,
) -> Result<bool, B::Exit> {
    let m64 = mode == 64;
    let sa = mode;
    if mode == 16 && (0xD8..=0xDF).contains(&d.opcode) {
        // 80286 以降で FPU がなければ ESC は #NM（実モードは IVT 7 へ）。
        if feats & polyisa_guest_x86::FEAT_I286 != 0 && feats & polyisa_guest_x86::FEAT_FPU == 0 {
            return sem_ea::int_real(b, eip, 0, 7, sa, sseg).map(|_| true);
        }
        if feats & polyisa_guest_x86::FEAT_I286 == 0 {
            // 8088 に 8087 は付いていない。ESC は建築状態を変えずに
            // 次の命令へ進む（バス上の ModRM 評価・ダミー読みは
            // 建築状態に現れない）。
            return Ok(true);
        }
        // i286+FPU は落下して FPU 意味論を実行する。成功時に
        // 80287 へのバス転送プロトコルを emit する（末尾の npx 参照）。
    }
    // 80286+80287 の ESC は実行成功時にポート F8/FC へ命令語と文脈
    // を転送する。オペランドの限界例外は転送に先行する（SST 80286
    // 実測でフォルト時はポートが無条件に書かれない）ので emit は
    // 実行後に行う。
    let npx = mode == 16
        && (0xD8..=0xDF).contains(&d.opcode)
        && feats & polyisa_guest_x86::FEAT_I286 != 0
        && feats & polyisa_guest_x86::FEAT_FPU != 0;
    use polyisa_guest_x86::decode::{self, Hw, Rm};
    use polyisa_guest_x86::sem::{Gpr, eflags_ref};
    use polyisa_guest_x86::sem_ea::{self, Alu, Sh, ShiftCnt, Src};
    use polyisa_sem::{W8, W16, W32, W64};
    const EAX: Gpr = Gpr(0);
    let w = d.osize;
    // VEX の GPR 演算（BMI 系）の被演算子幅。64 ビットモードでは
    // VEX.W（`d.rex` bit3 に畳み込み済み）で 32/64、他モードは常に 32。
    // pp=66 で `d.p66` が立つと osize が 16 になるので osize は使えない。
    let vw = if d.rex & 8 != 0 { 64 } else { 32 };
    // PUSH/POP/CALL/RET は 64ビットモードで既定 64（66 で 16）。m64 以外は
    // osize と同じ扱い。
    let sw = if m64 && !d.p66 { 64 } else { w };
    let reg = decode::reg(d);
    // Ea 被演算子（ModRM が無い命令は modrm=0 で mem 誤認するので
    // has_modrm で守る）。
    let ea = if d.has_modrm {
        decode::rm_of(b, d, next_rip, seg, seg_ss, mode == 16)
    } else {
        Rm::Reg(Gpr(0))
    };
    // Iz は osize 64 で imm32 の符号拡張。
    let iz = if w == 64 {
        d.imm as u32 as i32 as i64 as u64
    } else {
        d.imm
    };
    let ib8 = d.imm as u8 as i8 as i64 as u64;
    // Jcc（0F 8x 系）の分岐基準。386 では `66 0F 8x rel32` でも
    // 接頭辞込みの全命令長が基準になる（SST 80386 実測）。
    let jz_len = u32::from(d.len);
    // 被演算子を常に 64 ビット値として読む補助。
    fn rd_any<B: Backend>(
        b: &mut B,
        w: u8,
        rm: &Rm<B::V<W64>>,
        d: &polyisa_guest_x86::MapDec,
    ) -> Result<B::V<W64>, B::Exit> {
        match w {
            8 => {
                let v = decode::rd::<B, W8>(b, rm, d)?;
                Ok(b.zext::<W8, W64>(v))
            }
            16 => {
                let v = decode::rd::<B, W16>(b, rm, d)?;
                Ok(b.zext::<W16, W64>(v))
            }
            64 => decode::rd::<B, W64>(b, rm, d),
            _ => {
                let v = decode::rd::<B, W32>(b, rm, d)?;
                Ok(b.zext::<W32, W64>(v))
            }
        }
    }
    fn wr_any<B: Backend>(
        b: &mut B,
        w: u8,
        rm: &Rm<B::V<W64>>,
        d: &polyisa_guest_x86::MapDec,
        v: B::V<W64>,
    ) -> Result<(), B::Exit> {
        match w {
            8 => {
                let v: B::V<W8> = b.trunc::<W64, W8>(v);
                decode::wr::<B, W8>(b, rm, d, v)
            }
            16 => {
                let v: B::V<W16> = b.trunc::<W64, W16>(v);
                decode::wr::<B, W16>(b, rm, d, v)
            }
            64 => decode::wr::<B, W64>(b, rm, d, v),
            _ => {
                let v: B::V<W32> = b.trunc::<W64, W32>(v);
                decode::wr::<B, W32>(b, rm, d, v)
            }
        }
    }
    fn gr64<B: Backend>(b: &mut B, g: Gpr, w: u8) -> B::V<W64> {
        match w {
            16 => {
                let v: B::V<W32> = b.get(g.state());
                let m = b.konst::<W32>(0xffff);
                let lo = b.and::<W32>(v, m);
                b.zext::<W32, W64>(lo)
            }
            64 => polyisa_guest_x86::sem::read64(b, g),
            _ => {
                let v: B::V<W32> = b.get(g.state());
                b.zext::<W32, W64>(v)
            }
        }
    }
    fn gr_sext64<B: Backend>(b: &mut B, g: Gpr, w: u8) -> B::V<W64> {
        match w {
            16 => {
                let v = decode::grd16(b, g);
                b.sext::<W16, W64>(v)
            }
            64 => decode::grd64(b, g),
            _ => {
                let v = decode::grd32(b, g);
                b.sext::<W32, W64>(v)
            }
        }
    }
    fn put64<B: Backend>(b: &mut B, g: Gpr, w: u8, v: B::V<W64>, d: &polyisa_guest_x86::MapDec) {
        match w {
            16 => {
                let v16: B::V<W16> = b.trunc::<W64, W16>(v);
                W16::put(b, g, d, v16);
            }
            64 => polyisa_guest_x86::sem::write64(b, g, v),
            _ => {
                let v32: B::V<W32> = b.trunc::<W64, W32>(v);
                W32::put(b, g, d, v32);
            }
        }
    }
    let _ = m64;
    let r: Result<(), B::Exit> = match d.insn {
        Insn::AddEbGb => sem_ea::alu(b, Alu::Add, 8, &ea, d, Src::Reg(reg)),
        Insn::AddEvGv => sem_ea::alu(b, Alu::Add, w, &ea, d, Src::Reg(reg)),
        Insn::AddGbEb => sem_ea::alu(b, Alu::Add, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::AddGvEv => sem_ea::alu(b, Alu::Add, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::AddAlIb => sem_ea::alu(b, Alu::Add, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::AddEaxIz => sem_ea::alu(b, Alu::Add, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::AddEbIb => sem_ea::alu(b, Alu::Add, 8, &ea, d, Src::Imm(d.imm)),
        Insn::AddEvIz => sem_ea::alu(b, Alu::Add, w, &ea, d, Src::Imm(iz)),
        Insn::AddEvIb => sem_ea::alu(b, Alu::Add, w, &ea, d, Src::Imm(ib8)),
        Insn::OrEbGb => sem_ea::alu(b, Alu::Or, 8, &ea, d, Src::Reg(reg)),
        Insn::OrEvGv => sem_ea::alu(b, Alu::Or, w, &ea, d, Src::Reg(reg)),
        Insn::OrGbEb => sem_ea::alu(b, Alu::Or, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::OrGvEv => sem_ea::alu(b, Alu::Or, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::OrAlIb => sem_ea::alu(b, Alu::Or, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::OrEaxIz => sem_ea::alu(b, Alu::Or, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::OrEbIb => sem_ea::alu(b, Alu::Or, 8, &ea, d, Src::Imm(d.imm)),
        Insn::OrEvIz => sem_ea::alu(b, Alu::Or, w, &ea, d, Src::Imm(iz)),
        Insn::OrEvIb => sem_ea::alu(b, Alu::Or, w, &ea, d, Src::Imm(ib8)),
        Insn::AdcEbGb => sem_ea::alu(b, Alu::Adc, 8, &ea, d, Src::Reg(reg)),
        Insn::AdcEvGv => sem_ea::alu(b, Alu::Adc, w, &ea, d, Src::Reg(reg)),
        Insn::AdcGbEb => sem_ea::alu(b, Alu::Adc, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::AdcGvEv => sem_ea::alu(b, Alu::Adc, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::AdcAlIb => sem_ea::alu(b, Alu::Adc, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::AdcEaxIz => sem_ea::alu(b, Alu::Adc, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::AdcEbIb => sem_ea::alu(b, Alu::Adc, 8, &ea, d, Src::Imm(d.imm)),
        Insn::AdcEvIz => sem_ea::alu(b, Alu::Adc, w, &ea, d, Src::Imm(iz)),
        Insn::AdcEvIb => sem_ea::alu(b, Alu::Adc, w, &ea, d, Src::Imm(ib8)),
        Insn::SbbEbGb => sem_ea::alu(b, Alu::Sbb, 8, &ea, d, Src::Reg(reg)),
        Insn::SbbEvGv => sem_ea::alu(b, Alu::Sbb, w, &ea, d, Src::Reg(reg)),
        Insn::SbbGbEb => sem_ea::alu(b, Alu::Sbb, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::SbbGvEv => sem_ea::alu(b, Alu::Sbb, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::SbbAlIb => sem_ea::alu(b, Alu::Sbb, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::SbbEaxIz => sem_ea::alu(b, Alu::Sbb, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::SbbEbIb => sem_ea::alu(b, Alu::Sbb, 8, &ea, d, Src::Imm(d.imm)),
        Insn::SbbEvIz => sem_ea::alu(b, Alu::Sbb, w, &ea, d, Src::Imm(iz)),
        Insn::SbbEvIb => sem_ea::alu(b, Alu::Sbb, w, &ea, d, Src::Imm(ib8)),
        Insn::AndEbGb => sem_ea::alu(b, Alu::And, 8, &ea, d, Src::Reg(reg)),
        Insn::AndEvGv => sem_ea::alu(b, Alu::And, w, &ea, d, Src::Reg(reg)),
        Insn::AndGbEb => sem_ea::alu(b, Alu::And, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::AndGvEv => sem_ea::alu(b, Alu::And, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::AndAlIb => sem_ea::alu(b, Alu::And, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::AndEaxIz => sem_ea::alu(b, Alu::And, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::AndEbIb => sem_ea::alu(b, Alu::And, 8, &ea, d, Src::Imm(d.imm)),
        Insn::AndEvIz => sem_ea::alu(b, Alu::And, w, &ea, d, Src::Imm(iz)),
        Insn::AndEvIb => sem_ea::alu(b, Alu::And, w, &ea, d, Src::Imm(ib8)),
        Insn::SubEbGb => sem_ea::alu(b, Alu::Sub, 8, &ea, d, Src::Reg(reg)),
        Insn::SubEvGv => sem_ea::alu(b, Alu::Sub, w, &ea, d, Src::Reg(reg)),
        Insn::SubGbEb => sem_ea::alu(b, Alu::Sub, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::SubGvEv => sem_ea::alu(b, Alu::Sub, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::SubAlIb => sem_ea::alu(b, Alu::Sub, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::SubEaxIz => sem_ea::alu(b, Alu::Sub, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::SubEbIb => sem_ea::alu(b, Alu::Sub, 8, &ea, d, Src::Imm(d.imm)),
        Insn::SubEvIz => sem_ea::alu(b, Alu::Sub, w, &ea, d, Src::Imm(iz)),
        Insn::SubEvIb => sem_ea::alu(b, Alu::Sub, w, &ea, d, Src::Imm(ib8)),
        Insn::XorEbGb => sem_ea::alu(b, Alu::Xor, 8, &ea, d, Src::Reg(reg)),
        Insn::XorEvGv => sem_ea::alu(b, Alu::Xor, w, &ea, d, Src::Reg(reg)),
        Insn::XorGbEb => sem_ea::alu(b, Alu::Xor, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::XorGvEv => sem_ea::alu(b, Alu::Xor, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::XorAlIb => sem_ea::alu(b, Alu::Xor, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::XorEaxIz => sem_ea::alu(b, Alu::Xor, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::XorEbIb => sem_ea::alu(b, Alu::Xor, 8, &ea, d, Src::Imm(d.imm)),
        Insn::XorEvIz => sem_ea::alu(b, Alu::Xor, w, &ea, d, Src::Imm(iz)),
        Insn::XorEvIb => sem_ea::alu(b, Alu::Xor, w, &ea, d, Src::Imm(ib8)),
        Insn::CcmpsccEbGb => sem_ea::ccmp(b, 8, &ea, d, Src::Reg(reg)),
        Insn::CcmpsccEvGv => sem_ea::ccmp(b, w, &ea, d, Src::Reg(reg)),
        Insn::CcmpsccGbEb => sem_ea::ccmp(b, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::CcmpsccGvEv => sem_ea::ccmp(b, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::CcmpsccEbIb => sem_ea::ccmp(b, 8, &ea, d, Src::Imm(d.imm)),
        Insn::CcmpsccEvIz => sem_ea::ccmp(b, w, &ea, d, Src::Imm(iz)),
        Insn::CcmpsccEvIb => sem_ea::ccmp(b, w, &ea, d, Src::Imm(ib8)),
        Insn::CtestsccEbGb => sem_ea::ctest(b, 8, &ea, d, Src::Reg(reg)),
        Insn::CtestsccEvGv => sem_ea::ctest(b, w, &ea, d, Src::Reg(reg)),
        Insn::CtestsccEbI => sem_ea::ctest(b, 8, &ea, d, Src::Imm(d.imm)),
        Insn::CtestsccEvI => sem_ea::ctest(b, w, &ea, d, Src::Imm(iz)),
        Insn::CmpEbGb => sem_ea::alu(b, Alu::Cmp, 8, &ea, d, Src::Reg(reg)),
        Insn::CmpEvGv => sem_ea::alu(b, Alu::Cmp, w, &ea, d, Src::Reg(reg)),
        Insn::CmpGbEb => sem_ea::alu(b, Alu::Cmp, 8, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::CmpGvEv => sem_ea::alu(b, Alu::Cmp, w, &Rm::Reg(reg), d, Src::Ea(&ea)),
        Insn::CmpAlIb => sem_ea::alu(b, Alu::Cmp, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::CmpEaxIz => sem_ea::alu(b, Alu::Cmp, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::CmpEbIb => sem_ea::alu(b, Alu::Cmp, 8, &ea, d, Src::Imm(d.imm)),
        Insn::CmpEvIz => sem_ea::alu(b, Alu::Cmp, w, &ea, d, Src::Imm(iz)),
        Insn::CmpEvIb => sem_ea::alu(b, Alu::Cmp, w, &ea, d, Src::Imm(ib8)),
        Insn::TestEbGb => sem_ea::test(b, 8, &ea, d, Src::Reg(reg)),
        Insn::TestEvGv => sem_ea::test(b, w, &ea, d, Src::Reg(reg)),
        Insn::TestAlIb => sem_ea::test(b, 8, &Rm::Reg(EAX), d, Src::Imm(d.imm)),
        Insn::TestEaxIz => sem_ea::test(b, w, &Rm::Reg(EAX), d, Src::Imm(iz)),
        Insn::TestEbI => sem_ea::test(b, 8, &ea, d, Src::Imm(d.imm)),
        Insn::TestEvI => sem_ea::test(b, w, &ea, d, Src::Imm(iz)),
        Insn::XchgEbGb => sem_ea::xchg(b, 8, &ea, d, reg),
        Insn::XchgEvGv => sem_ea::xchg(b, w, &ea, d, reg),
        Insn::XchgRvEax => {
            if decode::op_reg(d).0 == 0 && d.rex & 1 == 0 {
                sem_ea::nop(b)
            } else {
                let e = Rm::Reg(EAX);
                sem_ea::xchg(b, w, &e, d, decode::op_reg(d))
            }
        }
        Insn::MovEbGb => sem_ea::mov_e(b, 8, &ea, d, Src::Reg(reg)),
        Insn::MovEvGv | Insn::MovntiEvGv => sem_ea::mov_e(b, w, &ea, d, Src::Reg(reg)),
        Insn::MovGbEb | Insn::MovrsGbEb => sem_ea::mov_r(b, 8, reg, &ea, d),
        Insn::MovGvEv | Insn::MovrsGvEv => sem_ea::mov_r(b, w, reg, &ea, d),
        Insn::MovEbIb => sem_ea::mov_e(b, 8, &ea, d, Src::Imm(d.imm)),
        Insn::MovEvIz => sem_ea::mov_e(b, w, &ea, d, Src::Imm(iz)),
        Insn::MovRbIb => sem_ea::mov_e(b, 8, &Rm::Reg(decode::op_reg(d)), d, Src::Imm(d.imm)),
        Insn::MovRvIv => sem_ea::mov_e(b, w, &Rm::Reg(decode::op_reg(d)), d, Src::Imm(d.imm)),
        Insn::LeaGvM => sem_ea::lea(b, w, reg, &ea, d.asize, seg, d),
        Insn::MovzxGvEb => sem_ea::movzx(b, w, 8, reg, &ea, d, false),
        Insn::MovzxGvEw => sem_ea::movzx(b, w, 16, reg, &ea, d, false),
        Insn::MovsxGvEb => sem_ea::movzx(b, w, 8, reg, &ea, d, true),
        Insn::MovsxGvEw => sem_ea::movzx(b, w, 16, reg, &ea, d, true),
        Insn::MovsxdGvEd => sem_ea::movzx(b, w, 32, reg, &ea, d, true),
        Insn::IncEb => sem_ea::incdec(b, true, 8, &ea, d),
        Insn::DecEb => sem_ea::incdec(b, false, 8, &ea, d),
        Insn::IncEv => sem_ea::incdec(b, true, w, &ea, d),
        Insn::DecEv => sem_ea::incdec(b, false, w, &ea, d),
        Insn::NotEb => sem_ea::not(b, 8, &ea, d),
        Insn::NotEv => sem_ea::not(b, w, &ea, d),
        Insn::NegEb => sem_ea::neg(b, 8, &ea, d),
        Insn::NegEv => sem_ea::neg(b, w, &ea, d),
        Insn::RolEbIb => sem_ea::shift(
            b,
            Sh::Rol,
            8,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RolEvIb => sem_ea::shift(
            b,
            Sh::Rol,
            w,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RolEb1 => sem_ea::shift(b, Sh::Rol, 8, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RolEv1 => sem_ea::shift(b, Sh::Rol, w, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RolEbCl => sem_ea::shift(b, Sh::Rol, 8, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::RolEvCl => sem_ea::shift(b, Sh::Rol, w, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::RorEbIb => sem_ea::shift(
            b,
            Sh::Ror,
            8,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RorEvIb => sem_ea::shift(
            b,
            Sh::Ror,
            w,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RorEb1 => sem_ea::shift(b, Sh::Ror, 8, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RorEv1 => sem_ea::shift(b, Sh::Ror, w, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RorEbCl => sem_ea::shift(b, Sh::Ror, 8, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::RorEvCl => sem_ea::shift(b, Sh::Ror, w, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::RclEbIb => sem_ea::shift(
            b,
            Sh::Rcl,
            8,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RclEvIb => sem_ea::shift(
            b,
            Sh::Rcl,
            w,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RclEb1 => sem_ea::shift(b, Sh::Rcl, 8, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RclEv1 => sem_ea::shift(b, Sh::Rcl, w, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RclEbCl => sem_ea::shift(b, Sh::Rcl, 8, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::RclEvCl => sem_ea::shift(b, Sh::Rcl, w, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::RcrEbIb => sem_ea::shift(
            b,
            Sh::Rcr,
            8,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RcrEvIb => sem_ea::shift(
            b,
            Sh::Rcr,
            w,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::RcrEb1 => sem_ea::shift(b, Sh::Rcr, 8, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RcrEv1 => sem_ea::shift(b, Sh::Rcr, w, &ea, d, ShiftCnt::One, mode == 16),
        Insn::RcrEbCl => sem_ea::shift(b, Sh::Rcr, 8, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::RcrEvCl => sem_ea::shift(b, Sh::Rcr, w, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::ShlEbIb => sem_ea::shift(
            b,
            grp2_op(d, mode, feats),
            8,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::ShlEvIb => sem_ea::shift(
            b,
            grp2_op(d, mode, feats),
            w,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::ShlEb1 => sem_ea::shift(
            b,
            grp2_op(d, mode, feats),
            8,
            &ea,
            d,
            ShiftCnt::One,
            mode == 16,
        ),
        Insn::ShlEv1 => sem_ea::shift(
            b,
            grp2_op(d, mode, feats),
            w,
            &ea,
            d,
            ShiftCnt::One,
            mode == 16,
        ),
        Insn::ShlEbCl => sem_ea::shift(
            b,
            grp2_op(d, mode, feats),
            8,
            &ea,
            d,
            ShiftCnt::Cl,
            mode == 16,
        ),
        Insn::ShlEvCl => sem_ea::shift(
            b,
            grp2_op(d, mode, feats),
            w,
            &ea,
            d,
            ShiftCnt::Cl,
            mode == 16,
        ),
        Insn::ShrEbIb => sem_ea::shift(
            b,
            Sh::Shr,
            8,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::ShrEvIb => sem_ea::shift(
            b,
            Sh::Shr,
            w,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::ShrEb1 => sem_ea::shift(b, Sh::Shr, 8, &ea, d, ShiftCnt::One, mode == 16),
        Insn::ShrEv1 => sem_ea::shift(b, Sh::Shr, w, &ea, d, ShiftCnt::One, mode == 16),
        Insn::ShrEbCl => sem_ea::shift(b, Sh::Shr, 8, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::ShrEvCl => sem_ea::shift(b, Sh::Shr, w, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::SarEbIb => sem_ea::shift(
            b,
            Sh::Sar,
            8,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::SarEvIb => sem_ea::shift(
            b,
            Sh::Sar,
            w,
            &ea,
            d,
            ShiftCnt::Imm(d.imm as u32),
            mode == 16,
        ),
        Insn::SarEb1 => sem_ea::shift(b, Sh::Sar, 8, &ea, d, ShiftCnt::One, mode == 16),
        Insn::SarEv1 => sem_ea::shift(b, Sh::Sar, w, &ea, d, ShiftCnt::One, mode == 16),
        Insn::SarEbCl => sem_ea::shift(b, Sh::Sar, 8, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::SarEvCl => sem_ea::shift(b, Sh::Sar, w, &ea, d, ShiftCnt::Cl, mode == 16),
        Insn::PushRv => {
            let r = decode::op_reg(d);
            let mut v = gr64(b, r, sw);
            // `push_sp` = post（8086/8088）ならデクリメント後の SP を積む。
            if b.param::<polyisa_guest_x86::PushSpParam>() == polyisa_guest_x86::PUSH_SP_POST
                && r.0 == 4
            {
                let sz = b.konst::<W64>(u64::from(sw / 8));
                v = b.sub::<W64>(v, sz);
            }
            sem_ea::push_v(b, sw, v, sa, sseg)
        }
        Insn::PopRv => {
            let v = sem_ea::pop_v(b, sw, sa, sseg)?;
            put64(b, decode::op_reg(d), sw, v, d);
            Ok(())
        }
        Insn::PushIz => {
            let v = b.konst::<W64>(iz);
            sem_ea::push_v(b, sw, v, sa, sseg)
        }
        Insn::PushIb => {
            let v = b.konst::<W64>(ib8);
            sem_ea::push_v(b, sw, v, sa, sseg)
        }
        Insn::PushEv => {
            let mut v = rd_any(b, sw, &ea, d)?;
            // `push_sp` = post なら mod=11, r/m=4 でもデクリメント後を積む。
            if b.param::<polyisa_guest_x86::PushSpParam>() == polyisa_guest_x86::PUSH_SP_POST
                && let Rm::Reg(g) = &ea
                && g.0 == 4
            {
                let sz = b.konst::<W64>(u64::from(sw / 8));
                v = b.sub::<W64>(v, sz);
            }
            sem_ea::push_v(b, sw, v, sa, sseg)
        }
        Insn::Push2Ev => sem_ea::push2(b, &ea, d, sa, sseg, false),
        Insn::Push2pEv => sem_ea::push2(b, &ea, d, sa, sseg, true),
        Insn::Pop2Ev => sem_ea::pop2(b, &ea, d, sa, sseg, false),
        Insn::Pop2pEv => sem_ea::pop2(b, &ea, d, sa, sseg, true),
        Insn::PopEv => {
            let sz = u64::from(sw / 8);
            // `pop [mem]` で EA が esp を参照するとき（a32 の SIB
            // base=esp）386 は SP 更新後の値で EA を計算する
            // （SST 80386 実測）。
            let ea2 = if mode == 16 && d.asize == 32 && (d.modrm & 7) == 4 && (d.sib & 7) == 4 {
                match &ea {
                    Rm::Mem { a, wseg } => {
                        let inc = b.konst::<W64>(sz);
                        Some(Rm::Mem {
                            a: b.add::<W64>(*a, inc),
                            wseg: wseg.map(|(seg, off)| (seg, b.add::<W64>(off, inc))),
                        })
                    }
                    Rm::Reg(_) => None,
                }
            } else {
                None
            };
            let ea2 = ea2.as_ref().unwrap_or(&ea);
            // 80386 系は全アクセスの限界を事前検査する。スタック読み
            // 出しの検査がデストより先（#SS が勝つ。SST 80386 実測）。
            // デスト違反では SP の更新も残らない。
            if mode == 16
                && b.param::<polyisa_guest_x86::FaultAtomicParam>()
                    == polyisa_guest_x86::FAULT_ATOMIC_ATOMIC
            {
                if sa == 16 {
                    let cur: B::V<W32> = b.get(Gpr(4).state());
                    let m16 = b.konst::<W32>(0xFFFF);
                    let lo = b.and::<W32>(cur, m16);
                    let off = b.zext::<W32, W64>(lo);
                    decode::seg_limit_chk_n(b, off, sseg | decode::WSEG_SS, sz)?;
                }
                if let Rm::Mem {
                    wseg: Some((seg, off)),
                    ..
                } = ea2
                {
                    decode::seg_limit_chk_n(b, *off, *seg, sz)?;
                }
            }
            let v = sem_ea::pop_v(b, sw, sa, sseg)?;
            wr_any(b, sw, ea2, d, v)
        }
        Insn::Pushf => {
            let f = b.get(eflags_ref());
            let mut v = if mode == 16 {
                let f16: B::V<W16> = b.trunc::<W32, W16>(f);
                b.zext::<W16, W64>(f16)
            } else {
                b.zext::<W32, W64>(f)
            };
            // `flags_top` = ones（8086/8088）は bit12-15 を立てて積む。
            if mode == 16
                && b.param::<polyisa_guest_x86::FlagsTopParam>()
                    == polyisa_guest_x86::FLAGS_TOP_ONES
            {
                let hi = b.konst::<W64>(0xF000);
                v = b.or::<W64>(v, hi);
            }
            sem_ea::push_v(b, sw, v, sa, sseg)
        }
        Insn::Popf => {
            let v = sem_ea::pop_v(b, sw, sa, sseg)?;
            let v32: B::V<W32> = b.trunc::<W64, W32>(v);
            let cur = b.get(eflags_ref());
            if mode == 16 {
                // bit1=1、bit3/5=0。`flags_top` = ones（8086/8088）は
                // bit12-15 も常に 1。zero（286 以降）はスタックの値。
                let m = b.konst::<W32>(0x0FD5);
                let low = b.and::<W32>(v32, m);
                let forced = if b.param::<polyisa_guest_x86::FlagsTopParam>()
                    == polyisa_guest_x86::FLAGS_TOP_ONES
                {
                    0xF002
                } else {
                    0x0002
                };
                let forced = b.konst::<W32>(forced);
                let low = b.or::<W32>(low, forced);
                let him = b.konst::<W32>(0xFFFF_0000);
                let hi = b.and::<W32>(cur, him);
                let merged = b.or::<W32>(hi, low);
                b.set(eflags_ref(), merged);
            } else {
                let km = b.konst::<W32>(!0xcd5u32);
                let keep = b.and::<W32>(cur, km);
                let merged = b.or::<W32>(keep, v32);
                b.set(eflags_ref(), merged);
            }
            Ok(())
        }
        Insn::JoJb => sem_ea::jcc(b, 0, eip, u32::from(d.len), d.rel),
        Insn::JoJz => sem_ea::jcc(b, 0, eip, jz_len, d.rel),
        Insn::SetjoEb => sem_ea::setcc(b, 0, &ea, d),
        Insn::CmovjoGvEv => sem_ea::cmov(b, 0, w, reg, &ea, d),
        Insn::JnoJb => sem_ea::jcc(b, 1, eip, u32::from(d.len), d.rel),
        Insn::JnoJz => sem_ea::jcc(b, 1, eip, jz_len, d.rel),
        Insn::SetjnoEb => sem_ea::setcc(b, 1, &ea, d),
        Insn::CmovjnoGvEv => sem_ea::cmov(b, 1, w, reg, &ea, d),
        Insn::JbJb => sem_ea::jcc(b, 2, eip, u32::from(d.len), d.rel),
        Insn::JbJz => sem_ea::jcc(b, 2, eip, jz_len, d.rel),
        Insn::SetjbEb => sem_ea::setcc(b, 2, &ea, d),
        Insn::CmovjbGvEv => sem_ea::cmov(b, 2, w, reg, &ea, d),
        Insn::JaeJb => sem_ea::jcc(b, 3, eip, u32::from(d.len), d.rel),
        Insn::JaeJz => sem_ea::jcc(b, 3, eip, jz_len, d.rel),
        Insn::SetjaeEb => sem_ea::setcc(b, 3, &ea, d),
        Insn::CmovjaeGvEv => sem_ea::cmov(b, 3, w, reg, &ea, d),
        Insn::JeJb => sem_ea::jcc(b, 4, eip, u32::from(d.len), d.rel),
        Insn::JeJz => sem_ea::jcc(b, 4, eip, jz_len, d.rel),
        Insn::SetjeEb => sem_ea::setcc(b, 4, &ea, d),
        Insn::CmovjeGvEv => sem_ea::cmov(b, 4, w, reg, &ea, d),
        Insn::JneJb => sem_ea::jcc(b, 5, eip, u32::from(d.len), d.rel),
        Insn::JneJz => sem_ea::jcc(b, 5, eip, jz_len, d.rel),
        Insn::SetjneEb => sem_ea::setcc(b, 5, &ea, d),
        Insn::CmovjneGvEv => sem_ea::cmov(b, 5, w, reg, &ea, d),
        Insn::JbeJb => sem_ea::jcc(b, 6, eip, u32::from(d.len), d.rel),
        Insn::JbeJz => sem_ea::jcc(b, 6, eip, jz_len, d.rel),
        Insn::SetjbeEb => sem_ea::setcc(b, 6, &ea, d),
        Insn::CmovjbeGvEv => sem_ea::cmov(b, 6, w, reg, &ea, d),
        Insn::JaJb => sem_ea::jcc(b, 7, eip, u32::from(d.len), d.rel),
        Insn::JaJz => sem_ea::jcc(b, 7, eip, jz_len, d.rel),
        Insn::SetjaEb => sem_ea::setcc(b, 7, &ea, d),
        Insn::CmovjaGvEv => sem_ea::cmov(b, 7, w, reg, &ea, d),
        Insn::JsJb => sem_ea::jcc(b, 8, eip, u32::from(d.len), d.rel),
        Insn::JsJz => sem_ea::jcc(b, 8, eip, jz_len, d.rel),
        Insn::SetjsEb => sem_ea::setcc(b, 8, &ea, d),
        Insn::CmovjsGvEv => sem_ea::cmov(b, 8, w, reg, &ea, d),
        Insn::JnsJb => sem_ea::jcc(b, 9, eip, u32::from(d.len), d.rel),
        Insn::JnsJz => sem_ea::jcc(b, 9, eip, jz_len, d.rel),
        Insn::SetjnsEb => sem_ea::setcc(b, 9, &ea, d),
        Insn::CmovjnsGvEv => sem_ea::cmov(b, 9, w, reg, &ea, d),
        Insn::JpJb => sem_ea::jcc(b, 10, eip, u32::from(d.len), d.rel),
        Insn::JpJz => sem_ea::jcc(b, 10, eip, jz_len, d.rel),
        Insn::SetjpEb => sem_ea::setcc(b, 10, &ea, d),
        Insn::CmovjpGvEv => sem_ea::cmov(b, 10, w, reg, &ea, d),
        Insn::JnpJb => sem_ea::jcc(b, 11, eip, u32::from(d.len), d.rel),
        Insn::JnpJz => sem_ea::jcc(b, 11, eip, jz_len, d.rel),
        Insn::SetjnpEb => sem_ea::setcc(b, 11, &ea, d),
        Insn::CmovjnpGvEv => sem_ea::cmov(b, 11, w, reg, &ea, d),
        Insn::JlJb => sem_ea::jcc(b, 12, eip, u32::from(d.len), d.rel),
        Insn::JlJz => sem_ea::jcc(b, 12, eip, jz_len, d.rel),
        Insn::SetjlEb => sem_ea::setcc(b, 12, &ea, d),
        Insn::CmovjlGvEv => sem_ea::cmov(b, 12, w, reg, &ea, d),
        Insn::JgeJb => sem_ea::jcc(b, 13, eip, u32::from(d.len), d.rel),
        Insn::JgeJz => sem_ea::jcc(b, 13, eip, jz_len, d.rel),
        Insn::SetjgeEb => sem_ea::setcc(b, 13, &ea, d),
        Insn::CmovjgeGvEv => sem_ea::cmov(b, 13, w, reg, &ea, d),
        Insn::JleJb => sem_ea::jcc(b, 14, eip, u32::from(d.len), d.rel),
        Insn::JleJz => sem_ea::jcc(b, 14, eip, jz_len, d.rel),
        Insn::SetjleEb => sem_ea::setcc(b, 14, &ea, d),
        Insn::CmovjleGvEv => sem_ea::cmov(b, 14, w, reg, &ea, d),
        Insn::JgJb => sem_ea::jcc(b, 15, eip, u32::from(d.len), d.rel),
        Insn::JgJz => sem_ea::jcc(b, 15, eip, jz_len, d.rel),
        Insn::SetjgEb => sem_ea::setcc(b, 15, &ea, d),
        Insn::CmovjgGvEv => sem_ea::cmov(b, 15, w, reg, &ea, d),
        Insn::CallJz => sem_ea::call_rel(b, eip, u32::from(d.len), d.rel, sw, sa, sseg),
        Insn::JmpJz => sem_ea::jmp_rel(b, eip, u32::from(d.len), d.rel),
        Insn::JmpJb => sem_ea::jmp_rel(b, eip, u32::from(d.len), d.rel),
        Insn::Ret => sem_ea::ret(b, sw, 0, sa, sseg),
        Insn::RetIw => sem_ea::ret(b, sw, d.imm as u16, sa, sseg),
        Insn::Retf => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::retf(b, sw, 0, sa, sseg)
        }
        Insn::RetfIw => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::retf(b, sw, d.imm as u16, sa, sseg)
        }
        Insn::CallfAp => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::callf_ptr(b, sw, d.imm, d.imm2, eip, u32::from(d.len), sa, sseg)
        }
        Insn::JmpfAp => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::jmpf_ptr(b, d.imm, d.imm2)
        }
        Insn::CallfRm => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::far_rm(b, w, &ea, true, eip, u32::from(d.len), sa, sseg)
        }
        Insn::JmpfRm => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::far_rm(b, w, &ea, false, eip, u32::from(d.len), sa, sseg)
        }
        Insn::Iret => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::iret_real(b, sw, sa, sseg)
        }
        Insn::Into => {
            if mode != 16 {
                return Ok(false);
            }
            sem_ea::into_real(b, eip, u32::from(d.len), sa, sseg)
        }
        Insn::CallEv => sem_ea::call_rm(b, sw, &ea, d, eip, u32::from(d.len), sa, sseg),
        Insn::JmpEv => sem_ea::jmp_rm(b, sw, &ea, d, sa),
        Insn::Leave => {
            // SDM: SP←BP は StackAddressSize、pop は OperandSize。
            if sa == 16 {
                // 80286 実測: pop が限界例外を起こすと SP:=BP は
                // コミットされず、例外フレームは元の SP に積まれる。
                let p = sem_ea::leave16(b, sw, sseg)?;
                put64(b, Gpr(5), sw, p, d);
            } else {
                let bp = Gpr(5);
                let v = gr64(b, bp, sa);
                put64(b, Gpr(4), sa, v, d);
                let p = sem_ea::pop_v(b, sw, sa, sseg)?;
                put64(b, bp, sw, p, d);
            }
            Ok(())
        }
        Insn::Cwde => sem_ea::cwde(b, w, d),
        Insn::Cdq => sem_ea::cdq(b, w),
        Insn::Sahf => sem_ea::sahf(b),
        Insn::Lahf => sem_ea::lahf(b),
        Insn::Daa => sem_ea::daa(b),
        Insn::Das => sem_ea::das(b),
        Insn::Aaa => sem_ea::aaa_aas(b, false),
        Insn::Aas => sem_ea::aaa_aas(b, true),
        Insn::Salc => sem_ea::salc(b),
        Insn::AamIb => sem_ea::aam(b, d.imm as u8, eip, u32::from(d.len), sa, sseg, mode),
        Insn::AadIb => sem_ea::aad(b, d.imm as u8),
        Insn::LesGvMp => sem_ea::load_far(b, w, d, &ea, 0),
        Insn::LdsGvMp => sem_ea::load_far(b, w, d, &ea, 3),
        // LSS/LFS/LGS の mod=3 形は #UD（SST 80386 実測）。
        Insn::LssGvMp | Insn::LfsGvMp | Insn::LgsGvMp => {
            if matches!(ea, decode::Rm::Reg(_)) {
                if mode == 16 {
                    return sem_ea::int_real(b, eip, 0, 6, sa, sseg).map(|_| true);
                }
                return sem_ea::trap(b, eip, 0x06).map(|_| true);
            }
            let s = match d.insn {
                Insn::LssGvMp => 2,
                Insn::LfsGvMp => 4,
                _ => 5,
            };
            sem_ea::load_far(b, w, d, &ea, s)
        }
        Insn::Cmc => sem_ea::flagop(b, 0x1, 2),
        Insn::Clc => sem_ea::flagop(b, 0x1, 0),
        Insn::Stc => sem_ea::flagop(b, 0x1, 1),
        Insn::Cld => sem_ea::flagop(b, 0x400, 0),
        Insn::Std => sem_ea::flagop(b, 0x400, 1),
        Insn::Cli => sem_ea::flagop(b, 0x200, 0),
        Insn::Sti => sem_ea::flagop(b, 0x200, 1),
        Insn::BswapRv => sem_ea::bswap(b, w, decode::op_reg(d)),
        Insn::NopEv => sem_ea::nop(b),
        Insn::Endbr => sem_ea::nop(b),
        Insn::Ud2 => {
            if mode == 16 {
                sem_ea::int_real(b, eip, 0, 6, sa, sseg)
            } else {
                sem_ea::trap(b, eip, 0x06)
            }
        }
        Insn::Int3 => {
            if mode == 16 {
                sem_ea::int_real(b, eip, u32::from(d.len), 3, sa, sseg)
            } else {
                sem_ea::int_n(b, eip, 3)
            }
        }
        Insn::IntIb => {
            if mode == 16 {
                sem_ea::int_real(b, eip, u32::from(d.len), d.imm as u8, sa, sseg)
            } else {
                sem_ea::int_n(b, eip, d.imm as u8)
            }
        }
        Insn::InAlIb => {
            let port = b.konst::<W64>(d.imm);
            sem_ea::io_in(b, 8, port, d)
        }
        Insn::InEvIb => {
            let port = b.konst::<W64>(d.imm);
            sem_ea::io_in(b, w, port, d)
        }
        Insn::OutIbAl => {
            let port = b.konst::<W64>(d.imm);
            sem_ea::io_out(b, 8, port, d)
        }
        Insn::OutIbEv => {
            let port = b.konst::<W64>(d.imm);
            sem_ea::io_out(b, w, port, d)
        }
        Insn::InAlDx => {
            let port = dx_port(b);
            sem_ea::io_in(b, 8, port, d)
        }
        Insn::InEvDx => {
            let port = dx_port(b);
            sem_ea::io_in(b, w, port, d)
        }
        Insn::OutDxAl => {
            let port = dx_port(b);
            sem_ea::io_out(b, 8, port, d)
        }
        Insn::OutDxEv => {
            let port = dx_port(b);
            sem_ea::io_out(b, w, port, d)
        }
        Insn::Syscall | Insn::SyscallAmd => sem::syscall(b, eip),
        Insn::Pause | Insn::PtwriteRv | Insn::UwrmsrRvEv => sem_ea::nop(b),
        Insn::RdpidRv => sem_ea::rdpid(b, w, &ea, d),
        Insn::UrdmsrRvEv => sem_ea::urdmsr(b, &ea),
        Insn::Rdpmc => sem_ea::rdpmc(b),
        // 特権キャッシュ制御はユーザーモードでは #GP。実モードは
        // CPL0 相当なので、キャッシュを持たない近似で no-op。
        Insn::Invd | Insn::Wbinvd | Insn::InvlpgMb => {
            if mode == 16 {
                sem_ea::nop(b)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        // MSR アクセスもユーザーモードでは #GP。システムモード側は
        // MSR 空間を持たない最小近似（RDMSR=0、WRMSR=no-op）。
        Insn::Rdmsr => {
            if mode == 16 {
                sem_ea::rdmsr_zero(b)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        Insn::Wrmsr => {
            if mode == 16 {
                sem_ea::nop(b)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        // SYSRET は CPL0 専用。実モードではエンコード自体が無効。
        Insn::Sysret | Insn::SysretAmd => {
            if mode == 16 {
                sem_ea::int_real(b, eip, 0, 6, sa, sseg)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        // SMX/VMX/SMM の実行環境はモデル化しない。CR4.SMXE=0、
        // VMX 非動作・SMM 外なので、これらは #UD となる。実モードでは
        // 例外を IVT[6] へ配送し、ユーザーモードでは GAP-0026 の
        // 未配送境界に従って Undefined を返す。
        Insn::Getsec | Insn::Rsm | Insn::VmreadEvGv | Insn::VmwriteGvEv => {
            if mode == 16 {
                sem_ea::int_real(b, eip, 0, 6, sa, sseg)
            } else {
                sem_ea::undefined(b, eip)
            }
        }
        Insn::Int1 => {
            if mode == 16 {
                sem_ea::int_real(b, eip, u32::from(d.len), 1, sa, sseg)
            } else {
                sem_ea::int_n(b, eip, 1)
            }
        }
        Insn::Ud0GvEv | Insn::Udb => {
            if mode == 16 {
                sem_ea::int_real(b, eip, 0, 6, sa, sseg)
            } else {
                sem_ea::trap(b, eip, 0x06)
            }
        }
        Insn::Cpuid => sem::cpuid(b),
        Insn::ImulGvEv => sem_ea::imul2(b, w, reg, &ea, d),
        Insn::ImulGvEvIz => sem_ea::imul3(b, w, reg, &ea, d, iz as i64),
        Insn::ImulGvEvIb => sem_ea::imul3(b, w, reg, &ea, d, ib8 as i64),
        Insn::IncRv => sem_ea::incdec(b, true, w, &Rm::Reg(decode::op_reg(d)), d),
        Insn::DecRv => sem_ea::incdec(b, false, w, &Rm::Reg(decode::op_reg(d)), d),
        Insn::Pusha => sem_ea::pusha(b, w, sa, sseg),
        Insn::Popa => sem_ea::popa(b, w, sa, sseg),
        Insn::CmpxchgEbGb => sem_ea::cmpxchg(b, 8, &ea, d, reg),
        Insn::CmpxchgEvGv => sem_ea::cmpxchg(b, w, &ea, d, reg),
        Insn::XaddEbGb => sem_ea::xadd(b, 8, &ea, d, reg),
        Insn::XaddEvGv => sem_ea::xadd(b, w, &ea, d, reg),
        Insn::BsfGvEv => sem_ea::bsfx(b, w, false, reg, &ea, d),
        Insn::BsrGvEv => sem_ea::bsfx(b, w, true, reg, &ea, d),
        Insn::LzcntGvEv => sem_ea::lzcnt(b, w, reg, &ea, d),
        // ADCX/ADOX の必須接頭辞（66/F3）はオペコード選択子で、
        // オペランド幅を縮めない。幅は REX.W ? 64 : 32 に固定。
        Insn::AdcxGvEv => sem_ea::adcx(b, if d.rex & 8 != 0 { 64 } else { 32 }, false, reg, &ea, d),
        Insn::AdoxGvEv => sem_ea::adcx(b, if d.rex & 8 != 0 { 64 } else { 32 }, true, reg, &ea, d),
        Insn::Ud1 => {
            if mode == 16 {
                sem_ea::int_real(b, eip, 0, 6, sa, sseg)
            } else {
                sem_ea::trap(b, eip, 0x06)
            }
        }
        Insn::LoopneJb => sem_ea::loopcc(b, 0, eip, u32::from(d.len), d.rel, d),
        Insn::LoopeJb => sem_ea::loopcc(b, 1, eip, u32::from(d.len), d.rel, d),
        Insn::LoopJb => sem_ea::loopcc(b, 2, eip, u32::from(d.len), d.rel, d),
        Insn::JcxzJb => sem_ea::loopcc(b, 3, eip, u32::from(d.len), d.rel, d),
        Insn::EnterIwIb => sem_ea::enter(b, sw, d.imm, d.imm2, sa, sseg),
        Insn::Xlat => sem_ea::xlat(b, d, seg),
        Insn::Rdtsc => sem_ea::rdtsc(b),
        Insn::PopcntGvEv => sem_ea::popcnt(b, w, reg, d, &ea),
        Insn::Cmpxchg8bMq => {
            // REX.W 形は CMPXCHG16B で `cx16` が要る。デコードは
            // `cx8` で通ったが、ワイド形の機能旗はここで検査する。
            if d.rex & 8 != 0 && feats & polyisa_guest_x86::FEAT_CX16 == 0 {
                return sem_ea::trap(b, eip, 0x06).map(|_| true);
            }
            sem_ea::cmpxchg_m(b, d.rex & 8 != 0, d, &ea)
        }
        // 0F AE 群。fence/clflush は機能シミュレーション上は無意味論。
        Insn::LdmxcsrMd => sem_ea::ldmxcsr(b, &ea),
        Insn::StmxcsrMd => sem_ea::stmxcsr(b, &ea),
        Insn::Lfence | Insn::Mfence | Insn::ClflushMb | Insn::Sfence => sem_ea::mem_hint(b),
        // SSE3。
        Insn::HaddpsXvWv => sem_ea::phaddsub_f(b, false, 32, d, &ea),
        Insn::HaddpdXvWv => sem_ea::phaddsub_f(b, false, 64, d, &ea),
        Insn::HsubpsXvWv => sem_ea::phaddsub_f(b, true, 32, d, &ea),
        Insn::HsubpdXvWv => sem_ea::phaddsub_f(b, true, 64, d, &ea),
        Insn::AddsubpsXvWv => sem_ea::addsub(b, 32, d, &ea),
        Insn::AddsubpdXvWv => sem_ea::addsub(b, 64, d, &ea),
        Insn::LddquXvMv => sem_ea::mov_x_w(b, d, &ea),
        Insn::Fwait => sem_ea::nop(b),
        Insn::InsEbDx => {
            sem_ea::str_op(b, sem_ea::Str::Ins, 8, d, eip, seg, seg_ss, es, mode == 16)
        }
        Insn::InsEvDx => {
            sem_ea::str_op(b, sem_ea::Str::Ins, w, d, eip, seg, seg_ss, es, mode == 16)
        }
        Insn::OutsDxEb => {
            sem_ea::str_op(b, sem_ea::Str::Outs, 8, d, eip, seg, seg_ss, es, mode == 16)
        }
        Insn::OutsDxEv => {
            sem_ea::str_op(b, sem_ea::Str::Outs, w, d, eip, seg, seg_ss, es, mode == 16)
        }
        Insn::BoundGvMp => sem_ea::bound(b, w, d, &ea, eip, mode, sa, sseg),
        Insn::PopCs => sem_ea::pop_sr(b, 1, sw, sa, sseg),
        Insn::SmswEw => sem_ea::smsw(b, &ea),
        // LMSW/LGDT/LIDT/LLDT/LTR は CPL0 専用。実モードは CPL0 相当
        // だが、32/64 ビットの本経路は Linux ユーザーモードなので #GP
        // に揃える。SGDT/SIDT/SLDT/STR/SMSW は UMIP=0 の非特権命令。
        Insn::LmswEw => {
            if mode == 16 {
                sem_ea::lmsw(b, &ea, eip)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        // 0F 00/01 のシステム状態群。ディスクリプタ機構を持たない
        // モデルでは保護系の検査は全て失敗（ZF=0）で近似する。
        Insn::SldtEw => sem_ea::sldt(b, false, &ea, mode, eip, sa, sseg),
        Insn::StrEw => sem_ea::sldt(b, true, &ea, mode, eip, sa, sseg),
        Insn::LldtEw => {
            if mode == 16 {
                sem_ea::lldt(b, false, &ea, mode, eip, sa, sseg)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        Insn::LtrEw => {
            if mode == 16 {
                sem_ea::lldt(b, true, &ea, mode, eip, sa, sseg)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        Insn::VerrEw | Insn::VerwEw => sem_ea::verrw(b, mode, eip, sa, sseg),
        Insn::LarGvEw | Insn::LslGvEw => sem_ea::lar_lsl(b, mode, eip, sa, sseg),
        Insn::SgdtMs => sem_ea::sgdt(b, &ea, mode),
        Insn::SidtMs => sem_ea::sidt(b, &ea, mode),
        Insn::LgdtMs => {
            if mode == 16 {
                sem_ea::lgdt(b, &ea, mode)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        Insn::LidtMs => {
            if mode == 16 {
                sem_ea::lidt(b, &ea, mode)
            } else {
                sem_ea::protection(b, eip)
            }
        }
        // SERIALIZE は逐次化 no-op。
        Insn::Serialize => sem_ea::nop(b),
        Insn::RdrandRv => sem_ea::rdrand(b, w, &ea, d),
        Insn::RdseedRv => sem_ea::rdrand(b, w, &ea, d),
        Insn::RdfsbaseRv => sem_ea::fsgsbase(b, w, &ea, false, false, d),
        Insn::RdgsbaseRv => sem_ea::fsgsbase(b, w, &ea, true, false, d),
        Insn::WrfsbaseRv => sem_ea::fsgsbase(b, w, &ea, false, true, d),
        Insn::WrgsbaseRv => sem_ea::fsgsbase(b, w, &ea, true, true, d),
        // 影響スタックはモデル化しない: INCSSP/SETSSBSY/CLRSSBSY/
        // RSTORSSP は no-op、RDSSP は 0 固定、WRSS/WRUSS は通常
        // ストア。
        Insn::RdsspdRv => sem_ea::rdssp(b, w, &ea, d),
        Insn::IncsspdRv
        | Insn::Setssbsy
        | Insn::ClrssbsyMq
        | Insn::RstorsspMq
        | Insn::Saveprevssp => sem_ea::nop(b),
        // WRSS/WRUSS のメモリ幅は d/q 固定。WRUSS の必須 66 は
        // オペコード選択子でオペランド幅を縮めないので、osize
        // ではなく rex.W から決める（ADCX/ADOX と同じ）。
        Insn::WrssdMvGv | Insn::WrussdMvGv => sem_ea::mov_e(
            b,
            if d.rex & 8 != 0 { 64 } else { 32 },
            &ea,
            d,
            Src::Reg(reg),
        ),
        // PKU は実状態。EAX=PKRU / PKRU=EAX。
        Insn::Rdpkru => sem_ea::rdpkru(b),
        Insn::Wrpkru => sem_ea::wrpkru(b),
        // XCR0 と保存領域。XGETBV/XSETBV は EDX:EAX 経由。
        Insn::Xgetbv => sem_ea::xgetbv(b),
        Insn::Xsetbv => sem_ea::xsetbv(b),
        Insn::Fxsave => sem_ea::fxsave(b, &ea, mode),
        Insn::Fxrstor => sem_ea::fxrstor(b, &ea, mode),
        Insn::Xsave | Insn::Xsaveopt => sem_ea::xsave(b, &ea, mode),
        Insn::Xrstor => sem_ea::xrstor(b, &ea, mode),
        // TSX。XBEGIN は常にアボートしてフォールバックへ分岐、
        // XTEST はトランザクション外なので ZF=1。XEND/XABORT は
        // トランザクション外では #GP/無効だが近似の no-op。
        Insn::XbeginJz => sem_ea::xbegin(b, eip, jz_len, d.rel),
        Insn::Xtest => sem_ea::xtest(b),
        // UIF=0・ウェイク即時の近似で CF=0。
        Insn::Testui | Insn::UmwaitRv => sem_ea::cf_clear(b),
        // UIRET/CLUI/STUI/SENDUIPI（ユーザー割り込みは配送
        // しない）、UMONITOR/TPAUSE（監視・タイマーなし）、
        // CLWB/CLFLUSHOPT/CLDEMOTE（キャッシュ階層なし）、
        // HRESET（履歴なし）— すべて近似の no-op。
        Insn::Xend
        | Insn::XabortIb
        | Insn::Uiret
        | Insn::Clui
        | Insn::Stui
        | Insn::SenduipiRv
        | Insn::UmonitorRv
        | Insn::TpauseRv
        | Insn::ClwbMb
        | Insn::ClflushoptMb
        | Insn::CldemoteMb
        | Insn::HresetIb => sem_ea::nop(b),
        // MOVDIRI は通常ストアとして近似。
        Insn::MovdiriMvGv => sem_ea::mov_e(b, w, &ea, d, Src::Reg(reg)),
        // MOVDIR64B/ENQCMD/ENQCMDS は reg の指す宛先へ
        // 64 バイトコピーする近似。
        Insn::Movdir64bGvMv | Insn::EnqcmdGvMv | Insn::EnqcmdsGvMv => {
            sem_ea::movdir64b(b, reg, &ea, m64)
        }
        Insn::MovsB => sem_ea::str_op(b, sem_ea::Str::Movs, 8, d, eip, seg, seg_ss, es, mode == 16),
        Insn::MovsV => sem_ea::str_op(b, sem_ea::Str::Movs, w, d, eip, seg, seg_ss, es, mode == 16),
        Insn::StosB => sem_ea::str_op(b, sem_ea::Str::Stos, 8, d, eip, seg, seg_ss, es, mode == 16),
        Insn::StosV => sem_ea::str_op(b, sem_ea::Str::Stos, w, d, eip, seg, seg_ss, es, mode == 16),
        Insn::LodsB => sem_ea::str_op(b, sem_ea::Str::Lods, 8, d, eip, seg, seg_ss, es, mode == 16),
        Insn::LodsV => sem_ea::str_op(b, sem_ea::Str::Lods, w, d, eip, seg, seg_ss, es, mode == 16),
        Insn::ScasB => sem_ea::str_op(b, sem_ea::Str::Scas, 8, d, eip, seg, seg_ss, es, mode == 16),
        Insn::ScasV => sem_ea::str_op(b, sem_ea::Str::Scas, w, d, eip, seg, seg_ss, es, mode == 16),
        Insn::CmpsB => sem_ea::str_op(b, sem_ea::Str::Cmps, 8, d, eip, seg, seg_ss, es, mode == 16),
        Insn::CmpsV => sem_ea::str_op(b, sem_ea::Str::Cmps, w, d, eip, seg, seg_ss, es, mode == 16),
        Insn::MovAlOb => sem_ea::mov_moffs_ld(b, 8, d.imm, seg, seg_ss, d, mode == 16),
        Insn::MovEaxOv => sem_ea::mov_moffs_ld(b, w, d.imm, seg, seg_ss, d, mode == 16),
        Insn::MovObAl => sem_ea::mov_moffs_st(b, 8, d.imm, seg, seg_ss, d, mode == 16),
        Insn::MovOvEax => sem_ea::mov_moffs_st(b, w, d.imm, seg, seg_ss, d, mode == 16),
        Insn::BtEvGv => {
            let n = gr_sext64(b, reg, w);
            sem_ea::bt_op(b, 0, w, &ea, d, n, false)
        }
        Insn::BtEvIb => {
            let n = b.konst::<W64>(ib8 as i8 as i64 as u64);
            sem_ea::bt_op(b, 0, w, &ea, d, n, true)
        }
        Insn::BtsEvGv => {
            let n = gr_sext64(b, reg, w);
            sem_ea::bt_op(b, 1, w, &ea, d, n, false)
        }
        Insn::BtsEvIb => {
            let n = b.konst::<W64>(ib8 as i8 as i64 as u64);
            sem_ea::bt_op(b, 1, w, &ea, d, n, true)
        }
        Insn::BtrEvGv => {
            let n = gr_sext64(b, reg, w);
            sem_ea::bt_op(b, 2, w, &ea, d, n, false)
        }
        Insn::BtrEvIb => {
            let n = b.konst::<W64>(ib8 as i8 as i64 as u64);
            sem_ea::bt_op(b, 2, w, &ea, d, n, true)
        }
        Insn::BtcEvGv => {
            let n = gr_sext64(b, reg, w);
            sem_ea::bt_op(b, 3, w, &ea, d, n, false)
        }
        Insn::BtcEvIb => {
            let n = b.konst::<W64>(ib8 as i8 as i64 as u64);
            sem_ea::bt_op(b, 3, w, &ea, d, n, true)
        }
        Insn::ShldEvGvIb => sem_ea::shxd(b, true, w, &ea, d, reg, ShiftCnt::Imm(d.imm as u32)),
        Insn::ShldEvGvCl => sem_ea::shxd(b, true, w, &ea, d, reg, ShiftCnt::Cl),
        Insn::ShrdEvGvIb => sem_ea::shxd(b, false, w, &ea, d, reg, ShiftCnt::Imm(d.imm as u32)),
        Insn::ShrdEvGvCl => sem_ea::shxd(b, false, w, &ea, d, reg, ShiftCnt::Cl),
        // ===== セグメント・特権 =====
        // セレクタ 6/7 は #UD。未対応として旧経路（＝Unimplemented）へ落ちる。
        Insn::MovEwSr => {
            // 8086/80186 には ES/CS/SS/DS しかなく、reg の上位ビットは
            // 無視される。80286 以降は /6,/7 が #UD、/4,/5 が FS/GS。
            let mut s = (d.modrm >> 3) & 7;
            if mode == 16 && feats & polyisa_guest_x86::FEAT_I286 == 0 {
                s &= 3;
            }
            if s > 5 {
                return Ok(false);
            }
            // 80386 の o32 形で r32 宛てのときはセレクタをゼロ拡張して
            // 32 ビット書き込む（メモリ形は word のまま。SST 80386 実測）。
            if w == 32
                && let polyisa_guest_x86::decode::Rm::Reg(g) = &ea
            {
                let v: B::V<W16> = b.get(polyisa_guest_x86::sem::sreg_ref(s));
                let v32 = b.zext::<W16, W32>(v);
                b.set(g.state(), v32);
                return Ok(true);
            }
            sem_ea::mov_sr_st(b, s, &ea)
        }
        Insn::MovSrEw => {
            let mut s = (d.modrm >> 3) & 7;
            if mode == 16 && feats & polyisa_guest_x86::FEAT_I286 == 0 {
                s &= 3;
            }
            if s > 5 {
                return Ok(false);
            }
            sem_ea::mov_sr_ld(b, s, &ea)
        }
        Insn::PushEs => sem_ea::push_sr(b, 0, sw, sa, sseg),
        Insn::PushCs => sem_ea::push_sr(b, 1, sw, sa, sseg),
        Insn::PushSs => sem_ea::push_sr(b, 2, sw, sa, sseg),
        Insn::PushDs => sem_ea::push_sr(b, 3, sw, sa, sseg),
        Insn::PushFs => sem_ea::push_sr(b, 4, sw, sa, sseg),
        Insn::PushGs => sem_ea::push_sr(b, 5, sw, sa, sseg),
        Insn::PopEs => sem_ea::pop_sr(b, 0, sw, sa, sseg),
        Insn::PopSs => sem_ea::pop_sr(b, 2, sw, sa, sseg),
        Insn::PopDs => sem_ea::pop_sr(b, 3, sw, sa, sseg),
        Insn::PopFs => sem_ea::pop_sr(b, 4, sw, sa, sseg),
        Insn::PopGs => sem_ea::pop_sr(b, 5, sw, sa, sseg),
        Insn::ArplEwGw => sem_ea::arpl(b, d, &ea, eip, mode, sa, sseg),
        Insn::Sysenter => sem_ea::sysenter(b, eip),
        Insn::Sysexit => sem_ea::sysexit(b, if d.rex & 8 != 0 { 64 } else { 32 }),
        // HLT は CPL0 専用だが旧経路と同じく nop として扱う。
        Insn::Hlt => Ok(()),
        // CLTS は CR0.TS を下ろすが、CR0 をモデル化していないので nop。
        Insn::Clts => Ok(()),
        Insn::AaddMvGv => sem_ea::rao_op(b, 0, w, d, &ea),
        Insn::AandMvGv => sem_ea::rao_op(b, 1, w, d, &ea),
        Insn::AorMvGv => sem_ea::rao_op(b, 2, w, d, &ea),
        Insn::AxorMvGv => sem_ea::rao_op(b, 3, w, d, &ea),
        Insn::CmpoxaddEvGv => sem_ea::cmpccxadd(b, 0, vw, d, &ea),
        Insn::CmpnoxaddEvGv => sem_ea::cmpccxadd(b, 1, vw, d, &ea),
        Insn::CmpbxaddEvGv => sem_ea::cmpccxadd(b, 2, vw, d, &ea),
        Insn::CmpnbxaddEvGv => sem_ea::cmpccxadd(b, 3, vw, d, &ea),
        Insn::CmpzxaddEvGv => sem_ea::cmpccxadd(b, 4, vw, d, &ea),
        Insn::CmpnzxaddEvGv => sem_ea::cmpccxadd(b, 5, vw, d, &ea),
        Insn::CmpbexaddEvGv => sem_ea::cmpccxadd(b, 6, vw, d, &ea),
        Insn::CmpnbexaddEvGv => sem_ea::cmpccxadd(b, 7, vw, d, &ea),
        Insn::CmpsxaddEvGv => sem_ea::cmpccxadd(b, 8, vw, d, &ea),
        Insn::CmpnsxaddEvGv => sem_ea::cmpccxadd(b, 9, vw, d, &ea),
        Insn::CmppxaddEvGv => sem_ea::cmpccxadd(b, 10, vw, d, &ea),
        Insn::CmpnpxaddEvGv => sem_ea::cmpccxadd(b, 11, vw, d, &ea),
        Insn::CmplxaddEvGv => sem_ea::cmpccxadd(b, 12, vw, d, &ea),
        Insn::CmpnlxaddEvGv => sem_ea::cmpccxadd(b, 13, vw, d, &ea),
        Insn::CmplexaddEvGv => sem_ea::cmpccxadd(b, 14, vw, d, &ea),
        Insn::CmpnlexaddEvGv => sem_ea::cmpccxadd(b, 15, vw, d, &ea),
        // ===== SSE/SSE2（0F 系）=====
        Insn::MovupsXvWv
        | Insn::MovupdXvWv
        | Insn::MovapsXvWv
        | Insn::MovapdXvWv
        | Insn::MovdqaXvWv
        | Insn::MovdquXvWv => sem_ea::mov_x_w(b, d, &ea),
        Insn::MovupsWvXv
        | Insn::MovupdWvXv
        | Insn::MovapsWvXv
        | Insn::MovapdWvXv
        | Insn::MovdqaWvXv
        | Insn::MovdquWvXv
        | Insn::MovntpsWvXv
        | Insn::MovntpdWvXv
        | Insn::MovntdqWvXv => sem_ea::mov_w_x(b, d, &ea),
        // EVEX の VMOVDQU32/64。要素幅は EVEX.W（d.vex_w）。
        Insn::Vmovdqu32XvWv | Insn::Vmovdqu32XvWvVl => sem_ea::emovdqu(b, d, &ea, false, d.vex_w),
        Insn::Vmovdqu32WvXv | Insn::Vmovdqu32WvXvVl => sem_ea::emovdqu(b, d, &ea, true, d.vex_w),
        // EVEX パック演算は efloat/eint/elogic/eabs の腕に統合
        // （同名の VEX 変種と Insn を共有するため `d.evex` で分岐する）。
        Insn::MovssXvWv => sem_ea::movs_ld(b, d, &ea, 32),
        Insn::MovsdXvWv => sem_ea::movs_ld(b, d, &ea, 64),
        Insn::MovssWvXv => sem_ea::movs_st(b, d, &ea, 32),
        Insn::MovsdWvXv => sem_ea::movs_st(b, d, &ea, 64),
        Insn::MovlpsXvWv | Insn::MovlpdXvWv | Insn::MovddupXvWv | Insn::MovsldupXvWv => {
            sem_ea::movl_d(b, d, &ea)
        }
        Insn::MovlpsWvXv | Insn::MovlpdWvXv => sem_ea::movl_st(b, d, &ea),
        Insn::MovhpsXvWv | Insn::MovhpdXvWv | Insn::MovshdupXvWv => sem_ea::movh_d(b, d, &ea),
        Insn::MovhlpsXvXv => sem_ea::movhlps_d(b, d, &ea),
        Insn::MovlhpsXvXv => sem_ea::movlhps_d(b, d, &ea),
        Insn::MovhpsWvXv | Insn::MovhpdWvXv => sem_ea::movh_st(b, d, &ea),
        Insn::MovqXvWv => sem_ea::movq_x_w(b, d, &ea),
        Insn::MovqWvXv => sem_ea::movq_w_x(b, d, &ea),
        Insn::Movdq2qPvXv => sem_ea::movdq2q(b, d, &ea),
        Insn::Movq2dqXvQv => sem_ea::movq2dq(b, d, &ea),
        Insn::MovdXvEv => sem_ea::movd_x_e(b, d, &ea),
        Insn::MovdEvXv => sem_ea::movd_e_x(b, d, &ea),
        Insn::MovmskpsGvWv => sem_ea::movmsk(b, 32, d, &ea),
        Insn::MovmskpdGvWv => sem_ea::movmsk(b, 64, d, &ea),
        Insn::PmovmskbGvWv => sem_ea::movmsk(b, 8, d, &ea),
        Insn::UcomissXvWv | Insn::ComissXvWv | Insn::VucomissXvWv | Insn::VcomissXvWv => {
            sem_ea::ucomis(b, 32, d, &ea)
        }
        Insn::UcomisdXvWv | Insn::ComisdXvWv | Insn::VucomisdXvWv | Insn::VcomisdXvWv => {
            sem_ea::ucomis(b, 64, d, &ea)
        }
        Insn::RsqrtpsXvWv => sem_ea::rcp_rs(b, true, d, &ea),
        Insn::RcppsXvWv => sem_ea::rcp_rs(b, false, d, &ea),
        Insn::RsqrtssXvWv => sem_ea::rcp_rs_s(b, true, d, &ea),
        Insn::RcpssXvWv => sem_ea::rcp_rs_s(b, false, d, &ea),
        Insn::Cvtpi2psXvQv => sem_ea::cvtpi2ps(b, d, &ea),
        Insn::Cvtpi2pdXvQv => sem_ea::cvtpi2pd(b, d, &ea),
        Insn::Cvttps2piPvWv => sem_ea::cvtps2pi(b, true, d, &ea),
        Insn::Cvtps2piPvWv => sem_ea::cvtps2pi(b, false, d, &ea),
        Insn::Cvttpd2piPvWv => sem_ea::cvtpd2pi(b, true, d, &ea),
        Insn::Cvtpd2piPvWv => sem_ea::cvtpd2pi(b, false, d, &ea),
        Insn::Cvtsi2ssXvEv => sem_ea::cvtsi(b, 32, d, &ea),
        Insn::Cvtsi2sdXvEv => sem_ea::cvtsi(b, 64, d, &ea),
        Insn::Cvttss2siGvWv => sem_ea::cvtf2i(b, 32, true, d, &ea, reg),
        Insn::Cvttsd2siGvWv => sem_ea::cvtf2i(b, 64, true, d, &ea, reg),
        Insn::Cvtss2siGvWv => sem_ea::cvtf2i(b, 32, false, d, &ea, reg),
        Insn::Cvtsd2siGvWv => sem_ea::cvtf2i(b, 64, false, d, &ea, reg),
        Insn::Cvtps2pdXvWv => sem_ea::cvtff(b, true, false, d, &ea),
        Insn::Cvtss2sdXvWv => sem_ea::cvtff(b, true, true, d, &ea),
        Insn::Cvtpd2psXvWv => sem_ea::cvtff(b, false, false, d, &ea),
        Insn::Cvtsd2ssXvWv => sem_ea::cvtff(b, false, true, d, &ea),
        Insn::CmppsXvWvIb => sem_ea::pfloat(b, sem_ea::Fop::Cmp(d.imm as u8), 32, d, &ea),
        Insn::CmppdXvWvIb => sem_ea::pfloat(b, sem_ea::Fop::Cmp(d.imm as u8), 64, d, &ea),
        Insn::CmpssXvWvIb => sem_ea::scmp(b, 32, d.imm as u8, d, &ea),
        Insn::CmpsdXvWvIb => sem_ea::scmp(b, 64, d.imm as u8, d, &ea),
        Insn::AndpsXvWv | Insn::AndpdXvWv | Insn::PandXvWv => {
            sem_ea::logic128(b, sem_ea::Lop::And, d, &ea)
        }
        Insn::AndnpsXvWv | Insn::AndnpdXvWv | Insn::PandnXvWv => {
            sem_ea::logic128(b, sem_ea::Lop::Andn, d, &ea)
        }
        Insn::OrpsXvWv | Insn::OrpdXvWv | Insn::PorXvWv => {
            sem_ea::logic128(b, sem_ea::Lop::Or, d, &ea)
        }
        Insn::XorpsXvWv | Insn::XorpdXvWv | Insn::PxorXvWv => {
            sem_ea::logic128(b, sem_ea::Lop::Xor, d, &ea)
        }
        Insn::PshufdXvWvIb => sem_ea::pshuf(b, 0, d.imm as u8, d, &ea),
        Insn::PshufhwXvWvIb => sem_ea::pshuf(b, 1, d.imm as u8, d, &ea),
        Insn::PshuflwXvWvIb => sem_ea::pshuf(b, 2, d.imm as u8, d, &ea),
        Insn::ShufpsXvWvIb => sem_ea::shufp(b, false, d.imm as u8, d, &ea),
        Insn::ShufpdXvWvIb => sem_ea::shufp(b, true, d.imm as u8, d, &ea),
        Insn::PunpcklbwXvWv => sem_ea::punpck(b, 8, false, d, &ea),
        Insn::PunpcklwdXvWv => sem_ea::punpck(b, 16, false, d, &ea),
        Insn::PunpckldqXvWv => sem_ea::punpck(b, 32, false, d, &ea),
        Insn::PunpcklqdqXvWv => sem_ea::punpck(b, 64, false, d, &ea),
        Insn::UnpcklpsXvWv => sem_ea::punpck(b, 32, false, d, &ea),
        Insn::UnpcklpdXvWv => sem_ea::punpck(b, 64, false, d, &ea),
        Insn::UnpckhpsXvWv => sem_ea::punpck(b, 32, true, d, &ea),
        Insn::UnpckhpdXvWv => sem_ea::punpck(b, 64, true, d, &ea),
        Insn::PunpckhbwXvWv => sem_ea::punpck(b, 8, true, d, &ea),
        Insn::PunpckhwdXvWv => sem_ea::punpck(b, 16, true, d, &ea),
        Insn::PunpckhdqXvWv => sem_ea::punpck(b, 32, true, d, &ea),
        Insn::PunpckhqdqXvWv => sem_ea::punpck(b, 64, true, d, &ea),
        Insn::PinsrwXvEwIb => sem_ea::pinsrw(b, d.imm as u8, d, &ea),
        Insn::PextrwGvWvIb => sem_ea::pextrw(b, d.imm as u8, d, &ea, reg),
        // パック浮動小数点。
        Insn::SqrtpsXvWv => sem_ea::pfloat(b, sem_ea::Fop::Sqrt, 32, d, &ea),
        Insn::SqrtpdXvWv => sem_ea::pfloat(b, sem_ea::Fop::Sqrt, 64, d, &ea),
        Insn::SqrtssXvWv => sem_ea::sfloat(b, sem_ea::Fop::Sqrt, 32, d, &ea),
        Insn::SqrtsdXvWv => sem_ea::sfloat(b, sem_ea::Fop::Sqrt, 64, d, &ea),
        Insn::AddpsXvWv => sem_ea::pfloat(b, sem_ea::Fop::Add, 32, d, &ea),
        Insn::AddpdXvWv => sem_ea::pfloat(b, sem_ea::Fop::Add, 64, d, &ea),
        Insn::AddssXvWv => sem_ea::sfloat(b, sem_ea::Fop::Add, 32, d, &ea),
        Insn::AddsdXvWv => sem_ea::sfloat(b, sem_ea::Fop::Add, 64, d, &ea),
        Insn::MulpsXvWv => sem_ea::pfloat(b, sem_ea::Fop::Mul, 32, d, &ea),
        Insn::MulpdXvWv => sem_ea::pfloat(b, sem_ea::Fop::Mul, 64, d, &ea),
        Insn::MulssXvWv => sem_ea::sfloat(b, sem_ea::Fop::Mul, 32, d, &ea),
        Insn::MulsdXvWv => sem_ea::sfloat(b, sem_ea::Fop::Mul, 64, d, &ea),
        Insn::SubpsXvWv => sem_ea::pfloat(b, sem_ea::Fop::Sub, 32, d, &ea),
        Insn::SubpdXvWv => sem_ea::pfloat(b, sem_ea::Fop::Sub, 64, d, &ea),
        Insn::SubssXvWv => sem_ea::sfloat(b, sem_ea::Fop::Sub, 32, d, &ea),
        Insn::SubsdXvWv => sem_ea::sfloat(b, sem_ea::Fop::Sub, 64, d, &ea),
        Insn::MinpsXvWv => sem_ea::pfloat(b, sem_ea::Fop::Min, 32, d, &ea),
        Insn::MinpdXvWv => sem_ea::pfloat(b, sem_ea::Fop::Min, 64, d, &ea),
        Insn::MinssXvWv => sem_ea::sfloat(b, sem_ea::Fop::Min, 32, d, &ea),
        Insn::MinsdXvWv => sem_ea::sfloat(b, sem_ea::Fop::Min, 64, d, &ea),
        Insn::DivpsXvWv => sem_ea::pfloat(b, sem_ea::Fop::Div, 32, d, &ea),
        Insn::DivpdXvWv => sem_ea::pfloat(b, sem_ea::Fop::Div, 64, d, &ea),
        Insn::DivssXvWv => sem_ea::sfloat(b, sem_ea::Fop::Div, 32, d, &ea),
        Insn::DivsdXvWv => sem_ea::sfloat(b, sem_ea::Fop::Div, 64, d, &ea),
        Insn::MaxpsXvWv => sem_ea::pfloat(b, sem_ea::Fop::Max, 32, d, &ea),
        Insn::MaxpdXvWv => sem_ea::pfloat(b, sem_ea::Fop::Max, 64, d, &ea),
        Insn::MaxssXvWv => sem_ea::sfloat(b, sem_ea::Fop::Max, 32, d, &ea),
        Insn::MaxsdXvWv => sem_ea::sfloat(b, sem_ea::Fop::Max, 64, d, &ea),
        // ===== VEX エンコード（AVX 基本形）=====
        Insn::Vzeroupper => sem_ea::vzero(b, false),
        Insn::Vzeroall => sem_ea::vzero(b, true),
        Insn::VmovupsXvWv | Insn::VmovupdXvWv | Insn::VmovdqaXvWv | Insn::VmovdquXvWv => {
            sem_ea::vmov_x_w(b, d, &ea)
        }
        Insn::VmovupsWvXv | Insn::VmovupdWvXv | Insn::VmovdqaWvXv | Insn::VmovdquWvXv => {
            sem_ea::vmov_w_x(b, d, &ea)
        }
        Insn::VmovssXvHvWv => sem_ea::vmovs_ld(b, d, &ea, 32),
        Insn::VmovsdXvHvWv => sem_ea::vmovs_ld(b, d, &ea, 64),
        Insn::VmovssWvHvXv => sem_ea::vmovs_st(b, d, &ea, 32),
        Insn::VmovsdWvHvXv => sem_ea::vmovs_st(b, d, &ea, 64),
        Insn::VsqrtpsXvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Sqrt, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Sqrt, 32, d, &ea)
            }
        }
        Insn::VsqrtpdXvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Sqrt, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Sqrt, 64, d, &ea)
            }
        }
        Insn::VsqrtssXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Sqrt, 32, d, &ea),
        Insn::VsqrtsdXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Sqrt, 64, d, &ea),
        Insn::VaddpsXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Add, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Add, 32, d, &ea)
            }
        }
        Insn::VaddpdXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Add, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Add, 64, d, &ea)
            }
        }
        Insn::VaddssXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Add, 32, d, &ea),
        Insn::VaddsdXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Add, 64, d, &ea),
        Insn::VmulpsXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Mul, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Mul, 32, d, &ea)
            }
        }
        Insn::VmulpdXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Mul, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Mul, 64, d, &ea)
            }
        }
        Insn::VmulssXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Mul, 32, d, &ea),
        Insn::VmulsdXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Mul, 64, d, &ea),
        Insn::VsubpsXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Sub, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Sub, 32, d, &ea)
            }
        }
        Insn::VsubpdXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Sub, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Sub, 64, d, &ea)
            }
        }
        Insn::VsubssXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Sub, 32, d, &ea),
        Insn::VsubsdXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Sub, 64, d, &ea),
        Insn::VminpsXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Min, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Min, 32, d, &ea)
            }
        }
        Insn::VminpdXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Min, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Min, 64, d, &ea)
            }
        }
        Insn::VminssXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Min, 32, d, &ea),
        Insn::VminsdXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Min, 64, d, &ea),
        Insn::VdivpsXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Div, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Div, 32, d, &ea)
            }
        }
        Insn::VdivpdXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Div, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Div, 64, d, &ea)
            }
        }
        Insn::VdivssXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Div, 32, d, &ea),
        Insn::VdivsdXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Div, 64, d, &ea),
        Insn::VmaxpsXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Max, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Max, 32, d, &ea)
            }
        }
        Insn::VmaxpdXvHvWv => {
            if d.evex {
                sem_ea::efloat(b, sem_ea::Fop::Max, d, &ea)
            } else {
                sem_ea::vpfloat(b, sem_ea::Fop::Max, 64, d, &ea)
            }
        }
        Insn::VmaxssXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Max, 32, d, &ea),
        Insn::VmaxsdXvHvWv => sem_ea::vsfloat(b, sem_ea::Fop::Max, 64, d, &ea),
        // SSE3 の水平加減算と ADDSUB の VEX 形。
        Insn::VhaddpsXvHvWv => sem_ea::vphaddsub_f(b, false, 32, d, &ea),
        Insn::VhaddpdXvHvWv => sem_ea::vphaddsub_f(b, false, 64, d, &ea),
        Insn::VhsubpsXvHvWv => sem_ea::vphaddsub_f(b, true, 32, d, &ea),
        Insn::VhsubpdXvHvWv => sem_ea::vphaddsub_f(b, true, 64, d, &ea),
        Insn::VaddsubpsXvHvWv => sem_ea::vaddsub(b, 32, d, &ea),
        Insn::VaddsubpdXvHvWv => sem_ea::vaddsub(b, 64, d, &ea),
        Insn::VandpsXvHvWv | Insn::VandpdXvHvWv | Insn::VpandXvHvWv => {
            sem_ea::vlogic(b, sem_ea::Lop::And, d, &ea)
        }
        Insn::VandnpsXvHvWv | Insn::VandnpdXvHvWv | Insn::VpandnXvHvWv => {
            sem_ea::vlogic(b, sem_ea::Lop::Andn, d, &ea)
        }
        Insn::VorpsXvHvWv | Insn::VorpdXvHvWv | Insn::VporXvHvWv => {
            sem_ea::vlogic(b, sem_ea::Lop::Or, d, &ea)
        }
        Insn::VxorpsXvHvWv | Insn::VxorpdXvHvWv | Insn::VpxorXvHvWv => {
            sem_ea::vlogic(b, sem_ea::Lop::Xor, d, &ea)
        }
        // パック整数。
        Insn::PcmpeqbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::PcmpeqwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::PcmpeqdXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::PcmpgtbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::PcmpgtwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::PcmpgtdXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::PaddqXvWv => sem_ea::pint::<B, W64>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PmullwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::MulLo, d, &ea),
        Insn::PsubusbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::SubSatU, d, &ea),
        Insn::PsubuswXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::SubSatU, d, &ea),
        Insn::PaddusbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::AddSatU, d, &ea),
        Insn::PadduswXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::AddSatU, d, &ea),
        Insn::PsubsbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::SubSatS, d, &ea),
        Insn::PsubswXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::SubSatS, d, &ea),
        Insn::PaddsbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::AddSatS, d, &ea),
        Insn::PaddswXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::AddSatS, d, &ea),
        Insn::PminubXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::MinU, d, &ea),
        Insn::PmaxubXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::MaxU, d, &ea),
        Insn::PminswXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::MinS, d, &ea),
        Insn::PmaxswXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::MaxS, d, &ea),
        Insn::PavgbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::Avg, d, &ea),
        Insn::PavgwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::Avg, d, &ea),
        Insn::PsubbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PsubwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PsubdXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PsubqXvWv => sem_ea::pint::<B, W64>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PaddbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PaddwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PadddXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PmulhuwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::MulHiU, d, &ea),
        Insn::PmulhwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::MulHiS, d, &ea),
        Insn::PmuludqXvWv => sem_ea::pmuludq(b, d, &ea),
        Insn::PmaddwdXvWv => sem_ea::pmaddwd(b, d, &ea),
        Insn::PsadbwXvWv => sem_ea::psadbw(b, d, &ea),
        // VEX の 3 オペランド・パック整数演算（B1b-1）。
        Insn::VpcmpeqbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::VpcmpeqwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::VpcmpeqdXvHvWv => sem_ea::vpint::<B, W32>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::VpcmpeqqXvHvWv => sem_ea::vpint::<B, W64>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::VpcmpgtbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::VpcmpgtwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::VpcmpgtdXvHvWv => sem_ea::vpint::<B, W32>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::VpcmpgtqXvHvWv => sem_ea::vpint::<B, W64>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::VpaddqXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::Add, d, &ea)
            } else {
                sem_ea::vpint::<B, W64>(b, sem_ea::Iop::Add, d, &ea)
            }
        }
        Insn::VpmullwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::MulLo, d, &ea),
        Insn::VpmulldXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::MulLo, d, &ea)
            } else {
                sem_ea::vpint::<B, W32>(b, sem_ea::Iop::MulLo, d, &ea)
            }
        }
        Insn::VpmulhuwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::MulHiU, d, &ea),
        Insn::VpmulhwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::MulHiS, d, &ea),
        Insn::VpavgbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::Avg, d, &ea),
        Insn::VpavgwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::Avg, d, &ea),
        Insn::VpsubusbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::SubSatU, d, &ea),
        Insn::VpsubuswXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::SubSatU, d, &ea),
        Insn::VpaddusbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::AddSatU, d, &ea),
        Insn::VpadduswXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::AddSatU, d, &ea),
        Insn::VpsubsbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::SubSatS, d, &ea),
        Insn::VpsubswXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::SubSatS, d, &ea),
        Insn::VpaddsbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::AddSatS, d, &ea),
        Insn::VpaddswXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::AddSatS, d, &ea),
        Insn::VpminubXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::MinU, d, &ea),
        Insn::VpmaxubXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::MaxU, d, &ea),
        Insn::VpminswXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::MinS, d, &ea),
        Insn::VpmaxswXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::MaxS, d, &ea),
        Insn::VpminsbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::MinS, d, &ea),
        Insn::VpminsdXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::MinS, d, &ea)
            } else {
                sem_ea::vpint::<B, W32>(b, sem_ea::Iop::MinS, d, &ea)
            }
        }
        Insn::VpminuwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::MinU, d, &ea),
        Insn::VpminudXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::MinU, d, &ea)
            } else {
                sem_ea::vpint::<B, W32>(b, sem_ea::Iop::MinU, d, &ea)
            }
        }
        Insn::VpmaxsbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::MaxS, d, &ea),
        Insn::VpmaxsdXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::MaxS, d, &ea)
            } else {
                sem_ea::vpint::<B, W32>(b, sem_ea::Iop::MaxS, d, &ea)
            }
        }
        Insn::VpmaxuwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::MaxU, d, &ea),
        Insn::VpmaxudXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::MaxU, d, &ea)
            } else {
                sem_ea::vpint::<B, W32>(b, sem_ea::Iop::MaxU, d, &ea)
            }
        }
        Insn::VpsignbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::Sign, d, &ea),
        Insn::VpsignwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::Sign, d, &ea),
        Insn::VpsigndXvHvWv => sem_ea::vpint::<B, W32>(b, sem_ea::Iop::Sign, d, &ea),
        Insn::VpsubbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::VpsubwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::VpsubdXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::Sub, d, &ea)
            } else {
                sem_ea::vpint::<B, W32>(b, sem_ea::Iop::Sub, d, &ea)
            }
        }
        Insn::VpsubqXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::Sub, d, &ea)
            } else {
                sem_ea::vpint::<B, W64>(b, sem_ea::Iop::Sub, d, &ea)
            }
        }
        Insn::VpaddbXvHvWv => sem_ea::vpint::<B, W8>(b, sem_ea::Iop::Add, d, &ea),
        Insn::VpaddwXvHvWv => sem_ea::vpint::<B, W16>(b, sem_ea::Iop::Add, d, &ea),
        Insn::VpadddXvHvWv => {
            if d.evex {
                sem_ea::eint(b, sem_ea::Iop::Add, d, &ea)
            } else {
                sem_ea::vpint::<B, W32>(b, sem_ea::Iop::Add, d, &ea)
            }
        }
        // EVEX 専用の FVM 項目（同名 VEX 変種が無いもの）。
        Insn::VpmullqXvHvWv => sem_ea::eint(b, sem_ea::Iop::MulLo, d, &ea),
        Insn::VpminsqXvHvWv => sem_ea::eint(b, sem_ea::Iop::MinS, d, &ea),
        Insn::VpminuqXvHvWv => sem_ea::eint(b, sem_ea::Iop::MinU, d, &ea),
        Insn::VpmaxsqXvHvWv => sem_ea::eint(b, sem_ea::Iop::MaxS, d, &ea),
        Insn::VpmaxuqXvHvWv => sem_ea::eint(b, sem_ea::Iop::MaxU, d, &ea),
        Insn::VpanddXvHvWv | Insn::VpandqXvHvWv => sem_ea::elogic(b, sem_ea::Lop::And, d, &ea),
        Insn::VpandndXvHvWv | Insn::VpandnqXvHvWv => sem_ea::elogic(b, sem_ea::Lop::Andn, d, &ea),
        Insn::VpordXvHvWv | Insn::VporqXvHvWv => sem_ea::elogic(b, sem_ea::Lop::Or, d, &ea),
        Insn::VpxordXvHvWv | Insn::VpxorqXvHvWv => sem_ea::elogic(b, sem_ea::Lop::Xor, d, &ea),
        Insn::VpabsqXvWv => sem_ea::eabs(b, d, &ea),
        Insn::VpsrlwXvHvWv => sem_ea::vpshift::<B, W16>(b, sem_ea::Psh::R, d, &ea),
        Insn::VpsrldXvHvWv => sem_ea::vpshift::<B, W32>(b, sem_ea::Psh::R, d, &ea),
        Insn::VpsrlqXvHvWv => sem_ea::vpshift::<B, W64>(b, sem_ea::Psh::R, d, &ea),
        Insn::VpsrawXvHvWv => sem_ea::vpshift::<B, W16>(b, sem_ea::Psh::A, d, &ea),
        Insn::VpsradXvHvWv => sem_ea::vpshift::<B, W32>(b, sem_ea::Psh::A, d, &ea),
        Insn::VpsllwXvHvWv => sem_ea::vpshift::<B, W16>(b, sem_ea::Psh::L, d, &ea),
        Insn::VpslldXvHvWv => sem_ea::vpshift::<B, W32>(b, sem_ea::Psh::L, d, &ea),
        Insn::VpsllqXvHvWv => sem_ea::vpshift::<B, W64>(b, sem_ea::Psh::L, d, &ea),
        Insn::VpsllvdXvHvWv => sem_ea::vpshiftv::<B, W32>(b, sem_ea::Psh::L, d, &ea),
        Insn::VpsllvqXvHvWv => sem_ea::vpshiftv::<B, W64>(b, sem_ea::Psh::L, d, &ea),
        Insn::VpsrlvdXvHvWv => sem_ea::vpshiftv::<B, W32>(b, sem_ea::Psh::R, d, &ea),
        Insn::VpsrlvqXvHvWv => sem_ea::vpshiftv::<B, W64>(b, sem_ea::Psh::R, d, &ea),
        Insn::VpsravdXvHvWv => sem_ea::vpshiftv::<B, W32>(b, sem_ea::Psh::A, d, &ea),
        Insn::VpsrlwHvWvIb => sem_ea::vpshift_i::<B, W16>(b, sem_ea::Psh::R, d),
        Insn::VpsrldHvWvIb => sem_ea::vpshift_i::<B, W32>(b, sem_ea::Psh::R, d),
        Insn::VpsrlqHvWvIb => sem_ea::vpshift_i::<B, W64>(b, sem_ea::Psh::R, d),
        Insn::VpsrawHvWvIb => sem_ea::vpshift_i::<B, W16>(b, sem_ea::Psh::A, d),
        Insn::VpsradHvWvIb => sem_ea::vpshift_i::<B, W32>(b, sem_ea::Psh::A, d),
        Insn::VpsllwHvWvIb => sem_ea::vpshift_i::<B, W16>(b, sem_ea::Psh::L, d),
        Insn::VpslldHvWvIb => sem_ea::vpshift_i::<B, W32>(b, sem_ea::Psh::L, d),
        Insn::VpsllqHvWvIb => sem_ea::vpshift_i::<B, W64>(b, sem_ea::Psh::L, d),
        Insn::VpsrldqHvWvIb => sem_ea::vbyteshift(b, false, d),
        Insn::VpslldqHvWvIb => sem_ea::vbyteshift(b, true, d),
        // VEX のデータ移動（B1b-2）。整列形は非整列と同じ移動。
        Insn::VmovapsXvWv | Insn::VmovapdXvWv => sem_ea::vmov_x_w(b, d, &ea),
        Insn::VmovapsWvXv | Insn::VmovapdWvXv => sem_ea::vmov_w_x(b, d, &ea),
        Insn::VmovlpsXvHvWv | Insn::VmovlpdXvHvWv => sem_ea::vmovl_ld(b, d, &ea),
        Insn::VmovlpsWvXv | Insn::VmovlpdWvXv => sem_ea::movl_st(b, d, &ea),
        Insn::VmovhpsXvHvWv | Insn::VmovhpdXvHvWv => sem_ea::vmovh_ld(b, d, &ea),
        Insn::VmovhpsWvXv | Insn::VmovhpdWvXv => sem_ea::movh_st(b, d, &ea),
        Insn::VmovlhpsXvHvWv => sem_ea::vmovlhps(b, d, &ea),
        Insn::VmovhlpsXvHvWv => sem_ea::vmovhlps(b, d, &ea),
        Insn::VmovddupXvWv => sem_ea::vmovddup(b, d, &ea),
        Insn::VmovsldupXvWv => sem_ea::vdupps(b, false, d, &ea),
        Insn::VrsqrtpsXvWv => sem_ea::vrcp_rs(b, true, d, &ea),
        Insn::VrcppsXvWv => sem_ea::vrcp_rs(b, false, d, &ea),
        Insn::VrsqrtssXvHvWv => sem_ea::vrcp_rs_s(b, true, d, &ea),
        Insn::VrcpssXvHvWv => sem_ea::vrcp_rs_s(b, false, d, &ea),
        Insn::VmaskmovdquXvWv => sem_ea::maskmovdqu(b, d, &ea, seg),
        Insn::VmovshdupXvWv => sem_ea::vdupps(b, true, d, &ea),
        Insn::VmovmskpsGvWv => sem_ea::vmovmsk(b, 32, d, &ea),
        Insn::VmovmskpdGvWv => sem_ea::vmovmsk(b, 64, d, &ea),
        Insn::VpmovmskbGvWv => sem_ea::vmovmsk(b, 8, d, &ea),
        Insn::VmovntpsWvXv | Insn::VmovntpdWvXv | Insn::VmovntdqWvXv => sem_ea::vmov_w_x(b, d, &ea),
        Insn::VldmxcsrMd => sem_ea::ldmxcsr(b, &ea),
        Insn::VstmxcsrMd => sem_ea::stmxcsr(b, &ea),
        Insn::VmovdXvEv | Insn::VmovqXvEq | Insn::VmovdW1XvEv => sem_ea::vmovd_x_e(b, d, &ea),
        Insn::VmovdEvXv | Insn::VmovqEqXv | Insn::VmovdW1EvXv => sem_ea::movd_e_x(b, d, &ea),
        Insn::VmovqXvWv => sem_ea::vmovq_x_w(b, d, &ea),
        Insn::VmovqWvXv => sem_ea::vmovq_w_x(b, d, &ea),
        Insn::VlddquXvMv => sem_ea::vmov_x_w(b, d, &ea),
        // VEX の比較（32 述語）。
        Insn::VcmppsXvHvWvIb => sem_ea::vpfloat(b, sem_ea::Fop::Cmp(d.imm as u8), 32, d, &ea),
        Insn::VcmppdXvHvWvIb => sem_ea::vpfloat(b, sem_ea::Fop::Cmp(d.imm as u8), 64, d, &ea),
        Insn::VcmpssXvHvWvIb => sem_ea::vsfloat(b, sem_ea::Fop::Cmp(d.imm as u8), 32, d, &ea),
        Insn::VcmpsdXvHvWvIb => sem_ea::vsfloat(b, sem_ea::Fop::Cmp(d.imm as u8), 64, d, &ea),
        // VEX の乗算・絶対差分和（B1b-2）。
        Insn::VpmuludqXvHvWv => sem_ea::vpmuludq(b, d, &ea),
        Insn::VpmuldqXvHvWv => sem_ea::vpmuldq(b, d, &ea),
        Insn::VpmaddwdXvHvWv => sem_ea::vpmaddwd(b, d, &ea),
        Insn::VpsadbwXvHvWv => sem_ea::vpsadbw(b, d, &ea),
        // VEX の SSSE3 系・テスト系（B1b-2）。
        Insn::VphaddwXvHvWv => sem_ea::vphaddsub::<B, W16>(b, false, false, d, &ea),
        Insn::VphadddXvHvWv => sem_ea::vphaddsub::<B, W32>(b, false, false, d, &ea),
        Insn::VphaddswXvHvWv => sem_ea::vphaddsub::<B, W16>(b, false, true, d, &ea),
        Insn::VphsubwXvHvWv => sem_ea::vphaddsub::<B, W16>(b, true, false, d, &ea),
        Insn::VphsubdXvHvWv => sem_ea::vphaddsub::<B, W32>(b, true, false, d, &ea),
        Insn::VphsubswXvHvWv => sem_ea::vphaddsub::<B, W16>(b, true, true, d, &ea),
        Insn::VpmaddubswXvHvWv => sem_ea::vpmaddubsw(b, d, &ea),
        Insn::VpmulhrswXvHvWv => sem_ea::vpmulhrsw(b, d, &ea),
        Insn::VptestXvWv => sem_ea::vptest(b, d, &ea),
        Insn::VtestpsXvWv => sem_ea::vtestf(b, d, 32, &ea),
        Insn::VtestpdXvWv => sem_ea::vtestf(b, d, 64, &ea),
        Insn::VpabsbXvWv => sem_ea::vpabs::<B, W8>(b, d, &ea),
        Insn::VpabswXvWv => sem_ea::vpabs::<B, W16>(b, d, &ea),
        Insn::VpabsdXvWv => {
            if d.evex {
                sem_ea::eabs(b, d, &ea)
            } else {
                sem_ea::vpabs::<B, W32>(b, d, &ea)
            }
        }
        Insn::VphminposuwXvWv => sem_ea::vphminposuw(b, d, &ea),
        // VCVT 系（パック変換）。
        Insn::Vcvtps2pdXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::Ps2Pd, d, &ea),
        Insn::Vcvtpd2psXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::Pd2Ps, d, &ea),
        Insn::Vcvtdq2psXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::Dq2Ps, d, &ea),
        Insn::Vcvtps2dqXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::Ps2Dq, d, &ea),
        Insn::Vcvttps2dqXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::TPs2Dq, d, &ea),
        Insn::Vcvtpd2dqXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::Pd2Dq, d, &ea),
        Insn::Vcvttpd2dqXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::TPd2Dq, d, &ea),
        Insn::Vcvtdq2pdXvWv => sem_ea::vcvtp(b, sem_ea::CvtK::Dq2Pd, d, &ea),
        // VCVT 系（スカラ・GPR 変換）。
        Insn::Vcvtss2sdXvHvWv => sem_ea::vcvtsf(b, true, d, &ea),
        Insn::Vcvtsd2ssXvHvWv => sem_ea::vcvtsf(b, false, d, &ea),
        Insn::Vcvtsi2ssXvHvEv => sem_ea::vcvtsi(b, 32, d, &ea),
        Insn::Vcvtsi2sdXvHvEv => sem_ea::vcvtsi(b, 64, d, &ea),
        Insn::Vcvttss2siGvWv => sem_ea::cvtf2i(b, 32, true, d, &ea, reg),
        Insn::Vcvttsd2siGvWv => sem_ea::cvtf2i(b, 64, true, d, &ea, reg),
        Insn::Vcvtss2siGvWv => sem_ea::cvtf2i(b, 32, false, d, &ea, reg),
        Insn::Vcvtsd2siGvWv => sem_ea::cvtf2i(b, 64, false, d, &ea, reg),
        // レガシー xmm 形の 5B/E6（マップ駆動に移行）。
        Insn::Cvtdq2psXvWv => sem_ea::pcvtp(b, sem_ea::CvtK::Dq2Ps, d, &ea),
        Insn::Cvtps2dqXvWv => sem_ea::pcvtp(b, sem_ea::CvtK::Ps2Dq, d, &ea),
        Insn::Cvttps2dqXvWv => sem_ea::pcvtp(b, sem_ea::CvtK::TPs2Dq, d, &ea),
        Insn::Cvtpd2dqXvWv => sem_ea::pcvtp(b, sem_ea::CvtK::Pd2Dq, d, &ea),
        Insn::Cvttpd2dqXvWv => sem_ea::pcvtp(b, sem_ea::CvtK::TPd2Dq, d, &ea),
        Insn::Cvtdq2pdXvWv => sem_ea::pcvtp(b, sem_ea::CvtK::Dq2Pd, d, &ea),
        // VEX シャッフル・アンパック・パック。
        Insn::VshufpsXvHvWvIb => sem_ea::vshufp(b, false, d.imm as u8, d, &ea),
        Insn::VshufpdXvHvWvIb => sem_ea::vshufp(b, true, d.imm as u8, d, &ea),
        Insn::VpshufdXvWvIb => sem_ea::vpshuf(b, 0, d.imm as u8, d, &ea),
        Insn::VpshufhwXvWvIb => sem_ea::vpshuf(b, 1, d.imm as u8, d, &ea),
        Insn::VpshuflwXvWvIb => sem_ea::vpshuf(b, 2, d.imm as u8, d, &ea),
        Insn::VpshufbXvHvWv => sem_ea::vpshufb(b, d, &ea),
        Insn::VunpcklpsXvHvWv => sem_ea::vpunpck(b, 32, false, d, &ea),
        Insn::VunpckhpsXvHvWv => sem_ea::vpunpck(b, 32, true, d, &ea),
        Insn::VunpcklpdXvHvWv => sem_ea::vpunpck(b, 64, false, d, &ea),
        Insn::VunpckhpdXvHvWv => sem_ea::vpunpck(b, 64, true, d, &ea),
        Insn::VpunpcklbwXvHvWv => sem_ea::vpunpck(b, 8, false, d, &ea),
        Insn::VpunpcklwdXvHvWv => sem_ea::vpunpck(b, 16, false, d, &ea),
        Insn::VpunpckldqXvHvWv => sem_ea::vpunpck(b, 32, false, d, &ea),
        Insn::VpunpcklqdqXvHvWv => sem_ea::vpunpck(b, 64, false, d, &ea),
        Insn::VpunpckhbwXvHvWv => sem_ea::vpunpck(b, 8, true, d, &ea),
        Insn::VpunpckhwdXvHvWv => sem_ea::vpunpck(b, 16, true, d, &ea),
        Insn::VpunpckhdqXvHvWv => sem_ea::vpunpck(b, 32, true, d, &ea),
        Insn::VpunpckhqdqXvHvWv => sem_ea::vpunpck(b, 64, true, d, &ea),
        Insn::VpacksswbXvHvWv => sem_ea::vpack::<B, W16>(b, false, d, &ea),
        Insn::VpackssdwXvHvWv => sem_ea::vpack::<B, W32>(b, false, d, &ea),
        Insn::VpackuswbXvHvWv => sem_ea::vpack::<B, W16>(b, true, d, &ea),
        Insn::VpackusdwXvHvWv => sem_ea::vpack::<B, W32>(b, true, d, &ea),
        // B1b-4a: blend・dpp・round・extend・insert/extract・permute・broadcast。
        Insn::VblendpsXvHvWvIb => sem_ea::vblendp(b, 32, d.imm as u8, d, &ea),
        Insn::VblendpdXvHvWvIb => sem_ea::vblendp(b, 64, d.imm as u8, d, &ea),
        Insn::VpblendwXvHvWvIb => sem_ea::vblendp(b, 16, d.imm as u8, d, &ea),
        Insn::VpblenddXvHvWvIb => sem_ea::vpblendd(b, d.imm as u8, d, &ea),
        Insn::VpclmulqdqXvHvWvIb => sem_ea::vpclmulqdq(b, d.imm as u8, d, &ea),
        Insn::Vpmadd52luqXvHvWv => sem_ea::vpmadd52(b, false, d, &ea),
        Insn::Vpmadd52huqXvHvWv => sem_ea::vpmadd52(b, true, d, &ea),
        Insn::VpdpbuudXvHvWv => sem_ea::vpdp(b, 8, false, false, false, d, &ea),
        Insn::VpdpbusdXvHvWv => sem_ea::vpdp(b, 8, false, true, false, d, &ea),
        Insn::VpdpbsudXvHvWv => sem_ea::vpdp(b, 8, true, false, false, d, &ea),
        Insn::VpdpbssdXvHvWv => sem_ea::vpdp(b, 8, true, true, false, d, &ea),
        Insn::VpdpbuudsXvHvWv => sem_ea::vpdp(b, 8, false, false, true, d, &ea),
        Insn::VpdpbusdsXvHvWv => sem_ea::vpdp(b, 8, false, true, true, d, &ea),
        Insn::VpdpbsudsXvHvWv => sem_ea::vpdp(b, 8, true, false, true, d, &ea),
        Insn::VpdpbssdsXvHvWv => sem_ea::vpdp(b, 8, true, true, true, d, &ea),
        Insn::VpdpwuudXvHvWv => sem_ea::vpdp(b, 16, false, false, false, d, &ea),
        Insn::VpdpwusdXvHvWv => sem_ea::vpdp(b, 16, false, true, false, d, &ea),
        Insn::VpdpwsudXvHvWv => sem_ea::vpdp(b, 16, true, false, false, d, &ea),
        Insn::VpdpwssdXvHvWv => sem_ea::vpdp(b, 16, true, true, false, d, &ea),
        Insn::VpdpwuudsXvHvWv => sem_ea::vpdp(b, 16, false, false, true, d, &ea),
        Insn::VpdpwusdsXvHvWv => sem_ea::vpdp(b, 16, false, true, true, d, &ea),
        Insn::VpdpwsudsXvHvWv => sem_ea::vpdp(b, 16, true, false, true, d, &ea),
        Insn::VpdpwssdsXvHvWv => sem_ea::vpdp(b, 16, true, true, true, d, &ea),
        Insn::VaesencXvHvWv => sem_ea::vaesround(b, 0, d, &ea),
        Insn::VaesenclastXvHvWv => sem_ea::vaesround(b, 1, d, &ea),
        Insn::VaesdecXvHvWv => sem_ea::vaesround(b, 2, d, &ea),
        Insn::VaesdeclastXvHvWv => sem_ea::vaesround(b, 3, d, &ea),
        Insn::VaesimcXvWv => sem_ea::vaesimc(b, d, &ea),
        Insn::Vgf2p8mulbXvHvWv => sem_ea::vgf2p8mulb(b, d, &ea),
        Insn::Vgf2p8affineqbXvHvWvIb => sem_ea::vgf2p8affine(b, false, d.imm as u8, d, &ea),
        Insn::Vgf2p8affineinvqbXvHvWvIb => sem_ea::vgf2p8affine(b, true, d.imm as u8, d, &ea),
        Insn::VaeskeygenassistXvWvIb => sem_ea::vaeskeygenassist(b, d.imm as u8, d, &ea),
        Insn::VblendvpsXvHvWvIb => sem_ea::vblendv(b, 32, d, &ea),
        Insn::VblendvpdXvHvWvIb => sem_ea::vblendv(b, 64, d, &ea),
        Insn::VpblendvbXvHvWvIb => sem_ea::vblendv(b, 8, d, &ea),
        Insn::VdppsXvHvWvIb => sem_ea::vdpp(b, 32, d.imm as u8, d, &ea),
        Insn::VdppdXvHvWvIb => sem_ea::vdpp(b, 64, d.imm as u8, d, &ea),
        Insn::VmpsadbwXvHvWvIb => sem_ea::vmpsadbw(b, d.imm as u8, d, &ea),
        Insn::VpalignrXvHvWvIb => sem_ea::vpalignr(b, d.imm as u8, d, &ea),
        Insn::VroundpsXvWvIb => sem_ea::vroundp(b, 32, d.imm as u8, d, &ea),
        Insn::VroundpdXvWvIb => sem_ea::vroundp(b, 64, d.imm as u8, d, &ea),
        Insn::VroundssXvHvWvIb => sem_ea::vrounds(b, 32, d.imm as u8, d, &ea),
        Insn::VroundsdXvHvWvIb => sem_ea::vrounds(b, 64, d.imm as u8, d, &ea),
        Insn::VinsertpsXvHvWvIb => sem_ea::vinsertps(b, d.imm as u8, d, &ea),
        Insn::VpinsrbXvHvEbIb => sem_ea::vpinsrx(b, 8, d.imm as u8, d, &ea),
        Insn::VpinsrwXvHvEwIb => sem_ea::vpinsrx(b, 16, d.imm as u8, d, &ea),
        Insn::VpinsrdXvHvEvIb => {
            sem_ea::vpinsrx(b, if d.rex & 8 != 0 { 64 } else { 32 }, d.imm as u8, d, &ea)
        }
        Insn::VpinsrqXvHvEqIb => sem_ea::vpinsrx(b, 64, d.imm as u8, d, &ea),
        Insn::VpinsrdW1XvHvEvIb => sem_ea::vpinsrx(b, 32, d.imm as u8, d, &ea),
        Insn::VpextrbEbXvIb => sem_ea::pextrx(b, 8, d.imm as u8, d, &ea),
        Insn::VpextrwEwXvIb => sem_ea::pextrx(b, 16, d.imm as u8, d, &ea),
        Insn::VpextrwGvWvIb => sem_ea::pextrw(b, d.imm as u8, d, &ea, reg),
        Insn::VpextrdEvXvIb => {
            sem_ea::pextrx(b, if d.rex & 8 != 0 { 64 } else { 32 }, d.imm as u8, d, &ea)
        }
        Insn::VpextrdW1EvXvIb => sem_ea::pextrx(b, 32, d.imm as u8, d, &ea),
        Insn::VpextrqEqXvIb => sem_ea::pextrx(b, 64, d.imm as u8, d, &ea),
        Insn::VextractpsEdXvIb => sem_ea::pextrx(b, 32, d.imm as u8, d, &ea),
        Insn::VpmovsxbwXvWv => sem_ea::vpmovx(b, 8, 16, true, d, &ea),
        Insn::VpmovsxbdXvWv => sem_ea::vpmovx(b, 8, 32, true, d, &ea),
        Insn::VpmovsxbqXvWv => sem_ea::vpmovx(b, 8, 64, true, d, &ea),
        Insn::VpmovsxwdXvWv => sem_ea::vpmovx(b, 16, 32, true, d, &ea),
        Insn::VpmovsxwqXvWv => sem_ea::vpmovx(b, 16, 64, true, d, &ea),
        Insn::VpmovsxdqXvWv => sem_ea::vpmovx(b, 32, 64, true, d, &ea),
        Insn::VpmovzxbwXvWv => sem_ea::vpmovx(b, 8, 16, false, d, &ea),
        Insn::VpmovzxbdXvWv => sem_ea::vpmovx(b, 8, 32, false, d, &ea),
        Insn::VpmovzxbqXvWv => sem_ea::vpmovx(b, 8, 64, false, d, &ea),
        Insn::VpmovzxwdXvWv => sem_ea::vpmovx(b, 16, 32, false, d, &ea),
        Insn::VpmovzxwqXvWv => sem_ea::vpmovx(b, 16, 64, false, d, &ea),
        Insn::VpmovzxdqXvWv => sem_ea::vpmovx(b, 32, 64, false, d, &ea),
        Insn::VmovntdqaXvWv => sem_ea::vmovntdqa(b, d, &ea),
        Insn::VpermilpsXvWvIb => sem_ea::vpermilp_i(b, 32, d.imm as u8, d, &ea),
        Insn::VpermilpdXvWvIb => sem_ea::vpermilp_i(b, 64, d.imm as u8, d, &ea),
        Insn::VpermilpsXvHvWv => sem_ea::vpermilp_v(b, 32, d, &ea),
        Insn::VpermilpdXvHvWv => sem_ea::vpermilp_v(b, 64, d, &ea),
        Insn::Vpermil2psXvHvWvIv => sem_ea::vpermil2(b, 32, d, &ea),
        Insn::Vpermil2pdXvHvWvIv => sem_ea::vpermil2(b, 64, d, &ea),
        Insn::Vperm2f128XvHvWvIb => sem_ea::vperm2x128(b, d.imm as u8, d, &ea),
        Insn::Vperm2i128XvHvWvIb => sem_ea::vperm2x128(b, d.imm as u8, d, &ea),
        Insn::VpermpsXvHvWv => sem_ea::vpermd(b, d, &ea),
        Insn::VpermdXvHvWv => sem_ea::vpermd(b, d, &ea),
        Insn::VpermqXvWvIb | Insn::VpermpdXvWvIb => sem_ea::vpermq(b, d.imm as u8, d, &ea),
        Insn::Vinsertf128XvHvWvIb => sem_ea::vinsertx128(b, d.imm as u8, d, &ea),
        Insn::Vinserti128XvHvWvIb => sem_ea::vinsertx128(b, d.imm as u8, d, &ea),
        Insn::Vextractf128WvXvIb => sem_ea::vextractx128(b, d.imm as u8, d, &ea),
        Insn::Vextracti128WvXvIb => sem_ea::vextractx128(b, d.imm as u8, d, &ea),
        Insn::VbroadcastssXvWv => sem_ea::vbcastss(b, d, &ea),
        Insn::VbroadcastssXvXv => sem_ea::vbcastss(b, d, &ea),
        Insn::VbroadcastsdXvWv => sem_ea::vbcastsd(b, d, &ea),
        Insn::VbroadcastsdXvXv => sem_ea::vbcastsd(b, d, &ea),
        Insn::Vbroadcastf128XvWv => sem_ea::vbcastx128(b, d, &ea),
        Insn::Vbroadcasti128XvWv => sem_ea::vbcastx128(b, d, &ea),
        Insn::VpbroadcastbXvWv => sem_ea::vpbroadcast(b, 8, d, &ea),
        Insn::VpbroadcastwXvWv => sem_ea::vpbroadcast(b, 16, d, &ea),
        Insn::VpbroadcastdXvWv => sem_ea::vpbroadcast(b, 32, d, &ea),
        Insn::VpbroadcastqXvWv => sem_ea::vpbroadcast(b, 64, d, &ea),
        // B1b-4b: VMASKMOV（ロード/ストア）と VGATHER（VSIB）。
        Insn::VmaskmovpsXvHvWv => sem_ea::vmaskmov_ld(b, 32, d, &ea),
        Insn::VmaskmovpdXvHvWv => sem_ea::vmaskmov_ld(b, 64, d, &ea),
        Insn::VmaskmovpsWvHvXv => sem_ea::vmaskmov_st(b, 32, d, &ea),
        Insn::VmaskmovpdWvHvXv => sem_ea::vmaskmov_st(b, 64, d, &ea),
        Insn::VpmaskmovdXvHvWv => sem_ea::vmaskmov_ld(b, 32, d, &ea),
        Insn::VpmaskmovdWvHvXv => sem_ea::vmaskmov_st(b, 32, d, &ea),
        Insn::VpmaskmovqXvHvWv => sem_ea::vmaskmov_ld(b, 64, d, &ea),
        Insn::VpmaskmovqWvHvXv => sem_ea::vmaskmov_st(b, 64, d, &ea),
        Insn::VpgatherddXvWvHv => sem_ea::vgather(b, false, d, seg),
        Insn::VpgatherqdXvWvHv => sem_ea::vgather(b, true, d, seg),
        Insn::VgatherdpsXvWvHv => sem_ea::vgather(b, false, d, seg),
        Insn::VgatherqpsXvWvHv => sem_ea::vgather(b, true, d, seg),
        // B1c-1: BMI1/BMI2（VEX の GPR 演算）と TZCNT。
        Insn::AndnGvByEv => sem_ea::andn(b, vw, reg, &ea, d),
        Insn::BlsrByEv => sem_ea::bls(b, vw, 1, &ea, d),
        Insn::BlsmskByEv => sem_ea::bls(b, vw, 2, &ea, d),
        Insn::BlsiByEv => sem_ea::bls(b, vw, 3, &ea, d),
        Insn::BextrGvEvBy => sem_ea::bextr(b, vw, reg, &ea, d),
        Insn::BzhiGvEvBy => sem_ea::bzhi(b, vw, reg, &ea, d),
        Insn::PdepGvByEv => sem_ea::pdep(b, vw, reg, &ea, d),
        Insn::PextGvByEv => sem_ea::pext(b, vw, reg, &ea, d),
        Insn::MulxGvByEv => sem_ea::vmulx(b, vw, reg, &ea, d),
        Insn::ShlxGvEvBy => sem_ea::vshiftx(b, vw, 0, reg, &ea, d),
        Insn::ShrxGvEvBy => sem_ea::vshiftx(b, vw, 1, reg, &ea, d),
        Insn::SarxGvEvBy => sem_ea::vshiftx(b, vw, 2, reg, &ea, d),
        Insn::RorxGvEvIb => sem_ea::rorx(b, vw, reg, &ea, d),
        Insn::TzcntGvEv => sem_ea::tzcnt(b, w, reg, &ea, d),
        // B1c-2: FMA（132/213/231 × 6 演算 × パック/スカラ）。
        // 要素幅は VEX.W（0=PS/SS、1=PD/SD）。
        Insn::Vfmadd132psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 0, 0, d, &ea),
        Insn::Vfmsub132psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 1, 0, d, &ea),
        Insn::Vfnmadd132psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 2, 0, d, &ea),
        Insn::Vfnmsub132psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 3, 0, d, &ea),
        Insn::Vfmaddsub132psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 4, 0, d, &ea),
        Insn::Vfmsubadd132psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 5, 0, d, &ea),
        Insn::Vfmadd213psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 0, 1, d, &ea),
        Insn::Vfmsub213psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 1, 1, d, &ea),
        Insn::Vfnmadd213psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 2, 1, d, &ea),
        Insn::Vfnmsub213psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 3, 1, d, &ea),
        Insn::Vfmaddsub213psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 4, 1, d, &ea),
        Insn::Vfmsubadd213psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 5, 1, d, &ea),
        Insn::Vfmadd231psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 0, 2, d, &ea),
        Insn::Vfmsub231psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 1, 2, d, &ea),
        Insn::Vfnmadd231psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 2, 2, d, &ea),
        Insn::Vfnmsub231psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 3, 2, d, &ea),
        Insn::Vfmaddsub231psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 4, 2, d, &ea),
        Insn::Vfmsubadd231psXvHvWv => sem_ea::vfma(b, d.vex_w, false, 5, 2, d, &ea),
        Insn::Vfmadd132ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 0, 0, d, &ea),
        Insn::Vfmsub132ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 1, 0, d, &ea),
        Insn::Vfnmadd132ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 2, 0, d, &ea),
        Insn::Vfnmsub132ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 3, 0, d, &ea),
        Insn::Vfmadd213ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 0, 1, d, &ea),
        Insn::Vfmsub213ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 1, 1, d, &ea),
        Insn::Vfnmadd213ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 2, 1, d, &ea),
        Insn::Vfnmsub213ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 3, 1, d, &ea),
        Insn::Vfmadd231ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 0, 2, d, &ea),
        Insn::Vfmsub231ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 1, 2, d, &ea),
        Insn::Vfnmadd231ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 2, 2, d, &ea),
        Insn::Vfnmsub231ssXvHvWv => sem_ea::vfma(b, d.vex_w, true, 3, 2, d, &ea),
        Insn::Vfmadd132pdXvHvWv => sem_ea::vfma(b, true, false, 0, 0, d, &ea),
        Insn::Vfmsub132pdXvHvWv => sem_ea::vfma(b, true, false, 1, 0, d, &ea),
        Insn::Vfnmadd132pdXvHvWv => sem_ea::vfma(b, true, false, 2, 0, d, &ea),
        Insn::Vfnmsub132pdXvHvWv => sem_ea::vfma(b, true, false, 3, 0, d, &ea),
        Insn::Vfmaddsub132pdXvHvWv => sem_ea::vfma(b, true, false, 4, 0, d, &ea),
        Insn::Vfmsubadd132pdXvHvWv => sem_ea::vfma(b, true, false, 5, 0, d, &ea),
        Insn::Vfmadd213pdXvHvWv => sem_ea::vfma(b, true, false, 0, 1, d, &ea),
        Insn::Vfmsub213pdXvHvWv => sem_ea::vfma(b, true, false, 1, 1, d, &ea),
        Insn::Vfnmadd213pdXvHvWv => sem_ea::vfma(b, true, false, 2, 1, d, &ea),
        Insn::Vfnmsub213pdXvHvWv => sem_ea::vfma(b, true, false, 3, 1, d, &ea),
        Insn::Vfmaddsub213pdXvHvWv => sem_ea::vfma(b, true, false, 4, 1, d, &ea),
        Insn::Vfmsubadd213pdXvHvWv => sem_ea::vfma(b, true, false, 5, 1, d, &ea),
        Insn::Vfmadd231pdXvHvWv => sem_ea::vfma(b, true, false, 0, 2, d, &ea),
        Insn::Vfmsub231pdXvHvWv => sem_ea::vfma(b, true, false, 1, 2, d, &ea),
        Insn::Vfnmadd231pdXvHvWv => sem_ea::vfma(b, true, false, 2, 2, d, &ea),
        Insn::Vfnmsub231pdXvHvWv => sem_ea::vfma(b, true, false, 3, 2, d, &ea),
        Insn::Vfmaddsub231pdXvHvWv => sem_ea::vfma(b, true, false, 4, 2, d, &ea),
        Insn::Vfmsubadd231pdXvHvWv => sem_ea::vfma(b, true, false, 5, 2, d, &ea),
        Insn::Vfmadd132sdXvHvWv => sem_ea::vfma(b, true, true, 0, 0, d, &ea),
        Insn::Vfmsub132sdXvHvWv => sem_ea::vfma(b, true, true, 1, 0, d, &ea),
        Insn::Vfnmadd132sdXvHvWv => sem_ea::vfma(b, true, true, 2, 0, d, &ea),
        Insn::Vfnmsub132sdXvHvWv => sem_ea::vfma(b, true, true, 3, 0, d, &ea),
        Insn::Vfmadd213sdXvHvWv => sem_ea::vfma(b, true, true, 0, 1, d, &ea),
        Insn::Vfmsub213sdXvHvWv => sem_ea::vfma(b, true, true, 1, 1, d, &ea),
        Insn::Vfnmadd213sdXvHvWv => sem_ea::vfma(b, true, true, 2, 1, d, &ea),
        Insn::Vfnmsub213sdXvHvWv => sem_ea::vfma(b, true, true, 3, 1, d, &ea),
        Insn::Vfmadd231sdXvHvWv => sem_ea::vfma(b, true, true, 0, 2, d, &ea),
        Insn::Vfmsub231sdXvHvWv => sem_ea::vfma(b, true, true, 1, 2, d, &ea),
        Insn::Vfnmadd231sdXvHvWv => sem_ea::vfma(b, true, true, 2, 2, d, &ea),
        Insn::Vfnmsub231sdXvHvWv => sem_ea::vfma(b, true, true, 3, 2, d, &ea),
        // B3b-2: AMD XOP/FMA4/TBM。FMA4 は XOP.8 と 66 0F 3A+is4 の
        // 両エンコードが同じ Insn を指す（4 オペランド、W で src2/src3 交換）。
        Insn::VfmaddpsXvHvWvIv => sem_ea::vfma4(b, false, false, 0, d, &ea),
        Insn::VfmaddpdXvHvWvIv => sem_ea::vfma4(b, true, false, 0, d, &ea),
        Insn::VfmaddssXvHvWvIv => sem_ea::vfma4(b, false, true, 0, d, &ea),
        Insn::VfmaddsdXvHvWvIv => sem_ea::vfma4(b, true, true, 0, d, &ea),
        Insn::VfmsubpsXvHvWvIv => sem_ea::vfma4(b, false, false, 1, d, &ea),
        Insn::VfmsubpdXvHvWvIv => sem_ea::vfma4(b, true, false, 1, d, &ea),
        Insn::VfmsubssXvHvWvIv => sem_ea::vfma4(b, false, true, 1, d, &ea),
        Insn::VfmsubsdXvHvWvIv => sem_ea::vfma4(b, true, true, 1, d, &ea),
        Insn::VfnmaddpsXvHvWvIv => sem_ea::vfma4(b, false, false, 2, d, &ea),
        Insn::VfnmaddpdXvHvWvIv => sem_ea::vfma4(b, true, false, 2, d, &ea),
        Insn::VfnmaddssXvHvWvIv => sem_ea::vfma4(b, false, true, 2, d, &ea),
        Insn::VfnmaddsdXvHvWvIv => sem_ea::vfma4(b, true, true, 2, d, &ea),
        Insn::VfnmsubpsXvHvWvIv => sem_ea::vfma4(b, false, false, 3, d, &ea),
        Insn::VfnmsubpdXvHvWvIv => sem_ea::vfma4(b, true, false, 3, d, &ea),
        Insn::VfnmsubssXvHvWvIv => sem_ea::vfma4(b, false, true, 3, d, &ea),
        Insn::VfnmsubsdXvHvWvIv => sem_ea::vfma4(b, true, true, 3, d, &ea),
        Insn::VfmaddsubpsXvHvWvIv => sem_ea::vfma4(b, false, false, 4, d, &ea),
        Insn::VfmaddsubpdXvHvWvIv => sem_ea::vfma4(b, true, false, 4, d, &ea),
        Insn::VfmsubaddpsXvHvWvIv => sem_ea::vfma4(b, false, false, 5, d, &ea),
        Insn::VfmsubaddpdXvHvWvIv => sem_ea::vfma4(b, true, false, 5, d, &ea),
        Insn::VpcmovXvHvWvIv => sem_ea::vpcmov(b, d, &ea),
        // TBM（宛先 vvvv、幅は XOP.W）。XOP.A の BEXTR は imm32 制御形。
        Insn::BlcfillByEv => sem_ea::tbm(b, vw, 0, &ea, d),
        Insn::BlsfillByEv => sem_ea::tbm(b, vw, 1, &ea, d),
        Insn::BlcsByEv => sem_ea::tbm(b, vw, 2, &ea, d),
        Insn::TzmskByEv => sem_ea::tbm(b, vw, 3, &ea, d),
        Insn::BlcicByEv => sem_ea::tbm(b, vw, 4, &ea, d),
        Insn::BlsicByEv => sem_ea::tbm(b, vw, 5, &ea, d),
        Insn::T1mskcByEv => sem_ea::tbm(b, vw, 6, &ea, d),
        Insn::BlciByEv => sem_ea::tbm(b, vw, 7, &ea, d),
        Insn::BlcmskByEv => sem_ea::tbm(b, vw, 8, &ea, d),
        Insn::BextrGvEvId => sem_ea::tbextr(b, vw, reg, &ea, d),
        // VFRCZ とパックシフト/ローテート（カウントは vvvv）。
        Insn::VfrczpsXvWv => sem_ea::vfrcz(b, false, false, d, &ea),
        Insn::VfrczpdXvWv => sem_ea::vfrcz(b, true, false, d, &ea),
        Insn::VfrczssXvWv => sem_ea::vfrcz(b, false, true, d, &ea),
        Insn::VfrczsdXvWv => sem_ea::vfrcz(b, true, true, d, &ea),
        Insn::VprotbXvWvHv => sem_ea::vpsh(b, 2, 8, d, &ea),
        Insn::VprotwXvWvHv => sem_ea::vpsh(b, 2, 16, d, &ea),
        Insn::VprotdXvWvHv => sem_ea::vpsh(b, 2, 32, d, &ea),
        Insn::VprotqXvWvHv => sem_ea::vpsh(b, 2, 64, d, &ea),
        Insn::VpshlbXvWvHv => sem_ea::vpsh(b, 1, 8, d, &ea),
        Insn::VpshlwXvWvHv => sem_ea::vpsh(b, 1, 16, d, &ea),
        Insn::VpshldXvWvHv => sem_ea::vpsh(b, 1, 32, d, &ea),
        Insn::VpshlqXvWvHv => sem_ea::vpsh(b, 1, 64, d, &ea),
        Insn::VpshabXvWvHv => sem_ea::vpsh(b, 0, 8, d, &ea),
        Insn::VpshawXvWvHv => sem_ea::vpsh(b, 0, 16, d, &ea),
        Insn::VpshadXvWvHv => sem_ea::vpsh(b, 0, 32, d, &ea),
        Insn::VpshaqXvWvHv => sem_ea::vpsh(b, 0, 64, d, &ea),
        // VPCOM（レーン比較→全1/全0 マスク、imm8[2:0]=述語）。
        Insn::VpcombXvHvWvIb => sem_ea::vpcom(b, 8, true, d, &ea),
        Insn::VpcomwXvHvWvIb => sem_ea::vpcom(b, 16, true, d, &ea),
        Insn::VpcomdXvHvWvIb => sem_ea::vpcom(b, 32, true, d, &ea),
        Insn::VpcomqXvHvWvIb => sem_ea::vpcom(b, 64, true, d, &ea),
        Insn::VpcomubXvHvWvIb => sem_ea::vpcom(b, 8, false, d, &ea),
        Insn::VpcomuwXvHvWvIb => sem_ea::vpcom(b, 16, false, d, &ea),
        Insn::VpcomudXvHvWvIb => sem_ea::vpcom(b, 32, false, d, &ea),
        Insn::VpcomuqXvHvWvIb => sem_ea::vpcom(b, 64, false, d, &ea),
        // B1c-3: F16C の半精度変換。
        Insn::Vcvtph2psXvWv => sem_ea::vcvtph2ps(b, d, &ea),
        Insn::Vcvtps2phWvXvIb => sem_ea::vcvtps2ph(b, d, &ea),
        // レガシー PACK の xmm 形（新規マップ項目）。
        Insn::PacksswbXvWv => sem_ea::ppack::<B, W16>(b, false, d, &ea),
        Insn::PackssdwXvWv => sem_ea::ppack::<B, W32>(b, false, d, &ea),
        Insn::PackuswbXvWv => sem_ea::ppack::<B, W16>(b, true, d, &ea),
        // パックシフト（カウントは xmm/m64 下位 64 または即値）。
        Insn::PsrlwXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W16>(b, sem_ea::Psh::R, c, d)
        }
        Insn::PsrldXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W32>(b, sem_ea::Psh::R, c, d)
        }
        Insn::PsrlqXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W64>(b, sem_ea::Psh::R, c, d)
        }
        Insn::PsrawXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W16>(b, sem_ea::Psh::A, c, d)
        }
        Insn::PsradXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W32>(b, sem_ea::Psh::A, c, d)
        }
        Insn::PsllwXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W16>(b, sem_ea::Psh::L, c, d)
        }
        Insn::PslldXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W32>(b, sem_ea::Psh::L, c, d)
        }
        Insn::PsllqXvWv => {
            let c = sem_ea::xm_lo64(b, &ea)?;
            sem_ea::pshift::<B, W64>(b, sem_ea::Psh::L, c, d)
        }
        Insn::PsrlwWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W16>(b, sem_ea::Psh::R, d.imm as u8, d)
        }
        Insn::PsrldWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W32>(b, sem_ea::Psh::R, d.imm as u8, d)
        }
        Insn::PsrlqWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W64>(b, sem_ea::Psh::R, d.imm as u8, d)
        }
        Insn::PsrawWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W16>(b, sem_ea::Psh::A, d.imm as u8, d)
        }
        Insn::PsradWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W32>(b, sem_ea::Psh::A, d.imm as u8, d)
        }
        Insn::PsllwWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W16>(b, sem_ea::Psh::L, d.imm as u8, d)
        }
        Insn::PslldWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W32>(b, sem_ea::Psh::L, d.imm as u8, d)
        }
        Insn::PsllqWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::pshift_i::<B, W64>(b, sem_ea::Psh::L, d.imm as u8, d)
        }
        Insn::PsrldqWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::byteshift(b, false, d.imm as u8, d)
        }
        Insn::PslldqWvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::byteshift(b, true, d.imm as u8, d)
        }
        // ===== MMX（接頭辞なし。P/Q = mm レジスタ形）=====
        Insn::PunpcklbwPvQv => sem_ea::mpunpck(b, 8, false, d, &ea),
        Insn::PunpcklwdPvQv => sem_ea::mpunpck(b, 16, false, d, &ea),
        Insn::PunpckldqPvQv => sem_ea::mpunpck(b, 32, false, d, &ea),
        Insn::PunpckhbwPvQv => sem_ea::mpunpck(b, 8, true, d, &ea),
        Insn::PunpckhwdPvQv => sem_ea::mpunpck(b, 16, true, d, &ea),
        Insn::PunpckhdqPvQv => sem_ea::mpunpck(b, 32, true, d, &ea),
        Insn::PacksswbPvQv => sem_ea::mpack::<B, W16>(b, false, d, &ea),
        Insn::PackssdwPvQv => sem_ea::mpack::<B, W32>(b, false, d, &ea),
        Insn::PackuswbPvQv => sem_ea::mpack::<B, W16>(b, true, d, &ea),
        Insn::PcmpgtbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::PcmpgtwPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::PcmpgtdPvQv => sem_ea::mint::<B, W32>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::PcmpeqbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::PcmpeqwPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::PcmpeqdPvQv => sem_ea::mint::<B, W32>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::PsrlwPvQv => sem_ea::mshift::<B, W16>(b, sem_ea::Psh::R, d, &ea),
        Insn::PsrldPvQv => sem_ea::mshift::<B, W32>(b, sem_ea::Psh::R, d, &ea),
        Insn::PsrlqPvQv => sem_ea::mshift::<B, W64>(b, sem_ea::Psh::R, d, &ea),
        Insn::PsrawPvQv => sem_ea::mshift::<B, W16>(b, sem_ea::Psh::A, d, &ea),
        Insn::PsradPvQv => sem_ea::mshift::<B, W32>(b, sem_ea::Psh::A, d, &ea),
        Insn::PsllwPvQv => sem_ea::mshift::<B, W16>(b, sem_ea::Psh::L, d, &ea),
        Insn::PslldPvQv => sem_ea::mshift::<B, W32>(b, sem_ea::Psh::L, d, &ea),
        Insn::PsllqPvQv => sem_ea::mshift::<B, W64>(b, sem_ea::Psh::L, d, &ea),
        Insn::PsrlwQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W16>(b, sem_ea::Psh::R, d.imm as u8, d)
        }
        Insn::PsrawQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W16>(b, sem_ea::Psh::A, d.imm as u8, d)
        }
        Insn::PsllwQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W16>(b, sem_ea::Psh::L, d.imm as u8, d)
        }
        Insn::PsrldQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W32>(b, sem_ea::Psh::R, d.imm as u8, d)
        }
        Insn::PsradQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W32>(b, sem_ea::Psh::A, d.imm as u8, d)
        }
        Insn::PslldQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W32>(b, sem_ea::Psh::L, d.imm as u8, d)
        }
        Insn::PsrlqQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W64>(b, sem_ea::Psh::R, d.imm as u8, d)
        }
        Insn::PsllqQvIb => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::mshift_i::<B, W64>(b, sem_ea::Psh::L, d.imm as u8, d)
        }
        Insn::PaddbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PaddwPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PadddPvQv => sem_ea::mint::<B, W32>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PaddqPvQv => sem_ea::mint::<B, W64>(b, sem_ea::Iop::Add, d, &ea),
        Insn::PsubbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PsubwPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PsubdPvQv => sem_ea::mint::<B, W32>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PsubqPvQv => sem_ea::mint::<B, W64>(b, sem_ea::Iop::Sub, d, &ea),
        Insn::PaddsbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::AddSatS, d, &ea),
        Insn::PaddswPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::AddSatS, d, &ea),
        Insn::PaddusbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::AddSatU, d, &ea),
        Insn::PadduswPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::AddSatU, d, &ea),
        Insn::PsubsbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::SubSatS, d, &ea),
        Insn::PsubswPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::SubSatS, d, &ea),
        Insn::PsubusbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::SubSatU, d, &ea),
        Insn::PsubuswPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::SubSatU, d, &ea),
        Insn::PmullwPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::MulLo, d, &ea),
        Insn::PavgbPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::Avg, d, &ea),
        Insn::PavgwPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::Avg, d, &ea),
        Insn::PminubPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::MinU, d, &ea),
        Insn::PmaxubPvQv => sem_ea::mint::<B, W8>(b, sem_ea::Iop::MaxU, d, &ea),
        Insn::PminswPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::MinS, d, &ea),
        Insn::PmaxswPvQv => sem_ea::mint::<B, W16>(b, sem_ea::Iop::MaxS, d, &ea),
        Insn::PandPvQv => sem_ea::mlogic(b, 0, d, &ea),
        Insn::PandnPvQv => sem_ea::mlogic(b, 1, d, &ea),
        Insn::PorPvQv => sem_ea::mlogic(b, 2, d, &ea),
        Insn::PxorPvQv => sem_ea::mlogic(b, 3, d, &ea),
        Insn::PmulhuwPvQv => sem_ea::mmulh(b, true, d, &ea),
        Insn::PmulhwPvQv => sem_ea::mmulh(b, false, d, &ea),
        Insn::PmuludqPvQv => sem_ea::mmuludq(b, d, &ea),
        Insn::PmaddwdPvQv => sem_ea::mmaddwd(b, d, &ea),
        Insn::PsadbwPvQv => sem_ea::msadbw(b, d, &ea),
        Insn::MovdPvEv => sem_ea::movd_pv_ev(b, w, d, &ea),
        Insn::MovdEvPv => sem_ea::movd_ev_pv(b, w, d, &ea),
        Insn::MovqPvQv => sem_ea::movq_pv_qv(b, d, &ea),
        Insn::MovqQvPv => sem_ea::movq_qv_pv(b, d, &ea),
        Insn::PshufwPvQvIb => sem_ea::mshufw(b, d.imm as u8, d, &ea),
        Insn::PinsrwPvEwIb => sem_ea::mpinsrw(b, d.imm as u8, d, &ea),
        Insn::PextrwGvPvIb => sem_ea::mpextrw(b, d.imm as u8, &ea, reg),
        Insn::PmovmskbGvQv => sem_ea::mmovmskb(b, &ea, reg),
        Insn::MovntqQvPv => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::movq_qv_pv(b, d, &ea)
        }
        Insn::MaskmovqPvQv => {
            if d.modrm < 0xC0 {
                return Ok(false);
            }
            sem_ea::maskmovq(b, d, &ea, seg)
        }
        Insn::MaskmovdquXvXv => sem_ea::maskmovdqu(b, d, &ea, seg),
        Insn::Emms => sem_ea::emms(b),
        // ===== 3DNow!（0F 0F /r imm8）=====
        Insn::Femms => sem_ea::femms(b),
        Insn::PfaddPqQq => sem_ea::dnow(b, sem_ea::Dop::Add, d, &ea),
        Insn::PfsubPqQq => sem_ea::dnow(b, sem_ea::Dop::Sub, d, &ea),
        Insn::PfsubrPqQq => sem_ea::dnow(b, sem_ea::Dop::Subr, d, &ea),
        Insn::PfmulPqQq => sem_ea::dnow(b, sem_ea::Dop::Mul, d, &ea),
        Insn::PfminPqQq => sem_ea::dnow(b, sem_ea::Dop::Min, d, &ea),
        Insn::PfmaxPqQq => sem_ea::dnow(b, sem_ea::Dop::Max, d, &ea),
        Insn::PfcmpeqPqQq => sem_ea::dnow(b, sem_ea::Dop::CmpEq, d, &ea),
        Insn::PfcmpgePqQq => sem_ea::dnow(b, sem_ea::Dop::CmpGe, d, &ea),
        Insn::PfcmpgtPqQq => sem_ea::dnow(b, sem_ea::Dop::CmpGt, d, &ea),
        Insn::PfaccPqQq => sem_ea::dnow(b, sem_ea::Dop::Acc, d, &ea),
        Insn::PfnaccPqQq => sem_ea::dnow(b, sem_ea::Dop::Nacc, d, &ea),
        Insn::PfpnaccPqQq => sem_ea::dnow(b, sem_ea::Dop::Pnacc, d, &ea),
        Insn::PswapdPqQq => sem_ea::dnow(b, sem_ea::Dop::Swap, d, &ea),
        Insn::PfrcpPqQq => sem_ea::dnow(b, sem_ea::Dop::Rcp, d, &ea),
        Insn::PfrsqrtPqQq => sem_ea::dnow(b, sem_ea::Dop::Rsqrt, d, &ea),
        Insn::Pfrcpit1PqQq => sem_ea::dnow(b, sem_ea::Dop::RcpIt1, d, &ea),
        Insn::Pfrsqit1PqQq => sem_ea::dnow(b, sem_ea::Dop::RsqrtIt1, d, &ea),
        Insn::Pfrcpit2PqQq => sem_ea::dnow(b, sem_ea::Dop::RcpIt2, d, &ea),
        Insn::Pf2idPqQq => sem_ea::dnow(b, sem_ea::Dop::F2Id, d, &ea),
        Insn::Pf2iwPqQq => sem_ea::dnow(b, sem_ea::Dop::F2Iw, d, &ea),
        Insn::Pi2fdPqQq => sem_ea::dnow(b, sem_ea::Dop::I2Fd, d, &ea),
        Insn::Pi2fwPqQq => sem_ea::dnow(b, sem_ea::Dop::I2Fw, d, &ea),
        Insn::PavgusbPqQq => sem_ea::dnow(b, sem_ea::Dop::AvgUsb, d, &ea),
        Insn::PmulhrwPqQq => sem_ea::dnow(b, sem_ea::Dop::MulHrw, d, &ea),
        // ===== SSE4a・AMD システム拡張 =====
        Insn::ExtrqWvIbIb => sem_ea::extrqi(b, d.imm as u8, d.imm2 as u8, d),
        Insn::ExtrqXvWv => sem_ea::extrqr(b, d, &ea),
        Insn::InsertqXvWvIbIb => sem_ea::insertqi(b, d.imm as u8, d.imm2 as u8, d, &ea),
        Insn::InsertqXvWv => sem_ea::insertqr(b, d, &ea),
        Insn::MovntssMdXv => sem_ea::movnts(b, true, d, &ea),
        Insn::MovntsdMqXv => sem_ea::movnts(b, false, d, &ea),
        // MONITORX/MWAITX は単スレッド実行なので NOP 扱い
        // （MONITOR/MWAIT と同じ）。
        Insn::Monitorx | Insn::Mwaitx => sem::nop(b),
        Insn::Clzero => sem_ea::clzero(b, d),
        Insn::Rdpru => sem_ea::rdpru(b),
        // ===== 0F 38（SSSE3/SSE4.1/MOVBE）=====
        Insn::PshufbXvWv => sem_ea::pshufb(b, d, &ea),
        Insn::PhaddwXvWv => sem_ea::phaddsub::<B, W16>(b, false, false, d, &ea),
        Insn::PhadddXvWv => sem_ea::phaddsub::<B, W32>(b, false, false, d, &ea),
        Insn::PhaddswXvWv => sem_ea::phaddsub::<B, W16>(b, false, true, d, &ea),
        Insn::PhsubwXvWv => sem_ea::phaddsub::<B, W16>(b, true, false, d, &ea),
        Insn::PhsubdXvWv => sem_ea::phaddsub::<B, W32>(b, true, false, d, &ea),
        Insn::PhsubswXvWv => sem_ea::phaddsub::<B, W16>(b, true, true, d, &ea),
        Insn::PmaddubswXvWv => sem_ea::pmaddubsw(b, d, &ea),
        Insn::PmulhrswXvWv => sem_ea::pmulhrsw(b, d, &ea),
        Insn::PsignbXvWv => sem_ea::psign::<B, W8>(b, d, &ea),
        Insn::PsignwXvWv => sem_ea::psign::<B, W16>(b, d, &ea),
        Insn::PsigndXvWv => sem_ea::psign::<B, W32>(b, d, &ea),
        Insn::PabsbXvWv => sem_ea::pabs::<B, W8>(b, d, &ea),
        Insn::PabswXvWv => sem_ea::pabs::<B, W16>(b, d, &ea),
        Insn::PabsdXvWv => sem_ea::pabs::<B, W32>(b, d, &ea),
        Insn::PtestXvWv => sem_ea::ptest(b, d, &ea),
        Insn::PmovsxbwXvWv => sem_ea::pmovx(b, 8, 16, true, d, &ea),
        Insn::PmovsxbdXvWv => sem_ea::pmovx(b, 8, 32, true, d, &ea),
        Insn::PmovsxbqXvWv => sem_ea::pmovx(b, 8, 64, true, d, &ea),
        Insn::PmovsxwdXvWv => sem_ea::pmovx(b, 16, 32, true, d, &ea),
        Insn::PmovsxwqXvWv => sem_ea::pmovx(b, 16, 64, true, d, &ea),
        Insn::PmovsxdqXvWv => sem_ea::pmovx(b, 32, 64, true, d, &ea),
        Insn::PmovzxbwXvWv => sem_ea::pmovx(b, 8, 16, false, d, &ea),
        Insn::PmovzxbdXvWv => sem_ea::pmovx(b, 8, 32, false, d, &ea),
        Insn::PmovzxbqXvWv => sem_ea::pmovx(b, 8, 64, false, d, &ea),
        Insn::PmovzxwdXvWv => sem_ea::pmovx(b, 16, 32, false, d, &ea),
        Insn::PmovzxwqXvWv => sem_ea::pmovx(b, 16, 64, false, d, &ea),
        Insn::PmovzxdqXvWv => sem_ea::pmovx(b, 32, 64, false, d, &ea),
        Insn::PmuldqXvWv => sem_ea::pmuldq(b, d, &ea),
        Insn::PmulldXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::MulLo, d, &ea),
        Insn::PcmpeqqXvWv => sem_ea::pint::<B, W64>(b, sem_ea::Iop::CmpEq, d, &ea),
        Insn::PcmpgtqXvWv => sem_ea::pint::<B, W64>(b, sem_ea::Iop::CmpGtS, d, &ea),
        Insn::PminsbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::MinS, d, &ea),
        Insn::PminsdXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::MinS, d, &ea),
        Insn::PminuwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::MinU, d, &ea),
        Insn::PminudXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::MinU, d, &ea),
        Insn::PmaxsbXvWv => sem_ea::pint::<B, W8>(b, sem_ea::Iop::MaxS, d, &ea),
        Insn::PmaxsdXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::MaxS, d, &ea),
        Insn::PmaxuwXvWv => sem_ea::pint::<B, W16>(b, sem_ea::Iop::MaxU, d, &ea),
        Insn::PmaxudXvWv => sem_ea::pint::<B, W32>(b, sem_ea::Iop::MaxU, d, &ea),
        Insn::PackusdwXvWv => sem_ea::packusdw(b, d, &ea),
        Insn::MovntdqaXvWv => sem_ea::mov_x_w(b, d, &ea),
        Insn::MovbeGvMv => sem_ea::movbe_ld(b, w, reg, d, &ea),
        Insn::MovbeMvGv => sem_ea::movbe_st(b, w, reg, d, &ea),
        Insn::PblendvbXvWv => sem_ea::pblendvb(b, d, &ea),
        Insn::BlendvpsXvWv => sem_ea::blendv(b, d, &ea, 32),
        Insn::BlendvpdXvWv => sem_ea::blendv(b, d, &ea, 64),
        Insn::PhminposuwXvWv => sem_ea::phminposuw(b, d, &ea),
        Insn::Crc32GvEb => sem_ea::crc32(b, 8, d, &ea),
        Insn::Crc32GvEv => sem_ea::crc32(b, u32::from(w), d, &ea),
        // SSSE3 の MMX 形。
        Insn::PshufbPvQv => sem_ea::pshufb64(b, d, &ea),
        Insn::PhaddwPvQv => sem_ea::phaddsub64::<B, W16>(b, false, false, d, &ea),
        Insn::PhadddPvQv => sem_ea::phaddsub64::<B, W32>(b, false, false, d, &ea),
        Insn::PhaddswPvQv => sem_ea::phaddsub64::<B, W16>(b, false, true, d, &ea),
        Insn::PhsubwPvQv => sem_ea::phaddsub64::<B, W16>(b, true, false, d, &ea),
        Insn::PhsubdPvQv => sem_ea::phaddsub64::<B, W32>(b, true, false, d, &ea),
        Insn::PhsubswPvQv => sem_ea::phaddsub64::<B, W16>(b, true, true, d, &ea),
        Insn::PmaddubswPvQv => sem_ea::pmaddubsw64(b, d, &ea),
        Insn::PmulhrswPvQv => sem_ea::pmulhrsw64(b, d, &ea),
        Insn::PsignbPvQv => sem_ea::psign64::<B, W8>(b, d, &ea),
        Insn::PsignwPvQv => sem_ea::psign64::<B, W16>(b, d, &ea),
        Insn::PsigndPvQv => sem_ea::psign64::<B, W32>(b, d, &ea),
        Insn::PabsbPvQv => sem_ea::pabs64::<B, W8>(b, d, &ea),
        Insn::PabswPvQv => sem_ea::pabs64::<B, W16>(b, d, &ea),
        Insn::PabsdPvQv => sem_ea::pabs64::<B, W32>(b, d, &ea),
        // ===== 0F 3A =====
        Insn::BlendpsXvWvIb => sem_ea::blendp(b, 32, d.imm as u8, d, &ea),
        Insn::BlendpdXvWvIb => sem_ea::blendp(b, 64, d.imm as u8, d, &ea),
        Insn::PblendwXvWvIb => sem_ea::blendp(b, 16, d.imm as u8, d, &ea),
        Insn::PalignrXvWvIb => sem_ea::palignr(b, d.imm as u8, d, &ea),
        Insn::PextrbEbXv => sem_ea::pextrx(b, 8, d.imm as u8, d, &ea),
        Insn::PextrwEwXv => sem_ea::pextrx(b, 16, d.imm as u8, d, &ea),
        Insn::PextrdEdXv => {
            sem_ea::pextrx(b, if d.rex & 8 != 0 { 64 } else { 32 }, d.imm as u8, d, &ea)
        }
        Insn::ExtractpsEdXv => sem_ea::pextrx(b, 32, d.imm as u8, d, &ea),
        Insn::PinsrbXvEbIb => sem_ea::pinsrx(b, 8, d.imm as u8, d, &ea),
        Insn::PinsrdXvEdIb => {
            sem_ea::pinsrx(b, if d.rex & 8 != 0 { 64 } else { 32 }, d.imm as u8, d, &ea)
        }
        Insn::InsertpsXvWvIb => sem_ea::insertps(b, d.imm as u8, d, &ea),
        Insn::RoundpsXvWvIb => sem_ea::round_p(b, 32, d.imm as u8, d, &ea),
        Insn::RoundpdXvWvIb => sem_ea::round_p(b, 64, d.imm as u8, d, &ea),
        Insn::RoundssXvWvIb => sem_ea::round_s(b, 32, d.imm as u8, d, &ea),
        Insn::RoundsdXvWvIb => sem_ea::round_s(b, 64, d.imm as u8, d, &ea),
        Insn::DppsXvWvIb => sem_ea::dpp(b, 32, d.imm as u8, d, &ea),
        Insn::DppdXvWvIb => sem_ea::dpp(b, 64, d.imm as u8, d, &ea),
        Insn::MpsadbwXvWvIb => sem_ea::mpsadbw(b, d.imm as u8, d, &ea),
        Insn::PalignrPvQvIb => sem_ea::palignr64(b, d.imm as u8, d, &ea),
        Insn::PcmpestriXvWvIb => sem_ea::pxstr(b, true, true, d.imm as u8, d, &ea),
        Insn::PcmpestrmXvWvIb => sem_ea::pxstr(b, true, false, d.imm as u8, d, &ea),
        Insn::PcmpistriXvWvIb => sem_ea::pxstr(b, false, true, d.imm as u8, d, &ea),
        Insn::PcmpistrmXvWvIb => sem_ea::pxstr(b, false, false, d.imm as u8, d, &ea),
        // AES-NI と PCLMULQDQ。
        Insn::AesimcXvWv => sem_ea::aesround(b, 4, d, &ea),
        Insn::AesencXvWv => sem_ea::aesround(b, 0, d, &ea),
        Insn::AesenclastXvWv => sem_ea::aesround(b, 1, d, &ea),
        Insn::AesdecXvWv => sem_ea::aesround(b, 2, d, &ea),
        Insn::AesdeclastXvWv => sem_ea::aesround(b, 3, d, &ea),
        Insn::AeskeygenassistXvWvIb => sem_ea::aeskeygenassist(b, d.imm as u8, d, &ea),
        Insn::PclmulqdqXvWvIb => sem_ea::pclmulqdq(b, d.imm as u8, d, &ea),
        // SHA-NI と GFNI。
        Insn::Sha1rnds4XvWvIb => sem_ea::sha1rnds4(b, d.imm as u8, d, &ea),
        Insn::Sha1nexteXvWv => sem_ea::sha1nexte(b, d, &ea),
        Insn::Sha1msg1XvWv => sem_ea::sha1msg1(b, d, &ea),
        Insn::Sha1msg2XvWv => sem_ea::sha1msg2(b, d, &ea),
        Insn::Sha256rnds2XvWv => sem_ea::sha256rnds2(b, d, &ea),
        Insn::Sha256msg1XvWv => sem_ea::sha256msg1(b, d, &ea),
        Insn::Sha256msg2XvWv => sem_ea::sha256msg2(b, d, &ea),
        Insn::Gf2p8mulbXvWv => sem_ea::gf2p8mulb(b, d, &ea),
        Insn::Gf2p8affineqbXvWvIb => sem_ea::gf2p8affine(b, false, d.imm as u8, d, &ea),
        Insn::Gf2p8affineinvqbXvWvIb => sem_ea::gf2p8affine(b, true, d.imm as u8, d, &ea),
        // ===== x87（D8-DF）。mod=11 は r/m フィールドを ST(i) として
        // 扱い、それ以外はメモリ形。ステータスワード依存の比較系は
        // 未モデルのため旧経路へフォールバックする。
        Insn::FaddM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Add, d.modrm & 7, false, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Add, &ea, 32)
            }
        }
        Insn::FmulM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Mul, d.modrm & 7, false, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Mul, &ea, 32)
            }
        }
        Insn::FsubM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Sub, d.modrm & 7, false, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Sub, &ea, 32)
            }
        }
        Insn::FsubrM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::SubR, d.modrm & 7, false, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::SubR, &ea, 32)
            }
        }
        Insn::FdivM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Div, d.modrm & 7, false, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Div, &ea, 32)
            }
        }
        Insn::FdivrM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::DivR, d.modrm & 7, false, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::DivR, &ea, 32)
            }
        }
        Insn::FldM32 => {
            if d.modrm >= 0xC0 {
                polyisa_guest_x86::sem::fld_st(b, d.modrm & 7)
            } else {
                sem_ea::fld_m(b, &ea, 32)
            }
        }
        Insn::FxchSti => {
            if d.modrm >= 0xC0 {
                polyisa_guest_x86::sem::fxch_st(b, d.modrm & 7)
            } else {
                return Ok(false);
            }
        }
        Insn::FstM32 => {
            if d.modrm >= 0xC0 {
                // mod=11 rm=0 は FNOP。残りは未定義。
                if d.modrm & 7 == 0 {
                    Ok(())
                } else {
                    return Ok(false);
                }
            } else {
                sem_ea::fst_m(b, &ea, 32, false)
            }
        }
        Insn::FstpM32 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fst_m(b, &ea, 32, true)
        }
        Insn::X87d94 => {
            if d.modrm >= 0xC0 {
                match d.modrm & 7 {
                    0 => sem_ea::fchs_abs(b, false),
                    1 => sem_ea::fchs_abs(b, true),
                    4 => sem_ea::ftst_st(b),
                    5 => sem_ea::fxam_st(b),
                    _ => return Ok(false),
                }
            } else {
                sem_ea::fldenv_m(b, &ea)
            }
        }
        Insn::FldcwM16 => {
            if d.modrm >= 0xC0 {
                // D9 E8+i: FLD1/L2T/L2E/PI/LG2/LN2/Z。rm=7 は未定義。
                if d.modrm & 7 == 7 {
                    return Ok(false);
                }
                sem_ea::fld_const(b, d.modrm & 7)
            } else {
                sem_ea::fldcw_m(b, &ea)
            }
        }
        Insn::X87d96 => {
            if d.modrm >= 0xC0 {
                match d.modrm & 7 {
                    // 0-3: F2XM1/FYL2X/FPTAN/FPATAN は softfloat 超越関数なし。
                    4 => sem_ea::fxtract_st(b),
                    5 => sem_ea::fprem_st(b, true),
                    6 => sem_ea::fdecstp(b, false),
                    7 => sem_ea::fdecstp(b, true),
                    _ => return Ok(false),
                }
            } else {
                sem_ea::fnstenv_m(b, &ea)
            }
        }
        Insn::FnstcwM16 => {
            if d.modrm >= 0xC0 {
                match d.modrm & 7 {
                    0 => sem_ea::fprem_st(b, false),
                    // 1: FYL2XP1、3: FSINCOS、6/7: FSIN/FCOS は超越関数なし。
                    2 => sem_ea::fsqrt_st(b),
                    4 => sem_ea::frndint_st(b),
                    5 => sem_ea::fscale_st(b),
                    _ => return Ok(false),
                }
            } else {
                sem_ea::fnstcw_m(b, &ea)
            }
        }
        Insn::FiaddM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 0, d.modrm & 7)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::Add, &ea, 32)
            }
        }
        Insn::FimulM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 1, d.modrm & 7)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::Mul, &ea, 32)
            }
        }
        Insn::FicomM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 2, d.modrm & 7)
            } else {
                return Ok(false);
            }
        }
        Insn::FicompM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 3, d.modrm & 7)
            } else {
                return Ok(false);
            }
        }
        Insn::FisubM32 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fiarith_m(b, sem_ea::FAr::Sub, &ea, 32)
        }
        Insn::FisubrM32 => {
            if d.modrm >= 0xC0 {
                // DA E9: FUCOMPP。rm!=1 は未定義。
                if d.modrm & 7 == 1 {
                    return sem_ea::fcompp_st(b).map(|()| true);
                }
                return Ok(false);
            }
            sem_ea::fiarith_m(b, sem_ea::FAr::SubR, &ea, 32)
        }
        Insn::FidivM32 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fiarith_m(b, sem_ea::FAr::Div, &ea, 32)
        }
        Insn::FidivrM32 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fiarith_m(b, sem_ea::FAr::DivR, &ea, 32)
        }
        Insn::FildM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 4, d.modrm & 7)
            } else {
                sem_ea::fild_m(b, &ea, 32)
            }
        }
        Insn::FisttpM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 5, d.modrm & 7)
            } else {
                sem_ea::fist_m(b, &ea, 32, true)
            }
        }
        Insn::FistM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 6, d.modrm & 7)
            } else {
                sem_ea::fist_m(b, &ea, 32, false)
            }
        }
        Insn::FistpM32 => {
            if d.modrm >= 0xC0 {
                sem_ea::fcmov_cc(b, 7, d.modrm & 7)
            } else {
                sem_ea::fist_m(b, &ea, 32, true)
            }
        }
        Insn::X87db4 => {
            if d.modrm >= 0xC0 {
                match d.modrm & 7 {
                    // FCLEX は例外状態未モデルで実質 NOP。
                    2 => Ok(()),
                    3 => sem_ea::finit(b),
                    _ => return Ok(false),
                }
            } else {
                return Ok(false);
            }
        }
        Insn::FldM80 => {
            if d.modrm >= 0xC0 {
                polyisa_guest_x86::sem::fucomi_st(b, d.modrm & 7)
            } else {
                sem_ea::fld_m(b, &ea, 80)
            }
        }
        Insn::FcomiSti => {
            if d.modrm >= 0xC0 {
                // FCOMI も旗の規則は FUCOMI と同じ。
                polyisa_guest_x86::sem::fucomi_st(b, d.modrm & 7)
            } else {
                return Ok(false);
            }
        }
        Insn::FstpM80 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fst_m(b, &ea, 80, true)
        }
        Insn::FaddM64 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Add, d.modrm & 7, true, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Add, &ea, 64)
            }
        }
        Insn::FmulM64 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Mul, d.modrm & 7, true, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Mul, &ea, 64)
            }
        }
        Insn::FsubM64 => {
            if d.modrm >= 0xC0 {
                // DC E0+i FSUBR: st(i) = st(0) - st(i)
                sem_ea::farith_st(b, sem_ea::FAr::SubR, d.modrm & 7, true, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Sub, &ea, 64)
            }
        }
        Insn::FsubrM64 => {
            if d.modrm >= 0xC0 {
                // DC E8+i FSUB: st(i) = st(i) - st(0)
                sem_ea::farith_st(b, sem_ea::FAr::Sub, d.modrm & 7, true, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::SubR, &ea, 64)
            }
        }
        Insn::FdivM64 => {
            if d.modrm >= 0xC0 {
                // DC F0+i FDIVR: st(i) = st(0) / st(i)
                sem_ea::farith_st(b, sem_ea::FAr::DivR, d.modrm & 7, true, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::Div, &ea, 64)
            }
        }
        Insn::FdivrM64 => {
            if d.modrm >= 0xC0 {
                // DC F8+i FDIV: st(i) = st(i) / st(0)
                sem_ea::farith_st(b, sem_ea::FAr::Div, d.modrm & 7, true, false)
            } else {
                sem_ea::farith_m(b, sem_ea::FAr::DivR, &ea, 64)
            }
        }
        Insn::FldM64 => {
            if d.modrm >= 0xC0 {
                sem_ea::ffree(b, d.modrm & 7)
            } else {
                sem_ea::fld_m(b, &ea, 64)
            }
        }
        Insn::FisttpM64 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            // FISTTP は常に切り捨てだが、現状は FCW 準拠の近似。
            sem_ea::fist_m(b, &ea, 64, true)
        }
        Insn::FstM64 => {
            if d.modrm >= 0xC0 {
                sem_ea::fst_sti(b, d.modrm & 7, false)
            } else {
                sem_ea::fst_m(b, &ea, 64, false)
            }
        }
        Insn::FstpM64 => {
            if d.modrm >= 0xC0 {
                sem_ea::fst_sti(b, d.modrm & 7, true)
            } else {
                sem_ea::fst_m(b, &ea, 64, true)
            }
        }
        Insn::MulEb => sem_ea::mulx(b, 8, d, &ea, false),
        Insn::MulEv => sem_ea::mulx(b, w, d, &ea, false),
        Insn::ImulEb => sem_ea::mulx(b, 8, d, &ea, true),
        Insn::ImulEv => sem_ea::mulx(b, w, d, &ea, true),
        Insn::DivEb => sem_ea::divx(b, 8, d, &ea, eip, u32::from(d.len), sa, sseg, mode, false),
        Insn::DivEv => sem_ea::divx(b, w, d, &ea, eip, u32::from(d.len), sa, sseg, mode, false),
        Insn::IdivEb => sem_ea::divx(b, 8, d, &ea, eip, u32::from(d.len), sa, sseg, mode, true),
        Insn::IdivEv => sem_ea::divx(b, w, d, &ea, eip, u32::from(d.len), sa, sseg, mode, true),
        Insn::FcomM32 => sem_ea::fcom_m(b, 32, d, &ea, false),
        Insn::FcompM32 => sem_ea::fcom_m(b, 32, d, &ea, true),
        Insn::FcomM64 => sem_ea::fcom_m(b, 64, d, &ea, false),
        Insn::FcompM64 => sem_ea::fcom_m(b, 64, d, &ea, true),
        Insn::FicomM16 => {
            // DE /2,/3: mod=11 は割り当てなし。
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::ficom_m16(b, &ea, false)
        }
        Insn::FicompM16 => {
            if d.modrm >= 0xC0 {
                // DE D9: FCOMPP。rm!=1 は未定義。
                if d.modrm & 7 == 1 {
                    return sem_ea::fcompp_st(b).map(|()| true);
                }
                return Ok(false);
            }
            sem_ea::ficom_m16(b, &ea, true)
        }
        Insn::X87dd4 => {
            // DD /4: mem=FRSTOR m108、mod=11 は DD E0+i FUCOM st(i)。
            if d.modrm >= 0xC0 {
                sem_ea::fcom_sti(b, d.modrm & 7, false)
            } else {
                sem_ea::frstor_m(b, &ea)
            }
        }
        Insn::X87dd5 => {
            // DD /5: mem は未定義、mod=11 は DD E8+i FUCOMP st(i)。
            if d.modrm >= 0xC0 {
                sem_ea::fcom_sti(b, d.modrm & 7, true)
            } else {
                return Ok(false);
            }
        }
        Insn::X87dd6 => {
            // DD /6: mem=FNSAVE m108。mod=11 は未定義。
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fnsave_m(b, &ea)
        }
        Insn::FnstswM16 => {
            // DD /7: mem=FNSTSW m16、mod=11 は DD F8+i FSTP st(i)。
            if d.modrm >= 0xC0 {
                sem_ea::fst_sti(b, d.modrm & 7, true)
            } else {
                sem_ea::fnstsw_m16(b, &ea)
            }
        }
        Insn::FiaddM16 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Add, d.modrm & 7, true, true)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::Add, &ea, 16)
            }
        }
        Insn::FimulM16 => {
            if d.modrm >= 0xC0 {
                sem_ea::farith_st(b, sem_ea::FAr::Mul, d.modrm & 7, true, true)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::Mul, &ea, 16)
            }
        }
        Insn::FisubM16 => {
            if d.modrm >= 0xC0 {
                // DE E0+i FSUBRP: st(i) = st(0) - st(i), pop
                sem_ea::farith_st(b, sem_ea::FAr::SubR, d.modrm & 7, true, true)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::Sub, &ea, 16)
            }
        }
        Insn::FisubrM16 => {
            if d.modrm >= 0xC0 {
                // DE E8+i FSUBP: st(i) = st(i) - st(0), pop
                sem_ea::farith_st(b, sem_ea::FAr::Sub, d.modrm & 7, true, true)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::SubR, &ea, 16)
            }
        }
        Insn::FidivM16 => {
            if d.modrm >= 0xC0 {
                // DE F0+i FDIVRP: st(i) = st(0) / st(i), pop
                sem_ea::farith_st(b, sem_ea::FAr::DivR, d.modrm & 7, true, true)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::Div, &ea, 16)
            }
        }
        Insn::FidivrM16 => {
            if d.modrm >= 0xC0 {
                // DE F8+i FDIVP: st(i) = st(i) / st(0), pop
                sem_ea::farith_st(b, sem_ea::FAr::Div, d.modrm & 7, true, true)
            } else {
                sem_ea::fiarith_m(b, sem_ea::FAr::DivR, &ea, 16)
            }
        }
        Insn::FildM16 => {
            if d.modrm >= 0xC0 {
                sem_ea::ffreep(b, d.modrm & 7)
            } else {
                sem_ea::fild_m(b, &ea, 16)
            }
        }
        Insn::FisttpM16 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fist_m(b, &ea, 16, true)
        }
        Insn::FistM16 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fist_m(b, &ea, 16, false)
        }
        Insn::FistpM16 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fist_m(b, &ea, 16, true)
        }
        Insn::FbldM80 => {
            if d.modrm >= 0xC0 {
                // DF E0 = FNSTSW AX。E1-E7 は未定義。
                if d.modrm & 7 == 0 {
                    sem_ea::fnstsw_ax(b);
                    Ok(())
                } else {
                    return Ok(false);
                }
            } else {
                sem_ea::fbld_m(b, &ea)
            }
        }
        Insn::FildM64 => {
            if d.modrm >= 0xC0 {
                polyisa_guest_x86::sem::fucomip_st(b, d.modrm & 7)
            } else {
                sem_ea::fild_m(b, &ea, 64)
            }
        }
        Insn::FbstpM80 => {
            if d.modrm >= 0xC0 {
                // FCOMIP も旗の規則は FUCOMIP と同じ。
                polyisa_guest_x86::sem::fucomip_st(b, d.modrm & 7)
            } else {
                sem_ea::fbstp_m(b, &ea)
            }
        }
        Insn::FistpM64 => {
            if d.modrm >= 0xC0 {
                return Ok(false);
            }
            sem_ea::fist_m(b, &ea, 64, true)
        }
        _ => return Ok(false),
    };
    let r = r.map(|()| true);
    if matches!(r, Ok(true)) && npx {
        // 80287 転送プロトコル: ポート F8 へ命令語 [opcode, modrm]、
        // FC へ [IP, CS, EAオフセット, オペランドのセグメント]（記憶形）
        // または FC へ [IP, CS]（mod=11 の st(i) 形）。
        let f8 = b.konst::<W64>(0xF8);
        let fc = b.konst::<W64>(0xFC);
        let iw = b.konst::<W16>(u16::from(d.opcode) | (u16::from(d.modrm) << 8));
        let ipw = b.konst::<W16>(eip as u16);
        let csw = b.get(sem::sreg_ref(1));
        let sgw = b.konst::<W16>((seg >> 4) as u16);
        b.port_out::<W16>(f8, iw)?;
        b.port_out::<W16>(fc, ipw)?;
        b.port_out::<W16>(fc, csw)?;
        if let Rm::Mem { a, .. } = &ea {
            let sb = b.konst::<W64>(seg);
            let off = b.sub::<W64>(*a, sb);
            let eaw = b.trunc::<W64, W16>(off);
            b.port_out::<W16>(fc, eaw)?;
            b.port_out::<W16>(fc, sgw)?;
        }
    }
    r
}

/// AMX タイル命令の実行（B4b）。タイル状態（`CpuState::tmm`/
/// `tilecfg`）の更新は行数・列バイト数が実行時値なので、IR/意味論
/// DSL ではなくインタプリタ層の具体値で組む。対象命令なら実行して
/// `Some(結果)` を返し、それ以外は `None` で通常経路へ。
fn amx_tile_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
) -> Option<Result<(), InterpExit>> {
    use polyisa_guest_x86::Insn;
    if !matches!(
        md.insn,
        Insn::Ldtilecfg
            | Insn::Sttilecfg
            | Insn::Tilerelease
            | Insn::Tilezero
            | Insn::Tileloadd
            | Insn::Tileloaddt1
            | Insn::Tileloaddrs
            | Insn::Tileloaddrst1
            | Insn::Tilestored
            | Insn::Tdpbssd
            | Insn::Tdpbsud
            | Insn::Tdpbusd
            | Insn::Tdpbuud
            | Insn::Tdpbf16ps
            | Insn::Tdpfp16ps
            | Insn::Tcmmimfp16ps
            | Insn::Tcmmrlfp16ps
    ) {
        return None;
    }
    Some(amx_tile_exec(env, md, next_rip, seg, eip))
}

/// `CpuState` 内のタイル構成の先頭オフセット（byte0=palette、
/// byte1=startRow、16..=47=colsb[16]、48..=63=rows[16]）。
const TILECFG_OFF: usize = core::mem::offset_of!(polyisa_guest_x86::CpuState, tilecfg);
const TMM_OFF: usize = core::mem::offset_of!(polyisa_guest_x86::CpuState, tmm);

/// タイルの行数。`st` は `CpuState` のバイト列。
fn tile_rows(st: &[u8], t: u8) -> usize {
    usize::from(st[TILECFG_OFF + 48 + usize::from(t)])
}

/// タイルの 1 行のバイト数。
fn tile_colsb(st: &[u8], t: u8) -> usize {
    usize::from(u16::from_le_bytes([
        st[TILECFG_OFF + 16 + 2 * usize::from(t)],
        st[TILECFG_OFF + 17 + 2 * usize::from(t)],
    ]))
}

/// タイルが有効（構成済みかつ行・列が非 0）か。
fn tile_valid(st: &[u8], t: u8) -> bool {
    tile_rows(st, t) > 0 && tile_colsb(st, t) > 0
}

/// タイル `t` の行 `r` の先頭オフセット（行は colsb バイトずつ連続）。
fn tile_cell(st: &[u8], t: u8, r: usize) -> usize {
    TMM_OFF + usize::from(t) * 1024 + r * tile_colsb(st, t)
}

/// SHA512/SM3/SM4 の VEX 形。全て固定幅の整数写像だが、
/// 128/256 ビットの lane 構造とメモリ読み込みを既存の AMX/AVX10
/// 例外写像へ合わせるため具体値で実行する。
fn vcrypto_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
) -> Option<Result<(), InterpExit>> {
    use polyisa_guest_x86::Insn;
    if !matches!(
        md.insn,
        Insn::Vsha512rnds2XvHvWv
            | Insn::Vsha512msg1XvWv
            | Insn::Vsha512msg2XvWv
            | Insn::Vsm3msg1XvHvWv
            | Insn::Vsm3msg2XvHvWv
            | Insn::Vsm4key4XvHvWv
            | Insn::Vsm4rnds4XvHvWv
    ) {
        return None;
    }
    Some(vcrypto_exec(env, md, next_rip, seg, eip))
}

const SM4_SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

fn sm4_sub_word(x: u32) -> u32 {
    let mut r = 0u32;
    for i in 0..4 {
        r |= u32::from(SM4_SBOX[(x >> (8 * i)) as u8 as usize]) << (8 * i);
    }
    r
}

fn vcrypto_exec(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    _eip: u32,
) -> Result<(), InterpExit> {
    use polyisa_guest_x86::{Insn, decode, sem};
    let vbytes = if md.vex_l { 32usize } else { 16 };
    let acc_r = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    let zget = |env: &mut BareEnv, r: u8| -> [u8; 32] {
        let mut v = [0u8; 32];
        for p in 0..2 {
            v[p * 16..p * 16 + 16]
                .copy_from_slice(&env.backend.get(sem::zreg_ref(r, p)).to_le_bytes());
        }
        v
    };
    let zput = |env: &mut BareEnv, r: u8, v: &[u8; 32]| {
        for p in 0..2 {
            env.backend.set(
                sem::zreg_ref(r, p),
                u128::from_le_bytes(v[p * 16..p * 16 + 16].try_into().unwrap()),
            );
        }
    };
    let read_src = |env: &mut BareEnv, bytes: usize| -> Result<[u8; 32], InterpExit> {
        match decode::rm_of(&mut env.backend, md, next_rip, seg, false, false) {
            decode::Rm::Reg(_) => Ok(zget(env, decode::rm_reg_x5(md))),
            decode::Rm::Mem { a, .. } => {
                let mut v = [0u8; 32];
                env.backend
                    .mem
                    .read(VirtAddr(a), &mut v[..bytes], acc_r)
                    .map_err(|er| amx_mem_exit(a, er))?;
                Ok(v)
            }
        }
    };
    let dst_r = decode::reg_x5(md);
    let dst = zget(env, dst_r);
    let s1 = zget(env, md.vex_v);
    let q64 = |v: &[u8; 32], i: usize| u64::from_le_bytes(v[i * 8..i * 8 + 8].try_into().unwrap());
    let d32 = |v: &[u8; 32], i: usize| u32::from_le_bytes(v[i * 4..i * 4 + 4].try_into().unwrap());
    let mut out = [0u8; 32];
    let put64 = |out: &mut [u8; 32], i: usize, x: u64| {
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    };
    match md.insn {
        Insn::Vsha512rnds2XvHvWv => {
            let s2 = read_src(env, 16)?;
            let ch = |e: u64, f: u64, g: u64| (e & f) ^ (!e & g);
            let maj = |a: u64, b: u64, c: u64| (a & b) ^ (a & c) ^ (b & c);
            let sg0 = |x: u64| x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39);
            let sg1 = |x: u64| x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41);
            let mut a = q64(&s1, 3);
            let mut b = q64(&s1, 2);
            let mut c = q64(&dst, 3);
            let mut d = q64(&dst, 2);
            let mut e = q64(&s1, 1);
            let mut f = q64(&s1, 0);
            let mut g = q64(&dst, 1);
            let mut h = q64(&dst, 0);
            for i in 0..2 {
                let wk = q64(&s2, i);
                let t1 = ch(e, f, g)
                    .wrapping_add(sg1(e))
                    .wrapping_add(wk)
                    .wrapping_add(h);
                let t2 = maj(a, b, c).wrapping_add(sg0(a));
                let na = t1.wrapping_add(t2);
                let ne = t1.wrapping_add(d);
                h = g;
                g = f;
                f = e;
                d = c;
                c = b;
                b = a;
                e = ne;
                a = na;
            }
            put64(&mut out, 3, a);
            put64(&mut out, 2, b);
            put64(&mut out, 1, e);
            put64(&mut out, 0, f);
        }
        Insn::Vsha512msg1XvWv => {
            let s2 = read_src(env, 16)?;
            let sg0 = |x: u64| x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
            let w = [
                q64(&dst, 0),
                q64(&dst, 1),
                q64(&dst, 2),
                q64(&dst, 3),
                q64(&s2, 0),
            ];
            for i in 0..4 {
                put64(&mut out, i, w[i].wrapping_add(sg0(w[i + 1])));
            }
        }
        Insn::Vsha512msg2XvWv => {
            let s2 = read_src(env, 32)?;
            let sg1 = |x: u64| x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6);
            let mut w = [0u64; 4];
            w[0] = q64(&dst, 0).wrapping_add(sg1(q64(&s2, 2)));
            w[1] = q64(&dst, 1).wrapping_add(sg1(q64(&s2, 3)));
            w[2] = q64(&dst, 2).wrapping_add(sg1(w[0]));
            w[3] = q64(&dst, 3).wrapping_add(sg1(w[1]));
            for (i, x) in w.iter().enumerate() {
                put64(&mut out, i, *x);
            }
        }
        Insn::Vsm3msg1XvHvWv | Insn::Vsm3msg2XvHvWv => {
            let s2 = read_src(env, 16)?;
            let p1 = |x: u32| x ^ x.rotate_left(15) ^ x.rotate_left(23);
            if md.insn == Insn::Vsm3msg1XvHvWv {
                for i in 0..4 {
                    let mut x = d32(&dst, i) ^ d32(&s2, i);
                    if i < 3 {
                        x ^= d32(&s1, i).rotate_left(15);
                    }
                    out[i * 4..i * 4 + 4].copy_from_slice(&p1(x).to_le_bytes());
                }
            } else {
                let mut first = 0u32;
                for i in 0..4 {
                    let mut x = d32(&dst, i) ^ d32(&s2, i) ^ d32(&s1, i).rotate_left(7);
                    if i == 0 {
                        first = x;
                    } else if i == 3 {
                        x ^= p1(first.rotate_left(15));
                    }
                    out[i * 4..i * 4 + 4].copy_from_slice(&x.to_le_bytes());
                }
            }
        }
        _ => {
            // VSM4KEY4/VSM4RNDS4。128 ビットレーンごとに独立。
            let s2 = read_src(env, vbytes)?;
            let key = md.insn == Insn::Vsm4key4XvHvWv;
            for lane in 0..vbytes / 16 {
                let base = lane * 4;
                let mut a = d32(&s1, base);
                let mut b = d32(&s1, base + 1);
                let mut c = d32(&s1, base + 2);
                let mut d = d32(&s1, base + 3);
                for j in 0..4 {
                    let x0 = b ^ c ^ d ^ d32(&s2, base + j);
                    let x1 = sm4_sub_word(x0);
                    let lin = if key {
                        x1 ^ x1.rotate_left(13) ^ x1.rotate_left(23)
                    } else {
                        x1 ^ x1.rotate_left(2)
                            ^ x1.rotate_left(10)
                            ^ x1.rotate_left(18)
                            ^ x1.rotate_left(24)
                    };
                    let x = a ^ lin;
                    out[(base + j) * 4..(base + j) * 4 + 4].copy_from_slice(&x.to_le_bytes());
                    a = b;
                    b = c;
                    c = d;
                    d = x;
                }
            }
        }
    }
    zput(env, dst_r, &out);
    Ok(())
}

/// AVX-NE-CONVERT の VEX 形。狭い浮動小数点変換で例外を
/// 立てない命令群なので、AVX10 と同じく具体値で処理する。
fn avxne_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
) -> Option<Result<(), InterpExit>> {
    use polyisa_guest_x86::Insn;
    if !matches!(
        md.insn,
        Insn::Vcvtneoph2psXvWv
            | Insn::Vcvtneeph2psXvWv
            | Insn::Vcvtneebf162psXvWv
            | Insn::Vcvtneobf162psXvWv
            | Insn::Vbcstnesh2psXvWv
            | Insn::Vbcstnebf162psXvWv
            | Insn::Vcvtneps2bf16XvWv
    ) {
        return None;
    }
    Some(avxne_exec(env, md, next_rip, seg, eip))
}

/// FP16 をビット保存で FP32 へ広げる。有限値は正確で、
/// 非正規 FP16 は正規 FP32 になる。NaN は quiet bit を立てる。
fn fp16_bits_to_fp32(h: u16) -> u32 {
    let s = u32::from(h & 0x8000) << 16;
    let e = u32::from((h >> 10) & 0x1f);
    let m = u32::from(h & 0x03ff);
    if e == 0 {
        if m == 0 {
            return s;
        }
        let v = (m as f32) * 2f32.powi(-24);
        return s | (v.to_bits() & 0x7fff_ffff);
    }
    if e == 0x1f {
        if m == 0 {
            return s | 0x7f80_0000;
        }
        return s | 0x7f80_0000 | (m << 13) | 0x0040_0000;
    }
    s | ((e + 112) << 23) | (m << 13)
}

fn avxne_exec(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    _eip: u32,
) -> Result<(), InterpExit> {
    use polyisa_guest_x86::{Insn, decode, sem};
    let vbytes = if md.vex_l { 32usize } else { 16 };
    let acc_r = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    let zget = |env: &mut BareEnv, r: u8| -> [u8; 32] {
        let mut v = [0u8; 32];
        for p in 0..2 {
            v[p * 16..p * 16 + 16]
                .copy_from_slice(&env.backend.get(sem::zreg_ref(r, p)).to_le_bytes());
        }
        v
    };
    let zput = |env: &mut BareEnv, r: u8, v: &[u8; 32]| {
        for p in 0..2 {
            env.backend.set(
                sem::zreg_ref(r, p),
                u128::from_le_bytes(v[p * 16..p * 16 + 16].try_into().unwrap()),
            );
        }
    };
    let rm = decode::rm_of(&mut env.backend, md, next_rip, seg, false, false);
    let mut src = [0u8; 32];
    match rm {
        decode::Rm::Reg(_) => {
            src = zget(env, decode::rm_reg_x5(md));
        }
        decode::Rm::Mem { a, .. } => {
            let read_len = if matches!(md.insn, Insn::Vbcstnesh2psXvWv | Insn::Vbcstnebf162psXvWv) {
                2
            } else {
                vbytes
            };
            env.backend
                .mem
                .read(VirtAddr(a), &mut src[..read_len], acc_r)
                .map_err(|er| amx_mem_exit(a, er))?;
        }
    }
    let mut out = [0u8; 32];
    match md.insn {
        Insn::Vcvtneoph2psXvWv
        | Insn::Vcvtneeph2psXvWv
        | Insn::Vcvtneebf162psXvWv
        | Insn::Vcvtneobf162psXvWv => {
            let odd = matches!(md.insn, Insn::Vcvtneoph2psXvWv | Insn::Vcvtneobf162psXvWv);
            let bf = matches!(md.insn, Insn::Vcvtneebf162psXvWv | Insn::Vcvtneobf162psXvWv);
            for i in 0..vbytes / 4 {
                let at = i * 4 + if odd { 2 } else { 0 };
                let h = u16::from_le_bytes(src[at..at + 2].try_into().unwrap());
                let w = if bf {
                    u32::from(h) << 16
                } else {
                    fp16_bits_to_fp32(h)
                };
                out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        Insn::Vbcstnesh2psXvWv | Insn::Vbcstnebf162psXvWv => {
            let h = u16::from_le_bytes(src[0..2].try_into().unwrap());
            let w = if md.insn == Insn::Vbcstnebf162psXvWv {
                u32::from(h) << 16
            } else {
                fp16_bits_to_fp32(h)
            };
            for i in 0..vbytes / 4 {
                out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        _ => {
            // VCVTNEPS2BF16。RNE 固定・MXCSR 非参照で、入力の
            // 非正規は符号付き 0 へフラッシュする。出力は xmm の下位半分。
            for i in 0..vbytes / 4 {
                let mut w = u32::from_le_bytes(src[i * 4..i * 4 + 4].try_into().unwrap());
                if w & 0x7fff_ffff != 0 && w & 0x7f80_0000 == 0 {
                    w &= 0x8000_0000;
                }
                let h = if w & 0x7f80_0000 == 0x7f80_0000 && w & 0x007f_ffff != 0 {
                    // NaN は符号とペイロード上位を残し、quiet bit を立てる。
                    ((w >> 16) & 0x8000) | 0x7f80 | ((w >> 16) & 0x007f) | 0x40
                } else {
                    // 7FFFh + 保持最下位ビットを足して偶数丸めし、上位 16 ビットを取る。
                    (w.wrapping_add(0x7fff + ((w >> 16) & 1)) >> 16) & 0xffff
                };
                out[i * 2..i * 2 + 2].copy_from_slice(&(h as u16).to_le_bytes());
            }
        }
    }
    let dst = decode::reg_x5(md);
    zput(env, dst, &out);
    Ok(())
}

/// #UD（64 ビットモードの未定義命令・無効オペランド）。
/// AVX10.2 の BF16/FP8 命令。要素幅が可変で値依存のため、
/// AMX と同じく InterpBackend の具体値レベルで実行する。
fn avx10_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
) -> Option<Result<(), InterpExit>> {
    use polyisa_guest_x86::Insn;
    if !matches!(
        md.insn,
        Insn::Vaddbf16XvHvWv
            | Insn::Vsubbf16XvHvWv
            | Insn::Vmulbf16XvHvWv
            | Insn::Vdivbf16XvHvWv
            | Insn::Vminbf16XvHvWv
            | Insn::Vmaxbf16XvHvWv
            | Insn::Vsqrtbf16XvWv
            | Insn::Vdpbf16psXvHvWv
            | Insn::Vcvtph2bf8XvWv
            | Insn::Vcvtph2bf8sXvWv
            | Insn::Vcvtph2hf8XvWv
            | Insn::Vcvtph2hf8sXvWv
            | Insn::Vcvt2ph2bf8XvHvWv
            | Insn::Vcvt2ph2bf8sXvHvWv
            | Insn::Vcvt2ph2hf8XvHvWv
            | Insn::Vcvt2ph2hf8sXvHvWv
    ) {
        return None;
    }
    Some(avx10_exec(env, md, next_rip, seg, eip))
}

fn avx10_exec(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    _eip: u32,
) -> Result<(), InterpExit> {
    use polyisa_guest_x86::{Insn, decode, sem};
    use polyisa_softfloat::{BF16, F16, F32, Rm};
    let ll = usize::from(md.evex_ll);
    let vbytes = 16usize << ll;
    let acc_r = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    // ベクタレジスタの読み書き（16 バイト part 単位の StateRef 経由）。
    let zget = |env: &mut BareEnv, r: u8| -> [u8; 64] {
        let mut v = [0u8; 64];
        for p in 0..4 {
            v[p * 16..p * 16 + 16]
                .copy_from_slice(&env.backend.get(sem::zreg_ref(r, p)).to_le_bytes());
        }
        v
    };
    let zput = |env: &mut BareEnv, r: u8, v: &[u8; 64]| {
        for p in 0..4 {
            env.backend.set(
                sem::zreg_ref(r, p),
                u128::from_le_bytes(v[p * 16..p * 16 + 16].try_into().unwrap()),
            );
        }
    };
    // 第 2 ソース（rm）。ベクタ幅ぶん読む。b=1 は要素ブロードキャスト
    // （bf16 形のみ宣言上許可）。
    let src2 = |env: &mut BareEnv| -> Result<[u8; 64], InterpExit> {
        match decode::rm_of(&mut env.backend, md, next_rip, seg, false, false) {
            decode::Rm::Reg(_) => Ok(zget(env, decode::rm_reg_x5(md))),
            decode::Rm::Mem { a, .. } => {
                let mut v = [0u8; 64];
                if md.evex_b {
                    let ebw = if matches!(md.insn, Insn::Vdpbf16psXvHvWv) {
                        4
                    } else {
                        2
                    };
                    let mut e = [0u8; 4];
                    env.backend
                        .mem
                        .read(VirtAddr(a), &mut e[..ebw], acc_r)
                        .map_err(|er| amx_mem_exit(a, er))?;
                    for i in 0..vbytes / ebw {
                        v[i * ebw..i * ebw + ebw].copy_from_slice(&e[..ebw]);
                    }
                } else {
                    env.backend
                        .mem
                        .read(VirtAddr(a), &mut v[..vbytes], acc_r)
                        .map_err(|er| amx_mem_exit(a, er))?;
                }
                Ok(v)
            }
        }
    };
    let dst_r = decode::reg_x5(md);
    let old = zget(env, dst_r);
    let x = zget(env, md.vex_v);
    let y = src2(env)?;
    // マスク（aaa=0 は全 1）。z でマスクオフの要素を 0 にする。
    let k: u64 = if md.evex_aaa == 0 {
        u64::MAX
    } else {
        env.backend.get(sem::kref(md.evex_aaa))
    };
    let rd16 = |v: &[u8; 64], i: usize| u16::from_le_bytes(v[i * 2..i * 2 + 2].try_into().unwrap());
    let mut flags = 0u8;
    // AVX10.2 の bf16 演算・VDPBF16PS は DAZ/FTZ が無条件に効く
    // （bf16/f32 の非正規の入出力を ±0 にフラッシュ）。
    let bf_r = |v: &[u8; 64], i: usize| -> BF16 {
        let w = rd16(v, i);
        let m = w & 0x7fff;
        BF16::from_bits(u64::from(if m != 0 && m < 0x0080 { w & 0x8000 } else { w }))
    };
    let ftz16 = |v: BF16| -> u16 {
        let b = v.bits() as u16;
        let m = b & 0x7fff;
        if m != 0 && m < 0x0080 { b & 0x8000 } else { b }
    };
    let ftz32 = |v: F32| -> u32 {
        let b = v.bits() as u32;
        let m = b & 0x7fff_ffff;
        if m != 0 && m < 0x0080_0000 {
            b & 0x8000_0000
        } else {
            b
        }
    };
    let bf2f = |v: BF16| F32::from_bits(u64::from(v.to_f32(Rm::Rne).0.bits() as u32));
    let f2e5 = |v: F32, sat: bool, sgn: u64, fl: &mut u8| -> u8 {
        let (r, f) = v.to_e5m2(Rm::Rne);
        *fl |= f;
        // 飽和形: オーバーフローは最大有限値 0x7B（57344）に飽和。
        if sat && !v.is_nan() && r.bits() & 0x7f == 0x7c {
            return (0x7b | sgn) as u8;
        }
        r.bits() as u8
    };
    let f2e4 = |v: F32, sat: bool, sgn: u64, fl: &mut u8| -> u8 {
        let (r, f) = v.to_e4m3(Rm::Rne);
        *fl |= f;
        if sat && !v.is_nan() && r.bits() & 0x7f == 0x7f {
            return (0x7e | sgn) as u8;
        }
        r.bits() as u8
    };
    let mut out = [0u8; 64];
    let lanes16 = vbytes / 2;
    let insn = md.insn;
    let merge16 = |out: &mut [u8; 64], old: &[u8; 64], d: &polyisa_guest_x86::MapDec| {
        for i in 0..lanes16 {
            if k >> i & 1 == 0 {
                let keep = if d.evex_z { 0 } else { rd16(old, i) };
                out[i * 2..i * 2 + 2].copy_from_slice(&keep.to_le_bytes());
            }
        }
    };
    match insn {
        Insn::Vaddbf16XvHvWv
        | Insn::Vsubbf16XvHvWv
        | Insn::Vmulbf16XvHvWv
        | Insn::Vdivbf16XvHvWv
        | Insn::Vminbf16XvHvWv
        | Insn::Vmaxbf16XvHvWv
        | Insn::Vsqrtbf16XvWv => {
            for i in 0..lanes16 {
                let a = bf_r(&x, i);
                let c = bf_r(&y, i);
                let (g, f) = match insn {
                    Insn::Vaddbf16XvHvWv => a.add_rm(c, Rm::Rne),
                    Insn::Vsubbf16XvHvWv => a.sub_rm(c, Rm::Rne),
                    Insn::Vmulbf16XvHvWv => a.mul_rm(c, Rm::Rne),
                    Insn::Vdivbf16XvHvWv => a.div_rm(c, Rm::Rne),
                    // x86 の MIN/MAX は src1 < src2 なら src1、それ以外
                    // （非順序・同値を含む）は src2 を返す。
                    Insn::Vminbf16XvHvWv => (if a.lt(c).0 { a } else { c }, 0),
                    Insn::Vmaxbf16XvHvWv => (if c.lt(a).0 { a } else { c }, 0),
                    _ => c.sqrt_rm(Rm::Rne),
                };
                flags |= f;
                out[i * 2..i * 2 + 2].copy_from_slice(&ftz16(g).to_le_bytes());
            }
            merge16(&mut out, &old, md);
        }
        Insn::Vdpbf16psXvHvWv => {
            // bf16 要素対の積を f32 へ蓄積するドット積。DAZ 入力・
            // FTZ 出力で、高位要素対の積から順に各ステップを
            // RNE で f32 に畳む近似（gaps: AVX10.2 の累積精度）。
            let lanes32 = vbytes / 4;
            for i in 0..lanes32 {
                if k >> i & 1 == 0 {
                    let keep: [u8; 4] = if md.evex_z {
                        [0; 4]
                    } else {
                        old[i * 4..i * 4 + 4].try_into().unwrap()
                    };
                    out[i * 4..i * 4 + 4].copy_from_slice(&keep);
                    continue;
                }
                let mut accb = u32::from_le_bytes(old[i * 4..i * 4 + 4].try_into().unwrap());
                let m = accb & 0x7fff_ffff;
                if m != 0 && m < 0x0080_0000 {
                    accb &= 0x8000_0000;
                }
                let acc = F32::from_bits(u64::from(accb));
                let (lo, f1) = bf2f(bf_r(&x, 2 * i)).mul_rm(bf2f(bf_r(&y, 2 * i)), Rm::Rne);
                let (hi, f2) = bf2f(bf_r(&x, 2 * i + 1)).mul_rm(bf2f(bf_r(&y, 2 * i + 1)), Rm::Rne);
                let (s1, f3) = acc.add_rm(hi, Rm::Rne);
                let (s2, f4) = s1.add_rm(lo, Rm::Rne);
                flags |= f1 | f2 | f3 | f4;
                out[i * 4..i * 4 + 4].copy_from_slice(&ftz32(s2).to_le_bytes());
            }
        }
        _ => {
            // FP8 変換。入力は f16。`two` は 2 ソース形で要素対ごとの
            // 交互配置、`sat` は飽和形。
            let (two, sat, hf8) = match insn {
                Insn::Vcvtph2bf8XvWv => (false, false, false),
                Insn::Vcvtph2bf8sXvWv => (false, true, false),
                Insn::Vcvtph2hf8XvWv => (false, false, true),
                Insn::Vcvtph2hf8sXvWv => (false, true, true),
                Insn::Vcvt2ph2bf8XvHvWv => (true, false, false),
                Insn::Vcvt2ph2bf8sXvHvWv => (true, true, false),
                Insn::Vcvt2ph2hf8XvHvWv => (true, false, true),
                Insn::Vcvt2ph2hf8sXvHvWv => (true, true, true),
                _ => unreachable!(),
            };
            let f16f = |w: u16| {
                F32::from_bits(u64::from(
                    (F16::from_bits(u64::from(w)).to_f32(Rm::Rne).0.bits()) as u32,
                ))
            };
            let cvt = |v: F32, fl: &mut u8| -> u8 {
                let sgn = ((v.bits() >> 31) & 1) << 7;
                if hf8 {
                    f2e4(v, sat, sgn, fl)
                } else {
                    f2e5(v, sat, sgn, fl)
                }
            };
            if two {
                // 出力の下位半分 ← src2（r/m）、上位半分 ← src1（vvvv）。
                for i in 0..lanes16 {
                    if k >> i & 1 != 0 {
                        out[i] = cvt(f16f(rd16(&y, i)), &mut flags);
                    } else {
                        out[i] = if md.evex_z { 0 } else { old[i] };
                    }
                    if k >> (lanes16 + i) & 1 != 0 {
                        out[lanes16 + i] = cvt(f16f(rd16(&x, i)), &mut flags);
                    } else {
                        out[lanes16 + i] = if md.evex_z { 0 } else { old[lanes16 + i] };
                    }
                }
            } else {
                // 1 ソース形は出力が半幅。上位は 0。
                for i in 0..lanes16 {
                    if k >> i & 1 != 0 {
                        out[i] = cvt(f16f(rd16(&y, i)), &mut flags);
                    } else {
                        out[i] = if md.evex_z { 0 } else { old[i] };
                    }
                }
            }
        }
    }
    zput(env, dst_r, &out);
    env.backend.fp_flags |= flags;
    Ok(())
}

fn amx_ud(eip: u32) -> InterpExit {
    InterpExit::Exception(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Undefined,
        code: 6,
        addr: Some(u64::from(eip)),
        in_delay_slot: false,
    })
}

/// タイル命令のメモリアクセスの失敗を例外に写す
/// （`InterpBackend::load` の `mem_exit` と同じ写像）。
fn amx_mem_exit(addr: u64, e: polyisa_mem::MemError) -> InterpExit {
    match e {
        polyisa_mem::MemError::NotAligned => InterpExit::Exception(polyisa_sem::GuestException {
            kind: polyisa_sem::ExceptionKind::Align,
            code: 0,
            addr: Some(addr),
            in_delay_slot: false,
        }),
        polyisa_mem::MemError::PageFault | polyisa_mem::MemError::OutOfMemory => {
            InterpExit::Exception(polyisa_sem::GuestException {
                kind: polyisa_sem::ExceptionKind::PageFault,
                code: 0,
                addr: Some(addr),
                in_delay_slot: false,
            })
        }
    }
}

/// XSAVEC（0F C7 /4）。標準 XSAVE と同じ成分を、RFBM にある
/// 拡張成分だけを 64 バイト整列で詰める圧縮レイアウトで書く。
/// XINUSE の省略最適化はせず、選択成分は使用中として保存する。
fn xsavec_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
    mode: u8,
) -> Option<Result<(), InterpExit>> {
    if md.insn != polyisa_guest_x86::Insn::XsavecMem {
        return None;
    }
    Some(xsavec_exec(env, md, next_rip, seg, eip, mode))
}

fn xsavec_w64(env: &mut BareEnv, a: u64, v: u64) -> Result<(), InterpExit> {
    env.backend
        .mem
        .write(VirtAddr(a), &v.to_le_bytes())
        .map_err(|e| amx_mem_exit(a, e))
}

fn xsavec_w128(env: &mut BareEnv, a: u64, v: u128) -> Result<(), InterpExit> {
    env.backend
        .mem
        .write(VirtAddr(a), &v.to_le_bytes())
        .map_err(|e| amx_mem_exit(a, e))
}

fn xsavec_exec(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
    mode: u8,
) -> Result<(), InterpExit> {
    use polyisa_guest_x86::{decode, sem, sem_ea};
    use polyisa_sem::Backend;
    let rm = decode::rm_of(&mut env.backend, md, next_rip, seg, false, false);
    let decode::Rm::Mem { a, .. } = rm else {
        return Err(amx_ud(eip));
    };
    let lo = u64::from(env.backend.get(polyisa_guest_x86::sem::Gpr(0).state()));
    let hi = u64::from(env.backend.get(polyisa_guest_x86::sem::Gpr(2).state()));
    let mask = ((hi << 32) | lo) & env.backend.get(sem::xcr0_ref());
    let b = &mut env.backend;
    sem_ea::fxsave_area(b, a, None, mode, mask & 1 != 0, mask & 2 != 0)?;
    // XSTATE_BV と XCOMP_BV。圧縮形式は bit63、下位は RFBM∩XCR0。
    xsavec_w64(env, a + 512, mask)?;
    xsavec_w64(env, a + 520, (1u64 << 63) | mask)?;
    // leaf D の ECX[1] どおり、AMX 成分だけを 64 バイト整列する。
    // YMMH・AVX-512 成分は直前成分の直後に置く。
    let mut off = 576u64;
    let mut put =
        |env: &mut BareEnv,
         bit: u64,
         size: u64,
         write: &mut dyn FnMut(&mut BareEnv, u64) -> Result<(), InterpExit>| {
            if mask & (1u64 << bit) == 0 {
                return Ok(());
            }
            if bit >= 17 {
                off = off.next_multiple_of(64);
            }
            write(env, a + off)?;
            off += size;
            Ok(())
        };
    put(env, 2, 0x100, &mut |env, base| {
        for i in 0..16u8 {
            let v = env.backend.get(sem::ymm_hi_ref(sem::Xmm(i)));
            xsavec_w128(env, base + u64::from(i) * 16, v)?;
        }
        Ok(())
    })?;
    put(env, 5, 0x40, &mut |env, base| {
        for i in 0..8u8 {
            let v = env.backend.get(sem::kref(i));
            xsavec_w64(env, base + u64::from(i) * 8, v)?;
        }
        Ok(())
    })?;
    put(env, 6, 0x200, &mut |env, base| {
        for r in 0..16u8 {
            for part in 2..4usize {
                let v = env.backend.get(sem::zreg_ref(r, part));
                xsavec_w128(env, base + u64::from(r) * 32 + (part as u64 - 2) * 16, v)?;
            }
        }
        Ok(())
    })?;
    put(env, 7, 0x400, &mut |env, base| {
        for r in 16..32u8 {
            for part in 0..4usize {
                let v = env.backend.get(sem::zreg_ref(r, part));
                xsavec_w128(env, base + u64::from(r - 16) * 64 + part as u64 * 16, v)?;
            }
        }
        Ok(())
    })?;
    put(env, 17, 0x40, &mut |env, base| {
        for i in 0..8usize {
            let v = env.backend.get(sem::tilecfg_qref(i));
            xsavec_w64(env, base + i as u64 * 8, v)?;
        }
        Ok(())
    })?;
    put(env, 18, 0x2000, &mut |env, base| {
        for i in 0..1024usize {
            let v = env.backend.get(sem::tmm_qref(i));
            xsavec_w64(env, base + i as u64 * 8, v)?;
        }
        Ok(())
    })
}

/// XSAVEC が書く圧縮形式かどうかをヘッダで調べ、必要なら
/// XRSTOR を圧縮レイアウトとして実行する。標準形式なら None を
/// 返して既存の IR 実装へ任せる。
fn xrstorc_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
    mode: u8,
) -> Option<Result<(), InterpExit>> {
    if md.insn != polyisa_guest_x86::Insn::Xrstor {
        return None;
    }
    let rm = polyisa_guest_x86::decode::rm_of(&mut env.backend, md, next_rip, seg, false, false);
    let polyisa_guest_x86::decode::Rm::Mem { a, .. } = rm else {
        return Some(Err(amx_ud(eip)));
    };
    match xsavec_r64(env, a + 520) {
        Ok(xcomp) if xcomp & (1u64 << 63) != 0 => {
            Some(xrstorc_exec(env, md, next_rip, seg, eip, mode, xcomp))
        }
        Ok(_) => None,
        Err(e) => Some(Err(e)),
    }
}

fn xsavec_r64(env: &mut BareEnv, a: u64) -> Result<u64, InterpExit> {
    let acc = Access {
        endian: Endian::Le,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    };
    let mut v = [0u8; 8];
    env.backend
        .mem
        .read(VirtAddr(a), &mut v, acc)
        .map_err(|e| amx_mem_exit(a, e))?;
    Ok(u64::from_le_bytes(v))
}

fn xsavec_r128(env: &mut BareEnv, a: u64) -> Result<u128, InterpExit> {
    let acc = Access {
        endian: Endian::Le,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    };
    let mut v = [0u8; 16];
    env.backend
        .mem
        .read(VirtAddr(a), &mut v, acc)
        .map_err(|e| amx_mem_exit(a, e))?;
    Ok(u128::from_le_bytes(v))
}

/// polyisa が保存する圧縮成分のサイズ。未知成分は XCOMP_SUPP に
/// 含めていないので、正規の XCR0 では発生しない。
fn xsavec_size(bit: u64) -> u64 {
    match bit {
        2 => 0x100,
        5 => 0x40,
        6 => 0x200,
        7 => 0x400,
        17 => 0x40,
        18 => 0x2000,
        _ => 0,
    }
}

/// XCOMP_BV が示す圧縮レイアウトでの成分オフセット。成分は昇順に
/// 並び、polyisa が CPUID で報告するものは 64 バイト整列を要求する。
fn xsavec_offset(xcomp: u64, bit: u64) -> u64 {
    let mut off = 576u64;
    for b in 2..=bit {
        if xcomp & (1u64 << b) == 0 {
            continue;
        }
        if b >= 17 {
            off = off.next_multiple_of(64);
        }
        if b == bit {
            return off;
        }
        off += xsavec_size(b);
    }
    off
}

fn xrstorc_exec(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
    mode: u8,
    xcomp: u64,
) -> Result<(), InterpExit> {
    use polyisa_guest_x86::{decode, sem, sem_ea};
    use polyisa_sem::Backend;
    let rm = decode::rm_of(&mut env.backend, md, next_rip, seg, false, false);
    let decode::Rm::Mem { a, .. } = rm else {
        return Err(amx_ud(eip));
    };
    let xbv = xsavec_r64(env, a + 512)?;
    let lo = u64::from(env.backend.get(sem::Gpr(0).state()));
    let hi = u64::from(env.backend.get(sem::Gpr(2).state()));
    let mask = ((hi << 32) | lo) & env.backend.get(sem::xcr0_ref());
    let rst = mask & xbv;
    let ini = mask & !xbv;
    let b = &mut env.backend;
    sem_ea::fxrstor_area(b, a, None, mode, rst, ini)?;
    // YMMH。
    let off = xsavec_offset(xcomp, 2);
    if rst & 4 != 0 {
        for i in 0..16u8 {
            let v = xsavec_r128(env, a + off + u64::from(i) * 16)?;
            env.backend.set(sem::ymm_hi_ref(sem::Xmm(i)), v);
        }
    } else if ini & 4 != 0 {
        for i in 0..16u8 {
            env.backend.set(sem::ymm_hi_ref(sem::Xmm(i)), 0);
        }
    }
    // opmask。
    let off = xsavec_offset(xcomp, 5);
    if rst & (1 << 5) != 0 {
        for i in 0..8u8 {
            let v = xsavec_r64(env, a + off + u64::from(i) * 8)?;
            env.backend.set(sem::kref(i), v);
        }
    } else if ini & (1 << 5) != 0 {
        for i in 0..8u8 {
            env.backend.set(sem::kref(i), 0);
        }
    }
    // ZMM_Hi256 / Hi16_ZMM。
    for (bit, first, last, parts, stride) in [
        (6u64, 0u8, 16u8, 2..4usize, 32u64),
        (7, 16, 32, 0..4usize, 64),
    ] {
        let off = xsavec_offset(xcomp, bit);
        if rst & (1 << bit) != 0 {
            for r in first..last {
                for part in parts.clone() {
                    let row = if bit == 6 {
                        u64::from(r)
                    } else {
                        u64::from(r - 16)
                    };
                    let poff = if bit == 6 {
                        part as u64 - 2
                    } else {
                        part as u64
                    };
                    let v = xsavec_r128(env, a + off + row * stride + poff * 16)?;
                    env.backend.set(sem::zreg_ref(r, part), v);
                }
            }
        } else if ini & (1 << bit) != 0 {
            for r in first..last {
                for part in parts.clone() {
                    env.backend.set(sem::zreg_ref(r, part), 0);
                }
            }
        }
    }
    // AMX tilecfg/tiledata。
    let off = xsavec_offset(xcomp, 17);
    if rst & (1 << 17) != 0 {
        for i in 0..8usize {
            let v = xsavec_r64(env, a + off + i as u64 * 8)?;
            env.backend.set(sem::tilecfg_qref(i), v);
        }
    } else if ini & (1 << 17) != 0 {
        for i in 0..8usize {
            env.backend.set(sem::tilecfg_qref(i), 0);
        }
    }
    let off = xsavec_offset(xcomp, 18);
    if rst & (1 << 18) != 0 {
        for i in 0..1024usize {
            let v = xsavec_r64(env, a + off + i as u64 * 8)?;
            env.backend.set(sem::tmm_qref(i), v);
        }
    } else if ini & (1 << 18) != 0 {
        for i in 0..1024usize {
            env.backend.set(sem::tmm_qref(i), 0);
        }
    }
    Ok(())
}

/// x87 拡張精度ビットを f64 へ落とす。53 ビットを超える精度と
/// f64 の範囲を外れる値は近似だが、超越関数の実装には十分な
/// 入力精度を持つ。exp_word は符号(bit15)+biased exponent、sig は
/// integer bit(bit63)付きの 64 ビット仮数。
fn x87_ext_to_f64(sig: u64, exp_word: u16) -> f64 {
    let neg = exp_word & 0x8000 != 0;
    let exp = i32::from(exp_word & 0x7fff);
    let sign = if neg { -1.0 } else { 1.0 };
    if exp == 0 {
        return if neg { -0.0 } else { 0.0 };
    }
    if exp == 0x7fff {
        if sig & !(1u64 << 63) != 0 {
            return f64::NAN;
        }
        return sign * f64::INFINITY;
    }
    // 先に 64 ビット仮数を [1,2) へスケールする。指数側を先に
    // 評価すると、f64 の正規数として表せる入力でも係数が先に
    // underflow して 0 になる。
    let frac = (sig as f64) * 2f64.powi(-63);
    sign * frac * 2f64.powi(exp - 16383)
}

/// f64 を x87 拡張精度ビットへ変換する。f64 で表せる値は拡張精度へ
/// 正確に写せる（丸め誤差は先行する transcendental 評価側に残る）。
fn x87_f64_to_ext(v: f64) -> (u64, u16) {
    let bits = v.to_bits();
    let sign = ((bits >> 63) as u16) << 15;
    let exp11 = ((bits >> 52) & 0x7ff) as i32;
    let frac = bits & ((1u64 << 52) - 1);
    if exp11 == 0x7ff {
        let sig = if frac == 0 {
            1u64 << 63
        } else {
            0xC000_0000_0000_0000
        };
        return (sig, sign | 0x7fff);
    }
    if exp11 == 0 && frac == 0 {
        return (0, sign);
    }
    if exp11 == 0 {
        // f64 非正規化数: frac * 2^-1074。最高位を integer bit へ
        // 揃え、指数はその位置に応じる。
        let p = 63 - frac.leading_zeros() as i32;
        let sig = frac << (63 - p);
        let exp = (p - 1074 + 16383) as u16;
        (sig, sign | exp)
    } else {
        let sig = (1u64 << 63) | (frac << 11);
        let exp = (exp11 - 1023 + 16383) as u16;
        (sig, sign | exp)
    }
}

fn x87_st_index(env: &mut BareEnv, logical: u16) -> usize {
    let top: u16 = env.backend.get(polyisa_guest_x86::sem::top_ref());
    usize::from((top + logical) & 7)
}

fn x87_read_st(env: &mut BareEnv, logical: u16) -> (u64, u16) {
    let i = x87_st_index(env, logical);
    (
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(i)),
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(i)),
    )
}

fn x87_write_st(env: &mut BareEnv, logical: u16, value: (u64, u16)) {
    let i = x87_st_index(env, logical);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(i), value.0);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(i), value.1);
}

fn x87_push(env: &mut BareEnv, value: (u64, u16)) {
    let top: u16 = env.backend.get(polyisa_guest_x86::sem::top_ref());
    let nt = top.wrapping_sub(1) & 7;
    env.backend.set(polyisa_guest_x86::sem::top_ref(), nt);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(usize::from(nt)), value.0);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(usize::from(nt)), value.1);
}

fn x87_pop(env: &mut BareEnv) {
    let top: u16 = env.backend.get(polyisa_guest_x86::sem::top_ref());
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(usize::from(top)), 0);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(usize::from(top)), 0);
    env.backend
        .set(polyisa_guest_x86::sem::top_ref(), (top + 1) & 7);
}

fn x87_set_c2(env: &mut BareEnv, on: bool) {
    let fsw: u16 = env.backend.get(polyisa_guest_x86::sem::fsw_ref());
    let nv = if on { fsw | 0x0400 } else { fsw & !0x0400 };
    env.backend.set(polyisa_guest_x86::sem::fsw_ref(), nv);
}

fn x87_transcendental_exec(env: &mut BareEnv, op: u8) {
    let (s0, e0) = x87_read_st(env, 0);
    // FSIN/FCOS/FSINCOS/FPTAN の有限入力は |x| < 2^63。範囲外では
    // C2=1、ST(0) 不変で、push 系も push しない。`exp` は bias 付き
    // なので 2^63 は 16383+63=16446。Infinity/NaN の invalid-operation
    // 面は host f64 近似に残るが、少なくとも有限大角度の制御規則は
    // ここで再現する。
    if matches!(op, 0xFB | 0xF2 | 0xFE | 0xFF) {
        let exp = i32::from(e0 & 0x7fff);
        let finite = exp != 0x7fff;
        if finite && exp >= 16446 {
            x87_set_c2(env, true);
            return;
        }
        x87_set_c2(env, false);
    }
    let x = x87_ext_to_f64(s0, e0);
    match op {
        // FSIN/FCOS は ST(0) を置き換える。
        0xFE | 0xFF => {
            let y = if op == 0xFE { x.sin() } else { x.cos() };
            x87_write_st(env, 0, x87_f64_to_ext(y));
        }
        // FSINCOS は ST(0) に sin、cos を新しい ST(0) として push する。
        0xFB => {
            x87_write_st(env, 0, x87_f64_to_ext(x.sin()));
            x87_push(env, x87_f64_to_ext(x.cos()));
        }
        // F2XM1 は 2^x-1。FPTAN は tan の後に 1.0 を push する。
        0xF0 => {
            let y = (x * std::f64::consts::LN_2).exp_m1();
            x87_write_st(env, 0, x87_f64_to_ext(y));
        }
        0xF2 => {
            x87_write_st(env, 0, x87_f64_to_ext(x.tan()));
            x87_push(env, x87_f64_to_ext(1.0));
        }
        // FPATAN: atan(ST1/ST0)、FYL2X系: ST1*log2(ST0[+1])。
        // いずれも結果を ST1 へ書いて pop する。
        0xF1 | 0xF3 | 0xF9 => {
            let (s1, e1) = x87_read_st(env, 1);
            let x1 = x87_ext_to_f64(s1, e1);
            let y = match op {
                0xF3 => x1.atan2(x),
                0xF1 => x1 * x.log2(),
                _ => x1 * (x.ln_1p() / std::f64::consts::LN_2),
            };
            x87_write_st(env, 1, x87_f64_to_ext(y));
            x87_pop(env);
        }
        _ => unreachable!(),
    }
}

/// メモリや可変幅タイル状態を直接扱う concrete 命令の 1 ステップ。
/// IR 経由の通常ディスパッチと同じく、前命令の分岐要求を消してから
/// 実行し、成功時は steps を進める。hook が対象外なら何も変えずに
/// `None` を返す。
fn concrete_step(
    env: &mut BareEnv,
    f: impl FnOnce(&mut BareEnv) -> Option<Result<(), InterpExit>>,
) -> Option<Result<(), InterpExit>> {
    env.backend.ctrl = polyisa_engine::interp::Ctrl::Fallthrough;
    let r = f(env)?;
    if r.is_ok() {
        if let polyisa_engine::interp::Ctrl::Jump(target) = env.backend.ctrl {
            env.pc = target;
        }
        env.steps += 1;
    }
    Some(r)
}

fn x87_transcendental_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
) -> Option<Result<(), InterpExit>> {
    use polyisa_guest_x86::Insn;
    if md.modrm < 0xC0 {
        return None;
    }
    let op = md.modrm;
    let hit = match md.insn {
        Insn::X87d96 => matches!(op, 0xF0..=0xF3),
        Insn::FnstcwM16 => matches!(op, 0xF9 | 0xFB | 0xFE | 0xFF),
        _ => false,
    };
    if hit {
        x87_transcendental_exec(env, op);
        Some(Ok(()))
    } else {
        None
    }
}

/// XSTORE/REP XSTORE（VIA PadLock RNG）。真の entropy source は
/// 持たないので、RDRAND と同じ splitmix64 の決定的列を使う。
/// plain 形は EDX[1:0] の品質選択に従って 8/4/2/1 バイトを返す。
fn xstore_exec(env: &mut BareEnv, md: &polyisa_guest_x86::MapDec) -> Result<(), InterpExit> {
    use polyisa_guest_x86::{Insn, sem};
    let rep = matches!(md.insn, Insn::RepXstore);
    let rdx: u64 = sem::read64(&mut env.backend, sem::Gpr(2));
    let quality = rdx & 3;
    let chunk = match quality {
        0 => 8usize,
        1 => 4,
        2 => 2,
        _ => 1,
    };
    let rcx: u64 = sem::read64(&mut env.backend, sem::Gpr(1));
    let mut rdi: u64 = sem::read64(&mut env.backend, sem::Gpr(7));
    let mut state: u64 = env.backend.get(sem::rand_state_ref());
    let seed = u64::from(env.backend.param::<polyisa_guest_x86::RandSeedParam>());
    let mut next32 = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state.wrapping_add(seed);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        z as u32
    };
    if rep {
        // REP XSTORE は quality ごとに n=8/4/2/1 バイトを 1 回分と
        // して生成し、各回を q=0 では 8 バイト、それ以外では 4 バイト
        // の store で書く。要求数が n で割り切れないときも最後の
        // 1 回分を生成するため、最大 7 バイト先まで書き、RDI も
        // 生成バイト数だけ進む。
        let n = 8usize >> quality;
        let store_n = if quality == 0 { 8 } else { 4 };
        let mut left = rcx;
        while left != 0 {
            let mut bytes = [0u8; 8];
            let mut off = 0usize;
            while off < n {
                let x = next32().to_le_bytes();
                let take = (n - off).min(4);
                bytes[off..off + take].copy_from_slice(&x[..take]);
                off += take;
            }
            env.backend
                .mem
                .write(VirtAddr(rdi), &bytes[..store_n])
                .map_err(|e| amx_mem_exit(rdi, e))?;
            rdi = rdi.wrapping_add(n as u64);
            left = left.saturating_sub(n as u64);
        }
        sem::write64(&mut env.backend, sem::Gpr(1), 0);
    } else {
        // quality 2/3 では残りの 4 バイト store を 0 で埋める。
        // quality 0 は 8 バイト（2 stores）、1 は 4 バイトを返す。
        let mut bytes = [0u8; 8];
        let mut off = 0usize;
        while off < chunk {
            let x = next32().to_le_bytes();
            let n = (chunk - off).min(4);
            bytes[off..off + n].copy_from_slice(&x[..n]);
            off += n;
        }
        let store_n = if chunk >= 4 { chunk.min(8) } else { 4 };
        env.backend
            .mem
            .write(VirtAddr(rdi), &bytes[..store_n])
            .map_err(|e| amx_mem_exit(rdi, e))?;
        rdi = rdi.wrapping_add(chunk as u64);
        sem::write64(&mut env.backend, sem::Gpr(0), chunk as u64);
    }
    env.backend.set(sem::rand_state_ref(), state);
    sem::write64(&mut env.backend, sem::Gpr(7), rdi);
    sem::write64(&mut env.backend, sem::Gpr(2), quality);
    Ok(())
}

fn xstore_step(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
) -> Option<Result<(), InterpExit>> {
    use polyisa_guest_x86::Insn;
    if matches!(md.insn, Insn::Xstore | Insn::RepXstore) {
        Some(xstore_exec(env, md))
    } else {
        None
    }
}

/// FP16 のビットパターンを f32 に変換する。
fn f16_to_f32(h: u16) -> f32 {
    let s = if h & 0x8000 != 0 { -1.0f32 } else { 1.0 };
    let e = i32::from((h >> 10) & 0x1F);
    let m = u32::from(h & 0x3FF);
    if e == 0 {
        s * (m as f32) * 2f32.powi(-24)
    } else if e == 31 {
        if m == 0 { s * f32::INFINITY } else { f32::NAN }
    } else {
        s * (1024 + m) as f32 * 2f32.powi(e - 25)
    }
}

/// タイル命令の実体。sibmem の行アドレスは base+index*scale+disp
/// のうち index*scale が行ストライドになる（start は base+disp）。
fn amx_tile_exec(
    env: &mut BareEnv,
    md: &polyisa_guest_x86::MapDec,
    next_rip: u64,
    seg: u64,
    eip: u32,
) -> Result<(), InterpExit> {
    use polyisa_guest_x86::{Insn, decode, sem};
    // XCR0 の XTILECFG(17)|XTILEDATA(18) が両方立っていなければ #UD。
    let x0: u64 = env.backend.get(sem::xcr0_ref());
    if x0 & 0x6_0000 != 0x6_0000 {
        return Err(amx_ud(eip));
    }
    let acc_r = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::DataRead,
    };
    // sibmem の行ベースとストライド。index=100b(+X=0) はストライド 0、
    // mod=00 base=101 は disp32 のみ（64 ビットでは RIP 相対）。
    let tile_ea = |env: &mut BareEnv| -> (u64, u64) {
        let s = md.sib;
        let idx_raw = (s >> 3) & 7;
        let no_index = idx_raw == 4 && (md.rex >> 1) & 1 == 0;
        let idx = idx_raw | (((md.rex >> 1) & 1) << 3);
        let base_raw = s & 7;
        let no_base = md.modrm >> 6 == 0 && base_raw == 5;
        let base = if no_base {
            md.disp as u64
        } else {
            let br = base_raw | ((md.rex & 1) << 3);
            let mut v = sem::read64(&mut env.backend, sem::Gpr(br));
            if md.asize == 32 {
                v &= 0xFFFF_FFFF;
            }
            (v as i64 + md.disp) as u64
        };
        let stride = if no_index {
            0
        } else {
            let mut v = sem::read64(&mut env.backend, sem::Gpr(idx));
            if md.asize == 32 {
                v &= 0xFFFF_FFFF;
            }
            v << (s >> 6)
        };
        (base.wrapping_add(seg), stride)
    };
    // メモリ形の EA（LDTILECFG/STTILECFG。タイル命令はリニア
    // アドレスを直接使い、modrm.reg の値は見ない）。
    let ea_mem = |env: &mut BareEnv| -> Result<u64, InterpExit> {
        // mod!=11 は必ず sibmem でも通常の EA 規則でも同じ並びの
        // バイトなので汎用 EA 評価で求める。
        match decode::rm_of(&mut env.backend, md, next_rip, seg, false, false) {
            decode::Rm::Mem { a, .. } => Ok(a),
            decode::Rm::Reg(_) => Err(amx_ud(eip)),
        }
    };
    let insn = md.insn;
    let st = &mut env.backend.state;
    match insn {
        Insn::Ldtilecfg | Insn::Sttilecfg => {
            let ea = ea_mem(env)?;
            let st = &mut env.backend.state;
            if insn == Insn::Ldtilecfg {
                let mut cfg = [0u8; 64];
                env.backend
                    .mem
                    .read(VirtAddr(ea), &mut cfg, acc_r)
                    .map_err(|e| amx_mem_exit(ea, e))?;
                // palette>1 は #GP。0 は解放（検査を経ずに全状態を
                // クリア）。1 なら予約域・tile8-15・寸法を検査する。
                if cfg[0] > 1 {
                    return Err(amx_ud(eip));
                }
                if cfg[0] == 1 {
                    // bytes2-15 の予約域と、palette1 で使わない
                    // tile8-15 の colsb/rows は 0 必須。
                    if cfg[2..16].iter().any(|&b| b != 0)
                        || cfg[32..48].iter().any(|&b| b != 0)
                        || cfg[56..64].iter().any(|&b| b != 0)
                    {
                        return Err(amx_ud(eip));
                    }
                    for i in 0..8 {
                        let cb = u16::from_le_bytes([cfg[16 + 2 * i], cfg[17 + 2 * i]]);
                        // colsb<=64・rows<=16・片方だけ 0 は #GP。
                        if cb > 64 || cfg[48 + i] > 16 || (cb == 0) != (cfg[48 + i] == 0) {
                            return Err(amx_ud(eip));
                        }
                    }
                }
                st[TILECFG_OFF..TILECFG_OFF + 64].copy_from_slice(&cfg);
                st[TMM_OFF..TMM_OFF + 8 * 1024].fill(0);
            } else {
                env.backend
                    .mem
                    .write(VirtAddr(ea), &st[TILECFG_OFF..TILECFG_OFF + 64])
                    .map_err(|e| amx_mem_exit(ea, e))?;
            }
            return Ok(());
        }
        Insn::Tilerelease => {
            st[TILECFG_OFF..TILECFG_OFF + 64].fill(0);
            st[TMM_OFF..TMM_OFF + 8 * 1024].fill(0);
            return Ok(());
        }
        _ => {}
    }
    // 以下は構成済み（palette=1）が前提。
    if st[TILECFG_OFF] != 1 {
        return Err(amx_ud(eip));
    }
    let dst = (md.modrm >> 3) & 7;
    match insn {
        Insn::Tilezero => {
            if !tile_valid(st, dst) || md.rex & 4 != 0 {
                return Err(amx_ud(eip));
            }
            let n = tile_rows(st, dst) * tile_colsb(st, dst);
            st[TMM_OFF + usize::from(dst) * 1024..TMM_OFF + usize::from(dst) * 1024 + n].fill(0);
            Ok(())
        }
        Insn::Tileloadd
        | Insn::Tileloaddt1
        | Insn::Tileloaddrs
        | Insn::Tileloaddrst1
        | Insn::Tilestored => {
            let (load, t) = if insn == Insn::Tilestored {
                (false, dst)
            } else {
                (true, dst)
            };
            // colsb は 4 バイト単位、startRow < rows、reg 側の
            // R 拡張ビット（tmm8-15 を指す）は #UD。
            if !tile_valid(st, t)
                || md.rex & 4 != 0
                || !tile_colsb(st, t).is_multiple_of(4)
                || usize::from(st[TILECFG_OFF + 1]) >= tile_rows(st, t)
            {
                return Err(amx_ud(eip));
            }
            let (base, stride) = tile_ea(env);
            let st = &mut env.backend.state;
            let colsb = tile_colsb(st, t);
            let srow = usize::from(st[TILECFG_OFF + 1]);
            for r in srow..tile_rows(st, t) {
                let a = base.wrapping_add(stride.wrapping_mul(r as u64));
                let cell = TMM_OFF + usize::from(t) * 1024 + r * colsb;
                if load {
                    let mut row = vec![0u8; colsb];
                    env.backend
                        .mem
                        .read(VirtAddr(a), &mut row, acc_r)
                        .map_err(|e| amx_mem_exit(a, e))?;
                    st[cell..cell + colsb].copy_from_slice(&row);
                } else {
                    let row = st[cell..cell + colsb].to_vec();
                    env.backend
                        .mem
                        .write(VirtAddr(a), &row)
                        .map_err(|e| amx_mem_exit(a, e))?;
                }
            }
            st[TILECFG_OFF + 1] = 0;
            Ok(())
        }
        _ => {
            // TDP/TCMM: dst=modrm.reg、src1=modrm.r/m、src2=vvvv。
            let s1 = md.modrm & 7;
            let s2 = decode::vvv_t(md);
            // 全て別レジスタ・vvvv<8・拡張ビットなし・rows(s1)=rows(dst)
            // が実機の受理条件。
            if !tile_valid(st, dst)
                || !tile_valid(st, s1)
                || !tile_valid(st, s2)
                || dst == s1
                || dst == s2
                || s1 == s2
                || md.vex_v > 7
                || md.rex & 7 != 0
                || tile_rows(st, s1) != tile_rows(st, dst)
            {
                return Err(amx_ud(eip));
            }
            // 形状の整合: 積和は dst が M×N dword、src1 が M×(4K) バイト
            // （FP16/BF16 では M×(2K) 要素）、src2 が K×N dword。
            let md_rows = tile_rows(st, dst);
            let md_cols = tile_colsb(st, dst) / 4;
            if !tile_colsb(st, dst).is_multiple_of(4) || !tile_colsb(st, s2).is_multiple_of(4) {
                return Err(amx_ud(eip));
            }
            if tile_colsb(st, s2) != tile_colsb(st, dst) {
                return Err(amx_ud(eip));
            }
            let int8 = matches!(
                insn,
                Insn::Tdpbssd | Insn::Tdpbsud | Insn::Tdpbusd | Insn::Tdpbuud
            );
            let k = if int8 {
                // INT8 は src1 の 4 バイト=内積の 1 ステップ。
                if tile_colsb(st, s1) != 4 * tile_rows(st, s2) {
                    return Err(amx_ud(eip));
                }
                tile_rows(st, s2)
            } else {
                // BF16/FP16/複素 FP16 は 4 バイト=1 要素対。
                if tile_colsb(st, s1) != 4 * tile_rows(st, s2)
                    || !tile_colsb(st, s1).is_multiple_of(4)
                {
                    return Err(amx_ud(eip));
                }
                tile_rows(st, s2)
            };
            let st = &mut env.backend.state;
            for m in 0..md_rows {
                for n in 0..md_cols {
                    let dcell = TMM_OFF + usize::from(dst) * 1024 + m * tile_colsb(st, dst) + 4 * n;
                    match insn {
                        Insn::Tdpbssd | Insn::Tdpbsud | Insn::Tdpbusd | Insn::Tdpbuud => {
                            let a_sgn = matches!(insn, Insn::Tdpbssd | Insn::Tdpbsud);
                            let b_sgn = matches!(insn, Insn::Tdpbssd | Insn::Tdpbusd);
                            let mut acc =
                                i32::from_le_bytes(st[dcell..dcell + 4].try_into().unwrap());
                            for kk in 0..k {
                                for q in 0..4 {
                                    let av = st[tile_cell(st, s1, m) + 4 * kk + q];
                                    let bv = st[tile_cell(st, s2, kk) + 4 * n + q];
                                    let a = if a_sgn {
                                        i32::from(av as i8)
                                    } else {
                                        i32::from(av)
                                    };
                                    let b = if b_sgn {
                                        i32::from(bv as i8)
                                    } else {
                                        i32::from(bv)
                                    };
                                    acc = acc.wrapping_add(a * b);
                                }
                            }
                            st[dcell..dcell + 4].copy_from_slice(&acc.to_le_bytes());
                        }
                        _ => {
                            // BF16/FP16/複素 FP16: dword 対の実・虚で
                            // f32 に拡張して積和する。
                            let mut acc =
                                f32::from_le_bytes(st[dcell..dcell + 4].try_into().unwrap());
                            for kk in 0..k {
                                let aw = u32::from_le_bytes(
                                    st[tile_cell(st, s1, m) + 4 * kk
                                        ..tile_cell(st, s1, m) + 4 * kk + 4]
                                        .try_into()
                                        .unwrap(),
                                );
                                let bw = u32::from_le_bytes(
                                    st[tile_cell(st, s2, kk) + 4 * n
                                        ..tile_cell(st, s2, kk) + 4 * n + 4]
                                        .try_into()
                                        .unwrap(),
                                );
                                let cvt: fn(u16) -> f32 = if insn == Insn::Tdpbf16ps {
                                    |h| f32::from_bits(u32::from(h) << 16)
                                } else {
                                    f16_to_f32
                                };
                                let (a_re, a_im) = (cvt(aw as u16), cvt((aw >> 16) as u16));
                                let (b_re, b_im) = (cvt(bw as u16), cvt((bw >> 16) as u16));
                                match insn {
                                    Insn::Tcmmrlfp16ps => {
                                        acc += a_re * b_re - a_im * b_im;
                                    }
                                    Insn::Tcmmimfp16ps => {
                                        acc += a_re * b_im + a_im * b_re;
                                    }
                                    _ => {
                                        acc += a_re * b_re + a_im * b_im;
                                    }
                                }
                            }
                            st[dcell..dcell + 4].copy_from_slice(&acc.to_le_bytes());
                        }
                    }
                }
            }
            Ok(())
        }
    }
}
/// オペコード表経路の 1 命令。表に無いか `dispatch_map` が未対応なら `None`
/// で呼び出し側が従来経路に下りる。
fn step_x86_map(
    env: &mut BareEnv,
    sys: &mut dyn TrapHandler,
    mode: u8,
    feats: u128,
    hist: &mut std::collections::VecDeque<(u32, String)>,
) -> Option<Result<(), Outcome>> {
    // 実モードでは eip 状態は IP（下位 16 ビット）で、
    // フェッチ番地は CS<<4 + IP。CS 基底を含める。
    let ip = eip_of(env);
    let csb = if mode == 16 {
        u64::from(env.backend.get(sem::sreg_ref(1))) * 16
    } else {
        0
    };
    let pc = if mode == 16 {
        csb + u64::from(ip & 0xFFFF)
    } else {
        u64::from(ip)
    };
    let mut buf = [0u8; 15];
    let mut n = 0usize;
    while n < 15 {
        // 実モードでは IP が 16 ビットで折り返す（命令が IP=FFFF を跨ぐ）。
        // cs*16+ip が 20 ビットを超えるときも addr_mask で折り返す。
        let a = (if mode == 16 {
            csb + u64::from((ip as u16).wrapping_add(n as u16))
        } else {
            pc + n as u64
        }) & env.backend.addr_mask;
        if env
            .backend
            .mem
            .read(VirtAddr(a), &mut buf[n..n + 1], acc_fetch())
            .is_err()
        {
            break;
        }
        n += 1;
    }
    let opd = match mode {
        16 => polyisa_guest_x86::MODE_OPD_O16,
        _ => polyisa_guest_x86::MODE_OPD_O32,
    };
    let adr = match mode {
        64 => polyisa_guest_x86::MODE_ADR_A64,
        16 => polyisa_guest_x86::MODE_ADR_A16,
        _ => polyisa_guest_x86::MODE_ADR_A32,
    };
    let mut modes =
        (opd << polyisa_guest_x86::MODE_OPD_SHIFT) | (adr << polyisa_guest_x86::MODE_ADR_SHIFT);
    if mode == 64 {
        modes |= polyisa_guest_x86::MODE_M64;
    }
    if mode == 16 && feats & polyisa_guest_x86::FEAT_I386 == 0 {
        // 386 より前の実モードでは FS/GS・0x66/0x67 接頭辞はなく、
        // 世代に応じて一部のオペコードは別名として実行される。
        let i186 = feats & polyisa_guest_x86::FEAT_I186 != 0;
        let i286 = feats & polyisa_guest_x86::FEAT_I286 != 0;
        let mut i = 0usize;
        while i < n && matches!(buf[i], 0x26 | 0x2E | 0x36 | 0x3E | 0xF0 | 0xF2 | 0xF3) {
            i += 1;
        }
        if i < n {
            if !i186 {
                // 8086/8088 の別名。60-6F は 70-7F の Jcc 別名、
                // C0/C1/C8/C9 は C2/C3/CA/CB、FF /7 は /6 push の別名。
                match buf[i] {
                    0x60..=0x6F => buf[i] |= 0x10,
                    0xC0 => buf[i] = 0xC2,
                    0xC1 => buf[i] = 0xC3,
                    0xC8 => buf[i] = 0xCA,
                    0xC9 => buf[i] = 0xCB,
                    0xFF if i + 1 < n && (buf[i + 1] >> 3) & 7 == 7 => {
                        buf[i + 1] = (buf[i + 1] & !0x38) | 0x30;
                    }
                    _ => {}
                }
            } else {
                // 80186/80286。0x63 は 286 から ARPL、残る 63-67 は
                // 73-77 の Jcc 別名として実行される。
                match buf[i] {
                    0x63 if !i286 => buf[i] |= 0x10,
                    0x64..=0x67 => buf[i] |= 0x10,
                    _ => {}
                }
            }
        }
    }
    // 実モードの SS 基底。デコード失敗時の #UD 配送でも使うので先に取る。
    let sseg = if mode == 16 {
        u64::from(env.backend.get(sem::sreg_ref(2))) << 4
    } else {
        0
    };
    let eip = if mode == 16 { ip & 0xFFFF } else { ip };
    // 命令長の上限。80286 の実モードは 10 バイト超で #GP、
    // 80386 以降は 15 バイト。
    let insn_len_lim = if mode == 16 {
        match env.backend.param::<polyisa_guest_x86::InsnLenParam>() {
            polyisa_guest_x86::INSN_LEN_L10 => 10u8,
            polyisa_guest_x86::INSN_LEN_L15 => 15,
            _ => u8::MAX,
        }
    } else {
        u8::MAX
    };
    // 80386 以降ではフェッチ位置自体が CS 限界（64KiB）を越えれば #GP。
    // 直前の命令が境界ぴったりに終わったとき IP は折り返さず
    // 0x1_0000 のまま届くので、デコードより先に検査する
    // （積まれる IP は 16 ビットに折られる。SST 80386 実測）。
    if mode == 16 && feats & polyisa_guest_x86::FEAT_I386 != 0 && u64::from(ip) >= 0x1_0000 {
        let r = env.step(|b| polyisa_guest_x86::sem_ea::int_real(b, ip, 0, 13, 16, sseg));
        return Some(x86_post_step(env, sys, ip, 0, 0, r, hist));
    }
    let md = match polyisa_guest_x86::decode_map(&buf[..n], modes, feats) {
        Some(md) => md,
        None => {
            // 80286 以降の実モードでは未定義命令は #UD（IVT 6 へ）。
            if mode == 16 && feats & polyisa_guest_x86::FEAT_I286 != 0 {
                // 命令長の #GP は #UD より先に評価される。無効なグループ
                // 値でもオペランド長は確定するので、8088/186 の別名形を
                // 仮にデコードして長さを見る（SST 80286 実測: C7 /7 で
                // 11 バイトなら #GP）。
                let alt = polyisa_guest_x86::decode_map(
                    &buf[..n],
                    modes,
                    feats & !polyisa_guest_x86::FEAT_I286,
                );
                let vec = match alt {
                    Some(alt) if alt.len > insn_len_lim => 13,
                    _ => 6,
                };
                let r = env.step(|b| polyisa_guest_x86::sem_ea::int_real(b, eip, 0, vec, 16, sseg));
                return Some(x86_post_step(env, sys, eip, 0, 0, r, hist));
            }
            return None;
        }
    };
    if md.len > insn_len_lim {
        let r = env.step(|b| polyisa_guest_x86::sem_ea::int_real(b, eip, 0, 13, 16, sseg));
        return Some(x86_post_step(env, sys, eip, 0, 0, r, hist));
    }
    // 80386 以降の実モードでは命令フェッチが CS 限界（64KiB）を
    // またぐと #GP。80286 以前は IP が 16 ビットで折り返す
    // （SST 80386 実測）。
    if mode == 16
        && feats & polyisa_guest_x86::FEAT_I386 != 0
        && u64::from(ip) + u64::from(md.len) > 0x1_0000
    {
        let r = env.step(|b| polyisa_guest_x86::sem_ea::int_real(b, eip, 0, 13, 16, sseg));
        return Some(x86_post_step(env, sys, eip, 0, 0, r, hist));
    }
    // 80386 以降では LOCK 接頭辞はメモリ宛ての RMW 命令にだけ有効で、
    // それ以外では #UD（SST 80386 実測）。80286 以前は無視される。
    // 形の可否はデコーダが MapDec.lock_ok に写す。ユーザーモードでは
    // CPU 例外配送をまだ持たないので Undefined 退出にする。
    if md.lock && !md.lock_ok {
        if mode == 16 {
            if feats & polyisa_guest_x86::FEAT_I386 != 0 {
                let r = env.step(|b| polyisa_guest_x86::sem_ea::int_real(b, eip, 0, 6, 16, sseg));
                return Some(x86_post_step(env, sys, eip, 0, 0, r, hist));
            }
        } else {
            let r = env.step(|b| polyisa_guest_x86::sem_ea::undefined(b, eip));
            return Some(x86_post_step(env, sys, eip, 0, 0, r, hist));
        }
    }
    let next_rip = pc + u64::from(md.len);
    // メモリアクセスの既定セグメント。実モードはセレクタ<<4 の基底で、
    // 上書き接頭辞は該当セグメントを、なければ BP/SP 系は SS、ほかは DS。
    let (seg, seg_ss, es) = if mode == 16 {
        let s = [
            env.backend.get(sem::sreg_ref(0)),
            env.backend.get(sem::sreg_ref(1)),
            env.backend.get(sem::sreg_ref(2)),
            env.backend.get(sem::sreg_ref(3)),
            env.backend.get(sem::sreg_ref(4)),
            env.backend.get(sem::sreg_ref(5)),
        ];
        let sel = |i: u8| u64::from(s[usize::from(i)]) << 4;
        let es = sel(0);
        // アクセスの既定セグメントが SS か（限界例外の #SS/#GP 選択）。
        let seg_ss = md.seg == 0x36 || (md.seg == 0 && polyisa_guest_x86::decode::ea_uses_ss(&md));
        let def = if polyisa_guest_x86::decode::ea_uses_ss(&md) {
            sseg
        } else {
            sel(3)
        };
        let ov = match md.seg {
            0x26 => es,
            0x2E => sel(1),
            0x36 => sseg,
            0x3E => sel(3),
            0x64 => sel(4),
            0x65 => sel(5),
            _ => 0,
        };
        (if md.seg != 0 { ov } else { def }, seg_ss, es)
    } else {
        let seg = match md.seg {
            0x64 => env.backend.get(sem::fs_base_ref()),
            0x65 => env.backend.get(sem::gs_base_ref()),
            _ => 0,
        };
        (seg, false, 0)
    };
    if let Some(r) = concrete_step(env, |env| {
        x87_transcendental_step(env, &md)
            .or_else(|| xsavec_step(env, &md, next_rip, seg, eip, mode))
            .or_else(|| xrstorc_step(env, &md, next_rip, seg, eip, mode))
            .or_else(|| xstore_step(env, &md))
            .or_else(|| avx10_step(env, &md, next_rip, seg, eip))
            .or_else(|| avxne_step(env, &md, next_rip, seg, eip))
            .or_else(|| vcrypto_step(env, &md, next_rip, seg, eip))
            .or_else(|| amx_tile_step(env, &md, next_rip, seg, eip))
    }) {
        let word = buf[..usize::from(md.len).min(16)]
            .iter()
            .rev()
            .fold(0u128, |w, c| (w << 8) | u128::from(*c));
        return Some(x86_post_step(
            env,
            sys,
            eip,
            u64::from(md.len),
            word,
            r,
            hist,
        ));
    }
    let r = env.step(|b| dispatch_map(b, &md, eip, next_rip, seg, seg_ss, sseg, es, mode, feats));
    let r = match r {
        Err(InterpExit::Exception(ref e))
            if mode == 16 && e.kind == polyisa_sem::ExceptionKind::Trap && e.code <= 0xFF =>
        {
            // 実モードではベクタ例外は IVT 経由で配送する（#SS/#GP/#NM 等。
            // 命令の実行を中断し、フォールトした命令の IP を積む）。
            env.step(|b| polyisa_guest_x86::sem_ea::int_real(b, eip, 0, e.code as u8, 16, sseg))
                .map(|_| true)
        }
        r => r,
    };
    if let Ok(false) = r {
        // 未移行。従来経路へ。
        return None;
    }
    let word = buf[..usize::from(md.len).min(16)]
        .iter()
        .rev()
        .fold(0u128, |w, c| (w << 8) | u128::from(*c));
    let res = x86_post_step(env, sys, eip, u64::from(md.len), word, r.map(|_| ()), hist);
    if mode == 16
        && res.is_ok()
        && matches!(env.backend.ctrl, polyisa_engine::interp::Ctrl::Jump(_))
    {
        // 実モードの近接制御移転は IP を 16 ビットで折り返す
        // （SST 80386 実測。ストレート進行の 0x1_0000 到達だけは
        // 折り返さず残して次フェッチの #GP を発火させる）。
        let v = eip_of(env) & 0xFFFF;
        env.backend.set(polyisa_guest_x86::sem::eip_ref(), v);
    }
    Some(res)
}

fn step_x86(
    env: &mut BareEnv,
    sys: &mut dyn TrapHandler,
    mode: u8,
    feats: u128,
    hist: &mut std::collections::VecDeque<(u32, String)>,
) -> Result<(), Outcome> {
    let is64 = mode == 64;
    let pc = eip_of(env) as u64;
    if std::env::var_os("POLYISA_HIST").is_some() {
        if hist.len() == 32 {
            hist.pop_front();
        }
        hist.push_back((pc as u32, String::new()));
    }
    // オペコード表経路を先に試す。未移行の命令は従来のパターンデコードへ。
    if std::env::var_os("POLYISA_NO_MAP").is_none()
        && let Some(r) = step_x86_map(env, sys, mode, feats, hist)
    {
        return r;
    }
    if mode == 16 {
        // 実モードは map 経路のみ。列挙経路は 32 ビット既定のため誤動作する。
        return Err(Outcome::Unimplemented {
            pc: u64::from(eip_of(env)),
            word: 0,
        });
    }
    step_x86_legacy(env, sys, is64, feats, hist)
}

/// 従来の列挙パターンデコード経路の 1 命令。
fn step_x86_legacy(
    env: &mut BareEnv,
    sys: &mut dyn TrapHandler,
    is64: bool,
    feats: u128,
    hist: &mut std::collections::VecDeque<(u32, String)>,
) -> Result<(), Outcome> {
    let pc = eip_of(env) as u64;
    let d = decode_x86(&env.backend.mem, pc, is64, feats, hist)?;
    let DecodedX86 {
        insn,
        word,
        nbytes,
        off,
        rex,
        has66,
        has_f2,
        rep,
        has_fs,
        has_gs,
    } = d;
    // REX 拡張は reg/rm/SIB 抽出で対応済み (R/R/B/X)。W は rex_w で切替.
    let _ = rex;
    // FS/GS 上書きの有無とベース。dispatch 側でセグメント相対アドレッシングに使う.
    // i386 musl は GS (TLS)、x86-64 は FS を使う。ベースは CPU 状態の
    // セグメントベースレジスタを読む（arch_prctl / set_thread_area が書く）。
    let fs = has_fs.then(|| env.backend.get(sem::fs_base_ref()));
    let seg = fs.or(has_gs.then(|| env.backend.get(sem::gs_base_ref())));
    // imm/disp の取り出し。32ビット値は LE 実バイト列から復元する。
    let imm32 = || (word as u32).swap_bytes();
    let disp8 = || (word & 0xff) as u8 as i8;
    let eip = pc as u32;
    // 意味論が分岐を取ると backend.ctrl に Jump が残る（取らなければ
    // Fallthrough）。eip 等値での判定は自己ループで誤るため使わない。
    let r = env.step(|b| {
        dispatch(
            b, insn, eip, word, nbytes, off, is64, rex, has66, has_f2, rep, seg, imm32, disp8,
        )
    });
    x86_post_step(env, sys, eip, nbytes, word, r, hist)
}

/// `env.step` の結果を `Outcome` に仕立てる後処理。分岐がなければ
/// eip を命令長分進め、Trap は `sys` に委譲する。
fn x86_post_step(
    env: &mut BareEnv,
    sys: &mut dyn TrapHandler,
    eip: u32,
    nbytes: u64,
    word: u128,
    r: Result<(), InterpExit>,
    hist: &mut std::collections::VecDeque<(u32, String)>,
) -> Result<(), Outcome> {
    use polyisa_engine::interp::Ctrl;
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
                        return Err(Outcome::Exit(u64::from(code)));
                    }
                }
                TrapOutcome::Blocked => {
                    if !sys.on_block(env) {
                        return Err(Outcome::Deadlock);
                    }
                }
                TrapOutcome::Unimplemented => {
                    return Err(Outcome::Unimplemented {
                        pc: u64::from(eip),
                        word,
                    });
                }
            }
        }
        // #DE/#UD/#PF 等の CPU 例外は OS パーソナリティへ渡し、
        // Linux では同期シグナルへ変換する。ハンドラがない、または
        // 処理できなければ従来どおり VM 境界で止める。
        Err(InterpExit::Exception(e)) => match sys.handle_exception(env, e) {
            TrapOutcome::Handled => {}
            TrapOutcome::Exit(code) => {
                if !sys.take_exit(env, code) {
                    return Err(Outcome::Exit(u64::from(code)));
                }
            }
            TrapOutcome::Blocked => {
                if !sys.on_block(env) {
                    return Err(Outcome::Deadlock);
                }
            }
            TrapOutcome::Unimplemented => {
                return Err(Outcome::Unimplemented {
                    pc: u64::from(eip),
                    word,
                });
            }
        },
        Err(ex) => {
            if std::env::var_os("POLYISA_HIST").is_some() {
                for (e, i) in hist.iter() {
                    eprintln!("hist {e:#x} {i}");
                }
                eprintln!("hist exit {ex:?}");
                for r in 0..8u8 {
                    let g = polyisa_guest_x86::sem::Gpr(r);
                    eprintln!("  r{r} = {:#x}", env.backend.get(g.state()));
                }
            }
            return Err(Outcome::Unimplemented {
                pc: u64::from(eip),
                word,
            });
        }
    }
    sys.after_step(env);
    Ok(())
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
    seg: Option<u64>,
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
            // 66 付きは16ビット。gzip 0x484ac0 の incw 0x484(%rax,%rsi,4)。
            if has66 {
                if no_index() {
                    sem::inc_r16_mem32(b, sib_base(), disp32())
                } else {
                    sem::inc_r16_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32())
                }
            } else if no_index() {
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
        Insn::DecRmSibd32 => {
            // FF /1 SIB mod=10 [base+index*scale+disp32]。CF は残す。
            if no_index() {
                sem::dec_r32_mem32(b, sib_base(), disp32())
            } else {
                sem::dec_r32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::IncRmMem32 => {
            // FF /0 mod=10 [base+disp32]。uname 0x4b3c4a 対応.
            // 66 付きは16ビット。gzip 0x484a42 の incw 0x13a8(%rdx)。
            if has66 {
                sem::inc_r16_mem32(b, rm(), disp32())
            } else {
                sem::inc_r32_mem32(b, rm(), disp32())
            }
        }
        Insn::DecRmMem32 => {
            // FF /1 mod=10 [base+disp32]。gzip 0x484714 の decl 0x2af4(%rbx)。CF は残す。
            sem::dec_r32_mem32(b, rm(), disp32())
        }
        Insn::IncRmMem8 => {
            // FF /0 mod=01 [base+disp8] (SIBなし)。CF 以外の 5 旗を更新する.
            sem::inc_r32_mem8(b, rm(), disp8())
        }
        Insn::IncRmRip => {
            // FF /0 mod=00 rm=101。64ビットは [RIP+disp32]、32ビットは [disp32]。
            if is64 {
                sem::inc_r32_rip(b, eip as u64 + nbytes, disp32())
            } else {
                let a = seg.map_or(imm32(), |s| (s as u32).wrapping_add(imm32()));
                sem::inc_r32_abs(b, a)
            }
        }
        Insn::DecRmMem8 => {
            // FF /1 mod=01 [base+disp8] (SIBなし)。CF 以外の 5 旗を更新する.
            sem::dec_r32_mem8(b, rm(), disp8())
        }
        Insn::DecRmRip => {
            // FF /1 mod=00 rm=101。64ビットは [RIP+disp32]、32ビットは [disp32]。
            if is64 {
                sem::dec_r32_rip(b, eip as u64 + nbytes, disp32())
            } else {
                let a = seg.map_or(imm32(), |s| (s as u32).wrapping_add(imm32()));
                sem::dec_r32_abs(b, a)
            }
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
        Insn::EnSyscall => sem::syscall(b, eip),
        Insn::EnCpuid => sem::cpuid(b),
        Insn::Endbr64 => sem::nop(b),
        Insn::EnHlt => sem::nop(b),
        // map 経路の rdssp と揃えて dest（固定形なので rax）に 0。
        Insn::Rdsspq => {
            let z = b.konst::<polyisa_sem::W64>(0);
            sem::write64(b, Gpr(0), z);
            sem::nop(b)
        }
        Insn::Rdtscp => polyisa_guest_x86::sem_ea::rdtscp(b),
        // 単スレッドのエミュレーションでは監視と待機は意味を持たない。
        Insn::Monitor | Insn::Mwait => sem::nop(b),
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
        Insn::DecR8 => {
            // FE /1 mod=11。dc 0x40efa1 の dec %dl。CF は残す。
            let rm_f = modrm() & 7;
            let (rd, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::dec_r8(b, rd, high)
        }
        Insn::DecM8Memnd => {
            // FE /1 mod=00 [base]。dc 0x40abca の dec byte [rcx]。CF は残す。
            sem::dec_m8_memnd(b, rm())
        }
        Insn::IncR8 => {
            let rm_f = modrm() & 7;
            let (rd, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::inc_r8(b, rd, high)
        }
        Insn::IncM8Rip => {
            // FE /0 mod=00 rm=101。64ビットは RIP 相対、i386 は絶対番地。
            if is64 {
                sem::inc_m8_rip(b, eip as u64 + nbytes, disp32())
            } else {
                sem::inc_m8_abs(b, disp32() as u32)
            }
        }
        Insn::XchgR8 => {
            // 86 /r mod=11。base64 0x4bd97a の xchg %ch, %cl。
            let reg_f = (modrm() >> 3) & 7;
            let rm_f = modrm() & 7;
            let (reg_r, reg_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let (rm_r, rm_high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::xchg_r8(b, rm_r, rm_high, reg_r, reg_high)
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
        Insn::AddM32R32Sib => {
            // 01 /r SIB mod=00 [base+index*scale]。sort 0x4d2c0d の addq %r15, (%rbx,%r12,8)。
            if no_index() {
                if rex_w {
                    sem::add_m64_r64_memnd(b, sib_base(), reg())
                } else {
                    sem::add_m32_r32_memnd(b, sib_base(), reg())
                }
            } else if rex_w {
                sem::add_m64_r64_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            } else {
                sem::add_m32_r32_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            }
        }
        Insn::AddM32R32Sibd32 => {
            // 01 /r SIB mod=10 [base+index*scale+disp32]。basename 0x48995c 対応.
            // 66 付きは16ビット。gzip 0x484a11 の addw %cx, 0x1364(%rdx,%r8,4)。
            if has66 {
                if no_index() {
                    sem::add_m16_r16_mem32(b, sib_base(), disp32(), reg())
                } else {
                    sem::add_m16_r16_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
                }
            } else if no_index() {
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
            if has66 {
                sem::sub_m16_r16_mem8(b, rm(), disp8(), reg())
            } else if rex_w {
                sem::sub_m64_r64_mem8(b, rm(), disp8(), reg())
            } else {
                sem::sub_m32_r32_mem8(b, rm(), disp8(), reg())
            }
        }
        Insn::AdcM32R32Mem8 => {
            // 11 /r mod=01 [base+disp8]。src は reg フィールド。i386 musl の 64bit 演算で使う。
            sem::adc_m32_r32_mem8(b, rm(), disp8(), reg())
        }
        Insn::AdcM32Imm8Mem8 => {
            // 83 /2 mod=01 [base+disp8],imm8 (4B)。disp は word 下位から2番目、imm は下位。
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            sem::adc_m32_imm8_mem8(b, rm(), d8, imm)
        }
        Insn::AdcM32Imm8Sibd => {
            // 83 /2 SIB mod=01 [base+index*scale+disp8],imm8 (5B)。i386 strings 0x806359d 対応.
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::adc_m32_imm8_mem8(b, base, d8, imm)
            } else {
                sem::adc_m32_imm8_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::AdcAlImm => sem::adc_al_imm(b, (word & 0xff) as u8),
        Insn::SbbM32R32Mem8 => {
            // 19 /r mod=01 [base+disp8]。src は reg フィールド。i386 musl の 64bit 演算で使う。
            sem::sbb_m32_r32_mem8(b, rm(), disp8(), reg())
        }
        Insn::AdcM32R32Sibd => {
            // 11 /r SIB mod=01。no_index は base+disp8 のみ。
            if no_index() {
                sem::adc_m32_r32_mem8(b, sib_base(), disp8(), reg())
            } else {
                sem::adc_m32_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            }
        }
        Insn::AdcM32R32Sibd32 => {
            // 11 /r SIB mod=10 [base+index*scale+disp32]。i386 iostat 0x808b68d 対応.
            if no_index() {
                if rex_w {
                    sem::adc_m64_r64_mem32(b, sib_base(), disp32(), reg())
                } else {
                    sem::adc_m32_r32_mem32(b, sib_base(), disp32(), reg())
                }
            } else if rex_w {
                sem::adc_m64_r64_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::adc_m32_r32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            }
        }
        Insn::AdcM32R32Mem32 => {
            // 11 /r mod=10 [base+disp32]。
            if rex_w {
                sem::adc_m64_r64_mem32(b, rm(), disp32(), reg())
            } else {
                sem::adc_m32_r32_mem32(b, rm(), disp32(), reg())
            }
        }
        Insn::SbbM32R32Sibd => {
            if no_index() {
                sem::sbb_m32_r32_mem8(b, sib_base(), disp8(), reg())
            } else {
                sem::sbb_m32_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            }
        }
        Insn::AdcRSibd => {
            // 13 /r SIB mod=01 [base+index*scale+disp8]。i386 musl の 64bit 演算（free 0x804bfce）。
            if no_index() {
                if rex_w {
                    sem::adc_r64_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::adc_r32_mem8(b, reg(), sib_base(), disp8())
                }
            } else if rex_w {
                sem::adc_r64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::adc_r32_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::AdcRSibabs => {
            // 13 /r SIB mod=00 base=101 [index*scale+disp32]。i386 sha512sum 0x80effe5 対応.
            if no_index() {
                if rex_w {
                    sem::adc_r64_abs(b, reg(), disp32() as u32)
                } else {
                    sem::adc_r32_abs(b, reg(), disp32() as u32)
                }
            } else if rex_w {
                sem::adc_r64_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::adc_r32_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::AndRSib => {
            // 23 /r SIB mod=00 [base+index*scale]。md5sum 0x9fd9e9 の and (%esp),%ebx.
            if no_index() {
                if rex_w {
                    sem::and_r64_memnd(b, reg(), sib_base())
                } else {
                    sem::and_r32_memnd(b, reg(), sib_base())
                }
            } else if rex_w {
                sem::and_r64_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            } else {
                sem::and_r32_sib(b, reg(), sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::SubM32Imm8Sibd32 => {
            // 83 /5 SIB mod=10 (8B)。disp32 は word 下位9–40ビット、imm8 は下位。
            let d32 = (((word >> 8) & 0xffff_ffff) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if no_index() {
                sem::sub_rm32_imm8_mem32(b, sib_base(), d32, imm)
            } else {
                sem::sub_m32_imm8_sibd32(b, sib_base(), sib_idx(), sib_shift(), d32, imm)
            }
        }
        Insn::SubM32R32Mem32 => {
            // 29 /r mod=10 [base+disp32]。gzip 0x48473b の subl %eax, 0x2af8(%rbx)。
            if rex_w {
                sem::sub_m64_r64_mem32(b, rm(), disp32(), reg())
            } else {
                sem::sub_m32_r32_mem32(b, rm(), disp32(), reg())
            }
        }
        Insn::SubM32R32Sibd32 => {
            // 29 /r SIB mod=10 [base+index*scale+disp32]。i386 deluser 0x804fce9 対応.
            if no_index() {
                if rex_w {
                    sem::sub_m64_r64_mem32(b, sib_base(), disp32(), reg())
                } else {
                    sem::sub_m32_r32_mem32(b, sib_base(), disp32(), reg())
                }
            } else if rex_w {
                sem::sub_m64_r64_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::sub_m32_r32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32(), reg())
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
            if has66 {
                // 66 8B mod=01。pgrep 0x44b629 の movw 0x12(%r14), %dx。上位は残す。
                sem::mov_r16_m16_mem8(b, reg(), rm(), disp8())
            } else if rex_w {
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
            if has66 {
                // 66 8B mod=00。gzip 0x4847b6 の movw (%rsi), %ax。上位は残す。
                sem::mov_r16_m16_memnd(b, reg(), rm())
            } else if let Some(base) = seg {
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
            if let Some(base) = seg {
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
            if has66 {
                // 66 8B mod=10: 16ビットロード。上位は残す。
                sem::mov_r16_m16_mem32(b, reg(), rm(), disp32())
            } else if rex_w {
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
            if let Some(s) = seg {
                // セグメント上書き時は RIP 相対ではなく seg:[disp32]。i386 musl の mov gs:0,eax.
                if rex_w {
                    sem::mov_r64_fs_abs(b, reg(), s, disp32())
                } else {
                    sem::mov_r32_fs_abs(b, reg(), s, disp32())
                }
            } else if has66 {
                // 66 8B: 16ビットロード。64ビットは RIP 相対、i386 は絶対番地。
                if is64 {
                    sem::mov_r16_rip(b, reg(), eip as u64 + nbytes, disp32())
                } else {
                    sem::mov_r16_m16_abs(b, reg(), disp32() as u32)
                }
            } else if rex_w {
                sem::mov_r64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::mov_eax_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::mov_eax_abs(b, reg(), imm32())
            }
        }
        Insn::MovAbsEax => {
            if let Some(s) = seg {
                if rex_w {
                    sem::mov_m64_fs_abs(b, reg(), s, disp32())
                } else {
                    sem::mov_m32_fs_abs(b, reg(), s, disp32())
                }
            } else if has66 {
                // 66 89: 16ビットストア。64ビットは RIP 相対、i386 は絶対番地。
                if is64 {
                    sem::mov_rip_r16(b, reg(), eip as u64 + nbytes, disp32())
                } else {
                    sem::mov_m16_r16_abs(b, reg(), disp32() as u32)
                }
            } else if rex_w {
                sem::mov_m64_rip(b, reg(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::mov_rip_eax(b, reg(), eip as u64 + nbytes, disp32())
            } else {
                sem::mov_abs_eax(b, reg(), imm32())
            }
        }
        Insn::MovEaxMoffs => {
            // A1: mov eax,[moffs32]。i386 musl。GS/FS 上書きはベース加算。
            if let Some(s) = seg {
                sem::mov_r32_fs_abs(b, Gpr(0), s, imm32() as i32)
            } else {
                sem::mov_eax_abs(b, Gpr(0), imm32())
            }
        }
        Insn::MovMoffsEax => {
            // A3: mov [moffs32],eax。i386 musl。GS/FS 上書きはベース加算。
            if let Some(s) = seg {
                sem::mov_m32_fs_abs(b, Gpr(0), s, imm32() as i32)
            } else {
                sem::mov_abs_eax(b, Gpr(0), imm32())
            }
        }
        Insn::MovAlMoffs => {
            // A0: mov al,[moffs32]。i386 musl。GS/FS 上書きはベース加算。
            let a = seg.map_or(imm32(), |s| (s as u32).wrapping_add(imm32()));
            sem::mov_r8_m8_abs(b, Gpr(0), false, a)
        }
        Insn::MovMoffsAl => {
            // A2: mov [moffs32],al。i386 musl。GS/FS 上書きはベース加算。
            let a = seg.map_or(imm32(), |s| (s as u32).wrapping_add(imm32()));
            sem::mov_m8_r8_abs(b, Gpr(0), a, false)
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
            if has66 {
                // 66 8B: 16ビット SIB+disp8 ロード。i386 musl の mov bp,[esp+disp]。
                if no_index() {
                    sem::mov_r16_m16_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::mov_r16_m16_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
                }
            } else if no_index() {
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
            if has66 {
                if no_index() {
                    sem::mov_r16_m16_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::mov_r16_m16_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
                }
            } else if no_index() {
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
            if has66 {
                // 66 89: 16ビット SIB+disp32 ストア。gzip 0x4859e4 の movw %cx, 0x12ec(%rbx,%rdx,4)。
                if no_index() {
                    sem::mov_m16_r16_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::mov_m16_r16_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
                }
            } else if no_index() {
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
                match seg {
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
                match seg {
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
                match seg {
                    Some(base) => sem::mov_m8_r8_fs_abs(b, src, base, disp32(), high),
                    None => sem::mov_m8_r8_abs(b, src, disp32() as u32, high),
                }
            } else if let Some(base) = seg {
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
                // 32ビット絶対番地 (8A 0d + disp32)。i386 nologin 0x8096afb 対応。
                sem::mov_r8_m8_abs(b, dst, high, imm32())
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
        Insn::SubM8R8Sib => {
            // 28 /r SIB mod=00。dc 0x40abb4 の sub [rdi+rax], cl。
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::sub_m8_r8_memnd(b, sib_base(), src, high)
            } else {
                sem::sub_m8_r8_sib(b, sib_base(), sib_idx(), sib_shift(), src, high)
            }
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
        Insn::XorM8R8Sib => {
            // 30 /r SIB mod=00。sha3sum 0x4b4edd の xorb %r9b, (%rdi,%rdx,1)。
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            if no_index() {
                sem::xor_m8_r8_memnd(b, sib_base(), src, high)
            } else {
                sem::xor_m8_r8_sib(b, sib_base(), sib_idx(), sib_shift(), src, high)
            }
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
        Insn::AndM8R8Mem8 => {
            // 20 /r mod=01 [base+disp8], r8。nologin 0x45a07d の and %al,-0x1(%rdi)。
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::and_m8_r8_mem8(b, rm(), disp8(), src, high)
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
        Insn::FsubpSt => {
            // DE E8+i。seq 0x4d0c51 の DE E9 は FSUBP ST(1), ST(0)。
            sem::fsubp_st(b, (word & 7) as u8)
        }
        Insn::FildM64Sib => {
            // DF /5 SIB mod=00 [base+index*scale]。seq 0x4018c4 の fildq (%rsp)。
            if no_index() {
                sem::fild_m64_memnd(b, sib_base())
            } else {
                sem::fild_m64_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::FildM64Sibd => {
            // DF /5 SIB mod=01。seq 0x4d0c4d の fildq 0x30(%rsp)。
            if no_index() {
                sem::fild_m64_mem8(b, sib_base(), disp8())
            } else {
                sem::fild_m64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::FistpM64Sibd => {
            // DF /7 SIB mod=01。seq 0x4d0c31 の fistpq 0x30(%rsp)。
            if no_index() {
                sem::fistp_m64_mem8(b, sib_base(), disp8())
            } else {
                sem::fistp_m64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
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
        Insn::FldM64Sib => {
            // DD /0 SIB mod=00。awk length 0x401b17 の fld QWORD PTR [rsp]。
            if no_index() {
                sem::fld_m64_memnd(b, sib_base())
            } else {
                sem::fld_m64_sib(b, sib_base(), sib_idx(), sib_shift())
            }
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
        Insn::OrM8R8Mem8 => {
            // 08 /r mod=01 [base+disp8], r8。powertop 0x44c15c の orb %al, 0x18(%rbx)。
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::or_m8_r8_mem8(b, rm(), disp8(), src, high)
        }
        Insn::OrM8R8Mem32 => {
            // 08 /r mod=10 [base+disp32], r8。udhcpc 0x44426d 対応.
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::or_m8_r8_mem32(b, rm(), disp32(), src, high)
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
        Insn::OrM8R8Rip => {
            // 08 /r mod=00 rm=101。hdparm 0x417721 の or byte [rip+disp32], al。
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
                sem::or_m8_r8_rip(b, eip as u64 + nbytes, disp, src, high)
            } else {
                sem::or_m8_r8_abs(b, (word as u32).swap_bytes(), src, high)
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
        Insn::TestM8R8Sibd => {
            // 84 /r SIB mod=01 [base+index*scale+disp8], r8。taskset 0x47c686。
            // SIB は (word>>8) 下位8、disp8 は最下位8。
            let reg_f = (modrm() >> 3) & 7;
            let (src, high) = if rex != 0 {
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
                sem::test_m8_r8_mem8(b, base, d8, src, high)
            } else {
                sem::test_m8_r8_sibd(b, base, idx, shift, d8, src, high)
            }
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
        Insn::FucomipSt => {
            // DF E8+i。dd 0x4d0ea6 の DF E9 は FUCOMIP ST(0), ST(1)。
            sem::fucomip_st(b, (word & 7) as u8)
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
        Insn::FldM80Rip => {
            // DB /5 mod=00 rm=5。dd 0x4d0e58 の fldt [rip+disp]。
            let disp = (word as u32).swap_bytes() as i32;
            if is64 {
                sem::fld_m80_rip(b, eip as u64 + nbytes, disp)
            } else {
                sem::fld_m80_abs(b, (word as u32).swap_bytes())
            }
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
        Insn::PushRmMemnd => {
            // FF /6 mod=00 [base]。i386 musl _start の pushl (%eax)。
            if is64 {
                sem::push_m64_mem8(b, rm(), 0)
            } else {
                sem::push_m32_mem8(b, rm(), 0)
            }
        }
        Insn::PushRmSib => {
            // FF /6 SIB mod=00 [base+index*scale]。
            if no_index() {
                if is64 {
                    sem::push_m64_mem8(b, sib_base(), 0)
                } else {
                    sem::push_m32_mem8(b, sib_base(), 0)
                }
            } else if is64 {
                sem::push_m64_sibd(b, sib_base(), sib_idx(), sib_shift(), 0)
            } else {
                sem::push_m32_sibd(b, sib_base(), sib_idx(), sib_shift(), 0)
            }
        }
        Insn::PushRmMem8 => {
            // FF /6 mod=01 [base+disp8]。vi 0x4ce196 の pushq 0x40(%rbx)。番地は減算前。
            if is64 {
                sem::push_m64_mem8(b, rm(), disp8())
            } else {
                sem::push_m32_mem8(b, rm(), disp8())
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
        Insn::PushRmAbs => {
            // FF /6 mod=00 rm=101。32ビットは [disp32]、64ビットは [RIP+disp32]。
            if is64 {
                sem::push_m64_rip(b, eip as u64 + nbytes, disp32())
            } else {
                let a = seg.map_or(imm32(), |s| (s as u32).wrapping_add(imm32()));
                sem::push_m32_abs(b, a)
            }
        }
        Insn::PushRmMem32 => {
            // FF /6 mod=10 非SIB。i386 musl の push [ebp-disp]。
            if is64 {
                sem::push_m64_mem32(b, rm(), disp32())
            } else {
                sem::push_m32_mem32(b, rm(), disp32())
            }
        }
        Insn::PushRmSibd32 => {
            // FF /6 SIB mod=10。top 0x44e0d6 の push qword [rsp+0x110]。番地は減算前。
            if no_index() {
                if is64 {
                    sem::push_m64_mem32(b, sib_base(), disp32())
                } else {
                    sem::push_m32_mem32(b, sib_base(), disp32())
                }
            } else if is64 {
                sem::push_m64_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::push_m32_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::PushRmSibabs => {
            // FF /6 SIB mod=00 base=直接番地 [index*scale+disp32] (7B)。i386 ifconfig 対応.
            if no_index() {
                if is64 {
                    // 64bit の SIB 直接番地は disp32 を符号拡張した絶対番地.
                    sem::push_m64_rip(b, 0, disp32())
                } else {
                    sem::push_m32_abs(b, imm32())
                }
            } else if is64 {
                sem::push_m64_sibabs(b, sib_idx(), sib_shift(), disp32())
            } else {
                sem::push_m32_sibabs(b, sib_idx(), sib_shift(), disp32())
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
        Insn::PopM64Mem8 => {
            // 8F /0 mod=01。vi 0x4ce187 の popq 0x40(%rdi)。
            if is64 {
                sem::pop_m64_mem8(b, rm(), disp8())
            } else {
                sem::pop_m32_mem8(b, rm(), disp8())
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
                // 32ビットでは絶対番地。GS 上書きは musl の vsyscall (gs:0x10)。
                let a = seg.map_or(imm32(), |s| (s as u32).wrapping_add(imm32()));
                sem::call_r32_abs(b, eip.wrapping_add(nbytes as u32), a)
            }
        }
        Insn::JmpRRm => {
            if is64 {
                sem::jmp_r64_rm(b, rm())
            } else {
                sem::jmp_r32_rm(b, rm())
            }
        }
        Insn::MovSregR => {
            // MOV Sreg,r16 (8E /r mod=11)。GS/FS ロードはフラットモデルで no-op。
            Ok(())
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
                let a = seg.map_or(imm32(), |s| (s as u32).wrapping_add(imm32()));
                sem::jmp_r32_abs(b, a)
            }
        }
        Insn::EnRet => {
            if is64 {
                sem::ret64(b)
            } else {
                sem::ret(b)
            }
        }
        Insn::RetImm => {
            // C2 iw (3B)。imm16 は最下位16 LE。POP 後に SP を imm 分だけ上げる.
            let n = ((word & 0xffff) as u16).swap_bytes();
            if is64 {
                sem::ret64_imm(b, n)
            } else {
                sem::ret_imm(b, n)
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
        Insn::TestRMem32 => {
            // 85 /r mod=10 [base+disp32]。hush 0x45e8d9 対応.
            let d32 = disp32();
            if rex_w {
                sem::test_r64_m64_mem32(b, reg(), rm(), d32)
            } else {
                sem::test_r32_m32_mem32(b, reg(), rm(), d32)
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
        Insn::TestRSibabs => {
            // 85 /r SIB mod=00 base=5。[index*scale+disp32]。lsattr 0x49f5e5 対応.
            if no_index() {
                if rex_w {
                    sem::test_r64_abs(b, disp32(), reg())
                } else {
                    sem::test_r32_abs(b, disp32(), reg())
                }
            } else if rex_w {
                sem::test_r64_m64_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::test_r32_m32_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
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
        Insn::TestRm16Imm => {
            // 66 F7 /0 mod=11。gunzip 0x48b06a の test r14w, imm16。imm は最下位16 LE。
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::test_rm16_imm(b, rm(), imm)
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
        Insn::TestRm32ImmSib => {
            // F7 /0 SIB mod=00 + imm32 (7B)。i386 ls 0x80d11e0 対応.
            // SIB は (word>>32) 下位8、imm は最下位32 LE.
            let sib_v = ((word >> 32) & 0xff) as u8;
            let imm = (word as u32).swap_bytes();
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::test_rm64_imm_memnd(b, base, imm)
                } else {
                    sem::test_rm32_imm_memnd(b, base, imm)
                }
            } else if rex_w {
                sem::test_rm64_imm_sib(b, base, idx, shift, imm)
            } else {
                sem::test_rm32_imm_sib(b, base, idx, shift, imm)
            }
        }
        Insn::TestRm32ImmSibd => {
            // F7 /0 SIB mod=01 + disp8 + imm32 (8B)。i386 musl 0x80fe3a9 対応.
            // SIB は (word>>40) 下位8、disp は (word>>32) 下位8、imm は最下位32 LE.
            let sib_v = ((word >> 40) & 0xff) as u8;
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            let imm = (word as u32).swap_bytes();
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::test_rm64_imm_mem8(b, base, d8, imm)
                } else {
                    sem::test_rm32_imm_mem8(b, base, d8, imm)
                }
            } else if rex_w {
                sem::test_rm64_imm_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::test_rm32_imm_sibd(b, base, idx, shift, d8, imm)
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
        Insn::XorRm8Imm => {
            // 80 /6 reg-direct。REXありは低8ビット、なしの4-7は上位8ビット.
            let rm_f = modrm() & 7;
            let (dst, high) = if rex != 0 {
                (Gpr(rm_f | ((rex & 1) << 3)), false)
            } else if rm_f < 4 {
                (Gpr(rm_f), false)
            } else {
                (Gpr(rm_f - 4), true)
            };
            sem::xor_rm8_imm(b, dst, (word & 0xff) as u8, high)
        }
        Insn::XorRm8ImmSibd => {
            // 80 74 SIB disp8 imm8 (40b)。iostat 0x448a1f の xorb $1, 0x1b(%rsp)。
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::xor_rm8_imm_mem8(b, base, d8, imm)
            } else {
                sem::xor_rm8_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::AddRm8ImmSib => {
            // 80 /0 SIB mod=00。sha3sum 0x4b4f20 の addb $-128, (%rdi,%rax,1)。
            let imm = (word & 0xff) as u8;
            if no_index() {
                sem::add_rm8_imm_memnd(b, sib_base(), imm)
            } else {
                sem::add_rm8_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm)
            }
        }
        Insn::AddRm8ImmSibd => {
            // 80 /0 SIB mod=01 + disp8 + imm8 (5B)。i386 sha3sum 0x80f0868 対応.
            // SIB は (word>>16) 下位8、disp は (word>>8) 下位8、imm は最下位8.
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::add_rm8_imm_mem8(b, base, d8, imm)
            } else {
                sem::add_rm8_imm_sibd(b, base, idx, shift, d8, imm)
            }
        }
        Insn::XorRm8ImmMemnd => {
            // 80 /6 mod=00 [base],imm8 (24b)。nmeter 0x44a570 の xorb $1, (%rax)。
            let imm = (word & 0xff) as u8;
            sem::xor_rm8_imm_memnd(b, rm(), imm)
        }
        Insn::XorRm8ImmMem32 => {
            // 80 /6 mod=10 [base+disp32],imm8 (7B)。i386 iostat 0x808b743 対応.
            // disp32 は word 下位9–40ビット LE、imm8 は最下位8.
            let d32 = (((word >> 8) & 0xffff_ffff) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            sem::xor_rm8_imm_mem32(b, rm(), d32, imm)
        }
        Insn::XorRm8ImmSib => {
            // 80 /6 SIB mod=00。sha3sum 0x4b4f14 の xorb $6, (%rdi,%rax,1)。
            let imm = (word & 0xff) as u8;
            if no_index() {
                sem::xor_rm8_imm_memnd(b, sib_base(), imm)
            } else {
                sem::xor_rm8_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm)
            }
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
        Insn::OrR8M8Mem8 => {
            // 0A /r mod=01。uudecode 0x49da3e の or sil, BYTE PTR [rcx-1]。
            let reg_f = (modrm() >> 3) & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::or_r8_m8_mem8(b, dst, dst_high, rm(), disp8())
        }
        Insn::OrR8M8Mem32 => {
            // 0A /r mod=10 [base+disp32]。i386 showkey 0x810d301 対応.
            let reg_f = (modrm() >> 3) & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            sem::or_r8_m8_mem32(b, dst, dst_high, rm(), disp32())
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
        Insn::OrR8M8Sibd32 => {
            // 0A /r SIB mod=10。tar -tf 0x48e5f4 の or al, [rsp+disp32]。
            let reg_f = (modrm() >> 3) & 7;
            let (dst, dst_high) = if rex != 0 {
                (Gpr(reg_f | ((rex >> 2) & 1) << 3), false)
            } else if reg_f < 4 {
                (Gpr(reg_f), false)
            } else {
                (Gpr(reg_f - 4), true)
            };
            let sib_v = ((word >> 32) & 0xff) as u8;
            let disp = (word as u32).swap_bytes() as i32;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::or_r8_m8_mem32(b, dst, dst_high, base, disp)
            } else {
                sem::or_r8_m8_sibd32(b, dst, dst_high, base, idx, shift, disp)
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
            if is64 {
                sem::or_r8_m8_rip(b, dst, dst_high, eip as u64 + nbytes, disp32())
            } else {
                // 32ビット絶対番地 (0A 05 + disp32)。i386 find 0x80ea86e 対応。
                sem::or_r8_m8_abs(b, dst, dst_high, imm32())
            }
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
        Insn::AndRm8ImmSibd32 => {
            // 80 /4 SIB mod=10 [base+index*scale+disp32],imm8 (64b)。nologin 0x454247 対応.
            let sib_v = ((word >> 40) & 0xff) as u8;
            let disp = (((word >> 8) as u32).swap_bytes()) as i32;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::and_rm8_imm_mem32(b, base, disp, imm)
            } else {
                sem::and_rm8_imm_sibd32(b, base, idx, shift, disp, imm)
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
        Insn::TestM8ImmSibd32 => {
            // F6 /0 SIB mod=10。ping 0x4c4288 の test BYTE PTR [rsp+disp32], imm8。
            let disp = ((word >> 8) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8;
            if no_index() {
                sem::test_m8_imm_mem32(b, sib_base(), disp, imm)
            } else {
                sem::test_m8_imm_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            }
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
        Insn::TestAxImm16 => {
            // 66 A9 + imm16 (24b、66 接頭辞は剥がし済み)。imm は最下位16 LE。
            sem::test_ax_imm16(b, ((word & 0xffff) as u16).swap_bytes())
        }
        Insn::Je => sem::je(b, eip, disp8()),
        Insn::Jne => sem::jne(b, eip, disp8()),
        Insn::Jcxz => {
            // E3 cb。i386 は ECX、64bit は RCX を検査する。vi 0x8109740 対応。
            if is64 {
                sem::jcxz64(b, eip, disp8())
            } else {
                sem::jcxz32(b, eip, disp8())
            }
        }
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
        Insn::EnLeave => {
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
        Insn::AndRm16ImmMemnd => {
            // 66 81 /4 mod=00 [base],imm16。mim 0x458c3a の andw $0xfb00,(%rbx)。
            sem::and_rm16_imm_memnd(b, rm(), ((word & 0xffff) as u16).swap_bytes())
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
        Insn::ShlM32Imm8Mem8 => {
            // C1 /4 mod=01 [base+disp8],imm8。bzip2 0x480237 の shll $8, 0x70(%rdi)。
            let rm_f = ((word >> 16) & 7) as u8;
            let base = Gpr(rm_f | ((rex & 1) << 3));
            let disp = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8;
            if rex_w {
                sem::shl_m64_imm8_mem8(b, base, disp, imm)
            } else {
                sem::shl_m32_imm8_mem8(b, base, disp, imm)
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
        Insn::ShlM81Mem32 => {
            // D0 /4 mod=10 [base+disp32]。gzip 0x484b2e の shlb 0x2af1(%rax)。
            let rm_f = ((word >> 32) & 7) as u8;
            let base = Gpr(rm_f | ((rex & 1) << 3));
            sem::shl_m8_1_mem32(b, base, disp32())
        }
        Insn::RolRm321 => {
            if rex_w {
                sem::rol_rm64_imm8(b, rm(), 1)
            } else {
                sem::rol_rm32_imm8(b, rm(), 1)
            }
        }
        Insn::RorRm321 => {
            // D1 /1。sha512sum 0x4b47c4 の rorq %rcx。
            if rex_w {
                sem::ror_rm64_imm8(b, rm(), 1)
            } else {
                sem::ror_rm32_imm8(b, rm(), 1)
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
            if has66 {
                sem::rol_rm16_imm8(b, rm(), word as u8)
            } else if rex_w {
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
        Insn::RolRm32Cl => {
            // D3 /0 mod=11。sha3sum 0x4b45f6 の rolq %cl, %r12。
            if rex_w {
                sem::rol_rm64_cl(b, rm())
            } else {
                sem::rol_rm32_cl(b, rm())
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
        Insn::XorRmImm8Sibd => {
            // 83 /6 SIB mod=01。sort 0x4d3045 の xorq $0x7, 0x10(%rsp)。
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::xor_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::xor_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if rex_w {
                sem::xor_rm64_imm8_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::xor_rm32_imm8_sibd(b, base, idx, shift, d8, imm)
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
        Insn::SbbRmImm8Sibd => {
            // 83 /3 SIB mod=01。fsck 0x4d272f の sbbl $-1, 0x14(%rsp)。
            let sib_v = ((word >> 16) & 0xff) as u8;
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                if rex_w {
                    sem::sbb_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::sbb_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if rex_w {
                sem::sbb_rm64_imm8_sibd(b, base, idx, shift, d8, imm)
            } else {
                sem::sbb_rm32_imm8_sibd(b, base, idx, shift, d8, imm)
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
            if has66 {
                // 66 83 /7。gzip 0x485212 の cmpw $0, 0x1366(%r12,%rcx,4)。
                if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                    sem::cmp_m16_imm8_mem32(b, base, disp, imm)
                } else {
                    sem::cmp_m16_imm8_sibd32(b, base, idx, shift, disp, imm)
                }
            } else if idx_raw == 4 && (rex >> 1) & 1 == 0 {
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
                if has66 && !rex_w {
                    sem::cmp_m16_imm8_mem8(b, base, d8, imm)
                } else if rex_w {
                    sem::cmp_rm64_imm8_mem8(b, base, d8, imm)
                } else {
                    sem::cmp_rm32_imm8_mem8(b, base, d8, imm)
                }
            } else if has66 && !rex_w {
                sem::cmp_m16_imm8_sibd(b, base, idx, shift, d8, imm)
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
            if has66 {
                sem::cmp_rm16_imm8(b, rm(), disp8())
            } else if rex_w {
                sem::cmp_rm64_imm8(b, rm(), disp8())
            } else {
                sem::cmp_rm32_imm8(b, rm(), disp8())
            }
        }
        Insn::CmpRmImm8m8 => {
            // mod=01 m8 形：disp8 は下から2バイト目、imm8 は最下位。
            let d8 = ((word >> 8) & 0xff) as u8 as i8;
            let i8 = (word & 0xff) as u8 as i8;
            if has66 {
                // 66 83 /7。ping 0x42e7b3 の cmpw $0xa, 0x4(%rbx)。
                sem::cmp_m16_imm8_mem8(b, rm(), d8, i8)
            } else if rex_w {
                sem::cmp_rm64_imm8m8(b, rm(), d8, i8)
            } else {
                sem::cmp_rm32_imm8m8(b, rm(), d8, i8)
            }
        }
        Insn::CmpRmImm8Memnd => {
            // mod=00 m8 形：imm8 は最下位.
            let i8 = (word & 0xff) as u8 as i8;
            if has66 {
                // 66 83 /7。ping 0x4be1f1 の cmpw $2, (%rdi)。
                sem::cmp_m16_imm8_memnd(b, rm(), i8)
            } else {
                sem::cmp_rm32_imm8_memnd(b, rm(), i8)
            }
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
            if has66 {
                // 66 83 /7。gzip 0x4846ab の cmpw $0, (%rdi,%rax,4)。
                if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                    sem::cmp_m16_imm8_memnd(b, base, imm)
                } else {
                    sem::cmp_m16_imm8_sib(b, base, idx, shift, imm)
                }
            } else if idx_raw == 4 && (rex >> 1) & 1 == 0 {
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
        Insn::AddRm32ImmSib => {
            // 81 /0 SIB mod=00 [base+index*scale],imm32。i386 musl の _start 対応。
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                if rex_w {
                    sem::add_rm64_imm_disp8(b, sib_base(), 0, imm)
                } else {
                    sem::add_rm32_imm_disp8(b, sib_base(), 0, imm)
                }
            } else if rex_w {
                sem::add_rm64_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), 0, imm)
            } else {
                sem::add_rm32_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), 0, imm)
            }
        }
        Insn::AddRm32ImmSibd => {
            // 81 /0 SIB mod=01 [base+disp8],imm32。bzip2 0x480dcd の addq $0x102, 0x28(%rsp)。
            let disp = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                if rex_w {
                    sem::add_rm64_imm_disp8(b, sib_base(), disp, imm)
                } else {
                    sem::add_rm32_imm_disp8(b, sib_base(), disp, imm)
                }
            } else if rex_w {
                sem::add_rm64_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            } else {
                sem::add_rm32_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            }
        }
        Insn::AddRm32ImmMem8 => {
            // 81 /0 mod=01 [base+disp8],imm32。tar -tf 0x48e5e8 の addq $0x200, 0x50(%rbx)。
            let d8 = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if rex_w {
                sem::add_rm64_imm_disp8(b, rm(), d8, imm)
            } else {
                sem::add_rm32_imm_disp8(b, rm(), d8, imm)
            }
        }
        Insn::AddRm64Imm => sem::add_rm64_imm(b, rm(), imm32()),
        Insn::OrRm32ImmSibd => {
            // 81 /1 SIB mod=01。resize 0x490ea6 の orl $0x880, 0x1c(%rsp)。
            let disp = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                if rex_w {
                    sem::or_rm64_imm_mem8(b, sib_base(), disp, imm)
                } else {
                    sem::or_rm32_imm_mem8(b, sib_base(), disp, imm)
                }
            } else if rex_w {
                sem::or_rm64_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            } else {
                sem::or_rm32_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            }
        }
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
        Insn::AndRm32ImmSibd => {
            // 81 /4 SIB mod=01。script 0x47b0b7 の andl $0xfffffe00, 0x14(%rsp)。
            let disp = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                if rex_w {
                    sem::and_rm64_imm_mem8(b, sib_base(), disp, imm)
                } else {
                    sem::and_rm32_imm_mem8(b, sib_base(), disp, imm)
                }
            } else if rex_w {
                sem::and_rm64_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            } else {
                sem::and_rm32_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            }
        }
        Insn::AndRm32ImmMem32 => {
            // 81 /4 mod=10 [base+disp32],imm32 (10B)。i386 script 0x80baad6 対応.
            // disp は (word>>32) 下位32 LE、imm は最下位32 LE.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            let imm = (word as u32).swap_bytes();
            if rex_w {
                sem::and_rm64_imm_mem32(b, rm(), disp, imm)
            } else {
                sem::and_rm32_imm_mem32(b, rm(), disp, imm)
            }
        }
        Insn::AddRm32ImmMem32 => {
            // 81 /0 mod=10 [base+disp32],imm32 (10B)。i386 script 0x80baae0 対応.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            let imm = (word as u32).swap_bytes();
            if rex_w {
                sem::add_rm64_imm_mem32(b, rm(), disp, imm)
            } else {
                sem::add_rm32_imm_mem32(b, rm(), disp, imm)
            }
        }
        Insn::XorRm32ImmSibd => {
            // 81 /6 SIB mod=01。mim 0x45a165 の xorl $0x100,0x4(%rsp)。
            let disp = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                if rex_w {
                    sem::xor_rm64_imm_mem8(b, sib_base(), disp, imm)
                } else {
                    sem::xor_rm32_imm_mem8(b, sib_base(), disp, imm)
                }
            } else if rex_w {
                sem::xor_rm64_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            } else {
                sem::xor_rm32_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
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
        Insn::AndRm32ImmMemnd => {
            // 81 /4 mod=00 [base],imm32。vi 0x40511c の andl $0xfffffaff, (%rbx)。
            if rex_w {
                sem::and_rm64_imm_memnd(b, rm(), imm32())
            } else {
                sem::and_rm32_imm_memnd(b, rm(), imm32())
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
        Insn::CmpRm32ImmRip => {
            // 81 3D + disp32 + imm32 (80b)。udhcpd 0x445747 対応.
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            if is64 {
                sem::cmp_rm32_imm_rip(b, eip as u64 + nbytes, disp, imm32())
            } else {
                sem::cmp_rm32_imm_abs(b, ((word >> 32) as u32).swap_bytes(), imm32())
            }
        }
        Insn::CmpRm16ImmMem8 => {
            // 66 81 /7 mod=01 [base+disp8],imm16。blkid 0x47d6bf 対応.
            let d8 = ((word >> 16) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::cmp_rm16_imm_mem8(b, rm(), d8, imm)
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
        Insn::CmpRm32ImmSib => {
            // 81 /7 SIB mod=00。awk 0x4a205a の cmpl $0x25072000, DWORD PTR [r12]。
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                if rex_w {
                    sem::cmp_rm64_imm_memnd(b, sib_base(), imm)
                } else {
                    sem::cmp_rm32_imm_memnd(b, sib_base(), imm)
                }
            } else if rex_w {
                sem::cmp_rm64_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm)
            } else {
                sem::cmp_rm32_imm_sib(b, sib_base(), sib_idx(), sib_shift(), imm)
            }
        }
        Insn::CmpRm32ImmSibd => {
            // 81 /7 SIB mod=01。nc 0x4c68d6 の cmpl $0xff, 0xc(%rsp)。
            let disp = ((word >> 32) & 0xff) as u8 as i8;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                sem::cmp_rm32_imm_mem8(b, sib_base(), disp, imm)
            } else {
                sem::cmp_rm32_imm_sibd(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
            }
        }
        Insn::CmpRm32ImmSibd32 => {
            // 81 /7 SIB mod=10 [base+index*scale+disp32],imm32 (11B)。i386 musl 対応。
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if no_index() {
                sem::cmp_rm32_imm_mem32(b, sib_base(), disp, imm)
            } else {
                sem::cmp_rm32_imm_sibd32(b, sib_base(), sib_idx(), sib_shift(), disp, imm)
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
            if has66 {
                // 66 03 /r mod=00。gzip 0x4847b9 の addw (%rcx), %ax。
                sem::add_r16_memnd(b, reg(), rm())
            } else if rex_w {
                sem::add_r64_memnd(b, reg(), rm())
            } else {
                sem::add_r32_memnd(b, reg(), rm())
            }
        }
        Insn::AddRMem8 => {
            if has66 {
                // 66 03 /r mod=01 (3B)。i386 gzip 0x80c381f 対応.
                sem::add_r16_mem8(b, reg(), rm(), disp8())
            } else if rex_w {
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
        Insn::AndRSibd => {
            // 23 /r SIB mod=01。seq 0x4d0d34 の andl 0x3c(%rsp), %edi。
            if no_index() {
                if rex_w {
                    sem::and_r64_mem8(b, reg(), sib_base(), disp8())
                } else {
                    sem::and_r32_mem8(b, reg(), sib_base(), disp8())
                }
            } else if rex_w {
                sem::and_r64_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::and_r32_sibd(b, reg(), sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::AndRMem32 => {
            if rex_w {
                sem::and_r64_mem32(b, reg(), rm(), disp32())
            } else {
                sem::and_r32_mem32(b, reg(), rm(), disp32())
            }
        }
        Insn::AndRSibd32 => {
            // 23 /r SIB mod=10。gunzip 0x48a957 の and ax, [r12+r12+disp32]。
            if no_index() {
                if has66 && !rex_w {
                    sem::and_r16_mem32(b, reg(), sib_base(), disp32())
                } else if rex_w {
                    sem::and_r64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::and_r32_mem32(b, reg(), sib_base(), disp32())
                }
            } else if has66 && !rex_w {
                sem::and_r16_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else if rex_w {
                sem::and_r64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::and_r32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
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
        Insn::SubRSibd32 => {
            // 2B SIB mod=10。iostat 0x448b8e の subq 0xc0(%rsp,%r13,1), %rbp。
            if no_index() {
                if rex_w {
                    sem::sub_r64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::sub_r32_mem32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::sub_r64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::sub_r32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
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
        Insn::OrRSibd32 => {
            // 0B /r SIB mod=10。bzip2 0x480ec8 の orq 0x98(%rdi,%rax), %rdx。
            if no_index() {
                if rex_w {
                    sem::or_r64_mem32(b, reg(), sib_base(), disp32())
                } else {
                    sem::or_r32_mem32(b, reg(), sib_base(), disp32())
                }
            } else if rex_w {
                sem::or_r64_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::or_r32_sibd32(b, reg(), sib_base(), sib_idx(), sib_shift(), disp32())
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
        Insn::OrRSibabs => {
            // 0B /r SIB mod=00 base=101。cryptpw 0x4bb2e0 の or r11d, [rdx*4+disp32]。
            if no_index() {
                if rex_w {
                    sem::or_r64_abs(b, reg(), imm32())
                } else {
                    sem::or_r32_abs(b, reg(), imm32())
                }
            } else if rex_w {
                sem::or_r64_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            } else {
                sem::or_r32_sibabs(b, reg(), sib_idx(), sib_shift(), disp32())
            }
        }
        Insn::AddRSibabs => {
            // 03 /r mod=00 SIB 直接番地 (7B)。disp32 は最下位32 LE。
            // no_index は [disp32]、索引ありは [idx*scale+disp32].
            // FS 上書きの有無でベースを切り替える（索引あり+FS は未対応のため FS を無視する）。
            let disp = disp32();
            let disp_le = imm32();
            if no_index() {
                match seg {
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
                match seg {
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
                match seg {
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
        Insn::EnCwde => {
            if rex_w {
                sem::cdqe(b)
            } else {
                sem::cwde(b)
            }
        }
        Insn::EnCdq => {
            // CDQ/CQO (0x99)。od 0x5acde6 対応。REX.W で64ビット.
            if rex_w { sem::cqo(b) } else { sem::cdq(b) }
        }
        Insn::CmpRm32 => {
            // 66 39 /r は cmpw。fgrep 0x401227 の 66 39 D6。
            if has66 {
                sem::cmp_rm16(b, rm(), reg())
            } else if rex_w {
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
            // 66 付きは16ビット。gzip 0x4845a8 の cmpw %r12w, (%rdi,%r13,4)。
            if has66 {
                if no_index() {
                    sem::cmp_m16_r16_memnd(b, sib_base(), reg())
                } else {
                    sem::cmp_m16_r16_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
                }
            } else if no_index() {
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
            if has66 {
                // 66 39 /r mod=00。gzip 0x4845d8 の cmpw %r8w, (%r11)。
                sem::cmp_m16_r16_memnd(b, rm(), reg())
            } else if rex_w {
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
        Insn::XorM32R32Memnd => {
            // 31 /r mod=00 [base]。sha3sum 0x4b45b5 の xorq %rcx, (%rdx)。
            if rex_w {
                sem::xor_m64_r64_memnd(b, rm(), reg())
            } else {
                sem::xor_m32_r32_memnd(b, rm(), reg())
            }
        }
        Insn::XorM32R32Mem8 => {
            // 31 /r mod=01 [base+disp8]。sha3sum 0x4b45b8 の xorq %rcx, 0x28(%rdx)。
            if rex_w {
                sem::xor_m64_r64_mem8(b, rm(), disp8(), reg())
            } else {
                sem::xor_m32_r32_mem8(b, rm(), disp8(), reg())
            }
        }
        Insn::XorM32R32Sibd => {
            // 31 /r SIB mod=01。gunzip 0x48a1c3 の xor DWORD PTR [rsp+disp8], ecx。
            if no_index() {
                if rex_w {
                    sem::xor_m64_r64_mem8(b, sib_base(), disp8(), reg())
                } else {
                    sem::xor_m32_r32_mem8(b, sib_base(), disp8(), reg())
                }
            } else if rex_w {
                sem::xor_m64_r64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            } else {
                sem::xor_m32_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            }
        }
        Insn::XorM32R32Mem32 => {
            // 31 /r mod=10 [base+disp32]。sha3sum 0x4b45c4 の xorq %rcx, 0xa0(%rdx)。
            if rex_w {
                sem::xor_m64_r64_mem32(b, rm(), disp32(), reg())
            } else {
                sem::xor_m32_r32_mem32(b, rm(), disp32(), reg())
            }
        }
        Insn::AndM32R32Memnd => {
            // 21 /r mod=00 [base]。chat 0x4d3473 の andq %rax, (%rdi)。
            if rex_w {
                sem::and_m64_r64_memnd(b, rm(), reg())
            } else {
                sem::and_m32_r32_memnd(b, rm(), reg())
            }
        }
        Insn::AndM32R32Sib => {
            // 21 /r SIB mod=00 [base+index*scale]。bzip2 0x47f93d の andl %ecx, (%r12,%rdx,4)。
            if no_index() {
                if rex_w {
                    sem::and_m64_r64_memnd(b, sib_base(), reg())
                } else {
                    sem::and_m32_r32_memnd(b, sib_base(), reg())
                }
            } else if rex_w {
                sem::and_m64_r64_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            } else {
                sem::and_m32_r32_sib(b, sib_base(), sib_idx(), sib_shift(), reg())
            }
        }
        Insn::AndM32R32Sibd => {
            // 21 /r SIB mod=01 [base+index*scale+disp8]。i386 nologin 0x80968e5 対応.
            if no_index() {
                if rex_w {
                    sem::and_m64_r64_mem8(b, sib_base(), disp8(), reg())
                } else {
                    sem::and_m32_r32_mem8(b, sib_base(), disp8(), reg())
                }
            } else if rex_w {
                sem::and_m64_r64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            } else {
                sem::and_m32_r32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8(), reg())
            }
        }
        Insn::AndM32R32Mem8 => {
            // 21 /r mod=01 [base+disp8]。
            if rex_w {
                sem::and_m64_r64_mem8(b, rm(), disp8(), reg())
            } else {
                sem::and_m32_r32_mem8(b, rm(), disp8(), reg())
            }
        }
        Insn::OrM32R32Sibabs => {
            // 09 /r SIB mod=00 base=101。dd 0x4cde65 の lock orq %rax, disp(,%rcx,8)。
            if no_index() {
                if rex_w {
                    sem::or_m64_r64_abs(b, disp32(), reg())
                } else {
                    sem::or_m32_r32_abs(b, reg(), disp32() as u32)
                }
            } else if rex_w {
                sem::or_m64_r64_sibabs(b, sib_idx(), sib_shift(), disp32(), reg())
            } else {
                sem::or_m32_r32_sibabs(b, sib_idx(), sib_shift(), disp32(), reg())
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
            if has66 && !rex_w {
                sem::xor_rm16(b, rm(), reg())
            } else if rex_w {
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
        Insn::MulRm32Sib => {
            // F7 /4 SIB mod=00 [base+index*scale] (3B)。i386 musl の mull (%esp)。base=5 は fetch が 7B にする.
            if no_index() {
                if rex_w {
                    sem::mul_rm64_memnd(b, sib_base())
                } else {
                    sem::mul_rm32_memnd(b, sib_base())
                }
            } else if rex_w {
                sem::mul_rm64_sib(b, sib_base(), sib_idx(), sib_shift())
            } else {
                sem::mul_rm32_sib(b, sib_base(), sib_idx(), sib_shift())
            }
        }
        Insn::MulRm32Rip => {
            // F7 25 + disp32。64bit は RIP 相対、i386 は絶対番地。i386 makemime 0x8103307 対応.
            if rex_w {
                sem::mul_rm64_rip(b, eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::mul_rm32_rip(b, eip as u64 + nbytes, disp32())
            } else {
                sem::mul_rm32_abs(b, imm32())
            }
        }
        Insn::ImulRmMem8 => {
            // F7 /5 mod=01 [base+disp8]。
            if rex_w {
                sem::imul_rm64_mem8(b, rm(), disp8())
            } else {
                sem::imul_rm32_mem8(b, rm(), disp8())
            }
        }
        Insn::ImulRmSibd => {
            // F7 /5 SIB mod=01。i386 musl の imul [esp+disp]。
            if no_index() {
                if rex_w {
                    sem::imul_rm64_mem8(b, sib_base(), disp8())
                } else {
                    sem::imul_rm32_mem8(b, sib_base(), disp8())
                }
            } else if rex_w {
                sem::imul_rm64_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            } else {
                sem::imul_rm32_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
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
        Insn::DivRm8 => {
            // F6 /6 mod=11。lzcat 0x48b6ef の div dl。AX を 8 ビットで割り、商は AL、剰余は AH。
            sem::div_rm8(b, eip, rm())
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
        Insn::EnCld => sem::cld(b),
        Insn::EnStd => sem::std(b),
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
        Insn::Cvtsi2sdM32Sibd => {
            // F2 0F 2A SIB mod=01。ntpd 0x42cb2f の cvtsi2sdq 0x8(%rsp), %xmm0。
            if sib0f_no_index() {
                if rex_w {
                    sem::cvtsi2sd_xmm_m64_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
                } else {
                    sem::cvtsi2sd_xmm_m32_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
                }
            } else if rex_w {
                sem::cvtsi2sd_xmm_m64_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            } else {
                sem::cvtsi2sd_xmm_m32_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            }
        }
        Insn::Cvtsi2sdM32Sib => {
            // F2 0F 2A SIB mod=00。ntpd 0x42cb3e の cvtsi2sdq (%rsp), %xmm1。base=5 は別長。
            if sib0f_no_index() {
                if rex_w {
                    sem::cvtsi2sd_xmm_m64_memnd(b, xmm_reg_r(), sib0f_base())
                } else {
                    sem::cvtsi2sd_xmm_m32_memnd(b, xmm_reg_r(), sib0f_base())
                }
            } else if rex_w {
                sem::cvtsi2sd_xmm_m64_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            } else {
                sem::cvtsi2sd_xmm_m32_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
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
        Insn::AddsdXmmM64Sibd => {
            // F2 0F 58 SIB mod=01。seq 0x499253 の addsd 0x10(%rsp), %xmm0。
            if sib0f_no_index() {
                sem::addsd_xmm_m64_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
            } else {
                sem::addsd_xmm_m64_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
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
        Insn::AddsdXmmM64Mem32 => {
            // F2 0F 58 /r mod=10。awk log 0x4c163e の addsd xmm3, [rdx+disp32]。
            sem::addsd_xmm_m64_mem32(b, xmm_reg_r(), rm0f(), disp32())
        }
        Insn::AddsdXmmM64Memnd => {
            // F2 0F 58 /r mod=00 [base]。ntpd 0x42c1d3 対応.
            sem::addsd_xmm_m64_memnd(b, xmm_reg_r(), rm0f())
        }
        Insn::AddsdXmmM64Mem8 => {
            // F2 0F 58 /r mod=01 [base+disp8]。ntpd の F2 0F 58 40 10。
            sem::addsd_xmm_m64_mem8(b, xmm_reg_r(), rm0f(), disp8())
        }
        // SUBSD xmm,xmm (F2 0F 5C /r reg-direct)。F2 は剥がし済み.
        Insn::Subsd => sem::subsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::SubsdXmmM64Rip => {
            // F2 0F 5C 05 + disp32。awk substr 0x4a3cbb の subsd xmm0, [rip+disp32]。
            if is64 {
                sem::subsd_xmm_m64_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::subsd_xmm_m64_abs(b, xmm_reg_r(), imm32())
            }
        }
        Insn::SubsdXmmM64Mem32 => {
            // F2 0F 5C /r mod=10。awk log 0x4c161e の subsd xmm2, [rcx+disp32]。
            sem::subsd_xmm_m64_mem32(b, xmm_reg_r(), rm0f(), disp32())
        }
        Insn::SubsdXmmM64Sibd => {
            // F2 0F 5C SIB mod=01。awk の 2^3 が 0x4c199c で使う subsd xmm0, [rsp+0x10]。
            if sib0f_no_index() {
                sem::subsd_xmm_m64_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
            } else {
                sem::subsd_xmm_m64_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
            }
        }
        Insn::SubsdXmmM64Mem8 => {
            // F2 0F 5C /r mod=01 [base+disp8]。ntpd 0x42c1ce 対応.
            sem::subsd_xmm_m64_mem8(b, xmm_reg_r(), rm0f(), disp8())
        }
        Insn::SubsdXmmM64Sibd32 => {
            // F2 0F 5C SIB mod=10。ntpd 0x42c207 の subsd xmm2, [rdi+rax*1+0x80]。
            if sib0f_no_index() {
                sem::subsd_xmm_m64_mem32(b, xmm_reg_r(), sib0f_base(), disp32())
            } else {
                sem::subsd_xmm_m64_sibd32(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            }
        }
        // MULSD xmm,xmm (F2 0F 59 /r reg-direct)。F2 は剥がし済み.
        Insn::Mulsd => sem::mulsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Sqrtsd => sem::sqrtsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Cvtsd2ss => {
            // F2 0F 5A = CVTSD2SS、F3 0F 5A = CVTSS2SD（同一 ModRM 形）。ntpd 0x42c158 対応.
            if rep {
                sem::cvtss2sd_xmm(b, xmm_reg_r(), xmm_rm_b())
            } else {
                sem::cvtsd2ss_xmm(b, xmm_reg_r(), xmm_rm_b())
            }
        }
        Insn::Cvtss2sdM32 => {
            // F3 0F 5A mod=00。od -tfF 0x4973b5 の cvtss2sd xmm0, [rbx]。F2 は m64 からの CVTSD2SS。
            if rep {
                sem::cvtss2sd_xmm_m32(b, xmm_reg_r(), rm0f())
            } else {
                sem::cvtsd2ss_xmm_m64(b, xmm_reg_r(), rm0f())
            }
        }
        Insn::MulsdM64Sib => {
            // F2 0F 59 SIB mod=00。awk 乗算 0x4a327c の mulsd xmm1, QWORD PTR [rsp]。
            if sib0f_no_index() {
                sem::mulsd_xmm_m64_memnd(b, xmm_reg_r(), sib0f_base())
            } else {
                sem::mulsd_xmm_m64_sib(b, xmm_reg_r(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
        Insn::MulsdXmmM64Rip => {
            // F2 0F 59 05 + disp32 (mod=00 RIP)。F2 は剥がし済み.
            if is64 {
                sem::mulsd_xmm_m64_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::mulsd_xmm_m64_abs(b, xmm_reg_r(), imm32())
            }
        }
        Insn::MulsdXmmM64Mem32 => {
            // F2 0F 59 /r mod=10。awk log 0x4c1636 の mulsd xmm2, [rdx+disp32]。
            sem::mulsd_xmm_m64_mem32(b, xmm_reg_r(), rm0f(), disp32())
        }
        Insn::Divsd => sem::divsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::Minsd => sem::minsd_xmm(b, xmm_reg_r(), xmm_rm_b()),
        Insn::DivsdXmmM64Rip => {
            // F2 0F 5E 05 + disp32。dd 0x4928e8 の divsd xmm0, [rip+disp]。
            if is64 {
                sem::divsd_xmm_m64_rip(b, xmm_reg_r(), eip as u64 + nbytes, disp32())
            } else {
                sem::divsd_xmm_m64_abs(b, xmm_reg_r(), imm32())
            }
        }
        Insn::MulsdXmmM64Sibd => {
            // F2 0F 59 SIB mod=01。seq 0x49924a の mulsd 0x8(%rsp), %xmm0。
            if sib0f_no_index() {
                sem::mulsd_xmm_m64_mem8(b, xmm_reg_r(), sib0f_base(), disp8())
            } else {
                sem::mulsd_xmm_m64_sibd(
                    b,
                    xmm_reg_r(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp8(),
                )
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
        Insn::Cvttsd2siM64Sib => {
            // F2 REX.W 0F 2C /r SIB mod=00。awk int 0x4a345e の cvttsd2si rax, [rsp]。
            if sib0f_no_index() {
                if rex_w {
                    sem::cvttsd2si_r64_memnd(b, reg0f_as_gpr(), sib0f_base())
                } else {
                    sem::cvttsd2si_r32_memnd(b, reg0f_as_gpr(), sib0f_base())
                }
            } else if rex_w {
                sem::cvttsd2si_r64_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            } else {
                sem::cvttsd2si_r32_sib(b, reg0f_as_gpr(), sib0f_base(), sib0f_idx(), sib0f_shift())
            }
        }
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
        Insn::BtM32ImmSib => {
            // BT m32,imm8 SIB mod=00 (0F BA /4 + ModRM + SIB + imm8、5B)。
            // SIB は (word>>8) 下位8、imm は最下位8。index=4 かつ REX.X=0 は [base]。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let imm = (word & 0xff) as u8;
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::bt_m32_imm(b, base, imm)
            } else {
                sem::bt_m32_imm_sib(b, base, idx, shift, imm)
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
        Insn::ShrdR32Imm8 => {
            // SHRD r/m32,r32,imm8 (0F AC /r ib mod=11)。REX.W で64ビット.
            let n = (word & 0xff) as u8;
            if rex_w {
                sem::shrd_r64_imm8(b, rm0f(), reg0f_as_gpr(), n)
            } else {
                sem::shrd_r32_imm8(b, rm0f(), reg0f_as_gpr(), n)
            }
        }
        Insn::ShldR32Imm8 => {
            // SHLD r/m32,r32,imm8 (0F A4 /r ib mod=11)。REX.W で64ビット.
            let n = (word & 0xff) as u8;
            if rex_w {
                sem::shld_r64_imm8(b, rm0f(), reg0f_as_gpr(), n)
            } else {
                sem::shld_r32_imm8(b, rm0f(), reg0f_as_gpr(), n)
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
        Insn::FnstcwSibd => {
            // D9 /7 SIB mod=01。seq 0x4d0c17 の fnstcw 0x4e(%rsp)。
            if no_index() {
                sem::fnstcw_mem8(b, sib_base(), disp8())
            } else {
                sem::fnstcw_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
        Insn::FnstcwMem32 => sem::fnstcw_mem32(b, rm(), disp32()),
        Insn::FldcwMemnd => sem::fldcw_memnd(b, rm()),
        Insn::FldcwMem8 => sem::fldcw_mem8(b, rm(), disp8()),
        Insn::FldcwSibd => {
            // D9 /5 SIB mod=01。seq 0x4d0c2d の fldcw 0x4c(%rsp)。
            if no_index() {
                sem::fldcw_mem8(b, sib_base(), disp8())
            } else {
                sem::fldcw_sibd(b, sib_base(), sib_idx(), sib_shift(), disp8())
            }
        }
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
        Insn::MovupsLoadSibabs => {
            // 0F 10 SIB mod=00 base=101。awk exp 0x4c12f4 の movsd xmm3, [rcx*8+disp32]。
            if sib0f_no_index() {
                if has_f2 {
                    sem::movsd_load_abs(b, xmm_reg_r(), disp32() as u32)
                } else {
                    sem::movups_load_abs(b, xmm_reg_r(), disp32() as u32)
                }
            } else if has_f2 {
                sem::movsd_load_sibabs(b, xmm_reg_r(), sib0f_idx(), sib0f_shift(), disp32())
            } else {
                sem::movups_load_sibabs(b, xmm_reg_r(), sib0f_idx(), sib0f_shift(), disp32())
            }
        }
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
        Insn::MovapsLoadSibd => {
            // 0F 28 SIB mod=01。diff -q 0x4a55eb の movaps 0x50(%rsp), %xmm0。
            if sib0f_no_index() {
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
            match seg {
                Some(base) if rex_w => sem::mov_rm64_imm_fs_mem8(b, base, rm(), d8, imm32()),
                Some(base) => sem::mov_rm32_imm_fs_mem8(b, base, rm(), d8, imm32()),
                None if rex_w => sem::mov_rm64_imm_mem8(b, rm(), d8, imm32()),
                None => sem::mov_rm32_imm_mem8(b, rm(), d8, imm32()),
            }
        }
        Insn::MovRmImmMemnd => {
            // C7 /0 mod=00 [base],imm32 (6B)。imm は最下位32.
            // FS 上書きでは FS_base + base に格納する.
            match seg {
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
        Insn::MovRm16ImmSibd32 => {
            // 66 C7 84 03 + disp32 + imm16。gzip 0x485910 の movw $0x8, 0xe6e(%rbx,%rax)。
            // SIB は (word>>48) 下位8、disp は (word>>16) 下位32 LE、imm は最下位16 LE。
            let sib_v = ((word >> 48) & 0xff) as u8;
            let disp = ((word >> 16) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            let shift = ((sib_v >> 6) & 3) as u32;
            let idx_raw = (sib_v >> 3) & 7;
            let idx = Gpr(idx_raw | (((rex >> 1) & 1) << 3));
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if idx_raw == 4 && (rex >> 1) & 1 == 0 {
                sem::mov_rm16_imm_mem32(b, base, disp, imm)
            } else {
                sem::mov_m16_imm_sibd32(b, base, idx, shift, disp, imm)
            }
        }
        Insn::MovRm16ImmDisp32 => {
            // 66 C7 /0 mod=10 rm!=4。gzip 0x485966 の movw $0x8, 0x12ce(%rbx)。
            let rm = ((word >> 48) & 7) as u8;
            let base = Gpr(rm | ((rex & 1) << 3));
            let disp = ((word >> 16) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff) as u16).swap_bytes();
            sem::mov_rm16_imm_mem32(b, base, disp, imm)
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
                match seg {
                    Some(base) if rex_w => sem::mov_rm64_imm_fs_abs(b, base, disp, imm32()),
                    Some(base) => sem::mov_rm32_imm_fs_abs(b, base, disp, imm32()),
                    None if rex_w => sem::mov_rm64_imm_abs(b, disp_le, imm32()),
                    None => sem::mov_rm32_imm_abs(b, disp_le, imm32()),
                }
            } else if let Some(base) = seg {
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
                match seg {
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
                match seg {
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
        Insn::CmovneMem8 => {
            // 0F 45 mod=01 [base+disp8]。ed 0x4b5cd8 の cmovne 0x30(%rbx), %rax。
            if rex_w {
                sem::cmovne_r64_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::cmovne_r32_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
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
        Insn::CmovbeR64Sibd => {
            // 0F 46 SIB mod=01 [base+disp8] no_index。softlimit 0x44eece。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if rex_w {
                sem::cmovbe_r64_sibd(b, reg0f_as_gpr(), base, d8)
            } else {
                sem::cmovbe_r32_sibd(b, reg0f_as_gpr(), base, d8)
            }
        }
        Insn::CmovbeMemnd => {
            // 0F 46 mod=00 [base]。gunzip 0x48a025 の cmovbe edx, [r8]。
            if rex_w {
                sem::cmovbe_r64_memnd(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::cmovbe_r32_memnd(b, reg0f_as_gpr(), rm0f())
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
        Insn::CmovaeMem8 => {
            // 0F 43 mod=01 [base+disp8]。dc 0x40bc13 の cmovae rax, [rsi+8]。
            if rex_w {
                sem::cmovae_r64_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::cmovae_r32_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
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
        Insn::CmovneR32Sibd32 => {
            // 0F 45 SIB mod=10 [base+disp32] no_index (64b)。free 0x44801c。
            // SIB は (word>>32) 下位8、disp32 は最下位32 LE。
            let sib_v = ((word >> 32) & 0xff) as u8;
            let disp = (word as u32).swap_bytes() as i32;
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if rex_w {
                sem::cmovne_r64_sibd32(b, reg0f_as_gpr(), base, disp)
            } else {
                sem::cmovne_r32_sibd32(b, reg0f_as_gpr(), base, disp)
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
        Insn::CmovgeR32Sibd => {
            // 0F 4D SIB mod=01 [base+disp8] no_index。seq 0x4d137a の cmovgel 0x10(%rsp), %eax。
            let sib_v = ((word >> 8) & 0xff) as u8;
            let d8 = (word & 0xff) as u8 as i8;
            let base = Gpr((sib_v & 7) | ((rex & 1) << 3));
            if rex_w {
                sem::cmovge_r64_sibd(b, reg0f_as_gpr(), base, d8)
            } else {
                sem::cmovge_r32_sibd(b, reg0f_as_gpr(), base, d8)
            }
        }
        Insn::CmovlR32Sib => {
            // 0F 4C SIB mod=00 [base] no_index。cut 0x492257 の cmovll (%rsp), %r10d。
            let base = sib0f_base();
            if rex_w {
                sem::cmovl_r64_sib(b, reg0f_as_gpr(), base)
            } else {
                sem::cmovl_r32_sib(b, reg0f_as_gpr(), base)
            }
        }
        Insn::CmovsR32Sib => {
            // 0F 48 SIB mod=00 [base] no_index。sed 0x4c9eb0 の cmovsl (%rsp), %ecx。
            let base = sib0f_base();
            if rex_w {
                sem::cmovs_r64_sib(b, reg0f_as_gpr(), base)
            } else {
                sem::cmovs_r32_sib(b, reg0f_as_gpr(), base)
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
        Insn::CmovbeRip => {
            // CMOVBE r64/r32, m64/m32 [RIP+disp32] (0F 46 05 + disp32)。sv 0x4512c9 対応.
            if rex_w {
                sem::cmovbe_r64_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else if is64 {
                sem::cmovbe_r32_rip(b, reg0f_as_gpr(), eip as u64 + nbytes, disp32())
            } else {
                sem::cmovbe_r32_abs(b, reg0f_as_gpr(), imm32())
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
        Insn::ImulRImmSib => {
            // 69 /r SIB mod=00 + imm32。dd 0x4067c3 の imulq $0xf4240, (%rsp), %rcx。
            if no_index() {
                if rex_w {
                    sem::imul_r64_imm_memnd(b, reg(), sib_base(), imm32())
                } else {
                    sem::imul_r32_imm_memnd(b, reg(), sib_base(), imm32())
                }
            } else if rex_w {
                sem::imul_r64_imm_sib(b, reg(), sib_base(), sib_idx(), sib_shift(), imm32())
            } else {
                sem::imul_r32_imm_sib(b, reg(), sib_base(), sib_idx(), sib_shift(), imm32())
            }
        }
        Insn::ImulRImmMem8 => {
            // 69 /r mod=01 [base+disp8], imm32。ifplugd 0x4264b0。フラグは変えない。
            let disp = ((word >> 32) & 0xff) as u8 as i8;
            if rex_w {
                sem::imul_r64_imm_mem8(b, reg(), rm(), disp, imm32())
            } else {
                sem::imul_r32_imm_mem8(b, reg(), rm(), disp, imm32())
            }
        }
        Insn::ImulRImmSibd => {
            // 69 /r SIB mod=01 + imm32。disp は imm32 の直前。mktemp 0x4d85cf。
            let disp = ((word >> 32) & 0xff) as u8 as i8;
            let base = sib_base();
            if rex_w {
                sem::imul_r64_imm_sibd(b, reg(), base, disp, imm32())
            } else {
                sem::imul_r32_imm_sibd(b, reg(), base, disp, imm32())
            }
        }
        Insn::ImulRImm8Sib => {
            // 6B /r SIB mod=00 + imm8。mpstat 0x449c01 の imul $0x48, (%rsp), %rbp。フラグは変えない。
            let imm = (word & 0xff) as u8 as i8;
            let base = sib_base();
            if rex_w {
                sem::imul_r64_imm8_memnd(b, reg(), base, imm)
            } else {
                sem::imul_r32_imm8_memnd(b, reg(), base, imm)
            }
        }
        Insn::ImulRImm8Sibd => {
            // 6B /r SIB mod=01 + imm8。disp は imm8 の直前。iostat 0x44897d。フラグは変えない。
            let disp = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            let base = sib_base();
            if rex_w {
                sem::imul_r64_imm8_sibd(b, reg(), base, disp, imm)
            } else {
                sem::imul_r32_imm8_sibd(b, reg(), base, disp, imm)
            }
        }
        Insn::ImulRImm8Mem8 => {
            // 6B /r mod=01 [base+disp8] + imm8。nmeter 0x44a5eb。フラグは変えない。
            let disp = ((word >> 8) & 0xff) as u8 as i8;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::imul_r64_imm8_mem8(b, reg(), rm(), disp, imm)
            } else {
                sem::imul_r32_imm8_mem8(b, reg(), rm(), disp, imm)
            }
        }
        Insn::ImulRImm8 => {
            if rex_w {
                sem::imul_r64_imm8(b, reg(), rm(), disp8())
            } else {
                sem::imul_r32_imm8(b, reg(), rm(), disp8())
            }
        }
        Insn::ImulRImm8Mem32 => {
            // 6B /r mod=10 [base+disp32] + imm8 (7B)。i386 iostat 0x808b648。フラグは変えない。
            let d32 = (((word >> 8) & 0xffff_ffff) as u32).swap_bytes() as i32;
            let imm = (word & 0xff) as u8 as i8;
            if rex_w {
                sem::imul_r64_imm8_mem32(b, reg(), rm(), d32, imm)
            } else {
                sem::imul_r32_imm8_mem32(b, reg(), rm(), d32, imm)
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
        Insn::ImulRSibabs => {
            // 0F AF SIB mod=00 base=101。awk 0x4d6114 の imul eax, [rdx*4+disp32]。
            if sib0f_no_index() {
                if rex_w {
                    sem::imul_r64_dispabs(b, reg0f_as_gpr(), disp32())
                } else {
                    sem::imul_r32_dispabs(b, reg0f_as_gpr(), disp32())
                }
            } else if rex_w {
                sem::imul_r64_sibabs(b, reg0f_as_gpr(), sib0f_idx(), sib0f_shift(), disp32())
            } else {
                sem::imul_r32_sibabs(b, reg0f_as_gpr(), sib0f_idx(), sib0f_shift(), disp32())
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
                // i386 の rm=101 は絶対番地 [disp32]。
                sem::cmpxchg_r32_abs(b, disp32(), reg0f_as_gpr())
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
        Insn::ImulRImmRip => {
            // 69 /r id + disp32 + imm32 (80b)。disp は (word>>32) 下位32 LE、imm は下位32 LE。
            // nslookup 0x42bb05 の imul eax, [rip+disp32], 0x3e8。
            let disp = ((word >> 32) as u32).swap_bytes() as i32;
            let imm = ((word & 0xffff_ffff) as u32).swap_bytes();
            if rex_w {
                sem::imul_r64_imm_rip(b, reg(), eip as u64 + nbytes, disp, imm)
            } else if is64 {
                sem::imul_r32_imm_rip(b, reg(), eip as u64 + nbytes, disp, imm)
            } else {
                sem::imul_r32_imm_abs(b, reg(), disp as u32, imm)
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
        Insn::MovsxR32R16 => {
            // 0F BF /r mod=11。man 0x4d80c6 の movsx esi, si。
            if rex_w {
                sem::movsx_r64_r16(b, reg0f_as_gpr(), rm0f())
            } else {
                sem::movsx_r32_r16(b, reg0f_as_gpr(), rm0f())
            }
        }
        Insn::MovzxR32M16Sibabs => {
            // 0F B7 SIB mod=00 base=5。microcom 0x4bc4f2 の movzx r9d, WORD PTR [rdx*4+disp32]。
            if sib0f_no_index() {
                sem::movzx_r32_m16_abs(b, reg0f_as_gpr(), disp32() as u32)
            } else if rex_w {
                sem::movzx_r64_m16_sibabs(b, reg0f_as_gpr(), sib0f_idx(), sib0f_shift(), disp32())
            } else {
                sem::movzx_r32_m16_sibabs(b, reg0f_as_gpr(), sib0f_idx(), sib0f_shift(), disp32())
            }
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
        Insn::MovsxR32M16Mem8 => {
            // 0F BF mod=01。lpq 0x4c336d の movswq 0x50(%rbp), %rax。
            if rex_w {
                sem::movsx_r64_m16_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            } else {
                sem::movsx_r32_m16_mem8(b, reg0f_as_gpr(), rm0f(), disp8())
            }
        }
        Insn::MovsxR32M16Sibd32 => {
            // 0F BF SIB mod=10。iostat 0x4be9fb の movswq disp(%rax,%rax,1), %rax。
            if sib0f_no_index() {
                if rex_w {
                    sem::movsx_r64_m16_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                } else {
                    sem::movsx_r32_m16_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                }
            } else if rex_w {
                sem::movsx_r64_m16_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            } else {
                sem::movsx_r32_m16_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
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
        Insn::MovsxR32M8Sibd32 => {
            // 0F BE SIB mod=10。nc 0x4c71fd の movsbl 0xfa(%rsp), %eax。
            if sib0f_no_index() {
                if rex_w {
                    sem::movsx_r64_m8_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                } else {
                    sem::movsx_r32_m8_mem32(b, reg0f_as_gpr(), sib0f_base(), disp32())
                }
            } else if rex_w {
                sem::movsx_r64_m8_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
            } else {
                sem::movsx_r32_m8_sibd32(
                    b,
                    reg0f_as_gpr(),
                    sib0f_base(),
                    sib0f_idx(),
                    sib0f_shift(),
                    disp32(),
                )
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
        Insn::SeteM8Rip => {
            // 0F 94 mod=00 rm=101。hdparm 0x417940 の sete byte [rip+disp32]。
            let disp = (word as u32).swap_bytes() as i32;
            if is64 {
                sem::sete_m8_rip(b, eip as u64 + nbytes, disp)
            } else {
                sem::sete_m8_abs(b, (word as u32).swap_bytes())
            }
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
        // オペコード表経路の命令は dispatch_map が処理する。ここに来たのは
        // 経路選択の誤り。
        _ => sem::nop(b),
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
            | Insn::EnCwde => Some(Gpr(0)),
            Insn::IncEcx | Insn::DecEcx => Some(Gpr(1)),
            Insn::IncEdx | Insn::DecEdx | Insn::EnCdq => Some(Gpr(2)),
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
            | Insn::RolRm32Cl
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
            | Insn::ImulRImm8Mem8
            | Insn::ImulRImm8Mem32
            | Insn::ImulRImm8Rip
            | Insn::ImulRImmRip => Some(reg()),
            Insn::Cmovb
            | Insn::Cmovne
            | Insn::Cmove
            | Insn::Cmovns
            | Insn::Cmovbe
            | Insn::CmovbeMemnd
            | Insn::Cmova
            | Insn::Cmovae
            | Insn::CmovaeMem8
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
            | Insn::MovzxR32M16Sibabs
            | Insn::MovzxR32M16Sibd
            | Insn::MovzxR32M16Sibd32
            | Insn::MovsxR32M8Mem32
            | Insn::MovsxR32M8Sibd32
            | Insn::MovzxR32M16Rip
            | Insn::MovzxR32M8Rip
            | Insn::MovzxR32M8Memnd
            | Insn::MovzxR32M8Mem8
            | Insn::MovzxR32M8Mem32
            | Insn::MovzxR32M8Sib
            | Insn::MovzxR32M8Sibd
            | Insn::MovzxR32M8Sibd32
            | Insn::MovzxR32R8
            | Insn::MovzxR32R16
            | Insn::MovzxR32M16Mem8
            | Insn::MovsxR32R16
            | Insn::MovsxR32R8
            | Insn::MovsxR32M16Mem8
            | Insn::MovsxR32M16Sibd32
            | Insn::MovsxR32M8Mem8
            | Insn::MovsxR32M8Memnd
            | Insn::MovsxR32M8Rip
            | Insn::MovsxR32M8Sib
            | Insn::MovsxR32M8Sibd
            | Insn::ImulRRm
            | Insn::ImulRMemnd
            | Insn::ImulRMem8
            | Insn::ImulRMem32
            | Insn::ImulRSibd
            | Insn::ImulRSibabs
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
            | Insn::BsrRRip
            | Insn::Cvttsd2siM64Sib => Some(reg0f_as_gpr()),
            Insn::Pmovmskb => Some(reg0f_as_gpr()),
            // BTS の宛先は rm 側（reg0f はビット番号）。上位は rm の
            // 32 ビット書き戻しで消える。
            Insn::BtsR32Rm => Some(rm0f()),
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
            | Insn::AndRSib
            | Insn::AndRSibd32
            | Insn::AndRRip
            | Insn::AdcRMemnd
            | Insn::AdcRMem8
            | Insn::AdcRMem32
            | Insn::AdcRSibd
            | Insn::AdcRSibabs
            | Insn::AdcRRip
            | Insn::SbbRMemnd
            | Insn::SbbRMem8
            | Insn::SbbRMem32
            | Insn::SbbRRip
            | Insn::OrRRip
            | Insn::OrRMemnd
            | Insn::OrRMem8
            | Insn::OrRMem32
            | Insn::OrRSibabs
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
            let skip = (rex_w
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
                ))
                || (rex_w
                    && matches!(
                        insn,
                        Insn::RolRm32Cl
                            | Insn::ImulRSibabs
                            | Insn::OrRSibabs
                            | Insn::MovsxR32M8Sibd32
                            | Insn::ImulRImmRip
                            | Insn::CmovbeMemnd
                            | Insn::CmovaeMem8
                            | Insn::MovsxR32R16
                            | Insn::Cvttsd2siM64Sib
                    ))
                || (has66
                    && matches!(
                        insn,
                        Insn::XorRm32 | Insn::RolRm32Imm8 | Insn::MovEaxMem8 | Insn::AndRSibd32
                    ));
            if !skip {
                sem::clear_hi(b, d);
            }
        }
        // 32ビット DIV/MUL/IMUL/IDIV のみゼロ拡張する。64ビット DIV (REX.W) は full64 のため消さない.
        if !rex_w
            && matches!(
                insn,
                Insn::MulRm32
                    | Insn::MulRm32Sib
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
/// 受け持つ。番号表は 32ビット Linux（i386 ABI）のものを使う。
pub fn run_image_x86_32(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut impl TrapHandler,
) -> Result<u64, String> {
    run_image_x86_32_ex(bytes, prog, argv, sys, polyisa_guest_x86::DEFAULT_FEATS)
}

/// 既定モデルの `CpuSel`（`--cpu` 省略時と同じ解決）。
/// CPUID の導出に使う機能名集合と識別情報の既定値。
fn default_sel() -> polyisa_isadl::select::CpuSel {
    polyisa_isadl::select::resolve(
        polyisa_guest_x86::MODEL_DEFS,
        polyisa_guest_x86::FEATURE_DEFS,
        polyisa_guest_x86::FEAT_BITS,
        "",
        &[],
        &[],
    )
    .expect("x86 の既定モデルの解決")
}

/// `run_image_x86_32` に機能集合を渡す（`--cpu` の配線）。
/// CPUID の識別情報は既定モデルのものを使う（`feats` だけを
/// 渡す経路では機能名集合を再現できないため）。
pub fn run_image_x86_32_ex(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut impl TrapHandler,
    feats: u128,
) -> Result<u64, String> {
    let sel = default_sel();
    run_image_x86_32_impl(
        bytes,
        prog,
        argv,
        sys,
        feats,
        &sel.features,
        &sel.ident,
        &polyisa_guest_x86::DEFAULT_PARAMS,
    )
}

/// `run_image_x86_32` に CPU モデルの選択を渡す（`--cpu` の配線）。
/// `None` でも既定モデルを解決し、CPUID の識別情報が空にならない
/// ようにする。
pub fn run_image_x86_32_sel(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut impl TrapHandler,
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let owned;
    let sel = match sel {
        Some(s) => s,
        None => {
            owned = default_sel();
            &owned
        }
    };
    run_image_x86_32_impl(
        bytes,
        prog,
        argv,
        sys,
        sel.feats,
        &sel.features,
        &sel.ident,
        &polyisa_guest_x86::model_params(&sel.name),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_image_x86_32_impl(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut impl TrapHandler,
    feats: u128,
    features: &std::collections::BTreeSet<String>,
    ident: &std::collections::BTreeMap<String, String>,
    params: &polyisa_guest_x86::Params,
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
    // ヒープの初期ブレークは像末尾（PT_LOAD の最大到達）。brk(0) の問い合わせに答える。
    let mut image_end = 0u64;
    for ph in &phdrs {
        if ph.seg_type != 1 {
            continue;
        }
        image_end = image_end.max(ph.vaddr.saturating_add(ph.memsz));
    }
    sys.init_brk(image_end);
    // 初期スタックを写像する。i386 はエントリ幅 4 バイトの像を使う（動的リンクは後の段階）。
    let top = 0x7fff_0000u64;
    let mut arg_bytes = vec![prog.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // i386 musl は syscall を `call *%gs:0x10`（AT_SYSINFO の vsyscall スタブ）で行う。
    // スタブページを写像し、AT_SYSINFO (32) で番地を知らせる。中身は int 0x80; ret.
    const VSYS_ADDR: u64 = 0xffff_e000;
    let (img, sp) = polyisa_os_linux::build_initial_stack32(
        top,
        &arg_bytes,
        &[],
        &[(6, 0x1000), (32, VSYS_ADDR)],
    );
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
    // vsyscall スタブページ（int 0x80; ret）。ELF より後に写像して上書きされないようにする.
    env.backend
        .mem
        .map(
            polyisa_mem::VirtAddr(VSYS_ADDR),
            1,
            Perms(Perms::R.0 | Perms::W.0 | Perms::X.0),
        )
        .map_err(|e| format!("vsys map: {e:?}"))?;
    env.backend
        .mem
        .write(polyisa_mem::VirtAddr(VSYS_ADDR), &[0xCD, 0x80, 0xC3])
        .map_err(|e| format!("vsys write: {e:?}"))?;
    env.backend.set(Gpr(4).state(), sp as u32);
    // x87 制御ワードの初期値（丸め最近接の 0x037F）。FNSTCW/FLDCW で使う.
    env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
    env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
    // OSXSAVE=1 を報告するので XCR0 は OS が対応成分を有効化した
    // 後の値で始める（実機のリセット値は 1。AVX モデルでは 7）。
    let supp = polyisa_guest_x86::cpuid::xcomp_supp(features);
    env.backend
        .set(polyisa_guest_x86::sem::xcr0_ref(), supp & 0xFFFF);
    env.backend
        .set(polyisa_guest_x86::sem::xcomp_supp_ref(), supp);
    env.backend
        .set(polyisa_guest_x86::sem::xcomp_perm_ref(), supp & 0xFFFF);
    install_cpuid(&mut env, features, ident);
    match run_mode_ex(
        &mut env,
        ehdr.entry as u32,
        sys,
        1_000_000,
        false,
        feats,
        params,
    ) {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
        Outcome::Breakpoint { pc } => Err(format!("breakpoint at {pc:#x}")),
    }
}

/// ELF ファイルを実行する。`run_elf` の x86 版である。
pub fn run_elf_x86_32(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_x86_32_sel(path, argv, None)
}

/// `run_elf_x86_32` に CPU モデルの選択を渡す（`--cpu` の配線）。
pub fn run_elf_x86_32_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = Linux::x86_32();
    run_image_x86_32_sel(&bytes, path, argv, &mut sys, sel)
}

/// ELF32 を実行し、終了コードと fd 1 の出力を返す。ホストの stdout には書かない。
pub fn run_elf_x86_32_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = Linux::x86_32();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    sys.capture_out = Some(std::rc::Rc::clone(&captured));
    let code = run_image_x86_32(&bytes, path, argv, &mut sys)?;
    Ok((code, captured.borrow().clone()))
}

/// ELF64 イメージを実行する。EM_X86_64 の静的実行を受け持つ。
/// 番号表は x86-64 Linux のものを使う。4GB 未満の配置を想定し、
/// RIP 上位と 64ビットスタックは扱わない（静的・非PIE のみ）。
pub fn run_image_x86_64(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut Linux,
) -> Result<u64, String> {
    run_image_x86_64_ex(bytes, prog, argv, sys, polyisa_guest_x86::DEFAULT_FEATS)
}

/// `run_image_x86_64` に機能集合を渡す（`--cpu` の配線）。
/// CPUID の識別情報は既定モデルのものを使う。
pub fn run_image_x86_64_ex(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut Linux,
    feats: u128,
) -> Result<u64, String> {
    let sel = default_sel();
    run_image_x86_64_impl(
        bytes,
        prog,
        argv,
        sys,
        feats,
        &sel.features,
        &sel.ident,
        None,
        &polyisa_guest_x86::DEFAULT_PARAMS,
        false,
    )
}

/// `run_image_x86_64` に CPU モデルの選択を渡す（`--cpu` の配線）。
/// `None` でも既定モデルを解決する。
pub fn run_image_x86_64_sel(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut Linux,
    sel: Option<&polyisa_isadl::select::CpuSel>,
    jit: Option<&mut polyisa_jit::Jit>,
) -> Result<u64, String> {
    let owned;
    let sel = match sel {
        Some(s) => s,
        None => {
            owned = default_sel();
            &owned
        }
    };
    run_image_x86_64_impl(
        bytes,
        prog,
        argv,
        sys,
        sel.feats,
        &sel.features,
        &sel.ident,
        jit,
        &polyisa_guest_x86::model_params(&sel.name),
        false,
    )
}

/// ELF32 + EM_X86_64 の x32（ILP32）イメージを実行する。
/// `sys` は `Linux::x86_x32()` で作ったものを渡す。
/// 命令は 64 ビットモード、ポインタ幅と実効アドレスは 32 ビット。
pub fn run_image_x86_x32_sel(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut Linux,
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let owned;
    let sel = match sel {
        Some(s) => s,
        None => {
            owned = default_sel();
            &owned
        }
    };
    run_image_x86_64_impl(
        bytes,
        prog,
        argv,
        sys,
        sel.feats,
        &sel.features,
        &sel.ident,
        None,
        &polyisa_guest_x86::model_params(&sel.name),
        true,
    )
}

/// x32 の ELF ファイルを実行する。`run_elf_x86_64_sel` の x32 版。
pub fn run_elf_x86_x32_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = Linux::x86_x32();
    run_image_x86_x32_sel(&bytes, path, argv, &mut sys, sel)
}

/// x32 の ELF を実行し、終了コードと fd 1 の出力を返す。ホストの stdout には書かない。
pub fn run_elf_x86_x32_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = Linux::x86_x32();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    sys.capture_out = Some(std::rc::Rc::clone(&captured));
    let code = run_image_x86_x32_sel(&bytes, path, argv, &mut sys, None)?;
    Ok((code, captured.borrow().clone()))
}

/// `run_image_x86_64_ex` の実体。`jit` があればブロック実行経路を使う。
/// `x32` のときは ELFCLASS32 の像を 64 ビットモードで実行し、
/// ポインタ幅と実効アドレスは 32 ビットに絞る。
#[allow(clippy::too_many_arguments)]
fn run_image_x86_64_impl(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut Linux,
    feats: u128,
    features: &std::collections::BTreeSet<String>,
    ident: &std::collections::BTreeMap<String, String>,
    jit: Option<&mut polyisa_jit::Jit>,
    params: &polyisa_guest_x86::Params,
    x32: bool,
) -> Result<u64, String> {
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_mem::{PAGE_SIZE, Perms};

    if sys.is_x32() != x32 {
        return Err("像の ABI とシステムコールハンドラが食い違う".to_string());
    }
    // x32 は ELFCLASS32 + EM_X86_64。Ref: SRC-LINUX (7.3)。
    let ehdr = if x32 {
        polyisa_loader::elf::parse_ehdr32(bytes).map_err(|e| format!("ehdr: {e:?}"))?
    } else {
        polyisa_loader::elf::parse_ehdr(bytes).map_err(|e| format!("ehdr: {e:?}"))?
    };
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
    let phdrs = if x32 {
        polyisa_loader::elf::parse_phdrs32(bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?
    } else {
        polyisa_loader::elf::parse_phdrs(bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?
    };
    // GNU_PROPERTY_X86_* の要求を CPU モデルと突き合わせる。
    // 不足は拒否ではなく警告にとどめる（cpu-models.md の規約）。
    check_gnu_properties(bytes, &phdrs, ehdr.little, features);
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
    // x32 のスタック項目は 32 ビット幅（ポインタが 4 バイトの ILP32）。
    let (img, sp) = if x32 {
        polyisa_os_linux::build_initial_stack32(top, &arg_bytes, &[], &[(6, 0x1000)])
    } else {
        polyisa_os_linux::build_initial_stack(top, &arg_bytes, &[], &[(6, 0x1000)])
    };
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
    // x86-64 の vsyscall ページ。call で飛んでくる呼び出しを
    // `mov eax,nr; syscall; ret` スタブ経由で OS パーソナリティへ回す。
    // ELF より後に写像して上書きされないようにする（i386 と同じ規則）。
    polyisa_os_linux::x86::map_vsyscall_page(&mut env.backend.mem)
        .map_err(|e| format!("vsys map: {e:?}"))?;
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), sp);
    // x87 制御ワードの初期値（丸め最近接の 0x037F）。FNSTCW/FLDCW で使う.
    env.backend.set(polyisa_guest_x86::sem::fcw_ref(), 0x037F);
    env.backend.set(polyisa_guest_x86::sem::mxcsr_ref(), 0x1F80);
    // OSXSAVE=1 を報告するので XCR0 は OS が対応成分を有効化した
    // 後の値で始める（実機のリセット値は 1。AVX モデルでは 7）。
    let supp = polyisa_guest_x86::cpuid::xcomp_supp(features);
    env.backend
        .set(polyisa_guest_x86::sem::xcr0_ref(), supp & 0xFFFF);
    env.backend
        .set(polyisa_guest_x86::sem::xcomp_supp_ref(), supp);
    env.backend
        .set(polyisa_guest_x86::sem::xcomp_perm_ref(), supp & 0xFFFF);
    install_cpuid(&mut env, features, ident);
    let out = if x32 {
        // JIT 経路は x32 未対応。64 ビットモード・32 ビットアドレス幅で逐次実行。
        run_mode_x32_ex(&mut env, ehdr.entry as u32, sys, 30_000_000, feats, params)
    } else {
        match jit {
            Some(jit) => run_mode_ex_jit(
                &mut env,
                ehdr.entry as u32,
                sys,
                30_000_000,
                true,
                feats,
                params,
                jit,
            ),
            None => run_mode_ex(
                &mut env,
                ehdr.entry as u32,
                sys,
                30_000_000,
                true,
                feats,
                params,
            ),
        }
    };
    match out {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
        Outcome::Breakpoint { pc } => Err(format!("breakpoint at {pc:#x}")),
    }
}

/// `PT_GNU_PROPERTY` の `GNU_PROPERTY_X86_*` が要求する機能を
/// CPU モデルの機能集合と突き合わせ、足りない機能を警告として出す。
fn check_gnu_properties(
    bytes: &[u8],
    phdrs: &[polyisa_loader::elf::Phdr],
    little: bool,
    features: &std::collections::BTreeSet<String>,
) {
    use polyisa_loader::elf::{
        GNU_PROPERTY_X86_FEATURE_1_AND, GNU_PROPERTY_X86_FEATURE_2_NEEDED,
        GNU_PROPERTY_X86_FEATURE_2_USED, GNU_PROPERTY_X86_ISA_1_NEEDED,
        GNU_PROPERTY_X86_ISA_1_USED, gnu_properties,
    };
    // FEATURE_1_AND: 立っている全ビットの機能を必要とする。
    // 値はカーネルが CET の判定に使うもの（Ref: SRC-LINUX）。
    const F1: &[(u64, &str)] = &[(0x1, "cet_ibt"), (0x2, "cet_ss")];
    // FEATURE_2_USED/NEEDED: プログラムが使うレジスタ状態の成分。
    // bit0 (X86) は基本機能で常に立つ。XSAVEC はモデルにない。
    const F2: &[(u64, &str)] = &[
        (0x2, "fpu"),        // X87
        (0x4, "mmx"),        // MMX
        (0x8, "sse"),        // XMM
        (0x10, "avx"),       // YMM
        (0x20, "avx512f"),   // ZMM
        (0x40, "fxsr"),      // FXSR
        (0x80, "xsave"),     // XSAVE
        (0x100, "xsaveopt"), // XSAVEOPT
        (0x400, "amx_tile"), // TMM
        (0x800, "avx512f"),  // MASK（AVX512 マスクレジスタ）
    ];
    // ISA_1_USED/NEEDED: マイクロアーキテクチャ水準（x86-64-v*）。
    const ISA_BASELINE: &[&str] = &["cmov", "cx8", "fpu", "mmx", "fxsr", "sse2"];
    const ISA_V2: &[&str] = &[
        "cx16", "lahf_lm", "popcnt", "sse3", "ssse3", "sse4_1", "sse4_2",
    ];
    const ISA_V3: &[&str] = &[
        "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe", "xsave",
    ];
    const ISA_V4: &[&str] = &["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"];
    const ISA_LEVELS: &[(u64, &str, &[&str])] = &[
        (0x1, "x86-64", ISA_BASELINE),
        (0x2, "x86-64-v2", ISA_V2),
        (0x4, "x86-64-v3", ISA_V3),
        (0x8, "x86-64-v4", ISA_V4),
    ];
    for (ty, val) in gnu_properties(bytes, phdrs, little) {
        match ty {
            GNU_PROPERTY_X86_FEATURE_1_AND
            | GNU_PROPERTY_X86_FEATURE_2_USED
            | GNU_PROPERTY_X86_FEATURE_2_NEEDED => {
                let (label, table) = match ty {
                    GNU_PROPERTY_X86_FEATURE_1_AND => ("FEATURE_1_AND", F1),
                    GNU_PROPERTY_X86_FEATURE_2_USED => ("FEATURE_2_USED", F2),
                    _ => ("FEATURE_2_NEEDED", F2),
                };
                let mut rest = val;
                for &(bit, name) in table {
                    if rest & bit == 0 {
                        continue;
                    }
                    rest &= !bit;
                    if !features.contains(name) {
                        eprintln!("run: ELF は {label} で {name} を要求するが CPU モデルにない");
                    }
                }
                // bit0（X86）は常に立つ基本機能ビット。残りは未知ビットとして報告。
                rest &= !1u64;
                if rest != 0 {
                    eprintln!("run: ELF は {label} で未対応の機能ビット {rest:#x} を要求する");
                }
            }
            GNU_PROPERTY_X86_ISA_1_USED | GNU_PROPERTY_X86_ISA_1_NEEDED => {
                let label = if ty == GNU_PROPERTY_X86_ISA_1_USED {
                    "ISA_1_USED"
                } else {
                    "ISA_1_NEEDED"
                };
                // 水準は累積（v3 は baseline・v2 を含む）なので、
                // 立った最上位の水準まで下位の全機能を検査する。
                let mut rest = val;
                let mut top = 0usize;
                for (i, &(bit, _, _)) in ISA_LEVELS.iter().enumerate() {
                    if rest & bit != 0 {
                        rest &= !bit;
                        top = i + 1;
                    }
                }
                for &(.., level, feats) in &ISA_LEVELS[..top] {
                    for name in feats {
                        if !features.contains(*name) {
                            eprintln!(
                                "run: ELF は {label} で {level} を要求するが CPU モデルに {name} がない"
                            );
                        }
                    }
                }
                if rest != 0 {
                    eprintln!("run: ELF は {label} で未対応の水準ビット {rest:#x} を要求する");
                }
            }
            _ => {}
        }
    }
}
/// ELF64 ファイルを実行する。`run_elf_x86_32` の x86-64 版である。
pub fn run_elf_x86_64(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_x86_64_sel(path, argv, None)
}

/// `run_elf_x86_64` に CPU モデルの選択を渡す（`--cpu` の配線）。
pub fn run_elf_x86_64_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = Linux::x86_64();
    // JIT は `POLYISA_JIT` 指定時のみ opt-in。既定はインタプリタ。
    let mut jit_owned = polyisa_jit::Jit::new();
    let jit = std::env::var_os("POLYISA_JIT").map(|_| &mut jit_owned);
    run_image_x86_64_sel(&bytes, path, argv, &mut sys, sel, jit)
}

/// ELF64 を実行し、終了コードと fd 1 の出力を返す。ホストの stdout には書かない。
pub fn run_elf_x86_64_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    run_elf_x86_64_captured_in(path, argv, &[])
}

/// 標準入力へ `stdin` を渡して ELF64 を実行し、終了コードと fd 1 の出力を返す。
pub fn run_elf_x86_64_captured_in(
    path: &str,
    argv: &[String],
    stdin: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    run_elf_x86_64_at(path, argv, stdin, None)
}

/// 作業ディレクトリを `dir` にして ELF64 を実行し、終了コードと fd 1 の出力を返す。
pub fn run_elf_x86_64_captured_dir(
    path: &str,
    argv: &[String],
    dir: &str,
) -> Result<(u64, Vec<u8>), String> {
    run_elf_x86_64_at(path, argv, &[], Some(dir))
}

/// 作業ディレクトリと標準入力を渡して ELF64 を実行する。
pub fn run_elf_x86_64_captured_dir_in(
    path: &str,
    argv: &[String],
    dir: &str,
    stdin: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    run_elf_x86_64_at(path, argv, stdin, Some(dir))
}

fn run_elf_x86_64_at(
    path: &str,
    argv: &[String],
    stdin: &[u8],
    dir: Option<&str>,
) -> Result<(u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = Linux::x86_64();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    sys.capture_out = Some(std::rc::Rc::clone(&captured));
    sys.stdin_buf = stdin.to_vec();
    if let Some(dir) = dir {
        sys.cwd = dir.to_string();
    }
    let code = run_image_x86_64(&bytes, path, argv, &mut sys)?;
    Ok((code, captured.borrow().clone()))
}

// ---- JIT（段階 9）----

/// 1 ブロックに記録する命令数の上限。x86 は 1 命令あたりの IR が
/// 重いので a64/arm より小さく取る。
const MAX_BLOCK_INSNS: usize = 16;

/// x86/x86-64 の翻訳器。`is64`/`feats`/`params` は実行と同じ
/// 設定で固定する。
pub struct X86Tx {
    pub is64: bool,
    pub feats: u128,
    pub params: polyisa_guest_x86::Params,
}

impl polyisa_jit::Translate for X86Tx {
    fn key(&self, b: &polyisa_engine::interp::InterpBackend, pc: u64) -> u64 {
        // FS/GS ベースは記録時に定数として埋め込まれるため、同じ pc でも
        // ベースが違えば別ブロックにする（syscall でしか変わらない）。
        // `get` は &mut を要るので、ここでは状態配列から直接読む。
        let at = sem::fs_base_ref().offset();
        let fs = u64::from_le_bytes(b.state[at..at + 8].try_into().unwrap_or([0; 8]));
        let at = sem::gs_base_ref().offset();
        let gs = u64::from_le_bytes(b.state[at..at + 8].try_into().unwrap_or([0; 8]));
        // 同じ Jit インスタンスを別設定で使い回してもブロックが混ざらない
        // ように、翻訳に影響する設定を全部畳む。
        pc ^ fs.rotate_left(19)
            ^ gs.rotate_left(41)
            ^ polyisa_guest_x86::params_key(&self.params)
            ^ (self.feats as u64 ^ (self.feats >> 64) as u64).rotate_left(7)
            ^ u64::from(self.is64)
    }

    fn record(
        &self,
        b: &mut polyisa_engine::interp::InterpBackend,
        entry: u64,
    ) -> Option<polyisa_ir::Recorded> {
        let mut irb = polyisa_ir::IrBackend::new();
        // 挙動パラメータは記録時に定数として読まれ、枝が畳まれる。
        polyisa_guest_x86::install_params(&mut irb, &self.params);
        let mut hist = std::collections::VecDeque::new();
        let mut pc = entry;
        for _ in 0..MAX_BLOCK_INSNS {
            let d = match decode_x86(&b.mem, pc, self.is64, self.feats, &mut hist) {
                Ok(d) => d,
                Err(_) => break,
            };
            b.mem.mark_code(VirtAddr(pc));
            // セグメントベースはゲスト状態の定数として埋め込む。変わるのは
            // トラップ経路（arch_prctl/set_thread_area）だけで、それは
            // ブロックの境界なので新しいベースで別ブロックを記録する。
            let fs = d.has_fs.then(|| b.get(sem::fs_base_ref()));
            let seg = fs.or(d.has_gs.then(|| b.get(sem::gs_base_ref())));
            irb.cur_pc = pc;
            irb.cur_next = pc + d.nbytes;
            let imm32 = || (d.word as u32).swap_bytes();
            let disp8 = || (d.word & 0xff) as u8 as i8;
            let r = dispatch(
                &mut irb, d.insn, pc as u32, d.word, d.nbytes, d.off, self.is64, d.rex, d.has66,
                d.has_f2, d.rep, seg, imm32, disp8,
            );
            match r {
                Ok(()) => {}
                Err(e) => {
                    irb.abort(e);
                    break;
                }
            }
            if irb.ir.has_flow() {
                pc += d.nbytes;
                break;
            }
            pc += d.nbytes;
        }
        if irb.ir.ops.is_empty() {
            return None;
        }
        polyisa_ir::optimize(&mut irb.ir);
        Some(polyisa_ir::Recorded {
            entry,
            fall: pc,
            ir: irb.ir,
        })
    }
}

/// `step_x86` の JIT 版。Trap（int 0x80/syscall）はインタプリタと同じく
/// `sys` へ委譲し、記録できない入口は 1 命令ぶんインタプリタで進める。
fn step_x86_jit(
    env: &mut BareEnv,
    sys: &mut dyn TrapHandler,
    jit: &mut polyisa_jit::Jit,
    is64: bool,
    feats: u128,
    params: &polyisa_guest_x86::Params,
    hist: &mut std::collections::VecDeque<(u32, String)>,
) -> Result<(), Outcome> {
    let pc = u64::from(eip_of(env));
    let tx = X86Tx {
        is64,
        feats,
        params: *params,
    };
    let Some(exit) = jit.exec_block(&mut env.backend, &tx, pc) else {
        return step_x86(env, sys, if is64 { 64 } else { 32 }, feats, hist);
    };
    let r = match exit {
        polyisa_jit::BlockExit::Next(next) => {
            env.backend.set(sem::eip_ref(), next as u32);
            env.pc = next;
            env.steps += 1;
            Ok(())
        }
        polyisa_jit::BlockExit::Raise { e, pc, next } => {
            // 例外が起きた命令に eip を合わせる（インタプリタと同じ状態）。
            env.backend.set(sem::eip_ref(), pc as u32);
            env.pc = pc;
            if e.kind == ExceptionKind::Trap {
                match sys.handle_trap(env, e.code as u32) {
                    TrapOutcome::Handled => {
                        // ハンドラが eip を動かさなければ次の命令へ進む。
                        if u64::from(eip_of(env)) == pc {
                            env.backend.set(sem::eip_ref(), next as u32);
                            env.pc = next;
                        }
                        Ok(())
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
                    TrapOutcome::Unimplemented => Err(Outcome::Unimplemented { pc, word: 0 }),
                }
            } else {
                Err(Outcome::Unimplemented { pc, word: 0 })
            }
        }
        polyisa_jit::BlockExit::Unimpl { pc } => {
            env.backend.set(sem::eip_ref(), pc as u32);
            env.pc = pc;
            Err(Outcome::Unimplemented { pc, word: 0 })
        }
    };
    if r.is_ok() {
        sys.after_step(env);
    }
    r
}

/// `run_mode_ex` の JIT 版。初期設定はインタプリタと同じ。
#[allow(clippy::too_many_arguments)]
pub fn run_mode_ex_jit(
    env: &mut BareEnv,
    entry: u32,
    sys: &mut impl TrapHandler,
    limit: u64,
    is64: bool,
    feats: u128,
    params: &polyisa_guest_x86::Params,
    jit: &mut polyisa_jit::Jit,
) -> Outcome {
    polyisa_guest_x86::install_params(&mut env.backend, params);
    env.backend.set(polyisa_guest_x86::sem::eip_ref(), entry);
    env.backend.addr_mask = if is64 { u64::MAX } else { 0xffff_ffff };
    let _ = sys.on_block(env);
    let mut hist = std::collections::VecDeque::<(u32, String)>::with_capacity(33);
    polyisa_engine::run::run(
        env,
        sys,
        limit,
        |env| u64::from(eip_of(env)),
        |env, sys| step_x86_jit(env, sys, jit, is64, feats, params, &mut hist),
    )
}

/// `run_image_x86_64_ex` の JIT 版。差分テストが使う。
pub fn run_image_x86_64_ex_jit(
    bytes: &[u8],
    prog: &str,
    argv: &[String],
    sys: &mut Linux,
    feats: u128,
    jit: &mut polyisa_jit::Jit,
) -> Result<u64, String> {
    let sel = default_sel();
    run_image_x86_64_impl(
        bytes,
        prog,
        argv,
        sys,
        feats,
        &sel.features,
        &sel.ident,
        Some(jit),
        &polyisa_guest_x86::DEFAULT_PARAMS,
        false,
    )
}

/// `run_elf_x86_64_captured` の JIT 版。
pub fn run_elf_x86_64_captured_jit(
    path: &str,
    argv: &[String],
    jit: &mut polyisa_jit::Jit,
) -> Result<(u64, Vec<u8>), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut sys = Linux::x86_64();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    sys.capture_out = Some(std::rc::Rc::clone(&captured));
    let code = run_image_x86_64_ex_jit(
        &bytes,
        path,
        argv,
        &mut sys,
        polyisa_guest_x86::DEFAULT_FEATS,
        jit,
    )?;
    Ok((code, captured.borrow().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_engine::bare::BareEnv;
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_mem::{Perms, VirtAddr};
    use polyisa_os_linux::x86::{SCHED_SLICE, data_access, get64, set64};

    fn bare() -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        env.backend.mem.map(VirtAddr(0), 2, Perms::RW).unwrap();
        env
    }

    fn push_mov_imm(code: &mut Vec<u8>, modrm: u8, imm: u32) {
        code.extend_from_slice(&[0x48, 0xC7, modrm]);
        code.extend_from_slice(&imm.to_le_bytes());
    }

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
    fn division_exception_enters_linux_signal_handler() {
        // SIGFPE ハンドラを rt_sigaction で設定し、div ecx の #DE で
        // ハンドラへ入ることを実行経路で確かめる。ハンドラは exit(42)。
        let mut sys = Linux::x86_64();
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x6000), 4, Perms::RW).unwrap();
        env.backend.set(sem::xcr0_ref(), 3);
        env.backend.set(Gpr(4).state(), 0x8000u32);
        let prog: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x0D, 0x00, 0x00, 0x00, // mov rax,13 (rt_sigaction)
            0x48, 0xC7, 0xC7, 0x08, 0x00, 0x00, 0x00, // mov rdi,8 (SIGFPE)
            0x48, 0xC7, 0xC6, 0x00, 0x18, 0x00, 0x00, // mov rsi,0x1800
            0x31, 0xD2, // xor edx,edx
            0x41, 0xC7, 0xC2, 0x08, 0x00, 0x00, 0x00, // mov r10d,8
            0x0F, 0x05, // syscall
            0x31, 0xC0, // xor eax,eax
            0x31, 0xD2, // xor edx,edx
            0x31, 0xC9, // xor ecx,ecx
            0xF7, 0xF1, // div ecx → #DE
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi,1
            0x0F, 0x05, // syscall（到達したら失敗）
        ];
        env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
        // kernel_sigaction {handler=0x1100, flags=SA_RESTORER,
        // restorer=0x1120, mask=0}。ハンドラは戻らず exit する。
        let mut act = [0u8; 32];
        act[0..8].copy_from_slice(&0x1100u64.to_le_bytes());
        act[8..16].copy_from_slice(&polyisa_os_linux::x86::SA_RESTORER.to_le_bytes());
        act[16..24].copy_from_slice(&0x1120u64.to_le_bytes());
        env.backend.mem.write(VirtAddr(0x1800), &act).unwrap();
        let handler: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
            0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00, // mov rdi,42
            0x0F, 0x05, // syscall
        ];
        env.backend.mem.write(VirtAddr(0x1100), handler).unwrap();
        let out = run_mode(&mut env, 0x1000, &mut sys, 200, true);
        assert_eq!(out, Outcome::Exit(42));
    }

    #[test]
    fn fs_relative_mov_sibabs() {
        // FS 上書き + REX.W 8B SIB直接番地 (MOV RDX,FS:[disp32]) を run する。
        // FS 絶対番地のため disp=target-fs_base=0x500 (RIP相対ではない)。
        // fs_base=0x1000、disp=0x500 で [0x1500] を読み、exit(低32)。
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.set(sem::fs_base_ref(), 0x1000);
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
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.set(sem::fs_base_ref(), 0x1000);
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
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.set(sem::fs_base_ref(), 0x1000);
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
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.set(sem::fs_base_ref(), 0x1000);
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
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.set(sem::fs_base_ref(), 0x1000);
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
        let mut sys = Linux::x86_64();
        let mut env = bare();
        env.backend.set(sem::fs_base_ref(), 0x1000);
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
    fn parent_sets_child_group_before_the_slice_ends() {
        let mut sys = Linux::x86_64();
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
        let mut sys = Linux::x86_64();
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
    fn child_runs_across_a_step_slice_before_wait() {
        let mut sys = Linux::x86_64();
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
        let mut sys = Linux::x86_64();
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

        let mut sys = Linux::x86_64();
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

    #[test]
    fn wait4_wnohang_leaves_child_then_reaps() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = Linux::x86_64();
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
    fn child_blocks_on_pipe_until_parent_writes() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = Linux::x86_64();
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
        assert_eq!(out, Outcome::Exit(u64::from(b'A')));
    }

    #[test]
    fn wait_and_empty_read_stop_as_deadlock() {
        use polyisa_os_linux::x86_64 as abi;
        let mut sys = Linux::x86_64();
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
        let mut sys = Linux::x86_64();
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
    /// 差分テスト用の環境。コードは 0x1000（RWX）、データ/スタックは
    /// 0x4000 から 8 ページ。レジスタはデータ領域を指す値で埋める。
    fn diff_env(code: &[u8]) -> BareEnv {
        let mut env = bare();
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x4000), 8, Perms::RW).unwrap();
        let pat: Vec<u8> = (0..0x8000usize)
            .map(|i| ((i * 31 + 7) & 0xff) as u8)
            .collect();
        env.backend.mem.write(VirtAddr(0x4000), &pat).unwrap();
        env.backend.mem.write(VirtAddr(0x1000), code).unwrap();
        for r in 0..16u8 {
            let v = 0x4010u64 + u64::from(r) * 0x111;
            sem::write64(&mut env.backend, Gpr(r), v);
        }
        // rsp はデータ領域の中ほどへ。
        sem::write64(&mut env.backend, Gpr(4), 0x7000);
        env.backend.set(sem::eflags_ref(), 0x202);
        env.backend.set(sem::eip_ref(), 0x1000);
        env
    }

    /// 全状態の差分を文字列で返す（一致なら None）。
    fn diff_state(a: &mut BareEnv, b: &mut BareEnv) -> Option<String> {
        let mut diffs = Vec::new();
        if a.pc != b.pc {
            diffs.push(format!("pc {:#x} vs {:#x}", a.pc, b.pc));
        }
        let (ea, eb) = (eip_of(a), eip_of(b));
        if ea != eb {
            diffs.push(format!("eip {ea:#x} vs {eb:#x}"));
        }
        for r in 0..16u8 {
            let va = sem::read64(&mut a.backend, Gpr(r));
            let vb = sem::read64(&mut b.backend, Gpr(r));
            if va != vb {
                diffs.push(format!("r{r} {va:#x} vs {vb:#x}"));
            }
        }
        let fa = a.backend.get(sem::eflags_ref());
        let fb = b.backend.get(sem::eflags_ref());
        if fa != fb {
            diffs.push(format!("eflags {fa:#x} vs {fb:#x}"));
        }
        let mut ma = vec![0u8; 0x8000];
        let mut mb = vec![0u8; 0x8000];
        a.backend
            .mem
            .read(VirtAddr(0x4000), &mut ma, data_access())
            .unwrap();
        b.backend
            .mem
            .read(VirtAddr(0x4000), &mut mb, data_access())
            .unwrap();
        if ma != mb {
            let k = ma.iter().zip(&mb).position(|(x, y)| x != y).unwrap();
            diffs.push(format!("mem[{k:#x}] {:#x} vs {:#x}", ma[k], mb[k]));
        }
        (!diffs.is_empty()).then(|| diffs.join("; "))
    }

    /// 1 命令差分の分類。
    #[derive(Debug)]
    enum DiffKind {
        /// 両経路で状態一致。
        Same,
        /// map が実行成功、列挙経路は未対応（カバレッジ拡大。差分ではない）。
        MapOnly,
        /// 列挙経路は実行成功、map が失敗（回帰）。
        Regress(String),
        /// 両方失敗だが内容が違う。
        ExitDiff(String),
        /// 両方成功だが状態が違う。
        StateDiff(String),
    }

    /// `code`（15バイト）を map 経路と列挙経路で 1 命令だけ実行して比較。
    /// None: map が扱わず列挙経路へ落ちる（スキップ）。
    fn diff_one(code: &[u8], is64: bool) -> Option<DiffKind> {
        let mut a = diff_env(code);
        let mut b = diff_env(code);
        let mut sa = Linux::x86_64();
        let mut sb = Linux::x86_64();
        let mut h = std::collections::VecDeque::new();
        let ra = step_x86_legacy(&mut a, &mut sa, is64, 0, &mut h);
        let mut h = std::collections::VecDeque::new();
        let rb = step_x86_map(&mut b, &mut sb, if is64 { 64 } else { 32 }, 0, &mut h)?;
        Some(match (&ra, &rb) {
            (Ok(()), Ok(())) => match diff_state(&mut a, &mut b) {
                Some(d) => DiffKind::StateDiff(d),
                None => DiffKind::Same,
            },
            (Err(_), Ok(())) => DiffKind::MapOnly,
            (Ok(()), Err(y)) => DiffKind::Regress(format!("map failed: {y:?}")),
            (Err(x), Err(y)) => {
                // 両方 Unimplemented なら失敗は同等（word の報告形式は経路で異なる）。
                let unimp = |e: &Outcome| matches!(e, Outcome::Unimplemented { .. });
                if format!("{x:?}") == format!("{y:?}") || (unimp(x) && unimp(y)) {
                    DiffKind::Same
                } else {
                    DiffKind::ExitDiff(format!("outcome {x:?} vs {y:?}"))
                }
            }
        })
    }

    /// 被演算子バイトのバリエーション。modrm（+SIB）と後続 8 バイトの組。
    fn modrm_cases() -> Vec<Vec<u8>> {
        let tail: &[u8] = &[0x10, 0x00, 0x00, 0x00, 0x5a, 0xa5, 0x11, 0x22];
        let mut v = Vec::new();
        // mod=11（レジスタ直接）: reg/rm 総当たりの抜粋
        for reg in [0u8, 1, 3, 7] {
            for rm in [0u8, 1, 3, 4, 5, 6, 7] {
                let mut c = vec![0xC0 | (reg << 3) | rm];
                c.extend_from_slice(tail);
                v.push(c);
            }
        }
        // mod=00: [reg], SIB, disp32
        for rm in [0u8, 1, 2, 3, 6, 7] {
            let mut c = vec![rm];
            c.extend_from_slice(tail);
            v.push(c);
        }
        // RIP 相対 / disp32
        let mut c = vec![0x05];
        c.extend_from_slice(tail);
        v.push(c);
        // SIB: [rax], [rax+rcx*2], baseなし disp32, [rsp]
        for sib in [0x00u8, 0x48, 0x05, 0x24, 0x84, 0x65, 0x94] {
            let mut c = vec![0x04, sib];
            c.extend_from_slice(tail);
            v.push(c);
        }
        // mod=01 disp8 / mod=10 disp32（reg=0 と reg=5）
        for m in [0x40u8, 0x45, 0x68, 0x80, 0x85, 0xA8] {
            let mut c = vec![m];
            c.extend_from_slice(tail);
            v.push(c);
        }
        v
    }

    /// map 経路と列挙経路で 1 命令ずつ実行し、状態が異なる組合せを報告する。
    /// 段階13の移行カバレッジを兼ねる回帰基盤。残差分は列挙経路側の
    /// 既知の近似（接頭辞の長・disp32 無視・16ビット上位クリア等）なので
    /// 診断専用とし、`cargo test -- --ignored` で実行する。
    #[test]
    #[ignore = "diagnostic"]
    fn map_path_matches_legacy_smoke() {
        let prefixes: &[&[u8]] = &[&[], &[0x48], &[0x44], &[0x41], &[0x4f], &[0x66], &[0xf3]];
        let cases = modrm_cases();
        let mut diffs: Vec<(String, String)> = Vec::new();
        let mut handled = 0usize;
        for op in 0u16..=0x1ff {
            let opb: Vec<u8> = if op < 0x100 {
                vec![op as u8]
            } else {
                vec![0x0f, (op & 0xff) as u8]
            };
            for p in prefixes {
                for c in &cases {
                    let mut code = Vec::with_capacity(16);
                    code.extend_from_slice(p);
                    code.extend_from_slice(&opb);
                    code.extend_from_slice(c);
                    code.resize(15, 0x90);
                    match diff_one(&code, true) {
                        Some(DiffKind::StateDiff(d))
                        | Some(DiffKind::Regress(d))
                        | Some(DiffKind::ExitDiff(d)) => {
                            handled += 1;
                            let key = format!(
                                "{:02x?}:{}",
                                &code[..3.min(code.len())],
                                d.split_whitespace().next().unwrap_or("")
                            );
                            diffs.push((key, format!("{:02x?}: {d}", &code[..8.min(code.len())])));
                        }
                        Some(DiffKind::Same) | Some(DiffKind::MapOnly) => handled += 1,
                        None => {}
                    }
                }
            }
        }
        // 差分の要約を出して失敗させる。集計は命令の先頭と差分種別で。
        let n = diffs.len();
        let mut by_head: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for (k, _) in &diffs {
            *by_head.entry(k.clone()).or_default() += 1;
        }
        let mut tops: Vec<_> = by_head.iter().collect();
        tops.sort_by_key(|(_, c)| core::cmp::Reverse(*c));
        let report = tops
            .iter()
            .take(400)
            .map(|(k, c)| {
                let ex = diffs.iter().find(|(dk, _)| dk == *k).unwrap();
                format!("x{c} {k} e.g. {}", ex.1)
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(diffs.is_empty(), "{n} diffs / {handled} handled\n{report}");
    }

    #[test]
    fn map_decode_probe() {
        let modes = polyisa_guest_x86::MODE_M64
            | (polyisa_guest_x86::MODE_OPD_O32 << polyisa_guest_x86::MODE_OPD_SHIFT)
            | (polyisa_guest_x86::MODE_ADR_A64 << polyisa_guest_x86::MODE_ADR_SHIFT);
        for code in [
            &[0x48, 0x8b, 0x7f, 0xf0][..],
            &[0x48, 0x89, 0xd7][..],
            &[0x50][..],
            &[0xe8, 0x10, 0, 0, 0][..],
            &[0x74, 0x05][..],
            &[0xc3][..],
            &[0x0f, 0x05][..],
        ] {
            let d = polyisa_guest_x86::decode_map(code, modes, polyisa_guest_x86::DEFAULT_FEATS);
            eprintln!("{code:02x?} -> {d:?}");
        }
    }

    /// busybox のような実 ELF を指定ステップ数だけ実行し、各ステップ後の
    /// (eip, GPR, eflags) を記録する。map 経路と列挙経路の最初の分岐点を
    /// 見つけるための診断基盤。
    fn trace_prog(
        bytes: &[u8],
        prog: &str,
        argv: &[String],
        use_map: bool,
        limit: usize,
    ) -> (Vec<(u32, [u64; 16], u32)>, String) {
        use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
        let ehdr = polyisa_loader::elf::parse_ehdr(bytes).unwrap();
        let phdrs = polyisa_loader::elf::parse_phdrs(bytes, &ehdr).unwrap();
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_x86::CpuState>());
        polyisa_loader::elf::load_segments(bytes, &phdrs, &mut env.backend.mem).unwrap();
        let mut sys = Linux::x86_64();
        let mut image_end = 0u64;
        for ph in &phdrs {
            if ph.seg_type == 1 {
                image_end = image_end.max(ph.vaddr.saturating_add(ph.memsz));
            }
        }
        sys.init_brk(image_end);
        sys.exe_path = prog.to_string();
        let top = 0x7fff_0000u64;
        let mut arg_bytes = vec![prog.as_bytes().to_vec()];
        for a in argv {
            arg_bytes.push(a.as_bytes().to_vec());
        }
        let (img, sp) = polyisa_os_linux::build_initial_stack(top, &arg_bytes, &[], &[(6, 0x1000)]);
        const STACK_SIZE: u64 = 8 * 1024 * 1024;
        let base = top - STACK_SIZE;
        let end = top.next_multiple_of(PAGE_SIZE);
        env.backend
            .mem
            .map(
                VirtAddr(base),
                (end - base) / PAGE_SIZE,
                Perms(Perms::R.0 | Perms::W.0),
            )
            .unwrap();
        env.backend.mem.write(VirtAddr(sp), &img).unwrap();
        sem::write64(&mut env.backend, Gpr(4), sp);
        env.backend.set(sem::fcw_ref(), 0x037F);
        env.backend.set(sem::mxcsr_ref(), 0x1F80);
        // OSXSAVE=1 を報告するので XCR0 は OS が x87+SSE を有効化した
        // 後の 3 で始める（実機のリセット値は 1）。
        env.backend.set(sem::xcr0_ref(), 3);
        // XCOMP の対応・許可マスク（既定モデル = amx_tile なしの 3）。
        env.backend.set(sem::xcomp_supp_ref(), 3);
        env.backend.set(sem::xcomp_perm_ref(), 3);
        env.backend.set(sem::eip_ref(), ehdr.entry as u32);
        env.backend.addr_mask = u64::MAX;
        let _ = sys.on_block(&mut env);
        let mut rec = Vec::new();
        let mut last = String::new();
        for _ in 0..limit {
            let mut h = std::collections::VecDeque::new();
            let r = if use_map {
                match step_x86_map(&mut env, &mut sys, 64, 0, &mut h) {
                    Some(r) => r,
                    None => {
                        let mut h = std::collections::VecDeque::new();
                        step_x86_legacy(&mut env, &mut sys, true, 0, &mut h)
                    }
                }
            } else {
                step_x86_legacy(&mut env, &mut sys, true, 0, &mut h)
            };
            let mut g = [0u64; 16];
            for (i, x) in g.iter_mut().enumerate() {
                *x = sem::read64(&mut env.backend, Gpr(i as u8));
            }
            rec.push((eip_of(&mut env), g, env.backend.get(sem::eflags_ref())));
            if let Err(o) = r {
                last = format!("{o:?}");
                break;
            }
        }
        (rec, last)
    }

    /// 実バイナリの両経路トレースを比較し、最初の分岐を報告する。
    /// POLYISA_BB でバイナリを指定する。診断専用。
    #[test]
    #[ignore = "diagnostic"]
    fn trace_first_divergence() {
        let Some(path) = std::env::var_os("POLYISA_BB") else {
            return;
        };
        let path = path.to_string_lossy().into_owned();
        let bytes = std::fs::read(&path).unwrap();
        let argv: Vec<String> = std::env::var("POLYISA_ARGV")
            .unwrap_or_else(|_| "seq\n1\n3".into())
            .split('\n')
            .map(String::from)
            .collect();
        let limit = 200_000;
        let (a, ea) = trace_prog(&bytes, &path, &argv, false, limit);
        let (b, eb) = trace_prog(&bytes, &path, &argv, true, limit);
        eprintln!("legacy steps={} end={}", a.len(), ea);
        eprintln!("map    steps={} end={}", b.len(), eb);
        for (i, (x, y)) in a.iter().zip(&b).enumerate() {
            if x != y {
                eprintln!("first divergence at step {i}:");
                eprintln!("  legacy eip={:#x} eflags={:#x}", x.0, x.2);
                eprintln!("  map    eip={:#x} eflags={:#x}", y.0, y.2);
                for r in 0..16 {
                    if x.1[r] != y.1[r] {
                        eprintln!("    r{r}: {:#x} vs {:#x}", x.1[r], y.1[r]);
                    }
                }
                // 前のステップの eip が分岐の原因命令。
                if i > 0 {
                    eprintln!("  prev eip={:#x}", a[i - 1].0);
                }
                return;
            }
        }
        eprintln!("no divergence in {} steps", a.len().min(b.len()));
    }

    #[test]
    fn diff_probe_shr() {
        for code in [
            &[0x48, 0x83, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00][..],
            &[0x48, 0xff, 0x00, 0x10, 0x00, 0x00, 0x00, 0x5a][..],
            &[0x48, 0x11, 0x40, 0x10, 0x00, 0x00, 0x00, 0x5a][..],
            &[0x4f, 0xd1, 0xc9, 0x10, 0x00, 0x00, 0x00, 0x5a][..],
            &[0x0f, 0xb1, 0xd8, 0x10, 0x00, 0x00, 0x00, 0x5a][..],
            &[0x0f, 0xb1, 0x18, 0x10, 0x00, 0x00, 0x00, 0x5a][..],
            &[0x5a][..],
        ] {
            let mut c = code.to_vec();
            c.resize(15, 0x90);
            eprintln!("{code:02x?} -> {:?}", diff_one(&c, true));
        }
    }

    #[test]
    fn diff_probe_ah() {
        let mut a = diff_env(&[0x80, 0xcc, 0x0c]);
        let mut b = diff_env(&[0x80, 0xcc, 0x0c]);
        // rax = 0x837f (AH=0x83)
        sem::write64(&mut a.backend, Gpr(0), 0x837f);
        sem::write64(&mut b.backend, Gpr(0), 0x837f);
        let mut sa = Linux::x86_64();
        let mut sb = Linux::x86_64();
        let mut h = std::collections::VecDeque::new();
        let ra = step_x86_legacy(&mut a, &mut sa, true, 0, &mut h);
        let mut h = std::collections::VecDeque::new();
        let rb = step_x86_map(&mut b, &mut sb, 64, 0, &mut h);
        eprintln!(
            "legacy: {:?} rax={:#x} eflags={:#x}",
            ra.is_ok(),
            sem::read64(&mut a.backend, Gpr(0)),
            a.backend.get(sem::eflags_ref())
        );
        eprintln!(
            "map   : {:?} rax={:#x} eflags={:#x}",
            rb.map(|r| r.is_ok()),
            sem::read64(&mut b.backend, Gpr(0)),
            b.backend.get(sem::eflags_ref())
        );
    }

    #[test]
    fn map_probe_80() {
        let modes = polyisa_guest_x86::MODE_M64
            | (polyisa_guest_x86::MODE_OPD_O32 << polyisa_guest_x86::MODE_OPD_SHIFT)
            | (polyisa_guest_x86::MODE_ADR_A64 << polyisa_guest_x86::MODE_ADR_SHIFT);
        let d = polyisa_guest_x86::decode_map(
            &[0x80, 0xcc, 0x0c],
            modes,
            polyisa_guest_x86::DEFAULT_FEATS,
        );
        eprintln!("{d:?}");
    }
}
