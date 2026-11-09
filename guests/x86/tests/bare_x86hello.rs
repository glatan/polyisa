// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 ユーザーモード実行の結合テスト。手組みの ELF32 静的バイナリを
//! ローダで読み、実行ループで回し、write/exit_group を検証する。
//! ELF32 の配置は SPEC-ELF-GABI、番号は i386 UAPI の事実を使う。
//! Ref: SPEC-ELF-GABI (Edition 4.1).
//! Ref: SRC-LINUX (7.3).

use polyisa_cli::run_x86::{self, TrapHandler, TrapOutcome};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::sem::Gpr;
use polyisa_sem::Backend as _;

/// write(1/2) を取り込み、exit/exit_group で抜けるハンドラ。
struct Capture {
    out: Vec<u8>,
}

impl TrapHandler for Capture {
    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let nr = env.backend.get(Gpr(0).state()) as u64;
        if nr == polyisa_os_linux::i386::WRITE {
            let fd: u32 = env.backend.get(Gpr(3).state());
            if fd != 1 && fd != 2 {
                return TrapOutcome::Unimplemented;
            }
            let buf = env.backend.get(Gpr(1).state()) as u64;
            let len = env.backend.get(Gpr(2).state()) as usize;
            let mut data = vec![0u8; len];
            let acc = polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            };
            if env
                .backend
                .mem
                .read(polyisa_mem::VirtAddr(buf), &mut data, acc)
                .is_err()
            {
                return TrapOutcome::Unimplemented;
            }
            self.out.extend_from_slice(&data);
            env.backend.set(Gpr(0).state(), len as u32);
            return TrapOutcome::Handled;
        }
        if nr == polyisa_os_linux::i386::EXIT || nr == polyisa_os_linux::i386::EXIT_GROUP {
            return TrapOutcome::Exit(env.backend.get(Gpr(3).state()));
        }
        TrapOutcome::Unimplemented
    }
}

/// 最小の ELF32 静的バイナリを組み立てる。
/// write(1, msg, 13) して exit_group(0) する。
fn hello_elf() -> Vec<u8> {
    // write(1, msg, 13) して exit_group(0) する。EAX は直前に番号を置き直す。
    let code: &[u8] = &[
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0x27, 0x00, 0x01, 0x00, // mov eax,0x10027
        0x50, // push eax
        0x59, // pop ecx
        0xB8, 0x0D, 0x00, 0x00, 0x00, // mov eax,13
        0x50, // push eax
        0x5A, // pop edx
        0xB8, 0x04, 0x00, 0x00, 0x00, // mov eax,4 (write)
        0xCD, 0x80, // int 0x80
        0x31, 0xC0, // xor eax,eax
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0xFC, 0x00, 0x00, 0x00, // mov eax,252
        0xCD, 0x80, // int 0x80
    ];
    let msg = b"Hello, poly!\n";
    assert_eq!(code.len(), 0x27);
    let mut f = Vec::new();
    // ELF32 ヘッダ（52バイト）。
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0]);
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&2u16.to_le_bytes()); // EXEC
    f.extend_from_slice(&3u16.to_le_bytes()); // EM_386
    f.extend_from_slice(&1u32.to_le_bytes()); // version
    f.extend_from_slice(&0x10000u32.to_le_bytes()); // entry
    f.extend_from_slice(&52u32.to_le_bytes()); // phoff
    f.extend_from_slice(&0u32.to_le_bytes()); // shoff
    f.extend_from_slice(&0u32.to_le_bytes()); // flags
    f.extend_from_slice(&52u16.to_le_bytes()); // ehsize
    f.extend_from_slice(&32u16.to_le_bytes()); // phentsize
    f.extend_from_slice(&1u16.to_le_bytes()); // phnum
    f.extend_from_slice(&0u16.to_le_bytes()); // shentsize
    f.extend_from_slice(&0u16.to_le_bytes()); // shnum
    f.extend_from_slice(&0u16.to_le_bytes()); // shstrndx
    assert_eq!(f.len(), 52);
    // プログラムヘッダ（32バイト）。
    let seg_len = (code.len() + msg.len()) as u32;
    f.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    f.extend_from_slice(&84u32.to_le_bytes()); // offset
    f.extend_from_slice(&0x10000u32.to_le_bytes()); // vaddr
    f.extend_from_slice(&0x10000u32.to_le_bytes()); // paddr
    f.extend_from_slice(&seg_len.to_le_bytes()); // filesz
    f.extend_from_slice(&seg_len.to_le_bytes()); // memsz
    f.extend_from_slice(&5u32.to_le_bytes()); // R+X
    f.extend_from_slice(&0x1000u32.to_le_bytes()); // align
    assert_eq!(f.len(), 84);
    f.extend_from_slice(code);
    f.extend_from_slice(msg);
    f
}

#[test]
fn hello_exits_zero_with_output() {
    let img = hello_elf();
    let mut sys = Capture { out: Vec::new() };
    let r = run_x86::run_image_x86(&img, "hello", &[], &mut sys);
    assert_eq!(r, Ok(0));
    assert_eq!(sys.out, b"Hello, poly!\n");
}

#[test]
fn rejects_non_386() {
    let mut img = hello_elf();
    // e_machine を RISC-V (243) に書き換える。
    img[18] = 243;
    img[19] = 0;
    let mut sys = Capture { out: Vec::new() };
    let r = run_x86::run_image_x86(&img, "hello", &[], &mut sys);
    assert!(r.is_err());
}
