// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 ファイル入出力の結合テスト。手組みの命令列で openat/read/write を回す.
//!
//! 番号表は 32ビット Linux（i386 ABI）の UAPI 由来の事実であり、自前の表現で書く。
//! Ref: SRC-LINUX (7.3).

use polyisa_cli::run_x86::{self, TrapHandler, TrapOutcome};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::CpuState;
use polyisa_guest_x86::sem::Gpr;
use polyisa_mem::{Perms, VirtAddr};
use polyisa_sem::Backend as _;

/// 標準出力だけを取り込む Linux の包み。openat/read/close/exit の
/// 実装自体は本番の `Linux` を使い、テストでは出力を検査する。
struct FileCat {
    inner: polyisa_os_linux::x86::Linux,
    out: Vec<u8>,
}

impl TrapHandler for FileCat {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        use polyisa_os_linux::x86_32;
        let nr: u64 = env.backend.get(Gpr(0).state()) as u64;
        if nr == x86_32::WRITE && env.backend.get(Gpr(3).state()) == 1 {
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
            self.out.extend_from_slice(&data);
            env.backend.set(Gpr(0).state(), len as u32);
            return TrapOutcome::Handled;
        }
        self.inner.handle_trap(env, code)
    }
}

/// openat→read→write→exit する命令列を実行し、ファイル内容が通ることを確かめる。
#[test]
fn cat_file_through_guest() {
    let mut input_path = std::env::temp_dir();
    input_path.push(format!("polyisa-cat-in-{}", std::process::id()));
    let content = b"Hello from host file!\nSecond line.\n";
    std::fs::write(&input_path, content).unwrap();
    let path_str = input_path.to_string_lossy().into_owned();
    assert!(path_str.len() < 0x100);

    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x3000);
    // path 文字列と読み出し先を置く。
    env.backend
        .mem
        .write(VirtAddr(0x1200), path_str.as_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1200 + path_str.len() as u64), &[0])
        .unwrap();
    // openat(-100, path, 0, 0); read(fd, buf, 64); write(1, buf, n); exit(0)。
    let prog: &[u8] = &[
        0xB8, 0x9C, 0xFF, 0xFF, 0xFF, // mov eax,-100
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0x00, 0x12, 0x00, 0x00, // mov eax,0x1200
        0x50, // push eax
        0x59, // pop ecx
        0x31, 0xC0, // xor eax,eax
        0x50, // push eax
        0x5A, // pop edx
        0x50, // push eax
        0x5E, // pop esi
        0xB8, 0x27, 0x01, 0x00, 0x00, // mov eax,295 (openat)
        0xCD, 0x80, // int 0x80
        0x50, // push eax
        0x5B, // pop ebx (ebx=fd)
        0xB8, 0x00, 0x13, 0x00, 0x00, // mov eax,0x1300 (buf)
        0x50, // push eax
        0x59, // pop ecx
        0xB8, 0x40, 0x00, 0x00, 0x00, // mov eax,64
        0x50, // push eax
        0x5A, // pop edx
        0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax,3 (read)
        0xCD, 0x80, // int 0x80
        0x50, // push eax
        0x5A, // pop edx (edx=n)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x50, // push eax
        0x5B, // pop ebx (ebx=1)
        0xB8, 0x04, 0x00, 0x00, 0x00, // mov eax,4 (write)
        0xCD, 0x80, // int 0x80
        0x31, 0xC0, // xor eax,eax
        0x50, // push eax
        0x5B, // pop ebx (ebx=0)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = FileCat {
        inner: polyisa_os_linux::x86::Linux::default(),
        out: Vec::new(),
    };
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 1000);
    let _ = std::fs::remove_file(&input_path);
    assert_eq!(out, run_x86::Outcome::Exit(0));
    assert_eq!(sys.out, content);
}
