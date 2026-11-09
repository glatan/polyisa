// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! x86 実行ループの結合テスト。手組みのバイト列をゲストメモリに置き、
//! フェッチ・デコード・ディスパッチ・eip 進行・トラップ退出を確かめる。

use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_x86::CpuState;
use polyisa_guest_x86::sem::Gpr;
use polyisa_mem::{Perms, VirtAddr};
use polyisa_sem::Backend as _;

/// `exit(ebx)` だけ処理する。番号は EAX、引数は EBX から読む。
struct ExitOne;

impl TrapHandler for ExitOne {
    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let nr: u32 = env.backend.get(Gpr(0).state());
        if nr == 1 {
            let code: u32 = env.backend.get(Gpr(3).state());
            TrapOutcome::Exit(code)
        } else {
            TrapOutcome::Unimplemented
        }
    }
}

#[test]
fn run_add_and_exit() {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    // コード頁（RWX）とスタック頁（RW）を写像する。
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    // mov eax,5; push eax; mov eax,6; pop ecx; add eax,ecx (=11);
    // push eax; pop ebx; mov eax,1; int 0x80 (=exit(11))。
    let prog: &[u8] = &[
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax,5
        0x50, // push eax
        0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax,6
        0x59, // pop ecx
        0x01, 0xC8, // add eax,ecx
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let out = run_x86::run(&mut env, 0x1000, &mut ExitOne, 1000);
    assert_eq!(out, Outcome::Exit(11));
}

#[test]
fn self_loop_hits_step_limit_without_advancing() {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    // JMP rel8 -2：自分自身に飛ぶ。taken でも eip は進まない。
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xEB, 0xFE])
        .unwrap();
    let out = run_x86::run(&mut env, 0x1000, &mut ExitOne, 100);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1000 });
}

#[test]
fn run_lea_and_logic_branch() {
    // LEA/AND/OR/CMP/JE を run 経由で回し、taken で exit(48) する。
    // 0x1000: B8 10 00 00 00  mov eax,0x10
    // 0x1005: 50             push eax
    // 0x1006: 59             pop ecx
    // 0x1007: 53             push ebx
    // 0x1008: 5B             pop ebx (placeholder, replaced below)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x100);
    let prog: &[u8] = &[
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax,0x10
        0x50, // push eax
        0x59, // pop ecx (ecx=0x10)
        0x53, // push ebx (ebx=0x100)
        0x5B, // pop ebx
        0x8D, 0x43, 0x20, // lea eax,[ebx+0x20] (eax=0x120)
        0x21, 0xC8, // and eax,ecx (eax=0x10)
        0x09, 0xC8, // or eax,ecx (eax=0x10)
        0x39, 0xC8, // cmp eax,ecx (ZF=1)
        0x74, 0x05, // je +5 -> 0x101a
        0xB8, 0x63, 0x00, 0x00, 0x00, // mov eax,99 (skipped)
        0x50, // push eax (eax=0x10)
        0x5B, // pop ebx (ebx=0x10)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(0x10)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x10));
}

#[test]
fn run_sib_load_store() {
    // SIB base+index 形式を run 経由で回し、exit コードで値を検証する。
    // ebx=0x1500、esi=0x20 を置き、mov [ebx+esi],eax で [0x1520] に書き、
    // mov eax,[ebx+esi] で読み戻して exit コードにする。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x1500)
        0xB8, 0x20, 0x00, 0x00, 0x00, // mov eax,0x20
        0x50, // push eax
        0x5E, // pop esi (esi=0x20)
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x04, 0x33, // mov [ebx+esi],eax ([0x1520]=0x77)
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x04, 0x33, // mov eax,[ebx+esi] (eax=0x77)
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x77)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_sib_disp8() {
    // run 経由で SIB+disp8 形式を回す。exit コードで検証する。
    // mov eax,0x1500; push eax; pop ebx (ebx=0x1500);
    // mov eax,0x20; push eax; pop esi (esi=0x20);
    // mov eax,0x77; mov [ebx+esi+0x10],eax ([0x1530]=0x77);
    // mov eax,0; mov eax,[ebx+esi+0x10] (eax=0x77);
    // push eax; pop ebx; mov eax,1; int 0x80 -> exit(0x77)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0x20, 0x00, 0x00, 0x00, // mov eax,0x20
        0x50, // push eax
        0x5E, // pop esi
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x44, 0x33, 0x10, // mov [ebx+esi+0x10],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x44, 0x33, 0x10, // mov eax,[ebx+esi+0x10]
        0x50, // push eax
        0x5B, // pop ebx
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}
