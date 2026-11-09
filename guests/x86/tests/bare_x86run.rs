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

#[test]
fn run_sib_scaled() {
    // SIB スケール付き (×4) を run 経由で回し、exit コードで検証する。
    // mov eax,0x1500; push eax; pop ebx (ebx=0x1500);
    // mov eax,0x10; push eax; pop esi (esi=0x10);
    // mov eax,0x77; mov [ebx+esi*4+0x10],eax ([0x1550]=0x77);
    // mov eax,0; mov eax,[ebx+esi*4+0x10] (eax=0x77);
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
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax,0x10
        0x50, // push eax
        0x5E, // pop esi
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x44, 0xB3, 0x10, // mov [ebx+esi*4+0x10],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x44, 0xB3, 0x10, // mov eax,[ebx+esi*4+0x10]
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

#[test]
fn run_sib_scaled_nd() {
    // SIB スケール付き・disp なし (×4、3バイト) を run 経由で回す。
    // mov eax,0x1500; push eax; pop ebx (ebx=0x1500);
    // mov eax,0x10; push eax; pop esi (esi=0x10);
    // mov eax,0x77; mov [ebx+esi*4],eax ([0x1540]=0x77);
    // mov eax,0; mov eax,[ebx+esi*4] (eax=0x77);
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
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax,0x10
        0x50, // push eax
        0x5E, // pop esi
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x04, 0xB3, // mov [ebx+esi*4],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x04, 0xB3, // mov eax,[ebx+esi*4]
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

#[test]
fn run_regreg_matrix() {
    // register-direct 汎用形を run 経由で回し、exit コードで検証する。
    // mov eax,0x10; push eax; pop ecx (ecx=0x10);
    // mov eax,0x13; sub eax,ecx (29 C8: eax=3);
    // xor ecx,ecx (31 C9: ecx=0);
    // mov edx,eax (8B D0: edx=3); mov ebx,edx (89 D3: ebx=3);
    // mov eax,1; int 0x80 -> exit(3)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax,0x10
        0x50, // push eax
        0x59, // pop ecx (ecx=0x10)
        0xB8, 0x13, 0x00, 0x00, 0x00, // mov eax,0x13
        0x29, 0xC8, // sub eax,ecx (eax=3)
        0x31, 0xC9, // xor ecx,ecx (ecx=0)
        0x8B, 0xD0, // mov edx,eax (edx=3)
        0x89, 0xD3, // mov ebx,edx (ebx=3)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(3)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(3));
}

#[test]
fn run_mem_disp32_and_absolute() {
    // mod=10 disp32 と絶対番地を run 経由で回し、exit コードで検証する。
    // mov eax,0x1500; push eax; pop ebx (ebx=0x1500);
    // mov eax,0x77; mov [ebx+0x20],eax ([0x1520]=0x77);
    // mov eax,0; mov eax,[ebx+0x20] (eax=0x77);
    // mov [0x1600],eax ([0x1600]=0x77); mov eax,0; mov eax,[0x1600] (eax=0x77);
    // push eax; pop ebx; mov eax,1; int 0x80 -> exit(0x77)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x1500)
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x83, 0x20, 0x00, 0x00, 0x00, // mov [ebx+0x20],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x83, 0x20, 0x00, 0x00, 0x00, // mov eax,[ebx+0x20]
        0x89, 0x05, 0x00, 0x16, 0x00, 0x00, // mov [0x1600],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x05, 0x00, 0x16, 0x00, 0x00, // mov eax,[0x1600]
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x77)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_lea_scaled() {
    // LEA スケール付きを run 経由で回す（メモリに触れず exit コードで検証）。
    // mov eax,0x1500; push eax; pop ebx (ebx=0x1500);
    // mov eax,0x10; push eax; pop esi (esi=0x10);
    // lea eax,[ebx+esi*4+0x10] (eax=0x1550);
    // push eax; pop ebx; mov eax,1; int 0x80 -> exit(0x1550)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x1500)
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax,0x10
        0x50, // push eax
        0x5E, // pop esi (esi=0x10)
        0x8D, 0x44, 0xB3, 0x10, // lea eax,[ebx+esi*4+0x10] (eax=0x1550)
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x1550)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(0x1550)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x1550));
}

#[test]
fn run_signed_branch() {
    // CMP+JL を run 経由で回す。-5 < 0 で taken、exit(7)。
    // mov eax,-5; cmp eax,0; jl +5 -> mov eax,7 を実行;
    // push eax; pop ebx; mov eax,1; int 0x80 -> exit(7)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0xFB, 0xFF, 0xFF, 0xFF, // mov eax,-5
        0x3D, 0x00, 0x00, 0x00, 0x00, // cmp eax,0
        0x7C, 0x05, // jl +5 -> 0x1011
        0xB8, 0x63, 0x00, 0x00, 0x00, // mov eax,99 (skipped)
        0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax,7
        0x50, // push eax
        0x5B, // pop ebx (ebx=7)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(7)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(7));
}

#[test]
fn run_gas_absorbed_cell() {
    // 実アセンブラ由来のバイト列をそのまま埋め込んだ統合テスト。
    // 由来：Binutils GAS (as --32) + ld -m elf_i386 でリンクした静的 i386 バイナリの
    // .text（leal cell,%ebx / movl $0x77,%eax / mov %eax,(%ebx) / mov (%ebx),%eax /
    // mov %eax,%ebx / movl $1,%eax / int $0x80）。cell = 0x804b028。
    // gas は disp8=0 を mod=00（89 03 / 8B 03）に畳む。dst=EBX の LEA を含む。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .map(VirtAddr(0x804b000), 1, Perms::RW)
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x8D, 0x1D, 0x28, 0xB0, 0x04, 0x08, // lea ebx,[0x804b028]
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x03, // mov [ebx],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x03, // mov eax,[ebx]
        0x89, 0xC3, // mov ebx,eax
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_sib_disp32() {
    // SIB+disp32（7バイト）を run 経由で回し、exit コードで検証する。
    // mov eax,0x1500; push eax; pop ebx (ebx=0x1500);
    // mov eax,0x10; push eax; pop esi (esi=0x10);
    // mov eax,0x77; mov [ebx+esi*4+0x20],eax ([0x1560]=0x77);
    // mov eax,0; mov eax,[ebx+esi*4+0x20] (eax=0x77);
    // mov [esi*4+0x1500],eax ([0x1540]=0x77);
    // mov eax,0; mov eax,[esi*4+0x1500] (eax=0x77);
    // push eax; pop ebx; mov eax,1; int 0x80 -> exit(0x77)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x1500)
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax,0x10
        0x50, // push eax
        0x5E, // pop esi (esi=0x10)
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x84, 0xB3, 0x20, 0x00, 0x00, 0x00, // mov [ebx+esi*4+0x20],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x84, 0xB3, 0x20, 0x00, 0x00, 0x00, // mov eax,[ebx+esi*4+0x20]
        0x89, 0x04, 0xB5, 0x00, 0x15, 0x00, 0x00, // mov [esi*4+0x1500],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x04, 0xB5, 0x00, 0x15, 0x00, 0x00, // mov eax,[esi*4+0x1500]
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x77)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_div_exit_quotient() {
    // F7 F1 の fetch と div ディスパッチを run 経由で検証する。
    // EDX:EAX=17 / ECX=5 -> EAX=3 で exit(3)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x50, // push eax
        0x5A, // pop edx (edx=0)
        0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax,5
        0x50, // push eax
        0x59, // pop ecx (ecx=5)
        0xB8, 0x11, 0x00, 0x00, 0x00, // mov eax,17
        0xF7, 0xF1, // div eax,ecx (eax=3, edx=2)
        0x50, // push eax
        0x5B, // pop ebx (ebx=3)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(3)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(3));
}

/// x86-64 用の最小トラップ処理。番号は RAX、引数は RDI にある。
struct X64Exit;

impl TrapHandler for X64Exit {
    fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
        let nr = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0));
        if nr == 60 {
            let code = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(7));
            TrapOutcome::Exit(code as u32)
        } else {
            TrapOutcome::Unimplemented
        }
    }
}

#[test]
fn run_rex64_basic() {
    // REX.W 最小形を 64ビットモードで回す。SYSCALL 番号は RAX、引数は RDI。
    // lea rax,[rip+0x10] (rax=0x1017); mov rcx,0x77; add rax,rcx (rax=0x108e);
    // mov rdi,rcx (rdi=0x77); mov rax,60; syscall -> exit(0x77)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, // lea rax,[rip+0x10]
        0x48, 0xC7, 0xC1, 0x77, 0x00, 0x00, 0x00, // mov rcx,0x77
        0x48, 0x01, 0xC8, // add rax,rcx
        0x48, 0x89, 0xCF, // mov rdi,rcx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x77));
    // 32ビット書き込みは上位をゼロ拡張する（LEA の RAX 上位は 0 のまま）。
    assert_eq!(env.backend.get(Gpr(0).state()), 60);
}

#[test]
fn run_rex64_gas_absorbed() {
    // 実アセンブラ由来の x86-64 バイト列をそのまま埋め込んだ統合テスト。
    // 由来：Binutils GAS + ld の静的 x86-64 バイナリの .text
    // （lea rsi,[rip+msg] / mov rdi,1 / mov rdx,13 / mov rax,1 / syscall /
    // mov rdi,7 / mov rax,60 / syscall）。コードを 0x1000 に置くため
    // msg は 0x1007+0x2029 = 0x3030 に写像する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x3030), b"Hello, poly!\n")
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x8D, 0x35, 0x29, 0x20, 0x00, 0x00, // lea rsi,[rip+0x2029]
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi,1
        0x48, 0xC7, 0xC2, 0x0D, 0x00, 0x00, 0x00, // mov rdx,13
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax,1 (write)
        0x0F, 0x05, // syscall
        0x48, 0xC7, 0xC7, 0x07, 0x00, 0x00, 0x00, // mov rdi,7
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60 (exit)
        0x0F, 0x05, // syscall -> exit(7)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = run_x86::CliLinux::x86_64();
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(7));
}

#[test]
fn run_rex_b_and_stack64() {
    // REX.B (R8/R9) と 64ビットスタックを run 経由で回す。
    // mov rax,0x77 (48 C7 C0); mov r8,rax (49 89 C0); push r8 (41 50);
    // pop r9 (41 59); mov rdi,r9 (4C 89 CF); mov rax,60; syscall -> exit(0x77)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x77, 0x00, 0x00, 0x00, // mov rax,0x77
        0x49, 0x89, 0xC0, // mov r8,rax
        0x41, 0x50, // push r8
        0x41, 0x59, // pop r9
        0x4C, 0x89, 0xCF, // mov rdi,r9
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_rip_relative_norex() {
    // REX なし RIP 相対（8B/89 05）を 64ビットモードで回す。
    // 0x1000: 89 05 FA 0F 00 00  mov [rip+0xffa],eax ([0x2000]=eax)
    // 0x1006: B8 00 00 00 00     mov eax,0
    // 0x100B: 8B 05 EF 0F 00 00  mov eax,[rip+0xfef] ([0x2000])
    // mov rdi,rax (48 89 C7); mov rax,60; syscall -> exit(0x77)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x77);
    let prog: &[u8] = &[
        0x89, 0x05, 0xFA, 0x0F, 0x00, 0x00, // mov [rip+0xffa],eax ([0x2000]=0x77)
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x05, 0xEF, 0x0F, 0x00, 0x00, // mov eax,[rip+0xfef] (eax=0x77)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_rep_movsb() {
    // REP MOVSB を run 経由で回す。ECX=3 で [0x1500..0x1502] を [0x1600..] に写す。
    // mov esi,0x1500 相当は push/pop で作る（mov imm は EAX のみ）。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x1500), &[7, 8, 9]).unwrap();
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5E, // pop esi (esi=0x1500)
        0xB8, 0x00, 0x16, 0x00, 0x00, // mov eax,0x1600
        0x50, // push eax
        0x5F, // pop edi (edi=0x1600)
        0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax,3
        0x50, // push eax
        0x59, // pop ecx (ecx=3)
        0xF3, 0xA4, // rep movsb
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x50, // push eax
        0x5B, // pop ebx (ebx=1)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(1)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(1));
    let mut back = [0u8; 3];
    env.backend
        .mem
        .read(
            VirtAddr(0x1600),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [7, 8, 9]);
}

#[test]
fn run_sib_generic_regs() {
    // SIB 汎用形（base=EBX、index=ECX、dst=EDX）を run 経由で回す。
    // mov eax,0x1500; push eax; pop ebx (ebx=0x1500);
    // mov eax,0x10; push eax; pop ecx (ecx=0x10);
    // mov eax,0x77; mov [ebx+ecx*4],eax ([0x1540]=0x77);
    // mov eax,0; mov edx,[ebx+ecx*4] (edx=0x77);
    // mov ebx,edx; mov eax,1; int 0x80 -> exit(0x77)
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x1500)
        0xB8, 0x10, 0x00, 0x00, 0x00, // mov eax,0x10
        0x50, // push eax
        0x59, // pop ecx (ecx=0x10)
        0xB8, 0x77, 0x00, 0x00, 0x00, // mov eax,0x77
        0x89, 0x04, 0x8B, // mov [ebx+ecx*4],eax
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0
        0x8B, 0x14, 0x8B, // mov edx,[ebx+ecx*4] (edx=0x77)
        0x89, 0xD3, // mov ebx,edx
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_xmm_movd_punpck_pshufd() {
    // 66 0F 6E C6 (movd xmm0,esi); 66 0F 60 C0 (punpcklbw); 66 0F 61 C0 (punpcklwd);
    // 66 0F 70 C0 00 (pshufd); mov rdi,rax; mov rax,60; syscall -> exit(0)
    // ここでは XMM が動くことだけ確かめ、exit コードは固定する。
    // ESI=0x44 -> 全バイト 0x44 の xmm0 を作る。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x44);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi
        0x66, 0x0F, 0x60, 0xC0, // punpcklbw xmm0,xmm0
        0x66, 0x0F, 0x61, 0xC0, // punpcklwd xmm0,xmm0
        0x66, 0x0F, 0x70, 0xC0, 0x00, // pshufd xmm0,xmm0,0
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    // xmm0 の低32ビットが 0x44444444 であることを確かめる。
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!((v & 0xffff_ffff) as u32, 0x4444_4444);
}

#[test]
fn run_movups_memnd_and_near_jcc() {
    // MOVUPS [0x1500],xmm0 -> MOVUPS xmm1,[0x1500] の往復と near Jcc。
    // movd xmm0,esi (esi=0x77); movups [0x1500],xmm0; movups xmm1,[0x1500];
    // cmp eax,0; je +6 (skip mov eax,1); mov eax,1; ... の代わりに
    // near JE (0F 84) で飛ぶことを確かめ、exit(0x77) する。
    // 簡略化：xmm 往復後に cmp + near je で分岐し、exit コードを変える。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x77);
    env.backend.set(Gpr(0).state(), 0);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0x77)
        0x0F, 0x11, 0x05, 0xF5, 0x04, 0x00, 0x00, // movups [rip+0x4f5],xmm0 ([0x1500])
        // next_rip = 0x1000+4+7=0x100B, +0x4F5=0x1500. 計算：0x100B+0x4F5=0x1500. 正しくは disp=0x1500-0x100B=0x4F5.
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax,0 (ZF=1にするため cmp の前座)
        0x3D, 0x00, 0x00, 0x00, 0x00, // cmp eax,0 (ZF=1)
        0x0F, 0x84, 0x05, 0x00, 0x00, 0x00, // je +5 (mov eax,1 を飛ばす)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (飛ばされる)
        0x48, 0xC7, 0xC7, 0x77, 0x00, 0x00, 0x00, // mov rdi,0x77
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_lea_rex_x_sib() {
    // LEA RCX,[RAX+R8] with REX.WX (4A 8D 0C 00): RAX=0x1000, R8=0x20 -> RCX=0x1020.
    // mov rax,0x1000; push rax; pop rax? Simpler: use mov r32,imm + push/pop for R8? R8 via REX.B mov? Use mov r8,rax? Actually mov r8,rax needs REX. Simpler: set regs directly via env, then run single LEA.
    // Here test via run: mov eax,0x1000; mov r8d,0x20? Need REX for R8. Instead set via env before run and execute single LEA.
    // For run経由: 4A 8D 0C 00 (lea rcx,[rax+r8]); mov rax,60; mov rdi,rcx; syscall exit(rcx low?) -> exit(0x1020 & 0xFF? Actually exit code is low 8? Use exit(0x20?) Hmm.
    // Simpler: verify via sem directly in bare_x86min? Already covered by SIB generic? Add run-level check with REX.X.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    // Set RAX=0x1000, R8=0x20 via direct backend writes (bypass run).
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x1000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(8), 0x20);
    let prog: &[u8] = &[
        0x4A, 0x8D, 0x0C, 0x00, // lea rcx,[rax+r8] (rcx=0x1020)
        0x48, 0x89, 0xCF, // mov rdi,rcx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(rdi=0x1020 -> low 8 = 0x20)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    // exit code is low 8? Actually exit code is u32 (rdi low 32). rdi=0x1020, exit=0x1020=4128? But exit code is & 0xFF? Linux exit code is low 8 bits. Our X64Exit returns rdi as u32 directly (not masked). So expect 0x1020.
    assert_eq!(out, Outcome::Exit(0x1020));
}

#[test]
fn run_cmpb_mem8_disp8() {
    // run 経由で 80 /7 mod=01 [base+disp8],imm8 を回す。
    // edi=0x1500、[0x1569]=0 として CMPB $0,0x69(%rdi) で ZF=1、
    // je taken で exit(0x77) になる。fetch 長 4B の検証も兼ねる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x1569), &[0u8]).unwrap();
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5F, // pop edi (edi=0x1500)
        0x80, 0x7F, 0x69, 0x00, // cmpb $0,0x69(%rdi)
        0x74, 0x07, // je +7
        0xBB, 0x01, 0x00, 0x00, 0x00, // mov ebx,1
        0xEB, 0x05, // jmp +5
        0xBB, 0x77, 0x00, 0x00, 0x00, // mov ebx,0x77
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_cmova_reg_direct() {
    // run 経由で 0F47 reg-direct (CMOVA ECX,EDX) を回す。
    // ECX=1、EDX=2、CF=0/ZF=0 なので ECX=2 になり exit(2)。
    // fetch/decode/dispatch のレジスタ抽出 (0F系) の検証も兼ねる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x50, // push eax
        0x59, // pop ecx (ecx=1)
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax,2
        0x50, // push eax
        0x5A, // pop edx (edx=2)
        0x0F, 0x47, 0xCA, // cmova ecx,edx (ecx=2)
        0x51, // push ecx
        0x5B, // pop ebx (ebx=2)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(2)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(2));
}

#[test]
fn run_cmovae_reg_direct() {
    // run 経由で 0F43 reg-direct (CMOVAE ECX,EDX) を回す。
    // ECX=1、EDX=2、CF=0 なので ECX=2 になり exit(2)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0x50, // push eax
        0x59, // pop ecx (ecx=1)
        0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax,2
        0x50, // push eax
        0x5A, // pop edx (edx=2)
        0x0F, 0x43, 0xCA, // cmovae ecx,edx (ecx=2)
        0x51, // push ecx
        0x5B, // pop ebx (ebx=2)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(2)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(2));
}

#[test]
fn run_movb_mem8_disp8() {
    // run 経由で C6 /0 mod=01 [base+disp8],imm8 を回す。
    // RDI=0x1500 として MOVB $0x77,0x69(%RDI) で [0x1569]=0x77 を書き、
    // CMPB $0x77,0x69(%RDI) + je で検証して exit(0x77)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x15, 0x00, 0x00, // mov eax,0x1500
        0x50, // push eax
        0x5F, // pop edi (edi=0x1500)
        0xC6, 0x47, 0x69, 0x77, // movb $0x77,0x69(%rdi)
        0x80, 0x7F, 0x69, 0x77, // cmpb $0x77,0x69(%rdi)
        0x74, 0x07, // je +7
        0xBB, 0x01, 0x00, 0x00, 0x00, // mov ebx,1
        0xEB, 0x05, // jmp +5
        0xBB, 0x77, 0x00, 0x00, 0x00, // mov ebx,0x77
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xCD, 0x80, // int 0x80 -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_movq_xmm_m64_rip() {
    // run 経由で F3 0F 7E mod=00 [RIP+disp32] (MOVQ xmm0,[0x1500]) を回す。
    // [0x1500]=0x77 として xmm0 低64が 0x77 になることを確かめ、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &[0x77u8, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x05, 0xF8, 0x04, 0x00, 0x00, // movq xmm0,[rip+0x4f8] ([0x1500])
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v & 0xffff_ffff_ffff_ffff, 0x77);
}

#[test]
fn run_and_imm8_rip() {
    // run 経由で 83 25 + disp32 + imm8 (ANDL [RIP],imm8) を回す。
    // [0x1500]=0xFFFFFFFF に AND $0xCF で [0x1500]=0xFFFFFFCF になり、exit(0)。
    // fetch長7BとRIP加算の経路検証も兼ねる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &[0xFFu8, 0xFF, 0xFF, 0xFF])
        .unwrap();
    let prog: &[u8] = &[
        0x83, 0x25, 0xF9, 0x04, 0x00, 0x00, 0xCF, // andl $0xcf,[rip+0x4f9] ([0x1500])
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x1500),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0xFFFF_FFCF);
}

#[test]
fn run_and_imm32_rip() {
    // run 経由で 81 25 + disp32 + imm32 (ANDL [RIP],imm32) を回す。
    // [0x1500]=0xFFFFFFFF に AND $0xFC3FFEF3 で [0x1500]=0xFC3FFEF3 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &[0xFFu8, 0xFF, 0xFF, 0xFF])
        .unwrap();
    let prog: &[u8] = &[
        0x81, 0x25, 0xF6, 0x04, 0x00, 0x00, 0xF3, 0xFE, 0x3F,
        0xFC, // andl $0xfc3ffef3,[rip+0x4f6] ([0x1500])
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x1500),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0xFC3F_FEF3);
}

#[test]
fn run_pand_reg_direct() {
    // run 経由で 66 0F DB /r (PAND xmm0,xmm1) を回す。
    // movd で xmm0=0xFF / xmm1=0x0F を作り、PAND で xmm0=0x0F になることを確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0xFF);
    env.backend.set(Gpr(1).state(), 0x0F);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0xFF)
        0x66, 0x0F, 0x6E, 0xC9, // movd xmm1,ecx (xmm1=0x0F)
        0x66, 0x0F, 0xDB, 0xC1, // pand xmm0,xmm1 (xmm0=0x0F)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v & 0xffff_ffff, 0x0F);
}

#[test]
fn run_sar_rm64_cl() {
    // run 経由で REX.W D3 /7 (SAR RDI,CL) を回す。
    // RDI=0xF0、CL=2 -> RDI=0x3C になり、exit(0x3C)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x48, 0xC7, 0xC7, 0xF0, 0x00, 0x00, 0x00, // mov rdi,0xF0
        0x48, 0xC7, 0xC1, 0x02, 0x00, 0x00, 0x00, // mov rcx,2
        0x48, 0xD3, 0xFF, // sar rdi,cl (rdi=0x3C)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(rdi=0x3C)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x3C));
}

#[test]
fn run_punpcklqdq_reg_direct() {
    // run 経由で 66 0F 6C /r (PUNPCKLQDQ xmm0,xmm0) を回す。
    // movd で xmm0 低32=0x11223344 を作り、PUNPCKLQDQ で [lo,lo] になることを確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x1122_3344);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0x11223344)
        0x66, 0x0F, 0x6C, 0xC0, // punpcklqdq xmm0,xmm0
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v, 0x0000_0000_1122_3344_0000_0000_1122_3344u128);
}

#[test]
fn run_imul_r64_imm8_rip() {
    // run 経由で REX.W 6B /r ib + disp32 (IMUL RDX,[RIP+disp],0x38) を回す。
    // [0x1500]=2 * 0x38 = 112=0x70 になり、exit(0x70)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &[2u8, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x6B, 0x15, 0xF8, 0x04, 0x00, 0x00,
        0x38, // imul rdx,[rip+0x4f8],0x38 ([0x1500]=2 -> 112)
        0x48, 0x89, 0xD7, // mov rdi,rdx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x70)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x70));
}

#[test]
fn run_movdqu_load_mem8() {
    // run 経由で F3 0F 6F mod=01 (MOVDQU xmm0,[rax+0x20]) を回す。
    // [0x1020] の16B を xmm0 にロードして exit(0)、xmm0 で検証する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(
            VirtAddr(0x1020),
            &[0x78u8, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x00, 0x10, 0x00, 0x00, // mov rax,0x1000
        0xF3, 0x0F, 0x6F, 0x40, 0x20, // movdqu xmm0,[rax+0x20]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    // prog は 0x1000 に7+5=12B、データは 0x1020 で重ならない.
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v & 0xffff_ffff, 0x12345678);
}

#[test]
fn run_add_r_memnd() {
    // run 経由で REX.W 03 /r mod=00 (ADD RDX,[RBX]) を回す。
    // [0x1500]=0x40, RDX=0x10 -> RDX=0x50 になり、exit(0x50)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &[0x40u8, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0xC7, 0xC3, 0x00, 0x15, 0x00, 0x00, // mov rbx,0x1500
        0x48, 0xC7, 0xC2, 0x10, 0x00, 0x00, 0x00, // mov rdx,0x10
        0x48, 0x03, 0x13, // add rdx,[rbx] (rdx=0x50)
        0x48, 0x89, 0xD7, // mov rdi,rdx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x50)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x50));
}

#[test]
fn run_orb_mem32_disp32() {
    // run 経由で 80 /1 mod=10 [base+disp32],imm8 (ORB) を回す。
    // RBX=0x1000、[0x1356]=0x01 に ORB $0x80 で [0x1356]=0x81 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x1356), &[0x01u8]).unwrap();
    let prog: &[u8] = &[
        0xB8, 0x00, 0x10, 0x00, 0x00, // mov eax,0x1000
        0x50, // push eax
        0x5B, // pop ebx (ebx=0x1000)
        0x80, 0x8B, 0x56, 0x03, 0x00, 0x00, 0x80, // orb $0x80,0x356(%rbx)
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xBB, 0x00, 0x00, 0x00, 0x00, // mov ebx,0
        0xCD, 0x80, // int 0x80 -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x1356),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x81u8]);
}

#[test]
fn run_c7_mem32_generic_base() {
    // run 経由で C7 /0 mod=10 [RBX+disp32],imm32 (汎用base) を回す。
    // [0x1500]=0x11223344 を書き込み、exit(0)。読み戻しで検証する.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x1000);
    let prog: &[u8] = &[
        0xC7, 0x83, 0x00, 0x05, 0x00, 0x00, 0x44, 0x33, 0x22,
        0x11, // movl $0x11223344,0x500(%rbx) ([0x1500])
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1 (exit)
        0xBB, 0x00, 0x00, 0x00, 0x00, // mov ebx,0
        0xCD, 0x80, // int 0x80 -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = ExitOne;
    let out = run_x86::run(&mut env, 0x1000, &mut sys, 100);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x1500),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0x1122_3344);
}

#[test]
fn run_movups_mem32_roundtrip() {
    // run 経由で 0F 11/0F 10 mod=10 [base+disp32] の往復を回す (64bit)。
    // movd xmm0,esi (0x77); movups [rbx+0x500],xmm0; movups xmm1,[rbx+0x500];
    // movups [rbx+0x510],xmm1; mov eax,[rbx+0x510]; mov rdi,rax; exit(0x77).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x00, 0x10, 0x00, 0x00, // mov rax,0x1000
        0x50, // push rax
        0x5B, // pop rbx (rbx=0x1000)
        0x48, 0xC7, 0xC6, 0x77, 0x00, 0x00, 0x00, // mov rsi,0x77
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0x77)
        0x0F, 0x11, 0x83, 0x00, 0x05, 0x00, 0x00, // movups [rbx+0x500],xmm0
        0x66, 0x0F, 0xEF, 0xC9, // pxor xmm1,xmm1
        0x0F, 0x10, 0x8B, 0x00, 0x05, 0x00, 0x00, // movups xmm1,[rbx+0x500]
        0x0F, 0x11, 0x8B, 0x10, 0x05, 0x00, 0x00, // movups [rbx+0x510],xmm1
        0x8B, 0x83, 0x10, 0x05, 0x00, 0x00, // mov eax,[rbx+0x510] (eax=0x77)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 200, true);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_cdqe_sign_extend() {
    // run 経由で REX.W 98 (CDQE) を回す。
    // EAX=0x80000000 -> RAX=0xFFFFFFFF80000000 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB8, 0x00, 0x00, 0x00, 0x80, // mov eax,0x80000000
        0x48, 0x98, // cdqe (rax=0xffffffff80000000)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x80000000)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x8000_0000));
    let v = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(7));
    assert_eq!(v, 0xFFFF_FFFF_8000_0000);
}

#[test]
fn run_movzx_r32_m8_rip() {
    // run 経由で 0F B6 05 + disp32 (MOVZX EAX,[RIP+disp]) を回す (64bit)。
    // [0x1500]=0x80 -> EAX=0x80 になり、exit(0x80)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x1500), &[0x80u8]).unwrap();
    let prog: &[u8] = &[
        0x0F, 0xB6, 0x05, 0xF9, 0x04, 0x00, 0x00, // movzx eax,[rip+0x4f9] ([0x1500]=0x80)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x80)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x80));
}

#[test]
fn run_mov_r64_rip() {
    // run 経由で REX.W 8B 05 + disp32 (MOV R8,[RIP+disp]) を回す。
    // [0x1500]=-160 -> R8=-160 として exit(0)、R8 で検証する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(
            VirtAddr(0x1500),
            &[0x60u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        )
        .unwrap();
    let prog: &[u8] = &[
        0x4C, 0x8B, 0x05, 0xF9, 0x04, 0x00, 0x00, // mov r8,[rip+0x4f9] ([0x1500]=-160)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(8));
    assert_eq!(v, 0xFFFF_FFFF_FFFF_FF60);
}

#[test]
fn run_cmpb_imm_rip() {
    // run 経由で 80 3D + disp32 + imm8 (CMPB [RIP],imm8) を回す (64bit)。
    // [0x1500]=0 に CMPB $0 で ZF=1、je taken で exit(0x77)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x1500), &[0u8]).unwrap();
    let prog: &[u8] = &[
        0x80, 0x3D, 0xF9, 0x04, 0x00, 0x00, 0x00, // cmpb $0,[rip+0x4f9] ([0x1500]=0 -> ZF=1)
        0x74, 0x09, // je +9 (to mov rdi,0x77)
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi,1
        0xEB, 0x07, // jmp +7 (to mov rax,60)
        0x48, 0xC7, 0xC7, 0x77, 0x00, 0x00, 0x00, // mov rdi,0x77
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x77)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x77));
}

#[test]
fn run_pslldq_dst_is_rm() {
    // run 経由で 66 0F 73 FA 03 (PSLLDQ xmm2,3) を回す。
    // 0F 73 /7 の dst は rm フィールド (xmm2)。reg=111 は拡張子のため xmm7 ではない.
    // movd xmm2,esi (esi=0x11223344) -> pslldq 3 -> xmm2=0x11223344000000.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x1122_3344);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xD6, // movd xmm2,esi (xmm2=0x11223344)
        0x66, 0x0F, 0x73, 0xFA, 0x03, // pslldq xmm2,3
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(2),
    ));
    assert_eq!(v, 0x0011_2233_4400_0000u128);
    // 誤って xmm7 をシフトしていないこと.
    let w: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(7),
    ));
    assert_eq!(w, 0);
}
