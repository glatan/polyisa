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

#[test]
fn run_imul_rm64() {
    // run 経由で 48 F7 EF (IMUL RDI) を回す。ls -l 0x4a479e 対応.
    // RAX=7、RDI=6 -> RAX=42、RDX=0、eip は 0x1003 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(0), 7);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(7), 6);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0xF7, 0xEF])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    env.step(|b| {
        let lo = polyisa_guest_x86::sem::read64(b, Gpr(0));
        assert_eq!(lo, 42);
        let hi = polyisa_guest_x86::sem::read64(b, Gpr(2));
        assert_eq!(hi, 0);
        Ok(())
    })
    .unwrap();
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
fn run_rep_stosb_zero_count() {
    // run 経由で F3 AA (REP STOSB) を RCX=0 で回す。od 0x5ad076 対応.
    // RDI=0x2000、[0x2000]=0x00、AL=0xFF、RCX=0 -> [0x2000]==0x00、exit(0)。
    // 旧実装は1バイト格納して 2^64 回ループし step limit になった.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 0);
    env.backend.set(Gpr(0).state(), 0xFF);
    env.backend.mem.write(VirtAddr(0x2000), &[0u8]).unwrap();
    let prog: &[u8] = &[
        0xF3, 0xAA, // rep stosb (何もしない)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0u8]);
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
fn run_por_sibd32() {
    // run 経由で 66 0F EB 84 33 20 00 00 00 (POR xmm0,[RBX+RSI+0x20]) を回す。grep 0x43d15b 対応.
    // RBX=0x2000、RSI=0x10、[0x2020]=0x0F..、xmm0=0xF0.. -> xmm0=0xFF..、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend
        .mem
        .write(
            VirtAddr(0x2030),
            &0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0Fu128.to_le_bytes(),
        )
        .unwrap();
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W128>(0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            v,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0xEB, 0x84, 0x33, 0x20, 0x00, 0x00, 0x00, // por xmm0,[rbx+rsi+0x20]
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
    assert_eq!(v, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128);
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
fn run_xorps_reg_direct() {
    // run 経由で 0F 57 C0 (XORPS xmm0,xmm0) を回す。
    // movd で xmm0=0xFF を作り、XORPS で xmm0=0 になることを確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0xFF);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0xFF)
        0x0F, 0x57, 0xC0, // xorps xmm0,xmm0 (xmm0=0)
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
    assert_eq!(v, 0);
}

#[test]
fn run_movdqa_load_xmm_rex() {
    // run 経由で REX.R 66 0F 6F CD (MOVDQA xmm9,xmm5) を回す。
    // movd で xmm5 下位=0xAABBCCDD を作り、転送で xmm9 が等しくなることを確かめる。
    // MOVDQA は MovdquLoadXmm を共用する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0xAABB_CCDD);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xED, // movd xmm5,ebp (xmm5=0xAABBCCDD)
        0x44, 0x0F, 0x6F, 0xCD, // movdqa xmm9,xmm5 (REX.R)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(9),
    ));
    assert_eq!(v, 0xAABB_CCDD);
    // xmm1 を汚していないこと。
    let w: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(1),
    ));
    assert_eq!(w, 0);
}

#[test]
fn run_paddb_reg_direct_rex() {
    // run 経由で REX.R 66 0F FC C1 (PADDB xmm8,xmm1) を回す。
    // movd で xmm8 下位=0x01 / xmm1 下位=0x02 を作り、PADDB で下位=0x03 になることを確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x01);
    env.backend.set(Gpr(1).state(), 0x02);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0x01)
        0x66, 0x0F, 0x6E, 0xC9, // movd xmm1,ecx (xmm1=0x02)
        0x66, 0x44, 0x0F, 0x6F, 0xC0, // movdqa xmm8,xmm0 (REX.R)
        0x66, 0x44, 0x0F, 0xFC, 0xC1, // paddb xmm8,xmm1 (REX.R。xmm8 下位=0x03)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(8),
    ));
    assert_eq!(v, 0x03);
}

#[test]
fn run_pcmpgtb_reg_direct_rex() {
    // run 経由で REX.R 66 0F 64 C6 (PCMPGTB xmm8,xmm6) を回す。
    // movd で xmm8 下位=0x02 / xmm6 下位=0x01 を作り、PCMPGTB で下位=0xFF になることを確かめる。
    // 逆（0x01 vs 0x02）では下位=0x00。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x02);
    env.backend.set(Gpr(1).state(), 0x01);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0x02)
        0x66, 0x0F, 0x6E, 0xC9, // movd xmm1,ecx (xmm1=0x01)
        0x66, 0x44, 0x0F, 0x6F, 0xC0, // movdqa xmm8,xmm0 (REX.R)
        0x66, 0x44, 0x0F, 0x6F, 0xC9, // movdqa xmm9,xmm1 (REX.R)
        0x66, 0x44, 0x0F, 0x64, 0xC1, // pcmpgtb xmm8,xmm1 (REX.R。xmm8 下位=0xFF)
        0x66, 0x44, 0x0F, 0x64, 0xC8, // pcmpgtb xmm9,xmm0 (REX.R。xmm9 下位=0x00)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(8),
    ));
    assert_eq!(v & 0xFF, 0xFF);
    let w: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(9),
    ));
    assert_eq!(w & 0xFF, 0x00);
}

#[test]
fn run_pandn_reg_direct_rex() {
    // run 経由で REX.R 66 0F DF C7 (PANDN xmm8,xmm7) を回す。
    // movd で xmm8 下位=0x0F / xmm7 下位=0x06 を作り、PANDN で下位=0x06 になることを確かめる。
    // (~0x0F)&0x06 = 0xF0&0x06 = 0x00? ではなく (~0x0F)&0xFF... 下位8ビットのみ見る:
    // (~0x0F)&0x06 = 0x00。別値にするため xmm8=0xF0、xmm7=0xFF -> (~0xF0)&0xFF=0x0F。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0xF0);
    env.backend.set(Gpr(7).state(), 0xFF);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (xmm0=0xF0)
        0x66, 0x0F, 0x6E, 0xFF, // movd xmm7,edi (xmm7=0xFF)
        0x66, 0x44, 0x0F, 0x6F, 0xC0, // movdqa xmm8,xmm0 (REX.R)
        0x66, 0x44, 0x0F, 0xDF, 0xC7, // pandn xmm8,xmm7 (REX.R。下位=0x0F)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(8),
    ));
    assert_eq!(v & 0xFF, 0x0F);
}

#[test]
fn run_cvtsi2sd_r64() {
    // run 経由で F2 REX.W 0F 2A C0 (CVTSI2SD xmm0,rax) を回す。
    // RAX=5 -> xmm0 下位=5.0 (0x4014000000000000)、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, // mov rax,5
        0xF2, 0x48, 0x0F, 0x2A, 0xC0, // cvtsi2sd xmm0,rax
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
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0x4014_0000_0000_0000);
}

#[test]
fn run_addsd_reg_direct() {
    // run 経由で F2 0F 58 C8 (ADDSD xmm1,xmm0) を回す。
    // movd で下位=1.0/2.0 を作り、ADDSD で下位=3.0 になることを確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    // 1.0 の下位32 (0x00000000) と 2.0 の下位32では movd で作れないため、
    // メモリに 64 ビット即値を置き movq で読み込む。
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x3FF0_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0x4000_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x4B, 0x08, // movq xmm1,[rbx+8] (xmm1=1.0)
        0xF3, 0x0F, 0x7E, 0x43, 0x10, // movq xmm0,[rbx+0x10] (xmm0=2.0)
        0xF2, 0x0F, 0x58, 0xC8, // addsd xmm1,xmm0 (xmm1=3.0)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(1),
    ));
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0x4008_0000_0000_0000);
}

#[test]
fn run_comisd_reg_direct() {
    // run 経由で 66 0F 2F C1 (COMISD xmm0,xmm1) を回す。
    // xmm0=1.0、xmm1=2.0 で CF=1 になり、exit(0)。
    // EFLAGS の読み出しは sem 経由ではできないため、経路の到達のみ確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x3FF0_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0x4000_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x43, 0x08, // movq xmm0,[rbx+8] (xmm0=1.0)
        0xF3, 0x0F, 0x7E, 0x4B, 0x10, // movq xmm1,[rbx+0x10] (xmm1=2.0)
        0x66, 0x0F, 0x2F, 0xC1, // comisd xmm0,xmm1
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cvttsd2si_r64() {
    // run 経由で F2 REX.W 0F 2C C0 (CVTTSD2SI rax,xmm0) を回す。
    // xmm0 下位=3.9 -> RAX=3、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x400B_3333_3333_3333u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x43, 0x00, // movq xmm0,[rbx+0] (xmm0=3.9)
        0xF2, 0x48, 0x0F, 0x2C, 0xC0, // cvttsd2si rax,xmm0 (rax=3)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(3)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(3));
}

#[test]
fn run_subsd_reg_direct() {
    // run 経由で F2 0F 5C C8 (SUBSD xmm1,xmm0) を回す。
    // xmm1=3.0、xmm0=1.0 で下位=2.0 になることを確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x4008_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0x3FF0_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x4B, 0x08, // movq xmm1,[rbx+8] (xmm1=3.0)
        0xF3, 0x0F, 0x7E, 0x43, 0x10, // movq xmm0,[rbx+0x10] (xmm0=1.0)
        0xF2, 0x0F, 0x5C, 0xC8, // subsd xmm1,xmm0 (xmm1=2.0)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(1),
    ));
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0x4000_0000_0000_0000);
}

#[test]
fn run_mulsd_xmm_m64_rip() {
    // run 経由で F2 0F 59 05 + disp32 (MULSD xmm0,[RIP]) を回す.
    // [0x1500]=2.0、xmm0 下位=3.0 -> 6.0、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &0x4000_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x1500);
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x43, 0x00, // movq xmm0,[rbx+0] (xmm0=2.0)
        0xF2, 0x0F, 0x59, 0x05, 0xF3, 0x04, 0x00,
        0x00, // mulsd xmm0,[rip+0x4f3] ([0x1500]=2.0 -> 4.0)
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
    // xmm0=2.0 * [0x1500]=2.0 -> 4.0。
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0x4010_0000_0000_0000);
}

#[test]
fn run_movzx_r32_r16() {
    // run 経由で 0F B7 C3 (MOVZX EAX,BX) を回す。
    // EBX=0x1234ABCD -> EAX=0xABCD、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x1234_ABCD);
    let prog: &[u8] = &[
        0x0F, 0xB7, 0xC3, // movzx eax,bx (eax=0xABCD)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0xABCD)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0xABCD));
}

#[test]
fn run_bt_r32_imm() {
    // run 経由で 0F BA E3 1E (BT EBX,0x1E) を回す。
    // EBX=0x40000000 で CF=1 になり、exit(0)。経路の到達のみ確かめる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x4000_0000);
    let prog: &[u8] = &[
        0x0F, 0xBA, 0xE3, 0x1E, // bt ebx,0x1e
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_xadd_r32_memnd() {
    // run 経由で F0 0F C1 03 (LOCK XADD EAX,[EBX]) を回す。
    // EAX=5、[0x2000]=3 -> EAX=3、[0x2000]=8、exit(0)。
    // LOCK は単一スレッド試作として無視する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 5);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x03u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xF0, 0x0F, 0xC1, 0x03, // lock xadd eax,[ebx]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(0).state()), 60);
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 8);
}

#[test]
fn run_test_m16_imm_rip() {
    // run 経由で 66 F7 05 + disp32 + imm16 (TESTW [RIP],0x202) を回す。
    // [0x1500]=0x0202 で ZF=0 のまま exit(0)。
    // disp は F2/66 込み長さ基準：命令先頭 0x1000、66剥離後8B+接頭辞1B=9B、next=0x1009。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &0x0202u16.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0xF7, 0x05, 0xF7, 0x04, 0x00, 0x00, 0x02,
        0x02, // testw $0x202,[rip+0x4f7] ([0x1500])
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cmovne_r64_sibd() {
    // run 経由で REX.W 0F 45 44 24 50 (CMOVNE RAX,0x50(%rsp)) を回す。
    // ZF=0 で [0x2050] を RAX に移し、exit(RAX下位の0x78)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2050), &0x78u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x0F, 0x45, 0x44, 0x24, 0x50, // cmovne rax,0x50(%rsp) (ZF=0)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x78)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x78));
}

#[test]
fn run_nopl_mem8() {
    // run 経由で 0F 1F 40 00 (NOPL [rax]) を回す。
    // 何もせず exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x0F, 0x1F, 0x40, 0x00, // nopl [rax]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_sub_r_sibd() {
    // run 経由で 2B 44 24 08 (SUB EAX,0x8(%rsp)) を回す。
    // EAX=10、[0x2008]=3 -> EAX=7、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 10);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x03u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x2B, 0x44, 0x24, 0x08, // sub eax,0x8(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_add_r_sibd() {
    // run 経由で 48 03 7C 24 18 (ADD RDI,0x18(%rsp)) を回す。
    // RDI=0x100、[0x2018]=0x23 -> RDI=0x123、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0x100);
    env.backend
        .mem
        .write(VirtAddr(0x2018), &0x23u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x03, 0x7C, 0x24, 0x18, // add rdi,0x18(%rsp) (rdi=0x123)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(rdi=0x123)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x123));
}

#[test]
fn run_add_r_sibd_indexed() {
    // run 経由で 48 03 7C B4 28 (ADD RDI,[RSP+RSI*4+0x28]) を回す。sha1sum 0x5cab68 対応.
    // RSP=0x2000、RSI=0x10、[0x2068]=5、RDI=3 -> RDI=8、exit(8)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(7).state(), 3);
    env.backend
        .mem
        .write(VirtAddr(0x2068), &5u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x03, 0x7C, 0xB4, 0x28, // add rdi,[rsp+rsi*4+0x28] (rdi=8)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(rdi=8)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(8));
}

#[test]
fn run_movsx_r32_m8_rip() {
    // run 経由で 0F BE 05 + disp32 (MOVSX EAX,[RIP]) を回す。
    // [0x1500]=0xFF -> EAX=0xFFFFFFFF、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x1500), &[0xFF]).unwrap();
    let prog: &[u8] = &[
        0x0F, 0xBE, 0x05, 0xF9, 0x04, 0x00, 0x00, // movsx eax,[rip+0x4f9] ([0x1500])
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_movzx_r32_m16_mem8() {
    // run 経由で 0F B7 56 10 (MOVZX EDX,[RSI+0x10]) を回す。
    // [0x2010]=0xABCD -> EDX=0xABCD、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0xABCDu16.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x0F, 0xB7, 0x56, 0x10, // movzx edx,[rsi+0x10]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(2).state()), 0xABCD);
}

#[test]
fn run_movzx_r32_m16_memnd() {
    // run 経由で 0F B7 0E (MOVZX ECX,[RSI]) を回す。ls -l 0x4824c4 対応.
    // [0x2000]=0xABCD -> ECX=0xABCD、eip は 0x1003 に進み exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(6).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xABCDu16.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x0F, 0xB7, 0x0E, // movzx ecx,[rsi]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(1).state()), 0xABCD);
}

#[test]
fn run_movaps_store_mem32() {
    // run 経由で 0F 29 85 E0 FE FF FF (MOVAPS [rbp-0x120],xmm0) を回す。
    // RBP=0x2000、disp=-0x120 -> [0x1EE0]=xmm0、exit(0)。
    // movd で xmm0 下位=0x11223344 を作る。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x1122_3344);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi
        0x0F, 0x29, 0x85, 0xE0, 0xFE, 0xFF, 0xFF, // movaps [rbp-0x120],xmm0
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
            VirtAddr(0x1EE0),
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
fn run_or_m32_r32_sibd32() {
    // run 経由で 09 94 B0 08 08 00 00 (OR [rax+rsi*4+0x808],edx) を回す。
    // RAX=0x2000、RSI=0、EDX=0x0F、[0x2808]=0xF0 -> 0xFF、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0);
    env.backend.set(Gpr(2).state(), 0x0F);
    env.backend
        .mem
        .write(VirtAddr(0x2808), &0xF0u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x09, 0x94, 0xB0, 0x08, 0x08, 0x00, 0x00, // or [rax+rsi*4+0x808],edx
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
            VirtAddr(0x2808),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0xFF);
}

#[test]
fn run_cmp_r_sib() {
    // run 経由で 48 3B 04 07 (CMP RAX,(%rdi,%rax)) を回す。
    // RAX=10、RDI=0、[0x0A]=10 -> ZF=1 のまま exit(0)。
    // [0x0A] はコード頁 (0x1000) と別に 0x0000 頁へ書く。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 10);
    env.backend.set(Gpr(7).state(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x0A), &0x0Au64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x3B, 0x04, 0x07, // cmp rax,(%rdi,%rax)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_sub_m32_r32_mem8() {
    // run 経由で 4C 29 6D A0 (SUB -0x60(%rbp),%r13) を回す。
    // RBP=0x2000、R13=3、[0x1FA0]=10 -> [0x1FA0]=7、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend.set(Gpr(13).state(), 3);
    env.backend
        .mem
        .write(VirtAddr(0x1FA0), &0x0Au64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x4C, 0x29, 0x6D, 0xA0, // sub -0x60(%rbp),%r13 (REX.WR)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x1FA0),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 7);
}

#[test]
fn run_mov_m8_r8_sib() {
    // run 経由で 88 14 07 (MOV [rdi+rax],dl) を回す。
    // RDI=0x2000、RAX=0、DL=0x42 -> [0x2000]=0x42、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0);
    env.backend.set(Gpr(2).state(), 0x42);
    let prog: &[u8] = &[
        0x88, 0x14, 0x07, // mov [rdi+rax],dl
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x42);
}

#[test]
fn run_mov_m8_r8_sibd32_rex() {
    // run 経由で 88 94 07 36 04 00 00 (MOV [rdi+rax+0x436],dl) を回す。
    // SIBd32 基本形の検証。RDI=0x2000、RAX=0x10、DL=0x42 -> [0x2446]=0x42.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x10);
    env.backend.set(Gpr(2).state(), 0x42);
    let prog: &[u8] = &[
        0x88, 0x94, 0x07, 0x36, 0x04, 0x00, 0x00, // mov [rdi+rax+0x436],dl
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2446),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x42);
}

#[test]
fn run_cmp_rm64_imm8_mem32_rex() {
    // run 経由で 48 83 BD E8 FB FF FF 00 (CMPQ $0,-0x418(%rbp)) を回す。
    // seq の停止点に対応。RBP=0x2000、[0x1BE8]=0 -> ZF=1 で exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1BE8), &0u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x83, 0xBD, 0xE8, 0xFB, 0xFF, 0xFF, 0x00, // cmpq $0,-0x418(%rbp) (REX.W)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_add_m32_r32_sibd() {
    // run 経由で 01 6C 24 18 (ADD 0x18(%rsp),%ebp) を回す。
    // [0x2018]=10、EBP=5 -> [0x2018]=15、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 5);
    env.backend
        .mem
        .write(VirtAddr(0x2018), &0x0Au32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x01, 0x6C, 0x24, 0x18, // add 0x18(%rsp),%ebp
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
            VirtAddr(0x2018),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 15);
}

#[test]
fn run_cmp_rm_imm8_sib() {
    // run 経由で 48 83 3C 24 00 (CMPQ $0,(%rsp)) を回す。
    // [0x2000]=0 で ZF=1 のまま exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x83, 0x3C, 0x24, 0x00, // cmpq $0,(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cmp_rm_imm8_sib_idx() {
    // run 経由で 48 83 3C D3 00 (CMPQ $0,(%rbx,%rdx,8)) を回す。
    // RBX=0x2000、RDX=0、[0x2000]=0 で ZF=1 のまま exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x83, 0x3C, 0xD3, 0x00, // cmpq $0,(%rbx,%rdx,8)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_test_r_mem8() {
    // run 経由で 44 85 78 04 (TEST R15D,[RAX+4]) を回す。
    // R15=0xFF、RAX=0x2000、[0x2004]=0xFF -> ZF=0 のまま exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.set(Gpr(15).state(), 0xFF);
    env.backend
        .mem
        .write(VirtAddr(0x2004), &0xFFu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x44, 0x85, 0x78, 0x04, // test r15d,[rax+4] (REX.R)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_test_rm32_memnd() {
    // run 経由で 85 07 (TEST EAX,(RDI)) を回す。find 0x5d17f7 対応.
    // EAX=0xFF、RDI=0x2000、[0x2000]=0x0F -> ZF=0、eip は 0x1002 に進み exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0xFF);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x0Fu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x85, 0x07, // test eax,(rdi)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_mov_m16_r16_mem32() {
    // run 経由で 66 89 8F 80 00 00 00 (MOV [rdi+0x80],cx) を回す。
    // RDI=0x2000、CX=0x1234 -> [0x2080]=0x1234、exit(0)。MovMemEax32 を共用する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 0x1234);
    let prog: &[u8] = &[
        0x66, 0x89, 0x8F, 0x80, 0x00, 0x00, 0x00, // mov [rdi+0x80],cx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2080),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x1234);
}

#[test]
fn run_or_rm32_imm_memnd() {
    // run 経由で 81 0F 0C 24 00 00 (OR $0x240C,(%rdi)) を回す。
    // RDI=0x2000、[0x2000]=0x1000 -> 0x340C、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x1000u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x81, 0x0F, 0x0C, 0x24, 0x00, 0x00, // or $0x240c,(%rdi)
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
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0x340C);
}

#[test]
fn run_or_al_imm() {
    // run 経由で 0C 80 (OR AL,0x80) を回す。
    // EAX=1 -> AL=0x81、exit(0x81)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 1);
    let prog: &[u8] = &[
        0x0C, 0x80, // or al,0x80
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x81)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x81));
}

#[test]
fn run_or_m8_r8_reg_direct() {
    // run 経由で 08 D0 (OR AL,DL) を回す。
    // EAX=0x01、EDX=0x02 -> AL=0x03、exit(3)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x01);
    env.backend.set(Gpr(2).state(), 0x02);
    let prog: &[u8] = &[
        0x08, 0xD0, // or al,dl
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(3)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(3));
}

#[test]
fn run_and_r8_m8_mem32() {
    // run 経由で 22 85 40 FB FF FF (AND AL,-0x4C0(%rbp)) を回す。
    // RBP=0x500、AL=0xFF、[0x40]=0x0F -> AL=0x0F、exit(0x0F)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0x500);
    env.backend.set(Gpr(0).state(), 0xFF);
    env.backend.mem.write(VirtAddr(0x40), &[0x0F]).unwrap();
    let prog: &[u8] = &[
        0x22, 0x85, 0x40, 0xFB, 0xFF, 0xFF, // and al,-0x4c0(%rbp)
        0x48, 0x89, 0xC7, // mov rdi,rax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x0F, 0x05, // syscall -> exit(0x0F)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0x0F));
}

#[test]
fn run_mov_m16_r16_mem8() {
    // run 経由で 66 89 47 74 (MOV 0x74(%rdi),ax) を回す。
    // RDI=0x2000、AX=0x1234 -> [0x2074]=0x1234、exit(0)。MovMemEax8 を共用する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x1234);
    let prog: &[u8] = &[
        0x66, 0x89, 0x47, 0x74, // mov 0x74(%rdi),ax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2074),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x1234);
}

#[test]
fn run_sete_m8_mem32() {
    // run 経由で 0F 94 85 0B FB FF FF (SETE -0x4F5(%rbp)) を回す。
    // RBP=0x500、ZF=1 -> [0x0B]=1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0x500);
    let prog: &[u8] = &[
        0x0F, 0x94, 0x85, 0x0B, 0xFB, 0xFF, 0xFF, // sete -0x4f5(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x0B),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    // ZF=0 のため [0x0B]=0 のまま。
    assert_eq!(back[0], 0);
}

#[test]
fn run_setle_m8_mem32() {
    // run 経由で 0F 9E 85 73 FD FF FF (SETLE -0x28D(%rbp)) を回す。grep 0x43e091 対応.
    // RBP=0x500、ZF=1 -> [0x273]=1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x500);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x40);
    let prog: &[u8] = &[
        0x0F, 0x9E, 0x85, 0x73, 0xFD, 0xFF, 0xFF, // setle -0x28d(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x273),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 1);
}

#[test]
fn run_sete_m8_mem8() {
    // run 経由で 0F 94 45 97 (SETE -0x69(%rbp)) を回す。grep 0x442245 対応.
    // RBP=0x500、ZF=1 -> [0x497]=1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x500);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x40);
    let prog: &[u8] = &[
        0x0F, 0x94, 0x45, 0x97, // sete -0x69(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x497),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 1);
}

#[test]
fn run_setne_m8_mem32() {
    // run 経由で 0F 95 85 C0 FD FF FF (SETNE -0x240(%rbp)) を回す。grep 0x43ddc1 対応.
    // RBP=0x2000、ZF=0 -> [0x1DC0]=1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let prog: &[u8] = &[
        0x0F, 0x95, 0x85, 0xC0, 0xFD, 0xFF, 0xFF, // setne -0x240(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x1DC0),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 1);
}

#[test]
fn run_setne_m8_sibd() {
    // run 経由で 0F 95 44 F0 06 (SETNE 0x06(%rax,%rsi,8)) を回す。ls -l 対応.
    // RAX=0x2000、RSI=0x10、ZF=0 -> [0x2086]=1、eip は 0x1005 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let prog: &[u8] = &[
        0x0F, 0x95, 0x44, 0xF0, 0x06, // setne 0x06(%rax,%rsi,8)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2086),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 1);
}

#[test]
fn run_test_m8_imm_sib() {
    // run 経由で 41 F6 04 24 04 (TESTB $0x04,(%r12)) を回す。ls -l 0x40e342 対応.
    // R12=0x1500、[0x1500]=0x04 -> ZF=0、eip は 0x1005 に進み exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(12), 0x1500);
        Ok(())
    })
    .unwrap();
    env.backend.mem.write(VirtAddr(0x1500), &[0x04u8]).unwrap();
    let prog: &[u8] = &[
        0x41, 0xF6, 0x04, 0x24, 0x04, // testb $0x04,(%r12)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_cmp_rm8_imm_mem32() {
    // run 経由で 80 BD 50 FB FF FF 20 (CMPB $0x20,-0x4B0(%rbp)) を回す。
    // RBP=0x500、[0x50]=0x20 で ZF=1 のまま exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0x500);
    env.backend.mem.write(VirtAddr(0x50), &[0x20]).unwrap();
    let prog: &[u8] = &[
        0x80, 0xBD, 0x50, 0xFB, 0xFF, 0xFF, 0x20, // cmpb $0x20,-0x4b0(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_and_rm8_imm_mem8() {
    // run 経由で 80 67 38 90 (ANDB $0x90,0x38(%rdi)) を回す。grep 0x442d1d 対応.
    // RDI=0x2000、[0x2038]=0xFF -> [0x2038]=0x90、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x2038), &[0xFFu8]).unwrap();
    let prog: &[u8] = &[
        0x80, 0x67, 0x38, 0x90, // andb $0x90,0x38(%rdi)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2038),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x90u8]);
}

#[test]
fn run_or_rm8_imm_mem8() {
    // run 経由で 80 4B 44 02 (ORB $0x02,0x44(%rbx)) を回す。sed 0x5bde04 対応.
    // RBX=0x2000、[0x2044]=0x01 -> [0x2044]=0x03、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x2044), &[0x01u8]).unwrap();
    let prog: &[u8] = &[
        0x80, 0x4B, 0x44, 0x02, // orb $0x02,0x44(%rbx)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2044),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x03u8]);
}

#[test]
fn run_and_rm8_imm_sibd() {
    // run 経由で 80 64 0F 3A F3 (ANDB $0xF3,0x3A(%rdi,%rcx)) を回す。grep 0x434710 対応.
    // RDI=0x2000、RCX=0x40、[0x207A]=0xFF -> [0x207A]=0xF3、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 0x40);
    env.backend.mem.write(VirtAddr(0x207A), &[0xFFu8]).unwrap();
    let prog: &[u8] = &[
        0x80, 0x64, 0x0F, 0x3A, 0xF3, // andb $0xF3,0x3A(%rdi,%rcx)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x207A),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0xF3u8]);
}

#[test]
fn run_cmp_m32_r32_sibd() {
    // run 経由で 39 54 24 14 (CMP 0x14(%rsp),%edx) を回す。
    // [0x2014]=5、EDX=5 -> ZF=1 のまま exit(0)。no_index は mem8 相当。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 5);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &0x05u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x39, 0x54, 0x24, 0x14, // cmp 0x14(%rsp),%edx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_movsx_r32_m8_mem8() {
    // run 経由で 0F BE 71 01 (MOVSX ESI,[RCX+1]) を回す。
    // RCX=0x2000、[0x2001]=0xFF -> ESI=0xFFFFFFFF、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x2001), &[0xFF]).unwrap();
    let prog: &[u8] = &[
        0x0F, 0xBE, 0x71, 0x01, // movsx esi,[rcx+1]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(6).state()), 0xFFFF_FFFF);
}

#[test]
fn run_cmp_rm8_imm_sibd_no_index() {
    // run 経由で 41 80 7C 24 1A 04 (CMPB $0x04,0x1A(%r12)) を回す。
    // R12=0x2000、[0x201A]=0x04 で ZF=1 のまま exit(0)。no_index は mem8 相当。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(12).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x201A), &[0x04]).unwrap();
    let prog: &[u8] = &[
        0x41, 0x80, 0x7C, 0x24, 0x1A, 0x04, // cmpb $0x04,0x1a(%r12) (REX.B)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cmp_rm8_imm_sibd32() {
    // run 経由で 80 BC 05 F0 FE FF FF 00 (CMPB $0x00,-0x110(%rbp,%rax)) を回す。stat 対応.
    // RBP=0x2000、RAX=0x100、[0x1FF0]=0x00 -> ZF=1、eip は 0x1008 に進み exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x100);
    env.backend.mem.write(VirtAddr(0x1FF0), &[0x00]).unwrap();
    let prog: &[u8] = &[
        0x80, 0xBC, 0x05, 0xF0, 0xFE, 0xFF, 0xFF, 0x00, // cmpb $0x00,-0x110(%rbp,%rax)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_add_m16_imm_sib() {
    // run 経由で 66 83 04 51 01 (ADDW $1,(%rcx,%rdx,2)) を回す。
    // RCX=0x2000、RDX=0、[0x2000]=0x10 -> 0x11、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x10u16.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0x83, 0x04, 0x51, 0x01, // addw $1,(%rcx,%rdx,2)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x11);
}

#[test]
fn run_cmp_rm_imm8_sibd() {
    // run 経由で 83 7C 24 14 00 (CMPL $0,0x14(%rsp)) を回す。
    // [0x2014]=0 で ZF=1 のまま exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &0u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x83, 0x7C, 0x24, 0x14, 0x00, // cmpl $0,0x14(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cmp_rm_imm8_mem32() {
    // run 経由で 83 BD 14 00 00 00 00 (CMPL $0,0x14(%rbp)) を回す。
    // [0x2014]=0 で ZF=1 のまま exit(0)。seq の停止点に対応.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &0u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x83, 0xBD, 0x14, 0x00, 0x00, 0x00, 0x00, // cmpl $0,0x14(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_and_m8_r8_rex() {
    // run 経由で 40 20 C6 (AND SIL,AL) を回す。REX 付き low8。
    // ESI=0xFF、EAX=0x0F -> SIL=0x0F で exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(6).state(), 0xFF);
    env.backend.set(Gpr(0).state(), 0x0F);
    let prog: &[u8] = &[
        0x40, 0x20, 0xC6, // and sil,al (REX)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(6).state()) & 0xFF, 0x0F);
}

#[test]
fn run_movsx_r32_m8_sib() {
    // run 経由で 0F BE 0C 24 (MOVSX ECX,[RSP]) を回す。
    // [0x2000]=0xFF -> ECX=0xFFFFFFFF で exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x2000), &[0xFF]).unwrap();
    let prog: &[u8] = &[
        0x0F, 0xBE, 0x0C, 0x24, // movsx ecx,[rsp]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(1).state()), 0xFFFF_FFFF);
}

#[test]
fn run_movdqu_load_sib() {
    // run 経由で 66 0F 6F 0C 0E (MOVDQA xmm1,[RSI+RCX]) を回す。
    // RSI=0x2000、RCX=0x100 -> [0x2100] 16B を xmm1 に載せて exit(0)。
    use polyisa_guest_x86::sem::Xmm;
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(6).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 0x100);
    env.backend
        .mem
        .write(
            VirtAddr(0x2100),
            &[
                0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                0xDD, 0xEE, 0xFF,
            ],
        )
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6F, 0x0C, 0x0E, // movdqa xmm1,[rsi+rcx]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(Xmm(1)));
    assert_eq!(v, 0xFFEEDDCCBBAA99887766554433221100u128);
}

#[test]
fn run_nopl_mem32() {
    // run 経由で 0F 1F 80 00 00 00 00 (NOPL [rax]) を回す。
    // 何もせず exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00, // nopl [rax]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cmp_rm8_imm_sib() {
    // run 経由で 41 80 3C 24 43 (CMPB $0x43,(%r12)) を回す。
    // [0x2000]=0x43 で ZF=1 のまま exit(0)。意味論は memnd 相当。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    // R12 = Gpr(12) = 0x2000。REX.B で base 拡張。
    env.backend.set(Gpr(12).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x2000), &[0x43]).unwrap();
    let prog: &[u8] = &[
        0x41, 0x80, 0x3C, 0x24, 0x43, // cmpb $0x43,(%r12) (REX.B)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cmp_rm8_imm_sib_idx() {
    // run 経由で 80 3C 13 00 (CMPB $0x00,(%rbx,%rdx)) を回す。grep 0x43e0e4 対応.
    // RBX=0x2000、RDX=0x10、[0x2010]=0x00 -> ZF=1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 0x10);
    env.backend.mem.write(VirtAddr(0x2010), &[0x00]).unwrap();
    let prog: &[u8] = &[
        0x80, 0x3C, 0x13, 0x00, // cmpb $0x00,(%rbx,%rdx)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_mov_rm8_imm_mem32() {
    // run 経由で C6 85 50 FB FF FF 20 (MOVB $0x20,-0x4B0(%rbp)) を回す。
    // RBP=0x2000、disp=-0x4B0 -> [0x1B50]=0x20、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0x2000);
    let prog: &[u8] = &[
        0xC6, 0x85, 0x50, 0xFB, 0xFF, 0xFF, 0x20, // movb $0x20,-0x4b0(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x1B50),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x20);
}

#[test]
fn run_mov_rm8_imm_mem32_rbx() {
    // run 経由で C6 83 DC 00 00 00 01 (MOVB $0x1,0xDC(%RBX)) を回す。
    // disp32 下位3bit が 100 でも decode する。RBX=0x2000 -> [0x20DC]=0x1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(5).state(), 0x2000);
    let prog: &[u8] = &[
        0xC6, 0x83, 0xDC, 0x00, 0x00, 0x00, 0x01, // movb $0x1,0xdc(%rbx)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(3), 0x2000);
        Ok(())
    })
    .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x20DC),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x01);
}

#[test]
fn run_mov_rm8_imm_sibd() {
    // run 経由で 42 C6 44 28 FE 3A (MOVB $0x3A,-2(%rax,%r13)) を回す。
    // RAX=0x2000、R13=2 -> [0x2000]=0x3A、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.set(Gpr(13).state(), 2);
    let prog: &[u8] = &[
        0x42, 0xC6, 0x44, 0x28, 0xFE, 0x3A, // movb $0x3a,-2(%rax,%r13) (REX.X)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x3A);
}

#[test]
fn run_mov_rm16_imm_sibd() {
    // run 経由で 66 C7 44 24 11 53 00 (MOVW $0x53,0x11(%rsp)) を回す。stat 対応.
    // RSP=0x2000 -> [0x2011]=0x53、eip は 0x1007 に進み exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x66, 0xC7, 0x44, 0x24, 0x11, 0x53, 0x00, // movw $0x53,0x11(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2011),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x53);
}

#[test]
fn run_mov_rm8_imm_sib() {
    // run 経由で C6 04 16 3A (MOVB $0x3A,(%rsi,%rdx)) を回す。
    // RSI=0x2000、RDX=0 -> [0x2000]=0x3A、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 0);
    let prog: &[u8] = &[
        0xC6, 0x04, 0x16, 0x3A, // movb $0x3a,(%rsi,%rdx)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x3A);
}

#[test]
fn run_mov_m16_r16_memnd() {
    // run 経由で 66 89 38 (MOV [rax],di) を回す。
    // [0x2000]=0x1234 になり、exit(0)。MovMemndEax を共用する。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0x1234);
    let prog: &[u8] = &[
        0x66, 0x89, 0x38, // mov [rax],di
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x1234);
}

#[test]
fn run_and_rm_imm8_sibd() {
    // run 経由で 48 83 64 24 10 00 (ANDQ $0,0x10(%rsp)) を回す。
    // [0x2010]=0xFF -> 0 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0xFFu64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x83, 0x64, 0x24, 0x10, 0x00, // andq $0,0x10(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 0);
}

#[test]
fn run_add_rm_imm8_sibd() {
    // run 経由で 48 83 44 24 08 08 (ADDQ $8,0x08(%rsp)) を回す。test 0x5b1d4e 対応.
    // RSP=0x2000、[0x2008]=0 -> 8 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x83, 0x44, 0x24, 0x08, 0x08, // addq $8,0x08(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2008),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 8);
}

#[test]
fn run_or_r_sib_no_index() {
    // run 経由で 0B 04 24 (ORL (%rsp),%eax) を回す。sed 0x5be0c9 対応.
    // RSP=0x2000、[0x2000]=0x0F、EAX=0xF0 -> EAX=0xFF。exit 系列で EAX が潰れるため [0x2100] に退避して検証.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0xF0);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x0Fu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x0B, 0x04, 0x24, // orl (%rsp),%eax
        0x89, 0x05, 0xF7, 0x10, 0x00, 0x00, // mov [rip+0x10F7],eax -> [0x2100]
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
            VirtAddr(0x2100),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0xFF);
}

#[test]
fn run_cmp_rm64_imm8_sibd() {
    // run 経由で 48 83 7C C1 F8 00 (CMPQ $0,-0x8(%rcx,%rax,8)) を回す。seq 10 の停止点 0x45bbd8 対応.
    // RCX=0x2000、RAX=0x10、[0x2078]=0 -> ZF=1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(1).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x10);
    env.backend
        .mem
        .write(VirtAddr(0x2078), &0u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x83, 0x7C, 0xC1, 0xF8, 0x00, // cmpq $0,-0x8(%rcx,%rax,8)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_cmp_m32_r32_sib_no_index() {
    // run 経由で 44 39 2C 24 (CMP [RSP],R13D with REX.R) を回す。paste 0x5ad26b 対応.
    // RSP=0x2000、[0x2000]=5、R13D=5 -> ZF=1、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(13), 5);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &5u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x44, 0x39, 0x2C, 0x24, // cmp [rsp],r13d
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_ucomisd_rip() {
    // run 経由で 66 0F 2E 0D + disp32 (UCOMISD xmm1,[RIP]) を回す。seq の停止点 0x45b763 に対応.
    // [0x2000]=2.0、xmm1=1.0 -> CF=1、ZF=0 になり、exit(0)。mov は旗を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &2.0f64.to_le_bytes())
        .unwrap();
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W128>(0x3FF0_0000_0000_0000);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(1)),
            v,
        );
        Ok(())
    })
    .unwrap();
    // next_rip=0x1008、target=0x2000 -> disp=0xFF8.
    let prog: &[u8] = &[
        0x66, 0x0F, 0x2E, 0x0D, 0xF8, 0x0F, 0x00, 0x00, // ucomisd xmm1,[rip+0xFF8]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        1
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_and_rm_imm8_sibd_indexed() {
    // run 経由で 83 64 97 FC 00 (ANDL $0,-4(%rdi,%rdx,4)) を回す。
    // RDI=0x2000、RDX=0x10、[0x203C]=0xFF -> 0 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 0x10);
    env.backend
        .mem
        .write(VirtAddr(0x203C), &0xFFu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x83, 0x64, 0x97, 0xFC, 0x00, // andl $0,-4(%rdi,%rdx,4)
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
            VirtAddr(0x203C),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0);
}

#[test]
fn run_or_rm_imm8_sibd_indexed() {
    // run 経由で 4A 83 4C 23 08 01 (ORQ $1,0x08(%rbx,%r12)) を回す。ls -l 対応.
    // RBX=0x2000、R12=0x10、[0x2018]=0 -> 1 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.set(Gpr(12).state(), 0x10);
    env.backend
        .mem
        .write(VirtAddr(0x2018), &0u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x4A, 0x83, 0x4C, 0x23, 0x08, 0x01, // orq $1,0x08(%rbx,%r12)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2018),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 1);
}

#[test]
fn run_and_rm_imm8_sib() {
    // run 経由で 83 24 24 00 (ANDL $0,(%rsp)) を回す。
    // [0x2000]=0xFF -> 0 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xFFu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x83, 0x24, 0x24, 0x00, // andl $0,(%rsp)
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
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0);
}

#[test]
fn run_inc_rm_sibd_indexed() {
    // run 経由で FF 44 97 FC (INCL -4(%rdi,%rdx,4)) を回す。
    // RDI=0x2000、RDX=0x10、[0x203C]=0xFE -> 0xFF になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 0x10);
    env.backend
        .mem
        .write(VirtAddr(0x203C), &0xFEu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xFF, 0x44, 0x97, 0xFC, // incl -4(%rdi,%rdx,4)
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
            VirtAddr(0x203C),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0xFF);
}

#[test]
fn run_and_rm_imm8_sib_indexed_rexx() {
    // run 経由で 42 83 24 88 00 (ANDL $0,(%rax,%r9,4)) を回す。REX.X で R9 を指す。
    // RAX=0x2000、R9=0x10、[0x2040]=0xFF -> 0 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(9), 0x10);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2040), &0xFFu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x42, 0x83, 0x24, 0x88, 0x00, // andl $0,(%rax,%r9,4)
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
            VirtAddr(0x2040),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0);
}

#[test]
fn run_cmp_r_sibd_no_index() {
    // run 経由で 3B 4C 24 14 (CMPL 0x14(%rsp),%ecx) を回す。
    // ECX=10、[0x2014]=10 -> ZF=1 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 10);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &10u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x3B, 0x4C, 0x24, 0x14, // cmpl 0x14(%rsp),%ecx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_test_r_sibd_no_index() {
    // run 経由で 85 44 24 1C (TESTL 0x1C(%rsp),%eax) を回す。wc の停止点 0x5b3696 に対応.
    // EAX=0xFF、[0x201C]=0x0F -> ZF=0 になり、exit(0)。mov は旗を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0xFF);
    env.backend
        .mem
        .write(VirtAddr(0x201C), &0x0Fu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x85, 0x44, 0x24, 0x1C, // testl 0x1C(%rsp),%eax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_test_r_sibd32_rex() {
    // run 経由で 4B 85 94 15 A8 00 00 00 (TEST 0xA8(%r13,%r10),%rdx with REX.W/X/B) を回す。
    // grep 0x43d250 対応。R13=0x2000、R10=0x10、[0x20B8]=0x0F、RDX=0xFF -> ZF=0、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(13), 0x2000);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(10), 0x10);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(2), 0xFF);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x20B8), &0x0Fu64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x4B, 0x85, 0x94, 0x15, 0xA8, 0x00, 0x00, 0x00, // test 0xA8(%r13,%r10),%rdx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_cmp_m32_r32_sibd_indexed() {
    // run 経由で 41 39 44 88 F8 (CMPL %eax,-8(%r8,%rcx,4)) を回す。head のループ停止点に対応.
    // R8=0x2000、RCX=0x10、[0x2038]=10、EAX=10 -> ZF=1 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(8), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(1).state(), 0x10);
    env.backend.set(Gpr(0).state(), 10);
    env.backend
        .mem
        .write(VirtAddr(0x2038), &10u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x41, 0x39, 0x44, 0x88, 0xF8, // cmpl %eax,-8(%r8,%rcx,4)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_cmp_m64_r64_sibd32_no_index() {
    // 48 39 84 24 88 00 00 00: cmpq %rax, 0x88(%rsp)。true 0x4bed0c 対応.
    // RSP=0x2000、[0x2088]=7、RAX=7 -> ZF=1。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 7);
    env.backend
        .mem
        .write(VirtAddr(0x2088), &7u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x39, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, // cmpq %rax, 0x88(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_call_r_sibabs() {
    // 42 FF 14 E5 00 20 00 00: callq *0x2000(,%r12,8)。true 0x403f86 と同形.
    // R12=1、[0x2008]=0x1100 の exit(0) へ飛ぶ。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x3800);
    env.backend.set(Gpr(12).state(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x1100u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x42, 0xFF, 0x14, 0xE5, 0x00, 0x20, 0x00, 0x00, // callq *0x2000(,%r12,8)
    ];
    let exit: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    env.backend.mem.write(VirtAddr(0x1100), exit).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_cmp_rm_imm8_sibd32_no_index() {
    // 48 83 BC 24 D8 00 00 00 00: cmpq $0, 0xd8(%rsp)。true 0x4bed16 対応.
    // RSP=0x2000、[0x20D8]=0 -> ZF=1。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x20D8), &0u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x83, 0xBC, 0x24, 0xD8, 0x00, 0x00, 0x00, 0x00, // cmpq $0, 0xd8(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_sub_r_sibd_indexed() {
    // run 経由で 2B 44 B0 50 (SUBL 0x50(%rax,%rsi,4),%eax) を回す。head の停止点に対応.
    // RAX=0x2000、RSI=0x10、[0x2090]=3、EAX=10 -> EAX=7 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(1).state(), 10);
    // dst ECX を使うため base RAX=0x2000 を保つ。2B 4C B0 50 (ecx) で回す.
    env.backend
        .mem
        .write(VirtAddr(0x2090), &0x03u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x2B, 0x4C, 0xB0, 0x50, // subl 0x50(%rax,%rsi,4),%ecx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(1).state()), 7);
}

#[test]
fn run_dec_rm_sibd_no_index() {
    // run 経由で FF 4C 24 0C (DECL 0x0C(%rsp)) を回す。head の停止点に対応.
    // RSP=0x2000、[0x200C]=1 -> 0 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x200C), &1u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xFF, 0x4C, 0x24, 0x0C, // decl 0x0C(%rsp)
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
            VirtAddr(0x200C),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0);
}

#[test]
fn run_or_m32_r32_sib() {
    // run 経由で 41 09 3C B4 (ORL %edi,(%r12,%rsi,4)) を回す。head の停止点に対応.
    // R12=0x2000、RSI=0x10、[0x2040]=0x0F、EDI=0xF0 -> [0x2040]=0xFF になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(12), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(6).state(), 0x10);
    env.backend.set(Gpr(7).state(), 0xF0);
    env.backend
        .mem
        .write(VirtAddr(0x2040), &0x0Fu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x41, 0x09, 0x3C, 0xB4, // orl %edi,(%r12,%rsi,4)
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
            VirtAddr(0x2040),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0xFF);
}

#[test]
fn run_movsx_r32_r8_rex() {
    // run 経由で 45 0F BE C6 (MOVSX R8D,R14B) を回す。seq の停止点 0x40b775 に対応.
    // R14=0xFF -> R8D=0xFFFFFFFF になり、exit(0)。REX.RB で 8-15 に拡張.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(14), 0xFF);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x45, 0x0F, 0xBE, 0xC6, // movsx r8d,r14b
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(8).state()), 0xFFFF_FFFF);
}

#[test]
fn run_jmp_r_sib() {
    // run 経由で FF 24 CA (JMP [RDX+RCX*8]) を回す。seq の停止点 0x40c83b に対応.
    // RDX=0x2000、RCX=0、[0x2000]=0x1010 -> 0x1010 へ飛び、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(2).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x1010u64.to_le_bytes())
        .unwrap();
    let jmp: &[u8] = &[0xFF, 0x24, 0xCA]; // jmp [rdx+rcx*8]
    let exit: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), jmp).unwrap();
    env.backend.mem.write(VirtAddr(0x1010), exit).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_jmp_r_mem8() {
    // run 経由で FF 60 18 (JMP [RAX+0x18]) を回す。seq の停止点 0x47e635 に対応.
    // RAX=0x2000、[0x2018]=0x1010 -> 0x1010 へ飛び、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2018), &0x1010u64.to_le_bytes())
        .unwrap();
    let jmp: &[u8] = &[0xFF, 0x60, 0x18]; // jmp [rax+0x18]
    let exit: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), jmp).unwrap();
    env.backend.mem.write(VirtAddr(0x1010), exit).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_or_rm8_imm_sibd() {
    // run 経由で 80 4C 04 F8 00 (ORB $0,-8(%rsp)) を回す。seq の停止点 0x45b828 に対応.
    // RSP=0x2000、[0x1FF8]=0xF0 -> 0xF0 のまま、ZF=0 になり、exit(0)。mov は旗を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x1FF8), &[0xF0u8]).unwrap();
    let prog: &[u8] = &[
        0x80, 0x4C, 0x04, 0xF8, 0x00, // orb $0,-8(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x1FF8),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0xF0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_mov_rm8_imm_sibd_no_index() {
    // run 経由で C6 44 24 0B 00 (MOVB $0,0x0B(%rsp)) を回す。head の停止点 0x5a945a に対応.
    // RSP=0x2000、[0x200B]=0xFF -> 0x00 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x200B), &[0xFFu8]).unwrap();
    let prog: &[u8] = &[
        0xC6, 0x44, 0x24, 0x0B, 0x00, // movb $0,0x0B(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x200B),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x00);
}

#[test]
fn run_mov_rm8_imm_sib_no_index() {
    // run 経由で C6 04 24 3A (MOVB $0x3A,(%rsp)) を回す。
    // RSP=0x2000、[0x2000]=0 -> 0x3A になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x2000), &[0u8]).unwrap();
    let prog: &[u8] = &[
        0xC6, 0x04, 0x24, 0x3A, // movb $0x3A,(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x3A);
}

#[test]
fn run_or_r8_m8_sibd() {
    // run 経由で 0A 44 24 0A (OR AL,[RSP+0x0A]) を回す。head の停止点 0x5a96cc に対応.
    // AL=0xF0、[0x200A]=0x0F -> AL=0xFF になり、exit(0)。mov は AL を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0xF0);
    env.backend.mem.write(VirtAddr(0x200A), &[0x0Fu8]).unwrap();
    let prog: &[u8] = &[
        0x0A, 0x44, 0x24, 0x0A, // or al,[rsp+0x0A]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    // AL は exit 系列で潰れるため flags で確認: 0xFF -> ZF=0.
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_or_r8_m8_rip() {
    // run 経由で 0A 05 + disp32 (OR AL,[RIP]) を回す。find 0x5c44a7 対応.
    // next_rip=0x1006、disp=0xFFA -> [0x2000]=0x0F、AL=0xF0 -> AL=0xFF、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0xF0);
    env.backend.mem.write(VirtAddr(0x2000), &[0x0Fu8]).unwrap();
    let prog: &[u8] = &[
        0x0A, 0x05, 0xFA, 0x0F, 0x00, 0x00, // or al,[rip+0xFFA]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    // AL は exit 系列で潰れるため flags で確認: 0xFF -> ZF=0.
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_or_r8_r8() {
    // run 経由で 0A C3 (OR AL,BL) を回す。
    // AL=0xF0、BL=0x0F -> AL=0xFF になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0xF0);
    env.backend.set(Gpr(3).state(), 0x0F);
    let prog: &[u8] = &[
        0x0A, 0xC3, // or al,bl
        0x88, 0x05, 0xF8, 0x0F, 0x00, 0x00, // mov [rip+0xFF8],al -> [0x2000]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0xFF);
}

#[test]
fn run_shr_rm8_imm8() {
    // run 経由で C0 E8 05 (SHRB $5,%al) を回す。head の停止点 0x4c9097 に対応.
    // AL=0xFF -> AL=0x07、CF=1。exit 系列で AL が潰れるため [0x2000] に退避して検証.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0xFF);
    let prog: &[u8] = &[
        0xC0, 0xE8, 0x05, // shrb $5,%al
        0x88, 0x05, 0xF7, 0x0F, 0x00, 0x00, // mov [rip+0xFF7],al -> [0x2000]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x07);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        1
    );
}

#[test]
fn run_shr_r11b_rex() {
    // run 経由で 41 C0 EB 05 (SHRB $5,%r11b) を回す。grep 0x439314 対応.
    // R11B=0xFF -> R11B=0x07、CF=1、exit(0)。R11B は exit 系列で潰れない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(11), 0xFF);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x41, 0xC0, 0xEB, 0x05, // shrb $5,%r11b (REX.B)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(11).state()) & 0xFF, 0x07);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        1
    );
}

#[test]
fn run_shr_r13b_1_rex() {
    // run 経由で 41 D0 ED (SHRB %r13b) を回す。sed 0x5bdd7d 対応.
    // R13B=0x03 -> R13B=0x01、CF=1、exit(0)。R13B は exit 系列で潰れない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(13), 0x03);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x41, 0xD0, 0xED, // shrb %r13b (REX.B, count=1)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(13).state()) & 0xFF, 0x01);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        1
    );
}

#[test]
fn run_dec_rm_mem8_nosib() {
    // run 経由で FF 4B 2C (DECL 0x2C(%rbx)) を回す。head の停止点に対応.
    // RBX=0x2000、[0x202C]=1 -> 0 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x202C), &1u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xFF, 0x4B, 0x2C, // decl 0x2C(%rbx)
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
            VirtAddr(0x202C),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0);
}

#[test]
fn run_inc_rm_mem8_nosib() {
    // run 経由で FF 43 2C (INCL 0x2C(%rbx)) を回す。
    // RBX=0x2000、[0x202C]=0 -> 1 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x202C), &0u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xFF, 0x43, 0x2C, // incl 0x2C(%rbx)
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
            VirtAddr(0x202C),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 1);
}

#[test]
fn run_inc_rm_rip() {
    // run 経由で FF 05 FA 0F 00 00 (INCL 0xFFA(%rip)) を回す。sed 0x5bdcc0 対応.
    // [0x2000]=0 -> 1 になり、exit(0)。RIP=0x1006 が next_rip.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xFF, 0x05, 0xFA, 0x0F, 0x00, 0x00, // incl 0xFFA(%rip) -> [0x2000]
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
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 1);
}

#[test]
fn run_dec_rm_rip() {
    // run 経由で FF 0D FA 0F 00 00 (DECL 0xFFA(%rip)) を回す。du -s 0x5a7fe7 対応.
    // [0x2000]=1 -> 0 になり、exit(0)。RIP=0x1006 が next_rip.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &1u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xFF, 0x0D, 0xFA, 0x0F, 0x00, 0x00, // decl 0xFFA(%rip) -> [0x2000]
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
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0);
}

#[test]
fn run_call_r_memnd_rexb() {
    // run 経由で 41 FF 17 (CALL (%r15) with REX.B) を回す。find -name 0x5c3479 対応.
    // R15=0x2400、[0x2400]=0x1100 (exit 系列)、RSP=0x2800。CALL で 0x1100 へ飛び exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(15), 0x2400);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(4).state(), 0x2800);
    env.backend
        .mem
        .write(VirtAddr(0x2400), &0x1100u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x41, 0xFF, 0x17, // call (%r15)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let exit: &[u8] = &[
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1100), exit).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_mov_rm16_imm_rip() {
    // run 経由で 66 C7 05 F7 0F 00 00 34 12 (MOVW [RIP+0xFF7],0x1234) を回す。od 0x5ac863 対応.
    // [0x2000]==0x1234 になり、exit(0)。RIP=0x1009 が next_rip.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0u16.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0xC7, 0x05, 0xF7, 0x0F, 0x00, 0x00, 0x34,
        0x12, // movw [rip+0xFF7],0x1234 -> [0x2000]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x1234);
}

#[test]
fn run_test_rm32_imm_memnd() {
    // run 経由で F7 00 FD FF FF FF (TESTL $0xFFFFFFFD,(%rax)) を回す。tac 0x5b0ca8 対応.
    // RAX=0x2000、[0x2000]=0xFFFFFFFF -> ZF=0、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xFFFF_FFFFu32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xF7, 0x00, 0xFD, 0xFF, 0xFF, 0xFF, // testl $0xfffffffd,(%rax)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
}

#[test]
fn run_add_r_sib_indexed() {
    // run 経由で 03 0C 9F (ADD ECX,[RDI+RBX*4]) を回す。md5sum 0x5ca46d 対応 (REX 剥がし済み形).
    // RDI=0x2000、RBX=0x10、[0x2040]=5、ECX=3 -> ECX=8、exit(0)。ECX は exit 系列で潰れない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x10);
    env.backend.set(Gpr(1).state(), 3);
    env.backend
        .mem
        .write(VirtAddr(0x2040), &5u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x03, 0x0C, 0x9F, // add ecx,[rdi+rbx*4]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(1).state()), 8);
}

#[test]
fn run_xor_r8_m8_memnd() {
    // run 経由で 32 06 (XOR AL,[RSI]) を回す。cksum 0x5c7fc7 対応.
    // RSI=0x2000、[0x2000]=0x0F、AL=0x0F -> AL=0、ZF=1、exit(0)。AL は exit 系列で潰れるため ZF で検証.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(6).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x0F);
    env.backend.mem.write(VirtAddr(0x2000), &[0x0Fu8]).unwrap();
    let prog: &[u8] = &[
        0x32, 0x06, // xor al,[rsi]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_cmp_r_sib_no_index() {
    // run 経由で 48 3B 04 24 (CMP RAX,[RSP] with REX.W) を回す。mv 0x5ab8fb 対応.
    // RSP=0x2000、[0x2000]=5、RAX=5 -> ZF=1、exit(0)。RAX は exit 系列で潰れるため ZF で検証.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 5);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &5u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x48, 0x3B, 0x04, 0x24, // cmp rax,[rsp]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_cmovne_r64_rip() {
    // run 経由で 48 0F 45 1D F9 0F 00 00 (CMOVNE RBX,[RIP+0xFF9]) を回す。ln 0x5a9e44 対応.
    // [0x2000]=0x1122334455667788、RBX=0、ZF=0 -> RBX=[0x2000]、exit(0)。RBX は exit 系列で潰れない.
    // RIP=0x1008 が next_rip.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0);
    let prog: &[u8] = &[
        0x48, 0x0F, 0x45, 0x1D, 0xF8, 0x0F, 0x00, 0x00, // cmovne rbx,[rip+0xFF8] -> [0x2000]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(3));
    assert_eq!(v, 0x1122_3344_5566_7788);
}

#[test]
fn run_sub_m8_r8_reg_direct() {
    // run 経由で 28 D1 (SUB CL,DL) を回す。
    // ECX=5、EDX=3 -> CL=2、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(1).state(), 5);
    env.backend.set(Gpr(2).state(), 3);
    let prog: &[u8] = &[
        0x28, 0xD1, // sub cl,dl (cl=2)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(1).state()) & 0xFF, 2);
}

#[test]
fn run_xor_m8_r8_reg_direct() {
    // run 経由で 30 C0 (XOR AL,AL) を回す。
    // EAX=0xFF -> AL=0、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0xFF);
    let prog: &[u8] = &[
        0x30, 0xC0, // xor al,al (al=0)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_movsx_r64_m8_memnd() {
    // run 経由で REX.W 0F BE 13 (MOVSX RDX,[RBX]) を回す。
    // [0x2000]=0xFF -> RDX=0xFFFFFFFFFFFFFFFF、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x2000), &[0xFF]).unwrap();
    let prog: &[u8] = &[
        0x48, 0x0F, 0xBE, 0x13, // movsx rdx,[rbx] (REX.W)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    // RDX 全64ビットが符号拡張されていること。
    let lo = env.backend.get(Gpr(2).state()) as u64;
    let hi = env.backend.get(polyisa_guest_x86::sem::hi_ref(Gpr(2))) as u64;
    assert_eq!((hi << 32) | lo, 0xFFFF_FFFF_FFFF_FFFFu64);
}

#[test]
fn run_mov_rm16_imm_sibd32() {
    // 66 C7 84 03 6E 0E 00 00 08 00 = movw $0x8, 0xe6e(%rbx,%rax)。gzip 0x485910。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 1);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x66, 0xC7, 0x84, 0x03, 0x6E, 0x0E, 0x00, 0x00, 0x08, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x100A });
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2E6F),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x08, 0x00]);
}

#[test]
fn run_mov_rm16_imm_disp32() {
    // 66 C7 83 CE 12 00 00 08 00 = movw $0x8, 0x12ce(%rbx)。gzip 0x485966。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x66, 0xC7, 0x83, 0xCE, 0x12, 0x00, 0x00, 0x08, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1009 });
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x32CE),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x08, 0x00]);
}

#[test]
fn run_mov_m16_r16_sibd32() {
    // 66 89 8C 93 EC 12 00 00 = movw %cx, 0x12ec(%rbx,%rdx,4)。gzip 0x4859e4。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend.set(Gpr(2).state(), 1);
    env.backend.set(Gpr(1).state(), 0xABCD);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x66, 0x89, 0x8C, 0x93, 0xEC, 0x12, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x32F0),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0xCD, 0xAB]);
}

#[test]
fn run_inc_r16_sibd32() {
    // 66 FF 84 B0 84 04 00 00 = incw 0x484(%rax,%rsi,4)。gzip 0x484ac0。
    // 0x7fff は 0x8000 になり、CF は残し OF と SF が立つ。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.set(Gpr(6).state(), 1);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x1);
    env.backend
        .mem
        .write(VirtAddr(0x2488), &[0xFF, 0x7F])
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x66, 0xFF, 0x84, 0xB0, 0x84, 0x04, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2488),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x00, 0x80]);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
        0x895
    );
}

#[test]
fn run_shl_m8_1_mem32() {
    // D0 A0 F1 2A 00 00 = shlb 0x2af1(%rax)。gzip 0x484b2e。
    // 0x81 は 0x02 になり、CF と OF が立つ。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x4AF1), &[0x81]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD0, 0xA0, 0xF1, 0x2A, 0x00, 0x00])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x4AF1),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x02]);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8C5,
        0x801
    );
}

#[test]
fn run_cmp_m16_imm8_sib() {
    // 66 83 3C 87 00 = cmpw $0, (%rdi,%rax,4)。gzip 0x4846ab。
    // 0 との比較は ZF を立て、0 以外は立てない。メモリは変えない。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, flags) in [([0x00, 0x00], 0x44u32), ([0x01, 0x00], 0x00)] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(7).state(), 0x2000);
        env.backend.set(Gpr(0).state(), 1);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x2004), &mem).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x66, 0x83, 0x3C, 0x87, 0x00])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(
                VirtAddr(0x2004),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back, mem);
    }
}

#[test]
fn run_cmp_m16_r16_memnd() {
    // 66 45 39 03 = cmpw %r8w, (%r11)。gzip 0x4845d8。
    // 同値は ZF。差が 1 のときは旗が立たない。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, src, flags) in [([0xAB, 0x00], 0xABu64, 0x44u32), ([0x02, 0x00], 0x01, 0x00)] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(11), 0x2000);
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(8), src);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x2000), &mem).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x66, 0x45, 0x39, 0x03])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
    }
}

#[test]
fn run_cmp_m16_r16_sib() {
    // 66 46 39 24 AF = cmpw %r12w, (%rdi,%r13,4)。gzip 0x4845a8。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, src, flags) in [([0xAB, 0x00], 0xABu64, 0x44u32), ([0x02, 0x00], 0x01, 0x00)] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(7).state(), 0x2000);
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(13), 1);
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(12), src);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x2004), &mem).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x66, 0x46, 0x39, 0x24, 0xAF])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
    }
}

#[test]
fn run_mov_r16_m16_memnd() {
    // 66 8B 06 = movw (%rsi), %ax。gzip 0x4847b6。上位16ビットは残す。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(6).state(), 0x2000);
    env.backend.set(Gpr(0).state(), 0x1111_0000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &[0xEF, 0xBE])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x8B, 0x06])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(env.backend.get(Gpr(0).state()), 0x1111_BEEF);
}

#[test]
fn run_add_r16_memnd() {
    // 66 03 01 = addw (%rcx), %ax。gzip 0x4847b9。上位16ビットは残す。
    // 0x7fff+1 は 0x8000 になり OF と SF が立つ。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (ax, mem, eax, flags) in [
        (0x0002u32, [0x01, 0x00], 0x1111_0003u32, 0x04u32),
        (0x7fff, [0x01, 0x00], 0x1111_8000, 0x894),
    ] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(1).state(), 0x2000);
        env.backend.set(Gpr(0).state(), 0x1111_0000 | ax);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x2000), &mem).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x66, 0x03, 0x01])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
        assert_eq!(env.backend.get(Gpr(0).state()), eax);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
    }
}

#[test]
fn run_dec_rm_mem32() {
    // FF 8B F4 2A 00 00 = decl 0x2af4(%rbx)。gzip 0x484714。CF は残す。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, flags, outb) in [
        ([0x05, 0x00, 0x00, 0x00], 0x01u32, [0x04, 0x00, 0x00, 0x00]),
        ([0x01, 0x00, 0x00, 0x00], 0x45, [0x00, 0x00, 0x00, 0x00]),
    ] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(3).state(), 0x2000);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
        env.backend.mem.write(VirtAddr(0x4AF4), &mem).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0xFF, 0x8B, 0xF4, 0x2A, 0x00, 0x00])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(
                VirtAddr(0x4AF4),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back, outb);
    }
}

#[test]
fn run_sub_m32_r32_mem32() {
    // 29 83 F8 2A 00 00 = subl %eax, 0x2af8(%rbx)。gzip 0x48473b。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, eax, flags, outb) in [
        (
            [0x05, 0x00, 0x00, 0x00],
            1u32,
            0x00u32,
            [0x04, 0x00, 0x00, 0x00],
        ),
        ([0x00, 0x00, 0x00, 0x00], 1, 0x95, [0xFF, 0xFF, 0xFF, 0xFF]),
    ] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(3).state(), 0x2000);
        env.backend.set(Gpr(0).state(), eax);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x4AF8), &mem).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x29, 0x83, 0xF8, 0x2A, 0x00, 0x00])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
        assert_eq!(env.backend.get(Gpr(0).state()), eax);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(
                VirtAddr(0x4AF8),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back, outb);
    }
}

#[test]
fn run_inc_r16_mem32() {
    // 66 FF 82 A8 13 00 00 = incw 0x13a8(%rdx)。gzip 0x484a42。
    // 0x7fff は 0x8000 になり、CF は残し OF と SF が立つ。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(2).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x1);
    env.backend
        .mem
        .write(VirtAddr(0x33A8), &[0xFF, 0x7F])
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x66, 0xFF, 0x82, 0xA8, 0x13, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x33A8),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x00, 0x80]);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
        0x895
    );
}

#[test]
fn run_add_m16_r16_sibd32() {
    // 66 42 01 8C 82 64 13 00 00 = addw %cx, 0x1364(%rdx,%r8,4)。gzip 0x484a11。
    // 0x7fff+1 は 0x8000 になり OF と SF が立つ。%ecx の上位は残る。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, flags, outb) in [
        ([0x02, 0x00], 0x04u32, [0x03, 0x00]),
        ([0xFF, 0x7F], 0x894, [0x00, 0x80]),
    ] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(2).state(), 0x2000);
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(8), 1);
        env.backend.set(Gpr(1).state(), 0x1111_0001);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x3368), &mem).unwrap();
        env.backend
            .mem
            .write(
                VirtAddr(0x1000),
                &[0x66, 0x42, 0x01, 0x8C, 0x82, 0x64, 0x13, 0x00, 0x00],
            )
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1009 });
        assert_eq!(env.backend.get(Gpr(1).state()), 0x1111_0001);
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(
                VirtAddr(0x3368),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back, outb);
    }
}

#[test]
fn run_cmp_m16_imm8_sibd32() {
    // 66 41 83 BC 8C 66 13 00 00 00 = cmpw $0, 0x1366(%r12,%rcx,4)。gzip 0x485212。
    // 0 との比較は ZF を立て、1 は立てない。メモリは変えない。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, flags) in [([0x00, 0x00], 0x44u32), ([0x01, 0x00], 0x00)] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(12), 0x2000);
        env.backend.set(Gpr(1).state(), 1);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x336A), &mem).unwrap();
        env.backend
            .mem
            .write(
                VirtAddr(0x1000),
                &[0x66, 0x41, 0x83, 0xBC, 0x8C, 0x66, 0x13, 0x00, 0x00, 0x00],
            )
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x100A });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
        let mut back = [0u8; 2];
        env.backend
            .mem
            .read(
                VirtAddr(0x336A),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back, mem);
    }
}

#[test]
fn run_and_m64_r64_memnd() {
    // 48 21 07 = andq %rax, (%rdi)。0xff & 0x0f = 0x0f。%rax は変わらない。chat 0x4d3473。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(7), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x0F);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xFFu64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x21, 0x07])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0)),
        0x0F
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8C5,
        0x04
    );
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 0x0F);
}

#[test]
fn run_and_m32_r32_sib() {
    // 41 21 0C 94 = andl %ecx, (%r12,%rdx,4)。bzip2 0x47f93d。
    // 0xff & 0x0f = 0x0f。%ecx は変わらない。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(12), 0x2000);
    env.backend.set(Gpr(2).state(), 1);
    env.backend.set(Gpr(1).state(), 0x1111_000F);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x2004), &[0xFF, 0x00, 0x00, 0x00])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x41, 0x21, 0x0C, 0x94])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(Gpr(1).state()), 0x1111_000F);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8C5,
        0x04
    );
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2004),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back, [0x0F, 0x00, 0x00, 0x00]);
}

#[test]
fn run_or_m64_r64_sibabs() {
    // F0 48 09 04 CD 00 20 00 00 = lock orq %rax, 0x2000(,%rcx,8)。dd 0x4cde65。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let code = [0xF0u8, 0x48, 0x09, 0x04, 0xCD, 0x00, 0x20, 0x00, 0x00];
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (rax, mem, flags, out) in [(0x0Fu64, 0xF0u64, 0x04u32, 0xFFu64), (0, 0, 0x44, 0)] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(0).state(), rax as u32);
        env.backend.set(Gpr(1).state(), 1);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend
            .mem
            .write(VirtAddr(0x2008), &mem.to_le_bytes())
            .unwrap();
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let mut sys = X64Exit;
        let got = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(got, Outcome::StepLimit { eip: 0x1009 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8C5,
            flags
        );
        let mut back = [0u8; 8];
        env.backend
            .mem
            .read(
                VirtAddr(0x2008),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(u64::from_le_bytes(back), out);
    }
}

#[test]
fn run_or_r64_sibd32() {
    // 48 0B 94 07 98 00 00 00 = orq 0x98(%rdi,%rax), %rdx。bzip2 0x480ec8。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let code = [0x48u8, 0x0B, 0x94, 0x07, 0x98, 0x00, 0x00, 0x00];
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (rdx, mem, flags, out) in [(0x0Fu32, 0xF0u64, 0x04u32, 0xFFu64), (0, 0, 0x44, 0)] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(7).state(), 0x2000);
        env.backend.set(Gpr(0).state(), 1);
        env.backend.set(Gpr(2).state(), rdx);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend
            .mem
            .write(VirtAddr(0x2099), &mem.to_le_bytes())
            .unwrap();
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let mut sys = X64Exit;
        let got = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(got, Outcome::StepLimit { eip: 0x1008 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8C5,
            flags
        );
        let lo = env.backend.get(Gpr(2).state()) as u64;
        let hi = env.backend.get(polyisa_guest_x86::sem::hi_ref(Gpr(2))) as u64;
        assert_eq!((hi << 32) | lo, out);
    }
}

#[test]
fn run_add_rm64_imm_sibd() {
    // 48 81 44 24 28 02 01 00 00 = addq $0x102, 0x28(%rsp)。bzip2 0x480dcd。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let code = [0x48u8, 0x81, 0x44, 0x24, 0x28, 0x02, 0x01, 0x00, 0x00];
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, flags, outb) in [(1u64, 0x04u32, 0x103u64), (0xFFFF_FFFF_FFFF_FF00, 0x01, 2)] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(4).state(), 0x2000);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend
            .mem
            .write(VirtAddr(0x2028), &mem.to_le_bytes())
            .unwrap();
        env.backend.mem.write(VirtAddr(0x1000), &code).unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1009 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8D5,
            flags
        );
        let mut back = [0u8; 8];
        env.backend
            .mem
            .read(
                VirtAddr(0x2028),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(u64::from_le_bytes(back), outb);
    }
}

#[test]
fn run_shl_m32_imm8_mem8() {
    // C1 67 70 08 = shll $8, 0x70(%rdi)。bzip2 0x480237。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    for (mem, flags, outb) in [
        ([0x81, 0x00, 0x00, 0x00], 0x04u32, [0x00, 0x81, 0x00, 0x00]),
        ([0x00, 0x00, 0x00, 0x01], 0x45, [0x00, 0x00, 0x00, 0x00]),
    ] {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(7).state(), 0x2000);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend.mem.write(VirtAddr(0x2070), &mem).unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0xC1, 0x67, 0x70, 0x08])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
        assert_eq!(
            env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x8C5,
            flags
        );
        let mut back = [0u8; 4];
        env.backend
            .mem
            .read(
                VirtAddr(0x2070),
                &mut back,
                polyisa_mem::Access {
                    endian: polyisa_mem::Endian::Le,
                    align: polyisa_mem::Align::Unaligned,
                    kind: polyisa_mem::AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(back, outb);
    }
}

#[test]
fn run_imul_r64_imm_sib() {
    // 48 69 0C 24 40 42 0F 00 = imulq $0xf4240, (%rsp), %rcx。2*1000000=2000000。
    // dd 0x4067c3。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &2u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x48, 0x69, 0x0C, 0x24, 0x40, 0x42, 0x0F, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let lo = env.backend.get(Gpr(1).state()) as u64;
    let hi = env.backend.get(polyisa_guest_x86::sem::hi_ref(Gpr(1))) as u64;
    assert_eq!((hi << 32) | lo, 0x1E_8480);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 1);
}

#[test]
fn run_or_sil_rcx_disp8() {
    // 40 0A 71 FF = or sil, BYTE PTR [rcx-1]。0xf0|0x0f は 0xff。上位は残る。uudecode 0x49da3e。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(6), 0x1111_2222_3333_00F0);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 0x2011);
    env.backend.mem.write(VirtAddr(0x2010), &[0x0F]).unwrap();
    env.backend.mem.write(VirtAddr(0x2011), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x40, 0x0A, 0x71, 0xFF])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let rsi: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(6));
    let rcx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(1));
    assert_eq!(rsi, 0x1111_2222_3333_00FF);
    assert_eq!(rcx, 0x2011);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x84);
    let mut nb = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb, [0x0F, 0xAB]);
}

#[test]
fn run_movzx_r9d_rdx_scale_abs() {
    // 44 0F B7 0C 95 00 20 00 00 = movzx r9d, WORD PTR [rdx*4+0x2000]。上位は消える。microcom 0x4bc4f2。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 4);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(9), 0x1111_2222_3333_4444);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0x8001u16.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2012), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x44, 0x0F, 0xB7, 0x0C, 0x95, 0x00, 0x20, 0x00, 0x00],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1009 });
    let r9: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(9));
    let rdx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(2));
    assert_eq!(r9, 0x8001);
    assert_eq!(rdx, 4);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2012),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_movsx_esi_si() {
    // 0F BF F6 = movsx esi, si。0x8000 は 0xffff8000。上位 32 は消える。man 0x4d80c6。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(6), 0x1111_2222_3333_8000);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x0F, 0xBF, 0xF6])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let rsi: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(6));
    assert_eq!(rsi, 0xFFFF_8000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_div_dl() {
    // F6 F2 = div dl。AX=0x107、DL=5 なら商 0x34、剰余 3。上位とフラグと DL は残る。lzcat 0x48b6ef。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x1111_2222_3333_0107);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 0xAAAA_BBBB_CCCC_0005);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF6, 0xF2])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    let rax: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0));
    let rdx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(2));
    assert_eq!(rax, 0x1111_2222_3333_0334);
    assert_eq!(rdx, 0xAAAA_BBBB_CCCC_0005);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_and_ax_r12_scale_disp32() {
    // 66 43 23 84 24 10 00 00 00 = and ax, [r12+r12+0x10]。0xff&0x0f は 0x0f。上位は残る。gunzip 0x48a957。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(12), 0x1000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x1111_2222_FFFF_00FF);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0x000Fu16.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2012), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x66, 0x43, 0x23, 0x84, 0x24, 0x10, 0x00, 0x00, 0x00],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1009 });
    let rax: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0));
    assert_eq!(rax, 0x1111_2222_FFFF_000F);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x04);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2012),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_xor_rsp_disp8_ecx() {
    // 31 4C 24 08 = xor DWORD PTR [rsp+0x8], ecx。1^1 は 0 で ZF。ecx と rsp は残る。gunzip 0x48a1c3。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 0x9999_8888_0000_0001);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x0000_0001u32.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x200C), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x31, 0x4C, 0x24, 0x08])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let rsp: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(4));
    let rcx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(1));
    assert_eq!(rsp, 0x2000);
    assert_eq!(rcx, 0x9999_8888_0000_0001);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
    let mut nb = [0u8; 5];
    env.backend
        .mem
        .read(
            VirtAddr(0x2008),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb, [0x00, 0x00, 0x00, 0x00, 0xAB]);
}

#[test]
fn run_cmovbe_edx_r8() {
    // 41 0F 46 10 = cmovbe edx, DWORD PTR [r8]。CF があるので移す。上位 32 は消える。gunzip 0x48a025。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(8), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 0x3333_4444_1111_2222);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xAABBCCDDu32.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2004), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x41, 0x0F, 0x46, 0x10])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let rdx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(2));
    assert_eq!(rdx, 0xAABBCCDD);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2004),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_test_r14w_imm() {
    // 66 41 F7 C6 00 02 = test r14w, 0x200。下位16が 0 なので ZF。上位は残る。gunzip 0x48b06a。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(14), 0x1111_2222_3333_0000);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x41, 0xF7, 0xC6, 0x00, 0x02])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let r14: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(14));
    assert_eq!(r14, 0x1111_2222_3333_0000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
}

#[test]
fn run_cmp_m16_imm_rbx_disp8() {
    // 66 83 7B 04 0A = cmpw $0xa, 0x4(%rbx)。等しいので ZF。メモリと rbx は残る。ping 0x42e7b3。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(3), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2004), &0x000Au16.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2006), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x83, 0x7B, 0x04, 0x0A])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let rbx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(3));
    assert_eq!(rbx, 0x2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2006),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_test_m8_imm_rsp_disp32() {
    // F6 84 24 10 00 00 00 01 = test BYTE PTR [rsp+0x10], 1。0&1 は ZF。メモリと rsp は残る。ping 0x4c4288。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &[0x00, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xF6, 0x84, 0x24, 0x10, 0x00, 0x00, 0x00, 0x01],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let rsp: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(4));
    assert_eq!(rsp, 0x2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
    let mut nb = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb, [0x00, 0xAB]);
}

#[test]
fn run_cmp_m16_imm_rdi() {
    // 66 83 3F 02 = cmpw $2, (%rdi)。等しいので ZF。メモリと rdi は残る。ping 0x4be1f1。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(7), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &2u16.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2002), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x83, 0x3F, 0x02])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let rdi: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(7));
    assert_eq!(rdi, 0x2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2002),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_minsd_xmm() {
    // F2 0F 5D C1 = minsd xmm0, xmm1。4.0 と 2.0 の小さい方は 2.0。上位64は残る。ping 0x42e6d9。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF2, 0x0F, 0x5D, 0xC1])
        .unwrap();
    env.backend.set(
        polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
        (0x1111_2222_3333_4444_u128 << 64) | 0x4010_0000_0000_0000,
    );
    env.backend.set(
        polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(1)),
        0x4000_0000_0000_0000_u128,
    );
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(
        v,
        (0x1111_2222_3333_4444_u128 << 64) | 0x4000_0000_0000_0000
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_mov_dx_r14_disp8() {
    // 66 41 8B 56 12 = movw 0x12(%r14), %dx。下位16だけ置き、上位は残る。pgrep 0x44b629。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(14), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 0x1111_2222_3333_4455);
    env.backend
        .mem
        .write(VirtAddr(0x2012), &0xABCDu16.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2014), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x41, 0x8B, 0x56, 0x12])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let edx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(2));
    assert_eq!(edx, 0x1111_2222_3333_ABCD);
    let r14: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(14));
    assert_eq!(r14, 0x2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2014),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_imul_eax_rip_imm32() {
    // 69 05 F6 0F 00 00 05 00 00 00 = imul eax, [rip+0xff6], 5。3*5=15。上位は消える。nslookup 0x42bb05。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x1111_0000_0000_0007);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &3u32.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2004), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x69, 0x05, 0xF6, 0x0F, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x100A });
    let eax: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0));
    assert_eq!(eax, 15);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2004),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_xor_rm8_imm_rax() {
    // 80 30 01 = xorb $1, (%rax)。1^1=0 で ZF。隣接バイトと rax は残る。nmeter 0x44a570。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &[0x01, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x80, 0x30, 0x01])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let rax: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0));
    assert_eq!(rax, 0x2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
    let mut nb = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb, [0x00, 0xAB]);
}

#[test]
fn run_cmp_imm_rsp_disp8() {
    // 81 7C 24 0C FF 00 00 00 = cmpl $0xff, 0xc(%rsp)。等しいので ZF。メモリと rsp は残る。nc 0x4c68d6。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x200C), &0xffu32.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2010), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x81, 0x7C, 0x24, 0x0C, 0xFF, 0x00, 0x00, 0x00],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let rsp: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(4));
    assert_eq!(rsp, 0x2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_movsx_eax_rsp_disp32() {
    // 0F BE 84 24 FA 00 00 00 = movsbl 0xfa(%rsp), %eax。0x80 は符号拡張。上位は消える。nc 0x4c71fd。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x1111_0000_0000_00AA);
    env.backend
        .mem
        .write(VirtAddr(0x20FA), &[0x80, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x0F, 0xBE, 0x84, 0x24, 0xFA, 0x00, 0x00, 0x00],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let eax: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0));
    assert_eq!(eax, 0xffff_ff80);
    let rsp: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(4));
    assert_eq!(rsp, 0x2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x20FB),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_or_r11d_rdx_scale_disp32() {
    // 44 0B 1C 95 00 20 00 00 = or r11d, [rdx*4+0x2000]。1|2=3。上位は消える。cryptpw 0x4bb2e0。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(11), 0x1111_0000_0000_0001);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2004), &2u32.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2008), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x44, 0x0B, 0x1C, 0x95, 0x00, 0x20, 0x00, 0x00],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let r11: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(11));
    assert_eq!(r11, 3);
    let rdx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(2));
    assert_eq!(rdx, 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x04);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2008),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_imul_eax_rdx_scale_disp32() {
    // 0F AF 04 95 00 20 00 00 = imul eax, [rdx*4+0x2000]。3*5=15。上位は消える。フラグは残る。awk 0x4d6114。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x9ABC_0000_0000_0003);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2004), &5u32.to_le_bytes())
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2008), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x0F, 0xAF, 0x04, 0x95, 0x00, 0x20, 0x00, 0x00],
        )
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let eax: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0));
    assert_eq!(eax, 15);
    let rdx: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(2));
    assert_eq!(rdx, 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
    let mut nb = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x2008),
            &mut nb,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(nb[0], 0xAB);
}

#[test]
fn run_cvtsi2sd_rsp_nodisp() {
    // F2 48 0F 2A 0C 24 = cvtsi2sdq (%rsp), %xmm1。整数 2 は 2.0。上位 64 は残る。ntpd 0x42cb3e。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &2i64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF2, 0x48, 0x0F, 0x2A, 0x0C, 0x24])
        .unwrap();
    env.backend.set(
        polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(1)),
        0x1111_2222_3333_4444_u128 << 64,
    );
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(1),
    ));
    assert_eq!(
        v,
        (0x1111_2222_3333_4444_u128 << 64) | 0x4000_0000_0000_0000
    );
}

#[test]
fn run_cvtsi2sd_rsp_disp8() {
    // F2 48 0F 2A 44 24 08 = cvtsi2sdq 0x8(%rsp), %xmm0。整数 2 は 2.0。上位 64 は残る。ntpd 0x42cb2f。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &2i64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xF2, 0x48, 0x0F, 0x2A, 0x44, 0x24, 0x08],
        )
        .unwrap();
    env.backend.set(
        polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
        0x1111_2222_3333_4444_u128 << 64,
    );
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(
        v,
        (0x1111_2222_3333_4444_u128 << 64) | 0x4000_0000_0000_0000
    );
}

#[test]
fn run_or_m8_al_rbx() {
    // 08 43 18 = orb %al, 0x18(%rbx)。0x03 と 0x01 は 0x03。AL は残る。powertop 0x44c15c。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(3), 0x2000);
    env.backend.set(Gpr(0).state(), 0xAB01);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2018), &[0x03, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x08, 0x43, 0x18])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let mut got = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2018),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x03, 0xAB]);
    assert_eq!(env.backend.get(Gpr(0).state()), 0xAB01);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x04);
}

#[test]
fn run_push_m64_rbx_disp8() {
    // FF 73 40 = pushq 0x40(%rbx)。変位の 8 バイトを積み、RSP は 8 減る。旗は残る。vi 0x4ce196。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(3), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2200);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(
            VirtAddr(0x2040),
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xAB],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xFF, 0x73, 0x40])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let mut got = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x21f8),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    let mut src = [0u8; 9];
    env.backend
        .mem
        .read(
            VirtAddr(0x2040),
            &mut src,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(src, [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xAB]);
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(4)),
        0x21f8
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_pop_m64_rdi_disp8() {
    // 8F 47 40 = popq 0x40(%rdi)。スタックの 8 バイトを写し、RSP は 8 進む。旗は残る。vi 0x4ce187。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2100);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(7), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(
            VirtAddr(0x2100),
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        )
        .unwrap();
    env.backend.mem.write(VirtAddr(0x2048), &[0xAB]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x8F, 0x47, 0x40])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let mut got = [0u8; 9];
    env.backend
        .mem
        .read(
            VirtAddr(0x2040),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xAB]);
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(4)),
        0x2108
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_and_rm32_imm_rbx() {
    // 81 23 FF FA FF FF = andl $0xfffffaff, (%rbx)。0x500 は 0。rbx は残る。vi 0x40511c。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(3), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &[0x00, 0x05, 0x00, 0x00, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x81, 0x23, 0xFF, 0xFA, 0xFF, 0xFF])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let mut got = [0u8; 5];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x00, 0x00, 0x00, 0x00, 0xAB]);
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(3)),
        0x2000
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
}

#[test]
fn run_rol_r12_cl() {
    // 49 D3 C4 = rolq %cl, %r12。4 回で 0x10000001 は 0x100000010。回数 0 は旗を残す。sha3sum 0x4b45f6。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(12), 0x1000_0001);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 4);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x49, 0xD3, 0xC4])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(12)),
        0x1_0000_0010
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(12), 0x1000_0001);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 0);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(12)),
        0x1000_0001
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_xor_m64_rcx_rdx_disp32() {
    // 48 31 8A A0 00 00 00 = xorq %rcx, 0xa0(%rdx)。0xf0 と 0xff は 0x0f。rcx は残る。sha3sum 0x4b45c4。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 0xFF);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(
            VirtAddr(0x20a0),
            &[0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0xAB],
        )
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x48, 0x31, 0x8A, 0xA0, 0x00, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    let mut got = [0u8; 9];
    env.backend
        .mem
        .read(
            VirtAddr(0x20a0),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0xAB]);
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(1)),
        0xFF
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x04);
}

#[test]
fn run_xor_m64_rcx_rdx_disp8() {
    // 48 31 4A 28 = xorq %rcx, 0x28(%rdx)。0xf0 と 0xff は 0x0f。rcx は残る。sha3sum 0x4b45b8。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 0xFF);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(
            VirtAddr(0x2028),
            &[0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0xAB],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x31, 0x4A, 0x28])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut got = [0u8; 9];
    env.backend
        .mem
        .read(
            VirtAddr(0x2028),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0xAB]);
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(1)),
        0xFF
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x04);
}

#[test]
fn run_xor_m64_rcx_rdx() {
    // 48 31 0A = xorq %rcx, (%rdx)。0xf0 と 0xff は 0x0f。rcx は残る。sha3sum 0x4b45b5。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(2), 0x2000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 0xFF);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(
            VirtAddr(0x2000),
            &[0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0xAB],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x31, 0x0A])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let mut got = [0u8; 9];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0xAB]);
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(1)),
        0xFF
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x04);
}

#[test]
fn run_add_rm8_imm_rdi_rax() {
    // 80 04 07 80 = addb $-128, (%rdi,%rax,1)。0x01 は 0x81。符号とパリティ。sha3sum 0x4b4f20。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(7), 0x2000);
    env.backend.set(Gpr(0).state(), 0x10);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &[0x01, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x80, 0x04, 0x07, 0x80])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut got = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x81, 0xAB]);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x84);
}

#[test]
fn run_xor_m8_r9_rdi_rdx() {
    // 44 30 0C 17 = xorb %r9b, (%rdi,%rdx,1)。0x07 と 0x06 は 0x01。r9 の上位は残る。sha3sum 0x4b4edd。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(7), 0x2000);
    env.backend.set(Gpr(2).state(), 0x10);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(9), 0x1234_0000_0000_0006);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &[0x07, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x44, 0x30, 0x0C, 0x17])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut got = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x01, 0xAB]);
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(9)),
        0x1234_0000_0000_0006
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0);
}

#[test]
fn run_xor_rm8_imm_rdi_rax() {
    // 80 34 07 06 = xorb $6, (%rdi,%rax,1)。0x07 は 0x01。隣のバイトは残る。sha3sum 0x4b4f14。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(7), 0x2000);
    env.backend.set(Gpr(0).state(), 0x10);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &[0x07, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x80, 0x34, 0x07, 0x06])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut got = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x01, 0xAB]);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0);
}

#[test]
fn run_and_rm32_imm_rsp() {
    // 81 64 24 14 00 FE FF FF = andl $0xfffffe00, 0x14(%rsp)。全ビットは下位9を落とす。script 0x47b0b7。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &[0xFF, 0xFF, 0xFF, 0xFF, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x81, 0x64, 0x24, 0x14, 0x00, 0xFE, 0xFF, 0xFF],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let mut got = [0u8; 5];
    env.backend
        .mem
        .read(
            VirtAddr(0x2014),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x00, 0xFE, 0xFF, 0xFF, 0xAB]);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x84);
}

#[test]
fn run_or_rm32_imm_rsp() {
    // 81 4C 24 1C 80 08 00 00 = orl $0x880, 0x1c(%rsp)。0x0f は 0x88f。キャリーは消える。resize 0x490ea6。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x201c), &[0x0F, 0x00, 0x00, 0x00, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x81, 0x4C, 0x24, 0x1C, 0x80, 0x08, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let mut got = [0u8; 5];
    env.backend
        .mem
        .read(
            VirtAddr(0x201c),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x8F, 0x08, 0x00, 0x00, 0xAB]);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0);
}

#[test]
fn run_cmp_m16_imm8_r12() {
    // 66 41 83 7C 24 14 2E = cmpw $0x2e, 0x14(%r12)。等しいとゼロとパリティ。メモリは残る。rdev 0x4b3703。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(12), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &[0x2E, 0x00, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x66, 0x41, 0x83, 0x7C, 0x24, 0x14, 0x2E],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
    let mut got = [0u8; 3];
    env.backend
        .mem
        .read(
            VirtAddr(0x2014),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x2E, 0x00, 0xAB]);
}

#[test]
fn run_xor_r13w_self() {
    // 66 45 31 ED = xor %r13w, %r13w。下位 16 ビットが 0 になり、ゼロとパリティが立つ。pgrep 0x44b572。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(13), 0x1234_0000_0000_ABCD);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x45, 0x31, 0xED])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(13)),
        0x1234_0000_0000_0000
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x44);
}

#[test]
fn run_imul_r64_imm8_rsp_nodisp() {
    // 48 6B 2C 24 48 = imul $0x48, (%rsp), %rbp。2*72=144。フラグは残る。mpstat 0x449c01。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &2u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x6B, 0x2C, 0x24, 0x48])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(5)),
        144
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_sub_m16_r16_mem8() {
    // 66 29 5D 52 = subw %bx, 0x52(%rbp)。0 から 1 を引くと借り。bx の上位は残る。lpq 0x4c3385。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0xABCD_0001);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x2051), &[0xEE, 0x00, 0x00, 0xCD])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x29, 0x5D, 0x52])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2051),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0xEE, 0xFF, 0xFF, 0xCD]);
    assert_eq!(env.backend.get(Gpr(3).state()), 0xABCD_0001);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x95);
}

#[test]
fn run_movsx_r64_m16_mem8() {
    // 48 0F BF 45 50 = movswq 0x50(%rbp), %rax。0xffff は -1。lpq 0x4c336d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(5), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2050), &0xFFFFu16.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x0F, 0xBF, 0x45, 0x50])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0)),
        u64::MAX
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_rol_bp_imm8() {
    // 66 C1 C5 08 = rol $8, %bp。0x00ab は 0xab00。上位は残る。httpd 0x4be767。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(5).state(), 0x1234_00AB);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0xC1, 0xC5, 0x08])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(Gpr(5).state()), 0x1234_AB00);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x84);
}

#[test]
fn run_sub_r64_sibd32() {
    // 4A 2B AC 2C C0 00 00 00 = subq 0xc0(%rsp,%r13,1), %rbp。1-2 は借り。iostat 0x448b8e。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x1000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(13), 0x1000);
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(5), 1);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x20c0), &2u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x4A, 0x2B, 0xAC, 0x2C, 0xC0, 0x00, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(5)),
        u64::MAX
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x95);
}

#[test]
fn run_xor_rm8_imm_rsp() {
    // 80 74 24 1B 01 = xorb $1, 0x1b(%rsp)。0x03 は 0x02 になり、隣のバイトは残る。iostat 0x448a1f。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x201b), &[0x03, 0xAB])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x80, 0x74, 0x24, 0x1B, 0x01])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let mut got = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x201b),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got, [0x02, 0xAB]);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0);
}

#[test]
fn run_imul_r64_imm8_rsp() {
    // 48 6B 44 24 28 58 = imul $0x58, 0x28(%rsp), %rax。2*88=176。フラグは残る。iostat 0x44897d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2028), &2u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x6B, 0x44, 0x24, 0x28, 0x58])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0)),
        176
    );
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 1);
}

#[test]
fn run_cmp_ax_imm8_sets_flags() {
    // 66 83 F8 FF = cmp $-1, %ax。0 と比較すると借りと補助キャリー。ax は残る。iostat 0x4bea1d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let run = |ax: u32| {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(Gpr(0).state(), ax);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x66, 0x83, 0xF8, 0xFF])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
        assert_eq!(env.backend.get(Gpr(0).state()), ax);
        env.backend.get(polyisa_guest_x86::sem::eflags_ref())
    };
    assert_eq!(run(0), 0x11);
    assert_eq!(run(0xFFFF), 0x44);
}

#[test]
fn run_movsx_r64_m16_sibd32() {
    // 48 0F BF 84 00 00 00 00 00 = movswq (%rax,%rax,1), %rax。0xffff は -1。iostat 0x4be9fb。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 0x1000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xFFFFu16.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x48, 0x0F, 0xBF, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1009 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0)),
        u64::MAX
    );
}

#[test]
fn run_sbb_rm32_imm8_rsp() {
    // 83 5C 24 14 FF = sbbl $-1, 0x14(%rsp)。0 から -1 を引くと 1、借りが出る。fsck 0x4d272f。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(4), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &0u32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x83, 0x5C, 0x24, 0x14, 0xFF])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x11);
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2014),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 1);
}

#[test]
fn run_imul_r32_imm_mem8() {
    // 69 43 04 E8 03 00 00 = imul $0x3e8, 0x4(%rbx), %eax。2*1000=2000。旗は残す。ifplugd 0x4264b0。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(3), 0x2000);
    env.backend.set(Gpr(0).state(), 0);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2004), &2u32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x69, 0x43, 0x04, 0xE8, 0x03, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    assert_eq!(env.backend.get(Gpr(0).state()), 2000);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 1);
}

#[test]
fn run_imul_r64_imm_sibd() {
    // 48 69 44 24 08 01 00 01 00 = imulq $0x10001, 0x8(%rsp), %rax。3*0x10001=0x30003。
    // mktemp 0x4d85cf。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &3u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x48, 0x69, 0x44, 0x24, 0x08, 0x01, 0x00, 0x01, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1009 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0)),
        0x30003
    );
}

#[test]
fn run_ror_rm64_by1() {
    // 48 D1 C9 = rorq %rcx。下位1ビットが最上位へ回る。sha512sum 0x4b47c4。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(1), 3);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0xD1, 0xC9])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(1)),
        0x8000_0000_0000_0001
    );
}

#[test]
fn run_rol_rm32_by1() {
    // run 経由で D1 C2 (ROLL $1,%edx) を回す。head の停止点 0x59eb6c に対応.
    // EDX=0x80000001 -> 0x00000003 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(2).state(), 0x8000_0001);
    let prog: &[u8] = &[
        0xD1, 0xC2, // roll $1,%edx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(2).state()), 0x0000_0003);
}

#[test]
fn run_add_rm16_imm() {
    // run 経由で 66 81 C6 FF 03 (ADDW $0x03ff,%si) を回す。seq の停止点 0x4c4677 に対応.
    // ESI=0x12340000 -> ESI=0x123403FF になり、exit(0)。mov は ESI を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(6).state(), 0x1234_0000);
    let prog: &[u8] = &[
        0x66, 0x81, 0xC6, 0xFF, 0x03, // addw $0x03ff,%si
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(6).state()), 0x1234_03FF);
}

#[test]
fn run_and_rm16_imm() {
    // run 経由で 66 81 E2 FF 08 (ANDW $0x08ff,%dx) を回す。seq の停止点 0x40b7f1 に対応.
    // EDX=0x1234FFFF -> EDX=0x123408FF になり、exit(0)。mov は EDX を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(2).state(), 0x1234_FFFF);
    let prog: &[u8] = &[
        0x66, 0x81, 0xE2, 0xFF, 0x08, // andw $0x08ff,%dx
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(2).state()), 0x1234_08FF);
}

#[test]
fn run_and_ax_imm16() {
    // run 経由で 66 25 00 0C (ANDW $0x0c00,%ax) を回す。seq の停止点 0x476e57 に対応.
    // EAX=0x1234037F -> EAX=0x12340000。exit 系列で EAX が潰れるため [0x2000] に退避して検証.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x1234_037F);
    let prog: &[u8] = &[
        0x66, 0x25, 0x00, 0x0C, // andw $0x0c00,%ax
        0x89, 0x05, 0xF6, 0x0F, 0x00, 0x00, // mov %eax,0xFF6(%rip) -> [0x2000]
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
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0x1234_0000);
}

#[test]
fn run_cmp_ax_imm16() {
    // run 経由で 66 3D 00 08 (CMPW $0x0800,%ax) を回す。seq の停止点 0x476e5b に対応.
    // AX=0 -> CF=1、ZF=0 になり、exit(0)。mov は旗を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0);
    let prog: &[u8] = &[
        0x66, 0x3D, 0x00, 0x08, // cmpw $0x0800,%ax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        1
    );
}

#[test]
fn run_shld_r64_cl_rexwr() {
    // run 経由で 4C 0F A5 C8 (SHLD RAX,R9,CL) を回す。seq の RBP 破壊バグに対応.
    // RAX=1、R9=0x8000000000000000、CL=1 -> RAX=3、RBP は保存される。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 1);
    env.backend.set(polyisa_guest_x86::sem::hi_ref(Gpr(0)), 0);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(9), 0x8000_0000_0000_0000);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(1).state(), 1);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(5), 0x7ffe_fcf0);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x4C, 0x0F, 0xA5, 0xC8, // shld rax,r9,cl
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    // RBP が保存される（旧実装は rm()/reg() 誤抽出で RBP を破壊した）。
    let rbp = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(5));
    assert_eq!(rbp, 0x7ffe_fcf0);
}

#[test]
fn run_shrd_r64_cl_rexwr() {
    // run 経由で 4C 0F AD C0 (SHRD RAX,R8,CL) を回す。seq 10 の停止点 0x4c4425 対応.
    // RAX=2、R8=1、CL=1 -> RAX=0x8000000000000001、RBP は保存される。
    // exit 系列で RAX が潰れるため [0x2100] に退避して検証.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 2);
    env.backend.set(polyisa_guest_x86::sem::hi_ref(Gpr(0)), 0);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(8), 1);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(1).state(), 1);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(5), 0x7ffe_fcf0);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x4C, 0x0F, 0xAD, 0xC0, // shrd rax,r8,cl
        0x48, 0x89, 0x05, 0xF5, 0x10, 0x00, 0x00, // mov [rip+0x10F5],rax -> [0x2100]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2100),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 0x8000_0000_0000_0001);
    // RBP が保存される（SHLD と同じ rm0f/reg0f 経路）。
    let rbp = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(5));
    assert_eq!(rbp, 0x7ffe_fcf0);
}

#[test]
fn run_and_r13b_mem32_rexr() {
    // run 経由で 44 22 AD 44 FB FF FF (AND R13B,[RBP-0x4BC]) を回す。wc の停止点 0x40bf62 に対応.
    // REX.R で dst を拡張。RBP=0x2000、[0x1B44]=0xF0、R13B=0x0F -> R13B=0x00、ZF=1.
    // REX 追随者ゲートの回帰 (旧実装はゲートで弾いていた)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(13), 0x0F);
        Ok(())
    })
    .unwrap();
    env.backend.mem.write(VirtAddr(0x1B44), &[0xF0u8]).unwrap();
    let prog: &[u8] = &[
        0x44, 0x22, 0xAD, 0x44, 0xFB, 0xFF, 0xFF, // and r13b,[rbp-0x4BC]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(13).state()) & 0xFF, 0x00);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_bt_r32_rm_rexr() {
    // run 経由で 44 0F A3 E8 (BT EAX,R13D) を回す。wc の停止点 0x5b380d に対応.
    // EAX=0x20 (bit5)、R13D=5 -> CF=1 になり、exit(0)。mov は旗を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(13), 5);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(0).state(), 0x20);
    let prog: &[u8] = &[
        0x44, 0x0F, 0xA3, 0xE8, // bt eax,r13d
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        1
    );
}

#[test]
fn run_sub_rm_imm8_rip() {
    // run 経由で 83 2D F9 0F 00 00 01 (SUBL $1,0xFF9(%rip)) を回す。head の停止点 0x417b1b に対応.
    // [0x2000]=10 - 1 = 9 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &10u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x83, 0x2D, 0xF9, 0x0F, 0x00, 0x00, 0x01, // subl $1,0xFF9(%rip)
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
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 9);
}

#[test]
fn run_fnstcw_mem8() {
    // run 経由で D9 7D C6 (FNSTCW -0x3a(%rbp)) を回す。seq の停止点 0x476e4a に対応.
    // RBP=0x2000、fcw=0x037F -> [0x1FC6]=0x037F になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W16>(0x037F);
        b.set(polyisa_guest_x86::sem::fcw_ref(), v);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0xD9, 0x7D, 0xC6, // fnstcw -0x3a(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x1FC6),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x037F);
}

#[test]
fn run_movsx_r32_m8_sibd() {
    // run 経由で 0F BE 4C 24 1B (MOVSX ECX,[RSP+0x1B]) を回す。wc の停止点 0x5b385a に対応.
    // [0x201B]=0xFF -> ECX=0xFFFFFFFF になり、exit(0)。mov は ECX を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.mem.write(VirtAddr(0x201B), &[0xFFu8]).unwrap();
    let prog: &[u8] = &[
        0x0F, 0xBE, 0x4C, 0x24, 0x1B, // movsx ecx,[rsp+0x1B]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(1).state()), 0xFFFF_FFFF);
}

#[test]
fn run_pminub_mem8() {
    // run 経由で 66 0F DA 40 50 (PMINUB xmm0,0x50(%rax)) を回す。head の停止点 0x4dddd5 に対応.
    // xmm0 low byte 0x05、[0x2050] low byte 0x03 -> 0x03 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0x2000);
    let mut mem16 = [0u8; 16];
    mem16[0] = 0x03;
    env.backend.mem.write(VirtAddr(0x2050), &mem16).unwrap();
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W128>(0x05);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            v,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0xDA, 0x40, 0x50, // pminub 0x50(%rax),%xmm0
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    env.step(|b| {
        let v: u128 = b.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(0),
        ));
        assert_eq!(v & 0xFF, 0x03);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_ucomisd_self() {
    // run 経由で 66 0F 2E C0 (UCOMISD xmm0,xmm0) を回す。seq の停止点 0x45b74d に対応.
    // xmm0=1.0 との比較は等価 -> ZF=1、PF=CF=0 になり、exit(0)。mov は旗を変えない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W128>(0x3FF0_0000_0000_0000);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            v,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x2E, 0xC0, // ucomisd xmm0,xmm0
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_movapd_co_use() {
    // run 経由で 66 0F 28 C1 (MOVAPD xmm0,xmm1) を回す。seq の停止点 0x45b757 に対応.
    // MOVAPD は MOVAPS と等価のため Insn 共用 + 66 ガードで対応。xmm1 -> xmm0 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W128>(0x112233445566778899AABBCCDDEEFF00);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(1)),
            v,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x28, 0xC1, // movapd xmm0,xmm1
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    env.step(|b| {
        let v: u128 = b.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(0),
        ));
        assert_eq!(v, 0x112233445566778899AABBCCDDEEFF00);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_divsd_xmm() {
    // F2 0F 5E C8 = divsd xmm1, xmm0。4.0/2.0=2.0。上位64は残す。dd 0x492911。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.step(|b| {
        let src = b.konst::<polyisa_sem::W128>(0x4000_0000_0000_0000u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            src,
        );
        let dst = b.konst::<polyisa_sem::W128>(0xFFFF_0000_0000_0000_4010_0000_0000_0000u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(1)),
            dst,
        );
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF2, 0x0F, 0x5E, 0xC8])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(1),
    ));
    assert_eq!(v, 0xFFFF_0000_0000_0000_4000_0000_0000_0000u128);
}

#[test]
fn run_divsd_xmm_m64_rip() {
    // F2 0F 5E 05 F8 0F 00 00 = divsd xmm0, [rip+0xff8]。4.0/2.0=2.0。上位64は残す。
    // 次命令は 0x1008、宛先は 0x2000。dd 0x4928e8。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x4000_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.step(|b| {
        let a = b.konst::<polyisa_sem::W128>(0xFFFF_0000_0000_0000_4010_0000_0000_0000u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            a,
        );
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xF2, 0x0F, 0x5E, 0x05, 0xF8, 0x0F, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v, 0xFFFF_0000_0000_0000_4000_0000_0000_0000u128);
}

#[test]
fn run_mulsd() {
    // run 経由で F2 0F 59 C2 (MULSD xmm0,xmm2) を回す。seq の停止点 0x5adf8c に対応.
    // xmm0 下位=2.0、xmm2=3.0 -> 下位=6.0 (0x4018000000000000)、上位は xmm0 のまま、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        let a = b.konst::<polyisa_sem::W128>(0xFFFF_0000_0000_0000_4000_0000_0000_0000u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            a,
        );
        let c = b.konst::<polyisa_sem::W128>(0x4008_0000_0000_0000u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(2)),
            c,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0xF2, 0x0F, 0x59, 0xC2, // mulsd xmm0,xmm2
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    env.step(|b| {
        let v: u128 = b.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(0),
        ));
        assert_eq!(v, 0xFFFF_0000_0000_0000_4018_0000_0000_0000u128);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_addsd_m64_sib() {
    // run 経由で F2 0F 58 04 24 (ADDSD xmm0,[rsp]) を回す。seq の停止点 0x5adf90 に対応.
    // [0x2000]=2.0、xmm0下位=3.0 -> 下位=5.0 (0x4014000000000000) になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &2.0f64.to_le_bytes())
        .unwrap();
    env.step(|b| {
        let a = b.konst::<polyisa_sem::W128>(0x4008_0000_0000_0000u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            a,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0xF2, 0x0F, 0x58, 0x04, 0x24, // addsd xmm0,[rsp]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    env.step(|b| {
        let v: u128 = b.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(0),
        ));
        assert_eq!(v, 0x4014_0000_0000_0000u128);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_addsd_xmm_m64_rip() {
    // run 経由で F2 0F 58 05 + disp32 (ADDSD xmm0,[RIP]) を回す.
    // [0x1500]=2.0、xmm0 下位=3.0 -> 5.0、exit(0)。awk の停止点 0x5b72fc に対応.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &0x4000_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x1500);
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x43, 0x00, // movq xmm0,[rbx+0] (xmm0=2.0)
        0xF2, 0x0F, 0x58, 0x05, 0xF3, 0x04, 0x00,
        0x00, // addsd xmm0,[rip+0x4f3] ([0x1500]=2.0 -> 4.0)
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
    // xmm0=2.0 + [0x1500]=2.0 -> 4.0。
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0x4010_0000_0000_0000);
}

#[test]
fn run_andpd() {
    // run 経由で 66 0F 54 C1 (ANDPD xmm0,xmm1) を回す。
    // xmm0=0xFF..FF、xmm1=0x0F0F.. -> xmm0=0x0F0F.. になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        let a = b.konst::<polyisa_sem::W128>(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF);
        let c = b.konst::<polyisa_sem::W128>(0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            a,
        );
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(1)),
            c,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x54, 0xC1, // andpd xmm0,xmm1
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    env.step(|b| {
        let v: u128 = b.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(0),
        ));
        assert_eq!(v, 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_andpd_rip() {
    // run 経由で 66 0F 54 0D + disp32 (ANDPD xmm1,[RIP]) を回す。seq の停止点 0x45b75b に対応.
    // [0x2000]=0x0F0F..、xmm1=0xFF..FF -> xmm1=0x0F0F.. になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    let mut mem16 = [0u8; 16];
    for b in mem16.iter_mut() {
        *b = 0x0F;
    }
    env.backend.mem.write(VirtAddr(0x2000), &mem16).unwrap();
    env.step(|b| {
        let a = b.konst::<polyisa_sem::W128>(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(1)),
            a,
        );
        Ok(())
    })
    .unwrap();
    // next_rip=0x1008、target=0x2000 -> disp=0xFF8.
    let prog: &[u8] = &[
        0x66, 0x0F, 0x54, 0x0D, 0xF8, 0x0F, 0x00, 0x00, // andpd xmm1,[rip+0xFF8]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    env.step(|b| {
        let v: u128 = b.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(1),
        ));
        assert_eq!(v, 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F);
        Ok(())
    })
    .unwrap();
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
fn run_movdqu_store_memnd() {
    // run 経由で F3 0F 7F mod=00 (MOVDQU [RDI],xmm0) を回す.
    // xmm0=16B を [0x2000] に格納して exit(0)、メモリで検証する.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(7).state(), 0x2000);
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W128>(0x0102030405060708090a0b0c0d0e0f10u128);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            v,
        );
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7F, 0x07, // movdqu [rdi],xmm0
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut buf = [0u8; 16];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut buf,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(
        buf,
        [
            0x10u8, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01
        ]
    );
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
fn run_cdq_sign_extend() {
    // run 経由で 99 (CDQ) を回す。od 0x5acde6 対応.
    // EAX=0xFFFFFFFF -> EDX=0xFFFFFFFF になり、exit(0)。EDX は exit 系列で潰れない.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(0).state(), 0xFFFF_FFFF);
    env.backend.set(polyisa_guest_x86::sem::hi_ref(Gpr(0)), 0);
    let prog: &[u8] = &[
        0x99, // cdq (edx=0xffffffff)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(2).state()), 0xFFFF_FFFF);
}

#[test]
fn run_cqo_sign_extend() {
    // run 経由で REX.W 99 (CQO) を回す。
    // RAX=0x8000000000000000 -> RDX=0xFFFFFFFFFFFFFFFF になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(0), 0x8000_0000_0000_0000);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x48, 0x99, // cqo (rdx=0xffffffffffffffff)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(2));
    assert_eq!(v, 0xFFFF_FFFF_FFFF_FFFF);
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

#[test]
fn run_psrldq_dst_is_rm() {
    // run 経由で 66 0F 73 D8 0D (PSRLDQ xmm0,13) を回す。head の停止点に対応.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0,esi (esi=0 -> xmm0=0)
        0x66, 0x0F, 0x73, 0xD8, 0x0D, // psrldq xmm0,13
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_movd_xmm_rip() {
    // run 経由で 66 0F 6E 05 + disp32 (MOVD xmm0,[RIP]) を回す.
    // [0x1500]=0x11223344 として xmm0 低32が一致することを確かめ、exit(0).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x1500), &0x1122_3344u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0x05, 0xF8, 0x04, 0x00, 0x00, // movd xmm0,[rip+0x4f8] ([0x1500])
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
    assert_eq!((v & 0xffff_ffff) as u32, 0x1122_3344);
}

#[test]
fn run_or_rm8_imm_reg_direct() {
    // run 経由で 80 CD 08 (OR CH,8) を回す。
    // ECX=0x100 (CH=1) -> CH=9 -> ECX=0x900 になり、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let prog: &[u8] = &[
        0xB9, 0x00, 0x01, 0x00, 0x00, // mov ecx,0x100
        0x80, 0xCD, 0x08, // or ch,8
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    assert_eq!(env.backend.get(Gpr(1).state()), 0x900);
}

#[test]
fn run_movq_xmm_m64_mem8() {
    // run 経由で F3 0F 7E 43 38 (MOVQ xmm0,[rbx+0x38]) を回す。
    // [0x2038]=0xAABBCCDDEEFF0011 -> xmm0 下位64、上位64は0、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2038), &0xAABB_CCDD_EEFF_0011u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xF3, 0x0F, 0x7E, 0x43, 0x38, // movq xmm0,[rbx+0x38]
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
    assert_eq!(v, 0xAABB_CCDD_EEFF_0011u128);
}

#[test]
fn run_testw_memnd() {
    // run 経由で 66 F7 03 02 02 (TESTW [rbx],0x202) を回す。
    // [0x2000]=0x0202 で ZF=0 のまま exit(0)。fetch/dispatch/sem 経路の検証を兼ねる。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x0202u16.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0xF7, 0x03, 0x02, 0x02, // testw $0x202,(%rbx)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_movhps_xmm_m64_mem8() {
    // run 経由で 0F 16 43 38 (MOVHPS xmm0,[rbx+0x38]) を回す。
    // xmm0 下位=0x1111222233334444 を保ち、上位=[0x2038]=0xAABBCCDDEEFF0011、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2038), &0xAABB_CCDD_EEFF_0011u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC0, // movd xmm0,eax (eax=0 -> xmm0=0。意味論の初期化)
        0x0F, 0x16, 0x43, 0x38, // movhps xmm0,[rbx+0x38]
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
    // 下位64は movd の 0、上位64は [0x2038].
    assert_eq!(v, 0xAABB_CCDD_EEFF_0011_0000_0000_0000_0000u128);
}

#[test]
fn run_movlpd_xmm_m64_memnd() {
    // run 経由で 66 0F 12 0F (MOVLPD xmm1,[rdi]) を回す。
    // [0x2000]=0xAABBCCDDEEFF0011 -> xmm1 下位64、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0xAABB_CCDD_EEFF_0011u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x12, 0x0F, // movlpd xmm1,[rdi]
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(1),
    ));
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0xAABB_CCDD_EEFF_0011);
}

#[test]
fn run_movhpd_xmm_m64_mem8() {
    // run 経由で 66 0F 16 43 38 (MOVHPD xmm0,[rbx+0x38]) を回す。
    // MOVHPS と等価：下位64は movd の 0 を保ち、上位64=[0x2038]、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2038), &0xAABB_CCDD_EEFF_0011u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC0, // movd xmm0,eax (eax=0 -> xmm0=0。意味論の初期化)
        0x66, 0x0F, 0x16, 0x43, 0x38, // movhpd xmm0,[rbx+0x38]
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
    assert_eq!(v, 0xAABB_CCDD_EEFF_0011_0000_0000_0000_0000u128);
}

#[test]
fn run_movsd_load_store_sibd() {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(3).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2038), &0xAABB_CCDD_EEFF_0011u64.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0xF2, 0x0F, 0x10, 0x43, 0x38, // movsd xmm0,[rbx+0x38]
        0xF2, 0x0F, 0x11, 0x43, 0x40, // movsd [rbx+0x40],xmm0
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
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0xAABB_CCDD_EEFF_0011);
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2040),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 0xAABB_CCDD_EEFF_0011);
}

#[test]
fn run_movq_xmm_r64_rexw() {
    // 66 REX.W 0F 6E C0 (movq xmm0,rax)。RAX=0x4045000000000000 -> xmm0低64。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(0), 0x4045_0000_0000_0000);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x66, 0x48, 0x0F, 0x6E, 0xC0, // movq xmm0,rax (REX.W)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    // RAXを復元 (write64で汚したため再設定は不要、prog内で上書きされる前に実行される)。
    // 実際は prog先頭でxmm0<-RAXを読むため、事前のRAX値が使われる。
    // BareEnvのRAXはwrite64で設定済みのためそのまま実行する。
    // ただし env.stepで設定した後にprogを書いたため順序は正しい。
    let mut sys = X64Exit;
    // RAXを再設定 (prog書込みでレジスタは変わらないため不要だが明示する)。
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(0), 0x4045_0000_0000_0000);
        Ok(())
    })
    .unwrap();
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!((v & 0xFFFF_FFFF_FFFF_FFFF) as u64, 0x4045_0000_0000_0000);
}

#[test]
fn run_bts_r64_imm() {
    // 48 0F BA EA 34 (BTS RDX,0x34 REX.W)。RDX=0 -> RDX=1<<52、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(2), 0);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x48, 0x0F, 0xBA, 0xEA, 0x34, // bts rdx,0x34 (REX.W)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    // RDXを再設定 (prog書込みでレジスタは変わらない)。
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(2), 0);
        Ok(())
    })
    .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    env.step(|b| {
        let v = polyisa_guest_x86::sem::read64(b, Gpr(2));
        assert_eq!(v, 1u64 << 52);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_pop_rbx_1p0_keeps_hi() {
    // POP RBX (0x5B) は64ビット既定のため上位を消さない。1.0 の復元を確かめる。
    // RSP=0x2000 に 1.0 を置き、RBX=0 から POP 1回で RBX=1.0・RSP=0x2008 になる.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.write(VirtAddr(0x1000), &[0x5B]).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x3ff0_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(3), 0);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1001 });
    env.step(|b| {
        let v = polyisa_guest_x86::sem::read64(b, Gpr(3));
        assert_eq!(v, 0x3ff0_0000_0000_0000);
        let rsp = polyisa_guest_x86::sem::read64(b, Gpr(4));
        assert_eq!(rsp, 0x2008);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_mov_rm8_imm_sibd32_stores_byte() {
    // MOVB [RBP+RDX+0x100],0x01 (C6 84 15 00 01 00 00 01) を64ビットで回す.
    // RBP=0x200、RDX=0x10 -> [0x310]=0x01、eip は 0x1008 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x0), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xC6, 0x84, 0x15, 0x00, 0x01, 0x00, 0x00, 0x01],
        )
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(5), 0x200);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(2), 0x10);
        Ok(())
    })
    .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x310),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 0x01);
}

#[test]
fn run_cmove_r64_sibd_moves_on_z() {
    // CMOVE RAX,[RSP+0x60] (48 0F 44 44 24 60) を64ビットで回す.
    // RSP=0x2000、[0x2060]=0x1122...、ZF=1 -> RAX=0x1122...、eip は 0x1006 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x0F, 0x44, 0x44, 0x24, 0x60])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2060), &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(0), 0);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x40);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    env.step(|b| {
        let v = polyisa_guest_x86::sem::read64(b, Gpr(0));
        assert_eq!(v, 0x1122_3344_5566_7788);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_cmovne_r64_mem32_moves_on_nz() {
    // CMOVNE RAX,[RBP-0xA8] (48 0F 45 85 58 FF FF FF) を64ビットで回す。grep 対応.
    // RBP=0x2000、[0x1F58]=0x1122...、ZF=0 -> RAX=0x1122...、eip は 0x1008 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x48, 0x0F, 0x45, 0x85, 0x58, 0xFF, 0xFF, 0xFF],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1F58), &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(5), 0x2000);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(0), 0);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    env.step(|b| {
        let v = polyisa_guest_x86::sem::read64(b, Gpr(0));
        assert_eq!(v, 0x1122_3344_5566_7788);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_div_rm32_mem8_quotient_remainder() {
    // DIV EAX,[RDI+4] (F7 77 04) を32ビットで回す.
    // EDX:EAX=17、[0x104]=5 -> EAX=3、EDX=2、eip は 0x1003 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x0), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF7, 0x77, 0x04])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x104), &5u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(7).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0);
    env.backend.set(Gpr(0).state(), 17);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(env.backend.get(Gpr(0).state()), 3);
    assert_eq!(env.backend.get(Gpr(2).state()), 2);
}

#[test]
fn run_div_rm32_sib_quotient_remainder() {
    // F7 34 24 = divl (%rsp)。EDX:EAX=17、[rsp]=5 で EAX=3、EDX=2。xxd 0x473876。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &5u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(Gpr(2).state(), 0);
    env.backend.set(Gpr(0).state(), 17);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF7, 0x34, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(env.backend.get(Gpr(0).state()), 3);
    assert_eq!(env.backend.get(Gpr(2).state()), 2);
}

#[test]
fn run_mov_rm16_imm_memnd() {
    // 66 41 C7 07 6C 6C = movw $0x6c6c, (%r15)。xxd 0x4b240f。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(15).state(), 0x2000u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x41, 0xC7, 0x07, 0x6C, 0x6C])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let mut got = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(got), 0x6c6c);
}

#[test]
fn run_dec_rm_sib_keeps_cf() {
    // FF 0C 24 = decl (%rsp)。10 が 9 になり、CF は残る。xxd 0x4b2bee。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &10u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xFF, 0x0C, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(got), 9);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 1);
}

#[test]
fn run_cmp_m8_r8_rip_sets_zf() {
    // 44 38 35 F9 0F 00 00 = cmpb %r14b, 0xff9(%rip)。次の RIP 0x1007 から 0x2000。
    // 両方 0x10 で ZF=1、CF は消える。grep 0x4aec6d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.write(VirtAddr(0x2000), &[0x10]).unwrap();
    env.backend.set(Gpr(14).state(), 0x10u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x44, 0x38, 0x35, 0xF9, 0x0F, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x41,
        0x40
    );
}

#[test]
fn run_div_rm32_sibd_quotient_remainder() {
    // DIV EAX,[RSP+0x0C] (F7 74 24 0C) をdispatch経由で回す.
    // EDX:EAX=17、[0x10C]=5 -> EAX=3、EDX=2、eip は 0x1004 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x0), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF7, 0x74, 0x24, 0x0C])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x10C), &5u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x100);
    env.backend.set(Gpr(2).state(), 0);
    env.backend.set(Gpr(0).state(), 17);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(Gpr(0).state()), 3);
    assert_eq!(env.backend.get(Gpr(2).state()), 2);
}

#[test]
fn run_bt_m32_imm_sets_cf() {
    // BT [RDI],0x0C (0F BA 27 0C) を32ビットで回す.
    // RDI=0x100、[0x100]=0x1000 (bit12) -> CF=1、eip は 0x1004 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x0), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x0F, 0xBA, 0x27, 0x0C])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x100), &0x1000u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(7).state(), 0x100);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        0x1
    );
}

#[test]
fn run_bt_m32_imm_rbx_sets_cf() {
    // BT [RBX],0x0B (0F BA 23 0B) を32ビットで回す.
    // RBX=0x100、[0x100]=0x800 (bit11) -> CF=1、eip は 0x1004 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x0), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x0F, 0xBA, 0x23, 0x0B])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x100), &0x800u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x100);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        0x1
    );
}

#[test]
fn run_or_rm32_imm_mem8_ors() {
    // ORL $0x400,[R13+0x00] (41 81 4D 00 00 04 00 00) を64ビットで回す.
    // R13=0x2000、[0x2000]=0 -> [0x2000]=0x400、eip は 0x1008 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x41, 0x81, 0x4D, 0x00, 0x00, 0x04, 0x00, 0x00],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0u32.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(13), 0x2000);
        Ok(())
    })
    .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0x400);
}

#[test]
fn run_cmp_rm32_imm_memnd_sets_zf() {
    // CMPL $0x2100,(%R14) (41 81 3E 00 21 00 00) を64ビットで回す.
    // R14=0x2000、[0x2000]=0x2100 -> ZF=1、eip は 0x1007 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x41, 0x81, 0x3E, 0x00, 0x21, 0x00, 0x00],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x2100u32.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(14), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_cmp_rm32_imm_mem32_sets_zf() {
    // CMPL $0x66695A54,-0x100(%RBP) (81 BD 00 FF FF FF 54 5A 69 66) を回す。ls -l 対応.
    // RBP=0x2000、[0x1F00]=0x66695A54 -> ZF=1、eip は 0x100A に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x81, 0xBD, 0x00, 0xFF, 0xFF, 0xFF, 0x54, 0x5A, 0x69, 0x66],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1F00), &0x66695A54u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x100A });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_cvtsi2sd_m32_mem8_converts() {
    // CVTSI2SDL -0x34(%RBX),%xmm0 (F2 0F 2A 43 CC) を64ビットで回す.
    // RBX=0x100、[0xCC]=5 -> xmm0 下位=5.0、eip は 0x1005 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x0), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF2, 0x0F, 0x2A, 0x43, 0xCC])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0xCC), &5u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x100);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v as u64, 0x4014_0000_0000_0000);
}

#[test]
fn run_andw_sibd_zeroes() {
    // ANDW $0x0,0x26(%RSP) (66 83 64 24 26 00) を64ビットで回す.
    // RSP=0x2000、[0x2026]=0xFFFF -> [0x2026]=0x0000、eip は 0x1006 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x83, 0x64, 0x24, 0x26, 0x00])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2026), &0xFFFFu16.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2026),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x0000);
}

#[test]
fn run_bts_r64_rm_sets_bit() {
    // BTS RDX,RSI (48 0F AB F2) を64ビットで回す.
    // RDX=0、RSI=5 -> RDX=0x20、CF=0、eip は 0x1004 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x0F, 0xAB, 0xF2])
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(2), 0);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(6), 5);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    env.step(|b| {
        let v = polyisa_guest_x86::sem::read64(b, Gpr(2));
        assert_eq!(v, 0x20);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        0x0
    );
}

#[test]
fn run_bt_m32_imm_sibd_sets_cf() {
    // BTL $0x10,0x18(%RSP) (0F BA 64 24 18 10) を64ビットで回す.
    // RSP=0x2000、[0x2018]=0x10000 (bit16) -> CF=1、eip は 0x1006 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x0F, 0xBA, 0x64, 0x24, 0x18, 0x10])
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2018), &0x10000u32.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        0x1
    );
}

#[test]
fn run_cmp_r64_sibd32_sets_zf() {
    // CMP RBX,[R12+0x98] (49 3B 9C 24 98 00 00 00) を64ビットで回す.
    // R12=0x2000、[0x2098]=7、RBX=7 -> ZF=1、eip は 0x1008 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x49, 0x3B, 0x9C, 0x24, 0x98, 0x00, 0x00, 0x00],
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2098), &7u64.to_le_bytes())
        .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(12), 0x2000);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(3), 7);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_bswap_ecx() {
    // run 経由で 0F C9 (BSWAP ECX) を回す。ls -l 0x429c02 対応.
    // ECX=0x12345678 -> 0x78563412、eip は 0x1002 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x0F, 0xC9])
        .unwrap();
    env.backend.set(Gpr(1).state(), 0x1234_5678);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(Gpr(1).state()), 0x7856_3412);
}

#[test]
fn run_imul_r_sibd() {
    // run 経由で 41 0F AF 6C 24 14 (IMUL EBP,[R12+0x14]) を回す。hexdump 0x5c8ca2 対応.
    // R12=0x2000、[0x2014]=6、EBP=7 -> EBP=42、exit(42)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(12), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(5).state(), 7);
    env.backend
        .mem
        .write(VirtAddr(0x2014), &0x06u32.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x41, 0x0F, 0xAF, 0x6C, 0x24, 0x14, // imul ebp,[r12+0x14] (ebp=42)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0x63, 0xFD, // movsxd rdi,ebp (rdi=42)
        0x0F, 0x05, // syscall -> exit(42)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(42));
}

#[test]
fn run_bt_r64_rm_rexw() {
    // run 経由で 49 0F A3 D6 (BT R14,RDX) を回す。hexdump 0x5c8dd9 対応.
    // R14=0x800100003E00、RDX=0x20 -> CF=1、eip は 0x1004 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(14), 0x8001_0000_3E00);
        Ok(())
    })
    .unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(2), 0x20);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x49, 0x0F, 0xA3, 0xD6])
        .unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x40);
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x1,
        1
    );
}

#[test]
fn run_mov_m16_imm_sib() {
    // run 経由で 66 41 C7 04 24 6C 6C (MOVW [R12],0x6C6C) を回す。hexdump 0x5c82dd 対応.
    // R12=0x2000 -> [0x2000]=0x6C6C、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(12), 0x2000);
        Ok(())
    })
    .unwrap();
    let prog: &[u8] = &[
        0x66, 0x41, 0xC7, 0x04, 0x24, 0x6C, 0x6C, // movw [r12],0x6c6c
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x6C6C);
}

#[test]
fn run_mov_m16_imm_mem8() {
    // run 経由で 66 C7 43 5C 01 01 (MOVW [RBX+0x5C],0x0101) を回す。hexdump 0x5c84f9 対応.
    // RBX=0x2000 -> [0x205C]=0x0101、exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(3).state(), 0x2000);
    let prog: &[u8] = &[
        0x66, 0xC7, 0x43, 0x5C, 0x01, 0x01, // movw [rbx+0x5c],0x0101
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(0x205C),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes(back), 0x0101);
}

#[test]
fn run_test_m16_imm_mem8() {
    // run 経由で 66 F7 45 08 02 04 (TESTW $0x402,[RBP+0x8]) を回す。hexdump 0x5c8822 対応.
    // [0x2008]=0x0402 で ZF=0 のまま exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x2000);
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x0402u16.to_le_bytes())
        .unwrap();
    let prog: &[u8] = &[
        0x66, 0xF7, 0x45, 0x08, 0x02, 0x04, // testw $0x402,0x8(%rbp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_sete_m8_sibd() {
    // run 経由で 0F 94 44 24 1F (SETE 0x1F(%rsp)) を回す。df 0x5a797e 対応.
    // RSP=0x2000、ZF=1 -> [0x201F]=1、eip は 0x1005 に進み exit(0)。
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x40);
    let prog: &[u8] = &[
        0x0F, 0x94, 0x44, 0x24, 0x1F, // sete 0x1f(%rsp)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax,60
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, // mov rdi,0
        0x0F, 0x05, // syscall -> exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 100, true);
    assert_eq!(out, Outcome::Exit(0));
    let mut back = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x201F),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(back[0], 1);
}

#[test]
fn run_pmaxub_reg_direct() {
    // run 経由で 66 0F DE D8 (PMAXUB xmm3,xmm0) を回す。df 0x4d0bcd 対応.
    // xmm3=0x01、xmm0=0x02 -> xmm3=0x02、eip は 0x1004 に進む.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.step(|b| {
        let v = b.konst::<polyisa_sem::W128>(0x01);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(3)),
            v,
        );
        let w = b.konst::<polyisa_sem::W128>(0x02);
        b.set(
            polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
            w,
        );
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x0F, 0xDE, 0xD8])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    env.step(|b| {
        let v: u128 = b.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(3),
        ));
        assert_eq!(v & 0xFF, 0x02);
        Ok(())
    })
    .unwrap();
}

#[test]
fn run_cmovbe_mem8() {
    // 48 0F 46 6B 08 = cmovbq 8(%rbx), %rbp。ZF=1 で 0x42 を取り exit する.
    // Ref: SPEC-X86-INTEL-SDM (v093). test 0x4d2874.
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x42u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(3).state(), 0x2000u32);
    env.backend.set(Gpr(5).state(), 7u32);
    env.backend
        .set(polyisa_guest_x86::sem::eflags_ref(), 0x40u32);
    let prog: &[u8] = &[
        0x48, 0x0F, 0x46, 0x6B, 0x08, // cmovbq 8(%rbx), %rbp
        0x48, 0x89, 0xEF, // mov %rbp, %rdi
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov $60, %rax
        0x0F, 0x05, // syscall
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 20, true);
    assert_eq!(out, Outcome::Exit(0x42));
}

#[test]
fn run_test_rax_imm32_sign_extends() {
    // 48 A9 00 F0 FF FF = test rax, 0xfffff000。imm32 は符号拡張され、
    // bit63 だけ立った rax と AND すると ZF=0。basename 0x4bff3f 対応.
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(0).state(), 0u32);
    env.backend
        .set(polyisa_guest_x86::sem::hi_ref(Gpr(0)), 0x8000_0000u32);
    let prog: &[u8] = &[
        0x48, 0xA9, 0x00, 0xF0, 0xFF, 0xFF, // test rax, 0xfffff000
        0x75, 0x10, // jne success
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov $60, %rax
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov $1, %rdi
        0x0F, 0x05, // syscall exit(1)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov $60, %rax
        0x48, 0x31, 0xFF, // xor %rdi, %rdi
        0x0F, 0x05, // syscall exit(0)
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 20, true);
    assert_eq!(out, Outcome::Exit(0));
}

#[test]
fn run_sub_r32_sib() {
    // 2B 04 32 = sub eax, [rdx+rsi]。8-5=3。basename 0x4898fc 対応.
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2008), &5u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(0).state(), 8u32);
    env.backend.set(Gpr(2).state(), 0x2000u32);
    env.backend.set(Gpr(6).state(), 8u32);
    let prog: &[u8] = &[
        0x2B, 0x04, 0x32, // sub eax, [rdx+rsi]
        0x89, 0xC7, // mov edi, eax
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov $60, %rax
        0x0F, 0x05,
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 20, true);
    assert_eq!(out, Outcome::Exit(3));
}

#[test]
fn run_inc_rm_sibd32_keeps_cf() {
    // FF 84 94 90 02 00 00 = incl 0x290(%rsp,%rdx,4)。CF は残す。basename 0x4899d0。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2294), &7u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(Gpr(2).state(), 1u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xFF, 0x84, 0x94, 0x90, 0x02, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2294),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(got), 8);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 1);
}

#[test]
fn run_add_m32_r32_sibd32() {
    // 01 AC 84 90 02 00 00 = addl %ebp, 0x290(%rsp,%rax,4)。10+3=13。
    // basename 0x48995c。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2294), &10u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(Gpr(0).state(), 1u32);
    env.backend.set(Gpr(5).state(), 3u32);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x01, 0xAC, 0x84, 0x90, 0x02, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2294),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(got), 13);
}

#[test]
fn run_cmp_di_imm16_sets_zf() {
    // 66 81 FF C0 0F = cmpw $0x0fc0, %di。一致なら ZF=1、edi は変えない。
    // basename 0x4bfaa8。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(7).state(), 0x1111_0FC0u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x81, 0xFF, 0xC0, 0x0F])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(env.backend.get(Gpr(7).state()), 0x1111_0FC0u32);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x40,
        0x40
    );
}

#[test]
fn run_test_rm32_imm_rip_sets_zf() {
    // F7 05 disp32 imm32 = testl $0x231, 0xff6(%rip)。メモリは 0 なので ZF=1、CF は消える。
    // 番地は next_rip+disp = 0x2000。ls 0x4963b6。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xF7, 0x05, 0xF6, 0x0F, 0x00, 0x00, 0x31, 0x02, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x100A });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x41,
        0x40
    );
}

#[test]
fn run_sub_m64_r64_sibd() {
    // 48 29 44 24 78 = subq %rax, 0x78(%rsp)。10-3=7。wc 0x49e1db。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2078), &10u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(Gpr(0).state(), 3u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x29, 0x44, 0x24, 0x78])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let mut got = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2078),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(got), 7);
}

#[test]
fn run_movaps_store_sib() {
    // 0F 29 04 24 = movaps (%rsp), xmm0。0F 29 44 24 D8 = movaps -0x28(%rsp), xmm0。
    // od 0x49788f と sed 0x400d19。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 2, rwx).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(Gpr(6).state(), 0x1122_3344u32);
    let prog: &[u8] = &[
        0x66, 0x0F, 0x6E, 0xC6, // movd xmm0, esi
        0x0F, 0x29, 0x04, 0x24, // movaps (%rsp), xmm0
        0x0F, 0x29, 0x44, 0x24, 0xD8, // movaps -0x28(%rsp), xmm0
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov $60, %rax
        0x48, 0x31, 0xFF, // xor %rdi, %rdi
        0x0F, 0x05,
    ];
    env.backend.mem.write(VirtAddr(0x1000), prog).unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 20, true);
    assert_eq!(out, Outcome::Exit(0));
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x2000), &mut back, acc)
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0x1122_3344);
    env.backend
        .mem
        .read(VirtAddr(0x1FD8), &mut back, acc)
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 0x1122_3344);
}

#[test]
fn run_or_m64_r64_sibd() {
    // 4C 09 4C C4 D8 = orq %r9, -0x28(%rsp,%rax,8)。0x10|7=0x17。sed 0x400d55。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2020), &0x10u64.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2040u32);
    env.backend.set(Gpr(0).state(), 1u32);
    env.backend.set(Gpr(9).state(), 7u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x4C, 0x09, 0x4C, 0xC4, 0xD8])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let mut got = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2020),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(got), 0x17);
}

#[test]
fn run_cmp_rm_imm8_sibd_rbp() {
    // 83 7C 35 C8 00 = cmpl $0, -0x38(%rbp,%rsi)。0 と比べて ZF=1、CF は消える。
    // sed 0x4c93bc。Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(5).state(), 0x2080u32);
    env.backend.set(Gpr(6).state(), 8u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x83, 0x7C, 0x35, 0xC8, 0x00])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x41,
        0x40
    );
}

#[test]
fn run_or_r32_sibd_r12() {
    // 41 0B 44 24 18 = orl 0x18(%r12), %eax。0x7|0x10=0x17。sed 0x4c9424。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2018), &0x10u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(12).state(), 0x2000u32);
    env.backend.set(Gpr(0).state(), 7u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x41, 0x0B, 0x44, 0x24, 0x18])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(env.backend.get(Gpr(0).state()), 0x17u32);
}

#[test]
fn run_inc_rm_sib_keeps_cf() {
    // FF 04 91 = incl (%rcx,%rdx,4)。10 が 11 になり、CF は残る。sed 0x4ca2c7。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2004), &10u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(1).state(), 0x2000u32);
    env.backend.set(Gpr(2).state(), 1u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xFF, 0x04, 0x91])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2004),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(got), 11);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 1);
}

#[test]
fn run_or_m8_r8_sibd() {
    // 08 44 24 2F = orb %al, 0x2f(%rsp)。0x10|0x07=0x17。sed 0x4a87dd。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.write(VirtAddr(0x202F), &[0x10]).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(Gpr(0).state(), 0x07u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x08, 0x44, 0x24, 0x2F])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut got = [0u8; 1];
    env.backend
        .mem
        .read(
            VirtAddr(0x202F),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(got[0], 0x17);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 0);
}

#[test]
fn run_or_rm32_imm_sib() {
    // 41 81 0C 24 00 04 00 00 = orl $0x400, (%r12)。0x10|0x400=0x410。awk 0x4a4354。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x10u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(12).state(), 0x2000u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0x41, 0x81, 0x0C, 0x24, 0x00, 0x04, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(got), 0x410);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 0);
}

#[test]
fn run_or_rm32_imm8_sib() {
    // 41 83 0C 24 01 = orl $1, (%r12)。0x10|1=0x11。awk 0x4a1704。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x10u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(12).state(), 0x2000u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x41, 0x83, 0x0C, 0x24, 0x01])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Natural,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(got), 0x11);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 0);
}

#[test]
fn run_test_r32_sib_r14() {
    // 44 85 34 24 = testl %r14d, (%rsp)。0 と比べて ZF=1、CF は消える。awk 0x4a1c82。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(Gpr(14).state(), 1u32);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x44, 0x85, 0x34, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 0x41,
        0x40
    );
}

#[test]
fn run_fld_m32_rip_pushes_one() {
    // D9 05 FA 0F 00 00 = flds 0xffa(%rip)。次の RIP 0x1006 から 0x2000 の 1.0。
    // 80ビットは指数 0x3fff、仮数の整数ビットだけ。seq 0x402335。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x3f800000u32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD9, 0x05, 0xFA, 0x0F, 0x00, 0x00])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x3fff
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        1u64 << 63
    );
}

#[test]
fn run_fstp_st0_pops() {
    // D9 05 … のあと DD D8。1.0 を載せて FSTP ST(0) すると空に戻る。seq 0x4024ee。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x3f800000u32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xD9, 0x05, 0xFA, 0x0F, 0x00, 0x00, 0xDD, 0xD8],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 2, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1008 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 0);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)), 0);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)), 0);
}

#[test]
fn run_fild_m32_sibd_pushes_three() {
    // DB 44 24 20 = fildl 0x20(%rsp)。3 は 1.1 * 2^1。seq 0x4018bc。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2020), &3u32.to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDB, 0x44, 0x24, 0x20])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fild_m64_sib_pushes_2_pow_40() {
    // DF 2C 24 = fildq (%rsp)。2^40 は指数 16423、仮数は整数ビットだけ。seq 0x4018c4。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &(1u64 << 40).to_le_bytes())
        .unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDF, 0x2C, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        16423
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        1u64 << 63
    );
}

#[test]
fn run_fmulp_st1_three_times_one() {
    // DE C9 = fmulp %st(1)。3 * 1 を ST(1) に残して ST(0) を捨てる。seq 0x4018c7。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(1), 0x3fffu16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(1), 1u64 << 63);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDE, 0xC9])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)), 0);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(1)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(1)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fmulp_st1_one_and_a_half_squared() {
    // 1.5 * 1.5 = 2.25。積が 2 以上なので指数が一つ増える。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    let one_and_half = (1u64 << 63) | (1u64 << 62);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x3fffu16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(0), one_and_half);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(1), 0x3fffu16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(1), one_and_half);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDE, 0xC9])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(1)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(1)),
        (1u64 << 63) | (1u64 << 60)
    );
}

#[test]
fn run_fstp_m64_sibd_stores_three() {
    // DD 5C 24 08 = fstpl 0x8(%rsp)。3.0 を倍精度で書いて ST(0) を捨てる。seq 0x4d3169。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000u32);
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDD, 0x5C, 0x24, 0x08])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(VirtAddr(0x2008), &mut back, acc)
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 0x4008_0000_0000_0000);
}

#[test]
fn run_or_m32_r32_sib_no_index_r12() {
    // 41 09 04 24 = orl %eax, (%r12)。index=4 は基底だけ。seq 0x499151。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(12), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(Gpr(0).state(), 0x2);
    env.backend
        .mem
        .write(VirtAddr(0x2000), &1u32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x41, 0x09, 0x04, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut back = [0u8; 4];
    env.backend
        .mem
        .read(
            VirtAddr(0x2000),
            &mut back,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u32::from_le_bytes(back), 3);
}

#[test]
fn run_fld_m64_rsp_pushes_three() {
    // DD 04 24 = fld QWORD PTR [rsp]。3.0 を 80 ビットへ伸ばして載せる。awk length 0x401b17。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x4008_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDD, 0x04, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
    let rsp: u64 = polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(4));
    assert_eq!(rsp, 0x2000);
}

#[test]
fn run_fld_m64_memnd_pushes_three() {
    // DD 00 = fldl (%rax)。3.0 を 80 ビットへ伸ばして載せる。seq 0x4d0723。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(0), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x4008_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDD, 0x00])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fstp_m80_memnd_stores_three() {
    // DB 3F = fstpt (%rdi)。3.0 を 10 バイトで書いて ST(0) を捨てる。seq 0x4d0725。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(7), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDB, 0x3F])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut sig = [0u8; 8];
    let mut exp = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x2000), &mut sig, acc)
        .unwrap();
    env.backend
        .mem
        .read(VirtAddr(0x2008), &mut exp, acc)
        .unwrap();
    assert_eq!(u64::from_le_bytes(sig), (1u64 << 63) | (1u64 << 62));
    assert_eq!(u16::from_le_bytes(exp), 0x4000);
}

#[test]
fn run_push_m64_sibd_from_rsp() {
    // FF 74 24 68 = pushq 0x68(%rsp)。減算前の番地を読む。seq 0x4d1a81。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2100);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2168), &0x1122_3344_5566_7788u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xFF, 0x74, 0x24, 0x68])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(Gpr(4).state()), 0x20f8);
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut back = [0u8; 8];
    env.backend
        .mem
        .read(VirtAddr(0x20f8), &mut back, acc)
        .unwrap();
    assert_eq!(u64::from_le_bytes(back), 0x1122_3344_5566_7788);
}

#[test]
fn run_fld_m80_rip_pushes_ten_bytes() {
    // DB 2D FA 0F 00 00 = fldt [rip+0xffa]。次命令 0x1006、宛先 0x2000。dd 0x4d0e58。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x2000),
            &((1u64 << 63) | (1u64 << 62)).to_le_bytes(),
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x4000u16.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDB, 0x2D, 0xFA, 0x0F, 0x00, 0x00])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fld_m80_sibd32_pushes_three() {
    // DB AC 24 80 1D 00 00 = fldt 0x1d80(%rsp)。10 バイトを載せる。seq 0x4d0853。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x3d80),
            &((1u64 << 63) | (1u64 << 62)).to_le_bytes(),
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x3d88), &0x4000u16.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xDB, 0xAC, 0x24, 0x80, 0x1D, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fld_st0_duplicates() {
    // D9 C0 = fld %st(0)。同じ値をもう一段載せる。元の段は残る。seq 0x4d0867。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD9, 0xC0])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)),
        (1u64 << 63) | (1u64 << 62)
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fstp_m80_sib_stores_three() {
    // DB 3C 24 = fstpt (%rsp)。10 バイトを書いて ST(0) を捨てる。seq 0x4d0869。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDB, 0x3C, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut sig = [0u8; 8];
    let mut exp = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x2000), &mut sig, acc)
        .unwrap();
    env.backend
        .mem
        .read(VirtAddr(0x2008), &mut exp, acc)
        .unwrap();
    assert_eq!(u64::from_le_bytes(sig), (1u64 << 63) | (1u64 << 62));
    assert_eq!(u16::from_le_bytes(exp), 0x4000);
}

#[test]
fn run_fstp_m80_sibd32_stores_three() {
    // DB BC 24 80 1D 00 00 = fstpt 0x1d80(%rsp)。seq 0x4d0874。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.mem.map(VirtAddr(0x3000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(
            VirtAddr(0x1000),
            &[0xDB, 0xBC, 0x24, 0x80, 0x1D, 0x00, 0x00],
        )
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1007 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut got_sig = [0u8; 8];
    let mut got_exp = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x3d80), &mut got_sig, acc)
        .unwrap();
    env.backend
        .mem
        .read(VirtAddr(0x3d88), &mut got_exp, acc)
        .unwrap();
    assert_eq!(u64::from_le_bytes(got_sig), (1u64 << 63) | (1u64 << 62));
    assert_eq!(u16::from_le_bytes(got_exp), 0x4000);
}

#[test]
fn run_fld_m80_sibd_pushes_three() {
    // DB 6C 24 20 = fldt 0x20(%rsp)。10 バイトを載せる。seq 0x4d7466。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x2020),
            &((1u64 << 63) | (1u64 << 62)).to_le_bytes(),
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2028), &0x4000u16.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDB, 0x6C, 0x24, 0x20])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_or_ax_imm16_keeps_high() {
    // 66 0D FE 3F = orw $0x3ffe, %ax。上位は残る。seq 0x4d74c9。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(0).state(), 0x1234_0001);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x66, 0x0D, 0xFE, 0x3F])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(Gpr(0).state()), 0x1234_3FFF);
}

#[test]
fn run_fld_m80_sib_pushes_three() {
    // DB 2C 24 = fldt (%rsp)。10 バイトを載せる。seq 0x4d74d4。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(
            VirtAddr(0x2000),
            &((1u64 << 63) | (1u64 << 62)).to_le_bytes(),
        )
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x4000u16.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDB, 0x2C, 0x24])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fstp_m80_sibd_stores_three() {
    // DB 7C 24 20 = fstpt 0x20(%rsp)。10 バイトを書いて ST(0) を捨てる。seq 0x4d74d7。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDB, 0x7C, 0x24, 0x20])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut sig = [0u8; 8];
    let mut exp = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x2020), &mut sig, acc)
        .unwrap();
    env.backend
        .mem
        .read(VirtAddr(0x2028), &mut exp, acc)
        .unwrap();
    assert_eq!(u64::from_le_bytes(sig), (1u64 << 63) | (1u64 << 62));
    assert_eq!(u16::from_le_bytes(exp), 0x4000);
}

#[test]
fn run_fadd_st0_doubles_three() {
    // D8 C0 = fadd %st(0), %st(0)。3+3=6。seq 0x4d097d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD8, 0xC0])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
        0x4001
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fadd_st1_one_plus_three() {
    // D8 C1 = fadd %st(0), %st(1)。1+3=4。ST(1) はそのまま。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x3FFFu16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(0), 1u64 << 63);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(1), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(1),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD8, 0xC1])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
        0x4001
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)),
        1u64 << 63
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(1)),
        0x4000
    );
}

#[test]
fn run_fadd_st1_three_minus_one() {
    // D8 C1。3+(-1)=2。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(1), 0xBFFFu16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(1), 1u64 << 63);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD8, 0xC1])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)),
        1u64 << 63
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(1)),
        0xBFFF
    );
}

#[test]
fn run_fldz_pushes_zero() {
    // D9 EE = fldz。+0 を載せ、元の ST(0) は残る。seq 0x4d097f。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD9, 0xEE])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)), 0);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)), 0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
        0x4000
    );
}

#[test]
fn run_fxch_st1_swaps_three_and_one() {
    // D9 C9 = fxch %st(1)。ST(0) と ST(1) を入れ替える。seq 0x4d0981。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(1), 0x3FFFu16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(1), 1u64 << 63);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD9, 0xC9])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
        0x3FFF
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)),
        1u64 << 63
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(1)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(1)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fucomip_st1_pops() {
    // DF E9 = fucomip %st(1), %st。等しいときは ZF を立て、先頭の段を捨てる。dd 0x4d0ea6。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x8D7);
    let three = (1u64 << 63) | (1u64 << 62);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(0), three);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(1), 0x4000u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_sig_ref(1), three);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDF, 0xE9])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x42);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)), 0);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(1)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(1)),
        three
    );
}

#[test]
fn run_fucomi_st1_sets_flags() {
    // DB E9 = fucomi %st(1), %st。OF/SF/AF を消し、ZF/PF/CF だけを書く。seq 0x4d0983。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    fn once(exp0: u16, sig0: u64, exp1: u16, sig1: u64) -> u32 {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x8D7);
        env.backend.set(polyisa_guest_x86::sem::st_exp_ref(0), exp0);
        env.backend.set(polyisa_guest_x86::sem::st_sig_ref(0), sig0);
        env.backend.set(polyisa_guest_x86::sem::st_exp_ref(1), exp1);
        env.backend.set(polyisa_guest_x86::sem::st_sig_ref(1), sig1);
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0xDB, 0xE9])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 0);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)), exp0);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), sig0);
        env.backend.get(polyisa_guest_x86::sem::eflags_ref())
    }
    let three = (1u64 << 63) | (1u64 << 62);
    let one = 1u64 << 63;
    assert_eq!(once(0x4000, three, 0x3FFF, one), 0x2);
    assert_eq!(once(0x3FFF, one, 0x4000, three), 0x3);
    assert_eq!(once(0x4000, three, 0x4000, three), 0x42);
    assert_eq!(once(0xBFFF, one, 0x3FFF, one), 0x3);
    assert_eq!(once(0, 0, 0x8000, 0), 0x42);
    assert_eq!(once(0x7FFF, 0xC000_0000_0000_0000, 0x3FFF, one), 0x47);
}

#[test]
fn run_fmul_m32_rip_three_times_two() {
    // D8 0D FA 0F 00 00 = fmuls 0xffa(%rip)。ST(0) の 3 に 2.0 を掛ける。seq 0x4d0bf4。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
    env.backend
        .set(polyisa_guest_x86::sem::st_exp_ref(0), 0x4000u16);
    env.backend.set(
        polyisa_guest_x86::sem::st_sig_ref(0),
        (1u64 << 63) | (1u64 << 62),
    );
    env.backend
        .mem
        .write(VirtAddr(0x2000), &0x40000000u32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD8, 0x0D, 0xFA, 0x0F, 0x00, 0x00])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 0);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)),
        0x4001
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_sub_rm_imm8_sibd_rsp() {
    // 83 6C 24 58 1C = subl $0x1c, 0x58(%rsp)。seq 0x4d0bfa。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2058), &0x1234_0020u32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x83, 0x6C, 0x24, 0x58, 0x1C])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut got = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(0x2058), &mut got, acc)
        .unwrap();
    assert_eq!(u32::from_le_bytes(got), 0x1234_0004);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 0);
}

#[test]
fn run_fnstcw_sibd_rsp() {
    // D9 7C 24 4E = fnstcw 0x4e(%rsp)。制御ワードを書く。seq 0x4d0c17。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        let v = b.konst::<polyisa_sem::W16>(0x037F);
        b.set(polyisa_guest_x86::sem::fcw_ref(), v);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD9, 0x7C, 0x24, 0x4E])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let acc = polyisa_mem::Access {
        endian: polyisa_mem::Endian::Le,
        align: polyisa_mem::Align::Unaligned,
        kind: polyisa_mem::AccessKind::DataRead,
    };
    let mut got = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(0x204E), &mut got, acc)
        .unwrap();
    assert_eq!(u16::from_le_bytes(got), 0x037F);
}

#[test]
fn run_fldcw_sibd_rsp() {
    // D9 6C 24 4C = fldcw 0x4c(%rsp)。制御ワードを読む。seq 0x4d0c2d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        let v = b.konst::<polyisa_sem::W16>(0x037F);
        b.set(polyisa_guest_x86::sem::fcw_ref(), v);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x204C), &0x0C00u16.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xD9, 0x6C, 0x24, 0x4C])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::fcw_ref()), 0x0C00);
}

#[test]
fn run_fistp_m64_sibd_honors_rounding() {
    // DF 7C 24 30 = fistpq 0x30(%rsp)。RC に従って整数を書き、ST(0) を捨てる。
    // seq 0x4d0c31 は RC=ゼロ方向。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    fn once(exp: u16, sig: u64, fcw: u16) -> (u64, u16) {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.step(|b| {
            polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
            let cw = b.konst::<polyisa_sem::W16>(fcw);
            b.set(polyisa_guest_x86::sem::fcw_ref(), cw);
            Ok(())
        })
        .unwrap();
        env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
        env.backend.set(polyisa_guest_x86::sem::st_exp_ref(0), exp);
        env.backend.set(polyisa_guest_x86::sem::st_sig_ref(0), sig);
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0xDF, 0x7C, 0x24, 0x30])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
        let acc = polyisa_mem::Access {
            endian: polyisa_mem::Endian::Le,
            align: polyisa_mem::Align::Unaligned,
            kind: polyisa_mem::AccessKind::DataRead,
        };
        let mut got = [0u8; 8];
        env.backend
            .mem
            .read(VirtAddr(0x2030), &mut got, acc)
            .unwrap();
        (
            u64::from_le_bytes(got),
            env.backend.get(polyisa_guest_x86::sem::top_ref()),
        )
    }
    let three = (1u64 << 63) | (1u64 << 62);
    let trunc = 0x037F | 0x0C00;
    assert_eq!(once(0x4000, three, trunc).0, 3);
    assert_eq!(once(0x3FFF, three, trunc).0, 1);
    assert_eq!(once(0xBFFF, three, trunc).0, u64::MAX);
    assert_eq!(once(0x3FFF, three, 0x037F).0, 2);
    assert_eq!(once(0x3FFE, 1u64 << 63, 0x037F).0, 0);
}

#[test]
fn run_fild_m64_sibd_pushes_three() {
    // DF 6C 24 30 = fildq 0x30(%rsp)。3 を載せる。seq 0x4d0c4d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(4), 0x2000);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2030), &3u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xDF, 0x6C, 0x24, 0x30])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 7);
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_exp_ref(7)),
        0x4000
    );
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::st_sig_ref(7)),
        (1u64 << 63) | (1u64 << 62)
    );
}

#[test]
fn run_fsubp_st1_subtracts_and_pops() {
    // DE E9 = fsubp %st(1), %st。ST(1)-ST(0) を書いてポップする。seq 0x4d0c51。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let three = (1u64 << 63) | (1u64 << 62);
    let one = 1u64 << 63;
    let run = |st0_exp: u16, st0_sig: u64, st1_exp: u16, st1_sig: u64| {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(polyisa_guest_x86::sem::top_ref(), 0u16);
        env.backend
            .set(polyisa_guest_x86::sem::st_exp_ref(0), st0_exp);
        env.backend
            .set(polyisa_guest_x86::sem::st_sig_ref(0), st0_sig);
        env.backend
            .set(polyisa_guest_x86::sem::st_exp_ref(1), st1_exp);
        env.backend
            .set(polyisa_guest_x86::sem::st_sig_ref(1), st1_sig);
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0xDE, 0xE9])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::top_ref()), 1);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_exp_ref(0)), 0);
        assert_eq!(env.backend.get(polyisa_guest_x86::sem::st_sig_ref(0)), 0);
        (
            env.backend.get(polyisa_guest_x86::sem::st_exp_ref(1)),
            env.backend.get(polyisa_guest_x86::sem::st_sig_ref(1)),
        )
    };
    assert_eq!(run(0x3FFF, one, 0x4000, three), (0x4000, one));
    assert_eq!(run(0x4000, three, 0x3FFF, one), (0xC000, one));
    assert_eq!(run(0x4000, three, 0x4000, three), (0, 0));
}

#[test]
fn run_and_r_sibd_edi() {
    // 23 7C 24 3C = andl 0x3c(%rsp), %edi。seq 0x4d0d34。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(Gpr(7).state(), 0xFFFF_1234);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x203C), &0x0000_00FFu32.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x23, 0x7C, 0x24, 0x3C])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    assert_eq!(env.backend.get(Gpr(7).state()), 0x34);
    let flags = env.backend.get(polyisa_guest_x86::sem::eflags_ref());
    assert_eq!(flags & 1, 0);
    assert_eq!(flags & 0x40, 0);
}

#[test]
fn run_cmovge_r32_sibd_moves_when_sf_eq_of() {
    // 0F 4D 44 24 10 = cmovgel 0x10(%rsp), %eax。SF==OF のときだけ移す。seq 0x4d137a。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let run = |flags: u32| {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(4).state(), 0x2000);
        env.backend.set(Gpr(0).state(), 1);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), flags);
        env.backend
            .mem
            .write(VirtAddr(0x2010), &0x42u32.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x0F, 0x4D, 0x44, 0x24, 0x10])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
        env.backend.get(Gpr(0).state())
    };
    assert_eq!(run(0), 0x42);
    assert_eq!(run(0x880), 0x42);
    assert_eq!(run(0x80), 1);
}

#[test]
fn run_mov_r32_imm_clears_high() {
    // BE 80 00 00 00 = movl $0x80, %esi。上位32ビットは消える。nproc の長さ引数。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(6).state(), 0x1111_1111);
    env.backend
        .set(polyisa_guest_x86::sem::hi_ref(Gpr(6)), 0x2222_2222);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xBE, 0x80, 0x00, 0x00, 0x00])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(6)),
        0x80
    );
}

#[test]
fn run_dec_r8_preserves_carry() {
    // FE CA = dec %dl。1 は 0 になり、キャリーは残る。dc 0x40efa1。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(2).state(), 0xAB01);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x3);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xFE, 0xCA])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(Gpr(2).state()), 0xAB00);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x47);

    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(2).state(), 0x80);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x3);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xFE, 0xC2])
        .unwrap();
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(Gpr(2).state()), 0x81);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 1);
}

#[test]
fn run_xchg_r8_swaps_bytes() {
    // 86 E9 = xchg %ch, %cl。86 D8 = xchg %bl, %al。フラグは残す。base64 0x4bd97a。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(1).state(), 0xABCD_1234);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 0x8D5);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x86, 0xE9])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(Gpr(1).state()), 0xABCD_3412);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()), 0x8D5);

    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.set(Gpr(0).state(), 0xAA11);
    env.backend.set(Gpr(3).state(), 0xBB22);
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x86, 0xD8])
        .unwrap();
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1002 });
    assert_eq!(env.backend.get(Gpr(0).state()), 0xAA22);
    assert_eq!(env.backend.get(Gpr(3).state()), 0xBB11);
}

#[test]
fn run_cmovne_r64_mem8() {
    // 48 0F 45 43 30 = cmovne 0x30(%rbx), %rax。ZF=0 のときだけ移す。ed 0x4b5cd8。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let run = |flags: u32| {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(3), 0x2000);
        polyisa_guest_x86::sem::write64(&mut env.backend, Gpr(0), 1);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), flags);
        env.backend
            .mem
            .write(VirtAddr(0x2030), &0x99u64.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x48, 0x0F, 0x45, 0x43, 0x30])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
        polyisa_guest_x86::sem::read64(&mut env.backend, Gpr(0))
    };
    assert_eq!(run(0), 0x99);
    assert_eq!(run(0x40), 1);
}

#[test]
fn run_cmovs_r32_sib_rsp() {
    // 0F 48 0C 24 = cmovsl (%rsp), %ecx。SF=1 のときだけ移す。sed 0x4c9eb0。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let run = |flags: u32| {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(4).state(), 0x2000);
        env.backend.set(Gpr(1).state(), 0x22);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), flags);
        env.backend
            .mem
            .write(VirtAddr(0x2000), &0x11u32.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x0F, 0x48, 0x0C, 0x24])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
        env.backend.get(Gpr(1).state())
    };
    assert_eq!(run(0), 0x22);
    assert_eq!(run(0x80), 0x11);
}

#[test]
fn run_cmovl_r32_sib_rsp() {
    // 44 0F 4C 14 24 = cmovll (%rsp), %r10d。SF!=OF のときだけ移す。cut 0x492257。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let run = |flags: u32| {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
        env.backend.set(Gpr(4).state(), 0x2000);
        env.backend.set(Gpr(10).state(), 1);
        env.backend.set(polyisa_guest_x86::sem::eflags_ref(), flags);
        env.backend
            .mem
            .write(VirtAddr(0x2000), &0x99u32.to_le_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x44, 0x0F, 0x4C, 0x14, 0x24])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
        env.backend.get(Gpr(10).state())
    };
    assert_eq!(run(0), 1);
    assert_eq!(run(0x880), 1);
    assert_eq!(run(0x80), 0x99);
    assert_eq!(run(0x800), 0x99);
}

#[test]
fn run_mulsd_xmm_m64_sibd_three_times_two() {
    // F2 0F 59 44 24 08 = mulsd 0x8(%rsp), %xmm0。3.0*2.0=6.0。上位64は残す。seq 0x49924a。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(
        polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
        0x1111_0000_0000_0000_4008_0000_0000_0000u128,
    );
    env.backend
        .mem
        .write(VirtAddr(0x2008), &0x4000_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF2, 0x0F, 0x59, 0x44, 0x24, 0x08])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v, 0x1111_0000_0000_0000_4018_0000_0000_0000u128);
}

#[test]
fn run_addsd_xmm_m64_sibd_three_plus_two() {
    // F2 0F 58 44 24 10 = addsd 0x10(%rsp), %xmm0。3.0+2.0=5.0。上位64は残す。seq 0x499253。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(
        polyisa_guest_x86::sem::xmm_ref(polyisa_guest_x86::sem::Xmm(0)),
        0x1111_0000_0000_0000_4008_0000_0000_0000u128,
    );
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0x4000_0000_0000_0000u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0xF2, 0x0F, 0x58, 0x44, 0x24, 0x10])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let v: u128 = env.backend.get(polyisa_guest_x86::sem::xmm_ref(
        polyisa_guest_x86::sem::Xmm(0),
    ));
    assert_eq!(v, 0x1111_0000_0000_0000_4014_0000_0000_0000u128);
}

#[test]
fn run_add_m64_r64_sib_scaled() {
    // 4E 01 3C E3 = addq %r15, (%rbx,%r12,8)。5+3=8。sort 0x4d2c0d。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.step(|b| {
        polyisa_guest_x86::sem::write64(b, Gpr(3), 0x2000);
        polyisa_guest_x86::sem::write64(b, Gpr(12), 1);
        polyisa_guest_x86::sem::write64(b, Gpr(15), 3);
        Ok(())
    })
    .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x2008), &5u64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x4E, 0x01, 0x3C, 0xE3])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1004 });
    let mut got = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2008),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(got), 8);
}

#[test]
fn run_xor_rm_imm8_sibd_rsp() {
    // 48 83 74 24 10 07 = xorq $0x7, 0x10(%rsp)。sort 0x4d3045。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    env.backend.set(polyisa_guest_x86::sem::eflags_ref(), 1);
    env.backend
        .mem
        .write(VirtAddr(0x2010), &0x0123_0000_0000_00FFu64.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x48, 0x83, 0x74, 0x24, 0x10, 0x07])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1006 });
    let mut got = [0u8; 8];
    env.backend
        .mem
        .read(
            VirtAddr(0x2010),
            &mut got,
            polyisa_mem::Access {
                endian: polyisa_mem::Endian::Le,
                align: polyisa_mem::Align::Unaligned,
                kind: polyisa_mem::AccessKind::DataRead,
            },
        )
        .unwrap();
    assert_eq!(u64::from_le_bytes(got), 0x0123_0000_0000_00F8);
    assert_eq!(env.backend.get(polyisa_guest_x86::sem::eflags_ref()) & 1, 0);
}

#[test]
fn run_movaps_load_sibd_rsp() {
    // 0F 28 44 24 50 = movaps 0x50(%rsp), %xmm0。diff -q 0x4a55eb。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
    env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
    env.backend.mem.map(VirtAddr(0x2000), 1, Perms::RW).unwrap();
    env.backend.set(Gpr(4).state(), 0x2000);
    let bits = 0x2222_0000_0000_0000_1111_0000_0000_0000u128;
    env.backend
        .mem
        .write(VirtAddr(0x2050), &bits.to_le_bytes())
        .unwrap();
    env.backend
        .mem
        .write(VirtAddr(0x1000), &[0x0F, 0x28, 0x44, 0x24, 0x50])
        .unwrap();
    let mut sys = X64Exit;
    let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
    assert_eq!(out, Outcome::StepLimit { eip: 0x1005 });
    assert_eq!(
        env.backend.get(polyisa_guest_x86::sem::xmm_ref(
            polyisa_guest_x86::sem::Xmm(0)
        )),
        bits
    );
}

#[test]
fn run_cmp_si_dx_sets_flags() {
    // 66 39 D6 = cmpw %dx, %si。SI-DX の旗だけを更新する。fgrep 0x401227。
    // Ref: SPEC-X86-INTEL-SDM (v093).
    let run = |si: u32, dx: u32| {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(0x1000), 1, rwx).unwrap();
        env.backend.set(Gpr(6).state(), si);
        env.backend.set(Gpr(2).state(), dx);
        env.backend
            .mem
            .write(VirtAddr(0x1000), &[0x66, 0x39, 0xD6])
            .unwrap();
        let mut sys = X64Exit;
        let out = run_x86::run_mode(&mut env, 0x1000, &mut sys, 1, true);
        assert_eq!(out, Outcome::StepLimit { eip: 0x1003 });
        assert_eq!(env.backend.get(Gpr(6).state()), si);
        assert_eq!(env.backend.get(Gpr(2).state()), dx);
        env.backend.get(polyisa_guest_x86::sem::eflags_ref())
    };
    assert_eq!(run(0x1234, 0x0034) & 0x41, 0);
    assert_eq!(run(0x0034, 0x0034) & 0x41, 0x40);
    assert_eq!(run(0x0010, 0x0020) & 1, 1);
}
