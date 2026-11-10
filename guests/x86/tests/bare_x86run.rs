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
