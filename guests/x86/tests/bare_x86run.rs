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
