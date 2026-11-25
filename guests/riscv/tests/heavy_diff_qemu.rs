// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0030
//! QEMU user-mode との RV64 実行差分（層: diff、E3）。
//!
//! RV64I の整数演算で作った 64 ビット値を静的 ELF から stdout へ
//! 書き、同じ ELF を polyisa と `qemu-riscv64` で実行して出力と
//! 終了コードを比較する。qemu-riscv64 がなければスキップする。

use std::process::Command;

use polyisa_cli::run_riscv::{EcallHandler, EcallOutcome, reg, run_elf_handler};
use polyisa_engine::bare::BareEnv;
use polyisa_guest_riscv::sem::Gpr;
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::Backend as _;

const BASE: u64 = 0x1_0000;

fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | ((rs1 & 31) << 15) | ((rd & 31) << 7) | 0x13
}

fn lui(rd: u32, imm20: u32) -> u32 {
    (imm20 << 12) | ((rd & 31) << 7) | 0x37
}

fn rtype(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32) -> u32 {
    ((funct7 & 0x7f) << 25)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((rd & 31) << 7)
        | 0x33
}

fn shiftimm(rd: u32, rs1: u32, shamt: u32, funct3: u32, high: u32) -> u32 {
    ((high & 0x3f) << 26)
        | ((shamt & 0x3f) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((rd & 31) << 7)
        | 0x13
}

fn stype(imm: i32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
    let i = (imm as u32) & 0xfff;
    ((i >> 5) << 25)
        | ((rs2 & 31) << 20)
        | ((rs1 & 31) << 15)
        | ((funct3 & 7) << 12)
        | ((i & 31) << 7)
        | 0x23
}

fn expected() -> u64 {
    let mut t0 = 0x1234_5000u64;
    t0 = t0.wrapping_add(0x678);
    t0 <<= 32;
    let mut t1 = 0x7654_3000u64;
    t1 = t1.wrapping_sub(1024);
    t0 |= t1;
    t0 ^= 73;
    let left = t0 << 3;
    let right = t0 >> 5;
    t0 = left.wrapping_sub(right);
    t0 &= (-123i64) as u64;
    t0
}

/// コード列と、結果を置く 8 バイトを含む 1 セグメント ELF。
fn image() -> Vec<u8> {
    let auipc_index = 12usize;
    let mut code = vec![
        lui(5, 0x12345),
        addi(5, 5, 0x678),
        shiftimm(5, 5, 32, 1, 0), // slli t0,t0,32
        lui(6, 0x76543),
        addi(6, 6, -1024),
        rtype(0, 6, 5, 6, 5), // or t0,t0,t1
        addi(7, 0, 73),
        rtype(0, 7, 5, 4, 5),    // xor t0,t0,t2
        shiftimm(6, 5, 3, 1, 0), // slli t1,t0,3
        shiftimm(7, 5, 5, 5, 0), // srli t2,t0,5
        rtype(0x20, 7, 6, 0, 5), // sub t0,t1,t2
        addi(6, 0, -123),
        0x0000_0597,          // auipc a1,0
        0,                    // addi a1,a1,out（後で差し替え）
        rtype(0, 6, 5, 7, 5), // and t0,t0,t1
        stype(0, 5, 11, 3),   // sd t0,0(a1)
        addi(10, 0, 1),
        addi(12, 0, 8),
        addi(17, 0, 64),
        0x0000_0073, // ecall: write
        addi(10, 0, 0),
        addi(17, 0, 94),
        0x0000_0073, // ecall: exit_group
    ];
    // auipc の次の addi が自己書き換えされないよう、out は命令列の
    // 直後に置く。単一セグメントなので file offset 差と VA 差は同じ。
    let auipc_file_off = 64 + 56 + auipc_index * 4;
    let out_file_off = 64 + 56 + code.len() * 4;
    code[auipc_index + 1] = addi(11, 11, (out_file_off - auipc_file_off) as i32);

    let filesz = out_file_off + 8;
    let mut v = vec![0u8; filesz];
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2; // ELFCLASS64
    v[5] = 1; // little endian
    v[6] = 1;
    v[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    v[18..20].copy_from_slice(&243u16.to_le_bytes()); // EM_RISCV
    v[20..24].copy_from_slice(&1u32.to_le_bytes());
    v[24..32].copy_from_slice(&(BASE + 120).to_le_bytes());
    v[32..40].copy_from_slice(&64u64.to_le_bytes());
    v[52..54].copy_from_slice(&64u16.to_le_bytes());
    v[54..56].copy_from_slice(&56u16.to_le_bytes());
    v[56..58].copy_from_slice(&1u16.to_le_bytes());
    let p = 64;
    v[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    v[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes()); // RWX
    v[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
    v[p + 16..p + 24].copy_from_slice(&BASE.to_le_bytes());
    v[p + 24..p + 32].copy_from_slice(&BASE.to_le_bytes());
    v[p + 32..p + 40].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 40..p + 48].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    let mut off = 64 + 56;
    for w in code {
        v[off..off + 4].copy_from_slice(&w.to_le_bytes());
        off += 4;
    }
    v
}

struct Capture {
    out: Vec<u8>,
}

impl EcallHandler for Capture {
    fn handle_ecall(&mut self, env: &mut BareEnv, _word: u32) -> EcallOutcome {
        let nr = reg(env, 17);
        if nr == polyisa_os_linux::rv64::WRITE {
            let fd = reg(env, 10);
            let buf = reg(env, 11);
            let len = reg(env, 12) as usize;
            if fd != 1 {
                return EcallOutcome::Unimplemented;
            }
            let mut data = vec![0u8; len];
            let acc = Access {
                endian: Endian::Le,
                align: Align::Unaligned,
                kind: AccessKind::DataRead,
            };
            if env.backend.mem.read(VirtAddr(buf), &mut data, acc).is_err() {
                return EcallOutcome::Unimplemented;
            }
            env.backend.set(Gpr(10).state(), len as u64);
            self.out.extend_from_slice(&data);
            return EcallOutcome::Handled;
        }
        if nr == polyisa_os_linux::rv64::EXIT_GROUP || nr == polyisa_os_linux::rv64::EXIT {
            return EcallOutcome::Exit(reg(env, 10));
        }
        EcallOutcome::Unimplemented
    }
}

fn qemu_path() -> Option<&'static str> {
    ["qemu-riscv64", "/usr/bin/qemu-riscv64"]
        .into_iter()
        .find(|c| {
            Command::new(c)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
}

#[test]
fn diff_qemu_rv64i_program() {
    let Some(qemu) = qemu_path() else {
        eprintln!("qemu-riscv64 がない。スキップ");
        return;
    };
    let dir = std::env::temp_dir().join(format!("polyisa-qemu-rv64-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("rv64diff");
    std::fs::write(&elf, image()).unwrap();
    // qemu-user はインタプリタとして読むが、実行ビットがない ELF は
    // 失敗させる。ホストの umask に依存しないよう明示する。
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&elf, std::fs::Permissions::from_mode(0o755)).unwrap();

    let qout = Command::new(qemu).arg(&elf).output().expect("qemu-riscv64");
    assert!(
        qout.status.success(),
        "qemu status {:?}: {}",
        qout.status,
        String::from_utf8_lossy(&qout.stderr)
    );

    let mut cap = Capture { out: Vec::new() };
    let argv = vec![elf.to_str().unwrap().to_string()];
    let code = run_elf_handler(elf.to_str().unwrap(), &argv, None, &mut cap).expect("polyisa run");
    assert_eq!(code, 0, "poly exit");
    assert_eq!(qout.stdout.len(), 8, "qemu stdout len");
    assert_eq!(cap.out.len(), 8, "poly stdout len");
    assert_eq!(cap.out, qout.stdout, "qemu/poly stdout");
    assert_eq!(
        u64::from_le_bytes(cap.out.try_into().unwrap()),
        expected(),
        "independent integer expectation"
    );
}

#[test]
fn rv64diff_image_layout() {
    let bytes = image();
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).unwrap();
    assert_eq!(ehdr.machine, 243);
    assert_eq!(ehdr.entry, BASE + 120);
}
