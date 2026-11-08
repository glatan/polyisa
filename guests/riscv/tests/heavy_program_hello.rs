//! 最小の静的プログラム実行（層7・program）。
//!
//! 手順は検証戦略の層7に従う。手で組み立てた RV64 の静的バイナリ
//! （write + exit_group）をローダで配置し、裸実行で1命令ずつ進め、
//! 出力と終了コードを確かめる。動的リンク・VFS・シグナルは後の段階。
//!
//! 使う資料は台帳 SPEC-ELF-GABI（配置）、SPEC-RISCV-PSABI（初期状態の考え方）、
//! SRC-LINUX（番号表・用途Fはos-linux側で注記）。ここでは自前の符号化のみ使う.

use polyisa_engine::bare::BareEnv;
use polyisa_guest_riscv::sem::Gpr;
use polyisa_guest_riscv::{CpuState, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::Backend as _;

const BASE: u64 = 0x1_0000;

fn acc_fetch() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    }
}

fn acc_read() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Unaligned,
        kind: AccessKind::DataRead,
    }
}

fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | ((rs1 & 31) << 15) | ((rd & 31) << 7) | 0x13
}

/// 手組み ELF（64LE・LOAD1件）。コードの後に "hi\n" を置く.
fn image() -> Vec<u8> {
    // addi a0,zero,1 / auipc a1,0 / addi a1,a1,32 / addi a2,zero,3
    // addi a7,zero,64 / ecall / addi a0,zero,0 / addi a7,zero,94 / ecall
    let code: [u32; 9] = [
        addi(10, 0, 1),
        0x0000_0597,
        0x0205_8593,
        addi(12, 0, 3),
        addi(17, 0, 64),
        0x0000_0073,
        addi(10, 0, 0),
        addi(17, 0, 94),
        0x0000_0073,
    ];
    let data = b"hi\n";
    let filesz = 64 + 56 + code.len() * 4 + data.len();
    let mut v = vec![0u8; filesz];
    v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    v[4] = 2;
    v[5] = 1;
    v[6] = 1;
    v[16..18].copy_from_slice(&2u16.to_le_bytes());
    v[24..32].copy_from_slice(&(BASE + 120).to_le_bytes());
    v[32..40].copy_from_slice(&64u64.to_le_bytes());
    v[52..54].copy_from_slice(&64u16.to_le_bytes());
    v[54..56].copy_from_slice(&56u16.to_le_bytes());
    v[56..58].copy_from_slice(&1u16.to_le_bytes());
    let p = 64;
    v[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
    v[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes());
    v[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
    v[p + 16..p + 24].copy_from_slice(&BASE.to_le_bytes());
    v[p + 32..p + 40].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 40..p + 48].copy_from_slice(&(filesz as u64).to_le_bytes());
    v[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    let mut off = 64 + 56;
    for w in code {
        v[off..off + 4].copy_from_slice(&w.to_le_bytes());
        off += 4;
    }
    v[off..off + data.len()].copy_from_slice(data);
    v
}

fn reg(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

#[test]
fn static_hello_write_exit() {
    let bytes = image();
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).unwrap();
    assert_eq!(ehdr.entry, BASE + 120);
    let phdrs = polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).unwrap();
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    polyisa_loader::elf::load_segments(&bytes, &phdrs, &mut env.backend.mem).unwrap();
    // 初期スタック（空引き数・空環境・空auxv）。
    let top = 0x7fff_0000u64;
    let (_img, sp) = polyisa_os_linux::build_initial_stack(top, &[], &[], &[]);
    env.backend.set(Gpr(2).state(), sp);
    env.pc = ehdr.entry;

    let mut out = Vec::new();
    let mut exit_code: Option<u64> = None;
    for _ in 0..32 {
        let mut w = [0u8; 4];
        env.backend
            .mem
            .read(VirtAddr(env.pc), &mut w, acc_fetch())
            .unwrap();
        let word = u32::from_le_bytes(w);
        if word == 0x0000_0073 {
            // ecall。a7 で分岐する。
            let nr = reg(&mut env, 17);
            let name = polyisa_os_linux::syscall_name(polyisa_os_linux::GuestAbi::Rv64Linux, nr);
            if nr == polyisa_os_linux::rv64::WRITE {
                assert_eq!(name, Some("write"));
                let fd = reg(&mut env, 10);
                let buf = reg(&mut env, 11);
                let len = reg(&mut env, 12) as usize;
                assert_eq!(fd, 1);
                let mut data = vec![0u8; len];
                env.backend
                    .mem
                    .read(VirtAddr(buf), &mut data, acc_read())
                    .unwrap();
                out.extend_from_slice(&data);
                env.pc += 4;
                continue;
            }
            if nr == polyisa_os_linux::rv64::EXIT_GROUP {
                exit_code = Some(reg(&mut env, 10));
                break;
            }
            panic!("unexpected syscall {nr}");
        }
        // addi / auipc のみを手で復号する（全命令の operand 対応は後の段階）。
        let op = word & 0x7f;
        if op == 0x13 {
            let rd = ((word >> 7) & 31) as u8;
            let rs1 = ((word >> 15) & 31) as u8;
            let imm = ((word as i32) >> 20) as i64;
            env.step(|b| sem::addi(b, Gpr(rd), Gpr(rs1), imm)).unwrap();
            env.pc += 4;
            continue;
        }
        if op == 0x17 {
            let rd = ((word >> 7) & 31) as u8;
            let imm20 = ((word as i32) >> 12) as i64;
            let pc = env.pc;
            env.step(|b| sem::auipc(b, Gpr(rd), pc, imm20)).unwrap();
            env.pc += 4;
            continue;
        }
        panic!("unsupported word {word:#x} at {:#x}", env.pc);
    }
    assert_eq!(out, b"hi\n");
    assert_eq!(exit_code, Some(0));
}
