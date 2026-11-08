//! riscv-tests の RV64UI 実行（層5・conformance）。
//!
//! `.testdata/riscv-tests` の1件を clang＋rust-lld でビルドし、自前の
//! run loop（fetch/decode/dispatch）で実行して合否を見る。終了規約は
//! `ecall`（a7=93）の a0（0=成功）である（`env/p/riscv_test.h` の
//! RVTEST_PASS/FAIL）。
//!
//! 使う外部ツールは台帳 TOOL-RUST（clang）と TOOL-LLVM ではなく rust-lld
//! （Rust 配布物、用途X・確認済み）。テストデータは台帳 TEST-RISCV-TESTS
//! （用途T・確認済み、リポジトリに含めない）.

use polyisa_engine::bare::BareEnv;
use polyisa_guest_riscv::sem::{Csr, Gpr};
use polyisa_guest_riscv::{CpuState, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, StateRef, W64};
use std::path::{Path, PathBuf};
use std::process::Command;

const STEP_LIMIT: u64 = 5_000_000;

fn testdata() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("riscv-tests")
}

fn bin(candidates: &[&str]) -> Option<String> {
    for c in candidates {
        if Command::new(c).arg("--version").output().is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

/// rustc の sysroot から rust-lld を探す。
fn rust_lld() -> Option<String> {
    let sysroot = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())?;
    let host = Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())?
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_string))?;
    let p = Path::new(&sysroot)
        .join("lib")
        .join("rustlib")
        .join(&host)
        .join("bin")
        .join("rust-lld");
    if p.exists() {
        return p.to_str().map(str::to_string);
    }
    // フォールバック：ツールチェーン下を探索する。
    let home = std::env::var("HOME").ok()?;
    let mut found = None;
    for e in walkdir(&Path::new(&home).join(".rustup/toolchains")) {
        if e.ends_with("rust-lld") {
            found = Some(e);
            break;
        }
    }
    found.and_then(|p| p.to_str().map(str::to_string))
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walkdir(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// 1件をビルドして ELF のバイト列を返す。道具がなければ None。
fn build_elf(name: &str) -> Option<Vec<u8>> {
    let root = testdata();
    let src = root.join("isa").join("rv64ui").join(format!("{name}.S"));
    if !src.exists() {
        return None;
    }
    let cc = bin(&["clang", "/usr/sbin/clang", "/usr/bin/clang"])?;
    let lld = rust_lld()?;
    let dir = std::env::temp_dir().join("polyisa-riscv-tests");
    let _ = std::fs::create_dir_all(&dir);
    let obj = dir.join(format!("{name}.o"));
    let elf = dir.join(format!("{name}.elf"));
    let st = Command::new(&cc)
        .args([
            "--target=riscv64-unknown-elf",
            "-march=rv64g",
            "-mabi=lp64d",
            "-mcmodel=medany",
            "-fvisibility=hidden",
            "-nostdlib",
            "-nostartfiles",
            "-I",
            root.join("env/p").to_str()?,
            "-I",
            root.join("isa/macros/scalar").to_str()?,
            "-c",
            src.to_str()?,
            "-o",
            obj.to_str()?,
        ])
        .output()
        .ok()?;
    if !st.status.success() {
        return None;
    }
    let st = Command::new(&lld)
        .args([
            "-flavor",
            "gnu",
            "-T",
            root.join("env/p/link.ld").to_str()?,
            obj.to_str()?,
            "-o",
            elf.to_str()?,
        ])
        .output()
        .ok()?;
    if !st.status.success() {
        return None;
    }
    std::fs::read(&elf).ok()
}

fn acc_fetch() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    }
}

fn reg(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
}

enum Outcome {
    Exit(u64),
    Unimplemented { pc: u64, word: u32 },
    StepLimit { pc: u64 },
}

/// I形式即値。
fn imm_i(word: u32) -> i64 {
    ((word as i32) >> 20) as i64
}

/// U形式20ビット。bit19から符号拡張する。
fn imm_u(word: u32) -> i64 {
    ((((word >> 12) & 0xF_FFFF) as i32) << 12 >> 12) as i64
}

/// S形式即値。
fn imm_s(word: u32) -> i64 {
    let v = ((word >> 25) << 5) | ((word >> 7) & 31);
    ((v as i32) << 20 >> 20) as i64
}

/// B形式分岐オフセット。
fn off_b(word: u32) -> i64 {
    let b12 = (word >> 31) & 1;
    let b11 = (word >> 7) & 1;
    let b10_5 = (word >> 25) & 63;
    let b4_1 = (word >> 8) & 15;
    let v = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    ((v as i32) << 19 >> 19) as i64
}

/// J形式ジャンプオフセット。
fn off_j(word: u32) -> i64 {
    let b20 = (word >> 31) & 1;
    let b10_1 = (word >> 21) & 0x3ff;
    let b11 = (word >> 20) & 1;
    let b19_12 = (word >> 12) & 0xff;
    let v = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    ((v as i32) << 11 >> 11) as i64
}

fn run(env: &mut BareEnv, entry: u64) -> Outcome {
    use polyisa_guest_riscv::Insn;
    env.pc = entry;
    for _ in 0..STEP_LIMIT {
        let mut w = [0u8; 4];
        if env
            .backend
            .mem
            .read(VirtAddr(env.pc), &mut w, acc_fetch())
            .is_err()
        {
            return Outcome::Unimplemented {
                pc: env.pc,
                word: 0xffff_ffff,
            };
        }
        let word = u32::from_le_bytes(w);
        // MRET（特権。user-mode相当のrunnerでは mepc へ戻す）。
        if word == 0x3020_0073 {
            let mepc: u64 = env.backend.get(StateRef::<W64>::from_offset(
                core::mem::offset_of!(CpuState, csr) + 0x341 * 8,
            ));
            env.pc = mepc;
            continue;
        }
        // C拡張はこの対象（rv64g）には含めない。
        if word & 0b11 != 0b11 {
            return Outcome::Unimplemented { pc: env.pc, word };
        }
        let Some(insn) = polyisa_guest_riscv::decode(word as u128, 32) else {
            return Outcome::Unimplemented { pc: env.pc, word };
        };
        let r = |b: u32, lo: u32| ((word >> lo) & ((1u32 << b) - 1)) as u8;
        let rd = Gpr(r(5, 7));
        let rs1 = Gpr(r(5, 15));
        let rs2 = Gpr(r(5, 20));
        let csr = Csr(((word >> 20) & 0xfff) as u16);
        let ok = match insn {
            Insn::Add => env.step(|b| sem::add(b, rd, rs1, rs2)),
            Insn::Addi => env.step(|b| sem::addi(b, rd, rs1, imm_i(word))),
            Insn::Addiw => env.step(|b| sem::addiw(b, rd, rs1, imm_i(word))),
            Insn::Lui => env.step(|b| sem::lui(b, rd, imm_u(word))),
            Insn::Auipc => {
                let pc = env.pc;
                env.step(|b| sem::auipc(b, rd, pc, imm_u(word)))
            }
            Insn::Jal => {
                let pc = env.pc;
                env.step(|b| sem::jal(b, rd, pc, off_j(word)))
            }
            Insn::Jalr => {
                let pc = env.pc;
                env.step(|b| sem::jalr(b, rd, rs1, pc, imm_i(word)))
            }
            Insn::Beq => {
                let pc = env.pc;
                env.step(|b| sem::beq(b, rs1, rs2, pc, off_b(word)))
            }
            Insn::Bne => {
                let pc = env.pc;
                env.step(|b| sem::bne(b, rs1, rs2, pc, off_b(word)))
            }
            Insn::Blt => {
                let pc = env.pc;
                env.step(|b| sem::blt(b, rs1, rs2, pc, off_b(word)))
            }
            Insn::Bge => {
                let pc = env.pc;
                env.step(|b| sem::bge(b, rs1, rs2, pc, off_b(word)))
            }
            Insn::Bltu => {
                let pc = env.pc;
                env.step(|b| sem::bltu(b, rs1, rs2, pc, off_b(word)))
            }
            Insn::Bgeu => {
                let pc = env.pc;
                env.step(|b| sem::bgeu(b, rs1, rs2, pc, off_b(word)))
            }
            Insn::Lb => env.step(|b| sem::lb(b, rd, rs1, imm_i(word))),
            Insn::Lh => env.step(|b| sem::lh(b, rd, rs1, imm_i(word))),
            Insn::Lw => env.step(|b| sem::lw(b, rd, rs1, imm_i(word))),
            Insn::Ld => env.step(|b| sem::ld(b, rd, rs1, imm_i(word))),
            Insn::Lbu => env.step(|b| sem::lbu(b, rd, rs1, imm_i(word))),
            Insn::Lhu => env.step(|b| sem::lhu(b, rd, rs1, imm_i(word))),
            Insn::Lwu => env.step(|b| sem::lwu(b, rd, rs1, imm_i(word))),
            Insn::Sb => env.step(|b| sem::sb(b, rs1, rs2, imm_s(word))),
            Insn::Sh => env.step(|b| sem::sh(b, rs1, rs2, imm_s(word))),
            Insn::Sw => env.step(|b| sem::sw(b, rs1, rs2, imm_s(word))),
            Insn::Sd => env.step(|b| sem::sd(b, rs1, rs2, imm_s(word))),
            Insn::Slli => env.step(|b| sem::slli(b, rd, rs1, ((word >> 20) & 63) as u64)),
            Insn::Srli => env.step(|b| sem::srli(b, rd, rs1, ((word >> 20) & 63) as u64)),
            Insn::Srai => env.step(|b| sem::srai(b, rd, rs1, ((word >> 20) & 63) as u64)),
            Insn::Sub => env.step(|b| sem::sub(b, rd, rs1, rs2)),
            Insn::Sll => env.step(|b| sem::sll(b, rd, rs1, rs2)),
            Insn::Slt => env.step(|b| sem::slt(b, rd, rs1, rs2)),
            Insn::Sltu => env.step(|b| sem::sltu(b, rd, rs1, rs2)),
            Insn::Xor => env.step(|b| sem::xor(b, rd, rs1, rs2)),
            Insn::Or => env.step(|b| sem::or(b, rd, rs1, rs2)),
            Insn::And => env.step(|b| sem::and(b, rd, rs1, rs2)),
            Insn::Sra => env.step(|b| sem::sra(b, rd, rs1, rs2)),
            Insn::Slti => env.step(|b| sem::slti(b, rd, rs1, imm_i(word))),
            Insn::Sltiu => env.step(|b| sem::sltiu(b, rd, rs1, imm_i(word))),
            Insn::Xori => env.step(|b| sem::xori(b, rd, rs1, imm_i(word))),
            Insn::Ori => env.step(|b| sem::ori(b, rd, rs1, imm_i(word))),
            Insn::Andi => env.step(|b| sem::andi(b, rd, rs1, imm_i(word))),
            Insn::Csrrw => env.step(|b| sem::csrrw(b, rd, rs1, csr)),
            Insn::Csrrs => env.step(|b| sem::csrrs(b, rd, rs1, csr)),
            Insn::Csrrc => env.step(|b| sem::csrrc(b, rd, rs1, csr)),
            Insn::Csrrwi => env.step(|b| sem::csrrwi(b, rd, ((word >> 15) & 31) as u64, csr)),
            Insn::Csrrsi => env.step(|b| sem::csrrsi(b, rd, ((word >> 15) & 31) as u64, csr)),
            Insn::Csrrci => env.step(|b| sem::csrrci(b, rd, ((word >> 15) & 31) as u64, csr)),
            Insn::Fence => env.step(sem::fence),
            Insn::FenceI => env.step(sem::fence_i),
            Insn::Ecall => {
                let a7 = reg(env, 17);
                if a7 == 93 {
                    return Outcome::Exit(reg(env, 10));
                }
                return Outcome::Unimplemented { pc: env.pc, word };
            }
            _ => return Outcome::Unimplemented { pc: env.pc, word },
        };
        if ok.is_err() {
            return Outcome::Unimplemented { pc: env.pc, word };
        }
        // 分岐なしは次へ進める（分岐成立は step が pc を置き換える）。
        if env.backend.ctrl == polyisa_engine::interp::Ctrl::Fallthrough {
            env.pc += 4;
        }
    }
    Outcome::StepLimit { pc: env.pc }
}

fn check_one(name: &str) {
    let root = testdata();
    if !root.join(format!("isa/rv64ui/{name}.S")).exists() {
        eprintln!("skip: .testdata/riscv-tests がないため未実行");
        return;
    }
    let Some(bytes) = build_elf(name) else {
        eprintln!("skip: 組み立て器がないため未実行");
        return;
    };
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).expect("ELFヘッダ");
    let phdrs = polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).expect("PHDR");
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    polyisa_loader::elf::load_segments(&bytes, &phdrs, &mut env.backend.mem).expect("配置");
    match run(&mut env, ehdr.entry) {
        Outcome::Exit(code) => assert_eq!(code, 0, "{name} が失敗"),
        Outcome::Unimplemented { pc, word } => {
            panic!("{name}: 未実装に到達 pc={pc:#x} word={word:#x}")
        }
        Outcome::StepLimit { pc } => panic!("{name}: 予算切れ pc={pc:#x}"),
    }
}

#[test]
fn rv64ui_p_addi() {
    check_one("addi");
}

#[test]
fn rv64ui_p_add() {
    check_one("add");
}

#[test]
fn rv64ui_p_sub() {
    check_one("sub");
}

#[test]
fn rv64ui_p_lw() {
    check_one("lw");
}

#[test]
fn rv64ui_p_sw() {
    check_one("sw");
}

#[test]
fn rv64ui_p_beq() {
    check_one("beq");
}

#[test]
fn rv64ui_p_jal() {
    check_one("jal");
}

#[test]
fn rv64ui_p_jalr() {
    check_one("jalr");
}

#[test]
fn rv64ui_p_sll() {
    check_one("sll");
}

#[test]
fn rv64ui_p_sra() {
    check_one("sra");
}

#[test]
fn rv64ui_p_and() {
    check_one("and");
}

#[test]
fn rv64ui_p_or() {
    check_one("or");
}
