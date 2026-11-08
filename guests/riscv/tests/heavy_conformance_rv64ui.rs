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
use polyisa_guest_riscv::sem::{Csr, Fpr, Gpr};
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
fn build_elf_in(sub: &str, name: &str) -> Option<Vec<u8>> {
    let root = testdata();
    let src = root.join("isa").join(sub).join(format!("{name}.S"));
    if !src.exists() {
        return None;
    }
    let cc = bin(&["clang", "/usr/sbin/clang", "/usr/bin/clang"])?;
    let lld = rust_lld()?;
    // RV32 と RV64 でツールチェインの指定を切り替える。
    let rv32 = sub.starts_with("rv32");
    let (target, march, abi, emul) = if rv32 {
        ("riscv32-unknown-elf", "rv32g", "ilp32d", "elf32lriscv")
    } else {
        ("riscv64-unknown-elf", "rv64g", "lp64d", "elf64lriscv")
    };
    let dir = std::env::temp_dir().join("polyisa-riscv-tests");
    let _ = std::fs::create_dir_all(&dir);
    let obj = dir.join(format!("{sub}_{name}.o"));
    let elf = dir.join(format!("{sub}_{name}.elf"));
    let st = Command::new(&cc)
        .args([
            &format!("--target={target}"),
            &format!("-march={march}"),
            &format!("-mabi={abi}"),
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
            "-m",
            emul,
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

/// rmフィールドから実効丸めモードを求める。DYN(7)はfrm CSRで解決する。
fn resolve_rm(env: &mut BareEnv, rm_bits: u8) -> u8 {
    if rm_bits != 7 {
        return rm_bits;
    }
    let fcsr: u64 = env.backend.get(StateRef::<W64>::from_offset(
        core::mem::offset_of!(CpuState, csr) + 3 * 8,
    ));
    ((fcsr >> 5) & 7) as u8
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

fn run(env: &mut BareEnv, entry: u64, rv32: bool) -> Outcome {
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
        // RV32 では MXLEN=32 の mepc に合わせ、下位 32 ビットに包む。
        if word == 0x3020_0073 {
            let mepc: u64 = env.backend.get(StateRef::<W64>::from_offset(
                core::mem::offset_of!(CpuState, csr) + 0x341 * 8,
            ));
            env.pc = if rv32 { mepc & 0xffff_ffff } else { mepc };
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
        let fd = Fpr(r(5, 7));
        let fs1 = Fpr(r(5, 15));
        let fs2 = Fpr(r(5, 20));
        let fs3 = Fpr(r(5, 27));
        let csr = Csr(((word >> 20) & 0xfff) as u16);
        let ok = match insn {
            Insn::Add => {
                if rv32 {
                    env.step(|b| sem::add_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::add(b, rd, rs1, rs2))
                }
            }
            Insn::Addi => {
                if rv32 {
                    env.step(|b| sem::addi_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::addi(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Addiw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::addiw(b, rd, rs1, imm_i(word)))
            }
            Insn::Lui => {
                if rv32 {
                    env.step(|b| sem::lui_rv32(b, rd, imm_u(word)))
                } else {
                    env.step(|b| sem::lui(b, rd, imm_u(word)))
                }
            }
            Insn::Auipc => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::auipc_rv32(b, rd, pc, imm_u(word)))
                } else {
                    env.step(|b| sem::auipc(b, rd, pc, imm_u(word)))
                }
            }
            Insn::Jal => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::jal_rv32(b, rd, pc, off_j(word)))
                } else {
                    env.step(|b| sem::jal(b, rd, pc, off_j(word)))
                }
            }
            Insn::Jalr => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::jalr_rv32(b, rd, rs1, pc, imm_i(word)))
                } else {
                    env.step(|b| sem::jalr(b, rd, rs1, pc, imm_i(word)))
                }
            }
            Insn::Beq => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::beq_rv32(b, rs1, rs2, pc, off_b(word)))
                } else {
                    env.step(|b| sem::beq(b, rs1, rs2, pc, off_b(word)))
                }
            }
            Insn::Bne => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::bne_rv32(b, rs1, rs2, pc, off_b(word)))
                } else {
                    env.step(|b| sem::bne(b, rs1, rs2, pc, off_b(word)))
                }
            }
            Insn::Blt => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::blt_rv32(b, rs1, rs2, pc, off_b(word)))
                } else {
                    env.step(|b| sem::blt(b, rs1, rs2, pc, off_b(word)))
                }
            }
            Insn::Bge => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::bge_rv32(b, rs1, rs2, pc, off_b(word)))
                } else {
                    env.step(|b| sem::bge(b, rs1, rs2, pc, off_b(word)))
                }
            }
            Insn::Bltu => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::bltu_rv32(b, rs1, rs2, pc, off_b(word)))
                } else {
                    env.step(|b| sem::bltu(b, rs1, rs2, pc, off_b(word)))
                }
            }
            Insn::Bgeu => {
                let pc = env.pc;
                if rv32 {
                    env.step(|b| sem::bgeu_rv32(b, rs1, rs2, pc, off_b(word)))
                } else {
                    env.step(|b| sem::bgeu(b, rs1, rs2, pc, off_b(word)))
                }
            }
            Insn::Lb => {
                if rv32 {
                    env.step(|b| sem::lb_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::lb(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Lh => {
                if rv32 {
                    env.step(|b| sem::lh_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::lh(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Lw => {
                if rv32 {
                    env.step(|b| sem::lw_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::lw(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Ld => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::ld(b, rd, rs1, imm_i(word)))
            }
            Insn::Lbu => {
                if rv32 {
                    env.step(|b| sem::lbu_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::lbu(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Lhu => {
                if rv32 {
                    env.step(|b| sem::lhu_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::lhu(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Lwu => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::lwu(b, rd, rs1, imm_i(word)))
            }
            Insn::Sb => {
                if rv32 {
                    env.step(|b| sem::sb_rv32(b, rs1, rs2, imm_s(word)))
                } else {
                    env.step(|b| sem::sb(b, rs1, rs2, imm_s(word)))
                }
            }
            Insn::Sh => {
                if rv32 {
                    env.step(|b| sem::sh_rv32(b, rs1, rs2, imm_s(word)))
                } else {
                    env.step(|b| sem::sh(b, rs1, rs2, imm_s(word)))
                }
            }
            Insn::Sw => {
                if rv32 {
                    env.step(|b| sem::sw_rv32(b, rs1, rs2, imm_s(word)))
                } else {
                    env.step(|b| sem::sw(b, rs1, rs2, imm_s(word)))
                }
            }
            Insn::Sd => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::sd(b, rs1, rs2, imm_s(word)))
            }
            Insn::Slli => {
                if rv32 {
                    env.step(|b| sem::slli_rv32(b, rd, rs1, ((word >> 20) & 63) as u64))
                } else {
                    env.step(|b| sem::slli(b, rd, rs1, ((word >> 20) & 63) as u64))
                }
            }
            Insn::Srli => {
                if rv32 {
                    env.step(|b| sem::srli_rv32(b, rd, rs1, ((word >> 20) & 63) as u64))
                } else {
                    env.step(|b| sem::srli(b, rd, rs1, ((word >> 20) & 63) as u64))
                }
            }
            Insn::Srai => {
                if rv32 {
                    env.step(|b| sem::srai_rv32(b, rd, rs1, ((word >> 20) & 63) as u64))
                } else {
                    env.step(|b| sem::srai(b, rd, rs1, ((word >> 20) & 63) as u64))
                }
            }
            Insn::Sub => {
                if rv32 {
                    env.step(|b| sem::sub_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::sub(b, rd, rs1, rs2))
                }
            }
            Insn::Sll => {
                if rv32 {
                    env.step(|b| sem::sll_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::sll(b, rd, rs1, rs2))
                }
            }
            Insn::Slt => {
                if rv32 {
                    env.step(|b| sem::slt_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::slt(b, rd, rs1, rs2))
                }
            }
            Insn::Sltu => {
                if rv32 {
                    env.step(|b| sem::sltu_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::sltu(b, rd, rs1, rs2))
                }
            }
            Insn::Xor => {
                if rv32 {
                    env.step(|b| sem::xor_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::xor(b, rd, rs1, rs2))
                }
            }
            Insn::Or => {
                if rv32 {
                    env.step(|b| sem::or_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::or(b, rd, rs1, rs2))
                }
            }
            Insn::And => {
                if rv32 {
                    env.step(|b| sem::and_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::and(b, rd, rs1, rs2))
                }
            }
            Insn::Sra => {
                if rv32 {
                    env.step(|b| sem::sra_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::sra(b, rd, rs1, rs2))
                }
            }
            Insn::Srl => {
                if rv32 {
                    env.step(|b| sem::srl_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::srl(b, rd, rs1, rs2))
                }
            }
            Insn::Slti => {
                if rv32 {
                    env.step(|b| sem::slti_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::slti(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Sltiu => {
                if rv32 {
                    env.step(|b| sem::sltiu_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::sltiu(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Mul => {
                if rv32 {
                    env.step(|b| sem::mul_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::mul(b, rd, rs1, rs2))
                }
            }
            Insn::Mulh => {
                if rv32 {
                    env.step(|b| sem::mulh_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::mulh(b, rd, rs1, rs2))
                }
            }
            Insn::Mulhsu => {
                if rv32 {
                    env.step(|b| sem::mulhsu_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::mulhsu(b, rd, rs1, rs2))
                }
            }
            Insn::Mulhu => {
                if rv32 {
                    env.step(|b| sem::mulhu_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::mulhu(b, rd, rs1, rs2))
                }
            }
            Insn::Div => {
                if rv32 {
                    env.step(|b| sem::div_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::div(b, rd, rs1, rs2))
                }
            }
            Insn::Divu => {
                if rv32 {
                    env.step(|b| sem::divu_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::divu(b, rd, rs1, rs2))
                }
            }
            Insn::Rem => {
                if rv32 {
                    env.step(|b| sem::rem_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::rem(b, rd, rs1, rs2))
                }
            }
            Insn::Remu => {
                if rv32 {
                    env.step(|b| sem::remu_rv32(b, rd, rs1, rs2))
                } else {
                    env.step(|b| sem::remu(b, rd, rs1, rs2))
                }
            }
            Insn::Mulw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::mulw(b, rd, rs1, rs2))
            }
            Insn::Divw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::divw(b, rd, rs1, rs2))
            }
            Insn::Divuw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::divuw(b, rd, rs1, rs2))
            }
            Insn::Remw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::remw(b, rd, rs1, rs2))
            }
            Insn::Remuw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::remuw(b, rd, rs1, rs2))
            }
            Insn::Xori => {
                if rv32 {
                    env.step(|b| sem::xori_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::xori(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Ori => {
                if rv32 {
                    env.step(|b| sem::ori_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::ori(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Andi => {
                if rv32 {
                    env.step(|b| sem::andi_rv32(b, rd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::andi(b, rd, rs1, imm_i(word)))
                }
            }
            Insn::Csrrw => {
                let pc = env.pc;
                env.step(|b| sem::csrrw(b, rd, rs1, csr, pc))
            }
            Insn::Csrrs => {
                let pc = env.pc;
                env.step(|b| sem::csrrs(b, rd, rs1, csr, pc))
            }
            Insn::Csrrc => {
                let pc = env.pc;
                env.step(|b| sem::csrrc(b, rd, rs1, csr, pc))
            }
            Insn::Csrrwi => {
                let pc = env.pc;
                env.step(|b| sem::csrrwi(b, rd, ((word >> 15) & 31) as u64, csr, pc))
            }
            Insn::Csrrsi => {
                let pc = env.pc;
                env.step(|b| sem::csrrsi(b, rd, ((word >> 15) & 31) as u64, csr, pc))
            }
            Insn::Csrrci => {
                let pc = env.pc;
                env.step(|b| sem::csrrci(b, rd, ((word >> 15) & 31) as u64, csr, pc))
            }
            Insn::Fence => env.step(sem::fence),
            Insn::FenceI => env.step(sem::fence_i),
            // F 単精度。
            Insn::Flw => env.step(|b| sem::flw(b, fd, rs1, imm_i(word))),
            Insn::Fsw => env.step(|b| sem::fsw(b, rs1, fs2, imm_s(word))),
            Insn::FaddS => env.step(|b| sem::fadd_s(b, fd, fs1, fs2)),
            Insn::FsubS => env.step(|b| sem::fsub_s(b, fd, fs1, fs2)),
            Insn::FmulS => env.step(|b| sem::fmul_s(b, fd, fs1, fs2)),
            Insn::FdivS => env.step(|b| sem::fdiv_s(b, fd, fs1, fs2)),
            Insn::FsqrtS => env.step(|b| sem::fsqrt_s(b, fd, fs1)),
            Insn::FsgnjS => env.step(|b| sem::fsgnj_s(b, fd, fs1, fs2)),
            Insn::FsgnjnS => env.step(|b| sem::fsgnjn_s(b, fd, fs1, fs2)),
            Insn::FsgnjxS => env.step(|b| sem::fsgnjx_s(b, fd, fs1, fs2)),
            Insn::FminS => env.step(|b| sem::fmin_s(b, fd, fs1, fs2)),
            Insn::FmaxS => env.step(|b| sem::fmax_s(b, fd, fs1, fs2)),
            Insn::FeqS => env.step(|b| sem::feq_s(b, rd, fs1, fs2)),
            Insn::FltS => env.step(|b| sem::flt_s(b, rd, fs1, fs2)),
            Insn::FleS => env.step(|b| sem::fle_s(b, rd, fs1, fs2)),
            Insn::FclassS => env.step(|b| sem::fclass_s(b, rd, fs1)),
            Insn::FcvtWS => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_w_s(b, rd, fs1, rm))
            }
            Insn::FcvtWuS => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_wu_s(b, rd, fs1, rm))
            }
            Insn::FcvtLS => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_l_s(b, rd, fs1, rm))
            }
            Insn::FcvtLuS => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_lu_s(b, rd, fs1, rm))
            }
            Insn::FmvXW => env.step(|b| sem::fmv_x_w(b, rd, fs1)),
            Insn::FcvtSW => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_s_w(b, fd, rs1, rm))
            }
            Insn::FcvtSWu => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_s_wu(b, fd, rs1, rm))
            }
            Insn::FcvtSL => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_s_l(b, fd, rs1, rm))
            }
            Insn::FcvtSLu => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_s_lu(b, fd, rs1, rm))
            }
            Insn::FmvWX => env.step(|b| sem::fmv_w_x(b, fd, rs1)),
            Insn::FmaddS => env.step(|b| sem::fmadd_s(b, fd, fs1, fs2, fs3)),
            Insn::FmsubS => env.step(|b| sem::fmsub_s(b, fd, fs1, fs2, fs3)),
            Insn::FnmsubS => env.step(|b| sem::fnmsub_s(b, fd, fs1, fs2, fs3)),
            Insn::FnmaddS => env.step(|b| sem::fnmadd_s(b, fd, fs1, fs2, fs3)),
            // D 倍精度。
            Insn::Fld => env.step(|b| sem::fld(b, fd, rs1, imm_i(word))),
            Insn::Fsd => env.step(|b| sem::fsd(b, rs1, fs2, imm_s(word))),
            Insn::FaddD => env.step(|b| sem::fadd_d(b, fd, fs1, fs2)),
            Insn::FsubD => env.step(|b| sem::fsub_d(b, fd, fs1, fs2)),
            Insn::FmulD => env.step(|b| sem::fmul_d(b, fd, fs1, fs2)),
            Insn::FdivD => env.step(|b| sem::fdiv_d(b, fd, fs1, fs2)),
            Insn::FsqrtD => env.step(|b| sem::fsqrt_d(b, fd, fs1)),
            Insn::FsgnjD => env.step(|b| sem::fsgnj_d(b, fd, fs1, fs2)),
            Insn::FsgnjnD => env.step(|b| sem::fsgnjn_d(b, fd, fs1, fs2)),
            Insn::FsgnjxD => env.step(|b| sem::fsgnjx_d(b, fd, fs1, fs2)),
            Insn::FminD => env.step(|b| sem::fmin_d(b, fd, fs1, fs2)),
            Insn::FmaxD => env.step(|b| sem::fmax_d(b, fd, fs1, fs2)),
            Insn::FeqD => env.step(|b| sem::feq_d(b, rd, fs1, fs2)),
            Insn::FltD => env.step(|b| sem::flt_d(b, rd, fs1, fs2)),
            Insn::FleD => env.step(|b| sem::fle_d(b, rd, fs1, fs2)),
            Insn::FclassD => env.step(|b| sem::fclass_d(b, rd, fs1)),
            Insn::FcvtWD => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_w_d(b, rd, fs1, rm))
            }
            Insn::FcvtWuD => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_wu_d(b, rd, fs1, rm))
            }
            Insn::FcvtLD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_l_d(b, rd, fs1, rm))
            }
            Insn::FcvtLuD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_lu_d(b, rd, fs1, rm))
            }
            Insn::FmvXD => env.step(|b| sem::fmv_x_d(b, rd, fs1)),
            Insn::FcvtDW => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_d_w(b, fd, rs1, rm))
            }
            Insn::FcvtDWu => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_d_wu(b, fd, rs1, rm))
            }
            Insn::FcvtDL => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_d_l(b, fd, rs1, rm))
            }
            Insn::FcvtDLu => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_d_lu(b, fd, rs1, rm))
            }
            Insn::FmvDX => env.step(|b| sem::fmv_d_x(b, fd, rs1)),
            Insn::FcvtSD => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_s_d(b, fd, fs1, rm))
            }
            Insn::FcvtDS => {
                let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
                env.step(|b| sem::fcvt_d_s(b, fd, fs1, rm))
            }
            Insn::FmaddD => env.step(|b| sem::fmadd_d(b, fd, fs1, fs2, fs3)),
            Insn::FmsubD => env.step(|b| sem::fmsub_d(b, fd, fs1, fs2, fs3)),
            Insn::FnmsubD => env.step(|b| sem::fnmsub_d(b, fd, fs1, fs2, fs3)),
            Insn::FnmaddD => env.step(|b| sem::fnmadd_d(b, fd, fs1, fs2, fs3)),
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

fn check_one_in(sub: &str, name: &str) {
    let root = testdata();
    if !root.join(format!("isa/{sub}/{name}.S")).exists() {
        eprintln!("skip: .testdata/riscv-tests がないため未実行");
        return;
    }
    let rv32 = sub.starts_with("rv32");
    let Some(bytes) = build_elf_in(sub, name) else {
        eprintln!("skip: 組み立て器がないため未実行");
        return;
    };
    let (ehdr, phdrs) = if rv32 {
        let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).expect("ELFヘッダ");
        let phdrs = polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).expect("PHDR");
        (ehdr, phdrs)
    } else {
        let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).expect("ELFヘッダ");
        let phdrs = polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).expect("PHDR");
        (ehdr, phdrs)
    };
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    // riscv-tests のハーネスは M モードで動く。特権レベルを M (3) に置く。
    env.backend.set(
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, priv_level)),
        3,
    );
    polyisa_loader::elf::load_segments(&bytes, &phdrs, &mut env.backend.mem).expect("配置");
    match run(&mut env, ehdr.entry, rv32) {
        Outcome::Exit(code) => assert_eq!(code, 0, "{name} が失敗"),
        Outcome::Unimplemented { pc, word } => {
            panic!("{name}: 未実装に到達 pc={pc:#x} word={word:#x}")
        }
        Outcome::StepLimit { pc } => panic!("{name}: 予算切れ pc={pc:#x}"),
    }
}

fn check_one(name: &str) {
    check_one_in("rv64ui", name);
}

fn check_rv32i(name: &str) {
    check_one_in("rv32ui", name);
}

fn check_rv32m(name: &str) {
    check_one_in("rv32um", name);
}

fn check_um(name: &str) {
    check_one_in("rv64um", name);
}

fn check_uf(name: &str) {
    check_one_in("rv64uf", name);
}

fn check_ud(name: &str) {
    check_one_in("rv64ud", name);
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

#[test]
fn rv64ui_p_xor() {
    check_one("xor");
}

#[test]
fn rv64ui_p_slt() {
    check_one("slt");
}

#[test]
fn rv64ui_p_sltu() {
    check_one("sltu");
}

#[test]
fn rv64ui_p_srli() {
    check_one("srli");
}

#[test]
fn rv64ui_p_srai() {
    check_one("srai");
}

#[test]
fn rv64ui_p_bne() {
    check_one("bne");
}

#[test]
fn rv64ui_p_blt() {
    check_one("blt");
}

#[test]
fn rv64ui_p_lui() {
    check_one("lui");
}

#[test]
fn rv64ui_p_auipc() {
    check_one("auipc");
}

#[test]
fn rv64ui_p_lb() {
    check_one("lb");
}

#[test]
fn rv64ui_p_sh() {
    check_one("sh");
}

#[test]
fn rv64um_p_mul() {
    check_um("mul");
}

#[test]
fn rv64um_p_div() {
    check_um("div");
}

#[test]
fn rv64um_p_rem() {
    check_um("rem");
}

#[test]
fn rv64um_p_mulh() {
    check_um("mulh");
}

#[test]
fn rv64um_p_divu() {
    check_um("divu");
}

#[test]
fn rv64uf_p_fadd() {
    check_uf("fadd");
}

#[test]
fn rv64uf_p_fclass() {
    check_uf("fclass");
}

#[test]
fn rv64uf_p_fcmp() {
    check_uf("fcmp");
}

#[test]
fn rv64uf_p_fcvt() {
    check_uf("fcvt");
}

#[test]
fn rv64uf_p_fcvt_w() {
    check_uf("fcvt_w");
}

#[test]
fn rv64uf_p_fdiv() {
    check_uf("fdiv");
}

#[test]
fn rv64uf_p_fmadd() {
    check_uf("fmadd");
}

#[test]
fn rv64uf_p_fmin() {
    check_uf("fmin");
}

#[test]
fn rv64uf_p_ldst() {
    check_uf("ldst");
}

#[test]
fn rv64uf_p_move() {
    check_uf("move");
}

#[test]
fn rv64uf_p_recoding() {
    check_uf("recoding");
}

#[test]
fn rv64ud_p_fadd() {
    check_ud("fadd");
}

#[test]
fn rv64ud_p_fclass() {
    check_ud("fclass");
}

#[test]
fn rv64ud_p_fcmp() {
    check_ud("fcmp");
}

#[test]
fn rv64ud_p_fcvt() {
    check_ud("fcvt");
}

#[test]
fn rv64ud_p_fcvt_w() {
    check_ud("fcvt_w");
}

#[test]
fn rv64ud_p_fdiv() {
    check_ud("fdiv");
}

#[test]
fn rv64ud_p_fmadd() {
    check_ud("fmadd");
}

#[test]
fn rv64ud_p_fmin() {
    check_ud("fmin");
}

#[test]
fn rv64ud_p_ldst() {
    check_ud("ldst");
}

#[test]
fn rv64ud_p_move() {
    check_ud("move");
}

#[test]
fn rv64ud_p_recoding() {
    check_ud("recoding");
}

#[test]
fn rv64ud_p_structural() {
    check_ud("structural");
}

// rv32ui のうち fence_i（非実行セグメントへの自己書き換え）と
// ma_data（非整列アクセス）は対象外。rv64 の実行分と同範囲に限る。
#[test]
fn rv32ui_p_add() {
    check_rv32i("add");
}

#[test]
fn rv32ui_p_addi() {
    check_rv32i("addi");
}

#[test]
fn rv32ui_p_and() {
    check_rv32i("and");
}

#[test]
fn rv32ui_p_andi() {
    check_rv32i("andi");
}

#[test]
fn rv32ui_p_auipc() {
    check_rv32i("auipc");
}

#[test]
fn rv32ui_p_beq() {
    check_rv32i("beq");
}

#[test]
fn rv32ui_p_bge() {
    check_rv32i("bge");
}

#[test]
fn rv32ui_p_bgeu() {
    check_rv32i("bgeu");
}

#[test]
fn rv32ui_p_blt() {
    check_rv32i("blt");
}

#[test]
fn rv32ui_p_bltu() {
    check_rv32i("bltu");
}

#[test]
fn rv32ui_p_bne() {
    check_rv32i("bne");
}

#[test]
fn rv32ui_p_jal() {
    check_rv32i("jal");
}

#[test]
fn rv32ui_p_jalr() {
    check_rv32i("jalr");
}

#[test]
fn rv32ui_p_lb() {
    check_rv32i("lb");
}

#[test]
fn rv32ui_p_lbu() {
    check_rv32i("lbu");
}

#[test]
fn rv32ui_p_lh() {
    check_rv32i("lh");
}

#[test]
fn rv32ui_p_lhu() {
    check_rv32i("lhu");
}

#[test]
fn rv32ui_p_lui() {
    check_rv32i("lui");
}

#[test]
fn rv32ui_p_lw() {
    check_rv32i("lw");
}

#[test]
fn rv32ui_p_or() {
    check_rv32i("or");
}

#[test]
fn rv32ui_p_ori() {
    check_rv32i("ori");
}

#[test]
fn rv32ui_p_sb() {
    check_rv32i("sb");
}

#[test]
fn rv32ui_p_sh() {
    check_rv32i("sh");
}

#[test]
fn rv32ui_p_sll() {
    check_rv32i("sll");
}

#[test]
fn rv32ui_p_slli() {
    check_rv32i("slli");
}

#[test]
fn rv32ui_p_slt() {
    check_rv32i("slt");
}

#[test]
fn rv32ui_p_slti() {
    check_rv32i("slti");
}

#[test]
fn rv32ui_p_sltiu() {
    check_rv32i("sltiu");
}

#[test]
fn rv32ui_p_sltu() {
    check_rv32i("sltu");
}

#[test]
fn rv32ui_p_sra() {
    check_rv32i("sra");
}

#[test]
fn rv32ui_p_srai() {
    check_rv32i("srai");
}

#[test]
fn rv32ui_p_srl() {
    check_rv32i("srl");
}

#[test]
fn rv32ui_p_srli() {
    check_rv32i("srli");
}

#[test]
fn rv32ui_p_sub() {
    check_rv32i("sub");
}

#[test]
fn rv32ui_p_sw() {
    check_rv32i("sw");
}

#[test]
fn rv32ui_p_xor() {
    check_rv32i("xor");
}

#[test]
fn rv32ui_p_xori() {
    check_rv32i("xori");
}

#[test]
fn rv32ui_p_simple() {
    check_rv32i("simple");
}

#[test]
fn rv32ui_p_ld_st() {
    check_rv32i("ld_st");
}

#[test]
fn rv32ui_p_st_ld() {
    check_rv32i("st_ld");
}

#[test]
fn rv32um_p_mul() {
    check_rv32m("mul");
}

#[test]
fn rv32um_p_mulh() {
    check_rv32m("mulh");
}

#[test]
fn rv32um_p_mulhsu() {
    check_rv32m("mulhsu");
}

#[test]
fn rv32um_p_mulhu() {
    check_rv32m("mulhu");
}

#[test]
fn rv32um_p_div() {
    check_rv32m("div");
}

#[test]
fn rv32um_p_divu() {
    check_rv32m("divu");
}

#[test]
fn rv32um_p_rem() {
    check_rv32m("rem");
}

#[test]
fn rv32um_p_remu() {
    check_rv32m("remu");
}
