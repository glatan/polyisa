//! riscv-tests の RV64UI 実行（層5・conformance）。
//!
//! `.testdata/riscv-tests` の1件を clang＋rust-lld でビルドし、自前の
//! run loop（fetch/decode/dispatch）で実行して合否を見る。終了規約は
//! `ecall`（a7=93）の a0（0=成功）である（`env/p/riscv_test.h` の
//! RVTEST_PASS/FAIL）。
//!
//! 使う外部ツールは台帳 TOOL-LLVM（clang）と rust-lld
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
        // 16 ビット単位でフェッチする（C 拡張のため）。32 ビット命令は
        // 下位 2 ビットが 0b11 である。
        let mut h = [0u8; 2];
        if env
            .backend
            .mem
            .read(VirtAddr(env.pc), &mut h, acc_fetch())
            .is_err()
        {
            return Outcome::Unimplemented {
                pc: env.pc,
                word: 0xffff_ffff,
            };
        }
        let lo = u16::from_le_bytes(h);
        let (word, ilen) = if lo & 0b11 == 0b11 {
            let mut hh = [0u8; 2];
            if env
                .backend
                .mem
                .read(VirtAddr(env.pc + 2), &mut hh, acc_fetch())
                .is_err()
            {
                return Outcome::Unimplemented {
                    pc: env.pc,
                    word: u32::from(lo),
                };
            }
            ((u16::from_le_bytes(hh) as u32) << 16 | u32::from(lo), 4u64)
        } else {
            (u32::from(lo), 2u64)
        };
        // MRET（特権。user-mode相当のrunnerでは mepc へ戻す）。
        // RV32 では MXLEN=32 の mepc に合わせ、下位 32 ビットに包む。
        if word == 0x3020_0073 {
            let mepc: u64 = env.backend.get(StateRef::<W64>::from_offset(
                core::mem::offset_of!(CpuState, csr) + 0x341 * 8,
            ));
            env.pc = if rv32 { mepc & 0xffff_ffff } else { mepc };
            continue;
        }
        if ilen == 2 {
            // 16 ビット命令は C 拡張の実行器に渡す。RV32 と重なる符号化の
            // 振り分けもそちらで行う（デコーダ自体は RV64 優先のまま）。
            if let Some(o) = step_c(env, word as u16, rv32) {
                return o;
            }
            continue;
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
            // W 接尾辞（RV64 のみ）。RV32 では不正命令相当として拒否する。
            Insn::Addw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::addw(b, rd, rs1, rs2))
            }
            Insn::Subw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::subw(b, rd, rs1, rs2))
            }
            Insn::Sllw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::sllw(b, rd, rs1, rs2))
            }
            Insn::Srlw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::srlw(b, rd, rs1, rs2))
            }
            Insn::Sraw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::sraw(b, rd, rs1, rs2))
            }
            Insn::Slliw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::slliw(b, rd, rs1, ((word >> 20) & 31) as u64))
            }
            Insn::Srliw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::srliw(b, rd, rs1, ((word >> 20) & 31) as u64))
            }
            Insn::Sraiw => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::sraiw(b, rd, rs1, ((word >> 20) & 31) as u64))
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
            // A 原子命令。W 接尾辞は RV32 でも使い、アドレスは包む。
            // D 接尾辞は RV64 のみ。
            Insn::LrW => {
                if rv32 {
                    env.step(|b| sem::lr_w_rv32(b, rd, rs1, 0))
                } else {
                    env.step(|b| sem::lr_w(b, rd, rs1, 0))
                }
            }
            Insn::ScW => {
                if rv32 {
                    env.step(|b| sem::sc_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::sc_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmoswapW => {
                if rv32 {
                    env.step(|b| sem::amoswap_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amoswap_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmoaddW => {
                if rv32 {
                    env.step(|b| sem::amoadd_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amoadd_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmoxorW => {
                if rv32 {
                    env.step(|b| sem::amoxor_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amoxor_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmoandW => {
                if rv32 {
                    env.step(|b| sem::amoand_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amoand_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmoorW => {
                if rv32 {
                    env.step(|b| sem::amoor_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amoor_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmominW => {
                if rv32 {
                    env.step(|b| sem::amomin_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amomin_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmomaxW => {
                if rv32 {
                    env.step(|b| sem::amomax_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amomax_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmominuW => {
                if rv32 {
                    env.step(|b| sem::amominu_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amominu_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::AmomaxuW => {
                if rv32 {
                    env.step(|b| sem::amomaxu_w_rv32(b, rd, rs1, rs2, 0))
                } else {
                    env.step(|b| sem::amomaxu_w(b, rd, rs1, rs2, 0))
                }
            }
            Insn::LrD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::lr_d(b, rd, rs1, 0))
            }
            Insn::ScD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::sc_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmoswapD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amoswap_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmoaddD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amoadd_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmoxorD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amoxor_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmoandD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amoand_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmoorD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amoor_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmominD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amomin_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmomaxD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amomax_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmominuD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amominu_d(b, rd, rs1, rs2, 0))
            }
            Insn::AmomaxuD => {
                if rv32 {
                    return Outcome::Unimplemented { pc: env.pc, word };
                }
                env.step(|b| sem::amomaxu_d(b, rd, rs1, rs2, 0))
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
            Insn::Flw => {
                if rv32 {
                    env.step(|b| sem::flw_rv32(b, fd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::flw(b, fd, rs1, imm_i(word)))
                }
            }
            Insn::Fsw => {
                if rv32 {
                    env.step(|b| sem::fsw_rv32(b, rs1, fs2, imm_s(word)))
                } else {
                    env.step(|b| sem::fsw(b, rs1, fs2, imm_s(word)))
                }
            }
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
            Insn::Fld => {
                if rv32 {
                    env.step(|b| sem::fld_rv32(b, fd, rs1, imm_i(word)))
                } else {
                    env.step(|b| sem::fld(b, fd, rs1, imm_i(word)))
                }
            }
            Insn::Fsd => {
                if rv32 {
                    env.step(|b| sem::fsd_rv32(b, rs1, fs2, imm_s(word)))
                } else {
                    env.step(|b| sem::fsd(b, rs1, fs2, imm_s(word)))
                }
            }
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

/// 16ビット命令を1件実行する。継続するとき None、退出するとき Some を返す。
/// RV32/RV64 で符号化が重なる命令は、モデル対応デコード（`decode_model`、
/// ADR-0006）が `when` の述語で振り分ける。
/// Ref: SPEC-RISCV-UNPRIV (20250508) §C.
fn step_c(env: &mut BareEnv, w16: u16, rv32: bool) -> Option<Outcome> {
    let word = u32::from(w16);
    let Some(insn) = polyisa_guest_riscv::decode_model(u128::from(word), 16, !rv32) else {
        return Some(Outcome::Unimplemented { pc: env.pc, word });
    };
    let r = run_c(env, insn, word, rv32);
    match r {
        Ok(()) => {
            if env.backend.ctrl == polyisa_engine::interp::Ctrl::Fallthrough {
                env.pc += 2;
            }
            None
        }
        Err(o) => Some(o),
    }
}

/// 圧縮レジスタ番号（3ビット）。x8〜x15 を指す。
fn c_reg3(w: u16, lo: u32) -> u8 {
    (((w as u32) >> lo) & 7) as u8 + 8
}

/// 5ビットレジスタ番号。
fn creg5(w: u16) -> u8 {
    (((w as u32) >> 7) & 31) as u8
}

/// CR 形式の rs1/rd（[11:7]）。
fn crd5(w: u16) -> u8 {
    (((w as u32) >> 7) & 31) as u8
}

/// CR 形式の rs2（[6:2]）。
fn crs2(w: u16) -> u8 {
    (((w as u32) >> 2) & 31) as u8
}

fn crd3(w: u16) -> u8 {
    c_reg3(w, 2)
}

fn crs1(w: u16) -> u8 {
    c_reg3(w, 7)
}

/// C.ADDI4SPN の nzuimm[9:2]。llvm-mc の符号化と突合済み。
fn c_addi4spn_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 7) & 0xF) << 6) | (((w >> 11) & 3) << 4) | (((w >> 5) & 1) << 3) | (((w >> 6) & 1) << 2)
}

/// CL 形式のロード・ストア即値（c.lw/c.sw/c.flw/c.fsw 用）。
fn c_lw_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 12) & 1) << 5)
        | (((w >> 11) & 1) << 4)
        | (((w >> 10) & 1) << 3)
        | (((w >> 6) & 1) << 2)
        | (((w >> 5) & 1) << 6)
}

/// C.ADDI16SP の nzimm[9:4]（符号付き10ビット相当に復元する）。
fn c_addi16sp_imm(w: u16) -> i64 {
    let w = w as u32;
    let nz = (((w >> 12) & 1) << 9)
        | (((w >> 3) & 3) << 7)
        | (((w >> 5) & 1) << 6)
        | (((w >> 2) & 1) << 5)
        | (((w >> 6) & 1) << 4);
    if nz & 0x200 != 0 {
        nz as i64 - 1024
    } else {
        nz as i64
    }
}

/// C.LUI の nzimm[17:12]。6ビット符号付きで、sem側で12ビット左へ寄せる。
/// llvm-mc の符号化と突合済み（c.lui s0, 0xfffe1 → 0x7405）。
fn c_lui_imm(w: u16) -> i64 {
    let w = w as u32;
    let v = (((w >> 12) & 1) << 5) | ((w >> 2) & 0x1F);
    if v & 0x20 != 0 {
        v as i64 - 64
    } else {
        v as i64
    }
}

/// CI/CB 形式の 6 ビット即値・シフト量（符号付きに復元する）。
fn c_imm6(w: u16) -> i64 {
    let v = ((((w as u32) >> 12) & 1) << 5) | (((w as u32) >> 2) & 0x1F);
    if v & 0x20 != 0 {
        v as i64 - 64
    } else {
        v as i64
    }
}

/// CI 形式のシフト量（0 拡張）。
fn c_shamt6(w: u16) -> u64 {
    ((((w as u32) >> 12) & 1) << 5 | (((w as u32) >> 2) & 0x1F)) as u64
}

/// CJ 形式のジャンプオフセット（符号付き）。
fn c_j_imm(w: u16) -> i64 {
    let w = w as u32;
    let v = (((w >> 12) & 1) << 11)
        | (((w >> 11) & 1) << 4)
        | (((w >> 9) & 3) << 8)
        | (((w >> 8) & 1) << 10)
        | (((w >> 7) & 1) << 6)
        | (((w >> 6) & 1) << 7)
        | (((w >> 3) & 7) << 1)
        | (((w >> 2) & 1) << 5);
    if v & 0x800 != 0 {
        v as i64 - 4096
    } else {
        v as i64
    }
}

/// CB 形式の分岐オフセット（符号付き）。
/// ビット配置は wavedrom（c-cb-format-ls.edn）と llvm-mc で突合済み。
/// inst[12]=off[8]、inst[11:10]=off[4:3]、inst[6:2]=off[7:6|2:1|5]。
fn c_b_imm(w: u16) -> i64 {
    let w = w as u32;
    let v = (((w >> 12) & 1) << 8)
        | (((w >> 11) & 1) << 4)
        | (((w >> 10) & 1) << 3)
        | (((w >> 6) & 1) << 7)
        | (((w >> 5) & 1) << 6)
        | (((w >> 4) & 1) << 2)
        | (((w >> 3) & 1) << 1)
        | (((w >> 2) & 1) << 5);
    if v & 0x100 != 0 {
        v as i64 - 512
    } else {
        v as i64
    }
}

/// C.LWSP の uimm[7:2]。
fn c_lwsp_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 12) & 1) << 5)
        | (((w >> 6) & 1) << 4)
        | (((w >> 5) & 1) << 3)
        | (((w >> 4) & 1) << 2)
        | (((w >> 2) & 3) << 6)
}

/// C.SWSP の uimm[7:2]。
fn c_swsp_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 9) & 0xF) << 2) | (((w >> 7) & 3) << 6)
}

/// CL 形式の倍精度ロード・ストア即値（c.ld/c.sd 用）の uimm[7:3]。
/// llvm-mc 単ビットプローブで突合済み。
/// inst[12:10]=off[5:3]、inst[6:5]=off[7:6]。
fn c_ld_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 10) & 7) << 3) | (((w >> 5) & 3) << 6)
}

/// C.LDSP の uimm[8:3]。llvm-mc 単ビットプローブで突合済み。
/// inst[12]=off[5]、inst[6:5]=off[4:3]、inst[4:2]=off[8:6]。
/// inst[7] は rd の一部でありオフセットに含めない。
fn c_ldsp_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 5) & 1) << 3)
        | (((w >> 6) & 1) << 4)
        | (((w >> 12) & 1) << 5)
        | (((w >> 2) & 1) << 6)
        | (((w >> 3) & 1) << 7)
        | (((w >> 4) & 1) << 8)
}

/// C.SDSP の uimm[8:3]。llvm-mc 単ビットプローブで突合済み。
/// inst[12:10]=off[5:3]、inst[9:7]=off[8:6]。
fn c_sdsp_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 10) & 1) << 3)
        | (((w >> 11) & 1) << 4)
        | (((w >> 12) & 1) << 5)
        | (((w >> 7) & 1) << 6)
        | (((w >> 8) & 1) << 7)
        | (((w >> 9) & 1) << 8)
}

/// 16ビット命令を実行する。Ok は実行して継続、Err は退出する。
fn run_c(
    env: &mut BareEnv,
    insn: polyisa_guest_riscv::Insn,
    word: u32,
    rv32: bool,
) -> Result<(), Outcome> {
    use polyisa_guest_riscv::Insn;
    let w = word as u16;
    let r = |b: u32, lo: u32| ((word >> lo) & ((1u32 << b) - 1)) as u8;
    let ok = match insn {
        Insn::CAddi4spn => {
            let rd = Gpr(crd3(w));
            let uimm = c_addi4spn_uimm(w) as i64;
            env.step(|b| sem::c_addi4spn(b, rd, uimm))
        }
        Insn::CLw => {
            let rd = Gpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_lw_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_lw_rv32(b, rd, rs1, off))
            } else {
                env.step(|b| sem::c_lw(b, rd, rs1, off))
            }
        }
        Insn::CFlw => {
            let rd = Fpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_lw_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_flw_rv32(b, rd, rs1, off))
            } else {
                env.step(|b| sem::c_flw(b, rd, rs1, off))
            }
        }
        Insn::CSw => {
            let rs1 = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            let off = c_lw_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_sw_rv32(b, rs1, rs2, off))
            } else {
                env.step(|b| sem::c_sw(b, rs1, rs2, off))
            }
        }
        Insn::CFsw => {
            let rs1 = Gpr(crs1(w));
            let rs2 = Fpr(crd3(w));
            let off = c_lw_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_fsw_rv32(b, rs1, rs2, off))
            } else {
                env.step(|b| sem::c_fsw(b, rs1, rs2, off))
            }
        }
        Insn::CFld => {
            let rd = Fpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_ld_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_fld_rv32(b, rd, rs1, off))
            } else {
                env.step(|b| sem::c_fld(b, rd, rs1, off))
            }
        }
        Insn::CFsd => {
            let rs1 = Gpr(crs1(w));
            let rs2 = Fpr(crd3(w));
            let off = c_ld_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_fsd_rv32(b, rs1, rs2, off))
            } else {
                env.step(|b| sem::c_fsd(b, rs1, rs2, off))
            }
        }
        Insn::CFlwsp => {
            let rd = Fpr(creg5(w));
            let off = c_lwsp_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_flwsp_rv32(b, rd, off))
            } else {
                env.step(|b| sem::c_flwsp(b, rd, off))
            }
        }
        Insn::CFswsp => {
            // CSS 形式。rs2 は bits[6:2]（CI の rd とは位置が違う）。
            let rs2 = Fpr(crs2(w));
            let off = c_swsp_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_fswsp_rv32(b, rs2, off))
            } else {
                env.step(|b| sem::c_fswsp(b, rs2, off))
            }
        }
        Insn::CFldsp => {
            let rd = Fpr(creg5(w));
            let off = c_ldsp_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_fldsp_rv32(b, rd, off))
            } else {
                env.step(|b| sem::c_fldsp(b, rd, off))
            }
        }
        Insn::CFsdsp => {
            // CSS 形式。rs2 は bits[6:2]。
            let rs2 = Fpr(crs2(w));
            let off = c_sdsp_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_fsdsp_rv32(b, rs2, off))
            } else {
                env.step(|b| sem::c_fsdsp(b, rs2, off))
            }
        }
        Insn::CLd => {
            if rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            let rd = Gpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_ld_uimm(w) as i64;
            env.step(|b| sem::c_ld(b, rd, rs1, off))
        }
        Insn::CSd => {
            if rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            let rs1 = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            let off = c_ld_uimm(w) as i64;
            env.step(|b| sem::c_sd(b, rs1, rs2, off))
        }
        Insn::CAddi => {
            let rd = Gpr(r(5, 7));
            let imm = c_imm6(w);
            if rv32 {
                env.step(|b| sem::c_addi_rv32(b, rd, imm))
            } else {
                env.step(|b| sem::c_addi(b, rd, imm))
            }
        }
        Insn::CAddiw => {
            if rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            let rd = Gpr(r(5, 7));
            let imm = c_imm6(w);
            env.step(|b| sem::c_addiw(b, rd, imm))
        }
        Insn::CJal => {
            // RV32 のみ（RV64 では CAddiw に分配される）。
            if !rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            let pc = env.pc;
            let off = c_j_imm(w);
            env.step(|b| sem::c_jal(b, pc, off))
        }
        Insn::CLi => {
            let rd = Gpr(r(5, 7));
            let imm = c_imm6(w);
            if rv32 {
                env.step(|b| sem::c_li_rv32(b, rd, imm))
            } else {
                env.step(|b| sem::c_li(b, rd, imm))
            }
        }
        Insn::CLuiAddi16sp => {
            let rd = Gpr(r(5, 7));
            if rd.0 == 2 {
                let imm = c_addi16sp_imm(w);
                if rv32 {
                    env.step(|b| sem::c_lui_addi16sp_rv32(b, rd, imm))
                } else {
                    env.step(|b| sem::c_lui_addi16sp(b, rd, imm))
                }
            } else {
                let imm = c_lui_imm(w);
                if rv32 {
                    env.step(|b| sem::c_lui_rv32(b, rd, imm))
                } else {
                    env.step(|b| sem::c_lui_addi16sp(b, rd, imm))
                }
            }
        }
        Insn::CJ => {
            let pc = env.pc;
            let off = c_j_imm(w);
            if rv32 {
                env.step(|b| sem::c_j_rv32(b, pc, off))
            } else {
                env.step(|b| sem::c_j(b, pc, off))
            }
        }
        Insn::CBeqz => {
            let rs1 = Gpr(crs1(w));
            let pc = env.pc;
            let off = c_b_imm(w);
            if rv32 {
                env.step(|b| sem::c_beqz_rv32(b, rs1, pc, off))
            } else {
                env.step(|b| sem::c_beqz(b, rs1, pc, off))
            }
        }
        Insn::CBnez => {
            let rs1 = Gpr(crs1(w));
            let pc = env.pc;
            let off = c_b_imm(w);
            if rv32 {
                env.step(|b| sem::c_bnez_rv32(b, rs1, pc, off))
            } else {
                env.step(|b| sem::c_bnez(b, rs1, pc, off))
            }
        }
        Insn::CSlli => {
            let rd = Gpr(r(5, 7));
            let shamt = c_shamt6(w);
            if rv32 {
                env.step(|b| sem::c_slli_rv32(b, rd, shamt))
            } else {
                env.step(|b| sem::c_slli(b, rd, shamt))
            }
        }
        Insn::CLwsp => {
            let rd = Gpr(creg5(w));
            let off = c_lwsp_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_lwsp_rv32(b, rd, off))
            } else {
                env.step(|b| sem::c_lwsp(b, rd, off))
            }
        }
        Insn::CLdsp => {
            if rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            let rd = Gpr(creg5(w));
            let off = c_ldsp_uimm(w) as i64;
            env.step(|b| sem::c_ldsp(b, rd, off))
        }
        Insn::CSwsp => {
            // CSS 形式。rs2 は bits[6:2]。
            let rs2 = Gpr(crs2(w));
            let off = c_swsp_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_swsp_rv32(b, rs2, off))
            } else {
                env.step(|b| sem::c_swsp(b, rs2, off))
            }
        }
        Insn::CSdsp => {
            if rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            // CSS 形式。rs2 は bits[6:2]。
            let rs2 = Gpr(crs2(w));
            let off = c_sdsp_uimm(w) as i64;
            env.step(|b| sem::c_sdsp(b, rs2, off))
        }
        Insn::CSrli => {
            let rd = Gpr(crs1(w));
            let shamt = c_shamt6(w);
            if rv32 {
                env.step(|b| sem::c_srli_rv32(b, rd, shamt))
            } else {
                env.step(|b| sem::c_srli(b, rd, shamt))
            }
        }
        Insn::CSrai => {
            let rd = Gpr(crs1(w));
            let shamt = c_shamt6(w);
            if rv32 {
                env.step(|b| sem::c_srai_rv32(b, rd, shamt))
            } else {
                env.step(|b| sem::c_srai(b, rd, shamt))
            }
        }
        Insn::CAndi => {
            let rd = Gpr(crs1(w));
            let imm = c_imm6(w);
            if rv32 {
                env.step(|b| sem::c_andi_rv32(b, rd, imm))
            } else {
                env.step(|b| sem::c_andi(b, rd, imm))
            }
        }
        Insn::CSub => {
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            if rv32 {
                env.step(|b| sem::c_sub_rv32(b, rd, rs2))
            } else {
                env.step(|b| sem::c_sub(b, rd, rs2))
            }
        }
        Insn::CXor => {
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            if rv32 {
                env.step(|b| sem::c_xor_rv32(b, rd, rs2))
            } else {
                env.step(|b| sem::c_xor(b, rd, rs2))
            }
        }
        Insn::COr => {
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            if rv32 {
                env.step(|b| sem::c_or_rv32(b, rd, rs2))
            } else {
                env.step(|b| sem::c_or(b, rd, rs2))
            }
        }
        Insn::CAnd => {
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            if rv32 {
                env.step(|b| sem::c_and_rv32(b, rd, rs2))
            } else {
                env.step(|b| sem::c_and(b, rd, rs2))
            }
        }
        Insn::CSubw => {
            if rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            env.step(|b| sem::c_subw(b, rd, rs2))
        }
        Insn::CAddw => {
            if rv32 {
                return Err(Outcome::Unimplemented { pc: env.pc, word });
            }
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            env.step(|b| sem::c_addw(b, rd, rs2))
        }
        Insn::CJr => {
            let rs1 = Gpr(crd5(w));
            let pc = env.pc;
            if rv32 {
                env.step(|b| sem::c_jr_rv32(b, rs1, pc))
            } else {
                env.step(|b| sem::c_jr(b, rs1, pc))
            }
        }
        Insn::CMv => {
            let rd = Gpr(crd5(w));
            let rs2 = Gpr(crs2(w));
            if rv32 {
                env.step(|b| sem::c_mv_rv32(b, rd, rs2))
            } else {
                env.step(|b| sem::c_mv(b, rd, rs2))
            }
        }
        Insn::CJalr => {
            let rs1 = Gpr(crd5(w));
            let pc = env.pc;
            if rv32 {
                env.step(|b| sem::c_jalr_rv32(b, rs1, pc))
            } else {
                env.step(|b| sem::c_jalr(b, rs1, pc))
            }
        }
        Insn::CAdd => {
            let rd = Gpr(crd5(w));
            let rs2 = Gpr(crs2(w));
            if rv32 {
                env.step(|b| sem::c_add_rv32(b, rd, rs2))
            } else {
                env.step(|b| sem::c_add(b, rd, rs2))
            }
        }
        Insn::CEbreak => {
            let pc = env.pc;
            env.step(|b| sem::c_ebreak(b, pc))
        }
        _ => {
            return Err(Outcome::Unimplemented { pc: env.pc, word });
        }
    };
    if ok.is_err() {
        return Err(Outcome::Unimplemented { pc: env.pc, word });
    }
    Ok(())
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

fn check_rv32f(name: &str) {
    check_one_in("rv32uf", name);
}

fn check_rv32d(name: &str) {
    check_one_in("rv32ud", name);
}

fn check_rv32c(name: &str) {
    check_one_in("rv32uc", name);
}

fn check_rv32a(name: &str) {
    check_one_in("rv32ua", name);
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

fn check_uc(name: &str) {
    check_one_in("rv64uc", name);
}

fn check_ua(name: &str) {
    check_one_in("rv64ua", name);
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

#[test]
fn rv32uf_p_fadd() {
    check_rv32f("fadd");
}

#[test]
fn rv32uf_p_fclass() {
    check_rv32f("fclass");
}

#[test]
fn rv32uf_p_fcmp() {
    check_rv32f("fcmp");
}

#[test]
fn rv32uf_p_fcvt() {
    check_rv32f("fcvt");
}

#[test]
fn rv32uf_p_fcvt_w() {
    check_rv32f("fcvt_w");
}

#[test]
fn rv32uf_p_fdiv() {
    check_rv32f("fdiv");
}

#[test]
fn rv32uf_p_fmadd() {
    check_rv32f("fmadd");
}

#[test]
fn rv32uf_p_fmin() {
    check_rv32f("fmin");
}

#[test]
fn rv32uf_p_ldst() {
    check_rv32f("ldst");
}

#[test]
fn rv32uf_p_move() {
    check_rv32f("move");
}

#[test]
fn rv32uf_p_recoding() {
    check_rv32f("recoding");
}

#[test]
fn rv32uc_p_rvc() {
    check_rv32c("rvc");
}

#[test]
fn rv32ud_p_fadd() {
    check_rv32d("fadd");
}

#[test]
fn rv32ud_p_fclass() {
    check_rv32d("fclass");
}

#[test]
fn rv32ud_p_fcmp() {
    check_rv32d("fcmp");
}

#[test]
fn rv32ud_p_fcvt() {
    check_rv32d("fcvt");
}

#[test]
fn rv32ud_p_fcvt_w() {
    check_rv32d("fcvt_w");
}

#[test]
fn rv32ud_p_fdiv() {
    check_rv32d("fdiv");
}

#[test]
fn rv32ud_p_fmadd() {
    check_rv32d("fmadd");
}

#[test]
fn rv32ud_p_fmin() {
    check_rv32d("fmin");
}

#[test]
fn rv32ud_p_ldst() {
    check_rv32d("ldst");
}

#[test]
fn rv32ud_p_move() {
    check_rv32d("move");
}

#[test]
fn rv32ud_p_recoding() {
    check_rv32d("recoding");
}

#[test]
fn rv64uc_p_rvc() {
    check_uc("rvc");
}

#[test]
fn rv32ua_p_amoadd_w() {
    check_rv32a("amoadd_w");
}

#[test]
fn rv32ua_p_amoand_w() {
    check_rv32a("amoand_w");
}

#[test]
fn rv32ua_p_amomax_w() {
    check_rv32a("amomax_w");
}

#[test]
fn rv32ua_p_amomaxu_w() {
    check_rv32a("amomaxu_w");
}

#[test]
fn rv32ua_p_amomin_w() {
    check_rv32a("amomin_w");
}

#[test]
fn rv32ua_p_amominu_w() {
    check_rv32a("amominu_w");
}

#[test]
fn rv32ua_p_amoor_w() {
    check_rv32a("amoor_w");
}

#[test]
fn rv32ua_p_amoswap_w() {
    check_rv32a("amoswap_w");
}

#[test]
fn rv32ua_p_amoxor_w() {
    check_rv32a("amoxor_w");
}

#[test]
fn rv32ua_p_lrsc() {
    check_rv32a("lrsc");
}

#[test]
fn rv64ua_p_amoadd_w() {
    check_ua("amoadd_w");
}

#[test]
fn rv64ua_p_amoadd_d() {
    check_ua("amoadd_d");
}

#[test]
fn rv64ua_p_amoand_w() {
    check_ua("amoand_w");
}

#[test]
fn rv64ua_p_amoand_d() {
    check_ua("amoand_d");
}

#[test]
fn rv64ua_p_amomax_w() {
    check_ua("amomax_w");
}

#[test]
fn rv64ua_p_amomax_d() {
    check_ua("amomax_d");
}

#[test]
fn rv64ua_p_amomaxu_w() {
    check_ua("amomaxu_w");
}

#[test]
fn rv64ua_p_amomaxu_d() {
    check_ua("amomaxu_d");
}

#[test]
fn rv64ua_p_amomin_w() {
    check_ua("amomin_w");
}

#[test]
fn rv64ua_p_amomin_d() {
    check_ua("amomin_d");
}

#[test]
fn rv64ua_p_amominu_w() {
    check_ua("amominu_w");
}

#[test]
fn rv64ua_p_amominu_d() {
    check_ua("amominu_d");
}

#[test]
fn rv64ua_p_amoor_w() {
    check_ua("amoor_w");
}

#[test]
fn rv64ua_p_amoor_d() {
    check_ua("amoor_d");
}

#[test]
fn rv64ua_p_amoswap_w() {
    check_ua("amoswap_w");
}

#[test]
fn rv64ua_p_amoswap_d() {
    check_ua("amoswap_d");
}

#[test]
fn rv64ua_p_amoxor_w() {
    check_ua("amoxor_w");
}

#[test]
fn rv64ua_p_amoxor_d() {
    check_ua("amoxor_d");
}

#[test]
fn rv64ua_p_lrsc() {
    check_ua("lrsc");
}

// rv64ui 残件（W接尾辞・LD/SD・LWU・残りのI命令）。
// fence_i（非実行セグメントへの自己書き換え）と
// ma_data（非整列アクセス）は対象外（ロードマップ注記）。

#[test]
fn rv64ui_p_addiw() {
    check_one("addiw");
}

#[test]
fn rv64ui_p_addw() {
    check_one("addw");
}

#[test]
fn rv64ui_p_andi() {
    check_one("andi");
}

#[test]
fn rv64ui_p_bge() {
    check_one("bge");
}

#[test]
fn rv64ui_p_bgeu() {
    check_one("bgeu");
}

#[test]
fn rv64ui_p_bltu() {
    check_one("bltu");
}

#[test]
fn rv64ui_p_lbu() {
    check_one("lbu");
}

#[test]
fn rv64ui_p_ld() {
    check_one("ld");
}

#[test]
fn rv64ui_p_ld_st() {
    check_one("ld_st");
}

#[test]
fn rv64ui_p_lh() {
    check_one("lh");
}

#[test]
fn rv64ui_p_lhu() {
    check_one("lhu");
}

#[test]
fn rv64ui_p_lwu() {
    check_one("lwu");
}

#[test]
fn rv64ui_p_ori() {
    check_one("ori");
}

#[test]
fn rv64ui_p_sb() {
    check_one("sb");
}

#[test]
fn rv64ui_p_sd() {
    check_one("sd");
}

#[test]
fn rv64ui_p_simple() {
    check_one("simple");
}

#[test]
fn rv64ui_p_slli() {
    check_one("slli");
}

#[test]
fn rv64ui_p_slliw() {
    check_one("slliw");
}

#[test]
fn rv64ui_p_sllw() {
    check_one("sllw");
}

#[test]
fn rv64ui_p_slti() {
    check_one("slti");
}

#[test]
fn rv64ui_p_sltiu() {
    check_one("sltiu");
}

#[test]
fn rv64ui_p_srl() {
    check_one("srl");
}

#[test]
fn rv64ui_p_srliw() {
    check_one("srliw");
}

#[test]
fn rv64ui_p_srlw() {
    check_one("srlw");
}

#[test]
fn rv64ui_p_st_ld() {
    check_one("st_ld");
}

#[test]
fn rv64ui_p_subw() {
    check_one("subw");
}

#[test]
fn rv64ui_p_xori() {
    check_one("xori");
}

#[test]
fn rv64ui_p_sraiw() {
    check_one("sraiw");
}

#[test]
fn rv64ui_p_sraw() {
    check_one("sraw");
}

#[test]
fn rv64um_p_divuw() {
    check_um("divuw");
}

#[test]
fn rv64um_p_divw() {
    check_um("divw");
}

#[test]
fn rv64um_p_mulhsu() {
    check_um("mulhsu");
}

#[test]
fn rv64um_p_mulhu() {
    check_um("mulhu");
}

#[test]
fn rv64um_p_mulw() {
    check_um("mulw");
}

#[test]
fn rv64um_p_remuw() {
    check_um("remuw");
}

#[test]
fn rv64um_p_remw() {
    check_um("remw");
}

#[test]
fn rv64um_p_remu() {
    check_um("remu");
}
