// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! RV64/RV32 ユーザーモード実行の run loop。fetch/decode/dispatch を回す.
//!
//! riscv-tests の適合実行と `cli run` で共有する。OS 依存の ecall 処理は
//! 呼び出し側が `EcallHandler` で渡す。CPU 状態・メモリの用意（ELF 配置、
//! 権限レベル、初期スタック）は呼び出し側の仕事である.
//!
//! モデル（XLEN）の解決はデコード時に `decode_model` で行う（ADR-0006）。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_guest_riscv::sem::{Csr, Fpr, Gpr};
use polyisa_guest_riscv::{CpuState, DEFAULT_FEATS, Insn, decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, StateRef, W64};

/// 1命令の実行上限。無限ループの検出用。
pub const STEP_LIMIT: u64 = 5_000_000;

pub use polyisa_engine::run::Outcome;

/// ecall 命令の処理結果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EcallOutcome {
    /// ゲストを終了する（終了コード）。
    Exit(u64),
    /// 処理して継続する（pc は次へ進める）。
    Handled,
    /// 扱えない ecall である。
    Unimplemented,
}

/// ecall の処理器。OS パーソナリティやテストハーネスが実装する。
// Gap: GAP-0024
pub trait EcallHandler {
    fn handle_ecall(&mut self, env: &mut BareEnv, word: u32) -> EcallOutcome;
}

/// `os-linux` の `TrapHandler` をこの実行ループの `EcallHandler` に適合する。
/// Linux パーソナリティは `polyisa_os_linux::rv64::sys::Linux` にある。
impl EcallHandler for polyisa_os_linux::rv64::sys::Linux {
    fn handle_ecall(&mut self, env: &mut BareEnv, word: u32) -> EcallOutcome {
        match polyisa_os_linux::TrapHandler::handle_trap(self, env, word) {
            polyisa_os_linux::TrapOutcome::Handled => EcallOutcome::Handled,
            polyisa_os_linux::TrapOutcome::Exit(code) => EcallOutcome::Exit(u64::from(code)),
            _ => EcallOutcome::Unimplemented,
        }
    }
}

/// riscv の semihosting 処理器。ebreak の標識列は step 側が確認
/// 済みで、ここでは word が ebreak であることだけ見る。
/// `a0`(x10) が演算番号、`a1`(x11) がパラメータ、結果は `a0` へ。
// Gap: GAP-0024
#[cfg(feature = "guest-riscv")]
pub struct SemiRv {
    /// 演算機械。入出力の capture は `semi.io` に入る。
    pub semi: polyisa_os_semihost::Semi,
    rv32: bool,
}

#[cfg(feature = "guest-riscv")]
impl SemiRv {
    /// `Semi::new` に語幅を添えて作る。
    #[must_use]
    pub fn new(root: &str, rv32: bool) -> Self {
        Self {
            semi: polyisa_os_semihost::Semi::new(root),
            rv32,
        }
    }
}

#[cfg(feature = "guest-riscv")]
impl EcallHandler for SemiRv {
    fn handle_ecall(&mut self, env: &mut BareEnv, word: u32) -> EcallOutcome {
        const EBREAK: u32 = 0x0010_0073;
        if word != EBREAK {
            return EcallOutcome::Unimplemented;
        }
        let (op, param) = (reg(env, 10), reg(env, 11));
        let ws = if self.rv32 {
            polyisa_os_semihost::WordSize::W32
        } else {
            polyisa_os_semihost::WordSize::W64
        };
        match self.semi.call(env, op as u32, param, ws) {
            polyisa_os_semihost::Reply::Ret(v) => {
                env.backend.set(Gpr(10).state(), v as u64);
                EcallOutcome::Handled
            }
            polyisa_os_semihost::Reply::Exit(c) => EcallOutcome::Exit(c),
            polyisa_os_semihost::Reply::Unimpl => EcallOutcome::Unimplemented,
        }
    }
}

fn acc_fetch() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    }
}

/// 整数レジスタを読む（ハンドラ用の検査口）。
pub fn reg(env: &mut BareEnv, r: u8) -> u64 {
    env.backend.get(Gpr(r).state())
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

/// エントリから実行する。`rv32` は RV32 モデルを選ぶ。
/// ecall は `sys` に委ね、それ以外は意味論で実行する。機能集合は
/// 既定モデル（RV64GC 相当）を使う。厳密なモデル選択には `run_ex` を使う。
pub fn run(env: &mut BareEnv, entry: u64, rv32: bool, sys: &mut impl EcallHandler) -> Outcome {
    run_ex(env, entry, rv32, DEFAULT_FEATS, sys)
}

/// `run` に機能集合を渡す。`feats` は生成した `FEAT_*` のビット和で、
/// `decode_model_ex` に渡る（ADR-0006）。CPU モデルの選択からの変換は
/// `polyisa_isadl::select::resolve` が行う。
pub fn run_ex(
    env: &mut BareEnv,
    entry: u64,
    rv32: bool,
    feats: u128,
    sys: &mut impl EcallHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_rv(env, sys, rv32, feats),
    )
}

/// 1 命令ぶんのフェッチ・解読・意味論と ecall 境界の解決。
/// 継続なら `Ok(())`、退出なら退出理由を返す。
/// `gdb_riscv` の単歩・継続の実行単位としても使う。
#[allow(clippy::too_many_lines)]
pub(crate) fn step_rv(
    env: &mut BareEnv,
    sys: &mut impl EcallHandler,
    rv32: bool,
    feats: u128,
) -> Result<(), Outcome> {
    let r = step_rv_inner(env, sys, rv32, feats);
    if r.is_ok() {
        // カウンタ CSR の最小近似。instret は退役数そのもので、
        // cycle/time は命令ごとに進む単調な時計として扱う。
        for csr in (0xc00usize..=0xc02).chain(0xc03..=0xc1f) {
            let rref = StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, csr) + csr * 8);
            let v: u64 = env.backend.get(rref);
            env.backend.set(rref, v.wrapping_add(1));
        }
    }
    r
}

fn step_rv_inner(
    env: &mut BareEnv,
    sys: &mut impl EcallHandler,
    rv32: bool,
    feats: u128,
) -> Result<(), Outcome> {
    // 16 ビット単位でフェッチする（C 拡張のため）。32 ビット命令は
    // 下位 2 ビットが 0b11 である。
    let mut h = [0u8; 2];
    if env
        .backend
        .mem
        .read(VirtAddr(env.pc), &mut h, acc_fetch())
        .is_err()
    {
        return Err(Outcome::Unimplemented {
            pc: env.pc,
            word: 0xffff_ffff,
        });
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
            return Err(Outcome::Unimplemented {
                pc: env.pc,
                word: u128::from(lo),
            });
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
        return Ok(());
    }
    if ilen == 2 {
        // 16 ビット命令は C 拡張の実行器に渡す。RV32 と重なる符号化の
        // 振り分けもそちらで行う（デコーダ自体は RV64 優先のまま）。
        if let Some(o) = step_c(env, word as u16, rv32, feats) {
            return Err(o);
        }
        return Ok(());
    }
    let Some(insn) = decode_model_ex(word as u128, 32, !rv32, feats) else {
        return Err(Outcome::Unimplemented {
            pc: env.pc,
            word: u128::from(word),
        });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::addiw(b, rd, rs1, imm_i(word)))
        }
        Insn::CboInval | Insn::CboClean | Insn::CboFlush => env.step(|b| sem::cbo_mgmt(b, rs1)),
        Insn::CboZero => {
            if rv32 {
                env.step(|b| sem::cbo_zero_rv32(b, rs1))
            } else {
                env.step(|b| sem::cbo_zero(b, rs1))
            }
        }
        Insn::MopR0 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR1 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR2 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR3 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR4 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR5 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR6 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR7 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR8 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR9 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR10 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR11 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR12 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR13 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR14 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR15 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR16 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR17 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR18 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR19 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR20 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR21 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR22 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR23 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR24 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR25 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR26 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR27 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR28 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR29 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR30 => env.step(|b| sem::mop(b, rd)),
        Insn::MopR31 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr0 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr1 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr2 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr3 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr4 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr5 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr6 => env.step(|b| sem::mop(b, rd)),
        Insn::MopRr7 => env.step(|b| sem::mop(b, rd)),
        Insn::AddUw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::add_uw(b, rd, rs1, rs2))
        }
        Insn::Sh1add => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sh1add(b, rd, rs1, rs2))
        }
        Insn::Sh2add => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sh2add(b, rd, rs1, rs2))
        }
        Insn::Sh3add => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sh3add(b, rd, rs1, rs2))
        }
        Insn::Sh1addUw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sh1add_uw(b, rd, rs1, rs2))
        }
        Insn::Sh2addUw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sh2add_uw(b, rd, rs1, rs2))
        }
        Insn::Sh3addUw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sh3add_uw(b, rd, rs1, rs2))
        }
        Insn::Andn => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::andn(b, rd, rs1, rs2))
        }
        Insn::Orn => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::orn(b, rd, rs1, rs2))
        }
        Insn::Xnor => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::xnor(b, rd, rs1, rs2))
        }
        Insn::Max => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::max(b, rd, rs1, rs2))
        }
        Insn::Maxu => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::maxu(b, rd, rs1, rs2))
        }
        Insn::Min => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::min(b, rd, rs1, rs2))
        }
        Insn::Minu => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::minu(b, rd, rs1, rs2))
        }
        Insn::Rol => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::rol(b, rd, rs1, rs2))
        }
        Insn::Rolw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::rolw(b, rd, rs1, rs2))
        }
        Insn::Ror => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::ror(b, rd, rs1, rs2))
        }
        Insn::Rorw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::rorw(b, rd, rs1, rs2))
        }
        Insn::Clmul => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::clmul(b, rd, rs1, rs2))
        }
        Insn::Clmulh => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::clmulh(b, rd, rs1, rs2))
        }
        Insn::Clmulr => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::clmulr(b, rd, rs1, rs2))
        }
        Insn::Bclr => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::bclr(b, rd, rs1, rs2))
        }
        Insn::Bext => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::bext(b, rd, rs1, rs2))
        }
        Insn::Binv => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::binv(b, rd, rs1, rs2))
        }
        Insn::Bset => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::bset(b, rd, rs1, rs2))
        }
        Insn::SlliUw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::slli_uw(b, rd, rs1, imm_i(word) as u64))
        }
        Insn::Rori => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::rori(b, rd, rs1, imm_i(word) as u64))
        }
        Insn::Roriw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::roriw(b, rd, rs1, imm_i(word) as u64))
        }
        Insn::Bclri => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::bclri(b, rd, rs1, imm_i(word) as u64))
        }
        Insn::Bexti => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::bexti(b, rd, rs1, imm_i(word) as u64))
        }
        Insn::Binvi => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::binvi(b, rd, rs1, imm_i(word) as u64))
        }
        Insn::Bseti => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::bseti(b, rd, rs1, imm_i(word) as u64))
        }
        Insn::Clz => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::clz(b, rd, rs1))
        }
        Insn::Clzw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::clzw(b, rd, rs1))
        }
        Insn::Ctz => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::ctz(b, rd, rs1))
        }
        Insn::Ctzw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::ctzw(b, rd, rs1))
        }
        Insn::Cpop => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::cpop(b, rd, rs1))
        }
        Insn::Cpopw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::cpopw(b, rd, rs1))
        }
        Insn::OrcB => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::orc_b(b, rd, rs1))
        }
        Insn::Rev8 => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::rev8(b, rd, rs1))
        }
        Insn::SextB => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sext_b(b, rd, rs1))
        }
        Insn::SextH => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sext_h(b, rd, rs1))
        }
        Insn::ZextH => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::zext_h(b, rd, rs1))
        }
        Insn::CzeroEqz => env.step(|b| sem::czero_eqz(b, rd, rs1, rs2)),
        Insn::CzeroNez => env.step(|b| sem::czero_nez(b, rd, rs1, rs2)),
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
        Insn::Beqi => {
            let pc = env.pc;
            let cimm = rs2.0;
            if rv32 {
                env.step(|b| sem::beqi_rv32(b, rs1, cimm, pc, off_b(word)))
            } else {
                env.step(|b| sem::beqi(b, rs1, cimm, pc, off_b(word)))
            }
        }
        Insn::Bnei => {
            let pc = env.pc;
            let cimm = rs2.0;
            if rv32 {
                env.step(|b| sem::bnei_rv32(b, rs1, cimm, pc, off_b(word)))
            } else {
                env.step(|b| sem::bnei(b, rs1, cimm, pc, off_b(word)))
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::addw(b, rd, rs1, rs2))
        }
        Insn::Subw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::subw(b, rd, rs1, rs2))
        }
        Insn::Sllw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sllw(b, rd, rs1, rs2))
        }
        Insn::Srlw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::srlw(b, rd, rs1, rs2))
        }
        Insn::Sraw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sraw(b, rd, rs1, rs2))
        }
        Insn::Slliw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::slliw(b, rd, rs1, ((word >> 20) & 31) as u64))
        }
        Insn::Srliw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::srliw(b, rd, rs1, ((word >> 20) & 31) as u64))
        }
        Insn::Sraiw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::mulw(b, rd, rs1, rs2))
        }
        Insn::Divw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::divw(b, rd, rs1, rs2))
        }
        Insn::Divuw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::divuw(b, rd, rs1, rs2))
        }
        Insn::Remw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::remw(b, rd, rs1, rs2))
        }
        Insn::Remuw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
        Insn::AmocasB => {
            if rv32 {
                env.step(|b| sem::amocas_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amocas_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmocasH => {
            if rv32 {
                env.step(|b| sem::amocas_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amocas_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmocasW => {
            if rv32 {
                env.step(|b| sem::amocas_w_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amocas_w(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmocasD => {
            if rv32 {
                env.step(|b| sem::amocas_d_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amocas_d(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmocasQ => env.step(|b| sem::amocas_q(b, rd, rs1, rs2, 0)),
        Insn::AmoswapB => {
            if rv32 {
                env.step(|b| sem::amoswap_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoswap_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoswapH => {
            if rv32 {
                env.step(|b| sem::amoswap_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoswap_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoaddB => {
            if rv32 {
                env.step(|b| sem::amoadd_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoadd_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoaddH => {
            if rv32 {
                env.step(|b| sem::amoadd_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoadd_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoxorB => {
            if rv32 {
                env.step(|b| sem::amoxor_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoxor_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoxorH => {
            if rv32 {
                env.step(|b| sem::amoxor_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoxor_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoandB => {
            if rv32 {
                env.step(|b| sem::amoand_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoand_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoandH => {
            if rv32 {
                env.step(|b| sem::amoand_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoand_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoorB => {
            if rv32 {
                env.step(|b| sem::amoor_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoor_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmoorH => {
            if rv32 {
                env.step(|b| sem::amoor_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amoor_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmominB => {
            if rv32 {
                env.step(|b| sem::amomin_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amomin_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmominH => {
            if rv32 {
                env.step(|b| sem::amomin_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amomin_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmomaxB => {
            if rv32 {
                env.step(|b| sem::amomax_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amomax_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmomaxH => {
            if rv32 {
                env.step(|b| sem::amomax_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amomax_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmominuB => {
            if rv32 {
                env.step(|b| sem::amominu_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amominu_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmominuH => {
            if rv32 {
                env.step(|b| sem::amominu_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amominu_h(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmomaxuB => {
            if rv32 {
                env.step(|b| sem::amomaxu_b_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amomaxu_b(b, rd, rs1, rs2, 0))
            }
        }
        Insn::AmomaxuH => {
            if rv32 {
                env.step(|b| sem::amomaxu_h_rv32(b, rd, rs1, rs2, 0))
            } else {
                env.step(|b| sem::amomaxu_h(b, rd, rs1, rs2, 0))
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::lr_d(b, rd, rs1, 0))
        }
        Insn::ScD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::sc_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmoswapD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amoswap_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmoaddD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amoadd_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmoxorD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amoxor_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmoandD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amoand_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmoorD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amoor_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmominD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amomin_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmomaxD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amomax_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmominuD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            env.step(|b| sem::amominu_d(b, rd, rs1, rs2, 0))
        }
        Insn::AmomaxuD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
        Insn::FaddS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fadd_s(b, fd, fs1, fs2, rm))
        }
        Insn::FsubS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fsub_s(b, fd, fs1, fs2, rm))
        }
        Insn::FmulS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fmul_s(b, fd, fs1, fs2, rm))
        }
        Insn::FdivS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fdiv_s(b, fd, fs1, fs2, rm))
        }
        Insn::FsqrtS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fsqrt_s(b, fd, fs1, rm))
        }
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fcvt_l_s(b, rd, fs1, rm))
        }
        Insn::FcvtLuS => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fcvt_s_l(b, fd, rs1, rm))
        }
        Insn::FcvtSLu => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fcvt_s_lu(b, fd, rs1, rm))
        }
        Insn::FmvWX => env.step(|b| sem::fmv_w_x(b, fd, rs1)),
        Insn::FmaddS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fmadd_s(b, fd, fs1, fs2, fs3, rm))
        }
        Insn::FmsubS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fmsub_s(b, fd, fs1, fs2, fs3, rm))
        }
        Insn::FnmsubS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fnmsub_s(b, fd, fs1, fs2, fs3, rm))
        }
        Insn::FnmaddS => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fnmadd_s(b, fd, fs1, fs2, fs3, rm))
        }
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
        Insn::FaddD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fadd_d(b, fd, fs1, fs2, rm))
        }
        Insn::FsubD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fsub_d(b, fd, fs1, fs2, rm))
        }
        Insn::FmulD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fmul_d(b, fd, fs1, fs2, rm))
        }
        Insn::FdivD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fdiv_d(b, fd, fs1, fs2, rm))
        }
        Insn::FsqrtD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fsqrt_d(b, fd, fs1, rm))
        }
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fcvt_l_d(b, rd, fs1, rm))
        }
        Insn::FcvtLuD => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fcvt_d_l(b, fd, rs1, rm))
        }
        Insn::FcvtDLu => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
        Insn::FmaddD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fmadd_d(b, fd, fs1, fs2, fs3, rm))
        }
        Insn::FmsubD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fmsub_d(b, fd, fs1, fs2, fs3, rm))
        }
        Insn::FnmsubD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fnmsub_d(b, fd, fs1, fs2, fs3, rm))
        }
        Insn::FnmaddD => {
            let rm = resolve_rm(env, ((word >> 12) & 7) as u8);
            env.step(|b| sem::fnmadd_d(b, fd, fs1, fs2, fs3, rm))
        }
        Insn::Ecall => match sys.handle_ecall(env, word) {
            EcallOutcome::Exit(code) => return Err(Outcome::Exit(code)),
            EcallOutcome::Handled => {
                env.pc += 4;
                return Ok(());
            }
            EcallOutcome::Unimplemented => {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
        },
        Insn::Ebreak => {
            // semihosting の標識列は ebreak の前後:
            // `slli x0,x0,0x1f; ebreak; srai x0,x0,7`。
            // 一致したときだけパーソナリティへ渡す。
            const SLLI_MARK: u32 = 0x01f0_1013;
            const SRAI_MARK: u32 = 0x4070_5013;
            let fetch = |va: u64| -> u32 {
                let mut b = [0u8; 4];
                env.backend
                    .mem
                    .read(VirtAddr(va), &mut b, acc_fetch())
                    .map(|()| u32::from_le_bytes(b))
                    .unwrap_or(0)
            };
            if fetch(env.pc.wrapping_sub(4)) == SLLI_MARK && fetch(env.pc + 4) == SRAI_MARK {
                match sys.handle_ecall(env, word) {
                    EcallOutcome::Exit(code) => return Err(Outcome::Exit(code)),
                    EcallOutcome::Handled => {
                        env.pc += 4;
                        return Ok(());
                    }
                    EcallOutcome::Unimplemented => {
                        return Err(Outcome::Unimplemented {
                            pc: env.pc,
                            word: u128::from(word),
                        });
                    }
                }
            }
            return Err(Outcome::Unimplemented {
                pc: env.pc,
                word: u128::from(word),
            });
        }
        _ => {
            return Err(Outcome::Unimplemented {
                pc: env.pc,
                word: u128::from(word),
            });
        }
    };
    if ok.is_err() {
        return Err(Outcome::Unimplemented {
            pc: env.pc,
            word: u128::from(word),
        });
    }
    // 分岐なしは次へ進める（分岐成立は step が pc を置き換える）。
    if env.backend.ctrl == Ctrl::Fallthrough {
        env.pc += 4;
    }
    Ok(())
}

/// 16ビット命令を1件実行する。継続するとき None、退出するとき Some を返す。
/// RV32/RV64 で符号化が重なる命令は、モデル対応デコード（`decode_model`、
/// ADR-0006）が `when` の述語で振り分ける。
/// Ref: SPEC-RISCV-UNPRIV (20250508) §C.
fn step_c(env: &mut BareEnv, w16: u16, rv32: bool, feats: u128) -> Option<Outcome> {
    let word = u32::from(w16);
    let Some(insn) = decode_model_ex(u128::from(word), 16, !rv32, feats) else {
        return Some(Outcome::Unimplemented {
            pc: env.pc,
            word: u128::from(word),
        });
    };
    let r = run_c(env, insn, word, rv32);
    match r {
        Ok(()) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
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

/// C.ADDI4SPN の nzuimm[9:2]。Ref: SPEC-RISCV-UNPRIV（C 拡張の即値表）。
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

/// Zcb の byte アクセス即値（0 または 1）。
fn c_zcb_b_uimm(w: u16) -> u32 {
    (((w as u32) >> 6) & 1) | ((((w as u32) >> 5) & 1) << 1)
}

/// Zcb の half アクセス即値（0 または 2）。
fn c_zcb_h_uimm(w: u16) -> u32 {
    (((w as u32) >> 5) & 1) << 1
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
/// Ref: SPEC-RISCV-UNPRIV（C 拡張の即値表）。
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
/// inst[12]=off[8]、inst[11:10]=off[4:3]、inst[6:2]=off[7:6|2:1|5]。
/// Ref: SPEC-RISCV-UNPRIV（C 拡張の即値表）。
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
/// inst[12:10]=off[5:3]、inst[6:5]=off[7:6]。
/// Ref: SPEC-RISCV-UNPRIV（C 拡張の即値表）。
fn c_ld_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 10) & 7) << 3) | (((w >> 5) & 3) << 6)
}

/// C.LDSP の uimm[8:3]。
/// inst[12]=off[5]、inst[6:5]=off[4:3]、inst[4:2]=off[8:6]。
/// inst[7] は rd の一部でありオフセットに含めない。
/// Ref: SPEC-RISCV-UNPRIV（C 拡張の即値表）。
fn c_ldsp_uimm(w: u16) -> u32 {
    let w = w as u32;
    (((w >> 5) & 1) << 3)
        | (((w >> 6) & 1) << 4)
        | (((w >> 12) & 1) << 5)
        | (((w >> 2) & 1) << 6)
        | (((w >> 3) & 1) << 7)
        | (((w >> 4) & 1) << 8)
}

/// C.SDSP の uimm[8:3]。
/// inst[12:10]=off[5:3]、inst[9:7]=off[8:6]。
/// Ref: SPEC-RISCV-UNPRIV（C 拡張の即値表）。
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
fn run_c(env: &mut BareEnv, insn: Insn, word: u32, rv32: bool) -> Result<(), Outcome> {
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
        Insn::CMop1 => env.step(sem::c_mop),
        Insn::CMop3 => env.step(sem::c_mop),
        Insn::CMop5 => env.step(sem::c_mop),
        Insn::CMop7 => env.step(sem::c_mop),
        Insn::CMop9 => env.step(sem::c_mop),
        Insn::CMop11 => env.step(sem::c_mop),
        Insn::CMop13 => env.step(sem::c_mop),
        Insn::CMop15 => env.step(sem::c_mop),
        Insn::CLbu => {
            let rd = Gpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_zcb_b_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_lbu_rv32(b, rd, rs1, off))
            } else {
                env.step(|b| sem::c_lbu(b, rd, rs1, off))
            }
        }
        Insn::CLh => {
            let rd = Gpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_zcb_h_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_lh_rv32(b, rd, rs1, off))
            } else {
                env.step(|b| sem::c_lh(b, rd, rs1, off))
            }
        }
        Insn::CLhu => {
            let rd = Gpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_zcb_h_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_lhu_rv32(b, rd, rs1, off))
            } else {
                env.step(|b| sem::c_lhu(b, rd, rs1, off))
            }
        }
        Insn::CSb => {
            let rs1 = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            let off = c_zcb_b_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_sb_rv32(b, rs1, rs2, off))
            } else {
                env.step(|b| sem::c_sb(b, rs1, rs2, off))
            }
        }
        Insn::CSh => {
            let rs1 = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            let off = c_zcb_h_uimm(w) as i64;
            if rv32 {
                env.step(|b| sem::c_sh_rv32(b, rs1, rs2, off))
            } else {
                env.step(|b| sem::c_sh(b, rs1, rs2, off))
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rd = Gpr(crd3(w));
            let rs1 = Gpr(crs1(w));
            let off = c_ld_uimm(w) as i64;
            env.step(|b| sem::c_ld(b, rd, rs1, off))
        }
        Insn::CSd => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rd = Gpr(r(5, 7));
            let imm = c_imm6(w);
            env.step(|b| sem::c_addiw(b, rd, imm))
        }
        Insn::CJal => {
            // RV32 のみ（RV64 では CAddiw に分配される）。
            if !rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
        Insn::CZextB => {
            let rd = Gpr(crs1(w));
            if rv32 {
                env.step(|b| sem::c_zext_b_rv32(b, rd))
            } else {
                env.step(|b| sem::c_zext_b(b, rd))
            }
        }
        Insn::CSextB => {
            let rd = Gpr(crs1(w));
            if rv32 {
                env.step(|b| sem::c_sext_b_rv32(b, rd))
            } else {
                env.step(|b| sem::c_sext_b(b, rd))
            }
        }
        Insn::CZextH => {
            let rd = Gpr(crs1(w));
            if rv32 {
                env.step(|b| sem::c_zext_h_rv32(b, rd))
            } else {
                env.step(|b| sem::c_zext_h(b, rd))
            }
        }
        Insn::CSextH => {
            let rd = Gpr(crs1(w));
            if rv32 {
                env.step(|b| sem::c_sext_h_rv32(b, rd))
            } else {
                env.step(|b| sem::c_sext_h(b, rd))
            }
        }
        Insn::CZextW => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rd = Gpr(crs1(w));
            env.step(|b| sem::c_zext_w(b, rd))
        }
        Insn::CNot => {
            let rd = Gpr(crs1(w));
            if rv32 {
                env.step(|b| sem::c_not_rv32(b, rd))
            } else {
                env.step(|b| sem::c_not(b, rd))
            }
        }
        Insn::CMul => {
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            if rv32 {
                env.step(|b| sem::c_mul_rv32(b, rd, rs2))
            } else {
                env.step(|b| sem::c_mul(b, rd, rs2))
            }
        }
        Insn::CSubw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
            }
            let rd = Gpr(crs1(w));
            let rs2 = Gpr(crd3(w));
            env.step(|b| sem::c_subw(b, rd, rs2))
        }
        Insn::CAddw => {
            if rv32 {
                return Err(Outcome::Unimplemented {
                    pc: env.pc,
                    word: u128::from(word),
                });
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
            return Err(Outcome::Unimplemented {
                pc: env.pc,
                word: u128::from(word),
            });
        }
    };
    if ok.is_err() {
        return Err(Outcome::Unimplemented {
            pc: env.pc,
            word: u128::from(word),
        });
    }
    Ok(())
}

/// 静的 RV64 ELF を実行する。`path` を起点に引数を渡す。
///
/// 段取り（`cli run` の垂直スライス）：ELF を読み、セグメントを写像し、
/// 初期スタックを置き、エントリから `run` で回す。ecall は
/// `os_linux::rv64::sys::Linux` が処理する（未実装のものは ENOSYS）。
/// 動的リンク・VFS・シグナルは後の段階。
pub fn run_elf(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_sel(path, argv, None)
}

/// `run_elf` に CPU モデルの選択を渡す。`sel` の `feats` が
/// `decode_model_ex` に届く（`--cpu` の配線）。`is_rv64` が
/// `Some(false)` の RV32 は入口で拒否される既存の規則のままとする。
pub fn run_elf_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::rv64::sys::Linux::default();
    run_elf_handler(path, argv, sel, &mut sys)
}

/// ELF の読み込みと初期スタックの構築。返すのは (env, entry)。
/// `env.pc` への代入は呼び出し側が行う（`run_ex` が `env.pc = entry` を
/// 書く）。`run_elf_handler` と `run -g` の入口で共有する。
pub(crate) fn load_elf_env(path: &str, argv: &[String]) -> Result<(BareEnv, u64), String> {
    use polyisa_mem::{PAGE_SIZE, Perms};

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // `run` は RV64 リトルエンディアンの実行のみを受け持つ。
    // EM_RISCV=243。BE や他 ISA は後の段階の入口で受ける。
    // Ref: SPEC-RISCV-PSABI (v1.0) §1（RISC-V の e_machine 値）。
    const EM_RISCV: u16 = 243;
    if !ehdr.little {
        return Err("big-endian ELF は未対応".to_string());
    }
    if ehdr.machine != EM_RISCV {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_riscv::CpuState>());
    polyisa_loader::elf::load_segments(&bytes, &phdrs, &mut env.backend.mem)
        .map_err(|e| format!("load: {e:?}"))?;
    // 初期スタックを写像する。`build_initial_stack` の返す像を置く。
    let top = 0x7fff_0000u64;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let (img, sp) = polyisa_os_linux::build_initial_stack(top, &arg_bytes, &[], &[(6, 0x1000)]);
    let base = sp & !(PAGE_SIZE - 1);
    let end = top.next_multiple_of(PAGE_SIZE);
    let count = (end - base) / PAGE_SIZE;
    env.backend
        .mem
        .map(
            polyisa_mem::VirtAddr(base),
            count,
            Perms(Perms::R.0 | Perms::W.0),
        )
        .map_err(|e| format!("stack map: {e:?}"))?;
    env.backend
        .mem
        .write(polyisa_mem::VirtAddr(sp), &img)
        .map_err(|e| format!("stack write: {e:?}"))?;
    env.backend.set(Gpr(2).state(), sp);
    Ok((env, ehdr.entry))
}

/// `run_elf_sel` に `EcallHandler` を差し込む形。semihosting は
/// `SemiRv` を渡す（`--os semihost`）。
pub fn run_elf_handler(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    handler: &mut impl EcallHandler,
) -> Result<u64, String> {
    run_elf_handler_priv(path, argv, sel, handler, 0)
}

/// `run_elf_handler` を M モードで始める。bare-metal の semihosting
/// プログラムはリセット直後の M モードで動き、CSR 初期化を行う。
pub fn run_elf_handler_mmode(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    handler: &mut impl EcallHandler,
) -> Result<u64, String> {
    run_elf_handler_priv(path, argv, sel, handler, 3)
}

fn run_elf_handler_priv(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    handler: &mut impl EcallHandler,
    priv_level: u64,
) -> Result<u64, String> {
    let (mut env, entry) = load_elf_env(path, argv)?;
    env.backend.set(
        StateRef::<W64>::from_offset(core::mem::offset_of!(
            polyisa_guest_riscv::CpuState,
            priv_level
        )),
        priv_level,
    );
    let feats = sel.map_or(DEFAULT_FEATS, |s| s.feats);
    match run_ex(&mut env, entry, false, feats, handler) {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
        Outcome::Breakpoint { pc } => Err(format!("breakpoint at {pc:#x}")),
    }
}
