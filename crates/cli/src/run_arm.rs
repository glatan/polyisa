// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ARM（AArch32・ARM 状態）のフェッチから次のフェッチまで。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する（ADR-0016、GAP-0007）。
//! syscall の処理は `os-linux` の `arm::sys::Linux` に委譲する。
//!
//! cond=bits[31:28] をここで評価する。不成立なら命令を実行せず pc を 4
//! 進める。cond=1111 は ARMv7 の無条件領域で、意味論はそのまま実行する。
//! Thumb/Thumb-2 は対象外。pc の読み値は意味論側で「命令アドレス+8」。
//! Ref: SPEC-ARM-ARM-A (Arm ARM A32).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_arm::sem::{self, Gpr};
use polyisa_guest_arm::{Insn, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind, GuestException};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct ArmModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u64,
}

impl ArmModel {
    /// ARMv5TE（EDSP・CLZ あり、ARMv7 のメディア・除算なし）。
    #[must_use]
    pub const fn armv5() -> Self {
        Self { feats: 0 }
    }

    /// ARMv7-A（MOVW/MOVT・BFI/BFC/UBFX/SBFX・SDIV/UDIV・並列演算）。
    /// 現在の意味論は v7 命令を無条件で受け付けるので、ここでも
    /// v5/v7 の区別は decode の `feats` に載せるだけである。
    /// 生成デコーダは機能旗を参照しないため、feats は常に 0。
    #[must_use]
    pub const fn armv7() -> Self {
        Self { feats: 0 }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(env: &mut BareEnv, entry: u64, model: ArmModel, sys: &mut impl TrapHandler) -> Outcome {
    run_ex(env, entry, model, sys, STEP_LIMIT)
}

/// `run` にステップ数の上限を渡す。
pub fn run_ex(
    env: &mut BareEnv,
    entry: u64,
    model: ArmModel,
    sys: &mut impl TrapHandler,
    limit: u64,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        limit,
        |env| env.pc,
        |env, sys| step_a32(env, sys, model),
    )
}

/// `svc` のトラップ委譲。`TrapOutcome` を `Outcome` へ写す。
fn svc<H: ?Sized + TrapHandler>(
    env: &mut BareEnv,
    sys: &mut H,
    pc: u64,
    word: u32,
) -> Result<(), Outcome> {
    match sys.handle_trap(env, word & 0x00ff_ffff) {
        TrapOutcome::Handled => {
            env.pc += 4;
            Ok(())
        }
        TrapOutcome::Exit(code) => {
            if sys.take_exit(env, code) {
                Ok(())
            } else {
                Err(Outcome::Exit(u64::from(code)))
            }
        }
        TrapOutcome::Blocked => {
            if sys.on_block(env) {
                Ok(())
            } else {
                Err(Outcome::Deadlock)
            }
        }
        TrapOutcome::Unimplemented => Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        }),
    }
}

/// CPSR の値から cond（bits[31:28]）を評価する。
/// Ref: SPEC-ARM-ARM-A (Arm ARM A32) — Condition codes.
fn cond_pass(cpsr: u32, cond: u32) -> bool {
    let n = cpsr & (1 << 31) != 0;
    let z = cpsr & (1 << 30) != 0;
    let c = cpsr & (1 << 29) != 0;
    let v = cpsr & (1 << 28) != 0;
    match cond {
        0x0 => z,            // eq
        0x1 => !z,           // ne
        0x2 => c,            // cs/hs
        0x3 => !c,           // cc/lo
        0x4 => n,            // mi
        0x5 => !n,           // pl
        0x6 => v,            // vs
        0x7 => !v,           // vc
        0x8 => c && !z,      // hi
        0x9 => !c || z,      // ls
        0xa => n == v,       // ge
        0xb => n != v,       // lt
        0xc => !z && n == v, // gt
        0xd => z || n != v,  // le
        _ => true,           // al
    }
}

/// 1 命令ぶんのフェッチ・解読・意味論と svc 境界の解決。
/// cond 不成立は pc を 4 進めるだけ。フェッチとデータアクセスは
/// リトルエンディアン（試作は EABI LE のみを対象とする）。
// Ref: SPEC-ARM-ARM-A (Arm ARM A32).
fn step_a32(env: &mut BareEnv, sys: &mut impl TrapHandler, model: ArmModel) -> Result<(), Outcome> {
    let pc = env.pc;
    let unimpl = |env: &BareEnv| Outcome::Unimplemented {
        pc: env.pc,
        word: 0xffff_ffff,
    };
    if !pc.is_multiple_of(4) {
        return Err(Outcome::Unimplemented { pc, word: 0 });
    }
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b4 = [0u8; 4];
    if env.backend.mem.read(VirtAddr(pc), &mut b4, acc).is_err() {
        return Err(unimpl(env));
    }
    let word = u32::from_le_bytes(b4);
    let Some(insn) = decode_model_ex(u128::from(word), 32, true, model.feats) else {
        return Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        });
    };
    // cond の評価。1111 は無条件領域（実行）。それ以外は CPSR を読む。
    let cond = word >> 28;
    if cond != 0xf {
        let cpsr: u32 = env.backend.get(sem::cpsr_ref());
        if !cond_pass(cpsr, cond) {
            env.pc += 4;
            return Ok(());
        }
    }
    if insn == Insn::Svc {
        return svc(env, sys, pc, word);
    }
    if std::env::var_os("POLYISA_ARM_TRACE_INSN").is_some() {
        eprintln!("insn@{pc:#x}={insn:?} {word:#x}");
        if let Ok(w) = std::env::var("POLYISA_ARM_WATCH") {
            let lo = u64::from_str_radix(w.trim_start_matches("0x"), 16).unwrap_or(0);
            if pc >= lo && pc < lo + 0x200 {
                let mut s = String::new();
                for r in 0u8..16 {
                    let v: u32 = env.backend.get(Gpr(r).state());
                    s.push_str(&format!(" r{r}={v:#x}"));
                }
                let cpsr: u32 = env.backend.get(sem::cpsr_ref());
                eprintln!("   {s} cpsr={cpsr:#x}");
                if std::env::var_os("POLYISA_ARM_VFP").is_some() {
                    let mut v = String::new();
                    for d in 0u8..16 {
                        let w: u64 = env.backend.get(sem::vfp_ref(d));
                        v.push_str(&format!(" d{d}={w:016x}({:#e})", f64::from_bits(w)));
                    }
                    eprintln!("  vfp{v}");
                }
            }
        }
    }
    LAST_EXC.with(|c| c.set(None));
    let ok = match insn {
        Insn::DpImm => env.step(|b| sem::dp_imm(b, word, pc)),
        Insn::DpReg => env.step(|b| sem::dp_reg(b, word, pc)),
        Insn::DpSreg => env.step(|b| sem::dp_sreg(b, word, pc)),
        Insn::Mul => env.step(|b| sem::mul(b, word, pc)),
        Insn::Mull => env.step(|b| sem::mull(b, word, pc)),
        Insn::Swp => env.step(|b| sem::swp(b, word, pc)),
        Insn::Excl => env.step(|b| sem::excl(b, word, pc)),
        Insn::ElsH | Insn::ElsD => env.step(|b| sem::els(b, word, pc)),
        Insn::LsImm => env.step(|b| sem::ls(b, word, pc, false)),
        Insn::LsReg => env.step(|b| sem::ls(b, word, pc, true)),
        Insn::Media => env.step(|b| sem::media(b, word, pc)),
        Insn::LdmStm => env.step(|b| sem::ldm_stm(b, word, pc)),
        Insn::B => env.step(|b| sem::b_bl(b, pc, word, false)),
        Insn::Bl => env.step(|b| sem::b_bl(b, pc, word, true)),
        Insn::CpLs => env.step(|b| sem::cp_ls(b, word, pc)),
        Insn::CpDp => env.step(|b| sem::cp_dp(b, word, pc)),
        Insn::BlxImm => env.step(|b| sem::blx_imm(b, pc, word)),
        Insn::UncondHint => env.step(|b| sem::uncond_hint(b, word)),
        Insn::Cp2Ls | Insn::Cp2Dp => env.step(|b| sem::cp2(b, word)),
        Insn::Svc => unreachable!("svc は先に振り分け済み"),
    };
    match ok {
        Ok(()) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
                env.pc += 4;
            }
            Ok(())
        }
        Err(polyisa_engine::interp::InterpExit::Exception(e)) => {
            LAST_EXC.with(|c| c.set(Some(e)));
            if std::env::var_os("POLYISA_ARM_TRACE").is_some() {
                eprintln!("exc {:?} addr={:?} pc={pc:#x}", e.kind, e.addr);
                for r in 0u8..16 {
                    let v: u32 = env.backend.get(Gpr(r).state());
                    eprintln!("  r{r}={v:#x}");
                }
            }
            Err(Outcome::Unimplemented {
                pc,
                word: u128::from(word),
            })
        }
        Err(polyisa_engine::interp::InterpExit::Unimplemented(_)) => Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        }),
    }
}

/// 静的な ARM ELF を実行する。機械番号 40（EM_ARM）。EABI・LE のみ。
/// `sys` は `os_linux::arm::sys::Linux` が処理する（未実装は ENOSYS）。
/// Ref: SPEC-ARM-ARM-A, SRC-LINUX (7.3).
pub fn run_elf_arm(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_arm_sel(path, argv, None)
}

/// `run_elf_arm` に CPU モデルの選択を渡す（`--cpu` の配線）。
pub fn run_elf_arm_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::arm::sys::Linux::new();
    run_elf_arm_sys(path, argv, sel, &mut sys)
}

/// `run_elf_arm_sel` に OS パーソナリティを差し込む形。
/// テストが syscall の結果（`sys.io` 等）を検査する用途に使う。
pub fn run_elf_arm_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::arm::sys::Linux,
) -> Result<u64, String> {
    use polyisa_mem::{PAGE_SIZE, Perms};

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if !matches!(bytes.get(4), Some(1)) {
        return Err("ARM は ELFCLASS32 のみ対応".to_string());
    }
    let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_ARM=40。Ref: SPEC-AARCH64-ELF（AAELF32）/AAELF32 §4.1。
    const EM_ARM: u16 = 40;
    if ehdr.machine != EM_ARM {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    if !ehdr.little {
        return Err("ARM はリトルエンディアンのみ対応".to_string());
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("PT_INTERP のある ARM ELF は未対応（静的のみ）".to_string());
    }
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_arm::CpuState>());
    // ET_DYN の主像は固定基盤へ寄せる（PIE）。ET_EXEC は p_vaddr どおり。
    const MAIN_DYN_BASE: u64 = 0x0001_0000;
    const ET_DYN: u16 = 3;
    let min_vaddr = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr & !(PAGE_SIZE - 1))
        .min()
        .unwrap_or(0);
    let main_bias = if ehdr.file_type == ET_DYN {
        MAIN_DYN_BASE - min_vaddr
    } else {
        0
    };
    let image_end = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr + p.memsz)
        .max()
        .unwrap_or(0)
        + main_bias;
    polyisa_loader::elf::load_segments_bias(&bytes, &phdrs, &mut env.backend.mem, main_bias)
        .map_err(|e| format!("load: {e:?}"))?;
    // 主像の phdr 表のゲスト内番地（AT_PHDR）。表は先頭の PT_LOAD が覆うのが
    // 普通だが、覆わない最小像は像の直後へ表だけ別置きする。
    // Ref: SPEC-ELF-GABI (Edition 4.1＋2001-04-24 DRAFT).
    let phdr_addr = match phdrs
        .iter()
        .find(|p| p.seg_type == 1 && p.offset <= ehdr.phoff && ehdr.phoff < p.offset + p.filesz)
    {
        Some(p) => main_bias + p.vaddr + (ehdr.phoff - p.offset),
        None => {
            let at = (main_bias + min_vaddr)
                .checked_sub(PAGE_SIZE)
                .ok_or_else(|| "phdr 表の置き場がない".to_string())?;
            let lo = ehdr.phoff as usize;
            let hi = lo + ehdr.phnum as usize * 32;
            env.backend
                .mem
                .map(VirtAddr(at), 1, Perms::RW)
                .map_err(|_| "phdr 表の写像に失敗".to_string())?;
            env.backend
                .mem
                .write(VirtAddr(at), &bytes[lo..hi])
                .map_err(|_| "phdr 表の書き込みに失敗".to_string())?;
            let _ = env.backend.mem.protect(VirtAddr(at), 1, Perms::R);
            at
        }
    };
    let entry = main_bias + ehdr.entry;
    // 初期スタック。32 ビットの上端は 0xbffff000 付近。成長は
    // ページフォルト駆動で伸ばす。
    let top = 0xbfff_f000u64;
    const STACK_LIMIT: u64 = 8 << 20;
    let img_top = top - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // HWCAP：musl は __set_tls で HWCAP_TLS(0x8000) を見る。
    // VFP/IDIV の両方を立てる（モデルに関係なく v7 面を使える実装のため）。
    const HWCAP_TLS: u64 = 0x8000;
    const HWCAP_VFP: u64 = 0x40;
    const HWCAP_EDSP: u64 = 0x80;
    const HWCAP_VFPV3: u64 = 0x2000;
    const HWCAP_IDIVA: u64 = 0x2_0000;
    const HWCAP_IDIVT: u64 = 0x4_0000;
    const HWCAP_VFPD32: u64 = 0x8_0000;
    let hwcap =
        HWCAP_TLS | HWCAP_VFP | HWCAP_EDSP | HWCAP_VFPV3 | HWCAP_IDIVA | HWCAP_IDIVT | HWCAP_VFPD32;
    let mut auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),             // AT_PHDR
        (4, 32),                    // AT_PHENT
        (5, u64::from(ehdr.phnum)), // AT_PHNUM
        (6, 0x1000),                // AT_PAGESZ
        (8, 0),                     // AT_FLAGS
        (9, entry),                 // AT_ENTRY
        (11, 0),                    // AT_UID
        (12, 0),                    // AT_EUID
        (13, 0),                    // AT_GID
        (14, 0),                    // AT_EGID
        (16, hwcap),                // AT_HWCAP
        (17, 100),                  // AT_CLKTCK
        (23, 0),                    // AT_SECURE
        (25, 0),                    // AT_RANDOM（後で実番地に差し替え）
    ];
    let rand_addr = top - 16;
    for (k, v) in auxv.iter_mut() {
        if *k == 25 {
            *v = rand_addr;
        }
    }
    let (img, sp) = polyisa_os_linux::build_initial_stack32(img_top, &arg_bytes, &[], &auxv);
    let stack_base = sp & !(PAGE_SIZE - 1);
    let stack_pages = (top - stack_base) / PAGE_SIZE;
    env.backend
        .mem
        .map(
            VirtAddr(stack_base),
            stack_pages,
            Perms(Perms::R.0 | Perms::W.0),
        )
        .map_err(|e| format!("stack map: {e:?}"))?;
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|e| format!("stack write: {e:?}"))?;
    env.backend
        .mem
        .write(
            VirtAddr(rand_addr),
            &[
                0x70, 0x6f, 0x6c, 0x79, 0x69, 0x73, 0x61, 0x2d, 0x61, 0x72, 0x6d, 0x33, 0x32, 0x21,
            ],
        )
        .map_err(|e| format!("stack write: {e:?}"))?;
    // sp=r13。cpsr/r0–r12/lr は 0 のまま。
    env.backend.set(Gpr(13).state(), sp as u32);
    sys.exe_path = path.to_string();
    sys.init_brk(image_end);
    // 生成デコーダは機能旗を参照しない（ARM の粗いクラス分けのため）。
    // 選択は意味論の振る舞いに使う余地として残し、feats は 0 を渡す。
    let _ = sel;
    let feats = 0;
    let growth = Some(StackGrowth {
        top,
        limit: top - STACK_LIMIT,
    });
    match run_with_growth(&mut env, entry, feats, growth, sys) {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
    }
}

/// スタックの成長窓。未写像フォルトをこの範囲で埋める。
// Ref: SRC-LINUX (7.3) — expand_stack の規約（RLIMIT 内の下方成長）。
#[derive(Clone, Copy, Debug)]
pub struct StackGrowth {
    /// スタック上端。
    pub top: u64,
    /// これより下は伸ばさない。
    pub limit: u64,
}

/// `run` にスタック成長窓を添える形。aarch64 と同じくフォルト駆動。
fn run_with_growth(
    env: &mut BareEnv,
    entry: u64,
    feats: u64,
    stack: Option<StackGrowth>,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    let model = ArmModel { feats };
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_a32_growth(env, sys, model, stack),
    )
}

/// `step_a32` にスタック成長のフォルト処理を添える。
fn step_a32_growth(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: ArmModel,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    match step_a32(env, sys, model) {
        Err(Outcome::Unimplemented { pc, word }) => {
            // 未実装のうちスタック窓内の PageFault は写像を伸ばして
            // 同じ命令をやり直す。それ以外はそのまま返す。
            let last = LAST_EXC.with(|c| c.get());
            if let Some(g) = last
                && stack_grow(env, stack, &g).is_some()
            {
                return Ok(());
            }
            Err(Outcome::Unimplemented { pc, word })
        }
        r => r,
    }
}

thread_local! {
    static LAST_EXC: std::cell::Cell<Option<GuestException>> =
        const { std::cell::Cell::new(None) };
}

/// ページフォルトをスタック成長として処理する。窓 `[limit, top)` 内の
/// 未写像ページへのフォルトなら、フォルトしたページから最初に写像済みの
/// ページの手前までを R/W で写像する。処理したなら `Some` を返す。
// Ref: SRC-LINUX (7.3) — expand_stack の規約（RLIMIT 内の下方成長）。
fn stack_grow(env: &mut BareEnv, stack: Option<StackGrowth>, e: &GuestException) -> Option<()> {
    use polyisa_mem::{PAGE_SIZE, PageNo, Perms};
    let s = stack?;
    if e.kind != ExceptionKind::PageFault {
        return None;
    }
    let a = e.addr?;
    if a >= s.top || a < s.limit {
        return None;
    }
    let lo = a & !(PAGE_SIZE - 1);
    let mut hi = lo;
    while hi < s.top && !env.backend.mem.is_mapped(PageNo(hi / PAGE_SIZE)) {
        hi += PAGE_SIZE;
    }
    let pages = (hi - lo) / PAGE_SIZE;
    if pages == 0 {
        return None;
    }
    env.backend
        .mem
        .map(VirtAddr(lo), pages, Perms(Perms::R.0 | Perms::W.0))
        .ok()
}
