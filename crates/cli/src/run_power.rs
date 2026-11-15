// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Power（ppc64・ELFv2）のフェッチから次のフェッチまで。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する（ARM 試作と同じ構造）。
//! syscall の処理は `os-linux` の `power::sys::Linux` に委譲する。
//!
//! 命令は固定長 32 ビット。遅延スロットはない。`sc`（主オペコード 17）で
//! `TrapHandler` へ委譲し、Handled なら pc を 4 進める。ELFv2 の大域入口
//! 規約として、プロセスの入口は r12 = 入口番地で呼ばれる（入口関数が
//! r12 から r2/TOC を組み立てる）。
//! Ref: SPEC-POWER-ISA (v3.1C), SPEC-POWER-ABI (ELFv2 r1.5).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_power::sem::{self, Gpr};
use polyisa_guest_power::{Insn, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind, GuestException};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct PowerModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u64,
    /// データ・命令のエンディアン。ppc64le が主対象。
    pub le: bool,
}

impl PowerModel {
    /// ppc64le ELFv2 の既定モデル。
    #[must_use]
    pub const fn powerpc64le() -> Self {
        Self { feats: 0, le: true }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: PowerModel,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_power(env, sys, model),
    )
}

/// `sc` のトラップ委譲。`TrapOutcome` を `Outcome` へ写す。
/// 成功/エラーの CR0.SO 書き戻しは `sys` 側の仕事。
fn sc<H: ?Sized + TrapHandler>(
    env: &mut BareEnv,
    sys: &mut H,
    pc: u64,
    word: u32,
) -> Result<(), Outcome> {
    match sys.handle_trap(env, 0) {
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

/// 1 命令ぶんのフェッチ・解読・意味論と `sc` 境界の解決。
/// `model.le` がフェッチとデータアクセスのエンディアンを決める。
// Ref: SPEC-POWER-ISA (v3.1C).
fn step_power(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: PowerModel,
) -> Result<(), Outcome> {
    let pc = env.pc;
    let unimpl = |env: &BareEnv| Outcome::Unimplemented {
        pc: env.pc,
        word: 0xffff_ffff,
    };
    if !pc.is_multiple_of(4) {
        return Err(Outcome::Unimplemented { pc, word: 0 });
    }
    let acc = Access {
        endian: if model.le { Endian::Le } else { Endian::Be },
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b4 = [0u8; 4];
    if env.backend.mem.read(VirtAddr(pc), &mut b4, acc).is_err() {
        return Err(unimpl(env));
    }
    // mem.read は生バイトを返すので命令語はここでエンディアン変換する。
    // ppc64le が主対象だが、ELF の EI_DATA をそのまま従う。
    let word = if model.le {
        u32::from_le_bytes(b4)
    } else {
        u32::from_be_bytes(b4)
    };
    let Some(insn) = decode_model_ex(u128::from(word), 32, true, model.feats) else {
        return Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        });
    };
    if insn == Insn::Sc {
        return sc(env, sys, pc, word);
    }
    if std::env::var_os("POLYISA_POWER_TRACE_INSN").is_some() {
        // aarch64/arm と同じ任意点検査の経路。LO/HI で範囲を絞れる。
        let lo = std::env::var("POLYISA_TRACE_LO")
            .ok()
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        let hi = std::env::var("POLYISA_TRACE_HI")
            .ok()
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or(u64::MAX);
        if pc >= lo && pc <= hi {
            eprintln!("insn@{pc:#x}={insn:?} {word:#x}");
            if std::env::var_os("POLYISA_POWER_DUMP").is_some() {
                for i in [5u8, 8, 9, 31] {
                    let r = env.backend.get(Gpr(i).state());
                    eprintln!("  r{i}={r:#x}");
                }
                let r5: u64 = env.backend.get(Gpr(5).state());
                let mut buf = [0u8; 8];
                let dacc = Access {
                    endian: if model.le { Endian::Le } else { Endian::Be },
                    align: Align::Natural,
                    kind: AccessKind::DataRead,
                };
                let mut mbuf = [0u8; 40];
                if env.backend.mem.read(VirtAddr(r5), &mut mbuf, dacc).is_ok() {
                    eprintln!("  mem[r5..+40]={mbuf:02x?}");
                }
                if env
                    .backend
                    .mem
                    .read(VirtAddr(r5 + 24), &mut buf, dacc)
                    .is_ok()
                {
                    eprintln!("  mem[r5+24]={buf:02x?}");
                }
            }
        }
    }
    // 一時デバッグ: POLYISA_WATCH_ADDR の 8 バイトを step ごとに比較する。
    let watch = std::env::var("POLYISA_WATCH_ADDR")
        .ok()
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());
    let wprev = watch.and_then(|wa| {
        let mut wb = [0u8; 8];
        let wacc = Access {
            endian: if model.le { Endian::Le } else { Endian::Be },
            align: Align::Natural,
            kind: AccessKind::DataRead,
        };
        env.backend.mem.read(VirtAddr(wa), &mut wb, wacc).ok()?;
        Some(wb)
    });
    LAST_EXC.with(|c| c.set(None));
    let le = model.le;
    let ok = match insn {
        Insn::Tdi => env.step(|b| sem::tdi(b, word, pc, le)),
        Insn::Twi => env.step(|b| sem::twi(b, word, pc, le)),
        Insn::X4 => env.step(|b| sem::x4(b, word, pc, le)),
        Insn::Mulli => env.step(|b| sem::mulli(b, word, pc, le)),
        Insn::Subfic => env.step(|b| sem::subfic(b, word, pc, le)),
        Insn::Cmpli => env.step(|b| sem::cmpli(b, word, pc, le)),
        Insn::Cmpwi => env.step(|b| sem::cmpwi(b, word, pc, le)),
        Insn::Addic => env.step(|b| sem::addic(b, word, pc, le)),
        Insn::AddicRc => env.step(|b| sem::addic_rc(b, word, pc, le)),
        Insn::Addi => env.step(|b| sem::addi(b, word, pc, le)),
        Insn::Addis => env.step(|b| sem::addis(b, word, pc, le)),
        Insn::Bc => env.step(|b| sem::bc(b, word, pc, le)),
        Insn::Sc => unreachable!("sc は先に振り分け済み"),
        Insn::B => env.step(|b| sem::b_(b, word, pc, le)),
        Insn::X19 => env.step(|b| sem::x19(b, word, pc, le)),
        Insn::Rlwimi => env.step(|b| sem::rlwimi(b, word, pc, le)),
        Insn::Rlwinm => env.step(|b| sem::rlwinm(b, word, pc, le)),
        Insn::Rlwnm => env.step(|b| sem::rlwnm(b, word, pc, le)),
        Insn::Ori => env.step(|b| sem::ori(b, word, pc, le)),
        Insn::Oris => env.step(|b| sem::oris(b, word, pc, le)),
        Insn::Xori => env.step(|b| sem::xori(b, word, pc, le)),
        Insn::Xoris => env.step(|b| sem::xoris(b, word, pc, le)),
        Insn::AndiRc => env.step(|b| sem::andi_rc(b, word, pc, le)),
        Insn::AndisRc => env.step(|b| sem::andis_rc(b, word, pc, le)),
        Insn::X30 => env.step(|b| sem::x30(b, word, pc, le)),
        Insn::X31 => env.step(|b| sem::x31(b, word, pc, le)),
        Insn::Lwz => env.step(|b| sem::lwz(b, word, pc, le)),
        Insn::Lwzu => env.step(|b| sem::lwzu(b, word, pc, le)),
        Insn::Lbz => env.step(|b| sem::lbz(b, word, pc, le)),
        Insn::Lbzu => env.step(|b| sem::lbzu(b, word, pc, le)),
        Insn::Stw => env.step(|b| sem::stw(b, word, pc, le)),
        Insn::Stwu => env.step(|b| sem::stwu(b, word, pc, le)),
        Insn::Stb => env.step(|b| sem::stb(b, word, pc, le)),
        Insn::Stbu => env.step(|b| sem::stbu(b, word, pc, le)),
        Insn::Lhz => env.step(|b| sem::lhz(b, word, pc, le)),
        Insn::Lhzu => env.step(|b| sem::lhzu(b, word, pc, le)),
        Insn::Lha => env.step(|b| sem::lha(b, word, pc, le)),
        Insn::Lhau => env.step(|b| sem::lhau(b, word, pc, le)),
        Insn::Sth => env.step(|b| sem::sth(b, word, pc, le)),
        Insn::Sthu => env.step(|b| sem::sthu(b, word, pc, le)),
        Insn::Lmw => env.step(|b| sem::lmw(b, word, pc, le)),
        Insn::Stmw => env.step(|b| sem::stmw(b, word, pc, le)),
        Insn::Lfs => env.step(|b| sem::lfs(b, word, pc, le)),
        Insn::Lfsu => env.step(|b| sem::lfsu(b, word, pc, le)),
        Insn::Lfd => env.step(|b| sem::lfd(b, word, pc, le)),
        Insn::Lfdu => env.step(|b| sem::lfdu(b, word, pc, le)),
        Insn::Stfs => env.step(|b| sem::stfs(b, word, pc, le)),
        Insn::Stfsu => env.step(|b| sem::stfsu(b, word, pc, le)),
        Insn::Stfd => env.step(|b| sem::stfd(b, word, pc, le)),
        Insn::Stfdu => env.step(|b| sem::stfdu(b, word, pc, le)),
        Insn::X56 => env.step(|b| sem::x56(b, word, pc, le)),
        Insn::X58 => env.step(|b| sem::x58(b, word, pc, le)),
        Insn::X59 => env.step(|b| sem::x59(b, word, pc, le)),
        Insn::X60 => env.step(|b| sem::x60(b, word, pc, le)),
        Insn::X61 => env.step(|b| sem::x61(b, word, pc, le)),
        Insn::X62 => env.step(|b| sem::x62(b, word, pc, le)),
        Insn::X63 => env.step(|b| sem::x63(b, word, pc, le)),
    };
    if let (Some(wa), Some(prev)) = (watch, wprev) {
        let wacc = Access {
            endian: if model.le { Endian::Le } else { Endian::Be },
            align: Align::Natural,
            kind: AccessKind::DataRead,
        };
        let mut wb = [0u8; 8];
        if env.backend.mem.read(VirtAddr(wa), &mut wb, wacc).is_ok() && wb != prev {
            eprintln!("watch {wa:#x}: {prev:02x?} -> {wb:02x?} @pc={pc:#x} w={word:#x}");
        }
    }
    match ok {
        Ok(()) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
                env.pc += 4;
            }
            Ok(())
        }
        Err(polyisa_engine::interp::InterpExit::Exception(e)) => {
            if std::env::var_os("POLYISA_POWER_TRACE").is_some() {
                eprintln!("exc {:?} addr={:?} pc={pc:#x}", e.kind, e.addr);
            }
            LAST_EXC.with(|c| c.set(Some(e)));
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

/// ppc64 の ELF を実行する。機械番号 21（EM_PPC64）。ELFv2・ppc64le が主対象。
/// `sys` は `os_linux::power::sys::Linux` が処理する（未実装は ENOSYS）。
/// Ref: SPEC-POWER-ABI (ELFv2 r1.5), SRC-LINUX (7.3).
pub fn run_elf_power(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_power_sel(path, argv, None)
}

/// `run_elf_power` に CPU モデルの選択を渡す（`--cpu` の配線）。
pub fn run_elf_power_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::power::sys::Linux::default();
    run_elf_power_impl(path, argv, sel, &mut sys, None)
}

/// `run_elf_power_sel` にゲストルートを渡す形（`--root` の配線）。
/// `root` は PT_INTERP の指す動的ローダと、syscall 経路のパス解決の両方で使う。
pub fn run_elf_power_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    root: Option<&str>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::power::sys::Linux::default();
    run_elf_power_impl(path, argv, sel, &mut sys, root)
}

/// `run_elf_power_sel` に OS パーソナリティを差し込む形。
/// テストが syscall の結果（`sys.io` 等）を検査する用途に使う。
pub fn run_elf_power_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::power::sys::Linux,
) -> Result<u64, String> {
    run_elf_power_impl(path, argv, sel, sys, None)
}

/// `run_elf_power_sys` にゲストルートを添える形。
/// PT_INTERP 経路の動的リンクと root 内のファイル参照を試すテストに使う。
pub fn run_elf_power_sys_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::power::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    run_elf_power_impl(path, argv, sel, sys, root)
}

/// `run_elf_power_sys` にゲストルートを添えた実体。
/// `root` は PT_INTERP の動的ローダ解決と `sys` のパス閉じ込めに使う。
fn run_elf_power_impl(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::power::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    use polyisa_mem::{PAGE_SIZE, Perms};

    // root 指定時は ELF のパスもゲストの名前空間（chroot と同じ規則）。
    let host_elf = match root {
        Some(root) => polyisa_os_linux::guest_path::resolve_guest_path_links(root, "/", path)
            .ok_or_else(|| format!("{path}: ゲストルートの外を指す"))?,
        None => path.to_string(),
    };
    let bytes = std::fs::read(&host_elf).map_err(|e| format!("read {path}: {e}"))?;
    if !matches!(bytes.get(4), Some(2)) {
        return Err("Power は ELFCLASS64 のみ対応".to_string());
    }
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_PPC64=21。Ref: SPEC-POWER-ABI (ELFv2 r1.5)。
    const EM_PPC64: u16 = 21;
    if ehdr.machine != EM_PPC64 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let le = ehdr.little;
    let data_endian = if le { Endian::Le } else { Endian::Be };
    let phdrs =
        polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let interp_path = polyisa_loader::elf::parse_interp(&bytes, &phdrs);
    sys.set_endian(data_endian);
    if let Some(r) = root {
        sys.set_guest_root(r);
    } else if interp_path.is_some() {
        return Err("PT_INTERP のある ELF には --root が必要".to_string());
    }
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_power::CpuState>());
    // ET_DYN の主像は固定基盤へ寄せる（PIE）。ET_EXEC は p_vaddr どおり。
    const MAIN_DYN_BASE: u64 = 0x0000_1000_0000_0000;
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
    // 主像の phdr 表のゲスト内番地（AT_PHDR）。
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
            let hi = lo + ehdr.phnum as usize * 56;
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
    // PT_INTERP の動的ローダを像として読み、その入口から始める。
    // Ref: SPEC-ELF-GABI (Edition 4.1＋2001-04-24 DRAFT).
    const INTERP_BASE: u64 = 0x0000_2000_0000_0000;
    let (entry, interp_bias) = if let Some(gpath) = interp_path {
        let host =
            polyisa_os_linux::guest_path::resolve_guest_path(root.unwrap_or(""), "/", &gpath)
                .ok_or_else(|| format!("interp {gpath} が root 外を指す"))?;
        let ibytes = std::fs::read(&host).map_err(|e| format!("read interp {host}: {e}"))?;
        if !matches!(ibytes.get(4), Some(2)) {
            return Err(format!("interp {host} は ELFCLASS64 ではない"));
        }
        let iehdr =
            polyisa_loader::elf::parse_ehdr(&ibytes).map_err(|e| format!("interp ehdr: {e:?}"))?;
        if iehdr.machine != EM_PPC64 {
            return Err(format!("interp {host} は ppc64 の ELF ではない"));
        }
        let iphdrs = polyisa_loader::elf::parse_phdrs(&ibytes, &iehdr)
            .map_err(|e| format!("interp phdrs: {e:?}"))?;
        let imin = iphdrs
            .iter()
            .filter(|p| p.seg_type == 1)
            .map(|p| p.vaddr & !(PAGE_SIZE - 1))
            .min()
            .unwrap_or(0);
        let ibias = if iehdr.file_type == ET_DYN {
            INTERP_BASE - imin
        } else {
            0
        };
        polyisa_loader::elf::load_segments_bias(&ibytes, &iphdrs, &mut env.backend.mem, ibias)
            .map_err(|e| format!("interp load: {e:?}"))?;
        (ibias + iehdr.entry, ibias)
    } else {
        (main_bias + ehdr.entry, 0)
    };
    // 初期スタック。像を載せる分だけ先に写像し、下方向の成長は
    // ページフォルト駆動で伸ばす。
    // Ref: SRC-LINUX (7.3) — expand_stack。
    let top = 0x0000_7fff_fff0_0000u64;
    const STACK_LIMIT: u64 = 8 << 20;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let img_top = top - 0x1_0000;
    // auxv。ppc64 の AT_HWCAP は PPC_FEATURE/PPC_FEATURE2 の能力旗。
    // VSX・Altivec を立てて musl の ifunc 解決を通す。
    // Ref: SRC-LINUX (7.3) `arch/powerpc/include/asm/cputable.h`。
    const PPC_FEATURE_HAS_ALTIVEC: u64 = 0x1000_0000;
    const PPC_FEATURE_HAS_VSX: u64 = 0x0000_0080;
    const PPC_FEATURE2_ARCH_2_07: u64 = 0x8000_0000;
    let mut auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),                                      // AT_PHDR
        (4, 56),                                             // AT_PHENT
        (5, u64::from(ehdr.phnum)),                          // AT_PHNUM
        (6, 0x1000),                                         // AT_PAGESZ
        (8, 0),                                              // AT_FLAGS
        (9, main_bias + ehdr.entry),                         // AT_ENTRY
        (11, 0),                                             // AT_UID
        (12, 0),                                             // AT_EUID
        (13, 0),                                             // AT_GID
        (14, 0),                                             // AT_EGID
        (16, PPC_FEATURE_HAS_ALTIVEC | PPC_FEATURE_HAS_VSX), // AT_HWCAP
        (17, 100),                                           // AT_CLKTCK
        (20, PPC_FEATURE2_ARCH_2_07),                        // AT_HWCAP2
        (23, 0),                                             // AT_SECURE
        (25, 0),                                             // AT_RANDOM（後で実番地に差し替え）
    ];
    if interp_bias != 0 {
        auxv.push((7, interp_bias)); // AT_BASE
    }
    let rand_addr = top - 16;
    for (k, v) in auxv.iter_mut() {
        if *k == 25 {
            *v = rand_addr;
        }
    }
    let (img, sp) =
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &[], &auxv, data_endian);
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
                0x70, 0x6f, 0x6c, 0x79, 0x69, 0x73, 0x61, 0x2d, 0x70, 0x70, 0x63, 0x36, 0x34, 0x21,
                0x21,
            ],
        )
        .map_err(|e| format!("stack write: {e:?}"))?;
    // r1 = sp。ELFv2 の大域入口規約で r12 = 入口番地（入口関数が r12 から
    // r2/TOC を組み立てる）。r2/r13 はゲストが自分で張る。
    // Ref: SPEC-POWER-ABI (ELFv2 r1.5) §3.4.1。
    env.backend.set(Gpr(1).state(), sp);
    env.backend.set(Gpr(12).state(), entry);
    sys.exe_path = path.to_string();
    sys.init_brk(image_end);
    let feats = sel.map_or(0, |s| s.feats);
    let model = PowerModel { feats, le };
    let growth = Some(StackGrowth {
        top,
        limit: top - STACK_LIMIT,
    });
    match run_with_growth(&mut env, entry, model, growth, sys) {
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

/// `run` にスタック成長窓を添える形。aarch64/arm と同じくフォルト駆動。
fn run_with_growth(
    env: &mut BareEnv,
    entry: u64,
    model: PowerModel,
    stack: Option<StackGrowth>,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_power_growth(env, sys, model, stack),
    )
}

/// `step_power` にスタック成長のフォルト処理を添える。
fn step_power_growth(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: PowerModel,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    match step_power(env, sys, model) {
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
