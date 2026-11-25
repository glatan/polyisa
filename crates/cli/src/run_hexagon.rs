// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hexagon の実行ループと Linux ELF 入口。
//!
//! 1 ステップぶんのパケット進行は `polyisa_guest_hexagon::run::step`
//! （guest 側。bare テストが直接確かめる）で、ここは繰り返しの
//! 駆動・モデル解決・ELF 像の配置・初期スタック構築の窓口。
//!
//! Linux ABI（段階22 HX11）: ELFCLASS32・ELFDATA2LSB・
//! EM_HEXAGON(164)。`trap0(#1)` が syscall 発行点で、OS
//! パーソナリティは `polyisa_os_linux::hexagon::sys::Linux`。
//! 初期 SP は r29（`pt_psp`）。PT_INTERP の動的ローダは
//! `kernel-asm/elf.h` の `ELF_ET_DYN_BASE`（0x0800_0000）を
//! 置き場に ET_DYN 像として読み、その入口から始める。
//! Ref: SPEC-HEXAGON-PRM (V79) Section 10,
//! SRC-LINUX-HEXAGON-UAPI — kernel-asm/elf.h.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct HexagonModel {
    /// `packet::expand`・`decode_model_ex` に渡す機能ビット。
    pub feats: u128,
}

impl HexagonModel {
    /// `--cpu` で解決した `CpuSel` から作る。
    #[must_use]
    pub fn new(feats: u128) -> Self {
        Self { feats }
    }
}

/// `entry`（パケット先頭アドレス）から実行する。
/// `sys` は OS パーソナリティ。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: HexagonModel,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| polyisa_guest_hexagon::run::step(env, sys, model.feats),
    )
}

/// `run` の lazymap 窓付き。`growth` の `[lo, hi)` 内の未写像
/// アクセスはページを遅延割付する（スタック・ヒープ近似）。
/// Gap: GAP-0073
fn run_growth(
    env: &mut BareEnv,
    entry: u64,
    model: HexagonModel,
    sys: &mut impl TrapHandler,
    growth: polyisa_guest_hexagon::run::Growth,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| polyisa_guest_hexagon::run::step_growth(env, sys, model.feats, growth),
    )
}

/// Hexagon Linux ELF（EM_HEXAGON=164・ELFCLASS32・LE）を実行する。
pub fn run_elf_hexagon_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    root: Option<&str>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::hexagon::sys::Linux::new();
    run_elf_hexagon_impl(path, argv, sel, &mut sys, root)
}

/// `run_elf_hexagon_root` に `sys` を注入する形。
/// 標準入出力の捕獲（`sys.io`）とゲストルートのテストに使う。
pub fn run_elf_hexagon_sys_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::hexagon::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    run_elf_hexagon_impl(path, argv, sel, sys, root)
}

#[allow(clippy::too_many_lines)]
fn run_elf_hexagon_impl(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::hexagon::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
    use polyisa_sem::Backend as _;

    let host_elf = match root {
        Some(root) => polyisa_os_linux::guest_path::resolve_guest_path_links(root, "/", path)
            .ok_or_else(|| format!("{path}: ゲストルートの外を指す"))?,
        None => path.to_string(),
    };
    let bytes = std::fs::read(&host_elf).map_err(|e| format!("read {path}: {e}"))?;
    if *bytes.get(5).unwrap_or(&0) != 1 {
        return Err("hexagon はリトルエンディアンのみ".to_string());
    }
    // EM_HEXAGON=164（EM_QDSP6 の別名）。Ref: SRC-LINUX-HEXAGON-UAPI
    // — kernel-asm/elf.h elf_check_arch.
    const EM_HEXAGON: u16 = 164;
    let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    if ehdr.machine != EM_HEXAGON {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let (file_type, ehdr_entry, phoff, phnum) =
        (ehdr.file_type, ehdr.entry, ehdr.phoff, ehdr.phnum);
    // モデルは `--cpu` があれば従い、なければ v73（配布物の
    // e_flags=0x73 が要求する版。generic=v5 系では musl が使う
    // 新しめの形を踏む）。
    let default_sel;
    let sel = match sel {
        Some(s) => s,
        None => {
            default_sel = polyisa_isadl::select::resolve(
                polyisa_guest_hexagon::MODEL_DEFS,
                polyisa_guest_hexagon::FEATURE_DEFS,
                polyisa_guest_hexagon::FEAT_BITS,
                "v73",
                &[],
                &[],
            )
            .map_err(|e| format!("hexagon: {e}"))?;
            &default_sel
        }
    };
    let model = HexagonModel { feats: sel.feats };
    sys.exe_path = path.to_string();
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_hexagon::CpuState>());
    env.backend.addr_mask = 0xffff_ffff;
    const ET_DYN: u16 = 3;
    let segs_vaddr_min = phdrs
        .iter()
        .filter(|s| s.seg_type == 1)
        .map(|s| s.vaddr & !(PAGE_SIZE - 1))
        .min()
        .unwrap_or(0);
    let image_end = phdrs
        .iter()
        .filter(|s| s.seg_type == 1)
        .map(|s| s.vaddr + s.memsz)
        .max()
        .unwrap_or(0);
    let main_bias = if file_type == ET_DYN {
        0x0001_0000u64.wrapping_sub(segs_vaddr_min)
    } else {
        0
    };
    let image_end = image_end.wrapping_add(main_bias);
    polyisa_loader::elf::load_segments_bias(&bytes, &phdrs, &mut env.backend.mem, main_bias)
        .map_err(|e| format!("load: {e:?}"))?;
    // PT_INTERP の動的ローダを像として読み、その入口から始める。
    let interp_path = polyisa_loader::elf::parse_interp(&bytes, &phdrs);
    if let Some(r) = root {
        sys.set_guest_root(r);
    } else if interp_path.is_some() {
        return Err("PT_INTERP のある ELF には --root が必要".to_string());
    }
    // kernel-asm/elf.h の ELF_ET_DYN_BASE。PT_INTERP の ET_DYN 像は
    // ここを底にずらして置く。
    const INTERP_BASE: u64 = 0x0800_0000;
    let (run_entry, interp_bias) = if let Some(gpath) = interp_path {
        let host =
            polyisa_os_linux::guest_path::resolve_guest_path(root.unwrap_or(""), "/", &gpath)
                .ok_or_else(|| format!("interp {gpath} が root 外を指す"))?;
        let ibytes = std::fs::read(&host).map_err(|e| format!("read interp {host}: {e}"))?;
        if *ibytes.get(5).unwrap_or(&0) != 1 {
            return Err(format!("interp {host} はリトルエンディアンではない"));
        }
        let iehdr = polyisa_loader::elf::parse_ehdr32(&ibytes)
            .map_err(|e| format!("interp ehdr: {e:?}"))?;
        if iehdr.machine != EM_HEXAGON {
            return Err(format!("interp {host} は Hexagon の ELF ではない"));
        }
        let iphdrs = polyisa_loader::elf::parse_phdrs32(&ibytes, &iehdr)
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
        (ibias.wrapping_add(iehdr.entry), ibias)
    } else {
        (main_bias.wrapping_add(ehdr_entry), 0)
    };
    let phdr_addr = {
        let found = phdrs
            .iter()
            .find(|s| s.seg_type == 1 && s.offset <= phoff && phoff < s.offset + s.filesz)
            .map(|s| {
                main_bias
                    .wrapping_add(s.vaddr)
                    .wrapping_add(phoff - s.offset)
            });
        match found {
            Some(a) => a,
            None => {
                let at = main_bias
                    .wrapping_add(segs_vaddr_min)
                    .checked_sub(PAGE_SIZE)
                    .ok_or_else(|| "phdr 表の置き場がない".to_string())?;
                let lo = phoff as usize;
                let hi = lo + phnum as usize * 32;
                env.backend
                    .mem
                    .map(VirtAddr(at), 1, Perms::RW)
                    .map_err(|_| "phdr 表の写像に失敗".to_string())?;
                env.backend
                    .mem
                    .write(VirtAddr(at), &bytes[lo..hi])
                    .map_err(|_| "phdr 表の書き込みに失敗".to_string())?;
                at
            }
        }
    };
    let entry_main = main_bias.wrapping_add(ehdr_entry);
    let top = 0x7fff_f000u64;
    let img_top = top - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // auxv。hexagon の ELF_HWCAP は 0（kernel-asm/elf.h）。
    let mut auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),        // AT_PHDR
        (4, 32),               // AT_PHENT
        (5, u64::from(phnum)), // AT_PHNUM
        (6, 0x1000),           // AT_PAGESZ
        (8, 0),                // AT_FLAGS
        (9, entry_main),       // AT_ENTRY
        (11, 0),               // AT_UID
        (12, 0),               // AT_EUID
        (13, 0),               // AT_GID
        (14, 0),               // AT_EGID
        (16, 0),               // AT_HWCAP
        (17, 100),             // AT_CLKTCK
        (23, 0),               // AT_SECURE
    ];
    if interp_bias != 0 {
        auxv.push((7, interp_bias)); // AT_BASE
    }
    let envv: Vec<Vec<u8>> = std::env::var("POLYISA_HEXAGON_ENV")
        .map(|s| s.split(':').map(|e| e.as_bytes().to_vec()).collect())
        .unwrap_or_default();
    let (img, sp) = polyisa_os_linux::build_initial_stack32_endian(
        img_top,
        &arg_bytes,
        &envv,
        &auxv,
        polyisa_mem::Endian::Le,
    );
    let stack_base = sp & !(PAGE_SIZE - 1);
    let stack_pages = (top - stack_base) / PAGE_SIZE;
    env.backend
        .mem
        .map(VirtAddr(stack_base), stack_pages, Perms::RW)
        .map_err(|e| format!("stack map: {e:?}"))?;
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|e| format!("stack write: {e:?}"))?;
    // Hexagon ABI の初期 SP は r29（`pt_psp`）。
    // Ref: SRC-LINUX-HEXAGON-UAPI — kernel-asm/elf.h.
    env.backend
        .set(polyisa_guest_hexagon::sem::r_ref(29), sp as u32);
    sys.init_brk(image_end);
    sys.set_stack_window(top - 0x200_0000, top);
    let outcome = run_growth(
        &mut env,
        run_entry,
        model,
        sys,
        polyisa_guest_hexagon::run::Growth {
            lo: image_end & !(PAGE_SIZE - 1),
            hi: top,
        },
    );
    match outcome {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("未実装: pc={pc:#x} word={word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("実行予算を使い切った: pc={pc:#x}")),
        Outcome::Deadlock => Err("デッドロック".to_string()),
        Outcome::Breakpoint { pc } => Err(format!("ブレークポイント: pc={pc:#x}")),
    }
}
