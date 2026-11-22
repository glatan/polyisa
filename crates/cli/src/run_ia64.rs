// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IA-64（Itanium）の実行ループ。
//!
//! 1 ステップぶんのバンドル進行は `polyisa_guest_ia64::run::step`
//! （guest 側。bare テストが直接確かめる）で、ここは繰り返しの
//! 駆動とモデル解決の窓口。ELF の入口は IA11 が足す。
//! Ref: SPEC-IA64-SDM (Rev 2.3).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct Ia64Model {
    /// `bundle::decode_slot` に渡す機能ビット。
    pub feats: u128,
}

impl Ia64Model {
    /// `--cpu` で解決した `CpuSel` から作る。
    #[must_use]
    pub fn new(feats: u128) -> Self {
        Self { feats }
    }
}

/// `entry`（ip = バンドルアドレス|スロット番号）から実行する。
/// `sys` は OS パーソナリティ。
pub fn run(env: &mut BareEnv, entry: u64, model: Ia64Model, sys: &mut impl TrapHandler) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| polyisa_guest_ia64::run::step(env, sys, model.feats),
    )
}

/// `Outcome` を実行結果へ写す。
fn finish(o: Outcome) -> Result<u64, String> {
    match o {
        Outcome::Exit(code) => Ok(code),
        Outcome::StepLimit { pc } => Err(format!("ステップ数を超過（pc={pc:#x}）")),
        Outcome::Deadlock => Err("デッドロック".to_string()),
        Outcome::Unimplemented { pc, word } => Err(format!("未実装: pc={pc:#x} word={word:#x}")),
    }
}

/// Linux ELF64（EM_IA_64）を実行する。
pub fn run_elf_ia64(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_ia64_sel(path, argv, None)
}

/// `--cpu` で解決した `CpuSel` を受け取る形。
pub fn run_elf_ia64_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    run_elf_ia64_sys(
        path,
        argv,
        sel,
        &mut polyisa_os_linux::ia64::sys::Linux::new(),
    )
}

/// 標準出力を集めたいテスト用（戻り値は終了コードと stdout）。
pub fn run_elf_ia64_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    run_elf_ia64_captured_in(path, argv, &[])
}

/// `run_elf_ia64_captured` に標準入力を添える。
/// 標準エラーを検査するときは `run_elf_ia64_sys` で `sys.io.stderr`
/// を読む。
pub fn run_elf_ia64_captured_in(
    path: &str,
    argv: &[String],
    input: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let mut sys = polyisa_os_linux::ia64::sys::Linux::new();
    sys.stdin_buf = input.to_vec();
    let code = run_elf_ia64_sys(path, argv, None, &mut sys)?;
    Ok((code, sys.io.stdout))
}

/// `run_elf_ia64` に OS パーソナリティを差し込む形。
pub fn run_elf_ia64_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::ia64::sys::Linux,
) -> Result<u64, String> {
    let (mut env, entry, model, image_end) = setup_ia64_elf(path, argv, sel)?;
    sys.init_brk(image_end);
    // /proc/self/exe の readlink は絶対パスを返す規約。
    sys.exe_path = std::fs::canonicalize(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.to_string());
    finish(run(&mut env, entry, model, sys))
}

/// ユーザスタックの上端（TASK_SIZE = RGN 5 の先頭）。
/// ゲート領域（`gate::ADDR`）はこの上に別ページとして存在する。
// Ref: SRC-LINUX-66 — kernel-asm/processor.h（TASK_SIZE）。
const STACK_TOP: u64 = 0xa000_0000_0000_0000;
/// スタックと RBS が共有する窓（DEFAULT_USER_STACK_SIZE 相当の
/// 8 MiB）。RBS の基底は窓の下端、メモリスタックは窓の上端から
/// 下向きに伸びる。
// Ref: SRC-LINUX-66 — kernel-asm/processor.h（rbs_bot の初期化）。
const STACK_WINDOW: u64 = 8 << 20;
/// RSE のバッキングストア基底（`rbs_bot`）。窓の下端。
const RBS_BOT: u64 = STACK_TOP - STACK_WINDOW;

/// ELF の検証・写像・初期スタックとレジスタ状態の構築。
/// 返り値は `(env, entry, model, image_end)`。
fn setup_ia64_elf(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<(BareEnv, u64, Ia64Model, u64), String> {
    use polyisa_guest_ia64::CpuState;
    use polyisa_mem::{PAGE_SIZE, Perms, VirtAddr};
    use polyisa_os_linux::ia64::{at, gate};
    use polyisa_sem::{Backend as _, StateRef, W64};

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_IA_64=50。Ref: SRC-LINUX-66 — kernel-asm/elf.h
    // (elf_check_arch は EM_IA_64)。
    if ehdr.machine != 50 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    if !ehdr.little {
        return Err("IA-64 はリトルエンディアンのみ対応".to_string());
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("PT_INTERP のある IA-64 ELF は未対応（静的のみ）".to_string());
    }
    // `--cpu` 省略時は itanium2（Itanium 2 以降の命令集合）。
    let default_sel;
    let sel = match sel {
        Some(s) => s,
        None => {
            default_sel = polyisa_isadl::select::resolve(
                polyisa_guest_ia64::MODEL_DEFS,
                polyisa_guest_ia64::FEATURE_DEFS,
                polyisa_guest_ia64::FEAT_BITS,
                "itanium2",
                &[],
                &[],
            )
            .map_err(|e| format!("ia64: {e}"))?;
            &default_sel
        }
    };
    let model = Ia64Model::new(sel.feats);
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    // ET_DYN は TASK_UNMAPPED_BASE + ELF_ET_DYN_BASE 相当へ寄せる。
    // Ref: SRC-LINUX-66 — kernel-asm/elf.h（ELF_ET_DYN_BASE）。
    const ET_DYN: u16 = 3;
    let main_bias = if ehdr.file_type == ET_DYN {
        const ELF_ET_DYN_BASE: u64 = 0x2000_0000_0000_0000 + 0x8_0000_0000;
        let min_vaddr = phdrs
            .iter()
            .filter(|p| p.seg_type == 1)
            .map(|p| p.vaddr & !(PAGE_SIZE - 1))
            .min()
            .unwrap_or(0);
        ELF_ET_DYN_BASE - min_vaddr
    } else {
        0
    };
    polyisa_loader::elf::load_segments_bias(&bytes, &phdrs, &mut env.backend.mem, main_bias)
        .map_err(|e| format!("load: {e:?}"))?;
    // 主像の phdr 表のゲスト内番地（AT_PHDR）。表は先頭の PT_LOAD が
    // 覆うのが普通で、覆っていなければ像の直前に1ページ置く。
    let phdr_addr = match phdrs
        .iter()
        .find(|p| p.seg_type == 1 && p.offset <= ehdr.phoff && ehdr.phoff < p.offset + p.filesz)
    {
        Some(p) => main_bias + p.vaddr + (ehdr.phoff - p.offset),
        None => {
            let min_vaddr = phdrs
                .iter()
                .filter(|p| p.seg_type == 1)
                .map(|p| p.vaddr & !(PAGE_SIZE - 1))
                .min()
                .unwrap_or(0);
            let at = (main_bias + min_vaddr)
                .checked_sub(PAGE_SIZE)
                .ok_or_else(|| "phdr 表の置き場がない".to_string())?;
            const PHENT: u64 = 56;
            let lo = ehdr.phoff as usize;
            let hi = lo + ehdr.phnum as usize * PHENT as usize;
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
    };
    let image_end = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr + p.memsz)
        .max()
        .unwrap_or(0)
        + main_bias;
    let entry = main_bias + ehdr.entry;

    // ゲート領域（EHDR ページ + via_break/via_epc の実バンドル）。
    polyisa_os_linux::ia64::sys::install_gate_page(&mut env)?;
    // AT_SYSINFO_EHDR が指すページに、解析しても壊れない最小の
    // ELF64 ヘッダを置く（glibc は静的実行でも dl_sysinfo_dso を
    // 覚える。シンボル経由の解決は行わないので phnum=0 でよい）。
    write_gate_ehdr(&mut env)?;

    // スタック＋RBS の共有窓。窓の上端から初期スタック像を、
    // 下端から RSE のバッキングストアを置く（両者は同じ
    // DEFAULT_USER_STACK_SIZE の窓を分け合う正本の配置）。
    let stack_lo = STACK_TOP - STACK_WINDOW;
    env.backend
        .mem
        .map(VirtAddr(stack_lo), STACK_WINDOW / PAGE_SIZE, Perms::RW)
        .map_err(|_| "スタック窓の写像に失敗".to_string())?;
    // 初期スタック像は窓の上端いっぱいに置く（sp は argc を指す）。
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),                       // AT_PHDR
        (4, 56),                              // AT_PHENT
        (5, u64::from(ehdr.phnum)),           // AT_PHNUM
        (6, PAGE_SIZE),                       // AT_PAGESZ
        (9, entry),                           // AT_ENTRY
        (11, 0),                              // AT_UID
        (12, 0),                              // AT_EUID
        (13, 0),                              // AT_GID
        (14, 0),                              // AT_EGID
        (16, 0),                              // AT_HWCAP（ELF_HWCAP=0）
        (17, 1024),                           // AT_CLKTCK（HZ）
        (23, 0),                              // AT_SECURE
        (at::SYSINFO, gate::SYSCALL_VIA_EPC), // AT_SYSINFO
        (at::SYSINFO_EHDR, gate::ADDR),       // AT_SYSINFO_EHDR
    ];
    let (img, sp) = polyisa_os_linux::build_initial_stack(STACK_TOP, &arg_bytes, &[], &auxv);
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|_| "スタックの書き込みに失敗".to_string())?;

    // start_thread の初期状態。
    // Ref: SRC-LINUX-66 — kernel-asm/processor.h（start_thread）。
    use polyisa_guest_ia64::sem;
    let b = &mut env.backend;
    // r12 = 新しい SP − 16（16 バイトのスクラッチ域）。
    sem::gr_set(b, 12, sp.wrapping_sub(16));
    // r8 = rtld_fini（動的ローダの終了関数ディスクリプタ）。
    // 静的リンクでは動的ローダが無いので 0（NULL）。
    sem::gr_set(b, 8, 0);
    let set_ar = |b: &mut polyisa_engine::interp::InterpBackend, off: usize, v: u64| {
        b.set(StateRef::<W64>::from_offset(off), v);
    };
    // ar.bsp = ar.bspstore = rbs_bot（バッキングストア基底）。
    set_ar(b, core::mem::offset_of!(CpuState, bsp), RBS_BOT);
    set_ar(b, core::mem::offset_of!(CpuState, bspstore), RBS_BOT);
    // ar.rsc = 0xf（eager モード・特権レベル 3）、ar.rnat = 0。
    set_ar(b, core::mem::offset_of!(CpuState, rsc), 0xf);
    set_ar(b, core::mem::offset_of!(CpuState, rnat), 0);
    // ar.fpsr = FPSR_DEFAULT。
    set_ar(
        b,
        core::mem::offset_of!(CpuState, fpsr),
        0x0009_804c_0270_033f,
    );
    Ok((env, entry, model, image_end))
}

/// ゲートの EHDR ページに最小限の ELF64 ヘッダを書く。
/// e_type=ET_DYN・e_machine=EM_IA_64・e_phnum=0（glibc の
/// sysinfo_dso 走査がこのヘッダだけを読む想定）。
fn write_gate_ehdr(env: &mut BareEnv) -> Result<(), String> {
    use polyisa_mem::{Perms, VirtAddr};
    use polyisa_os_linux::ia64::gate;

    // EHDR ページは読み取り専用で写像済みなので、一時的に書き込み
    // 可能にしてから元へ戻す。
    env.backend
        .mem
        .protect(VirtAddr(gate::ADDR), 1, Perms::RW)
        .map_err(|_| "ゲート EHDR の保護解除に失敗".to_string())?;
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    h[4] = 2; // ELFCLASS64
    h[5] = 1; // ELFDATA2LSB
    h[6] = 1; // EV_CURRENT
    h[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    h[18..20].copy_from_slice(&50u16.to_le_bytes()); // EM_IA_64
    h[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    h[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    h[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    h[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    env.backend
        .mem
        .write(VirtAddr(gate::ADDR), &h)
        .map_err(|_| "ゲート EHDR の書き込みに失敗".to_string())?;
    env.backend
        .mem
        .protect(VirtAddr(gate::ADDR), 1, Perms::R)
        .map_err(|_| "ゲート EHDR の保護復帰に失敗".to_string())
}
