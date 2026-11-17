// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390/zArchitecture（s390x）のフェッチから次のフェッチまで。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する（Power 試作と同じ構造）。
//! syscall の処理は `os-linux` の `s390::sys::Linux` に委譲する。
//!
//! 命令は可変長 16/32/48 ビットで、先頭バイトの上位 2 ビットが長さを
//! 決める（00→2B、01/10→4B、11→6B）。`svc`（主オペコード 0x0a）で
//! `TrapHandler` へ委譲し、Handled なら pc を命令長分進める。
//! データ・命令ともにビッグエンディアン固定。スタックポインタは r15。
//! Ref: SPEC-S390-ZARCH-POP (SA22-7832-13), SPEC-S390-ABI.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_s390::sem::{self, Gpr};
use polyisa_guest_s390::{Insn, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind, GuestException};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct S390Model {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
}

impl S390Model {
    /// z/Architecture（s390x）の既定モデル。
    #[must_use]
    pub const fn s390x() -> Self {
        Self { feats: 0 }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(env: &mut BareEnv, entry: u64, model: S390Model, sys: &mut impl TrapHandler) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_s390_growth(env, sys, model, None),
    )
}

/// `svc` のトラップ委譲。`TrapOutcome` を `Outcome` へ写す。
fn svc<H: ?Sized + TrapHandler>(
    env: &mut BareEnv,
    sys: &mut H,
    pc: u64,
    len: u64,
    word: u64,
) -> Result<(), Outcome> {
    if std::env::var_os("POLYISA_S390_TRACE_SVC").is_some() {
        let mut rs = [0u64; 8];
        for (i, r) in rs.iter_mut().enumerate() {
            *r = env.backend.get(Gpr(i as u8).state());
        }
        eprintln!("svc@{pc:#x} n={} args={:x?}", rs[1], &rs[2..8]);
        // write(2)/read(3) のバッファ先頭をダンプする。
        if rs[1] == 4 && rs[4] > 0 && rs[4] <= 4096 {
            let mut buf = vec![0u8; rs[4].min(64) as usize];
            let _ = env.backend.mem.read(
                VirtAddr(rs[3]),
                &mut buf,
                Access {
                    endian: Endian::Be,
                    align: Align::Natural,
                    kind: AccessKind::DataRead,
                },
            );
            eprintln!("  buf@{:#x}={buf:02x?}", rs[3]);
        }
    }
    match sys.handle_trap(env, (word & 0xff) as u32) {
        TrapOutcome::Handled => {
            env.pc += len;
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

/// EX/EXRL: 対象命令を（r1 の下位バイトで修飾して）1 回だけ実行する。
/// PoP: r1!=0 のとき対象命令の第 2 バイトに r1 の下位バイトを OR する
/// が、メモリ上の命令語は書き換えない。EX 系の入れ子は execute 例外。
/// 相対アドレスは対象命令自身の位置で評価する（QEMU と同じ扱い）。
// Ref: SPEC-S390-ZARCH-POP — EXECUTE。
#[allow(clippy::too_many_arguments)]
fn step_ex(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: S390Model,
    pc: u64,
    len: u64,
    word: u64,
    insn: Insn,
) -> Result<(), Outcome> {
    let unimpl = |env: &BareEnv, word: u64| Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    };
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let amask = env.backend.get(sem::amask_ref());
    // 対象アドレスと修飾レジスタ（sem::execute_target で共用）。
    let mut regs = [0u64; 16];
    for (i, v) in regs.iter_mut().enumerate() {
        *v = env.backend.get(Gpr(i as u8).state());
    }
    let (taddr, r1) = sem::execute_target(insn, word, pc, |i| regs[i as usize], amask);
    if taddr & 1 != 0 {
        return Err(unimpl(env, word));
    }
    // 修飾バイト（r1=0 なら修飾なし）。
    let modifier = if r1 == 0 {
        0
    } else {
        (regs[r1 as usize] & 0xff) as u8
    };
    // 対象命令をフェッチ。
    let mut b0 = [0u8; 1];
    if env.backend.mem.read(VirtAddr(taddr), &mut b0, acc).is_err() {
        return Err(unimpl(env, word));
    }
    let tlen: u64 = match b0[0] >> 6 {
        0 => 2,
        1 | 2 => 4,
        _ => 6,
    };
    let mut tbytes = [0u8; 6];
    tbytes[0] = b0[0];
    if env
        .backend
        .mem
        .read(VirtAddr(taddr + 1), &mut tbytes[1..tlen as usize], acc)
        .is_err()
    {
        return Err(unimpl(env, u64::from(b0[0])));
    }
    let mut tword = 0u64;
    for &x in &tbytes[..tlen as usize] {
        tword = (tword << 8) | u64::from(x);
    }
    // 第 2 バイトへ修飾（メモリ上の命令は書き換えない）。
    tword = sem::resolve_execute(tword, tlen as u8, modifier);
    let tbits = (tlen * 8) as u32;
    let Some(tinsn) = decode_model_ex(u128::from(tword), tbits, true, model.feats) else {
        return Err(unimpl(env, tword));
    };
    // EX の入れ子は execute 例外。
    if tinsn == Insn::Ex || tinsn == Insn::Exrl {
        return Err(unimpl(env, tword));
    }
    if tinsn == Insn::Svc {
        return svc(env, sys, pc, len, tword);
    }
    LAST_EXC.with(|c| c.set(None));
    match env.step(|b| sem::exec(b, tinsn, tword, taddr)) {
        Ok(()) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
                env.pc += len;
            }
            Ok(())
        }
        Err(InterpExit::Exception(e)) => {
            LAST_EXC.with(|c| c.set(Some(e)));
            Err(unimpl(env, tword))
        }
        Err(InterpExit::Unimplemented(_)) => Err(unimpl(env, tword)),
    }
}

/// 1 命令ぶんのフェッチ・解読・意味論と `svc` 境界の解決。
// Ref: SPEC-S390-ZARCH-POP (SA22-7832-13).
fn step_s390(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: S390Model,
) -> Result<(), Outcome> {
    let pc = env.pc;
    let unimpl = |env: &BareEnv, word: u64| Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    };
    // 命令は偶数アドレスに整列する。
    if pc & 1 != 0 {
        return Err(unimpl(env, 0));
    }
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b0 = [0u8; 1];
    if env.backend.mem.read(VirtAddr(pc), &mut b0, acc).is_err() {
        return Err(unimpl(env, 0));
    }
    // 先頭バイトの上位 2 ビットが命令長を決める。
    let len: u64 = match b0[0] >> 6 {
        0 => 2,
        1 | 2 => 4,
        _ => 6,
    };
    let mut bytes = [0u8; 6];
    bytes[0] = b0[0];
    if env
        .backend
        .mem
        .read(VirtAddr(pc + 1), &mut bytes[1..len as usize], acc)
        .is_err()
    {
        return Err(unimpl(env, u64::from(b0[0])));
    }
    // 意味論のフィールド規約に合わせ右詰め u64 に畳む。
    let mut word = 0u64;
    for &x in &bytes[..len as usize] {
        word = (word << 8) | u64::from(x);
    }
    let bits = (len * 8) as u32;
    let Some(insn) = decode_model_ex(u128::from(word), bits, true, model.feats) else {
        return Err(unimpl(env, word));
    };
    if insn == Insn::Svc {
        return svc(env, sys, pc, len, word);
    }
    if insn == Insn::Ex || insn == Insn::Exrl {
        return step_ex(env, sys, model, pc, len, word, insn);
    }
    if std::env::var_os("POLYISA_S390_TRACE_INSN").is_some() {
        eprintln!("insn@{pc:#x}={insn:?} {word:#x}");
    }
    LAST_EXC.with(|c| c.set(None));
    match env.step(|b| sem::exec(b, insn, word, pc)) {
        Ok(()) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
                env.pc += len;
            }
            if let Some(v) = std::env::var_os("POLYISA_S390_DUMP_AT") {
                let hit = v
                    .to_string_lossy()
                    .split(',')
                    .filter_map(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
                    .any(|a| a == pc);
                if hit {
                    use polyisa_guest_s390::sem::Fpr;
                    eprintln!("dump@{pc:#x} cc={}", env.backend.get(sem::cc_ref()));
                    for i in 0..16u8 {
                        eprint!(" r{i}={:#x}", env.backend.get(Gpr(i).state()));
                    }
                    eprintln!();
                    for i in 0..16u8 {
                        eprint!(" f{i}={:#x}", env.backend.get(Fpr(i).state()));
                    }
                    eprintln!();
                }
            }
            Ok(())
        }
        Err(InterpExit::Exception(e)) => {
            if std::env::var_os("POLYISA_S390_TRACE").is_some() {
                eprintln!("exc {:?} addr={:?} pc={pc:#x}", e.kind, e.addr);
                if let Some(a) = e.addr {
                    use polyisa_mem::PageNo;
                    eprintln!("  mapped={}", env.backend.mem.is_mapped(PageNo(a / 0x1000)));
                }
                for i in 0..16u8 {
                    let r: u64 = env.backend.get(Gpr(i).state());
                    eprintln!("  r{i}={r:#x}");
                }
            }
            LAST_EXC.with(|c| c.set(Some(e)));
            Err(unimpl(env, word))
        }
        Err(InterpExit::Unimplemented(_)) => Err(unimpl(env, word)),
    }
}

thread_local! {
    static LAST_EXC: std::cell::Cell<Option<GuestException>> =
        const { std::cell::Cell::new(None) };
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

/// `run` にスタック成長窓を添える形。
fn run_with_growth(
    env: &mut BareEnv,
    entry: u64,
    model: S390Model,
    stack: Option<StackGrowth>,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_s390_growth(env, sys, model, stack),
    )
}

/// `step_s390` にスタック成長のフォルト処理を添える。
fn step_s390_growth(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: S390Model,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    match step_s390(env, sys, model) {
        Err(Outcome::Unimplemented { pc, word }) => {
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

/// ページフォルトをスタック成長として処理する。
// Ref: SRC-LINUX (7.3) — expand_stack。
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

/// s390x の ELF を実行する。機械番号 22（EM_S390）。
/// `sys` は `os_linux::s390::sys::Linux` が処理する（未実装は ENOSYS）。
/// Ref: SPEC-S390-ABI, SRC-LINUX (7.3).
pub fn run_elf_s390(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_s390_sel(path, argv, None)
}

/// `run_elf_s390` に CPU モデルの選択を渡す（`--cpu` の配線）。
pub fn run_elf_s390_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::s390::sys::Linux::default();
    run_elf_s390_impl(path, argv, sel, &mut sys, None)
}

/// `run_elf_s390_sel` にゲストルートを渡す形（`--root` の配線）。
pub fn run_elf_s390_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    root: Option<&str>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::s390::sys::Linux::default();
    run_elf_s390_impl(path, argv, sel, &mut sys, root)
}

/// `run_elf_s390_sel` に OS パーソナリティを差し込む形。
/// テストが syscall の結果（`sys.io` 等）を検査する用途に使う。
pub fn run_elf_s390_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::s390::sys::Linux,
) -> Result<u64, String> {
    run_elf_s390_impl(path, argv, sel, sys, None)
}

/// `run_elf_s390_sys` にゲストルートを添える形。
pub fn run_elf_s390_sys_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::s390::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    run_elf_s390_impl(path, argv, sel, sys, root)
}

/// `run_elf_s390_sys` にゲストルートを添えた実体。
fn run_elf_s390_impl(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::s390::sys::Linux,
    root: Option<&str>,
) -> Result<u64, String> {
    use polyisa_mem::{PAGE_SIZE, Perms};

    let host_elf = match root {
        Some(root) => polyisa_os_linux::guest_path::resolve_guest_path_links(root, "/", path)
            .ok_or_else(|| format!("{path}: ゲストルートの外を指す"))?,
        None => path.to_string(),
    };
    let bytes = std::fs::read(&host_elf).map_err(|e| format!("read {path}: {e}"))?;
    if !matches!(bytes.get(4), Some(2)) {
        return Err("s390x は ELFCLASS64 のみ対応".to_string());
    }
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_S390=22。Ref: SPEC-S390-ABI。
    const EM_S390: u16 = 22;
    if ehdr.machine != EM_S390 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    if ehdr.little {
        return Err("s390x はビッグエンディアンのみ対応".to_string());
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let interp_path = polyisa_loader::elf::parse_interp(&bytes, &phdrs);
    if let Some(r) = root {
        sys.set_root(r, "/");
    } else if interp_path.is_some() {
        return Err("PT_INTERP のある ELF には --root が必要".to_string());
    }
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_s390::CpuState>());
    // 64 ビットモードの有効アドレスマスク（CpuState::default と同じ）。
    env.backend
        .set(polyisa_guest_s390::sem::amask_ref(), u64::MAX);
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
    // s390 Linux は 0 番地にゼロページを写像する。`mvcle`/`mvcl` 系の
    // 埋めバイト読み（memset が `mvcle …,0` を使う）がこれに依存する。
    // Ref: SRC-LINUX (7.3) — CONFIG mmap_min_addr=0 / s390 の慣習。
    let _ = env.backend.mem.map(VirtAddr(0), 1, Perms::R);
    // AT_PHDR。
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
        if iehdr.machine != EM_S390 {
            return Err(format!("interp {host} は s390x の ELF ではない"));
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
    // 初期スタック。r15 がスタックポインタ。
    let top = 0x0000_7fff_fff0_0000u64;
    const STACK_LIMIT: u64 = 8 << 20;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let img_top = top - 0x1_0000;
    let rand_addr = top - 16;
    let mut auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),              // AT_PHDR
        (4, 56),                     // AT_PHENT
        (5, u64::from(ehdr.phnum)),  // AT_PHNUM
        (6, 0x1000),                 // AT_PAGESZ
        (8, 0),                      // AT_FLAGS
        (9, main_bias + ehdr.entry), // AT_ENTRY
        (11, 0),                     // AT_UID
        (12, 0),                     // AT_EUID
        (13, 0),                     // AT_GID
        (14, 0),                     // AT_EGID
        (17, 100),                   // AT_CLKTCK
        (23, 0),                     // AT_SECURE
        (25, rand_addr),             // AT_RANDOM
    ];
    if interp_bias != 0 {
        auxv.push((7, interp_bias)); // AT_BASE
    }
    let (img, sp) =
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &[], &auxv, Endian::Be);
    let stack_base = sp & !(PAGE_SIZE - 1);
    let stack_pages = (top - stack_base) / PAGE_SIZE;
    if std::env::var_os("POLYISA_S390_TRACE").is_some() {
        eprintln!("stack: base={stack_base:#x} top={top:#x} sp={sp:#x}");
    }
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
        .write(VirtAddr(rand_addr), b"polyisa-s390x!!!")
        .map_err(|e| format!("stack write: {e:?}"))?;
    // r15 = sp。z/Architecture のスタックポインタ。
    // Ref: SPEC-S390-ABI §register conventions。
    env.backend.set(Gpr(15).state(), sp);
    sys.exe_path = path.to_string();
    sys.init_brk(image_end);
    let feats = sel.map_or(0, |s| s.feats);
    let model = S390Model { feats };
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
