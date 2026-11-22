// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! OpenRISC（OR1K・32 ビット）のフェッチから次のフェッチまで。
//!
//! 命令は固定 32 ビット・ビッグエンディアン。CPUCFGR[ND]=0 の
//! 構成（既定・`dslot` 機能）では制御転送に 1 命令の遅延スロット
//! が伴い、ここが `pending` で織り込む。`l.sys` は例外ベクタ
//! 0xc00 の Trap を上げ、OS パーソナリティが拾う。
//! 遅延スロット中の制御転送（DCTI 連鎖）は仕様上不定として
//! 明示に止める（Gap）。
//! Ref: SPEC-OPENRISC-1000 §5.3, §6, §16.4（CPUCFGR[ND]）.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_openrisc::{decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// ページフォルト駆動の lazymap 窓（ヒープ全域 + スタック）。
/// 実カーネルのヒープ VMA は [elf_brk, brk) をデマンドページする。
/// musl ldso は brk 発行前に elf 画像直後のページを触るため
/// （BIN-DISTRO-OR1K の memset 観測）、[elf 末端, スタック窓) を
/// まとめて遅延割付する近似を採る。
#[derive(Clone, Copy)]
pub struct StackGrowth {
    /// 遅延割付の上限（スタック頂）。
    pub top: u64,
    /// 遅延割付の下限（elf 画像末端のページ。スタック限界も兼ねる）。
    pub limit: u64,
}

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct OpenriscModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
    /// 遅延スロット構成か（CPUCFGR[ND]=0）。
    pub dslot: bool,
}

/// `entry` から `model` で実行する。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: OpenriscModel,
    sys: &mut impl TrapHandler,
    stack: Option<StackGrowth>,
) -> Outcome {
    env.pc = entry;
    // 遅延スロット中に残した制御転送の着地点。
    let mut pending: Option<u64> = None;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_openrisc(env, sys, model, &mut pending, stack),
    )
}

fn fetch32(env: &mut BareEnv, pc: u64) -> Option<u32> {
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b = [0u8; 4];
    env.backend.mem.read(VirtAddr(pc), &mut b, acc).ok()?;
    Some(u32::from_be_bytes(b))
}

fn trap_result(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    t: TrapOutcome,
    word: u64,
    ok: impl FnOnce(&mut BareEnv),
) -> Result<(), Outcome> {
    match t {
        TrapOutcome::Handled => {
            ok(env);
            Ok(())
        }
        TrapOutcome::Exit(code) => {
            let _ = sys;
            Err(Outcome::Exit(u64::from(code)))
        }
        TrapOutcome::Blocked => Err(Outcome::Deadlock),
        TrapOutcome::Unimplemented => Err(Outcome::Unimplemented {
            pc: env.pc,
            word: u128::from(word),
        }),
    }
}

fn unimpl_insn(env: &mut BareEnv, sys: &mut impl TrapHandler, word: u64) -> Result<(), Outcome> {
    let t = sys.handle_trap(env, sem::TRAP_ILL as u32);
    trap_result(env, sys, t, word, |_| {})
}

fn stack_grow(
    env: &mut BareEnv,
    stack: Option<StackGrowth>,
    e: &polyisa_sem::GuestException,
) -> Option<()> {
    let stack = stack?;
    if e.kind != ExceptionKind::PageFault {
        return None;
    }
    let addr = e.addr?;
    if addr < stack.limit || addr >= stack.top {
        return None;
    }
    let page = addr & !0xfff;
    // 既に写像あるページへの違反（PROT_NONE ガード等）は育てない。
    if env
        .backend
        .mem
        .is_mapped(polyisa_mem::PageNo(page / 0x1000))
    {
        return None;
    }
    env.backend.mem.map(VirtAddr(page), 1, Perms::RW).ok()?;
    Some(())
}

/// 1 命令ぶんのフェッチ・解読・意味論と PC の前進。
/// `pending` は遅延スロットの着地点（実行中の命令がスロットなら Some）。
fn step_openrisc(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: OpenriscModel,
    pending: &mut Option<u64>,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let pc = env.pc;
    if pc & 3 != 0 {
        return Err(Outcome::Unimplemented { pc, word: 0 });
    }
    let Some(word) = fetch32(env, pc) else {
        return unimpl_insn(env, sys, 0);
    };
    let Some(insn) = decode_model_ex(u128::from(word), 32, false, model.feats) else {
        return unimpl_insn(env, sys, u64::from(word));
    };
    let r = env.step(|b| sem::exec(b, insn, word, pc, model.dslot));
    // 決定論的時計（TTCR）をステップ毎に進める。
    {
        let c = env.backend.get(sem::ttcr_ref());
        env.backend.set(sem::ttcr_ref(), c.wrapping_add(1));
    }
    let next = match r {
        Ok(taken) => {
            let npc = env.backend.get(sem::npc_ref());
            env.backend.set(sem::ppc_ref(), pc);
            if taken {
                if pending.is_some() {
                    // 遅延スロット内の制御転送は仕様上不定（Gap）。
                    return Err(Outcome::Unimplemented {
                        pc,
                        word: u128::from(word),
                    });
                }
                if model.dslot {
                    *pending = Some(npc);
                    env.backend
                        .set(sem::npc_ref(), pc.wrapping_add(8) & 0xffff_ffff);
                    pc.wrapping_add(4) & 0xffff_ffff
                } else {
                    env.backend.set(sem::npc_ref(), npc);
                    npc
                }
            } else if let Some(t) = pending.take() {
                env.backend
                    .set(sem::npc_ref(), t.wrapping_add(4) & 0xffff_ffff);
                t
            } else {
                env.backend
                    .set(sem::npc_ref(), pc.wrapping_add(4) & 0xffff_ffff);
                pc.wrapping_add(4) & 0xffff_ffff
            }
        }
        Err(InterpExit::Exception(e)) => {
            if stack_grow(env, stack, &e).is_some() {
                return Ok(());
            }
            if e.kind == ExceptionKind::Trap {
                // l.sys/l.trap の発行点。戻り番地は pc+4 だが、
                // 遅延スロット中なら分岐成立後の着地点へ進む。
                env.backend.set(sem::ppc_ref(), pc);
                let t = sys.handle_trap(env, e.code as u32);
                return trap_result(env, sys, t, u64::from(word), |env| {
                    env.pc = match pending.take() {
                        Some(t) => t,
                        None => pc.wrapping_add(4) & 0xffff_ffff,
                    };
                });
            }
            return Err(Outcome::Unimplemented {
                pc,
                word: u128::from(word),
            });
        }
        Err(InterpExit::Unimplemented(_)) => return unimpl_insn(env, sys, u64::from(word)),
    };
    env.pc = next;
    Ok(())
}

/// OpenRISC Linux ELF（EM_OPENRISC=92・ELFCLASS32・BE）を実行する。
pub fn run_elf_openrisc_root(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    root: Option<&str>,
) -> Result<u64, String> {
    use polyisa_mem::PAGE_SIZE;
    use polyisa_sem::Backend as _;

    let host_elf = match root {
        Some(root) => polyisa_os_linux::guest_path::resolve_guest_path_links(root, "/", path)
            .ok_or_else(|| format!("{path}: ゲストルートの外を指す"))?,
        None => path.to_string(),
    };
    let bytes = std::fs::read(&host_elf).map_err(|e| format!("read {path}: {e}"))?;
    if *bytes.get(5).unwrap_or(&0) != 2 {
        return Err("openrisc はビッグエンディアンのみ".to_string());
    }
    const EM_OPENRISC: u16 = 92;
    let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    if ehdr.machine != EM_OPENRISC {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    let (file_type, ehdr_entry, phoff, phnum) =
        (ehdr.file_type, ehdr.entry, ehdr.phoff, ehdr.phnum);
    // モデルは `--cpu` があれば従い、なければ mor1kx（fpu+dslot）。
    let default_sel;
    let sel = match sel {
        Some(s) => s,
        None => {
            default_sel = polyisa_isadl::select::resolve(
                polyisa_guest_openrisc::MODEL_DEFS,
                polyisa_guest_openrisc::FEATURE_DEFS,
                polyisa_guest_openrisc::FEAT_BITS,
                "mor1kx",
                &[],
                &[],
            )
            .map_err(|e| format!("openrisc: {e}"))?;
            &default_sel
        }
    };
    let feats = sel.feats;
    let dslot = feats & polyisa_guest_openrisc::FEAT_DSLOT != 0;
    let model = OpenriscModel { feats, dslot };
    let mut sys = polyisa_os_linux::openrisc::sys::Linux::new();
    sys.exe_path = path.to_string();
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_openrisc::CpuState>());
    env.backend.addr_mask = 0xffff_ffff;
    // 構成レジスタの決定論値（モデルが供給する読み取り専用値）。
    {
        use polyisa_guest_openrisc::cpucfgr_bit as cb;
        let mut c = 1u64 << cb::OB32S;
        if !dslot {
            c |= 1 << cb::ND;
        }
        if feats & polyisa_guest_openrisc::FEAT_FPU != 0 {
            c |= 1 << cb::OF32S;
        }
        if feats & polyisa_guest_openrisc::FEAT_F64A32 != 0 {
            c |= 1 << cb::OF64A32S;
        }
        env.backend.set(sem::cpucfgr_ref(), c);
        env.backend.set(sem::vr_ref(), 0x1400_0000);
        let upr = if feats & polyisa_guest_openrisc::FEAT_FPU != 0 {
            0x41
        } else {
            1
        };
        env.backend.set(sem::upr_ref(), upr);
    }
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
    const INTERP_BASE: u64 = 0x4000_0000;
    let (run_entry, interp_bias) = if let Some(gpath) = interp_path {
        let host =
            polyisa_os_linux::guest_path::resolve_guest_path(root.unwrap_or(""), "/", &gpath)
                .ok_or_else(|| format!("interp {gpath} が root 外を指す"))?;
        let ibytes = std::fs::read(&host).map_err(|e| format!("read interp {host}: {e}"))?;
        if *ibytes.get(5).unwrap_or(&0) != 2 {
            return Err(format!("interp {host} はビッグエンディアンではない"));
        }
        let iehdr = polyisa_loader::elf::parse_ehdr32(&ibytes)
            .map_err(|e| format!("interp ehdr: {e:?}"))?;
        if iehdr.machine != EM_OPENRISC {
            return Err(format!("interp {host} は OpenRISC の ELF ではない"));
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
    let top = 0xbfff_f000u64;
    let img_top = top - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // auxv。or1k の AT_HWCAP 定義はない（0 で出す）。
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
    let envv: Vec<Vec<u8>> = std::env::var("POLYISA_OPENRISC_ENV")
        .map(|s| s.split(':').map(|e| e.as_bytes().to_vec()).collect())
        .unwrap_or_default();
    let (img, sp) = polyisa_os_linux::build_initial_stack32_endian(
        img_top,
        &arg_bytes,
        &envv,
        &auxv,
        Endian::Be,
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
    // OpenRISC ABI の初期 SP は r1。
    env.backend.set(sem::r_ref(1), sp);
    sys.init_brk(image_end);
    sys.set_stack_window(top - 0x200_0000, top);
    let outcome = run(
        &mut env,
        run_entry,
        model,
        &mut sys,
        Some(StackGrowth {
            top,
            limit: image_end & !(PAGE_SIZE - 1),
        }),
    );
    match outcome {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("未実装: pc={pc:#x} word={word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("実行予算を使い切った: pc={pc:#x}")),
        Outcome::Deadlock => Err("デッドロック".to_string()),
    }
}
