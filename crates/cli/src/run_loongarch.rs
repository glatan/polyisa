// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! LoongArch（LA64/LA32）のフェッチから次のフェッチまで。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは
//! 1 ステップぶんのフェッチ・解読・意味論を `step` として提供する
//! （superh/m68k/PA-RISC と同じ構造）。
//!
//! 命令は固定 32 ビットで、リトルエンディアンのみ。LA32 の
//! 実効アドレスは 32 ビットに折り返す（`addr_mask`）。
//! `syscall` は `ExceptionKind::Trap` を上げ、code は
//! `TRAP_SYS | code15`。Linux の syscall 発行点は OS
//! パーソナリティが拾う。
//! Ref: SPEC-LOONGARCH-RM §2.2.12, SRC-LINUX — arch/loongarch/
//! kernel/entry.S（syscall 発行点と引数規約 a7/a0-a5）.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_loongarch::{decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::ExceptionKind;

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// ページフォルト駆動のスタック成長の設定。
/// `top` はスタック上端、`limit` は下向き成長の下限（RLIMIT_STACK 相当）。
/// 窓 `[limit, top)` 内の未写像ページへのフォルトで写像を伸ばす。
#[derive(Clone, Copy)]
pub struct StackGrowth {
    pub top: u64,
    pub limit: u64,
}

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct LoongarchModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
    /// LA64 モデルか（LA32 は実効アドレスを 32 ビットに折り返す）。
    pub la64: bool,
}

impl LoongarchModel {
    /// `--cpu` で解決した `CpuSel` と ELF クラスから作る。
    #[must_use]
    pub fn new(feats: u128, la64: bool) -> Self {
        Self { feats, la64 }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
/// `stack` が `Some` ならページフォルト駆動でスタックを伸ばす。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: LoongarchModel,
    sys: &mut impl TrapHandler,
    stack: Option<StackGrowth>,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_loongarch(env, sys, model, stack),
    )
}

/// `pc` の 32 ビット命令語をフェッチする。
fn fetch32(env: &mut BareEnv, pc: u64) -> Option<u32> {
    let acc = Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b = [0u8; 4];
    env.backend.mem.read(VirtAddr(pc), &mut b, acc).ok()?;
    Some(u32::from_le_bytes(b))
}

/// `TrapOutcome` を `Outcome` 面へ写す。`ok` は Handled 時の
/// 継続処理（pc の前進など）。
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
            let _ = (sys, word);
            Err(Outcome::Exit(u64::from(code)))
        }
        TrapOutcome::Blocked => Err(Outcome::Deadlock),
        TrapOutcome::Unimplemented => Err(Outcome::Unimplemented {
            pc: env.pc,
            word: u128::from(word),
        }),
    }
}

/// 解読不能・未実装の命令を OS パーソナリティに報せる。
fn unimpl_insn(env: &mut BareEnv, sys: &mut impl TrapHandler, word: u64) -> Result<(), Outcome> {
    let t = sys.handle_trap(env, sem::TRAP_ILL as u32);
    trap_result(env, sys, t, word, |_| {})
}

/// フォルトでスタックを伸ばせるなら伸ばす。伸ばしたら `Some`。
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
    env.backend.mem.map(VirtAddr(page), 1, Perms::RW).ok()?;
    Some(())
}

/// 例外を OS パーソナリティへ渡す。
fn exception_result(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    e: polyisa_sem::GuestException,
    pc: u64,
    word: u64,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    if e.kind == ExceptionKind::Trap {
        // `syscall` の発行点。code の下位 15 ビットは命令語の
        // 即値で、syscall 番号は $a7 が持つ。pc は発行点の
        // 次へ進める（戻り値の受け側が pc+4 を見る規約）。
        let t = sys.handle_trap(env, e.code as u32);
        return trap_result(env, sys, t, word, |env| env.pc = pc.wrapping_add(4));
    }
    if stack_grow(env, stack, &e).is_some() {
        return Ok(());
    }
    if std::env::var_os("POLYISA_LOONGARCH_DEBUG").is_some() {
        eprintln!("loongarch: exception {e:?} at pc={pc:#x}");
    }
    Err(Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    })
}

/// 1 命令ぶんのフェッチ・解読・意味論。
// Ref: SPEC-LOONGARCH-RM §2.
fn step_loongarch(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: LoongarchModel,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let pc = env.pc;
    // 命令は 4 バイト整列。
    if pc & 3 != 0 {
        return Err(Outcome::Unimplemented { pc, word: 0 });
    }
    let Some(word) = fetch32(env, pc) else {
        return unimpl_insn(env, sys, 0);
    };
    let Some(insn) = decode_model_ex(u128::from(word), 32, model.la64, model.feats) else {
        return unimpl_insn(env, sys, u64::from(word));
    };
    if std::env::var_os("POLYISA_LOONGARCH_TRACE").is_some() {
        use polyisa_sem::Backend as _;
        let regs: Vec<u64> = (0..8).map(|i| env.backend.get(sem::r_ref(i))).collect();
        let fcc = env.backend.get(sem::fcc_ref());
        eprintln!("{pc:#x}: {word:#x} {insn:?} r0-7={regs:x?} fcc={fcc:#x}");
    }
    let r = env.step(|b| sem::exec(b, insn, word, pc, model.la64));
    // 安定カウンタはステップ毎に進める（決定論的時計）。
    // Ref: SPEC-LOONGARCH-RM §2.2.10.1.
    {
        use polyisa_sem::Backend as _;
        let c = env.backend.get(sem::cnt_ref());
        env.backend.set(sem::cnt_ref(), c.wrapping_add(1));
    }
    match r {
        Ok(true) => {
            env.pc = match env.backend.ctrl {
                Ctrl::Jump(t) => t,
                Ctrl::Fallthrough => pc.wrapping_add(4),
            };
            Ok(())
        }
        Ok(false) => {
            env.pc = match env.backend.ctrl {
                Ctrl::Jump(t) => t,
                Ctrl::Fallthrough => pc.wrapping_add(4),
            };
            Ok(())
        }
        Err(InterpExit::Exception(e)) => exception_result(env, sys, e, pc, u64::from(word), stack),
        Err(InterpExit::Unimplemented(_)) => unimpl_insn(env, sys, u64::from(word)),
    }
}

/// LoongArch の Linux ELF（EM_LOONGARCH=258）を実行する。
/// `--cpu` で解決したモデルがあれば従い、なければ ELF クラス
/// から `la64`/`la32` を引く。
// Ref: SRC-LINUX, SPEC-ELF-GABI, SPEC-LOONGARCH-PSABI.
pub fn run_elf_loongarch(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_loongarch_sel(path, argv, None)
}

/// `--cpu` で解決したモデルを指定する `run_elf_loongarch`。
pub fn run_elf_loongarch_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::loongarch::sys::Linux::new();
    run_elf_loongarch_sys(path, argv, sel, &mut sys)
}

/// 終了コードと標準出力の捕獲を返す。
pub fn run_elf_loongarch_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    run_elf_loongarch_captured_in(path, argv, &[])
}

/// 標準入力 `stdin` を与えて実行し、終了コードと標準出力の捕獲を返す。
pub fn run_elf_loongarch_captured_in(
    path: &str,
    argv: &[String],
    stdin: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let mut sys = polyisa_os_linux::loongarch::sys::Linux::new();
    sys.stdin_buf = stdin.to_vec();
    let code = run_elf_loongarch_sys(path, argv, None, &mut sys)?;
    Ok((code, sys.io.stdout))
}

/// `run_elf_loongarch` に OS パーソナリティを差し込む形。
pub fn run_elf_loongarch_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::loongarch::sys::Linux,
) -> Result<u64, String> {
    use polyisa_mem::PAGE_SIZE;
    use polyisa_sem::Backend as _;

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let class = *bytes.get(4).unwrap_or(&0);
    let little = *bytes.get(5).unwrap_or(&0) == 1;
    if !little {
        return Err("loongarch はリトルエンディアンのみ".to_string());
    }
    // EM_LOONGARCH=258。Ref: SRC-LINUX (include/uapi/linux/elf-em.h).
    const EM_LOONGARCH: u16 = 258;
    let (la64, ehdr, phdrs) = match class {
        2 => {
            let e = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            let p = polyisa_loader::elf::parse_phdrs(&bytes, &e)
                .map_err(|e| format!("phdrs: {e:?}"))?;
            (true, e, p)
        }
        1 => {
            let e =
                polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            let p = polyisa_loader::elf::parse_phdrs32(&bytes, &e)
                .map_err(|e| format!("phdrs: {e:?}"))?;
            (false, e, p)
        }
        _ => return Err(format!("未対応の ELF クラス: {class}")),
    };
    if ehdr.machine != EM_LOONGARCH {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let (file_type, entry, phoff, phnum) = (ehdr.file_type, ehdr.entry, ehdr.phoff, ehdr.phnum);
    // e_flags の ABI 版は [7:6]。NW=0x40。OW(0x0)は LA10 で
    // 明示する方針。Ref: SPEC-LOONGARCH-PSABI（e_flags ABI 版）.
    let flags = ehdr.flags;
    let abi_version = flags & 0xc0;
    if abi_version != 0x40 && abi_version != 0 {
        return Err(format!("未対応の ABI 版 e_flags={flags:#x}"));
    }
    // モデルは `--cpu` があれば従い、なければ ELF クラスで引く。
    let model_name = if la64 { "la64" } else { "la32" };
    let default_sel;
    let sel = match sel {
        Some(s) => s,
        None => {
            default_sel = polyisa_isadl::select::resolve(
                polyisa_guest_loongarch::MODEL_DEFS,
                polyisa_guest_loongarch::FEATURE_DEFS,
                polyisa_guest_loongarch::FEAT_BITS,
                model_name,
                &[],
                &[],
            )
            .map_err(|e| format!("loongarch: {e}"))?;
            &default_sel
        }
    };
    let model = LoongarchModel::new(sel.feats, la64);
    sys.exe_path = path.to_string();
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_loongarch::CpuState>());
    if !la64 {
        env.backend.addr_mask = 0xffff_ffff;
    }
    // CPUCFG の語を既定値で埋める（LA8 で整備する決定論値）。
    init_cpucfg(&mut env, la64);
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
        const MAIN_DYN_BASE: u64 = 0x0001_0000;
        MAIN_DYN_BASE.wrapping_sub(segs_vaddr_min)
    } else {
        0
    };
    let image_end = image_end.wrapping_add(main_bias);
    polyisa_loader::elf::load_segments_bias(&bytes, &phdrs, &mut env.backend.mem, main_bias)
        .map_err(|e| format!("load: {e:?}"))?;
    // PT_INTERP は LA10 の動的ロード経路で扱う。ここでは拒まない。
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
                let phent: u64 = if la64 { 56 } else { 32 };
                let lo = phoff as usize;
                let hi = lo + phnum as usize * phent as usize;
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
    let entry = main_bias.wrapping_add(entry);
    let top = if la64 {
        0x0000_7fff_ffff_f000u64
    } else {
        0xbfff_f000u64
    };
    let img_top = top - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // auxv。AT_RANDOM・AT_EXECFN は build_initial_stack64 が詰める。
    let auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),                    // AT_PHDR
        (4, if la64 { 56 } else { 32 }),   // AT_PHENT
        (5, u64::from(phnum)),             // AT_PHNUM
        (6, 0x1000),                       // AT_PAGESZ
        (8, 0),                            // AT_FLAGS
        (9, entry),                        // AT_ENTRY
        (11, 0),                           // AT_UID
        (12, 0),                           // AT_EUID
        (13, 0),                           // AT_GID
        (14, 0),                           // AT_EGID
        (16, if la64 { 0x1f } else { 0 }), // AT_HWCAP（LA64 の LAM/LAM_UA 等は LA10 で整備）
        (17, 100),                         // AT_CLKTCK
        (23, 0),                           // AT_SECURE
        (25, 0),                           // AT_RANDOM（詰め物はスタック側で置く）
    ];
    let envv: Vec<Vec<u8>> = std::env::var("POLYISA_LOONGARCH_ENV")
        .map(|s| s.split(':').map(|e| e.as_bytes().to_vec()).collect())
        .unwrap_or_default();
    let (img, sp) = if la64 {
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &envv, &auxv, Endian::Le)
    } else {
        polyisa_os_linux::build_initial_stack32_endian(
            img_top,
            &arg_bytes,
            &envv,
            &auxv,
            Endian::Le,
        )
    };
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
    // LoongArch の初期 SP は $sp = $r3。
    env.backend.set(sem::r_ref(3), sp);
    sys.init_brk(image_end);
    let outcome = run(
        &mut env,
        entry,
        model,
        sys,
        Some(StackGrowth {
            top,
            limit: top - 0x200_0000,
        }),
    );
    match outcome {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("未実装: pc={pc:#x} word={word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("実行予算を使い切った: pc={pc:#x}")),
        Outcome::Deadlock => Err("デッドロック".to_string()),
    }
}

/// CPUCFG の構成情報を既定値で埋める。
/// Ref: SPEC-LOONGARCH-RM §2.2.10.2.
fn init_cpucfg(env: &mut BareEnv, la64: bool) {
    use polyisa_sem::Backend as _;
    let set = |env: &mut BareEnv, i: u32, v: u32| {
        env.backend.set_indexed(sem::cpucfg_array(), i, v);
    };
    // word0: PRID（実装者識別。Loongson 風の 0x0014_xxxx 系）。
    set(env, 0, 0x0014_a000);
    // word1: アーキテクチャ情報。LA64=bit1, LA32=bit0、
    // PGMMU=bit4、IOCSR=bit5、PALEN/VABILEN は後で足す。
    let w1 = if la64 { 1 << 1 } else { 1 << 0 } | (1 << 4) | (1 << 5);
    set(env, 1, w1);
    // word2: 拡張機能（FP=1, FP_SP=2, FP_DP=4, FP_ver=bits5-7,
    // LSX=bit12, LASX=bit13, LBT=bit16-18, LVZ=bit9?）。
    // LA8 の段階では基本 FP+拡張宣言のみ。
    set(env, 2, 1 | 2 | 4 | (2 << 5));
    // word3: 機能情報（CC 方式・LSPW 等）。既定 0 のまま。
}
