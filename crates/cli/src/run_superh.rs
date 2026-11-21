// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SuperH（SH-1/2/3/4・J-core）のフェッチから次のフェッチまで。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは
//! 1 ステップぶんのフェッチ・解読・意味論を `step` として提供する
//! （m68k/PA-RISC と同じ構造）。
//!
//! 命令は常に 16 ビットパーセル。SH-2A の 32 ビット命令は
//! 「先頭パーセル（上位 16 ビット）＋次パーセル（下位 16 ビット）」で、
//! エンディアンはパーセル内のバイト順だけに効く。先ず 16 ビットで
//! 解読し、当たらなければ次パーセルを読んで 32 ビットで解読する。
//! Ref: SPEC-SUPERH-SH2A §1（32 ビット命令の構成）.
//!
//! 遅延分岐は `bra`/`bsr`/`jmp`/`jsr`/`rts`/`braf`/`bsrf`/`bf.s`/`bt.s`。
//! 遅延スロットは成立・不成立にかかわらず常に実行される（SH に
//! annul は無い。`bf.s`/`bt.s` は「遅延付き条件分岐」であり、
//! スロットの副作用は必ず起きる — glibc の auxv 走査がそれに依存）。
//! `bf`/`bt` は遅延スロットを持たない通常の条件分岐で、不成立なら
//! pc+2 へそのまま進む。`rts/n`/`rtv/n`/`jsr/n` もスロットを持たない。
//! 遅延スロット中の分岐系命令と 32 ビット命令は slot-illegal で、
//! `handle_unimpl` を経ず `Unimplemented` に畳む。
//! Ref: SPEC-SUPERH-SH2 §6（遅延分岐の規則）, SPEC-SUPERH-SH4A
//! §5（遅延分岐命令の一覧: JMP, JSR, BRA, BRAF, BSR, BSRF, RTS, RTE,
//! BT/S, BF/S）.
//!
//! `trapa` は `ExceptionKind::Trap` を上げ、code は即値。Linux の
//! syscall 発行点（#0x10-#0x1f）は OS パーソナリティが拾う。
//! Ref: SRC-LINUX — arch/sh/kernel/entry.S.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_superh::{Insn, decode_model_ex, sem};
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
pub struct SuperhModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
    /// フェッチとデータアクセスのエンディアン。SH-4（sh4）は
    /// リトル、SH-4EB（sh4eb）はビッグ。
    pub endian: Endian,
}

impl SuperhModel {
    /// `--cpu` で解決した `CpuSel` とエンディアンから作る。
    #[must_use]
    pub fn new(feats: u128, endian: Endian) -> Self {
        Self { feats, endian }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
/// `stack` が `Some` ならページフォルト駆動でスタックを伸ばす。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: SuperhModel,
    sys: &mut impl TrapHandler,
    stack: Option<StackGrowth>,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_superh(env, sys, model, stack),
    )
}

/// `pc` の 16 ビットパーセルを命令フェッチする。
fn fetch16(env: &mut BareEnv, pc: u64, endian: Endian) -> Option<u16> {
    let acc = Access {
        endian,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b = [0u8; 2];
    env.backend.mem.read(VirtAddr(pc), &mut b, acc).ok()?;
    Some(match endian {
        Endian::Le => u16::from_le_bytes(b),
        Endian::Be => u16::from_be_bytes(b),
    })
}

/// `pc` の命令を解読し、（命令, 語, バイト長）を返す。
/// 先頭パーセルが 16 ビット語彙に当たらなければ次パーセルと
/// 合わせて 32 ビット語彙を試す。32 ビット命令の語は
/// `parcel1 << 16 | parcel2`。
/// `Err(word)` は解読不能で、`word` に生の先頭パーセルを返す。
// Ref: SPEC-SUPERH-SH2A §1.
fn fetch_insn(
    env: &mut BareEnv,
    pc: u64,
    endian: Endian,
    feats: u128,
) -> Result<(Insn, u32, u64), u32> {
    let Some(p1) = fetch16(env, pc, endian) else {
        return Err(0);
    };
    if let Some(insn) = decode_model_ex(u128::from(p1), 16, false, feats) {
        return Ok((insn, u32::from(p1), 2));
    }
    let Some(p2) = fetch16(env, pc + 2, endian) else {
        return Err(u32::from(p1));
    };
    let w = (u32::from(p1) << 16) | u32::from(p2);
    match decode_model_ex(u128::from(w), 32, false, feats) {
        Some(insn) => Ok((insn, w, 4)),
        None => Err(u32::from(p1)),
    }
}

/// 遅延スロットを持つ分岐か。スロットは常に実行される。
/// `bf`/`bt` は遅延スロットを持たない通常の条件分岐。
fn delayed(insn: Insn) -> bool {
    matches!(
        insn,
        Insn::Bra
            | Insn::Bsr
            | Insn::Braf
            | Insn::Bsrf
            | Insn::Jmp
            | Insn::Jsr
            | Insn::Rts
            | Insn::Bfs
            | Insn::Bts
    )
}

/// 遅延スロットを持たない分岐か（SH-2A の `/n` 系）。
fn direct_branch(insn: Insn) -> bool {
    matches!(
        insn,
        Insn::Rtsn | Insn::Rtvn | Insn::JsrnMem | Insn::JsrnTbr
    )
}

/// 遅延スロットに置けない命令か（分岐系全般）。
fn branch_any(insn: Insn) -> bool {
    delayed(insn) || direct_branch(insn) || matches!(insn, Insn::Bf | Insn::Bt)
}

/// `pc` の命令を意味論に渡し、制御の転移先を返す。
/// `Ok((target, ran))`。
fn exec_at(
    env: &mut BareEnv,
    insn: Insn,
    word: u32,
    pc: u64,
    endian: Endian,
) -> Result<bool, InterpExit> {
    env.step(|b| sem::exec(b, insn, word, pc, endian))
}

/// `TrapOutcome` を `Outcome` 面へ写す。`ok` は Handled 時の
/// 継続処理（pc の進め方）。
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
            if sys.take_exit(env, code) {
                ok(env);
                Ok(())
            } else {
                Err(Outcome::Exit(u64::from(code)))
            }
        }
        TrapOutcome::Blocked => {
            if sys.on_block(env) {
                ok(env);
                Ok(())
            } else {
                Err(Outcome::Deadlock)
            }
        }
        TrapOutcome::Unimplemented => Err(Outcome::Unimplemented {
            pc: env.pc,
            word: u128::from(word),
        }),
    }
}

/// 解読不能・未実装の命令語。OS パーソナリティの補完経路
/// （`handle_unimpl`）を先に試し、受けなければ `Unimplemented` に畳む。
fn unimpl_insn(env: &mut BareEnv, sys: &mut impl TrapHandler, word: u64) -> Result<(), Outcome> {
    match sys.handle_unimpl(env, env.pc, word) {
        TrapOutcome::Handled => Ok(()),
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
            pc: env.pc,
            word: u128::from(word),
        }),
    }
}

/// ページフォルトをスタック成長として処理する。窓 `[limit, top)` 内の
/// 未写像ページへのフォルトなら、フォルトしたページから最初に写像済みの
/// ページの手前までを R/W で写像する。処理したなら `Some` を返す。
// Ref: SRC-LINUX (7.3) — expand_stack の規約（RLIMIT 内の下方成長）。
fn stack_grow(
    env: &mut BareEnv,
    stack: Option<StackGrowth>,
    e: &polyisa_sem::GuestException,
) -> Option<()> {
    use polyisa_mem::{PAGE_SIZE, PageNo};
    let s = stack?;
    if e.kind != ExceptionKind::PageFault {
        return None;
    }
    let a = e.addr?;
    if a >= s.top || a < s.limit {
        return None;
    }
    let lo = a & !(PAGE_SIZE - 1);
    // フォルトしたページから上向きに、現状の写像の下端を探す。
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

/// 例外を OS パーソナリティと写像に畳む。
fn exception_result(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    e: polyisa_sem::GuestException,
    pc: u64,
    len: u64,
    word: u64,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    if e.kind == ExceptionKind::Trap {
        // syscall 発行点（trapa #0x10-#0x1f）や特権命令。
        let t = sys.handle_trap(env, e.code as u32);
        return trap_result(env, sys, t, word, |env| env.pc = pc.wrapping_add(len));
    }
    if stack_grow(env, stack, &e).is_some() {
        return Ok(());
    }
    if std::env::var_os("POLYISA_SUPERH_DEBUG").is_some() {
        eprintln!("superh: exception {e:?} at pc={pc:#x}");
    }
    Err(Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    })
}

/// 1 命令ぶんのフェッチ・解読・意味論。遅延スロットを持つ分岐は
/// スロット実行まで 1 ステップで済ませる。
// Ref: SPEC-SUPERH-SH2 §6, SPEC-SUPERH-SH2A §1.
fn step_superh(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: SuperhModel,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let pc = env.pc;
    // 命令は偶数アドレスに整列する。
    if pc & 1 != 0 {
        return Err(Outcome::Unimplemented { pc, word: 0 });
    }
    let (insn, word, len) = match fetch_insn(env, pc, model.endian, model.feats) {
        Ok(v) => v,
        Err(raw) => return unimpl_insn(env, sys, u64::from(raw)),
    };
    if std::env::var_os("POLYISA_SUPERH_TRACE").is_some() {
        // `POLYISA_SUPERH_TRACE=lo-hi` で範囲を絞れる（デバッグ用）。
        let range = std::env::var("POLYISA_SUPERH_TRACE").unwrap_or_default();
        let show = if let Some((lo, hi)) = range.split_once('-') {
            let lo = u64::from_str_radix(lo.trim_start_matches("0x"), 16).unwrap_or(0);
            let hi = u64::from_str_radix(hi.trim_start_matches("0x"), 16).unwrap_or(u64::MAX);
            (lo..=hi).contains(&pc)
        } else {
            true
        };
        if show {
            use polyisa_sem::Backend as _;
            let regs: Vec<u64> = (0..16)
                .map(|i| u64::from(env.backend.get(sem::R(i).state())))
                .collect();
            let pr = u64::from(env.backend.get(sem::pr_ref()));
            eprintln!("{pc:#x}: {word:#x} {insn:?} pr={pr:#x} {regs:x?}");
        }
    }
    let r = exec_at(env, insn, word, pc, model.endian);
    let taken = match env.backend.ctrl {
        Ctrl::Jump(t) => Some(t),
        Ctrl::Fallthrough => None,
    };
    match r {
        Ok(false) => return unimpl_insn(env, sys, u64::from(word)),
        Err(InterpExit::Exception(e)) => {
            return exception_result(env, sys, e, pc, len, u64::from(word), stack);
        }
        Err(InterpExit::Unimplemented(_)) => {
            return unimpl_insn(env, sys, u64::from(word));
        }
        Ok(true) => {}
    }
    // 遅延スロットを持たない分岐（SH-2A /n 系）。
    if direct_branch(insn) {
        if let Some(t) = taken {
            env.pc = t;
        }
        return Ok(());
    }
    // 遅延スロット（bf.s/bt.s でも常に実行）。
    if !delayed(insn) {
        env.pc = taken.unwrap_or(pc.wrapping_add(len));
        return Ok(());
    }
    // 遅延スロット（pc+2 の 16 ビット命令）。32 ビット命令と
    // 分岐系命令は slot-illegal。
    let spc = pc.wrapping_add(2);
    // 遅延スロット中の命令を実行する。`next` は例外からの継続 pc。
    macro_rules! run_slot {
        ($spc:expr, $next:expr) => {{
            let spc = $spc;
            let (sinsn, sword, slen) = match fetch_insn(env, spc, model.endian, model.feats) {
                Ok(v) => v,
                Err(raw) => {
                    return Err(Outcome::Unimplemented {
                        pc: spc,
                        word: u128::from(raw),
                    });
                }
            };
            if slen != 2 {
                return Err(Outcome::Unimplemented {
                    pc: spc,
                    word: u128::from(sword),
                });
            }
            let rs = exec_at(env, sinsn, sword, spc, model.endian);
            match rs {
                Ok(true) => {}
                Ok(false) => return unimpl_insn(env, sys, u64::from(sword)),
                Err(InterpExit::Exception(e)) => {
                    return match e.kind {
                        ExceptionKind::Trap => {
                            let t = sys.handle_trap(env, e.code as u32);
                            trap_result(env, sys, t, u64::from(sword), $next)
                        }
                        _ => {
                            if stack_grow(env, stack, &e).is_some() {
                                Ok(())
                            } else {
                                if std::env::var_os("POLYISA_SUPERH_DEBUG").is_some() {
                                    eprintln!("superh: slot exception {e:?} at pc={spc:#x}");
                                }
                                Err(Outcome::Unimplemented {
                                    pc: spc,
                                    word: u128::from(sword),
                                })
                            }
                        }
                    };
                }
                Err(InterpExit::Unimplemented(_)) => {
                    return unimpl_insn(env, sys, u64::from(sword));
                }
            }
            let ctrl = match env.backend.ctrl {
                Ctrl::Jump(t) => Some(t),
                Ctrl::Fallthrough => None,
            };
            (sinsn, sword, ctrl)
        }};
    }
    let (sinsn, sword, _s_taken) = run_slot!(spc, |env: &mut BareEnv| {
        env.pc = taken.unwrap_or_else(|| pc.wrapping_add(4))
    });
    if branch_any(sinsn) {
        // スロット中の分岐は slot-illegal。
        return Err(Outcome::Unimplemented {
            pc: spc,
            word: u128::from(sword),
        });
    }
    env.pc = taken.unwrap_or_else(|| pc.wrapping_add(4));
    Ok(())
}

/// SuperH の Linux ELF（EM_SH=42・ELFCLASS32・LE/BE）を実行する。
/// `--cpu` で解決したモデルがあれば従い、なければ `sh4`。
// Ref: SRC-LINUX (7.3), SPEC-ELF-GABI.
pub fn run_elf_superh(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_superh_sel(path, argv, None)
}

/// `--cpu` で解決したモデルを指定する `run_elf_superh`。
pub fn run_elf_superh_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::superh::sys::Linux::new();
    run_elf_superh_sys(path, argv, sel, &mut sys)
}

/// 終了コードと標準出力の捕獲を返す。
pub fn run_elf_superh_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    run_elf_superh_captured_in(path, argv, &[])
}

/// 標準入力 `stdin` を与えて実行し、終了コードと標準出力の捕獲を返す。
pub fn run_elf_superh_captured_in(
    path: &str,
    argv: &[String],
    stdin: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let mut sys = polyisa_os_linux::superh::sys::Linux::new();
    sys.stdin_buf = stdin.to_vec();
    let code = run_elf_superh_sys(path, argv, None, &mut sys)?;
    Ok((code, sys.io.stdout))
}

/// `run_elf_superh` に OS パーソナリティを差し込む形。テストが
/// syscall の結果（`sys.io` 等）を検査する用途に使う。
pub fn run_elf_superh_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::superh::sys::Linux,
) -> Result<u64, String> {
    use polyisa_mem::PAGE_SIZE;
    use polyisa_sem::Backend as _;

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if !matches!(bytes.get(4), Some(1)) {
        return Err("superh は ELFCLASS32 のみ対応".to_string());
    }
    let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_SH=42。Ref: SRC-LINUX (include/uapi/linux/elf-em.h)。
    const EM_SH: u16 = 42;
    if ehdr.machine != EM_SH {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    let endian = if ehdr.little { Endian::Le } else { Endian::Be };
    let phdrs =
        polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("PT_INTERP のある SuperH ELF は未対応（静的のみ）".to_string());
    }
    // `--cpu` 省略時は ELF の e_flags（EM_SH のアーキテクチャフラグ）
    // からモデルを引く。0xc は SH-4A、0x17 は SH2A-or-SH4 の慣習の
    // 割当（BIN-DISTRO-SH4/SH4EB 台帳の記述と一致）。未知・未対応の
    // 値は sh4（Linux SH-4 ABI の基盤モデル）に畳む。
    let flags = ehdr.flags & 0xff;
    let model_name = match flags {
        1 => "sh1",                   // EF_SH1
        2 => "sh2",                   // EF_SH2
        3 => "sh3",                   // EF_SH3
        8 => "sh3e",                  // EF_SH3E
        9 | 0x10 | 0x12 => "sh4",     // EF_SH4・EF_SH4_NOFPU・EF_SH4_NOMMU_NOFPU
        0x0b => "sh2e",               // EF_SH2E
        0x0c | 0x11 => "sh4a",        // EF_SH4A・EF_SH4A_NOFPU
        0x0d | 0x13 => "sh2a",        // EF_SH2A・EF_SH2A_NOFPU
        0x14 => "sh3",                // EF_SH3_NOMMU
        0x15 | 0x17 => "sh4",         // EF_SH2A_SH4*_：両コア共通の命令範囲
        0x16 | 0x18 => "sh3e",        // EF_SH2A_SH3*：SH-3/SH-3E 共通範囲
        4 | 5 | 6 | 7 | 0xa => "sh4", // DSP 系・EF_SH_UNKNOWN は sh4 に近似
        _ => "sh4",
    };
    let default_sel;
    let sel = match sel {
        Some(s) => s,
        None => {
            default_sel = polyisa_isadl::select::resolve(
                polyisa_guest_superh::MODEL_DEFS,
                polyisa_guest_superh::FEATURE_DEFS,
                polyisa_guest_superh::FEAT_BITS,
                model_name,
                &[],
                &[],
            )
            .map_err(|e| format!("superh: {e}"))?;
            &default_sel
        }
    };
    let model = SuperhModel::new(sel.feats, endian);
    sys.endian = endian;
    sys.exe_path = path.to_string();
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_superh::CpuState>());
    const ET_DYN: u16 = 3;
    let main_bias = if ehdr.file_type == ET_DYN {
        const MAIN_DYN_BASE: u64 = 0x0001_0000;
        let min_vaddr = phdrs
            .iter()
            .filter(|p| p.seg_type == 1)
            .map(|p| p.vaddr & !(PAGE_SIZE - 1))
            .min()
            .unwrap_or(0);
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
            const PHENT32: u64 = 32; // ELF32 の phdr は 32 バイト固定。
            let lo = ehdr.phoff as usize;
            let hi = lo + ehdr.phnum as usize * PHENT32 as usize;
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
    let entry = main_bias + ehdr.entry;
    let top = 0xbfff_f000u64;
    let img_top = top - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let auxv: Vec<(u64, u64)> = vec![
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
        (17, 100),                  // AT_CLKTCK
        (23, 0),                    // AT_SECURE
    ];
    // `POLYISA_SUPERH_ENV` を `a=1:b=2` 形で envp へ渡すデバッグ経路。
    let envv: Vec<Vec<u8>> = std::env::var("POLYISA_SUPERH_ENV")
        .map(|s| s.split(':').map(|e| e.as_bytes().to_vec()).collect())
        .unwrap_or_default();
    let (img, sp) =
        polyisa_os_linux::build_initial_stack32_endian(img_top, &arg_bytes, &envv, &auxv, endian);
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
    if std::env::var_os("POLYISA_SUPERH_DEBUG").is_some() {
        let mut b = [0u8; 64];
        let _ = env.backend.mem.read(
            VirtAddr(sp),
            &mut b,
            Access {
                endian,
                align: Align::Unaligned,
                kind: AccessKind::DataRead,
            },
        );
        eprintln!("superh: stack img at {sp:#x}: {b:02x?}");
        let mut b = [0u8; 8];
        let _ = env.backend.mem.read(
            VirtAddr(0x5a0d84),
            &mut b,
            Access {
                endian,
                align: Align::Unaligned,
                kind: AccessKind::DataRead,
            },
        );
        eprintln!("superh: mem@0x5a0d84: {b:02x?}");
    }
    // SH の初期 SP は R15。
    env.backend.set(sem::R(15).state(), sp as u32);
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
