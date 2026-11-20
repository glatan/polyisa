// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PA-RISC のフェッチから次のフェッチまで。
//!
//! 命令は32ビット固定長のビッグエンディアン。PC は IAOQ
//! （instruction address offset queue）の前後2要素（`iaoq_f`/
//! `iaoq_b`）で進み、分岐は遅延スロットを持つ。下位2ビットは
//! 特権レベル（ユーザモード = 3）で、フェッチ番地は `& !3` で
//! 取る（SPEC-PARISC-11 §3: IAOQ{62..63} が特権ビット）。
//!
//! 遷移規則（`state` 側のキューを直接操作する。`Ctrl::Jump` は
//! 分岐ターゲットとして読むだけで `env.pc` は報告用）:
//! - 通常・条件不成立分岐: `iaoq_f = iaoq_b`、`iaoq_b += 4`
//! - 分岐成立（Jump(t)）: `iaoq_f = iaoq_b`（遅延スロット番地）、
//!   `iaoq_b = t`。この1ステップだけ PSW.B を立て、遅延スロット
//!   内の `gate` 検査に使う（SPEC-PARISC-11 §4-2）
//! - 無効化（PSW.N=1 でフェッチした命令）: 命令語は読むが実行
//!   せず、PSW.N と PSW.B を消費して通常どおりキューを進める
//!
//! ゲートウェイ（ページゼロ。`ble 0x100(%sr0,%rN)` 等で到達）:
//! フェッチ番地が 0x1000 未満なら Linux のゲートウェイページ
//! （設計判断: 実機ではカーネルがページゼロに置くゲートウェイ
//! 命令列であり、本実装は各オフセットを ABI 上の入口として
//! 直接振り分ける）。0xe0 は set_thread_pointer 入口で
//! `cr27 = r26` して `r31` へ戻る内蔵処理、それ以外は
//! オフセットを `code` に載せて `TrapHandler::handle_trap`
//! へ渡す（Handled なら `r31` へ戻る。Linux では `r31` が
//! 呼び出し側に戻る規約）。
//! Ref: SPEC-PARISC-11 §4, SRC-LINUX (arch/parisc gateway page).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_parisc::{decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct PariscModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
}

impl PariscModel {
    /// `CpuSel` から機能ビットだけを取る。
    #[must_use]
    pub fn from_sel(sel: &polyisa_isadl::select::CpuSel) -> Self {
        Self { feats: sel.feats }
    }
}

/// スタックの成長窓。未写像フォルトをこの範囲で埋める。
#[derive(Clone, Copy, Debug)]
pub struct StackGrowth {
    /// スタック上端。
    pub top: u64,
    /// これより下は伸ばさない。
    pub limit: u64,
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
/// `stack` はページフォルト駆動のスタック成長窓（不要なら `None`）。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: PariscModel,
    sys: &mut impl TrapHandler,
    stack: Option<StackGrowth>,
) -> Outcome {
    // ユーザモード（priv=3）でキューを初期化する。
    env.backend.set(sem::iaoq_f_ref(), entry | 3);
    env.backend
        .set(sem::iaoq_b_ref(), entry.wrapping_add(4) | 3);
    env.backend.set(sem::iasq_f_ref(), 0);
    env.backend.set(sem::iasq_b_ref(), 0);
    env.pc = entry;
    let trace = std::env::var_os("POLYISA_PARISC_TRACE").is_some();
    let mut hist = std::collections::VecDeque::with_capacity(512);
    let o = polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.backend.get(sem::iaoq_f_ref()) & !3,
        |env, sys| {
            if trace {
                hist.push_back(env.backend.get(sem::iaoq_f_ref()) & !3);
                if hist.len() > 512 {
                    hist.pop_front();
                }
            }
            step_parisc(env, sys, model, stack)
        },
    );
    if trace && !matches!(o, Outcome::Exit(_)) {
        eprintln!(
            "parisc: last pcs: {}",
            hist.iter()
                .map(|p| format!("{p:#x}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        for i in [2u8, 4, 5, 19, 20, 21, 22, 25, 26, 28, 29, 30, 31] {
            eprintln!("  r{i} = {:#x}", env.backend.get(sem::Gr(i).state()));
        }
        eprintln!("  psw = {:#x}", env.backend.get(sem::psw_ref()));
        eprintln!(
            "  iaoq = {:#x} {:#x}",
            env.backend.get(sem::iaoq_f_ref()),
            env.backend.get(sem::iaoq_b_ref())
        );
    }
    o
}

/// 命令フェッチ用のアクセス属性。PA-RISC はビッグエンディアン。
const FETCH: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::Fetch,
};

/// キュー（`iaoq_f`/`iaoq_b`）を書き、`env.pc` を報告用に揃える。
fn set_queue(env: &mut BareEnv, f: u64, b: u64) {
    env.backend.set(sem::iaoq_f_ref(), f);
    env.backend.set(sem::iaoq_b_ref(), b);
    env.pc = f & !3;
}

/// `r31`（RP）への復帰。ゲートウェイ・トラップの Handled 帰路
/// （`iaoq_f = gr[31] | 3`、`iaoq_b = iaoq_f + 4` の通常遷移。
/// 下位2ビットのユーザ特権付与は Linux のページゼロ
/// ゲートウェイの復帰規約に倣う）。
// Ref: SRC-LINUX (arch/parisc gateway page).
fn gate_ret(env: &mut BareEnv) {
    let r = env.backend.get(sem::Gr(31).state()) | 3;
    set_queue(env, r, r.wrapping_add(4));
}

/// `sys.handle_trap` の戻り値を `Outcome` 面へ写す。
/// `ok` は Handled 時に走らせる継続処理（キュー遷移や `gate_ret`）。
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
            pc: env.backend.get(sem::iaoq_f_ref()) & !3,
            word: u128::from(word),
        }),
    }
}

/// `handle_unimpl` の戻り値を `Outcome` 面へ写す。`Handled` は
/// 「ハンドラが復帰 PC（IAOQ キュー）を設定済み」という
/// `TrapHandler::handle_unimpl` の契約なのでキューは自動で
/// 進めない（`trap_result` と違い `ok` 継続を取らない）。
/// また遅延スロット中の未実装命令をハンドラが処理済みにした
/// 場合に PSW.B が残らないよう落とす。
fn unimpl_result(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    t: TrapOutcome,
    word: u64,
) -> Result<(), Outcome> {
    match t {
        TrapOutcome::Handled => {
            let mut p = env.backend.get(sem::psw_ref());
            p &= !sem::PSW_B;
            env.backend.set(sem::psw_ref(), p);
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
            pc: env.backend.get(sem::iaoq_f_ref()) & !3,
            word: u128::from(word),
        }),
    }
}

/// ページゼロのゲートウェイ（Linux ABI の入口集合）。
/// `addr` は `iaoq_f & !3`（0x1000 未満）。PSW.N/PSW.B が立って
/// 到達した gate は不正（遅延スロット中の gate も含む。
/// SPEC-PARISC-20 §B,GATE の遅延スロット禁止に対応）。
fn gateway(env: &mut BareEnv, sys: &mut impl TrapHandler, addr: u64) -> Result<(), Outcome> {
    let mut psw = env.backend.get(sem::psw_ref());
    if psw & (sem::PSW_N | sem::PSW_B) != 0 {
        // 無効化の gate、または遅延スロット中の gate → 不正命令。
        // トラップが Handled でも継続するので N/B 両方を落とす。
        psw &= !(sem::PSW_N | sem::PSW_B);
        env.backend.set(sem::psw_ref(), psw);
        let t = sys.handle_trap(env, sem::TRAP_ILL as u32);
        return trap_result(env, sys, t, 0xffff_fffe, |env| {
            // Handled でも継続位置はキューの通常遷移と同じ。
            let b = env.backend.get(sem::iaoq_b_ref());
            set_queue(env, b, b.wrapping_add(4));
        });
    }
    match addr {
        // SET_THREAD_POINTER: cr27 = r26 で r31 へ戻る。
        // Ref: SRC-LINUX (arch/parisc gateway page, offset 0xe0).
        0xe0 => {
            let tp = env.backend.get(sem::Gr(26).state());
            env.backend.set(sem::Cr(27).state(), tp);
            gate_ret(env);
            env.steps += 1;
            Ok(())
        }
        // それ以外はオフセットをそのまま code に載せて OS 側へ。
        _ => {
            env.steps += 1;
            let t = sys.handle_trap(env, addr as u32);
            trap_result(env, sys, t, addr, gate_ret)
        }
    }
}

/// 1 命令ぶんのフェッチ・解読・意味論とキュー遷移。
// Ref: SPEC-PARISC-11 §4（IAOQ 遷移と無効化）.
fn step_parisc(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: PariscModel,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let iaoq_f = env.backend.get(sem::iaoq_f_ref());
    let iaoq_b = env.backend.get(sem::iaoq_b_ref());
    let psw = env.backend.get(sem::psw_ref());
    env.pc = iaoq_f & !3;
    let addr = iaoq_f & !3;
    let unimpl = |word: u64| Outcome::Unimplemented {
        pc: addr,
        word: u128::from(word),
    };

    // ページゼロのゲートウェイ（nullified であっても判定する）。
    if addr < 0x1000 {
        return gateway(env, sys, addr);
    }

    // 無効化されていても命令語は読む（フェッチの検査は実行有無
    // と独立という規約）。
    let mut b4 = [0u8; 4];
    if env
        .backend
        .mem
        .read(VirtAddr(addr), &mut b4, FETCH)
        .is_err()
    {
        // フェッチ不能はページフォルト扱い→スタック成長の余地だけ見る。
        let e = polyisa_sem::GuestException {
            kind: ExceptionKind::PageFault,
            code: 0,
            addr: Some(addr),
            in_delay_slot: psw & sem::PSW_B != 0,
        };
        if stack_grow(env, stack, &e).is_some() {
            return Ok(());
        }
        if std::env::var_os("POLYISA_PARISC_TRACE").is_some() {
            eprintln!("parisc: fetch fault pc={addr:#x} word=0xffffffff");
        }
        return Err(unimpl(0xffff_ffff));
    }
    let word = u32::from_be_bytes(b4);

    // PSW.N が立っていればこの命令は実行されない。
    if psw & sem::PSW_N != 0 {
        let p = psw & !(sem::PSW_N | sem::PSW_B);
        env.backend.set(sem::psw_ref(), p);
        set_queue(env, iaoq_b, iaoq_b.wrapping_add(4));
        env.steps += 1;
        return Ok(());
    }

    let Some(insn) = decode_model_ex(u128::from(word), 32, false, model.feats) else {
        match sys.handle_unimpl(env, addr, u64::from(word)) {
            TrapOutcome::Unimplemented => return Err(unimpl(u64::from(word))),
            other => return unimpl_result(env, sys, other, u64::from(word)),
        }
    };

    // PSW.N を消費してから実行する（PSW.B は gate 検査のため残す）。
    let p = psw & !sem::PSW_N;
    env.backend.set(sem::psw_ref(), p);
    env.backend.ctrl = Ctrl::Fallthrough;
    let r = sem::exec(&mut env.backend, insn, word, iaoq_f);
    env.steps += 1;
    match r {
        Ok(true) => {
            // キュー遷移。分岐成立時は iaoq_b にターゲットを載せ、
            // PSW.B を立てて遅延スロットを示す。
            let target = match env.backend.ctrl {
                Ctrl::Jump(t) => Some(t),
                Ctrl::Fallthrough => None,
            };
            let mut p = env.backend.get(sem::psw_ref());
            p = (p & !sem::PSW_B) | if target.is_some() { sem::PSW_B } else { 0 };
            env.backend.set(sem::psw_ref(), p);
            let new_b = target.unwrap_or_else(|| iaoq_b.wrapping_add(4));
            set_queue(env, iaoq_b, new_b);
            Ok(())
        }
        Ok(false) => match sys.handle_unimpl(env, addr, u64::from(word)) {
            TrapOutcome::Unimplemented => Err(unimpl(u64::from(word))),
            other => unimpl_result(env, sys, other, u64::from(word)),
        },
        // 意味論のトラップ（`,tsv`・`,tc`・特権命令・delay slot 内
        // の gate 等）。命令は終端で発生する扱いなので、Handled なら
        // キューは通常どおり進む（遅延スロット中なら保留分岐が続く）。
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => {
            let t = sys.handle_trap(env, e.code as u32);
            trap_result(env, sys, t, u64::from(word), |env| {
                let mut p = env.backend.get(sem::psw_ref());
                p &= !sem::PSW_B;
                env.backend.set(sem::psw_ref(), p);
                let b = env.backend.get(sem::iaoq_b_ref());
                set_queue(env, b, b.wrapping_add(4));
            })
        }
        // ページフォルトはスタック成長窓の内側なら写像を伸ばして
        // 同一命令をやり直す（キューはまだ進んでいない）。
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::PageFault => {
            if stack_grow(env, stack, &e).is_some() {
                Ok(())
            } else {
                if std::env::var_os("POLYISA_PARISC_TRACE").is_some() {
                    eprintln!(
                        "parisc: page fault pc={addr:#x} word={word:#x} fault_addr={:?}",
                        e.addr
                    );
                }
                Err(unimpl(u64::from(word)))
            }
        }
        // その他の例外はこの段階では未実装に写す。
        Err(InterpExit::Exception(_)) | Err(InterpExit::Unimplemented(_)) => {
            Err(unimpl(u64::from(word)))
        }
    }
}

/// ページフォルトをスタック成長として処理する。
// Ref: SRC-LINUX (7.3) — expand_stack。
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
    // hppa のスタックは上向き成長（CONFIG_STACK_GROWSUP）なので、既存
    // 写像の直上にある未写像区間の下端から fault ページまでを埋める。
    // Ref: SRC-LINUX — expand_upwards。
    let base = a & !(PAGE_SIZE - 1);
    let mut lo = base;
    while lo > s.limit
        && !env
            .backend
            .mem
            .is_mapped(PageNo((lo - PAGE_SIZE) / PAGE_SIZE))
    {
        lo -= PAGE_SIZE;
    }
    let hi = base + PAGE_SIZE;
    let pages = (hi - lo) / PAGE_SIZE;
    if pages == 0 {
        return None;
    }
    env.backend.mem.map(VirtAddr(lo), pages, Perms::RW).ok()
}

/// ELF32・EM_PARISC（15）の静的実行（Linux パーソナリティ）。
pub fn run_elf_parisc(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_parisc_sel(path, argv, None)
}

/// `--cpu` で解決したモデルを指定する `run_elf_parisc`。
pub fn run_elf_parisc_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let mut sys = polyisa_os_linux::parisc::sys::Linux::new();
    run_elf_parisc_sys(path, argv, sel, &mut sys)
}

/// 終了コードと標準出力の捕獲を返す。
pub fn run_elf_parisc_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    run_elf_parisc_captured_in(path, argv, &[])
}

/// 標準入力 `stdin` を与えて実行し、終了コードと標準出力の捕獲を返す。
pub fn run_elf_parisc_captured_in(
    path: &str,
    argv: &[String],
    stdin: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let mut sys = polyisa_os_linux::parisc::sys::Linux::new();
    sys.stdin_buf = stdin.to_vec();
    let code = run_elf_parisc_sys(path, argv, None, &mut sys)?;
    Ok((code, sys.io.stdout))
}

/// `sys` の状態を引き継いで PA-RISC の Linux ELF を実行する。
pub fn run_elf_parisc_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::parisc::sys::Linux,
) -> Result<u64, String> {
    let (mut env, entry, model, image_end) = setup_parisc_elf(path, argv, sel)?;
    // /proc/self/exe の readlink は絶対パスを返す規約。
    sys.exe_path = std::fs::canonicalize(path)
        .map_or_else(|_| path.to_string(), |p| p.to_string_lossy().into_owned());
    sys.init_brk(image_end);
    let growth = Some(StackGrowth {
        top: STACK_TOP,
        limit: STACK_TOP - STACK_LIMIT,
    });
    finish(run(&mut env, entry, model, sys, growth))
}

/// スタック上端。hppa32 Linux の TASK_SIZE（0xffff_0000）の直下。
// Ref: SRC-LINUX (7.3) — arch/parisc/include/asm/processor.h.
const STACK_TOP: u64 = 0xfffe_0000;
/// スタック成長窓の下限。Linux 既定の RLIMIT_STACK（8 MiB）。
const STACK_LIMIT: u64 = 8 << 20;

/// `Outcome` を実行結果へ写す。
fn finish(o: Outcome) -> Result<u64, String> {
    match o {
        Outcome::Exit(code) => Ok(code),
        Outcome::StepLimit { pc } => Err(format!("ステップ数を超過（pc={pc:#x}）")),
        Outcome::Deadlock => Err("デッドロック".to_string()),
        Outcome::Unimplemented { pc, word } => Err(format!("未実装: pc={pc:#x} word={word:#x}")),
    }
}

/// ELF の検証・写像・初期スタックの構築。
/// 返り値は `(env, entry, model, image_end)`。
fn setup_parisc_elf(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<(BareEnv, u64, PariscModel, u64), String> {
    use polyisa_mem::PAGE_SIZE;

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_PARISC=15。Ref: SRC-LINUX (include/uapi/linux/elf-em.h).
    if ehdr.machine != 15 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    if ehdr.little {
        return Err("PA-RISC はビッグエンディアンのみ対応".to_string());
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("PT_INTERP のある PA-RISC ELF は未対応（静的のみ）".to_string());
    }
    // `--cpu` 省略時は pa7300lc（PA 1.1 + MAX-1 = hppa Linux の
    // 32ビット ABI の基盤モデル）。
    let default_sel;
    let sel = match sel {
        Some(s) => s,
        None => {
            default_sel = polyisa_isadl::select::resolve(
                polyisa_guest_parisc::MODEL_DEFS,
                polyisa_guest_parisc::FEATURE_DEFS,
                polyisa_guest_parisc::FEAT_BITS,
                "pa7300lc",
                &[],
                &[],
            )
            .map_err(|e| format!("parisc: {e}"))?;
            &default_sel
        }
    };
    let model = PariscModel::from_sel(sel);
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_parisc::CpuState>());
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
    let image_end = phdrs
        .iter()
        .filter(|p| p.seg_type == 1)
        .map(|p| p.vaddr + p.memsz)
        .max()
        .unwrap_or(0)
        + main_bias;
    let entry = main_bias + ehdr.entry;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // ELF32 + ビッグエンディアンの初期スタック。
    let auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),             // AT_PHDR
        (4, 32),                    // AT_PHENT（ELF32 の phdr 幅）
        (5, u64::from(ehdr.phnum)), // AT_PHNUM
        (6, 0x1000),                // AT_PAGESZ（PA Linux のページは 4KiB）
        (9, entry),                 // AT_ENTRY
        (11, 0),                    // AT_UID
        (12, 0),                    // AT_EUID
        (13, 0),                    // AT_GID
        (14, 0),                    // AT_EGID
        (17, 100),                  // AT_CLKTCK
        (23, 0),                    // AT_SECURE
    ];
    // hppa Linux のユーザスタックは上向き成長（CONFIG_STACK_GROWSUP）。
    // カーネルは arg ブロックをスタック窓の *下端* に置き、画像の直上
    // に 64 バイトのリンケージバッファを残して sp を立てる。
    // Ref: SRC-LINUX（arch/parisc: CONFIG_STACK_GROWSUP と arg ブロック配置）。
    let stack_bottom = STACK_TOP - STACK_LIMIT;
    let (probe, _) = polyisa_os_linux::build_initial_stack32_endian(
        STACK_TOP,
        &arg_bytes,
        &[],
        &auxv,
        Endian::Be,
    );
    let img_top = stack_bottom + probe.len() as u64;
    let (img, sp) =
        polyisa_os_linux::build_initial_stack32_endian(img_top, &arg_bytes, &[], &auxv, Endian::Be);
    // 画像＋リンケージバッファを含むページだけ先に写像する。
    let map_hi = (img_top + 64).next_multiple_of(PAGE_SIZE);
    let stack_pages = (map_hi - stack_bottom) / PAGE_SIZE;
    env.backend
        .mem
        .map(VirtAddr(stack_bottom), stack_pages, Perms::RW)
        .map_err(|_| "スタックの写像に失敗".to_string())?;
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|_| "スタックの書き込みに失敗".to_string())?;
    // PA Linux のエントリ条件（Ref: SRC-LINUX arch/parisc/kernel/entry.S と
    // ELF_PLAT_INIT 系の起動規約）:
    //   r23 = 0（rtld_fini）、r24 = argv、r25 = argc、
    //   r30 = start_stack + 64、r31 = entry。
    env.backend.set(sem::Gr(23).state(), 0);
    env.backend.set(sem::Gr(24).state(), sp + 4);
    env.backend.set(sem::Gr(25).state(), arg_bytes.len() as u64);
    env.backend.set(sem::Gr(30).state(), img_top + 64);
    env.backend.set(sem::Gr(31).state(), entry);
    Ok((env, entry, model, image_end))
}

/// ゲートウェイ・トラップを受けないスタブ。`ble` 到達で止める
/// だけの裸実行（`NoSys`）に使う。
pub struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_parisc::{CpuState, FEAT_MAX1, FEAT_MAX2, FEAT_PA11, FEAT_PA20};

    const ALL: u128 = FEAT_PA11 | FEAT_PA20 | FEAT_MAX1 | FEAT_MAX2;

    /// プログラム語列を `base` に置いた裸実行環境（RXW 全域）。
    fn env_at(base: u64, words: &[u32]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let lo = base & !0xFFF;
        let hi = (base + words.len() as u64 * 4 + 0xFFF) & !0xFFF;
        env.backend
            .mem
            .map(VirtAddr(lo), (hi - lo) / 0x1000, polyisa_mem::Perms(0b111))
            .unwrap();
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_be_bytes());
        }
        env.backend.mem.write(VirtAddr(base), &bytes).unwrap();
        env
    }

    fn model() -> PariscModel {
        PariscModel { feats: ALL }
    }

    fn g(env: &mut BareEnv, r: u8) -> u64 {
        env.backend.get(sem::Gr(r).state())
    }

    fn set_g(env: &mut BareEnv, r: u8, v: u64) {
        env.backend.set(sem::Gr(r).state(), v);
    }

    /// `ldo i(b),t`（i は 0 以上の小さな正数）。
    fn ldo(i: u32, b: u8, t: u8) -> u32 {
        0x3400_0000 | (b as u32) << 21 | (t as u32) << 16 | (i << 1)
    }

    /// `add a,b,t`。
    fn add(a: u8, b: u8, t: u8) -> u32 {
        0x0800_0000 | (a as u32) << 21 | (b as u32) << 16 | 0x18 << 6 | t as u32
    }

    /// `bl disp,l`（disp >= 0 で 4 整列）。
    fn bl(disp: u32, l: u8) -> u32 {
        0xe800_0000 | (l as u32) << 21 | ((disp >> 2) & 0x3ff) << 3
    }

    /// `ble disp(sr,b)`（disp >= 0 で 4 整列）。
    /// sr 桁は bits13-15（assemble_sr3: bit13=LSB、bits14-15=上位2）。
    fn ble(disp: u32, sr: u8, b: u8) -> u32 {
        let i = disp >> 2;
        0xe400_0000
            | (b as u32) << 21
            | ((i >> 11) & 0x1f) << 16
            | (sr as u32 & 1) << 13
            | (sr as u32 >> 1) << 14
            | ((i >> 10) & 1) << 2
            | (i & 0x3ff) << 3
    }

    /// `bv 0(b)`。
    fn bv(b: u8) -> u32 {
        0xe800_0000 | (b as u32) << 21 | 0b110 << 13
    }

    /// `comb,=,n ra,rb,disp`（c=1 "="、disp >= 0 で 4 整列）。
    fn comb_eq_n(a: u8, b: u8, disp: u32) -> u32 {
        0x8000_0000
            | (a as u32) << 21
            | (b as u32) << 16
            | 1 << 13
            | ((disp >> 2) & 0x3ff) << 3
            | 1 << 1
    }

    const NOP: u32 = 0x0800_0240; // or r0,r0,r0
    const UNIMP: u32 = 0xffff_ffff;

    #[test]
    fn straight_line_runs_to_unimp() {
        // ldo 5,r4; ldo 7,r5; add r4,r5,r6; unimp → r6=12。
        let mut env = env_at(0x1000, &[ldo(5, 0, 4), ldo(7, 0, 5), add(4, 5, 6), UNIMP]);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 4), 5);
        assert_eq!(g(&mut env, 5), 7);
        assert_eq!(g(&mut env, 6), 12);
        assert_eq!(env.backend.get(sem::iaoq_f_ref()) & !3, 0x100c);
        assert_eq!(env.backend.get(sem::iaoq_b_ref()) & !3, 0x1010);
    }

    #[test]
    fn direct_branch_executes_delay_slot() {
        // bl +12,r0 → 遅延スロット（0x1004）は実行、0x1008/0x100c/0x1010
        // は飛ばして 0x1014 へ。
        let mut env = env_at(
            0x1000,
            &[
                bl(12, 0),    // 0x1000
                ldo(3, 0, 4), // 0x1004（遅延スロット）
                ldo(9, 0, 5), // 0x1008（飛ばされる）
                NOP,          // 0x100c
                NOP,          // 0x1010
                ldo(4, 0, 6), // 0x1014（分岐先）
                UNIMP,        // 0x1018
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1018),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 4), 3);
        assert_eq!(g(&mut env, 5), 0);
        assert_eq!(g(&mut env, 6), 4);
    }

    #[test]
    fn bl_links_r31_and_bv_returns() {
        // 0x1000: bl +8,r31（r31=0x1008|3 → 0x1010 へ）
        // 0x1004: ldo 1,r4（遅延）
        // 0x1008: ldo 2,r5（戻り先）
        // 0x100c: unimp
        // 0x1010: bv 0(r31) → r31 の番地へ戻る
        // 0x1014: ldo 3,r6（遅延）
        let mut env = env_at(
            0x1000,
            &[
                bl(8, 31),
                ldo(1, 0, 4),
                ldo(2, 0, 5),
                UNIMP,
                bv(31),
                ldo(3, 0, 6),
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 4), 1);
        assert_eq!(g(&mut env, 5), 2);
        assert_eq!(g(&mut env, 6), 3);
        assert_eq!(g(&mut env, 31) & !3, 0x1008);
    }

    #[test]
    fn comb_taken_forward_n_nullifies_delay_slot() {
        // comb,=,n r4,r5,+4（0x1000）: 前方・成立 → 遅延スロット無効化、
        // 分岐先は pc+8+4 = 0x100c。遅延の ldo 7 は実行されない。
        let mut env = env_at(
            0x1000,
            &[
                comb_eq_n(4, 5, 4), // 0x1000 → 成立 → 0x100c
                ldo(7, 0, 6),       // 0x1004（無効化される）
                NOP,                // 0x1008（飛ばされる）
                ldo(8, 0, 7),       // 0x100c（分岐先）
                UNIMP,              // 0x1010
            ],
        );
        set_g(&mut env, 4, 9);
        set_g(&mut env, 5, 9);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1010),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 6), 0); // 無効化
        assert_eq!(g(&mut env, 7), 8);
    }

    #[test]
    fn comb_not_taken_forward_n_executes_delay_slot() {
        // comb,=,n r4,r5,+4: 不成立 → `,n` でも前方・不成立は
        // 遅延スロットを実行し、分岐せず 0x1008 へ進む。
        let mut env = env_at(
            0x1000,
            &[
                comb_eq_n(4, 5, 4),
                ldo(7, 0, 6), // 実行される
                ldo(8, 0, 7),
                UNIMP,
            ],
        );
        set_g(&mut env, 4, 9);
        set_g(&mut env, 5, 1);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 6), 7);
        assert_eq!(g(&mut env, 7), 8);
    }

    #[test]
    fn fetch_requires_execute_perm() {
        // W-only ページへのフェッチは不可（命令語を読まず失敗）。
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b010))
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x2000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, word } => {
                assert_eq!(pc, 0x2000);
                assert_eq!(word, 0xffff_ffff);
            }
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn big_endian_fetch_reads_be_words() {
        // BE で並んだ語列が 1 命令ずつ解読されることの確認
        // （ストレートラインで 2 命令進む = 各語が独立に正しく読めた）。
        let mut env = env_at(0x3000, &[ldo(0x11, 0, 4), ldo(0x22, 0, 5), UNIMP]);
        let mut sys = NoSys;
        let out = run(&mut env, 0x3000, model(), &mut sys, None);
        assert!(matches!(out, Outcome::Unimplemented { .. }));
        assert_eq!(g(&mut env, 4), 0x11);
        assert_eq!(g(&mut env, 5), 0x22);
    }

    #[test]
    fn stp_gateway_sets_cr27_and_returns() {
        // ble 0xe0(sr2,r0) → 内蔵 STP: cr27 = r26 → r31 へ戻る。
        let mut env = env_at(0x1000, &[ble(0xe0, 2, 0), NOP, UNIMP]);
        set_g(&mut env, 26, 0xdead_beef);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(env.backend.get(sem::Cr(27).state()), 0xdead_beef);
    }

    #[test]
    fn syscall_gateway_exit_group() {
        // ble 0x100(sr2,r0) + Linux パーソナリティ → exit_group(42)。
        let mut env = env_at(0x1000, &[ble(0x100, 2, 0), NOP, UNIMP]);
        set_g(&mut env, 20, 222); // nr = exit_group
        set_g(&mut env, 26, 42); // arg0
        let mut sys = polyisa_os_linux::parisc::sys::Linux::new();
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Exit(code) => assert_eq!(code, 42),
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn syscall_gateway_write_captures_stdout() {
        // write(1, 0x2000, 4) → "hi!\n" が capture に載る。
        // ABI: nr=r20、fd=r26、buf=r25、len=r24、ret=r28。
        let mut env = env_at(0x1000, &[ble(0x100, 2, 0), NOP, UNIMP]);
        set_g(&mut env, 20, 4); // nr = write
        set_g(&mut env, 26, 1); // fd
        set_g(&mut env, 25, 0x2000); // buf
        set_g(&mut env, 24, 4); // len
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b011))
            .unwrap();
        env.backend.mem.write(VirtAddr(0x2000), b"hi!\n").unwrap();
        let mut sys = polyisa_os_linux::parisc::sys::Linux::new();
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(sys.io.stdout, b"hi!\n");
        assert_eq!(g(&mut env, 28), 4); // 戻り値 = 書いた長さ
    }

    #[test]
    fn lws_cas_succeeds_on_equal() {
        // lws-cas: *adr == old なら new を書く。ble 0xb0(sr2,r0)。
        let mut env = env_at(0x1000, &[ble(0xb0, 2, 0), NOP, UNIMP]);
        set_g(&mut env, 20, 0); // lws which=0
        set_g(&mut env, 26, 0x2000); // adr
        set_g(&mut env, 25, 0x1111_2222); // old
        set_g(&mut env, 24, 0x3333_4444); // new
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x2000), &0x1111_2222u32.to_be_bytes())
            .unwrap();
        let mut sys = polyisa_os_linux::parisc::sys::Linux::new();
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        let mut b = [0u8; 4];
        env.backend
            .mem
            .read(
                VirtAddr(0x2000),
                &mut b,
                Access {
                    endian: Endian::Be,
                    align: Align::Natural,
                    kind: AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(u32::from_be_bytes(b), 0x3333_4444);
        assert_eq!(g(&mut env, 28), 0x1111_2222); // 元値
        assert_eq!(g(&mut env, 21), 0); // 状態 = 成功
    }

    #[test]
    fn be_external_absolute_target() {
        // be 0x2000(sr0,r0): be は GR[b]+disp の絶対分岐（ble と同形）。
        let mut env = env_at(
            0x1000,
            &[
                0xe001_0000,  // be 0x2000(sr0,r0): w5=1 → i=0x800 → disp=0x2000
                ldo(1, 0, 4), // 遅延スロット
                UNIMP,        // 0x1008（飛ばされる）
            ],
        );
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        let mut body = Vec::new();
        for w in [ldo(6, 0, 7), UNIMP] {
            body.extend_from_slice(&w.to_be_bytes());
        }
        env.backend.mem.write(VirtAddr(0x2000), &body).unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1000, model(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x2004),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 4), 1); // 遅延スロットは実行済み
        assert_eq!(g(&mut env, 7), 6);
    }
}
