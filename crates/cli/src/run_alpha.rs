// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alpha AXP のフェッチから次のフェッチまで。
//!
//! 命令は32ビット固定長のリトルエンディアンで、遅延スロットは
//! 持たない（AArch64 と同じ素直な PC 前進モデル）。意味論が
//! `Ctrl::Jump` を置いたときはその値を次の pc にし、
//! `Fallthrough` のままなら pc+4 に進める。
//!
//! `call_pal` は機能番号を code に載せた Trap 例外として OS
//! パーソナリティへ委ねる（Handled なら pc+4 に復帰）。
//! Ref: SPEC-ALPHA-ARM.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_alpha::{Insn, decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind};

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct AlphaModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
}

impl AlphaModel {
    /// `CpuSel` から機能ビットだけを取る。
    #[must_use]
    pub fn from_sel(sel: &polyisa_isadl::select::CpuSel) -> Self {
        Self { feats: sel.feats }
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

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
/// `stack` はページフォルト駆動のスタック成長窓（不要なら `None`）。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: AlphaModel,
    sys: &mut impl TrapHandler,
    stack: Option<StackGrowth>,
) -> Outcome {
    env.pc = entry;
    let trace = std::env::var_os("POLYISA_ALPHA_TRACE").is_some();
    let mut hist = std::collections::VecDeque::with_capacity(512);
    let o = polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| {
            if trace {
                hist.push_back(env.pc);
                if hist.len() > 512 {
                    hist.pop_front();
                }
            }
            step_alpha(env, sys, model, stack)
        },
    );
    if trace && !matches!(o, Outcome::Exit(_)) {
        eprintln!(
            "alpha: last pcs: {}",
            hist.iter()
                .map(|p| format!("{p:#x}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        for i in [0u8, 9, 15, 16, 19, 26, 27, 29, 30] {
            eprintln!("  r{i} = {:#x}", env.backend.get(sem::Gpr(i).state()));
        }
    }
    o
}

/// 命令フェッチ用のアクセス属性。
const fn acc_fetch() -> Access {
    Access {
        endian: Endian::Le,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    }
}

/// 1 命令ぶんのフェッチ・解読・意味論。
// Ref: SPEC-ALPHA-ARM.
fn step_alpha(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: AlphaModel,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let pc = env.pc;
    let unimpl = |env: &BareEnv, word: u64| Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    };
    let mut b4 = [0u8; 4];
    if env
        .backend
        .mem
        .read(VirtAddr(pc), &mut b4, acc_fetch())
        .is_err()
    {
        return Err(unimpl(env, 0xffff_ffff));
    }
    let word = u32::from_le_bytes(b4);
    let Some(insn) = decode_model_ex(u128::from(word), 32, false, model.feats) else {
        return Err(unimpl(env, u64::from(word)));
    };
    let r = env.step(|b| sem::exec(b, insn, word, pc));
    // rpcc が読む疑似サイクルカウンタを1命令ぶん進める。例外発生でも
    // その命令は消費されたので、完了したステップは全て数える。
    let c = env.backend.get(sem::cycle_ref());
    env.backend.set(sem::cycle_ref(), c + 1);
    match r {
        Ok(true) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
                env.pc += 4;
            }
            Ok(())
        }
        // `exec` が受けなかった命令（この段階の範囲外）。
        Ok(false) => Err(unimpl(env, u64::from(word))),
        // call_pal は OS パーソナリティへ。Handled なら pc+4 に復帰。
        // 命令語で分別しないと /v 算術例外（code=1）の Trap が
        // call_pal 1 に化けるため、insn == CallPal で絞る。
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap && insn == Insn::CallPal => {
            match sys.handle_trap(env, e.code as u32) {
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
                TrapOutcome::Unimplemented => Err(unimpl(env, u64::from(word))),
            }
        }
        // ページフォルトはスタック成長窓の内側なら写像を伸ばして
        // 同一命令をやり直す（pc はまだ進んでいない）。
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::PageFault => {
            if stack_grow(env, stack, &e).is_some() {
                Ok(())
            } else {
                Err(unimpl(env, u64::from(word)))
            }
        }
        // PAL 予約オペコードの Undefined など。その他の例外は
        // この段階では未実装に写す。
        Err(InterpExit::Exception(_)) | Err(InterpExit::Unimplemented(_)) => {
            Err(unimpl(env, u64::from(word)))
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
    let lo = a & !(PAGE_SIZE - 1);
    let mut hi = lo;
    while hi < s.top && !env.backend.mem.is_mapped(PageNo(hi / PAGE_SIZE)) {
        hi += PAGE_SIZE;
    }
    let pages = (hi - lo) / PAGE_SIZE;
    if pages == 0 {
        return None;
    }
    env.backend.mem.map(VirtAddr(lo), pages, Perms::RW).ok()
}

/// ELF64・EM_ALPHA_EXP（0x9026）の静的実行。
/// `sys` がなければ `call_pal` で止まるため、OS パーソナリティ
/// なしの裸実行は動作確認用の入口。
pub fn run_elf_alpha(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_alpha_sel(path, argv, None)
}

/// `--cpu` で解決したモデルを指定する `run_elf_alpha`。
pub fn run_elf_alpha_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    let (mut env, entry, model, ..) = setup_alpha_elf(path, argv, sel)?;
    let growth = Some(StackGrowth {
        top: STACK_TOP,
        limit: STACK_TOP - STACK_LIMIT,
    });
    finish(run(&mut env, entry, model, &mut NoSys, growth))
}

/// 終了コードと標準出力の捕獲を返す。
pub fn run_elf_alpha_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    run_elf_alpha_captured_in(path, argv, &[])
}

/// 標準入力 `stdin` を与えて実行し、終了コードと標準出力の捕獲を返す。
/// 標準エラーを検査するときは `run_elf_alpha_sys` で `sys.io.stderr`
/// を読む。
pub fn run_elf_alpha_captured_in(
    path: &str,
    argv: &[String],
    stdin: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let mut sys = polyisa_os_linux::alpha::sys::Linux::new();
    sys.stdin_buf = stdin.to_vec();
    let code = run_elf_alpha_sys(path, argv, None, &mut sys)?;
    Ok((code, sys.io.stdout))
}

/// Linux パーソナリティとモデルを指定する `run_elf_alpha`。
pub fn run_elf_alpha_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut polyisa_os_linux::alpha::sys::Linux,
) -> Result<u64, String> {
    let (mut env, entry, model, image_end) = setup_alpha_elf(path, argv, sel)?;
    sys.init_brk(image_end);
    // /proc/self/exe の readlink は絶対パスを返す規約。
    sys.exe_path = std::fs::canonicalize(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.to_string());
    let growth = Some(StackGrowth {
        top: STACK_TOP,
        limit: STACK_TOP - STACK_LIMIT,
    });
    finish(run(&mut env, entry, model, sys, growth))
}

/// スタック上端。カーネルの STACK_TOP_MAX（0x0012_0000_0000）と
/// 同値にする。TASK_SIZE は 42 ビットユーザ空間（0x400_0000_0000）。
// Ref: SRC-LINUX (7.3) — arch/alpha/include/asm/processor.h.
const STACK_TOP: u64 = 0x0001_2000_0000;
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
fn setup_alpha_elf(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<(BareEnv, u64, AlphaModel, u64), String> {
    use polyisa_mem::PAGE_SIZE;
    use polyisa_sem::Backend as _;

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let ehdr = polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_ALPHA_EXP=0x9026。Ref: binutils include/elf/common.h.
    if ehdr.machine != 0x9026 {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    if !ehdr.little {
        return Err("Alpha はリトルエンディアンのみ対応".to_string());
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("PT_INTERP のある Alpha ELF は未対応（静的のみ）".to_string());
    }
    // `--cpu` 省略時は 21264（EV6 世代 = BWX/FIX/CIX/MVI 全搭載）。
    let default_sel;
    let sel = match sel {
        Some(s) => s,
        None => {
            default_sel = polyisa_isadl::select::resolve(
                polyisa_guest_alpha::MODEL_DEFS,
                polyisa_guest_alpha::FEATURE_DEFS,
                polyisa_guest_alpha::FEAT_BITS,
                "21264",
                &[],
                &[],
            )
            .map_err(|e| format!("alpha: {e}"))?;
            &default_sel
        }
    };
    let model = AlphaModel::from_sel(sel);
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_alpha::CpuState>());
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
            const PHENT: u64 = 56; // ELF64 の phdr は 56 バイト固定。
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
    let img_top = STACK_TOP - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // 最小限のスタック（argc/argv/auxv）は Linux の初期化と同じ
    // 配置にする。
    let auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),             // AT_PHDR
        (4, 56),                    // AT_PHENT
        (5, u64::from(ehdr.phnum)), // AT_PHNUM
        (6, 0x2000),                // AT_PAGESZ（Alpha Linux のページは 8KiB）
        (9, entry),                 // AT_ENTRY
        (11, 0),                    // AT_UID
        (12, 0),                    // AT_EUID
        (13, 0),                    // AT_GID
        (14, 0),                    // AT_EGID
        (17, 100),                  // AT_CLKTCK
        (23, 0),                    // AT_SECURE
    ];
    let (img, sp) =
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &[], &auxv, Endian::Le);
    // 初期スタックは像の分だけ写像し、下方向はページフォルト駆動で
    // `STACK_LIMIT` まで伸ばす。glibc は起動時の大きなフレーム確保で
    // `stq r31,-N(r30)` のプローブを打つため、伸長は必須。
    let stack_base = sp & !(PAGE_SIZE - 1);
    let stack_pages = (STACK_TOP - stack_base) / PAGE_SIZE;
    env.backend
        .mem
        .map(VirtAddr(stack_base), stack_pages, Perms::RW)
        .map_err(|_| "スタックの写像に失敗".to_string())?;
    env.backend
        .mem
        .write(VirtAddr(sp), &img)
        .map_err(|_| "スタックの書き込みに失敗".to_string())?;
    // r30 = sp が ABI のエントリ条件（argc/argv 領域を指す）。
    env.backend.set(sem::Gpr(30).state(), sp);
    Ok((env, entry, model, image_end))
}

/// PAL/syscall を受けないスタブ。`call_pal` で止めるだけの
/// 裸実行（`NoSys`）に使う。
pub struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 語列（32ビット LE）を RX として写像した環境。`base` が入口。
    fn env_at(base: u64, words: &[u32]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_alpha::CpuState>());
        env.backend
            .mem
            .map(VirtAddr(base & !0xFFF), 1, Perms(0b111))
            .unwrap();
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        env.backend.mem.write(VirtAddr(base), &bytes).unwrap();
        env
    }

    /// 全機能を持つモデル（テストはデコードの上限を見るだけ）。
    const ALL_FEATS: u128 = polyisa_guest_alpha::FEAT_EV5
        | polyisa_guest_alpha::FEAT_EV56
        | polyisa_guest_alpha::FEAT_EV7
        | polyisa_guest_alpha::FEAT_BWX
        | polyisa_guest_alpha::FEAT_FIX
        | polyisa_guest_alpha::FEAT_CIX
        | polyisa_guest_alpha::FEAT_MVI;

    /// `lda ra, disp(rb)` の手エンコード（op=001000）。
    const fn lda(ra: u32, rb: u32, disp: u32) -> u32 {
        (0x08 << 26) | (ra << 21) | (rb << 16) | (disp & 0xffff)
    }

    #[test]
    fn lda_sequence_advances_pc() {
        // lda r1, 42(r31); lda r2, -1(r31)。続きの語は 0 →
        // call_pal 0 として Trap を上げ、NoSys が受けないので停止。
        let mut env = env_at(0x1000, &[lda(1, 31, 42), lda(2, 31, 0xffff)]);
        let mut sys = NoSys;
        match run(
            &mut env,
            0x1000,
            AlphaModel { feats: ALL_FEATS },
            &mut sys,
            None,
        ) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(env.backend.get(sem::Gpr(1).state()), 42);
        assert_eq!(env.backend.get(sem::Gpr(2).state()), -1i64 as u64);
    }

    #[test]
    fn br_links_and_jumps() {
        // br r31, +4 → pc+4+4 で 3 語目（0x1008）へ（2 語目を飛ばす）。
        // 0x100c の語は 0 → call_pal 0 として Trap → NoSys 未受理で停止。
        //   op=110000 ra=11111 disp=1 → (0x30<<26)|(31<<21)|1
        let mut env = env_at(
            0x1000,
            &[
                0xc3e0_0001,   // br r31, +4 → 0x1008
                lda(1, 31, 5), // 飛ばされる
                lda(1, 31, 7),
            ],
        );
        let mut sys = NoSys;
        match run(
            &mut env,
            0x1000,
            AlphaModel { feats: ALL_FEATS },
            &mut sys,
            None,
        ) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(env.backend.get(sem::Gpr(1).state()), 7);
        // r31 へのリンクは破棄される。
        assert_eq!(env.backend.get(sem::Gpr(31).state()), 0);
    }

    #[test]
    fn call_pal_is_trap() {
        // call_pal 0x83（callsys）→ Trap(code=0x83) を NoSys が
        // 受けないので Unimplemented になる。
        let mut env = env_at(0x1000, &[0x0000_0083]);
        let mut sys = NoSys;
        match run(
            &mut env,
            0x1000,
            AlphaModel { feats: ALL_FEATS },
            &mut sys,
            None,
        ) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1000),
            o => panic!("unexpected outcome: {o:?}"),
        }
    }
}
