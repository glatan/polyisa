// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC のフェッチから次のフェッチまで。遅延スロットは分岐と同じステップで実行する。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する。
//! 分岐は `npc` だけを書き換え、pc+4 からフェッチした遅延スロットを実行してから
//! `commit` で pc を npc に進める。annul が立っていれば遅延スロットは実行しない。
//! 遅延スロット内の制御転送（DCTI couple）は、各 CTI の遅延スロットを順に
//! 実行し、最後の CTI が書いた npc を着地点とする連鎖として扱う（V9 準拠の
//! 実装選択。V8 では結果不定）。
//! Ref: SPEC-SPARC-V8 (Version 8).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::InterpExit;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_sparc::sem;
use polyisa_guest_sparc::{Insn, Params, decode_model_ex};
use polyisa_mem::{Access, AccessKind, Align, Endian, VirtAddr};
use polyisa_sem::{Backend as _, ExceptionKind, StateRef, W64};

// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// `top` はスタック上端、`limit` は下向き成長の下限（RLIMIT_STACK 相当）。
/// 窓 `[limit, top)` 内の未写像ページへのフォルトで写像を伸ばす。
#[derive(Clone, Copy)]
pub struct StackGrowth {
    pub top: u64,
    pub limit: u64,
}

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct SparcModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
    /// 意味論が `b.param` で読む挙動パラメータ。
    pub params: Params,
    /// アドレスバスのマスク。SPARC32（V7/V8）は 32 ビット、V9 は 64 ビット。
    pub addr_mask: u64,
    /// `decode_model_ex` の 64 ビット指定。`word64` モデルで真。
    pub is64: bool,
}

impl SparcModel {
    /// SPARC V8 の既定モデル。
    #[must_use]
    pub const fn v8() -> Self {
        Self {
            feats: polyisa_guest_sparc::FEAT_V7 | polyisa_guest_sparc::FEAT_V8,
            params: polyisa_guest_sparc::DEFAULT_PARAMS,
            addr_mask: 0xFFFF_FFFF,
            is64: false,
        }
    }

    /// モデル名（`MODELS` のいずれか）から解決する。
    /// 未知の名前は既定パラメータのモデルになる。
    #[must_use]
    pub fn named(name: &str) -> Self {
        let params = polyisa_guest_sparc::model_params(name);
        Self {
            feats: polyisa_guest_sparc::model_feats(name),
            addr_mask: if params.word64 { u64::MAX } else { 0xFFFF_FFFF },
            is64: params.word64,
            params,
        }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
/// `stack` はページフォルト駆動のスタック成長窓（不要なら `None`）。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: SparcModel,
    sys: &mut impl TrapHandler,
    stack: Option<StackGrowth>,
) -> Outcome {
    polyisa_guest_sparc::install_params(&mut env.backend, &model.params);
    env.backend.addr_mask = model.addr_mask;
    env.pc = entry;
    set_u64(env, sem::pc_ref().offset(), entry & model.addr_mask);
    set_u64(
        env,
        sem::npc_ref().offset(),
        entry.wrapping_add(4) & model.addr_mask,
    );
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| get_u64(env, sem::pc_ref().offset()),
        |env, sys| step(env, sys, model, stack),
    )
}

/// 遅延スロットを持つ命令か。Bicc・CALL・JMPL・V9 の RETURN が
/// 該当する。
/// Ref: SPEC-SPARC-V8 (Version 8) §Control-Transfer Instructions;
/// SPEC-SPARC-V9 §RETURN.
fn has_delay_slot(insn: Insn) -> bool {
    matches!(
        insn,
        Insn::Bicc
            | Insn::Bpcc
            | Insn::Bpr
            | Insn::Fbfcc
            | Insn::Fbpfcc
            | Insn::Call
            | Insn::Jmpl
            | Insn::JmplI
            | Insn::Return
            | Insn::ReturnI
    )
}

/// 1 命令ぶんのフェッチ・解読・意味論。遅延スロットは分岐と同じ
/// 呼び出しの内側で実行する。
fn step(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: SparcModel,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let pc = get_u64(env, sem::pc_ref().offset()) & model.addr_mask;
    // 命令フェッチは 4 バイト整列。非整列なら
    // mem_address_not_aligned（tt=0x07）を通常のトラップ経路で配送する。
    if pc & 3 != 0 {
        env.backend.set(sem::tt_ref(), 0x07);
        return finish(
            env,
            sys,
            InterpExit::Exception(polyisa_sem::GuestException {
                kind: ExceptionKind::Trap,
                code: 0,
                addr: Some(pc),
                in_delay_slot: false,
            }),
            pc,
            0,
            stack,
        );
    }
    let word = match fetch(env, pc) {
        Some(w) => w,
        None => {
            return Err(Outcome::Unimplemented {
                pc,
                word: 0xffff_ffff,
            });
        }
    };
    let Some(insn) = decode_model_ex(u128::from(word), 32, model.is64, model.feats) else {
        return Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        });
    };
    if let Err(e) = env.step(|b| sem::exec(b, insn, word, pc)) {
        return finish(env, sys, e, pc, word, stack);
    }
    if has_delay_slot(insn) {
        return delay(env, sys, model, pc, word, stack);
    }
    commit(env, pc, word)
}

/// 遅延スロットの実行。スロットの命令は pc+4 からフェッチし、
/// annul が立っていなければ実行してから commit する。スロット内の
/// 例外は `in_delay_slot` を立てて戻す。
/// スロットが制御転送命令（DCTI couple）のときは連鎖として扱う。
/// V8 は結果を不定とするので、V9 の pc/npc パイプラインに倣い、
/// 各 CTI の遅延スロットを順に実行し、最後の CTI が書いた npc を
/// 着地点とする定義済みの動作を選ぶ。
/// Ref: SPEC-SPARC-V9 (Version 9) Table "DCTI Couples".
fn delay(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: SparcModel,
    pc: u64,
    word: u32,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    let mut slot_pc = pc.wrapping_add(4) & model.addr_mask;
    loop {
        // annul が立っていればスロットの命令自体を読まない。取り消された
        // 命令のフェッチや解読は実機でも起きないため、未写像や DCTI 語で
        // 止まってはいけない。
        if get_u64(env, sem::annul_ref().offset()) != 0 {
            return env.step(|b| sem::delay_slot(b, |_| Ok(()))).map_err(|_| {
                Outcome::Unimplemented {
                    pc,
                    word: u128::from(word),
                }
            });
        }
        let Some(slot_word) = fetch(env, slot_pc) else {
            return Err(Outcome::Unimplemented {
                pc: slot_pc,
                word: 0xffff_ffff,
            });
        };
        let Some(slot_insn) = decode_model_ex(u128::from(slot_word), 32, model.is64, model.feats)
        else {
            return Err(Outcome::Unimplemented {
                pc: slot_pc,
                word: u128::from(slot_word),
            });
        };
        let coupled = has_delay_slot(slot_insn);
        let r = env.step(|b| {
            sem::delay_slot_exec(b, |bb| {
                let r = sem::exec(bb, slot_insn, slot_word, slot_pc);
                if let Err(e) = &r
                    && let InterpExit::Exception(g) = e
                {
                    let mut g = *g;
                    g.in_delay_slot = true;
                    return Err(InterpExit::Exception(g));
                }
                r
            })
        });
        if let Err(e) = r {
            return finish(env, sys, e, pc, word, stack);
        }
        // スロットが制御転送命令なら、その遅延スロットを次に実行する
        // 連鎖を続ける。そうでなければ 1 回だけ commit して終わる。
        if !coupled {
            return commit(env, pc, word);
        }
        slot_pc = slot_pc.wrapping_add(4) & model.addr_mask;
    }
}

/// 例外を OS パーソナリティか `Outcome` に写す。Trap 系は
/// `handle_trap` に委ね、それ以外は未実装として止める。
fn finish(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    e: InterpExit,
    pc: u64,
    word: u32,
    stack: Option<StackGrowth>,
) -> Result<(), Outcome> {
    if let InterpExit::Exception(g) = e {
        if stack_grow(env, stack, &g).is_some() {
            return Ok(());
        }
        if g.kind == ExceptionKind::Trap {
            match sys.handle_trap(env, g.code as u32) {
                // 処理済みの復帰 PC はハンドラが設定済みの契約。
                TrapOutcome::Handled => return Ok(()),
                TrapOutcome::Exit(code) => {
                    if sys.take_exit(env, code) {
                        return Ok(());
                    }
                    return Err(Outcome::Exit(u64::from(code)));
                }
                TrapOutcome::Blocked => {
                    if sys.on_block(env) {
                        return Ok(());
                    }
                    return Err(Outcome::Deadlock);
                }
                TrapOutcome::Unimplemented => {}
            }
        }
    }
    Err(Outcome::Unimplemented {
        pc,
        word: u128::from(word),
    })
}

/// スタック成長窓の内側へのページフォルトなら写像を伸ばす。
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
        .map(
            VirtAddr(lo),
            pages,
            polyisa_mem::Perms(polyisa_mem::Perms::R.0 | polyisa_mem::Perms::W.0),
        )
        .ok()
}

/// 遅延スロットのない命令の完了。pc を npc に進める。
fn commit(env: &mut BareEnv, pc: u64, word: u32) -> Result<(), Outcome> {
    match env.step(sem::commit) {
        Ok(()) => Ok(()),
        Err(_) => Err(Outcome::Unimplemented {
            pc,
            word: u128::from(word),
        }),
    }
}

/// 命令のフェッチ。BE・自然整列で 4 バイト読む。
fn fetch(env: &BareEnv, pc: u64) -> Option<u32> {
    let mut buf = [0u8; 4];
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    env.backend.mem.read(VirtAddr(pc), &mut buf, acc).ok()?;
    Some(u32::from_be_bytes(buf))
}

fn get_u64(env: &mut BareEnv, offset: usize) -> u64 {
    env.backend.get(StateRef::<W64>::from_offset(offset))
}

fn set_u64(env: &mut BareEnv, offset: usize, value: u64) {
    env.backend.set(StateRef::<W64>::from_offset(offset), value);
}

/// SPARC の Linux ELF を実行する。sparc32 は EM_SPARC /
/// EM_SPARC32PLUS の ELFCLASS32、sparc64 は EM_SPARCV9 の
/// ELFCLASS64 で、どちらもビッグエンディアンの静的リンクのみ。
// Ref: SRC-LINUX (7.3), SPEC-ELF-GABI, SPEC-SPARC-V9 §Software Considerations.
pub fn run_elf_sparc(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_sparc_sys(path, argv, &mut polyisa_os_linux::sparc::sys::Linux::new())
}

/// 終了コードと標準出力の捕獲を返す。
pub fn run_elf_sparc_captured(path: &str, argv: &[String]) -> Result<(u64, Vec<u8>), String> {
    run_elf_sparc_captured_in(path, argv, &[])
}

/// 標準入力 `stdin` を与えて実行し、終了コードと標準出力の捕獲を返す。
/// 標準エラーを検査するときは `run_elf_sparc_sys` で `sys.io.stderr`
/// を読む。
pub fn run_elf_sparc_captured_in(
    path: &str,
    argv: &[String],
    stdin: &[u8],
) -> Result<(u64, Vec<u8>), String> {
    let mut sys = polyisa_os_linux::sparc::sys::Linux::new();
    sys.stdin_buf = stdin.to_vec();
    let code = run_elf_sparc_sys(path, argv, &mut sys)?;
    Ok((code, sys.io.stdout))
}

/// `sys` の状態を引き継いで SPARC の Linux ELF を実行する。
pub fn run_elf_sparc_sys(
    path: &str,
    argv: &[String],
    sys: &mut polyisa_os_linux::sparc::sys::Linux,
) -> Result<u64, String> {
    use polyisa_mem::{PAGE_SIZE, Perms};
    use polyisa_sem::Backend as _;

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    // EM_SPARC=2, EM_SPARC32PLUS=18, EM_SPARCV9=43。
    // Ref: SRC-LINUX (include/uapi/linux/elf-em.h).
    let (ehdr, phdrs, phent, model, top) = match bytes.get(4) {
        Some(1) => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            if !matches!(ehdr.machine, 2 | 18) {
                return Err(format!("未対応の e_machine: {}", ehdr.machine));
            }
            let phdrs = polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr)
                .map_err(|e| format!("phdrs: {e:?}"))?;
            // Linux の sparc32 ユーザランドは V8 命令集合を使う。
            // スタック上端は実機の TASK_SIZE（0xf000_0000）に合わせる。
            (ehdr, phdrs, 32u64, SparcModel::named("v8"), 0xf000_0000u64)
        }
        Some(2) => {
            let ehdr =
                polyisa_loader::elf::parse_ehdr(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
            if ehdr.machine != 43 {
                return Err(format!("未対応の e_machine: {}", ehdr.machine));
            }
            let phdrs = polyisa_loader::elf::parse_phdrs(&bytes, &ehdr)
                .map_err(|e| format!("phdrs: {e:?}"))?;
            (
                ehdr,
                phdrs,
                56u64,
                SparcModel::named("ultrasparc3"),
                // 実機の STACK_TOP64（2^43 - 2^32）に合わせる。
                0x0000_07ff_0000_0000u64,
            )
        }
        _ => return Err("ELFCLASS32/64 ではない".to_string()),
    };
    if ehdr.little {
        return Err("SPARC はビッグエンディアンのみ対応".to_string());
    }
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("PT_INTERP のある SPARC ELF は未対応（静的のみ）".to_string());
    }
    let is64 = model.is64;
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_sparc::CpuState>());
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
            let hi = lo + ehdr.phnum as usize * phent as usize;
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
    let img_top = top - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    let auxv: Vec<(u64, u64)> = vec![
        (3, phdr_addr),             // AT_PHDR
        (4, phent),                 // AT_PHENT
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
    let (img, sp) = if is64 {
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &[], &auxv, Endian::Be)
    } else {
        polyisa_os_linux::build_initial_stack32_endian(img_top, &arg_bytes, &[], &auxv, Endian::Be)
    };
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
    // 初期 %sp は見える番号の %o6 に入る。CWP=0 の物理位置は o6 と
    // 一致する。カーネル規約では先頭にレジスタ保存領域があり argc
    // はその直後に置く。保存領域は sparc32 が 16×4=64 バイト、
    // sparc64 が 16×8=128 バイトで、V9 では加えて ABI の
    // STACK_BIAS（2047）を引く。
    // Ref: SPEC-SPARC-V9 §STACK_BIAS, SRC-LINUX.
    let o6 = if is64 { sp - 128 - 2047 } else { sp - 64 };
    env.backend.set(sem::Gpr(14).state(), o6);
    // 初期ウィンドウ状態。現窓だけ使用中で残りは空きにする。
    // cansave は NWINDOWS-2 が規約。CANSAVE+CANRESTORE+OTHERWIN の
    // 和が NWINDOWS-2 であり、現窓と ins/outs が他窓と重なって
    // 未使用でなければならない overlap 窓の 2 窓は計上しない。
    // Ref: SPEC-SPARC-V9 §Overlapping Windows, SRC-LINUX.
    let nw = u64::from(model.params.nwindows);
    env.backend.set(sem::cansave_ref(), nw - 2);
    if is64 {
        // Linux は起動時から FPU を使える状態でユーザを走らせる
        // （PSTATE.PEF + FPRS.FEF）。
        env.backend.set(sem::tstate_ref(), 1 << 12);
        env.backend.set(sem::fprs_ref(), 0b100);
    } else {
        // V8 も同じく PSR.EF（bit 12）を立てて FPU を有効にする。
        env.backend.set(sem::psr_ref(), 1 << 12);
    }
    // /proc/self/exe の readlink は絶対パスを返す規約。
    sys.exe_path = std::fs::canonicalize(path)
        .map_or_else(|_| path.to_string(), |p| p.to_string_lossy().into_owned());
    sys.init_brk(image_end);
    // 初期スタックは像の分だけ写像し、下方向はページフォルト駆動で
    // RLIMIT_STACK 既定値（8 MiB）まで伸ばす。
    const STACK_LIMIT: u64 = 8 << 20;
    let growth = Some(StackGrowth {
        top,
        limit: top - STACK_LIMIT,
    });
    // パーソナリティ側の窓退避・復帰がフォルトしたときも同じ窓で
    // 伸ばせるよう、境界を教えておく。
    sys.stack_top = top;
    sys.stack_limit = top - STACK_LIMIT;
    let out = run(&mut env, entry, model, sys, growth);
    match out {
        Outcome::Exit(code) => Ok(code),
        Outcome::Unimplemented { pc, word } => Err(format!("unimplemented at {pc:#x}: {word:#x}")),
        Outcome::StepLimit { pc } => Err(format!("step limit at {pc:#x}")),
        Outcome::Deadlock => Err("deadlock".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_guest_sparc::{CpuState, sem::Gpr};

    /// プログラム語列を `base` に置いた裸実行環境。
    fn env_at(base: u64, words: &[u32]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(VirtAddr(base & !0xFFF), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_be_bytes());
        }
        env.backend.mem.write(VirtAddr(base), &bytes).unwrap();
        env
    }

    /// 何もしないハンドラ。trap 委譲のない裸実行に使う。
    struct NoSys;

    impl TrapHandler for NoSys {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
    }

    fn g(env: &mut BareEnv, r: u8) -> u64 {
        env.backend.get(Gpr(r).state())
    }

    #[test]
    fn straight_line_runs_to_unimp() {
        // sethi 1,%g1; add %g1,3,%g2; unimp → g2=0x403 で未実装停止。
        let mut env = env_at(0x1000, &[0x0300_0001, 0x8400_6003, 0x0000_0000]);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x400);
        assert_eq!(g(&mut env, 2), 0x403);
    }

    #[test]
    fn branch_runs_delay_slot_then_jumps() {
        // ba +12: 遅延スロットの sethi は実行し、0x1008 の sethi %g3 は飛ばす。
        // 0x100c: add %g1,3,%g2; 0x1010: unimp。
        let mut env = env_at(
            0x1000,
            &[
                0x1080_0003, // ba +12
                0x0300_0001, // sethi 1,%g1（遅延スロット）
                0x0600_0009, // sethi 9,%g3（飛ばされる）
                0x8400_6003, // add %g1,3,%g2
                0x0000_0000, // unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1010),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x400);
        assert_eq!(g(&mut env, 2), 0x403);
        assert_eq!(g(&mut env, 3), 0);
    }

    #[test]
    fn annulled_branch_skips_delay_slot() {
        // ba,a +8: 遅延スロットの sethi は取り消される。
        let mut env = env_at(0x1000, &[0x3080_0002, 0x0300_0009, 0x0000_0000]);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0);
    }

    #[test]
    fn annulled_branch_never_fetches_slot() {
        // ba,a のスロットが未写像でも、取り消される命令は読まない。
        // ba,a を 0x1FFC（スロットは未写像の 0x2000）に置き、
        // 0x3000 の unimp へ飛ぶ。
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        env.backend
            .mem
            .map(VirtAddr(0x1000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .map(VirtAddr(0x3000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        // ba,a +0x1004（0x1FFC + 0x1004 = 0x3000）。
        env.backend
            .mem
            .write(VirtAddr(0x1FFC), &0x3080_0401u32.to_be_bytes())
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x3000), &0x0000_0000u32.to_be_bytes())
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1FFC, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x3000),
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn not_taken_branch_falls_through_delay_slot() {
        // ICC=0 で be は不成立。遅延スロットは実行し pc+8 へ進む。
        let mut env = env_at(
            0x1000,
            &[0x0280_0002, 0x0300_0001, 0x8400_6003, 0x0000_0000],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x400);
        assert_eq!(g(&mut env, 2), 0x403);
    }

    #[test]
    fn annulled_cond_branch_not_taken_skips_slot() {
        // Z=0 で be,a は不成立。遅延スロットは取り消され pc+8 へ進む。
        let mut env = env_at(
            0x1000,
            &[
                0x2280_0002, // be,a +8
                0x0300_0009, // sethi 9,%g1（取り消される）
                0x0500_0001, // sethi 1,%g2
                0x0000_0000, // unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0);
        assert_eq!(g(&mut env, 2), 0x400);
    }

    #[test]
    fn annulled_cond_branch_taken_runs_slot() {
        // Z=1 で be,a は成立。成立時は a にかかわらずスロットを実行し、
        // 0x1020 へ飛ぶ。0x1008-0x101c の命令は実行されない。
        let mut env = env_at(
            0x1000,
            &[
                0x2280_0008, // be,a 0x1020
                0x0300_0009, // sethi 9,%g1（遅延スロット）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000, // unimp（飛ばされる）
                0x0900_0001, // 0x1020: sethi 1,%g4
                0x0000_0000, // 0x1024: unimp
            ],
        );
        env.backend.set(sem::psr_ref(), 1 << 22);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1024),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x2400);
        assert_eq!(g(&mut env, 4), 0x400);
    }

    #[test]
    fn call_writes_o7_and_jumps() {
        // call 0x1020。%o7 に戻り（0x1000）を書き、遅延スロット実行後
        // 0x1020 へ飛ぶ。
        let mut env = env_at(
            0x1000,
            &[
                0x4000_0008, // call 0x1020
                0x0300_0009, // sethi 9,%g1（遅延スロット）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000, // 0x1020: unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1020),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 15), 0x1000);
        assert_eq!(g(&mut env, 1), 0x2400);
    }

    #[test]
    fn jmpl_jumps_after_delay_slot() {
        // jmpl %g1, %g0 に %g1=0x1020 を仕込んで実行。間接飛び先へ
        // 遅延スロットを挟んで進む。
        let mut env = env_at(
            0x1000,
            &[
                0x81c0_6000, // jmpl %g1+0, %g0
                0x0500_0009, // sethi 9,%g2（遅延スロット）
                0x0000_0000, // unimp（飛ばされる）
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000, // 0x1020: unimp
            ],
        );
        env.backend.set(Gpr(1).state(), 0x1020);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1020),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 2), 0x2400);
    }

    #[test]
    fn dcti_couple_chains_through_delay_slots() {
        // ba 0x1F00; ba 0x2000 の DCTI couple。V9 に倣い各遅延
        // スロットを実行し、npc は最後の CTI（0x2000）が効く。
        // 外側の飛び先 0x1F00 は実行されない。
        let mut words = vec![0x0000_0000u32; 0x400];
        words[0] = 0x1080_03c0; // 0x1000: ba 0x1F00
        words[1] = 0x1080_03ff; // 0x1004: ba 0x2000
        words[2] = 0x0300_0005; // 0x1008: sethi 5,%g1（内側のスロット）
        words[0x3c0] = 0x0500_0007; // 0x1F00: sethi 7,%g2（実行されない）
        let mut env = env_at(0x1000, &words);
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x2000), &0x0000_0000u32.to_be_bytes())
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x2000),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x1400);
        assert_eq!(g(&mut env, 2), 0);
    }

    /// トラップ番号を `tt` から読むハンドラ。番号は実行時値なので
    /// 例外の code ではなく TBR.tt 相当の状態フィールドに積まれる。
    struct TtSys;

    impl TrapHandler for TtSys {
        fn handle_trap(&mut self, env: &mut BareEnv, _code: u32) -> TrapOutcome {
            let tt = env.backend.get(sem::tt_ref());
            TrapOutcome::Exit(tt as u32)
        }
    }

    #[test]
    fn ta_passes_trap_number_through_tt() {
        // ta 0x10。tt に 0x80 + 0x10 が積まれてハンドラへ渡る。
        let mut env = env_at(0x1000, &[0x91d0_2010]);
        let mut sys = TtSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Exit(code) => assert_eq!(code, 0x90),
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn ticc_not_taken_continues() {
        // ICC=0 で te は不成立。次の命令へ進む。
        let mut env = env_at(
            0x1000,
            &[
                0x83d0_2010, // te 0x10（cond=1 不成立）
                0x0300_0001, // sethi 1,%g1
                0x0000_0000, // unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1008),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0x400);
    }

    #[test]
    fn wry_rdy_round_trip_in_loop() {
        // wry で %y を書き rdy で読む。
        let mut env = env_at(
            0x1000,
            &[
                0x0300_1234, // sethi 0x1234,%g1
                0x8180_6fff, // wr %g1, 0xfff, %y（0x48d000 ^ 0xfff）
                0x8540_0000, // rd %y, %g2
                0x0000_0000, // unimp
            ],
        );
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x100c),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 2), 0x0048_dfff);
    }

    #[test]
    fn rdpsr_traps_in_user_mode() {
        // rd %psr, %g5 は特権命令。ユーザーモードでは tt=3 でハンドラへ。
        let mut env = env_at(0x1000, &[0x8b48_0000]);
        let mut sys = TtSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Exit(code) => assert_eq!(code, 3),
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn dcti_couple_inner_annul_skips_its_slot() {
        // ba 0x1F00; ba,a 0x2000。内側の annul で 0x1008 は取り消され、
        // そのまま 0x2000 へ進む。
        let mut env = env_at(
            0x1000,
            &[
                0x1080_03c0, // 0x1000: ba 0x1F00
                0x3080_03ff, // 0x1004: ba,a 0x2000
                0x0300_0005, // 0x1008: sethi 5,%g1（取り消される）
            ],
        );
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, polyisa_mem::Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x2000), &0x0000_0000u32.to_be_bytes())
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1000, SparcModel::v8(), &mut sys, None) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x2000),
            o => panic!("unexpected outcome: {o:?}"),
        }
        assert_eq!(g(&mut env, 1), 0);
    }

    /// 物理スロット番号 `i` を読む。
    fn slot_get(env: &mut BareEnv, i: usize) -> u64 {
        env.backend.get(StateRef::<W64>::from_offset(
            core::mem::offset_of!(CpuState, g) + i * 8,
        ))
    }

    /// 物理スロット番号 `i` に書く。
    fn slot_set(env: &mut BareEnv, i: usize, v: u64) {
        env.backend.set(
            StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, g) + i * 8),
            v,
        );
    }

    /// メモリ `addr` から BE u32 を読む。
    fn mem_u32(env: &BareEnv, addr: u64) -> u32 {
        let mut b = [0u8; 4];
        let acc = Access {
            endian: Endian::Be,
            align: Align::Unaligned,
            kind: AccessKind::DataRead,
        };
        env.backend.mem.read(VirtAddr(addr), &mut b, acc).unwrap();
        u32::from_be_bytes(b)
    }

    /// `ta n` のトラップを Linux パーソナリティへ渡す。
    #[test]
    fn linux_window_spill_and_fill_round_trip() {
        use polyisa_os_linux::sparc::sys::Linux;
        let mut env = env_at(0x1000, &[]);
        env.map_rw(0x8000, 4).unwrap();
        // CWP=0 で全窓が埋まった状態（nw=8、物理窓 7 が最古）。
        env.backend.set(sem::cansave_ref(), 0);
        env.backend.set(sem::canrestore_ref(), 7);
        // 窓 7 の退避先 sp（その窓の %o6 = 物理スロット 126）。
        slot_set(&mut env, 126, 0x8000);
        // 窓 7 の l0（スロット 128）と i0（スロット 8 = 窓 0 の o0 別名）。
        slot_set(&mut env, 128, 0xdead_0001);
        slot_set(&mut env, 8, 0xbeef_0002);
        // あふれトラップ（tt=0x05）。
        env.backend.set(sem::tt_ref(), 0x05);
        let mut sys = Linux::new();
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        // 窓 7 の l0–l7 → i0–i7 が 16 語 BE で [0x8000..) に退避された。
        assert_eq!(mem_u32(&env, 0x8000), 0xdead_0001);
        assert_eq!(mem_u32(&env, 0x8020), 0xbeef_0002);
        // 空きが 1 枚戻り、退避分は canrestore から外れる。
        assert_eq!(env.backend.get(sem::cansave_ref()), 1);
        assert_eq!(env.backend.get(sem::canrestore_ref()), 6);
        // 不足側。現窓の %i6（スロット 30、窓 1 の %o6 別名）が
        // 退避域を指し、窓 1 の中身を埋め戻す。
        env.backend.set(sem::canrestore_ref(), 0);
        env.backend.set(sem::cansave_ref(), 7);
        slot_set(&mut env, 30, 0x8000);
        env.backend.set(sem::tt_ref(), 0x06);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        // 窓 1 の l0（スロット 32）と i0（スロット 40）。
        assert_eq!(slot_get(&mut env, 32), 0xdead_0001);
        assert_eq!(slot_get(&mut env, 40), 0xbeef_0002);
        assert_eq!(env.backend.get(sem::canrestore_ref()), 1);
    }

    /// getpid と未知番号で syscall の返却規約を見る。
    #[test]
    fn linux_syscall_return_and_errno_convention() {
        use polyisa_os_linux::sparc::{errno, nr, sys::Linux};
        let mut env = env_at(0x1000, &[]);
        let mut sys = Linux::new();
        // getpid（sparc nr=20）。見える %g1 はスロット 1。
        env.backend.set(sem::pc_ref(), 0x1000);
        env.backend.set(sem::npc_ref(), 0x1004);
        env.backend.set(Gpr(1).state(), nr::GETPID);
        env.backend.set(sem::tt_ref(), 0x90);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        // 戻り値は見える %o0（スロット 8）。pid=1、キャリーなし。
        assert_eq!(slot_get(&mut env, 8), 1);
        assert_eq!(env.backend.get(sem::psr_ref()) & (1 << 20), 0);
        // pc は npc へ、npc は +4 進む。
        assert_eq!(env.backend.get(sem::pc_ref()), 0x1004);
        assert_eq!(env.backend.get(sem::npc_ref()), 0x1008);
        // 未知番号は SPARC の ENOSYS（=90）とキャリー。
        env.backend.set(Gpr(1).state(), 0xffff);
        env.backend.set(sem::tt_ref(), 0x90);
        assert!(matches!(sys.handle_trap(&mut env, 0), TrapOutcome::Handled));
        assert_eq!(slot_get(&mut env, 8), u64::from(errno::ENOSYS));
        assert_ne!(env.backend.get(sem::psr_ref()) & (1 << 20), 0);
    }
}
