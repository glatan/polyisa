// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! m68k（68000 系列）のフェッチから次のフェッチまで。
//!
//! 繰り返しと退出の判定は `engine::run::run` に置き、ここでは 1 ステップぶんの
//! フェッチ・解読・意味論を `step` として提供する（Power 試作と同じ構造）。
//!
//! 命令は16ビットの先頭ワードと EA が要求する拡張語（両 EA で最大4語）
//! からなり、命令長は先頭ワードの EA フィールドから `ea::insn_ext_words` で決める
//! （拡張語の中身の読み出しは意味論側が backend 経由で行う）。
//! 命令は偶数アドレスに整列し、データ・命令ともにビッグエンディアン固定。
//! Trap 系例外は 6 バイトフレームを積んでベクタへ配送する（アドレス
//! エラーの 14 バイトフレームは未接続）。デコード不能な語は
//! `Unimplemented` に写す（実機では illegal ベクタ 4 — デコーダが
//! 認める範囲外を例外へ写す経路は未接続）。
//! Ref: SPEC-M68K-PRM (Rev 1).

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_m68k::{decode_model_ex, ea, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::ExceptionKind;

/// 実バイナリの処理量を見込んだ上限。
const STEP_LIMIT: u64 = 256_000_000;

/// 実行する CPU モデルの、ループが読む分。
#[derive(Clone, Copy, Debug)]
pub struct M68kModel {
    /// `decode_model_ex` に渡す機能ビット。
    pub feats: u128,
    /// 意味論が `b.param` で読む挙動パラメータ。
    pub params: polyisa_guest_m68k::Params,
    /// アドレスバス幅のマスク。68000/68010 は 24 ビット、
    /// 68020 以降は 32 ビット。
    pub addr_mask: u64,
}

impl M68kModel {
    /// MC68000 の既定モデル。
    #[must_use]
    pub const fn m68000() -> Self {
        Self {
            feats: polyisa_guest_m68k::FEAT_M68000,
            params: polyisa_guest_m68k::DEFAULT_PARAMS,
            addr_mask: 0x00FF_FFFF,
        }
    }

    /// モデル名（`MODELS` のいずれか）から解決する。
    /// 未知の名前は既定モデルになる。
    #[must_use]
    pub fn named(name: &str) -> Self {
        // 68020 以降はアドレスバスが 32 ビットになる。
        let wide = !matches!(name, "i68000" | "i68010" | "generic");
        Self {
            feats: polyisa_guest_m68k::model_feats(name),
            params: polyisa_guest_m68k::model_params(name),
            addr_mask: if wide { 0xFFFF_FFFF } else { 0x00FF_FFFF },
        }
    }
}

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(env: &mut BareEnv, entry: u64, model: M68kModel, sys: &mut impl TrapHandler) -> Outcome {
    env.pc = entry;
    polyisa_guest_m68k::install_params(&mut env.backend, &model.params);
    // PC は32ビットの内部レジスタだがアドレスバスはモデル依存
    // （68000/68010 は 24 ビット、68020 以降は 32 ビット）。意味論が
    // 64 ビットで組み立てたアドレスをアクセス直前に切る。
    env.backend.addr_mask = model.addr_mask;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_m68k(env, sys, model),
    )
}

/// 1 命令ぶんのフェッチ・解読・意味論。
// Ref: SPEC-M68K-PRM (Rev 1).
fn step_m68k(
    env: &mut BareEnv,
    sys: &mut impl TrapHandler,
    model: M68kModel,
) -> Result<(), Outcome> {
    let pc = env.pc;
    let unimpl = |env: &BareEnv, word: u64| Outcome::Unimplemented {
        pc: env.pc,
        word: u128::from(word),
    };
    // 命令は偶数アドレスに整列する（奇数 PC はアドレス例外だが、
    // 例外ベクタの配送は未接続なので Unimplemented に写す）。
    if pc & 1 != 0 {
        return Err(unimpl(env, 0));
    }
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let mut b2 = [0u8; 2];
    // アドレスバスはモデルの幅（68000/68010 は24、68020+ は32ビット）。
    if env
        .backend
        .mem
        .read(VirtAddr(pc & model.addr_mask), &mut b2, acc)
        .is_err()
    {
        return Err(unimpl(env, 0));
    }
    let word = u64::from(u16::from_be_bytes(b2));
    let Some(insn) = decode_model_ex(u128::from(word), 16, true, model.feats) else {
        return Err(unimpl(env, word));
    };
    // 命令長は先頭ワードの EA フィールドから決める。拡張語自体は
    // 意味論側が pc+2 以降から backend 経由で読む。
    let Some(ext) = ea::insn_ext_words(insn, word) else {
        return Err(unimpl(env, word));
    };
    let len = 2 + u64::from(ext) * 2;
    match env.step(|b| sem::exec(b, insn, word, pc)) {
        Ok(()) => {
            if env.backend.ctrl == Ctrl::Fallthrough {
                // PC は32ビットのアドレス空間で折り返す。
                env.pc = (env.pc + len) & 0xFFFF_FFFF;
            }
            Ok(())
        }
        // trap #0（ベクタ 32）は Linux の syscall 発行点。OS
        // パーソナリティに委ね、Unimplemented なら素の例外として配送する。
        // その他の Trap 系例外は 6 バイトフレームを積んでベクタへ（C14）。
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => {
            if e.code == 32 {
                match sys.handle_trap(env, e.code as u32) {
                    TrapOutcome::Handled => {
                        env.pc = (env.pc + len) & 0xFFFF_FFFF;
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
                    TrapOutcome::Unimplemented => env
                        .step(|b| sem::deliver(b, e.code as u32, pc, len))
                        .map_err(|_| unimpl(env, word)),
                }
            } else {
                env.step(|b| sem::deliver(b, e.code as u32, pc, len))
                    .map_err(|_| unimpl(env, word))
            }
        }
        // アドレスエラー（14 バイトフレーム）は未接続。
        Err(InterpExit::Exception(_)) | Err(InterpExit::Unimplemented(_)) => Err(unimpl(env, word)),
    }
}

/// m68k の Linux ELF（EM_68K・ELFCLASS32・ビッグエンディアン）を
/// 実行する。スタック・auxv の形は run_arm と同じ。
// Ref: SRC-LINUX (7.3), SPEC-ELF-GABI.
#[cfg(feature = "guest-m68k")]
pub fn run_elf_m68k(path: &str, argv: &[String]) -> Result<u64, String> {
    use polyisa_mem::PAGE_SIZE;
    use polyisa_sem::Backend as _;

    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if !matches!(bytes.get(4), Some(1)) {
        return Err("m68k は ELFCLASS32 のみ対応".to_string());
    }
    let ehdr = polyisa_loader::elf::parse_ehdr32(&bytes).map_err(|e| format!("ehdr: {e:?}"))?;
    // EM_68K=4。Ref: binutils include/elf/common.h.
    const EM_68K: u16 = 4;
    if ehdr.machine != EM_68K {
        return Err(format!("未対応の e_machine: {}", ehdr.machine));
    }
    if ehdr.little {
        return Err("m68k はビッグエンディアンのみ対応".to_string());
    }
    let phdrs =
        polyisa_loader::elf::parse_phdrs32(&bytes, &ehdr).map_err(|e| format!("phdrs: {e:?}"))?;
    if polyisa_loader::elf::parse_interp(&bytes, &phdrs).is_some() {
        return Err("PT_INTERP のある m68k ELF は未対応（静的のみ）".to_string());
    }
    let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_m68k::CpuState>());
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
            let hi = lo + ehdr.phnum as usize * 32;
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
    let (img, sp) =
        polyisa_os_linux::build_initial_stack32_endian(img_top, &arg_bytes, &[], &auxv, Endian::Be);
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
    // A7 = 初期スタック。SR=0（ユーザモード）なので USP が A7 になる。
    env.backend.set(sem::Usp.state(), sp as u32);
    let mut sys = polyisa_os_linux::m68k::sys::Linux::new();
    sys.exe_path = path.to_string();
    sys.init_brk(image_end);
    // Linux ユーザランドは 68020 以降向けにリンクされる。32 ビットの
    // アドレスバスと世代パラメータが要るため i68020 を使う。
    let out = run(&mut env, entry, M68kModel::named("i68020"), &mut sys);
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
    use polyisa_engine::run::TrapOutcome;
    use polyisa_guest_m68k::Insn;
    use polyisa_mem::Perms;
    use polyisa_sem::Backend as _;

    /// 語列を RX として写像した環境。`base` が入口。
    fn env_at(base: u64, words: &[u16]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<polyisa_guest_m68k::CpuState>());
        env.backend
            .mem
            .map(VirtAddr(base & !0xFFF), 1, Perms(0b111))
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

    #[test]
    fn nop_sequence_advances_pc() {
        // ページ末尾に nop×3 を置き、続きの 0x2000 は未写像で
        // fetch 失敗 → Unimplemented。
        let mut env = env_at(0x1FFA, &[0x4E71, 0x4E71, 0x4E71]);
        let mut sys = NoSys;
        match run(&mut env, 0x1FFA, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x2000),
            o => panic!("unexpected outcome: {o:?}"),
        }
        // 実行入口で 24 ビットバスマスクが掛かる契約を固定する。
        assert_eq!(env.backend.addr_mask, 0x00FF_FFFF);
    }

    #[test]
    fn undecodable_word_is_unimplemented() {
        // nop の次がデコード不能（0x4E74 は 68000 では未割当）→ Unimplemented。
        let mut env = env_at(0x1000, &[0x4E71, 0x4E74]);
        let mut sys = NoSys;
        match run(&mut env, 0x1000, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, word } => {
                assert_eq!(pc, 0x1002);
                assert_eq!(word, 0x4E74);
            }
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn illegal_delivers_vector4_frame() {
        // nop; illegal。illegal はベクタ 4 へ配送される（C14）:
        // SSP に [sr][pc] の 6 バイトフレームを積み、S=1 になって
        // ハンドラへ飛ぶ。ハンドラ先は未定義語で Unimplemented にする。
        let mut env = env_at(0x1000, &[0x4E71, 0x4AFC]);
        env.backend.mem.map(VirtAddr(0), 1, Perms::RW).unwrap();
        env.backend.mem.map(VirtAddr(0x4000), 1, Perms::RW).unwrap();
        env.backend.set(sem::Ssp.state(), 0x4100);
        // ベクタ 4（0x10）→ ハンドラ先頭 0x2000。未定義語を置く。
        env.backend
            .mem
            .write(VirtAddr(0x10), &[0, 0, 0x20, 0x00])
            .unwrap();
        env.backend
            .mem
            .map(VirtAddr(0x2000), 1, Perms(0b111))
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(0x2000), &[0x4E, 0x74])
            .unwrap();
        let mut sys = NoSys;
        match run(&mut env, 0x1000, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, word } => {
                assert_eq!(pc, 0x2000);
                assert_eq!(word, 0x4E74);
            }
            o => panic!("unexpected outcome: {o:?}"),
        }
        // フレーム: ssp = 0x4100-6、[sr][積み pc=0x1002]（illegal は
        // 命令自身の先頭）。S=1・T=0 になっている。
        assert_eq!(env.backend.get(sem::Ssp.state()), 0x40FA);
        assert_eq!(env.backend.get(sem::sr_ref()) & 0x2000, 0x2000);
        let mut buf = [0u8; 6];
        env.backend
            .mem
            .read(
                VirtAddr(0x40FA),
                &mut buf,
                Access {
                    endian: Endian::Be,
                    align: Align::Natural,
                    kind: AccessKind::DataRead,
                },
            )
            .unwrap();
        assert_eq!(&buf[2..6], &[0x00, 0x00, 0x10, 0x02]);
    }

    #[test]
    fn odd_pc_is_unimplemented() {
        let mut env = env_at(0x1000, &[0x4E71]);
        let mut sys = NoSys;
        match run(&mut env, 0x1001, M68kModel::m68000(), &mut sys) {
            Outcome::Unimplemented { pc, word } => {
                assert_eq!(pc, 0x1001);
                assert_eq!(word, 0);
            }
            o => panic!("unexpected outcome: {o:?}"),
        }
    }

    #[test]
    fn insn_ext_words_fixed_is_zero() {
        // F0 形式の固定ワードは拡張語を持たない。
        assert_eq!(ea::insn_ext_words(Insn::Nop, 0x4E71), Some(0));
        assert_eq!(ea::insn_ext_words(Insn::Illegal, 0x4AFC), Some(0));
    }
}
