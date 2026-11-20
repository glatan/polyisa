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
//! パーソナリティへ委ねる（Handled なら pc+4 に復帰）。実際の
//! PAL/syscall の中身は段階16-10 以降で実装する。
//! Ref: SPEC-ALPHA-ARM.

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::{Ctrl, InterpExit};
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_alpha::{decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::ExceptionKind;

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

/// `entry` から `model` で実行する。`sys` は OS パーソナリティ。
pub fn run(
    env: &mut BareEnv,
    entry: u64,
    model: AlphaModel,
    sys: &mut impl TrapHandler,
) -> Outcome {
    env.pc = entry;
    polyisa_engine::run::run(
        env,
        sys,
        STEP_LIMIT,
        |env| env.pc,
        |env, sys| step_alpha(env, sys, model),
    )
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
        Err(InterpExit::Exception(e)) if e.kind == ExceptionKind::Trap => {
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
        // PAL 予約オペコードの Undefined など。その他の例外は
        // この段階では未実装に写す。
        Err(InterpExit::Exception(_)) | Err(InterpExit::Unimplemented(_)) => {
            Err(unimpl(env, u64::from(word)))
        }
    }
}

/// ELF64・EM_ALPHA_EXP（0x9026）の静的実行。
/// `sys` がなければ `call_pal` で止まるため、os-linux の Alpha
/// パーソナリティが来る段階16-10/11 までは動作確認用の入口。
pub fn run_elf_alpha(path: &str, argv: &[String]) -> Result<u64, String> {
    run_elf_alpha_sel(path, argv, None)
}

/// `--cpu` で解決したモデルを指定する `run_elf_alpha`。
pub fn run_elf_alpha_sel(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
) -> Result<u64, String> {
    run_elf_alpha_sys(path, argv, sel, &mut NoSys)
}

/// `sys` とモデルを指定する `run_elf_alpha`。
pub fn run_elf_alpha_sys(
    path: &str,
    argv: &[String],
    sel: Option<&polyisa_isadl::select::CpuSel>,
    sys: &mut impl TrapHandler,
) -> Result<u64, String> {
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
    let entry = main_bias + ehdr.entry;
    // スタック上端。Alpha のユーザ空間は 43 ビット級なので、実効
    // TASK_SIZE 内の値を置く（照合は段階16-11 の ABI 作業で行う）。
    let top: u64 = 0x0000_2000_0000_0000;
    let img_top = top - 0x1_0000;
    let mut arg_bytes = vec![path.as_bytes().to_vec()];
    for a in argv {
        arg_bytes.push(a.as_bytes().to_vec());
    }
    // 最小限のスタック（argc/argv/auxv）は Linux の初期化と同じ
    // 配置にする。AT_PHDR 等の残りは段階16-11 で足す。
    let auxv: Vec<(u64, u64)> = vec![
        (6, 0x1000), // AT_PAGESZ
        (9, entry),  // AT_ENTRY
        (11, 0),     // AT_UID
        (12, 0),     // AT_EUID
        (13, 0),     // AT_GID
        (14, 0),     // AT_EGID
        (17, 100),   // AT_CLKTCK
        (23, 0),     // AT_SECURE
    ];
    let (img, sp) =
        polyisa_os_linux::build_initial_stack_endian(img_top, &arg_bytes, &[], &auxv, Endian::Le);
    let stack_base = sp & !(PAGE_SIZE - 1);
    let stack_pages = (top - stack_base) / PAGE_SIZE;
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
    match run(&mut env, entry, model, sys) {
        Outcome::Exit(code) => Ok(code),
        Outcome::StepLimit { pc } => Err(format!("ステップ数を超過（pc={pc:#x}）")),
        Outcome::Deadlock => Err("デッドロック".to_string()),
        Outcome::Unimplemented { pc, word } => Err(format!("未実装: pc={pc:#x} word={word:#x}")),
    }
}

/// PAL/syscall を受けないスタブ。`call_pal` で止めるだけの
/// 裸実行に使う（OS パーソナリティは段階16-10 以降）。
pub struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polyisa_sem::Backend as _;

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
        match run(&mut env, 0x1000, AlphaModel { feats: ALL_FEATS }, &mut sys) {
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
        match run(&mut env, 0x1000, AlphaModel { feats: ALL_FEATS }, &mut sys) {
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
        match run(&mut env, 0x1000, AlphaModel { feats: ALL_FEATS }, &mut sys) {
            Outcome::Unimplemented { pc, .. } => assert_eq!(pc, 0x1000),
            o => panic!("unexpected outcome: {o:?}"),
        }
    }
}
