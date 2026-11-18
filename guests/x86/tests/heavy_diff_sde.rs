// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0030
//! Intel SDE との実行差分（層: diff、E3）。
//!
//! ホスト CPU が持たない拡張（現コーパスは APX の REX2 形）の
//! 命令列を、polyisa と Intel SDE の両方で実行して状態を比較する。
//! heavy_diff_host（E2）がホスト CPU を直接叩くのに対し、こちらは
//! `sde64 -future` の下で生成 ELF を走らせるため、REX2 の拡張 GPR
//! （R16-R31）までカバーできる。map4 の NDD・昇格形は polyisa が
//! decode のみ（意味論未実装）で SDE -future でも実行できないため
//! 現コーパスには含まない。
//!
//! 仕組み:
//! - 乱択した命令列を1枚の静的 ELF（RWX の1セグメント）に焼く。
//!   `_start` が初期 ctx を読み込み、命令ごとに全 GPR と RFLAGS を
//!   ctx スロットへ書き戻し、最後に `write(1, slots)` + `exit` する。
//! - SDE の stdout からスロット列を回収し、各ステップの polyisa 状態
//!   （BareEnv + run_mode_ex）と比較する。
//! - r15 は ctx ポインタの予約レジスタ、rsp はゲストスタックのため
//!   コーパスの被演算子と比較対象の双方から除く。比較は残り 30 GPR
//!   とユーザ可視フラグ。命令ごとに定義済み旗のマスクを掛ける。
//!
//! sde64 が無ければスキップする（testkit::reqs でもフィルタ済み）。

#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", unix))]
mod imp {
    use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
    use polyisa_engine::bare::BareEnv;
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_guest_x86::{CpuState, sem};
    use polyisa_mem::{Perms, VirtAddr};
    use polyisa_sem::Backend as _;
    use std::process::Command;

    /// 比較対象のユーザ可視フラグ（CF PF ZF SF OF）。bit1 は常時 1。
    /// AF はシフト・乗除算系でアーキテクチャ上不定のため外す。
    const FLAG_MASK: u64 = 0x8C5;
    /// ゲストコードの仮想アドレス（polyisa 側）。
    const CODE_VA: u64 = 0x10_0000;
    /// ELF のイメージベースと _start のオフセット。
    const ELF_BASE: u64 = 0x40_0000;
    const HDRS: u64 = 64 + 56;
    /// ctx スロットのサイズ（r0-r31, rsp, rflags の 34 qword）。
    const SLOT: usize = 34 * 8;
    /// シーケンスあたりの命令数と、既定のシーケンス数。
    const STEPS: usize = 16;
    const SEQS: usize = 48;

    /// ctx スロット。フィールド順は x86 レジスタ番号順。
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Ctx {
        g: [u64; 32],
        rsp: u64,
        rflags: u64,
    }

    impl Ctx {
        fn gpr(&self, i: usize) -> u64 {
            self.g[i]
        }

        fn set_gpr(&mut self, i: usize, v: u64) {
            self.g[i] = v;
        }
    }

    const _: () = assert!(size_of::<Ctx>() == SLOT);

    /// `mov reg64, [r15 + disp32]` の REX 形（r0-r15 用）。
    fn ld64(v: &mut Vec<u8>, reg: u8, disp: u32) {
        // mod=10 reg=reg rm=111。rm=7 は REX.B で r15。
        let rex = 0x48 | if reg >= 8 { 5 } else { 1 };
        v.push(rex);
        v.push(0x8B);
        v.push(0x87 | ((reg & 7) << 3));
        v.extend_from_slice(&disp.to_le_bytes());
    }

    /// `mov [r15 + disp32], reg64` の REX 形（r0-r15 用）。
    fn st64(v: &mut Vec<u8>, reg: u8, disp: u32) {
        let rex = 0x48 | if reg >= 8 { 5 } else { 1 };
        v.push(rex);
        v.push(0x89);
        v.push(0x87 | ((reg & 7) << 3));
        v.extend_from_slice(&disp.to_le_bytes());
    }

    /// `mov reg64, [r15 + disp32]` の REX2 形（r16-r31 用）。
    /// ペイロードは [M0 R4 X4 B4 | W R X B]。reg の 16 番台は R4、
    /// 24 番台は R、rm=r15 の拡張は B。W=1 で 64 ビット。
    fn ld64_e(v: &mut Vec<u8>, reg: u8, disp: u32) {
        let pp = 0x49 | if reg >= 24 { 4 } else { 0 };
        v.extend_from_slice(&[0xD5, pp, 0x8B, 0x87 | ((reg & 7) << 3)]);
        v.extend_from_slice(&disp.to_le_bytes());
    }

    /// `mov [r15 + disp32], reg64` の REX2 形（r16-r31 用）。
    fn st64_e(v: &mut Vec<u8>, reg: u8, disp: u32) {
        let pp = 0x49 | if reg >= 24 { 4 } else { 0 };
        v.extend_from_slice(&[0xD5, pp, 0x89, 0x87 | ((reg & 7) << 3)]);
        v.extend_from_slice(&disp.to_le_bytes());
    }

    /// ctx スロットへの状態書き戻し（1 命令分）。r15 = スロット先頭。
    /// RFLAGS は lahf + seto で合成してから書く。
    fn epilogue(v: &mut Vec<u8>) {
        for r in 0..16u8 {
            st64(v, r, (r as u32) * 8);
        }
        for r in 16..32u8 {
            st64_e(v, r, (r as u32) * 8);
        }
        // rsp。
        v.extend_from_slice(&[0x49, 0x89, 0xA7]);
        v.extend_from_slice(&(256u32).to_le_bytes());
        // RFLAGS: AH に low8（CF|PF|AF|ZF|SF）、AL に OF → bit11。
        v.extend_from_slice(&[0x9F]); // lahf
        v.extend_from_slice(&[0x0F, 0x90, 0xC0]); // seto al
        v.extend_from_slice(&[0x0F, 0xB6, 0xCC]); // movzx ecx, ah
        v.extend_from_slice(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        v.extend_from_slice(&[0xC1, 0xE0, 0x0B]); // shl eax, 11
        v.extend_from_slice(&[0x09, 0xC8]); // or eax, ecx
        v.extend_from_slice(&[0x49, 0x89, 0x87]);
        v.extend_from_slice(&(264u32).to_le_bytes());
        // フラグ合成で rax/rcx を潰したのでスロットから復元する。
        // （スロットは先に全 GPR を書き済みなので値は戻る。）
        ld64(v, 0, 0);
        ld64(v, 1, 8);
        // スロットを進めてから前スロットの rflags を popfq で復元
        // （add 自体がフラグを変えるのでこの順序）。
        v.extend_from_slice(&[0x49, 0x81, 0xC7]);
        v.extend_from_slice(&(SLOT as u32).to_le_bytes());
        v.extend_from_slice(&[0x41, 0xFF, 0x77, 0xF8]); // push [r15-8]
        v.push(0x9D); // popfq
    }

    /// init ctx の VA。コード領域（8KiB 固定）の直後。
    fn init_va_of() -> u64 {
        ELF_BASE + HDRS + 8192
    }

    /// ctx スロット列の VA（init の直後）。
    fn slots_va_of() -> u64 {
        init_va_of() + SLOT as u64
    }

    /// 命令列と初期 ctx から静的 ELF64 を組み立てる。
    /// データ領域は init_ctx(272B) + slots(STEPS*272B) を後続に置く。
    fn build_elf(insns: &[Vec<u8>], init: &Ctx) -> Vec<u8> {
        let n = insns.len();
        let code_start = ELF_BASE + HDRS;
        let mut code = Vec::with_capacity(8192);
        // プロローグ: r15 = init ctx、flags と全 GPR を読む。
        let init_va = init_va_of();
        code.extend_from_slice(&[0x49, 0xBF]);
        code.extend_from_slice(&init_va.to_le_bytes()); // mov r15, imm64
        // push [r15 + 264]; popfq で rflags を初期化。
        code.extend_from_slice(&[0x41, 0xFF, 0xB7]);
        code.extend_from_slice(&(264u32).to_le_bytes());
        code.push(0x9D);
        for r in (0..15u8).filter(|r| *r != 4) {
            ld64(&mut code, r, (r as u32) * 8);
        }
        for r in 16..32u8 {
            ld64_e(&mut code, r, (r as u32) * 8);
        }
        code.extend_from_slice(&[0x49, 0x8B, 0xA7]); // mov rsp, [r15+256]
        code.extend_from_slice(&(256u32).to_le_bytes());
        // スロット先頭へ r15 を張り替える。
        let slots_va = init_va + SLOT as u64;
        code.extend_from_slice(&[0x49, 0xBF]);
        code.extend_from_slice(&slots_va.to_le_bytes());
        // 各命令 + スロット書き戻し。
        for insn in insns {
            code.extend_from_slice(insn);
            epilogue(&mut code);
        }
        // write(1, slots, STEPS*SLOT); exit(0)
        code.extend_from_slice(&[0xB8, 1, 0, 0, 0]); // mov eax, 1
        code.extend_from_slice(&[0xBF, 1, 0, 0, 0]); // mov edi, 1
        code.extend_from_slice(&[0x48, 0xBE]); // mov rsi, imm64
        code.extend_from_slice(&slots_va.to_le_bytes());
        code.extend_from_slice(&[0xBA]); // mov edx, imm32
        code.extend_from_slice(&((n * SLOT) as u32).to_le_bytes());
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0xB8, 60, 0, 0, 0]); // mov eax, 60
        code.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        assert!(code.len() <= 8192, "blob too large: {}", code.len());

        let data = {
            let mut d = Vec::with_capacity(SLOT * (n + 1) + 4096);
            d.extend_from_slice(unsafe { &*(&raw const *init).cast::<[u8; SLOT]>() });
            // init + slots + スクラッチスタック（4KiB）。
            // init.rsp はこの中程を指す。
            d.resize(SLOT * (n + 1) + 4096, 0);
            d
        };

        // コード領域を 8KiB にパディングし、data の VA を
        // init_va (= code_start + 8192) に一致させる。
        code.resize(8192, 0x90);
        let filesz = HDRS as usize + code.len() + data.len();
        let mut elf = Vec::with_capacity(filesz);
        let ehdr = {
            let mut e = Vec::with_capacity(64);
            e.extend_from_slice(b"\x7fELF\x02\x01\x01");
            e.resize(16, 0);
            e.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
            e.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
            e.extend_from_slice(&1u32.to_le_bytes());
            e.extend_from_slice(&code_start.to_le_bytes()); // e_entry
            e.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
            e.extend_from_slice(&0u64.to_le_bytes());
            e.extend_from_slice(&0u32.to_le_bytes());
            e.extend_from_slice(&64u16.to_le_bytes());
            e.extend_from_slice(&56u16.to_le_bytes());
            e.extend_from_slice(&1u16.to_le_bytes());
            e.extend_from_slice(&0u16.to_le_bytes());
            e.extend_from_slice(&0u16.to_le_bytes());
            e.extend_from_slice(&0u16.to_le_bytes());
            e
        };
        elf.extend_from_slice(&ehdr);
        // PT_LOAD RWX、ファイル全域を BASE へ。
        elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        elf.extend_from_slice(&7u32.to_le_bytes()); // RWX
        elf.extend_from_slice(&0u64.to_le_bytes());
        elf.extend_from_slice(&ELF_BASE.to_le_bytes());
        elf.extend_from_slice(&ELF_BASE.to_le_bytes());
        elf.extend_from_slice(&(filesz as u64).to_le_bytes());
        elf.extend_from_slice(&(filesz as u64).to_le_bytes());
        elf.extend_from_slice(&0x1000u64.to_le_bytes());
        elf.extend_from_slice(&code);
        elf.extend_from_slice(&data);
        elf
    }

    /// xorshift64*。決定的にするため固定種から始める。
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn imm(&mut self) -> u64 {
            // 上位ビットのばらつきを重視し、まれに小さい値にする。
            let v = self.next();
            if v.is_multiple_of(16) { v & 0xffff } else { v }
        }
    }

    /// 被演算子レジスタ。rsp(4) と ctx 予約の r15 を除く 0-31。
    fn reg(rng: &mut Rng) -> u8 {
        // 30 候補を 4(rsp)・15(ctx 予約) を飛ばして 0-31 に割り当てる。
        let r = (rng.next() % 30) as u8;
        if r < 4 {
            r
        } else if r < 14 {
            r + 1
        } else {
            r + 2
        }
    }

    /// REX2 ペイロード = [M0 R4 X4 B4 | W R X B]。reg/rm は 0-31。
    /// map1（0F 副表）は m0=1。reg の bit3 は R、rm の bit3 は B。
    fn rex2(reg: u8, rm: u8, w: bool, m0: bool) -> u8 {
        ((m0 as u8) << 7)
            | (((reg >> 4) & 1) << 6)
            | (((rm >> 4) & 1) << 4)
            | ((w as u8) << 3)
            | (((reg >> 3) & 1) << 2)
            | ((rm >> 3) & 1)
    }

    /// `D5 pp op modrm`（mod=3 レジスタ直）を組み立てる。
    fn rr2(op: u8, reg: u8, rm: u8, w: bool) -> Vec<u8> {
        vec![
            0xD5,
            rex2(reg, rm, w, false),
            op,
            0xC0 | ((reg & 7) << 3) | (rm & 7),
        ]
    }

    /// `D5 pp op`（map1）。op は 0F マップの第2バイト。
    fn rrm2(op: u8, reg: u8, rm: u8, w: bool) -> Vec<u8> {
        vec![
            0xD5,
            rex2(reg, rm, w, true),
            op,
            0xC0 | ((reg & 7) << 3) | (rm & 7),
        ]
    }

    /// 命令ごとのフラグ比較マスク。`FLAG_MASK` のうち、その命令が
    /// 定義する旗だけを見る。
    const M_SHIFT: u64 = FLAG_MASK & !0x800; // OF 不定
    const M_MUL: u64 = 0x801; // CF|OF
    const M_BSF: u64 = 0x40; // ZF のみ（他旗は不定）

    /// 乱択命令を1つ生成する。APX（REX2）の reg-reg 整数命令が主体。
    /// 戻り値は (バイト列, フラグ比較マスク)。
    fn gen_insn(rng: &mut Rng) -> (Vec<u8>, u64) {
        let a = reg(rng);
        let b = reg(rng);
        let w = rng.next().is_multiple_of(2);
        match rng.next() % 12 {
            // ALU 2項（dst rm ← reg）。
            0..=4 => {
                let op =
                    [0x01u8, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39][(rng.next() % 8) as usize];
                (rr2(op, a, b, w), FLAG_MASK)
            }
            // 逆方向 ALU（dst reg ← rm）と test/mov/xchg/movsxd。
            5 => {
                let op = [
                    0x03u8, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x3B, 0x85, 0x87, 0x89, 0x8B,
                ][(rng.next() % 12) as usize];
                (rr2(op, a, b, w), FLAG_MASK)
            }
            6 => (rr2(0x63, a, b, true), FLAG_MASK),
            // map1: imul/shld/shrd/bt/xadd/bsf/bsr/movsx/movzx。
            7 => {
                let op = [0xAFu8, 0xBC, 0xBD, 0xB6, 0xB7, 0xBE, 0xBF, 0xC1, 0xA3]
                    [(rng.next() % 9) as usize];
                let m = if op == 0xA3 {
                    0x1
                } else if op == 0xAF {
                    M_MUL
                } else if op == 0xBC || op == 0xBD {
                    M_BSF
                } else {
                    FLAG_MASK
                };
                (rrm2(op, a, b, w), m)
            }
            8 => {
                let op = [0xA4u8, 0xA5, 0xAC, 0xAD][(rng.next() % 4) as usize];
                let mut v = rrm2(op, a, b, w);
                if op & 1 == 0 {
                    v.push((rng.next() % 40) as u8);
                }
                (v, M_SHIFT)
            }
            // 単項 /r。grp は modrm reg フィールド（EGPR 不可）。
            9 => {
                let grp = [2u8, 3, 4, 5][(rng.next() % 4) as usize];
                let m = if grp >= 4 { M_MUL } else { FLAG_MASK };
                (rr2(0xF7, grp, a, w), m)
            }
            // シフト /r。grp=1,4,5,6,7。0F 側は map1。
            // ROR(1) は SF/ZF/PF も不定なので CF|OF のみ見る。
            10 => {
                let grp = [1u8, 4, 5, 6, 7][(rng.next() % 5) as usize];
                let m = if grp == 1 { M_MUL } else { M_SHIFT };
                if rng.next().is_multiple_of(3) {
                    (rr2(0xD3, grp, a, w), m)
                } else {
                    let mut v = rr2(0xC1, grp, a, w);
                    v.push((rng.next() % 40) as u8);
                    (v, m)
                }
            }
            // cmov / setcc（map1）か mov imm。
            _ => {
                if rng.next().is_multiple_of(2) {
                    let cc = (rng.next() % 16) as u8;
                    (rrm2(0x40 | cc, a, b, w), FLAG_MASK)
                } else {
                    let mut v = vec![0xD5, rex2(0, a, w, false), 0xB8 | (a & 7)];
                    let n = if w { 8 } else { 4 };
                    v.extend_from_slice(&rng.imm().to_le_bytes()[..n]);
                    (v, FLAG_MASK)
                }
            }
        }
    }

    /// polyisa 側の環境。コード頁だけを写像する（コーパスは
    /// reg-direct なのでメモリ比較対象はない）。
    fn poly_env() -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(CODE_VA), 1, rwx).unwrap();
        env
    }

    /// ctx の全状態を polyisa 側に写す。Gpr(16-31) は x2 に行く。
    fn poly_load(env: &mut BareEnv, ctx: &Ctx) {
        for i in 0..32u8 {
            let v = if i == 4 { CODE_VA } else { ctx.gpr(i as usize) };
            sem::write64(&mut env.backend, Gpr(i), v);
        }
        let f = (ctx.rflags & FLAG_MASK) as u32 | 0x2;
        env.backend.set(sem::eflags_ref(), f);
    }

    /// トラップは差分として扱う（コーパスに分岐・trap は無い）。
    struct NoTrap;

    impl TrapHandler for NoTrap {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
    }

    /// 1 シーケンスを実行し、最初の差分を報告用文字列で返す。
    /// `sde` は sde64 のパス。
    fn run_seq(sde: &str, seed: u64) -> Option<String> {
        let mut rng = Rng(seed);
        let mut insns: Vec<Vec<u8>> = Vec::with_capacity(STEPS);
        let mut masks: Vec<u64> = Vec::with_capacity(STEPS);
        // map4 の NDD・昇格形は polyisa が decode のみ（意味論未実装）、
        // SDE -future でも実行できないため、コーパスは REX2 のみ。
        while insns.len() < STEPS {
            let (v, m) = gen_insn(&mut rng);
            insns.push(v);
            masks.push(m);
        }

        // 初期 ctx を乱択し、ELF を焼く。
        let mut init = Ctx {
            g: [0; 32],
            rsp: 0,
            rflags: (rng.next() & FLAG_MASK) | 0x2,
        };
        for r in 0..32usize {
            if r != 4 && r != 15 {
                init.set_gpr(r, rng.imm());
            }
        }
        // init.rsp をデータ末尾のスクラッチ中程へ向ける
        // （popfq 復元の push が生きられるよう有効なスタックが要る）。
        init.rsp = slots_va_of() + STEPS as u64 * SLOT as u64 + 2048;
        let elf = build_elf(&insns, &init);

        // 一時ファイルに書いて sde64 -future で走らせる。
        let dir = std::env::temp_dir().join(format!("polyisa_sde_{}_{seed:x}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seq.elf");
        std::fs::write(&path, &elf).unwrap();
        // execve は実行権限が要る（sde の起動も同じ）。
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = Command::new(sde)
            .arg("-future")
            .arg("--")
            .arg(&path)
            // SDE は例外時に sde-error.txt を cwd へ吐くため
            // ワークツリーを汚さないよう一時ディレクトリで動かす。
            .current_dir(&dir)
            .output()
            .map_err(|e| format!("sde64 起動失敗: {e}"))
            .unwrap();
        let slots = out.stdout;
        let want = STEPS * SLOT;
        let _ = std::fs::remove_dir_all(&dir);
        if !out.status.success() || slots.len() != want {
            let dump = insns
                .iter()
                .map(|i| i.iter().map(|b| format!("{b:02x}")).collect::<String>())
                .collect::<Vec<_>>()
                .join(" ");
            return Some(format!(
                "seq {seed}: sde status {:?} stdout {} bytes (want {want}): {dump}",
                out.status,
                slots.len()
            ));
        }
        let native: Vec<Ctx> = (0..STEPS)
            .map(|i| {
                let b = &slots[i * SLOT..(i + 1) * SLOT];
                let mut g = [0u64; 32];
                for (j, c) in g.iter_mut().enumerate() {
                    *c = u64::from_le_bytes(b[j * 8..j * 8 + 8].try_into().unwrap());
                }
                Ctx {
                    g,
                    rsp: u64::from_le_bytes(b[256..264].try_into().unwrap()),
                    rflags: u64::from_le_bytes(b[264..272].try_into().unwrap()),
                }
            })
            .collect();

        // polyisa 側を同じ初期 ctx で1命令ずつ追う。
        let mut env = poly_env();
        let ctx = init;
        poly_load(&mut env, &ctx);
        for (i, insn) in insns.iter().enumerate() {
            env.backend.mem.write(VirtAddr(CODE_VA), insn).unwrap();
            let out = run_x86::run_mode_ex(
                &mut env,
                CODE_VA as u32,
                &mut NoTrap,
                1,
                true,
                polyisa_guest_x86::DEFAULT_FEATS | polyisa_guest_x86::FEAT_APX,
                &polyisa_guest_x86::DEFAULT_PARAMS,
            );
            if !matches!(out, Outcome::StepLimit { .. }) {
                return Some(format!(
                    "seq {seed} step {i}: insn {}: poly outcome {out:?}",
                    insn.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                ));
            }
            let n = &native[i];
            let mut ds = Vec::new();
            for r in 0..32u8 {
                if r == 4 || r == 15 {
                    // rsp はゲストスタック（コーパスは触らない）、
                    // r15 は SDE 側で ctx ポインタに使う予約レジスタ。
                    continue;
                }
                let (hv, pv) = (n.gpr(r as usize), sem::read64(&mut env.backend, Gpr(r)));
                if hv != pv {
                    ds.push(format!("r{r} {hv:#x} vs {pv:#x}"));
                }
            }
            let mask = masks[i];
            let hf = n.rflags & mask;
            let pf = u64::from(env.backend.get(sem::eflags_ref())) & mask;
            if hf != pf {
                ds.push(format!("eflags {hf:#x} vs {pf:#x}"));
            }
            if !ds.is_empty() {
                return Some(format!(
                    "seq {seed} step {i}: insn {}: {}",
                    insn.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    ds.join("; ")
                ));
            }
            // 不定旗（シフトの OF 等）は SDE 側の実値で同期する。
            // 残置すると次ステップの全マスク比較で再浮上する。
            env.backend
                .set(sem::eflags_ref(), (n.rflags & FLAG_MASK) as u32 | 0x2);
        }
        None
    }

    fn sde_path() -> Option<String> {
        // `-future`（APX 含む将来モデル）が実際に走るかまで見る。
        ["sde64", "/opt/sde/sde64", "/usr/bin/sde64"]
            .iter()
            .find(|c| {
                Command::new(c)
                    .args(["-future", "--", "/bin/true"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            })
            .map(|s| s.to_string())
    }

    pub fn run() {
        let Some(sde) = sde_path() else {
            eprintln!("sde64 がない。スキップ");
            return;
        };
        let mut rng = Rng(0xE300_0001);
        let mut reports = Vec::new();
        for _ in 0..SEQS {
            let seed = rng.next();
            if let Some(r) = run_seq(&sde, seed) {
                reports.push(r);
                if reports.len() >= 16 {
                    break;
                }
            }
        }
        assert!(reports.is_empty(), "sde diff:\n{}", reports.join("\n"));
    }
}

#[cfg(all(target_arch = "x86_64", unix))]
#[test]
fn diff_sde() {
    imp::run();
}

/// 対象外プラットフォームでは空のテスト。
#[cfg(not(all(target_arch = "x86_64", unix)))]
#[test]
fn diff_sde() {}
