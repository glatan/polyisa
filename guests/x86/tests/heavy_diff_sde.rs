// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0030
//! Intel SDE との実行差分（層: diff、E3）。
//!
//! ホスト CPU が持たない拡張（現コーパスは APX の REX2 形）の
//! 命令列を、polyisa と Intel SDE の両方で実行して状態を比較する。
//! heavy_diff_host（E2）がホスト CPU を直接叩くのに対し、こちらは
//! `sde64 -future` の下で生成 ELF を走らせるため、REX2 の拡張 GPR
//! （R16-R31）までカバーできる。EVEX map4 の NDD/NF 昇格形は
//! reg-direct 形と絶対アドレス/base+disp8/SIB index のメモリ形をコーパスへ入れ、CFCMOV の
//! 条件付きストアと PUSH2/POP2 のメモリ出力も比較する。
//!
//! 仕組み:
//! - 乱択した命令列を1枚の静的 ELF（RWX の1セグメント）に焼く。
//!   `_start` が初期 ctx を読み込み、命令ごとに全 GPR と RFLAGS を
//!   ctx スロットへ書き戻し、最後に `write(1, slots+memory+stack)` +
//!   `exit` する。
//! - SDE の stdout からスロット列を回収し、各ステップの polyisa 状態
//!   （BareEnv + run_mode_ex）と比較する。
//! - r15 は ctx ポインタの予約レジスタなのでコーパスの被演算子と
//!   比較対象から除く。比較は rsp を含む残り 31 GPR、ユーザ可視フラグ、
//!   最終メモリ/スタック。命令ごとに定義済み旗のマスクを掛ける。
//!
//! sde64 が無ければスキップする（testkit::reqs でもフィルタ済み）。

#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", unix))]
mod imp {
    use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
    use polyisa_engine::bare::BareEnv;
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_guest_x86::{CpuState, sem};
    use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
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
    /// APX メモリ被演算子の入力/出力スクラッチ。
    const MEM_BYTES: usize = 256;
    /// PUSH2/POP2 と epilogue の一時 push が使うゲストスタック。
    const STACK_BYTES: usize = 4096;

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

    /// メモリ被演算子スクラッチの VA。slots の直後に置き、
    /// 最後の write syscall で slots と一緒に出力できるようにする。
    fn mem_va_of() -> u64 {
        slots_va_of() + STEPS as u64 * SLOT as u64
    }

    /// ゲストスタックの VA。メモリスクラッチの直後。
    fn stack_va_of() -> u64 {
        mem_va_of() + MEM_BYTES as u64
    }

    /// stdout に出す後半データのバイト数（メモリ + スタック）。
    const fn out_tail_bytes() -> usize {
        MEM_BYTES + STACK_BYTES
    }

    fn data_access() -> Access {
        Access {
            endian: Endian::Le,
            align: Align::Unaligned,
            kind: AccessKind::DataRead,
        }
    }

    /// polyisa と SDE が共有する決定的なメモリ入力。
    fn mem_pattern() -> [u8; MEM_BYTES] {
        let mut out = [0u8; MEM_BYTES];
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(73).wrapping_add(19);
        }
        out
    }

    /// 命令列と初期 ctx から静的 ELF64 を組み立てる。
    /// データ領域は init_ctx(272B) + slots(STEPS*272B) を後続に置く。
    fn build_elf(insns: &[Vec<u8>], init: &Ctx) -> Vec<u8> {
        let n = insns.len();
        assert_eq!(n, STEPS, "メモリレイアウトは STEPS 固定");
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
        // write(1, slots, STEPS*SLOT + memory + stack); exit(0)
        code.extend_from_slice(&[0xB8, 1, 0, 0, 0]); // mov eax, 1
        code.extend_from_slice(&[0xBF, 1, 0, 0, 0]); // mov edi, 1
        code.extend_from_slice(&[0x48, 0xBE]); // mov rsi, imm64
        code.extend_from_slice(&slots_va.to_le_bytes());
        code.extend_from_slice(&[0xBA]); // mov edx, imm32
        code.extend_from_slice(&((n * SLOT + out_tail_bytes()) as u32).to_le_bytes());
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0xB8, 60, 0, 0, 0]); // mov eax, 60
        code.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        assert!(code.len() <= 8192, "blob too large: {}", code.len());

        let data = {
            let mut d = Vec::with_capacity(SLOT * (n + 1) + out_tail_bytes());
            d.extend_from_slice(unsafe { &*(&raw const *init).cast::<[u8; SLOT]>() });
            // init + slots + メモリ + スタック。メモリは入力パターン
            // から始め、条件付きストアの出力先にも使う。スタックは
            // 0 初期化で、init.rsp はその中程を指す。
            let mem_off = SLOT * (n + 1);
            d.resize(mem_off + out_tail_bytes(), 0);
            d[mem_off..mem_off + MEM_BYTES].copy_from_slice(&mem_pattern());
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

    /// 被演算子レジスタ。rsp(4)、メモリベースの r14、ctx 予約の r15、
    /// メモリインデックスの r29 を除く。
    fn reg(rng: &mut Rng) -> u8 {
        // 28 候補を 0-3・5-13・16-28・30-31 へ割り当てる。
        let r = (rng.next() % 28) as u8;
        if r < 4 {
            r
        } else if r < 13 {
            r + 1
        } else if r < 26 {
            r + 3
        } else {
            r + 4
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

    /// EVEX map4 の 4 バイト接頭辞。`rxreg` は ModRM.reg に対応する
    /// R/R4 拡張を持つレジスタ番号（グループ命令では 0）、`rm` は
    /// ModRM.r/m、`ndd` は vvvv+V' の宛先レジスタ。mod=11 専用なので
    /// X4 は 0（U=1）に固定する。pp は NP=0。
    fn evex4_nd(rxreg: u8, rm: u8, ndd: u8, w: bool, nf: bool, pp: u8, nd: bool) -> [u8; 4] {
        let p0 = 0x40 // ~X（X=0）
            | 0x04 // mm=4
            | if rxreg & 8 == 0 { 0x80 } else { 0 } // ~R
            | if rm & 8 == 0 { 0x20 } else { 0 } // ~B
            | if rxreg & 16 == 0 { 0x10 } else { 0 } // ~R4
            | if rm & 16 != 0 { 0x08 } else { 0 }; // B4
        let p1 = ((w as u8) << 7)
            | ((!ndd & 0x0F) << 3)
            | 0x04 // U=1（X4=0）
            | (pp & 3);
        let p2 = if nd { 0x10 } else { 0 }
            | if nf { 0x04 } else { 0 }
            | if ndd & 16 == 0 { 0x08 } else { 0 }; // ~V'
        [0x62, p0, p1, p2]
    }

    fn evex4(rxreg: u8, rm: u8, ndd: u8, w: bool, nf: bool, pp: u8) -> [u8; 4] {
        evex4_nd(rxreg, rm, ndd, w, nf, pp, true)
    }

    /// APX NDD の `op r/m, reg` レジスタ直形。
    /// 意味は `ndd = r/m OP reg`（CMOV 以外の ALU 昇格形）。
    fn apx_rr(op: u8, ndd: u8, reg: u8, rm: u8, w: bool, nf: bool) -> Vec<u8> {
        let mut v = evex4(reg, rm, ndd, w, nf, 0).to_vec();
        v.push(op);
        v.push(0xC0 | ((reg & 7) << 3) | (rm & 7));
        v
    }

    /// APX NDD のグループ命令レジスタ直形。ModRM.reg は opcode
    /// 拡張なので R/R4 拡張は 0 に固定する。
    fn apx_group(op: u8, grp: u8, ndd: u8, rm: u8, w: bool, nf: bool) -> Vec<u8> {
        let mut v = evex4(0, rm, ndd, w, nf, 0).to_vec();
        v.push(op);
        v.push(0xC0 | ((grp & 7) << 3) | (rm & 7));
        v
    }

    /// APX NDD のメモリ被演算子形。SIB の no-index/no-base + disp32
    /// で絶対アドレスを指す。NDD 昇格ではメモリは入力だけなので、
    /// 出力メモリ比較なしにアドレス解釈と読み出しを差分できる。
    fn apx_mem(op: u8, ndd: u8, reg: u8, addr: u64, w: bool, nf: bool) -> Vec<u8> {
        let mut v = evex4(reg, 0, ndd, w, nf, 0).to_vec();
        v.push(op);
        v.push(((reg & 7) << 3) | 4);
        v.push(0x25); // scale=0,index=100(no index),base=101(disp32)
        v.extend_from_slice(&(addr as u32).to_le_bytes());
        v
    }

    /// APX のメモリ被演算子形。ND=0 も作れる（CFCMOV の
    /// 条件付きロード/ストアの確認用）。
    fn apx_mem_nd(op: u8, ndd: u8, reg: u8, addr: u64, w: bool, nf: bool, nd: bool) -> Vec<u8> {
        let mut v = evex4_nd(reg, 0, ndd, w, nf, 0, nd).to_vec();
        v.push(op);
        v.push(((reg & 7) << 3) | 4);
        v.push(0x25);
        v.extend_from_slice(&(addr as u32).to_le_bytes());
        v
    }

    /// APX のレジスタ直形。ND=0 も作れる。
    fn apx_rr_nd(op: u8, ndd: u8, reg: u8, rm: u8, w: bool, nf: bool, nd: bool) -> Vec<u8> {
        let mut v = evex4_nd(reg, rm, ndd, w, nf, 0, nd).to_vec();
        v.push(op);
        v.push(0xC0 | ((reg & 7) << 3) | (rm & 7));
        v
    }

    /// APX NDD のグループ命令メモリ形。
    fn apx_group_mem(op: u8, grp: u8, ndd: u8, addr: u64, w: bool, nf: bool) -> Vec<u8> {
        let mut v = evex4(0, 0, ndd, w, nf, 0).to_vec();
        v.push(op);
        v.push(((grp & 7) << 3) | 4);
        v.push(0x25);
        v.extend_from_slice(&(addr as u32).to_le_bytes());
        v
    }

    /// r14 をベースにした mod=01 disp8 のメモリ形。
    fn apx_mem_base(op: u8, ndd: u8, reg: u8, disp: u8, w: bool, nf: bool) -> Vec<u8> {
        let mut v = evex4(reg, 14, ndd, w, nf, 0).to_vec();
        v.push(op);
        v.push(0x40 | ((reg & 7) << 3) | (14 & 7));
        v.push(disp);
        v
    }

    fn apx_mem_base_nd(op: u8, ndd: u8, reg: u8, disp: u8, w: bool, nf: bool, nd: bool) -> Vec<u8> {
        let mut v = evex4_nd(reg, 14, ndd, w, nf, 0, nd).to_vec();
        v.push(op);
        v.push(0x40 | ((reg & 7) << 3) | (14 & 7));
        v.push(disp);
        v
    }

    fn apx_group_mem_base(op: u8, grp: u8, ndd: u8, disp: u8, w: bool, nf: bool) -> Vec<u8> {
        let mut v = evex4(0, 14, ndd, w, nf, 0).to_vec();
        v.push(op);
        v.push(0x40 | ((grp & 7) << 3) | (14 & 7));
        v.push(disp);
        v
    }

    /// SIB index つき EVEX map4 接頭辞。base=r14、index=r29。
    /// X4=1 のため P1.2（U）は 0 にする。
    fn evex4_idx(rxreg: u8, idx: u8, ndd: u8, w: bool, nf: bool, nd: bool) -> [u8; 4] {
        let base = 14u8;
        let p0 = 0x04
            | if idx & 8 == 0 { 0x40 } else { 0 }
            | if rxreg & 8 == 0 { 0x80 } else { 0 }
            | if base & 8 == 0 { 0x20 } else { 0 }
            | if rxreg & 16 == 0 { 0x10 } else { 0 }
            | if base & 16 != 0 { 0x08 } else { 0 };
        let p1 = ((w as u8) << 7) | ((!ndd & 0x0F) << 3) | if idx & 16 == 0 { 0x04 } else { 0 };
        let p2 = if nd { 0x10 } else { 0 }
            | if nf { 0x04 } else { 0 }
            | if ndd & 16 == 0 { 0x08 } else { 0 };
        [0x62, p0, p1, p2]
    }

    /// base=r14、index=r29、scale 可変、disp8 のメモリ形。
    #[allow(clippy::too_many_arguments)]
    fn apx_mem_sib_nd(
        op: u8,
        ndd: u8,
        reg: u8,
        scale: u8,
        disp: u8,
        w: bool,
        nf: bool,
        nd: bool,
    ) -> Vec<u8> {
        let idx = 29u8;
        let base = 14u8;
        let mut v = evex4_idx(reg, idx, ndd, w, nf, nd).to_vec();
        v.push(op);
        v.push(0x40 | ((reg & 7) << 3) | 4);
        v.push((scale << 6) | ((idx & 7) << 3) | (base & 7));
        v.push(disp);
        v
    }

    fn apx_mem_sib(op: u8, ndd: u8, reg: u8, scale: u8, disp: u8, w: bool, nf: bool) -> Vec<u8> {
        apx_mem_sib_nd(op, ndd, reg, scale, disp, w, nf, true)
    }

    fn apx_group_mem_sib(
        op: u8,
        grp: u8,
        ndd: u8,
        scale: u8,
        disp: u8,
        w: bool,
        nf: bool,
    ) -> Vec<u8> {
        let idx = 29u8;
        let base = 14u8;
        let mut v = evex4_idx(0, idx, ndd, w, nf, true).to_vec();
        v.push(op);
        v.push(0x40 | ((grp & 7) << 3) | 4);
        v.push((scale << 6) | ((idx & 7) << 3) | (base & 7));
        v.push(disp);
        v
    }

    fn mem_disp(rng: &mut Rng) -> u8 {
        ((rng.next() % 16) * 8) as u8
    }

    fn apx_mem_any(rng: &mut Rng, op: u8, ndd: u8, reg: u8, w: bool, nf: bool) -> Vec<u8> {
        match rng.next() % 3 {
            0 => apx_mem(op, ndd, reg, mem_addr(rng), w, nf),
            1 => {
                let disp = mem_disp(rng);
                apx_mem_base(op, ndd, reg, disp, w, nf)
            }
            _ => {
                let disp = mem_disp(rng);
                let scale = (rng.next() % 4) as u8;
                apx_mem_sib(op, ndd, reg, scale, disp, w, nf)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apx_mem_nd_any(
        rng: &mut Rng,
        op: u8,
        ndd: u8,
        reg: u8,
        w: bool,
        nf: bool,
        nd: bool,
    ) -> Vec<u8> {
        match rng.next() % 3 {
            0 => apx_mem_nd(op, ndd, reg, mem_addr(rng), w, nf, nd),
            1 => {
                let disp = mem_disp(rng);
                apx_mem_base_nd(op, ndd, reg, disp, w, nf, nd)
            }
            _ => {
                let disp = mem_disp(rng);
                let scale = (rng.next() % 4) as u8;
                apx_mem_sib_nd(op, ndd, reg, scale, disp, w, nf, nd)
            }
        }
    }

    fn apx_group_mem_any(rng: &mut Rng, op: u8, grp: u8, ndd: u8, w: bool, nf: bool) -> Vec<u8> {
        match rng.next() % 3 {
            0 => apx_group_mem(op, grp, ndd, mem_addr(rng), w, nf),
            1 => {
                let disp = mem_disp(rng);
                apx_group_mem_base(op, grp, ndd, disp, w, nf)
            }
            _ => {
                let disp = mem_disp(rng);
                let scale = (rng.next() % 4) as u8;
                apx_group_mem_sib(op, grp, ndd, scale, disp, w, nf)
            }
        }
    }

    /// スクラッチ内の 8 バイト整列アドレス。
    fn mem_addr(rng: &mut Rng) -> u64 {
        mem_va_of() + (rng.next() % 30) * 8
    }

    /// 命令ごとのフラグ比較マスク。`FLAG_MASK` のうち、その命令が
    /// 定義する旗だけを見る。
    const M_SHIFT: u64 = FLAG_MASK & !0x800; // OF 不定
    const M_MUL: u64 = 0x801; // CF|OF
    const M_BSF: u64 = 0x40; // ZF のみ（他旗は不定）

    /// BSF/BSR は source=0 で destination が不定。マスク上位に
    /// (dst,src,w) を畳み、SDE 側の不定値で同期できるようにする。
    const SCAN_TAG: u64 = 1 << 32;
    fn with_scan(mask: u64, dst: u8, src: u8, w: bool) -> u64 {
        mask | SCAN_TAG | ((dst as u64) << 33) | ((src as u64) << 39) | ((w as u64) << 45)
    }

    fn scan_meta(mask: u64) -> Option<(u8, u8, bool)> {
        if mask & SCAN_TAG == 0 {
            return None;
        }
        Some((
            ((mask >> 33) & 0x3f) as u8,
            ((mask >> 39) & 0x3f) as u8,
            mask & (1 << 45) != 0,
        ))
    }

    /// 乱択命令を1つ生成する。APX（REX2）の reg-reg 整数命令が主体。
    /// 戻り値は (バイト列, フラグ比較マスク)。
    fn gen_insn(rng: &mut Rng) -> (Vec<u8>, u64) {
        let a = reg(rng);
        let b = reg(rng);
        let w = rng.next().is_multiple_of(2);
        match rng.next() % 18 {
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
                let meta = if op == 0xBC || op == 0xBD {
                    with_scan(m, a, b, w)
                } else {
                    m
                };
                (rrm2(op, a, b, w), meta)
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
            // EVEX map4 の NDD/NF 2 項 ALU。ADC/SBB は NF を持たない。
            12 => {
                let (op, nf_ok) = [
                    (0x01u8, true),
                    (0x09, true),
                    (0x11, false),
                    (0x19, false),
                    (0x21, true),
                    (0x29, true),
                    (0x31, true),
                ][(rng.next() % 7) as usize];
                let d = reg(rng);
                let nf = nf_ok && rng.next().is_multiple_of(2);
                let v = if rng.next().is_multiple_of(4) {
                    apx_mem_any(rng, op, d, a, w, nf)
                } else {
                    apx_rr(op, d, a, b, w, nf)
                };
                (v, if nf { 0 } else { FLAG_MASK })
            }
            // EVEX map4 の INC/DEC/NOT/NEG と CL カウントの SHL/SHR/SAR。NOT だけ NF なし。
            13 => {
                let (op, grp, nf_ok) = [
                    (0xFFu8, 0u8, true),
                    (0xFF, 1, true),
                    (0xF7, 2, false),
                    (0xF7, 3, true),
                    (0xD1, 4, true),
                    (0xD1, 5, true),
                    (0xD1, 7, true),
                ][(rng.next() % 7) as usize];
                let d = reg(rng);
                let nf = nf_ok && rng.next().is_multiple_of(2);
                (
                    if rng.next().is_multiple_of(4) {
                        apx_group_mem_any(rng, op, grp, d, w, nf)
                    } else {
                        apx_group(op, grp, d, a, w, nf)
                    },
                    if nf { 0 } else { FLAG_MASK },
                )
            }
            // REX2 の cmov（map1）か mov imm。
            11 => {
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
            // PUSH2/POP2。レジスタ被演算子だけだが、実際の読み書きは
            // ゲストスタックへ行く。W は P 形の選択、flags は変えない。
            16 => {
                let d = reg(rng);
                let mut rm = reg(rng);
                let pop = rng.next().is_multiple_of(2);
                if pop && rm == d {
                    rm = if d == 0 { 1 } else { 0 };
                }
                let pp = rng.next().is_multiple_of(2);
                (
                    apx_group(
                        if pop { 0x8F } else { 0xFF },
                        if pop { 0 } else { 6 },
                        d,
                        rm,
                        pp,
                        false,
                    ),
                    0,
                )
            }
            // CMOV/CFCMOV の ND/NF 4 形。ND=0,NF=1 のメモリ形は
            // 条件付きストアで、メモリ出力比較の対象になる。
            17 => {
                let cc = (rng.next() % 16) as u8;
                let variant = rng.next() % 4;
                let (nd, nf) = match variant {
                    0 => (false, false),
                    1 => (false, true),
                    2 => (true, false),
                    _ => (true, true),
                };
                let d = if nd { reg(rng) } else { 0 };
                let v = if rng.next().is_multiple_of(2) {
                    apx_mem_nd_any(rng, 0x40 | cc, d, a, w, nf, nd)
                } else {
                    apx_rr_nd(0x40 | cc, d, a, b, w, nf, nd)
                };
                (v, 0)
            }
            // CCMP/CTEST の NCI。常に真/偽の両側を固定バイトで入れ、
            // dfv と実比較の双方をカバーする。被演算子は r25/r26 だが、
            // 初期 ctx が乱択なので値はシードごとに変わる。
            15 => {
                let v = match rng.next() % 4 {
                    0 => vec![0x62, 0x4C, 0x14, 0x0B, 0x39, 0xD1],
                    1 => vec![0x62, 0x4C, 0x14, 0x0A, 0x39, 0xD1],
                    2 => vec![0x62, 0x4C, 0x0C, 0x0B, 0xF7, 0xC1, 0x02, 0x00, 0x00, 0x00],
                    _ => vec![0x62, 0x4C, 0x0C, 0x0A, 0xF7, 0xC1, 0x02, 0x00, 0x00, 0x00],
                };
                (v, FLAG_MASK | 0x10)
            }
            // EVEX map4 の IMUL または NDD CMOVcc。
            _ => {
                let d = reg(rng);
                if rng.next().is_multiple_of(2) {
                    let nf = rng.next().is_multiple_of(2);
                    let v = if rng.next().is_multiple_of(4) {
                        apx_mem_any(rng, 0xAF, d, a, w, nf)
                    } else {
                        apx_rr(0xAF, d, a, b, w, nf)
                    };
                    (v, if nf { 0 } else { M_MUL })
                } else {
                    let cc = (rng.next() % 16) as u8;
                    let nf = rng.next().is_multiple_of(2);
                    let v = if rng.next().is_multiple_of(4) {
                        apx_mem_any(rng, 0x40 | cc, d, a, w, nf)
                    } else {
                        apx_rr(0x40 | cc, d, a, b, w, nf)
                    };
                    (v, 0)
                }
            }
        }
    }

    /// polyisa 側の環境。コード頁とメモリ/スタック領域を写像する。
    fn poly_env() -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(CODE_VA), 1, rwx).unwrap();
        let mem_base = mem_va_of() & !0xfff;
        env.backend
            .mem
            .map(VirtAddr(mem_base), 2, Perms::RW)
            .unwrap();
        env.backend
            .mem
            .write(VirtAddr(mem_va_of()), &mem_pattern())
            .unwrap();
        env.backend
            .set(polyisa_guest_x86::sem::xcr0_ref(), 0x8_0003);
        env
    }

    /// ctx の全状態を polyisa 側に写す。Gpr(16-31) は x2 に行く。
    fn poly_load(env: &mut BareEnv, ctx: &Ctx) {
        for i in 0..32u8 {
            let v = if i == 4 { ctx.rsp } else { ctx.gpr(i as usize) };
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
        init.set_gpr(14, mem_va_of());
        init.set_gpr(29, 4);
        // init.rsp をスタック中程の 16 バイト境界へ向ける
        // （popfq 復元の push が生きられるよう有効なスタックが要る）。
        init.rsp = (stack_va_of() + 2048) & !0xf;
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
        let want = STEPS * SLOT + out_tail_bytes();
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
        // 各 epilogue は flags 復元のために `push;popfq` を行う。
        // pop はメモリを消さないので、SDE 側の最終メモリに残るこの
        // 一時 qword を polyisa 側へも再現する。プロローグの初期
        // flags 読み込みは init.rsp へ張り替える前なので、ゲスト
        // スタックには残らない。
        for (i, insn) in insns.iter().enumerate() {
            let scan_zero = scan_meta(masks[i]).is_some_and(|(_, src, w)| {
                let v = sem::read64(&mut env.backend, Gpr(src));
                if w { v == 0 } else { v as u32 == 0 }
            });
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
                if r == 15 {
                    // r15 は SDE 側で ctx ポインタに使う予約レジスタ。
                    continue;
                }
                if scan_zero && scan_meta(masks[i]).is_some_and(|(dst, _, _)| dst == r) {
                    continue;
                }
                let (hv, pv) = (n.gpr(r as usize), sem::read64(&mut env.backend, Gpr(r)));
                if hv != pv {
                    ds.push(format!("r{r} {hv:#x} vs {pv:#x}"));
                }
            }
            let mask = masks[i] & 0xffff_ffff;
            let hf = n.rflags & mask;
            let pf = u64::from(env.backend.get(sem::eflags_ref())) & mask;
            if hf != pf {
                ds.push(format!("eflags {hf:#x} vs {pf:#x}"));
            }
            if !ds.is_empty() {
                let before = if i == 0 {
                    ctx.rflags
                } else {
                    native[i - 1].rflags
                };
                return Some(format!(
                    "seq {seed} step {i}: insn {}: {}; init r7={:#x} r23={:#x} flags={:#x}; before flags={:#x}",
                    insn.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    ds.join("; "),
                    ctx.gpr(7),
                    ctx.gpr(23),
                    ctx.rflags,
                    before,
                ));
            }
            // 不定旗（シフトの OF 等）は SDE 側の実値で同期する。
            // 残置すると次ステップの全マスク比較で再浮上する。
            env.backend
                .set(sem::eflags_ref(), (n.rflags & FLAG_MASK) as u32 | 0x2);
            if scan_zero && let Some((dst, _, _)) = scan_meta(masks[i]) {
                sem::write64(&mut env.backend, Gpr(dst), n.gpr(dst as usize));
            }
            env.backend
                .mem
                .write(VirtAddr(n.rsp - 8), &n.rflags.to_le_bytes())
                .unwrap();
        }

        // 最終メモリとスタックを比較する。出力は slots の後ろに
        // memory(256B)+stack(4KiB) の順で並ぶ。
        let tail = &slots[STEPS * SLOT..];
        let mut pmem = vec![0u8; out_tail_bytes()];
        env.backend
            .mem
            .read(VirtAddr(mem_va_of()), &mut pmem, data_access())
            .unwrap();
        if tail != pmem.as_slice() {
            let at = tail
                .iter()
                .zip(pmem.iter())
                .position(|(a, b)| a != b)
                .unwrap();
            return Some(format!(
                "seq {seed}: memory +{at:#x} ({:#x}) {:#x} vs {:#x}",
                mem_va_of() + at as u64,
                tail[at],
                pmem[at],
            ));
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

    #[test]
    fn apx_corpus_polyisa_smoke() {
        // SDE がない環境でも、生成した reg-direct 命令が polyisa で
        // デコード・実行できることを確認する。値の正しさは SDE 差分が担う。
        let mut rng = Rng(0xA94C_0001);
        for i in 0..256 {
            let (insn, _) = gen_insn(&mut rng);
            let mut env = poly_env();
            env.backend.set(sem::xcr0_ref(), 0x8_0003);
            sem::write64(&mut env.backend, Gpr(4), (stack_va_of() + 2048) & !0xf);
            sem::write64(&mut env.backend, Gpr(14), mem_va_of());
            sem::write64(&mut env.backend, Gpr(29), 4);
            env.backend.mem.write(VirtAddr(CODE_VA), &insn).unwrap();
            let out = run_x86::run_mode_ex(
                &mut env,
                CODE_VA as u32,
                &mut NoTrap,
                1,
                true,
                polyisa_guest_x86::DEFAULT_FEATS | polyisa_guest_x86::FEAT_APX,
                &polyisa_guest_x86::DEFAULT_PARAMS,
            );
            assert!(
                matches!(out, Outcome::StepLimit { .. }),
                "generated insn {i} {}: {out:?}",
                insn.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
        }
    }

    #[test]
    fn apx_encoding_examples() {
        // bare_x86run の既知バイト列と同じ map4 形を作れることを固定する。
        assert_eq!(
            apx_rr(0x29, 24, 26, 25, false, false),
            vec![0x62, 0x4C, 0x3C, 0x10, 0x29, 0xD1]
        );
        assert_eq!(
            apx_rr(0x29, 24, 26, 25, false, true),
            vec![0x62, 0x4C, 0x3C, 0x14, 0x29, 0xD1]
        );
        assert_eq!(
            apx_rr(0x44, 24, 26, 25, false, false),
            vec![0x62, 0x4C, 0x3C, 0x10, 0x44, 0xD1]
        );
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
