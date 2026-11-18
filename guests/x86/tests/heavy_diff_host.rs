// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Gap: GAP-0030
//! ホスト CPU との実行差分（層: diff、E2）。
//!
//! 乱択のレジスタ-レジスタ整数命令を、polyisa とホスト CPU で
//! 1 命令ずつ実行し、GPR・RFLAGS・スタックスクラッチを比較する。
//!
//! ホスト側は `polyisa_host::exec_mem::ExecMem` に
//! 「命令 + 状態回収エピローグ」を置き、裸関数 `run_ctx` が全 GPR
//! と RFLAGS の読み書きを請け負う。r15 は ctx ポインタの予約
//! レジスタで、コーパスは r15 と rsp を被演算子に選ばない。
//!
//! コーパスは fault・分岐・外部観測を起こさない命令に限る
//! （div 系・メモリオペランド・制御移転・`popfq`・CPUID/RDSEED は除く）。
//! 比較は RFLAGS のユーザ可視旗（CF PF ZF SF OF）と全 GPR
//! （rsp はベースからの相対値）、スタックスクラッチ全域で行う。
//! 命令ごとに定義済み旗のマスクを掛け、不定旗は比較しない。
//!
//! x86-64 の unix ホストでのみ動く。他のホストでは空のテストになる。

#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", unix))]
mod imp {
    use polyisa_cli::run_x86::{self, Outcome, TrapHandler, TrapOutcome};
    use polyisa_engine::bare::BareEnv;
    use polyisa_guest_x86::sem::Gpr;
    use polyisa_guest_x86::{CpuState, sem};
    use polyisa_host::exec_mem::ExecMem;
    use polyisa_mem::{Perms, VirtAddr};
    use polyisa_os_linux::x86::data_access;
    use polyisa_sem::Backend as _;
    use std::cell::UnsafeCell;

    /// 比較対象のユーザ可視フラグ（CF PF ZF SF OF）。bit1 は常時 1。
    /// AF はシフト・乗除算系でアーキテクチャ上不定であり、polyisa は
    /// ホストの残り値を再現しないので比較対象から外す。
    const FLAG_MASK: u64 = 0x8C5;
    /// ゲストコードの仮想アドレス。
    const CODE_VA: u64 = 0x1000;
    /// ゲストスタック（スクラッチ）の仮想アドレスとサイズ。
    const STACK_VA: u64 = 0x10_0000;
    const SCRATCH: usize = 0x1000;
    /// シーケンスあたりの命令数と、既定のシーケンス数。
    const STEPS: usize = 32;
    const SEQS: usize = 128;

    /// ホスト実行コンテキスト。オフセットは `run_ctx` とエピローグの
    /// 機械語に直結するため `#[repr(C)]` で固定する。
    #[repr(C)]
    struct Ctx {
        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rsi: u64,
        rdi: u64,
        rbp: u64,
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rsp: u64,
        rflags: u64,
        code: u64,
        host_rsp: u64,
    }

    impl Ctx {
        /// `i` は x86 のレジスタ番号（rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..）。
        fn gpr(&self, i: usize) -> u64 {
            match i {
                0 => self.rax,
                1 => self.rcx,
                2 => self.rdx,
                3 => self.rbx,
                4 => self.rsp,
                5 => self.rbp,
                6 => self.rsi,
                7 => self.rdi,
                8 => self.r8,
                9 => self.r9,
                10 => self.r10,
                11 => self.r11,
                12 => self.r12,
                13 => self.r13,
                14 => self.r14,
                15 => self.r15,
                _ => unreachable!(),
            }
        }

        fn set_gpr(&mut self, i: usize, v: u64) {
            match i {
                0 => self.rax = v,
                1 => self.rcx = v,
                2 => self.rdx = v,
                3 => self.rbx = v,
                4 => self.rsp = v,
                5 => self.rbp = v,
                6 => self.rsi = v,
                7 => self.rdi = v,
                8 => self.r8 = v,
                9 => self.r9 = v,
                10 => self.r10 = v,
                11 => self.r11 = v,
                12 => self.r12 = v,
                13 => self.r13 = v,
                14 => self.r14 = v,
                15 => self.r15 = v,
                _ => unreachable!(),
            }
        }
    }

    /// ctx 上の全 GPR・RFLAGS・rsp を読み、`ctx.code` へ飛ぶ。
    /// 戻り値はない。実行結果は ctx に書き戻される。
    /// r15 はハーネス予約で、ctx のポインタを通して持つ。
    /// コーパスが r15 をオペランドに選ぶことはないので、
    /// 命令実行をまたいで ctx が失われない。ゲストの r15 値は
    /// 初期値のまま動かないものとして両側で一致する。
    ///
    /// # Safety
    /// `ctx` は有効な `Ctx` を指し、`ctx.code` はエピローグを持つ
    /// 実行可能な領域を指すこと。`ctx.rsp` は書き込み可能な
    /// スクラッチ領域を指すこと。
    #[unsafe(naked)]
    unsafe extern "C" fn run_ctx(_ctx: *mut Ctx) {
        core::arch::naked_asm!(
            "push rbx",
            "push rbp",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "mov [rdi + 144], rsp",
            "mov r15, rdi",
            "push qword ptr [r15 + 128]",
            "popfq",
            "mov rax, [r15 + 0]",
            "mov rbx, [r15 + 8]",
            "mov rcx, [r15 + 16]",
            "mov rdx, [r15 + 24]",
            "mov rsi, [r15 + 32]",
            "mov rdi, [r15 + 40]",
            "mov rbp, [r15 + 48]",
            "mov r8,  [r15 + 56]",
            "mov r9,  [r15 + 64]",
            "mov r10, [r15 + 72]",
            "mov r11, [r15 + 80]",
            "mov r12, [r15 + 88]",
            "mov r13, [r15 + 96]",
            "mov r14, [r15 + 104]",
            "mov rsp, [r15 + 120]",
            "jmp qword ptr [r15 + 136]",
        );
    }

    /// `mov [r15 + disp32], src` の命令バイトを追記する。
    fn st64(v: &mut Vec<u8>, rex_op: &[u8], disp: u32) {
        v.extend_from_slice(rex_op);
        v.extend_from_slice(&disp.to_le_bytes());
    }

    /// エピローグの機械語。r15 = ctx の前提で全フィールドを書き戻し、
    /// ホストの callee-saved を復元して ret する。スタックは一切
    /// 使わない（コーパスが触れたスクラッチに残りを出さないため）。
    /// RFLAGS は pushfq を使わず lahf + seto で合成する。
    fn epilogue() -> Vec<u8> {
        let mut v = Vec::with_capacity(160);
        st64(&mut v, &[0x49, 0x89, 0x87], 0); // rax
        st64(&mut v, &[0x49, 0x89, 0x9F], 8); // rbx
        st64(&mut v, &[0x49, 0x89, 0x8F], 16); // rcx
        st64(&mut v, &[0x49, 0x89, 0x97], 24); // rdx
        st64(&mut v, &[0x49, 0x89, 0xB7], 32); // rsi
        st64(&mut v, &[0x49, 0x89, 0xAF], 48); // rbp
        st64(&mut v, &[0x4D, 0x89, 0x87], 56); // r8
        st64(&mut v, &[0x4D, 0x89, 0x8F], 64); // r9
        st64(&mut v, &[0x4D, 0x89, 0x97], 72); // r10
        st64(&mut v, &[0x4D, 0x89, 0x9F], 80); // r11
        st64(&mut v, &[0x4D, 0x89, 0xA7], 88); // r12
        st64(&mut v, &[0x4D, 0x89, 0xAF], 96); // r13
        st64(&mut v, &[0x4D, 0x89, 0xB7], 104); // r14
        // r15 は ctx ポインタなので書き戻さない（コーパスも触らない）。
        st64(&mut v, &[0x49, 0x89, 0xBF], 40); // rdi
        st64(&mut v, &[0x49, 0x89, 0xA7], 120); // rsp
        // RFLAGS のユーザ可視ビットを合成する: AH（lahf）に low8
        // （CF|PF|AF|ZF|SF）、seto の AL に OF。or で bit11 に揃える。
        v.extend_from_slice(&[0x9F]); // lahf
        v.extend_from_slice(&[0x0F, 0x90, 0xC0]); // seto al
        v.extend_from_slice(&[0x0F, 0xB6, 0xCC]); // movzx ecx, ah
        v.extend_from_slice(&[0x0F, 0xB6, 0xC0]); // movzx eax, al
        v.extend_from_slice(&[0xC1, 0xE0, 0x0B]); // shl eax, 11
        v.extend_from_slice(&[0x09, 0xC8]); // or eax, ecx
        st64(&mut v, &[0x49, 0x89, 0x87], 128); // rflags
        v.extend_from_slice(&[0x49, 0x8B, 0xA7]); // mov rsp, [r15 + 144]
        v.extend_from_slice(&144u32.to_le_bytes());
        v.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
        v.extend_from_slice(&[0x5D, 0x5B, 0xC3]); // pop rbp; pop rbx; ret
        v
    }

    /// `insn` をホスト上で `ctx` の状態から 1 命令だけ実行し、
    /// ctx を実行後の状態に更新する。
    fn host_step(ctx: &mut Ctx, insn: &[u8]) {
        let mut code = Vec::with_capacity(insn.len() + 200);
        code.extend_from_slice(insn);
        code.extend_from_slice(&epilogue());
        let mut m = ExecMem::new(code.len()).expect("map rw");
        m.write(&code).expect("write code");
        let m = m.finalize().expect("make rx");
        if std::env::var_os("POLYISA_BLOB").is_some() {
            eprintln!(
                "blob @{:#x}: {}",
                m.ptr() as u64,
                code.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
        }
        ctx.code = m.ptr() as u64;
        // SAFETY: code は insn+epilogue からなり、ctx.rsp は
        // スクラッチスタック内を指す。
        unsafe { run_ctx(ctx) };
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

        /// オペランド用のレジスタ番号。rsp (4) と r15 を外す。
        /// rsp は任意値を書く命令でエピローグが壊れないよう、
        /// r15 はハーネス予約（ctx ポインタ）のため。
        /// push/pop による ±8 はそのまま試される。
        fn reg(&mut self) -> u8 {
            loop {
                let r = (self.next() & 15) as u8;
                if r != 4 && r != 15 {
                    return r;
                }
            }
        }

        /// 境界値に偏らせた即値。
        fn imm(&mut self) -> u64 {
            match self.next() % 8 {
                0 => 0,
                1 => 1,
                2 => u64::MAX,
                3 => 0x8000_0000_0000_0000,
                4 => 0x7FFF_FFFF_FFFF_FFFF,
                5 => u64::from(self.next() as u8),
                _ => self.next(),
            }
        }
    }

    fn rex(w: bool, r: u8, b: u8) -> u8 {
        0x40 | u8::from(w) << 3 | ((r >> 3) & 1) << 2 | ((b >> 3) & 1)
    }

    /// mod=11 の modrm バイト。
    fn mrm(r: u8, m: u8) -> u8 {
        0xC0 | (r & 7) << 3 | (m & 7)
    }

    /// REX.W が要る 64 ビット形か、`w=false` で 32 ビット形の r,r 命令。
    /// 16 ビット形は `p66`、8 ビット形は `op8` 側を使う。
    fn rr(w: bool, op: u8, r: u8, m: u8, p66: bool) -> Vec<u8> {
        let mut v = Vec::with_capacity(4);
        if p66 {
            v.push(0x66);
        }
        if w || r >= 8 || m >= 8 {
            v.push(rex(w, r, m));
        }
        v.push(op);
        v.push(mrm(r, m));
        v
    }

    /// 8 ビット r,r 命令。reg 4-7 は REX なしで AH-BH、REX ありで
    /// SPL-DIL になるので、拡張レジスタを選んだときだけ REX を足す。
    fn rr8(op: u8, r: u8, m: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(3);
        if r >= 8 || m >= 8 {
            v.push(rex(false, r, m));
        }
        v.push(op);
        v.push(mrm(r, m));
        v
    }

    /// `rr` 系の出力 `[66][REX] op modrm` に 0F エスケープを挿す。
    /// REX は 0F の前に来る（`REX 0F op` の順）。
    fn two(mut v: Vec<u8>) -> Vec<u8> {
        v.insert(v.len() - 2, 0x0F);
        v
    }

    /// 命令ごとのフラグ比較マスク。`FLAG_MASK` のうち、その命令が
    /// アーキテクチャ上「不定」にするビットを落としたもの。
    /// - シフト/ローテート（D0-D3, C0-C1）: 回数 1 以外で OF は不定。
    /// - 乗除算・imul（F6/F7 /4,/5, 0F AF, 69, 6B）: CF|OF 以外は不定。
    /// - bt 系（0F A3/AB/B3/BB）: CF 以外は不定。
    const M_SHIFT: u64 = FLAG_MASK & !0x800; // OF 不定
    const M_MUL: u64 = 0x801; // CF|OF のみ確定
    const M_BT: u64 = 0x1; // CF のみ確定

    /// 1 命令の機械語とフラグ比較マスクを乱択で生成する。
    /// 生成物は fault しない・分岐しない・外を観測しない命令に限る。
    fn gen_insn(rng: &mut Rng) -> (Vec<u8>, u64) {
        let (a, b) = (rng.reg(), rng.reg());
        let w = rng.next() & 1 == 0;
        let (v, m) = match rng.next() % 24 {
            // 演算・比較の r,r 形（両方向）。8/16/32/64 ビット幅を混ぜる。
            0..=5 => {
                let alu = [
                    0x01u8, 0x03, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21, 0x23, 0x29, 0x2B, 0x31,
                    0x33, 0x39, 0x3B, 0x85, 0x87, 0x89, 0x8B,
                ];
                let op = alu[(rng.next() as usize) % alu.len()];
                let v = match rng.next() % 4 {
                    0 => rr8(op - 1, a, b),
                    1 => rr(false, op, a, b, true),
                    2 => rr(false, op, a, b, false),
                    _ => rr(true, op, a, b, false),
                };
                (v, FLAG_MASK)
            }
            // 演算の imm8（符号拡張）/imm32 形。
            6 | 7 => {
                let grp = (rng.next() % 8) as u8;
                let op = if rng.next() & 1 == 0 { 0x83 } else { 0x81 };
                let p66 = rng.next().is_multiple_of(4);
                let mut v = rr(w, op, grp, a, p66);
                // 66 接頭辞付きは imm16、83 は imm8、残りは imm32。
                // 66 は REX.W なしのときだけ imm16 に効く（66+REX.W は imm32）。
                let n = if op == 0x83 {
                    1
                } else if p66 && !w {
                    2
                } else {
                    4
                };
                v.extend_from_slice(&rng.imm().to_le_bytes()[..n]);
                (v, FLAG_MASK)
            }
            // mov r, imm。REX.W なら imm64、さもなければ C7 /0 imm32。
            8 => {
                let v = if w {
                    let mut v = vec![rex(true, 0, a), 0xB8 + (a & 7)];
                    v.extend_from_slice(&rng.imm().to_le_bytes());
                    v
                } else {
                    let p66 = rng.next().is_multiple_of(3);
                    let mut v = rr(false, 0xC7, 0, a, p66);
                    let n = if p66 { 2 } else { 4 };
                    v.extend_from_slice(&rng.imm().to_le_bytes()[..n]);
                    v
                };
                (v, FLAG_MASK)
            }
            // inc/dec/not/neg/mul/imul。
            9 => {
                let grp = [0u8, 1][(rng.next() & 1) as usize];
                (rr(w, 0xFF, grp, a, false), FLAG_MASK)
            }
            10 => {
                let grp = [2u8, 3, 4, 5][(rng.next() % 4) as usize];
                let v = if rng.next().is_multiple_of(4) {
                    rr8(0xF6, grp, a)
                } else {
                    rr(w, 0xF7, grp, a, false)
                };
                let m = if grp >= 4 { M_MUL } else { FLAG_MASK };
                (v, m)
            }
            // シフト・ローテート（CL、imm8、1 ビット）。
            11 | 12 => {
                let grp = [0u8, 1, 2, 3, 4, 5, 7][(rng.next() % 7) as usize];
                let op = [0xD3u8, 0xC1, 0xD1][(rng.next() % 3) as usize];
                let is8 = rng.next().is_multiple_of(5);
                let mut v = if is8 {
                    rr8(op - 1, grp, a)
                } else {
                    rr(w, op, grp, a, false)
                };
                // C0/C1 は imm8 形、D0-D3 は暗黙（1 または CL）。
                if op == 0xC1 {
                    v.push((rng.next() % 64) as u8);
                }
                // D1/D0 は回数 1 で OF 確定、C1/D3/D2 は不定。
                (v, if op == 0xD1 { FLAG_MASK } else { M_SHIFT })
            }
            // shld/shrd。
            13 => {
                let op = [0xA4u8, 0xA5, 0xAC, 0xAD][(rng.next() % 4) as usize];
                let mut v = two(rr(w, op, a, b, false));
                if op == 0xA4 || op == 0xAC {
                    v.push((rng.next() % 64) as u8);
                }
                (v, M_SHIFT)
            }
            // movzx/movsx/movsxd。
            14 => {
                let op = [0xB6u8, 0xB7, 0xBE, 0xBF][(rng.next() % 4) as usize];
                let mut v = Vec::new();
                // r8 ソース（B6/BE）で reg 4-7 は REX が要る（SPL 系）。
                if w || a >= 8 || b >= 8 || op & 1 == 0 && b >= 4 {
                    v.push(rex(w, a, b));
                }
                v.extend_from_slice(&[0x0F, op, mrm(a, b)]);
                (v, FLAG_MASK)
            }
            // movsxd (63 /r, REX.W)。
            15 => (rr(true, 0x63, a, b, false), FLAG_MASK),
            // bswap。
            16 => {
                let mut v = Vec::new();
                if w || a >= 8 {
                    v.push(rex(w, 0, a));
                }
                v.extend_from_slice(&[0x0F, 0xC8 + (a & 7)]);
                (v, FLAG_MASK)
            }
            // setcc。
            17 => {
                let mut v = Vec::new();
                if a >= 4 {
                    v.push(rex(false, 0, a));
                }
                v.extend_from_slice(&[0x0F, 0x90 + (rng.next() % 16) as u8, 0xC0 + (a & 7)]);
                (v, FLAG_MASK)
            }
            // cmovcc。
            18 => (
                two(rr(w, 0x40 + (rng.next() % 16) as u8, a, b, false)),
                FLAG_MASK,
            ),
            // bt/bts/btr/btc r,r。
            19 => (
                two(rr(
                    w,
                    [0xA3u8, 0xAB, 0xB3, 0xBB][(rng.next() % 4) as usize],
                    a,
                    b,
                    false,
                )),
                M_BT,
            ),
            // imul r,r / r,r,imm。
            20 => (two(rr(w, 0xAF, a, b, false)), M_MUL),
            21 => {
                let op = if rng.next() & 1 == 0 { 0x6B } else { 0x69 };
                let mut v = rr(w, op, a, b, false);
                let n = if op == 0x6B { 1 } else { 4 };
                v.extend_from_slice(&rng.imm().to_le_bytes()[..n]);
                (v, M_MUL)
            }
            // xadd/cmpxchg。
            22 => (
                two(rr(
                    w,
                    if rng.next() & 1 == 0 { 0xC1 } else { 0xB1 },
                    a,
                    b,
                    false,
                )),
                FLAG_MASK,
            ),
            // push/pop/pushfq/lahf/sahf/cbw/cwde/cdq/cqo/nop/xchg rax,r。
            _ => {
                let v = match rng.next() % 11 {
                    0 => {
                        if a >= 8 {
                            vec![0x41, 0x50 + (a & 7)]
                        } else {
                            vec![0x50 + a]
                        }
                    }
                    1 => {
                        if a >= 8 {
                            vec![0x41, 0x58 + (a & 7)]
                        } else {
                            vec![0x58 + a]
                        }
                    }
                    // 0x9C (pushfq) はシステムフラグ（IF 等）の残り差を
                    // 押すので対象外——polyisa はユーザ可視旗だけを持つ。
                    2 => vec![0x9F],
                    3 => vec![0x9E],
                    4 => vec![0x98],
                    5 => vec![0x66, 0x98],
                    6 => vec![0x99],
                    7 => vec![0x48, 0x99],
                    8 => vec![0x90],
                    9 => vec![0x6A, (rng.next() % 128) as u8],
                    _ => {
                        let mut v = Vec::new();
                        if a >= 8 {
                            v.push(rex(true, 0, a));
                        }
                        v.push(0x90 + (a & 7));
                        v
                    }
                };
                (v, FLAG_MASK)
            }
        };
        (v, m)
    }

    /// ゲストメモリのスタックスクラッチに対応するホスト側の領域。
    /// `UnsafeCell` で包み、実行中に機械語から書き込めるようにする。
    struct Scratch(UnsafeCell<[u8; SCRATCH]>);

    // SAFETY: このテストは run_ctx 経由の機械語がスクラッチ内だけを
    // 触るよう設計されており、複数スレッドからは触らない。
    unsafe impl Sync for Scratch {}

    impl Scratch {
        fn new() -> Self {
            Self(UnsafeCell::new([0u8; SCRATCH]))
        }

        fn base(&self) -> u64 {
            self.0.get() as u64
        }

        fn buf(&self) -> &[u8; SCRATCH] {
            // SAFETY: run_ctx の呼び出しの合間だけ読む。
            unsafe { &*self.0.get() }
        }

        fn reset(&self, pat: &[u8]) {
            // SAFETY: run_ctx の呼び出しの合間だけ書く。
            unsafe {
                (*self.0.get()).copy_from_slice(pat);
            }
        }
    }

    /// polyisa 側の環境。コード頁とスタックスクラッチを写像する。
    fn poly_env(pat: &[u8]) -> BareEnv {
        let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
        let rwx = Perms(Perms::R.0 | Perms::W.0 | Perms::X.0);
        env.backend.mem.map(VirtAddr(CODE_VA), 1, rwx).unwrap();
        env.backend
            .mem
            .map(VirtAddr(STACK_VA), 1, Perms::RW)
            .unwrap();
        env.backend.mem.write(VirtAddr(STACK_VA), pat).unwrap();
        env
    }

    /// ctx の全状態を polyisa 側に写す。rsp はスタック相対で変換する。
    fn poly_load(env: &mut BareEnv, ctx: &Ctx, stack_base: u64) {
        for i in 0..16u8 {
            let v = if i == 4 {
                STACK_VA + (ctx.rsp - stack_base)
            } else {
                ctx.gpr(i as usize)
            };
            sem::write64(&mut env.backend, Gpr(i), v);
        }
        let f = (ctx.rflags & FLAG_MASK) as u32 | 0x2;
        env.backend.set(sem::eflags_ref(), f);
    }

    /// 実行後の host ctx と polyisa env の差を返す。
    fn diff(
        ctx: &Ctx,
        stack_base: u64,
        env: &mut BareEnv,
        scratch: &Scratch,
        mask: u64,
    ) -> Option<String> {
        let mut ds = Vec::new();
        for i in 0..16u8 {
            let (hv, pv) = if i == 4 {
                let h = ctx.rsp.wrapping_sub(stack_base);
                let p = sem::read64(&mut env.backend, Gpr(i)).wrapping_sub(STACK_VA);
                (h, p)
            } else {
                (ctx.gpr(i as usize), sem::read64(&mut env.backend, Gpr(i)))
            };
            if hv != pv {
                ds.push(format!("r{i} {hv:#x} vs {pv:#x}"));
            }
        }
        let hf = ctx.rflags & mask;
        let pf = u64::from(env.backend.get(sem::eflags_ref())) & mask;
        if hf != pf {
            ds.push(format!("eflags {hf:#x} vs {pf:#x}"));
        }
        let mut pm = vec![0u8; SCRATCH];
        env.backend
            .mem
            .read(VirtAddr(STACK_VA), &mut pm, data_access())
            .unwrap();
        let hm = scratch.buf();
        if pm.as_slice() != hm.as_slice() {
            let k = pm.iter().zip(hm.iter()).position(|(x, y)| x != y).unwrap();
            ds.push(format!("stk[{k:#x}] {:#x} vs {:#x}", pm[k], hm[k]));
        }
        (!ds.is_empty()).then(|| ds.join("; "))
    }

    /// トラップは差分として扱う（コーパスに分岐・trap は無い）。
    struct NoTrap;

    impl TrapHandler for NoTrap {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
    }

    /// 1 シーケンスを実行し、最初の差分を報告用文字列で返す。
    fn run_seq(seed: u64) -> Option<String> {
        let mut rng = Rng(seed);
        let insns: Vec<(Vec<u8>, u64)> = (0..STEPS).map(|_| gen_insn(&mut rng)).collect();
        let scratch = Scratch::new();
        let pat: Vec<u8> = (0..SCRATCH)
            .map(|i| ((i.wrapping_mul(31) + 7) & 0xff) as u8)
            .collect();
        let stack_base = scratch.base();
        let mut env = poly_env(&pat);
        scratch.reset(&pat);
        let mut ctx = Ctx {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: stack_base + 0x800,
            rflags: 0x2,
            code: 0,
            host_rsp: 0,
        };
        for (i, (insn, mask)) in insns.iter().enumerate() {
            // 毎ステップ、レジスタとフラグを乱択し直す（setcc/cmov/adc を打つ）。
            for r in 0..16u8 {
                if r != 4 {
                    ctx.set_gpr(r as usize, rng.imm());
                }
            }
            ctx.rflags = (rng.next() & FLAG_MASK) | 0x2;
            // CL はシフト量。過剰な値でも両側で同じマスクが効く。
            poly_load(&mut env, &ctx, stack_base);
            env.backend.mem.write(VirtAddr(CODE_VA), insn).unwrap();
            host_step(&mut ctx, insn);
            let out = run_x86::run_mode_ex(
                &mut env,
                CODE_VA as u32,
                &mut NoTrap,
                1,
                true,
                polyisa_guest_x86::DEFAULT_FEATS,
                &polyisa_guest_x86::DEFAULT_PARAMS,
            );
            if !matches!(out, Outcome::StepLimit { .. }) {
                return Some(format!(
                    "seq {seed} step {i}: insn {}: poly outcome {out:?}",
                    insn.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                ));
            }
            if let Some(d) = diff(&ctx, stack_base, &mut env, &scratch, *mask) {
                return Some(format!(
                    "seq {seed} step {i}: insn {}: {d}",
                    insn.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                ));
            }
        }
        None
    }

    pub fn run() {
        let mut rng = Rng(0xD1FF_0001);
        let mut reports = Vec::new();
        for _ in 0..SEQS {
            let seed = rng.next();
            if let Some(r) = run_seq(seed) {
                reports.push(r);
                if reports.len() >= 20 {
                    break;
                }
            }
        }
        assert!(reports.is_empty(), "host diff:\n{}", reports.join("\n"));
    }
}

/// x86-64 ホストでは乱択シーケンスを差分する。他ホストでは何もしない。
#[test]
fn diff_host() {
    #[cfg(all(target_arch = "x86_64", unix))]
    imp::run();
}
