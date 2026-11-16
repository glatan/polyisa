// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! IR を x86-64 の機械語にする。
//!
//! ISADL のエンコーダはまだスタブなので、使う命令だけを手で焼く
//! （段階 9 の判断として `docs/notes-stage5-25-pending.md` に記す）。
//! 値はフレーム内の 16 バイトのスロットに置き、よく触る状態の
//! フィールドは r12-r15 に固定する。それ以外の演算・メモリは
//! `rt.rs` の関数へ呼び出しにする（正しさ優先）。
//!
//! 生成する関数の形：`unsafe extern "sysv64" fn(*mut RtCtx)`。
//! フレーム内配置：
//! ```text
//! rsp+0   : ctrl（最後の Jump/Branch が書く、出口の既定の次）
//! rsp+16  : ヘルパー呼び出し用の 64 バイトのスクラッチ
//! rsp+80  : 値スロット（16 バイト × 値番号）
//! ```
//! サブフレーム後の rsp は 16 の倍数なので、`u128` を載せる
//! スクラッチと値スロットは 16 の倍数の番地に置く。

use polyisa_host::exec_mem::ExecMem;
use polyisa_ir::{BinOp, Ext, Id, Inst, Recorded, UnOp, Wid};
use polyisa_sem::Cmp;

use crate::ctx::RtCtx;
use crate::rt;

// レジスタ番号。
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSP: u8 = 4;
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;
const R8: u8 = 8;
const R9: u8 = 9;
const R12: u8 = 12;
const R13: u8 = 13;
const R14: u8 = 14;
const R15: u8 = 15;

/// フレーム内の値スロットの先頭。16 の倍数（`u128` の整列）。
const VALS: i32 = 80;
/// ヘルパー呼び出しのスクラッチ領域。16 の倍数（`u128` の整列）。
const SCRATCH: i32 = 16;

/// `RtCtx` のフィールド番地。
macro_rules! coff {
    ($f:ident) => {
        core::mem::offset_of!(RtCtx, $f) as i32
    };
}

/// ブロック関数の形。
pub type BlockFn = unsafe extern "sysv64" fn(*mut RtCtx);

/// コンパイル済みブロック。`mem` は RX のコード領域。
pub struct Compiled {
    mem: polyisa_host::exec_mem::FinalMem,
}

impl Compiled {
    /// 先頭から実行する。
    ///
    /// # 安全性
    /// `ctx` は有効な `RtCtx` を指す必要がある。生成コードは
    /// `ctx.backend`/`ctx.state` の指す先を読み書きする。
    pub unsafe fn call(&self, ctx: *mut RtCtx) {
        // SAFETY: `mem` は `compile` が置いたこの形の関数。
        let f: BlockFn = unsafe { core::mem::transmute(self.mem.ptr()) };
        unsafe { f(ctx) };
    }
}

/// `Recorded` を機械語にする。実行可能メモリが取れなければ `None`。
pub fn compile(rec: &Recorded) -> Option<Compiled> {
    let mut g = Gen::new(rec);
    let code = g.build();
    let mut mem = ExecMem::new(code.len().max(64))?;
    mem.write(&code)?;
    let mem = mem.finalize()?;
    Some(Compiled { mem })
}

/// コード生成の状態。
struct Gen<'a> {
    e: Em,
    rec: &'a Recorded,
    /// ((off, w), 固定レジスタ)。番号順に r12.. を割り当てる。
    cache: Vec<((u32, Wid), u8)>,
    /// 固定レジスタに書かれた（戻す必要がある）もの。
    dirty: [bool; 4],
    /// エピローグへ飛ぶジャンプの位置。
    epi: Vec<usize>,
    /// フレームサイズ。
    frame: i32,
}

/// エミッタ。
struct Em {
    c: Vec<u8>,
}

impl Em {
    fn new() -> Self {
        Self {
            c: Vec::with_capacity(512),
        }
    }
    fn u8(&mut self, v: u8) {
        self.c.push(v);
    }
    fn i32(&mut self, v: i32) {
        self.c.extend(v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.c.extend(v.to_le_bytes());
    }
    fn pos(&self) -> usize {
        self.c.len()
    }
    /// `pos` の rel32 を現在位置へ向かせる。
    fn patch(&mut self, pos: usize) {
        let rel = self.c.len() - pos - 4;
        self.c[pos..pos + 4].copy_from_slice(&(rel as i32).to_le_bytes());
    }
    /// `pos` の rel32 を `target` の位置へ向かせる。
    fn patch_to(&mut self, pos: usize, target: usize) {
        let rel = target - pos - 4;
        self.c[pos..pos + 4].copy_from_slice(&(rel as i32).to_le_bytes());
    }

    /// REX。`r` は reg フィールド、`m` は r/m フィールドの拡張。
    fn rex(&mut self, w: bool, r: u8, m: u8) {
        let v = 0x40 | ((w as u8) << 3) | (((r >> 3) & 1) << 2) | ((m >> 3) & 1);
        if v != 0x40 {
            self.u8(v);
        }
    }

    /// `[base + off]` の modrm(+sib)+disp。reg フィールドは `reg`。
    fn rm_mem(&mut self, reg: u8, base: u8, off: i32) {
        let mdo = if off == 0 && base != RBP {
            0u8
        } else if (-128..128).contains(&off) {
            1
        } else {
            2
        };
        let sib = base & 7 == 4;
        self.u8(mdo << 6 | (reg & 7) << 3 | if sib { 4 } else { base & 7 });
        if sib {
            // scale=0, index=100 (なし), base
            self.u8(0x20 | (base & 7));
        }
        match mdo {
            1 => self.u8(off as u8),
            2 => self.i32(off),
            _ => {}
        }
    }

    // ---- 基本の転送 ----

    /// `mov r64, imm64`。
    fn mov_ri(&mut self, r: u8, v: u64) {
        self.rex(true, 0, r);
        self.u8(0xB8 | (r & 7));
        self.u64(v);
    }
    /// `mov r64, r64`。
    fn mov_rr(&mut self, d: u8, s: u8) {
        self.rex(true, s, d);
        self.u8(0x89);
        self.u8(0xC0 | (s & 7) << 3 | (d & 7));
    }
    /// `mov r64, [base+off]`。
    fn mov_rm(&mut self, r: u8, base: u8, off: i32) {
        self.rex(true, r, base);
        self.u8(0x8B);
        self.rm_mem(r, base, off);
    }
    /// `mov [base+off], r64`。
    fn mov_mr(&mut self, base: u8, off: i32, r: u8) {
        self.rex(true, r, base);
        self.u8(0x89);
        self.rm_mem(r, base, off);
    }
    /// `mov r32, [base+off]`（上位は 0）。
    fn mov_rm32(&mut self, r: u8, base: u8, off: i32) {
        self.rex(false, r, base);
        self.u8(0x8B);
        self.rm_mem(r, base, off);
    }
    /// `mov [base+off], r32`。
    fn mov_mr32(&mut self, base: u8, off: i32, r: u8) {
        self.rex(false, r, base);
        self.u8(0x89);
        self.rm_mem(r, base, off);
    }
    fn movzx8(&mut self, r: u8, base: u8, off: i32) {
        self.rex(false, r, base);
        self.u8(0x0F);
        self.u8(0xB6);
        self.rm_mem(r, base, off);
    }
    fn movzx16(&mut self, r: u8, base: u8, off: i32) {
        self.rex(false, r, base);
        self.u8(0x0F);
        self.u8(0xB7);
        self.rm_mem(r, base, off);
    }
    fn movsx8(&mut self, r: u8, base: u8, off: i32) {
        self.rex(false, r, base);
        self.u8(0x0F);
        self.u8(0xBE);
        self.rm_mem(r, base, off);
    }
    fn movsx16(&mut self, r: u8, base: u8, off: i32) {
        self.rex(false, r, base);
        self.u8(0x0F);
        self.u8(0xBF);
        self.rm_mem(r, base, off);
    }
    fn movsxd(&mut self, r: u8, base: u8, off: i32) {
        self.rex(true, r, base);
        self.u8(0x63);
        self.rm_mem(r, base, off);
    }
    /// `mov [base+off], r8`。
    fn st8(&mut self, base: u8, off: i32, r: u8) {
        self.rex(false, r, base);
        self.u8(0x88);
        self.rm_mem(r, base, off);
    }
    /// `mov [base+off], r16`。
    fn st16(&mut self, base: u8, off: i32, r: u8) {
        self.u8(0x66);
        self.rex(false, r, base);
        self.u8(0x89);
        self.rm_mem(r, base, off);
    }
    /// `mov qword [base+off], imm32`（符号拡張される）。
    fn st_imm32(&mut self, base: u8, off: i32, v: i32) {
        self.rex(true, 0, base);
        self.u8(0xC7);
        self.rm_mem(0, base, off);
        self.i32(v);
    }
    /// `lea r64, [base+off]`。
    fn lea(&mut self, r: u8, base: u8, off: i32) {
        self.rex(true, r, base);
        self.u8(0x8D);
        self.rm_mem(r, base, off);
    }

    /// 幅 `w` の値を `[base+off]` から `r` へ読む（`signed` で符号拡張）。
    fn load(&mut self, r: u8, base: u8, off: i32, w: Wid, signed: bool) {
        match (w.bytes(), signed) {
            (1, true) => self.movsx8(r, base, off),
            (1, false) => self.movzx8(r, base, off),
            (2, true) => self.movsx16(r, base, off),
            (2, false) => self.movzx16(r, base, off),
            (4, true) => self.movsxd(r, base, off),
            (4, false) => self.mov_rm32(r, base, off),
            _ => self.mov_rm(r, base, off),
        }
    }
    /// `r` の値を幅 `w` で `[base+off]` へ書く。
    fn store(&mut self, base: u8, off: i32, r: u8, w: Wid) {
        match w.bytes() {
            1 => self.st8(base, off, r),
            2 => self.st16(base, off, r),
            4 => self.mov_mr32(base, off, r),
            _ => self.mov_mr(base, off, r),
        }
    }

    // ---- 演算・分岐 ----

    /// `add/sub/and/or/xor r64, [base+off]`。
    fn alu_rm(&mut self, opcode: u8, r: u8, base: u8, off: i32) {
        self.rex(true, r, base);
        self.u8(opcode);
        self.rm_mem(r, base, off);
    }
    /// `not r64`。
    fn not_r(&mut self, r: u8) {
        self.rex(true, 2, r);
        self.u8(0xF7);
        self.u8(0xC0 | 2 << 3 | (r & 7));
    }
    /// `cmp r64, imm32`。
    fn cmp_ri(&mut self, r: u8, v: i32) {
        self.rex(true, 7, r);
        self.u8(0x81);
        self.u8(0xC0 | 7 << 3 | (r & 7));
        self.i32(v);
    }
    /// `cmp byte [base+off], 0`。
    fn cmp8_m(&mut self, base: u8, off: i32) {
        self.u8(0x80);
        self.rm_mem(7, base, off);
        self.u8(0);
    }
    /// `cmp r64, r64`。
    fn cmp_rr(&mut self, a: u8, b: u8) {
        self.rex(true, b, a);
        self.u8(0x39);
        self.u8(0xC0 | (b & 7) << 3 | (a & 7));
    }
    /// `imul r64, [base+off]`。
    fn imul_rm(&mut self, r: u8, base: u8, off: i32) {
        self.rex(true, r, base);
        self.u8(0x0F);
        self.u8(0xAF);
        self.rm_mem(r, base, off);
    }
    /// `shl/shr/sar r64, cl`。`kind` は 4/5/7。
    fn shift_cl(&mut self, kind: u8, r: u8) {
        self.rex(true, kind, r);
        self.u8(0xD3);
        self.u8(0xC0 | (kind & 7) << 3 | (r & 7));
    }
    /// `sar r64, imm8`。
    fn sar_ri(&mut self, r: u8, v: u8) {
        self.rex(true, 7, r);
        self.u8(0xC1);
        self.u8(0xC0 | 7 << 3 | (r & 7));
        self.u8(v);
    }
    /// `setcc al`（`cc` は 0..=0xf）。
    fn setcc_al(&mut self, cc: u8) {
        self.u8(0x0F);
        self.u8(0x90 | cc);
        self.u8(0xC0);
    }
    /// `cmovcc r64, r64`。
    fn cmovcc(&mut self, cc: u8, d: u8, s: u8) {
        self.rex(true, d, s);
        self.u8(0x0F);
        self.u8(0x40 | cc);
        self.u8(0xC0 | (d & 7) << 3 | (s & 7));
    }
    /// `jcc rel32`（`cc` は 0..=0xf）。位置を返す。
    fn jcc(&mut self, cc: u8) -> usize {
        self.u8(0x0F);
        self.u8(0x80 | cc);
        let p = self.pos();
        self.i32(0);
        p
    }
    /// `jmp rel32`。位置を返す。
    fn jmp(&mut self) -> usize {
        self.u8(0xE9);
        let p = self.pos();
        self.i32(0);
        p
    }
    /// `call rax`。
    fn call_rax(&mut self) {
        self.u8(0xFF);
        self.u8(0xD0);
    }
    /// `test r64, r64`。
    fn test_rr(&mut self, a: u8, b: u8) {
        self.rex(true, b, a);
        self.u8(0x85);
        self.u8(0xC0 | (b & 7) << 3 | (a & 7));
    }
    /// `xor r64, r64`。
    fn xor_rr(&mut self, a: u8, b: u8) {
        self.rex(true, b, a);
        self.u8(0x31);
        self.u8(0xC0 | (b & 7) << 3 | (a & 7));
    }
    fn push(&mut self, r: u8) {
        if r >= 8 {
            self.u8(0x41);
        }
        self.u8(0x50 | (r & 7));
    }
    fn pop(&mut self, r: u8) {
        if r >= 8 {
            self.u8(0x41);
        }
        self.u8(0x58 | (r & 7));
    }
    fn ret(&mut self) {
        self.u8(0xC3);
    }

    // ---- 値スロット ----

    /// 値を `r` に読む（`W1`/`W8`..`W64`、0 拡張）。
    fn vload(&mut self, r: u8, id: Id, w: Wid) {
        self.load(r, RSP, slot(id), w, false);
    }
    /// 値を符号拡張して読む。
    fn vsload(&mut self, r: u8, id: Id, w: Wid) {
        self.load(r, RSP, slot(id), w, true);
    }
    /// `r` をスロットへ書く。
    fn vstore(&mut self, id: Id, r: u8, w: Wid) {
        self.store(RSP, slot(id), r, w);
    }
    /// `c` の値（バイト）を 0 と比べる。
    fn test_cond(&mut self, c: Id) {
        self.cmp8_m(RSP, slot(c));
    }
}

/// 値スロットの番地。
fn slot(id: Id) -> i32 {
    VALS + id as i32 * 16
}

/// `rt_call` の引数。
#[derive(Clone, Copy)]
enum Arg {
    /// 定数。
    Imm(u64),
    /// 値スロットの番地。
    Ptr(Id),
    /// 値スロットの `u64` の値。
    Val(Id),
    /// 値スロットの `u8` の値。
    Val8(Id),
    /// スクラッチ領域の番地。
    Scratch,
}

impl Gen<'_> {
    fn new(rec: &Recorded) -> Gen<'_> {
        let cache = pick_cache(&rec.ir);
        Gen {
            e: Em::new(),
            rec,
            cache,
            dirty: [false; 4],
            epi: Vec::new(),
            frame: 0,
        }
    }

    fn build(&mut self) -> Vec<u8> {
        let nvals = self.rec.ir.wids.len() as i32;
        // 呼び出し規約の整列（呼び出し時点で rsp ≡ 8 mod 16）に合わせる。
        self.frame = ((VALS + 16 * nvals + 15) & !15) + 8;
        // プロローグ。callee-saved を退避し ctx/state を rbx/rbp に。
        self.e.push(RBX);
        self.e.push(RBP);
        self.e.push(R12);
        self.e.push(R13);
        self.e.push(R14);
        self.e.push(R15);
        self.e.mov_rr(RBX, RDI);
        self.e.mov_rm(RBP, RBX, coff!(state));
        self.sub_rsp();
        // ctrl = fall
        self.e.mov_ri(RAX, self.rec.fall);
        self.e.mov_mr(RSP, 0, RAX);
        // キャッシュしたフィールドをレジスタへ読む。
        for ((off, w), r) in self.cache.clone() {
            self.e.load(r, RBP, off as i32, w, false);
        }
        let ops = self.rec.ir.ops.clone();
        self.gen_ops(&ops);
        // フォールスルー出口。pc = ctrl, next = ctrl, code = 0。
        self.e.mov_rm(RAX, RSP, 0);
        self.e.mov_mr(RBX, coff!(pc), RAX);
        self.e.mov_mr(RBX, coff!(next), RAX);
        self.e.mov_mr(RBX, coff!(code), RAX);
        // エピローグ。汚れた固定レジスタを状態へ戻す。
        let epi = self.e.pos();
        for p in core::mem::take(&mut self.epi) {
            self.e.patch_to(p, epi);
        }
        for (i, ((off, w), r)) in self.cache.clone().iter().enumerate() {
            if self.dirty[i] {
                self.e.store(RBP, *off as i32, *r, *w);
            }
        }
        self.add_rsp();
        self.e.pop(R15);
        self.e.pop(R14);
        self.e.pop(R13);
        self.e.pop(R12);
        self.e.pop(RBP);
        self.e.pop(RBX);
        self.e.ret();
        core::mem::take(&mut self.e.c)
    }

    fn sub_rsp(&mut self) {
        // sub rsp, imm32（81 /5）。
        self.e.rex(true, 5, RSP);
        self.e.u8(0x81);
        self.e.u8(0xC0 | 5 << 3 | RSP);
        self.e.i32(self.frame);
    }
    fn add_rsp(&mut self) {
        // add rsp, imm32（81 /0）。
        self.e.rex(true, 0, RSP);
        self.e.u8(0x81);
        self.e.u8(0xC0 | RSP);
        self.e.i32(self.frame);
    }

    /// `off` の `u64` を `[rbx+off]` へ書く。
    fn st_ctx_imm(&mut self, off: i32, v: u64) {
        if let Ok(v32) = i32::try_from(v as i64)
            && i64::from(v32) == v as i64
        {
            self.e.st_imm32(RBX, off, v32);
        } else {
            self.e.mov_ri(RAX, v);
            self.e.mov_mr(RBX, off, RAX);
        }
    }

    /// 例外出口のコード。`write_exc` と同じ内容を焼き込む。
    fn exit_stub(&mut self, e: polyisa_sem::GuestException, pc: u64, next: u64) {
        let kind = match e.kind {
            polyisa_sem::ExceptionKind::Undefined => 0,
            polyisa_sem::ExceptionKind::PageFault => 1,
            polyisa_sem::ExceptionKind::Align => 2,
            polyisa_sem::ExceptionKind::DivZero => 3,
            polyisa_sem::ExceptionKind::Fp => 4,
            polyisa_sem::ExceptionKind::Break => 5,
            polyisa_sem::ExceptionKind::Trap => 6,
        };
        self.st_ctx_imm(coff!(exc_kind), kind);
        self.st_ctx_imm(coff!(exc_code), e.code);
        let flags = u64::from(e.addr.is_some()) | (u64::from(e.in_delay_slot) << 1);
        self.st_ctx_imm(coff!(exc_flags), flags);
        self.st_ctx_imm(coff!(exc_addr), e.addr.unwrap_or(0));
        self.st_ctx_imm(coff!(pc), pc);
        self.st_ctx_imm(coff!(next), next);
        self.st_ctx_imm(coff!(code), 1);
        let p = self.e.jmp();
        self.epi.push(p);
    }

    /// 未実装出口。
    fn unimpl_stub(&mut self, pc: u64) {
        self.st_ctx_imm(coff!(pc), pc);
        self.st_ctx_imm(coff!(next), pc);
        self.st_ctx_imm(coff!(code), 2);
        let p = self.e.jmp();
        self.epi.push(p);
    }

    /// ヘルパー呼び出しの後のフォールト検査。`rax != 0` で例外出口へ。
    fn fault_check(&mut self, pc: u64, next: u64) {
        self.e.test_rr(RAX, RAX);
        let ok = self.e.jcc(0x4); // jz -> ok
        self.st_ctx_imm(coff!(pc), pc);
        self.st_ctx_imm(coff!(next), next);
        self.st_ctx_imm(coff!(code), 1);
        let p = self.e.jmp();
        self.epi.push(p);
        self.e.patch(ok);
    }

    /// 実行時関数を呼ぶ。`rdi` = ctx のあと `args` の順。
    fn rt_call(&mut self, f: *const (), args: &[Arg]) {
        const REGS: [u8; 5] = [RSI, RDX, RCX, R8, R9];
        self.e.mov_rr(RDI, RBX);
        for (i, a) in args.iter().enumerate() {
            match *a {
                Arg::Imm(v) => self.e.mov_ri(REGS[i], v),
                Arg::Ptr(id) => self.e.lea(REGS[i], RSP, slot(id)),
                Arg::Val(id) => self.e.mov_rm(REGS[i], RSP, slot(id)),
                Arg::Val8(id) => self.e.movzx8(REGS[i], RSP, slot(id)),
                Arg::Scratch => self.e.lea(REGS[i], RSP, SCRATCH),
            }
        }
        self.e.mov_ri(RAX, f as u64);
        self.e.call_rax();
    }

    /// `Set` の書き込み先。値は rax に用意済み。
    fn set_field(&mut self, off: u32, w: Wid) {
        match self.cache.iter().position(|(f, _)| *f == (off, w)) {
            Some(i) => {
                self.dirty[i] = true;
                let r = self.cache[i].1;
                self.e.mov_rr(r, RAX);
            }
            None => {
                self.e.store(RBP, off as i32, RAX, w);
            }
        }
    }

    /// `Get` の読み出し。結果は rax。
    fn get_field(&mut self, off: u32, w: Wid) {
        match self.cache.iter().find(|(f, _)| *f == (off, w)) {
            Some(&(_, r)) => {
                self.e.mov_rr(RAX, r);
            }
            None => {
                self.e.load(RAX, RBP, off as i32, w, false);
            }
        }
    }

    fn gen_ops(&mut self, ops: &[Inst]) {
        for i in ops {
            self.gen_inst(i);
        }
    }

    fn gen_inst(&mut self, i: &Inst) {
        match *i {
            Inst::Const { d, w, v } => {
                if w == Wid::W128 {
                    self.e.mov_ri(RAX, v as u64);
                    self.e.mov_mr(RSP, slot(d), RAX);
                    self.e.mov_ri(RAX, (v >> 64) as u64);
                    self.e.mov_mr(RSP, slot(d) + 8, RAX);
                } else {
                    let v = v & w.mask();
                    if let Ok(v32) = i32::try_from(v as i64)
                        && i64::from(v32) == v as i64
                    {
                        self.e.st_imm32(RSP, slot(d), v32);
                    } else {
                        self.e.mov_ri(RAX, v as u64);
                        self.e.mov_mr(RSP, slot(d), RAX);
                    }
                }
            }
            Inst::Get { d, off, w } => {
                if w == Wid::W128 {
                    // 128bit は 2 回に分けて動かす。
                    self.e.mov_rm(RAX, RBP, off as i32);
                    self.e.mov_mr(RSP, slot(d), RAX);
                    self.e.mov_rm(RAX, RBP, off as i32 + 8);
                    self.e.mov_mr(RSP, slot(d) + 8, RAX);
                } else {
                    self.get_field(off, w);
                    self.e.vstore(d, RAX, w);
                }
            }
            Inst::Set { off, w, v } => {
                if w == Wid::W128 {
                    self.e.mov_rm(RAX, RSP, slot(v));
                    self.e.mov_mr(RBP, off as i32, RAX);
                    self.e.mov_rm(RAX, RSP, slot(v) + 8);
                    self.e.mov_mr(RBP, off as i32 + 8, RAX);
                } else {
                    self.e.vload(RAX, v, w);
                    self.set_field(off, w);
                }
            }
            Inst::GetIx {
                d,
                base,
                stride,
                ix,
                w,
            } => {
                self.rt_call(
                    rt::rt_get_ix as *const (),
                    &[
                        Arg::Imm(u64::from(base)),
                        Arg::Imm(u64::from(stride)),
                        Arg::Val(ix),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Ptr(d),
                    ],
                );
            }
            Inst::SetIx {
                base,
                stride,
                ix,
                v,
                w,
            } => {
                self.rt_call(
                    rt::rt_set_ix as *const (),
                    &[
                        Arg::Imm(u64::from(base)),
                        Arg::Imm(u64::from(stride)),
                        Arg::Val(ix),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Ptr(v),
                    ],
                );
            }
            Inst::Un { d, op, a, w } => {
                if op == UnOp::Not && w != Wid::W128 {
                    self.e.vload(RAX, a, w);
                    self.e.not_r(RAX);
                    self.e.vstore(d, RAX, w);
                } else {
                    self.rt_call(
                        rt::rt_una as *const (),
                        &[
                            Arg::Imm(rt::un_code(op)),
                            Arg::Imm(u64::from(w.bits())),
                            Arg::Ptr(a),
                            Arg::Ptr(d),
                        ],
                    );
                }
            }
            Inst::Bin { d, op, a, b, w } => self.gen_bin(d, op, a, b, w),
            Inst::Tri { d, a, b, c, w, .. } => {
                self.rt_call(
                    rt::rt_tri as *const (),
                    &[
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Ptr(a),
                        Arg::Ptr(b),
                        Arg::Ptr(c),
                        Arg::Ptr(d),
                    ],
                );
            }
            Inst::Adc {
                d,
                dc,
                dv,
                a,
                b,
                c,
                w,
            } => {
                self.rt_call(
                    rt::rt_adc as *const (),
                    &[
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Ptr(a),
                        Arg::Ptr(b),
                        Arg::Val8(c),
                        Arg::Scratch,
                    ],
                );
                self.e.mov_rm(RAX, RSP, SCRATCH);
                self.e.vstore(d, RAX, w);
                self.e.mov_rm(RAX, RSP, SCRATCH + 16);
                self.e.vstore(dc, RAX, Wid::W1);
                self.e.mov_rm(RAX, RSP, SCRATCH + 32);
                self.e.vstore(dv, RAX, Wid::W1);
            }
            Inst::Cmp { d, op, a, b, w } => {
                if w == Wid::W128 {
                    self.rt_call(
                        rt::rt_cmp as *const (),
                        &[
                            Arg::Imm(rt::cmp_code(op)),
                            Arg::Imm(u64::from(w.bits())),
                            Arg::Ptr(a),
                            Arg::Ptr(b),
                        ],
                    );
                    self.e.vstore(d, RAX, Wid::W1);
                } else {
                    let signed = matches!(op, Cmp::LtS | Cmp::GtS | Cmp::LeS | Cmp::GeS);
                    if signed {
                        self.e.vsload(RAX, a, w);
                        self.e.vsload(RCX, b, w);
                    } else {
                        self.e.vload(RAX, a, w);
                        self.e.vload(RCX, b, w);
                    }
                    self.e.cmp_rr(RAX, RCX);
                    let cc = match op {
                        Cmp::Eq => 0x4,
                        Cmp::Ne => 0x5,
                        Cmp::LtU => 0x2,
                        Cmp::LtS => 0xC,
                        Cmp::GtU => 0x7,
                        Cmp::GtS => 0xF,
                        Cmp::LeU => 0x6,
                        Cmp::LeS => 0xE,
                        Cmp::GeU => 0x3,
                        Cmp::GeS => 0xD,
                    };
                    self.e.setcc_al(cc);
                    self.e.st8(RSP, slot(d), RAX);
                }
            }
            Inst::FpCmp { d, op, a, b, w } => {
                self.rt_call(
                    rt::rt_fcmp as *const (),
                    &[
                        Arg::Imm(rt::fcmp_code(op)),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Ptr(a),
                        Arg::Ptr(b),
                    ],
                );
                self.e.vstore(d, RAX, Wid::W1);
            }
            Inst::Sel { d, c, t, f, w } => {
                if w == Wid::W128 {
                    self.e.mov_rm(RAX, RSP, slot(f));
                    self.e.mov_rm(RCX, RSP, slot(t));
                    self.e.test_cond(c);
                    self.e.cmovcc(0x5, RAX, RCX);
                    self.e.mov_mr(RSP, slot(d), RAX);
                    self.e.mov_rm(RAX, RSP, slot(f) + 8);
                    self.e.mov_rm(RCX, RSP, slot(t) + 8);
                    self.e.test_cond(c);
                    self.e.cmovcc(0x5, RAX, RCX);
                    self.e.mov_mr(RSP, slot(d) + 8, RAX);
                } else {
                    self.e.vload(RAX, f, w);
                    self.e.vload(RCX, t, w);
                    self.e.test_cond(c);
                    self.e.cmovcc(0x5, RAX, RCX);
                    self.e.vstore(d, RAX, w);
                }
            }
            Inst::Ext { d, op, a, from, to } => {
                if to == Wid::W128 {
                    let of =
                        rt::ext_code(op) | u64::from(from.bits()) << 8 | u64::from(to.bits()) << 16;
                    self.rt_call(
                        rt::rt_ext as *const (),
                        &[Arg::Imm(of), Arg::Ptr(a), Arg::Ptr(d)],
                    );
                } else {
                    match op {
                        // 0 拡張は from 幅で読めば上位は 0。
                        Ext::Zext => self.e.vload(RAX, a, from),
                        Ext::Sext => self.e.vsload(RAX, a, from),
                        Ext::Trunc => self.e.vload(RAX, a, to),
                    }
                    self.e.vstore(d, RAX, to);
                }
            }
            Inst::Cvt {
                d,
                op,
                a,
                from,
                to,
                rm,
            } => {
                let of = rt::cvt_code(op)
                    | u64::from(from.bits()) << 8
                    | u64::from(to.bits()) << 16
                    | u64::from(rm) << 24;
                self.rt_call(
                    rt::rt_cvt as *const (),
                    &[Arg::Imm(of), Arg::Ptr(a), Arg::Ptr(d)],
                );
            }
            Inst::Load {
                d,
                addr,
                w,
                acc,
                pc,
                next,
            } => {
                self.rt_call(
                    rt::rt_load as *const (),
                    &[
                        Arg::Val(addr),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Imm(rt::pack_access(acc)),
                        Arg::Ptr(d),
                    ],
                );
                self.fault_check(pc, next);
            }
            Inst::Store {
                addr,
                v,
                w,
                acc,
                pc,
                next,
            } => {
                self.rt_call(
                    rt::rt_store as *const (),
                    &[
                        Arg::Val(addr),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Imm(rt::pack_access(acc)),
                        Arg::Ptr(v),
                    ],
                );
                self.fault_check(pc, next);
            }
            Inst::Probe {
                addr,
                len,
                acc,
                pc,
                next,
            } => {
                self.rt_call(
                    rt::rt_probe as *const (),
                    &[
                        Arg::Val(addr),
                        Arg::Imm(u64::from(len)),
                        Arg::Imm(rt::pack_access(acc)),
                    ],
                );
                self.fault_check(pc, next);
            }
            Inst::Cmpx {
                d,
                addr,
                old,
                new,
                w,
                acc,
                pc,
                next,
            } => {
                // io = {old, new, out} をスクラッチに組む。
                self.e.mov_rm(RAX, RSP, slot(old));
                self.e.mov_mr(RSP, SCRATCH, RAX);
                self.e.mov_rm(RAX, RSP, slot(old) + 8);
                self.e.mov_mr(RSP, SCRATCH + 8, RAX);
                self.e.mov_rm(RAX, RSP, slot(new));
                self.e.mov_mr(RSP, SCRATCH + 16, RAX);
                self.e.mov_rm(RAX, RSP, slot(new) + 8);
                self.e.mov_mr(RSP, SCRATCH + 24, RAX);
                self.rt_call(
                    rt::rt_cmpx as *const (),
                    &[
                        Arg::Val(addr),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Imm(rt::pack_access(acc)),
                        Arg::Scratch,
                    ],
                );
                self.fault_check(pc, next);
                self.e.mov_rm(RAX, RSP, SCRATCH + 32);
                self.e.mov_mr(RSP, slot(d), RAX);
                self.e.mov_rm(RAX, RSP, SCRATCH + 40);
                self.e.mov_mr(RSP, slot(d) + 8, RAX);
            }
            Inst::LdRes {
                d,
                addr,
                w,
                acc,
                pc,
                next,
            } => {
                self.rt_call(
                    rt::rt_ldres as *const (),
                    &[
                        Arg::Val(addr),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Imm(rt::pack_access(acc)),
                        Arg::Ptr(d),
                    ],
                );
                self.fault_check(pc, next);
            }
            Inst::StCond {
                d,
                addr,
                v,
                w,
                acc,
                pc,
                next,
            } => {
                self.rt_call(
                    rt::rt_stcond as *const (),
                    &[
                        Arg::Val(addr),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Imm(rt::pack_access(acc)),
                        Arg::Ptr(v),
                        Arg::Scratch,
                    ],
                );
                self.fault_check(pc, next);
                self.e.mov_rm(RAX, RSP, SCRATCH);
                self.e.st8(RSP, slot(d), RAX);
            }
            Inst::If { c, ref t, ref f } => {
                self.e.test_cond(c);
                let els = self.e.jcc(0x4); // jz -> else
                self.gen_ops(t);
                let end = self.e.jmp();
                self.e.patch(els);
                self.gen_ops(f);
                self.e.patch(end);
            }
            Inst::Jump { v } => {
                self.e.mov_rm(RAX, RSP, slot(v));
                self.e.mov_mr(RSP, 0, RAX);
            }
            Inst::Branch { c, target } => {
                self.e.test_cond(c);
                let skip = self.e.jcc(0x4);
                self.e.mov_ri(RAX, target);
                self.e.mov_mr(RSP, 0, RAX);
                self.e.patch(skip);
            }
            Inst::Exit { e, pc, next } => self.exit_stub(e, pc, next),
            Inst::Unimpl { pc } => self.unimpl_stub(pc),
            Inst::Hint { .. } => {}
        }
    }

    /// `Bin` のコード生成。
    fn gen_bin(&mut self, d: Id, op: BinOp, a: Id, b: Id, w: Wid) {
        match op {
            BinOp::Add | BinOp::Sub | BinOp::And | BinOp::Or | BinOp::Xor if w != Wid::W128 => {
                self.e.vload(RAX, a, w);
                let opcode = match op {
                    BinOp::Add => 0x03,
                    BinOp::Sub => 0x2B,
                    BinOp::And => 0x23,
                    BinOp::Or => 0x0B,
                    _ => 0x33,
                };
                self.e.alu_rm(opcode, RAX, RSP, slot(b));
                self.e.vstore(d, RAX, w);
            }
            BinOp::Mul if w != Wid::W128 => {
                self.e.vload(RAX, a, w);
                self.e.imul_rm(RAX, RSP, slot(b));
                self.e.vstore(d, RAX, w);
            }
            BinOp::Shl | BinOp::ShrL | BinOp::ShrA if w != Wid::W128 => {
                match op {
                    BinOp::ShrA => self.e.vsload(RAX, a, w),
                    _ => self.e.vload(RAX, a, w),
                }
                self.e.vload(RCX, b, w);
                self.e.cmp_ri(RCX, w.bits() as i32);
                // n >= w は別扱い。
                let big = self.e.jcc(0x3); // jae
                match op {
                    BinOp::Shl => self.e.shift_cl(4, RAX),
                    BinOp::ShrL => self.e.shift_cl(5, RAX),
                    _ => self.e.shift_cl(7, RAX),
                }
                let done = self.e.jmp();
                self.e.patch(big);
                match op {
                    // 符号埋め。
                    BinOp::ShrA => self.e.sar_ri(RAX, 63),
                    _ => self.e.xor_rr(RAX, RAX),
                }
                self.e.patch(done);
                self.e.vstore(d, RAX, w);
            }
            _ => {
                // 幅 128・除算・mulh・浮動小数点はヘルパーへ。
                self.rt_call(
                    rt::rt_alu as *const (),
                    &[
                        Arg::Imm(rt::bin_code(op)),
                        Arg::Imm(u64::from(w.bits())),
                        Arg::Ptr(a),
                        Arg::Ptr(b),
                        Arg::Ptr(d),
                    ],
                );
            }
        }
    }
}

/// 固定レジスタに載せるフィールドを選ぶ。条件：
/// - 幅が 64 ビット以下
/// - 同じ範囲を別の幅で読み書きしない（重複を避ける）
/// - 動的添字アクセスがブロックにない（何にでも当たり得るため）
/// - アクセス数の多い順に 4 つまで
fn pick_cache(ir: &polyisa_ir::Ir) -> Vec<((u32, Wid), u8)> {
    use std::collections::{HashMap, HashSet};
    let mut count: HashMap<(u32, Wid), u32> = HashMap::new();
    let mut has_ix = false;
    fn walk(ops: &[Inst], count: &mut HashMap<(u32, Wid), u32>, has_ix: &mut bool) {
        for i in ops {
            match *i {
                Inst::Get { off, w, .. } | Inst::Set { off, w, .. } => {
                    *count.entry((off, w)).or_insert(0) += 1;
                }
                Inst::GetIx { .. } | Inst::SetIx { .. } => *has_ix = true,
                Inst::If { ref t, ref f, .. } => {
                    walk(t, count, has_ix);
                    walk(f, count, has_ix);
                }
                _ => {}
            }
        }
    }
    walk(&ir.ops, &mut count, &mut has_ix);
    if has_ix {
        return Vec::new();
    }
    // 重なり合う範囲の読み書きが別幅であるフィールドは外す。
    let fields: Vec<(u32, Wid)> = count.keys().copied().collect();
    let mut bad = HashSet::new();
    for &(a, wa) in &fields {
        for &(b, wb) in &fields {
            if (a, wa) == (b, wb) {
                continue;
            }
            let (a0, a1) = (a as u64, a as u64 + u64::from(wa.bytes()));
            let (b0, b1) = (b as u64, b as u64 + u64::from(wb.bytes()));
            if a0 < b1 && b0 < a1 {
                bad.insert((a, wa));
            }
        }
    }
    const REGS: [u8; 4] = [R12, R13, R14, R15];
    let mut cand: Vec<((u32, Wid), u32)> = count
        .into_iter()
        .filter(|(f, _)| f.1 != Wid::W128 && !bad.contains(f))
        .collect();
    cand.sort_by_key(|(_, n)| core::cmp::Reverse(*n));
    cand.into_iter()
        .take(4)
        .zip(REGS)
        .map(|((f, _), r)| (f, r))
        .collect()
}
