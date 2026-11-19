// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SPARC の命令意味論。バックエンドに対して総称的に書く。
//!
//! 分岐は即時に飛ばず npc だけを書き換え、遅延スロットの1命令を
//! 実行してから `commit` で pc を npc に進める。遅延スロットの命令は
//! 分岐命令の pc + 4 からフェッチする（npc からではない）。分岐の
//! annul が立っているときは、`delay_slot` が遅延スロットの命令を
//! 実行しない。遅延スロット内の例外の `in_delay_slot` 修正は
//! 実行ループ側の責務で、ここでは `false` を置くだけである。
//! 見える out/local/in は CWP と `nwindows` パラメータで
//! レジスタファイル上の位置が変わる。SAVE は CWP を 1 減らし、
//! RESTORE は 1 増やす。ウィンドウのあふれと不足は OS パーソナリティ
//! が再現する（段階 15 の SP12）。
//! V7/V8 は整数レジスタの演算を 32 ビットで、V9 は 64 ビットで行う
//! （`word64` パラメータ）。
//!
//! 出典は SPEC-SPARC-V7 (Solbourne 101482-00)、SPEC-SPARC-V8
//! (Version 8)、SPEC-SPARC-V9 (SAV09R1459912) である。
//! Ref: SPEC-SPARC-V7.
//! Ref: SPEC-SPARC-V8 (Version 8).
//! Ref: SPEC-SPARC-V9.

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, Flow, StateArray, StateRef, W32, W64};

use super::{CpuState, Insn};

/// 整数レジスタ番号。`g0`（番号 0）は読むと 0、書き込みは捨てる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。ウィンドウ内のレジスタは
    /// `phys_index` で物理番号を求めてから使う。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, g) + (self.0 as usize) * 8)
    }

    /// `g0` かどうか。
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// 浮動小数点レジスタ番号。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpr(pub u8);

impl Fpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + (self.0 as usize) * 8)
    }
}

/// pc を指す。
pub fn pc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, pc))
}

/// npc を指す。
pub fn npc_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, npc))
}

/// cwp を指す。
pub fn cwp_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, cwp))
}

/// annul ビットを指す。1 のとき、次の遅延スロットは実行しない。
pub fn annul_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, annul))
}

/// V7/V8 の PSR を指す。
pub fn psr_ref() -> StateRef<W32> {
    StateRef::<W32>::from_offset(core::mem::offset_of!(CpuState, psr))
}

/// V9 の TSTATE を指す。
pub fn tstate_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, tstate))
}

/// V7/V8 の Y レジスタを指す。
pub fn y_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, y))
}

/// FSR を指す。
pub fn fsr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, fsr))
}

/// V9 の GSR を指す。
pub fn gsr_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, gsr))
}

/// V9 の %tick 基準を指す。
pub fn tick_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, tick))
}

fn reg_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, g), 8)
}

/// `nwindows` パラメータの値。`Backend::param` が流し込まれていなければ
/// 宣言の既定値（8）になる。仕様上の範囲は 2 から 32 で、ここでは
/// ファイルが巡回する前提なので下限を確かめる。
/// Ref: SPEC-SPARC-V8 (Version 8) §The Windowed Integer Registers.
fn nwindows<B: Backend>(b: &mut B) -> u64 {
    let nw = u64::from(b.param::<super::NwindowsParam>());
    assert!(nw >= 2, "nwindows must be at least 2, got {nw}");
    nw
}

/// 見えるレジスタ番号を、CWP でずらした物理番号にする。0〜7 は
/// グローバル。in は次のウィンドウの out への別名なので、物理位置は
/// `cwp*16 + (reg-8)` を `nwindows*16` で折り返した場所にある。
/// Ref: SPEC-SPARC-V8 (Version 8) §The Windowed Integer Registers.
fn phys_index<B: Backend>(b: &mut B, reg: u8) -> B::V<W32> {
    if reg < 8 {
        return b.konst::<W32>(u32::from(reg));
    }
    let nw = nwindows(b);
    let cwp: B::V<W64> = b.get(cwp_ref());
    let off = b.konst::<W64>(u64::from(reg) - 8);
    let sixteen = b.konst::<W64>(16);
    let base = b.mul::<W64>(cwp, sixteen);
    let sum = b.add::<W64>(base, off);
    let span = b.konst::<W64>(nw * 16);
    let wrapped = b.urem::<W64>(sum, span);
    let eight = b.konst::<W64>(8);
    let phys = b.add::<W64>(eight, wrapped);
    b.trunc::<W64, W32>(phys)
}

/// 整数レジスタの読み出し。
fn read<B: Backend>(b: &mut B, r: Gpr) -> B::V<W64> {
    if r.is_zero() {
        b.konst::<W64>(0)
    } else {
        let idx = phys_index(b, r.0);
        b.get_indexed(reg_array(), idx)
    }
}

/// 整数レジスタの書き込み。`g0` への書き込みは捨てる。
fn write<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W64>) {
    if !rd.is_zero() {
        let idx = phys_index(b, rd.0);
        b.set_indexed(reg_array(), idx, v);
    }
}

/// 演算結果をモデルの語幅に包む。V7/V8 は 32 ビット、V9 は 64 ビット。
/// Ref: SPEC-SPARC-V9 §Integer Register Usage.
fn wmask<B: Backend>(b: &mut B, v: B::V<W64>) -> B::V<W64> {
    if b.param::<super::Word64Param>() {
        v
    } else {
        let lo = b.konst::<W64>(0xffff_ffff);
        b.and::<W64>(v, lo)
    }
}

/// CWP を `delta` 進め、ウィンドウ枚数で折り返す。
fn step_cwp<B: Backend>(b: &mut B, delta: u64) {
    let nw = nwindows(b);
    let cwp = b.get(cwp_ref());
    let d = b.konst::<W64>(delta);
    let sum = b.add::<W64>(cwp, d);
    let span = b.konst::<W64>(nw);
    let next = b.urem::<W64>(sum, span);
    b.set(cwp_ref(), next);
}

fn const_w64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

/// simm13 の符号拡張。
fn sext13(v: u64) -> i64 {
    ((v as i64) << 51) >> 51
}

const DATA_READ: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

const DATA_WRITE: Access = Access {
    endian: Endian::Be,
    align: Align::Natural,
    kind: AccessKind::DataWrite,
};

/// 3 オペランド形の第 2 ソース。レジスタ（i=0）か即値（i=1）。
pub enum Src2 {
    /// `rs2` レジスタを読む。
    Reg(Gpr),
    /// 符号拡張済みの即値。
    Imm(i64),
}

fn src2<B: Backend>(b: &mut B, s: Src2) -> B::V<W64> {
    match s {
        Src2::Reg(r) => read(b, r),
        Src2::Imm(v) => const_w64(b, v as u64),
    }
}

/// ADD。
pub fn add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    write(b, rd, v);
    Ok(())
}

/// SUB。
pub fn sub<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let d = b.sub::<W64>(x, y);
    let v = wmask(b, d);
    write(b, rd, v);
    Ok(())
}

/// AND。
pub fn and<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let t = b.and::<W64>(x, y);
    let v = wmask(b, t);
    write(b, rd, v);
    Ok(())
}

/// OR。
pub fn or<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let t = b.or::<W64>(x, y);
    let v = wmask(b, t);
    write(b, rd, v);
    Ok(())
}

/// SLL。V7/V8 は下位 5 ビット、V9 は 6 ビットのシフト量。
/// Ref: SPEC-SPARC-V9 §Shift Instructions.
pub fn sll<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let bits = if b.param::<super::Word64Param>() {
        63
    } else {
        31
    };
    let m = b.konst::<W64>(bits);
    let n = b.and::<W64>(y, m);
    let t = b.shl::<W64>(x, n);
    let v = wmask(b, t);
    write(b, rd, v);
    Ok(())
}

/// SETHI。imm22 を上位に置く（rd = imm22 << 10）。V9 は 32 ビット目の
/// 符号を上位 32 ビットへ拡張する。V7/V8 は `wmask` で上位を捨てる。
/// Ref: SPEC-SPARC-V8 (Version 8) §SETHI.
/// Ref: SPEC-SPARC-V9 §SETHI.
pub fn sethi<B: Backend>(b: &mut B, rd: Gpr, imm22: u64) -> Flow<B> {
    let v32 = b.konst::<W32>((imm22 << 10) as u32);
    let s = b.sext::<W32, W64>(v32);
    let v = wmask(b, s);
    write(b, rd, v);
    Ok(())
}

/// LD（word。BE・自然整列）。
pub fn ld<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let base = read(b, rs1);
    let off = src2(b, s);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W32> = b.load::<W32>(addr, DATA_READ)?;
    let w = b.zext::<W32, W64>(v);
    write(b, rd, w);
    Ok(())
}

/// ST（word。BE・自然整列）。
pub fn st<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let base = read(b, rs1);
    let off = src2(b, s);
    let addr = b.add::<W64>(base, off);
    let v: B::V<W64> = read(b, rd);
    let lo: B::V<W32> = b.trunc::<W64, W32>(v);
    b.store::<W32>(addr, lo, DATA_WRITE)?;
    Ok(())
}

/// JMPL。遅延スロット付きの間接分岐。戻り（pc）を `rd` に書き、
/// npc だけを書き換える。飛び先が 4 の倍数でないときの
/// mem_address_not_aligned トラップは後続ステップで検出する。
/// Ref: SPEC-SPARC-V8 (Version 8) §JMPL.
pub fn jmpl<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2, pc: u64) -> Flow<B> {
    let base = read(b, rs1);
    let off = src2(b, s);
    let sum = b.add::<W64>(base, off);
    let target = wmask(b, sum);
    let ret = const_w64(b, pc);
    write(b, rd, ret);
    b.set(npc_ref(), target);
    Ok(())
}

/// CALL。遅延スロット付きの直接呼び出し。戻り（pc）を %o7 に書く。
/// `target` は pc + sign_extend(disp30 << 2)。
/// Ref: SPEC-SPARC-V8 (Version 8) §CALL.
pub fn call<B: Backend>(b: &mut B, pc: u64, target: u64) -> Flow<B> {
    let ret = const_w64(b, pc);
    write(b, Gpr(15), ret);
    let k = const_w64(b, target);
    let t = wmask(b, k);
    b.set(npc_ref(), t);
    Ok(())
}

/// Bicc。ICC を評価して npc を書き換える。成立すれば npc は
/// `target`（pc + sign_extend(disp22 << 2)）、不成立なら pc + 8。
/// 不成立でも npc を進めるのは、遅延スロットが pc + 4 にあって
/// commit が pc を npc に写すためで、書き換えないと遅延スロットの
/// 命令を二度実行することになる。
/// `a` が立っていて条件が成立したときは、遅延スロットを取り消す
/// （annul）。
/// Ref: SPEC-SPARC-V8 (Version 8) §Bicc.
pub fn bicc<B: Backend>(b: &mut B, a: u8, cond: u8, pc: u64, target: u64) -> Flow<B> {
    let taken = cond_holds(b, cond);
    let t = const_w64(b, target);
    let fall = const_w64(b, pc.wrapping_add(8));
    let s = b.select::<W64>(taken, t, fall);
    let npc = wmask(b, s);
    b.set(npc_ref(), npc);
    if a != 0 {
        // 成立して分岐したときだけ、遅延スロットを取り消す。
        b.if_then(taken, |bb| {
            let one = bb.konst::<W64>(1);
            bb.set(annul_ref(), one);
            Ok(())
        })?;
    }
    Ok(())
}

/// 条件の評価。ICC は PSR の N(23) Z(22) V(21) C(20)。
/// 返り値は `taken` の判定値。各条件は値演算で 0/1 を組み立てて
/// 0 でないかを比較する。
/// V9 の条件コード（%ccr）は TSTATE 側にあり、ここでは V7/V8 の
/// ICC だけを読む。V9 の Bicc/FBfcc 差分は後続ステップで扱う。
/// Ref: SPEC-SPARC-V8 (Version 8) §Instruction Descriptions (Bicc).
fn cond_holds<B: Backend>(b: &mut B, cond: u8) -> B::B {
    let psr = b.get(psr_ref());
    let p64 = b.zext::<W32, W64>(psr);
    let bit = |bb: &mut B, n: u64| -> B::V<W64> {
        let sh = bb.konst::<W64>(n);
        let one = bb.konst::<W64>(1);
        let s = bb.shr_l::<W64>(p64, sh);
        bb.and::<W64>(s, one)
    };
    let n = bit(b, 23);
    let z = bit(b, 22);
    let v = bit(b, 21);
    let c = bit(b, 20);
    let one = b.konst::<W64>(1);
    let inv = |x: B::V<W64>, bb: &mut B| -> B::V<W64> {
        let o = bb.konst::<W64>(1);
        bb.xor::<W64>(x, o)
    };
    let zero = b.konst::<W64>(0);
    let nxv = b.xor::<W64>(n, v);
    let nz = b.not::<W64>(z); // 下位ビット以外も立つので and で 1 に留める
    let not_z = b.and::<W64>(nz, one);
    let nc = b.not::<W64>(c);
    let not_c = b.and::<W64>(nc, one);
    let not_nxv = inv(nxv, b);
    let not_n = inv(n, b);
    let not_v = inv(v, b);
    let le = b.or::<W64>(nxv, z);
    let bleu = b.or::<W64>(z, c);
    let g = b.and::<W64>(not_nxv, not_z);
    let gu = b.and::<W64>(not_c, not_z);
    let val = match cond {
        0b0000 => zero,    // bn
        0b0001 => z,       // be
        0b0010 => le,      // ble
        0b0011 => nxv,     // bl
        0b0100 => bleu,    // bleu
        0b0101 => c,       // bcs
        0b0110 => n,       // bneg
        0b0111 => v,       // bvs
        0b1000 => one,     // ba
        0b1001 => not_z,   // bne
        0b1010 => g,       // bg
        0b1011 => not_nxv, // bge
        0b1100 => gu,      // bgu
        0b1101 => not_c,   // bcc
        0b1110 => not_n,   // bpos
        _ => not_v,        // bvc
    };
    b.cmp::<W64>(Cmp::Ne, val, zero)
}

/// SAVE。旧ウィンドウで加算し、CWP を 1 減らしてから新ウィンドウへ書く。
/// ウィンドウあふれの検出は OS パーソナリティが再現するため、
/// ここではファイル内を巡回するだけである。
/// Ref: SPEC-SPARC-V8 (Version 8) §SAVE.
pub fn save<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    let nw = nwindows(b);
    step_cwp(b, nw - 1);
    write(b, rd, v);
    Ok(())
}

/// RESTORE。現ウィンドウで加算し、CWP を 1 増やしてから戻った
/// ウィンドウへ書く。
/// Ref: SPEC-SPARC-V8 (Version 8) §RESTORE.
pub fn restore<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, s: Src2) -> Flow<B> {
    let x = read(b, rs1);
    let y = src2(b, s);
    let sum = b.add::<W64>(x, y);
    let v = wmask(b, sum);
    step_cwp(b, 1);
    write(b, rd, v);
    Ok(())
}

/// UNIMP。illegal instruction トラップとして表す。
// Ref: SPEC-SPARC-V8 (Version 8) §UNIMP.
pub fn unimp<B: Backend>(b: &mut B, imm22: u64) -> B::Exit {
    b.raise(polyisa_sem::GuestException {
        kind: polyisa_sem::ExceptionKind::Trap,
        code: u64::from(imm22 as u32),
        addr: None,
        in_delay_slot: false,
    })
}

/// 遅延スロットのステップ。annul が 0 のときだけ `slot` を実行し、
/// ビットを消してから commit する。
pub fn delay_slot<B: Backend>(b: &mut B, slot: impl FnOnce(&mut B) -> Flow<B>) -> Flow<B> {
    let annul = b.get(annul_ref());
    let zero = b.konst::<W64>(0);
    let run = b.cmp::<W64>(Cmp::Eq, annul, zero);
    b.if_then(run, slot)?;
    b.set(annul_ref(), zero);
    commit(b)
}

/// 遅延スロットの実行後に pc を npc に進め、npc を +4 する。
pub fn commit<B: Backend>(b: &mut B) -> Flow<B> {
    let npc: B::V<W64> = b.get(npc_ref());
    b.set(pc_ref(), npc);
    let four = b.konst::<W64>(4);
    let sum = b.add::<W64>(npc, four);
    let next = wmask(b, sum);
    b.set(npc_ref(), next);
    Ok(())
}

/// デコードした命令の意味論。実行ループは `extract_ops` で得た
/// オペランド値を `exec` が語から取り出し、個別の意味論に振る。
/// `pc` は命令自身の pc（JMPL の戻りと分岐の基準）。
/// Ref: SPEC-SPARC-V8 (Version 8) §Instruction Descriptions.
pub fn exec<B: Backend>(b: &mut B, insn: Insn, word: u32, pc: u64) -> Flow<B> {
    let o = super::extract_ops(insn, u128::from(word));
    match insn {
        Insn::Add
        | Insn::Sub
        | Insn::And
        | Insn::Or
        | Insn::Sll
        | Insn::Jmpl
        | Insn::Save
        | Insn::Restore
        | Insn::Ld => dispatch3(
            b,
            insn,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Src2::Reg(Gpr(o[2] as u8)),
            pc,
        ),
        Insn::AddI
        | Insn::SubI
        | Insn::AndI
        | Insn::OrI
        | Insn::JmplI
        | Insn::SaveI
        | Insn::RestoreI
        | Insn::LdI => dispatch3(
            b,
            insn,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Src2::Imm(sext13(o[2])),
            pc,
        ),
        Insn::St => st(
            b,
            Gpr(o[0] as u8),
            Gpr(o[1] as u8),
            Src2::Reg(Gpr(o[2] as u8)),
        ),
        Insn::StI => st(b, Gpr(o[0] as u8), Gpr(o[1] as u8), Src2::Imm(sext13(o[2]))),
        Insn::Sethi => sethi(b, Gpr(o[0] as u8), o[1]),
        Insn::Call => {
            // disp30 は符号拡張して <<2 の PC 相対。
            let disp = ((o[0] as i64) << 34) >> 34;
            let target = pc.wrapping_add((disp << 2) as u64);
            call(b, pc, target)
        }
        Insn::Bicc => {
            let a = o[0] as u8;
            let cond = o[1] as u8;
            let disp22 = ((o[2] as i64) << 42) >> 42;
            let target = pc.wrapping_add((disp22 << 2) as u64);
            bicc(b, a, cond, pc, target)
        }
        Insn::Unimp => Err(unimp(b, o[0])),
    }
}

fn dispatch3<B: Backend>(b: &mut B, insn: Insn, rd: Gpr, rs1: Gpr, s: Src2, pc: u64) -> Flow<B> {
    match insn {
        Insn::Add | Insn::AddI => add(b, rd, rs1, s),
        Insn::Sub | Insn::SubI => sub(b, rd, rs1, s),
        Insn::And | Insn::AndI => and(b, rd, rs1, s),
        Insn::Or | Insn::OrI => or(b, rd, rs1, s),
        Insn::Sll => sll(b, rd, rs1, s),
        Insn::Jmpl | Insn::JmplI => jmpl(b, rd, rs1, s, pc),
        Insn::Save | Insn::SaveI => save(b, rd, rs1, s),
        Insn::Restore | Insn::RestoreI => restore(b, rd, rs1, s),
        Insn::Ld | Insn::LdI => ld(b, rd, rs1, s),
        _ => unreachable!(),
    }
}
