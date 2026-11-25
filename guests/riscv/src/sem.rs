// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! RV64I の命令意味論。バックエンドに対して総称的に書く.
//!
//! デコード済みのオペランドは Rust の値で受け、実行時の値は `B::V` で扱う。
//! 出典の版は SPEC-RISCV-UNPRIV (20250508) である（`// Ref:` は `build.rs` に集約）。
//!
//! - 即値は組み立て済みの値を `i64` で受ける。切り出しと符号拡張はデコーダの仕事であり、後の段階で生成する。
//! - シフト量は ISA の規則どおりに下位ビットだけ使う（RV64 で 6 ビット、W 接尾辞で 5 ビット）。
//! - バックエンドの呼び出しは必ず文で分け、引数の中で借用を重ねない。

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{
    Backend, Cmp, F16, F32, F64, Flow, GuestException, StateArray, StateRef, W8, W16, W32, W64,
};

use super::CpuState;

/// 整数レジスタ番号。`x0` は読むと 0、書き込みは捨てる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gpr(pub u8);

impl Gpr {
    /// CPU 状態の対応する要素を指す。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, x) + (self.0 as usize) * 8)
    }

    /// `x0` かどうか。
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

const DATA_READ: Access = Access {
    endian: Endian::Le,
    // 非整列を許す実装を選ぶ。RISC-V は非整列の扱いを実装に委ねており、
    // ユーザーモードの実行器はバイト単位で正値を返す（`ma_data` が通る）。
    // 不可分操作（LR/SC/AMO）は整列を要求するので別の属性のままである。
    // Ref: SPEC-RISCV-UNPRIV (20250508), arch-requirements.md §RISC-V.
    align: Align::Unaligned,
    kind: AccessKind::DataRead,
};

const DATA_WRITE: Access = Access {
    endian: Endian::Le,
    // DATA_READ と同じ理由で非整列を許す。
    align: Align::Unaligned,
    kind: AccessKind::DataWrite,
};

const LR_ACC: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::LoadReserved,
};

const SC_ACC: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::StoreConditional,
};

const AMO_ACC: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
    kind: AccessKind::AtomicRw,
};

fn read<B: Backend>(b: &mut B, r: Gpr) -> B::V<W64> {
    if r.is_zero() {
        b.konst::<W64>(0)
    } else {
        b.get(r.state())
    }
}

fn write<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W64>) {
    if !rd.is_zero() {
        b.set(rd.state(), v);
    }
}

fn const_w64<B: Backend>(b: &mut B, v: u64) -> B::V<W64> {
    b.konst::<W64>(v)
}

// U 型と J 型

/// LUI。`imm20` は 20 ビットの即値（下位に配置する前の値）である。
pub fn lui<B: Backend>(b: &mut B, rd: Gpr, imm20: i64) -> Flow<B> {
    let v = const_w64(b, (imm20 as u64) << 12);
    write(b, rd, v);
    Ok(())
}

/// AUIPC。
pub fn auipc<B: Backend>(b: &mut B, rd: Gpr, pc: u64, imm20: i64) -> Flow<B> {
    let v = const_w64(b, pc.wrapping_add((imm20 as u64) << 12));
    write(b, rd, v);
    Ok(())
}

/// JAL。`jimm` は組み立て済みのバイトオフセットである。
pub fn jal<B: Backend>(b: &mut B, rd: Gpr, pc: u64, jimm: i64) -> Flow<B> {
    let ret = const_w64(b, pc.wrapping_add(4));
    write(b, rd, ret);
    let target = const_w64(b, pc.wrapping_add(jimm as u64));
    b.jump(target);
    Ok(())
}

/// JALR。飛び先の最下位ビットは 0 にする。
pub fn jalr<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, pc: u64, oimm: i64) -> Flow<B> {
    let base = read(b, rs1);
    let off = const_w64(b, oimm as u64);
    let sum = b.add(base, off);
    let mask = const_w64(b, !1);
    let target = b.and(sum, mask);
    let ret = const_w64(b, pc.wrapping_add(4));
    write(b, rd, ret);
    b.jump(target);
    Ok(())
}

// 分岐

fn branch<B: Backend>(b: &mut B, op: Cmp, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let c = b.cmp(op, x, y);
    b.branch(c, pc.wrapping_add(bimm as u64));
    Ok(())
}

fn cimm_value(cimm: u8) -> u64 {
    if cimm == 0 { u64::MAX } else { u64::from(cimm) }
}

fn branch_imm<B: Backend>(b: &mut B, op: Cmp, rs1: Gpr, cimm: u8, pc: u64, bimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = const_w64(b, cimm_value(cimm));
    let c = b.cmp(op, x, y);
    b.branch(c, pc.wrapping_add(bimm as u64));
    Ok(())
}

pub fn beqi<B: Backend>(b: &mut B, rs1: Gpr, cimm: u8, pc: u64, bimm: i64) -> Flow<B> {
    branch_imm(b, Cmp::Eq, rs1, cimm, pc, bimm)
}

pub fn bnei<B: Backend>(b: &mut B, rs1: Gpr, cimm: u8, pc: u64, bimm: i64) -> Flow<B> {
    branch_imm(b, Cmp::Ne, rs1, cimm, pc, bimm)
}

pub fn beq<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch(b, Cmp::Eq, rs1, rs2, pc, bimm)
}

pub fn bne<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch(b, Cmp::Ne, rs1, rs2, pc, bimm)
}

pub fn blt<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch(b, Cmp::LtS, rs1, rs2, pc, bimm)
}

pub fn bge<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch(b, Cmp::GeS, rs1, rs2, pc, bimm)
}

pub fn bltu<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch(b, Cmp::LtU, rs1, rs2, pc, bimm)
}

pub fn bgeu<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch(b, Cmp::GeU, rs1, rs2, pc, bimm)
}

// ロード

fn load_addr<B: Backend>(b: &mut B, rs1: Gpr, oimm: i64) -> B::V<W64> {
    let base = read(b, rs1);
    let off = const_w64(b, oimm as u64);
    b.add(base, off)
}

pub fn lb<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W8> = b.load(addr, DATA_READ)?;
    let e = b.sext::<W8, W64>(v);
    write(b, rd, e);
    Ok(())
}

pub fn lh<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W16> = b.load(addr, DATA_READ)?;
    let e = b.sext::<W16, W64>(v);
    write(b, rd, e);
    Ok(())
}

pub fn lw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W32> = b.load(addr, DATA_READ)?;
    let e = b.sext::<W32, W64>(v);
    write(b, rd, e);
    Ok(())
}

pub fn ld<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W64> = b.load(addr, DATA_READ)?;
    write(b, rd, v);
    Ok(())
}

pub fn lbu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W8> = b.load(addr, DATA_READ)?;
    let e = b.zext::<W8, W64>(v);
    write(b, rd, e);
    Ok(())
}

pub fn lhu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W16> = b.load(addr, DATA_READ)?;
    let e = b.zext::<W16, W64>(v);
    write(b, rd, e);
    Ok(())
}

pub fn lwu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W32> = b.load(addr, DATA_READ)?;
    let e = b.zext::<W32, W64>(v);
    write(b, rd, e);
    Ok(())
}

// ストア。書き込みの前に `probe` で全範囲の可否を確かめ、
// 例外時は状態を変えずに退出する（[命令意味論](../../../docs/architecture/execution.md)）。

pub fn sb<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W8>(raw);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 1, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sh<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W16>(raw);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 2, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sw<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W32>(raw);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 4, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sd<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let v = read(b, rs2);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 8, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

// OP-IMM

pub fn addi<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = const_w64(b, oimm as u64);
    let s = b.add(x, y);
    write(b, rd, s);
    Ok(())
}

fn setcc<B: Backend>(b: &mut B, rd: Gpr, c: B::B) {
    let t = const_w64(b, 1);
    let f = const_w64(b, 0);
    let v = b.select(c, t, f);
    write(b, rd, v);
}

pub fn slti<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = const_w64(b, oimm as u64);
    let c = b.cmp(Cmp::LtS, x, y);
    setcc(b, rd, c);
    Ok(())
}

pub fn sltiu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = const_w64(b, oimm as u64);
    let c = b.cmp(Cmp::LtU, x, y);
    setcc(b, rd, c);
    Ok(())
}

pub fn xori<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = const_w64(b, oimm as u64);
    let s = b.xor(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn ori<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = const_w64(b, oimm as u64);
    let s = b.or(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn andi<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read(b, rs1);
    let y = const_w64(b, oimm as u64);
    let s = b.and(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn slli<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x = read(b, rs1);
    let n = const_w64(b, shamt & 63);
    let s = b.shl(x, n);
    write(b, rd, s);
    Ok(())
}

pub fn srli<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x = read(b, rs1);
    let n = const_w64(b, shamt & 63);
    let s = b.shr_l(x, n);
    write(b, rd, s);
    Ok(())
}

pub fn srai<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x = read(b, rs1);
    let n = const_w64(b, shamt & 63);
    let s = b.shr_a(x, n);
    write(b, rd, s);
    Ok(())
}

// OP-IMM-32。下位 32 ビットで演算し、符号拡張して書く。

fn write_w<B: Backend>(b: &mut B, rd: Gpr, v: B::V<W32>) {
    let e = b.sext::<W32, W64>(v);
    write(b, rd, e);
}

pub fn addiw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let xr = read(b, rs1);
    let x = b.trunc::<W64, W32>(xr);
    let y = b.konst::<W32>(oimm as u32);
    let s = b.add(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn slliw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let xr = read(b, rs1);
    let x = b.trunc::<W64, W32>(xr);
    let n = b.konst::<W32>((shamt & 31) as u32);
    let s = b.shl(x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn srliw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let xr = read(b, rs1);
    let x = b.trunc::<W64, W32>(xr);
    let n = b.konst::<W32>((shamt & 31) as u32);
    let s = b.shr_l(x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn sraiw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let xr = read(b, rs1);
    let x = b.trunc::<W64, W32>(xr);
    let n = b.konst::<W32>((shamt & 31) as u32);
    let s = b.shr_a(x, n);
    write_w(b, rd, s);
    Ok(())
}

// OP

pub fn add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.add(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn sub<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.sub(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn sll<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let m = const_w64(b, 63);
    let raw = read(b, rs2);
    let n = b.and(raw, m);
    let s = b.shl(x, n);
    write(b, rd, s);
    Ok(())
}

pub fn slt<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let c = b.cmp(Cmp::LtS, x, y);
    setcc(b, rd, c);
    Ok(())
}

pub fn sltu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let c = b.cmp(Cmp::LtU, x, y);
    setcc(b, rd, c);
    Ok(())
}

pub fn xor<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.xor(x, y);
    write(b, rd, s);
    Ok(())
}

/// キャッシュ管理操作はコヒアレントなエミュレーションでは何もしない。
pub fn cbo_mgmt<B: Backend>(_b: &mut B, _rs1: Gpr) -> Flow<B> {
    Ok(())
}

/// CBO.ZERO はアドレスを含む 64 バイトブロックを零で埋める。
pub fn cbo_zero<B: Backend>(b: &mut B, rs1: Gpr) -> Flow<B> {
    let addr = read(b, rs1);
    let keep = const_w64(b, !63u64);
    let base0 = b.and(addr, keep);
    let zero = const_w64(b, 0);
    for i in 0..8u64 {
        let off = const_w64(b, i * 8);
        let a = b.add(base0, off);
        b.store::<W64>(a, zero, DATA_WRITE)?;
    }
    Ok(())
}

/// RV32 の CBO.ZERO。アドレスは下位 32 ビットである。
pub fn cbo_zero_rv32<B: Backend>(b: &mut B, rs1: Gpr) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W32>(x64);
    let addr = b.zext::<W32, W64>(x);
    let keep = const_w64(b, !63u64);
    let base0 = b.and(addr, keep);
    let zero = const_w64(b, 0);
    for i in 0..8u64 {
        let off = const_w64(b, i * 8);
        let a = b.add(base0, off);
        b.store::<W64>(a, zero, DATA_WRITE)?;
    }
    Ok(())
}

/// MOP は再定義されない限り rd へ 0 を書く。
pub fn mop<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let z = const_w64(b, 0);
    write(b, rd, z);
    Ok(())
}

/// 圧縮 MOP は再定義されない限り何もしない。
pub fn c_mop<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

// Zba/Zbb/Zbc/Zbs。RV64 形の意味論。RV32 形は対応する符号化と
// 32 ビット包み込みを別途そろえる。

fn shl64<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let k = const_w64(b, n);
    b.shl(x, k)
}

fn shr64<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let k = const_w64(b, n);
    b.shr_l(x, k)
}

fn bit_count<B: Backend>(b: &mut B, x: B::V<W64>, bits: u32) -> B::V<W64> {
    let mut acc = const_w64(b, 0);
    let one = const_w64(b, 1);
    for i in 0..bits {
        let s = shr64(b, x, u64::from(i));
        let bit = b.and(s, one);
        acc = b.add(acc, bit);
    }
    acc
}

fn zero_count<B: Backend>(b: &mut B, x: B::V<W64>, bits: u32, leading: bool) -> B::V<W64> {
    let mut acc = const_w64(b, 0);
    let mut higher = const_w64(b, 0);
    let one = const_w64(b, 1);
    for i in 0..bits {
        let pos = if leading { bits - 1 - i } else { i };
        let s = shr64(b, x, u64::from(pos));
        let bit = b.and(s, one);
        let notbit = b.sub(one, bit);
        let unseen = b.sub(one, higher);
        let contribute = b.and(notbit, unseen);
        acc = b.add(acc, contribute);
        higher = b.or(higher, bit);
    }
    acc
}

fn rol64<B: Backend>(b: &mut B, x: B::V<W64>, n: B::V<W64>) -> B::V<W64> {
    let mask = const_w64(b, 63);
    let n = b.and(n, mask);
    let width = const_w64(b, 64);
    let inv0 = b.sub(width, n);
    let inv = b.and(inv0, mask);
    let l = b.shl(x, n);
    let r = b.shr_l(x, inv);
    b.or(l, r)
}

fn ror64<B: Backend>(b: &mut B, x: B::V<W64>, n: B::V<W64>) -> B::V<W64> {
    let mask = const_w64(b, 63);
    let n = b.and(n, mask);
    let width = const_w64(b, 64);
    let inv0 = b.sub(width, n);
    let inv = b.and(inv0, mask);
    let r = b.shr_l(x, n);
    let l = b.shl(x, inv);
    b.or(l, r)
}

fn rol32<B: Backend>(b: &mut B, x: B::V<W32>, n: B::V<W32>) -> B::V<W32> {
    let mask = b.konst::<W32>(31);
    let n = b.and(n, mask);
    let width = b.konst::<W32>(32);
    let inv0 = b.sub(width, n);
    let inv = b.and(inv0, mask);
    let l = b.shl(x, n);
    let r = b.shr_l(x, inv);
    b.or(l, r)
}

fn ror32<B: Backend>(b: &mut B, x: B::V<W32>, n: B::V<W32>) -> B::V<W32> {
    let mask = b.konst::<W32>(31);
    let n = b.and(n, mask);
    let width = b.konst::<W32>(32);
    let inv0 = b.sub(width, n);
    let inv = b.and(inv0, mask);
    let r = b.shr_l(x, n);
    let l = b.shl(x, inv);
    b.or(l, r)
}

pub fn add_uw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x64 = read(b, rs1);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.zext::<W32, W64>(x32);
    let y = read(b, rs2);
    let s = b.add(x, y);
    write(b, rd, s);
    Ok(())
}

fn shadd<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, sh: u64) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let t = shl64(b, x, sh);
    let s = b.add(t, y);
    write(b, rd, s);
    Ok(())
}

pub fn sh1add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    shadd(b, rd, rs1, rs2, 1)
}
pub fn sh2add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    shadd(b, rd, rs1, rs2, 2)
}
pub fn sh3add<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    shadd(b, rd, rs1, rs2, 3)
}

fn shadd_uw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, sh: u64) -> Flow<B> {
    let x64 = read(b, rs1);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.zext::<W32, W64>(x32);
    let y = read(b, rs2);
    let t = shl64(b, x, sh);
    let s = b.add(t, y);
    write(b, rd, s);
    Ok(())
}

pub fn sh1add_uw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    shadd_uw(b, rd, rs1, rs2, 1)
}
pub fn sh2add_uw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    shadd_uw(b, rd, rs1, rs2, 2)
}
pub fn sh3add_uw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    shadd_uw(b, rd, rs1, rs2, 3)
}

pub fn slli_uw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x64 = read(b, rs1);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.zext::<W32, W64>(x32);
    let s = shl64(b, x, shamt & 63);
    write(b, rd, s);
    Ok(())
}

pub fn andn<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let ny = b.not(y);
    let s = b.and(x, ny);
    write(b, rd, s);
    Ok(())
}

pub fn orn<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let ny = b.not(y);
    let s = b.or(x, ny);
    write(b, rd, s);
    Ok(())
}

pub fn xnor<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let xy = b.xor(x, y);
    let s = b.not(xy);
    write(b, rd, s);
    Ok(())
}

fn count64<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, kind: u32) -> Flow<B> {
    let x = read(b, rs1);
    let s = match kind {
        0 => zero_count(b, x, 64, true),
        1 => zero_count(b, x, 64, false),
        _ => bit_count(b, x, 64),
    };
    write(b, rd, s);
    Ok(())
}

pub fn clz<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    count64(b, rd, rs1, 0)
}
pub fn ctz<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    count64(b, rd, rs1, 1)
}
pub fn cpop<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    count64(b, rd, rs1, 2)
}

fn countw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, kind: u32) -> Flow<B> {
    let x64 = read(b, rs1);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.zext::<W32, W64>(x32);
    let s64 = match kind {
        0 => zero_count(b, x, 32, true),
        1 => zero_count(b, x, 32, false),
        _ => bit_count(b, x, 32),
    };
    let s = b.trunc::<W64, W32>(s64);
    write_w(b, rd, s);
    Ok(())
}

pub fn clzw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    countw(b, rd, rs1, 0)
}
pub fn ctzw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    countw(b, rd, rs1, 1)
}
pub fn cpopw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    countw(b, rd, rs1, 2)
}

fn minmax<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, op: Cmp, choose_x: bool) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let c = b.cmp(op, x, y);
    let s = if choose_x {
        b.select(c, x, y)
    } else {
        b.select(c, y, x)
    };
    write(b, rd, s);
    Ok(())
}

pub fn max<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    minmax(b, rd, rs1, rs2, Cmp::GtS, true)
}
pub fn maxu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    minmax(b, rd, rs1, rs2, Cmp::GtU, true)
}
pub fn min<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    minmax(b, rd, rs1, rs2, Cmp::LtS, true)
}
pub fn minu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    minmax(b, rd, rs1, rs2, Cmp::LtU, true)
}

pub fn rol<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let n = read(b, rs2);
    let s = rol64(b, x, n);
    write(b, rd, s);
    Ok(())
}

pub fn ror<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let n = read(b, rs2);
    let s = ror64(b, x, n);
    write(b, rd, s);
    Ok(())
}

pub fn rolw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W32>(x64);
    let n64 = read(b, rs2);
    let n = b.trunc::<W64, W32>(n64);
    let s = rol32(b, x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn rorw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W32>(x64);
    let n64 = read(b, rs2);
    let n = b.trunc::<W64, W32>(n64);
    let s = ror32(b, x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn rori<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x = read(b, rs1);
    let n = const_w64(b, shamt & 63);
    let s = ror64(b, x, n);
    write(b, rd, s);
    Ok(())
}

pub fn roriw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W32>(x64);
    let n = b.konst::<W32>((shamt & 31) as u32);
    let s = ror32(b, x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn orc_b<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let mut out = const_w64(b, 0);
    let zero = const_w64(b, 0);
    let ff = const_w64(b, 0xff);
    for i in 0..8 {
        let sh = shr64(b, x, i * 8);
        let byte = b.and(sh, ff);
        let nz = b.cmp(Cmp::Ne, byte, zero);
        let part0 = b.select(nz, ff, zero);
        let part = shl64(b, part0, i * 8);
        out = b.or(out, part);
    }
    write(b, rd, out);
    Ok(())
}

pub fn rev8<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let mut out = const_w64(b, 0);
    let ff = const_w64(b, 0xff);
    for i in 0..8 {
        let sh = shr64(b, x, i * 8);
        let byte = b.and(sh, ff);
        let part = shl64(b, byte, 56 - i * 8);
        out = b.or(out, part);
    }
    write(b, rd, out);
    Ok(())
}

fn xperm64<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs1: Gpr,
    rs2: Gpr,
    elem_bits: u64,
    lanes: u64,
) -> Flow<B> {
    let lut = read(b, rs1);
    let idxs = read(b, rs2);
    let elem_mask = const_w64(b, (1u64 << elem_bits) - 1);
    let count = const_w64(b, lanes);
    let zero = const_w64(b, 0);
    let bits = const_w64(b, elem_bits);
    let mut out = zero;
    for lane in 0..lanes {
        let pos = lane * elem_bits;
        let idx0 = shr64(b, idxs, pos);
        // xperm8 の index 幅は 8 ビットなので、表の要素数を越えるものは 0 にする。
        let idx_mask = if elem_bits == 8 {
            const_w64(b, 0xff)
        } else {
            elem_mask
        };
        let idx = b.and(idx0, idx_mask);
        let valid = b.cmp(Cmp::LtU, idx, count);
        let shift = b.mul(idx, bits);
        let raw = b.shr_l(lut, shift);
        let elem0 = b.and(raw, elem_mask);
        let elem = b.select(valid, elem0, zero);
        let part = shl64(b, elem, pos);
        out = b.or(out, part);
    }
    write(b, rd, out);
    Ok(())
}

fn ror32_const<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let k = b.konst::<W32>(n);
    ror32(b, x, k)
}

fn ror64_const<B: Backend>(b: &mut B, x: B::V<W64>, n: u64) -> B::V<W64> {
    let k = const_w64(b, n);
    ror64(b, x, k)
}

struct AesTables {
    sbox: [u32; 256],
    inv_sbox: [u32; 256],
    fwd: [[u32; 256]; 4],
    inv: [[u32; 256]; 4],
    inv_id: [[u32; 256]; 4],
}

const fn aes_gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

const fn aes_gf_pow(mut x: u8, mut n: u32) -> u8 {
    let mut out = 1u8;
    while n != 0 {
        if n & 1 != 0 {
            out = aes_gf_mul(out, x);
        }
        x = aes_gf_mul(x, x);
        n >>= 1;
    }
    out
}

const fn aes_sbox_val(x: u8) -> u8 {
    let inv = if x == 0 { 0 } else { aes_gf_pow(x, 254) };
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

const fn aes_mixcolumn_fwd_const(x: u32) -> u32 {
    let s0 = x as u8;
    let s1 = (x >> 8) as u8;
    let s2 = (x >> 16) as u8;
    let s3 = (x >> 24) as u8;
    let b0 = aes_gf_mul(s0, 2) ^ aes_gf_mul(s1, 3) ^ s2 ^ s3;
    let b1 = s0 ^ aes_gf_mul(s1, 2) ^ aes_gf_mul(s2, 3) ^ s3;
    let b2 = s0 ^ s1 ^ aes_gf_mul(s2, 2) ^ aes_gf_mul(s3, 3);
    let b3 = aes_gf_mul(s0, 3) ^ s1 ^ s2 ^ aes_gf_mul(s3, 2);
    ((b3 as u32) << 24) | ((b2 as u32) << 16) | ((b1 as u32) << 8) | b0 as u32
}

const fn aes_mixcolumn_inv_const(x: u32) -> u32 {
    let s0 = x as u8;
    let s1 = (x >> 8) as u8;
    let s2 = (x >> 16) as u8;
    let s3 = (x >> 24) as u8;
    let b0 = aes_gf_mul(s0, 0xe) ^ aes_gf_mul(s1, 0xb) ^ aes_gf_mul(s2, 0xd) ^ aes_gf_mul(s3, 9);
    let b1 = aes_gf_mul(s0, 9) ^ aes_gf_mul(s1, 0xe) ^ aes_gf_mul(s2, 0xb) ^ aes_gf_mul(s3, 0xd);
    let b2 = aes_gf_mul(s0, 0xd) ^ aes_gf_mul(s1, 9) ^ aes_gf_mul(s2, 0xe) ^ aes_gf_mul(s3, 0xb);
    let b3 = aes_gf_mul(s0, 0xb) ^ aes_gf_mul(s1, 0xd) ^ aes_gf_mul(s2, 9) ^ aes_gf_mul(s3, 0xe);
    ((b3 as u32) << 24) | ((b2 as u32) << 16) | ((b1 as u32) << 8) | b0 as u32
}

const fn aes_tables() -> AesTables {
    let mut sbox8 = [0u8; 256];
    let mut inv_sbox8 = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let v = aes_sbox_val(i as u8);
        sbox8[i] = v;
        inv_sbox8[v as usize] = i as u8;
        i += 1;
    }
    let mut sbox = [0u32; 256];
    let mut inv_sbox = [0u32; 256];
    let mut fwd = [[0u32; 256]; 4];
    let mut inv = [[0u32; 256]; 4];
    let mut inv_id = [[0u32; 256]; 4];
    let mut pos = 0usize;
    while pos < 4 {
        let mut x = 0usize;
        while x < 256 {
            let sh = (pos * 8) as u32;
            let sx = sbox8[x] as u32;
            let ix = inv_sbox8[x] as u32;
            sbox[x] = sx;
            inv_sbox[x] = ix;
            fwd[pos][x] = aes_mixcolumn_fwd_const(sx << sh);
            inv[pos][x] = aes_mixcolumn_inv_const(ix << sh);
            inv_id[pos][x] = aes_mixcolumn_inv_const((x as u32) << sh);
            x += 1;
        }
        pos += 1;
    }
    AesTables {
        sbox,
        inv_sbox,
        fwd,
        inv,
        inv_id,
    }
}

const AES_TABLES: AesTables = aes_tables();

fn byte64<B: Backend>(b: &mut B, x: B::V<W64>, index: u64) -> B::V<W32> {
    let s = shr64(b, x, index * 8);
    b.trunc::<W64, W32>(s)
}

fn pack32<B: Backend>(b: &mut B, bytes: [B::V<W32>; 4]) -> B::V<W32> {
    let ff = b.konst::<W32>(0xff);
    let mut out = b.konst::<W32>(0);
    for (i, byte) in bytes.into_iter().enumerate() {
        let v = b.and(byte, ff);
        let sh = b.konst::<W32>((i as u32) * 8);
        let part = b.shl(v, sh);
        out = b.or(out, part);
    }
    out
}

fn pack64<B: Backend>(b: &mut B, bytes: [B::V<W32>; 8]) -> B::V<W64> {
    let mut out = const_w64(b, 0);
    for (i, byte) in bytes.into_iter().enumerate() {
        let v = b.zext::<W32, W64>(byte);
        let ff = const_w64(b, 0xff);
        let v = b.and(v, ff);
        let part = shl64(b, v, (i as u64) * 8);
        out = b.or(out, part);
    }
    out
}

fn aes_apply_sbox64<B: Backend>(b: &mut B, x: B::V<W64>, inverse: bool) -> B::V<W64> {
    let table = if inverse {
        &AES_TABLES.inv_sbox
    } else {
        &AES_TABLES.sbox
    };
    let mut bytes = [b.konst::<W32>(0); 8];
    for (i, slot) in bytes.iter_mut().enumerate() {
        let idx = byte64(b, x, i as u64);
        *slot = lut32(b, idx, table);
    }
    pack64(b, bytes)
}

fn aes_shiftrows_fwd64<B: Backend>(b: &mut B, rs2v: B::V<W64>, rs1v: B::V<W64>) -> B::V<W64> {
    let b0 = byte64(b, rs1v, 0);
    let b1 = byte64(b, rs1v, 5);
    let b2 = byte64(b, rs2v, 2);
    let b3 = byte64(b, rs2v, 7);
    let b4 = byte64(b, rs1v, 4);
    let b5 = byte64(b, rs2v, 1);
    let b6 = byte64(b, rs2v, 6);
    let b7 = byte64(b, rs1v, 3);
    pack64(b, [b0, b1, b2, b3, b4, b5, b6, b7])
}

fn aes_shiftrows_inv64<B: Backend>(b: &mut B, rs2v: B::V<W64>, rs1v: B::V<W64>) -> B::V<W64> {
    let b0 = byte64(b, rs1v, 0);
    let b1 = byte64(b, rs2v, 5);
    let b2 = byte64(b, rs2v, 2);
    let b3 = byte64(b, rs1v, 7);
    let b4 = byte64(b, rs1v, 4);
    let b5 = byte64(b, rs1v, 1);
    let b6 = byte64(b, rs2v, 6);
    let b7 = byte64(b, rs2v, 3);
    pack64(b, [b0, b1, b2, b3, b4, b5, b6, b7])
}

fn aes_mix64_tables<B: Backend>(b: &mut B, x: B::V<W64>, tables: &[[u32; 256]; 4]) -> B::V<W64> {
    let zero = b.konst::<W32>(0);
    let mut cols = [zero; 2];
    for (col, slot) in cols.iter_mut().enumerate() {
        let mut out = zero;
        for pos in 0..4u64 {
            let idx = byte64(b, x, (col as u64) * 4 + pos);
            let v = lut32(b, idx, &tables[pos as usize]);
            out = b.xor(out, v);
        }
        *slot = out;
    }
    let lo = b.zext::<W32, W64>(cols[0]);
    let hi0 = b.zext::<W32, W64>(cols[1]);
    let hi = shl64(b, hi0, 32);
    b.or(lo, hi)
}

fn aes64_round<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs1: Gpr,
    rs2: Gpr,
    decrypt: bool,
    mix: bool,
) -> Flow<B> {
    let x1 = read(b, rs1);
    let x2 = read(b, rs2);
    let sr = if decrypt {
        aes_shiftrows_inv64(b, x2, x1)
    } else {
        aes_shiftrows_fwd64(b, x2, x1)
    };
    let out = if mix {
        let tables = if decrypt {
            &AES_TABLES.inv
        } else {
            &AES_TABLES.fwd
        };
        aes_mix64_tables(b, sr, tables)
    } else {
        aes_apply_sbox64(b, sr, decrypt)
    };
    write(b, rd, out);
    Ok(())
}

pub fn aes64es<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    aes64_round(b, rd, rs1, rs2, false, false)
}

pub fn aes64esm<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    aes64_round(b, rd, rs1, rs2, false, true)
}

pub fn aes64ds<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    aes64_round(b, rd, rs1, rs2, true, false)
}

pub fn aes64dsm<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    aes64_round(b, rd, rs1, rs2, true, true)
}

pub fn aes64im<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let out = aes_mix64_tables(b, x, &AES_TABLES.inv_id);
    write(b, rd, out);
    Ok(())
}

fn aes_subword<B: Backend>(b: &mut B, x: B::V<W32>) -> B::V<W32> {
    let ff = b.konst::<W32>(0xff);
    let mut bytes = [b.konst::<W32>(0); 4];
    for (i, slot) in bytes.iter_mut().enumerate() {
        let sh = b.konst::<W32>((i as u32) * 8);
        let idx0 = b.shr_l(x, sh);
        let idx = b.and(idx0, ff);
        *slot = lut32(b, idx, &AES_TABLES.sbox);
    }
    pack32(b, bytes)
}

pub fn aes64ks1i<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rnum: u8) -> Flow<B> {
    let x = read(b, rs1);
    let hi64 = shr64(b, x, 32);
    let tmp1 = b.trunc::<W64, W32>(hi64);
    let tmp2 = if rnum == 10 {
        tmp1
    } else {
        ror32_const(b, tmp1, 8)
    };
    let tmp3 = aes_subword(b, tmp2);
    let rc = if rnum < 10 {
        [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36][rnum as usize]
    } else {
        0
    };
    let rcv = b.konst::<W32>(rc);
    let w = b.xor(tmp3, rcv);
    let lo = b.zext::<W32, W64>(w);
    let hi0 = b.zext::<W32, W64>(w);
    let hi = shl64(b, hi0, 32);
    let out = b.or(lo, hi);
    write(b, rd, out);
    Ok(())
}

pub fn aes64ks2<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x1 = read(b, rs1);
    let x2 = read(b, rs2);
    let ff64 = const_w64(b, 0xffff_ffff);
    let rs1_hi64 = shr64(b, x1, 32);
    let rs2_lo64 = b.and(x2, ff64);
    let rs2_hi64 = shr64(b, x2, 32);
    let rs1_hi = b.trunc::<W64, W32>(rs1_hi64);
    let rs2_lo = b.trunc::<W64, W32>(rs2_lo64);
    let rs2_hi = b.trunc::<W64, W32>(rs2_hi64);
    let w0 = b.xor(rs1_hi, rs2_lo);
    let w1 = b.xor(w0, rs2_hi);
    let lo = b.zext::<W32, W64>(w0);
    let hi0 = b.zext::<W32, W64>(w1);
    let hi = shl64(b, hi0, 32);
    let out = b.or(lo, hi);
    write(b, rd, out);
    Ok(())
}

#[rustfmt::skip]
const SM4_SBOX: [u8; 256] = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
];

const fn sm4_t_tables() -> ([u32; 256], [u32; 256]) {
    let mut ed = [0u32; 256];
    let mut ks = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let x = SM4_SBOX[i] as u32;
        // 仕様は byte をゼロ拡張した x に対し、線形層をマスク付きの
        // 左シフト合成として定義する。単純な 32 ビット rotate とは
        // 桁上がりの扱いが違うので、その形で固定しておく。
        ed[i] = x
            ^ x.wrapping_shl(8)
            ^ x.wrapping_shl(2)
            ^ x.wrapping_shl(18)
            ^ ((x & 0x3f).wrapping_shl(26))
            ^ ((x & 0xc0).wrapping_shl(10));
        ks[i] = x
            ^ ((x & 0x07).wrapping_shl(29))
            ^ ((x & 0xfe).wrapping_shl(7))
            ^ ((x & 0x01).wrapping_shl(23))
            ^ ((x & 0xf8).wrapping_shl(13));
        i += 1;
    }
    (ed, ks)
}

const SM4_T_ED: [u32; 256] = sm4_t_tables().0;
const SM4_T_KS: [u32; 256] = sm4_t_tables().1;

fn lut32<B: Backend>(b: &mut B, idx: B::V<W32>, table: &[u32; 256]) -> B::V<W32> {
    let ff = b.konst::<W32>(0xff);
    let idx = b.and(idx, ff);
    let mut out = b.konst::<W32>(table[0]);
    for (i, v) in table.iter().enumerate().skip(1) {
        let k = b.konst::<W32>(i as u32);
        let eq = b.cmp(Cmp::Eq, idx, k);
        let val = b.konst::<W32>(*v);
        out = b.select(eq, val, out);
    }
    out
}

fn sm4_op<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, bs: u8, key_sched: bool) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W32>(x64);
    let a64 = read(b, rs2);
    let a = b.trunc::<W64, W32>(a64);
    let sh = b.konst::<W32>((bs as u32) * 8);
    let byte0 = b.shr_l(a, sh);
    let t = if key_sched {
        lut32(b, byte0, &SM4_T_KS)
    } else {
        lut32(b, byte0, &SM4_T_ED)
    };
    let rot = rol32_const(b, t, (bs as u32) * 8);
    let out = b.xor(x, rot);
    write_w(b, rd, out);
    Ok(())
}

pub fn sm4ed<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, bs: u8) -> Flow<B> {
    sm4_op(b, rd, rs1, rs2, bs, false)
}

pub fn sm4ks<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, bs: u8) -> Flow<B> {
    sm4_op(b, rd, rs1, rs2, bs, true)
}

fn rol32_const<B: Backend>(b: &mut B, x: B::V<W32>, n: u32) -> B::V<W32> {
    let k = b.konst::<W32>(n);
    rol32(b, x, k)
}

fn sm3p<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, a: u32, c: u32) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W32>(x64);
    let l = rol32_const(b, x, a);
    let r = rol32_const(b, x, c);
    let t = b.xor(x, l);
    let out = b.xor(t, r);
    write_w(b, rd, out);
    Ok(())
}

pub fn sm3p0<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sm3p(b, rd, rs1, 9, 17)
}

pub fn sm3p1<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sm3p(b, rd, rs1, 15, 23)
}

fn sha256_op<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, kind: u8) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W32>(x64);
    let (a, c, d, shift) = match kind {
        0 => (ror32_const(b, x, 7), ror32_const(b, x, 18), None, 3),
        1 => (ror32_const(b, x, 17), ror32_const(b, x, 19), None, 10),
        2 => (
            ror32_const(b, x, 2),
            ror32_const(b, x, 13),
            Some(ror32_const(b, x, 22)),
            0,
        ),
        _ => (
            ror32_const(b, x, 6),
            ror32_const(b, x, 11),
            Some(ror32_const(b, x, 25)),
            0,
        ),
    };
    let mut out = b.xor(a, c);
    if let Some(v) = d {
        out = b.xor(out, v);
    } else {
        let k = b.konst::<W32>(shift);
        let v = b.shr_l(x, k);
        out = b.xor(out, v);
    }
    write_w(b, rd, out);
    Ok(())
}

pub fn sha256sig0<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha256_op(b, rd, rs1, 0)
}
pub fn sha256sig1<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha256_op(b, rd, rs1, 1)
}
pub fn sha256sum0<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha256_op(b, rd, rs1, 2)
}
pub fn sha256sum1<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha256_op(b, rd, rs1, 3)
}

fn sha512_op<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, kind: u8) -> Flow<B> {
    let x = read(b, rs1);
    let (a, c, d, shift) = match kind {
        0 => (ror64_const(b, x, 1), ror64_const(b, x, 8), None, 7),
        1 => (ror64_const(b, x, 19), ror64_const(b, x, 61), None, 6),
        2 => (
            ror64_const(b, x, 28),
            ror64_const(b, x, 34),
            Some(ror64_const(b, x, 39)),
            0,
        ),
        _ => (
            ror64_const(b, x, 14),
            ror64_const(b, x, 18),
            Some(ror64_const(b, x, 41)),
            0,
        ),
    };
    let mut out = b.xor(a, c);
    if let Some(v) = d {
        out = b.xor(out, v);
    } else {
        let k = const_w64(b, shift);
        let v = b.shr_l(x, k);
        out = b.xor(out, v);
    }
    write(b, rd, out);
    Ok(())
}

pub fn sha512sig0<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha512_op(b, rd, rs1, 0)
}
pub fn sha512sig1<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha512_op(b, rd, rs1, 1)
}
pub fn sha512sum0<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha512_op(b, rd, rs1, 2)
}
pub fn sha512sum1<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    sha512_op(b, rd, rs1, 3)
}

pub fn xperm4<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    xperm64(b, rd, rs1, rs2, 4, 16)
}

pub fn xperm8<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    xperm64(b, rd, rs1, rs2, 8, 8)
}

fn xperm32<B: Backend>(
    b: &mut B,
    rd: Gpr,
    rs1: Gpr,
    rs2: Gpr,
    elem_bits: u64,
    lanes: u64,
) -> Flow<B> {
    let lut64 = read(b, rs1);
    let lut32 = b.trunc::<W64, W32>(lut64);
    let lut = b.zext::<W32, W64>(lut32);
    let idx64 = read(b, rs2);
    let idx32 = b.trunc::<W64, W32>(idx64);
    let idxs = b.zext::<W32, W64>(idx32);
    let elem_mask = const_w64(b, (1u64 << elem_bits) - 1);
    let count = const_w64(b, lanes);
    let zero = const_w64(b, 0);
    let bits = const_w64(b, elem_bits);
    let mut out = zero;
    for lane in 0..lanes {
        let pos = lane * elem_bits;
        let idx0 = shr64(b, idxs, pos);
        let idx_mask = if elem_bits == 8 {
            const_w64(b, 0xff)
        } else {
            elem_mask
        };
        let idx = b.and(idx0, idx_mask);
        let valid = b.cmp(Cmp::LtU, idx, count);
        let shift = b.mul(idx, bits);
        let raw = b.shr_l(lut, shift);
        let elem0 = b.and(raw, elem_mask);
        let elem = b.select(valid, elem0, zero);
        let part = shl64(b, elem, pos);
        out = b.or(out, part);
    }
    let out32 = b.trunc::<W64, W32>(out);
    write_w(b, rd, out32);
    Ok(())
}

pub fn xperm4_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    xperm32(b, rd, rs1, rs2, 4, 8)
}

pub fn xperm8_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    xperm32(b, rd, rs1, rs2, 8, 4)
}

pub fn sext_b<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W8>(x64);
    let s = b.sext::<W8, W64>(x);
    write(b, rd, s);
    Ok(())
}

pub fn sext_h<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W16>(x64);
    let s = b.sext::<W16, W64>(x);
    write(b, rd, s);
    Ok(())
}

pub fn zext_h<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr) -> Flow<B> {
    let x64 = read(b, rs1);
    let x = b.trunc::<W64, W16>(x64);
    let s = b.zext::<W16, W64>(x);
    write(b, rd, s);
    Ok(())
}

fn clmul_parts<B: Backend>(b: &mut B, x: B::V<W64>, y: B::V<W64>) -> (B::V<W64>, B::V<W64>) {
    let mut lo = const_w64(b, 0);
    let mut hi = const_w64(b, 0);
    let zero = const_w64(b, 0);
    let one = const_w64(b, 1);
    for i in 0..64u64 {
        let ys = shr64(b, y, i);
        let bit = b.and(ys, one);
        let on = b.cmp(Cmp::Ne, bit, zero);
        let lt = if i == 0 { x } else { shl64(b, x, i) };
        let ht = if i == 0 { zero } else { shr64(b, x, 64 - i) };
        let lt = b.select(on, lt, zero);
        let ht = b.select(on, ht, zero);
        lo = b.xor(lo, lt);
        hi = b.xor(hi, ht);
    }
    (lo, hi)
}

pub fn clmul<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let (s, _) = clmul_parts(b, x, y);
    write(b, rd, s);
    Ok(())
}

pub fn clmulh<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let (_, s) = clmul_parts(b, x, y);
    write(b, rd, s);
    Ok(())
}

pub fn clmulr<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let (lo, hi) = clmul_parts(b, x, y);
    let a = shr64(b, lo, 63);
    let c = shl64(b, hi, 1);
    let s = b.or(a, c);
    write(b, rd, s);
    Ok(())
}

fn bitpos64<B: Backend>(b: &mut B, rs2: Gpr) -> B::V<W64> {
    let raw = read(b, rs2);
    let m = const_w64(b, 63);
    b.and(raw, m)
}

fn bitmask64<B: Backend>(b: &mut B, n: B::V<W64>) -> B::V<W64> {
    let one = const_w64(b, 1);
    b.shl(one, n)
}

pub fn bclr<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let n = bitpos64(b, rs2);
    let mask = bitmask64(b, n);
    let nm = b.not(mask);
    let s = b.and(x, nm);
    write(b, rd, s);
    Ok(())
}

pub fn bext<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let n = bitpos64(b, rs2);
    let s0 = b.shr_l(x, n);
    let one = const_w64(b, 1);
    let s = b.and(s0, one);
    write(b, rd, s);
    Ok(())
}

pub fn binv<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let n = bitpos64(b, rs2);
    let mask = bitmask64(b, n);
    let s = b.xor(x, mask);
    write(b, rd, s);
    Ok(())
}

pub fn bset<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let n = bitpos64(b, rs2);
    let mask = bitmask64(b, n);
    let s = b.or(x, mask);
    write(b, rd, s);
    Ok(())
}

fn bitop_imm<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64, kind: u32) -> Flow<B> {
    let x = read(b, rs1);
    let n = const_w64(b, shamt & 63);
    let mask = bitmask64(b, n);
    let s = match kind {
        0 => {
            let nm = b.not(mask);
            b.and(x, nm)
        }
        1 => {
            let v = b.shr_l(x, n);
            let one = const_w64(b, 1);
            b.and(v, one)
        }
        2 => b.xor(x, mask),
        _ => b.or(x, mask),
    };
    write(b, rd, s);
    Ok(())
}

pub fn bclri<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    bitop_imm(b, rd, rs1, shamt, 0)
}
pub fn bexti<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    bitop_imm(b, rd, rs1, shamt, 1)
}
pub fn binvi<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    bitop_imm(b, rd, rs1, shamt, 2)
}
pub fn bseti<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    bitop_imm(b, rd, rs1, shamt, 3)
}

pub fn czero_eqz<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let cond = read(b, rs2);
    let zero = const_w64(b, 0);
    let is_zero = b.cmp(Cmp::Eq, cond, zero);
    let s = b.select(is_zero, zero, x);
    write(b, rd, s);
    Ok(())
}

pub fn czero_nez<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let cond = read(b, rs2);
    let zero = const_w64(b, 0);
    let nonzero = b.cmp(Cmp::Ne, cond, zero);
    let s = b.select(nonzero, zero, x);
    write(b, rd, s);
    Ok(())
}

pub fn srl<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let m = const_w64(b, 63);
    let raw = read(b, rs2);
    let n = b.and(raw, m);
    let s = b.shr_l(x, n);
    write(b, rd, s);
    Ok(())
}

pub fn sra<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let m = const_w64(b, 63);
    let raw = read(b, rs2);
    let n = b.and(raw, m);
    let s = b.shr_a(x, n);
    write(b, rd, s);
    Ok(())
}

pub fn or<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.or(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn and<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.and(x, y);
    write(b, rd, s);
    Ok(())
}

// OP-32

fn read_w<B: Backend>(b: &mut B, r: Gpr) -> B::V<W32> {
    let v = read(b, r);
    b.trunc::<W64, W32>(v)
}

pub fn addw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.add(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn subw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.sub(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn sllw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let m = b.konst::<W32>(31);
    let raw = read_w(b, rs2);
    let n = b.and(raw, m);
    let x = read_w(b, rs1);
    let s = b.shl(x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn srlw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let m = b.konst::<W32>(31);
    let raw = read_w(b, rs2);
    let n = b.and(raw, m);
    let x = read_w(b, rs1);
    let s = b.shr_l(x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn sraw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let m = b.konst::<W32>(31);
    let raw = read_w(b, rs2);
    let n = b.and(raw, m);
    let x = read_w(b, rs1);
    let s = b.shr_a(x, n);
    write_w(b, rd, s);
    Ok(())
}

// M（乗除算）

pub fn mul<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.mul(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn mulh<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.mulh(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn mulhsu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.mulhsu(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn mulhu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.mulhu(x, y);
    write(b, rd, s);
    Ok(())
}

/// DIV。0 除算は -1、最小値の -1 除算は最小値（RISC-V の規定）。
pub fn div<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let q = b.sdiv(x, y);
    let zero = const_w64(b, 0);
    let c = b.cmp(Cmp::Eq, y, zero);
    let all = const_w64(b, u64::MAX);
    let s = b.select(c, all, q);
    write(b, rd, s);
    Ok(())
}

/// DIVU。0 除算は全ビット 1（バックエンドの全域定義と一致）。
pub fn divu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.udiv(x, y);
    write(b, rd, s);
    Ok(())
}

/// REM。0 除算の剰余は被除数（バックエンドの全域定義と一致）。
pub fn rem<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.srem(x, y);
    write(b, rd, s);
    Ok(())
}

/// REMU。同上。
pub fn remu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let y = read(b, rs2);
    let s = b.urem(x, y);
    write(b, rd, s);
    Ok(())
}

pub fn mulw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.mul(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn divw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let q = b.sdiv(x, y);
    let zero = b.konst::<W32>(0);
    let c = b.cmp(Cmp::Eq, y, zero);
    let all = b.konst::<W32>(u32::MAX);
    let s = b.select(c, all, q);
    write_w(b, rd, s);
    Ok(())
}

pub fn divuw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.udiv(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn remw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.srem(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn remuw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.urem(x, y);
    write_w(b, rd, s);
    Ok(())
}

// RV32（XLEN=32）の整数演算。GPR は下位 32 ビットに符号拡張した値を置き、
// 分岐・ジャンプの飛び先とロードストアのアドレスは 32 ビットで包む。
// W 接尾辞の RV64 命令と同じ約束なので、意味が同一の演算は W 版に委譲する。
// Ref: SPEC-RISCV-UNPRIV (20250508) §RV32I.

/// 32 ビットマスク。RV32 の PC とアドレスの包み込みに使う。
const MASK32: u64 = 0xffff_ffff;

/// RV32 用のロードアドレス。32 ビットで包んでゼロ拡張する。
fn load_addr_rv32<B: Backend>(b: &mut B, rs1: Gpr, oimm: i64) -> B::V<W64> {
    let base = read(b, rs1);
    let b32 = b.trunc::<W64, W32>(base);
    let off = b.konst::<W32>(oimm as u32);
    let a32 = b.add(b32, off);
    b.zext::<W32, W64>(a32)
}

/// LUI（RV32）。
pub fn lui_rv32<B: Backend>(b: &mut B, rd: Gpr, imm20: i64) -> Flow<B> {
    let v = b.konst::<W32>((imm20 as u32) << 12);
    write_w(b, rd, v);
    Ok(())
}

/// AUIPC（RV32）。
pub fn auipc_rv32<B: Backend>(b: &mut B, rd: Gpr, pc: u64, imm20: i64) -> Flow<B> {
    let v = pc.wrapping_add((imm20 as u64) << 12) & MASK32;
    let w = b.konst::<W32>(v as u32);
    write_w(b, rd, w);
    Ok(())
}

/// JAL（RV32）。
pub fn jal_rv32<B: Backend>(b: &mut B, rd: Gpr, pc: u64, jimm: i64) -> Flow<B> {
    let ret = b.konst::<W32>(((pc.wrapping_add(4)) & MASK32) as u32);
    write_w(b, rd, ret);
    let target = const_w64(b, pc.wrapping_add(jimm as u64) & MASK32);
    b.jump(target);
    Ok(())
}

/// JALR（RV32）。飛び先の最下位ビットは 0 にし、32 ビットで包む。
pub fn jalr_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, pc: u64, oimm: i64) -> Flow<B> {
    let base = read(b, rs1);
    let b32 = b.trunc::<W64, W32>(base);
    let off = b.konst::<W32>(oimm as u32);
    let sum = b.add(b32, off);
    let addr = b.zext::<W32, W64>(sum);
    let mask = const_w64(b, !1);
    let target = b.and(addr, mask);
    let ret = b.konst::<W32>(((pc.wrapping_add(4)) & MASK32) as u32);
    write_w(b, rd, ret);
    b.jump(target);
    Ok(())
}

// RV32 分岐。条件は 32 ビットで比べ、飛び先は 32 ビットで包む。

fn branch_rv32<B: Backend>(b: &mut B, op: Cmp, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    // 符号付き比較は 64 ビットに符号拡張してから比べる。
    // 符号なし比較はゼロ拡張のままで正しい。
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let c = match op {
        Cmp::LtS | Cmp::GeS => {
            let xs = b.sext::<W32, W64>(x);
            let ys = b.sext::<W32, W64>(y);
            b.cmp(op, xs, ys)
        }
        _ => b.cmp(op, x, y),
    };
    b.branch(c, pc.wrapping_add(bimm as u64) & MASK32);
    Ok(())
}

fn branch_imm_rv32<B: Backend>(
    b: &mut B,
    op: Cmp,
    rs1: Gpr,
    cimm: u8,
    pc: u64,
    bimm: i64,
) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = b.konst::<W32>((cimm_value(cimm) & 0xffff_ffff) as u32);
    let c = b.cmp(op, x, y);
    b.branch(c, pc.wrapping_add(bimm as u64) & MASK32);
    Ok(())
}

pub fn beqi_rv32<B: Backend>(b: &mut B, rs1: Gpr, cimm: u8, pc: u64, bimm: i64) -> Flow<B> {
    branch_imm_rv32(b, Cmp::Eq, rs1, cimm, pc, bimm)
}

pub fn bnei_rv32<B: Backend>(b: &mut B, rs1: Gpr, cimm: u8, pc: u64, bimm: i64) -> Flow<B> {
    branch_imm_rv32(b, Cmp::Ne, rs1, cimm, pc, bimm)
}

pub fn beq_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch_rv32(b, Cmp::Eq, rs1, rs2, pc, bimm)
}

pub fn bne_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch_rv32(b, Cmp::Ne, rs1, rs2, pc, bimm)
}

pub fn blt_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch_rv32(b, Cmp::LtS, rs1, rs2, pc, bimm)
}

pub fn bge_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch_rv32(b, Cmp::GeS, rs1, rs2, pc, bimm)
}

pub fn bltu_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch_rv32(b, Cmp::LtU, rs1, rs2, pc, bimm)
}

pub fn bgeu_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, pc: u64, bimm: i64) -> Flow<B> {
    branch_rv32(b, Cmp::GeU, rs1, rs2, pc, bimm)
}

// RV32 ロード。32 ビットに符号・ゼロ拡張して書き戻す。

pub fn lb_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    let v: B::V<W8> = b.load(addr, DATA_READ)?;
    let e = b.sext::<W8, W32>(v);
    write_w(b, rd, e);
    Ok(())
}

pub fn lh_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    let v: B::V<W16> = b.load(addr, DATA_READ)?;
    let e = b.sext::<W16, W32>(v);
    write_w(b, rd, e);
    Ok(())
}

pub fn lw_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    let v: B::V<W32> = b.load(addr, DATA_READ)?;
    write_w(b, rd, v);
    Ok(())
}

pub fn lbu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    let v: B::V<W8> = b.load(addr, DATA_READ)?;
    let e = b.zext::<W8, W32>(v);
    write_w(b, rd, e);
    Ok(())
}

pub fn lhu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    let v: B::V<W16> = b.load(addr, DATA_READ)?;
    let e = b.zext::<W16, W32>(v);
    write_w(b, rd, e);
    Ok(())
}

// RV32 ストア。値の切り詰めは XLEN によらないので 64 ビット版と同じ形である。

pub fn sb_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W8>(raw);
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 1, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sh_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W16>(raw);
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 2, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sw_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W32>(raw);
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 4, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

// RV32 OP-IMM。32 ビット演算して符号拡張して書く。

pub fn addi_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = b.konst::<W32>(oimm as u32);
    let s = b.add(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn slti_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read_w(b, rs1);
    let xs = b.sext::<W32, W64>(x);
    let y = b.konst::<W32>(oimm as u32);
    let ys = b.sext::<W32, W64>(y);
    let c = b.cmp(Cmp::LtS, xs, ys);
    setcc(b, rd, c);
    Ok(())
}

pub fn sltiu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = b.konst::<W32>(oimm as u32);
    let c = b.cmp(Cmp::LtU, x, y);
    setcc(b, rd, c);
    Ok(())
}

pub fn xori_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = b.konst::<W32>(oimm as u32);
    let s = b.xor(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn ori_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = b.konst::<W32>(oimm as u32);
    let s = b.or(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn andi_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = b.konst::<W32>(oimm as u32);
    let s = b.and(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn slli_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x = read_w(b, rs1);
    let n = b.konst::<W32>((shamt & 31) as u32);
    let s = b.shl(x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn srli_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x = read_w(b, rs1);
    let n = b.konst::<W32>((shamt & 31) as u32);
    let s = b.shr_l(x, n);
    write_w(b, rd, s);
    Ok(())
}

pub fn srai_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, shamt: u64) -> Flow<B> {
    let x = read_w(b, rs1);
    let n = b.konst::<W32>((shamt & 31) as u32);
    let s = b.shr_a(x, n);
    write_w(b, rd, s);
    Ok(())
}

// RV32 OP。32 ビット演算して符号拡張して書く。W 接尾辞と意味が同一のものは委譲する。

pub fn add_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    addw(b, rd, rs1, rs2)
}

pub fn sub_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    subw(b, rd, rs1, rs2)
}

pub fn sll_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    sllw(b, rd, rs1, rs2)
}

pub fn slt_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let xs = b.sext::<W32, W64>(x);
    let y = read_w(b, rs2);
    let ys = b.sext::<W32, W64>(y);
    let c = b.cmp(Cmp::LtS, xs, ys);
    setcc(b, rd, c);
    Ok(())
}

pub fn sltu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let c = b.cmp(Cmp::LtU, x, y);
    setcc(b, rd, c);
    Ok(())
}

pub fn xor_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.xor(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn srl_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    srlw(b, rd, rs1, rs2)
}

pub fn sra_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    sraw(b, rd, rs1, rs2)
}

pub fn or_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.or(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn and_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.and(x, y);
    write_w(b, rd, s);
    Ok(())
}

// RV32 M（乗除算）。下位 32 ビットの積と剰余は W 版と同じである。

pub fn mul_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    mulw(b, rd, rs1, rs2)
}

pub fn mulh_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.mulh(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn mulhsu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.mulhsu(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn mulhu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    let x = read_w(b, rs1);
    let y = read_w(b, rs2);
    let s = b.mulhu(x, y);
    write_w(b, rd, s);
    Ok(())
}

pub fn div_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    divw(b, rd, rs1, rs2)
}

pub fn divu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    divuw(b, rd, rs1, rs2)
}

pub fn rem_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    remw(b, rd, rs1, rs2)
}

pub fn remu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr) -> Flow<B> {
    remuw(b, rd, rs1, rs2)
}

// CSR（Zicsr）。権限と読み書き属性を検査する。
// Ref: SPEC-RISCV-PRIV (20250508) §CSR address mapping conventions.

/// CSR 番号（12 ビット）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Csr(pub u16);

/// 現在の特権レベルの CPU 状態での位置。
fn priv_ref() -> StateRef<W64> {
    StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, priv_level))
}

/// 不正命令の退出。mcause の値は 2（illegal instruction）である。
fn illegal_insn<B: Backend>(b: &mut B, pc: u64) -> B::Exit {
    b.raise(GuestException {
        kind: polyisa_sem::ExceptionKind::Undefined,
        code: 2,
        addr: Some(pc),
        in_delay_slot: false,
    })
}

/// ユーザーモードで使える CSR。fflags/frm/fcsr とカウンタのみである。
fn is_user_csr(n: u16) -> bool {
    matches!(n, 0x001 | 0x002 | 0x003 | 0xC00 | 0xC01 | 0xC02)
}

/// CSR アクセスの権限検査。状態を書く前に呼ぶ。
fn check_csr<B: Backend>(b: &mut B, csr: Csr, will_write: bool, pc: u64) -> Flow<B> {
    // csr[9:8] が要求する最低特権レベル、csr[11:10]==0b11 が読み出し専用である。
    let need = ((csr.0 >> 8) & 3) as u64;
    if will_write && (csr.0 >> 10) & 3 == 3 {
        return Err(illegal_insn(b, pc));
    }
    let cur: B::V<W64> = b.get(priv_ref());
    let need_v = b.konst::<W64>(need);
    let low = b.cmp(Cmp::LtU, cur, need_v);
    b.if_then(low, |b| Err(illegal_insn(b, pc)))?;
    // U モードでは未定義の U 権限 CSR も不正命令にする。
    // M モードの裸ハーネスは全 CSR を許す。
    if !is_user_csr(csr.0) {
        let u_mode = b.konst::<W64>(0);
        let is_u = b.cmp(Cmp::Eq, cur, u_mode);
        b.if_then(is_u, |b| Err(illegal_insn(b, pc)))?;
    }
    Ok(())
}

fn csr_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, csr), 8)
}

/// fcsr（0x003）の下位 8 ビットが正本であり、frm（0x002）は
/// その [7:5]、fflags（0x001）は [4:0] の別名である。
/// 上位の予約ビットへの書き込みは捨てる。
fn read_csr<B: Backend>(b: &mut B, csr: Csr) -> B::V<W64> {
    let three = b.konst::<W32>(3);
    let fcsr: B::V<W64> = b.get_indexed(csr_array(), three);
    match csr.0 {
        0x001 => {
            let m = b.konst::<W64>(0x1F);
            b.and(fcsr, m)
        }
        0x002 => {
            let n = b.konst::<W64>(5);
            let s = b.shr_l(fcsr, n);
            let m = b.konst::<W64>(7);
            b.and(s, m)
        }
        0x003 => {
            let m = b.konst::<W64>(0xFF);
            b.and(fcsr, m)
        }
        _ => {
            let i = b.konst::<W32>(u32::from(csr.0));
            b.get_indexed(csr_array(), i)
        }
    }
}

fn write_csr<B: Backend>(b: &mut B, csr: Csr, v: B::V<W64>) {
    let three = b.konst::<W32>(3);
    let master: B::V<W64> = b.get_indexed(csr_array(), three);
    let e0 = b.konst::<W64>(0xE0);
    let m1f = b.konst::<W64>(0x1F);
    let m7 = b.konst::<W64>(7);
    let n5 = b.konst::<W64>(5);
    let w = match csr.0 {
        0x001 => {
            let a = b.and(master, e0);
            let lo = b.and(v, m1f);
            b.or(a, lo)
        }
        0x002 => {
            let a = b.and(master, m1f);
            let f = b.and(v, m7);
            let s = b.shl(f, n5);
            b.or(a, s)
        }
        0x003 => {
            let m = b.konst::<W64>(0xFF);
            b.and(v, m)
        }
        _ => v,
    };
    let i = b.konst::<W32>(match csr.0 {
        0x001..=0x003 => 3,
        n => u32::from(n),
    });
    b.set_indexed(csr_array(), i, w);
}

/// 蓄積したFP例外フラグをfcsr/fflagsに積む。signalingなFP演算の直後に呼ぶ。
fn accrue_fp<B: Backend>(b: &mut B) {
    let f = b.fp_flags();
    if f == 0 {
        return;
    }
    let cur = read_csr(b, Csr(0x003));
    let bits = b.konst::<W64>(u64::from(f));
    let nxt = b.or(cur, bits);
    write_csr(b, Csr(0x003), nxt);
}

pub fn csrrw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, csr: Csr, pc: u64) -> Flow<B> {
    check_csr(b, csr, true, pc)?;
    let t = read_csr(b, csr);
    let x = read(b, rs1);
    write_csr(b, csr, x);
    write(b, rd, t);
    Ok(())
}

pub fn csrrs<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, csr: Csr, pc: u64) -> Flow<B> {
    check_csr(b, csr, !rs1.is_zero(), pc)?;
    let t = read_csr(b, csr);
    if !rs1.is_zero() {
        let x = read(b, rs1);
        let s = b.or(t, x);
        write_csr(b, csr, s);
    }
    write(b, rd, t);
    Ok(())
}

pub fn csrrc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, csr: Csr, pc: u64) -> Flow<B> {
    check_csr(b, csr, !rs1.is_zero(), pc)?;
    let t = read_csr(b, csr);
    if !rs1.is_zero() {
        let x = read(b, rs1);
        let n = b.not(x);
        let s = b.and(t, n);
        write_csr(b, csr, s);
    }
    write(b, rd, t);
    Ok(())
}

pub fn csrrwi<B: Backend>(b: &mut B, rd: Gpr, uimm: u64, csr: Csr, pc: u64) -> Flow<B> {
    check_csr(b, csr, true, pc)?;
    let t = read_csr(b, csr);
    let x = b.konst::<W64>(uimm & 31);
    write_csr(b, csr, x);
    write(b, rd, t);
    Ok(())
}

pub fn csrrsi<B: Backend>(b: &mut B, rd: Gpr, uimm: u64, csr: Csr, pc: u64) -> Flow<B> {
    check_csr(b, csr, uimm & 31 != 0, pc)?;
    let t = read_csr(b, csr);
    if uimm & 31 != 0 {
        let x = b.konst::<W64>(uimm & 31);
        let s = b.or(t, x);
        write_csr(b, csr, s);
    }
    write(b, rd, t);
    Ok(())
}

pub fn csrrci<B: Backend>(b: &mut B, rd: Gpr, uimm: u64, csr: Csr, pc: u64) -> Flow<B> {
    check_csr(b, csr, uimm & 31 != 0, pc)?;
    let t = read_csr(b, csr);
    if uimm & 31 != 0 {
        let x = b.konst::<W64>(uimm & 31);
        let n = b.not(x);
        let s = b.and(t, n);
        write_csr(b, csr, s);
    }
    write(b, rd, t);
    Ok(())
}

// A（不可分操作）。aq/rl ビットは順序保証の不要な段階では無視する。

pub fn lr_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 4, LR_ACC)?;
    let v: B::V<W32> = b.load_reserved(addr, LR_ACC)?;
    write_w(b, rd, v);
    Ok(())
}

pub fn lr_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 8, LR_ACC)?;
    let v: B::V<W64> = b.load_reserved(addr, LR_ACC)?;
    write(b, rd, v);
    Ok(())
}

/// SC。成功で 0、失敗で 0 以外を書く。
pub fn sc_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W32>(raw);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 4, SC_ACC)?;
    let ok = b.store_conditional(addr, v, SC_ACC)?;
    let zero = const_w64(b, 0);
    let one = const_w64(b, 1);
    let s = b.select(ok, zero, one);
    write(b, rd, s);
    Ok(())
}

pub fn sc_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let v = read(b, rs2);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 8, SC_ACC)?;
    let ok = b.store_conditional(addr, v, SC_ACC)?;
    let zero = const_w64(b, 0);
    let one = const_w64(b, 1);
    let s = b.select(ok, zero, one);
    write(b, rd, s);
    Ok(())
}

fn amo_w<B: Backend, F>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64, f: F) -> Flow<B>
where
    F: FnOnce(&mut B, B::V<W32>, B::V<W32>) -> B::V<W32>,
{
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 4, AMO_ACC)?;
    let cur: B::V<W32> = b.load(addr, AMO_ACC)?;
    let raw = read(b, rs2);
    let y = b.trunc::<W64, W32>(raw);
    let nxt = f(b, cur, y);
    // 意味論の側で読み書きを分けても、単一ホストスレッドでは不可分になる。
    b.store(addr, nxt, AMO_ACC)?;
    write_w(b, rd, cur);
    Ok(())
}

fn amo_d<B: Backend, F>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64, f: F) -> Flow<B>
where
    F: FnOnce(&mut B, B::V<W64>, B::V<W64>) -> B::V<W64>,
{
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 8, AMO_ACC)?;
    let cur: B::V<W64> = b.load(addr, AMO_ACC)?;
    let y = read(b, rs2);
    let nxt = f(b, cur, y);
    b.store(addr, nxt, AMO_ACC)?;
    write(b, rd, cur);
    Ok(())
}

fn amo_b<B: Backend, F>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64, f: F) -> Flow<B>
where
    F: FnOnce(&mut B, B::V<W8>, B::V<W8>) -> B::V<W8>,
{
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 1, AMO_ACC)?;
    let cur: B::V<W8> = b.load(addr, AMO_ACC)?;
    let raw = read(b, rs2);
    let y = b.trunc::<W64, W8>(raw);
    let nxt = f(b, cur, y);
    b.store(addr, nxt, AMO_ACC)?;
    let old = b.sext::<W8, W64>(cur);
    write(b, rd, old);
    Ok(())
}

fn amo_h<B: Backend, F>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64, f: F) -> Flow<B>
where
    F: FnOnce(&mut B, B::V<W16>, B::V<W16>) -> B::V<W16>,
{
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 2, AMO_ACC)?;
    let cur: B::V<W16> = b.load(addr, AMO_ACC)?;
    let raw = read(b, rs2);
    let y = b.trunc::<W64, W16>(raw);
    let nxt = f(b, cur, y);
    b.store(addr, nxt, AMO_ACC)?;
    let old = b.sext::<W16, W64>(cur);
    write(b, rd, old);
    Ok(())
}

fn amo_b_rv32<B: Backend, F>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64, f: F) -> Flow<B>
where
    F: FnOnce(&mut B, B::V<W8>, B::V<W8>) -> B::V<W8>,
{
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 1, AMO_ACC)?;
    let cur: B::V<W8> = b.load(addr, AMO_ACC)?;
    let raw = read(b, rs2);
    let y = b.trunc::<W64, W8>(raw);
    let nxt = f(b, cur, y);
    b.store(addr, nxt, AMO_ACC)?;
    let cur32 = b.sext::<W8, W32>(cur);
    write_w(b, rd, cur32);
    Ok(())
}

fn amo_h_rv32<B: Backend, F>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64, f: F) -> Flow<B>
where
    F: FnOnce(&mut B, B::V<W16>, B::V<W16>) -> B::V<W16>,
{
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 2, AMO_ACC)?;
    let cur: B::V<W16> = b.load(addr, AMO_ACC)?;
    let raw = read(b, rs2);
    let y = b.trunc::<W64, W16>(raw);
    let nxt = f(b, cur, y);
    b.store(addr, nxt, AMO_ACC)?;
    let cur32 = b.sext::<W16, W32>(cur);
    write_w(b, rd, cur32);
    Ok(())
}

macro_rules! amocas_small {
    ($name:ident, $rv32:ident, $w:ident, $len:expr) => {
        pub fn $name<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
            let addr = load_addr(b, rs1, oimm);
            b.probe(addr, $len, AMO_ACC)?;
            let cmp64 = read(b, rd);
            let cmp = b.trunc::<W64, $w>(cmp64);
            let new64 = read(b, rs2);
            let new = b.trunc::<W64, $w>(new64);
            let old = b.cmpxchg(addr, cmp, new, AMO_ACC)?;
            let out = b.sext::<$w, W64>(old);
            write(b, rd, out);
            Ok(())
        }
        pub fn $rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
            let addr = load_addr_rv32(b, rs1, oimm);
            b.probe(addr, $len, AMO_ACC)?;
            let cmp64 = read(b, rd);
            let cmp = b.trunc::<W64, $w>(cmp64);
            let new64 = read(b, rs2);
            let new = b.trunc::<W64, $w>(new64);
            let old = b.cmpxchg(addr, cmp, new, AMO_ACC)?;
            let out = b.sext::<$w, W32>(old);
            write_w(b, rd, out);
            Ok(())
        }
    };
}

amocas_small!(amocas_b, amocas_b_rv32, W8, 1);
amocas_small!(amocas_h, amocas_h_rv32, W16, 2);
amocas_small!(amocas_w, amocas_w_rv32, W32, 4);
amocas_small!(amocas_d, amocas_d_rv32, W64, 8);

fn pair_reg(r: Gpr) -> (Gpr, Gpr) {
    (r, Gpr(r.0.wrapping_add(1) & 31))
}

fn read_pair<B: Backend>(b: &mut B, r: Gpr) -> (B::V<W64>, B::V<W64>) {
    if r.is_zero() {
        (const_w64(b, 0), const_w64(b, 0))
    } else {
        let (lo, hi) = pair_reg(r);
        (read(b, lo), read(b, hi))
    }
}

fn write_pair<B: Backend>(b: &mut B, r: Gpr, lo: B::V<W64>, hi: B::V<W64>) {
    if !r.is_zero() {
        let (rlo, rhi) = pair_reg(r);
        write(b, rlo, lo);
        write(b, rhi, hi);
    }
}

/// AMOCAS.Q（RV64）。単一ホストスレッドでは二つの 64 ビットアクセスでも不可分性は変わらない。
pub fn amocas_q<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 16, AMO_ACC)?;
    let old_lo: B::V<W64> = b.load(addr, AMO_ACC)?;
    let off = const_w64(b, 8);
    let hi_addr = b.add(addr, off);
    let old_hi: B::V<W64> = b.load(hi_addr, AMO_ACC)?;
    let (cmp_lo, cmp_hi) = read_pair(b, rd);
    let (new_lo, new_hi) = read_pair(b, rs2);
    let eq_lo = b.cmp(Cmp::Eq, old_lo, cmp_lo);
    b.if_then(eq_lo, |b| {
        let eq_hi = b.cmp(Cmp::Eq, old_hi, cmp_hi);
        b.if_then(eq_hi, |b| {
            b.store(addr, new_lo, AMO_ACC)?;
            b.store(hi_addr, new_hi, AMO_ACC)?;
            Ok(())
        })
    })?;
    write_pair(b, rd, old_lo, old_hi);
    Ok(())
}

macro_rules! amo_bh {
    ($bname:ident, $hname:ident, $b32:ident, $h32:ident, $op:expr) => {
        pub fn $bname<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
            amo_b(b, rd, rs1, rs2, oimm, $op)
        }
        pub fn $hname<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
            amo_h(b, rd, rs1, rs2, oimm, $op)
        }
        pub fn $b32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
            amo_b_rv32(b, rd, rs1, rs2, oimm, $op)
        }
        pub fn $h32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
            amo_h_rv32(b, rd, rs1, rs2, oimm, $op)
        }
    };
}

amo_bh!(
    amoswap_b,
    amoswap_h,
    amoswap_b_rv32,
    amoswap_h_rv32,
    |_, _, y| y
);
amo_bh!(
    amoadd_b,
    amoadd_h,
    amoadd_b_rv32,
    amoadd_h_rv32,
    |b, a, y| b.add(a, y)
);
amo_bh!(
    amoxor_b,
    amoxor_h,
    amoxor_b_rv32,
    amoxor_h_rv32,
    |b, a, y| b.xor(a, y)
);
amo_bh!(
    amoand_b,
    amoand_h,
    amoand_b_rv32,
    amoand_h_rv32,
    |b, a, y| b.and(a, y)
);
amo_bh!(amoor_b, amoor_h, amoor_b_rv32, amoor_h_rv32, |b, a, y| b
    .or(a, y));
amo_bh!(
    amomin_b,
    amomin_h,
    amomin_b_rv32,
    amomin_h_rv32,
    |b, a, y| {
        let c = b.cmp(Cmp::LtS, a, y);
        b.select(c, a, y)
    }
);
amo_bh!(
    amomax_b,
    amomax_h,
    amomax_b_rv32,
    amomax_h_rv32,
    |b, a, y| {
        let c = b.cmp(Cmp::LtS, a, y);
        b.select(c, y, a)
    }
);
amo_bh!(
    amominu_b,
    amominu_h,
    amominu_b_rv32,
    amominu_h_rv32,
    |b, a, y| {
        let c = b.cmp(Cmp::LtU, a, y);
        b.select(c, a, y)
    }
);
amo_bh!(
    amomaxu_b,
    amomaxu_h,
    amomaxu_b_rv32,
    amomaxu_h_rv32,
    |b, a, y| {
        let c = b.cmp(Cmp::LtU, a, y);
        b.select(c, y, a)
    }
);

// A（RV32）。W 接尾辞の演算は 32 ビットで同一だが、アドレスは 32 ビットで包む。

/// LR.W（RV32）。
pub fn lr_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 4, LR_ACC)?;
    let v: B::V<W32> = b.load_reserved(addr, LR_ACC)?;
    write_w(b, rd, v);
    Ok(())
}

/// SC.W（RV32）。成功で 0、失敗で 0 以外を書く。
pub fn sc_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W32>(raw);
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 4, SC_ACC)?;
    let ok = b.store_conditional(addr, v, SC_ACC)?;
    let zero = const_w64(b, 0);
    let one = const_w64(b, 1);
    let s = b.select(ok, zero, one);
    write(b, rd, s);
    Ok(())
}

fn amo_w_rv32<B: Backend, F>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64, f: F) -> Flow<B>
where
    F: FnOnce(&mut B, B::V<W32>, B::V<W32>) -> B::V<W32>,
{
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 4, AMO_ACC)?;
    let cur: B::V<W32> = b.load(addr, AMO_ACC)?;
    let raw = read(b, rs2);
    let y = b.trunc::<W64, W32>(raw);
    let nxt = f(b, cur, y);
    b.store(addr, nxt, AMO_ACC)?;
    write_w(b, rd, cur);
    Ok(())
}

/// AMOSWAP.W（RV32）。
pub fn amoswap_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, |_, _, y| y)
}

/// AMOADD.W（RV32）。
pub fn amoadd_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, |b, a, y| b.add(a, y))
}

/// AMOXOR.W（RV32）。
pub fn amoxor_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, |b, a, y| b.xor(a, y))
}

/// AMOAND.W（RV32）。
pub fn amoand_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, |b, a, y| b.and(a, y))
}

/// AMOOR.W（RV32）。
pub fn amoor_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, |b, a, y| b.or(a, y))
}

/// AMOMIN.W（RV32）。
pub fn amomin_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, min_s)
}

/// AMOMAX.W（RV32）。
pub fn amomax_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, max_s)
}

/// AMOMINU.W（RV32）。
pub fn amominu_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, min_u)
}

/// AMOMAXU.W（RV32）。
pub fn amomaxu_w_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w_rv32(b, rd, rs1, rs2, oimm, max_u)
}

fn min_s<B: Backend>(b: &mut B, a: B::V<W32>, y: B::V<W32>) -> B::V<W32> {
    let c = b.cmp(Cmp::LtS, a, y);
    b.select(c, a, y)
}

fn max_s<B: Backend>(b: &mut B, a: B::V<W32>, y: B::V<W32>) -> B::V<W32> {
    let c = b.cmp(Cmp::LtS, a, y);
    b.select(c, y, a)
}

fn min_u<B: Backend>(b: &mut B, a: B::V<W32>, y: B::V<W32>) -> B::V<W32> {
    let c = b.cmp(Cmp::LtU, a, y);
    b.select(c, a, y)
}

fn max_u<B: Backend>(b: &mut B, a: B::V<W32>, y: B::V<W32>) -> B::V<W32> {
    let c = b.cmp(Cmp::LtU, a, y);
    b.select(c, y, a)
}

fn min_s64<B: Backend>(b: &mut B, a: B::V<W64>, y: B::V<W64>) -> B::V<W64> {
    let c = b.cmp(Cmp::LtS, a, y);
    b.select(c, a, y)
}

fn max_s64<B: Backend>(b: &mut B, a: B::V<W64>, y: B::V<W64>) -> B::V<W64> {
    let c = b.cmp(Cmp::LtS, a, y);
    b.select(c, y, a)
}

fn min_u64<B: Backend>(b: &mut B, a: B::V<W64>, y: B::V<W64>) -> B::V<W64> {
    let c = b.cmp(Cmp::LtU, a, y);
    b.select(c, a, y)
}

fn max_u64<B: Backend>(b: &mut B, a: B::V<W64>, y: B::V<W64>) -> B::V<W64> {
    let c = b.cmp(Cmp::LtU, a, y);
    b.select(c, y, a)
}

pub fn amoswap_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, |_, _, y| y)
}

pub fn amoadd_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, |b, a, y| b.add(a, y))
}

pub fn amoxor_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, |b, a, y| b.xor(a, y))
}

pub fn amoand_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, |b, a, y| b.and(a, y))
}

pub fn amoor_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, |b, a, y| b.or(a, y))
}

pub fn amomin_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, min_s)
}

pub fn amomax_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, max_s)
}

pub fn amominu_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, min_u)
}

pub fn amomaxu_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_w(b, rd, rs1, rs2, oimm, max_u)
}

pub fn amoswap_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, |_, _, y| y)
}

pub fn amoadd_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, |b, a, y| b.add(a, y))
}

pub fn amoxor_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, |b, a, y| b.xor(a, y))
}

pub fn amoand_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, |b, a, y| b.and(a, y))
}

pub fn amoor_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, |b, a, y| b.or(a, y))
}

pub fn amomin_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, min_s64)
}

pub fn amomax_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, max_s64)
}

pub fn amominu_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, min_u64)
}

pub fn amomaxu_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    amo_d(b, rd, rs1, rs2, oimm, max_u64)
}

// SYSTEM

/// 浮動小数点レジスタ番号。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fpr(pub u8);

impl Fpr {
    /// CPU 状態の対応する要素を指す。値は u64 の NaN ボックス形で持つ。
    pub fn state(self) -> StateRef<W64> {
        StateRef::<W64>::from_offset(core::mem::offset_of!(CpuState, f) + usize::from(self.0) * 8)
    }
}

fn read_f<B: Backend>(b: &mut B, r: Fpr) -> B::V<F32> {
    // 転送系（FSW/FMV.X.W）は素通し。下位32ビットを無視せず転送する。
    let w: B::V<W64> = b.get(r.state());
    b.trunc::<W64, F32>(w)
}

/// NaNボックス検査付き読み出し。転送以外の単精度演算で使う。
/// 上位32ビットが全1でなければ正準NaNを返す（SPEC-RISCV-UNPRIV D章）。
fn read_f_checked<B: Backend>(b: &mut B, r: Fpr) -> B::V<F32> {
    let w: B::V<W64> = b.get(r.state());
    let low = b.trunc::<W64, F32>(w);
    let shift = b.konst::<W64>(32);
    let hi64 = b.shr_l(w, shift);
    let hi = b.trunc::<W64, W32>(hi64);
    let all1 = b.konst::<W32>(0xffff_ffff);
    let boxed = b.cmp(Cmp::Eq, hi, all1);
    let canon = b.konst::<F32>(0x7fc0_0000);
    b.select(boxed, low, canon)
}

/// 単精度の値を NaN ボックスして書く。
fn write_f<B: Backend>(b: &mut B, rd: Fpr, v: B::V<F32>) {
    let w = b.zext::<F32, W64>(v);
    let top = b.konst::<W64>(0xffff_ffff_0000_0000);
    let boxed = b.or(w, top);
    b.set(rd.state(), boxed);
}

/// FENCE。裸実行と順序保証の不要な段階では何もしない。
pub fn fence<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

/// FENCE.I。同上。
pub fn fence_i<B: Backend>(_b: &mut B) -> Flow<B> {
    Ok(())
}

fn env_exit<B: Backend>(b: &mut B, kind: polyisa_sem::ExceptionKind, pc: u64) -> Flow<B> {
    let e = GuestException {
        kind,
        code: 0,
        addr: Some(pc),
        in_delay_slot: false,
    };
    Err(b.raise(e))
}

/// ECALL。OS パーソナリティが処理する退出を返す。
pub fn ecall<B: Backend>(b: &mut B, pc: u64) -> Flow<B> {
    env_exit(b, polyisa_sem::ExceptionKind::Trap, pc)
}

/// EBREAK。デバッガが処理する退出を返す。
pub fn ebreak<B: Backend>(b: &mut B, pc: u64) -> Flow<B> {
    env_exit(b, polyisa_sem::ExceptionKind::Break, pc)
}

fn bool01<B: Backend>(b: &mut B, c: B::B) -> B::V<W32> {
    let one = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    b.select(c, one, zero)
}

fn bool_and<B: Backend>(b: &mut B, x: B::B, y: B::B) -> B::B {
    let xv = bool01(b, x);
    let yv = bool01(b, y);
    let both = b.and(xv, yv);
    let zero = b.konst::<W32>(0);
    b.cmp(Cmp::Ne, both, zero)
}

fn read_bf16_checked<B: Backend>(b: &mut B, r: Fpr) -> B::V<F16> {
    let w: B::V<W64> = b.get(r.state());
    let low = b.trunc::<W64, F16>(w);
    let shift = b.konst::<W64>(16);
    let hi64 = b.shr_l(w, shift);
    let hi = b.trunc::<W64, W64>(hi64);
    let all1 = b.konst::<W64>(0xffff_ffff_ffff);
    let boxed = b.cmp(Cmp::Eq, hi, all1);
    let canon = b.konst::<F16>(0x7fc0);
    b.select(boxed, low, canon)
}

// Zfbfmin の形式変換。BF16 も F16 と同じ 16 ビット容器で保持する。

fn bf16_from_f32_bits<B: Backend>(
    b: &mut B,
    bits: B::V<W32>,
    rm: u8,
) -> Result<B::V<F16>, B::Exit> {
    let one32 = b.konst::<W32>(1);
    let zero = b.konst::<W32>(0);
    let sign_shift = b.konst::<W32>(31);
    let sign0 = b.shr_l(bits, sign_shift);
    let sign = b.and(sign0, one32);
    let exp_shift = b.konst::<W32>(23);
    let exp0 = b.shr_l(bits, exp_shift);
    let ff32 = b.konst::<W32>(0xff);
    let exp = b.and(exp0, ff32);
    let frac_mask = b.konst::<W32>(0x7f_ffff);
    let frac = b.and(bits, frac_mask);
    let exp255 = b.konst::<W32>(0xff);
    let is255 = b.cmp(Cmp::Eq, exp, exp255);
    let nonzero_frac = b.cmp(Cmp::Ne, frac, zero);
    let frac_nonzero_val = b.select(nonzero_frac, one32, zero);
    let nan_val = b.select(is255, frac_nonzero_val, zero);
    let is_nan = b.cmp(Cmp::Ne, nan_val, zero);
    // NaN は BF16 の正準 NaN にする。
    let canon = b.konst::<W32>(0x7fc0);

    let sign16_shift = b.konst::<W32>(15);
    let sign16 = b.shl(sign, sign16_shift);
    let exp16_shift = b.konst::<W32>(7);
    let mant_shift = b.konst::<W32>(16);
    let mant = b.shr_l(frac, mant_shift);
    let guard_shift = b.konst::<W32>(15);
    let guard0 = b.shr_l(frac, guard_shift);
    let guard = b.and(guard0, one32);
    let sticky_mask = b.konst::<W32>(0x7fff);
    let sticky_bits = b.and(frac, sticky_mask);
    let low16_mask = b.konst::<W32>(0xffff);
    let low16 = b.and(frac, low16_mask);
    let any_nz = b.cmp(Cmp::Ne, low16, zero);
    let lsb = b.and(mant, one32);
    let guard_nz = b.cmp(Cmp::Ne, guard, zero);
    let sign_nz = b.cmp(Cmp::Ne, sign, zero);
    let not_sign = b.cmp(Cmp::Eq, sign, zero);

    // rm は実行時レジスタではなく意味論引数なので、ここでは制御を
    // 分けて真理値演算の合成を避ける。
    let inc = match rm {
        // RTZ
        1 => zero,
        // RDN: 負で捨てる桁があれば繰り上げる。
        2 => {
            let v = b.select(any_nz, one32, zero);
            b.select(sign_nz, v, zero)
        }
        // RUP: 正で捨てる桁があれば繰り上げる。
        3 => {
            let v = b.select(any_nz, one32, zero);
            b.select(not_sign, v, zero)
        }
        // RMM: guard が立っていれば繰り上げる。
        4 => b.select(guard_nz, one32, zero),
        // RNE: guard があり、sticky または奇数 LSB があれば繰り上げる。
        _ => {
            let rest_bits = b.or(sticky_bits, lsb);
            let rest_nz = b.cmp(Cmp::Ne, rest_bits, zero);
            let rest = b.select(rest_nz, one32, zero);
            b.select(guard_nz, rest, zero)
        }
    };
    let mant_rounded0 = b.add(mant, inc);
    let mant_mask = b.konst::<W32>(0x7f);
    let carry_shift = b.konst::<W32>(7);
    let carry = b.shr_l(mant_rounded0, carry_shift);
    let mant_rounded = b.and(mant_rounded0, mant_mask);
    let exp_rounded = b.add(exp, carry);
    let exp_out = b.shl(exp_rounded, exp16_shift);
    let finite0 = b.or(sign16, exp_out);
    let finite = b.or(finite0, mant_rounded);
    // 入力 Inf または丸めで指数が 0xff へ達したら Inf。
    let exp_inf = b.cmp(Cmp::Eq, exp_rounded, exp255);
    let inf_bits = b.konst::<W32>(0x7f80);
    let inf0 = b.or(sign16, inf_bits);
    let finite_or_inf = b.select(exp_inf, inf0, finite);
    let out = b.select(is_nan, canon, finite_or_inf);

    // sNaN は NV。有限入力で桁落ちがあれば NX。非正規化結果では UF、
    // 無限大へのあふれでは OF も立つ。NaN 入力には NX/UF/OF を立てない。
    let qbit_shift = b.konst::<W32>(22);
    let qbit0 = b.shr_l(frac, qbit_shift);
    let qbit = b.and(qbit0, one32);
    let qzero = b.cmp(Cmp::Eq, qbit, zero);
    let is_snan = bool_and(b, is_nan, qzero);
    b.if_then(is_snan, |b| {
        b.fp_accrue(0x10);
        Ok(())
    })?;

    let input_finite = b.cmp(Cmp::LtU, exp, exp255);
    let finite_inexact = bool_and(b, input_finite, any_nz);
    b.if_then(finite_inexact, |b| {
        b.fp_accrue(0x01);
        Ok(())
    })?;
    let exp0_out = b.cmp(Cmp::Eq, exp_rounded, zero);
    let underflow = bool_and(b, finite_inexact, exp0_out);
    b.if_then(underflow, |b| {
        b.fp_accrue(0x02);
        Ok(())
    })?;
    let overflow0 = bool_and(b, input_finite, exp_inf);
    let overflow = bool_and(b, overflow0, finite_inexact);
    b.if_then(overflow, |b| {
        b.fp_accrue(0x04);
        Ok(())
    })?;
    Ok(b.trunc::<W32, F16>(out))
}

pub fn fcvt_s_bf16<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, _rm: u8) -> Flow<B> {
    // BF16 と単精度は指数幅が同じで、BF16 は上位 16 ビットだけを持つ。
    // 拡張は下位 16 ビットを 0 で埋める。NaN は正準 NaN にし、
    // SNaN では NV を立てる。
    let x = read_bf16_checked(b, rs1);
    let w16 = b.trunc::<F16, W16>(x);
    let w32raw = b.zext::<W16, W32>(w16);
    let exp_shift = b.konst::<W32>(7);
    let exp0 = b.shr_l(w32raw, exp_shift);
    let ff32 = b.konst::<W32>(0xff);
    let exp = b.and(exp0, ff32);
    let frac_mask = b.konst::<W32>(0x7f);
    let frac = b.and(w32raw, frac_mask);
    let exp255 = b.konst::<W32>(0xff);
    let zero = b.konst::<W32>(0);
    let is255 = b.cmp(Cmp::Eq, exp, exp255);
    let nonzero_frac = b.cmp(Cmp::Ne, frac, zero);
    let is_nan = bool_and(b, is255, nonzero_frac);
    let qbit = b.konst::<W32>(0x40);
    let qbits = b.and(frac, qbit);
    let qzero = b.cmp(Cmp::Eq, qbits, zero);
    let is_snan = bool_and(b, is_nan, qzero);
    let canon = b.konst::<W32>(0x7fc0);
    let out16 = b.select(is_nan, canon, w32raw);
    b.if_then(is_snan, |b| {
        b.fp_accrue(0x10);
        Ok(())
    })?;
    let sh = b.konst::<W32>(16);
    let bits = b.shl(out16, sh);
    let f = b.trunc::<W32, F32>(bits);
    write_f(b, rd, f);
    accrue_fp(b);
    Ok(())
}

pub fn fcvt_bf16_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let bits = b.trunc::<F32, W32>(x);
    let out = bf16_from_f32_bits(b, bits, rm)?;
    write_h(b, rd, out);
    accrue_fp(b);
    Ok(())
}

// Zfhmin。半精度は 64 ビットレジスタへ NaN ボックスして保持する。

fn read_h<B: Backend>(b: &mut B, r: Fpr) -> B::V<F16> {
    let w: B::V<W64> = b.get(r.state());
    b.trunc::<W64, F16>(w)
}

fn read_h_checked<B: Backend>(b: &mut B, r: Fpr) -> B::V<F16> {
    let w: B::V<W64> = b.get(r.state());
    let low = b.trunc::<W64, F16>(w);
    let shift = b.konst::<W64>(16);
    let hi64 = b.shr_l(w, shift);
    let hi = b.trunc::<W64, W64>(hi64);
    let all1 = b.konst::<W64>(0xffff_ffff_ffff);
    let boxed = b.cmp(Cmp::Eq, hi, all1);
    let canon = b.konst::<F16>(0x7e00);
    b.select(boxed, low, canon)
}

fn write_h<B: Backend>(b: &mut B, rd: Fpr, v: B::V<F16>) {
    let w = b.zext::<F16, W64>(v);
    let top = b.konst::<W64>(0xffff_ffff_ffff_0000);
    let boxed = b.or(w, top);
    b.set(rd.state(), boxed);
}

pub fn flh<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W16> = b.load(addr, DATA_READ)?;
    let h = b.trunc::<W16, F16>(v);
    write_h(b, rd, h);
    Ok(())
}

pub fn fsh<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    let v = read_h(b, rs2);
    let w = b.trunc::<F16, W16>(v);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 2, DATA_WRITE)?;
    b.store(addr, w, DATA_WRITE)?;
    Ok(())
}

pub fn fmv_x_h<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_h(b, rs1);
    let w = b.sext::<F16, W64>(x);
    write(b, rd, w);
    Ok(())
}

pub fn fmv_h_x<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, F16>(raw);
    write_h(b, rd, x);
    Ok(())
}

pub fn fcvt_s_h<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_h_checked(b, rs1);
    let s = b.fcvt_ff::<F16, F32>(x, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

pub fn fcvt_h_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let s = b.fcvt_ff::<F32, F16>(x, rm);
    write_h(b, rd, s);
    accrue_fp(b);
    Ok(())
}

pub fn fcvt_d_h<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_h_checked(b, rs1);
    let s = b.fcvt_ff::<F16, F64>(x, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

pub fn fcvt_h_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let s = b.fcvt_ff::<F64, F16>(x, rm);
    write_h(b, rd, s);
    accrue_fp(b);
    Ok(())
}

// F（単精度浮動小数点）。丸めモードは引数 rm で受ける（rm=7/DYN は
// 呼び出し側が frm CSR で解決する）。RNE 固定の記述は残さない。

/// FLW。
pub fn flw<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W32> = b.load(addr, DATA_READ)?;
    let w = b.trunc::<W32, F32>(v);
    write_f(b, rd, w);
    Ok(())
}

/// FSW。
pub fn fsw<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    let v = read_f(b, rs2);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 4, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

/// FADD.S。
pub fn fadd_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let s = b.fadd_r(x, y, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FSUB.S。
pub fn fsub_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let s = b.fsub_r(x, y, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMUL.S。
pub fn fmul_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let s = b.fmul_r(x, y, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FDIV.S。
pub fn fdiv_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let s = b.fdiv_r(x, y, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FSQRT.S。
pub fn fsqrt_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let s = b.fsqrt_r(x, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FSGNJ.S。
pub fn fsgnj_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let __v = b.fsgnj(x, y);
    write_f(b, rd, __v);
    Ok(())
}

/// FSGNJN.S。
pub fn fsgnjn_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let __v = b.fsgnjn(x, y);
    write_f(b, rd, __v);
    Ok(())
}

/// FSGNJX.S。
pub fn fsgnjx_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let __v = b.fsgnjx(x, y);
    write_f(b, rd, __v);
    Ok(())
}

/// FMIN.S。
pub fn fmin_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let __v = b.fmin(x, y);
    write_f(b, rd, __v);
    accrue_fp(b);
    Ok(())
}

/// FMAX.S。
pub fn fmax_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let __v = b.fmax(x, y);
    write_f(b, rd, __v);
    accrue_fp(b);
    Ok(())
}

fn write_cmp<B: Backend>(b: &mut B, rd: Gpr, c: B::B) {
    let t = b.konst::<W64>(1);
    let f = b.konst::<W64>(0);
    let s = b.select(c, t, f);
    write(b, rd, s);
}

/// FEQ.S。
pub fn feq_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let c = b.feq(x, y);
    write_cmp(b, rd, c);
    accrue_fp(b);
    Ok(())
}

/// FLT.S。
pub fn flt_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let c = b.flt(x, y);
    write_cmp(b, rd, c);
    accrue_fp(b);
    Ok(())
}

/// FLE.S。
pub fn fle_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let c = b.fle(x, y);
    write_cmp(b, rd, c);
    accrue_fp(b);
    Ok(())
}

/// FCLASS.S。分類ビットを整数レジスタに書く。
pub fn fclass_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let v = b.fclass(x);
    let w = b.zext::<W32, W64>(v);
    write(b, rd, w);
    Ok(())
}

/// FCVT.W.S。範囲外は飽和する。
pub fn fcvt_w_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let v = b.fcvt_s32(x, rm);
    let w = b.sext::<W32, W64>(v);
    write(b, rd, w);
    accrue_fp(b);
    Ok(())
}

/// FCVT.WU.S。
pub fn fcvt_wu_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let v = b.fcvt_u32(x, rm);
    let w = b.sext::<W32, W64>(v);
    write(b, rd, w);
    accrue_fp(b);
    Ok(())
}

/// FCVT.L.S。
pub fn fcvt_l_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let s = b.fcvt_s64(x, rm);
    write(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.LU.S。
pub fn fcvt_lu_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let s = b.fcvt_u64(x, rm);
    write(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.S.W。
pub fn fcvt_s_w<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_s32(x, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.S.WU。
pub fn fcvt_s_wu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_u32(x, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.S.L。
pub fn fcvt_s_l<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_s64(x, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.S.LU。
pub fn fcvt_s_lu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_u64(x, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMV.X.W。ビット列をそのまま整数レジスタに移す（符号拡張する）。
pub fn fmv_x_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let w = b.sext::<F32, W64>(x);
    write(b, rd, w);
    Ok(())
}

/// FMV.W.X。下位 32 ビットを浮動小数点レジスタに移す（NaN ボックスする）。
pub fn fmv_w_x<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, F32>(raw);
    write_f(b, rd, x);
    Ok(())
}

// D（倍精度浮動小数点）。64 ビット全体を使い、NaN ボックスは不要である。

fn read_fd<B: Backend>(b: &mut B, r: Fpr) -> B::V<F64> {
    let w: B::V<W64> = b.get(r.state());
    b.trunc::<W64, F64>(w)
}

fn write_fd<B: Backend>(b: &mut B, rd: Fpr, v: B::V<F64>) {
    let w = b.zext::<F64, W64>(v);
    b.set(rd.state(), w);
}

/// FLD。
pub fn fld<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W64> = b.load(addr, DATA_READ)?;
    let w = b.trunc::<W64, F64>(v);
    write_fd(b, rd, w);
    Ok(())
}

/// FSD。
pub fn fsd<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    let v = read_fd(b, rs2);
    let addr = load_addr(b, rs1, oimm);
    b.probe(addr, 8, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

// RV32 の浮動小数点ロードストア。アドレスは 32 ビットで包む。
// 値の扱いは XLEN によらない。

/// FLW（RV32）。
pub fn flw_rv32<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    let v: B::V<W32> = b.load(addr, DATA_READ)?;
    let w = b.trunc::<W32, F32>(v);
    write_f(b, rd, w);
    Ok(())
}

/// FSW（RV32）。
pub fn fsw_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    let v = read_f(b, rs2);
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 4, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

/// FLD（RV32）。
pub fn fld_rv32<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr_rv32(b, rs1, oimm);
    let v: B::V<W64> = b.load(addr, DATA_READ)?;
    let w = b.trunc::<W64, F64>(v);
    write_fd(b, rd, w);
    Ok(())
}

/// FSD（RV32）。
pub fn fsd_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    let v = read_fd(b, rs2);
    let addr = load_addr_rv32(b, rs1, oimm);
    b.probe(addr, 8, DATA_WRITE)?;
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

/// C.FLW（RV32）。
pub fn c_flw_rv32<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    flw_rv32(b, rd, rs1, oimm)
}

/// C.FSW（RV32）。
pub fn c_fsw_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsw_rv32(b, rs1, rs2, oimm)
}

/// C.FLWSP（RV32）。`flw rd, offset(x2)` に展開する。
pub fn c_flwsp_rv32<B: Backend>(b: &mut B, rd: Fpr, oimm: i64) -> Flow<B> {
    flw_rv32(b, rd, Gpr(2), oimm)
}

/// C.FSWSP（RV32）。`fsw rs2, offset(x2)` に展開する。
pub fn c_fswsp_rv32<B: Backend>(b: &mut B, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsw_rv32(b, Gpr(2), rs2, oimm)
}

/// FADD.D。
pub fn fadd_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fadd_r(x, y, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FSUB.D。
pub fn fsub_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fsub_r(x, y, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMUL.D。
pub fn fmul_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fmul_r(x, y, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMADD.S。積和融合（単精度、単一丸め）。
pub fn fmadd_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let z = read_f_checked(b, rs3);
    let s = b.fmadd_r(x, y, z, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMSUB.S。`rs1*rs2-rs3` の融合演算。
pub fn fmsub_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let z = read_f_checked(b, rs3);
    let nz = b.fsgnjn(z, z);
    let s = b.fmadd_r(x, y, nz, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FNMSUB.S。`-(rs1*rs2)+rs3` の融合演算。
pub fn fnmsub_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let z = read_f_checked(b, rs3);
    let nx = b.fsgnjn(x, x);
    let s = b.fmadd_r(nx, y, z, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FNMADD.S。`-(rs1*rs2)-rs3` の融合演算。
pub fn fnmadd_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let y = read_f_checked(b, rs2);
    let z = read_f_checked(b, rs3);
    let nx = b.fsgnjn(x, x);
    let nz = b.fsgnjn(z, z);
    let s = b.fmadd_r(nx, y, nz, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMADD.D。積和融合（倍精度、単一丸め）。
pub fn fmadd_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let z = read_fd(b, rs3);
    let s = b.fmadd_r(x, y, z, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMSUB.D。
pub fn fmsub_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let z = read_fd(b, rs3);
    let nz = b.fsgnjn(z, z);
    let s = b.fmadd_r(x, y, nz, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FNMSUB.D。
pub fn fnmsub_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let z = read_fd(b, rs3);
    let nx = b.fsgnjn(x, x);
    let s = b.fmadd_r(nx, y, z, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FNMADD.D。
pub fn fnmadd_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rs3: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let z = read_fd(b, rs3);
    let nx = b.fsgnjn(x, x);
    let nz = b.fsgnjn(z, z);
    let s = b.fmadd_r(nx, y, nz, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FDIV.D。
pub fn fdiv_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fdiv_r(x, y, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FSQRT.D。
pub fn fsqrt_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let __w = b.fsqrt_r(x, rm);
    write_fd(b, rd, __w);
    accrue_fp(b);
    Ok(())
}

/// FSGNJ.D。
pub fn fsgnj_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let __w = b.fsgnj(x, y);
    write_fd(b, rd, __w);
    Ok(())
}

/// FSGNJN.D。
pub fn fsgnjn_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let __w = b.fsgnjn(x, y);
    write_fd(b, rd, __w);
    Ok(())
}

/// FSGNJX.D。
pub fn fsgnjx_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let __w = b.fsgnjx(x, y);
    write_fd(b, rd, __w);
    Ok(())
}

/// FMIN.D。
pub fn fmin_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let __w = b.fmin(x, y);
    write_fd(b, rd, __w);
    accrue_fp(b);
    Ok(())
}

/// FMAX.D。
pub fn fmax_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let __w = b.fmax(x, y);
    write_fd(b, rd, __w);
    accrue_fp(b);
    Ok(())
}

/// FEQ.D。
pub fn feq_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let c = b.feq(x, y);
    write_cmp(b, rd, c);
    accrue_fp(b);
    Ok(())
}

/// FLT.D。
pub fn flt_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let c = b.flt(x, y);
    write_cmp(b, rd, c);
    accrue_fp(b);
    Ok(())
}

/// FLE.D。
pub fn fle_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let c = b.fle(x, y);
    write_cmp(b, rd, c);
    accrue_fp(b);
    Ok(())
}

/// FCLASS.D。
pub fn fclass_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let v = b.fclass(x);
    let w = b.zext::<W32, W64>(v);
    write(b, rd, w);
    Ok(())
}

/// FCVT.W.D。
pub fn fcvt_w_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let v = b.fcvt_s32(x, rm);
    let s = b.sext::<W32, W64>(v);
    write(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.WU.D。
pub fn fcvt_wu_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let v = b.fcvt_u32(x, rm);
    let z = b.sext::<W32, W64>(v);
    write(b, rd, z);
    accrue_fp(b);
    Ok(())
}

/// FCVT.L.D。
pub fn fcvt_l_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let s = b.fcvt_s64(x, rm);
    write(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.LU.D。
pub fn fcvt_lu_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let s = b.fcvt_u64(x, rm);
    write(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FMV.X.D。ビット列をそのまま整数レジスタに移す。
pub fn fmv_x_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let w = b.trunc::<F64, W64>(x);
    write(b, rd, w);
    Ok(())
}

/// FMV.D.X。64 ビットをそのまま浮動小数点レジスタに移す。
pub fn fmv_d_x<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let w = b.trunc::<W64, F64>(x);
    write_fd(b, rd, w);
    Ok(())
}

/// FCVT.D.W。
pub fn fcvt_d_w<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_s32(x, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.D.WU。
pub fn fcvt_d_wu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_u32(x, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.D.L。
pub fn fcvt_d_l<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_s64(x, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.D.LU。
pub fn fcvt_d_lu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, rm: u8) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_u64(x, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.S.D。単精度に丸める。
pub fn fcvt_s_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_fd(b, rs1);
    let s = b.fcvt_ff(x, rm);
    write_f(b, rd, s);
    accrue_fp(b);
    Ok(())
}

/// FCVT.D.S。倍精度に広げる。
pub fn fcvt_d_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rm: u8) -> Flow<B> {
    let x = read_f_checked(b, rs1);
    let s = b.fcvt_ff(x, rm);
    write_fd(b, rd, s);
    accrue_fp(b);
    Ok(())
}

// C（圧縮）。各命令は対応する32ビット命令への展開である。
// Ref: SPEC-RISCV-UNPRIV (20250508) §C.
// 即値は呼び出し側で組み立て済み（バイトオフセット）として受ける。

/// C.ADDI4SPN。`addi rd, x2, uimm` に展開する。
pub fn c_addi4spn<B: Backend>(b: &mut B, rd: Gpr, uimm: i64) -> Flow<B> {
    addi(b, rd, Gpr(2), uimm)
}

/// C.LW。
pub fn c_lw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lw(b, rd, rs1, oimm)
}

/// C.LD。
pub fn c_ld<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    ld(b, rd, rs1, oimm)
}

/// C.SW。
pub fn c_sw<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    sw(b, rs1, rs2, oimm)
}

/// C.LBU。
pub fn c_lbu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lbu(b, rd, rs1, oimm)
}

/// C.LH。
pub fn c_lh<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lh(b, rd, rs1, oimm)
}

/// C.LHU。
pub fn c_lhu<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lhu(b, rd, rs1, oimm)
}

/// C.SB。
pub fn c_sb<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    sb(b, rs1, rs2, oimm)
}

/// C.SH。
pub fn c_sh<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    sh(b, rs1, rs2, oimm)
}

/// C.SD。
pub fn c_sd<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    sd(b, rs1, rs2, oimm)
}

/// C.ADDI。`addi rd, rd, nzimm` に展開する。
pub fn c_addi<B: Backend>(b: &mut B, rd: Gpr, nzimm: i64) -> Flow<B> {
    let r = rd.0;
    addi(b, rd, Gpr(r), nzimm)
}

/// C.ADDIW。`addiw rd, rd, imm` に展開する。
pub fn c_addiw<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    let r = rd.0;
    addiw(b, rd, Gpr(r), imm)
}

/// C.LI。`addi rd, x0, imm` に展開する。
pub fn c_li<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    addi(b, rd, Gpr(0), imm)
}

/// C.J。`jal x0, offset` に展開する。rd=x0 捨てのため戻りの pc+2/pc+4
/// の違いは現れない。リンクを残す C.JAL と区別する。
pub fn c_j<B: Backend>(b: &mut B, pc: u64, offset: i64) -> Flow<B> {
    jal(b, Gpr(0), pc, offset)
}

/// C.BEQZ。`beq rs1, x0, offset` に展開する。
pub fn c_beqz<B: Backend>(b: &mut B, rs1: Gpr, pc: u64, offset: i64) -> Flow<B> {
    beq(b, rs1, Gpr(0), pc, offset)
}

/// C.BNEZ。`bne rs1, x0, offset` に展開する。
pub fn c_bnez<B: Backend>(b: &mut B, rs1: Gpr, pc: u64, offset: i64) -> Flow<B> {
    bne(b, rs1, Gpr(0), pc, offset)
}

/// C.SLLI。
pub fn c_slli<B: Backend>(b: &mut B, rd: Gpr, shamt: u64) -> Flow<B> {
    let r = rd.0;
    slli(b, rd, Gpr(r), shamt)
}

/// C.LWSP。`lw rd, offset(x2)` に展開する。
pub fn c_lwsp<B: Backend>(b: &mut B, rd: Gpr, oimm: i64) -> Flow<B> {
    lw(b, rd, Gpr(2), oimm)
}

/// C.LDSP。`ld rd, offset(x2)` に展開する。
pub fn c_ldsp<B: Backend>(b: &mut B, rd: Gpr, oimm: i64) -> Flow<B> {
    ld(b, rd, Gpr(2), oimm)
}

/// C.SWSP。`sw rs2, offset(x2)` に展開する。
pub fn c_swsp<B: Backend>(b: &mut B, rs2: Gpr, oimm: i64) -> Flow<B> {
    sw(b, Gpr(2), rs2, oimm)
}

/// C.SDSP。`sd rs2, offset(x2)` に展開する。
pub fn c_sdsp<B: Backend>(b: &mut B, rs2: Gpr, oimm: i64) -> Flow<B> {
    sd(b, Gpr(2), rs2, oimm)
}

/// C.FLD。
pub fn c_fld<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    fld(b, rd, rs1, oimm)
}

/// C.FSD。
pub fn c_fsd<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsd(b, rs1, rs2, oimm)
}

/// C.FLDSP。`fld rd, offset(x2)` に展開する。
pub fn c_fldsp<B: Backend>(b: &mut B, rd: Fpr, oimm: i64) -> Flow<B> {
    fld(b, rd, Gpr(2), oimm)
}

/// C.FSDSP。`fsd rs2, offset(x2)` に展開する。
pub fn c_fsdsp<B: Backend>(b: &mut B, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsd(b, Gpr(2), rs2, oimm)
}

/// C.FLD（RV32）。アドレスは 32 ビットで包む。
pub fn c_fld_rv32<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    fld_rv32(b, rd, rs1, oimm)
}

/// C.FSD（RV32）。アドレスは 32 ビットで包む。
pub fn c_fsd_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsd_rv32(b, rs1, rs2, oimm)
}

/// C.FLDSP（RV32）。`fld rd, offset(x2)` に展開する。
pub fn c_fldsp_rv32<B: Backend>(b: &mut B, rd: Fpr, oimm: i64) -> Flow<B> {
    fld_rv32(b, rd, Gpr(2), oimm)
}

/// C.FSDSP（RV32）。`fsd rs2, offset(x2)` に展開する。
pub fn c_fsdsp_rv32<B: Backend>(b: &mut B, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsd_rv32(b, Gpr(2), rs2, oimm)
}

/// C.SRLI。
pub fn c_srli<B: Backend>(b: &mut B, rd: Gpr, shamt: u64) -> Flow<B> {
    let r = rd.0;
    srli(b, rd, Gpr(r), shamt)
}

/// C.SRAI。
pub fn c_srai<B: Backend>(b: &mut B, rd: Gpr, shamt: u64) -> Flow<B> {
    let r = rd.0;
    srai(b, rd, Gpr(r), shamt)
}

/// C.ANDI。
pub fn c_andi<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    let r = rd.0;
    andi(b, rd, Gpr(r), imm)
}

/// C.SUB。
pub fn c_sub<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    sub(b, rd, Gpr(r), rs2)
}

/// C.XOR。
pub fn c_xor<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    xor(b, rd, Gpr(r), rs2)
}

/// C.OR。
pub fn c_or<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    or(b, rd, Gpr(r), rs2)
}

/// C.AND。
pub fn c_and<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    and(b, rd, Gpr(r), rs2)
}

/// C.SUBW。
pub fn c_subw<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    subw(b, rd, Gpr(r), rs2)
}

/// C.ADDW。
pub fn c_addw<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    addw(b, rd, Gpr(r), rs2)
}

/// C.ZEXT.B。
pub fn c_zext_b<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x = b.trunc::<W64, W8>(x64);
    let s = b.zext::<W8, W64>(x);
    write(b, rd, s);
    Ok(())
}

/// C.SEXT.B。
pub fn c_sext_b<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x = b.trunc::<W64, W8>(x64);
    let s = b.sext::<W8, W64>(x);
    write(b, rd, s);
    Ok(())
}

/// C.ZEXT.H。
pub fn c_zext_h<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x = b.trunc::<W64, W16>(x64);
    let s = b.zext::<W16, W64>(x);
    write(b, rd, s);
    Ok(())
}

/// C.SEXT.H。
pub fn c_sext_h<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x = b.trunc::<W64, W16>(x64);
    let s = b.sext::<W16, W64>(x);
    write(b, rd, s);
    Ok(())
}

/// C.ZEXT.W。
pub fn c_zext_w<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x = b.trunc::<W64, W32>(x64);
    let s = b.zext::<W32, W64>(x);
    write(b, rd, s);
    Ok(())
}

/// C.NOT。
pub fn c_not<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x = read(b, rd);
    let s = b.not(x);
    write(b, rd, s);
    Ok(())
}

/// C.MUL。
pub fn c_mul<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    mul(b, rd, Gpr(r), rs2)
}

/// C.LUI / C.ADDI16SP。rd==x2で分岐する（展開先が異なるため）。
pub fn c_lui_addi16sp<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    if rd.0 == 2 {
        addi(b, rd, Gpr(2), imm)
    } else {
        lui(b, rd, imm)
    }
}

/// C.JAL（RV32）。戻りアドレスは pc+2（16ビット命令）で、飛び先は32ビットで包む。
pub fn c_jal<B: Backend>(b: &mut B, pc: u64, offset: i64) -> Flow<B> {
    let ret = b.konst::<W32>(((pc.wrapping_add(2)) & MASK32) as u32);
    write_w(b, Gpr(1), ret);
    let target = const_w64(b, pc.wrapping_add(offset as u64) & MASK32);
    b.jump(target);
    Ok(())
}

/// C.JR。`jalr x0, 0(rs1)` に展開する。
pub fn c_jr<B: Backend>(b: &mut B, rs1: Gpr, pc: u64) -> Flow<B> {
    jalr(b, Gpr(0), rs1, pc, 0)
}

/// C.MV。`add rd, x0, rs2` に展開する。
pub fn c_mv<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    add(b, rd, Gpr(0), rs2)
}

/// C.JALR。戻りアドレスは pc+2（16ビット命令）。RV64 用で飛び先は包まない。
pub fn c_jalr<B: Backend>(b: &mut B, rs1: Gpr, pc: u64) -> Flow<B> {
    let base = read(b, rs1);
    let mask = const_w64(b, !1);
    let target = b.and(base, mask);
    let ret = const_w64(b, pc.wrapping_add(2));
    write(b, Gpr(1), ret);
    b.jump(target);
    Ok(())
}

/// C.JR（RV32）。`jalr x0, 0(rs1)` と同じで、飛び先は32ビットで包む。
pub fn c_jr_rv32<B: Backend>(b: &mut B, rs1: Gpr, pc: u64) -> Flow<B> {
    jalr_rv32(b, Gpr(0), rs1, pc, 0)
}

/// C.JALR（RV32）。戻りは (pc+2) を32ビットで包み、飛び先も32ビットで包む。
pub fn c_jalr_rv32<B: Backend>(b: &mut B, rs1: Gpr, pc: u64) -> Flow<B> {
    let base = read(b, rs1);
    let b32 = b.trunc::<W64, W32>(base);
    let addr = b.zext::<W32, W64>(b32);
    let mask = const_w64(b, !1);
    let target = b.and(addr, mask);
    let ret = b.konst::<W32>(((pc.wrapping_add(2)) & MASK32) as u32);
    write_w(b, Gpr(1), ret);
    b.jump(target);
    Ok(())
}

/// C.ADD。`add rd, rd, rs2` に展開する。
pub fn c_add<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    add(b, rd, Gpr(r), rs2)
}

/// C.EBREAK。`ebreak` と同じ。
pub fn c_ebreak<B: Backend>(b: &mut B, pc: u64) -> Flow<B> {
    ebreak(b, pc)
}

/// C.FLW。RV64 側の実行器（RV32 は事前振り分けで c_flw_rv32 を使う）。
/// 単精度ロード。
pub fn c_flw<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    flw(b, rd, rs1, oimm)
}

/// C.FSW。RV64 側の実行器（RV32 は事前振り分けで c_fsw_rv32 を使う）。
/// 単精度ストア。
pub fn c_fsw<B: Backend>(b: &mut B, rs1: Gpr, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsw(b, rs1, rs2, oimm)
}

// C（RV32）。GPR は下位 32 ビットに符号拡張して置く。

/// C.LW（RV32）。
pub fn c_lw_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lw_rv32(b, rd, rs1, oimm)
}

/// C.SW（RV32）。
pub fn c_sw_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    sw_rv32(b, rs1, rs2, oimm)
}

/// C.ADDI（RV32）。`addi rd, rd, nzimm` に展開する。
pub fn c_addi_rv32<B: Backend>(b: &mut B, rd: Gpr, nzimm: i64) -> Flow<B> {
    let r = rd.0;
    addi_rv32(b, rd, Gpr(r), nzimm)
}

/// C.LI（RV32）。`addi rd, x0, imm` に展開する。
pub fn c_li_rv32<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    addi_rv32(b, rd, Gpr(0), imm)
}

/// C.LUI / C.ADDI16SP（RV32）。
pub fn c_lui_addi16sp_rv32<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    if rd.0 == 2 {
        addi_rv32(b, rd, Gpr(2), imm)
    } else {
        lui_rv32(b, rd, imm)
    }
}

/// C.LUI（RV32）。
pub fn c_lui_rv32<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    lui_rv32(b, rd, imm)
}

/// C.J（RV32）。`jal x0, offset` に展開する。
pub fn c_j_rv32<B: Backend>(b: &mut B, pc: u64, offset: i64) -> Flow<B> {
    jal_rv32(b, Gpr(0), pc, offset)
}

/// C.BEQZ（RV32）。
pub fn c_beqz_rv32<B: Backend>(b: &mut B, rs1: Gpr, pc: u64, offset: i64) -> Flow<B> {
    beq_rv32(b, rs1, Gpr(0), pc, offset)
}

/// C.BNEZ（RV32）。
pub fn c_bnez_rv32<B: Backend>(b: &mut B, rs1: Gpr, pc: u64, offset: i64) -> Flow<B> {
    bne_rv32(b, rs1, Gpr(0), pc, offset)
}

/// C.SLLI（RV32）。
pub fn c_slli_rv32<B: Backend>(b: &mut B, rd: Gpr, shamt: u64) -> Flow<B> {
    let r = rd.0;
    slli_rv32(b, rd, Gpr(r), shamt)
}

/// C.LWSP（RV32）。
pub fn c_lwsp_rv32<B: Backend>(b: &mut B, rd: Gpr, oimm: i64) -> Flow<B> {
    lw_rv32(b, rd, Gpr(2), oimm)
}

/// C.SWSP（RV32）。
pub fn c_swsp_rv32<B: Backend>(b: &mut B, rs2: Gpr, oimm: i64) -> Flow<B> {
    sw_rv32(b, Gpr(2), rs2, oimm)
}

/// C.SRLI（RV32）。
pub fn c_srli_rv32<B: Backend>(b: &mut B, rd: Gpr, shamt: u64) -> Flow<B> {
    let r = rd.0;
    srli_rv32(b, rd, Gpr(r), shamt)
}

/// C.SRAI（RV32）。
pub fn c_srai_rv32<B: Backend>(b: &mut B, rd: Gpr, shamt: u64) -> Flow<B> {
    let r = rd.0;
    srai_rv32(b, rd, Gpr(r), shamt)
}

/// C.ANDI（RV32）。
pub fn c_andi_rv32<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    let r = rd.0;
    andi_rv32(b, rd, Gpr(r), imm)
}

/// C.SUB（RV32）。
pub fn c_sub_rv32<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    sub_rv32(b, rd, Gpr(r), rs2)
}

/// C.XOR（RV32）。
pub fn c_xor_rv32<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    xor_rv32(b, rd, Gpr(r), rs2)
}

/// C.OR（RV32）。
pub fn c_or_rv32<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    or_rv32(b, rd, Gpr(r), rs2)
}

/// C.AND（RV32）。
pub fn c_and_rv32<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    and_rv32(b, rd, Gpr(r), rs2)
}

/// C.MV（RV32）。
pub fn c_mv_rv32<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    add_rv32(b, rd, Gpr(0), rs2)
}

/// C.ADD（RV32）。
pub fn c_add_rv32<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    add_rv32(b, rd, Gpr(r), rs2)
}

/// C.LBU（RV32）。
pub fn c_lbu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lbu_rv32(b, rd, rs1, oimm)
}

/// C.LH（RV32）。
pub fn c_lh_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lh_rv32(b, rd, rs1, oimm)
}

/// C.LHU（RV32）。
pub fn c_lhu_rv32<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    lhu_rv32(b, rd, rs1, oimm)
}

/// C.SB（RV32）。
pub fn c_sb_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    sb_rv32(b, rs1, rs2, oimm)
}

/// C.SH（RV32）。
pub fn c_sh_rv32<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    sh_rv32(b, rs1, rs2, oimm)
}

/// C.ZEXT.B（RV32）。
pub fn c_zext_b_rv32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.trunc::<W32, W8>(x32);
    let s = b.zext::<W8, W32>(x);
    write_w(b, rd, s);
    Ok(())
}

/// C.SEXT.B（RV32）。
pub fn c_sext_b_rv32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.trunc::<W32, W8>(x32);
    let s = b.sext::<W8, W32>(x);
    write_w(b, rd, s);
    Ok(())
}

/// C.ZEXT.H（RV32）。
pub fn c_zext_h_rv32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.trunc::<W32, W16>(x32);
    let s = b.zext::<W16, W32>(x);
    write_w(b, rd, s);
    Ok(())
}

/// C.SEXT.H（RV32）。
pub fn c_sext_h_rv32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x64 = read(b, rd);
    let x32 = b.trunc::<W64, W32>(x64);
    let x = b.trunc::<W32, W16>(x32);
    let s = b.sext::<W16, W32>(x);
    write_w(b, rd, s);
    Ok(())
}

/// C.NOT（RV32）。
pub fn c_not_rv32<B: Backend>(b: &mut B, rd: Gpr) -> Flow<B> {
    let x = read_w(b, rd);
    let s = b.not(x);
    write_w(b, rd, s);
    Ok(())
}

/// C.MUL（RV32）。
pub fn c_mul_rv32<B: Backend>(b: &mut B, rd: Gpr, rs2: Gpr) -> Flow<B> {
    let r = rd.0;
    mul_rv32(b, rd, Gpr(r), rs2)
}

/// C.FLWSP。RV64 側の実行器（RV32 は事前振り分けで c_flwsp_rv32 を使う）。
/// `flw rd, offset(x2)` に展開する。
pub fn c_flwsp<B: Backend>(b: &mut B, rd: Fpr, oimm: i64) -> Flow<B> {
    flw(b, rd, Gpr(2), oimm)
}

/// C.FSWSP。RV64 側の実行器（RV32 は事前振り分けで c_fswsp_rv32 を使う）。
/// `fsw rs2, offset(x2)` に展開する。
pub fn c_fswsp<B: Backend>(b: &mut B, rs2: Fpr, oimm: i64) -> Flow<B> {
    fsw(b, Gpr(2), rs2, oimm)
}
