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
    Backend, Cmp, F32, F64, Flow, GuestException, StateArray, StateRef, W8, W16, W32, W64,
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
    align: Align::Natural,
    kind: AccessKind::DataRead,
};

const DATA_WRITE: Access = Access {
    endian: Endian::Le,
    align: Align::Natural,
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

// ストア。複数ページにまたがる命令の `probe` は後の段階で足す。

pub fn sb<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W8>(raw);
    let addr = load_addr(b, rs1, oimm);
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sh<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W16>(raw);
    let addr = load_addr(b, rs1, oimm);
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sw<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W32>(raw);
    let addr = load_addr(b, rs1, oimm);
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

pub fn sd<B: Backend>(b: &mut B, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let v = read(b, rs2);
    let addr = load_addr(b, rs1, oimm);
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

// CSR（Zicsr）。権限と読み書き属性の検査は後の段階で足す。

/// CSR 番号（12 ビット）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Csr(pub u16);

fn csr_array() -> StateArray<W64> {
    StateArray::<W64>::from_layout(core::mem::offset_of!(CpuState, csr), 8)
}

fn read_csr<B: Backend>(b: &mut B, csr: Csr) -> B::V<W64> {
    let i = b.konst::<W32>(u32::from(csr.0));
    b.get_indexed(csr_array(), i)
}

fn write_csr<B: Backend>(b: &mut B, csr: Csr, v: B::V<W64>) {
    let i = b.konst::<W32>(u32::from(csr.0));
    b.set_indexed(csr_array(), i, v);
}

pub fn csrrw<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, csr: Csr) -> Flow<B> {
    let t = read_csr(b, csr);
    let x = read(b, rs1);
    write_csr(b, csr, x);
    write(b, rd, t);
    Ok(())
}

pub fn csrrs<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, csr: Csr) -> Flow<B> {
    let t = read_csr(b, csr);
    if !rs1.is_zero() {
        let x = read(b, rs1);
        let s = b.or(t, x);
        write_csr(b, csr, s);
    }
    write(b, rd, t);
    Ok(())
}

pub fn csrrc<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, csr: Csr) -> Flow<B> {
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

pub fn csrrwi<B: Backend>(b: &mut B, rd: Gpr, uimm: u64, csr: Csr) -> Flow<B> {
    let t = read_csr(b, csr);
    let x = b.konst::<W64>(uimm & 31);
    write_csr(b, csr, x);
    write(b, rd, t);
    Ok(())
}

pub fn csrrsi<B: Backend>(b: &mut B, rd: Gpr, uimm: u64, csr: Csr) -> Flow<B> {
    let t = read_csr(b, csr);
    if uimm & 31 != 0 {
        let x = b.konst::<W64>(uimm & 31);
        let s = b.or(t, x);
        write_csr(b, csr, s);
    }
    write(b, rd, t);
    Ok(())
}

pub fn csrrci<B: Backend>(b: &mut B, rd: Gpr, uimm: u64, csr: Csr) -> Flow<B> {
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
    let v: B::V<W32> = b.load_reserved(addr, LR_ACC)?;
    write_w(b, rd, v);
    Ok(())
}

pub fn lr_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, oimm: i64) -> Flow<B> {
    let addr = load_addr(b, rs1, oimm);
    let v: B::V<W64> = b.load_reserved(addr, LR_ACC)?;
    write(b, rd, v);
    Ok(())
}

/// SC。成功で 0、失敗で 0 以外を書く。
pub fn sc_w<B: Backend>(b: &mut B, rd: Gpr, rs1: Gpr, rs2: Gpr, oimm: i64) -> Flow<B> {
    let raw = read(b, rs2);
    let v = b.trunc::<W64, W32>(raw);
    let addr = load_addr(b, rs1, oimm);
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
    let cur: B::V<W64> = b.load(addr, AMO_ACC)?;
    let y = read(b, rs2);
    let nxt = f(b, cur, y);
    b.store(addr, nxt, AMO_ACC)?;
    write(b, rd, cur);
    Ok(())
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
    let w: B::V<W64> = b.get(r.state());
    b.trunc::<W64, F32>(w)
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

// F（単精度浮動小数点）。丸めは RNE 固定、動的丸めは後の段階で足す。

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
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

/// FADD.S。
pub fn fadd_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let s = b.fadd(x, y);
    write_f(b, rd, s);
    Ok(())
}

/// FSUB.S。
pub fn fsub_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let s = b.fsub(x, y);
    write_f(b, rd, s);
    Ok(())
}

/// FMUL.S。
pub fn fmul_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let s = b.fmul(x, y);
    write_f(b, rd, s);
    Ok(())
}

/// FDIV.S。
pub fn fdiv_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let s = b.fdiv(x, y);
    write_f(b, rd, s);
    Ok(())
}

/// FSQRT.S。
pub fn fsqrt_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let s = b.fsqrt(x);
    write_f(b, rd, s);
    Ok(())
}

/// FSGNJ.S。
pub fn fsgnj_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let __v = b.fsgnj(x, y);
    write_f(b, rd, __v);
    Ok(())
}

/// FSGNJN.S。
pub fn fsgnjn_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let __v = b.fsgnjn(x, y);
    write_f(b, rd, __v);
    Ok(())
}

/// FSGNJX.S。
pub fn fsgnjx_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let __v = b.fsgnjx(x, y);
    write_f(b, rd, __v);
    Ok(())
}

/// FMIN.S。
pub fn fmin_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let __v = b.fmin(x, y);
    write_f(b, rd, __v);
    Ok(())
}

/// FMAX.S。
pub fn fmax_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let __v = b.fmax(x, y);
    write_f(b, rd, __v);
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
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let c = b.feq(x, y);
    write_cmp(b, rd, c);
    Ok(())
}

/// FLT.S。
pub fn flt_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let c = b.flt(x, y);
    write_cmp(b, rd, c);
    Ok(())
}

/// FLE.S。
pub fn fle_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let y = read_f(b, rs2);
    let c = b.fle(x, y);
    write_cmp(b, rd, c);
    Ok(())
}

/// FCLASS.S。分類ビットを整数レジスタに書く。
pub fn fclass_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let v = b.fclass(x);
    let w = b.zext::<W32, W64>(v);
    write(b, rd, w);
    Ok(())
}

/// FCVT.W.S。範囲外は飽和する。
pub fn fcvt_w_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let v = b.fcvt_s32(x);
    let w = b.sext::<W32, W64>(v);
    write(b, rd, w);
    Ok(())
}

/// FCVT.WU.S。
pub fn fcvt_wu_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let v = b.fcvt_u32(x);
    let w = b.zext::<W32, W64>(v);
    write(b, rd, w);
    Ok(())
}

/// FCVT.L.S。
pub fn fcvt_l_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let s = b.fcvt_s64(x);
    write(b, rd, s);
    Ok(())
}

/// FCVT.LU.S。
pub fn fcvt_lu_s<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let s = b.fcvt_u64(x);
    write(b, rd, s);
    Ok(())
}

/// FCVT.S.W。
pub fn fcvt_s_w<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_s32(x);
    write_f(b, rd, s);
    Ok(())
}

/// FCVT.S.WU。
pub fn fcvt_s_wu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_u32(x);
    write_f(b, rd, s);
    Ok(())
}

/// FCVT.S.L。
pub fn fcvt_s_l<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_s64(x);
    write_f(b, rd, s);
    Ok(())
}

/// FCVT.S.LU。
pub fn fcvt_s_lu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_u64(x);
    write_f(b, rd, s);
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
    b.store(addr, v, DATA_WRITE)?;
    Ok(())
}

/// FADD.D。
pub fn fadd_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fadd(x, y);
    write_fd(b, rd, s);
    Ok(())
}

/// FSUB.D。
pub fn fsub_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fsub(x, y);
    write_fd(b, rd, s);
    Ok(())
}

/// FMUL.D。
pub fn fmul_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fmul(x, y);
    write_fd(b, rd, s);
    Ok(())
}

/// FDIV.D。
pub fn fdiv_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let s = b.fdiv(x, y);
    write_fd(b, rd, s);
    Ok(())
}

/// FSQRT.D。
pub fn fsqrt_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let __w = b.fsqrt(x);
    write_fd(b, rd, __w);
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
    Ok(())
}

/// FMAX.D。
pub fn fmax_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let __w = b.fmax(x, y);
    write_fd(b, rd, __w);
    Ok(())
}

/// FEQ.D。
pub fn feq_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let c = b.feq(x, y);
    write_cmp(b, rd, c);
    Ok(())
}

/// FLT.D。
pub fn flt_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let c = b.flt(x, y);
    write_cmp(b, rd, c);
    Ok(())
}

/// FLE.D。
pub fn fle_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr, rs2: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let y = read_fd(b, rs2);
    let c = b.fle(x, y);
    write_cmp(b, rd, c);
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
pub fn fcvt_w_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let v = b.fcvt_s64(x);
    let w = b.trunc::<W64, W32>(v);
    let s = b.sext::<W32, W64>(w);
    write(b, rd, s);
    Ok(())
}

/// FCVT.WU.D。
pub fn fcvt_wu_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let v = b.fcvt_u64(x);
    let w = b.trunc::<W64, W32>(v);
    let z = b.zext::<W32, W64>(w);
    write(b, rd, z);
    Ok(())
}

/// FCVT.L.D。
pub fn fcvt_l_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let s = b.fcvt_s64(x);
    write(b, rd, s);
    Ok(())
}

/// FCVT.LU.D。
pub fn fcvt_lu_d<B: Backend>(b: &mut B, rd: Gpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let s = b.fcvt_u64(x);
    write(b, rd, s);
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
pub fn fcvt_d_w<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_s32(x);
    write_fd(b, rd, s);
    Ok(())
}

/// FCVT.D.WU。
pub fn fcvt_d_wu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let raw = read(b, rs1);
    let x = b.trunc::<W64, W32>(raw);
    let s = b.fcvt_from_u32(x);
    write_fd(b, rd, s);
    Ok(())
}

/// FCVT.D.L。
pub fn fcvt_d_l<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_s64(x);
    write_fd(b, rd, s);
    Ok(())
}

/// FCVT.D.LU。
pub fn fcvt_d_lu<B: Backend>(b: &mut B, rd: Fpr, rs1: Gpr) -> Flow<B> {
    let x = read(b, rs1);
    let s = b.fcvt_from_u64(x);
    write_fd(b, rd, s);
    Ok(())
}

/// FCVT.S.D。単精度に丸める。
pub fn fcvt_s_d<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr) -> Flow<B> {
    let x = read_fd(b, rs1);
    let s = b.fcvt_ff(x);
    write_f(b, rd, s);
    Ok(())
}

/// FCVT.D.S。倍精度に広げる。
pub fn fcvt_d_s<B: Backend>(b: &mut B, rd: Fpr, rs1: Fpr) -> Flow<B> {
    let x = read_f(b, rs1);
    let s = b.fcvt_ff(x);
    write_fd(b, rd, s);
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

/// C.J。`jal x0, offset` に展開する。
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

/// C.LUI / C.ADDI16SP。rd==x2で分岐する（展開先が異なるため）。
pub fn c_lui_addi16sp<B: Backend>(b: &mut B, rd: Gpr, imm: i64) -> Flow<B> {
    if rd.0 == 2 {
        addi(b, rd, Gpr(2), imm)
    } else {
        lui(b, rd, imm)
    }
}

/// C.JAL（RV32）。`jal x1, offset` に展開する。
pub fn c_jal<B: Backend>(b: &mut B, pc: u64, offset: i64) -> Flow<B> {
    jal(b, Gpr(1), pc, offset)
}
