//! RV64I の命令意味論。バックエンドに対して総称的に書く.
//!
//! デコード済みのオペランドは Rust の値で受け、実行時の値は `B::V` で扱う。
//! 出典の版は SPEC-RISCV-UNPRIV (20250508) である（`// Ref:` は `build.rs` に集約）。
//!
//! - 即値は組み立て済みの値を `i64` で受ける。切り出しと符号拡張はデコーダの仕事であり、後の段階で生成する。
//! - シフト量は ISA の規則どおりに下位ビットだけ使う（RV64 で 6 ビット、W 接尾辞で 5 ビット）。
//! - バックエンドの呼び出しは必ず文で分け、引数の中で借用を重ねない。

use polyisa_mem::{Access, AccessKind, Align, Endian};
use polyisa_sem::{Backend, Cmp, Flow, GuestException, StateArray, StateRef, W8, W16, W32, W64};

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

// SYSTEM

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
