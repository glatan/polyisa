// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 関数本体の命令と、バイト列からの解読。
//!
//! `Instr` は検証と実行の共用の内部形式。`block`/`loop`/`if`/`else` は
//! 解読時に対応する `end`（と `else`）の命令指標を解決して持つ。
//! 分岐先の解決を実行時の走査なしに済ませるためである。
//! Ref: SPEC-WASM-CORE 5.4（命令）、5.4.5（数値命令の表）.

use crate::types::{BlockType, RefType, ValType};

/// メモリアクセスの幅と符号。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadOp {
    I32,
    I64,
    F32,
    F64,
    I32x8S,
    I32x8U,
    I32x16S,
    I32x16U,
    I64x8S,
    I64x8U,
    I64x16S,
    I64x16U,
    I64x32S,
    I64x32U,
}

/// ストアの幅。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreOp {
    I32,
    I64,
    F32,
    F64,
    I32x8,
    I32x16,
    I64x8,
    I64x16,
    I64x32,
}

/// デコード済みの一命令。
#[derive(Clone, Debug)]
pub enum Instr {
    // --- 制御 ---
    Unreachable,
    Nop,
    /// `end` は対応する End 命令の指標。`Loop` のブロック型は分岐の arity を決める。
    Block {
        bt: BlockType,
        end: u32,
    },
    Loop {
        bt: BlockType,
        end: u32,
    },
    /// `els` は Else 命令の指標（else 部がなければ `end` と同じ指標）。
    If {
        bt: BlockType,
        els: u32,
        end: u32,
    },
    /// 対応する `end` の指標。
    Else {
        end: u32,
    },
    /// ブロック・関数本体の終端。
    End,
    Br {
        l: u32,
    },
    BrIf {
        l: u32,
    },
    BrTable {
        ls: Box<[u32]>,
        ln: u32,
    },
    Return,
    Call {
        f: u32,
    },
    CallIndirect {
        ty: u32,
        table: u32,
    },
    // --- パラメトリック ---
    Drop,
    Select,
    SelectT(ValType),
    // --- 変数 ---
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    // --- テーブル ---
    TableGet(u32),
    TableSet(u32),
    TableSize(u32),
    TableGrow(u32),
    TableFill(u32),
    TableInit {
        table: u32,
        elem: u32,
    },
    ElemDrop(u32),
    TableCopy {
        dst: u32,
        src: u32,
    },
    // --- メモリ ---
    Load {
        op: LoadOp,
        off: u64,
        al: u32,
        mi: u32,
    },
    Store {
        op: StoreOp,
        off: u64,
        al: u32,
        mi: u32,
    },
    MemorySize,
    MemoryGrow,
    MemoryInit(u32),
    DataDrop(u32),
    MemoryCopy,
    MemoryFill,
    // --- 数値: 定数 ---
    I32Const(i32),
    I64Const(i64),
    F32Const(u32),
    F64Const(u64),
    // --- 数値: i32 比較 ---
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    // --- 数値: i64 比較 ---
    I64Eqz,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
    // --- 数値: f32/f64 比較 ---
    F32Eq,
    F32Ne,
    F32Lt,
    F32Gt,
    F32Le,
    F32Ge,
    F64Eq,
    F64Ne,
    F64Lt,
    F64Gt,
    F64Le,
    F64Ge,
    // --- 数値: i32 演算 ---
    I32Clz,
    I32Ctz,
    I32Popcnt,
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    // --- 数値: i64 演算 ---
    I64Clz,
    I64Ctz,
    I64Popcnt,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,
    // --- 数値: f32 演算 ---
    F32Abs,
    F32Neg,
    F32Ceil,
    F32Floor,
    F32Trunc,
    F32Nearest,
    F32Sqrt,
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Min,
    F32Max,
    F32Copysign,
    // --- 数値: f64 演算 ---
    F64Abs,
    F64Neg,
    F64Ceil,
    F64Floor,
    F64Trunc,
    F64Nearest,
    F64Sqrt,
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Min,
    F64Max,
    F64Copysign,
    // --- 数値: 変換 ---
    I32WrapI64,
    I32TruncF32S,
    I32TruncF32U,
    I32TruncF64S,
    I32TruncF64U,
    I64ExtendI32S,
    I64ExtendI32U,
    I64TruncF32S,
    I64TruncF32U,
    I64TruncF64S,
    I64TruncF64U,
    F32ConvertI32S,
    F32ConvertI32U,
    F32ConvertI64S,
    F32ConvertI64U,
    F32DemoteF64,
    F64ConvertI32S,
    F64ConvertI32U,
    F64ConvertI64S,
    F64ConvertI64U,
    F64PromoteF32,
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    I32TruncSatF32S,
    I32TruncSatF32U,
    I32TruncSatF64S,
    I32TruncSatF64U,
    I64TruncSatF32S,
    I64TruncSatF32U,
    I64TruncSatF64S,
    I64TruncSatF64U,
    // --- 参照 ---
    RefNull(RefType),
    RefIsNull,
    RefFunc(u32),
}

/// 解読エラー。`malformed` は仕様の malformed 相当。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecodeError(pub String);

impl DecodeError {
    pub fn malformed(msg: &str) -> DecodeError {
        DecodeError(msg.to_string())
    }
}

type D<T> = Result<T, DecodeError>;

/// 入力バイト列の読み出し器。
/// `limit` は式の境界（セクションの宣言終端）。スカラのフィールドは
/// 宣言サイズを超えて読み進め得るが、式の命令列は `limit` で打ち止め
/// られる（仕様実装の動作に合わせる）。
pub struct Reader<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
    pub limit: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader {
            bytes,
            pos: 0,
            limit: bytes.len(),
        }
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn byte(&mut self) -> D<u8> {
        if self.pos >= self.bytes.len() {
            return Err(DecodeError::malformed("unexpected end"));
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// 1 バイトの即値フィールド。仕様の `s7`/`byte` 相当で、
    /// `0x80` 以上は LEB 継続を含むため「integer representation too long」。
    pub fn byte7(&mut self) -> D<u8> {
        let b = self.byte()?;
        if b & 0x80 != 0 {
            return Err(DecodeError::malformed("integer representation too long"));
        }
        Ok(b)
    }

    pub fn take(&mut self, n: usize) -> D<&'a [u8]> {
        if self.remaining() < n {
            return Err(DecodeError::malformed("unexpected end"));
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// 符号なし LEB128（`N` ビット）。`u64` で返す（N≤64）。
    pub fn uleb(&mut self, bits: u32) -> D<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        let max_bytes = bits.div_ceil(7);
        for i in 0..max_bytes {
            let b = self.byte()?;
            let low = u64::from(b & 0x7f);
            if i == max_bytes - 1 {
                // 最終バイトに収まらない上位ビットがあれば overflow。
                let usable = bits - shift;
                if usable < 7 && (low >> usable) != 0 {
                    return Err(DecodeError::malformed("integer too large"));
                }
            }
            result |= low << shift;
            shift += 7;
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(DecodeError::malformed("integer representation too long"))
    }

    /// 符号付き LEB128（`N` ビット）。`i64` で返す。
    pub fn sleb(&mut self, bits: u32) -> D<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        let max_bytes = bits.div_ceil(7);
        for i in 0..max_bytes {
            let b = self.byte()?;
            let low = i64::from(b & 0x7f);
            if i == max_bytes - 1 {
                // 最終バイト: 残りの許容ビットに収まるか検査する。
                // 上位の (7 - usable) ビットは符号ビットの延長でなければならない。
                let usable = bits - shift;
                if usable < 7 {
                    let sign = (low >> (usable - 1)) & 1;
                    let high = low >> usable;
                    let expected = if sign == 1 {
                        (1i64 << (7 - usable)) - 1
                    } else {
                        0
                    };
                    if high != expected {
                        return Err(DecodeError::malformed("integer too large"));
                    }
                }
            }
            result |= low << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && (b & 0x40) != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
        }
        Err(DecodeError::malformed("integer representation too long"))
    }

    pub fn u32(&mut self) -> D<u32> {
        let v = self.uleb(32)?;
        Ok(v as u32)
    }

    /// 名前（u8 列の UTF-8）。不正 UTF-8 は malformed。
    pub fn name(&mut self) -> D<String> {
        let n = self.u32()? as usize;
        if n > self.remaining() {
            return Err(DecodeError::malformed("length out of bounds"));
        }
        let s = self.take(n)?;
        String::from_utf8(s.to_vec())
            .map_err(|_| DecodeError::malformed("malformed UTF-8 encoding"))
    }

    /// バイト列（vec(u8)）。長さ超過は打ち切り（unexpected end）として扱う。
    pub fn bytes(&mut self) -> D<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

/// valtype のバイト。
pub fn val_type(b: u8) -> Option<ValType> {
    Some(match b {
        0x7f => ValType::I32,
        0x7e => ValType::I64,
        0x7d => ValType::F32,
        0x7c => ValType::F64,
        0x7b => ValType::V128,
        0x70 => ValType::Ref(RefType::Func),
        0x6f => ValType::Ref(RefType::Extern),
        _ => return None,
    })
}

/// ヒープ型（s33）。非負は具体型指標、負の単バイトは抽象ヒープ型。
/// 仕様実装は `typeuse s33` を先に試し、負なら s7 の抽象型へ
/// 戻る（`either` でバックトラック）ため、s7 側が継続ビットを
/// 持つバイト列を「integer representation too long」と診断する。
pub fn heap_type(r: &mut Reader) -> D<RefType> {
    let start = r.pos;
    match r.sleb(33) {
        Ok(v) if v >= 0 => Ok(RefType::Idx(v as u32)),
        _ => {
            r.pos = start;
            match r.byte7()? {
                0x70 => Ok(RefType::Func),
                0x6f => Ok(RefType::Extern),
                _ => Err(DecodeError::malformed("malformed heap type")),
            }
        }
    }
}

/// ブロック型（s33: 0x40=empty、負=値型、非負=typeidx）。
fn block_type(r: &mut Reader) -> D<BlockType> {
    // 先頭バイトを覗いて高速分岐する（0x40 と 0x70–0x7f は単一バイト）。
    let b = *r
        .bytes
        .get(r.pos)
        .ok_or_else(|| DecodeError::malformed("unexpected end"))?;
    match b {
        0x40 => {
            r.pos += 1;
            Ok(BlockType::Empty)
        }
        0x6f | 0x70 | 0x7b..=0x7f => {
            r.pos += 1;
            Ok(BlockType::Val(val_type(b).ok_or_else(|| {
                DecodeError::malformed("malformed value type")
            })?))
        }
        _ => {
            let v = r.sleb(33)?;
            if v < 0 {
                return Err(DecodeError::malformed("malformed block type"));
            }
            Ok(BlockType::Func(v as u32))
        }
    }
}

/// memarg `{offset, align, memidx}`。`align` は 2 の冪の指数。
/// flags バイトは bit0–5 が指数、bit6 が memidx 有無、bit7 以上は
/// 予約（malformed memop flags）。
fn mem_arg(r: &mut Reader) -> D<(u64, u32, u32)> {
    let a = r.u32()?;
    if a & !0x7f != 0 {
        return Err(DecodeError::malformed("malformed memop flags"));
    }
    let al = a & 0x3f;
    let mi = if a & 0x40 != 0 { r.u32()? } else { 0 };
    // オフセットのフィールドは 3.0 の文法では u64（memory64 取り込みで
    // 統一）。u32 を超える値は malformed ではなく、検証側で 32 ビット
    // メモリの「offset out of range」（invalid）として弾く
    // （binary-leb128.wast・address.wast・align.wast 参照）。
    let off = r.uleb(64)?;
    Ok((off, al, mi))
}

fn table_idx(r: &mut Reader) -> D<u32> {
    r.u32()
}

fn load_op(b: u8) -> Option<LoadOp> {
    Some(match b {
        0x28 => LoadOp::I32,
        0x29 => LoadOp::I64,
        0x2a => LoadOp::F32,
        0x2b => LoadOp::F64,
        0x2c => LoadOp::I32x8S,
        0x2d => LoadOp::I32x8U,
        0x2e => LoadOp::I32x16S,
        0x2f => LoadOp::I32x16U,
        0x30 => LoadOp::I64x8S,
        0x31 => LoadOp::I64x8U,
        0x32 => LoadOp::I64x16S,
        0x33 => LoadOp::I64x16U,
        0x34 => LoadOp::I64x32S,
        0x35 => LoadOp::I64x32U,
        _ => return None,
    })
}

fn store_op(b: u8) -> Option<StoreOp> {
    Some(match b {
        0x36 => StoreOp::I32,
        0x37 => StoreOp::I64,
        0x38 => StoreOp::F32,
        0x39 => StoreOp::F64,
        0x3a => StoreOp::I32x8,
        0x3b => StoreOp::I32x16,
        0x3c => StoreOp::I64x8,
        0x3d => StoreOp::I64x16,
        0x3e => StoreOp::I64x32,
        _ => return None,
    })
}

fn simple(b: u8) -> Option<Instr> {
    use Instr::*;
    Some(match b {
        0x00 => Unreachable,
        0x01 => Nop,
        0x0f => Return,
        0x1a => Drop,
        0x1b => Select,
        // 0x3f/0x40（memory.size/grow）は memidx バイトを持つため
        // `one` が先に処理する。ここには来ない。
        0x45 => I32Eqz,
        0x46 => I32Eq,
        0x47 => I32Ne,
        0x48 => I32LtS,
        0x49 => I32LtU,
        0x4a => I32GtS,
        0x4b => I32GtU,
        0x4c => I32LeS,
        0x4d => I32LeU,
        0x4e => I32GeS,
        0x4f => I32GeU,
        0x50 => I64Eqz,
        0x51 => I64Eq,
        0x52 => I64Ne,
        0x53 => I64LtS,
        0x54 => I64LtU,
        0x55 => I64GtS,
        0x56 => I64GtU,
        0x57 => I64LeS,
        0x58 => I64LeU,
        0x59 => I64GeS,
        0x5a => I64GeU,
        0x5b => F32Eq,
        0x5c => F32Ne,
        0x5d => F32Lt,
        0x5e => F32Gt,
        0x5f => F32Le,
        0x60 => F32Ge,
        0x61 => F64Eq,
        0x62 => F64Ne,
        0x63 => F64Lt,
        0x64 => F64Gt,
        0x65 => F64Le,
        0x66 => F64Ge,
        0x67 => I32Clz,
        0x68 => I32Ctz,
        0x69 => I32Popcnt,
        0x6a => I32Add,
        0x6b => I32Sub,
        0x6c => I32Mul,
        0x6d => I32DivS,
        0x6e => I32DivU,
        0x6f => I32RemS,
        0x70 => I32RemU,
        0x71 => I32And,
        0x72 => I32Or,
        0x73 => I32Xor,
        0x74 => I32Shl,
        0x75 => I32ShrS,
        0x76 => I32ShrU,
        0x77 => I32Rotl,
        0x78 => I32Rotr,
        0x79 => I64Clz,
        0x7a => I64Ctz,
        0x7b => I64Popcnt,
        0x7c => I64Add,
        0x7d => I64Sub,
        0x7e => I64Mul,
        0x7f => I64DivS,
        0x80 => I64DivU,
        0x81 => I64RemS,
        0x82 => I64RemU,
        0x83 => I64And,
        0x84 => I64Or,
        0x85 => I64Xor,
        0x86 => I64Shl,
        0x87 => I64ShrS,
        0x88 => I64ShrU,
        0x89 => I64Rotl,
        0x8a => I64Rotr,
        0x8b => F32Abs,
        0x8c => F32Neg,
        0x8d => F32Ceil,
        0x8e => F32Floor,
        0x8f => F32Trunc,
        0x90 => F32Nearest,
        0x91 => F32Sqrt,
        0x92 => F32Add,
        0x93 => F32Sub,
        0x94 => F32Mul,
        0x95 => F32Div,
        0x96 => F32Min,
        0x97 => F32Max,
        0x98 => F32Copysign,
        0x99 => F64Abs,
        0x9a => F64Neg,
        0x9b => F64Ceil,
        0x9c => F64Floor,
        0x9d => F64Trunc,
        0x9e => F64Nearest,
        0x9f => F64Sqrt,
        0xa0 => F64Add,
        0xa1 => F64Sub,
        0xa2 => F64Mul,
        0xa3 => F64Div,
        0xa4 => F64Min,
        0xa5 => F64Max,
        0xa6 => F64Copysign,
        0xa7 => I32WrapI64,
        0xa8 => I32TruncF32S,
        0xa9 => I32TruncF32U,
        0xaa => I32TruncF64S,
        0xab => I32TruncF64U,
        0xac => I64ExtendI32S,
        0xad => I64ExtendI32U,
        0xae => I64TruncF32S,
        0xaf => I64TruncF32U,
        0xb0 => I64TruncF64S,
        0xb1 => I64TruncF64U,
        0xb2 => F32ConvertI32S,
        0xb3 => F32ConvertI32U,
        0xb4 => F32ConvertI64S,
        0xb5 => F32ConvertI64U,
        0xb6 => F32DemoteF64,
        0xb7 => F64ConvertI32S,
        0xb8 => F64ConvertI32U,
        0xb9 => F64ConvertI64S,
        0xba => F64ConvertI64U,
        0xbb => F64PromoteF32,
        0xbc => I32ReinterpretF32,
        0xbd => I64ReinterpretF64,
        0xbe => F32ReinterpretI32,
        0xbf => F64ReinterpretI64,
        0xc0 => I32Extend8S,
        0xc1 => I32Extend16S,
        0xc2 => I64Extend8S,
        0xc3 => I64Extend16S,
        0xc4 => I64Extend32S,
        0xd1 => RefIsNull,
        _ => return None,
    })
}

/// 0xfc 接頭辞の命令。
fn prefixed_fc(r: &mut Reader) -> D<Instr> {
    use Instr::*;
    let sub = r.u32()?;
    Ok(match sub {
        0x00 => I32TruncSatF32S,
        0x01 => I32TruncSatF32U,
        0x02 => I32TruncSatF64S,
        0x03 => I32TruncSatF64U,
        0x04 => I64TruncSatF32S,
        0x05 => I64TruncSatF32U,
        0x06 => I64TruncSatF64S,
        0x07 => I64TruncSatF64U,
        0x08 => {
            let seg = r.u32()?;
            let zero = r.byte()?;
            if zero != 0 {
                return Err(DecodeError::malformed("zero byte expected"));
            }
            MemoryInit(seg)
        }
        0x09 => DataDrop(r.u32()?),
        0x0a => {
            let a = r.byte()?;
            let b = r.byte()?;
            if a != 0 || b != 0 {
                return Err(DecodeError::malformed("zero byte expected"));
            }
            MemoryCopy
        }
        0x0b => {
            let a = r.byte()?;
            if a != 0 {
                return Err(DecodeError::malformed("zero byte expected"));
            }
            MemoryFill
        }
        0x0c => {
            let elem = r.u32()?;
            let table = r.u32()?;
            TableInit { table, elem }
        }
        0x0d => ElemDrop(r.u32()?),
        0x0e => {
            let dst = r.u32()?;
            let src = r.u32()?;
            TableCopy { dst, src }
        }
        0x0f => TableGrow(r.u32()?),
        0x10 => TableSize(r.u32()?),
        0x11 => TableFill(r.u32()?),
        _ => return Err(DecodeError::malformed(&format!("illegal opcode {sub:02x}"))),
    })
}

/// 一命令を解読する。`Else`/`End` はここでは即値を持たず、
/// 対応付けは `decode_body` が行う。
pub fn one(r: &mut Reader) -> D<Instr> {
    use Instr::*;
    let b = r.byte()?;
    // メモリサイズ系は memidx バイトを持つ（1.0/2.0 では 0 固定）。
    if b == 0x3f || b == 0x40 {
        if r.u32()? != 0 {
            return Err(DecodeError::malformed("zero byte expected"));
        }
        return Ok(if b == 0x3f { MemorySize } else { MemoryGrow });
    }
    if let Some(i) = simple(b) {
        return Ok(i);
    }
    if let Some(op) = load_op(b) {
        let (off, al, mi) = mem_arg(r)?;
        return Ok(Load { op, off, al, mi });
    }
    if let Some(op) = store_op(b) {
        let (off, al, mi) = mem_arg(r)?;
        return Ok(Store { op, off, al, mi });
    }
    Ok(match b {
        0x02 => Block {
            bt: block_type(r)?,
            end: u32::MAX,
        },
        0x03 => Loop {
            bt: block_type(r)?,
            end: u32::MAX,
        },
        0x04 => If {
            bt: block_type(r)?,
            els: u32::MAX,
            end: u32::MAX,
        },
        0x05 => Else { end: u32::MAX },
        0x0b => End,
        0x0c => Br { l: r.u32()? },
        0x0d => BrIf { l: r.u32()? },
        0x0e => {
            let n = r.u32()? as usize;
            if n > 1 << 22 {
                return Err(DecodeError::malformed("length out of bounds"));
            }
            let mut ls = Vec::with_capacity(n.min(1 << 16));
            for _ in 0..n {
                ls.push(r.u32()?);
            }
            let ln = r.u32()?;
            BrTable {
                ls: ls.into_boxed_slice(),
                ln,
            }
        }
        0x10 => Call { f: r.u32()? },
        0x11 => {
            let ty = r.u32()?;
            let table = table_idx(r)?;
            CallIndirect { ty, table }
        }
        0x1c => {
            let n = r.u32()?;
            if n != 1 {
                return Err(DecodeError::malformed("invalid result arity"));
            }
            let t = r.byte7()?;
            SelectT(val_type(t).ok_or_else(|| DecodeError::malformed("malformed value type"))?)
        }
        0x20 => LocalGet(r.u32()?),
        0x21 => LocalSet(r.u32()?),
        0x22 => LocalTee(r.u32()?),
        0x23 => GlobalGet(r.u32()?),
        0x24 => GlobalSet(r.u32()?),
        0x25 => TableGet(table_idx(r)?),
        0x26 => TableSet(table_idx(r)?),
        0x41 => I32Const(r.sleb(32)? as i32),
        0x42 => I64Const(r.sleb(64)?),
        0x43 => {
            let s = r.take(4)?;
            F32Const(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        }
        0x44 => {
            let s = r.take(8)?;
            let mut b8 = [0u8; 8];
            b8.copy_from_slice(s);
            F64Const(u64::from_le_bytes(b8))
        }
        0xd0 => RefNull(heap_type(r)?),
        0xd2 => RefFunc(r.u32()?),
        0xfc => return prefixed_fc(r),
        _ => return Err(DecodeError::malformed(&format!("illegal opcode {b:02x}"))),
    })
}

/// `end` で終わる式を `r` から解読し、制御命令に `end`/`else` の
/// 指標を解決して入れる。`r` は終端の `0x0b` の直後まで進む。
/// 関数本体の式は宣言サイズを超えて読み進め得るため、サイズ照合は
/// 呼び出し側が行う（仕様実装と同じく `end` まで読む）。
pub fn decode_exprs(r: &mut Reader) -> D<Vec<Instr>> {
    let mut instrs: Vec<Instr> = Vec::new();
    // 開いているブロック命令の指標と、あれば else 命令の指標。
    let mut open: Vec<(usize, Option<usize>)> = Vec::new();
    loop {
        if r.remaining() == 0 {
            return Err(DecodeError::malformed("unexpected end"));
        }
        let idx = instrs.len() as u32;
        let ins = one(r)?;
        match ins {
            Instr::Block { .. } | Instr::Loop { .. } | Instr::If { .. } => {
                open.push((idx as usize, None));
                instrs.push(ins);
            }
            Instr::Else { .. } => {
                let Some((top, else_idx)) = open.last_mut() else {
                    // 式の先頭での else は end の欠落として扱う（仕様実装と同じ）。
                    return Err(DecodeError::malformed("END opcode expected"));
                };
                // else は if の途中でのみ合法（else を持つ if への重複も拒否）。
                if !matches!(instrs[*top], Instr::If { .. }) || else_idx.is_some() {
                    return Err(DecodeError::malformed("else opcode without matching if"));
                }
                instrs.push(ins);
                *else_idx = Some(idx as usize);
                if let Instr::If { els, .. } = &mut instrs[*top] {
                    *els = idx;
                }
            }
            Instr::End => {
                instrs.push(ins);
                match open.pop() {
                    Some((top, else_idx)) => {
                        match &mut instrs[top] {
                            Instr::Block { end, .. } | Instr::Loop { end, .. } => *end = idx,
                            Instr::If { els, end, .. } => {
                                if *els == u32::MAX {
                                    *els = idx;
                                }
                                *end = idx;
                            }
                            _ => {}
                        }
                        if let Some(e) = else_idx
                            && let Instr::Else { end } = &mut instrs[e]
                        {
                            *end = idx;
                        }
                    }
                    None => {
                        // 式を閉じる end。これで終わり。
                        return Ok(instrs);
                    }
                }
            }
            _ => instrs.push(ins),
        }
    }
}

/// 関数本体（`end` で終わる式）を `body` 全体から解読する。
/// 終端 `end` の後にバイトが残っていれば malformed。
pub fn decode_body(body: &[u8]) -> D<Vec<Instr>> {
    let mut r = Reader::new(body);
    let instrs = decode_exprs(&mut r)?;
    if r.remaining() != 0 {
        return Err(DecodeError::malformed(
            "section size mismatch in function body",
        ));
    }
    Ok(instrs)
}
