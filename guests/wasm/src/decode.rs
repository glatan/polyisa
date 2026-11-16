// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly バイナリ形式のデコーダ。ヘッダ・各セクション・LEB128 を解読する。
//!
//! 受理する範囲は 1.0/2.0 のコア。custom セクションは名前の UTF-8 を
//! 検査した上で読み飛ばす。セクションは定義順（custom 以外・各 1 回）を
//! 強制する。Ref: SPEC-WASM-CORE 5.5（バイナリ形式）.

use crate::instr::{self, DecodeError, Reader, val_type};
use crate::module::*;
use crate::types::*;

/// セクション ID。
const SEC_TYPE: u8 = 1;
const SEC_IMPORT: u8 = 2;
const SEC_FUNC: u8 = 3;
const SEC_TABLE: u8 = 4;
const SEC_MEM: u8 = 5;
const SEC_GLOBAL: u8 = 6;
const SEC_EXPORT: u8 = 7;
const SEC_START: u8 = 8;
const SEC_ELEM: u8 = 9;
const SEC_CODE: u8 = 10;
const SEC_DATA: u8 = 11;
const SEC_DATACOUNT: u8 = 12;

type D<T> = Result<T, DecodeError>;

fn malformed(msg: &str) -> DecodeError {
    DecodeError::malformed(msg)
}

/// モジュール全体をデコードする。
/// Ref: SPEC-WASM-CORE 5.5.1.
pub fn decode_module(bytes: &[u8]) -> D<Module> {
    let mut r = Reader::new(bytes);
    let magic = r.take(4)?;
    if magic != b"\0asm" {
        return Err(malformed("magic header not detected"));
    }
    let version = r.take(4)?;
    if version != [1, 0, 0, 0] {
        return Err(malformed("unknown binary version"));
    }
    let mut m = Module::default();
    // custom(0) 以外のセクションは仕様の定義順・各 1 回。
    // datacount(12) は elem(9) と code(10) の間に置かれるため、
    // 順序は id の数値順ではなく専用の順位で見る。
    let mut last_rank = 0u8;
    while r.remaining() > 0 {
        let id = r.byte()?;
        let size = r.u32()? as usize;
        if size > r.remaining() {
            return Err(malformed("length out of bounds"));
        }
        let end = r.pos + size;
        if id != 0 {
            let rank = match id {
                1..=9 => id,
                SEC_DATACOUNT => 10,
                SEC_CODE => 11,
                SEC_DATA => 12,
                _ => return Err(malformed("malformed section id")),
            };
            // 順位の単調増加が重複と順序違反の両方を拒否する。
            if rank <= last_rank {
                return Err(malformed("unexpected content after last section"));
            }
            last_rank = rank;
        }
        if id == 0 {
            // custom: name + 残りのバイト。名前は UTF-8 で宣言長を超えない。
            let payload = r.take(size)?;
            let mut sr = Reader::new(payload);
            sr.name()?;
            continue;
        }
        // 非 custom セクションは主流から読む。スカラのフィールドは宣言
        // サイズを超えて読み進め得るが、式は `r.limit` で打ち止められる。
        // 消費量と宣言の差異は最後に section size mismatch で検出する。
        r.limit = end;
        let inner = match id {
            SEC_TYPE => sec_types(&mut r, &mut m),
            SEC_IMPORT => sec_imports(&mut r, &mut m),
            SEC_FUNC => sec_funcs(&mut r, &mut m),
            SEC_TABLE => sec_tables(&mut r, &mut m),
            SEC_MEM => sec_mems(&mut r, &mut m),
            SEC_GLOBAL => sec_globals(&mut r, &mut m),
            SEC_EXPORT => sec_exports(&mut r, &mut m),
            SEC_START => r.u32().map(|v| m.start = Some(v)),
            SEC_ELEM => sec_elems(&mut r, &mut m),
            SEC_CODE => sec_code(&mut r, &mut m),
            SEC_DATA => sec_datas(&mut r, &mut m),
            SEC_DATACOUNT => r.u32().map(|v| m.data_count = Some(v)),
            _ => unreachable!(),
        };
        r.limit = r.bytes.len();
        if let Err(e) = inner {
            // セクション内部でバイト列が尽きたときの文言。
            if e.0 == "unexpected end" {
                return Err(malformed("unexpected end of section or function"));
            }
            return Err(e);
        }
        if r.pos != end {
            return Err(malformed("section size mismatch"));
        }
    }
    if m.funcs.len() != m.code.len() {
        return Err(malformed(
            "function and code section have inconsistent lengths",
        ));
    }
    if let Some(dc) = m.data_count
        && dc as usize != m.datas.len()
    {
        return Err(malformed(
            "data count and data section have inconsistent lengths",
        ));
    }
    Ok(m)
}

fn vec_count(r: &mut Reader) -> D<usize> {
    // 要素数と残りバイト数の照合は行わない。要素読み出しが尽きれば
    // "unexpected end of section or function" となる（仕様実装と同じ）。
    Ok(r.u32()? as usize)
}

fn func_type(r: &mut Reader) -> D<FuncType> {
    let tag = r.byte7()?;
    if tag != 0x60 {
        return Err(malformed("malformed functype"));
    }
    let np = vec_count(r)?;
    let mut params = Vec::with_capacity(np.min(1024));
    for _ in 0..np {
        params.push(read_val_type(r)?);
    }
    let nr = vec_count(r)?;
    let mut results = Vec::with_capacity(nr.min(1024));
    for _ in 0..nr {
        results.push(read_val_type(r)?);
    }
    Ok(FuncType { params, results })
}

/// limits の min/max。仕様実装は u64 まで読んでから範囲検査するため、
/// 10 バイト超の LEB は「integer too large」になる。
fn limit_u32(r: &mut Reader) -> D<u32> {
    let v = r.uleb(64)?;
    u32::try_from(v).map_err(|_| malformed("integer too large"))
}

fn limits(r: &mut Reader) -> D<Limits> {
    let flag = r.byte()?;
    match flag {
        0x00 => {
            let min = limit_u32(r)?;
            Ok(Limits { min, max: None })
        }
        0x01 => {
            let min = limit_u32(r)?;
            let max = limit_u32(r)?;
            Ok(Limits {
                min,
                max: Some(max),
            })
        }
        _ => Err(malformed("malformed limits flags")),
    }
}

/// 参照型の読み出し。短縮形 `0x70`/`0x6f` とヒープ型形
/// `0x63/0x64 + heaptype`（2.0）の両方を受理し、内部の
/// RefType（nullability を持たない）に写す。戻り値の第2要素は
/// `0x64`（non-null `(ref ht)`）のとき true。
fn read_ref_type(r: &mut Reader) -> D<(RefType, bool)> {
    match r.byte7()? {
        0x70 => Ok((RefType::Func, false)),
        0x6f => Ok((RefType::Extern, false)),
        0x63 => crate::instr::heap_type(r).map(|t| (t, false)),
        0x64 => crate::instr::heap_type(r).map(|t| (t, true)),
        _ => Err(malformed("malformed reference type")),
    }
}

/// 値型。`0x63/0x64`（`(ref (null) ht)` 形）はヒープ型が続くので
/// `read_ref_type` に回し、それ以外は単バイトの `val_type`。
fn read_val_type(r: &mut Reader) -> D<ValType> {
    match r.byte7()? {
        0x63 | 0x64 => {
            r.pos -= 1;
            Ok(ValType::Ref(read_ref_type(r)?.0))
        }
        b => val_type(b).ok_or_else(|| malformed("malformed value type")),
    }
}

/// テーブル型。戻り値の `Some` は 2.0 の初期化式
/// (`0x40 0x00 reftype limits expr` 形）を含み、`bool` は
/// 要素型が non-null か。
fn table_type(r: &mut Reader) -> D<(TableType, Option<ConstExpr>, bool)> {
    // 初期化式つき形の先頭バイト。
    if r.bytes.get(r.pos) == Some(&0x40) {
        r.byte()?;
        if r.byte()? != 0x00 {
            return Err(malformed("malformed table type"));
        }
        let (et, nn) = read_ref_type(r)?;
        let lim = limits(r)?;
        let init = const_expr(r)?;
        return Ok((TableType { et, lim }, Some(init), nn));
    }
    let (et, nn) = read_ref_type(r)?;
    let lim = limits(r)?;
    Ok((TableType { et, lim }, None, nn))
}

fn global_type(r: &mut Reader) -> D<GlobalType> {
    let vt = read_val_type(r)?;
    let mutable = match r.byte()? {
        0x00 => false,
        0x01 => true,
        _ => return Err(malformed("malformed mutability")),
    };
    Ok(GlobalType { vt, mutable })
}

/// 定数式（`end` で終わる命令列）。
fn const_expr(r: &mut Reader) -> D<ConstExpr> {
    let mut instrs = Vec::new();
    loop {
        // 式はセクションの宣言終端で打ち止められる（仕様実装と同じ）。
        if r.pos >= r.limit {
            return Err(malformed("unexpected end"));
        }
        let ins = instr::one(r)?;
        let end = matches!(ins, instr::Instr::End);
        instrs.push(ins);
        if end {
            return Ok(ConstExpr { instrs });
        }
    }
}

fn sec_types(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        m.types.push(func_type(r)?);
    }
    Ok(())
}

fn sec_imports(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        let module = r.name()?;
        let name = r.name()?;
        let kind = r.byte()?;
        let desc = match kind {
            0x00 => ImportDesc::Func(r.u32()?),
            0x01 => ImportDesc::Table(table_type(r)?.0),
            0x02 => ImportDesc::Mem(MemType { lim: limits(r)? }),
            0x03 => ImportDesc::Global(global_type(r)?),
            _ => return Err(malformed("malformed import kind")),
        };
        m.imports.push(Import { module, name, desc });
    }
    Ok(())
}

fn sec_funcs(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        m.funcs.push(r.u32()?);
    }
    Ok(())
}

fn sec_tables(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        let (t, init, nn) = table_type(r)?;
        m.tables.push(t);
        m.table_inits.push(init);
        m.table_nonnull.push(nn);
    }
    Ok(())
}

fn sec_mems(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        m.mems.push(MemType { lim: limits(r)? });
    }
    Ok(())
}

fn sec_globals(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        let ty = global_type(r)?;
        let init = const_expr(r)?;
        m.globals.push(Global { ty, init });
    }
    Ok(())
}

fn sec_exports(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        let name = r.name()?;
        let kind = r.byte()?;
        if kind > 3 {
            return Err(malformed("malformed export kind"));
        }
        let idx = r.u32()?;
        m.exports.push(Export { name, kind, idx });
    }
    Ok(())
}

fn sec_elems(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        let flag = r.u32()?;
        let elem = match flag {
            0 => {
                let offset = const_expr(r)?;
                let funcs = func_idx_vec(r)?;
                Elem {
                    ty: RefType::Func,
                    // funcidx 列の要素型は non-null の `(ref func)`。
                    nonnull: true,
                    init: ElemItem::Funcs(funcs),
                    mode: ElemMode::Active { table: 0, offset },
                }
            }
            1 => {
                elem_kind(r)?;
                let funcs = func_idx_vec(r)?;
                Elem {
                    ty: RefType::Func,
                    // funcidx 列の要素型は non-null の `(ref func)`。
                    nonnull: true,
                    init: ElemItem::Funcs(funcs),
                    mode: ElemMode::Passive,
                }
            }
            2 => {
                let table = r.u32()?;
                let offset = const_expr(r)?;
                elem_kind(r)?;
                let funcs = func_idx_vec(r)?;
                Elem {
                    ty: RefType::Func,
                    // funcidx 列の要素型は non-null の `(ref func)`。
                    nonnull: true,
                    init: ElemItem::Funcs(funcs),
                    mode: ElemMode::Active { table, offset },
                }
            }
            3 => {
                elem_kind(r)?;
                let funcs = func_idx_vec(r)?;
                Elem {
                    ty: RefType::Func,
                    // funcidx 列の要素型は non-null の `(ref func)`。
                    nonnull: true,
                    init: ElemItem::Funcs(funcs),
                    mode: ElemMode::Declared,
                }
            }
            4 => {
                let offset = const_expr(r)?;
                let exprs = expr_vec(r)?;
                Elem {
                    ty: RefType::Func,
                    nonnull: false,
                    init: ElemItem::Exprs(exprs),
                    mode: ElemMode::Active { table: 0, offset },
                }
            }
            5 => {
                let (ty, nonnull) = elem_ref_type(r)?;
                let exprs = expr_vec(r)?;
                Elem {
                    ty,
                    nonnull,
                    init: ElemItem::Exprs(exprs),
                    mode: ElemMode::Passive,
                }
            }
            6 => {
                let table = r.u32()?;
                let offset = const_expr(r)?;
                let (ty, nonnull) = elem_ref_type(r)?;
                let exprs = expr_vec(r)?;
                Elem {
                    ty,
                    nonnull,
                    init: ElemItem::Exprs(exprs),
                    mode: ElemMode::Active { table, offset },
                }
            }
            7 => {
                let (ty, nonnull) = elem_ref_type(r)?;
                let exprs = expr_vec(r)?;
                Elem {
                    ty,
                    nonnull,
                    init: ElemItem::Exprs(exprs),
                    mode: ElemMode::Declared,
                }
            }
            _ => return Err(malformed("malformed elem segment flag")),
        };
        m.elems.push(elem);
    }
    Ok(())
}

/// elemkind バイト（0x00 = funcref）の検査。
fn elem_kind(r: &mut Reader) -> D<()> {
    if r.byte()? != 0x00 {
        return Err(malformed("malformed elemkind"));
    }
    Ok(())
}

/// elem セグメントの reftype。`(RefType, nonnull)` を返す。
fn elem_ref_type(r: &mut Reader) -> D<(RefType, bool)> {
    read_ref_type(r)
}

fn func_idx_vec(r: &mut Reader) -> D<Vec<u32>> {
    let n = vec_count(r)?;
    let mut out = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        out.push(r.u32()?);
    }
    Ok(out)
}

fn expr_vec(r: &mut Reader) -> D<Vec<ConstExpr>> {
    let n = vec_count(r)?;
    let mut out = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        out.push(const_expr(r)?);
    }
    Ok(out)
}

fn sec_code(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        let size = r.u32()? as usize;
        // 本体式は宣言サイズを超えて読み進め得る。終端 `end` まで読んで
        // から消費量と宣言を照合する（仕様実装と同じ）。
        let body_end = r.pos + size;
        let lcount = vec_count(r)?;
        let mut locals = Vec::new();
        for _ in 0..lcount {
            let rep = r.u32()?;
            let t = read_val_type(r)?;
            // 仕様の上限は u32::MAX 個。超えたら展開前に拒否する。
            let total = locals.len() as u64 + u64::from(rep);
            if total > u64::from(u32::MAX) {
                return Err(malformed("too many locals"));
            }
            locals.resize(total as usize, t);
        }
        let istart = r.pos;
        // 命令列の malformed は decode 段で拾う（assert_malformed が
        // decode だけを見るため、遅延解読だと受理扱いになる）。
        let instrs = instr::decode_exprs(r)?;
        // memory.init / data.drop は datacount セクションを要求する。
        if m.data_count.is_none()
            && instrs
                .iter()
                .any(|i| matches!(i, instr::Instr::MemoryInit(_) | instr::Instr::DataDrop(_)))
        {
            return Err(malformed("data count section required"));
        }
        let body = r.bytes[istart..r.pos].to_vec();
        if r.pos != body_end {
            return Err(malformed("section size mismatch"));
        }
        m.code.push(Code { locals, body });
    }
    Ok(())
}

fn sec_datas(r: &mut Reader, m: &mut Module) -> D<()> {
    let n = vec_count(r)?;
    for _ in 0..n {
        let flag = r.u32()?;
        let data = match flag {
            0 => {
                let offset = const_expr(r)?;
                let bytes = r.bytes()?;
                Data {
                    mode: DataMode::Active { mem: 0, offset },
                    bytes,
                }
            }
            1 => {
                let bytes = r.bytes()?;
                Data {
                    mode: DataMode::Passive,
                    bytes,
                }
            }
            2 => {
                let mem = r.u32()?;
                let offset = const_expr(r)?;
                let bytes = r.bytes()?;
                Data {
                    mode: DataMode::Active { mem, offset },
                    bytes,
                }
            }
            _ => return Err(malformed("malformed data segment flag")),
        };
        m.datas.push(data);
    }
    Ok(())
}
