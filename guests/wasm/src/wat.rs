// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! WebAssembly テキスト形式（`.wat`）からバイナリへの変換。
//!
//! `.wast` の `module` ディレクティブと `assert_malformed (module quote ..)`
//! が必要とする全構文をカバーする：typeuse、`$` 名の各指標空間、
//! 畳み込み式とフラットな命令列、block/if/else/end、`br_table`、
//! `offset=`/`align=` の memarg、数値・16進浮動小数・文字列、
//! エレメント7形態・データ3形態、inline import/export、`elem`/`data` の
//! インライン初期化、`(module binary|quote)`。
//!
//! 変換はテキスト AST → バイナリの一直線で、結果は `decode`/`validate`
//! に通して使う（テキスト側の解読ミスが実行へ漏れないようにする）。
//! Ref: SPEC-WASM-CORE 6（テキスト形式）.

use std::collections::HashMap;

use crate::sexpr::Sx;
use crate::types::*;

/// テキスト形式のエラー。`assert_malformed` の期待文言に寄せる。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WatErr(pub String);

impl std::fmt::Display for WatErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type R<T> = Result<T, WatErr>;

fn err(msg: &str) -> WatErr {
    WatErr(msg.to_string())
}

// ---------------------------------------------------------------------------
// LEB128 などの小さな出力器
// ---------------------------------------------------------------------------

fn ulebs(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn slebs(out: &mut Vec<u8>, mut v: i64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        let sign = b & 0x40;
        v >>= 7;
        if (v == 0 && sign == 0) || (v == -1 && sign != 0) {
            out.push(b);
            break;
        }
        b |= 0x80;
        out.push(b);
    }
}

fn emit_name(out: &mut Vec<u8>, s: &str) {
    ulebs(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn emit_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    ulebs(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn emit_section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
    out.push(id);
    ulebs(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn emit_valtype(out: &mut Vec<u8>, t: ValType) {
    out.push(match t {
        ValType::I32 => 0x7f,
        ValType::I64 => 0x7e,
        ValType::F32 => 0x7d,
        ValType::F64 => 0x7c,
        ValType::V128 => 0x7b,
        ValType::Ref(r) => r.code(),
    });
}

fn emit_limits(out: &mut Vec<u8>, lim: &Limits) {
    match lim.max {
        None => {
            out.push(0);
            ulebs(out, u64::from(lim.min));
        }
        Some(mx) => {
            out.push(1);
            ulebs(out, u64::from(lim.min));
            ulebs(out, u64::from(mx));
        }
    }
}

// ---------------------------------------------------------------------------
// アトムの解析：数値・指標・型
// ---------------------------------------------------------------------------

/// `_` を除いた数字列を `u128` として読む（10進・16進）。
/// `_` は数字同士の間にしか置けない（spec の num 字句規則）。
fn underscores_ok(s: &str, hex: bool) -> bool {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'_' {
            let ok = |c: u8| {
                if hex {
                    c.is_ascii_hexdigit()
                } else {
                    c.is_ascii_digit()
                }
            };
            if i == 0 || i + 1 == b.len() || !ok(b[i - 1]) || !ok(b[i + 1]) {
                return false;
            }
        }
    }
    true
}

fn parse_int_digits(s: &str) -> R<u128> {
    let s: String = s.chars().filter(|c| *c != '_').collect();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).map_err(|_| err("unknown operator"))
    } else {
        s.parse::<u128>().map_err(|_| err("unknown operator"))
    }
}

/// 符号付き整数（`+`/`-` 接頭辞を許す）。
pub(crate) fn parse_int_signed(s: &str) -> R<i128> {
    let (neg, t) = match s.strip_prefix('-') {
        Some(t) => (true, t),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if !underscores_ok(t, t.starts_with("0x") || t.starts_with("0X")) {
        return Err(err("unknown operator"));
    }
    let v = parse_int_digits(t)? as i128;
    Ok(if neg { -v } else { v })
}

/// 16進浮動小数 `0x<mant>.<frac>p<exp>` を仮数と指数に分解する。
fn hexfloat_parts(s: &str) -> R<(u128, i64)> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| err("unknown operator"))?;
    let (mant_s, exp_s) = match body.split_once(['p', 'P']) {
        Some((m, e)) => (m, e),
        None => (body, "0"),
    };
    if !underscores_ok(mant_s, true) || !underscores_ok(exp_s, false) {
        return Err(err("unknown operator"));
    }
    let e: i64 = exp_s.parse().map_err(|_| err("unknown operator"))?;
    let (ip, fp) = match mant_s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mant_s, ""),
    };
    // 少なくとも 1 つの 16 進桁が必要。
    if ip.chars().chain(fp.chars()).all(|c| c == '_') {
        return Err(err("unknown operator"));
    }
    let mut mant: u128 = 0;
    let mut dropped = 0i64;
    let mut sticky = false;
    for c in ip.chars().chain(fp.chars()) {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(16).ok_or_else(|| err("unknown operator"))?;
        // u128 を超える下位桁は捨てて指数側に回し、丸め判定用の
        // sticky ビットに畳み込む。
        match mant
            .checked_mul(16)
            .and_then(|m| m.checked_add(u128::from(d)))
        {
            Some(m) => mant = m,
            None => {
                sticky |= d != 0;
                dropped += 1;
            }
        }
    }
    let frac_bits = 4 * fp.chars().filter(|c| *c != '_').count() as i64;
    // 捨てた桁は mant の 16 倍ずつだった → 指数を 4 ずつ戻す。
    // sticky は丸め判定用に最下位ビットとして残す。
    let mut e = e - frac_bits + 4 * dropped;
    if sticky || dropped > 0 {
        if let Some(m) = mant.checked_shl(1) {
            mant = m | u128::from(sticky);
            e -= 1;
        } else {
            mant |= u128::from(sticky);
        }
    }
    Ok((mant, e))
}

/// `m` を `drop` ビット捨てて roundTiesToEven する。
fn shift_round(m: u128, drop: u32) -> u128 {
    if drop == 0 {
        return m;
    }
    if drop > 128 {
        return 0;
    }
    if drop == 128 {
        // hi は 0 で、仮数全部が捨てられる。ちょうど半分（m == 2^127）は
        // タイで偶数側の 0、それより大きければ 1。
        return u128::from(m > (1u128 << 127));
    }
    let low = m & ((1u128 << drop) - 1);
    let half = 1u128 << (drop - 1);
    let mut hi = m >> drop;
    if low > half || (low == half && (hi & 1) == 1) {
        hi += 1;
    }
    hi
}

/// 値 `mant * 2^e` を IEEE 浮動小数点ビットに変換する（roundTiesToEven）。
/// `ebits`/`fbits` は指数・仮数のビット数。
fn float_bits_of(mant: u128, e: i64, ebits: u32, fbits: u32) -> u64 {
    if mant == 0 {
        return 0;
    }
    let emax = (1i64 << (ebits - 1)) - 1;
    let emin = 1 - emax;
    let msb = 127 - mant.leading_zeros() as i64; // mant の最上位ビット位置
    let mut exp2 = msb + e; // 実値の二進指数（mant が 1.xxx 相当になる指数）
    // 正規数として prec=fbits+1 桁に丸める。
    let prec = i64::from(fbits) + 1;
    let drop = (msb + 1 - prec).max(0) as u32;
    let mut m = shift_round(mant, drop);
    // 丸めで桁上がりしたら指数を上げる。
    if m >> (prec) != 0 {
        m >>= 1;
        exp2 += 1;
    }
    if exp2 > emax {
        return inf_bits(ebits);
    }
    if exp2 >= emin {
        let expf = ((exp2 + emax) as u64) << fbits;
        // 正規化：先頭の 1 を prec-1 位に揃えてから隠れビットを除く。
        let msb2 = (127 - m.leading_zeros()) as i64;
        let sh = (prec - 1 - msb2).max(0) as u32;
        let frac = ((m as u64) << sh) & ((1u64 << fbits) - 1);
        return expf | frac;
    }
    // 非正規数：値 = mant × 2^e を
    // field × 2^(emin - fbits) の形に合わせる。
    // 丸め桁上がり後の exp2 ではなく元の e を使う（桁上がりで
    // 指数が 1 増えたまま計算すると field が 1 ulp 高くなる）。
    let shift = e - emin + i64::from(fbits);
    let m2 = if shift >= 0 {
        // 非正規なので field < 2^fbits、シフト量は必ず u32 に収まる。
        mant << (shift as u32)
    } else {
        shift_round(mant, (-shift) as u32)
    };
    // 非正規の最大は 2^fbits-1。繰り上がりで最小正規数になることもある。
    if m2 >> fbits != 0 {
        return 1u64 << fbits;
    }
    (m2 as u64) & ((1u64 << fbits) - 1)
}

fn inf_bits(ebits: u32) -> u64 {
    match ebits {
        8 => 0x7f80_0000,
        _ => 0x7ff0_0000_0000_0000,
    }
}

enum NanKind {
    Canonical,
    Arith,
}

fn nan_bits(f32_bits: bool, kind: Option<NanKind>) -> u64 {
    let payload = match kind {
        None | Some(NanKind::Canonical) => 1u64 << if f32_bits { 22 } else { 51 },
        Some(NanKind::Arith) => (1u64 << if f32_bits { 22 } else { 51 }) | 1,
    };
    let exp = if f32_bits {
        0x7f80_0000u64
    } else {
        0x7ff0_0000_0000_0000u64
    };
    exp | payload
}

fn nan_payload(f32_bits: bool, p: u64) -> u64 {
    let mask = if f32_bits {
        0x007f_ffffu64
    } else {
        0x000f_ffff_ffff_ffffu64
    };
    let exp = if f32_bits {
        0x7f80_0000u64
    } else {
        0x7ff0_0000_0000_0000u64
    };
    exp | (p & mask)
}

/// 浮動小数アトム → ビット列。
pub(crate) fn parse_float_bits(s: &str, f32_bits: bool) -> R<u64> {
    let (neg, t) = match s.strip_prefix('-') {
        Some(t) => (true, t),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let sign = u64::from(neg) << if f32_bits { 31 } else { 63 };
    let hex = t.starts_with("0x") || t.starts_with("0X") || t.contains("nan:0x");
    if !underscores_ok(t, hex) {
        return Err(err("unknown operator"));
    }
    let clean: String = t.chars().filter(|c| *c != '_').collect();
    match clean.as_str() {
        "inf" => Ok(sign | inf_bits(if f32_bits { 8 } else { 11 })),
        "nan" | "nan:canonical" => Ok(sign | nan_bits(f32_bits, Some(NanKind::Canonical))),
        "nan:arithmetic" => Ok(sign | nan_bits(f32_bits, Some(NanKind::Arith))),
        _ => {
            if let Some(p) = clean.strip_prefix("nan:0x") {
                let payload = u64::from_str_radix(p, 16).map_err(|_| err("unknown operator"))?;
                let max = if f32_bits {
                    0x007f_ffffu64
                } else {
                    0x000f_ffff_ffff_ffffu64
                };
                // payload は 1..=max（0 は NaN ではなく ±inf になる）。
                if payload == 0 || payload > max {
                    return Err(err("constant out of range"));
                }
                return Ok(sign | nan_payload(f32_bits, payload));
            }
            if clean.starts_with("0x") || clean.starts_with("0X") {
                let (mant, e) = hexfloat_parts(&clean)?;
                let (eb, fb) = if f32_bits { (8, 23) } else { (11, 52) };
                let v = float_bits_of(mant, e, eb, fb);
                // 無限大へのあふれは literal の範囲外。
                if v == inf_bits(eb) {
                    return Err(err("constant out of range"));
                }
                return Ok(sign | v);
            }
            // 10進の num 形は先頭が数字。
            if !clean.starts_with(|c: char| c.is_ascii_digit()) {
                return Err(err("unknown operator"));
            }
            let f = if f32_bits {
                f64::from(clean.parse::<f32>().map_err(|_| err("unknown operator"))?)
            } else {
                clean.parse::<f64>().map_err(|_| err("unknown operator"))?
            };
            if f.is_infinite() {
                return Err(err("constant out of range"));
            }
            let bits = if f32_bits {
                u64::from((f as f32).to_bits())
            } else {
                f.to_bits()
            };
            Ok(sign | bits)
        }
    }
}

/// 任意指標アトムか（`$name` または数字始まり）。`end` などの
/// キーワードを指標と誤読しないための判定。
fn idx_atom(sx: &Sx) -> bool {
    match sx.atom() {
        Some(a) if a.starts_with('$') => true,
        Some(a) => a
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '+'),
        None => false,
    }
}

/// `$name` または非負整数の指標。
fn idx_of(sx: &Sx, names: &HashMap<String, u32>, kind: &str) -> R<u32> {
    match sx {
        Sx::Atom(a) if a.starts_with('$') => names
            .get(a.as_str())
            .copied()
            .ok_or_else(|| err(&format!("unknown {kind}"))),
        Sx::Atom(a) => {
            let v = parse_int_signed(a)?;
            if v < 0 || v > i128::from(u32::MAX) {
                return Err(err(&format!("unknown {kind}")));
            }
            Ok(v as u32)
        }
        _ => Err(err(&format!("unknown {kind}"))),
    }
}

fn valtype_of(s: &str) -> Option<ValType> {
    Some(match s {
        "i32" => ValType::I32,
        "i64" => ValType::I64,
        "f32" => ValType::F32,
        "f64" => ValType::F64,
        "v128" => ValType::V128,
        "funcref" => ValType::Ref(RefType::Func),
        "externref" => ValType::Ref(RefType::Extern),
        _ => return None,
    })
}

fn reftype_of(s: &str) -> Option<RefType> {
    match s {
        "funcref" => Some(RefType::Func),
        "externref" => Some(RefType::Extern),
        _ => None,
    }
}

/// 参照型の S 式。アトム `funcref`/`externref` とリスト形
/// `(ref ht)` / `(ref null ht)`（ht = func|extern）を受理する。
/// nullability は内部モデルに持たず Func/Extern に潰す。
/// `(ref [null] ht)` の nullability つき参照型。第2戻り値は non-null。
fn reftype_sx_nn(sx: &Sx) -> Option<(RefType, bool)> {
    if let Some(a) = sx.atom() {
        return reftype_of(a).map(|t| (t, false));
    }
    let l = sx.list()?;
    if l.first().and_then(Sx::atom) != Some("ref") {
        return None;
    }
    let mut j = 1;
    let mut nn = true;
    if l.get(1).and_then(Sx::atom) == Some("null") {
        nn = false;
        j = 2;
    }
    match l.get(j).and_then(Sx::atom) {
        Some("func") => Some((RefType::Func, nn)),
        Some("extern") => Some((RefType::Extern, nn)),
        _ => None,
    }
}

fn reftype_sx(sx: &Sx) -> Option<RefType> {
    reftype_sx_nn(sx).map(|(t, _)| t)
}

/// 値型の S 式。アトムに加え `(ref [null] ht)` も受理する。
/// param/result/global の型位置で使う。
fn valtype_sx(sx: &Sx) -> Option<ValType> {
    if let Some(a) = sx.atom() {
        return valtype_of(a);
    }
    reftype_sx(sx).map(ValType::Ref)
}

// ---------------------------------------------------------------------------
// モジュールの組み立て
// ---------------------------------------------------------------------------

/// エレメント1件（flags の値と残りの組み立て方）。
struct ElemParts {
    flag: u32,
    /// offset 式のバイト列（active のとき）。
    offset: Option<Vec<u8>>,
    table: u32,
    /// `elemkind` バイトまたは reftype バイト。
    kind: RefType,
    /// 要素型が non-null（`(ref ht)`）か。flags 5–7 の reftype を `0x64` 形で出す。
    nonnull: bool,
    /// funcidx 列（flags 0–3）か式列（flags 4–7）。
    funcs: Vec<u32>,
    exprs: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Mb {
    types: Vec<FuncType>,
    type_names: HashMap<String, u32>,
    func_names: HashMap<String, u32>,
    table_names: HashMap<String, u32>,
    mem_names: HashMap<String, u32>,
    global_names: HashMap<String, u32>,
    elem_names: HashMap<String, u32>,
    data_names: HashMap<String, u32>,
    imports: Vec<(String, String, u8, Vec<u8>)>,
    funcs: Vec<u32>,
    codes: Vec<Vec<u8>>,
    tables: Vec<TableType>,
    /// `tables` と同じ長さ。2.0 の初期化式（`0x40 0x00` 形）の生バイト。
    table_inits: Vec<Option<Vec<u8>>>,
    /// `tables` と同じ長さ。要素型が non-null（`(ref ht)`）か。
    table_nonnull: Vec<bool>,
    mems: Vec<Limits>,
    globals: Vec<(GlobalType, Vec<u8>)>,
    elems: Vec<ElemParts>,
    datas: Vec<Vec<u8>>,
    exports: Vec<(String, u8, u32)>,
    start: Option<u32>,
}

impl Mb {
    /// `typeuse` を解決して型指標を返す。`items[*i..]` から
    /// `(type)`/`(param)`/`(result)` の並びを消費する。
    /// 戻り値は解決した typeidx。
    fn type_use(&mut self, items: &[Sx], i: &mut usize) -> R<u32> {
        let mut named: Option<u32> = None;
        let mut params: Vec<ValType> = Vec::new();
        let mut results: Vec<ValType> = Vec::new();
        while *i < items.len() {
            let Some(l) = items[*i].list() else { break };
            match l.first().and_then(Sx::atom) {
                Some("type") => {
                    // `(type)` は typeuse の先頭に1つだけ。
                    if named.is_some() || !params.is_empty() || !results.is_empty() {
                        return Err(err("unexpected token"));
                    }
                    named = Some(idx_of(&l[1], &self.type_names, "type")?);
                    *i += 1;
                }
                Some("param") => {
                    if !results.is_empty() {
                        return Err(err("unexpected token"));
                    }
                    for p in &l[1..] {
                        if p.atom().is_some_and(|a| a.starts_with('$')) {
                            continue;
                        }
                        params.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                    }
                    *i += 1;
                }
                Some("result") => {
                    for p in &l[1..] {
                        results.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                    }
                    *i += 1;
                }
                _ => break,
            }
        }
        if let Some(t) = named {
            if params.is_empty() && results.is_empty() {
                return Ok(t);
            }
            let ft = self
                .types
                .get(t as usize)
                .ok_or_else(|| err("unknown type"))?;
            if ft.params == params && ft.results == results {
                return Ok(t);
            }
            return Err(err("inline function type"));
        }
        let ft = FuncType { params, results };
        if let Some(pos) = self.types.iter().position(|t| *t == ft) {
            return Ok(pos as u32);
        }
        self.types.push(ft);
        Ok(self.types.len() as u32 - 1)
    }
}

/// 命令出力中の文脈。`mb` を `&mut` で持ち、blocktype の型追加を許す。
struct FnCx<'m> {
    mb: &'m mut Mb,
    locals: HashMap<String, u32>,
    labels: Vec<Option<String>>,
}

/// 命令列のカーソル。
struct Cur<'a> {
    items: &'a [Sx],
    i: usize,
}

// ---------------------------------------------------------------------------
// 無即値・接頭辞・メモリ命令の表
// ---------------------------------------------------------------------------

fn simple_opcode(name: &str) -> Option<&'static [u8]> {
    Some(match name {
        "unreachable" => &[0x00],
        "nop" => &[0x01],
        "return" => &[0x0f],
        "drop" => &[0x1a],
        "select" => &[0x1b],
        "memory.size" => &[0x3f, 0x00],
        "memory.grow" => &[0x40, 0x00],
        "i32.eqz" => &[0x45],
        "i32.eq" => &[0x46],
        "i32.ne" => &[0x47],
        "i32.lt_s" => &[0x48],
        "i32.lt_u" => &[0x49],
        "i32.gt_s" => &[0x4a],
        "i32.gt_u" => &[0x4b],
        "i32.le_s" => &[0x4c],
        "i32.le_u" => &[0x4d],
        "i32.ge_s" => &[0x4e],
        "i32.ge_u" => &[0x4f],
        "i64.eqz" => &[0x50],
        "i64.eq" => &[0x51],
        "i64.ne" => &[0x52],
        "i64.lt_s" => &[0x53],
        "i64.lt_u" => &[0x54],
        "i64.gt_s" => &[0x55],
        "i64.gt_u" => &[0x56],
        "i64.le_s" => &[0x57],
        "i64.le_u" => &[0x58],
        "i64.ge_s" => &[0x59],
        "i64.ge_u" => &[0x5a],
        "f32.eq" => &[0x5b],
        "f32.ne" => &[0x5c],
        "f32.lt" => &[0x5d],
        "f32.gt" => &[0x5e],
        "f32.le" => &[0x5f],
        "f32.ge" => &[0x60],
        "f64.eq" => &[0x61],
        "f64.ne" => &[0x62],
        "f64.lt" => &[0x63],
        "f64.gt" => &[0x64],
        "f64.le" => &[0x65],
        "f64.ge" => &[0x66],
        "i32.clz" => &[0x67],
        "i32.ctz" => &[0x68],
        "i32.popcnt" => &[0x69],
        "i32.add" => &[0x6a],
        "i32.sub" => &[0x6b],
        "i32.mul" => &[0x6c],
        "i32.div_s" => &[0x6d],
        "i32.div_u" => &[0x6e],
        "i32.rem_s" => &[0x6f],
        "i32.rem_u" => &[0x70],
        "i32.and" => &[0x71],
        "i32.or" => &[0x72],
        "i32.xor" => &[0x73],
        "i32.shl" => &[0x74],
        "i32.shr_s" => &[0x75],
        "i32.shr_u" => &[0x76],
        "i32.rotl" => &[0x77],
        "i32.rotr" => &[0x78],
        "i64.clz" => &[0x79],
        "i64.ctz" => &[0x7a],
        "i64.popcnt" => &[0x7b],
        "i64.add" => &[0x7c],
        "i64.sub" => &[0x7d],
        "i64.mul" => &[0x7e],
        "i64.div_s" => &[0x7f],
        "i64.div_u" => &[0x80],
        "i64.rem_s" => &[0x81],
        "i64.rem_u" => &[0x82],
        "i64.and" => &[0x83],
        "i64.or" => &[0x84],
        "i64.xor" => &[0x85],
        "i64.shl" => &[0x86],
        "i64.shr_s" => &[0x87],
        "i64.shr_u" => &[0x88],
        "i64.rotl" => &[0x89],
        "i64.rotr" => &[0x8a],
        "f32.abs" => &[0x8b],
        "f32.neg" => &[0x8c],
        "f32.ceil" => &[0x8d],
        "f32.floor" => &[0x8e],
        "f32.trunc" => &[0x8f],
        "f32.nearest" => &[0x90],
        "f32.sqrt" => &[0x91],
        "f32.add" => &[0x92],
        "f32.sub" => &[0x93],
        "f32.mul" => &[0x94],
        "f32.div" => &[0x95],
        "f32.min" => &[0x96],
        "f32.max" => &[0x97],
        "f32.copysign" => &[0x98],
        "f64.abs" => &[0x99],
        "f64.neg" => &[0x9a],
        "f64.ceil" => &[0x9b],
        "f64.floor" => &[0x9c],
        "f64.trunc" => &[0x9d],
        "f64.nearest" => &[0x9e],
        "f64.sqrt" => &[0x9f],
        "f64.add" => &[0xa0],
        "f64.sub" => &[0xa1],
        "f64.mul" => &[0xa2],
        "f64.div" => &[0xa3],
        "f64.min" => &[0xa4],
        "f64.max" => &[0xa5],
        "f64.copysign" => &[0xa6],
        "i32.wrap_i64" => &[0xa7],
        "i32.trunc_f32_s" => &[0xa8],
        "i32.trunc_f32_u" => &[0xa9],
        "i32.trunc_f64_s" => &[0xaa],
        "i32.trunc_f64_u" => &[0xab],
        "i64.extend_i32_s" => &[0xac],
        "i64.extend_i32_u" => &[0xad],
        "i64.trunc_f32_s" => &[0xae],
        "i64.trunc_f32_u" => &[0xaf],
        "i64.trunc_f64_s" => &[0xb0],
        "i64.trunc_f64_u" => &[0xb1],
        "f32.convert_i32_s" => &[0xb2],
        "f32.convert_i32_u" => &[0xb3],
        "f32.convert_i64_s" => &[0xb4],
        "f32.convert_i64_u" => &[0xb5],
        "f32.demote_f64" => &[0xb6],
        "f64.convert_i32_s" => &[0xb7],
        "f64.convert_i32_u" => &[0xb8],
        "f64.convert_i64_s" => &[0xb9],
        "f64.convert_i64_u" => &[0xba],
        "f64.promote_f32" => &[0xbb],
        "i32.reinterpret_f32" => &[0xbc],
        "i64.reinterpret_f64" => &[0xbd],
        "f32.reinterpret_i32" => &[0xbe],
        "f64.reinterpret_i64" => &[0xbf],
        "i32.extend8_s" => &[0xc0],
        "i32.extend16_s" => &[0xc1],
        "i64.extend8_s" => &[0xc2],
        "i64.extend16_s" => &[0xc3],
        "i64.extend32_s" => &[0xc4],
        "ref.is_null" => &[0xd1],
        "memory.copy" => &[0xfc, 0x0a, 0x00, 0x00],
        "memory.fill" => &[0xfc, 0x0b, 0x00],
        _ => return None,
    })
}

/// 0xfc 接頭辞の無即値命令（名前 → 接尾コード）。
fn fc_imm_opcode(name: &str) -> Option<u32> {
    Some(match name {
        "i32.trunc_sat_f32_s" => 0x00,
        "i32.trunc_sat_f32_u" => 0x01,
        "i32.trunc_sat_f64_s" => 0x02,
        "i32.trunc_sat_f64_u" => 0x03,
        "i64.trunc_sat_f32_s" => 0x04,
        "i64.trunc_sat_f32_u" => 0x05,
        "i64.trunc_sat_f64_s" => 0x06,
        "i64.trunc_sat_f64_u" => 0x07,
        _ => return None,
    })
}

/// メモリアクセス命令（名前 → (オペコード, 既定アライン指数)）。
fn mem_opcode(name: &str) -> Option<(u8, u32)> {
    Some(match name {
        "i32.load" => (0x28, 2),
        "i64.load" => (0x29, 3),
        "f32.load" => (0x2a, 2),
        "f64.load" => (0x2b, 3),
        "i32.load8_s" => (0x2c, 0),
        "i32.load8_u" => (0x2d, 0),
        "i32.load16_s" => (0x2e, 1),
        "i32.load16_u" => (0x2f, 1),
        "i64.load8_s" => (0x30, 0),
        "i64.load8_u" => (0x31, 0),
        "i64.load16_s" => (0x32, 1),
        "i64.load16_u" => (0x33, 1),
        "i64.load32_s" => (0x34, 2),
        "i64.load32_u" => (0x35, 2),
        "i32.store" => (0x36, 2),
        "i64.store" => (0x37, 3),
        "f32.store" => (0x38, 2),
        "f64.store" => (0x39, 3),
        "i32.store8" => (0x3a, 0),
        "i32.store16" => (0x3b, 1),
        "i64.store8" => (0x3c, 0),
        "i64.store16" => (0x3d, 1),
        "i64.store32" => (0x3e, 2),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// 関数本体の出力
// ---------------------------------------------------------------------------

fn local_idx(cx: &FnCx, sx: &Sx) -> R<u32> {
    match sx {
        Sx::Atom(a) if a.starts_with('$') => cx
            .locals
            .get(a.as_str())
            .copied()
            .ok_or_else(|| err("unknown local")),
        _ => idx_of(sx, &HashMap::new(), "local"),
    }
}

fn label_idx(cx: &FnCx, sx: &Sx) -> R<u32> {
    match sx {
        Sx::Atom(a) if a.starts_with('$') => {
            for (d, n) in cx.labels.iter().rev().enumerate() {
                if n.as_deref() == Some(a.as_str()) {
                    return Ok(d as u32);
                }
            }
            Err(err("unknown label"))
        }
        _ => {
            let v = parse_int_signed(sx.atom().unwrap_or(""))?;
            if v < 0 || v > i128::from(u32::MAX) {
                return Err(err("unknown label"));
            }
            Ok(v as u32)
        }
    }
}

/// blocktype 修飾列を読み取り即値バイトに変換する。
fn blocktype_imm(cx: &mut FnCx, items: &[Sx], i: &mut usize) -> R<Vec<u8>> {
    let mut named: Option<u32> = None;
    let mut params: Vec<ValType> = Vec::new();
    let mut results: Vec<ValType> = Vec::new();
    while *i < items.len() {
        let Some(l) = items[*i].list() else { break };
        match l.first().and_then(Sx::atom) {
            Some("type") => {
                if named.is_some() || !params.is_empty() || !results.is_empty() {
                    return Err(err("unexpected token"));
                }
                named = Some(idx_of(&l[1], &cx.mb.type_names, "type")?);
                *i += 1;
            }
            Some("param") => {
                if !results.is_empty() {
                    return Err(err("unexpected token"));
                }
                for p in &l[1..] {
                    // blocktype の param に名は許されない。
                    if p.atom().is_some_and(|a| a.starts_with('$')) {
                        return Err(err("unexpected token"));
                    }
                    params.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                }
                *i += 1;
            }
            Some("result") => {
                for p in &l[1..] {
                    results.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                }
                *i += 1;
            }
            _ => break,
        }
    }
    let mut out = Vec::new();
    if let Some(t) = named {
        if params.is_empty() && results.is_empty() {
            slebs(&mut out, i64::from(t));
            return Ok(out);
        }
        let ft = cx
            .mb
            .types
            .get(t as usize)
            .ok_or_else(|| err("unknown type"))?;
        if ft.params == params && ft.results == results {
            slebs(&mut out, i64::from(t));
            return Ok(out);
        }
        return Err(err("inline function type"));
    }
    match (params.len(), results.len()) {
        (0, 0) => out.push(0x40),
        (0, 1) => emit_valtype(&mut out, results[0]),
        _ => {
            let ft = FuncType { params, results };
            let t = match cx.mb.types.iter().position(|x| *x == ft) {
                Some(p) => p as u32,
                None => {
                    cx.mb.types.push(ft);
                    cx.mb.types.len() as u32 - 1
                }
            };
            slebs(&mut out, i64::from(t));
        }
    }
    Ok(out)
}

/// フラットな命令列を `end`/`else` まで出力する。
/// 戻り値は見つけた終端語。
fn emit_seq(cx: &mut FnCx, cur: &mut Cur, out: &mut Vec<u8>) -> R<Option<String>> {
    while cur.i < cur.items.len() {
        match &cur.items[cur.i] {
            Sx::Atom(a) => match a.as_str() {
                "end" | "else" => {
                    // 終端語と、あれば再掲ラベル名 (`end $l`) を消費する。
                    cur.i += 1;
                    let mut restated = None;
                    if let Some(Sx::Atom(n)) = cur.items.get(cur.i)
                        && n.starts_with('$')
                    {
                        restated = Some(n.clone());
                        cur.i += 1;
                    }
                    // 再掲ラベルは内側ブロックのラベルと一致しなければならない。
                    if let Some(n) = &restated {
                        let want = cx.labels.last().and_then(|o| o.as_deref());
                        if want != Some(n.as_str()) {
                            return Err(err("mismatching label"));
                        }
                    }
                    return Ok(Some(a.clone()));
                }
                "block" | "loop" | "if" => {
                    cur.i += 1;
                    let mut lname = None;
                    if let Some(Sx::Atom(n)) = cur.items.get(cur.i)
                        && n.starts_with('$')
                    {
                        lname = Some(n.clone());
                        cur.i += 1;
                    }
                    let bt = blocktype_imm(cx, cur.items, &mut cur.i)?;
                    cx.labels.push(lname);
                    out.push(match a.as_str() {
                        "block" => 0x02,
                        "loop" => 0x03,
                        _ => 0x04,
                    });
                    out.extend_from_slice(&bt);
                    let is_if = a == "if";
                    let term = emit_seq(cx, cur, out)?;
                    match (is_if, term.as_deref()) {
                        (true, Some("else")) => {
                            out.push(0x05);
                            let t2 = emit_seq(cx, cur, out)?;
                            cx.labels.pop();
                            if t2.as_deref() != Some("end") {
                                return Err(err("expected end"));
                            }
                        }
                        (_, Some("end")) => {
                            cx.labels.pop();
                        }
                        _ => {
                            cx.labels.pop();
                            return Err(err("expected end"));
                        }
                    }
                    out.push(0x0b);
                }
                _ => {
                    cur.i += 1;
                    emit_plain_after(cx, cur, a, out)?;
                }
            },
            Sx::List(items) => {
                cur.i += 1;
                emit_folded(cx, items, out)?;
            }
            Sx::Str(_) => return Err(err("unknown operator")),
        }
    }
    Ok(None)
}

/// 次のカーソル位置のアトムを即値として取る。
fn next_atom(cur: &mut Cur) -> R<String> {
    match cur.items.get(cur.i) {
        Some(Sx::Atom(s)) => {
            cur.i += 1;
            Ok(s.clone())
        }
        _ => Err(err("unexpected token")),
    }
}

/// 次の S 式を指標として取る。
fn next_idx(cur: &mut Cur, names: &HashMap<String, u32>, kind: &str) -> R<u32> {
    match cur.items.get(cur.i) {
        Some(sx) => {
            let v = idx_of(sx, names, kind)?;
            cur.i += 1;
            Ok(v)
        }
        None => Err(err(&format!("missing {kind} index"))),
    }
}

/// typeuse 修飾列 `(type|param|result)` が後に続くか見て、あれば解決する。
fn try_type_use(cx: &mut FnCx, cur: &mut Cur) -> R<Option<u32>> {
    let mut k = cur.i;
    let mut found = false;
    while k < cur.items.len() {
        let Some(l) = cur.items[k].list() else { break };
        match l.first().and_then(Sx::atom) {
            Some("type") | Some("param") | Some("result") => {
                k += 1;
                found = true;
            }
            _ => break,
        }
    }
    if !found {
        return Ok(None);
    }
    // 修飾列を type_use で解決する（items は同じ配列）。
    let mut i = cur.i;
    let t = {
        let mb = &mut *cx.mb;
        let mut named: Option<u32> = None;
        let mut params: Vec<ValType> = Vec::new();
        let mut results: Vec<ValType> = Vec::new();
        while i < k {
            let l = cur.items[i].list().unwrap();
            match l.first().and_then(Sx::atom) {
                Some("type") => {
                    if named.is_some() || !params.is_empty() || !results.is_empty() {
                        return Err(err("unexpected token"));
                    }
                    named = Some(idx_of(&l[1], &mb.type_names, "type")?);
                }
                Some("param") => {
                    if !results.is_empty() {
                        return Err(err("unexpected token"));
                    }
                    for p in &l[1..] {
                        // call_indirect 等の文脈では param に名は許されない。
                        if p.atom().is_some_and(|a| a.starts_with('$')) {
                            return Err(err("unexpected token"));
                        }
                        params.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                    }
                }
                Some("result") => {
                    for p in &l[1..] {
                        results.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        resolve_type(mb, named, params, results)?
    };
    cur.i = k;
    Ok(Some(t))
}

/// typeuse の解決結果を typeidx にする。
fn resolve_type(
    mb: &mut Mb,
    named: Option<u32>,
    params: Vec<ValType>,
    results: Vec<ValType>,
) -> R<u32> {
    if let Some(t) = named {
        if params.is_empty() && results.is_empty() {
            return Ok(t);
        }
        let ft = mb
            .types
            .get(t as usize)
            .ok_or_else(|| err("unknown type"))?;
        if ft.params == params && ft.results == results {
            return Ok(t);
        }
        return Err(err("inline function type"));
    }
    let ft = FuncType { params, results };
    if let Some(pos) = mb.types.iter().position(|x| *x == ft) {
        return Ok(pos as u32);
    }
    mb.types.push(ft);
    Ok(mb.types.len() as u32 - 1)
}

/// memarg の `offset=`/`align=` をカーソルから読む。
/// offset は u64（memory64 の構文を受け、範囲検査は検証側）。
/// align は 2 の冪（指数として返す）。
fn read_memarg(cur: &mut Cur, default_align: u32) -> R<(u32, u64)> {
    let mut off = 0u64;
    let mut align = default_align;
    while let Some(Sx::Atom(s)) = cur.items.get(cur.i) {
        if let Some(v) = s.strip_prefix("offset=") {
            let n = parse_int_signed(v)?;
            if !(0..=i128::from(u64::MAX)).contains(&n) {
                return Err(err("offset out of range"));
            }
            off = n as u64;
            cur.i += 1;
        } else if let Some(v) = s.strip_prefix("align=") {
            let n = parse_int_signed(v)?;
            if n <= 0 || (n & (n - 1)) != 0 {
                return Err(err("alignment must be power of 2"));
            }
            align = (n as u64).trailing_zeros();
            cur.i += 1;
        } else {
            break;
        }
    }
    Ok((align, off))
}

/// フラット命令の即値を読み、命令バイトを `imm` に出力する。
/// 副式オペランドを持つ命令では `cur` は副式の直前で止まる。
fn plain_imm(cx: &mut FnCx, cur: &mut Cur, head: &str, imm: &mut Vec<u8>) -> R<()> {
    match head {
        "br" | "br_if" => {
            let l = label_idx(
                cx,
                cur.items
                    .get(cur.i)
                    .ok_or_else(|| err("br: missing label"))?,
            )?;
            cur.i += 1;
            imm.push(if head == "br" { 0x0c } else { 0x0d });
            ulebs(imm, u64::from(l));
        }
        "br_table" => {
            let mut ls = Vec::new();
            while let Some(sx) = cur.items.get(cur.i) {
                // labelidx は `$名` か非負整数だけ。それ以外のアトム
                // （次の命令キーワード・`end`/`else`）でラベル列は終わる。
                if !idx_atom(sx) {
                    break;
                }
                ls.push(label_idx(cx, sx)?);
                cur.i += 1;
            }
            if ls.is_empty() {
                return Err(err("br_table: missing labels"));
            }
            let ln = ls.pop().unwrap();
            imm.push(0x0e);
            ulebs(imm, ls.len() as u64);
            for l in ls {
                ulebs(imm, u64::from(l));
            }
            ulebs(imm, u64::from(ln));
        }
        "call" => {
            let f = next_idx(cur, &cx.mb.func_names, "function")?;
            imm.push(0x10);
            ulebs(imm, u64::from(f));
        }
        "call_indirect" => {
            let mut table = 0u32;
            if let Some(sx) = cur.items.get(cur.i)
                && idx_atom(sx)
            {
                table = idx_of(sx, &cx.mb.table_names, "table")?;
                cur.i += 1;
            }
            // typeuse 省略時は型指標 0（仕様テキストの既定）。
            let t = match try_type_use(cx, cur)? {
                Some(t) => t,
                None if !cx.mb.types.is_empty() => 0,
                None => return Err(err("call_indirect: missing type")),
            };
            imm.push(0x11);
            ulebs(imm, u64::from(t));
            ulebs(imm, u64::from(table));
        }
        "local.get" | "local.set" | "local.tee" => {
            let x = local_idx(
                cx,
                cur.items
                    .get(cur.i)
                    .ok_or_else(|| err("local: missing index"))?,
            )?;
            cur.i += 1;
            imm.push(match head {
                "local.get" => 0x20,
                "local.set" => 0x21,
                _ => 0x22,
            });
            ulebs(imm, u64::from(x));
        }
        "global.get" | "global.set" => {
            let g = next_idx(cur, &cx.mb.global_names, "global")?;
            imm.push(if head == "global.get" { 0x23 } else { 0x24 });
            ulebs(imm, u64::from(g));
        }
        "table.get" | "table.set" => {
            let mut t = 0u32;
            if let Some(sx) = cur.items.get(cur.i)
                && idx_atom(sx)
            {
                t = idx_of(sx, &cx.mb.table_names, "table")?;
                cur.i += 1;
            }
            imm.push(if head == "table.get" { 0x25 } else { 0x26 });
            ulebs(imm, u64::from(t));
        }
        "table.grow" | "table.size" | "table.fill" => {
            let mut t = 0u32;
            if let Some(sx) = cur.items.get(cur.i)
                && idx_atom(sx)
            {
                t = idx_of(sx, &cx.mb.table_names, "table")?;
                cur.i += 1;
            }
            imm.push(0xfc);
            ulebs(
                imm,
                match head {
                    "table.grow" => 0x0f,
                    "table.size" => 0x10,
                    _ => 0x11,
                },
            );
            ulebs(imm, u64::from(t));
        }
        "table.init" => {
            // テキストは tableidx elemidx の順（tableidx は省略時 0）。
            // バイナリは elemidx tableidx の順で書き出す。
            let first = cur
                .items
                .get(cur.i)
                .ok_or_else(|| err("missing elem index"))?;
            let (t, e);
            if matches!(cur.items.get(cur.i + 1), Some(sx) if idx_atom(sx)) {
                t = idx_of(first, &cx.mb.table_names, "table")?;
                cur.i += 1;
                e = next_idx(cur, &cx.mb.elem_names, "elem")?;
            } else {
                t = 0;
                e = idx_of(first, &cx.mb.elem_names, "elem")?;
                cur.i += 1;
            }
            imm.extend_from_slice(&[0xfc, 0x0c]);
            ulebs(imm, u64::from(e));
            ulebs(imm, u64::from(t));
        }
        "elem.drop" => {
            let e = next_idx(cur, &cx.mb.elem_names, "elem")?;
            imm.extend_from_slice(&[0xfc, 0x0d]);
            ulebs(imm, u64::from(e));
        }
        "table.copy" => {
            let mut a2 = 0u32;
            let mut b2 = 0u32;
            for k in 0..2 {
                if let Some(sx) = cur.items.get(cur.i)
                    && idx_atom(sx)
                {
                    let v = idx_of(sx, &cx.mb.table_names, "table")?;
                    if k == 0 {
                        a2 = v;
                    } else {
                        b2 = v;
                    }
                    cur.i += 1;
                }
            }
            imm.extend_from_slice(&[0xfc, 0x0e]);
            ulebs(imm, u64::from(a2));
            ulebs(imm, u64::from(b2));
        }
        "memory.init" => {
            let d = next_idx(cur, &cx.mb.data_names, "data")?;
            imm.extend_from_slice(&[0xfc, 0x08]);
            ulebs(imm, u64::from(d));
            imm.push(0x00);
        }
        "data.drop" => {
            let d = next_idx(cur, &cx.mb.data_names, "data")?;
            imm.extend_from_slice(&[0xfc, 0x09]);
            ulebs(imm, u64::from(d));
        }
        "i32.const" | "i64.const" => {
            let s = next_atom(cur)?;
            // nan 系の字句は整数即値の位置では unexpected token。
            let bare = s.strip_prefix(['-', '+']).unwrap_or(&s);
            if bare.starts_with("nan") {
                return Err(err("unexpected token"));
            }
            let v = parse_int_signed(&s)?;
            // 範囲: i32 は [-2^31, 2^32-1]、i64 は [-2^63, 2^64-1]。
            let ok = if head == "i32.const" {
                (-0x8000_0000i128..=0xffff_ffffi128).contains(&v)
            } else {
                (-0x8000_0000_0000_0000i128..=0xffff_ffff_ffff_ffffi128).contains(&v)
            };
            if !ok {
                return Err(err("constant out of range"));
            }
            imm.push(if head == "i32.const" { 0x41 } else { 0x42 });
            // i32.const は s32 即値: u32 範囲のリテラルは負に折り返す。
            slebs(
                imm,
                if head == "i32.const" {
                    i64::from(v as i32)
                } else {
                    v as i64
                },
            );
        }
        "f32.const" => {
            let s = next_atom(cur)?;
            // nan:canonical/nan:arithmetic はモジュール中の字句として不正
            // (assert の期待値だけに許される）。
            if s == "nan:canonical" || s == "nan:arithmetic" {
                return Err(err("unexpected token"));
            }
            let b = parse_float_bits(&s, true)?;
            imm.push(0x43);
            imm.extend_from_slice(&(b as u32).to_le_bytes());
        }
        "f64.const" => {
            let s = next_atom(cur)?;
            if s == "nan:canonical" || s == "nan:arithmetic" {
                return Err(err("unexpected token"));
            }
            let b = parse_float_bits(&s, false)?;
            imm.push(0x44);
            imm.extend_from_slice(&b.to_le_bytes());
        }
        "ref.null" => {
            let s = next_atom(cur)?;
            // ヒープ型は func/extern（短縮形 funcref/externref も許す）。
            let t = match s.as_str() {
                "func" | "funcref" => RefType::Func,
                "extern" | "externref" => RefType::Extern,
                _ => return Err(err("malformed reference type")),
            };
            imm.push(0xd0);
            imm.push(t.code());
        }
        "ref.func" => {
            let f = next_idx(cur, &cx.mb.func_names, "function")?;
            imm.push(0xd2);
            ulebs(imm, u64::from(f));
        }
        "select" => {
            // `(result t)` 修飾の select_t。注釈は複数並び得て、
            // 集めた型の総数が 1 なら typed select（`(result)` は
            // 型 0 件で unannotated と同じ扱い）。
            let mut ts = Vec::new();
            let mut annotated = false;
            while let Some(l) = cur.items.get(cur.i).and_then(Sx::list)
                && l.first().and_then(Sx::atom) == Some("result")
            {
                annotated = true;
                for p in &l[1..] {
                    ts.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                }
                cur.i += 1;
            }
            // 注釈があれば型はちょうど 1 個（0・2 個は arity 違反）。
            if annotated && ts.len() != 1 {
                return Err(err("invalid result arity"));
            }
            match ts.len() {
                0 => imm.push(0x1b),
                1 => {
                    imm.push(0x1c);
                    ulebs(imm, 1);
                    emit_valtype(imm, ts[0]);
                }
                _ => unreachable!(),
            }
        }
        _ => {
            if let Some((op, default_align)) = mem_opcode(head) {
                let (align, off) = read_memarg(cur, default_align)?;
                imm.push(op);
                ulebs(imm, u64::from(align));
                ulebs(imm, off);
                return Ok(());
            }
            if let Some(code) = fc_imm_opcode(head) {
                imm.push(0xfc);
                ulebs(imm, u64::from(code));
                return Ok(());
            }
            if let Some(bytes) = simple_opcode(head) {
                imm.extend_from_slice(bytes);
                return Ok(());
            }
            return Err(err(&format!("unknown operator {head}")));
        }
    }
    Ok(())
}

/// フラット命令の即値と本体を出力する（`a` は命令名）。
fn emit_plain_after(cx: &mut FnCx, cur: &mut Cur, a: &str, out: &mut Vec<u8>) -> R<()> {
    let mut imm = Vec::new();
    plain_imm(cx, cur, a, &mut imm)?;
    out.extend_from_slice(&imm);
    Ok(())
}

/// 畳み込み式 `(op ...)` の出力。
fn emit_folded(cx: &mut FnCx, items: &[Sx], out: &mut Vec<u8>) -> R<()> {
    let Some(head) = items.first().and_then(Sx::atom) else {
        return Err(err("expected instruction"));
    };
    match head {
        "block" | "loop" => {
            let mut i = 1;
            let mut lname = None;
            if let Some(Sx::Atom(n)) = items.get(i)
                && n.starts_with('$')
            {
                lname = Some(n.clone());
                i += 1;
            }
            let bt = blocktype_imm(cx, items, &mut i)?;
            out.push(if head == "block" { 0x02 } else { 0x03 });
            out.extend_from_slice(&bt);
            cx.labels.push(lname);
            let mut cur = Cur { items, i };
            let term = emit_seq(cx, &mut cur, out)?;
            cx.labels.pop();
            if term.is_some() {
                return Err(err("unexpected end/else"));
            }
            out.push(0x0b);
        }
        "if" => {
            let mut i = 1;
            let mut lname = None;
            if let Some(Sx::Atom(n)) = items.get(i)
                && n.starts_with('$')
            {
                lname = Some(n.clone());
                i += 1;
            }
            let bt = blocktype_imm(cx, items, &mut i)?;
            // 条件部・then・else を仕分ける。文法は
            // `foldedinstr* (then instr*) (else instr*)?` の順固定なので、
            // (then) の後は (else) 1 つだけを認め、他の項・重複はエラー。
            let mut cond_end = items.len();
            let mut then_part: Option<&[Sx]> = None;
            let mut else_part: Option<&[Sx]> = None;
            for (k, it) in items.iter().enumerate().skip(i) {
                let h = it.list().and_then(|l| l.first()).and_then(Sx::atom);
                match h {
                    Some("then") => {
                        if then_part.is_some() || else_part.is_some() {
                            return Err(err("unexpected token"));
                        }
                        then_part = Some(&it.list().unwrap()[1..]);
                        cond_end = k;
                    }
                    Some("else") => {
                        if then_part.is_none() || else_part.is_some() {
                            return Err(err("unexpected token"));
                        }
                        else_part = Some(&it.list().unwrap()[1..]);
                    }
                    _ => {
                        if then_part.is_some() {
                            return Err(err("unexpected token"));
                        }
                    }
                }
            }
            let Some(then_part) = then_part else {
                return Err(err("if without then"));
            };
            // 条件部の命令を先に出す。
            // 畳み if の条件部は foldedinstr (リスト) のみ許される。
            for it in &items[i..cond_end] {
                if it.list().is_none() {
                    return Err(err("unexpected token"));
                }
            }
            {
                let mut cur = Cur {
                    items: &items[i..cond_end],
                    i: 0,
                };
                if emit_seq(cx, &mut cur, out)?.is_some() {
                    return Err(err("unexpected end/else"));
                }
            }
            out.push(0x04);
            out.extend_from_slice(&bt);
            cx.labels.push(lname);
            {
                let mut cur = Cur {
                    items: then_part,
                    i: 0,
                };
                if emit_seq(cx, &mut cur, out)?.is_some() {
                    return Err(err("unexpected end/else"));
                }
            }
            if let Some(else_part) = else_part {
                out.push(0x05);
                let mut cur = Cur {
                    items: else_part,
                    i: 0,
                };
                if emit_seq(cx, &mut cur, out)?.is_some() {
                    return Err(err("unexpected end/else"));
                }
            }
            cx.labels.pop();
            out.push(0x0b);
        }
        // func 宣言の構文項が命令位置に来るのは malformed。
        "param" | "result" | "local" => return Err(err("unexpected token")),
        _ => {
            // 即値を読み、残り（副式）を先に出してから命令を出す。
            let mut cur = Cur { items, i: 1 };
            let mut imm = Vec::new();
            plain_imm(cx, &mut cur, head, &mut imm)?;
            let mut sub = Cur { items, i: cur.i };
            if emit_seq(cx, &mut sub, out)?.is_some() {
                return Err(err("unexpected end/else"));
            }
            out.extend_from_slice(&imm);
        }
    }
    Ok(())
}

/// 定数式を構成しうる命令の先頭語（2.0 の extended const を含む）。
fn const_head(a: &str) -> bool {
    matches!(
        a,
        "i32.const"
            | "i64.const"
            | "f32.const"
            | "f64.const"
            | "ref.null"
            | "ref.func"
            | "global.get"
            | "i32.add"
            | "i32.sub"
            | "i32.mul"
            | "i64.add"
            | "i64.sub"
            | "i64.mul"
    )
}

/// 定数式（畳み込み式）をバイト列にする。
fn const_expr_bytes(cx: &mut FnCx, sx: &Sx) -> R<Vec<u8>> {
    let mut out = Vec::new();
    match sx {
        Sx::List(items) => {
            let head = items.first().and_then(Sx::atom).unwrap_or("");
            if const_head(head) {
                emit_folded(cx, items, &mut out)?;
            } else if head == "item" {
                // `(item instr*)` の中身はフラット/畳み混在の命令列。
                let mut cur = Cur {
                    items: &items[1..],
                    i: 0,
                };
                if emit_seq(cx, &mut cur, &mut out)?.is_some() {
                    return Err(err("unexpected end/else"));
                }
            } else {
                return Err(err("constant expression required"));
            }
            out.push(0x0b);
        }
        _ => return Err(err("constant expression required")),
    }
    Ok(out)
}

/// 定数式の項列を出力する。`expr ::= instr*` なので `(i32.const 0)`
/// の畳み形と `i32.const 0` のフラット形を混在して受け付ける。
/// 複数式は区切りの `end` を除いて連結する（検証側が type mismatch
/// を出す）。終端の `end` は呼び出し側が足す。
fn const_seq(cx: &mut FnCx, items: &[Sx], out: &mut Vec<u8>) -> R<()> {
    let mut cur = Cur { items, i: 0 };
    while cur.i < items.len() {
        match &items[cur.i] {
            Sx::Atom(a) => {
                if !const_head(a) {
                    return Err(err("constant expression required"));
                }
                let a = a.clone();
                cur.i += 1;
                emit_plain_after(cx, &mut cur, &a, out)?;
            }
            Sx::List(_) => {
                let b = const_expr_bytes(cx, &items[cur.i])?;
                out.extend_from_slice(&b[..b.len() - 1]);
                cur.i += 1;
            }
            _ => return Err(err("constant expression required")),
        }
    }
    Ok(())
}

/// `(offset e* ...)` または裸式リストから定数式バイトを作る。
/// `(offset)` 空形は `end` のみの式になる。
fn offset_expr_bytes(cx: &mut FnCx, l: &Sx) -> R<Vec<u8>> {
    let inner = l.list().unwrap();
    if inner.first().and_then(Sx::atom) != Some("offset") {
        return const_expr_bytes(cx, l);
    }
    let mut out = Vec::new();
    const_seq(cx, &inner[1..], &mut out)?;
    out.push(0x0b);
    Ok(out)
}

// ---------------------------------------------------------------------------
// モジュールフィールドの解釈
// ---------------------------------------------------------------------------

/// 名フィールドは UTF-8 でなければならない（assert_malformed 対象）。
fn str_utf8(sx: Option<&Sx>) -> R<String> {
    let b = sx
        .and_then(Sx::string)
        .ok_or_else(|| err("malformed name"))?;
    String::from_utf8(b.to_vec()).map_err(|_| err("malformed UTF-8 encoding"))
}

/// `l` が `(import "m" "n")` なら (m,n) を返す。
fn inline_import(l: &[Sx]) -> R<Option<(String, String)>> {
    if l.first().and_then(Sx::atom) != Some("import") {
        return Ok(None);
    }
    // `(import "m" "n" extra ...)` の余分な項は文法エラー。
    if l.len() != 3 {
        return Err(err("malformed import"));
    }
    let m = str_utf8(l.get(1))?;
    let n = str_utf8(l.get(2))?;
    Ok(Some((m, n)))
}

/// `l` が `(export "n")` なら名前を返す。
fn inline_export(l: &[Sx]) -> R<Option<String>> {
    if l.first().and_then(Sx::atom) != Some("export") {
        return Ok(None);
    }
    Ok(Some(str_utf8(l.get(1))?))
}

/// `import_desc` の戻りの部品（kind バイト、descriptor バイト列、$名）。
type ImportDescParts = (u8, Vec<u8>, Option<String>);

/// インポート記述 `(func|table|memory|global ...)` を解釈し登録する。
/// 未知の種別（`tag` など段階 12 範囲外の提案）は `None` を返し、
/// 呼び出し側はそのインポートを落とす。
fn import_desc(mb: &mut Mb, l: &[Sx], i: usize) -> R<Option<ImportDescParts>> {
    let kind = l.first().and_then(Sx::atom).unwrap_or("");
    match kind {
        "func" => {
            let mut name = None;
            let mut j = 1;
            if let Some(Sx::Atom(a)) = l.get(1)
                && a.starts_with('$')
            {
                name = Some(a.clone());
                j = 2;
            }
            let mut k = j;
            let t = mb.type_use(l, &mut k)?;
            let mut b = Vec::new();
            ulebs(&mut b, u64::from(t));
            let _ = i;
            Ok(Some((0x00, b, name)))
        }
        "table" => {
            let (tt, nn, name, j) = table_decl(mb, l)?;
            let _ = j;
            let mut b = Vec::new();
            if nn {
                b.push(0x64);
            }
            b.push(tt.et.code());
            emit_limits(&mut b, &tt.lim);
            Ok(Some((0x01, b, name)))
        }
        "memory" => {
            let (lim, name, _j) = mem_decl(l)?;
            let mut b = Vec::new();
            emit_limits(&mut b, &lim);
            Ok(Some((0x02, b, name)))
        }
        "global" => {
            let (gt, name, _j) = global_decl(l)?;
            let mut b = Vec::new();
            emit_valtype(&mut b, gt.vt);
            b.push(u8::from(gt.mutable));
            Ok(Some((0x03, b, name)))
        }
        _ => Ok(None),
    }
}

/// `(table $n? limits et)` の宣言部分（plain 形）。
/// 戻りは (型, non-null か, $名, 消費位置)。
fn table_decl_plain(l: &[Sx], i0: usize) -> R<(TableType, bool, Option<String>, usize)> {
    let mut i = i0;
    let mut name = None;
    if let Some(Sx::Atom(a)) = l.get(i)
        && a.starts_with('$')
    {
        name = Some(a.clone());
        i += 1;
    }
    let Some(Sx::Atom(min_a)) = l.get(i) else {
        return Err(err("malformed table"));
    };
    let min =
        u32::try_from(parse_int_signed(min_a)?).map_err(|_| err("table size exceeds limit"))?;
    i += 1;
    let mut max = None;
    if let Some(Sx::Atom(a)) = l.get(i)
        && !a.starts_with('$')
        && reftype_of(a).is_none()
    {
        max =
            Some(u32::try_from(parse_int_signed(a)?).map_err(|_| err("table size exceeds limit"))?);
        i += 1;
    }
    let (et, nn) = match l.get(i) {
        Some(sx) => reftype_sx_nn(sx).ok_or_else(|| err("malformed reference type"))?,
        None => (RefType::Func, false),
    };
    Ok((
        TableType {
            et,
            lim: Limits { min, max },
        },
        nn,
        name,
        i + 1,
    ))
}

/// `(table $n? ...)` の互換名（`import_desc` から呼ばれる）。
fn table_decl(mb: &mut Mb, l: &[Sx]) -> R<(TableType, bool, Option<String>, usize)> {
    let _ = mb;
    table_decl_plain(l, 1)
}

/// `(memory $n? ...)` の宣言部分。戻りは (limits, $名, 消費位置)。
fn mem_decl(l: &[Sx]) -> R<(Limits, Option<String>, usize)> {
    let mut i = 1;
    let mut name = None;
    if let Some(Sx::Atom(a)) = l.get(1)
        && a.starts_with('$')
    {
        name = Some(a.clone());
        i = 2;
    }
    let Some(Sx::Atom(min_a)) = l.get(i) else {
        return Err(err("malformed memory"));
    };
    let min =
        u32::try_from(parse_int_signed(min_a)?).map_err(|_| err("memory size exceeds limit"))?;
    i += 1;
    let mut max = None;
    if let Some(Sx::Atom(a)) = l.get(i) {
        max = Some(
            u32::try_from(parse_int_signed(a)?).map_err(|_| err("memory size exceeds limit"))?,
        );
        i += 1;
    }
    Ok((Limits { min, max }, name, i))
}

/// `(global $n? ...)` の型部分。戻りは (GlobalType, $名, 消費位置)。
fn global_decl(l: &[Sx]) -> R<(GlobalType, Option<String>, usize)> {
    let mut i = 1;
    let mut name = None;
    if let Some(Sx::Atom(a)) = l.get(1)
        && a.starts_with('$')
    {
        name = Some(a.clone());
        i = 2;
    }
    match l.get(i) {
        Some(Sx::List(inner)) if inner.first().and_then(Sx::atom) == Some("mut") => {
            let vt = inner
                .get(1)
                .and_then(valtype_sx)
                .ok_or_else(|| err("malformed value type"))?;
            Ok((GlobalType { vt, mutable: true }, name, i + 1))
        }
        Some(sx) if valtype_sx(sx).is_some() => Ok((
            GlobalType {
                vt: valtype_sx(sx).unwrap(),
                mutable: false,
            },
            name,
            i + 1,
        )),
        // 型位置の不明なアトム（例: 旧式の `anyfunc`）は
        // `unknown operator` を期待される。
        Some(Sx::Atom(a)) => Err(err(&format!("unknown operator {a}"))),
        _ => Err(err("malformed global")),
    }
}

/// func 型宣言 `(func (param ..)* (result ..)*)` → FuncType。
fn functype_from_decl(l: &[Sx]) -> R<FuncType> {
    let mut params = Vec::new();
    let mut results = Vec::new();
    let mut saw_result = false;
    for it in l {
        let Some(inner) = it.list() else {
            return Err(err("unexpected token"));
        };
        match inner.first().and_then(Sx::atom) {
            Some("param") => {
                // param は result より先に来なければならない。
                if saw_result {
                    return Err(err("unexpected token"));
                }
                for p in &inner[1..] {
                    if p.atom().is_some_and(|a| a.starts_with('$')) {
                        continue;
                    }
                    params.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                }
            }
            Some("result") => {
                saw_result = true;
                for p in &inner[1..] {
                    // result は名前を取れない。
                    if p.atom().is_some_and(|a| a.starts_with('$')) {
                        return Err(err("unexpected token"));
                    }
                    results.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
                }
            }
            _ => return Err(err("unexpected token")),
        }
    }
    Ok(FuncType { params, results })
}

/// `decl_head` の戻り（$名、export 位置列、import 位置、次位置）。
type DeclHead = (Option<String>, Vec<usize>, Option<usize>, usize);

/// decl の中から `$名`・inline export・inline import を拾う。
/// 戻りは (name, export位置列, import位置, 次位置)。
fn decl_head(items: &[Sx], i0: usize) -> R<DeclHead> {
    let mut i = i0;
    let mut name = None;
    if let Some(Sx::Atom(a)) = items.get(i)
        && a.starts_with('$')
    {
        name = Some(a.clone());
        i += 1;
    }
    let mut exports = Vec::new();
    while let Some(l) = items.get(i).and_then(Sx::list) {
        if l.first().and_then(Sx::atom) == Some("export") {
            str_utf8(l.get(1))?;
            exports.push(i);
            i += 1;
        } else {
            break;
        }
    }
    let mut import = None;
    if let Some(l) = items.get(i).and_then(Sx::list)
        && l.first().and_then(Sx::atom) == Some("import")
    {
        str_utf8(l.get(1))?;
        str_utf8(l.get(2))?;
        import = Some(i);
        i += 1;
    }
    Ok((name, exports, import, i))
}

/// 定義関数の本体を出力し、`mb.funcs`/`mb.codes` に追加する。
/// `items` は `(func ...)` の中身（head を含む）、`i0` は typeuse の開始位置。
fn emit_func_def(mb: &mut Mb, items: &[Sx], i0: usize) -> R<()> {
    let tu_start = i0;
    let mut i = i0;
    let ty = mb.type_use(items, &mut i)?;
    let fty = mb
        .types
        .get(ty as usize)
        .ok_or_else(|| err("unknown type"))?
        .clone();
    mb.funcs.push(ty);
    // パラメータ名：type_use が消費した範囲の (param $n t) をなめる。
    let mut locals_map: HashMap<String, u32> = HashMap::new();
    {
        let mut pidx = 0u32;
        for it in &items[tu_start..i] {
            let Some(l) = it.list() else { continue };
            if l.first().and_then(Sx::atom) != Some("param") {
                continue;
            }
            // 1 つの `(param …)` につき `$名` は先頭の1個までで、
            // そのとき型はちょうど1つ（`(param $x $y t)`・`(param $x)`
            // のような形は文法エラー）。
            let mut name_seen = false;
            let mut types_in = 0usize;
            for p in &l[1..] {
                if let Some(a) = p.atom()
                    && a.starts_with('$')
                {
                    if name_seen || types_in > 0 {
                        return Err(err("unexpected token"));
                    }
                    name_seen = true;
                    if locals_map.insert(a.to_string(), pidx).is_some() {
                        return Err(err("duplicate local"));
                    }
                } else {
                    types_in += 1;
                    pidx += 1;
                }
            }
            if name_seen && types_in != 1 {
                return Err(err("unexpected token"));
            }
        }
        let _ = fty;
    }
    // 宣言ローカル。
    let mut local_types: Vec<ValType> = Vec::new();
    let mut j = i;
    while j < items.len() {
        let Some(l) = items[j].list() else { break };
        if l.first().and_then(Sx::atom) != Some("local") {
            break;
        }
        // `$名` は先頭の1個までで、そのとき型はちょうど1つ
        // （`(local i32 $l i64)` のような形は文法エラー）。
        let mut name: Option<String> = None;
        let base = local_types.len() as u32;
        for p in &l[1..] {
            if let Some(a) = p.atom()
                && a.starts_with('$')
            {
                if name.is_some() || local_types.len() as u32 != base {
                    return Err(err("unexpected token"));
                }
                name = Some(a.to_string());
                continue;
            }
            local_types.push(valtype_sx(p).ok_or_else(|| err("malformed value type"))?);
        }
        if let Some(n) = name {
            if local_types.len() as u32 - base != 1 {
                return Err(err("unexpected token"));
            }
            let idx = fty.params.len() as u32 + base;
            if locals_map.insert(n, idx).is_some() {
                return Err(err("duplicate local"));
            }
        }
        j += 1;
    }
    // 本体の命令列を出力する。
    let mut body = Vec::new();
    {
        let mut cx = FnCx {
            mb,
            locals: locals_map,
            labels: Vec::new(),
        };
        let mut cur = Cur { items, i: j };
        // 本体末尾の裸の `end`/`else` は文法エラー（残りは捨てない）。
        if emit_seq(&mut cx, &mut cur, &mut body)?.is_some() {
            return Err(err("unexpected end/else"));
        }
        body.push(0x0b);
        // locals 宣言の圧縮表現。
        let mut hdr = Vec::new();
        let mut groups: Vec<(u32, ValType)> = Vec::new();
        for t in &local_types {
            match groups.last_mut() {
                Some((n, t2)) if *t2 == *t => *n += 1,
                _ => groups.push((1, *t)),
            }
        }
        ulebs(&mut hdr, groups.len() as u64);
        for (n, t) in groups {
            ulebs(&mut hdr, u64::from(n));
            emit_valtype(&mut hdr, t);
        }
        let mut fcode = Vec::new();
        fcode.extend_from_slice(&hdr);
        fcode.extend_from_slice(&body);
        let mut entry = Vec::new();
        ulebs(&mut entry, fcode.len() as u64);
        entry.extend_from_slice(&fcode);
        cx.mb.codes.push(entry);
    }
    Ok(())
}

/// `(elem ...)` の中身を ElemParts に解釈する。`i0` は $名の次の位置。
fn emit_elem(mb: &mut Mb, items: &[Sx], i0: usize) -> R<()> {
    let mut i = i0;
    let mut mode: u32 = 1; // 1=passive, 2=active, 3=declared の内部表現
    let mut table = 0u32;
    let mut offset_list: Option<&Sx> = None;
    // declare
    if let Some(Sx::Atom(a)) = items.get(i)
        && a == "declare"
    {
        mode = 3;
        i += 1;
    } else if let Some(Sx::List(l)) = items.get(i) {
        match l.first().and_then(Sx::atom) {
            Some("table") => {
                table = idx_of(&l[1], &mb.table_names, "table")?;
                i += 1;
                // 次の List が offset 式。
                if let Some(Sx::List(off)) = items.get(i) {
                    offset_list = Some(&items[i]);
                    let _ = off;
                    i += 1;
                }
                mode = 2;
            }
            Some("offset") => {
                offset_list = Some(&items[i]);
                i += 1;
                mode = 2;
            }
            _ => {
                // 畳み込み式 = offset（table 0 の active）。
                // ただし `(ref ht)` は参照型（elemlist の種別）であり offset ではない。
                if l.first().and_then(Sx::atom) != Some("ref") {
                    offset_list = Some(&items[i]);
                    i += 1;
                    mode = 2;
                }
            }
        }
    }
    // elemlist
    let mut kind = RefType::Func;
    let mut nonnull = false;
    let mut exprs_form = false;
    if let Some(sx) = items.get(i) {
        if sx.atom() == Some("func") {
            i += 1;
        } else if let Some((rt, nn)) = reftype_sx_nn(sx) {
            kind = rt;
            nonnull = nn;
            exprs_form = true;
            i += 1;
        }
    }
    let mut funcs = Vec::new();
    let mut exprs: Vec<Vec<u8>> = Vec::new();
    for it in &items[i..] {
        if exprs_form {
            // `(item ...)` は const_expr_bytes の item 枝が連結するので
            // 剥がさずそのまま渡す（複数式は検証で type mismatch になる）。
            match it {
                // 裸の関数名は (ref.func n) の短縮。
                Sx::Atom(_) => {
                    let f = idx_of(it, &mb.func_names, "function")?;
                    let mut b = vec![0xd2];
                    ulebs(&mut b, u64::from(f));
                    b.push(0x0b);
                    exprs.push(b);
                }
                Sx::List(_) => {
                    let mut cx = FnCx {
                        mb: &mut *mb,
                        locals: HashMap::new(),
                        labels: Vec::new(),
                    };
                    exprs.push(const_expr_bytes(&mut cx, it)?);
                }
                _ => return Err(err("malformed elem item")),
            }
        } else {
            // funcs 形では `(item X)` の糖衣を剥がす。
            let inner: &Sx = match it {
                Sx::List(l) if l.first().and_then(Sx::atom) == Some("item") => {
                    if l.len() != 2 {
                        return Err(err("malformed elem item"));
                    }
                    l.get(1).ok_or_else(|| err("malformed elem item"))?
                }
                _ => it,
            };
            funcs.push(idx_of(inner, &mb.func_names, "function")?);
        }
    }
    // flags を決める。
    let flag = match (mode, exprs_form, kind) {
        (1, false, _) => 1,
        (3, false, _) => 3,
        (2, false, _) => {
            if table == 0 {
                0
            } else {
                2
            }
        }
        (1, true, _) => 5,
        (3, true, _) => 7,
        (2, true, RefType::Func) => {
            // flag 4 は暗黙の funcref（nullable）形なので、non-null や
            // table != 0 のときは reftype つきの flag 6 を使う。
            if table == 0 && !nonnull { 4 } else { 6 }
        }
        (2, true, _) => 6,
        _ => return Err(err("malformed elem segment")),
    };
    let offset = match offset_list {
        Some(l) => {
            let mut cx = FnCx {
                mb: &mut *mb,
                locals: HashMap::new(),
                labels: Vec::new(),
            };
            Some(offset_expr_bytes(&mut cx, l)?)
        }
        None => None,
    };
    mb.elems.push(ElemParts {
        flag,
        offset,
        table,
        kind,
        nonnull,
        funcs,
        exprs,
    });
    Ok(())
}

/// `(data ...)` の中身をバイト列にする。`i0` は $名の次の位置。
/// `mem_idx` は inline data（memory の elem 糖衣）で使う強制メモリ指標。
fn emit_data(mb: &mut Mb, items: &[Sx], i0: usize, mem_idx: Option<u32>) -> R<()> {
    let mut i = i0;
    let mut mem = mem_idx;
    let mut offset_list: Option<&Sx> = None;
    // (memory x) 修飾。
    if let Some(Sx::List(l)) = items.get(i)
        && l.first().and_then(Sx::atom) == Some("memory")
    {
        mem = Some(idx_of(&l[1], &mb.mem_names, "memory")?);
        i += 1;
    }
    // offset 式。
    if let Some(Sx::List(_l)) = items.get(i) {
        offset_list = Some(&items[i]);
        i += 1;
    }
    let mut bytes = Vec::new();
    for it in &items[i..] {
        match it {
            Sx::Str(s) => bytes.extend_from_slice(s),
            _ => return Err(err("malformed data segment")),
        }
    }
    let mut out = Vec::new();
    match (mem, offset_list) {
        (None, None) => {
            ulebs(&mut out, 1);
            emit_bytes(&mut out, &bytes);
        }
        (m, Some(l)) => {
            let mm = m.unwrap_or(0);
            ulebs(&mut out, if mm == 0 { 0 } else { 2 });
            if mm != 0 {
                ulebs(&mut out, u64::from(mm));
            }
            let mut cx = FnCx {
                mb: &mut *mb,
                locals: HashMap::new(),
                labels: Vec::new(),
            };
            out.extend_from_slice(&offset_expr_bytes(&mut cx, l)?);
            emit_bytes(&mut out, &bytes);
        }
        (Some(_), None) => return Err(err("malformed data segment")),
    }
    mb.datas.push(out);
    Ok(())
}

/// `(type $n? (func decl))` を Pass A で登録する。
fn scan_type(mb: &mut Mb, l: &[Sx]) -> R<()> {
    let mut i = 1;
    if let Some(Sx::Atom(a)) = l.get(1)
        && a.starts_with('$')
    {
        insert_name(&mut mb.type_names, a.clone(), mb.types.len() as u32, "type")?;
        i = 2;
    }
    let Some(Sx::List(fdecl)) = l.get(i) else {
        return Err(err("malformed type"));
    };
    if fdecl.first().and_then(Sx::atom) != Some("func") {
        return Err(err("malformed type"));
    }
    mb.types.push(functype_from_decl(&fdecl[1..])?);
    Ok(())
}

/// `$名` を拾う（あれば）。
fn name_of(items: &[Sx], i0: usize) -> Option<String> {
    match items.get(i0) {
        Some(Sx::Atom(a)) if a.starts_with('$') => Some(a.clone()),
        _ => None,
    }
}

/// 名を指標表に登録する。重複は文法エラー。
fn insert_name(names: &mut HashMap<String, u32>, n: String, idx: u32, kind: &str) -> R<()> {
    if names.insert(n, idx).is_some() {
        return Err(err(&format!("duplicate {kind}")));
    }
    Ok(())
}

/// モジュールのフィールド列からバイナリを組み立てる。
#[allow(clippy::too_many_lines)]
fn build_module(fields: &[Sx]) -> R<Vec<u8>> {
    let mut mb = Mb::default();
    // --- Pass A: 型宣言 ---
    for f in fields {
        if let Some(l) = f.list()
            && l.first().and_then(Sx::atom) == Some("type")
        {
            scan_type(&mut mb, l)?;
        }
    }
    // --- Pass B: 名と指標空間の下見 ---
    // kind: 0=func 1=table 2=mem 3=global
    let mut imp_count = [0u32; 4];
    // 定義指標は無名定義も消費するので、(名前, 定義順位) を記録する。
    let mut def_names: [Vec<(String, u32)>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut def_count = [0u32; 4];
    let mut elem_count = 0u32;
    let mut data_count = 0u32;
    // 最初に現れた定義フィールドの種類。インポートは定義より
    // 先になければならない（"import after {kind}"）。
    let mut first_def: Option<&'static str> = None;
    for f in fields {
        let Some(l) = f.list() else {
            // 裸アトムは `$name` だけが合法（モジュール名）。
            if let Sx::Atom(a) = f
                && !a.starts_with('$')
            {
                return Err(err(&format!("unknown operator {a}")));
            }
            continue;
        };
        let Some(head) = l.first().and_then(Sx::atom) else {
            continue;
        };
        match head {
            "import" => {
                if let Some(k) = first_def {
                    return Err(err(&format!("import after {k}")));
                }
                if let Some(Sx::List(d)) = l.get(3) {
                    let kind = match d.first().and_then(Sx::atom) {
                        Some("func") => 0,
                        Some("table") => 1,
                        Some("memory") => 2,
                        Some("global") => 3,
                        _ => continue,
                    };
                    if let Some(n) = name_of(d, 1) {
                        let (names, kw) = match kind {
                            0 => (&mut mb.func_names, "func"),
                            1 => (&mut mb.table_names, "table"),
                            2 => (&mut mb.mem_names, "memory"),
                            _ => (&mut mb.global_names, "global"),
                        };
                        insert_name(names, n, imp_count[kind], kw)?;
                    }
                    imp_count[kind] += 1;
                }
            }
            "func" | "table" | "memory" | "global" => {
                let kind = match head {
                    "func" => 0,
                    "table" => 1,
                    "memory" => 2,
                    _ => 3,
                };
                let (_, _, imp, _) = decl_head(l, 1)?;
                if imp.is_some() {
                    if let Some(k) = first_def {
                        return Err(err(&format!("import after {k}")));
                    }
                    if let Some(n) = name_of(l, 1) {
                        let (names, kw) = match kind {
                            0 => (&mut mb.func_names, "func"),
                            1 => (&mut mb.table_names, "table"),
                            2 => (&mut mb.mem_names, "memory"),
                            _ => (&mut mb.global_names, "global"),
                        };
                        insert_name(names, n, imp_count[kind], kw)?;
                    }
                    imp_count[kind] += 1;
                } else {
                    if first_def.is_none() {
                        first_def = Some(match head {
                            "func" => "function",
                            "table" => "table",
                            "memory" => "memory",
                            _ => "global",
                        });
                    }
                    if let Some(n) = name_of(l, 1) {
                        def_names[kind].push((n, def_count[kind]));
                    }
                    def_count[kind] += 1;
                    // 糖衣: (table .. (elem ..)) / (memory .. (data ..)) は
                    // 暗黙のセグメントを1個生やすので指標を進める。
                    let sugar_head = if kind == 1 { "elem" } else { "data" };
                    if kind != 0
                        && l.iter().any(|it| {
                            it.list().and_then(|x| x.first()).and_then(Sx::atom) == Some(sugar_head)
                        })
                    {
                        if kind == 1 {
                            elem_count += 1;
                        } else if kind == 2 {
                            data_count += 1;
                        }
                    }
                }
            }
            "elem" => {
                if let Some(n) = name_of(l, 1) {
                    insert_name(&mut mb.elem_names, n, elem_count, "elem segment")?;
                }
                elem_count += 1;
            }
            "data" => {
                if let Some(n) = name_of(l, 1) {
                    insert_name(&mut mb.data_names, n, data_count, "data segment")?;
                }
                data_count += 1;
            }
            _ => {}
        }
    }
    // 定義側の名を確定する（import 数 + 定義順）。
    for (n, j) in &def_names[0] {
        insert_name(&mut mb.func_names, n.clone(), imp_count[0] + j, "func")?;
    }
    for (n, j) in &def_names[1] {
        insert_name(&mut mb.table_names, n.clone(), imp_count[1] + j, "table")?;
    }
    for (n, j) in &def_names[2] {
        insert_name(&mut mb.mem_names, n.clone(), imp_count[2] + j, "memory")?;
    }
    for (n, j) in &def_names[3] {
        insert_name(&mut mb.global_names, n.clone(), imp_count[3] + j, "global")?;
    }
    // --- Pass C: フィールド出力 ---
    for f in fields {
        let Some(l) = f.list() else { continue };
        let Some(head) = l.first().and_then(Sx::atom) else {
            continue;
        };
        match head {
            "type" => {}
            "import" => {
                let m = str_utf8(l.get(1))?;
                let n = str_utf8(l.get(2))?;
                let Some(Sx::List(d)) = l.get(3) else {
                    return Err(err("malformed import"));
                };
                // 記述子の後の余分な項は文法エラー。
                if l.len() > 4 {
                    return Err(err("unexpected token"));
                }
                let Some((kind, bytes, _name)) = import_desc(&mut mb, d, 0)? else {
                    // 範囲外の種別（tag 等）はインポート自体を落とす。
                    continue;
                };
                mb.imports.push((m, n, kind, bytes));
            }
            "func" => {
                let (_, exports, imp, i) = decl_head(l, 1)?;
                if let Some(pos) = imp {
                    let il = l[pos].list().unwrap();
                    let (m, n) = inline_import(il)?.unwrap();
                    let mut k = i;
                    let t = mb.type_use(l, &mut k)?;
                    let mut b = Vec::new();
                    ulebs(&mut b, u64::from(t));
                    let fidx = mb.imports.iter().filter(|x| x.2 == 0).count() as u32;
                    for pos2 in exports {
                        let en = inline_export(l[pos2].list().unwrap())?.unwrap();
                        mb.exports.push((en, 0, fidx));
                    }
                    mb.imports.push((m, n, 0x00, b));
                } else {
                    let fidx = imp_count[0] + mb.funcs.len() as u32;
                    for pos in exports {
                        let en = inline_export(l[pos].list().unwrap())?.unwrap();
                        mb.exports.push((en, 0, fidx));
                    }
                    emit_func_def(&mut mb, l, i)?;
                }
            }
            "table" => {
                let (_, exports, imp, i) = decl_head(l, 1)?;
                if let Some(pos) = imp {
                    let il = l[pos].list().unwrap();
                    let (m, n) = inline_import(il)?.unwrap();
                    let (tt, nn, _, _) = table_decl_plain(l, i)?;
                    let mut b = Vec::new();
                    if nn {
                        b.push(0x64);
                    }
                    b.push(tt.et.code());
                    emit_limits(&mut b, &tt.lim);
                    let tidx = mb.imports.iter().filter(|x| x.2 == 1).count() as u32;
                    for pos2 in exports {
                        let en = inline_export(l[pos2].list().unwrap())?.unwrap();
                        mb.exports.push((en, 1, tidx));
                    }
                    mb.imports.push((m, n, 0x01, b));
                    continue;
                }
                // (table $n? rt (elem ...)) の糖衣判定。
                let mut j = i;
                let mut et = RefType::Func;
                if let Some(Sx::Atom(a)) = l.get(j)
                    && reftype_of(a).is_some()
                {
                    et = reftype_of(a).unwrap();
                    j += 1;
                }
                let tidx = imp_count[1] + mb.tables.len() as u32;
                for pos in exports {
                    let en = inline_export(l[pos].list().unwrap())?.unwrap();
                    mb.exports.push((en, 1, tidx));
                }
                if let Some(Sx::List(el)) = l.get(j)
                    && el.first().and_then(Sx::atom) == Some("elem")
                {
                    // 初期化糖衣：limits = n..n、active elem seg 添付。
                    // 要素を数えて limits を作る。
                    let mut items = Vec::new();
                    for it in &el[1..] {
                        items.push(it.clone());
                    }
                    // active table 0 offset 0 として作り、table を差し替える。
                    // 先頭が elemkind/参照型でなければテーブルの要素型を補う。
                    let mut wrapped = vec![
                        Sx::Atom("elem".into()),
                        Sx::List(vec![
                            Sx::Atom("offset".into()),
                            Sx::List(vec![Sx::Atom("i32.const".into()), Sx::Atom("0".into())]),
                        ]),
                    ];
                    let has_kind = items
                        .first()
                        .is_some_and(|it| it.atom() == Some("func") || reftype_sx(it).is_some());
                    if !has_kind {
                        wrapped.push(match et {
                            RefType::Func => Sx::Atom("funcref".into()),
                            RefType::Extern => Sx::Atom("externref".into()),
                            RefType::Idx(_) => {
                                return Err(err("unsupported heap type index"));
                            }
                        });
                    }
                    wrapped.extend(items);
                    emit_elem(&mut mb, &wrapped, 1)?;
                    let last = mb.elems.last_mut().unwrap();
                    // table 指標をこのテーブルに差し替える（offset=0 の flag 4/0 を flag 6/2 へ）。
                    last.table = tidx;
                    last.flag = match last.flag {
                        0 => 2,
                        4 => 6,
                        x => x,
                    };
                    let n = last.funcs.len().max(last.exprs.len()) as u32;
                    mb.tables.push(TableType {
                        et,
                        lim: Limits {
                            min: n,
                            max: Some(n),
                        },
                    });
                    mb.table_inits.push(None);
                    mb.table_nonnull.push(false);
                    continue;
                }
                let (tt, nn, _, i2) = table_decl_plain(l, i)?;
                // `(table limits rt (expr))`: 2.0 の初期化式つき形。
                if l.len() == i2 + 1
                    && l[i2].list().is_some()
                    && l[i2].list().unwrap().first().and_then(Sx::atom) != Some("elem")
                {
                    let mut cx = FnCx {
                        mb: &mut mb,
                        locals: HashMap::new(),
                        labels: Vec::new(),
                    };
                    let e = const_expr_bytes(&mut cx, &l[i2])?;
                    mb.tables.push(tt);
                    mb.table_inits.push(Some(e));
                    mb.table_nonnull.push(nn);
                    continue;
                }
                // 末尾に要素を書く形: (table n rt e*) → n 個の active elem。
                if i2 < l.len() {
                    let tidx2 = imp_count[1] + mb.tables.len() as u32;
                    let mut wrapped = vec![
                        Sx::Atom("elem".into()),
                        Sx::List(vec![
                            Sx::Atom("offset".into()),
                            Sx::List(vec![Sx::Atom("i32.const".into()), Sx::Atom("0".into())]),
                        ]),
                    ];
                    let has_kind = l[i2..]
                        .first()
                        .is_some_and(|it| it.atom() == Some("func") || reftype_sx(it).is_some());
                    if !has_kind {
                        wrapped.push(match tt.et {
                            RefType::Func => Sx::Atom("funcref".into()),
                            RefType::Extern => Sx::Atom("externref".into()),
                            RefType::Idx(_) => {
                                return Err(err("unsupported heap type index"));
                            }
                        });
                    }
                    wrapped.extend(l[i2..].iter().cloned());
                    emit_elem(&mut mb, &wrapped, 1)?;
                    let last = mb.elems.last_mut().unwrap();
                    last.table = tidx2;
                    last.flag = match last.flag {
                        0 => 2,
                        4 => 6,
                        x => x,
                    };
                    let n = last.funcs.len().max(last.exprs.len()) as u32;
                    mb.tables.push(TableType {
                        et: tt.et,
                        lim: Limits {
                            min: n,
                            max: Some(n),
                        },
                    });
                    mb.table_inits.push(None);
                    mb.table_nonnull.push(nn);
                    continue;
                }
                mb.tables.push(tt);
                mb.table_inits.push(None);
                mb.table_nonnull.push(nn);
            }
            "memory" => {
                let (_, exports, imp, i) = decl_head(l, 1)?;
                if let Some(pos) = imp {
                    let il = l[pos].list().unwrap();
                    let (m, n) = inline_import(il)?.unwrap();
                    let (lim, _, _) = mem_decl_at(l, i)?;
                    let mut b = Vec::new();
                    emit_limits(&mut b, &lim);
                    let midx = mb.imports.iter().filter(|x| x.2 == 2).count() as u32;
                    for pos2 in exports {
                        let en = inline_export(l[pos2].list().unwrap())?.unwrap();
                        mb.exports.push((en, 2, midx));
                    }
                    mb.imports.push((m, n, 0x02, b));
                    continue;
                }
                let midx = imp_count[2] + mb.mems.len() as u32;
                for pos in exports {
                    let en = inline_export(l[pos].list().unwrap())?.unwrap();
                    mb.exports.push((en, 2, midx));
                }
                // (memory (data "...")) 糖衣。
                if let Some(Sx::List(d)) = l.get(i)
                    && d.first().and_then(Sx::atom) == Some("data")
                {
                    let mut bytes = Vec::new();
                    for it in &d[1..] {
                        if let Sx::Str(s) = it {
                            bytes.extend_from_slice(s);
                        }
                    }
                    let pages = bytes.len().div_ceil(65536) as u32;
                    mb.mems.push(Limits {
                        min: pages,
                        max: Some(pages),
                    });
                    // active data seg at offset 0, mem = midx
                    let mut seg = Vec::new();
                    ulebs(&mut seg, 2);
                    ulebs(&mut seg, u64::from(midx));
                    seg.extend_from_slice(&[0x41, 0x00, 0x0b]); // i32.const 0
                    emit_bytes(&mut seg, &bytes);
                    mb.datas.push(seg);
                    continue;
                }
                let (lim, _, _) = mem_decl_at(l, i)?;
                mb.mems.push(lim);
            }
            "global" => {
                let (_, exports, imp, i) = decl_head(l, 1)?;
                if let Some(pos) = imp {
                    let il = l[pos].list().unwrap();
                    let (m, n) = inline_import(il)?.unwrap();
                    let (gt, _, j) = global_decl_at(l, i)?;
                    let _ = j;
                    let mut b = Vec::new();
                    emit_valtype(&mut b, gt.vt);
                    b.push(u8::from(gt.mutable));
                    let gidx = mb.imports.iter().filter(|x| x.2 == 3).count() as u32;
                    for pos2 in exports {
                        let en = inline_export(l[pos2].list().unwrap())?.unwrap();
                        mb.exports.push((en, 3, gidx));
                    }
                    mb.imports.push((m, n, 0x03, b));
                    continue;
                }
                let (gt, _, j) = global_decl_at(l, i)?;
                let gidx = imp_count[3] + mb.globals.len() as u32;
                for pos in exports {
                    let en = inline_export(l[pos].list().unwrap())?.unwrap();
                    mb.exports.push((en, 3, gidx));
                }
                // 初期化式：`expr ::= instr*` なので畳み形とフラット形を
                // 混在して受け付ける（複数式は検証で type mismatch になる）。
                let mut init = Vec::new();
                {
                    let mut cx = FnCx {
                        mb: &mut mb,
                        locals: HashMap::new(),
                        labels: Vec::new(),
                    };
                    const_seq(&mut cx, &l[j..], &mut init)?;
                }
                init.push(0x0b);
                mb.globals.push((gt, init));
            }
            "export" => {
                let Some(Sx::List(d)) = l.get(2) else {
                    return Err(err("malformed export"));
                };
                let (kind, space) = match d.first().and_then(Sx::atom) {
                    Some("func") => (0u8, &mb.func_names),
                    Some("table") => (1, &mb.table_names),
                    Some("memory") => (2, &mb.mem_names),
                    Some("global") => (3, &mb.global_names),
                    // 範囲外の種別（tag 等）のエクスポートは落とす。
                    _ => continue,
                };
                let idx = idx_of(
                    d.get(1).ok_or_else(|| err("malformed export"))?,
                    space,
                    match kind {
                        0 => "function",
                        1 => "table",
                        2 => "memory",
                        _ => "global",
                    },
                )?;
                mb.exports.push((str_utf8(l.get(1))?, kind, idx));
            }
            "start" => {
                if mb.start.is_some() {
                    return Err(err("multiple start sections"));
                }
                let f = idx_of(
                    l.get(1).ok_or_else(|| err("malformed start"))?,
                    &mb.func_names,
                    "function",
                )?;
                mb.start = Some(f);
            }
            "elem" => {
                let i = if name_of(l, 1).is_some() { 2 } else { 1 };
                emit_elem(&mut mb, l, i)?;
            }
            "data" => {
                let i = if name_of(l, 1).is_some() { 2 } else { 1 };
                emit_data(&mut mb, l, i, None)?;
            }
            other => {
                return Err(err(&format!("unknown operator {other}")));
            }
        }
    }
    // --- セクション組み立て ---
    let mut out = Vec::new();
    out.extend_from_slice(b"\0asm");
    out.extend_from_slice(&[1, 0, 0, 0]);
    if !mb.types.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.types.len() as u64);
        for ft in &mb.types {
            p.push(0x60);
            ulebs(&mut p, ft.params.len() as u64);
            for t in &ft.params {
                emit_valtype(&mut p, *t);
            }
            ulebs(&mut p, ft.results.len() as u64);
            for t in &ft.results {
                emit_valtype(&mut p, *t);
            }
        }
        emit_section(&mut out, 1, &p);
    }
    if !mb.imports.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.imports.len() as u64);
        for (m, n, kind, desc) in &mb.imports {
            emit_name(&mut p, m);
            emit_name(&mut p, n);
            p.push(*kind);
            p.extend_from_slice(desc);
        }
        emit_section(&mut out, 2, &p);
    }
    if !mb.funcs.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.funcs.len() as u64);
        for t in &mb.funcs {
            ulebs(&mut p, u64::from(*t));
        }
        emit_section(&mut out, 3, &p);
    }
    if !mb.tables.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.tables.len() as u64);
        for ((t, init), nn) in mb.tables.iter().zip(&mb.table_inits).zip(&mb.table_nonnull) {
            if init.is_some() {
                p.push(0x40);
                p.push(0x00);
            }
            // `(ref ht)` は `0x64` + ヒープ型、`(ref null ht)` は `0x63`。
            if *nn {
                p.push(0x64);
            }
            p.push(t.et.code());
            emit_limits(&mut p, &t.lim);
            if let Some(e) = init {
                p.extend_from_slice(e);
            }
        }
        emit_section(&mut out, 4, &p);
    }
    if !mb.mems.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.mems.len() as u64);
        for lim in &mb.mems {
            emit_limits(&mut p, lim);
        }
        emit_section(&mut out, 5, &p);
    }
    if !mb.globals.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.globals.len() as u64);
        for (gt, init) in &mb.globals {
            emit_valtype(&mut p, gt.vt);
            p.push(u8::from(gt.mutable));
            p.extend_from_slice(init);
        }
        emit_section(&mut out, 6, &p);
    }
    if !mb.exports.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.exports.len() as u64);
        for (n, kind, idx) in &mb.exports {
            emit_name(&mut p, n);
            p.push(*kind);
            ulebs(&mut p, u64::from(*idx));
        }
        emit_section(&mut out, 7, &p);
    }
    if let Some(s) = mb.start {
        let mut p = Vec::new();
        ulebs(&mut p, u64::from(s));
        emit_section(&mut out, 8, &p);
    }
    if !mb.elems.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.elems.len() as u64);
        for e in &mb.elems {
            ulebs(&mut p, u64::from(e.flag));
            match e.flag {
                0 => {
                    p.extend_from_slice(e.offset.as_ref().unwrap());
                    ulebs(&mut p, e.funcs.len() as u64);
                    for f in &e.funcs {
                        ulebs(&mut p, u64::from(*f));
                    }
                }
                1 | 3 => {
                    p.push(0x00);
                    ulebs(&mut p, e.funcs.len() as u64);
                    for f in &e.funcs {
                        ulebs(&mut p, u64::from(*f));
                    }
                }
                2 => {
                    ulebs(&mut p, u64::from(e.table));
                    p.extend_from_slice(e.offset.as_ref().unwrap());
                    p.push(0x00);
                    ulebs(&mut p, e.funcs.len() as u64);
                    for f in &e.funcs {
                        ulebs(&mut p, u64::from(*f));
                    }
                }
                4 => {
                    p.extend_from_slice(e.offset.as_ref().unwrap());
                    ulebs(&mut p, e.exprs.len() as u64);
                    for x in &e.exprs {
                        p.extend_from_slice(x);
                    }
                }
                5 => {
                    if e.nonnull {
                        p.push(0x64);
                    }
                    p.push(e.kind.code());
                    ulebs(&mut p, e.exprs.len() as u64);
                    for x in &e.exprs {
                        p.extend_from_slice(x);
                    }
                }
                6 => {
                    ulebs(&mut p, u64::from(e.table));
                    p.extend_from_slice(e.offset.as_ref().unwrap());
                    if e.nonnull {
                        p.push(0x64);
                    }
                    p.push(e.kind.code());
                    ulebs(&mut p, e.exprs.len() as u64);
                    for x in &e.exprs {
                        p.extend_from_slice(x);
                    }
                }
                7 => {
                    if e.nonnull {
                        p.push(0x64);
                    }
                    p.push(e.kind.code());
                    ulebs(&mut p, e.exprs.len() as u64);
                    for x in &e.exprs {
                        p.extend_from_slice(x);
                    }
                }
                _ => unreachable!(),
            }
        }
        emit_section(&mut out, 9, &p);
    }
    // data count：data があれば必須。memory.init/data.drop 用にも出す。
    let has_bulk = mb
        .codes
        .iter()
        .any(|c| c.windows(2).any(|w| w == [0xfc, 0x08] || w == [0xfc, 0x09]));
    if !mb.datas.is_empty() || has_bulk {
        let mut p = Vec::new();
        ulebs(&mut p, mb.datas.len() as u64);
        emit_section(&mut out, 12, &p);
    }
    if !mb.codes.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.codes.len() as u64);
        for c in &mb.codes {
            p.extend_from_slice(c);
        }
        emit_section(&mut out, 10, &p);
    }
    if !mb.datas.is_empty() {
        let mut p = Vec::new();
        ulebs(&mut p, mb.datas.len() as u64);
        for d in &mb.datas {
            p.extend_from_slice(d);
        }
        emit_section(&mut out, 11, &p);
    }
    Ok(out)
}

/// `(memory $n? min max?)` を指定位置から読む。
fn mem_decl_at(l: &[Sx], i0: usize) -> R<(Limits, Option<String>, usize)> {
    let mut i = i0;
    let Some(Sx::Atom(min_a)) = l.get(i) else {
        return Err(err("malformed memory"));
    };
    let min =
        u32::try_from(parse_int_signed(min_a)?).map_err(|_| err("memory size exceeds limit"))?;
    i += 1;
    let mut max = None;
    if let Some(Sx::Atom(a)) = l.get(i) {
        max = Some(
            u32::try_from(parse_int_signed(a)?).map_err(|_| err("memory size exceeds limit"))?,
        );
        i += 1;
    }
    Ok((Limits { min, max }, None, i))
}

/// `(global $n? (mut t)|t)` を指定位置から読む。
fn global_decl_at(l: &[Sx], i0: usize) -> R<(GlobalType, Option<String>, usize)> {
    let i = i0;
    match l.get(i) {
        Some(Sx::List(inner)) if inner.first().and_then(Sx::atom) == Some("mut") => {
            let vt = inner
                .get(1)
                .and_then(valtype_sx)
                .ok_or_else(|| err("malformed value type"))?;
            Ok((GlobalType { vt, mutable: true }, None, i + 1))
        }
        Some(sx) if valtype_sx(sx).is_some() => Ok((
            GlobalType {
                vt: valtype_sx(sx).unwrap(),
                mutable: false,
            },
            None,
            i + 1,
        )),
        // 型位置の不明なアトム（例: 旧式の `anyfunc`）は
        // `unknown operator` を期待される。
        Some(Sx::Atom(a)) => Err(err(&format!("unknown operator {a}"))),
        _ => Err(err("malformed global")),
    }
}

/// `(module ...)` の S 式からバイナリを組み立てる。
/// `(module binary "...")` はバイト連結、`(module quote "...")` は再解析。
pub fn module_bytes(sx: &Sx) -> R<Vec<u8>> {
    let Some(items) = sx.list() else {
        return Err(err("expected (module ...)"));
    };
    if items.first().and_then(Sx::atom) != Some("module") {
        return Err(err("expected module"));
    }
    let mut i = 1;
    if let Some(Sx::Atom(a)) = items.get(i)
        && a.starts_with('$')
    {
        i += 1;
    }
    if let Some(Sx::Atom(k)) = items.get(i) {
        match k.as_str() {
            "binary" => {
                let mut out = Vec::new();
                for it in &items[i + 1..] {
                    match it {
                        Sx::Str(s) => out.extend_from_slice(s),
                        _ => return Err(err("malformed binary module")),
                    }
                }
                return Ok(out);
            }
            "quote" => {
                let mut text = Vec::new();
                for it in &items[i + 1..] {
                    match it {
                        Sx::Str(s) => text.extend_from_slice(s),
                        _ => return Err(err("malformed quoted module")),
                    }
                }
                let src = String::from_utf8(text).map_err(|_| err("malformed UTF-8 encoding"))?;
                let sxs = crate::sexpr::parse_all(&src).map_err(|e| err(&e.msg))?;
                // 引用の中身はモジュールの中身の列。ただし完全な
                // (module ...) が1つだけ入っている形も受け付ける。
                if sxs.len() == 1
                    && sxs[0]
                        .list()
                        .is_some_and(|l| l.first().and_then(Sx::atom) == Some("module"))
                {
                    return module_bytes(&sxs[0]);
                }
                return build_module(&sxs);
            }
            _ => {}
        }
    }
    build_module(&items[i..])
}

/// テキストのモジュールをバイナリにする。
pub fn module_from_str(src: &str) -> R<Vec<u8>> {
    let sx = crate::sexpr::parse_one(src).map_err(|e| err(&e.msg))?;
    module_bytes(&sx)
}
