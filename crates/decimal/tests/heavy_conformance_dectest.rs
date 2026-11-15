// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! decTest との比較（層5・conformance）。
//!
//! `.testdata/dectest` のテキスト形式を読み、四則・比較・符号化
//! （`apply`）・変換の結果と条件を照合する。データはリポジトリに
//! 含めない。取得元・権利・SHA-256 は台帳 TEST-DECTEST を見る。
//! データがなければ `devtool test:plan` が実行対象から外す。

use polyisa_decimal::dfp::{self, Ctx, Dec, DfpFmt, FMT_D32, FMT_D64, FMT_D128, Kind, Rm, cond};
use std::path::PathBuf;

fn testdata_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.join(".testdata").join("dectest")
}

// ---- decTest パーサ ----

/// 空白区切りだが '...' と "..." は一連のトークン。
/// トークン分解。引用符付きトークンは to-number 構文チェックの
/// 対象なので引用の有無も返す（(text, quoted)）。
fn tokens(line: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b' ' | b'\t' => i += 1,
            b'\'' | b'"' => {
                let q = b[i];
                i += 1;
                let start = i;
                while i < b.len() && b[i] != q {
                    i += 1;
                }
                out.push((String::from_utf8_lossy(&b[start..i]).into_owned(), true));
                i += 1;
            }
            _ => {
                let start = i;
                while i < b.len() && b[i] != b' ' && b[i] != b'\t' {
                    i += 1;
                }
                out.push((String::from_utf8_lossy(&b[start..i]).into_owned(), false));
            }
        }
    }
    out
}

fn rounding(s: &str) -> Option<Rm> {
    Some(match s.to_ascii_lowercase().replace('-', "_").as_str() {
        "half_even" | "half_even_" => Rm::HalfEven,
        "half_up" => Rm::HalfUp,
        "half_down" => Rm::HalfDown,
        "up" => Rm::Up,
        "down" => Rm::Down,
        "ceiling" => Rm::Ceiling,
        "floor" => Rm::Floor,
        "05up" | "half_05up" => Rm::Up05,
        _ => return None,
    })
}

fn cond_of(name: &str) -> Option<u32> {
    Some(match name.to_ascii_lowercase().as_str() {
        "clamped" => cond::CLAMPED,
        "conversion_syntax" => cond::CONV_SYNTAX,
        "division_by_zero" => cond::DIV_ZERO,
        "division_impossible" => cond::DIV_IMPOSSIBLE,
        "division_undefined" => cond::DIV_UNDEFINED,
        "inexact" => cond::INEXACT,
        "insufficient_storage" => cond::INSUFF_STORAGE,
        "invalid_operation" => cond::INVALID,
        "lost_digits" => cond::LOST_DIGITS,
        "overflow" => cond::OVERFLOW,
        "rounded" => cond::ROUNDED,
        "subnormal" => cond::SUBNORMAL,
        "underflow" => cond::UNDERFLOW,
        "no_flags" | "invalid_context" => 0,
        _ => return None,
    })
}

struct Case {
    file: String,
    id: String,
    op: String,
    args: Vec<String>,
    /// args と並行：引用符付き（to-number 構文テスト）なら true。
    quoted: Vec<bool>,
    want: String,
    want_conds: u32,
    ctx: Ctx,
    extended: bool,
}

fn parse_file(name: &str, body: &str) -> (Vec<Case>, Vec<String>) {
    // decTest の既定: precision 9、emax 999、emin -999、half_even、
    // clamp 0、extended 1（extended=0 では未対応の検査になる）。
    let mut ctx = Ctx {
        prec: 9,
        emax: 999,
        emin: -999,
        rm: Rm::HalfEven,
        clamp: false,
    };
    let mut extended = true;
    let mut cases = Vec::new();
    let mut skipped = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("--") {
            continue;
        }
        // 指示行: "name: value"（name は大文字小文字を区別しない）。
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            // 行末の "-- comment" を捨てて最初のトークンを取る。
            let v = v.split("--").next().unwrap_or("").trim();
            match k.as_str() {
                "precision" => ctx.prec = v.parse().unwrap_or(0),
                "maxexponent" => ctx.emax = v.parse().unwrap_or(0),
                "minexponent" => ctx.emin = v.parse().unwrap_or(0),
                "rounding" => ctx.rm = rounding(v).unwrap_or(Rm::HalfEven),
                "clamp" => ctx.clamp = v == "1",
                "extended" => extended = v != "0",
                _ => {}
            }
            continue;
        }
        if !line.contains("->") {
            continue;
        }
        let toks = tokens(line);
        if toks.len() < 4 {
            skipped.push(line.to_string());
            continue;
        }
        let id = toks[0].0.clone();
        let op = toks[1].0.clone();
        let arrow = toks.iter().position(|t| t.0 == "->");
        let Some(arrow) = arrow else {
            skipped.push(line.to_string());
            continue;
        };
        let args: Vec<String> = toks[2..arrow].iter().map(|t| t.0.clone()).collect();
        let quoted: Vec<bool> = toks[2..arrow].iter().map(|t| t.1).collect();
        let mut want = String::new();
        let mut wconds = 0u32;
        let mut ok = true;
        for (n, t) in toks[arrow + 1..].iter().enumerate() {
            if n == 0 {
                want = t.0.clone();
            } else {
                match cond_of(&t.0) {
                    Some(c) => wconds |= c,
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
        }
        if !ok {
            skipped.push(line.to_string());
            continue;
        }
        cases.push(Case {
            file: name.to_string(),
            id,
            op,
            args,
            quoted,
            want,
            want_conds: wconds,
            ctx,
            extended,
        });
    }
    (cases, skipped)
}

// ---- 被試験演算 ----

fn fmt_for(ctx: &Ctx) -> Option<DfpFmt> {
    [FMT_D32, FMT_D64, FMT_D128]
        .into_iter()
        .find(|f| f.ctx().prec == ctx.prec && f.ctx().emax == ctx.emax)
}

/// NULL オペランド（'#' 単独）を示す内部フラグ。decTest の条件
/// ビット（<= UNDERFLOW=4096）と衝突しない位置を使う。
const NULL_OP: u32 = 1 << 30;

/// 1 個の値をコンテキストに合わせる（decTest の入力側の規則では
/// 係数が precision を超えると Lost_digits、指数超過は Invalid になる）。
/// extended=0 のときのみ適用する。
fn fit_input(d: &Dec, c: &Case) -> (Dec, u32) {
    if c.extended || d.kind != Kind::Finite {
        return (d.clone(), 0);
    }
    // extended=0: 係数桁数は precision まで、指数は範囲内（Etiny〜Etop）。
    if d.is_nan() {
        return (d.clone(), 0);
    }
    let mut f = 0u32;
    let out = d.clone();
    if out.digits() > c.ctx.prec {
        return (Dec::nan(false), cond::INVALID);
    }
    if !out.is_zero() {
        let etiny = c.ctx.emin - c.ctx.prec as i32 + 1;
        if out.exp < etiny || out.exp > c.ctx.emax {
            return (Dec::nan(false), cond::INVALID);
        }
    }
    let _ = &mut f;
    (out, f)
}

/// 書式名の接頭 "N#"（例 "64#1E+384"）。その書式で表される
/// 係数形（コーホート）に変換する。指数が etop を超える分は
/// 係数の 0 詰めで吸収する（IEEE の clamped 表現）。
fn fmt_apply(d: &Dec, f: &DfpFmt) -> Dec {
    if d.kind != Kind::Finite {
        return d.clone();
    }
    let mut x = d.clone();
    let etop = i64::from(f.emax) - i64::from(f.prec) + 1;
    let etiny = i64::from(f.emax) - 2 * (i64::from(f.prec) - 1);
    if !x.is_zero() && i64::from(x.exp) > etop {
        let pad = i64::from(x.exp) - etop;
        if x.digits() as i64 + pad <= i64::from(f.prec) {
            for _ in 0..pad {
                x.coef.push(0);
            }
            x.exp = etop as i32;
        }
    }
    let _ = etiny;
    x
}

fn fmt_by_name(n: u32) -> Option<DfpFmt> {
    [FMT_D32, FMT_D64, FMT_D128]
        .into_iter()
        .find(|f| f.bits == n)
}

fn operand(tok: &str, quoted: bool, c: &Case) -> Result<(Dec, u32), String> {
    if tok == "#" {
        // NULL オペランド。専用ビットを立てて run() 側で
        // NaN + Invalid_operation にする（comparetotal のように
        // sNaN でも例外を立てない演算があるため値としては
        // 区別できる印が要る）。
        return Ok((Dec::nan(false), NULL_OP));
    }
    if let Some(h) = tok.strip_prefix('#') {
        let bits = u128::from_str_radix(h, 16).map_err(|e| e.to_string())?;
        let f = fmt_for(&c.ctx).ok_or("no fmt")?;
        return Ok((dfp::decode(f, bits), 0));
    }
    // "64#…" のような書式名接頭。その書式のコーホートに変換する。
    let mut text = tok;
    let mut cohort: Option<DfpFmt> = None;
    if let Some((n, rest)) = tok.split_once('#')
        && !rest.starts_with('#')
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
        && let Ok(v) = n.parse::<u32>()
    {
        cohort = fmt_by_name(v);
        text = rest;
    }
    match tok {
        "+" | "-" => return Err("sign token".into()),
        _ => {}
    }
    match Dec::parse(text) {
        Some(mut d) => {
            if let Some(f) = cohort {
                d = fmt_apply(&d, &f);
            }
            // 引用符付き（to-number テスト）の NaN 診断桁は書式なら
            // prec-1、一般文脈なら prec 桁まで。裸オペランドは抽象値。
            if quoted && d.is_nan() {
                let lim = if fmt_for(&c.ctx).is_some() {
                    c.ctx.prec - 1
                } else {
                    c.ctx.prec
                };
                if d.digits() > lim {
                    return Ok((Dec::nan(false), cond::CONV_SYNTAX));
                }
            }
            Ok(fit_input(&d, c))
        }
        None => Ok((Dec::nan(false), cond::CONV_SYNTAX)),
    }
}

/// 演算を実行する。未対応は Err。
fn run(c: &Case) -> Result<(Dec, u32), String> {
    let ctx = &c.ctx;
    let (a, fa) = operand(&c.args[0], c.quoted.first().copied().unwrap_or(false), c)?;
    // コーパスには tosci / remainderNear のような大小混在がある。
    let op = c.op.to_ascii_lowercase();
    let unary = |f: &dyn Fn(&Dec, &Ctx) -> (Dec, u32)| -> (Dec, u32) {
        let (r, x) = f(&a, ctx);
        (r, x | fa)
    };
    let (b, fb) = if c.args.len() > 1 {
        operand(&c.args[1], c.quoted.get(1).copied().unwrap_or(false), c)?
    } else {
        (Dec::zero(false), 0)
    };
    let flags_in = fa | fb;
    // NULL オペランド（'#'）は全演算で NaN + Invalid_operation。
    if flags_in & NULL_OP != 0 {
        return Ok((Dec::nan(false), cond::INVALID | (flags_in & !NULL_OP)));
    }
    Ok(match op.as_str() {
        "add" => {
            let (r, f) = a.add(&b, ctx);
            (r, f | flags_in)
        }
        "subtract" => {
            let (r, f) = a.sub(&b, ctx);
            (r, f | flags_in)
        }
        "multiply" => {
            let (r, f) = a.mul(&b, ctx);
            (r, f | flags_in)
        }
        "divide" => {
            let (r, f) = a.div(&b, ctx);
            (r, f | flags_in)
        }
        "compare" => {
            let (r, f) = a.compare(&b, ctx);
            (r, f | flags_in)
        }
        "comparesig" => {
            let (r, f) = a.compare_sig(&b, ctx);
            (r, f | flags_in)
        }
        "comparetotal" => (compare_total(&a, &b, false, ctx), flags_in),
        "comparetotmag" => (compare_total(&a, &b, true, ctx), flags_in),
        "max" => {
            let (r, f) = a.max_num(&b, ctx);
            (r, f | flags_in)
        }
        "min" => {
            let (r, f) = a.min_num(&b, ctx);
            (r, f | flags_in)
        }
        "maxmag" => {
            let (r, f) = a.max_mag(&b, ctx);
            (r, f | flags_in)
        }
        "minmag" => {
            let (r, f) = a.min_mag(&b, ctx);
            (r, f | flags_in)
        }
        "quantize" => {
            let (r, f) = a.quantize(&b, ctx);
            let mut f = f | flags_in;
            // N# 書式バインドの量子化では、結果指数が Etop を超えると
            // IEEE の Clamped が立つ（抽象文脈では立たない）。
            let bound = c.args.iter().any(|t| t.contains('#')) || c.want.contains('#');
            if bound
                && r.kind == Kind::Finite
                && i64::from(r.exp) > i64::from(ctx.emax) - i64::from(ctx.prec) + 1
            {
                f |= cond::CLAMPED;
            }
            (r, f)
        }
        "samequantum" => {
            let (r, f) = a.same_quantum(&b);
            (r, f | flags_in)
        }
        "fma" => {
            let (c2, fc) = operand(&c.args[2], c.quoted.get(2).copied().unwrap_or(false), c)?;
            if fc & NULL_OP != 0 {
                return Ok((Dec::nan(false), cond::INVALID | (fc & !NULL_OP) | flags_in));
            }
            let (r, f) = a.fma(&b, &c2, ctx);
            (r, f | flags_in | fc)
        }
        "plus" => unary(&|d, c| d.plus(c)),
        "minus" => unary(&|d, c| d.minus(c)),
        "abs" => unary(&|d, c| d.abs(c)),
        "copy" => (a, flags_in),
        "copyabs" => unary(&|d, _| {
            let mut x = d.clone();
            x.neg = false;
            (x, 0)
        }),
        "copynegate" => unary(&|d, _| {
            let mut x = d.clone();
            x.neg = !x.neg;
            (x, 0)
        }),
        "copysign" => {
            let mut x = a.clone();
            x.neg = b.neg;
            (x, flags_in)
        }
        "reduce" | "trim" => {
            let (r, f) = a.reduce(ctx);
            (r, f | flags_in)
        }
        "tointegral" => {
            let (r, f) = a.to_integral(false, ctx);
            (r, f | flags_in)
        }
        "tointegralx" => {
            let (r, f) = a.to_integral(true, ctx);
            (r, f | flags_in)
        }
        "rescale" => {
            // 第2項は指数の値（整数の Dec として与えられる）。
            let (r, f) = a.rescale(&b, ctx);
            (r, f | flags_in)
        }
        "squareroot" => {
            let (r, f) = a.sqrt(ctx);
            (r, f | flags_in)
        }
        "power" => {
            let (r, f) = power_int(&a, &b, ctx);
            (r, f | flags_in)
        }
        "divideint" => {
            let (r, f) = divide_int(&a, &b, ctx);
            (r, f | flags_in)
        }
        "remainder" => {
            let (r, f) = remainder(&a, &b, ctx, false);
            (r, f | flags_in)
        }
        "remaindernear" => {
            let (r, f) = remainder(&a, &b, ctx, true);
            (r, f | flags_in)
        }
        "and" | "or" | "xor" | "invert" => {
            let (r, f) = logical(op.as_str(), &a, &b, ctx);
            (r, f | flags_in)
        }
        "shift" => {
            let (r, f) = shift_digits(&a, &b, ctx);
            (r, f | flags_in)
        }
        "rotate" => {
            let (r, f) = rotate_digits(&a, &b, ctx);
            (r, f | flags_in)
        }
        "scaleb" => {
            let (r, f) = scaleb(&a, &b, ctx);
            (r, f | flags_in)
        }
        "logb" => {
            let (r, f) = logb(&a, ctx);
            (r, f | flags_in)
        }
        "nextplus" => {
            let (r, f) = next(&a, ctx, 1, false);
            (r, f | flags_in)
        }
        "nextminus" => {
            let (r, f) = next(&a, ctx, -1, false);
            (r, f | flags_in)
        }
        "nexttoward" => {
            let (r, f) = next_toward(&a, &b, ctx);
            (r, f | flags_in)
        }
        "canonical" => {
            // 抽象値の正規化は文脈適用（符号は保持）。
            let (r, f) = a.clone().finish(ctx);
            (r, f | flags_in)
        }
        "apply" => {
            // '#' で取った値は decode 済み。文字列は parse 済み。
            // apply は文脈を適用するが -0 の符号は保持し、
            // NaN はそのまま返す（quiet 化しない）。
            if a.is_nan() {
                (a.clone(), fa)
            } else {
                let (r, f) = a.clone().finish(ctx);
                (r, f | flags_in)
            }
        }
        "tosci" | "toeng" => {
            // 文字列化は文脈を適用してから書式化する（-0 の符号は
            // 保持）。書式を伴う比較のため文字列はエラー経路で返す。
            let (r, f) = if a.is_nan() {
                (a.clone(), fa)
            } else {
                let (rr, ff) = a.clone().finish(ctx);
                (rr, ff | flags_in)
            };
            let t = if op == "toeng" {
                r.to_eng()
            } else {
                r.to_sci()
            };
            return Err(format!("str:{f:x}:{t}"));
        }
        "class" => {
            let s = class_of(&a, ctx);
            return Err(format!("class:{s}")); // 文字列を返す特殊演算
        }
        "exp" | "ln" | "log" | "log10" | "powersqrt" | "isnormal" | "issubnormal" | "iszero"
        | "issigned" | "isinf" | "isnan" | "isqnan" | "issnan" | "iscanonical" | "isfinite"
        | "isinfinite" | "isnormalfinite" | "sign" | "radix" | "digits" => {
            return Err(format!("unimplemented op {op}"));
        }
        _ => return Err(format!("unknown op {op}")),
    })
}

/// NaN の伝播。sNaN があればそれを quiet 化して INVALID、
/// なければ最初の qNaN をそのまま返す。ペイロードは precision 桁に収める。
fn nan_prop(a: &Dec, b: &Dec, ctx: &Ctx) -> Option<(Dec, u32)> {
    let snan = a.kind == Kind::Snan || b.kind == Kind::Snan;
    let src = if a.kind == Kind::Snan {
        Some(a)
    } else if b.kind == Kind::Snan {
        Some(b)
    } else if a.is_nan() {
        Some(a)
    } else if b.is_nan() {
        Some(b)
    } else {
        None
    };
    let s = src?;
    let mut n = s.clone();
    n.kind = Kind::Qnan;
    let nd = n.digits() as usize;
    if nd > ctx.prec as usize {
        let drop = nd - ctx.prec as usize;
        n.coef.drain(0..drop);
    }
    Some((n, if snan { cond::INVALID } else { 0 }))
}

/// 整数のべき（power）。指数が整数なら厳密な累乗を作ってから
/// 一度だけ丸める（IEEE の整数指数 power は正確に丸められる）。
fn power_int(a: &Dec, b: &Dec, ctx: &Ctx) -> (Dec, u32) {
    use polyisa_decimal::PackedDec;
    if let Some(r) = nan_prop(a, b, ctx) {
        return r;
    }
    // b は整数値が必要。値として整数でなければ未対応の形。
    let n = match as_int(b) {
        Some(n) if n.abs() <= 10_000 => n,
        _ => return (Dec::nan(false), cond::INVALID),
    };
    if a.kind == Kind::Inf {
        if n == 0 {
            return (Dec::finite(false, vec![1], 0), 0);
        }
        // Inf の整数べき。負べきは 0、正べきは Inf。
        let neg = a.neg && n % 2 != 0;
        if n < 0 {
            let mut d = Dec::zero(neg);
            d.exp = 0;
            return (d, 0);
        }
        return (Dec::inf(neg), 0);
    }
    if a.is_zero() {
        let neg = a.neg && n % 2 != 0;
        if n == 0 {
            return (Dec::finite(false, vec![1], 0), 0);
        }
        if n < 0 {
            return (Dec::inf(neg), cond::DIV_ZERO);
        }
        let mut d = Dec::zero(neg);
        d.exp = a.exp.saturating_mul(n as i32);
        return d.finish(ctx);
    }
    if n == 0 {
        return (Dec::finite(false, vec![1], 0), 0);
    }
    // 係数の |n| 乗を厳密に計算。
    let base = PackedDec::from_digits(&a.coef, false).unwrap();
    let mut acc = PackedDec::from_digits(&[1], false).unwrap();
    let mut k = n.unsigned_abs();
    let mut p = base;
    while k > 0 {
        if k & 1 == 1 {
            acc = acc.mul(&p);
        }
        k >>= 1;
        if k > 0 {
            p = p.mul(&p);
        }
    }
    let e = i64::from(a.exp) * n.unsigned_abs() as i64;
    let e = e.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
    let neg = a.neg && n % 2 != 0;
    let d = Dec::finite(neg, acc.digits.clone(), e);
    if n > 0 {
        d.finish(ctx)
    } else {
        // 負べきは 1/x^|n|。一度の除算なので正確に丸められる。
        Dec::finite(false, vec![1], 0).div(&d, ctx)
    }
}

/// 整数値を i64 として取り出す（有限・整数値・範囲内のみ）。
fn as_int(d: &Dec) -> Option<i64> {
    if d.kind != Kind::Finite {
        return None;
    }
    let mut v: i64 = 0;
    for &x in &d.coef {
        v = v.checked_mul(10)?.checked_add(i64::from(x))?;
    }
    let e = i64::from(d.exp);
    if e >= 0 {
        v = v.checked_mul(10i64.checked_pow(e.min(18) as u32)?)?;
        if e > 18 && v != 0 {
            return None;
        }
    } else {
        // 10^-e で割り切れること。
        let div = 10i64.checked_pow((-e).min(18) as u32)?;
        if -e > 18 || v % div != 0 {
            return None;
        }
        v /= div;
    }
    Some(if d.neg { -v } else { v })
}

fn scale_exp(b: &Dec) -> i32 {
    // b は整数のはず。係数を i32 にする。
    let mut v: i64 = 0;
    for &d in &b.coef {
        v = v * 10 + i64::from(d);
    }
    // exp の分だけ 0 を足す（b は整数のはずだが exp が負のこともある）。
    for _ in 0..b.exp.max(0) {
        v = v.saturating_mul(10);
    }
    let v = if b.neg { -v } else { v };
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// 整数除算。商の桁が precision を超えれば Division_impossible。
fn divide_int(a: &Dec, b: &Dec, ctx: &Ctx) -> (Dec, u32) {
    use polyisa_decimal::PackedDec;
    if let Some(r) = nan_prop(a, b, ctx) {
        return r;
    }
    let neg = a.neg ^ b.neg;
    if b.kind == Kind::Inf {
        if a.kind == Kind::Inf {
            return (Dec::nan(false), cond::INVALID);
        }
        return (Dec::zero(neg), 0);
    }
    if a.kind == Kind::Inf {
        return (Dec::inf(neg), 0);
    }
    if b.is_zero() {
        if a.is_zero() {
            return (Dec::nan(false), cond::DIV_UNDEFINED);
        }
        // 整数除算の 0 除算は Infinity + Division_by_zero。
        return (Dec::inf(neg), cond::DIV_ZERO);
    }
    if a.is_zero() {
        return (Dec::zero(neg), 0);
    }
    // a = c1*10^e1, b = c2*10^e2。GDA: 結果の指数は 0。
    // 桁数から商の大きさを先に見積もり、不可能なら計算しない。
    let e = i64::from(a.exp) - i64::from(b.exp);
    let nl = a.digits() as i64 + e.max(0);
    let dl = b.digits() as i64 + (-e).max(0);
    if nl < dl {
        // |num| < |den| → 商は 0。
        return (Dec::zero(neg), 0);
    }
    if nl - dl + 1 > i64::from(ctx.prec) {
        return (Dec::nan(false), cond::DIV_IMPOSSIBLE);
    }
    let mut num = a.coef.clone();
    num.resize(a.coef.len() + e.max(0) as usize, 0);
    let mut den = b.coef.clone();
    den.resize(b.coef.len() + (-e).max(0) as usize, 0);
    let np = PackedDec::from_digits(&num, false).unwrap();
    let dp = PackedDec::from_digits(&den, false).unwrap();
    let (q, _r) = np.divmod(&dp).unwrap();
    let qd = Dec::finite(neg, q.digits, 0);
    if qd.digits() > ctx.prec {
        return (Dec::nan(false), cond::DIV_IMPOSSIBLE);
    }
    (qd, 0)
}

/// 剰余。a - n*b（n は整数商、近い方は remaindernear）。
fn remainder(a: &Dec, b: &Dec, ctx: &Ctx, near: bool) -> (Dec, u32) {
    use polyisa_decimal::PackedDec;
    if let Some(r) = nan_prop(a, b, ctx) {
        return r;
    }
    if b.kind == Kind::Inf {
        if a.kind == Kind::Inf {
            return (Dec::nan(false), cond::INVALID);
        }
        let (r, f) = a.clone().finish(ctx);
        return (r, f);
    }
    if a.kind == Kind::Inf {
        return (Dec::nan(false), cond::INVALID);
    }
    if b.is_zero() {
        if a.is_zero() {
            return (Dec::nan(false), cond::DIV_UNDEFINED);
        }
        // remainder の 0 除算は Invalid_operation（Infinity ではない）。
        return (Dec::nan(false), cond::INVALID);
    }
    if a.is_zero() {
        let mut d = Dec::zero(a.neg);
        d.exp = a.exp.min(b.exp);
        return d.finish(ctx);
    }
    // 桁数から商の大きさを先に見積もり、不可能なら計算しない。
    let e = i64::from(a.exp) - i64::from(b.exp);
    let nl = a.digits() as i64 + e.max(0);
    let dl = b.digits() as i64 + (-e).max(0);
    if nl < dl && !near {
        // |a| < |b| → 剰余は a を min(e1,e2) の指数に合わせた形。
        let mut d = a.clone();
        let pad = (i64::from(a.exp) - i64::from(a.exp).min(i64::from(b.exp))).max(0) as usize;
        for _ in 0..pad {
            d.coef.push(0);
        }
        d.exp = a.exp.min(b.exp);
        return d.finish(ctx);
    }
    // 商の桁数は nl-dl か nl-dl+1。nl-dl が precision を超えれば
    // 確実に不可能（境界は実際の商で判定する）。
    if nl - dl > i64::from(ctx.prec) {
        return (Dec::nan(false), cond::DIV_IMPOSSIBLE);
    }
    let mut num = a.coef.clone();
    num.resize(a.coef.len() + e.max(0) as usize, 0);
    let mut den = b.coef.clone();
    den.resize(b.coef.len() + (-e).max(0) as usize, 0);
    let np = PackedDec::from_digits(&num, false).unwrap();
    let dp = PackedDec::from_digits(&den, false).unwrap();
    let (q, r) = np.divmod(&dp).unwrap();
    let mut n = q;
    if near && !r.is_zero() {
        // |2r| >= |den| なら商を 1 増やす（同距離は偶数側）。
        let two_r = r.add(&r);
        match two_r.cmp(&dp) {
            core::cmp::Ordering::Greater => {
                n = n.add(&PackedDec::from_digits(&[1], false).unwrap());
            }
            core::cmp::Ordering::Equal => {
                if n.digits.last().is_some_and(|d| d % 2 == 1) {
                    n = n.add(&PackedDec::from_digits(&[1], false).unwrap());
                }
            }
            core::cmp::Ordering::Less => {}
        }
    }
    // 丸め後の商が precision を超えれば Division_impossible。
    if n.digit_len() > ctx.prec as usize {
        return (Dec::nan(false), cond::DIV_IMPOSSIBLE);
    }
    // 剰余 = num - n*den を exp=min(e1,e2) の世界で求める。
    // n を増やした場合は負になりうる（剰余の符号が被除数と逆）。
    let prod = n.mul(&dp);
    let (mag, neg_mag) = if prod.cmp(&np) == core::cmp::Ordering::Greater {
        (prod.sub(&np), true)
    } else {
        (np.sub(&prod), false)
    };
    let mut d = Dec::finite(a.neg ^ neg_mag, mag.digits, a.exp.min(b.exp));
    if d.is_zero() {
        // 0 の符号は被除数の符号。
        d.neg = a.neg;
    }
    d.finish(ctx)
}

/// 論理演算。係数は全桁 0/1 で precision 桁以下、指数 0 が前提。
fn logical(op: &str, a: &Dec, b: &Dec, ctx: &Ctx) -> (Dec, u32) {
    // 論理オペランド：正・指数 0・全桁 0/1。桁数は precision を
    // 超えてもよく、その場合は窓の右端 prec 桁だけが使われる。
    let valid =
        |d: &Dec| d.kind == Kind::Finite && !d.neg && d.exp == 0 && d.coef.iter().all(|&x| x <= 1);
    // 論理演算では非有限オペランド（NaN・Inf）はすべて Invalid_operation。
    if a.kind != Kind::Finite || (op != "invert" && b.kind != Kind::Finite) {
        return (Dec::nan(false), cond::INVALID);
    }
    if !valid(a) || (op != "invert" && !valid(b)) {
        return (Dec::nan(false), cond::INVALID);
    }
    let n = ctx.prec as usize;
    let mut full_a = vec![0u8; n];
    let mut full_b = vec![0u8; n];
    let la = a.coef.len().min(n);
    let srca = a.coef[a.coef.len() - la..].to_vec();
    full_a[n - la..].copy_from_slice(&srca);
    if op != "invert" {
        let lb = b.coef.len().min(n);
        let srcb = b.coef[b.coef.len() - lb..].to_vec();
        full_b[n - lb..].copy_from_slice(&srcb);
    }
    let mut out = vec![0u8; n];
    for i in 0..n {
        out[i] = match op {
            "and" => u8::from(full_a[i] == 1 && full_b[i] == 1),
            "or" => u8::from(full_a[i] == 1 || full_b[i] == 1),
            "xor" => u8::from((full_a[i] == 1) != (full_b[i] == 1)),
            "invert" => 1 - full_a[i],
            _ => 0,
        };
    }
    let mut res = Dec::finite(false, out, 0);
    // 先頭の 0 は削る（結果の係数は正規化される）。
    let first = res
        .coef
        .iter()
        .position(|&d| d != 0)
        .unwrap_or(res.coef.len() - 1);
    res.coef.drain(0..first);
    (res, 0)
}

/// シフト/回転の第2項の妥当性：有限・exp==0・|値| <= precision。
fn shift_amount(b: &Dec, ctx: &Ctx) -> Option<i32> {
    if b.kind != Kind::Finite || b.exp != 0 {
        return None;
    }
    let v = scale_exp(b);
    if v.abs() > ctx.prec as i32 {
        return None;
    }
    Some(v)
}

/// 桁シフト。第2項はシフト量（-precision..=precision）。
fn shift_digits(a: &Dec, b: &Dec, ctx: &Ctx) -> (Dec, u32) {
    if let Some(r) = nan_prop(a, b, ctx) {
        return r;
    }
    let Some(k) = shift_amount(b, ctx) else {
        return (Dec::nan(false), cond::INVALID);
    };
    if a.kind == Kind::Inf {
        return (Dec::inf(a.neg), 0);
    }
    let p = ctx.prec as usize;
    let mut full = vec![0u8; p];
    let l = a.coef.len().min(p);
    let src = a.coef[a.coef.len() - l..].to_vec();
    full[p - l..].copy_from_slice(&src);
    let mut out = vec![0u8; p];
    if k >= 0 {
        // 左シフト：上位に押し出された桁は捨てる。
        let k = k as usize;
        for i in 0..p {
            if i + k < p {
                out[i] = full[i + k];
            }
        }
    } else {
        // 右シフト：下位に押し出された桁は捨てる。
        let k = (-k) as usize;
        for i in 0..p {
            if i >= k {
                out[i] = full[i - k];
            }
        }
    }
    let mut res = Dec::finite(a.neg, out, a.exp);
    let first = res
        .coef
        .iter()
        .position(|&d| d != 0)
        .unwrap_or(res.coef.len() - 1);
    res.coef.drain(0..first);
    (res, 0)
}

/// 桁回転。
fn rotate_digits(a: &Dec, b: &Dec, ctx: &Ctx) -> (Dec, u32) {
    if let Some(r) = nan_prop(a, b, ctx) {
        return r;
    }
    let Some(k) = shift_amount(b, ctx) else {
        return (Dec::nan(false), cond::INVALID);
    };
    if a.kind == Kind::Inf {
        return (Dec::inf(a.neg), 0);
    }
    let p = ctx.prec as usize;
    let mut full = vec![0u8; p];
    let l = a.coef.len().min(p);
    let src = a.coef[a.coef.len() - l..].to_vec();
    full[p - l..].copy_from_slice(&src);
    let k = k.rem_euclid(p as i32) as usize;
    let mut out = vec![0u8; p];
    for i in 0..p {
        out[i] = full[(i + k) % p];
    }
    let mut res = Dec::finite(a.neg, out, a.exp);
    let first = res
        .coef
        .iter()
        .position(|&d| d != 0)
        .unwrap_or(res.coef.len() - 1);
    res.coef.drain(0..first);
    (res, 0)
}

/// scaleb。a × 10^b（b は整数）。
fn scaleb(a: &Dec, b: &Dec, ctx: &Ctx) -> (Dec, u32) {
    if let Some(r) = nan_prop(a, b, ctx) {
        return r;
    }
    if a.kind == Kind::Inf {
        return (Dec::inf(a.neg), 0);
    }
    if b.kind == Kind::Inf {
        return (Dec::nan(false), cond::INVALID);
    }
    let k = scale_exp(b);
    // 第 2 項は指数 0 の整数形が必須（1E+1 や 1.00 は Invalid）。
    // 範囲は ±(2*(emax+prec)) 程度まで。超過は INVALID。
    let limit = 2 * (ctx.emax + ctx.prec as i32);
    if k.abs() > limit || b.exp != 0 {
        // b が整数形でない・大きすぎる。
        return (Dec::nan(false), cond::INVALID);
    }
    let mut d = a.clone();
    d.exp = d.exp.saturating_add(k);
    d.finish(ctx)
}

/// logb。調整済み指数を整数として返す。
fn logb(a: &Dec, ctx: &Ctx) -> (Dec, u32) {
    if a.is_nan() {
        // ペイロードは伝播させる（sNaN は quiet 化 + INVALID）。
        return nan_prop(a, &Dec::zero(false), ctx).unwrap_or((Dec::nan(false), cond::INVALID));
    }
    if a.kind == Kind::Inf {
        return (Dec::inf(false), 0);
    }
    if a.is_zero() {
        return (Dec::inf(true), cond::DIV_ZERO);
    }
    let mut d = Dec::finite(false, digits_of(a.adj_exp() as i32), 0);
    d.neg = a.adj_exp() < 0;
    if d.is_zero() {
        d.neg = false;
    }
    d.finish(ctx)
}

fn digits_of(v: i32) -> Vec<u8> {
    v.unsigned_abs()
        .to_string()
        .bytes()
        .map(|b| b - b'0')
        .collect()
}

/// nextplus/nextminus/nexttoward の共通「次の表現値」。
/// dir=+1 で +∞ 方向。toward では結果に応じて条件を立てる。
fn next(a: &Dec, ctx: &Ctx, dir: i32, toward: bool) -> (Dec, u32) {
    if a.is_nan() {
        let f = if a.kind == Kind::Snan {
            cond::INVALID
        } else {
            0
        };
        let mut n = a.clone();
        n.kind = Kind::Qnan;
        return (n, f);
    }
    if a.kind == Kind::Inf {
        if (dir > 0) != a.neg {
            return (Dec::inf(a.neg), 0);
        }
        // 無限大から戻る：最大有限値。
        let etop = ctx.emax - ctx.prec as i32 + 1;
        return (Dec::finite(a.neg, vec![9; ctx.prec as usize], etop), 0);
    }
    let etiny = ctx.emin - ctx.prec as i32 + 1;
    let etop = ctx.emax - ctx.prec as i32 + 1;
    // 静かな丸め（条件を立てない）で dir 方向の最近接表現値を得る。
    let sctx = Ctx {
        rm: if dir > 0 { Rm::Ceiling } else { Rm::Floor },
        ..*ctx
    };
    let (r, _) = a.clone().finish(&sctx);
    // 結果に応じた nexttoward の条件集合。
    let tflags = |d: &Dec, inf: bool| -> u32 {
        if !toward {
            return 0;
        }
        if inf {
            return cond::OVERFLOW | cond::INEXACT | cond::ROUNDED;
        }
        if d.is_zero() {
            return cond::UNDERFLOW
                | cond::SUBNORMAL
                | cond::INEXACT
                | cond::ROUNDED
                | cond::CLAMPED;
        }
        if d.kind == Kind::Finite && d.adj_exp() < i64::from(ctx.emin) {
            return cond::UNDERFLOW | cond::SUBNORMAL | cond::INEXACT | cond::ROUNDED;
        }
        0
    };
    // 表現値なら値は変わらない（数値として同じ）。
    let same = r.kind == Kind::Finite && a.kind == Kind::Finite && {
        let o = r.compare(a, ctx).0;
        o.kind == Kind::Finite && o.coef == [0]
    };
    if !same {
        let inf = r.kind == Kind::Inf;
        let f = tflags(&r, inf);
        return (r, f);
    }
    // r は表現値。ここから dir 方向に ulp 1 つ進める。
    if r.is_zero() {
        // 0 からの次は最小非零値。sign は dir で決まる。
        let d = Dec::finite(dir < 0, vec![1], etiny);
        let f = tflags(&d, false);
        return (d, f);
    }
    // 最小係数形（末尾 0 を取る）で歩幅の深さを決める。
    let (cm, em) = minimal(&r);
    let up = (dir > 0) != r.neg;
    // r の下方向では 10^k 形は 1 桁深い格子を使う（pred(1)=0.99..9）。
    let is_pow10 = cm[0] == 1 && cm[1..].iter().all(|&d| d == 0);
    let m = (i64::from(ctx.prec) - cm.len() as i64 + i64::from(!up && is_pow10))
        .min(em - i64::from(etiny))
        .max(0);
    let mut c = Dec {
        neg: r.neg,
        kind: Kind::Finite,
        coef: cm,
        exp: 0,
    };
    for _ in 0..m {
        c.coef.push(0);
    }
    c.exp = i32::try_from(em - m).unwrap_or(if em - m < 0 { i32::MIN } else { i32::MAX });
    if up {
        // 係数を 1 増やす。可変長なので桁上がりで係数が
        // precision+1 桁になったときだけ末尾 0 を落として指数を上げる。
        // 部分正規数の境界では 9E-1007 → 10E-1007 (=1.0E-1006) の
        // ように係数が伸びるのが正しい隣接値。
        let mut i = c.coef.len();
        loop {
            if i == 0 {
                c.coef.insert(0, 1);
                break;
            }
            i -= 1;
            if c.coef[i] < 9 {
                c.coef[i] += 1;
                break;
            }
            c.coef[i] = 0;
        }
        if c.coef.len() > ctx.prec as usize {
            c.coef.pop();
            c.exp += 1;
        }
        // 上端を超えたらオーバーフロー。
        if c.adj_exp() > i64::from(ctx.emax) {
            if !toward {
                return (Dec::inf(c.neg), 0);
            }
            let to_inf = match ctx.rm {
                Rm::Down | Rm::Up05 => false,
                Rm::Ceiling => !c.neg,
                Rm::Floor => c.neg,
                _ => true,
            };
            let f = cond::OVERFLOW | cond::INEXACT | cond::ROUNDED;
            if to_inf {
                return (Dec::inf(c.neg), f);
            }
            return (Dec::finite(c.neg, vec![9; ctx.prec as usize], etop), f);
        }
    } else {
        // 係数を 1 減らす。
        let mut i = c.coef.len();
        loop {
            i -= 1;
            if c.coef[i] > 0 {
                c.coef[i] -= 1;
                break;
            }
            c.coef[i] = 9;
            if i == 0 {
                break;
            }
        }
        if let Some(f0) = c.coef.iter().position(|&d| d != 0) {
            c.coef.drain(0..f0);
        } else {
            // 最小値から下へ：元の符号の 0（exp は量子に留める）。
            c.coef = vec![0];
        }
    }
    let f = tflags(&c, false);
    (c, f)
}

/// 最小係数形（末尾の 0 を取り去った係数とそれに対応する指数）。
fn minimal(d: &Dec) -> (Vec<u8>, i64) {
    let mut c = d.coef.clone();
    let mut e = i64::from(d.exp);
    while c.len() > 1 && c.last() == Some(&0) {
        c.pop();
        e += 1;
    }
    (c, e)
}

fn next_toward(a: &Dec, b: &Dec, ctx: &Ctx) -> (Dec, u32) {
    if let Some(r) = nan_prop(a, b, ctx) {
        return r;
    }
    let ord = a.compare(b, ctx).0;
    if ord.kind == Kind::Finite && ord.coef == [0] {
        // 等しければ a（符号は b 側）。条件は立たない。
        let mut d = a.clone();
        d.neg = b.neg;
        return (d, 0);
    }
    // a < b（ord = -1）なら b へ向かって + 方向。
    let dir = if ord.neg { 1 } else { -1 };
    next(a, ctx, dir, true)
}

/// 総順序比較（comparetotal/comparetotmag）。
fn compare_total(a: &Dec, b: &Dec, mag: bool, ctx: &Ctx) -> Dec {
    let one = |v: i8| Dec::finite(v < 0, vec![v.unsigned_abs()], 0);
    // 絶対順序では符号を外してから並べる。
    let mut aa = a.clone();
    let mut bb = b.clone();
    if mag {
        aa.neg = false;
        bb.neg = false;
    }
    let (a, b) = (&aa, &bb);
    // 全順序：-qNaN < -sNaN < -inf < -finite < -0 < +0 < +finite
    // < +inf < +sNaN < +qNaN。sNaN は同符号 qNaN より内側
    // （正）/外側（負の並びでは -qNaN の方が小）。NaN 同士はペイロード比較。
    fn rank(d: &Dec) -> i8 {
        match d.kind {
            Kind::Snan => {
                if d.neg {
                    -3
                } else {
                    3
                }
            }
            Kind::Qnan => {
                if d.neg {
                    -4
                } else {
                    4
                }
            }
            Kind::Inf => {
                if d.neg {
                    -2
                } else {
                    2
                }
            }
            Kind::Finite => {
                if d.neg {
                    -1
                } else {
                    1
                }
            }
        }
    }
    let (ra, rb) = (rank(a), rank(b));
    if ra != rb {
        return one(if ra < rb { -1 } else { 1 });
    }
    // 同ランク。
    if a.is_nan() {
        // ペイロードを整数として比較。負の NaN は大きい方が小。
        let ord = a
            .coef
            .len()
            .cmp(&b.coef.len())
            .then_with(|| a.coef.cmp(&b.coef));
        let ord = if a.neg { ord.reverse() } else { ord };
        return one(match ord {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        });
    }
    if a.kind == Kind::Inf {
        return one(0);
    }
    let ord = if mag {
        abs_cmp_dec(a, b, ctx)
    } else {
        a.compare(b, ctx).0
    };
    let v = if ord.kind == Kind::Finite && ord.coef == [0] {
        // 同値。符号が違えば符号で決める（-0 < +0）。同符号なら
        // コーホート順序：指数が小さい（桁が多い）方が小。負値は逆順。
        if a.neg != b.neg {
            if a.neg { -1 } else { 1 }
        } else if a.exp == b.exp {
            0
        } else {
            let base = if a.exp < b.exp { -1 } else { 1 };
            if a.neg { -base } else { base }
        }
    } else {
        ord.coef[0] as i8 * if ord.neg { -1 } else { 1 }
    };
    one(v)
}

fn abs_cmp_dec(a: &Dec, b: &Dec, ctx: &Ctx) -> Dec {
    let mut x = a.clone();
    let mut y = b.clone();
    x.neg = false;
    y.neg = false;
    x.compare(&y, ctx).0
}

fn class_of(a: &Dec, ctx: &Ctx) -> &'static str {
    match a.kind {
        Kind::Snan => "sNaN",
        Kind::Qnan => "NaN",
        Kind::Inf => {
            if a.neg {
                "-Infinity"
            } else {
                "+Infinity"
            }
        }
        Kind::Finite => {
            if a.is_zero() {
                if a.neg { "-Zero" } else { "+Zero" }
            } else {
                let sub = a.adj_exp() < i64::from(ctx.emin);
                match (a.neg, sub) {
                    (true, true) => "-Subnormal",
                    (true, false) => "-Normal",
                    (false, true) => "+Subnormal",
                    (false, false) => "+Normal",
                }
            }
        }
    }
}

/// 期待値と結果の等価性を比較する。
/// 期待が '#…' なら符号化値として、それ以外は十進文字列として比較する。
fn result_eq(got: &Dec, want: &str, c: &Case) -> bool {
    if let Some(h) = want.strip_prefix('#') {
        let Ok(bits) = u128::from_str_radix(h, 16) else {
            return false;
        };
        let Some(f) = fmt_for(&c.ctx) else {
            return false;
        };
        let w = dfp::decode(f, bits);
        return got.to_sci() == w.to_sci() || enc_eq(got, bits, f);
    }
    // "64#…" のような書式名接頭の期待値。両辺をその書式の
    // コーホートに揃えて比べる。
    if let Some((n, rest)) = want.split_once('#')
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
        && n.parse::<u32>().ok().and_then(fmt_by_name).is_some()
    {
        let f = fmt_by_name(n.parse().unwrap()).unwrap();
        let Some(w) = Dec::parse(rest) else {
            return false;
        };
        let w = fmt_apply(&w, &f);
        let g = fmt_apply(got, &f);
        return g.to_sci() == w.to_sci();
    }
    let Some(w) = Dec::parse(want) else {
        return false;
    };
    got.to_sci() == w.to_sci()
}

fn enc_eq(got: &Dec, bits: u128, f: DfpFmt) -> bool {
    dfp::encode(f, got) == bits
}

struct Stats {
    total: usize,
    ok: usize,
    bad: usize,
    skipped: usize,
    unsupported: usize,
    failures: Vec<String>,
}

fn max_fails() -> usize {
    std::env::var("DECTEST_MAX_FAILS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40)
}

fn run_file(path: &PathBuf, name: &str, st: &mut Stats) {
    let Ok(body) = std::fs::read_to_string(path) else {
        return;
    };
    let (cases, skip) = parse_file(name, &body);
    st.skipped += skip.len();
    for c in cases {
        st.total += 1;
        match run(&c) {
            Err(e) => {
                if let Some(rest) = e.strip_prefix("str:") {
                    // "str:{flags:x}:{text}": 書式化結果と条件を比較。
                    let (fs, t) = rest.split_once(':').unwrap_or(("0", rest));
                    let got_f = u32::from_str_radix(fs, 16).unwrap_or(0);
                    if t == c.want && got_f == c.want_conds {
                        st.ok += 1;
                    } else {
                        st.bad += 1;
                        if st.failures.len() < max_fails() {
                            st.failures.push(format!(
                                "{} {} {}: got str {t} (cond {got_f:b}), want {} (cond {:b})",
                                c.file, c.id, c.op, c.want, c.want_conds
                            ));
                        }
                    }
                    continue;
                }
                if let Some(got) = e.strip_prefix("class:") {
                    // class は文字列を返す特殊演算。
                    let want = c.want.clone();
                    let sub = subnormal_flag(&c);
                    let want2 = if sub {
                        want.replace("Normal", "Subnormal")
                    } else {
                        want
                    };
                    // class の期待は ±Normal/±Subnormal 等。
                    let want_fix = want2;
                    if got == want_fix {
                        st.ok += 1;
                    } else {
                        st.bad += 1;
                        if st.failures.len() < max_fails() {
                            st.failures.push(format!(
                                "{} {}: got class {got}, want {want_fix}",
                                c.file, c.id
                            ));
                        }
                    }
                } else {
                    st.unsupported += 1;
                }
            }
            Ok((got, flags)) => {
                let w = c.want.clone();
                // 期待値が "?" のものは結果不問（条件だけ見る）。
                let ok_val = w == "?" || result_eq(&got, &w, &c);
                // 条件の比較：得られたフラグと期待の集合が一致。
                // ただし DIV_UNDEFINED/DIV_IMPOSSIBLE/DIV_ZERO は
                // INVALID を伴わないのでそのまま比べる。
                let ok_cond = flags == c.want_conds;
                if ok_val && ok_cond {
                    st.ok += 1;
                } else {
                    st.bad += 1;
                    if st.failures.len() < max_fails() {
                        st.failures.push(format!(
                            "{} {} {}: got {} (cond {flags:b}), want {} (cond {:b})",
                            c.file,
                            c.id,
                            c.op,
                            got.to_sci(),
                            w,
                            c.want_conds
                        ));
                    }
                }
            }
        }
    }
}

fn subnormal_flag(c: &Case) -> bool {
    c.want_conds & cond::SUBNORMAL != 0
}

#[test]
fn dectest_conformance() {
    let root = testdata_root();
    assert!(root.exists(), ".testdata/dectest がない");
    let files = [
        // 指定の必修分野：四則・比較・符号化・変換。
        "add.decTest",
        "subtract.decTest",
        "multiply.decTest",
        "divide.decTest",
        "compare.decTest",
        "comparesig.decTest",
        "ddAdd.decTest",
        "ddSubtract.decTest",
        "ddMultiply.decTest",
        "ddDivide.decTest",
        "ddCompare.decTest",
        "ddCompareSig.decTest",
        "ddEncode.decTest",
        "decSingle.decTest",
        "decDouble.decTest",
        "decQuad.decTest",
        // 変換とその周辺。
        "base.decTest",
        "tointegral.decTest",
        "tointegralx.decTest",
        "reduce.decTest",
        "rescale.decTest",
        "quantize.decTest",
        "plus.decTest",
        "minus.decTest",
        "abs.decTest",
        "max.decTest",
        "min.decTest",
        "maxmag.decTest",
        "minmag.decTest",
        "samequantum.decTest",
        "rounding.decTest",
        "inexact.decTest",
        "clamp.decTest",
        "remainder.decTest",
        "remaindernear.decTest",
        "divideint.decTest",
        "fma.decTest",
        "squareroot.decTest",
        "nextplus.decTest",
        "nextminus.decTest",
        "nexttoward.decTest",
        "logb.decTest",
        "scaleb.decTest",
        "shift.decTest",
        "rotate.decTest",
        "and.decTest",
        "or.decTest",
        "xor.decTest",
        "invert.decTest",
        "comparetotal.decTest",
        "comparetotmag.decTest",
        "copy.decTest",
        "copyabs.decTest",
        "copynegate.decTest",
        "copysign.decTest",
        "class.decTest",
        "ddCopy.decTest",
        "ddCopyAbs.decTest",
        "ddCopyNegate.decTest",
        "ddCopySign.decTest",
        "ddAbs.decTest",
        "ddPlus.decTest",
        "ddMinus.decTest",
        "ddMax.decTest",
        "ddMin.decTest",
        "ddMaxMag.decTest",
        "ddMinMag.decTest",
        "ddSameQuantum.decTest",
        "ddQuantize.decTest",
        "ddFMA.decTest",
        "ddToIntegral.decTest",
        "ddToIntegralX.decTest",
        "ddNextPlus.decTest",
        "ddNextMinus.decTest",
        "ddNextToward.decTest",
        "ddLogB.decTest",
        "ddScaleB.decTest",
        "ddShift.decTest",
        "ddRotate.decTest",
        "ddAnd.decTest",
        "ddOr.decTest",
        "ddXor.decTest",
        "ddInvert.decTest",
        "ddCompareTotal.decTest",
        "ddCompareTotalMag.decTest",
        "ddDivideInt.decTest",
        "ddRemainder.decTest",
        "ddRemainderNear.decTest",
        "ddReduce.decTest",
        "ddSquareroot.decTest",
        "ddRescale.decTest",
        "ddCanonical.decTest",
        "ddClass.decTest",
        "ddBase.decTest",
        "dqAdd.decTest",
        "dqSubtract.decTest",
        "dqMultiply.decTest",
        "dqDivide.decTest",
        "dqCompare.decTest",
        "dqQuantize.decTest",
        "dqFMA.decTest",
        "dsAdd.decTest",
        "dsSubtract.decTest",
        "dsMultiply.decTest",
        "dsDivide.decTest",
        "dsCompare.decTest",
        "dsEncode.decTest",
        "dsBase.decTest",
        "dqEncode.decTest",
        "dqBase.decTest",
    ];
    let mut st = Stats {
        total: 0,
        ok: 0,
        bad: 0,
        skipped: 0,
        unsupported: 0,
        failures: Vec::new(),
    };
    for f in files {
        let p = root.join(f);
        if p.exists() {
            run_file(&p, f, &mut st);
        }
    }
    eprintln!(
        "decTest: {} cases, {} ok, {} bad, {} unsupported ops, {} lines skipped",
        st.total, st.ok, st.bad, st.unsupported, st.skipped
    );
    for f in &st.failures {
        eprintln!("  {f}");
    }
    assert!(st.total > 30_000, "decTest の件数が少ない: {}", st.total);
    assert_eq!(st.bad, 0, "decTest 不一致が {} 件", st.bad);
    assert_eq!(st.unsupported, 0, "未対応の演算が {} 件", st.unsupported);
}
