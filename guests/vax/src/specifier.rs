// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX のオペランド指定子の読み取りと符号化。
//!
//! 命令はオペコード（1/2 バイト、生成デコーダが `Insn` に解く）の
//! 後に、命令ごとに定まる指定子の並びが続く。指定子は 1 バイトの
//! 「モード 4 ビット + レジスタ 4 ビット」と、モードに応じた拡張
//! バイト（変位・即値・index の基底指定子）からなる。分岐変位
//! （.b アクセス）だけは指定子バイトを持たず、幅分の変位だけが
//! ストリームに置かれる。
//!
//! このモジュールは指定子の構造的な読み取り（`decode_spec`）、
//! 長さだけの軽い経路（`spec_len`）、アクセス型との適合検査
//! （`legality`）、再符号化（`encode_spec`）、命令ごとの指定子
//! シグネチャ（`insn_ops`）、命令全体のデコード（`decode_insn`）
//! を提供する。レジスタ・メモリへの実アクセス（評価・読み書き・
//! 自動増減の副作用）は意味論側（VX4 以降）の責務で、ここでは
//! デコード結果の形と消費長だけを扱う。m68k の ea.rs と同型の
//! 分割である。
//!
//! 出典は SPEC-VAX-ARM（命令形式とアドレッシングモードの章）。
//! Ref: SPEC-VAX-ARM.

use super::{Insn, reg};

/// PC（r15）のレジスタ番号。
const PC: u8 = reg::PC as u8;

/// オペランドのデータ幅（`.xy` 表記の第 2 文字）。
/// 即値の拡張バイト数、自動増減の刻み、index の乗数に使う。
// Ref: SPEC-VAX-ARM（データ型の章）.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Width {
    /// byte。
    B,
    /// word。
    W,
    /// longword。
    L,
    /// quadword。
    Q,
    /// octaword。
    O,
    /// F_floating。
    F,
    /// D_floating。
    D,
    /// G_floating。
    G,
    /// H_floating。
    H,
}

impl Width {
    /// この幅のバイト数。
    pub const fn bytes(self) -> u32 {
        match self {
            Self::B => 1,
            Self::W => 2,
            Self::L | Self::F => 4,
            Self::Q | Self::D | Self::G => 8,
            Self::O | Self::H => 16,
        }
    }
}

/// オペランドのアクセス種別（`.xy` 表記の第 1 文字）。
// Ref: SPEC-VAX-ARM（アクセス型の定義）.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Acc {
    /// 読み出しのみ。
    R,
    /// 書き込みのみ。
    W,
    /// 読み・変形・書き戻し。
    M,
    /// 実効アドレスがオペランド（レジスタ・リテラル不可）。
    A,
    /// 可変長ビットフィールドの基底（A と同じだがレジスタ可）。
    V,
    /// 分岐変位。指定子バイトを持たない。
    B,
}

/// オペランド型（アクセス + 幅）。命令の指定子シグネチャの 1 項。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpTy {
    /// アクセス種別。
    pub acc: Acc,
    /// データ幅。
    pub width: Width,
}

impl OpTy {
    const fn new(acc: Acc, width: Width) -> Self {
        Self { acc, width }
    }
}

macro_rules! opty {
    ($($name:ident = ($acc:ident, $w:ident);)*) => {
        $(#[doc = concat!(".", stringify!($acc), stringify!($w), " 型のオペランド。")]
        pub const $name: OpTy = OpTy::new(Acc::$acc, Width::$w);)*
    };
}

opty! {
    RB = (R, B); RW = (R, W); RL = (R, L); RQ = (R, Q); RO = (R, O);
    RF = (R, F); RD = (R, D); RG = (R, G); RH = (R, H);
    MB = (M, B); MW = (M, W); ML = (M, L); MQ = (M, Q); MO = (M, O);
    MF = (M, F); MD = (M, D); MG = (M, G); MH = (M, H);
    WB = (W, B); WW = (W, W); WL = (W, L); WQ = (W, Q); WO = (W, O);
    WF = (W, F); WD = (W, D); WG = (W, G); WH = (W, H);
    AB = (A, B); AW = (A, W); AL = (A, L); AQ = (A, Q); AO = (A, O);
    AF = (A, F); AD = (A, D); AG = (A, G); AH = (A, H);
    VB = (V, B);
    BB = (B, B); BW = (B, W);
}

/// 変位拡張の幅（byte/word/longword displacement）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DispW {
    /// 1 バイト変位（モード A/B）。
    B,
    /// 2 バイト変位（モード C/D）。
    W,
    /// 4 バイト変位（モード E/F）。
    L,
}

impl DispW {
    const fn bytes(self) -> u32 {
        match self {
            Self::B => 1,
            Self::W => 2,
            Self::L => 4,
        }
    }
}

/// デコードしたオペランド指定子 1 個。モード・レジスタ・拡張値を
/// 保持するので、長さ・再符号化・評価（意味論側）のどれにも使える。
/// モード 8/9 でレジスタが PC のものは別バリアント（`Imm`/`Abs`）
/// に畳む。Rn=PC の変位形は `Disp`/`DispDef` の `r` が PC のものと
/// して残す（基底は拡張直後の位置 = 呼び出し側が追跡する）。
// Ref: SPEC-VAX-ARM（アドレッシングモードの章）.
#[derive(Clone, PartialEq, Debug)]
pub enum Spec {
    /// モード 0-3: 短リテラル。値は指定子バイト全体（0-63）。
    /// 浮動型では 3+3 ビットの指数・仮数部として評価時に展開する。
    Lit(u8),
    /// モード 4: index 指定子。`rx` は指数レジスタ（PC 不可）、
    /// `base` はアドレスを返す基底指定子（再帰。リテラル・
    /// レジスタ・index・即値は基底に使えず illegal fault）。
    Indexed { rx: u8, base: Box<Spec> },
    /// モード 5: レジスタ直接（.a には使えない。.v は可）。
    Reg(u8),
    /// モード 6: (Rn)。PC は UNPREDICTABLE。
    RegDef(u8),
    /// モード 7: -(Rn)。PC は UNPREDICTABLE。
    AutoDec(u8),
    /// モード 8（Rn != PC）: (Rn)+。評価後に幅分進める。
    AutoInc(u8),
    /// モード 8 で Rn=PC: 即値。`v` はストリームの生値
    /// （幅 `w` バイトの LE）。.a/.v では値ではなく、オペランド
    /// アドレスは拡張バイトの位置そのもの。
    Imm { v: u128, w: Width },
    /// モード 9（Rn != PC）: @(Rn)+。Rn は常に 4 進む。
    AutoIncDef(u8),
    /// モード 9 で Rn=PC: 絶対。次のロングワードがオペランド
    /// アドレス。
    Abs(u32),
    /// モード A/C/E: d(Rn)。`d` は幅 `w` で符号拡張済み。
    /// `r` が PC なら PC 相対（基底は拡張直後のストリーム位置）。
    Disp { r: u8, w: DispW, d: i32 },
    /// モード B/D/F: @d(Rn)。`r` が PC なら PC 相対間接。
    DispDef { r: u8, w: DispW, d: i32 },
}

/// オペランド 1 個のデコード結果。
#[derive(Clone, PartialEq, Debug)]
pub enum Opnd {
    /// オペランド指定子（r/w/m/a/v アクセス）。
    Spec(Spec),
    /// 分岐変位（b アクセス。指定子バイトを持たず幅分の変位）。
    Br(i32),
}

/// 指定子とアクセス型の適合。decode は構造的な読み取りだけを行い、
/// 適合はこの評価で別途見る。
// Ref: SPEC-VAX-ARM（アドレッシングモードの章）.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Legality {
    /// 合法。
    Legal,
    /// 建築上は結果が UNPREDICTABLE（受理はする。意味論側で
    /// 決定的な振る舞いを選ぶ）。
    Unpredictable,
    /// アクセス型に使えないモード（illegal/reserved addressing
    /// mode fault 系）。
    Illegal,
}

/// 指定子バイトの次から `n` バイトを LE で読む（n <= 16）。
fn le(bytes: &[u8], n: u32) -> Option<u128> {
    let n = n as usize;
    if bytes.len() < n {
        return None;
    }
    let mut v = 0u128;
    for (i, &b) in bytes[..n].iter().enumerate() {
        v |= u128::from(b) << (i * 8);
    }
    Some(v)
}

/// `n` バイト値を符号拡張する（n は 1/2/4）。
fn sext(v: u128, n: u32) -> i32 {
    let sh = 128 - n * 8;
    (((v << sh) as i128) >> sh) as i32
}

/// 指定子を構造的に 1 個読み、消費バイト数とともに返す。
/// アクセス型との適合（リテラル不可、PC 制約、基底指定子の制約）は
/// 見ない —— `legality` が担う。`w` はこの指定子が属するオペランドの
/// 幅（即値の拡張バイト数と index 基底の即値長に使う）。
// Ref: SPEC-VAX-ARM（アドレッシングモードの章）.
pub fn decode_spec(bytes: &[u8], w: Width) -> Option<(Spec, u32)> {
    let &b = bytes.first()?;
    let mode = b >> 4;
    let r = b & 0xf;
    let rest = &bytes[1..];
    let (spec, ext) = match mode {
        0..=3 => (Spec::Lit(b), 0),
        4 => {
            // index の拡張部は基底指定子全体（その消費長をそのまま使う）。
            let (base, n) = decode_spec(rest, w)?;
            (
                Spec::Indexed {
                    rx: r,
                    base: Box::new(base),
                },
                n,
            )
        }
        5 => (Spec::Reg(r), 0),
        6 => (Spec::RegDef(r), 0),
        7 => (Spec::AutoDec(r), 0),
        8 if r == PC => (
            Spec::Imm {
                v: le(rest, w.bytes())?,
                w,
            },
            w.bytes(),
        ),
        8 => (Spec::AutoInc(r), 0),
        9 if r == PC => (Spec::Abs(le(rest, 4)? as u32), 4),
        9 => (Spec::AutoIncDef(r), 0),
        0xa | 0xc | 0xe => {
            let dw = match mode {
                0xa => DispW::B,
                0xc => DispW::W,
                _ => DispW::L,
            };
            (
                Spec::Disp {
                    r,
                    w: dw,
                    d: sext(le(rest, dw.bytes())?, dw.bytes()),
                },
                dw.bytes(),
            )
        }
        _ => {
            let dw = match mode {
                0xb => DispW::B,
                0xd => DispW::W,
                _ => DispW::L,
            };
            (
                Spec::DispDef {
                    r,
                    w: dw,
                    d: sext(le(rest, dw.bytes())?, dw.bytes()),
                },
                dw.bytes(),
            )
        }
    };
    Some((spec, 1 + ext))
}

/// 指定子 1 個の消費バイト数だけを返す軽い経路（指定子バイトの
/// モード表のみを見る。`decode_spec` の消費長と一致する ——
/// テストで両経路の一致を検査する）。
// Ref: SPEC-VAX-ARM（アドレッシングモードの章）.
#[must_use]
pub fn spec_len(bytes: &[u8], w: Width) -> Option<u32> {
    let &b = bytes.first()?;
    let (mode, r) = (b >> 4, b & 0xf);
    if mode == 4 {
        // index 指定子は基底指定子の長さに再帰する。
        return spec_len(&bytes[1..], w).map(|n| 1 + n);
    }
    let ext = match mode {
        0..=7 => 0,
        8 if r == PC => w.bytes(),
        8 => 0,
        9 if r == PC => 4, // 絶対（次の語がアドレス）
        9 => 0,
        0xa | 0xb => 1,
        0xc | 0xd => 2,
        _ => 4,
    };
    if bytes.len() < 1 + ext as usize {
        return None;
    }
    Some(1 + ext)
}

/// 指定子とアクセス型の適合を返す。`Indexed` は基底指定子の制約
/// （リテラル・レジスタ・index・即値の基底と、指数レジスタの PC
/// 使用は fault、基底と同じレジスタの自動増減は UNPREDICTABLE）
/// を再帰して検査する。
// Ref: SPEC-VAX-ARM（アドレッシングモードの章）.
#[must_use]
pub fn legality(spec: &Spec, acc: Acc) -> Legality {
    match spec {
        // リテラルは read のみ。address/modify/write では fault。
        Spec::Lit(_) if acc == Acc::R => Legality::Legal,
        Spec::Lit(_) => Legality::Illegal,
        Spec::Indexed { rx, base } => indexed_legality(*rx, base),
        // レジスタ直接は .a では fault。.v はフィールドの基底として可。
        Spec::Reg(_) if acc == Acc::A => Legality::Illegal,
        Spec::Reg(r) if *r == PC => Legality::Unpredictable,
        // (PC)・-(PC) は建築上 UNPREDICTABLE。
        Spec::RegDef(r) | Spec::AutoDec(r) if *r == PC => Legality::Unpredictable,
        // 即値を modify/write に書くのは UNPREDICTABLE。
        Spec::Imm { .. } if matches!(acc, Acc::M | Acc::W) => Legality::Unpredictable,
        _ => Legality::Legal,
    }
}

/// index 指定子の適合（基底指定子の制約を含む）。
fn indexed_legality(rx: u8, base: &Spec) -> Legality {
    // PC は指数レジスタに使えない（reserved addressing mode fault）。
    if rx == PC {
        return Legality::Illegal;
    }
    match base {
        // リテラル・レジスタ・index・即値を基底にするのは fault。
        Spec::Lit(_) | Spec::Reg(_) | Spec::Indexed { .. } | Spec::Imm { .. } => Legality::Illegal,
        // (PC)・-(PC) を基底に使うのは単独使用と同じく UNPREDICTABLE。
        Spec::RegDef(r) | Spec::AutoDec(r) if *r == PC => Legality::Unpredictable,
        // 基底がレジスタを更新する形で指数と同じレジスタを使うのは
        // UNPREDICTABLE。
        Spec::AutoDec(r) | Spec::AutoInc(r) | Spec::AutoIncDef(r) if *r == rx => {
            Legality::Unpredictable
        }
        _ => Legality::Legal,
    }
}

/// オペランド 1 個をストリームから読む。`.b` アクセスは指定子
/// バイトを持たず、幅分の変位を読む。
pub fn decode_op(bytes: &[u8], ty: OpTy) -> Option<(Opnd, u32)> {
    if ty.acc == Acc::B {
        let n = ty.width.bytes();
        return Some((Opnd::Br(sext(le(bytes, n)?, n)), n));
    }
    let (spec, n) = decode_spec(bytes, ty.width)?;
    Some((Opnd::Spec(spec), n))
}

/// 指定子をストリーム形に再符号化する。`w` はオペランド幅
/// （即値のバイト数の検査に使う）。変位が幅に収まらない、
/// リテラルが 63 を越える、即値が幅と不合のときは `None`。
pub fn encode_spec(spec: &Spec, w: Width, out: &mut Vec<u8>) -> Option<()> {
    match spec {
        Spec::Lit(v) => {
            if *v >= 64 {
                return None;
            }
            out.push(*v);
        }
        Spec::Indexed { rx, base } => {
            if *rx == PC {
                return None;
            }
            out.push(0x40 | rx);
            encode_spec(base, w, out)?;
        }
        Spec::Reg(r) => out.push(0x50 | r),
        Spec::RegDef(r) => out.push(0x60 | r),
        Spec::AutoDec(r) => out.push(0x70 | r),
        Spec::AutoInc(r) => out.push(0x80 | r),
        Spec::Imm { v, w: iw } => {
            if *iw != w {
                return None;
            }
            out.push(0x8f);
            out.extend_from_slice(&v.to_le_bytes()[..w.bytes() as usize]);
        }
        Spec::AutoIncDef(r) => out.push(0x90 | r),
        Spec::Abs(a) => {
            out.push(0x9f);
            out.extend_from_slice(&a.to_le_bytes());
        }
        Spec::Disp { r, w: dw, d } => {
            out.push(disp_mode(*dw, false) | r);
            push_disp(*dw, *d, out)?;
        }
        Spec::DispDef { r, w: dw, d } => {
            out.push(disp_mode(*dw, true) | r);
            push_disp(*dw, *d, out)?;
        }
    }
    Some(())
}

/// 変位形のモード上位ニブル。
const fn disp_mode(w: DispW, def: bool) -> u8 {
    match (w, def) {
        (DispW::B, false) => 0xa0,
        (DispW::B, true) => 0xb0,
        (DispW::W, false) => 0xc0,
        (DispW::W, true) => 0xd0,
        (DispW::L, false) => 0xe0,
        (DispW::L, true) => 0xf0,
    }
}

/// 変位を幅分の LE で書く。符号付きで収まらなければ `None`。
fn push_disp(w: DispW, d: i32, out: &mut Vec<u8>) -> Option<()> {
    let n = w.bytes();
    let bits = n * 8 - 1;
    let (lo, hi) = (-(1i64 << bits), (1i64 << bits) - 1);
    if i64::from(d) < lo || i64::from(d) > hi {
        return None;
    }
    out.extend_from_slice(&d.to_le_bytes()[..n as usize]);
    Some(())
}

/// オペランド 1 個を符号化する（`.b` は変位のみ）。
pub fn encode_op(ty: OpTy, op: &Opnd, out: &mut Vec<u8>) -> Option<()> {
    match op {
        Opnd::Br(d) => {
            if ty.acc != Acc::B {
                return None;
            }
            let w = match ty.width {
                Width::B => DispW::B,
                Width::W => DispW::W,
                _ => return None,
            };
            push_disp(w, *d, out)
        }
        Opnd::Spec(spec) => {
            if ty.acc == Acc::B {
                return None;
            }
            encode_spec(spec, ty.width, out)
        }
    }
}

/// 命令の指定子シグネチャ（`.xy` 型の並び。`Insn` と同じ順）。
/// 指定子を持たない命令は空列。命令を追加したらここにも足す
/// （網羅 match）。
// Ref: SPEC-VAX-ARM（各命令の形式記述）.
#[must_use]
pub fn insn_ops(insn: Insn) -> &'static [OpTy] {
    match insn {
        Insn::Movb => &[RB, WB],
        Insn::Movw => &[RW, WW],
        Insn::Movl => &[RL, WL],
        Insn::Movq => &[RQ, WQ],
        Insn::Movo => &[RO, WO],
        Insn::Movzbl => &[RB, WL],
        Insn::Movzbw => &[RB, WW],
        Insn::Movzwl => &[RW, WL],
        Insn::Mcomb => &[RB, WB],
        Insn::Mcomw => &[RW, WW],
        Insn::Mcoml => &[RL, WL],
        Insn::Clrb => &[WB],
        Insn::Clrw => &[WW],
        Insn::Clrl => &[WL],
        Insn::Clrq => &[WQ],
        Insn::Pushl => &[RL],
        Insn::Movab => &[AB, WL],
        Insn::Movaw => &[AW, WL],
        Insn::Moval => &[AL, WL],
        Insn::Movaq => &[AQ, WL],
        Insn::Movah => &[AH, WL],
        Insn::Pushab => &[AB],
        Insn::Pushaw => &[AW],
        Insn::Pushal => &[AL],
        Insn::Pushaq => &[AQ],
        Insn::Pushah => &[AH],
        Insn::Addb2 => &[RB, MB],
        Insn::Addw2 => &[RW, MW],
        Insn::Addl2 => &[RL, ML],
        Insn::Addb3 => &[RB, RB, WB],
        Insn::Addw3 => &[RW, RW, WW],
        Insn::Addl3 => &[RL, RL, WL],
        Insn::Subb2 => &[RB, MB],
        Insn::Subb3 => &[RB, RB, WB],
        Insn::Subw2 => &[RW, MW],
        Insn::Subw3 => &[RW, RW, WW],
        Insn::Subl2 => &[RL, ML],
        Insn::Subl3 => &[RL, RL, WL],
        Insn::Adwc => &[RL, ML],
        Insn::Sbwc => &[RL, ML],
        Insn::Mulb2 => &[RB, MB],
        Insn::Mulb3 => &[RB, RB, WB],
        Insn::Mulw2 => &[RW, MW],
        Insn::Mulw3 => &[RW, RW, WW],
        Insn::Mull2 => &[RL, ML],
        Insn::Mull3 => &[RL, RL, WL],
        Insn::Divb2 => &[RB, MB],
        Insn::Divb3 => &[RB, RB, WB],
        Insn::Divw2 => &[RW, MW],
        Insn::Divw3 => &[RW, RW, WW],
        Insn::Divl2 => &[RL, ML],
        Insn::Divl3 => &[RL, RL, WL],
        Insn::Emul => &[RL, RL, RL, WQ],
        Insn::Ediv => &[RL, RQ, WL, WL],
        Insn::Mnegb => &[RB, WB],
        Insn::Mnegw => &[RW, WW],
        Insn::Mnegl => &[RL, WL],
        Insn::Cvtbw => &[RB, WW],
        Insn::Cvtbl => &[RB, WL],
        Insn::Cvtwb => &[RW, WB],
        Insn::Cvtwl => &[RW, WL],
        Insn::Cvtlb => &[RL, WB],
        Insn::Cvtlw => &[RL, WW],
        Insn::Bisb2 => &[RB, MB],
        Insn::Bisw2 => &[RW, MW],
        Insn::Bisl2 => &[RL, ML],
        Insn::Bisb3 => &[RB, RB, WB],
        Insn::Bisw3 => &[RW, RW, WW],
        Insn::Bisl3 => &[RL, RL, WL],
        Insn::Bicb2 => &[RB, MB],
        Insn::Bicw2 => &[RW, MW],
        Insn::Bicl2 => &[RL, ML],
        Insn::Bicb3 => &[RB, RB, WB],
        Insn::Bicw3 => &[RW, RW, WW],
        Insn::Bicl3 => &[RL, RL, WL],
        Insn::Xorb2 => &[RB, MB],
        Insn::Xorw2 => &[RW, MW],
        Insn::Xorl2 => &[RL, ML],
        Insn::Xorb3 => &[RB, RB, WB],
        Insn::Xorw3 => &[RW, RW, WW],
        Insn::Xorl3 => &[RL, RL, WL],
        Insn::Bitb => &[RB, RB],
        Insn::Bitw => &[RW, RW],
        Insn::Bitl => &[RL, RL],
        Insn::Ashl => &[RB, RL, WL],
        Insn::Ashq => &[RB, RQ, WQ],
        Insn::Cmpb => &[RB, RB],
        Insn::Cmpw => &[RW, RW],
        Insn::Cmpl => &[RL, RL],
        Insn::Tstb => &[RB],
        Insn::Tstw => &[RW],
        Insn::Tstl => &[RL],
        Insn::Incb => &[MB],
        Insn::Incw => &[MW],
        Insn::Incl => &[ML],
        Insn::Decb => &[MB],
        Insn::Decw => &[MW],
        Insn::Decl => &[ML],
        Insn::Rotl => &[RB, RL, WL],
        Insn::Caseb => &[RB, RB, RB],
        Insn::Casew => &[RW, RW, RW],
        Insn::Casel => &[RL, RL, RL],
        Insn::Acbb => &[RB, RB, MB, BW],
        Insn::Acbw => &[RW, RW, MW, BW],
        Insn::Acbl => &[RL, RL, ML, BW],
        Insn::Aoblss => &[RL, ML, BB],
        Insn::Aobleq => &[RL, ML, BB],
        Insn::Sobgeq => &[ML, BB],
        Insn::Sobgtr => &[ML, BB],
        Insn::Brb => &[BB],
        Insn::Brw => &[BW],
        Insn::Beql | Insn::Bneq => &[BB],
        Insn::Bgtr | Insn::Bleq => &[BB],
        Insn::Bgeq | Insn::Blss => &[BB],
        Insn::Bgtru | Insn::Blequ => &[BB],
        Insn::Bvc | Insn::Bvs => &[BB],
        Insn::Bgequ | Insn::Blssu => &[BB],
        Insn::Index => &[RL, RL, RL, RL, RL, WL],
        Insn::Prober | Insn::Probew => &[RB, RW, AB],
        Insn::Bsbb => &[BB],
        Insn::Bsbw => &[BW],
        Insn::Jmp => &[AB],
        Insn::Jsb => &[AB],
        Insn::Bbs => &[RL, VB, BB],
        Insn::Bbc => &[RL, VB, BB],
        Insn::Bbss => &[RL, VB, BB],
        Insn::Bbcs => &[RL, VB, BB],
        Insn::Bbsc => &[RL, VB, BB],
        Insn::Bbcc => &[RL, VB, BB],
        Insn::Bbssi => &[RL, VB, BB],
        Insn::Bbcci => &[RL, VB, BB],
        Insn::Blbs => &[RL, BB],
        Insn::Blbc => &[RL, BB],
        Insn::Callg => &[AB, AB],
        Insn::Calls => &[RL, AB],
        Insn::Extv | Insn::Extzv | Insn::Ffs | Insn::Ffc => &[RL, RB, VB, WL],
        Insn::Insv => &[RL, RL, RB, VB],
        Insn::Cmpv | Insn::Cmpzv => &[RL, RB, VB, RL],
        Insn::Movc3 => &[RW, AB, AB],
        Insn::Movc5 => &[RW, AB, RB, RW, AB],
        Insn::Cmpc3 => &[RW, AB, AB],
        Insn::Cmpc5 => &[RB, RW, AB, RW, AB],
        Insn::Locc | Insn::Skpc => &[RB, RW, AB],
        Insn::Scanc | Insn::Spanc => &[RW, AB, AB, RB],
        Insn::Matchc => &[RW, AB, RW, AB],
        Insn::Movtc | Insn::Movtuc => &[RW, AB, RB, AB, RW, AB],
        Insn::Crc => &[AB, RL, RW, AB],
        // ---- 十進文字列（VX10）----
        Insn::Movp => &[RW, AB, AB],
        Insn::Cmpp3 => &[RW, AB, AB],
        Insn::Cmpp4 => &[RW, AB, RW, AB],
        Insn::Addp4 | Insn::Subp4 | Insn::Cvtps | Insn::Cvtsp => &[RW, AB, RW, AB],
        Insn::Addp6 | Insn::Subp6 | Insn::Mulp | Insn::Divp => &[RW, AB, RW, AB, RW, AB],
        Insn::Cvtpl => &[RW, AB, WL],
        Insn::Cvtlp => &[RL, RW, AB],
        Insn::Cvtpt | Insn::Cvttp => &[RW, AB, AB, RW, AB],
        Insn::Ashp => &[RB, RW, AB, RB, RW, AB],
        Insn::Editpc => &[RW, AB, AB, AB],
        Insn::Insque => &[AB, AB],
        Insn::Remque => &[AB, WL],
        Insn::Insqhi | Insn::Insqti => &[AB, AQ],
        Insn::Remqhi | Insn::Remqti => &[AQ, WL],
        // ---- 浮動小数点（VX9）。mulrx は EMODF/D では .rb、
        // EMODG/H では .rw（上位 11/15 ビットを使う）。
        Insn::Addf2 => &[RF, MF],
        Insn::Addf3 => &[RF, RF, WF],
        Insn::Subf2 => &[RF, MF],
        Insn::Subf3 => &[RF, RF, WF],
        Insn::Mulf2 => &[RF, MF],
        Insn::Mulf3 => &[RF, RF, WF],
        Insn::Divf2 => &[RF, MF],
        Insn::Divf3 => &[RF, RF, WF],
        Insn::Cvtfb => &[RF, WB],
        Insn::Cvtfw => &[RF, WW],
        Insn::Cvtfl | Insn::Cvtrfl => &[RF, WL],
        Insn::Cvtbf => &[RB, WF],
        Insn::Cvtwf => &[RW, WF],
        Insn::Cvtlf => &[RL, WF],
        Insn::Acbf => &[RF, RF, MF, BW],
        Insn::Movf => &[RF, WF],
        Insn::Cmpf => &[RF, RF],
        Insn::Mnegf => &[RF, WF],
        Insn::Tstf => &[RF],
        Insn::Emodf => &[RF, RB, RF, WL, WF],
        Insn::Polyf => &[RF, RW, AB],
        Insn::Cvtfd => &[RF, WD],
        Insn::Addd2 => &[RD, MD],
        Insn::Addd3 => &[RD, RD, WD],
        Insn::Subd2 => &[RD, MD],
        Insn::Subd3 => &[RD, RD, WD],
        Insn::Muld2 => &[RD, MD],
        Insn::Muld3 => &[RD, RD, WD],
        Insn::Divd2 => &[RD, MD],
        Insn::Divd3 => &[RD, RD, WD],
        Insn::Cvtdb => &[RD, WB],
        Insn::Cvtdw => &[RD, WW],
        Insn::Cvtdl | Insn::Cvtrdl => &[RD, WL],
        Insn::Cvtbd => &[RB, WD],
        Insn::Cvtwd => &[RW, WD],
        Insn::Cvtld => &[RL, WD],
        Insn::Acbd => &[RD, RD, MD, BW],
        Insn::Movd => &[RD, WD],
        Insn::Cmpd => &[RD, RD],
        Insn::Mnegd => &[RD, WD],
        Insn::Tstd => &[RD],
        Insn::Emodd => &[RD, RB, RD, WL, WD],
        Insn::Polyd => &[RD, RW, AB],
        Insn::Cvtdf => &[RD, WF],
        Insn::Addg2 => &[RG, MG],
        Insn::Addg3 => &[RG, RG, WG],
        Insn::Subg2 => &[RG, MG],
        Insn::Subg3 => &[RG, RG, WG],
        Insn::Mulg2 => &[RG, MG],
        Insn::Mulg3 => &[RG, RG, WG],
        Insn::Divg2 => &[RG, MG],
        Insn::Divg3 => &[RG, RG, WG],
        Insn::Cvtgb => &[RG, WB],
        Insn::Cvtgw => &[RG, WW],
        Insn::Cvtgl | Insn::Cvtrgl => &[RG, WL],
        Insn::Cvtbg => &[RB, WG],
        Insn::Cvtwg => &[RW, WG],
        Insn::Cvtlg => &[RL, WG],
        Insn::Acbg => &[RG, RG, MG, BW],
        Insn::Movg => &[RG, WG],
        Insn::Cmpg => &[RG, RG],
        Insn::Mnegg => &[RG, WG],
        Insn::Tstg => &[RG],
        Insn::Emodg => &[RG, RW, RG, WL, WG],
        Insn::Polyg => &[RG, RW, AB],
        Insn::Cvtgf => &[RG, WF],
        Insn::Cvtfg => &[RF, WG],
        Insn::Addh2 => &[RH, MH],
        Insn::Addh3 => &[RH, RH, WH],
        Insn::Subh2 => &[RH, MH],
        Insn::Subh3 => &[RH, RH, WH],
        Insn::Mulh2 => &[RH, MH],
        Insn::Mulh3 => &[RH, RH, WH],
        Insn::Divh2 => &[RH, MH],
        Insn::Divh3 => &[RH, RH, WH],
        Insn::Cvthb => &[RH, WB],
        Insn::Cvthw => &[RH, WW],
        Insn::Cvthl | Insn::Cvtrhl => &[RH, WL],
        Insn::Cvtbh => &[RB, WH],
        Insn::Cvtwh => &[RW, WH],
        Insn::Cvtlh => &[RL, WH],
        Insn::Acbh => &[RH, RH, MH, BW],
        Insn::Movh => &[RH, WH],
        Insn::Cmph => &[RH, RH],
        Insn::Mnegh => &[RH, WH],
        Insn::Tsth => &[RH],
        Insn::Emodh => &[RH, RW, RH, WL, WH],
        Insn::Polyh => &[RH, RW, AB],
        Insn::Cvtgh => &[RG, WH],
        Insn::Cvthg => &[RH, WG],
        Insn::Cvtfh => &[RF, WH],
        Insn::Cvtdh => &[RD, WH],
        Insn::Cvthf => &[RH, WF],
        Insn::Cvthd => &[RH, WD],
        Insn::Clro => &[WO],
        Insn::Pushr | Insn::Popr => &[RW],
        Insn::Chmk | Insn::Chme | Insn::Chms | Insn::Chmu => &[RW],
        Insn::Halt
        | Insn::Nop
        | Insn::Rei
        | Insn::Bpt
        | Insn::Ret
        | Insn::Rsb
        | Insn::Ldpctx
        | Insn::Svpctx
        | Insn::Bugw
        | Insn::Bugl => &[],
    }
}

/// 命令 1 個分のデコード結果（オペコード + 指定子列）。
#[derive(Clone, Debug)]
pub struct Fetched {
    /// オペコードが解けた命令。
    pub insn: Insn,
    /// 指定子のデコード結果（`insn_ops` と同じ並び）。
    pub ops: Vec<Opnd>,
    /// 命令全体のバイト長（オペコード + 各指定子の消費長）。
    pub len: u32,
}

/// オペコード語（1/2 バイト）をストリーム先頭から読む。
/// (語, バイト長) を返す。
fn opcode_word(bytes: &[u8]) -> Option<(u128, u32)> {
    let b0 = *bytes.first()?;
    if matches!(b0, 0xfd..=0xff) {
        let b1 = *bytes.get(1)?;
        Some((u128::from(b0) | u128::from(b1) << 8, 2))
    } else {
        Some((u128::from(b0), 1))
    }
}

/// 命令ストリームからオペコードと指定子列を読む。
/// `feats` は生成デコーダの機能ビット（`model_feats`）。
pub fn decode_insn_ex(bytes: &[u8], feats: u128) -> Option<Fetched> {
    let (word, oplen) = opcode_word(bytes)?;
    let insn = super::decode_model_ex(word, oplen * 8, false, feats)?;
    let mut ops = Vec::with_capacity(insn_ops(insn).len());
    let mut len = oplen;
    for &ty in insn_ops(insn) {
        let (op, n) = decode_op(&bytes[len as usize..], ty)?;
        ops.push(op);
        len += n;
    }
    Some(Fetched { insn, ops, len })
}

/// `decode_insn_ex` の全機能版。
pub fn decode_insn(bytes: &[u8]) -> Option<Fetched> {
    decode_insn_ex(bytes, super::DEFAULT_FEATS)
}

/// 命令全体のバイト長だけを返す軽い経路（オペコード + `spec_len`
/// の和。`decode_insn` の `len` と一致することをテストで検査する）。
#[must_use]
pub fn insn_len(bytes: &[u8]) -> Option<u32> {
    insn_len_ex(bytes, super::DEFAULT_FEATS)
}

/// `insn_len` の機能指定版。
#[must_use]
pub fn insn_len_ex(bytes: &[u8], feats: u128) -> Option<u32> {
    let (word, oplen) = opcode_word(bytes)?;
    let insn = super::decode_model_ex(word, oplen * 8, false, feats)?;
    let mut len = oplen;
    for &ty in insn_ops(insn) {
        let n = if ty.acc == Acc::B {
            ty.width.bytes()
        } else {
            spec_len(&bytes[len as usize..], ty.width)?
        };
        len += n;
    }
    Some(len)
}
