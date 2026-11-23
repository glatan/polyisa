// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 のオペランド指定子の読み取りと符号化。
//!
//! 命令語は 16 ビット固定長で、指定子は語内の (mode 3 + reg 3)
//! フィールド —— VAX のような指定子ストリームはない。先頭語は
//! 生成デコーダが `Insn` に解き、ここでは語内の指定子フィールドを
//! オペランドに解釈する。モード 6/7 のインデックス語と、PC
//! （r7）指定子が実質的に消費する即値・絶対語は命令語に続く拡張
//! 語（16 ビット）で、指定子ごとに最大 1 語。命令長は
//! 2 + 拡張語数×2 バイトとなる。
//!
//! このモジュールは指定子の構造的な読み取り（`decode_spec`）、
//! 消費語数だけの軽い経路（`spec_words`・`insn_len`）、アクセス型と
//! の適合検査（`legality`）、再符号化（`encode_spec`・`encode_insn`）、
//! 命令ごとの指定子シグネチャ（`insn_ops`）、命令全体のデコード
//! （`decode_insn`）、レジスタの具体的な値による EA 評価（`eval`）、
//! long/F/D の「3412」語順写像（`word_order`）を提供する。m68k の
//! ea.rs・VAX の specifier.rs と同型の分割で、意味論（条件コード・
//! 実行）は PD5 以降の責務。
//!
//! 出典は SPEC-PDP11-ARCH83（第3章 データ表現・第4章 アドレッシング）。
//! Ref: SPEC-PDP11-ARCH83.

use super::{Insn, reg};

/// PC（r7）のレジスタ番号。
const PC: u8 = reg::PC as u8;

/// SP（r6）のレジスタ番号。
const SP: u8 = reg::SP as u8;

/// オペランドのデータ幅。オート増減の刻みと語順写像に使う。
/// L（32 ビット整数）と F/D は FP11・EIS・CIS のオペランド向けの器。
// Ref: SPEC-PDP11-ARCH83（第3章）.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Width {
    /// byte。
    B,
    /// word。
    W,
    /// longword（32 ビット整数）。
    L,
    /// F_floating（32 ビット）。
    F,
    /// D_floating（64 ビット）。
    D,
}

impl Width {
    /// この幅のバイト数。
    pub const fn bytes(self) -> u32 {
        match self {
            Self::B => 1,
            Self::W => 2,
            Self::L | Self::F => 4,
            Self::D => 8,
        }
    }
}

/// オペランドのアクセス種別。
// Ref: SPEC-PDP11-ARCH83（第5章 各命令の形式記述）.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Acc {
    /// 読み出しのみ（ソース・比較の両辺）。
    R,
    /// 書き込みのみ（clr 系・mov の宛先）。
    W,
    /// 読み・変形・書き戻し（add の宛先・単一オペランド算術）。
    M,
    /// 実効アドレスがオペランド（jmp・jsr。モード 0 は
    /// 違法で `jmp_reg_trap` パラメータのベクタに落ちる）。
    A,
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
        $(#[doc = concat!(stringify!($acc), stringify!($w), " 型のオペランド。")]
        pub const $name: OpTy = OpTy::new(Acc::$acc, Width::$w);)*
    };
}

opty! {
    RB = (R, B); RW = (R, W);
    MB = (M, B); MW = (M, W);
    WB = (W, B); WW = (W, W);
    AW = (A, W);
    // FP11 オペランドの印。実際の幅（F/D/I/L）は FPS の FD/FL が
    // 実行時に決めるので、ここの width はプレースホルダ。
    RF = (R, F); MF = (M, F); WF = (W, F);
}

/// デコードしたオペランド指定子 1 個。モード・レジスタ・拡張語を
/// 保持するので、長さ・再符号化・評価のどれにも使える。
/// PC の特殊用途（モード 2=即値・モード 3=絶対）は別バリアントに
/// 畳む。モード 6/7 で r=PC のものは相対・相対間接で、`Index`/
/// `IndexDef` の `r` が PC のものとして残す（基準は拡張語の次の
/// 語のアドレス —— `eval` が追跡する）。
// Ref: SPEC-PDP11-ARCH83（第4章）.
#[derive(Clone, PartialEq, Debug)]
pub enum Spec {
    /// モード 0: レジスタ直接（Rn）。
    Reg(u8),
    /// モード 1: レジスタ間接（(Rn)）。
    RegDef(u8),
    /// モード 2（Rn != PC）: 自動増（(Rn)+）。
    AutoInc(u8),
    /// モード 2 で Rn=PC: 即値（#imm）。`v` は拡張語そのもの
    /// （byte オペランドは下位バイトを使う）。
    Imm(u16),
    /// モード 3（Rn != PC）: 自動増間接（@(Rn)+）。
    AutoIncDef(u8),
    /// モード 3 で Rn=PC: 絶対（@#a）。拡張語がオペランドアドレス。
    Abs(u16),
    /// モード 4: 自動減（-(Rn)）。
    AutoDec(u8),
    /// モード 5: 自動減間接（@-(Rn)）。
    AutoDecDef(u8),
    /// モード 6: インデックス（x(Rn)）。`x` は拡張語。
    /// r=PC は相対（基準は拡張語の次の語）。
    Index { r: u8, x: u16 },
    /// モード 7: インデックス間接（@x(Rn)）。r=PC は相対間接。
    IndexDef { r: u8, x: u16 },
}

/// 指定子とアクセス型の適合。decode は構造的な読み取りだけを行い、
/// 適合はこの評価で別途見る。
// Ref: SPEC-PDP11-ARCH83（第4章・第5章）.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Legality {
    /// 合法。
    Legal,
    /// ハードウェアは受理するが結果は定義されない
    /// （即値への書き込み・-(PC) 系。意味論側で決定的な振る舞いを
    /// 選ぶ）。
    Unpredictable,
    /// アクセス型に使えないモード（A アクセスのモード 0 —
    /// `jmp_reg_trap` パラメータのベクタにトラップ）。
    Illegal,
}

/// 指定子が消費する拡張語数（0 または 1）。モード 6/7 の
/// インデックス語と、PC 指定子（モード 2/3）の即値・絶対語が
/// 1 語を消費する —— PC 特殊用途の消費は Rn=PC のときだけ。
/// 長さだけの軽い経路（`decode_spec` の消費数と一致する）。
// Ref: SPEC-PDP11-ARCH83（第4章）.
#[must_use]
pub const fn spec_words(mode: u8, r: u8) -> u32 {
    match mode {
        6 | 7 => 1,
        2 | 3 if r == PC => 1,
        _ => 0,
    }
}

/// (mode, reg) 対とそれに続く拡張語列から指定子を構造的に
/// 1 個読み、消費した拡張語数とともに返す。アクセス型との適合は
/// 見ない —— `legality` が担う。
// Ref: SPEC-PDP11-ARCH83（第4章）.
pub fn decode_spec(mode: u8, r: u8, ext: &[u16]) -> Option<(Spec, u32)> {
    let w = || ext.first().copied();
    let (spec, n) = match mode {
        0 => (Spec::Reg(r), 0),
        1 => (Spec::RegDef(r), 0),
        2 if r == PC => (Spec::Imm(w()?), 1),
        2 => (Spec::AutoInc(r), 0),
        3 if r == PC => (Spec::Abs(w()?), 1),
        3 => (Spec::AutoIncDef(r), 0),
        4 => (Spec::AutoDec(r), 0),
        5 => (Spec::AutoDecDef(r), 0),
        6 => (Spec::Index { r, x: w()? }, 1),
        7 => (Spec::IndexDef { r, x: w()? }, 1),
        _ => return None,
    };
    Some((spec, n))
}

/// 指定子を (mode, reg) の語内フィールドと拡張語に再符号化する。
/// `decode_spec` の逆。構築不能な指定子（不正な組合せ）はない —
/// `Reg`/`RegDef`/… は常に対応するモードへ写る。
// Ref: SPEC-PDP11-ARCH83（第4章）.
pub fn encode_spec(spec: &Spec) -> (u8, u8, Option<u16>) {
    match *spec {
        Spec::Reg(r) => (0, r, None),
        Spec::RegDef(r) => (1, r, None),
        Spec::AutoInc(r) => (2, r, None),
        Spec::Imm(v) => (2, PC, Some(v)),
        Spec::AutoIncDef(r) => (3, r, None),
        Spec::Abs(a) => (3, PC, Some(a)),
        Spec::AutoDec(r) => (4, r, None),
        Spec::AutoDecDef(r) => (5, r, None),
        Spec::Index { r, x } => (6, r, Some(x)),
        Spec::IndexDef { r, x } => (7, r, Some(x)),
    }
}

/// 指定子とアクセス型の適合を返す。
// Ref: SPEC-PDP11-ARCH83（第4章・第5章）.
#[must_use]
pub fn legality(spec: &Spec, acc: Acc) -> Legality {
    match spec {
        // jmp/jsr の宛先にモード 0 は使えない
        // （`jmp_reg_trap` パラメータのベクタにトラップ）。
        Spec::Reg(_) if acc == Acc::A => Legality::Illegal,
        // -(PC)・@-(PC) は結果が定義されない。
        Spec::AutoDec(r) | Spec::AutoDecDef(r) if *r == PC => Legality::Unpredictable,
        // 即値・（実質）命令ストリームへの書き込みは定義されない。
        Spec::Imm(_) if matches!(acc, Acc::W | Acc::M) => Legality::Unpredictable,
        _ => Legality::Legal,
    }
}

/// 命令の指定子シグネチャ（`Insn` と同じ順。指定子フィールドを
/// 持つオペランドだけを列挙し、JSR/EIS の `reg`・SOB/分岐の変位の
/// ような語内の他フィールドは含まない —— それらは生成 `ops_*` が
/// 取り出す）。指定子を持たない命令は空列。命令を追加したら
/// ここにも足す（網羅 match）。
// Ref: SPEC-PDP11-ARCH83（第5章 各命令の形式記述）.
#[must_use]
pub fn insn_ops(insn: Insn) -> &'static [OpTy] {
    match insn {
        Insn::Mov => &[RW, WW],
        Insn::Movb => &[RB, WB],
        Insn::Cmp | Insn::Bit => &[RW, RW],
        Insn::Cmpb | Insn::Bitb => &[RB, RB],
        Insn::Bic | Insn::Bis | Insn::Add | Insn::Sub => &[RW, MW],
        Insn::Bicb | Insn::Bisb => &[RB, MB],
        Insn::Jmp => &[AW],
        // csm は引数語を読むオペランド（モード 0 も合法で、その
        // レジスタ値が積まれる —— KDJ11-E UG の CSM 記述）。
        Insn::Csm => &[RW],
        Insn::Swab
        | Insn::Com
        | Insn::Inc
        | Insn::Dec
        | Insn::Neg
        | Insn::Adc
        | Insn::Sbc
        | Insn::Ror
        | Insn::Rol
        | Insn::Asr
        | Insn::Asl
        | Insn::Xor
        | Insn::Tstset
        | Insn::Wrtlck => &[MW],
        Insn::Clr | Insn::Mtpi | Insn::Sxt | Insn::Mtpd => &[WW],
        Insn::Tst | Insn::Mfpi | Insn::Mfpd | Insn::Mul | Insn::Div | Insn::Ash | Insn::Ashc => {
            &[RW]
        }
        Insn::Comb
        | Insn::Incb
        | Insn::Decb
        | Insn::Negb
        | Insn::Adcb
        | Insn::Sbcb
        | Insn::Rorb
        | Insn::Rolb
        | Insn::Asrb
        | Insn::Aslb => &[MB],
        Insn::Clrb | Insn::Mfps => &[WB],
        Insn::Tstb | Insn::Mtps => &[RB],
        Insn::Jsr => &[AW],
        // FP11（ARCH83 6章）。オペランドの型（F/D/I/L）は FPS の
        // FD/FL が実行時に決めるので、幅の解決は sem の FP 系
        // オペランド評価が担う。
        Insn::Ldfps => &[RW],
        Insn::Stfps | Insn::Stst => &[WW],
        Insn::Clrf => &[WF],
        Insn::Tstf => &[RF],
        Insn::Absf | Insn::Negf => &[MF],
        Insn::Mulf
        | Insn::Modf
        | Insn::Addf
        | Insn::Ldf
        | Insn::Subf
        | Insn::Cmpf
        | Insn::Divf
        | Insn::Ldcff
        | Insn::Ldexp
        | Insn::Ldcif => &[RF],
        Insn::Stf | Insn::Stcfd | Insn::Stexp | Insn::Stcfi => &[WF],
        // 指定子を持たない命令: RTS/FIS/分岐/トラップ/MARK/SPL/固定語。
        // CIS も語内の (mode,reg) 指定子を持たない —— レジスタ形は
        // R0-R5 の固定枠、in-line 形は命令ストリームの記述子語を
        // `cis_words` と `sem` の CIS 評価器が読む。
        Insn::L2d
        | Insn::L3d
        | Insn::Movc
        | Insn::Movrc
        | Insn::Movtc
        | Insn::Locc
        | Insn::Skpc
        | Insn::Scanc
        | Insn::Spanc
        | Insn::Cmpc
        | Insn::Matc
        | Insn::Addn
        | Insn::Subn
        | Insn::Cmpn
        | Insn::Cvtnl
        | Insn::Cvtpn
        | Insn::Cvtnp
        | Insn::Ashn
        | Insn::Cvtln
        | Insn::Addp
        | Insn::Subp
        | Insn::Cmpp
        | Insn::Cvtpl
        | Insn::Mulp
        | Insn::Divp
        | Insn::Ashp
        | Insn::Cvtlp
        | Insn::Movci
        | Insn::Movrci
        | Insn::Movtci
        | Insn::Locci
        | Insn::Skpci
        | Insn::Scanci
        | Insn::Spanci
        | Insn::Cmpci
        | Insn::Matci
        | Insn::Addni
        | Insn::Subni
        | Insn::Cmpni
        | Insn::Cvtnli
        | Insn::Cvtpni
        | Insn::Cvtnpi
        | Insn::Ashni
        | Insn::Cvtlni
        | Insn::Addpi
        | Insn::Subpi
        | Insn::Cmppi
        | Insn::Cvtpli
        | Insn::Mulpi
        | Insn::Divpi
        | Insn::Ashpi
        | Insn::Cvtlpi
        | Insn::Rts
        | Insn::Sob
        | Insn::Fadd
        | Insn::Fsub
        | Insn::Fmul
        | Insn::Fdiv
        | Insn::Br
        | Insn::Bne
        | Insn::Beq
        | Insn::Bge
        | Insn::Blt
        | Insn::Bgt
        | Insn::Ble
        | Insn::Bpl
        | Insn::Bmi
        | Insn::Bhi
        | Insn::Blos
        | Insn::Bvc
        | Insn::Bvs
        | Insn::Bcc
        | Insn::Bcs
        | Insn::Emt
        | Insn::Trap
        | Insn::Mark
        | Insn::Spl
        | Insn::Halt
        | Insn::Wait
        | Insn::Rti
        | Insn::Bpt
        | Insn::Iot
        | Insn::Reset
        | Insn::Rtt
        | Insn::Mfpt
        | Insn::Nop
        | Insn::Cfcc
        | Insn::Setf
        | Insn::Setd
        | Insn::Seti
        | Insn::Setl
        | Insn::Ccc
        | Insn::Scc => &[],
    }
}

/// オペランド番号 `i` の指定子フィールドが命令語のどの 6 ビットに
/// 入るかのシフト量（フィールドの下位が reg、上位 3 ビットが mode）。
/// 指定子が 2 個の命令（FD 形式）の第 1 オペランドだけソース
/// スロット（bits<11:6>）で、それ以外はすべて宛先スロット
/// （bits<5:0>）。`n` は `insn_ops` の長さ。
fn spec_shift(n: usize, i: usize) -> u32 {
    if n == 2 && i == 0 { 6 } else { 0 }
}

/// 命令語 `w` のオペランド番号 `i` の指定子フィールド (mode, reg)。
fn spec_field(n: usize, i: usize, w: u16) -> (u8, u8) {
    let f = (w >> spec_shift(n, i)) & 0o77;
    ((f >> 3) as u8, (f & 7) as u8)
}

/// 命令 1 個分のデコード結果（命令語 + 指定子列）。
#[derive(Clone, Debug)]
pub struct Fetched {
    /// 命令語が解けた命令。
    pub insn: Insn,
    /// 命令語そのもの（指定子以外のフィールド —— JSR/EIS の reg・
    /// 分岐変位 —— は生成 `ops_*` でここから取り出す）。
    pub word: u16,
    /// 指定子のデコード結果（`insn_ops` と同じ並び）。
    pub ops: Vec<Spec>,
    /// 命令全体のバイト長（命令語 + 各指定子の拡張語）。
    pub len: u32,
}

/// 命令語列から命令と指定子列を読む。`words[0]` が命令語で、
/// 以降は指定子の消費する拡張語が続く。`feats` は生成デコーダの
/// 機能ビット（`model_feats`）。
pub fn decode_insn_ex(words: &[u16], feats: u128) -> Option<Fetched> {
    let &w = words.first()?;
    let insn = super::decode_model_ex(u128::from(w), 16, false, feats)?;
    let tys = insn_ops(insn);
    let mut ops = Vec::with_capacity(tys.len());
    let mut words_used = 1usize;
    for (i, &ty) in tys.iter().enumerate() {
        let _ = ty; // 消費語数は幅に依らない。適合は呼び出し側が `legality` で見る。
        let (m, r) = spec_field(tys.len(), i, w);
        let (s, n) = decode_spec(m, r, &words[words_used..])?;
        ops.push(s);
        words_used += n as usize;
    }
    // 全長は `insn_words` に任せる —— CIS の in-line 形と L2D7/
    // L3D7 は語内フィールドで定まる記述子語を命令語の後ろに消費
    // し、指定子列の消費語数（words_used）とは別系統。
    Some(Fetched {
        insn,
        word: w,
        ops,
        len: insn_words(insn, w).unwrap_or(2 * words_used as u32),
    })
}

/// `decode_insn_ex` の全機能版。
pub fn decode_insn(words: &[u16]) -> Option<Fetched> {
    decode_insn_ex(words, super::DEFAULT_FEATS)
}

/// 命令全体のバイト長だけを返す軽い経路（語内フィールドだけを見る。
/// `decode_insn` の `len` と一致することをテストで検査する）。
#[must_use]
pub fn insn_len(words: &[u16]) -> Option<u32> {
    insn_len_ex(words, super::DEFAULT_FEATS)
}

/// `insn_len` の機能指定版。
#[must_use]
pub fn insn_len_ex(words: &[u16], feats: u128) -> Option<u32> {
    let &w = words.first()?;
    let insn = super::decode_model_ex(u128::from(w), 16, false, feats)?;
    insn_words(insn, w)
}

/// CIS in-line 形の命令が命令語に続けて消費する記述子語の数
/// （KE44-A —— in-line 形のオペランドは命令ストリームの
/// ポインタ/値語）。in-line 形以外は 0。
// Ref: SPEC-PDP11-CIS（各命令の in-line 形式）.
#[must_use]
pub fn cis_ext_words(insn: Insn) -> u32 {
    match insn {
        // src.dscr.ptr + dst.dscr.ptr + fill 語。MOVTCI は
        // さらに table.adr 語が続く。
        Insn::Movci | Insn::Movrci | Insn::Cmpci => 3,
        Insn::Movtci => 4,
        // src.dscr.ptr + char 語、または src.dscr.ptr + set.dscr.ptr、
        // src.dscr.ptr + obj.dscr.ptr。
        Insn::Locci | Insn::Skpci | Insn::Scanci | Insn::Spanci | Insn::Matci => 2,
        // 3 記述子形: src1.dscr.ptr + src2.dscr.ptr + dst.dscr.ptr。
        Insn::Addni | Insn::Subni | Insn::Addpi | Insn::Subpi | Insn::Mulpi | Insn::Divpi => 3,
        // 2 項形: src.dscr.ptr + dst.dscr.ptr（CVTNLI/CVTPLI は
        // src.dscr.ptr + dst.long.ptr、CVTLNI/CVTLPI は
        // dst.dscr.ptr + src.long.ptr）。
        Insn::Cmpni
        | Insn::Cvtnli
        | Insn::Cvtpni
        | Insn::Cvtnpi
        | Insn::Cvtlni
        | Insn::Cmppi
        | Insn::Cvtpli
        | Insn::Cvtlpi => 2,
        // src.dscr.ptr + dst.dscr.ptr + shift.dscr 語。
        Insn::Ashni | Insn::Ashpi => 3,
        _ => 0,
    }
}

/// デコード済み命令の語内フィールドから全長（バイト）を求める。
/// CIS の in-line 形は語内フィールドで定まる固定数の記述子語を
/// 消費し、L2Dr/L3Dr は r=PC のときポインタ語を命令ストリーム
/// から消費する（@(PC)+ の規則）。
#[must_use]
pub fn insn_words(insn: Insn, w: u16) -> Option<u32> {
    // CIS: in-line 形の記述子語、または L2Dr/L3Dr の r=PC。
    let cis = cis_ext_words(insn);
    if cis != 0 {
        return Some(2 * (1 + cis));
    }
    if matches!(insn, Insn::L2d | Insn::L3d) {
        let r = w & 7;
        if r == 7 {
            return Some(if insn == Insn::L2d { 6 } else { 8 });
        }
        return Some(2);
    }
    let tys = insn_ops(insn);
    let mut n = 1u32;
    for i in 0..tys.len() {
        let (m, r) = spec_field(tys.len(), i, w);
        n += spec_words(m, r);
    }
    Some(2 * n)
}

/// 指定子列を命令語のフィールドと拡張語列に符号化する。
/// `base` は生成 `encode_*` が返す語（オペコード部のみ・
/// 指定子フィールドは 0）。戻り値は（命令語, 拡張語列）で、
/// `decode_insn` の逆。`specs` の個数が `insn_ops` と合わない
/// 命令では使えない（呼び出し側の責任）。
pub fn encode_insn(base: u16, specs: &[Spec]) -> (u16, Vec<u16>) {
    let mut w = base;
    let mut ext = Vec::new();
    for (i, s) in specs.iter().enumerate() {
        let (m, r, x) = encode_spec(s);
        let sh = spec_shift(specs.len(), i);
        w |= (u16::from(m) << 3 | u16::from(r)) << sh;
        if let Some(x) = x {
            ext.push(x);
        }
    }
    (w, ext)
}

/// オート増減（モード 2/4 の直接形）の刻み（バイト）。
/// オペランド幅に従うが、byte オペランドでも SP/PC は常に ±2
/// （ワード整列を保つ規則）。間接形（モード 3/5）は指し先が
/// 語なので常に ±2 —— `eval` が使い分ける。
// Ref: SPEC-PDP11-ARCH83（第4章）.
#[must_use]
pub const fn step(w: Width, r: u8) -> u16 {
    let n = w.bytes() as u16;
    if n == 1 && (r == SP || r == PC) { 2 } else { n }
}

/// 指定子の具体的な評価結果。レジスタ直接は番号、メモリは
/// 実効アドレス（間接形では指し先語のアドレス）を持つ。
pub enum Ea {
    /// モード 0: レジスタ直接。
    Reg(u8),
    /// メモリ実効アドレス（バイトアドレス）。
    Addr(u16),
    /// 即値（モード 2 の PC 形のみ）。
    Imm(u16),
}

/// 指定子をレジスタの具体的な値で評価し、EA とオート増減の
/// 書き戻し (reg, 新値) を返す。
///
/// `w` はオペランド幅（オート増減の刻みに使う）。`ext_addr` は
/// この指定子の拡張語のアドレスで、拡張語を持たない指定子では
/// 未使用。`Index`/`IndexDef` で r=PC（相対・相対間接）の基準は
/// `ext_addr + 2` —— 拡張語を読み終えた時点の PC。
// Ref: SPEC-PDP11-ARCH83（第4章）.
pub fn eval(spec: &Spec, w: Width, ext_addr: u16, r: &[u16; 8]) -> (Ea, Option<(u8, u16)>) {
    match *spec {
        Spec::Reg(n) => (Ea::Reg(n), None),
        Spec::RegDef(n) => (Ea::Addr(r[n as usize]), None),
        // (Rn)+: 読み出し後に刻み分進める。指し先語は常に +2。
        Spec::AutoInc(n) => {
            let a = r[n as usize];
            (Ea::Addr(a), Some((n, a.wrapping_add(step(w, n)))))
        }
        Spec::AutoIncDef(n) => {
            let a = r[n as usize];
            (Ea::Addr(a), Some((n, a.wrapping_add(2))))
        }
        // -(Rn): 刻み分下げてから読み出す。指し先語は常に -2。
        Spec::AutoDec(n) => {
            let a = r[n as usize].wrapping_sub(step(w, n));
            (Ea::Addr(a), Some((n, a)))
        }
        Spec::AutoDecDef(n) => {
            let a = r[n as usize].wrapping_sub(2);
            (Ea::Addr(a), Some((n, a)))
        }
        // x(Rn): 変位を加える。r=PC の基準は拡張語の次の語。
        Spec::Index { r: n, x } | Spec::IndexDef { r: n, x } => {
            let base = if n == PC {
                ext_addr.wrapping_add(2)
            } else {
                r[n as usize]
            };
            (Ea::Addr(base.wrapping_add(x)), None)
        }
        Spec::Imm(v) => (Ea::Imm(v), None),
        Spec::Abs(a) => (Ea::Addr(a), None),
    }
}

/// 「3412」語順の並べ替え（自己逆）。L（32 ビット整数）と F/D
/// 浮動は、上位語（long の上位・浮動の符号と指数を含む語）が
/// 最下位アドレスに来る。連続する 16 ビット語を正準形の
/// 32/64 ビット値（上位が最上位ビット。decfp の `bits()` の形）
/// として読み書きするときに掛ける写像で、整数の mov 系のように
/// 語単位のまま扱う経路では使わない（VAX の `fp_order` と同じ
/// 責務分界）。
// Ref: SPEC-PDP11-ARCH83（第3章 データ表現）.
#[must_use]
pub fn word_order(w: Width, v: u64) -> u64 {
    if !matches!(w, Width::L | Width::F | Width::D) {
        return v;
    }
    let n = w.bytes() / 2;
    let mut out = 0u64;
    for i in 0..n {
        out |= (v >> (16 * i) & 0xffff) << (16 * (n - 1 - i));
    }
    out
}
