// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX-11/780 のマイクロコード実行時間モデル（専用タイミング）。
//!
//! VAX の命令時間はマイクロコードの実行時間として決まり、
//! 「命令本体の時間 + 各オペランド指定子の評価・データアクセス
//! 時間」の構造で見積もる（m68k の ea 計時と同型の分割）。時間の
//! 単位は EBOX マイクロサイクル（200 ns）。
//!
//! 値の拠り所は次のとおり:
//! - 登録正本（SPEC-VAX-ARM・SPEC-VAX-MICROVAX）に命令時間の表は
//!   ない（段階23 計画 VX1 の不確実項目 5 → VX12 で確定）。
//! - MEAS-VAX-USENET（VAX-11/780・FPA なしの命令別時間 μs 表。
//!   元 DEC 従業員経由で精度未保証と投稿者が明記）の値を
//!   MEAS-VAX-EMERCLARK の EBOX マイクロサイクル（200 ns）へ
//!   換算したものを、整数・浮動小数点・手続呼出・キュー・
//!   パック十進・文字列の代表命令のアンカーとして採る
//!   （例: addl2 reg,reg=2、mull2=32、divl3=48、
//!   calls #0+ret=74、crc 16B=240、movc5 512B=557）。
//! - 指定子の評価・アクセスコストはその実測値の差分から当てはめた
//!   近似で、表にない命令はクラス既定値。較正用の実機計測は
//!   行っていないので忠実度は未較正の approx とする。
//!
//! 対象モデルは `vax11_780`（FPA なし。G/H 形式の命令も
//! 表にある値をそのまま採る）。MicroVAX 系・NVAX の時間は
//! 持たない。範囲の記録は GAP-0080。
//! Ref: SPEC-VAX-ARM, SPEC-VAX-MICROVAX, MEAS-VAX-USENET,
//! MEAS-VAX-EMERCLARK.
// Gap: GAP-0080

use polyisa_timing::{Fidelity, InstrEvent, TimingModel, VirtualTime};

use crate::Insn;
use crate::specifier::{self, Acc, Fetched, Opnd, Spec};

/// 値によって実行時間が変わる命令へ渡す実行時情報。
///
/// 各フィールドは該当命令でのみ使われる。
#[derive(Debug, Clone, Copy, Default)]
pub struct Rt {
    /// 条件分岐の成立（取ったなら true）。
    pub taken: Option<bool>,
    /// この命令イベントが処理する単位数。文字列命令はバイト数、
    /// 十進文字列命令は桁数（mulp は両桁数の積）、poly は評価する
    /// 次数、pushr/popr はマスク内のレジスタ数、calls は引数個数。
    /// `first=true` の一括見積もりでは処理長全体を渡す。
    pub units: u64,
    /// 反復命令の先頭ステップ（初期化コストとオペランド指定子の
    /// 評価コストを足す）。反復しない命令では常に true。
    /// 「反復 1 回 = 1 ステップ」で走る文字列・十進命令は
    /// 先頭ステップだけ true にする。
    pub first: bool,
}

/// 指定子の評価コスト（μc）。拡張バイトのフェッチ・ポインタの
/// 間接読み出し・指数乗算・自動増減の更新を含み、オペランドの
/// データアクセス自体は含まない。実測値の差分から当てはめた近似。
// Gap: GAP-0080
fn spec_eval(s: &Spec) -> u64 {
    match s {
        Spec::Lit(_) | Spec::Reg(_) | Spec::RegDef(_) => 0,
        // 即値・絶対は拡張語のフェッチ。
        Spec::Imm { .. } | Spec::Abs(_) => 2,
        // 自動増減はレジスタ更新。
        Spec::AutoInc(_) | Spec::AutoDec(_) => 1,
        // 間接は更新に加えポインタの読み出し。
        Spec::AutoIncDef(_) => 3,
        // 変位は拡張バイトのフェッチ（幅によらず 1）、間接は
        // ポインタ読み出しが加わる。
        Spec::Disp { .. } => 1,
        Spec::DispDef { .. } => 3,
        // index は基底評価に指数の乗算・加算を足す。
        Spec::Indexed { base, .. } => 3 + spec_eval(base),
    }
}

/// オペランド 1 個のデータアクセスコスト（μc）。アクセス型と幅
/// （4 バイトごとに 1 メモリアクセスとする近似）で決まる。
/// `.a`/`.b` はデータアクセスを持たず、`.v` はフィールドの基底
/// 読み出しとして読み出し側を数える。
// Gap: GAP-0080
fn data_acc(ty: specifier::OpTy) -> u64 {
    // 4 バイト単位のメモリアクセス回数。
    let acc = u64::from(ty.width.bytes().div_ceil(4)) * 2;
    match ty.acc {
        Acc::R | Acc::V => acc,
        // 書き込み・読み書きは読み出しより重い（実測の差分どおり）。
        Acc::W | Acc::M => acc + 2,
        Acc::A | Acc::B => 0,
    }
}

/// オペランド 1 個のコスト（指定子評価 + データアクセス）。
/// レジスタ・リテラルは 0、即値は評価側に畳み込まれる。
fn opnd_cost(op: &Opnd, ty: specifier::OpTy) -> u64 {
    match op {
        Opnd::Br(_) => 0,
        Opnd::Spec(s) => {
            spec_eval(s)
                + match s {
                    // レジスタ・リテラル・即値はアクセスコストがない
                    // （即値のフェッチは評価側）。
                    Spec::Lit(_) | Spec::Reg(_) | Spec::Imm { .. } => 0,
                    _ => data_acc(ty),
                }
        }
    }
}

/// 命令本体のマイクロコード時間（μc）。指定子評価・データ
/// アクセスは `opnd_cost` が別途足す。
/// 値は 780 実測（μs × 5）のアンカーと、表にない命令のクラス近似。
/// `rt.units` は反復命令の処理単位数、`rt.first` は初期化コストの
/// 支払い、`rt.taken` は条件分岐の成立。
// Gap: GAP-0080
fn body(insn: Insn, rt: &Rt) -> u64 {
    let u = rt.units;
    let setup = u64::from(rt.first);
    match insn {
        // ---- 整数 ----
        Insn::Nop => 1,
        Insn::Addb2
        | Insn::Addw2
        | Insn::Addl2
        | Insn::Subb2
        | Insn::Subw2
        | Insn::Subl2
        | Insn::Adwc
        | Insn::Sbwc
        | Insn::Bisb2
        | Insn::Bisw2
        | Insn::Bisl2
        | Insn::Bicb2
        | Insn::Bicw2
        | Insn::Bicl2
        | Insn::Xorb2
        | Insn::Xorw2
        | Insn::Xorl2 => 2,
        Insn::Addb3
        | Insn::Addw3
        | Insn::Addl3
        | Insn::Subb3
        | Insn::Subw3
        | Insn::Subl3
        | Insn::Bisb3
        | Insn::Bisw3
        | Insn::Bisl3
        | Insn::Bicb3
        | Insn::Bicw3
        | Insn::Bicl3
        | Insn::Xorb3
        | Insn::Xorw3
        | Insn::Xorl3 => 3,
        Insn::Movb | Insn::Movw | Insn::Movl | Insn::Movzbl | Insn::Movzbw | Insn::Movzwl => 2,
        Insn::Movq => 3,
        Insn::Movo => 4,
        Insn::Mcomb | Insn::Mcomw | Insn::Mcoml | Insn::Mnegb | Insn::Mnegw | Insn::Mnegl => 2,
        Insn::Clrb | Insn::Clrw | Insn::Clrl => 3,
        Insn::Clrq => 6,
        Insn::Clro => 8,
        Insn::Incb | Insn::Incw | Insn::Incl | Insn::Decb | Insn::Decw | Insn::Decl => 2,
        Insn::Cmpb
        | Insn::Cmpw
        | Insn::Cmpl
        | Insn::Tstb
        | Insn::Tstw
        | Insn::Tstl
        | Insn::Bitb
        | Insn::Bitw
        | Insn::Bitl => 2,
        Insn::Cvtbw | Insn::Cvtbl | Insn::Cvtwb | Insn::Cvtwl | Insn::Cvtlb | Insn::Cvtlw => 2,
        Insn::Movab
        | Insn::Movaw
        | Insn::Moval
        | Insn::Movaq
        | Insn::Movah
        | Insn::Pushab
        | Insn::Pushaw
        | Insn::Pushal
        | Insn::Pushaq
        | Insn::Pushah => 2,
        Insn::Pushl => 3,
        Insn::Mulb2 | Insn::Mulb3 => 16,
        Insn::Mulw2 | Insn::Mulw3 => 24,
        Insn::Mull2 | Insn::Mull3 => 32,
        Insn::Divb2 | Insn::Divb3 => 32,
        Insn::Divw2 | Insn::Divw3 => 40,
        Insn::Divl2 | Insn::Divl3 => 48,
        Insn::Emul => 34,
        Insn::Ediv => 60,
        Insn::Rotl => 6,
        Insn::Ashl => 10,
        Insn::Ashq => 12,
        Insn::Extv => 15,
        Insn::Extzv | Insn::Cmpv | Insn::Cmpzv => 13,
        Insn::Insv => 18,
        Insn::Ffs | Insn::Ffc => 10,
        Insn::Index => 10,
        // pushr/popr: ベース + マスク内レジスタ数 × 2。
        Insn::Pushr | Insn::Popr => 4 + 2 * u,
        Insn::Caseb | Insn::Casew | Insn::Casel => 10,
        Insn::Acbb | Insn::Acbw | Insn::Acbl => 7,
        Insn::Aoblss | Insn::Aobleq | Insn::Sobgeq | Insn::Sobgtr => 5,
        Insn::Bbs | Insn::Bbc => 7,
        Insn::Bbss | Insn::Bbcs | Insn::Bbsc | Insn::Bbcc | Insn::Bbssi | Insn::Bbcci => 8,
        Insn::Blbs | Insn::Blbc => 4,
        // ---- 分岐・手続呼出 ----
        Insn::Brb | Insn::Brw | Insn::Jmp => 4,
        Insn::Bneq
        | Insn::Beql
        | Insn::Bgtr
        | Insn::Bleq
        | Insn::Bgeq
        | Insn::Blss
        | Insn::Bgtru
        | Insn::Blequ
        | Insn::Bvc
        | Insn::Bvs
        | Insn::Bgequ
        | Insn::Blssu => {
            if rt.taken.unwrap_or(true) {
                4
            } else {
                2
            }
        }
        Insn::Bsbb | Insn::Bsbw | Insn::Jsb => 8,
        Insn::Rsb => 6,
        Insn::Ret => 14,
        // calls+ret のペア実測（#0 引数）から calls と ret を切り
        // 分け、calls は引数 1 個ごとに +2（近似）。
        Insn::Callg => 55,
        Insn::Calls => 60 + 2 * u,
        // ---- キュー ----
        Insn::Insque | Insn::Remque => 35,
        Insn::Insqhi | Insn::Insqti | Insn::Remqhi | Insn::Remqti => 76,
        // ---- 文字列（setup + 単位数ごと）----
        Insn::Movc3 | Insn::Movc5 => 25 * setup + u,
        Insn::Cmpc3 | Insn::Cmpc5 => 20 * setup + 5 * u,
        Insn::Locc | Insn::Skpc | Insn::Scanc | Insn::Spanc => 15 * setup + 5 * u,
        Insn::Matchc => 25 * setup + 5 * u,
        Insn::Movtc | Insn::Movtuc => 30 * setup + 4 * u,
        Insn::Crc => 10 * setup + 15 * u,
        Insn::Editpc => 40 * setup + 10 * u,
        // ---- 十進文字列 ----
        Insn::Movp => 5 * setup + 5 * u,
        Insn::Cmpp3 | Insn::Cmpp4 => 10 * setup + 8 * u,
        Insn::Addp4 | Insn::Subp4 => 10 * setup + 9 * u,
        Insn::Addp6 | Insn::Subp6 => 20 * setup + 10 * u,
        // mulp は units に両桁数の積を取る（d1*d2 の重み）。
        Insn::Mulp => 200 * setup + 6 * u,
        Insn::Divp => 110 * setup + 2 * u * u,
        Insn::Cvtpl => 40 * setup + 2 * u,
        Insn::Cvtlp | Insn::Cvtps | Insn::Cvtsp => 40 * setup + 4 * u,
        Insn::Cvtpt => 30 * setup + 5 * u,
        Insn::Cvttp => 35 * setup + 4 * u,
        Insn::Ashp => 40 * setup + 5 * u,
        // ---- 浮動小数点（F/D は FPA の値、G/H はマイクロコード）----
        Insn::Addf2
        | Insn::Addf3
        | Insn::Subf2
        | Insn::Subf3
        | Insn::Movf
        | Insn::Mnegf
        | Insn::Tstf
        | Insn::Cmpf => 4,
        Insn::Mulf2 | Insn::Mulf3 => 6,
        Insn::Divf2 | Insn::Divf3 => 23,
        Insn::Addd2
        | Insn::Addd3
        | Insn::Subd2
        | Insn::Subd3
        | Insn::Movd
        | Insn::Mnegd
        | Insn::Tstd
        | Insn::Cmpd => 7,
        Insn::Muld2 | Insn::Muld3 => 17,
        Insn::Divd2 | Insn::Divd3 => 44,
        Insn::Addg2
        | Insn::Addg3
        | Insn::Subg2
        | Insn::Subg3
        | Insn::Movg
        | Insn::Mnegg
        | Insn::Tstg
        | Insn::Cmpg => 72,
        Insn::Mulg2 | Insn::Mulg3 => 148,
        Insn::Divg2 | Insn::Divg3 => 264,
        Insn::Addh2
        | Insn::Addh3
        | Insn::Subh2
        | Insn::Subh3
        | Insn::Movh
        | Insn::Mnegh
        | Insn::Tsth
        | Insn::Cmph => 138,
        Insn::Mulh2 | Insn::Mulh3 => 426,
        Insn::Divh2 | Insn::Divh3 => 1115,
        // 変換・acb・emod は対応する算術のオーダー（近似）。
        Insn::Cvtfb
        | Insn::Cvtfw
        | Insn::Cvtfl
        | Insn::Cvtrfl
        | Insn::Cvtbf
        | Insn::Cvtwf
        | Insn::Cvtlf
        | Insn::Cvtfd
        | Insn::Cvtfg
        | Insn::Cvtfh
        | Insn::Acbf => 6,
        Insn::Cvtdb
        | Insn::Cvtdw
        | Insn::Cvtdl
        | Insn::Cvtrdl
        | Insn::Cvtbd
        | Insn::Cvtwd
        | Insn::Cvtld
        | Insn::Cvtdf
        | Insn::Cvtdh
        | Insn::Acbd => 9,
        Insn::Cvtgb
        | Insn::Cvtgw
        | Insn::Cvtgl
        | Insn::Cvtrgl
        | Insn::Cvtbg
        | Insn::Cvtwg
        | Insn::Cvtlg
        | Insn::Cvtgf
        | Insn::Cvtgh
        | Insn::Acbg => 75,
        Insn::Cvthb
        | Insn::Cvthw
        | Insn::Cvthl
        | Insn::Cvtrhl
        | Insn::Cvtbh
        | Insn::Cvtwh
        | Insn::Cvtlh
        | Insn::Cvthf
        | Insn::Cvthd
        | Insn::Cvthg
        | Insn::Acbh => 140,
        Insn::Emodf => 10,
        Insn::Emodd => 25,
        Insn::Emodg => 160,
        Insn::Emodh => 450,
        // poly: 初期化 + 次数ごとの Horner 反復（反復 1 回が
        // mul+add+係数読み出しの連鎖）。
        Insn::Polyf => 10 * setup + 9 * u,
        Insn::Polyd => 15 * setup + 18 * u,
        Insn::Polyg => 25 * setup + 185 * u,
        Insn::Polyh => 30 * setup + 720 * u,
        // ---- システム・その他 ----
        Insn::Prober | Insn::Probew => 8,
        Insn::Chmk | Insn::Chme | Insn::Chms | Insn::Chmu => 20,
        Insn::Halt
        | Insn::Rei
        | Insn::Bpt
        | Insn::Ldpctx
        | Insn::Svpctx
        | Insn::Bugw
        | Insn::Bugl => 10,
    }
}

/// 命令 1 個の消費マイクロサイクルを見積もる。
/// 本体時間に加え、`rt.first`（反復命令の先頭ステップ）では
/// 各オペランド指定子の評価・データアクセスコストを足す。
/// 反復の後続ステップでは指定子評価を数えない（この実行モデルは
/// 意味論側で指定子を再評価するが、実機のマイクロコードは
/// 退避した内部状態で続行するため）。
#[must_use]
pub fn insn_cycles(f: &Fetched, rt: &Rt) -> u64 {
    let mut c = body(f.insn, rt);
    if rt.first {
        let tys = specifier::insn_ops(f.insn);
        for (op, ty) in f.ops.iter().zip(tys) {
            c += opnd_cost(op, *ty);
        }
    }
    c
}

/// VAX-11/780 のマイクロコード時間モデル。命令ごとの消費
/// マイクロサイクルを仮想時間へ累積する。
///
/// `step` がデコード済み命令（`Fetched`）の消費時間を計算して
/// 足す。`TimingModel` 経路では、汎用イベントは指定子の形を
/// 持たないため `ev.hint` に `insn_cycles` の結果を入れて渡す
/// 約束とする。
#[derive(Default)]
pub struct Vax780 {
    /// 累積マイクロサイクル。
    pub time: u64,
}

impl Vax780 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 1 命令ぶんを足し、加算した μc を返す。
    pub fn step(&mut self, f: &Fetched, rt: &Rt) -> u64 {
        let c = insn_cycles(f, rt);
        self.time += c;
        c
    }

    /// 宣言する忠実度。実測の抜粋アンカー + クラス近似の混合で、
    /// 実機による較正を行っていないので未較正 approx。
    #[must_use]
    pub fn fidelity(&self) -> Fidelity {
        Fidelity::ApproxUncalibrated
    }
}

impl TimingModel for Vax780 {
    /// `ev.hint` を計算済み μc として足す。
    fn observe(&mut self, ev: &InstrEvent) {
        self.time += ev.hint;
    }

    fn now(&self) -> VirtualTime {
        VirtualTime(self.time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::specifier::decode_insn;

    fn rt() -> Rt {
        Rt {
            taken: None,
            units: 0,
            first: true,
        }
    }

    /// addl2 系の符号化（第 1 オペランド src、第 2 オペランド dst）。
    fn addl2(src: &[u8], dst: &[u8]) -> Fetched {
        let mut b = vec![0xd0];
        b.extend_from_slice(src);
        b.extend_from_slice(dst);
        decode_insn(&b).unwrap()
    }

    // アンカー照合: addl2 r0,r1 = 0.40μs = 2μc。
    #[test]
    fn alu_reg_reg() {
        let f = addl2(&[0x50], &[0x51]);
        assert_eq!(insn_cycles(&f, &rt()), 2);
        // 3 項は +1。
        let mut b = vec![0xc1, 0x50, 0x51, 0x52];
        let f = decode_insn(&b).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 3);
        b[0] = 0xcd; // xorl3 も同じクラス
        let f = decode_insn(&b).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 3);
    }

    // アンカー照合: addl2 #imm,r = 4.2、addl2 (r),r = 4.0、
    // addl2 B^disp(r),r ≈ 4-5、addl2 r,(r) = 6.65、
    // addl2 (r)[rx],r = 7.0 の近似帯。
    #[test]
    fn alu_operand_costs() {
        // #imm（0x8f + 4B）。
        let f = addl2(&[0x8f, 1, 0, 0, 0], &[0x51]);
        assert_eq!(insn_cycles(&f, &rt()), 4);
        // (r0) 読み出し = eval 0 + read 2。
        let f = addl2(&[0x60], &[0x51]);
        assert_eq!(insn_cycles(&f, &rt()), 4);
        // B^disp(r0) = eval 1 + read 2。
        let f = addl2(&[0xa0, 0x10], &[0x51]);
        assert_eq!(insn_cycles(&f, &rt()), 5);
        // dst (r0) 書き込み = eval 0 + modify 4。
        let f = addl2(&[0x51], &[0x60]);
        assert_eq!(insn_cycles(&f, &rt()), 6);
        // (r0)[r1] = index 3 + read 2。
        let f = addl2(&[0x41, 0x60], &[0x52]);
        assert_eq!(insn_cycles(&f, &rt()), 7);
        // mem,mem = read 2 + modify 4。
        let f = addl2(&[0x60], &[0x61]);
        assert_eq!(insn_cycles(&f, &rt()), 8);
    }

    #[test]
    fn mul_div_anchors() {
        // mull2 r,r = 6.43μs ≈ 32μc。
        let mut b = vec![0xc4, 0x50, 0x51];
        assert_eq!(insn_cycles(&decode_insn(&b).unwrap(), &rt()), 32);
        // divl3 r,r,r ≈ 48μc。
        b = vec![0xc7, 0x50, 0x51, 0x52];
        assert_eq!(insn_cycles(&decode_insn(&b).unwrap(), &rt()), 48);
        // emul ≈ 34、ediv ≈ 60。
        b = vec![0x7a, 0x50, 0x51, 0x52, 0x53];
        assert_eq!(insn_cycles(&decode_insn(&b).unwrap(), &rt()), 34);
        b = vec![0x7b, 0x50, 0x51, 0x52, 0x53];
        assert_eq!(insn_cycles(&decode_insn(&b).unwrap(), &rt()), 60);
    }

    #[test]
    fn branch_taken() {
        // beql 取る=4、取らない=2、brb=4。
        let f = decode_insn(&[0x13, 0x10]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 4);
        let rt_nt = Rt {
            taken: Some(false),
            ..rt()
        };
        assert_eq!(insn_cycles(&f, &rt_nt), 2);
        let f = decode_insn(&[0x11, 0x10]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 4);
    }

    #[test]
    fn iterative_setup_and_units() {
        // movc3 len.ab,src.ab,dst.ab: 一括 len=10 → 25 + 10 = 35。
        let mut b = vec![0x28];
        // rw #10: 0x8f + 2B
        b.extend_from_slice(&[0x8f, 10, 0]);
        b.extend_from_slice(&[0x9f, 0, 0, 4, 0]); // @#src
        b.extend_from_slice(&[0x9f, 0, 0, 5, 0]); // @#dst
        let f = decode_insn(&b).unwrap();
        let rt_all = Rt { units: 10, ..rt() };
        let whole = insn_cycles(&f, &rt_all);
        // 反復分割: first だけ setup+指定子、以後 1 バイトごと。
        let rt_step0 = Rt { units: 1, ..rt() };
        let rt_later = Rt {
            units: 1,
            first: false,
            ..rt()
        };
        let mut total = insn_cycles(&f, &rt_step0);
        for _ in 1..10 {
            total += insn_cycles(&f, &rt_later);
        }
        // 分割した総和は一括見積もりと一致する（setup・指定子
        // 評価は先頭ステップで 1 度だけ払う）。
        assert_eq!(total, whole);
        assert_eq!(whole, 25 + opnd_cost_all(&f) + 10);
    }

    fn opnd_cost_all(f: &Fetched) -> u64 {
        let tys = specifier::insn_ops(f.insn);
        f.ops.iter().zip(tys).map(|(o, t)| opnd_cost(o, *t)).sum()
    }

    #[test]
    fn decimal_and_fp() {
        // addf2 r,r = 4、mulf2 = 6、divf3 = 23、addg2 = 72（FPA 非対象）。
        let f = decode_insn(&[0x40, 0x50, 0x51]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 4);
        let f = decode_insn(&[0xfd, 0x40, 0x50, 0x51]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 72);
        // movp 7 桁 = 5 + 5*7 = 40 + 指定子コスト。
        let b = vec![0x34, 0x8f, 7, 0, 0x9f, 0, 0, 4, 0, 0x9f, 0, 0, 5, 0];
        let f = decode_insn(&b).unwrap();
        let rt7 = Rt { units: 7, ..rt() };
        // @#abs の .ab はアドレス評価のみ（eval 2）、#imm rw は eval 2。
        assert_eq!(insn_cycles(&f, &rt7), 40 + 2 + 2 + 2);
        // addp6 18 桁 = 20 + 10*18 = 200。
        let b = vec![
            0x21, 0x8f, 18, 0, 0x9f, 0, 0, 4, 0, 0x8f, 18, 0, 0x9f, 0, 0, 5, 0, 0x8f, 18, 0, 0x9f,
            0, 0, 6, 0,
        ];
        let f = decode_insn(&b).unwrap();
        let rt18 = Rt { units: 18, ..rt() };
        assert_eq!(insn_cycles(&f, &rt18), 200 + 2 + 2 + 2 + 2 + 2 + 2);
    }

    #[test]
    fn queue_and_calls() {
        // insque entry.ab,pred.ab = 35 + 指定子。
        let f = decode_insn(&[0x0e, 0x60, 0x61]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 35);
        // インターロック版は 76。
        let f = decode_insn(&[0x5c, 0x60, 0x61]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 76);
        // ret = 14。calls #0 = 60。
        let f = decode_insn(&[0x04]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 14);
        // calls #0,(r0): rl の即値評価（2）が乗る。
        let f = decode_insn(&[0xfb, 0x8f, 0, 0, 0, 0, 0x60]).unwrap();
        assert_eq!(insn_cycles(&f, &rt()), 62);
    }

    #[test]
    fn model_accumulates() {
        let mut m = Vax780::new();
        assert_eq!(m.fidelity(), Fidelity::ApproxUncalibrated);
        let f = decode_insn(&[0xd0, 0x50, 0x51]).unwrap(); // addl2 r,r
        assert_eq!(m.step(&f, &rt()), 2);
        let f = decode_insn(&[0x11, 0x04]).unwrap(); // brb
        assert_eq!(m.step(&f, &rt()), 4);
        assert_eq!(m.now(), VirtualTime(6));
    }

    #[test]
    fn observe_uses_hint() {
        let mut m = Vax780::new();
        let ev = InstrEvent::new(0x1000, "alu");
        let ev = InstrEvent { hint: 7, ..ev };
        m.observe(&ev);
        assert_eq!(m.now(), VirtualTime(7));
    }
}
