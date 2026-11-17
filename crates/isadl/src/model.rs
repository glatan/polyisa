// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 検査済みモデルの入れ物。構文解析器がこの形を作り、検査と生成が読む。
//!
//! ビット連結（`++`）、スケーリング、フックの詳細は後の段階で足す。
//! ここでは範囲フィールドと名前解決に必要な項目だけを持つ。

use super::pattern::Pattern;
use super::pred::Pred;

/// ISA の宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Isa {
    pub name: String,
    /// 命令フェッチの単位（ビット）。
    pub parcel_bits: u32,
}

/// 実行モードの値の種類。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ModeType {
    Bool,
    Enum(Vec<String>),
}

/// 実行モードの宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mode {
    pub name: String,
    pub ty: ModeType,
}

/// レジスタクラス。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegClass {
    pub name: String,
    /// 実行時に位置を計算するかどうか。
    pub dynamic: bool,
}

/// フィールドの取り出し方。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FieldKind {
    /// 命令語の `[hi:lo]`。
    Bits { hi: u32, lo: u32 },
    /// Rust のフック。逆変換の有無でエンコーダ可否が決まる。
    Hook { has_encoder: bool },
}

/// フィールドの宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
}

/// オペランドの読み書き。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

/// オペランドの宣言。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Operand {
    pub name: String,
    pub regclass: Option<String>,
    pub access: Access,
}

/// 形式。複数命令で共通する配置とオペランド。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Format {
    pub name: String,
    pub fields: Vec<String>,
    pub operands: Vec<Operand>,
}

/// フィールド値の制約（`where`）。デコード時に評価する。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WhereOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// `where` の右辺。リテラル値か、同じ形式の別フィールド。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WhereRhs {
    Lit(u128),
    Field(String),
}

/// フィールド値の制約（`where`）1 件。`field` は形式のフィールド名である。
/// `rhs` が `Field` のときはフィールド同士の比較（MIPS R6 の BOVC/BEQC 等）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WhereClause {
    pub field: String,
    pub op: WhereOp,
    pub rhs: WhereRhs,
}

/// 命令。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Insn {
    pub name: String,
    pub format: String,
    pub pattern: Pattern,
    pub when: Pred,
    pub wheres: Vec<WhereClause>,
    pub syntax: String,
    pub timing: String,
}

/// 機能。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Feature {
    pub name: String,
    pub implies: Vec<String>,
    pub conflicts: Vec<String>,
}

/// 挙動パラメータの型（真偽値・列挙・整数）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParamKind {
    /// 真偽値。値は "true"/"false"。
    Bool,
    /// 列挙。値は列挙子の名前（序数で保持する）。
    Enum(Vec<String>),
    /// 整数。値は 0..=max。
    Int(u32),
}

/// 挙動パラメータの宣言（既定値と説明を持つ型付きの値）。
/// `cpu-models.md` の `param` 句に対応する。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Param {
    pub name: String,
    pub kind: ParamKind,
    /// 既定値（kind が Enum なら列挙子名、Bool なら "true"/"false"、
    /// Int なら 10 進整数）。
    pub default: String,
    /// 説明。出典は `ref` 慣習どおり括弧に書く。
    pub doc: String,
}

/// CPU モデルの定義（機能の足し引きと親の指定）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModelDef {
    pub name: String,
    pub parent: String,
    pub add_features: Vec<String>,
    pub remove_features: Vec<String>,
    /// 挙動パラメータの値の上書き（`param` 句の値）。
    pub params: Vec<(String, String)>,
    /// 機能に対応しない識別情報の値（`cpuid.vendor`・`cpuid.family`
    /// 等のキーと文字列値の対）。機能の有無に対応するビットは
    /// `IdentBit` が導出するのでここには書かない。
    pub ident: Vec<(String, String)>,
}

/// 機能から識別情報のビットへの対応。機能が有効なら識別情報の
/// リーフ `leaf`・サブリーフ `subleaf` のレジスタ `reg` の
/// ビット `bit` を立てる。x86 の CPUID の対応表が典型例である
/// （`cpuid_bit sse2 = leaf 0x1, edx, 26;`、cpu-models.md 参照）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentBit {
    /// 対応する機能の名前。
    pub feature: String,
    /// 識別情報のリーフ番号（CPUID の EAX 入力値）。
    pub leaf: u32,
    /// サブリーフ番号（CPUID の ECX 入力値。なければ 0）。
    pub subleaf: u32,
    /// 出力レジスタの名前（`eax`・`ebx`・`ecx`・`edx` 等）。
    pub reg: String,
    /// レジスタ内のビット位置。
    pub bit: u8,
}

/// オペランドの幅。`V` は有効オペランドサイズ（16/32/64）、`Z` は 16/32、
/// `A` は有効アドレスサイズに従う。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpWidth {
    B8,
    W16,
    V,
    Z,
    D32,
    Q64,
    O128,
    A,
}

/// `map` 記述のオペランドの種類。ModRM 系はデコーダがバイトを消費する
/// 規則を持ち、即値と相対変位は命令の末尾から読む。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpKind {
    /// ModRM.r/m の EA またはレジスタ（Eb/Ev/Ew/Ed/Eq/Eo）。
    Ea(OpWidth),
    /// ModRM.reg の GPR（Gb/Gv/Gw/Gd）。
    Reg(OpWidth),
    /// ModRM.reg のセグメントレジスタ（Sreg）。
    RegS,
    /// ModRM.reg の XMM（V/U 系）。
    RegX,
    /// ModRM.r/m の XMM（W 系）。EA のときは 128 ビットのメモリ。
    RmX,
    /// ModRM.reg の MMX レジスタ（P 系）。
    RegM,
    /// ModRM.r/m の MMX または 64 ビットメモリ（Q 系）。
    RmM,
    /// オペコード下位 3 ビットの GPR（+rb/+rw/+ro/+rv）。
    InOp(OpWidth),
    /// 即値（Ib/Iw/Iz/Iv）。`V` は 64 ビット時に符号拡張された 32 ビット。
    Imm(OpWidth),
    /// 2 つ目の即値（ENTER の imm8）。
    Imm2(OpWidth),
    /// 相対変位（Jb/Jz）。
    Rel(OpWidth),
    /// moffs（Ob/Ov）。幅は有効アドレスサイズ。
    Moffs(OpWidth),
    /// 暗黙オペランド。
    Imp(ImpOp),
}

/// 暗黙オペランド。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImpOp {
    /// アキュムレータ（AL/AX/EAX/RAX、幅は V）。
    Eax,
    Ecx,
    Edx,
    Ebx,
    Esp,
    Ebp,
    Esi,
    Edi,
    /// 8 ビットの CL。
    Cl,
    /// 定数 1（シフト）。
    One,
    /// x87 の ST(0)。
    St0,
    /// x87 の ST(i)。i は ModRM.r/m またはオペコードのフィールド。
    Sti,
    /// DS:(E)SI のソース（string 命令）。
    Xsrc,
    /// ES:(E)DI のデスティネーション（string 命令）。
    Ydst,
    /// セグメントレジスタの暗黙指定（PUSH FS 等）。
    Seg(u8),
}

/// `map` の命令項目が要求する必須接頭辞の状態。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PfxSel {
    /// 必須接頭辞で区別しない（primary 系の既定）。
    Any,
    /// 0x66・0xF2・0xF3 がいずれもないもの（MOVUPS など）。
    Plain,
    /// 0x66 がないもの。F2/F3 は必須接頭辞でないエンコーディング
    /// では無視される（0F 38 / 0F 3A の MMX 形など）。
    No66,
    /// 0x66 も 0xF3 もないもの（NP + F2）。F3 が別命令に
    /// 割り当てられている MMX 形（MOVQ など）に使う。
    No66F3,
    /// 0xF2 がないもの（NP + 66 + F3）。F2 が別命令に
    /// 割り当てられているもの（0F 38 F0/F1 の MOVBE と
    /// CRC32 の関係）に使う。
    NoF2,
    /// 0xF3 がないもの（NP + 66 + F2）。F3 が別命令に
    /// 割り当てられているもの（0F BD の BSR と LZCNT の
    /// 関係）に使う。
    NoF3,
    /// 0x66 を要求する（MOVUPD など）。
    P66,
    /// 0xF2 を要求する（MOVSD など）。
    PF2,
    /// 0xF3 を要求する（MOVSS など）。
    PF3,
}

/// `map` の中で宣言する命令。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MapInsn {
    pub name: String,
    /// オペランドの並び。消費するバイトの規則をここから導く。
    pub ops: Vec<OpKind>,
    /// ModRM.reg によるグループ選択（/0 から /7）。None は /r または ModRM なし。
    pub group: Option<u8>,
    /// ModRM.mod の選択。`Some(true)` は mod=11（レジスタ形）のみ、
    /// `Some(false)` は mod!=11（メモリ形）のみ。None は制約なし。
    /// 0F AE の fence（mod=11）と clflush（mod!=11）のように同じ /n で
    /// mod で分岐するエンコーディングや、メモリ形専用の非グループ項目
    /// （LEA・MOVBE・MOVLPS ストアなど）に使う。
    pub group_mod: Option<bool>,
    /// 必須接頭辞の状態。
    pub pfx: PfxSel,
    pub when: Pred,
    pub syntax: String,
    pub timing: String,
}

/// `map` の一要素。命令を宣言するか、別の表へ分岐する。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MapItem {
    /// バイト値 `u8` に対する命令（グループ・必須接頭辞は `MapInsn` が持つ）。
    Insn(u8, MapInsn),
    /// バイト値 `u8` で別の表に分岐する（0F、VEX 後の map 選択）。
    /// `when` が成り立たないときは分岐せず、同じバイトの命令項目へ
    /// 進む（8088 の 0F=POP CS と 0F 副表の振り分けに使う）。
    Map(u8, String, Pred),
}

/// オペコード表。バイト値をキーとする。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MapDecl {
    pub name: String,
    pub items: Vec<MapItem>,
}

/// 検査済みモデルの全体。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Model {
    pub isa: Option<Isa>,
    pub modes: Vec<Mode>,
    pub regclasses: Vec<RegClass>,
    pub fields: Vec<Field>,
    pub formats: Vec<Format>,
    pub insns: Vec<Insn>,
    pub features: Vec<Feature>,
    /// 挙動パラメータの宣言。
    pub params: Vec<Param>,
    pub models: Vec<ModelDef>,
    /// 機能から識別情報のビットへの対応表。
    pub ident_bits: Vec<IdentBit>,
    pub timing_classes: Vec<String>,
    /// オペコード表（可変長 ISA 用。`primary` がデコードの入口）。
    pub maps: Vec<MapDecl>,
}

impl Model {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 挙動パラメータを一件宣言する。`default` は kind が Enum なら
    /// 列挙子名、Bool なら "true"/"false"、Int なら 10 進整数。
    pub fn param(&mut self, name: &str, kind: ParamKind, default: &str, doc: &str) -> &mut Self {
        self.params.push(Param {
            name: name.to_string(),
            kind,
            default: default.to_string(),
            doc: doc.to_string(),
        });
        self
    }

    /// 機能→識別情報ビットの対応を一件追加する。
    pub fn ident_bit(
        &mut self,
        feature: &str,
        leaf: u32,
        subleaf: u32,
        reg: &str,
        bit: u8,
    ) -> &mut Self {
        self.ident_bits.push(IdentBit {
            feature: feature.to_string(),
            leaf,
            subleaf,
            reg: reg.to_string(),
            bit,
        });
        self
    }
}
