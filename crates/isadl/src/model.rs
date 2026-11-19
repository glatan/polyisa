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
    /// 論理値が命令語の複数範囲に分かれるもの（RISC-V の S/B/J 形式の
    /// 即値など）。`parts` は `(hi, lo)` の範囲を論理値の上位側から
    /// 並べたもので、デコードは順に連結して論理値を得る。`zfill` は
    /// 論理値の下位に暗黙の 0 を足す幅（分岐即値の `++ 0b0`）。
    Parts { parts: Vec<(u32, u32)>, zfill: u32 },
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
    /// 値を保持するフィールド。`None` なら `name` と同名のフィールドを
    /// 使う。構文中の名前（`{imm}` など）と、形式ごとに配置の違う
    /// フィールド（`imm_i`/`imm_s` など）を分けるために使う。
    pub field: Option<String>,
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
/// `A` は有効アドレスサイズに従う。`J` は近接分岐の変位で、64 ビット
/// モードではオペランドサイズが 64 に固定されるため常に 32（66 接頭辞は
/// 無視される）、それ以外のモードでは `Z` と同じ 16/32。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpWidth {
    B8,
    W16,
    V,
    Z,
    J,
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
    /// VEX.vvvv の 3 番目オペランド（H 系）。接頭辞フィールドなので
    /// バイトは消費しない。
    Vv,
    /// ModRM.reg のタイルレジスタ（AMX の tmm 宛先・TILEZERO）。
    RegT,
    /// ModRM.r/m のタイルレジスタ（AMX のソース。mod=11 のみ）。
    RmT,
    /// VEX.vvvv のタイルレジスタ（AMX の第 3 オペランド）。
    VvT,
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
    /// 0x66 がないもの。必須接頭辞でない F2/F3 は #UD であり
    /// 無視されない（XED 実測）。名前が指す条件は「別命令が
    /// 該当接頭辞を要求する」意図の印であり、受理集合は
    /// `Plain` と同じ（NP のみ）。
    No66,
    /// `No66` と同じ受理集合。F3 が別命令に割り当てられている
    /// MMX 形（MOVQ など）に使う。
    No66F3,
    /// 0x66 を許し F2/F3 は #UD。F2 が別命令に割り当てられて
    /// いるもの（0F 38 F0/F1 の MOVBE と CRC32 の関係）に使う。
    /// 受理集合は `NoF2F3` と同じ。
    NoF2,
    /// 0xF3 以外のもの（NP + 66 + F2）。F3 が別命令に
    /// 割り当てられているもの（0F BD の BSR と LZCNT の
    /// 関係、0F 1E のヒント NOP と ENDBR/RDSSP の関係）
    /// に使う。F2 は必須接頭辞でないため無視されて受理
    /// される（XED 実測）。
    NoF3,
    /// 0xF2 も 0xF3 もないもの（NP + 66）。F2/F3 が別命令に
    /// 割り当てられているもの（0F 01 E8 の SERIALIZE と
    /// XSUSLDTRK/SETSSBSY の関係）に使う。
    NoF2F3,
    /// 0x66 を要求する（MOVUPD など）。
    P66,
    /// 0xF2 を要求する（MOVSD など）。
    PF2,
    /// 0xF3 を要求する（MOVSS など）。
    PF3,
}

/// VEX.L の許容範囲。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VexL {
    /// L=0/1 の両方（128/256 ビットの両形）。
    Any,
    /// L=0（128 ビット形）のみ。
    L0,
    /// L=1（256 ビット形）のみ。
    L1,
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
    /// ModRM.r/m の選択。`Some(v)` は r/m フィールドが `v` のときだけに
    /// 解読する。0F 01 /5 mod=11 の r/m 副エンコーディング
    /// （rm=0 SETSSBSY、rm=2 SAVEPREVSSP、rm=4 UIRET など）や
    /// C7 /7 の XBEGIN（rm=0 固定）のように、同じグループ番号で
    /// r/m に応じて命令が分かれるときに使う。
    pub group_rm: Option<u8>,
    /// VEX 接頭辞の要求。None はレガシーエンコーディングのみ
    /// （VEX 経路では選ばれない）。`Some` は VEX が必須で、
    /// 値は VEX.L の許容範囲を表す。
    pub vex: Option<VexL>,
    /// EVEX 接頭辞の要求。`Some(mask)` は EVEX が必須で、mask は
    /// 許容する L'L のビット集合（bit0=128、bit1=256、bit2=512）。
    /// `vex` との同時指定は不可。
    pub evex: Option<u8>,
    /// EVEX disp8 の倍率。EVEX のメモリ形は disp8 を N 倍して
    /// 読む（disp8*N 方式）。0 はベクタ全幅（16<<L'L）。n は
    /// バイト数で、broadcast を許す項目では b=1 のメモリ形に、
    /// それ以外では常に適用される（スカラ形のオペランド）。
    pub edisp: u8,
    /// EVEX.b のメモリ形を許す（埋め込み broadcast）。r/m が
    /// メモリのとき EVEX.b=1 で要素をベクタ全幅に複製して読む。
    /// `evex` が必須で、要素サイズは `edisp` に置く。
    pub bcast: bool,
    /// EVEX.b のレジスタ形を許す（{er}/{sae}）。r/m がレジスタの
    /// とき EVEX.b=1 で L'L はベクタ長ではなく丸め指定になる
    /// （00=rn, 01=rd, 10=ru, 11=rz）。ベクトル長は 512 固定。
    pub er: bool,
    /// VEX.W / EVEX.W による項目選択。`Some(w)` の項目は
    /// W==w のエンコードにだけ一致する（同じオペコードで W 別の
    /// 要素幅を持つ命令を分ける）。None は W を区別しない。
    pub wsel: Option<bool>,
    /// APX EVEX 昇格形（map4）の項目。P2 の b/ND・NF・~v4 と
    /// P0 の B4/R4・P1 の U/X4 を使い、z=0・L'L=0 を要求する。
    /// `vex`/`evex` とは併用不可（EVEX.map4 経路でのみ選ばれる）。
    pub promoted: bool,
    /// 昇格形のうち ND=1 を必須とする項目（PUSH2/POP2 など
    /// vvvv が被演算子になるもの）。`promoted` とだけ併用する。
    pub ndd_req: bool,
    /// APX ZU 形。ND ビットが新宛先ではなくゼロ拡張を選ぶ項目
    /// （IMUL Gv,Ev,Iz/Ib・SETcc）。ND=1 と vvvv 全 1（未使用）
    /// の両方を要求し、宛先は引き続き ModRM.reg になる。
    /// `promoted` とだけ併用する。
    pub zu: bool,
    /// NF（P2.2）を受理する昇格形。NF 可能命令の一覧外
    /// （ADC/SBB/NOT/CMP/TEST/RCL/RCR・PUSH2/POP2 など）では
    /// NF=1 のエンコードは #UD。`promoted` とだけ併用する。
    pub nf_ok: bool,
    /// VEX.vvvv / EVEX.vvvv+V' が未使用（全ビット 1 固定）か。
    /// `vex`/`evex` が Some のときのみ意味を持つ。
    pub vex_rv: bool,
    /// LOCK 接頭辞（F0）を受理する。真の項目でも r/m が
    /// レジスタ（mod=11）の形では #UD。ALU の r/m 宛先形・
    /// INC/DEC/NEG/NOT・XCHG/XADD/CMPXCHG・BT 系のメモリ宛先
    /// だけが対象（Intel SDM の LOCK 許容一覧）。
    pub lock_ok: bool,
    /// ModRM.r/m=100（SIB 必須）かつ mod!=11 のメモリ形だけを
    /// 解読する。AMX の TILELOADD/TILESTORED の sibmem に使う。
    pub sib: bool,
    /// 必須接頭辞の状態。VEX 項目では VEX.pp に対応する。
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
    /// VEX.mmmmm がこの表を選ぶときの値（1=0F, 2=0F38, 3=0F3A）。
    /// None の表は VEX 経路から到達しない。
    pub vex_code: Option<u8>,
    /// オペコードが ModRM（と SIB・変位）の後に来る表
    /// （3DNow! の `0F 0F /r imm8` 形式）。true の表は先に
    /// ModRM を読んでから照合バイトを消費する。
    pub postop: bool,
    /// APX REX2 の M0=1 経路（0xD5 で 0F 表を指す）でこの表を
    /// 選ぶ。0F 表にだけ立てる。
    pub rex2_map1: bool,
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
