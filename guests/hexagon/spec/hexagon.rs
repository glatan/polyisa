// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Hexagon の ISADL モデル（段階22）。
//
// Hexagon の命令語は 32 ビットで、1–4 語を束ねたパケットが
// フェッチ・実行の単位。語内の Parse 桁（bits[15:14]）が
// パケット終端（11）・非終端（01/10、10 はループ終端の標識でも
// ある）・duplex（00、1 語に 13 ビット subinsn 2 個）を識別し、
// ICLASS 桁（bits[31:28]）が命令クラスを指す（0 は constant
// extender 語）。本モデルは 32 ビット語を命令語として宣言し、
// パケットの切り出し・duplex の subinsn 分解・constant extender
// の即値併合は実行側が担う（ia64 のバンドル→スロット語と同じ
// 分割）。
//
// duplex の subinsn は 13 ビット語としてこのモデルに宣言する
// （不確実項目 1 の結論: 擬似 32 ビット語への展開ではなく、
// 13 ビットパターンの Insn として宣言し、グループごとの
// 文脈旗 dx_{l1,l2,s1,s2,a} で絞る。ia64 の unit_* と同じ構造）。
// subinsn の 13 ビット割付は正本の表に図表としてのみ収録され
// テキスト化されていないため、本実装は符号化オラクルとの
// 照合で桁を確定済み。subinsn のレジスタ桁は 4 ビットの
// 部分集合符号（r0–r7→0–7、r16–r23→8–15、対レジスタは
// r(2n+1):(2n)→n）。構文の {dxd} 等はこの符号値をそのまま出す。
//
// constant extender（不確実項目 2 の結論）は ICLASS=0 の専用
// 32 ビット語として `immext` Insn を宣言し、実行側が直後の
// 命令と対にする。extender は実行スロットを消費しない。
//
// HX3 の段階では代表形式＋subinsn 全表を置く。32 ビット命令の
// 本格語彙は HX5–HX8 で足す。
// 主正本は SPEC-HEXAGON-PRM (V79, 80-N2040-60 Rev AB)。
// V5x〜V73 の版差の根拠は SPEC-HEXAGON-PRM-PREV 群
// （80-N2040-8/-33/-36/-39/-42/-45/-46/-53、-53 が V73）。
// Ref: SPEC-HEXAGON-PRM (V79), SPEC-HEXAGON-PRM-PREV.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// Hexagon の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "system", "misc", "hvx"] {
        m.timing_classes.push(class.to_string());
    }

    // 機能旗。
    // - `v*`: 版の系列。各版の命令集合（v5/v55/v60/v62/
    //   v65/v66/v67/v68/v69/v71/v73/v75/v79）で、新版は先行版を
    //   含意する。PREV 台帳の文書番号→版対応（-53=V73 以外の
    //   -8/-33/-36/-39/-42/-45/-46 の帰属）は各 PDF の表紙確認が
    //   要るため、版差の具体的な内容は HX3 以降で旗に写す。
    // - `tinycore`: v67t/v71t 系の tiny core 変種旗。版旗と直交。
    // - `hvx`: HVX ベクトル命令群の別旗（HVX の版差は HX9 で足す）。
    // - `dx_*`: duplex subinsn のデコード文脈旗。duplex ICLASS が
    //   各 subinsn のグループ（L1/L2/S1/S2/A）を指し、対応する
    //   旗を立てて 13 ビット語を decode_model_ex に通す
    //   （ia64 の unit_* と同型で、CPU モデルには含めない）。
    // Ref: SPEC-HEXAGON-PRM (V79), SPEC-HEXAGON-PRM-PREV.
    let versions = [
        "v5", "v55", "v60", "v62", "v65", "v66", "v67", "v68", "v69", "v71", "v73", "v75", "v79",
    ];
    for (i, name) in versions.iter().enumerate() {
        m.features.push(Feature {
            name: name.to_string(),
            implies: if i == 0 {
                vec![]
            } else {
                vec![versions[i - 1].to_string()]
            },
            conflicts: vec![],
        });
    }
    for name in ["tinycore", "hvx"] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: vec![],
        });
    }
    // dx_* は互いに排他（1 個の subinsn は 1 つのグループにだけ
    // 属する）。両立しない `when` とみなされるよう conflicts に
    // 後続の旗を並べる（ia64 の unit_* と同じ手順）。
    let dxs = ["dx_l1", "dx_l2", "dx_s1", "dx_s2", "dx_a"];
    for (i, name) in dxs.iter().enumerate() {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: dxs[i + 1..].iter().map(|s| s.to_string()).collect(),
        });
    }

    // CPU モデル。generic は V5 系のベースライン。v73 は Linux ABI
    // の配布物が要求する版（BIN-DISTRO-HEXAGON の e_flags 0x73）、
    // v79 は主正本の最新版。dx_* は文脈旗なのでモデルには含めない。
    for (name, parent, add) in [
        ("generic", "", &["v5"][..]),
        ("v73", "generic", &["v73"][..]),
        ("v79", "generic", &["v79"][..]),
    ] {
        m.models.push(ModelDef {
            params: vec![],
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: vec![],
            ident: vec![],
        });
    }

    // レジスタ類。gpr は r0-r31（対レジスタ Rdd は偶奇対）、pred は
    // p0-p3（各 8 ビット、P3:0 で 32 ビットに並ぶ）、creg は
    // 制御レジスタ c0-c31（SA0/LC0/.../USR/PC/UGP/GP/CS0/CS1 等）。
    // Ref: SPEC-HEXAGON-PRM (V79) registers.
    for (name, prefix) in [("gpr", "r"), ("pred", "p"), ("creg", "c")] {
        m.regclasses.push(RegClass {
            name: name.to_string(),
            dynamic: false,
            prefix: Some(prefix.to_string()),
        });
    }

    // ---- 桁。
    // 全形式共通の桁（ICLASS・Parse）と、duplex・constant
    // extender 語の配置、32 ビット命令の代表形式で使う桁。
    // Ref: SPEC-HEXAGON-PRM (V79) instruction encoding.
    for (name, hi, lo) in [
        ("iclass", 31, 28), // 命令クラス。0 は constant extender
        ("pp", 15, 14),     // Parse 桁（00=duplex, 01/10=非終端, 11=終端）
        ("sublo", 12, 0),   // duplex の slot0 subinsn
        ("subhi", 28, 16),  // duplex の slot1 subinsn
        // 32 ビット命令の代表形式で使う桁。
        ("s5", 20, 16),  // 5 ビットソース/ベースレジスタ
        ("t5", 12, 8),   // 5 ビットソース/ストア値レジスタ
        ("x5", 20, 16),  // 5 ビットソース=デスティネーションレジスタ
        ("d5", 4, 0),    // 5 ビットデスティネーションレジスタ
        ("c5", 20, 16),  // 制御レジスタ番号（Rd=Cs / Cd=Rs）
        ("pd2", 1, 0),   // 述語デスティネーション（2 ビット）
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }
    // 分割即値・duplex の 4 ビット ICLASS・extender 26 ビット即値。
    // - diclass: duplex の bits{31:29,13}。
    // - imm26: extender の bits{27:16}+{13:0}。
    // - s16: `Rd=#s16` の bits{23:22}+{20:16}+{13:5}。
    // - ai16: `Rd=add(Rs,#s16)` の bits{27:21}+{13:5}。
    // - ui16: `Rx.[HL]=#u16` の bits{23:22}+{13:0}。
    // - ls11/ss11: `mem*(Rs+#s11:2)` の scaled 即値（load は
    //   bits{26:25}+{13:5}、store は bits{26:25}+{13}+{7:0}）。
    // - r22: jump/call の bits{24:16}+{13:1}、zfill 2。
    // Ref: SPEC-HEXAGON-PRM (V79).
    for (name, parts, zfill) in [
        ("diclass", vec![(31, 29), (13, 13)], 0),
        ("imm26", vec![(27, 16), (13, 0)], 0),
        // trap0(#u6) の分割即値（bits[10:8]+[4:2]）。
        ("tu6", vec![(10, 8), (4, 2)], 0),
        ("s16", vec![(23, 22), (20, 16), (13, 5)], 0),
        ("ai16", vec![(27, 21), (13, 5)], 0),
        ("ui16", vec![(23, 22), (13, 0)], 0),
        ("ls11", vec![(26, 25), (13, 5)], 2),
        ("ss11", vec![(26, 25), (13, 13), (7, 0)], 2),
        ("r22", vec![(24, 16), (13, 1)], 2),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Parts { parts, zfill },
        });
    }

    // duplex subinsn（13 ビット語）の桁。全グループ共通で
    // [7:4] がソース/ベース・[3:0] がデスティネーション/データの
    // 部分集合レジスタ桁（対レジスタは [2:0]）。
    // Ref: SPEC-HEXAGON-PRM (V79) sub-instructions.
    for (name, hi, lo) in [
        ("dxs", 7, 4),   // subinsn のソース/ベースレジスタ
        ("dxd", 3, 0),   // subinsn のデスティネーション/データレジスタ
        ("dxx", 3, 0),   // subinsn の Rx（ソース=デスティネーション）
        ("ddp", 2, 0),   // subinsn の対レジスタ（3 ビット）
        ("du3", 10, 8),  // u3 即値（h:1 系・b:0 系）
        ("du4h", 11, 8), // u4 即値（L1/S1 の w:2・ub:0 系）
        ("du4l", 3, 0),  // u4 即値（S2 のストア即値形）
        ("du5", 8, 4),   // u5 即値（r29 相対・allocframe）
        ("du5d", 7, 3),  // u5 即値（L2 memd r29 相対）
        ("ds6", 8, 3),   // s6 即値（S2 memd r29 相対）
        ("du6", 9, 4),   // u6 即値（A の #u6・add(r29,#u6:2)）
        ("ds7", 10, 4),  // s7 即値（A の add(Rx,#s7)）
        ("du1", 8, 8),   // U1 即値（S2 のストア即値形の 0/1）
        ("du2a", 4, 3),  // u2 即値（combine の第 1 即値）
        ("du2b", 6, 5),  // U2 即値（combine の第 2 即値）
        ("du2c", 1, 0),  // u2 即値（cmp.eq の即値）
        ("dprd", 6, 4),  // 述語選択（A の条件クリア/`-1`）
        ("dprd3", 2, 0), // 述語選択（L2 の jumpr/dealloc_return）
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    let gpr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("gpr".to_string()),
        access,
    };
    let preg = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("pred".to_string()),
        access,
    };
    let creg = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("creg".to_string()),
        access,
    };
    let val = |name: &str, field: &str| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: None,
        access: Access::Read,
    };
    let fmt = |name: &str, fields: &[&str], operands: Vec<Operand>| Format {
        name: name.to_string(),
        fields: fields.iter().map(|s| s.to_string()).collect(),
        operands,
    };

    // ---- 32 ビット語の形式 ----
    // F32 は基底形（宣言のみ）、FEXT は constant extender 語。
    // Ref: SPEC-HEXAGON-PRM (V79) instruction encoding.
    m.formats.push(fmt("F32", &["iclass", "pp"], vec![]));
    m.formats.push(fmt(
        "FEXT",
        &["iclass", "pp", "imm26"],
        vec![val("imm", "imm26")],
    ));
    // nop（ALU32、オペランドなし）。
    m.formats.push(fmt("FN", &["pp"], vec![]));
    // Rd = add(Rs,#s16)。
    m.formats.push(fmt(
        "FRI16",
        &["s5", "d5", "ai16"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "ai16"),
        ],
    ));
    // Rd = add(Rs,Rt)（代表の 3 項形）。
    m.formats.push(fmt(
        "FRR",
        &["s5", "t5", "d5"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
        ],
    ));
    // Rd = #s16。
    m.formats.push(fmt(
        "FS16",
        &["d5", "s16"],
        vec![gpr("d", "d5", Access::Write), val("imm", "s16")],
    ));
    // Rd = Rs。
    m.formats.push(fmt(
        "FRS",
        &["s5", "d5"],
        vec![gpr("d", "d5", Access::Write), gpr("s", "s5", Access::Read)],
    ));
    // Rx.[HL] = #u16。
    m.formats.push(fmt(
        "FX16",
        &["x5", "ui16"],
        vec![gpr("x", "x5", Access::ReadWrite), val("imm", "ui16")],
    ));
    // Rd = memw(Rs+#s11:2)。
    m.formats.push(fmt(
        "FLDW",
        &["s5", "d5", "ls11"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "ls11"),
        ],
    ));
    // memw(Rs+#s11:2) = Rt。
    m.formats.push(fmt(
        "FSTW",
        &["s5", "t5", "ss11"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            val("imm", "ss11"),
        ],
    ));
    // jump/call の PC 相対形。
    m.formats.push(fmt("FJ", &["r22"], vec![val("target", "r22")]));
    // trap0(#u6)。
    m.formats.push(fmt("FTRAP", &["tu6"], vec![val("u", "tu6")]));
    // jumpr/callr のレジスタ形。
    m.formats.push(fmt(
        "FJR",
        &["s5"],
        vec![gpr("s", "s5", Access::Read)],
    ));
    // Rd = Cs。
    m.formats.push(fmt(
        "FRDC",
        &["c5", "d5"],
        vec![gpr("d", "d5", Access::Write), creg("c", "c5", Access::Read)],
    ));
    // Cd = Rs。
    m.formats.push(fmt(
        "FWRC",
        &["s5", "d5"],
        vec![creg("d", "d5", Access::Write), gpr("s", "s5", Access::Read)],
    ));
    // Pd = cmp.eq/gt(Rs,Rt)。
    m.formats.push(fmt(
        "FCMP",
        &["s5", "t5", "pd2"],
        vec![
            preg("d", "pd2", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
        ],
    ));

    // ---- duplex subinsn（13 ビット語）の形式 ----
    // 構文の {dxs}/{dxd}/{dxx}/{ddp} は subinsn レジスタ符号
    // （r0–r7→0–7、r16–r23→8–15、対は 3 ビット）をそのまま出す。
    let dxrd = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: None,
        access,
    };
    let dx = |name: &str, fields: &[&str], operands: Vec<Operand>| Format {
        name: name.to_string(),
        fields: fields.iter().map(|s| s.to_string()).collect(),
        operands,
    };
    // L1/S1 共通: u4 + base + dst。
    m.formats.push(dx(
        "DXLD",
        &["du4h", "dxs", "dxd"],
        vec![
            dxrd("d", "dxd", Access::Write),
            dxrd("s", "dxs", Access::Read),
            val("u", "du4h"),
        ],
    ));
    // S1 共通: u4 + base + data（DXLD と同じ桁だが {t} は
    // 読み出しのソース）。
    m.formats.push(dx(
        "DXS1",
        &["du4h", "dxs", "dxd"],
        vec![
            dxrd("s", "dxs", Access::Read),
            dxrd("t", "dxd", Access::Read),
            val("u", "du4h"),
        ],
    ));
    // L2 の h:1・b:0 系: u3 + base + dst。
    m.formats.push(dx(
        "DXL2",
        &["du3", "dxs", "dxd"],
        vec![
            dxrd("d", "dxd", Access::Write),
            dxrd("s", "dxs", Access::Read),
            val("u", "du3"),
        ],
    ));
    // r29 相対の u5 + dst。
    m.formats.push(dx(
        "DXSP",
        &["du5", "dxd"],
        vec![dxrd("d", "dxd", Access::Write), val("u", "du5")],
    ));
    // r29 相対の対 load（u5:3 + ddp）。
    m.formats.push(dx(
        "DXMD",
        &["du5d", "ddp"],
        vec![dxrd("dd", "ddp", Access::Write), val("u", "du5d")],
    ));
    // フレーム/リターン系（deallocframe・jumpr・dealloc_return。
    // 述語選択桁 dprd3: 0=無条件、4=p0、5=!p0、6=p0.new、7=!p0.new）。
    m.formats.push(dx("DXFR", &["dprd3"], vec![val("pred", "dprd3")]));
    // S2 共通: u3 + base + data。
    m.formats.push(dx(
        "DXST",
        &["du3", "dxs", "dxd"],
        vec![
            dxrd("s", "dxs", Access::Read),
            dxrd("t", "dxd", Access::Read),
            val("u", "du3"),
        ],
    ));
    // S2 r29 相対: u5 + data。
    m.formats.push(dx(
        "DXSSP",
        &["du5", "dxd"],
        vec![dxrd("t", "dxd", Access::Read), val("u", "du5")],
    ));
    // S2 r29 相対の対 store（s6:3 + ddp）。
    m.formats.push(dx(
        "DXSMD",
        &["ds6", "ddp"],
        vec![dxrd("tt", "ddp", Access::Read), val("i", "ds6")],
    ));
    // S2 ストア即値形: U1 + base + u4。
    m.formats.push(dx(
        "DXSI",
        &["du1", "dxs", "du4l"],
        vec![dxrd("s", "dxs", Access::Read), val("u4", "du4l"), val("i", "du1")],
    ));
    // allocframe(#u5:3)。
    m.formats.push(dx("DXAF", &["du5"], vec![val("u", "du5")]));
    // A: add(Rx,#s7)。
    m.formats.push(dx(
        "DXAI",
        &["ds7", "dxx"],
        vec![dxrd("x", "dxx", Access::ReadWrite), val("s", "ds7")],
    ));
    // A: Rd=#u6 / add(r29,#u6:2)。
    m.formats.push(dx(
        "DXU6",
        &["du6", "dxd"],
        vec![dxrd("d", "dxd", Access::Write), val("u", "du6")],
    ));
    // A: レジスタ形（Rd=Rs・add/sub/and/sxt/zxt 系、Rx=add(Rx,Rs)）。
    m.formats.push(dx(
        "DXRR",
        &["dxs", "dxd"],
        vec![
            dxrd("d", "dxd", Access::Write),
            dxrd("s", "dxs", Access::Read),
        ],
    ));
    // A: cmp.eq(Rs,#u2)（述語デスティネーションは p0 固定）。
    m.formats.push(dx(
        "DXCE",
        &["dxs", "du2c"],
        vec![dxrd("s", "dxs", Access::Read), val("u", "du2c")],
    ));
    // A: 条件クリア（dprd: 0=Rd=#-1、4=p0.new、5=!p0.new、6=p0、7=!p0）。
    m.formats.push(dx(
        "DXCL",
        &["dprd", "dxd"],
        vec![dxrd("d", "dxd", Access::Write), val("pred", "dprd")],
    ));
    // A: combine(#u2,#U2)。
    m.formats.push(dx(
        "DXCI",
        &["du2b", "du2a", "ddp"],
        vec![
            dxrd("dd", "ddp", Access::Write),
            val("ua", "du2a"),
            val("ub", "du2b"),
        ],
    ));
    // A: combine(#0,Rs)/combine(Rs,#0)。
    m.formats.push(dx(
        "DXCR",
        &["dxs", "ddp"],
        vec![dxrd("dd", "ddp", Access::Write), dxrd("s", "dxs", Access::Read)],
    ));

    let ins = |name: &str, format: &str, pattern: &str, when: Pred, syntax: &str, timing: &str| {
        Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        }
    };
    let base = || Pred::True;
    let wl1 = || Pred::Flag("dx_l1".to_string());
    let wl2 = || Pred::Flag("dx_l2".to_string());
    let ws1 = || Pred::Flag("dx_s1".to_string());
    let ws2 = || Pred::Flag("dx_s2".to_string());
    let wa = || Pred::Flag("dx_a".to_string());

    // ---- 32 ビット命令（HX3 の代表形式）。
    // ICLASS → クラス/スロットの対応:
    //   0000=extender, 0001/0010/0101=J{2,3}（ICLASS5 の間接系は
    //   JR{2}）, 0011/0100=LDST{0,1}, 0110=CR{3},
    //   0111/1011/1111=ALU32{0-3},
    //   1000/1100/1101/1110=XTYPE{2,3}, 1001=LD{0,1}, 1010=ST{0}
    //   （dual store / slot1 store+slot0 load 形では slot1）。
    // Ref: SPEC-HEXAGON-PRM (V79) Table: instruction class encoding.
    for (name, format, pattern, syntax, timing) in [
        // constant extender 語（ICLASS=0、実行スロットを消費しない。
        // disasm では immext と出る）。Ref: Table: constant extender.
        ("immext", "FEXT", "0000............................", "immext #{imm}", "misc"),
        // nop。Ref: ALU32 nop.
        ("nop", "FN", "01111111........ ................", "nop", "alu"),
        // Rd = add(Rs,#s16)。Ref: ALU32 add.
        ("add_ri", "FRI16", "1011............................", "add {d},{s},#{imm}", "alu"),
        // Rd = add(Rs,Rt)。Ref: ALU32 add.
        ("add_rr", "FRR", "11110011000.....................", "add {d},{s},{t}", "alu"),
        // Rd = #s16。Ref: ALU32 transfer immediate.
        ("eq_s16", "FS16", "01111000........................", "{d}=#{imm}", "alu"),
        // Rd = Rs。Ref: ALU32 transfer register.
        ("mov_rr", "FRS", "01110000011.......0.............", "{d}={s}", "alu"),
        // Rx.L = #u16 / Rx.H = #u16。Ref: ALU32 transfer immediate.
        ("immlo", "FX16", "01110001........................", "{x}.l=#{imm}", "alu"),
        ("immhi", "FX16", "01110010........................", "{x}.h=#{imm}", "alu"),
        // Rd = memw(Rs+#s11:2)。Ref: LD load word.
        ("ldw_ri", "FLDW", "10010..1100.....................", "{d}=memw({s}+#{imm})", "load"),
        // memw(Rs+#s11:2) = Rt。Ref: ST store word.
        ("stw_ri", "FSTW", "10100..1100.....................", "memw({s}+#{imm})={t}", "store"),
        // jump/call の PC 相対形。Ref: J jump/call.
        ("jump_pcrel", "FJ", "0101100.........................", "jump #{target}", "branch"),
        ("call_pcrel", "FJ", "0101101........................0", "call #{target}", "branch"),
        // jumpr/callr のレジスタ形。Ref: J indirect jump/call.
        ("jumpr", "FJR", "01010010100.....................", "jumpr {s}", "branch"),
        ("callr", "FJR", "01010000101.....................", "callr {s}", "branch"),
        // trap0(#u6)。ユーザモードの #1 が OS 呼出し。trap1/2 は
        // 特権でユーザ範囲外（HX7 で範囲を確定）。
        // Ref: system instructions.
        ("trap0", "FTRAP", "01010100000.....................", "trap0(#{u})", "system"),
        // Rd = Cs / Cd = Rs。Ref: CR control register transfer.
        ("rdcr", "FRDC", "01101010000.....................", "{d}=c{c}", "system"),
        ("wrcr", "FWRC", "01100010001.....................", "c{d}={s}", "system"),
        // Pd = cmp.eq/gt(Rs,Rt)。Ref: ALU32 compare.
        ("cmpeq_rr", "FCMP", "11110010000.............000000..", "p{d}=cmp.eq({s},{t})", "alu"),
        ("cmpgt_rr", "FCMP", "11110010010.............000000..", "p{d}=cmp.gt({s},{t})", "alu"),
    ] {
        m.insns.push(ins(name, format, pattern, base(), syntax, timing));
    }

    // ---- duplex subinsn（13 ビット語）。
    // 各命令の `when` は subinsn のグループに対応する文脈旗。
    // Ref: SPEC-HEXAGON-PRM (V79) sub-instructions / duplex encoding.
    for (name, format, pattern, when, syntax, timing) in [
        // L1: u4 + base + dst。bit12=0 は w:2、1 は ub:0。
        ("dx_l1_memw", "DXLD", "0............", wl1(), "{d}=memw({s}+#{u}:2)", "load"),
        ("dx_l1_memub", "DXLD", "1............", wl1(), "{d}=memub({s}+#{u}:0)", "load"),
        // L2: [12:11]=00 memh、01 memuh、10 memb。u3 は h:1・b:0。
        ("dx_l2_memh", "DXL2", "00...........", wl2(), "{d}=memh({s}+#{u}:1)", "load"),
        ("dx_l2_memuh", "DXL2", "01...........", wl2(), "{d}=memuh({s}+#{u}:1)", "load"),
        ("dx_l2_memb", "DXL2", "10...........", wl2(), "{d}=memb({s}+#{u}:0)", "load"),
        // L2: r29 相対。
        ("dx_l2_ldwsp", "DXSP", "1110.........", wl2(), "{d}=memw(r29+#{u}:2)", "load"),
        ("dx_l2_lddsp", "DXMD", "11110........", wl2(), "{dd}=memd(r29+#{u}:3)", "load"),
        // L2: フレーム/リターン。dprd3: 0=無条件、4/5=p0/!p0、
        // 6/7=p0.new/!p0.new（実符号と照合済み）。
        ("dx_l2_deallocframe", "DXFR", "1111100000...", wl2(), "deallocframe", "alu"),
        ("dx_l2_deallocret", "DXFR", "1111101......", wl2(), "dealloc_return:{pred}", "branch"),
        ("dx_l2_jumpr", "DXFR", "1111111......", wl2(), "jumpr31:{pred}", "branch"),
        // S1: u4 + base + data。bit12=0 は w:2、1 は b:0。
        ("dx_s1_memw", "DXS1", "0............", ws1(), "memw({s}+#{u}:2)={t}", "store"),
        ("dx_s1_memb", "DXS1", "1............", ws1(), "memb({s}+#{u}:0)={t}", "store"),
        // S2: [12:11]=00 memh。u3 は h:1。
        ("dx_s2_memh", "DXST", "00...........", ws2(), "memh({s}+#{u}:1)={t}", "store"),
        // S2: r29 相対。
        ("dx_s2_stwsp", "DXSSP", "0100.........", ws2(), "memw(r29+#{u}:2)={t}", "store"),
        ("dx_s2_stdsp", "DXSMD", "0101.........", ws2(), "memd(r29+#{i}:3)={tt}", "store"),
        // S2: ストア即値形。bit9=0 は w:2、1 は b:0。
        ("dx_s2_stwi", "DXSI", "1000.........", ws2(), "memw({s}+#{u4}:2)=#{i}", "store"),
        ("dx_s2_stbi", "DXSI", "1001.........", ws2(), "memb({s}+#{u4}:0)=#{i}", "store"),
        // S2: allocframe。
        ("dx_s2_allocframe", "DXAF", "1110.........", ws2(), "allocframe(#{u}:3)", "store"),
        // A: [12:11]=00 add(Rx,#s7)。
        ("dx_a_addi", "DXAI", "00...........", wa(), "add({x},{x},#{s})", "alu"),
        // A: [12:10]=010 Rd=#u6、011 add(r29,#u6:2)。
        ("dx_a_uimm", "DXU6", "010..........", wa(), "{d}=#{u}", "alu"),
        ("dx_a_spadd", "DXU6", "011..........", wa(), "{d}=add(r29,#{u}:2)", "alu"),
        // A: bit12=1 のレジスタ/即値形。[11:8] が副オペコード。
        ("dx_a_mov", "DXRR", "10000........", wa(), "{d}={s}", "alu"),
        ("dx_a_add1", "DXRR", "10001........", wa(), "{d}=add({s},#1)", "alu"),
        ("dx_a_and1", "DXRR", "10010........", wa(), "{d}=and({s},#1)", "alu"),
        ("dx_a_sub1", "DXRR", "10011........", wa(), "{d}=add({s},#-1)", "alu"),
        ("dx_a_sxth", "DXRR", "10100........", wa(), "{d}=sxth({s})", "alu"),
        ("dx_a_sxtb", "DXRR", "10101........", wa(), "{d}=sxtb({s})", "alu"),
        ("dx_a_zxth", "DXRR", "10110........", wa(), "{d}=zxth({s})", "alu"),
        ("dx_a_zxtb", "DXRR", "10111........", wa(), "{d}=zxtb({s})", "alu"),
        ("dx_a_addr", "DXRR", "11000........", wa(), "add({d},{d},{s})", "alu"),
        ("dx_a_cmpeq", "DXCE", "11001....00..", wa(), "p0=cmp.eq({s},#{u})", "alu"),
        // A: 条件クリア/`-1`。dprd: 0=Rd=#-1、4/5=p0.new/!p0.new、
        // 6/7=p0/!p0（実符号と照合済み）。bit7=0 固定。
        ("dx_a_clr", "DXCL", "110100.......", wa(), "clr:{pred} {d}", "alu"),
        // A: combine 系。11100=#u2/#U2、11101=#0/Rs(bit3=0)・Rs/#0(bit3=1)。
        ("dx_a_combi", "DXCI", "11100........", wa(), "{dd}=combine(#{ua},#{ub})", "alu"),
        ("dx_a_comb0", "DXCR", "11101....0...", wa(), "{dd}=combine(#0,{s})", "alu"),
        ("dx_a_comb1", "DXCR", "11101....1...", wa(), "{dd}=combine({s},#0)", "alu"),
    ] {
        m.insns.push(ins(name, format, pattern, when, syntax, timing));
    }

    // `Rd = #-1`（条件クリアの無条件形）は dx_a_clr の dprd=0 に
    // 畳まれる（符号化上は同一命令の述語選択桁の一値）。
    // dealloc_return の dprd3: 0=無条件、4/5=p0/!p0、6/7=p0.new。
    for insn in m.insns.iter_mut() {
        // deallocframe に述語選択はない。dprd3 桁（と上位の未使用
        // 桁）は 0 固定。
        if insn.name == "dx_l2_deallocframe" {
            insn.wheres.push(WhereClause {
                field: "dprd3".to_string(),
                op: WhereOp::Eq,
                rhs: WhereRhs::Lit(0),
            });
        }
        // dealloc_return の述語選択桁は 1/2/3 が未割当。
        if insn.name == "dx_l2_deallocret" {
            for bad in [1u128, 2, 3] {
                insn.wheres.push(WhereClause {
                    field: "dprd3".to_string(),
                    op: WhereOp::Ne,
                    rhs: WhereRhs::Lit(bad),
                });
            }
        }
        // 条件クリアの述語選択桁（dprd: 0=無条件、4/5=p0.new/
        // !p0.new、6/7=p0/!p0）は 1/2/3 が未割当なので拒否する。
        if insn.name == "dx_a_clr" {
            for bad in [1u128, 2, 3] {
                insn.wheres.push(WhereClause {
                    field: "dprd".to_string(),
                    op: WhereOp::Ne,
                    rhs: WhereRhs::Lit(bad),
                });
            }
        }
        // jumpr R31 の述語選択桁（dprd3: 0=無条件、4/5=p0/!p0、
        // 6/7=p0.new）は 1/2/3 を拒否する。
        if insn.name == "dx_l2_jumpr" {
            for bad in [1u128, 2, 3] {
                insn.wheres.push(WhereClause {
                    field: "dprd3".to_string(),
                    op: WhereOp::Ne,
                    rhs: WhereRhs::Lit(bad),
                });
            }
        }
    }

    m
}
