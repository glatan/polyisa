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
        // ---- HX5: 整数語彙の追加桁 ----
        ("ps2", 17, 16), // 述語ソース Ps（P 演算、bits[17:16]）
        ("pt2", 9, 8),   // 述語ソース Pt（P 演算、bits[9:8]）
        ("pu2b", 7, 6),  // 述語ソース Pu（3 入力 P 演算）
        ("pu2", 6, 5),   // 述語選択/キャリー Px（mux・carry・valignb 等）
        ("pu2i", 22, 21), // mux 即値系の Pu
        ("pu2j", 24, 23), // mux(#s8,#S8) の Pu
        ("psx", 17, 16), // Rd = Ps の Ps
        ("rx5", 4, 0),   // 累積/破壊的更新の Rx・insert/tableidx/add3 の宛先やソース
        ("iu6", 13, 8),  // u6/s6 即値（64 ビットシフト・bitsclr・tableidx・add(clb,#s6)）
        ("xu3", 7, 5),   // u3 即値（addasl・valignb・vspliceb）
        ("ai8", 12, 5),  // 8 ビット即値（combine・mux・cmpb/cmph・累積・cmp.eq→Rd）
        ("iu9", 13, 5),  // 9 ビット即値（cmp.gtu #u9）
        ("pc6", 12, 7),  // add(pc,#u6) の u6
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
        // ---- HX5: 分割即値 ----
        // ai10: ICLASS7 系の s10/u9（bits{21}+{13:5}）。
        ("ai10", vec![(21, 21), (13, 5)], 0),
        // cs8: combine(#s8,#S8) の第 2 即値（bits{22:16}+{13}）。
        ("cs8", vec![(22, 16), (13, 13)], 0),
        // cu6: combine(#s8,#U6) の第 2 即値（bits{21:16}+{13}）。
        ("cu6", vec![(21, 16), (13, 13)], 0),
        // xtu4: tableidx の u4（bits{21}+{7:5}）。
        ("xtu4", vec![(21, 21), (7, 5)], 0),
        // xw5/xw6: extract/insert の幅（32 ビットは
        // bits{22:21}+{7:5}、64 ビットは bits{23:21}+{7:5}）。
        ("xw5", vec![(22, 21), (7, 5)], 0),
        ("xw6", vec![(23, 21), (7, 5)], 0),
        // xa6: add(Rs,add(Ru,#s6)) 系の s6（bits{22:21}+{13}+{7:5}）。
        ("xa6", vec![(22, 21), (13, 13), (7, 5)], 0),
        // xu8: add/sub/and/or(#u8,{asl,lsr}(Rx,#U5)) の u8
        // （bits{23:21}+{13}+{7:5}+{3}）。
        ("xu8", vec![(23, 21), (13, 13), (7, 5), (3, 3)], 0),
        // lsl6: lsl(#s6,Rt) の s6（bits{20:16}+{5}）。
        ("lsl6", vec![(20, 16), (5, 5)], 0),
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

    // ---- HX5 形式 ----
    // mux/valignb/vspliceb/vmux/carry の述語選択付き 3 項形。
    m.formats.push(fmt(
        "FMUX",
        &["s5", "t5", "d5", "pu2"],
        vec![
            gpr("d", "d5", Access::Write),
            preg("p", "pu2", Access::Read),
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
        ],
    ));
    // mux(Pu,Rs,#s8) / mux(Pu,#s8,Rs)。
    m.formats.push(fmt(
        "FMUXI",
        &["s5", "d5", "ai8", "pu2i"],
        vec![
            gpr("d", "d5", Access::Write),
            preg("p", "pu2i", Access::Read),
            gpr("s", "s5", Access::Read),
            val("imm", "ai8"),
        ],
    ));
    // mux(Pu,#s8,#S8)（第 2 即値は bits{22:16}+{13} の cs8）。
    m.formats.push(fmt(
        "FMUXII",
        &["d5", "ai8", "cs8", "pu2j"],
        vec![
            gpr("d", "d5", Access::Write),
            preg("p", "pu2j", Access::Read),
            val("imm1", "ai8"),
            val("imm2", "cs8"),
        ],
    ));
    // Rd = op(Rs,#i8) 系（combine・Rd=cmp.eq・mux の共用骨格）。
    m.formats.push(fmt(
        "FRI8",
        &["s5", "d5", "ai8"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "ai8"),
        ],
    ));
    // Rdd = combine(#s8,#S8)。
    m.formats.push(fmt(
        "FCII",
        &["d5", "ai8", "cs8"],
        vec![
            gpr("d", "d5", Access::Write),
            val("imm1", "ai8"),
            val("imm2", "cs8"),
        ],
    ));
    // Rdd = combine(#s8,#U6)。
    m.formats.push(fmt(
        "FCU6",
        &["d5", "ai8", "cu6"],
        vec![
            gpr("d", "d5", Access::Write),
            val("imm1", "ai8"),
            val("imm2", "cu6"),
        ],
    ));
    // Rd = and/or/sub(#s10 or Rs,#s10)（ICLASS7 の s10 系）。
    m.formats.push(fmt(
        "FRI10",
        &["s5", "d5", "ai10"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "ai10"),
        ],
    ));
    // Pd = cmp.*(Rs,#imm)（s10 系と u9 系）。
    m.formats.push(fmt(
        "FCMPI",
        &["s5", "pd2", "ai10"],
        vec![
            preg("d", "pd2", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "ai10"),
        ],
    ));
    m.formats.push(fmt(
        "FCMPIU",
        &["s5", "pd2", "iu9"],
        vec![
            preg("d", "pd2", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "iu9"),
        ],
    ));
    // Pd = cmpb/cmph.*(Rs,#u8 or #s8)。
    m.formats.push(fmt(
        "FCMPBI",
        &["s5", "pd2", "ai8"],
        vec![
            preg("d", "pd2", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "ai8"),
        ],
    ));
    // Rx op= op(Rs,Rt) / Rx=insert(Rs,Rtt) 等の破壊的 3 項形
    // （Rx は bits[4:0]）。
    m.formats.push(fmt(
        "FXRR",
        &["s5", "t5", "rx5"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
        ],
    ));
    // Rx op= op(Rs,#i8)。
    m.formats.push(fmt(
        "FXI8",
        &["s5", "rx5", "ai8"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            val("imm", "ai8"),
        ],
    ));
    // Rx op= op(Rs,#s10)。
    m.formats.push(fmt(
        "FXI10",
        &["s5", "rx5", "ai10"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            val("imm", "ai10"),
        ],
    ));
    // Rx op= shift(Rs,#u5)。
    m.formats.push(fmt(
        "FXSH",
        &["s5", "t5", "rx5"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            val("imm", "t5"),
        ],
    ));
    // Rxx op= shift(Rss,#u6)。
    m.formats.push(fmt(
        "FXSH6",
        &["s5", "rx5", "iu6"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            val("imm", "iu6"),
        ],
    ));
    // Rd = addasl(Rt,Rs,#u3) 系（シフト付き加算）と
    // valignb/vspliceb の #u3 形。
    m.formats.push(fmt(
        "FASL3",
        &["s5", "t5", "d5", "xu3"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            val("imm", "xu3"),
        ],
    ));
    // 単項形の即値添え（add(clb(Rs),#s6)）。
    m.formats.push(fmt(
        "FCLADD",
        &["s5", "d5", "iu6"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "iu6"),
        ],
    ));
    // extract/insert の幅・オフセット即値形。
    m.formats.push(fmt(
        "FXTR",
        &["s5", "d5", "t5", "xw5"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("width", "t5"),
            val("off", "xw5"),
        ],
    ));
    m.formats.push(fmt(
        "FXTR64",
        &["s5", "d5", "iu6", "xw6"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("width", "iu6"),
            val("off", "xw6"),
        ],
    ));
    m.formats.push(fmt(
        "FINS",
        &["s5", "rx5", "t5", "xw5"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            val("width", "t5"),
            val("off", "xw5"),
        ],
    ));
    m.formats.push(fmt(
        "FINS64",
        &["s5", "rx5", "iu6", "xw6"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            val("width", "iu6"),
            val("off", "xw6"),
        ],
    ));
    // Rx = tableidx(Rs,#u4,#S6)。
    m.formats.push(fmt(
        "FTIDX",
        &["s5", "rx5", "xtu4", "iu6"],
        vec![
            gpr("x", "rx5", Access::ReadWrite),
            gpr("s", "s5", Access::Read),
            val("imm", "xtu4"),
            val("off", "iu6"),
        ],
    ));
    // Rd = add/sub(Rs,add/sub(Ru,#s6))（Rd が bits[12:8]、
    // Ru が bits[4:0]、s6 は分割即値）。
    m.formats.push(fmt(
        "FADD3",
        &["s5", "t5", "rx5", "xa6"],
        vec![
            gpr("d", "t5", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("u", "rx5", Access::Read),
            val("imm", "xa6"),
        ],
    ));
    // Rx = or(Ru,and(Rx,#s10))。
    m.formats.push(fmt(
        "FOAC",
        &["x5", "rx5", "ai10"],
        vec![
            gpr("x", "x5", Access::ReadWrite),
            gpr("u", "rx5", Access::Read),
            val("imm", "ai10"),
        ],
    ));
    // Rx = add/sub/and/or(#u8,{asl,lsr}(Rx,#U5))。
    m.formats.push(fmt(
        "FSHIMM",
        &["x5", "t5", "xu8"],
        vec![
            gpr("x", "x5", Access::ReadWrite),
            val("ushift", "t5"),
            val("imm", "xu8"),
        ],
    ));
    // Rd = lsl(#s6,Rt)。
    m.formats.push(fmt(
        "FLSL",
        &["d5", "t5", "lsl6"],
        vec![
            gpr("d", "d5", Access::Write),
            val("imm", "lsl6"),
            gpr("t", "t5", Access::Read),
        ],
    ));
    // Rd = add(pc,#u6)。
    m.formats.push(fmt(
        "FPC6",
        &["d5", "pc6"],
        vec![gpr("d", "d5", Access::Write), val("imm", "pc6")],
    ));

    // Rd = shift(Rs,#u5) / Rd=setbit(Rs,#u5) 等の u5 即値形。
    m.formats.push(fmt(
        "FSHI",
        &["s5", "d5", "t5"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "t5"),
        ],
    ));
    // Rdd = shift(Rss,#u6) / Pd=bitsclr(Rs,#u6) の u6 即値形。
    m.formats.push(fmt(
        "FSHI6",
        &["s5", "d5", "iu6"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "iu6"),
        ],
    ));
    // Pd = tstbit(Rs,#u5) 系（述語デスティネーション + u5）。
    m.formats.push(fmt(
        "FPTST",
        &["s5", "pd2", "t5"],
        vec![
            preg("d", "pd2", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "t5"),
        ],
    ));
    // Pd = bitsclr(Rs,#u6) 系。
    m.formats.push(fmt(
        "FPCLR",
        &["s5", "pd2", "iu6"],
        vec![
            preg("d", "pd2", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "iu6"),
        ],
    ));
    // Pd = and/or/xor(Ps,Pt) の 2 入力述語形。
    m.formats.push(fmt(
        "FP3",
        &["ps2", "pt2", "pd2"],
        vec![
            preg("d", "pd2", Access::Write),
            preg("s", "ps2", Access::Read),
            preg("t", "pt2", Access::Read),
        ],
    ));
    // Pd = and/or(Ps,and/or(Pt,Pu)) の 3 入力述語形。
    m.formats.push(fmt(
        "FP4",
        &["ps2", "pt2", "pu2b", "pd2"],
        vec![
            preg("d", "pd2", Access::Write),
            preg("s", "ps2", Access::Read),
            preg("t", "pt2", Access::Read),
            preg("u", "pu2b", Access::Read),
        ],
    ));
    // Pd = not(Ps)。
    m.formats.push(fmt(
        "FPN",
        &["ps2", "pd2"],
        vec![
            preg("d", "pd2", Access::Write),
            preg("s", "ps2", Access::Read),
        ],
    ));
    // Rd = Ps。
    m.formats.push(fmt(
        "FRFP",
        &["psx", "d5"],
        vec![
            gpr("d", "d5", Access::Write),
            preg("s", "psx", Access::Read),
        ],
    ));
    // Pd = Rs。
    m.formats.push(fmt(
        "FPRF",
        &["s5", "pd2"],
        vec![
            preg("d", "pd2", Access::Write),
            gpr("s", "s5", Access::Read),
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

    // ---- HX5: 整数算術・論理・シフト・combine/mux 系。
    // ALU32/XTYPE の加減算・論理・半語演算、64 ビット対レジスタ
    // 演算、述語生産比較・述語演算、シフト/ローテートとその累積形、
    // ビット計数・ビットフィールド・テーブルビット、飽和/パック系、
    // combine/mux/min/max、整列/交差/複製のスカラベクトル系。
    // 語彙は V79 正本のビットマップから機械抽出し、参照
    // アセンブラの実符号と照合済み。
    // Ref: SPEC-HEXAGON-PRM (V79) ALU32/XTYPE/PERM/PRED/BIT chapters.
    for (name, format, pattern, syntax, timing) in [
        ("add_sat_rr", "FRR", "11110110010.....................", "add {d},{s},{t}:sat", "alu"),
        ("and_rr", "FRR", "11110001000.....................", "and {d},{s},{t}", "alu"),
        ("andn2_rr", "FRR", "11110001100.....................", "and {t},~{s}", "alu"),
        ("or_rr", "FRR", "11110001001.....................", "or {d},{s},{t}", "alu"),
        ("orn2_rr", "FRR", "11110001101.....................", "or {t},~{s}", "alu"),
        ("xor_rr", "FRR", "11110001011.....................", "xor {d},{s},{t}", "alu"),
        ("sub_rr", "FRR", "11110011001.....................", "sub {t},{s}", "alu"),
        ("sub_sat_rr", "FRR", "11110110110.....................", "sub {t},{s}:sat", "alu"),
        ("vaddh_rr", "FRR", "11110110000.....................", "vaddh {d},{s},{t}", "alu"),
        ("vaddh_sat_rr", "FRR", "11110110001.....................", "vaddh {d},{s},{t}:sat", "alu"),
        ("vadduh_sat_rr", "FRR", "11110110011.....................", "vadduh {d},{s},{t}:sat", "alu"),
        ("vavgh_rr", "FRR", "11110111.00.....................", "vavgh {d},{s},{t}", "alu"),
        ("vavgh_rnd_rr", "FRR", "11110111.01.....................", "vavgh {d},{s},{t}:rnd", "alu"),
        ("vnavgh_rr", "FRR", "11110111.11.....................", "vnavgh {t},{s}", "alu"),
        ("vsubh_rr", "FRR", "11110110100.....................", "vsubh {t},{s}", "alu"),
        ("vsubh_sat_rr", "FRR", "11110110101.....................", "vsubh {t},{s}:sat", "alu"),
        ("vsubuh_sat_rr", "FRR", "11110110111.....................", "vsubuh {t},{s}:sat", "alu"),
        ("and_ri", "FRI10", "0111011000......................", "and {d},{s},#{imm}", "alu"),
        ("or_ri", "FRI10", "0111011010......................", "or {d},{s},#{imm}", "alu"),
        ("sub_ir", "FRI10", "0111011001......................", "sub #{imm},{s}", "alu"),
        ("aslh", "FRS", "01110000000.......0.............", "aslh {d},{s}", "alu"),
        ("asrh", "FRS", "01110000001.......0.............", "asrh {d},{s}", "alu"),
        ("sxtb", "FRS", "01110000101.......0.............", "sxtb {d},{s}", "alu"),
        ("sxth", "FRS", "01110000111.......0.............", "sxth {d},{s}", "alu"),
        ("zxth", "FRS", "01110000110.......0.............", "zxth {d},{s}", "alu"),
        ("combine_rr", "FRR", "111101010.......................", "combine {dd},{s},{t}", "alu"),
        ("comb_hh", "FRR", "11110011100.....................", "combine {d},{t}.h,{s}.h", "alu"),
        ("comb_hl", "FRR", "11110011101.....................", "combine {d},{t}.h,{s}.l", "alu"),
        ("comb_lh", "FRR", "11110011110.....................", "combine {d},{t}.l,{s}.h", "alu"),
        ("comb_ll", "FRR", "11110011111.....................", "combine {d},{t}.l,{s}.l", "alu"),
        ("packhl", "FRR", "111101011.......................", "packhl {dd},{s},{t}", "alu"),
        ("comb_ri", "FRI8", "01110011.00.......1.............", "combine {dd},{s},#{imm}", "alu"),
        ("comb_ir", "FRI8", "01110011.01.......1.............", "combine {dd},#{imm},{s}", "alu"),
        ("comb_ii", "FCII", "011111000.......................", "combine {dd},#{imm1},#{imm2}", "alu"),
        ("comb_iu6", "FCU6", "011111001.......................", "combine {dd},#{imm1},#{imm2}", "alu"),
        ("mux_rr", "FMUX", "11110100........................", "mux p{p},{s},{t}", "alu"),
        ("mux_ri", "FMUXI", "011100110.........0.............", "mux p{p},{s},#{imm}", "alu"),
        ("mux_ir", "FMUXI", "011100111.........0.............", "mux p{p},#{imm},{s}", "alu"),
        ("mux_ii", "FMUXII", "0111101.........................", "mux p{p},#{imm1},#{imm2}", "alu"),
        ("cmpgtu_rr", "FCMP", "11110010.11................000..", "p{d}=cmp.gtu({s},{t})", "alu"),
        ("cmpeqn_rr", "FCMP", "11110010.00................100..", "p{d}=!cmp.eq({s},{t})", "alu"),
        ("cmpgtn_rr", "FCMP", "11110010.10................100..", "p{d}=!cmp.gt({s},{t})", "alu"),
        ("cmpgtun_rr", "FCMP", "11110010.11................100..", "p{d}=!cmp.gtu({s},{t})", "alu"),
        ("cmpeq_i", "FCMPI", "0111010100.................000..", "p{d}=cmp.eq({s},#{imm})", "alu"),
        ("cmpgt_i", "FCMPI", "0111010101.................000..", "p{d}=cmp.gt({s},#{imm})", "alu"),
        ("cmpgtu_i", "FCMPIU", "01110101100................000..", "p{d}=cmp.gtu({s},#{imm})", "alu"),
        ("cmpeqn_i", "FCMPI", "0111010100.................100..", "p{d}=!cmp.eq({s},#{imm})", "alu"),
        ("cmpgtn_i", "FCMPI", "0111010101.................100..", "p{d}=!cmp.gt({s},#{imm})", "alu"),
        ("cmpgtun_i", "FCMPIU", "01110101100................100..", "p{d}=!cmp.gtu({s},#{imm})", "alu"),
        ("cmpeq_rd_rr", "FRR", "11110011010.....................", "cmp.eq {d},{s},{t}", "alu"),
        ("cmpeqn_rd_rr", "FRR", "11110011011.....................", "!cmp.eq {d},{s},{t}", "alu"),
        ("cmpeq_rd_i", "FRI8", "01110011.10.......1.............", "cmp.eq {d},{s},#{imm}", "alu"),
        ("cmpeqn_rd_i", "FRI8", "01110011.11.......1.............", "!cmp.eq {d},{s},#{imm}", "alu"),
        ("pand", "FP3", "011010110000......0.............", "p{d}=and(p{t},p{s})", "alu"),
        ("por", "FP3", "011010110010......0.............", "p{d}=or(p{t},p{s})", "alu"),
        ("pxor", "FP3", "011010110100......0.............", "p{d}=xor(p{s},p{t})", "alu"),
        ("pandn", "FP3", "011010110110......0.............", "p{d}=and(p{t},!p{s})", "alu"),
        ("porn", "FP3", "011010111110......0.............", "p{d}=or(p{t},!p{s})", "alu"),
        ("pnot", "FPN", "011010111100......0.............", "p{d}=not(p{s})", "alu"),
        ("pany8", "FPN", "011010111000......0.............", "p{d}=any8(p{s})", "alu"),
        ("pall8", "FPN", "011010111010......0.............", "p{d}=all8(p{s})", "alu"),
        ("pfc9", "FP3", "01101011000000..111000..100100..", "p{d}=fastcorner9(p{s},p{t})", "alu"),
        ("pfc9n", "FP3", "01101011000100..111000..100100..", "p{d}=!fastcorner9(p{s},p{t})", "alu"),
        ("pand_a", "FP4", "011010110001......0.............", "p{d}=and(p{s},and(p{t},p{u}))", "alu"),
        ("pand_o", "FP4", "011010110011......0.............", "p{d}=and(p{s},or(p{t},p{u}))", "alu"),
        ("por_a", "FP4", "011010110101......0.............", "p{d}=or(p{s},and(p{t},p{u}))", "alu"),
        ("por_o", "FP4", "011010110111......0.............", "p{d}=or(p{s},or(p{t},p{u}))", "alu"),
        ("pand_an", "FP4", "011010111001......0.............", "p{d}=and(p{s},and(p{t},!p{u}))", "alu"),
        ("pand_on", "FP4", "011010111011......0.............", "p{d}=and(p{s},or(p{t},!p{u}))", "alu"),
        ("por_an", "FP4", "011010111101......0.............", "p{d}=or(p{s},and(p{t},!p{u}))", "alu"),
        ("por_on", "FP4", "011010111111......0.............", "p{d}=or(p{s},or(p{t},!p{u}))", "alu"),
        ("rd_ps", "FRFP", "10001001.1......................", "{d}=p{s}", "alu"),
        ("pd_rs", "FPRF", "10000101010.....................", "p{d}={s}", "alu"),
        ("add64", "FRR", "11010011000.............111.....", "add {dd},{ss},{tt}", "alu"),
        ("add64_sat", "FRR", "11010011011.............101.....", "add {dd},{ss},{tt}:sat", "alu"),
        ("add64_raw_lo", "FRR", "11010011011.............110.....", "add {dd},{ss},{tt}:raw:lo", "alu"),
        ("add64_raw_hi", "FRR", "11010011011.............111.....", "add {dd},{ss},{tt}:raw:hi", "alu"),
        ("sub64", "FRR", "11010011001.............111.....", "sub {dd},{tt},{ss}", "alu"),
        ("and64", "FRR", "11010011111.............000.....", "and {dd},{ss},{tt}", "alu"),
        ("andn64", "FRR", "11010011111.............001.....", "and {dd},{tt},~{ss}", "alu"),
        ("or64", "FRR", "11010011111.............010.....", "or {dd},{ss},{tt}", "alu"),
        ("orn64", "FRR", "11010011111.............011.....", "or {dd},{tt},~{ss}", "alu"),
        ("xor64", "FRR", "11010011111.............100.....", "xor {dd},{ss},{tt}", "alu"),
        ("not64", "FRS", "10000000100.............100.....", "not {dd},{ss}", "alu"),
        ("neg64", "FRS", "10000000100.............101.....", "neg {dd},{ss}", "alu"),
        ("abs64", "FRS", "10000000100.............110.....", "abs {dd},{ss}", "alu"),
        ("abs", "FRS", "10001100100.............100.....", "abs {d},{s}", "alu"),
        ("abs_sat", "FRS", "10001100100.............101.....", "abs {d},{s}:sat", "alu"),
        ("neg_sat", "FRS", "10001100100.............110.....", "neg {d},{s}:sat", "alu"),
        ("sxtw", "FRS", "1000010001..............00......", "sxtw {dd},{s}", "alu"),
        ("modwrap", "FRR", "11010011111.............111.....", "modwrap {d},{s},{t}", "alu"),
        ("add_carry", "FMUX", "11000010110.....................", "add {dd},{ss},{tt},p{p}:carry", "alu"),
        ("sub_carry", "FMUX", "11000010111.....................", "sub {dd},{ss},{tt},p{p}:carry", "alu"),
        ("max", "FRR", "11010101110.............0.......", "max {d},{s},{t}", "alu"),
        ("maxu", "FRR", "11010101110.............1.......", "maxu {d},{s},{t}", "alu"),
        ("min", "FRR", "11010101101.............0.......", "min {d},{t},{s}", "alu"),
        ("minu", "FRR", "11010101101.............1.......", "minu {d},{t},{s}", "alu"),
        ("max64", "FRR", "11010011110.............100.....", "max {dd},{ss},{tt}", "alu"),
        ("maxu64", "FRR", "11010011110.............101.....", "maxu {dd},{ss},{tt}", "alu"),
        ("min64", "FRR", "11010011101.............110.....", "min {dd},{tt},{ss}", "alu"),
        ("minu64", "FRR", "11010011101.............111.....", "minu {dd},{tt},{ss}", "alu"),
        ("cmp64_eq", "FCMP", "11010010100.............000.....", "p{d}=cmp.eq({ss},{tt})", "alu"),
        ("cmp64_gt", "FCMP", "11010010100.............010.....", "p{d}=cmp.gt({ss},{tt})", "alu"),
        ("cmp64_gtu", "FCMP", "11010010100.............100.....", "p{d}=cmp.gtu({ss},{tt})", "alu"),
        ("add_ll", "FRR", "11010101000.............00......", "add {d},{t}.l,{s}.l", "alu"),
        ("add_lh", "FRR", "11010101000.............01......", "add {d},{t}.l,{s}.h", "alu"),
        ("add_ll_sat", "FRR", "11010101000.............10......", "add {d},{t}.l,{s}.l:sat", "alu"),
        ("add_lh_sat", "FRR", "11010101000.............11......", "add {d},{t}.l,{s}.h:sat", "alu"),
        ("add_ll_s16", "FRR", "11010101010.............000.....", "add {d},{t}.l,{s}.l:<<16", "alu"),
        ("add_lh_s16", "FRR", "11010101010.............001.....", "add {d},{t}.l,{s}.h:<<16", "alu"),
        ("add_hl_s16", "FRR", "11010101010.............010.....", "add {d},{t}.h,{s}.l:<<16", "alu"),
        ("add_hh_s16", "FRR", "11010101010.............011.....", "add {d},{t}.h,{s}.h:<<16", "alu"),
        ("add_ll_sat_s16", "FRR", "11010101010.............100.....", "add {d},{t}.l,{s}.l:sat:<<16", "alu"),
        ("add_lh_sat_s16", "FRR", "11010101010.............101.....", "add {d},{t}.l,{s}.h:sat:<<16", "alu"),
        ("add_hl_sat_s16", "FRR", "11010101010.............110.....", "add {d},{t}.h,{s}.l:sat:<<16", "alu"),
        ("add_hh_sat_s16", "FRR", "11010101010.............111.....", "add {d},{t}.h,{s}.h:sat:<<16", "alu"),
        ("sub_ll", "FRR", "11010101001.............00......", "sub {d},{t}.l,{s}.l", "alu"),
        ("sub_lh", "FRR", "11010101001.............01......", "sub {d},{t}.l,{s}.h", "alu"),
        ("sub_ll_sat", "FRR", "11010101001.............10......", "sub {d},{t}.l,{s}.l:sat", "alu"),
        ("sub_lh_sat", "FRR", "11010101001.............11......", "sub {d},{t}.l,{s}.h:sat", "alu"),
        ("sub_ll_s16", "FRR", "11010101011.............000.....", "sub {d},{t}.l,{s}.l:<<16", "alu"),
        ("sub_lh_s16", "FRR", "11010101011.............001.....", "sub {d},{t}.l,{s}.h:<<16", "alu"),
        ("sub_hl_s16", "FRR", "11010101011.............010.....", "sub {d},{t}.h,{s}.l:<<16", "alu"),
        ("sub_hh_s16", "FRR", "11010101011.............011.....", "sub {d},{t}.h,{s}.h:<<16", "alu"),
        ("sub_ll_sat_s16", "FRR", "11010101011.............100.....", "sub {d},{t}.l,{s}.l:sat:<<16", "alu"),
        ("sub_lh_sat_s16", "FRR", "11010101011.............101.....", "sub {d},{t}.l,{s}.h:sat:<<16", "alu"),
        ("sub_hl_sat_s16", "FRR", "11010101011.............110.....", "sub {d},{t}.h,{s}.l:sat:<<16", "alu"),
        ("sub_hh_sat_s16", "FRR", "11010101011.............111.....", "sub {d},{t}.h,{s}.h:sat:<<16", "alu"),
        ("asr_i", "FSHI", "10001100000.......0.....000.....", "asr {d},{s},#{imm}", "alu"),
        ("lsr_i", "FSHI", "10001100000.......0.....001.....", "lsr {d},{s},#{imm}", "alu"),
        ("asl_i", "FSHI", "10001100000.......0.....010.....", "asl {d},{s},#{imm}", "alu"),
        ("asl_i_sat", "FSHI", "10001100010.......0.....010.....", "asl {d},{s},#{imm}:sat", "alu"),
        ("rol_i", "FSHI", "10001100000.......0.....011.....", "rol {d},{s},#{imm}", "alu"),
        ("asr64_i", "FSHI6", "10000000000.............000.....", "asr {dd},{ss},#{imm}", "alu"),
        ("lsr64_i", "FSHI6", "10000000000.............001.....", "lsr {dd},{ss},#{imm}", "alu"),
        ("asl64_i", "FSHI6", "10000000000.............010.....", "asl {dd},{ss},#{imm}", "alu"),
        ("rol64_i", "FSHI6", "10000000000.............011.....", "rol {dd},{ss},#{imm}", "alu"),
        ("asr_rr", "FRR", "1100011001..............00......", "asr {d},{s},{t}", "alu"),
        ("asl_rr", "FRR", "1100011001..............10......", "asl {d},{s},{t}", "alu"),
        ("lsr_rr", "FRR", "1100011001..............01......", "lsr {d},{s},{t}", "alu"),
        ("lsl_rr", "FRR", "1100011001..............11......", "lsl {d},{s},{t}", "alu"),
        ("asl_rr_sat", "FRR", "1100011000..............10......", "asl {d},{s},{t}:sat", "alu"),
        ("asr_rr_sat", "FRR", "1100011000..............00......", "asr {d},{s},{t}:sat", "alu"),
        ("asr64_rr", "FRR", "1100001110..............00......", "asr {dd},{ss},{t}", "alu"),
        ("asl64_rr", "FRR", "1100001110..............10......", "asl {dd},{ss},{t}", "alu"),
        ("lsr64_rr", "FRR", "1100001110..............01......", "lsr {dd},{ss},{t}", "alu"),
        ("lsl64_rr", "FRR", "1100001110..............11......", "lsl {dd},{ss},{t}", "alu"),
        ("lsl_ir", "FLSL", "1100011010..............11......", "lsl {d},#{imm},{t}", "alu"),
        ("addasl", "FASL3", "11000100000.......0.............", "addasl {d},{t},{s},#{imm}", "alu"),
        ("add_asr_i", "FXSH", "1000111000........0.....100.....", "{x}+=asr({s},#{imm})", "alu"),
        ("add_lsr_i", "FXSH", "1000111000........0.....101.....", "{x}+=lsr({s},#{imm})", "alu"),
        ("add_asl_i", "FXSH", "1000111000........0.....110.....", "{x}+=asl({s},#{imm})", "alu"),
        ("add_rol_i", "FXSH", "1000111000........0.....111.....", "{x}+=rol({s},#{imm})", "alu"),
        ("sub_asr_i", "FXSH", "1000111000........0.....000.....", "{x}-=asr({s},#{imm})", "alu"),
        ("sub_lsr_i", "FXSH", "1000111000........0.....001.....", "{x}-=lsr({s},#{imm})", "alu"),
        ("sub_asl_i", "FXSH", "1000111000........0.....010.....", "{x}-=asl({s},#{imm})", "alu"),
        ("sub_rol_i", "FXSH", "1000111000........0.....011.....", "{x}-=rol({s},#{imm})", "alu"),
        ("and_asr_i", "FXSH", "1000111001........0.....000.....", "{x}&=asr({s},#{imm})", "alu"),
        ("and_lsr_i", "FXSH", "1000111001........0.....001.....", "{x}&=lsr({s},#{imm})", "alu"),
        ("and_asl_i", "FXSH", "1000111001........0.....010.....", "{x}&=asl({s},#{imm})", "alu"),
        ("and_rol_i", "FXSH", "1000111001........0.....011.....", "{x}&=rol({s},#{imm})", "alu"),
        ("or_asr_i", "FXSH", "1000111001........0.....100.....", "{x}|=asr({s},#{imm})", "alu"),
        ("or_lsr_i", "FXSH", "1000111001........0.....101.....", "{x}|=lsr({s},#{imm})", "alu"),
        ("or_asl_i", "FXSH", "1000111001........0.....110.....", "{x}|=asl({s},#{imm})", "alu"),
        ("or_rol_i", "FXSH", "1000111001........0.....111.....", "{x}|=rol({s},#{imm})", "alu"),
        ("xor_lsr_i", "FXSH", "1000111010........0.....001.....", "{x}^=lsr({s},#{imm})", "alu"),
        ("xor_asl_i", "FXSH", "1000111010........0.....010.....", "{x}^=asl({s},#{imm})", "alu"),
        ("xor_rol_i", "FXSH", "1000111010........0.....011.....", "{x}^=rol({s},#{imm})", "alu"),
        ("add64_asr_i", "FXSH6", "1000001000..............100.....", "{xx}+=asr({ss},#{imm})", "alu"),
        ("add64_lsr_i", "FXSH6", "1000001000..............101.....", "{xx}+=lsr({ss},#{imm})", "alu"),
        ("add64_asl_i", "FXSH6", "1000001000..............110.....", "{xx}+=asl({ss},#{imm})", "alu"),
        ("add64_rol_i", "FXSH6", "1000001000..............111.....", "{xx}+=rol({ss},#{imm})", "alu"),
        ("sub64_asr_i", "FXSH6", "1000001000..............000.....", "{xx}-=asr({ss},#{imm})", "alu"),
        ("sub64_lsr_i", "FXSH6", "1000001000..............001.....", "{xx}-=lsr({ss},#{imm})", "alu"),
        ("sub64_asl_i", "FXSH6", "1000001000..............010.....", "{xx}-=asl({ss},#{imm})", "alu"),
        ("sub64_rol_i", "FXSH6", "1000001000..............011.....", "{xx}-=rol({ss},#{imm})", "alu"),
        ("and64_asr_i", "FXSH6", "1000001001..............000.....", "{xx}&=asr({ss},#{imm})", "alu"),
        ("and64_lsr_i", "FXSH6", "1000001001..............001.....", "{xx}&=lsr({ss},#{imm})", "alu"),
        ("and64_asl_i", "FXSH6", "1000001001..............010.....", "{xx}&=asl({ss},#{imm})", "alu"),
        ("and64_rol_i", "FXSH6", "1000001001..............011.....", "{xx}&=rol({ss},#{imm})", "alu"),
        ("or64_asr_i", "FXSH6", "1000001001..............100.....", "{xx}|=asr({ss},#{imm})", "alu"),
        ("or64_lsr_i", "FXSH6", "1000001001..............101.....", "{xx}|=lsr({ss},#{imm})", "alu"),
        ("or64_asl_i", "FXSH6", "1000001001..............110.....", "{xx}|=asl({ss},#{imm})", "alu"),
        ("or64_rol_i", "FXSH6", "1000001001..............111.....", "{xx}|=rol({ss},#{imm})", "alu"),
        ("xor64_lsr_i", "FXSH6", "1000001010..............001.....", "{xx}^=lsr({ss},#{imm})", "alu"),
        ("xor64_asl_i", "FXSH6", "1000001010..............010.....", "{xx}^=asl({ss},#{imm})", "alu"),
        ("xor64_rol_i", "FXSH6", "1000001010..............011.....", "{xx}^=rol({ss},#{imm})", "alu"),
        ("add_asr", "FXRR", "1100110011..............00......", "{x}+=asr({s},{t})", "alu"),
        ("add_lsr", "FXRR", "1100110011..............01......", "{x}+=lsr({s},{t})", "alu"),
        ("add_asl", "FXRR", "1100110011..............10......", "{x}+=asl({s},{t})", "alu"),
        ("add_lsl", "FXRR", "1100110011..............11......", "{x}+=lsl({s},{t})", "alu"),
        ("sub_asr", "FXRR", "1100110010..............00......", "{x}-=asr({s},{t})", "alu"),
        ("sub_lsr", "FXRR", "1100110010..............01......", "{x}-=lsr({s},{t})", "alu"),
        ("sub_asl", "FXRR", "1100110010..............10......", "{x}-=asl({s},{t})", "alu"),
        ("sub_lsl", "FXRR", "1100110010..............11......", "{x}-=lsl({s},{t})", "alu"),
        ("or_asr", "FXRR", "1100110000..............00......", "{x}|=asr({s},{t})", "alu"),
        ("or_lsr", "FXRR", "1100110000..............01......", "{x}|=lsr({s},{t})", "alu"),
        ("or_asl", "FXRR", "1100110000..............10......", "{x}|=asl({s},{t})", "alu"),
        ("or_lsl", "FXRR", "1100110000..............11......", "{x}|=lsl({s},{t})", "alu"),
        ("add64_asr", "FXRR", "11001011110.............00......", "{xx}+=asr({ss},{t})", "alu"),
        ("add64_lsr", "FXRR", "11001011110.............01......", "{xx}+=lsr({ss},{t})", "alu"),
        ("add64_asl", "FXRR", "11001011110.............10......", "{xx}+=asl({ss},{t})", "alu"),
        ("add64_lsl", "FXRR", "11001011110.............11......", "{xx}+=lsl({ss},{t})", "alu"),
        ("sub64_asr", "FXRR", "11001011100.............00......", "{xx}-=asr({ss},{t})", "alu"),
        ("sub64_lsr", "FXRR", "11001011100.............01......", "{xx}-=lsr({ss},{t})", "alu"),
        ("sub64_asl", "FXRR", "11001011100.............10......", "{xx}-=asl({ss},{t})", "alu"),
        ("sub64_lsl", "FXRR", "11001011100.............11......", "{xx}-=lsl({ss},{t})", "alu"),
        ("or64_asr", "FXRR", "11001011000.............00......", "{xx}|=asr({ss},{t})", "alu"),
        ("or64_lsr", "FXRR", "11001011000.............01......", "{xx}|=lsr({ss},{t})", "alu"),
        ("or64_asl", "FXRR", "11001011000.............10......", "{xx}|=asl({ss},{t})", "alu"),
        ("or64_lsl", "FXRR", "11001011000.............11......", "{xx}|=lsl({ss},{t})", "alu"),
        ("add_acc", "FXRR", "11101111000.......0.....001.....", "{x}+=add({s},{t})", "alu"),
        ("sub_acc", "FXRR", "11101111100.......0.....001.....", "{x}-=add({s},{t})", "alu"),
        ("addsub_acc", "FXRR", "11101111000.......0.....011.....", "{x}+=sub({t},{s})", "alu"),
        ("add_acc_i", "FXI8", "111000100.........0.............", "{x}+=add({s},#{imm})", "alu"),
        ("sub_acc_i", "FXI8", "111000101.........0.............", "{x}-=add({s},#{imm})", "alu"),
        ("and_and", "FXRR", "11101111010.......0.....000.....", "{x}&=and({s},{t})", "alu"),
        ("and_andn", "FXRR", "11101111001.......0.....001.....", "{x}&=and({s},~{t})", "alu"),
        ("and_or", "FXRR", "11101111010.......0.....001.....", "{x}&=or({s},{t})", "alu"),
        ("and_xor", "FXRR", "11101111010.......0.....010.....", "{x}&=xor({s},{t})", "alu"),
        ("or_and", "FXRR", "11101111010.......0.....011.....", "{x}|=and({s},{t})", "alu"),
        ("or_andn", "FXRR", "11101111001.......0.....000.....", "{x}|=and({s},~{t})", "alu"),
        ("or_or", "FXRR", "11101111110.......0.....000.....", "{x}|=or({s},{t})", "alu"),
        ("or_xor", "FXRR", "11101111110.......0.....001.....", "{x}|=xor({s},{t})", "alu"),
        ("xor_and", "FXRR", "11101111110.......0.....010.....", "{x}^=and({s},{t})", "alu"),
        ("xor_or", "FXRR", "11101111110.......0.....011.....", "{x}^=or({s},{t})", "alu"),
        ("xor_xor", "FXRR", "11101111100.......0.....011.....", "{x}^=xor({s},{t})", "alu"),
        ("xor_andn", "FXRR", "11101111001.......0.....010.....", "{x}^=and({s},~{t})", "alu"),
        ("xor64_xor", "FXRR", "1100101010........0.....000.....", "{xx}^=xor({ss},{tt})", "alu"),
        ("or_and_i", "FXI10", "1101101000......................", "{x}|=and({s},#{imm})", "alu"),
        ("or_or_i", "FXI10", "1101101010......................", "{x}|=or({s},#{imm})", "alu"),
        ("or_ac", "FOAC", "1101101001......................", "{x}=or({u},and({x},#{imm}))", "alu"),
        ("add3", "FADD3", "110110110.......................", "add {d},{s},add({u},#{imm})", "alu"),
        ("sub3", "FADD3", "110110111.......................", "add {d},{s},sub(#{imm},{u})", "alu"),
        ("cadd_asl", "FSHIMM", "11011110...................0.10.", "{x}=add(#{imm},asl({x},#{ushift}))", "alu"),
        ("csub_asl", "FSHIMM", "11011110...................0.11.", "{x}=sub(#{imm},asl({x},#{ushift}))", "alu"),
        ("cand_asl", "FSHIMM", "11011110...................0.00.", "{x}=and(#{imm},asl({x},#{ushift}))", "alu"),
        ("cor_asl", "FSHIMM", "11011110...................0.01.", "{x}=or(#{imm},asl({x},#{ushift}))", "alu"),
        ("cadd_lsr", "FSHIMM", "11011110...................1.10.", "{x}=add(#{imm},lsr({x},#{ushift}))", "alu"),
        ("csub_lsr", "FSHIMM", "11011110...................1.11.", "{x}=sub(#{imm},lsr({x},#{ushift}))", "alu"),
        ("cand_lsr", "FSHIMM", "11011110...................1.00.", "{x}=and(#{imm},lsr({x},#{ushift}))", "alu"),
        ("cor_lsr", "FSHIMM", "11011110...................1.01.", "{x}=or(#{imm},lsr({x},#{ushift}))", "alu"),
        ("asr_i_rnd", "FSHI", "10001100010.......0.....000.....", "asr {d},{s},#{imm}:rnd", "alu"),
        ("asr64_i_rnd", "FSHI6", "10000000110.............111.....", "asr {dd},{ss},#{imm}:rnd", "alu"),
        ("cl0", "FRS", "10001100000.............101.....", "cl0 {d},{s}", "alu"),
        ("cl1", "FRS", "10001100000.............110.....", "cl1 {d},{s}", "alu"),
        ("clb", "FRS", "10001100000.............100.....", "clb {d},{s}", "alu"),
        ("cl064", "FRS", "10001000010.............010.....", "cl0 {d},{ss}", "alu"),
        ("cl164", "FRS", "10001000010.............100.....", "cl1 {d},{ss}", "alu"),
        ("clb64", "FRS", "10001000010.............000.....", "clb {d},{ss}", "alu"),
        ("normamt", "FRS", "10001100000.............111.....", "normamt {d},{s}", "alu"),
        ("normamt64", "FRS", "10001000011.............000.....", "normamt {d},{ss}", "alu"),
        ("clbadd", "FCLADD", "10001100001.............000.....", "add(clb {d},{s},#{imm})", "alu"),
        ("clbadd64", "FCLADD", "10001000011.............010.....", "add(clb {d},{ss},#{imm})", "alu"),
        ("ct0", "FRS", "10001100010.............100.....", "ct0 {d},{s}", "alu"),
        ("ct1", "FRS", "10001100010.............101.....", "ct1 {d},{s}", "alu"),
        ("ct064", "FRS", "10001000111.............010.....", "ct0 {d},{ss}", "alu"),
        ("ct164", "FRS", "10001000111.............100.....", "ct1 {d},{ss}", "alu"),
        ("popcount", "FRS", "10001000011.............011.....", "popcount {d},{ss}", "alu"),
        ("parity", "FRR", "11010101111.....................", "parity {d},{s},{t}", "alu"),
        ("parity64", "FRR", "11010000........................", "parity {d},{ss},{tt}", "alu"),
        ("brev", "FRS", "10001100010.............110.....", "brev {d},{s}", "alu"),
        ("brev64", "FRS", "10000000110.............110.....", "brev {dd},{ss}", "alu"),
        ("swiz", "FRS", "10001100100.............111.....", "swiz {d},{s}", "alu"),
        ("tstbit_i", "FPTST", "10000101000.......0.............", "p{d}=tstbit({s},#{imm})", "alu"),
        ("tstbitn_i", "FPTST", "10000101001.......0.............", "p{d}=!tstbit({s},#{imm})", "alu"),
        ("tstbit_r", "FCMP", "11000111000.....................", "p{d}=tstbit({s},{t})", "alu"),
        ("tstbitn_r", "FCMP", "11000111001.....................", "p{d}=!tstbit({s},{t})", "alu"),
        ("setbit_i", "FSHI", "10001100110.......0.....000.....", "setbit {d},{s},#{imm}", "alu"),
        ("clrbit_i", "FSHI", "10001100110.......0.....001.....", "clrbit {d},{s},#{imm}", "alu"),
        ("togglebit_i", "FSHI", "10001100110.......0.....010.....", "togglebit {d},{s},#{imm}", "alu"),
        ("setbit_r", "FRR", "1100011010..............00......", "setbit {d},{s},{t}", "alu"),
        ("clrbit_r", "FRR", "1100011010..............01......", "clrbit {d},{s},{t}", "alu"),
        ("togglebit_r", "FRR", "1100011010..............10......", "togglebit {d},{s},{t}", "alu"),
        ("bitsclr_r", "FCMP", "11000111100.....................", "p{d}=bitsclr({s},{t})", "alu"),
        ("bitsclrn_r", "FCMP", "11000111101.....................", "p{d}=!bitsclr({s},{t})", "alu"),
        ("bitsset_r", "FCMP", "11000111010.....................", "p{d}=bitsset({s},{t})", "alu"),
        ("bitssetn_r", "FCMP", "11000111011.....................", "p{d}=!bitsset({s},{t})", "alu"),
        ("bitsclr_i", "FPCLR", "10000101100.....................", "p{d}=bitsclr({s},#{imm})", "alu"),
        ("bitsclrn_i", "FPCLR", "10000101101.....................", "p{d}=!bitsclr({s},#{imm})", "alu"),
        ("extract", "FXTR", "100011011.........0.............", "extract {d},{s},#{width},#{off}", "alu"),
        ("extractu", "FXTR", "100011010.........0.............", "extractu {d},{s},#{width},#{off}", "alu"),
        ("extract64", "FXTR64", "10001010........................", "extract {dd},{ss},#{width},#{off}", "alu"),
        ("extractu64", "FXTR64", "10000001........................", "extractu {dd},{ss},#{width},#{off}", "alu"),
        ("extract_r", "FRR", "1100100100..............01......", "extract {d},{s},{tt}", "alu"),
        ("extractu_r", "FRR", "1100100100..............00......", "extractu {d},{s},{tt}", "alu"),
        ("extract64_r", "FRR", "1100000111..............10......", "extract {dd},{ss},{tt}", "alu"),
        ("extractu64_r", "FRR", "1100000100..............00......", "extractu {dd},{ss},{tt}", "alu"),
        ("insert", "FINS", "100011110.........0.............", "insert {x},{s},#{width},#{off}", "alu"),
        ("insert64", "FINS64", "10000011........................", "insert {xx},{ss},#{width},#{off}", "alu"),
        ("insert_r", "FXRR", "11001000........................", "insert {x},{s},{tt}", "alu"),
        ("insert64_r", "FXRR", "110010100.........0.............", "insert {xx},{ss},{tt}", "alu"),
        ("bitsplit_i", "FSHI", "10001000110.......0.....100.....", "bitsplit {dd},{s},#{imm}", "alu"),
        ("bitsplit_r", "FRR", "11010100..1.....................", "bitsplit {dd},{s},{t}", "alu"),
        ("cmpb_eq", "FCMP", "11000111110.............110.....", "p{d}=cmpb.eq({s},{t})", "alu"),
        ("cmpb_gt", "FCMP", "11000111110.............010.....", "p{d}=cmpb.gt({s},{t})", "alu"),
        ("cmpb_gtu", "FCMP", "11000111110.............111.....", "p{d}=cmpb.gtu({s},{t})", "alu"),
        ("cmpb_eq_i", "FCMPBI", "11011101.00................00...", "p{d}=cmpb.eq({s},#{imm})", "alu"),
        ("cmpb_gt_i", "FCMPBI", "11011101.01................00...", "p{d}=cmpb.gt({s},#{imm})", "alu"),
        ("cmpb_gtu_i", "FCMPBI", "11011101.10........0.......00...", "p{d}=cmpb.gtu({s},#{imm})", "alu"),
        ("cmph_eq", "FCMP", "11000111110.............011.....", "p{d}=cmph.eq({s},{t})", "alu"),
        ("cmph_gt", "FCMP", "11000111110.............100.....", "p{d}=cmph.gt({s},{t})", "alu"),
        ("cmph_gtu", "FCMP", "11000111110.............101.....", "p{d}=cmph.gtu({s},{t})", "alu"),
        ("cmph_gt_i", "FCMPBI", "11011101.01................01...", "p{d}=cmph.gt({s},#{imm})", "alu"),
        ("cmph_gtu_i", "FCMPBI", "11011101.10........0.......01...", "p{d}=cmph.gtu({s},#{imm})", "alu"),
        ("sat", "FRS", "10001000110.............000.....", "sat {d},{ss}", "alu"),
        ("sath", "FRS", "10001100110.............100.....", "sath {d},{s}", "alu"),
        ("satuh", "FRS", "10001100110.............101.....", "satuh {d},{s}", "alu"),
        ("satb", "FRS", "10001100110.............111.....", "satb {d},{s}", "alu"),
        ("satub", "FRS", "10001100110.............110.....", "satub {d},{s}", "alu"),
        ("round_sat", "FRS", "10001000110.............001.....", "round {d},{ss}:sat", "alu"),
        ("round_i", "FSHI", "10001100111.......0.....10......", "round {d},{s},#{imm}", "alu"),
        ("round_i_sat", "FSHI", "10001100111.......0.....11......", "round {d},{s},#{imm}:sat", "alu"),
        ("round_r", "FRR", "1100011011..............10......", "round {d},{s},{t}", "alu"),
        ("round_r_sat", "FRR", "1100011011..............11......", "round {d},{s},{t}:sat", "alu"),
        ("cround_i", "FSHI", "10001100111.......0.....00......", "cround {d},{s},#{imm}", "alu"),
        ("cround_r", "FRR", "1100011011..............00......", "cround {d},{s},{t}", "alu"),
        ("vsathub", "FRS", "10001000000.............000.....", "vsathub {d},{ss}", "alu"),
        ("vsathb", "FRS", "10001000000.............110.....", "vsathb {d},{ss}", "alu"),
        ("vsathub_p", "FRS", "10000000000.............100.....", "vsathub {dd},{ss}", "alu"),
        ("vsathb_p", "FRS", "10000000000.............111.....", "vsathb {dd},{ss}", "alu"),
        ("vaddhub_sat", "FRR", "1100000101..............001.....", "vaddhub {d},{ss},{tt}:sat", "alu"),
        ("tableidxb", "FTIDX", "1000011100......................", "tableidxb {x},{s},#{imm},#{off}", "alu"),
        ("tableidxh", "FTIDX", "1000011101......................", "tableidxh {x},{s},#{imm},#{off}", "alu"),
        ("tableidxw", "FTIDX", "1000011110......................", "tableidxw {x},{s},#{imm},#{off}", "alu"),
        ("tableidxd", "FTIDX", "1000011111......................", "tableidxd {x},{s},#{imm},#{off}", "alu"),
        ("cmph_eq_i", "FCMPBI", "11011101.00................01...", "p{d}=cmph.eq({s},#{imm})", "alu"),
        ("vsatwh", "FRS", "10001000000.............010.....", "vsatwh {d},{ss}", "alu"),
        ("vsatwuh", "FRS", "10001000000.............100.....", "vsatwuh {d},{ss}", "alu"),
        ("vsathub_rs", "FRS", "1000110010..............01......", "vsathub {d},{s}", "alu"),
        ("vsathb_rs", "FRS", "1000110010..............00......", "vsathb {d},{s}", "alu"),
        ("vsatwh_p", "FRS", "10000000000.............110.....", "vsatwh {dd},{ss}", "alu"),
        ("vsatwuh_p", "FRS", "10000000000.............101.....", "vsatwuh {dd},{ss}", "alu"),
        ("vrndwh", "FRS", "10001000100.............100.....", "vrndwh {d},{ss}", "alu"),
        ("vrndwh_sat", "FRS", "10001000100.............110.....", "vrndwh {d},{ss}:sat", "alu"),
        ("vaddub64", "FRR", "11010011000.............000.....", "vaddub {dd},{ss},{tt}", "alu"),
        ("vaddub64_sat", "FRR", "11010011000.............001.....", "vaddub {dd},{ss},{tt}:sat", "alu"),
        ("vaddh64", "FRR", "11010011000.............010.....", "vaddh {dd},{ss},{tt}", "alu"),
        ("vaddh64_sat", "FRR", "11010011000.............011.....", "vaddh {dd},{ss},{tt}:sat", "alu"),
        ("vadduh64_sat", "FRR", "11010011000.............100.....", "vadduh {dd},{ss},{tt}:sat", "alu"),
        ("vaddw64", "FRR", "11010011000.............101.....", "vaddw {dd},{ss},{tt}", "alu"),
        ("vaddw64_sat", "FRR", "11010011000.............110.....", "vaddw {dd},{ss},{tt}:sat", "alu"),
        ("vsubub64", "FRR", "11010011001.............000.....", "vsubub {dd},{tt},{ss}", "alu"),
        ("vsubub64_sat", "FRR", "11010011001.............001.....", "vsubub {dd},{tt},{ss}:sat", "alu"),
        ("vsubh64", "FRR", "11010011001.............010.....", "vsubh {dd},{tt},{ss}", "alu"),
        ("vsubh64_sat", "FRR", "11010011001.............011.....", "vsubh {dd},{tt},{ss}:sat", "alu"),
        ("vsubuh64_sat", "FRR", "11010011001.............100.....", "vsubuh {dd},{tt},{ss}:sat", "alu"),
        ("vsubw64", "FRR", "11010011001.............101.....", "vsubw {dd},{tt},{ss}", "alu"),
        ("vsubw64_sat", "FRR", "11010011001.............110.....", "vsubw {dd},{tt},{ss}:sat", "alu"),
        ("vavgub64", "FRR", "11010011010.............000.....", "vavgub {dd},{ss},{tt}", "alu"),
        ("vavgub64_rnd", "FRR", "11010011010.............001.....", "vavgub {dd},{ss},{tt}:rnd", "alu"),
        ("vavguh64", "FRR", "11010011010.............101.....", "vavguh {dd},{ss},{tt}", "alu"),
        ("vavguh64_rnd", "FRR", "11010011010.............11......", "vavguh {dd},{ss},{tt}:rnd", "alu"),
        ("vavgh64", "FRR", "11010011010.............010.....", "vavgh {dd},{ss},{tt}", "alu"),
        ("vavgh64_rnd", "FRR", "11010011010.............011.....", "vavgh {dd},{ss},{tt}:rnd", "alu"),
        ("vavgh64_crnd", "FRR", "11010011010.............100.....", "vavgh {dd},{ss},{tt}:crnd", "alu"),
        ("vavgw64", "FRR", "11010011011.............000.....", "vavgw {dd},{ss},{tt}", "alu"),
        ("vavgw64_rnd", "FRR", "11010011011.............001.....", "vavgw {dd},{ss},{tt}:rnd", "alu"),
        ("vavgw64_crnd", "FRR", "11010011011.............010.....", "vavgw {dd},{ss},{tt}:crnd", "alu"),
        ("vavguw64", "FRR", "11010011011.............011.....", "vavguw {dd},{ss},{tt}", "alu"),
        ("vavguw64_rnd", "FRR", "11010011011.............100.....", "vavguw {dd},{ss},{tt}:rnd", "alu"),
        ("vnavgh64", "FRR", "11010011100.............000.....", "vnavgh {dd},{tt},{ss}", "alu"),
        ("vnavgh64_rnd_sat", "FRR", "11010011100.............001.....", "vnavgh {dd},{tt},{ss}:rnd:sat", "alu"),
        ("vnavgh64_crnd_sat", "FRR", "11010011100.............010.....", "vnavgh {dd},{tt},{ss}:crnd:sat", "alu"),
        ("vnavgw64", "FRR", "11010011100.............011.....", "vnavgw {dd},{tt},{ss}", "alu"),
        ("vnavgw64_rnd_sat", "FRR", "11010011100.............10......", "vnavgw {dd},{tt},{ss}:rnd:sat", "alu"),
        ("vnavgw64_crnd_sat", "FRR", "11010011100.............11......", "vnavgw {dd},{tt},{ss}:crnd:sat", "alu"),
        ("vmaxub64", "FRR", "11010011110.............000.....", "vmaxub {dd},{tt},{ss}", "alu"),
        ("vmaxb64", "FRR", "11010011110.............110.....", "vmaxb {dd},{tt},{ss}", "alu"),
        ("vmaxuh64", "FRR", "11010011110.............010.....", "vmaxuh {dd},{tt},{ss}", "alu"),
        ("vmaxh64", "FRR", "11010011110.............001.....", "vmaxh {dd},{tt},{ss}", "alu"),
        ("vmaxw64", "FRR", "11010011110.............011.....", "vmaxw {dd},{tt},{ss}", "alu"),
        ("vmaxuw64", "FRR", "11010011101.............101.....", "vmaxuw {dd},{tt},{ss}", "alu"),
        ("vminub64", "FRR", "11010011101.............000.....", "vminub {dd},{tt},{ss}", "alu"),
        ("vminb64", "FRR", "11010011110.............111.....", "vminb {dd},{tt},{ss}", "alu"),
        ("vminuh64", "FRR", "11010011101.............010.....", "vminuh {dd},{tt},{ss}", "alu"),
        ("vminh64", "FRR", "11010011101.............001.....", "vminh {dd},{tt},{ss}", "alu"),
        ("vminw64", "FRR", "11010011101.............011.....", "vminw {dd},{tt},{ss}", "alu"),
        ("vminuw64", "FRR", "11010011101.............100.....", "vminuw {dd},{tt},{ss}", "alu"),
        ("vmux", "FMUX", "11010001........................", "vmux {dd},p{p},{ss},{tt}", "alu"),
        ("valignb_i", "FASL3", "110000000.......................", "valignb {dd},{tt},{ss},#{imm}", "alu"),
        ("valignb_p", "FMUX", "110000100.......................", "valignb {dd},{tt},{ss},p{p}", "alu"),
        ("vspliceb_i", "FASL3", "110000001.......................", "vspliceb {dd},{ss},{tt},#{imm}", "alu"),
        ("vspliceb_p", "FMUX", "11000010100.....................", "vspliceb {dd},{ss},{tt},p{p}", "alu"),
        ("vcnegh", "FRR", "1100001111..............01......", "vcnegh {dd},{ss},{t}", "alu"),
        ("vrcnegh", "FXRR", "11001011001.......1.....111.....", "{xx}+=vrcnegh({ss},{t})", "alu"),
        ("interleave", "FRS", "10000000110.............101.....", "interleave {dd},{ss}", "alu"),
        ("deinterleave", "FRS", "10000000110.............100.....", "deinterleave {dd},{ss}", "alu"),
        ("lfs", "FRR", "1100000110..............110.....", "lfs {dd},{ss},{tt}", "alu"),
        ("vtrunehb", "FRS", "10001000100.............010.....", "vtrunehb {d},{ss}", "alu"),
        ("vtrunohb", "FRS", "10001000100.............000.....", "vtrunohb {d},{ss}", "alu"),
        ("vtrunewh", "FRR", "1100000110..............010.....", "vtrunewh {dd},{ss},{tt}", "alu"),
        ("vtrunowh", "FRR", "1100000110..............100.....", "vtrunowh {dd},{ss},{tt}", "alu"),
        ("vtrunehb_p", "FRR", "1100000110..............011.....", "vtrunehb {dd},{ss},{tt}", "alu"),
        ("vtrunohb_p", "FRR", "1100000110..............101.....", "vtrunohb {dd},{ss},{tt}", "alu"),
        ("vsplatb", "FRS", "10001100010.............111.....", "vsplatb {d},{s}", "alu"),
        ("vsplatb_p", "FRS", "1000010001..............10......", "vsplatb {dd},{s}", "alu"),
        ("vsplath", "FRS", "1000010001..............01......", "vsplath {dd},{s}", "alu"),
        ("vsxtbh", "FRS", "1000010000..............00......", "vsxtbh {dd},{s}", "alu"),
        ("vsxthw", "FRS", "1000010000..............10......", "vsxthw {dd},{s}", "alu"),
        ("vzxtbh", "FRS", "1000010000..............01......", "vzxtbh {dd},{s}", "alu"),
        ("vzxthw", "FRS", "1000010000..............11......", "vzxthw {dd},{s}", "alu"),
        ("andn_rr", "FRR", "11110001010.....................", "and {d},{s},~{t}", "alu"),
        ("orn_rr", "FRR", "11110001110.....................", "or {d},{s},~{t}", "alu"),
        ("addpc", "FPC6", "0110101001001001................", "add {d},pc,#{imm}", "alu"),
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
