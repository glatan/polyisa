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
        timing: None,
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
    // HX9: HVX のレジスタ類。v0-v31（各 128B）と述語 q0-q3（各 128b、
    // ベクトル要素ごとの真偽ビット）。ベクトル幅は V73 系の 128B 固定。
    // Ref: SPEC-HEXAGON-PRM (V79), 80-N2040-61 (HVX).
    for (name, prefix) in [("vreg", "v"), ("vpred", "q")] {
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
        ("s5", 20, 16), // 5 ビットソース/ベースレジスタ
        ("t5", 12, 8),  // 5 ビットソース/ストア値レジスタ
        ("x5", 20, 16), // 5 ビットソース=デスティネーションレジスタ
        ("d5", 4, 0),   // 5 ビットデスティネーションレジスタ
        ("c5", 20, 16), // 制御レジスタ番号（Rd=Cs / Cd=Rs）
        ("pd2", 1, 0),  // 述語デスティネーション（2 ビット）
        // ---- HX5: 整数語彙の追加桁 ----
        ("ps2", 17, 16),  // 述語ソース Ps（P 演算、bits[17:16]）
        ("pt2", 9, 8),    // 述語ソース Pt（P 演算、bits[9:8]）
        ("pu2b", 7, 6),   // 述語ソース Pu（3 入力 P 演算）
        ("pu2", 6, 5),    // 述語選択/キャリー Px（mux・carry・valignb 等）
        ("pu2i", 22, 21), // mux 即値系の Pu
        ("pu2j", 24, 23), // mux(#s8,#S8) の Pu
        ("psx", 17, 16),  // Rd = Ps の Ps
        ("rx5", 4, 0),    // 累積/破壊的更新の Rx・insert/tableidx/add3 の宛先やソース
        ("iu6", 13, 8),   // u6/s6 即値（64 ビットシフト・bitsclr・tableidx・add(clb,#s6)）
        ("xu3", 7, 5),    // u3 即値（addasl・valignb・vspliceb）
        ("ai8", 12, 5),   // 8 ビット即値（combine・mux・cmpb/cmph・累積・cmp.eq→Rd）
        ("iu9", 13, 5),   // 9 ビット即値（cmp.gtu #u9）
        ("pc6", 12, 7),   // add(pc,#u6) の u6
        // ---- HX6: ロード/ストア ----
        // sz3: アクセスサイズの 3 ビット（b=000 ub=001 h=010
        // uh=011 w=100 w.h=101 d=110）。`.new` ストア値形は
        // 101 を共有するため、通常形は wheres で 101 を除く。
        ("sz3", 23, 21),
        // sz2: `.new` ストア値形のアクセスサイズ（b=00 h=01 w=10）。
        ("sz2", 12, 11),
        // nt2: `.new` 値の生産者距離（bits[10:9] = Nt>>1。
        // bit8 は 0 固定でパターン側が担う）。
        ("nt2", 10, 9),
        // mu1: 修飾レジスタ M0/M1 の選択（bit13）。
        ("mu1", 13, 13),
        // mo2: memop の演算選択（bits[6:5]。即値形は
        // 0=+ 1=- 2=clrbit 3=setbit、レジスタ形は 0=+ 1=- 2=& 3=|）。
        ("mo2", 6, 5),
        // pd2m: ストア即値形・述語付 reg-offset の述語選択
        // （bits[6:5]）。
        ("pd2m", 6, 5),
        // sz2i: ストア即値形・memop の 2 ビットサイズ
        // （bits[22:21]。b=00 h=01 w=10）。
        ("sz2i", 22, 21),
        // sz2r/nt2r: reg-offset `.new` ストア値形のサイズ（bits[4:3]）
        // と生産者距離（bits[2:1] = Nt>>1。bit0 は 0 固定）。
        ("sz2r", 4, 3),
        ("nt2r", 2, 1),
        // sz3m: memop の 3 ビットサイズ（bits[23:21]。
        // b=000 h=001 w=010。0b011 以降は予約）。
        ("sz3m", 23, 21),
        // pv2l/pv2pi: 述語付メモリ形の述語番号 Pv
        // （io ロードは bits[12:11]、post-inc/abs ロードは
        // bits[10:9]）。
        ("pv2l", 12, 11),
        ("pv2pi", 10, 9),
        // q2v/q2r/q2p/q2ps/q2st: 述語付形の qualifier 選択
        // 2 ビット。値の意味は全形式で共通（bit1=.new、
        // bit0=否定: 0=if 1=if! 2=if.new 3=if!.new）。
        // io 形は {bit25=.new,bit26=!}、ro/st_ip 形は
        // {[25]/[24]},{[24]/[23]}、post-inc/abs ロードは
        // bits[12:11]、post-inc/abs ストアは {bit7/bit13,bit2}。
        ("q2r", 25, 24),
        ("q2p", 12, 11),
        ("q2st", 24, 23),
        // ps4q/ps4p: 述語付 post-inc の s4（ストアは
        // bits[6:3]、ロードは {bit8}+{bits[7:5]}）。
        ("ps4q", 6, 3),
        // ps4/ps4s: post-increment 即値 s4（LD: bits[8:5]、
        // ST: bits[6:3]）。
        ("ps4", 8, 5),
        ("ps4s", 6, 3),
        // ssa6: ST shifted-abs の即値（bits[5:0]）。
        ("ssa6", 5, 0),
        // ---- HX7: 分岐・frame・system ----
        // jpv: 条件付き分岐・条件付き dealloc_return の述語
        // 選択（bits[9:8] の Pu/Pv）。
        ("jpv", 9, 8),
        // jn21/jn13/jn22: 各条件形の否定桁（Pu 系の bit21、
        // dealloc_return qualifier の bit13、compare-jump と
        // new-value compare-jump の bit22）。
        ("jn21", 21, 21),
        ("jn13", 13, 13),
        ("jn22", 22, 22),
        // jpd25/jpd12: 複合 compare-jump（`pX = cmp.* ; if
        // ([!]pX.new) jump` が 1 命令に畳まれた形）の述語宛先
        // （即値形は bit25、レジスタ形は bit12）。
        ("jpd25", 25, 25),
        ("jpd12", 12, 12),
        // j4/j4t: J 系複合命令の 4 ビット部分集合レジスタ
        // （bits[19:16] と bits[11:8]。r0-7/r16-23 の符号）。
        ("j4", 19, 16),
        ("j4t", 11, 8),
        // zpd98: 条件付き sign/zero-extend（`if ([!]Pu[.new])
        // Rd = sxtb/...(Rs)`）の述語選択（bits[9:8]）。
        ("zpd98", 9, 8),
        // zq1110: 同じく条件 qualifier（bit11=否定、
        // bit10=.new。ビット順が他の qualifier と逆）。
        ("zq1110", 11, 10),
        // nt3: new-value compare-jump の生産距離（bits[18:16]。
        // エンコード値がそのまま距離）。
        ("nt3", 18, 16),
        // u6t: 転送ジャンプ `Rd=#U6; jump` の U6（bits[13:8]）。
        ("u6t", 13, 8),
        // ---- HX9: HVX ----
        // vqt: q 論理・vand(Qv,Vs) の第 2 述語ソース（bits[23:22]）。
        ("vqt", 23, 22),
        // vqp: 述語付き vmem ストアのベクトル述語 Qv（bits[12:11]）。
        ("vqp", 12, 11),
        // vq1: 述語付き vmem ストアの否定桁（bit5）。
        ("vq1", 5, 5),
        // vs3: vmem post-inc 即値 s3（bits[10:8]、ベクトル幅単位）。
        ("vs3", 10, 8),
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
        // trap0(#u8)/trap1(Rx,#u8) の分割即値
        // （bits[12:11]+[10:8]+[4:2]。実符号照合済み）。
        ("tu8", vec![(12, 11), (10, 8), (4, 2)], 0),
        // pause(#u10) の分割即値（bits[17:16]+[12:11]+[10:8]
        // +[4:2]。実符号照合済み）。
        ("pu10", vec![(17, 16), (12, 11), (10, 8), (4, 2)], 0),
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
        // yi6: add(#s6,mpyi(Rs,#s6)) の mpyi 側 s6
        // （bits{23}+{4:0}。実符号照合済み）。
        ("yi6", vec![(23, 23), (4, 0)], 0),
        // xu8: add/sub/and/or(#u8,{asl,lsr}(Rx,#U5)) の u8
        // （bits{23:21}+{13}+{7:5}+{3}）。
        ("xu8", vec![(23, 21), (13, 13), (7, 5), (3, 3)], 0),
        // lsl6: lsl(#s6,Rt) の s6（bits{20:16}+{5}）。
        ("lsl6", vec![(20, 16), (5, 5)], 0),
        // ---- HX6: ロード/ストアの分割即値 ----
        // lu11/su11: scaled でない s11（ls11/ss11 と同じ桁、zfill 0。
        // サイズは sz3 が指すのでスケーリングは実行側で行う）。
        ("lu11", vec![(26, 25), (13, 5)], 0),
        ("su11", vec![(26, 25), (13, 13), (7, 0)], 0),
        // post-increment 即値 s4（LD: bits[8:5]、ST: bits[6:3]。
        // 単一範囲なので Bits 宣言側にある）。
        // reg-offset/shifted-abs のシフト量 u2（LD: bits{13}+{7}、
        // ST: bits{13}+{6}）。
        ("u2", vec![(13, 13), (7, 7)], 0),
        ("u2a", vec![(13, 13), (6, 6)], 0),
        // LD shifted-abs/absolute-set の即値（bits{11:8}+{6:5}）。
        ("sa6", vec![(11, 8), (6, 5)], 0),
        // ST shifted-abs の即値（bits[5:0]。Bits 宣言側）。
        // 述語付ロードの u6 即値（bits{10:8}+{7:5}）。
        ("lu6", vec![(10, 8), (7, 5)], 0),
        // 述語付ストアの u6 即値（bits{13}+{7:3}）。
        ("su6", vec![(13, 13), (7, 3)], 0),
        // GP 相対の 16 ビットオフセット（LD: bits{26:25}+{20:16}
        // +{13:5}、ST: 同 +{7:0}）。fEA_GP の素の u16。
        ("ldgp16", vec![(26, 25), (20, 16), (13, 5)], 0),
        ("stgp16", vec![(26, 25), (20, 16), (13, 13), (7, 0)], 0),
        // ストア即値形・memop のオフセット u6（bits{12:8}+{7}）。
        ("stiu6", vec![(12, 8), (7, 7)], 0),
        // ストア即値形の値（非述語 s8: bits{13}+{6:0}、
        // 述語付き s6: bits{13}+{4:0}）。
        ("si8", vec![(13, 13), (6, 0)], 0),
        ("si6", vec![(13, 13), (4, 0)], 0),
        // q2v: io 述語付形の qualifier（{bit25=.new}+{bit26=!}）。
        ("q2v", vec![(25, 25), (26, 26)], 0),
        // q2ps: post-inc/abs ストア述語付形の qualifier
        // （{bit7=.new}+{bit2=!}）。
        ("q2ps", vec![(7, 7), (2, 2)], 0),
        // ps4p: post-inc ロード述語付形の s4（{bit8}+{bits[7:5]}）。
        ("ps4p", vec![(8, 8), (7, 5)], 0),
        // u6a: 述語付 abs ロードの u6（{bits[20:16]}+{bit8}）。
        ("u6a", vec![(20, 16), (8, 8)], 0),
        // u6b: 述語付 abs ストアの u6（{bits[17:16]}+{bits[6:3]}）。
        ("u6b", vec![(17, 16), (6, 3)], 0),
        // q2a: 述語付 abs ストアの qualifier（{bit13=.new}+{bit2=!}）。
        ("q2a", vec![(13, 13), (2, 2)], 0),
        // ---- HX11: 条件付き ALU 系の分割桁 ----
        // q2c: `if ([!]Pu[.new]) Rd = op(Rs,Rt)` 系の qualifier
        // （{bit13=.new}+{bit7=!}）。
        ("q2c", vec![(13, 13), (7, 7)], 0),
        // q2d: `if ([!]Pu[.new]) Rd = add(Rs,#s8)` /
        // `Rd = #s12` 系の qualifier（{bit13=.new}+{bit23=!}）。
        ("q2d", vec![(13, 13), (23, 23)], 0),
        // ci12: `Rd = #s12` の分割即値（bits{19:16}+{12:5}）。
        ("ci12", vec![(19, 16), (12, 5)], 0),
        // ---- HX7: 分岐系の分割即値 ----
        // r15: `if ([!]Pu[.new]) jump/call` の PC 相対オフセット
        // （bits{23:22}+{20:16}+{13}+{7:1}、zfill 2）。
        ("r15", vec![(23, 22), (20, 16), (13, 13), (7, 1)], 2),
        // r13: `if (Rs {!=,==,>=,<=} #0) jump` の PC 相対
        // オフセット（bits{21}+{13}+{11:1}、zfill 2）。
        ("r13", vec![(21, 21), (13, 13), (11, 1)], 2),
        // r9: 複合 compare-jump・new-value compare-jump・
        // 転送ジャンプの PC 相対オフセット（bits{21:20}+{7:1}、
        // zfill 2）。
        ("r9", vec![(21, 20), (7, 1)], 2),
        // af11: allocframe のフレームサイズ（bits[10:0]、
        // zfill 3 でバイトオフセット）。
        ("af11", vec![(10, 0)], 3),
        // ---- HX8: ハードウェアループ ----
        // lr7: loopN のループ開始即値（bits{12:8}+{4:3} の
        // 7 ビット符号付きワードオフセット。zfill 2 でバイト
        // 距離、宣言パケットの先頭相対。extender 併合でも
        // 32 ビット PC 相対オフセットのまま）。
        ("lr7", vec![(12, 8), (4, 3)], 2),
        // lc10: loopN の反復回数 U10（bits{20:16}+{7:5}+{1:0}）。
        ("lc10", vec![(20, 16), (7, 5), (1, 0)], 0),
        // ---- HX9: HVX ----
        // vs4: vmem 基本形のオフセット s4（bits{13}+{10:8}、
        // ベクトル幅単位。V73 系の 128B 幅に実行側が掛ける）。
        ("vs4", vec![(13, 13), (10, 8)], 0),
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
    let vreg = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("vreg".to_string()),
        access,
    };
    let qreg = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("vpred".to_string()),
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
    // ---- HX6: ロード/ストアの形式 ----
    // サイズは全形式とも sz3/sz2 が供給し、構文・パターンから
    // 型名が落ちるため Insn 名はアドレッシングモードを指す
    // （Ref: SPEC-HEXAGON-PRM (V79) mem* 各節）。
    // Rd = memXX(Rs+#s11)。
    m.formats.push(fmt(
        "FLDR",
        &["s5", "d5", "sz3", "lu11"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("sz", "sz3"),
            val("imm", "lu11"),
        ],
    ));
    // Rd = memXX(Rx++#s4)。
    m.formats.push(fmt(
        "FLDPI",
        &["s5", "d5", "sz3", "ps4"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("x", "s5", Access::ReadWrite),
            val("sz", "sz3"),
            val("s4", "ps4"),
        ],
    ));
    // Rd = memXX(Rx++Mu) / brev / I:circ。
    m.formats.push(fmt(
        "FLDMU",
        &["s5", "d5", "sz3", "mu1"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("x", "s5", Access::ReadWrite),
            val("sz", "sz3"),
            val("mu", "mu1"),
        ],
    ));
    // Rd = memXX(Rx++#s4:circ(Mu))。
    m.formats.push(fmt(
        "FLDCI",
        &["s5", "d5", "sz3", "mu1", "ps4"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("x", "s5", Access::ReadWrite),
            val("sz", "sz3"),
            val("mu", "mu1"),
            val("s4", "ps4"),
        ],
    ));
    // Rd = memXX(gp+#s11) / memXX(##address)。
    m.formats.push(fmt(
        "FLDGP",
        &["d5", "sz3", "ldgp16"],
        vec![
            gpr("d", "d5", Access::Write),
            val("sz", "sz3"),
            val("imm", "ldgp16"),
        ],
    ));
    // Rd = memXX(Re=##address)（absolute-set。Re も更新）。
    m.formats.push(fmt(
        "FLDAS",
        &["s5", "d5", "sz3", "sa6"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("e", "s5", Access::ReadWrite),
            val("sz", "sz3"),
            val("imm", "sa6"),
        ],
    ));
    // Rd = memXX(Ru<<#u2+##address)（shifted absolute）。
    m.formats.push(fmt(
        "FLDSA",
        &["s5", "d5", "sz3", "u2", "sa6"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("u", "s5", Access::Read),
            val("sz", "sz3"),
            val("sh", "u2"),
            val("imm", "sa6"),
        ],
    ));
    // Rd = memXX(Rs+Ru<<#u2)（register offset）。
    m.formats.push(fmt(
        "FLDRO",
        &["s5", "t5", "d5", "sz3", "u2"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("u", "t5", Access::Read),
            val("sz", "sz3"),
            val("sh", "u2"),
        ],
    ));
    // if ([!]Pv[.new]) Rd = memXX(Rs+#u6)。
    m.formats.push(fmt(
        "FLDPQ",
        &["s5", "d5", "sz3", "lu6", "pv2l", "q2v"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("sz", "sz3"),
            val("u", "lu6"),
            preg("p", "pv2l", Access::Read),
            val("q", "q2v"),
        ],
    ));
    // if ([!]Pv[.new]) Rd = memXX(Rx++#s4)。
    m.formats.push(fmt(
        "FLDPQI",
        &["s5", "d5", "sz3", "ps4p", "pv2pi", "q2p"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("x", "s5", Access::ReadWrite),
            val("sz", "sz3"),
            val("s4", "ps4p"),
            preg("p", "pv2pi", Access::Read),
            val("q", "q2p"),
        ],
    ));
    // if ([!]Pv[.new]) Rd = memXX(Rs+Ru<<#u2)。
    m.formats.push(fmt(
        "FLDPQR",
        &["s5", "t5", "d5", "sz3", "u2", "pd2m", "q2r"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("u", "t5", Access::Read),
            val("sz", "sz3"),
            val("sh", "u2"),
            preg("p", "pd2m", Access::Read),
            val("q", "q2r"),
        ],
    ));
    // if ([!]Pv[.new]) Rd = memXX(#u6)（述語付 abs。実質
    // ## 拡張専用。u6 は {bits[20:16]}+{bit8}）。
    m.formats.push(fmt(
        "FLDABS",
        &["d5", "sz3", "u6a", "pv2pi", "q2p"],
        vec![
            gpr("d", "d5", Access::Write),
            val("sz", "sz3"),
            val("u", "u6a"),
            preg("p", "pv2pi", Access::Read),
            val("q", "q2p"),
        ],
    ));
    // Rd = memw_locked(Rs)（load-linked）。
    m.formats.push(fmt(
        "FLLL",
        &["s5", "d5"],
        vec![gpr("d", "d5", Access::Write), gpr("s", "s5", Access::Read)],
    ));
    // memw_locked(Rs,Pd) = Rt（store-conditional。Pd へ
    // 成功/失敗を書く）。
    m.formats.push(fmt(
        "FSCL",
        &["s5", "t5", "pd2"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            preg("p", "pd2", Access::Write),
        ],
    ));
    // memXX(Rs+#s11) = Rt。
    m.formats.push(fmt(
        "FSTR",
        &["s5", "t5", "sz3", "su11"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("imm", "su11"),
        ],
    ));
    // memXX(Rx++#s4) = Rt。
    m.formats.push(fmt(
        "FSTPI",
        &["s5", "t5", "sz3", "ps4s"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("s4", "ps4s"),
        ],
    ));
    // memXX(Rx++Mu) = Rt / brev / I:circ。
    m.formats.push(fmt(
        "FSTMU",
        &["s5", "t5", "sz3", "mu1"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("mu", "mu1"),
        ],
    ));
    // memXX(Rx++#s4:circ(Mu)) = Rt。
    m.formats.push(fmt(
        "FSTCI",
        &["s5", "t5", "sz3", "mu1", "ps4s"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("mu", "mu1"),
            val("s4", "ps4s"),
        ],
    ));
    // memXX(gp+#s11) = Rt / memXX(##address) = Rt。
    m.formats.push(fmt(
        "FSTGP",
        &["t5", "sz3", "stgp16"],
        vec![
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("imm", "stgp16"),
        ],
    ));
    // memXX(Re=##address) = Rt（absolute-set）。
    m.formats.push(fmt(
        "FSTAS",
        &["s5", "t5", "sz3", "ssa6"],
        vec![
            gpr("e", "s5", Access::ReadWrite),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("imm", "ssa6"),
        ],
    ));
    // memXX(Ru<<#u2+##address) = Rt（shifted absolute）。
    m.formats.push(fmt(
        "FSTSA",
        &["s5", "t5", "sz3", "u2a", "ssa6"],
        vec![
            gpr("u", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("sh", "u2a"),
            val("imm", "ssa6"),
        ],
    ));
    // memXX(Rs+Ru<<#u2) = Rt（register offset）。
    m.formats.push(fmt(
        "FSTRO",
        &["s5", "t5", "d5", "sz3", "u2"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("u", "t5", Access::Read),
            gpr("t", "d5", Access::Read),
            val("sz", "sz3"),
            val("sh", "u2"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(Rs+#u6) = Rt。
    m.formats.push(fmt(
        "FSTPQ",
        &["s5", "t5", "sz3", "su6", "pd2", "q2v"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("u", "su6"),
            preg("p", "pd2", Access::Read),
            val("q", "q2v"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(Rx++#s4) = Rt。
    m.formats.push(fmt(
        "FSTPQI",
        &["s5", "t5", "sz3", "ps4q", "pd2", "q2ps"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("s4", "ps4q"),
            preg("p", "pd2", Access::Read),
            val("q", "q2ps"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(Rs+Ru<<#u2) = Rt。
    m.formats.push(fmt(
        "FSTPQR",
        &["s5", "t5", "d5", "sz3", "u2", "pd2m", "q2r"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("u", "t5", Access::Read),
            gpr("t", "d5", Access::Read),
            val("sz", "sz3"),
            val("sh", "u2"),
            preg("p", "pd2m", Access::Read),
            val("q", "q2r"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(#u6) = Rt（述語付 abs。
    // u6 は {bits[17:16]}+{bits[6:3]}、qualifier は
    // {bit13=.new}+{bit2=!}）。
    m.formats.push(fmt(
        "FSTQABS",
        &["t5", "sz3", "u6b", "pd2", "q2a"],
        vec![
            gpr("t", "t5", Access::Read),
            val("sz", "sz3"),
            val("u", "u6b"),
            preg("p", "pd2", Access::Read),
            val("q", "q2a"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(#u6) = Rt.new（述語付 abs の
    // .new 値形。SRC は sz2[12:11]+nt2[10:9]+bit8=0）。
    m.formats.push(fmt(
        "FSTQABSNT",
        &["sz3", "sz2", "nt2", "u6b", "pd2", "q2a"],
        vec![
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("u", "u6b"),
            preg("p", "pd2", Access::Read),
            val("q", "q2a"),
        ],
    ));
    // memXX(Rs+#u6) = #s8（ストア即値形。サイズは sz2i の
    // 2 ビットで d はない）。
    m.formats.push(fmt(
        "FSTI",
        &["s5", "sz2i", "stiu6", "si8"],
        vec![
            gpr("s", "s5", Access::Read),
            val("sz", "sz2i"),
            val("off", "stiu6"),
            val("imm", "si8"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(Rs+#u6) = #s6。
    m.formats.push(fmt(
        "FSTIP",
        &["s5", "sz2i", "stiu6", "si6", "pd2m", "q2st"],
        vec![
            gpr("s", "s5", Access::Read),
            val("sz", "sz2i"),
            val("off", "stiu6"),
            val("imm", "si6"),
            preg("p", "pd2m", Access::Read),
            val("q", "q2st"),
        ],
    ));
    // memXX(Rs+#u6) op= #u5 / op= Rt（read-modify-write）。
    m.formats.push(fmt(
        "FMOPI",
        &["s5", "sz3m", "stiu6", "mo2", "d5"],
        vec![
            gpr("s", "s5", Access::Read),
            val("sz", "sz3m"),
            val("off", "stiu6"),
            val("op", "mo2"),
            val("imm", "d5"),
        ],
    ));
    m.formats.push(fmt(
        "FMOPR",
        &["s5", "sz3m", "stiu6", "mo2", "d5"],
        vec![
            gpr("s", "s5", Access::Read),
            val("sz", "sz3m"),
            val("off", "stiu6"),
            val("op", "mo2"),
            gpr("t", "d5", Access::Read),
        ],
    ));
    // ---- .new ストア値形 ----
    // [23:21] は通常ストアと共用の sz3 で、値 101 が .new を
    // 指す。宣言の where で sz3==5 を固定して通常形と排他にする。
    // サイズは sz2（b=00 h=01 w=10、d はない）。
    // memXX(Rs+#s11) = Rt.new。
    m.formats.push(fmt(
        "FSTNT",
        &["s5", "sz3", "sz2", "nt2", "su11"],
        vec![
            gpr("s", "s5", Access::Read),
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("imm", "su11"),
        ],
    ));
    // memXX(Rx++#s4) = Rt.new。
    m.formats.push(fmt(
        "FSTPNT",
        &["s5", "sz3", "sz2", "nt2", "ps4s"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("s4", "ps4s"),
        ],
    ));
    // memXX(Rx++Mu) = Rt.new / brev / I:circ。
    m.formats.push(fmt(
        "FSTMNT",
        &["s5", "sz3", "sz2", "nt2", "mu1"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("mu", "mu1"),
        ],
    ));
    // memXX(Rx++#s4:circ(Mu)) = Rt.new。
    m.formats.push(fmt(
        "FSTCNT",
        &["s5", "sz3", "sz2", "nt2", "mu1", "ps4s"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("mu", "mu1"),
            val("s4", "ps4s"),
        ],
    ));
    // memXX(gp+#s16)/memXX(##address) = Rt.new。
    m.formats.push(fmt(
        "FSTGNT",
        &["sz3", "sz2", "nt2", "stgp16"],
        vec![
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("imm", "stgp16"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(Rs+#u6) = Rt.new。
    m.formats.push(fmt(
        "FSTQNT",
        &["s5", "sz3", "sz2", "nt2", "su6", "pd2", "q2v"],
        vec![
            gpr("s", "s5", Access::Read),
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("u", "su6"),
            preg("p", "pd2", Access::Read),
            val("q", "q2v"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(Rx++#s4) = Rt.new。
    m.formats.push(fmt(
        "FSTPQINT",
        &["s5", "sz3", "sz2", "nt2", "ps4q", "pd2", "q2ps"],
        vec![
            gpr("x", "s5", Access::ReadWrite),
            val("sz3", "sz3"),
            val("sz", "sz2"),
            val("nt", "nt2"),
            val("s4", "ps4q"),
            preg("p", "pd2", Access::Read),
            val("q", "q2ps"),
        ],
    ));
    // memXX(Rs+Ru<<#u2) = Rt.new。
    m.formats.push(fmt(
        "FSTRNT",
        &["s5", "t5", "sz3", "sz2r", "nt2r", "u2"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("u", "t5", Access::Read),
            val("sz3", "sz3"),
            val("sz", "sz2r"),
            val("nt", "nt2r"),
            val("sh", "u2"),
        ],
    ));
    // if ([!]Pv[.new]) memXX(Rs+Ru<<#u2) = Rt.new。
    m.formats.push(fmt(
        "FSTQRNT",
        &["s5", "t5", "sz3", "sz2r", "nt2r", "u2", "pd2m", "q2r"],
        vec![
            gpr("s", "s5", Access::Read),
            gpr("u", "t5", Access::Read),
            val("sz3", "sz3"),
            val("sz", "sz2r"),
            val("nt", "nt2r"),
            val("sh", "u2"),
            preg("p", "pd2m", Access::Read),
            val("q", "q2r"),
        ],
    ));
    // jump/call の PC 相対形。
    m.formats
        .push(fmt("FJ", &["r22"], vec![val("target", "r22")]));
    // trap0(#u8)。
    m.formats
        .push(fmt("FTRAP", &["tu8"], vec![val("u", "tu8")]));
    // trap1(Rx,#u8)。
    m.formats.push(fmt(
        "FTRAP1",
        &["s5", "tu8"],
        vec![gpr("x", "s5", Access::Read), val("u", "tu8")],
    ));
    // pause(#u10)。
    m.formats
        .push(fmt("FPAUSE", &["pu10"], vec![val("u", "pu10")]));
    // jumpr/callr/jumprh/callrh/hintjr のレジスタ形。
    m.formats
        .push(fmt("FJR", &["s5"], vec![gpr("s", "s5", Access::Read)]));
    // ---- HX7: 分岐・frame 系の形式 ----
    // if ([!]Pu[.new]) jump/call。末尾 2 オペランドは (述語, 否定)。
    m.formats.push(fmt(
        "FJ15",
        &["r15", "jpv", "jn21"],
        vec![
            val("target", "r15"),
            preg("p", "jpv", Access::Read),
            val("q", "jn21"),
        ],
    ));
    // if ([!]Pu[.new]) jumpr/callr。末尾 2 オペランドは (述語, 否定)。
    m.formats.push(fmt(
        "FJRPQ",
        &["s5", "jpv", "jn21"],
        vec![
            gpr("s", "s5", Access::Read),
            preg("p", "jpv", Access::Read),
            val("q", "jn21"),
        ],
    ));
    // if (Rs {!=,==,>=,<=} #0) jump のレジスタ条件形。
    m.formats.push(fmt(
        "FRCJ",
        &["s5", "r13"],
        vec![gpr("s", "s5", Access::Read), val("target", "r13")],
    ));
    // 複合 compare-jump の即値形（pX = cmp.*(Rs,#U5);
    // if ([!]pX.new) jump が 1 命令の形。否定は bit22）。
    m.formats.push(fmt(
        "FCJI",
        &["j4", "t5", "jpd25", "jn22", "r9"],
        vec![
            gpr("s", "j4", Access::Read),
            val("u", "t5"),
            preg("d", "jpd25", Access::Write),
            val("q", "jn22"),
            val("target", "r9"),
        ],
    ));
    // 複合 compare-jump の固定即値形（cmp.*(Rs,#-1)/tstbit。
    // 即値桁は使わない）。
    m.formats.push(fmt(
        "FCJS",
        &["j4", "jpd25", "jn22", "r9"],
        vec![
            gpr("s", "j4", Access::Read),
            preg("d", "jpd25", Access::Write),
            val("q", "jn22"),
            val("target", "r9"),
        ],
    ));
    // 複合 compare-jump のレジスタ形（pX = cmp.*(Rs,Rt)）。
    m.formats.push(fmt(
        "FCJR",
        &["j4", "j4t", "jpd12", "jn22", "r9"],
        vec![
            gpr("s", "j4", Access::Read),
            gpr("t", "j4t", Access::Read),
            preg("d", "jpd12", Access::Write),
            val("q", "jn22"),
            val("target", "r9"),
        ],
    ));
    // new-value compare-jump（slot 0 専用の .new 値比較形。
    // U5/Rt はどちらも bits[12:8] の t5 桁）。
    m.formats.push(fmt(
        "FNVJ",
        &["nt3", "t5", "jn22", "r9"],
        vec![
            val("nt", "nt3"),
            gpr("t", "t5", Access::Read),
            val("q", "jn22"),
            val("target", "r9"),
        ],
    ));
    // new-value compare-jump の即値形。t5 桁はレジスタではなく
    // 比較即値。
    m.formats.push(fmt(
        "FNVJI",
        &["nt3", "t5", "jn22", "r9"],
        vec![
            val("nt", "nt3"),
            val("t", "t5"),
            val("q", "jn22"),
            val("target", "r9"),
        ],
    ));
    // 転送ジャンプ `Rd=#U6; jump` / `Rd=Rs; jump`。
    m.formats.push(fmt(
        "FTJI",
        &["j4", "u6t", "r9"],
        vec![
            gpr("d", "j4", Access::Write),
            val("u", "u6t"),
            val("target", "r9"),
        ],
    ));
    m.formats.push(fmt(
        "FTJR",
        &["j4", "j4t", "r9"],
        vec![
            gpr("s", "j4", Access::Read),
            gpr("d", "j4t", Access::Write),
            val("target", "r9"),
        ],
    ));
    // Rdd = deallocframe(Rs):raw。
    m.formats.push(fmt(
        "FDCF",
        &["s5", "d5"],
        vec![gpr("dd", "d5", Access::Write), gpr("s", "s5", Access::Read)],
    ));
    // if ([!]Pv[.new]) Rdd = dealloc_return(Rs):raw。末尾 2
    // オペランドは (述語, 否定)。
    m.formats.push(fmt(
        "FDCP",
        &["s5", "d5", "jpv", "jn13"],
        vec![
            gpr("dd", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            preg("p", "jpv", Access::Read),
            val("q", "jn13"),
        ],
    ));
    // allocframe(Rx,#u11:3):raw。
    m.formats.push(fmt(
        "FAF",
        &["s5", "af11"],
        vec![gpr("x", "s5", Access::ReadWrite), val("u", "af11")],
    ));
    // ---- HX8: ハードウェアループ宣言 ----
    // loopN(start,#u10)（start は宣言パケット先頭相対の
    // PC 相対オフセット。## 併合でも PC 相対のまま）。
    m.formats.push(fmt(
        "FLOOPI",
        &["lr7", "lc10"],
        vec![val("target", "lr7"), val("imm", "lc10")],
    ));
    // loopN(start,Rs)。
    m.formats.push(fmt(
        "FLOOPR",
        &["lr7", "s5"],
        vec![val("target", "lr7"), gpr("s", "s5", Access::Read)],
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
    // Rd = add(#s6,mpyi(Rs,Rt)) の複合積和形（s6 は xa6）。
    m.formats.push(fmt(
        "FAMPY",
        &["s5", "t5", "d5", "xa6"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            val("imm", "xa6"),
        ],
    ));
    // Rd = add(#s6,mpyi(Rs,#s6))（mpyi の第 2 ソースも即値。
    // Rd は bits[12:8] の珍しい位置）。
    m.formats.push(fmt(
        "FAMPYI",
        &["s5", "t5", "xa6", "yi6"],
        vec![
            gpr("d", "t5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "xa6"),
            val("imm2", "yi6"),
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
    m.formats
        .push(dx("DXFR", &["dprd3"], vec![val("pred", "dprd3")]));
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
        vec![
            dxrd("s", "dxs", Access::Read),
            val("u4", "du4l"),
            val("i", "du1"),
        ],
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
        vec![
            dxrd("dd", "ddp", Access::Write),
            dxrd("s", "dxs", Access::Read),
        ],
    ));

    // ---- HX9: HVX の形式 ----
    // 実符号は参照アセンブラ（V73 + hvx）との照合済み。ベクトル
    // レジスタは d5=デスティネーション、t5=第 1 ソース、s5=第 2
    // ソースの配置が基本。vmem の即値はベクトル幅単位。
    // Ref: SPEC-HEXAGON-PRM (V79), 80-N2040-61 (HVX).
    // Vd = vmem(Rt+#s4) / :nt / vmemu(Rt)。
    m.formats.push(fmt(
        "FVLD",
        &["d5", "s5", "vs4"],
        vec![
            vreg("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "vs4"),
        ],
    ));
    // vmem(Rt+#s4)=Vs / :nt / vmemu(Rt)=Vs。
    m.formats.push(fmt(
        "FVST",
        &["d5", "s5", "vs4"],
        vec![
            vreg("t", "d5", Access::Read),
            gpr("s", "s5", Access::Read),
            val("imm", "vs4"),
        ],
    ));
    // Vd = vmem(Rt++#s3)。
    m.formats.push(fmt(
        "FVLDPI",
        &["d5", "s5", "vs3"],
        vec![
            vreg("d", "d5", Access::Write),
            gpr("x", "s5", Access::ReadWrite),
            val("s4", "vs3"),
        ],
    ));
    // vmem(Rt++#s3)=Vs。
    m.formats.push(fmt(
        "FVSTPI",
        &["d5", "s5", "vs3"],
        vec![
            vreg("t", "d5", Access::Read),
            gpr("x", "s5", Access::ReadWrite),
            val("s4", "vs3"),
        ],
    ));
    // Vd = vmem(Rt++Mu)。
    m.formats.push(fmt(
        "FVLDMU",
        &["d5", "s5", "mu1"],
        vec![
            vreg("d", "d5", Access::Write),
            gpr("x", "s5", Access::ReadWrite),
            val("mu", "mu1"),
        ],
    ));
    // vmem(Rt++Mu)=Vs。
    m.formats.push(fmt(
        "FVSTMU",
        &["d5", "s5", "mu1"],
        vec![
            vreg("t", "d5", Access::Read),
            gpr("x", "s5", Access::ReadWrite),
            val("mu", "mu1"),
        ],
    ));
    // if ([!]Qv) vmem(Rt+#s4)=Vs（:nt を含む）。
    m.formats.push(fmt(
        "FVSTPQ",
        &["d5", "s5", "vs4", "vqp", "vq1"],
        vec![
            vreg("t", "d5", Access::Read),
            gpr("s", "s5", Access::Read),
            val("imm", "vs4"),
            qreg("p", "vqp", Access::Read),
            val("q", "vq1"),
        ],
    ));
    // Vd = op(Vu,Vv) / Qd = vcmp.*(Vu,Vv)（3 オペランド形）。
    m.formats.push(fmt(
        "FV3",
        &["d5", "s5", "t5"],
        vec![
            vreg("d", "d5", Access::Write),
            vreg("u", "t5", Access::Read),
            vreg("v", "s5", Access::Read),
        ],
    ));
    // Vdd = op(Vu,Vv)（ペアデスティネーション。d5 は偶数側）。
    m.formats.push(fmt(
        "FVDD",
        &["d5", "s5", "t5"],
        vec![
            vreg("dd", "d5", Access::Write),
            vreg("u", "t5", Access::Read),
            vreg("v", "s5", Access::Read),
        ],
    ));
    // Vd = op(Vu)（vmov 等の単一ソース形）。
    m.formats.push(fmt(
        "FV2",
        &["d5", "t5"],
        vec![
            vreg("d", "d5", Access::Write),
            vreg("u", "t5", Access::Read),
        ],
    ));
    // Qd = op(Qs,Qt)（q 論理の 2 ソース形）。
    m.formats.push(fmt(
        "FVQ",
        &["pd2", "t5", "vqt"],
        vec![
            qreg("qd", "pd2", Access::Write),
            qreg("s", "t5", Access::Read),
            qreg("t", "vqt", Access::Read),
        ],
    ));
    // Qd = op(Qs)（q 論理の単一ソース形）。
    m.formats.push(fmt(
        "FVQ1",
        &["pd2", "t5"],
        vec![
            qreg("qd", "pd2", Access::Write),
            qreg("s", "t5", Access::Read),
        ],
    ));
    // Qd = vcmp.*(Vu,Vv)。
    m.formats.push(fmt(
        "FVCMP",
        &["pd2", "s5", "t5"],
        vec![
            qreg("qd", "pd2", Access::Write),
            vreg("u", "t5", Access::Read),
            vreg("v", "s5", Access::Read),
        ],
    ));
    // Vd = op(Rs)（vsplat/vinsert の GPR→ベクトル形）。
    m.formats.push(fmt(
        "FVG",
        &["d5", "s5"],
        vec![vreg("d", "d5", Access::Write), gpr("s", "s5", Access::Read)],
    ));
    // Vd = vand(Qv,Vu)。
    m.formats.push(fmt(
        "FVQV",
        &["d5", "vqt", "t5"],
        vec![
            vreg("d", "d5", Access::Write),
            qreg("p", "vqt", Access::Read),
            vreg("u", "t5", Access::Read),
        ],
    ));

    // ---- HX11: 条件付き ALU ----
    // `if ([!]Pu[.new]) Rd = op(Rs,Rt)` / `Rdd = combine(Rs,Rt)`。
    // 述語は pd2m（bits[6:5]）、qualifier は q2c
    // （bit7=否定、bit13=.new）。実符号照合済み。
    // Ref: SPEC-HEXAGON-PRM (V79) conditional instructions.
    m.formats.push(fmt(
        "FCPQ",
        &["s5", "t5", "d5", "pd2m", "q2c"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            gpr("t", "t5", Access::Read),
            preg("p", "pd2m", Access::Read),
            val("q", "q2c"),
        ],
    ));
    // `if ([!]Pu[.new]) Rd = {sxtb,zxtb,sxth,zxth}(Rs)`。
    // 述語は zpd98（bits[9:8]）、qualifier は zq1110
    // （bit11=否定、bit10=.new——ビット順が通常の q と逆）。
    // bits[14:13]=11 が条件形の識別子（無条件形は bit13=0）。
    // 実符号照合済み。
    m.formats.push(fmt(
        "FCZX",
        &["s5", "d5", "zpd98", "zq1110"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            preg("p", "zpd98", Access::Read),
            val("q", "zq1110"),
        ],
    ));
    // `if ([!]Pu[.new]) Rd = add(Rs,#s8)`。述語は pu2i
    // （bits[22:21]）、qualifier は q2d（bit23=否定、
    // bit13=.new）。実符号照合済み。
    m.formats.push(fmt(
        "FCAI",
        &["s5", "d5", "ai8", "pu2i", "q2d"],
        vec![
            gpr("d", "d5", Access::Write),
            gpr("s", "s5", Access::Read),
            val("imm", "ai8"),
            preg("p", "pu2i", Access::Read),
            val("q", "q2d"),
        ],
    ));
    // `if ([!]Pu[.new]) Rd = #s12`（## 拡張可能）。qualifier は
    // q2d、即値は ci12（bits{19:16}+{12:5}）。実符号照合済み。
    m.formats.push(fmt(
        "FCI12",
        &["d5", "ci12", "pu2i", "q2d"],
        vec![
            gpr("d", "d5", Access::Write),
            val("imm", "ci12"),
            preg("p", "pu2i", Access::Read),
            val("q", "q2d"),
        ],
    ));

    let ins =
        |name: &str, format: &str, pattern: &str, when: Pred, syntax: &str, timing: &str| Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when,
            wheres: vec![],
            syntax: syntax.to_string(),
        timing: timing.to_string(),
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
        (
            "immext",
            "FEXT",
            "0000............................",
            "immext #{imm}",
            "misc",
        ),
        // nop。Ref: ALU32 nop.
        (
            "nop",
            "FN",
            "01111111........ ................",
            "nop",
            "alu",
        ),
        // Rd = add(Rs,#s16)。Ref: ALU32 add.
        (
            "add_ri",
            "FRI16",
            "1011............................",
            "add {d},{s},#{imm}",
            "alu",
        ),
        // Rd = add(Rs,Rt)。Ref: ALU32 add.
        (
            "add_rr",
            "FRR",
            "11110011000.....................",
            "add {d},{s},{t}",
            "alu",
        ),
        // Rd = #s16。Ref: ALU32 transfer immediate.
        (
            "eq_s16",
            "FS16",
            "01111000........................",
            "{d}=#{imm}",
            "alu",
        ),
        // Rd = Rs。Ref: ALU32 transfer register.
        (
            "mov_rr",
            "FRS",
            "01110000011.......0.............",
            "{d}={s}",
            "alu",
        ),
        // Rx.L = #u16 / Rx.H = #u16。Ref: ALU32 transfer immediate.
        (
            "immlo",
            "FX16",
            "01110001........................",
            "{x}.l=#{imm}",
            "alu",
        ),
        (
            "immhi",
            "FX16",
            "01110010........................",
            "{x}.h=#{imm}",
            "alu",
        ),
        // jump/call の PC 相対形。Ref: J jump/call.
        (
            "jump_pcrel",
            "FJ",
            "0101100.........................",
            "jump #{target}",
            "branch",
        ),
        (
            "call_pcrel",
            "FJ",
            "0101101........................0",
            "call #{target}",
            "branch",
        ),
        // jumpr/callr のレジスタ形。Ref: J indirect jump/call.
        (
            "jumpr",
            "FJR",
            "01010010100.....................",
            "jumpr {s}",
            "branch",
        ),
        (
            "callr",
            "FJR",
            "01010000101.....................",
            "callr {s}",
            "branch",
        ),
        // ---- HX7: 分岐・frame・system ----
        // if ([!]Pu) jump（:t/:nt の予測桁は意味論を変えない）。
        // Ref: J jump to address.
        (
            "jump_pq",
            "FJ15",
            "01011100............0...........",
            "if(...) jump #{target}",
            "branch",
        ),
        // if ([!]Pu.new) jump。
        (
            "jump_pqn",
            "FJ15",
            "01011100............1...........",
            "if(...new) jump #{target}",
            "branch",
        ),
        // if ([!]Pu) call（.new 形はない）。Ref: J call subroutine.
        (
            "call_pq",
            "FJ15",
            "01011101............0...........",
            "if(...) call #{target}",
            "branch",
        ),
        // if ([!]Pu[.new]) jumpr（bit11 が .new、bit12 が :t
        // ヒント、bit21 が否定）。Ref: J jump to address from reg.
        (
            "jumpr_pq",
            "FJRPQ",
            "0101001101..........0...........",
            "if(...) jumpr {s}",
            "branch",
        ),
        (
            "jumpr_pqn",
            "FJRPQ",
            "0101001101..........1...........",
            "if(...new) jumpr {s}",
            "branch",
        ),
        // if ([!]Pu) callr（.new 形はないので bit11 = 0 固定）。
        (
            "callr_pq",
            "FJRPQ",
            "0101000100..........0...........",
            "if(...) callr {s}",
            "branch",
        ),
        // hintjr は間接ジャンプ先の予測ヒント。建築状態を変えない。
        (
            "hintjr",
            "FJR",
            "01010010101.....................",
            "hintjr {s}",
            "branch",
        ),
        // if (Rs {!=,>=,==,<=} #0) jump。Ref: J register-cond jump.
        (
            "rcj_ne",
            "FRCJ",
            "0110000100......................",
            "if({s}!=#0) jump #{target}",
            "branch",
        ),
        (
            "rcj_ge",
            "FRCJ",
            "0110000101......................",
            "if({s}>=#0) jump #{target}",
            "branch",
        ),
        (
            "rcj_eq",
            "FRCJ",
            "0110000110......................",
            "if({s}==#0) jump #{target}",
            "branch",
        ),
        (
            "rcj_le",
            "FRCJ",
            "0110000111......................",
            "if({s}<=#0) jump #{target}",
            "branch",
        ),
        // 複合 compare-jump。Ref: J compare-and-jump.
        (
            "cj_eqi",
            "FCJI",
            "000100.00.......................",
            "cmp.eq({s},#{u})/jump #{target}",
            "branch",
        ),
        (
            "cj_gti",
            "FCJI",
            "000100.01.......................",
            "cmp.gt({s},#{u})/jump #{target}",
            "branch",
        ),
        (
            "cj_gtui",
            "FCJI",
            "000100.10.......................",
            "cmp.gtu({s},#{u})/jump #{target}",
            "branch",
        ),
        (
            "cj_eqi1",
            "FCJS",
            "000100.11.............00........",
            "cmp.eq({s},#-1)/jump #{target}",
            "branch",
        ),
        (
            "cj_gti1",
            "FCJS",
            "000100.11.............01........",
            "cmp.gt({s},#-1)/jump #{target}",
            "branch",
        ),
        (
            "cj_tst",
            "FCJS",
            "000100.11.............11........",
            "tstbit({s},#0)/jump #{target}",
            "branch",
        ),
        (
            "cj_eqr",
            "FCJR",
            "000101000.......................",
            "cmp.eq({s},{t})/jump #{target}",
            "branch",
        ),
        (
            "cj_gtr",
            "FCJR",
            "000101001.......................",
            "cmp.gt({s},{t})/jump #{target}",
            "branch",
        ),
        (
            "cj_gtur",
            "FCJR",
            "000101010.......................",
            "cmp.gtu({s},{t})/jump #{target}",
            "branch",
        ),
        // new-value compare-jump（slot 0 専用。bits[27:22] が
        // 比較選択+否定）。
        // Ref: J jump to address condition on new register value.
        (
            "nvj_eqr",
            "FNVJ",
            "001000000.......................",
            "if(cmp.eq(r.new,{t})) jump #{target}",
            "branch",
        ),
        (
            "nvj_gtr",
            "FNVJ",
            "001000001.......................",
            "if(cmp.gt(r.new,{t})) jump #{target}",
            "branch",
        ),
        (
            "nvj_gtur",
            "FNVJ",
            "001000010.......................",
            "if(cmp.gtu(r.new,{t})) jump #{target}",
            "branch",
        ),
        (
            "nvj_gtrr",
            "FNVJ",
            "001000011.......................",
            "if(cmp.gt({t},r.new)) jump #{target}",
            "branch",
        ),
        (
            "nvj_gturr",
            "FNVJ",
            "001000100.......................",
            "if(cmp.gtu({t},r.new)) jump #{target}",
            "branch",
        ),
        (
            "nvj_eqi",
            "FNVJI",
            "001001000.......................",
            "if(cmp.eq(r.new,#{t})) jump #{target}",
            "branch",
        ),
        (
            "nvj_gti",
            "FNVJI",
            "001001001.......................",
            "if(cmp.gt(r.new,#{t})) jump #{target}",
            "branch",
        ),
        (
            "nvj_gtui",
            "FNVJI",
            "001001010.......................",
            "if(cmp.gtu(r.new,#{t})) jump #{target}",
            "branch",
        ),
        (
            "nvj_tst",
            "FNVJ",
            "001001011.......................",
            "if(tstbit(r.new,#0)) jump #{target}",
            "branch",
        ),
        (
            "nvj_eqi1",
            "FNVJ",
            "001001100.......................",
            "if(cmp.eq(r.new,#-1)) jump #{target}",
            "branch",
        ),
        (
            "nvj_gti1",
            "FNVJ",
            "001001101.......................",
            "if(cmp.gt(r.new,#-1)) jump #{target}",
            "branch",
        ),
        // 転送ジャンプ `Rd=#U6; jump` / `Rd=Rs; jump`。
        // Ref: J transfer and jump.
        (
            "tj_i",
            "FTJI",
            "00010110........................",
            "{d}=#{u};jump #{target}",
            "branch",
        ),
        (
            "tj_r",
            "FTJR",
            "00010111........................",
            "{d}={s};jump #{target}",
            "branch",
        ),
        // frame の構築・解除・復帰。Ref: stack instructions.
        (
            "allocframe",
            "FAF",
            "10100000100.......000...........",
            "allocframe {x},#{u}",
            "store",
        ),
        (
            "deallocframe",
            "FDCF",
            "10010000000.......0.............",
            "{dd}=deallocframe({s})",
            "load",
        ),
        (
            "deallocret",
            "FDCF",
            "10010110000.......0000..........",
            "{dd}=dealloc_return({s})",
            "branch",
        ),
        (
            "deallocret_pq",
            "FDCP",
            "10010110000........100..........",
            "if(...) {dd}=dealloc_return({s})",
            "branch",
        ),
        (
            "deallocret_pqn",
            "FDCP",
            "10010110000.........10..........",
            "if(...new) {dd}=dealloc_return({s})",
            "branch",
        ),
        // trap0(#u8)。ユーザモードの #1 が OS 呼出し。trap1 は
        // monitor 系のトラップで、ユーザモードでは例外として
        // OS パーソナリティに委ねる（code = 0x100|u）。trap2 は
        // PRM に存在しない。pause はタイミングヒント（solo 命令、
        // 建築状態を変えない）。brkpt/unpause/icinva/isync/
        // dcfetch/l2fetch は語彙外（復号不能=illegal）。
        // Gap: GAP-0075（ヒント・フェンス・語彙外・特権の近似）
        // Ref: system instructions.
        (
            "trap0",
            "FTRAP",
            "0101010000......................",
            "trap0(#{u})",
            "system",
        ),
        (
            "trap1",
            "FTRAP1",
            "0101010010......................",
            "trap1({x},#{u})",
            "system",
        ),
        (
            "pause",
            "FPAUSE",
            "0101010001......................",
            "pause(#{u})",
            "system",
        ),
        // HX11: barrier/syncht。メモリ順序のフェンスで、musl の
        // a_barrier（stdio ロックのリリースフェンス）が使う。
        // 単一コア・逐次実行のエミュレータでは no-op。
        (
            "barrier",
            "FN",
            "1010100000000000..0.............",
            "barrier",
            "system",
        ),
        (
            "syncht",
            "FN",
            "1010100001000000..0.............",
            "syncht",
            "system",
        ),
        // Rd = Cs / Cd = Rs。Ref: CR control register transfer.
        (
            "rdcr",
            "FRDC",
            "01101010000.....................",
            "{d}={c}",
            "system",
        ),
        (
            "wrcr",
            "FWRC",
            "01100010001.....................",
            "{d}={s}",
            "system",
        ),
        // Pd = cmp.eq/gt(Rs,Rt)。Ref: ALU32 compare.
        (
            "cmpeq_rr",
            "FCMP",
            "11110010000.............000000..",
            "{d}=cmp.eq({s},{t})",
            "alu",
        ),
        (
            "cmpgt_rr",
            "FCMP",
            "11110010010.............000000..",
            "{d}=cmp.gt({s},{t})",
            "alu",
        ),
        // ---- HX8: ハードウェアループ（CR クラスで slot 3）。
        // loopN(start,#u10) / loopN(start,Rs)。start は宣言
        // パケットの先頭相対（## 併合でも PC 相対）、count は
        // LCn に入る。loop0 が内側、loop1 が外側のループ。
        // Ref: hardware loops / instruction class CR.
        (
            "loop0i",
            "FLOOPI",
            "01101001000.......0..........0..",
            "loop0(#{target},#{imm})",
            "branch",
        ),
        (
            "loop1i",
            "FLOOPI",
            "01101001001.......0..........0..",
            "loop1(#{target},#{imm})",
            "branch",
        ),
        (
            "loop0r",
            "FLOOPR",
            "01100000000.......0.....000..000",
            "loop0(#{target},{s})",
            "branch",
        ),
        (
            "loop1r",
            "FLOOPR",
            "01100000001.......0.....000..000",
            "loop1(#{target},{s})",
            "branch",
        ),
    ] {
        m.insns
            .push(ins(name, format, pattern, base(), syntax, timing));
    }

    // ---- HX6: ロード/ストア ----
    // アクセスサイズはパターンではなく sz3/sz2 桁が運び、Insn 名は
    // アドレッシングモードを指す（型名でなく中身の契約）。実符号は
    // 参照アセンブラ（V73 プロファイル）と照合済み。
    // - LD（ICLASS9 = LD{0,1}、GP 相対は ICLASS4）: 基底+即値・
    //   post-inc 即値/M0M1/円環/brev・GP 相対・absolute-set・
    //   shifted-abs・reg-offset・述語付き。
    // - ST（ICLASS10 = ST{0}、GP 相対・述語付きは ICLASS4）: 同構成 +
    //   ストア即値形（ICLASS3）・memop（read-modify-write）・
    //   `.new` ストア値（sz3=101 + sz2 + Nt）。
    // - sz3 はロード 0-4,6、ストア 0,2,3(hh),4,6、memop/ストア
    //   即値形は 0,2,4。`.new` 値形は sz3=101 で通常形と排他
    //   （wheres で切る）。
    // Ref: SPEC-HEXAGON-PRM (V79) mem* / memop* / addressing modes.
    let weq = |f: &str, v: u128| WhereClause {
        field: f.to_string(),
        op: WhereOp::Eq,
        rhs: WhereRhs::Lit(v),
    };
    // LD: 許容サイズ 0,1,2,3,4,6（5,7 を禁止）。
    const LD_NE: &[u128] = &[5, 7];
    // ST: 許容サイズ 0,2,3(memf),4,6（1,5,7 を禁止）。
    const ST_NE: &[u128] = &[1, 5, 7];
    for (name, format, pattern, ne, syntax, timing) in [
        // Rd = memXX(Rs+#s11)。
        (
            "ld_ri",
            "FLDR",
            "10010..1........................",
            LD_NE,
            "{d}=memx({s}+#{imm})",
            "load",
        ),
        // Rd = memXX(Rx++#s4)。
        (
            "ld_pi",
            "FLDPI",
            "10011011..........00............",
            LD_NE,
            "{d}=memx({x}++#{s4})",
            "load",
        ),
        // Rd = memXX(Rx++Mu)。
        (
            "ld_pr",
            "FLDMU",
            "10011101...........0....0.......",
            LD_NE,
            "{d}=memx({x}++m{mu})",
            "load",
        ),
        // Rd = memXX(Rx++Mu:brev)。
        (
            "ld_pbr",
            "FLDMU",
            "10011111...........0....0.......",
            LD_NE,
            "{d}=memx({x}++m{mu}:brev)",
            "load",
        ),
        // Rd = memXX(Rx++#s4:circ(Mu))。
        (
            "ld_pci",
            "FLDCI",
            "10011001...........0..0.........",
            LD_NE,
            "{d}=memx({x}++#{s4}:circ(m{mu}))",
            "load",
        ),
        // Rd = memXX(Rx++I:circ(Mu))。
        (
            "ld_pcr",
            "FLDMU",
            "10011001...........0..1.0.......",
            LD_NE,
            "{d}=memx({x}++i:circ(m{mu}))",
            "load",
        ),
        // Rd = memXX(gp+#s16) / memXX(##imm)。
        (
            "ld_gp",
            "FLDGP",
            "01001..1........................",
            LD_NE,
            "{d}=memx(gp+#{imm})",
            "load",
        ),
        // Rd = memXX(Re=##imm)。
        (
            "ld_as",
            "FLDAS",
            "10011011..........01............",
            LD_NE,
            "{d}=memx({e}=##{imm})",
            "load",
        ),
        // Rd = memXX(Ru<<#u2+##imm)。
        (
            "ld_sa",
            "FLDSA",
            "10011101...........1............",
            LD_NE,
            "{d}=memx({u}<<#{sh}+##{imm})",
            "load",
        ),
        // Rd = memXX(Rs+Ru<<#u2)。
        (
            "ld_rro",
            "FLDRO",
            "00111010........................",
            LD_NE,
            "{d}=memx({s}+{u}<<#{sh})",
            "load",
        ),
        // if ([!]Pv[.new]) Rd = memXX(Rs+#u6)。
        (
            "ld_pq",
            "FLDPQ",
            "01000..1..........0.............",
            LD_NE,
            "{d}=memx({s}+#{u})",
            "load",
        ),
        // if ([!]Pv[.new]) Rd = memXX(Rx++#s4)。
        (
            "ld_pq_pi",
            "FLDPQI",
            "10011011..........1.............",
            LD_NE,
            "{d}=memx({x}++#{s4})",
            "load",
        ),
        // if ([!]Pv[.new]) Rd = memXX(Rs+Ru<<#u2)。
        (
            "ld_pq_ro",
            "FLDPQR",
            "001100..........................",
            LD_NE,
            "{d}=memx({s}+{u}<<#{sh})",
            "load",
        ),
        // if ([!]Pv[.new]) Rd = memXX(#u6)（abs。## 拡張前提）。
        (
            "ld_pq_abs",
            "FLDABS",
            "10011111..........1.....1.......",
            LD_NE,
            "{d}=memx(#{u})",
            "load",
        ),
    ] {
        m.insns.push({
            let mut i = ins(name, format, pattern, base(), syntax, timing);
            for &v in ne {
                i.wheres.push(WhereClause {
                    field: "sz3".to_string(),
                    op: WhereOp::Ne,
                    rhs: WhereRhs::Lit(v),
                });
            }
            i
        });
    }
    for (name, format, pattern, ne, syntax, timing) in [
        // memXX(Rs+#s11) = Rt。
        (
            "st_ri",
            "FSTR",
            "10100..1........................",
            ST_NE,
            "memx({s}+#{imm})={t}",
            "store",
        ),
        // memXX(Rx++#s4) = Rt。
        (
            "st_pi",
            "FSTPI",
            "10101011..........0.....0.....0.",
            ST_NE,
            "memx({x}++#{s4})={t}",
            "store",
        ),
        // memXX(Rx++Mu) = Rt。
        (
            "st_pr",
            "FSTMU",
            "10101101................0.......",
            ST_NE,
            "memx({x}++m{mu})={t}",
            "store",
        ),
        // memXX(Rx++Mu:brev) = Rt。
        (
            "st_pbr",
            "FSTMU",
            "10101111................0.......",
            ST_NE,
            "memx({x}++m{mu}:brev)={t}",
            "store",
        ),
        // memXX(Rx++#s4:circ(Mu)) = Rt。
        (
            "st_pci",
            "FSTCI",
            "10101001................0.....0.",
            ST_NE,
            "memx({x}++#{s4}:circ(m{mu}))={t}",
            "store",
        ),
        // memXX(Rx++I:circ(Mu)) = Rt。
        (
            "st_pcr",
            "FSTMU",
            "10101001................0.....1.",
            ST_NE,
            "memx({x}++i:circ(m{mu}))={t}",
            "store",
        ),
        // memXX(gp+#s16) = Rt / memXX(##imm) = Rt。
        (
            "st_gp",
            "FSTGP",
            "01001..0........................",
            ST_NE,
            "memx(gp+#{imm})={t}",
            "store",
        ),
        // memXX(Re=##imm) = Rt。
        (
            "st_as",
            "FSTAS",
            "10101011..........0.....1.......",
            ST_NE,
            "memx({e}=##{imm})={t}",
            "store",
        ),
        // memXX(Ru<<#u2+##imm) = Rt。
        (
            "st_sa",
            "FSTSA",
            "10101101................1.......",
            ST_NE,
            "memx({u}<<#{sh}+##{imm})={t}",
            "store",
        ),
        // memXX(Rs+Ru<<#u2) = Rt。
        (
            "st_rro",
            "FSTRO",
            "00111011........................",
            ST_NE,
            "memx({s}+{u}<<#{sh})={t}",
            "store",
        ),
        // if ([!]Pv[.new]) memXX(Rs+#u6) = Rt。
        (
            "st_pq",
            "FSTPQ",
            "01000..0.....................0..",
            ST_NE,
            "memx({s}+#{u})={t}",
            "store",
        ),
        // if ([!]Pv[.new]) memXX(Rx++#s4) = Rt。
        (
            "st_pq_pi",
            "FSTPQI",
            "10101011..........1.............",
            ST_NE,
            "memx({x}++#{s4})={t}",
            "store",
        ),
        // if ([!]Pv[.new]) memXX(Rs+Ru<<#u2) = Rt。
        (
            "st_pq_ro",
            "FSTPQR",
            "001101..........................",
            ST_NE,
            "memx({s}+{u}<<#{sh})={t}",
            "store",
        ),
        // if ([!]Pv[.new]) memXX(#u6) = Rt（abs。## 拡張前提）。
        (
            "st_pq_abs",
            "FSTQABS",
            "10101111................1.......",
            ST_NE,
            "memx(#{u})={t}",
            "store",
        ),
    ] {
        m.insns.push({
            let mut i = ins(name, format, pattern, base(), syntax, timing);
            for &v in ne {
                i.wheres.push(WhereClause {
                    field: "sz3".to_string(),
                    op: WhereOp::Ne,
                    rhs: WhereRhs::Lit(v),
                });
            }
            i
        });
    }
    // ---- HX11: LL/SC（memw_locked）----
    // Rd = memw_locked(Rs)（load-linked）。musl のアトミック
    // 実装が使う。実符号照合済み。
    m.insns.push(ins(
        "ld_locked",
        "FLLL",
        "10010010000.......0.....000.....",
        base(),
        "{d}=memw_locked({s})",
        "load",
    ));
    // memw_locked(Rs,Pd) = Rt（store-conditional）。成功時のみ
    // ストアし Pd に真を書く。実符号照合済み。
    m.insns.push(ins(
        "st_locked",
        "FSCL",
        "10100000101.......0.....000000..",
        base(),
        "memw_locked({s},{p})={t}",
        "store",
    ));
    // ストア即値形・述語付き即値形・memop。サイズは sz2i の
    // 2 ビット（b=0 h=1 w=2、d=3 を禁止）。memop は
    // read-modify-write でスロット 0 専用・slot1 ストア禁止
    // （packet::expand が担う）。
    for (name, format, pattern, syntax) in [
        // memXX(Rs+#u6) = #s8。
        (
            "st_i",
            "FSTI",
            "0011110.........................",
            "memx({s}+#{off})=#{imm}",
        ),
        // if ([!]Pv[.new]) memXX(Rs+#u6) = #s6。
        (
            "st_ip",
            "FSTIP",
            "0011100.........................",
            "memx({s}+#{off})=#{imm}",
        ),
        // memXX(Rs+#u6) op= #u5（imm 形は 2=clrbit 3=setbit）。
        (
            "mop_i",
            "FMOPI",
            "00111111..........0.............",
            "memx({s}+#{off})op=#{imm}",
        ),
        // memXX(Rs+#u6) op= Rt（reg 形は 2=& 3=|）。
        (
            "mop_r",
            "FMOPR",
            "00111110..........0.............",
            "memx({s}+#{off})op={t}",
        ),
    ] {
        m.insns.push({
            let mut i = ins(name, format, pattern, base(), syntax, "store");
            i.wheres.push(WhereClause {
                field: "sz2i".to_string(),
                op: WhereOp::Ne,
                rhs: WhereRhs::Lit(3),
            });
            i
        });
    }
    // ---- `.new` ストア値形 ----
    // sz3=101 を where で固定して通常形と排他にし、サイズは
    // sz2（0=b,1=h,2=w。3 は memd に相当し禁止）、Nt は
    // bits[10]=0 固定＋[9:8] が距離 1-3（nt2、0 禁止）。
    // reg-offset 形は [4:3]=sz2r・bit2=0 固定・[1:0]=nt2r。
    for (name, format, pattern, syntax) in [
        // memXX(Rs+#s11) = Rt.new。
        (
            "st_nt",
            "FSTNT",
            "10100..1101............0........",
            "memx({s}+#{imm})=r.new",
        ),
        // memXX(Rx++#s4) = Rt.new。
        (
            "st_pi_nt",
            "FSTPNT",
            "10101011101.......0....00.....0.",
            "memx({x}++#{s4})=r.new",
        ),
        // memXX(Rx++Mu) = Rt.new。
        (
            "st_pr_nt",
            "FSTMNT",
            "10101101101............00.......",
            "memx({x}++m{mu})=r.new",
        ),
        // memXX(Rx++Mu:brev) = Rt.new。
        (
            "st_pbr_nt",
            "FSTMNT",
            "10101111101............00.......",
            "memx({x}++m{mu}:brev)=r.new",
        ),
        // memXX(Rx++#s4:circ(Mu)) = Rt.new。
        (
            "st_pci_nt",
            "FSTCNT",
            "10101001101............00.....0.",
            "memx({x}++#{s4}:circ(m{mu}))=r.new",
        ),
        // memXX(Rx++I:circ(Mu)) = Rt.new。
        (
            "st_pcr_nt",
            "FSTMNT",
            "10101001101............00.....1.",
            "memx({x}++i:circ(m{mu}))=r.new",
        ),
        // memXX(gp+#s16)/##imm = Rt.new。
        (
            "st_gp_nt",
            "FSTGNT",
            "01001..0101............0........",
            "memx(gp+#{imm})=r.new",
        ),
        // if ([!]Pv[.new]) memXX(Rs+#u6) = Rt.new。
        (
            "st_pq_nt",
            "FSTQNT",
            "01000..0101............0.....0..",
            "memx({s}+#{u})=r.new",
        ),
        // if ([!]Pv[.new]) memXX(Rx++#s4) = Rt.new。
        (
            "st_pq_pi_nt",
            "FSTPQINT",
            "10101011101.......1....0........",
            "memx({x}++#{s4})=r.new",
        ),
        // if ([!]Pv[.new]) memXX(#u6) = Rt.new（述語付 abs。
        // ## 拡張前提）。
        (
            "st_pq_abs_nt",
            "FSTQABSNT",
            "10101111101............01.......",
            "memx(#{u})=r.new",
        ),
    ] {
        let mut i = ins(name, format, pattern, base(), syntax, "store");
        i.wheres.push(weq("sz3", 5));
        i.wheres.push(WhereClause {
            field: "sz2".to_string(),
            op: WhereOp::Ne,
            rhs: WhereRhs::Lit(3),
        });
        i.wheres.push(WhereClause {
            field: "nt2".to_string(),
            op: WhereOp::Ne,
            rhs: WhereRhs::Lit(0),
        });
        m.insns.push(i);
    }
    for (name, format, pattern, syntax) in [
        // memXX(Rs+Ru<<#u2) = Rt.new。
        (
            "st_ro_nt",
            "FSTRNT",
            "00111011101....................0",
            "memx({s}+{u}<<#{sh})=r.new",
        ),
        // if ([!]Pv[.new]) memXX(Rs+Ru<<#u2) = Rt.new。
        (
            "st_pq_ro_nt",
            "FSTQRNT",
            "001101..101....................0",
            "memx({s}+{u}<<#{sh})=r.new",
        ),
    ] {
        let mut i = ins(name, format, pattern, base(), syntax, "store");
        i.wheres.push(weq("sz3", 5));
        i.wheres.push(WhereClause {
            field: "sz2r".to_string(),
            op: WhereOp::Ne,
            rhs: WhereRhs::Lit(3),
        });
        i.wheres.push(WhereClause {
            field: "nt2r".to_string(),
            op: WhereOp::Ne,
            rhs: WhereRhs::Lit(0),
        });
        m.insns.push(i);
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
        (
            "add_sat_rr",
            "FRR",
            "11110110010.....................",
            "add {d},{s},{t}:sat",
            "alu",
        ),
        (
            "and_rr",
            "FRR",
            "11110001000.....................",
            "and {d},{s},{t}",
            "alu",
        ),
        (
            "andn2_rr",
            "FRR",
            "11110001100.....................",
            "and {t},~{s}",
            "alu",
        ),
        (
            "or_rr",
            "FRR",
            "11110001001.....................",
            "or {d},{s},{t}",
            "alu",
        ),
        (
            "orn2_rr",
            "FRR",
            "11110001101.....................",
            "or {t},~{s}",
            "alu",
        ),
        (
            "xor_rr",
            "FRR",
            "11110001011.....................",
            "xor {d},{s},{t}",
            "alu",
        ),
        (
            "sub_rr",
            "FRR",
            "11110011001.....................",
            "sub {d},{t},{s}",
            "alu",
        ),
        (
            "sub_sat_rr",
            "FRR",
            "11110110110.....................",
            "sub {d},{t},{s}:sat",
            "alu",
        ),
        (
            "vaddh_rr",
            "FRR",
            "11110110000.....................",
            "vaddh {d},{s},{t}",
            "alu",
        ),
        (
            "vaddh_sat_rr",
            "FRR",
            "11110110001.....................",
            "vaddh {d},{s},{t}:sat",
            "alu",
        ),
        (
            "vadduh_sat_rr",
            "FRR",
            "11110110011.....................",
            "vadduh {d},{s},{t}:sat",
            "alu",
        ),
        (
            "vavgh_rr",
            "FRR",
            "11110111.00.....................",
            "vavgh {d},{s},{t}",
            "alu",
        ),
        (
            "vavgh_rnd_rr",
            "FRR",
            "11110111.01.....................",
            "vavgh {d},{s},{t}:rnd",
            "alu",
        ),
        (
            "vnavgh_rr",
            "FRR",
            "11110111.11.....................",
            "vnavgh {t},{s}",
            "alu",
        ),
        (
            "vsubh_rr",
            "FRR",
            "11110110100.....................",
            "vsubh {t},{s}",
            "alu",
        ),
        (
            "vsubh_sat_rr",
            "FRR",
            "11110110101.....................",
            "vsubh {t},{s}:sat",
            "alu",
        ),
        (
            "vsubuh_sat_rr",
            "FRR",
            "11110110111.....................",
            "vsubuh {t},{s}:sat",
            "alu",
        ),
        (
            "and_ri",
            "FRI10",
            "0111011000......................",
            "and {d},{s},#{imm}",
            "alu",
        ),
        (
            "or_ri",
            "FRI10",
            "0111011010......................",
            "or {d},{s},#{imm}",
            "alu",
        ),
        (
            "sub_ir",
            "FRI10",
            "0111011001......................",
            "sub {d},#{imm},{s}",
            "alu",
        ),
        (
            "aslh",
            "FRS",
            "01110000000.......0.............",
            "aslh {d},{s}",
            "alu",
        ),
        (
            "asrh",
            "FRS",
            "01110000001.......0.............",
            "asrh {d},{s}",
            "alu",
        ),
        (
            "sxtb",
            "FRS",
            "01110000101.......0.............",
            "sxtb {d},{s}",
            "alu",
        ),
        (
            "sxth",
            "FRS",
            "01110000111.......0.............",
            "sxth {d},{s}",
            "alu",
        ),
        (
            "zxth",
            "FRS",
            "01110000110.......0.............",
            "zxth {d},{s}",
            "alu",
        ),
        // ---- HX13: `if ([!]Pu[.new]) Rd = {sxtb,zxtb,sxth,zxth}(Rs)` ----
        // 無条件形と同じ bits[25:21] の演算選択。bits[14:13]=11
        // が条件形の識別子（bit15 は実符号上で 0/1 両方が出る
        // エイリアス桁）。述語は bits[9:8]、否定 bit11、.new
        // bit10。実符号は参照アセンブラ（V73）との照合済み。
        (
            "czxtb",
            "FCZX",
            "01110000100......110............",
            "if(...) zxtb {d},{s}",
            "alu",
        ),
        (
            "csxtb",
            "FCZX",
            "01110000101......110............",
            "if(...) sxtb {d},{s}",
            "alu",
        ),
        (
            "czxth",
            "FCZX",
            "01110000110......110............",
            "if(...) zxth {d},{s}",
            "alu",
        ),
        (
            "csxth",
            "FCZX",
            "01110000111......110............",
            "if(...) sxth {d},{s}",
            "alu",
        ),
        (
            "combine_rr",
            "FRR",
            "111101010.......................",
            "combine {d},{s},{t}",
            "alu",
        ),
        (
            "comb_hh",
            "FRR",
            "11110011100.....................",
            "combine {d},{t}.h,{s}.h",
            "alu",
        ),
        (
            "comb_hl",
            "FRR",
            "11110011101.....................",
            "combine {d},{t}.h,{s}.l",
            "alu",
        ),
        (
            "comb_lh",
            "FRR",
            "11110011110.....................",
            "combine {d},{t}.l,{s}.h",
            "alu",
        ),
        (
            "comb_ll",
            "FRR",
            "11110011111.....................",
            "combine {d},{t}.l,{s}.l",
            "alu",
        ),
        (
            "packhl",
            "FRR",
            "111101011.......................",
            "packhl {d},{s},{t}",
            "alu",
        ),
        (
            "comb_ri",
            "FRI8",
            "01110011.00.......1.............",
            "combine {d},{s},#{imm}",
            "alu",
        ),
        (
            "comb_ir",
            "FRI8",
            "01110011.01.......1.............",
            "combine {d},#{imm},{s}",
            "alu",
        ),
        (
            "comb_ii",
            "FCII",
            "011111000.......................",
            "combine {d},#{imm1},#{imm2}",
            "alu",
        ),
        (
            "comb_iu6",
            "FCU6",
            "011111001.......................",
            "combine {d},#{imm1},#{imm2}",
            "alu",
        ),
        (
            "mux_rr",
            "FMUX",
            "11110100........................",
            "mux {d},{p},{s},{t}",
            "alu",
        ),
        (
            "mux_ri",
            "FMUXI",
            "011100110.........0.............",
            "mux {d},{p},{s},#{imm}",
            "alu",
        ),
        (
            "mux_ir",
            "FMUXI",
            "011100111.........0.............",
            "mux {d},{p},#{imm},{s}",
            "alu",
        ),
        (
            "mux_ii",
            "FMUXII",
            "0111101.........................",
            "mux {d},{p},#{imm1},#{imm2}",
            "alu",
        ),
        (
            "cmpgtu_rr",
            "FCMP",
            "11110010.11................000..",
            "{d}=cmp.gtu({s},{t})",
            "alu",
        ),
        (
            "cmpeqn_rr",
            "FCMP",
            "11110010.00................100..",
            "{d}=!cmp.eq({s},{t})",
            "alu",
        ),
        (
            "cmpgtn_rr",
            "FCMP",
            "11110010.10................100..",
            "{d}=!cmp.gt({s},{t})",
            "alu",
        ),
        (
            "cmpgtun_rr",
            "FCMP",
            "11110010.11................100..",
            "{d}=!cmp.gtu({s},{t})",
            "alu",
        ),
        (
            "cmpeq_i",
            "FCMPI",
            "0111010100.................000..",
            "{d}=cmp.eq({s},#{imm})",
            "alu",
        ),
        (
            "cmpgt_i",
            "FCMPI",
            "0111010101.................000..",
            "{d}=cmp.gt({s},#{imm})",
            "alu",
        ),
        (
            "cmpgtu_i",
            "FCMPIU",
            "01110101100................000..",
            "{d}=cmp.gtu({s},#{imm})",
            "alu",
        ),
        (
            "cmpeqn_i",
            "FCMPI",
            "0111010100.................100..",
            "{d}=!cmp.eq({s},#{imm})",
            "alu",
        ),
        (
            "cmpgtn_i",
            "FCMPI",
            "0111010101.................100..",
            "{d}=!cmp.gt({s},#{imm})",
            "alu",
        ),
        (
            "cmpgtun_i",
            "FCMPIU",
            "01110101100................100..",
            "{d}=!cmp.gtu({s},#{imm})",
            "alu",
        ),
        (
            "cmpeq_rd_rr",
            "FRR",
            "11110011010.....................",
            "cmp.eq {d},{s},{t}",
            "alu",
        ),
        (
            "cmpeqn_rd_rr",
            "FRR",
            "11110011011.....................",
            "!cmp.eq {d},{s},{t}",
            "alu",
        ),
        (
            "cmpeq_rd_i",
            "FRI8",
            "01110011.10.......1.............",
            "cmp.eq {d},{s},#{imm}",
            "alu",
        ),
        (
            "cmpeqn_rd_i",
            "FRI8",
            "01110011.11.......1.............",
            "!cmp.eq {d},{s},#{imm}",
            "alu",
        ),
        (
            "pand",
            "FP3",
            "011010110000......0.............",
            "{d}=and({t},{s})",
            "alu",
        ),
        (
            "por",
            "FP3",
            "011010110010......0.............",
            "{d}=or({t},{s})",
            "alu",
        ),
        (
            "pxor",
            "FP3",
            "011010110100......0.............",
            "{d}=xor({s},{t})",
            "alu",
        ),
        (
            "pandn",
            "FP3",
            "011010110110......0.............",
            "{d}=and({t},!{s})",
            "alu",
        ),
        (
            "porn",
            "FP3",
            "011010111110......0.............",
            "{d}=or({t},!{s})",
            "alu",
        ),
        (
            "pnot",
            "FPN",
            "011010111100......0.............",
            "{d}=not({s})",
            "alu",
        ),
        (
            "pany8",
            "FPN",
            "011010111000......0.............",
            "{d}=any8({s})",
            "alu",
        ),
        (
            "pall8",
            "FPN",
            "011010111010......0.............",
            "{d}=all8({s})",
            "alu",
        ),
        (
            "pfc9",
            "FP3",
            "01101011000000....1000..100100..",
            "{d}=fastcorner9({s},{t})",
            "alu",
        ),
        (
            "pfc9n",
            "FP3",
            "01101011000100....1000..100100..",
            "{d}=!fastcorner9({s},{t})",
            "alu",
        ),
        (
            "pand_a",
            "FP4",
            "011010110001......0.............",
            "{d}=and({s},and({t},{u}))",
            "alu",
        ),
        (
            "pand_o",
            "FP4",
            "011010110011......0.............",
            "{d}=and({s},or({t},{u}))",
            "alu",
        ),
        (
            "por_a",
            "FP4",
            "011010110101......0.............",
            "{d}=or({s},and({t},{u}))",
            "alu",
        ),
        (
            "por_o",
            "FP4",
            "011010110111......0.............",
            "{d}=or({s},or({t},{u}))",
            "alu",
        ),
        (
            "pand_an",
            "FP4",
            "011010111001......0.............",
            "{d}=and({s},and({t},!{u}))",
            "alu",
        ),
        (
            "pand_on",
            "FP4",
            "011010111011......0.............",
            "{d}=and({s},or({t},!{u}))",
            "alu",
        ),
        (
            "por_an",
            "FP4",
            "011010111101......0.............",
            "{d}=or({s},and({t},!{u}))",
            "alu",
        ),
        (
            "por_on",
            "FP4",
            "011010111111......0.............",
            "{d}=or({s},or({t},!{u}))",
            "alu",
        ),
        (
            "rd_ps",
            "FRFP",
            "10001001.1......................",
            "{d}={s}",
            "alu",
        ),
        (
            "pd_rs",
            "FPRF",
            "10000101010.....................",
            "{d}={s}",
            "alu",
        ),
        (
            "add64",
            "FRR",
            "11010011000.............111.....",
            "add {d},{s},{t}",
            "alu",
        ),
        (
            "add64_sat",
            "FRR",
            "11010011011.............101.....",
            "add {d},{s},{t}:sat",
            "alu",
        ),
        (
            "add64_raw_lo",
            "FRR",
            "11010011011.............110.....",
            "add {d},{s},{t}:raw:lo",
            "alu",
        ),
        (
            "add64_raw_hi",
            "FRR",
            "11010011011.............111.....",
            "add {d},{s},{t}:raw:hi",
            "alu",
        ),
        (
            "sub64",
            "FRR",
            "11010011001.............111.....",
            "sub {d},{t},{s}",
            "alu",
        ),
        (
            "and64",
            "FRR",
            "11010011111.............000.....",
            "and {d},{s},{t}",
            "alu",
        ),
        (
            "andn64",
            "FRR",
            "11010011111.............001.....",
            "and {d},{t},~{s}",
            "alu",
        ),
        (
            "or64",
            "FRR",
            "11010011111.............010.....",
            "or {d},{s},{t}",
            "alu",
        ),
        (
            "orn64",
            "FRR",
            "11010011111.............011.....",
            "or {d},{t},~{s}",
            "alu",
        ),
        (
            "xor64",
            "FRR",
            "11010011111.............100.....",
            "xor {d},{s},{t}",
            "alu",
        ),
        (
            "not64",
            "FRS",
            "10000000100.............100.....",
            "not {d},{s}",
            "alu",
        ),
        (
            "neg64",
            "FRS",
            "10000000100.............101.....",
            "neg {d},{s}",
            "alu",
        ),
        (
            "abs64",
            "FRS",
            "10000000100.............110.....",
            "abs {d},{s}",
            "alu",
        ),
        (
            "abs",
            "FRS",
            "10001100100.............100.....",
            "abs {d},{s}",
            "alu",
        ),
        (
            "abs_sat",
            "FRS",
            "10001100100.............101.....",
            "abs {d},{s}:sat",
            "alu",
        ),
        (
            "neg_sat",
            "FRS",
            "10001100100.............110.....",
            "neg {d},{s}:sat",
            "alu",
        ),
        (
            "sxtw",
            "FRS",
            "1000010001..............00......",
            "sxtw {d},{s}",
            "alu",
        ),
        (
            "modwrap",
            "FRR",
            "11010011111.............111.....",
            "modwrap {d},{s},{t}",
            "alu",
        ),
        (
            "add_carry",
            "FMUX",
            "11000010110.....................",
            "add {d},{s},{t},{p}:carry",
            "alu",
        ),
        (
            "sub_carry",
            "FMUX",
            "11000010111.....................",
            "sub {d},{s},{t},{p}:carry",
            "alu",
        ),
        (
            "max",
            "FRR",
            "11010101110.............0.......",
            "max {d},{s},{t}",
            "alu",
        ),
        (
            "maxu",
            "FRR",
            "11010101110.............1.......",
            "maxu {d},{s},{t}",
            "alu",
        ),
        (
            "min",
            "FRR",
            "11010101101.............0.......",
            "min {d},{t},{s}",
            "alu",
        ),
        (
            "minu",
            "FRR",
            "11010101101.............1.......",
            "minu {d},{t},{s}",
            "alu",
        ),
        (
            "max64",
            "FRR",
            "11010011110.............100.....",
            "max {d},{s},{t}",
            "alu",
        ),
        (
            "maxu64",
            "FRR",
            "11010011110.............101.....",
            "maxu {d},{s},{t}",
            "alu",
        ),
        (
            "min64",
            "FRR",
            "11010011101.............110.....",
            "min {d},{t},{s}",
            "alu",
        ),
        (
            "minu64",
            "FRR",
            "11010011101.............111.....",
            "minu {d},{t},{s}",
            "alu",
        ),
        (
            "cmp64_eq",
            "FCMP",
            "11010010100.............000.....",
            "{d}=cmp.eq({s},{t})",
            "alu",
        ),
        (
            "cmp64_gt",
            "FCMP",
            "11010010100.............010.....",
            "{d}=cmp.gt({s},{t})",
            "alu",
        ),
        (
            "cmp64_gtu",
            "FCMP",
            "11010010100.............100.....",
            "{d}=cmp.gtu({s},{t})",
            "alu",
        ),
        (
            "add_ll",
            "FRR",
            "11010101000.............00......",
            "add {d},{t}.l,{s}.l",
            "alu",
        ),
        (
            "add_lh",
            "FRR",
            "11010101000.............01......",
            "add {d},{t}.l,{s}.h",
            "alu",
        ),
        (
            "add_ll_sat",
            "FRR",
            "11010101000.............10......",
            "add {d},{t}.l,{s}.l:sat",
            "alu",
        ),
        (
            "add_lh_sat",
            "FRR",
            "11010101000.............11......",
            "add {d},{t}.l,{s}.h:sat",
            "alu",
        ),
        (
            "add_ll_s16",
            "FRR",
            "11010101010.............000.....",
            "add {d},{t}.l,{s}.l:<<16",
            "alu",
        ),
        (
            "add_lh_s16",
            "FRR",
            "11010101010.............001.....",
            "add {d},{t}.l,{s}.h:<<16",
            "alu",
        ),
        (
            "add_hl_s16",
            "FRR",
            "11010101010.............010.....",
            "add {d},{t}.h,{s}.l:<<16",
            "alu",
        ),
        (
            "add_hh_s16",
            "FRR",
            "11010101010.............011.....",
            "add {d},{t}.h,{s}.h:<<16",
            "alu",
        ),
        (
            "add_ll_sat_s16",
            "FRR",
            "11010101010.............100.....",
            "add {d},{t}.l,{s}.l:sat:<<16",
            "alu",
        ),
        (
            "add_lh_sat_s16",
            "FRR",
            "11010101010.............101.....",
            "add {d},{t}.l,{s}.h:sat:<<16",
            "alu",
        ),
        (
            "add_hl_sat_s16",
            "FRR",
            "11010101010.............110.....",
            "add {d},{t}.h,{s}.l:sat:<<16",
            "alu",
        ),
        (
            "add_hh_sat_s16",
            "FRR",
            "11010101010.............111.....",
            "add {d},{t}.h,{s}.h:sat:<<16",
            "alu",
        ),
        (
            "sub_ll",
            "FRR",
            "11010101001.............00......",
            "sub {d},{t}.l,{s}.l",
            "alu",
        ),
        (
            "sub_lh",
            "FRR",
            "11010101001.............01......",
            "sub {d},{t}.l,{s}.h",
            "alu",
        ),
        (
            "sub_ll_sat",
            "FRR",
            "11010101001.............10......",
            "sub {d},{t}.l,{s}.l:sat",
            "alu",
        ),
        (
            "sub_lh_sat",
            "FRR",
            "11010101001.............11......",
            "sub {d},{t}.l,{s}.h:sat",
            "alu",
        ),
        (
            "sub_ll_s16",
            "FRR",
            "11010101011.............000.....",
            "sub {d},{t}.l,{s}.l:<<16",
            "alu",
        ),
        (
            "sub_lh_s16",
            "FRR",
            "11010101011.............001.....",
            "sub {d},{t}.l,{s}.h:<<16",
            "alu",
        ),
        (
            "sub_hl_s16",
            "FRR",
            "11010101011.............010.....",
            "sub {d},{t}.h,{s}.l:<<16",
            "alu",
        ),
        (
            "sub_hh_s16",
            "FRR",
            "11010101011.............011.....",
            "sub {d},{t}.h,{s}.h:<<16",
            "alu",
        ),
        (
            "sub_ll_sat_s16",
            "FRR",
            "11010101011.............100.....",
            "sub {d},{t}.l,{s}.l:sat:<<16",
            "alu",
        ),
        (
            "sub_lh_sat_s16",
            "FRR",
            "11010101011.............101.....",
            "sub {d},{t}.l,{s}.h:sat:<<16",
            "alu",
        ),
        (
            "sub_hl_sat_s16",
            "FRR",
            "11010101011.............110.....",
            "sub {d},{t}.h,{s}.l:sat:<<16",
            "alu",
        ),
        (
            "sub_hh_sat_s16",
            "FRR",
            "11010101011.............111.....",
            "sub {d},{t}.h,{s}.h:sat:<<16",
            "alu",
        ),
        (
            "asr_i",
            "FSHI",
            "10001100000.......0.....000.....",
            "asr {d},{s},#{imm}",
            "alu",
        ),
        (
            "lsr_i",
            "FSHI",
            "10001100000.......0.....001.....",
            "lsr {d},{s},#{imm}",
            "alu",
        ),
        (
            "asl_i",
            "FSHI",
            "10001100000.......0.....010.....",
            "asl {d},{s},#{imm}",
            "alu",
        ),
        (
            "asl_i_sat",
            "FSHI",
            "10001100010.......0.....010.....",
            "asl {d},{s},#{imm}:sat",
            "alu",
        ),
        (
            "rol_i",
            "FSHI",
            "10001100000.......0.....011.....",
            "rol {d},{s},#{imm}",
            "alu",
        ),
        (
            "asr64_i",
            "FSHI6",
            "10000000000.............000.....",
            "asr {d},{s},#{imm}",
            "alu",
        ),
        (
            "lsr64_i",
            "FSHI6",
            "10000000000.............001.....",
            "lsr {d},{s},#{imm}",
            "alu",
        ),
        (
            "asl64_i",
            "FSHI6",
            "10000000000.............010.....",
            "asl {d},{s},#{imm}",
            "alu",
        ),
        (
            "rol64_i",
            "FSHI6",
            "10000000000.............011.....",
            "rol {d},{s},#{imm}",
            "alu",
        ),
        // ベクトル即値シフト。bits[7:5] が op（0=asr,1=lsr,2=asl）、
        // 即値は u6 桁だが要素幅で意味が違う（w: u5、h: u4）。
        // vlsl*_i は実在しない（参照アセンブラ照合）。bits[15:14] は
        // パケット parse 桁なのでパターンには入れない。
        (
            "vasrw_i",
            "FSHI6",
            "10000000010.............000.....",
            "vasrw {d},{s},#{imm}",
            "alu",
        ),
        (
            "vlsrw_i",
            "FSHI6",
            "10000000010.............001.....",
            "vlsrw {d},{s},#{imm}",
            "alu",
        ),
        (
            "vaslw_i",
            "FSHI6",
            "10000000010.............010.....",
            "vaslw {d},{s},#{imm}",
            "alu",
        ),
        (
            "vasrh_i",
            "FSHI6",
            "10000000100.............000.....",
            "vasrh {d},{s},#{imm}",
            "alu",
        ),
        (
            "vlsrh_i",
            "FSHI6",
            "10000000100.............001.....",
            "vlsrh {d},{s},#{imm}",
            "alu",
        ),
        (
            "vaslh_i",
            "FSHI6",
            "10000000100.............010.....",
            "vaslh {d},{s},#{imm}",
            "alu",
        ),
        (
            "asr_rr",
            "FRR",
            "1100011001..............00......",
            "asr {d},{s},{t}",
            "alu",
        ),
        (
            "asl_rr",
            "FRR",
            "1100011001..............10......",
            "asl {d},{s},{t}",
            "alu",
        ),
        (
            "lsr_rr",
            "FRR",
            "1100011001..............01......",
            "lsr {d},{s},{t}",
            "alu",
        ),
        (
            "lsl_rr",
            "FRR",
            "1100011001..............11......",
            "lsl {d},{s},{t}",
            "alu",
        ),
        (
            "asl_rr_sat",
            "FRR",
            "1100011000..............10......",
            "asl {d},{s},{t}:sat",
            "alu",
        ),
        (
            "asr_rr_sat",
            "FRR",
            "1100011000..............00......",
            "asr {d},{s},{t}:sat",
            "alu",
        ),
        (
            "vasrw",
            "FRR",
            "1100001100..............00......",
            "vasrw {d},{s},{t}",
            "alu",
        ),
        (
            "vlsrw",
            "FRR",
            "1100001100..............01......",
            "vlsrw {d},{s},{t}",
            "alu",
        ),
        (
            "vaslw",
            "FRR",
            "1100001100..............10......",
            "vaslw {d},{s},{t}",
            "alu",
        ),
        (
            "vlslw",
            "FRR",
            "1100001100..............11......",
            "vlslw {d},{s},{t}",
            "alu",
        ),
        (
            "vasrh",
            "FRR",
            "1100001101..............00......",
            "vasrh {d},{s},{t}",
            "alu",
        ),
        (
            "vlsrh",
            "FRR",
            "1100001101..............01......",
            "vlsrh {d},{s},{t}",
            "alu",
        ),
        (
            "vaslh",
            "FRR",
            "1100001101..............10......",
            "vaslh {d},{s},{t}",
            "alu",
        ),
        (
            "vlslh",
            "FRR",
            "1100001101..............11......",
            "vlslh {d},{s},{t}",
            "alu",
        ),
        (
            "asr64_rr",
            "FRR",
            "1100001110..............00......",
            "asr {d},{s},{t}",
            "alu",
        ),
        (
            "asl64_rr",
            "FRR",
            "1100001110..............10......",
            "asl {d},{s},{t}",
            "alu",
        ),
        (
            "lsr64_rr",
            "FRR",
            "1100001110..............01......",
            "lsr {d},{s},{t}",
            "alu",
        ),
        (
            "lsl64_rr",
            "FRR",
            "1100001110..............11......",
            "lsl {d},{s},{t}",
            "alu",
        ),
        (
            "lsl_ir",
            "FLSL",
            "1100011010..............11......",
            "lsl {d},#{imm},{t}",
            "alu",
        ),
        (
            "addasl",
            "FASL3",
            "11000100000.......0.............",
            "addasl {d},{t},{s},#{imm}",
            "alu",
        ),
        (
            "add_asr_i",
            "FXSH",
            "1000111000........0.....100.....",
            "{x}+=asr({s},#{imm})",
            "alu",
        ),
        (
            "add_lsr_i",
            "FXSH",
            "1000111000........0.....101.....",
            "{x}+=lsr({s},#{imm})",
            "alu",
        ),
        (
            "add_asl_i",
            "FXSH",
            "1000111000........0.....110.....",
            "{x}+=asl({s},#{imm})",
            "alu",
        ),
        (
            "add_rol_i",
            "FXSH",
            "1000111000........0.....111.....",
            "{x}+=rol({s},#{imm})",
            "alu",
        ),
        (
            "sub_asr_i",
            "FXSH",
            "1000111000........0.....000.....",
            "{x}-=asr({s},#{imm})",
            "alu",
        ),
        (
            "sub_lsr_i",
            "FXSH",
            "1000111000........0.....001.....",
            "{x}-=lsr({s},#{imm})",
            "alu",
        ),
        (
            "sub_asl_i",
            "FXSH",
            "1000111000........0.....010.....",
            "{x}-=asl({s},#{imm})",
            "alu",
        ),
        (
            "sub_rol_i",
            "FXSH",
            "1000111000........0.....011.....",
            "{x}-=rol({s},#{imm})",
            "alu",
        ),
        (
            "and_asr_i",
            "FXSH",
            "1000111001........0.....000.....",
            "{x}&=asr({s},#{imm})",
            "alu",
        ),
        (
            "and_lsr_i",
            "FXSH",
            "1000111001........0.....001.....",
            "{x}&=lsr({s},#{imm})",
            "alu",
        ),
        (
            "and_asl_i",
            "FXSH",
            "1000111001........0.....010.....",
            "{x}&=asl({s},#{imm})",
            "alu",
        ),
        (
            "and_rol_i",
            "FXSH",
            "1000111001........0.....011.....",
            "{x}&=rol({s},#{imm})",
            "alu",
        ),
        (
            "or_asr_i",
            "FXSH",
            "1000111001........0.....100.....",
            "{x}|=asr({s},#{imm})",
            "alu",
        ),
        (
            "or_lsr_i",
            "FXSH",
            "1000111001........0.....101.....",
            "{x}|=lsr({s},#{imm})",
            "alu",
        ),
        (
            "or_asl_i",
            "FXSH",
            "1000111001........0.....110.....",
            "{x}|=asl({s},#{imm})",
            "alu",
        ),
        (
            "or_rol_i",
            "FXSH",
            "1000111001........0.....111.....",
            "{x}|=rol({s},#{imm})",
            "alu",
        ),
        (
            "xor_lsr_i",
            "FXSH",
            "1000111010........0.....001.....",
            "{x}^=lsr({s},#{imm})",
            "alu",
        ),
        (
            "xor_asl_i",
            "FXSH",
            "1000111010........0.....010.....",
            "{x}^=asl({s},#{imm})",
            "alu",
        ),
        (
            "xor_rol_i",
            "FXSH",
            "1000111010........0.....011.....",
            "{x}^=rol({s},#{imm})",
            "alu",
        ),
        (
            "add64_asr_i",
            "FXSH6",
            "1000001000..............100.....",
            "{x}+=asr({s},#{imm})",
            "alu",
        ),
        (
            "add64_lsr_i",
            "FXSH6",
            "1000001000..............101.....",
            "{x}+=lsr({s},#{imm})",
            "alu",
        ),
        (
            "add64_asl_i",
            "FXSH6",
            "1000001000..............110.....",
            "{x}+=asl({s},#{imm})",
            "alu",
        ),
        (
            "add64_rol_i",
            "FXSH6",
            "1000001000..............111.....",
            "{x}+=rol({s},#{imm})",
            "alu",
        ),
        (
            "sub64_asr_i",
            "FXSH6",
            "1000001000..............000.....",
            "{x}-=asr({s},#{imm})",
            "alu",
        ),
        (
            "sub64_lsr_i",
            "FXSH6",
            "1000001000..............001.....",
            "{x}-=lsr({s},#{imm})",
            "alu",
        ),
        (
            "sub64_asl_i",
            "FXSH6",
            "1000001000..............010.....",
            "{x}-=asl({s},#{imm})",
            "alu",
        ),
        (
            "sub64_rol_i",
            "FXSH6",
            "1000001000..............011.....",
            "{x}-=rol({s},#{imm})",
            "alu",
        ),
        (
            "and64_asr_i",
            "FXSH6",
            "1000001001..............000.....",
            "{x}&=asr({s},#{imm})",
            "alu",
        ),
        (
            "and64_lsr_i",
            "FXSH6",
            "1000001001..............001.....",
            "{x}&=lsr({s},#{imm})",
            "alu",
        ),
        (
            "and64_asl_i",
            "FXSH6",
            "1000001001..............010.....",
            "{x}&=asl({s},#{imm})",
            "alu",
        ),
        (
            "and64_rol_i",
            "FXSH6",
            "1000001001..............011.....",
            "{x}&=rol({s},#{imm})",
            "alu",
        ),
        (
            "or64_asr_i",
            "FXSH6",
            "1000001001..............100.....",
            "{x}|=asr({s},#{imm})",
            "alu",
        ),
        (
            "or64_lsr_i",
            "FXSH6",
            "1000001001..............101.....",
            "{x}|=lsr({s},#{imm})",
            "alu",
        ),
        (
            "or64_asl_i",
            "FXSH6",
            "1000001001..............110.....",
            "{x}|=asl({s},#{imm})",
            "alu",
        ),
        (
            "or64_rol_i",
            "FXSH6",
            "1000001001..............111.....",
            "{x}|=rol({s},#{imm})",
            "alu",
        ),
        (
            "xor64_lsr_i",
            "FXSH6",
            "1000001010..............001.....",
            "{x}^=lsr({s},#{imm})",
            "alu",
        ),
        (
            "xor64_asl_i",
            "FXSH6",
            "1000001010..............010.....",
            "{x}^=asl({s},#{imm})",
            "alu",
        ),
        (
            "xor64_rol_i",
            "FXSH6",
            "1000001010..............011.....",
            "{x}^=rol({s},#{imm})",
            "alu",
        ),
        (
            "add_asr",
            "FXRR",
            "1100110011..............00......",
            "{x}+=asr({s},{t})",
            "alu",
        ),
        (
            "add_lsr",
            "FXRR",
            "1100110011..............01......",
            "{x}+=lsr({s},{t})",
            "alu",
        ),
        (
            "add_asl",
            "FXRR",
            "1100110011..............10......",
            "{x}+=asl({s},{t})",
            "alu",
        ),
        (
            "add_lsl",
            "FXRR",
            "1100110011..............11......",
            "{x}+=lsl({s},{t})",
            "alu",
        ),
        (
            "sub_asr",
            "FXRR",
            "1100110010..............00......",
            "{x}-=asr({s},{t})",
            "alu",
        ),
        (
            "sub_lsr",
            "FXRR",
            "1100110010..............01......",
            "{x}-=lsr({s},{t})",
            "alu",
        ),
        (
            "sub_asl",
            "FXRR",
            "1100110010..............10......",
            "{x}-=asl({s},{t})",
            "alu",
        ),
        (
            "sub_lsl",
            "FXRR",
            "1100110010..............11......",
            "{x}-=lsl({s},{t})",
            "alu",
        ),
        (
            "or_asr",
            "FXRR",
            "1100110000..............00......",
            "{x}|=asr({s},{t})",
            "alu",
        ),
        (
            "or_lsr",
            "FXRR",
            "1100110000..............01......",
            "{x}|=lsr({s},{t})",
            "alu",
        ),
        (
            "or_asl",
            "FXRR",
            "1100110000..............10......",
            "{x}|=asl({s},{t})",
            "alu",
        ),
        (
            "or_lsl",
            "FXRR",
            "1100110000..............11......",
            "{x}|=lsl({s},{t})",
            "alu",
        ),
        // &= の reg-shift 系（HX11 で musl の `rX &= lsr/asr/asl(r,r)`
        // を実測。符号の空きは or/sub/add 系と同じ末尾 2 桁の
        // asr/lsr/asl/rol 配列）。
        (
            "and_asr",
            "FXRR",
            "1100110001..............00......",
            "{x}&=asr({s},{t})",
            "alu",
        ),
        (
            "and_lsr",
            "FXRR",
            "1100110001..............01......",
            "{x}&=lsr({s},{t})",
            "alu",
        ),
        (
            "and_asl",
            "FXRR",
            "1100110001..............10......",
            "{x}&=asl({s},{t})",
            "alu",
        ),
        (
            "and_rol",
            "FXRR",
            "1100110001..............11......",
            "{x}&=rol({s},{t})",
            "alu",
        ),
        (
            "add64_asr",
            "FXRR",
            "11001011110.............00......",
            "{x}+=asr({s},{t})",
            "alu",
        ),
        (
            "add64_lsr",
            "FXRR",
            "11001011110.............01......",
            "{x}+=lsr({s},{t})",
            "alu",
        ),
        (
            "add64_asl",
            "FXRR",
            "11001011110.............10......",
            "{x}+=asl({s},{t})",
            "alu",
        ),
        (
            "add64_lsl",
            "FXRR",
            "11001011110.............11......",
            "{x}+=lsl({s},{t})",
            "alu",
        ),
        (
            "sub64_asr",
            "FXRR",
            "11001011100.............00......",
            "{x}-=asr({s},{t})",
            "alu",
        ),
        (
            "sub64_lsr",
            "FXRR",
            "11001011100.............01......",
            "{x}-=lsr({s},{t})",
            "alu",
        ),
        (
            "sub64_asl",
            "FXRR",
            "11001011100.............10......",
            "{x}-=asl({s},{t})",
            "alu",
        ),
        (
            "sub64_lsl",
            "FXRR",
            "11001011100.............11......",
            "{x}-=lsl({s},{t})",
            "alu",
        ),
        (
            "or64_asr",
            "FXRR",
            "11001011000.............00......",
            "{x}|=asr({s},{t})",
            "alu",
        ),
        (
            "or64_lsr",
            "FXRR",
            "11001011000.............01......",
            "{x}|=lsr({s},{t})",
            "alu",
        ),
        (
            "or64_asl",
            "FXRR",
            "11001011000.............10......",
            "{x}|=asl({s},{t})",
            "alu",
        ),
        (
            "or64_lsl",
            "FXRR",
            "11001011000.............11......",
            "{x}|=lsl({s},{t})",
            "alu",
        ),
        (
            "add_acc",
            "FXRR",
            "11101111000.......0.....001.....",
            "{x}+=add({s},{t})",
            "alu",
        ),
        (
            "sub_acc",
            "FXRR",
            "11101111100.......0.....001.....",
            "{x}-=add({s},{t})",
            "alu",
        ),
        (
            "addsub_acc",
            "FXRR",
            "11101111000.......0.....011.....",
            "{x}+=sub({t},{s})",
            "alu",
        ),
        (
            "add_acc_i",
            "FXI8",
            "111000100.........0.............",
            "{x}+=add({s},#{imm})",
            "alu",
        ),
        (
            "sub_acc_i",
            "FXI8",
            "111000101.........0.............",
            "{x}-=add({s},#{imm})",
            "alu",
        ),
        // ---- HX11: mpy 系 ----
        // Rd = ±mpyi(Rs,#u8)（bits[27:24]=0000、bit23=符号、
        // 即値は bits[12:5] の u8）。実符号照合済み。
        (
            "mpyi",
            "FRI8",
            "11100000000.......0.............",
            "{d}=+mpyi({s},#{imm})",
            "alu",
        ),
        (
            "mpyin",
            "FRI8",
            "11100000100.......0.............",
            "{d}=-mpyi({s},#{imm})",
            "alu",
        ),
        // Rx ±= mpyi(Rs,#u8)（bits[27:24]=0001）。
        (
            "mpyia",
            "FXI8",
            "11100001000.......0.............",
            "{x}+=mpyi({s},#{imm})",
            "alu",
        ),
        (
            "mpyina",
            "FXI8",
            "11100001100.......0.............",
            "{x}-=mpyi({s},#{imm})",
            "alu",
        ),
        // Rd = add(#s6,mpyi(Rs,Rt))（複合積和。musl の
        // alloc_group 等が使う。実符号照合済み）。
        (
            "add_mpyi",
            "FAMPY",
            "110101110.......................",
            "{d}=add(#{imm},mpyi({s},{t}))",
            "alu",
        ),
        // Rd = add(#s6,mpyi(Rs,#s6))（mpyi 側も即値。Rd は
        // bits[12:8]、mpyi 即値は bits{23}+{4:0} の yi6。
        // 実符号照合済み）。
        (
            "add_mpyii",
            "FAMPYI",
            "11011000........................",
            "{d}=add(#{imm},mpyi({s},#{imm2}))",
            "alu",
        ),
        // Rdd = mpy(Rs,Rt)（符号付き）/ mpyu（符号無し）。
        // bits[27:24]=0101、bits[23:21] が 000=mpy / 010=mpyu。
        (
            "mpy",
            "FRR",
            "11100101000.......0.....000.....",
            "{d}=mpy({s},{t})",
            "alu",
        ),
        (
            "mpyu",
            "FRR",
            "11100101010.......0.....000.....",
            "{d}=mpyu({s},{t})",
            "alu",
        ),
        // Rxx ±= mpy/mpyu（bits[27:24]=0111、bits[23:21] が
        // 000=+mpy / 001=-mpy / 010=+mpyu）。
        (
            "mpy_a",
            "FXRR",
            "11100111000.......0.....000.....",
            "{x}+=mpy({s},{t})",
            "alu",
        ),
        (
            "mpy_na",
            "FXRR",
            "11100111001.......0.....000.....",
            "{x}-=mpy({s},{t})",
            "alu",
        ),
        (
            "mpyu_a",
            "FXRR",
            "11100111010.......0.....000.....",
            "{x}+=mpyu({s},{t})",
            "alu",
        ),
        (
            "mpyu_na",
            "FXRR",
            "11100111011.......0.....000.....",
            "{x}-=mpyu({s},{t})",
            "alu",
        ),
        // Rd = mpy(Rs,Rt)（積の下位 32 ビット）。
        (
            "mpy32",
            "FRR",
            "11101101000.......0.....001.....",
            "{d}=mpy({s},{t})",
            "alu",
        ),
        // Rd = mpyu(Rs,Rt)（符号無し積の下位 32 ビット、bit22=1）。
        (
            "mpyu32",
            "FRR",
            "11101101010.......0.....001.....",
            "{d}=mpyu({s},{t})",
            "alu",
        ),
        // Rd = mpyi(Rs,Rt)（積の下位 32 ビット、レジスタ形）。
        (
            "mpyi_rr",
            "FRR",
            "11101101000.......0.....000.....",
            "{d}=mpyi({s},{t})",
            "alu",
        ),
        // Rx ±= mpyi(Rs,Rt)（bit23 が加算/減算選択、
        // bits[22:21]=00・bits[15:13]=110・bits[7:5]=000）。
        (
            "mpyia_rr",
            "FXRR",
            "11101111000.......0.....000.....",
            "{x}+=mpyi({s},{t})",
            "alu",
        ),
        (
            "mpyina_rr",
            "FXRR",
            "11101111100.......0.....000.....",
            "{x}-=mpyi({s},{t})",
            "alu",
        ),
        // Rdd = mpy(Rs.{h,l},Rt.{h,l})（bits[27:24]=0100、
        // bits[7:5] が半語選択 000=ll/001=lh/010=hl/011=hh）。
        (
            "mpyll",
            "FRR",
            "11100100000.......0.....000.....",
            "{d}=mpy({s}.l,{t}.l)",
            "alu",
        ),
        (
            "mpylh",
            "FRR",
            "11100100000.......0.....001.....",
            "{d}=mpy({s}.l,{t}.h)",
            "alu",
        ),
        (
            "mpyhl",
            "FRR",
            "11100100000.......0.....010.....",
            "{d}=mpy({s}.h,{t}.l)",
            "alu",
        ),
        (
            "mpyhh",
            "FRR",
            "11100100000.......0.....011.....",
            "{d}=mpy({s}.h,{t}.h)",
            "alu",
        ),
        // Rxx ±= mpy(Rs.{h,l},Rt.{h,l})（bits[27:24]=0110、
        // bits[23:21] が 000=+= / 001=-=）。
        (
            "mpyll_a",
            "FXRR",
            "11100110000.......0.....000.....",
            "{x}+=mpy({s}.l,{t}.l)",
            "alu",
        ),
        (
            "mpyll_na",
            "FXRR",
            "11100110001.......0.....000.....",
            "{x}-=mpy({s}.l,{t}.l)",
            "alu",
        ),
        (
            "mpylh_a",
            "FXRR",
            "11100110000.......0.....001.....",
            "{x}+=mpy({s}.l,{t}.h)",
            "alu",
        ),
        (
            "mpylh_na",
            "FXRR",
            "11100110001.......0.....001.....",
            "{x}-=mpy({s}.l,{t}.h)",
            "alu",
        ),
        (
            "mpyhl_a",
            "FXRR",
            "11100110000.......0.....010.....",
            "{x}+=mpy({s}.h,{t}.l)",
            "alu",
        ),
        (
            "mpyhl_na",
            "FXRR",
            "11100110001.......0.....010.....",
            "{x}-=mpy({s}.h,{t}.l)",
            "alu",
        ),
        (
            "mpyhh_a",
            "FXRR",
            "11100110000.......0.....011.....",
            "{x}+=mpy({s}.h,{t}.h)",
            "alu",
        ),
        (
            "mpyhh_na",
            "FXRR",
            "11100110001.......0.....011.....",
            "{x}-=mpy({s}.h,{t}.h)",
            "alu",
        ),
        // Rd = mpy(Rs.{h,l},Rt.{h,l})（bits[27:24]=1100、積の
        // 下位 32 ビット）。
        (
            "mpy32ll",
            "FRR",
            "11101100000.......0.....000.....",
            "{d}=mpy({s}.l,{t}.l)",
            "alu",
        ),
        (
            "mpy32lh",
            "FRR",
            "11101100000.......0.....001.....",
            "{d}=mpy({s}.l,{t}.h)",
            "alu",
        ),
        (
            "mpy32hl",
            "FRR",
            "11101100000.......0.....010.....",
            "{d}=mpy({s}.h,{t}.l)",
            "alu",
        ),
        (
            "mpy32hh",
            "FRR",
            "11101100000.......0.....011.....",
            "{d}=mpy({s}.h,{t}.h)",
            "alu",
        ),
        (
            "and_and",
            "FXRR",
            "11101111010.......0.....000.....",
            "{x}&=and({s},{t})",
            "alu",
        ),
        (
            "and_andn",
            "FXRR",
            "11101111001.......0.....001.....",
            "{x}&=and({s},~{t})",
            "alu",
        ),
        (
            "and_or",
            "FXRR",
            "11101111010.......0.....001.....",
            "{x}&=or({s},{t})",
            "alu",
        ),
        (
            "and_xor",
            "FXRR",
            "11101111010.......0.....010.....",
            "{x}&=xor({s},{t})",
            "alu",
        ),
        (
            "or_and",
            "FXRR",
            "11101111010.......0.....011.....",
            "{x}|=and({s},{t})",
            "alu",
        ),
        (
            "or_andn",
            "FXRR",
            "11101111001.......0.....000.....",
            "{x}|=and({s},~{t})",
            "alu",
        ),
        (
            "or_or",
            "FXRR",
            "11101111110.......0.....000.....",
            "{x}|=or({s},{t})",
            "alu",
        ),
        (
            "or_xor",
            "FXRR",
            "11101111110.......0.....001.....",
            "{x}|=xor({s},{t})",
            "alu",
        ),
        (
            "xor_and",
            "FXRR",
            "11101111110.......0.....010.....",
            "{x}^=and({s},{t})",
            "alu",
        ),
        (
            "xor_or",
            "FXRR",
            "11101111110.......0.....011.....",
            "{x}^=or({s},{t})",
            "alu",
        ),
        (
            "xor_xor",
            "FXRR",
            "11101111100.......0.....011.....",
            "{x}^=xor({s},{t})",
            "alu",
        ),
        (
            "xor_andn",
            "FXRR",
            "11101111001.......0.....010.....",
            "{x}^=and({s},~{t})",
            "alu",
        ),
        (
            "xor64_xor",
            "FXRR",
            "1100101010........0.....000.....",
            "{x}^=xor({s},{t})",
            "alu",
        ),
        (
            "or_and_i",
            "FXI10",
            "1101101000......................",
            "{x}|=and({s},#{imm})",
            "alu",
        ),
        (
            "or_or_i",
            "FXI10",
            "1101101010......................",
            "{x}|=or({s},#{imm})",
            "alu",
        ),
        (
            "or_ac",
            "FOAC",
            "1101101001......................",
            "{x}=or({u},and({x},#{imm}))",
            "alu",
        ),
        (
            "add3",
            "FADD3",
            "110110110.......................",
            "add {d},{s},add({u},#{imm})",
            "alu",
        ),
        (
            "sub3",
            "FADD3",
            "110110111.......................",
            "add {d},{s},sub(#{imm},{u})",
            "alu",
        ),
        (
            "cadd_asl",
            "FSHIMM",
            "11011110...................0.10.",
            "{x}=add(#{imm},asl({x},#{ushift}))",
            "alu",
        ),
        (
            "csub_asl",
            "FSHIMM",
            "11011110...................0.11.",
            "{x}=sub(#{imm},asl({x},#{ushift}))",
            "alu",
        ),
        (
            "cand_asl",
            "FSHIMM",
            "11011110...................0.00.",
            "{x}=and(#{imm},asl({x},#{ushift}))",
            "alu",
        ),
        (
            "cor_asl",
            "FSHIMM",
            "11011110...................0.01.",
            "{x}=or(#{imm},asl({x},#{ushift}))",
            "alu",
        ),
        (
            "cadd_lsr",
            "FSHIMM",
            "11011110...................1.10.",
            "{x}=add(#{imm},lsr({x},#{ushift}))",
            "alu",
        ),
        (
            "csub_lsr",
            "FSHIMM",
            "11011110...................1.11.",
            "{x}=sub(#{imm},lsr({x},#{ushift}))",
            "alu",
        ),
        (
            "cand_lsr",
            "FSHIMM",
            "11011110...................1.00.",
            "{x}=and(#{imm},lsr({x},#{ushift}))",
            "alu",
        ),
        (
            "cor_lsr",
            "FSHIMM",
            "11011110...................1.01.",
            "{x}=or(#{imm},lsr({x},#{ushift}))",
            "alu",
        ),
        (
            "asr_i_rnd",
            "FSHI",
            "10001100010.......0.....000.....",
            "asr {d},{s},#{imm}:rnd",
            "alu",
        ),
        (
            "asr64_i_rnd",
            "FSHI6",
            "10000000110.............111.....",
            "asr {d},{s},#{imm}:rnd",
            "alu",
        ),
        (
            "cl0",
            "FRS",
            "10001100000.............101.....",
            "cl0 {d},{s}",
            "alu",
        ),
        (
            "cl1",
            "FRS",
            "10001100000.............110.....",
            "cl1 {d},{s}",
            "alu",
        ),
        (
            "clb",
            "FRS",
            "10001100000.............100.....",
            "clb {d},{s}",
            "alu",
        ),
        (
            "cl064",
            "FRS",
            "10001000010.............010.....",
            "cl0 {d},{s}",
            "alu",
        ),
        (
            "cl164",
            "FRS",
            "10001000010.............100.....",
            "cl1 {d},{s}",
            "alu",
        ),
        (
            "clb64",
            "FRS",
            "10001000010.............000.....",
            "clb {d},{s}",
            "alu",
        ),
        (
            "normamt",
            "FRS",
            "10001100000.............111.....",
            "normamt {d},{s}",
            "alu",
        ),
        (
            "normamt64",
            "FRS",
            "10001000011.............000.....",
            "normamt {d},{s}",
            "alu",
        ),
        (
            "clbadd",
            "FCLADD",
            "10001100001.............000.....",
            "add(clb {d},{s},#{imm})",
            "alu",
        ),
        (
            "clbadd64",
            "FCLADD",
            "10001000011.............010.....",
            "add(clb {d},{s},#{imm})",
            "alu",
        ),
        (
            "ct0",
            "FRS",
            "10001100010.............100.....",
            "ct0 {d},{s}",
            "alu",
        ),
        (
            "ct1",
            "FRS",
            "10001100010.............101.....",
            "ct1 {d},{s}",
            "alu",
        ),
        (
            "ct064",
            "FRS",
            "10001000111.............010.....",
            "ct0 {d},{s}",
            "alu",
        ),
        (
            "ct164",
            "FRS",
            "10001000111.............100.....",
            "ct1 {d},{s}",
            "alu",
        ),
        (
            "popcount",
            "FRS",
            "10001000011.............011.....",
            "popcount {d},{s}",
            "alu",
        ),
        (
            "parity",
            "FRR",
            "11010101111.....................",
            "parity {d},{s},{t}",
            "alu",
        ),
        (
            "parity64",
            "FRR",
            "11010000........................",
            "parity {d},{s},{t}",
            "alu",
        ),
        (
            "brev",
            "FRS",
            "10001100010.............110.....",
            "brev {d},{s}",
            "alu",
        ),
        (
            "brev64",
            "FRS",
            "10000000110.............110.....",
            "brev {d},{s}",
            "alu",
        ),
        (
            "swiz",
            "FRS",
            "10001100100.............111.....",
            "swiz {d},{s}",
            "alu",
        ),
        (
            "tstbit_i",
            "FPTST",
            "10000101000.......0.............",
            "{d}=tstbit({s},#{imm})",
            "alu",
        ),
        (
            "tstbitn_i",
            "FPTST",
            "10000101001.......0.............",
            "{d}=!tstbit({s},#{imm})",
            "alu",
        ),
        (
            "tstbit_r",
            "FCMP",
            "11000111000.....................",
            "{d}=tstbit({s},{t})",
            "alu",
        ),
        (
            "tstbitn_r",
            "FCMP",
            "11000111001.....................",
            "{d}=!tstbit({s},{t})",
            "alu",
        ),
        (
            "setbit_i",
            "FSHI",
            "10001100110.......0.....000.....",
            "setbit {d},{s},#{imm}",
            "alu",
        ),
        (
            "clrbit_i",
            "FSHI",
            "10001100110.......0.....001.....",
            "clrbit {d},{s},#{imm}",
            "alu",
        ),
        (
            "togglebit_i",
            "FSHI",
            "10001100110.......0.....010.....",
            "togglebit {d},{s},#{imm}",
            "alu",
        ),
        (
            "setbit_r",
            "FRR",
            "1100011010..............00......",
            "setbit {d},{s},{t}",
            "alu",
        ),
        (
            "clrbit_r",
            "FRR",
            "1100011010..............01......",
            "clrbit {d},{s},{t}",
            "alu",
        ),
        (
            "togglebit_r",
            "FRR",
            "1100011010..............10......",
            "togglebit {d},{s},{t}",
            "alu",
        ),
        (
            "bitsclr_r",
            "FCMP",
            "11000111100.....................",
            "{d}=bitsclr({s},{t})",
            "alu",
        ),
        (
            "bitsclrn_r",
            "FCMP",
            "11000111101.....................",
            "{d}=!bitsclr({s},{t})",
            "alu",
        ),
        (
            "bitsset_r",
            "FCMP",
            "11000111010.....................",
            "{d}=bitsset({s},{t})",
            "alu",
        ),
        (
            "bitssetn_r",
            "FCMP",
            "11000111011.....................",
            "{d}=!bitsset({s},{t})",
            "alu",
        ),
        (
            "bitsclr_i",
            "FPCLR",
            "10000101100.....................",
            "{d}=bitsclr({s},#{imm})",
            "alu",
        ),
        (
            "bitsclrn_i",
            "FPCLR",
            "10000101101.....................",
            "{d}=!bitsclr({s},#{imm})",
            "alu",
        ),
        (
            "extract",
            "FXTR",
            "100011011.........0.............",
            "extract {d},{s},#{width},#{off}",
            "alu",
        ),
        (
            "extractu",
            "FXTR",
            "100011010.........0.............",
            "extractu {d},{s},#{width},#{off}",
            "alu",
        ),
        (
            "extract64",
            "FXTR64",
            "10001010........................",
            "extract {d},{s},#{width},#{off}",
            "alu",
        ),
        (
            "extractu64",
            "FXTR64",
            "10000001........................",
            "extractu {d},{s},#{width},#{off}",
            "alu",
        ),
        (
            "extract_r",
            "FRR",
            "1100100100..............01......",
            "extract {d},{s},{t}",
            "alu",
        ),
        (
            "extractu_r",
            "FRR",
            "1100100100..............00......",
            "extractu {d},{s},{t}",
            "alu",
        ),
        (
            "extract64_r",
            "FRR",
            "1100000111..............10......",
            "extract {d},{s},{t}",
            "alu",
        ),
        (
            "extractu64_r",
            "FRR",
            "1100000100..............00......",
            "extractu {d},{s},{t}",
            "alu",
        ),
        (
            "insert",
            "FINS",
            "100011110.........0.............",
            "insert {x},{s},#{width},#{off}",
            "alu",
        ),
        (
            "insert64",
            "FINS64",
            "10000011........................",
            "insert {x},{s},#{width},#{off}",
            "alu",
        ),
        (
            "insert_r",
            "FXRR",
            "11001000........................",
            "insert {x},{s},{t}",
            "alu",
        ),
        (
            "insert64_r",
            "FXRR",
            "110010100.........0.............",
            "insert {x},{s},{t}",
            "alu",
        ),
        (
            "bitsplit_i",
            "FSHI",
            "10001000110.......0.....100.....",
            "bitsplit {d},{s},#{imm}",
            "alu",
        ),
        (
            "bitsplit_r",
            "FRR",
            "11010100..1.....................",
            "bitsplit {d},{s},{t}",
            "alu",
        ),
        (
            "cmpb_eq",
            "FCMP",
            "11000111110.............110.....",
            "{d}=cmpb.eq({s},{t})",
            "alu",
        ),
        (
            "cmpb_gt",
            "FCMP",
            "11000111110.............010.....",
            "{d}=cmpb.gt({s},{t})",
            "alu",
        ),
        (
            "cmpb_gtu",
            "FCMP",
            "11000111110.............111.....",
            "{d}=cmpb.gtu({s},{t})",
            "alu",
        ),
        (
            "cmpb_eq_i",
            "FCMPBI",
            "11011101.00................00...",
            "{d}=cmpb.eq({s},#{imm})",
            "alu",
        ),
        (
            "cmpb_gt_i",
            "FCMPBI",
            "11011101.01................00...",
            "{d}=cmpb.gt({s},#{imm})",
            "alu",
        ),
        (
            "cmpb_gtu_i",
            "FCMPBI",
            "11011101.10........0.......00...",
            "{d}=cmpb.gtu({s},#{imm})",
            "alu",
        ),
        (
            "cmph_eq",
            "FCMP",
            "11000111110.............011.....",
            "{d}=cmph.eq({s},{t})",
            "alu",
        ),
        (
            "cmph_gt",
            "FCMP",
            "11000111110.............100.....",
            "{d}=cmph.gt({s},{t})",
            "alu",
        ),
        (
            "cmph_gtu",
            "FCMP",
            "11000111110.............101.....",
            "{d}=cmph.gtu({s},{t})",
            "alu",
        ),
        (
            "cmph_gt_i",
            "FCMPBI",
            "11011101.01................01...",
            "{d}=cmph.gt({s},#{imm})",
            "alu",
        ),
        (
            "cmph_gtu_i",
            "FCMPBI",
            "11011101.10........0.......01...",
            "{d}=cmph.gtu({s},#{imm})",
            "alu",
        ),
        (
            "sat",
            "FRS",
            "10001000110.............000.....",
            "sat {d},{s}",
            "alu",
        ),
        (
            "sath",
            "FRS",
            "10001100110.............100.....",
            "sath {d},{s}",
            "alu",
        ),
        (
            "satuh",
            "FRS",
            "10001100110.............101.....",
            "satuh {d},{s}",
            "alu",
        ),
        (
            "satb",
            "FRS",
            "10001100110.............111.....",
            "satb {d},{s}",
            "alu",
        ),
        (
            "satub",
            "FRS",
            "10001100110.............110.....",
            "satub {d},{s}",
            "alu",
        ),
        (
            "round_sat",
            "FRS",
            "10001000110.............001.....",
            "round {d},{s}:sat",
            "alu",
        ),
        (
            "round_i",
            "FSHI",
            "10001100111.......0.....10......",
            "round {d},{s},#{imm}",
            "alu",
        ),
        (
            "round_i_sat",
            "FSHI",
            "10001100111.......0.....11......",
            "round {d},{s},#{imm}:sat",
            "alu",
        ),
        (
            "round_r",
            "FRR",
            "1100011011..............10......",
            "round {d},{s},{t}",
            "alu",
        ),
        (
            "round_r_sat",
            "FRR",
            "1100011011..............11......",
            "round {d},{s},{t}:sat",
            "alu",
        ),
        (
            "cround_i",
            "FSHI",
            "10001100111.......0.....00......",
            "cround {d},{s},#{imm}",
            "alu",
        ),
        (
            "cround_r",
            "FRR",
            "1100011011..............00......",
            "cround {d},{s},{t}",
            "alu",
        ),
        (
            "vsathub",
            "FRS",
            "10001000000.............000.....",
            "vsathub {d},{s}",
            "alu",
        ),
        (
            "vsathb",
            "FRS",
            "10001000000.............110.....",
            "vsathb {d},{s}",
            "alu",
        ),
        (
            "vsathub_p",
            "FRS",
            "10000000000.............100.....",
            "vsathub {d},{s}",
            "alu",
        ),
        (
            "vsathb_p",
            "FRS",
            "10000000000.............111.....",
            "vsathb {d},{s}",
            "alu",
        ),
        (
            "vaddhub_sat",
            "FRR",
            "1100000101..............001.....",
            "vaddhub {d},{s},{t}:sat",
            "alu",
        ),
        (
            "tableidxb",
            "FTIDX",
            "1000011100......................",
            "tableidxb {x},{s},#{imm},#{off}",
            "alu",
        ),
        (
            "tableidxh",
            "FTIDX",
            "1000011101......................",
            "tableidxh {x},{s},#{imm},#{off}",
            "alu",
        ),
        (
            "tableidxw",
            "FTIDX",
            "1000011110......................",
            "tableidxw {x},{s},#{imm},#{off}",
            "alu",
        ),
        (
            "tableidxd",
            "FTIDX",
            "1000011111......................",
            "tableidxd {x},{s},#{imm},#{off}",
            "alu",
        ),
        (
            "cmph_eq_i",
            "FCMPBI",
            "11011101.00................01...",
            "{d}=cmph.eq({s},#{imm})",
            "alu",
        ),
        (
            "vsatwh",
            "FRS",
            "10001000000.............010.....",
            "vsatwh {d},{s}",
            "alu",
        ),
        (
            "vsatwuh",
            "FRS",
            "10001000000.............100.....",
            "vsatwuh {d},{s}",
            "alu",
        ),
        (
            "vsathub_rs",
            "FRS",
            "1000110010..............01......",
            "vsathub {d},{s}",
            "alu",
        ),
        (
            "vsathb_rs",
            "FRS",
            "1000110010..............00......",
            "vsathb {d},{s}",
            "alu",
        ),
        (
            "vsatwh_p",
            "FRS",
            "10000000000.............110.....",
            "vsatwh {d},{s}",
            "alu",
        ),
        (
            "vsatwuh_p",
            "FRS",
            "10000000000.............101.....",
            "vsatwuh {d},{s}",
            "alu",
        ),
        (
            "vrndwh",
            "FRS",
            "10001000100.............100.....",
            "vrndwh {d},{s}",
            "alu",
        ),
        (
            "vrndwh_sat",
            "FRS",
            "10001000100.............110.....",
            "vrndwh {d},{s}:sat",
            "alu",
        ),
        (
            "vaddub64",
            "FRR",
            "11010011000.............000.....",
            "vaddub {d},{s},{t}",
            "alu",
        ),
        (
            "vaddub64_sat",
            "FRR",
            "11010011000.............001.....",
            "vaddub {d},{s},{t}:sat",
            "alu",
        ),
        (
            "vaddh64",
            "FRR",
            "11010011000.............010.....",
            "vaddh {d},{s},{t}",
            "alu",
        ),
        (
            "vaddh64_sat",
            "FRR",
            "11010011000.............011.....",
            "vaddh {d},{s},{t}:sat",
            "alu",
        ),
        (
            "vadduh64_sat",
            "FRR",
            "11010011000.............100.....",
            "vadduh {d},{s},{t}:sat",
            "alu",
        ),
        (
            "vaddw64",
            "FRR",
            "11010011000.............101.....",
            "vaddw {d},{s},{t}",
            "alu",
        ),
        (
            "vaddw64_sat",
            "FRR",
            "11010011000.............110.....",
            "vaddw {d},{s},{t}:sat",
            "alu",
        ),
        (
            "vsubub64",
            "FRR",
            "11010011001.............000.....",
            "vsubub {d},{t},{s}",
            "alu",
        ),
        (
            "vsubub64_sat",
            "FRR",
            "11010011001.............001.....",
            "vsubub {d},{t},{s}:sat",
            "alu",
        ),
        (
            "vsubh64",
            "FRR",
            "11010011001.............010.....",
            "vsubh {d},{t},{s}",
            "alu",
        ),
        (
            "vsubh64_sat",
            "FRR",
            "11010011001.............011.....",
            "vsubh {d},{t},{s}:sat",
            "alu",
        ),
        (
            "vsubuh64_sat",
            "FRR",
            "11010011001.............100.....",
            "vsubuh {d},{t},{s}:sat",
            "alu",
        ),
        (
            "vsubw64",
            "FRR",
            "11010011001.............101.....",
            "vsubw {d},{t},{s}",
            "alu",
        ),
        (
            "vsubw64_sat",
            "FRR",
            "11010011001.............110.....",
            "vsubw {d},{t},{s}:sat",
            "alu",
        ),
        (
            "vavgub64",
            "FRR",
            "11010011010.............000.....",
            "vavgub {d},{s},{t}",
            "alu",
        ),
        (
            "vavgub64_rnd",
            "FRR",
            "11010011010.............001.....",
            "vavgub {d},{s},{t}:rnd",
            "alu",
        ),
        (
            "vavguh64",
            "FRR",
            "11010011010.............101.....",
            "vavguh {d},{s},{t}",
            "alu",
        ),
        (
            "vavguh64_rnd",
            "FRR",
            "11010011010.............11......",
            "vavguh {d},{s},{t}:rnd",
            "alu",
        ),
        (
            "vavgh64",
            "FRR",
            "11010011010.............010.....",
            "vavgh {d},{s},{t}",
            "alu",
        ),
        (
            "vavgh64_rnd",
            "FRR",
            "11010011010.............011.....",
            "vavgh {d},{s},{t}:rnd",
            "alu",
        ),
        (
            "vavgh64_crnd",
            "FRR",
            "11010011010.............100.....",
            "vavgh {d},{s},{t}:crnd",
            "alu",
        ),
        (
            "vavgw64",
            "FRR",
            "11010011011.............000.....",
            "vavgw {d},{s},{t}",
            "alu",
        ),
        (
            "vavgw64_rnd",
            "FRR",
            "11010011011.............001.....",
            "vavgw {d},{s},{t}:rnd",
            "alu",
        ),
        (
            "vavgw64_crnd",
            "FRR",
            "11010011011.............010.....",
            "vavgw {d},{s},{t}:crnd",
            "alu",
        ),
        (
            "vavguw64",
            "FRR",
            "11010011011.............011.....",
            "vavguw {d},{s},{t}",
            "alu",
        ),
        (
            "vavguw64_rnd",
            "FRR",
            "11010011011.............100.....",
            "vavguw {d},{s},{t}:rnd",
            "alu",
        ),
        (
            "vnavgh64",
            "FRR",
            "11010011100.............000.....",
            "vnavgh {d},{t},{s}",
            "alu",
        ),
        (
            "vnavgh64_rnd_sat",
            "FRR",
            "11010011100.............001.....",
            "vnavgh {d},{t},{s}:rnd:sat",
            "alu",
        ),
        (
            "vnavgh64_crnd_sat",
            "FRR",
            "11010011100.............010.....",
            "vnavgh {d},{t},{s}:crnd:sat",
            "alu",
        ),
        (
            "vnavgw64",
            "FRR",
            "11010011100.............011.....",
            "vnavgw {d},{t},{s}",
            "alu",
        ),
        (
            "vnavgw64_rnd_sat",
            "FRR",
            "11010011100.............10......",
            "vnavgw {d},{t},{s}:rnd:sat",
            "alu",
        ),
        (
            "vnavgw64_crnd_sat",
            "FRR",
            "11010011100.............11......",
            "vnavgw {d},{t},{s}:crnd:sat",
            "alu",
        ),
        (
            "vmaxub64",
            "FRR",
            "11010011110.............000.....",
            "vmaxub {d},{t},{s}",
            "alu",
        ),
        (
            "vmaxb64",
            "FRR",
            "11010011110.............110.....",
            "vmaxb {d},{t},{s}",
            "alu",
        ),
        (
            "vmaxuh64",
            "FRR",
            "11010011110.............010.....",
            "vmaxuh {d},{t},{s}",
            "alu",
        ),
        (
            "vmaxh64",
            "FRR",
            "11010011110.............001.....",
            "vmaxh {d},{t},{s}",
            "alu",
        ),
        (
            "vmaxw64",
            "FRR",
            "11010011110.............011.....",
            "vmaxw {d},{t},{s}",
            "alu",
        ),
        (
            "vmaxuw64",
            "FRR",
            "11010011101.............101.....",
            "vmaxuw {d},{t},{s}",
            "alu",
        ),
        (
            "vminub64",
            "FRR",
            "11010011101.............000.....",
            "vminub {d},{t},{s}",
            "alu",
        ),
        (
            "vminb64",
            "FRR",
            "11010011110.............111.....",
            "vminb {d},{t},{s}",
            "alu",
        ),
        (
            "vminuh64",
            "FRR",
            "11010011101.............010.....",
            "vminuh {d},{t},{s}",
            "alu",
        ),
        (
            "vminh64",
            "FRR",
            "11010011101.............001.....",
            "vminh {d},{t},{s}",
            "alu",
        ),
        (
            "vminw64",
            "FRR",
            "11010011101.............011.....",
            "vminw {d},{t},{s}",
            "alu",
        ),
        (
            "vminuw64",
            "FRR",
            "11010011101.............100.....",
            "vminuw {d},{t},{s}",
            "alu",
        ),
        (
            "vmux",
            "FMUX",
            "11010001........................",
            "vmux {d},{p},{s},{t}",
            "alu",
        ),
        (
            "valignb_i",
            "FASL3",
            "110000000.......................",
            "valignb {d},{t},{s},#{imm}",
            "alu",
        ),
        (
            "valignb_p",
            "FMUX",
            "110000100.......................",
            "valignb {d},{t},{s},{p}",
            "alu",
        ),
        (
            "vspliceb_i",
            "FASL3",
            "110000001.......................",
            "vspliceb {d},{s},{t},#{imm}",
            "alu",
        ),
        (
            "vspliceb_p",
            "FMUX",
            "11000010100.....................",
            "vspliceb {d},{s},{t},{p}",
            "alu",
        ),
        (
            "vcnegh",
            "FRR",
            "1100001111..............01......",
            "vcnegh {d},{s},{t}",
            "alu",
        ),
        (
            "vrcnegh",
            "FXRR",
            "11001011001.......1.....111.....",
            "{x}+=vrcnegh({s},{t})",
            "alu",
        ),
        (
            "interleave",
            "FRS",
            "10000000110.............101.....",
            "interleave {d},{s}",
            "alu",
        ),
        (
            "deinterleave",
            "FRS",
            "10000000110.............100.....",
            "deinterleave {d},{s}",
            "alu",
        ),
        (
            "lfs",
            "FRR",
            "1100000110..............110.....",
            "lfs {d},{s},{t}",
            "alu",
        ),
        (
            "vtrunehb",
            "FRS",
            "10001000100.............010.....",
            "vtrunehb {d},{s}",
            "alu",
        ),
        (
            "vtrunohb",
            "FRS",
            "10001000100.............000.....",
            "vtrunohb {d},{s}",
            "alu",
        ),
        (
            "vtrunewh",
            "FRR",
            "1100000110..............010.....",
            "vtrunewh {d},{s},{t}",
            "alu",
        ),
        (
            "vtrunowh",
            "FRR",
            "1100000110..............100.....",
            "vtrunowh {d},{s},{t}",
            "alu",
        ),
        (
            "vtrunehb_p",
            "FRR",
            "1100000110..............011.....",
            "vtrunehb {d},{s},{t}",
            "alu",
        ),
        (
            "vtrunohb_p",
            "FRR",
            "1100000110..............101.....",
            "vtrunohb {d},{s},{t}",
            "alu",
        ),
        (
            "vsplatb",
            "FRS",
            "10001100010.............111.....",
            "vsplatb {d},{s}",
            "alu",
        ),
        (
            "vsplatb_p",
            "FRS",
            "1000010001..............10......",
            "vsplatb {d},{s}",
            "alu",
        ),
        (
            "vsplath",
            "FRS",
            "1000010001..............01......",
            "vsplath {d},{s}",
            "alu",
        ),
        (
            "vsxtbh",
            "FRS",
            "1000010000..............00......",
            "vsxtbh {d},{s}",
            "alu",
        ),
        (
            "vsxthw",
            "FRS",
            "1000010000..............10......",
            "vsxthw {d},{s}",
            "alu",
        ),
        (
            "vzxtbh",
            "FRS",
            "1000010000..............01......",
            "vzxtbh {d},{s}",
            "alu",
        ),
        (
            "vzxthw",
            "FRS",
            "1000010000..............11......",
            "vzxthw {d},{s}",
            "alu",
        ),
        (
            "andn_rr",
            "FRR",
            "11110001010.....................",
            "and {d},{s},~{t}",
            "alu",
        ),
        (
            "orn_rr",
            "FRR",
            "11110001110.....................",
            "or {d},{s},~{t}",
            "alu",
        ),
        (
            "addpc",
            "FPC6",
            "0110101001001001................",
            "add {d},pc,#{imm}",
            "alu",
        ),
    ] {
        m.insns
            .push(ins(name, format, pattern, base(), syntax, timing));
    }

    // ---- HX11: `if ([!]Pu[.new])` 条件付き ALU ----
    // ICLASS 15 の `11111xxx` は `11110xxx` の無条件形に対応
    // する条件実行形で、[26:21] の副オペコードを引き継ぐ:
    // [26:24]=001 は論理（and=000/or=001/xor=011、andn/orn 系は
    // なし）、011 は加減算（add=000/sub=001）、101 は combine
    // （000）。述語は pd2m（bits[6:5]）、否定 bit7・.new
    // bit13。combine は d5 を対レジスタの偶数側とみなす。
    // 条件付き即値形は `01110100`（Rd=add(Rs,#s8)。述語は
    // bits[22:21]、否定 bit23）と `01111110`（Rd=#s12。
    // 即値は bits{19:16}+{12:5}、## 拡張可能）で、どちらも
    // bit13 が .new。実符号は参照アセンブラの V73
    // プロファイルと照合済み（参照アセンブラは `Rd={#0,Rs}` の
    // 条件付き転送を add(Rs,#0)/#s12 に落とす）。
    // Ref: SPEC-HEXAGON-PRM (V79) conditional instructions.
    for (name, format, pattern, syntax, timing) in [
        (
            "cand_rr",
            "FCPQ",
            "11111001000.....................",
            "and {d},{s},{t}",
            "alu",
        ),
        (
            "cor_rr",
            "FCPQ",
            "11111001001.....................",
            "or {d},{s},{t}",
            "alu",
        ),
        (
            "cxor_rr",
            "FCPQ",
            "11111001011.....................",
            "xor {d},{s},{t}",
            "alu",
        ),
        (
            "cadd_rr",
            "FCPQ",
            "11111011000.....................",
            "add {d},{s},{t}",
            "alu",
        ),
        (
            "csub_rr",
            "FCPQ",
            "11111011001.....................",
            "sub {d},{t},{s}",
            "alu",
        ),
        (
            "ccomb_rr",
            "FCPQ",
            "11111101000.....................",
            "combine {d},{s},{t}",
            "alu",
        ),
        // if ([!]Pu[.new]) Rd = add(Rs,#s8)。
        (
            "cadd_ri",
            "FCAI",
            "01110100........................",
            "add {d},{s},#{imm}",
            "alu",
        ),
        // if ([!]Pu[.new]) Rd = #s12（## 拡張可能）。
        (
            "cmov_i",
            "FCI12",
            "01111110........................",
            "{d}=#{imm}",
            "alu",
        ),
    ] {
        m.insns
            .push(ins(name, format, pattern, base(), syntax, timing));
    }

    // ---- duplex subinsn（13 ビット語）。
    // 各命令の `when` は subinsn のグループに対応する文脈旗。
    // Ref: SPEC-HEXAGON-PRM (V79) sub-instructions / duplex encoding.
    for (name, format, pattern, when, syntax, timing) in [
        // L1: u4 + base + dst。bit12=0 は w:2、1 は ub:0。
        (
            "dx_l1_memw",
            "DXLD",
            "0............",
            wl1(),
            "{d}=memw({s}+#{u}:2)",
            "load",
        ),
        (
            "dx_l1_memub",
            "DXLD",
            "1............",
            wl1(),
            "{d}=memub({s}+#{u}:0)",
            "load",
        ),
        // L2: [12:11]=00 memh、01 memuh、10 memb。u3 は h:1・b:0。
        (
            "dx_l2_memh",
            "DXL2",
            "00...........",
            wl2(),
            "{d}=memh({s}+#{u}:1)",
            "load",
        ),
        (
            "dx_l2_memuh",
            "DXL2",
            "01...........",
            wl2(),
            "{d}=memuh({s}+#{u}:1)",
            "load",
        ),
        (
            "dx_l2_memb",
            "DXL2",
            "10...........",
            wl2(),
            "{d}=memb({s}+#{u}:0)",
            "load",
        ),
        // L2: r29 相対。
        (
            "dx_l2_ldwsp",
            "DXSP",
            "1110.........",
            wl2(),
            "{d}=memw(r29+#{u}:2)",
            "load",
        ),
        (
            "dx_l2_lddsp",
            "DXMD",
            "11110........",
            wl2(),
            "{dd}=memd(r29+#{u}:3)",
            "load",
        ),
        // L2: フレーム/リターン。dprd3: 0=無条件、4/5=p0/!p0、
        // 6/7=p0.new/!p0.new（実符号と照合済み）。
        (
            "dx_l2_deallocframe",
            "DXFR",
            "1111100000...",
            wl2(),
            "deallocframe",
            "alu",
        ),
        (
            "dx_l2_deallocret",
            "DXFR",
            "1111101......",
            wl2(),
            "dealloc_return:{pred}",
            "branch",
        ),
        (
            "dx_l2_jumpr",
            "DXFR",
            "1111111......",
            wl2(),
            "jumpr31:{pred}",
            "branch",
        ),
        // S1: u4 + base + data。bit12=0 は w:2、1 は b:0。
        (
            "dx_s1_memw",
            "DXS1",
            "0............",
            ws1(),
            "memw({s}+#{u}:2)={t}",
            "store",
        ),
        (
            "dx_s1_memb",
            "DXS1",
            "1............",
            ws1(),
            "memb({s}+#{u}:0)={t}",
            "store",
        ),
        // S2: [12:11]=00 memh。u3 は h:1。
        (
            "dx_s2_memh",
            "DXST",
            "00...........",
            ws2(),
            "memh({s}+#{u}:1)={t}",
            "store",
        ),
        // S2: r29 相対。
        (
            "dx_s2_stwsp",
            "DXSSP",
            "0100.........",
            ws2(),
            "memw(r29+#{u}:2)={t}",
            "store",
        ),
        (
            "dx_s2_stdsp",
            "DXSMD",
            "0101.........",
            ws2(),
            "memd(r29+#{i}:3)={tt}",
            "store",
        ),
        // S2: ストア即値形。bit9=0 は w:2、1 は b:0。
        (
            "dx_s2_stwi",
            "DXSI",
            "1000.........",
            ws2(),
            "memw({s}+#{u4}:2)=#{i}",
            "store",
        ),
        (
            "dx_s2_stbi",
            "DXSI",
            "1001.........",
            ws2(),
            "memb({s}+#{u4}:0)=#{i}",
            "store",
        ),
        // S2: allocframe。
        (
            "dx_s2_allocframe",
            "DXAF",
            "1110.........",
            ws2(),
            "allocframe(#{u}:3)",
            "store",
        ),
        // A: [12:11]=00 add(Rx,#s7)。
        (
            "dx_a_addi",
            "DXAI",
            "00...........",
            wa(),
            "add({x},{x},#{s})",
            "alu",
        ),
        // A: [12:10]=010 Rd=#u6、011 add(r29,#u6:2)。
        (
            "dx_a_uimm",
            "DXU6",
            "010..........",
            wa(),
            "{d}=#{u}",
            "alu",
        ),
        (
            "dx_a_spadd",
            "DXU6",
            "011..........",
            wa(),
            "{d}=add(r29,#{u}:2)",
            "alu",
        ),
        // A: bit12=1 のレジスタ/即値形。[11:8] が副オペコード。
        ("dx_a_mov", "DXRR", "10000........", wa(), "{d}={s}", "alu"),
        (
            "dx_a_add1",
            "DXRR",
            "10001........",
            wa(),
            "{d}=add({s},#1)",
            "alu",
        ),
        (
            "dx_a_and1",
            "DXRR",
            "10010........",
            wa(),
            "{d}=and({s},#1)",
            "alu",
        ),
        (
            "dx_a_sub1",
            "DXRR",
            "10011........",
            wa(),
            "{d}=add({s},#-1)",
            "alu",
        ),
        (
            "dx_a_sxth",
            "DXRR",
            "10100........",
            wa(),
            "{d}=sxth({s})",
            "alu",
        ),
        (
            "dx_a_sxtb",
            "DXRR",
            "10101........",
            wa(),
            "{d}=sxtb({s})",
            "alu",
        ),
        (
            "dx_a_zxth",
            "DXRR",
            "10110........",
            wa(),
            "{d}=zxth({s})",
            "alu",
        ),
        (
            "dx_a_zxtb",
            "DXRR",
            "10111........",
            wa(),
            "{d}=zxtb({s})",
            "alu",
        ),
        (
            "dx_a_addr",
            "DXRR",
            "11000........",
            wa(),
            "add({d},{d},{s})",
            "alu",
        ),
        (
            "dx_a_cmpeq",
            "DXCE",
            "11001....00..",
            wa(),
            "p0=cmp.eq({s},#{u})",
            "alu",
        ),
        // A: 条件クリア/`-1`。dprd: 0=Rd=#-1、4/5=p0.new/!p0.new、
        // 6/7=p0/!p0（実符号と照合済み）。bit7=0 固定。
        (
            "dx_a_clr",
            "DXCL",
            "110100.......",
            wa(),
            "clr:{pred} {d}",
            "alu",
        ),
        // A: combine 系。11100=#u2/#U2、11101=#0/Rs(bit3=0)・Rs/#0(bit3=1)。
        (
            "dx_a_combi",
            "DXCI",
            "11100........",
            wa(),
            "{dd}=combine(#{ua},#{ub})",
            "alu",
        ),
        (
            "dx_a_comb0",
            "DXCR",
            "11101....0...",
            wa(),
            "{dd}=combine(#0,{s})",
            "alu",
        ),
        (
            "dx_a_comb1",
            "DXCR",
            "11101....1...",
            wa(),
            "{dd}=combine({s},#0)",
            "alu",
        ),
    ] {
        m.insns
            .push(ins(name, format, pattern, when, syntax, timing));
    }

    // ---- HX9: HVX 代表部分集合 ----
    // Gap: GAP-0070 GAP-0071
    // 全部 `hvx` 旗でゲート（同旗がないモデルでは復号不能＝
    // illegal 命令例外となる）。実符号は参照アセンブラ
    // （V73 + hvx プロファイル）と照合済み。
    // - vmem: 整列 io 形（ld/st/:nt）・vmemu 非整列形・
    //   post-inc 即値/++Mu・Qv 述語付きストア（:nt 含む）。
    //   即値はベクトル幅単位（V73 系 128B）。tmp/scatter/
    //   gather・reg-offset 系は語彙外（docs/gaps.md 参照）。
    // - ALU: vadd/vsub（b/h/w）、論理（vand/vor/vxor）、
    //   vavg/vnavg、vmin/vmax（b/ub/h/uh/w）、:sat 加減算、
    //   vmpy 系（bb/ub→h、hh/uh→w、+= 累積）、vcombine/vmov/
    //   vsplat/vinsert.w/vand(Qv,Vs)。
    // - Q: vcmp.eq/gt（b/h/w）→Qd と q 論理（and/or/xor/not/
    //   否定入力版）。
    // Ref: SPEC-HEXAGON-PRM (V79), 80-N2040-61 (HVX).
    let whvx = || Pred::Flag("hvx".to_string());
    for (name, format, pattern, syntax) in [
        // vmem 基本 io 形（ICLASS 系 LD/ST スロット）。bits[12:11]
        // は無述語形で 0 固定、bits[7:5]=000 が整列形。
        (
            "hvld_io",
            "FVLD",
            "00101000000........00...000.....",
            "{d}=vmem({s}+#{imm})",
        ),
        (
            "hvld_iont",
            "FVLD",
            "00101000010........00...000.....",
            "{d}=vmem({s}+#{imm}):nt",
        ),
        (
            "hvst_io",
            "FVST",
            "00101000001........00...000.....",
            "vmem({s}+#{imm})={t}",
        ),
        (
            "hvst_iont",
            "FVST",
            "00101000011........00...000.....",
            "vmem({s}+#{imm}):nt={t}",
        ),
        // vmemu 非整列形（bits[7:5]=111、オフセット桁は 0 固定）。
        (
            "hvldu_io",
            "FVLD",
            "00101000000........00...111.....",
            "{d}=vmemu({s})",
        ),
        (
            "hvstu_io",
            "FVST",
            "00101000001........00...111.....",
            "vmemu({s})={t}",
        ),
        // Qv 述語付きストア（bits[12:11]=Qv、bit5=否定）。
        (
            "hvst_iopq",
            "FVSTPQ",
            "00101000100.............00......",
            "if(...) vmem({s}+#{imm})={t}",
        ),
        (
            "hvst_iopqnt",
            "FVSTPQ",
            "00101000110.............00......",
            "if(...) vmem({s}+#{imm}):nt={t}",
        ),
        // post-inc 即値形（bits[10:8]=s3、ベクトル幅単位）。
        (
            "hvld_pi",
            "FVLDPI",
            "00101001000.......000...000.....",
            "{d}=vmem({x}++#{s4})",
        ),
        (
            "hvst_pi",
            "FVSTPI",
            "00101001001.......000...000.....",
            "vmem({x}++#{s4})={t}",
        ),
        // post-inc ++Mu 形（bit13=M0/M1 選択）。
        (
            "hvld_pr",
            "FVLDMU",
            "00101011000........00000000.....",
            "{d}=vmem({x}++m{mu})",
        ),
        (
            "hvld_prnt",
            "FVLDMU",
            "00101011010........00000000.....",
            "{d}=vmem({x}++m{mu}):nt",
        ),
        (
            "hvst_pr",
            "FVSTMU",
            "00101011001........00000000.....",
            "vmem({x}++m{mu})={t}",
        ),
        // ベクトル加減算（b/h/w）。
        (
            "hv_vadd_b",
            "FV3",
            "00011111101.......0.....110.....",
            "{d}.b=vadd({u}.b,{v}.b)",
        ),
        (
            "hv_vadd_h",
            "FV3",
            "00011111101.......0.....111.....",
            "{d}.h=vadd({u}.h,{v}.h)",
        ),
        (
            "hv_vadd_w",
            "FV3",
            "00011100010.......0.....000.....",
            "{d}.w=vadd({u}.w,{v}.w)",
        ),
        (
            "hv_vsub_b",
            "FV3",
            "00011100010.......0.....101.....",
            "{d}.b=vsub({u}.b,{v}.b)",
        ),
        (
            "hv_vsub_h",
            "FV3",
            "00011100010.......0.....110.....",
            "{d}.h=vsub({u}.h,{v}.h)",
        ),
        (
            "hv_vsub_w",
            "FV3",
            "00011100010.......0.....111.....",
            "{d}.w=vsub({u}.w,{v}.w)",
        ),
        // ベクトル論理。
        (
            "hv_vand",
            "FV3",
            "00011100001.......0.....101.....",
            "{d}=vand({u},{v})",
        ),
        (
            "hv_vor",
            "FV3",
            "00011100001.......0.....110.....",
            "{d}=vor({u},{v})",
        ),
        (
            "hv_vxor",
            "FV3",
            "00011100001.......0.....111.....",
            "{d}=vxor({u},{v})",
        ),
        // 平均系（b/ub/h/uh と :rnd・vnavg.h）。
        (
            "hv_vavg_b",
            "FV3",
            "00011111000.......1.....100.....",
            "{d}.b=vavg({u}.b,{v}.b)",
        ),
        (
            "hv_vavg_ub",
            "FV3",
            "00011100110.......0.....100.....",
            "{d}.ub=vavg({u}.ub,{v}.ub)",
        ),
        (
            "hv_vavg_uh",
            "FV3",
            "00011100110.......0.....101.....",
            "{d}.uh=vavg({u}.uh,{v}.uh)",
        ),
        (
            "hv_vavg_h",
            "FV3",
            "00011100110.......0.....110.....",
            "{d}.h=vavg({u}.h,{v}.h)",
        ),
        (
            "hv_vavghr",
            "FV3",
            "00011100111.......0.....101.....",
            "{d}.h=vavg({u}.h,{v}.h):rnd",
        ),
        (
            "hv_vnavg_h",
            "FV3",
            "00011100111.......0.....001.....",
            "{d}.h=vnavg({u}.h,{v}.h)",
        ),
        // 最小・最大（b/ub/h/uh/w）。
        (
            "hv_vmin_b",
            "FV3",
            "00011111001.......0.....100.....",
            "{d}.b=vmin({u}.b,{v}.b)",
        ),
        (
            "hv_vmin_ub",
            "FV3",
            "00011111000.......0.....001.....",
            "{d}.ub=vmin({u}.ub,{v}.ub)",
        ),
        (
            "hv_vmin_h",
            "FV3",
            "00011111000.......0.....011.....",
            "{d}.h=vmin({u}.h,{v}.h)",
        ),
        (
            "hv_vmin_uh",
            "FV3",
            "00011111000.......0.....010.....",
            "{d}.uh=vmin({u}.uh,{v}.uh)",
        ),
        (
            "hv_vmin_w",
            "FV3",
            "00011111000.......0.....100.....",
            "{d}.w=vmin({u}.w,{v}.w)",
        ),
        (
            "hv_vmax_b",
            "FV3",
            "00011111001.......0.....101.....",
            "{d}.b=vmax({u}.b,{v}.b)",
        ),
        (
            "hv_vmax_ub",
            "FV3",
            "00011111000.......0.....101.....",
            "{d}.ub=vmax({u}.ub,{v}.ub)",
        ),
        (
            "hv_vmax_h",
            "FV3",
            "00011111000.......0.....111.....",
            "{d}.h=vmax({u}.h,{v}.h)",
        ),
        (
            "hv_vmax_uh",
            "FV3",
            "00011111000.......0.....110.....",
            "{d}.uh=vmax({u}.uh,{v}.uh)",
        ),
        (
            "hv_vmax_w",
            "FV3",
            "00011111001.......0.....000.....",
            "{d}.w=vmax({u}.w,{v}.w)",
        ),
        // 飽和加減算（b/ub/h/uh/w/uw。飽和時は vcsr に sticky）。
        (
            "hv_vadds_b",
            "FV3",
            "00011111000.......0.....000.....",
            "{d}.b=vadd({u}.b,{v}.b):sat",
        ),
        (
            "hv_vadds_ub",
            "FV3",
            "00011100010.......0.....001.....",
            "{d}.ub=vadd({u}.ub,{v}.ub):sat",
        ),
        (
            "hv_vadds_uh",
            "FV3",
            "00011100010.......0.....010.....",
            "{d}.uh=vadd({u}.uh,{v}.uh):sat",
        ),
        (
            "hv_vadds_h",
            "FV3",
            "00011100010.......0.....011.....",
            "{d}.h=vadd({u}.h,{v}.h):sat",
        ),
        (
            "hv_vadds_w",
            "FV3",
            "00011100010.......0.....100.....",
            "{d}.w=vadd({u}.w,{v}.w):sat",
        ),
        (
            "hv_vadds_uw",
            "FV3",
            "00011111011.......0.....001.....",
            "{d}.uw=vadd({u}.uw,{v}.uw):sat",
        ),
        (
            "hv_vsubs_b",
            "FV3",
            "00011111001.......0.....010.....",
            "{d}.b=vsub({u}.b,{v}.b):sat",
        ),
        (
            "hv_vsubs_ub",
            "FV3",
            "00011100011.......0.....000.....",
            "{d}.ub=vsub({u}.ub,{v}.ub):sat",
        ),
        (
            "hv_vsubs_uh",
            "FV3",
            "00011100011.......0.....001.....",
            "{d}.uh=vsub({u}.uh,{v}.uh):sat",
        ),
        (
            "hv_vsubs_h",
            "FV3",
            "00011100011.......0.....010.....",
            "{d}.h=vsub({u}.h,{v}.h):sat",
        ),
        (
            "hv_vsubs_w",
            "FV3",
            "00011100011.......0.....011.....",
            "{d}.w=vsub({u}.w,{v}.w):sat",
        ),
        // ペア出力の乗算系（bb/ub→h、hh/uh→w と += 累積形）。
        (
            "hv_vmpy_bb",
            "FVDD",
            "00011100000.......0.....100.....",
            "{dd}.h=vmpy({u}.b,{v}.b)",
        ),
        (
            "hv_vmpy_ub",
            "FVDD",
            "00011100000.......0.....101.....",
            "{dd}.uh=vmpy({u}.ub,{v}.ub)",
        ),
        (
            "hv_vmpy_hh",
            "FVDD",
            "00011100000.......0.....111.....",
            "{dd}.w=vmpy({u}.h,{v}.h)",
        ),
        (
            "hv_vmpy_uh",
            "FVDD",
            "00011100001.......0.....000.....",
            "{dd}.uw=vmpy({u}.uh,{v}.uh)",
        ),
        (
            "hv_vmpy_bb_acc",
            "FVDD",
            "00011100000.......1.....100.....",
            "{dd}.h+=vmpy({u}.b,{v}.b)",
        ),
        (
            "hv_vmpy_ub_acc",
            "FVDD",
            "00011100000.......1.....101.....",
            "{dd}.uh+=vmpy({u}.ub,{v}.ub)",
        ),
        (
            "hv_vmpy_hh_acc",
            "FVDD",
            "00011100000.......1.....111.....",
            "{dd}.w+=vmpy({u}.h,{v}.h)",
        ),
        (
            "hv_vmpy_uh_acc",
            "FVDD",
            "00011100001.......1.....000.....",
            "{dd}.uw+=vmpy({u}.uh,{v}.uh)",
        ),
        // ムーブ系（vcombine/vmov/vsplats/vinsert.w/vand(Qv,Vs)）。
        (
            "hv_vcombine",
            "FVDD",
            "00011111010.......0.....111.....",
            "{dd}=vcombine({u},{v})",
        ),
        (
            "hv_vmov",
            "FV2",
            "0001111000000011..1.....111.....",
            "{d}={u}",
        ),
        (
            "hv_vsplat_b",
            "FVG",
            "00011001110.......000000010.....",
            "{d}.b=vsplat({s})",
        ),
        (
            "hv_vsplat_h",
            "FVG",
            "00011001110.......000000001.....",
            "{d}.h=vsplat({s})",
        ),
        (
            "hv_vinsert_w",
            "FVG",
            "00011001101.......100000001.....",
            "{d}.w=vinsert({s})",
        ),
        (
            "hv_vandq",
            "FVQV",
            "00011110..000011..1.....000.....",
            "{d}=vand({p},{u})",
        ),
        // Q 生成の要素比較（eq/gt、b/h/w）。
        (
            "hv_vcmpeq_b",
            "FVCMP",
            "00011111100.......0.....000000..",
            "{qd}=vcmp.eq({u}.b,{v}.b)",
        ),
        (
            "hv_vcmpeq_h",
            "FVCMP",
            "00011111100.......0.....000001..",
            "{qd}=vcmp.eq({u}.h,{v}.h)",
        ),
        (
            "hv_vcmpeq_w",
            "FVCMP",
            "00011111100.......0.....000010..",
            "{qd}=vcmp.eq({u}.w,{v}.w)",
        ),
        (
            "hv_vcmpgt_b",
            "FVCMP",
            "00011111100.......0.....000100..",
            "{qd}=vcmp.gt({u}.b,{v}.b)",
        ),
        (
            "hv_vcmpgt_h",
            "FVCMP",
            "00011111100.......0.....000101..",
            "{qd}=vcmp.gt({u}.h,{v}.h)",
        ),
        (
            "hv_vcmpgt_w",
            "FVCMP",
            "00011111100.......0.....000110..",
            "{qd}=vcmp.gt({u}.w,{v}.w)",
        ),
        // q 論理（and/or/xor/否定入力/not）。
        (
            "hv_qand",
            "FVQ",
            "00011110..000011..0.....000000..",
            "{qd}=and({s},{t})",
        ),
        (
            "hv_qor",
            "FVQ",
            "00011110..000011..0.....000001..",
            "{qd}=or({s},{t})",
        ),
        (
            "hv_qxor",
            "FVQ",
            "00011110..000011..0.....000011..",
            "{qd}=xor({s},{t})",
        ),
        (
            "hv_qorn",
            "FVQ",
            "00011110..000011..0.....000100..",
            "{qd}=or({s},!{t})",
        ),
        (
            "hv_qandn",
            "FVQ",
            "00011110..000011..0.....000101..",
            "{qd}=and({s},!{t})",
        ),
        (
            "hv_qnot",
            "FVQ1",
            "0001111000000011..0.....000010..",
            "{qd}=not({s})",
        ),
    ] {
        m.insns
            .push(ins(name, format, pattern, whvx(), syntax, "hvx"));
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
