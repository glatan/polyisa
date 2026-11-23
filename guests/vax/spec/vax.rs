// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// VAX の ISADL モデル（段階23）。
//
// VAX の命令は可変長で、1 バイト本体と 0xFD/0xFE/0xFF 接頭の
// 2 バイトオペコードの後に、オペランド指定子のバイト列が続く。
// 本モデルはオペコード部だけを命令語（8/16 ビット）として宣言し、
// `decode(word, 8|16)` の長さ分岐で全オペコード空間を表す
// （IA-64 のスロット語先例）。語へのバイトの詰め方はフェッチ順に
// 下位ビットから（1 バイト目が bits[7:0]、2 バイト語の上位は
// 接頭の次のバイト）。オペランド指定子の読み取り・消費長・適合
// 検査・符号化と命令ごとの指定子シグネチャは
// `guests/vax/src/specifier.rs` が担う（VX3 で m68k 分割を採用）。
//
// 出典は SPEC-VAX-ARM（命令エンコーディングとサブセット化の規則）
// と SPEC-VAX-MICROVAX（KA660 §3.7 の実装群/支援群/未実装群の
// 区分）である。
// Ref: SPEC-VAX-ARM, SPEC-VAX-MICROVAX.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// VAX の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "move", "branch", "call", "fp", "decimal", "string", "queue", "system", "misc",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 機能旗。命令群の実装差（直接実行か補完経路か）を表す。
    // フル VAX はすべて持ち、MicroVAX 系は実装しない群を
    // remove_features で削る。削られた命令は補完要求（サブセット
    // 例外）として扱い、配送経路は `emul_dispatch` パラメータ。
    // - `decimal`: パック十進・数値文字列命令（movp/cmpp/addp/
    //   subp/mulp/divp/cvt*/ashp 系）。
    // - `hfp`: H 形式浮動小数点と octaword 命令。
    // - `string_ext`: 拡張文字列命令（matchc/movtc/movtuc）。
    // - `string_cmp`: 文字列の比較・走査系（cmpc3/cmpc5/locc/
    //   scanc/skpc/spanc の 6 個）。SOC 系はマイクロコードで実装
    //   するが、KA630（MicroVAX II）では補完対象だった世代差の節点。
    // - `crc`: crc。
    // - `editpc`: editpc。
    // - `compat`: PDP-11 互換モード命令。
    // Ref: SPEC-VAX-ARM（サブセット化の章）, SPEC-VAX-MICROVAX §3.7.
    for name in [
        "decimal",
        "hfp",
        "string_ext",
        "string_cmp",
        "crc",
        "editpc",
        "compat",
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: vec![],
        });
    }

    // 挙動パラメータ。
    // Ref: SPEC-VAX-MICROVAX §3.9（補完経路と SCB）.
    m.param(
        "emul_dispatch",
        ParamKind::Enum(vec!["hook".to_string(), "scb".to_string()]),
        "hook",
        "実装しない命令（サブセット外）の補完要求の配送経路。\
         hook=実行側のトラップハンドラへ渡す、\
         scb=SCB の補完ベクタ（FPD=0/1 で開始/継続）への実機どおりの配送",
    );
    m.param(
        "dv_hw",
        ParamKind::Bool,
        "true",
        "PSL<7> DV（十進オーバーフロー トラップ有効）をハードが扱うか。\
         KA660 では無効で、十進補完の macrocode がこの桁を使う",
    );

    // CPU モデル。11/780 はフル VAX（全機能）の基底。MicroVAX 系は
    // 実装しない群を削る。NVAX 以降の世代差（compat の有無等）の
    // 確定は VX11 で正本照合のうえ行う。
    // - microvax2（KA630・MicroVAX II）: decimal/hfp/string_ext/
    //   string_cmp/crc/editpc/compat を補完対象とする。
    // - ka660（SOC）: KA630 との差は string_cmp の 6 個を実装
    //   する点。dv_hw はハードが扱わない。
    // Ref: SPEC-VAX-ARM, SPEC-VAX-MICROVAX §3.7.
    let subset: &[&str] = &[
        "decimal",
        "hfp",
        "string_ext",
        "string_cmp",
        "crc",
        "editpc",
        "compat",
    ];
    for (name, parent, add, remove, params) in [
        ("vax11_780", "", subset, &[][..], &[][..]),
        ("microvax2", "vax11_780", &[][..], subset, &[][..]),
        (
            "ka660",
            "vax11_780",
            &[][..],
            &[
                "decimal",
                "hfp",
                "string_ext",
                "crc",
                "editpc",
                "compat",
            ][..],
            &[("dv_hw", "false")][..],
        ),
        ("nvax", "vax11_780", &[][..], &["compat"][..], &[][..]),
    ] {
        m.models.push(ModelDef {
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: remove.iter().map(|s| s.to_string()).collect(),
            ident: vec![],
        });
    }

    // 汎用レジスタ r0-r15。構文上 r12-r15 は AP/FP/SP/PC と書く。
    m.regclasses.push(RegClass {
        name: "gr".to_string(),
        dynamic: false,
        prefix: Some("r".to_string()),
    });

    // 桁。2 バイトオペコードの第 2 バイト（接頭の次）。オペランド
    // 指定子の桁は命令語に含まれないためここでは宣言しない
    // （指定子ストリームの設計は VX3）。
    m.fields.push(Field {
        name: "op2".to_string(),
        kind: FieldKind::Bits { hi: 15, lo: 8 },
    });

    // 形式。O1 は 1 バイトオペコード、O2 は 0xFD/0xFE/0xFF 接頭の
    // 2 バイトオペコード。いずれもオペランド指定子を伴わない。
    m.formats.push(Format {
        name: "O1".to_string(),
        fields: vec![],
        operands: vec![],
    });
    m.formats.push(Format {
        name: "O2".to_string(),
        fields: vec!["op2".to_string()],
        operands: vec![],
    });

    // 命令の宣言。パターンは語の上位ビットから書く。2 バイト語は
    // bits[7:0] が接頭、bits[15:8]（op2）が次のバイト。
    //
    // 指定子を伴う命令も形式は O1/O2 のまま（指定子は命令語に乗ら
    // ない）。各命令の指定子シグネチャ（.xy 型の並び。最終列は
    // その写し）は `guests/vax/src/specifier.rs` の `insn_ops` が
    // 持つ —— m68k の ea.rs と同型の分割（段階23 計画 VX3）。
    //
    // `feat` が空でない命令はその機能旗を `when` に持ち、旗を削る
    // モデルではデコードされず補完経路に乗る。
    // Ref: SPEC-VAX-ARM（命令エンコーディングと各命令の形式記述）.
    let insns: &[(&str, &str, &str, &str, &str, &str)] = &[
        // (名前, 形式, パターン, タイミング, 機能旗, 指定子)
        ("halt", "O1", "0000 0000", "system", "", ""),
        ("nop", "O1", "0000 0001", "misc", "", ""),
        ("rei", "O1", "0000 0010", "system", "", ""),
        ("bpt", "O1", "0000 0011", "system", "", ""),
        ("ret", "O1", "0000 0100", "call", "", ""),
        ("rsb", "O1", "0000 0101", "call", "", ""),
        ("ldpctx", "O1", "0000 0110", "system", "", ""),
        ("svpctx", "O1", "0000 0111", "system", "", ""),
        ("insque", "O1", "0000 1110", "queue", "", "ab,ab"),
        ("remque", "O1", "0000 1111", "queue", "", "ab,wl"),
        ("bsbb", "O1", "0001 0000", "call", "", "bb"),
        ("brb", "O1", "0001 0001", "branch", "", "bb"),
        ("bneq", "O1", "0001 0010", "branch", "", "bb"),
        ("beql", "O1", "0001 0011", "branch", "", "bb"),
        ("jsb", "O1", "0001 0110", "call", "", "ab"),
        ("jmp", "O1", "0001 0111", "branch", "", "ab"),
        ("movc3", "O1", "0010 1000", "string", "", "rw,ab,ab"),
        ("cmpc3", "O1", "0010 1001", "string", "string_cmp", "rw,ab,ab"),
        (
            "scanc",
            "O1",
            "0010 1010",
            "string",
            "string_cmp",
            "rw,ab,ab,rb",
        ),
        (
            "spanc",
            "O1",
            "0010 1011",
            "string",
            "string_cmp",
            "rw,ab,ab,rb",
        ),
        ("movc5", "O1", "0010 1100", "string", "", "rw,ab,rb,rw,ab"),
        (
            "cmpc5",
            "O1",
            "0010 1101",
            "string",
            "string_cmp",
            "rb,rw,ab,rw,ab",
        ),
        ("bsbw", "O1", "0011 0000", "call", "", "bw"),
        ("brw", "O1", "0011 0001", "branch", "", "bw"),
        ("cvtwl", "O1", "0011 0010", "alu", "", "rw,wl"),
        ("cvtwb", "O1", "0011 0011", "alu", "", "rw,wb"),
        ("locc", "O1", "0011 1010", "string", "string_cmp", "rb,rw,ab"),
        ("skpc", "O1", "0011 1011", "string", "string_cmp", "rb,rw,ab"),
        ("movzwl", "O1", "0011 1100", "move", "", "rw,wl"),
        ("movaw", "O1", "0011 1110", "move", "", "aw,wl"),
        ("pushaw", "O1", "0011 1111", "move", "", "aw"),
        ("emul", "O1", "0111 1010", "alu", "", "rl,rl,rl,wq"),
        ("ediv", "O1", "0111 1011", "alu", "", "rl,rq,wl,wl"),
        ("clrq", "O1", "0111 1100", "move", "", "wq"),
        ("movq", "O1", "0111 1101", "move", "", "rq,wq"),
        ("movaq", "O1", "0111 1110", "move", "", "aq,wl"),
        ("pushaq", "O1", "0111 1111", "move", "", "aq"),
        ("addb2", "O1", "1000 0000", "alu", "", "rb,mb"),
        ("addb3", "O1", "1000 0001", "alu", "", "rb,rb,wb"),
        ("subb2", "O1", "1000 0010", "alu", "", "rb,mb"),
        ("subb3", "O1", "1000 0011", "alu", "", "rb,rb,wb"),
        ("mulb2", "O1", "1000 0100", "alu", "", "rb,mb"),
        ("mulb3", "O1", "1000 0101", "alu", "", "rb,rb,wb"),
        ("divb2", "O1", "1000 0110", "alu", "", "rb,mb"),
        ("divb3", "O1", "1000 0111", "alu", "", "rb,rb,wb"),
        ("mnegb", "O1", "1000 1110", "alu", "", "rb,wb"),
        ("caseb", "O1", "1000 1111", "branch", "", "rb,rb,rb"),
        ("movb", "O1", "1001 0000", "move", "", "rb,wb"),
        ("cmpb", "O1", "1001 0001", "alu", "", "rb,rb"),
        ("mcomb", "O1", "1001 0010", "move", "", "rb,wb"),
        ("clrb", "O1", "1001 0100", "move", "", "wb"),
        ("tstb", "O1", "1001 0101", "alu", "", "rb"),
        ("incb", "O1", "1001 0110", "alu", "", "mb"),
        ("decb", "O1", "1001 0111", "alu", "", "mb"),
        ("cvtbl", "O1", "1001 1000", "alu", "", "rb,wl"),
        ("cvtbw", "O1", "1001 1001", "alu", "", "rb,ww"),
        ("movzbl", "O1", "1001 1010", "move", "", "rb,wl"),
        ("movzbw", "O1", "1001 1011", "move", "", "rb,ww"),
        ("rotl", "O1", "1001 1100", "alu", "", "rb,rl,wl"),
        ("movab", "O1", "1001 1110", "move", "", "ab,wl"),
        ("pushab", "O1", "1001 1111", "move", "", "ab"),
        ("addw2", "O1", "1010 0000", "alu", "", "rw,mw"),
        ("addw3", "O1", "1010 0001", "alu", "", "rw,rw,ww"),
        ("subw2", "O1", "1010 0010", "alu", "", "rw,mw"),
        ("subw3", "O1", "1010 0011", "alu", "", "rw,rw,ww"),
        ("mulw2", "O1", "1010 0100", "alu", "", "rw,mw"),
        ("mulw3", "O1", "1010 0101", "alu", "", "rw,rw,ww"),
        ("divw2", "O1", "1010 0110", "alu", "", "rw,mw"),
        ("divw3", "O1", "1010 0111", "alu", "", "rw,rw,ww"),
        ("mnegw", "O1", "1010 1110", "alu", "", "rw,ww"),
        ("casew", "O1", "1010 1111", "branch", "", "rw,rw,rw"),
        ("movw", "O1", "1011 0000", "move", "", "rw,ww"),
        ("cmpw", "O1", "1011 0001", "alu", "", "rw,rw"),
        ("mcomw", "O1", "1011 0010", "move", "", "rw,ww"),
        ("clrw", "O1", "1011 0100", "move", "", "ww"),
        ("tstw", "O1", "1011 0101", "alu", "", "rw"),
        ("incw", "O1", "1011 0110", "alu", "", "mw"),
        ("decw", "O1", "1011 0111", "alu", "", "mw"),
        ("addl2", "O1", "1100 0000", "alu", "", "rl,ml"),
        ("addl3", "O1", "1100 0001", "alu", "", "rl,rl,wl"),
        ("subl2", "O1", "1100 0010", "alu", "", "rl,ml"),
        ("subl3", "O1", "1100 0011", "alu", "", "rl,rl,wl"),
        ("mull2", "O1", "1100 0100", "alu", "", "rl,ml"),
        ("mull3", "O1", "1100 0101", "alu", "", "rl,rl,wl"),
        ("divl2", "O1", "1100 0110", "alu", "", "rl,ml"),
        ("divl3", "O1", "1100 0111", "alu", "", "rl,rl,wl"),
        ("bisl2", "O1", "1100 1000", "alu", "", "rl,ml"),
        ("bicl2", "O1", "1100 1010", "alu", "", "rl,ml"),
        ("xorl2", "O1", "1100 1100", "alu", "", "rl,ml"),
        ("mnegl", "O1", "1100 1110", "alu", "", "rl,wl"),
        ("casel", "O1", "1100 1111", "branch", "", "rl,rl,rl"),
        ("movl", "O1", "1101 0000", "move", "", "rl,wl"),
        ("cmpl", "O1", "1101 0001", "alu", "", "rl,rl"),
        ("mcoml", "O1", "1101 0010", "move", "", "rl,wl"),
        ("clrl", "O1", "1101 0100", "move", "", "wl"),
        ("tstl", "O1", "1101 0101", "alu", "", "rl"),
        ("incl", "O1", "1101 0110", "alu", "", "ml"),
        ("decl", "O1", "1101 0111", "alu", "", "ml"),
        ("adwc", "O1", "1101 1000", "alu", "", "rl,ml"),
        ("sbwc", "O1", "1101 1001", "alu", "", "rl,ml"),
        ("pushl", "O1", "1101 1101", "move", "", "rl"),
        ("moval", "O1", "1101 1110", "move", "", "al,wl"),
        ("pushal", "O1", "1101 1111", "move", "", "al"),
        ("bbs", "O1", "1110 0000", "branch", "", "rl,vb,bb"),
        ("bbc", "O1", "1110 0001", "branch", "", "rl,vb,bb"),
        ("bbss", "O1", "1110 0010", "branch", "", "rl,vb,bb"),
        ("bbcc", "O1", "1110 0101", "branch", "", "rl,vb,bb"),
        ("blbs", "O1", "1110 1000", "branch", "", "rl,bb"),
        ("blbc", "O1", "1110 1001", "branch", "", "rl,bb"),
        ("ffs", "O1", "1110 1010", "alu", "", "rl,rb,vb,wl"),
        ("ffc", "O1", "1110 1011", "alu", "", "rl,rb,vb,wl"),
        ("cmpv", "O1", "1110 1100", "alu", "", "rl,rb,vb,rl"),
        ("cmpzv", "O1", "1110 1101", "alu", "", "rl,rb,vb,rl"),
        ("extv", "O1", "1110 1110", "alu", "", "rl,rb,vb,wl"),
        ("extzv", "O1", "1110 1111", "alu", "", "rl,rb,vb,wl"),
        ("insv", "O1", "1111 0000", "alu", "", "rl,rl,rb,vb"),
        ("acbl", "O1", "1111 0001", "alu", "", "rl,rl,ml,bw"),
        ("aoblss", "O1", "1111 0010", "alu", "", "rl,ml,bb"),
        ("aobleq", "O1", "1111 0011", "alu", "", "rl,ml,bb"),
        ("sobgeq", "O1", "1111 0100", "branch", "", "ml,bb"),
        ("sobgtr", "O1", "1111 0101", "branch", "", "ml,bb"),
        ("cvtlb", "O1", "1111 0110", "alu", "", "rl,wb"),
        ("cvtlw", "O1", "1111 0111", "alu", "", "rl,ww"),
        ("callg", "O1", "1111 1010", "call", "", "ab,ab"),
        ("calls", "O1", "1111 1011", "call", "", "rl,ab"),
        ("bugw", "O2", "1111 1111 1111 1101", "system", "", ""),
        ("bugl", "O2", "1111 1111 1111 1110", "system", "", ""),
        ("movo", "O2", "0111 1101 1111 1101", "move", "hfp", "ro,wo"),
        ("movah", "O2", "0111 1110 1111 1101", "move", "hfp", "ah,wl"),
        ("pushah", "O2", "0111 1111 1111 1101", "move", "hfp", "ah"),
    ];
    for &(name, format, pattern, timing, feat, _ops) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: if feat.is_empty() {
                Pred::True
            } else {
                Pred::Flag(feat.to_string())
            },
            wheres: vec![],
            syntax: name.to_string(),
            timing: timing.to_string(),
        });
    }

    m
}
