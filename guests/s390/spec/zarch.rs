// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// s390/zArchitecture の ISADL モデル（ユーザーモード・命令面）。
//
// z/Architecture は可変長（2/4/6 バイト）・ビッグエンディアン。命令長は
// 先頭バイトの上位 2 ビットで決まる: 00→2B, 01→4B, 10→4B, 11→6B。
// フェッチ側がこの規則で長さを決め、16/32/48 ビットのパターンに振り分ける。
//
// 分類は「先頭バイトごとの命令」が基本で、0xB2(S 形式)/0xB9(RRE/RRF)/
// 0xB3(RRF)/0xE3(RXY)/0xEB(RSY)/0xEC(RIE)/0xED(RXE)/0xC0-0xC6(RIL)/0xE5
// のような 2 バイトオペコード空間は 1 つの Insn にまとめ、細かい機能の
// 振り分けは意味論側（`sem`）が行う。ARM/Power と同じ粗分類である。
//
// 出典は SPEC-S390-ZARCH-POP（SA22-7832）と SPEC-S390-ESA390-POP
// （SA22-7201）。ESA/390 の命令面は bare 実行で併せてカバーする。
// Ref: SPEC-S390-ZARCH-POP (SA22-7832-13), SPEC-S390-ESA390-POP (SA22-7201-08).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// s390 の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "mult", "div", "system", "fp", "string",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // 機能と CPU モデル。ESA/390 面は esa390 で z/Arch 追加分を外せる形。
    for name in ["zarch", "long-disp", "ext-imm", "dfp", "hfp"] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: vec![],
            conflicts: vec![],
        });
    }
    for (name, parent, add, rem) in [
        ("z900", "", vec!["zarch"], vec![]),
        ("z990", "z900", vec![], vec![]),
        ("z9ec", "z990", vec!["long-disp"], vec![]),
        ("z10ec", "z9ec", vec![], vec![]),
        ("z196", "z10ec", vec![], vec![]),
        ("zec12", "z196", vec![], vec![]),
        ("z13", "zec12", vec![], vec![]),
        ("generic", "z13", vec![], vec![]),
        ("esa390", "", vec![], vec!["zarch"]),
    ] {
        m.models.push(ModelDef {
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: rem.iter().map(|s| s.to_string()).collect(),
        ident: vec![],
        });
    }

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    m.formats.push(Format {
        name: "FR".to_string(),
        fields: vec![],
        operands: vec![],
    });

    let mut push = |name: &str, pattern: String, timing: &str| {
        m.insns.push(Insn {
            name: name.to_string(),
            format: "FR".to_string(),
            pattern: Pattern::parse(&pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![],
            syntax: name.to_string(),
            timing: timing.to_string(),
        });
    };

    // 16 ビット（先頭バイト 0x00-0x3f）。E 形式・RR 形式。
    let p16 = |b0: u8| format!("{b0:08b} ........");
    push("e_misc", "000000.. ........".to_string(), "system");
    for (name, op, timing) in [
        ("spm", 0x04, "system"),
        ("balr", 0x05, "branch"),
        ("bctr", 0x06, "branch"),
        ("bcr", 0x07, "branch"),
        ("x08", 0x08, "system"), // SSK（特権）
        ("x09", 0x09, "system"), // ISK（特権）
        ("svc", 0x0a, "system"),
        ("bsm", 0x0b, "branch"),
        ("bassm", 0x0c, "branch"),
        ("basr", 0x0d, "branch"),
        ("mvcl", 0x0e, "string"),
        ("clcl", 0x0f, "string"),
        ("lpr", 0x10, "alu"),
        ("lnr", 0x11, "alu"),
        ("ltr", 0x12, "alu"),
        ("lcr", 0x13, "alu"),
        ("nr", 0x14, "alu"),
        ("clr", 0x15, "alu"),
        ("or", 0x16, "alu"),
        ("xr", 0x17, "alu"),
        ("lr", 0x18, "alu"),
        ("cr", 0x19, "alu"),
        ("ar", 0x1a, "alu"),
        ("sr", 0x1b, "alu"),
        ("mr", 0x1c, "mult"),
        ("dr", 0x1d, "div"),
        ("alr", 0x1e, "alu"),
        ("slr", 0x1f, "alu"),
        ("lpdr", 0x20, "fp"),
        ("lndr", 0x21, "fp"),
        ("ltdr", 0x22, "fp"),
        ("lcdr", 0x23, "fp"),
        ("hdr", 0x24, "fp"),
        ("ldxr", 0x25, "fp"),
        ("mxr", 0x26, "fp"),
        ("mxdr", 0x27, "fp"),
        ("ldr", 0x28, "fp"),
        ("cdr", 0x29, "fp"),
        ("adr", 0x2a, "fp"),
        ("sdr", 0x2b, "fp"),
        ("mdr", 0x2c, "fp"),
        ("ddr", 0x2d, "fp"),
        ("awr", 0x2e, "fp"),
        ("swr", 0x2f, "fp"),
        ("lper", 0x30, "fp"),
        ("lner", 0x31, "fp"),
        ("lter", 0x32, "fp"),
        ("lcer", 0x33, "fp"),
        ("her", 0x34, "fp"),
        ("ledr", 0x35, "fp"),
        ("axr", 0x36, "fp"),
        ("sxr", 0x37, "fp"),
        ("ler", 0x38, "fp"),
        ("cer", 0x39, "fp"),
        ("aer", 0x3a, "fp"),
        ("ser", 0x3b, "fp"),
        ("mer", 0x3c, "fp"),
        ("der", 0x3d, "fp"),
        ("x3e", 0x3e, "alu"),
        ("x3f", 0x3f, "alu"),
    ] {
        push(name, p16(op), timing);
    }

    // 32 ビット（先頭バイト 0x40-0xbf）。RX/RS/SI/S/RRE/RRF 形式。
    let p32 = |b0: u8| format!("{b0:08b} ........ ........ ........");
    for (name, op, timing) in [
        ("sth", 0x40, "store"),
        ("la", 0x41, "alu"),
        ("stc", 0x42, "store"),
        ("ic", 0x43, "load"),
        ("ex", 0x44, "system"),
        ("bal", 0x45, "branch"),
        ("bct", 0x46, "branch"),
        ("bc", 0x47, "branch"),
        ("lh", 0x48, "load"),
        ("ch", 0x49, "alu"),
        ("ah", 0x4a, "alu"),
        ("sh", 0x4b, "alu"),
        ("mh", 0x4c, "mult"),
        ("bas", 0x4d, "branch"),
        ("cvd", 0x4e, "alu"),
        ("cvb", 0x4f, "alu"),
        ("st", 0x50, "store"),
        ("lae", 0x51, "alu"),
        ("n", 0x54, "alu"),
        ("cl", 0x55, "alu"),
        ("o", 0x56, "alu"),
        ("x", 0x57, "alu"),
        ("l", 0x58, "load"),
        ("c", 0x59, "alu"),
        ("a", 0x5a, "alu"),
        ("s", 0x5b, "alu"),
        ("mulw", 0x5c, "mult"), // M
        ("d", 0x5d, "div"),
        ("al", 0x5e, "alu"),
        ("sl", 0x5f, "alu"),
        ("std", 0x60, "store"),
        ("mxd", 0x67, "fp"),
        ("ld", 0x68, "load"),
        ("cd", 0x69, "fp"),
        ("ad", 0x6a, "fp"),
        ("sd", 0x6b, "fp"),
        ("md", 0x6c, "fp"),
        ("dd", 0x6d, "fp"),
        ("aw", 0x6e, "fp"),
        ("sw", 0x6f, "fp"),
        ("ste", 0x70, "store"),
        ("ms", 0x71, "mult"),
        ("le", 0x78, "load"),
        ("ce", 0x79, "fp"),
        ("ae", 0x7a, "fp"),
        ("se", 0x7b, "fp"),
        ("mde", 0x7c, "fp"),
        ("de", 0x7d, "fp"),
        ("au", 0x7e, "fp"),
        ("su", 0x7f, "fp"),
        ("diag", 0x83, "system"),
        ("brxh", 0x84, "branch"),
        ("brxle", 0x85, "branch"),
        ("bxh", 0x86, "branch"),
        ("bxle", 0x87, "branch"),
        ("srl", 0x88, "alu"),
        ("sll", 0x89, "alu"),
        ("sra", 0x8a, "alu"),
        ("sla", 0x8b, "alu"),
        ("srdl", 0x8c, "alu"),
        ("sldl", 0x8d, "alu"),
        ("srda", 0x8e, "alu"),
        ("slda", 0x8f, "alu"),
        ("stm", 0x90, "store"),
        ("tm", 0x91, "alu"),
        ("mvi", 0x92, "store"),
        ("ts", 0x93, "system"),
        ("ni", 0x94, "alu"),
        ("cli", 0x95, "alu"),
        ("oi", 0x96, "alu"),
        ("xi", 0x97, "alu"),
        ("lm", 0x98, "load"),
        ("lam", 0x9a, "load"),
        ("stam", 0x9b, "store"),
        ("mvcle", 0xa8, "string"),
        ("clcle", 0xa9, "string"),
        ("stnsm", 0xac, "system"),
        ("stosm", 0xad, "system"),
        ("cs", 0xba, "alu"),
        ("cds", 0xbb, "alu"),
        ("clm", 0xbd, "alu"),
        ("stcm", 0xbe, "store"),
        ("icm", 0xbf, "load"),
    ] {
        push(name, p32(op), timing);
    }
    // RI 形式（A5/A7: 先頭バイト＋下位ニブル機能）。
    let p32ri = |b0: u8, f: u8| format!("{b0:08b} .... {f:04b} ................");
    for (name, f) in [
        ("nihh", 0x4u8),
        ("nihl", 0x5),
        ("nilh", 0x6),
        ("nill", 0x7),
        ("oihh", 0x8),
        ("oihl", 0x9),
        ("oilh", 0xa),
        ("oill", 0xb),
        ("llihh", 0xc),
        ("llihl", 0xd),
        ("llilh", 0xe),
        ("llill", 0xf),
    ] {
        push(name, p32ri(0xa5, f), "alu");
    }
    for (name, f, t) in [
        ("tmlh", 0x0u8, "alu"),
        ("tmll", 0x1, "alu"),
        ("tmhh", 0x2, "alu"),
        ("tmhl", 0x3, "alu"),
        ("brc", 0x4, "branch"),
        ("bras", 0x5, "branch"),
        ("brct", 0x6, "branch"),
        ("brctg", 0x7, "branch"),
        ("lhi", 0x8, "alu"),
        ("lghi", 0x9, "alu"),
        ("ahi", 0xa, "alu"),
        ("aghi", 0xb, "alu"),
        ("mhi", 0xc, "mult"),
        ("mghi", 0xd, "mult"),
        ("chi", 0xe, "alu"),
        ("cghi", 0xf, "alu"),
    ] {
        push(name, p32ri(0xa7, f), t);
    }
    // 2 バイトオペコードの塊（細かい振り分けは sem の仕事）。
    push("s_b2", p32(0xb2), "system"); // S 形式・拡張 RRE（stck/srst/cksm 等）
    push("b3", p32(0xb3), "fp"); // RRF/RRE の BFP 群
    push("b9", p32(0xb9), "alu"); // RRE/RRF の整数群

    // 48 ビット（先頭バイト 0xc0-0xff）。RIL/SS/RXY/RSY/RIE/RXE/SIL/SSE。
    let p48 = |b0: u8| format!("{b0:08b} ........ ........ ........ ........ ........");
    let p48f = |b0: u8, f: u8| {
        format!("{b0:08b} .... {f:04b} ................ ................")
    };
    for (name, f, t) in [
        ("larl", 0x0u8, "alu"),
        ("lgfi", 0x1, "alu"),
        ("brcl", 0x4, "branch"),
        ("brasl", 0x5, "branch"),
        ("xihf", 0x6, "alu"),
        ("xilf", 0x7, "alu"),
        ("iihf", 0x8, "alu"),
        ("iilf", 0x9, "alu"),
        ("nihf", 0xa, "alu"),
        ("nilf", 0xb, "alu"),
        ("oihf", 0xc, "alu"),
        ("oilf", 0xd, "alu"),
        ("llihf", 0xe, "alu"),
        ("llilf", 0xf, "alu"),
    ] {
        push(name, p48f(0xc0, f), t);
    }
    for (name, f) in [
        ("msgfi", 0x0u8),
        ("msfi", 0x1),
        ("slgfi", 0x4),
        ("slfi", 0x5),
        ("agfi", 0x8),
        ("afi", 0x9),
        ("algfi", 0xa),
        ("alfi", 0xb),
        ("cgfi", 0xc),
        ("cfi", 0xd),
        ("clgfi", 0xe),
        ("clfi", 0xf),
    ] {
        push(name, p48f(0xc2, f), "alu");
    }
    for (name, f, t) in [
        ("llhrl", 0x2u8, "load"),
        ("lghrl", 0x4, "load"),
        ("lhrl", 0x5, "load"),
        ("llghrl", 0x6, "load"),
        ("sthrl", 0x7, "store"),
        ("lgrl", 0x8, "load"),
        ("stgrl", 0xb, "store"),
        ("lgfrl", 0xc, "load"),
        ("lrl", 0xd, "load"),
        ("llgfrl", 0xe, "load"),
        ("strl", 0xf, "store"),
    ] {
        push(name, p48f(0xc4, f), t);
    }
    // C5 は BPRP（分枝予測ヒント）。ユーザーモードでは no-op 扱い。
    push("bprp", p48(0xc5), "branch");
    for (name, f, t) in [
        ("exrl", 0x0u8, "system"),
        ("cghrl", 0x4, "alu"),
        ("chrl", 0x5, "alu"),
        ("clghrl", 0x6, "alu"),
        ("clhrl", 0x7, "alu"),
        ("cgrl", 0x8, "alu"),
        ("clgrl", 0xa, "alu"),
        ("cgfrl", 0xc, "alu"),
        ("crl", 0xd, "alu"),
        ("clgfrl", 0xe, "alu"),
        ("clrl", 0xf, "alu"),
    ] {
        push(name, p48f(0xc6, f), t);
    }
    // SS 形式（文字列・10 進）。未対応は sem が明示的に未定義にする。
    for (name, op, timing) in [
        ("mvn", 0xd1, "string"),
        ("mvc", 0xd2, "string"),
        ("mvz", 0xd3, "string"),
        ("nc", 0xd4, "string"),
        ("clc", 0xd5, "string"),
        ("oc", 0xd6, "string"),
        ("xc", 0xd7, "string"),
        ("tr", 0xdc, "string"),
        ("trt", 0xdd, "string"),
        ("ed", 0xde, "string"),
        ("edmk", 0xdf, "string"),
        ("srp", 0xf0, "system"),
        ("mvo", 0xf1, "string"),
        ("pack", 0xf2, "string"),
        ("unpk", 0xf3, "string"),
        ("zap", 0xf8, "string"),
        ("cp", 0xf9, "string"),
        ("ap", 0xfa, "string"),
        ("sp", 0xfb, "string"),
        ("mp", 0xfc, "string"),
        ("dp", 0xfd, "string"),
    ] {
        push(name, p48(op), timing);
    }
    // RXY/RSY/RIE/RXE/SIL/SSE の塊。
    push("e3", p48(0xe3), "alu"); // RXY（lg/stg/llgf/cs/dsg 等）
    push("eb", p48(0xeb), "alu"); // RSY（lmg/stmg/slgf/sllg/rllg/icmh 等）
    push("ec", p48(0xec), "alu"); // RIE（cgij/cgrj/risbg 等）
    push("rxe", p48(0xed), "fp"); // RXE（adb/ldb/stdy/ley 等）
    push("e5", p48(0xe5), "system"); // SSE/SIL（mvhhi/mvhi 等、LASP は特権）

    m
}
