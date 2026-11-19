// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// AArch64（A64）整数命令の ISADL モデル。
//
// 最初の範囲は Armv8.0-A 相当の整数命令と、ユーザーモードで必要な
// システム命令（SVC・ヒント・ユーザー可読システムレジスタ）である。
// 浮動小数点・AdvSIMD・FEAT_* の各拡張は後から足す。
// Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// A64 の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "system", "mult", "div"] {
        m.timing_classes.push(class.to_string());
    }

    // 機能と汎用 CPU モデル。FEAT_* は後の段階で足す。
    // Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09).
    m.features.push(polyisa_isadl::model::Feature {
        name: "fp".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.features.push(polyisa_isadl::model::Feature {
        name: "asimd".to_string(),
        implies: vec!["fp".to_string()],
        conflicts: vec![],
    });
    m.features.push(polyisa_isadl::model::Feature {
        name: "lse".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.features.push(polyisa_isadl::model::Feature {
        name: "be".to_string(),
        implies: vec![],
        conflicts: vec![],
    });
    m.models.push(polyisa_isadl::model::ModelDef {
            params: vec![],
        name: "generic".to_string(),
        parent: String::new(),
        add_features: ["fp", "asimd"].iter().map(|s| s.to_string()).collect(),
        remove_features: Vec::new(),
        ident: vec![],
    });
    m.models.push(polyisa_isadl::model::ModelDef {
            params: vec![],
        name: "generic_v81".to_string(),
        parent: "generic".to_string(),
        add_features: ["lse"].iter().map(|s| s.to_string()).collect(),
        remove_features: Vec::new(),
        ident: vec![],
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
        prefix: Some("x".to_string()),
    });

    // ビットフィールド宣言。A64 のフィールドは命令形式で位置がばらけるため、
    // 使うものすべてを名前つきで宣言する。
    for (name, hi, lo) in [
        ("sf", 31, 31),
        ("opc", 30, 29),
        ("op30", 30, 30),
        ("size", 31, 30),
        ("opc_ls", 23, 22),
        ("rd", 4, 0),
        ("rn", 9, 5),
        ("rm", 20, 16),
        ("ra", 14, 10),
        ("rt2", 14, 10),
        ("cond", 3, 0),
        ("nzcv", 3, 0),
        ("hw", 22, 21),
        ("sh", 22, 22),
        ("shift", 23, 22),
        ("nbit", 22, 22),
        ("option", 15, 13),
        ("sbit", 12, 12),
        ("imm3", 12, 10),
        ("imm5", 20, 16),
        ("imm6", 15, 10),
        ("imm7", 21, 15),
        ("imm9", 20, 12),
        ("imm12", 21, 10),
        ("imm14", 18, 5),
        ("imm16", 20, 5),
        ("imm19", 23, 5),
        ("imm26", 25, 0),
        ("immr", 21, 16),
        ("imms", 15, 10),
        ("b40", 23, 19),
        ("mode", 11, 10),
        ("idx", 24, 23),
        ("lbit", 22, 22),
        ("op0", 20, 19),
        ("op1", 18, 16),
        ("crn", 15, 12),
        ("crm", 11, 8),
        ("op2", 7, 5),
        ("o0", 15, 15),
        ("o2", 21, 21),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    // 形式（operand メタデータ。解読はパターンの仕事）。
    let gpr = |name: &str, access: Access| Operand {
        name: name.to_string(),
        field: None,
        regclass: Some("gpr".to_string()),
        access,
    };
    m.formats.push(Format {
        name: "F3".to_string(),
        fields: vec!["rd".to_string(), "rn".to_string(), "rm".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rn", Access::Read),
            gpr("rm", Access::Read),
        ],
    });
    m.formats.push(Format {
        name: "F2".to_string(),
        fields: vec!["rd".to_string(), "rn".to_string()],
        operands: vec![gpr("rd", Access::Write), gpr("rn", Access::Read)],
    });
    m.formats.push(Format {
        name: "FL".to_string(),
        fields: vec!["rd".to_string(), "rn".to_string()],
        operands: vec![gpr("rd", Access::Write), gpr("rn", Access::Read)],
    });
    m.formats.push(Format {
        name: "FB".to_string(),
        fields: vec![],
        operands: vec![],
    });
    m.formats.push(Format {
        name: "FT".to_string(),
        fields: vec!["rd".to_string(), "rn".to_string()],
        operands: vec![gpr("rd", Access::Write), gpr("rn", Access::Read)],
    });
    m.formats.push(Format {
        name: "FN".to_string(),
        fields: vec![],
        operands: vec![],
    });

    // (名前, 形式, パターン, 構文, 分類)
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        // ---- 分岐 ----
        // B/BL。imm26 << 2 の PC 相対。
        ("b", "FB", "000101 ..........................", "b {imm}", "branch"),
        ("bl", "FB", "100101 ..........................", "bl {imm}", "branch"),
        // B.cond。bit4=0 固定。
        ("b_cond", "FB", "01010100 ................... 0 ....", "b.cond {imm}", "branch"),
        // CBZ/CBNZ。sf で W/X を分ける（exec 側がフィールドを読む）。
        ("cbz", "FB", ". 011010 0 ................... .....", "cbz {rt}, {imm}", "branch"),
        ("cbnz", "FB", ". 011010 1 ................... .....", "cbnz {rt}, {imm}", "branch"),
        // TBZ/TBNZ。bit = (b5<<5)|b40。
        ("tbz", "FB", ". 011011 0 ..... .............. .....", "tbz {rt}, {bit}, {imm}", "branch"),
        ("tbnz", "FB", ". 011011 1 ..... .............. .....", "tbnz {rt}, {bit}, {imm}", "branch"),
        // レジスタ分岐。
        ("br", "FB", "1101011 0000 11111 000000 ..... 00000", "br {rn}", "branch"),
        ("blr", "FB", "1101011 0001 11111 000000 ..... 00000", "blr {rn}", "branch"),
        ("ret", "FB", "1101011 0010 11111 000000 ..... 00000", "ret {rn}", "branch"),
        // ---- 例外生成・システム ----
        ("svc", "FN", "11010100 000 ................ 000 01", "svc {imm}", "system"),
        ("hvc", "FN", "11010100 000 ................ 000 10", "hvc {imm}", "system"),
        ("smc", "FN", "11010100 000 ................ 000 11", "smc {imm}", "system"),
        ("brk", "FN", "11010100 001 ................ 000 00", "brk {imm}", "system"),
        ("hlt", "FN", "11010100 010 ................ 000 00", "hlt {imm}", "system"),
        // システムレジスタとシステム命令。MSR/MRS は op0[1]=1（S2/S3 系）、
        // SYS/SYSL は op0[1]=0。ヒント（NOP・バリア）と IC/DC は SYS 空間に
        // 含まれるため、SYS 側が無害な NOP として処理する。
        ("msr", "FN", "1101010100 0 1. ... .... .... ... .....", "msr {sysop}, {rt}", "system"),
        ("mrs", "FN", "1101010100 1 1. ... .... .... ... .....", "mrs {rt}, {sysop}", "system"),
        ("sys", "FN", "1101010100 0 0. ... .... .... ... .....", "sys {sysop}", "system"),
        ("sysl", "FN", "1101010100 1 0. ... .... .... ... .....", "sysl {rt}, {sysop}", "system"),
        // ---- データ処理（即値）----
        // 加減算（imm12 << (12*sh)）。sf/op/S はフィールドで取る。
        ("add_imm", "F3", ". 00 100010 . ............ ..... .....", "add {rd}, {rn}, {imm}", "alu"),
        ("adds_imm", "F3", ". 01 100010 . ............ ..... .....", "adds {rd}, {rn}, {imm}", "alu"),
        ("sub_imm", "F3", ". 10 100010 . ............ ..... .....", "sub {rd}, {rn}, {imm}", "alu"),
        ("subs_imm", "F3", ". 11 100010 . ............ ..... .....", "subs {rd}, {rn}, {imm}", "alu"),
        // 論理即値（ビットマスク即値）。op: and/orr/eor/ands。
        ("and_imm", "F3", ". 00 100100 . ...... ...... ..... .....", "and {rd}, {rn}, {imm}", "alu"),
        ("orr_imm", "F3", ". 01 100100 . ...... ...... ..... .....", "orr {rd}, {rn}, {imm}", "alu"),
        ("eor_imm", "F3", ". 10 100100 . ...... ...... ..... .....", "eor {rd}, {rn}, {imm}", "alu"),
        ("ands_imm", "F3", ". 11 100100 . ...... ...... ..... .....", "ands {rd}, {rn}, {imm}", "alu"),
        // ワイド即値。opc: movn/movz/movk（opc=01 は未割り当て）。
        ("movn", "F2", ". 00 100101 .. ................ .....", "movn {rd}, {imm}", "alu"),
        ("movz", "F2", ". 10 100101 .. ................ .....", "movz {rd}, {imm}", "alu"),
        ("movk", "F2", ". 11 100101 .. ................ .....", "movk {rd}, {imm}", "alu"),
        // ADR/ADRP。op で区別、imm = sext(immhi:immlo) << (12*op)。
        ("adr", "F2", "0 .. 10000 ................... .....", "adr {rd}, {imm}", "alu"),
        ("adrp", "F2", "1 .. 10000 ................... .....", "adrp {rd}, {imm}", "alu"),
        // ビットフィールド。opc: sbfm/bfm/ubfm。N は sf と一致が必須。
        ("sbfm", "F3", ". 00 100110 . ...... ...... ..... .....", "sbfm {rd}, {rn}, {immr}, {imms}", "alu"),
        ("bfm", "F3", ". 01 100110 . ...... ...... ..... .....", "bfm {rd}, {rn}, {immr}, {imms}", "alu"),
        ("ubfm", "F3", ". 10 100110 . ...... ...... ..... .....", "ubfm {rd}, {rn}, {immr}, {imms}", "alu"),
        // EXTR（連結右シフト。ror の別名を含む）。N は sf と一致が必須。
        ("extr", "F3", ". 00 100111 . 0 ..... ...... ..... .....", "extr {rd}, {rn}, {rm}, {imms}", "alu"),
        // ---- データ処理（レジスタ）----
        // 論理シフト。opc と N で 8 命令。shift: lsl/lsr/asr/ror。
        ("and_sh", "F3", ". 00 01010 .. 0 ..... ...... ..... .....", "and {rd}, {rn}, {rm}", "alu"),
        ("bic_sh", "F3", ". 00 01010 .. 1 ..... ...... ..... .....", "bic {rd}, {rn}, {rm}", "alu"),
        ("orr_sh", "F3", ". 01 01010 .. 0 ..... ...... ..... .....", "orr {rd}, {rn}, {rm}", "alu"),
        ("orn_sh", "F3", ". 01 01010 .. 1 ..... ...... ..... .....", "orn {rd}, {rn}, {rm}", "alu"),
        ("eor_sh", "F3", ". 10 01010 .. 0 ..... ...... ..... .....", "eor {rd}, {rn}, {rm}", "alu"),
        ("eon_sh", "F3", ". 10 01010 .. 1 ..... ...... ..... .....", "eon {rd}, {rn}, {rm}", "alu"),
        ("ands_sh", "F3", ". 11 01010 .. 0 ..... ...... ..... .....", "ands {rd}, {rn}, {rm}", "alu"),
        ("bics_sh", "F3", ". 11 01010 .. 1 ..... ...... ..... .....", "bics {rd}, {rn}, {rm}", "alu"),
        // 加減算シフト。bit21=0。
        ("add_sh", "F3", ". 00 01011 .. 0 ..... ...... ..... .....", "add {rd}, {rn}, {rm}", "alu"),
        ("adds_sh", "F3", ". 01 01011 .. 0 ..... ...... ..... .....", "adds {rd}, {rn}, {rm}", "alu"),
        ("sub_sh", "F3", ". 10 01011 .. 0 ..... ...... ..... .....", "sub {rd}, {rn}, {rm}", "alu"),
        ("subs_sh", "F3", ". 11 01011 .. 0 ..... ...... ..... .....", "subs {rd}, {rn}, {rm}", "alu"),
        // 加減算拡張。bit21=1、shift=00 固定。option で uxtw/sxtw 等を選ぶ。
        ("add_ext", "F3", ". 00 01011 00 1 ..... ... ... ..... .....", "add {rd}, {rn}, {rm}", "alu"),
        ("adds_ext", "F3", ". 01 01011 00 1 ..... ... ... ..... .....", "adds {rd}, {rn}, {rm}", "alu"),
        ("sub_ext", "F3", ". 10 01011 00 1 ..... ... ... ..... .....", "sub {rd}, {rn}, {rm}", "alu"),
        ("subs_ext", "F3", ". 11 01011 00 1 ..... ... ... ..... .....", "subs {rd}, {rn}, {rm}", "alu"),
        // 条件選択。op2[10] と op[30] で 4 命令。S=0。
        ("csel", "F3", ". 00 11010100 ..... .... 0 0 ..... .....", "csel {rd}, {rn}, {rm}, {cond}", "alu"),
        ("csinc", "F3", ". 00 11010100 ..... .... 0 1 ..... .....", "csinc {rd}, {rn}, {rm}, {cond}", "alu"),
        ("csinv", "F3", ". 10 11010100 ..... .... 0 0 ..... .....", "csinv {rd}, {rn}, {rm}, {cond}", "alu"),
        ("csneg", "F3", ". 10 11010100 ..... .... 0 1 ..... .....", "csneg {rd}, {rn}, {rm}, {cond}", "alu"),
        // 条件比較（レジスタ/即値）。op: ccmn/ccmp。
        ("ccmn_reg", "F3", ". 0 1 11010010 ..... .... 0 0 ..... . ....", "ccmn {rn}, {rm}, {nzcv}, {cond}", "alu"),
        ("ccmp_reg", "F3", ". 1 1 11010010 ..... .... 0 0 ..... . ....", "ccmp {rn}, {rm}, {nzcv}, {cond}", "alu"),
        ("ccmn_imm", "F3", ". 0 1 11010010 ..... .... 1 0 ..... . ....", "ccmn {rn}, {imm5}, {nzcv}, {cond}", "alu"),
        ("ccmp_imm", "F3", ". 1 1 11010010 ..... .... 1 0 ..... . ....", "ccmp {rn}, {imm5}, {nzcv}, {cond}", "alu"),
        // 2 オペランド。opcode[15:10] で命令を分ける。
        ("udiv", "F3", ". 00 11010110 ..... 000010 ..... .....", "udiv {rd}, {rn}, {rm}", "div"),
        ("sdiv", "F3", ". 00 11010110 ..... 000011 ..... .....", "sdiv {rd}, {rn}, {rm}", "div"),
        ("lslv", "F3", ". 00 11010110 ..... 001000 ..... .....", "lsl {rd}, {rn}, {rm}", "alu"),
        ("lsrv", "F3", ". 00 11010110 ..... 001001 ..... .....", "lsr {rd}, {rn}, {rm}", "alu"),
        ("asrv", "F3", ". 00 11010110 ..... 001010 ..... .....", "asr {rd}, {rn}, {rm}", "alu"),
        ("rorv", "F3", ". 00 11010110 ..... 001011 ..... .....", "ror {rd}, {rn}, {rm}", "alu"),
        // 1 オペランド。[30]=1、[20:16]=00000。
        ("rbit", "F2", ". 10 11010110 00000 000000 ..... .....", "rbit {rd}, {rn}", "alu"),
        ("rev16", "F2", ". 10 11010110 00000 000001 ..... .....", "rev16 {rd}, {rn}", "alu"),
        ("rev32", "F2", "1 1. 11010110 00000 000010 ..... .....", "rev32 {rd}, {rn}", "alu"),
        ("rev", "F2", "0 1. 11010110 00000 000010 ..... .....", "rev {rd}, {rn}", "alu"),
        ("rev64", "F2", "1 1. 11010110 00000 000011 ..... .....", "rev64 {rd}, {rn}", "alu"),
        ("clz", "F2", ". 10 11010110 00000 000100 ..... .....", "clz {rd}, {rn}", "alu"),
        ("cls", "F2", ". 10 11010110 00000 000101 ..... .....", "cls {rd}, {rn}", "alu"),
        // 3 オペランド。madd/msub。sf で W/X。
        ("madd", "F3", ". 00 11011 000 ..... 0 ..... ..... .....", "madd {rd}, {rn}, {rm}, {ra}", "mult"),
        ("msub", "F3", ". 00 11011 000 ..... 1 ..... ..... .....", "msub {rd}, {rn}, {rm}, {ra}", "mult"),
        // 64 ビットの積和。op54: smaddl/umaddl、smull 系。
        ("smaddl", "F3", "1 00 11011 001 ..... 0 ..... ..... .....", "smaddl {rd}, {rn}, {rm}, {ra}", "mult"),
        ("smsubl", "F3", "1 00 11011 001 ..... 1 ..... ..... .....", "smsubl {rd}, {rn}, {rm}, {ra}", "mult"),
        ("umaddl", "F3", "1 00 11011 101 ..... 0 ..... ..... .....", "umaddl {rd}, {rn}, {rm}, {ra}", "mult"),
        ("umsubl", "F3", "1 00 11011 101 ..... 1 ..... ..... .....", "umsubl {rd}, {rn}, {rm}, {ra}", "mult"),
        ("smulh", "F3", "1 00 11011 010 ..... 0 11111 ..... .....", "smulh {rd}, {rn}, {rm}", "mult"),
        ("umulh", "F3", "1 00 11011 110 ..... 0 11111 ..... .....", "umulh {rd}, {rn}, {rm}", "mult"),
        // ---- ロード・ストア ----
        // 符号なし即値。[29:24]=111001。size/opc_ls で 13 種。
        ("strb_u", "FL", "00 111001 00 ............ ..... .....", "strb {rt}, [{rn}, {imm}]", "store"),
        ("ldrb_u", "FL", "00 111001 01 ............ ..... .....", "ldrb {rt}, [{rn}, {imm}]", "load"),
        ("ldrsb_u_x", "FL", "00 111001 10 ............ ..... .....", "ldrsb {rt}, [{rn}, {imm}]", "load"),
        ("ldrsb_u_w", "FL", "00 111001 11 ............ ..... .....", "ldrsb {rt}, [{rn}, {imm}]", "load"),
        ("strh_u", "FL", "01 111001 00 ............ ..... .....", "strh {rt}, [{rn}, {imm}]", "store"),
        ("ldrh_u", "FL", "01 111001 01 ............ ..... .....", "ldrh {rt}, [{rn}, {imm}]", "load"),
        ("ldrsh_u_x", "FL", "01 111001 10 ............ ..... .....", "ldrsh {rt}, [{rn}, {imm}]", "load"),
        ("ldrsh_u_w", "FL", "01 111001 11 ............ ..... .....", "ldrsh {rt}, [{rn}, {imm}]", "load"),
        ("str_u_w", "FL", "10 111001 00 ............ ..... .....", "str {rt}, [{rn}, {imm}]", "store"),
        ("ldr_u_w", "FL", "10 111001 01 ............ ..... .....", "ldr {rt}, [{rn}, {imm}]", "load"),
        ("ldrsw_u", "FL", "10 111001 10 ............ ..... .....", "ldrsw {rt}, [{rn}, {imm}]", "load"),
        ("str_u_x", "FL", "11 111001 00 ............ ..... .....", "str {rt}, [{rn}, {imm}]", "store"),
        ("ldr_u_x", "FL", "11 111001 01 ............ ..... .....", "ldr {rt}, [{rn}, {imm}]", "load"),
        // imm9 系。[29:24]=111000、bit21=0。mode[11:10]: 00=unscaled, 01=post, 11=pre。
        // unscaled（ldur/stur 系）
        ("sturb", "FL", "00 111000 00 0 ......... 00 ..... .....", "sturb {rt}, [{rn}, {imm}]", "store"),
        ("ldurb", "FL", "00 111000 01 0 ......... 00 ..... .....", "ldurb {rt}, [{rn}, {imm}]", "load"),
        ("ldursb_x", "FL", "00 111000 10 0 ......... 00 ..... .....", "ldursb {rt}, [{rn}, {imm}]", "load"),
        ("ldursb_w", "FL", "00 111000 11 0 ......... 00 ..... .....", "ldursb {rt}, [{rn}, {imm}]", "load"),
        ("sturh", "FL", "01 111000 00 0 ......... 00 ..... .....", "sturh {rt}, [{rn}, {imm}]", "store"),
        ("ldurh", "FL", "01 111000 01 0 ......... 00 ..... .....", "ldurh {rt}, [{rn}, {imm}]", "load"),
        ("ldursh_x", "FL", "01 111000 10 0 ......... 00 ..... .....", "ldursh {rt}, [{rn}, {imm}]", "load"),
        ("ldursh_w", "FL", "01 111000 11 0 ......... 00 ..... .....", "ldursh {rt}, [{rn}, {imm}]", "load"),
        ("stur_w", "FL", "10 111000 00 0 ......... 00 ..... .....", "stur {rt}, [{rn}, {imm}]", "store"),
        ("ldur_w", "FL", "10 111000 01 0 ......... 00 ..... .....", "ldur {rt}, [{rn}, {imm}]", "load"),
        ("ldursw", "FL", "10 111000 10 0 ......... 00 ..... .....", "ldursw {rt}, [{rn}, {imm}]", "load"),
        ("stur_x", "FL", "11 111000 00 0 ......... 00 ..... .....", "stur {rt}, [{rn}, {imm}]", "store"),
        ("ldur_x", "FL", "11 111000 01 0 ......... 00 ..... .....", "ldur {rt}, [{rn}, {imm}]", "load"),
        // post-index
        ("strb_post", "FL", "00 111000 00 0 ......... 01 ..... .....", "strb {rt}, [{rn}], {imm}", "store"),
        ("ldrb_post", "FL", "00 111000 01 0 ......... 01 ..... .....", "ldrb {rt}, [{rn}], {imm}", "load"),
        ("ldrsb_post_x", "FL", "00 111000 10 0 ......... 01 ..... .....", "ldrsb {rt}, [{rn}], {imm}", "load"),
        ("ldrsb_post_w", "FL", "00 111000 11 0 ......... 01 ..... .....", "ldrsb {rt}, [{rn}], {imm}", "load"),
        ("strh_post", "FL", "01 111000 00 0 ......... 01 ..... .....", "strh {rt}, [{rn}], {imm}", "store"),
        ("ldrh_post", "FL", "01 111000 01 0 ......... 01 ..... .....", "ldrh {rt}, [{rn}], {imm}", "load"),
        ("ldrsh_post_x", "FL", "01 111000 10 0 ......... 01 ..... .....", "ldrsh {rt}, [{rn}], {imm}", "load"),
        ("ldrsh_post_w", "FL", "01 111000 11 0 ......... 01 ..... .....", "ldrsh {rt}, [{rn}], {imm}", "load"),
        ("str_post_w", "FL", "10 111000 00 0 ......... 01 ..... .....", "str {rt}, [{rn}], {imm}", "store"),
        ("ldr_post_w", "FL", "10 111000 01 0 ......... 01 ..... .....", "ldr {rt}, [{rn}], {imm}", "load"),
        ("ldrsw_post", "FL", "10 111000 10 0 ......... 01 ..... .....", "ldrsw {rt}, [{rn}], {imm}", "load"),
        ("str_post_x", "FL", "11 111000 00 0 ......... 01 ..... .....", "str {rt}, [{rn}], {imm}", "store"),
        ("ldr_post_x", "FL", "11 111000 01 0 ......... 01 ..... .....", "ldr {rt}, [{rn}], {imm}", "load"),
        // pre-index
        ("strb_pre", "FL", "00 111000 00 0 ......... 11 ..... .....", "strb {rt}, [{rn}, {imm}]!", "store"),
        ("ldrb_pre", "FL", "00 111000 01 0 ......... 11 ..... .....", "ldrb {rt}, [{rn}, {imm}]!", "load"),
        ("ldrsb_pre_x", "FL", "00 111000 10 0 ......... 11 ..... .....", "ldrsb {rt}, [{rn}, {imm}]!", "load"),
        ("ldrsb_pre_w", "FL", "00 111000 11 0 ......... 11 ..... .....", "ldrsb {rt}, [{rn}, {imm}]!", "load"),
        ("strh_pre", "FL", "01 111000 00 0 ......... 11 ..... .....", "strh {rt}, [{rn}, {imm}]!", "store"),
        ("ldrh_pre", "FL", "01 111000 01 0 ......... 11 ..... .....", "ldrh {rt}, [{rn}, {imm}]!", "load"),
        ("ldrsh_pre_x", "FL", "01 111000 10 0 ......... 11 ..... .....", "ldrsh {rt}, [{rn}, {imm}]!", "load"),
        ("ldrsh_pre_w", "FL", "01 111000 11 0 ......... 11 ..... .....", "ldrsh {rt}, [{rn}, {imm}]!", "load"),
        ("str_pre_w", "FL", "10 111000 00 0 ......... 11 ..... .....", "str {rt}, [{rn}, {imm}]!", "store"),
        ("ldr_pre_w", "FL", "10 111000 01 0 ......... 11 ..... .....", "ldr {rt}, [{rn}, {imm}]!", "load"),
        ("ldrsw_pre", "FL", "10 111000 10 0 ......... 11 ..... .....", "ldrsw {rt}, [{rn}, {imm}]!", "load"),
        ("str_pre_x", "FL", "11 111000 00 0 ......... 11 ..... .....", "str {rt}, [{rn}, {imm}]!", "store"),
        ("ldr_pre_x", "FL", "11 111000 01 0 ......... 11 ..... .....", "ldr {rt}, [{rn}, {imm}]!", "load"),
        // レジスタオフセット。bit21=1、[11:10]=10。option/S で拡張を選ぶ。
        ("strb_reg", "FL", "00 111000 00 1 ..... ... . 10 ..... .....", "strb {rt}, [{rn}, {rm}]", "store"),
        ("ldrb_reg", "FL", "00 111000 01 1 ..... ... . 10 ..... .....", "ldrb {rt}, [{rn}, {rm}]", "load"),
        ("ldrsb_reg_x", "FL", "00 111000 10 1 ..... ... . 10 ..... .....", "ldrsb {rt}, [{rn}, {rm}]", "load"),
        ("ldrsb_reg_w", "FL", "00 111000 11 1 ..... ... . 10 ..... .....", "ldrsb {rt}, [{rn}, {rm}]", "load"),
        ("strh_reg", "FL", "01 111000 00 1 ..... ... . 10 ..... .....", "strh {rt}, [{rn}, {rm}]", "store"),
        ("ldrh_reg", "FL", "01 111000 01 1 ..... ... . 10 ..... .....", "ldrh {rt}, [{rn}, {rm}]", "load"),
        ("ldrsh_reg_x", "FL", "01 111000 10 1 ..... ... . 10 ..... .....", "ldrsh {rt}, [{rn}, {rm}]", "load"),
        ("ldrsh_reg_w", "FL", "01 111000 11 1 ..... ... . 10 ..... .....", "ldrsh {rt}, [{rn}, {rm}]", "load"),
        ("str_reg_w", "FL", "10 111000 00 1 ..... ... . 10 ..... .....", "str {rt}, [{rn}, {rm}]", "store"),
        ("ldr_reg_w", "FL", "10 111000 01 1 ..... ... . 10 ..... .....", "ldr {rt}, [{rn}, {rm}]", "load"),
        ("ldrsw_reg", "FL", "10 111000 10 1 ..... ... . 10 ..... .....", "ldrsw {rt}, [{rn}, {rm}]", "load"),
        ("str_reg_x", "FL", "11 111000 00 1 ..... ... . 10 ..... .....", "str {rt}, [{rn}, {rm}]", "store"),
        ("ldr_reg_x", "FL", "11 111000 01 1 ..... ... . 10 ..... .....", "ldr {rt}, [{rn}, {rm}]", "load"),
        // リテラルロード。[29:24]=011000。opc: w/x/sw/prfm。
        ("ldr_w_lit", "FL", "00 011 000 ................... .....", "ldr {rt}, {imm}", "load"),
        ("ldr_x_lit", "FL", "01 011 000 ................... .....", "ldr {rt}, {imm}", "load"),
        ("ldrsw_lit", "FL", "10 011 000 ................... .....", "ldrsw {rt}, {imm}", "load"),
        ("prfm_lit", "FL", "11 011 000 ................... .....", "prfm {rt}, {imm}", "load"),
        // ペアロード・ストア。opc 00=W、10=X。[24:23]: 01=post,10=off,11=pre。
        ("stp_w_off", "FL", "00 101 0 0 10 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]", "store"),
        ("ldp_w_off", "FL", "00 101 0 0 10 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]", "load"),
        ("stp_x_off", "FL", "10 101 0 0 10 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]", "store"),
        ("ldp_x_off", "FL", "10 101 0 0 10 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]", "load"),
        ("stp_w_post", "FL", "00 101 0 0 01 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}], {imm}", "store"),
        ("ldp_w_post", "FL", "00 101 0 0 01 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}], {imm}", "load"),
        ("stp_x_post", "FL", "10 101 0 0 01 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}], {imm}", "store"),
        ("ldp_x_post", "FL", "10 101 0 0 01 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}], {imm}", "load"),
        ("stp_w_pre", "FL", "00 101 0 0 11 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]!", "store"),
        ("ldp_w_pre", "FL", "00 101 0 0 11 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]!", "load"),
        ("stp_x_pre", "FL", "10 101 0 0 11 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]!", "store"),
        ("ldp_x_pre", "FL", "10 101 0 0 11 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]!", "load"),
        // FP/SIMD ペア。bit26=1。opc: 00=S(4B), 01=D(8B), 10=Q(16B)。imm7<<scale。
        ("stp_s_off", "FL", "00 101 1 010 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]", "store"),
        ("ldp_s_off", "FL", "00 101 1 010 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]", "load"),
        ("stp_d_off", "FL", "01 101 1 010 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]", "store"),
        ("ldp_d_off", "FL", "01 101 1 010 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]", "load"),
        ("stp_q_off", "FL", "10 101 1 010 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]", "store"),
        ("ldp_q_off", "FL", "10 101 1 010 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]", "load"),
        ("stp_s_post", "FL", "00 101 1 001 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}], {imm}", "store"),
        ("ldp_s_post", "FL", "00 101 1 001 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}], {imm}", "load"),
        ("stp_d_post", "FL", "01 101 1 001 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}], {imm}", "store"),
        ("ldp_d_post", "FL", "01 101 1 001 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}], {imm}", "load"),
        ("stp_q_post", "FL", "10 101 1 001 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}], {imm}", "store"),
        ("ldp_q_post", "FL", "10 101 1 001 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}], {imm}", "load"),
        ("stp_s_pre", "FL", "00 101 1 011 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]!", "store"),
        ("ldp_s_pre", "FL", "00 101 1 011 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]!", "load"),
        ("stp_d_pre", "FL", "01 101 1 011 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]!", "store"),
        ("ldp_d_pre", "FL", "01 101 1 011 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]!", "load"),
        ("stp_q_pre", "FL", "10 101 1 011 0 ....... ..... ..... .....", "stp {rt}, {rt2}, [{rn}, {imm}]!", "store"),
        ("ldp_q_pre", "FL", "10 101 1 011 1 ....... ..... ..... .....", "ldp {rt}, {rt2}, [{rn}, {imm}]!", "load"),
        // FP/SIMD 符号なし即値。[29:24]=111101。size:opc で要素幅（q は opc[1]=1）。
        ("str_b_vu", "FL", "00 1111 01 00 ............ ..... .....", "str {rt}, [{rn}, {imm}]", "store"),
        ("ldr_b_vu", "FL", "00 1111 01 01 ............ ..... .....", "ldr {rt}, [{rn}, {imm}]", "load"),
        ("str_h_vu", "FL", "01 1111 01 00 ............ ..... .....", "str {rt}, [{rn}, {imm}]", "store"),
        ("ldr_h_vu", "FL", "01 1111 01 01 ............ ..... .....", "ldr {rt}, [{rn}, {imm}]", "load"),
        ("str_s_vu", "FL", "10 1111 01 00 ............ ..... .....", "str {rt}, [{rn}, {imm}]", "store"),
        ("ldr_s_vu", "FL", "10 1111 01 01 ............ ..... .....", "ldr {rt}, [{rn}, {imm}]", "load"),
        ("str_d_vu", "FL", "11 1111 01 00 ............ ..... .....", "str {rt}, [{rn}, {imm}]", "store"),
        ("ldr_d_vu", "FL", "11 1111 01 01 ............ ..... .....", "ldr {rt}, [{rn}, {imm}]", "load"),
        ("str_q_vu", "FL", "00 1111 01 10 ............ ..... .....", "str {rt}, [{rn}, {imm}]", "store"),
        ("ldr_q_vu", "FL", "00 1111 01 11 ............ ..... .....", "ldr {rt}, [{rn}, {imm}]", "load"),
        // FP/SIMD imm9。unscaled(00)/post(01)/pre(11)。
        ("stur_b", "FL", "00 111100 00 0 ......... 00 ..... .....", "stur {rt}, [{rn}, {imm}]", "store"),
        ("ldur_b", "FL", "00 111100 01 0 ......... 00 ..... .....", "ldur {rt}, [{rn}, {imm}]", "load"),
        ("stur_h", "FL", "01 111100 00 0 ......... 00 ..... .....", "stur {rt}, [{rn}, {imm}]", "store"),
        ("ldur_h", "FL", "01 111100 01 0 ......... 00 ..... .....", "ldur {rt}, [{rn}, {imm}]", "load"),
        ("stur_s", "FL", "10 111100 00 0 ......... 00 ..... .....", "stur {rt}, [{rn}, {imm}]", "store"),
        ("ldur_s", "FL", "10 111100 01 0 ......... 00 ..... .....", "ldur {rt}, [{rn}, {imm}]", "load"),
        ("stur_d", "FL", "11 111100 00 0 ......... 00 ..... .....", "stur {rt}, [{rn}, {imm}]", "store"),
        ("ldur_d", "FL", "11 111100 01 0 ......... 00 ..... .....", "ldur {rt}, [{rn}, {imm}]", "load"),
        ("stur_q", "FL", "00 111100 10 0 ......... 00 ..... .....", "stur {rt}, [{rn}, {imm}]", "store"),
        ("ldur_q", "FL", "00 111100 11 0 ......... 00 ..... .....", "ldur {rt}, [{rn}, {imm}]", "load"),
        ("str_b_post_v", "FL", "00 111100 00 0 ......... 01 ..... .....", "str {rt}, [{rn}], {imm}", "store"),
        ("ldr_b_post_v", "FL", "00 111100 01 0 ......... 01 ..... .....", "ldr {rt}, [{rn}], {imm}", "load"),
        ("str_h_post_v", "FL", "01 111100 00 0 ......... 01 ..... .....", "str {rt}, [{rn}], {imm}", "store"),
        ("ldr_h_post_v", "FL", "01 111100 01 0 ......... 01 ..... .....", "ldr {rt}, [{rn}], {imm}", "load"),
        ("str_s_post_v", "FL", "10 111100 00 0 ......... 01 ..... .....", "str {rt}, [{rn}], {imm}", "store"),
        ("ldr_s_post_v", "FL", "10 111100 01 0 ......... 01 ..... .....", "ldr {rt}, [{rn}], {imm}", "load"),
        ("str_d_post_v", "FL", "11 111100 00 0 ......... 01 ..... .....", "str {rt}, [{rn}], {imm}", "store"),
        ("ldr_d_post_v", "FL", "11 111100 01 0 ......... 01 ..... .....", "ldr {rt}, [{rn}], {imm}", "load"),
        ("str_q_post_v", "FL", "00 111100 10 0 ......... 01 ..... .....", "str {rt}, [{rn}], {imm}", "store"),
        ("ldr_q_post_v", "FL", "00 111100 11 0 ......... 01 ..... .....", "ldr {rt}, [{rn}], {imm}", "load"),
        ("str_b_pre_v", "FL", "00 111100 00 0 ......... 11 ..... .....", "str {rt}, [{rn}, {imm}]!", "store"),
        ("ldr_b_pre_v", "FL", "00 111100 01 0 ......... 11 ..... .....", "ldr {rt}, [{rn}, {imm}]!", "load"),
        ("str_h_pre_v", "FL", "01 111100 00 0 ......... 11 ..... .....", "str {rt}, [{rn}, {imm}]!", "store"),
        ("ldr_h_pre_v", "FL", "01 111100 01 0 ......... 11 ..... .....", "ldr {rt}, [{rn}, {imm}]!", "load"),
        ("str_s_pre_v", "FL", "10 111100 00 0 ......... 11 ..... .....", "str {rt}, [{rn}, {imm}]!", "store"),
        ("ldr_s_pre_v", "FL", "10 111100 01 0 ......... 11 ..... .....", "ldr {rt}, [{rn}, {imm}]!", "load"),
        ("str_d_pre_v", "FL", "11 111100 00 0 ......... 11 ..... .....", "str {rt}, [{rn}, {imm}]!", "store"),
        ("ldr_d_pre_v", "FL", "11 111100 01 0 ......... 11 ..... .....", "ldr {rt}, [{rn}, {imm}]!", "load"),
        ("str_q_pre_v", "FL", "00 111100 10 0 ......... 11 ..... .....", "str {rt}, [{rn}, {imm}]!", "store"),
        ("ldr_q_pre_v", "FL", "00 111100 11 0 ......... 11 ..... .....", "ldr {rt}, [{rn}, {imm}]!", "load"),
        // AdvSIMD コピー。imm5 の最下位立ちビットが要素幅、上位がレーン番号。
        // dup Vd.T, Rn / ins Vd.T[i], Rn / umov Wd/Xd, Vn.T[i]。
        ("dup_gen", "FN", "0 . 001110 000 ..... 0000 11 ..... .....", "dup {rd}, {rn}", "alu"),
        ("ins_gen", "FN", "0 . 001110 000 ..... 0001 11 ..... .....", "ins {rd}, {rn}", "alu"),
        ("umov", "FN", "0 . 001110 000 ..... 0011 11 ..... .....", "umov {rd}, {rn}", "alu"),
        ("mod_imm", "FN", "0 . . 01111 00000 ... .... 01 ..... .....", "movi/mvni/orr/bic {rd}", "alu"),
        // FMOV（汎用↔FP/SIMD レジスタの素通し転送）。bit30=0 が整数側との切り分け。
        ("fmov_w_s", "FL", "00011110 00100110 000000 ..... .....", "fmov {rd}, {rn}", "alu"),
        ("fmov_s_w", "FL", "00011110 00100111 000000 ..... .....", "fmov {rd}, {rn}", "alu"),
        ("fmov_x_d", "FL", "10011110 01100110 000000 ..... .....", "fmov {rd}, {rn}", "alu"),
        ("fmov_d_x", "FL", "10011110 01100111 000000 ..... .....", "fmov {rd}, {rn}", "alu"),
        ("fmov_x_dhi", "FL", "10011110 10101110 000000 ..... .....", "fmov {rd}, {rn}", "alu"),
        ("fmov_dhi_x", "FL", "10011110 10101111 000000 ..... .....", "fmov {rd}, {rn}", "alu"),
        // スカラー FP 3 項。ptype[23:22]=0x が S/D、opc[15:12] が演算。
        // 0=fmul 1=fdiv 2=fadd 3=fsub 4=fmax 5=fmin 6=fmaxnm 7=fminnm 8=fnmul。
        ("fp3", "FN", "00011110 0. 1 ..... .... 10 ..... .....", "fp3 {rd}, {rn}, {rm}", "alu"),
        // スカラー FP 1 項。opc[20:15] が演算（0=fmov 1=fabs 2=fneg 3=fsqrt
        // 4=fcvt d→s 5=fcvt s→d 8..15=frintn/p/m/z/a/-/x/i）。
        ("fp1", "FN", "00011110 0. 1 ...... 10000 ..... .....", "fp1 {rd}, {rn}", "alu"),
        // FMA。bit21=積の否定（fn*）、bit15=加算項の否定（*msub）。
        ("fma", "FN", "00011111 0. . ..... . ..... ..... .....", "fma {rd}, {rn}, {rm}, {ra}", "alu"),
        // 整数↔FP 変換。opc[18:16]=010/011 が int→fp（scvtf/ucvtf）、
        // 0/1（rmode[20:19] 付き）が fp→int（fcvt{n,p,m,a,z}{s,u}）。
        // sf=整数幅、ptype=FP 側。opc=110/111 は未割当なので bit18=0 に限定。
        ("fcvt", "FN", ". 00 11110 0. 1 ..0.. 000000 ..... .....", "fcvt {rd}, {rn}", "alu"),
        // FCVTA* は rmode=00 + opc=10x の別スロット。
        ("fcvt_a", "FN", ". 00 11110 0. 1 0010. 000000 ..... .....", "fcvta {rd}, {rn}", "alu"),
        // FP 比較。op2[4]=fcmpe（NV 時の例外。ここでは同じ扱い）、op2[3]=#0.0。
        ("fcmp", "FN", "00011110 0. 1 ..... 001000 ..... .....", "fcmp {rn}, {rm}", "alu"),
        // FP 条件付き比較。op[4]=fccmpe。不成立時は nzcv[3:0] を書く。
        ("fccmp", "FN", "00011110 0. 1 ..... .... 01 ..... .....", "fccmp {rn}, {rm}", "alu"),
        // FP 条件選択。cond[15:12]。
        ("fcsel", "FN", "00011110 0. 1 ..... .... 11 ..... .....", "fcsel {rd}, {rn}, {rm}", "alu"),
        // FP 即値（FP8 展開）。imm8[20:13]。
        ("fmov_imm", "FN", "00011110 0. 1 ........ 100 00000 .....", "fmov {rd}, #imm", "alu"),
        // 排他ロード・ストア。[29:23]=0010000、bit22=L、bit15=o0（aq）。Rt2=11111。
        ("stxr_w", "FL", "10 001000 00 0 ..... 0 11111 ..... .....", "stxr {rs}, {rt}, [{rn}]", "store"),
        ("ldxr_w", "FL", "10 001000 01 0 11111 0 11111 ..... .....", "ldxr {rt}, [{rn}]", "load"),
        ("stlxr_w", "FL", "10 001000 00 0 ..... 1 11111 ..... .....", "stlxr {rs}, {rt}, [{rn}]", "store"),
        ("ldaxr_w", "FL", "10 001000 01 0 11111 1 11111 ..... .....", "ldaxr {rt}, [{rn}]", "load"),
        ("stxr_x", "FL", "11 001000 00 0 ..... 0 11111 ..... .....", "stxr {rs}, {rt}, [{rn}]", "store"),
        ("ldxr_x", "FL", "11 001000 01 0 11111 0 11111 ..... .....", "ldxr {rt}, [{rn}]", "load"),
        ("stlxr_x", "FL", "11 001000 00 0 ..... 1 11111 ..... .....", "stlxr {rs}, {rt}, [{rn}]", "store"),
        ("ldaxr_x", "FL", "11 001000 01 0 11111 1 11111 ..... .....", "ldaxr {rt}, [{rn}]", "load"),
        ("stxrb", "FL", "00 001000 00 0 ..... 0 11111 ..... .....", "stxrb {rs}, {rt}, [{rn}]", "store"),
        ("ldxrb", "FL", "00 001000 01 0 11111 0 11111 ..... .....", "ldxrb {rt}, [{rn}]", "load"),
        ("stlxrb", "FL", "00 001000 00 0 ..... 1 11111 ..... .....", "stlxrb {rs}, {rt}, [{rn}]", "store"),
        ("ldaxrb", "FL", "00 001000 01 0 11111 1 11111 ..... .....", "ldaxrb {rt}, [{rn}]", "load"),
        ("stxrh", "FL", "01 001000 00 0 ..... 0 11111 ..... .....", "stxrh {rs}, {rt}, [{rn}]", "store"),
        ("ldxrh", "FL", "01 001000 01 0 11111 0 11111 ..... .....", "ldxrh {rt}, [{rn}]", "load"),
        ("stlxrh", "FL", "01 001000 00 0 ..... 1 11111 ..... .....", "stlxrh {rs}, {rt}, [{rn}]", "store"),
        ("ldaxrh", "FL", "01 001000 01 0 11111 1 11111 ..... .....", "ldaxrh {rt}, [{rn}]", "load"),
    ];

    for (name, format, pattern, syntax, timing) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres: vec![],
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }

    // N==sf の必須条件。SBFM/BFM/UBFM/EXTR は sf=0 のとき N=0、
    // sf=1 のとき N=1 でなければならない（フィールド間比較の where）。
    // Ref: SPEC-ARM-ARM-A (Armv9-A ARM ARM 2024-09).
    for name in ["sbfm", "bfm", "ubfm", "extr"] {
        let insn = m.insns.iter_mut().find(|i| i.name == name).expect(name);
        insn.wheres.push(WhereClause {
            field: "nbit".to_string(),
            op: WhereOp::Eq,
            rhs: WhereRhs::Field("sf".to_string()),
        });
    }
    m
}
