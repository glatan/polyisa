// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// SuperH の ISADL モデル（段階18）。
//
// SuperH の命令語は基本 16 ビットで、SH-2A が追加した 32 ビット命令は
// 2 つの 16 ビットパーセルから構成される。フェッチは常に 16 ビット単位で、
// 32 ビット命令の先頭パーセルは 16 ビット命令としては未定義の符号化
// （0011nnnnmmmm0001 系、0011nnnn0iii1001、0000nnnnxxxx000x 等）から
// 選ばれているため、16 ビット解読が失敗した語を 32 ビット命令の先頭と
// 見なして次のパーセルを読む規則で判別する。
// Ref: SPEC-SUPERH-SH2A §5（32 ビット命令の識別）.
//
// レジスタ番号の記法は Renesas 記法（MSB 側が語の上位）で、
// ここでは LSB=0 の桁番号に揃える。語の [11:8] が `n`、[7:4] が
// `m` の通常配置。
//
// パターンの固定ビットは SPEC-SUPERH-SH2 付録の命令表、
// SPEC-SUPERH-SH3 §7.12、SPEC-SUPERH-SH4 §10、SPEC-SUPERH-SH2A §5、
// SPEC-SUPERH-SH4A 命令一覧、SPEC-SUPERH-JCORE の命令表を正本とする。
// Ref: SPEC-SUPERH-SH2, SPEC-SUPERH-SH3, SPEC-SUPERH-SH4,
// SPEC-SUPERH-SH2A, SPEC-SUPERH-SH4A, SPEC-SUPERH-JCORE.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// SuperH の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in [
        "alu", "load", "store", "branch", "system", "fp", "misc",
    ] {
        m.timing_classes.push(class.to_string());
    }

    // ISA の世代。上位世代は下位の機能を implies で持つ（SH-4 は
    // SH-3 を含み、SH-4A は SH-4 を含む）。`fpu` は単精度 FPU
    // （SH-2E/SH-3E/SH-4/SH2A-FPU）、`fpud` は倍精度（SH-4 系・
    // SH2A-FPU）。`jcore` は J-core/J2 の追加命令（SH-2 系に乗る）。
    // Ref: SPEC-SUPERH-SH2 Table 3, SPEC-SUPERH-SH4A.
    for (name, implies) in [
        ("sh1", &[][..]),
        ("sh2", &["sh1"][..]),
        ("sh2a", &["sh2"][..]),
        ("sh3", &["sh2"][..]),
        ("sh4", &["sh3", "fpu", "fpud"][..]),
        ("sh4a", &["sh4"][..]),
        ("jcore", &["sh2"][..]),
        ("fpu", &[][..]),
        ("fpud", &["fpu"][..]),
    ] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: vec![],
        });
    }

    // CPU モデル。SH-1 から SH-4A と J-core/J2。SH2A-FPU は SH-2A に
    // 単精度・倍精度 FPU を足した型（R01US0031 の "SH2A-FPU"）。
    // Ref: SPEC-SUPERH-SH2, SPEC-SUPERH-SH3, SPEC-SUPERH-SH4,
    // SPEC-SUPERH-SH2A, SPEC-SUPERH-SH4A, SPEC-SUPERH-JCORE.
    for (name, parent, add, rem) in [
        ("sh1", "", &["sh1"][..], &[][..]),
        ("sh2", "sh1", &["sh2"][..], &[][..]),
        ("sh2e", "sh2", &["fpu"][..], &[][..]),
        ("sh2a", "sh2", &["sh2a"][..], &[][..]),
        ("sh2af", "sh2a", &["fpu", "fpud"][..], &[][..]),
        ("sh3", "sh2", &["sh3"][..], &[][..]),
        ("sh3e", "sh3", &["fpu"][..], &[][..]),
        ("sh4", "sh3", &["sh4"][..], &[][..]),
        ("sh4a", "sh4", &["sh4a"][..], &[][..]),
        ("jcore", "sh2", &["jcore"][..], &[][..]),
        ("j2", "jcore", &[][..], &[][..]),
    ] as [(&str, &str, &[&str], &[&str]); 11] {
        m.models.push(ModelDef {
        timing: None,
        params: Default::default(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: rem.iter().map(|s| s.to_string()).collect(),
            ident: vec![],
        });
    }

    // 整数レジスタ R0-R15 と FP レジスタ FR0-15。
    m.regclasses.push(RegClass {
        name: "gr".to_string(),
        dynamic: false,
        prefix: Some("r".to_string()),
    });
    m.regclasses.push(RegClass {
        name: "fpr".to_string(),
        dynamic: false,
        prefix: Some("fr".to_string()),
    });

    // 16 ビット命令語内の桁。
    //   n(11-8) m(7-4) i(7-0) d(11-0) d4(3-0)
    //   n3(11-9)/m3(7-5)       … DR/XD レジスタの 3 ビット番号
    //   fn(11-10)/fm(9-8)      … FVn/FVm の 2 ビット番号
    //   b(6-4)                  … R_BANK のバンク番号
    //   i3(2-0)                 … ビット命令の imm3（レジスタ形式）
    // 32 ビット命令語内の桁（上位 16 ビット = 先頭パーセル）:
    //   nw(27-24) mw(23-20) i3w(22-20) i4w(23-20)
    //   iw(15-0)               … MOVI20 の下位 16 ビット
    //   d(11-0)                … 32 ビット命令の disp12（下位語全体でも
    //                            同じ位置なので 16 ビットと共有できる）
    // Ref: SPEC-SUPERH-SH4 §10, SPEC-SUPERH-SH2A §5.
    for (name, hi, lo) in [
        ("n", 11, 8),
        ("m", 7, 4),
        ("i", 7, 0),
        ("d", 11, 0),
        ("d8", 7, 0),
        ("d4", 3, 0),
        ("n3", 11, 9),
        ("m3", 7, 5),
        ("fvn", 11, 10),
        ("fvm", 9, 8),
        ("b", 6, 4),
        ("i3", 2, 0),
        ("nw", 27, 24),
        ("mw", 23, 20),
        ("i3w", 22, 20),
        ("i4w", 23, 20),
        ("iw", 15, 0),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    let gr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("gr".to_string()),
        access,
    };
    let fpr = |name: &str, field: &str, access: Access| Operand {
        name: name.to_string(),
        field: Some(field.to_string()),
        regclass: Some("fpr".to_string()),
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
    
    // オペランドなし（全桁固定の命令）。
    m.formats.push(fmt("FNONE", &[], vec![]));
    // n だけの命令（cmp/pl・tas.b・各種シフトなど）。
    m.formats.push(fmt("FN", &["n"], vec![gr("n", "n", Access::ReadWrite)]));
    // m だけの命令（jmp/jsr/ldc 系、ソースのみ）。命令語上レジスタは
    // [11:8] 桁（`n` 桁）にある（FMB と同じ作法で `{m}`→`n` に束ねる）。
    m.formats.push(fmt("FM", &["n"], vec![gr("m", "n", Access::Read)]));
    // n と m のペア（3 オペランド命令の基本形）。
    m.formats.push(fmt("FNM", &["n", "m"], vec![gr("n", "n", Access::ReadWrite), gr("m", "m", Access::Read)]));
    // n + 8 ビット即値/変位。
    m.formats.push(fmt("FNI", &["n", "i"], vec![gr("n", "n", Access::ReadWrite), val("i", "i")]));
    // n + 4 ビット変位（`mov.{b,w} r0, @({d4},{n})` の Rn は [7:4] 桁）。
    m.formats.push(fmt("FND4", &["m", "d4"], vec![gr("n", "m", Access::Read), val("d4", "d4")]));
    // m + 4 ビット変位。
    m.formats.push(fmt("FMD4", &["m", "d4"], vec![gr("m", "m", Access::Read), val("d4", "d4")]));
    // n + m + 4 ビット変位。
    m.formats.push(fmt(
        "FNM4",
        &["n", "m", "d4"],
        vec![gr("n", "n", Access::ReadWrite), gr("m", "m", Access::Read), val("d4", "d4")],
    ));
    // 8 ビット即値のみ（trapa・論理即値・gbr 変位）。
    m.formats.push(fmt("FI", &["i"], vec![val("i", "i")]));
    // 12 ビット変位のみ（bra/bsr）。
    m.formats.push(fmt("FD", &["d"], vec![val("d", "d")]));
    // 8 ビット変位のみ（bf/bt/bf.s/bt.s/jsr.n @@(disp8,TBR)）。
    m.formats.push(fmt("FD8", &["d8"], vec![val("d", "d8")]));
    // n + バンク番号（STC R_BANK,Rn）。
    m.formats.push(fmt("FNB", &["n", "b"], vec![gr("n", "n", Access::Write), gr("b", "b", Access::Read)]));
    // m + バンク番号（LDC Rm,R_BANK）。命令語上レジスタは
    // [11:8] 桁（`n` 桁）にあり、バンク番号が [6:4]。
    m.formats.push(fmt("FMB", &["n", "b"], vec![gr("m", "n", Access::Read), gr("b", "b", Access::Write)]));
    // n + i3（レジスタ形式のビット命令。Rn は [7:4] 桁）。
    m.formats.push(fmt("FNI3", &["m", "i3"], vec![gr("n", "m", Access::ReadWrite), val("i3", "i3")]));
    // FRn 単独（FABS/FNEG/FSQRT/FLDI/FLDS/FSTS/FLOAT/FSRRA 等）。
    m.formats.push(fmt("FFN", &["n"], vec![fpr("n", "n", Access::ReadWrite)]));
    // FRm 単独（FTRC/FLDS のソース側）。レジスタは [11:8] 桁。
    m.formats.push(fmt("FFM", &["n"], vec![fpr("m", "n", Access::Read)]));
    // FRn・FRm のペア（FADD/FSUB/FMUL/FDIV/FCMP/FMOV/FMAC）。
    m.formats.push(fmt(
        "FFF",
        &["n", "m"],
        vec![fpr("n", "n", Access::ReadWrite), fpr("m", "m", Access::Read)],
    ));
    // FVn・FVm のペア（FIPR）。
    m.formats.push(fmt(
        "FFV",
        &["fvn", "fvm"],
        vec![fpr("fvn", "fvn", Access::ReadWrite), fpr("fvm", "fvm", Access::Read)],
    ));
    // FVn 単独（FTRV は XMTRX 固定）。
    m.formats.push(fmt("FFV1", &["fvn"], vec![fpr("fvn", "fvn", Access::ReadWrite)]));
    // DRn 単独・書込（FSCA/FCNVSD は FPUL から DRn へ）。
    m.formats.push(fmt("FN3", &["n3"], vec![fpr("drn", "n3", Access::Write)]));
    // DRn 単独・読出（FCNVDS は DRn から FPUL へ）。
    m.formats.push(fmt("FN3R", &["n3"], vec![fpr("drn", "n3", Access::Read)]));
    // FMOV.S メモリ形式: ロードは n=FR・m=R アドレス。
    m.formats.push(fmt(
        "FFLD",
        &["n", "m"],
        vec![fpr("n", "n", Access::ReadWrite), gr("m", "m", Access::Read)],
    ));
    // FMOV.S メモリ形式: ストアは n=R アドレス・m=FR。
    m.formats.push(fmt(
        "FFST",
        &["n", "m"],
        vec![gr("n", "n", Access::ReadWrite), fpr("m", "m", Access::Read)],
    ));
    // 32 ビット命令の nw・mw・d12 三つ組（MOV disp12 系・FMOV.S disp12 系）。
    m.formats.push(fmt(
        "FW3",
        &["nw", "mw", "d"],
        vec![gr("n", "nw", Access::ReadWrite), gr("m", "mw", Access::Read), val("d", "d")],
    ));
    // 32 ビット FMOV.S disp12 ロード（n=FR・m=R アドレス）。
    m.formats.push(fmt(
        "FW3FLD",
        &["nw", "mw", "d"],
        vec![fpr("n", "nw", Access::ReadWrite), gr("m", "mw", Access::Read), val("d", "d")],
    ));
    // 32 ビット FMOV.S disp12 ストア（n=R アドレス・m=FR）。
    m.formats.push(fmt(
        "FW3FST",
        &["nw", "mw", "d"],
        vec![gr("n", "nw", Access::ReadWrite), fpr("m", "mw", Access::Read), val("d", "d")],
    ));
    // 32 ビット ビット命令（メモリ形式）。
    m.formats.push(fmt(
        "FWB",
        &["nw", "i3w", "d"],
        vec![gr("n", "nw", Access::ReadWrite), val("i3", "i3w"), val("d", "d")],
    ));
    // MOVI20/MOVI20S（i4 + imm16）。
    m.formats.push(fmt(
        "FWI",
        &["nw", "i4w", "iw"],
        vec![gr("n", "nw", Access::Write), val("i4", "i4w"), val("i16", "iw")],
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
    let f_sh2 = || Pred::Flag("sh2".to_string());
    let f_sh3 = || Pred::Flag("sh3".to_string());
    let f_sh4 = || Pred::Flag("sh4".to_string());
    let f_sh4a = || Pred::Flag("sh4a".to_string());
    let f_sh2a = || Pred::Flag("sh2a".to_string());
    let f_fpu = || Pred::Flag("fpu".to_string());
    let f_fpud = || Pred::Flag("fpud".to_string());
    let f_jcore = || Pred::Flag("jcore".to_string());
    // SHAD/SHLD は SH-3・SH-2A・J-core が持つ。
    // Ref: SPEC-SUPERH-SH3 §7.12, SPEC-SUPERH-SH2A, SPEC-SUPERH-JCORE.
    let f_dyn_shift = || {
        Pred::Any(vec![f_sh3(), f_sh2a(), f_jcore()])
    };
    // PREF は SH-4 と SH-2A が持つ。
    // Ref: SPEC-SUPERH-SH4 §10, SPEC-SUPERH-SH2A §5.
    let f_pref = || Pred::Any(vec![f_sh4(), f_sh2a()]);
    // MOVUA.L は SH-4A と SH-2A が持つ。
    // Ref: SPEC-SUPERH-SH4A, SPEC-SUPERH-SH2A.
    let f_movua = || Pred::Any(vec![f_sh4a(), f_sh2a()]);
    // SGR は SH-3E・SH-4 系が持つ。
    // Ref: SPEC-SUPERH-SH3（SH-3E のレジスタ構成）, SPEC-SUPERH-SH4 §2.
    let f_sgr = || Pred::All(vec![f_sh3(), f_fpu()]);

    // ---- SH-1 基本語彙（全モデル）。Ref: SPEC-SUPERH-SH2 §3/§6. ----
    for (name, format, pattern, syntax, timing) in [
        // MOV 系。
        ("mov_imm", "FNI", "1110............", "mov #{i}, {n}", "alu"),
        ("mov_w_pcl", "FNI", "1001............", "mov.w @({i},pc), {n}", "load"),
        ("mov_l_pcl", "FNI", "1101............", "mov.l @({i},pc), {n}", "load"),
        ("mov_b_ld", "FNM", "0110........0000", "mov.b @{m}, {n}", "load"),
        ("mov_w_ld", "FNM", "0110........0001", "mov.w @{m}, {n}", "load"),
        ("mov_l_ld", "FNM", "0110........0010", "mov.l @{m}, {n}", "load"),
        ("mov_reg", "FNM", "0110........0011", "mov {m}, {n}", "alu"),
        ("mov_b_ldp", "FNM", "0110........0100", "mov.b @{m}+, {n}", "load"),
        ("mov_w_ldp", "FNM", "0110........0101", "mov.w @{m}+, {n}", "load"),
        ("mov_l_ldp", "FNM", "0110........0110", "mov.l @{m}+, {n}", "load"),
        ("mov_b_st", "FNM", "0010........0000", "mov.b {m}, @{n}", "store"),
        ("mov_w_st", "FNM", "0010........0001", "mov.w {m}, @{n}", "store"),
        ("mov_l_st", "FNM", "0010........0010", "mov.l {m}, @{n}", "store"),
        ("mov_b_stp", "FNM", "0010........0100", "mov.b {m}, @-{n}", "store"),
        ("mov_w_stp", "FNM", "0010........0101", "mov.w {m}, @-{n}", "store"),
        ("mov_l_stp", "FNM", "0010........0110", "mov.l {m}, @-{n}", "store"),
        ("mov_b_idx_st", "FNM", "0000........0100", "mov.b {m}, @(r0,{n})", "store"),
        ("mov_w_idx_st", "FNM", "0000........0101", "mov.w {m}, @(r0,{n})", "store"),
        ("mov_l_idx_st", "FNM", "0000........0110", "mov.l {m}, @(r0,{n})", "store"),
        ("mov_b_idx_ld", "FNM", "0000........1100", "mov.b @(r0,{m}), {n}", "load"),
        ("mov_w_idx_ld", "FNM", "0000........1101", "mov.w @(r0,{m}), {n}", "load"),
        ("mov_l_idx_ld", "FNM", "0000........1110", "mov.l @(r0,{m}), {n}", "load"),
        ("mov_b_r0_st", "FND4", "10000000........", "mov.b r0, @({d4},{n})", "store"),
        ("mov_w_r0_st", "FND4", "10000001........", "mov.w r0, @({d4},{n})", "store"),
        ("mov_l_st_d", "FNM4", "0001............", "mov.l {m}, @({d4},{n})", "store"),
        ("mov_b_r0_ld", "FMD4", "10000100........", "mov.b @({d4},{m}), r0", "load"),
        ("mov_w_r0_ld", "FMD4", "10000101........", "mov.w @({d4},{m}), r0", "load"),
        ("mov_l_ld_d", "FNM4", "0101............", "mov.l @({d4},{m}), {n}", "load"),
        ("mov_b_gbr_st", "FI", "11000000........", "mov.b r0, @({i},gbr)", "store"),
        ("mov_w_gbr_st", "FI", "11000001........", "mov.w r0, @({i},gbr)", "store"),
        ("mov_l_gbr_st", "FI", "11000010........", "mov.l r0, @({i},gbr)", "store"),
        ("mov_b_gbr_ld", "FI", "11000100........", "mov.b @({i},gbr), r0", "load"),
        ("mov_w_gbr_ld", "FI", "11000101........", "mov.w @({i},gbr), r0", "load"),
        ("mov_l_gbr_ld", "FI", "11000110........", "mov.l @({i},gbr), r0", "load"),
        ("mova", "FI", "11000111........", "mova @({i},pc), r0", "alu"),
        ("movt", "FN", "0000....00101001", "movt {n}", "alu"),
        // SWAP/XTRCT。
        ("swap_b", "FNM", "0110........1000", "swap.b {m}, {n}", "alu"),
        ("swap_w", "FNM", "0110........1001", "swap.w {m}, {n}", "alu"),
        ("xtrct", "FNM", "0010........1101", "xtrct {m}, {n}", "alu"),
        // 算術。
        ("add_imm", "FNI", "0111............", "add #{i}, {n}", "alu"),
        ("add", "FNM", "0011........1100", "add {m}, {n}", "alu"),
        ("addc", "FNM", "0011........1110", "addc {m}, {n}", "alu"),
        ("addv", "FNM", "0011........1111", "addv {m}, {n}", "alu"),
        ("cmp_eq_imm", "FI", "10001000........", "cmp/eq #{i}, r0", "alu"),
        ("cmp_eq", "FNM", "0011........0000", "cmp/eq {m}, {n}", "alu"),
        ("cmp_hs", "FNM", "0011........0010", "cmp/hs {m}, {n}", "alu"),
        ("cmp_ge", "FNM", "0011........0011", "cmp/ge {m}, {n}", "alu"),
        ("cmp_hi", "FNM", "0011........0110", "cmp/hi {m}, {n}", "alu"),
        ("cmp_gt", "FNM", "0011........0111", "cmp/gt {m}, {n}", "alu"),
        ("cmp_pl", "FN", "0100....00010101", "cmp/pl {n}", "alu"),
        ("cmp_pz", "FN", "0100....00010001", "cmp/pz {n}", "alu"),
        ("cmp_str", "FNM", "0010........1100", "cmp/str {m}, {n}", "alu"),
        ("div0s", "FNM", "0010........0111", "div0s {m}, {n}", "alu"),
        ("div0u", "FNONE", "0000000000011001", "div0u", "alu"),
        ("div1", "FNM", "0011........0100", "div1 {m}, {n}", "alu"),
        ("neg", "FNM", "0110........1011", "neg {m}, {n}", "alu"),
        ("negc", "FNM", "0110........1010", "negc {m}, {n}", "alu"),
        ("sub", "FNM", "0011........1000", "sub {m}, {n}", "alu"),
        ("subc", "FNM", "0011........1010", "subc {m}, {n}", "alu"),
        ("subv", "FNM", "0011........1011", "subv {m}, {n}", "alu"),
        // 論理。
        ("and", "FNM", "0010........1001", "and {m}, {n}", "alu"),
        ("and_imm", "FI", "11001001........", "and #{i}, r0", "alu"),
        ("and_b_imm", "FI", "11001101........", "and.b #{i}, @(r0,gbr)", "alu"),
        ("not", "FNM", "0110........0111", "not {m}, {n}", "alu"),
        ("or", "FNM", "0010........1011", "or {m}, {n}", "alu"),
        ("or_imm", "FI", "11001011........", "or #{i}, r0", "alu"),
        ("or_b_imm", "FI", "11001111........", "or.b #{i}, @(r0,gbr)", "alu"),
        ("tas_b", "FN", "0100....00011011", "tas.b @{n}", "alu"),
        ("tst", "FNM", "0010........1000", "tst {m}, {n}", "alu"),
        ("tst_imm", "FI", "11001000........", "tst #{i}, r0", "alu"),
        ("tst_b_imm", "FI", "11001100........", "tst.b #{i}, @(r0,gbr)", "alu"),
        ("xor", "FNM", "0010........1010", "xor {m}, {n}", "alu"),
        ("xor_imm", "FI", "11001010........", "xor #{i}, r0", "alu"),
        ("xor_b_imm", "FI", "11001110........", "xor.b #{i}, @(r0,gbr)", "alu"),
        // シフト・ローテート・拡張。
        ("shll", "FN", "0100....00000000", "shll {n}", "alu"),
        ("shlr", "FN", "0100....00000001", "shlr {n}", "alu"),
        ("shll2", "FN", "0100....00001000", "shll2 {n}", "alu"),
        ("shlr2", "FN", "0100....00001001", "shlr2 {n}", "alu"),
        ("shll8", "FN", "0100....00011000", "shll8 {n}", "alu"),
        ("shlr8", "FN", "0100....00011001", "shlr8 {n}", "alu"),
        ("shll16", "FN", "0100....00101000", "shll16 {n}", "alu"),
        ("shlr16", "FN", "0100....00101001", "shlr16 {n}", "alu"),
        ("shal", "FN", "0100....00100000", "shal {n}", "alu"),
        ("shar", "FN", "0100....00100001", "shar {n}", "alu"),
        ("rotl", "FN", "0100....00000100", "rotl {n}", "alu"),
        ("rotr", "FN", "0100....00000101", "rotr {n}", "alu"),
        ("rotcl", "FN", "0100....00100100", "rotcl {n}", "alu"),
        ("rotcr", "FN", "0100....00100101", "rotcr {n}", "alu"),
        ("extu_b", "FNM", "0110........1100", "extu.b {m}, {n}", "alu"),
        ("extu_w", "FNM", "0110........1101", "extu.w {m}, {n}", "alu"),
        ("exts_b", "FNM", "0110........1110", "exts.b {m}, {n}", "alu"),
        ("exts_w", "FNM", "0110........1111", "exts.w {m}, {n}", "alu"),
        // 乗算・MAC（SH-1 は MULS/MULU/MAC.W を持つ）。
        // Ref: SPEC-SUPERH-SH2 Table 3.
        ("muls_w", "FNM", "0010........1111", "muls.w {m}, {n}", "alu"),
        ("mulu_w", "FNM", "0010........1110", "mulu.w {m}, {n}", "alu"),
        ("mac_w", "FNM", "0100........1111", "mac.w @{m}+, @{n}+", "alu"),
        ("clrmac", "FNONE", "0000000000101000", "clrmac", "system"),
        // 分岐・制御。
        ("bf", "FD8", "10001011........", "bf {d}", "branch"),
        ("bt", "FD8", "10001001........", "bt {d}", "branch"),
        ("bra", "FD", "1010............", "bra {d}", "branch"),
        ("bsr", "FD", "1011............", "bsr {d}", "branch"),
        ("jmp", "FM", "0100....00101011", "jmp @{m}", "branch"),
        ("jsr", "FM", "0100....00001011", "jsr @{m}", "branch"),
        ("rts", "FNONE", "0000000000001011", "rts", "branch"),
        ("trapa", "FI", "11000011........", "trapa #{i}", "system"),
        ("nop", "FNONE", "0000000000001001", "nop", "misc"),
        ("sett", "FNONE", "0000000000011000", "sett", "system"),
        ("clrt", "FNONE", "0000000000001000", "clrt", "system"),
        ("rte", "FNONE", "0000000000101011", "rte", "system"),
        ("sleep", "FNONE", "0000000000011011", "sleep", "system"),
        // STC/LDC/STS/LDS 基本（SR/GBR/VBR と MACH/MACL/PR）。
        ("stc_sr", "FN", "0000....00000010", "stc sr, {n}", "system"),
        ("stc_gbr", "FN", "0000....00010010", "stc gbr, {n}", "system"),
        ("stc_vbr", "FN", "0000....00100010", "stc vbr, {n}", "system"),
        ("stcm_sr", "FN", "0100....00000011", "stc.l sr, @-{n}", "store"),
        ("stcm_gbr", "FN", "0100....00010011", "stc.l gbr, @-{n}", "store"),
        ("stcm_vbr", "FN", "0100....00100011", "stc.l vbr, @-{n}", "store"),
        ("ldc_sr", "FM", "0100....00001110", "ldc {m}, sr", "system"),
        ("ldc_gbr", "FM", "0100....00011110", "ldc {m}, gbr", "system"),
        ("ldc_vbr", "FM", "0100....00101110", "ldc {m}, vbr", "system"),
        ("ldcm_sr", "FM", "0100....00000111", "ldc.l @{m}+, sr", "load"),
        ("ldcm_gbr", "FM", "0100....00010111", "ldc.l @{m}+, gbr", "load"),
        ("ldcm_vbr", "FM", "0100....00100111", "ldc.l @{m}+, vbr", "load"),
        ("sts_mach", "FN", "0000....00001010", "sts mach, {n}", "system"),
        ("sts_macl", "FN", "0000....00011010", "sts macl, {n}", "system"),
        ("sts_pr", "FN", "0000....00101010", "sts pr, {n}", "system"),
        ("stsm_mach", "FN", "0100....00000010", "sts.l mach, @-{n}", "store"),
        ("stsm_macl", "FN", "0100....00010010", "sts.l macl, @-{n}", "store"),
        ("stsm_pr", "FN", "0100....00100010", "sts.l pr, @-{n}", "store"),
        ("lds_mach", "FM", "0100....00001010", "lds {m}, mach", "system"),
        ("lds_macl", "FM", "0100....00011010", "lds {m}, macl", "system"),
        ("lds_pr", "FM", "0100....00101010", "lds {m}, pr", "system"),
        ("ldsm_mach", "FM", "0100....00000110", "lds.l @{m}+, mach", "load"),
        ("ldsm_macl", "FM", "0100....00010110", "lds.l @{m}+, macl", "load"),
        ("ldsm_pr", "FM", "0100....00100110", "lds.l @{m}+, pr", "load"),
    ] {
        m.insns.push(ins(name, format, pattern, base(), syntax, timing));
    }

    // ---- SH-2 追加（BF/S・BT/S・BRAF・BSRF・DT・DMULx・MAC.L・MUL.L）。
    // Ref: SPEC-SUPERH-SH2 Table 3.
    for (name, format, pattern, syntax, timing) in [
        ("bfs", "FD8", "10001111........", "bf/s {d}", "branch"),
        ("bts", "FD8", "10001101........", "bt/s {d}", "branch"),
        ("braf", "FM", "0000....00100011", "braf {m}", "branch"),
        ("bsrf", "FM", "0000....00000011", "bsrf {m}", "branch"),
        ("dt", "FN", "0100....00010000", "dt {n}", "alu"),
        ("dmuls", "FNM", "0011........1101", "dmuls.l {m}, {n}", "alu"),
        ("dmulu", "FNM", "0011........0101", "dmulu.l {m}, {n}", "alu"),
        ("mac_l", "FNM", "0000........1111", "mac.l @{m}+, @{n}+", "alu"),
        ("mul_l", "FNM", "0000........0111", "mul.l {m}, {n}", "alu"),
    ] {
        m.insns.push(ins(name, format, pattern, f_sh2(), syntax, timing));
    }

    // ---- SH-3 追加。CLRS/LDTLB は SH-4 系も持つ。SETS は SH-3 のみ
    // （SH-4 系の命令表に `...01011000` の割当がない）。
    // Ref: SPEC-SUPERH-SH3 §7.12/§8.2.56, SPEC-SUPERH-SH4 §10.
    m.insns.push(ins("clrs", "FNONE", "0000000001001000", f_sh3(), "clrs", "system"));
    m.insns.push(ins(
        "sets",
        "FNONE",
        "0000000001011000",
        Pred::All(vec![f_sh3(), Pred::Not(Box::new(f_sh4()))]),
        "sets",
        "system",
    ));
    m.insns.push(ins("ldtlb", "FNONE", "0000000000111000", f_sh3(), "ldtlb", "system"));

    // SHAD/SHLD（SH-3・SH-2A・J-core）。
    // Ref: SPEC-SUPERH-SH3 §7.12, SPEC-SUPERH-SH2A §5, SPEC-SUPERH-JCORE.
    m.insns.push(ins("shad", "FNM", "0100........1100", f_dyn_shift(), "shad {m}, {n}", "alu"));
    m.insns.push(ins("shld", "FNM", "0100........1101", f_dyn_shift(), "shld {m}, {n}", "alu"));

    // SSR/SPC（SH-3 系。SH-4 も持つ）。
    // Ref: SPEC-SUPERH-SH3 §7.12, SPEC-SUPERH-SH4A.
    for (name, format, pattern, syntax, timing) in [
        ("stc_ssr", "FN", "0000....00110010", "stc ssr, {n}", "system"),
        ("stcm_ssr", "FN", "0100....00110011", "stc.l ssr, @-{n}", "store"),
        ("stc_spc", "FN", "0000....01000010", "stc spc, {n}", "system"),
        ("stcm_spc", "FN", "0100....01000011", "stc.l spc, @-{n}", "store"),
        ("ldc_ssr", "FM", "0100....00111110", "ldc {m}, ssr", "system"),
        ("ldcm_ssr", "FM", "0100....00110111", "ldc.l @{m}+, ssr", "load"),
        ("ldc_spc", "FM", "0100....01001110", "ldc {m}, spc", "system"),
        ("ldcm_spc", "FM", "0100....01000111", "ldc.l @{m}+, spc", "load"),
    ] {
        m.insns.push(ins(name, format, pattern, f_sh3(), syntax, timing));
    }

    // SGR（SH-3E・SH-4 系）。
    // Ref: SPEC-SUPERH-SH3（SH-3E のレジスタ構成）, SPEC-SUPERH-SH4A.
    for (name, format, pattern, syntax, timing) in [
        ("stc_sgr", "FN", "0000....00111010", "stc sgr, {n}", "system"),
        ("stcm_sgr", "FN", "0100....00110010", "stc.l sgr, @-{n}", "store"),
        ("ldc_sgr", "FM", "0100....00111010", "ldc {m}, sgr", "system"),
        ("ldcm_sgr", "FM", "0100....00110110", "ldc.l @{m}+, sgr", "load"),
    ] {
        m.insns.push(ins(name, format, pattern, f_sgr(), syntax, timing));
    }

    // ---- SH-4 追加。R_BANK・キャッシュ系・FPU 拡張。
    // Ref: SPEC-SUPERH-SH4 §10, SPEC-SUPERH-SH4A.
    for (name, format, pattern, syntax, timing) in [
        ("stc_rbank", "FNB", "0000....1...0010", "stc r{b}_bank, {n}", "system"),
        ("stcm_rbank", "FNB", "0100....1...0011", "stc.l r{b}_bank, @-{n}", "store"),
        ("ldc_rbank", "FMB", "0100....1...1110", "ldc {m}, r{b}_bank", "system"),
        ("ldcm_rbank", "FMB", "0100....1...0111", "ldc.l @{m}+, r{b}_bank", "load"),
        ("ocbi", "FN", "0000....10010011", "ocbi @{n}", "system"),
        ("ocbp", "FN", "0000....10100011", "ocbp @{n}", "system"),
        ("ocbwb", "FN", "0000....10110011", "ocbwb @{n}", "system"),
        ("movca", "FN", "0000....11000011", "movca.l r0, @{n}", "store"),
        ("frchg", "FNONE", "1111101111111101", "frchg", "fp"),
        ("fsrra", "FFN", "1111....01111101", "fsrra {n}", "fp"),
        ("fsca", "FN3", "1111...011111101", "fsca fpul, {drn}", "fp"),
        ("fipr", "FFV", "1111....11101101", "fipr {fvm}, {fvn}", "fp"),
        ("ftrv", "FFV1", "1111..0111111101", "ftrv xmtx, {fvn}", "fp"),
    ] {
        m.insns.push(ins(name, format, pattern, f_sh4(), syntax, timing));
    }

    // PREF は SH-4 と SH-2A が持つ。
    m.insns.push(ins("pref", "FN", "0000....10000011", f_pref(), "pref @{n}", "system"));

    // ---- SH-4A 追加。MOVLI/MOVCO/ICBI/PREFI/SYNCO/FPCHG/DBR。
    // Ref: SPEC-SUPERH-SH4A.
    for (name, format, pattern, syntax, timing) in [
        ("movli", "FN", "0000....01100011", "movli.l @{n}, r0", "load"),
        ("movco", "FN", "0000....01110011", "movco.l r0, @{n}", "store"),
        ("synco", "FNONE", "0000000010101011", "synco", "system"),
        ("icbi", "FN", "0000....11100011", "icbi @{n}", "system"),
        ("prefi", "FN", "0000....11010011", "prefi @{n}", "system"),
        ("fpchg", "FNONE", "1111011111111101", "fpchg", "fp"),
        ("stc_dbr", "FN", "0000....11111010", "stc dbr, {n}", "system"),
        ("stcm_dbr", "FN", "0100....11110010", "stc.l dbr, @-{n}", "store"),
        ("ldc_dbr", "FM", "0100....11111010", "ldc {m}, dbr", "system"),
        ("ldcm_dbr", "FM", "0100....11110110", "ldc.l @{m}+, dbr", "load"),
    ] {
        m.insns.push(ins(name, format, pattern, f_sh4a(), syntax, timing));
    }

    // MOVUA.L は SH-4A と SH-2A が持つ。
    // Ref: SPEC-SUPERH-SH4A, SPEC-SUPERH-SH2A.
    m.insns.push(ins("movua_l", "FM", "0100....10101001", f_movua(), "movua.l @{m}, r0", "load"));
    m.insns.push(ins(
        "movua_l_post",
        "FM",
        "0100....11101001",
        f_movua(),
        "movua.l @{m}+, r0",
        "load",
    ));

    // ---- J-core 追加。CAS.L・SHAD/SHLD（後者は上で宣言済み）。
    // Ref: SPEC-SUPERH-JCORE.
    m.insns.push(ins("cas_l", "FNM", "0010........0011", f_jcore(), "cas.l {m}, {n}, @r0", "alu"));

    // ---- SH-2A 追加（16 ビット形式）。
    // Ref: SPEC-SUPERH-SH2A §5.
    for (name, format, pattern, syntax, timing) in [
        ("mov_b_r0_stp", "FN", "0100....10001011", "mov.b r0, @{n}+", "store"),
        ("mov_w_r0_stp", "FN", "0100....10011011", "mov.w r0, @{n}+", "store"),
        ("mov_l_r0_stp", "FN", "0100....10101011", "mov.l r0, @{n}+", "store"),
        ("mov_b_r0_ldp", "FM", "0100....11001011", "mov.b @-{m}, r0", "load"),
        ("mov_w_r0_ldp", "FM", "0100....11011011", "mov.w @-{m}, r0", "load"),
        ("mov_l_r0_ldp", "FM", "0100....11101011", "mov.l @-{m}, r0", "load"),
        ("movml_st", "FM", "0100....11110001", "movml.l {m}, @-r15", "store"),
        ("movml_ld", "FN", "0100....11110101", "movml.l @r15+, {n}", "load"),
        ("movmu_st", "FM", "0100....11110000", "movmu.l {m}, @-r15", "store"),
        ("movmu_ld", "FN", "0100....11110100", "movmu.l @r15+, {n}", "load"),
        ("movrt", "FN", "0000....00111001", "movrt {n}", "alu"),
        ("nott", "FNONE", "0000000001101000", "nott", "alu"),
        ("clips_b", "FN", "0100....10010001", "clips.b {n}", "alu"),
        ("clips_w", "FN", "0100....10010101", "clips.w {n}", "alu"),
        ("clipu_b", "FN", "0100....10000001", "clipu.b {n}", "alu"),
        ("clipu_w", "FN", "0100....10000101", "clipu.w {n}", "alu"),
        ("divs", "FN", "0100....10010100", "divs r0, {n}", "alu"),
        ("divu", "FN", "0100....10000100", "divu r0, {n}", "alu"),
        ("mulr", "FN", "0100....10000000", "mulr r0, {n}", "alu"),
        ("jsrn_mem", "FM", "0100....01001011", "jsr/n @{m}", "branch"),
        ("jsrn_tbr", "FD8", "10000011........", "jsr/n @@({d},tbr)", "branch"),
        ("rtsn", "FNONE", "0000000001101011", "rts/n", "branch"),
        ("rtvn", "FM", "0000....01111011", "rtv/n {m}", "branch"),
        ("ldbank", "FM", "0100....11100101", "ldbank @{m}, r0", "load"),
        ("stbank", "FN", "0100....11100001", "stbank r0, @{n}", "store"),
        ("resbank", "FNONE", "0000000001011011", "resbank", "system"),
        ("stc_tbr", "FN", "0000....01001010", "stc tbr, {n}", "system"),
        ("ldc_tbr", "FM", "0100....01001010", "ldc {m}, tbr", "system"),
        ("bclr_reg", "FNI3", "10000110....0...", "bclr #{i3}, {n}", "alu"),
        ("bset_reg", "FNI3", "10000110....1...", "bset #{i3}, {n}", "alu"),
        ("bld_reg", "FNI3", "10000111....1...", "bld #{i3}, {n}", "alu"),
        ("bst_reg", "FNI3", "10000111....0...", "bst #{i3}, {n}", "alu"),
    ] {
        m.insns.push(ins(name, format, pattern, f_sh2a(), syntax, timing));
    }

    // ---- SH-2A の 32 ビット命令（先頭パーセル + 次パーセル）。
    // MOV disp12 系は先頭語 `0011nnnnmmmm0001`、下位語の上位 4 ビット
    // がオペ種別（0000/0001/0010=ストア、0100/0101/0110=ロード、
    // 1000/1001=MOVU）。FMOV disp12 系は `0011` が FMOV.S ストア、
    // `0111` が FMOV.S ロードで、SH2A-FPU（sh2a+fpu）のみ。
    // 下位語で `DRm/DRn` の 3 ビット形式も表に出るが、これは FPSCR.SZ=1
    // のとき同一語を対移動として再解釈するもので独立符号化ではない
    // （m/n の偶奇が FR と DR/XD を切替える）。よって 4 ビット形式の
    // FMOV.S だけを宣言する。
    // Ref: SPEC-SUPERH-SH2A §5, SPEC-SUPERH-SH4 §6（SZ ビット）.
    for (name, format, pattern, syntax, timing) in [
        ("mov_b_d12_st", "FW3", "0011........0001 0000............", "mov.b {m}, @({d},{n})", "store"),
        ("mov_w_d12_st", "FW3", "0011........0001 0001............", "mov.w {m}, @({d},{n})", "store"),
        ("mov_l_d12_st", "FW3", "0011........0001 0010............", "mov.l {m}, @({d},{n})", "store"),
        ("mov_b_d12_ld", "FW3", "0011........0001 0100............", "mov.b @({d},{m}), {n}", "load"),
        ("mov_w_d12_ld", "FW3", "0011........0001 0101............", "mov.w @({d},{m}), {n}", "load"),
        ("mov_l_d12_ld", "FW3", "0011........0001 0110............", "mov.l @({d},{m}), {n}", "load"),
        ("movu_b_d12", "FW3", "0011........0001 1000............", "movu.b @({d},{m}), {n}", "load"),
        ("movu_w_d12", "FW3", "0011........0001 1001............", "movu.w @({d},{m}), {n}", "load"),
    ] {
        m.insns.push(ins(name, format, pattern, f_sh2a(), syntax, timing));
    }
    let f_sh2afpu = || Pred::All(vec![f_sh2a(), f_fpu()]);
    m.insns.push(ins(
        "fmov_s_d12_st",
        "FW3FST",
        "0011........0001 0011............",
        f_sh2afpu(),
        "fmov.s {m}, @({d},{n})",
        "store",
    ));
    m.insns.push(ins(
        "fmov_s_d12_ld",
        "FW3FLD",
        "0011........0001 0111............",
        f_sh2afpu(),
        "fmov.s @({d},{m}), {n}",
        "load",
    ));

    // 32 ビット ビット命令（`0011nnnn0iii1001` + 下位語）。
    // Ref: SPEC-SUPERH-SH2A §5.
    for (name, pattern, syntax) in [
        ("bclr_d12", "0011....0...1001 0000............", "bclr.b #{i3}, @({d},{n})"),
        ("bset_d12", "0011....0...1001 0001............", "bset.b #{i3}, @({d},{n})"),
        ("bst_d12", "0011....0...1001 0010............", "bst.b #{i3}, @({d},{n})"),
        ("bld_d12", "0011....0...1001 0011............", "bld.b #{i3}, @({d},{n})"),
        ("band_d12", "0011....0...1001 0100............", "band.b #{i3}, @({d},{n})"),
        ("bor_d12", "0011....0...1001 0101............", "bor.b #{i3}, @({d},{n})"),
        ("bxor_d12", "0011....0...1001 0110............", "bxor.b #{i3}, @({d},{n})"),
        ("bldnot_d12", "0011....0...1001 1011............", "bldnot.b #{i3}, @({d},{n})"),
        ("bandnot_d12", "0011....0...1001 1100............", "bandnot.b #{i3}, @({d},{n})"),
        ("bornot_d12", "0011....0...1001 1101............", "bornot.b #{i3}, @({d},{n})"),
    ] {
        m.insns.push(ins(name, "FWB", pattern, f_sh2a(), syntax, "alu"));
    }

    // MOVI20/MOVI20S（`0000nnnniiii000x` + imm16）。
    // Ref: SPEC-SUPERH-SH2A §5.
    m.insns.push(ins(
        "movi20",
        "FWI",
        "0000........0000 ................",
        f_sh2a(),
        "movi20 #{i4}{i16}, {n}",
        "alu",
    ));
    m.insns.push(ins(
        "movi20s",
        "FWI",
        "0000........0001 ................",
        f_sh2a(),
        "movi20s #{i4}{i16}, {n}",
        "alu",
    ));

    // ---- 単精度 FPU（SH-2E/SH-3E/SH-4/SH2A-FPU）。
    // Ref: SPEC-SUPERH-SH4 §10, SPEC-SUPERH-SH2A §5.
    // SH-2E の FPU 部分集合は公開一次資料が手元にないため、
    // 単精度命令を `fpu` 一旗で近似する（SH-2E は FSQRT 等を持たない
    // 可能性がある）。
    // Gap: GAP-0059
    for (name, format, pattern, syntax, timing) in [
        ("fadd", "FFF", "1111........0000", "fadd {m}, {n}", "fp"),
        ("fsub", "FFF", "1111........0001", "fsub {m}, {n}", "fp"),
        ("fmul", "FFF", "1111........0010", "fmul {m}, {n}", "fp"),
        ("fdiv", "FFF", "1111........0011", "fdiv {m}, {n}", "fp"),
        ("fcmp_eq", "FFF", "1111........0100", "fcmp/eq {m}, {n}", "fp"),
        ("fcmp_gt", "FFF", "1111........0101", "fcmp/gt {m}, {n}", "fp"),
        ("fmov_s_idx_ld", "FFLD", "1111........0110", "fmov.s @(r0,{m}), {n}", "load"),
        ("fmov_s_idx_st", "FFST", "1111........0111", "fmov.s {m}, @(r0,{n})", "store"),
        ("fmov_s_ld", "FFLD", "1111........1000", "fmov.s @{m}, {n}", "load"),
        ("fmov_s_ldp", "FFLD", "1111........1001", "fmov.s @{m}+, {n}", "load"),
        ("fmov_s_st", "FFST", "1111........1010", "fmov.s {m}, @{n}", "store"),
        ("fmov_s_stp", "FFST", "1111........1011", "fmov.s {m}, @-{n}", "store"),
        ("fmov_reg", "FFF", "1111........1100", "fmov {m}, {n}", "fp"),
        ("fmac", "FFF", "1111........1110", "fmac fr0, {m}, {n}", "fp"),
        ("fsts", "FFN", "1111....00001101", "fsts fpul, {n}", "fp"),
        ("flds", "FFM", "1111....00011101", "flds {m}, fpul", "fp"),
        ("float", "FFN", "1111....00101101", "float fpul, {n}", "fp"),
        ("ftrc", "FFM", "1111....00111101", "ftrc {m}, fpul", "fp"),
        ("fneg", "FFN", "1111....01001101", "fneg {n}", "fp"),
        ("fabs", "FFN", "1111....01011101", "fabs {n}", "fp"),
        ("fsqrt", "FFN", "1111....01101101", "fsqrt {n}", "fp"),
        ("fldi0", "FFN", "1111....10001101", "fldi0 {n}", "fp"),
        ("fldi1", "FFN", "1111....10011101", "fldi1 {n}", "fp"),
        ("fschg", "FNONE", "1111001111111101", "fschg", "fp"),
        ("sts_fpscr", "FN", "0000....01101010", "sts fpscr, {n}", "system"),
        ("sts_fpul", "FN", "0000....01011010", "sts fpul, {n}", "system"),
        ("stsm_fpscr", "FN", "0100....01100010", "sts.l fpscr, @-{n}", "store"),
        ("stsm_fpul", "FN", "0100....01010010", "sts.l fpul, @-{n}", "store"),
        ("lds_fpscr", "FM", "0100....01101010", "lds {m}, fpscr", "system"),
        ("lds_fpul", "FM", "0100....01011010", "lds {m}, fpul", "system"),
        ("ldsm_fpscr", "FM", "0100....01100110", "lds.l @{m}+, fpscr", "load"),
        ("ldsm_fpul", "FM", "0100....01010110", "lds.l @{m}+, fpul", "load"),
    ] {
        m.insns.push(ins(name, format, pattern, f_fpu(), syntax, timing));
    }

    // ---- 倍精度 FPU・XD バンク（SH-4/SH-4A/SH2A-FPU）。
    // 命令表に `1111nnn0mmm0xxxx` の形で出る FADD DRm,DRn や
    // FMOV DRm,@Rn 等は全て対応する 4 ビット形式（上の `fpu` 群）の
    // 部分集合で、FPSCR.PR/SZ=1 のとき同一語を対・倍精度として再解釈
    // するもの（独立符号化ではない）。よってここでは 4 ビット形式と
    // 重ならない固有符号化（FCNVSD/FCNVDS のみ、`[7:0]` が 0xad/0xbd で
    // 基本語彙に無い）だけを宣言する。FSCA/FTRV/FIPR/FSRRA/FRCHG は
    // 固有符号化で `sh4` 旗側に宣言済み。
    // Ref: SPEC-SUPERH-SH4 §6/§10, SPEC-SUPERH-SH2A §5.
    // レジスタ桁は [11:9] の 3 ビット（bit8=0 は符号化上の選択子）。
    m.insns.push(ins(
        "fcnvds",
        "FN3R",
        "1111...010111101",
        f_fpud(),
        "fcnvds {drn}, fpul",
        "fp",
    ));
    m.insns.push(ins(
        "fcnvsd",
        "FN3",
        "1111...010101101",
        f_fpud(),
        "fcnvsd fpul, {drn}",
        "fp",
    ));

    m
}
