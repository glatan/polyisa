// RV64I の ISADL モデル。
//
// 出典は下記の資料の版 20250508 である。各命令の節番号は
// 将来の `.isadl` 構文解析で付ける。ここでは事実（符号化）のみを記述する。
// Ref: SPEC-RISCV-UNPRIV (20250508).

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// RV64I の検査済みモデルを作る。RV32I 共通 37 件のうちシフト 3 件は RV64 版で置き換える。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    for class in ["alu", "load", "store", "branch", "jump", "system", "mult", "div", "atomic", "fpu"] {
        m.timing_classes.push(class.to_string());
    }

    // 機能と汎用CPUモデル。RVA22U64相当のRV64GCを汎用とする。
    // Ref: SPEC-RISCV-UNPRIV (20250508), SPEC-RISCV-PROFILES (RVA23 v1.0).
    for (name, implies, conflicts) in [
        ("rv64", &[][..], &["rv32"][..]),
        ("rv32", &[][..], &["rv64"][..]),
        ("m", &[][..], &[][..]),
        ("a", &[][..], &[][..]),
        ("f", &[][..], &[][..]),
        ("d", &["f"][..], &[][..]),
        ("c", &[][..], &[][..]),
        ("zicsr", &[][..], &[][..]),
        ("zifencei", &[][..], &[][..]),
    ] {
        m.features.push(polyisa_isadl::model::Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: conflicts.iter().map(|s| s.to_string()).collect(),
        });
    }
    m.models.push(polyisa_isadl::model::ModelDef {
        name: "rv64gc".to_string(),
        parent: String::new(),
        add_features: ["rv64", "m", "a", "f", "d", "c", "zicsr", "zifencei"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        remove_features: Vec::new(),
    });
    m.models.push(polyisa_isadl::model::ModelDef {
        name: "rv64imac".to_string(),
        parent: "rv64gc".to_string(),
        add_features: Vec::new(),
        remove_features: ["f", "d"].iter().map(|s| s.to_string()).collect(),
    });

    m.regclasses.push(RegClass {
        name: "gpr".to_string(),
        dynamic: false,
    });

    for (name, hi, lo) in [("rd", 11, 7), ("rs1", 19, 15), ("rs2", 24, 20), ("funct3", 14, 12)] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    let gpr = |name: &str, access: Access| Operand {
        name: name.to_string(),
        regclass: Some("gpr".to_string()),
        access,
    };
    m.formats.push(Format {
        name: "R".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string(), "rs2".to_string()],
        operands: vec![
            gpr("rd", Access::Write),
            gpr("rs1", Access::Read),
            gpr("rs2", Access::Read),
        ],
    });
    m.formats.push(Format {
        name: "I".to_string(),
        fields: vec!["rd".to_string(), "rs1".to_string()],
        operands: vec![gpr("rd", Access::Write), gpr("rs1", Access::Read)],
    });
    m.formats.push(Format {
        name: "S".to_string(),
        fields: vec!["rs1".to_string(), "rs2".to_string()],
        operands: vec![gpr("rs1", Access::Read), gpr("rs2", Access::Read)],
    });
    m.formats.push(Format {
        name: "B".to_string(),
        fields: vec!["rs1".to_string(), "rs2".to_string()],
        operands: vec![gpr("rs1", Access::Read), gpr("rs2", Access::Read)],
    });
    m.formats.push(Format {
        name: "U".to_string(),
        fields: vec!["rd".to_string()],
        operands: vec![gpr("rd", Access::Write)],
    });
    m.formats.push(Format {
        name: "J".to_string(),
        fields: vec!["rd".to_string()],
        operands: vec![gpr("rd", Access::Write)],
    });

    // (名前, 形式, パターン, 構文, 分類)
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        // U/J/分岐
        ("lui", "U", ".................... ..... 0110111", "lui {rd}, {imm}", "alu"),
        ("auipc", "U", ".................... ..... 0010111", "auipc {rd}, {imm}", "alu"),
        ("jal", "J", ".................... ..... 1101111", "jal {rd}, {imm}", "jump"),
        ("jalr", "I", "............ ..... 000 ..... 1100111", "jalr {rd}, {rs1}, {imm}", "jump"),
        ("beq", "B", "....... ..... ..... 000 ..... 1100011", "beq {rs1}, {rs2}, {imm}", "branch"),
        ("bne", "B", "....... ..... ..... 001 ..... 1100011", "bne {rs1}, {rs2}, {imm}", "branch"),
        ("blt", "B", "....... ..... ..... 100 ..... 1100011", "blt {rs1}, {rs2}, {imm}", "branch"),
        ("bge", "B", "....... ..... ..... 101 ..... 1100011", "bge {rs1}, {rs2}, {imm}", "branch"),
        ("bltu", "B", "....... ..... ..... 110 ..... 1100011", "bltu {rs1}, {rs2}, {imm}", "branch"),
        ("bgeu", "B", "....... ..... ..... 111 ..... 1100011", "bgeu {rs1}, {rs2}, {imm}", "branch"),
        // ロード・ストア
        ("lb", "I", "............ ..... 000 ..... 0000011", "lb {rd}, {imm}({rs1})", "load"),
        ("lh", "I", "............ ..... 001 ..... 0000011", "lh {rd}, {imm}({rs1})", "load"),
        ("lw", "I", "............ ..... 010 ..... 0000011", "lw {rd}, {imm}({rs1})", "load"),
        ("ld", "I", "............ ..... 011 ..... 0000011", "ld {rd}, {imm}({rs1})", "load"),
        ("lbu", "I", "............ ..... 100 ..... 0000011", "lbu {rd}, {imm}({rs1})", "load"),
        ("lhu", "I", "............ ..... 101 ..... 0000011", "lhu {rd}, {imm}({rs1})", "load"),
        ("lwu", "I", "............ ..... 110 ..... 0000011", "lwu {rd}, {imm}({rs1})", "load"),
        ("sb", "S", "....... ..... ..... 000 ..... 0100011", "sb {rs2}, {imm}({rs1})", "store"),
        ("sh", "S", "....... ..... ..... 001 ..... 0100011", "sh {rs2}, {imm}({rs1})", "store"),
        ("sw", "S", "....... ..... ..... 010 ..... 0100011", "sw {rs2}, {imm}({rs1})", "store"),
        ("sd", "S", "....... ..... ..... 011 ..... 0100011", "sd {rs2}, {imm}({rs1})", "store"),
        // OP-IMM
        ("addi", "I", "............ ..... 000 ..... 0010011", "addi {rd}, {rs1}, {imm}", "alu"),
        ("slti", "I", "............ ..... 010 ..... 0010011", "slti {rd}, {rs1}, {imm}", "alu"),
        ("sltiu", "I", "............ ..... 011 ..... 0010011", "sltiu {rd}, {rs1}, {imm}", "alu"),
        ("xori", "I", "............ ..... 100 ..... 0010011", "xori {rd}, {rs1}, {imm}", "alu"),
        ("ori", "I", "............ ..... 110 ..... 0010011", "ori {rd}, {rs1}, {imm}", "alu"),
        ("andi", "I", "............ ..... 111 ..... 0010011", "andi {rd}, {rs1}, {imm}", "alu"),
        ("slli", "I", "000000 ...... ..... 001 ..... 0010011", "slli {rd}, {rs1}, {imm}", "alu"),
        ("srli", "I", "000000 ...... ..... 101 ..... 0010011", "srli {rd}, {rs1}, {imm}", "alu"),
        ("srai", "I", "010000 ...... ..... 101 ..... 0010011", "srai {rd}, {rs1}, {imm}", "alu"),
        // OP-IMM-32
        ("addiw", "I", "............ ..... 000 ..... 0011011", "addiw {rd}, {rs1}, {imm}", "alu"),
        ("slliw", "I", "0000000 ..... ..... 001 ..... 0011011", "slliw {rd}, {rs1}, {imm}", "alu"),
        ("srliw", "I", "0000000 ..... ..... 101 ..... 0011011", "srliw {rd}, {rs1}, {imm}", "alu"),
        ("sraiw", "I", "0100000 ..... ..... 101 ..... 0011011", "sraiw {rd}, {rs1}, {imm}", "alu"),
        // OP
        ("add", "R", "0000000 ..... ..... 000 ..... 0110011", "add {rd}, {rs1}, {rs2}", "alu"),
        ("sub", "R", "0100000 ..... ..... 000 ..... 0110011", "sub {rd}, {rs1}, {rs2}", "alu"),
        ("sll", "R", "0000000 ..... ..... 001 ..... 0110011", "sll {rd}, {rs1}, {rs2}", "alu"),
        ("slt", "R", "0000000 ..... ..... 010 ..... 0110011", "slt {rd}, {rs1}, {rs2}", "alu"),
        ("sltu", "R", "0000000 ..... ..... 011 ..... 0110011", "sltu {rd}, {rs1}, {rs2}", "alu"),
        ("xor", "R", "0000000 ..... ..... 100 ..... 0110011", "xor {rd}, {rs1}, {rs2}", "alu"),
        ("srl", "R", "0000000 ..... ..... 101 ..... 0110011", "srl {rd}, {rs1}, {rs2}", "alu"),
        ("sra", "R", "0100000 ..... ..... 101 ..... 0110011", "sra {rd}, {rs1}, {rs2}", "alu"),
        ("or", "R", "0000000 ..... ..... 110 ..... 0110011", "or {rd}, {rs1}, {rs2}", "alu"),
        ("and", "R", "0000000 ..... ..... 111 ..... 0110011", "and {rd}, {rs1}, {rs2}", "alu"),
        // OP-32
        ("addw", "R", "0000000 ..... ..... 000 ..... 0111011", "addw {rd}, {rs1}, {rs2}", "alu"),
        ("subw", "R", "0100000 ..... ..... 000 ..... 0111011", "subw {rd}, {rs1}, {rs2}", "alu"),
        ("sllw", "R", "0000000 ..... ..... 001 ..... 0111011", "sllw {rd}, {rs1}, {rs2}", "alu"),
        ("srlw", "R", "0000000 ..... ..... 101 ..... 0111011", "srlw {rd}, {rs1}, {rs2}", "alu"),
        ("sraw", "R", "0100000 ..... ..... 101 ..... 0111011", "sraw {rd}, {rs1}, {rs2}", "alu"),
        // SYSTEM（正規形のみ。pred/succ の一般形は後の段階で足す）
        ("fence", "I", "00001111111100000000000000001111", "fence", "system"),
        ("fence_i", "I", "00000000000000000001000000001111", "fence.i", "system"),
        ("ecall", "I", "000000000000 ..... 000 ..... 1110011", "ecall", "system"),
        ("ebreak", "I", "000000000001 ..... 000 ..... 1110011", "ebreak", "system"),
        // M（乗除算。funct7=0000001）
        ("mul", "R", "0000001 ..... ..... 000 ..... 0110011", "mul {rd}, {rs1}, {rs2}", "mult"),
        ("mulh", "R", "0000001 ..... ..... 001 ..... 0110011", "mulh {rd}, {rs1}, {rs2}", "mult"),
        ("mulhsu", "R", "0000001 ..... ..... 010 ..... 0110011", "mulhsu {rd}, {rs1}, {rs2}", "mult"),
        ("mulhu", "R", "0000001 ..... ..... 011 ..... 0110011", "mulhu {rd}, {rs1}, {rs2}", "mult"),
        ("div", "R", "0000001 ..... ..... 100 ..... 0110011", "div {rd}, {rs1}, {rs2}", "div"),
        ("divu", "R", "0000001 ..... ..... 101 ..... 0110011", "divu {rd}, {rs1}, {rs2}", "div"),
        ("rem", "R", "0000001 ..... ..... 110 ..... 0110011", "rem {rd}, {rs1}, {rs2}", "div"),
        ("remu", "R", "0000001 ..... ..... 111 ..... 0110011", "remu {rd}, {rs1}, {rs2}", "div"),
        ("mulw", "R", "0000001 ..... ..... 000 ..... 0111011", "mulw {rd}, {rs1}, {rs2}", "mult"),
        ("divw", "R", "0000001 ..... ..... 100 ..... 0111011", "divw {rd}, {rs1}, {rs2}", "div"),
        ("divuw", "R", "0000001 ..... ..... 101 ..... 0111011", "divuw {rd}, {rs1}, {rs2}", "div"),
        ("remw", "R", "0000001 ..... ..... 110 ..... 0111011", "remw {rd}, {rs1}, {rs2}", "div"),
        ("remuw", "R", "0000001 ..... ..... 111 ..... 0111011", "remuw {rd}, {rs1}, {rs2}", "div"),
        // SYSTEM の CSR 系（Zicsr）
        ("csrrw", "I", "............ ..... 001 ..... 1110011", "csrrw {rd}, {csr}, {rs1}", "system"),
        ("csrrs", "I", "............ ..... 010 ..... 1110011", "csrrs {rd}, {csr}, {rs1}", "system"),
        ("csrrc", "I", "............ ..... 011 ..... 1110011", "csrrc {rd}, {csr}, {rs1}", "system"),
        ("csrrwi", "I", "............ ..... 101 ..... 1110011", "csrrwi {rd}, {csr}, {uimm}", "system"),
        ("csrrsi", "I", "............ ..... 110 ..... 1110011", "csrrsi {rd}, {csr}, {uimm}", "system"),
        ("csrrci", "I", "............ ..... 111 ..... 1110011", "csrrci {rd}, {csr}, {uimm}", "system"),
        // A（不可分操作。aq/rl=00 の通常形のみ）
        ("lr_w", "I", "000100000000 ..... 010 ..... 0101111", "lr_w {rd}, ({rs1})", "atomic"),
        ("lr_d", "I", "000100000000 ..... 011 ..... 0101111", "lr_d {rd}, ({rs1})", "atomic"),
        ("sc_w", "R", "0001100 ..... ..... 010 ..... 0101111", "sc_w {rd}, {rs1}, {rs2}", "atomic"),
        ("sc_d", "R", "0001100 ..... ..... 011 ..... 0101111", "sc_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoswap_w", "R", "0000100 ..... ..... 010 ..... 0101111", "amoswap_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoadd_w", "R", "0000000 ..... ..... 010 ..... 0101111", "amoadd_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoxor_w", "R", "0010000 ..... ..... 010 ..... 0101111", "amoxor_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoand_w", "R", "0110000 ..... ..... 010 ..... 0101111", "amoand_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoor_w", "R", "0100000 ..... ..... 010 ..... 0101111", "amoor_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amomin_w", "R", "1000000 ..... ..... 010 ..... 0101111", "amomin_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amomax_w", "R", "1010000 ..... ..... 010 ..... 0101111", "amomax_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amominu_w", "R", "1100000 ..... ..... 010 ..... 0101111", "amominu_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amomaxu_w", "R", "1110000 ..... ..... 010 ..... 0101111", "amomaxu_w {rd}, {rs1}, {rs2}", "atomic"),
        ("amoswap_d", "R", "0000100 ..... ..... 011 ..... 0101111", "amoswap_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoadd_d", "R", "0000000 ..... ..... 011 ..... 0101111", "amoadd_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoxor_d", "R", "0010000 ..... ..... 011 ..... 0101111", "amoxor_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoand_d", "R", "0110000 ..... ..... 011 ..... 0101111", "amoand_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amoor_d", "R", "0100000 ..... ..... 011 ..... 0101111", "amoor_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amomin_d", "R", "1000000 ..... ..... 011 ..... 0101111", "amomin_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amomax_d", "R", "1010000 ..... ..... 011 ..... 0101111", "amomax_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amominu_d", "R", "1100000 ..... ..... 011 ..... 0101111", "amominu_d {rd}, {rs1}, {rs2}", "atomic"),
        ("amomaxu_d", "R", "1110000 ..... ..... 011 ..... 0101111", "amomaxu_d {rd}, {rs1}, {rs2}", "atomic"),
        // F（単精度浮動小数点。fmt=00。rm は RNE 固定で無視する）
        ("flw", "I", "............ ..... 010 ..... 0000111", "flw {rd}, {imm}({rs1})", "load"),
        ("fsw", "S", "....... ..... ..... 010 ..... 0100111", "fsw {rs2}, {imm}({rs1})", "store"),
        ("fadd_s", "R", "0000000 ..... ..... ... ..... 1010011", "fadd.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fsub_s", "R", "0000100 ..... ..... ... ..... 1010011", "fsub.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fmul_s", "R", "0001000 ..... ..... ... ..... 1010011", "fmul.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fdiv_s", "R", "0001100 ..... ..... ... ..... 1010011", "fdiv.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fsqrt_s", "R", "0101100 00000 ..... ... ..... 1010011", "fsqrt.s {rd}, {rs1}", "fpu"),
        ("fsgnj_s", "R", "0010000 ..... ..... 000 ..... 1010011", "fsgnj.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fsgnjn_s", "R", "0010000 ..... ..... 001 ..... 1010011", "fsgnjn.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fsgnjx_s", "R", "0010000 ..... ..... 010 ..... 1010011", "fsgnjx.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fmin_s", "R", "0010100 ..... ..... 000 ..... 1010011", "fmin.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fmax_s", "R", "0010100 ..... ..... 001 ..... 1010011", "fmax.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fcvt_w_s", "R", "1100000 00000 ..... ... ..... 1010011", "fcvt.w.s {rd}, {rs1}", "fpu"),
        ("fcvt_wu_s", "R", "1100000 00001 ..... ... ..... 1010011", "fcvt.wu.s {rd}, {rs1}", "fpu"),
        ("fcvt_l_s", "R", "1100000 00010 ..... ... ..... 1010011", "fcvt.l.s {rd}, {rs1}", "fpu"),
        ("fcvt_lu_s", "R", "1100000 00011 ..... ... ..... 1010011", "fcvt.lu.s {rd}, {rs1}", "fpu"),
        ("fmv_x_w", "R", "1110000 00000 ..... 000 ..... 1010011", "fmv.x.w {rd}, {rs1}", "fpu"),
        ("fclass_s", "R", "1110000 00000 ..... 001 ..... 1010011", "fclass.s {rd}, {rs1}", "fpu"),
        ("feq_s", "R", "1010000 ..... ..... 010 ..... 1010011", "feq.s {rd}, {rs1}, {rs2}", "fpu"),
        ("flt_s", "R", "1010000 ..... ..... 001 ..... 1010011", "flt.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fle_s", "R", "1010000 ..... ..... 000 ..... 1010011", "fle.s {rd}, {rs1}, {rs2}", "fpu"),
        ("fcvt_s_w", "R", "1101000 00000 ..... ... ..... 1010011", "fcvt.s.w {rd}, {rs1}", "fpu"),
        ("fcvt_s_wu", "R", "1101000 00001 ..... ... ..... 1010011", "fcvt.s.wu {rd}, {rs1}", "fpu"),
        ("fcvt_s_l", "R", "1101000 00010 ..... ... ..... 1010011", "fcvt.s.l {rd}, {rs1}", "fpu"),
        ("fcvt_s_lu", "R", "1101000 00011 ..... ... ..... 1010011", "fcvt.s.lu {rd}, {rs1}", "fpu"),
        ("fmv_w_x", "R", "1111000 00000 ..... 000 ..... 1010011", "fmv.w.x {rd}, {rs1}", "fpu"),
        // D（倍精度浮動小数点。fmt=01）
        ("fld", "I", "............ ..... 011 ..... 0000111", "fld {rd}, {imm}({rs1})", "load"),
        ("fsd", "S", "....... ..... ..... 011 ..... 0100111", "fsd {rs2}, {imm}({rs1})", "store"),
        ("fadd_d", "R", "0000001 ..... ..... ... ..... 1010011", "fadd.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fsub_d", "R", "0000101 ..... ..... ... ..... 1010011", "fsub.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fmul_d", "R", "0001001 ..... ..... ... ..... 1010011", "fmul.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fdiv_d", "R", "0001101 ..... ..... ... ..... 1010011", "fdiv.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fsqrt_d", "R", "0101101 00000 ..... ... ..... 1010011", "fsqrt.d {rd}, {rs1}", "fpu"),
        ("fsgnj_d", "R", "0010001 ..... ..... 000 ..... 1010011", "fsgnj.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fsgnjn_d", "R", "0010001 ..... ..... 001 ..... 1010011", "fsgnjn.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fsgnjx_d", "R", "0010001 ..... ..... 010 ..... 1010011", "fsgnjx.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fmin_d", "R", "0010101 ..... ..... 000 ..... 1010011", "fmin.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fmax_d", "R", "0010101 ..... ..... 001 ..... 1010011", "fmax.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fcvt_w_d", "R", "1100001 00000 ..... ... ..... 1010011", "fcvt.w.d {rd}, {rs1}", "fpu"),
        ("fcvt_wu_d", "R", "1100001 00001 ..... ... ..... 1010011", "fcvt.wu.d {rd}, {rs1}", "fpu"),
        ("fcvt_l_d", "R", "1100001 00010 ..... ... ..... 1010011", "fcvt.l.d {rd}, {rs1}", "fpu"),
        ("fcvt_lu_d", "R", "1100001 00011 ..... ... ..... 1010011", "fcvt.lu.d {rd}, {rs1}", "fpu"),
        ("fmv_x_d", "R", "1110001 00000 ..... 000 ..... 1010011", "fmv.x.d {rd}, {rs1}", "fpu"),
        ("fclass_d", "R", "1110001 00000 ..... 001 ..... 1010011", "fclass.d {rd}, {rs1}", "fpu"),
        ("feq_d", "R", "1010001 ..... ..... 010 ..... 1010011", "feq.d {rd}, {rs1}, {rs2}", "fpu"),
        ("flt_d", "R", "1010001 ..... ..... 001 ..... 1010011", "flt.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fle_d", "R", "1010001 ..... ..... 000 ..... 1010011", "fle.d {rd}, {rs1}, {rs2}", "fpu"),
        ("fcvt_d_w", "R", "1101001 00000 ..... ... ..... 1010011", "fcvt.d.w {rd}, {rs1}", "fpu"),
        ("fcvt_d_wu", "R", "1101001 00001 ..... ... ..... 1010011", "fcvt.d.wu {rd}, {rs1}", "fpu"),
        ("fcvt_d_l", "R", "1101001 00010 ..... ... ..... 1010011", "fcvt.d.l {rd}, {rs1}", "fpu"),
        ("fcvt_d_lu", "R", "1101001 00011 ..... ... ..... 1010011", "fcvt.d.lu {rd}, {rs1}", "fpu"),
        ("fmv_d_x", "R", "1111001 00000 ..... 000 ..... 1010011", "fmv.d.x {rd}, {rs1}", "fpu"),
        ("fcvt_s_d", "R", "0100000 00001 ..... ... ..... 1010011", "fcvt.s.d {rd}, {rs1}", "fpu"),
        ("fcvt_d_s", "R", "0100001 00000 ..... ... ..... 1010011", "fcvt.d.s {rd}, {rs1}", "fpu"),
        // C（圧縮。16ビット。funct3とop下位2ビットで区別できる衝突なし subset）
        // Ref: SPEC-RISCV-UNPRIV (20250508) §C.
        ("c_addi4spn", "R", "000 ........ ... 00", "c.addi4spn {rd}, {imm}", "alu"),
        ("c_fld", "R", "001 ........ ... 00", "c.fld {rd}, {imm}({rs1})", "load"),
        ("c_fsd", "R", "101 ........ ... 00", "c.fsd {rs2}, {imm}({rs1})", "store"),
        ("c_lw", "R", "010 ........ ... 00", "c.lw {rd}, {imm}({rs1})", "load"),
        ("c_ld", "R", "011 ........ ... 00", "c.ld {rd}, {imm}({rs1})", "load"),
        ("c_sw", "R", "110 ........ ... 00", "c.sw {rs2}, {imm}({rs1})", "store"),
        ("c_sd", "R", "111 ........ ... 00", "c.sd {rs2}, {imm}({rs1})", "store"),
        ("c_addi", "R", "000 ........ ... 01", "c.addi {rd}, {imm}", "alu"),
        ("c_addiw", "R", "001 ........ ... 01", "c.addiw {rd}, {imm}", "alu"),
        ("c_li", "R", "010 ........ ... 01", "c.li {rd}, {imm}", "alu"),
        ("c_j", "R", "101 ........ ... 01", "c.j {imm}", "jump"),
        ("c_beqz", "R", "110 ........ ... 01", "c.beqz {rs1}, {imm}", "branch"),
        ("c_bnez", "R", "111 ........ ... 01", "c.bnez {rs1}, {imm}", "branch"),
        ("c_slli", "R", "000 ........ ... 10", "c.slli {rd}, {imm}", "alu"),
        ("c_lwsp", "R", "010 ........ ... 10", "c.lwsp {rd}, {imm}", "load"),
        ("c_ldsp", "R", "011 ........ ... 10", "c.ldsp {rd}, {imm}", "load"),
        ("c_fldsp", "R", "001 ........ ... 10", "c.fldsp {rd}, {imm}", "load"),
        ("c_fsdsp", "R", "101 ........ ... 10", "c.fsdsp {rs2}, {imm}", "store"),
        ("c_swsp", "R", "110 ........ ... 10", "c.swsp {rs2}, {imm}", "store"),
        ("c_sdsp", "R", "111 ........ ... 10", "c.sdsp {rs2}, {imm}", "store"),
    ];
    for (name, format, pattern, syntax, timing) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            syntax: syntax.to_string(),
            timing: timing.to_string(),
        });
    }
    // RV64限定命令にrv64注記を付ける。デコーダは現段階ではwhenを評価しない
    // （解決はデコード時という設計の将来対応）。検証の一意性には影響しない。
    // Ref: SPEC-RISCV-UNPRIV (20250508).
    for insn in m.insns.iter_mut() {
        let rv64_only = matches!(
            insn.name.as_str(),
            "ld" | "lwu"
                | "sd" | "addiw"
                | "slliw" | "srliw"
                | "sraiw" | "addw"
                | "subw" | "sllw"
                | "srlw" | "sraw"
                | "mulw" | "divw"
                | "divuw" | "remw"
                | "remuw" | "lr_d"
                | "sc_d" | "amoswap_d"
                | "amoadd_d" | "amoxor_d"
                | "amoand_d" | "amoor_d"
                | "amomin_d" | "amomax_d"
                | "amominu_d" | "amomaxu_d"
                | "c_ld" | "c_sd"
                | "c_addiw" | "c_ldsp"
                | "c_sdsp"
        );
        if rv64_only {
            insn.when = Pred::Flag("rv64".to_string());
        }
    }
    m
}
