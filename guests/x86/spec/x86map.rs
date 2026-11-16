// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// x86 のオペコード表記述（段階13）。
//
// `x86min.rs` の変形ごとの列挙に代わり、SDM のオペコード表の構成に沿って
// `map` で記述する（ADR-0018 の見直し条件）。ModRM/SIB・変位・即値の
// 消費は生成された `decode_map` が担い、実効アドレスの計算は
// `src/decode.rs` の EA フックが担う。
// 出典は SPEC-X86-INTEL-SDM Combined v093 (2026-09-24) である。
// Ref: SPEC-X86-INTEL-SDM (v093).

use polyisa_isadl::model::*;
use polyisa_isadl::pred::Pred;

/// 命令項目の省略形。`group` は ModRM.reg の選択（/0 から /7）、
/// `pfx` は必須接頭辞の状態、`when` は機能・実行モードの述語。
fn mi(
    name: &str,
    ops: &[OpKind],
    group: Option<u8>,
    pfx: PfxSel,
    when: Pred,
    syntax: &str,
    timing: &str,
) -> MapInsn {
    MapInsn {
        name: name.to_string(),
        ops: ops.to_vec(),
        group,
        pfx,
        when,
        syntax: syntax.to_string(),
        timing: timing.to_string(),
    }
}

/// グループでも必須接頭辞でもない、無条件の命令項目。
fn n(name: &str, ops: &[OpKind], syntax: &str, timing: &str) -> MapInsn {
    mi(name, ops, None, PfxSel::Any, Pred::True, syntax, timing)
}

/// グループ選択の命令項目。
fn g(name: &str, group: u8, ops: &[OpKind], syntax: &str, timing: &str) -> MapInsn {
    mi(name, ops, Some(group), PfxSel::Any, Pred::True, syntax, timing)
}

/// 実行モードの述語を作る。
fn w(s: &str) -> Pred {
    polyisa_isadl::pred::parse(s).expect("valid when")
}

/// `map` の記述をモデルに足す。
pub fn build_maps(m: &mut Model) {
    // 実行モード。`m64` は 64 ビットモード、`opd` は既定のオペランド
    // サイズ（CS.D）、`adr` は既定のアドレスサイズを表す。生成される
    // デコーダが有効サイズの計算に使う。
    m.modes.push(Mode {
        name: "m64".to_string(),
        ty: ModeType::Bool,
    });
    m.modes.push(Mode {
        name: "opd".to_string(),
        ty: ModeType::Enum(vec!["o16".to_string(), "o32".to_string()]),
    });
    m.modes.push(Mode {
        name: "adr".to_string(),
        ty: ModeType::Enum(vec!["a16".to_string(), "a32".to_string(), "a64".to_string()]),
    });

    use OpKind::*;
    use OpWidth::*;

    // 8 つの ALU 演算の項目を並べる補助。op は基本オペコード。
    fn alu_family(
        items: &mut Vec<MapItem>,
        op: u8,
        name: &str,
        timing: &str,
    ) {
        let forms: [(u8, &[OpKind], &str); 6] = [
            (op, &[Ea(B8), Reg(B8)], "{0} {e}, {g}"),
            (op + 1, &[Ea(V), Reg(V)], "{0} {e}, {g}"),
            (op + 2, &[Reg(B8), Ea(B8)], "{0} {g}, {e}"),
            (op + 3, &[Reg(V), Ea(V)], "{0} {g}, {e}"),
            (op + 4, &[Imp(ImpOp::Eax), Imm(B8)], "{0} al, {i}"),
            (op + 5, &[Imp(ImpOp::Eax), Imm(Z)], "{0} eax, {i}"),
        ];
        let suffixes = ["eb_gb", "ev_gv", "gb_eb", "gv_ev", "al_ib", "eax_iz"];
        for (k, (byte, ops, syntax)) in forms.iter().enumerate() {
            items.push(MapItem::Insn(
                *byte,
                n(&format!("{name}_{}", suffixes[k]), ops, syntax, timing),
            ));
        }
    }

    let mut primary: Vec<MapItem> = Vec::new();

    // ALU 系（00-05, 08-0D, 10-15, 18-1D, 20-25, 28-2D, 30-35, 38-3D）。
    for (k, name) in [
        "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp",
    ]
    .iter()
    .enumerate()
    {
        alu_family(&mut primary, (k * 8) as u8, name, "alu");
    }

    // 0x63: ARPL（非64）と MOVSXD（64）。
    primary.push(MapItem::Insn(
        0x63,
        mi(
            "arpl_ew_gw",
            &[Ea(W16), Reg(W16)],
            None,
            PfxSel::Any,
            w("!m64"),
            "arpl {e}, {g}",
            "alu",
        ),
    ));
    primary.push(MapItem::Insn(
        0x63,
        mi(
            "movsxd_gv_ed",
            &[Reg(V), Ea(D32)],
            None,
            PfxSel::Any,
            w("m64"),
            "movsxd {g}, {e}",
            "alu",
        ),
    ));

    // PUSH/POP と即値 PUSH。
    primary.push(MapItem::Insn(0x68, n("push_iz", &[Imm(Z)], "push {i}", "store")));
    primary.push(MapItem::Insn(0x6A, n("push_ib", &[Imm(B8)], "push {i}", "store")));
    // IMUL 3 オペランド形。
    primary.push(MapItem::Insn(
        0x69,
        n("imul_gv_ev_iz", &[Reg(V), Ea(V), Imm(Z)], "imul {g}, {e}, {i}", "mult"),
    ));
    primary.push(MapItem::Insn(
        0x6B,
        n("imul_gv_ev_ib", &[Reg(V), Ea(V), Imm(B8)], "imul {g}, {e}, {i}", "mult"),
    ));

    // Jcc rel8（70-7F）。
    let cc8 = [
        "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl",
        "jge", "jle", "jg",
    ];
    for (k, cc) in cc8.iter().enumerate() {
        primary.push(MapItem::Insn(
            0x70 + k as u8,
            n(&format!("{cc}_jb"), &[Rel(B8)], "jcc {r}", "jump"),
        ));
    }

    // グループ 1（80/81/83）。
    let grp1 = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
    for (byte, wdt, imm) in [(0x80u8, B8, B8), (0x81, V, Z), (0x83, V, B8)] {
        for (gi, name) in grp1.iter().enumerate() {
            let suf = match (wdt, imm) {
                (OpWidth::B8, _) => "eb_ib",
                (_, OpWidth::Z) => "ev_iz",
                _ => "ev_ib",
            };
            primary.push(MapItem::Insn(
                byte,
                g(
                    &format!("{name}_{suf}"),
                    gi as u8,
                    &[Ea(wdt), Imm(imm)],
                    "{0} {e}, {i}",
                    "alu",
                ),
            ));
        }
    }

    // MOV 系。
    primary.extend([
        MapItem::Insn(0x84, n("test_eb_gb", &[Ea(B8), Reg(B8)], "test {e}, {g}", "alu")),
        MapItem::Insn(0x85, n("test_ev_gv", &[Ea(V), Reg(V)], "test {e}, {g}", "alu")),
        MapItem::Insn(0x86, n("xchg_eb_gb", &[Ea(B8), Reg(B8)], "xchg {e}, {g}", "alu")),
        MapItem::Insn(0x87, n("xchg_ev_gv", &[Ea(V), Reg(V)], "xchg {e}, {g}", "alu")),
        MapItem::Insn(0x88, n("mov_eb_gb", &[Ea(B8), Reg(B8)], "mov {e}, {g}", "load")),
        MapItem::Insn(0x89, n("mov_ev_gv", &[Ea(V), Reg(V)], "mov {e}, {g}", "load")),
        MapItem::Insn(0x8A, n("mov_gb_eb", &[Reg(B8), Ea(B8)], "mov {g}, {e}", "load")),
        MapItem::Insn(0x8B, n("mov_gv_ev", &[Reg(V), Ea(V)], "mov {g}, {e}", "load")),
        MapItem::Insn(0x8C, n("mov_ew_sr", &[Ea(W16), RegS], "mov {e}, sreg", "load")),
        MapItem::Insn(0x8D, n("lea_gv_m", &[Reg(V), Ea(V)], "lea {g}, {e}", "alu")),
        MapItem::Insn(0x8E, n("mov_sr_ew", &[RegS, Ea(W16)], "mov sreg, {e}", "load")),
        MapItem::Insn(
            0x8F,
            g("pop_ev", 0, &[Ea(V)], "pop {e}", "load"),
        ),
    ]);

    // 50-5F: PUSH/POP r。64ビットモードでの既定幅は 64（接頭辞 66 で 16）。
    for k in 0..8u8 {
        primary.push(MapItem::Insn(0x50 + k, n("push_rv", &[InOp(V)], "push {r}", "store")));
        primary.push(MapItem::Insn(0x58 + k, n("pop_rv", &[InOp(V)], "pop {r}", "load")));
    }

    // 90-97: XCHG eAX,r。90 は REX.B なしで NOP 相当（dispatch が処理する）。
    for k in 0..8u8 {
        primary.push(MapItem::Insn(
            0x90 + k,
            n(
                "xchg_rv_eax",
                &[InOp(V), Imp(ImpOp::Eax)],
                "xchg {r}, eax",
                "alu",
            ),
        ));
    }
    primary.push(MapItem::Insn(0x98, n("cwde", &[], "cbw/cwde/cdqe", "alu")));
    primary.push(MapItem::Insn(0x99, n("cdq", &[], "cwd/cdq/cqo", "alu")));
    primary.push(MapItem::Insn(0x9C, n("pushf", &[], "pushf", "store")));
    primary.push(MapItem::Insn(0x9D, n("popf", &[], "popf", "load")));
    primary.push(MapItem::Insn(0x9E, n("sahf", &[], "sahf", "alu")));
    primary.push(MapItem::Insn(0x9F, n("lahf", &[], "lahf", "alu")));

    // moffs と string 命令。
    primary.extend([
        MapItem::Insn(0xA0, n("mov_al_ob", &[Imp(ImpOp::Eax), Moffs(B8)], "mov al, [{m}]", "load")),
        MapItem::Insn(0xA1, n("mov_eax_ov", &[Imp(ImpOp::Eax), Moffs(V)], "mov eax, [{m}]", "load")),
        MapItem::Insn(0xA2, n("mov_ob_al", &[Moffs(B8), Imp(ImpOp::Eax)], "mov [{m}], al", "store")),
        MapItem::Insn(0xA3, n("mov_ov_eax", &[Moffs(V), Imp(ImpOp::Eax)], "mov [{m}], eax", "store")),
        MapItem::Insn(0xA4, n("movs_b", &[Imp(ImpOp::Ydst), Imp(ImpOp::Xsrc)], "movsb", "load")),
        MapItem::Insn(0xA5, n("movs_v", &[Imp(ImpOp::Ydst), Imp(ImpOp::Xsrc)], "movs", "load")),
        MapItem::Insn(0xA6, n("cmps_b", &[Imp(ImpOp::Xsrc), Imp(ImpOp::Ydst)], "cmpsb", "alu")),
        MapItem::Insn(0xA7, n("cmps_v", &[Imp(ImpOp::Xsrc), Imp(ImpOp::Ydst)], "cmps", "alu")),
        MapItem::Insn(0xA8, n("test_al_ib", &[Imp(ImpOp::Eax), Imm(B8)], "test al, {i}", "alu")),
        MapItem::Insn(0xA9, n("test_eax_iz", &[Imp(ImpOp::Eax), Imm(Z)], "test eax, {i}", "alu")),
        MapItem::Insn(0xAA, n("stos_b", &[Imp(ImpOp::Ydst)], "stosb", "store")),
        MapItem::Insn(0xAB, n("stos_v", &[Imp(ImpOp::Ydst)], "stos", "store")),
        MapItem::Insn(0xAC, n("lods_b", &[Imp(ImpOp::Xsrc)], "lodsb", "load")),
        MapItem::Insn(0xAD, n("lods_v", &[Imp(ImpOp::Xsrc)], "lods", "load")),
        MapItem::Insn(0xAE, n("scas_b", &[Imp(ImpOp::Ydst)], "scasb", "alu")),
        MapItem::Insn(0xAF, n("scas_v", &[Imp(ImpOp::Ydst)], "scas", "alu")),
    ]);

    // MOV +r 即値。B0-B7 は imm8、B8-BF は osize 幅（64 では imm64、MOVABS）。
    for k in 0..8u8 {
        primary.push(MapItem::Insn(
            0xB0 + k,
            n("mov_rb_ib", &[InOp(B8), Imm(B8)], "mov {r}, {i}", "load"),
        ));
        primary.push(MapItem::Insn(
            0xB8 + k,
            n("mov_rv_iv", &[InOp(V), Imm(V)], "mov {r}, {i}", "load"),
        ));
    }

    // グループ 2（シフト・ローテート）。
    let grp2 = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"];
    for (byte, cnt) in [
        (0xC0u8, Imm(B8)),
        (0xC1, Imm(B8)),
        (0xD0, Imp(ImpOp::One)),
        (0xD1, Imp(ImpOp::One)),
        (0xD2, Imp(ImpOp::Cl)),
        (0xD3, Imp(ImpOp::Cl)),
    ] {
        let wdt = if byte & 1 == 0 { B8 } else { V };
        for (gi, name) in grp2.iter().enumerate() {
            let suf = match (wdt, cnt) {
                (OpWidth::B8, OpKind::Imm(_)) => "eb_ib",
                (_, OpKind::Imm(_)) => "ev_ib",
                (OpWidth::B8, OpKind::Imp(ImpOp::One)) => "eb_1",
                (_, OpKind::Imp(ImpOp::One)) => "ev_1",
                (OpWidth::B8, _) => "eb_cl",
                _ => "ev_cl",
            };
            primary.push(MapItem::Insn(
                byte,
                g(
                    &format!("{name}_{suf}"),
                    gi as u8,
                    &[Ea(wdt), cnt],
                    "{0} {e}, {c}",
                    "alu",
                ),
            ));
        }
    }

    primary.extend([
        MapItem::Insn(0xC2, n("ret_iw", &[Imm(W16)], "ret {i}", "jump")),
        MapItem::Insn(0xC3, n("ret", &[], "ret", "jump")),
        MapItem::Insn(
            0xC6,
            g("mov_eb_ib", 0, &[Ea(B8), Imm(B8)], "mov {e}, {i}", "store"),
        ),
        MapItem::Insn(
            0xC7,
            g("mov_ev_iz", 0, &[Ea(V), Imm(Z)], "mov {e}, {i}", "store"),
        ),
        MapItem::Insn(
            0xC8,
            n("enter_iw_ib", &[Imm(W16), Imm2(B8)], "enter {i}, {j}", "store"),
        ),
        MapItem::Insn(0xC9, n("leave", &[], "leave", "alu")),
        MapItem::Insn(0xCC, n("int3", &[], "int3", "system")),
        MapItem::Insn(0xCD, n("int_ib", &[Imm(B8)], "int {i}", "system")),
        MapItem::Insn(0xD7, n("xlat", &[], "xlat", "load")),
    ]);

    // LOOP 系。
    for (byte, name) in [
        (0xE0u8, "loopne_jb"),
        (0xE1, "loope_jb"),
        (0xE2, "loop_jb"),
        (0xE3, "jcxz_jb"),
    ] {
        primary.push(MapItem::Insn(
            byte,
            n(name, &[Rel(B8)], "loop {r}", "jump"),
        ));
    }
    primary.extend([
        MapItem::Insn(0xE8, n("call_jz", &[Rel(Z)], "call {r}", "jump")),
        MapItem::Insn(0xE9, n("jmp_jz", &[Rel(Z)], "jmp {r}", "jump")),
        MapItem::Insn(0xEB, n("jmp_jb", &[Rel(B8)], "jmp {r}", "jump")),
    ]);

    // フラグ操作と HLT。
    primary.extend([
        MapItem::Insn(0xF4, n("hlt", &[], "hlt", "system")),
        MapItem::Insn(0xF5, n("cmc", &[], "cmc", "alu")),
        MapItem::Insn(0xF8, n("clc", &[], "clc", "alu")),
        MapItem::Insn(0xF9, n("stc", &[], "stc", "alu")),
        MapItem::Insn(0xFC, n("cld", &[], "cld", "alu")),
        MapItem::Insn(0xFD, n("std", &[], "std", "alu")),
    ]);

    // グループ 3（F6/F7）とグループ 4/5（FE/FF）。
    let grp3 = [
        ("test", "test {e}, {i}"),
        ("test", "test {e}, {i}"),
        ("not", "not {e}"),
        ("neg", "neg {e}"),
        ("mul", "mul {e}"),
        ("imul", "imul {e}"),
        ("div", "div {e}"),
        ("idiv", "idiv {e}"),
    ];
    for (byte, wdt, timing) in [(0xF6u8, B8, "mult"), (0xF7, V, "mult")] {
        for (gi, (name, syntax)) in grp3.iter().enumerate() {
            let ops: Vec<OpKind> = if gi < 2 {
                let iw = if matches!(wdt, OpWidth::B8) {
                    B8
                } else {
                    Z
                };
                vec![Ea(wdt), Imm(iw)]
            } else {
                vec![Ea(wdt)]
            };
            let suf = if matches!(wdt, OpWidth::B8) { "eb" } else { "ev" };
            let suf = if gi < 2 {
                format!("{name}_{suf}_i")
            } else {
                format!("{name}_{suf}")
            };
            primary.push(MapItem::Insn(
                byte,
                g(&suf, gi as u8, &ops, syntax, timing),
            ));
        }
    }
    primary.extend([
        MapItem::Insn(0xFE, g("inc_eb", 0, &[Ea(B8)], "inc {e}", "alu")),
        MapItem::Insn(0xFE, g("dec_eb", 1, &[Ea(B8)], "dec {e}", "alu")),
        MapItem::Insn(0xFF, g("inc_ev", 0, &[Ea(V)], "inc {e}", "alu")),
        MapItem::Insn(0xFF, g("dec_ev", 1, &[Ea(V)], "dec {e}", "alu")),
        MapItem::Insn(0xFF, g("call_ev", 2, &[Ea(V)], "call {e}", "jump")),
        MapItem::Insn(0xFF, g("jmp_ev", 4, &[Ea(V)], "jmp {e}", "jump")),
        MapItem::Insn(0xFF, g("push_ev", 6, &[Ea(V)], "push {e}", "store")),
    ]);

    // 0F への分岐。
    primary.push(MapItem::Map(0x0F, "map_0f".to_string()));

    m.maps.push(MapDecl {
        name: "primary".to_string(),
        items: primary,
    });

    // 0F マップ。
    let mut m0f: Vec<MapItem> = Vec::new();
    m0f.extend([
        MapItem::Insn(0x05, n("syscall", &[], "syscall", "system")),
        MapItem::Insn(0x0B, n("ud2", &[], "ud2", "system")),
        MapItem::Insn(
            0x1E,
            mi(
                "endbr",
                &[Ea(V)],
                None,
                PfxSel::PF3,
                Pred::True,
                "endbr",
                "alu",
            ),
        ),
        MapItem::Insn(
            0x1F,
            g("nop_ev", 0, &[Ea(V)], "nop {e}", "alu"),
        ),
        MapItem::Insn(0x31, n("rdtsc", &[], "rdtsc", "system")),
        MapItem::Insn(0x34, n("sysenter", &[], "sysenter", "system")),
        MapItem::Insn(0x35, n("sysexit", &[], "sysexit", "system")),
        MapItem::Insn(0xA2, n("cpuid", &[], "cpuid", "system")),
        MapItem::Insn(0xAF, n("imul_gv_ev", &[Reg(V), Ea(V)], "imul {g}, {e}", "mult")),
        MapItem::Insn(0xB6, n("movzx_gv_eb", &[Reg(V), Ea(B8)], "movzx {g}, {e}", "load")),
        MapItem::Insn(0xB7, n("movzx_gv_ew", &[Reg(V), Ea(W16)], "movzx {g}, {e}", "load")),
        MapItem::Insn(0xBE, n("movsx_gv_eb", &[Reg(V), Ea(B8)], "movsx {g}, {e}", "load")),
        MapItem::Insn(0xBF, n("movsx_gv_ew", &[Reg(V), Ea(W16)], "movsx {g}, {e}", "load")),
    ]);
    // CMOVcc（0F 40-4F）、Jcc near（0F 80-8F）、SETcc（0F 90-9F）。
    for (k, cc) in cc8.iter().enumerate() {
        m0f.push(MapItem::Insn(
            0x40 + k as u8,
            n(&format!("cmov{cc}_gv_ev"), &[Reg(V), Ea(V)], "cmovcc {g}, {e}", "alu"),
        ));
        m0f.push(MapItem::Insn(
            0x80 + k as u8,
            n(&format!("{cc}_jz"), &[Rel(Z)], "jcc {r}", "jump"),
        ));
        m0f.push(MapItem::Insn(
            0x90 + k as u8,
            n(&format!("set{cc}_eb"), &[Ea(B8)], "setcc {e}", "alu"),
        ));
    }
    // BSWAP は 0F C8-CF の 8 個のみ。
    for k in 0..8u8 {
        m0f.push(MapItem::Insn(
            0xC8 + k,
            n("bswap_rv", &[InOp(V)], "bswap {r}", "alu"),
        ));
    }
    // PUSH/POP FS・GS。
    m0f.extend([
        MapItem::Insn(0xA0, n("push_fs", &[], "push fs", "store")),
        MapItem::Insn(0xA1, n("pop_fs", &[], "pop fs", "load")),
        MapItem::Insn(0xA8, n("push_gs", &[], "push gs", "store")),
        MapItem::Insn(0xA9, n("pop_gs", &[], "pop gs", "load")),
    ]);
    // BT 系（0F A3, AB, B3, BB / 0F BA 群）。
    m0f.extend([
        MapItem::Insn(0xA3, n("bt_ev_gv", &[Ea(V), Reg(V)], "bt {e}, {g}", "alu")),
        MapItem::Insn(0xAB, n("bts_ev_gv", &[Ea(V), Reg(V)], "bts {e}, {g}", "alu")),
        MapItem::Insn(0xB3, n("btr_ev_gv", &[Ea(V), Reg(V)], "btr {e}, {g}", "alu")),
        MapItem::Insn(0xBB, n("btc_ev_gv", &[Ea(V), Reg(V)], "btc {e}, {g}", "alu")),
        MapItem::Insn(0xBA, g("bt_ev_ib", 4, &[Ea(V), Imm(B8)], "bt {e}, {i}", "alu")),
        MapItem::Insn(0xBA, g("bts_ev_ib", 5, &[Ea(V), Imm(B8)], "bts {e}, {i}", "alu")),
        MapItem::Insn(0xBA, g("btr_ev_ib", 6, &[Ea(V), Imm(B8)], "btr {e}, {i}", "alu")),
        MapItem::Insn(0xBA, g("btc_ev_ib", 7, &[Ea(V), Imm(B8)], "btc {e}, {i}", "alu")),
        // SHLD/SHRD。
        MapItem::Insn(0xA4, n("shld_ev_gv_ib", &[Ea(V), Reg(V), Imm(B8)], "shld {e}, {g}, {i}", "alu")),
        MapItem::Insn(0xA5, n("shld_ev_gv_cl", &[Ea(V), Reg(V), Imp(ImpOp::Cl)], "shld {e}, {g}, cl", "alu")),
        MapItem::Insn(0xAC, n("shrd_ev_gv_ib", &[Ea(V), Reg(V), Imm(B8)], "shrd {e}, {g}, {i}", "alu")),
        MapItem::Insn(0xAD, n("shrd_ev_gv_cl", &[Ea(V), Reg(V), Imp(ImpOp::Cl)], "shrd {e}, {g}, cl", "alu")),
    ]);
    m.maps.push(MapDecl {
        name: "map_0f".to_string(),
        items: m0f,
    });
}
