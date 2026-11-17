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
        group_mod: None,
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

/// グループ選択に mod 制約を付けた命令項目。`reg_form` が真なら
/// mod=11（レジスタ形）のみ、偽なら mod!=11（メモリ形）のみに解読する。
fn gm(name: &str, group: u8, reg_form: bool, ops: &[OpKind], syntax: &str, timing: &str) -> MapInsn {
    let mut it = g(name, group, ops, syntax, timing);
    it.group_mod = Some(reg_form);
    it
}

/// グループ選択・必須接頭辞・mod 制約を持つ命令項目。
fn gmp(
    name: &str,
    group: u8,
    reg_form: bool,
    ops: &[OpKind],
    pfx: PfxSel,
    syntax: &str,
    timing: &str,
) -> MapInsn {
    let mut it = mi(name, ops, Some(group), pfx, Pred::True, syntax, timing);
    it.group_mod = Some(reg_form);
    it
}

/// mod=11（レジスタ形）のみに解読する。
fn mreg(it: MapInsn) -> MapInsn {
    let mut it = it;
    it.group_mod = Some(true);
    it
}

/// mod!=11（メモリ形）のみに解読する。
fn mmem(it: MapInsn) -> MapInsn {
    let mut it = it;
    it.group_mod = Some(false);
    it
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

    // セグメントの push/pop（06/07/0E/16/17/1E/1F）。64 ビットモードでは
    // 無効（0x06 等は別の命令になる）なので非64 のみ。
    for (op, sreg, what) in [
        (0x06u8, "es", "push"),
        (0x07, "es", "pop"),
        (0x0E, "cs", "push"),
        (0x16, "ss", "push"),
        (0x17, "ss", "pop"),
        (0x1E, "ds", "push"),
        (0x1F, "ds", "pop"),
    ] {
        primary.push(MapItem::Insn(
            op,
            mi(
                &format!("{what}_{sreg}"),
                &[],
                None,
                PfxSel::Any,
                w("!m64"),
                &format!("{what} {sreg}"),
                if what == "push" { "store" } else { "load" },
            ),
        ));
    }

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
            w("i286 && !m64"),
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

    // PUSH/POP と即値 PUSH（80186 以降）。
    primary.push(MapItem::Insn(
        0x68,
        mi("push_iz", &[Imm(Z)], None, PfxSel::Any, w("i186"), "push {i}", "store"),
    ));
    primary.push(MapItem::Insn(
        0x6A,
        mi("push_ib", &[Imm(B8)], None, PfxSel::Any, w("i186"), "push {i}", "store"),
    ));
    // IMUL 3 オペランド形。
    primary.push(MapItem::Insn(
        0x69,
        mi(
            "imul_gv_ev_iz",
            &[Reg(V), Ea(V), Imm(Z)],
            None,
            PfxSel::Any,
            w("i186"),
            "imul {g}, {e}, {i}",
            "mult",
        ),
    ));
    primary.push(MapItem::Insn(
        0x6B,
        mi(
            "imul_gv_ev_ib",
            &[Reg(V), Ea(V), Imm(B8)],
            None,
            PfxSel::Any,
            w("i186"),
            "imul {g}, {e}, {i}",
            "mult",
        ),
    ));
    // BOUND（62、mod=11 は #UD）と INS/OUTS（6C-6F）。
    primary.push(MapItem::Insn(
        0x62,
        mmem(mi(
            "bound_gv_mp",
            &[Reg(V), Ea(V)],
            None,
            PfxSel::Any,
            w("i186 && !m64"),
            "bound {g}, {e}",
            "system",
        )),
    ));
    primary.extend([
        MapItem::Insn(
            0x6C,
            mi("ins_eb_dx", &[], None, PfxSel::Any, w("i186"), "insb", "system"),
        ),
        MapItem::Insn(
            0x6D,
            mi("ins_ev_dx", &[], None, PfxSel::Any, w("i186"), "ins {a}", "system"),
        ),
        MapItem::Insn(
            0x6E,
            mi("outs_dx_eb", &[], None, PfxSel::Any, w("i186"), "outsb", "system"),
        ),
        MapItem::Insn(
            0x6F,
            mi("outs_dx_ev", &[], None, PfxSel::Any, w("i186"), "outs {a}", "system"),
        ),
    ]);

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

    // 0x82 は 0x80 のエイリアス（386EX までの実モード世代で実行。
    // SST 80386 実測）。
    for (gi, name) in grp1.iter().enumerate() {
        primary.push(MapItem::Insn(
            0x82,
            mi(
                &format!("{name}_eb_ib"),
                &[Ea(B8), Imm(B8)],
                Some(gi as u8),
                PfxSel::Any,
                w("op82"),
                "{0} {e}, {i}",
                "alu",
            ),
        ));
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
        // MOV sreg は /0-/5 のみ有効（/6,/7 は #UD）。LEA は
        // メモリ形のみ。
        MapItem::Insn(0x8D, mmem(n("lea_gv_m", &[Reg(V), Ea(V)], "lea {g}, {e}", "alu"))),
        // POP r/m。メモリ形・レジスタ形とも全世代で実行される
        // （80286 の mod=11 も #UD ではない。SST 80286 実測）。
        MapItem::Insn(0x8F, gm("pop_ev", 0, false, &[Ea(V)], "pop {e}", "load")),
        MapItem::Insn(
            0x8F,
            mreg(mi("pop_ev", &[Ea(V)], Some(0), PfxSel::Any, Pred::True, "pop {e}", "load")),
        ),
    ]);
    // MOV sreg。近世 x86 で /0-/5 のみ有効だが、MOV sreg,rm への
    // CS 書き込み（8E /1）は 80286 以降 #UD、FS/GS（/4,/5）は
    // 80386 以降の機能。16 ビットモードの 8086/80186 では reg>=4
    // （/4-/7）の上位ビットは無視され sreg & 3 の別名として動くので、
    // その形も受理する（意味論側が &3 で捌く）。
    // `opd_o16 && adr_a16` は 16 ビット実行モードの目印。
    for grp in 0..4u8 {
        primary.push(MapItem::Insn(
            0x8C,
            g("mov_ew_sr", grp, &[Ea(W16), RegS], "mov {e}, sreg", "load"),
        ));
        let gate = if grp == 1 { w("!i286") } else { Pred::True };
        primary.push(MapItem::Insn(
            0x8E,
            mi("mov_sr_ew", &[RegS, Ea(W16)], Some(grp), PfxSel::Any, gate, "mov sreg, {e}", "load"),
        ));
    }
    // /4,/5。386 以降は FS/GS として本物。それ以前の実モードでは
    // sreg & 3 の別名として実行される（意味論側が !i286 のとき &3）。
    // /6,/7 は 286 以降 #UD。8086/80186 では同じく別名。
    for grp in 4..6u8 {
        primary.push(MapItem::Insn(
            0x8C,
            mi("mov_ew_sr", &[Ea(W16), RegS], Some(grp), PfxSel::Any, w("i386 || (opd_o16 && adr_a16 && !i286)"), "mov {e}, sreg", "load"),
        ));
        primary.push(MapItem::Insn(
            0x8E,
            mi("mov_sr_ew", &[RegS, Ea(W16)], Some(grp), PfxSel::Any, w("i386 || (opd_o16 && adr_a16 && !i286)"), "mov sreg, {e}", "load"),
        ));
    }
    for grp in 6..8u8 {
        primary.push(MapItem::Insn(
            0x8C,
            mi("mov_ew_sr", &[Ea(W16), RegS], Some(grp), PfxSel::Any, w("opd_o16 && adr_a16 && !i286"), "mov {e}, sreg", "load"),
        ));
        primary.push(MapItem::Insn(
            0x8E,
            mi("mov_sr_ew", &[RegS, Ea(W16)], Some(grp), PfxSel::Any, w("opd_o16 && adr_a16 && !i286"), "mov sreg, {e}", "load"),
        ));
    }

    // 40-4F: INC/DEC r32。64ビットモードでは REX 接頭辞なので非64のみ。
    for k in 0..8u8 {
        primary.push(MapItem::Insn(
            0x40 + k,
            mi("inc_rv", &[InOp(V)], None, PfxSel::Any, w("!m64"), "inc {r}", "alu"),
        ));
        primary.push(MapItem::Insn(
            0x48 + k,
            mi("dec_rv", &[InOp(V)], None, PfxSel::Any, w("!m64"), "dec {r}", "alu"),
        ));
    }

    // 60/61: PUSHA/POPA（非64ビットモードのみ）。
    primary.extend([
        MapItem::Insn(
            0x60,
            mi("pusha", &[], None, PfxSel::Any, w("i186 && !m64"), "pusha", "store"),
        ),
        MapItem::Insn(
            0x61,
            mi("popa", &[], None, PfxSel::Any, w("i186 && !m64"), "popa", "load"),
        ),
        MapItem::Insn(0x9B, n("fwait", &[], "fwait", "system")),
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
    // LAHF/SAHF は 64 ビットモードでは LAHF-LM（CPUID.8000_0001:ECX.0）
    // を要する。
    primary.push(MapItem::Insn(0x9E, mi("sahf", &[], None, PfxSel::Any, w("!m64 || lahf_lm"), "sahf", "alu")));
    primary.push(MapItem::Insn(0x9F, mi("lahf", &[], None, PfxSel::Any, w("!m64 || lahf_lm"), "lahf", "alu")));

    // BCD 補正と far ポインタロード・SALC。64 ビットモードでは無効。
    for (op, name, syntax) in [
        (0x27u8, "daa", "daa"),
        (0x2F, "das", "das"),
        (0x37, "aaa", "aaa"),
        (0x3F, "aas", "aas"),
        (0xD6, "salc", "salc"),
    ] {
        primary.push(MapItem::Insn(op, mi(name, &[], None, PfxSel::Any, w("!m64"), syntax, "alu")));
    }
    primary.push(MapItem::Insn(
        0xC4,
        mmem(mi("les_gv_mp", &[Reg(V), Ea(V)], None, PfxSel::Any, w("!m64"), "les {g}, {e}", "load")),
    ));
    primary.push(MapItem::Insn(
        0xC5,
        mmem(mi("lds_gv_mp", &[Reg(V), Ea(V)], None, PfxSel::Any, w("!m64"), "lds {g}, {e}", "load")),
    ));
    primary.push(MapItem::Insn(
        0xD4,
        mi("aam_ib", &[Imp(ImpOp::Eax), Imm(B8)], None, PfxSel::Any, w("!m64"), "aam {i}", "alu"),
    ));
    primary.push(MapItem::Insn(
        0xD5,
        mi("aad_ib", &[Imp(ImpOp::Eax), Imm(B8)], None, PfxSel::Any, w("!m64"), "aad {i}", "alu"),
    ));
    primary.push(MapItem::Insn(0xFA, n("cli", &[], "cli", "system")));
    primary.push(MapItem::Insn(0xFB, n("sti", &[], "sti", "system")));

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

    // グループ 2（シフト・ローテート）。即値形（C0/C1）は 80186 以降。
    let grp2 = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"];
    for (byte, cnt) in [
        (0xC0u8, Imm(B8)),
        (0xC1, Imm(B8)),
        (0xD0, Imp(ImpOp::One)),
        (0xD1, Imp(ImpOp::One)),
        (0xD2, Imp(ImpOp::Cl)),
        (0xD3, Imp(ImpOp::Cl)),
    ] {
        let gate = if byte < 0xD0 { w("i186") } else { Pred::True };
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
            let mut it = g(
                &format!("{name}_{suf}"),
                gi as u8,
                &[Ea(wdt), cnt],
                "{0} {e}, {c}",
                "alu",
            );
            it.when = gate.clone();
            primary.push(MapItem::Insn(
                byte,
                it,
            ));
        }
    }

    primary.extend([
        MapItem::Insn(0xC2, n("ret_iw", &[Imm(W16)], "ret {i}", "jump")),
        MapItem::Insn(0xC3, n("ret", &[], "ret", "jump")),
        // far 転移と割り込み系。実モード経路が意味論を持つ。
        MapItem::Insn(
            0x9A,
            mi(
                "callf_ap",
                &[Imm(Z), Imm2(W16)],
                None,
                PfxSel::Any,
                w("!m64"),
                "callf {i}",
                "jump",
            ),
        ),
        MapItem::Insn(
            0xCA,
            mi("retf_iw", &[Imm(W16)], None, PfxSel::Any, w("!m64"), "retf {i}", "jump"),
        ),
        MapItem::Insn(
            0xCB,
            mi("retf", &[], None, PfxSel::Any, w("!m64"), "retf", "jump"),
        ),
        MapItem::Insn(
            0xCE,
            mi("into", &[], None, PfxSel::Any, w("!m64"), "into", "system"),
        ),
        MapItem::Insn(
            0xCF,
            mi("iret", &[], None, PfxSel::Any, w("!m64"), "iret", "jump"),
        ),
        MapItem::Insn(
            0xEA,
            mi(
                "jmpf_ap",
                &[Imm(Z), Imm2(W16)],
                None,
                PfxSel::Any,
                w("!m64"),
                "jmpf {i}",
                "jump",
            ),
        ),
        // C6/C7 は近世 x86 で /0 のみ有効（/1-/7 は #UD）。8088/186
        // では全値が /0 の別名になるので、16 ビットモード限定の
        // グループ項目を後ろで追加する。
        MapItem::Insn(0xC6, g("mov_eb_ib", 0, &[Ea(B8), Imm(B8)], "mov {e}, {i}", "store")),
        MapItem::Insn(0xC7, g("mov_ev_iz", 0, &[Ea(V), Imm(Z)], "mov {e}, {i}", "store")),
        MapItem::Insn(
            0xC8,
            mi(
                "enter_iw_ib",
                &[Imm(W16), Imm2(B8)],
                None,
                PfxSel::Any,
                w("i186"),
                "enter {i}, {j}",
                "store",
            ),
        ),
        MapItem::Insn(
            0xC9,
            mi("leave", &[], None, PfxSel::Any, w("i186"), "leave", "alu"),
        ),
        MapItem::Insn(0xCC, n("int3", &[], "int3", "system")),
        MapItem::Insn(0xCD, n("int_ib", &[Imm(B8)], "int {i}", "system")),
        MapItem::Insn(0xD7, n("xlat", &[], "xlat", "load")),
    ]);
    // 8088/186 では C6/C7 の /1-/7 は /0 の別名として動く（286 以降は #UD）。
    for grp in 1..8u8 {
        primary.push(MapItem::Insn(
            0xC6,
            mi("mov_eb_ib", &[Ea(B8), Imm(B8)], Some(grp), PfxSel::Any, w("opd_o16 && adr_a16 && !i286"), "mov {e}, {i}", "store"),
        ));
        primary.push(MapItem::Insn(
            0xC7,
            mi("mov_ev_iz", &[Ea(V), Imm(Z)], Some(grp), PfxSel::Any, w("opd_o16 && adr_a16 && !i286"), "mov {e}, {i}", "store"),
        ));
    }

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

    // IN/OUT。ポート番号は imm8 または DX、データはアキュムレータ
    // （AL 固定か osize 幅）。フラグは変わらない。
    primary.extend([
        MapItem::Insn(
            0xE4,
            n(
                "in_al_ib",
                &[Imp(ImpOp::Eax), Imm(B8)],
                "in al, {i}",
                "system",
            ),
        ),
        MapItem::Insn(
            0xE5,
            n(
                "in_ev_ib",
                &[Imp(ImpOp::Eax), Imm(B8)],
                "in {a}, {i}",
                "system",
            ),
        ),
        MapItem::Insn(
            0xE6,
            n(
                "out_ib_al",
                &[Imm(B8), Imp(ImpOp::Eax)],
                "out {i}, al",
                "system",
            ),
        ),
        MapItem::Insn(
            0xE7,
            n(
                "out_ib_ev",
                &[Imm(B8), Imp(ImpOp::Eax)],
                "out {i}, {a}",
                "system",
            ),
        ),
        MapItem::Insn(
            0xEC,
            n(
                "in_al_dx",
                &[Imp(ImpOp::Eax), Imp(ImpOp::Edx)],
                "in al, dx",
                "system",
            ),
        ),
        MapItem::Insn(
            0xED,
            n(
                "in_ev_dx",
                &[Imp(ImpOp::Eax), Imp(ImpOp::Edx)],
                "in {a}, dx",
                "system",
            ),
        ),
        MapItem::Insn(
            0xEE,
            n(
                "out_dx_al",
                &[Imp(ImpOp::Edx), Imp(ImpOp::Eax)],
                "out dx, al",
                "system",
            ),
        ),
        MapItem::Insn(
            0xEF,
            n(
                "out_dx_ev",
                &[Imp(ImpOp::Edx), Imp(ImpOp::Eax)],
                "out dx, {a}",
                "system",
            ),
        ),
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
        MapItem::Insn(0xFF, gm("callf_rm", 3, false, &[Ea(V)], "callf {e}", "jump")),
        MapItem::Insn(0xFF, g("jmp_ev", 4, &[Ea(V)], "jmp {e}", "jump")),
        MapItem::Insn(0xFF, gm("jmpf_rm", 5, false, &[Ea(V)], "jmpf {e}", "jump")),
        MapItem::Insn(0xFF, g("push_ev", 6, &[Ea(V)], "push {e}", "store")),
    ]);

    // x87（D8-DF）。/n はメモリ形の選択で、mod=11 のときは同じ
    // r/m フィールドが ST(i) 系の選択に変わる。どちらの意味を取るかは
    // 意味論側で d.modrm の mod を見て決める（被演算子に Imp(Sti) を
    // 置いてその旨を示す）。メモリの幅も意味論側で決める。
    use OpWidth::{D32 as D, Q64 as Q};
    let mut f = |byte: u8, grp: u8, name: &str, ops: &[OpKind], syn: &str| {
        primary.push(MapItem::Insn(
            byte,
            mi(name, ops, Some(grp), PfxSel::Any, Pred::True, syn, "alu"),
        ));
    };
    // D8: m32 実数演算 + ST(0),ST(i)。
    for (grp, mn) in [
        (0u8, "fadd_m32"),
        (1, "fmul_m32"),
        (2, "fcom_m32"),
        (3, "fcomp_m32"),
        (4, "fsub_m32"),
        (5, "fsubr_m32"),
        (6, "fdiv_m32"),
        (7, "fdivr_m32"),
    ] {
        f(0xD8, grp, mn, &[Ea(D), Imp(ImpOp::Sti)], "x87 {e}|st(i)");
    }
    // D9: 移動と単項。mod=11 側は rm ごとの複合（意味論が rm を見る）。
    f(0xD9, 0, "fld_m32", &[Ea(D), Imp(ImpOp::Sti)], "fld {e}|st(i)");
    f(0xD9, 1, "fxch_sti", &[Imp(ImpOp::Sti)], "fxch st(i)");
    f(0xD9, 2, "fst_m32", &[Ea(D)], "fst {e}");
    f(0xD9, 3, "fstp_m32", &[Ea(D)], "fstp {e}");
    f(0xD9, 4, "x87d9_4", &[Ea(D), Imp(ImpOp::Sti)], "x87 {e}");
    f(0xD9, 5, "fldcw_m16", &[Ea(W16), Imp(ImpOp::Sti)], "fldcw {e}|const");
    f(0xD9, 6, "x87d9_6", &[Ea(D), Imp(ImpOp::Sti)], "x87 {e}");
    f(0xD9, 7, "fnstcw_m16", &[Ea(W16), Imp(ImpOp::Sti)], "fnstcw {e}|x87");
    // DA: m32 整数演算 + FCMOV/FUCOMPP。
    for (grp, mn) in [
        (0u8, "fiadd_m32"),
        (1, "fimul_m32"),
        (2, "ficom_m32"),
        (3, "ficomp_m32"),
        (4, "fisub_m32"),
        (5, "fisubr_m32"),
        (6, "fidiv_m32"),
        (7, "fidivr_m32"),
    ] {
        f(0xDA, grp, mn, &[Ea(D), Imp(ImpOp::Sti)], "x87 {e}|st(i)");
    }
    // DB: 変換 + FCMOVN/FUCOMI/FCOMI/FCLEX/FINIT。
    f(0xDB, 0, "fild_m32", &[Ea(D), Imp(ImpOp::Sti)], "fild {e}|st(i)");
    f(0xDB, 1, "fisttp_m32", &[Ea(D), Imp(ImpOp::Sti)], "fisttp {e}|st(i)");
    f(0xDB, 2, "fist_m32", &[Ea(D), Imp(ImpOp::Sti)], "fist {e}|st(i)");
    f(0xDB, 3, "fistp_m32", &[Ea(D), Imp(ImpOp::Sti)], "fistp {e}|st(i)");
    f(0xDB, 4, "x87db_4", &[Imp(ImpOp::Sti)], "x87");
    f(0xDB, 5, "fld_m80", &[Ea(Q), Imp(ImpOp::Sti)], "fld {e}|fucomi");
    f(0xDB, 6, "fcomi_sti", &[Imp(ImpOp::Sti)], "fcomi st(i)");
    f(0xDB, 7, "fstp_m80", &[Ea(Q)], "fstp {e}");
    // DC: m64 実数演算 + ST(i),ST(0)。
    for (grp, mn) in [
        (0u8, "fadd_m64"),
        (1, "fmul_m64"),
        (2, "fcom_m64"),
        (3, "fcomp_m64"),
        (4, "fsub_m64"),
        (5, "fsubr_m64"),
        (6, "fdiv_m64"),
        (7, "fdivr_m64"),
    ] {
        f(0xDC, grp, mn, &[Ea(Q), Imp(ImpOp::Sti)], "x87 {e}|st(i)");
    }
    // DD: m64 移動 + ST(i) 移動・解放。
    f(0xDD, 0, "fld_m64", &[Ea(Q), Imp(ImpOp::Sti)], "fld {e}|ffree");
    f(0xDD, 1, "fisttp_m64", &[Ea(Q), Imp(ImpOp::Sti)], "fisttp {e}");
    f(0xDD, 2, "fst_m64", &[Ea(Q), Imp(ImpOp::Sti)], "fst {e}|st(i)");
    f(0xDD, 3, "fstp_m64", &[Ea(Q), Imp(ImpOp::Sti)], "fstp {e}|st(i)");
    f(0xDD, 4, "x87dd_4", &[Ea(Q), Imp(ImpOp::Sti)], "x87 {e}");
    f(0xDD, 5, "x87dd_5", &[Imp(ImpOp::Sti)], "x87");
    f(0xDD, 6, "x87dd_6", &[Ea(Q)], "x87 {e}");
    f(0xDD, 7, "fnstsw_m16", &[Ea(W16)], "fnstsw {e}");
    // DE: m16 整数演算 + 演算+pop（FADDP 等）。
    for (grp, mn) in [
        (0u8, "fiadd_m16"),
        (1, "fimul_m16"),
        (2, "ficom_m16"),
        (3, "ficomp_m16"),
        (4, "fisub_m16"),
        (5, "fisubr_m16"),
        (6, "fidiv_m16"),
        (7, "fidivr_m16"),
    ] {
        f(0xDE, grp, mn, &[Ea(W16), Imp(ImpOp::Sti)], "x87 {e}|st(i)p");
    }
    // DF: 16/64 ビット整数変換 + FNSTSW AX/FUCOMIP/FCOMIP。
    f(0xDF, 0, "fild_m16", &[Ea(W16), Imp(ImpOp::Sti)], "fild {e}");
    f(0xDF, 1, "fisttp_m16", &[Ea(W16)], "fisttp {e}");
    f(0xDF, 2, "fist_m16", &[Ea(W16)], "fist {e}");
    f(0xDF, 3, "fistp_m16", &[Ea(W16)], "fistp {e}");
    f(0xDF, 4, "fbld_m80", &[Ea(Q), Imp(ImpOp::Sti)], "fbld {e}|fnstsw");
    f(0xDF, 5, "fild_m64", &[Ea(Q), Imp(ImpOp::Sti)], "fild {e}|fucomip");
    f(0xDF, 6, "fbstp_m80", &[Ea(Q), Imp(ImpOp::Sti)], "fbstp {e}|fcomip");
    f(0xDF, 7, "fistp_m64", &[Ea(Q)], "fistp {e}");

    // 0F への分岐。
    // 0F は 8086/8088 では POP CS、以降は副表への分岐。
    primary.push(MapItem::Map(0x0F, "map_0f".to_string(), w("!pop_cs")));
    primary.push(MapItem::Insn(
        0x0F,
        mi("pop_cs", &[], None, PfxSel::Any, w("pop_cs"), "pop cs", "load"),
    ));

    m.maps.push(MapDecl {
        name: "primary".to_string(),
        items: primary,
    });

    // 0F マップ。
    let mut m0f: Vec<MapItem> = Vec::new();
    // 0F 01 グループ。実モードでは 80286 の SMSW(/4)/LMSW(/6) だけを
    // 解読する（SGDT/SIDT/SLDT/STR の実モード形と保護モード系は A4）。
    let m286 = |grp: u8, name: &str, syntax: &str| {
        mi(
            name,
            &[Ea(W16)],
            Some(grp),
            PfxSel::Any,
            w("i286 && opd_o16 && adr_a16"),
            syntax,
            "system",
        )
    };
    m0f.push(MapItem::Insn(0x01, m286(4, "smsw_ew", "smsw {e}")));
    m0f.push(MapItem::Insn(0x01, m286(6, "lmsw_ew", "lmsw {e}")));
    // CLTS（0F 06）。80386 で追加。実モードでは CR0 の TS を下ろすだけで、
    // 現行モデルは CR0 を持たないので no-op として扱う（SST 80386 実測）。
    m0f.push(MapItem::Insn(
        0x06,
        mi("clts", &[], None, PfxSel::Any, w("i386"), "clts", "system"),
    ));
    m0f.extend([
        MapItem::Insn(0x05, mi("syscall", &[], None, PfxSel::Any, w("m64"), "syscall", "system")),
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
        // 0F AE グループ。mod!=11 は MXCSR/CLFLUSH、mod=11 は fence。
        // /0 /1 /4 は FXSAVE/FXRSTOR/XSAVE（C1 の範囲）なので未宣言。
        MapItem::Insn(0xAE, gm("ldmxcsr_md", 2, false, &[Ea(D32)], "ldmxcsr {e}", "load")),
        MapItem::Insn(0xAE, gm("stmxcsr_md", 3, false, &[Ea(D32)], "stmxcsr {e}", "store")),
        // fence は接頭辞なし。F3 0F AE は RDFSBASE/INCSSP/UMONITOR/
        // PTWRITE 系、66/F2 も別命令なので Plain で切る。
        MapItem::Insn(0xAE, gmp("lfence", 5, true, &[], PfxSel::Plain, "lfence", "alu")),
        MapItem::Insn(0xAE, gmp("mfence", 6, true, &[], PfxSel::Plain, "mfence", "alu")),
        MapItem::Insn(0xAE, gm("clflush_mb", 7, false, &[Ea(B8)], "clflush {e}", "alu")),
        MapItem::Insn(0xAE, gmp("sfence", 7, true, &[], PfxSel::Plain, "sfence", "alu")),
        // POPCNT（F3 0F B8）。接頭辞なしは TZCNT/JMPE で別物。
        MapItem::Insn(0xB8, mi("popcnt_gv_ev", &[Reg(V), Ea(V)], None, PfxSel::PF3, Pred::True, "popcnt {g}, {e}", "alu")),
        // CMPXCHG8B/16B（0F C7 /1、メモリ形のみ。REX.W で 16 バイト）。
        MapItem::Insn(0xC7, gm("cmpxchg8b_mq", 1, false, &[Ea(Q64)], "cmpxchg8b {e}", "alu")),
        MapItem::Insn(
            0xB0,
            n("cmpxchg_eb_gb", &[Ea(B8), Reg(B8)], "cmpxchg {e}, {g}", "alu"),
        ),
        MapItem::Insn(
            0xB1,
            n("cmpxchg_ev_gv", &[Ea(V), Reg(V)], "cmpxchg {e}, {g}", "alu"),
        ),
        MapItem::Insn(0xB9, n("ud1", &[Ea(V)], "ud1 {e}", "system")),
        MapItem::Insn(
            0xBC,
            n("bsf_gv_ev", &[Reg(V), Ea(V)], "bsf {g}, {e}", "alu"),
        ),
        // LZCNT（F3 0F BD）。LZCNT 機能が無い CPU での F3 0F BD は
        // 実機では BSR として動くが、BSR は NoF3 で排他しているので
        // このモデルではデコード不能になる（既知の近似）。
        MapItem::Insn(
            0xBD,
            mi(
                "lzcnt_gv_ev",
                &[Reg(V), Ea(V)],
                None,
                PfxSel::PF3,
                Pred::True,
                "lzcnt {g}, {e}",
                "alu",
            ),
        ),
        MapItem::Insn(
            0xBD,
            mi(
                "bsr_gv_ev",
                &[Reg(V), Ea(V)],
                None,
                PfxSel::NoF3,
                Pred::True,
                "bsr {g}, {e}",
                "alu",
            ),
        ),
        MapItem::Insn(
            0xC0,
            n("xadd_eb_gb", &[Ea(B8), Reg(B8)], "xadd {e}, {g}", "alu"),
        ),
        MapItem::Insn(
            0xC1,
            n("xadd_ev_gv", &[Ea(V), Reg(V)], "xadd {e}, {g}", "alu"),
        ),
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
    // ヒント NOP: 0F 0D（prefetch 系）と 0F 18-1D + 0F 1F /1-7（全グループ）。
    // 1E は F3 が ENDBR のため今回は対象外、1F /0 は既に登録済み。
    for grp in 0..8u8 {
        m0f.push(MapItem::Insn(0x0D, g("nop_ev", grp, &[Ea(V)], "nop {e}", "alu")));
        for byte in [0x18u8, 0x19, 0x1A, 0x1B, 0x1C, 0x1D] {
            m0f.push(MapItem::Insn(
                byte,
                g("nop_ev", grp, &[Ea(V)], "nop {e}", "alu"),
            ));
        }
        if grp > 0 {
            m0f.push(MapItem::Insn(
                0x1F,
                g("nop_ev", grp, &[Ea(V)], "nop {e}", "alu"),
            ));
        }
    }
    for k in 0..8u8 {
        m0f.push(MapItem::Insn(
            0xC8 + k,
            n("bswap_rv", &[InOp(V)], "bswap {r}", "alu"),
        ));
    }
    // SSE/SSE2（0F 10-2F、50-5F、60-77、C2、C4-C6、D0-EF、F1-FF）。
    // 必須接頭辞は PfxSel で選ぶ。V は ModRM.reg の XMM、W は
    // ModRM.r/m の XMM/メモリ（メモリ幅は意味論側が決める）。
    // 接頭辞なしの同オペコードは MMX 形（P = ModRM.reg の mm、
    // Q = ModRM.r/m の mm/m64）。
    // MOVUP は F2/F3 がスカラ形に取られるため Plain、
    // MOVAP は F2/F3 が無視されるので No66。
    for (byte, base, np) in [
        (0x10u8, "movup", PfxSel::Plain),
        (0x28, "movap", PfxSel::No66),
    ] {
        for (sel, suf) in [(np, "s"), (PfxSel::P66, "d")] {
            let mn = format!("{base}{suf}");
            m0f.push(MapItem::Insn(
                byte,
                mi(&format!("{mn}_xv_wv"), &[RegX, RmX], None, sel, Pred::True, "mov {x}, {w}", "load"),
            ));
            m0f.push(MapItem::Insn(
                byte + 1,
                mi(&format!("{mn}_wv_xv"), &[RmX, RegX], None, sel, Pred::True, "mov {w}, {x}", "store"),
            ));
        }
    }
    // 0F 10/11 の F2/F3 はスカラ形。
    for (byte, ld) in [(0x10u8, true), (0x11, false)] {
        for (sel, mn) in [(PfxSel::PF2, "movsd"), (PfxSel::PF3, "movss")] {
            let name = if ld {
                format!("{mn}_xv_wv")
            } else {
                format!("{mn}_wv_xv")
            };
            let ops: &[OpKind] = if ld { &[RegX, RmX] } else { &[RmX, RegX] };
            let syn = if ld { "mov {x}, {w}" } else { "mov {w}, {x}" };
            let tim = if ld { "load" } else { "store" };
            m0f.push(MapItem::Insn(byte, mi(&name, ops, None, sel, Pred::True, syn, tim)));
        }
    }
    m0f.extend([
        // MOVLP/MOVHP/MOVH/MOVL の高下半分移動。
        // 0F 12: NP+mem=MOVLPS、NP+reg=MOVHLPS、66+mem=MOVLPD、
        // 66+reg は MOVHLPS（66 は無視される）。F2=MOVDDUP、F3=MOVSLDUP。
        MapItem::Insn(0x12, mmem(mi("movlps_xv_wv", &[RegX, RmX], None, PfxSel::Plain, Pred::True, "movlps {x}, {w}", "load"))),
        MapItem::Insn(0x12, mreg(mi("movhlps_xv_xv", &[RegX, RmX], None, PfxSel::Plain, Pred::True, "movhlps {x}, {w}", "alu"))),
        MapItem::Insn(0x12, mreg(mi("movhlps_xv_xv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "movhlps {x}, {w}", "alu"))),
        MapItem::Insn(0x12, mmem(mi("movlpd_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "movlpd {x}, {w}", "load"))),
        MapItem::Insn(0x12, mi("movddup_xv_wv", &[RegX, RmX], None, PfxSel::PF2, Pred::True, "movddup {x}, {w}", "load")),
        MapItem::Insn(0x12, mi("movsldup_xv_wv", &[RegX, RmX], None, PfxSel::PF3, Pred::True, "movsldup {x}, {w}", "load")),
        // ストアはメモリ形のみ。F2/F3 は無視される（No66）。
        MapItem::Insn(0x13, mmem(mi("movlps_wv_xv", &[RmX, RegX], None, PfxSel::No66, Pred::True, "movlps {w}, {x}", "store"))),
        MapItem::Insn(0x13, mmem(mi("movlpd_wv_xv", &[RmX, RegX], None, PfxSel::P66, Pred::True, "movlpd {w}, {x}", "store"))),
        // 0F 16: NP+mem=MOVHPS、NP/66+reg=MOVLHPS（66 無視）、
        // 66+mem=MOVHPD。F2=MOVLDUP（未宣言）、F3=MOVSHDUP。
        MapItem::Insn(0x16, mmem(mi("movhps_xv_wv", &[RegX, RmX], None, PfxSel::Plain, Pred::True, "movhps {x}, {w}", "load"))),
        MapItem::Insn(0x16, mreg(mi("movlhps_xv_xv", &[RegX, RmX], None, PfxSel::Plain, Pred::True, "movlhps {x}, {w}", "alu"))),
        MapItem::Insn(0x16, mreg(mi("movlhps_xv_xv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "movlhps {x}, {w}", "alu"))),
        MapItem::Insn(0x16, mmem(mi("movhpd_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "movhpd {x}, {w}", "load"))),
        MapItem::Insn(0x16, mi("movshdup_xv_wv", &[RegX, RmX], None, PfxSel::PF3, Pred::True, "movshdup {x}, {w}", "load")),
        MapItem::Insn(0x17, mmem(mi("movhps_wv_xv", &[RmX, RegX], None, PfxSel::No66, Pred::True, "movhps {w}, {x}", "store"))),
        MapItem::Insn(0x17, mmem(mi("movhpd_wv_xv", &[RmX, RegX], None, PfxSel::P66, Pred::True, "movhpd {w}, {x}", "store"))),
        // UNPCKLPS/PD・UNPCKHPS/PD（0F 14/15）。
        MapItem::Insn(0x14, mi("unpcklps_xv_wv", &[RegX, RmX], None, PfxSel::No66, Pred::True, "unpcklps {x}, {w}", "alu")),
        MapItem::Insn(0x14, mi("unpcklpd_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "unpcklpd {x}, {w}", "alu")),
        MapItem::Insn(0x15, mi("unpckhps_xv_wv", &[RegX, RmX], None, PfxSel::No66, Pred::True, "unpckhps {x}, {w}", "alu")),
        MapItem::Insn(0x15, mi("unpckhpd_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "unpckhpd {x}, {w}", "alu")),
        // スカラ比較。
        MapItem::Insn(0x2E, mi("ucomiss_xv_wv", &[RegX, RmX], None, PfxSel::No66, Pred::True, "ucomiss {x}, {w}", "alu")),
        MapItem::Insn(0x2E, mi("ucomisd_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "ucomisd {x}, {w}", "alu")),
        MapItem::Insn(0x2F, mi("comiss_xv_wv", &[RegX, RmX], None, PfxSel::No66, Pred::True, "comiss {x}, {w}", "alu")),
        MapItem::Insn(0x2F, mi("comisd_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "comisd {x}, {w}", "alu")),
        // 変換。
        MapItem::Insn(0x2A, mi("cvtsi2ss_xv_ev", &[RegX, Ea(V)], None, PfxSel::PF3, Pred::True, "cvtsi2ss {x}, {e}", "alu")),
        MapItem::Insn(0x2A, mi("cvtsi2sd_xv_ev", &[RegX, Ea(V)], None, PfxSel::PF2, Pred::True, "cvtsi2sd {x}, {e}", "alu")),
        MapItem::Insn(0x2C, mi("cvttss2si_gv_wv", &[Reg(V), RmX], None, PfxSel::PF3, Pred::True, "cvttss2si {g}, {w}", "alu")),
        MapItem::Insn(0x2C, mi("cvttsd2si_gv_wv", &[Reg(V), RmX], None, PfxSel::PF2, Pred::True, "cvttsd2si {g}, {w}", "alu")),
        MapItem::Insn(0x2D, mi("cvtss2si_gv_wv", &[Reg(V), RmX], None, PfxSel::PF3, Pred::True, "cvtss2si {g}, {w}", "alu")),
        MapItem::Insn(0x2D, mi("cvtsd2si_gv_wv", &[Reg(V), RmX], None, PfxSel::PF2, Pred::True, "cvtsd2si {g}, {w}", "alu")),
        MapItem::Insn(0x50, mreg(mi("movmskps_gv_wv", &[Reg(V), RmX], None, PfxSel::No66, Pred::True, "movmskps {g}, {w}", "alu"))),
        MapItem::Insn(0x50, mreg(mi("movmskpd_gv_wv", &[Reg(V), RmX], None, PfxSel::P66, Pred::True, "movmskpd {g}, {w}", "alu"))),
        MapItem::Insn(0x5A, mi("cvtps2pd_xv_wv", &[RegX, RmX], None, PfxSel::Plain, Pred::True, "cvtps2pd {x}, {w}", "alu")),
        MapItem::Insn(0x5A, mi("cvtpd2ps_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "cvtpd2ps {x}, {w}", "alu")),
        MapItem::Insn(0x5A, mi("cvtss2sd_xv_wv", &[RegX, RmX], None, PfxSel::PF3, Pred::True, "cvtss2sd {x}, {w}", "alu")),
        MapItem::Insn(0x5A, mi("cvtsd2ss_xv_wv", &[RegX, RmX], None, PfxSel::PF2, Pred::True, "cvtsd2ss {x}, {w}", "alu")),
        // MOVDQA/MOVDQU（アライメント検査は現状なし）。
        MapItem::Insn(0x6F, mi("movdqa_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "movdqa {x}, {w}", "load")),
        MapItem::Insn(0x6F, mi("movdqu_xv_wv", &[RegX, RmX], None, PfxSel::PF3, Pred::True, "movdqu {x}, {w}", "load")),
        MapItem::Insn(0x7F, mi("movdqa_wv_xv", &[RmX, RegX], None, PfxSel::P66, Pred::True, "movdqa {w}, {x}", "store")),
        MapItem::Insn(0x7F, mi("movdqu_wv_xv", &[RmX, RegX], None, PfxSel::PF3, Pred::True, "movdqu {w}, {x}", "store")),
        // MOVD/MOVQ。
        MapItem::Insn(0x6E, mi("movd_xv_ev", &[RegX, Ea(V)], None, PfxSel::P66, Pred::True, "movd {x}, {e}", "load")),
        MapItem::Insn(0x7E, mi("movd_ev_xv", &[Ea(V), RegX], None, PfxSel::P66, Pred::True, "movd {e}, {x}", "store")),
        MapItem::Insn(0x7E, mi("movq_xv_wv", &[RegX, RmX], None, PfxSel::PF3, Pred::True, "movq {x}, {w}", "load")),
        MapItem::Insn(0xD6, mi("movq_wv_xv", &[RmX, RegX], None, PfxSel::P66, Pred::True, "movq {w}, {x}", "store")),
        // PSHUF/PINSR/PEXTR。
        MapItem::Insn(0x70, mi("pshufd_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::P66, Pred::True, "pshufd {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x70, mi("pshuflw_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::PF2, Pred::True, "pshuflw {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x70, mi("pshufhw_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::PF3, Pred::True, "pshufhw {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xC2, mi("cmpps_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::Plain, Pred::True, "cmpps {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xC2, mi("cmppd_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::P66, Pred::True, "cmppd {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xC2, mi("cmpss_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::PF3, Pred::True, "cmpss {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xC2, mi("cmpsd_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::PF2, Pred::True, "cmpsd {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xC4, mi("pinsrw_xv_ew_ib", &[RegX, Ea(W16), Imm(B8)], None, PfxSel::P66, Pred::True, "pinsrw {x}, {e}, {i}", "alu")),
        MapItem::Insn(0xC5, mreg(mi("pextrw_gv_wv_ib", &[Reg(V), RmX, Imm(B8)], None, PfxSel::P66, Pred::True, "pextrw {g}, {w}, {i}", "alu"))),
        MapItem::Insn(0xC6, mi("shufps_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::No66, Pred::True, "shufps {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xC6, mi("shufpd_xv_wv_ib", &[RegX, RmX, Imm(B8)], None, PfxSel::P66, Pred::True, "shufpd {x}, {w}, {i}", "alu")),
        // PMOVMSKB。
        MapItem::Insn(0xD7, mreg(mi("pmovmskb_gv_wv", &[Reg(V), RmX], None, PfxSel::P66, Pred::True, "pmovmskb {g}, {w}", "alu"))),
    ]);
    // パック浮動小数点（51, 58, 59, 5C, 5D, 5E, 5F）。名前は map insn。
    for (byte, mn) in [
        (0x51u8, "sqrt"),
        (0x58, "add"),
        (0x59, "mul"),
        (0x5C, "sub"),
        (0x5D, "min"),
        (0x5E, "div"),
        (0x5F, "max"),
    ] {
        for (sel, suf) in [
            (PfxSel::Plain, "ps"),
            (PfxSel::P66, "pd"),
            (PfxSel::PF3, "ss"),
            (PfxSel::PF2, "sd"),
        ] {
            m0f.push(MapItem::Insn(
                byte,
                mi(&format!("{mn}{suf}_xv_wv"), &[RegX, RmX], None, sel, Pred::True, "{op} {x}, {w}", "alu"),
            ));
        }
    }
    // SSE3 の水平加減算と ADDSUB、LDDQU。
    for (byte, mn, sel) in [
        (0x7Cu8, "haddps", PfxSel::PF2),
        (0x7C, "haddpd", PfxSel::P66),
        (0x7D, "hsubps", PfxSel::PF2),
        (0x7D, "hsubpd", PfxSel::P66),
        (0xD0, "addsubps", PfxSel::PF2),
        (0xD0, "addsubpd", PfxSel::P66),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            mi(&format!("{mn}_xv_wv"), &[RegX, RmX], None, sel, Pred::True, "{op} {x}, {w}", "alu"),
        ));
    }
    m0f.push(MapItem::Insn(
        0xF0,
        mmem(mi("lddqu_xv_mv", &[RegX, RmX], None, PfxSel::PF2, Pred::True, "lddqu {x}, {w}", "load")),
    ));
    // パック論理（54-57）とパック整数の論理（DB, DF, EB, EF）。
    for (byte, mn, sel) in [
        (0x54u8, "andps", PfxSel::No66),
        (0x54, "andpd", PfxSel::P66),
        (0x55, "andnps", PfxSel::No66),
        (0x55, "andnpd", PfxSel::P66),
        (0x56, "orps", PfxSel::No66),
        (0x56, "orpd", PfxSel::P66),
        (0x57, "xorps", PfxSel::No66),
        (0x57, "xorpd", PfxSel::P66),
        (0xDB, "pand", PfxSel::P66),
        (0xDF, "pandn", PfxSel::P66),
        (0xEB, "por", PfxSel::P66),
        (0xEF, "pxor", PfxSel::P66),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            mi(&format!("{mn}_xv_wv"), &[RegX, RmX], None, sel, Pred::True, "{op} {x}, {w}", "alu"),
        ));
    }
    // パック整数（P66 のみ。MMX 形は対象外）。
    for (byte, mn) in [
        (0x60u8, "punpcklbw"),
        (0x61, "punpcklwd"),
        (0x62, "punpckldq"),
        (0x64, "pcmpgtb"),
        (0x65, "pcmpgtw"),
        (0x66, "pcmpgtd"),
        (0x68, "punpckhbw"),
        (0x69, "punpckhwd"),
        (0x6A, "punpckhdq"),
        (0x6C, "punpcklqdq"),
        (0x6D, "punpckhqdq"),
        (0x74, "pcmpeqb"),
        (0x75, "pcmpeqw"),
        (0x76, "pcmpeqd"),
        (0xD1, "psrlw"),
        (0xD2, "psrld"),
        (0xD3, "psrlq"),
        (0xD4, "paddq"),
        (0xD5, "pmullw"),
        (0xD8, "psubusb"),
        (0xD9, "psubusw"),
        (0xDA, "pminub"),
        (0xDC, "paddusb"),
        (0xDD, "paddusw"),
        (0xDE, "pmaxub"),
        (0xE0, "pavgb"),
        (0xE1, "psraw"),
        (0xE2, "psrad"),
        (0xE3, "pavgw"),
        (0xE8, "psubsb"),
        (0xE9, "psubsw"),
        (0xEA, "pminsw"),
        (0xEC, "paddsb"),
        (0xED, "paddsw"),
        (0xEE, "pmaxsw"),
        (0xF1, "psllw"),
        (0xF2, "pslld"),
        (0xF3, "psllq"),
        (0xF8, "psubb"),
        (0xF9, "psubw"),
        (0xFA, "psubd"),
        (0xFB, "psubq"),
        (0xFC, "paddb"),
        (0xFD, "paddw"),
        (0xFE, "paddd"),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            mi(&format!("{mn}_xv_wv"), &[RegX, RmX], None, PfxSel::P66, Pred::True, "{op} {x}, {w}", "alu"),
        ));
    }
    // パックシフト群（0F 71-73、/n はグループ、被演算子は xmm + imm8）。
    for (byte, entries) in [
        (0x71u8, &[(2u8, "psrlw"), (4, "psraw"), (6, "psllw")][..]),
        (0x72, &[(2u8, "psrld"), (4, "psrad"), (6, "pslld")][..]),
        (0x73, &[(2u8, "psrlq"), (3, "psrldq"), (6, "psllq"), (7, "pslldq")][..]),
    ] {
        for (grp, mn) in entries.iter().copied() {
            m0f.push(MapItem::Insn(
                byte,
                mi(&format!("{mn}_wv_ib"), &[RmX, Imm(B8)], Some(grp), PfxSel::P66, Pred::True, "{op} {w}, {i}", "alu"),
            ));
        }
    }
    // 同グループの MMX 形（psrldq/pslldq は xmm 専用で MMX にはない）。
    for (byte, entries) in [
        (0x71u8, &[(2u8, "psrlw"), (4, "psraw"), (6, "psllw")][..]),
        (0x72, &[(2u8, "psrld"), (4, "psrad"), (6, "pslld")][..]),
        (0x73, &[(2u8, "psrlq"), (6, "psllq")][..]),
    ] {
        for (grp, mn) in entries.iter().copied() {
            m0f.push(MapItem::Insn(
                byte,
                mi(&format!("{mn}_qv_ib"), &[RmM, Imm(B8)], Some(grp), PfxSel::No66, Pred::True, "{op} {q}, {i}", "alu"),
            ));
        }
    }
    // MMX 形（接頭辞なし。P = ModRM.reg の mm、Q = ModRM.r/m の
    // mm/m64）。xmm 側と同じオペコードの plain バリアント。
    for (byte, mn) in [
        (0x60u8, "punpcklbw"),
        (0x61, "punpcklwd"),
        (0x62, "punpckldq"),
        (0x63, "packsswb"),
        (0x64, "pcmpgtb"),
        (0x65, "pcmpgtw"),
        (0x66, "pcmpgtd"),
        (0x67, "packuswb"),
        (0x68, "punpckhbw"),
        (0x69, "punpckhwd"),
        (0x6A, "punpckhdq"),
        (0x6B, "packssdw"),
        (0x74, "pcmpeqb"),
        (0x75, "pcmpeqw"),
        (0x76, "pcmpeqd"),
        (0xD1, "psrlw"),
        (0xD2, "psrld"),
        (0xD3, "psrlq"),
        (0xD4, "paddq"),
        (0xD5, "pmullw"),
        (0xD8, "psubusb"),
        (0xD9, "psubusw"),
        (0xDA, "pminub"),
        (0xDB, "pand"),
        (0xDC, "paddusb"),
        (0xDD, "paddusw"),
        (0xDE, "pmaxub"),
        (0xDF, "pandn"),
        (0xE0, "pavgb"),
        (0xE1, "psraw"),
        (0xE2, "psrad"),
        (0xE3, "pavgw"),
        (0xE4, "pmulhuw"),
        (0xE5, "pmulhw"),
        (0xE8, "psubsb"),
        (0xE9, "psubsw"),
        (0xEA, "pminsw"),
        (0xEB, "por"),
        (0xEC, "paddsb"),
        (0xED, "paddsw"),
        (0xEE, "pmaxsw"),
        (0xEF, "pxor"),
        (0xF1, "psllw"),
        (0xF2, "pslld"),
        (0xF3, "psllq"),
        (0xF4, "pmuludq"),
        (0xF5, "pmaddwd"),
        (0xF6, "psadbw"),
        (0xF8, "psubb"),
        (0xF9, "psubw"),
        (0xFA, "psubd"),
        (0xFB, "psubq"),
        (0xFC, "paddb"),
        (0xFD, "paddw"),
        (0xFE, "paddd"),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            mi(&format!("{mn}_pv_qv"), &[RegM, RmM], None, PfxSel::No66, Pred::True, "{op} {p}, {q}", "alu"),
        ));
    }
    // MMX の移動・シャッフル・特殊形。
    m0f.extend([
        // MOVD/MOVQ mm, r/m（osize が 64 なら movq、さもなくば movd）。
        // MMX 形は F2/F3 を無視して解読するが、0F 6F/7E/7F は
        // F3 が MOVDQU/MOVQ xmm に取られるので No66F3。
        MapItem::Insn(0x6E, mi("movd_pv_ev", &[RegM, Ea(V)], None, PfxSel::No66, Pred::True, "movd {p}, {e}", "load")),
        MapItem::Insn(0x7E, mi("movd_ev_pv", &[Ea(V), RegM], None, PfxSel::No66F3, Pred::True, "movd {e}, {p}", "store")),
        // MOVQ mm, mm/m64。
        MapItem::Insn(0x6F, mi("movq_pv_qv", &[RegM, RmM], None, PfxSel::No66F3, Pred::True, "movq {p}, {q}", "load")),
        MapItem::Insn(0x7F, mi("movq_qv_pv", &[RmM, RegM], None, PfxSel::No66F3, Pred::True, "movq {q}, {p}", "store")),
        // PSHUFW（SSE1 で追加された mm シャッフル）。66/F2/F3 は
        // 全て xmm 形に取られるので Plain のまま。
        MapItem::Insn(0x70, mi("pshufw_pv_qv_ib", &[RegM, RmM, Imm(B8)], None, PfxSel::Plain, Pred::True, "pshufw {p}, {q}, {i}", "alu")),
        // EMMS。x87 タグのクリア（当モデルでは建築状態の変化なし）。
        // 接頭辞はすべて無視される。
        MapItem::Insn(0x77, mi("emms", &[], None, PfxSel::Any, Pred::True, "emms", "alu")),
        // PINSRW/PEXTRW/PMOVMSKB（SSE1 で mm にも拡張）。
        // PEXTRW/PMOVMSKB はレジスタ形のみ。
        MapItem::Insn(0xC4, mi("pinsrw_pv_ew_ib", &[RegM, Ea(W16), Imm(B8)], None, PfxSel::No66, Pred::True, "pinsrw {p}, {e}, {i}", "alu")),
        MapItem::Insn(0xC5, mreg(mi("pextrw_gv_pv_ib", &[Reg(V), RmM, Imm(B8)], None, PfxSel::No66, Pred::True, "pextrw {g}, {q}, {i}", "alu"))),
        MapItem::Insn(0xD7, mreg(mi("pmovmskb_gv_qv", &[Reg(V), RmM], None, PfxSel::No66, Pred::True, "pmovmskb {g}, {q}", "alu"))),
        // MASKMOVQ（DS:(E)DI へマスク書き込み、レジスタ形のみ）と
        // MOVNTQ（メモリ形のみ）。
        MapItem::Insn(0xE7, mmem(mi("movntq_qv_pv", &[RmM, RegM], None, PfxSel::No66, Pred::True, "movntq {q}, {p}", "store"))),
        MapItem::Insn(0xF7, mreg(mi("maskmovq_pv_qv", &[RegM, RmM], None, PfxSel::No66, Pred::True, "maskmovq {p}, {q}", "store"))),
        MapItem::Insn(0xF7, mreg(mi("maskmovdqu_xv_xv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "maskmovdqu {x}, {w}", "store"))),
    ]);
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
        // LSS/LFS/LGS（i386 で追加される far ポインタロード）。
        MapItem::Insn(0xB2, mi("lss_gv_mp", &[Reg(V), Ea(V)], None, PfxSel::Any, w("i386"), "lss {g}, {e}", "load")),
        MapItem::Insn(0xB4, mi("lfs_gv_mp", &[Reg(V), Ea(V)], None, PfxSel::Any, w("i386"), "lfs {g}, {e}", "load")),
        MapItem::Insn(0xB5, mi("lgs_gv_mp", &[Reg(V), Ea(V)], None, PfxSel::Any, w("i386"), "lgs {g}, {e}", "load")),
        // SHLD/SHRD。
        MapItem::Insn(0xA4, n("shld_ev_gv_ib", &[Ea(V), Reg(V), Imm(B8)], "shld {e}, {g}, {i}", "alu")),
        MapItem::Insn(0xA5, n("shld_ev_gv_cl", &[Ea(V), Reg(V), Imp(ImpOp::Cl)], "shld {e}, {g}, cl", "alu")),
        MapItem::Insn(0xAC, n("shrd_ev_gv_ib", &[Ea(V), Reg(V), Imm(B8)], "shrd {e}, {g}, {i}", "alu")),
        MapItem::Insn(0xAD, n("shrd_ev_gv_cl", &[Ea(V), Reg(V), Imp(ImpOp::Cl)], "shrd {e}, {g}, cl", "alu")),
        // 3 バイトオペコードのサブマップ。
        MapItem::Map(0x38, "map_0f38".to_string(), Pred::True),
        MapItem::Map(0x3A, "map_0f3a".to_string(), Pred::True),
    ]);
    m.maps.push(MapDecl {
        name: "map_0f".to_string(),
        items: m0f,
    });
    build_map_0f38(m);
    build_map_0f3a(m);
}

/// 0F 38 サブマップ（SSSE3/SSE4.1/MOVBE）。XMM 形は必須接頭辞 0x66。
/// MMX 形（接頭辞なし）は st_sig 経由で x87 にエイリアスする。
fn build_map_0f38(m: &mut Model) {
    use OpKind::*;
    use OpWidth::*;
    let xv_wv: &[OpKind] = &[RegX, RmX];
    let mut v: Vec<MapItem> = Vec::new();
    let mut x = |op: u8, name: &str| {
        v.push(MapItem::Insn(
            op,
            mi(name, xv_wv, None, PfxSel::P66, Pred::True, "", "alu"),
        ));
    };
    // SSSE3。
    x(0x00, "pshufb_xv_wv");
    x(0x01, "phaddw_xv_wv");
    x(0x02, "phaddd_xv_wv");
    x(0x03, "phaddsw_xv_wv");
    x(0x04, "pmaddubsw_xv_wv");
    x(0x05, "phsubw_xv_wv");
    x(0x06, "phsubd_xv_wv");
    x(0x07, "phsubsw_xv_wv");
    x(0x08, "psignb_xv_wv");
    x(0x09, "psignw_xv_wv");
    x(0x0A, "psignd_xv_wv");
    x(0x0B, "pmulhrsw_xv_wv");
    // SSE4.1。
    x(0x17, "ptest_xv_wv");
    x(0x1C, "pabsb_xv_wv");
    x(0x1D, "pabsw_xv_wv");
    x(0x1E, "pabsd_xv_wv");
    x(0x20, "pmovsxbw_xv_wv");
    x(0x21, "pmovsxbd_xv_wv");
    x(0x22, "pmovsxbq_xv_wv");
    x(0x23, "pmovsxwd_xv_wv");
    x(0x24, "pmovsxwq_xv_wv");
    x(0x25, "pmovsxdq_xv_wv");
    x(0x28, "pmuldq_xv_wv");
    x(0x29, "pcmpeqq_xv_wv");
    x(0x2A, "movntdqa_xv_wv");
    x(0x2B, "packusdw_xv_wv");
    x(0x30, "pmovzxbw_xv_wv");
    x(0x31, "pmovzxbd_xv_wv");
    x(0x32, "pmovzxbq_xv_wv");
    x(0x33, "pmovzxwd_xv_wv");
    x(0x34, "pmovzxwq_xv_wv");
    x(0x35, "pmovzxdq_xv_wv");
    x(0x37, "pcmpgtq_xv_wv");
    x(0x38, "pminsb_xv_wv");
    x(0x39, "pminsd_xv_wv");
    x(0x3A, "pminuw_xv_wv");
    x(0x3B, "pminud_xv_wv");
    x(0x3C, "pmaxsb_xv_wv");
    x(0x3D, "pmaxsd_xv_wv");
    x(0x3E, "pmaxuw_xv_wv");
    x(0x3F, "pmaxud_xv_wv");
    x(0x40, "pmulld_xv_wv");
    x(0x10, "pblendvb_xv_wv");
    x(0x14, "blendvps_xv_wv");
    x(0x15, "blendvpd_xv_wv");
    x(0x41, "phminposuw_xv_wv");
    // ADX。ADCX は必須 66、ADOX は必須 F3。
    v.push(MapItem::Insn(
        0xF6,
        mi("adcx_gv_ev", &[Reg(V), Ea(V)], None, PfxSel::P66, Pred::True, "adcx {g}, {e}", "alu"),
    ));
    v.push(MapItem::Insn(
        0xF6,
        mi("adox_gv_ev", &[Reg(V), Ea(V)], None, PfxSel::PF3, Pred::True, "adox {g}, {e}", "alu"),
    ));
    // AES-NI のラウンド変換（0xDB-0xDF、必須接頭辞 0x66）。
    for (op, name, syn) in [
        (0xDBu8, "aesimc_xv_wv", "aesimc {x}, {w}"),
        (0xDC, "aesenc_xv_wv", "aesenc {x}, {w}"),
        (0xDD, "aesenclast_xv_wv", "aesenclast {x}, {w}"),
        (0xDE, "aesdec_xv_wv", "aesdec {x}, {w}"),
        (0xDF, "aesdeclast_xv_wv", "aesdeclast {x}, {w}"),
    ] {
        v.push(MapItem::Insn(
            op,
            mi(name, &[RegX, RmX], None, PfxSel::P66, Pred::True, syn, "alu"),
        ));
    }
    // SHA-NI（0xC8-0xCD、接頭辞なし NP）。SHA256RNDS2 は
    // 暗黙の XMM0 も読む（意味論側で参照）。
    for (op, name, syn) in [
        (0xC8u8, "sha1nexte_xv_wv", "sha1nexte {x}, {w}"),
        (0xC9, "sha1msg1_xv_wv", "sha1msg1 {x}, {w}"),
        (0xCA, "sha1msg2_xv_wv", "sha1msg2 {x}, {w}"),
        (0xCB, "sha256rnds2_xv_wv", "sha256rnds2 {x}, {w}"),
        (0xCC, "sha256msg1_xv_wv", "sha256msg1 {x}, {w}"),
        (0xCD, "sha256msg2_xv_wv", "sha256msg2 {x}, {w}"),
    ] {
        v.push(MapItem::Insn(
            op,
            mi(name, &[RegX, RmX], None, PfxSel::Plain, Pred::True, syn, "alu"),
        ));
    }
    // GFNI の GF(2^8) 乗算（必須接頭辞 0x66）。
    v.push(MapItem::Insn(
        0xCF,
        mi("gf2p8mulb_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "gf2p8mulb {x}, {w}", "alu"),
    ));
    // CRC32（F2 0F38 F0/F1）。MOVBE と同バイトで接頭辞で分ける。
    v.push(MapItem::Insn(
        0xF0,
        mi("crc32_gv_eb", &[Reg(V), Ea(B8)], None, PfxSel::PF2, Pred::True, "crc32 {g}, {e}", "alu"),
    ));
    v.push(MapItem::Insn(
        0xF1,
        mi("crc32_gv_ev", &[Reg(V), Ea(V)], None, PfxSel::PF2, Pred::True, "crc32 {g}, {e}", "alu"),
    ));
    // SSSE3 の MMX 形（接頭辞なし。mm は x87 仮数部のエイリアス）。
    for (op, mn) in [
        (0x00u8, "pshufb"),
        (0x01, "phaddw"),
        (0x02, "phaddd"),
        (0x03, "phaddsw"),
        (0x04, "pmaddubsw"),
        (0x05, "phsubw"),
        (0x06, "phsubd"),
        (0x07, "phsubsw"),
        (0x08, "psignb"),
        (0x09, "psignw"),
        (0x0A, "psignd"),
        (0x0B, "pmulhrsw"),
        (0x1C, "pabsb"),
        (0x1D, "pabsw"),
        (0x1E, "pabsd"),
    ] {
        v.push(MapItem::Insn(
            op,
            mi(&format!("{mn}_pv_qv"), &[RegM, RmM], None, PfxSel::No66, Pred::True, "", "alu"),
        ));
    }
    // MOVBE。必須接頭辞はなく 0x66 は 16 ビット幅を選ぶ。
    // F3 は無視されるが F2 は CRC32 に取られる。メモリ形のみ。
    for (op, name, ops, syn, tim) in [
        (0xF0u8, "movbe_gv_mv", &[Reg(V), Ea(V)] as &[OpKind], "movbe {g}, {e}", "load"),
        (0xF1, "movbe_mv_gv", &[Ea(V), Reg(V)], "movbe {e}, {g}", "store"),
    ] {
        v.push(MapItem::Insn(
            op,
            mmem(mi(name, ops, None, PfxSel::NoF2, Pred::True, syn, tim)),
        ));
    }
    // MOVNTDQA はメモリ形のみ。
    for it in v.iter_mut() {
        if let MapItem::Insn(0x2A, mi) = it {
            mi.group_mod = Some(false);
        }
    }
    m.maps.push(MapDecl {
        name: "map_0f38".to_string(),
        items: v,
    });
}

/// 0F 3A サブマップ。すべて必須接頭辞 0x66 + imm8。
fn build_map_0f3a(m: &mut Model) {
    use OpKind::*;
    use OpWidth::*;
    let ib = Imm(B8);
    let items = vec![
        MapItem::Insn(0x08, mi("roundps_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "roundps {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x09, mi("roundpd_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "roundpd {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x0A, mi("roundss_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "roundss {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x0B, mi("roundsd_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "roundsd {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x0C, mi("blendps_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "blendps {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x0D, mi("blendpd_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "blendpd {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x0E, mi("pblendw_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "pblendw {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x0F, mi("palignr_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "palignr {x}, {w}, {i}", "alu")),
        // PALIGNR の MMX 形（接頭辞なし）。
        MapItem::Insn(0x0F, mi("palignr_pv_qv_ib", &[RegM, RmM, ib], None, PfxSel::No66, Pred::True, "palignr {p}, {q}, {i}", "alu")),
        MapItem::Insn(0x14, mi("pextrb_eb_xv", &[Ea(B8), RegX, ib], None, PfxSel::P66, Pred::True, "pextrb {e}, {x}, {i}", "store")),
        MapItem::Insn(0x15, mi("pextrw_ew_xv", &[Ea(W16), RegX, ib], None, PfxSel::P66, Pred::True, "pextrw {e}, {x}, {i}", "store")),
        MapItem::Insn(0x16, mi("pextrd_ed_xv", &[Ea(V), RegX, ib], None, PfxSel::P66, Pred::True, "pextrd {e}, {x}, {i}", "store")),
        MapItem::Insn(0x17, mi("extractps_ed_xv", &[Ea(D32), RegX, ib], None, PfxSel::P66, Pred::True, "extractps {e}, {x}, {i}", "store")),
        MapItem::Insn(0x20, mi("pinsrb_xv_eb_ib", &[RegX, Ea(B8), ib], None, PfxSel::P66, Pred::True, "pinsrb {x}, {e}, {i}", "alu")),
        MapItem::Insn(0x21, mi("insertps_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "insertps {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x22, mi("pinsrd_xv_ed_ib", &[RegX, Ea(V), ib], None, PfxSel::P66, Pred::True, "pinsrd {x}, {e}, {i}", "alu")),
        // SSE4.1 のドット積と隣接差分絶対和。
        MapItem::Insn(0x40, mi("dpps_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "dpps {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x41, mi("dppd_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "dppd {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x42, mi("mpsadbw_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "mpsadbw {x}, {w}, {i}", "alu")),
        // SSE4.2 の明示・暗黙長文字列比較。
        MapItem::Insn(0x60, mi("pcmpestrm_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "pcmpestrm {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x61, mi("pcmpestri_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "pcmpestri {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x62, mi("pcmpistrm_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "pcmpistrm {x}, {w}, {i}", "alu")),
        MapItem::Insn(0x63, mi("pcmpistri_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "pcmpistri {x}, {w}, {i}", "alu")),
        // PCLMULQDQ と AESKEYGENASSIST（必須接頭辞 0x66 + imm8）。
        MapItem::Insn(0x44, mi("pclmulqdq_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "pclmulqdq {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xDF, mi("aeskeygenassist_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "aeskeygenassist {x}, {w}, {i}", "alu")),
        // SHA1RNDS4（NP + imm8）と GFNI の affine 変換（必須接頭辞 0x66 + imm8）。
        MapItem::Insn(0xCC, mi("sha1rnds4_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::Plain, Pred::True, "sha1rnds4 {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xCE, mi("gf2p8affineqb_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "gf2p8affineqb {x}, {w}, {i}", "alu")),
        MapItem::Insn(0xCF, mi("gf2p8affineinvqb_xv_wv_ib", &[RegX, RmX, ib], None, PfxSel::P66, Pred::True, "gf2p8affineinvqb {x}, {w}, {i}", "alu")),
    ];
    m.maps.push(MapDecl {
        name: "map_0f3a".to_string(),
        items,
    });
}
