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
        group_rm: None,
        vex: None,
        evex: None,
        edisp: 0,
        bcast: false,
        er: false,
        wsel: None,
        vex_rv: false,
        pfx,
        when,
        syntax: syntax.to_string(),
        timing: timing.to_string(),
    }
}

/// VEX 接頭辞の命令項目。`sel` は VEX.pp に対応する接頭辞選択、
/// `l` は VEX.L の許容範囲、`rv` が真なら vvvv フィールドが
/// 未使用（1111b）のときだけ解読する。
fn vmx(
    name: &str,
    ops: &[OpKind],
    sel: PfxSel,
    l: VexL,
    rv: bool,
    syntax: &str,
    timing: &str,
) -> MapInsn {
    let mut it = mi(name, ops, None, sel, Pred::True, syntax, timing);
    it.vex = Some(l);
    it.vex_rv = rv;
    it
}

/// EVEX 接頭辞の命令項目。`ll` は許容する L'L のビット集合
/// （bit0=128、bit1=256、bit2=512）。`apply_gates` の EVEX 既定は
/// `avx512f`。`rv` が真なら vvvv+V' が未使用（全ビット 1）のとき
/// だけ解読する。
fn ex(
    name: &str,
    ops: &[OpKind],
    sel: PfxSel,
    ll: u8,
    rv: bool,
    syntax: &str,
    timing: &str,
) -> MapInsn {
    let mut it = mi(name, ops, None, sel, Pred::True, syntax, timing);
    it.evex = Some(ll);
    it.vex_rv = rv;
    it
}

/// VEX 接頭辞で AVX2 ゲートの命令項目（256 ビット整数演算用）。
/// `apply_gates` の VEX 既定 `avx` と `when` の `avx2` が結合される。
fn vax(
    name: &str,
    ops: &[OpKind],
    sel: PfxSel,
    l: VexL,
    rv: bool,
    syntax: &str,
    timing: &str,
) -> MapInsn {
    let mut it = vmx(name, ops, sel, l, rv, syntax, timing);
    it.when = Pred::Flag("avx2".to_string());
    it
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

    // TSX。XBEGIN（C7 /7 mod=11 rm=0）と XABORT（C6 /7 mod=11
    // rm=0）は 32/64 ビットモード専用。トランザクションは
    // モデル化しないので XBEGIN は常にアボートしフォールバックへ
    // 分岐する（`tsx_abort` パラメータが EAX に入る）。8088 系の
    // C6/C7 別名（i286 否定）とは i286 で素集合。
    primary.push(MapItem::Insn(0xC7, {
        let mut it = mi("xbegin_jz", &[Rel(Z)], Some(7), PfxSel::Any, w("i286 && opd_o32"), "xbegin {r}", "jump");
        it.group_mod = Some(true);
        it.group_rm = Some(0);
        it
    }));
    primary.push(MapItem::Insn(0xC6, {
        let mut it = mi("xabort_ib", &[Imm(B8)], Some(7), PfxSel::Any, w("i286 && opd_o32"), "xabort {i}", "system");
        it.group_mod = Some(true);
        it.group_rm = Some(0);
        it
    }));

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
        vex_code: None,
        postop: false,
        items: primary,
    });

    // 0F マップ。
    let mut m0f: Vec<MapItem> = Vec::new();
    // 0F 00 グループ（80286 以降のシステム命令）。SLDT/STR は
    // 80386 以降では実モードでも動くが 80286 の実モードでは
    // #UD — 世代差は意味論側で分岐する。LLDT/LTR/VERR/VERW は
    // 実モードで #UD（意味論側）。ディスクリプタテーブルを
    // 持たないので保護系の検査は全て失敗として扱う。
    let msys = |grp: u8, name: &str, syntax: &str| {
        mi(
            name,
            &[Ea(W16)],
            Some(grp),
            PfxSel::Any,
            w("i286"),
            syntax,
            "system",
        )
    };
    for (grp, name, syn) in [
        (0u8, "sldt_ew", "sldt {e}"),
        (1, "str_ew", "str {e}"),
        (2, "lldt_ew", "lldt {e}"),
        (3, "ltr_ew", "ltr {e}"),
        (4, "verr_ew", "verr {e}"),
        (5, "verw_ew", "verw {e}"),
    ] {
        m0f.push(MapItem::Insn(0x00, msys(grp, name, syn)));
    }
    // LAR/LSL（0F 02/03）。保護系の検査は全て失敗（ZF=0）。
    m0f.push(MapItem::Insn(
        0x02,
        mi(
            "lar_gv_ew",
            &[Reg(V), Ea(W16)],
            None,
            PfxSel::Any,
            w("i286"),
            "lar {g}, {e}",
            "system",
        ),
    ));
    m0f.push(MapItem::Insn(
        0x03,
        mi(
            "lsl_gv_ew",
            &[Reg(V), Ea(W16)],
            None,
            PfxSel::Any,
            w("i286"),
            "lsl {g}, {e}",
            "system",
        ),
    ));
    // 0F 01 グループ。/0-/3 は GDTR/IDTR の退避・復帰（メモリ形
    // のみ）、/4 SMSW と /6 LMSW は 80286 以降の全モードで動く。
    let m01 = |grp: u8, name: &str, syntax: &str| {
        mi(
            name,
            &[Ea(V)],
            Some(grp),
            PfxSel::Any,
            w("i286"),
            syntax,
            "system",
        )
    };
    for (grp, name, syn) in [
        (0u8, "sgdt_ms", "sgdt {e}"),
        (1, "sidt_ms", "sidt {e}"),
        (2, "lgdt_ms", "lgdt {e}"),
        (3, "lidt_ms", "lidt {e}"),
    ] {
        let mut it = m01(grp, name, syn);
        it.group_mod = Some(false);
        m0f.push(MapItem::Insn(0x01, it));
    }
    let mut it = m01(4, "smsw_ew", "smsw {e}");
    it.ops = vec![Ea(W16)];
    m0f.push(MapItem::Insn(0x01, it));
    let mut it = m01(6, "lmsw_ew", "lmsw {e}");
    it.ops = vec![Ea(W16)];
    m0f.push(MapItem::Insn(0x01, it));
    // 0F 01 /5 mod=11 は rm 副エンコーディング（rm×接頭辞で
    // 命令が分かれる）: NP/66 rm=0 SERIALIZE、F3 rm=0 SETSSBSY、
    // F3 rm=2 SAVEPREVSSP、F3 rm=4-7 UIRET/TESTUI/CLUI/STUI
    // （UINTR は 64 ビット専用）、NP/66/F2 rm=6 RDPKRU、
    // rm=7 WRPKRU。rm=1,3 は予約。
    // SERIALIZE。逐次化の意味論は持たないので no-op。
    let mut it = m01(5, "serialize", "serialize");
    it.ops = vec![];
    it.group_mod = Some(true);
    it.group_rm = Some(0);
    it.pfx = PfxSel::NoF2F3;
    m0f.push(MapItem::Insn(0x01, it));
    // CET-SS。影響スタックはモデル化しないので no-op 系。
    m0f.push(MapItem::Insn(0x01, {
        let mut it = gmp("setssbsy", 5, true, &[], PfxSel::PF3, "setssbsy", "system");
        it.group_rm = Some(0);
        it
    }));
    m0f.push(MapItem::Insn(0x01, {
        let mut it = gmp("saveprevssp", 5, true, &[], PfxSel::PF3, "saveprevssp", "system");
        it.group_rm = Some(2);
        it
    }));
    m0f.push(MapItem::Insn(
        0x01,
        gmp("rstorssp_mq", 5, false, &[Ea(Q64)], PfxSel::PF3, "rstorssp {e}", "system"),
    ));
    // UINTR（64 ビット専用）。UIRET はユーザー割り込みからの
    // リターン、TESTUI は CF=UIF（UIF=0 固定）、CLUI/STUI は
    // UIF の更新。すべて近似のスタブ意味論。
    for (rm, name) in [(4u8, "uiret"), (5, "testui"), (6, "clui"), (7, "stui")] {
        let mut it = mi(name, &[], Some(5), PfxSel::PF3, w("m64"), name, "system");
        it.group_mod = Some(true);
        it.group_rm = Some(rm);
        m0f.push(MapItem::Insn(0x01, it));
    }
    // PKU。F2/66 は無視される接頭辞なので NoF3 で受理し、
    // F3 は m64 では CLUI/STUI に譲る（i386 では CLUI 系が
    // 無効なので F3 も RDPKRU/WRPKRU に落ちる — llvm 実測）。
    for (rm, name) in [(6u8, "rdpkru"), (7, "wrpkru")] {
        let mut it = mi(name, &[], Some(5), PfxSel::NoF3, Pred::True, name, "system");
        it.group_mod = Some(true);
        it.group_rm = Some(rm);
        m0f.push(MapItem::Insn(0x01, it));
        let mut it = mi(name, &[], Some(5), PfxSel::PF3, w("!m64"), name, "system");
        it.group_mod = Some(true);
        it.group_rm = Some(rm);
        m0f.push(MapItem::Insn(0x01, it));
    }
    // XCR0（/2 rm=0/1）。全接頭辞を無視する（llvm 実測）。
    // XSETBV は特権命令だが CPL はモデル化しない。
    for (rm, name) in [(0u8, "xgetbv"), (1, "xsetbv")] {
        let mut it = mi(name, &[], Some(2), PfxSel::Any, Pred::True, name, "system");
        it.group_mod = Some(true);
        it.group_rm = Some(rm);
        m0f.push(MapItem::Insn(0x01, it));
    }
    // TSX。XEND（/2 rm=5）と XTEST（/2 rm=6）は 0F 01 /2 の
    // mod=11 副エンコーディング。XTEST はトランザクション外で
    // ZF=1、XEND はトランザクション外で #UD。
    for (rm, name) in [(5u8, "xend"), (6, "xtest")] {
        let mut it = mi(name, &[], Some(2), PfxSel::Any, Pred::True, name, "system");
        it.group_mod = Some(true);
        it.group_rm = Some(rm);
        m0f.push(MapItem::Insn(0x01, it));
    }
    // AMD 拡張（/7 mod=11 副エンコーディング）。MONITORX/MWAITX
    // （mwaitx）、CLZERO（clzero）、RDPRU（rdpru）。
    for (rm, name) in [(2u8, "monitorx"), (3, "mwaitx"), (4, "clzero"), (5, "rdpru")] {
        let mut it = mi(name, &[], Some(7), PfxSel::Any, Pred::True, name, "system");
        it.group_mod = Some(true);
        it.group_rm = Some(rm);
        m0f.push(MapItem::Insn(0x01, it));
    }
    // CLTS（0F 06）。80386 で追加。実モードでは CR0 の TS を下ろすだけで、
    // 現行モデルは CR0 を持たないので no-op として扱う（SST 80386 実測）。
    m0f.push(MapItem::Insn(
        0x06,
        mi("clts", &[], None, PfxSel::Any, w("i386"), "clts", "system"),
    ));
    m0f.extend([
        MapItem::Insn(0x05, mi("syscall", &[], None, PfxSel::Any, w("m64"), "syscall", "system")),
        MapItem::Insn(0x0B, n("ud2", &[], "ud2", "system")),
        // RDSSP（F3 0F 1E /1、mod=11）。ENDBR より先に置く
        // （endbr は全 ModRM を受ける非グループ項目なので、
        // /1 mod=11 をこちらで先に拾う）。影響スタックは
        // モデル化しないので dest は 0 固定。
        MapItem::Insn(0x1E, gmp("rdsspd_rv", 1, true, &[Ea(V)], PfxSel::PF3, "rdssp {e}", "system")),
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
        // CLDEMOTE（0F 1C /0、メモリ形のみ）。全接頭辞を無視
        // する（llvm 実測で NP/66/F2/F3 いずれも受理）。
        // キャッシュ階層はモデル化しないので no-op。
        MapItem::Insn(
            0x1C,
            gm("cldemote_mb", 0, false, &[Ea(B8)], "cldemote {e}", "alu"),
        ),
        MapItem::Insn(0x31, n("rdtsc", &[], "rdtsc", "system")),
        // 0F AE グループ。mod!=11 は MXCSR/CLFLUSH、mod=11 は fence。
        // FXSAVE/FXRSTOR（/0 /1 メモリ形）は全接頭辞を無視する
        // （llvm 実測）。
        MapItem::Insn(0xAE, gmp("fxsave", 0, false, &[Ea(Q64)], PfxSel::Any, "fxsave {e}", "system")),
        MapItem::Insn(0xAE, gmp("fxrstor", 1, false, &[Ea(Q64)], PfxSel::Any, "fxrstor {e}", "system")),
        // XSAVE（/4）は F3 が PTWRITE なので NoF3。XRSTOR（/5）は
        // 全接頭辞を無視する（llvm 実測）。XSAVEOPT（/6）は
        // NP+F2 で 66 は CLWB、F3 は CLRSSBSY に譲る。
        // SDM 上は XSAVE 系の 66/F2 は #UD だが、llvm と同じく
        // 「実装されていない命令でなければ接頭辞を無視する」
        // 近似で受理する。
        MapItem::Insn(0xAE, gmp("xsave", 4, false, &[Ea(Q64)], PfxSel::NoF3, "xsave {e}", "system")),
        MapItem::Insn(0xAE, gmp("xrstor", 5, false, &[Ea(Q64)], PfxSel::Any, "xrstor {e}", "system")),
        MapItem::Insn(0xAE, gmp("xsaveopt", 6, false, &[Ea(Q64)], PfxSel::No66F3, "xsaveopt {e}", "system")),
        MapItem::Insn(0xAE, gm("ldmxcsr_md", 2, false, &[Ea(D32)], "ldmxcsr {e}", "load")),
        MapItem::Insn(0xAE, gm("stmxcsr_md", 3, false, &[Ea(D32)], "stmxcsr {e}", "store")),
        // FSGSBASE（F3 0F AE /0-/3、mod=11、レジスタ形のみ）。
        // 64 ビットモード専用（Compat/Leg は N.E.）。`{e}` の幅は
        // V 既定（o32/o64 で d/q が変わる）。
        MapItem::Insn(0xAE, {
            let mut it = mi("rdfsbase_rv", &[Ea(V)], Some(0), PfxSel::PF3, w("m64"), "rdfsbase {e}", "system");
            it.group_mod = Some(true);
            it
        }),
        MapItem::Insn(0xAE, {
            let mut it = mi("rdgsbase_rv", &[Ea(V)], Some(1), PfxSel::PF3, w("m64"), "rdgsbase {e}", "system");
            it.group_mod = Some(true);
            it
        }),
        MapItem::Insn(0xAE, {
            let mut it = mi("wrfsbase_rv", &[Ea(V)], Some(2), PfxSel::PF3, w("m64"), "wrfsbase {e}", "system");
            it.group_mod = Some(true);
            it
        }),
        MapItem::Insn(0xAE, {
            let mut it = mi("wrgsbase_rv", &[Ea(V)], Some(3), PfxSel::PF3, w("m64"), "wrgsbase {e}", "system");
            it.group_mod = Some(true);
            it
        }),
        // CET-SS のユーザー命令。影響スタックはモデル化しない
        // ので意味論側は no-op/0 固定。INCSSP は /5 mod=11。
        MapItem::Insn(0xAE, gmp("incsspd_rv", 5, true, &[Ea(V)], PfxSel::PF3, "incssp {e}", "system")),
        // CLRSSBSY は /6 のメモリ形のみ。mod=11 の /6 は
        // UMONITOR 系として別途宣言する。
        MapItem::Insn(0xAE, gmp("clrssbsy_mq", 6, false, &[Ea(Q64)], PfxSel::PF3, "clrssbsy {e}", "system")),
        // WAITPKG（/6 mod=11、rm がオペランドレジスタ）。
        // UMONITOR はアドレス監視、UMWAIT は待機で CF=0 固定、
        // TPAUSE は仮想時間まで待つ — 単スレッド近似のスタブ。
        MapItem::Insn(0xAE, gmp("umonitor_rv", 6, true, &[Ea(V)], PfxSel::PF3, "umonitor {e}", "system")),
        MapItem::Insn(0xAE, gmp("tpause_rv", 6, true, &[Ea(V)], PfxSel::P66, "tpause {e}", "system")),
        MapItem::Insn(0xAE, gmp("umwait_rv", 6, true, &[Ea(V)], PfxSel::PF2, "umwait {e}", "system")),
        // キャッシュ制御。CLWB（66 /6 メモリ形）と
        // CLFLUSHOPT（66 /7 メモリ形）。キャッシュ階層は
        // モデル化しないので no-op。
        MapItem::Insn(0xAE, gmp("clwb_mb", 6, false, &[Ea(B8)], PfxSel::P66, "clwb {e}", "alu")),
        MapItem::Insn(0xAE, gmp("clflushopt_mb", 7, false, &[Ea(B8)], PfxSel::P66, "clflushopt {e}", "alu")),
        // fence は接頭辞なし。F3 0F AE は RDFSBASE/INCSSP/UMONITOR/
        // PTWRITE 系、66/F2 も別命令なので Plain で切る。
        MapItem::Insn(0xAE, gmp("lfence", 5, true, &[], PfxSel::Plain, "lfence", "alu")),
        MapItem::Insn(0xAE, gmp("mfence", 6, true, &[], PfxSel::Plain, "mfence", "alu")),
        // CLFLUSH は F2/F3 を無視して受理（llvm 実測）するが、
        // 66 は CLFLUSHOPT なので No66 で切る。
        MapItem::Insn(0xAE, gmp("clflush_mb", 7, false, &[Ea(B8)], PfxSel::No66, "clflush {e}", "alu")),
        MapItem::Insn(0xAE, gmp("sfence", 7, true, &[], PfxSel::Plain, "sfence", "alu")),
        // POPCNT（F3 0F B8）。接頭辞なしは TZCNT/JMPE で別物。
        MapItem::Insn(0xB8, mi("popcnt_gv_ev", &[Reg(V), Ea(V)], None, PfxSel::PF3, Pred::True, "popcnt {g}, {e}", "alu")),
        // CMPXCHG8B/16B（0F C7 /1、メモリ形のみ。REX.W で 16 バイト）。
        MapItem::Insn(0xC7, gm("cmpxchg8b_mq", 1, false, &[Ea(Q64)], "cmpxchg8b {e}", "alu")),
        // RDRAND/RDSEED（0F C7 /6 /7、レジスタ形のみ）。
        MapItem::Insn(
            0xC7,
            // F3 0F C7 /6 は 64 ビットで SENDUIPI（m32 では予約）、
            // F2 は予約。NP+66 のみ受理する。
            gmp("rdrand_rv", 6, true, &[Ea(V)], PfxSel::NoF2F3, "rdrand {e}", "alu"),
        ),
        MapItem::Insn(
            0xC7,
            // SENDUIPI（F3 0F C7 /6 mod=11、64 ビット専用）。
            // ユーザー割り込みの配送はモデル化しないので no-op。
            {
                let mut it = mi("senduipi_rv", &[Ea(V)], Some(6), PfxSel::PF3, w("m64"), "senduipi {e}", "system");
                it.group_mod = Some(true);
                it
            },
        ),
        MapItem::Insn(
            0xC7,
            // F3 0F C7 /7 は RDPID、F2 は予約。NP+66 のみ受理する。
            gmp("rdseed_rv", 7, true, &[Ea(V)], PfxSel::NoF2F3, "rdseed {e}", "alu"),
        ),
        MapItem::Insn(
            0xB0,
            n("cmpxchg_eb_gb", &[Ea(B8), Reg(B8)], "cmpxchg {e}, {g}", "alu"),
        ),
        MapItem::Insn(
            0xB1,
            n("cmpxchg_ev_gv", &[Ea(V), Reg(V)], "cmpxchg {e}, {g}", "alu"),
        ),
        MapItem::Insn(0xB9, n("ud1", &[Ea(V)], "ud1 {e}", "system")),
        // TZCNT（F3 0F BC、BMI1）。TZCNT 機能が無い CPU での
        // F3 0F BC は実機では BSF として動くが、BSF は NoF3 で
        // 排他しているのでこのモデルではデコード不能になる
        // （LZCNT/BSR と同じ既知の近似）。
        MapItem::Insn(
            0xBC,
            mi(
                "tzcnt_gv_ev",
                &[Reg(V), Ea(V)],
                None,
                PfxSel::PF3,
                w("bmi1"),
                "tzcnt {g}, {e}",
                "alu",
            ),
        ),
        MapItem::Insn(
            0xBC,
            mi(
                "bsf_gv_ev",
                &[Reg(V), Ea(V)],
                None,
                PfxSel::NoF3,
                Pred::True,
                "bsf {g}, {e}",
                "alu",
            ),
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
        // 0x1C は /0 mod!=11 が CLDEMOTE なので別途登録する。
        for byte in [0x18u8, 0x19, 0x1A, 0x1B, 0x1D] {
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
        // 0x1C の /0 mod=11 と /1-/7 はヒント NOP として残す
        // （/0 mod!=11 のみ CLDEMOTE）。
        m0f.push(MapItem::Insn(
            0x1C,
            if grp == 0 {
                gmp("nop_ev", 0, true, &[Ea(V)], PfxSel::Any, "nop {e}", "alu")
            } else {
                g("nop_ev", grp, &[Ea(V)], "nop {e}", "alu")
            },
        ));
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
        (0x63, "packsswb"),
        (0x64, "pcmpgtb"),
        (0x65, "pcmpgtw"),
        (0x66, "pcmpgtd"),
        (0x67, "packuswb"),
        (0x68, "punpckhbw"),
        (0x69, "punpckhwd"),
        (0x6A, "punpckhdq"),
        (0x6B, "packssdw"),
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
        // SSE4a（AMD 拡張）。EXTRQ の imm 形（66 78 /0）は r/m が
        // 宛先で length・index の順の ib×2、reg 形（66 79 /r）は
        // reg が宛先で制御は r/m ソース xmm の b[0]=length・
        // b[1]=index。INSERTQ は reg が宛先（F2 78/79 /r）、reg 形の
        // 制御はソース xmm の b[8]=length・b[9]=index。
        // MOVNTSS/MOVNTSD は F3/F2 2B のメモリ形のみ。
        MapItem::Insn(0x78, gmp("extrq_wv_ib_ib", 0, true, &[RmX, Imm(B8), Imm2(B8)], PfxSel::P66, "extrq {w}, {i}, {j}", "alu")),
        MapItem::Insn(0x79, mreg(mi("extrq_xv_wv", &[RegX, RmX], None, PfxSel::P66, Pred::True, "extrq {x}, {w}", "alu"))),
        MapItem::Insn(0x78, mreg(mi("insertq_xv_wv_ib_ib", &[RegX, RmX, Imm(B8), Imm2(B8)], None, PfxSel::PF2, Pred::True, "insertq {x}, {w}, {i}, {j}", "alu"))),
        MapItem::Insn(0x79, mreg(mi("insertq_xv_wv", &[RegX, RmX], None, PfxSel::PF2, Pred::True, "insertq {x}, {w}", "alu"))),
        MapItem::Insn(0x2B, mmem(mi("movntss_md_xv", &[Ea(D32), RegX], None, PfxSel::PF3, Pred::True, "movntss {e}, {x}", "store"))),
        MapItem::Insn(0x2B, mmem(mi("movntsd_mq_xv", &[Ea(Q64), RegX], None, PfxSel::PF2, Pred::True, "movntsd {e}, {x}", "store"))),
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
        // 3DNow! 系。FEMMS（0F 0E）は post-opcode ではなく
        // 独立した命令。0F 0F /r imm8 は操作選択バイトが
        // ModRM・SIB・変位の後に来るので postop 表に投げる。
        MapItem::Insn(0x0E, mi("femms", &[], None, PfxSel::Any, Pred::True, "femms", "alu")),
        MapItem::Map(0x0F, "map_3dnow".to_string(), w("dnow || dnowext")),
        // 3 バイトオペコードのサブマップ。
        MapItem::Map(0x38, "map_0f38".to_string(), Pred::True),
        MapItem::Map(0x3A, "map_0f3a".to_string(), Pred::True),
    ]);
    // ===== VEX エンコーディング（VEX.0F、AVX の基本形）=====
    // VEX 経路では同じ表を VEX.mmmmm=1 として再入するので、
    // このブロックは同じ m0f に並べる。vvvv がオペランドとして
    // 生きる形は `Vv` を ops に含め、`rv` は vvvv=1111b 必須の
    // 項目（2 オペランド形）に立てる。
    use VexL::*;
    // VZEROUPPER（L0）/VZEROALL（L1）。
    m0f.push(MapItem::Insn(
        0x77,
        vmx("vzeroupper", &[], PfxSel::Plain, L0, true, "vzeroupper", "alu"),
    ));
    m0f.push(MapItem::Insn(
        0x77,
        vmx("vzeroall", &[], PfxSel::Plain, L1, true, "vzeroall", "alu"),
    ));
    // データ移動のロード（10）/ストア（11）。整列なし形のみ
    // （VMOVAPS/VMOVAPD は B1b）。vvvv は未使用。
    for (sel, mn) in [(PfxSel::Plain, "vmovups"), (PfxSel::P66, "vmovupd")] {
        m0f.push(MapItem::Insn(
            0x10,
            vmx(&format!("{mn}_xv_wv"), &[RegX, RmX], sel, Any, true, "{op} {x}, {w}", "load"),
        ));
        m0f.push(MapItem::Insn(
            0x11,
            vmx(&format!("{mn}_wv_xv"), &[RmX, RegX], sel, Any, true, "{op} {w}, {x}", "store"),
        ));
    }
    // VMOVDQA/VMOVDQU（66/F3 の 6F/7F）。vvvv は未使用。
    for (sel, mn) in [(PfxSel::P66, "vmovdqa"), (PfxSel::PF3, "vmovdqu")] {
        m0f.push(MapItem::Insn(
            0x6F,
            vmx(&format!("{mn}_xv_wv"), &[RegX, RmX], sel, Any, true, "{op} {x}, {w}", "load"),
        ));
        m0f.push(MapItem::Insn(
            0x7F,
            vmx(&format!("{mn}_wv_xv"), &[RmX, RegX], sel, Any, true, "{op} {w}, {x}", "store"),
        ));
    }
    // VMOVDQU32/64（EVEX.F3.0F の 6F/7F）。W で 32/64 ビット要素を
    // 選ぶが、名前は W=0 形に寄せる（vpmaskmovd と同じ近似）。
    // 128/256 ビット形は avx512vl、512 ビット形は avx512f で
    // ゲートする（L'L 集合で項目を分ける）。
    for (op, ops, syn, tm) in [
        (0x6Fu8, [RegX, RmX], "{op} {x}, {w}", "load"),
        (0x7F, [RmX, RegX], "{op} {w}, {x}", "store"),
    ] {
        let mn = if op == 0x6F { "vmovdqu32_xv_wv" } else { "vmovdqu32_wv_xv" };
        m0f.push(MapItem::Insn(
            op,
            ex(mn, &ops, PfxSel::PF3, 0b100, true, syn, tm),
        ));
        let mut vl = ex(
            &format!("{mn}_vl"),
            &ops,
            PfxSel::PF3,
            0b011,
            true,
            syn,
            tm,
        );
        vl.when = Pred::Flag("avx512vl".to_string());
        m0f.push(MapItem::Insn(op, vl));
    }
    // EVEX パック演算（FVM：512 ビット形のみ）。浮動小数点の
    // VADDPS/PD は {er}/{sae} と埋め込み broadcast（m32bcst/
    // m64bcst）を、整数の VPADDD/Q は broadcast のみ許す。
    // `edisp` は broadcast 形の disp8 倍率（要素バイト数）。
    // W=0/1 の要素幅別項目は `wsel` で分ける。
    for (op, sel, mn, w, edisp, er) in [
        (0x58u8, PfxSel::Plain, "vaddps", false, 4u8, true),
        (0x58, PfxSel::P66, "vaddpd", true, 8, true),
        (0x59, PfxSel::Plain, "vmulps", false, 4, true),
        (0x59, PfxSel::P66, "vmulpd", true, 8, true),
        (0x5C, PfxSel::Plain, "vsubps", false, 4, true),
        (0x5C, PfxSel::P66, "vsubpd", true, 8, true),
        (0x5D, PfxSel::Plain, "vminps", false, 4, false),
        (0x5D, PfxSel::P66, "vminpd", true, 8, false),
        (0x5E, PfxSel::Plain, "vdivps", false, 4, true),
        (0x5E, PfxSel::P66, "vdivpd", true, 8, true),
        (0x5F, PfxSel::Plain, "vmaxps", false, 4, false),
        (0x5F, PfxSel::P66, "vmaxpd", true, 8, false),
        (0xFA, PfxSel::P66, "vpsubd", false, 4, false),
        (0xFB, PfxSel::P66, "vpsubq", true, 8, false),
        (0xFE, PfxSel::P66, "vpaddd", false, 4, false),
        (0xD4, PfxSel::P66, "vpaddq", true, 8, false),
    ] {
        let mut it = ex(
            &format!("{mn}_xv_hv_wv"),
            &[RegX, Vv, RmX],
            sel,
            0b100,
            false,
            "{op} {x}, {h}, {w}",
            "alu",
        );
        it.bcast = true;
        it.er = er;
        it.edisp = edisp;
        it.wsel = Some(w);
        m0f.push(MapItem::Insn(op, it));
    }
    // EVEX 論理演算（0F マップの DB/DF/EB/EF。0F38 ではない）。
    for (op, mn, w, edisp) in [
        (0xDBu8, "vpandd", false, 4u8),
        (0xDB, "vpandq", true, 8),
        (0xDF, "vpandnd", false, 4),
        (0xDF, "vpandnq", true, 8),
        (0xEB, "vpord", false, 4),
        (0xEB, "vporq", true, 8),
        (0xEF, "vpxord", false, 4),
        (0xEF, "vpxorq", true, 8),
    ] {
        let mut it = ex(
            &format!("{mn}_xv_hv_wv"),
            &[RegX, Vv, RmX],
            PfxSel::P66,
            0b100,
            false,
            "{op} {x}, {h}, {w}",
            "alu",
        );
        it.bcast = true;
        it.edisp = edisp;
        it.wsel = Some(w);
        m0f.push(MapItem::Insn(op, it));
    }
    // VSQRTPS/PD の EVEX 形（FVM、単項で vvvv=1111b 必須）。
    // b=1 はメモリ形の m32bcst/m64bcst とレジスタ形の {er}。
    for (sel, mn, w, edisp) in [
        (PfxSel::Plain, "vsqrtps", false, 4u8),
        (PfxSel::P66, "vsqrtpd", true, 8),
    ] {
        let mut it = ex(
            &format!("{mn}_xv_wv"),
            &[RegX, RmX],
            sel,
            0b100,
            true,
            "{op} {x}, {w}",
            "alu",
        );
        it.bcast = true;
        it.er = true;
        it.edisp = edisp;
        it.wsel = Some(w);
        m0f.push(MapItem::Insn(0x51, it));
    }
    // VMOVSS/VMOVSD（F3/F2 の 10/11、L0 のみ）。レジスタ形は
    // vvvv が第 2 ソースになる 3 オペランド形。メモリ形で
    // vvvv が 1111b 以外のときの #UD はモデル化しない。
    for (sel, mn) in [(PfxSel::PF3, "vmovss"), (PfxSel::PF2, "vmovsd")] {
        m0f.push(MapItem::Insn(
            0x10,
            vmx(&format!("{mn}_xv_hv_wv"), &[RegX, Vv, RmX], sel, L0, false, "{op} {x}, {h}, {w}", "load"),
        ));
        m0f.push(MapItem::Insn(
            0x11,
            vmx(&format!("{mn}_wv_hv_xv"), &[RmX, Vv, RegX], sel, L0, false, "{op} {w}, {h}, {x}", "store"),
        ));
    }
    // パック・スカラ浮動小数点演算（58-5F と 51 の SQRT）。
    // パック形は 128/256、スカラ形は L0。VSQRT のパック形は
    // 2 オペランドなので vvvv=1111b を要求する。
    for (b, mn) in [
        (0x51u8, "vsqrt"),
        (0x58, "vadd"),
        (0x59, "vmul"),
        (0x5C, "vsub"),
        (0x5D, "vmin"),
        (0x5E, "vdiv"),
        (0x5F, "vmax"),
    ] {
        let pk = b == 0x51;
        // SQRT のパック形だけ 2 オペランド（vvvv=1111b 必須）。
        let (suf, ops): (&str, &[OpKind]) = if pk {
            ("ps_xv_wv", &[RegX, RmX])
        } else {
            ("ps_xv_hv_wv", &[RegX, Vv, RmX])
        };
        let ps = format!("{mn}{suf}");
        let syn = if pk { "{op} {x}, {w}" } else { "{op} {x}, {h}, {w}" };
        m0f.push(MapItem::Insn(
            b,
            vmx(&ps, ops, PfxSel::Plain, Any, pk, syn, "alu"),
        ));
        let (suf, ops): (&str, &[OpKind]) = if pk {
            ("pd_xv_wv", &[RegX, RmX])
        } else {
            ("pd_xv_hv_wv", &[RegX, Vv, RmX])
        };
        let pd = format!("{mn}{suf}");
        m0f.push(MapItem::Insn(
            b,
            vmx(&pd, ops, PfxSel::P66, Any, pk, syn, "alu"),
        ));
        m0f.push(MapItem::Insn(
            b,
            vmx(&format!("{mn}ss_xv_hv_wv"), &[RegX, Vv, RmX], PfxSel::PF3, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        m0f.push(MapItem::Insn(
            b,
            vmx(&format!("{mn}sd_xv_hv_wv"), &[RegX, Vv, RmX], PfxSel::PF2, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // パック論理（54-57 の浮動小数点形と DB/DF/EB/EF の整数形）。
    // 整数形の 128 ビットは AVX、256 ビットは AVX2 なので
    // L0/L1 を別項目にして機能を分ける。
    for (b, sel, mn) in [
        (0x54u8, PfxSel::Plain, "vandps"),
        (0x54, PfxSel::P66, "vandpd"),
        (0x55, PfxSel::Plain, "vandnps"),
        (0x55, PfxSel::P66, "vandnpd"),
        (0x56, PfxSel::Plain, "vorps"),
        (0x56, PfxSel::P66, "vorpd"),
        (0x57, PfxSel::Plain, "vxorps"),
        (0x57, PfxSel::P66, "vxorpd"),
        (0xDB, PfxSel::P66, "vpand"),
        (0xDF, PfxSel::P66, "vpandn"),
        (0xEB, PfxSel::P66, "vpor"),
        (0xEF, PfxSel::P66, "vpxor"),
    ] {
        let int = b >= 0xDB;
        m0f.push(MapItem::Insn(
            b,
            vmx(&format!("{mn}_xv_hv_wv"), &[RegX, Vv, RmX], sel, if int { L0 } else { Any }, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        if int {
            m0f.push(MapItem::Insn(
                b,
                vax(&format!("{mn}_xv_hv_wv"), &[RegX, Vv, RmX], sel, L1, false, "{op} {x}, {h}, {w}", "alu"),
            ));
        }
    }
    // パック整数の 3 オペランド演算（66 0F の xmm 形に対応する
    // VEX 形）。128 ビットは AVX、256 ビットは AVX2。
    for (b, mn) in [
        (0x64u8, "vpcmpgtb"),
        (0x65, "vpcmpgtw"),
        (0x66, "vpcmpgtd"),
        (0x74, "vpcmpeqb"),
        (0x75, "vpcmpeqw"),
        (0x76, "vpcmpeqd"),
        (0xD4, "vpaddq"),
        (0xD5, "vpmullw"),
        (0xD8, "vpsubusb"),
        (0xD9, "vpsubusw"),
        (0xDA, "vpminub"),
        (0xDC, "vpaddusb"),
        (0xDD, "vpaddusw"),
        (0xDE, "vpmaxub"),
        (0xE0, "vpavgb"),
        (0xE3, "vpavgw"),
        (0xE4, "vpmulhuw"),
        (0xE5, "vpmulhw"),
        (0xE8, "vpsubsb"),
        (0xE9, "vpsubsw"),
        (0xEA, "vpminsw"),
        (0xEC, "vpaddsb"),
        (0xED, "vpaddsw"),
        (0xEE, "vpmaxsw"),
        (0xF8, "vpsubb"),
        (0xF9, "vpsubw"),
        (0xFA, "vpsubd"),
        (0xFB, "vpsubq"),
        (0xFC, "vpaddb"),
        (0xFD, "vpaddw"),
        (0xFE, "vpaddd"),
    ] {
        let n = format!("{mn}_xv_hv_wv");
        m0f.push(MapItem::Insn(
            b,
            vmx(&n, &[RegX, Vv, RmX], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        m0f.push(MapItem::Insn(
            b,
            vax(&n, &[RegX, Vv, RmX], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // パックシフト（xmm/m128 カウント形）。カウントは第 2
    // ソースの下位 64 ビットだけを使う。
    for (b, mn) in [
        (0xD1u8, "vpsrlw"),
        (0xD2, "vpsrld"),
        (0xD3, "vpsrlq"),
        (0xE1, "vpsraw"),
        (0xE2, "vpsrad"),
        (0xF1, "vpsllw"),
        (0xF2, "vpslld"),
        (0xF3, "vpsllq"),
    ] {
        let n = format!("{mn}_xv_hv_wv");
        m0f.push(MapItem::Insn(
            b,
            vmx(&n, &[RegX, Vv, RmX], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        m0f.push(MapItem::Insn(
            b,
            vax(&n, &[RegX, Vv, RmX], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // グループ即値シフト（0F 71-73 の 66 形）。r/m がソースで
    // vvvv が宛先（Op/En B）。
    for (b, grp, mn) in [
        (0x71u8, 2u8, "vpsrlw"),
        (0x71, 4, "vpsraw"),
        (0x71, 6, "vpsllw"),
        (0x72, 2, "vpsrld"),
        (0x72, 4, "vpsrad"),
        (0x72, 6, "vpslld"),
        (0x73, 2, "vpsrlq"),
        (0x73, 3, "vpsrldq"),
        (0x73, 6, "vpsllq"),
        (0x73, 7, "vpslldq"),
    ] {
        let n = format!("{mn}_hv_wv_ib");
        for it in [
            vmx(&n, &[Vv, RmX, Imm(B8)], PfxSel::P66, L0, false, "{op} {h}, {w}, {i}", "alu"),
            vax(&n, &[Vv, RmX, Imm(B8)], PfxSel::P66, L1, false, "{op} {h}, {w}, {i}", "alu"),
        ] {
            let mut it = it;
            it.group = Some(grp);
            it.group_mod = Some(true);
            m0f.push(MapItem::Insn(b, it));
        }
    }
    // データ移動（28/29 の整列形と 12/13、16/17 の半分形）。
    // VMOVAPS/VMOVAPD は 128/256。vvvv は未使用。
    for (sel, mn) in [(PfxSel::Plain, "vmovaps"), (PfxSel::P66, "vmovapd")] {
        m0f.push(MapItem::Insn(
            0x28,
            vmx(&format!("{mn}_xv_wv"), &[RegX, RmX], sel, Any, true, "{op} {x}, {w}", "load"),
        ));
        m0f.push(MapItem::Insn(
            0x29,
            vmx(&format!("{mn}_wv_xv"), &[RmX, RegX], sel, Any, true, "{op} {w}, {x}", "store"),
        ));
    }
    // VMOVLPS/VMOVLPD（12、L0）。メモリ形は 3 オペランド、
    // mod=11 は VMOVHLPS。VMOVDDUP（F2、Any）と VMOVSLDUP
    // （F3、Any）は 2 オペランド。
    for (sel, mn) in [(PfxSel::Plain, "vmovlps"), (PfxSel::P66, "vmovlpd")] {
        m0f.push(MapItem::Insn(
            0x12,
            mmem(vmx(&format!("{mn}_xv_hv_wv"), &[RegX, Vv, RmX], sel, L0, false, "{op} {x}, {h}, {w}", "load")),
        ));
        m0f.push(MapItem::Insn(
            0x13,
            mmem(vmx(&format!("{mn}_wv_xv"), &[RmX, RegX], sel, L0, true, "{op} {w}, {x}", "store")),
        ));
    }
    m0f.push(MapItem::Insn(
        0x12,
        mreg(vmx("vmovhlps_xv_hv_wv", &[RegX, Vv, RmX], PfxSel::Plain, L0, false, "{op} {x}, {h}, {w}", "alu")),
    ));
    m0f.push(MapItem::Insn(
        0x12,
        vmx("vmovddup_xv_wv", &[RegX, RmX], PfxSel::PF2, Any, true, "{op} {x}, {w}", "load"),
    ));
    m0f.push(MapItem::Insn(
        0x12,
        vmx("vmovsldup_xv_wv", &[RegX, RmX], PfxSel::PF3, Any, true, "{op} {x}, {w}", "load"),
    ));
    // VMOVHPS/VMOVHPD（16、L0）。メモリ形は 3 オペランド、
    // mod=11 は VMOVLHPS。VMOVSHDUP（F3、Any）は 2 オペランド。
    for (sel, mn) in [(PfxSel::Plain, "vmovhps"), (PfxSel::P66, "vmovhpd")] {
        m0f.push(MapItem::Insn(
            0x16,
            mmem(vmx(&format!("{mn}_xv_hv_wv"), &[RegX, Vv, RmX], sel, L0, false, "{op} {x}, {h}, {w}", "load")),
        ));
        m0f.push(MapItem::Insn(
            0x17,
            mmem(vmx(&format!("{mn}_wv_xv"), &[RmX, RegX], sel, L0, true, "{op} {w}, {x}", "store")),
        ));
    }
    m0f.push(MapItem::Insn(
        0x16,
        mreg(vmx("vmovlhps_xv_hv_wv", &[RegX, Vv, RmX], PfxSel::Plain, L0, false, "{op} {x}, {h}, {w}", "alu")),
    ));
    m0f.push(MapItem::Insn(
        0x16,
        vmx("vmovshdup_xv_wv", &[RegX, RmX], PfxSel::PF3, Any, true, "{op} {x}, {w}", "load"),
    ));
    // VMOVMSKPS/VMOVMSKPD（50、Any）と VPMOVMSKB（D7）。
    // VPMOVMSKB の 256 ビット形は AVX2。
    for (sel, mn) in [(PfxSel::Plain, "vmovmskps"), (PfxSel::P66, "vmovmskpd")] {
        m0f.push(MapItem::Insn(
            0x50,
            mreg(vmx(&format!("{mn}_gv_wv"), &[Reg(V), RmX], sel, Any, true, "{op} {g}, {w}", "alu")),
        ));
    }
    m0f.push(MapItem::Insn(
        0xD7,
        mreg(vmx("vpmovmskb_gv_wv", &[Reg(V), RmX], PfxSel::P66, L0, true, "{op} {g}, {w}", "alu")),
    ));
    m0f.push(MapItem::Insn(
        0xD7,
        mreg(vax("vpmovmskb_gv_wv", &[Reg(V), RmX], PfxSel::P66, L1, true, "{op} {g}, {w}", "alu")),
    ));
    // VMOVNTPS/VMOVNTPD（2B、メモリ形のみ）と VMOVNTDQ（66 E7、
    // メモリ形のみ）。VMOVNTDQ の 256 ビット形は AVX2。
    for (sel, mn) in [(PfxSel::Plain, "vmovntps"), (PfxSel::P66, "vmovntpd")] {
        m0f.push(MapItem::Insn(
            0x2B,
            mmem(vmx(&format!("{mn}_wv_xv"), &[RmX, RegX], sel, Any, true, "{op} {w}, {x}", "store")),
        ));
    }
    m0f.push(MapItem::Insn(
        0xE7,
        mmem(vmx("vmovntdq_wv_xv", &[RmX, RegX], PfxSel::P66, L0, true, "{op} {w}, {x}", "store")),
    ));
    m0f.push(MapItem::Insn(
        0xE7,
        mmem(vax("vmovntdq_wv_xv", &[RmX, RegX], PfxSel::P66, L1, true, "{op} {w}, {x}", "store")),
    ));
    // VLDMXCSR/VSTMXCSR（AE /2、/3 のメモリ形。L0）。
    for (grp, mn, tm) in [(2u8, "vldmxcsr_md", "load"), (3, "vstmxcsr_md", "store")] {
        let mut it = vmx(mn, &[Ea(D32)], PfxSel::Plain, L0, true, "{op} {e}", tm);
        it.group = Some(grp);
        it.group_mod = Some(false);
        m0f.push(MapItem::Insn(0xAE, it));
    }
    // VMOVD/VMOVQ（66 6E/7E と F3 7E、66 D6）。vvvv は未使用。
    m0f.push(MapItem::Insn(
        0x6E,
        vmx("vmovd_xv_ev", &[RegX, Ea(V)], PfxSel::P66, L0, true, "{op} {x}, {e}", "load"),
    ));
    m0f.push(MapItem::Insn(
        0x7E,
        vmx("vmovd_ev_xv", &[Ea(V), RegX], PfxSel::P66, L0, true, "{op} {e}, {x}", "store"),
    ));
    m0f.push(MapItem::Insn(
        0x7E,
        vmx("vmovq_xv_wv", &[RegX, RmX], PfxSel::PF3, L0, true, "{op} {x}, {w}", "load"),
    ));
    m0f.push(MapItem::Insn(
        0xD6,
        vmx("vmovq_wv_xv", &[RmX, RegX], PfxSel::P66, L0, true, "{op} {w}, {x}", "store"),
    ));
    // VCMPPS/VCMPPD/VCMPSS/VCMPSD（C2 + imm8）。
    for (sel, mn, l) in [
        (PfxSel::Plain, "vcmpps", Any),
        (PfxSel::P66, "vcmppd", Any),
        (PfxSel::PF3, "vcmpss", L0),
        (PfxSel::PF2, "vcmpsd", L0),
    ] {
        m0f.push(MapItem::Insn(
            0xC2,
            vmx(&format!("{mn}_xv_hv_wv_ib"), &[RegX, Vv, RmX, Imm(B8)], sel, l, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
    }
    // VPMULUDQ/VPMADDWD/VPSADBW（F4-F6）。128 は AVX、256 は AVX2。
    for (b, mn) in [(0xF4u8, "vpmuludq"), (0xF5, "vpmaddwd"), (0xF6, "vpsadbw")] {
        let n = format!("{mn}_xv_hv_wv");
        m0f.push(MapItem::Insn(
            b,
            vmx(&n, &[RegX, Vv, RmX], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        m0f.push(MapItem::Insn(
            b,
            vax(&n, &[RegX, Vv, RmX], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // VCVT 系。5A: ps2pd(NP)/pd2ps(66)/ss2sd(F3)/sd2ss(F2)。スカラ形は
    // 3 オペランドで vvvv ソースへマージする。
    for (sel, mn, ops, l, rv) in [
        (PfxSel::Plain, "vcvtps2pd", &[RegX, RmX][..], Any, true),
        (PfxSel::P66, "vcvtpd2ps", &[RegX, RmX][..], Any, true),
        (PfxSel::PF3, "vcvtss2sd", &[RegX, Vv, RmX][..], L0, false),
        (PfxSel::PF2, "vcvtsd2ss", &[RegX, Vv, RmX][..], L0, false),
    ] {
        let n = if rv {
            format!("{mn}_xv_wv")
        } else {
            format!("{mn}_xv_hv_wv")
        };
        let syn = if rv {
            "{op} {x}, {w}"
        } else {
            "{op} {x}, {h}, {w}"
        };
        m0f.push(MapItem::Insn(0x5A, vmx(&n, ops, sel, l, rv, syn, "alu")));
    }
    // 5B: dq2ps(NP)/ps2dq(66)/tps2dq(F3)。E6: pd2dq(F2)/tpd2dq(66)/dq2pd(F3)。
    for (byte, sel, mn) in [
        (0x5Bu8, PfxSel::Plain, "vcvtdq2ps"),
        (0x5B, PfxSel::P66, "vcvtps2dq"),
        (0x5B, PfxSel::PF3, "vcvttps2dq"),
        (0xE6, PfxSel::PF2, "vcvtpd2dq"),
        (0xE6, PfxSel::P66, "vcvttpd2dq"),
        (0xE6, PfxSel::PF3, "vcvtdq2pd"),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            vmx(&format!("{mn}_xv_wv"), &[RegX, RmX], sel, Any, true, "{op} {x}, {w}", "alu"),
        ));
    }
    // 同項目のレガシー xmm 形（F4-F6 と同じくマップ駆動に寄せる）。
    for (byte, sel, mn) in [
        (0x5Bu8, PfxSel::Plain, "cvtdq2ps"),
        (0x5B, PfxSel::P66, "cvtps2dq"),
        (0x5B, PfxSel::PF3, "cvttps2dq"),
        (0xE6, PfxSel::PF2, "cvtpd2dq"),
        (0xE6, PfxSel::P66, "cvttpd2dq"),
        (0xE6, PfxSel::PF3, "cvtdq2pd"),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            mi(&format!("{mn}_xv_wv"), &[RegX, RmX], None, sel, Pred::True, "{op} {x}, {w}", "alu"),
        ));
    }
    // 2A: VCVTSI2SS（F3）/VCVTSI2SD（F2）。L0・3 オペランド。
    for (sel, mn) in [(PfxSel::PF3, "vcvtsi2ss"), (PfxSel::PF2, "vcvtsi2sd")] {
        m0f.push(MapItem::Insn(
            0x2A,
            vmx(&format!("{mn}_xv_hv_ev"), &[RegX, Vv, Ea(V)], sel, L0, false, "{op} {x}, {h}, {e}", "alu"),
        ));
    }
    // 2C/2D: f→GPR。vvvv は未使用。
    for (byte, sel, mn) in [
        (0x2Cu8, PfxSel::PF3, "vcvttss2si"),
        (0x2C, PfxSel::PF2, "vcvttsd2si"),
        (0x2D, PfxSel::PF3, "vcvtss2si"),
        (0x2D, PfxSel::PF2, "vcvtsd2si"),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            vmx(&format!("{mn}_gv_wv"), &[Reg(V), RmX], sel, L0, true, "{op} {g}, {w}", "alu"),
        ));
    }
    // C6: VSHUFPS/VSHUFPD（3 オペランド＋imm8、Any）。
    for (sel, mn) in [(PfxSel::Plain, "vshufps"), (PfxSel::P66, "vshufpd")] {
        m0f.push(MapItem::Insn(
            0xC6,
            vmx(&format!("{mn}_xv_hv_wv_ib"), &[RegX, Vv, RmX, Imm(B8)], sel, Any, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
    }
    // 14/15: VUNPCKL*/VUNPCKH*（3 オペランド、Any）。
    for (byte, sel, mn) in [
        (0x14u8, PfxSel::Plain, "vunpcklps"),
        (0x14, PfxSel::P66, "vunpcklpd"),
        (0x15, PfxSel::Plain, "vunpckhps"),
        (0x15, PfxSel::P66, "vunpckhpd"),
    ] {
        m0f.push(MapItem::Insn(
            byte,
            vmx(&format!("{mn}_xv_hv_wv"), &[RegX, Vv, RmX], sel, Any, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // 70: VPSHUFD（66）/VPSHUFLW（F2）/VPSHUFHW（F3）。128 は AVX、
    // 256 は AVX2。
    for (sel, mn) in [(PfxSel::P66, "vpshufd"), (PfxSel::PF2, "vpshuflw"), (PfxSel::PF3, "vpshufhw")] {
        let n = format!("{mn}_xv_wv_ib");
        m0f.push(MapItem::Insn(
            0x70,
            vmx(&n, &[RegX, RmX, Imm(B8)], sel, L0, true, "{op} {x}, {w}, {i}", "alu"),
        ));
        m0f.push(MapItem::Insn(
            0x70,
            vax(&n, &[RegX, RmX, Imm(B8)], sel, L1, true, "{op} {x}, {w}, {i}", "alu"),
        ));
    }
    // 60-6D: VPUNPCK*/VPACK*（3 オペランド。128 は AVX、256 は AVX2）。
    for (byte, mn) in [
        (0x60u8, "vpunpcklbw"),
        (0x61, "vpunpcklwd"),
        (0x62, "vpunpckldq"),
        (0x63, "vpacksswb"),
        (0x67, "vpackuswb"),
        (0x68, "vpunpckhbw"),
        (0x69, "vpunpckhwd"),
        (0x6A, "vpunpckhdq"),
        (0x6B, "vpackssdw"),
        (0x6C, "vpunpcklqdq"),
        (0x6D, "vpunpckhqdq"),
    ] {
        let n = format!("{mn}_xv_hv_wv");
        m0f.push(MapItem::Insn(
            byte,
            vmx(&n, &[RegX, Vv, RmX], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        m0f.push(MapItem::Insn(
            byte,
            vax(&n, &[RegX, Vv, RmX], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // VPINSRW（0F C4、3 オペランド）と VPEXTRW（0F C5、レジスタ形のみ）。
    m0f.push(MapItem::Insn(
        0xC4,
        vmx(
            "vpinsrw_xv_hv_ew_ib",
            &[RegX, Vv, Ea(W16), Imm(B8)],
            PfxSel::P66,
            L0,
            false,
            "{op} {x}, {h}, {e}, {i}",
            "alu",
        ),
    ));
    m0f.push(MapItem::Insn(
        0xC5,
        mreg(vmx(
            "vpextrw_gv_wv_ib",
            &[Reg(V), RmX, Imm(B8)],
            PfxSel::P66,
            L0,
            true,
            "{op} {g}, {w}, {i}",
            "alu",
        )),
    ));
    m.maps.push(MapDecl {
        name: "map_0f".to_string(),
        vex_code: Some(1),
        postop: false,
        items: m0f,
    });
    build_map_0f38(m);
    build_map_0f3a(m);
    build_map_3dnow(m);
}

/// 3DNow!（0F 0F /r imm8）。ModRM（と SIB・変位）の後に来る
/// 選択バイトが操作を決める postop 表。オペランドは全て
/// `mm, mm/m64`（P = ModRM.reg、Q = r/m）の 2 形。
/// PF2IW/PFNACC/PFPNACC/PI2FW/PSWAPD は拡張 3DNow!（`dnowext`）で、
/// それ以外は基本 3DNow!（`dnow`）。ゲートは `named_gate`。
fn build_map_3dnow(m: &mut Model) {
    use OpKind::*;
    let pq_qq: &[OpKind] = &[RegM, RmM];
    let mut v: Vec<MapItem> = Vec::new();
    let mut d = |op: u8, name: &str, timing: &str| {
        v.push(MapItem::Insn(
            op,
            mi(
                &format!("{name}_pq_qq"),
                pq_qq,
                None,
                PfxSel::Any,
                Pred::True,
                &format!("{name} {{p}}, {{q}}"),
                timing,
            ),
        ));
    };
    // 基本 3DNow!（K6-2）。
    d(0x0D, "pi2fd", "alu");
    d(0x1D, "pf2id", "alu");
    d(0x8A, "pfnacc", "alu");
    d(0x8E, "pfpnacc", "alu");
    d(0x90, "pfcmpge", "alu");
    d(0x94, "pfmin", "alu");
    d(0x96, "pfrcp", "alu");
    d(0x97, "pfrsqrt", "alu");
    d(0x9A, "pfsub", "alu");
    d(0x9E, "pfadd", "alu");
    d(0xA0, "pfcmpgt", "alu");
    d(0xA4, "pfmax", "alu");
    d(0xA6, "pfrcpit1", "alu");
    d(0xA7, "pfrsqit1", "alu");
    d(0xAA, "pfsubr", "alu");
    d(0xAE, "pfacc", "alu");
    d(0xB0, "pfcmpeq", "alu");
    d(0xB4, "pfmul", "alu");
    d(0xB6, "pfrcpit2", "alu");
    d(0xB7, "pmulhrw", "alu");
    d(0xBF, "pavgusb", "alu");
    // 拡張 3DNow!（Athlon 以降）。
    d(0x0C, "pi2fw", "alu");
    d(0x1C, "pf2iw", "alu");
    d(0xBB, "pswapd", "alu");
    m.maps.push(MapDecl {
        name: "map_3dnow".to_string(),
        vex_code: None,
        postop: true,
        items: v,
    });
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
    // CET-SS の WRSS/WRUSS（メモリ形のみ）。WRSS は NP 0F 38 F6
    // （mod=11 は予約）、WRUSS は 66 0F 38 F5（mod=11 は予約）。
    // 影響スタックはモデル化しないので通常ストアとして扱う。
    {
        let mut it = mi(
            "wrssd_mv_gv",
            &[Ea(V), Reg(V)],
            None,
            PfxSel::Plain,
            Pred::True,
            "wrss {e}, {g}",
            "store",
        );
        it.group_mod = Some(false);
        v.push(MapItem::Insn(0xF6, it));
    }
    {
        let mut it = mi(
            "wrussd_mv_gv",
            &[Ea(V), Reg(V)],
            None,
            PfxSel::P66,
            Pred::True,
            "wruss {e}, {g}",
            "store",
        );
        it.group_mod = Some(false);
        v.push(MapItem::Insn(0xF5, it));
    }
    // MOVDIR/ENQCMD（いずれもメモリ形のみ、mod=11 は別用途）。
    // MOVDIRI はダイレクトストア、MOVDIR64B は 64 バイトコピー、
    // ENQCMD/ENQCMDS はデバイス投入。
    {
        let mut it = mi(
            "movdiri_mv_gv",
            &[Ea(V), Reg(V)],
            None,
            PfxSel::Plain,
            Pred::True,
            "movdiri {e}, {g}",
            "store",
        );
        it.group_mod = Some(false);
        v.push(MapItem::Insn(0xF9, it));
    }
    for (name, pfx, syn) in [
        ("enqcmd_gv_mv", PfxSel::PF2, "enqcmd {g}, {e}"),
        ("enqcmds_gv_mv", PfxSel::PF3, "enqcmds {g}, {e}"),
    ] {
        // 第1オペランドは配送先アドレスを持つレジスタ、第2は
        // 64 バイトのコマンドを読むメモリ。
        let mut it = mi(name, &[Reg(V), Ea(Q64)], None, pfx, Pred::True, syn, "load");
        it.group_mod = Some(false);
        v.push(MapItem::Insn(0xF8, it));
    }
    {
        let mut it = mi(
            "movdir64b_gv_mv",
            &[Reg(V), Ea(Q64)],
            None,
            PfxSel::P66,
            Pred::True,
            "movdir64b {g}, {e}",
            "load",
        );
        it.group_mod = Some(false);
        v.push(MapItem::Insn(0xF8, it));
    }
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
    // AVX/AVX2 の整数演算（VEX.mmmmm=2）。128 ビットは AVX、
    // 256 ビットは AVX2。
    use VexL::{Any, L0, L1};
    for (op, mn) in [
        (0x08u8, "vpsignb"),
        (0x09, "vpsignw"),
        (0x0A, "vpsignd"),
        (0x29, "vpcmpeqq"),
        (0x37, "vpcmpgtq"),
        (0x38, "vpminsb"),
        (0x39, "vpminsd"),
        (0x3A, "vpminuw"),
        (0x3B, "vpminud"),
        (0x3C, "vpmaxsb"),
        (0x3D, "vpmaxsd"),
        (0x3E, "vpmaxuw"),
        (0x3F, "vpmaxud"),
        (0x40, "vpmulld"),
    ] {
        let n = format!("{mn}_xv_hv_wv");
        v.push(MapItem::Insn(
            op,
            vmx(&n, &[RegX, Vv, RmX], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        v.push(MapItem::Insn(
            op,
            vax(&n, &[RegX, Vv, RmX], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // SSSE3 系の 3 オペランド VEX 形（PHADD/PHSUB/PMADDUBSW/
    // PMULHRSW）。128 ビットは AVX、256 ビットは AVX2。
    for (op, mn) in [
        (0x00u8, "vpshufb"),
        (0x01, "vphaddw"),
        (0x02, "vphaddd"),
        (0x03, "vphaddsw"),
        (0x04, "vpmaddubsw"),
        (0x05, "vphsubw"),
        (0x06, "vphsubd"),
        (0x07, "vphsubsw"),
        (0x0B, "vpmulhrsw"),
        (0x2B, "vpackusdw"),
    ] {
        let n = format!("{mn}_xv_hv_wv");
        v.push(MapItem::Insn(
            op,
            vmx(&n, &[RegX, Vv, RmX], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}", "alu"),
        ));
        v.push(MapItem::Insn(
            op,
            vax(&n, &[RegX, Vv, RmX], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}", "alu"),
        ));
    }
    // VPTEST（2 オペランド、vvvv 未使用）。256 ビット形は AVX2。
    v.push(MapItem::Insn(
        0x17,
        vmx("vptest_xv_wv", &[RegX, RmX], PfxSel::P66, L0, true, "{op} {x}, {w}", "alu"),
    ));
    v.push(MapItem::Insn(
        0x17,
        vax("vptest_xv_wv", &[RegX, RmX], PfxSel::P66, L1, true, "{op} {x}, {w}", "alu"),
    ));
    // VTESTPS/VTESTPD（2 オペランド。256 ビット形も AVX）。
    v.push(MapItem::Insn(
        0x0E,
        vmx("vtestps_xv_wv", &[RegX, RmX], PfxSel::P66, Any, true, "{op} {x}, {w}", "alu"),
    ));
    v.push(MapItem::Insn(
        0x0F,
        vmx("vtestpd_xv_wv", &[RegX, RmX], PfxSel::P66, Any, true, "{op} {x}, {w}", "alu"),
    ));
    // VPABSB/W/D（単項、vvvv 未使用）。256 ビット形は AVX2。
    for (op, mn) in [(0x1Cu8, "vpabsb"), (0x1D, "vpabsw"), (0x1E, "vpabsd")] {
        let n = format!("{mn}_xv_wv");
        v.push(MapItem::Insn(
            op,
            vmx(&n, &[RegX, RmX], PfxSel::P66, L0, true, "{op} {x}, {w}", "alu"),
        ));
        v.push(MapItem::Insn(
            op,
            vax(&n, &[RegX, RmX], PfxSel::P66, L1, true, "{op} {x}, {w}", "alu"),
        ));
    }
    // VPHMINPOSUW（単項、vvvv 未使用。128 ビットのみ）。
    v.push(MapItem::Insn(
        0x41,
        vmx("vphminposuw_xv_wv", &[RegX, RmX], PfxSel::P66, L0, true, "{op} {x}, {w}", "alu"),
    ));
    // VPERMILPS/VPERMILPD の可変形（3 オペランド。256 ビットも AVX）。
    for (op, mn) in [(0x0Cu8, "vpermilps"), (0x0D, "vpermilpd")] {
        v.push(MapItem::Insn(
            op,
            vmx(
                &format!("{mn}_xv_hv_wv"),
                &[RegX, Vv, RmX],
                PfxSel::P66,
                Any,
                false,
                "{op} {x}, {h}, {w}",
                "alu",
            ),
        ));
    }
    // VPERMPS・VPERMD（AVX2・256 ビットのみ）。
    for (op, mn) in [(0x16u8, "vpermps"), (0x36, "vpermd")] {
        v.push(MapItem::Insn(
            op,
            vax(
                &format!("{mn}_xv_hv_wv"),
                &[RegX, Vv, RmX],
                PfxSel::P66,
                L1,
                false,
                "{op} {x}, {h}, {w}",
                "alu",
            ),
        ));
    }
    // VBROADCASTSS（Any）・VBROADCASTSD（256 のみ）。メモリ形は AVX、
    // レジスタ形は AVX2。
    for (op, mn, l) in [
        (0x18u8, "vbroadcastss", Any),
        (0x19, "vbroadcastsd", L1),
    ] {
        let nm = format!("{mn}_xv_wv");
        let nr = format!("{mn}_xv_xv");
        v.push(MapItem::Insn(
            op,
            mmem(vmx(&nm, &[RegX, RmX], PfxSel::P66, l, true, "{op} {x}, {w}", "load")),
        ));
        v.push(MapItem::Insn(
            op,
            mreg(vax(&nr, &[RegX, RmX], PfxSel::P66, l, true, "{op} {x}, {w}", "alu")),
        ));
    }
    // VBROADCASTF128（メモリ形のみ・256 ビットのみ）。
    v.push(MapItem::Insn(
        0x1A,
        mmem(vmx(
            "vbroadcastf128_xv_wv",
            &[RegX, RmX],
            PfxSel::P66,
            L1,
            true,
            "{op} {x}, {w}",
            "load",
        )),
    ));
    // VPMOVSX*/VPMOVZX*（128 ビットは AVX、256 ビットは AVX2）。
    for (op, mn) in [
        (0x20u8, "vpmovsxbw"),
        (0x21, "vpmovsxbd"),
        (0x22, "vpmovsxbq"),
        (0x23, "vpmovsxwd"),
        (0x24, "vpmovsxwq"),
        (0x25, "vpmovsxdq"),
        (0x30, "vpmovzxbw"),
        (0x31, "vpmovzxbd"),
        (0x32, "vpmovzxbq"),
        (0x33, "vpmovzxwd"),
        (0x34, "vpmovzxwq"),
        (0x35, "vpmovzxdq"),
    ] {
        let n = format!("{mn}_xv_wv");
        v.push(MapItem::Insn(
            op,
            vmx(&n, &[RegX, RmX], PfxSel::P66, L0, true, "{op} {x}, {w}", "alu"),
        ));
        v.push(MapItem::Insn(
            op,
            vax(&n, &[RegX, RmX], PfxSel::P66, L1, true, "{op} {x}, {w}", "alu"),
        ));
    }
    // VMOVNTDQA（メモリ形のみ。256 ビット形は AVX2）。
    v.push(MapItem::Insn(
        0x2A,
        mmem(vmx(
            "vmovntdqa_xv_wv",
            &[RegX, RmX],
            PfxSel::P66,
            L0,
            true,
            "{op} {x}, {w}",
            "load",
        )),
    ));
    v.push(MapItem::Insn(
        0x2A,
        mmem(vax(
            "vmovntdqa_xv_wv",
            &[RegX, RmX],
            PfxSel::P66,
            L1,
            true,
            "{op} {x}, {w}",
            "load",
        )),
    ));
    // VPBROADCASTB/W/D/Q（AVX2。レジスタ・メモリ両形）。
    for (op, mn) in [
        (0x78u8, "vpbroadcastb"),
        (0x79, "vpbroadcastw"),
        (0x58, "vpbroadcastd"),
        (0x59, "vpbroadcastq"),
    ] {
        v.push(MapItem::Insn(
            op,
            vax(
                &format!("{mn}_xv_wv"),
                &[RegX, RmX],
                PfxSel::P66,
                Any,
                true,
                "{op} {x}, {w}",
                "load",
            ),
        ));
    }
    // VBROADCASTI128（AVX2・メモリ形のみ・256 ビットのみ）。
    v.push(MapItem::Insn(
        0x5A,
        mmem(vax(
            "vbroadcasti128_xv_wv",
            &[RegX, RmX],
            PfxSel::P66,
            L1,
            true,
            "{op} {x}, {w}",
            "load",
        )),
    ));
    // VMASKMOVPS/PD（AVX）・VPMASKMOVD/Q（AVX2）。ロード形は
    // 0x2C/0x2D・0x8C、ストア形は 0x2E/0x2F・0x8E。VPMASKMOV の
    // Q 形は VEX.W で共用（`d.rex` で切替）。メモリ形のみ。
    for (op, mn) in [(0x2Cu8, "vmaskmovps"), (0x2D, "vmaskmovpd")] {
        v.push(MapItem::Insn(
            op,
            mmem(vmx(
                &format!("{mn}_xv_hv_wv"),
                &[RegX, Vv, RmX],
                PfxSel::P66,
                Any,
                false,
                "{op} {x}, {h}, {w}",
                "load",
            )),
        ));
        v.push(MapItem::Insn(
            op + 2,
            mmem(vmx(
                &format!("{mn}_wv_hv_xv"),
                &[RmX, Vv, RegX],
                PfxSel::P66,
                Any,
                false,
                "{op} {w}, {h}, {x}",
                "store",
            )),
        ));
    }
    v.push(MapItem::Insn(
        0x8C,
        mmem(vax(
            "vpmaskmovd_xv_hv_wv",
            &[RegX, Vv, RmX],
            PfxSel::P66,
            Any,
            false,
            "{op} {x}, {h}, {w}",
            "load",
        )),
    ));
    v.push(MapItem::Insn(
        0x8E,
        mmem(vax(
            "vpmaskmovd_wv_hv_xv",
            &[RmX, Vv, RegX],
            PfxSel::P66,
            Any,
            false,
            "{op} {w}, {h}, {x}",
            "store",
        )),
    ));
    // VGATHERDPS/QPS・VPGATHERDD/QD（W=0）とその W=1 版
    // （DPD/DQ・QPD/QQ）はオペコード共用。index 幅は
    // オペコード bit0、収集幅は VEX.W。VSIB メモリ形のみで、
    // `Rm::Mem.a` は使わず意味論が `decode::vsib` で再構成する。
    // W=0 版は 128 ビットのみだが、W ゲートがないので L=1 の
    // W=0 エンコードも受理する近似。
    for (op, mn) in [
        (0x90u8, "vpgatherdd"),
        (0x91, "vpgatherqd"),
        (0x92, "vgatherdps"),
        (0x93, "vgatherqps"),
    ] {
        v.push(MapItem::Insn(
            op,
            mmem(vax(
                &format!("{mn}_xv_wv_hv"),
                &[RegX, RmX, Vv],
                PfxSel::P66,
                Any,
                false,
                "{op} {x}, {w}, {h}",
                "load",
            )),
        ));
    }
    // BMI1/BMI2（VEX の GPR 演算）。幅は VEX.W（64 ビット
    // モードのみ、他は 32）。L=0。vvvv は GPR を指す。
    // ANDN Gv, By, Ev（F2 NP）。
    v.push(MapItem::Insn(
        0xF2,
        vmx("andn_gv_by_ev", &[Reg(V), Vv, Ea(V)], PfxSel::Plain, L0, false, "andn {g}, {h}, {e}", "alu"),
    ));
    // BLSR/BLSMSK/BLSI（F3 /1 /2 /3）。宛先は vvvv。
    for (grp, mn) in [(1u8, "blsr"), (2, "blsmsk"), (3, "blsi")] {
        let mut it = vmx(&format!("{mn}_by_ev"), &[Vv, Ea(V)], PfxSel::Plain, L0, false, "{op} {h}, {e}", "alu");
        it.group = Some(grp);
        v.push(MapItem::Insn(0xF3, it));
    }
    // BZHI（F5 NP）・PDEP（F5 F2）・PEXT（F5 F3）。
    v.push(MapItem::Insn(
        0xF5,
        vmx("bzhi_gv_ev_by", &[Reg(V), Ea(V), Vv], PfxSel::Plain, L0, false, "bzhi {g}, {e}, {h}", "alu"),
    ));
    v.push(MapItem::Insn(
        0xF5,
        vmx("pdep_gv_by_ev", &[Reg(V), Vv, Ea(V)], PfxSel::PF2, L0, false, "pdep {g}, {h}, {e}", "alu"),
    ));
    v.push(MapItem::Insn(
        0xF5,
        vmx("pext_gv_by_ev", &[Reg(V), Vv, Ea(V)], PfxSel::PF3, L0, false, "pext {g}, {h}, {e}", "alu"),
    ));
    // MULX（F6 F2）。上位は ModRM.reg、下位は vvvv。暗黙 EDX/RDX。
    v.push(MapItem::Insn(
        0xF6,
        vmx("mulx_gv_by_ev", &[Reg(V), Vv, Ea(V)], PfxSel::PF2, L0, false, "mulx {g}, {h}, {e}", "alu"),
    ));
    // BEXTR（F7 NP）・SHLX（66）・SHRX（F2）・SARX（F3）。
    // すべて Gv, Ev, By。
    for (sel, mn) in [
        (PfxSel::Plain, "bextr"),
        (PfxSel::P66, "shlx"),
        (PfxSel::PF2, "shrx"),
        (PfxSel::PF3, "sarx"),
    ] {
        v.push(MapItem::Insn(
            0xF7,
            vmx(&format!("{mn}_gv_ev_by"), &[Reg(V), Ea(V), Vv], sel, L0, false, "{op} {g}, {e}, {h}", "alu"),
        ));
    }
    // VCVTPH2PS（66 0F 38 13）。半精度→単精度。vvvv は 1111b 必須。
    v.push(MapItem::Insn(
        0x13,
        vmx(
            "vcvtph2ps_xv_wv",
            &[RegX, RmX],
            PfxSel::P66,
            Any,
            true,
            "vcvtph2ps {x}, {w}",
            "alu",
        ),
    ));
    // FMA（VEX.66）。W=0 が PS/SS、W=1 が PD/SD。各ブロックの
    // 配置は 96=fmaddsub・97=fmsubadd・98/99=fmadd パック/スカラ・
    // 9A/9B=fmsub・9C/9D=fnmadd・9E/9F=fnmsub（132/213/231 は
    // 0x96/0xA6/0xB6 起点で同配置）。W ゲートがないので名前は
    // W=0（ps/ss）形で立て、W=1 は意味論が vex_w を見て pd/sd
    // として動く（逆アセンブル表示は ps/ss になる近似）。
    for (base, ord) in [(0x96u8, 0u8), (0xA6, 1), (0xB6, 2)] {
        let os = match ord {
            0 => "132",
            1 => "213",
            _ => "231",
        };
        for (i, mn) in ["vfmaddsub", "vfmsubadd"].iter().enumerate() {
            v.push(MapItem::Insn(
                base + i as u8,
                vmx(
                    &format!("{mn}{os}ps_xv_hv_wv"),
                    &[RegX, Vv, RmX],
                    PfxSel::P66,
                    Any,
                    false,
                    "{op} {x}, {h}, {w}",
                    "alu",
                ),
            ));
        }
        for (i, mn) in ["vfmadd", "vfmsub", "vfnmadd", "vfnmsub"]
            .iter()
            .enumerate()
        {
            for (sfx, l) in [("ps", Any), ("ss", L0)] {
                v.push(MapItem::Insn(
                    base + 2 + 2 * i as u8 + u8::from(l == L0),
                    vmx(
                        &format!("{mn}{os}{sfx}_xv_hv_wv"),
                        &[RegX, Vv, RmX],
                        PfxSel::P66,
                        l,
                        false,
                        "{op} {x}, {h}, {w}",
                        "alu",
                    ),
                ));
            }
        }
    }
    // EVEX 0F38 の FVM 整数演算（512 ビット形のみ）。W=0/1 の
    // 要素幅別項目は `wsel` で分け、メモリ形の b=1 は
    // m32bcst/m64bcst（`edisp` が要素バイト数）。VPMULLQ と
    // VPABSQ は avx512dq ゲート。論理演算（DB/DF/EB/EF）は
    // 0F マップ側にある。
    for (op, mn, w, edisp, dq) in [
        (0x40u8, "vpmulld", false, 4u8, false),
        (0x40, "vpmullq", true, 8, true),
        (0x39, "vpminsd", false, 4, false),
        (0x39, "vpminsq", true, 8, false),
        (0x3B, "vpminud", false, 4, false),
        (0x3B, "vpminuq", true, 8, false),
        (0x3D, "vpmaxsd", false, 4, false),
        (0x3D, "vpmaxsq", true, 8, false),
        (0x3F, "vpmaxud", false, 4, false),
        (0x3F, "vpmaxuq", true, 8, false),
    ] {
        let mut it = ex(
            &format!("{mn}_xv_hv_wv"),
            &[RegX, Vv, RmX],
            PfxSel::P66,
            0b100,
            false,
            "{op} {x}, {h}, {w}",
            "alu",
        );
        it.bcast = true;
        it.edisp = edisp;
        it.wsel = Some(w);
        if dq {
            it.when = Pred::Flag("avx512dq".to_string());
        }
        v.push(MapItem::Insn(op, it));
    }
    // VPABSD/Q（単項、vvvv=1111b 必須）。どちらも avx512f。
    for (op, mn, w, edisp, dq) in [
        (0x1Eu8, "vpabsd", false, 4u8, false),
        (0x1F, "vpabsq", true, 8, false),
    ] {
        let mut it = ex(
            &format!("{mn}_xv_wv"),
            &[RegX, RmX],
            PfxSel::P66,
            0b100,
            true,
            "{op} {x}, {w}",
            "alu",
        );
        it.bcast = true;
        it.edisp = edisp;
        it.wsel = Some(w);
        if dq {
            it.when = Pred::Flag("avx512dq".to_string());
        }
        v.push(MapItem::Insn(op, it));
    }
    m.maps.push(MapDecl {
        name: "map_0f38".to_string(),
        vex_code: Some(2),
        postop: false,
        items: v,
    });
}

/// 0F 3A サブマップ。すべて必須接頭辞 0x66 + imm8。
fn build_map_0f3a(m: &mut Model) {
    use OpKind::*;
    use OpWidth::*;
    let ib = Imm(B8);
    let mut items = vec![
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
        // HRESET（F3 0F 3A F0 /0 mod=11 rm=0、imm8）。
        // ハードウェア履歴リセット — スタブとして no-op。
        {
            let mut it = mi("hreset_ib", &[Imm(B8)], Some(0), PfxSel::PF3, Pred::True, "hreset {i}", "system");
            it.group_mod = Some(true);
            it.group_rm = Some(0);
            MapItem::Insn(0xF0, it)
        },
    ];
    {
        use VexL::{Any, L0, L1};
        // VPERMQ（AVX2・256 のみ・W=1 必須だが W ゲートはないので
        // W によらず解読する近似）。
        items.push(MapItem::Insn(
            0x00,
            vax(
                "vpermq_xv_wv_ib",
                &[RegX, RmX, ib],
                PfxSel::P66,
                L1,
                true,
                "{op} {x}, {w}, {i}",
                "alu",
            ),
        ));
        // RORX（F2 0F 3A F0 /r ib、BMI2）。幅は VEX.W。
        // vvvv は未使用（1111b 必須）。
        items.push(MapItem::Insn(
            0xF0,
            vmx("rorx_gv_ev_ib", &[Reg(V), Ea(V), ib], PfxSel::PF2, L0, true, "rorx {g}, {e}, {i}", "alu"),
        ));
        // VCVTPS2PH（66 0F 3A 1D /r ib）。単精度→半精度。
        // 宛先は r/m 側（xmm/m64 または xmm/m128）。
        items.push(MapItem::Insn(
            0x1D,
            vmx(
                "vcvtps2ph_wv_xv_ib",
                &[RmX, RegX, ib],
                PfxSel::P66,
                Any,
                true,
                "vcvtps2ph {w}, {x}, {i}",
                "store",
            ),
        ));
        // VPERMILPS/VPERMILPD の即値形（vvvv 未使用）。
        items.push(MapItem::Insn(
            0x04,
            vmx("vpermilps_xv_wv_ib", &[RegX, RmX, ib], PfxSel::P66, Any, true, "{op} {x}, {w}, {i}", "alu"),
        ));
        items.push(MapItem::Insn(
            0x05,
            vmx("vpermilpd_xv_wv_ib", &[RegX, RmX, ib], PfxSel::P66, Any, true, "{op} {x}, {w}, {i}", "alu"),
        ));
        // VPERM2F128（AVX・256 のみ）。
        items.push(MapItem::Insn(
            0x06,
            vmx(
                "vperm2f128_xv_hv_wv_ib",
                &[RegX, Vv, RmX, ib],
                PfxSel::P66,
                L1,
                false,
                "{op} {x}, {h}, {w}, {i}",
                "alu",
            ),
        ));
        // VROUNDPS/PD（vvvv 未使用）と VROUNDSS/SD（3 オペランド）。
        for (op, mn) in [
            (0x08u8, "vroundps"),
            (0x09, "vroundpd"),
        ] {
            items.push(MapItem::Insn(
                op,
                vmx(
                    &format!("{mn}_xv_wv_ib"),
                    &[RegX, RmX, ib],
                    PfxSel::P66,
                    Any,
                    true,
                    "{op} {x}, {w}, {i}",
                    "alu",
                ),
            ));
        }
        for (op, mn) in [(0x0Au8, "vroundss"), (0x0B, "vroundsd")] {
            items.push(MapItem::Insn(
                op,
                vmx(
                    &format!("{mn}_xv_hv_wv_ib"),
                    &[RegX, Vv, RmX, ib],
                    PfxSel::P66,
                    L0,
                    false,
                    "{op} {x}, {h}, {w}, {i}",
                    "alu",
                ),
            ));
        }
        // VBLENDPS/VBLENDPD（256 ビットも AVX）。
        for (op, mn) in [(0x0Cu8, "vblendps"), (0x0D, "vblendpd")] {
            items.push(MapItem::Insn(
                op,
                vmx(
                    &format!("{mn}_xv_hv_wv_ib"),
                    &[RegX, Vv, RmX, ib],
                    PfxSel::P66,
                    Any,
                    false,
                    "{op} {x}, {h}, {w}, {i}",
                    "alu",
                ),
            ));
        }
        // VPBLENDW（256 ビット形は AVX2）。
        items.push(MapItem::Insn(
            0x0E,
            vmx("vpblendw_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        items.push(MapItem::Insn(
            0x0E,
            vax("vpblendw_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        // VPEXTRB/W/D/Q・VEXTRACTPS（vvvv 未使用・128 のみ）。
        for (op, mn, w) in [
            (0x14u8, "vpextrb_eb_xv_ib", B8),
            (0x15, "vpextrw_ew_xv_ib", W16),
            (0x16, "vpextrd_ev_xv_ib", V),
            (0x17, "vextractps_ed_xv_ib", D32),
        ] {
            items.push(MapItem::Insn(
                op,
                vmx(
                    mn,
                    &[Ea(w), RegX, ib],
                    PfxSel::P66,
                    L0,
                    true,
                    "{op} {e}, {x}, {i}",
                    "store",
                ),
            ));
        }
        // VINSERTF128（AVX）/VEXTRACTF128（AVX）・VINSERTI128/
        // VEXTRACTI128（AVX2）。すべて 256 のみ。
        for (op, mn, f) in [
            (0x18u8, "vinsertf128", false),
            (0x19, "vextractf128", true),
            (0x38, "vinserti128", false),
            (0x39, "vextracti128", true),
        ] {
            let it = if f {
                if op < 0x20 {
                    vmx(
                        &format!("{mn}_wv_xv_ib"),
                        &[RmX, RegX, ib],
                        PfxSel::P66,
                        L1,
                        true,
                        "{op} {w}, {x}, {i}",
                        "store",
                    )
                } else {
                    vax(
                        &format!("{mn}_wv_xv_ib"),
                        &[RmX, RegX, ib],
                        PfxSel::P66,
                        L1,
                        true,
                        "{op} {w}, {x}, {i}",
                        "store",
                    )
                }
            } else if op < 0x20 {
                vmx(
                    &format!("{mn}_xv_hv_wv_ib"),
                    &[RegX, Vv, RmX, ib],
                    PfxSel::P66,
                    L1,
                    false,
                    "{op} {x}, {h}, {w}, {i}",
                    "alu",
                )
            } else {
                vax(
                    &format!("{mn}_xv_hv_wv_ib"),
                    &[RegX, Vv, RmX, ib],
                    PfxSel::P66,
                    L1,
                    false,
                    "{op} {x}, {h}, {w}, {i}",
                    "alu",
                )
            };
            items.push(MapItem::Insn(op, it));
        }
        // VPINSRB・VINSERTPS・VPINSRD/Q（128 のみ）。VPINSRQ は
        // Ea(V)+VEX.W の `d.rex` 経由で幅を選ぶ。
        items.push(MapItem::Insn(
            0x20,
            vmx(
                "vpinsrb_xv_hv_eb_ib",
                &[RegX, Vv, Ea(B8), ib],
                PfxSel::P66,
                L0,
                false,
                "{op} {x}, {h}, {e}, {i}",
                "alu",
            ),
        ));
        items.push(MapItem::Insn(
            0x21,
            vmx(
                "vinsertps_xv_hv_wv_ib",
                &[RegX, Vv, RmX, ib],
                PfxSel::P66,
                L0,
                false,
                "{op} {x}, {h}, {w}, {i}",
                "alu",
            ),
        ));
        items.push(MapItem::Insn(
            0x22,
            vmx(
                "vpinsrd_xv_hv_ev_ib",
                &[RegX, Vv, Ea(V), ib],
                PfxSel::P66,
                L0,
                false,
                "{op} {x}, {h}, {e}, {i}",
                "alu",
            ),
        ));
        // VDPPS（256 ビットも AVX）・VDPPD（128 のみ）と
        // VMPSADBW（256 は AVX2）。
        items.push(MapItem::Insn(
            0x40,
            vmx("vdpps_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, Any, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        items.push(MapItem::Insn(
            0x41,
            vmx("vdppd_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        items.push(MapItem::Insn(
            0x42,
            vmx("vmpsadbw_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        items.push(MapItem::Insn(
            0x42,
            vax("vmpsadbw_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        // VBLENDVPS/VBLENDVPD（256 も AVX）と VPBLENDVB（256 は AVX2）。
        // imm8[7:4] がマスクレジスタ。
        for (op, mn) in [(0x4Au8, "vblendvps"), (0x4B, "vblendvpd")] {
            items.push(MapItem::Insn(
                op,
                vmx(
                    &format!("{mn}_xv_hv_wv_ib"),
                    &[RegX, Vv, RmX, ib],
                    PfxSel::P66,
                    Any,
                    false,
                    "{op} {x}, {h}, {w}, {i}",
                    "alu",
                ),
            ));
        }
        items.push(MapItem::Insn(
            0x4C,
            vmx("vpblendvb_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, L0, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        items.push(MapItem::Insn(
            0x4C,
            vax("vpblendvb_xv_hv_wv_ib", &[RegX, Vv, RmX, ib], PfxSel::P66, L1, false, "{op} {x}, {h}, {w}, {i}", "alu"),
        ));
        // VPERM2I128（AVX2・256 のみ）。
        items.push(MapItem::Insn(
            0x46,
            vax(
                "vperm2i128_xv_hv_wv_ib",
                &[RegX, Vv, RmX, ib],
                PfxSel::P66,
                L1,
                false,
                "{op} {x}, {h}, {w}, {i}",
                "alu",
            ),
        ));
    }
    m.maps.push(MapDecl {
        name: "map_0f3a".to_string(),
        vex_code: Some(3),
        postop: false,
        items,
    });
}
