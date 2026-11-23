// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! PDP-11 の骨格検査（段階24・PD2）。16 ビット語のデコードと
//! CPU モデル宣言・機能旗・挙動パラメータの形を見る。
//! 出典は SPEC-PDP11-ARCH83 ほかである。

use polyisa_guest_pdp11::*;

/// 16 ビット命令語のデコード（既定モデル）。
fn dec(w: u16) -> Option<Insn> {
    decode(u128::from(w), 16)
}

/// モデルの機能集合でのデコード。
fn dec_m(w: u16, model: &str) -> Option<Insn> {
    decode_model_ex(u128::from(w), 16, false, model_feats(model))
}

#[test]
fn decode_double_operand() {
    // 01SSDD mov・06SSDD add・16SSDD sub。
    assert_eq!(dec(0o010001), Some(Insn::Mov)); // mov r0, r1
    assert_eq!(dec(0o110377), Some(Insn::Movb)); // movb @#0,-(pc) 相当
    assert_eq!(dec(0o064723), Some(Insn::Add));
    assert_eq!(dec(0o160001), Some(Insn::Sub));
    assert_eq!(dec(0o020001), Some(Insn::Cmp));
    assert_eq!(dec(0o050001), Some(Insn::Bis));
}

#[test]
fn decode_single_operand_and_control() {
    assert_eq!(dec(0o005000), Some(Insn::Clr)); // clr r0
    assert_eq!(dec(0o005737), Some(Insn::Tst)); // tst @#…
    assert_eq!(dec(0o000100), Some(Insn::Jmp));
    assert_eq!(dec(0o000300), Some(Insn::Swab));
    assert_eq!(dec(0o000240), Some(Insn::Nop));
    assert_eq!(dec(0o000000), Some(Insn::Halt));
    assert_eq!(dec(0o000001), Some(Insn::Wait));
    assert_eq!(dec(0o000002), Some(Insn::Rti));
    assert_eq!(dec(0o000200), Some(Insn::Rts)); // rts r0
}

#[test]
fn decode_branch_and_traps() {
    assert_eq!(dec(0o000400), Some(Insn::Br));
    assert_eq!(dec(0o001001), Some(Insn::Bne));
    assert_eq!(dec(0o103777), Some(Insn::Bcs));
    assert_eq!(dec(0o104000), Some(Insn::Emt));
    assert_eq!(dec(0o104400), Some(Insn::Trap));
    assert_eq!(dec(0o077501), Some(Insn::Sob)); // sob r2, …
}

#[test]
fn decode_gated_by_features() {
    // 既定モデル（pdp11_03）は EIS を持たないので 070RSS は解けない。
    assert_eq!(dec(0o070000), None); // mul r0, r0
    assert_eq!(dec_m(0o070000, "pdp11_70"), Some(Insn::Mul));
    // FIS も旗が要る（+fis で足した集合で解ける）。
    assert_eq!(dec(0o075002), None); // fadd r2
    let feats = model_feats("pdp11_03") | FEAT_FIS;
    assert_eq!(
        decode_model_ex(0o075002, 16, false, feats),
        Some(Insn::Fadd)
    );
    // MMU 命令と MTPS/MFPS・SPL・MFPT・J-11 命令。
    assert_eq!(dec_m(0o006500, "pdp11_70"), Some(Insn::Mfpi));
    assert_eq!(dec(0o006500), None);
    assert_eq!(dec_m(0o106400, "pdp11_03"), Some(Insn::Mtps));
    assert_eq!(dec_m(0o106400, "pdp11_70"), None);
    assert_eq!(dec_m(0o000230, "pdp11_70"), Some(Insn::Spl));
    assert_eq!(dec_m(0o000007, "pdp11_23"), Some(Insn::Mfpt));
    assert_eq!(dec_m(0o007000, "pdp11_73"), Some(Insn::Csm));
    assert_eq!(dec_m(0o007200, "pdp11_73"), Some(Insn::Tstset));
    assert_eq!(dec_m(0o007300, "pdp11_73"), Some(Insn::Wrtlck));
}

#[test]
fn insn_count() {
    // 二重 12 + 単一語 20 + 単一バイト 16 + JSR/RTS/SOB 3 + EIS/XOR 5
    // + FIS 4 + 分岐 15 + EMT/TRAP 2 + MARK/SPL 2 + 固定語 11
    // （条件コード操作は nop + ccc/scc のマスク形として数える）。
    assert_eq!(INSNS.len(), 90);
}

#[test]
fn cpu_models() {
    for n in [
        "pdp11_03", "pdp11_04", "pdp11_34", "pdp11_44", "pdp11_60", "pdp11_70", "pdp11_23",
        "pdp11_24", "pdp11_73", "pdp11_83", "pdp11_93", "t11",
    ] {
        assert!(MODELS.contains(&n), "{n}");
    }
    for f in [
        "eis",
        "fis",
        "fp11",
        "cis",
        "mmu",
        "id_split",
        "sm",
        "dual_regset",
        "mtps",
        "mfpt",
        "spl",
        "csm",
        "tstset_wrtlck",
    ] {
        assert!(FEATURES.contains(&f), "{f}");
    }
    // 11/70: EIS・MMU・分離 I/D・スーパーバイザ・第2レジスタセット。
    let f70 = model_feats("pdp11_70");
    assert_eq!(
        f70 & (FEAT_EIS | FEAT_MMU | FEAT_ID_SPLIT | FEAT_SM | FEAT_DUAL_REGSET | FEAT_SPL),
        FEAT_EIS | FEAT_MMU | FEAT_ID_SPLIT | FEAT_SM | FEAT_DUAL_REGSET | FEAT_SPL
    );
    assert_eq!(f70 & (FEAT_MTPS | FEAT_FP11), 0);
    // 11/03: MTPS/MFPS のみ。
    let f03 = model_feats("pdp11_03");
    assert_eq!(f03, FEAT_MTPS);
    // J-11: EIS・FP11 標準、CSM・TSTSET/WRTLCK を持つ。FIS は排他。
    let f73 = model_feats("pdp11_73");
    assert_ne!(
        f73 & (FEAT_EIS | FEAT_FP11 | FEAT_CSM | FEAT_TSTSET_WRTLCK),
        0
    );
    assert_eq!(f73 & FEAT_FIS, 0);
    // 親チェーン: 11/83/93 は 11/73 の機能を継ぐ、11/24 は 23 に
    // tstset_wrtlck を足す。
    assert_eq!(model_feats("pdp11_83"), f73);
    assert_eq!(
        model_feats("pdp11_24"),
        model_feats("pdp11_23") | FEAT_TSTSET_WRTLCK
    );
    // implies: csm→sm→mmu、id_split→mmu。
    assert_ne!(f73 & FEAT_MMU, 0);
}

#[test]
fn model_params_resolve() {
    let p03 = model_params("pdp11_03");
    assert!(!p03.odd_addr_trap);
    assert!(!p03.psw_mapped);
    assert_eq!(p03.jmp_reg_trap, JMP_REG_TRAP_VEC004);
    let p70 = model_params("pdp11_70");
    assert!(p70.odd_addr_trap);
    assert!(p70.psw_mapped);
    assert_eq!(p70.jmp_reg_trap, JMP_REG_TRAP_VEC004);
    // パラメータも親チェーンで継承される。
    let p83 = model_params("pdp11_83");
    assert_eq!(p83, model_params("pdp11_73"));
}

#[test]
fn disasm_word_spot() {
    assert_eq!(disasm_word(0o010001, 16).as_deref(), Some("mov"));
    assert_eq!(disasm_word(0o000240, 16).as_deref(), Some("nop"));
}

// ---- PD3: オペランド指定子 ----

use polyisa_guest_pdp11::specifier::*;

/// 命令語 + 拡張語の列への組立て（生成 `encode` の語に指定子を載せる）。
fn asm(insn: Insn, specs: &[Spec]) -> Vec<u16> {
    let base = encode(insn, &[]).expect("encodable") as u16;
    let (w, ext) = encode_insn(base, specs);
    let mut v = vec![w];
    v.extend(ext);
    v
}

/// 指定子 1 個の構造的デコード（消費語数込み）。
fn spec(mode: u8, r: u8, ext: &[u16]) -> Spec {
    let (s, n) = decode_spec(mode, r, ext).expect("specifier decodes");
    assert_eq!(n as usize, ext.len().min(1));
    s
}

#[test]
fn spec_decode_all_modes() {
    // 8 モードを r0-r7 の代表で構造的に読む。
    assert_eq!(spec(0, 3, &[]), Spec::Reg(3));
    assert_eq!(spec(1, 4, &[]), Spec::RegDef(4));
    assert_eq!(spec(2, 5, &[]), Spec::AutoInc(5));
    assert_eq!(spec(3, 6, &[]), Spec::AutoIncDef(6));
    assert_eq!(spec(4, 0, &[]), Spec::AutoDec(0));
    assert_eq!(spec(5, 1, &[]), Spec::AutoDecDef(1));
    assert_eq!(spec(6, 2, &[0o100]), Spec::Index { r: 2, x: 0o100 });
    assert_eq!(spec(7, 3, &[0o200]), Spec::IndexDef { r: 3, x: 0o200 });
    // PC 特殊用途: 2,7=即値・3,7=絶対・6,7=相対・7,7=相対間接。
    assert_eq!(spec(2, 7, &[0o1234]), Spec::Imm(0o1234));
    assert_eq!(spec(3, 7, &[0o5670]), Spec::Abs(0o5670));
    assert_eq!(spec(6, 7, &[0o10]), Spec::Index { r: 7, x: 0o10 });
    assert_eq!(spec(7, 7, &[0o20]), Spec::IndexDef { r: 7, x: 0o20 });
}

#[test]
fn spec_extension_words() {
    // 拡張語の消費はモードと Rn=PC で決まる（幅には依らない）。
    for m in [0u8, 1, 4, 5] {
        assert_eq!(spec_words(m, 0), 0);
        assert_eq!(spec_words(m, 7), 0);
    }
    // モード 2/3 は Rn=PC のときだけ 1 語（即値・絶対）。
    assert_eq!(spec_words(2, 0), 0);
    assert_eq!(spec_words(2, 7), 1);
    assert_eq!(spec_words(3, 6), 0);
    assert_eq!(spec_words(3, 7), 1);
    // モード 6/7 は常にインデックス語 1 語。
    for m in [6u8, 7] {
        assert_eq!(spec_words(m, 0), 1);
        assert_eq!(spec_words(m, 7), 1);
    }
    // 語が足りないときは None。
    assert_eq!(decode_spec(6, 0, &[]), None);
    assert_eq!(decode_spec(2, 7, &[]), None);
    assert_eq!(decode_spec(8, 0, &[0]), None);
}

#[test]
fn spec_legality() {
    // jmp/jsr の宛先（A アクセス）にモード 0 は違法。
    assert_eq!(legality(&Spec::Reg(0), Acc::A), Legality::Illegal);
    assert_eq!(legality(&Spec::Reg(7), Acc::A), Legality::Illegal);
    assert_eq!(legality(&Spec::Reg(0), Acc::W), Legality::Legal);
    // -(PC)・@-(PC) は定義されない。
    assert_eq!(legality(&Spec::AutoDec(7), Acc::R), Legality::Unpredictable);
    assert_eq!(
        legality(&Spec::AutoDecDef(7), Acc::M),
        Legality::Unpredictable
    );
    assert_eq!(legality(&Spec::AutoDec(0), Acc::R), Legality::Legal);
    // 即値への書き込みは定義されないが読み出しは合法。
    assert_eq!(legality(&Spec::Imm(1), Acc::R), Legality::Legal);
    assert_eq!(legality(&Spec::Imm(1), Acc::M), Legality::Unpredictable);
    assert_eq!(legality(&Spec::Abs(0), Acc::W), Legality::Legal);
}

#[test]
fn spec_autoinc_steps() {
    // モード 2/4 の刻みはオペランド幅。byte でも SP/PC は ±2。
    let mut r = [0u16; 8];
    r[3] = 0o2000;
    r[6] = 0o4000;
    let (ea, wb) = eval(&Spec::AutoInc(3), Width::B, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o2000)));
    assert_eq!(wb, Some((3, 0o2001)));
    let (ea, wb) = eval(&Spec::AutoInc(3), Width::W, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o2000)));
    assert_eq!(wb, Some((3, 0o2002)));
    // byte の SP は +2（ワード整列）。
    let (ea, wb) = eval(&Spec::AutoInc(6), Width::B, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o4000)));
    assert_eq!(wb, Some((6, 0o4002)));
    // -(Rn): 下げてから読み出す。
    let (ea, wb) = eval(&Spec::AutoDec(3), Width::W, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o1776)));
    assert_eq!(wb, Some((3, 0o1776)));
    // 間接形の指し先語は常に ±2。
    let (ea, wb) = eval(&Spec::AutoIncDef(3), Width::B, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o2000)));
    assert_eq!(wb, Some((3, 0o2002)));
    let (ea, wb) = eval(&Spec::AutoDecDef(3), Width::W, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o1776)));
    assert_eq!(wb, Some((3, 0o1776)));
    // long/F/D の刻みはオペランド幅。
    let (_, wb) = eval(&Spec::AutoInc(3), Width::L, 0, &r);
    assert_eq!(wb, Some((3, 0o2004)));
    let (_, wb) = eval(&Spec::AutoInc(3), Width::D, 0, &r);
    assert_eq!(wb, Some((3, 0o2010)));
}

#[test]
fn spec_eval_pc_relative() {
    // x(PC): 基準は拡張語の次の語（拡張語を読み終えた PC）。
    let r = [0u16; 8];
    let (ea, wb) = eval(&Spec::Index { r: 7, x: 0o100 }, Width::W, 0o1002, &r);
    assert!(matches!(ea, Ea::Addr(0o1104)));
    assert_eq!(wb, None);
    // @x(PC) も同じ基準の指し先語。
    let (ea, _) = eval(&Spec::IndexDef { r: 7, x: 0o20 }, Width::W, 0o2000, &r);
    assert!(matches!(ea, Ea::Addr(0o2022)));
    // r!=PC はレジスタ + 変位。
    let mut r = [0u16; 8];
    r[4] = 0o5000;
    let (ea, _) = eval(&Spec::Index { r: 4, x: 0o30 }, Width::W, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o5030)));
    // (Rn)・レジスタ直接・即値・絶対。
    let (ea, _) = eval(&Spec::RegDef(4), Width::W, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o5000)));
    let (ea, _) = eval(&Spec::Reg(4), Width::W, 0, &r);
    assert!(matches!(ea, Ea::Reg(4)));
    let (ea, _) = eval(&Spec::Imm(0o777), Width::B, 0, &r);
    assert!(matches!(ea, Ea::Imm(0o777)));
    let (ea, _) = eval(&Spec::Abs(0o1000), Width::W, 0, &r);
    assert!(matches!(ea, Ea::Addr(0o1000)));
}

#[test]
fn insn_decode_with_specifiers() {
    // mov r0, r1 — 拡張語なしで 2 バイト。
    let f = decode_insn(&[0o010001]).expect("decodes");
    assert_eq!(f.insn, Insn::Mov);
    assert_eq!(f.ops, [Spec::Reg(0), Spec::Reg(1)]);
    assert_eq!(f.len, 2);
    // mov #v, r0: src が即値語を消費して 4 バイト。
    let f = decode_insn(&[0o012700, 0o1234]).expect("decodes");
    assert_eq!(f.ops, [Spec::Imm(0o1234), Spec::Reg(0)]);
    assert_eq!(f.len, 4);
    // mov x(r1), y(r2): src → dst の順に拡張語を消費して 6 バイト。
    let f = decode_insn(&[0o016162, 0o10, 0o20]).expect("decodes");
    assert_eq!(
        f.ops,
        [Spec::Index { r: 1, x: 0o10 }, Spec::Index { r: 2, x: 0o20 }]
    );
    assert_eq!(f.len, 6);
    // tst @#a: 絶対語 1 語で 4 バイト。
    let f = decode_insn(&[0o005737, 0o177776]).expect("decodes");
    assert_eq!(f.ops, [Spec::Abs(0o177776)]);
    assert_eq!(f.len, 4);
    // 拡張語が足りないとデコード失敗。
    assert!(decode_insn(&[0o016162, 0o10]).is_none());
}

#[test]
fn insn_len_matches_decode() {
    // 軽い経路と構造的デコードの長さが一致する。
    for words in [
        &[0o010001][..],
        &[0o012700, 0o1234][..],
        &[0o016162, 0o10, 0o20][..],
        &[0o005737, 0o177776][..],
        &[0o005000][..],
        &[0o000240][..],
    ] {
        let want = decode_insn(words).map(|f| f.len);
        assert_eq!(insn_len(words), want, "{words:?}");
    }
    // 機能旗で解けない命令は None（mul は EIS が要る）。
    assert_eq!(insn_len(&[0o070000]), None);
    assert_eq!(insn_len_ex(&[0o070000], model_feats("pdp11_70")), Some(2));
}

#[test]
fn insn_ops_signature() {
    // 指定子を持つ命令の型と個数。
    assert_eq!(
        insn_ops(Insn::Mov),
        [
            OpTy {
                acc: Acc::R,
                width: Width::W
            },
            WW
        ]
    );
    assert_eq!(insn_ops(Insn::Movb), [RB, WB]);
    assert_eq!(insn_ops(Insn::Add), [RW, MW]);
    assert_eq!(insn_ops(Insn::Jmp), [AW]);
    assert_eq!(insn_ops(Insn::Tstb), [RB]);
    assert_eq!(insn_ops(Insn::Xor), [MW]);
    // 指定子を持たない命令。
    for i in [
        Insn::Br,
        Insn::Sob,
        Insn::Rts,
        Insn::Nop,
        Insn::Emt,
        Insn::Fadd,
    ] {
        assert!(insn_ops(i).is_empty());
    }
}

#[test]
fn spec_roundtrip() {
    // 全バリアントの encode → decode が元に戻る。
    for s in [
        Spec::Reg(0),
        Spec::Reg(7),
        Spec::RegDef(3),
        Spec::AutoInc(6),
        Spec::Imm(0o177777),
        Spec::AutoIncDef(2),
        Spec::Abs(0o177776),
        Spec::AutoDec(5),
        Spec::AutoDecDef(0),
        Spec::Index { r: 4, x: 0o100 },
        Spec::Index { r: 7, x: 0o20 },
        Spec::IndexDef { r: 1, x: 0o40 },
        Spec::IndexDef { r: 7, x: 0o60 },
    ] {
        let (m, r, x) = encode_spec(&s);
        assert_eq!(spec_words(m, r), u32::from(x.is_some()), "{s:?}");
        let ext: Vec<u16> = x.into_iter().collect();
        let (back, n) = decode_spec(m, r, &ext).expect("redecodes");
        assert_eq!(back, s, "{s:?}");
        assert_eq!(n as usize, ext.len());
    }
}

#[test]
fn insn_roundtrip() {
    // encode_insn → decode_insn が語・指定子・長さを往復する。
    for (insn, specs) in [
        (Insn::Mov, &[Spec::Reg(0), Spec::Reg(1)][..]),
        (Insn::Mov, &[Spec::Imm(0o1234), Spec::AutoDec(6)][..]),
        (
            Insn::Add,
            &[Spec::Index { r: 7, x: 0o10 }, Spec::Abs(0o177776)][..],
        ),
        (Insn::Clrb, &[Spec::AutoIncDef(3)][..]),
        (Insn::Jmp, &[Spec::IndexDef { r: 2, x: 0o200 }][..]),
        (Insn::Nop, &[][..]),
    ] {
        let words = asm(insn, specs);
        let f = decode_insn(&words).expect("redecodes");
        assert_eq!(f.insn, insn);
        assert_eq!(f.ops, specs, "{insn:?} {words:?}");
        assert_eq!(f.len as usize, 2 * words.len());
        // 命令語は語内フィールドまで一致する。
        assert_eq!(f.word, words[0]);
    }
    // mov #imm, x(pc) の語構成を直接見る。
    let words = asm(Insn::Mov, &[Spec::Imm(0o42), Spec::Index { r: 7, x: 0o10 }]);
    assert_eq!(words, [0o012767, 0o42, 0o10]);
}

#[test]
fn word_order_3412() {
    // L/F/D は上位語が最下位アドレスの「3412」順。正準形（上位が
    // 最上位語）との写像は自己逆。
    assert_eq!(word_order(Width::L, 0x1234_5678), 0x5678_1234);
    assert_eq!(word_order(Width::F, 0x1234_5678), 0x5678_1234);
    assert_eq!(
        word_order(Width::D, 0x1122_3344_5566_7788),
        0x7788_5566_3344_1122
    );
    // byte/word は素通し。往復で元に戻る。
    assert_eq!(word_order(Width::W, 0xaabb), 0xaabb);
    for w in [Width::L, Width::F, Width::D] {
        let v = if w == Width::D {
            0xdead_beef_cafe_f00d
        } else {
            0xdead_beef
        };
        assert_eq!(word_order(w, word_order(w, v)), v);
    }
}

// ---- PD4: 実行ループ・トラップ配送 ----

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};

/// 何も捌かないハンドラ — 全て実機の配送（vector 読み出し）に回る。
struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

/// スタックポインタの初期値（写像ページ内）。
const SP0: u16 = 0o41000;

/// ベクタ領域・語列・スタックを写像した裸実行環境。`base` に語列
/// （LE）を置き、`model` の挙動パラメータを流す。ページ 0 は
/// ベクタと語列の両方を兼ねる。
fn env_at(model: &str, base: u16, words: &[u16]) -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.backend.mem.map(VirtAddr(0), 1, Perms(0b111)).unwrap();
    env.backend
        .mem
        .map(VirtAddr(0o40000), 1, Perms::RW)
        .unwrap();
    let mut bytes = Vec::new();
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    env.backend
        .mem
        .write(VirtAddr(u64::from(base)), &bytes)
        .unwrap();
    install_params(&mut env.backend, &model_params(model));
    env.backend.addr_mask = 0xFFFF;
    env.pc = u64::from(base);
    sem::r_set(&mut env.backend, reg::SP as u8, SP0);
    env
}

/// `model` で 1 ステップ実行する。
fn step_m(env: &mut BareEnv, model: &str) -> Result<(), Outcome> {
    run::step(env, &mut NoSys, model_feats(model))
}

/// 語を LE で書く。
fn put16(env: &mut BareEnv, a: u16, v: u16) {
    env.backend
        .mem
        .write(VirtAddr(u64::from(a)), &v.to_le_bytes())
        .unwrap();
}

/// 語を LE で読む。
fn get16(env: &BareEnv, a: u16) -> u16 {
    let mut b = [0u8; 2];
    env.backend
        .mem
        .read(
            VirtAddr(u64::from(a)),
            &mut b,
            Access {
                endian: Endian::Le,
                align: Align::Unaligned,
                kind: AccessKind::DataRead,
            },
        )
        .unwrap();
    u16::from_le_bytes(b)
}

#[test]
fn word_fetch_advances_pc() {
    // nop; nop — 語フェッチで PC が命令長（2）ずつ進み、実行中の
    // r7 も次の命令を指す。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000240, 0o000240]);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1002);
    assert_eq!(sem::r_get(&env.backend, reg::PC as u8), 0o1002);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1004);
}

#[test]
fn mov_immediate_consumes_extension() {
    // mov #0o1234, r0 — 拡張語を消費して 4 バイト命令。PC は +4。
    let words = asm(Insn::Mov, &[Spec::Imm(0o1234), Spec::Reg(0)]);
    assert_eq!(words.len(), 2);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o1234);
    assert_eq!(env.pc, 0o1004);
    // CC: 値は正なので N=0・Z=0・V=0。C は保存（初期 0）。
    assert_eq!(sem::psw_get(&env.backend) & 0xf, 0);
}

#[test]
fn movb_sign_extends_into_register() {
    // movb @#a, r0 — byte→レジスタの書き込みは符号拡張。
    let words = asm(Insn::Movb, &[Spec::Abs(0o2000), Spec::Reg(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    env.backend.mem.write(VirtAddr(0o2000), &[0o200]).unwrap();
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o177600);
    // N=1（結果が負）。
    assert_ne!(sem::psw_get(&env.backend) & (1 << psw::N), 0);
}

#[test]
fn specifier_eval_autoinc_and_deferred() {
    // mov (r1)+, r0; mov @(r2)+, r3 — オート増の書き戻しと間接の
    // 指し先語の読み出しが実行経路で起きる。
    let w1 = asm(Insn::Mov, &[Spec::AutoInc(1), Spec::Reg(0)]);
    let w2 = asm(Insn::Mov, &[Spec::AutoIncDef(2), Spec::Reg(3)]);
    let mut env = env_at("pdp11_34", 0o1000, &[w1[0], w2[0]]);
    put16(&mut env, 0o2000, 0o1234);
    put16(&mut env, 0o2002, 0o2010); // r2 が指す語 → オペランド 0o2010
    put16(&mut env, 0o2010, 0o5670);
    sem::r_set(&mut env.backend, 1, 0o2000);
    sem::r_set(&mut env.backend, 2, 0o2002);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o1234);
    assert_eq!(sem::r_get(&env.backend, 1), 0o2002); // ワードで +2
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 3), 0o5670);
    assert_eq!(sem::r_get(&env.backend, 2), 0o2004); // 間接は常に +2
}

#[test]
fn odd_addr_traps_to_vector4() {
    // odd_addr_trap のモデル: @#0o2001 のワード読み出しはバスエラー
    // → vector 004 へ配送。積む PC は命令先頭（fault）。
    let words = asm(Insn::Mov, &[Spec::Abs(0o2001), Spec::Reg(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    sem::psw_put(&mut env.backend, 0o17); // CC を立てて積まれるか見る
    put16(&mut env, 0o004, 0o3000);
    put16(&mut env, 0o006, 0o140);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(sp, SP0 - 4);
    // -(SP) に PSW → PC の順（RTI が PC→PSW で戻す形）。
    assert_eq!(get16(&env, sp), 0o1000);
    assert_eq!(get16(&env, sp + 2), 0o17);
    assert_eq!(sem::psw_get(&env.backend), 0o140);
}

#[test]
fn odd_addr_aligns_on_untrapped_model() {
    // odd_addr_trap=false（pdp11_03）: 奇数アドレスのワードアクセスは
    // 偶数に揃えて行われる（トラップ未実装の決定的な表現）。
    let words = asm(Insn::Mov, &[Spec::Abs(0o2001), Spec::Reg(0)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    put16(&mut env, 0o2000, 0o1234);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o1234);
    assert_eq!(env.pc, 0o1004);
}

#[test]
fn bpt_delivers_vector014() {
    // bpt は trap — 積む PC は次の命令で、vector 014 へ配送。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000003, 0o000240]);
    put16(&mut env, 0o014, 0o3000);
    put16(&mut env, 0o016, 0o140);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o1002); // 次の命令
    assert_eq!(sem::psw_get(&env.backend), 0o140);
}

#[test]
fn trap_reaches_personality_first() {
    // ハンドラが Handled なら実機の配送に回らない（OS 経路）。
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    let mut env = env_at("pdp11_34", 0o1000, &[0o104001]); // emt 1
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, model_feats("pdp11_34")).unwrap();
    assert_eq!(sys.0, u32::from(sem::tv::EMT));
    assert_eq!(env.pc, 0o1002);
    // スタックは触られていない。
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0);
}

#[test]
fn reserved_insn_delivers_vector010() {
    // EIS を持たないモデルの 070RSS は予約命令 → vector 010（fault —
    // 積む PC は命令先頭）。
    let mut env = env_at("pdp11_03", 0o1000, &[0o070000]);
    put16(&mut env, 0o010, 0o2400);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(env.pc, 0o2400);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o1000);
}

#[test]
fn jmp_reg_trap_param_selects_vector() {
    // `jmp r0`（モード 0 の A アクセス）は jmp_reg_trap パラメータの
    // ベクタ — 付録 B 項目 5 のモデル差。
    let words = asm(Insn::Jmp, &[Spec::Reg(0)]);
    for (model, vec) in [("pdp11_34", 0o004u16), ("pdp11_23", 0o010u16)] {
        let mut env = env_at(model, 0o1000, &words);
        put16(&mut env, vec, 0o3200);
        step_m(&mut env, model).unwrap();
        assert_eq!(env.pc, 0o3200, "{model}");
    }
}

#[test]
fn jmp_and_branch_update_pc() {
    // br +2 で 2 命令先へ、jmp @#a で絶対跳躍、beq は CC を見る。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000402]); // br +2
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1006); // next(0o1002) + 2×2

    let words = asm(Insn::Jmp, &[Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);

    // Z=1 で beq が取られる（変位は語単位）。
    let mut env = env_at("pdp11_34", 0o1000, &[0o001401]); // beq +1
    sem::psw_put(&mut env.backend, 1 << psw::Z);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1004);
    // Z=0 では落ちる。
    let mut env = env_at("pdp11_34", 0o1000, &[0o001401]);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1002);
}

#[test]
fn fetch_from_unmapped_is_bus_error() {
    // 未写像へのフェッチはバスエラー → vector 004。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000240]);
    put16(&mut env, 0o004, 0o2600);
    env.pc = 0o50000; // 未写像ページ
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o2600);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o50000); // fault — フェッチ点
}

#[test]
fn halt_stops_the_loop() {
    // halt は CPU 停止 — 裸モデルでは終端として Unimplemented。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000000]);
    match step_m(&mut env, "pdp11_34") {
        Err(Outcome::Unimplemented { pc, word }) => {
            assert_eq!(pc, 0o1000);
            assert_eq!(word, 0);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn program_runs_to_halt() {
    // mov #v,r0; mov r0,@#a; halt — 語列・拡張語・指定子評価・
    // 最小命令が通して動く。
    let mut words = asm(Insn::Mov, &[Spec::Imm(0o42), Spec::Reg(0)]);
    words.extend(asm(Insn::Mov, &[Spec::Reg(0), Spec::Abs(0o2000)]));
    words.extend(asm(Insn::Halt, &[]));
    let mut env = env_at("pdp11_34", 0o1000, &words);
    let mut sys = NoSys;
    let feats = model_feats("pdp11_34");
    let out = polyisa_engine::run::run(
        &mut env,
        &mut sys,
        16,
        |e| e.pc,
        |e, s| run::step(e, s, feats),
    );
    match out {
        Outcome::Unimplemented { pc, word } => {
            assert_eq!(pc, 0o1010); // halt の位置
            assert_eq!(word, 0);
        }
        o => panic!("unexpected: {o:?}"),
    }
    assert_eq!(get16(&env, 0o2000), 0o42);
}

// ---- PD5: 整数命令（単一・二重オペランド）----

/// 条件コード（PSW<3:0> = NZVC、N=8 Z=4 V=2 C=1）。
fn nzvc(env: &BareEnv) -> u16 {
    sem::psw_get(&env.backend) & 0xf
}

/// レジスタ dst の単一オペランド命令を (insn, 旧 r0, CC0) → (r0, CC) で
/// 一括検査する。byte 命令のレジスタ宛ては下位バイトに作用し、
/// 結果は符号拡張で書き戻される。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn alu_unary_cc_table() {
    let r0 = &[Spec::Reg(0)][..];
    for (insn, old, cc0, new, cc) in [
        // com: dst ← ~dst。V=0・C=1。
        (Insn::Com, 0o000377u16, 0, 0o177400, 0o11), // N+C
        (Insn::Com, 0o177777, 0, 0, 0o5),            // Z+C
        (Insn::Com, 0o177777, 0o17, 0, 0o5),         // 旧 CC は置き換わる
        // comb: 下位バイトの補数を符号拡張で書き戻す。
        (Insn::Comb, 0o000000, 0, 0o177777, 0o11), // N+C
        (Insn::Comb, 0o000377, 0, 0, 0o5),         // Z+C
        (Insn::Comb, 0o177400, 0, 0o177777, 0o11), // 上位は捨てられる
        // inc: V=旧値が最大正。C 不変。
        (Insn::Inc, 0o077777, 0o17, 0o100000, 0o13), // N+V+C保存
        (Insn::Inc, 0o177777, 0o1, 0, 0o5),          // Z+C保存
        (Insn::Inc, 0o000001, 0o2, 0o000002, 0),     // V は置き換わる
        (Insn::Incb, 0o000177, 0, 0o177600, 0o12),   // 0177+1 → 0200: N+V
        (Insn::Incb, 0o000377, 0, 0, 0o4),           // 0377+1 → 0: Z
        // dec: V=旧値が最大負。C 不変。
        (Insn::Dec, 0o100000, 0o1, 0o077777, 0o3), // V+C保存
        (Insn::Dec, 0o000001, 0, 0, 0o4),          // Z
        (Insn::Dec, 0o000000, 0, 0o177777, 0o10),  // N（負へ）
        (Insn::Decb, 0o000200, 0o1, 0o000177, 0o3), // V+C保存
        // neg: dst ← −dst。V=結果が最大負。C=結果が非零。
        (Insn::Neg, 0o100000, 0, 0o100000, 0o13),  // N+V+C
        (Insn::Neg, 0o000000, 0o17, 0, 0o4),       // Z、C 消える
        (Insn::Neg, 0o000005, 0, 0o177773, 0o11),  // N+C
        (Insn::Negb, 0o000200, 0, 0o177600, 0o13), // N+V+C
        // adc: dst ← dst + C。V=旧値が最大正かつ C。C=旧値が全 1 かつ C。
        (Insn::Adc, 0o077777, 0o1, 0o100000, 0o12), // N+V
        (Insn::Adc, 0o177777, 0o1, 0, 0o5),         // Z+C
        (Insn::Adc, 0o077777, 0, 0o077777, 0),      // C=0 なら変わらず
        (Insn::Adc, 0o177777, 0, 0o177777, 0o10),   // N のみ
        (Insn::Adcb, 0o000377, 0o1, 0, 0o5),        // Z+C
        // sbc: dst ← dst − C。V=旧値が最大負（C 入力を問わない
        // —— ARCH83 第5章の規則）。C=旧値が 0 かつ C 入力。
        (Insn::Sbc, 0o100000, 0o1, 0o077777, 0o2), // V（真の溢れ）
        (Insn::Sbc, 0o100000, 0, 0o100000, 0o12),  // V は C=0 でも立つ
        (Insn::Sbc, 0o000000, 0o1, 0o177777, 0o11), // N+C（借り）
        (Insn::Sbc, 0o000005, 0, 0o000005, 0),     // C=0 なら変わらず
        (Insn::Sbc, 0o000001, 0o1, 0, 0o4),        // Z
        (Insn::Sbcb, 0o000000, 0o1, 0o177777, 0o11), // byte の借り
    ] {
        let mut env = env_at("pdp11_34", 0o1000, &asm(insn, r0));
        sem::psw_put(&mut env.backend, cc0);
        sem::r_set(&mut env.backend, 0, old);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 0), nzvc(&env)),
            (new, cc),
            "{insn:?} dst={old:o} cc0={cc0:o}"
        );
    }
}

/// レジスタ間の二重オペランド命令を (insn, src, 旧 dst, CC0) →
/// （新 dst, CC) で一括検査する。byte 形は下位バイトで演算し
/// 符号拡張で書き戻す。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn alu_double_cc_table() {
    let rr = &[Spec::Reg(0), Spec::Reg(1)][..];
    for (insn, s, d0, cc0, d1, cc) in [
        // add: dst ← dst + src。
        (Insn::Add, 0o000001u16, 0o077777, 0, 0o100000, 0o12), // N+V
        (Insn::Add, 0o000001, 0o177777, 0, 0, 0o5),            // Z+C
        (Insn::Add, 0o100000, 0o100000, 0, 0, 0o7),            // Z+V+C
        (Insn::Add, 0o000005, 0o000003, 0, 0o000010, 0),
        (Insn::Add, 0o177777, 0o177777, 0o17, 0o177776, 0o11), // N+C（桁出し）
        (Insn::Add, 0o177777, 0o077777, 0, 0o077776, 0o1),     // C のみ（正の和）
        // sub: dst ← dst − src。C=借り。
        (Insn::Sub, 0o000001, 0o100000, 0, 0o077777, 0o2), // V
        (Insn::Sub, 0o000001, 0o000000, 0, 0o177777, 0o11), // N+C（借り）
        (Insn::Sub, 0o000005, 0o000005, 0, 0, 0o4),        // Z
        (Insn::Sub, 0o100000, 0o077777, 0, 0o177777, 0o13), // N+V+C
        // cmp: src − dst を調べる（書き戻しなし）。
        (Insn::Cmp, 0o000001, 0o000002, 0, 0o000002, 0o11), // N+C
        (Insn::Cmp, 0o000002, 0o000001, 0, 0o000001, 0),
        (Insn::Cmp, 0o000005, 0o000005, 0, 0o000005, 0o4), // Z
        (Insn::Cmp, 0o077777, 0o177777, 0, 0o177777, 0o13), // N+V+C
        (Insn::Cmp, 0o100000, 0o000001, 0, 0o000001, 0o2), // V
        // cmpb: byte の比較。−128−127 は溢れて V。
        (Insn::Cmpb, 0o000200, 0o000177, 0, 0o000177, 0o2), // V
        (Insn::Cmpb, 0o000001, 0o000002, 0, 0o000002, 0o11), // N+C
        // bit: src ∧ dst を調べる。V=0・C 不変（dst は書き戻さない）。
        (Insn::Bit, 0o177400, 0o007760, 0o1, 0o007760, 0o1), // C 保存のみ
        (Insn::Bit, 0o100000, 0o177777, 0, 0o177777, 0o10),  // N
        (Insn::Bit, 0o000000, 0o177777, 0o1, 0o177777, 0o5), // Z+C 保存
        (Insn::Bitb, 0o000200, 0o000377, 0, 0o000377, 0o10), // N
        // bic: dst ← dst ∧ ~src。V=0・C 不変。
        (Insn::Bic, 0o000377, 0o177777, 0o1, 0o177400, 0o11), // N+C 保存
        (Insn::Bic, 0o177777, 0o000005, 0, 0, 0o4),           // Z
        (Insn::Bicb, 0o000177, 0x00ffu16, 0, 0o177600, 0o10), // ~0177∧0377=0200→符号拡張
        // bis: dst ← dst ∨ src。V=0・C 不変。
        (Insn::Bis, 0o100000, 0o000001, 0o1, 0o100001, 0o11), // N+C 保存
        (Insn::Bis, 0o000000, 0o000000, 0, 0, 0o4),           // Z
        (Insn::Bisb, 0o000200, 0o000001, 0, 0o177601, 0o10),  // 0201→符号拡張
    ] {
        let mut env = env_at("pdp11_34", 0o1000, &asm(insn, rr));
        sem::psw_put(&mut env.backend, cc0);
        sem::r_set(&mut env.backend, 0, s);
        sem::r_set(&mut env.backend, 1, d0);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 1), nzvc(&env)),
            (d1, cc),
            "{insn:?} src={s:o} dst={d0:o} cc0={cc0:o}"
        );
        // ソースは変わらない。
        assert_eq!(sem::r_get(&env.backend, 0), s, "{insn:?}");
    }
}

#[test]
fn byte_ops_sign_extend_register_dst() {
    // incb で 0177→0200（負）の境界、かつ非ゼロの上位桁が捨てられる
    // こと（byte→レジスタの書き込みは常に符号拡張された全語）。
    let mut env = env_at("pdp11_34", 0o1000, &asm(Insn::Incb, &[Spec::Reg(2)]));
    sem::r_set(&mut env.backend, 2, 0o177177); // 上位にゴミ + 下位 0177
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 2), 0o177600);
    assert_eq!(nzvc(&env), 0o12); // N+V
    // negb r0: 下位バイトの 2 の補数を 16 ビットへ符号拡張。
    let mut env = env_at("pdp11_34", 0o1000, &asm(Insn::Negb, &[Spec::Reg(0)]));
    sem::r_set(&mut env.backend, 0, 0o000005);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o177773); // −5 を符号拡張
    assert_eq!(nzvc(&env), 0o11); // N+C
}

#[test]
fn immediate_and_memory_operands() {
    // add #imm, r0 — 即値ソース。
    let words = asm(Insn::Add, &[Spec::Imm(0o77), Spec::Reg(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0o1);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o100);
    assert_eq!(env.pc, 0o1004);

    // add (r1)+, r0 — オート増の評価順序（ソース→宛先）。
    let words = asm(Insn::Add, &[Spec::AutoInc(1), Spec::Reg(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o2000, 0o30);
    sem::r_set(&mut env.backend, 0, 0o10);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o40);
    assert_eq!(sem::r_get(&env.backend, 1), 0o2002);

    // sub r0, -(r2) — 宛先のオート減（先に下げてから読み・書き戻し）。
    let words = asm(Insn::Sub, &[Spec::Reg(0), Spec::AutoDec(2)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o1776, 0o50);
    sem::r_set(&mut env.backend, 0, 0o10);
    sem::r_set(&mut env.backend, 2, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o1776), 0o40);
    assert_eq!(sem::r_get(&env.backend, 2), 0o1776);

    // neg @#a・inc @#a — メモリの読み・変形・書き戻し。
    for (insn, old, new) in [
        (Insn::Neg, 0o000005u16, 0o177773u16),
        (Insn::Inc, 0o177777, 0),
        (Insn::Com, 0o125252, 0o052525),
        (Insn::Dec, 0o000001, 0),
    ] {
        let words = asm(insn, &[Spec::Abs(0o3000)]);
        let mut env = env_at("pdp11_34", 0o1000, &words);
        put16(&mut env, 0o3000, old);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(get16(&env, 0o3000), new, "{insn:?}");
    }

    // bicb @#a, r0 — 絶対指定子の byte 読み出し（下位バイト）。
    let words = asm(Insn::Bicb, &[Spec::Abs(0o3000), Spec::Reg(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    env.backend.mem.write(VirtAddr(0o3000), &[0o037]).unwrap();
    sem::r_set(&mut env.backend, 0, 0o177);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o140);
}

#[test]
fn index_and_deferred_operands() {
    // bis 4(r3), r0 — インデックス指定子。
    let words = asm(Insn::Bis, &[Spec::Index { r: 3, x: 0o4 }, Spec::Reg(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o2004, 0o100000);
    sem::r_set(&mut env.backend, 3, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o100000);
    assert_eq!(nzvc(&env), 0o10); // N

    // cmp @(r1)+, r0 — 間接オート増（指し先語は常に +2）。
    let words = asm(Insn::Cmp, &[Spec::AutoIncDef(1), Spec::Reg(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o2000, 0o2010); // r1 の指し先 → オペランドアドレス
    put16(&mut env, 0o2010, 0o7);
    sem::r_set(&mut env.backend, 0, 0o7);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(nzvc(&env), 0o4); // Z（等しい）
    assert_eq!(sem::r_get(&env.backend, 1), 0o2002);
}

#[test]
fn same_register_autoinc_order() {
    // mov (r0)+, (r0)+ 系の副作用順序は PD4 の指定子テストで見たが、
    // add -(r0), -(r0) はソースの評価が先: src=-2、dst=-4。
    let words = asm(Insn::Add, &[Spec::AutoDec(0), Spec::AutoDec(0)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o1776, 0o3); // src（先に -2 で指す）
    put16(&mut env, 0o1774, 0o5); // dst（次に -4 で指す）
    sem::r_set(&mut env.backend, 0, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o1774), 0o10); // dst += src
    assert_eq!(get16(&env, 0o1776), 0o3);
    assert_eq!(sem::r_get(&env.backend, 0), 0o1774);
}

#[test]
fn cmp_tst_do_not_write() {
    // cmp r0, @#a — 宛先メモリは変わらない。
    let words = asm(Insn::Cmp, &[Spec::Reg(0), Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o3000, 0o7);
    sem::r_set(&mut env.backend, 0, 0o5);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o3000), 0o7);
    assert_eq!(nzvc(&env), 0o11); // N+C（5 < 7 の借り）

    // bit r0, @#a も書き戻さない。
    let words = asm(Insn::Bit, &[Spec::Reg(0), Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o3000, 0o7);
    sem::r_set(&mut env.backend, 0, 0o4);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o3000), 0o7);
    assert_eq!(nzvc(&env), 0); // 4∧7=4 → 全 CC 落ち
}

#[test]
fn branch_uses_new_cc() {
    // cmp #1, #2; bcc … — cmp が立てた C を直後の分岐が読む。
    // 1-2 → C=1（借り）なので bcs が取られる。
    let mut words = asm(Insn::Cmp, &[Spec::Imm(0o1), Spec::Imm(0o2)]);
    words.push(0o103402); // bcs +2
    words.push(0o000000); // halt（分岐が取られなければここで止まる）
    words.push(0o000240);
    words.push(0o000240);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(nzvc(&env), 0o11); // N+C
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1014); // bcs +2 成立（next=0o1010 + 4）
}

#[test]
fn multi_precision_add_sub_chain() {
    // adc/sbc が多倍長演算の鎖として働く形:
    // 下位語の add が C=1 を出し、上位語の adc が C を拾う。
    let mut env2 = env_at(
        "pdp11_34",
        0o1000,
        &asm(Insn::Add, &[Spec::Reg(2), Spec::Reg(0)]),
    );
    sem::r_set(&mut env2.backend, 0, 1);
    sem::r_set(&mut env2.backend, 2, 0o177777);
    step_m(&mut env2, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env2.backend, 0), 0);
    assert_eq!(nzvc(&env2), 0o5); // Z+C

    // adc r1 — C を拾う。
    let words = asm(Insn::Adc, &[Spec::Reg(1)]);
    let mut env3 = env_at("pdp11_34", 0o1000, &words);
    sem::psw_put(&mut env3.backend, 0o1);
    sem::r_set(&mut env3.backend, 1, 0);
    step_m(&mut env3, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env3.backend, 1), 1);
    assert_eq!(nzvc(&env3), 0); // C 消える

    // sbc で借りが伝播する（0 − C → −1、C 持続）。
    let words = asm(Insn::Sbc, &[Spec::Reg(1)]);
    let mut env4 = env_at("pdp11_34", 0o1000, &words);
    sem::psw_put(&mut env4.backend, 0o1);
    sem::r_set(&mut env4.backend, 1, 0);
    step_m(&mut env4, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env4.backend, 1), 0o177777);
    assert_eq!(nzvc(&env4), 0o11); // N+C
}

// ---- PD6: 論理・シフト・CC 操作 ----

/// FRD 形（reg<8:6> + 指定子）の組立て。`asm` は指定子だけを載せる
/// ので、語の reg フィールドはここで立てる（xor・jsr・EIS 形）。
fn asm_r(insn: Insn, n: u8, specs: &[Spec]) -> Vec<u16> {
    let mut v = asm(insn, specs);
    v[0] |= (u16::from(n) & 7) << 6;
    v
}

#[test]
fn decode_cc_ops_mask() {
    // 条件コード操作はマスク形: ccc=000240+m（選択桁を消す）・
    // scc=000260+m（立てる）。mask=0 の消しは nop の正準名を持つ。
    assert_eq!(dec(0o000240), Some(Insn::Nop));
    for m in 1..=0o17u16 {
        assert_eq!(dec(0o000240 | m), Some(Insn::Ccc), "ccc+{m:o}");
        assert_eq!(dec(0o000260 | m), Some(Insn::Scc), "scc+{m:o}");
    }
    // マスク 0 の立て側（000260）も合法で、実行しても何もしない。
    assert_eq!(dec(0o000260), Some(Insn::Scc));
    // 000220-000227 は予約（spl も 00023x のみ）。
    assert_eq!(dec(0o000220), None);
    assert_eq!(dec_m(0o000227, "pdp11_70"), None);
    // 個別名はマスクの特例なので逆アセンブルは族名に畳まれる。
    assert_eq!(disasm_word(0o000241, 16).as_deref(), Some("ccc"));
}

/// シフト・回転の (insn, 旧 r0, CC0) → (r0, CC) 一括検査。
/// C=シフトアウトした桁、V=N xor C（新しい両ビット）。byte 形は
/// 下位バイトで演算し符号拡張で書き戻す。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn shift_rotate_cc_table() {
    let r0 = &[Spec::Reg(0)][..];
    for (insn, old, cc0, new, cc) in [
        // asr: 右へ 1 桁シフトして符号桁を複写。C=旧最下位桁。
        (Insn::Asr, 0o000005u16, 0, 0o000002, 0o3), // +5→+2、V=N xor C
        (Insn::Asr, 0o100000, 0o1, 0o140000, 0o12), // M.N.I./2、N+V
        (Insn::Asr, 0o177777, 0, 0o177777, 0o11),   // −1→−1、N+C
        (Insn::Asr, 0o000001, 0, 0, 0o7),           // +1→0、Z+V+C
        (Insn::Asr, 0o000004, 0o17, 0o000002, 0),   // 旧 CC は置き換わる
        // asrb: 0201(−127)→0300(−64) を符号拡張。
        (Insn::Asrb, 0o000201, 0, 0o177700, 0o11), // N+C
        (Insn::Asrb, 0o000101, 0, 0o000040, 0o3),  // 0101→040、V+C
        (Insn::Asrb, 0o000200, 0, 0o177700, 0o12), // −128→−64、N+V
        // asl: 左へ 1 桁シフトして 0 挿入。C=旧符号桁。
        (Insn::Asl, 0o040000, 0, 0o100000, 0o12), // N+V（溢れ）
        (Insn::Asl, 0o100000, 0, 0, 0o7),         // →0、Z+V+C
        (Insn::Asl, 0o177777, 0, 0o177776, 0o11), // N+C
        (Insn::Asl, 0o077777, 0o1, 0o177776, 0o12), // 旧 C は置き換わる
        // aslb: 0177→0376（符号拡張 −2）。
        (Insn::Aslb, 0o000177, 0, 0o177776, 0o12), // N+V
        (Insn::Aslb, 0o000200, 0, 0, 0o7),         // →0、Z+V+C
        // ror: C を最上位に入れる右回転。C=旧最下位桁。
        (Insn::Ror, 0o000002, 0o1, 0o100001, 0o12), // C が入る、N+V
        (Insn::Ror, 0o000001, 0, 0, 0o7),           // →0、Z+V+C
        (Insn::Ror, 0o100000, 0, 0o040000, 0),      // 符号桁→040000
        (Insn::Ror, 0o100001, 0o1, 0o140000, 0o11), // N+C
        // rorb: 0201、C=0 → 0100。C=1、V=N xor C=1。
        (Insn::Rorb, 0o000201, 0, 0o000100, 0o3), // V+C
        // rol: C を最下位に入れる左回転。C=旧符号桁。
        (Insn::Rol, 0o100000, 0o1, 0o000001, 0o3),  // V+C
        (Insn::Rol, 0o000001, 0o1, 0o000003, 0),    // C が入る
        (Insn::Rol, 0o000000, 0o1, 0o000001, 0),    // 0→1、C 消える
        (Insn::Rol, 0o177777, 0o1, 0o177777, 0o11), // 全 1→全 1、N+C
        // rolb: 0100、C=1 → 0201（符号拡張 −127）。
        (Insn::Rolb, 0o000100, 0o1, 0o177601, 0o12), // N+V
    ] {
        let mut env = env_at("pdp11_34", 0o1000, &asm(insn, r0));
        sem::psw_put(&mut env.backend, cc0);
        sem::r_set(&mut env.backend, 0, old);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 0), nzvc(&env)),
            (new, cc),
            "{insn:?} dst={old:o} cc0={cc0:o}"
        );
    }
}

#[test]
fn shift_memory_operand() {
    // asl @#a — メモリの読み・シフト・書き戻し。
    let words = asm(Insn::Asl, &[Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o3000, 0o040000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o3000), 0o100000);
    assert_eq!(nzvc(&env), 0o12); // N+V

    // rorb @#a — バイトの読み・回転・書き戻し（語の下位バイト）。
    let words = asm(Insn::Rorb, &[Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o3000, 0o000201);
    sem::psw_put(&mut env.backend, 0o1); // C=1
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o3000) & 0xff, 0o300);
    assert_eq!(nzvc(&env), 0o11); // N+C
}

/// swab は語専用 — 上下バイトを交換し、結果の下位バイトで N/Z、
/// V・C は消える。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn swab_cc() {
    for (old, cc0, new, cc) in [
        (0o100377u16, 0, 0o177600u16, 0o10), // 結果の下位 0200 → N
        (0o000377, 0o17, 0o177400, 0o4),     // 結果の下位 0 → Z、V/C 消える
        (0o052400, 0o1, 0o000125, 0),        // 正の下位バイト、C 消える
        (0o177777, 0, 0o177777, 0o10),       // 0xff↔0xff → N
        (0o000200, 0o3, 0o100000, 0o4),      // 結果の下位 0 → Z
    ] {
        let mut env = env_at("pdp11_34", 0o1000, &asm(Insn::Swab, &[Spec::Reg(0)]));
        sem::psw_put(&mut env.backend, cc0);
        sem::r_set(&mut env.backend, 0, old);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 0), nzvc(&env)),
            (new, cc),
            "swab {old:o} cc0={cc0:o}"
        );
    }
    // swab @#a — メモリの語も交換する。
    let words = asm(Insn::Swab, &[Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o3000, 0o100377);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o3000), 0o177600);
    assert_eq!(nzvc(&env), 0o10); // N
}

/// sxt は N を dst 語全体へ拡張する。N・C は不変、Z=N が消えて
/// いるときに立つ、V=0。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn sxt_extends_n() {
    for (cc0, new, cc) in [
        (0o10u16, 0o177777u16, 0o10u16), // N → −1、N が残る
        (0o11, 0o177777, 0o11),          // N+C → C も残る
        (0, 0, 0o4),                     // N=0 → 0、Z
        (0o5, 0, 0o5),                   // Z+C → Z・C とも残る
        (0o16, 0o177777, 0o10),          // N+Z+V → Z・V は消える
    ] {
        let mut env = env_at("pdp11_34", 0o1000, &asm(Insn::Sxt, &[Spec::Reg(0)]));
        sem::psw_put(&mut env.backend, cc0);
        sem::r_set(&mut env.backend, 0, 0o123456);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 0), nzvc(&env)),
            (new, cc),
            "sxt cc0={cc0:o}"
        );
    }
    // sxt @#a — メモリへも −1 を書く。
    let words = asm(Insn::Sxt, &[Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    sem::psw_put(&mut env.backend, 0o10);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o3000), 0o177777);
    assert_eq!(nzvc(&env), 0o10); // N 不変
}

/// xor はレジスタ形 — dst ← reg ^ dst。V=0・C 不変。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn xor_cc_and_operands() {
    for (s, d0, cc0, d1, cc) in [
        (0o125252u16, 0o052525u16, 0o1u16, 0o177777u16, 0o11u16), // N+C 保存
        (0o125252, 0o125252, 0o10, 0, 0o4),                       // Z、N 消える
        (0o000000, 0o077777, 0o17, 0o077777, 0o1),                // C のみ残る
        (0o177777, 0o000000, 0, 0o177777, 0o10),                  // N
    ] {
        // xor r0, r1 — 語の reg フィールド <8:6> = 0。
        let mut env = env_at("pdp11_34", 0o1000, &asm_r(Insn::Xor, 0, &[Spec::Reg(1)]));
        sem::psw_put(&mut env.backend, cc0);
        sem::r_set(&mut env.backend, 0, s);
        sem::r_set(&mut env.backend, 1, d0);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 1), nzvc(&env)),
            (d1, cc),
            "xor {s:o}^{d0:o} cc0={cc0:o}"
        );
        // ソースレジスタは変わらない。
        assert_eq!(sem::r_get(&env.backend, 0), s);
    }
    // xor r2, @#a — 宛先メモリの書き戻し。
    let words = asm_r(Insn::Xor, 2, &[Spec::Abs(0o3000)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o3000, 0o052525);
    sem::psw_put(&mut env.backend, 0o1); // C=1
    sem::r_set(&mut env.backend, 2, 0o125252);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(get16(&env, 0o3000), 0o177777);
    assert_eq!(nzvc(&env), 0o11); // N+C 保存
}

/// 条件コード操作: ccc=000240+m（消し）・scc=000260+m（立て）。
/// 個別名（clc/sec/…）と複合マスク・マスク 0 のどれも正規の形。
// Ref: SPEC-PDP11-ARCH83（第5章 条件コード操作）.
#[test]
fn cc_ops_apply_mask() {
    for (word, cc0, cc) in [
        (0o000241u16, 0o17u16, 0o16u16), // clc: C を消す
        (0o000242, 0o17, 0o15),          // clv
        (0o000244, 0o17, 0o13),          // clz
        (0o000250, 0o17, 0o07),          // cln
        (0o000257, 0o17, 0),             // ccc: 全消し
        (0o000243, 0o17, 0o14),          // 複合: V+C を消す
        (0o000261, 0o16, 0o17),          // sec: C を立てる
        (0o000262, 0o15, 0o17),          // sev
        (0o000264, 0o13, 0o17),          // sez
        (0o000270, 0o07, 0o17),          // sen
        (0o000277, 0, 0o17),             // scc: 全立て
        (0o000263, 0o10, 0o13),          // 複合: V+C を立てる
        (0o000260, 0o05, 0o05),          // scc+0: 何もしない
        (0o000240, 0o13, 0o13),          // nop: 何もしない
    ] {
        let mut env = env_at("pdp11_34", 0o1000, &[word]);
        sem::psw_put(&mut env.backend, cc0);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(nzvc(&env), cc, "{word:o} cc0={cc0:o}");
        assert_eq!(env.pc, 0o1002);
    }
    // CC 以外の PSW 桁（T・優先度・モード）は触らない。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000257]); // ccc
    sem::psw_put(&mut env.backend, 0o177777);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::psw_get(&env.backend), 0o177760);
}

// ---- PD7: サブルーチン命令（sob・jsr・rts・mark）----

#[test]
fn decode_subroutine_insns() {
    assert_eq!(dec(0o004000), Some(Insn::Jsr)); // jsr r0, …
    assert_eq!(dec(0o004777), Some(Insn::Jsr)); // jsr r7, …
    assert_eq!(dec(0o006400), Some(Insn::Mark)); // mark 0
    assert_eq!(dec(0o006477), Some(Insn::Mark)); // mark 63
    assert_eq!(dec(0o077000), Some(Insn::Sob)); // sob r0, -0
    assert_eq!(dec(0o000200), Some(Insn::Rts)); // rts r0
    assert_eq!(dec(0o000207), Some(Insn::Rts)); // rts pc
}

/// sob は reg−1 が非零なら PC−2×off6（語単位の後方向き）へ。
/// 条件コードは不変。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn sob_counts_down_backward() {
    // sob r2, off4 — 分岐の可否と語単位の後方変位。
    for (r2, new_r2, pc) in [
        (0o5u16, 0o4u16, 0o772u16), // 5→4、next(0o1002)−2×4
        (0o1, 0, 0o1002),           // 1→0 で素通し
        (0, 0o177777, 0o772),       // 0→−1（非零）で分岐
    ] {
        let mut env = env_at("pdp11_34", 0o1000, &[0o077204]);
        sem::r_set(&mut env.backend, 2, r2);
        step_m(&mut env, "pdp11_34").unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 2), env.pc as u16),
            (new_r2, pc),
            "sob r2={r2:o}"
        );
    }
    // off6=0 は減算だけで同じ次の語へ進む。
    let mut env = env_at("pdp11_34", 0o1000, &[0o077200]);
    sem::r_set(&mut env.backend, 2, 0o5);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::r_get(&env.backend, 2), 0o4);
    assert_eq!(env.pc, 0o1002);
    // CC は不変（立てたまま残る）。
    let mut env = env_at("pdp11_34", 0o1000, &[0o077204]);
    sem::r_set(&mut env.backend, 2, 0o1);
    sem::psw_put(&mut env.backend, 0o17);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(nzvc(&env), 0o17);
    // sob ループ: 3 回まわしてから落ちる（off6=2 は nop の位置）。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000240, 0o077202]);
    sem::r_set(&mut env.backend, 2, 0o3);
    for i in 0..3 {
        step_m(&mut env, "pdp11_34").unwrap(); // nop（ループ先）
        step_m(&mut env, "pdp11_34").unwrap(); // sob
        assert_eq!(sem::r_get(&env.backend, 2), 2 - i);
    }
    assert_eq!(env.pc, 0o1004); // 3 回目で落ちる
}

/// jsr は tmp=宛先アドレス→link を -(SP) へ→link=次の命令→PC=tmp。
/// 宛先は指定子評価（@#a の絶対語等）で、CC は不変。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn jsr_pushes_link_and_loads_return() {
    let words = asm_r(Insn::Jsr, 5, &[Spec::Abs(0o3000)]);
    assert_eq!(words, [0o004537, 0o3000]); // jsr r5, @#a
    let mut env = env_at("pdp11_34", 0o1000, &words);
    sem::r_set(&mut env.backend, 5, 0o7777);
    sem::psw_put(&mut env.backend, 0o17); // CC は不変
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    assert_eq!(sem::r_get(&env.backend, 5), 0o1004); // link=次の命令
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(sp, SP0 - 2);
    assert_eq!(get16(&env, sp), 0o7777); // 旧 link 値が積まれた
    assert_eq!(nzvc(&env), 0o17);
}

/// link レジスタが dst 評価のオート増減で変わるとき、積まれるのは
/// 変更後の値（jsr r5,@(r5)+ の規則 — 指定子の書き戻しが push の
/// 読み出しに先立つ）。EA 自体は増分前の値。
// Ref: SPEC-PDP11-ARCH83（第5章 jsr の記述）.
#[test]
fn jsr_link_autoinc_pushes_modified_value() {
    let words = asm_r(Insn::Jsr, 5, &[Spec::AutoIncDef(5)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o2000, 0o3000); // r5 の指し先 → サブルーチン
    sem::r_set(&mut env.backend, 5, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000); // 増分前の指し先語がジャンプ先
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o2002); // 増分後の r5 が積まれた
    assert_eq!(sem::r_get(&env.backend, 5), 0o1002); // link=次の命令
}

/// rts は PC=link→link=(SP)+。link に SP・PC を選んだときも規定の
/// 逐語順に従う（rts pc は積まれた戻りアドレスが PC に入る）。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn rts_pops_link_after_jump() {
    // rts r0 — 跳び先は r0 の旧値、r0 にはスタックの語が入る。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000200]);
    put16(&mut env, SP0, 0o5555);
    sem::r_set(&mut env.backend, 0, 0o3000);
    sem::psw_put(&mut env.backend, 0o17); // CC は不変
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    assert_eq!(sem::r_get(&env.backend, 0), 0o5555);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0 + 2);
    assert_eq!(nzvc(&env), 0o17);
    // rts pc — link=PC は積まれた語がそのまま PC になる。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000207]);
    put16(&mut env, SP0, 0o3000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0 + 2);
    // rts sp — PC←旧 SP、(SP) の語が SP に入る（更新の逐語順）。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000206]);
    put16(&mut env, SP0, 0o4444);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, u64::from(SP0));
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), 0o4444);
}

/// jsr/rts の往復 — link レジスタを変えた組と PC link 規約。
// Ref: SPEC-PDP11-ARCH83（第5章・付録 F）.
#[test]
fn jsr_rts_roundtrip_and_link_regs() {
    // jsr r5, @#0o3000 の後に rts r5 — link の往復。
    let mut env = env_at(
        "pdp11_34",
        0o1000,
        &asm_r(Insn::Jsr, 5, &[Spec::Abs(0o3000)]),
    );
    put16(&mut env, 0o3000, 0o000205); // rts r5
    sem::r_set(&mut env.backend, 5, 0o7777);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1004); // jsr の次へ戻る
    assert_eq!(sem::r_get(&env.backend, 5), 0o7777); // link 復元
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0);
    // jsr pc, @#a — link=PC は戻りアドレスを積むだけで、rts pc が
    // それを PC へ戻す（汎用レジスタを link に取らない規約）。
    let mut env = env_at(
        "pdp11_34",
        0o1000,
        &asm_r(Insn::Jsr, 7, &[Spec::Abs(0o3000)]),
    );
    put16(&mut env, 0o3000, 0o000207); // rts pc
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    assert_eq!(get16(&env, SP0 - 2), 0o1004); // 戻りアドレス
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1004);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0);
}

/// 同じ link レジスタでの 2 段呼出 — link は順に積まれ逆順に
/// 復元される（jsr の自動ネスト規則）。
// Ref: SPEC-PDP11-ARCH83（第5章）.
#[test]
fn jsr_rts_nests_with_same_link() {
    // 0o1000: jsr r5, @#0o3000 (戻り 0o1004)
    // 0o3000: jsr r5, @#0o3400 (戻り 0o3004)
    // 0o3004: rts r5
    // 0o3400: rts r5
    let w2 = asm_r(Insn::Jsr, 5, &[Spec::Abs(0o3400)]);
    let mut env = env_at(
        "pdp11_34",
        0o1000,
        &asm_r(Insn::Jsr, 5, &[Spec::Abs(0o3000)]),
    );
    put16(&mut env, 0o3000, w2[0]);
    put16(&mut env, 0o3002, w2[1]);
    put16(&mut env, 0o3004, 0o000205); // rts r5
    put16(&mut env, 0o3400, 0o000205); // rts r5
    sem::r_set(&mut env.backend, 5, 0o7777);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    assert_eq!(sem::r_get(&env.backend, 5), 0o1004);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3400);
    assert_eq!(sem::r_get(&env.backend, 5), 0o3004); // link 上書き
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o1004); // top = 外側の戻り link
    assert_eq!(get16(&env, sp + 2), 0o7777); // その下 = 旧 r5
    step_m(&mut env, "pdp11_34").unwrap(); // 内側の rts
    assert_eq!(env.pc, 0o3004);
    assert_eq!(sem::r_get(&env.backend, 5), 0o1004);
    step_m(&mut env, "pdp11_34").unwrap(); // 外側の rts
    assert_eq!(env.pc, 0o1004);
    assert_eq!(sem::r_get(&env.backend, 5), 0o7777);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0);
}

/// mark は SP=PC+2×nn→PC=r5→r5=(SP)+ の手順除去形（rti 類似）。
/// 標準規約では mark 語そのものがスタック上に置かれ、PC+2n が
/// スタック内の引数ブロックを飛び越える基準になる —— ここでは
/// 同じ語列をコード領域に置いて逐語の規則を見る（mem は単一空間）。
// Ref: SPEC-PDP11-ARCH83（第5章・第9章）.
#[test]
fn mark_discards_frame_and_restores_r5() {
    // 0o1000: mark 2 / 0o1002: 引数語 / 0o1004: 引数語 /
    // 0o1006: 復元される r5 —— SP は PC+2×2 で 0o1006 を指す。
    let mut env = env_at("pdp11_34", 0o1000, &[0o006402, 0o1111, 0o2222, 0o7777]);
    sem::r_set(&mut env.backend, 5, 0o3000); // 呼出側の続き
    sem::psw_put(&mut env.backend, 0o17); // CC は不変
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000); // PC ← r5
    assert_eq!(sem::r_get(&env.backend, 5), 0o7777); // r5 ← (SP)+
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), 0o1010);
    assert_eq!(nzvc(&env), 0o17);
    // mark 0 — 引数なし。SP は次の語を指し、そこから pop する。
    let mut env = env_at("pdp11_34", 0o1000, &[0o006400, 0o5555]);
    sem::r_set(&mut env.backend, 5, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o2000);
    assert_eq!(sem::r_get(&env.backend, 5), 0o5555);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), 0o1004);
}

/// jmp/jsr の残りの指定子形 — 即値語の位置が EA、間接形は指し先。
/// jsr のモード 0 宛先も jmp と同じ jmp_reg_trap のベクタに落ちる。
// Ref: SPEC-PDP11-ARCH83（第4・5章・付録 B 項目 5）.
#[test]
fn jmp_jsr_specifier_forms() {
    // jmp #x — 即値語（命令ストリームの次の語）のアドレスが EA。
    let words = asm(Insn::Jmp, &[Spec::Imm(0o1234)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o1002); // 即値語の位置へ跳ぶ
    // jmp @(r2)+ — 指し先語がジャンプ先、r2 は +2。
    let words = asm(Insn::Jmp, &[Spec::AutoIncDef(2)]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    put16(&mut env, 0o2000, 0o3000);
    sem::r_set(&mut env.backend, 2, 0o2000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3000);
    assert_eq!(sem::r_get(&env.backend, 2), 0o2002);
    // jmp x(r3) — インデックス指定子。
    let words = asm(Insn::Jmp, &[Spec::Index { r: 3, x: 0o40 }]);
    let mut env = env_at("pdp11_34", 0o1000, &words);
    sem::r_set(&mut env.backend, 3, 0o3000);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o3040);
    // jsr r0, r1 — モード 0 の A アクセスは jmp_reg_trap のベクタ。
    let words = asm_r(Insn::Jsr, 0, &[Spec::Reg(1)]);
    for (model, vec) in [("pdp11_34", 0o004u16), ("pdp11_23", 0o010u16)] {
        let mut env = env_at(model, 0o1000, &words);
        put16(&mut env, vec, 0o3200);
        step_m(&mut env, model).unwrap();
        assert_eq!(env.pc, 0o3200, "{model}");
        let sp = sem::r_get(&env.backend, reg::SP as u8);
        assert_eq!(get16(&env, sp), 0o1000); // fault — 命令先頭
    }
}
