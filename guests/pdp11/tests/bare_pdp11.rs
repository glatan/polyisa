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
    // + FIS 4 + FP11 26 + 分岐 15 + EMT/TRAP 2 + MARK/SPL 2 + 固定語 11
    // （条件コード操作は nop + ccc/scc のマスク形として数える）。
    assert_eq!(INSNS.len(), 116);
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
    // CC 以外の PSW 桁（優先度・モード）は触らない。T は立てない —
    // 立つと命令の完了時にトレーストラップが発火し、この裸環境の
    // カーネルスタック退避先（ksp=0）は未写像で配送できない
    // （発火自体の検証は PD8 節の tbit_trace_* が担う）。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000257]); // ccc
    sem::psw_put(&mut env.backend, 0o177757);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(sem::psw_get(&env.backend), 0o177740);
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

// ---- PD8: トラップ・特権・システム命令 ----

use polyisa_sem::{Backend, StateRef, W16, W64};

/// 状態面の語（ksp/ssp/usp/mmr などの退避先）を書く。
fn st_put(env: &mut BareEnv, off: usize, v: u16) {
    env.backend.set(StateRef::<W16>::from_offset(off), v);
}

/// 状態面の語を読む。
fn st_get(env: &mut BareEnv, off: usize) -> u16 {
    env.backend.get(StateRef::<W16>::from_offset(off))
}

const KSP: usize = core::mem::offset_of!(CpuState, ksp);
const SSP: usize = core::mem::offset_of!(CpuState, ssp);
const USP: usize = core::mem::offset_of!(CpuState, usp);
const MMR3: usize = core::mem::offset_of!(CpuState, mmr) + 6;

/// trap → ハンドラの rti で積まれた PC・PSW が往復する。
/// スタック形状は PC が下位・PSW が上位（-(SP) PSW→PC の順）。
// Ref: SPEC-PDP11-ARCH83（第5章 RTI・第8章）.
#[test]
fn rti_round_trip_through_trap() {
    let mut env = env_at("pdp11_34", 0o1000, &[0o104400, 0o000240]); // trap / nop
    put16(&mut env, 0o034, 0o2000);
    put16(&mut env, 0o036, 0o17); // 新 PSW（CC 立ち）
    put16(&mut env, 0o2000, 0o000002); // rti
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o2000);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(sp, SP0 - 4);
    assert_eq!(get16(&env, sp), 0o1002); // trap — 次の命令
    assert_eq!(get16(&env, sp + 2), 0); // 旧 PSW
    assert_eq!(sem::psw_get(&env.backend), 0o17);
    step_m(&mut env, "pdp11_34").unwrap(); // rti
    assert_eq!(env.pc, 0o1002);
    assert_eq!(sem::psw_get(&env.backend), 0);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0);
}

/// モードを跨ぐ RTI・トラップはモード別 SP 退避先を経由する。
/// カーネルの rti がユーザーモード PSW を復元すれば r6 は USP に
/// 切替わり、ユーザー側のトラップは（新 PSW の）カーネルスタックへ。
// Ref: SPEC-PDP11-ARCH83（第5章 RTI・第9章）.
#[test]
fn rti_and_trap_switch_per_mode_stacks() {
    let mut env = env_at("pdp11_70", 0o1000, &[0o000002]); // rti
    put16(&mut env, SP0, 0o2000); // 復帰 PC
    put16(&mut env, SP0 + 2, 0o140000); // ユーザーモード PSW
    put16(&mut env, 0o2000, 0o104000); // ユーザー側で emt 0
    put16(&mut env, 0o030, 0o2400); // emt ベクタ → カーネルハンドラ
    put16(&mut env, 0o032, 0); // 新 PSW = カーネル
    put16(&mut env, 0o2400, 0o000002); // ハンドラ末尾は rti
    st_put(&mut env, USP, 0o6000);
    step_m(&mut env, "pdp11_70").unwrap(); // rti — ユーザーモードへ
    assert_eq!(env.pc, 0o2000);
    assert_eq!(sem::psw_get(&env.backend), 0o140000);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), 0o6000); // USP
    assert_eq!(st_get(&mut env, KSP), SP0 + 4); // pop 後のカーネル SP
    step_m(&mut env, "pdp11_70").unwrap(); // ユーザーモードの emt
    assert_eq!(env.pc, 0o2400);
    assert_eq!(sem::psw_get(&env.backend), 0);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(sp, SP0); // カーネルスタック（SP0+4）に 2 語
    assert_eq!(get16(&env, sp), 0o2002);
    assert_eq!(get16(&env, sp + 2), 0o140000); // 旧 PSW = ユーザー
    assert_eq!(st_get(&mut env, USP), 0o6000); // USP 退避は不変
    step_m(&mut env, "pdp11_70").unwrap(); // rti — ユーザーへ戻る
    assert_eq!(env.pc, 0o2002);
    assert_eq!(sem::psw_get(&env.backend), 0o140000);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), 0o6000);
}

/// カーネル以外で実行した rti は PSW 保護規則が掛かる —— 優先度
/// <7:5> は現値のまま、<15:12>・RS<11> は旧値との OR でしか下がら
/// ない（user から kernel へは戻れない）。
// Ref: SPEC-PDP11-J11（8.4.1・8.4.4 RTI）.
#[test]
fn rti_in_user_mode_preserves_protected_bits() {
    let mut env = env_at("pdp11_70", 0o1000, &[0o000002]); // rti
    sem::psw_put(&mut env.backend, 0o140240); // ユーザー・優先度 5
    sem::r_set(&mut env.backend, reg::SP as u8, 0o6000);
    put16(&mut env, 0o6000, 0o3000); // 復帰 PC
    put16(&mut env, 0o6002, 0o177757); // kernel・pri7・RS・CC を偽装
    step_m(&mut env, "pdp11_70").unwrap();
    assert_eq!(env.pc, 0o3000);
    // <15:12> = user|kernel = user 維持、RS = 0|1 = 1、優先度は旧 5、
    // <10:0> は積まれた値（T は積まれていないので発火しない）。
    assert_eq!(sem::psw_get(&env.backend), 0o177657);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), 0o6004);
}

/// T ビットトレーストラップ。imm モデル（既定）では RTI が T を立てた
/// 直後に発火、RTT は抑止して次の命令の完了時に発火する。traced な
/// 命令が T を消しても発火する（フェッチ時の内部 flag）。
// Ref: SPEC-PDP11-J11（8.7.7）, SPEC-PDP11-ARCH83（付録 B 項目 11）.
#[test]
fn tbit_trace_trap_and_rtt_timing() {
    // RTI → T=1: 次の命令の実行前に vector 014 へ。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000002]); // rti
    put16(&mut env, SP0, 0o2000);
    put16(&mut env, SP0 + 2, 0o20); // T=1
    put16(&mut env, 0o014, 0o2400);
    put16(&mut env, 0o016, 0); // ハンドラ PSW（T=0）
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o2400);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o2000); // 次の命令が積まれる
    assert_eq!(get16(&env, sp + 2) & 0o20, 0o20); // 積んだ PSW は T=1
    assert_eq!(sem::psw_get(&env.backend), 0);
    // RTT → T=1: 境界では発火せず、次の命令の完了時に発火。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000006]); // rtt
    put16(&mut env, SP0, 0o2000);
    put16(&mut env, SP0 + 2, 0o20);
    put16(&mut env, 0o2000, 0o000240); // 次の命令 nop
    put16(&mut env, 0o014, 0o2400);
    put16(&mut env, 0o016, 0);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o2000); // 抑止
    step_m(&mut env, "pdp11_34").unwrap(); // nop —— traced
    assert_eq!(env.pc, 0o2400);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o2002);
    // traced な命令が T を消しても発火（積む PSW は T=0）。
    let mut env = env_at("pdp11_34", 0o1000, &[0o000002]); // rti
    sem::psw_put(&mut env.backend, 0o20); // T=1 で実行 —— traced
    put16(&mut env, SP0, 0o2000);
    put16(&mut env, SP0 + 2, 0); // T=0 を復元
    put16(&mut env, 0o014, 0o2400);
    put16(&mut env, 0o016, 0);
    step_m(&mut env, "pdp11_34").unwrap();
    assert_eq!(env.pc, 0o2400);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp + 2), 0); // 積んだ PSW は T=0
}

/// mtps/mfps は PSW 下位バイトを読み書きする。mtps は T<4> を書けず、
/// カーネル以外では NZVC だけが変わる。mfps のレジスタ宛ては bit7 の
/// 符号拡張、N=bit7・Z=(byte==0)・V=0・C 不変。
// Ref: SPEC-PDP11-J11（8.4.4 MTPS/MFPS）, SPEC-PDP11-ARCH83（第5章）.
#[test]
fn mtps_mfps_low_byte_semantics() {
    // カーネル: <7:0> を書くが T は保存（0o377 を書いても T=0）。
    let words = asm(Insn::Mtps, &[Spec::Imm(0o377)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(sem::psw_get(&env.backend), 0o357);
    // ユーザーモード: NZVC のみ書き換わる。
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::psw_put(&mut env.backend, 0o140240); // ユーザー・優先度 5
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(sem::psw_get(&env.backend), 0o140257);
    // mfps r0 —— 符号拡張（0o357 → 0o177757）。N=1・V=0・C 保存。
    let words = asm(Insn::Mfps, &[Spec::Reg(0)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::psw_put(&mut env.backend, 0o357 | 1);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o177757);
    assert_eq!(nzvc(&env), 0o11); // N=1・Z=0・V=0・C=1（保存）
    // mfps @(r1) —— メモリ宛ては下位バイトのみ（上位は残る）。
    let words = asm(Insn::Mfps, &[Spec::RegDef(1)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::psw_put(&mut env.backend, 0o244); // bit7=1・C=0
    sem::r_set(&mut env.backend, 1, 0o2000);
    put16(&mut env, 0o2000, 0o1234);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(get16(&env, 0o2000), 0o1244); // 上位バイト 0o2 は残る
    assert_eq!(nzvc(&env), 0o10); // N=1（bit7）
}

/// MFPT は R0 にモデル固有のプロセッサ型番を返す（`mfpt_code`
/// パラメータ。上位バイトのサブコードは 0）。
// Ref: SPEC-PDP11-ARCH83（第5章 MFPT）, SPEC-PDP11-J11（8.6 MFPT）.
#[test]
fn mfpt_returns_model_processor_code() {
    for (model, code) in [
        ("pdp11_44", 1u16),
        ("pdp11_23", 3),
        ("pdp11_24", 3), // 親チェーンで継承
        ("pdp11_73", 5),
        ("pdp11_93", 5),
        ("t11", 4),
    ] {
        let mut env = env_at(model, 0o1000, &[0o000007]);
        step_m(&mut env, model).unwrap();
        assert_eq!(sem::r_get(&env.backend, 0), code, "{model}");
    }
}

/// SPL はカーネルモードで PSW<7:5> を書き、他のモードでは NOP。
// Ref: SPEC-PDP11-J11（8.4.1・8.4.4 SPL）.
#[test]
fn spl_sets_priority_in_kernel_only() {
    let mut env = env_at("pdp11_70", 0o1000, &[0o000235]); // spl 5
    step_m(&mut env, "pdp11_70").unwrap();
    assert_eq!(sem::psw_get(&env.backend), 5 << psw::PRI);
    let mut env = env_at("pdp11_70", 0o1000, &[0o000237]); // spl 7
    sem::psw_put(&mut env.backend, 0o140000 | 0o17); // ユーザー・CC 立ち
    step_m(&mut env, "pdp11_70").unwrap();
    assert_eq!(sem::psw_get(&env.backend), 0o140000 | 0o17); // NOP —— CC も不変
}

/// CSM: MMR3<3> が立ちカーネル以外で実行すると、SSP に現 SP を残して
/// スーパーバイザモードへ移り、3 語（CC 消し PSW・PC・引数語）を積み
/// PC ← (010)。復帰は引数語を捨てて RTI。
// Ref: SPEC-PDP11-J11（8.7.5）.
#[test]
fn csm_calls_supervisor_and_returns_via_rti() {
    let words = asm(Insn::Csm, &[Spec::Imm(0o1234)]);
    let mut env = env_at("pdp11_73", 0o1000, &words);
    sem::psw_put(&mut env.backend, 0o140017); // ユーザー・CC 全部
    sem::r_set(&mut env.backend, reg::SP as u8, 0o6000);
    st_put(&mut env, SSP, 0o7777); // 旧 SSP は捨てられる
    st_put(&mut env, MMR3, 0o10); // MMR3<3> = 1
    put16(&mut env, 0o010, 0o2400);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(env.pc, 0o2400);
    // cur=sup・prev=user・T=0、優先度と CC は維持。
    assert_eq!(sem::psw_get(&env.backend), 0o070017);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(sp, 0o6000 - 6);
    assert_eq!(get16(&env, sp), 0o1234); // -(SP) ← 引数語（最後に積む）
    assert_eq!(get16(&env, sp + 2), 0o1004); // -(SP) ← 復帰 PC
    assert_eq!(get16(&env, sp + 4), 0o140000); // -(SP) ← CC 消し PSW
    assert_eq!(st_get(&mut env, SSP), 0o6000); // supervisor SP ← 現 SP
    assert_eq!(st_get(&mut env, USP), 0o6000); // モード退避も残る
    // ハンドラが引数語を捨てて RTI で戻る。
    put16(&mut env, 0o2400, 0o000002); // rti
    sem::r_set(&mut env.backend, reg::SP as u8, sp + 2);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(env.pc, 0o1004);
    // スーパーバイザの RTI は保護付き —— 復元モードは sup|user=user。
    assert_eq!(sem::psw_get(&env.backend) >> psw::CUR_MOD, psw::USER);
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), 0o6000);
    // カーネルモードでは違法 —— vector 010 に fault（命令先頭）。
    let mut env = env_at("pdp11_73", 0o1000, &words);
    st_put(&mut env, MMR3, 0o10);
    put16(&mut env, 0o010, 0o2200);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(env.pc, 0o2200);
    assert_eq!(get16(&env, sem::r_get(&env.backend, reg::SP as u8)), 0o1000);
    // MMR3<3>=0 でも同じく vector 010 に fault。
    let mut env = env_at("pdp11_73", 0o1000, &words);
    sem::psw_put(&mut env.backend, 0o140000);
    sem::r_set(&mut env.backend, reg::SP as u8, 0o6000);
    st_put(&mut env, USP, 0o6000);
    st_put(&mut env, KSP, SP0);
    put16(&mut env, 0o010, 0o2200);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(env.pc, 0o2200);
}

/// TSTSET/WRTLCK の読み書き不可分（単一スレッド近似で読み→書き）。
/// TSTSET: R0←(dst)、(dst)←(dst)∨1、N・Z は読み出し値、C←旧 bit0。
/// WRTLCK: (dst)←R0、N・Z は R0、C 不変。モード 0 は vector 010。
// Ref: SPEC-PDP11-J11（8.4.4 WRTLCK/TSTSET）.
#[test]
fn tstset_and_wrtlck_interlock_words() {
    let words = asm(Insn::Tstset, &[Spec::RegDef(1)]);
    let mut env = env_at("pdp11_24", 0o1000, &words);
    sem::r_set(&mut env.backend, 1, 0o2000);
    put16(&mut env, 0o2000, 0o100000); // 負・bit0=0
    step_m(&mut env, "pdp11_24").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o100000);
    assert_eq!(get16(&env, 0o2000), 0o100001);
    assert_eq!(nzvc(&env), 0o10); // N のみ（V=0・C=旧 bit0=0）
    // 既に立った bit0 は C に残り、dst は 1 のまま。
    let mut env = env_at("pdp11_24", 0o1000, &words);
    sem::r_set(&mut env.backend, 1, 0o2000);
    put16(&mut env, 0o2000, 0o000001);
    step_m(&mut env, "pdp11_24").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 1);
    assert_eq!(get16(&env, 0o2000), 1);
    assert_eq!(nzvc(&env), 0o01); // C=1
    // wrtlck @r1: (dst)←R0。N・Z は R0 で、C は不変。
    let words = asm(Insn::Wrtlck, &[Spec::RegDef(1)]);
    let mut env = env_at("pdp11_24", 0o1000, &words);
    sem::r_set(&mut env.backend, 1, 0o2000);
    sem::psw_put(&mut env.backend, 1); // C=1
    step_m(&mut env, "pdp11_24").unwrap();
    assert_eq!(get16(&env, 0o2000), 0);
    assert_eq!(nzvc(&env), 0o05); // Z=1・C=1（不変）
    // モード 0 の指定は vector 010 に fault。
    for insn in [Insn::Tstset, Insn::Wrtlck] {
        let words = asm(insn, &[Spec::Reg(2)]);
        let mut env = env_at("pdp11_24", 0o1000, &words);
        put16(&mut env, 0o010, 0o2400);
        step_m(&mut env, "pdp11_24").unwrap();
        assert_eq!(env.pc, 0o2400, "{insn:?}");
        assert_eq!(get16(&env, sem::r_get(&env.backend, reg::SP as u8)), 0o1000);
    }
}

/// halt はカーネルモードで CPU 停止（裸では終端）だが、他のモード
/// では location 4 にトラップする。
// Ref: SPEC-PDP11-J11（8.4.1）.
#[test]
fn halt_in_user_mode_traps_to_vector4() {
    let mut env = env_at("pdp11_70", 0o1000, &[0o000000]); // halt
    sem::psw_put(&mut env.backend, 0o140000); // ユーザー
    sem::r_set(&mut env.backend, reg::SP as u8, 0o6000);
    st_put(&mut env, USP, 0o6000);
    st_put(&mut env, KSP, SP0);
    put16(&mut env, 0o004, 0o2400);
    step_m(&mut env, "pdp11_70").unwrap();
    assert_eq!(env.pc, 0o2400);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o1002); // trap — 次の命令
    // カーネルでは従来どおり終端。
    let mut env = env_at("pdp11_70", 0o1000, &[0o000000]);
    assert!(step_m(&mut env, "pdp11_70").is_err());
}

// ---- PD9: EIS（mul/div/ash/ashc）と FIS（0750xR）----

/// FIS 命令語（0750xR — freg<2:0> のみを載せる）。
fn asm_f(insn: Insn, n: u8) -> u16 {
    encode(insn, &[]).expect("encodable") as u16 | u16::from(n & 7)
}

/// F 形式の 32 ビット値をフレームに書く（上位語が低アドレス —
/// PDP-11 の語順規則）。
fn putf(env: &mut BareEnv, a: u16, bits: u32) {
    put16(env, a, (bits >> 16) as u16);
    put16(env, a.wrapping_add(2), bits as u16);
}

/// F 形式を読む。
fn getf(env: &BareEnv, a: u16) -> u32 {
    u32::from(get16(env, a)) << 16 | u32::from(get16(env, a.wrapping_add(2)))
}

/// 機能旗を足した集合での 1 ステップ（eis/fis を持たない既定モデル
/// に旗だけ乗せる）。
fn step_f(env: &mut BareEnv, feats: u128) -> Result<(), Outcome> {
    run::step(env, &mut NoSys, feats)
}

/// mul は偶数 R で R,R+1 に 32 ビット積、奇数 R では下位積のみ。
/// CC は常に 32 ビット積で立つ（C=積が 16 ビットに収まらない）。
// Ref: SPEC-PDP11-ARCH83（第5章 MUL）.
#[test]
fn mul_register_pair_and_cc() {
    let feats = model_feats("pdp11_03") | FEAT_EIS;
    for (n, dst, src, r_lo, r_hi, cc) in [
        // 偶数 R: r2:r3 ← 0o1234 × 0o1000（= 0x53800）。16 ビットに
        // 収まらないので C=1、V=0。
        (2u8, 0o1234u16, 0o1000u16, 0o5u16, 0o34000u16, 0o1u16),
        // 収まる積: 2×2=4 → CC 全消し。
        (2, 0o2, 0o2, 0, 0o4, 0),
        // 負の積: -1 × 3 = -3 = 0xFFFF_FFFD → N=1。16 ビットに
        // 収まるので C=0。
        (0, 0o177777u16, 0o3, 0o177777u16, 0o177775u16, 0o10u16),
        // 奇数 R: -32768 × 2 = -65536。下位語だけが R に残り、
        // CC は 32 ビット積で立つ（N=1・C=1）。
        (3, 0o100000u16, 0o2, 0, 0, 0o11u16),
        // 積が 0: -32768 × 0 → Z=1・C=0。
        (2, 0o100000u16, 0, 0, 0, 0o4u16),
        // -1 × -1 = 1 → 正・収まる。
        (0, 0o177777u16, 0o177777u16, 0, 0o1, 0),
    ] {
        let words = asm_r(Insn::Mul, n, &[Spec::Imm(src)]);
        let mut env = env_at("pdp11_03", 0o1000, &words);
        sem::psw_put(&mut env.backend, 0o17); // 旧 CC は置き換わる
        sem::r_set(&mut env.backend, n, dst);
        step_f(&mut env, feats).unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, n), sem::r_get(&env.backend, n | 1)),
            (r_lo, r_hi),
            "mul r{n} dst={dst:o} src={src:o}"
        );
        assert_eq!(nzvc(&env), cc, "mul r{n} dst={dst:o} src={src:o}");
    }
    // メモリソース: mul (r1)+, r2 — src は指定子評価される。
    let words = asm_r(Insn::Mul, 2, &[Spec::AutoInc(1)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    put16(&mut env, 0o2000, 0o400);
    sem::r_set(&mut env.backend, 1, 0o2000);
    sem::r_set(&mut env.backend, 2, 0o3);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 2), 0);
    assert_eq!(sem::r_get(&env.backend, 3), 0o1400); // 3×0o400
    assert_eq!(sem::r_get(&env.backend, 1), 0o2002);
}

/// div は偶数 R で R,R+1 の 32 ビット被除数を src で割り、商を R・
/// 剰余を R+1 に入れる。剰余は被除数と同符号（0 方向切詰）。
/// 0 除算は V=1・C=1、商が 16 ビットに収まらなければ V=1・C=0
/// でレジスタは不変。
// Ref: SPEC-PDP11-ARCH83（第5章 DIV）.
#[test]
fn div_quotient_remainder_and_errors() {
    let feats = model_feats("pdp11_03") | FEAT_EIS;
    for (dvd_hi, dvd_lo, src, q, rem, cc) in [
        // 64 / 8 = 8 余り 0。
        (0u16, 0o100u16, 0o10u16, 0o10u16, 0u16, 0u16),
        // -7 / 2 = -3 余り -1（0 方向切詰・剰余は被除数と同符号）。
        (0o177777, 0o177771, 0o2, 0o177775, 0o177777, 0o10),
        // -8192 / -4 = 2048 余り 0。
        (0o177777, 0o160000, 0o177774, 0o4000, 0, 0),
        // 0 / 5 = 0 余り 0 → Z。
        (0, 0, 0o5, 0, 0, 0o4),
    ] {
        let words = asm_r(Insn::Div, 0, &[Spec::Imm(src)]);
        let mut env = env_at("pdp11_03", 0o1000, &words);
        sem::r_set(&mut env.backend, 0, dvd_hi);
        sem::r_set(&mut env.backend, 1, dvd_lo);
        step_f(&mut env, feats).unwrap();
        assert_eq!(
            (
                sem::r_get(&env.backend, 0),
                sem::r_get(&env.backend, 1),
                nzvc(&env)
            ),
            (q, rem, cc),
            "div {dvd_hi:o}:{dvd_lo:o} / {src:o}"
        );
    }
    // 0 除算: V=1・C=1、レジスタ不変。
    let words = asm_r(Insn::Div, 0, &[Spec::Reg(2)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0o1234);
    sem::r_set(&mut env.backend, 1, 0o5670);
    sem::r_set(&mut env.backend, 2, 0);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o1234);
    assert_eq!(sem::r_get(&env.backend, 1), 0o5670);
    assert_eq!(nzvc(&env), 0o3); // V+C
    // 商溢れ: 0x8000_0000 / -1 → V=1・C=0、レジスタ不変。
    let words = asm_r(Insn::Div, 0, &[Spec::Imm(0o177777)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0o100000);
    sem::r_set(&mut env.backend, 1, 0);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o100000);
    assert_eq!(nzvc(&env), 0o2); // V のみ
    // 商が 16 ビットを 1 だけ超える: 32768 / 1 → V=1。
    let words = asm_r(Insn::Div, 0, &[Spec::Imm(0o1)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0);
    sem::r_set(&mut env.backend, 1, 0o100000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(nzvc(&env), 0o2);
}

/// ash は src<5:0> を符号付き 6 ビットのカウントで算術シフト
/// （負=右・正=左）。C=最後に出た桁、V=シフト中に符号が変わった、
/// どちらも NN=0 では消える。
// Ref: SPEC-PDP11-ARCH83（第5章 ASH）.
#[test]
fn ash_signed_count_and_cc() {
    let feats = model_feats("pdp11_03") | FEAT_EIS;
    for (old, cnt, new, cc) in [
        // 左 4: 0o12345 → 0o47120。シフト中に符号が 1 になった
        // ことがある → V=1、最後に出た桁=1 → C=1。
        (0o12345u16, 0o4u16, 0o47120u16, 0o3u16),
        // 左 1: 0o040000 → 0o100000。符号が 0→1 → V=1、C=0。
        (0o040000, 0o1, 0o100000, 0o12),
        // 右 3（カウント 0o75 = -3）: 0o100000 → 0o170000。
        // 符号複写なので V=0・C=0、N=1。
        (0o100000, 0o75, 0o170000, 0o10),
        // 右 1（0o77 = -1）: 0o5 → 0o2。C=出た bit0=1、N=0、V=0。
        (0o5, 0o77, 0o2, 0o1),
        // カウント 0: 値不変、CC は結果から（N=1、V=0・C=0）。
        (0o100000, 0, 0o100000, 0o10),
        // 左 31: 0o77777 → 0。全桁が出て C=0、V=1、Z=1。
        (0o77777, 0o37, 0, 0o6),
        // 右 32（0o40 = -32）: 0o100000 → 0o177777。最後に出たのは
        // 符号桁 → C=1、V=0、N=1。
        (0o100000, 0o40, 0o177777, 0o11),
        // 上位ビットはカウントに関係ない（src<5:0> のみ —— 上位桁を
        // 立てても 0o04 = +4 と同じ結果）。
        (0o12345, 0o177704, 0o47120, 0o3),
    ] {
        let words = asm_r(Insn::Ash, 0, &[Spec::Imm(cnt)]);
        let mut env = env_at("pdp11_03", 0o1000, &words);
        sem::psw_put(&mut env.backend, 0o17); // 旧 CC は置き換わる
        sem::r_set(&mut env.backend, 0, old);
        step_f(&mut env, feats).unwrap();
        assert_eq!(
            (sem::r_get(&env.backend, 0), nzvc(&env)),
            (new, cc),
            "ash r0={old:o} cnt={cnt:o}"
        );
    }
}

/// ashc は R:R|1 の 32 ビット対をシフト。奇数 R では被演算が
/// R:R（同じレジスタの複製）で、右シフトは 16 ビットの回転になる。
/// CC は常に 32 ビット結果で立つ。
// Ref: SPEC-PDP11-ARCH83（第5章 ASHC）.
#[test]
fn ashc_32bit_pair_and_odd_rotate() {
    let feats = model_feats("pdp11_03") | FEAT_EIS;
    // 偶数対: r0:r1 = 0x0001_0000 を左 4 → 0x0010_0000。
    let words = asm_r(Insn::Ashc, 0, &[Spec::Imm(0o4)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0o1);
    sem::r_set(&mut env.backend, 1, 0);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o20);
    assert_eq!(sem::r_get(&env.backend, 1), 0);
    assert_eq!(nzvc(&env), 0);
    // 右 4: r0:r1 = 0x8000_0000 → 0xF800_0000 → N=1。C=bit3=0。
    let words = asm_r(Insn::Ashc, 0, &[Spec::Imm(0o74)]); // -4
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0o100000);
    sem::r_set(&mut env.backend, 1, 0);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o174000);
    assert_eq!(sem::r_get(&env.backend, 1), 0);
    assert_eq!(nzvc(&env), 0o10);
    // V: 0x4000_0000 の左 1 → 符号が 0→1 に変わる → V=1。
    let words = asm_r(Insn::Ashc, 0, &[Spec::Imm(0o1)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0o040000);
    sem::r_set(&mut env.backend, 1, 0);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o100000);
    assert_eq!(nzvc(&env), 0o12); // N+V
    // 奇数 R の右シフトは回転: r3 = 0o100001、右 1 → 0o140000
    // （ROR と同値）。C=出た bit0=1。
    let words = asm_r(Insn::Ashc, 3, &[Spec::Imm(0o77)]); // -1
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 3, 0o100001);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 3), 0o140000);
    assert_eq!(nzvc(&env), 0o11); // N+C
    // 奇数 R の左シフトは 16 ビット左シフト相当: r3=1、左 4 → 0o20。
    let words = asm_r(Insn::Ashc, 3, &[Spec::Imm(0o4)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    sem::r_set(&mut env.backend, 3, 0o1);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, 3), 0o20);
    // Z は 32 ビット結果: 対が全部 0 → Z=1。
    let words = asm_r(Insn::Ashc, 0, &[Spec::Imm(0o10)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    step_f(&mut env, feats).unwrap();
    assert_eq!(nzvc(&env), 0o4);
}

/// EIS は `eis` 旗がないと予約命令（vector 010、fault —— 積む
/// PC は命令先頭）。旗があればデコード・実行できる。
// Ref: SPEC-PDP11-ARCH83（第5章・付録 C）.
#[test]
fn eis_fis_gated_by_flags() {
    // pdp11_03 は EIS を持たない → 070RSS は vector 010。
    let words = asm_r(Insn::Mul, 0, &[Spec::Reg(0)]);
    let mut env = env_at("pdp11_03", 0o1000, &words);
    put16(&mut env, 0o010, 0o2400);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(env.pc, 0o2400);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o1000); // fault — 命令先頭
    // pdp11_70 は EIS 標準 —— 同じ語が mul として動く。
    let mut env = env_at("pdp11_70", 0o1000, &words);
    sem::r_set(&mut env.backend, 0, 0o3);
    step_m(&mut env, "pdp11_70").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0);
    assert_eq!(sem::r_get(&env.backend, 1), 0o11); // 3×3
    // FIS も旗なしでは vector 010。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fadd, 1)]);
    put16(&mut env, 0o010, 0o2400);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(env.pc, 0o2400);
    // pdp11_73 は FP11 標準で FIS は排他（decode も付録 C どおり）。
    assert_eq!(dec_m(0o075001, "pdp11_73"), None);
}

/// FIS: 汎用レジスタがフレームを指し、(R)/(R+2)=B・(R+4)/(R+6)=A。
/// 結果は A 位置へ、成功なら R ← R+4。CC は N=結果<0・Z=結果=0・
/// V=0・C=0。
// Ref: SPEC-PDP11-ARCH83（付録 C）.
#[test]
fn fis_arith_frame_and_cc() {
    let feats = model_feats("pdp11_03") | FEAT_FIS;
    // 1.0 / 2.0 / 3.0 / 6.0 / 0.5 / 2^-24 の F 形式ビット列
    // （符号・指数 excess 200・仮数）。
    const F1_0: u32 = 0x4080_0000;
    const F2_0: u32 = 0x4100_0000;
    const F3_0: u32 = 0x4140_0000;
    const F6_0: u32 = 0x41C0_0000;
    const F_2M24: u32 = 0x3480_0000; // 2^-24
    // fadd r1: B=1.0・A=2.0 → 3.0。r1 ← +4。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fadd, 1)]);
    putf(&mut env, 0o2000, F1_0);
    putf(&mut env, 0o2004, F2_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), F3_0);
    assert_eq!(sem::r_get(&env.backend, 1), 0o2004); // R+4 → 結果上位
    assert_eq!(nzvc(&env), 0);
    // fsub r1: 3.0 - 1.0 → 2.0。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fsub, 1)]);
    putf(&mut env, 0o2000, F1_0);
    putf(&mut env, 0o2004, F3_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), F2_0);
    // fmul r1: 2.0 × 3.0 → 6.0。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fmul, 1)]);
    putf(&mut env, 0o2000, F2_0);
    putf(&mut env, 0o2004, F3_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), F6_0);
    // fdiv r1: 6.0 / 3.0 → 2.0。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fdiv, 1)]);
    putf(&mut env, 0o2000, F3_0);
    putf(&mut env, 0o2004, F6_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), F2_0);
    // 丸め: 1.0 + 2^-24。真の結果は 1 ulp の半分 —— FIS は絶対値
    // を増やす方向へ丸める（KE11-F）ので 1.0+ulp。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fadd, 1)]);
    putf(&mut env, 0o2000, F_2M24);
    putf(&mut env, 0o2004, F1_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), 0x4080_0001);
    // 負の結果: 1.0 - 3.0 = -2.0 → N=1。結果は -2.0 = 0xC100_0000。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fsub, 1)]);
    putf(&mut env, 0o2000, F3_0);
    putf(&mut env, 0o2004, F1_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), 0xC100_0000);
    assert_eq!(nzvc(&env), 0o10); // N
    // 零の結果: 1.0 - 1.0 = 0 → Z=1（クリーンな 0 が格納される）。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fsub, 1)]);
    putf(&mut env, 0o2000, F1_0);
    putf(&mut env, 0o2004, F1_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), 0);
    assert_eq!(nzvc(&env), 0o4); // Z
    // 指数 0 のオペランドは符号を問わず 0（KE11-F）: -0 + 1.0 = 1.0。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fadd, 1)]);
    putf(&mut env, 0o2000, 0x8000_0000); // -0（指数 0・符号 1）
    putf(&mut env, 0o2004, F1_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), F1_0);
}

/// FIS の例外: 0 除算・オーバーフロー・アンダーフローは CC を
/// 再解釈して vector 244 へ fault（積む PC は命令先頭、PSW は
/// エラー CC を含む）。R とオペランドは不変。
// Ref: SPEC-PDP11-ARCH83（付録 C）.
#[test]
fn fis_errors_trap_244_with_reinterpreted_cc() {
    let feats = model_feats("pdp11_03") | FEAT_FIS;
    const F1_0: u32 = 0x4080_0000;
    const F2_0: u32 = 0x4100_0000;
    const F_MAX: u32 = 0x7FFF_FFFF; // 最大正規化（exp 377・仮数全 1）
    const F_MIN: u32 = 0x0080_0000; // 最小正規化（exp 1・仮数 0）
    const F_HALF: u32 = 0x4000_0000; // 0.5
    // 0 除算: V=1・N=1・C=1・Z=0。B=0 で fdiv。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fdiv, 1)]);
    putf(&mut env, 0o2000, 0); // B = 0
    putf(&mut env, 0o2004, F1_0); // A = 1.0
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(env.pc, 0o3000);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp), 0o1000); // fault — 命令先頭
    // 積まれた PSW はエラー CC（V=1・N=1・C=1・Z=0）。配送後の現行
    // PSW はベクタの新 PSW（0o246 = 0）なので、エラー CC は積まれた
    // 側だけに残る形になる。
    assert_eq!(get16(&env, sp + 2) & 0xf, 0o13);
    // R とオペランドは不変。
    assert_eq!(sem::r_get(&env.backend, 1), 0o2000);
    assert_eq!(getf(&env, 0o2004), F1_0);
    // オーバーフロー: max × 2.0 → V=1・N=0・C=0・Z=0。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fmul, 1)]);
    putf(&mut env, 0o2000, F2_0);
    putf(&mut env, 0o2004, F_MAX);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(env.pc, 0o3000);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp + 2) & 0xf, 0o2); // V のみ
    assert_eq!(sem::r_get(&env.backend, 1), 0o2000);
    assert_eq!(getf(&env, 0o2004), F_MAX); // A 不変
    // アンダーフロー: min × 0.5 → V=1・N=1・C=0・Z=0。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fmul, 1)]);
    putf(&mut env, 0o2000, F_HALF);
    putf(&mut env, 0o2004, F_MIN);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(env.pc, 0o3000);
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(&env, sp + 2) & 0xf, 0o12); // V+N
    // fsub のアンダーフロー: min - 0 は引く数が 0 で結果は
    // min —— 例外なしの確認にもなる。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fadd, 1)]);
    putf(&mut env, 0o2000, 0);
    putf(&mut env, 0o2004, F_MIN);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), F_MIN);
    assert_eq!(nzvc(&env), 0);
}

/// FMUL/FDIV は R6 スタックへ作業語を 1 語 push/pop する
/// （付録 C 注記・付録 B 項目 22）—— SP が書き込めなければ
/// バスエラーで命令が中断する。FADD/FSUB は SP を触らない。
// Ref: SPEC-PDP11-ARCH83（付録 C・付録 B 項目 22）.
#[test]
fn fis_mul_div_implicit_sp_scratch() {
    let feats = model_feats("pdp11_03") | FEAT_FIS;
    const F1_0: u32 = 0x4080_0000;
    const F2_0: u32 = 0x4100_0000;
    // 正常系: fmul が終わると SP は元に戻る（push+pop）。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fmul, 1)]);
    putf(&mut env, 0o2000, F2_0);
    putf(&mut env, 0o2004, F1_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    step_f(&mut env, feats).unwrap();
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), SP0);
    assert_eq!(getf(&env, 0o2004), F2_0); // 2.0 × 1.0
    // SP-2 が未写像 → fmul の push がバスエラー（vector 004）。配送
    // の push は新 PSW（ユーザーモード）のスタック —— usp を
    // 写像済みにしておく。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fmul, 1)]);
    putf(&mut env, 0o2000, F2_0);
    putf(&mut env, 0o2004, F1_0);
    put16(&mut env, 0o004, 0o3000);
    put16(&mut env, 0o006, 0o140000); // ユーザーモードの PSW
    st_put(&mut env, USP, SP0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    sem::r_set(&mut env.backend, reg::SP as u8, 0o20002); // SP-2 が未写像
    step_f(&mut env, feats).unwrap();
    assert_eq!(env.pc, 0o3000);
    assert_eq!(getf(&env, 0o2004), F1_0); // A は演算前のまま
    // 同条件の fadd は SP を触らないので普通に実行できる。
    let mut env = env_at("pdp11_03", 0o1000, &[asm_f(Insn::Fadd, 1)]);
    putf(&mut env, 0o2000, F2_0);
    putf(&mut env, 0o2004, F1_0);
    sem::r_set(&mut env.backend, 1, 0o2000);
    sem::r_set(&mut env.backend, reg::SP as u8, 0o20002);
    step_f(&mut env, feats).unwrap();
    assert_eq!(getf(&env, 0o2004), 0x4140_0000); // 3.0
}

// ---- PD10: FP11（17xxxx —— F/D 浮動小数点オプション）----

/// FP11 命令語（FRD: AC は <7:6> —— bit8 は命令対の選択子で
/// パターン側が固定するので AC0-AC3 のみ表せる）。
fn asm_fp(insn: Insn, ac: u8, specs: &[Spec]) -> Vec<u16> {
    let base = encode(insn, &[]).expect("encodable") as u16;
    let (w, ext) = encode_insn(base | u16::from(ac & 3) << 6, specs);
    let mut v = vec![w];
    v.extend(ext);
    v
}

/// D 形式の 64 ビット値をメモリに書く（上位語が低番地）。
fn putd(env: &mut BareEnv, a: u16, bits: u64) {
    for k in 0..4 {
        put16(env, a.wrapping_add(2 * k), (bits >> (48 - 16 * k)) as u16);
    }
}

/// D 形式を読む。
fn getd(env: &BareEnv, a: u16) -> u64 {
    let mut v = 0u64;
    for k in 0..4 {
        v = v << 16 | u64::from(get16(env, a.wrapping_add(2 * k)));
    }
    v
}

/// FPS/FEC/FEA の状態面オフセット。
const FPS_OFF: usize = core::mem::offset_of!(CpuState, fps);
const FEC_OFF: usize = core::mem::offset_of!(CpuState, fec);
const FEA_OFF: usize = core::mem::offset_of!(CpuState, fea);
const AC_OFF: usize = core::mem::offset_of!(CpuState, ac);

/// AC_n の生値（F 形式は <63:32> 左詰め）。
fn ac_get(env: &BareEnv, n: u8) -> u64 {
    let off = AC_OFF + usize::from(n) * 8;
    u64::from_le_bytes(env.backend.state[off..off + 8].try_into().expect("w64"))
}

fn ac_put(env: &mut BareEnv, n: u8, v: u64) {
    env.backend
        .set(StateRef::<W64>::from_offset(AC_OFF + usize::from(n) * 8), v);
}

/// AC_n の F 形式ビット列（<63:32>）。
fn acf_get(env: &BareEnv, n: u8) -> u32 {
    (ac_get(env, n) >> 32) as u32
}

fn acf_put(env: &mut BareEnv, n: u8, bits: u32) {
    ac_put(env, n, u64::from(bits) << 32);
}

/// FPS ビット（sem::fps と同じ配置）。
const FPS_FER: u16 = 1 << 15;
const FPS_FID: u16 = 1 << 14;
const FPS_FIUV: u16 = 1 << 11;
const FPS_FIU: u16 = 1 << 10;
const FPS_FIV: u16 = 1 << 9;
const FPS_FIC: u16 = 1 << 8;
const FPS_FD: u16 = 1 << 7;
const FPS_FL: u16 = 1 << 6;
const FPS_FT: u16 = 1 << 5;
const FPS_FN: u16 = 1 << 3;
const FPS_FZ: u16 = 1 << 2;
const FPS_FV: u16 = 1 << 1;
const FPS_FC: u16 = 1;

/// 状態面の語を読む（& 版 —— st_get は &mut 専用）。
fn st_rd(env: &BareEnv, off: usize) -> u16 {
    u16::from_le_bytes(env.backend.state[off..off + 2].try_into().expect("w16"))
}

fn fps_get(env: &BareEnv) -> u16 {
    st_rd(env, FPS_OFF)
}

fn fps_put(env: &mut BareEnv, v: u16) {
    st_put(env, FPS_OFF, v);
}

/// vector 244 の FP 例外へ飛んだことと、積まれた PC（次の命令）
/// を検査する。戻り値はスタックに積まれた PC。
fn expect_fp_trap(env: &BareEnv, handler: u16, stacked_pc: u16) {
    assert_eq!(env.pc, u64::from(handler));
    let sp = sem::r_get(&env.backend, reg::SP as u8);
    assert_eq!(get16(env, sp), stacked_pc);
}

/// テスト用の F 形式値（符号・指数 excess 200・仮数）。
const F1_0: u32 = 0x4080_0000;
const F2_0: u32 = 0x4100_0000;
const F3_0: u32 = 0x4140_0000;
const F5_0: u32 = 0x41A0_0000;
const F6_0: u32 = 0x41C0_0000;
const F_075: u32 = 0x4040_0000; // 0.75
const F_375: u32 = 0x4170_0000; // 3.75
const F_MAX: u32 = 0x7FFF_FFFF; // 最大正規化（exp 377・仮数全 1）
const F_MIN: u32 = 0x0080_0000; // 最小正規化（exp 1・仮数 0）
const F_N0: u32 = 0x8000_0000; // -0（指数 0・符号 1）

#[test]
fn fp11_decode_gated() {
    // 既定モデル（fp11 なし）では解けず、pdp11_73（J-11 = FPJ11）
    // では全語彙が解ける。FIS モデルでは排他なので解けない。
    assert_eq!(dec(0o172400), None); // ldf
    for w in [
        0o170000u16,
        0o170001,
        0o170002,
        0o170011,
        0o170012, // 固定形
        0o170100,
        0o170200,
        0o170300, // ldfps/stfps/stst
        0o170400,
        0o170500,
        0o170600,
        0o170700, // clrf..negf
        0o171000,
        0o171400,
        0o172000,
        0o172400, // mulf..ldf
        0o173000,
        0o173400,
        0o174000,
        0o174400, // subf..divf
        0o175000,
        0o175400,
        0o176000,
        0o176400, // stexp..ldexp
        0o177000,
        0o177400, // ldcif/ldcff
    ] {
        assert!(dec_m(w, "pdp11_73").is_some(), "{w:o} should decode");
        assert_eq!(dec_m(w, "pdp11_03"), None);
    }
    // FIS は fp11 と排他（175xxx は FIS 空間に被るが解けない）。
    let fis = model_feats("pdp11_03") | FEAT_FIS;
    assert_eq!(decode_model_ex(0o172400u128, 16, false, fis), None);
    // 未割当の 17xxxx（170003 は seti と setd の間）は解けない。
    assert_eq!(dec_m(0o170003, "pdp11_73"), None);
}

#[test]
fn fp11_ldf_stf_f_format_and_cc() {
    // ldf @#2000,ac0 → AC<63:32> ← F。CC は FN/FZ に出る。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Ldf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F2_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F2_0);
    assert_eq!(fps_get(&env) & 0o17, 0); // FN=FZ=FV=FC=0
    // stf ac0,@#2004 → メモリへ（上位語が低番地 —— 3412 配置）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Stf, 0, &[Spec::Abs(0o2004)]),
    );
    acf_put(&mut env, 0, F_375);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getf(&env, 0o2004), F_375);
    // 負値は FN、零は FZ。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Ldf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F_N0 | F2_0); // -2.0
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env) & (FPS_FN | FPS_FZ), FPS_FN);
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Ldf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env) & (FPS_FN | FPS_FZ), FPS_FZ);
}

#[test]
fn fp11_d_format_memory_order() {
    // setd 後の ldf/stf は 8 バイト D 形式。低番地語が最上位語。
    let mut w = asm(Insn::Setd, &[]);
    w.extend(asm_fp(Insn::Ldf, 0, &[Spec::Abs(0o2000)]));
    w.extend(asm_fp(Insn::Stf, 0, &[Spec::Abs(0o2010)]));
    let mut env = env_at("pdp11_73", 0o1000, &w);
    let d3 = 0x4140_0000_0000_0000u64; // 3.0（D）
    putd(&mut env, 0o2000, d3);
    step_m(&mut env, "pdp11_73").unwrap(); // setd
    assert_eq!(fps_get(&env) & FPS_FD, FPS_FD);
    step_m(&mut env, "pdp11_73").unwrap(); // ldf
    assert_eq!(ac_get(&env, 0), d3);
    step_m(&mut env, "pdp11_73").unwrap(); // stf
    assert_eq!(getd(&env, 0o2010), d3);
}

#[test]
fn fp11_mode0_is_ac_and_ac67_illegal() {
    // モード 0 は AC を選ぶ: ldf ac1,ac0（語 172401 相当）。
    let mut env = env_at("pdp11_73", 0o1000, &asm_fp(Insn::Ldf, 0, &[Spec::Reg(1)]));
    acf_put(&mut env, 1, F5_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F5_0);
    // AC6/AC7 は浮動オペコードエラー（FEC=2）→ vector 244。
    let mut env = env_at("pdp11_73", 0o1000, &asm_fp(Insn::Ldf, 0, &[Spec::Reg(6)]));
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    expect_fp_trap(&env, 0o3000, 0o1002);
    assert_eq!(st_rd(&env, FEC_OFF), 0o2);
    assert_eq!(st_rd(&env, FEA_OFF), 0o1000);
    assert_eq!(fps_get(&env) & FPS_FER, FPS_FER);
    // FID で抑止すると FEC/FEA は更新されるが trap せず読み飛ばす。
    let mut env = env_at("pdp11_73", 0o1000, &asm_fp(Insn::Ldf, 0, &[Spec::Reg(6)]));
    fps_put(&mut env, FPS_FID);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(env.pc, 0o1002);
    assert_eq!(st_rd(&env, FEC_OFF), 0o2);
}

#[test]
fn fp11_undecoded_17xxxx_is_fp_illegal() {
    // 170003（seti と setd の間の未割当語）は FEC=2 で vector 244。
    let mut env = env_at("pdp11_73", 0o1000, &[0o170003]);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    expect_fp_trap(&env, 0o3000, 0o1002);
    assert_eq!(st_rd(&env, FEC_OFF), 0o2);
    // fp11 を持たないモデルでは従来の違法命令（vector 010）。
    let mut env = env_at("pdp11_03", 0o1000, &[0o170003]);
    put16(&mut env, 0o010, 0o2400);
    step_m(&mut env, "pdp11_03").unwrap();
    assert_eq!(env.pc, 0o2400);
}

#[test]
fn fp11_ldfps_stfps_stst() {
    // ldfps #v → FPS。桁 13・12・4 は読み出せない（LDFPS で消す）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm(Insn::Ldfps, &[Spec::Imm(0o167777)]),
    );
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env), 0o167777 & !0o30020);
    // stfps @#a → FPS を書き出す。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Stfps, &[Spec::Abs(0o2000)]));
    fps_put(&mut env, FPS_FER | FPS_FD | FPS_FN | 0o30020);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(get16(&env, 0o2000), fps_get(&env));
    // stst @#a → FEC・FEA を 2 語で書き出す。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Stst, &[Spec::Abs(0o2000)]));
    st_put(&mut env, FEC_OFF, 0o10);
    st_put(&mut env, FEA_OFF, 0o1234);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(get16(&env, 0o2000), 0o10);
    assert_eq!(get16(&env, 0o2002), 0o1234);
    // stst r0 は FEC のみ。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Stst, &[Spec::Reg(0)]));
    st_put(&mut env, FEC_OFF, 0o4);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), 0o4);
}

#[test]
fn fp11_setf_setd_seti_setl() {
    for (insn, bit, on) in [
        (Insn::Setf, FPS_FD, false),
        (Insn::Setd, FPS_FD, true),
        (Insn::Seti, FPS_FL, false),
        (Insn::Setl, FPS_FL, true),
    ] {
        let mut env = env_at("pdp11_73", 0o1000, &asm(insn, &[]));
        fps_put(&mut env, FPS_FD | FPS_FL);
        step_m(&mut env, "pdp11_73").unwrap();
        assert_eq!(fps_get(&env) & bit != 0, on, "{insn:?}");
        assert_eq!(env.pc, 0o1002);
    }
    // CC 系の FPS 桁は触らない。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Setd, &[]));
    fps_put(&mut env, FPS_FN | FPS_FC);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env) & 0o17, FPS_FN | FPS_FC);
}

#[test]
fn fp11_cfcc_copies_fps_cc() {
    // FPS<3:0> → PSW<3:0>。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Cfcc, &[]));
    fps_put(&mut env, FPS_FN | FPS_FC);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(nzvc(&env), 0o11); // N+C
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Cfcc, &[]));
    fps_put(&mut env, 0);
    sem::psw_put(&mut env.backend, 0o17);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(nzvc(&env), 0);
}

#[test]
fn fp11_clrf_tstf_negf_absf() {
    // clrf @#a → +0。FZ=1。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Clrf, &[Spec::Abs(0o2000)]));
    putf(&mut env, 0o2000, F5_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getf(&env, 0o2000), 0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FZ);
    // tstf -2.0 → FN。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Tstf, &[Spec::Abs(0o2000)]));
    putf(&mut env, 0o2000, F_N0 | F2_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env) & 0o17, FPS_FN);
    // negf +2.0 → -2.0（符号反転）。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Negf, &[Spec::Abs(0o2000)]));
    putf(&mut env, 0o2000, F2_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getf(&env, 0o2000), F2_0 | F_N0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FN);
    // negf +0 → 正確な零（指数 0 のオペランドは常に正確な零を
    // 格納する FP11 の規則 —— 符号は反転されない）。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Negf, &[Spec::Abs(0o2000)]));
    putf(&mut env, 0o2000, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getf(&env, 0o2000), 0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FZ);
    // negf -0 も正確な +0。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Negf, &[Spec::Abs(0o2000)]));
    putf(&mut env, 0o2000, F_N0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getf(&env, 0o2000), 0);
    // absf -2.0 → +2.0。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Absf, &[Spec::Abs(0o2000)]));
    putf(&mut env, 0o2000, F_N0 | F2_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getf(&env, 0o2000), F2_0);
    assert_eq!(fps_get(&env) & 0o17, 0);
    // absf/negf の AC 宛て: 下位 32 ビットは不変。
    let mut env = env_at("pdp11_73", 0o1000, &asm(Insn::Negf, &[Spec::Reg(2)]));
    ac_put(&mut env, 2, u64::from(F2_0) << 32 | 0x1234_5678);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 2), F2_0 | F_N0);
    assert_eq!(ac_get(&env, 2) & 0xffff_ffff, 0x1234_5678);
}

#[test]
fn fp11_add_sub_mul_div() {
    // addf src,ac: AC ← AC + src。2.0 + 3.0 = 5.0。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Addf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F3_0);
    acf_put(&mut env, 0, F2_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F5_0);
    assert_eq!(fps_get(&env) & 0o17, 0);
    // subf: 3.0 - 5.0 = -2.0 → FN。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Subf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F5_0);
    acf_put(&mut env, 0, F3_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F2_0 | F_N0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FN);
    // mulf: 2.0 × 3.0 = 6.0。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Mulf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F3_0);
    acf_put(&mut env, 0, F2_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F6_0);
    // divf: 6.0 / 3.0 = 2.0。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Divf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F3_0);
    acf_put(&mut env, 0, F6_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F2_0);
    // 等しき引き算は正確な +0（FZ）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Subf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F1_0);
    acf_put(&mut env, 0, F1_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), 0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FZ);
    // -0 オペランドは零として扱う（FIUV が消えていれば）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Addf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F_N0);
    acf_put(&mut env, 0, F1_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F1_0);
    // 丸め（FT=0）: 1.0 + 2^-24 の真値は 1+ulp/2 —— FP11 の丸めは
    // 丸めビットが立てば切捨て値に 1 LSB 加える（半値は絶対値を
    // 増やす向き）ので 1.0+ulp。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Addf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0x3480_0000); // 2^-24
    acf_put(&mut env, 0, F1_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F1_0 + 1);
    // FT=1（切捨て）: 1.0 + 2^-25 → 切捨てで 1.0。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Addf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0x3400_0000); // 2^-25
    acf_put(&mut env, 0, F1_0);
    fps_put(&mut env, FPS_FT);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F1_0);
}

#[test]
fn fp11_cmpf() {
    // cmpf src,ac: (src) - (AC) の CC。src > AC → FN なし、src < AC → FN。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Cmpf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F5_0);
    acf_put(&mut env, 0, F3_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env) & 0o17, 0); // 5.0 - 3.0 > 0
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Cmpf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F3_0);
    acf_put(&mut env, 0, F5_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env) & 0o17, FPS_FN); // 3.0 - 5.0 < 0
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Cmpf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F5_0);
    acf_put(&mut env, 0, F5_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(fps_get(&env) & 0o17, FPS_FZ); // 等しい
    // 両方零の比較は AC ← 正確な零に掃除される（KDJ11-E UG 注記）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Cmpf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0x0000_0001); // dirty zero（exp 0・frac≠0）
    acf_put(&mut env, 0, F_N0); // -0
    fps_put(&mut env, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), 0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FZ);
}

#[test]
fn fp11_modf() {
    // modf src,ac: N=|AC×src| の整数部 → ACv1、g=小数部 → AC。
    // 3.75 × 1.0: N=3.0（AC1）・g=0.75（AC0）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Modf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F1_0);
    acf_put(&mut env, 0, F_375);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 1), F3_0);
    assert_eq!(acf_get(&env, 0), F_075);
    assert_eq!(fps_get(&env) & 0o17, 0); // g > 0
    // 奇数 AC では整数部を格納しない（AC2 へは書かない）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Modf, 1, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F1_0);
    acf_put(&mut env, 1, F_375);
    acf_put(&mut env, 2, F6_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 1), F_075); // g のみ
    assert_eq!(acf_get(&env, 2), F6_0); // 無傷
    // 負の積: -3.75 × 1.0 → N=-3.0・g=-0.75。FN は g で立つ。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Modf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F1_0);
    acf_put(&mut env, 0, F_375 | F_N0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 1), F3_0 | F_N0);
    assert_eq!(acf_get(&env, 0), F_075 | F_N0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FN);
    // |PROD| < 1 → N=0・g=PROD。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Modf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F_075);
    acf_put(&mut env, 0, F_075); // 0.5625 = 0x4070_0000
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 1), 0);
    assert_eq!(acf_get(&env, 0), 0x4010_0000); // 0.5625 = 0.5625×2^0
}

#[test]
fn fp11_stexp_ldexp() {
    // stexp ac,@#a → EXP-200₈。5.0 の指数は 203 → 3。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Stexp, 0, &[Spec::Abs(0o2000)]),
    );
    acf_put(&mut env, 0, F5_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(get16(&env, 0o2000), 3);
    assert_eq!(nzvc(&env), 0); // CPU CC も立つ
    // 指数 0（零）→ -200₈。
    let mut env = env_at("pdp11_73", 0o1000, &asm_fp(Insn::Stexp, 0, &[Spec::Reg(0)]));
    acf_put(&mut env, 0, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(sem::r_get(&env.backend, 0), (-0o200i16) as u16);
    // ldexp src,ac: EXP ← (src)+200₈。exp=2 → 4.0（仮数不変）。
    let mut env = env_at("pdp11_73", 0o1000, &asm_fp(Insn::Ldexp, 0, &[Spec::Imm(2)]));
    acf_put(&mut env, 0, F1_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), 0x4100_0000); // 2.0
    // ldexp は負の指数も取る: src=-1 → 0.25（仮数不変）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Ldexp, 0, &[Spec::Imm(-1i16 as u16)]),
    );
    acf_put(&mut env, 0, F1_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), 0x3F80_0000);
}

#[test]
fn fp11_ldcif_stcfi() {
    // ldcif #5,ac0 → 5.0。
    let mut env = env_at("pdp11_73", 0o1000, &asm_fp(Insn::Ldcif, 0, &[Spec::Imm(5)]));
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F5_0);
    // 負の整数 → -5.0（FN）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Ldcif, 0, &[Spec::Imm(-5i16 as u16)]),
    );
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F5_0 | F_N0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FN);
    // stcfi ac,@#a → 整数へ（常に切捨て）。5.75 → 5。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Stcfi, 0, &[Spec::Abs(0o2000)]),
    );
    acf_put(&mut env, 0, 0x41B8_0000); // 5.75
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(get16(&env, 0o2000), 5);
    assert_eq!(nzvc(&env), 0); // CPU CC も立つ
    // 範囲外（exp 大 → |v|≥2^15）→ dst ← 0・FC=1・CPU C=1。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Stcfi, 0, &[Spec::Abs(0o2000)]),
    );
    acf_put(&mut env, 0, 0x4800_0000); // 32768.0
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(get16(&env, 0o2000), 0);
    assert_eq!(nzvc(&env), 0o5); // Z+C
    assert_eq!(fps_get(&env) & 0o17, FPS_FC | FPS_FZ);
    // FIC を立てると同じ失敗が FEC=6 で vector 244 へ。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Stcfi, 0, &[Spec::Abs(0o2000)]),
    );
    acf_put(&mut env, 0, 0x4800_0000);
    fps_put(&mut env, FPS_FIC);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    expect_fp_trap(&env, 0o3000, 0o1004);
    assert_eq!(st_rd(&env, FEC_OFF), 0o6);
    // setl の L 形変換: 32 ビット整数 ↔ 浮動。
    let mut w = asm(Insn::Setl, &[]);
    w.extend(asm_fp(Insn::Stcfi, 0, &[Spec::Abs(0o2000)]));
    let mut env = env_at("pdp11_73", 0o1000, &w);
    acf_put(&mut env, 0, 0x4800_0000); // 32768
    step_m(&mut env, "pdp11_73").unwrap();
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(get16(&env, 0o2000), 0); // hi
    assert_eq!(get16(&env, 0o2002), 0o100000); // lo
    // setl+ldcif: メモリの L 形式（hi が低番地）。
    let mut w = asm(Insn::Setl, &[]);
    w.extend(asm_fp(Insn::Ldcif, 0, &[Spec::Abs(0o2000)]));
    let mut env = env_at("pdp11_73", 0o1000, &w);
    put16(&mut env, 0o2000, 0x0001);
    put16(&mut env, 0o2002, 0x0000); // 65536
    step_m(&mut env, "pdp11_73").unwrap();
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), 0x4880_0000); // 65536.0
}

#[test]
fn fp11_stcfd_ldcff() {
    // stcfd（FD=0）: AC の F → fdst の D（正確な拡大）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Stcfd, 0, &[Spec::Abs(0o2000)]),
    );
    acf_put(&mut env, 0, F_375);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getd(&env, 0o2000), 0x4170_0000_0000_0000);
    // stcfd（FD=1）: AC の D → fdst の F（丸めは FT）。正確な 3.75。
    let mut w = asm(Insn::Setd, &[]);
    w.extend(asm_fp(Insn::Stcfd, 0, &[Spec::Abs(0o2000)]));
    let mut env = env_at("pdp11_73", 0o1000, &w);
    ac_put(&mut env, 0, 0x4170_0000_0000_0000);
    step_m(&mut env, "pdp11_73").unwrap();
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(getf(&env, 0o2000), F_375);
    // ldcff（FD=0）: fsrc の D → AC の F。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Ldcff, 0, &[Spec::Abs(0o2000)]),
    );
    putd(&mut env, 0o2000, 0x4140_0000_0000_0000); // 3.0 (D)
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F3_0);
    // ldcff（FD=1）: fsrc の F → AC の D（正確）。
    let mut w = asm(Insn::Setd, &[]);
    w.extend(asm_fp(Insn::Ldcff, 0, &[Spec::Abs(0o2000)]));
    let mut env = env_at("pdp11_73", 0o1000, &w);
    putf(&mut env, 0o2000, F6_0);
    step_m(&mut env, "pdp11_73").unwrap();
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(ac_get(&env, 0), 0x41C0_0000_0000_0000);
}

#[test]
fn fp11_div_zero_traps_unconditional() {
    // ゼロ除算: FID でも抑止されず vector 244・FEC=4。AC は不変。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Divf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0);
    acf_put(&mut env, 0, F1_0);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    expect_fp_trap(&env, 0o3000, 0o1004);
    assert_eq!(st_rd(&env, FEC_OFF), 0o4);
    assert_eq!(acf_get(&env, 0), F1_0); // AC 不変
    // FID を立てても FER/FEC/FEA は更新される（抑止は割込みのみ）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Divf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0);
    acf_put(&mut env, 0, F1_0);
    fps_put(&mut env, FPS_FID);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(env.pc, 0o1004);
    assert_eq!(st_rd(&env, FEC_OFF), 0o4);
    assert_eq!(fps_get(&env) & FPS_FER, FPS_FER);
}

#[test]
fn fp11_overflow_result_and_trap() {
    // FIV=0: オーバーフロー結果は正確な零・FV=1・FER=1・trap なし。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Mulf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F2_0);
    acf_put(&mut env, 0, F_MAX);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), 0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FV | FPS_FZ);
    // 割込み不許可は「エラー」ではないので FER/FEC は立たない。
    assert_eq!(fps_get(&env) & FPS_FER, 0);
    assert_eq!(st_rd(&env, FEC_OFF), 0);
    // FIV=1: 指数を 400₈ ずらした結果を AC に残して vector 244。
    // max×4.0 の真の指数は 402₈ → 格納は 402-400=2 ではなく
    // フィールド幅で折り返し 401-400=1 …… DEC 規則「結果の指数
    // は真値より 400₈ 小さい」（符号・仮数は保持）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Mulf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0x4180_0000); // 4.0
    acf_put(&mut env, 0, F_MAX);
    fps_put(&mut env, FPS_FIV);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    expect_fp_trap(&env, 0o3000, 0o1004);
    assert_eq!(st_rd(&env, FEC_OFF), 0o10);
    let ac = acf_get(&env, 0);
    assert_eq!(ac >> 23 & 0xff, 1, "exponent shifted by -0o400");
    assert_eq!(ac & 0x007f_ffff, F_MAX & 0x007f_ffff);
    // FID で抑止すると FIV 許可でも trap せず結果は残る。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Mulf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0x4180_0000);
    acf_put(&mut env, 0, F_MAX);
    fps_put(&mut env, FPS_FID | FPS_FIV);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(env.pc, 0o1004);
    assert_eq!(acf_get(&env, 0) >> 23 & 0xff, 1);
    assert_eq!(st_rd(&env, FEC_OFF), 0o10);
}

#[test]
fn fp11_underflow_result_and_trap() {
    // FIU=0: アンダーフロー → 正確な零・trap なし。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Mulf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0x4000_0000); // 0.5
    acf_put(&mut env, 0, F_MIN);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), 0);
    assert_eq!(fps_get(&env) & 0o17, FPS_FZ);
    assert_eq!(st_rd(&env, FEC_OFF), 0);
    // FIU=1: 指数 +400₈ の結果を残して trap。min×0.25 = 2^-130
    // （真の指数 -1）→ 格納は -1+400₈ = 377₈。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Mulf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, 0x3F80_0000); // 0.25
    acf_put(&mut env, 0, F_MIN);
    fps_put(&mut env, FPS_FIU);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    expect_fp_trap(&env, 0o3000, 0o1004);
    assert_eq!(st_rd(&env, FEC_OFF), 0o12);
    assert_eq!(acf_get(&env, 0) >> 23 & 0xff, 0o377);
}

#[test]
fn fp11_fiuv_memory_negative_zero() {
    // FIUV=1・メモリの -0 オペランド → FEC=14 で vector 244。
    // addf は実行前に落ちる（AC 不変）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Addf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F_N0);
    acf_put(&mut env, 0, F1_0);
    fps_put(&mut env, FPS_FIUV);
    put16(&mut env, 0o244, 0o3000);
    put16(&mut env, 0o246, 0);
    step_m(&mut env, "pdp11_73").unwrap();
    expect_fp_trap(&env, 0o3000, 0o1004);
    assert_eq!(st_rd(&env, FEC_OFF), 0o14);
    assert_eq!(acf_get(&env, 0), F1_0);
    assert_eq!(fps_get(&env) & FPS_FZ, FPS_FZ); // CC は -0 の形
    // AC 内の -0 は FIUV の対象外（メモリ由来のみ）。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Addf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F1_0);
    acf_put(&mut env, 0, F_N0);
    fps_put(&mut env, FPS_FIUV);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F1_0);
    // FIUV=0 なら -0 は零として演算される。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Addf, 0, &[Spec::Abs(0o2000)]),
    );
    putf(&mut env, 0o2000, F_N0);
    acf_put(&mut env, 0, F1_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F1_0);
}

#[test]
fn fp11_int_dst_mode0_is_gpr() {
    // 整数宛先のモード 0 は（AC でなく）GPR —— stcfi r4 は r4 に
    // 変換結果を書く（整数オペランドの番地指定は CPU 側）。
    let mut env = env_at("pdp11_73", 0o1000, &asm_fp(Insn::Stcfi, 0, &[Spec::Reg(4)]));
    acf_put(&mut env, 0, F5_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(sem::r_get(&env.backend, 4), 5);
}

#[test]
fn fp11_autoinc_steps_by_format() {
    // F 形式の (r1)+ は +4、D 形式（setd 後）は +8。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Ldf, 0, &[Spec::AutoInc(1)]),
    );
    sem::r_set(&mut env.backend, 1, 0o2000);
    putf(&mut env, 0o2000, F1_0);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(sem::r_get(&env.backend, 1), 0o2004);
    assert_eq!(acf_get(&env, 0), F1_0);
    let mut w = asm(Insn::Setd, &[]);
    w.extend(asm_fp(Insn::Ldf, 0, &[Spec::AutoInc(1)]));
    let mut env = env_at("pdp11_73", 0o1000, &w);
    sem::r_set(&mut env.backend, 1, 0o2000);
    putd(&mut env, 0o2000, 0x4140_0000_0000_0000);
    step_m(&mut env, "pdp11_73").unwrap();
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(sem::r_get(&env.backend, 1), 0o2010);
    assert_eq!(ac_get(&env, 0), 0x4140_0000_0000_0000);
}

#[test]
fn fp11_immediate_consumes_operand_words() {
    // ldf @#imm,ac0: F 即値は命令ストリームの 2 語を消費する
    // （指定子デコードの 1 語 + FP 幅の残り）。PC は 6 バイト進む。
    let mut words = asm_fp(Insn::Ldf, 0, &[Spec::Imm(0)]);
    words[1] = 0x4140; // F3_0 の上位語
    words.push(0x0000); // 下位語
    words.extend(asm(Insn::Halt, &[]));
    let mut env = env_at("pdp11_73", 0o1000, &words);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(acf_get(&env, 0), F3_0);
    assert_eq!(env.pc, 0o1006); // 命令語 + 4 バイトの FP 即値
    // 次の halt に届く（即値語を命令と誤読しない）。
    match step_m(&mut env, "pdp11_73") {
        Err(Outcome::Unimplemented { pc, word }) => {
            assert_eq!(pc, 0o1006);
            assert_eq!(word, 0);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn fp11_stack_operand() {
    // FP 指定子のモード 0 以外は通常のメモリ番地 —— -(sp) は
    // F 幅の 4 バイトを刻んでスタックに F を積む。
    let mut env = env_at(
        "pdp11_73",
        0o1000,
        &asm_fp(Insn::Stf, 0, &[Spec::AutoDec(6)]),
    );
    acf_put(&mut env, 0, F2_0);
    let sp0 = sem::r_get(&env.backend, reg::SP as u8);
    step_m(&mut env, "pdp11_73").unwrap();
    assert_eq!(sem::r_get(&env.backend, reg::SP as u8), sp0 - 4);
    assert_eq!(getf(&env, sp0 - 4), F2_0);
}
