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
    // + FIS 4 + 分岐 15 + EMT/TRAP 2 + MARK/SPL 2 + 固定語 19。
    assert_eq!(INSNS.len(), 98);
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
    assert_eq!(insn_ops(Insn::Xor), [MB]);
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
