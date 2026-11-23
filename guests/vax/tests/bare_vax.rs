// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の骨格検査（段階23・VX2/VX3/VX4）。オペコード空間（1/2 バイト語）
//! のデコード、CPU モデル宣言・機能旗・挙動パラメータの形、
//! オペランド指定子の読み取り・長さ・適合・再符号化と命令全体の
//! ストリーム消費、実行ループ（可変長フェッチ・指定子評価・例外・
//! 中断可能命令の途中状態の器）を見る。
//! 出典は SPEC-VAX-ARM と SPEC-VAX-MICROVAX である。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::run::{Outcome, TrapHandler, TrapOutcome};
use polyisa_guest_vax::specifier::*;
use polyisa_guest_vax::*;
use polyisa_mem::{Access, PAGE_SIZE, Perms, VirtAddr};

/// 1 バイトオペコード語のデコード。
fn dec1(b: u8) -> Option<Insn> {
    decode(u128::from(b), 8)
}

/// 2 バイトオペコード語（接頭 + 次のバイト。語はフェッチ順に
/// 下位ビットから詰める）のデコード。
fn dec2(prefix: u8, op2: u8) -> Option<Insn> {
    decode(u128::from(prefix) | u128::from(op2) << 8, 16)
}

#[test]
fn decode_one_byte_opcodes() {
    assert_eq!(dec1(0x00), Some(Insn::Halt));
    assert_eq!(dec1(0x01), Some(Insn::Nop));
    assert_eq!(dec1(0x02), Some(Insn::Rei));
    assert_eq!(dec1(0x03), Some(Insn::Bpt));
    assert_eq!(dec1(0x04), Some(Insn::Ret));
    assert_eq!(dec1(0x05), Some(Insn::Rsb));
    assert_eq!(dec1(0x06), Some(Insn::Ldpctx));
    assert_eq!(dec1(0x07), Some(Insn::Svpctx));
    assert_eq!(dec1(0x08), Some(Insn::Cvtps));
    // 未宣言の語と、接頭だけの語は命令にならない。
    assert_eq!(dec1(0x0a), None);
    assert_eq!(dec1(0xfd), None);
    assert_eq!(dec1(0xfe), None);
    assert_eq!(dec1(0xff), None);
}

#[test]
fn decode_two_byte_opcodes() {
    assert_eq!(dec2(0xfd, 0xff), Some(Insn::Bugw));
    assert_eq!(dec2(0xfe, 0xff), Some(Insn::Bugl));
    // 接頭の違う同じ第 2 バイトは別の語。
    assert_eq!(dec2(0xff, 0xff), None);
    // 8 ビット語としては 2 バイト語の空間に入らない。
    assert_eq!(decode(0xfffd, 8), None);
}

#[test]
fn feature_flags() {
    for f in [
        "decimal",
        "hfp",
        "string_ext",
        "string_cmp",
        "crc",
        "editpc",
        "compat",
    ] {
        assert!(FEATURES.contains(&f), "{f}");
    }
}

#[test]
fn cpu_models() {
    for name in ["vax11_780", "microvax2", "ka660", "nvax"] {
        assert!(MODELS.contains(&name), "{name}");
    }
    // フル VAX は全機能を持つ。
    let full = model_feats("vax11_780");
    assert_ne!(full & FEAT_DECIMAL, 0);
    assert_ne!(full & FEAT_HFP, 0);
    assert_ne!(full & FEAT_STRING_EXT, 0);
    assert_ne!(full & FEAT_STRING_CMP, 0);
    assert_ne!(full & FEAT_CRC, 0);
    assert_ne!(full & FEAT_EDITPC, 0);
    // KA660 は実装しない群を削り、string_cmp の 6 個は実装する。
    let ka660 = model_feats("ka660");
    assert_eq!(ka660 & FEAT_DECIMAL, 0);
    assert_eq!(ka660 & FEAT_HFP, 0);
    assert_eq!(ka660 & FEAT_STRING_EXT, 0);
    assert_eq!(ka660 & FEAT_CRC, 0);
    assert_eq!(ka660 & FEAT_EDITPC, 0);
    assert_eq!(ka660 & FEAT_COMPAT, 0);
    assert_ne!(ka660 & FEAT_STRING_CMP, 0);
    // KA630 は string_cmp も補完対象。
    let ka630 = model_feats("microvax2");
    assert_eq!(ka630 & FEAT_STRING_CMP, 0);
    // NVAX は compat 以外を持つ。
    let nvax = model_feats("nvax");
    assert_ne!(nvax & FEAT_DECIMAL, 0);
    assert_eq!(nvax & FEAT_COMPAT, 0);
}

#[test]
fn cpu_model_params() {
    // KA660 は DV をハードが扱わない。それ以外は扱う。
    assert!(!model_params("ka660").dv_hw);
    assert!(model_params("vax11_780").dv_hw);
    assert!(model_params("microvax2").dv_hw);
    // 補完経路の配送は既定で実行側のトラップハンドラ。
    assert_eq!(DEFAULT_PARAMS.emul_dispatch, EMUL_DISPATCH_HOOK);
    assert_eq!(model_params("ka660").emul_dispatch, EMUL_DISPATCH_HOOK);
}

// ---- VX3: オペランド指定子 ----

/// 指定子を読み、消費長が `spec_len` と一致することを合わせて見る。
fn spec(bytes: &[u8], w: Width) -> Spec {
    let (s, n) = decode_spec(bytes, w).expect("specifier decodes");
    assert_eq!(spec_len(bytes, w), Some(n), "spec_len for {bytes:02x?}");
    s
}

/// 指定子の再符号化が元のバイト列に戻ることを見る。
fn roundtrip(bytes: &[u8], w: Width) {
    let (s, n) = decode_spec(bytes, w).expect("specifier decodes");
    let mut out = Vec::new();
    assert_eq!(encode_spec(&s, w, &mut out), Some(()));
    assert_eq!(&out[..], &bytes[..n as usize]);
}

#[test]
fn spec_all_sixteen_modes() {
    // 0-3: 短リテラル（指定子バイト全体が 0-63 の値）。
    assert_eq!(spec(&[0x00], Width::L), Spec::Lit(0));
    assert_eq!(spec(&[0x3f], Width::L), Spec::Lit(63));
    // 4: index。基底指定子が再帰して続く。
    assert_eq!(
        spec(&[0x41, 0x50], Width::L),
        Spec::Indexed {
            rx: 1,
            base: Box::new(Spec::Reg(0))
        }
    );
    // 5/6/7: レジスタ・レジスタ間接・自動減。
    assert_eq!(spec(&[0x52], Width::L), Spec::Reg(2));
    assert_eq!(spec(&[0x63], Width::L), Spec::RegDef(3));
    assert_eq!(spec(&[0x7e], Width::L), Spec::AutoDec(14));
    // 8: 自動増。PC は即値。
    assert_eq!(spec(&[0x84], Width::L), Spec::AutoInc(4));
    assert_eq!(
        spec(&[0x8f, 0x78, 0x56, 0x34, 0x12], Width::L),
        Spec::Imm {
            v: 0x1234_5678,
            w: Width::L
        }
    );
    // 9: 自動増間接。PC は絶対（4 バイトのアドレス）。
    assert_eq!(spec(&[0x95], Width::L), Spec::AutoIncDef(5));
    assert_eq!(
        spec(&[0x9f, 0x00, 0x08, 0x00, 0x00], Width::L),
        Spec::Abs(0x800)
    );
    // A-F: byte/word/long の変位と間接変位。
    assert_eq!(
        spec(&[0xa6, 0x7f], Width::L),
        Spec::Disp {
            r: 6,
            w: DispW::B,
            d: 0x7f
        }
    );
    assert_eq!(
        spec(&[0xb7, 0x80], Width::L),
        Spec::DispDef {
            r: 7,
            w: DispW::B,
            d: -0x80
        }
    );
    assert_eq!(
        spec(&[0xc8, 0x34, 0x12], Width::L),
        Spec::Disp {
            r: 8,
            w: DispW::W,
            d: 0x1234
        }
    );
    assert_eq!(
        spec(&[0xd9, 0xff, 0xff], Width::L),
        Spec::DispDef {
            r: 9,
            w: DispW::W,
            d: -1
        }
    );
    assert_eq!(
        spec(&[0xea, 0x78, 0x56, 0x34, 0x12], Width::L),
        Spec::Disp {
            r: 10,
            w: DispW::L,
            d: 0x1234_5678
        }
    );
    assert_eq!(
        spec(&[0xfb, 0x00, 0x00, 0x00, 0x80], Width::L),
        Spec::DispDef {
            r: 11,
            w: DispW::L,
            d: -0x8000_0000
        }
    );
}

#[test]
fn spec_immediate_widths() {
    // 即値の拡張バイト数はオペランドのデータ幅に従う。
    for (w, n) in [
        (Width::B, 1),
        (Width::W, 2),
        (Width::L, 4),
        (Width::F, 4),
        (Width::Q, 8),
        (Width::D, 8),
        (Width::G, 8),
        (Width::O, 16),
        (Width::H, 16),
    ] {
        let bytes = [0x8f, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let (s, len) = decode_spec(&bytes, w).expect("imm decodes");
        assert_eq!(len, 1 + n, "{w:?}");
        assert_eq!(s, Spec::Imm { v: 1, w });
        assert_eq!(spec_len(&bytes, w), Some(1 + n));
    }
}

#[test]
fn spec_len_table() {
    // 長さだけの経路: モードごとの消費バイト数。
    let w = Width::L;
    // 指定子バイトのみ。
    for b in [0x10u8, 0x30, 0x41, 0x55, 0x66, 0x77, 0x88, 0x99] {
        if b >> 4 == 4 {
            continue; // index は基底分も読む
        }
        assert_eq!(spec_len(&[b], w), Some(1), "{b:02x}");
    }
    // 即値（幅依存）・絶対（常に 4）・変位（1/2/4）。
    assert_eq!(spec_len(&[0x8f, 0, 0, 0, 0], w), Some(5));
    assert_eq!(spec_len(&[0x9f, 0, 0, 0, 0], w), Some(5));
    assert_eq!(spec_len(&[0xa0, 0], w), Some(2));
    assert_eq!(spec_len(&[0xb0, 0], w), Some(2));
    assert_eq!(spec_len(&[0xc0, 0, 0], w), Some(3));
    assert_eq!(spec_len(&[0xd0, 0, 0], w), Some(3));
    assert_eq!(spec_len(&[0xe0, 0, 0, 0, 0], w), Some(5));
    assert_eq!(spec_len(&[0xf0, 0, 0, 0, 0], w), Some(5));
    // index + 基底（変位付き）。
    assert_eq!(spec_len(&[0x41, 0xa0, 0x04], w), Some(3));
    // バッファ不足は None。
    assert_eq!(spec_len(&[], w), None);
    assert_eq!(spec_len(&[0x8f, 0, 0], w), None);
    assert_eq!(spec_len(&[0x41], w), None);
}

#[test]
fn spec_indexed_recursion() {
    // index の基底に変位・絶対・自動増減を取れる。
    let s = spec(&[0x42, 0xa0, 0x04], Width::L);
    assert_eq!(
        s,
        Spec::Indexed {
            rx: 2,
            base: Box::new(Spec::Disp {
                r: 0,
                w: DispW::B,
                d: 4
            })
        }
    );
    let s = spec(&[0x43, 0x9f, 0x00, 0x20, 0x00, 0x00], Width::L);
    assert_eq!(
        s,
        Spec::Indexed {
            rx: 3,
            base: Box::new(Spec::Abs(0x2000))
        }
    );
    let s = spec(&[0x44, 0x75], Width::L);
    assert_eq!(
        s,
        Spec::Indexed {
            rx: 4,
            base: Box::new(Spec::AutoDec(5))
        }
    );
}

#[test]
fn spec_legality() {
    use Acc::*;
    // リテラルは read のみ。
    assert_eq!(legality(&Spec::Lit(1), R), Legality::Legal);
    for a in [W, M, A, V] {
        assert_eq!(legality(&Spec::Lit(1), a), Legality::Illegal, "{a:?}");
    }
    // レジスタは .a では fault。.v では可。PC 直接は UNPREDICTABLE。
    assert_eq!(legality(&Spec::Reg(0), A), Legality::Illegal);
    assert_eq!(legality(&Spec::Reg(0), V), Legality::Legal);
    assert_eq!(legality(&Spec::Reg(15), R), Legality::Unpredictable);
    // (PC)・-(PC) は UNPREDICTABLE。
    assert_eq!(legality(&Spec::RegDef(15), R), Legality::Unpredictable);
    assert_eq!(legality(&Spec::AutoDec(15), R), Legality::Unpredictable);
    // 即値を modify/write に書くのは UNPREDICTABLE。read は合法。
    let imm = Spec::Imm { v: 1, w: Width::L };
    assert_eq!(legality(&imm, R), Legality::Legal);
    assert_eq!(legality(&imm, W), Legality::Unpredictable);
    assert_eq!(legality(&imm, M), Legality::Unpredictable);
}

#[test]
fn spec_indexed_legality() {
    use Acc::*;
    // 指数レジスタに PC は使えない。
    let bad = Spec::Indexed {
        rx: 15,
        base: Box::new(Spec::RegDef(0)),
    };
    assert_eq!(legality(&bad, R), Legality::Illegal);
    // 基底にリテラル・レジスタ・index・即値は使えない。
    for base in [
        Spec::Lit(0),
        Spec::Reg(0),
        Spec::Imm { v: 0, w: Width::L },
        Spec::Indexed {
            rx: 1,
            base: Box::new(Spec::RegDef(0)),
        },
    ] {
        let s = Spec::Indexed {
            rx: 1,
            base: Box::new(base),
        };
        assert_eq!(legality(&s, R), Legality::Illegal, "{s:?}");
    }
    // 基底と同じレジスタを自動増減するのは UNPREDICTABLE。
    for base in [Spec::AutoDec(2), Spec::AutoInc(2), Spec::AutoIncDef(2)] {
        let s = Spec::Indexed {
            rx: 2,
            base: Box::new(base),
        };
        assert_eq!(legality(&s, R), Legality::Unpredictable, "{s:?}");
    }
    // 普通の形は合法。
    let ok = Spec::Indexed {
        rx: 1,
        base: Box::new(Spec::Disp {
            r: 4,
            w: DispW::L,
            d: 0,
        }),
    };
    assert_eq!(legality(&ok, R), Legality::Legal);
}

#[test]
fn spec_roundtrip() {
    let w = Width::L;
    for bytes in [
        &[0x00][..],
        &[0x3f][..],
        &[0x50][..],
        &[0x6f][..],
        &[0x7e][..],
        &[0x84][..],
        &[0x8f, 1, 2, 3, 4][..],
        &[0x95][..],
        &[0x9f, 0, 8, 0, 0][..],
        &[0xa6, 0x80][..],
        &[0xb7, 0x01][..],
        &[0xc8, 0x34, 0x12][..],
        &[0xd9, 0xff, 0xff][..],
        &[0xea, 0x78, 0x56, 0x34, 0x12][..],
        &[0xfb, 0, 0, 0, 0x80][..],
        &[0x41, 0xa0, 0x04][..],
        &[0x42, 0x9f, 0, 0x20, 0, 0][..],
    ] {
        roundtrip(bytes, w);
    }
    // 符号化できない形。
    let mut out = Vec::new();
    assert_eq!(encode_spec(&Spec::Lit(64), w, &mut out), None);
    let mut out = Vec::new();
    assert_eq!(
        encode_spec(
            &Spec::Disp {
                r: 0,
                w: DispW::B,
                d: 200
            },
            w,
            &mut out
        ),
        None
    );
}

#[test]
fn insn_ops_signatures() {
    // 代表命令の指定子シグネチャ。
    assert_eq!(insn_ops(Insn::Movl), &[RL, WL]);
    assert_eq!(insn_ops(Insn::Addl2), &[RL, ML]);
    assert_eq!(insn_ops(Insn::Cmpl), &[RL, RL]);
    assert_eq!(insn_ops(Insn::Beql), &[BB]);
    assert_eq!(insn_ops(Insn::Brw), &[BW]);
    assert_eq!(insn_ops(Insn::Extv), &[RL, RB, VB, WL]);
    assert_eq!(insn_ops(Insn::Movc3), &[RW, AB, AB]);
    assert_eq!(insn_ops(Insn::Calls), &[RL, AB]);
    assert_eq!(insn_ops(Insn::Movo), &[RO, WO]);
    assert_eq!(insn_ops(Insn::Nop), &[]);
    assert_eq!(insn_ops(Insn::Bugw), &[]);
}

#[test]
fn decode_insn_streams() {
    // movl (r1), r2
    let f = decode_insn(&[0xd0, 0x61, 0x52]).expect("movl decodes");
    assert_eq!(f.insn, Insn::Movl);
    assert_eq!(f.len, 3);
    assert_eq!(
        f.ops,
        [Opnd::Spec(Spec::RegDef(1)), Opnd::Spec(Spec::Reg(2))]
    );

    // movl #0x12345678, r0 — 即値は幅（long）で 4 バイト。
    let f = decode_insn(&[0xd0, 0x8f, 0x78, 0x56, 0x34, 0x12, 0x50]).expect("decodes");
    assert_eq!(f.insn, Insn::Movl);
    assert_eq!(f.len, 7);
    assert_eq!(
        f.ops[0],
        Opnd::Spec(Spec::Imm {
            v: 0x1234_5678,
            w: Width::L
        })
    );

    // movl 4(r0)[r1], r2 — index + 変位基底。
    let f = decode_insn(&[0xd0, 0x41, 0xa0, 0x04, 0x52]).expect("decodes");
    assert_eq!(f.len, 5);
    assert_eq!(
        f.ops[0],
        Opnd::Spec(Spec::Indexed {
            rx: 1,
            base: Box::new(Spec::Disp {
                r: 0,
                w: DispW::B,
                d: 4
            })
        })
    );

    // beql +5 — 分岐変位は指定子バイトを持たない。
    let f = decode_insn(&[0x13, 0x05]).expect("beql decodes");
    assert_eq!(f.insn, Insn::Beql);
    assert_eq!(f.len, 2);
    assert_eq!(f.ops, [Opnd::Br(5)]);

    // sobgeq r3, -4 — modify + word 変位ではなく byte 変位。
    let f = decode_insn(&[0xf4, 0x53, 0xfc]).expect("sobgeq decodes");
    assert_eq!(f.insn, Insn::Sobgeq);
    assert_eq!(f.len, 3);
    assert_eq!(f.ops, [Opnd::Spec(Spec::Reg(3)), Opnd::Br(-4)]);

    // movc3 #5, (r1), (r2) — 3 指定子。即値は幅 word で 2 バイト。
    let f = decode_insn(&[0x28, 0x8f, 0x05, 0x00, 0x61, 0x62]).expect("movc3 decodes");
    assert_eq!(f.insn, Insn::Movc3);
    assert_eq!(f.len, 6);
    assert_eq!(f.ops[0], Opnd::Spec(Spec::Imm { v: 5, w: Width::W }));

    // calls #2, @#0x800 — 即値（long 幅で 4 バイト）と絶対。
    let f = decode_insn(&[0xfb, 0x8f, 2, 0, 0, 0, 0x9f, 0x00, 0x08, 0x00, 0x00])
        .expect("calls decodes");
    assert_eq!(f.insn, Insn::Calls);
    assert_eq!(f.len, 11);
    assert_eq!(f.ops[1], Opnd::Spec(Spec::Abs(0x800)));

    // 指定子を持たない命令はそのまま 1/2 バイト。
    let f = decode_insn(&[0x01]).expect("nop decodes");
    assert_eq!(f.insn, Insn::Nop);
    assert_eq!(f.len, 1);
    assert!(f.ops.is_empty());
    let f = decode_insn(&[0xfd, 0xff]).expect("bugw decodes");
    assert_eq!(f.insn, Insn::Bugw);
    assert_eq!(f.len, 2);
}

#[test]
fn decode_insn_two_byte_opcodes() {
    // 2 バイトオペコード（0xfd 接頭）も指定子を続けて読む。
    // movo r0, r1
    let f = decode_insn(&[0xfd, 0x7d, 0x50, 0x51]).expect("movo decodes");
    assert_eq!(f.insn, Insn::Movo);
    assert_eq!(f.len, 4);
    assert_eq!(f.ops, [Opnd::Spec(Spec::Reg(0)), Opnd::Spec(Spec::Reg(1))]);
    // pushah — hfp 機能の命令。
    let f = decode_insn(&[0xfd, 0x7f, 0xab, 0x10]).expect("pushah decodes");
    assert_eq!(f.insn, Insn::Pushah);
    assert_eq!(f.len, 4);
}

#[test]
fn insn_len_matches_decode() {
    // 長さだけの経路は完全デコードと同じ全長を返す。
    for bytes in [
        &[0x01][..],
        &[0xfd, 0xff][..],
        &[0xd0, 0x61, 0x52][..],
        &[0xd0, 0x8f, 0x78, 0x56, 0x34, 0x12, 0x50][..],
        &[0xd0, 0x41, 0xa0, 0x04, 0x52][..],
        &[0x13, 0x05][..],
        &[0x31, 0x00, 0x80][..], // brw -32768
        &[0xf4, 0x53, 0xfc][..],
        &[0x28, 0x8f, 0x05, 0x00, 0x61, 0x62][..],
        &[0xfd, 0x7d, 0x50, 0x51][..],
    ] {
        assert_eq!(
            insn_len(bytes),
            decode_insn(bytes).map(|f| f.len),
            "{bytes:02x?}"
        );
    }
    // 途中で切れたストリームはどちらも None。
    assert_eq!(insn_len(&[0xd0]), None);
    assert_eq!(insn_len(&[0xd0, 0x8f, 1]), None);
    assert!(decode_insn(&[0xd0, 0x8f, 1]).is_none());
}

#[test]
fn decode_insn_feature_gated() {
    // hfp 旗のないモデルでは movo/movah/pushah はデコードされない。
    let no_hfp = DEFAULT_FEATS & !FEAT_HFP;
    assert!(decode_insn_ex(&[0xfd, 0x7d, 0x50, 0x51], no_hfp).is_none());
    assert_eq!(insn_len_ex(&[0xfd, 0x7d, 0x50, 0x51], no_hfp), None);
    // string_cmp 旗のないモデルでは cmpc3 等はデコードされない。
    let no_cmp = DEFAULT_FEATS & !FEAT_STRING_CMP;
    assert!(decode_insn_ex(&[0x29, 0x50, 0x61, 0x62], no_cmp).is_none());
    // ka660 は string_cmp を持つので cmpc3 はデコードできる。
    let ka660 = model_feats("ka660");
    let f = decode_insn_ex(&[0x29, 0x8f, 0x03, 0x00, 0x61, 0x62], ka660).expect("cmpc3 on ka660");
    assert_eq!(f.insn, Insn::Cmpc3);
    assert_eq!(f.len, 6);
}

#[test]
fn declared_operand_insns_decode() {
    // 宣言した代表命令がオペコードから解ける。
    assert_eq!(dec1(0xd0), Some(Insn::Movl));
    assert_eq!(dec1(0xc0), Some(Insn::Addl2));
    assert_eq!(dec1(0xd1), Some(Insn::Cmpl));
    assert_eq!(dec1(0x13), Some(Insn::Beql));
    assert_eq!(dec1(0x28), Some(Insn::Movc3));
    assert_eq!(dec1(0xfb), Some(Insn::Calls));
    assert_eq!(dec1(0x0e), Some(Insn::Insque));
    assert_eq!(dec2(0xfd, 0x7d), Some(Insn::Movo));
    assert_eq!(dec2(0xfd, 0x7e), Some(Insn::Movah));
    assert_eq!(dec2(0xfd, 0x7f), Some(Insn::Pushah));
    // 機能旗で削ると解けない。
    let no_hfp = DEFAULT_FEATS & !FEAT_HFP;
    assert_eq!(decode_model_ex(0x7dfd, 16, false, no_hfp), None);
    // まだ宣言していない語は解けない。
    assert_eq!(dec2(0xfd, 0x00), None);
    // insn_ops の match は Insn 全バリアントを網羅する
    // （コンパイル時の保証）。INSNS メタ表にも代表名がある。
    for name in ["movl", "addl2", "cmpl", "beql", "movc3", "movo"] {
        assert!(INSNS.iter().any(|m| m.name == name), "{name}");
    }
}

// ---- VX4: 実行ループ ----

const BASE: u64 = 0x1_0000;

/// トラップを捌かないハンドラ。
struct NoSys;

impl TrapHandler for NoSys {
    fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
        TrapOutcome::Unimplemented
    }
}

/// 読み書き実行可能なページを BASE に `pages` 枚写像した環境。
/// PSL はユーザーモード相当、SP は妥当な値を入れる。
fn run_env(pages: u64) -> BareEnv {
    let mut env = BareEnv::new(core::mem::size_of::<CpuState>());
    env.backend
        .mem
        .map(VirtAddr(BASE), pages, Perms(Perms::RW.0 | Perms::X.0))
        .unwrap();
    env.backend.addr_mask = 0xFFFF_FFFF;
    sem::psl_put(&mut env.backend, psl::USER);
    sem::r_set(&mut env.backend, reg::SP as u8, 0x7fff_0000);
    env
}

fn put(env: &mut BareEnv, addr: u64, bytes: &[u8]) {
    env.backend.mem.write(VirtAddr(addr), bytes).unwrap();
}

fn step(env: &mut BareEnv) -> Result<(), Outcome> {
    run::step(env, &mut NoSys, DEFAULT_FEATS)
}

fn r(env: &BareEnv, i: u8) -> u32 {
    sem::r_get(&env.backend, i)
}

fn mem32(env: &BareEnv, a: u64) -> u32 {
    let mut b = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(a), &mut b, Access::DATA_LE)
        .unwrap();
    u32::from_le_bytes(b)
}

#[test]
fn variable_length_sequence() {
    // 異なる長さの命令列: nop(1) movb #0x42,r0(4) clrw (r1)(2)
    // movl #0x12345678,r2(7) —— ステップごとに PC が命令長ぶん進む。
    let mut env = run_env(1);
    let prog = [
        0x01, // nop
        0x90, 0x8f, 0x42, 0x50, // movb #0x42, r0
        0xb4, 0x61, // clrw (r1)
        0xd0, 0x8f, 0x78, 0x56, 0x34, 0x12, 0x52, // movl #0x12345678, r2
    ];
    put(&mut env, BASE, &prog);
    put(&mut env, BASE + 0x100, &0xaabb_ccddu32.to_le_bytes());
    sem::r_set(&mut env.backend, 1, (BASE + 0x100) as u32);
    env.pc = BASE;

    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 1);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 5);
    assert_eq!(r(&env, 0), 0x42);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 7);
    // clrw は下位語だけを 0 にし、上位語は保存する。
    assert_eq!(mem32(&env, BASE + 0x100), 0xaabb_0000);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 14);
    assert_eq!(r(&env, 2), 0x1234_5678);
    assert_eq!(env.steps, 4);
}

#[test]
fn specifier_eval_side_effects() {
    // 自動増・自動減・変位・間接の評価とレジスタ更新。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &0x1111_2222u32.to_le_bytes());
    put(&mut env, BASE + 0x204, &0x3333_4444u32.to_le_bytes());
    put(
        &mut env,
        BASE + 0x300,
        &((BASE + 0x200) as u32).to_le_bytes(),
    );
    env.pc = BASE;

    // movl (r0)+, r1 → r1=[r0], r0 += 4
    put(&mut env, BASE, &[0xd0, 0x80, 0x51]);
    sem::r_set(&mut env.backend, 0, (BASE + 0x200) as u32);
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), 0x1111_2222);
    assert_eq!(r(&env, 0), (BASE + 0x204) as u32);

    // movl -(r0), r2 → r0 -= 4, r2=[r0]
    put(&mut env, BASE + 0x10, &[0xd0, 0x70, 0x52]);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), (BASE + 0x200) as u32);
    assert_eq!(r(&env, 2), 0x1111_2222);

    // movl @4(r3), r4 → 4(r3) のロングワードがオペランドアドレス
    put(&mut env, BASE + 0x20, &[0xd0, 0xb3, 0x04, 0x54]);
    sem::r_set(&mut env.backend, 3, (BASE + 0x2fc) as u32);
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 4), 0x1111_2222);

    // movl @(r5)+, r6 → r5 += 4（間接は常に longword）
    put(&mut env, BASE + 0x30, &[0xd0, 0x95, 0x56]);
    sem::r_set(&mut env.backend, 5, (BASE + 0x300) as u32);
    env.pc = BASE + 0x30;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 6), 0x1111_2222);
    assert_eq!(r(&env, 5), (BASE + 0x304) as u32);
}

#[test]
fn specifier_eval_indexed_and_address() {
    // index 指定子（基底変位 + 指数×データ幅）と .a オペランド。
    let mut env = run_env(1);
    for i in 0..4u32 {
        put(
            &mut env,
            BASE + 0x400 + u64::from(i) * 4,
            &(0x1000 + i).to_le_bytes(),
        );
    }
    env.pc = BASE;
    // movl 8(r2)[r1], r3 → addr = r2 + 8 + r1*4（0xa2 はバイト変位 r2）
    put(&mut env, BASE, &[0xd0, 0x41, 0xa2, 0x08, 0x53]);
    sem::r_set(&mut env.backend, 1, 1);
    sem::r_set(&mut env.backend, 2, (BASE + 0x3f8) as u32);
    step(&mut env).unwrap();
    assert_eq!(r(&env, 3), 0x1001);

    // movab (r9)+, r10 —— .ab の自動増は byte 刻み（+1）。
    put(&mut env, BASE + 0x10, &[0x9e, 0x89, 0x5a]);
    sem::r_set(&mut env.backend, 9, (BASE + 0x400) as u32);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 10), (BASE + 0x400) as u32);
    assert_eq!(r(&env, 9), (BASE + 0x401) as u32);

    // moval #imm, r1 —— .a の即値は拡張バイトの位置がオペランド。
    put(
        &mut env,
        BASE + 0x20,
        &[0xde, 0x8f, 0xaa, 0xbb, 0xcc, 0xdd, 0x51],
    );
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), (BASE + 0x22) as u32);
}

#[test]
fn pc_relative_and_pc_write() {
    let mut env = run_env(1);
    put(&mut env, BASE + 0x40, &0xdead_beefu32.to_le_bytes());
    env.pc = BASE;
    // movl 4(PC), r0 —— 基底は指定子の終端（insn+3）。+4 で insn+7。
    put(&mut env, BASE, &[0xd0, 0xaf, 0x04, 0x50]);
    put(&mut env, BASE + 7, &0xdeadc0deu32.to_le_bytes());
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xdeadc0de);

    // movl #target, r15 —— PC への書き込みは分岐。
    let dst = BASE + 0x80;
    put(
        &mut env,
        BASE + 0x10,
        &[
            0xd0,
            0x8f,
            dst as u8,
            (dst >> 8) as u8,
            (dst >> 16) as u8,
            (dst >> 24) as u8,
            0x5f,
        ],
    );
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(env.pc, dst);
}

#[test]
fn push_and_stack() {
    // pushl #v → SP-=4, [SP]=v。pushal @#a → アドレスを積む。
    let mut env = run_env(1);
    env.pc = BASE;
    put(&mut env, BASE, &[0xdd, 0x8f, 0x44, 0x33, 0x22, 0x11]); // pushl #0x11223344
    let sp = r(&env, 14);
    // スタックの着地先を写像（0x7fff_0000 は未写像なのでテスト用に張る）。
    env.backend
        .mem
        .map(
            VirtAddr(0x7fff_0000 - PAGE_SIZE),
            1,
            Perms(Perms::RW.0 | Perms::X.0),
        )
        .unwrap();
    step(&mut env).unwrap();
    assert_eq!(r(&env, 14), sp - 4);
    assert_eq!(mem32(&env, u64::from(sp - 4)), 0x1122_3344);
}

#[test]
fn movcc_flags() {
    // movb #0, r0 → Z=1 N=0 V=0、movb #0x80 → N=1。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x90, 0x8f, 0x00, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    let p = sem::psl_get(&env.backend);
    assert_ne!(p & (1 << psl::Z), 0);
    assert_eq!(p & (1 << psl::N), 0);
    assert_eq!(p & (1 << psl::V), 0);
    put(&mut env, BASE + 0x10, &[0x90, 0x8f, 0x80, 0x51]);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    let p = sem::psl_get(&env.backend);
    assert_eq!(p & (1 << psl::Z), 0);
    assert_ne!(p & (1 << psl::N), 0);
    // movb は書き込み先の上位バイトを保存する。
    sem::r_set(&mut env.backend, 2, 0xaabb_ccdd);
    put(&mut env, BASE + 0x20, &[0x90, 0x8f, 0x7f, 0x52]);
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0xaabb_cc7f);
}

#[test]
fn halt_is_privileged_fault() {
    // halt はユーザーモードで特権命令 fault（SCB 0x10）。
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Exit(0)
        }
    }
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x00]);
    env.pc = BASE;
    let mut sys = Rec(0);
    let r = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(r, Err(Outcome::Exit(0)));
    assert_eq!(sys.0, sem::scb::PRIV_INSN);
    // fault なので復帰先は命令先頭。
    assert_eq!(env.pc, BASE);
}

#[test]
fn reserved_mode_and_insn_faults() {
    struct Rec(Vec<u32>);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0.push(code);
            TrapOutcome::Unimplemented
        }
    }
    let mut env = run_env(1);
    let mut sys = Rec(Vec::new());
    // movb S^#1, r0 —— 書き込み先にリテラルは使えない → fault 0x1c。
    put(&mut env, BASE, &[0x90, 0x8f, 0x01, 0x01]);
    env.pc = BASE;
    let r = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(sys.0, [sem::scb::RESERVED_MODE]);
    assert!(matches!(r, Err(Outcome::Unimplemented { .. })));
    // 0x0a（index）は予約オペコード → 予約命令 fault 0x10。
    put(&mut env, BASE + 0x10, &[0x0a]);
    env.pc = BASE + 0x10;
    let r = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(sys.0.last(), Some(&sem::scb::PRIV_INSN));
    assert!(matches!(r, Err(Outcome::Unimplemented { .. })));
}

#[test]
fn bpt_trap_advances_pc() {
    // BPT は trap —— 復帰先は次の命令（fault と違い PC が進む）。
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x03, 0x01]); // bpt; nop
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::BPT);
    assert_eq!(env.pc, BASE + 1);
}

#[test]
fn fetch_fault_restart() {
    // 未写像ページへのフェッチは ACV fault → ハンドラがページを
    // 張って Handled → 同じ命令をやり直す（env.pc は動かない）。
    struct MapSys(bool);
    impl TrapHandler for MapSys {
        fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
            if code == sem::scb::ACV && !self.0 {
                self.0 = true;
                env.backend
                    .mem
                    .map(
                        VirtAddr(BASE + PAGE_SIZE),
                        1,
                        Perms(Perms::RW.0 | Perms::X.0),
                    )
                    .unwrap();
                TrapOutcome::Handled
            } else {
                TrapOutcome::Unimplemented
            }
        }
    }
    let mut env = run_env(1);
    let mut sys = MapSys(false);
    env.pc = BASE + PAGE_SIZE;
    let r = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(r, Ok(()));
    assert_eq!(env.pc, BASE + PAGE_SIZE);
    assert!(sys.0);
    // 張ったページに nop を置くと普通に実行できる。
    put(&mut env, BASE + PAGE_SIZE, &[0x01]);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(env.pc, BASE + PAGE_SIZE + 1);
}

#[test]
fn specifier_crossing_page() {
    // ページ末尾に置いた命令の即値拡張が次ページに跨る。
    let mut env = run_env(2);
    let insn = BASE + PAGE_SIZE - 3;
    // movl #0x12345678, r0 —— 7 バイト（うち即値 4 バイトが跨ぐ）。
    put(&mut env, insn, &[0xd0, 0x8f, 0x78, 0x56, 0x34, 0x12, 0x50]);
    env.pc = insn;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0x1234_5678);
    assert_eq!(env.pc, insn + 7);
}

#[test]
fn fpd_roundtrip_vessel() {
    // 反復命令が使う途中状態の器: 退避 → FPD=1・PC 復帰、再入 →
    // 作業語、完了 → 消去。
    let mut env = run_env(1);
    // movc3 のオペコード語は 0x28。
    sem::partial_save(&mut env.backend, 0x28, [7, 0x800, 9, 0x900], 0x200);
    assert!(sem::fpd(&env.backend));
    assert_eq!(r(&env, reg::PC as u8), 0x200);
    assert_eq!(sem::partial_insn(&env.backend), 0x28);
    // 自命令の作業語だけが再入に返る。
    assert_eq!(
        sem::partial_resume(&mut env.backend, 0x28),
        Some([7, 0x800, 9, 0x900])
    );
    assert_eq!(sem::partial_resume(&mut env.backend, 0x2c), None);
    // 完了は標識を消す。
    sem::partial_done(&mut env.backend);
    assert!(!sem::fpd(&env.backend));
    assert_eq!(sem::partial_insn(&env.backend), PART_INSN_NONE);
    assert_eq!(sem::partial_resume(&mut env.backend, 0x28), None);

    // 部分実行の標識が残っていても、反復しない命令の実行で消える。
    sem::partial_save(&mut env.backend, 0x28, [1, 2, 3, 4], 0x200);
    put(&mut env, BASE, &[0x01]); // nop
    env.pc = BASE;
    step(&mut env).unwrap();
    assert!(!sem::fpd(&env.backend));
    assert_eq!(sem::partial_insn(&env.backend), PART_INSN_NONE);
}

#[test]
fn fp_word_order_3412() {
    // D/G/H 浮動型の語順: 最上位語（符号・指数を含む）が最下位
    // アドレスに来る「3412」順。正準形（符号が最上位ビット）との
    // 写像は 16 ビット語の逆順 —— 自己逆で往復する。
    // D: 8 バイト = 4 語。
    let canon: u128 = 0x1111_2222_3333_4444;
    let vax = sem::fp_order(Width::D, canon);
    assert_eq!(vax, 0x4444_3333_2222_1111);
    // 往復で元に戻る。
    assert_eq!(sem::fp_order(Width::D, vax), canon);
    // H: 16 バイト = 8 語。
    let canon: u128 = 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10;
    assert_eq!(
        sem::fp_order(Width::H, canon),
        0x0f10_0d0e_0b0c_090a_0708_0506_0304_0102
    );
    // 整数幅は素通し（mov の写像は生の語順）。
    assert_eq!(sem::fp_order(Width::L, 0xaabb_ccdd), 0xaabb_ccdd);
}

// ---- VX5: 整数演算 ----

/// 条件コードを (N,Z,V,C) で取り出す。
fn cc(env: &BareEnv) -> (bool, bool, bool, bool) {
    let p = sem::psl_get(&env.backend);
    (
        p & (1 << psl::N) != 0,
        p & (1 << psl::Z) != 0,
        p & (1 << psl::V) != 0,
        p & (1 << psl::C) != 0,
    )
}

/// 1 命令を BASE に置いて 1 ステップ実行した環境を返す。
fn exec1(bytes: &[u8]) -> BareEnv {
    let mut env = run_env(1);
    put(&mut env, BASE, bytes);
    env.pc = BASE;
    step(&mut env).unwrap();
    env
}

#[test]
fn new_integer_insns_decode() {
    assert_eq!(dec1(0x7a), Some(Insn::Emul));
    assert_eq!(dec1(0x7b), Some(Insn::Ediv));
    assert_eq!(dec1(0x84), Some(Insn::Mulb2));
    assert_eq!(dec1(0x87), Some(Insn::Divb3));
    assert_eq!(dec1(0x8e), Some(Insn::Mnegb));
    assert_eq!(dec1(0x98), Some(Insn::Cvtbl));
    assert_eq!(dec1(0xa4), Some(Insn::Mulw2));
    assert_eq!(dec1(0xa6), Some(Insn::Divw2));
    assert_eq!(dec1(0xae), Some(Insn::Mnegw));
    assert_eq!(dec1(0xce), Some(Insn::Mnegl));
    assert_eq!(dec1(0x32), Some(Insn::Cvtwl));
    assert_eq!(dec1(0x33), Some(Insn::Cvtwb));
    assert_eq!(dec1(0xf6), Some(Insn::Cvtlb));
    assert_eq!(dec1(0xf7), Some(Insn::Cvtlw));
    assert_eq!(insn_ops(Insn::Emul), &[RL, RL, RL, WQ]);
    assert_eq!(insn_ops(Insn::Ediv), &[RL, RQ, WL, WL]);
    assert_eq!(insn_ops(Insn::Divb3), &[RB, RB, WB]);
    assert_eq!(insn_ops(Insn::Cvtlw), &[RL, WW]);
}

#[test]
fn add_results_and_cc() {
    // addl3 #0x7fffffff, #1, r0 —— 正のあふれ: N=1 V=1 C=0。
    let env = exec1(&[0xc1, 0x8f, 0xff, 0xff, 0xff, 0x7f, 0x8f, 1, 0, 0, 0, 0x50]);
    assert_eq!(r(&env, 0), 0x8000_0000);
    assert_eq!(cc(&env), (true, false, true, false));

    // addb3 #0x7f, #1, r0 —— byte でも符号付きあふれは V=1。
    let env = exec1(&[0x81, 0x8f, 0x7f, 0x8f, 0x01, 0x50]);
    assert_eq!(r(&env, 0) & 0xff, 0x80);
    assert_eq!(cc(&env), (true, false, true, false));

    // addw3 #0xffff, #1, r0 —— 桁出し: Z=1 C=1 V=0。
    let env = exec1(&[0xa1, 0x8f, 0xff, 0xff, 0x8f, 1, 0, 0x50]);
    assert_eq!(r(&env, 0) & 0xffff, 0);
    assert_eq!(cc(&env), (false, true, false, true));

    // addl2 #-1, r0 —— 負の結果、あふれ・桁出しなし。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xc0, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x50]);
    sem::r_set(&mut env.backend, 0, 0);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xffff_ffff);
    assert_eq!(cc(&env), (true, false, false, false));

    // addl2 #1, r0 —— 0xffffffff + 1: Z=1 C=1。
    sem::r_set(&mut env.backend, 0, 0xffff_ffff);
    put(&mut env, BASE + 0x10, &[0xc0, 0x8f, 1, 0, 0, 0, 0x50]);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0);
    assert_eq!(cc(&env), (false, true, false, true));

    // addw2 は書き込み先の上位を保存（mw は 2 バイトだけ更新）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0xaabb_0001);
    put(&mut env, BASE, &[0xa0, 0x8f, 0xff, 0xff, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xaabb_0000);
}

#[test]
fn sub_results_and_cc() {
    // subl3 #0, #1, r0 —— 借り: N=1 C=1。
    let env = exec1(&[0xc3, 0x8f, 0, 0, 0, 0, 0x8f, 1, 0, 0, 0, 0x50]);
    assert_eq!(r(&env, 0), 0xffff_ffff);
    assert_eq!(cc(&env), (true, false, false, true));

    // subl3 #0x80000000, #1, r0 —— 最負値 - 1: V=1 C=0。
    let env = exec1(&[0xc3, 0x8f, 0, 0, 0, 0x80, 0x8f, 1, 0, 0, 0, 0x50]);
    assert_eq!(r(&env, 0), 0x7fff_ffff);
    assert_eq!(cc(&env), (false, false, true, false));

    // subb2 #1, r0 —— 0 - 1 = 0xff: N=1 C=1。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x82, 0x8f, 0x01, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xff, 0xff);
    assert_eq!(cc(&env), (true, false, false, true));

    // subw3 #1, #1, r0 —— 等しい: Z=1 C=0。
    let env = exec1(&[0xa3, 0x8f, 1, 0, 0x8f, 1, 0, 0x50]);
    assert_eq!(r(&env, 0) & 0xffff, 0);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn adwc_sbwc_carry_chains() {
    // 桁入れ・借り入れとして C を使う。
    let mut env = run_env(1);
    // adwc #0, r0 —— r0=0xffffffff, C=1 → 0、新しい C=1。
    put(&mut env, BASE, &[0xd8, 0x8f, 0, 0, 0, 0, 0x50]);
    sem::r_set(&mut env.backend, 0, 0xffff_ffff);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0);
    assert_eq!(cc(&env), (false, true, false, true));

    // adwc #0, r0 —— r0=5, C=1 → 6、C=0。
    sem::r_set(&mut env.backend, 0, 5);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 6);
    assert_eq!(cc(&env), (false, false, false, false));

    // sbwc #0, r0 —— r0=0, C=1 → -1、借りで C=1。
    put(&mut env, BASE + 0x10, &[0xd9, 0x8f, 0, 0, 0, 0, 0x50]);
    sem::r_set(&mut env.backend, 0, 0);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xffff_ffff);
    assert_eq!(cc(&env), (true, false, false, true));

    // sbwc #0, r0 —— r0=5, C=1 → 4、C=0。
    sem::r_set(&mut env.backend, 0, 5);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 4);
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn inc_dec_flags() {
    // incb r0 —— 0x7f → 0x80: N=1 V=1。C は保存（立てておく）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0x7f);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    put(&mut env, BASE, &[0x96, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xff, 0x80);
    assert_eq!(cc(&env), (true, false, true, true));

    // decb r0 —— 0x80(-128) → 0x7f: V=1。C=0 を保存。
    sem::r_set(&mut env.backend, 0, 0x80);
    sem::psl_put(&mut env.backend, psl::USER);
    put(&mut env, BASE + 0x10, &[0x97, 0x50]);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xff, 0x7f);
    assert_eq!(cc(&env), (false, false, true, false));

    // incl r0 —— -1 + 1 = 0: Z=1 V=0。C=1 を保存。
    sem::r_set(&mut env.backend, 0, 0xffff_ffff);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    put(&mut env, BASE + 0x20, &[0xd6, 0x50]);
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0);
    assert_eq!(cc(&env), (false, true, false, true));

    // decw r0 —— 0 → 0xffff: N=1 V=0 C=0。
    sem::r_set(&mut env.backend, 0, 0);
    sem::psl_put(&mut env.backend, psl::USER);
    put(&mut env, BASE + 0x30, &[0xb7, 0x50]);
    env.pc = BASE + 0x30;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xffff, 0xffff);
    assert_eq!(cc(&env), (true, false, false, false));
}

#[test]
fn mneg_flags() {
    // mnegl #5, r0 → -5: N=1 V=0 C=0（C は立てておいて消える）。
    let mut env = run_env(1);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    put(&mut env, BASE, &[0xce, 0x8f, 5, 0, 0, 0, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xffff_fffb);
    assert_eq!(cc(&env), (true, false, false, false));

    // mnegb #0x80(-128), r0 → 反転できず 0x80: V=1。
    let env = exec1(&[0x8e, 0x8f, 0x80, 0x50]);
    assert_eq!(r(&env, 0) & 0xff, 0x80);
    assert_eq!(cc(&env), (true, false, true, false));

    // mnegw #0, r0 → 0: Z=1。
    let env = exec1(&[0xae, 0x8f, 0, 0, 0x50]);
    assert_eq!(r(&env, 0) & 0xffff, 0);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn mul_flags() {
    // mull3 #0x10000, #0x10000, r0 —— 2^32 は longword に入らない:
    // 切り詰め 0、V=1 Z=1。
    let env = exec1(&[0xc5, 0x8f, 0, 0, 1, 0, 0x8f, 0, 0, 1, 0, 0x50]);
    assert_eq!(r(&env, 0), 0);
    assert_eq!(cc(&env), (false, true, true, false));

    // mulb3 #0x40, #4, r0 —— 0x100 → 0x00、V=1。
    let env = exec1(&[0x85, 0x8f, 0x40, 0x8f, 0x04, 0x50]);
    assert_eq!(r(&env, 0) & 0xff, 0);
    assert_eq!(cc(&env), (false, true, true, false));

    // mull3 #-3, #5, r1 → -15: N=1 V=0。
    let env = exec1(&[0xc5, 0x8f, 0xfd, 0xff, 0xff, 0xff, 0x8f, 5, 0, 0, 0, 0x51]);
    assert_eq!(r(&env, 1), 0xffff_fff1);
    assert_eq!(cc(&env), (true, false, false, false));

    // mulw2 #3, r0 —— 7*3=21。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 7);
    put(&mut env, BASE, &[0xa4, 0x8f, 3, 0, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xffff, 21);
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn div_results() {
    // divl3 #2, #-7, r0 —— 商は 0 方向切り詰めで -3（余りは捨てる）。
    let env = exec1(&[0xc7, 0x8f, 2, 0, 0, 0, 0x8f, 0xf9, 0xff, 0xff, 0xff, 0x50]);
    assert_eq!(r(&env, 0), 0xffff_fffd);
    assert_eq!(cc(&env), (true, false, false, false));

    // divl3 #-2, #7, r0 → -3。
    let env = exec1(&[0xc7, 0x8f, 0xfe, 0xff, 0xff, 0xff, 0x8f, 7, 0, 0, 0, 0x50]);
    assert_eq!(r(&env, 0), 0xffff_fffd);
    assert_eq!(cc(&env), (true, false, false, false));

    // divb3 #-3, #-8, r0 → 2（8/3 = 2.6 切り詰め）。
    let env = exec1(&[0x87, 0x8f, 0xfd, 0x8f, 0xf8, 0x50]);
    assert_eq!(r(&env, 0) & 0xff, 2);
    assert_eq!(cc(&env), (false, false, false, false));

    // divl2 #2, r0 —— r0=7 → 3。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 7);
    put(&mut env, BASE, &[0xc6, 0x8f, 2, 0, 0, 0, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 3);

    // divb3 #0xff(-1), #0x80(-128), r0 —— 商 128 は byte に入らず
    // V=1、結果は切り詰め 0x80。書き込み先の上位は保存。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0xaabb_cc00);
    put(&mut env, BASE, &[0x87, 0x8f, 0xff, 0x8f, 0x80, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xaabb_cc80);
    assert_eq!(cc(&env), (true, false, true, false));
}

#[test]
fn div_by_zero_is_arithmetic_trap() {
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    let mut env = run_env(1);
    // divl2 #0, r0 —— 整数ゼロ除算 trap（IV とは無関係）。
    put(&mut env, BASE, &[0xc6, 0x8f, 0, 0, 0, 0, 0x50, 0x01]);
    sem::r_set(&mut env.backend, 0, 0xdead_beef);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::N));
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::INT_DIV_ZERO));
    // trap なので復帰先は次の命令。書き戻しと条件コードは行わない。
    assert_eq!(env.pc, BASE + 7);
    assert_eq!(r(&env, 0), 0xdead_beef);
    assert!(sem::psl_get(&env.backend) & (1 << psl::N) != 0);

    // divb3 #0, #5, r0 —— 除数は第 1 オペランド。
    put(&mut env, BASE + 0x10, &[0x87, 0x8f, 0, 0x8f, 5, 0x50]);
    env.pc = BASE + 0x10;
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::INT_DIV_ZERO));
}

#[test]
fn integer_overflow_trap_gated_by_iv() {
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xc0, 0x8f, 1, 0, 0, 0, 0x50, 0x01]);
    // IV=1: あふれで算術 trap（型パラメータ 1）。結果は書き戻し済み。
    sem::r_set(&mut env.backend, 0, 0x7fff_ffff);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::IV));
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::INT_OVERFLOW));
    assert_eq!(env.pc, BASE + 7);
    assert_eq!(r(&env, 0), 0x8000_0000);
    // IV=0: 同じあふれは trap せず V=1 だけ。
    sem::r_set(&mut env.backend, 0, 0x7fff_ffff);
    sem::psl_put(&mut env.backend, psl::USER);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (true, false, true, false));
}

#[test]
fn emul_ediv_quadword() {
    // emul #0x10000, #0x10000, #0, r0 —— r0:r1 = 2^32。
    let env = exec1(&[
        0x7a, 0x8f, 0, 0, 1, 0, 0x8f, 0, 0, 1, 0, 0x8f, 0, 0, 0, 0, 0x50,
    ]);
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), 1);
    assert_eq!(cc(&env), (false, false, false, false));

    // emul #-2, #3, #5, r2 —— -1 を符号拡張した 64 ビット。
    let env = exec1(&[
        0x7a, 0x8f, 0xfe, 0xff, 0xff, 0xff, 0x8f, 3, 0, 0, 0, 0x8f, 5, 0, 0, 0, 0x52,
    ]);
    assert_eq!(r(&env, 2), 0xffff_ffff);
    assert_eq!(r(&env, 3), 0xffff_ffff);
    assert_eq!(cc(&env), (true, false, false, false));

    // ediv #3, r0:r1, r2, r3 —— 0x1_0000_0007 / 3 = 0x5555_5557 余り 2。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 7);
    sem::r_set(&mut env.backend, 1, 1);
    put(&mut env, BASE, &[0x7b, 0x8f, 3, 0, 0, 0, 0x50, 0x52, 0x53]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0x5555_5557);
    assert_eq!(r(&env, 3), 2);
    assert_eq!(cc(&env), (false, false, false, false));

    // ediv #3, r0:r1(-7) —— 商 -2、剰余は被除数と同符号の -1。
    sem::r_set(&mut env.backend, 0, 0xffff_fff9);
    sem::r_set(&mut env.backend, 1, 0xffff_ffff);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0xffff_fffe);
    assert_eq!(r(&env, 3), 0xffff_ffff);
    assert_eq!(cc(&env), (true, false, false, false));

    // ediv #1, r0:r1(2^32) —— 商が longword に入らず V=1。
    sem::r_set(&mut env.backend, 0, 0);
    sem::r_set(&mut env.backend, 1, 1);
    put(
        &mut env,
        BASE + 0x20,
        &[0x7b, 0x8f, 1, 0, 0, 0, 0x50, 0x52, 0x53],
    );
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (false, true, true, false));
}

#[test]
fn ediv_div_zero_trap() {
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x7b, 0x8f, 0, 0, 0, 0, 0x50, 0x52, 0x53]);
    sem::r_set(&mut env.backend, 0, 1);
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::INT_DIV_ZERO));
}

#[test]
fn cmp_tst_flags() {
    // cmpl #5, #5 → Z=1。
    let env = exec1(&[0xd1, 0x8f, 5, 0, 0, 0, 0x8f, 5, 0, 0, 0]);
    assert_eq!(cc(&env), (false, true, false, false));

    // cmpl #1, #-1 —— 符号付きでは op1>op2（N=0）だが符号なしでは
    // op1<op2（C=1）。差の符号（0x8000_0002→N 誤判定）でなく真の
    // 比較結果。
    let env = exec1(&[0xd1, 0x8f, 1, 0, 0, 0, 0x8f, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(cc(&env), (false, false, false, true));

    // cmpl #0x7fffffff, #-1 —— 差は負の符号だが真の比較は N=0。
    let env = exec1(&[
        0xd1, 0x8f, 0xff, 0xff, 0xff, 0x7f, 0x8f, 0xff, 0xff, 0xff, 0xff,
    ]);
    assert_eq!(cc(&env), (false, false, false, true));

    // cmpl #-1, #1 —— N=1、符号なしは op1>op2 で C=0。
    let env = exec1(&[0xd1, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x8f, 1, 0, 0, 0]);
    assert_eq!(cc(&env), (true, false, false, false));

    // cmpb #0x80(-128), #0x7f —— 符号付きは小さい、符号なしは大きい。
    let env = exec1(&[0x91, 0x8f, 0x80, 0x8f, 0x7f]);
    assert_eq!(cc(&env), (true, false, false, false));

    // cmpb S^#5, r0 —— 短リテラル指定子（5>3 で N=0 C=0）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 3);
    put(&mut env, BASE, &[0x91, 0x05, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (false, false, false, false));

    // tstl #-1 → N=1、tstb #0 → Z=1。tst は C を 0 にする。
    let mut env = run_env(1);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    put(&mut env, BASE, &[0xd5, 0x8f, 0xff, 0xff, 0xff, 0xff]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (true, false, false, false));
    let env = exec1(&[0x95, 0x8f, 0x00]);
    assert_eq!(cc(&env), (false, true, false, false));
    let env = exec1(&[0xb5, 0x8f, 0x00, 0x80]);
    assert_eq!(cc(&env), (true, false, false, false));
}

#[test]
fn cvt_integer_widths() {
    // cvtbl #0x80(-128), r0 → 符号拡張 0xffffff80。
    let env = exec1(&[0x98, 0x8f, 0x80, 0x50]);
    assert_eq!(r(&env, 0), 0xffff_ff80);
    assert_eq!(cc(&env), (true, false, false, false));

    // cvtbw #0x80, r0 → 0xff80。
    let env = exec1(&[0x99, 0x8f, 0x80, 0x50]);
    assert_eq!(r(&env, 0) & 0xffff, 0xff80);
    assert_eq!(cc(&env), (true, false, false, false));

    // cvtwl #-1, r0 → 0xffffffff。
    let env = exec1(&[0x32, 0x8f, 0xff, 0xff, 0x50]);
    assert_eq!(r(&env, 0), 0xffff_ffff);
    assert_eq!(cc(&env), (true, false, false, false));

    // cvtlb #0x180, r0 → 収まらず V=1、結果は下位 0x80。
    let env = exec1(&[0xf6, 0x8f, 0x80, 0x01, 0, 0, 0x50]);
    assert_eq!(r(&env, 0) & 0xff, 0x80);
    assert_eq!(cc(&env), (true, false, true, false));

    // cvtwb #0x7f00, r0 → V=1、結果 0。
    let env = exec1(&[0x33, 0x8f, 0, 0x7f, 0x50]);
    assert_eq!(r(&env, 0) & 0xff, 0);
    assert_eq!(cc(&env), (false, true, true, false));

    // cvtlw #0x18000, r0 → V=1、結果 0x8000。
    let env = exec1(&[0xf7, 0x8f, 0, 0x80, 0x01, 0, 0x50]);
    assert_eq!(r(&env, 0) & 0xffff, 0x8000);
    assert_eq!(cc(&env), (true, false, true, false));

    // cvtlb #0x7f, r0 → 収まる: V=0。
    let env = exec1(&[0xf6, 0x8f, 0x7f, 0, 0, 0, 0x50]);
    assert_eq!(r(&env, 0) & 0xff, 0x7f);
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn arith_with_specifier_mix() {
    // addl3 4(r2)[r1], #7, r3 —— index + 変位基底の読み出し。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x300, &39u32.to_le_bytes());
    sem::r_set(&mut env.backend, 1, 0x20);
    sem::r_set(&mut env.backend, 2, (BASE + 0x300 - 4 - 0x80) as u32);
    put(
        &mut env,
        BASE,
        &[0xc1, 0x41, 0xa2, 0x04, 0x8f, 7, 0, 0, 0, 0x53],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 3), 46);

    // divb2 (r0)+, r1 —— 除数の自動増。（r0 はバイト刻み +1）
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[3]);
    sem::r_set(&mut env.backend, 0, (BASE + 0x200) as u32);
    sem::r_set(&mut env.backend, 1, 10);
    put(&mut env, BASE, &[0x86, 0x80, 0x51]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1) & 0xff, 3);
    assert_eq!(r(&env, 0), (BASE + 0x201) as u32);

    // mnegw -(r0), r1 —— 書き込み側の自動減（word 刻み -2）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, (BASE + 0x204) as u32);
    put(&mut env, BASE, &[0xae, 0x8f, 5, 0, 0x70]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), (BASE + 0x202) as u32);
    let mut b = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(BASE + 0x202), &mut b, Access::DATA_LE)
        .unwrap();
    assert_eq!(u16::from_le_bytes(b), 0xfffb);
}

#[test]
fn subset_insn_goes_unimpl_hook() {
    // 機能集合にない命令（ka660 の movo）は補完経路のフックに渡る。
    struct Hook(u64, u64);
    impl TrapHandler for Hook {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
        fn handle_unimpl(&mut self, _env: &mut BareEnv, pc: u64, word: u64) -> TrapOutcome {
            self.0 = pc;
            self.1 = word;
            TrapOutcome::Unimplemented
        }
    }
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x7d, 0x50, 0x51]); // movo r0, r1
    env.pc = BASE;
    let ka660 = model_feats("ka660");
    let mut sys = Hook(0, 0);
    let res = run::step(&mut env, &mut sys, ka660);
    assert_eq!(sys.0, BASE);
    assert_eq!(sys.1, 0x7dfd);
    assert!(matches!(res, Err(Outcome::Unimplemented { .. })));
    // フル VAX モデルなら movo は解読できて意味論まで来る。
    // .o のレジスタ指定子は Rn:Rn+3 —— movo r0,r1 は r0..r3 を
    // r1..r4 に運ぶ（REI では引数領域と重なる正当な使い方）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x7d, 0x50, 0x51]);
    sem::r_set(&mut env.backend, 0, 0x1111_2222);
    sem::r_set(&mut env.backend, 1, 0x3333_4444);
    sem::r_set(&mut env.backend, 2, 0x5555_6666);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), 0x1111_2222);
    assert_eq!(r(&env, 2), 0x3333_4444);
    assert_eq!(r(&env, 3), 0x5555_6666);
    assert_eq!(r(&env, 4), 0);
    assert_eq!(env.pc, BASE + 4);
}

// ---- VX6: 論理・ビット・bitfield・shift/rot・分岐複合 ----

#[test]
fn new_bit_insns_decode() {
    assert_eq!(dec1(0x78), Some(Insn::Ashl));
    assert_eq!(dec1(0x79), Some(Insn::Ashq));
    assert_eq!(dec1(0x88), Some(Insn::Bisb2));
    assert_eq!(dec1(0x89), Some(Insn::Bisb3));
    assert_eq!(dec1(0x8a), Some(Insn::Bicb2));
    assert_eq!(dec1(0x8b), Some(Insn::Bicb3));
    assert_eq!(dec1(0x8c), Some(Insn::Xorb2));
    assert_eq!(dec1(0x8d), Some(Insn::Xorb3));
    assert_eq!(dec1(0x93), Some(Insn::Bitb));
    assert_eq!(dec1(0x9d), Some(Insn::Acbb));
    assert_eq!(dec1(0xa8), Some(Insn::Bisw2));
    assert_eq!(dec1(0xa9), Some(Insn::Bisw3));
    assert_eq!(dec1(0xaa), Some(Insn::Bicw2));
    assert_eq!(dec1(0xab), Some(Insn::Bicw3));
    assert_eq!(dec1(0xac), Some(Insn::Xorw2));
    assert_eq!(dec1(0xad), Some(Insn::Xorw3));
    assert_eq!(dec1(0xb3), Some(Insn::Bitw));
    assert_eq!(dec1(0xc9), Some(Insn::Bisl3));
    assert_eq!(dec1(0xcb), Some(Insn::Bicl3));
    assert_eq!(dec1(0xcd), Some(Insn::Xorl3));
    assert_eq!(dec1(0xd3), Some(Insn::Bitl));
    assert_eq!(dec1(0x3d), Some(Insn::Acbw));
    assert_eq!(dec1(0xe3), Some(Insn::Bbcs));
    assert_eq!(dec1(0xe4), Some(Insn::Bbsc));
    assert_eq!(dec1(0xe6), Some(Insn::Bbssi));
    assert_eq!(dec1(0xe7), Some(Insn::Bbcci));
    assert_eq!(insn_ops(Insn::Ashl), &[RB, RL, WL]);
    assert_eq!(insn_ops(Insn::Bisl3), &[RL, RL, WL]);
    assert_eq!(insn_ops(Insn::Bitl), &[RL, RL]);
    assert_eq!(insn_ops(Insn::Acbb), &[RB, RB, MB, BW]);
    assert_eq!(insn_ops(Insn::Bbssi), &[RL, VB, BB]);
}

#[test]
fn bis_bic_xor_results_and_cc() {
    // bisl2 #0x0f0f, r0 —— OR。C は保存（立てておく）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0x00f0_0000);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    put(&mut env, BASE, &[0xc8, 0x8f, 0x0f, 0x0f, 0, 0, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0x00f0_0f0f);
    assert_eq!(cc(&env), (false, false, false, true));

    // bisl3 #0xff00, #0x00ff, r1 → 0xffff。
    let env = exec1(&[0xc9, 0x8f, 0, 0xff, 0, 0, 0x8f, 0xff, 0, 0, 0, 0x51]);
    assert_eq!(r(&env, 1), 0x0000_ffff);
    assert_eq!(cc(&env), (false, false, false, false));

    // bicl2 #0xffff, r0 —— AND NOT（上位保存、下位がクリア）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0xaabb_ccdd);
    put(&mut env, BASE, &[0xca, 0x8f, 0xff, 0xff, 0, 0, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xaabb_0000);
    assert_eq!(cc(&env), (true, false, false, false)); // 符号ビットが立つ

    // bicw3 #0x00ff, #0xabcd, r1 → 0xab00。
    let env = exec1(&[0xab, 0x8f, 0xff, 0, 0x8f, 0xcd, 0xab, 0x51]);
    assert_eq!(r(&env, 1) & 0xffff, 0xab00);

    // xorl2 #-1, r0 —— 1 の補数。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0x1234_5678);
    put(&mut env, BASE, &[0xcc, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xedcb_a987);
    assert_eq!(cc(&env), (true, false, false, false));

    // xorb3 #0xf0, #0x3c, r1 → 0xcc（書き込み先は下位バイトのみ）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 1, 0xdead_be00);
    put(&mut env, BASE, &[0x8d, 0x8f, 0xf0, 0x8f, 0x3c, 0x51]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), 0xdead_becc);
    assert_eq!(cc(&env), (true, false, false, false));

    // bisb2 S^#1, r0 —— 短リテラル mask。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0x40);
    put(&mut env, BASE, &[0x88, 0x01, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xff, 0x41);
}

#[test]
fn bit_flags_only() {
    // bitl #0x0f, #0xf0 —— 積は 0: Z=1 N=0。オペランドは変えない。
    let env = exec1(&[0xd3, 0x8f, 0x0f, 0, 0, 0, 0x8f, 0xf0, 0, 0, 0]);
    assert_eq!(cc(&env), (false, true, false, false));

    // bitl #0x8000_0000, #-1 —— 積の符号で N=1。
    let env = exec1(&[0xd3, 0x8f, 0, 0, 0, 0x80, 0x8f, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(cc(&env), (true, false, false, false));

    // bitb #0x01, r0 —— 積が非零: Z=0。C は保存。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 3);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    put(&mut env, BASE, &[0x93, 0x8f, 0x01, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 3);
    assert_eq!(cc(&env), (false, false, false, true));
}

#[test]
fn ash_shifts_and_overflow() {
    // ashl #4, #0x123, r0 → 0x1230。
    let env = exec1(&[0x78, 0x8f, 4, 0x8f, 0x23, 0x01, 0, 0, 0x50]);
    assert_eq!(r(&env, 0), 0x1230);
    assert_eq!(cc(&env), (false, false, false, false));

    // ashl #-4, #0x8000_0000, r0 → 右算術 0xf800_0000（N=1）。
    let env = exec1(&[0x78, 0x8f, 0xfc, 0x8f, 0, 0, 0, 0x80, 0x50]);
    assert_eq!(r(&env, 0), 0xf800_0000);
    assert_eq!(cc(&env), (true, false, false, false));

    // ashl #31, #-1, r0 → 0x8000_0000。符号位置に入るビットは
    // すべて 1（= 元の符号）なので V=0。
    let env = exec1(&[0x78, 0x8f, 31, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x50]);
    assert_eq!(r(&env, 0), 0x8000_0000);
    assert_eq!(cc(&env), (true, false, false, false));

    // ashl #1, #0x4000_0000, r0 → 0x8000_0000、V=1（正→負）。
    let env = exec1(&[0x78, 0x8f, 1, 0x8f, 0, 0, 0, 0x40, 0x50]);
    assert_eq!(r(&env, 0), 0x8000_0000);
    assert_eq!(cc(&env), (true, false, true, false));

    // ashl #33, #-1, r0 → カウント > 幅で 0。src≠0 なので
    // 符号位置に入るビットが元の符号と異なり V=1。
    let env = exec1(&[0x78, 0x8f, 33, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x50]);
    assert_eq!(r(&env, 0), 0);
    assert_eq!(cc(&env), (false, true, true, false));

    // ashl #-31, #1, r0 → 符号複製（正は 0）。
    let env = exec1(&[0x78, 0x8f, 0xe1, 0x8f, 1, 0, 0, 0, 0x50]);
    assert_eq!(r(&env, 0), 0);
    // ashl #-31, #-1, r0 → 0xffff_ffff。
    let env = exec1(&[0x78, 0x8f, 0xe1, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x50]);
    assert_eq!(r(&env, 0), 0xffff_ffff);

    // ashq #8, r0:r1 → r2:r3。0x007f00ff_aabbccdd << 8（収まるので
    // V=0、上位レジスタへ桁上がりする）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0xaabb_ccdd);
    sem::r_set(&mut env.backend, 1, 0x007f_00ff);
    put(&mut env, BASE, &[0x79, 0x8f, 8, 0x50, 0x52]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!((r(&env, 2), r(&env, 3)), (0xbbcc_dd00, 0x7f00_ffaa));
    assert_eq!(cc(&env), (false, false, false, false));

    // ashq #40, r0:r1 → 上桁があふれて V=1（結果は切り詰め）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 1);
    sem::r_set(&mut env.backend, 1, 1);
    put(&mut env, BASE, &[0x79, 0x8f, 40, 0x50, 0x52]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!((r(&env, 2), r(&env, 3)), (0, 0x0100));
    assert_eq!(cc(&env), (false, false, true, false));

    // ashq #-40, 同 → 0x1_1000（正の値の右シフト）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 1);
    sem::r_set(&mut env.backend, 1, 0x0110_0000);
    put(&mut env, BASE, &[0x79, 0x8f, 0xd8, 0x50, 0x52]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!((r(&env, 2), r(&env, 3)), (0x1_1000, 0));
    // ashq #65 → 0、src≠0 なので V=1。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0xffff_ffff);
    put(&mut env, BASE, &[0x79, 0x8f, 65, 0x50, 0x52]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!((r(&env, 2), r(&env, 3)), (0, 0));
    assert_eq!(cc(&env), (false, true, true, false));

    // rotl #4, #0x1234_5678, r0 → 0x2345_6781。C 保存。
    let mut env = run_env(1);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    put(
        &mut env,
        BASE,
        &[0x9c, 0x8f, 4, 0x8f, 0x78, 0x56, 0x34, 0x12, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0x2345_6781);
    assert_eq!(cc(&env), (false, false, false, true));

    // rotl #-4（右回転）→ 0x8123_4567。rotl #0 → src の写し。
    let env = exec1(&[0x9c, 0x8f, 0xfc, 0x8f, 0x78, 0x56, 0x34, 0x12, 0x50]);
    assert_eq!(r(&env, 0), 0x8123_4567);
    let env = exec1(&[0x9c, 0x8f, 0, 0x8f, 0x78, 0x56, 0x34, 0x12, 0x50]);
    assert_eq!(r(&env, 0), 0x1234_5678);
}

#[test]
fn ash_overflow_traps_with_iv() {
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[0x78, 0x8f, 1, 0x8f, 0, 0, 0, 0x40, 0x50, 0x01],
    );
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::IV));
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::INT_OVERFLOW));
    assert_eq!(r(&env, 0), 0x8000_0000);
}

#[test]
fn extv_extzv_register_and_memory() {
    // extv #8, #8, r2, r0 —— r2 の bits<15:8> を符号拡張。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0x1234_8078);
    put(
        &mut env,
        BASE,
        &[0xee, 0x8f, 8, 0, 0, 0, 0x8f, 8, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xffff_ff80);
    assert_eq!(cc(&env), (true, false, false, false));

    // extzv 同条件 → ゼロ拡張 0x80。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0x1234_8078);
    put(
        &mut env,
        BASE,
        &[0xef, 0x8f, 8, 0, 0, 0, 0x8f, 8, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0x80);
    assert_eq!(cc(&env), (false, false, false, false)); // ゼロ拡張なので N=0

    // レジスタ越境: extzv #20, #20, r2 → r2<31:20> に r3<7:0> を
    // 連結した 20 ビット。r2=0xfff0_0000, r3=0xa5 → 0xa5fff。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0xfff0_0000);
    sem::r_set(&mut env.backend, 3, 0xa5);
    put(
        &mut env,
        BASE,
        &[0xef, 0x8f, 20, 0, 0, 0, 0x8f, 20, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0x000a_5fff);

    // メモリ基底・負の位置: フィールドは base-1 の bit4 から。
    // bytes[..]=0xBA, [..+1]=0xDC → (0xdcba >> 4) & 0xff = 0xcb。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0xba, 0xdc]);
    put(
        &mut env,
        BASE,
        &[
            0xee, 0x8f, 0xfc, 0xff, 0xff, 0xff, 0x8f, 8, 0x9f, 0x01, 0x02, 0x01, 0x00, 0x50,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    // 0xcb を符号拡張 → 0xffff_ffcb。base は BASE+0x201、pos=-4。
    assert_eq!(r(&env, 0), 0xffff_ffcb);

    // size=32 のメモリフィールド（pos=0）→  longword まるごと。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &0xdead_beefu32.to_le_bytes());
    put(
        &mut env,
        BASE,
        &[
            0xef, 0x8f, 0, 0, 0, 0, 0x8f, 32, 0x9f, 0x00, 0x02, 0x01, 0x00, 0x50,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xdead_beef);

    // size=0 → dst=0 Z=1（pos が不正でも fault しない）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 1);
    put(
        &mut env,
        BASE,
        &[0xef, 0x8f, 99, 0, 0, 0, 0x8f, 0, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn insv_field_write() {
    // insv #0xabc, #8, #12, r2 —— r2<19:8> に挿入。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0xdead_beef);
    put(
        &mut env,
        BASE,
        &[
            0xf0, 0x8f, 0xbc, 0x0a, 0, 0, 0x8f, 8, 0, 0, 0, 0x8f, 12, 0x52,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0xdeaa_bcef);

    // レジスタ越境: insv #0xfffff, #20, #20, r2 —— r2<31:20> と
    // r3<7:0> にまたがる。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[
            0xf0, 0x8f, 0xff, 0xff, 0x0f, 0, 0x8f, 20, 0, 0, 0, 0x8f, 20, 0x52,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0xfff0_0000);
    assert_eq!(r(&env, 3), 0x0000_00ff);

    // メモリ基底: insv #0b101, #13, #3, @#addr —— 2 バイトにまたがる。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0, 0]);
    put(
        &mut env,
        BASE,
        &[
            0xf0, 0x8f, 5, 0, 0, 0, 0x8f, 13, 0, 0, 0, 0x8f, 3, 0x9f, 0x00, 0x02, 0x01, 0x00,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    // bits 13-15 → 上位バイト（base+1）の bit5-7 に 0b101。
    let mut b = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(BASE + 0x200), &mut b, Access::DATA_LE)
        .unwrap();
    assert_eq!(b, [0x00, 0xa0]);

    // size=0 は何も書かない。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0xaa]);
    put(
        &mut env,
        BASE,
        &[
            0xf0, 0x8f, 1, 0, 0, 0, 0x8f, 0, 0, 0, 0, 0x8f, 0, 0x9f, 0x00, 0x02, 0x01, 0x00,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    let mut b = [0u8; 1];
    env.backend
        .mem
        .read(VirtAddr(BASE + 0x200), &mut b, Access::DATA_LE)
        .unwrap();
    assert_eq!(b, [0xaa]);
}

#[test]
fn field_reserved_operand_faults() {
    struct Rec(Vec<u32>);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0.push(code);
            TrapOutcome::Unimplemented
        }
    }
    let mut env = run_env(1);
    let mut sys = Rec(Vec::new());
    // extv #32, #4, r2, r0 —— レジスタ基底で pos>31 → fault 0x18。
    sem::r_set(&mut env.backend, 2, 0x1234);
    put(
        &mut env,
        BASE,
        &[0xee, 0x8f, 32, 0, 0, 0, 0x8f, 4, 0x52, 0x50],
    );
    env.pc = BASE;
    let _ = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(sys.0, [sem::scb::RESERVED_OPERAND]);
    // フィールド・dst は不変。
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 2), 0x1234);

    // extv #0, #33, r2, r0 —— size>32 も fault。
    put(
        &mut env,
        BASE + 0x10,
        &[0xee, 0x8f, 0, 0, 0, 0, 0x8f, 33, 0x52, 0x50],
    );
    env.pc = BASE + 0x10;
    let _ = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(sys.0.last(), Some(&sem::scb::RESERVED_OPERAND));

    // メモリ基底なら pos>31 は fault にならない（base+5 の bit0-3）。
    put(&mut env, BASE + 0x305, &[0x05]);
    put(
        &mut env,
        BASE + 0x20,
        &[
            0xef, 0x8f, 40, 0, 0, 0, 0x8f, 4, 0x9f, 0x00, 0x03, 0x01, 0x00, 0x50,
        ],
    );
    env.pc = BASE + 0x20;
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(r(&env, 0), 5);

    // bbs #32, r2, disp —— レジスタ基底で pos>31 → fault。
    put(
        &mut env,
        BASE + 0x30,
        &[0xe0, 0x8f, 32, 0, 0, 0, 0x52, 0x01],
    );
    env.pc = BASE + 0x30;
    let _ = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(sys.0.last(), Some(&sem::scb::RESERVED_OPERAND));
}

#[test]
fn ffs_ffc_find_first() {
    // ffs #0, #16, @#addr, r0 —— 0x2000 の先頭 set ビットは 13。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0x00, 0x20]);
    put(
        &mut env,
        BASE,
        &[
            0xea, 0x8f, 0, 0, 0, 0, 0x8f, 16, 0x9f, 0x00, 0x02, 0x01, 0x00, 0x50,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 13);
    assert_eq!(cc(&env), (false, false, false, false));

    // ffc 同条件 → 先頭の clear ビットは 0。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0x00, 0x20]);
    put(
        &mut env,
        BASE,
        &[
            0xeb, 0x8f, 0, 0, 0, 0, 0x8f, 16, 0x9f, 0x00, 0x02, 0x01, 0x00, 0x50,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0);
    assert_eq!(cc(&env), (false, false, false, false));

    // ffs #4, #4, r2, r0 —— r2=0b1010_0000 → bits4-7 = 0b1010 →
    // 最初の set はフィールド内 1 ビット目 → findpos=5。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0xa0);
    put(
        &mut env,
        BASE,
        &[0xea, 0x8f, 4, 0, 0, 0, 0x8f, 4, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 5);

    // 未発見: ffs #0, #8, r2 → r2=0 → findpos=0+8=8、Z=1。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[0xea, 0x8f, 0, 0, 0, 0, 0x8f, 8, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 8);
    assert_eq!(cc(&env), (false, true, false, false));

    // ffc で全ビット set → 未発見: findpos=startpos+size、Z=1。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0xff);
    put(
        &mut env,
        BASE,
        &[0xeb, 0x8f, 0, 0, 0, 0, 0x8f, 8, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 8);
    assert_eq!(cc(&env), (false, true, false, false));

    // size=0 → findpos=startpos、Z=1。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[0xea, 0x8f, 7, 0, 0, 0, 0x8f, 0, 0x52, 0x50],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 7);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn cmpv_cmpzv_flags() {
    // cmpv #4, #4, r2, #15 —— フィールド 0b0101(=5) vs 15。
    // N = field < src、C = 符号なしでも小さい。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0x50);
    put(
        &mut env,
        BASE,
        &[0xec, 0x8f, 4, 0, 0, 0, 0x8f, 4, 0x52, 0x8f, 15, 0, 0, 0],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (true, false, false, true));

    // cmpv で負のフィールド: 0b1110 → -2。vs #0 → N=1、
    // 符号なし比較は field(0xffff_fffe) > src で C=0。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0xe0);
    put(
        &mut env,
        BASE,
        &[0xec, 0x8f, 4, 0, 0, 0, 0x8f, 4, 0x52, 0x8f, 0, 0, 0, 0],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (true, false, false, false));

    // cmpzv 同条件 → 14 vs 0 → N=0、符号なし大きい C=0。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0xe0);
    put(
        &mut env,
        BASE,
        &[0xed, 0x8f, 4, 0, 0, 0, 0x8f, 4, 0x52, 0x8f, 0, 0, 0, 0],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn bb_branch_and_modify() {
    // bbs #2, @#addr, +8 —— bit2=1 → 分岐。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0x04]);
    put(
        &mut env,
        BASE,
        &[0xe0, 0x8f, 2, 0, 0, 0, 0x9f, 0x00, 0x02, 0x01, 0x00, 8],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 12 + 8);

    // bbc #3 —— bit3=0 → 分岐。bit2=1 に対しては落ちる。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0x04]);
    put(
        &mut env,
        BASE,
        &[0xe1, 0x8f, 3, 0, 0, 0, 0x9f, 0x00, 0x02, 0x01, 0x00, 8],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 12 + 8);
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0x04]);
    put(
        &mut env,
        BASE,
        &[0xe1, 0x8f, 2, 0, 0, 0, 0x9f, 0x00, 0x02, 0x01, 0x00, 8],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 12); // 分岐しない

    // bbsc #1, r2, -4 —— bit1=1 → 分岐してクリア → r2=0（8 バイト命令）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0x02);
    put(&mut env, BASE, &[0xe4, 0x8f, 1, 0, 0, 0, 0x52, 0xfc]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0);
    assert_eq!(env.pc, BASE + 8 - 4);

    // bbcs #0, r2 —— bit0=0 → 分岐してセット → r2=1。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xe3, 0x8f, 0, 0, 0, 0, 0x52, 0x10]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 1);
    assert_eq!(env.pc, BASE + 8 + 0x10);

    // bbss #7, r2 —— bit7=0 → 分岐しないがセット → r2=0x80。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xe2, 0x8f, 7, 0, 0, 0, 0x52, 0x10]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0x80);
    assert_eq!(env.pc, BASE + 8);

    // bbcc #0, r2 —— bit0=0 → 分岐してクリア（変化なし）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xe5, 0x8f, 0, 0, 0, 0, 0x52, 0x10]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0);
    assert_eq!(env.pc, BASE + 8 + 0x10);

    // bbssi/bbcci —— 同じ動作（単一スレッド近似）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0x04);
    put(&mut env, BASE, &[0xe6, 0x8f, 2, 0, 0, 0, 0x52, 0x10]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0x04); // bit2 はすでに 1 → 分岐、再 set で不変
    assert_eq!(env.pc, BASE + 8 + 0x10);
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 2, 0x04);
    put(&mut env, BASE, &[0xe7, 0x8f, 2, 0, 0, 0, 0x52, 0x10]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0); // bit2 は set → 分岐しないが clear
    assert_eq!(env.pc, BASE + 8);

    // メモリ基底の modify: bbss #9, @#addr —— byte1 の bit1 を立てる。
    let mut env = run_env(1);
    put(&mut env, BASE + 0x200, &[0, 0]);
    put(
        &mut env,
        BASE,
        &[0xe2, 0x8f, 9, 0, 0, 0, 0x9f, 0x00, 0x02, 0x01, 0x00, 4],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    let mut b = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(BASE + 0x200), &mut b, Access::DATA_LE)
        .unwrap();
    assert_eq!(b, [0, 0x02]);
    assert_eq!(env.pc, BASE + 12); // bit9=0 → 分岐しない

    // blbs #3, +4 → 分岐。blbc #2 → 分岐。それぞれ逆は落ちる。
    let env = exec1(&[0xe8, 0x8f, 3, 0, 0, 0, 4]);
    assert_eq!(env.pc, BASE + 7 + 4);
    let env = exec1(&[0xe9, 0x8f, 2, 0, 0, 0, 4]);
    assert_eq!(env.pc, BASE + 7 + 4);
    let env = exec1(&[0xe8, 0x8f, 2, 0, 0, 0, 4]);
    assert_eq!(env.pc, BASE + 7);
    let env = exec1(&[0xe9, 0x8f, 3, 0, 0, 0, 4]);
    assert_eq!(env.pc, BASE + 7);
}

#[test]
fn case_dispatch_table() {
    // casel #5, #2, #7 —— tmp=3 ≤ 7 → displ[3] の語変位で分岐。
    // 命令は 16 バイト、表は BASE+16。displ[3] は BASE+22。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[0xcf, 0x8f, 5, 0, 0, 0, 0x8f, 2, 0, 0, 0, 0x8f, 7, 0, 0, 0],
    );
    put(&mut env, BASE + 22, &0x0020u16.to_le_bytes());
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 16 + 0x20);
    // tmp=3 < limit=7: N=1 C=1（符号・符号なしとも小さい）。
    assert_eq!(cc(&env), (true, false, false, true));

    // 範囲外: casel #100, #2, #7 —— tmp=98 > 7 → 表の直後へ
    // （命令終端 + 2 + 2*7 = BASE+32）。CC: N=0（98 は 7 より大）。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[0xcf, 0x8f, 100, 0, 0, 0, 0x8f, 2, 0, 0, 0, 0x8f, 7, 0, 0, 0],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 16 + 2 + 14);
    assert_eq!(cc(&env), (false, false, false, false));

    // caseb #3, #3, #0 —— tmp=0 ≤ 0 → displ[0]。Z=1 N=0 C=0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x8f, 0x8f, 3, 0x8f, 3, 0x8f, 0]);
    put(&mut env, BASE + 7, &0xfff0u16.to_le_bytes());
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 7 - 16);
    assert_eq!(cc(&env), (false, true, false, false));

    // casew #0, #0x8000, #0 —— tmp=0x8000（符号付き -32768）≤u 0 は
    // 偽 → 範囲外。N = tmp LSS limit（-32768 < 0 → 1）。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[0xaf, 0x8f, 0, 0, 0x8f, 0, 0x80, 0x8f, 0, 0],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 10 + 2);
    assert_eq!(cc(&env), (true, false, false, false));
}

#[test]
fn acb_loops() {
    // movl #0, r0; acbl #3, #1, r0, loop —— 4 回目で脱出。
    // acbl は 14 バイト（1+5+5+1+2）。戻り変位 = -14。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xd0, 0x8f, 0, 0, 0, 0, 0x50]);
    put(
        &mut env,
        BASE + 7,
        &[0xf1, 0x8f, 3, 0, 0, 0, 0x8f, 1, 0, 0, 0, 0x50, 0xf2, 0xff],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    for _ in 0..3 {
        step(&mut env).unwrap();
        assert_eq!(env.pc, BASE + 7);
    }
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 4);
    assert_eq!(env.pc, BASE + 21);
    assert_eq!(cc(&env), (false, false, false, false));

    // acbl #0, #-1, r0 —— 負の add は index>=limit で分岐。
    // r0=1 → 0 ≥ 0 → 分岐（Z=1）。r0=0 → -1 < 0 → 落ちる（N=1）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 1);
    put(
        &mut env,
        BASE,
        &[
            0xf1, 0x8f, 0, 0, 0, 0, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x50, 0x10, 0x00,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0);
    assert_eq!(env.pc, BASE + 14 + 0x10);
    assert_eq!(cc(&env), (false, true, false, false));

    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[
            0xf1, 0x8f, 0, 0, 0, 0, 0x8f, 0xff, 0xff, 0xff, 0xff, 0x50, 0x10, 0x00,
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xffff_ffff);
    assert_eq!(env.pc, BASE + 14);
    assert_eq!(cc(&env), (true, false, false, false));

    // acbb #10, #1, r0 —— byte の modify。V は byte のあふれ。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0x7f);
    put(&mut env, BASE, &[0x9d, 0x8f, 10, 0x8f, 1, 0x50, 0x05, 0x00]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xff, 0x80);
    assert_eq!(cc(&env), (true, false, true, false));
    // 0x80 = -128 ≥ limit ではない（add>0、-128 <= 10 → 分岐）。
    assert_eq!(env.pc, BASE + 8 + 5);

    // acbw #0x7fff, #1, r0 —— word でも同じ。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0x7fff);
    put(
        &mut env,
        BASE,
        &[0x3d, 0x8f, 0xff, 0x7f, 0x8f, 1, 0, 0x50, 0x05, 0x00],
    );
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) & 0xffff, 0x8000);
    assert_eq!(cc(&env), (true, false, true, false));
    assert_eq!(env.pc, BASE + 10 + 5);
}

#[test]
fn aob_sob_loop_branches() {
    // aoblss #5, r0, +8 —— r0=4 → 5 < 5 は偽、分岐しない Z=1
    // （aob 系は 8 バイト命令）。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 4);
    put(&mut env, BASE, &[0xf2, 0x8f, 5, 0, 0, 0, 0x50, 8]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 5);
    assert_eq!(env.pc, BASE + 8);
    // Z は index 自身が 0 のときだけ立つ（比較結果ではない）。
    assert_eq!(cc(&env), (false, false, false, false));

    // aobleq #5, r0 —— 5 <= 5 → 分岐。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 4);
    put(&mut env, BASE, &[0xf3, 0x8f, 5, 0, 0, 0, 0x50, 8]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8 + 8);

    // aoblss #5, r0 —— r0=7 → 8 < 5 偽、分岐しない。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 7);
    put(&mut env, BASE, &[0xf2, 0x8f, 5, 0, 0, 0, 0x50, 8]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 8);

    // sobgeq r0, -6 —— r0=3 → 2 ≥ 0 → 分岐。r0=0 → -1 → N=1 で落ちる。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 3);
    put(&mut env, BASE, &[0xf4, 0x50, 0xfa]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 2);
    assert_eq!(env.pc, BASE + 3 - 6);

    let mut env = run_env(1);
    put(&mut env, BASE, &[0xf4, 0x50, 0xfa]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xffff_ffff);
    assert_eq!(env.pc, BASE + 3);
    assert_eq!(cc(&env), (true, false, false, false));

    // sobgeq のあふれ: r0=0x8000_0000 → 0x7fff_ffff、V=1 で分岐。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 0x8000_0000);
    put(&mut env, BASE, &[0xf4, 0x50, 0xfa]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0x7fff_ffff);
    assert_eq!(cc(&env), (false, false, true, false));
    assert_eq!(env.pc, BASE + 3 - 6);

    // sobgtr r0 —— r0=1 → 0 > 0 偽 → 分岐しない。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 1);
    put(&mut env, BASE, &[0xf5, 0x50, 0xfa]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0);
    assert_eq!(env.pc, BASE + 3);
    assert_eq!(cc(&env), (false, true, false, false));

    // sobgtr r0 —— r0=2 → 1 > 0 → 分岐。
    let mut env = run_env(1);
    sem::r_set(&mut env.backend, 0, 2);
    put(&mut env, BASE, &[0xf5, 0x50, 0xfa]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 3 - 6);
}

// ---- VX7: キュー・文字列・マスク積み降ろし・CHM ----

/// スタックが使える環境（0x7fff_0000 の 1 ページを張る）。
fn run_env_stack() -> BareEnv {
    let mut env = run_env(1);
    env.backend
        .mem
        .map(
            VirtAddr(0x7fff_0000 - PAGE_SIZE),
            1,
            Perms(Perms::RW.0 | Perms::X.0),
        )
        .unwrap();
    env
}

/// @#addr の絶対アドレス指定子のバイト列。
fn abs(addr: u64, out: &mut Vec<u8>) {
    out.push(0x9f);
    out.extend_from_slice(&(addr as u32).to_le_bytes());
}

/// データ領域の先頭（8 バイト整列済み）。
const DATA: u64 = BASE + 0x800;

#[test]
fn new_vx7_insns_decode() {
    assert_eq!(dec1(0x0b), Some(Insn::Crc));
    assert_eq!(dec1(0x5c), Some(Insn::Insqhi));
    assert_eq!(dec1(0x5d), Some(Insn::Insqti));
    assert_eq!(dec1(0x5e), Some(Insn::Remqhi));
    assert_eq!(dec1(0x5f), Some(Insn::Remqti));
    assert_eq!(dec1(0x39), Some(Insn::Matchc));
    assert_eq!(dec1(0x2e), Some(Insn::Movtc));
    assert_eq!(dec1(0x2f), Some(Insn::Movtuc));
    assert_eq!(dec1(0xba), Some(Insn::Popr));
    assert_eq!(dec1(0xbb), Some(Insn::Pushr));
    assert_eq!(dec1(0xbc), Some(Insn::Chmk));
    assert_eq!(dec1(0xbd), Some(Insn::Chme));
    assert_eq!(dec1(0xbe), Some(Insn::Chms));
    assert_eq!(dec1(0xbf), Some(Insn::Chmu));
    assert_eq!(insn_ops(Insn::Insqhi), &[AB, AQ]);
    assert_eq!(insn_ops(Insn::Remqti), &[AQ, WL]);
    assert_eq!(insn_ops(Insn::Matchc), &[RW, AB, RW, AB]);
    assert_eq!(insn_ops(Insn::Movtc), &[RW, AB, RB, AB, RW, AB]);
    assert_eq!(insn_ops(Insn::Crc), &[AB, RL, RW, AB]);
    assert_eq!(insn_ops(Insn::Pushr), &[RW]);
    assert_eq!(insn_ops(Insn::Chmk), &[RW]);
    // 拡張文字列命令は string_ext で削れる。
    let no_str = DEFAULT_FEATS & !FEAT_STRING_EXT;
    assert_eq!(decode_model_ex(0x2e, 8, false, no_str), None);
    assert_eq!(decode_model_ex(0x39, 8, false, no_str), None);
    let no_crc = DEFAULT_FEATS & !FEAT_CRC;
    assert_eq!(decode_model_ex(0x0b, 8, false, no_crc), None);
    // movc3/movc5・キュー・CHM はカーネル集合なので削れない。
    assert!(decode_model_ex(0x28, 8, false, no_str).is_some());
    assert!(decode_model_ex(0x5c, 8, false, no_str).is_some());
    assert!(decode_model_ex(0xbc, 8, false, no_str).is_some());
}

#[test]
fn insque_remque_absolute() {
    // 絶対リンクキュー: 空ヘッダ H{H,H} へ A を挿入 → 1 項目の輪。
    let mut env = run_env(1);
    let (h, a, b) = (DATA, DATA + 0x10, DATA + 0x20);
    put(&mut env, h, &(h as u32).to_le_bytes());
    put(&mut env, h + 4, &(h as u32).to_le_bytes());
    // insque @#A, @#H
    let mut insn = vec![0x0e];
    abs(a, &mut insn);
    abs(h, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem32(&env, h), a as u32);
    assert_eq!(mem32(&env, h + 4), a as u32);
    assert_eq!(mem32(&env, a), h as u32);
    assert_eq!(mem32(&env, a + 4), h as u32);
    // Z=1（先頭項目）・N=V=C=0（succ==pred）。
    assert_eq!(cc(&env), (false, true, false, false));

    // insque @#B, @#A —— A の後ろへ。succ=H <u pred=A で C=1・N=1。
    let mut insn = vec![0x0e];
    abs(b, &mut insn);
    abs(a, &mut insn);
    put(&mut env, BASE + 0x10, &insn);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(mem32(&env, a), b as u32);
    assert_eq!(mem32(&env, b), h as u32);
    assert_eq!(mem32(&env, b + 4), a as u32);
    assert_eq!(mem32(&env, h + 4), b as u32);
    assert_eq!(cc(&env), (true, false, false, true));

    // remque @#B, r2 —— B を外す。輪は H<->A に戻る。
    let mut insn = vec![0x0f];
    abs(b, &mut insn);
    insn.push(0x52);
    put(&mut env, BASE + 0x20, &insn);
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), b as u32);
    assert_eq!(mem32(&env, a), h as u32);
    assert_eq!(mem32(&env, h + 4), a as u32);
    assert_eq!(cc(&env), (true, false, false, true));

    // 空ヘッダの remque —— V=1（外せる項目なし）・Z=1。
    put(&mut env, h, &(h as u32).to_le_bytes());
    put(&mut env, h + 4, &(h as u32).to_le_bytes());
    let mut insn = vec![0x0f];
    abs(h, &mut insn);
    insn.push(0x52);
    put(&mut env, BASE + 0x30, &insn);
    env.pc = BASE + 0x30;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), h as u32);
    assert_eq!(cc(&env), (false, true, true, false));
}

#[test]
fn interlocked_queue_self_relative() {
    // 自己相対キュー: 空ヘッダ {0,0}。insqhi で先頭へ、insqti で
    // 末尾へ、remqhi/remqti で順に外す。
    let mut env = run_env(1);
    let (h, e, f) = (DATA, DATA + 0x10, DATA + 0x20);
    put(&mut env, h, &0u32.to_le_bytes());
    put(&mut env, h + 4, &0u32.to_le_bytes());

    // insqhi @#E, @#H —— 空への挿入 → Z=1。
    let mut insn = vec![0x5c];
    abs(e, &mut insn);
    abs(h, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem32(&env, h), (e - h) as u32);
    assert_eq!(mem32(&env, h + 4), (e - h) as u32);
    assert_eq!(mem32(&env, e), (h.wrapping_sub(e)) as u32);
    assert_eq!(mem32(&env, e + 4), (h.wrapping_sub(e)) as u32);
    assert_eq!(cc(&env), (false, true, false, false));

    // insqti @#F, @#H —— 末尾へ → Z=0。
    let mut insn = vec![0x5d];
    abs(f, &mut insn);
    abs(h, &mut insn);
    put(&mut env, BASE + 0x10, &insn);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(mem32(&env, h), (e - h) as u32);
    assert_eq!(mem32(&env, h + 4), (f - h) as u32);
    assert_eq!(mem32(&env, e), (f - e) as u32);
    assert_eq!(mem32(&env, f), (h.wrapping_sub(f)) as u32);
    assert_eq!(mem32(&env, f + 4), (e.wrapping_sub(f)) as u32);
    assert_eq!(cc(&env), (false, false, false, false));

    // remqhi @#H, r2 —— E を外す → V=0・Z=0。
    let mut insn = vec![0x5e];
    abs(h, &mut insn);
    insn.push(0x52);
    put(&mut env, BASE + 0x20, &insn);
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), e as u32);
    assert_eq!(mem32(&env, h), (f - h) as u32);
    assert_eq!(mem32(&env, h + 4), (f - h) as u32);
    assert_eq!(mem32(&env, f), (h.wrapping_sub(f)) as u32);
    assert_eq!(cc(&env), (false, false, false, false));

    // remqti @#H, r2 —— 最後の 1 項目 F を外す → Z=1（空になった）。
    let mut insn = vec![0x5f];
    abs(h, &mut insn);
    insn.push(0x52);
    put(&mut env, BASE + 0x30, &insn);
    env.pc = BASE + 0x30;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), f as u32);
    assert_eq!(mem32(&env, h), 0);
    assert_eq!(mem32(&env, h + 4), 0);
    assert_eq!(cc(&env), (false, true, false, false));

    // 空キューの remqhi → V=1・Z=1、addr にはヘッダの位置。
    let mut insn = vec![0x5e];
    abs(h, &mut insn);
    insn.push(0x52);
    put(&mut env, BASE + 0x40, &insn);
    env.pc = BASE + 0x40;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), h as u32);
    assert_eq!(cc(&env), (false, true, true, false));
}

#[test]
fn queue_reserved_operands() {
    struct Rec(Vec<u32>);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0.push(code);
            TrapOutcome::Unimplemented
        }
    }
    let h = DATA;
    // 副インターロックが立っている → V=1・C=1 の失敗終了。
    let mut env = run_env(1);
    put(&mut env, h, &1u32.to_le_bytes());
    put(&mut env, h + 4, &0u32.to_le_bytes());
    let mut insn = vec![0x5c];
    abs(DATA + 0x10, &mut insn);
    abs(h, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (false, false, true, true));
    assert_eq!(mem32(&env, h), 1); // キューは不変。

    // ヘッダ語 <2:1> が残っている → 予約オペランド fault。
    let mut env = run_env(1);
    let mut sys = Rec(Vec::new());
    put(&mut env, h, &4u32.to_le_bytes());
    put(&mut env, h + 4, &0u32.to_le_bytes());
    let mut insn = vec![0x5c];
    abs(DATA + 0x10, &mut insn);
    abs(h, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    let r = run::step(&mut env, &mut sys, DEFAULT_FEATS);
    assert_eq!(sys.0, [sem::scb::RESERVED_OPERAND]);
    assert!(matches!(r, Err(Outcome::Unimplemented { .. })));

    // entry の非 8 バイト整列 → 予約オペランド fault。
    let mut env = run_env(1);
    let mut sys = Rec(Vec::new());
    put(&mut env, h, &0u32.to_le_bytes());
    put(&mut env, h + 4, &0u32.to_le_bytes());
    let mut insn = vec![0x5c];
    abs(DATA + 0x14, &mut insn);
    abs(h, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap_err();
    assert_eq!(sys.0, [sem::scb::RESERVED_OPERAND]);
}

#[test]
fn movc3_forward_and_regs() {
    // movc3 #4, @#src, @#dst —— dst<src なら前向き 1 バイトずつ、
    // FPD を見る。
    let mut env = run_env(1);
    let (s, d) = (DATA + 0x100, DATA);
    put(&mut env, s, &[0x11, 0x22, 0x33, 0x44]);
    let mut insn = vec![0x28, 0x04];
    abs(s, &mut insn);
    abs(d, &mut insn);
    let ilen = insn.len() as u64;
    put(&mut env, BASE, &insn);
    env.pc = BASE;

    // 1 ステップ = 1 バイト。中断状態は建築レジスタに見える。
    step(&mut env).unwrap();
    assert!(sem::fpd(&env.backend));
    assert_eq!(env.pc, BASE);
    assert_eq!(r(&env, 0), 3);
    assert_eq!(r(&env, 1), (s + 1) as u32);
    assert_eq!(r(&env, 3), (d + 1) as u32);
    step(&mut env).unwrap();
    step(&mut env).unwrap();
    step(&mut env).unwrap();
    assert!(!sem::fpd(&env.backend));
    assert_eq!(env.pc, BASE + ilen);
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), (s + 4) as u32);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), (d + 4) as u32);
    let mut out = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(d), &mut out, Access::DATA_LE)
        .unwrap();
    assert_eq!(out, [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn movc3_backward_overlap() {
    // dst が src 内部（src<dst<src+len）→ 末尾から複写して元の
    // バイト列が保存される。src=DATA, dst=DATA+2, len=4。
    let mut env = run_env(1);
    let s = DATA;
    let d = DATA + 2;
    put(&mut env, s, &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    let mut insn = vec![0x28, 0x04];
    abs(s, &mut insn);
    abs(d, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..4 {
        step(&mut env).unwrap();
    }
    let mut out = [0u8; 6];
    env.backend
        .mem
        .read(VirtAddr(s), &mut out, Access::DATA_LE)
        .unwrap();
    // 前向きなら壊れる並びが後ろ向きで守られる。
    assert_eq!(out, [0x10, 0x20, 0x10, 0x20, 0x30, 0x40]);
    assert_eq!(r(&env, 1), (s + 4) as u32);
    assert_eq!(r(&env, 3), (d + 4) as u32);
}

#[test]
fn movc5_fill_and_cc() {
    // movc5 #2, @#src, #0x2e, #5, @#dst —— 埋め草で伸ばす。
    let mut env = run_env(1);
    let (s, d) = (DATA, DATA + 0x100);
    put(&mut env, s, &[0xaa, 0xbb]);
    let mut insn = vec![0x2c, 0x02];
    abs(s, &mut insn);
    insn.push(0x2e); // fill='.'
    insn.push(0x05);
    abs(d, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..5 {
        step(&mut env).unwrap();
    }
    let mut out = [0u8; 5];
    env.backend
        .mem
        .read(VirtAddr(d), &mut out, Access::DATA_LE)
        .unwrap();
    assert_eq!(out, [0xaa, 0xbb, 0x2e, 0x2e, 0x2e]);
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), (s + 2) as u32);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), (d + 5) as u32);
    // srclen(2) < dstlen(5) → N=1・C=1。
    assert_eq!(cc(&env), (true, false, false, true));

    // src が長い場合: 余分は移らず r0 に残り数が返る。
    let mut env = run_env(1);
    put(&mut env, s, &[1, 2, 3, 4, 5, 6]);
    let mut insn = vec![0x2c, 0x06];
    abs(s, &mut insn);
    insn.push(0x00);
    insn.push(0x04);
    abs(d, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..4 {
        step(&mut env).unwrap();
    }
    assert_eq!(r(&env, 0), 2);
    assert_eq!(r(&env, 1), (s + 4) as u32);
    assert_eq!(r(&env, 3), (d + 4) as u32);
    // srclen(6) > dstlen(4) → N=0・Z=0・C=0。
    assert_eq!(cc(&env), (false, false, false, false));
    let mut out = [0u8; 4];
    env.backend
        .mem
        .read(VirtAddr(d), &mut out, Access::DATA_LE)
        .unwrap();
    assert_eq!(out, [1, 2, 3, 4]);
}

#[test]
fn cmpc3_and_cmpc5() {
    // cmpc3 #3, @#a, @#b —— 等しい → Z=1、r0-r3 は終端位置。
    let mut env = run_env(1);
    let (a, b) = (DATA, DATA + 0x40);
    put(&mut env, a, &[0x61, 0x62, 0x63]);
    put(&mut env, b, &[0x61, 0x62, 0x63]);
    let mut insn = vec![0x29, 0x03];
    abs(a, &mut insn);
    abs(b, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..3 {
        step(&mut env).unwrap();
    }
    assert_eq!(cc(&env), (false, true, false, false));
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), (a + 3) as u32);
    assert_eq!(r(&env, 3), (b + 3) as u32);

    // 不一致で止まる: "abc" vs "abd...": 3 バイト目で 'c'<'d'。
    let mut env = run_env(1);
    put(&mut env, a, &[0x61, 0x62, 0x63]);
    put(&mut env, b, &[0x61, 0x62, 0x7a]);
    let mut insn = vec![0x29, 0x03];
    abs(a, &mut insn);
    abs(b, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..3 {
        step(&mut env).unwrap();
    }
    // r0=残り（終端バイトを含む）=1、r1/r3=不一致バイトの位置。
    assert_eq!(r(&env, 0), 1);
    assert_eq!(r(&env, 1), (a + 2) as u32);
    assert_eq!(r(&env, 2), 1);
    assert_eq!(r(&env, 3), (b + 2) as u32);
    assert_eq!(cc(&env), (true, false, false, true));

    // cmpc5 #0x20, #2, @#a, #4, @#b —— "ab" vs "ab  ": fill で
    // 拡張して等しい → Z=1。
    let mut env = run_env(1);
    put(&mut env, a, &[0x61, 0x62]);
    put(&mut env, b, &[0x61, 0x62, 0x20, 0x20]);
    let mut insn = vec![0x2d, 0x20, 0x02];
    abs(a, &mut insn);
    insn.push(0x04);
    abs(b, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..4 {
        step(&mut env).unwrap();
    }
    assert_eq!(cc(&env), (false, true, false, false));
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 2), 0);

    // cmpc5: "ab" vs "abc!" —— fill 0x20 より 'c' が大きいので
    // 短い側が小さい判定（第 1 項 = fill 側の比較で N=0・C=1? ——
    // fill(0x20) < 'c'(0x63) → N=0・C=1）。
    let mut env = run_env(1);
    put(&mut env, a, &[0x61, 0x62]);
    put(&mut env, b, &[0x61, 0x62, 0x63, 0x21]);
    let mut insn = vec![0x2d, 0x20, 0x02];
    abs(a, &mut insn);
    insn.push(0x04);
    abs(b, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..3 {
        step(&mut env).unwrap();
    }
    // 3 バイト目: fill(0x20) vs 'c'(0x63) → 第 1 項が小さい。
    // r2 は終了バイトを含む残り（位置 2 から 4 バイト中 2 個）。
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 2), 2);
    assert_eq!(r(&env, 3), (b + 2) as u32);
    assert_eq!(cc(&env), (true, false, false, true));
}

#[test]
fn locc_skpc_scanc_spanc() {
    let s = DATA;
    // locc #'c', #5, @#s —— 3 バイト目で一致: r0=3（含む）・
    // r1=その位置・Z=0。
    let mut env = run_env(1);
    put(&mut env, s, b"abcde");
    let mut insn = vec![0x3a, 0x8f, 0x63, 0x05];
    abs(s, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..3 {
        step(&mut env).unwrap();
    }
    assert_eq!(r(&env, 0), 3);
    assert_eq!(r(&env, 1), (s + 2) as u32);
    assert_eq!(cc(&env), (false, false, false, false));

    // 見つからない → r0=0・r1=1 つ先・Z=1。
    let mut env = run_env(1);
    put(&mut env, s, b"abcde");
    let mut insn = vec![0x3a, 0x8f, 0x7a, 0x05];
    abs(s, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..5 {
        step(&mut env).unwrap();
    }
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), (s + 5) as u32);
    assert_eq!(cc(&env), (false, true, false, false));

    // skpc #'a', #3, @#s —— "aab": 3 バイト目が 'a' でない。
    let mut env = run_env(1);
    put(&mut env, s, b"aabde");
    let mut insn = vec![0x3b, 0x8f, 0x61, 0x03];
    abs(s, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..3 {
        step(&mut env).unwrap();
    }
    assert_eq!(r(&env, 0), 1);
    assert_eq!(r(&env, 1), (s + 2) as u32);
    assert_eq!(cc(&env), (false, false, false, false));

    // scanc #4, @#s, @#tbl, #0x01 —— 表に立つ文字まで走査。
    // 表: 'c' と 'e' に 1 を立てる。
    let mut env = run_env(1);
    let t = DATA + 0x200;
    put(&mut env, s, b"acde");
    put(&mut env, t + 0x63, &[1]);
    put(&mut env, t + 0x65, &[1]);
    let mut insn = vec![0x2a, 0x04];
    abs(s, &mut insn);
    abs(t, &mut insn);
    insn.push(0x01);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..2 {
        step(&mut env).unwrap();
    }
    assert_eq!(r(&env, 0), 3);
    assert_eq!(r(&env, 1), (s + 1) as u32);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), t as u32);
    assert_eq!(cc(&env), (false, false, false, false));

    // spanc: 表に立つ間は読み進める（空白のスパン）。
    let mut env = run_env(1);
    put(&mut env, s, b"  ab");
    put(&mut env, t + 0x20, &[1]);
    let mut insn = vec![0x2b, 0x04];
    abs(s, &mut insn);
    abs(t, &mut insn);
    insn.push(0x01);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..3 {
        step(&mut env).unwrap();
    }
    assert_eq!(r(&env, 0), 2);
    assert_eq!(r(&env, 1), (s + 2) as u32);
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn matchc_search() {
    // matchc #2, @#obj, #7, @#src —— "de" in "abcdefg": 一致で
    // r0=0・r1=obj 終端・r2=一致末尾以降の残り・r3=一致末尾の 1 つ先。
    let mut env = run_env(1);
    let (o, s) = (DATA + 0x100, DATA);
    put(&mut env, o, b"de");
    put(&mut env, s, b"abcdefg");
    let mut insn = vec![0x39, 0x02];
    abs(o, &mut insn);
    insn.push(0x07);
    abs(s, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    // 1 反復 = 1 比較 —— 十分な回数まわす。
    for _ in 0..16 {
        step(&mut env).unwrap();
        if !sem::fpd(&env.backend) {
            break;
        }
    }
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), (o + 2) as u32);
    assert_eq!(r(&env, 2), 2);
    assert_eq!(r(&env, 3), (s + 5) as u32);
    assert_eq!(cc(&env), (false, true, false, false));

    // 見つからない → r0=objlen・r1=objaddr・r2=0・r3=src 終端。
    let mut env = run_env(1);
    put(&mut env, o, b"zz");
    let mut insn = vec![0x39, 0x02];
    abs(o, &mut insn);
    insn.push(0x07);
    abs(s, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..16 {
        step(&mut env).unwrap();
        if !sem::fpd(&env.backend) {
            break;
        }
    }
    assert_eq!(r(&env, 0), 2);
    assert_eq!(r(&env, 1), o as u32);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), (s + 7) as u32);
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn movtc_movtuc() {
    // movtc #3, @#src, #0x2e, @#tbl, #5, @#dst —— 表で大文字化して
    // 残りを '.' で埋める。
    let mut env = run_env(1);
    let (s, t, d) = (DATA, DATA + 0x200, DATA + 0x100);
    put(&mut env, s, b"abc");
    for i in 0..256u32 {
        let u = if (0x61..=0x7a).contains(&(i as u8)) {
            i as u8 - 0x20
        } else {
            i as u8
        };
        put(&mut env, t + u64::from(i), &[u]);
    }
    let mut insn = vec![0x2e, 0x03];
    abs(s, &mut insn);
    insn.push(0x2e);
    abs(t, &mut insn);
    insn.push(0x05);
    abs(d, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..5 {
        step(&mut env).unwrap();
    }
    let mut out = [0u8; 5];
    env.backend
        .mem
        .read(VirtAddr(d), &mut out, Access::DATA_LE)
        .unwrap();
    assert_eq!(&out, b"ABC..");
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), (s + 3) as u32);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), t as u32);
    assert_eq!(r(&env, 4), 0);
    assert_eq!(r(&env, 5), (d + 5) as u32);
    assert_eq!(cc(&env), (true, false, false, true));

    // movtuc #5, @#src, #0x00, @#tbl, #5, @#dst —— 表で 0 に写る
    // バイト（'!' 位置に 0 を置いた表）で止まる。
    let mut env = run_env(1);
    put(&mut env, s, b"ab!cd");
    for i in 0..256u32 {
        put(&mut env, t + u64::from(i), &[i as u8]);
    }
    put(&mut env, t + 0x21, &[0]); // '!' -> 0 = esc
    let mut insn = vec![0x2f, 0x05];
    abs(s, &mut insn);
    insn.push(0x00);
    abs(t, &mut insn);
    insn.push(0x05);
    abs(d, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..5 {
        step(&mut env).unwrap();
        if !sem::fpd(&env.backend) {
            break;
        }
    }
    // '!' で止まる: r0=3（'!' を含む残り）・r1='!'・r5=受けるはず
    // だった位置。V=1。dst には "ab" だけ。
    assert_eq!(r(&env, 0), 3);
    assert_eq!(r(&env, 1), (s + 2) as u32);
    assert_eq!(r(&env, 4), 3);
    assert_eq!(r(&env, 5), (d + 2) as u32);
    assert_eq!(cc(&env), (false, true, true, false));
    let mut out = [0u8; 2];
    env.backend
        .mem
        .read(VirtAddr(d), &mut out, Access::DATA_LE)
        .unwrap();
    assert_eq!(&out, b"ab");
}

#[test]
fn crc_table_poly() {
    // CRC-32（Ethernet/AUTODIN-II 多項式）の表で "123456789" を
    // 畳む —— 既知値 0xcbf43926 と一致するはず。
    let mut env = run_env(1);
    let (t, s) = (DATA + 0x200, DATA);
    const POLY: u32 = 0xedb8_8320;
    for i in 0..16u32 {
        let mut v = i;
        for _ in 0..4 {
            v = v >> 1 ^ if v & 1 != 0 { POLY } else { 0 };
        }
        put(&mut env, t + u64::from(i) * 4, &v.to_le_bytes());
    }
    put(&mut env, s, b"123456789");
    // crc @#tbl, #0xffffffff, #9, @#s
    let mut insn = vec![0x0b];
    abs(t, &mut insn);
    insn.push(0x8f);
    insn.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    insn.push(0x09);
    abs(s, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    for _ in 0..9 {
        step(&mut env).unwrap();
    }
    let got = r(&env, 0) ^ 0xffff_ffff;
    assert_eq!(got, 0xcbf4_3926, "crc {:08x}", got);
    assert_eq!(r(&env, 1), 0);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), (s + 9) as u32);
    // r0=0x340bc6d9 —— N=0・Z=0。
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn pushr_popr_roundtrip() {
    // pushr #mask —— mask の立ったレジスタを r14 から順に積む。
    let mut env = run_env_stack();
    let mask: u16 = 0x5003; // r0, r1, r12, r14
    for (i, v) in [(0u8, 0xa0u32), (1, 0xa1), (12, 0xac)] {
        sem::r_set(&mut env.backend, i, v);
    }
    // mask は SP 自身も含むので、積まれる値は元の SP。
    let sp = r(&env, 14);
    let mut insn = vec![0xbb, 0x8f];
    insn.extend_from_slice(&mask.to_le_bytes());
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    step(&mut env).unwrap();
    // push 順は r14→r12→r1→r0: [sp-4]=r14, [sp-8]=r12, ...
    assert_eq!(r(&env, 14), sp - 16);
    assert_eq!(mem32(&env, u64::from(sp - 4)), sp);
    assert_eq!(mem32(&env, u64::from(sp - 8)), 0xac);
    assert_eq!(mem32(&env, u64::from(sp - 12)), 0xa1);
    assert_eq!(mem32(&env, u64::from(sp - 16)), 0xa0);

    // レジスタを壊してから同じ mask で popr —— r0 側から戻る。
    for i in [0u8, 1, 12] {
        sem::r_set(&mut env.backend, i, 0);
    }
    let mut insn = vec![0xba, 0x8f];
    insn.extend_from_slice(&mask.to_le_bytes());
    put(&mut env, BASE + 0x10, &insn);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0xa0);
    assert_eq!(r(&env, 1), 0xa1);
    assert_eq!(r(&env, 12), 0xac);
    assert_eq!(r(&env, 14), sp);
}

#[test]
fn chmk_dispatch() {
    // chmk #7 —— code を符号拡張してスタックへ積み、SCB 0x40 の
    // trap としてパーソナリティへ渡る。
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    let mut env = run_env_stack();
    put(&mut env, BASE, &[0xbc, 0x07]);
    env.pc = BASE;
    let sp = r(&env, 14);
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::CHMK);
    // trap なので復帰先は次の命令。
    assert_eq!(env.pc, BASE + 2);
    assert_eq!(r(&env, 14), sp - 4);
    assert_eq!(mem32(&env, u64::from(sp - 4)), 7);
    // PRV_MOD=user(3)・CUR_MOD=kernel(0)。
    let p = sem::psl_get(&env.backend);
    assert_eq!(p >> psl::PRV_MOD & 3, 3);
    assert_eq!(p >> psl::CUR_MOD & 3, 0);

    // chmu #-2 —— user から user へは現行モードのまま、code は
    // 符号拡張される。
    let mut env = run_env_stack();
    let mut insn = vec![0xbf, 0x8f];
    insn.extend_from_slice(&0xfffeu16.to_le_bytes());
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    let sp = r(&env, 14);
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::CHMU);
    assert_eq!(mem32(&env, u64::from(sp - 4)), 0xffff_fffe);
    let p = sem::psl_get(&env.backend);
    assert_eq!(p >> psl::CUR_MOD & 3, 3);
    assert_eq!(p >> psl::PRV_MOD & 3, 3);
}

// ---- VX8: 分岐・calls/callg/ret ----

/// 手続本体を `proc` に置く（入口マスク語 + 本体命令列）。
fn proc_at(env: &mut BareEnv, proc: u64, mask: u16, body: &[u8]) {
    put(env, proc, &mask.to_le_bytes());
    put(env, proc + 2, body);
}

#[test]
fn unconditional_branches() {
    let mut env = run_env(1);
    // brb: 変位は命令終端基準。+4 → 終端+4。
    put(&mut env, BASE, &[0x11, 0x04]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 6);
    // 負の変位。
    put(&mut env, BASE, &[0x11, 0xfc]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE - 2);
    // brw: 2 バイト変位。
    put(&mut env, BASE, &[0x31, 0x00, 0x01]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x103);
    // jmp @#dst。
    let dst = BASE + 0x80;
    let mut insn = vec![0x17];
    abs(dst, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, dst);
    // 条件コードは変えない（tstb で立てた Z が brb で生きる）。
    put(&mut env, BASE + 0x20, &[0x95, 0x8f, 0x00]); // tstb #0
    put(&mut env, BASE + 0x23, &[0x11, 0x00]); // brb +0（分岐しても PC=終端）
    env.pc = BASE + 0x20;
    step(&mut env).unwrap();
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x25);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn bsb_jsb_rsb() {
    let mut env = run_env_stack();
    let sp0 = r(&env, 14);
    // bsbb: 戻り PC（命令終端）を積んで BASE+0x20 の rsb へ。
    put(&mut env, BASE, &[0x10, 0x1e]);
    put(&mut env, BASE + 0x20, &[0x05]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x20);
    assert_eq!(r(&env, 14), sp0 - 4);
    assert_eq!(mem32(&env, u64::from(sp0 - 4)), (BASE + 2) as u32);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 2);
    assert_eq!(r(&env, 14), sp0);
    // bsbw: 2 バイト変位の往復。
    put(&mut env, BASE + 0x10, &[0x30, 0x0e, 0x00]);
    put(&mut env, BASE + 0x21, &[0x05]);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x21);
    assert_eq!(mem32(&env, u64::from(sp0 - 4)), (BASE + 0x13) as u32);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x13);
    // jsb @#sub: 先に指定子を評価してから戻り PC を積む。
    let mut insn = vec![0x16];
    abs(BASE + 0x40, &mut insn);
    put(&mut env, BASE + 0x30, &insn);
    put(&mut env, BASE + 0x40, &[0x05]);
    env.pc = BASE + 0x30;
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x40);
    assert_eq!(mem32(&env, u64::from(sp0 - 4)), (BASE + 0x36) as u32);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 0x36);
    assert_eq!(r(&env, 14), sp0);
}

#[test]
fn callg_frame_construction() {
    let mut env = run_env_stack();
    let sp0 = r(&env, 14);
    let args = DATA + 0x100;
    // 引数リスト: [個数, arg1, arg2]。
    put(&mut env, args, &2u32.to_le_bytes());
    put(&mut env, args + 4, &0xaaaau32.to_le_bytes());
    put(&mut env, args + 8, &0xbbbbu32.to_le_bytes());
    let proc = BASE + 0x200;
    // 入口マスク: r2・r5 保存 + IV 有効（<14>）。本体は r2 を
    // 壊してから ret（退避から復帰する証明）。
    proc_at(
        &mut env,
        proc,
        (1 << 2) | (1 << 5) | (1 << 14),
        &[0xd0, 0x8f, 0xad, 0xde, 0x00, 0x00, 0x52, 0x04],
    );
    // callg @#args, @#proc
    let mut insn = vec![0xfa];
    abs(args, &mut insn);
    abs(proc, &mut insn);
    put(&mut env, BASE, &insn);
    let ret_pc = BASE + insn.len() as u64;
    sem::r_set(&mut env.backend, 2, 0x2222);
    sem::r_set(&mut env.backend, 5, 0x5555);
    sem::r_set(&mut env.backend, reg::AP as u8, 0xaaaa_0000);
    sem::r_set(&mut env.backend, reg::FP as u8, 0xbbbb_0000);
    env.pc = BASE;
    step(&mut env).unwrap();
    let fp = u64::from(r(&env, 13));
    assert_eq!(env.pc, proc + 2);
    assert_eq!(r(&env, 12), args as u32); // AP = 引数リスト
    assert_eq!(r(&env, 14) as u64, fp); // SP = FP（フレーム最下位）
    // フレーム（低アドレス側から）: 条件ハンドラ・フレーム語・
    // 退避 AP/FP/PC・退避レジスタ（r0 側が最下位）。
    assert_eq!(mem32(&env, fp), 0);
    // S=0・SPA=0・mask<11:0>=0x024・退避 PSW=0。
    assert_eq!(mem32(&env, fp + 4), 0x0024_0000);
    assert_eq!(mem32(&env, fp + 8), 0xaaaa_0000);
    assert_eq!(mem32(&env, fp + 12), 0xbbbb_0000);
    assert_eq!(mem32(&env, fp + 16), ret_pc as u32);
    assert_eq!(mem32(&env, fp + 20), 0x2222); // r2
    assert_eq!(mem32(&env, fp + 24), 0x5555); // r5
    // IV 有効・DV/FU/条件コードは 0。
    let p = sem::psl_get(&env.backend);
    assert_ne!(p & (1 << psl::IV), 0);
    assert_eq!(p & (1 << psl::DV | 1 << psl::FU | 0xf), 0);
    // 本体が r2 を壊す。
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0xdead);
    // ret で完全復帰。
    step(&mut env).unwrap();
    assert_eq!(env.pc, ret_pc);
    assert_eq!(r(&env, 14), sp0);
    assert_eq!(r(&env, 2), 0x2222);
    assert_eq!(r(&env, 5), 0x5555);
    assert_eq!(r(&env, 12), 0xaaaa_0000);
    assert_eq!(r(&env, 13), 0xbbbb_0000);
    assert_eq!(sem::psl_get(&env.backend) & 0xffff, 0);
}

#[test]
fn calls_args_and_cleanup() {
    let mut env = run_env_stack();
    let sp0 = r(&env, 14);
    // 引数 2 個を逆順で積む（arg1 が最下位）。
    put(&mut env, BASE, &[0xdd, 0x8f, 0x22, 0x22, 0x22, 0x22]); // pushl #arg2
    put(&mut env, BASE + 6, &[0xdd, 0x8f, 0x11, 0x11, 0x11, 0x11]); // pushl #arg1
    // calls S^#2, @#proc
    let mut insn = vec![0xfb, 0x02];
    abs(BASE + 0x200, &mut insn);
    put(&mut env, BASE + 12, &insn);
    let ret_pc = BASE + 12 + insn.len() as u64;
    // 本体: r0=(AP+4)=arg1・r1=(AP+8)=arg2・r2=フレーム語。
    proc_at(
        &mut env,
        BASE + 0x200,
        0,
        &[
            0xd0, 0xac, 0x04, 0x50, // movl 4(ap), r0
            0xd0, 0xac, 0x08, 0x51, // movl 8(ap), r1
            0xd0, 0xad, 0x04, 0x52, // movl 4(fp), r2
            0x04, // ret
        ],
    );
    env.pc = BASE;
    step(&mut env).unwrap(); // pushl
    step(&mut env).unwrap(); // pushl
    step(&mut env).unwrap(); // calls
    let ap = r(&env, 12);
    let fp = u64::from(r(&env, 13));
    assert_eq!(env.pc, BASE + 0x202);
    assert_eq!(mem32(&env, u64::from(ap)), 2); // 個数語
    step(&mut env).unwrap();
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 0x1111_1111);
    assert_eq!(r(&env, 1), 0x2222_2222);
    step(&mut env).unwrap();
    // S<29>=1（calls フレーム）・mask=0・SPA=0・退避 PSW=0。
    assert_eq!(r(&env, 2), 1 << 29);
    assert_eq!(mem32(&env, fp), 0);
    step(&mut env).unwrap(); // ret
    assert_eq!(env.pc, ret_pc);
    // 個数語 + 引数リストが除去されて SP は呼出し前に戻る。
    assert_eq!(r(&env, 14), sp0);
}

#[test]
fn calls_unaligned_spa() {
    let mut env = run_env_stack();
    let sp0 = r(&env, 14);
    // 非整列 SP（<1:0>=1）。callg の SPA は呼出し時点の SP<1:0>。
    sem::r_set(&mut env.backend, reg::SP as u8, sp0 - 3);
    let args = DATA + 0x100;
    put(&mut env, args, &0u32.to_le_bytes());
    let proc = BASE + 0x200;
    proc_at(&mut env, proc, 0, &[0xd0, 0xad, 0x04, 0x52, 0x04]); // r2=フレーム語; ret
    let mut insn = vec![0xfa];
    abs(args, &mut insn);
    abs(proc, &mut insn);
    put(&mut env, BASE, &insn);
    let ret_pc = BASE + insn.len() as u64;
    env.pc = BASE;
    step(&mut env).unwrap();
    let fp = u64::from(r(&env, 13));
    // 整列後の SP（sp0-4）がフレーム上端。フレーム語は SPA<31:30>=1。
    assert_eq!(fp + 20, u64::from(sp0 - 4));
    assert_eq!(mem32(&env, fp + 4), 1 << 30);
    step(&mut env).unwrap(); // movl 4(fp), r2
    assert_eq!(r(&env, 2), 1 << 30);
    step(&mut env).unwrap(); // ret
    // SPA 分が復帰して SP は呼出し時の値に戻る。
    assert_eq!(env.pc, ret_pc);
    assert_eq!(r(&env, 14), sp0 - 3);
}

#[test]
fn call_enables_and_saved_psw() {
    let mut env = run_env_stack();
    // 呼び出し側で FU・IV・N を立てる。退避語には T と条件
    // コードを抜いた <14:0> が残る。
    sem::psl_put(
        &mut env.backend,
        psl::USER | 1 << psl::FU | 1 << psl::IV | 1 << psl::N,
    );
    let args = DATA + 0x100;
    put(&mut env, args, &0u32.to_le_bytes());
    let proc = BASE + 0x200;
    // マスク <15> で DV を有効化。本体はフレーム PSW へ条件
    // コードを OR で書き足して戻る（ret が復帰する CC の源。
    // 退避済みの IV/FU/DV 桁は同じバイトなので bisb2 で残す）。
    proc_at(
        &mut env,
        proc,
        1 << 15,
        &[0x88, 0x8f, 0x0b, 0xad, 0x04, 0x04],
    );
    let mut insn = vec![0xfa];
    abs(args, &mut insn);
    abs(proc, &mut insn);
    put(&mut env, BASE, &insn);
    let ret_pc = BASE + insn.len() as u64;
    env.pc = BASE;
    step(&mut env).unwrap();
    let fp = u64::from(r(&env, 13));
    // 呼出し後: DV=1（マスク<15>）・IV=0（マスク<14>=0）・FU=0・CC=0。
    let p = sem::psl_get(&env.backend);
    assert_ne!(p & (1 << psl::DV), 0);
    assert_eq!(p & (1 << psl::IV | 1 << psl::FU | 0xf), 0);
    // フレーム語の退避 PSW<14:0> は FU|IV（T・CC は 0）。
    assert_eq!(
        mem32(&env, fp + 4) & 0xffff,
        (1 << psl::FU | 1 << psl::IV) as u32
    );
    // 本体がフレーム PSW<7:0> に 0x0b（N|V|C）を OR する。
    step(&mut env).unwrap();
    step(&mut env).unwrap(); // ret
    assert_eq!(env.pc, ret_pc);
    // 退避 PSW 復帰: 本体が書いた CC (N|V|C) + 呼出し時の
    // FU|IV。DV は呼出し前になかったので 0 に戻る。
    assert_eq!(cc(&env), (true, false, true, true));
    let p = sem::psl_get(&env.backend);
    assert_ne!(p & (1 << psl::FU | 1 << psl::IV), 0);
    assert_eq!(p & (1 << psl::DV), 0);
}

#[test]
fn call_nested() {
    let mut env = run_env_stack();
    let sp0 = r(&env, 14);
    let (proca, procb) = (BASE + 0x200, BASE + 0x300);
    let argsb = DATA + 0x200;
    put(&mut env, argsb, &0u32.to_le_bytes());
    // B: 何もしないで ret。A: callg で B を呼んでから ret。
    proc_at(&mut env, procb, 0, &[0x04]);
    let mut abody = vec![0xfa];
    abs(argsb, &mut abody);
    abs(procb, &mut abody);
    let a_ret_pc = proca + 2 + abody.len() as u64;
    abody.push(0x04);
    proc_at(&mut env, proca, 1 << 2, &abody);
    // calls S^#0, @#proca（r2 を壊して A のマスク復帰も見る）。
    let mut insn = vec![0xfb, 0x00];
    abs(proca, &mut insn);
    put(&mut env, BASE, &insn);
    let ret_pc = BASE + insn.len() as u64;
    sem::r_set(&mut env.backend, 2, 0x2222);
    sem::r_set(&mut env.backend, reg::FP as u8, 0xbbbb_0000);
    env.pc = BASE;
    step(&mut env).unwrap(); // calls → A
    let fpa = u64::from(r(&env, 13));
    assert_eq!(env.pc, proca + 2);
    sem::r_set(&mut env.backend, 2, 0xbad);
    step(&mut env).unwrap(); // A の callg → B
    let fpb = u64::from(r(&env, 13));
    assert_eq!(env.pc, procb + 2);
    assert_ne!(fpb, fpa);
    // B のフレームの退避 FP は A の FP、退避 PC は A の ret 位置。
    assert_eq!(mem32(&env, fpb + 12) as u64, fpa);
    assert_eq!(mem32(&env, fpb + 16), a_ret_pc as u32);
    step(&mut env).unwrap(); // B の ret → A の ret へ
    assert_eq!(env.pc, a_ret_pc);
    assert_eq!(r(&env, 13) as u64, fpa);
    step(&mut env).unwrap(); // A の ret → 呼出し側へ
    assert_eq!(env.pc, ret_pc);
    assert_eq!(r(&env, 14), sp0);
    assert_eq!(r(&env, 2), 0x2222); // A のマスクで復帰
    assert_eq!(r(&env, 13), 0xbbbb_0000);
}

#[test]
fn call_frame_faults() {
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Unimplemented
        }
    }
    // 入口マスク <13:12> != 0 → 予約オペランド fault。
    let mut env = run_env_stack();
    let args = DATA + 0x100;
    put(&mut env, args, &0u32.to_le_bytes());
    proc_at(&mut env, BASE + 0x200, 0x2000, &[0x04]);
    let mut insn = vec![0xfa];
    abs(args, &mut insn);
    abs(BASE + 0x200, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    let mut sys = Rec(0);
    assert!(run::step(&mut env, &mut sys, DEFAULT_FEATS).is_err());
    assert_eq!(sys.0, sem::scb::RESERVED_OPERAND);
    assert_eq!(env.pc, BASE); // fault は命令先頭へ

    // フレーム語 <15:8> != 0 → ret が予約オペランド fault。
    let mut env = run_env_stack();
    proc_at(
        &mut env,
        BASE + 0x200,
        0,
        &[0x90, 0x8f, 0x01, 0xad, 0x05, 0x04], // movb #1, 5(fp); ret
    );
    let mut insn = vec![0xfa];
    abs(args, &mut insn);
    abs(BASE + 0x200, &mut insn);
    put(&mut env, BASE, &insn);
    env.pc = BASE;
    step(&mut env).unwrap(); // callg
    step(&mut env).unwrap(); // movb
    let mut sys = Rec(0);
    let pc_ret = env.pc;
    assert!(run::step(&mut env, &mut sys, DEFAULT_FEATS).is_err());
    assert_eq!(sys.0, sem::scb::RESERVED_OPERAND);
    assert_eq!(env.pc, pc_ret);
}

// ---- VX9: 浮動小数点 ----

/// F 形式の値（語順写像済み —— レジスタ・メモリに置く形）。
/// 建築の語順は「指数・符号の語が最下位アドレス」なので、
/// F 1.0 = 0x00004080。
fn fv(v: u128) -> u32 {
    sem::fp_order(Width::F, v) as u32
}

/// D/G 形式の下位 32 ビット（語順写像済み）。
fn dv(w: Width, v: u128) -> u32 {
    sem::fp_order(w, v) as u32
}

const F1: u32 = 0x0000_4080; // 1.0
const F2: u32 = 0x0000_4100; // 2.0
const FH: u32 = 0x0000_4000; // 0.5
const FM1: u32 = 0x0000_c080; // -1.0
const FMAX: u32 = 0xffff_7fff; // 最大の有限値（指数 255・仮数全 1）
const FMIN: u32 = 0x0000_0080; // 最小の正規数（指数 1・仮数 0）

#[test]
fn vx9_fp_decode() {
    assert_eq!(dec1(0x40), Some(Insn::Addf2));
    assert_eq!(dec1(0x4f), Some(Insn::Acbf));
    assert_eq!(dec1(0x54), Some(Insn::Emodf));
    assert_eq!(dec1(0x55), Some(Insn::Polyf));
    assert_eq!(dec1(0x56), Some(Insn::Cvtfd));
    assert_eq!(dec1(0x60), Some(Insn::Addd2));
    assert_eq!(dec1(0x75), Some(Insn::Polyd));
    assert_eq!(dec1(0x76), Some(Insn::Cvtdf));
    assert_eq!(dec2(0xfd, 0x32), Some(Insn::Cvtdh));
    assert_eq!(dec2(0xfd, 0x33), Some(Insn::Cvtgf));
    assert_eq!(dec2(0xfd, 0x55), Some(Insn::Polyg));
    assert_eq!(dec2(0xfd, 0x56), Some(Insn::Cvtgh));
    assert_eq!(dec2(0xfd, 0x60), Some(Insn::Addh2));
    assert_eq!(dec2(0xfd, 0x75), Some(Insn::Polyh));
    assert_eq!(dec2(0xfd, 0x7c), Some(Insn::Clro));
    assert_eq!(dec2(0xfd, 0x98), Some(Insn::Cvtfh));
    assert_eq!(dec2(0xfd, 0x99), Some(Insn::Cvtfg));
    assert_eq!(dec2(0xfd, 0xf6), Some(Insn::Cvthf));
    assert_eq!(dec2(0xfd, 0xf7), Some(Insn::Cvthd));
    // hfp を削ると H 命令は解けない（F/D/G は残る）。
    let no_hfp = DEFAULT_FEATS & !FEAT_HFP;
    assert_eq!(decode_model_ex(0x60fd, 16, false, no_hfp), None);
    assert_eq!(
        decode_model_ex(0x40fd, 16, false, no_hfp),
        Some(Insn::Addg2)
    );
}

#[test]
fn fp_f_word_order() {
    // F 1.0 のメモリ上の並びは 80 40 00 00（指数語が先頭）。
    let mut env = run_env(1);
    put(&mut env, DATA, &[0x80, 0x40, 0x00, 0x00]);
    // movf (r0), r1 —— メモリからレジスタへ（語順は保たれる）。
    put(&mut env, BASE, &[0x50, 0x60, 0x51]);
    sem::r_set(&mut env.backend, 0, DATA as u32);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), F1);
    assert_eq!(cc(&env), (false, false, false, false));

    // tstf (r0) —— 正の値は N=0/Z=0。
    put(&mut env, BASE + 0x10, &[0x53, 0x60]);
    env.pc = BASE + 0x10;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn fp_f_arith() {
    // addf3 r0, r1, r2 —— 1.0 + 1.0 = 2.0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x41, 0x50, 0x51, 0x52]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), F2);
    assert_eq!(cc(&env), (false, false, false, false));

    // subf3 r0, r1, r2 —— 1.0 - 1.0 = 0 → Z=1。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x43, 0x50, 0x51, 0x52]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0);
    assert_eq!(cc(&env), (false, true, false, false));

    // mulf3 r0, r1, r2 —— 1.5 * 2.0 = 3.0（canon 0x41400000）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x45, 0x50, 0x51, 0x52]);
    sem::r_set(&mut env.backend, 0, fv(0x40c0_0000));
    sem::r_set(&mut env.backend, 1, F2);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), fv(0x4140_0000));

    // divf3 r0, r1, r2 —— 1.0 / 2.0 = 0.5。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x47, 0x50, 0x51, 0x52]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, F2);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), FH);

    // addf2 r0, r1 —— 2 項形は第 2 オペランドに畳む。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x40, 0x50, 0x51]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), F2);
}

#[test]
fn fp_literal_and_mov_mneg() {
    // addf3 S#8, S#8, r0 —— 浮動リテラル 8 は 1.0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x41, 0x08, 0x08, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), F2);

    // movf は dirty zero（指数 0・符号 0・仮数 != 0）を真の零に畳む。
    // C は保存される。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x50, 0x50, 0x51]);
    sem::r_set(&mut env.backend, 0, 0x0001_0000); // canon 0x00000001
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::C));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), 0);
    assert_eq!(cc(&env), (false, true, false, true));

    // mnegf r0, r1 —— 1.0 → -1.0（N=1）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x52, 0x50, 0x51]);
    sem::r_set(&mut env.backend, 0, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1), FM1);
    assert_eq!(cc(&env), (true, false, false, false));

    // cmpf: 1.0 < 2.0 → N=1。等値は Z=1。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x51, 0x50, 0x51]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, F2);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (true, false, false, false));
    sem::r_set(&mut env.backend, 0, F2);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn fp_d_g_h_arith() {
    // addd3 r0'r1, r2'r3, r4'r5 —— 1.0 + 1.0 = 2.0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x61, 0x50, 0x52, 0x54]);
    sem::r_set(&mut env.backend, 0, 0x4080);
    sem::r_set(&mut env.backend, 1, 0);
    sem::r_set(&mut env.backend, 2, 0x4080);
    sem::r_set(&mut env.backend, 3, 0);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 4), 0x4100);
    assert_eq!(r(&env, 5), 0);

    // addg3 —— G 1.0 + G 1.0 = G 2.0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x41, 0x50, 0x52, 0x54]);
    sem::r_set(&mut env.backend, 0, 0x4010);
    sem::r_set(&mut env.backend, 2, 0x4010);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 4), 0x4020);
    assert_eq!(r(&env, 5), 0);

    // addh3 —— H 1.0 + H 1.0 = H 2.0（r8'r9'r10'r11）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x61, 0x50, 0x54, 0x58]);
    sem::r_set(&mut env.backend, 0, 0x4001);
    sem::r_set(&mut env.backend, 4, 0x4001);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 8), 0x4002);
    assert_eq!(r(&env, 9), 0);
    assert_eq!(r(&env, 10), 0);
    assert_eq!(r(&env, 11), 0);

    // clro (r0) —— 16 バイトを消す。
    let mut env = run_env(1);
    put(&mut env, DATA, &[0xaa; 16]);
    put(&mut env, BASE, &[0xfd, 0x7c, 0x60]);
    sem::r_set(&mut env.backend, 0, DATA as u32);
    env.pc = BASE;
    step(&mut env).unwrap();
    for i in 0..4 {
        assert_eq!(mem32(&env, DATA + i * 4), 0);
    }
}

#[test]
fn fp_cvt_int() {
    // cvtlf #5, r0 —— 5.0 = 0x41a00000（canon）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x4e, 0x05, 0x50]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), fv(0x41a0_0000));

    // cvtfl: 2.5 → 2（切捨）。cvtrfl: 2.5 → 3（丸め）。
    // -2.5 → cvtrfl → -3（絶対値側の丸め）。
    for (opc, src, want) in [
        (0x4a, fv(0x4120_0000), 2u32),
        (0x4b, fv(0x4120_0000), 3),
        (0x4b, fv(0xc120_0000), -3i32 as u32),
        (0x4a, fv(0xc120_0000), -2i32 as u32),
    ] {
        let mut env = run_env(1);
        put(&mut env, BASE, &[opc, 0x50, 0x51]);
        sem::r_set(&mut env.backend, 0, src);
        env.pc = BASE;
        step(&mut env).unwrap();
        assert_eq!(r(&env, 1) as i32, want as i32, "opc {opc:#x}");
    }

    // cvtfb: 200.0 → byte あふれ → 下位 8 ビットと V=1。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x48, 0x50, 0x51]);
    sem::r_set(&mut env.backend, 0, fv(0x4448_0000)); // 200.0
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 1) & 0xff, 200i32 as u8 as u32);
    assert!(cc(&env).2); // V=1
}

#[test]
fn fp_cvt_formats() {
    // cvtfd r0, r2'r3 —— F 1.0 → D 1.0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x56, 0x50, 0x52]);
    sem::r_set(&mut env.backend, 0, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0x4080);
    assert_eq!(r(&env, 3), 0);

    // cvtdf —— D 1.0 → F 1.0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x76, 0x50, 0x52]);
    sem::r_set(&mut env.backend, 0, 0x4080);
    sem::r_set(&mut env.backend, 1, 0);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), F1);

    // cvtfg —— F 1.0 → G 1.0。cvtgf —— G 1.0 → F 1.0。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x99, 0x50, 0x52]);
    sem::r_set(&mut env.backend, 0, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0x4010);
    assert_eq!(r(&env, 3), 0);

    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x33, 0x50, 0x52]);
    sem::r_set(&mut env.backend, 0, 0x4010);
    sem::r_set(&mut env.backend, 1, 0);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), F1);

    // cvtfh —— F 1.0 → H 1.0（r4-r7）。cvthf で戻す。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x98, 0x50, 0x54]);
    sem::r_set(&mut env.backend, 0, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 4), 0x4001);
    for i in 5..8 {
        assert_eq!(r(&env, i), 0);
    }
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0xf6, 0x50, 0x54]);
    sem::r_set(&mut env.backend, 0, 0x4001);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 4), F1);
}

#[test]
fn fp_acb() {
    // acbf r0(=limit 3.0), r1(=add 1.0), r2(=index), -6 ——
    // index が 1→2→3→4 と進み、index<=limit の間は命令先頭へ戻る。
    // 変位は .bw（word）。命令長 6 バイトなので戻り変位は -6。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x4f, 0x50, 0x51, 0x52, 0xfa, 0xff, 0x01]);
    sem::r_set(&mut env.backend, 0, fv(0x4140_0000)); // limit = 3.0
    sem::r_set(&mut env.backend, 1, F1); // add = 1.0
    sem::r_set(&mut env.backend, 2, F1); // index = 1.0
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), F2); // index = 2.0
    assert_eq!(env.pc, BASE); // 2.0 <= 3.0 → 分岐で先頭へ
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), fv(0x4140_0000)); // 3.0
    assert_eq!(env.pc, BASE); // 3.0 <= 3.0 → まだ分岐
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), fv(0x4180_0000)); // 4.0
    assert_eq!(env.pc, BASE + 6); // 4.0 > 3.0 → 抜ける
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn fp_exceptions() {
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }

    // divf2 r1(=0), r0 —— 浮動ゼロ除算 fault（型 9）。dst 手つかず、
    // 復帰先は命令先頭（浮動リテラルは 0 を表せないのでレジスタで
    // 真の零を作る）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x46, 0x51, 0x50]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, 0);
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::FLT_DIV_ZERO_F));
    assert_eq!(env.pc, BASE);
    assert_eq!(r(&env, 0), F1);

    // addf3 max + max → 浮動オーバーフロー fault（型 8）。dst 手つかず。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x41, 0x50, 0x51, 0x52]);
    sem::r_set(&mut env.backend, 0, FMAX);
    sem::r_set(&mut env.backend, 1, FMAX);
    sem::r_set(&mut env.backend, 2, 0xdead_beef);
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::FLT_OVERFLOW_F));
    assert_eq!(env.pc, BASE);
    assert_eq!(r(&env, 2), 0xdead_beef);

    // divf3 min, 2.0 → アンダーフロー。FU=0 なら真の零で続行。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x47, 0x50, 0x51, 0x52]);
    sem::r_set(&mut env.backend, 0, FMIN);
    sem::r_set(&mut env.backend, 1, F2);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 2), 0);
    assert_eq!(cc(&env), (false, true, false, false));

    // FU=1 ならアンダーフロー fault（型 A）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x47, 0x50, 0x51, 0x52]);
    sem::r_set(&mut env.backend, 0, FMIN);
    sem::r_set(&mut env.backend, 1, F2);
    sem::r_set(&mut env.backend, 2, 0xdead_beef);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::FU));
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::arith(sem::scb::at::FLT_UNDERFLOW_F));
    assert_eq!(env.pc, BASE);
    assert_eq!(r(&env, 2), 0xdead_beef);

    // 予約オペランド（指数 0・符号 1）は予約オペランド fault。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x53, 0x50]); // tstf r0
    sem::r_set(&mut env.backend, 0, 0x0000_8000);
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::RESERVED_OPERAND);
    assert_eq!(env.pc, BASE);
}

#[test]
fn fp_emod() {
    // emodf r0(mulr), r1(mulrx), r2(muld), r3(int), r4(fract) ——
    // 1.5 * 1.5 = 2.25 → int=2, fract=0.25。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x54, 0x50, 0x51, 0x52, 0x53, 0x54]);
    sem::r_set(&mut env.backend, 0, fv(0x40c0_0000)); // 1.5
    sem::r_set(&mut env.backend, 1, 0);
    sem::r_set(&mut env.backend, 2, fv(0x40c0_0000)); // 1.5
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 3), 2);
    assert_eq!(r(&env, 4), fv(0x3f80_0000)); // 0.25
    assert_eq!(cc(&env), (false, false, false, false));

    // 拡張係数 mulrx=0x80: mulr = 1.0 + 2^-24 → * 1.0 →
    // int=1, fract = 2^-24（canon 0x34000000）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x54, 0x50, 0x51, 0x52, 0x53, 0x54]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, 0x80);
    sem::r_set(&mut env.backend, 2, F1);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 3), 1);
    assert_eq!(r(&env, 4), fv(0x3480_0000)); // 2^-24

    // 整数あふれ: 1.0 * 2^40 → int に収まらない → V=1、低 32 ビット。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x54, 0x50, 0x51, 0x52, 0x53, 0x54]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, 0);
    sem::r_set(&mut env.backend, 2, fv(0x5480_0000)); // 2^40
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 3), 0); // 2^40 の下位 32 ビット
    assert_eq!(r(&env, 4), 0);
    assert!(cc(&env).2); // V=1

    // emodg —— mulr=r0'r1, mulrx=r1, muld=r2'r3, int=r3, fract=r4'r5。
    // 1.5*1.5 = 2.25 → int=2（r3 は muld の上位として読んでから
    // int の書き先になる —— ソースは書き込み前に評価済み）。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0xfd, 0x54, 0x50, 0x51, 0x52, 0x53, 0x54]);
    let g15 = dv(Width::G, 0x4018_0000_0000_0000); // G 1.5
    sem::r_set(&mut env.backend, 0, g15);
    sem::r_set(&mut env.backend, 1, 0);
    sem::r_set(&mut env.backend, 2, g15);
    sem::r_set(&mut env.backend, 3, 0);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 3), 2); // int.wl
    assert_eq!(r(&env, 4), dv(Width::G, 0x3ff0_0000_0000_0000)); // G 0.25
    assert_eq!(r(&env, 5), 0);
}

#[test]
fn fp_poly() {
    // polyf r0(arg), r1(degree), (r5)(tbladdr) ——
    // arg=2.0, degree=2, table=[1.0, 0.5, 0.25]（高次係数が先頭）
    // → 1.0*x^2 + 0.5*x + 0.25 = 5.25。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x55, 0x50, 0x51, 0x65]);
    for (i, c) in [F1, FH, fv(0x3f80_0000)].iter().enumerate() {
        put(&mut env, DATA + (i as u64) * 4, &c.to_le_bytes());
    }
    sem::r_set(&mut env.backend, 0, F2);
    sem::r_set(&mut env.backend, 1, 2);
    sem::r_set(&mut env.backend, 5, DATA as u32);
    env.pc = BASE;
    // 「初期化 + 反復 1 回」が最初のステップ、以後 1 反復 =
    // 1 ステップ。途中は FPD=1 で PC は命令先頭へ戻る。
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE);
    assert!(sem::psl_get(&env.backend) & (1 << psl::FPD) != 0);
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + 4); // 完了 → 次の命令
    assert!(sem::psl_get(&env.backend) & (1 << psl::FPD) == 0);
    assert_eq!(r(&env, 0), fv(0x41a8_0000)); // 5.25
    assert_eq!(r(&env, 1), 0);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), (DATA + 12) as u32); // 表の終端
    assert_eq!(cc(&env), (false, false, false, false));
}

#[test]
fn fp_poly_degree_and_h() {
    struct Rec(u32);
    impl TrapHandler for Rec {
        fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
            self.0 = code;
            TrapOutcome::Handled
        }
    }
    // 次数 > 31 は予約オペランド fault。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x55, 0x50, 0x51, 0x65]);
    sem::r_set(&mut env.backend, 0, F1);
    sem::r_set(&mut env.backend, 1, 32);
    sem::r_set(&mut env.backend, 5, DATA as u32);
    env.pc = BASE;
    let mut sys = Rec(0);
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, sem::scb::RESERVED_OPERAND);
    assert_eq!(env.pc, BASE);

    // polyh —— arg は反復中スタックへ退避し、完了で取り除く。
    // arg=2.0, degree=2, table=[1.0, 0.5, 0.25] → 5.25。
    // H の arg は r0'r1'r2'r3 に跨るので degree は r6 に置く。
    let mut env = run_env_stack();
    put(&mut env, BASE, &[0xfd, 0x75, 0x50, 0x56, 0x65]);
    // 表の H 値は指数語が最下位アドレス: H 1.0 = 0x4001、
    // H 0.5 = 0x4000、H 0.25 = 0x3fff（残り 12 バイトは初期値 0）。
    put(&mut env, DATA, &0x4001u32.to_le_bytes());
    put(&mut env, DATA + 16, &0x4000u32.to_le_bytes());
    put(&mut env, DATA + 32, &0x3fffu32.to_le_bytes());
    sem::r_set(&mut env.backend, 0, 0x4002); // H 2.0
    sem::r_set(&mut env.backend, 6, 2);
    sem::r_set(&mut env.backend, 5, DATA as u32);
    let sp0 = r(&env, reg::SP as u8);
    env.pc = BASE;
    step(&mut env).unwrap(); // 初期化 + arg 退避 + 反復 1 回
    assert_eq!(r(&env, reg::SP as u8), sp0 - 16);
    step(&mut env).unwrap(); // 反復 2 回目で完了
    assert_eq!(r(&env, reg::SP as u8), sp0);
    // 5.25 = 0.65625*2^3 → 指数語 0x4003、仮数の先頭語 0x5000。
    assert_eq!(r(&env, 0), 0x5000_4003);
    assert_eq!(r(&env, 1), 0);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), 0);
}

// ---- VX10: 十進文字列 ----

/// 十進の .rw オペランド（#n 即値語）。
fn rw(n: u16, out: &mut Vec<u8>) {
    out.push(0x8f);
    out.extend_from_slice(&n.to_le_bytes());
}

/// 十進の .ab オペランド（@#addr）。
fn ab(addr: u64, out: &mut Vec<u8>) {
    abs(addr, out);
}

/// パック十進のテスト用バイト列（右詰め・優先符号 C/D）。
fn pk(digits: &[u8], neg: bool) -> Vec<u8> {
    let len = digits.len();
    let n = len / 2 + 1;
    let mut out = vec![0u8; n];
    for k in 0..len {
        let p = 2 * n - 2 - k;
        let d = digits[len - 1 - k];
        if p.is_multiple_of(2) {
            out[p / 2] |= d << 4;
        } else {
            out[p / 2] |= d;
        }
    }
    out[n - 1] = (out[n - 1] & 0xf0) | if neg { 0xd } else { 0xc };
    out
}

/// メモリの len 桁パック十進を文字列化して比較しやすくする。
fn mem_pack(env: &BareEnv, a: u64, len: usize) -> (Vec<u8>, bool) {
    let n = len / 2 + 1;
    let mut b = vec![0u8; n];
    env.backend
        .mem
        .read(VirtAddr(a), &mut b, Access::DATA_LE)
        .unwrap();
    let mut digits = Vec::new();
    for k in 0..len {
        let p = 2 * n - 2 - k;
        digits.push(if p.is_multiple_of(2) {
            b[p / 2] >> 4
        } else {
            b[p / 2] & 0xf
        });
    }
    digits.reverse();
    (digits, b[n - 1] & 0xf == 0xd || b[n - 1] & 0xf == 0xb)
}

fn mem_bytes(env: &BareEnv, a: u64, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    env.backend
        .mem
        .read(VirtAddr(a), &mut b, Access::DATA_LE)
        .unwrap();
    b
}

/// trap/fault コードを集めるハンドラ（処置済みとして続行）。
struct Rec(Vec<u32>);
impl TrapHandler for Rec {
    fn handle_trap(&mut self, _env: &mut BareEnv, code: u32) -> TrapOutcome {
        self.0.push(code);
        TrapOutcome::Handled
    }
}

const DEC: u64 = DATA;

#[test]
fn dec_insns_decode() {
    assert_eq!(dec1(0x08), Some(Insn::Cvtps));
    assert_eq!(dec1(0x09), Some(Insn::Cvtsp));
    assert_eq!(dec1(0x20), Some(Insn::Addp4));
    assert_eq!(dec1(0x21), Some(Insn::Addp6));
    assert_eq!(dec1(0x22), Some(Insn::Subp4));
    assert_eq!(dec1(0x23), Some(Insn::Subp6));
    assert_eq!(dec1(0x24), Some(Insn::Cvtpt));
    assert_eq!(dec1(0x25), Some(Insn::Mulp));
    assert_eq!(dec1(0x26), Some(Insn::Cvttp));
    assert_eq!(dec1(0x27), Some(Insn::Divp));
    assert_eq!(dec1(0x34), Some(Insn::Movp));
    assert_eq!(dec1(0x35), Some(Insn::Cmpp3));
    assert_eq!(dec1(0x36), Some(Insn::Cvtpl));
    assert_eq!(dec1(0x37), Some(Insn::Cmpp4));
    assert_eq!(dec1(0x38), Some(Insn::Editpc));
    assert_eq!(dec1(0xf8), Some(Insn::Ashp));
    assert_eq!(dec1(0xf9), Some(Insn::Cvtlp));
    // decimal 機能が無いモデルでは解けない。
    let no_dec = DEFAULT_FEATS & !FEAT_DECIMAL & !FEAT_EDITPC;
    assert_eq!(decode_model_ex(0x34, 8, false, no_dec), None);
    assert_eq!(decode_model_ex(0x38, 8, false, no_dec), None);
    assert_eq!(decode_model_ex(0xf8, 8, false, no_dec), None);
}

#[test]
fn dec_movp_basic_and_minus_zero() {
    // movp #5, @#src, @#dst —— "12345"+ を写す。
    let mut env = run_env(1);
    let mut prog = vec![0x34];
    rw(5, &mut prog);
    ab(DEC, &mut prog);
    ab(DEC + 0x40, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2, 3, 4, 5], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_bytes(&env, DEC + 0x40, 3), pk(&[1, 2, 3, 4, 5], false));
    assert_eq!(cc(&env), (false, false, false, false));
    assert_eq!(r(&env, 0), 0);
    assert_eq!(r(&env, 1), DEC as u32);
    assert_eq!(r(&env, 3), (DEC + 0x40) as u32);

    // -0 のソースは結果 +0（符号ニブルを優先の正に直す）。
    let mut env = run_env(1);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[0, 0, 0, 0, 0], true));
    env.pc = BASE;
    step(&mut env).unwrap();
    let (d, neg) = mem_pack(&env, DEC + 0x40, 5);
    assert!(d.iter().all(|&x| x == 0));
    assert!(!neg);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn dec_cmpp_and_zero_len() {
    // cmpp3 #3, @#s1, @#s2 —— "123" vs "124" → N=1。
    let mut env = run_env(1);
    let mut prog = vec![0x35];
    rw(3, &mut prog);
    ab(DEC, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2, 3], false));
    put(&mut env, DEC + 0x20, &pk(&[1, 2, 4], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (true, false, false, false));

    // cmpp4 で桁数違いの等値: "0123" vs "123" → Z=1。
    let mut env = run_env(1);
    let mut prog = vec![0x37];
    rw(4, &mut prog);
    ab(DEC, &mut prog);
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[0, 1, 2, 3], false));
    put(&mut env, DEC + 0x20, &pk(&[1, 2, 3], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(cc(&env), (false, true, false, false));

    // 長さ 0 の文字列は値 0。movp #0 は符号つき 1 バイトを写す。
    let mut env = run_env(1);
    let mut prog = vec![0x34];
    rw(0, &mut prog);
    ab(DEC, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[], false));
    put(&mut env, DEC + 0x20, &[0xff]);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_bytes(&env, DEC + 0x20, 1), vec![0x0c]);
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn dec_add_sub_overflow() {
    // addp4 #2,@#a, #3,@#b —— "23" + "100" → "123"。
    let mut env = run_env(1);
    let mut prog = vec![0x20];
    rw(2, &mut prog);
    ab(DEC, &mut prog);
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[2, 3], false));
    put(&mut env, DEC + 0x20, &pk(&[1, 0, 0], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 3), (vec![1, 2, 3], false));
    assert_eq!(cc(&env), (false, false, false, false));
    assert_eq!(r(&env, 1), DEC as u32);
    assert_eq!(r(&env, 3), (DEC + 0x20) as u32);

    // addp6: "999" + "005" = "1004" → 3 桁に収まらず "004"、V=1。
    let mut env = run_env(1);
    let mut prog = vec![0x21];
    rw(3, &mut prog);
    ab(DEC, &mut prog);
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);
    rw(3, &mut prog);
    ab(DEC + 0x40, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[9, 9, 9], false));
    put(&mut env, DEC + 0x20, &pk(&[0, 0, 5], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x40, 3), (vec![0, 0, 4], false));
    assert_eq!(cc(&env), (false, false, true, false));

    // subp6: "0100" - "0001" = "0099"。
    let mut env = run_env(1);
    let mut prog = vec![0x23];
    rw(4, &mut prog);
    ab(DEC, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x20, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x40, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[0, 0, 0, 1], false));
    put(&mut env, DEC + 0x20, &pk(&[0, 1, 0, 0], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x40, 4), (vec![0, 0, 9, 9], false));
    assert_eq!(cc(&env), (false, false, false, false));

    // subp4: "0005" - "0010" = "-0005" → N=1。
    let mut env = run_env(1);
    let mut prog = vec![0x22];
    rw(4, &mut prog);
    ab(DEC, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[0, 0, 1, 0], false));
    put(&mut env, DEC + 0x20, &pk(&[0, 0, 0, 5], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 4), (vec![0, 0, 0, 5], true));
    assert_eq!(cc(&env), (true, false, false, false));
}

#[test]
fn dec_mulp_divp() {
    // mulp: "12" * "34" = "0408"。
    let mut env = run_env_stack();
    let mut prog = vec![0x25];
    rw(2, &mut prog);
    ab(DEC, &mut prog);
    rw(2, &mut prog);
    ab(DEC + 0x20, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x40, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2], false));
    put(&mut env, DEC + 0x20, &pk(&[3, 4], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x40, 4), (vec![0, 4, 0, 8], false));
    assert_eq!(cc(&env), (false, false, false, false));
    assert_eq!(r(&env, 5), (DEC + 0x40) as u32);

    // divp: "100" / "7" = "14"（商のみ。負×正 → 負）。
    let mut env = run_env_stack();
    let mut prog = vec![0x27];
    rw(1, &mut prog);
    ab(DEC, &mut prog);
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);
    rw(2, &mut prog);
    ab(DEC + 0x40, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[7], false));
    put(&mut env, DEC + 0x20, &pk(&[1, 0, 0], true));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x40, 2), (vec![1, 4], true));
    assert_eq!(cc(&env), (true, false, false, false));

    // divp by 0 → 算術 trap（div-zero 型）。
    let mut env = run_env_stack();
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[0], false));
    env.pc = BASE;
    let mut sys = Rec(Vec::new());
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, [sem::scb::arith(sem::scb::at::FLT_DIV_ZERO)]);
}

#[test]
fn dec_cvtpl_cvtlp_round_trip() {
    // cvtpl #5,@#src,r0 —— -12345 → r0。
    let mut env = run_env(1);
    let mut prog = vec![0x36];
    rw(5, &mut prog);
    ab(DEC, &mut prog);
    prog.push(0x50); // r0
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2, 3, 4, 5], true));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) as i32, -12345);
    assert_eq!(cc(&env), (true, false, false, false));

    // 範囲外 → 下位 32 ビット + V=1。
    let mut env = run_env(1);
    put(&mut env, BASE, &prog);
    let big = pk(&[9, 9, 9, 9, 9], false); // 99999 は収まるので 30 桁にする
    put(&mut env, DEC, &big);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0) as i32, 99999);
    assert_eq!(cc(&env), (false, false, false, false));

    // cvtpl で 11 桁 → V=1。
    let mut env = run_env(1);
    let mut prog = vec![0x36];
    rw(11, &mut prog);
    ab(DEC, &mut prog);
    prog.push(0x50);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[9; 11], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(r(&env, 0), 99_999_999_999u64 as u32);
    // 99999999999 mod 2^32 = 0x4876_e7ff（符号ビットは立たない）。
    assert_eq!(cc(&env), (false, false, true, false));

    // cvtlp r0 → packed。往復する。
    let mut env = run_env(1);
    let mut prog = vec![0xf9, 0x50];
    rw(5, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    sem::r_set(&mut env.backend, 0, -12345i32 as u32);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_bytes(&env, DEC + 0x20, 3), pk(&[1, 2, 3, 4, 5], true));
    assert_eq!(cc(&env), (true, false, false, false));
    assert_eq!(r(&env, 3), (DEC + 0x20) as u32);

    // cvtlp で十進オーバーフロー: 12345 → len3 "345" + V。
    let mut env = run_env(1);
    let mut prog = vec![0xf9, 0x50];
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    sem::r_set(&mut env.backend, 0, 12345);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 3), (vec![3, 4, 5], false));
    assert_eq!(cc(&env), (false, false, true, false));
}

#[test]
fn dec_cvtps_cvtsp() {
    // cvtps: "-0123" → "-" + "123"。len4 → dst 5 バイト。
    let mut env = run_env(1);
    let mut prog = vec![0x08];
    rw(4, &mut prog);
    ab(DEC, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[0, 1, 2, 3], true));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_bytes(&env, DEC + 0x20, 5), b"-0123");
    assert_eq!(cc(&env), (true, false, false, false));

    // cvtsp: 往復 "+00042" → packed len5 = 0 0 0 4 2。
    let mut env = run_env(1);
    let mut prog = vec![0x09];
    rw(5, &mut prog);
    ab(DEC, &mut prog);
    rw(5, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, b"+00042");
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 5), (vec![0, 0, 0, 4, 2], false));
    assert_eq!(cc(&env), (false, false, false, false));
    assert_eq!(r(&env, 1), DEC as u32);

    // 不正バイト → 予約オペランド fault（PC は命令先頭）。
    let mut env = run_env(1);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, b"+0004X");
    env.pc = BASE;
    let mut sys = Rec(Vec::new());
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, [sem::scb::RESERVED_OPERAND]);
    assert_eq!(env.pc, BASE);

    // 不正な符号バイトも同様。
    let mut env = run_env(1);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, b"X00042");
    env.pc = BASE;
    let mut sys = Rec(Vec::new());
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, [sem::scb::RESERVED_OPERAND]);
}

#[test]
fn dec_cvtpt_cvttp() {
    const TBL: u64 = DEC + 0x200;
    // 変換表（双方向）: ASCII '0'+d ↔ 0xdC（正）、'@'+d ↔ 0xdD（負）。
    // その他は不正ニブル（検査のため 0xff 埋め）。
    let mut tbl = [0xffu8; 256];
    for d in 0..10u8 {
        tbl[b'0'.wrapping_add(d) as usize] = d << 4 | 0x0c;
        tbl[b'@'.wrapping_add(d) as usize] = d << 4 | 0x0d;
        tbl[(d << 4 | 0x0c) as usize] = b'0' + d;
        tbl[(d << 4 | 0x0d) as usize] = b'@' + d;
    }

    // cvttp: "004C"（'C'='@'+3 = -3）→ packed "0043"-。
    let mut env = run_env(1);
    let mut prog = vec![0x26];
    rw(4, &mut prog);
    ab(DEC, &mut prog);
    ab(TBL, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, b"004C");
    put(&mut env, TBL, &tbl);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 4), (vec![0, 0, 4, 3], true));
    assert_eq!(cc(&env), (true, false, false, false));

    // cvtpt で往復: packed "0043"- → "004" + tbl[0x3D]='C'。
    let mut env = run_env(1);
    let mut prog = vec![0x24];
    rw(4, &mut prog);
    ab(DEC + 0x20, &mut prog);
    ab(TBL, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x40, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC + 0x20, &pk(&[0, 0, 4, 3], true));
    put(&mut env, TBL, &tbl);
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_bytes(&env, DEC + 0x40, 4), b"004C");
    assert_eq!(cc(&env), (true, false, false, false));

    // 表から不正な符号ニブルが返ると abort。
    let mut env = run_env(1);
    let mut prog = vec![0x26];
    rw(4, &mut prog);
    ab(DEC, &mut prog);
    ab(TBL, &mut prog);
    rw(4, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, b"004!"); // '!' → tbl = 0xff → 不正
    put(&mut env, TBL, &tbl);
    env.pc = BASE;
    let mut sys = Rec(Vec::new());
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, [sem::scb::RESERVED_OPERAND]);
}

#[test]
fn dec_ashp() {
    // ashp cnt=+2, src "123" → dst "12300"（len5）。
    let mut env = run_env(1);
    let mut prog = vec![0xf8, 0x8f, 0x02];
    rw(3, &mut prog);
    ab(DEC, &mut prog);
    prog.extend_from_slice(&[0x8f, 0x00]); // round=0
    rw(5, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2, 3], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 5), (vec![1, 2, 3, 0, 0], false));

    // ashp cnt=-1, round=5: "123" → 最下位桁捨て → "12"、
    // 捨てた最上位は 3 → 3+5<10 で丸めなし → "012"。
    let mut env = run_env(1);
    let mut prog = vec![0xf8, 0x8f, 0xffu8];
    rw(3, &mut prog);
    ab(DEC, &mut prog);
    prog.extend_from_slice(&[0x8f, 0x05]);
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2, 3], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 3), (vec![0, 1, 2], false));

    // round=9: 3+9>=10 → 桁上げ "013"。
    let mut env = run_env(1);
    let mut prog = vec![0xf8, 0x8f, 0xffu8];
    rw(3, &mut prog);
    ab(DEC, &mut prog);
    prog.extend_from_slice(&[0x8f, 0x09]);
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2, 3], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    assert_eq!(mem_pack(&env, DEC + 0x20, 3), (vec![0, 1, 3], false));
}

#[test]
fn dec_len_reserved() {
    // 桁数 > 31 は予約オペランド abort（fault → PC は命令先頭）。
    let mut env = run_env(1);
    let mut prog = vec![0x34];
    rw(32, &mut prog);
    ab(DEC, &mut prog);
    ab(DEC + 0x20, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &[0x0c]);
    env.pc = BASE;
    let mut sys = Rec(Vec::new());
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.0, [sem::scb::RESERVED_OPERAND]);
    assert_eq!(env.pc, BASE);
}

#[test]
fn dec_editpc_basic() {
    // パターン: EO$FLOAT 3 → 負数 "−12345" の先頭に '-' を立てて
    // "−123" まで有意化 → EO$INSERT ',' → EO$MOVE 2 → EO$END。
    // dst = "-123,45"。パターン演算子 1 個 = 1 ステップで FPD。
    let mut env = run_env(1);
    let src = DEC;
    let pat = DEC + 0x20;
    let dst = DEC + 0x40;
    let mut prog = vec![0x38];
    rw(5, &mut prog);
    ab(src, &mut prog);
    ab(pat, &mut prog);
    ab(dst, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, src, &pk(&[1, 2, 3, 4, 5], true));
    put(&mut env, pat, &[0xa3, 0x44, b',', 0x92, 0x00]);
    env.pc = BASE;

    step(&mut env).unwrap(); // float3（r3 = pat+1）
    assert_eq!(env.pc, BASE);
    assert!(sem::psl_get(&env.backend) & (1 << psl::FPD) != 0);
    assert_eq!(r(&env, 3), (pat + 1) as u32);
    assert_eq!(mem_bytes(&env, dst, 4), b"-123");

    step(&mut env).unwrap(); // insert ','
    assert_eq!(env.pc, BASE);
    step(&mut env).unwrap(); // move2
    step(&mut env).unwrap(); // EO$END → 完了
    assert_eq!(env.pc, BASE + prog.len() as u64);
    assert!(sem::psl_get(&env.backend) & (1 << psl::FPD) == 0);
    assert_eq!(mem_bytes(&env, dst, 7), b"-123,45");
    // 完了時の制御ブロック: r0=元の桁数・r1=src 先頭・
    // r2/r4=0・r3=EO$END の位置・r5=dst 終端。
    assert_eq!(r(&env, 0), 5);
    assert_eq!(r(&env, 1), src as u32);
    assert_eq!(r(&env, 2), 0);
    assert_eq!(r(&env, 3), (pat + 4) as u32);
    assert_eq!(r(&env, 4), 0);
    assert_eq!(r(&env, 5), (dst + 7) as u32);
    assert_eq!(cc(&env), (true, false, false, true));
}

#[test]
fn dec_editpc_blank_zero() {
    // 値 0 の入力を EO$BLANK_ZERO で fill に置き換える:
    // fill='*', move3 で "***"（零なので全部 fill）→ blank_zero(3)
    // で直前 3 バイトを fill に。dst="***"、Z=1・N=0。
    let mut env = run_env(1);
    let src = DEC;
    let pat = DEC + 0x20;
    let dst = DEC + 0x40;
    let mut prog = vec![0x38];
    rw(3, &mut prog);
    ab(src, &mut prog);
    ab(pat, &mut prog);
    ab(dst, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, src, &pk(&[0, 0, 0], false));
    put(&mut env, pat, &[0x40, b'*', 0x93, 0x45, 0x03, 0x00]);
    env.pc = BASE;
    // 4 演算子（fill, move3, blank_zero, end）= 4 ステップ。
    for _ in 0..3 {
        step(&mut env).unwrap();
        assert_eq!(env.pc, BASE);
    }
    step(&mut env).unwrap();
    assert_eq!(env.pc, BASE + prog.len() as u64);
    assert_eq!(mem_bytes(&env, dst, 3), b"***");
    assert_eq!(cc(&env), (false, true, false, false));
}

#[test]
fn dec_overlap_copy() {
    // 部分重複の movp（dst = src+1）: 結果は UNPREDICTABLE でも
    // クラッシュしない（決定的: 単純な前向きコピー）。
    let mut env = run_env(1);
    let mut prog = vec![0x34];
    rw(5, &mut prog);
    ab(DEC, &mut prog);
    ab(DEC + 1, &mut prog);
    put(&mut env, BASE, &prog);
    put(&mut env, DEC, &pk(&[1, 2, 3, 4, 5], false));
    env.pc = BASE;
    step(&mut env).unwrap();
    // 前向き 1 バイトコピーなので先頭バイトが伝播する（決定的）。
    assert_eq!(mem_bytes(&env, DEC, 4), [0x12, 0x12, 0x12, 0x12]);
}

// ---- VX11: モデル差と補完経路 ----

/// trap コードと `handle_unimpl` の呼出を記録するハンドラ。
#[derive(Default)]
struct Emul {
    trap: Option<u32>,
    trap_pc: u64,
    unimpl: Option<(u64, u64)>,
}

impl TrapHandler for Emul {
    fn handle_trap(&mut self, env: &mut BareEnv, code: u32) -> TrapOutcome {
        self.trap = Some(code);
        self.trap_pc = env.pc;
        TrapOutcome::Handled
    }
    fn handle_unimpl(&mut self, _env: &mut BareEnv, pc: u64, word: u64) -> TrapOutcome {
        self.unimpl = Some((pc, word));
        TrapOutcome::Unimplemented
    }
}

#[test]
fn vx11_model_insn_matrix() {
    // モデル×命令の受理行列（Ref: SPEC-VAX-ARM 付録 B,
    // SPEC-VAX-MICROVAX §3.7）。
    let f = |n: &str| model_feats(n);
    let dec = |w: u128, l: u32, m: u128| decode_model_ex(w, l, false, m).is_some();
    // 文字列比較 6 個（cmpc3=0x29）: 780・ka660・nvax では直接
    // 実行、microvax2 では補完対象。
    for n in ["vax11_780", "ka660", "nvax"] {
        assert!(dec(0x29, 8, f(n)), "{n}: cmpc3");
    }
    assert!(!dec(0x29, 8, f("microvax2")), "microvax2: cmpc3");
    // 十進（movp=0x34）・crc(0x0b)・editpc(0x38)・movtc(0x2e) は
    // フル集合のモデルのみ。
    for w in [0x34u128, 0x0b, 0x38, 0x2e] {
        for n in ["vax11_780", "nvax"] {
            assert!(dec(w, 8, f(n)), "{n}: {w:#x}");
        }
        for n in ["microvax2", "ka660"] {
            assert!(!dec(w, 8, f(n)), "{n}: {w:#x}");
        }
    }
    // octaword（movo=0xfd 0x7d）もフル集合のみ。
    for n in ["vax11_780", "nvax"] {
        assert!(dec(0x7dfd, 16, f(n)), "{n}: movo");
    }
    for n in ["microvax2", "ka660"] {
        assert!(!dec(0x7dfd, 16, f(n)), "{n}: movo");
    }
    // kernel の movc3/movc5 は全モデルで直接実行。
    for n in ["vax11_780", "microvax2", "ka660", "nvax"] {
        assert!(dec(0x28, 8, f(n)), "{n}: movc3");
        assert!(dec(0x2c, 8, f(n)), "{n}: movc5");
    }
    // 予約語（0x0a 未宣言）はどのモデルでも解けない。
    for n in ["vax11_780", "microvax2", "ka660", "nvax"] {
        assert!(!dec(0x0a, 8, f(n)), "{n}: 0x0a");
    }
}

#[test]
fn vx11_model_exec_matrix() {
    // ka660 で cmpc3 は直接実行される（string_cmp を実装）。
    // cmpc3 #1,@#a,@#b —— 等しい 1 バイト同士で Z=1。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[
            0x29, 0x8f, 1, 0, 0x9f, 0, 0x08, 0x01, 0, 0x9f, 1, 0x08, 0x01, 0,
        ],
    );
    put(&mut env, DATA, &[0x42]);
    put(&mut env, DATA + 1, &[0x42]);
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("ka660")).unwrap();
    assert_eq!(env.pc, BASE + 14);
    assert_eq!(cc(&env), (false, true, false, false));
    assert_eq!(sys.unimpl, None);
    assert_eq!(sys.trap, None);

    // nvax で addp4 は直接実行される（decimal あり）。
    // addp4 #1,@#a, #1,@#b —— "1"+"2"="3"。
    let mut env = run_env(1);
    put(
        &mut env,
        BASE,
        &[
            0x20, 0x8f, 1, 0, 0x9f, 0, 0x08, 0x01, 0, 0x8f, 1, 0, 0x9f, 1, 0x08, 0x01, 0,
        ],
    );
    put(&mut env, DATA, &pk(&[1], false));
    put(&mut env, DATA + 1, &pk(&[2], false));
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("nvax")).unwrap();
    assert_eq!(mem_pack(&env, DATA + 1, 1), (vec![3], false));
    assert_eq!(sys.unimpl, None);
}

#[test]
fn vx11_hook_emulates_subset_insn() {
    // hook（既定）では handle_unimpl が補完の役目を負う。
    // Handled ならハンドラが復帰 PC を設定した契約。
    struct EmuOk;
    impl TrapHandler for EmuOk {
        fn handle_trap(&mut self, _env: &mut BareEnv, _code: u32) -> TrapOutcome {
            TrapOutcome::Unimplemented
        }
        fn handle_unimpl(&mut self, env: &mut BareEnv, pc: u64, _word: u64) -> TrapOutcome {
            env.pc = pc + 5; // movp #1,@#a,@#b の命令長ぶん進める
            TrapOutcome::Handled
        }
    }
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x34, 0x8f, 1, 0, 0x50]); // movp #1,@#a,@#b（指定子は未完でもよい）
    env.pc = BASE;
    let mut sys = EmuOk;
    run::step(&mut env, &mut sys, model_feats("ka660")).unwrap();
    assert_eq!(env.pc, BASE + 5);

    // hook を辞退した命令はクラス別の実機 fault に写る ——
    // 十進命令なら補完例外 0xC8（FPD=0）、予約語なら 0x10。
    let mut env = run_env(1);
    put(&mut env, BASE, &[0x34]);
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("ka660")).unwrap();
    assert_eq!(sys.unimpl, Some((BASE, 0x34)));
    assert_eq!(sys.trap, Some(sem::scb::EMUL_START));
    assert_eq!(sys.trap_pc, BASE);

    let mut env = run_env(1);
    put(&mut env, BASE, &[0x0a]); // どの集合にもない語は予約命令 fault
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("ka660")).unwrap();
    assert_eq!(sys.unimpl, None);
    assert_eq!(sys.trap, Some(sem::scb::PRIV_INSN));
}

#[test]
fn vx11_scb_dispatch() {
    // scb では handle_unimpl を呼ばず実機どおりのベクタへ配送。
    let mut env = run_env(1);
    install_params(
        &mut env.backend,
        &Params {
            emul_dispatch: EMUL_DISPATCH_SCB,
            dv_hw: false,
        },
    );
    put(&mut env, BASE, &[0x34]); // movp（decimal、ka660 では省略）
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("ka660")).unwrap();
    assert_eq!(sys.unimpl, None);
    assert_eq!(sys.trap, Some(sem::scb::EMUL_START));
    assert_eq!(sys.trap_pc, BASE); // fault の復帰先は命令先頭

    // FPD=1 の再入は継続ベクタ 0xCC（補完が中断された形）。
    let mut env = run_env(1);
    install_params(
        &mut env.backend,
        &Params {
            emul_dispatch: EMUL_DISPATCH_SCB,
            dv_hw: false,
        },
    );
    put(&mut env, BASE, &[0x38]); // editpc
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::FPD));
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("ka660")).unwrap();
    assert_eq!(sys.trap, Some(sem::scb::EMUL_CONT));

    // 省略された浮動群（movo=hfp）は予約命令 fault 0x10 ——
    // 補完例外の対象は文字列・十進系だけという正本規則。
    let mut env = run_env(1);
    install_params(
        &mut env.backend,
        &Params {
            emul_dispatch: EMUL_DISPATCH_SCB,
            dv_hw: false,
        },
    );
    put(&mut env, BASE, &[0xfd, 0x7d]); // movo
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("ka660")).unwrap();
    assert_eq!(sys.trap, Some(sem::scb::PRIV_INSN));
    assert_eq!(sys.unimpl, None);

    // microvax2 では string_cmp も補完対象 —— cmpc3 が 0xC8 に乗る。
    let mut env = run_env(1);
    install_params(
        &mut env.backend,
        &Params {
            emul_dispatch: EMUL_DISPATCH_SCB,
            dv_hw: true,
        },
    );
    put(&mut env, BASE, &[0x29]); // cmpc3
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, model_feats("microvax2")).unwrap();
    assert_eq!(sys.trap, Some(sem::scb::EMUL_START));
}

#[test]
fn vx11_dv_hw_param() {
    // cvtlp r0,#3,@#dst —— 12345 は 3 桁に収まらず V=1（十進
    // オーバーフロー）。PSL<DV>=1 のとき dv_hw=true なら算術 trap
    // 型 6、dv_hw=false（KA660）ならハードは桁を扱わず trap しない。
    let mut prog = vec![0xf9, 0x50];
    rw(3, &mut prog);
    ab(DEC + 0x20, &mut prog);

    let mut env = run_env(1);
    install_params(
        &mut env.backend,
        &Params {
            emul_dispatch: EMUL_DISPATCH_HOOK,
            dv_hw: true,
        },
    );
    put(&mut env, BASE, &prog);
    sem::r_set(&mut env.backend, 0, 12345);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::DV));
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.trap, Some(sem::scb::arith(sem::scb::at::DEC_OVERFLOW)));
    assert_eq!(sys.trap_pc, BASE + prog.len() as u64); // trap は命令終端へ

    let mut env = run_env(1);
    install_params(
        &mut env.backend,
        &Params {
            emul_dispatch: EMUL_DISPATCH_HOOK,
            dv_hw: false,
        },
    );
    put(&mut env, BASE, &prog);
    sem::r_set(&mut env.backend, 0, 12345);
    sem::psl_put(&mut env.backend, psl::USER | (1 << psl::DV));
    env.pc = BASE;
    let mut sys = Emul::default();
    run::step(&mut env, &mut sys, DEFAULT_FEATS).unwrap();
    assert_eq!(sys.trap, None);
    assert_eq!(cc(&env), (false, false, true, false));
}
