// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VAX の骨格検査（段階23・VX2/VX3）。オペコード空間（1/2 バイト語）
//! のデコード、CPU モデル宣言・機能旗・挙動パラメータの形、
//! オペランド指定子の読み取り・長さ・適合・再符号化と命令全体の
//! ストリーム消費を見る。命令単位の実行検査は VX4 以降でこの
//! ファイルに足す。
//! 出典は SPEC-VAX-ARM と SPEC-VAX-MICROVAX である。

use polyisa_guest_vax::specifier::*;
use polyisa_guest_vax::*;

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
    // 未宣言の語と、接頭だけの語は命令にならない。
    assert_eq!(dec1(0x08), None);
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
    assert_eq!(dec1(0x08), None);
    assert_eq!(dec2(0xfd, 0x00), None);
    // insn_ops の match は Insn 全バリアントを網羅する
    // （コンパイル時の保証）。INSNS メタ表にも代表名がある。
    for name in ["movl", "addl2", "cmpl", "beql", "movc3", "movo"] {
        assert!(INSNS.iter().any(|m| m.name == name), "{name}");
    }
}
