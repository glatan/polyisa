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
    // 0x08 は予約オペコード → 予約命令 fault 0x10。
    put(&mut env, BASE + 0x10, &[0x08]);
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
