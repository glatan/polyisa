// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! A64 デコーダの符号化表回帰試験。
//!
//! musl ld.so / busybox の実行で見つかった符号化の誤り・未実装を押さえる。
//! - `umulh` の op ビット組み合わせ
//! - subs 拡張形式（cmp sp, x2 系スタックプローブ）
//! - AdvSIMD modified-immediate / 複製・要素移動・128bit ロードストア

use polyisa_guest_aarch64::{Insn, decode};

#[test]
fn fp_simd_instructions_decode() {
    for (name, w, want) in [
        ("dup v0.16b,w1", 0x4e010c20u32, Insn::DupGen),
        ("dup v0.8b,w1", 0x0e010c20, Insn::DupGen),
        ("mov x1,v0.d[0]", 0x4e083c01, Insn::Umov),
        ("mov x1,v0.d[1]", 0x4e183c01, Insn::Umov),
        ("mov v0.d[0],x1", 0x4e081c20, Insn::InsGen),
        ("str q0,[x0]", 0x3d800000, Insn::StrQVu),
        ("str q0,[x0,#0x40]", 0x3d801000, Insn::StrQVu),
        ("ldr q0,[x0,#0x20]", 0x3dc00800, Insn::LdrQVu),
        ("stur q0,[x4,-0x10]", 0x3c9f0080, Insn::SturQ),
        ("ldur q0,[x4,-0x20]", 0x3cde0080, Insn::LdurQ),
        ("stp q0,q0,[x0,#0x20]", 0xad010000, Insn::StpQOff),
        ("stp q0,q0,[x3,#0x40]!", 0xad820060, Insn::StpQPre),
        ("ldp q0,q1,[x0,#0x20]", 0xad410400, Insn::LdpQOff),
        ("str d0,[x0,#8]", 0xfd000400, Insn::StrDVu),
        ("ldr d0,[x0,#8]", 0xfd400400, Insn::LdrDVu),
        ("str s0,[x0,#4]", 0xbd000400, Insn::StrSVu),
        ("ldr s0,[x0,#4]", 0xbd400400, Insn::LdrSVu),
        ("fmov w1,s0", 0x1e260001, Insn::FmovWS),
        ("fmov s0,w1", 0x1e270020, Insn::FmovSW),
        ("fmov x1,d0", 0x9e660001, Insn::FmovXD),
        ("fmov d0,x1", 0x9e670020, Insn::FmovDX),
        ("ldp d0,d1,[sp,#0x20]", 0x6d4107e0, Insn::LdpDOff),
        ("stp d8,d9,[sp,#-0x20]!", 0x6da22bfd, Insn::StpDPre),
        ("str b0,[x0,#1]", 0x3d000400, Insn::StrBVu),
        ("ldr h0,[x0,#2]", 0x7d400800, Insn::LdrHVu),
        ("ldp s0,s1,[x0]", 0x2d400400, Insn::LdpSOff),
        ("movi v31.4s,#0", 0x4f00041f, Insn::ModImm),
    ] {
        assert_eq!(decode(u128::from(w), 32), Some(want), "{name} word={w:#x}");
    }
}

#[test]
fn integer_instructions_decode() {
    for (name, w, want) in [
        ("umulh x2,x1,x0", 0x9bc07c22u32, Insn::Umulh),
        ("strb wzr,[x0]", 0x3900001f, Insn::StrbU),
        ("str xzr,[sp,#1024]", 0xf90203ff, Insn::StrUX),
        ("cmp sp,x2 (subs_ext)", 0xeb2263ff, Insn::SubsExt),
        ("add sp,sp,x2 (add_ext)", 0x8b2263ff, Insn::AddExt),
        ("clz w2,w1", 0x5ac01022, Insn::Clz),
        ("rbit w4,w0", 0x5ac00004, Insn::Rbit),
        ("csel x3,x4,x5,hs", 0x9a852083, Insn::Csel),
        ("ldp x25,x26,[sp],#0x40", 0xa8c46bf9, Insn::LdpXPost),
        ("ldr x5,[x0,x2,lsl#3]", 0xf8627805, Insn::LdrRegX),
    ] {
        assert_eq!(decode(u128::from(w), 32), Some(want), "{name} word={w:#x}");
    }
}
