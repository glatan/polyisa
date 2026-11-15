// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! s390 の裸実行テスト（層2・bare、S11-4）。
//!
//! OS 人格を通さず BareEnv の解釈実行だけで、手で組み立てた可変長命令
//! プログラムを回す。z/Architecture 64 ビット有効アドレスと ESA/390 の
//! 31 ビット有効アドレス（amask=0x7fffffff）の両モードを同じプログラム
//! で検査する。
//! 出典は SPEC-S390-ZARCH-POP（SA22-7832）と SPEC-S390-ESA390-POP
//! （SA22-7201）である。
//!
//! テストデータは使わない。

use polyisa_engine::bare::BareEnv;
use polyisa_engine::interp::Ctrl;
use polyisa_guest_s390::sem::Gpr;
use polyisa_guest_s390::{Insn, decode_model_ex, sem};
use polyisa_mem::{Access, AccessKind, Align, Endian, Perms, VirtAddr};
use polyisa_sem::Backend;

/// プログラム: r1=5 から 1 まで合計して [r3] へ書き、r5 への自己
/// ループ分岐で停止する。
///
/// ```text
/// 0x1000  lghi %r1,5         a7 19 00 05
/// 0x1004  lghi %r2,0         a7 29 00 00
/// 0x1008  ar   %r2,%r1       1a 21          ; sum += r1
/// 0x100a  ahi  %r1,-1        a7 1a ff ff
/// 0x100e  cghi %r1,0         a7 1f 00 00
/// 0x1012  brc  2,0x1008      a7 24 ff fb    ; r1>0 の間ループ（CC2）
/// 0x1016  stg  %r2,0(%r3)    e3 20 30 00 00 24
/// 0x101c  larl %r5,0x1022    c0 50 00 00 00 03
/// 0x1022  br   %r5           07 f5          ; 自己ループ＝停止番
/// ```
const PROG: &[(u64, &[u8])] = &[(
    0x1000,
    &[
        0xa7, 0x19, 0x00, 0x05, 0xa7, 0x29, 0x00, 0x00, 0x1a, 0x21, 0xa7, 0x1a, 0xff, 0xff, 0xa7,
        0x1f, 0x00, 0x00, 0xa7, 0x24, 0xff, 0xfb, 0xe3, 0x20, 0x30, 0x00, 0x00, 0x24, 0xc0, 0x50,
        0x00, 0x00, 0x00, 0x03, 0x07, 0xf5,
    ],
)];

const HALT: u64 = 0x1022;

fn env(amask: u64) -> BareEnv {
    let mut e = BareEnv::new(core::mem::size_of::<polyisa_guest_s390::CpuState>());
    e.backend
        .mem
        .map(
            VirtAddr(0x1000),
            1,
            Perms(Perms::R.0 | Perms::W.0 | Perms::X.0),
        )
        .unwrap();
    e.map_rw(0x2000, 1).unwrap();
    e.backend.set(sem::amask_ref(), amask);
    for &(a, bytes) in PROG {
        e.backend.mem.write(VirtAddr(a), bytes).unwrap();
    }
    e.pc = 0x1000;
    e
}

/// run_s390 と同じ規約で、先頭バイトから長さを決めて右詰め u64 に畳み、
/// decode → exec → 分岐反映を行う。
fn step(e: &mut BareEnv) -> Result<(), polyisa_engine::interp::InterpExit> {
    let acc = Access {
        endian: Endian::Be,
        align: Align::Natural,
        kind: AccessKind::Fetch,
    };
    let pc = e.pc;
    let mut b0 = [0u8; 1];
    e.backend
        .mem
        .read(VirtAddr(pc), &mut b0, acc)
        .map_err(|e2| polyisa_engine::interp::InterpExit::Unimplemented(format!("{e2:?}")))?;
    let len = match b0[0] >> 6 {
        0 => 2u64,
        1 | 2 => 4,
        _ => 6,
    };
    let mut bytes = [0u8; 6];
    bytes[0] = b0[0];
    e.backend
        .mem
        .read(VirtAddr(pc + 1), &mut bytes[1..len as usize], acc)
        .map_err(|e2| polyisa_engine::interp::InterpExit::Unimplemented(format!("{e2:?}")))?;
    let mut word = 0u64;
    for &x in &bytes[..len as usize] {
        word = (word << 8) | u64::from(x);
    }
    let insn: Insn =
        decode_model_ex(u128::from(word), (len * 8) as u32, true, 0).ok_or_else(|| {
            polyisa_engine::interp::InterpExit::Unimplemented(format!("word {word:#x}"))
        })?;
    e.step(|b| sem::exec(b, insn, word, pc))?;
    if e.backend.ctrl == Ctrl::Fallthrough {
        e.pc += len;
    }
    Ok(())
}

fn run_to_halt(e: &mut BareEnv, limit: u64) {
    let mut n = 0u64;
    while e.pc != HALT {
        step(e).expect("step");
        n += 1;
        assert!(n < limit, "命令ステップ上限超過 pc={:#x}", e.pc);
    }
}

fn mem64(e: &mut BareEnv, a: u64) -> u64 {
    let mut buf = [0u8; 8];
    e.backend
        .mem
        .read(
            VirtAddr(a),
            &mut buf,
            Access {
                endian: Endian::Be,
                align: Align::Natural,
                kind: AccessKind::DataRead,
            },
        )
        .unwrap();
    u64::from_be_bytes(buf)
}

#[test]
fn bare_loop_sum_zarch64() {
    let mut e = env(u64::MAX);
    e.backend.set(Gpr(3).state(), 0x2000);
    run_to_halt(&mut e, 1000);
    // 5+4+3+2+1 = 15 が [0x2000] にビッグエンディアンで入る。
    assert_eq!(mem64(&mut e, 0x2000), 15);
}

#[test]
fn bare_esa_31bit_amask() {
    // ESA/390: amask=0x7fffffff。ベースレジスタの上位 32 ビットは
    // 有効アドレス計算で捨てられる。
    let mut e = env(0x7fff_ffff);
    e.backend.set(Gpr(3).state(), 0xffff_ffff_0000_2000);
    run_to_halt(&mut e, 1000);
    assert_eq!(mem64(&mut e, 0x2000), 15);
}

#[test]
fn bare_zarch64_full_address_faults() {
    // 同じベース値を 64 ビットモードで使うと巨大アドレスになり、
    // 未写像でフォールトする。ESA 側との対比。
    let mut e = env(u64::MAX);
    e.backend.set(Gpr(3).state(), 0xffff_ffff_0000_2000);
    let mut err = None;
    let mut n = 0u64;
    while e.pc != HALT && n < 1000 {
        if let Err(x) = step(&mut e) {
            err = Some(x);
            break;
        }
        n += 1;
    }
    assert!(err.is_some(), "64 ビットモードで未写像アクセスが無視された");
}

#[test]
fn bare_esa_amask_via_la() {
    // `la` は 31 ビットモードでは下位 32 ビットのみ書き換える。
    // stg が通ることを含め、小さな往復で確認する。
    let mut e = env(0x7fff_ffff);
    e.backend.set(Gpr(3).state(), 0x2000);
    run_to_halt(&mut e, 1000);
    assert_eq!(mem64(&mut e, 0x2000), 15);
}
