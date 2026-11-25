// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! 総称意味論と直接実装の性能比較（段階1完了条件3の記録用）。
//!
//! 手順はロードマップ段階1の完了条件3に従う。代表命令について
//! バックエンド経由と素直な整数演算の時間を比べ、差を記録する。
//! 判定（10%超の調査・ADR）は結果を見て行う。このテスト自体は
//! 時間の長短で合否を変えない（決定的な検証ではない）.
//!
//! 結果の記録と受入れ判断は [ADR-0012](../../docs/architecture/execution.md)
//! にある。数値を変えたらそちらも更新する.

use polyisa_engine::interp::InterpBackend;
use polyisa_sem::{Backend, F64 as FW64, W64};
use std::hint::black_box;
use std::time::Instant;

const ITERS: u64 = 200_000;

#[test]
fn bench_generic_vs_direct() {
    // 直接の u64 加算。
    let t0 = Instant::now();
    let mut acc = 0u64;
    for i in 0..ITERS {
        acc = black_box(acc.wrapping_add(black_box(i)));
    }
    let direct = t0.elapsed();
    black_box(acc);

    // バックエンド経由の加算。
    let mut b = InterpBackend::new(8);
    let t0 = Instant::now();
    let mut acc = 0u64;
    for i in 0..ITERS {
        acc = b.add::<W64>(black_box(acc), black_box(i));
        black_box(acc);
    }
    let generic = t0.elapsed();
    black_box(acc);

    // 浮動小数点加算（generic のみ。softfloat 委譲の費用の目安）。
    let mut b = InterpBackend::new(8);
    let t0 = Instant::now();
    let mut acc = f64::from_bits(0x3FF0_0000_0000_0000);
    for _ in 0..ITERS {
        let x: u64 = b.add::<FW64>(
            black_box(f64::to_bits(acc)),
            black_box(0x3FF0_0000_0000_0000),
        );
        acc = f64::from_bits(black_box(x));
        black_box(acc);
    }
    let fadd = t0.elapsed();

    eprintln!(
        "bench generic_vs_direct: iters={ITERS} direct={direct:?} generic={generic:?} fadd={fadd:?}"
    );
    // 記録用であり、合否には使わない。10%超の判定は結果の記録を見て行う。
}
