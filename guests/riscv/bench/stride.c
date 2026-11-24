// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// ストライドアクセスの測定。バッファを一定間隔で舐め、応答を
// L1 / L2 / メモリ(+TLB) に分ける。区間 0 は 64B（ライン内で連続）、
// 区間 1 は 512B、区間 2 は 4KiB（ページ境界）。
// 読み出した値は次の読み出しに使わない（スループット側を見る）。
//
// ビルド: このディレクトリの Makefile を見る。

#include "common.h"

#define SIZE (4u * 1024 * 1024) /* 4MiB */
#define PASSES 4

static u64 buf[SIZE / 8];

void bench_main(void)
{
	u64 i;
	u64 p;
	u64 acc = 0;

	for (i = 0; i < SIZE / 8; i++)
		buf[i] = i * 0x9e3779b9UL;

	/* 各区間: stride バイト刻みで PASSES 周。 */
	static const u64 strides[3] = { 64, 512, 4096 };
	u64 s;

	for (s = 0; s < 3; s++) {
		u64 stride = strides[s];
		u64 mark = s * 2;
		MARK(mark, s + 1);
		for (p = 0; p < PASSES; p++) {
			for (i = 0; i < SIZE; i += stride)
				acc += *(volatile u64 *)((u64)buf + i);
		}
		MARK(mark + 1, acc);
	}
	SINK(acc);
}
