// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// 分岐の測定。区間 0 はほぼ全て正予測できる条件分岐のループ、
// 区間 1 は擬似乱数で向きが決まる予測困難な条件分岐のループ。
//
// ビルド: このディレクトリの Makefile を見る。

#include "common.h"

#define ITER (1u << 17)

void bench_main(void)
{
	u64 i;
	u64 x;
	u64 acc = 0;

	/* 64 回に 1 回だけ入る側の分岐。規則的なので高い率で当たる。 */
	MARK(0, 1);
	for (i = 1; i <= ITER; i++) {
		if ((i & 63) != 0)
			acc += 1;
		else
			acc ^= 0x9e3779b9UL;
	}
	MARK(1, acc);
	SINK(acc);

	/* xorshift の下位ビットで向きが決まる分岐。 */
	x = 0x9e3779b97f4a7c15UL;
	MARK(2, 2);
	for (i = 0; i < ITER; i++) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
		if (x & 1)
			acc += 1;
		else
			acc ^= x;
	}
	MARK(3, acc);
	SINK(acc);
}
