// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// 整数演算の混在負荷。各車線の累積・xor シフトは反復をまたぐ直列鎖で、
// d/f が同じ反復の a/c の結果を読むので鎖どうしも一部繋がる。
// 依存鎖の深さとスループットの両方を見る。
//
// ビルド: このディレクトリの Makefile を見る。

#include "common.h"

#define ITER (1u << 18)

void bench_main(void)
{
	u64 a = 0x243f6a8885a308d3UL;
	u64 b = 0x13198a2e03707344UL;
	u64 c = 0xa4093822299f31d0UL;
	u64 d = 0x082efa98ec4e6c89UL;
	u64 e = 0x452821e638d01377UL;
	u64 f = 0xbe5466cf34e90c6cUL;
	u64 g = 0xc0ac29b7c97c50ddUL;
	u64 h = 0x3f84d5b5b5470917UL;
	u64 i;

	MARK(0, 1);
	for (i = 0; i < ITER; i++) {
		a ^= a << 7;
		b += 0x9e3779b9UL;
		c ^= c >> 9;
		d += a;
		e ^= e << 13;
		f += c;
		g ^= g >> 17;
		h += 1;
	}
	MARK(1, h);
	SINK(a + b + c + d + e + f + g + h);
}
