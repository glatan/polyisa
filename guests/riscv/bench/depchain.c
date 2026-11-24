// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// 依存鎖のレイテンシ測定。区間 0 はポインタチェイシング（ロード→使用）、
// 区間 1 はレジスタ依存鎖（前の結果を次の入力に使う演算列）。
//
// ビルド: このディレクトリの Makefile を見る。

#include "common.h"

#define NODES 2048
#define ITER 4096
#define CHAIN_ITER (1u << 20)

static u64 nodes[NODES];

void bench_main(void)
{
	u64 i;
	u64 p;
	u64 x;

	/* 単純な巡回リスト。辿る順は定まったステップで巡回する。 */
	for (i = 0; i < NODES; i++)
		nodes[i] = (u64)&nodes[(i * 29 + 1) % NODES];

	MARK(0, 1);
	p = (u64)&nodes[0];
	for (i = 0; i < ITER; i++)
		p = *(volatile u64 *)p;
	MARK(1, p);
	SINK(p);

	MARK(2, 2);
	x = 0x9e3779b97f4a7c15UL;
	for (i = 0; i < CHAIN_ITER; i++)
		x = x * 0x2545f4914f6cdd1dUL + 0x9e3779b9UL;
	MARK(3, x);
	SINK(x);
}
