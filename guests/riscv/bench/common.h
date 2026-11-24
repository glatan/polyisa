// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// 較正ベンチマークの共通部品。自己計測はしない。実機側は PMU/rdcycle
// または perf で `bench_mark` への書き込みを目印に区間を切り出し、
// polyisa 側は同じ区間の仮想時間と照合する。
//
// `bench_main` は各ベンチが定義する。終了は a7=93 の ecall
// （Linux の exit と同じ規約。スタティックな nolibc ELF としても動く）。

typedef unsigned long u64;
typedef unsigned int u32;

/* 測定区間の目印。i 番区間の開始は 2i、終了は 2i+1 に通し値を書く。 */
static volatile u64 bench_mark[32];
static volatile u64 bench_sink;

#define MARK(i, v) (bench_mark[(i)] = (u64)(v))
#define SINK(v) (bench_sink ^= (u64)(v))

void bench_main(void);

void _start(void)
{
	bench_main();
	/* a7=93: exit（riscv-tests・Linux 共通の規約） */
	__asm__ volatile(
		"li a0, 0\n\t"
		"li a7, 93\n\t"
		"ecall");
	for (;;) {
	}
}
