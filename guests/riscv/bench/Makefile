# Copyright (c) polyisa contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# 較正ベンチマークのビルド。clang＋lld で freestanding の RV64 ELF を作る
# （heavy_conformance_rv64ui.rs の慣習と同じ道具）。出来上がる ELF は
# スタティックな nolibc バイナリで、実機（Linux のユーザーモードとして
# exec するか PMON 系の素の環境）と polyisa の両方で動く。
#
#   make            全ベンチを build/ にビルド
#   CLANG=clang     ホストの clang（--target=riscv64-unknown-elf）
#   LLD=ld.lld      lld（rust-lld でもよい）
#
# 実機計測は bench_mark[] への書き込みを区間の目印にして、perf stat や
# rdcycle 計測で区間のサイクルを取る。結果の記録は docs/guides/calibration.md を見る。

CLANG ?= clang
LLD ?= ld.lld
MARCH ?= rv64g
MABI ?= lp64d

CFLAGS := --target=riscv64-unknown-elf -march=$(MARCH) -mabi=$(MABI) \
	-mcmodel=medany -O2 -nostdlib -fvisibility=hidden

BENCHES := depchain istream branch stride

all: $(BENCHES:%=build/%.elf)

build/%.elf: %.o | build
	$(LLD) -flavor gnu -m elf64lriscv -o $@ $<

%.o: %.c common.h
	$(CLANG) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

clean:
	rm -rf build $(BENCHES:%=%.o)

.PHONY: all clean
