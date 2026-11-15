# 段階 7–25 作業メモ（ユーザー確認待ち・作業記録）

段階 7（ARM）から段階 25（追加の OS パーソナリティ）までの作業で、
所有者の確認・判断を待っている事項と、各段階の作業記録を一か所に
まとめた一覧。段階 5・6 のメモ（`notes-stage5-6-pending.md`）と
同じ形式で、番号は確認待ち全体で通しとする。

## 確認待ち

### 台帳の「確認」欄（所有者のみが埋められる）

1. 段階 7 着手時点で未確認のまま残っている項目:
   SPEC-MIPS32R2 / SPEC-MIPS64 / SPEC-MIPS-ABI-N32 /
   BIN-DISTRO-AARCH64 / BIN-DISTRO-MIPSEL / BIN-DISTRO-MIPS64 /
   TOOL-MUSLCC-N32（`notes-stage5-6-pending.md` と `references.md`
   を参照）。段階 7 以降に使う分を追加登録したものは後述。

### 仕様・設計の判断

2. 段階 7（ARM）で追加した台帳項目の確認待ち:
   BIN-DISTRO-ARMV5L / BIN-DISTRO-ARMV7L（BusyBox 1.31.0、
   `.testdata/bin-distro-armv5l|armv7l`）、SRC-LINUX-ARM-UAPI
   （v6.6 の `syscall.tbl` と `uapi/asm/unistd.h`、
   `.testdata/uapi-arm`）。いずれも用途 T で、
   所有者の確認欄は空欄のまま。
3. 段階 7（ARM）の実装スコープ判断:
   - 対象は A32（ARM 状態）のみ。Thumb/Thumb-2 は実バイナリの
     エントリが ARM モードで始まること、試作の粗分類デコーダと
     整合させるため対象外。Thumb 命令が出たら未実装として報告。
   - デコーダは大域の粗分類（Insn=領域）で、細かい振り分けは
     `sem` の各エントリ内の固定ビット検査で行う。oracle テストも
     領域までの突き合わせとし、udf は media 領域（恒久的未定義は
     意味論側の責務）とした。
   - MCRR/MRRC（`vmov d0, r0, r1` 等のレジスタ対転送）は
     110 帯の `cp_ls` 領域に入る（Arm ARM の解読表どおり）。
   - kuser ヘルパー領域（0xffff0fa0 等）は未実装。
     musl 1.31 は `mrc p15, c13` の TLS 経路を選ぶため
     実バイナリでは未到達。将来の配布物で要るなら段階 25 の
     OS パーソナリティ側で扱う。
4. `__ARM_NR_cmpxchg` の番号は UAPI ヘッダに現れない
   （`arch/arm/include/asm/unistd.h` の内部定義、
   `__ARM_NR_BASE+0xfff0`=0xffff0）。初版は誤って連番の
   0xf0007 を置いていた。musl では kuser ヘルパー経由が
   主経路のため影響は限定的だが、カーネルの定義に合わせて修正済み。

## 段階ごとの作業記録

### 段階 7（ARM、A32・EABI）

- 追加: `guests/arm`（spec/armi.rs = 領域の粗分類 ISADL、
  src/sem.rs ≈ 3000 行の意味論。条件実行、PC+8 読み、
  LDM/STM、乗算系、排他ロード/ストア、バリア、CP15 TLS、
  VFP 転送・f64 演算・変換・比較を実装）。
- 追加: `crates/os-linux/src/arm.rs`（EABI 番号表 ≈ 450 件、
  name 表、errno/フラグ）と `crates/os-linux/src/arm/sys.rs`
  （syscall 機械。ファイル・mmap・brk・時計・uname・
  getdents64・set_tls/cacheflush 等）。
- 追加: `crates/cli/src/run_arm.rs`（ELF32 e_machine=40 の
  ディスパッチ、armv5/armv7 モデル、--cpu 選択）。
- テスト: `guests/arm/tests/sem.rs`（条件実行・PC+8 の
  意味論テスト）、`heavy_oracle_llvm.rs`（llvm-mc 符号化と
  領域の突き合わせ）、`heavy_abi_arm.rs`（UAPI tbl との
  番号突き合わせ ≈ 250 名）、`heavy_program_arm.rs`
  （clang -nostdlib の hi/fib と両 busybox のコマンド群、
  VFP 経由の awk 含む）。
- 修正: arm の番号表が `vserver`(313) の欠落で 313–399 帯が
  全て -1 になっていたのを UAPI 突き合わせで発見・修正
  （openat=322 等に是正。name 表も同時に修正）。
- 修正: `__ARM_NR_cmpxchg` を 0xf0007 → 0xffff0 に是正。
- refs:check ok（113 ids）、devtool check ok、
  全ワークスペースのフルテスト実施済み（件数はコミット時点の
  出力を参照）。

## 参考

- 段階の完了条件は `design/roadmap.md` の各段階の表。
- 台帳の規則は `references.md` の冒頭。
- 前段階の記録は `notes-stage5-6-pending.md`。
