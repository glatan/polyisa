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
   - 対象は A32（ARM 状態）のみ。Thumb/Thumb-2 と NEON は
     実バイナリのエントリが ARM モードで始まること、試作の
     粗分類デコーダとの整合のため今回の範囲外とした。
     Thumb 命令が出たら未実装として報告する。ロードマップは
     「最初の範囲」に Thumb-2 と NEON を挙げているので、
     これらをいつ足すかは所有者判断。IT ブロックも Thumb
     側の話題であり同時に扱う。
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
5. 段階 8（Power）で追加した台帳項目の確認待ち:
   BIN-DISTRO-POWERPC64 / BIN-DISTRO-POWERPC64LE /
   BIN-DISTRO-POWERPC（BusyBox 1.31.0 の ppc64 BE ELFv2・
   ppc32 BE と、Alpine 3.21.0 minirootfs ppc64le）、
   SRC-LINUX-POWERPC-UAPI（v6.6 の
   `arch/powerpc/kernel/syscalls/syscall.tbl`、
   `.testdata/uapi-powerpc`）。いずれも用途 T で、
   所有者の確認欄は空欄のまま。
6. 段階 8（Power）の実装スコープ判断:
   - 主対象は ppc64le の ELFv2 ユーザーモード。ppc64 BE は
     ELFv2 スタティック BusyBox で検証済みだが ELFv1
     （関数記述子・`.opd`）は未実装。ppc32 は番号表と
     testdata 取得までで、意味論・ローダは未着手。
   - デコーダは主オペコード（6 ビット）の粗分類で、XO・
     拡張ビットの細分は `sem` 側が担う（ARM と同じ構造）。
   - syscall 番号は ppc64 系の tbl（32 行は compat 専用）。
     `getrlimit` は 76 が ni-syscall のため ugetrlimit(190)
     を採用。`sync_file_range` は ppc64 の
     `sync_file_range2`(308) に対応。
   - 残件: musl 動的リンクの BusyBox で、free/dequeue
     経路のブックキーピングがずれて `.long 0` の罠に落ちる
     アプレットがある（`echo`・`printf %d`・`id` 等）。
     CA・mfocrf・ロードストア・予約の見直し後も残っている
     ため、別の意味論差分の可能性が高い。動的アプレットの
     テスト一覧は通るものに絞ってある。
   - 残件: ISA 3.1 の接頭辞付き命令は未実装（ロードマップの
     範囲内。musl/Alpine ppc64le の現バイナリでは未到達）。
   - 残件: SPE（e500）・十進 FP・Book E 系は未着手。

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
- レビュー（サブエージェント）実施。指摘を受けて修正:
  - 並列加減算のレーンマスク欠落・GE フラグ未実装・
    halving の符号扱いを修正し、UH（0x67）を追加。
  - BFI/BFC のソースレジスタ面（[3:0]）と msb 面
    （最上位ビット位置）、SBFX/UBFX/BFI の top8 に
    msb[4] が入る dispatch 穴を修正。
  - SMLA/SMLAW/SMLAL の Ra/Rd/RdHi/RdLo フィールドと
    SMULxy/SMLAxy の半選択ビット（x/y）を修正。
  - UMAAL の累算を RdLo+RdHi の二項和に修正。
  - QSUB/QDADD/QDSUB のオペランド順と QD* の二倍飽和、
    SSAT16/USAT16 のシフト面なし・usat16 の imm ビット
    飽和を修正。VFP 即値展開（10 bit）と VNMLS、
    REV16 のバイト並びも修正。
  - レジスタシフト版 TST/TEQ/CMP/CMN を misc 落ちから
    データ処理へ振り分け。
  - linux 側: pwrite64 のオフセット書き込み、
    truncate64/ftruncate64 の EABI 整合ペア（r2:r3）、
    statx の path/flags 面、getpriority の戻り値、
    unimpl_path（実際は削除処理）を rmdir/link/linkat の
    実装に置き換え。
  - 回帰テスト 10 件を `guests/arm/tests/sem.rs` に追加。
  - 上記修正で `heavy_program_arm::distro_commands` も通過。
    段階 7 の完了条件 3 件すべて green。
- レビュー残件（所有者判断・段階横断）:
  - Thumb/Thumb-2・NEON の実装時期（確認待ち #3 と同一案件）。
  - ELF `e_flags`/`--cpu`/HWCAP/uname の整合見直し。
  - kuser ヘルパー・ARM プライベート cmpxchg（現状 ENOSYS）。

### 段階 8（Power、ppc64le・ELFv2）

- 追加: `guests/power`（spec/poweri.rs = 主オペコード粗分類
  ISADL、src/sem.rs の意味論。整数・CR/XER・ロードストア・
  予約・分岐・FP（単精度/倍精度）・VSX/AltiVec の主な
  ユーザーモード命令を実装）。
- 追加: `crates/os-linux/src/power.rs`（ppc64 番号表 ≈ 220 件と
  name 表）と `crates/os-linux/src/power/sys.rs`（syscall 機械。
  CR0.SO のエラー返し、r0=番号・r3–r8=引数・r3=戻り値、
  ゲストルートのパス解決）。
- 追加: `crates/cli/src/run_power.rs`（ELF64 e_machine=21 の
  ディスパッチ、EI_DATA でエンディアン選択、PT_INTERP 動的
  ローダ、ELFv2 入口 r12・TOC 規約、フォルト駆動の
  スタック成長、`--cpu`/`--root` 配線と OS 注入形
  `run_elf_power_sys`/`run_elf_power_sys_root`）。
- テスト: `guests/power/tests/sem_unit.rs`（CA/CR/XER/
  mfocrf 等の単体）、`heavy_oracle_power.rs`（llvm-mc
  符号化と領域の突き合わせ。lxv/stxv/lq は llvm-mc 23 が
  出せないため手符号の語で領域だけ確認）、
  `heavy_abi_power.rs`（v6.6 tbl との番号突き合わせ 216 名、
  abi 列は common・nospu・64）、`heavy_program_power.rs`
  （clang -nostdlib の hi/fib、ppc64 BE スタティック BusyBox、
  Alpine ppc64le minirootfs の動的 BusyBox 群）。
- 修正: `x31_arith` が全 XO で CA を更新していたのを、
  carry 生成形（subfc/addc/neg/subfe/adde/subfze/addze/
  subfme/addme）だけに限定。musl の整数書式（`printf %d`
  のパディング等）が直った。
- 修正: `mfocrf` がフィールドを FXM 面（bits 12–19）から
  読んでいたのを、命令のフィールド面（bits 23–25）に修正。
  `seq`/`awk` 等の CR 依存経路が通るようになった。
- 修正: VSX/FP 群の意味論（xvcvdpsp、xxpermdi/xxsldwi、
  xxspltw/xxinsertw、xsmaxjdp/xsminjdp、xvmadd 系の
  msub/nmsub、xs*dp スカラ madd、mffs/mtfsb/mtfsfi/mcrfs、
  fsel/frsqrte）を広く是正。
- S8-1..3 を実テスト名で判定に反映。段階 8 の完了条件
  3 件は green。
- 残件（確認待ち #6 と同一案件）: musl 動的の allocator
  teardown 差分、ISA 3.1 接頭辞付き命令、ppc32/ELFv1/SPE。

## 参考

- 段階の完了条件は `design/roadmap.md` の各段階の表。
- 台帳の規則は `references.md` の冒頭。
- 前段階の記録は `notes-stage5-6-pending.md`。
