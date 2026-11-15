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

- 段階 8 レビュー（サブエージェント）の対応記録:
  - 修正済: isel の選択極性（C1, 逆だった）、OE 形式の
    基底 XO 照合（C2）、bclrl が新 LR を飛び先に読む誤り
    （C3）、lve*/stve*/lvsl/lvsr の未実装（C4, 実装追加）、
    statx レイアウト（C5）、sysinfo レイアウト（C6）、
    addic/subfic/mulli/cmpwi/cmplwi/tdi/twi の r0=0 読み
    （M2）、neg の CA 破壊（M3）、vslo/vsro の 8 倍シフト
    （M4）、div OE 形式の OV 欠落（M16）、access 系の
    mode 無視（M14）、statfs64/fstatfs64 の引数位置
    （M15）、powerpc 固有 ioctl 定数（M1）。
  - 未対応（確認待ち・次段階案件）: FPSCR/FPCC/CR1 の
    更新と RN 反映（M7/M8/M9）、lxvl/stxvl の LE 配置
    （M6）、vinsert*/xvcvsxdsp/xscv*dsp/xxbr*/vsld/vsrd/
    lqarx/stqcx/stq/mcrxrx/ftdiv/mfocrf 複数フィールド/
    lswx カウント 0（M5/M10/M11/M12/Minor 群）、
    xvmadd 系の単一丸め化（M13）、musl 動的アプレットの
    a_crash 残存（activate_group の assert(!avail_mask)
    破れ。head meta が prev=next=自己でありながら
    ctx.active 残留。queue/dequeue のリスト操作または
    lwarx/stwcx 経路の差分を要調査）、TCGETS 系の
    termios 実書き込み、O_NOFOLLOW 等 open フラグ、
    dirfd!=AT_FDCWD、epoll/poll、rt_sigpending、
    getresuid、setrlimit、sched_getaffinity、prctl、
    lswi/stswi 残件、scv 区別、ppc32 意味論、ELFv1。
  - レビュー報告の「検証済み正しい」: bo_ok/CTR/CR、
    larx/stcx 幅、ldx/stx/bswap_ls、shift 系、
    lane/put_lane 系ヘルパ、vperm/vsel/vsldoi、
    x31_arith 大体、lq、put_stat、uname、CR0.SO。

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

### 段階 9（IR と JIT）

- 追加: `crates/ir`（`inst.rs` = `Wid`/`Id`/`Inst`/`Ir`/
  `Recorded` の SSA IR、`rec.rs` = `Backend` を実装する
  記録器 `IrBackend`、`exec.rs` = 任意の `Concrete` バックエンド
  上で IR を解釈する `exec`、`opt.rs` = 定数畳み込み・コピー
  伝播・CSE・死んだストア除去・DCE を回す `optimize`）。
  `Concrete` は `Backend` に「値 ⇔ u128」「Bool ⇔ bool」
  「Exit → ExitClass」の橋を足すだけの小さい trait。
- `IrBackend` の方針: `if_then_else`/`if_then` は両枝を
  `Inst::If` として記録し、`raise` は `IrExit::Raise`、
  `abort` で `Exit`/`Unimpl` を確定する。helper と parameter は
  まだ IR に落とさず、helper は `Unimpl`（ブロック境界で
  インタプリタへ戻す）、parameter はインタプリタと同じく
  panic。フォールトし得るメモリ操作には `pc`/`next` を焼く。
- 追加: `crates/host`（`exec_mem.rs` = mmap で RW 確保→
  書き込み→`mprotect` で RX にする W^X の実行メモリ）。
- 追加: `crates/jit`（`ctx.rs` = `#[repr(C)]` の `RtCtx` と
  例外の詰め替え、`rt.rs` = 生成コードから呼ぶメモリ/重い
  演算のランタイム関数、`x64.rs` = 命令エミッタと IR→x86-64
  の `compile`、`lib.rs` = PC を鍵にしたブロックキャッシュ・
  熱カウンタ・記録→IR 解釈→コンパイル→呼び出しの `Jit`）。
- 実行経路: ブロックは `Translate::record` で `Recorded` にし、
  熱くなるまでは `polyisa_ir::exec` で解釈し、しきい値に
  達したら `x64::compile` して `BlockFn` を呼ぶ。出口は
  `BlockExit::Next/Raise/Unimpl` に戻し、`Unimpl`・例外・
  トラップ境界は常にインタプリタ側の処理へ戻す。コード
  ページへの書き込みは `invalidate` でブロックを破棄する。
- x64 レイアウトの修正: 値スロットとスクラッチ領域の開始を
  16 バイト整列（`SCRATCH=16`、`VALS=80`）に直し、`u128`
  の読み書きで misaligned pointer dereference していた
  クラッシュを解消。
- ランナ統合（既定は従来どおりインタプリタ。`POLYISA_JIT`
  で JIT が有効）:
  - AArch64: `dispatch_a64<B: Backend>` に意味論を抽出し、
    `A64Tx` が 32 命令まで記録（`svc`・未対応デコード・
    フロー操作でブロックを閉じる）。
  - ARM: `dispatch_a32<B: Backend>` に抽出し、`ArmTx` は
    CPSR から条件式を作って `if_then` で包むことで条件付き
    実行を記録。`svc`/未対応で境界。
  - x86: 既存のデコードと `dispatch` をそのまま `X86Tx` に
    使い、トラップ/syscall の手前ではインタプリタへ戻して
    `TrapHandler`・`after_step` の振る舞いを保つ。
- テスト:
  - `crates/engine/src/interp.rs` に「同じ意味論を
    インタプリタ直接と 記録→optimize→exec で比べる」
    単体テスト 6 件（算術/メモリ/if 両枝/分岐・ジャンプ/
    例外/メモリフォールト）。
  - `crates/ir/src/opt.rs` に pass 別の単体テスト 10 件
    （畳み込み・コピー伝播・CSE・DSE 3 件・Get 転送・DCE・
    定数条件 If の展開）。
  - `crates/jit/src/lib.rs` に生成コードを実際に呼ぶ
    スモーク 2 件（`Next` 経路と `Raise` 経路）。
  - `crates/cli/tests/heavy_jit_diff.rs` に 3 ISA（AArch64・
    ARM・x86-64）の interpreter vs JIT 差分テスト。
    clang -nostdlib の小さい静的 ELF（fib→`55` 表示）を
    両経路で走らせ、最終状態・出力・終了を突き合わせる。
    `reqs.rs` に `heavy_jit_diff`（clang 必須）を登録。
- 設計からの明示的な範囲:
  - helper/parameter の IR 化は未対応（該当ブロックは
    インタプリタへフォールバック）。正しさ優先で速度は追わ
    ない。
  - フォールト境界を跨ぐメモリ操作の移動はしない
    （DSE も Store/Exit の手前の Set は消さない）。
  - 生成コードの最適度は低い（値スロット経由・重い演算は
    ランタイム呼び出し）。オラクルとの一致を優先。
- 完了条件: `heavy_jit_diff` の 3 件が green。

## 参考

- 段階の完了条件は `design/roadmap.md` の各段階の表。
- 台帳の規則は `references.md` の冒頭。
- 前段階の記録は `notes-stage5-6-pending.md`。
