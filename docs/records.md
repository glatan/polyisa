# 段階の対応記録と残件

この文書は、完了した段階の定義と対応した内容、残っている事項の記録である。ロードマップ（`design/roadmap.md`）は未着手の段階の定義と作業計画、共通の着手条件・完了条件を持つ。設計との差の正本は `gaps.md` であり、ここではその行番号を参照する。

## 段階の一覧

| 段階 | 対象 | 状態 |
|---|---|---|
| 0 | 基盤 | 完了 |
| 1 | RISC-V の縦の一本 | 完了 |
| 2 | 抽象の試作 | 完了 |
| 3 | MIPS | 完了 |
| 4 | x86 | 完了 |
| 5 | MIPS の本実装 | 完了 |
| 6 | AArch64 | 完了 |
| 7 | ARM | 完了 |
| 8 | Power | 完了 |
| 9 | IR と JIT | 完了 |
| 10 | 十進演算と非 IEEE 浮動小数点 | 完了 |
| 11 | s390 系 | 完了 |
| 12 | WebAssembly と WASI | 完了 |
| 13 | x86 の残り | 完了 |
| 14 | m68k | 完了 |
| 15 | SPARC | 完了 |
| 16 | Alpha | 完了 |
| 17 | PA-RISC | 完了 |
| 18 | SuperH | 完了 |
| 19 | LoongArch | 完了 |
| 20 | OpenRISC | 完了 |
| 21 | IA-64 | 完了 |
| 22 | Hexagon | 完了 |
| 23 | VAX | 完了 |
| 24 | PDP-11 | 未着手（作業計画は `design/roadmap.md`） |
| 25-29 | OS パーソナリティ・システムコール段階 5・タイミング・ホスト移植・GDB | 未着手 |

## 対応した内容

### 段階 0：基盤

ワークスペース、検査、基礎のクレートを用意する。

- ワークスペースの定義、`Taskfile.yml`、nextest の設定、コミット前のフック（[開発作業とローカル検証](design/dev-workflow.md)）
- devtool の検査（外部依存の禁止、クレート間の依存規則、`cfg` の使用の規則、台帳の検査）
- [参照資料の台帳](references.md) のうち、段階 0 と段階 1 で使う項目（RISC-V の仕様と psABI、ELF、Linux カーネルのソース、IEEE 754、TestFloat、riscv-tests、riscv-arch-test、使うツール）の確認
- `bits`、`testkit`（擬似乱数、性質テストの実行器、SHA-256）
- `isadl`（ビットパターンのデコーダの入口、フィールド、オペランド、形式、命令、機能、プロファイル、CPU モデルの記述）と `isagen`（命令の型、デコーダ、逆アセンブラ、エンコーダ、往復テストの生成）
- `sem` のバックエンドトレイトの整数演算、CPU 状態、メモリ、制御の操作
- `mem` のアドレス空間、ページフレーム、ソフトウェア TLB
- `engine` のインタプリタと裸実行環境

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S0-1 | RV64I の命令を ISADL で記述し、裸実行環境で命令単位のテストが通る。 | テスト：`bare_rv64i` |
| S0-2 | `task check` と `task test` が通り、コミット前のフックが `task check` を実行する。 | 所有者 |

対応した内容：

- ワークスペース・`Taskfile`・devtool・`isadl`/`isagen`・`mem`・`engine`・裸実行環境の基盤を整備


### 段階 1：RISC-V の縦の一本

RISC-V で、ユーザーモードのプログラムの実行までを通す。

- RV32 と RV64 の I、M、A、F、D、C、Zicsr、Zifencei と、汎用 CPU モデル
- `softfloat` の binary32 と binary64、TestFloat との比較
- `loader` の ELF、`kernel` と `os-linux` のシステムコールの段階 1 と 2（[ユーザーモード](design/user-mode.md)）
- `trace` の命令トレースとシステムコールトレース、`cli` の `run`、`cpus`、`disasm`
- llvm-objdump とのデコーダの差分テスト、riscv-tests と riscv-arch-test

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S1-1 | 静的リンクと動的リンクのテストプログラムが、ゲストのルートを使って正しい出力を返す。 | テスト：`heavy_program_hello`、`heavy_program_dyn` |
| S1-2 | riscv-tests と riscv-arch-test のユーザーモードの対象のテストが通る。 | テスト：`heavy_conformance_riscv_tests`、`heavy_conformance_rv64ui` |
| S1-3 | 意味論をバックエンドに対して総称的に書いた版と、インタプリタ専用に直接書いた版を、代表的な命令で比較するベンチマークを取り、性能の差を記録する。差が 10% を超えた場合は、原因を調べ、バックエンドトレイトの設計を見直すか、差を受け入れる理由を設計文書に書く。 | 所有者 |

対応した内容：

- ISADL からユーザーモード実行までの一本を RISC-V で通した（softfloat・loader・kernel/os-linux・trace・cli）

残っている事項：

- GAP-0010: riscv-tests/riscv-arch-test の実行ハーネスは殻のまま
- GAP-0022: i386 全アプレット走査の所有者確認

### 段階 2：抽象の試作

以下の ISA の小さな部分集合を、裸実行環境で動かす。本格的な実装は後の段階で行う。

| 試作の対象 | 確かめる抽象 |
|---|---|
| Hexagon（パケット、`.new` オペランド、ハードウェアループ） | パケットのステップ、書き込みの一括反映 |
| IA-64（バンドル、述語、回転レジスタ） | 複数のデコーダの入口、述語実行、動的なレジスタ参照 |
| SPARC（レジスタウィンドウ、遅延スロットと annul） | 動的なレジスタ参照、遅延スロットのステップ |
| WebAssembly（モジュールの検証、整数命令、制御命令） | 非線形なプログラムカウンタ、フレームの基底からの参照、トラップ |

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S2-1 | 各試作で、選んだ命令の単位テストが通る。 | テスト：`bare_hexmin`、`bare_ia64min`、`bare_sparcv8`、`bare_wasmmin` |
| S2-2 | 共通の抽象の変更点が文書に反映されている。 | 所有者 |

対応した内容：

- hexmin・ia64min・sparcv8・wasmmin の試作で共通抽象（パケット・バンドル・ウィンドウ・モジュール）を検証


### 段階 3：MIPS

ISA のバージョンの表現と、最初の `exact` のタイミングモデルを確かめる。

- MIPS I から Release 6 までのプロファイル、Release 6 のオペコードの割り当て直し、遅延スロット、MIPS I のロードの遅延スロット、両エンディアン
- o32、n32、n64 のゲスト ABI、システムコールの段階 3
- R3000 の CPU モデルと、`exact` のタイミング表、タイミングの検証用の命令列

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S3-1 | MIPS I と MIPS32 Release 2 と Release 6 の CPU モデルで、それぞれ同じテストプログラムを（Release 6 は再コンパイルして）実行できる。 | テスト：`heavy_program_mips` |
| S3-2 | R3000 のタイミングの検証用の命令列がすべて一致する。 | テスト：`heavy_timing_r3000` |

対応した内容：

- MIPS I・MIPS32r2・R6 のモデルと R3000 タイミングを実装


### 段階 4：x86

可変長命令、オペコード表、遅延評価のフラグ、x87 を確かめる。

- x86-32 と x86-64 のゲスト ABI、x87 と SSE2 までを最初の範囲とし、後から拡張を足す
- CPUID の機能からの導出、Intel と AMD の挙動パラメータ
- ホストの CPU との実行の差分テスト
- システムコールの段階 4（busybox が動く）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S4-1 | x86-64 と x86-32 の busybox のコマンド群のテストが通る。対象のコマンドは、台帳で確認した busybox の `busybox --list` が示すアプレットとする。`df` の扱いは [ADR-0014](adr/0014-statfs-number-table-only.md) による。 | テスト：`heavy_program_busybox` |
| S4-2 | この段階の終わりに共通の抽象を見直し、確定させる。 | 所有者 |

対応した内容：

- x86-64/x86-32 で busybox のコマンド群を通し、共通抽象を確定

残っている事項：

- GAP-0022 の所有者確認（上記）

### 段階 5：MIPS の本実装

段階 3 で始めた MIPS を、共通の構造に載せて完成させる。

- MIPS o32 のシステムコール処理を `cli` から `os-linux` へ移す（GAP-0001）
- 遅延スロットを持つ独自の実行ループを `engine` の実行ループへ移す（GAP-0007）
- o32、n32、n64 のゲスト ABI と、Release 6 のオペコードの割り当て直しの残り

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S5-1 | 段階 3 の判定に使ったテストが、移管後も引き続き通る。 | テスト：`heavy_program_mips`、`heavy_timing_r3000` |
| S5-2 | GAP-0001 と GAP-0007 が解消され、`cli` に MIPS 固有の実行経路が残っていない。 | 所有者 |

対応した内容：

- GAP-0001・GAP-0007 を解消（syscall 処理を `os-linux` へ、実行ループを `engine::run` へ移管）
- MIPS32r2・MIPS64・Release 6（コンパクト分岐 19 系・乗除・PC 相対ロード等）を実装
- n32/n64 ABI 経路と、ELF のクラス・`EF_MIPS_ARCH` からのモデル自動選択
- 実バイナリ検証で 64 ビット比較の 32 ビット正規化・BE 初期スタック等の実害を修正

残っている事項：

- o32 旧 `mmap` の引数順（テスト不足）・R6 コンパクト分岐 `rs>rt` の厳格化判断

### 段階 6：AArch64

AArch64 の本格的な実装と、Linux の aarch64 ゲスト ABI。

- 版の範囲は Armv8.0-A から Armv9.x-A までで、`FEAT_*` を機能として表す。最初の範囲は整数・浮動小数点・AdvSIMD と汎用 CPU モデルとし、SVE、SME、MTE は後から拡張を足す。ベクトル長とストリーミングモードは実行モードとする
- ユーザー空間からの ID レジスタの読み出しは OS による命令の補完で扱う
- LP64（リトルエンディアンとビッグエンディアン）のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S6-1 | aarch64 の静的リンクと動的リンクのテストプログラムと、配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_aarch64`）。 | テスト：`heavy_program_aarch64` |
| S6-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_aarch64`）。 | テスト：`heavy_abi_aarch64` |
| S6-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_llvm`）。 | テスト：`heavy_oracle_llvm` |

対応した内容：

- `guests/aarch64`（ISADL spec・sem）。整数一式に加え、musl が要求する AdvSIMD 部分集合を実装
- `os-linux::aarch64`（asm-generic 番号表、LP64 ABI の syscall 機械）
- `--root` のゲスト名前空間パス解決（`resolve_guest_path_links`）
- 実バイナリ走行で DecodeBitMasks・UBFM/SBFM・csel の cond 抽出等の実害を修正

残っている事項：

- AdvSIMD のベクトル演算系（musl が要求した転送・積載系以外は未実装）
- 段階 6 の完了コミット本文への検証記録の転記（所有者の作業）

### 段階 7：ARM

ARM（AArch32 とそれ以前）の本格的な実装と、Linux の arm EABI ゲスト ABI。

- 版の範囲は ARMv2 から Armv8-A の AArch32 まで。最初の範囲は ARMv5 から Armv7-A までの ARM と Thumb-2、VFP、NEON と汎用 CPU モデルとする。ARMv2 と ARMv3 の 26 ビットモードと M プロファイルは裸実行環境で検証する
- ARM と Thumb の切り替え、IT ブロック、条件実行、非整列 `LDR` の回転、BE32 と BE8、kuser helper の特別なアドレス
- arm EABI のゲスト ABI。ソフトウェア浮動小数点とハードウェア浮動小数点の呼び出し規約の差は ELF の属性で区別する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S7-1 | arm のテストプログラムと配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_arm`）。 | テスト：`heavy_program_arm` |
| S7-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_arm`）。 | テスト：`heavy_abi_arm` |
| S7-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_arm`）。 | テスト：`heavy_oracle_llvm` |

対応した内容：

- `guests/arm`（A32 の粗分類デコード＋`sem`。条件実行・LDM/STM・排他・CP15 TLS・VFP f64）
- `os-linux::arm`（EABI 番号表 ≈450 件、syscall 機械）
- UAPI 突き合わせで番号表の 313-399 帯ずれと `__ARM_NR_cmpxchg` の誤値を発見・修正

残っている事項：

- Thumb/Thumb-2・NEON の実装時期（所有者判断）
- kuser ヘルパー領域と `__ARM_NR_cmpxchg`（現状 ENOSYS）

### 段階 8：Power

Power の本格的な実装と、Linux の ppc32、ppc64、ppc64le ゲスト ABI。

- 版の範囲は POWER、PowerPC（601 から 970 まで）、Power ISA 2.0x から 3.1 まで、Book E（e500 の SPE を含む）。最初の範囲は整数・浮動小数点・AltiVec と汎用 CPU モデルとし、十進浮動小数点と `bcdadd.` は段階 10 で追加する
- ISA 3.1 の接頭辞付き命令、リトルエンディアンの実行モード、SPE と AltiVec の `conflicts`、`MFPVR` の補完、601 の POWER と PowerPC の二つの機能集合
- ppc32、ppc64（ELFv1、ビッグエンディアン）、ppc64le（ELFv2）のゲスト ABI。エラーの返しは CR0 の SO ビット

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S8-1 | ppc64le のテストプログラムと配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_power`）。 | テスト：`heavy_program_power` |
| S8-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_power`）。 | テスト：`heavy_abi_power` |
| S8-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_power`）。 | テスト：`heavy_oracle_power` |

対応した内容：

- `guests/power`（ppc64le ELFv2 を主対象。整数・CR/XER・予約・FP・VSX/AltiVec）
- `os-linux::power`・`run_power`（ELFv2 入口・TOC 規約・フォルト駆動スタック）
- 実バイナリで炙り出した実害を修正（CA 更新範囲・mfocrf・VSX フィールド・`cmpi` の ra 規約・VR 番号マップ・musl allocator の meta 破壊）

残っている事項：

- ELFv1・ppc32・ISA 3.1 接頭辞付き命令・SPE/Book E・十進 FP
- FPSCR/FPCC/CR1 更新の残り・lxvl/stxvl・xvmadd 系の単一丸め等（段階 8 レビュー残件）

### 段階 9：IR と JIT

前提：段階 6 から 8（主対象の ISA が三つ動いている）。

`ir` クレートと `jit` クレートを実装し、x86-64 のホストのバックエンドを持つ（[JIT](design/jit.md)）。

- ブロック単位の SSA の IR と、IR の解釈実行器。バックエンドトレイトの操作と一対一に対応する操作、ブロックの出口の分類、ブロック内の最適化（定数畳み込み、共通部分式、デッドストア、レジスタ保持）
- x86-64（System V）のホストのバックエンド。命令のエンコードは x86 の ISADL の記述から生成したエンコーダを使う。実行可能メモリは `host` 経由で、書き込み可能な状態で書いてから実行可能に切り替える
- 実行回数による階層化、ブロックの連結、タイミングモデルとの接続、観測が要求されたブロックのインタプリタへの切り戻し

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S9-1 | 三つ以上の主対象の ISA で、JIT とインタプリタの実行結果がブロックの境界ごとに一致する（[検証戦略](design/testing.md) の層 9、テスト `heavy_jit_diff`）。 | テスト：`heavy_jit_diff` |

対応した内容：

- `crates/ir`（SSA 記録・optimize）・`crates/jit`（x64 バックエンド・ブロックキャッシュ・熱カウンタ）
- AArch64・ARM・x86 のランナ統合（`POLYISA_JIT` で有効化、既定はインタプリタ）

残っている事項：

- helper/parameter の IR 化（該当ブロックはインタプリタへフォールバック）

### 段階 10：十進演算と非 IEEE 浮動小数点

以降の段階で実装する ISA が必要とする、`decimal` クレートと `softfloat` の非 IEEE 形式（[浮動小数点と十進演算](design/floating-point.md)）。

- `decimal`：ISA ごとの環境を持つパック十進整数（BCD）の演算と、IEEE 754 十進浮動小数点（DPD 符号化）
- `softfloat` の拡張：IBM 16 進浮動小数点、DEC の F、D、G、H 形式、68881 の拡張精度
- Power の十進浮動小数点と `bcdadd.` の意味論はこの段階で追加する。s390 系の 16 進浮動小数点と十進演算は、この段階の基盤の上で段階 11 が実装する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S10-1 | `decimal` の演算が decTest と比較して一致する（テスト `heavy_conformance_dectest`）。 | テスト：`heavy_conformance_dectest` |
| S10-2 | 16 進浮動小数点、DEC の形式、68881 拡張精度が、仕様書の例と一致する（テスト `nonieee_examples`）。 | テスト：`nonieee_examples` |

対応した内容：

- `crates/decimal` と 16 進浮動小数点・DEC 形式・68881 拡張精度


### 段階 11：s390 系

前提：段階 10（16 進浮動小数点、十進浮動小数点、パック十進）。

s390 系（System/360 から z/Architecture まで）の本格的な実装と、Linux の s390 と s390x ゲスト ABI。

- 版の範囲は System/360 から z/Architecture までで、z/Architecture の世代ごとのファシリティを機能として表す。最初の範囲は ESA/390 の後期と z/Architecture（Linux が動く世代）とし、それより前の世代は裸実行環境で検証する
- 先頭 2 ビットで決まる 2、4、6 バイトの命令長、24、31、64 ビットのアドレッシングモード、`EX` と `EXRL` の実行時のデコード、`MVCL` などの反復のステップ
- 16 進・二進・十進浮動小数点とパック十進命令（段階 10 の基盤を使う）
- s390（31 ビット）と s390x のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S11-1 | s390x のテストプログラムと配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_s390`）。 | テスト：`heavy_program_s390` |
| S11-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_s390`）。 | テスト：`heavy_abi_s390` |
| S11-3 | llvm-objdump（SystemZ）とのデコーダの差分テストが通る（テスト `heavy_oracle_s390`）。 | テスト：`heavy_oracle_s390` |
| S11-4 | ESA/390 より前の世代の命令単位テストが裸実行環境で通る（テスト `bare_s390`）。 | テスト：`bare_s390` |

対応した内容：

- `guests/s390`（z/Arch を主対象、ESA/390 31 ビットは AMASK で裸検証。モデル esa390〜z13/generic）
- `os-linux::s390`・`run_s390`（フィーチャ `guest-s390`）
- 実バイナリで LNR/LNGR・MADBR フィールド配置・MVHHI 系・RXF 到達不能の実害を修正

残っている事項：

- 128 ビット BFP 実値・HFP/DFP・パック十進・`EX`/`EXRL` の残り
- `wait4`/`clone`・ソケット・`execve`・シグナルフレーム・SIE/特権命令

### 段階 12：WebAssembly と WASI

WebAssembly の本格的な実装と、WASI preview1 の OS パーソナリティ（`os-wasi`）。WASI は ISA ではなく OS パーソナリティだが、WebAssembly のモジュールからのインポート呼び出しとして現れるため、同じ段階で実装する。

- 版の範囲は 1.0、2.0、3.0 と各提案。最初の範囲は 1.0 と 2.0 の命令と WASI preview1 とし、GC、memory64、マルチメモリは後から拡張を足す
- モジュールの読み込みと検証、関数ごとの実行用の内部形式、フレームの基底からの動的なレジスタ参照、トラップによる退出
- 仕様のテストスイート（`.wast`）の構文解析とバイナリ形式へのエンコードを、テスト用の部品として実装する
- `os-wasi` は仮想カーネルのファイル記述子の表と仮想ファイルシステムを `os-linux` と共有し、プリオープンのディレクトリに対応する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S12-1 | WebAssembly 仕様のテストスイートが通る（テスト `heavy_conformance_wasm_spec`）。 | テスト：`heavy_conformance_wasm_spec` |
| S12-2 | wasmtime との実行の差分テストが通る（テスト `heavy_diff_wasmtime`）。 | テスト：`heavy_diff_wasmtime` |
| S12-3 | WASI preview1 を使うプログラムが正しい出力を返す（テスト `heavy_program_wasi`）。 | テスト：`heavy_program_wasi` |

対応した内容：

- `guests/wasm`（decode/validate/exec/wat/wast）・`crates/os-wasi`（preview1 の host 関数一式）
- 仕様スイートを `wast::Runner` で採点（範囲外の提案機能は skip 分類）

残っている事項：

- 提案機能（module linking・GC・tail-call・SIMD・threads・EH）は範囲外のまま
- hex-float の文字列→ビット変換で 1ulp 差が残る可能性

### 段階 13：x86 の残り

前提：段階 10（x87 の BCD 命令）。

段階 4 の範囲の外にあった x86 の部分を実装し、ユーザーモードで実行できる命令の全範囲をカバーする。対象は、Intel SDM と AMD APM の台帳で確認した版が定める、ユーザーモードで実行できる命令のすべてである。特権命令とシステムモードの機能（ページテーブル走査、記述子テーブルによる保護機構、割り込みコントローラ、VMX、SGX など）は、[設計概要](design/overview.md) の非目標どおり対象にしない。

- 記述の基盤。x86min の変形ごとの列挙はこの命令数に対応できないので、オペコード表（`map`）と接頭辞・ModRM/SIB・VEX/EVEX/REX2 のフックを ISADL に実装し、x86 の記述をそれらで書き直す（[ADR-0018](adr/0018-x86min-enumerated-encoding.md) の「列挙の複製が主な費用になったとき」にあたる）。実行モード（16、32、64 ビットのオペランドサイズとアドレスサイズ、ModRM の 16 ビットアドレッシング）を ISADL でモデル化し（GAP-0029 の解消）、挙動パラメータと機能から識別情報への導出を繋げる（GAP-0027 の解消）
- 8086、8088、80286。実モードに限り、裸実行環境で検証する（プロテクトモードはシステムモードの範囲）。命令プリフェッチキューによる自己書き換えコードの振る舞いは、機能の側で再現する。世代ごとの差（FLAGS の固定ビット、`PUSH SP` の値、シフト回数のマスク、`0F` が `POP CS`、0x82 のエイリアス、80186 以降の命令の有無、FS・GS と 0x66・0x67 の接頭辞の有無、除算エラーの戻りアドレス、1 MiB でのアドレスの巻き戻し、CPUID の有無）は、機能と挙動パラメータで表す。8088 のバスインターフェースユニットと命令プリフェッチキューは、専用のタイミングモデルとする（[タイミングモデル](design/timing.md)）
- x87 の残り。`FBLD`/`FBSTP` は段階 10 の `decimal` を使う。8087、80287 と 80387 以降での擬似非正規化数などの扱いの差は、挙動パラメータとする（[浮動小数点と十進演算](design/floating-point.md)）。FPU を持たない CPU モデルでは、ESC 命令は世代の規定どおりの振る舞い（8086 ではダミーのフェッチ、80286 では MSW の EM ビットによる INT 7）とする
- SSE2 以降の拡張のすべて。MMX と 3DNow!（MMX のレジスタは x87 のスタックにエイリアスされる）を含み、SSE3 以降の各版、AES-NI・PCLMUL・SHA・GFNI・RDRAND・RDSEED・ADX・BMI・F16C・FMA、AVX 系、AVX-512 の全サブセット、AVX10（10.3 まで）、ACE（外積による行列演算。v2 まで）、AMX の全拡張、APX（REX2、NDD、拡張 GPR）を実装する。AVX10.3 と ACE v2 が使う 8 ビットと 4 ビットの浮動小数点形式（E4M3、E5M2、E2M1 など）は `softfloat` の形式として追加する（[浮動小数点と十進演算](design/floating-point.md)）。AMD の拡張（FMA4、XOP、TBM、SSE4a、MONITORX・MWAITX、CLZERO、RDPRU）も、AMD APM が定める範囲で対象とする。AVX 系をユーザーモードで使うために、XCR0 と `XGETBV`、`XSAVE` 系と xsave 領域の配置を持ち、シグナルフレームの浮動小数点状態もこの配置に従う。AMX の利用許可は `arch_prctl` の `ARCH_REQ_XCOMP_PERM` で再現する。CET のユーザー命令（ENDBR とシャドウスタックの操作）、PKU、WAITPKG、MOVDIR、CLDEMOTE、SERIALIZE、HRESET、FSGSBASE 系、TSX も対象とする。TSX のトランザクションの開始は [アーキテクチャ固有の要求](design/arch-requirements.md) どおり常に失敗させ、挙動パラメータで切り替えられる形にする。WAITPKG の `TPAUSE` の期限は仮想時間に従う。ユーザーモードから読めるシステム状態の命令（`SGDT`、`SIDT`、`SLDT`、`STR`、`SMSW`、`LAR`、`LSL`、`VERR`、`VERW`、`ARPL`）は、CPU モデルと OS パーソナリティが持つモデル化した値を返す。`RDRAND` と `RDSEED` は、決定性の原則に従い、設定した種から生成する擬似乱数を返す。UINTR の命令群（`SENDUIPI`、`UIRET`、`TESTUI`、`CLUI`、`STUI`）と `ENQCMD` のように、実行に OS による許可や設定が要る命令は、許可のない状態の規定の振る舞いとする
- x86-64 のマイクロアーキテクチャレベルのプロファイル（v1 から v4）と、ベンダーと世代ごとの CPU モデル
- 80486 と Pentium の `exact` のタイミング表。U/V パイプラインはインオーダーの汎用モデル（段階 3 で R3000 に使ったもの）で表す
- x32 のゲスト ABI（[ユーザーモード](design/user-mode.md) の ABI 表の残りの変種）。ELF の `GNU_PROPERTY_X86_FEATURE_*` の注記が要求する機能（IBT、SHSTK など）はローダが読み、CPU モデルにない機能の要求は [CPU モデル](design/cpu-models.md) の規約どおり警告にとどめる。`SYSENTER` と `SYSEXIT` は x86-32 の Linux のシステムコールの入口として OS パーソナリティに渡し、x86-64 の vsyscall ページ（gettimeofday、time、getcpu の固定アドレス）は [アーキテクチャ固有の要求](design/arch-requirements.md) の「特別なアドレスを経由する OS の呼び出し」で再現する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S13-1 | 8088 と 80286 の SingleStepTests のデータ集と命令の振る舞いが一致する（テスト `heavy_conformance_sst8088`、`heavy_conformance_sst80286`）。 | テスト：`heavy_conformance_sst8088`、`heavy_conformance_sst80286` |
| S13-2 | 追加した拡張と 80286、x87 の世代差の命令単位テストが裸実行環境で通る（テスト `bare_x86ext`）。 | テスト：`bare_x86ext` |
| S13-3 | 80486 と Pentium のタイミングの検証用の命令列がすべて一致する（テスト `heavy_timing_i486`、`heavy_timing_pentium`）。 | テスト：`heavy_timing_i486`、`heavy_timing_pentium` |
| S13-4 | 8088 の専用のタイミングモデルが、SingleStepTests のサイクル数と一致する（テスト `heavy_timing_8088`）。 | テスト：`heavy_timing_8088` |
| S13-5 | 追加した拡張と 16 ビットモードについて、llvm-objdump と XED とのデコーダの差分テストが通る（テスト `heavy_oracle_llvm`、`heavy_oracle_xed`。両方のオラクルが対応しない拡張は S13-2 で検証する）。 | テスト：`heavy_oracle_llvm`、`heavy_oracle_xed` |
| S13-6 | ホストの CPU と、ホストが持つ拡張について実行の差分テストが通る（テスト `heavy_diff_host`。GAP-0030 の解消を兼ねる）。ホストが持たない拡張は、Intel SDE（TOOL-INTEL-SDE）が対応する版の範囲で実行の差分テスト（`heavy_diff_sde`）を行う。 | テスト：`heavy_diff_host`、`heavy_diff_sde` |
| S13-7 | x32 ABI のテストプログラムと、xsave 領域・`XGETBV`・AMX の許可・vsyscall 経由の呼び出しを使うテストプログラムが正しい出力を返す（テスト `heavy_program_x32`、`heavy_program_x86ext`）。 | テスト：`heavy_program_x32`、`heavy_program_x86ext` |

対応した内容：

- SSE/x87 の map 経路移行、`0F 38`/`0F 3A` サブマップ、セグメント・特権命令
- 8088/80286/80386 の SST 適合、8088/i486/Pentium のタイミング、x32 ABI、REX2/EGPR/AMX/APX/AVX10 等の拡張

残っている事項：

- GAP-0030（map4 未検証・AMX 等の SDE 差分・QEMU oracle 未導入）・GAP-0037（llvm-mc 既知差分）・GAP-0038（x87 近似）・GAP-0039（8088 タイミングの対象範囲）

### 段階 14：m68k

前提：段階 10（68881 の拡張精度、BCD）。

- 版の範囲は 68000 から 68060 まで、CPU32、ColdFire、68881 と 68882 の FPU
- 実効アドレスと拡張語のフック、世代ごとのアライメントの差、68040 と 68060 の未実装命令は OS による命令の補完
- m68k のゲスト ABI。68000 の専用のタイミングモデル（バスサイクルとプリフェッチ）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S14-1 | 68000 の SingleStepTests のデータ集と命令の振る舞いが一致する（テスト `heavy_conformance_sst68000`）。 | テスト：`heavy_conformance_sst68000` |
| S14-2 | 68000 のタイミングの検証用の命令列がすべて一致する（SingleStepTests のサイクル数を含めて使う。テスト `heavy_timing_68000`）。 | テスト：`heavy_timing_68000` |
| S14-3 | m68k の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_m68k`）。 | テスト：`heavy_program_m68k` |
| S14-4 | ABI 表が SRC-LINUX の UAPI と一致する（clang が m68k に対応しないため層 6 の抽出方法は使えず、`syscall.tbl` と直接照合する。テスト `heavy_abi_m68k`）。 | テスト：`heavy_abi_m68k` |

対応した内容：

- `guests/m68k`（spec・sem・ea・timing）・`run_m68k`・`os-linux::m68k`（syscall 表・Line-F 補完の器）
- 68000 命令群一式と、busybox に要った 68020+ 分（extb.l・divl/mull・cas・bf 系・full 形式 EA）
- 68000 のバスサイクルタイミングを SST で較正（全 310,000 件一致）
- `heavy_conformance_sst68000` 全 317,500 件・差分 0（55,606 件 exceptional、2,500 件 TAS の unimplemented）

残っている事項：

- GAP-0040（アドレスエラーの 14 バイトフレーム配送）・GAP-0041（DIV 値依存時間・例外経路サイクル）・GAP-0042（TAS）・GAP-0043（68010/68020+ 残り・68040/68060 差分・FPU 算術・CPU32・ColdFire）

### 段階 15：SPARC

対応した内容：

- `guests/sparc`（spec・sem）・`run_sparc`・`os-linux::sparc`（sparc32/sparc64 の syscall 表、ウィンドウのあふれと不足の OS 再現）
- 版の範囲 V7・V8・V9 と VIS のうちユーザーモード実行に要る命令群（整数・load/store・分岐と annul/DCTI couple・ウィンドウ命令・ユーザ ASR・FPU・movcc/movr・cas/casx）
- `heavy_program_sparc`（sparc32/sparc64 の配布物コマンド群）・`heavy_abi_sparc`（UAPI 照合）・`heavy_oracle_sparc`（llvm-mc とのデコード差分、オラクル用途）

残っている事項：

- GAP-0044（版の範囲の未実装分：ユーザ ASR の一部・タグ演算・コプロセッサ命令・V9 quad FPU 等）・GAP-0049（仕様書が実装依存とする領域の意味論）

### 段階 16：Alpha

対応した内容：

- `guests/alpha`（spec・sem）・`run_alpha`・`os-linux::alpha`（syscall 表・FdTable 系・8KiB ページ）
- 整数 Operate・乗除と拡張（BWX/FIX/CIX/MVI）・load/store と非整列・分岐・IEEE 浮動小数点一式
- `CALL_PAL` の Linux パーソナリティ経路（callsys・rduniq/wruniq）
- `heavy_program_alpha`（配布物コマンド群）・`heavy_abi_alpha`（UAPI の syscall.tbl 照合）
- 規則9 是正の過程で仕様との実差分を修正（CVTLQ/FTOIS の符号拡張、`/v` 例外時の宛先書き込み順）

残っている事項：

- GAP-0045（VAX F/G 形式・/s・/i 例外モデル・FPCR 集約・cvttq の modulo 変換）・GAP-0046（syscall ABI の意図的な簡略化）・GAP-0050（仕様書が黙っている動作の簡略化）

### 段階 17：PA-RISC

対応した内容：

- `guests/parisc`（spec・sem）・`run_parisc`・`os-linux::parisc`（hppa32 syscall 表・FdTable 系・ゲートウェイページの 3 入口と LWS）
- 版の範囲 PA-RISC 1.1・2.0 と MAX のうちユーザーモード実行に要る命令群（整数・extract/deposit・load/store・LDCW 系・分岐と無効化・IAOQ キュー・FP・MAX-1/MAX-2）。PA-RISC 1.0 は根拠資料がないため範囲から除外
- `heavy_program_parisc`（配布物コマンド群）・`heavy_abi_parisc`（UAPI の syscall.tbl 照合。abi ∈ {common,32} の 408 エントリ）

残っている事項：

- S17-2 の所有者確認（`heavy_abi_parisc` が機械的証拠）
- GAP-0047（SPOPn・debug SFU・COPR uid≠0・PA1.1 の 0x0E 半面選択形の未モデル分）・GAP-0052（LDCW 予約近似・GATE 特権・IASQ・トラップ復帰等の簡略化）・GAP-0053（未定義域の決定的評価）・GAP-0054（SUBB 系の条件評価の読み）・GAP-0055（絶対番地アクセスと PROBE の簡略化）・GAP-0056（ゲートウェイページの近似）・GAP-0057（FP 例外トラップの配送）・GAP-0058（syscall ABI の意図的な簡略化）

### 段階 18：SuperH

対応した内容：

- `guests/superh`（spec・sem）・`run_superh`・`os-linux::superh`（sh4 syscall 表・FdTable 系・dirfd 解決を含む両エンディアンの直列化）
- 版の範囲 SH-1 から SH-4A・J-core のうちユーザーモード実行に要る命令群（SH-2A の 32 ビット命令はデコーダ入口の長さ規則、遅延スロットとスロット不正命令例外、FPSCR の PR/SZ/FR を実行モードとする SH-4 FPU、DIV1 の Q 更新は J-core 式）
- `heavy_program_superh`（sh4 両エンディアンの BusyBox。LE は BIN-DISTRO-SH4、BE は自前ビルドの BIN-DISTRO-SH4EB。e_flags でモデルを選択し SH-4A 側の synco/movli/movco を解決）・`heavy_abi_superh`（SRC-LINUX-SH-UAPI の syscall.tbl 照合。abi 列は全行 common の 437 エントリ）

残っている事項：

- S18-2 の所有者確認（`heavy_abi_superh` が機械的証拠）
- GAP-0059（意味論の意図的な簡略化）・GAP-0060（syscall ABI の意図的な簡略化）・GAP-0061（SH-2A レジスタバンクの部分モデル）

### 段階 19：LoongArch

対応した内容：

- `guests/loongarch`（spec・sem）・`run_loongarch`・`os-linux::loongarch`（asm-generic 系の la64 syscall 表・FdTable 系・ゲストルート内のパス解決と `/dev/*` のホスト devtmpfs へのフォールスルー）
- 版の範囲 LA32・LA64 のうちユーザーモード実行に要る命令群（32 ビット固定長のデコード、整数算術・load/store・ll/sc と am 系の予約、分岐と jirl・境界検査、CSR 列と ertn の簡易遷移、CPUCFG を識別情報とする構成、スカラ FPU と fcc による条件分岐）。LA32 は配布物がないため裸実行環境で検証
- LSX は Alpine 3.24 の musl/BusyBox が実際に実行する命令に限定した部分実装（LA13 の棚卸しで確定した語彙）。LASX・LBT は機能旗の宣言のみ（LASX/LBT のバイナリは現行の入手可能な配布物に存在しないという棚卸しの結論）
- 新旧 ABI は `e_flags[7:6]` の ABI version で区別し、OBJ-v1（新ワールド）のみ受理して旧ワールドと未割当て値はローダが拒否
- `bare_loongarch`（層1–3: デコードと裸実行の命令単位検査）・`heavy_oracle_loongarch`（llvm-objdump との busybox 全語照合）・`heavy_abi_loongarch`（`.testdata/uapi-loongarch` の syscall.tbl 照合。abi ∈ {common,64,memfd_secret}）・`heavy_program_loongarch`（BIN-DISTRO-LOONGARCH の Alpine minirootfs コマンド群とゲストルートの検査）

残っている事項：

- S19-1〜S19-3 はすべてテスト判定で確定しており、所有者確認の残件はない
- LASX・LBT の命令実装（棚卸しの結論どおり未実装のまま。入手可能な配布物の登場時に再検討）・LSX の部分実装の残り語彙・旧ワールド（e_flags v0）ABI の実装（テスト入力の入手経路がない）
- GAP-0062（syscall ABI の意図的な簡略化。devtmpfs フォールスルーと GROWSDOWN 相当の syscall バッファ窓を含む）・GAP-0063（意味論の意図的な簡略化）

### 段階 20：OpenRISC

対応した内容：

- `guests/openrisc`（spec・sem）・`run_openrisc`・`os-linux::openrisc`（or1k の syscall 表は共通表 `scripts/syscall.tbl` を abi ∈ {common,32,or1k,time32,stat64,rlimit,renameat} で畳んだ 348 エントリと固有の `or1k_atomic`(244)。FdTable 系・dirfd 解決・`/dev/*` のホスト devtmpfs へのフォールスルー）
- 版の範囲 OpenRISC 1000 の各版と浮動小数点の拡張のうちユーザーモード実行に要る命令群（32 ビット固定長・BE の ORBIS32 全語彙、整数・load/store・分岐と遅延スロット、SPR・l.mac 系、ORFPX32 と ORFPX64A32）。遅延スロットの有無は機能 `dslot`（既定あり、CPUCFGR[ND]=0 相当）。ORBIS64・ORVDX64 は機能旗の宣言のみで命令の割当てなし
- モデルは or1200（`dslot`）と mor1kx（or1200＋`fpu`）。ELF32 BE ランナ（EM_OPENRISC=92、EXEC と PT_INTERP `/lib/ld-musl-or1k.so.1` の動的リンク経路）と Linux パーソナリティ（`l.sys` → ベクタ 0xc00 の Trap 受け渡し、nr=r11・引数 r3-r8・戻り値 r11/-errno）
- `bare_openrisc`・`sem_openrisc`（層1–3: デコード・エンコード往復と裸実行の命令単位検査）・`heavy_abi_openrisc`（`.testdata/uapi-openrisc` の syscall.tbl 照合。Makefile.syscalls の opt-in 固定・番号ピン留め・双方向照合）・`heavy_program_openrisc`（BIN-DISTRO-OR1K の musl busybox rootfs コマンド群とゲストルートの検査）

残っている事項：

- S20-2 の所有者確認（`heavy_abi_openrisc` が機械的証拠）
- ORBIS64・ORVDX64・カスタム命令（`l.cust1-8`・`lf.cust1.*`）の未実装（機能旗の宣言のみ）と、特権専用の `l.rfe`・例外配送・`l.lwa`/`l.swa` の単一スレッド近似（GAP-0066）
- GAP-0064（syscall ABI の意図的な簡略化。単一プロセス・単一スレッド模型、`or1k_atomic` 未実装、dirfd/O_* フラグの近似、決定論的ダミー getrandom 等）・GAP-0065（lazymap 窓のデマンドページ近似）・GAP-0067（generic Backend 化の未対応）

### 段階 21：IA-64

対応した内容：

- `guests/ia64`（spec・sem・bundle）・`run_ia64`・`os-linux::ia64`（アーチ固有 `syscall.tbl` の表番号（0–452・abi 全行 common・355 エントリ）に `NR_BASE`=1024 を足す規約で畳む。FdTable 系・dirfd 解決・単一プロセス模型）
- 版の範囲 Itanium〜Itanium 9700 系のうちユーザーモード実行に要る命令群。128 ビットバンドルはテンプレート（bits[4:0]）でスロットのユニット要求と stop を決め、41 ビットのスロット語（MLX の X は 82 ビット語）を ISADL の語長分岐でデコード。整数・比較と述語生成・メモリ（ld/st 系・ALAT・chk・セマフォ）・分岐と call/ret・ループ・回転分岐・回転改名と RSE（96 項リング駐在域・バッキングストアへの書き出し/読み戻し・NaT 集積穴）・82 ビット FP（`{sign,exp17,sig64}`、fma 系・fcmp・sf0–3・NaTVal）
- syscall は `break 0x100000` とゲートページ（`GATE_ADDR+PERCPU_PAGE_SIZE` に実バンドルを供給し via_break/via_epc 両入口を break に畳む。auxv の AT_SYSINFO/AT_SYSINFO_EHDR）と、ELF64 EXEC（静的）ローダ・初期スタック
- `bare_ia64`（層1–3: デコード・エンコード往復と裸実行の命令単位検査）・`heavy_program_ia64`（BIN-DISTRO-IA64 の busybox-static 1.35.0 コマンド群。basic 18 件＋stdin 4 件）・`heavy_abi_ia64`（`.testdata/uapi-ia64` の syscall.tbl 照合。+1024 生成規則の固定・nr 定数 203 件の番号ピン留め・名表 355 件の双方向照合）

残っている事項：

- S21-2 の所有者確認（`heavy_abi_ia64` が機械的証拠）
- GAP-0068（意味論の意図的な簡略化。ALAT の単一スレッド近似・RSE 書き出し粒度・ヒント/予測無視・バリア no-op・特権/IA-32 系の範囲外・FP 例外配送なし・syscall ABI の単一プロセス簡略化等を包摂）
- Insn→実行ユニット対応表は `bundle.rs` の `insn_unit` 手書き表。属性表としての生成化は GAP-0023 の残項目

### 段階 22：Hexagon

対応した内容：

- `guests/hexagon`（spec・sem・packet・threads）・`run_hexagon`・`os-linux::hexagon`（アーチ固有の `syscall.tbl` を持たず、共通表を abi ∈ {common, 32, hexagon, time32, stat64, rlimit, renameat} で畳む（v7.3 の tbl に abi=hexagon の行はない）。`__NR_sync_file_range2`=84 の改名と `sys_mmap2→sys_mmap_pgoff`・`hexagon_fadvise64_64`(223) の差替えを反映。FdTable 系・dirfd 解決・lazymap 窓のデマンドページ・単一プロセス模型）
- 版の範囲 V5 以降の各版と HVX のうちユーザーモード実行に要る命令群。主対象は V73（BIN-DISTRO-HEXAGON の e_flags 0x73）、主正本の最新版 V79 と `tinycore`・`hvx` は機能旗。命令語は 32 ビットで、フェッチ層が PP 桁（bits[15:14]）でパケットを確定し、duplex 語を 2 subinsn に分解、constant extender を後続の命令語の即値に併合してから decode に渡す。パケット内の命令は同時発行で、書き込みは `pkt_*` 未確定域に溜めて終端の commit で一括反映（`.new` オペランドはこの一時値を読み、dot-if 述語で命令ごとに抑制）。整数・load/store・memop・`.new` ストア・円環/brev/Mu 修飾アドレッシング・jump/call/jumpr・述語付き/複合/new-value compare-jump・allocframe/deallocframe/dealloc_return・trap0/trap1/pause・loop0/loop1 のハードウェアループ（LC/SA・endloop・ネスト）・HVX 代表部分集合（v/q/vcsr の建築状態と vmem・vALU・vmpy・vcmp・q 論理。`hvx` 旗でゲート）
- `threads::Core` の複数 HW スレッド交互実行モデル（1 発行枠 = 1 パケットの単純 IMT ラウンドロビン、全スレッド共有メモリ、pause の休眠/復帰、trap の引き継ぎ）
- syscall は `trap0(#1)`（nr=r6・引数 r0–r5・返り値 r0・失敗は -errno）と、ELF32 LE（EM_QDSP6=164・e_flags 0x73）ローダ・PT_INTERP `/lib/ld-musl-hexagon.so.1` の動的リンク経路（INTERP_BASE 0x0800_0000・PT_GNU_RELRO の mprotect 反映）・初期スタック・auxv（AT_HWCAP=0）
- `bare_hexagon`・`threads_hexagon`（層1–3: デコード・エンコード往復・パケット構造と裸実行の命令単位検査・交互実行モデル）・`heavy_program_hexagon`（BIN-DISTRO-HEXAGON の musl BusyBox 1.37.0 コマンド群、basic 19 件）・`heavy_abi_hexagon`（`.testdata/uapi-hexagon` の syscall.tbl 照合。Makefile.syscalls の opt-in と改名/差替え・trap0 呼出規約の固定・nr 定数 153 件のピン留め・名表の双方向照合、5 件）・`heavy_oracle_hexagon`（BIN-DISTRO-HEXAGON の busybox の .text を `llvm-objdump --mcpu=hexagonv73` と語ごとに照合。146,804 語中 146,587 語をデコードして差分 0）

残っている事項：

- GAP-0069（パケット組立規則の手書き表。属性表としての生成化は GAP-0023 の残項目）・GAP-0070（HVX 語彙の代表部分集合）・GAP-0071（HVX 意味論・配置の近似）・GAP-0072（HW スレッド交互実行モデルの近似）・GAP-0073（Linux ABI の近似）・GAP-0074（df/sf の FP 語彙と `date`/`seq` 系の残不具合）・GAP-0075（意味論の意図的な簡略化。ヒント/予測・フェンス no-op・キャッシュ/プリフェッチ系の語彙外・特権の範囲外扱い・制御レジスタの部分集合・generic Backend 化の未対応）

### 段階 23：VAX

対応した内容：

- `guests/vax`（spec・specifier・sem・decimal・timing）と `cli` の `run_vax`（feature `guest-vax`、裸実行のみ。主流の Linux 移植がないため裸実行環境で検証し、BSD パーソナリティは段階 25 の対象）
- 版の範囲は VAX-11/780 から NVAX までのモデル（vax11_780 は全オプション搭載のフル VAX、microvax2・ka660・nvax は機能旗でサブセット化）と F・D・G・H の浮動小数点形式。機能旗 decimal・hfp・string_ext・string_cmp・crc・editpc・compat が実装群の差を表し、削られた命令はデコードから外れて補完経路に乗る。挙動パラメータは `emul_dispatch`（hook=OS パーソナリティの `handle_unimpl` へ、scb=SCB 0xC8/0xCC の補完例外へ FPD で開始/継続を振り分ける実機配送）と `dv_hw`（KA660 は DV をハードが扱わない）
- 命令はオペコード語（1 バイト、または 0xFD/0xFE/0xFF 接頭の 2 バイト。生成デコーダが解く）＋オペランド指定子列で、指定子は m68k ea.rs と同型の分割として `specifier.rs` が構造読み取り・長さ表・適合検査・再符号化・`insn_ops` シグネチャを担う（手書き表。属性表としての生成化は GAP-0023 の残項目）。実行は `run::step` がバイト単位の必要分フェッチで組み立て、fault 系（ACV・予約モード・予約/特権命令）は PC を動かさず配送して Handled ならやり直し、trap 系（BPT・算術）は終端に進めてから配送する正本規則
- 実装した命令群は整数・論理・bitfield・shift/rot・分岐（Bcc 全結合子・bb 系・sob/aob/acb・case・jsb/jmp）・calls/callg/ret のフレーム構築と解除・pushr/popr・キュー（insq/remq）・文字列（movc/cmpc/locc/skpc/scanc/spanc/matchc/movtc/movtuc/crc）・chm 系・F/D/G/H 演算と cvt/emod・poly 系・パック十進・数値文字列 3 形式・editpc・index/prober/probew。中断可能命令は「1 ステップ = 1 単位」で PSL<FPD> を立てて同じ命令へ再入し、進捗は正本どおり r0–r5 に露出、内部状態は `partial.work` の器に限る。chm はモード遷移をモデル化して SCB 0x40+4*mode の trap として OS パーソナリティへ委ねる
- `timing::Vax780` は VAX-11/780 の EBOX マイクロサイクル（200 ns）単位の専用時間モデル。命令本体＋指定子評価・データアクセスの構造で、`Rt`（分岐成立・単位数・先頭ステップ）で反復・中断可能命令の部分ステップを計時する。時間値は MEAS-VAX-USENET の μs 表をマイクロサイクル換算したアンカー＋差分近似で、未較正の approx（`Fidelity::ApproxUncalibrated`）
- `bare_vax`（層1–3: オペコード語のデコード・指定子の読み取り/長さ/適合/往復・シグネチャ表・機能旗とモデル差・補完配送・裸実行の命令単位検査。117 件）と lib 単体テスト（13 件）で S23-1 を判定

残っている事項：

- S23-1 はテスト判定で確定しており、所有者確認の残件はない
- 特権・システム系の命令（rei/ldpctx/svpctx/bugw/bugl）と PDP-11 互換モードは語彙宣言までで意味論は未実装（ユーザーモード対象の範囲。halt はユーザーモードの特権命令 fault を再現し、カーネル側は Unimplemented。REI の CM 遷移規定は GAP-0079(d)）
- GAP-0076（キューの単一スレッド近似・中断可能文字列命令の 1 バイト粒度・chm の単一スタック近似）・GAP-0077（poly 系の中断粒度・退避形の近似）・GAP-0078（十進演算の 1 ステップ完結・UNPREDICTABLE 入力の決定化）・GAP-0079（nvax/ka650 の機能集合代用・SCB フレーム構築のパーソナリティ委譲・compat/REI）・GAP-0080（Vax780 の未較正 approx・MicroVAX 系/NVAX の時間・例外時間・probe のページ保護なし近似）

## 残っている事項（横断）

### 台帳の未登録項目

版の方針は「新しい資料が古い資料の記載を内包する想定で新しい版を採り、古い版にしか存在しない記載が必要な場合のみ例外とする」。台帳に登録した項目は全て確認済みとするため、登録済みの項目に残る作業はない。残るのは未登録の項目のみ：

- 段階 25 の V7/BSD バイナリ、段階 26・27・28 の BIN・較正ベンチマーク・ホスト OS 文書（実装時に追加登録する）

### 所有者の作業

- 段階 6 の完了コミット本文への検証記録の転記

### 仕様・設計の判断待ち

- `--root` 時の ELF パス解釈（ゲスト名前空間として解決する実装で確定してよいか）
- 重いテストの命名規約（`heavy_oracle_llvm` の共通名を今後も採るか、個別名に揃えるか）
- R6 コンパクト分岐の 2R 形式 `rs>rt` の受理（SPEC-MIPS-R6 の条文確認が前提）
- `polyisa-host` への OS 依存 API 集約の方針
- `lui` の rs フィールド厳格化（実シリコンの受理挙動との互換の要否）
- 段階 15-24: 版の範囲に根拠資料が無い項目（LSI-11/11-03）の追加登録か範囲除外の決定（SPARC V7 は SPEC-SPARC-V7 登録で、PA-RISC 1.0 は段階 17 の範囲除外で、SH-3/SH-3E は段階 18 の着手条件で SPEC-SUPERH-SH3 登録による範囲維持で、それぞれ決定済み）

### 未完了・保留

- 各段階の残件は上記の各節と `gaps.md`（未着手・代替の行が正本）。GAP-0023 の残項目は段階 15 以降の非 LLVM ISA の着手条件
- TEST-RISCV-ARCH-TEST: 後継の riscv/riscv-arch-test は ACT4 フレームワークへの全面移行（riscof 廃止・自己検査型 ELF）で、追従にはハーネスの再設計と利用条件の再確認が要る
- 段階 15-24 の計画のうち着手条件に未確定項目があるものは、`design/roadmap.md` の各段階の作業計画の先頭ステップで確認する
