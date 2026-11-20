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
| 17 | PA-RISC | 進行中（作業計画は `design/roadmap.md` の該当段階） |
| 18-24 | SuperH〜PDP-11 | 未着手（作業計画は `design/roadmap.md` の各段階） |
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
- 段階 15-24: 版の範囲に根拠資料が無い項目（SH-3/SH-3E・LSI-11/11-03）の追加登録か範囲除外の決定（SPARC V7 は SPEC-SPARC-V7 登録で、PA-RISC 1.0 は段階 17 の範囲除外で決定済み）

### 未完了・保留

- 各段階の残件は上記の各節と `gaps.md`（未着手・代替の行が正本）。GAP-0023 の残項目は段階 15 以降の非 LLVM ISA の着手条件
- TEST-RISCV-ARCH-TEST: 後継の riscv/riscv-arch-test は ACT4 フレームワークへの全面移行（riscof 廃止・自己検査型 ELF）で、追従にはハーネスの再設計と利用条件の再確認が要る
- 段階 15-24 の計画のうち着手条件に未確定項目があるものは、`design/roadmap.md` の各段階の作業計画の先頭ステップで確認する
