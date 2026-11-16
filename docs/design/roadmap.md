# ロードマップ

この文書は、実装を進める段階の順序と、各段階の完了条件を定める。段階の順序は、共通の抽象の誤りをできるだけ早く見つけることを優先して決めた。抽象の誤りは、その抽象の上に実装した ISA の数だけ修正の費用が増えるからである。

## 順序の考え方

最初に一つの ISA で、ISADL からユーザーモードでのプログラムの実行までを一通り動かす。この ISA には RISC-V を選ぶ。RISC-V は、エンコーディングが規則的で ISADL の最初の実装に向き、公式の適合テストスイートがあり、手元の clang と rustup のターゲットでテスト用のプログラムを作れる。

次に、性質の大きく異なる ISA の小さな部分集合を試作し、共通の抽象が受け止められるかを確かめる。パケット（Hexagon）、バンドルと回転レジスタ（IA-64）、レジスタウィンドウと遅延スロット（SPARC）、モジュール構造とスタックマシン（WebAssembly）がその対象である。試作で抽象を直してから、本格的な ISA の実装を増やす。

共通の抽象は、三つの ISA ファミリ（RISC-V、MIPS、x86）を本格的に実装し終えるまで、確定させない。確定までは、抽象の変更を通常の変更として行う。確定させた後の変更は ADR を書いて行う。

## 段階

完了条件の表の「判定」は、次の三つの形のいずれかである。`テスト：` のあとに続ける名前は、判定に使うテストバイナリであり、バッククォートで囲んで「、」で並べる。名前は `crates/*/tests/` か `guests/*/tests/` にある `.rs` のファイル名から、拡張子を除いたものである。`所有者` は、テストでは判定できず、所有者が判定することを示す。`未整備` は、判定に使えるテストがないことを示す。

### 段階 0：基盤

ワークスペース、検査、基礎のクレートを用意する。

- ワークスペースの定義、`Taskfile.yml`、nextest の設定、コミット前のフック（[開発作業とローカル検証](dev-workflow.md)）
- devtool の検査（外部依存の禁止、クレート間の依存規則、`cfg` の使用の規則、台帳の検査）
- [参照資料の台帳](../references.md) のうち、段階 0 と段階 1 で使う項目（RISC-V の仕様と psABI、ELF、Linux カーネルのソース、IEEE 754、TestFloat、riscv-tests、riscv-arch-test、使うツール）の確認
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

### 段階 1：RISC-V の縦の一本

RISC-V で、ユーザーモードのプログラムの実行までを通す。

- RV32 と RV64 の I、M、A、F、D、C、Zicsr、Zifencei と、汎用 CPU モデル
- `softfloat` の binary32 と binary64、TestFloat との比較
- `loader` の ELF、`kernel` と `os-linux` のシステムコールの段階 1 と 2（[ユーザーモード](user-mode.md)）
- `trace` の命令トレースとシステムコールトレース、`cli` の `run`、`cpus`、`disasm`
- llvm-objdump とのデコーダの差分テスト、riscv-tests と riscv-arch-test

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S1-1 | 静的リンクと動的リンクのテストプログラムが、ゲストのルートを使って正しい出力を返す。 | テスト：`heavy_program_hello`、`heavy_program_dyn` |
| S1-2 | riscv-tests と riscv-arch-test のユーザーモードの対象のテストが通る。 | テスト：`heavy_conformance_riscv_tests`、`heavy_conformance_rv64ui` |
| S1-3 | 意味論をバックエンドに対して総称的に書いた版と、インタプリタ専用に直接書いた版を、代表的な命令で比較するベンチマークを取り、性能の差を記録する。差が 10% を超えた場合は、原因を調べ、バックエンドトレイトの設計を見直すか、差を受け入れる理由を ADR に書く。 | 所有者 |

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

### 段階 4：x86

可変長命令、オペコード表、遅延評価のフラグ、x87 を確かめる。

- x86-32 と x86-64 のゲスト ABI、x87 と SSE2 までを最初の範囲とし、後から拡張を足す
- CPUID の機能からの導出、Intel と AMD の挙動パラメータ
- ホストの CPU との実行の差分テスト
- システムコールの段階 4（busybox が動く）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S4-1 | x86-64 と x86-32 の busybox のコマンド群のテストが通る。対象のコマンドは、台帳で確認した busybox の `busybox --list` が示すアプレットとする。`df` の扱いは [ADR-0014](../adr/0014-statfs-number-table-only.md) による。 | テスト：`heavy_program_busybox` |
| S4-2 | この段階の終わりに共通の抽象を見直し、確定させる。 | 所有者 |

### 段階 5 以降

段階 5 以降は、一段階につき一つの対象に絞る。複数の ISA を一つの段階にまとめると、完了条件の判定を段階全体に閉じられず、遅れている ISA のために先に終わった作業を確定できないからである。段階の順序は目安であり、必要に応じて入れ替える。段階間に依存があるときは、その段階の冒頭に「前提」として書く。

各 ISA の段階では、その ISA の Linux ゲスト ABI（システムコール番号表、呼出規約、構造体と定数の表、シグナルフレーム、初期スタックと補助ベクタ）を実装する。Linux が動かない ISA と版の範囲は、裸実行環境で検証する。

判定が `未整備` の条件は、判定に使うテストの名前を条件の文に書く。テストはその段階の作業の中で作り、判定を `テスト：` に更新する。

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

### 段階 9：IR と JIT

前提：段階 6 から 8（主対象の ISA が三つ動いている）。

`ir` クレートと `jit` クレートを実装し、x86-64 のホストのバックエンドを持つ（[JIT](jit.md)）。

- ブロック単位の SSA の IR と、IR の解釈実行器。バックエンドトレイトの操作と一対一に対応する操作、ブロックの出口の分類、ブロック内の最適化（定数畳み込み、共通部分式、デッドストア、レジスタ保持）
- x86-64（System V）のホストのバックエンド。命令のエンコードは x86 の ISADL の記述から生成したエンコーダを使う。実行可能メモリは `host` 経由で、書き込み可能な状態で書いてから実行可能に切り替える
- 実行回数による階層化、ブロックの連結、タイミングモデルとの接続、観測が要求されたブロックのインタプリタへの切り戻し

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S9-1 | 三つ以上の主対象の ISA で、JIT とインタプリタの実行結果がブロックの境界ごとに一致する（[検証戦略](testing.md) の層 9、テスト `heavy_jit_diff`）。 | テスト：`heavy_jit_diff` |

### 段階 10：十進演算と非 IEEE 浮動小数点

以降の段階で実装する ISA が必要とする、`decimal` クレートと `softfloat` の非 IEEE 形式（[浮動小数点と十進演算](floating-point.md)）。

- `decimal`：ISA ごとの環境を持つパック十進整数（BCD）の演算と、IEEE 754 十進浮動小数点（DPD 符号化）
- `softfloat` の拡張：IBM 16 進浮動小数点、DEC の F、D、G、H 形式、68881 の拡張精度
- Power の十進浮動小数点と `bcdadd.` の意味論はこの段階で追加する。s390 系の 16 進浮動小数点と十進演算は、この段階の基盤の上で段階 11 が実装する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S10-1 | `decimal` の演算が decTest と比較して一致する（テスト `heavy_conformance_dectest`）。 | テスト：`heavy_conformance_dectest` |
| S10-2 | 16 進浮動小数点、DEC の形式、68881 拡張精度が、仕様書の例と一致する（テスト `nonieee_examples`）。 | テスト：`nonieee_examples` |

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

### 段階 13：x86 の残り

前提：段階 10（x87 の BCD 命令）。

段階 4 の範囲の外にあった x86 の部分を実装する。

- 8086、8088、80286。Linux が動かないので裸実行環境で検証する。命令プリフェッチキューによる自己書き換えコードの振る舞いは、機能の側で再現する
- SSE2 以降の拡張（SSE3 以降、AVX 系、AVX-512 のサブセット、AMX、APX）と、x86-64 のマイクロアーキテクチャレベルのプロファイル（v1 から v4）
- 80486 と Pentium の `exact` のタイミング表。U/V パイプラインはインオーダーの汎用モデル（段階 3 で R3000 に使ったもの）で表す

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S13-1 | 8088 の SingleStepTests のデータ集と命令の振る舞いが一致する（テスト `heavy_conformance_sst8088`）。 | 未整備 |
| S13-2 | 追加した拡張の命令単位テストが裸実行環境で通る（テスト `bare_x86ext`）。 | 未整備 |
| S13-3 | 80486 と Pentium のタイミングの検証用の命令列がすべて一致する（テスト `heavy_timing_i486`、`heavy_timing_pentium`）。 | 未整備 |

### 段階 14：m68k

前提：段階 10（68881 の拡張精度、BCD）。

- 版の範囲は 68000 から 68060 まで、CPU32、ColdFire、68881 と 68882 の FPU
- 実効アドレスと拡張語のフック、世代ごとのアライメントの差、68040 と 68060 の未実装命令は OS による命令の補完
- m68k のゲスト ABI。68000 の専用のタイミングモデル（バスサイクルとプリフェッチ）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S14-1 | 68000 の SingleStepTests のデータ集と命令の振る舞いが一致する（テスト `heavy_conformance_sst68000`）。 | 未整備 |
| S14-2 | 68000 のタイミングの検証用の命令列がすべて一致する（SingleStepTests のサイクル数を含めて使う。テスト `heavy_timing_68000`）。 | 未整備 |
| S14-3 | m68k の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_m68k`）。 | 未整備 |
| S14-4 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する（clang が m68k に対応しないため、層 6 の抽出方法は使えない）。 | 所有者 |

### 段階 15：SPARC

- 版の範囲は V7、V8、V9 と VIS。レジスタウィンドウ（動的なレジスタ参照、ウィンドウ数は CPU モデルのパラメータ）、ウィンドウのあふれと不足は OS パーソナリティが再現
- 遅延スロット、annul ビット、遅延スロット内の分岐（DCTI couple）、ユーザーが使える ASI、PSTATE.AM のアドレスマスク
- sparc32 と sparc64 のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S15-1 | sparc64 のテストプログラムと配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_sparc`）。 | 未整備 |
| S15-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_sparc`）。 | 未整備 |
| S15-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_sparc`）。 | 未整備 |

### 段階 16：Alpha

- 版の範囲は 21064 から 21364 までと、BWX、FIX、CIX、MVI の拡張。`AMASK` と `IMPLVER` は識別情報
- `CALL_PAL` の PAL コードの役割は OS パーソナリティ、浮動小数点の補完と非整列アクセスの補完は OS による命令の補完、8 KiB のページサイズ
- alpha のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S16-1 | alpha の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_alpha`）。 | 未整備 |
| S16-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

### 段階 17：PA-RISC

- 版の範囲は PA-RISC 1.0、1.1、2.0 と MAX。命令アドレスキューと遅延分岐、無効化（PSW の N ビット）
- Linux のシステムコールはゲートウェイページへの分岐（特別なアドレスを経由する OS の呼び出し）
- hppa（32 ビット）のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S17-1 | hppa の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_parisc`）。 | 未整備 |
| S17-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

### 段階 18：SuperH

- 版の範囲は SH-1 から SH-4A までと、SH-2 互換の J-core。SH-2A の 32 ビット命令はデコーダの入口の長さの規則で扱う
- SH-4 の FPSCR の PR、SZ、FR は実行モード。遅延スロット内の分岐はスロット不正命令の例外。gUSA は再開可能な不可分列
- sh4（両エンディアン）のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S18-1 | sh4 の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_superh`）。 | 未整備 |
| S18-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

### 段階 19：LoongArch

- 版の範囲は LA32 と LA64、LSX、LASX、LBT の拡張。LBT が参照する x86 と ARM の状態は CPU 状態に含める。LSX、LASX、LBT の公式仕様（Reference Manual の Vol.2、Vol.3）は未刊行であり、公開されるまで拡張の実装は保留する（SPEC-LOONGARCH-VEXT）
- 初期の独自の ABI と本流の ABI はゲスト ABI の変種として区別する。`CPUCFG` は識別情報
- LA64 のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S19-1 | la64 のテストプログラムと配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_loongarch`）。 | 未整備 |
| S19-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_loongarch`）。 | 未整備 |
| S19-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_loongarch`）。 | 未整備 |

### 段階 20：OpenRISC

- 版の範囲は OpenRISC 1000 アーキテクチャの各版と浮動小数点の拡張。遅延スロットの有無は機能とする
- or1k のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S20-1 | or1k の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_openrisc`）。 | 未整備 |
| S20-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

### 段階 21：IA-64

- 版の範囲は Itanium から Itanium 9700 系まで。128 ビットのバンドル、述語実行、回転レジスタとレジスタスタック（バッキングストアへの実際の書き出し）、NaT と ALAT
- システムコールは `break 0x100000` とゲートページの高速なシステムコール
- ia64 のゲスト ABI（Linux 6.7 で削除されたため、削除前のカーネルの ABI を対象にする）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S21-1 | ia64 の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_ia64`）。 | 未整備 |
| S21-2 | ABI 表が SRC-LINUX-66 の UAPI と一致することを所有者が確認する。 | 所有者 |

### 段階 22：Hexagon

- 版の範囲は V5 以降の各版と HVX。パケットのステップ、`.new` オペランド、デュプレックス、定数拡張子、ハードウェアループ
- 複数のハードウェアスレッドを交互に実行する構造に対応する専用のタイミングモデル
- hexagon のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S22-1 | hexagon の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_hexagon`）。 | 未整備 |
| S22-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_hexagon`）。 | 未整備 |
| S22-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_hexagon`）。 | 未整備 |

### 段階 23：VAX

前提：段階 10（DEC の浮動小数点形式、パック十進）。

- 版の範囲は VAX-11/780 から NVAX まで、MicroVAX のサブセット、F、D、G、H の浮動小数点形式
- オペランド指定子のフック、`CALLS` と `RET` のフレーム、中断可能な命令の途中状態、MicroVAX が省いた命令は OS による命令の補完
- マイクロコードによる実行時間の専用のタイミングモデル
- 主流の Linux の移植がないので裸実行環境で検証する。BSD パーソナリティは段階 25 で扱う

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S23-1 | 命令単位のテストが裸実行環境で通る（DEC の形式とパック十進を含む。テスト `bare_vax`）。 | 未整備 |

### 段階 24：PDP-11

前提：段階 10（F、D の浮動小数点形式）。

- 版の範囲は 11/03 から J-11 までの各モデルと、EIS、FIS、FP11、CIS のオプション。モデル間の振る舞いの差は挙動パラメータ
- 命令空間とデータ空間の分離（アクセスの種類ごとにアドレス空間を選ぶ `mem` の拡張）
- 裸実行環境で検証する。Unix V7 パーソナリティは段階 25 で扱う

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S24-1 | 命令単位のテストが裸実行環境で通る（分離 I&D のアドレス空間を含む。テスト `bare_pdp11`）。 | 未整備 |

### 段階 25：追加の OS パーソナリティ

前提：段階 23 と 24。WASI は段階 12 で実装済みである。

- PDP-11 の Unix V7 と、VAX の BSD（対象の版は実装時に決める）の OS パーソナリティ。いずれも仮想カーネルの機構を共有し、システムコールの規約だけを実装する
- a.out の変種を解析するローダ
- ベアメタルのテスト用のセミホスティング（主に ARM と RISC-V の対象）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S25-1 | Unix V7 のプログラムが PDP-11 で正しく動く（テスト `heavy_program_unixv7`）。 | 未整備 |
| S25-2 | BSD のプログラムが VAX で正しく動く（テスト `heavy_program_bsdvax`）。 | 未整備 |
| S25-3 | セミホスティングを使うプログラムが正しく動く（テスト `heavy_program_semihosting`）。 | 未整備 |

### 段階 26：システムコールの段階 5

[ユーザーモード](user-mode.md) の実装の段階の 5（ネットワークと待ち合わせ）。

- ソケット関連、`poll`、`ppoll`、`epoll_*`、`timerfd_*`、`eventfd2`
- ファイル記述子が指す対象を多態な型で表す表への作り替え（GAP-0025 の解消を含む）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S26-1 | ソケットと待ち合わせを使うプログラムが正しく動く（テスト `heavy_program_net`）。 | 未整備 |

### 段階 27：タイミングの残りの汎用モデルと較正

ISA 固有のタイミング（68000、80486、Pentium、VAX）は各 ISA の段階で扱う。この段階では `timing` クレートの残りの汎用モデルと、`approx` の較正を行う。

- キャッシュ階層、分岐予測器、アウトオブオーダー実行の汎用モデル
- `approx` の較正用のベンチマーク集（マイクロベンチマークと実際のプログラム）と、インオーダーの現行の CPU（SiFive U74 など）の `approx` の CPU モデル。較正できていないモデルは「未較正」と表示する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S27-1 | アウトオブオーダーの汎用モデルが、マイクロベンチマークで宣言した誤差の範囲に収まる（テスト `heavy_timing_ooo`）。 | 未整備 |
| S27-2 | U74 の `approx` が実機の計測で較正され、宣言した誤差の範囲に収まる（実機の計測が条件）。 | 所有者 |

### 段階 28：ホストの移植

[ホスト抽象化](host.md) の段階表に従い、ホストを増やす。各ホストの OS の文書は、使う前に台帳へ登録する。

- 段階 2：Linux AArch64 と macOS（Apple Silicon）。インタプリタから始める。AArch64 の JIT のバックエンドはこの段階で追加を検討する。macOS の JIT は `MAP_JIT` と書き込み保護の切り替えが必要になる
- 段階 3：Windows x86_64。ゲストの uid、gid、パーミッションは仮想カーネルで合成する
- 段階 4：wasm32。インタプリタのみ。ホストのスレッドがない環境では、ホストの入出力を直接行う

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S28-1 | Linux AArch64 のホストで `task test:full` が通る（ホストの環境が条件）。 | 所有者 |
| S28-2 | macOS（Apple Silicon）のホストで `task test:full` が通る（同上）。 | 所有者 |
| S28-3 | Windows x86_64 のホストで `task test:full` が通る（同上）。 | 所有者 |
| S28-4 | wasm32 のホストでインタプリタによる実行が動く（同上）。 | 所有者 |

### 段階 29：GDB 接続

- `gdbstub` による GDB との接続。レジスタの転送、シングルステップ、ブレークポイントを、実行エンジンの観測点を通して提供する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S29-1 | GDB からの接続、シングルステップ、ブレークポイント、レジスタの読み書きが動く（テスト `heavy_gdbstub`）。 | 未整備 |

## ISA の実装の着手の条件

ISA ファミリの実装を始める前に、その ISA の仕様書、ABI の文書、テストに使う資料とツールを台帳に登録し、所有者が確認済みにする（[ADR-0010](../adr/0010-reference-register.md)）。段階 2 の試作も同じ条件に従う。確認が済んでいない資料に依存する作業は始めない。

LLVM の対応しない ISA（m68k、Alpha、PA-RISC、SuperH、OpenRISC、IA-64、VAX、PDP-11）では、オラクルの逆アセンブラと、テストの命令列を組み立てる手段がない。これらの ISA の命令単位のテストは ISADL から生成したエンコーダで組み立てるので、エンコーダとオペランド入りの逆アセンブラの生成（GAP-0023 の解消）を着手の条件に含める。

### 段階ごとの確認対象

所有者が確認する台帳項目は、段階ごとにおおむね次のとおりである。版・用途の確定を含む。

| 段階 | 仕様書 | ABI・テスト・ツール |
|---|---|---|
| 段階 2（Hexagon 試作） | SPEC-HEXAGON-PRM（版確定） | TOOL-LLVM（確認済みで足りるか点検）、リンカ方針 |
| 段階 2（IA-64 試作） | SPEC-IA64-SDM（版確定） | オラクルなし（手組ベクタは SPEC の F 許可が条件） |
| 段階 2（SPARC 試作） | SPEC-SPARC-V8（V9 要否含む） | TOOL-LLVM（確認済み） |
| 段階 2（WASM 試作） | SPEC-WASM-CORE、SPEC-WASI-P1（版確定） | TEST-WASM-SPEC、TOOL-WASMTIME（用途Xは確認時に付与） |
| 段階 3（MIPS） | SPEC-MIPS-IV/R6/R3000（版確定） | o32/n32/n64 の ABI 文書（未登録分は追加）、TOOL-LLVM |
| 段階 4（x86） | SPEC-X86 各書、SPEC-X86-PSABI（登録済み、版は確認時に確定） | busybox 等の BIN（未登録分は追加） |
| 段階 5（MIPS の本実装） | SPEC-MIPS-IV/R6/R3000（確認済み） | SPEC-MIPS-ABI-N32（版確定）、SRC-LINUX |
| 段階 6（AArch64） | SPEC-ARM-ARM-A（確認済み） | SPEC-AARCH64-ABI（確認済み）、SPEC-AARCH64-ELF（版確定）、BIN（aarch64 の配布物、未登録分は追加）、TOOL-LLVM |
| 段階 7（ARM） | SPEC-ARM-ARM-A、SPEC-ARM-ARM-V7AR、SPEC-ARM-ARM-LEGACY（確認済み） | SPEC-ARM-EABI（確認済み）、BIN（未登録分は追加）、TOOL-LLVM |
| 段階 8（Power） | SPEC-POWER-ISA（確認済み）、SPEC-POWERPC-PEM（版確定）、SPEC-POWER-PEM64（版確定）、SPEC-POWER-601-UM（版確定）、SPEC-POWER-ALTIVEC-PEM（版確定）、SPEC-POWER-EREF（版確定）、SPEC-POWER-SPE-PEM（版確定） | SPEC-POWER-ABI（確認済み）、SPEC-POWER-ABI32（版確定）、BIN（未登録分は追加）、TOOL-LLVM |
| 段階 9（IR と JIT） | 既存の確認済み項目で足りるか点検（x86 のエンコーダ生成に使う記述は段階 4 と同じ資料） | — |
| 段階 10（十進演算と非 IEEE 浮動小数点） | SPEC-DECIMAL-ARITH（確認済み）、各形式の根拠（SPEC-S390-ZARCH-POP、SPEC-VAX-ARM、SPEC-M68K-FPU） | TEST-DECTEST（確認済み） |
| 段階 11（s390 系） | SPEC-S390-ZARCH-POP（確認済み）、SPEC-S390-ESA390-POP（版確定）、SPEC-S390-S360-POP（版確定） | SPEC-S390-ABI（確認済み）、SPEC-S390-ABI-31（版確定）、BIN（未登録分は追加）、TOOL-LLVM |
| 段階 12（WebAssembly と WASI） | SPEC-WASM-CORE、SPEC-WASI-P1（確認済み） | TEST-WASM-SPEC、TOOL-WASMTIME |
| 段階 13（x86 の残り） | SPEC-X86-8086（確認済み）、SPEC-X86-I286（版確定）、SPEC-X86-PENTIUM（確認済み）、SPEC-X86-I486（版確定） | TEST-SINGLESTEP-8088、MEAS-UOPS-INFO、MEAS-AGNER |
| 段階 14（m68k） | SPEC-M68K-PRM、SPEC-M68K-UM、SPEC-M68K-FPU（確認済み）、SPEC-M68K-CPU32（版確定）、SPEC-M68K-COLDFIRE（版確定） | SPEC-M68K-ABI（版確定）、TEST-SINGLESTEP-68000、SRC-LINUX、BIN（未登録分は追加） |
| 段階 15（SPARC） | SPEC-SPARC-V8（確認済み）、SPEC-SPARC-V9（版確定） | SPEC-SPARC-PSABI（版確定）、SRC-LINUX、BIN（未登録分は追加）、TOOL-LLVM |
| 段階 16（Alpha） | SPEC-ALPHA-ARM（版確定） | SPEC-ALPHA-CALLSTD（版確定）、SRC-LINUX、BIN（未登録分は追加） |
| 段階 17（PA-RISC） | SPEC-PARISC-11、SPEC-PARISC-20（確認済み） | SRC-LINUX、BIN（未登録分は追加） |
| 段階 18（SuperH） | SPEC-SUPERH-SH2、SPEC-SUPERH-SH4（確認済み）、SPEC-SUPERH-SH2A（版確定）、SPEC-SUPERH-JCORE（版確定） | SRC-LINUX、BIN（未登録分は追加） |
| 段階 19（LoongArch） | SPEC-LOONGARCH-RM（確認済み）、SPEC-LOONGARCH-VEXT（未刊行。公開を待つか方針を決める） | SPEC-LOONGARCH-PSABI（版確定）、SRC-LINUX、BIN（未登録分は追加）、TOOL-LLVM |
| 段階 20（OpenRISC） | SPEC-OPENRISC-1000（確認済み） | SRC-LINUX、BIN（未登録分は追加） |
| 段階 21（IA-64） | SPEC-IA64-SDM（確認済み） | SRC-LINUX-66、BIN（未登録分は追加） |
| 段階 22（Hexagon） | SPEC-HEXAGON-PRM（確認済み）、SPEC-HEXAGON-PRM-PREV（版確定） | SRC-LINUX、BIN（未登録分は追加）、TOOL-LLVM |
| 段階 23（VAX） | SPEC-VAX-ARM（確認済み）、SPEC-VAX-MICROVAX（版確定） | — |
| 段階 24（PDP-11） | SPEC-PDP11-HANDBOOK（確認済み）、SPEC-PDP11-ARCH83（版確定）、SPEC-PDP11-CIS（版確定）、SPEC-PDP11-J11（版確定） | — |
| 段階 25（追加の OS パーソナリティ） | SPEC-UNIX-V7（版確定）、SPEC-BSD-43（版確定）、SPEC-ARM-SEMIHOST（版確定） | V7 と BSD のバイナリ（未登録分は追加） |
| 段階 26（システムコールの段階 5） | SRC-LINUX（確認済み）、SPEC-LINUX-MANPAGES（確認済み） | BIN（未登録分は追加） |
| 段階 27（タイミングの残り） | SPEC-SIFIVE-U74（確認済み）ほか対象の CPU の資料 | 較正用のベンチマーク集（未登録分は追加） |
| 段階 28（ホストの移植） | SPEC-WIN32（版確定）、SRC-XNU（版確定） | 各ホスト OS の文書（未登録分は追加） |
| 段階 29（GDB 接続） | SPEC-GDB-RSP（版確定） | TOOL-GDB（確認済み） |

## 各段階に共通の完了条件

どの段階でも、次のことを完了の条件に含める。

| ID | 条件 | 判定 |
|---|---|---|
| SC-1 | 追加した ISA と CPU モデルについて、[検証戦略](testing.md) の層 1 から 3 のテストがある。 | 所有者 |
| SC-2 | `task test:full` を実行し、その結果を完了のタグのメッセージに記録している（[開発作業とローカル検証](dev-workflow.md)）。 | 所有者 |
| SC-3 | 追加した機能の設計が、設計文書に反映されている。設計を変えた場合は、該当する文書を同じ変更で更新する。 | 所有者 |
| SC-4 | 新たに下した設計判断のうち、元に戻すのに大きな費用がかかるものは ADR に記録されている。 | 所有者 |
