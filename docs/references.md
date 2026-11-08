# 参照資料の台帳

この文書は、polyisa が参照し、または使用する外部の資料とツールを、利用条件とともに一か所で管理する台帳である。台帳を設けた理由と運用の決定は [ADR-0010](adr/0010-reference-register.md) にある。ライセンスと利用条件の情報はこの文書にだけ書き、他の文書、コード、ISADL の記述、テストは、台帳の ID で資料を参照する。

## 対象

台帳には次の種類の資料を登録する。種類は ID の接頭辞で表す。

| 接頭辞 | 種類 | 例 |
|---|---|---|
| `SPEC-` | 仕様 | ISA の仕様書、プロセッサのマニュアル、ABI の文書、規格 |
| `SRC-` | ソース | 事実を確かめるために読むソースコード |
| `TEST-` | テスト | テストスイート、テストベクタ、テストデータ集 |
| `BIN-` | バイナリ | テストの入力として実行する他者のバイナリ |
| `MEAS-` | 計測データ | 公開されている命令の実行時間などの計測値 |
| `TOOL-` | ツール | 別プロセスとして実行する外部のツール |

台帳が扱うのは、著作権のライセンスと、資料に付いた利用条件である。特許の扱いは台帳では判断しない。資料の利用条件が特許に言及している場合は、その旨を備考に書き、所有者が別に判断する。

## 用途

各項目は、polyisa がその資料をどう使ってよいかを、次の用途の記号の組み合わせで示す。

| 記号 | 用途 | 内容 |
|---|---|---|
| `R` | 参照 | 読んで理解し、設計と実装の判断に使う。本文、図、表、コードを複製しない |
| `F` | 事実の記述 | 資料が定める事実（エンコーディング、定数、構造体の配置、数値）を、polyisa 自身の表現（ISADL、Rust の表、テストの期待値）で書く |
| `T` | 取得して検証に使う | テストの実行の前にローカルへ取得し、テストの入力や期待値として使う。リポジトリには入れない |
| `X` | 実行 | 別プロセスとして実行する |
| `D` | 再配布 | 資料の全部または一部をリポジトリに含める |
| `C` | コードの流用 | ソースコードを複製、移植、翻訳する |

ライセンスが決まるまでは、どの項目にも `D` と `C` を許可しない（[ADR-0009](adr/0009-no-code-reuse-until-license.md)）。

## 規則

1. polyisa の成果物（コード、ISADL の記述、テスト、文書）に資料の内容を反映する前に、その資料を台帳に登録する。
2. 用途は、利用条件の原文を読み、原文が許していると確認できたものだけを許可する。原文から判断できない用途は許可しない。
3. 利用条件の確認は版ごとに行う。参照する版を変えたら、確認をやり直す。
4. 項目を確認済みにできるのはプロジェクトの所有者だけである。他の参加者と AI のエージェントは、項目を追加して確認を依頼できるが、「確認」の欄は埋めない。確認の欄は `YYYY-MM-DD 確認者名` の形で書く。
5. 成果物（`crates/`、`guests/`、`tools/` のコード、ISADL の記述、テスト、取得定義）の中で資料を参照するときは、機械可読の注記で書く。Rust のコードとテストでは `// Ref: SPEC-RISCV-UNPRIV §2.4` のように ID と節を書き、ライセンスの情報を書き写さない。ISADL では `reference SPEC-RISCV-UNPRIV;` と `ref SPEC-RISCV-UNPRIV "§2.4"` で書く。この書式以外の ID の言及は、検査の参照とみなさない。
6. 確認済みでない項目は、成果物のいかなる用途にも使わない。ただし、利用条件を確かめるために資料を読むことは除く。設計文書での引用は記述の形を示す例示に限り、実装の根拠にしない。例示の引用は検査の対象外とする。
7. 用途の欄は `R`、`F`、`T`、`X` の組み合わせをカンマ区切りで書く（例：`R,F`）。確認前は `—` とする。`—` はいかなる用途の許可も表さない。`D` と `C` はライセンス決定まで書かない。
8. 開発の立ち上げに必要な道具（`TOOL-RUST`、`TOOL-GIT`、`TOOL-CURL`、`TOOL-TASK`、`TOOL-NEXTEST`）は、他の項目に先立って確認する。それまでの開発作業は、利用条件を確かめる範囲（規則 6 の例外）に位置づける。

## 機械的な検査

`task refs:check` は次のことを検査し、違反があれば失敗する。この検査は `task check` に含まれ、Git のコミット前のフックでも実行される（[開発作業とローカル検証](design/dev-workflow.md)）。

1. 成果物（`crates/`、`guests/`、`tools/`）の固定書式の注記に現れる台帳の ID が、すべて台帳にある。
2. 参照された項目が確認済みであり、参照の場所に応じた用途を許可している。確認の欄が `YYYY-MM-DD` で始まる日付と確認者名で埋まり、用途の欄に必要な記号が含まれていること。

   | 参照の場所 | 必要な用途 |
   |---|---|
   | ISADL の `reference` と `ref`、Rust のコードとテストの出典の注記（`// Ref:`） | `F` |
   | テストデータの取得定義と、`testkit` の表に書いたテストデータ | `T` |
   | `testkit` の表に書いたツールと、devtool が実行するツール | `X` |

3. テストデータの取得先（`.testdata/`）が `.gitignore` の対象であり、`git ls-files` に現れない。取得定義（`tools/testdata/manifest.txt`）がある場合は、各行の ID が台帳にあり、用途 `T` が許可されていること。
4. 台帳を除くリポジトリのファイルに、polyisa のもの以外の著作権表示と SPDX のライセンス識別子が含まれていない。走査するのは `Copyright`、`©`、`SPDX-License-Identifier` の文字列であり、台帳の `docs/references.md` は対象外とする。
5. `Cargo.lock` にワークスペース外のパッケージがない（[ADR-0001](adr/0001-no-external-crates.md)）。

設計文書と台帳は、1 と 2 の検査の対象外とする。設計文書に現れる ID は、記述の形を示す例示とみなす。設計文書での資料の参照（`R`）は、規則 1 と 6 によって管理する。

この検査は、許可されていない用途の多くを見つけられるが、すべてではない。資料の文章を言い換えて書き写した場合や、ID を書かずに資料の内容を使った場合は見つからない。規則 1 と 5 が守られていなければ、検査は違反を見つけられない。

台帳の表は `task refs:check` が読む。表の列の順序と書式を変えるときは、検査の実装も同じ変更で直す。

## 台帳

各列の意味は次のとおりである。

- 版：利用条件を確認した版。確認前は空欄（`—`）とする。
- 対象：その資料を使う ISA ファミリ、クレート、作業。
- 利用条件：ライセンスや利用規約の名称と、原文の所在。
- 用途：許可した用途の記号。確認前は空欄とする。
- 確認：確認した日付と確認者。確認前は「未確認」とする。

名称の欄に「書名は確認時に確定」とある項目は、正式な書名をまだ特定していない。確認の際に正式な書名を記入する。

以下の項目は、設計文書が予定している資料を登録したものであり、すべて未確認である。ISA ファミリごとの ABI の文書など、ここにない資料は、その ISA の実装を始めるときに登録する（[ロードマップ](design/roadmap.md) の着手の条件）。

### 仕様

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| SPEC-X86-INTEL-SDM | Intel 64 and IA-32 Architectures Software Developer's Manual | Intel | — | x86 | — | — | 未確認 | |
| SPEC-X86-AMD-APM | AMD64 Architecture Programmer's Manual | AMD | — | x86 | — | — | 未確認 | |
| SPEC-X86-INTEL-OPT | Intel 64 and IA-32 Architectures Optimization Reference Manual | Intel | — | x86 のタイミング | — | — | 未確認 | |
| SPEC-X86-8086 | 8086 と 8088 のユーザーズマニュアル（書名は確認時に確定） | Intel | — | x86（8086、8088） | — | — | 未確認 | |
| SPEC-X86-I486 | 80486 のプログラマ向けリファレンスマニュアル（書名は確認時に確定） | Intel | — | x86（80486 のタイミング） | — | — | 未確認 | |
| SPEC-X86-PENTIUM | Pentium の開発者向けマニュアル（書名は確認時に確定） | Intel | — | x86（Pentium のタイミング） | — | — | 未確認 | |
| SPEC-ARM-ARM-A | Arm Architecture Reference Manual for A-profile architecture | Arm | — | aarch64、arm | — | — | 未確認 | |
| SPEC-ARM-ARM-V7AR | ARM Architecture Reference Manual, ARMv7-A and ARMv7-R edition | Arm | — | arm | — | — | 未確認 | |
| SPEC-ARM-ARM-LEGACY | ARMv6 以前の ARM Architecture Reference Manual（版は確認時に確定） | Arm | — | arm | — | — | 未確認 | |
| SPEC-MIPS-R6 | MIPS Architecture For Programmers（MIPS32 と MIPS64 の Release 6） | MIPS | — | mips | — | — | 未確認 | |
| SPEC-MIPS-IV | MIPS IV Instruction Set | MIPS Technologies | — | mips | — | — | 未確認 | |
| SPEC-MIPS-R3000 | R3000 のソフトウェアリファレンスマニュアル（書名は確認時に確定） | 確認時に記録 | — | mips（R3000 のタイミング） | — | — | 未確認 | |
| SPEC-RISCV-UNPRIV | The RISC-V Instruction Set Manual, Volume I: Unprivileged Architecture | RISC-V International | — | riscv | — | — | 未確認 | |
| SPEC-RISCV-PRIV | The RISC-V Instruction Set Manual, Volume II: Privileged Architecture | RISC-V International | — | riscv | — | — | 未確認 | |
| SPEC-RISCV-PROFILES | RISC-V Profiles | RISC-V International | — | riscv | — | — | 未確認 | |
| SPEC-RISCV-PSABI | RISC-V ELF psABI Specification | RISC-V International | — | riscv、os-linux | — | — | 未確認 | |
| SPEC-SIFIVE-U74 | SiFive U74 のコアのマニュアル（書名は確認時に確定） | SiFive | — | riscv（U74 のタイミング） | — | — | 未確認 | |
| SPEC-POWER-ISA | Power ISA | OpenPOWER Foundation | — | power | — | — | 未確認 | |
| SPEC-POWERPC-PEM | 32 ビットの PowerPC のプログラミング環境のマニュアル（書名は確認時に確定） | 確認時に記録 | — | power | — | — | 未確認 | |
| SPEC-S390-ZARCH-POP | z/Architecture Principles of Operation | IBM | — | s390 | — | — | 未確認 | |
| SPEC-S390-ESA390-POP | Enterprise Systems Architecture/390 Principles of Operation | IBM | — | s390 | — | — | 未確認 | |
| SPEC-S390-S360-POP | IBM System/360 Principles of Operation | IBM | — | s390 | — | — | 未確認 | |
| SPEC-WASM-CORE | WebAssembly Core Specification | W3C | — | wasm | — | — | 未確認 | |
| SPEC-WASI-P1 | WASI preview1 の定義 | 確認時に記録 | — | wasm、os-wasi | — | — | 未確認 | |
| SPEC-M68K-PRM | M68000 Family Programmer's Reference Manual | Motorola | — | m68k | — | — | 未確認 | |
| SPEC-M68K-UM | M68000 8-/16-/32-Bit Microprocessors User's Manual | Motorola | — | m68k（68000 のタイミング） | — | — | 未確認 | |
| SPEC-M68K-FPU | MC68881/MC68882 Floating-Point Coprocessor User's Manual | Motorola | — | m68k | — | — | 未確認 | |
| SPEC-M68K-COLDFIRE | ColdFire Family Programmer's Reference Manual | Freescale | — | m68k | — | — | 未確認 | |
| SPEC-VAX-ARM | VAX Architecture Reference Manual | DEC | — | vax | — | — | 未確認 | |
| SPEC-PDP11-HANDBOOK | PDP-11 Processor Handbook（モデルごとの版は確認時に確定） | DEC | — | pdp11 | — | — | 未確認 | |
| SPEC-SPARC-V8 | The SPARC Architecture Manual, Version 8 | SPARC International | — | sparc | — | — | 未確認 | |
| SPEC-SPARC-V9 | The SPARC Architecture Manual, Version 9 | SPARC International | — | sparc | — | — | 未確認 | |
| SPEC-ALPHA-ARM | Alpha Architecture Reference Manual | DEC | — | alpha | — | — | 未確認 | |
| SPEC-PARISC-11 | PA-RISC 1.1 Architecture and Instruction Set Reference Manual | HP | — | parisc | — | — | 未確認 | |
| SPEC-PARISC-20 | PA-RISC 2.0 Architecture | HP | — | parisc | — | — | 未確認 | |
| SPEC-SUPERH-SH2 | SH-1 と SH-2 のソフトウェアマニュアル（書名は確認時に確定） | 確認時に記録 | — | superh | — | — | 未確認 | |
| SPEC-SUPERH-SH4 | SH-4 のソフトウェアマニュアル（書名は確認時に確定） | 確認時に記録 | — | superh | — | — | 未確認 | |
| SPEC-LOONGARCH-RM | LoongArch Reference Manual, Volume 1: Basic Architecture | Loongson | — | loongarch | — | — | 未確認 | |
| SPEC-OPENRISC-1000 | OpenRISC 1000 Architecture Manual | 確認時に記録 | — | openrisc | — | — | 未確認 | |
| SPEC-IA64-SDM | Intel Itanium Architecture Software Developer's Manual | Intel | — | ia64 | — | — | 未確認 | |
| SPEC-HEXAGON-PRM | Hexagon の Programmer's Reference Manual（版ごとに項目を分ける） | Qualcomm | — | hexagon | — | — | 未確認 | |
| SPEC-IEEE754 | IEEE Standard for Floating-Point Arithmetic（IEEE 754） | IEEE | — | softfloat | — | — | 未確認 | |
| SPEC-DECIMAL-ARITH | General Decimal Arithmetic Specification | 確認時に記録 | — | decimal | — | — | 未確認 | |
| SPEC-ELF-GABI | System V Application Binary Interface の ELF の汎用部分（書名は確認時に確定） | 確認時に記録 | — | loader | — | — | 未確認 | |
| SPEC-LINUX-MANPAGES | Linux man-pages | Linux man-pages プロジェクト | — | os-linux | — | — | 未確認 | |

### ソース

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| SRC-LINUX | Linux カーネルのソース（UAPI ヘッダ、システムコールの表、シグナルフレームの定義） | Linux カーネルの開発者 | — | os-linux | — | — | 未確認 | カーネル本体のコードの翻訳は `C` にあたる |

### テスト

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| TEST-RISCV-TESTS | riscv-tests | 確認時に記録 | — | riscv | — | — | 未確認 | |
| TEST-RISCV-ARCH-TEST | riscv-arch-test | 確認時に記録 | — | riscv | — | — | 未確認 | |
| TEST-WASM-SPEC | WebAssembly の仕様のテストスイート | 確認時に記録 | — | wasm | — | — | 未確認 | |
| TEST-TESTFLOAT | Berkeley TestFloat | 確認時に記録 | — | softfloat | — | — | 未確認 | テストベクタの生成のために実行する（`X`）ことと、生成したベクタを使う（`T`）ことの両方を要する |
| TEST-DECTEST | 十進演算のテストケース集（書名は確認時に確定） | 確認時に記録 | — | decimal | — | — | 未確認 | |
| TEST-SINGLESTEP-68000 | SingleStepTests の 68000 のテストデータ | 確認時に記録 | — | m68k | — | — | 未確認 | |
| TEST-SINGLESTEP-8088 | SingleStepTests の 8088 のテストデータ | 確認時に記録 | — | x86 | — | — | 未確認 | |

### バイナリ

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| BIN-DISTRO | Linux のディストリビューションのバイナリとライブラリ（ディストリビューションと版は確認時に確定） | 確認時に記録 | — | os-linux のプログラム単位のテスト | — | — | 未確認 | パッケージごとに利用条件が異なる。使うパッケージを確認時に列挙する |

### 計測データ

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| MEAS-UOPS-INFO | uops.info の命令の計測データ | 確認時に記録 | — | x86 のタイミング | — | — | 未確認 | |
| MEAS-AGNER | Agner Fog の命令表 | 確認時に記録 | — | x86 のタイミング | — | — | 未確認 | |

### ツール

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| TOOL-RUST | Rust のツールチェーン（rustc、cargo、rust-lld、rustfmt、clippy、Miri） | Rust プロジェクト | 1.99.1 | 全体 | MIT OR Apache-2.0（LICENSE-MIT、LICENSE-APACHE） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-TASK | Task 3.54.0（Arch Linux のパッケージ名は go-task） | go-task | 3.54.0 | 開発作業 | MIT（LICENSE） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-NEXTEST | cargo-nextest | nextest-rs | 0.9.151 | テストの実行 | MIT OR Apache-2.0（LICENSE-MIT、LICENSE-APACHE） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-GIT | Git | Git プロジェクト | 2.56.0 | 開発作業、テストデータの取得 | GNU GPL version 2（COPYING。v2 のみ） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-CURL | curl | curl プロジェクト | 8.23.0 | テストデータの取得 | curl license（COPYING） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-LLVM | LLVM と clang（llvm-objdump を含む） | LLVM プロジェクト | — | 検証 | — | — | 未確認 | |
| TOOL-GDB | GDB | GNU プロジェクト | — | 検証 | — | — | 未確認 | |
| TOOL-WASMTIME | wasmtime | Bytecode Alliance | — | wasm の検証 | — | — | 未確認 | |
| TOOL-QEMU | QEMU | QEMU プロジェクト | — | 検証（用意できた環境だけ） | — | — | 未確認 | |
| TOOL-BINUTILS | GNU binutils | GNU プロジェクト | — | 検証（用意できた環境だけ） | — | — | 未確認 | |
