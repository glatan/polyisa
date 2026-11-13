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

BSD 系の資産は `D` と `C` を許可できる。GPL 系の資産と Arm の機械可読仕様には `D` と `C` を許可しない（[ADR-0013](adr/0013-license-mit-or-apache.md)）。

## 規則

1. polyisa の成果物（コード、ISADL の記述、テスト、文書）に資料の内容を反映する前に、その資料を台帳に登録する。
2. 用途は、利用条件の原文を読み、原文が許していると確認できたものだけを許可する。原文から判断できない用途は許可しない。
3. 利用条件の確認は版ごとに行う。参照する版を変えたら、確認をやり直す。
4. 項目を確認済みにできるのはプロジェクトの所有者だけである。他の参加者と AI のエージェントは、項目を追加して確認を依頼できるが、「確認」の欄は埋めない。確認の欄は `YYYY-MM-DD 確認者名` の形で書く。
5. 成果物（`crates/`、`guests/`、`tools/` のコード、ISADL の記述、テスト、取得定義）の中で資料を参照するときは、機械可読の注記で書く。Rust のコードとテストでは `// Ref: SPEC-RISCV-UNPRIV §2.4` のように ID と節を書き、ライセンスの情報を書き写さない。ISADL では `reference SPEC-RISCV-UNPRIV;` と `ref SPEC-RISCV-UNPRIV "§2.4"` で書く。この書式以外の ID の言及は、検査の参照とみなさない。
6. 確認済みでない項目は、成果物のいかなる用途にも使わない。ただし、利用条件を確かめるために資料を読むことは除く。設計文書での引用は記述の形を示す例示に限り、実装の根拠にしない。例示の引用は検査の対象外とする。
7. 用途の欄は `R`、`F`、`T`、`X`、`D`、`C` の組み合わせをカンマ区切りで書く（例：`R,F`）。確認前は `—` とする。`—` はいかなる用途の許可も表さない。`D` と `C` は BSD 系の資産に限り、所有者が原文を確認して許可する。GPL 系の資産と Arm の機械可読仕様には `D` と `C` を許可しない。
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
4. 台帳と自前のライセンス文を除くリポジトリのファイルに、polyisa のもの以外の著作権表示と SPDX のライセンス識別子が含まれていない。走査するのは `Copyright`、`©`、`SPDX-License-Identifier` の文字列であり、台帳の `docs/references.md` と自前の `LICENSE-MIT`、`LICENSE-APACHE` は対象外とする。自前の `MIT OR Apache-2.0` の識別子行と `polyisa contributors` の著作権行は許可する。
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
| SPEC-X86-INTEL-SDM | Intel 64 and IA-32 Architectures Software Developer's Manual（Combined、Version 093、2026-09-24） | Intel | v093 | x86 | Intel 標準の法務通知（前文で確認。未変更の複製と 0BSD の Sample Code を除き IP 許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図・表の複製なし |
| SPEC-X86-AMD-APM | AMD64 Architecture Programmer's Manual, Vol. 1-5（合本 Pub 40332 Rev 4.11、2026-10） | Advanced Micro Devices, Inc. | Rev 4.11 | x86 | © 2013–2026 AMD、All rights reserved（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図・表の複製なし |
| SPEC-X86-INTEL-OPT | Intel 64 and IA-32 Architectures Optimization Reference Manual, Volume 1（Doc 248966-051US、2026-10。Vol.2 は別途確認） | Intel | Vol.1 051 | x86 のタイミング | Intel 標準の法務通知（公開PDFの前文で確認。未変更の複製と 0BSD の Sample Code を除き IP 許諾なし） | R,F | 2026-11-09 glatan | タイミング等の事実を自前表現で記述。条文・図表の複製なし。R,F の許可は Vol.1 の範囲 |
| SPEC-X86-8086 | The 8086 Family User's Manual（Order 9800722-03、1979-10。8086/8088/8089） | Intel | 9800722-03 | x86（8086、8088） | © Intel Corporation 1978, 1979（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-X86-I486 | i486 Processor Programmer's Reference Manual（Order 240486、1990） | Intel | 240486 | x86（80486 のタイミング） | — | — | 未確認 | 書名・版は公開PDF本文の注記と表題で確認。© 表記の verbatim は抽出文中に見当たらず未確認。段階5の実装時に前文を確定する |
| SPEC-X86-PENTIUM | Pentium Processor Family Developer's Manual（Order 241428/241429/241430、1994–1997） | Intel | 241428 他 | x86（Pentium のタイミング） | © INTEL CORPORATION 1996（前文で確認。No license... の標準通知。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-X86-PSABI | System V ABI, AMD64 Architecture Processor Supplement, Version 1.0 | x86-64 psABI 編集者 | v1.0（master e1ce0983 2025-03-12） | x86（psABI、初期スタック・シグナルフレーム） | LICENSE ファイルなし（GitLab API で 404 を確認。Intel 変更分のみ CC BY 4.0） | R,F | 2026-11-09 glatan | 構造体配置等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-ARM-ARM-A | Arm Architecture Reference Manual for A-profile architecture（DDI 0487 M.c） | Arm | DDI 0487 M.c | aarch64、arm | © 2010-2026 Arm Limited、All rights reserved（Proprietary Notice で確認。無断複製・再配布不可） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。機械可読仕様は対象外 |
| SPEC-ARM-ARM-V7AR | ARM Architecture Reference Manual, ARMv7-A and ARMv7-R edition（DDI 0406B、2008＋errata） | Arm | DDI 0406B | arm | © 1996-1998, 2000, 2004-2011 ARM Limited、All rights reserved（Proprietary Notice を公開PDFの前文で確認。無断複製不可） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。機械可読仕様は対象外 |
| SPEC-ARM-ARM-LEGACY | ARM Architecture Reference Manual, DDI 0100 Issue I（2005-07。初版 1996-02） | Arm | DDI 0100 Issue I | arm | © 1996-1998, 2000, 2004, 2005 ARM Limited、All rights reserved（公開PDFの前文で確認。再配布の明示的許諾条項は見当たらない） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。機械可読仕様は対象外 |
| SPEC-ARM-EABI | ABI for the Arm Architecture, Base Standard（BSABI32）＋ Procedure Call Standard（AAPCS32）。repo 2026Q3 | Arm Limited and its affiliates | 2026Q3 | arm（os-linux の ARM 対応） | CC-BY-SA-4.0 ＋ Grant of Patent License（repo の LICENSE.md で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし。機械可読仕様は対象外 |
| SPEC-AARCH64-ABI | Procedure Call Standard for the Arm 64-bit Architecture（AAPCS64、2025Q4） | Arm Limited and its affiliates | 2025Q4 | aarch64（os-linux の AArch64 対応） | CC-BY-SA-4.0 ＋ Grant of Patent License（repo の LICENSE.md で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし。機械可読仕様は対象外 |
| SPEC-MIPS-R6 | MIPS Architecture For Programmers, MIPS32/MIPS64 Release 6（MD00086/MD00087 Rev 6.06、2016-12-15） | MIPS Technologies（Wave Computing） | Rev 6.06 | mips | All rights reserved（前文に複製許諾なし。「Public. This publication contains proprietary information...」） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-MIPS-IV | MIPS IV Instruction Set（Rev 3.2、1995-09） | MIPS Technologies, Inc. | Rev 3.2 | mips | © MIPS Technologies, Inc. All rights reserved（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-MIPS-R3000 | IDT R30xx Family Software Reference Manual（Rev 1.0、1994） | Integrated Device Technology, Inc. | Rev 1.0 | mips（R3000 のタイミング） | 文書全体の複製禁止条項なし（特許の非許諾言及あり） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。サンプルコードの複製なし |
| SPEC-MIPS-ABI | System V ABI, MIPS RISC Processor Supplement, 3rd Edition（o32 のみ。n32/n64 は対象外） | The Santa Cruz Operation, Inc. | 3rd Edition | mips（os-linux の MIPS 対応） | © 1990-1996 SCO、All rights reserved（前文で確認。事前の書面許諾なく複製不可） | R,F | 2026-11-09 glatan | o32 の番号・配置の事実を自前表現で記述。n32/n64 は別文書が必要 |
| SPEC-MIPS-ABI-N32 | MIPS n32/n64 ABI の根拠文書（候補：SGI MIPSpro N32 ABI Handbook 007-2816 / ELF-64 1.5 Draft 2） | 確認時に記録 | — | mips（os-linux の MIPS 対応） | — | — | 未確認 | SPEC-MIPS-ABI 3rd Edition は o32 のみ。候補文書の利用条件は未確認。特定と確認は MIPS 対応時に実施する |
| SPEC-RISCV-UNPRIV | The RISC-V Instruction Set Manual, Volume I: Unprivileged Architecture | RISC-V International | 20250508 | riscv | CC-BY-4.0 | R,F | 2026-11-08 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-RISCV-PRIV | The RISC-V Instruction Set Manual, Volume II: Privileged Architecture | RISC-V International | 20250508 | riscv | CC-BY-4.0 | R,F | 2026-11-08 glatan | 同上 |
| SPEC-RISCV-PROFILES | RISC-V Profiles（RVA23 v1.0、2024-10-17） | RISC-V International | RVA23 v1.0 | riscv | CC-BY-4.0 | R,F | 2026-11-08 glatan | プロファイルの構成の事実を自前表現で記述 |
| SPEC-RISCV-PSABI | RISC-V ELF psABI Specification | RISC-V International | v1.0 | riscv、os-linux | CC-BY-4.0 | R,F | 2026-11-08 glatan | 構造体配置等の事実を自前表現で記述 |
| SPEC-SIFIVE-U74 | SiFive U74-MC Core Complex Manual（21G3.02.00、2019–2022） | SiFive, Inc. | 21G3.02.00 | riscv（U74 のタイミング） | © 2019–2022 SiFive, Inc.、All rights reserved（CC BY-NC-ND 4.0 の併記あり） | R,F | 2026-11-09 glatan | タイミング等の事実を自前表現で記述。条文・図表の複製なし。NC/ND の範囲外利用なし |
| SPEC-POWER-ISA | Power ISA, Version 3.1C（2024-05-26） | OpenPOWER Foundation | v3.1C | power | OpenPOWER EULA 1.1–1.3（適合実装の作成・利用・頒布に明示的許諾。文書自体への CC 許諾ではない） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-POWERPC-PEM | PowerPC Microprocessor Family: The Programming Environments for 32-Bit Microprocessors（MPCFPE32B Rev 3、2005-10-17 推奨） | Motorola（現 NXP） | Rev 3 | power | © Motorola/Freescale、All rights reserved（免責・許諾なし文言。verbatim は未確認） | — | 未確認 | 版は NXP 目録で確認。前文の逐語確認が残る。段階5の実装時に確定する |
| SPEC-POWER-ABI | Power Architecture 64-Bit ELF V2 ABI Supplement, Revision 1.5（2020-12-01。ppc64 BE 旧版は ELFv1 1.9） | OpenPOWER Foundation | Rev 1.5 | power（os-linux の Power 対応） | GNU Free Documentation License 1.3（無変更・表紙文言なし。前文で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし |
| SPEC-S390-ZARCH-POP | z/Architecture Principles of Operation, SA22-7832-14, Fifteenth Edition（2025-04） | IBM | SA22-7832-14 | s390 | © IBM Corp. 2000, 2025（公開PDFの頁フッタで確認。再配布の明示的許諾条項は前文に見当たらない） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-S390-ESA390-POP | Enterprise Systems Architecture/390 Principles of Operation（SA22-7201-08、Ninth Edition 2003-06 以降改訂なしと推定） | IBM | SA22-7201-08 | s390 | — | — | 未確認 | 版と公開URLは未確定。前文の逐語確認が残る。段階5の実装時に確定する |
| SPEC-S390-S360-POP | IBM System/360 Principles of Operation（A22-6821-7、1967-12。TNL N22-0282 まで適用） | IBM | A22-6821-7 | s390 | — | — | 未確認 | 版は文書番号と改訂表で確認。© 表記の verbatim は抽出文中に見当たらず未確認。保存コピーの入手経路の適法性判断も要する。段階5の実装時に確定する |
| SPEC-S390-ABI | ELF Application Binary Interface s390x Supplement, Version 1.7（2025-06） | IBM + open source community | v1.7 | s390（os-linux の s390 対応） | GNU Free Documentation License 1.1（無変更・表紙文言なし。repo の LICENSE で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし |
| SPEC-WASM-CORE | WebAssembly Core Specification, Release 3.0 | W3C、WebAssembly Community Group | 3.0 | wasm | W3C Software and Document Notice and License（repo の document/ の条件。公開の LICENSE 表で確認） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-WASI-P1 | WASI 0.1（wasi_snapshot_preview1） | WebAssembly Community Group、Bytecode Alliance | 0.1 | wasm、os-wasi | ライセンス表示なし（GitHub NOASSERTION。wasi-0.1 に LICENSE ファイルなし） | R,F | 2026-11-09 glatan | API 定義等の事実を自前表現で記述。複製なし |
| SPEC-M68K-PRM | M68000 Family Programmer's Reference Manual, M68000PM/AD Rev.1（1992） | Motorola, Inc. | Rev.1 | m68k | ©MOTOROLA INC., 1992（前文で確認。特許の非許諾言及あり。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-M68K-UM | M68000 8-/16-/32-Bit Microprocessors User's Manual, Ninth Edition（1993） | Motorola, Inc. | 9th Edition | m68k（68000 のタイミング） | ©MOTOROLA INC., 1993（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | タイミング等の事実を自前表現で記述。条文・図表の複製なし |
| SPEC-M68K-FPU | MC68881/MC68882 Floating-Point Coprocessor User's Manual, Second Edition（1989） | Motorola, Inc. | 2nd Edition | m68k | ©MOTOROLA, INC., 1987（前文で確認。特許の非許諾言及あり。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-M68K-COLDFIRE | ColdFire Family Programmer's Reference Manual（CFPRM Rev 3、2005-03） | Freescale Semiconductor | CFPRM Rev 3 | m68k | — | — | 未確認 | 版は文書表題で確認。© 表記の verbatim は抽出文中に見当たらず未確認。段階5の実装時に前文を確定する |
| SPEC-VAX-ARM | VAX Architecture Reference Manual, EY-3459E-DP（1987） | Digital Equipment Corporation | 1987 | vax | © 1987 Digital Equipment Corporation、All rights reserved（前文で確認。事前の書面許諾なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-PDP11-HANDBOOK | PDP-11 Processor Handbook 1979（11/04/34A/44/60/70） | Digital Equipment Corporation | 1979 | pdp11 | © 1979 DEC（公開PDFの前文で確認。再配布の明示的禁止条項は見当たらない） | R,F | 2026-11-09 glatan | モデル別の性質の事実を自前表現で記述。条文・図の複製なし。他モデル版が必要になれば項目を追加する |
| SPEC-SPARC-V8 | The SPARC Architecture Manual, Version 8（1992） | SPARC International | Version 8 | sparc | © 1991,1992 SPARC International, Inc.、All rights reserved（公開PDFの前文で確認。事前の許諾なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし。試作はV8で実施しV9は使わない |
| SPEC-SPARC-V9 | The SPARC Architecture Manual, Version 9 | SPARC International | — | sparc | — | — | 未確認 | 試作は V8 で実施するため未確認のまま |
| SPEC-ALPHA-ARM | Alpha Architecture Reference Manual, Fourth Edition（2002-01、Compaq） | Compaq Computer Corporation | 4th Edition | alpha | — | — | 未確認 | 版は本文冒頭で確認。©表記の verbatim は未確認。段階5の実装時に前文を確定する |
| SPEC-PARISC-11 | PA-RISC 1.1 Architecture and Instruction Set Reference Manual, Third Edition（1994-02、HP 09740-90039） | Hewlett-Packard Company | 3rd Edition | parisc | © 1986–1994 HP（公開PDFの前文で確認。事前の書面許諾なく複製不可。All rights reserved） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-PARISC-20 | PA-RISC 2.0 Architecture（1995-08、HP） | Hewlett-Packard Company | 1995-08 | parisc | © 1995 HP、All rights reserved（公開PDFの前文で確認。事前の書面許諾なく複製・翻訳不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-SUPERH-SH2 | SuperH RISC Engine SH-1/SH-2 Programming Manual（1996-09-03、Hitachi） | Hitachi, Ltd. | 1996-09-03 | superh | All rights reserved（前文で確認。Hitachi の許可なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-SUPERH-SH4 | SH-4 32-Bit CPU Core Architecture（ADCS 7182230F、2002-09-12） | STMicroelectronics | 2002-09-12 | superh | © Hitachi, Ltd., 1998、All rights reserved（前文で確認。書面承認なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-LOONGARCH-RM | LoongArch Reference Manual, Volume 1: Basic Architecture, v1.10 | Loongson Technology Corporation Limited | v1.10 | loongarch | CC BY-NC-ND 4.0 と無断開示・複製禁止の併記（LICENSE 原文で確認。両立は所有者判断） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。NC/ND の範囲外利用なし |
| SPEC-OPENRISC-1000 | OpenRISC 1000 Architecture Manual, Version 1.4 rev0（2022-02-20） | OpenRISC Community | v1.4 rev0 | openrisc | GNU GPL に基づく再配布・改変の許諾（PDF 前文で確認。GPL 版数は要確認） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-IA64-SDM | Intel Itanium Architecture Software Developer's Manual, Revision 2.3（2010-05。全4巻） | Intel | Rev 2.3 | ia64 | © Intel Corporation、All rights reserved（Intel 標準の法務通知。公開の Specification Update 248699-009 で同文を確認。複製の許諾なし） | R,F | 2026-11-09 glatan | 手組ベクタ用の事実を自前表現で記述。条文・図の複製なし。オラクルなし |
| SPEC-HEXAGON-PRM | Qualcomm Hexagon V73 Programmer's Reference Manual（80-N2040-53） | Qualcomm | V73 | hexagon | © 2022, 2024 Qualcomm Technologies, Inc. and/or its subsidiaries、All rights reserved（公開PDFの前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-IEEE754 | IEEE Standard for Floating-Point Arithmetic（IEEE 754-2019） | IEEE | 2019 | softfloat | © IEEE、All rights reserved（本文書の購入・購読で入手） | R,F | 2026-11-08 glatan | 数値・丸め規則の事実のみ自前表現で使用。条文・図表の複製なし。許諾範囲は所有者判断 |
| SPEC-DECIMAL-ARITH | General Decimal Arithmetic Specification, Version 1.70（2009-03-25） | Mike Cowlishaw（IBM 許諾のもと speleotrove 掲載） | v1.70 | decimal | © 1997, 2009 IBM（掲載頁で確認。オープンライセンスなし） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・例の複製なし |
| SPEC-ELF-GABI | System V Application Binary Interface の ELF の汎用部分 | SCO（現 Xinuos） | Edition 4.1（1997）＋2001-04-24 DRAFT（ch.4/5） | loader | © SCO、All rights reserved（複製の明示的許諾なし） | R,F | 2026-11-08 glatan | 数値・配置の事実のみ自前表現で使用。条文・図表の複製なし。許諾範囲は所有者判断 |
| SPEC-LINUX-MANPAGES | Linux man-pages | Linux man-pages プロジェクト | 6.20 | os-linux | 各ページに異なるライセンス（GPL、BSD系、Linux-man-pages-copyleft系、verbatim-onlyが混在。ページ冒頭の表示が効力を持つ） | R | 2026-11-08 glatan | 動作理解の参照のみ。verbatim-onlyの頁があるためFは許可しない。番号・配置の事実は SRC-LINUX から取る |

### ソース

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| SRC-LINUX | Linux カーネルのソース（UAPI ヘッダ、システムコールの表、シグナルフレームの定義） | Linux カーネルの開発者 | 7.3 | os-linux | GNU GPL version 2（COPYING）。UAPI は Linux-syscall-note の例外でユーザ空間利用可 | R,F | 2026-11-08 glatan | 番号・配置の事実を自前表現で記述。カーネル本体コードの翻訳はしない（`C` にあたる） |
| SRC-LINUX-66 | Linux カーネルのソース v6.6（ia64 ABI 用。6.7 で arch/ia64 削除前の最終版） | Linux カーネルの開発者 | 6.6 | os-linux（ia64） | GNU GPL version 2（COPYING）。UAPI は Linux-syscall-note の例外でユーザ空間利用可 | R,F | 2026-11-09 glatan | arch/ia64 の存在を v6.6 で確認、v6.7 で削除を確認。番号・配置の事実を自前表現で記述 |
| SRC-SOFTFLOAT3 | Berkeley SoftFloat-3（TestFloat 生成器のビルドに使用） | John Hauser（UC Berkeley） | Release 3e（commit 07ebd29d） | softfloat（TestFloat 実行） | BSD 3-clause（COPYING.txt。Regents of the University of California） | X | 2026-11-09 glatan | リポジトリに含めない。版は `git ls-remote` で HEAD==07ebd29d を確認、COPYING.txt は BSD 3-clause 型文面 |

### テスト

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| TEST-RISCV-TESTS | riscv-tests | RISC-V International のコントリビュータ | commit 3df703c（HEAD） | riscv | BSD 3-clause（Regents of the University of California） | T | 2026-11-08 glatan | 取得して検証に使う。リポジトリに含めない |
| TEST-RISCV-ARCH-TEST | riscv-arch-test | RISC-V International のコントリビュータ | commit 7569d06（HEAD） | riscv | コード BSD-3-Clause／Apache-2.0、文書 CC-BY-4.0 | T | 2026-11-08 glatan | 取得して検証に使う。リポジトリに含めない |
| TEST-WASM-SPEC | WebAssembly 仕様のテストスイート（WebAssembly/spec の test/） | WebAssembly Community Group | main HEAD==f3268fa9（確認時に固定） | wasm | Apache License 2.0（test/ の条件。公開の LICENSE 表で確認） | T | 2026-11-09 glatan | 版は `git ls-remote` で HEAD を確認。取得して使う。リポジトリに含めない |
| TEST-TESTFLOAT | Berkeley TestFloat | John Hauser（UC Berkeley） | Release 3e | softfloat | BSD 3-clause（Regents of the University of California） | T,X | 2026-11-08 glatan | 生成ベクタの使用（`T`）とベクタ生成のための実行（`X`）。リポジトリに含めない |
| TEST-DECTEST | decTest（Version 2.62、2010-04-19。81,300 超テスト） | Mike Cowlishaw（IBM） | v2.62 | decimal | as-is 提供＋IBM © 表示（掲載頁で確認。ICU ライセンスの適用あり） | T | 2026-11-09 glatan | 取得して検証に使う。リポジトリに含めない |
| TEST-SINGLESTEP-68000 | SingleStepTests m68000（commit 64b2531） | SingleStepTests | commit 64b2531 | m68k | MIT License（LICENSE 原文で確認。© 2024 SingleStepTests） | T | 2026-11-09 glatan | 取得して検証に使う。リポジトリに含めない |
| TEST-SINGLESTEP-8088 | SingleStepTests 8088（commit aea8448） | SingleStepTests | commit aea8448 | x86 | MIT License（LICENSE 原文で確認。© 2024 SingleStepTests） | T | 2026-11-09 glatan | 取得して検証に使う。リポジトリに含めない |

### バイナリ

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| BIN-DISTRO | BusyBox 公式静的バイナリ 1.35.0 x86_64-linux-musl（2022-01-17） | BusyBox 開発者 | 1.35.0 | os-linux のプログラム単位のテスト（x86_64 初回） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | 2026-11-09 glatan | 取得してテストの入力に使う。リポジトリに含めない。再配布しない。他ディストロ・他 ISA は使うときに項目を追加する |
| BIN-DISTRO-I386 | BusyBox 公式静的バイナリ 1.35.0 i686-linux-musl（2022-01-17） | BusyBox 開発者 | 1.35.0 | os-linux のプログラム単位のテスト（x86-32） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | 2026-11-14 glatan | 取得してテストの入力に使う（`.testdata/bin-distro-i386/busybox`）。リポジトリに含めない。再配布しない |

### 計測データ

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| MEAS-UOPS-INFO | uops.info（Latency/Throughput/Port Usage。instructions.xml 2026-03 版） | Andreas Abel、Jan Reineke | 2026-03 | x86 のタイミング | ライセンス表示なし（引用要請のみ。2026-11-08 確認） | R,F | 2026-11-09 glatan | 計測値の事実を自前表現で記述。データの再配布なし |
| MEAS-AGNER | Agner Fog の命令表（instruction_tables、2025-09-20 更新） | Agner Fog | 2025-09-20 | x86 のタイミング | © 1996–2025 Agner Fog（前文で確認。Public distribution and mirroring is not allowed） | R,F | 2026-11-09 glatan | 計測値の事実を自前表現で記述。表の再配布・ミラーなし |

### ツール

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| TOOL-RUST | Rust のツールチェーン（rustc、cargo、rust-lld、rustfmt、clippy、Miri） | Rust プロジェクト | 1.99.1 | 全体 | MIT OR Apache-2.0（LICENSE-MIT、LICENSE-APACHE） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-TASK | Task 3.54.0（Arch Linux のパッケージ名は go-task） | go-task | 3.54.0 | 開発作業 | MIT（LICENSE） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-NEXTEST | cargo-nextest | nextest-rs | 0.9.151 | テストの実行 | Apache-2.0 OR MIT（LICENSE-APACHE、LICENSE-MIT） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-GIT | Git | Git プロジェクト | 2.56.0 | 開発作業、テストデータの取得 | GNU GPL version 2（COPYING。v2 のみ） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-CURL | curl | curl プロジェクト | 8.23.0 | テストデータの取得 | curl license（COPYING） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-LLVM | LLVM と clang（llvm-objdump を含む） | LLVM プロジェクト | 23.1.4（手元検証） | 検証 | Apache-2.0 WITH LLVM-exception（LICENSE.TXT） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-GDB | GDB | GNU プロジェクト | 18.1（手元検証） | 検証 | GNU GPL version 3（COPYING） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-WASMTIME | wasmtime | Bytecode Alliance | 50.0.1（手元検証） | wasm の検証 | Apache-2.0 with LLVM exception（LICENSE） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-QEMU | QEMU | QEMU プロジェクト | —（手元未導入） | 検証（用意できた環境だけ） | GNU GPL version 2（LICENSE。全体。手元未検証） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-BINUTILS | GNU binutils | GNU プロジェクト | 2.47（手元検証） | 検証（用意できた環境だけ） | GNU GPL version 3（COPYING） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
