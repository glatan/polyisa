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

以下の表には、使用している資料と、設計文書が予定している資料を登録する。未確認の項目は段階の着手の条件を満たさない。ISA ファミリごとの ABI の文書など、ここにない資料は、その ISA の実装を始めるときに登録する（[ロードマップ](design/roadmap.md) の着手の条件）。

### 仕様

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| SPEC-X86-INTEL-SDM | Intel 64 and IA-32 Architectures Software Developer's Manual（Combined、Version 093、2026-09-24） | Intel | v093 | x86 | Intel 標準の法務通知（前文で確認。未変更の複製と 0BSD の Sample Code を除き IP 許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図・表の複製なし |
| SPEC-X86-AMD-APM | AMD64 Architecture Programmer's Manual, Vol. 1-5（合本 Pub 40332 Rev 4.11、2026-10。Vol.3 は Pub 24594 Rev 3.39） | Advanced Micro Devices, Inc. | Rev 4.11 / Vol.3 Rev 3.39 | x86 | © 2013–2026 AMD、All rights reserved（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図・表の複製なし。Vol.3 Rev 3.39（2026-10）の本文を確認し、3DNow!・XOP・FMA4・TBM・SSE4a・MONITORX・CLZERO・RDPRU の収録を確認済み |
| SPEC-X86-INTEL-OPT | Intel 64 and IA-32 Architectures Optimization Reference Manual, Volume 1（Doc 248966-051US、2026-10） | Intel | Vol.1 051 | x86 のタイミング | Intel 標準の法務通知（公開PDFの前文で確認。未変更の複製と 0BSD の Sample Code を除き IP 許諾なし） | R,F | 2026-11-09 glatan | タイミング等の事実を自前表現で記述。条文・図表の複製なし。R,F の許可は Vol.1 の範囲 |
| SPEC-X86-INTEL-OPT-V2 | Intel 64 and IA-32 Architectures Optimization Reference Manual, Volume 2: Optimizing Earlier Generations of Intel 64 and IA-32 Processor Architectures, Throughput and Latency（Ref# 356477-050US、2024-04） | Intel | 356477-050US | x86（旧世代のタイミング） | Intel 標準の法務通知（-050 の前文で確認。未変更の複製と 0BSD のコードを除き IP 許諾なし） | R,F | 2026-11-17 glatan | 旧世代マイクロアーキテクチャのスループット・レイテンシの公式データ（486・Pentium より新しい世代向け）。cdrdv2-public.intel.com/821614 の 356477-Optimization-Reference-Manual-V2-050.pdf を取得・前文確認済み。-049（2024-01）で題名変更、-050（2024-04）で TSX 章追加 |
| SPEC-X86-8086 | The 8086 Family User's Manual（Order 9800722-03、1979-10。8086/8088/8089） | Intel | 9800722-03 | x86（8086、8088） | © Intel Corporation 1978, 1979（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-X86-8087 | iAPX 86, 88 User's Manual（Order 210201-001、1981-08。iAPX 86/20, 88/20 Numerics Supplement＝8087 NPX の詳細を含む） | Intel | 210201-001 | x86（8087） | © Intel 1981。「No part of this document may be copied or reproduced in any form or by any means without the prior written consent of Intel Corporation」（前文 p.ii で確認） | R,F | 2026-11-17 glatan | SPEC-X86-8086 の 1979 版は 8087 を含まない。本書の Numerics Supplement が 8087 の根拠（目次と序文で内包を確認）。8087・80287 と 80387 以降の挙動差の根拠。bitsavers に公開PDFあり（1981_iAPX_86_88_Users_Manual）。事実の自前表現での利用（R,F）。段階13の実装時に確定する |
| SPEC-X86-I186 | iAPX 86, 88, 186 and 188 User's Manual, Programmer's Reference（Order 210911-001、1983-05。80186/80188 の追加命令を含む） | Intel | 210911-001 | x86（80186） | © Intel 1983（前文で確認。保証否認・商標一覧型の標準前文） | R,F | 2026-11-17 glatan | 「80186 以降の命令」の境界の根拠。bitsavers に公開PDFあり（210911-001）。1985 年の統合版は 210912-001。事実の自前表現での利用（R,F）。段階13の実装時に確定する |
| SPEC-X86-I286 | iAPX 286 Programmer's Reference Manual（Order 210498、1983/1985。iAPX 286 Numeric Supplement を含む） | Intel | 210498 | x86（80286） | © Intel（210498-003 の前文で確認。保証否認・商標一覧型に複製禁止条項「No part of this document may be copied or reproduced ... without the prior written consent of Intel Corporation」を含む標準前文） | R,F | 2026-11-17 glatan | bitsavers に公開PDFあり（210498-001/003）。210498-003（1985）の表題は「... including the iAPX 286 Numeric Supplement」で Numeric Supplement の内包を確認。マニュアル自身の © 行は画像のため未抽出。80287 を含む 1987 年合冊版は 210498-005（"80286 and 80287 Programmer's Reference Manual"）。段階13の実装時に確定する |
| SPEC-X86-I386 | Intel 80386 Programmer's Reference Manual（Order 230985-001、1986） | Intel | 230985-001 | x86（80386） | © Intel（前文で確認。bitsavers の 230985-001 のスキャンは 1988 年印刷で法務ページの © 行は 1988、表題は 1986 のまま。保証否認・商標一覧型の標準前文） | R,F | 2026-11-17 glatan | 注文番号は 230985-001（bitsavers に公開PDFあり）。80386 の CPU モデルと SingleStepTests の 386EX データとの対応の根拠。事実の自前表現での利用（R,F）。段階13の実装時に確定する |
| SPEC-X86-I387 | Intel 80387 Programmer's Reference Manual（Order 231917-001、1987。80387 NPX の命令・挙動の専門書） | Intel | 231917-001 | x86（80387） | © Intel 1987（前文で確認。保証否認・商標一覧型の標準前文） | R,F | 2026-11-17 glatan | 80387 以降の x87 挙動（80387+ の例外・denormal 等）の根拠。bitsavers に公開PDFあり（231917-001）。段階13の実装時に確定する |
| SPEC-X86-I486 | Intel486 Microprocessor Family Programmer's Reference Manual（Order 240486、1992/1993 印刷） | Intel | 240486 | x86（80486 のタイミング） | © Intel Corporation 1993（前文で確認。保証否認型の標準前文） | R,F | 2026-11-17 glatan | bitsavers の 1992 版 PDF（1992_Intel_486_Programmers_Reference_Manual）で © 1993 を確認。注文番号はページフッターの OCR 層（240486i26-4 等）から 240486 に確定。段階13の実装時に確定する |
| SPEC-X86-PENTIUM | Pentium Processor Family Developer's Manual（Order 241428/241429/241430、1994–1997） | Intel | 241428 他 | x86（Pentium のタイミング） | © INTEL CORPORATION 1996（前文で確認。No license... の標準通知。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-X86-PSABI | System V ABI, AMD64 Architecture Processor Supplement（With LP64 and ILP32 Programming Models）, Version 1.0 | x86-64 psABI 編集者 | v1.0（master e1ce0983 2025-03-12） | x86（psABI、初期スタック・シグナルフレーム、x32 の ILP32） | LICENSE ファイルなし（GitLab API で 404 を確認。Intel 変更分のみ CC BY 4.0） | R,F | 2026-11-09 glatan | 構造体配置等の事実を自前表現で記述。条文・図の複製なし。x32 の ABI は本文書の ILP32 の節が根拠 |
| SPEC-X86-I386-PSABI | System V Application Binary Interface, Intel386 Architecture Processor Supplement, Version 1.2（x86-psABIs の i386-ABI repo、docs/i386-psABI-2025-08-24.pdf） | x86 psABIs 編集者 | v1.2（2025-08-24） | x86-32（os-linux の i386 ABI） | LICENSE ファイルなし（リポジトリを確認。前文にもライセンス条項なし。AMD64 版から派生した版） | R,F | 2026-11-17 glatan | x86-32 ABI の配置と初期スタックの根拠。2025-08-24 版 PDF を取得済み。段階13の実装時に確定する |
| SPEC-X86-APX | Intel Advanced Performance Extensions (Intel APX) Architecture Specification（355828-009US、2026-08、Revision 9.0） | Intel | Rev 9.0 | x86（APX、REX2） | Intel 標準の法務通知（前文で確認。未変更の複製と 0BSD の Sample Code を除き IP 許諾なし。「create software implementations ... intended to execute on the Intel product(s)」は可） | R,F | 2026-11-17 glatan | SDM と別冊の APX 仕様（355828-009.pdf を取得・前文確認済み）。SDM v093 での収録状況を確認し、不足分の根拠とする。段階13の実装時に確定する |
| SPEC-X86-ISE | Intel Architecture Instruction Set Extensions and Future Features Programming Reference（319433、-063、2026-11） | Intel | -063（2026-11） | x86（SDM に先行する拡張） | Intel 標準の法務通知（-063 の前文で確認。未変更の複製と 0BSD のコードを除き IP 許諾なし） | R,F | 2026-11-17 glatan | SDM より先に拡張が載る文書（UINTR・MOVRS・AVX10_VPMLDSABFLYDQ 等の収録先）。-063 で Razor Lake・Coral Rapids が追加。SDM v093 にない分の根拠。cdrdv2-public.intel.com/932753 の公開 PDF を取得済み |
| SPEC-X86-AVX10-2 | Intel Advanced Vector Extensions 10.2 Architecture Specification（361050-007US、2026-04、Revision 7.0） | Intel | Rev 7.0 | x86（AVX10.1、AVX10.2） | Intel 標準の法務通知（前文で確認。未変更の複製と 0BSD の Sample Code を除き IP 許諾なし） | R,F | 2026-11-17 glatan | Intel 発行の別冊仕様。AVX10.1 の版履歴を含む（361050-007US の PDF を取得・前文確認済み）。段階13の実装時に確定する |
| SPEC-X86-ACE-V1 | AI Compute Extensions (ACE) Specification（Version 1.16.2、2026-07-28） | x86 Ecosystem Advisory Group | v1.16.2 | x86（ACE v1） | © 2026 Intel Corporation and AMD（前文で確認。Intel+AMD 共同。無改変複製の頒布可。本書に基づく x86 製品向けソフトウェア実装は可。**0BSD 条項なし**。Intel+AMD 双方への特許許諾条項と輸出管理条項あり） | R,F | 2026-11-17 glatan | x86ecosystem.org の公開 PDF（ACE_v1_Specification_public.pdf を取得・前文確認済み）。Intel 単独文書と異なり Sample Code の 0BSD 条項がない点に注意。事実の自前表現での利用（R,F）。版を変えるときは確認をやり直す |
| SPEC-X86-ACE-AVX10-3 | ACE v2 / AVX10.3 Architecture Specification（Version 0.9.2.4、2026-10-22） | x86 Ecosystem Advisory Group | v0.9.2.4（ドラフト） | x86（ACE v2、AVX10.3） | © 2026 Intel Corporation and AMD（前文で確認。ACE v1 と同一の通知。無改変複製可、x86 製品向けソフトウェア実装可、0BSD 条項なし、特許・輸出管理条項あり） | R,F | 2026-11-17 glatan | x86ecosystem.org の公開 PDF（ACE_v2_AVX10_3_Specification_public.pdf を取得・前文確認済み）。事実の自前表現での利用（R,F）。ドラフトの版を変えるときは確認をやり直す |
| SPEC-X86-MOO | MOO File Format Specification（dbalsom/moo の doc/moo_format_v1.md。Machine Opcode Operation 形式） | Daniel Balsom | v1.1（commit c438962d、2025-11-19） | x86 のテストデータ形式 | MIT License（LICENSE 原文で確認。© 2025 Daniel Balsom） | R,F | 2026-11-17 glatan | TEST-SINGLESTEP-80286・TEST-SINGLESTEP-80386 の .MOO.gz の形式の根拠（8088 の v2 系とは別版。RMSK・RG32・RM32・EA32 チャンクを追加）。参照パーサ（Rust/C++/Python moo2json）を同梱するが、利用は仕様の読解と自前実装の根拠（R,F）に限る想定。段階13の実装時に確定する |
| SPEC-ARM-ARM-A | Arm Architecture Reference Manual for A-profile architecture（DDI 0487 M.c） | Arm | DDI 0487 M.c | aarch64、arm | © 2010-2026 Arm Limited、All rights reserved（Proprietary Notice で確認。無断複製・再配布不可） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。機械可読仕様は対象外 |
| SPEC-ARM-ARM-V7AR | ARM Architecture Reference Manual, ARMv7-A and ARMv7-R edition（DDI 0406B、2008＋errata） | Arm | DDI 0406B | arm | © 1996-1998, 2000, 2004-2011 ARM Limited、All rights reserved（Proprietary Notice を公開PDFの前文で確認。無断複製不可） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。機械可読仕様は対象外 |
| SPEC-ARM-ARM-LEGACY | ARM Architecture Reference Manual, DDI 0100 Issue I（2005-07。初版 1996-02） | Arm | DDI 0100 Issue I | arm | © 1996-1998, 2000, 2004, 2005 ARM Limited、All rights reserved（公開PDFの前文で確認。再配布の明示的許諾条項は見当たらない） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。機械可読仕様は対象外 |
| SPEC-ARM-EABI | ABI for the Arm Architecture, Base Standard（BSABI32）＋ Procedure Call Standard（AAPCS32）。repo 2026Q3 | Arm Limited and its affiliates | 2026Q3 | arm（os-linux の ARM 対応） | CC-BY-SA-4.0 ＋ Grant of Patent License（repo の LICENSE.md で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし。機械可読仕様は対象外 |
| SPEC-AARCH64-ABI | Procedure Call Standard for the Arm 64-bit Architecture（AAPCS64、2025Q4） | Arm Limited and its affiliates | 2025Q4 | aarch64（os-linux の AArch64 対応） | CC-BY-SA-4.0 ＋ Grant of Patent License（repo の LICENSE.md で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし。機械可読仕様は対象外 |
| SPEC-AARCH64-ELF | ELF for the Arm 64-bit Architecture（AAELF64、ARM-software/abi-aa repo） | Arm Limited and its affiliates | 2025Q4（daa7a94） | aarch64（os-linux の AArch64 対応） | CC-BY-SA-4.0 ＋ Grant of Patent License（repo の LICENSE.md で確認） | R,F | 2026-11-09 glatan | EM_AARCH64、auxv、初期スタックの根拠。条文・表の複製なし。機械可読仕様は対象外 |
| SPEC-MIPS-R6 | MIPS Architecture For Programmers, MIPS32/MIPS64 Release 6（MD00086/MD00087 Rev 6.06、2016-12-15） | MIPS Technologies（Wave Computing） | Rev 6.06 | mips | All rights reserved（前文に複製許諾なし。「Public. This publication contains proprietary information...」） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-MIPS-IV | MIPS IV Instruction Set（Rev 3.2、1995-09） | MIPS Technologies, Inc. | Rev 3.2 | mips | © MIPS Technologies, Inc. All rights reserved（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-MIPS-R3000 | IDT R30xx Family Software Reference Manual（Rev 1.0、1994） | Integrated Device Technology, Inc. | Rev 1.0 | mips（R3000 のタイミング） | 文書全体の複製禁止条項なし（特許の非許諾言及あり） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。サンプルコードの複製なし |
| SPEC-MIPS-ABI | System V ABI, MIPS RISC Processor Supplement, 3rd Edition（o32 のみ。n32/n64 は対象外） | The Santa Cruz Operation, Inc. | 3rd Edition | mips（os-linux の MIPS 対応） | © 1990-1996 SCO、All rights reserved（前文で確認。事前の書面許諾なく複製不可） | R,F | 2026-11-09 glatan | o32 の番号・配置の事実を自前表現で記述。n32/n64 は別文書が必要 |
| SPEC-MIPS-ABI-N32 | MIPS n32/n64 ABI の根拠文書（候補：SGI MIPSpro N32 ABI Handbook 007-2816 / ELF-64 1.5 Draft 2） | 確認時に記録 | — | mips（os-linux の MIPS 対応） | — | — | 未確認 | SPEC-MIPS-ABI 3rd Edition は o32 のみ。候補文書の利用条件は未確認。特定と確認は MIPS 対応時に実施する |
| SPEC-MIPS32R2 | MIPS32 Architecture For Programmers Volume II: The MIPS32 Instruction Set（MD00086、Rev 4.x 系。MIPS32r2 命令の根拠） | MIPS Technologies, Inc. | — | mips | — | — | 未確認 | ext/ins/seb/seh/wsbh/movz/movn/madd/ll/sc/rdhwr 等 r2 命令の一次根拠。© MIPS Technologies と推定（SPEC-MIPS-IV と同族）。条文確認は所有者の仕事 |
| SPEC-MIPS64 | MIPS64 Architecture For Programmers Volume II: The MIPS64 Instruction Set（MD00087。MIPS64r2 拡張の根拠） | MIPS Technologies, Inc. | — | mips | — | — | 未確認 | dext/dins/dsbh/dshd/dclz/dclo 等 MIPS64r2 拡張の一次根拠。素の MIPS64 整数命令は SPEC-MIPS-IV がカバーする。条文確認は所有者の仕事 |
| SPEC-RISCV-UNPRIV | The RISC-V Instruction Set Manual, Volume I: Unprivileged Architecture | RISC-V International | 20250508 | riscv | CC-BY-4.0 | R,F | 2026-11-08 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-RISCV-PRIV | The RISC-V Instruction Set Manual, Volume II: Privileged Architecture | RISC-V International | 20250508 | riscv | CC-BY-4.0 | R,F | 2026-11-08 glatan | 同上 |
| SPEC-RISCV-PROFILES | RISC-V Profiles（RVA23 v1.0、2024-10-17） | RISC-V International | RVA23 v1.0 | riscv | CC-BY-4.0 | R,F | 2026-11-08 glatan | プロファイルの構成の事実を自前表現で記述 |
| SPEC-RISCV-PSABI | RISC-V ELF psABI Specification | RISC-V International | v1.0 | riscv、os-linux | CC-BY-4.0 | R,F | 2026-11-08 glatan | 構造体配置等の事実を自前表現で記述 |
| SPEC-SIFIVE-U74 | SiFive U74-MC Core Complex Manual（21G3.02.00、2019–2022） | SiFive, Inc. | 21G3.02.00 | riscv（U74 のタイミング） | © 2019–2022 SiFive, Inc.、All rights reserved（CC BY-NC-ND 4.0 の併記あり） | R,F | 2026-11-09 glatan | タイミング等の事実を自前表現で記述。条文・図表の複製なし。NC/ND の範囲外利用なし |
| SPEC-POWER-ISA | Power ISA, Version 3.1C（2024-05-26） | OpenPOWER Foundation | v3.1C | power | OpenPOWER EULA 1.1–1.3（適合実装の作成・利用・頒布に明示的許諾。文書自体への CC 許諾ではない） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-POWERPC-PEM | PowerPC Microprocessor Family: The Programming Environments for 32-Bit Microprocessors（MPCFPE32B Rev 3、2005-10-17 推奨） | Motorola（現 NXP） | Rev 3 | power | © Motorola/Freescale、All rights reserved（免責・許諾なし文言。verbatim は未確認） | — | 未確認 | 版は NXP 目録で確認。前文の逐語確認が残る。段階8の実装時に確定する |
| SPEC-POWER-ABI | Power Architecture 64-Bit ELF V2 ABI Supplement, Revision 1.5（2020-12-01。ppc64 BE 旧版は ELFv1 1.9） | OpenPOWER Foundation | Rev 1.5 | power（os-linux の Power 対応） | GNU Free Documentation License 1.3（無変更・表紙文言なし。前文で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし |
| SPEC-POWER-ABI32 | System V Application Binary Interface, PowerPC Processor Supplement（SunSoft Part No. 802-3334-10 Revision A、1995-09） | Sun Microsystems / IBM | Rev A | power（ppc32 の ABI） | — | — | 未確認 | © 1995 Sun Microsystems、© 1993 IBM、All rights reserved（表紙で確認。複製の許諾なし）。sourceware の mirror と freecalypso に所在。前文の逐語確認が残る。段階8の実装時に確定する |
| SPEC-POWER-ALTIVEC-PEM | AltiVec Technology Programming Environments Manual（ALTIVECPEM Rev. 3、2006-04） | Freescale Semiconductor（現 NXP） | Rev. 3 | power（AltiVec） | — | — | 未確認 | © Motorola/Freescale、All rights reserved と推定（Errata 文書は © 1999 Motorola で確認）。NXP 配布。前文の逐語確認が残る。段階8の実装時に確定する |
| SPEC-POWER-EREF | EREF 2.0: A Programmer's Reference Manual for Freescale Power Architecture Processors（EREFRM、2011-09） | Freescale Semiconductor（現 NXP） | Rev. 0 | power（Book E、e500） | — | — | 未確認 | © Freescale と推定。Book E と Freescale EIS の UISA を網羅。E500CORERM との使い分けは段階8で決める。前文の逐語確認が残る |
| SPEC-POWER-SPE-PEM | Signal Processing Engine (SPE) Programming Environments Manual: A Supplement to the EREF（SPEPEM Rev. 0、2008-01） | Freescale Semiconductor（現 NXP） | Rev. 0 | power（e500 の SPE と組込み浮動小数点） | — | — | 未確認 | © Freescale と推定。EREF の補遺。NXP 配布。前文の逐語確認が残る。段階8の実装時に確定する |
| SPEC-POWER-PEM64 | PowerPC Microprocessor Family: The Programming Environments Manual for 64-Bit Microprocessors（MPCFPE64B） | Motorola（現 NXP） | 版確定 | power（64 ビット PowerPC） | — | — | 未確認 | 970 など 64 ビット世代の動作環境アーキテクチャの根拠。版の特定と前文の確認が残る。段階8の実装時に確定する |
| SPEC-POWER-601-UM | PowerPC 601 RISC Microprocessor User's Manual（MPC601UM/AD、1993） | Motorola / IBM | 版確定 | power（601 の POWER 由来の機能集合） | — | — | 未確認 | 601 が実装する POWER 由来の命令の根拠。版の特定と前文の確認が残る。段階8の実装時に確定する |
| SPEC-S390-ZARCH-POP | z/Architecture Principles of Operation, SA22-7832-14, Fifteenth Edition（2025-04） | IBM | SA22-7832-14 | s390 | © IBM Corp. 2000, 2025（公開PDFの頁フッタで確認。再配布の明示的許諾条項は前文に見当たらない） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-S390-ESA390-POP | Enterprise Systems Architecture/390 Principles of Operation（SA22-7201-08、Ninth Edition 2003-06 以降改訂なしと推定） | IBM | SA22-7201-08 | s390 | — | — | 未確認 | 版と公開URLは未確定。前文の逐語確認が残る。段階11の実装時に確定する |
| SPEC-S390-S360-POP | IBM System/360 Principles of Operation（A22-6821-7、1967-12。TNL N22-0282 まで適用） | IBM | A22-6821-7 | s390 | — | — | 未確認 | 版は文書番号と改訂表で確認。© 表記の verbatim は抽出文中に見当たらず未確認。保存コピーの入手経路の適法性判断も要する。段階11の実装時に確定する |
| SPEC-S390-ABI | ELF Application Binary Interface s390x Supplement, Version 1.7（2025-06） | IBM + open source community | v1.7 | s390（os-linux の s390 対応） | GNU Free Documentation License 1.1（無変更・表紙文言なし。repo の LICENSE で確認） | R,F | 2026-11-09 glatan | ABI の事実を自前表現で記述。条文の複製なし |
| SPEC-S390-ABI-31 | S/390 ELF Application Binary Interface Supplement（v1.02、2002-11-18。IBM/s390x-abi repo の 31 ビット側の出力） | IBM + The Linux Foundation | v1.02 | s390（os-linux の s390 31 ビット対応） | GNU Free Documentation License 1.1（無変更・表紙文言なし。lzsabi0_s390 で確認） | — | 未確認 | SPEC-S390-ABI と同じ文書の 31 ビット版。版の確認が残る。段階11の実装時に確定する |
| SPEC-WASM-CORE | WebAssembly Core Specification, Release 3.0 | W3C、WebAssembly Community Group | 3.0 | wasm | W3C Software and Document Notice and License（repo の document/ の条件。公開の LICENSE 表で確認） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-WASI-P1 | WASI 0.1（wasi_snapshot_preview1） | WebAssembly Community Group、Bytecode Alliance | 0.1 | wasm、os-wasi | ライセンス表示なし（GitHub NOASSERTION。wasi-0.1 に LICENSE ファイルなし） | R,F | 2026-11-09 glatan | API 定義等の事実を自前表現で記述。複製なし |
| SPEC-M68K-PRM | M68000 Family Programmer's Reference Manual, M68000PM/AD Rev.1（1992） | Motorola, Inc. | Rev.1 | m68k | ©MOTOROLA INC., 1992（前文で確認。特許の非許諾言及あり。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-M68K-UM | M68000 8-/16-/32-Bit Microprocessors User's Manual, Ninth Edition（1993） | Motorola, Inc. | 9th Edition | m68k（68000 のタイミング） | ©MOTOROLA INC., 1993（前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | タイミング等の事実を自前表現で記述。条文・図表の複製なし |
| SPEC-M68K-FPU | MC68881/MC68882 Floating-Point Coprocessor User's Manual, Second Edition（1989） | Motorola, Inc. | 2nd Edition | m68k | ©MOTOROLA, INC., 1987（前文で確認。特許の非許諾言及あり。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-M68K-COLDFIRE | ColdFire Family Programmer's Reference Manual（CFPRM Rev 3、2005-03） | Freescale Semiconductor | CFPRM Rev 3 | m68k | — | — | 未確認 | 版は文書表題で確認。© 表記の verbatim は抽出文中に見当たらず未確認。段階14の実装時に前文を確定する |
| SPEC-M68K-CPU32 | CPU32 Reference Manual（CPU32RM/AD） | Motorola | 版確定 | m68k（CPU32） | — | — | 未確認 | © Motorola と推定。683xx 系の CPU32 コアの命令差分の根拠。版の特定と前文の確認が残る。段階14の実装時に確定する |
| SPEC-M68K-ABI | System V Application Binary Interface, Motorola 68000 Family Processor Supplement | AT&T / Unix System Laboratories | 版確定 | m68k（os-linux の m68k 対応） | — | — | 未確認 | © AT&T/USL と推定。スキャンは m680x0.github.io と people.debian.org/~glaubitz に所在。前文の逐語確認が残る。段階14の実装時に確定する |
| SPEC-VAX-ARM | VAX Architecture Reference Manual, EY-3459E-DP（1987） | Digital Equipment Corporation | 1987 | vax | © 1987 Digital Equipment Corporation、All rights reserved（前文で確認。事前の書面許諾なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-VAX-MICROVAX | MicroVAX 系の機種別文書（候補：MicroVAX 3800/3900、KA655/KA660 の CPU 文書） | Digital Equipment Corporation | — | vax（MicroVAX サブセット） | — | — | 未確認 | MicroVAX が省いた命令と OS による命令補完の根拠。VAX-ARM の MicroVAX 節で足りるか先に点検する。段階23の実装時に確定する |
| SPEC-PDP11-HANDBOOK | PDP-11 Processor Handbook 1979（11/04/34A/44/60/70） | Digital Equipment Corporation | 1979 | pdp11 | © 1979 DEC（公開PDFの前文で確認。再配布の明示的禁止条項は見当たらない） | R,F | 2026-11-09 glatan | モデル別の性質の事実を自前表現で記述。条文・図の複製なし。他モデル版が必要になれば項目を追加する |
| SPEC-PDP11-ARCH83 | PDP-11 Architecture Handbook 1983（EB-23657-18） | Digital Equipment Corporation | 1983 | pdp11（FP11、FIS、MMU） | — | — | 未確認 | FP11 の章と FIS の付録を含む。© DEC と推定。bitsavers に所在。前文の逐語確認が残る。段階24の実装時に確定する |
| SPEC-PDP11-CIS | KE44-A CISP User's Guide（EK-KE44A-UG-002、1981） | Digital Equipment Corporation | 1981 | pdp11（CIS） | — | — | 未確認 | Commercial Instruction Set の定義（076nnn、文字列と十進文字列の演算）。© DEC と推定。bitsavers に所在。前文の逐語確認が残る。段階24の実装時に確定する |
| SPEC-PDP11-J11 | J-11 系（11/73、11/83、11/84）のプロセッサ文書（候補：KDJ11-B/KDJ11-E の User's Guide、PDP-11/84 handbook） | Digital Equipment Corporation | — | pdp11（J-11） | — | — | 未確認 | J-11 固有の振る舞い（FPJ11、分離 I&D、CSM）の根拠。特定と前文の確認が残る。段階24の実装時に確定する |
| SPEC-SPARC-V8 | The SPARC Architecture Manual, Version 8（1992） | SPARC International | Version 8 | sparc | © 1991,1992 SPARC International, Inc.、All rights reserved（公開PDFの前文で確認。事前の許諾なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし。試作はV8で実施しV9は使わない |
| SPEC-SPARC-V9 | The SPARC Architecture Manual, Version 9 | SPARC International | — | sparc | — | — | 未確認 | 試作は V8 で実施するため未確認のまま。段階15の実装時に版と前文を確定する |
| SPEC-SPARC-PSABI | System V ABI の SPARC 補遺（候補：SPARC Compliance Definition 2.4.1 の ABI 部） | AT&T/USL → SPARC International | — | sparc（os-linux の SPARC 対応） | — | — | 未確認 | 候補文書の特定と利用条件の確認が残る。段階15の実装時に確定する |
| SPEC-ALPHA-ARM | Alpha Architecture Reference Manual, Fourth Edition（2002-01、Compaq） | Compaq Computer Corporation | 4th Edition | alpha | — | — | 未確認 | 版は本文冒頭で確認。©表記の verbatim は未確認。段階16の実装時に前文を確定する |
| SPEC-ALPHA-CALLSTD | Calling Standard for Alpha Systems（AA-PY8AC-TE、Digital UNIX V4.0、1996-03） | Digital Equipment Corporation | AA-PY8AC-TE | alpha（呼出規約） | — | — | 未確認 | © DEC と推定。Digital UNIX の呼出規約の定義。alpha の Linux ABI は本書と SRC-LINUX から組み立てる。前文の逐語確認が残る。段階16の実装時に確定する |
| SPEC-PARISC-11 | PA-RISC 1.1 Architecture and Instruction Set Reference Manual, Third Edition（1994-02、HP 09740-90039） | Hewlett-Packard Company | 3rd Edition | parisc | © 1986–1994 HP（公開PDFの前文で確認。事前の書面許諾なく複製不可。All rights reserved） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-PARISC-20 | PA-RISC 2.0 Architecture（1995-08、HP） | Hewlett-Packard Company | 1995-08 | parisc | © 1995 HP、All rights reserved（公開PDFの前文で確認。事前の書面許諾なく複製・翻訳不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-SUPERH-SH2 | SuperH RISC Engine SH-1/SH-2 Programming Manual（1996-09-03、Hitachi） | Hitachi, Ltd. | 1996-09-03 | superh | All rights reserved（前文で確認。Hitachi の許可なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-SUPERH-SH4 | SH-4 32-Bit CPU Core Architecture（ADCS 7182230F、2002-09-12） | STMicroelectronics | 2002-09-12 | superh | © Hitachi, Ltd., 1998、All rights reserved（前文で確認。書面承認なく複製不可） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-SUPERH-SH2A | SH-2A, SH2A-FPU Software Manual（REJ09B0051-0300 Rev. 3.00、2005-07） | Renesas Technology（現 Renesas Electronics） | Rev. 3.00 | superh（SH-2A の 32 ビット命令） | — | — | 未確認 | © 2005 Renesas Technology、All rights reserved（出版物頁で確認）。Renesas 配布。前文の逐語確認が残る。段階18の実装時に確定する |
| SPEC-SUPERH-JCORE | J-core の J2 の定義（j-core.org の公開資料。SH-2 互換＋SHAD/SHLD/CAS.L の追加命令） | J-core プロジェクト | 版確定 | superh（J-core） | BSD license（j-core.org の記述。実装に対するもので、文書としての扱いは確認要） | — | 未確認 | J2 の追加命令と振る舞いの根拠。サイト文書としての利用条件は確認時に判断する。段階18の実装時に確定する |
| SPEC-LOONGARCH-RM | LoongArch Reference Manual, Volume 1: Basic Architecture, v1.10 | Loongson Technology Corporation Limited | v1.10 | loongarch | CC BY-NC-ND 4.0 と無断開示・複製禁止の併記（LICENSE 原文で確認。両立は所有者判断） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし。NC/ND の範囲外利用なし |
| SPEC-LOONGARCH-PSABI | Application Binary Interface for the LoongArch Architecture（la-abi-specs repo の lapcs と laelf） | Loongson Technology Corporation Limited | 版確定 | loongarch（os-linux の LoongArch 対応） | CC BY-NC-ND 4.0（repo の README/LICENSE で確認） | — | 未確認 | NC/ND の範囲外利用なし。段階19の実装時に確定する |
| SPEC-LOONGARCH-VEXT | LoongArch Reference Manual Volume 2（Vector Extensions: LSX、LASX）と Volume 3（Virtualization and Binary Translation: LBT） | Loongson Technology Corporation Limited | — | loongarch（拡張） | — | — | 未確認 | 公式文書サイトで Vol.2、Vol.3 は TBD（未刊行）。公開まで拡張の実装は不可。公開を待つか binutils の実装から拾うかは段階19で決める |
| SPEC-OPENRISC-1000 | OpenRISC 1000 Architecture Manual, Version 1.4 rev0（2022-02-20） | OpenRISC Community | v1.4 rev0 | openrisc | GNU GPL に基づく再配布・改変の許諾（PDF 前文で確認。GPL 版数は要確認） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・図の複製なし |
| SPEC-IA64-SDM | Intel Itanium Architecture Software Developer's Manual, Revision 2.3（2010-05。全4巻） | Intel | Rev 2.3 | ia64 | © Intel Corporation、All rights reserved（Intel 標準の法務通知。公開の Specification Update 248699-009 で同文を確認。複製の許諾なし） | R,F | 2026-11-09 glatan | 手組ベクタ用の事実を自前表現で記述。条文・図の複製なし。オラクルなし |
| SPEC-HEXAGON-PRM | Qualcomm Hexagon V73 Programmer's Reference Manual（80-N2040-53） | Qualcomm | V73 | hexagon | © 2022, 2024 Qualcomm Technologies, Inc. and/or its subsidiaries、All rights reserved（公開PDFの前文で確認。複製の許諾なし） | R,F | 2026-11-09 glatan | エンコーディング等の事実を自前表現で記述。条文・図の複製なし |
| SPEC-HEXAGON-PRM-PREV | Hexagon V5x から V68 までの版別 Programmer's Reference Manual（80-N2040-8、-33、-36、-39、-42、-45、-46）と HVX Programmer's Reference Manual（80-N2040-30、-37、-41、-44、-47） | Qualcomm | 版確定 | hexagon（V5 以降の各版の差分と HVX） | — | — | 未確認 | © Qualcomm、All rights reserved（SPEC-HEXAGON-PRM と同じ条件と推定）。docs.qualcomm.com の文書一覧で番号を確認。段階22の実装時に確定する |
| SPEC-IEEE754 | IEEE Standard for Floating-Point Arithmetic（IEEE 754-2019） | IEEE | 2019 | softfloat | © IEEE、All rights reserved（本文書の購入・購読で入手） | R,F | 2026-11-08 glatan | 数値・丸め規則の事実のみ自前表現で使用。条文・図表の複製なし。許諾範囲は所有者判断 |
| SPEC-DECIMAL-ARITH | General Decimal Arithmetic Specification, Version 1.70（2009-03-25） | Mike Cowlishaw（IBM 許諾のもと speleotrove 掲載） | v1.70 | decimal | © 1997, 2009 IBM（掲載頁で確認。オープンライセンスなし） | R,F | 2026-11-09 glatan | 仕様の事実を自前表現で記述。条文・例の複製なし |
| SPEC-ELF-GABI | System V Application Binary Interface の ELF の汎用部分 | SCO（現 Xinuos） | Edition 4.1（1997）＋2001-04-24 DRAFT（ch.4/5） | loader | © SCO、All rights reserved（複製の明示的許諾なし） | R,F | 2026-11-08 glatan | 数値・配置の事実のみ自前表現で使用。条文・図表の複製なし。許諾範囲は所有者判断 |
| SPEC-LINUX-MANPAGES | Linux man-pages | Linux man-pages プロジェクト | 6.20 | os-linux | 各ページに異なるライセンス（GPL、BSD系、Linux-man-pages-copyleft系、verbatim-onlyが混在。ページ冒頭の表示が効力を持つ） | R | 2026-11-08 glatan | 動作理解の参照のみ。verbatim-onlyの頁があるためFは許可しない。番号・配置の事実は SRC-LINUX から取る |
| SPEC-UNIX-V7 | UNIX Programmer's Manual, Seventh Edition（1979。a.out(5) を含む） | Bell Telephone Laboratories（Caldera 許諾） | 7th Edition | pdp11 の Unix V7 パーソナリティ | Caldera License（2002-01-23、SPDX: Caldera。V1-V7+32V のソースと文書に BSD 型の再配布許諾。文書が対象に含まれる点は確認要） | — | 未確認 | ライセンス文面は SPDX と lemis.com の写しで確認。システムコール規約の根拠。段階25の実装時に確定する |
| SPEC-BSD-43 | 4.3BSD/4.4BSD の UNIX 文書（Programmer's Reference Manual 等。a.out を含む） | The Regents of the University of California | 版確定 | vax の BSD パーソナリティ | BSD 系（UC Regents ©。4.4BSD-Lite の文書は再配布許諾ありと推定） | — | 未確認 | 対象の版（4.3BSD Tahoe/Reno か 4.4 か）は段階25で決める。版ごとの利用条件の確認が残る |
| SPEC-ARM-SEMIHOST | Semihosting for AArch32 and AArch64（ARM-software/abi-aa repo、SEMIHOST） | Arm Limited and its affiliates | 版確定 | セミホスティング | CC-BY-SA-4.0 ＋ Grant of Patent License（repo の LICENSE.md で確認） | — | 未確認 | AArch32 と AArch64 の両方を定義。SPEC-ARM-EABI と同じ repo・同じ条件。段階25の実装時に確定する |
| SPEC-GDB-RSP | Debugging with GDB 付録 E: GDB Remote Serial Protocol | Free Software Foundation | 版確定 | gdbstub | GNU FDL（GDB の文書の条件。版数は確認時に記録） | — | 未確認 | パケット形式の事実を自前表現で記述。ソースの gdb/remote.h は GPL。段階29の実装時に確定する |
| SPEC-WIN32 | Win32 API リファレンス（MicrosoftDocs/win32 repo） | Microsoft | 版確定 | Windows x86_64 ホスト | CC-BY-4.0（repo の LICENSE で確認。コード例は MIT） | — | 未確認 | VirtualAlloc 等のホスト API の根拠。段階28の実装時に確定する |

### ソース

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| SRC-LINUX | Linux カーネルのソース（UAPI ヘッダ、システムコールの表、シグナルフレームの定義） | Linux カーネルの開発者 | 7.3 | os-linux | GNU GPL version 2（COPYING）。UAPI は Linux-syscall-note の例外でユーザ空間利用可 | R,F | 2026-11-08 glatan | 番号・配置の事実を自前表現で記述。カーネル本体コードの翻訳はしない（`C` にあたる） |
| SRC-LINUX-66 | Linux カーネルのソース v6.6（ia64 ABI 用。6.7 で arch/ia64 削除前の最終版） | Linux カーネルの開発者 | 6.6 | os-linux（ia64） | GNU GPL version 2（COPYING）。UAPI は Linux-syscall-note の例外でユーザ空間利用可 | R,F | 2026-11-09 glatan | arch/ia64 の存在を v6.6 で確認、v6.7 で削除を確認。番号・配置の事実を自前表現で記述 |
| SRC-LINUX-ARM-UAPI | Linux カーネル v6.6 の arm UAPI 番号の正本（`arch/arm/tools/syscall.tbl` と `arch/arm/include/uapi/asm/unistd.h`） | Linux カーネルの開発者 | 6.6 | os-linux（arm EABI） | GNU GPL version 2。UAPI は Linux-syscall-note の例外でユーザ空間利用可 | T | | `https://raw.githubusercontent.com/torvalds/linux/v6.6/` 配下の当該2ファイルを `.testdata/uapi-arm` に置き、heavy_abi_arm が番号表と突き合わせる。生成ヘッダ（unistd-eabi.h 等）は配布物に無いため tbl を正本とする。リポジトリに含めない。所有者の確認待ち |
| SRC-LINUX-POWERPC-UAPI | Linux カーネル v6.6 の powerpc UAPI 番号の正本（`arch/powerpc/kernel/syscalls/syscall.tbl`） | Linux カーネルの開発者 | 6.6 | os-linux（power） | GNU GPL version 2。UAPI は Linux-syscall-note の例外でユーザ空間利用可 | T | | `https://raw.githubusercontent.com/torvalds/linux/v6.6/` 配下の当該ファイルを `.testdata/uapi-powerpc` に置き、heavy_abi_power が番号表と突き合わせる。ppc64 は abi 列が common・nospu・64 の行を使う。リポジトリに含めない。所有者の確認待ち |
| SRC-LINUX-S390-UAPI | Linux カーネル v6.6 の s390 UAPI 番号の正本（`arch/s390/kernel/syscalls/syscall.tbl`） | Linux カーネルの開発者 | 6.6 | os-linux（s390） | GNU GPL version 2。UAPI は Linux-syscall-note の例外でユーザ空間利用可 | T | | `https://raw.githubusercontent.com/torvalds/linux/v6.6/` 配下の当該ファイルを `.testdata/uapi-s390` に置き、heavy_abi_s390 が番号表と突き合わせる。s390x は abi 列が common・64 の行を使う。リポジトリに含めない。所有者の確認待ち |
| SRC-XNU | XNU カーネルのソース（macOS の mmap、時計、スレッドの振る舞いの根拠） | Apple | 版確定 | macOS ホスト | APSL 2.0（xnu の LICENSE） | — | 未確認 | 事実の確認に読むだけとし、コードの翻訳はしない。段階28の実装時に確定する |
| SRC-SOFTFLOAT3 | Berkeley SoftFloat-3（TestFloat 生成器のビルドに使用） | John Hauser（UC Berkeley） | Release 3e（commit 07ebd29d） | softfloat（TestFloat 実行） | BSD 3-clause（COPYING.txt。Regents of the University of California） | X | 2026-11-09 glatan | リポジトリに含めない。版は `git ls-remote` で HEAD==07ebd29d を確認、COPYING.txt は BSD 3-clause 型文面 |

### テスト

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| TEST-RISCV-TESTS | riscv-tests | RISC-V International のコントリビュータ | commit 3df703c（HEAD） | riscv | BSD 3-clause（Regents of the University of California） | T | 2026-11-08 glatan | 取得して検証に使う。リポジトリに含めない |
| TEST-RISCV-ARCH-TEST | riscv-arch-test | RISC-V International のコントリビュータ | commit 7569d06（HEAD） | riscv | コード BSD-3-Clause／Apache-2.0、文書 CC-BY-4.0 | T | 2026-11-08 glatan | 取得して検証に使う。リポジトリに含めない |
| TEST-WASM-SPEC | WebAssembly 仕様のテストスイート（WebAssembly/spec の test/） | WebAssembly Community Group | main HEAD==f3268fa9（確認時に固定） | wasm | Apache License 2.0（test/ の条件。公開の LICENSE 表で確認） | T | 2026-11-09 glatan | 版は `git ls-remote` で HEAD を確認。取得して使う。リポジトリに含めない |
| TEST-TESTFLOAT | Berkeley TestFloat | John Hauser（UC Berkeley） | Release 3e | softfloat | BSD 3-clause（Regents of the University of California） | T,X | 2026-11-08 glatan | 生成ベクタの使用（`T`）とベクタ生成のための実行（`X`）。リポジトリに含めない |
| TEST-DECTEST | decTest（Version 2.62、2010-04-19。81,300 超テスト） | Mike Cowlishaw（IBM） | v2.62 | decimal | as-is 提供＋IBM © 表示（掲載頁で確認。ICU ライセンスの適用あり） | T | 2026-11-09 glatan | `speleotrove.com/decimal/` の dectest.zip から `.testdata/dectest` に展開して検証に使う。リポジトリに含めない。展開ツリー全体の完全性は `find .testdata/dectest -type f \| sort \| xargs sha256sum \| sha256sum` の値 `117212405be0343abbe77f2c92c6da808a7a1d875a04d93825f87e0a23d5282a` で確認する（144 ファイル分の sha256 を並べた行の sha256） |
| TEST-SINGLESTEP-68000 | SingleStepTests m68000（commit 64b2531） | SingleStepTests | commit 64b2531 | m68k | MIT License（LICENSE 原文で確認。© 2024 SingleStepTests） | T | 2026-11-09 glatan | 取得して検証に使う。リポジトリに含めない |
| TEST-SINGLESTEP-8088 | SingleStepTests 8088（commit aea8448、2025-09-03。v2 系を含む） | SingleStepTests | commit aea8448 | x86 | MIT License（LICENSE 原文で確認。© 2024 SingleStepTests） | T | 2026-11-09 glatan | 取得して検証に使う。リポジトリに含めない。登録コミットは v2 系の期間（v2.0.1 の後）。ピンを更新する場合は版を変えるので確認をやり直す |
| TEST-SINGLESTEP-80286 | SingleStepTests 80286（v1.1.0。実モードのテスト集、サイクル記録つき。MOO 形式） | SingleStepTests | v1.1.0 | x86（80286） | MIT License（LICENSE 原文で確認。© 2025 Daniel Balsom） | T | 2026-11-17 glatan | v1_unreal_mode・v1_protected_mode は未公開。ESC 系（D9–DF）と IDIV の例外のテストが未収録という issue あり。段階13の実装時に確定する |
| TEST-SINGLESTEP-80386 | SingleStepTests 80386（v1.0.0。386EX の実モードのテスト集。MOO 形式） | SingleStepTests | v1.0.0 | x86（80386EX） | MIT License（ソフトウェア）＋データはパブリックドメイン（LICENSE 原文で確認） | T | 2026-11-17 glatan | ライセンスは LICENSE 原文で確認（GitHub の「Other」表示は複合表示のため）。実モードのみ（v1_ex_real_mode）。段階13の実装時に確定する |

### バイナリ

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| BIN-DISTRO | BusyBox 公式静的バイナリ 1.35.0 x86_64-linux-musl（2022-01-17） | BusyBox 開発者 | 1.35.0 | os-linux のプログラム単位のテスト（x86_64 初回） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | 2026-11-09 glatan | 取得してテストの入力に使う。リポジトリに含めない。再配布しない。他ディストロ・他 ISA は使うときに項目を追加する |
| BIN-DISTRO-I386 | BusyBox 公式静的バイナリ 1.35.0 i686-linux-musl（2022-01-17） | BusyBox 開発者 | 1.35.0 | os-linux のプログラム単位のテスト（x86-32） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | 2026-11-14 glatan | 取得してテストの入力に使う（`.testdata/bin-distro-i386/busybox`）。リポジトリに含めない。再配布しない |
| BIN-DISTRO-AARCH64 | Alpine minirootfs aarch64（musl + BusyBox 1.37.0、動的リンクのルートファイルシステム一式） | Alpine Linux プロジェクト | 3.21.9 | os-linux のプログラム単位のテスト（aarch64、動的リンク・ゲストルート） | 同梱物ごとのライセンスに従う（busybox は GPLv2、musl は MIT。busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | 取得してテストの入力に使う（`.testdata/bin-distro-aarch64`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-MIPSEL | BusyBox 公式静的バイナリ 1.31.0-defconfig-multiarch-musl `busybox-mipsel`（o32 LE、2019-06-10 ビルド、1629080 B、sha256 7495ae45f748068707e3351b4f7eb0e4f2666981904f7e933fc53e9614f80e72） | BusyBox 開発者 | 1.31.0 | os-linux のプログラム単位のテスト（mips o32） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | `https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/` から取得してテストの入力に使う（`.testdata/bin-distro-mipsel/busybox`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-MIPS64 | BusyBox 公式静的バイナリ 1.31.0-defconfig-multiarch-musl `busybox-mips64`（n64 BE、2019-06-10 ビルド、1587152 B、sha256 3293f0a613ff707a6f087b8585cc5c69b9fd20ae0c76b0000797b0cf245c95c3） | BusyBox 開発者 | 1.31.0 | os-linux のプログラム単位のテスト（mips n64） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | `https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/` から取得してテストの入力に使う（`.testdata/bin-distro-mips64/busybox`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| TOOL-MUSLCC-N32 | musl.cc クロスツールチェイン `mips64-linux-musln32-cross.tgz`（GCC + musl、約 100 MB） | musl.cc / Rich Felker ほか | — | n32 検証用ゲストバイナリの生成（テスト入力のビルド） | ツールチェイン同梱物ごとのライセンスに従う（GCC は GPLv3+GCC Runtime Exception、musl は MIT） | X | | 取得してビルドに使う（`/tmp` 等ローカル。生成物はテストの入力）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-ARMV5L | BusyBox 公式静的バイナリ 1.31.0-defconfig-multiarch-musl `busybox-armv5l`（armv5 LE hard-float EABI5、musl、2019-06-10 ビルド） | BusyBox 開発者 | 1.31.0 | os-linux のプログラム単位のテスト（arm v5 EABI） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | `https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/` から取得してテストの入力に使う（`.testdata/bin-distro-armv5l/busybox`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-ARMV7L | BusyBox 公式静的バイナリ 1.31.0-defconfig-multiarch-musl `busybox-armv7l`（armv7 LE hard-float EABI5、musl、2019-06-10 ビルド） | BusyBox 開発者 | 1.31.0 | os-linux のプログラム単位のテスト（arm v7 EABI） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | `https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/` から取得してテストの入力に使う（`.testdata/bin-distro-armv7l/busybox`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-POWERPC64 | BusyBox 公式静的バイナリ 1.31.0-defconfig-multiarch-musl `busybox-powerpc64`（ppc64 BE ELFv2、musl、2019-06-10 ビルド、1443568 B、sha256 7f896a2560ef3e2d11438018fef2fbdf8c2a6a2e4b84b1bcbaacc669967532d4） | BusyBox 開発者 | 1.31.0 | os-linux のプログラム単位のテスト（ppc64 BE ELFv2） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | `https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/` から取得してテストの入力に使う（`.testdata/bin-distro-powerpc64/busybox`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-POWERPC64LE | Alpine minirootfs ppc64le（musl + BusyBox 1.37.0、動的リンクのルートファイルシステム一式） | Alpine Linux プロジェクト | 3.21.0 | os-linux のプログラム単位のテスト（ppc64le、動的リンク・ゲストルート） | 同梱物ごとのライセンスに従う（busybox は GPLv2、musl は MIT。busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | 取得してテストの入力に使う（`.testdata/bin-distro-powerpc64le`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-POWERPC | BusyBox 公式静的バイナリ 1.31.0-defconfig-multiarch-musl `busybox-powerpc`（ppc32 BE、musl、2019-06-10 ビルド、1246492 B、sha256 5217f3710842ecebf31637026be209b538019b6456bff9ad196be27d7b85a8b6） | BusyBox 開発者 | 1.31.0 | os-linux のプログラム単位のテスト（ppc32。任意範囲の予備） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | `https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/` から取得済み。ppc32 対応が入った時点でテストの入力に使う（`.testdata/bin-distro-powerpc/busybox`）。リポジトリに含めない。再配布しない。所有者の確認待ち |
| BIN-DISTRO-S390X | BusyBox 公式静的バイナリ 1.31.0-defconfig-multiarch-musl `busybox-s390x`（s390x BE、musl、2019-06-10 ビルド、1381984 B、sha256 48d13ac057046b95ba58921958be639cc3a179ac888cdd65aacd7a69139aa857） | BusyBox 開発者 | 1.31.0 | os-linux のプログラム単位のテスト（s390x） | GNU GPL version 2（busybox.net/license.html で確認。再配布時はソース提供義務あり） | T | | `https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/` から取得してテストの入力に使う（`.testdata/bin-distro-s390x`）。リポジトリに含めない。再配布しない。このビルドは long double が 8 バイトで musl の 128 ビット fmt_fp と不整合があり、`%f`/`%e`/`%g` の出力が実機でも壊れる既知の不具合（エミュレーションはそのまま再現する）。所有者の確認待ち |

### 計測データ

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| MEAS-UOPS-INFO | uops.info（Latency/Throughput/Port Usage。instructions.xml 2026-03 版） | Andreas Abel、Jan Reineke | 2026-03 | x86 のタイミング | ライセンス表示なし（引用要請のみ。2026-11-08 確認） | R,F | 2026-11-09 glatan | 計測値の事実を自前表現で記述。データの再配布なし |
| MEAS-AGNER | Agner Fog の命令表（instruction_tables、2025-09-20 更新） | Agner Fog | 2025-09-20 | x86 のタイミング | © 1996–2025 Agner Fog（前文で確認。Public distribution and mirroring is not allowed） | R,F | 2026-11-09 glatan | 計測値の事実を自前表現で記述。表の再配布・ミラーなし |
| MEAS-INSTLATX64 | InstLatx64 の CPUID ダンプ集（github.com/instlatx64/InstLatx64。実機ごとの CPUID の値の記録） | instlatx64 | — | x86（CPU モデルの識別情報） | LICENSE ファイルなし（リポジトリを確認。README は instlatx64.atw.hu のコピーと明記。公開データで利用条件の明示なし） | R,F | 2026-11-17 glatan | ベンダー・世代ごとの CPU モデルの CPUID などの識別情報の根拠。CPUID の値は事実データなので R,F 想定だが、利用条件の明示がないため所有者の確認が要る。段階13の実装時に確定する |

### ツール

| ID | 名称 | 発行者 | 版 | 対象 | 利用条件 | 用途 | 確認 | 備考 |
|---|---|---|---|---|---|---|---|---|
| TOOL-RUST | Rust のツールチェーン（rustc、cargo、rust-lld、rustfmt、clippy、Miri） | Rust プロジェクト | 1.100.0 | 全体 | MIT OR Apache-2.0（LICENSE-MIT、LICENSE-APACHE） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-TASK | Task 3.54.0（Arch Linux のパッケージ名は go-task） | go-task | 3.54.0 | 開発作業 | MIT（LICENSE） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-NEXTEST | cargo-nextest | nextest-rs | 0.9.151 | テストの実行 | Apache-2.0 OR MIT（LICENSE-APACHE、LICENSE-MIT） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-GIT | Git | Git プロジェクト | 2.56.0 | 開発作業、テストデータの取得 | GNU GPL version 2（COPYING。v2 のみ） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-CURL | curl | curl プロジェクト | 8.23.0 | テストデータの取得 | curl license（COPYING） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布しない |
| TOOL-LLVM | LLVM と clang（llvm-objdump を含む） | LLVM プロジェクト | 23.1.6（`Containerfile` のイメージ内。ホスト手元検証は 23.1.4） | 検証 | Apache-2.0 WITH LLVM-exception（LICENSE.TXT） | X | 2026-11-08 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-GDB | GDB | GNU プロジェクト | 18.1（手元検証） | 検証 | GNU GPL version 3（COPYING） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-WASMTIME | wasmtime | Bytecode Alliance | 50.0.1（手元検証） | wasm の検証 | Apache-2.0 with LLVM exception（LICENSE） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-QEMU | QEMU | QEMU プロジェクト | 10.0.13（`Containerfile` のイメージ内に導入） | 検証（用意できた環境だけ） | GNU GPL version 2（LICENSE。全体。手元未検証） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-BINUTILS | GNU binutils | GNU プロジェクト | 2.47（手元検証） | 検証（用意できた環境だけ） | GNU GPL version 3（COPYING） | X | 2026-11-09 glatan | 別プロセスで実行する。複製・再配布・組み込みをしない |
| TOOL-XED | Intel XED（x86 エンコーダ・デコーダ。コマンドラインのデコーダを別プロセスで使う） | Intel（intelxed/xed） | v2026.08.23 | x86 のデコードの検証 | Apache License 2.0（LICENSE 原文で確認） | X | 2026-11-17 glatan | llvm-objdump より新しい拡張への追従が速い第2のデコードオラクル（v2026.08.23 で ACE-V1・APX に対応）。版を変えるときは確認をやり直す。ルートの `Containerfile` でソースビルドして `/opt/xed` に導入済み |
| TOOL-GCC-X32 | x32（`-mx32`）対応の GCC ツールチェーン（Debian gcc-14-x86-64-linux-gnux32 と libc6-dev-x32-cross） | GNU プロジェクト（Debian パッケージ） | gcc-14 14.2.0-19cross1 / glibc 2.41-11cross1（Debian trixie） | x32 のテストバイナリの生成 | GNU GPL version 3 ＋ GCC Runtime Exception（パッケージの copyright で確認） | X | 2026-11-17 glatan | x32 の公式配布バイナリはなく、`heavy_program_x32` の入力は自前でビルドする。musl は x32 に非対応（glibc 系）。環境は ルートの `Containerfile`（`localhost/polyisa-dev`）。`x86_64-linux-gnux32-gcc-14` による ELF32/EM_X86_64 の静的バイナリ生成と、ホストカーネル（CONFIG_X86_X32_ABI=y）での実行を確認済み |
| TOOL-INTEL-SDE | Intel Software Development Emulator（将来命令を既存 CPU 上で実行する Intel 公式エミュレータ） | Intel | 10.13.1（2026-07-28） | 未出荷拡張の実行差分オラクル | Intel Simplified Software License（2023-08-23 版。利用・無改変再配布は可、リバースエンジニアリング禁止） | X | 2026-11-17 glatan | ISE -062・AVX10.2 v7・APX・ACE v1.15 に対応する実行系オラクル。ホスト CPU が持たない拡張（ACE・AMX・APX 等）の実行差分に使える唯一の経路。ACE v2/AVX10.3 は現行版では未対応のため、その更新を追う。段階13の実装時に版と条項を確定する。ルートの `Containerfile` で公式配布物を `/opt/sde` に展開済み |
