# ADR-0013：ライセンスを MIT OR Apache-2.0 とする

- 状態：承認
- 日付：2026-11-09

## 背景

polyisa のライセンスは未定であり（[概要](../design/overview.md) R8）、[ADR-0009](0009-no-code-reuse-until-license.md) が有効な間は他の実装のコードとデータを取り込めない。2026-11-09 時点の確認済み台帳 17 件（`docs/references.md`）と取得定義（`tools/testdata/manifest.txt`）を一次情報と突き合わせた結果、版と利用条件の記載は正確であり、用途 `R,F,T,X` の範囲では追加義務は生じないことが確かめられた。詳細は本 ADR の検討記録ではなく、台帳の備考と `manifest.txt` の正準 URL への修正（2026-11-09）に残す。

残る作業はライセンスの選択である。選択によって [ADR-0009](0009-no-code-reuse-until-license.md) の見直し範囲（どの資産の `D`・`C` が解禁されるか）が変わるため、候補を比較して推奨を記録する。選定により `Cargo.toml` の `license` を `MIT OR Apache-2.0` とした。

一次情報の突合せ結果（2026-11-09）：

- RISC-V 仕様 4 件（UNPRIV/PRIV 20250508、PROFILES RVA23 v1.0、psABI v1.0）はいずれも CC-BY-4.0 で公開され、版は実在する。事実を自前表現で書く `F` と読むだけの `R` は、条文・図表を複製しない運用の範囲では CC-BY-4.0 の帰属義務（共有時のみ発生）を引き起こさない。
- IEEE 754-2019 と ELF gABI（Edition 4.1＋2001-04-24 DRAFT ch.4/5）はいずれも All rights reserved であり、`F` の根拠は許諾ではなく事実とアイデアの二分論にある。言い換えや翻訳は `F` に含めない。許諾範囲は所有者判断とする備考を維持する。
- Linux カーネル 7.3 は GPL-2.0 のみ＋Linux-syscall-note 例外であり、番号・配置の自前記述は UAPI の境界内である。本体コードの翻訳はしない。
- man-pages 6.20 は単一ライセンスを持たず、verbatim-only の頁が混在するため `R` のみが正しい。事実が必要な場合は SRC-LINUX を根拠にする。
- テスト 3 件（riscv-tests 3df703c、riscv-arch-test 7569d06、TestFloat Release 3e＝a9c849f）の LICENSE はいずれも BSD-3-Clause 系（arch-test の文書のみ CC-BY-4.0）であり、`T`（取得して使う、リポジトリに含めない）と TestFloat の `X`（別プロセス実行）は許諾範囲内である。
- ツール 6 件（Rust 1.99.1、Task 3.54.0、nextest 0.9.151、Git 2.56.0、curl 8.23.0、LLVM 23.1.4）の版は手元と一致し、`X`（別プロセス実行のみ）では copyleft を含め追加義務は生じない。

## 決定

polyisa のライセンスを `MIT OR Apache-2.0`（Rust の慣行）とする。

- `LICENSE-MIT` と `LICENSE-APACHE` を置き、各クレートの `Cargo.toml` に `license = "MIT OR Apache-2.0"` を設定する。
- ファイルごとの SPDX 識別子の付与方針を決め、REUSE に準拠する。
- [ADR-0009](0009-no-code-reuse-until-license.md) を見直し、新しい ADR で `D`・`C` が解禁される範囲を資産種別に記録する。BSD 系（riscv-opcodes、riscv-tests 等）は `D`・`C` が可能になり、GPL 系（QEMU、GPL のテスト）と Arm の機械可読仕様は引き続き `T`・`X`・`R,F` 止まりであることを明記する。

本 ADR の承認によりライセンスは確定した。承認後の成果物への `D`・`C` の持ち込みは、BSD 系の資産に限り、台帳で所有者が用途を許可した場合に行う。GPL 系の資産と Arm の機械可読仕様の持ち込みは引き続き禁止する。

## 帰結

- Rust エコシステムとの整合性が最大になり、コントリビューションの障壁が最も低い。Apache-2.0 側で特許許諾を確保できる。
- BSD 系の資産は `D`・`C` が可能になり、[ADR-0009](0009-no-code-reuse-until-license.md) の制約緩和の効果が大きい。現成果物（自前コード＋事実の自前表現のみ）は書き換え不要である。
- GPL のコードの移植・翻訳（`C`）は引き続きできない。将来 QEMU 等の GPL コードの取り込みが必須になった場合は、本決定を再検討する。
- ISA ホルダの特許（命令・SIMD・仮想化等）に対する防御にはならない。特許条項が守るのはコントリビュータ由来の特許のみである。

## 検討した代替案

- Apache-2.0 単独：BSD 系資産との相性は同等である。MIT とのデュアルを不要とする場合の単純化案である。特許訴訟時の権利終了条項が下流の商用法務の検討対象になる場合がある。
- MPL-2.0（ファイル単位 copyleft）：ISA 意味論の開放維持と商用利用の両立を狙う中間案である。ISADL 生成コードが改変か新規かの境界定義と REUSE 運用のコストがかかる。GPL-2.0-only の Linux 本体とは非両立である。
- GPL-3.0-only（強い copyleft の代表）：唯一 GPL 資産の `C`・`D` が可能になる。配布時にソース開示義務が生じ、商用・組み込み製品への組み込みは実質困難になる。GPL 資産の取り込みが必須の場合にのみ選択肢になる。
- 除外した案：GPL-2.0-only（Apache-2.0 資産と非両立）、LGPL（組み込み用ライブラリ API を提供しないため利点が薄い）、BSD-3-Clause 単独・MIT 単独（Rust 慣行のデュアルに含まれるため単独案にしない）。

## 追記（2026-11-10）

前回からの反映と残件を記録する。本 ADR の状態は提案のままである。

- `tools/testdata/manifest.txt` の取得元 2 件を正準 URL に修正した（riscv-tests は riscv-software-src、arch-test は riscv-non-isa）。`testdata:fetch` で 3 件とも版一致を確認した。
- 未確認 5 件に一次情報の候補を記入し、2026-11-09 に所有者が確認した（用途 X）。SRC-SOFTFLOAT3 は Release 3e（HEAD==07ebd29d、COPYING.txt は BSD 3-clause 型文面）。TOOL-GDB は手元 18.1（`show copying` で GPLv3 文面）。TOOL-WASMTIME は手元 50.0.1（LICENSE は Apache-2.0 with LLVM exception）。TOOL-QEMU は手元未導入のため版なし（LICENSE は全体 GPL version 2、手元未検証）。TOOL-BINUTILS は手元 2.47（COPYING は GPL version 3）。
- 確認済み 2 件の編集的修正は確認日付を維持したまま所有者が承認した。TOOL-NEXTEST の表記順の統一と SPEC-LINUX-MANPAGES の備考の精密化であり、用途の変更はない。
- `Cargo.toml` の `license = "TBD"` は維持し、LICENSE ファイルの追加は行わない。`task check`、`refs:check`、`testdata:fetch`、`fmt --check`、`clippy -- -D warnings` はいずれも成功した。

## 選定の実施（2026-11-10）

推奨案での選定の指示により、本 ADR を承認とした。実施内容は次のとおりである。

- `LICENSE-MIT` と `LICENSE-APACHE` を配置した。
- ワークスペースの `license` を `MIT OR Apache-2.0` とし、全メンバーに `license.workspace = true` を設定した。
- `task check` の著作権走査から自前の `LICENSE-MIT` と `LICENSE-APACHE` を除外し、台帳の規則 4 の対象外に追記した。
- README のライセンス節、概要 R8、台帳の用途体系（`D`・`C` は BSD 系に限り所有者が許可、GPL 系と Arm 機械可読仕様は不可）を更新した。
- ADR-0009 を置き換え済み（ADR-0013）とし、一覧を更新した。
- ファイルごとの識別子付与（REUSE 準拠）は残件とし、LICENSE ファイル配置による表示義務の履行を優先した。

## 識別子付与の実施（2026-11-10）

- 全49件の `.rs` ファイル（`crates/`、`guests/`、`tools/`）の先頭に `// SPDX-License-Identifier: MIT OR Apache-2.0` を付与した。
- `task check` の走査は自前の `MIT OR Apache-2.0` の識別子行を許可し、それ以外の第三者の表示を引き続き検出する。台帳の規則4に対象外を追記した。

## 確定（2026-11-10）

- 著作権者は `polyisa contributors` に確定した。各 `.rs` ファイルの先頭に `// Copyright (c) polyisa contributors` を付与し、走査は自前の著作権行を許可する。台帳の規則4に追記した。
- 配布クレートに root の LICENSE 全文が同梱されない点は受容する。`license = "MIT OR Apache-2.0"` の表記が crates.io 上のライセンス表示として有効であり、全文はリポジトリ root で提供する。これは Rust ワークスペースの慣行に従う。
- 許可リストの穴（同表記の第三者ファイルの素通り）は、同条件のため実害なしとして受容する。
- 本 ADR はこの確定をもって凍結する。以後の記録は新規 ADR かコミット文に行う。
