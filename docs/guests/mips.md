# MIPS

## 概要と対応範囲

MIPS I（R3000）、MIPS32 Release 2、MIPS64 Release 2、および Release 6（32/64 ビット、コンパクト分岐 19 系・乗除・PC 相対ロード等）を `guests/mips` で扱う。リトルエンディアン・ビッグエンディアン双方に対応する。

- **CPU モデル**：`r3000`、`mips32r1`、`mips32r2`、`r6`、`mips64r1`、`mips64r2`、`mips64r6`、`r4000`、`r10000`（計 9 モデル）。`r4000`（MIPS III）の厳密な層は LL/SC が `mips32r1` 旗に MOVZ/MOVN と束ねられている関係で旗の分割待ち、`r10000`（MIPS IV）は MOVZ/MOVN を持つので R1 層までの構成で近似。R1 は R2 追加命令を持たない構成で、LL/SC・MOVZ/MOVN・SYNC・PREF・TEQ・SPECIAL2 の MUL/MADD/MSUB/CLZ/CLO 系は R1 の層（`mips32r1` 旗）として R2 とは別にゲートする。実機コア（24Kf など）は ASE 構成の確認待ち。
- **タイミング**：R3000 の `exact` タイミングモデルを持つ（`heavy_timing_r3000` で全検証列が一致）。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::mips`）**：`o32`・`n32`・`n64` の 3 ABI（両エンディアン）。ELF クラスと `EF_MIPS_ARCH` から CPU モデルを自動選択する。`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

遅延スロット、branch likely、MIPS I のロード遅延スロットを実行ステップ側で再現している。Release 6 で旧オペコード（`ADDI` 等）が再割当てされた命令（`BOVC`・`BEQZALC`・`BEQC` 等）は、`when`（`!mips_r6` / `mips_r6`）とフィールド間比較の `where` 句で区別する。実行ループは `engine::run` へ統合済みである。

## 既知の簡略化と未対応範囲

- **未実装の拡張**：microMIPS、MIPS16e、DSP、MSA、ベンダー拡張（R5900 MMI 等）は未実装。
- **o32 旧 `mmap` の引数順**：テストが不足している。
- **判断待ちの細則**：Release 6 コンパクト分岐 2R 形式における `rs > rt` の厳格化、および `lui` の `rs` フィールドの厳格化は方針未確定（[横断的な未実装・暫定課題](../known-issues.md)）。
- **JIT**：`run_mips.rs` への JIT 統合は未実施。

## 検証手段

- **OS なし・単体**：`bare_mipsi`
- **ABI・プログラム**：`heavy_abi_uapi`、`heavy_program_mips`
- **タイミング**：`heavy_timing_r3000`
