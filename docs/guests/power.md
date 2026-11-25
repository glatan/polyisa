# Power

## 概要と対応範囲

64 ビット Power（ppc64le / ELFv2）を主対象とし、整数演算、CR/XER、予約付きロード／条件付きストア、浮動小数点、VSX/AltiVec、および十進演算（`decimal` クレート経由の十進浮動小数点・`bcdadd.`）を `guests/power` で実装している。

- **CPU モデル**：`generic`（計 1 モデル）。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::power`）**：ppc64le（ELFv2、TOC 規約、エラー返却は CR0.SO ビット）。`--root` のゲスト名前空間パス解決、フォルト駆動スタック成長、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

`guests/power/spec/poweri.rs` に 32 ビット命令群を記述し、総称 `Backend` 上で意味論を実装している。配布物の実バイナリ検証で CA 更新範囲、`mfocrf`、VSX フィールド配置、`cmpi` の `ra` 規約、VR 番号対応を検証済みである。

## 既知の簡略化と未対応範囲

- **機能旗のデコード未接続**：`fp`・`altivec`・`vsx` は命令の `when` 条件に接続されていない。現行は `generic` 1 モデルのため実害はないが、POWER 世代モデルの追加に先立ち、ISA 版ごとの機能分割と `when` への接続が必要である（[GAP-0101](../known-issues.md)）。
- **未対応の ABI・版**：ppc32、ppc64 ビッグエンディアン（ELFv1）、Power ISA 3.1 の 8 バイト接頭辞付き命令、Book E / e500 SPE、601 の POWER 互換機能は未実装。
- **浮動小数点・VSX の残り**：FPSCR/FPCC/CR1 更新の一部、`lxvl`/`stxvl`、`xvmadd` 系の単一丸めは簡略化が残る。
- **JIT**：`run_power.rs` への JIT 統合は未実施。

## 検証手段

- **OS なし・単体**：`sem_unit`
- **デコーダオラクル**：`heavy_oracle_power`
- **ABI・プログラム**：`heavy_abi_power`、`heavy_program_power`
