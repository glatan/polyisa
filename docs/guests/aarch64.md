# AArch64

## 概要と対応範囲

Armv8.0-A を起点とする 64 ビット固定長（32 ビット命令語）の ISA を `guests/aarch64` で扱う。整数命令一式、浮動小数点命令、および musl/BusyBox が使用する AdvSIMD の転送・積載系を実装している。

- **CPU モデル**：`generic`、`generic_v81`、`armv8_0a`、`armv8_1a`、`armv8_2a`、`cortex_a53`、`cortex_a57`、`cortex_a72`（計 8 モデル）。Cortex-A5x/7x は ARMv8.0 世代で LSE を持たない構成（現状は `generic` と同じ機能構成の器で、MIDR の識別情報配線は未整備）。`armv8_2a` は FP16 とドット積の旗を足すが、命令自体は未実装でカバレッジ表にゼロ件で見える。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::aarch64`）**：LP64（リトルエンディアン・ビッグエンディアン）。asm-generic 番号表、ゲストルート名前空間のパス解決（`--root`、`resolve_guest_path_links`）、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。
- **Semihosting 2.0（`os-semihost::SemiA64`）**：`hlt #0xf000` 入口で `polyisa run --os semihost` に対応している。
- **JIT**：`crates/cli/src/run_aarch64.rs` が `POLYISA_JIT` で x86-64 ホスト JIT に対応している（Linux・Semihosting 双方）。

## 実装の構造と特記事項

命令は 32 ビット固定長であり、`guests/aarch64/spec/a64i.rs` のビットパターンで記述する。`DecodeBitMasks` や `UBFM`/`SBFM` 等のビットフィールド命令を含め、総称 `Backend` 上で意味論を実装している。

## 既知の簡略化と未対応範囲

- **機能旗のデコード未接続**：`fp`・`asimd`・`lse` は命令の `when` 条件に接続されておらず、`generic` と `generic_v81` で命令の利用可否は変わらない。LSE 命令自体も未実装である（[GAP-0101](../known-issues.md)）。
- **AdvSIMD**：musl・配布物バイナリが要求する転送・積載系の部分集合に限られ、ベクトル算術演算系の多くは未実装である。
- **上位拡張**：SVE、SME（ストリーミングモード）、MTE（メモリタギング）は未実装である。
- **`brk` の暫定動作**：`do_brk` が既存写像の確認なしに `mem.map` で上書きする箇所が残る（[GAP-0034](../known-issues.md)）。
- **単一プロセス模型**：Linux ABI の `os-linux::aarch64` は単一プロセス・単一スレッド前提で動作し、待ち合わせは主スレッドで消化する。

## 検証手段

- **OS なし・単体**：`bit_masks`、`decode`
- **デコーダオラクル**：`heavy_oracle_llvm`
- **ABI・プログラム・JIT**：`heavy_abi_aarch64`、`heavy_program_aarch64`、`heavy_program_net`、`heavy_program_semihosting`、`heavy_jit_diff`
