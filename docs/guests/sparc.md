# SPARC

## 概要と対応範囲

SPARC V7・V8・V9 および VIS のうち、ユーザーモード実行に必要な命令群（整数、ロード／ストア、分岐・annul・DCTI couple、レジスタウィンドウ、ユーザー ASR、FPU、`movcc`/`movr`、`cas`/`casx`）を `guests/sparc` で実装している。

- **CPU モデル**：`v7`、`v8`、`v9`、`ultrasparc`、`ultrasparc3`、`leon3`、`supersparc`、`microsparc`、`leon4`、`ultrasparc2`、`ultrasparc4`、`ultrasparc_t1`、`ultrasparc_t2`（計 13 モデル）。`supersparc`–`ultrasparc4`・`leon4` は命令集合が親と同じ器。T1/T2 は VIS を持たない構成（一次資料の確認待ち）で VIS3 以降は未実装。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::sparc`）**：`sparc32`・`sparc64` の両 ABI。レジスタウィンドウのあふれ・不足トラップのスタック退避／復元を OS パーソナリティ側で再現し、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

レジスタウィンドウは `StateArray` による動的レジスタ参照で表現し、32 ビットプログラム用のアドレスマスク（`PSTATE.AM`）は実行モードとして扱う。遅延スロット・annul ビット・遅延スロット内の分岐（DCTI couple）はステップ構成で再現している。

## 既知の簡略化と未対応範囲

- **版の範囲の未実装分**：ユーザー可読 ASR のうち `%tick`（`rd %tick`）と `%pic`、V8 タグ演算（`taddcc`/`tsubcc`/`taddcctv`/`tsubcctv`）、V7/V8 コプロセッサ命令（`cpop1`/`cpop2`・`ldc`/`stc` 系）、V9 の 4 倍精度 FPU（`faddq` 等と非 ASI 形の `ldqf`/`stqf`）は未宣言。VIS3 以降の拡張と特権 ASR（`%stick`/`%tick_cmpr` 等）は対象外。
- **仕様書が実装依存とする領域**：BLK 系 ASI の 64 バイト転送・整列・`fd` 8 の倍数制約、FL8/FL16 の SHORT ASI 部分転送、`RDGSR`/`WRGSR` の `fp_disabled` 規則、`WRFPRS` 予約ビットの 32 ビット保持、VIS 命令群（`IMPDEP1` 空間）の意味論、`EDGE` 比較への `PSTATE.AM` 適用、`FMUL8x16AU` の符号拡張、`LDQFA`/`STQFA` の非整列 `rd` を `illegal` とする扱いは、SPARC V9 仕様書が実装依存とする領域であり、UltraSPARC 系の設計選択として実装している。

## 検証手段

- **OS なし・単体**：`bare_sparc`
- **デコーダオラクル**：`heavy_oracle_sparc`（llvm-mc 差分）
- **ABI・プログラム**：`heavy_abi_sparc`、`heavy_program_sparc`（sparc32/sparc64 配布物コマンド群）
