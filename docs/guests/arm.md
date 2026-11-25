# ARM（AArch32）

## 概要と対応範囲

ARMv5〜ARMv7-A の A32（32 ビット命令）を主対象とし、条件実行、整数演算、`LDM`/`STM`、排他アクセス（`LDREX`/`STREX`）、CP15 TLS 読み出し、VFP（単精度・倍精度）を `guests/arm` で実装している。

- **CPU モデル**：`armv4`、`armv5`、`armv6`、`armv7`（計 4 モデル）。版連鎖は `v5`・`v6`・`v7` の旗で積むが、現状ではいずれの旗も命令の `when` に接続されていない。実機名（ARM7TDMI 等）はタイミング段階。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::arm`）**：ARM EABI（番号表約 450 件、OABI `select(82)` を含む）。`os-linux::sock`・`os-linux::wait` 正準層を接続済み。
- **Semihosting 2.0（`os-semihost::SemiA32`）**：`svc #0x123456`（および T32 `#0xab`）入口で `polyisa run --os semihost` に対応している。
- **JIT**：`crates/cli/src/run_arm.rs` が `POLYISA_JIT` で x86-64 ホスト JIT に対応している（Linux・Semihosting 双方）。

## 実装の構造と特記事項

`guests/arm/spec/armi.rs` は粗分類デコードの記述を置き、細かな命令分岐と条件実行（`if_then`）を `guests/arm/src/sem.rs` で総称 `Backend` 上に実装している。このため、`status.md` 上の ISADL 命令記述数（22）より広い A32 命令群を実行できる。

## 既知の簡略化と未対応範囲

- **機能旗の未接続**：粗分類デコードのため `v7` 旗は命令の `when` 条件に接続されておらず、CLI はモデル選択を破棄して `feats = 0` をデコーダへ渡す。`armv5` と `armv7` の選択は実行に影響せず、ARMv6・ARMv7 系の命令は無条件にデコードされる（[GAP-0101](../known-issues.md)）。
- **Thumb / Thumb-2・NEON**：未実装である（A32 と VFP が対象）。
- **ARMv2/ARMv3 の 26 ビットモード・M プロファイル**：未実装である。
- **kuser helper 領域と `__ARM_NR_cmpxchg`**：未実装であり、`__ARM_NR_cmpxchg` は `ENOSYS` を返す。
- **単一プロセス模型**：Linux ABI は単一プロセス・単一スレッド前提で動作する。

## 検証手段

- **OS なし・単体**：`sem`
- **デコーダオラクル**：`heavy_oracle_llvm`
- **ABI・プログラム・JIT**：`heavy_abi_arm`、`heavy_program_arm`、`heavy_program_semihosting`、`heavy_jit_diff`
