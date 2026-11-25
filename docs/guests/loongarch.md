# LoongArch

## 概要と対応範囲

LA32 および LA64 の 32 ビット固定長命令群（整数算術、ロード／ストア、`ll`/`sc`・`am*` 予約、分岐・`jirl`・境界検査、CSR・`ertn`、`CPUCFG`、スカラ FPU、`fcc` 条件分岐）と、Alpine 配布物が実行する LSX 部分集合を `guests/loongarch` で実装している。LA32 は配布物がないため OS なし実行で検証している。

- **CPU モデル**：`la32`、`la132`、`la264`、`la464`、`la664`（計 5 モデル）。`la464`（3A5000 系）に `lasx`・`lbt`（3A5000 の CPUCFG で LASX も報告される）、`la664`（3A6000 系）に `lasx` を対応づけたが、LASX・LBT の命令自体は未実装で、カバレッジ表ではゼロ件のまま見える。`la364` は構成の一次資料確認が済んでいないため未追加。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::loongarch`）**：LA64 ABI（asm-generic 系）。ELF `e_flags[7:6]` の OBJ-v1（新ワールド）のみ受理し、旧ワールド（v0）と未割当て値はローダで拒否する。`--root` のゲストルート閉じ込め（ルート内にない `/dev/*` はホスト devtmpfs へフォールスルー）、GROWSDOWN 相当の syscall バッファ遅延割当て、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

32 ビット固定長命令を `guests/loongarch/spec/loongarch.rs` に記述する。`CPUCFG` は構成表から識別情報を返し、スカラ FPU の例外フラグは `FCSR0`–`FCSR3` のエイリアスとして管理する。

## 既知の簡略化と未対応範囲

- **拡張命令の範囲**：LSX は Alpine 3.24 の musl/BusyBox が実行する部分集合に限る。LASX・LBT は機能フラグの宣言のみで命令実装はない。
- **旧ワールド ABI**：`e_flags` v0 ABI はテスト入力の入手経路がないため未実装。
- **意味論の簡略化**：
  - `DBAR`/`IBAR`/`PRELD`・TLB 操作命令・`CACOP`/`LDPTE`/`IOCSR*` は no-op または 0 返却、`IDLE` は即復帰、`LL`/`SC` は単一スレッド前提で常に成功する。
  - CSR 列は 512 エントリの単純配列（超過番号は読み 0・書き捨て）、`ERTN` は簡易遷移、`CPUCFG` は固定値表、`RDTIME` は 1 ステップごとの決定的カウンタ（Counter ID 0）。
  - FP 例外はフラグ集約のみでトラップを起こさず、`FRECIPE`/`FRSQRTE` は正確な `FRECIP`/`FRSQRT` で代替、`FSCALEB`/`FLOGB`/`FRINT`・`FCMP` 一部に近似がある。
- **Linux ABI の簡略化**：単一プロセス模型（`fork`/`clone`/`execve`/`wait*` 等は未対応、シグナル配送なし、`futex` 即抜け、`uname`/`getrandom`/`prlimit64` は合成値、`renameat(38)` は受理する近似）。

## 検証手段

- **OS なし・単体**：`bare_loongarch`
- **デコーダオラクル**：`heavy_oracle_loongarch`（llvm-objdump と BusyBox 全語照合）
- **ABI・プログラム**：`heavy_abi_loongarch`（`syscall.tbl` 照合）、`heavy_program_loongarch`（Alpine minirootfs）
