# SuperH

## 概要と対応範囲

SH-1〜SH-4A および J-core（J2）のうちユーザーモード実行に必要な命令群（16 ビット命令、SH-2A の 32 ビット命令、遅延スロットとスロット不正命令例外、SH-4 FPU、`DIV1`）を `guests/superh` で実装している。SH-5 は別アーキテクチャのため対象外である。

- **CPU モデル**：`sh1`、`sh2`、`sh2e`、`sh2a`、`sh2af`、`sh3`、`sh3e`、`sh4`、`sh4a`、`jcore`、`j2`（計 11 モデル）。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::superh`）**：sh4 両エンディアン（LE・BE、437 エントリの syscall 表）。ELF `e_flags` からモデルを自動選択して SH-4A の `synco`/`movli`/`movco` を解決し、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

SH-2A の 32 ビット命令は長さ規則で切り替え、SH-4 FPU の `FPSCR.PR`/`SZ`/`FR` は実行モードとして扱う。`DIV1` の Q 更新は J-core の式に従い、遅延スロット内の分岐はスロット不正命令例外を起こす。

## 既知の簡略化と未対応範囲

- **意味論の簡略化**：
  - `FSCA`（sin/cos）は多項式近似、`FSRRA` は `1.0 / sqrt(x)` 近似、`FIPR`/`FTRV` は逐次 F32 madd であり、SH-4 専用回路の丸め誤差は再現しない。
  - `MAC.W`/`MAC.L` の S ビット飽和（48/32 ビット）は未実装で、飽和なしの 64 ビット加算を行う。
  - SH-2E の FPU 部分集合は一次資料がないため `fpu` 単一フラグで近似し、SH-4 全 FPU 命令を解読する。
  - 特権命令（`RTE`/`SLEEP`/`LDTLB`/`RESBANK` 等）は `TRAP_PRIV`/`TRAP_ILL` に落とし、`LDC Rm, SR` は特権検査なしに SR 値を保持のみする。
  - `movli`/`movco` は単一スレッド前提で常に成功し、gUSA（再開可能不可分列）も先占がない単一スレッド実行として通常命令列と同様に扱う。
- **SH-2A レジスタバンク**：`LDBANK`/`STBANK` は `bank=0` かつ `entry < 8`（`R0_BANK`–`R7_BANK` 相当）のみ保持し、他バンク・他エントリや `IBNR`/`IBCR`・自動退避は未モデル。
- **Linux ABI の簡略化**：単一プロセス模型（`fork`/`clone`/`execve`/`wait*`/`pipe*`/`inotify`/POSIX タイマ等は `ENOSYS`/`EPERM`）。file-backed `mmap` は事前読み込み近似、`uname`/`statfs`/`sysinfo` は合成値、シグナル配送と `/proc`（`exe` 以外）合成は未実装。

## 検証手段

- **OS なし・単体**：`bare_superh`
- **ABI・プログラム**：`heavy_abi_superh`（`syscall.tbl` 照合）、`heavy_program_superh`（sh4 LE/BE 双方の BusyBox）
