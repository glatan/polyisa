# PA-RISC

## 概要と対応範囲

PA-RISC 1.1・2.0 と MAX-1/MAX-2 のうちユーザーモード実行に必要な命令群（整数、extract/deposit、ロード／ストア、`LDCW` 系、分岐と無効化、IAOQ キュー、浮動小数点）を `guests/parisc` で実装している。PA-RISC 1.0 は根拠となる一次資料がないため対象外としている。

- **CPU モデル**：`pa7100`、`pa7100lc`、`pa7300lc`、`pa8000`、`pa8500`、`pa8600`、`pa8700`（計 7 モデル）。`pa7100` は MAX-1 を持たない PA 1.1 実装。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::parisc`）**：hppa32 ABI（ビッグエンディアン、408 エントリの syscall 表）。ゲートウェイページ（ページ 0）の 3 入口（`0xb0` LWS、`0xe0` `set_thread_pointer`、`0x100` syscall）を処理し、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

前後の 2 つのプログラムカウンタを持つ命令アドレスキュー（IAOQ）と遅延分岐をステップ構成で扱い、直後命令の無効化（nullification）は `PSW.N` ビットをステップ先頭で判定する。NaN 符号化は IEEE 754-2008 と逆向きの PA-RISC 規則（仮数部最上位ビット 1 が sNaN）に従う。`isagen` 生成の `extract_ops` を意味論で使用している。

## 既知の簡略化と未対応範囲

- **デコードの未モデル分**：`SPOPn`（opcode `0x04`）、debug SFU 命令、`uid != 0` の一般コプロセッサ命令、PA 1.1 の opcode `0x0E` L/R 半面選択形（PA 2.0 の 64 レジスタ形のみ宣言）は未モデル。`SYNCDMA` は `sync` が吸収し、`ftest`/`bb`/`mfctl` の一部は仕様より緩く受理する。
- **意味論の簡略化**：
  - `LDCW`/`LDCD` 系の 16 バイト整列検査は省略し、予約失敗時はトラップへ落とす。`GATE` は特権遷移を省略して `IAOQ_Next{62:63} ← 0` 固定。`PSW.W=0`（narrow）のみ対応し、IASQ/SR ターゲット選択と IPSW/IIA 復元は簡略化している。
  - `SUBB`/`SUB,DB` の条件評価は多語 borrow 連鎖と整合するキャリ込み比較を採用している。
  - 絶対番地ロード／ストア（`LDAW`/`STAW` 等）はフラットメモリ上の通常アクセスとして扱い、`PROBE` 系は先頭バイトのマップ・R/W 許可有無から 1/0 を返す近似。
  - `extract`/`deposit` の `pos < len-1` や 32 ビット deposit 上位語など仕様上の未定義域は決定的な値へ正規化している。`STBY`/`STDBY` は BE（`PSW.E=0`）側のみ実装し、IOR（CR21）退避は未モデル。
- **FP 例外トラップと IR 経路**：FPSR の enable ビットが立っていても assist 例外トラップは起こさずフラグ集約のみ行う。IR 経路では `Backend::fp_flags()` が 0 を返すため、主要 invalid 条件のみ自前で判定して PA 既定 NaN へ置換している。
- **ゲートウェイページと Linux ABI**：ゲートウェイページの 3 入口以外は `Unimplemented`、ページ 0 のデータ参照禁止や `0x1000`–`0x3fff` 予約領域は未強制。`os-linux::parisc` は単一プロセス模型（`fork`/`clone`/`execve`/`wait*`/`pipe*`/`rt_sigreturn` は `ENOSYS`、シグナル配送なし、`statfs*`/`sysinfo`/`times` は合成値、`fcntl` の `F_SETFL`・`chown`・xattr 等は簡略化）。

## 検証手段

- **OS なし・単体**：`bare_parisc`
- **ABI・プログラム**：`heavy_abi_parisc`（`syscall.tbl` 照合）、`heavy_program_parisc`
