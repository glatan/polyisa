# OpenRISC

## 概要と対応範囲

OpenRISC 1000（32 ビット固定長・ビッグエンディアン）の ORBIS32 全命令群（整数、ロード／ストア、分岐と遅延スロット、SPR、`l.mac` 系）および ORFPX32・ORFPX64A32 を `guests/openrisc` で実装している。遅延スロットの有無は機能フラグ `dslot`（既定あり、`CPUCFGR[ND]=0` 相当）で切り替える。

- **CPU モデル**：`or1200`（`dslot`）、`mor1kx`（`or1200` + `fpu`）、`mor1kx_pronto`（遅延スロットなし）、`orbis64`（計 4 モデル）。Cappuccino・Espresso 間の差はキャッシュ・MMU 等の構成差で命令集合上は同じため、パイプライン版はタイミング段階で分ける。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::openrisc`）**：or1k ABI（348 エントリの共通表＋固有 `or1k_atomic(244)`、`l.sys` → ベクタ `0xc00`、番号 `r11`・引数 `r3`–`r8`・戻り値 `r11`/`-errno`）。ELF32 BE の静的・動的リンク（`/lib/ld-musl-or1k.so.1`）、`--root` のゲスト名前空間解決、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

`guests/openrisc/spec/openrisc.rs` に 32 ビット命令を記述し、意味論は現行では `InterpBackend` 上の具体値記述として実装している。

## 既知の簡略化と未対応範囲

- **総称 `Backend` 未対応**：意味論が具体値インタプリタ上の記述であり、IR/JIT 向けの総称 `B: Backend` 化は未着手。
- **未実装の拡張・特権命令**：ORBIS64・ORVDX64 は機能フラグ宣言のみで命令実装なし。`l.rfe`・カスタム命令（`l.cust1`–`8`・`lf.cust1.*`）・ORBIS64 `l.ld`/`l.sd`・遅延スロット内の制御転送（DCTI 連鎖）は未実装停止。
- **SPR・予約の簡略化**：SPR の書き込みは `USER_WRITABLE`（F・CY・OV）に制限し、未実装グループ読み出しは 0。`EPCR`/`EEAR`/`ESR`/`PICMR`/`PICSR` は保持のみで例外・割込み配送はない。`l.lwa`/`l.swa` は単一スレッド前提で常に成功する。
- **デマンドページ窓（lazymap）の近似**：musl ldso が `brk` 前にイメージ直後ページへアクセスする挙動に合わせ、`[ELF 末尾, スタック頂)` 全体をフォールト時に遅延割当て（フェッチ時は RWX）している。
- **Linux ABI の簡略化**：単一プロセス模型（`clone`/`execve`/`wait*`/パイプは未対応、`or1k_atomic(244)` は未実装停止）。シグナル配送なし、file-backed `mmap2` は事前読み込み近似、`openat` の一部フラグ無視、`getrandom` は決定的擬似乱数。

## 検証手段

- **OS なし・単体**：`bare_openrisc`、`sem_openrisc`
- **ABI・プログラム**：`heavy_abi_openrisc`（`syscall.tbl` 照合）、`heavy_program_openrisc`（musl BusyBox rootfs）
