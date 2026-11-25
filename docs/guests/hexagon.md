# Hexagon

## 概要と対応範囲

Hexagon V5〜V79（主対象 V73）の VLIW パケット命令群（整数、ロード／ストア、`memop`、`.new` オペランド・ストア、円環・brev・Mu 修飾アドレッシング、分岐・複合／new-value compare-jump、`allocframe`/`dealloc_return`、`loop0`/`loop1` ハードウェアループ、duplex 16 ビット対、定数拡張子 `immext`）、HVX 代表部分集合（`hvx` 機能フラグ）、および複数ハードウェアスレッド交互実行モデル（`threads::Core`）を `guests/hexagon` で実装している。

- **CPU モデル**：`generic`、`v55`、`v60`、`v62`、`v65`、`v66`、`v67`、`v68`、`v69`、`v71`、`v73`、`v75`、`v79`、`v67t`、`v71t`（計 15 モデル）。版モデルは版旗の含意連鎖で前版の機能を引く。`v67t`・`v71t` は tinycore 構成の版で、tinycore が縮減を表すか追加を表すかは一次資料の確認待ち（現状は構成旗を足す器）。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::hexagon`）**：ELF32 LE（`EM_QDSP6=164`、`e_flags=0x73`）、動的リンク（`/lib/ld-musl-hexagon.so.1`、`PT_GNU_RELRO` 反映）、`trap0(#1)` 呼出し規約（番号 `r6`・引数 `r0`–`r5`・戻り値 `r0`）、`--root` のゲストルート解決、`os-linux::sock`・`os-linux::wait` 正準層を接続済み。

## 実装の構造と特記事項

フェッチ層が各 32 ビット語の `PP` ビット（`bits[15:14]`）からパケット境界を確定し、duplex 語を 2 つの subinsn へ分解し、`immext` を後続命令の即値へ結合してからデコードする。パケット内の書き込みは未確定バッファ（`pkt_*`）へ溜め、パケット終端で一括コミットする（`.new` は未確定値を読む）。パケット組立規則は `guests/hexagon/src/packet.rs` に手書き表として持ち、意味論は現行では `InterpBackend` 上の具体値記述である。

## 既知の簡略化と未対応範囲

- **版旗のデコード未接続**：`v5`–`v79` の版旗は命令の `when` 条件に接続されておらず、`generic`・`v73`・`v79` で命令の利用可否は変わらない。利用可否に効くのは `hvx` とデコード文脈旗 `dx_*` のみである（[GAP-0101](../known-issues.md)）。
- **未対応の浮動小数点命令と残不具合**：
  - 単精度／倍精度スカラ FP 命令群（`convert_*`・`dfadd`/`dfsub`/`dfmpy*`/`dfcmp*`/`sfmpy`/`sfrecipa` 等）は未実装のため、musl `decfloat`（`printf %f`・BusyBox `seq` 等）に到達すると未実装エラーになる。
  - `__secs_to_tm` 経路で 64 ビット算術に起因するとみられる残不具合があり、`busybox date`・`ls -l` の時刻整形が停止するケースがある。
- **HVX の範囲と近似**：`hvx` 旗で有効になる命令は `vmem`/`vmemu`・基本ベクトル加減算・`vavg`/`vmin`/`vmax`・代表 `vmpy`・`vcombine`/`vmov`/`vsplat`/`vinsert`・`vcmp`・`q` 論理の代表部分集合に限る（scatter/gather・`vshuff`/`vdeal`/`vdelta`/`vrmpy`/`vhist`/テンソル系等は未宣言）。`vinsert` の配置、`vcsr` 飽和 sticky の即時更新、HVX スロット制約、一部 `vmem` 修飾は簡略化している。
- **パケット組立・意味論・HW スレッドの近似**：
  - パケット規則の一部（ICLASS 6 フロー命令、`wrcr` 以外の SA/LC 書込み、一部 `.new` 生産／消費形）は未分離。スロット単調性を満たせないパケットは許容マスク探索へフォールバックする。
  - 分岐予測ヒント・`barrier`/`syncht` は no-op、キャッシュ／プリフェッチ／デバッグ系命令と一部制御レジスタ（`UPCYCLE`・`PKTCOUNT` 等）は未収録、総称 `B: Backend` 化は未着手。
  - `threads::Core` は単純ラウンドロビン（1 発行枠＝1 パケット＝1 サイクル）であり、優先度スケジューリング・パイプライン stall 繰上げ・モデル別既定スレッド数表は持たない。
- **Linux ABI の簡略化**：単一プロセス模型（`fork`/`clone`/`execve`/`wait*`/パイプは `ENOSYS`、シグナル配送なし、file-backed `mmap` は事前読み込み近似、lazymap 遅延割当て、`statfs`/`uname`/`rlimit` は合成値、`getrandom` はホスト `/dev/urandom` 直結）。

## 検証手段

- **OS なし・単体**：`bare_hexagon`、`threads_hexagon`
- **デコーダオラクル**：`heavy_oracle_hexagon`（`llvm-objdump --mcpu=hexagonv73` で BusyBox `.text` 146,804 語中 146,587 語を差分 0 で照合）
- **ABI・プログラム**：`heavy_abi_hexagon`（`syscall.tbl` 照合）、`heavy_program_hexagon`（musl BusyBox 1.37.0）
