# 実機タイミング計測ガイド

`approx` タイミングモデルの較正は、マイクロベンチマークを実機と polyisa の両方で実行し、区間ごとのサイクル数を照合して行います。現在は RISC-V の SiFive U74 モデル（`sifive_u74`）向けベンチマーク一式と記録表を用意しています。

## SiFive U74 の計測手順

較正用ベンチマークは `guests/riscv/bench/` にあります（ビルドは同ディレクトリの `Makefile` を使います）。各計測区間は `bench_mark[]` 配列への書き込み対（開始＝偶数、終了＝奇数）で挟まれています。

1. 実機上で `guests/riscv/bench/` の各ベンチマークを実行し、PMU・`rdcycle` または `perf` で各区間のサイクル数を取得します。
2. polyisa 上で同じバイナリを `--cpu riscv:sifive_u74` で実行し、対応する区間の仮想時間サイクルを記録します。
3. 相対誤差 `|実機 − polyisa| / 実機` を計算し、`guests/riscv/src/timing.rs` の L2 ヒットレイテンシ・主記憶レイテンシ等を調整します。
4. 全区間が宣言誤差内に収まったら、`guests/riscv/spec/rv64i.rs` 内の `sifive_u74` の忠実度を `approx_uncalibrated` から `approx` へ引き上げます（これにより `polyisa cpus` の `（未較正）` 表示が外れます）。

### 測定環境（未計測）

| 項目 | 値 |
|---|---|
| CPU | （型番・コア番号を記入。例：SiFive U74-MC） |
| クロック | （GHz。定格・実測の別を記入） |
| 搭載ボード / SoC | （記入） |
| OS・カーネル | （ディストリビューションとカーネル版を記入） |
| 測定法 | （`perf`・PMU カウンタ・`rdcycle` 等の区間切り出し方法を記入） |
| 測定日 | （記入） |
| polyisa の版 | （コミットハッシュを記入） |

### 計測値（`bench_mark` 区間対応）

`depchain`・`istream`・`branch` は区間番号 `k` が `bench_mark[2k]`/`[2k+1]`、`stride` は区間 `s` が `bench_mark[2s]`/`[2s+1]` に対応します。

| ベンチマーク | 区間 | 内容 | 実機サイクル | polyisa サイクル | 相対誤差 |
|---|---|---|---|---|---|
| depchain | 0 | ポインタチェイシング 4096 回 | | | |
| depchain | 1 | レジスタ依存鎖 2^20 回 | | | |
| istream | 0 | 独立演算 8 命令 × 2^18 回 | | | |
| branch | 0 | 予測可能な条件分岐 2^17 回 | | | |
| branch | 1 | 予測困難な条件分岐 2^17 回 | | | |
| stride | 0 | 64B ストライド × 4 周（4 MiB） | | | |
| stride | 1 | 512B ストライド × 4 周 | | | |
| stride | 2 | 4 KiB ストライド × 4 周 | | | |

### 較正の記録

（実機計測で確定したパラメータと `guests/riscv/src/timing.rs` への反映内容をここに記入します。）
