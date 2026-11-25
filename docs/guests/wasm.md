# WebAssembly

## 概要と対応範囲

WebAssembly 1.0 および 2.0 のコア仕様（モジュール解析・検証・実行、およびテスト用の WAT/WAST パーサと実行器）を `guests/wasm` で実装している。

- **CPU モデル**：`generic`（計 1 モデル）。

## 対応する OS・ABI と実行環境

- **WASI preview1（`os-wasi`）**：`polyisa run` はファイル先頭の `\0asm`（version 1）を検出して WASI preview1 で実行する。`--root` はプリオープン `/` として渡る（モジュール本体はホストパスから読み込む）。`wasi_snapshot_preview1` および旧名 `wasi_unstable` のインポートを正準シグネチャ検証付きで提供し、未対応の 26 関数は `ENOSYS` スタブで応答する。

## 実装の構造と特記事項

`guests/wasm` はバイトコードのデコード、型・スタックの静的検証（`validate`）、内部実行形式でのインタプリタ実行（`exec`）、およびテキスト形式パーサ・仕様テストランナ（`wat`・`wast`）をすべて外部依存なしで自前実装している。浮動小数点演算の NaN は決定性を保つため正準 NaN に固定している。

なお、ISADL の命令記述（`guests/wasm/spec/wasmmin.rs`）は試作時の最小記述（8 件）のまま残っており、本体のデコード・検証・実行は `guests/wasm/src/` の専用モジュールが担う。

## 既知の簡略化と未対応範囲

- **範囲外の提案機能**：module linking、GC、tail-call、SIMD、threads、exception handling、memory64、マルチメモリは未対応（仕様テストの `wast::Runner` では範囲外としてスキップ分類）。
- **hex-float 変換精度**：テキスト形式（WAT/WAST）の 16 進浮動小数点リテラル解析で 1 ulp 差が残る可能性がある。
- **CLI `cpus`**：`polyisa cpus` の一覧出力には未登録。

## 検証手段

- **OS なし・単体**：`bare_wasmmin`、`imported_table_init`、`malformed_memarg`、`malformed_wat_forms`
- **適合テスト**：`heavy_conformance_wasm_spec`（公式 `.wast` テストスイート）
- **実行差分・プログラム**：`heavy_diff_wasmtime`（wasmtime との実行差分）、`heavy_program_wasi`
