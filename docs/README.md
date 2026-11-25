# polyisa ドキュメント案内

このディレクトリには、polyisa の実装状況、現行アーキテクチャの設計文書、19 の ISA 別仕様、開発・検証ガイド、および法務・課題の台帳を置いています。設計文書は「現在のコードが実現している構造と契約」を正本として記述しています。

## 目的別の入口

| 目的 | 参照先 | 概要 |
|---|---|---|
| 現在の実装状況を一覧で見たい | [実装状況](status.md) | 19 ISA・OS パーソナリティ・ホストターゲット・横断課題の自動生成マトリクス（`task status` で更新） |
| 特定の ISA の対応範囲や制限を知りたい | [対応 ISA 一覧](guests/README.md) | 19 ファミリの個別仕様（対応モデル、OS/ABI、既知の簡略化、テスト）と共通仕組みの対照表 |
| 横断的な未実装・暫定実装を知りたい | [横断的な未実装・暫定課題](known-issues.md) | 複数 ISA やクレートにまたがる課題と解消条件（コード中の `// Gap:` 注記と連動検査） |
| ビルド・テスト・コンテナ検証を回したい | [開発・検証ガイド](guides/development.md) | Task・nextest・Podman コンテナ・pre-commit フック・コミット規約 |
| テスト構成やオラクルの扱いを知りたい | [テストガイド](guides/testing.md) | テストの層、重いテストの命名、オラクル未導入時の自動除外、期待値の書き方 |
| 実機でタイミング較正を行いたい | [実機タイミング計測ガイド](guides/calibration.md) | SiFive U74 ベンチマークの計測手順と記録テンプレート |
| ライセンスや一次資料の規則を確認したい | [参照資料の台帳](references.md) | 参照仕様・テストデータ・外部ツールの利用条件と `task refs:check` の検査規則 |

## アーキテクチャ設計書（`docs/architecture/`）

コード全体の構造を把握したい場合は、上から順に読むと全体像がつかめます。

| 文書 | 扱う内容 |
|---|---|
| [アーキテクチャ概要](architecture/overview.md) | 目的、対象範囲と対象外、8 層構造、実行の流れ、設計原則 |
| [ワークスペース構成](architecture/workspace.md) | 45 クレートの責務、依存規則、外部依存禁止、機能フラグ、ツールチェーン、`unsafe` とエラー方針 |
| [ISA 記述とコード生成](architecture/isadl.md) | Rust DSL（`isadl::Model`）による記述、`when`/`where` と静的検査、`isagen` 生成物 |
| [CPU モデルとバージョン](architecture/cpu-models.md) | 機能・プロファイル・モデル継承、挙動パラメータ、識別情報導出、`--cpu` 選択 |
| [命令意味論・実行エンジン・JIT](architecture/execution.md) | 総称 `Backend`、ステップ構成と例外一貫性、`engine`/`cli` 分担、SSA IR と x86-64 JIT |
| [ゲストメモリ](architecture/memory.md) | ソフトウェアページ表、4 KiB ページフレーム、アクセス属性、予約・不可分操作 |
| [浮動小数点と十進演算](architecture/arithmetic.md) | `softfloat`（IEEE 754・非 IEEE 形式・`FpEnv`）と `decimal`（BCD・DPD） |
| [タイミングモデル](architecture/timing.md) | 機能とタイミングの分離、5 段階の忠実度、汎用モデル（cache/branch/inorder/ooo）と専用モデル |
| [仮想カーネル・ローダ・OS パーソナリティ](architecture/os-layer.md) | `loader`、`kernel`（スケジューラ・`FdTable`・`HostIo`）、Linux 16 ABI と V7/BSD/WASI/Semihosting |
| [ホスト抽象化](architecture/host.md) | `host` クレートと FFI 規則、`cfg` 制限、クロスチェックと wasm32-wasi ホスト |
| [CLI・トレース・GDB 接続・診断ログ](architecture/cli-debug.md) | `polyisa` サブコマンド、`trace`、`gdbstub`（RSP・`-g`）、`diag` |
