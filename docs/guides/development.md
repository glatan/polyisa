# 開発・検証ガイド

polyisa では CI を使わず、すべての検査とテストを開発者の手元で実行します。作業の入口は Task（`Taskfile.yml`）、テストランナは `cargo-nextest`（`.config/nextest.toml`）に統一しています。Arch Linux のように実行ファイル名が `go-task` の環境では、以下の `task` を `go-task` に読み替えてください。

## 開発ツール一覧

| ツール | 設定・配置 | 役割 |
|---|---|---|
| Task | `Taskfile.yml` | 検査、テスト、テストデータ取得、status 生成、コンテナ実行の入口 |
| cargo-nextest | `.config/nextest.toml` | プロファイル別のテスト実行とタイムアウト制御 |
| devtool | `tools/devtool/` | タスクから呼ぶ Rust 製チェック・生成コマンド（外部依存なし） |
| Podman | `Containerfile` | Rust・LLVM・各種オラクルを版固定した検証コンテナの実行 |

条件分岐やデータ処理はシェルではなく `tools/devtool`（Rust）に実装し、ホスト環境によるシェルの挙動差を避けています。

## タスク一覧

`task --list` で確認できる主要タスクは次のとおりです。

| タスク | 内容 |
|---|---|
| `task check` | `cargo fmt --check`、`cargo clippy --workspace --all-targets -- -D warnings`、および `devtool check`（外部依存禁止、クレート依存規則、`cfg` 規則、参照資料台帳、横断課題一覧、`spec` 表、`docs/status.md` 鮮度） |
| `task check:targets` | ビッグエンディアン・32 ビット・wasm32 ターゲット（`powerpc64`・`i686`・`wasm32-unknown-unknown`・`wasm32-wasip1`）での `cargo check --workspace` |
| `task refs:check` | [参照資料の台帳](../references.md) とコード中 `// Ref:` 注記の整合検査のみを実行 |
| `task test` | nextest の `default` プロファイル（軽量テスト）と `cargo test --doc --workspace` |
| `task test:full` | 利用可能なオラクルとテストデータを自動判定し、実行できる全テストを `full` プロファイル・`heavy` ビルドで実行 |
| `task test:layer LAYER=<層>` | 重いテストのうち特定の層（`oracle`・`conformance`・`abi`・`program`・`diff`・`jit`・`timing`）だけを実行 |
| `task testdata:fetch` | `tools/testdata/manifest.txt` に従って `.testdata/` へテストデータを取得し、SHA-256 を検証 |
| `task isagen:dump ISA=<isa>` | 指定 ISA の `isagen` 生成コードを書き出し |
| `task status` | [実装状況](../status.md)（`docs/status.md`）を再生成 |
| `task status:dump` | 全 19 ISA の命令・モデル詳細一覧を `target/status/` へ書き出し |
| `task bench` | 総称バックエンドと直接実装の比較ベンチマーク（`bench_generic_direct`）を実行 |
| `task doctor` | 外部ツールとインストール済み Rust ターゲットの版を表示 |
| `task hooks:install` | `task check` を実行する Git pre-commit フックを `.git/hooks/pre-commit` に配置 |
| `task container:build` | `Containerfile` から `localhost/polyisa-dev` イメージをビルド |
| `task container -- <コマンド>` | 検証コンテナ内でコマンドを実行（例：`task container -- task check`） |

## 検証コンテナ（Podman）

`Containerfile` は検証に必要なツールチェーン（Rust・LLVM・オラクル群・クロスコンパイラ）を版固定で収めています。`task container` は作業ツリーをコンテナ内の同一絶対パスにマウントするため、`CARGO_MANIFEST_DIR` 由来の `.testdata/` 参照パスがホストと一致し、`target/` も安全に共有できます。

コンテナは `--userns=keep-id --cap-drop=ALL` でホストと同じ非特権 UID として起動します。これは `chroot` や `setuid` が権限不足で失敗する一般ユーザー前提のテスト（BusyBox テスト等）を壊さないためです。rootless の Podman（非 root ユーザー）で実行してください。

## テストデータの取得

外部のテストスイート、テストベクタ、配布物バイナリはリポジトリに含めず、`task testdata:fetch` で `.testdata/` に取得します。`tools/testdata/manifest.txt` の各行は台帳 ID・URL・SHA-256・保存先パスで構成され、台帳で用途 `T` が許可されていない ID を書くと `task refs:check` が失敗します。`.testdata/` は `.gitignore` 対象です。

## 検証の目安と pre-commit フック

- **コミット前**：`task check`（pre-commit フックで自動実行）と `task test` を実行します。合わせて 5 分以内に収まるよう、時間のかかるテストや外部ツール依存テストは `heavy_` バイナリへ分離しています。
- **大きな変更後**（ISA・OS 機能追加、共通抽象の変更）：`task check:targets`、`task testdata:fetch`、`task test:full`、`task bench` を実行します。検証の要点（実行タスクと成功・失敗・未実行件数）はコミット本文に残します。

リポジトリをクローンしたら最初に `task hooks:install` を実行してください。ライセンス検査を含む `task check` を迂回する `git commit --no-verify` は使わないでください。

## コミットメッセージの方針

件名は変更の対象（例：`docs:`、`devtool:`、`guests/x86:`、`feat(gdbstub):`）または解消する課題 ID（例：`GAP-0028:`）で始め、本文には変更の理由と判断根拠を書きます。命令件数やテスト件数のような陳腐化しやすい数値は本文に書かず、自動生成される `docs/status.md` に任せます。
