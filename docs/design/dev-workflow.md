# 開発作業とローカル検証

polyisa は CI を使わず、検証はすべて開発者の手元で行う（[概要](overview.md) の要件 R9）。開発作業の入口は Task のタスクとし、テストは cargo-nextest で実行する（要件 R11）。この文書は、タスクの構成、nextest の設定、オラクルがない場合の扱い、検証を行う機会、検証の記録を定める。何をどの層でテストするかは [検証戦略](testing.md) にある。

## 道具

| 道具 | 置き場所 | 役割 |
|---|---|---|
| Task | `Taskfile.yml` | 開発作業の入口。検査、テスト、テストデータの取得、生成コードの書き出し、性能の計測をタスクとして定義する |
| cargo-nextest | `.config/nextest.toml` | テストの実行。プロファイルによって、実行するテストの範囲と時間の上限を切り替える |
| devtool | `tools/devtool/` | タスクから呼ぶ Rust のコマンド。検査とデータの処理を行う |

Task と cargo-nextest は外部のツールであり、[参照資料の台帳](../references.md) に登録して使う。Arch Linux のパッケージでは Task の実行ファイルの名前が `go-task` なので、その環境ではこの文書の `task` を `go-task` と読み替える。

タスクの手順は、ツールを呼ぶ短いコマンドの並びにとどめる。条件分岐とデータの処理（`cargo metadata` の出力の解析、台帳の解析、チェックサムの検証、オラクルの検出）は devtool に書く。シェルの書き方の差がホストの OS ごとの問題になることを避け、処理そのものを Rust のテストで確かめるためである。devtool は成果物に含まれず、ほかのクレートから依存されない。devtool も外部のクレートに依存しない（[ADR-0001](../adr/0001-no-external-crates.md)）。

## タスク

他の文書が参照するタスクは次のとおりである。各タスクの手順は `Taskfile.yml` に書き、`task --list` で一覧を表示できる。

| タスク | 内容 |
|---|---|
| `task check` | rustfmt の検査、clippy、devtool による規則の検査（外部依存の禁止、クレート間の依存規則、`cfg` の使用の規則、台帳の検査、設計との差の台帳の検査、完了条件の検査、spec の表と `build.rs` の一致、実装状況の鮮度の検査） |
| `task check:targets` | ビッグエンディアンのターゲットと 32 ビットのターゲットでの `cargo check`（[ホスト抽象化](host.md)） |
| `task refs:check` | 台帳の検査だけを行う（[参照資料の台帳](../references.md)） |
| `task test` | nextest の `default` プロファイルによる軽いテストと、`cargo test --doc` |
| `task test:full` | オラクルの有無を調べ、使えるものだけで nextest の `full` プロファイルを実行する |
| `task test:layer LAYER=<層の名前>` | 重いテストのうち、一つの層のテストバイナリだけを `full` プロファイルで実行する。オラクルの扱いは `task test:full` と同じ |
| `task testdata:fetch` | 取得定義に従ってテストデータを取得し、チェックサムを検証する |
| `task isagen:dump ISA=<ISA の名前>` | ISADL から生成したコードを書き出す（[ワークスペース](workspace.md)） |
| `task status` | 実装状況を `docs/status/` に生成する |
| `task bench` | 性能の計測（[実行エンジン](execution-engine.md)） |
| `task doctor` | 外部のツールと Rust のターゲットの有無と版を表示する |
| `task hooks:install` | Git のコミット前のフックを入れる |

## 実装状況の生成

`task status` は、追跡しているファイルだけから `docs/status/` を生成する。生成の元は、ISADL の記述、ロードマップの完了条件、設計との差の台帳、cli のシステムコールの表（`RV64_SYSCALLS`、`X86_64_SYSCALLS`、`I386_SYSCALLS`）である。テストの結果は含めない。生成物はコミットする。生成の元を変えた変更では、同じ変更の中で `task status` を実行し直す。`task check` は、生成し直した結果と `docs/status/` を比べ、食い違えば失敗する。

テストは nextest で実行する。エディタから個別のテストを `cargo test` で実行してもよいが、テストの範囲と時間の上限は nextest の設定にだけ書くので、全体の検証には `cargo test` を使わない。nextest は doctest を実行しないので、doctest だけは `task test` が `cargo test --doc` で実行する。

## nextest の設定

### プロファイル

| プロファイル | 実行するテスト | 主な設定 |
|---|---|---|
| `default` | 単体テストと、名前が `heavy_` で始まらないテストバイナリ | 最初の失敗で止める。1 テストあたりの時間の上限を短くする |
| `full` | すべてのテスト | 失敗しても最後まで実行する。時間の上限を長くする。結果を JUnit 形式でも書き出す |

重いテストバイナリの名前の付け方は [検証戦略](testing.md) で定める。設定は次の形になる。時間の上限の値は仮のものであり、段階 1 で計測して決める。

```toml
[profile.default]
default-filter = "not binary(/^heavy_/)"
retries = 0
slow-timeout = { period = "30s", terminate-after = 2 }

[profile.full]
default-filter = "all()"
fail-fast = false
slow-timeout = { period = "300s", terminate-after = 12 }
junit.path = "junit.xml"    # target/nextest/full/junit.xml に書き出される
```

どのプロファイルでも、失敗したテストの再試行（`retries`）は使わない。polyisa の実行は決定的であるべきなので（[ADR-0007](../adr/0007-deterministic-single-host-thread.md)）、再試行で通るテストは、テストか polyisa の不具合として扱う。

### テストグループ

外部のエミュレータを起動するテストは、テストグループで同時に実行する数を制限する。大きなゲストのメモリを使うテストは、`threads-required` で複数のスレッドの枠を占有させる。具体的な値は段階 1 で計測して決める。

### ビルドの設定

`task test:full` は、重いテストを次の Cargo のプロファイルでビルドする（`cargo nextest run --profile full --cargo-profile heavy`）。

```toml
[profile.heavy]
inherits = "release"
debug-assertions = true
overflow-checks = true
```

重いテストは多数の命令を実行するので、最適化しないビルドでは時間がかかりすぎる。一方で、デバッグ用の表明と整数のオーバーフローの検査は、テストでは残しておきたい。このプロファイルはその両方を満たす。

## オラクルがない場合の扱い

オラクルが見つからないことをテストの中で検出して、そのテストを成功として終えると、オラクルのない環境で検証が通ったように見えてしまう。そこで、オラクルの有無はテストを実行する前に調べ、使えないテストバイナリは nextest のフィルタで実行の対象から除く。

1. 重いテストバイナリが必要とするツールとテストデータは、`testkit` の表に台帳の ID で一か所に書く。テストと devtool の両方がこの表を読む。
2. `task test:full` は、最初に devtool でツールとテストデータの有無を調べる。devtool は、使えないものを必要とするテストバイナリを除く nextest のフィルタ式と、除いたテストバイナリの一覧を出力する。
3. タスクはそのフィルタ式を付けて nextest を実行し、最後に、除いたテストバイナリとその理由を「未実行」として表示する。
4. テストの中でツールやテストデータが見つからなかった場合、そのテストは失敗する。成功として扱わない。

## テストデータの取得

`task testdata:fetch` は、取得定義（`tools/testdata/manifest.txt`）に従って、テストデータを `.testdata/` に取得する。取得定義の各行は、台帳の ID、取得元の URL、SHA-256、取得先のパスからなる。取得には外部のツール（curl、Git）を使い、取得したデータの SHA-256 を devtool が検証する。チェックサムが一致しないデータは使わない。台帳で `T` を許可されていない ID を取得定義に書くと、`task refs:check` が失敗する。

`.testdata/` は Git の追跡の対象外とし、コミットしない（[ADR-0009](../adr/0009-no-code-reuse-until-license.md)）。

## 検証の機会

| 機会 | 実行するタスク | 時間の目安 |
|---|---|---|
| コミットの前 | `task check`（フックで実行される）と `task test` | 合わせて 5 分以内。これを超えるようになったら、時間のかかるテストを `heavy_` のテストバイナリに移す |
| 段階の完了、ISA ファミリの追加、共通の抽象の変更の後 | `task check:targets`、`task testdata:fetch`、`task test:full`、`task bench` | 上限を設けない。nextest の `--partition` で分けて実行してよい |

## 検証の記録

CI がないので、検証の結果は自動では残らない。段階の完了は、注釈付きのタグ `stage-<段階の番号>` で表す。完了の判定に使った検証の記録は、そのタグのメッセージに次のことを書く。

- 実行したタスク
- `task doctor` が表示したツールの版
- テストの成功、失敗、未実行の数と、未実行のテストバイナリとその理由
- 性能の計測の結果

nextest の JUnit 形式の出力（`target/nextest/full/junit.xml`）はコミットしない。

## コミットの件名と本文

件名の先頭には、次のいずれかを置く。

- 段階。例は `段階4` である。
- 解消する台帳の ID。例は `GAP-0003` である。
- 変更の対象。例は `docs`、`devtool` である。

リポジトリの文書で定義していないラベルは、件名に使わない。本文には、変更の理由を書く。実装状況（命令の件数、テストの件数）は本文に書かない。

## コミット前のフック

`task hooks:install` は、`task check` を実行するフックを `.git/hooks/pre-commit` に入れる。台帳の検査は `task check` に含まれるので、許可されていない資料の参照はコミットの時点で止まる。Git はフックを複製しないので、リポジトリを複製したら最初に `task hooks:install` を実行する。フックを迂回するコミット（`git commit --no-verify`）はしない。
