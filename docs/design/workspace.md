# ワークスペース構成

この文書は、Cargo ワークスペースのクレート構成、クレート間の依存規則、命名規則、ツールチェーン、`unsafe` とエラーの扱いを定める。層の考え方は [設計概要](overview.md) にある。

## ディレクトリ構成

```text
polyisa/
├── Cargo.toml          ワークスペース定義（メンバー、共通の lint と profile）
├── crates/             ISA に依存しないクレート
│   ├── bits/  softfloat/  decimal/  diag/
│   ├── mem/  timing/
│   ├── isadl/  isagen/  sem/  guest/
│   ├── engine/  ir/  jit/
│   ├── loader/  kernel/  os-linux/  os-v7/  os-bsd/  os-semihost/  os-wasi/
│   ├── host/  trace/  gdbstub/  cli/
│   └── testkit/
├── guests/             ゲスト ISA ごとのクレート
│   ├── x86/  arm/  aarch64/  mips/  riscv/  power/  s390/  wasm/
│   └── m68k/  vax/  pdp11/  sparc/  alpha/  parisc/  superh/  loongarch/  openrisc/  ia64/  hexagon/
├── tools/
│   ├── devtool/        タスクから呼ぶ開発作業のコマンド
│   └── testdata/       テストデータの取得定義
├── .config/nextest.toml  nextest の設定
├── Taskfile.yml        開発作業のタスク
└── docs/
```

ディレクトリ名は接頭辞を付けず、パッケージ名は `polyisa-` を付ける。`guests/` の下のパッケージは `polyisa-guest-<ISA ファミリ名>` とする（例：`guests/riscv` は `polyisa-guest-riscv`）。クレートは必要になった時点で作り、上の一覧を先に空のクレートで埋めることはしない。

## クレートの責務

各クレートの名前は、次の表の「責務」を契約として表す。「含まないもの」に挙げたものを持ち込む変更は、クレートの分割か配置の見直しを伴う。

| クレート | 責務 | 含まないもの |
|---|---|---|
| `bits` | ビット列の操作。符号拡張、フィールドの抽出と挿入、桁上げとオーバーフローの計算、エンディアン変換、128 ビット整数の補助 | CPU や ISA の概念 |
| `softfloat` | ソフトウェア浮動小数点。IEEE 754 の二進形式、x87 拡張精度、IBM 16 進浮動小数点、DEC の浮動小数点形式 | ISA ごとの NaN 規則の選択（呼び出し側が設定で渡す） |
| `decimal` | 十進演算。パック十進整数と IEEE 754 十進浮動小数点 | 同上 |
| `diag` | polyisa 自身の診断ログ。出力する対象と水準を環境変数で選ぶ | ゲストの実行のトレース（`trace` が扱う） |
| `isadl` | ISADL の字句解析、構文解析、意味検査、検査済みモデル | Rust コードの生成 |
| `isagen` | ISADL の検査済みモデルから Rust コードを生成する | ISADL の構文解析 |
| `mem` | ゲストメモリ。アドレス空間、ソフトウェアページ表、ページフレーム、ソフトウェア TLB、アクセス属性 | ISA ごとのアドレス変換、OS の `mmap` の方針 |
| `sem` | 命令意味論の語彙。バックエンドトレイト、値の型、退出の型 | 特定のバックエンドの実装 |
| `guest` | ゲスト ISA が実装するトレイトと、CPU モデル、機能集合、レジスタ記述の共通型 | 特定の ISA |
| `timing` | タイミングモデルのトレイト、命令イベント、汎用のタイミングモデル（固定 CPI、インオーダーパイプライン、アウトオブオーダー、キャッシュ、分岐予測） | 特定の CPU モデルの表（ゲスト ISA 側に置く） |
| `engine` | 実行エンジン。インタプリタのバックエンド、デコードキャッシュ、ブロックの管理と無効化、実行ループ、観測点 | OS の処理、ホスト依存の処理 |
| `ir` | 中間表現、IR のバックエンド、最適化 | 機械語の生成 |
| `jit` | IR からホストの機械語を生成し、実行する | IR の最適化 |
| `loader` | 実行ファイル形式の解析（ELF、a.out、ECOFF など） | アドレス空間への配置の方針（OS パーソナリティが決める） |
| `kernel` | 仮想カーネル。ゲストプロセス、ゲストスレッド、スケジューラ、ファイル記述子、仮想ファイルシステム、パイプ、シグナルの配送機構、futex、時計 | 特定の OS のシステムコール規約 |
| `os-linux` | Linux パーソナリティ。システムコールの実装と、ゲスト ABI ごとの番号、構造体、定数、シグナルフレーム | 仮想カーネルの汎用機構 |
| `os-v7` | Unix V7 パーソナリティ（PDP-11）。`trap` の syscall 規約、a.out の配置と初期スタック、分離 I/D のユーザ PAR/PDR と MMR3 | 同上 |
| `os-bsd` | 4.3BSD パーソナリティ（VAX）。`chmk` の syscall 規約（コード語をスタックから取る）、ZMAGIC/OMAGIC の配置と初期スタック | 同上 |
| `os-semihost` | Semihosting 2.0 パーソナリティ。`SYS_*` 演算をホスト入出力へ写す本体（`Semi::call`）と、aarch64/arm の `TrapHandler` 適合（`SemiA64`/`SemiA32`）。riscv の ebreak 入口は cli の `EcallHandler` 適合層が `Semi::call` を呼ぶ | 同上 |
| `os-wasi` | WASI パーソナリティ | 同上 |
| `host` | ホスト依存の機能。実行可能メモリ、端末の制御、ホストの CPU 機能の検出など | ゲストの概念 |
| `trace` | 命令トレースとシステムコールトレースの記録形式と出力 | トレースの採取（エンジンの観測点が行う） |
| `gdbstub` | GDB リモートシリアルプロトコルのサーバ | ISA 固有のレジスタ定義（ゲスト ISA のレジスタ記述を使う） |
| `cli` | `polyisa` コマンド。依存規則の都合でここにしか置けない配線（ISA ごとの `step`、命令の振り分け、ELF の配置） | 実行ループの駆動（`engine`）、命令意味論（`guests/*`）、システムコールの実装（`os-*`） |
| `testkit` | テスト用の部品。擬似乱数、性質テストの実行器、テストベクタの読み込み、オラクルの呼び出し、重いテストが必要とするツールとテストデータの表 | 本番コード（成果物のクレートからは dev-dependencies としてのみ使う） |
| `guests/<isa>` | ISA ファミリの ISADL 記述、CPU 状態、命令意味論、ヘルパー、CPU モデルとタイミング表 | OS との結合（システムコール番号やシグナルフレームは OS パーソナリティ側） |
| `tools/devtool` | 開発作業のコマンド。規則の検査、台帳の検査、設計との差の台帳の検査、実装状況の生成、テストデータの検証、オラクルの検出、生成コードの書き出し、トレースの変換（[開発作業とローカル検証](dev-workflow.md)） | 成果物の機能（`cli` が持つ） |

OS と ISA の組み合わせに固有のコードを OS パーソナリティ側に置くのは、ゲスト ISA クレートを OS から独立させるためである。ゲスト ISA クレートが Linux の ABI を含むと、Unix V7 や WASI のパーソナリティを足すたびにゲスト ISA クレートを変更することになり、将来のシステムモードでも Linux の規約が混ざった CPU 定義を使うことになる。

## 依存規則

依存は次の向きに限る。矢印は「依存する側 → 依存される側」を表す。

```text
基礎層       softfloat, decimal → bits
             diag（依存なし。どのクレートから使ってもよい）
マシンモデル層 mem → bits
             timing → bits
ISA 基盤層   isagen → isadl
             sem → bits, mem
             guest → bits, sem, timing
ゲスト ISA 層 guests/* → bits, softfloat, decimal, mem, sem, guest, timing
             （build-dependency として isagen）
実行層       engine → bits, mem, sem, guest, timing, softfloat, ir
             ir → sem, guest, mem
             jit → ir, host, engine, mem, sem
             （build-dependency として isagen。ホストの命令のエンコーダだけを生成する）
OS 層        loader → bits
             kernel → mem, engine, guest, timing, host
             os-linux → kernel, loader, engine, guest, host, mem, sem,
                        guests/*（機能フラグで選択）
             os-v7 → kernel, loader, engine, host, mem,
                     guests/pdp11
             os-bsd → kernel, loader, engine, host, mem,
                     guests/vax
             os-semihost → engine, sem, mem,
                     guests/aarch64, guests/arm（機能フラグで選択）
             os-wasi → kernel, engine, guest, host, guests/wasm
ツール層     trace → engine, guest
             gdbstub → engine, guest
             cli → すべて
開発用       devtool → testkit, isadl, isagen, trace
             （どのクレートからも依存されない）
```

この向きから、次の性質が成り立つ。

- `engine`、`mem`、`sem`、`guest`、`timing` は、特定のゲスト ISA にも `host` にも依存しない。これらは標準ライブラリだけで書かれ、どのホストでもビルドできる。
- `host` に依存するのは `kernel`、`jit`、`cli` だけである。ホストへの移植作業は `host` の実装の追加で完結する。
- ゲスト ISA クレート同士は依存しない。共通化したいコードは、ISA に依存しない形にして基礎層か ISA 基盤層に移す。

規則の検査は devtool が `cargo metadata` の出力を読んで行い、`task check` で実行する（[開発作業とローカル検証](dev-workflow.md)）。

## 外部依存の禁止

ワークスペースのどの `Cargo.toml` も、ワークスペース外のクレートを `dependencies`、`dev-dependencies`、`build-dependencies` に書かない（[ADR-0001](../adr/0001-no-external-crates.md)）。devtool もこの規則に従う。`task check` は、`Cargo.lock` にワークスペース外のパッケージが現れないことも確認する。

外部のツールは、別プロセスで実行するテストのオラクルと開発の補助に限り、[参照資料の台帳](../references.md) に登録して使う。オラクルがない環境では、該当するテストを失敗ではなく「未実行」として報告する（[開発作業とローカル検証](dev-workflow.md)）。

## 機能フラグ

`cli`・`os-linux`・`os-semihost` は、ゲスト ISA ごとに `guest-<isa>` という機能フラグを持ち、ビルドに含めるゲスト ISA を選べる。既定では、実装済みのゲスト ISA をすべて含める。ゲスト ISA クレートは機能フラグで命令や CPU モデルを削らない。CPU モデルの選択は実行時に行う（[CPU モデル](cpu-models.md)）。`cli` の `guest-riscv` 機能は `gdbstub` への依存も連動させる（`run -g` のデバッグ対象が rv64 のレジスタ表を使う）。

## 生成コード

ゲスト ISA クレートは、`build.rs` で `isagen` を呼び、`spec/` 以下の ISADL ファイルから Rust のコードを `OUT_DIR` に生成し、`include!` で取り込む（[ADR-0002](../adr/0002-isa-description-language.md)）。生成コードはリポジトリにコミットしない。生成器は rustfmt に頼らず、読める形に整形したコードを出力する。生成結果を確認したいときは `task isagen:dump ISA=<isa>` で書き出す。

## ツールチェーン

- エディションは 2024 とする。
- `rust-version` は 1.99 とし、安定版の機能だけを使う。nightly の機能、`build.rs` での rustc の版の判定は使わない。
- `rust-version` を上げるときは、上げる理由になる言語機能や標準ライブラリの API を変更の説明に書く。
- 書式は rustfmt の既定、lint は clippy の既定に、ワークスペースの `[workspace.lints]` で追加の規則を足す。

## `unsafe` の扱い

`unsafe` を使ってよいクレートは `mem`、`engine`、`jit`、`host` に限る。ワークスペースの lint 既定は `unsafe_code = "deny"` で、許可する 4 クレートは `#![allow(unsafe_code)]`、それ以外のクレートは `#![forbid(unsafe_code)]` を宣言する。許可する理由はそれぞれ次のとおりである。

- `mem`：ソフトウェア TLB の高速経路で、ページフレームへのホストポインタを直接読み書きする。
- `engine`：インタプリタのバックエンドが、CPU 状態のフィールドにオフセットでアクセスする（[命令意味論](semantics.md)）。
- `jit`：生成した機械語を実行する。
- `host`：自前の FFI 宣言を呼ぶ。

許可したクレートの中でも、`unsafe` は安全な API の内側に閉じ込め、各ブロックに不変条件を説明する `// SAFETY:` コメントを付ける。`unsafe` を含むモジュールの単体テストは、Miri（rustup のコンポーネント）でも実行する。

## エラーと異常の扱い

ゲストプログラムが引き起こす事象は、Rust のエラーやパニックとして扱わない。未定義命令、ページフォールト、ゼロ除算などは、ゲストの例外として意味論から退出し、OS パーソナリティがシグナルに変換する。

polyisa 自身の不具合（不変条件の破れ）はパニックとして扱う。polyisa が未実装の命令、システムコール、機能に到達した場合は、黙って無視せず、未実装であることを示す退出を返す。この退出には、ゲストのプログラムカウンタ、命令のバイト列、CPU モデル、未実装の対象の名前を含め、利用者が何が足りないかを特定できるようにする。
