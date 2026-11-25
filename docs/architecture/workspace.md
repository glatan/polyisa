# ワークスペース構成

Cargo ワークスペースは 45 のメンバー（ISA 非依存クレート 25、ゲスト ISA クレート 19、開発用コマンド 1）で構成される。

## ディレクトリ構成

```text
polyisa/
├── Cargo.toml            ワークスペース定義、共通パッケージメタデータ、共通 lint、heavy プロファイル
├── crates/               ISA 非依存クレート（25 クレート）
│   ├── bits/  softfloat/  decimal/  diag/
│   ├── mem/  timing/
│   ├── isadl/  isagen/  sem/  guest/
│   ├── engine/  ir/  jit/
│   ├── loader/  kernel/  os-linux/  os-v7/  os-bsd/  os-semihost/  os-wasi/
│   ├── host/  trace/  gdbstub/  cli/
│   └── testkit/
├── guests/               ゲスト ISA クレート（19 ファミリ）
│   ├── aarch64/  alpha/  arm/  hexagon/  ia64/  loongarch/  m68k/
│   ├── mips/  openrisc/  parisc/  pdp11/  power/  riscv/  s390/
│   └── sparc/  superh/  vax/  wasm/  x86/
├── tools/
│   ├── devtool/          検査・status 生成・テスト計画を行う開発用コマンド
│   └── testdata/         外部テストデータの取得定義（manifest.txt）
├── .config/nextest.toml  cargo-nextest のプロファイル設定
├── Taskfile.yml          開発・検証タスクの入口
├── Containerfile         版固定の検証コンテナ定義
└── docs/                 設計文書・ISA 別仕様・ガイド・台帳
```

ディレクトリ名には接頭辞を付けず、Cargo パッケージ名には `polyisa-` を付ける。`guests/<isa>` のパッケージ名は `polyisa-guest-<isa>` である。

## クレートの責務

各クレートの名前は、以下の責務と境界を表す。

| クレート | 責務 | 含まないもの |
|---|---|---|
| `bits` | 符号拡張、ビット抽出・挿入、桁上げ/オーバーフロー計算、エンディアン変換、128 ビット整数補助 | CPU・ISA の概念 |
| `softfloat` | ソフトウェア浮動小数点（IEEE 754 二進、x87 80bit、68881 拡張、IBM 16 進、DEC F/D/G/H、IA-64 82bit、FP8/FP4） | ISA ごとの規則選択（呼び出し側が環境で渡す） |
| `decimal` | パック十進整数（BCD）と IEEE 754 十進浮動小数点（DPD 符号化） | 同上 |
| `diag` | 環境変数で制御する polyisa 自身の診断ログ | ゲストの実行トレース（`trace` の責務） |
| `isadl` | ISA 仕様のモデル型（`Model`）、ビットパターン照合、述語評価、静的検査、モデル選択 | Rust コード生成 |
| `isagen` | 検査済み `Model` からの Rust コード生成（`Insn`・デコーダ・エンコーダ・逆アセンブラ・モデル表） | 構文解析 |
| `mem` | ゲスト仮想アドレス空間、ソフトウェアページ表、ページフレーム、ソフトウェア TLB、アクセス属性 | ISA 固有のアドレス変換、OS の `mmap` 方針 |
| `sem` | 命令意味論の `Backend` トレイト、幅型（`W8`〜`W128`・`F16`〜`F64`）、例外・退出型 | 特定のバックエンド実装 |
| `guest` | ゲスト ISA の共通トレイト、CPU モデル・機能集合・レジスタ記述の共通型 | 特定の ISA |
| `timing` | タイミングモデルのトレイト、命令イベント、汎用モデル（固定 CPI、インオーダー、アウトオブオーダー、キャッシュ、分岐予測） | 特定 CPU のタイミング表（`guests/*` に置く） |
| `engine` | インタプリタバックエンド（`InterpBackend`）、`BareEnv`、実行ループ駆動（`run`・`TrapHandler`・`Observer`・`Breakpoints`）、ブロック/キャッシュ型 | OS 処理、ホスト依存処理 |
| `ir` | ブロック単位の SSA 中間表現、IR 記録バックエンド、ブロック内最適化、IR 解釈実行器 | ホスト機械語生成 |
| `jit` | IR からの x86-64（System V）機械語生成、ホットブロック管理、実行時補助。非 x86-64 Unix ホストではスタブへ退避 | IR の最適化 |
| `loader` | ELF（32/64 ビット、LE/BE）と a.out（PDP-11・VAX）の解析 | アドレス空間への配置方針 |
| `kernel` | 仮想カーネル（プロセス・スレッド表、スケジューラ、多態 `FdTable`、`HostIo` 作業スレッド、パイプ、futex） | 特定 OS のシステムコール規約 |
| `os-linux` | Linux パーソナリティ（16 ISA の ABI 定数・syscall 実装、`sock`/`wait` 正準層、`guest_path` パス解決） | 仮想カーネルの汎用機構 |
| `os-v7` | PDP-11 向け Unix V7 パーソナリティ（`trap` 規約、`SYSENT`、分離 I/D の配置） | 同上 |
| `os-bsd` | VAX 向け 4.3BSD-Reno パーソナリティ（`chmk` 規約、a.out 配置） | 同上 |
| `os-semihost` | Semihosting 2.0 パーソナリティ（`Semi::call` 本体と aarch64/arm 用 `TrapHandler`） | 同上 |
| `os-wasi` | WASI preview1 パーソナリティ（`wasi_snapshot_preview1` / `wasi_unstable`） | 同上 |
| `host` | 実行可能メモリ、ソケット FFI、端末制御などのホスト依存機能 | ゲストの概念 |
| `trace` | 命令トレース（`InsnTrace`）とシステムコールトレースの整形 | 観測点の駆動（`engine` の責務） |
| `gdbstub` | GDB リモートシリアルプロトコルサーバ、ターゲットトレイト、RISC-V レジスタ表 | 実行ループの駆動 |
| `cli` | `polyisa` コマンド、ISA ごとの実行入口・`step`・ディスパッチ・ELF/a.out/Wasm 配置配線 | 実行ループ駆動、命令意味論、syscall 本体 |
| `testkit` | テスト補助（擬似乱数、性質テスト、SHA-256、オラクル呼び出し、重いテストの要件表） | 本番コード（`dev-dependencies` 専用） |
| `guests/<isa>` | ISA の `spec/` 記述、CPU 状態、命令意味論、ヘルパー、専用タイミングモデル | OS との結合 |
| `tools/devtool` | `task check` / `refs:check` / `status` / `test:plan` / `testdata:fetch` / `isagen:dump` の実装 | 成果物の機能 |

OS と ISA の組み合わせに固有のコード（システムコール番号、構造体配置、シグナルフレーム等）を `os-*` 側に置くことで、ゲスト ISA クレートを OS から独立させている。これにより、同じ ISA を Linux・Semihosting・OS なし実行で共用できる。

## 依存規則

依存は次の向きに限る。矢印は「依存する側 → 依存される側」を表す。

```text
基礎層         softfloat, decimal → bits
               diag（依存なし。どのクレートから使ってもよい）
マシンモデル層 mem, timing → bits
ISA 基盤層     isagen → isadl
               sem → bits, mem
               guest → bits, sem, timing
ゲスト ISA 層  guests/* → bits, softfloat, decimal, mem, sem, guest, timing
               （build-dependency として isadl, isagen）
実行層         engine → bits, mem, sem, guest, timing, softfloat, ir
               ir → sem, guest, mem
               jit → ir, host, engine, mem, sem
               （build-dependency として isagen）
OS 層          loader → bits, mem
               kernel → mem, engine, guest, timing, host
               os-linux → kernel, loader, engine, guest, host, mem, sem, guests/*（機能フラグで選択）
               os-v7 → kernel, loader, engine, host, mem, guests/pdp11
               os-bsd → kernel, loader, engine, host, mem, guests/vax
               os-semihost → engine, sem, mem, guests/aarch64, guests/arm（機能フラグで選択）
               os-wasi → kernel, engine, guest, host, guests/wasm
ツール層       trace → engine, guest
               gdbstub → engine, guest
               cli → 全クレート（ゲスト ISA は機能フラグで選択）
開発用         devtool → testkit, isadl, isagen（どのクレートからも依存されない）
```

この依存構造により、次の性質が成り立つ。

- `engine`・`mem`・`sem`・`guest`・`timing` は特定のゲスト ISA にも `host` にも依存しない。
- `host` への直接依存は `kernel`・`os-*`（`os-semihost` を除く）・`jit`・`cli` に限られる。
- ゲスト ISA クレート同士は互いに依存しない。

依存規則の許可表は `tools/devtool/src/main.rs` の `allowed_deps` と `allowed_build_deps` が検査し、`task check` で実行する。検査は各 `Cargo.toml` の `[dependencies]` と `[build-dependencies]` を対象とする。`build.rs` は ISADL のモデル型を直接使うため、ゲスト ISA クレートの build-dependency は `isadl` と `isagen` に限る。

## 外部依存の禁止

ワークスペースのどの `Cargo.toml` も外部クレートを依存に書かない。`dependencies`・`dev-dependencies`・`build-dependencies` に加え、`tools/devtool` も対象である。

外部クレートを完全に排除する理由は三つある。

- 依存クレートの更新、脆弱性追跡、多数クレートのライセンス監査が発生せず、オフラインでビルドできる。
- polyisa が必要とするホスト OS の FFI は十数個の関数に限られ、`libc` クレートを丸ごと導入する費用に見合わない。
- JIT もゲスト固有の最適化（遅延フラグ削除など）を IR で行う必要があり、ホスト機械語のエンコーダは自前の ISADL 記述から生成できる。

`task check` は `Cargo.lock` にワークスペース外のパッケージが含まれていないことを機械的に確認する。外部ツール（clang、llvm-objdump、gdb、wasmtime、Task、cargo-nextest 等）はリンクせず別プロセスとして実行し、[参照資料の台帳](../references.md) で利用条件を管理する。

## 機能フラグと生成コード

`cli`・`os-linux`・`os-semihost` はゲスト ISA ごとに `guest-<isa>` 機能フラグを持ち、既定で全ゲスト ISA を有効にする。`cli` の `guest-riscv` は `gdbstub` 依存も連動させる。ゲスト ISA クレート自体は機能フラグで命令や CPU モデルを削らず、モデルの選択は実行時に行う。

各ゲスト ISA クレートは `build.rs` から `isagen` を呼び出し、`spec/*.rs` の仕様記述から `OUT_DIR` に Rust コードを生成して `include!` で取り込む。生成コードはリポジトリにコミットしない。生成内容を確認したいときは `task isagen:dump ISA=<isa>` を使う。

## ツールチェーンと lint

エディションと MSRV はルートの `[workspace.package]` に一元化し、各メンバーは `.workspace = true` で継承する。

- **Rust エディション**：2024
- **MSRV（`rust-version`）**：1.100.0（安定版の機能のみを使用。nightly 機能は使わない）
- **書式・lint**：`rustfmt` 既定設定、`clippy::all = "warn"`（`task check` で `-D warnings`）、`unsafe_code = "deny"`

## `unsafe` とエラーの扱い

### `unsafe` の許可範囲

ワークスペース既定は `unsafe_code = "deny"` とし、以下の 4 クレートのみ `#![allow(unsafe_code)]` を許可する。その他のクレートは `#![forbid(unsafe_code)]` を宣言する。

- `mem`：ソフトウェア TLB の高速経路でのページフレーム直接アクセス
- `engine`：`InterpBackend` における CPU 状態フィールドへのオフセットアクセス
- `jit`：実行可能メモリ上の生成機械語の呼び出し
- `host`：自前の FFI 宣言の呼び出し

許可クレート内でも `unsafe` は安全な API の内側に閉じ込め、すべてのブロックに不変条件を説明する `// SAFETY:` コメントを付ける。

### エラーと異常の境界

- **ゲスト由来の事象**（未定義命令、ページフォールト、ゼロ除算等）：Rust のパニックにせず、`GuestException` として意味論から退出し、OS パーソナリティがシグナルやエラーへ変換する。
- **未実装の命令・機能・システムコール**：黙って無視せず、PC・命令語・対象名を含む未実装退出（`Outcome::Unimplemented`）を返す。ただし Linux 等のシステムコールは既定で一度報告したうえで `ENOSYS` を返し実行を続ける。
- **polyisa 自身の不変条件違反**：パニックとして扱う。
