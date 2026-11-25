# polyisa

polyisa は、19 の CPU アーキテクチャ向けにビルドされたユーザープログラムを実行するエミュレータです。Rust で実装しており、`dependencies`・`dev-dependencies`・`build-dependencies` を含めて外部クレートには一切依存していません。

- **19 の ISA ファミリに対応**：x86、AArch64、ARM、RISC-V、MIPS、Power、s390、WebAssembly、m68k、SPARC、Alpha、PA-RISC、SuperH、LoongArch、OpenRISC、IA-64、Hexagon、VAX、PDP-11（詳細は [対応 ISA 一覧](docs/guests/README.md) を参照してください）
- **実行時の CPU モデル選択**：ISA のバージョン・拡張・世代差を CPU モデルとして定義し、`--cpu` で切り替えます
- **プロセス内の仮想カーネルと 5 つの OS パーソナリティ**：Linux、Unix V7、4.3BSD-Reno、WASI preview1、Semihosting 2.0 を提供します
- **インタプリタと x86-64 JIT**：共通の命令意味論からインタプリタと JIT（`POLYISA_JIT` で有効化）を動かします
- **タイミングモデルと GDB 接続**：CPU モデルごとに宣言した忠実度でサイクル数を数え、`-g` オプションで GDB からデバッグできます

## クイックスタート

Rust 1.100.0 以降（エディション 2024）が必要です。開発タスクには Task（Arch Linux では `go-task`）と `cargo-nextest` を使用します。

```bash
# ビルドして利用可能な CPU モデルを表示
cargo run -p polyisa-cli -- cpus

# ELF / a.out / Wasm バイナリを実行
cargo run -p polyisa-cli -- run ./path/to/binary [args...]

# CPU モデル・ゲストルート・OS パーソナリティを指定して実行
cargo run -p polyisa-cli -- run --cpu riscv:sifive_u74 --os semihost ./prog.elf
cargo run -p polyisa-cli -- run --cpu pdp11:pdp11_70 --root ./v7root /bin/echo hello

# 開発チェックと標準テスト（軽量テスト＋doctest）
task check
task test
```

検証用のコンテナや重いテスト（オラクル差分・配布物バイナリ実行）の進め方は [開発・検証ガイド](docs/guides/development.md) にまとめています。

## ドキュメント

- **[実装状況](docs/status.md)**：ISA・OS・ホストターゲット・横断課題の現在地（`task status` が自動生成し、`task check` で鮮度を検証します）
- **[対応 ISA 一覧](docs/guests/README.md)**：19 ファミリごとの対応範囲・実装構造・既知の簡略化・検証手段
- **[ドキュメント案内](docs/README.md)**：アーキテクチャ設計書、開発・テストガイド、横断課題一覧への入口

## ライセンスと参照資料

ライセンスは `MIT OR Apache-2.0` です。全文は [LICENSE-MIT](LICENSE-MIT) と [LICENSE-APACHE](LICENSE-APACHE) に置いています。

参照している一次仕様書、テストデータ、外部ツールの利用条件と許可用途は [参照資料の台帳](docs/references.md) で一元管理し、`task refs:check` で検査しています。
