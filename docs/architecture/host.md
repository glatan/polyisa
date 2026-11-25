# ホスト抽象化（`host`）と移植性

`host` クレートは、標準ライブラリに存在しないホスト OS 固有の機能を自前の FFI 宣言で包み、他のクレートを OS・CPU・エンディアン・ポインタ幅から独立させる。

## ホスト依存の隔離規則

- **標準ライブラリの優先**：メモリ確保、ファイル操作、ソケット基礎、スレッド、時刻、端末判定（`std::io::IsTerminal`）は標準ライブラリを使う。
- **`cfg` と `std::os::*` の制限**：`crates/` 内でホスト OS やホストアーキテクチャを分岐する `cfg(target_*)` および `std::os::unix` 等の OS 固有モジュールを使えるのは、`host` と `jit`（ホストバックエンド）および `os-linux` の Unix 専用ソケット変換経路に限る。この規則は `task check`（`devtool` の `check_cfg_rules`）で機械検査する。
- **エンディアンとポインタ幅の非依存**：ゲストメモリの多バイト値は常に `from_le_bytes`/`from_be_bytes` で変換し、ゲストアドレスは `u64` で保持する（ホスト添字への `usize` 変換時のみ検査付きで変換する）。

## `host` クレートが提供する機能

| モジュール・機能 | 用途 | 実装方式 |
|---|---|---|
| `host::exec_mem` | JIT 用の実行可能メモリ（W^X 切替） | Unix で `mmap` / `mprotect` / `munmap` の FFI 宣言 |
| `host::sock` | ホストソケット操作（`socket`・`bind`・`connect`・`listen`・`accept4`・`send`/`recv`・`getsockopt`/`setsockopt`・`fcntl` 非阻止・`poll`・`socketpair`） | Unix で C ライブラリの `extern "C"` FFI を `SockFd` で安全な型に包む |
| `host` 本体（`lib.rs`） | `symlink`・`utimensat`・端末属性・メタデータ補助など `std` に欠ける Unix 補助 | 自前 FFI 宣言または `std::os::unix` 補助を安全な関数で公開 |

FFI 宣言は C ライブラリの関数を `extern "C"` で宣言し、インラインアセンブリによる生システムコール発行は使わない。各宣言には根拠資料の参照注記（`// Ref:`）を付け、`unsafe` は `host` 内部に閉じ込める。

## 移植ターゲットと検証状況

主ホストは **Linux x86_64**（全機能＋x86-64 JIT 対応）である。クロスプラットフォームの回帰を防ぐため、`task check:targets` で次のターゲットに対して `cargo check --workspace` を実行する。

- `powerpc64-unknown-linux-gnu`（ビッグエンディアン検証）
- `i686-unknown-linux-gnu`（32 ビット検証）
- `wasm32-unknown-unknown`（OS 非依存・32 ビット検証）
- `wasm32-wasip1`（WASI ホスト検証）

### wasm32（WASI）ホストの現状

`polyisa-cli` は `wasm32-wasip1`・`wasm32-wasip2`・`wasm32-wasip3` でビルドでき、`heavy_host_wasi` テストが wasmtime 上で RV64 ELF を実行して検証している。

wasm32 ホストでは以下の制限がある（[GAP-0099](../known-issues.md)）。

- `jit` はコンパイルが常に `None` を返すスタブになり、インタプリタ／IR 解釈のみで動作する。
- `kernel::HostIo::spawn` は作業スレッドを起動せず直接フォールバックする。
- Unix のホストソケット FFI が使えないため、ホストソケットを要するシステムコールはエラーになる（カーネル内 `PairSock` の `socketpair` は動作する）。`wasi:sockets` への接続は未着手である。

Linux AArch64・macOS（Apple Silicon）・Windows x86_64 向けのネイティブ JIT バックエンドや個別 OS 実装は未着手である。
