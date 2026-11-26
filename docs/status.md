# 実装状況

このファイルは `task status` が自動生成する。手で編集しない。

各表は ISADL の仕様定義（`guests/*/spec/`）、OS パーソナリティの実装（`crates/os-*`）、CLI ランナ（`crates/cli`）、テストバイナリ（`crates/*/tests/`・`guests/*/tests/`）、`Taskfile.yml`、`docs/known-issues.md` から機械的に集計した現在地を示す。命令単位の詳細一覧と機能旗ごとのカバレッジ（`when` 条件での使用数とモデル参照数）は `task status:dump` で、命令×テスト層の静的証拠は `cargo run -p polyisa-devtool -- coverage` で `target/status/` に書き出せる。

## ISA 対応マトリクス

| ISA | モデル数 | 機能数 | CLI 実行 | 対応 OS | JIT | タイミング | GDB | テスト層 | 詳細 |
|---|---|---|---|---|---|---|---|---|---|
| aarch64 | 11 | 6 | ELF | Linux・Semihosting | 対応 | — | — | bare・oracle・abi・program・jit | [aarch64.md](guests/aarch64.md) |
| alpha | 13 | 7 | ELF | Linux | — | — | — | bare・abi・program | [alpha.md](guests/alpha.md) |
| arm | 4 | 3 | ELF | Linux・Semihosting | 対応 | — | — | bare・oracle・abi・program・jit | [arm.md](guests/arm.md) |
| hexagon | 13 | 21 | ELF | Linux | — | — | — | bare・oracle・abi・program | [hexagon.md](guests/hexagon.md) |
| ia64 | 6 | 9 | ELF | Linux | — | — | — | bare・abi・program | [ia64.md](guests/ia64.md) |
| loongarch | 6 | 5 | ELF | Linux | — | — | — | bare・oracle・abi・program | [loongarch.md](guests/loongarch.md) |
| m68k | 11 | 21 | ELF（`cpus`未掲載） | Linux | — | 専用モデル（検証あり） | — | bare・conformance・abi・program・timing | [m68k.md](guests/m68k.md) |
| mips | 9 | 8 | ELF | Linux | — | 専用モデル（検証あり） | — | bare・abi・program・timing | [mips.md](guests/mips.md) |
| openrisc | 4 | 5 | ELF | Linux | — | — | — | bare・abi・program | [openrisc.md](guests/openrisc.md) |
| parisc | 7 | 4 | ELF | Linux | — | — | — | bare・abi・program | [parisc.md](guests/parisc.md) |
| pdp11 | 21 | 16 | a.out（`cpus`未掲載） | Unix V7 | — | — | — | bare・program | [pdp11.md](guests/pdp11.md) |
| power | 6 | 8 | ELF | Linux | — | — | — | bare・oracle・abi・program | [power.md](guests/power.md) |
| riscv | 15 | 43 | ELF | Linux・Semihosting | — | approx_uncalibrated | 対応 | bare・conformance・oracle・abi・program・diff | [riscv.md](guests/riscv.md) |
| s390 | 19 | 5 | ELF | Linux | — | — | — | bare・oracle・abi・program | [s390.md](guests/s390.md) |
| sparc | 13 | 5 | ELF | Linux | — | — | — | bare・oracle・abi・program | [sparc.md](guests/sparc.md) |
| superh | 12 | 10 | ELF | Linux | — | — | — | bare・abi・program | [superh.md](guests/superh.md) |
| vax | 11 | 7 | a.out | 4.3BSD | — | 専用モデル（未較正） | — | bare・program | [vax.md](guests/vax.md) |
| wasm | 3 | 9 | Wasm（`cpus`未掲載） | WASI | — | — | — | bare・conformance・program・diff | [wasm.md](guests/wasm.md) |
| x86 | 44 | 159 | ELF | Linux | 対応 | 専用モデル（検証あり） | — | bare・conformance・oracle・abi・program・diff・jit・timing | [x86.md](guests/x86.md) |

## OS パーソナリティ（Linux）

| ISA / ABI | ソケット共通層 | 待ち合わせ共通層 | ABI 照合テスト | プログラムテスト |
|---|---|---|---|---|
| aarch64 (LP64 LE/BE) | 接続済み | 接続済み | `heavy_abi_aarch64` | `heavy_program_aarch64`、`heavy_program_net` |
| alpha | 接続済み | 接続済み | `heavy_abi_alpha` | `heavy_program_alpha` |
| arm (EABI) | 接続済み | 接続済み | `heavy_abi_arm` | `heavy_program_arm` |
| hexagon | 接続済み | 接続済み | `heavy_abi_hexagon` | `heavy_program_hexagon` |
| ia64 | 接続済み | 接続済み | `heavy_abi_ia64` | `heavy_program_ia64` |
| loongarch (LA64) | 接続済み | 接続済み | `heavy_abi_loongarch` | `heavy_program_loongarch` |
| m68k | 接続済み | 接続済み | `heavy_abi_m68k` | `heavy_program_m68k` |
| mips (o32 / n32 / n64) | 接続済み | 接続済み | `heavy_abi_uapi` | `heavy_program_mips` |
| openrisc (or1k) | 接続済み | 接続済み | `heavy_abi_openrisc` | `heavy_program_openrisc` |
| parisc (hppa32) | 接続済み | 接続済み | `heavy_abi_parisc` | `heavy_program_parisc` |
| power (ppc64le) | 接続済み | 接続済み | `heavy_abi_power` | `heavy_program_power` |
| riscv (RV64) | — | — | `heavy_abi_uapi` | `heavy_program_gdbstub`、`heavy_program_dyn`、`heavy_program_hello` |
| s390 (s390x) | 接続済み | 接続済み | `heavy_abi_s390` | `heavy_program_s390` |
| sparc (sparc32 / sparc64) | 接続済み | 接続済み | `heavy_abi_sparc` | `heavy_program_sparc` |
| superh (sh4 LE/BE) | 接続済み | 接続済み | `heavy_abi_superh` | `heavy_program_superh` |
| x86 (x86_64 / i386 / x32) | 接続済み | 接続済み | `heavy_abi_uapi` | `heavy_program_busybox`、`heavy_program_busybox_i386`、`heavy_program_i386_applet_probe`、`heavy_program_net`、`heavy_program_x32`、`heavy_program_x86ext` |

## その他の OS パーソナリティ

| クレート | 対象 OS | 対象 ISA | プログラムテスト |
|---|---|---|---|
| `os-v7` | Unix V7 | pdp11 | `heavy_program_unixv7` |
| `os-bsd` | 4.3BSD-Reno | vax | `heavy_program_bsdvax` |
| `os-wasi` | WASI preview1 | wasm | `heavy_program_wasi` |
| `os-semihost` | Semihosting 2.0 | aarch64・arm・riscv | `heavy_program_semihosting` |

## ホストターゲット

| ターゲット | 検査経路 | JIT | ホストテスト |
|---|---|---|---|
| x86_64-unknown-linux-gnu（主ホスト） | `task check` / `task test` | 対応（x86-64 バックエンド） | `heavy_jit_diff` ほか全テスト |
| `powerpc64-unknown-linux-gnu` | `task check:targets` | インタプリタのみ | — |
| `i686-unknown-linux-gnu` | `task check:targets` | インタプリタのみ | — |
| `wasm32-unknown-unknown` | `task check:targets` | インタプリタのみ | — |
| `wasm32-wasip1` | `task check:targets` | インタプリタのみ | `heavy_host_wasi` |

## 横断課題の要約

詳細は [横断的な未実装・暫定課題](known-issues.md) にある。未着手は 5 件、暫定は 14 件である。

| ID | 区分 | 関連文書 |
|---|---|---|
| GAP-0002 | 暫定 | [OS 層](architecture/os-layer.md) |
| GAP-0009 | 暫定 | [浮動小数点と十進演算](architecture/arithmetic.md) |
| GAP-0010 | 暫定 | [テストガイド](guides/testing.md) |
| GAP-0021 | 暫定 | [テストガイド](guides/testing.md) |
| GAP-0023 | 暫定 | [ISA 記述とコード生成](architecture/isadl.md) |
| GAP-0024 | 暫定 | [命令意味論・実行エンジン・JIT](architecture/execution.md) |
| GAP-0026 | 暫定 | [OS 層](architecture/os-layer.md) |
| GAP-0027 | 暫定 | [CPU モデルとバージョン](architecture/cpu-models.md) |
| GAP-0028 | 未着手 | [命令意味論・実行エンジン・JIT](architecture/execution.md) |
| GAP-0030 | 暫定 | [テストガイド](guides/testing.md) |
| GAP-0031 | 未着手 | [テストガイド](guides/testing.md) |
| GAP-0032 | 暫定 | [OS 層](architecture/os-layer.md) |
| GAP-0033 | 未着手 | [ゲストメモリ](architecture/memory.md) |
| GAP-0034 | 暫定 | [OS 層](architecture/os-layer.md) |
| GAP-0091 | 暫定 | [タイミングモデル](architecture/timing.md) |
| GAP-0092 | 暫定 | [タイミングモデル](architecture/timing.md) |
| GAP-0099 | 未着手 | [ホスト抽象化](architecture/host.md) |
| GAP-0100 | 未着手 | [CLI・トレース・GDB 接続](architecture/cli-debug.md) |
| GAP-0101 | 暫定 | [CPU モデルとバージョン](architecture/cpu-models.md) |
