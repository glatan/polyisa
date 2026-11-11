# 実装状況

このファイルは `task status` が生成する。手で編集しない。

生成の元は、ISADL の記述（`guests/*/spec/`）、ロードマップの完了条件、設計との差の台帳、システムコールの表（`crates/cli/src/run.rs` の `RV64_SYSCALLS`、`crates/cli/src/run_x86.rs` の `X86_64_SYSCALLS` と `I386_SYSCALLS`、`crates/cli/src/run_mips.rs` の `MIPS_O32_SYSCALLS`）である。テストの結果は含めない。

## 段階の完了条件

条件の文言は [ロードマップ](../design/roadmap.md) にある。

| ID | 判定 |
|---|---|
| S0-1 | テスト：`bare_rv64i` |
| S0-2 | 所有者 |
| S1-1 | テスト：`heavy_program_hello`、`heavy_program_dyn` |
| S1-2 | テスト：`heavy_conformance_riscv_tests`、`heavy_conformance_rv64ui` |
| S1-3 | 所有者 |
| S2-1 | テスト：`bare_hexmin`、`bare_ia64min`、`bare_sparcv8`、`bare_wasmmin` |
| S2-2 | 所有者 |
| S3-1 | テスト：`heavy_program_mips` |
| S3-2 | テスト：`heavy_timing_r3000` |
| S4-1 | テスト：`heavy_program_busybox` |
| S4-2 | 所有者 |
| SC-1 | 所有者 |
| SC-2 | 所有者 |
| SC-3 | 所有者 |
| SC-4 | 所有者 |

## ISA

| ISA | 命令の記述 | ニーモニック | CPU モデル | 詳細 |
|---|---|---|---|---|
| hexagon | 6 | 6 | generic | [isa-hexagon.md](isa-hexagon.md) |
| ia64 | 6 | 5 | generic | [isa-ia64.md](isa-ia64.md) |
| mips | 59 | 59 | r3000、mips32r2、r6 | [isa-mips.md](isa-mips.md) |
| riscv | 196 | 196 | rv64gc、rv64imac | [isa-riscv.md](isa-riscv.md) |
| sparc | 10 | 10 | generic | [isa-sparc.md](isa-sparc.md) |
| wasm | 8 | 8 | generic | [isa-wasm.md](isa-wasm.md) |
| x86 | 696 | 158 | generic32 | [isa-x86.md](isa-x86.md) |

## システムコール

| ゲスト ABI | 処理するシステムコール | 詳細 |
|---|---|---|
| rv64 | 3 | [syscalls.md](syscalls.md) |
| x86_64 | 71 | [syscalls.md](syscalls.md) |
| i386 | 43 | [syscalls.md](syscalls.md) |
| mips_o32 | 2 | [syscalls.md](syscalls.md) |

## 設計との差

台帳は [設計との差の台帳](../gaps.md) にある。未着手は 4 件、代替は 10 件、対象外は 1 件である。

| ID | 区分 | 設計 |
|---|---|---|
| GAP-0001 | 代替 | [ユーザーモード「構成」](../design/user-mode.md#構成) |
| GAP-0002 | 代替 | [ユーザーモード「仮想ファイルシステム」](../design/user-mode.md#仮想ファイルシステム) |
| GAP-0003 | 代替 | [ユーザーモード「未実装のシステムコール」](../design/user-mode.md#未実装のシステムコール) |
| GAP-0004 | 対象外 | [ホスト抽象化「必要なホストの機能」](../design/host.md#必要なホストの機能) |
| GAP-0005 | 代替 | [開発作業とローカル検証「オラクルがない場合の扱い」](../design/dev-workflow.md#オラクルがない場合の扱い) |
| GAP-0006 | 代替 | [ISA 記述言語（ISADL）「ファイルの配置」](../design/isa-description.md#ファイルの配置) |
| GAP-0007 | 代替 | [実行エンジン「実行ループ」](../design/execution-engine.md#実行ループ) |
| GAP-0008 | 未着手 | [実行エンジン「観測点」](../design/execution-engine.md#観測点) |
| GAP-0009 | 代替 | [浮動小数点と十進演算「検証」](../design/floating-point.md#検証) |
| GAP-0010 | 未着手 | [検証戦略「5. 適合テストスイート」](../design/testing.md#5-適合テストスイート) |
| GAP-0011 | 未着手 | [検証戦略「7. プログラム単位のテスト」](../design/testing.md#7-プログラム単位のテスト) |
| GAP-0012 | 代替 | [ワークスペース構成「依存規則」](../design/workspace.md#依存規則) |
| GAP-0014 | 代替 | [ISA 記述言語（ISADL）「形式と命令」](../design/isa-description.md#形式と命令) |
| GAP-0015 | 代替 | [ISA 記述言語（ISADL）「オペコード表」](../design/isa-description.md#オペコード表)、[同「フィールドとオペランド」](../design/isa-description.md#フィールドとオペランド) |
| GAP-0021 | 未着手 | [検証戦略「テストの網羅の記録」](../design/testing.md#テストの網羅の記録) |
