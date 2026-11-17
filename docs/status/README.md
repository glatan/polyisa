# 実装状況

このファイルは `task status` が生成する。手で編集しない。

生成の元は、ISADL の記述（`guests/*/spec/`）、ロードマップの完了条件、設計との差の台帳、システムコールの表（`crates/os-linux/src/rv64/sys.rs` の `RV64_SYSCALLS`、`crates/os-linux/src/x86/sys.rs` の `X86_64_SYSCALLS` と `X86_32_SYSCALLS`、`crates/os-linux/src/mips_o32.rs`・`mips_n32.rs`・`mips_n64.rs`・`aarch64.rs`・`power.rs` の各 `SYSCALLS`）である。テストの結果は含めない。

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
| S5-1 | テスト：`heavy_program_mips`、`heavy_timing_r3000` |
| S5-2 | 所有者 |
| S6-1 | テスト：`heavy_program_aarch64` |
| S6-2 | テスト：`heavy_abi_aarch64` |
| S6-3 | テスト：`heavy_oracle_llvm` |
| S7-1 | テスト：`heavy_program_arm` |
| S7-2 | テスト：`heavy_abi_arm` |
| S7-3 | テスト：`heavy_oracle_llvm` |
| S8-1 | テスト：`heavy_program_power` |
| S8-2 | テスト：`heavy_abi_power` |
| S8-3 | テスト：`heavy_oracle_power` |
| S9-1 | テスト：`heavy_jit_diff` |
| S10-1 | テスト：`heavy_conformance_dectest` |
| S10-2 | テスト：`nonieee_examples` |
| S11-1 | テスト：`heavy_program_s390` |
| S11-2 | テスト：`heavy_abi_s390` |
| S11-3 | テスト：`heavy_oracle_s390` |
| S11-4 | テスト：`bare_s390` |
| S12-1 | テスト：`heavy_conformance_wasm_spec` |
| S12-2 | テスト：`heavy_diff_wasmtime` |
| S12-3 | テスト：`heavy_program_wasi` |
| S13-1 | 未整備 |
| S13-2 | 未整備 |
| S13-3 | 未整備 |
| S13-4 | 未整備 |
| S13-5 | 未整備 |
| S13-6 | 未整備 |
| S13-7 | 未整備 |
| S14-1 | 未整備 |
| S14-2 | 未整備 |
| S14-3 | 未整備 |
| S14-4 | 所有者 |
| S15-1 | 未整備 |
| S15-2 | 未整備 |
| S15-3 | 未整備 |
| S16-1 | 未整備 |
| S16-2 | 所有者 |
| S17-1 | 未整備 |
| S17-2 | 所有者 |
| S18-1 | 未整備 |
| S18-2 | 所有者 |
| S19-1 | 未整備 |
| S19-2 | 未整備 |
| S19-3 | 未整備 |
| S20-1 | 未整備 |
| S20-2 | 所有者 |
| S21-1 | 未整備 |
| S21-2 | 所有者 |
| S22-1 | 未整備 |
| S22-2 | 未整備 |
| S22-3 | 未整備 |
| S23-1 | 未整備 |
| S24-1 | 未整備 |
| S25-1 | 未整備 |
| S25-2 | 未整備 |
| S25-3 | 未整備 |
| S26-1 | 未整備 |
| S27-1 | 未整備 |
| S27-2 | 所有者 |
| S28-1 | 所有者 |
| S28-2 | 所有者 |
| S28-3 | 所有者 |
| S28-4 | 所有者 |
| S29-1 | 未整備 |
| SC-1 | 所有者 |
| SC-2 | 所有者 |
| SC-3 | 所有者 |
| SC-4 | 所有者 |

## ISA

| ISA | 命令の記述 | ニーモニック | CPU モデル | 詳細 |
|---|---|---|---|---|
| aarch64 | 255 | 113 | generic、generic_v81 | [isa-aarch64.md](isa-aarch64.md) |
| arm | 22 | 22 | armv5、armv7 | [isa-arm.md](isa-arm.md) |
| hexagon | 6 | 6 | generic | [isa-hexagon.md](isa-hexagon.md) |
| ia64 | 6 | 5 | generic | [isa-ia64.md](isa-ia64.md) |
| mips | 283 | 270 | r3000、mips32r2、r6、mips64r2、mips64r6 | [isa-mips.md](isa-mips.md) |
| power | 57 | 57 | generic | [isa-power.md](isa-power.md) |
| riscv | 196 | 196 | rv64gc、rv64imac | [isa-riscv.md](isa-riscv.md) |
| s390 | 250 | 250 | z900、z990、z9ec、z10ec、z196、zec12、z13、generic、esa390 | [isa-s390.md](isa-s390.md) |
| sparc | 10 | 10 | generic | [isa-sparc.md](isa-sparc.md) |
| wasm | 8 | 8 | generic | [isa-wasm.md](isa-wasm.md) |
| x86 | 2111 | 669 | x86_64、x86_64_v2、x86_64_v3、x86_64_v4、i8088、i186、i286、i386、i486、pentium、pentium_pro、pentium_iii、generic32 | [isa-x86.md](isa-x86.md) |

## システムコール

| ゲスト ABI | 処理するシステムコール | 詳細 |
|---|---|---|
| rv64 | 3 | [syscalls.md](syscalls.md) |
| x86_64 | 153 | [syscalls.md](syscalls.md) |
| x86_32 | 86 | [syscalls.md](syscalls.md) |
| mips_o32 | 444 | [syscalls.md](syscalls.md) |
| mips_n32 | 398 | [syscalls.md](syscalls.md) |
| mips_n64 | 374 | [syscalls.md](syscalls.md) |
| aarch64 | 122 | [syscalls.md](syscalls.md) |
| power | 221 | [syscalls.md](syscalls.md) |

## 設計との差

台帳は [設計との差の台帳](../gaps.md) にある。未着手は 8 件、代替は 17 件、対象外は 3 件である。

| ID | 区分 | 設計 |
|---|---|---|
| GAP-0002 | 代替 | [ユーザーモード「仮想ファイルシステム」](../design/user-mode.md#仮想ファイルシステム) |
| GAP-0004 | 対象外 | [ホスト抽象化「必要なホストの機能」](../design/host.md#必要なホストの機能) |
| GAP-0006 | 対象外 | [ISA 記述言語（ISADL）「ファイルの配置」](../design/isa-description.md#ファイルの配置) |
| GAP-0008 | 未着手 | [実行エンジン「観測点」](../design/execution-engine.md#観測点) |
| GAP-0009 | 代替 | [浮動小数点と十進演算「検証」](../design/floating-point.md#検証) |
| GAP-0010 | 未着手 | [検証戦略「5. 適合テストスイート」](../design/testing.md#5-適合テストスイート) |
| GAP-0011 | 未着手 | [検証戦略「7. プログラム単位のテスト」](../design/testing.md#7-プログラム単位のテスト) |
| GAP-0012 | 代替 | [ワークスペース構成「依存規則」](../design/workspace.md#依存規則) |
| GAP-0014 | 代替 | [ISA 記述言語（ISADL）「形式と命令」](../design/isa-description.md#形式と命令) |
| GAP-0015 | 対象外 | [ISA 記述言語（ISADL）「オペコード表」](../design/isa-description.md#オペコード表)、[同「フィールドとオペランド」](../design/isa-description.md#フィールドとオペランド) |
| GAP-0021 | 未着手 | [検証戦略「テストの網羅の記録」](../design/testing.md#テストの網羅の記録) |
| GAP-0022 | 代替 | [ロードマップ「段階 4：x86」](../design/roadmap.md#段階-4x86) |
| GAP-0023 | 代替 | [ISA 記述言語（ISADL）「生成物」](../design/isa-description.md#生成物) |
| GAP-0024 | 代替 | [実行エンジン「実行ループ」](../design/execution-engine.md#実行ループ) |
| GAP-0025 | 代替 | [ユーザーモード「ファイル記述子」](../design/user-mode.md#ファイル記述子) |
| GAP-0026 | 代替 | [ユーザーモード「シグナル」](../design/user-mode.md#シグナル) |
| GAP-0027 | 代替 | [CPU モデルとバージョンの表現「挙動パラメータ」](../design/cpu-models.md#挙動パラメータ) |
| GAP-0028 | 未着手 | [実行エンジン「ブロックとデコードキャッシュ」](../design/execution-engine.md#ブロックとデコードキャッシュ) |
| GAP-0029 | 代替 | [ISA 記述言語（ISADL）「実行モード」](../design/isa-description.md#実行モード) |
| GAP-0030 | 未着手 | [検証戦略「8. 実行の差分テスト」](../design/testing.md#8-実行の差分テスト) |
| GAP-0031 | 未着手 | [検証戦略「11. 決定性のテスト」](../design/testing.md#11-決定性のテスト) |
| GAP-0032 | 代替 | [ユーザーモード「ゲスト ABI」](../design/user-mode.md#ゲスト-abi) |
| GAP-0033 | 未着手 | [ゲストメモリ「ファイルの写像」](../design/memory.md#ファイルの写像) |
| GAP-0034 | 代替 | [ユーザーモード「Linux のシステムコールの実装の段階」](../design/user-mode.md#linux-のシステムコールの実装の段階) |
| GAP-0035 | 代替 | [CPU モデルとバージョンの表現「機能」](../design/cpu-models.md#機能) |
| GAP-0036 | 代替 | x86 ゲスト「SSE4.2 文字列・拡張の近似」 |
| GAP-0037 | 代替 | x86 ゲスト「llvm-mc とのデコード差分」 |
| GAP-0038 | 代替 | x86 ゲスト「x87 超越関数と精度の近似」 |
