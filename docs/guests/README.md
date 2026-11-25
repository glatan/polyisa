# 対応 ISA 一覧

polyisa は 19 の ISA ファミリを `guests/<isa>` クレートとして実装している。各 ISA のモデル数・OS・JIT・タイミング・テスト層の最新集計は [実装状況](../status.md) に自動生成される。

## 19 ファミリの個別文書

| ファミリ | 文書 | 主な実行対象 |
|---|---|---|
| x86 | [x86.md](x86.md) | Linux（x86_64・i386・x32）、実モード（8088・80286） |
| AArch64 | [aarch64.md](aarch64.md) | Linux（LP64 LE/BE）、Semihosting 2.0 |
| ARM | [arm.md](arm.md) | Linux（EABI）、Semihosting 2.0 |
| RISC-V | [riscv.md](riscv.md) | Linux（RV64）、Semihosting 2.0、GDB 接続 |
| MIPS | [mips.md](mips.md) | Linux（o32・n32・n64 両エンディアン）、R3000 タイミング |
| Power | [power.md](power.md) | Linux（ppc64le ELFv2） |
| s390 | [s390.md](s390.md) | Linux（s390x）、ESA/390（OS なし実行） |
| WebAssembly | [wasm.md](wasm.md) | Wasm 1.0/2.0、WASI preview1 |
| m68k | [m68k.md](m68k.md) | Linux（m68k）、68000 SST・タイミング |
| SPARC | [sparc.md](sparc.md) | Linux（sparc32・sparc64） |
| Alpha | [alpha.md](alpha.md) | Linux（alpha） |
| PA-RISC | [parisc.md](parisc.md) | Linux（hppa32） |
| SuperH | [superh.md](superh.md) | Linux（sh4 LE/BE） |
| LoongArch | [loongarch.md](loongarch.md) | Linux（LA64）、LA32（OS なし実行） |
| OpenRISC | [openrisc.md](openrisc.md) | Linux（or1k） |
| IA-64 | [ia64.md](ia64.md) | Linux（ia64） |
| Hexagon | [hexagon.md](hexagon.md) | Linux（hexagon） |
| VAX | [vax.md](vax.md) | 4.3BSD-Reno（a.out）、OS なし実行 |
| PDP-11 | [pdp11.md](pdp11.md) | Unix V7（a.out・分離 I/D）、OS なし実行 |

## 共通の仕組みと ISA の対応

複数の ISA が共有するアーキテクチャ上の仕組みと、それを利用する ISA の対応は次のとおりである。

| 仕組み | 利用する ISA | 設計文書 |
|---|---|---|
| 可変長命令 | x86、m68k、VAX、PDP-11、s390、ARM（Thumb）、RISC-V（C 拡張）、Power（ISA 3.1）、SuperH（SH-2A）、Wasm | [ISADL](../architecture/isadl.md) |
| 手続き的オペランドデコード | x86（ModRM/SIB）、m68k（実効アドレス）、VAX・PDP-11（オペランド指定子） | [ISADL](../architecture/isadl.md) |
| 実行モード切替 | x86、ARM、MIPS、SuperH、s390、Power、AArch64、SPARC、RISC-V | [ISADL](../architecture/isadl.md) |
| 遅延スロット・無効化 | MIPS、SPARC、SuperH、PA-RISC、OpenRISC | [命令意味論・実行エンジン](../architecture/execution.md) |
| パケット・バンドル・述語実行 | Hexagon、IA-64、ARM | [命令意味論・実行エンジン](../architecture/execution.md) |
| 動的なレジスタ参照 | SPARC（ウィンドウ）、IA-64（回転/RSE）、x86（x87 スタック） | [命令意味論・実行エンジン](../architecture/execution.md) |
| 遅延評価の条件フラグ | x86、s390、m68k | [命令意味論・実行エンジン](../architecture/execution.md) |
| 反復ステップと途中状態 | x86（REP）、VAX（文字列・POLY）、PDP-11（CIS）、s390（MVCL） | [命令意味論・実行エンジン](../architecture/execution.md) |
| 非 IEEE 浮動小数点 | x86、m68k、s390、VAX、PDP-11、Alpha、IA-64 | [浮動小数点と十進演算](../architecture/arithmetic.md) |
| 十進演算（BCD / DFP） | VAX、PDP-11、s390、x86、m68k、Power | [浮動小数点と十進演算](../architecture/arithmetic.md) |
| 予約付きロード／条件付きストア | MIPS、RISC-V、Power、ARM、AArch64、Alpha、LoongArch、OpenRISC、Hexagon、SuperH | [ゲストメモリ](../architecture/memory.md) |
| 特定アドレス経由の OS 呼出し | PA-RISC（ゲートウェイページ）、x86-64（vsyscall）、IA-64（ゲートページ）、ARM（kuser helper） | [OS 層](../architecture/os-layer.md) |
| OS による命令補完 | m68k（Line-F 等）、VAX（サブセット補完）、Alpha（CALL_PAL）、MIPS、Power、ARM | [OS 層](../architecture/os-layer.md) |
| トランザクショナルメモリ | x86（TSX）、Power（HTM）、s390（TX）— 現行は常に失敗経路を返す | 各 ISA 文書 |
