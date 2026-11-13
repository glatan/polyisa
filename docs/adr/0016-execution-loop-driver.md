# ADR-0016：実行ループの駆動を engine に置き、ISA 別の step は呼び出し側に残す

- 状態：承認
- 日付：2026-11-15

## 背景

GAP-0007 のとおり、実行ループは `cli` にあった。`run_x86.rs` の `pub fn run`/`run_mode`（x86）、`run.rs` の `pub fn run`（RISC-V）、`run_mips.rs` の `pub fn run`（MIPS）がそれぞれフェッチから退出までを担い、`engine` には `Vcpu`/`VcpuRunner` の型だけがあり、ループの実装も `VcpuRunner` の実装もなかった。

設計は実行ループを `engine` に置く。一方で依存規則（[ワークスペース構成](../design/workspace.md)）は、`engine` が特定のゲスト ISA に依存することも、`guests/*` が `engine` に依存することも禁じる。`dispatch` や `fetch_len` のような命令の振り分けは `guests/x86` の `Insn` と `decode` を必要とするため、`engine` と `guests/*` のどちらにも置けない。両方を見えるクレートは `cli` と `os-linux` だけである。

## 決定

実行ループを二つに分ける。

1. 繰り返しと実行予算・退出の判定は `engine::run::run` に置く。1 命令ぶんの処理は、呼び出し側が `step` クロージャとして渡す。
2. フェッチ・解読・意味論とトラップ境界の解決は ISA ごとの `step` 実装（x86 は `cli` の `step_x86`、RISC-V は `step_rv`）が担う。x86 の `dispatch`/`fetch_len` が手でバイトを取り出している件は、ADR-0002 の ISADL で置き換えるかどうかの判断（GAP-0006・GAP-0015）まで cli に残す。
3. `Outcome`（実行結果）と `TrapHandler`/`TrapOutcome`（OS との境界）は `BareEnv` だけを触る汎用の型なので `engine::run` に移し、`os-linux` と `cli` は再エクスポートする。
4. `engine::run::StepRunner` を `VcpuRunner` の実装として提供する。実行予算はステップ数のみ受け付け、サイクル予算はタイミングモデルとの接続まで未実装とする。
5. MIPS の実行ループは遅延スロットと保留効果の構造が独自であり、o32 の syscall 処理の移管（GAP-0001）と同じ段階 5 で行う。

## 帰結

- `cli` は `run`/`run_mode` の薄い入口（PC の初期値、アドレス幅のマスク、スレッド切り替えの初回呼び出し）と `step_*`・`dispatch`・ELF ロードを持つ。ループの繰り返しと退出判定は `engine` にある。
- `os-linux` の `TrapHandler`/`TrapOutcome` は `engine::run` の定義を再エクスポートする。`os-linux` 側の実装は変わらない。
- `Outcome` は `Exit(u64)`、`Unimplemented { pc: u64, word: u128 }`、`StepLimit { pc: u64 }`、`Deadlock` に統一した。x86 側は `eip: u32` を `pc: u64` に、`Exit(u32)` を `Exit(u64)` に合わせた。
- `Stop` に `Exit(u64)` と `Deadlock` を加えた。`Stop::Syscall`（トラップごとに退出する型）はブロック化した実行ループの段階で使う設計であり、現行の駆動はトラップを `step` の内側で解決する。
