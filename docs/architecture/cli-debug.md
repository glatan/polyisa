# CLI・トレース・GDB 接続・診断ログ

ツール層は `cli`・`trace`・`gdbstub` の 3 クレートと、基礎層の診断ログ `diag` で構成される。

## `polyisa` コマンド（`cli`）

`crates/cli/src/main.rs` が提供するサブコマンドは次の 3 つである。

| サブコマンド | 構文 | 機能 |
|---|---|---|
| `run` | `polyisa run [--cpu <ファミリ>:<モデル>[,+機能,-機能]] [--root <dir>] [--os <linux\|semihost>] [-g <ポート>] <バイナリ> [args...]` | ゲストプログラムを実行する。ELF・a.out・Wasm を自動判別し、環境変数 `POLYISA_JIT` で対応 ISA の JIT を有効化する |
| `cpus` | `polyisa cpus` | 有効なゲスト ISA の CPU モデル一覧と、タイミング宣言があるモデルの忠実度・エンジン・表名を表示する |
| `disasm` | `polyisa disasm <hex-word>` | 16 進の命令語を逆アセンブルする（現行は RISC-V のみ対応） |

### 現行 CLI の制約

- `--root` は現在 `aarch64`・`power`（ppc64）・`s390`（s390x）・`loongarch`・`openrisc`・`hexagon` の ELF、および `wasm`（プリオープン `/`）・`pdp11`（Unix V7）・`vax`（4.3BSD）・`semihost` で解釈する。他の ELF ISA では未対応エラーまたは一部未適用となる（[GAP-0002](../known-issues.md)）。
- `--os` は ELF 向けに `linux`（既定）と `semihost`（aarch64・arm・riscv のみ）を受け付ける。
- `cpus` の一覧表示には `m68k`・`pdp11`・`wasm` がまだ接続されていない（[実装状況](../status.md) 参照）。
- アセンブラサブコマンド（`asm`）、`cpus --group` 絞り込み、CLI オプションによるトレース・統計出力は未実装である。

## トレース（`trace`）

`trace` クレートは `engine::obs::Observer` を実装した `InsnTrace` を提供し、実行したステップを `format_step` でテキスト行へ整形・蓄積する。命令の逆アセンブル文字列は呼び出し側がクロージャで供給する。システムコールトレースの整形関数（`format_syscall`）は定義済みだが、実行経路への配線は未接続である（[GAP-0100](../known-issues.md)）。

## GDB 接続（`gdbstub`）

`polyisa run -g <ポート>` は `std::net` の TCP サーバを起動し、GDB リモートシリアルプロトコル（RSP）でクライアントの接続を待つ。

- **実装済みパケット**：`?`、`qSupported`、`qXfer:features:read:target.xml`、`g`/`G`、`p`/`P`、`m`/`M`、`c`/`s`、`Z0`/`z0`（ソフトウェアブレークポイントの表登録。ゲストメモリは書き換えない）、`k`、`D`、`H`、`vCont?` 等。
- **検証済み対象**：RISC-V（RV64 Linux ELF）。レジスタ記述（`x0`–`x31`・`pc`・`f0`–`f31`・`fcsr`）と `target.xml` 生成を `crates/gdbstub/src/riscv.rs` に持ち、`heavy_program_gdbstub` で `gdb` からの `break`・`continue`・`si`・レジスタ読み書き・逆アセンブル・`kill` を検証している。

### 現行の制限（[GAP-0100](../known-issues.md)）

- 対象は RISC-V の Linux ELF のみであり、他 ISA のレジスタ表・Semihosting 経路・非 ELF は未対応。
- ウォッチポイント（`Z2`–`Z4`）、複数スレッドの一覧・切替（常に 1 スレッドを返す）、シグナル種別ごとの停止報告、detach 後の継続実行、NAK（`-`）への再送、Ctrl-C（`0x03`）による非同期停止は未実装。

## 内部診断ログ（`diag`）

`diag` クレートは基礎層に置き、どのクレートからも依存できる最小限のログ出力を提供する。環境変数 `POLYISA_LOG` で出力対象とログ水準を制御し、標準エラー出力へ書き出す。
