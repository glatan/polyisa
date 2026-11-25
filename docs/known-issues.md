# 横断的な未実装・暫定課題

この文書は、複数の ISA やクレートにまたがる未実装機能と暫定実装を一箇所で管理する。各 ISA 固有の簡略化や未対応命令は、ここには置かず [対応 ISA 一覧](guests/README.md) 配下の各 ISA 文書に記録する。

## 区分と検査規則

- **未着手**：実装がまだない横断機能。コード注記は任意。
- **暫定**：設計上の暫定実装・部分実装で動いている箇所。コード中に 1 箇所以上の `// Gap: GAP-NNNN`（`Taskfile.yml`・`.config/*.toml` は `# Gap: GAP-NNNN`）注記を必須とする。
- 解消した項目は行を削除し、ID は再利用しない。

`task check`（`tools/devtool`）は、ID の書式と一意性、区分の妥当性、関連文書リンクの実在、参照資料 ID の実在、コード注記との一致、および「暫定」行にコード注記が存在することを機械的に検査する。

## 課題一覧

| ID | 関連文書 | 内容 | 区分 | 解消の条件 |
|---|---|---|---|---|
| GAP-0002 | [OS 層](architecture/os-layer.md) | 仮想ファイルシステムの完全な名前空間閉じ込めが全 ABI に揃っていない。x86 等の `openat` はホストパスへ直接アクセスし、`/proc/self/maps`・`/proc/cpuinfo`・`/dev` の統一合成もない | 暫定 | 仮想カーネル側でゲストルートと `/proc`・`/dev` の合成を統一実装し、全 Linux ABI から利用する |
| GAP-0009 | [浮動小数点と十進演算](architecture/arithmetic.md) | Berkeley TestFloat のベクタを生成しておらず、`heavy_conformance_testfloat` は `.testdata/testfloat` がなければ成功で戻る。現状の検証はホスト演算との差分（`heavy_diff_host`）による | 暫定 | SRC-SOFTFLOAT3 から TestFloat ベクタを生成し、`heavy_conformance_testfloat` で比較する（TEST-TESTFLOAT） |
| GAP-0010 | [テストガイド](guides/testing.md) | `heavy_conformance_rv64ui` は riscv-tests の RV32/RV64 ユーザーモード対象を実行するが、`heavy_conformance_riscv_tests` は riscv-arch-test の存在確認に留まり、ACT4 形式を含む実行ハーネスがない | 暫定 | riscv-arch-test（ACT4 形式を含む）のユーザーモード対象を実行するハーネスを実装する |
| GAP-0012 | [ワークスペース構成](architecture/workspace.md) | 依存規則の検査（`devtool`）が `cargo metadata` を使わず `Cargo.toml` の `[dependencies]` のみを読むため、`build-dependencies`（`isagen`）を検査していない | 暫定 | 検査を `build-dependencies` 対応に拡張するか、検査対象を `[dependencies]` 限定として仕様を確定する |
| GAP-0021 | [テストガイド](guides/testing.md) | `task status` は ISA・OS・テストバイナリ有無を集計するが、命令単位でどのテスト層を通過したかの網羅集計は生成しない | 未着手 | `task status` または専用レポートで命令×テスト層の網羅状況を生成できるようにする |
| GAP-0023 | [ISA 記述とコード生成](architecture/isadl.md) | `isagen` の生成物が一部未完。デコーダは線形比較（決定木・バイト表なし）、意味論ディスパッチは手書き `match`、`map` 経路で `disasm_word` が命令を返さず、属性表・レジスタ記述表・実行モード表を生成していない | 暫定 | 決定木／バイト表デコーダ、意味論ディスパッチ、`map` 経路逆アセンブル、属性・レジスタ・実行モード表の生成を実装する |
| GAP-0024 | [命令意味論・実行エンジン・JIT](architecture/execution.md) | OS パーソナリティへのトラップ境界が二系統に分かれている（他 ISA は `engine::run::TrapHandler`、RISC-V は `cli` 独自の `EcallHandler` 変換層） | 暫定 | RISC-V の `EcallHandler` を廃止し、トラップ境界を `TrapHandler`（または統一的な退出表現）へ一本化する |
| GAP-0026 | [OS 層](architecture/os-layer.md) | シグナルの保留・マスク・配送が `os-linux::x86` に閉じている。x86-64/i386 の自分宛て rt フレーム配送、CPU 例外からの同期シグナル変換、既定動作終了はあるが、他スレッド配送、タイマ由来シグナル、`sigaltstack`、x32 専用フレーム、i386 `fpstate`、拡張 xstate を含むフレームは未実装 | 暫定 | シグナルの汎用機構を `kernel` へ移管し、他スレッド配送・`sigaltstack`・各 ABI の正確なフレームを実装する |
| GAP-0027 | [CPU モデルとバージョン](architecture/cpu-models.md) | 挙動パラメータとバックエンドの一部が未接続。`Backend::call<Helper>` が `Unimplemented`、`Backend::timing_hint` が空実装、`--cpu` の `param=値` 上書き構文、`sem match param.X` のデコード時切替、`guest::FeatureSet`/`CpuModel` と `CpuSel` の接続が残る | 暫定 | `call`・`timing_hint` の配線、`--cpu param=値`、`sem match` のデコード時切替、`guest` 共通型との接続を実装する |
| GAP-0028 | [命令意味論・実行エンジン・JIT](architecture/execution.md) | `engine` のブロック・ジャンプキャッシュと `mem` のソフトウェア TLB が型定義のみで実行ループに未接続。1 命令ごとの線形デコードとページ表走査を繰り返しており、自己書き換えコード検出とブロック無効化もない | 未着手 | ブロックキャッシュ・ソフトウェア TLB・自己書き換えコード無効化を実行経路に接続し、`task bench` で効果を確認する |
| GAP-0030 | [テストガイド](guides/testing.md) | 実行差分テストの残件。x86 は APX map4 の reg-direct/メモリ NDD/NF/NCI 形、CFCMOV 条件付きストア、PUSH2/POP2、AMX-INT8 基本列を SDE 差分へ追加済みで、RV64I/M/A/C・幅違いロード・分岐/JAL を使うプログラムを QEMU user-mode と比較する経路もある。ただし、APX の disp32 ベースや例外系、AMX の広い形状・他拡張、QEMU 差分は F/D/CSR や他 ISA をカバーしていない | 暫定 | APX の例外系、AMX の形状バリエーションを SDE 差分コーパスへ追加し、QEMU 差分コーパスを F/D/CSR と他 ISA へ広げる |
| GAP-0031 | [テストガイド](guides/testing.md) | 同一入力の 2 回実行で命令トレース・仮想時間・出力の一致を確認する決定性テスト（複数ゲストスレッドを含む）がない | 未着手 | 複数ゲストスレッドを含むプログラムで `heavy_determinism_*` テストを実装する |
| GAP-0032 | [OS 層](architecture/os-layer.md) | `os-linux` の ABI 引数抽出・戻り値書き戻しと状態構造体が ABI ごとに重複している（例：`x86::SysCtx` と `x86::sys::Linux` が x86_32/x86_64 固有） | 暫定 | ABI ごとの引数・戻り値変換を共通トレイト化し、システムコール状態を ABI 非依存に整理する |
| GAP-0033 | [ゲストメモリ](architecture/memory.md) | ファイル裏付け `mmap` の共通実装がなく、匿名でない要求を拒否または事前読み込みで近似している。遅延読み込み、`MAP_SHARED` のページフレーム共有、`msync`/`munmap`/終了時の書き戻しが未着手 | 未着手 | `MAP_PRIVATE` の遅延読み込みと `MAP_SHARED` の共有・書き戻しを `mem` と `kernel` に実装する |
| GAP-0034 | [OS 層](architecture/os-layer.md) | 一部 Linux ABI で `munmap` が写像を解除せず 0 を返し、`brk` が要求値ではなくページ整列値を保持する。aarch64 の `do_brk` は既存写像を確認せず上書きしうる | 暫定 | `munmap` による写像解除と `brk` の正確なブレーク追跡および衝突検査を全 Linux ABI に揃える |
| GAP-0091 | [タイミングモデル](architecture/timing.md) | `timing::cache` に立ち退きラインの汚れと書き戻し時間がなく、`timing::branch` の BTB/IJTP は飛び先を保持せず、RAS の戻りアドレスは `pc + 4` 固定の近似 | 暫定 | 較正誤差として問題になった時点で、キャッシュの書き戻し時間と BTB/IJTP の飛び先保持・可変長 RAS を追加する |
| GAP-0092 | [タイミングモデル](architecture/timing.md) | `timing::ooo` が再帰式近似であり、サイクル単位の資源仲裁、レジスタリネーム（WAW/WAR 偽依存）、発行順キャッシュ状態変化、誤予測経路の実行効果を持たない | 暫定 | `heavy_timing_ooo` 等の較正で宣言誤差を超える対象が現れた時点で、該当資源のモデルを詳細化する |
| GAP-0099 | [ホスト抽象化](architecture/host.md) | wasm32（WASI）ホストでは Unix ソケット FFI が使えずホストソケット系 syscall がエラーになる。ホスト fd 待ちもスリープ近似で、`wasi:sockets` への接続は未着手 | 未着手 | wasm ホストでネットワーク syscall を要するテストが現れた時点で、`wasi:sockets`（wasip2/p3）を接続する |
| GAP-0100 | [CLI・トレース・GDB 接続](architecture/cli-debug.md) | `gdbstub` が RISC-V Linux ELF の最小集合に限られる。ウォッチポイント、複数スレッド一覧・切替、シグナル停止報告、他 ISA レジスタ表、detach 継続、NAK 再送、非同期割込み（`0x03`）、および `trace::format_syscall` 配線が未実装 | 未着手 | ウォッチポイント用のメモリアクセス観測点、複数スレッド・シグナル報告、他 ISA のレジスタ表を追加する |
| GAP-0101 | [CPU モデルとバージョン](architecture/cpu-models.md) | aarch64（fp/asimd/lse）・arm（v7）・s390（zarch/long-disp/ext-imm/dfp/hfp）・hexagon（v5–v79）で世代・拡張の機能旗が命令の `when` 条件に接続されておらず、CPU モデル間で命令の利用可否が変わらない。ISA ごとの具体的な状態は各ゲスト文書を参照 | 暫定 | 各 ISA の機能旗を命令の `when` 条件に接続し、モデル間で命令の利用可否が変わることを bare テストで検証する |

## 設計判断が未確定の事項

以下は実装上の致命的な欠陥ではないが、将来の方針整理が残っている事項である。

- `--root` 指定時の実行ファイルパス解釈（現行のゲスト名前空間解決を全 ISA の正式規約とするか）
- 重いオラクルテストの命名統一（`heavy_oracle_llvm` の共通名か `heavy_oracle_<isa>` の個別名か）
- `polyisa-host` への OS 依存 API 集約範囲（`os-linux` の `#[cfg(unix)]` 経路をどこまで `host` へ寄せるか）
- MIPS Release 6 コンパクト分岐（2R 形式 `rs > rt`）と `lui` の `rs` フィールドの厳格化可否
- `TEST-RISCV-ARCH-TEST` の ACT4（自己検査型 ELF）への移行対応
- `cli` の `polyisa cpus` への `m68k`・`pdp11`・`wasm` の追加
