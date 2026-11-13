# 設計との差の台帳

この文書は、設計文書が定める設計と現在の実装との差を一か所で管理する台帳である。設計文書は、実装の有無にかかわらず、採用している設計を書く。実装が設計と異なる箇所、設計どおりの実装がまだない箇所、判断により当面実装しない箇所は、この台帳にだけ書く。命令やシステムコールの実装の一覧は、この台帳には書かない。それらは `docs/status/` に生成する。

## 区分

| 区分 | 意味 | コードの注記 | 解消の条件 |
|---|---|---|---|
| 未着手 | 設計どおりに実装する予定で、まだ実装がない | 任意 | 必須 |
| 代替 | 設計と異なる方法で実装している（試作を含む） | 必須（1 か所以上） | 必須 |
| 対象外 | 判断により当面実装しない | 任意 | 必須。判断を記録した ADR（提案を含む）の番号を含める |

## 規則

1. 対象は、設計文書（ロードマップの段階の対象を含む）が定めるもののうち、段階 0 から 4 の範囲にあるものとする。区分が未着手の行は、完了条件の判定が満たされても残る欠落に限る。判定が未整備の完了条件の範囲で機能がまだないことと、段階 5 以降の機能がないことは書かない。
2. 一つの行は、設計文書の一つの節が定める一つの事柄に対応する。注記は複数の箇所に置いてよい。
3. 差を解消したら行を削除する。履歴は Git に残る。ID は再利用しない。
4. コードの注記は、Rust では `// Gap: GAP-0001`、`Taskfile.yml` と `.config/` の TOML では `# Gap: GAP-0001` と書く。注記は差がある箇所に置き、台帳の内容を書き写さない。
5. 判断を後で下す事項は「将来 ADR（未起票）」のように書かず、提案の状態の ADR を起票して、その番号を解消の条件に書く。

## 機械的な検査

`task check` は次のことを検査し、違反があれば失敗する。表の列の順序と書式を変えるときは、検査の実装も同じ変更で直す。

1. 各行の ID が `GAP-` と 4 桁の数字からなり、重複しない。
2. 区分が「未着手」「代替」「対象外」のいずれかである。
3. 解消の条件が空でない。そこに現れる完了条件の ID（`S1-2`、`SC-2` の形）、ADR の番号（`ADR-0014` の形）、台帳の ID（`GAP-0003` の形）、参照資料の台帳の ID（`SPEC-` などで始まるもの）がすべて実在する。区分が「対象外」の行は ADR の番号を含む。
4. 設計の列のリンク先のファイルが実在する。`#` 以降のアンカーは検査しない。
5. 成果物（`crates/`、`guests/`、`tools/` の Rust、`Taskfile.yml`、`.config/` の TOML）の注記に現れる ID がすべて台帳にある。走査から `target/` と `.testdata/` を除く。
6. 区分が「代替」の行には、注記が一つ以上ある。
7. 台帳の表と、ロードマップの完了条件の表が、それぞれ 1 行以上ある。

## 台帳

| ID | 設計 | 現在の実装 | 区分 | 解消の条件 |
|---|---|---|---|---|
| GAP-0001 | [ユーザーモード「構成」](design/user-mode.md#構成) | `kernel` はプロセス表（生成、fork、終了、wait の回収）を持つ。`os-linux` は番号表、`build_initial_stack`、終了ステータスの符号化と syscall の状態機械（x86 は `x86::sys::Linux`、RV64 は `rv64::sys::Linux`）を持ち、clone（プロセス）、execve、wait4 もそこで処理する。残るのは MIPS o32 の syscall 処理で、`crates/cli/src/run_mips.rs` の `o32_syscall` と `O32Io` にある | 代替 | 段階 5 の MIPS 本実装時に `os-linux` へ移す |
| GAP-0002 | [ユーザーモード「仮想ファイルシステム」](design/user-mode.md#仮想ファイルシステム) | ゲストのルートの割り当てはない。`openat` は絶対パスの文字列をホストのパスとして `std::fs` で開く。`/proc/self/exe` の合成は `readlink` と `readlinkat` だけで、`exe_path` が空でなければゲスト実行ファイルのホストパスを返す。`/proc/self/maps`、`/proc/cpuinfo`、`/dev` の合成はない。`/proc/self/fd/<fd>` はホストのそのパスを開く | 代替 | S1-1（条件に「ゲストのルートを使って」を含む） |
| GAP-0004 | [ホスト抽象化「必要なホストの機能」](design/host.md#必要なホストの機能) | x86_64 の statfs（137）と fstatfs（138）、i386 の statfs（99）、fstatfs（100）、statfs64（268）、fstatfs64（269）は番号表と `syscall_name` だけにあり、トラップ処理に分岐はない。処理しない番号は報告のあと `ENOSYS` を返して続ける。busybox の `df` は x86_64 の statfs（137）が `ENOSYS` になるため失敗扱いになる。i386 の到達経路は確かめていない | 対象外 | ADR-0014 |
| GAP-0005 | [開発作業とローカル検証「オラクルがない場合の扱い」](design/dev-workflow.md#オラクルがない場合の扱い) | `task test:full` は `cargo nextest run --profile full` だけで、オラクルとテストデータの有無を調べず、未実行の一覧も出さない。`heavy_abi_uapi`、`heavy_conformance_riscv_tests`、`heavy_conformance_rv64ui`、`heavy_conformance_testfloat`、`heavy_oracle_llvm` は、必要なデータやツールがないと成功で戻る。`heavy_diff_host`、`heavy_program_hello`、`heavy_program_dyn` に、その早期成功はない | 代替 | SC-2 |
| GAP-0006 | [ISA 記述言語（ISADL）「ファイルの配置」](design/isa-description.md#ファイルの配置) | ISADL のテキストの字句解析と構文解析はない。各 ISA の記述は `guests/<isa>/spec/*.rs` が `polyisa_isadl::Model` を組み立て、`build.rs` が `include!` する | 代替 | S4-2（構文を実装するか、Rust の組み立てを続けて ADR-0002 を置き換える ADR を起票するかを決める） |
| GAP-0007 | [実行エンジン「実行ループ」](design/execution-engine.md#実行ループ) | RISC-V の実行ループは `run.rs` の `pub fn run`、x86 の実行ループと命令の振り分けは `run_x86.rs` の `pub fn run` と `dispatch` にある。`engine` はブロックの表、インタプリタのバックエンド、裸実行環境の `step`、`Vcpu`、`VcpuRunner` トレイトを持つ。フェッチから退出までのループの実装はなく、`VcpuRunner` の実装もない | 代替 | S4-2 |
| GAP-0008 | [実行エンジン「観測点」](design/execution-engine.md#観測点) | `Observer` はない。`trace` は `format_step` と `format_syscall` だけを持ち、呼び出し元はない。`cli` は `polyisa-trace` に依存するが、命令トレースを出していない | 未着手 | 段階 1 の範囲の命令トレースを観測点で実装する |
| GAP-0009 | [浮動小数点と十進演算「検証」](design/floating-point.md#検証) | TestFloat のベクタは生成していない。比較は `heavy_diff_host` がホストの浮動小数点演算との差分で行う。`heavy_conformance_testfloat` は `.testdata/testfloat` がなければ成功で戻る。`SRC-SOFTFLOAT3` は台帳で確認済みであり、用途は `X` である | 代替 | TestFloat の生成器を SRC-SOFTFLOAT3 でビルドしてベクタを得、`heavy_conformance_testfloat` で比較する（TEST-TESTFLOAT） |
| GAP-0010 | [検証戦略「5. 適合テストスイート」](design/testing.md#5-適合テストスイート) | `heavy_conformance_riscv_tests` は `.testdata` に riscv-tests と riscv-arch-test のディレクトリがあることだけを見る。なければ成功で戻る。あっても中のテストは実行しない。UDB 構成、rvmodel のマクロ、リンカスクリプト、期待値の生成用の Sail モデルを使うハーネスはない | 未着手 | S1-2 |
| GAP-0011 | [検証戦略「7. プログラム単位のテスト」](design/testing.md#7-プログラム単位のテスト) | 動的リンクの検証は `heavy_program_dyn` の合成 ELF（interp と app）で行う。実 libc の動的リンカでは実行していない。`BIN-DISTRO` は BusyBox 1.35.0 の静的リンクのバイナリであり、libc を含む sysroot ではない | 未着手 | S1-1（libc を含む配布物のバイナリを台帳に登録し、所有者が確認する） |
| GAP-0012 | [ワークスペース構成「依存規則」](design/workspace.md#依存規則) | 依存規則の検査は `cargo metadata` を使わず各 `Cargo.toml` を直接読み、`[dependencies]` だけを見る。設計の依存規則が対象とする build-dependency（`isagen`）を検査しない | 代替 | 検査を設計に合わせるか、設計文書の記述を改める |
| GAP-0014 | [ISA 記述言語（ISADL）「形式と命令」](design/isa-description.md#形式と命令) | `hexmin.rs` と `ia64min.rs` のパターンは、上位 8 ビットで命令を区別する簡略化であり、実命令のエンコーディングではない | 代替 | 段階 5 以降の本格的な実装で実際のエンコーディングに置き換える |
| GAP-0015 | [ISA 記述言語（ISADL）「オペコード表」](design/isa-description.md#オペコード表)、[同「フィールドとオペランド」](design/isa-description.md#フィールドとオペランド) | `x86min.rs` はオペコード表も ModRM/SIB のフックも使わず、レジスタ、mod、SIB の有無と変位の長さごとに命令を列挙する。ModRM と SIB のバイトの取り出しは `run_x86.rs` の `dispatch` が行う | 代替 | S4-2 |
| GAP-0021 | [検証戦略「テストの網羅の記録」](design/testing.md#テストの網羅の記録) | `task status` は命令の記述、完了条件の判定、設計との差を生成する。命令がどの層でテストされたかは生成しない | 未着手 | `task status` が命令と層の網羅を生成する |
| GAP-0022 | [ロードマップ「段階 4：x86」](design/roadmap.md#段階-4x86) | BIN-DISTRO-I386（i686-linux-musl 1.35.0）の基本コマンド群は `heavy_program_busybox_i386` で通る。`--list` 全アプレット網羅は x86_64 版テストと同等には到達していない | 代替 | 段階 4 完遂までにアプレット網羅率を確認し、不足があれば命令形を追加する |
