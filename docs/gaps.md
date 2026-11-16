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
| GAP-0002 | [ユーザーモード「仮想ファイルシステム」](design/user-mode.md#仮想ファイルシステム) | ゲストのルートの割り当てはない。`openat` は絶対パスの文字列をホストのパスとして `std::fs` で開く。`/proc/self/exe` の合成は `readlink` と `readlinkat` だけで、`exe_path` が空でなければゲスト実行ファイルのホストパスを返す。`/proc/self/maps`、`/proc/cpuinfo`、`/dev` の合成はない。`/proc/self/fd/<fd>` はホストのそのパスを開く | 代替 | S1-1（条件に「ゲストのルートを使って」を含む） |
| GAP-0004 | [ホスト抽象化「必要なホストの機能」](design/host.md#必要なホストの機能) | x86_64 の statfs（137）と fstatfs（138）、i386 の statfs（99）、fstatfs（100）、statfs64（268）、fstatfs64（269）は番号表と `syscall_name` だけにあり、トラップ処理に分岐はない。処理しない番号は報告のあと `ENOSYS` を返して続ける。busybox の `df` は x86_64 の statfs（137）が `ENOSYS` になるため失敗扱いになる。i386 の到達経路は確かめていない | 対象外 | ADR-0014 |
| GAP-0006 | [ISA 記述言語（ISADL）「ファイルの配置」](design/isa-description.md#ファイルの配置) | 記述面は `guests/<isa>/spec/*.rs` が `polyisa_isadl::Model` を組み立てる Rust DSL を正規とし、`.isadl` テキストの構文解析は実装しない。テキスト文法はフロントエンドの設計として文書に残る | 対象外 | ADR-0017 |
| GAP-0008 | [実行エンジン「観測点」](design/execution-engine.md#観測点) | `Observer` はない。`trace` は `format_step` と `format_syscall` だけを持ち、呼び出し元はない。`cli` は `polyisa-trace` に依存するが、命令トレースを出していない | 未着手 | 段階 1 の範囲の命令トレースを観測点で実装する |
| GAP-0009 | [浮動小数点と十進演算「検証」](design/floating-point.md#検証) | TestFloat のベクタは生成していない。比較は `heavy_diff_host` がホストの浮動小数点演算との差分で行う。`heavy_conformance_testfloat` は `.testdata/testfloat` がなければ成功で戻る。`SRC-SOFTFLOAT3` は台帳で確認済みであり、用途は `X` である | 代替 | TestFloat の生成器を SRC-SOFTFLOAT3 でビルドしてベクタを得、`heavy_conformance_testfloat` で比較する（TEST-TESTFLOAT） |
| GAP-0010 | [検証戦略「5. 適合テストスイート」](design/testing.md#5-適合テストスイート) | `heavy_conformance_riscv_tests` は `.testdata` に riscv-tests と riscv-arch-test のディレクトリがあることだけを見る。なければ成功で戻る。あっても中のテストは実行しない。UDB 構成、rvmodel のマクロ、リンカスクリプト、期待値の生成用の Sail モデルを使うハーネスはない | 未着手 | S1-2 |
| GAP-0011 | [検証戦略「7. プログラム単位のテスト」](design/testing.md#7-プログラム単位のテスト) | x86 では動的リンクの検証は `heavy_program_dyn` の合成 ELF（interp と app）で行い、`BIN-DISTRO` は BusyBox 1.35.0 の静的リンクのバイナリであり libc を含む sysroot ではない。aarch64 では `BIN-DISTRO-AARCH64`（Alpine minirootfs、musl + BusyBox、動的）を PT_INTERP 経路で実 libc の動的リンカのまま `--root` 実行する（`heavy_program_aarch64`）。BIN-DISTRO-AARCH64 の台帳の確認は未だ | 未着手 | S1-1（libc を含む配布物のバイナリを台帳に登録し、所有者が確認する） |
| GAP-0012 | [ワークスペース構成「依存規則」](design/workspace.md#依存規則) | 依存規則の検査は `cargo metadata` を使わず各 `Cargo.toml` を直接読み、`[dependencies]` だけを見る。設計の依存規則が対象とする build-dependency（`isagen`）を検査しない | 代替 | 検査を設計に合わせるか、設計文書の記述を改める |
| GAP-0014 | [ISA 記述言語（ISADL）「形式と命令」](design/isa-description.md#形式と命令) | `hexmin.rs` と `ia64min.rs` のパターンは、上位 8 ビットで命令を区別する簡略化であり、実命令のエンコーディングではない | 代替 | 段階 5 以降の本格的な実装で実際のエンコーディングに置き換える |
| GAP-0015 | [ISA 記述言語（ISADL）「オペコード表」](design/isa-description.md#オペコード表)、[同「フィールドとオペランド」](design/isa-description.md#フィールドとオペランド) | `x86min.rs` はレジスタ、mod、SIB の有無と変位の長さごとに命令を列挙する方針を採る。オペコード表と ModRM/SIB フックの機構は、二番目の可変長 ISA の実装時か列挙の複製が主な費用になったときに作る。命令長の判定（`fetch_len`）とオペランドの取り出し（`dispatch`）は `cli` の `step_x86` が担う | 対象外 | ADR-0018 |
| GAP-0021 | [検証戦略「テストの網羅の記録」](design/testing.md#テストの網羅の記録) | `task status` は命令の記述、完了条件の判定、設計との差を生成する。命令がどの層でテストされたかは生成しない | 未着手 | `task status` が命令と層の網羅を生成する |
| GAP-0022 | [ロードマップ「段階 4：x86」](design/roadmap.md#段階-4x86) | BIN-DISTRO-I386（i686-linux-musl 1.35.0）の基本コマンド群は `heavy_program_busybox_i386` で通る。`heavy_program_i386_applet_probe` による全アプレット走査で整数命令の欠落は解消済み。残りの未到達は x87 FPU（範囲外）と実行時間制限のみ | 代替 | `heavy_program_i386_applet_probe` による全アプレット走査で、`Outcome::Unimplemented` に達したアプレットが x87 系命令と実行時間制限のものだけであることを所有者が確認し、段階 4 の完了タグのメッセージに記録する（SC-2） |
| GAP-0023 | [ISA 記述言語（ISADL）「生成物」](design/isa-description.md#生成物) | 生成の一部が殻のまま。`encode_*` は全件 `None` を返し、`disasm` はオペランドの穴を置換せず雛形を返す。`ops_*` は生成するが実行側の振り分けが使わず、`cli` がビットを手で取り出している。意味論への呼び出しの生成はない。デコーダは全命令との線形比較で、決定木とバイト表はない。`MODEL_DEFS`/`FEATURE_DEFS`/`FEAT_BITS` は生成し `--cpu` が使うが、属性、オペランドの読み書き、レジスタ記述、実行モードの表は生成しない | 代替 | 生成物を設計の一覧にそろえる（エンコーダ、オペランド入りの逆アセンブラ、意味論への振り分け、決定木、属性・レジスタ記述・実行モードの表） |
| GAP-0024 | [実行エンジン「実行ループ」](design/execution-engine.md#実行ループ) | OS パーソナリティへのトラップの受け渡しが二系統ある。x86 は `engine::run::TrapHandler`（`handle_trap` → `TrapOutcome`）、RISC-V は `cli` 独自の `EcallHandler`（`handle_ecall` → `EcallOutcome`）で、後者は os-linux の `TrapOutcome` への変換層にすぎない。`step` と `dispatch` が `cli` にある形は ADR-0016 の確定どおり | 代替 | トラップの境界を一つの形に揃える。WASI のホスト関数呼び出しを `Stop::Syscall` と同じ退出として扱う設計に合わせ、トラップを退出として表す方向で検討する |
| GAP-0025 | [ユーザーモード「ファイル記述子」](design/user-mode.md#ファイル記述子) | `kernel::FdTable` は `std::fs::File` を直接保持し、fd が指す対象を一つの型で表さない。パイプは別の `PipeTable` で管理し、fd 番号の空間は `extra_free` コールバックで二つの表の間を調整している。ソケット、`eventfd`、`timerfd`、`signalfd`、`epoll`、`memfd`、端末を入れる場所がない | 代替 | fd の対象を多態な型で表す表に作り替え、パイプをその一種にする |
| GAP-0026 | [ユーザーモード「シグナル」](design/user-mode.md#シグナル) | シグナルの保留、マスク、ハンドラの選択、配送の機構はない。`rt_sigaction`、`rt_sigprocmask`、`rt_sigreturn`、`sigaltstack` は受理して成功を返すだけで、`kill` は `ProcessTable` の `signal` 欄に死因を記録するだけである。ハンドラの起動、シグナルフレーム、`sigreturn` での復元、CPU 例外からのシグナルへの変換はいずれもない | 代替 | ゲストシグナルの保留・マスク・配送と、ゲスト ABI ごとのシグナルフレームを実装する |
| GAP-0027 | [CPU モデルとバージョンの表現「挙動パラメータ」](design/cpu-models.md#挙動パラメータ) | `--cpu <ファミリ>:<モデル>[,+機能,-機能]` は生成した `MODEL_DEFS`/`FEATURE_DEFS`/`FEAT_BITS` から `isadl::select::resolve` で解決し、`decode_model_ex` の `feats` に届く。残るのは挙動パラメータと識別情報。`Backend::param` は panic、`call<Helper>` は `Unimplemented` を返し、`timing_hint` は空の実装で、呼び出し側も存在しない。CPUID は機能からの導出ではなく固定の最小形である。`guest` の `FeatureSet`/`CpuModel` は `CpuSel` と繋がっていない | 代替 | 挙動パラメータの宣言と `param`/`call` の配線、機能から CPUID 等の識別情報への導出を繋げる |
| GAP-0028 | [実行エンジン「ブロックとデコードキャッシュ」](design/execution-engine.md#ブロックとデコードキャッシュ) | ブロック、ジャンプキャッシュ、デコード済みステップの表は型が定義されているだけで、実行ループは使っていない。`mem` のソフトウェア TLB も実行経路に繋がっておらず、`Vcpu.tlb` は保持するだけである。ループは 1 命令ずつページ表の走査と線形デコードを繰り返す。自己書き換えコードの検出とブロックの無効化もない | 未着手 | ブロックとソフトウェア TLB を実行経路に繋ぎ、`task bench` で差を計測する |
| GAP-0029 | [ISA 記述言語（ISADL）「実行モード」](design/isa-description.md#実行モード) | x86 の実行モードは `x86map.rs` が `m64`/`o16`/`o32`/`a16`/`a32`/`a64` として宣言し、`decode_map` の入力になった。実行ループは内部で 16/32/64 のモード値を持ち、`run_m16` は実モード（セレクタ<<4 のセグメント基底・SP の 16 ビット化・フェッチの CS:IP 合成）を map 経路のみで実行する。残りは、旧の列挙経路が `cli` の `is64` の真偽で持つことと、`CpuState.eip` が `u32` で x86-64 のプログラムカウンタの上位 32 ビットを保持しないことである | 代替 | 実行モードを ISADL の宣言として表し、x86-64 のプログラムカウンタを完全な幅で持つ |
| GAP-0030 | [検証戦略「8. 実行の差分テスト」](design/testing.md#8-実行の差分テスト) | x86-64 のホスト CPU との実行の差分テストはない（`heavy_diff_host` は `softfloat` の比較のみ）。ロードマップの段階 4 は「ホストの CPU との実行の差分テスト」を内容に挙げる。オラクルの QEMU は台帳に登録済みだが未導入である | 未着手 | 命令列を乱択で生成し、polyisa とホストの CPU で実行して CPU 状態を比較する `heavy_diff_*` のテストを置く |
| GAP-0031 | [検証戦略「11. 決定性のテスト」](design/testing.md#11-決定性のテスト) | 決定性のテストはない。同じプログラムの 2 回実行で命令トレース・仮想時間・出力が一致することと、複数ゲストスレッドを使うプログラムでの決定性は検証していない | 未着手 | 複数ゲストスレッドを含むプログラムで、層 11 のテストを `heavy_determinism_*` に置く |
| GAP-0032 | [ユーザーモード「ゲスト ABI」](design/user-mode.md#ゲスト-abi) | `os-linux` で ABI 間に共有できる形が整っていない。`x86::SysCtx` は x86 固有の `Gpr` で引数レジスタを表し、`x86::sys::Linux` は x86_32 と x86_64 の状態を一つの構造体に持つ。syscall の振り分けは「番号から名前への match」と「名前から関数ポインタへの表」の二段の解決で、ABI を足すたびに複写が要る | 代替 | 引数の取り出しと結果の書き戻しを ABI ごとの関数として表し、syscall の状態を ABI に依らない形にする |
| GAP-0033 | [ゲストメモリ「ファイルの写像」](design/memory.md#ファイルの写像) | ファイル backed の `mmap` は実装がなく、`sys_mmap` は匿名でない要求を `EINVAL` で拒否する。ページの遅延読み込み、`MAP_SHARED` のページフレーム共有、`msync`・`munmap`・終了時の書き戻しはいずれもない | 未着手 | `MAP_PRIVATE` の遅延読み込みと `MAP_SHARED` の共有・書き戻しを実装する |
| GAP-0034 | [ユーザーモード「Linux のシステムコールの実装の段階」](design/user-mode.md#linux-のシステムコールの実装の段階) | `sys_munmap` は写像を解除せず 0 を返し、解放域は写像のまま残る（再利用もしない）。`sys_brk` は要求値ではなくページ整列したヒープ末尾をブレークとして記録・返却する。匿名の `sys_mmap` は `mmap_base` から昇順に割り当て、`brk` のヒープとは別空間とする。aarch64 の `do_brk` は既存写像の確認なしに `mem.map` で上書きするため、ヒープ成長域の先行 mmap を潰し得る | 代替 | `munmap` が写像を解除し、`brk` が要求したブレークを保持する実装にする |
