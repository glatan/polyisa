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
| GAP-0026 | [ユーザーモード「シグナル」](design/user-mode.md#シグナル) | x86-64 では `rt_sigaction`/`rt_sigprocmask`/`rt_sigpending`/`rt_sigreturn` とハンドラ表・マスク・保留集合があり、自分宛ての `kill`/`tgkill` がハンドラ登録済みの番号を保留に積み、`after_step` で rt フレームを作って配送する。フレームの fpstate は FXSAVE 配置を使う。一方、i386 のフレーム、CPU 例外からのシグナル変換、SIGKILL 以外の既定動作による終了、他プロセス/他スレッドへの配送、タイマ由来のシグナル、`sigaltstack` はない。シグナル汎用の機構はカーネルではなく `os-linux` の `Linux` 状態が持つ | 代替 | ゲストシグナルの保留・マスク・配送の残り（例外変換・i386 フレーム・既定動作・他者への配送）と、汎用機構のカーネルへの移管を実装する |
| GAP-0027 | [CPU モデルとバージョンの表現「挙動パラメータ」](design/cpu-models.md#挙動パラメータ) | `--cpu <ファミリ>:<モデル>[,+機能,-機能]` は生成した `MODEL_DEFS`/`FEATURE_DEFS`/`FEAT_BITS` から `isadl::select::resolve` で解決し、`decode_model_ex` と `decode_map` の `feats` に届く。識別情報は `ModelDef.ident`（親から継承するキーと値）と `IDENT_BITS`（機能→CPUID リーフ/レジスタ/ビット）で表し、`cpuid::derive` が機能集合からリーフ値を導出して `CpuState.cpuid` に置く。`when` の機能旗は列挙・マップ双方のデコードで検査される。挙動パラメータは `Model::param`（`ParamKind` の Bool/Enum/Int）で宣言し、既定値・列挙の列挙子・モデルの上書き値を検査する。生成コードは `Params` 構造体・列挙子定数・`DEFAULT_PARAMS`・親連鎖で解決した `model_params`・`Backend::param` のマーカー型・`install_params` を出す。`InterpBackend`/`IrBackend` は `Param` の型を鍵にした値表を持ち、`set_param` で流し込み `param` で読む。IR では記録時に定数になるので枝が畳まれる。最初の消費側は `bsf_zero_input`（BSF/BSR の入力 0 の宛先）。残るのは `call<Helper>`（`Unimplemented` のまま）、`--cpu` の `param=値` 構文、`timing_hint`（空の実装）、命令全体を差し替える `sem match param.X` のデコード時切り替え（規則 2）、`guest` の `FeatureSet`/`CpuModel` と `CpuSel` の接続 | 代替 | `call`/`timing_hint` の配線、`--cpu` のパラメータ上書き、`sem match` のデコード時切り替え、`FeatureSet`/`CpuModel` と `CpuSel` の接続 |
| GAP-0028 | [実行エンジン「ブロックとデコードキャッシュ」](design/execution-engine.md#ブロックとデコードキャッシュ) | ブロック、ジャンプキャッシュ、デコード済みステップの表は型が定義されているだけで、実行ループは使っていない。`mem` のソフトウェア TLB も実行経路に繋がっておらず、`Vcpu.tlb` は保持するだけである。ループは 1 命令ずつページ表の走査と線形デコードを繰り返す。自己書き換えコードの検出とブロックの無効化もない | 未着手 | ブロックとソフトウェア TLB を実行経路に繋ぎ、`task bench` で差を計測する |
| GAP-0029 | [ISA 記述言語（ISADL）「実行モード」](design/isa-description.md#実行モード) | x86 の実行モードは `x86map.rs` が `m64`/`o16`/`o32`/`a16`/`a32`/`a64` として宣言し、`decode_map` の入力になった。実行ループは内部で 16/32/64 のモード値を持ち、`run_m16` は実モード（セレクタ<<4 のセグメント基底・SP の 16 ビット化・フェッチの CS:IP 合成）を map 経路のみで実行する。残りは、旧の列挙経路が `cli` の `is64` の真偽で持つことと、`CpuState.eip` が `u32` で x86-64 のプログラムカウンタの上位 32 ビットを保持しないことである | 代替 | 実行モードを ISADL の宣言として表し、x86-64 のプログラムカウンタを完全な幅で持つ |
| GAP-0030 | [検証戦略「8. 実行の差分テスト」](design/testing.md#8-実行の差分テスト) | `heavy_diff_host` でホスト CPU との GPR・RFLAGS・スクラッチの差分、`heavy_diff_sde` で Intel SDE（`-future`）との REX2/EGPR 命令の差分を実施する。残る差は (a) map4（NDD・昇格形）は両側とも実行できず未検証、(b) AMX 等他拡張の SDE 差分、(c) オラクルの QEMU は台帳に登録済みだが未導入である | 代替 | 残る (a) は意味論実装後にコーパスへ追加、(b) は拡張ごとのコーパスを追加、(c) QEMU を導入して `heavy_oracle_*`/`heavy_diff_*` に接続する |
| GAP-0031 | [検証戦略「11. 決定性のテスト」](design/testing.md#11-決定性のテスト) | 決定性のテストはない。同じプログラムの 2 回実行で命令トレース・仮想時間・出力が一致することと、複数ゲストスレッドを使うプログラムでの決定性は検証していない | 未着手 | 複数ゲストスレッドを含むプログラムで、層 11 のテストを `heavy_determinism_*` に置く |
| GAP-0032 | [ユーザーモード「ゲスト ABI」](design/user-mode.md#ゲスト-abi) | `os-linux` で ABI 間に共有できる形が整っていない。`x86::SysCtx` は x86 固有の `Gpr` で引数レジスタを表し、`x86::sys::Linux` は x86_32 と x86_64 の状態を一つの構造体に持つ。syscall の振り分けは「番号から名前への match」と「名前から関数ポインタへの表」の二段の解決で、ABI を足すたびに複写が要る | 代替 | 引数の取り出しと結果の書き戻しを ABI ごとの関数として表し、syscall の状態を ABI に依らない形にする |
| GAP-0033 | [ゲストメモリ「ファイルの写像」](design/memory.md#ファイルの写像) | ファイル backed の `mmap` は実装がなく、`sys_mmap` は匿名でない要求を `EINVAL` で拒否する。ページの遅延読み込み、`MAP_SHARED` のページフレーム共有、`msync`・`munmap`・終了時の書き戻しはいずれもない | 未着手 | `MAP_PRIVATE` の遅延読み込みと `MAP_SHARED` の共有・書き戻しを実装する |
| GAP-0034 | [ユーザーモード「Linux のシステムコールの実装の段階」](design/user-mode.md#linux-のシステムコールの実装の段階) | `sys_munmap` は写像を解除せず 0 を返し、解放域は写像のまま残る（再利用もしない）。`sys_brk` は要求値ではなくページ整列したヒープ末尾をブレークとして記録・返却する。匿名の `sys_mmap` は `mmap_base` から昇順に割り当て、`brk` のヒープとは別空間とする。aarch64 の `do_brk` は既存写像の確認なしに `mem.map` で上書きするため、ヒープ成長域の先行 mmap を潰し得る | 代替 | `munmap` が写像を解除し、`brk` が要求したブレークを保持する実装にする |
| GAP-0035 | [CPU モデルとバージョンの表現「機能」](design/cpu-models.md#機能) | x87（ESC D8-DF）の命令は `fpu` 機能でゲートしない。FPU の無い 8088 が ESC を #UD でなく無視するのでデコード不能にすると実モードが壊れるためで、FPU 無し・387・486SX（INT7）・SSE3 以降の FISTTP といった世代ごとの ESC スロットの扱いは意味論側で未実装のままである | 代替 | ESC スロットの世代別の扱いを挙動パラメータまたは機能旗で表し、FPU 無しモデルでは消費だけする形にする |
| GAP-0036 | x86 ゲスト「SSE4.2 文字列・拡張の近似」 | PCMPxSTRx は imm[1:0] を無視してバイト・符号なし要素として処理する（ワード要素・符号付き比較は未対応）。ROUNDPS/PD/SS/SD は MXCSR の丸め指定ビット（imm[3]）を受理するが、MXCSR の例外マスク・フラグ反映はしない | 代替 | PCMPxSTRx の要素幅・符号を imm[1:0] で分岐し、ROUND の MXCSR 連携を実装する |
| GAP-0037 | x86 ゲスト「llvm-mc とのデコード差分」 | `heavy_oracle_llvm` の既知差分表（KNOWN）に分類済み。(a) メモリ専用命令（movbe 等）の mod=11 形を受理する — マップ宣言にオペランドの mod 制約がない。(b) x87 mod=11 副表は実行意味論を A2 で実装済みだが、デコードは未定義スロット（D9 D1-D7 等）も受理して列挙差分として残る。(c) SSE1/2 の未宣言残り（cvtpi2ps/movntps/cvttps2pi/cvtps2pi/rsqrtps/rcpps/cvt*2dq/movnti）。(d) 列挙経路は接頭辞剥がし後の空間を解読する設計のため、必須接頭辞のない形（punpck*qdq、psrldq/pslldq、rdsspq）や REX 位置の inc/dec を受理する | 代替 | (a) オペランドの mod 制約を宣言・検査する。(b)(c) を後続ステップで実装・修正する。(d) は設計として記録し、列挙経路の退役時に解消する |
| GAP-0038 | x86 ゲスト「x87 超越関数と精度の近似」 | FSIN/FCOS/FSINCOS/FPTAN/FPATAN/FYL2X/FYL2XP1/F2XM1 は softfloat 層に超越関数がなく未実装（`Ok(false)` で既存デコードへ戻る）。FPREM/FPREM1 は倍精度経由の一回減算近似で C2=0（完全減算）固定、部分剰余の反復はしない。FSCALE は指数加算の飽和近似、FXAM はタグ未モデルのため 0.0 と空スロットを区別できず Zero に分類する。FLDENV/FNSTENV の FIP/FCS/FOP/FDP/FDS はモデル外で 0 とする | 代替 | softfloat 層に拡張精度の超越関数と剰余を実装し、タグワードと FIP/FOP 系の状態をモデルに追加する |
| GAP-0039 | x86 ゲスト「8088 タイミングモデルの対象範囲」 | `timing::I8088` は 4 バイトのプリフェッチキューと BIU のバス占有を T-state 単位で模倣し、`classify_8088` が `heavy_timing_8088` で SST 8088 の CYCL 件数と一致するのは「バスアクセスなし・キューフラッシュなし」の形に限る。対象外は (a) スタック・メモリのデータアクセスを伴う形（push/pop/xlat/ret 等、EU のマイクロ命令順序が未解明）、(b) 分岐成立でキューをフラッシュする形（call/jmp/ret/jcc 成立・loop 系成立）、(c) modrm と即値を併せ持つ `iz`/`iv`/`i` 接尾の形（81・C7・F6/F7.0-1）、(d) キュー状態で ±1 揺れる形（cwd/aaa/aas/aam/aad）、(e) REP 接頭辞付き、(f) 文字列命令（rep なしの mem 形は (a) と同じ境界）である。なお 0xC0/0xC1 は 8088 では imm カウントシフトではなく RET のエイリアスとして動作する（SST の逆アセンブルと CYCL で裏付け済み）ので、シフトとして扱わない | 代替 | SST のバストレース（FB/SB/FL と PASV/CODE/MEMR/MEMW の T-state 位置）から EU のマイクロ命令順序を逆推定し、mem 形・フラッシュ形の doc/位置パラメータを一括フィッティングする。REP・文字列命令は BIU アイドル検出と EU ループのモデルが要る |
