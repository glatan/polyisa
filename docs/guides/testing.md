# テストガイド

エミュレータの不具合は、誤った値が多数の命令を経たあとに症状として現れるため、原因の特定に時間がかかります。polyisa では単体・命令単位のテストを厚くし、プログラム単位や差分テストでシステムコール・シグナル・命令の組合せを検証しています。テストの補助部品（擬似乱数、性質テスト、SHA-256、オラクル呼出し、要件表）はすべて `crates/testkit` に自前実装しています。

## テストの層と重いテストの命名

テストは役割ごとに次の層へ分けています。外部ツールや `.testdata/` を必要とするテスト、または `default` プロファイルの時間上限を超えるテストは「重いテスト」として、テストバイナリ名を `heavy_<層名>_*.rs` にします。

| 層名（接頭辞） | 対象 | 主なテスト内容 |
|---|---|---|
| （接頭辞なし / 単体） | 基礎・ISADL 往復・OS なし実行 | `bits`・`softfloat`・`decimal`・`isadl`・`mem`・`engine` の単体テスト、`ENCODE_ROUNDTRIP`、`bare_*` 命令単位テスト |
| `oracle` | デコーダ差分 | `llvm-objdump`・`llvm-mc`・Intel XED との逆アセンブル差分テスト |
| `conformance` | 適合テストスイート | SingleStepTests（8088・80286・80386・68000）、WebAssembly 仕様テスト（`.wast`）、decTest、TestFloat、riscv-tests、riscv-arch-test（ACT4 の代表テスト） |
| `abi` | ABI 表照合 | Linux カーネル UAPI ヘッダおよび `syscall.tbl` と `os-linux` の番号・定数・構造体配置の突き合わせ |
| `program` | プログラム単位実行 | 静的／動的リンクの自前プログラム、BusyBox・Alpine・Unix V7・4.3BSD 配布物バイナリ、Semihosting・WASI・GDB 接続 |
| `diff` | 実行差分 | ホスト x86-64 CPU、Intel SDE、QEMU user-mode、wasmtime との実行状態差分テスト |
| `jit` | JIT 等価性 | インタプリタと JIT のブロック境界ごとの状態一致（`heavy_jit_diff`） |
| `timing` | タイミング検証 | `exact`（R3000・8088・i486・Pentium・68000）のサイクル一致と `approx`（`heavy_timing_ooo`）の誤差検証 |
| `host` | ホスト移植性 | wasmtime 上での `wasm32-wasi` ビルド実行（`heavy_host_wasi`） |
| `determinism` | 決定性 | 同一入力 2 回実行でのトレース・仮想時間・出力一致（未着手：[GAP-0031](../known-issues.md)） |

各 ISA で整備されているテスト層の最新状況は [実装状況](../status.md) で確認できます。

## nextest とビルドプロファイル

テストは `cargo-nextest`（`.config/nextest.toml`）で実行します。全体の検証に素の `cargo test` は使いません（doctest のみ `task test` が `cargo test --doc --workspace` を実行します）。

- **`default` プロファイル（`task test`）**：`not binary(/^heavy_/)` で単体テストと軽量テストのみを実行します。最初の失敗で停止し、タイムアウトは短め（`30s` × 2）です。
- **`full` プロファイル（`task test:full` / `task test:layer`）**：`--cargo-profile heavy`（`release` 継承＋`debug-assertions = true`＋`overflow-checks = true`）でビルドして重いテストを実行します。失敗しても最後まで実行し、JUnit 出力を `target/nextest/full/junit.xml`（コミット対象外）へ書き出します。
- **再試行なし（`retries = 0`）**：実行は決定的であるべきため、再試行で通るテストは不具合として扱います。

## オラクルやテストデータがない場合の扱い

外部ツールや `.testdata/` が揃っていない環境でテストを暗黙に成功させると、検証漏れに気づけません。polyisa では実行前に `devtool test:plan` で不足分を検出し、次のように制御しています。

1. 重いテストバイナリが必要とするツール・テストデータは `crates/testkit` の要件表に台帳 ID で一箇所に記述します。
2. `task test:full` / `task test:layer` は事前に `devtool test:plan --filter` を呼び、要件を満たさないテストバイナリを nextest フィルタ式から除外します。
3. テスト終了後に `devtool test:plan` が、除外したバイナリと不足理由を「未実行」として一覧表示します。
4. テスト本体の中でツールやデータが見つからない場合は、成功にせず失敗させます。

## テスト設計と期待値の書き方

- **期待値の根拠をコメントに残す**：ピン留めした値が正しさの根拠を持つかは値だけでは判断できません。コメントに次のいずれかを明記してください。
  - **一次資料・実測値**：ISA 仕様書（`// Ref: SPEC-...`）、実機、SingleStepTests など。XED や LLVM などの二次実装はオラクル比較（用途 `X`）にのみ使い、事実の根拠（用途 `F`）にはしません（[参照資料の台帳](../references.md) の規則 9）。
  - **実装の規約**：polyisa が意図的に選んだ決定的挙動。
  - **回帰ガード**：外部検証なしのピン留め。
- **手書きバイト列の検証**：テストに機械語バイト列を直接書く前に、エンコーダまたはデコーダ・逆アセンブラで意図した命令になっているか確認します。複数テストで同じ命令列を使う場合は生成関数を共有してください。
- **回帰の切り分け**：複数テストがまとめて失敗したとき、「環境由来」と決めつけて `#[ignore]` で隠さず、実装側の欠落と仕様変更への追従漏れを切り分けて原因を特定します。
- **恒真テストの防止**：新しいテスト群を書く前に、入力と入力を比較するだけの恒真検査やパラメータ未参照がないかを確認してください。
