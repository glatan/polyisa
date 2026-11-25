# RISC-V

## 概要と対応範囲

RV32 / RV64 の I・M・A・F・D・C・Zicsr・Zifencei 拡張と、汎用モデルおよび SiFive U74 モデルを `guests/riscv` で実装している。

- **CPU モデル**：`rv64gc`、`rv64imac`、`sifive_u74`、`rv32i`、`rv32im`、`rv32ima`、`rv32imac`、`rv32gc`、`rv64i`、`rv64im`、`rv64ima`、`sifive_e31`、`rva20u64`、`rva22u64`、`rva23u64`（計 15 モデル）。RVA22/23 の拡張命令はいずれも未実装でカバレッジ表にゼロ件で見える。整数系プロファイル（`rv32i` 系・`rv64i` 系）は Zicsr・Zifencei を含めない純粋な拡張列。RVA プロファイル（`rva20u64` など）は必須拡張の旗が未宣言のため未追加。
- **タイミング**：`sifive_u74` モデルが `timing::inorder`（デュアルイシュー・インオーダー）を使用する `approx_uncalibrated` 宣言を持つ（`guests/riscv/src/timing.rs`）。

## 対応する OS・ABI と実行環境

- **Linux（`os-linux::rv64`）**：RV64 の最小システムコール（`exit`・`exit_group`・`write` 等）。動的リンクを含むテストプログラムを実行できる。
- **Semihosting 2.0（`os-semihost`）**：ebreak 標識列経由で `polyisa run --os semihost` に対応している（`cli` の `SemiRv` 適合層を使用）。
- **GDB 接続（`gdbstub::riscv`）**：`polyisa run -g <ポート>` に対応している唯一の ISA であり、`x0`–`x31`・`pc`・`f0`–`f31`・`fcsr` のレジスタ表と `target.xml` 生成を持つ。
- **CLI `disasm`**：`polyisa disasm <hex-word>` の現行対象 ISA である。

## 実装の構造と特記事項

16 ビット圧縮命令（C 拡張）と 32 ビット命令を先頭 2 ビットで判別し、`C.JR` 群は `where` 句、RV32/RV64 間の符号化重複（`C.FLW` と `C.LD` 等）は `when` 述語で区別する。RV32 実行時は GPR に下位 32 ビットの符号拡張値を保持し、アドレスは 32 ビットにマスクする。

## 既知の簡略化と未対応範囲

- **拡張機能旗のデコード接続**：`m`・`a`・`f`・`d`・`c`・`zicsr`・`zifencei` は命令の `when` 条件へ接続済みで、`rv64i` や `rv64imac` では対応しない拡張命令をデコードしない。RV32/RV64 で符号化が重なる圧縮命令と、RV64 限定の浮動小数点変換・移動もモデルで振り分ける。
- **Linux syscall の範囲**：`os-linux::rv64` は初期の最小構成のままであり、`os-linux::sock`・`os-linux::wait` 正準層は未接続である。また、CLI からのトラップ境界に独自の `EcallHandler` 変換層が残っている（[GAP-0024](../known-issues.md)）。
- **JIT**：`run_riscv.rs` への `polyisa_jit::Jit` 統合は未実施。
- **SiFive U74 のタイミング近似と未較正**：
  - 実機計測が未実施のため、L2 ヒットレイテンシと主記憶応答時間は仮値のままであり、忠実度は `approx_uncalibrated` である（較正手順は [実機タイミング計測ガイド](../guides/calibration.md)）。
  - L1 D$ のバイト・ハーフワードアクセスに対する 3 サイクル応答（word/dword は 2 サイクル）を `CacheLevel` の単一 `hit_latency = 2` に近似している。
  - ストアパイプヒット時の 5 サイクルペナルティ、未完了ラインフィル 1 本制約、L2 の 2 バンク構成は簡略化している。
  - 整数除算の可変レイテンシ（6–68 サイクル）は `div_latency()` 規約を定義済みだが、意味論からの `hint` 送出が未接続のため代表値 6 固定。`fdiv`/`fsqrt`/`fcvt`/`fmv.d`・CSR・分岐誤予測（4 固定）も代表値で近似している。
  - `sifive_u74` は `zba`/`zbb` 機能ビットを宣言しているが、両拡張の命令記述と意味論は未実装。
- **GDB レジスタ表**：FPU レジスタは `fcsr` のみ掲載し、`fflags`/`frm` の個別項目は省略している（XML で regnum を明示しているため GDB 動作に支障はない）。
- **適合テストスイート**：`heavy_conformance_rv64ui` は riscv-tests の RV32/RV64 ユーザーモード対象を広く実行する。riscv-arch-test（ACT4 形式を含む）の実行ハーネスは未実装（[GAP-0010](../known-issues.md)）。
- **ACT4 の前提**：ACT4 は Sail リファレンスモデルで生成した期待 signature を自己検査 ELF へ埋め込む。ACT4 の要求版は Sail 0.16 で、上流が Linux x86-64 向けの署名検証可能な prebuilt binary を公開している。フレームワーク本体の選定には Ruby/UDB と Python/uv、コンパイルには GCC 15 または Clang 20 以降が要る。現在の開発コンテナには Clang 23 と qemu-user だけがあり、qemu-user は bare-metal ACT ELF の実行基盤にはならない。polyisa 側のハーネスでは、ACT の全体フレームワークに依存せず、選定した代表的なユーザーモード対象について reference signature 生成・compile/link・製品ランタイム実行・console/signature 判定の経路を固定する必要がある。

## 検証手段

- **OS なし・単体**：`bare_rv64i`、`bare_sifive_u74`
- **適合・オラクル・実行差分**：`heavy_conformance_rv64ui`、`heavy_oracle_llvm`、`heavy_diff_qemu`（RV64I/M/A・幅違いロード・分岐）
- **ABI・プログラム・GDB**：`heavy_abi_uapi`、`heavy_program_hello`、`heavy_program_dyn`、`heavy_program_semihosting`、`heavy_program_gdbstub`、`heavy_host_wasi`（wasm32 ホスト上で RV64 ELF を実行）
