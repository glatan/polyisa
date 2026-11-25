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

- **拡張機能旗のデコード未接続**：`m`・`a`・`f`・`d`・`c`・`zicsr`・`zifencei` はモデル宣言にだけ使われ、命令の `when` 条件に接続されていない。生成デコーダは `feats` を参照しないため、`rv64imac` で F/D 拡張を外しても浮動小数点命令がデコード・実行できる（`rv32`/`rv64` の語長差だけは `when` で区別している）（[GAP-0101](../known-issues.md)）。
- **Linux syscall の範囲**：`os-linux::rv64` は初期の最小構成のままであり、`os-linux::sock`・`os-linux::wait` 正準層は未接続である。また、CLI からのトラップ境界に独自の `EcallHandler` 変換層が残っている（[GAP-0024](../known-issues.md)）。
- **JIT**：`run_riscv.rs` への `polyisa_jit::Jit` 統合は未実施。
- **SiFive U74 のタイミング近似と未較正**：
  - 実機計測が未実施のため、L2 ヒットレイテンシと主記憶応答時間は仮値のままであり、忠実度は `approx_uncalibrated` である（較正手順は [実機タイミング計測ガイド](../guides/calibration.md)）。
  - L1 D$ のバイト・ハーフワードアクセスに対する 3 サイクル応答（word/dword は 2 サイクル）を `CacheLevel` の単一 `hit_latency = 2` に近似している。
  - ストアパイプヒット時の 5 サイクルペナルティ、未完了ラインフィル 1 本制約、L2 の 2 バンク構成は簡略化している。
  - 整数除算の可変レイテンシ（6–68 サイクル）は `div_latency()` 規約を定義済みだが、意味論からの `hint` 送出が未接続のため代表値 6 固定。`fdiv`/`fsqrt`/`fcvt`/`fmv.d`・CSR・分岐誤予測（4 固定）も代表値で近似している。
  - `sifive_u74` は `zba`/`zbb` 機能ビットを宣言しているが、両拡張の命令記述と意味論は未実装。
- **GDB レジスタ表**：FPU レジスタは `fcsr` のみ掲載し、`fflags`/`frm` の個別項目は省略している（XML で regnum を明示しているため GDB 動作に支障はない）。
- **適合テストスイート**：`heavy_conformance_riscv_tests` の実行ハーネスは未実装（[GAP-0010](../known-issues.md)）。

## 検証手段

- **OS なし・単体**：`bare_rv64i`、`bare_sifive_u74`
- **適合・オラクル・実行差分**：`heavy_conformance_rv64ui`、`heavy_oracle_llvm`、`heavy_diff_qemu`
- **ABI・プログラム・GDB**：`heavy_abi_uapi`、`heavy_program_hello`、`heavy_program_dyn`、`heavy_program_semihosting`、`heavy_program_gdbstub`、`heavy_host_wasi`（wasm32 ホスト上で RV64 ELF を実行）
