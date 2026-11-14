# 段階 5・6 作業メモ（ユーザー確認待ち）

段階 5（MIPS 本実装）の作業中に持ち越した確認事項と未完了の作業。

## 完了した作業

- **GAP-0001 解消**: MIPS の syscall 処理を `crates/cli/src/run_mips.rs` から
  `crates/os-linux/src/mips/sys.rs`（`mips::sys::Linux`、`TrapHandler` 実装）へ移管。
  o32・n32・n64 の番号表（`mips_o32.rs`/`mips_n32.rs`/`mips_n64.rs`、UAPI 6.19 由来）、
  MIPS 固有 errno・signal・oflag・mflag・ioc 定数を `crates/os-linux/src/mips.rs` に実装。
- **GAP-0007 解消**: MIPS の実行ループを `engine::run::run` + `MipsStep::step` に移管。
  遅延スロット・ロード遅延は `MipsStep` が保持する。
- `CpuState` に `hwr[4]`（RDHWR/TLS）を追加。`set_thread_area` → `hwr[3]`。
- `polyisa_host` に移植層を追加（`Stat`/`stat`/`lstat`/`fstat`/`pread`/`pwrite`/`dirent_ino`）。
- `heavy_program_mips`（4 モデル）通過。`task check`（fmt/clippy/devtool）通過。

## 確認待ち・未完了（段階 5 残件）

1. **MIPS64（n32/n64）命令実装**: `guests/mips/spec/mipsi.rs` は MIPS I + `beqzalc` のみ。
   `daddu`/`ld`/`sd`/`dsll` 等の MIPS64 命令と `FEAT_MIPS64` フラグがない。
   `MipsModel::mips64r2()`/`mips64r6()` は `feats: 0` のまま（is64 フラグのみ）。
   → spec への命令追加と sem.rs の意味論が必要。
2. **R6 残り命令**: R6 固有命令（コンパクト分岐 `bc`/`balc`/`beqc` 等、
   `seleqz`/`mul`/`muh`/`mod`、`lsa`、`auipc`/`lwpc`、`align`、`jic`/`jialc`、
   `bitswap`）が spec・sem とも未実装。
3. **MIPS32r2 追加命令**: `ext`/`ins`/`seb`/`seh`/`wsbh`/`clz`/`clo`/`movz`/`movn`/
   `madd`/`ll`/`sc`/`rdhwr`/`sync`/`teq` が未実装（`rdhwr` は `hwr_ref` のみ用意済み）。
4. **`MIPS_O32_SYSCALLS` の後継**: status 生成が `mips_o32.rs` 等の `SYSCALLS` 表を
   読むように変更した。`syscall_entry_name` は `(nr, "name")` 形も受理するよう拡張済み。
5. **busybox の MIPS 版**: `heavy_program_mips` は裸 ELF（write/exit のみ）。
   dist コマンド実行は `.testdata/bin-distro` に MIPS 版がないため未実行。

## 確認待ち・未着手（段階 6）

6. **AArch64 全体**: `guests/aarch64`（ISADL+sem）、`step_aarch64`、ELF 派分、
   `os-linux::aarch64`（asm-generic 番号表・LP64・初期スタック/auxv・シグナルフレーム）、
   `heavy_program_aarch64`/`heavy_abi_aarch64`/`heavy_oracle_aarch64` が未着手。
   `SPEC-AARCH64-ELF`（aaelf64）は台帳に登録済みだが未確認。

## 確認を要する判断

7. **`MipsModel::is64` の扱い**: n32/n64 の番号表は揃えたが、MIPS64 の意味論がないため
   n64 ELF を実行しても命令が Unimplemented になる。is64 モデルを --cpu で選べるように
   するかは命令実装後に判断したい。
8. **o32 `mmap` の旧引数順**: o32 の mmap（番号 90）は fd/offset をスタック引数で受ける。
   実装は `args[4]`/`args[5]`（スタック経由）としてあるが、glibc の実使用は `mmap2`（210）。
   旧 mmap の挙動差異はテスト不足。
9. **`do_statfs` の中身**: MIPS の `statfs` 構造体は 120B でレイアウト固有。
   現状は最小限（f_type=EXT2、bsize=4096 等）のみ。
10. **`polyisa-host` の OS 依存 API**: `Stat`/`pread`/`pwrite`/`dirent_ino` を host クレートに
    追加した（cfg 規則対応）。`std::os::unix` を `os-linux` で使わない方針でよいか確認したい
    （x86 側は `std::fs` の portable API のみで stat を組み立てている）。

## 参考

- Linux UAPI 6.19（`syscall_o32.tbl`/`n32.tbl`/`n64.tbl`、`asm/unistd.h`）が番号表の根拠。
- 台帳 `SPEC-MIPS-ABI-N32`（n32/n64 ABI）は未確認のまま。
