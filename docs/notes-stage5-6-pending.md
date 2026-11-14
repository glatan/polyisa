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
- **MIPS32r2 命令**: ext/ins/seb/seh/wsbh/clz/clo/movz/movn/madd/msub/mul/ll/sc/rdhwr/
  sync/teq/pref を spec・sem・exec に実装。
- **MIPS64 命令**: daddu/dadd/daddiu/daddi/dsub/dsll/dsra/dsll32/dmult/ddiv/ld/sd/lwu/
  lld/scd/ldl/ldr/sdl/sdr/dext/dins/dsbh/dshd/dclz/dclo を実装。
- **Release 6**: コンパクト分岐全 19 系（フィールド間比較 `where` で分解）、
  乗除算 mul/muh/mod 系、seleqz/selnez、lsa/dlsa、auipc/aluipc/addiupc/lwpc/lwupc/ldpc、
  align/dalign/bitswap/dbitswap、jic/jialc、beqzc/bnezc、bc/balc、
  aui/daui/dahi/dati、nal/bal、synci、SPECIAL3 の ll_r6/sc_r6/lld_r6/scd_r6 を実装。
- ISADL の `where` を拡張（Lt/Le/Gt/Ge とフィールド間比較 `WhereRhs::Field`）。
  R6 コンパクト分岐の rs/rt 制約を宣言的に記述。
- `is_compact()` でコンパクト制御を遅延スロットなし実行、
  `has_delay_slot()` で遅延分岐群を区別。
- `heavy_program_mips`（4 モデル）・`heavy_timing_r3000` 通過。
  `task check`（fmt/clippy/devtool）通過。

## 確認待ち・未完了（段階 5 残件）

1. **`MIPS_O32_SYSCALLS` の後継**: status 生成が `mips_o32.rs` 等の `SYSCALLS` 表を
   読むように変更した。`syscall_entry_name` は `(nr, "name")` 形も受理するよう拡張済み。
2. **busybox の MIPS 版**: `heavy_program_mips` は裸 ELF（write/exit のみ）。
   dist コマンド実行は `.testdata/bin-distro` に MIPS 版がないため未実行。
3. **n32/n64 実行経路**: syscall 番号表は揃ったが、n32/n64 用の初期スタック/
   auxv/ELF 派分の接続は未着手（`os-linux::mips` の ABI 選択経路）。
4. **R6 オプション命令は対象外**: LLWP/SCWP（ペア LL/SC、特定コアのみ）と
   LLE/SCE（EVA 版、ユーザモードでは LL/SC と同義）は実装していない。
   実シリコン依存の拡張のため今回の範囲外とした。必要なら別途追加する。

## 確認待ち・未着手（段階 6）

5. **AArch64 全体**: `guests/aarch64`（ISADL+sem）、`step_aarch64`、ELF 派分、
   `os-linux::aarch64`（asm-generic 番号表・LP64・初期スタック/auxv・シグナルフレーム）、
   `heavy_program_aarch64`/`heavy_abi_aarch64`/`heavy_oracle_aarch64` が未着手。
   `SPEC-AARCH64-ELF`（aaelf64）は台帳に登録済みだが未確認。

## 確認を要する判断

6. **`MipsModel::is64` の扱い**: n32/n64 の番号表は揃えたが、MIPS64 命令の
   意味論は追加済みでも `--cpu` で is64 モデルを選ぶ経路は未接続の可能性がある。
   n64 ELF を実行できるか確認したい。
7. **o32 `mmap` の旧引数順**: o32 の mmap（番号 90）は fd/offset をスタック引数で受ける。
   実装は `args[4]`/`args[5]`（スタック経由）としてあるが、glibc の実使用は `mmap2`（210）。
   旧 mmap の挙動差異はテスト不足。
8. **`do_statfs` の中身**: MIPS の `statfs` 構造体は 120B でレイアウト固有。
   現状は最小限（f_type=EXT2、bsize=4096 等）のみ。
9. **`polyisa-host` の OS 依存 API**: `Stat`/`pread`/`pwrite`/`dirent_ino` を host クレートに
   追加した（cfg 規則対応）。`std::os::unix` を `os-linux` で使わない方針でよいか確認したい
   （x86 側は `std::fs` の portable API のみで stat を組み立てている）。
10. **R6 コンパクト分岐の 2R 形式の `rs>rt`**: BLEZ/BGTZ/BLEZL/BGTZL 群の
    2R 命令（BGEUC/BLTUC/BGEC/BLTC）は、`rs!=0 && rs!=rt` をすべて受ける。
    SPEC-MIPS-R6 の符号化表では `rs>rt` が予約の可能性があり、QEMU は寛容に
    受理する（本実装も同じ）。仕様書の条文で `rs>rt` が予約ならデコードで
    落とすよう厳格化するか判断したい。
11. **SPEC-MIPS32R2 / SPEC-MIPS64 の確認**: r2 拡張（ext/ins/seb 等）と
    MIPS64r2 拡張（dext/dins/dsbh 等）の一次根拠として台帳に未確認登録済み。
    条文確認は所有者の仕事。
12. **lui の符号化修正**: LUI の rs フィールドは 00000 固定が正しい
    （旧実装は任意値を許容していたため修正）。pre-R6 で rs!=0 の 001111 は
    LUI ではなく予約として扱うようになった。実シリコンの受理挙動と異なる
    可能性は低いが、互換性のために緩めたい場合は別途検討する。

## 参考

- Linux UAPI 6.19（`syscall_o32.tbl`/`n32.tbl`/`n64.tbl`、`asm/unistd.h`）が番号表の根拠。
- 台帳 `SPEC-MIPS-ABI-N32`（n32/n64 ABI）は未確認のまま。
- R6 コンパクト分岐の分解規則は QEMU `gen_compute_compact_branch`
  （target/mips/tcg/translate.c）と LLVM Mips32r6InstrInfo.td の OPGROUP 表で確認した。
- R6 の SPECIAL3 LL/SC（0x36/0x26/0x37/0x27）と DAHI/DATI/DAUI は
  QEMU translate.c と LLVM Mips32r6InstrInfo.td で確認した。
