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
- **n32/n64 ABI 経路**: ELF クラス（EI_CLASS）で `parse_ehdr`/`parse_ehdr32` を
  派分し、`abi_from_elf` で CLASS64→n64・CLASS32+EF_MIPS_ABI2→n32・他→o32 を選択。
  o64/eabi は未対応エラー。n32/n64 は 64 ビットモデル必須。
  CLASS_64 の EM_MIPS を `run_path_with` に追加。`--cpu mips64r2`/`mips64r6` が
  is64 モデルとして選択可能。
- **`model_from_flags` 修正**: EF_MIPS_ARCH の値を binutils 定義に合わせた
  （0x5=MIPS32, 0x8=MIPS64r2 を追加、0x5→mips64r2 の誤マップを解消）。
  MIPS32/MIPS64 r1 は r2 モデルで代用。
- `heavy_program_mips`（4 モデル）・`heavy_timing_r3000` 通過。
  `task check`（fmt/clippy/devtool）通過。

## 確認待ち・未完了（段階 5 残件）

1. **`MIPS_O32_SYSCALLS` の後継**: status 生成が `mips_o32.rs` 等の `SYSCALLS` 表を
   読むように変更した。`syscall_entry_name` は `(nr, "name")` 形も受理するよう拡張済み。
2. **busybox の MIPS 版**: `heavy_program_mips` は裸 ELF（write/exit のみ）。
   dist コマンド実行は `.testdata/bin-distro` に MIPS 版がないため未実行。
   n32/n64 の ELF も同様に実バイナリでの検証がない。
3. **R6 オプション命令は対象外**: LLWP/SCWP（ペア LL/SC、特定コアのみ）と
   LLE/SCE（EVA 版、ユーザモードでは LL/SC と同義）は実装していない。
   実シリコン依存の拡張のため今回の範囲外とした。必要なら別途追加する。

## 段階 6 の進捗（AArch64）

- **guests/aarch64**: ISADL spec（a64i.rs、約 90 命令: 分岐/加減算/論理/
  ビットフィールド/乗算/ロードストア全アドレッシング/ペア/排他/システム）と
  `sem.rs` を実装。レジスタ 31 の SP/ZR 文脈分岐、NZCV、DecodeBitMasks を
  exec 側で計算。モデル `generic`/`generic_v81`。
- **意味論の修正（実バイナリで発見）**: `add_imm`/`add_sh`/`add_ext`/`log_imm`/
  `log_sh` が flags 設定時に rd へ結果を書き戻していなかった（`subs x8, x8, #1`
  が x8 を更新せず無限再帰 → スタック溢れ）。S 形式は ZR 文脈・結果は常に
  書き戻す（rd=31 は ZR として破棄）に統一。
- **ADR/ADRP のオフセット**: `immhi<<2|immlo` の 21 ビット符号付きが正しい
  （初版はフィールド結合が誤りで clang 生成の後方参照 ADR が壊れていた）。
- **os-linux::aarch64**: asm-generic 番号表（`aarch64.rs`）、LP64 ABI
  （x8=nr、x0-x5=引数、x0=返り値、負 errno）、`sys::Linux`（TrapHandler）。
  read/write/openat/close/lseek/fstat/mmap/munmap/mprotect/brk/uname/
  exit/exit_group/identity/clock_gettime/getrandom/getdents64/dup/dup3/
  fcntl/ioctl/signal 最小スタブ。未知番号は ENOSYS を返して続行。
- **cli**: `run_aarch64.rs`（step_aarch64、EM_AARCH64=183 派分、
  `--cpu aarch64:` モデル解決、初期スタック、svc → TrapHandler）、
  `run_elf_aarch64`/`run_elf_aarch64_sel`/`run_elf_aarch64_sys`。
- **テスト**: `heavy_program_aarch64`（clang 23 aarch64-linux-gnu:
  write+exit_group で "hi\n"、再帰 fib(10)=55 で "55\n"）、
  `run_path` の手組み EM_AARCH64 ELF 派分テスト、裸実行の
  movz/add/subs/b.cond/sp-zr 単体テスト。
- `SPEC-AARCH64-ELF` を確認済みに更新（2025Q4 daa7a94）。

## 確認待ち・未完了（段階 6 残件）

5. **スタック成長**: 現状は固定 1 MiB を先行確保（`run_aarch64.rs`）。
   ページフォルト駆動の成長（fault → TrapHandler 経路）は未実装。
   容量の適性と成長方式の設計判断を要する。
6. **FP/AdvSIMD**: FEATURE `fp`/`asimd` は宣言済みだが命令未実装
   （モデル generic の既定機能が空でない点に注意。decode が要求しないため
   現状影響なし。実装時に MODEL_DEFS の既定を見直す）。
7. **BE エンディアン**: FEAT_BE 宣言のみ。データフェッチ/ロードストアの
   エンディアン切替と ELF の EI_DATA 確認は未接続（現状 LE 固定・BE 拒否）。
8. **MRS/MSR の ID レジスタ**: MRS/MSR の枠は実装済みだが ID_AA64 系の
   個別値は未整備（実装した機能に応じた値の台帳が要る）。
9. **heavy_abi / heavy_oracle / 動的リンク**: 段階 6 の完了条件表に
   残る heavy_abi_aarch64（引数・スタック規約の機械検証）と
   heavy_oracle（QEMU/実機との結果突合）、および PT_INTERP 経路は未着手。

## 確認を要する判断

6. **`MipsModel::is64` の扱い（解消）**: `--cpu mips64r2`/`mips64r6` と
   EF_MIPS_ARCH からの自動選択で is64 モデルが選べる。n32/n64 の ELF は
   `abi_from_elf` が ABI を選び is64 モデルを要求する。実バイナリでの
   検証は残る（上記 2 番）。
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
