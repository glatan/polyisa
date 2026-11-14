# 段階 5・6 作業メモ（ユーザー確認待ち）

段階 5（MIPS 本実装）と段階 6（AArch64）の作業で、所有者の確認・判断を
待っている事項を一か所にまとめた一覧。番号は確認待ち全体で通しである。
完了した作業と検証の記録は後半に残す。

## 確認待ち

### 台帳の「確認」欄（所有者のみが埋められる）

1. **BIN-DISTRO-AARCH64**: Alpine minirootfs 3.21.9 aarch64（musl +
   BusyBox 1.37.0、動的リンク一式）を `.testdata/bin-distro-aarch64` に
   配置済みで `heavy_program_aarch64` が使用する。台帳には登録したが
   確認欄は空欄。取得手順の manifest 化は未取得定義（git clone 形式の
   定義しかないため、tarball 系の取得は定義の拡張か手順書が要る）。
2. **SPEC-MIPS32R2 / SPEC-MIPS64**: r2 拡張（ext/ins/seb 等）と
   MIPS64r2 拡張（dext/dins/dsbh 等）の一次根拠として台帳に未確認登録済み。
   条文確認は所有者の仕事。
3. **SPEC-MIPS-ABI-N32**: n32/n64 ABI の一次根拠。台帳に未確認のまま。

### 所有者の作業

4. **`stage-6` タグ**: 段階の完了は注釈付きタグ `stage-6` で表す規約
   （dev-workflow「検証の記録」）。`stage-4` は所有者が付けており、
   メッセージに検証記録と所有者の確認を書く形式のため、エージェント側は
   作成していない。メッセージに転記する検証結果は後半の
   「検証記録（段階6）」に残す。

### 仕様・設計の判断

5. **`--root` 時の ELF パス解釈**: 実行対象のパスをゲスト名前空間として
   解決する実装にした（chroot と同じ規則。`resolve_guest_path_links`）。
   ホストパスで渡す呼び方とは互換でない点に注意。x86/mips は `--root`
   未対応のため影響なし。この解釈で確定してよいか。
6. **重いテストのバイナリ命名**: oracle 系の重いテストバイナリ名は
   `heavy_oracle_llvm` で各パッケージ共通とした。roadmap の S7-以降の
   命名（`heavy_oracle_arm` 等）はその段階でこの規約に揃えるか、
   個別名を採るか。
7. **R6 コンパクト分岐の 2R 形式の `rs>rt`**: BLEZ/BGTZ/BLEZL/BGTZL 群の
   2R 命令（BGEUC/BLTUC/BGEC/BLTC）は、`rs!=0 && rs!=rt` をすべて受ける。
   SPEC-MIPS-R6 の符号化表では `rs>rt` が予約の可能性があり、QEMU は寛容に
   受理する（本実装も同じ）。仕様書の条文で `rs>rt` が予約ならデコードで
   落とすよう厳格化するか判断したい。
8. **o32 `mmap` の旧引数順**: o32 の mmap（番号 90）は fd/offset を
   スタック引数で受ける。実装は `args[4]`/`args[5]`（スタック経由）と
   してあるが、glibc の実使用は `mmap2`（210）。旧 mmap の挙動差異は
   テスト不足。
9. **`polyisa-host` の OS 依存 API**: `Stat`/`pread`/`pwrite`/`dirent_ino`/
    `symlink` を host クレートに集約した（cfg 規則対応）。`std::os::unix`
    を `os-linux` で使わない方針でよいか確認したい（x86 側は `std::fs` の
    portable API のみで stat を組み立てている）。
10. **`lui` の厳格化の緩和**: LUI の rs フィールドは 00000 固定が正しい
    （旧実装は任意値を許容していたため修正）。pre-R6 で rs!=0 の 001111 は
    LUI ではなく予約として扱うようになった。実シリコンの受理挙動と異なる
    可能性は低いが、互換性のために緩めたい場合は別途検討する。

### 未完了・保留の作業

11. **FP/AdvSIMD の残り（aarch64）**: FP スカラー一式（算術・比較・
    変換・条件選択）は実装済み。AdvSIMD は musl の動的リンクが要求した
    部分集合（dup/ins/umov/movi・load/store 系）のみで、ベクトル演算系は
    未実装。必要になった時点で台帳とともに追加する。
12. **busybox の MIPS 版・n32/n64 の実バイナリ検証**: `heavy_program_mips`
    は裸 ELF（write/exit のみ）。実バイナリ検証を開始し
    `.testdata/bin-distro-mipsel`（o32 LE）と `.testdata/bin-distro-mips64`
    （n64 BE）を取得済み。台帳登録と配布物の正式選定は未了。
    現状: cop1 (FPU) を実装済み（FR=1 全幅・約70命令）。o32 は
    `echo`/`uname`/`date`/`id`/`ls`/`ls -l`/`cat`/`head`/`whoami` が
    動作（`/tmp` のような千件級ディレクトリは整形処理が O(n²) で
    ステップ上限に達するのみ）。n64 BE は
    `echo`/`uname`/`uname -a`/`cat`/`wc`/`basename`/`dirname`/`seq`/
    `yes`/`true`/`pwd` に加え `date`/`head`/`id`/`id -un`/`whoami` が
    動作。
    大きな根因は `slt`/`sltu`/`slti`/`sltiu` と分岐・トラップ系の
    符号比較（`cmp_regs`/`cmp_zero`）が 64 ビットモデルでも被演算子を
    32 ビットに正規化していた点で、上位アドレス（0x120xxxxxx・スタック
    0x7ffexxxx）同士のポインタ比較が常に誤判定になっていた。
    musl の疑似 FILE（sh_fromstring: rpos=s, rend=s+INT64_MAX）で
    `shgetc` マクロの `rpos != shend` 判定が壊れ、`__uflow` → 未初期化
    `f->read` への jalr で止まっていた。`sext_w`/`zext_w` ヘルパーで
    is64 時に全幅比較へ修正済み。
    残バグ（n64）: `ls` は getopt 出力で "NO OPT"（argv/文字列経路の
    別問題）、`cut`/`sed`/`grep` は 0x1200066xx のロック+ハッシュ走査
    ループでステップ上限（ll/sc スピンロック周辺の調査が残る）。
    既に確定させた修正: `do_readv`/`do_writev` の iovec ストライド
    （`w`→`2*w`）、`getdents64` の fd ごとのディレクトリ位置追跡、
    `do_brk` の既マップページ上書き、`mmap_next` の衝突回避、
    `sendfile`/`sendfile64`（cat 用、offset==NULL）の実装。
    回帰テスト: `n64_readv_iovec_stride`・`getdents64_advances_position`
    を `mips::sys::tests` に追加。
    残作業: 上記個別バグ（ls NO OPT・ハッシュ走査スピン）、n32 実
    バイナリ、台帳登録。

## 解消済み（記録）

- **aarch64 残件**: ID_AA64 系レジスタ値の整備（実装機能に整合する値 +
  MRS テスト）、BE エンディアン（EI_DATA 受理・データアクセス反転・
  手組み BE ELF テスト）、スタック成長（ページフォルト駆動・上限
  8 MiB）、FP スカラー一式（fadd/fsub/fmul/fdiv/fmuladd 系・fcmp/fccmp/
  fcsel・fcvt 系・fmov imm/int 往復・llvm oracle 拡充）は全て実装済み。
- **MIPS ABI 精査**: o32 の 64bit 引数は偶数語対（truncate64/ftruncate64
  は a2/a3、pread64/pwrite64 はスタック lo/hi）に修正、n32 は単一
  64bit レジスタに修正。`do_statfs` を本レイアウト（o32=68B /
  statfs64=92B / n64=128B）で実装し `ustat` も配線。
- **MIPS R6 オプション命令**: LLWP/SCWP（語対）と LLE/SCE（EVA）を
  実装（paired 形は rd フィールド+bit6=1）。branch-likely 8 命令
  （beql/bnel/blezl/bgtzl/bltzl/bgezl/bltzall/bgezall）を非 R6 で実装し
  遅延スロット nullify を追加。
- **MIPS 実バイナリ向け修正**: 初期スタックを 8 MiB+argv/envp/auxv に、
  `rdhwr $29`（ULR→set_thread_area の TLS）、n64 の jr/jalr・J/JAL
  ターゲットの上位ビット、o32 `uname`(122) 配線、is64 時の 32bit
  演算結果の符号拡張正規化（mask32）。

- **`MIPS_O32_SYSCALLS` の後継**: status 生成が `mips_o32.rs` 等の
  `SYSCALLS` 表を読むように変更した。`syscall_entry_name` は
  `(nr, "name")` 形も受理するよう拡張済み。aarch64 も同じ表形式に揃えた。
- **`MipsModel::is64` の扱い**: `--cpu mips64r2`/`mips64r6` と
  EF_MIPS_ARCH からの自動選択で is64 モデルが選べる。n32/n64 の ELF は
  `abi_from_elf` が ABI を選び is64 モデルを要求する。
- **`rv32ud_p_move` の除外**: `test:full` で唯一失敗していた。上流
  riscv-tests の `rv32ud/Makefrag` は `move`（と `structural`）を
  rv32 向けに未実装として対象外にしており、`rv32ud/move.S` は
  `rv64ud/move.S` を include するだけで `fmv.d.x`/`fmv.x.d` が
  rv32g では組み立てられない。polyisa のテスト一覧から除去した
  （上流の一覧と一致）。段階6以前からの既存失敗であり、aarch64 作業とは
  無関係。

## 検証記録（段階6）

`stage-6` タグのメッセージに転記するための実行結果。

- `task check`: fmt / clippy(-D warnings) / devtool check すべて ok
- `task check:targets`: powerpc64 / i686 / wasm32 で `cargo check` 通過
- `task doctor`: rustc/cargo 1.100.0、go-task 3.54.0、nextest 0.9.151、
  git 2.56.1、clang・llvm-mc は重いテストの実行で確認
- `task testdata:fetch`: TEST-RISCV-TESTS / TEST-RISCV-ARCH-TEST /
  TEST-TESTFLOAT いずれも版が一致
- `task test:full`: test:plan が要件を調べ `all()`（除外なし）。
  1483 tests run: 1483 passed, 0 failed, 0 skipped（約 42 秒）
- `task bench`: generic_vs_direct iters=200000
  direct=38.031µs generic=55.324µs fadd=72.676µs

## 完了した作業（記録）

### 段階 5

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

### 段階 6

- **guests/aarch64**: ISADL spec（a64i.rs）と `sem.rs`。整数命令一式
  （分岐/加減算/論理/ビットフィールド/乗算/ロードストア全アドレッシング/
  ペア/排他/システム）に加え、musl の動的リンクが要求する AdvSIMD 部分集合
  （dup/umov/ins/fmov、Q/D/S/B/H の load/store、ldp/stp の Q/D/S、
  modified immediate 群）を実装。レジスタ 31 の SP/ZR 文脈分岐、NZCV、
  DecodeBitMasks（`sem::decode_bit_masks`）。モデル `generic`/`generic_v81`。
- **意味論の修正（実バイナリで発見）**: `add_imm`/`add_sh`/`add_ext`/`log_imm`/
  `log_sh` が flags 設定時に rd へ結果を書き戻していなかった（`subs x8, x8, #1`
  が x8 を更新せず無限再帰 → スタック溢れ）。S 形式は ZR 文脈・結果は常に
  書き戻す（rd=31 は ZR として破棄）に統一。
- **ADR/ADRP のオフセット**: `immhi<<2|immlo` の 21 ビット符号付きが正しい
  （初版はフィールド結合が誤りで clang 生成の後方参照 ADR が壊れていた）。
- **musl/BusyBox 実走行で発見して修正した意味論**: `DecodeBitMasks` の
  `emask`（要素幅のマスクが `(1<<esize)-1` でなく `esize-1` になっていた。
  `tst` が常に Z を立て haszero を見逃し）、UBFM/SBFM のマスク導出
  （`immr<=imms` 抽出系と `immr>imms` 挿入系の区別、符号位置は元ソースの
  bit imms）、`csel` の cond 抽出（bits[15:12]、B.cond の bits[3:0] を
  流用していた）、`add_ext`/`subs_ext` の Rn=31 は常に SP（flags 有無と
  無関係）、`ls_pair` のポストインデックス書き戻し、`clz32`/`clz64` の
  +1 ずれ、`umulh` の spec パターン（bits[30:29]）、`ldp` の rt2。
- **os-linux::aarch64**: asm-generic 番号表（`aarch64.rs`）、LP64 ABI
  （x8=nr、x0-x5=引数、x0=返り値、負 errno）、`sys::Linux`（TrapHandler）。
  read/write/openat/close/lseek/fstat/mmap/munmap/mprotect/brk/uname/
  exit/exit_group/identity/clock_gettime/getrandom/getdents64/dup/dup3/
  fcntl/ioctl/signal 最小スタブ。未知番号は ENOSYS を返して続行。
  `getdents64` は fd ごとのディレクトリ位置（`dir_pos`）を追跡して
  EOF を返す。`mmap` は `find_free_run` で brk 成長・既存マップと衝突
  しない領域を選ぶ。
- **ゲストパス**: `os-linux::guest_path` に `resolve_guest_path`（root
  閉じ込め）と `resolve_guest_path_links`（シンボリックリンク追跡。
  絶対ターゲットはゲストルートへ結び直す chroot 規則）を集約。
  `--root` 時の ELF パスと PT_INTERP の指す ld.so はゲスト名前空間で
  解決する。syscall 側の open/stat 等は `host_path_followed` 経由。
- **cli**: `run_aarch64.rs`（`engine::run::run` 経路、EM_AARCH64=183 派分、
  `--cpu aarch64:` モデル解決、PT_INTERP 動的ロード、初期スタック、
  svc → TrapHandler）。`run_elf_aarch64`/`_sel`/`_sys`/`_sys_root`/`_root`。
- **初期スタック**: AT_RANDOM の 16 バイトはスタック最上端（`top-16`）に置く。
  musl のスタックプロービングが sp 直下を使うため像の直上にもマージンを確保。
- **テスト**: `heavy_program_aarch64`（静的 "hi\n"、fib(10)=55、
  Alpine minirootfs の BusyBox コマンド群を `--root` で実行）、
  `heavy_abi_aarch64`（asm-generic UAPI との番号突合）、
  `heavy_oracle_llvm`（llvm-mc/objdump とのデコード差分）、
  `guests/aarch64/tests/{decode,bit_masks}.rs`、`run_path` の手組み ELF、
  sys.rs/run_aarch64.rs の `mod tests`（getdents 位置・mmap/brk 衝突・
  ゲストルート絶対リンク・各種意味論の回帰）。
- `SPEC-AARCH64-ELF` を確認済みに更新（2025Q4 daa7a94）。

## 参考

- Linux UAPI 6.19（`syscall_o32.tbl`/`n32.tbl`/`n64.tbl`、`asm/unistd.h`）が番号表の根拠。
- R6 コンパクト分岐の分解規則は QEMU `gen_compute_compact_branch`
  （target/mips/tcg/translate.c）と LLVM Mips32r6InstrInfo.td の OPGROUP 表で確認した。
- R6 の SPECIAL3 LL/SC（0x36/0x26/0x37/0x27）と DAHI/DATI/DAUI は
  QEMU translate.c と LLVM Mips32r6InstrInfo.td で確認した。
