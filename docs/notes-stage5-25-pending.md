# 段階 5–25 作業メモ（ユーザー確認待ち・作業記録）

段階 5（MIPS 本実装）から段階 25（追加の OS パーソナリティ）までの
作業で、所有者の確認・判断を待っている事項と、各段階の作業記録を
一か所にまとめた一覧。番号は確認待ち全体で通しとする。
（旧 `notes-stage5-6-pending.md` と `notes-stage7-25-pending.md`
を統合したもの。）

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
4. **BIN-DISTRO-MIPSEL / BIN-DISTRO-MIPS64 / TOOL-MUSLCC-N32**:
   段階 7 着手時点で未確認のまま残っている項目（上記 1–3 と合わせて
   `references.md` を参照）。
5. 段階 7（ARM）で追加した台帳項目の確認待ち:
   BIN-DISTRO-ARMV5L / BIN-DISTRO-ARMV7L（BusyBox 1.31.0、
   `.testdata/bin-distro-armv5l|armv7l`）、SRC-LINUX-ARM-UAPI
   （v6.6 の `syscall.tbl` と `uapi/asm/unistd.h`、
   `.testdata/uapi-arm`）。いずれも用途 T で、
   所有者の確認欄は空欄のまま。
6. 段階 8（Power）で追加した台帳項目の確認待ち:
   BIN-DISTRO-POWERPC64 / BIN-DISTRO-POWERPC64LE /
   BIN-DISTRO-POWERPC（BusyBox 1.31.0 の ppc64 BE ELFv2・
   ppc32 BE と、Alpine 3.21.0 minirootfs ppc64le）、
   SRC-LINUX-POWERPC-UAPI（v6.6 の
   `arch/powerpc/kernel/syscalls/syscall.tbl`、
   `.testdata/uapi-powerpc`）。いずれも用途 T で、
   所有者の確認欄は空欄のまま。
7. 段階 11（s390）で追加した台帳項目の確認待ち:
   BIN-DISTRO-S390X（BusyBox 1.31.0 の s390x BE、
   `.testdata/bin-distro-s390x`）、SRC-LINUX-S390-UAPI
   （v6.6 の `arch/s390/kernel/syscalls/syscall.tbl`、
   `.testdata/uapi-s390`）。いずれも用途 T で、
   所有者の確認欄は空欄のまま。

### 所有者の作業

8. **段階 6 の完了記録**: タグの規約は廃止。段階の完了はコミットで表し、
   検証の要点は完了のコミットの本文に書く（dev-workflow「検証の記録」）。
   本文に転記する検証結果は後半の「検証記録（段階6）」に残す。

### 仕様・設計の判断

9. **`--root` 時の ELF パス解釈**: 実行対象のパスをゲスト名前空間として
   解決する実装にした（chroot と同じ規則。`resolve_guest_path_links`）。
   ホストパスで渡す呼び方とは互換でない点に注意。x86/mips は `--root`
   未対応のため影響なし。この解釈で確定してよいか。
10. **重いテストのバイナリ命名**: oracle 系の重いテストバイナリ名は
    `heavy_oracle_llvm` で各パッケージ共通とした。roadmap の S7-以降の
    命名（`heavy_oracle_arm` 等）はその段階でこの規約に揃えるか、
    個別名を採るか。
11. **R6 コンパクト分岐の 2R 形式の `rs>rt`**: BLEZ/BGTZ/BLEZL/BGTZL 群の
    2R 命令（BGEUC/BLTUC/BGEC/BLTC）は、`rs!=0 && rs!=rt` をすべて受ける。
    SPEC-MIPS-R6 の符号化表では `rs>rt` が予約の可能性があり、QEMU は寛容に
    受理する（本実装も同じ）。仕様書の条文で `rs>rt` が予約ならデコードで
    落とすよう厳格化するか判断したい。
12. **o32 `mmap` の旧引数順**: o32 の mmap（番号 90）は fd/offset を
    スタック引数で受ける。実装は `args[4]`/`args[5]`（スタック経由）と
    してあるが、glibc の実使用は `mmap2`（210）。旧 mmap の挙動差異は
    テスト不足。
13. **`polyisa-host` の OS 依存 API**: `Stat`/`pread`/`pwrite`/`dirent_ino`/
    `symlink` を host クレートに集約した（cfg 規則対応）。`std::os::unix`
    を `os-linux` で使わない方針でよいか確認したい（x86 側は `std::fs` の
    portable API のみで stat を組み立てている）。
14. **`lui` の厳格化の緩和**: LUI の rs フィールドは 00000 固定が正しい
    （旧実装は任意値を許容していたため修正）。pre-R6 で rs!=0 の 001111 は
    LUI ではなく予約として扱うようになった。実シリコンの受理挙動と異なる
    可能性は低いが、互換性のために緩めたい場合は別途検討する。
15. 段階 7（ARM）の実装スコープ判断:
    - 対象は A32（ARM 状態）のみ。Thumb/Thumb-2 と NEON は
      実バイナリのエントリが ARM モードで始まること、試作の
      粗分類デコーダとの整合のため今回の範囲外とした。
      Thumb 命令が出たら未実装として報告する。ロードマップは
      「最初の範囲」に Thumb-2 と NEON を挙げているので、
      これらをいつ足すかは所有者判断。IT ブロックも Thumb
      側の話題であり同時に扱う。
    - デコーダは大域の粗分類（Insn=領域）で、細かい振り分けは
      `sem` の各エントリ内の固定ビット検査で行う。oracle テストも
      領域までの突き合わせとし、udf は media 領域（恒久的未定義は
      意味論側の責務）とした。
    - MCRR/MRRC（`vmov d0, r0, r1` 等のレジスタ対転送）は
      110 帯の `cp_ls` 領域に入る（Arm ARM の解読表どおり）。
    - kuser ヘルパー領域（0xffff0fa0 等）は未実装。
      musl 1.31 は `mrc p15, c13` の TLS 経路を選ぶため
      実バイナリでは未到達。将来の配布物で要るなら段階 25 の
      OS パーソナリティ側で扱う。
16. `__ARM_NR_cmpxchg` の番号は UAPI ヘッダに現れない
    （`arch/arm/include/asm/unistd.h` の内部定義、
    `__ARM_NR_BASE+0xfff0`=0xffff0）。初版は誤って連番の
    0xf0007 を置いていた。musl では kuser ヘルパー経由が
    主経路のため影響は限定的だが、カーネルの定義に合わせて修正済み。
17. 段階 8（Power）の実装スコープ判断:
    - 主対象は ppc64le の ELFv2 ユーザーモード。ppc64 BE は
      ELFv2 スタティック BusyBox で検証済みだが ELFv1
      （関数記述子・`.opd`）は未実装。ppc32 は番号表と
      testdata 取得までで、意味論・ローダは未着手。
    - デコーダは主オペコード（6 ビット）の粗分類で、XO・
      拡張ビットの細分は `sem` 側が担う（ARM と同じ構造）。
    - syscall 番号は ppc64 系の tbl（32 行は compat 専用）。
      `getrlimit` は 76 が ni-syscall のため ugetrlimit(190)
      を採用。`sync_file_range` は ppc64 の
      `sync_file_range2`(308) に対応。
    - 残件: musl 動的リンクの BusyBox で、free/dequeue
      経路のブックキーピングがずれて `.long 0` の罠に落ちる
      アプレットがある（`echo`・`printf %d`・`id` 等）。
      CA・mfocrf・ロードストア・予約の見直し後も残っている
      ため、別の意味論差分の可能性が高い。動的アプレットの
      テスト一覧は通るものに絞ってある。
    - 残件: ISA 3.1 の接頭辞付き命令は未実装（ロードマップの
      範囲内。musl/Alpine ppc64le の現バイナリでは未到達）。
    - 残件: SPE（e500）・十進 FP・Book E 系は未着手。
18. 段階 11（s390）の実装スコープ判断:
    - 主対象は z/Architecture 64 ビットのユーザーモード。
      ESA/390 31 ビットは AMASK・`la` 系の裸テストで
      カバー（z/Architecture ファシリティは CPU モデル
      z900..z13/generic/esa390 で機能単位に切る）。
    - BFP（二進浮動小数点）は f32/f64 を実装。拡張
      （128 ビット）は f64 近似で片方のレジスタだけを
      読み書きし、実利用面はカバー（GAP）。16 進浮動
      小数点と十進演算（DFP・パック十進・`ed`/`mk` 系の
      文字・十進ユーティリティ）は段階 10 基盤の提供前の
      ため今回の範囲外。未対応命令は `unimp` で報告する。
    - `MADBR` 系（RRF-a）はフィールド配置が `B3 ff|r1 0|
      r2 r3` で、2 値 RRE の `r1|r2` 並びと異なる点に注意
      （初版が全フィールドをずらして読み、busybox `seq` の
      無限ループを引いた不具合を修正済み）。
    - BIN-DISTRO-S390X の既知の不具合: このビルドは
      long double が 8 バイトで、musl の 128 ビット前提の
      `fmt_fp`/`frexpl` と不整合し、`%f`/`%e`/`%g` の
      出力が実機でも壊れる（例: `printf %f 2.0`→
      `7.500000`、`seq 3` の数値部分）。エミュレーションは
      そのまま再現する方針で、テストの期待値はこの経路を
      避けてある。armv5l の同版 BusyBox は正しく出力する
      ことを確認済み（フィクスチャ固有の問題）。
    - 残件: `wait4`/`clone` 系のプロセス生成は未実装
      （`sh` はフォークした子側で実行するため出力は出るが
      wait が ENOSYS）。ソケット系・`execve`・シグナル
      フレームも未着手。

- 段階 8 レビュー（サブエージェント）の対応記録:
  - 修正済: isel の選択極性（C1, 逆だった）、OE 形式の
    基底 XO 照合（C2）、bclrl が新 LR を飛び先に読む誤り
    （C3）、lve*/stve*/lvsl/lvsr の未実装（C4, 実装追加）、
    statx レイアウト（C5）、sysinfo レイアウト（C6）、
    addic/subfic/mulli/cmpwi/cmplwi/tdi/twi の r0=0 読み
    （M2）、neg の CA 破壊（M3）、vslo/vsro の 8 倍シフト
    （M4）、div OE 形式の OV 欠落（M16）、access 系の
    mode 無視（M14）、statfs64/fstatfs64 の引数位置
    （M15）、powerpc 固有 ioctl 定数（M1）。
  - 未対応（確認待ち・次段階案件）: FPSCR/FPCC/CR1 の
    更新と RN 反映（M7/M8/M9）、lxvl/stxvl の LE 配置
    （M6）、vinsert*/xvcvsxdsp/xscv*dsp/xxbr*/vsld/vsrd/
    lqarx/stqcx/stq/mcrxrx/ftdiv/mfocrf 複数フィールド/
    lswx カウント 0（M5/M10/M11/M12/Minor 群）、
    xvmadd 系の単一丸め化（M13）、musl 動的アプレットの
    a_crash 残存（activate_group の assert(!avail_mask)
    破れ。head meta が prev=next=自己でありながら
    ctx.active 残留。queue/dequeue のリスト操作または
    lwarx/stwcx 経路の差分を要調査）、TCGETS 系の
    termios 実書き込み、O_NOFOLLOW 等 open フラグ、
    dirfd!=AT_FDCWD、epoll/poll、rt_sigpending、
    getresuid、setrlimit、sched_getaffinity、prctl、
    lswi/stswi 残件、scv 区別、ppc32 意味論、ELFv1。
  - レビュー報告の「検証済み正しい」: bo_ok/CTR/CR、
    larx/stcx 幅、ldx/stx/bswap_ls、shift 系、
    lane/put_lane 系ヘルパ、vperm/vsel/vsldoi、
    x31_arith 大体、lq、put_stat、uname、CR0.SO。

### 未完了・保留の作業

19. **FP/AdvSIMD の残り（aarch64）**: FP スカラー一式（算術・比較・
    変換・条件選択）は実装済み。AdvSIMD は musl の動的リンクが要求した
    部分集合（dup/ins/umov/movi・load/store 系）のみで、ベクトル演算系は
    未実装。必要になった時点で台帳とともに追加する。
20. **busybox の MIPS 版・n32/n64 の実バイナリ検証**: `heavy_program_mips`
    は裸 ELF（write/exit のみ）。実バイナリ検証を開始し
    `.testdata/bin-distro-mipsel`（o32 LE）と `.testdata/bin-distro-mips64`
    （n64 BE）を取得済み。台帳登録と配布物の正式選定は未了。
    現状: cop1 (FPU) を実装済み（FR=1 全幅・約70命令）。o32 は
    `echo`/`uname`/`date`/`id`/`ls`/`ls -l`/`cat`/`head`/`whoami` が
    動作（`/tmp` のような千件級ディレクトリは整形処理が O(n²) で
    ステップ上限に達するのみ）。n64 BE は
    `echo`/`uname`/`uname -a`/`cat`/`wc`/`basename`/`dirname`/`seq`/
    `yes`/`true`/`pwd`/`date`/`head`/`id`/`id -un`/`whoami` に加え
    `ls`/`cut`/`sed`/`grep` の実処理も動作するようになった。
    大きな根因は二つ。(1) `slt`/`sltu`/`slti`/`sltiu` と分岐・トラップ系の
    符号比較（`cmp_regs`/`cmp_zero`）が 64 ビットモデルでも被演算子を
    32 ビットに正規化し、上位アドレス同士のポインタ比較を誤判定して
    いた（`sext_w`/`zext_w` で全幅比較へ修正済み）。
    (2) `nor`/`xor` 等の 64 ビット論理演算・`andi`/`ori`/`xori`・
    `sra`/`srl` 系・`mul`/`ext`/`ins`/`seb`/`seh`/`wsbh`/HI・LO 系に
    32 ビット結果正規化（`mask32`＝is64 時 sext32）が混在し、
    `~(1<<36)` のような値の上位ビットが失われて musl malloc の
    binmap/unbin が壊れていた。「32 ビット結果命令のみ `mask32`、
    64 ビット演算は全幅」を徹底して修正済み（`dsllv_nor_dsra32_
    unbin_mask` 等の回帰テスト追加）。
    ELF 自動モデル選択も修正: flags=0 の実用バイナリはロード
    インタロック前提でスケジュールされているため `mips32r2()` を
    選ぶ。真の R3000 ロード遅延は `--cpu mips:r3000` で選択可能
    （`elf_flags_pick_load_delay`/`r3000_model_keeps_load_delay`）。
    既に確定させた修正: `do_readv`/`do_writev` の iovec ストライド
    （`w`→`2*w`）、`getdents64` の fd ごとのディレクトリ位置追跡、
    `do_brk` の既マップページ上書き、`mmap_next` の衝突回避、
    `sendfile`/`sendfile64`（cat 用、offset==NULL）の実装。
    回帰テスト: `n64_readv_iovec_stride`・`getdents64_advances_position`
    を `mips::sys::tests` に追加。
    `cut --version` のエラー出力経路も解決: busybox は usage テキストを
    bzip2 圧縮して保持し、`bb_show_usage` が bunzip2 で展開する。
    33 KiB 出力のデコードが 5M ステップを超えるだけで、意味論のバグ
    ではなかった（`STEP_LIMIT` を 256M に引き上げて完走を確認、
    usage 出力と終了コード 1 が正しい）。
    n32 実バイナリは musl.cc の `mips64-linux-musln32-cross` で
    生成した BE ELF32（abi2/mips3、flags 0x20000027）で検証。
    malloc/free・fopen/fclose・ファイル読取・`uname`・アロケータの
    反復チャーン（free/malloc 200 回）まで動作することを確認した。
    当初 exit 経路で `get_meta` 内の `teq`/PageFault に落ちていたが、
    原因はエミュレータ側の初期スタック構築だった: `build_initial_stack_ws`
    が BE+ワード幅4B のとき 8 バイト値の**上位**4 バイトを書いており、
    argc/argv/envp/auxv がすべて 0 化していた。musl は auxv を
    AT_NULL 直後と誤認して `libc.page_size=0` のまま動き、mallocng の
    `needed += -needed & (pagesize-1)` が `needed=0` を返して
    `mmap(0,0)` → `maplen=0` のメタが生まれ、free 時に
    `get_meta(g->mem)` が先行ガードページを読んで死亡する連鎖だった。
    BE は下位バイトを書くよう修正（`stack32_be_writes_low_bytes`
    回帰テスト追加）。なお o32(LE)・n64(ws=8) は無影響。
    残作業: 台帳登録（上記 #4 の BIN-DISTRO-MIPSEL・
    BIN-DISTRO-MIPS64・TOOL-MUSLCC-N32）。

## 段階ごとの作業記録

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

### 段階 7（ARM、A32・EABI）

- 追加: `guests/arm`（spec/armi.rs = 領域の粗分類 ISADL、
  src/sem.rs ≈ 3000 行の意味論。条件実行、PC+8 読み、
  LDM/STM、乗算系、排他ロード/ストア、バリア、CP15 TLS、
  VFP 転送・f64 演算・変換・比較を実装）。
- 追加: `crates/os-linux/src/arm.rs`（EABI 番号表 ≈ 450 件、
  name 表、errno/フラグ）と `crates/os-linux/src/arm/sys.rs`
  （syscall 機械。ファイル・mmap・brk・時計・uname・
  getdents64・set_tls/cacheflush 等）。
- 追加: `crates/cli/src/run_arm.rs`（ELF32 e_machine=40 の
  ディスパッチ、armv5/armv7 モデル、--cpu 選択）。
- テスト: `guests/arm/tests/sem.rs`（条件実行・PC+8 の
  意味論テスト）、`heavy_oracle_llvm.rs`（llvm-mc 符号化と
  領域の突き合わせ）、`heavy_abi_arm.rs`（UAPI tbl との
  番号突き合わせ ≈ 250 名）、`heavy_program_arm.rs`
  （clang -nostdlib の hi/fib と両 busybox のコマンド群、
  VFP 経由の awk 含む）。
- 修正: arm の番号表が `vserver`(313) の欠落で 313–399 帯が
  全て -1 になっていたのを UAPI 突き合わせで発見・修正
  （openat=322 等に是正。name 表も同時に修正）。
- 修正: `__ARM_NR_cmpxchg` を 0xf0007 → 0xffff0 に是正。
- refs:check ok（113 ids）、devtool check ok、
  全ワークスペースのフルテスト実施済み（件数はコミット時点の
  出力を参照）。
- レビュー（サブエージェント）実施。指摘を受けて修正:
  - 並列加減算のレーンマスク欠落・GE フラグ未実装・
    halving の符号扱いを修正し、UH（0x67）を追加。
  - BFI/BFC のソースレジスタ面（[3:0]）と msb 面
    （最上位ビット位置）、SBFX/UBFX/BFI の top8 に
    msb[4] が入る dispatch 穴を修正。
  - SMLA/SMLAW/SMLAL の Ra/Rd/RdHi/RdLo フィールドと
    SMULxy/SMLAxy の半選択ビット（x/y）を修正。
  - UMAAL の累算を RdLo+RdHi の二項和に修正。
  - QSUB/QDADD/QDSUB のオペランド順と QD* の二倍飽和、
    SSAT16/USAT16 のシフト面なし・usat16 の imm ビット
    飽和を修正。VFP 即値展開（10 bit）と VNMLS、
    REV16 のバイト並びも修正。
  - レジスタシフト版 TST/TEQ/CMP/CMN を misc 落ちから
    データ処理へ振り分け。
  - linux 側: pwrite64 のオフセット書き込み、
    truncate64/ftruncate64 の EABI 整合ペア（r2:r3）、
    statx の path/flags 面、getpriority の戻り値、
    unimpl_path（実際は削除処理）を rmdir/link/linkat の
    実装に置き換え。
  - 回帰テスト 10 件を `guests/arm/tests/sem.rs` に追加。
  - 上記修正で `heavy_program_arm::distro_commands` も通過。
    段階 7 の完了条件 3 件すべて green。
- レビュー残件（所有者判断・段階横断）:
  - Thumb/Thumb-2・NEON の実装時期（確認待ち #15 と同一案件）。
  - ELF `e_flags`/`--cpu`/HWCAP/uname の整合見直し。
  - kuser ヘルパー・ARM プライベート cmpxchg（現状 ENOSYS）。

### 段階 8（Power、ppc64le・ELFv2）

- 追加: `guests/power`（spec/poweri.rs = 主オペコード粗分類
  ISADL、src/sem.rs の意味論。整数・CR/XER・ロードストア・
  予約・分岐・FP（単精度/倍精度）・VSX/AltiVec の主な
  ユーザーモード命令を実装）。
- 追加: `crates/os-linux/src/power.rs`（ppc64 番号表 ≈ 220 件と
  name 表）と `crates/os-linux/src/power/sys.rs`（syscall 機械。
  CR0.SO のエラー返し、r0=番号・r3–r8=引数・r3=戻り値、
  ゲストルートのパス解決）。
- 追加: `crates/cli/src/run_power.rs`（ELF64 e_machine=21 の
  ディスパッチ、EI_DATA でエンディアン選択、PT_INTERP 動的
  ローダ、ELFv2 入口 r12・TOC 規約、フォルト駆動の
  スタック成長、`--cpu`/`--root` 配線と OS 注入形
  `run_elf_power_sys`/`run_elf_power_sys_root`）。
- テスト: `guests/power/tests/sem_unit.rs`（CA/CR/XER/
  mfocrf 等の単体）、`heavy_oracle_power.rs`（llvm-mc
  符号化と領域の突き合わせ。lxv/stxv/lq は llvm-mc 23 が
  出せないため手符号の語で領域だけ確認）、
  `heavy_abi_power.rs`（v6.6 tbl との番号突き合わせ 216 名、
  abi 列は common・nospu・64）、`heavy_program_power.rs`
  （clang -nostdlib の hi/fib、ppc64 BE スタティック BusyBox、
  Alpine ppc64le minirootfs の動的 BusyBox 群）。
- 修正: `x31_arith` が全 XO で CA を更新していたのを、
  carry 生成形（subfc/addc/neg/subfe/adde/subfze/addze/
  subfme/addme）だけに限定。musl の整数書式（`printf %d`
  のパディング等）が直った。
- 修正: `mfocrf` がフィールドを FXM 面（bits 12–19）から
  読んでいたのを、命令のフィールド面（bits 23–25）に修正。
  `seq`/`awk` 等の CR 依存経路が通るようになった。
- 修正: VSX/FP 群の意味論（xvcvdpsp、xxpermdi/xxsldwi、
  xxspltw/xxinsertw、xsmaxjdp/xsminjdp、xvmadd 系の
  msub/nmsub、xs*dp スカラ madd、mffs/mtfsb/mtfsfi/mcrfs、
  fsel/frsqrte）を広く是正。
- S8-1..3 を実テスト名で判定に反映。段階 8 の完了条件
  3 件は green。
- 残件（確認待ち #17 と同一案件）: musl 動的の allocator
  teardown 差分、ISA 3.1 接頭辞付き命令、ppc32/ELFv1/SPE。

### 段階 9（IR と JIT）

- 追加: `crates/ir`（`inst.rs` = `Wid`/`Id`/`Inst`/`Ir`/
  `Recorded` の SSA IR、`rec.rs` = `Backend` を実装する
  記録器 `IrBackend`、`exec.rs` = 任意の `Concrete` バックエンド
  上で IR を解釈する `exec`、`opt.rs` = 定数畳み込み・コピー
  伝播・CSE・死んだストア除去・DCE を回す `optimize`）。
  `Concrete` は `Backend` に「値 ⇔ u128」「Bool ⇔ bool」
  「Exit → ExitClass」の橋を足すだけの小さい trait。
- `IrBackend` の方針: `if_then_else`/`if_then` は両枝を
  `Inst::If` として記録し、`raise` は `IrExit::Raise`、
  `abort` で `Exit`/`Unimpl` を確定する。helper と parameter は
  まだ IR に落とさず、helper は `Unimpl`（ブロック境界で
  インタプリタへ戻す）、parameter はインタプリタと同じく
  panic。フォールトし得るメモリ操作には `pc`/`next` を焼く。
- 追加: `crates/host`（`exec_mem.rs` = mmap で RW 確保→
  書き込み→`mprotect` で RX にする W^X の実行メモリ）。
- 追加: `crates/jit`（`ctx.rs` = `#[repr(C)]` の `RtCtx` と
  例外の詰め替え、`rt.rs` = 生成コードから呼ぶメモリ/重い
  演算のランタイム関数、`x64.rs` = 命令エミッタと IR→x86-64
  の `compile`、`lib.rs` = PC を鍵にしたブロックキャッシュ・
  熱カウンタ・記録→IR 解釈→コンパイル→呼び出しの `Jit`）。
- 実行経路: ブロックは `Translate::record` で `Recorded` にし、
  熱くなるまでは `polyisa_ir::exec` で解釈し、しきい値に
  達したら `x64::compile` して `BlockFn` を呼ぶ。出口は
  `BlockExit::Next/Raise/Unimpl` に戻し、`Unimpl`・例外・
  トラップ境界は常にインタプリタ側の処理へ戻す。コード
  ページへの書き込みは `invalidate` でブロックを破棄する。
- x64 レイアウトの修正: 値スロットとスクラッチ領域の開始を
  16 バイト整列（`SCRATCH=16`、`VALS=80`）に直し、`u128`
  の読み書きで misaligned pointer dereference していた
  クラッシュを解消。
- ランナ統合（既定は従来どおりインタプリタ。`POLYISA_JIT`
  で JIT が有効）:
  - AArch64: `dispatch_a64<B: Backend>` に意味論を抽出し、
    `A64Tx` が 32 命令まで記録（`svc`・未対応デコード・
    フロー操作でブロックを閉じる）。
  - ARM: `dispatch_a32<B: Backend>` に抽出し、`ArmTx` は
    CPSR から条件式を作って `if_then` で包むことで条件付き
    実行を記録。`svc`/未対応で境界。
  - x86: 既存のデコードと `dispatch` をそのまま `X86Tx` に
    使い、トラップ/syscall の手前ではインタプリタへ戻して
    `TrapHandler`・`after_step` の振る舞いを保つ。
- テスト:
  - `crates/engine/src/interp.rs` に「同じ意味論を
    インタプリタ直接と 記録→optimize→exec で比べる」
    単体テスト 6 件（算術/メモリ/if 両枝/分岐・ジャンプ/
    例外/メモリフォールト）。
  - `crates/ir/src/opt.rs` に pass 別の単体テスト 10 件
    （畳み込み・コピー伝播・CSE・DSE 3 件・Get 転送・DCE・
    定数条件 If の展開）。
  - `crates/jit/src/lib.rs` に生成コードを実際に呼ぶ
    スモーク 2 件（`Next` 経路と `Raise` 経路）。
  - `crates/cli/tests/heavy_jit_diff.rs` に 3 ISA（AArch64・
    ARM・x86-64）の interpreter vs JIT 差分テスト。
    clang -nostdlib の小さい静的 ELF（fib→`55` 表示）を
    両経路で走らせ、最終状態・出力・終了を突き合わせる。
    `reqs.rs` に `heavy_jit_diff`（clang 必須）を登録。
- 設計からの明示的な範囲:
  - helper/parameter の IR 化は未対応（該当ブロックは
    インタプリタへフォールバック）。正しさ優先で速度は追わ
    ない。
  - フォールト境界を跨ぐメモリ操作の移動はしない
    （DSE も Store/Exit の手前の Set は消さない）。
  - 生成コードの最適度は低い（値スロット経由・重い演算は
    ランタイム呼び出し）。オラクルとの一致を優先。
- 完了条件: `heavy_jit_diff` の 3 件が green。

### 段階 11（s390x・z/Architecture、ESA/390 31 ビット）

- 追加: `guests/s390`（`spec/zarch.rs` = 先頭バイトと
  サブオペコードの粗分類 ISADL、CPU モデルは
  esa390/z900/z990/z9ec/z10ec/z196/zec12/z13/generic、
  機能フラグは zarch/long-disp/ext-imm/hfp/dfp。
  `src/sem.rs` = 形式別の意味論。命令長は先頭 2 ビットの
  2/4/6 バイト、BE 可変長フェッチ、AMODE は AMASK で
  31 ビットをマスク）。
- 追加: `crates/os-linux/src/s390.rs`（番号表 =
  `syscall.tbl` の common/64 行）と `s390/sys.rs`
  （`svc 0`、番号 r1・引数 r2..r7・戻り値 r2。
  write/writev/read/open/stat 系/mmap/brk/umask 等）。
- 追加: `crates/cli/src/run_s390.rs`（ELF ロード、
  BE 初期スタック、`POLYISA_S390_*` の調査フック）。
  フィーチャ `guest-s390` で有効。
- テスト:
  - `guests/s390/tests/bare_s390.rs` 4 件（z/Arch 64
    ビットループ、全アドレスフォールト、ESA 31 ビット
    AMASK、`la` 系 AMASK）。
  - `guests/s390/tests/heavy_oracle_s390.rs` 2 件
    （llvm-mc SystemZ とのデコード突き合わせ、命令長）。
  - `guests/s390/tests/sem_unit.rs` 16 件。
  - `crates/os-linux/tests/heavy_abi_s390.rs` 1 件
    （UAPI tbl との番号突き合わせ。`sys` 実装だけ
    `guest-s390` 機能の内側にし、番号表は機能なしで
    使える形にした）。
  - `crates/cli/tests/heavy_program_s390.rs` 3 件
    （nostdlib hello、再帰 fib=55、BusyBox アプレット
    9 コマンド）。`reqs.rs` に 3 バイナリ分を登録。
- 実機バイナリから潰した意味論の不具合:
  - `LNR`/`LNGR` が `x|符号` で負の絶対値を近似し、
    0→INT_MIN に化けていた（busybox `basename` の
    full_write が 0 扱いになる原因）。符号なし減算と
    条件選択で置き換え。
  - `MADBR` 系（RRF-a）のフィールド配置ずれ（確認待ち
    #18 の通り。`seq` の無限ループの原因）。
  - `MVHHI`/`MVGHI`/`MVHI`（SIL、0xE5）のサブ
    オペコードが byte0 を読んでおり常に `unimp`
    （fib テストの失敗原因）。
  - RXF（`ed`）の `MAEB`/`MSEB`/`MADB`/`MSDB` が
    先に並んだ 2 値演算のアームに吸われて到達不能に
    なっていたのを、除外して通した。
- S11-1..4 を実テスト名で判定に反映。段階 11 の
  完了条件 4 件は green。
- 残件（確認待ち #18 と同一案件）: 128 ビット拡張 BFP の
  実値、HFP/DFP/パック十進、プロセス生成系 syscall、
  ソケット、シグナルフレーム、`EX`/`EXRL` の一部、
  SIE/特権命令（esa390 モデルの裸検証範囲のみ）。

### 段階 12（WebAssembly 1.0/2.0 + WASI preview1）

- `guests/wasm` は機械語ゲストと同じ層のクレートとして
  `decode`/`validate`/`exec`/`wat`/`wast` を
  持つ。`decode` は `\0asm` バイナリ、`wat`/`sexpr` は
  WAT/WAST のテキストを読む。仕様スイート
  （`.testdata/wasm-spec/test/core`）は
  `heavy_conformance_wasm_spec` が `wast::Runner` で
  全ディレクティブを採点する。
- WASI preview1 は `crates/os-wasi` に OS 人格として
  実装し、`wasi_snapshot_preview1` / `wasi_unstable` の
  インポートを host 関数で供給する（`fd_write`/
  `fd_read`/`fd_close`/`fd_seek`/`fd_tell`/`fd_prestat_*`/
  `fd_fdstat_get`/`fd_filestat_get`/`fd_readdir`/`path_open`/
  `args_*`/`environ_*`/`clock_time_get`/`random_get`/
  `proc_exit`）。fd 表と VFS は kernel の概念を共有するが
  依存は `os-wasi → kernel` 方向のみ。
- `cli` はバイナリ先頭の `\0asm` で WASM を検出し
  `run_wasm` に振り分ける。`--root` は preopen fd 3、
  CLI argv は `args_get`/`args_sizes_get` で見える。
  `_start`（コマンド）/ `_initialize`（リアクター）を
  探して実行し、`proc_exit` はトラップで運ぶ。
- 完了条件の対応テスト: S12-1 =
  `heavy_conformance_wasm_spec`（guest-wasm）、
  S12-2 = `heavy_diff_wasmtime`（cli、wasmtime 外部
  ツールがあれば出力比較）、S12-3 =
  `heavy_program_wasi`（cli。wasi-sdk/clang が無い
  環境では `fd_write`+`proc_exit` を import する手組
  モジュールで検証）。
- スイート採点では範囲外の提案機能（module linking、
  GC・function-references の完全な型体系、tail-call、
  SIMD、threads、exception handling 等）は
  `skipped_named`/`skipped_regs` で skip に落とし、
  依存する後続ディレクティブのカスケード失敗を防ぐ。
  具象ヒープ型 `RefType::Idx` はデコードで受理し
  検証で型空間の範囲を見て内部表現の `Func` に正規化
  する（完全なヒープ型同一性は未実装）。
- 残件: 提案機能の完全実装は範囲外のまま。実値は
  f32/f64 の文字列→ビット変換で hex-float タイの
  1ulp 差が残る可能性がある。wasi-sdk/clang が無い
  環境では S12-3 は手組モジュール経路のみ。
- レビュー（サブエージェント 3 系）実施。指摘を受けて修正:
  - `table_inits` がインポート込みのテーブル空間で
    添字付けされていたのを定義テーブル起点に修正
    （インポートテーブルの上書き防止。回帰テスト
    `imported_table_init`）。
  - 宣言ローカルの個数上限 `u32::MAX` が decode 時に
    巨大確保を強いるのを連長表現化で回避（decode/
    validate/exec の 3 層）。テーブル確保は
    `try_reserve` 化し、確保失敗は grow→-1、
    インスタンス化→link エラー。
  - validate の関数ごとの Ctx deep clone を解消、
    非 null テーブルの init 必須化、`collect_refs` が
    `table_inits` を拾うよう修正、`ref.is_null` の
    オペランドを reftype 限定に。
  - インポート記述の table に `0x40` init 形式を
    malformed として拒否。`(ref ht)` 要素への
    `ref.null` 項目を invalid に。
  - WAT 受理の穴: フラット `br_table` の非ラベル
    原子で停止、孤立 `end`/`else` の黙殺をエラー化、
    `(offset …)` 等のフラット定数式受理、
    `call_indirect (type N)` の OOB パニック解消、
    param/local の `$id` 規則、if 折り畳み・import
    記述の末尾ゴミ拒否、sexpr の `\u{}` 桁溢れ・
    深さ上限・制御文字拒否。
  - wast 採点の穴: `assert_exhaustion` の文言照合、
    Trap/Link の種別保持（assert_trap↔unlinkable
    の混同解消）、`has_out_of_scope` の誤検出
    （`(ref func)` 等の 2.0 内構文・文字列中の走査）
    を修正。`(ref.func N)` の添字比較対応。
  - os-wasi: `resolve_under` を要素ごとの
    `symlink_metadata` 走査＋canonicalize で
    プリオープン外 symlink を NOTCAPABLE に
    （dirflags も反映）。`fd_readdir` の
    `bufused==buf_len` 切詰め、`random_get` の
    全量充填（32 KiB チャンク）、iovec 走査の
    u64 化、fd ごとの rights 保持と必須権検査
    （NOTCAPABLE）、`canonical_sig` によるインポート
    シグネチャ照合、ディレクトリへの write intent
    拒否（ISDIR/EXIST/NOTDIR/NOENT）、errno 表追加
    （NOSYS/OVERFLOW/NOTSOCK/STALE/DQUOT）。
  - 判明した誤指摘: memarg offset は仕様 3.0 の
    u64 読みが正（レビュー #24 は 2.0 前提の誤り。
    binary-leb128/address/align の suite で検証済み）。
    table init の `global.get` 束縛は imported 限定が
    正（table.wast:104 で検証済み）。
  - 追加テスト: `imported_table_init`・
    `malformed_wat_forms`（guest-wasm）、ctx.rs の
    readdir/symlink/rights 単体テスト（os-wasi）。
    os-wasi → host の dev 依存を追加（テストの
    symlink 作成用。依存規則・workspace.md 更新済み）。
  - スイート採点 28050/0/697 → 28053/0/694。

## 検証記録（段階6）

段階 6 の完了コミットの本文に転記するための実行結果。

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

## 進行ログ

### 17:30 UTC 時点

- e7affcc: 段階10+11 を同一コミットで push（エージェント途中停止のため）。
- 段階11 レビュー完了: C2（old_mmap ABI・EX/EXRL）、M28件
  （形式誤り・CC 表・幅/レジスタ保存・FP・stat レイアウト）。
  修正エージェント 7b96f65f が対応中。
- 段階10 レビュー（5d4378fa）・Power %f/アロケータ調査
  （29f66a52）・段階12 WASM 実装（18ae746d）が並行稼働。
- Power 動的 musl: `%f` 小数部消失（1.5→1.0、0.5 は正）と
  `%d`/echo で allocator assert の2件が未解決として残る。

### Power 動的 musl 2件の解決

段階8 レビュー記録の「未対応」2件はいずれも Power 意味論の
不具合が原因で、修正済み。

- `%f`/`%e`/`%g` の小数部消失:
  - 原因: `cmpi`/`cmpli`/`tdi`/`twi` が被演算子に `ra()`（(RA|0)
    規約、r0 を定数 0 と読む）を使っていた。ISA では即値形式の
    比較・トラップは `(RA)` であり、エンコードが r0 のときも
    格納値を読む。M2 の「r0=0 読み」修正がアドレッシング基底と
    同じ規約を即値比較に誤適用した退行（15a1637 では正、
    02b151e で混入）。
  - 症状: musl の `fesetenv`/fmt_fp 経路の `cmpwi r0,0`
    （PC 0x2…213c0 付近）が実 r0 を捨てて桁生成の繰り越し
    ストアを飛ばし、1 以上の値の小数部が全て 0 になった
    （`%f 1.5`→`1.000000`、`0.5` は正しい）。
  - 修正: `sem.rs` の `cmp_imm`/`cmpl_imm`/`trap_imm` を
    `ra()`→`g()` に変更。
- mallocng `activate_group` の `assert(!avail_mask)` a_crash:
  - 原因: Altivec（VMX）の VR 番号フィールドを VSR[32+n] に
    マップすべきところ、生の 5 ビットを VSR 番号として使って
    いた。`lvx`/`stvx`（X31 XO 103/231）と op4 系ベクタ命令
    （vperm/vsel/vsldoi/加減算等の全 VA/VX 系）が FPR 空間
    （VSR0-31）を読み書きしていた。
  - 症状: gcc は callee-saved の VR31（VSR63）を musl
    mallocng の `queue()` 用 `struct meta*` スプラット値の
    キャッシュに使う。alloc_group→alloc_slot→alloc_group の
    入れ子呼出で、内側の `stvx 31` が VSR31（f31）の値を退避し
    `lvx 31` が VSR31 へ復帰するため、外側呼出に戻った時点で
    VSR63 が内側の meta 値のままになる。その結果 `queue` の
    `stxvd2x 63,0,30` が `m->prev`/`m->next` に別の meta
    ポインタを書き、破壊された単一ノードの `avail_mask` 非零で
    `.long 0`（a_crash）に落ちた。
  - 修正: `x31_vsx_ls` の lvx/stvx を `xt`→`t+32` に、`x4` の
    VR フィールド（t/a/bb/各 c）を `+32` に変更。op4 で
    A フィールドをサブopcode として使う群（vext*/vctzd/vnegw/
    vprtybw=1538）と bcd 系（FPR 番号）は生フィールドを使う
    よう `t_raw`/`a_raw`/`bb_raw` を併置。
- 確認: `echo`・`printf %d`・`id`・`printf %f/%e/%g`・`ls`・
  `seq`・`sort`・`wc`・`uname` が正常終了し、
  `cargo test -p polyisa-cli --test heavy_program_power`（
  distro_commands_le_dynamic 含む 4 件）が全通過。
- 補足: `%a`/`%La` が invalid format になるのは BusyBox printf
  アプレット自体の制約で、エミュレーション不具合ではない。

## 参考

- 段階の完了条件は `design/roadmap.md` の各段階の表。
- 台帳の規則は `references.md` の冒頭。
- Linux UAPI 6.19（`syscall_o32.tbl`/`n32.tbl`/`n64.tbl`、`asm/unistd.h`）が番号表の根拠。
- R6 コンパクト分岐の分解規則は QEMU `gen_compute_compact_branch`
  （target/mips/tcg/translate.c）と LLVM Mips32r6InstrInfo.td の OPGROUP 表で確認した。
- R6 の SPECIAL3 LL/SC（0x36/0x26/0x37/0x27）と DAHI/DATI/DAUI は
  QEMU translate.c と LLVM Mips32r6InstrInfo.td で確認した。
