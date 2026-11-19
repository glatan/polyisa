# ロードマップ

この文書は、実装を進める段階の順序と、各段階の完了条件を定める。段階の順序は、共通の抽象の誤りをできるだけ早く見つけることを優先して決めた。抽象の誤りは、その抽象の上に実装した ISA の数だけ修正の費用が増えるからである。

## 順序の考え方

最初に一つの ISA で、ISADL からユーザーモードでのプログラムの実行までを一通り動かす。この ISA には RISC-V を選ぶ。RISC-V は、エンコーディングが規則的で ISADL の最初の実装に向き、公式の適合テストスイートがあり、手元の clang と rustup のターゲットでテスト用のプログラムを作れる。

次に、性質の大きく異なる ISA の小さな部分集合を試作し、共通の抽象が受け止められるかを確かめる。パケット（Hexagon）、バンドルと回転レジスタ（IA-64）、レジスタウィンドウと遅延スロット（SPARC）、モジュール構造とスタックマシン（WebAssembly）がその対象である。試作で抽象を直してから、本格的な ISA の実装を増やす。

共通の抽象は、三つの ISA ファミリ（RISC-V、MIPS、x86）を本格的に実装し終えるまで、確定させない。確定までは、抽象の変更を通常の変更として行う。確定させた後の変更は、変更の理由を設計文書とコミットの本文に書いて行う（ADR は新規に作らない。[docs/adr](../adr/README.md) を見る）。

## 段階

完了条件の表の「判定」は、次の三つの形のいずれかである。`テスト：` のあとに続ける名前は、判定に使うテストバイナリであり、バッククォートで囲んで「、」で並べる。名前は `crates/*/tests/` か `guests/*/tests/` にある `.rs` のファイル名から、拡張子を除いたものである。`所有者` は、テストでは判定できず、所有者が判定することを示す。`未整備` は、判定に使えるテストがないことを示す。

### 段階 5 以降

段階 5 以降は、一段階につき一つの対象に絞る。複数の ISA を一つの段階にまとめると、完了条件の判定を段階全体に閉じられず、遅れている ISA のために先に終わった作業を確定できないからである。段階の順序は目安であり、必要に応じて入れ替える。段階間に依存があるときは、その段階の冒頭に「前提」として書く。

各 ISA の段階では、その ISA の Linux ゲスト ABI（システムコール番号表、呼出規約、構造体と定数の表、シグナルフレーム、初期スタックと補助ベクタ）を実装する。Linux が動かない ISA と版の範囲は、裸実行環境で検証する。

判定が `未整備` の条件は、判定に使うテストの名前を条件の文に書く。テストはその段階の作業の中で作り、判定を `テスト：` に更新する。

段階 15 から 24 の各段階には、その節の末尾に作業計画がある。構成は各段階で共通であり、着手条件の整備、骨格、命令群、世代差・拡張、ABI・OS パーソナリティ、タイミング、残件整理の順に進める。各ステップの終わりにサブエージェントのレビューを挟み、レビュー後の修正のあとに push する。計画は作業の進行に合わせて更新し、確定したステップにはコミット番号を記録する。

### 段階 15：SPARC

- 版の範囲は V7、V8、V9 と VIS。レジスタウィンドウ（動的なレジスタ参照、ウィンドウ数は CPU モデルのパラメータ）、ウィンドウのあふれと不足は OS パーソナリティが再現
- 遅延スロット、annul ビット、遅延スロット内の分岐（DCTI couple）、ユーザーが使える ASI、PSTATE.AM のアドレスマスク
- sparc32 と sparc64 のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S15-1 | sparc64 のテストプログラムと配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_sparc`）。 | 未整備 |
| S15-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_sparc`）。 | 未整備 |
| S15-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_sparc`）。 | 未整備 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| SP1 | 着手条件: SPEC-SPARC-V9・SPEC-SPARC-PSABI の版確定、V7 の根拠資料の追加登録または範囲からの除外の決定、BIN 登録（sparc32・sparc64 配布物）、SST 類の既存適合データの有無の調査 | - | 98af983 |
| SP2 | `guests/sparc` の段階 2 の試作を本実装に差し替える骨格: CpuState（g/o/i/l レジスタ・CWP・PSR/TSTATE・PC/nPC）、機能（V7・V8・V9・VIS）とモデルの宣言、sem 層、ワークスペース配線 | SP1 | 85df434 |
| SP3 | デコード方式の決定: 32 ビット固定長の map/パターン。遅延スロットは PC/nPC として実行ループ側で表現 | SP2 | 85df434 |
| SP4 | `run_sparc` 実行ループ + bare 最小テスト | SP3 | 4c08ee8 |
| SP5 | 整数演算: add/sub/論理/シフト/sethi と、V8 の umul/smul/udiv/sdiv/mulscc | SP4 | 069ed0d |
| SP6 | load/store 全サイズ・ldstub/swap・ASI 指定形 | SP4 | 21fd504 |
| SP7 | 分岐・call・jmpl・return。annul ビットと遅延スロット内の分岐（DCTI couple） | SP4 | - |
| SP8 | ウィンドウ命令 save/restore・ta/tcc（V8 の Ticc を含む）・ユーザ ASR（rdy/wry、V9 の rdccr/wrccr/rdpc）。rd/wr psr や rett/done/retry は特権命令なので、ユーザーモードでは特権違反トラップの経路だけを実装する | SP4 | - |
| SP9 | V9 の追加: movcc/movr・64 ビット演算・PSTATE.AM のアドレスマスク・cas/casx・membar/stbar/flush・popc | SP5-8 | - |
| SP10 | FPU: ldf/stf/lddf・fadd/fsub/fmul/fdiv/fsqrt・fcmp・fcvt・fmov、V9 の fmovcc/fmovr と %fsr | SP4 | - |
| SP11 | VIS とユーザ ASI。V7/V8/V9 のモデル差を `when` 述語と挙動パラメータで切り分け | SP9,SP10 | - |
| SP12 | Linux ABI: sparc32/sparc64 の syscall 表、ELF、ウィンドウのあふれと不足を OS パーソナリティで再現 | SP11 | - |
| SP13 | `heavy_program_sparc`（配布物のコマンド群） | SP12 | S15-1 |
| SP14 | `heavy_abi_sparc`（UAPI 抽出値との照合） | SP12 | S15-2 |
| SP15 | `heavy_oracle_sparc`（llvm-objdump 差分） | SP11 | S15-3 |
| SP16 | 残件整理: 判定列の更新、未整備分の GAP 登録 | SP13-15 | - |

### 段階 16：Alpha

- 版の範囲は 21064 から 21364 までと、BWX、FIX、CIX、MVI の拡張。`AMASK` と `IMPLVER` は識別情報
- `CALL_PAL` の PAL コードの役割は OS パーソナリティ、浮動小数点の補完と非整列アクセスの補完は OS による命令の補完、8 KiB のページサイズ
- alpha のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S16-1 | alpha の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_alpha`）。 | 未整備 |
| S16-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| AL1 | 着手条件: SPEC-ALPHA-ARM・SPEC-ALPHA-CALLSTD の版確定、BIN 登録、GAP-0023 残項目の点検 | 段階 10 | - |
| AL2 | `guests/alpha` 骨格: CpuState（r0-31・f0-31・PC・PAL 関連状態）、機能（BWX・FIX・CIX・MVI）とモデル（21064-21364）の宣言、AMASK/IMPLVER を識別情報へ | AL1 | - |
| AL3 | デコード: 32 ビット固定長、形式別（Operate/Memory/Branch/CALL_PAL）のパターン | AL2 | - |
| AL4 | `run_alpha` 実行ループ + bare 最小テスト | AL3 | - |
| AL5 | 整数 Operate 系: add/sub/論理/シフト/比較/cmov・mb/wmb・rpcc/rc/rs | AL4 | - |
| AL6 | 乗除と拡張（BWX・FIX・CIX・MVI の世代差を `when` 述語で） | AL5 | - |
| AL7 | load/store・lda・非整列アクセス（ldq_u/stq_u）と補完経路 | AL4 | - |
| AL8 | 分岐・jmp/jsr/ret | AL4 | - |
| AL9 | 浮動小数点: load/store・四則・変換（IEEE/VAX 形式は段階 10 の実装を接続） | AL4 | - |
| AL10 | CALL_PAL を OS パーソナリティへ渡す経路（rduniq/wruniq の TLS 呼出を含む） | AL4 | - |
| AL11 | Linux ABI: alpha の syscall 表、ELF、8KiB ページ、浮動小数点補完と非整列補完の OS 実装 | AL10 | - |
| AL12 | `heavy_program_alpha`（配布物のコマンド群） | AL11 | S16-1 |
| AL13 | ABI 照合（SRC-LINUX UAPI、所有者確認）+ 残件整理・判定列更新 | AL12 | S16-2 |

### 段階 17：PA-RISC

- 版の範囲は PA-RISC 1.0、1.1、2.0 と MAX。命令アドレスキューと遅延分岐、無効化（PSW の N ビット）
- Linux のシステムコールはゲートウェイページへの分岐（特別なアドレスを経由する OS の呼び出し）
- hppa（32 ビット）のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S17-1 | hppa の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_parisc`）。 | 未整備 |
| S17-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| PR1 | 着手条件: SPEC-PARISC-11・SPEC-PARISC-20 の点検（確認済み）、PA-RISC 1.0 の根拠資料の追加登録または範囲からの除外の決定、BIN 登録、GAP-0023 残項目の点検 | - | - |
| PR2 | `guests/parisc` 骨格: CpuState（GR・CR・SR・IAOQ 前後・PSW）、モデル（1.0・1.1・2.0）の宣言 | PR1 | - |
| PR3 | デコード: 32 ビット固定長、opcode + completer フィールドの扱い | PR2 | - |
| PR4 | `run_parisc` 実行ループ: IAOQ の進行と無効化（PSW.N）+ bare 最小テスト | PR3 | - |
| PR5 | 算術・論理・比較（add/sub/comb/and/or/xor）、extract/deposit・シフト | PR4 | - |
| PR6 | load/store（空間レジスタ経由を含む）・ldcw/ldcws・mfctl（cr27 の TLS 読み出しを含む）・probe | PR4 | - |
| PR7 | 分岐: bv/be/bl、遅延分岐と nullify の条件 | PR4 | - |
| PR8 | システムコール: ゲートウェイページへの分岐という特殊経路（lws の CAS 規約を含む） | PR4 | - |
| PR9 | FP 命令と MAX 拡張 | PR4 | - |
| PR10 | Linux ABI: hppa の syscall 表・ELF・`heavy_program_parisc` | PR8,PR9 | S17-1 |
| PR11 | ABI 照合（SRC-LINUX UAPI、所有者確認）+ 残件整理・判定列更新 | PR10 | S17-2 |

### 段階 18：SuperH

- 版の範囲は SH-1 から SH-4A までと、SH-2 互換の J-core。SH-2A の 32 ビット命令はデコーダの入口の長さの規則で扱う
- SH-4 の FPSCR の PR、SZ、FR は実行モード。遅延スロット内の分岐はスロット不正命令の例外。gUSA は再開可能な不可分列
- sh4（両エンディアン）のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S18-1 | sh4 の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_superh`）。 | 未整備 |
| S18-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| SH1 | 着手条件: SPEC-SUPERH-SH2A・SPEC-SUPERH-JCORE の版確定、SH-3/SH-3E の根拠資料の追加登録または範囲からの除外の決定、BIN 登録（sh4 両エンディアン）、GAP-0023 残項目の点検 | - | - |
| SH2 | `guests/superh` 骨格: CpuState（R0-15・PC/PR/SR/GBR/VBR/MACH/MACL/FPUL・FP/FPSCR）、モデル（SH-1 から SH-4A・J-core）の宣言 | SH1 | - |
| SH3 | デコード: 16 ビット主体 + SH-2A の 32 ビット命令（デコーダ入口の長さ規則）。両エンディアンの語並び | SH2 | - |
| SH4 | `run_superh` 実行ループ: 遅延スロットとスロット不正命令の例外 + bare 最小テスト | SH3 | - |
| SH5 | 算術・論理・比較（add/sub/neg/and/or/xor/cmp 系）・lds/sts（PR/GBR/MACH/MACL/FPUL/FPSCR の転送） | SH4 | - |
| SH6 | load/store: レジスタ相対・GBR 相対・R0 相対・PC 相対リテラル | SH4 | - |
| SH7 | 分岐: bf/bt/bra/bsr/bsrf/jsr/rts/trapa と遅延スロット | SH4 | - |
| SH8 | 乗算・MAC（mul/macl/dmuls・MACH/MACL）・ext/シフト系 | SH4 | - |
| SH9 | SH-4 FPU: fmov/fadd/fsub/fmul/fdiv/fmac/ftrc/ftst。FPSCR の PR/SZ/FR を実行モードとして扱う | SH4 | - |
| SH10 | モデル差（SH-1 から SH-4A・SH-2A・J-core）を `when` 述語とパラメータで切り分け。gUSA と SH-4A の movli/movco、J-core の cas.l/shad/shld の扱いを決める | SH5-9 | - |
| SH11 | Linux ABI: sh4 の syscall 表・ELF・`heavy_program_superh`（両エンディアン） | SH10 | S18-1 |
| SH12 | ABI 照合（SRC-LINUX UAPI、所有者確認）+ 残件整理・判定列更新 | SH11 | S18-2 |

### 段階 19：LoongArch

- 版の範囲は LA32 と LA64、LSX、LASX、LBT の拡張。LBT が参照する x86 と ARM の状態は CPU 状態に含める。LSX、LASX、LBT の公式仕様（Reference Manual の Vol.2、Vol.3）は未刊行であり、公開されるまで拡張の実装は保留する（SPEC-LOONGARCH-VEXT）
- 初期の独自の ABI と本流の ABI はゲスト ABI の変種として区別する。`CPUCFG` は識別情報
- LA64 のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S19-1 | la64 のテストプログラムと配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_loongarch`）。 | 未整備 |
| S19-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_loongarch`）。 | 未整備 |
| S19-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_loongarch`）。 | 未整備 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| LA1 | 着手条件: SPEC-LOONGARCH-PSABI の版確定、BIN 登録、初期の独自 ABI と本流 ABI の区別の確認 | - | - |
| LA2 | `guests/loongarch` 骨格: CpuState（r0-31・f0-31・PC・CSR・fcc）、機能（LA32・LA64、LSX/LASX/LBT は機能旗のみ先に）とモデルの宣言 | LA1 | - |
| LA3 | デコード: 32 ビット固定長、LA32/LA64 の差 | LA2 | - |
| LA4 | `run_loongarch` 実行ループ + bare 最小テスト（LA32 は Linux 移植がないので裸環境で検証する） | LA3 | - |
| LA5 | 整数算術・論理・シフト・比較 | LA4 | - |
| LA6 | load/store・原子（ll/sc・am* 系） | LA4 | - |
| LA7 | 分岐・jirl・b/bl | LA4 | - |
| LA8 | CSR・例外・ertn、CPUCFG を識別情報へ接続、syscall/break・dbar/ibar・rdcntvl/rdcntvh/rdcntid/rdtime | LA4 | - |
| LA9 | FPU（単・倍・fcc による条件分岐） | LA4 | - |
| LA10 | Linux ABI: 独自 ABI と本流 ABI をゲスト ABI の変種として区別し、syscall 表・ELF・`heavy_program_loongarch` | LA8,LA9 | S19-1 |
| LA11 | `heavy_abi_loongarch` | LA10 | S19-2 |
| LA12 | `heavy_oracle_loongarch` | LA9 | S19-3 |
| LA13 | LSX/LASX/LBT の保留方針の確定（SPEC-LOONGARCH-VEXT 未刊行）+ 残件整理・判定列更新 | LA11,LA12 | - |

### 段階 20：OpenRISC

- 版の範囲は OpenRISC 1000 アーキテクチャの各版と浮動小数点の拡張。遅延スロットの有無は機能とする
- or1k のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S20-1 | or1k の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_openrisc`）。 | 未整備 |
| S20-2 | ABI 表が SRC-LINUX の UAPI と一致することを所有者が確認する。 | 所有者 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| OR1 | 着手条件: BIN 登録、GAP-0023 残項目の点検 | - | - |
| OR2 | `guests/openrisc` 骨格: CpuState（r0-31・SR・PPC/NPC・SPR）、遅延スロットの有無の機能旗 | OR1 | - |
| OR3 | デコード方式の決定（32 ビット固定長） | OR2 | - |
| OR4 | `run_openrisc` 実行ループ + bare 最小テスト | OR3 | - |
| OR5 | 算術・論理・シフト・比較（l.add/l.sub/l.and/l.sll/l.sf* 系）・l.cmov | OR4 | - |
| OR6 | load/store・l.lwa/l.swa・l.msync/l.psync/l.csync | OR4 | - |
| OR7 | 分岐・l.bf/l.bnf・l.j/l.jal/l.jr/l.jalr・l.sys/l.trap・l.mfspr/l.mtspr | OR4 | - |
| OR8 | l.mac・浮動小数点拡張 | OR4 | - |
| OR9 | Linux ABI: or1k の syscall 表・ELF・`heavy_program_openrisc` | OR8 | S20-1 |
| OR10 | ABI 照合（SRC-LINUX UAPI、所有者確認）+ 残件整理・判定列更新 | OR9 | S20-2 |

### 段階 21：IA-64

- 版の範囲は Itanium から Itanium 9700 系まで。128 ビットのバンドル、述語実行、回転レジスタとレジスタスタック（バッキングストアへの実際の書き出し）、NaT と ALAT
- システムコールは `break 0x100000` とゲートページの高速なシステムコール
- ia64 のゲスト ABI（Linux 6.7 で削除されたため、削除前のカーネルの ABI を対象にする）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S21-1 | ia64 の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_ia64`）。 | 未整備 |
| S21-2 | ABI 表が SRC-LINUX-66 の UAPI と一致することを所有者が確認する。 | 所有者 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| IA1 | 着手条件: SRC-LINUX-66 の点検（確認済み）、ia64 配布物の入手経路の確定（Linux 6.7 で ABI 削除済み）、GAP-0023 残項目の点検 | - | - |
| IA2 | `guests/ia64` の段階 2 の試作を本実装に差し替える骨格: CpuState（GR 128・回転領域・PR・BR・AR（ar.lc/ar.ec を含む）・NaT・ALAT・RSE 状態）、モデルの宣言 | IA1 | - |
| IA3 | デコード: 128 ビットバンドル（テンプレート・スロット・stop ビット）の ISADL 表現 | IA2 | - |
| IA4 | `run_ia64` 実行ループ: バンドル進行と RIP 管理 + bare 最小テスト | IA3 | - |
| IA5 | 整数算術・比較・述語生成・シフト/extr/mix 系 | IA4 | - |
| IA6 | load/store・ALAT（advanced load と check）・chk.s/chk.a・mf | IA4 | - |
| IA7 | 分岐: br.cond/br.call/br.ret/br.cloop/br.cexit/br.wexit・述語実行 | IA4 | - |
| IA8 | 回転レジスタ・レジスタスタック（alloc/st.spill/ld.fill/flushrs/loadrs/cover、RSE とバッキングストアへの書き出し） | IA4 | - |
| IA9 | FP（82 ビット形式・fcvt/fma 系。softfloat の拡張精度を接続） | IA4 | - |
| IA10 | システムコール: `break 0x100000` とゲートページ経由の高速呼出 | IA4 | - |
| IA11 | Linux ABI（SRC-LINUX-66 の UAPI）・ELF・`heavy_program_ia64` | IA10 | S21-1 |
| IA12 | ABI 照合（所有者確認）+ 残件整理・判定列更新 | IA11 | S21-2 |

### 段階 22：Hexagon

- 版の範囲は V5 以降の各版と HVX。パケットのステップ、`.new` オペランド、デュプレックス、定数拡張子、ハードウェアループ
- 複数のハードウェアスレッドを交互に実行する構造に対応する専用のタイミングモデル
- hexagon のゲスト ABI

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S22-1 | hexagon の配布物のコマンド群が、ゲストのルートを使って正しい出力を返す（テスト `heavy_program_hexagon`）。 | 未整備 |
| S22-2 | ABI 表が、UAPI ヘッダからの抽出値と一致する（テスト `heavy_abi_hexagon`）。 | 未整備 |
| S22-3 | llvm-objdump とのデコーダの差分テストが通る（テスト `heavy_oracle_hexagon`）。 | 未整備 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| HX1 | 着手条件: SPEC-HEXAGON-PRM-PREV の版確定、BIN 登録 | - | - |
| HX2 | `guests/hexagon` の段階 2 の試作を本実装に差し替える骨格: CpuState（r0-31・p0-3・USR・PC・LC/SA・GP・M0/M1・CS0/CS1・スレッド状態）、モデル（V5 以降の各版）の宣言 | HX1 | - |
| HX3 | デコード: パケット構造（1 から 4 命令・パケット終端ビット・duplex・constant extender） | HX2 | - |
| HX4 | 実行エンジンの接続: パケット単位の step（同時発行の意味論・`.new` オペランド）+ bare 最小テスト | HX3 | - |
| HX5 | 整数算術・論理・シフト・combine/mux 系 | HX4 | - |
| HX6 | load/store・memop・`.new` 書き込み | HX4 | - |
| HX7 | 分岐・jump/call/jumpr・述語付き実行・allocframe/deallocframe/dealloc_return・endloop・trap0 | HX4 | - |
| HX8 | ハードウェアループ（loop0/loop1、LC/SA） | HX4 | - |
| HX9 | HVX | HX4 | - |
| HX10 | タイミングモデル: 複数ハードウェアスレッドの交互実行を表す専用モデル | HX4 | - |
| HX11 | Linux ABI: hexagon の syscall 表（trap0）・ELF・`heavy_program_hexagon` | HX5-9 | S22-1 |
| HX12 | `heavy_abi_hexagon` | HX11 | S22-2 |
| HX13 | `heavy_oracle_hexagon`（llvm-objdump 差分） | HX9 | S22-3 |
| HX14 | 残件整理・判定列更新 | HX10,HX12,HX13 | - |

### 段階 23：VAX

前提：段階 10（DEC の浮動小数点形式、パック十進）。

- 版の範囲は VAX-11/780 から NVAX まで、MicroVAX のサブセット、F、D、G、H の浮動小数点形式
- オペランド指定子のフック、`CALLS` と `RET` のフレーム、中断可能な命令の途中状態、MicroVAX が省いた命令は OS による命令の補完
- マイクロコードによる実行時間の専用のタイミングモデル
- 主流の Linux の移植がないので裸実行環境で検証する。BSD パーソナリティは段階 25 で扱う

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S23-1 | 命令単位のテストが裸実行環境で通る（DEC の形式とパック十進を含む。テスト `bare_vax`）。 | 未整備 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| VX1 | 着手条件: SPEC-VAX-MICROVAX の版確定、段階 10 の成果（DEC 形式・パック十進）の確認、GAP-0023 残項目の点検 | 段階 10 | - |
| VX2 | `guests/vax` 骨格: CpuState（r0-15（AP/FP/SP/PC）・PSL・命令の途中状態）、モデル（11/780 から NVAX・MicroVAX）の宣言 | VX1 | - |
| VX3 | デコード: 可変長命令とオペランド指定子のフックの ISADL 拡張（指定子の評価・読み書き・長さ） | VX2 | - |
| VX4 | `run_vax` 実行ループ: 可変長 fetch・中断可能な命令の途中状態 + bare 最小テスト | VX3 | - |
| VX5 | 整数: mov/add/sub/mul/div/emul/ediv・cmp/tst/clr/inc/dec | VX4 | - |
| VX6 | 論理・ビット・bitfield・shift/rot | VX4 | - |
| VX7 | push/pop・queue 命令（insq*/remq* 系）・文字列命令（movc/cmpc/loc/skp/scan/span/matchc/movtc/movtuc/crc）・chmk/chme（段階 25 の BSD パーソナリティが使う） | VX4 | - |
| VX8 | 分岐・calls/callg/ret のフレーム構築と解除 | VX4 | - |
| VX9 | 浮動小数点（F・D・G・H。poly 系を含む）・cvt 系。D 形式のワード並び（middle-endian）はオペランド指定子側で扱う | VX4 | - |
| VX10 | パック十進（movp/cmpp/addp/subp/mulp/divp/cvt 系） | VX9 | - |
| VX11 | モデル差と MicroVAX 省略命令の OS 補完経路 | VX5-10 | - |
| VX12 | `bare_vax` テスト群（DEC 形式とパック十進を含む）+ マイクロコード時間の専用タイミングモデル | VX11 | S23-1 |
| VX13 | 残件整理・判定列更新 | VX12 | - |

### 段階 24：PDP-11

前提：段階 10（F、D の浮動小数点形式）。

- 版の範囲は 11/03 から J-11 までの各モデルと、EIS、FIS、FP11、CIS のオプション。モデル間の振る舞いの差は挙動パラメータ
- 命令空間とデータ空間の分離（アクセスの種類ごとにアドレス空間を選ぶ `mem` の拡張）
- 裸実行環境で検証する。Unix V7 パーソナリティは段階 25 で扱う

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S24-1 | 命令単位のテストが裸実行環境で通る（分離 I&D のアドレス空間を含む。テスト `bare_pdp11`）。 | 未整備 |

作業計画：

| # | 内容 | 前提 | 判定 |
|---|---|---|---|
| PD1 | 着手条件: SPEC-PDP11-ARCH83・SPEC-PDP11-CIS・SPEC-PDP11-J11 の版確定、LSI-11/11/03 の根拠資料の追加登録または範囲からの除外の決定、段階 10（F・D 形式）の成果確認、GAP-0023 残項目の点検 | 段階 10 | - |
| PD2 | `guests/pdp11` 骨格: CpuState（r0-7・PSW）、モデル（11/03 から J-11）とオプション（EIS・FIS・FP11・CIS）の機能旗 | PD1 | - |
| PD3 | デコード: 16 ビット固定・8 モードのオペランド指定子（byte/word の扱い）。long/D 形式の middle-endian（3412）の語順 | PD2 | - |
| PD4 | `run_pdp11` 実行ループ: ワード fetch・奇数アドレスのアドレスエラー + bare 最小テスト | PD3 | - |
| PD5 | 整数: mov/add/sub/cmp/bit/bic/bis/clr/com/inc/dec/neg/tst（byte/word） | PD4 | - |
| PD6 | 論理・シフト・rot/sxt/xor・adc/sbc/swab・scc/ccc | PD4 | - |
| PD7 | 分岐・sob・jsr/rts/jmp | PD4 | - |

### 段階 25：追加の OS パーソナリティ

前提：段階 23 と 24。WASI は段階 12 で実装済みである。

- PDP-11 の Unix V7 と、VAX の BSD（対象の版は実装時に決める）の OS パーソナリティ。いずれも仮想カーネルの機構を共有し、システムコールの規約だけを実装する
- a.out の変種を解析するローダ
- ベアメタルのテスト用のセミホスティング（主に ARM と RISC-V の対象）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S25-1 | Unix V7 のプログラムが PDP-11 で正しく動く（テスト `heavy_program_unixv7`）。 | 未整備 |
| S25-2 | BSD のプログラムが VAX で正しく動く（テスト `heavy_program_bsdvax`）。 | 未整備 |
| S25-3 | セミホスティングを使うプログラムが正しく動く（テスト `heavy_program_semihosting`）。 | 未整備 |

### 段階 26：システムコールの段階 5

[ユーザーモード](user-mode.md) の実装の段階の 5（ネットワークと待ち合わせ）。

- ソケット関連、`poll`、`ppoll`、`epoll_*`、`timerfd_*`、`eventfd2`
- ファイル記述子が指す対象を多態な型で表す表への作り替え（GAP-0025 の解消を含む）

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S26-1 | ソケットと待ち合わせを使うプログラムが正しく動く（テスト `heavy_program_net`）。 | 未整備 |

### 段階 27：タイミングの残りの汎用モデルと較正

ISA 固有のタイミング（68000、80486、Pentium、VAX）は各 ISA の段階で扱う。この段階では `timing` クレートの残りの汎用モデルと、`approx` の較正を行う。

- キャッシュ階層、分岐予測器、アウトオブオーダー実行の汎用モデル
- `approx` の較正用のベンチマーク集（マイクロベンチマークと実際のプログラム）と、インオーダーの現行の CPU（SiFive U74 など）の `approx` の CPU モデル。較正できていないモデルは「未較正」と表示する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S27-1 | アウトオブオーダーの汎用モデルが、マイクロベンチマークで宣言した誤差の範囲に収まる（テスト `heavy_timing_ooo`）。 | 未整備 |
| S27-2 | U74 の `approx` が実機の計測で較正され、宣言した誤差の範囲に収まる（実機の計測が条件）。 | 所有者 |

### 段階 28：ホストの移植

[ホスト抽象化](host.md) の段階表に従い、ホストを増やす。各ホストの OS の文書は、使う前に台帳へ登録する。

- 段階 2：Linux AArch64 と macOS（Apple Silicon）。インタプリタから始める。AArch64 の JIT のバックエンドはこの段階で追加を検討する。macOS の JIT は `MAP_JIT` と書き込み保護の切り替えが必要になる
- 段階 3：Windows x86_64。ゲストの uid、gid、パーミッションは仮想カーネルで合成する
- 段階 4：wasm32。インタプリタのみ。ホストのスレッドがない環境では、ホストの入出力を直接行う

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S28-1 | Linux AArch64 のホストで `task test:full` が通る（ホストの環境が条件）。 | 所有者 |
| S28-2 | macOS（Apple Silicon）のホストで `task test:full` が通る（同上）。 | 所有者 |
| S28-3 | Windows x86_64 のホストで `task test:full` が通る（同上）。 | 所有者 |
| S28-4 | wasm32 のホストでインタプリタによる実行が動く（同上）。 | 所有者 |

### 段階 29：GDB 接続

- `gdbstub` による GDB との接続。レジスタの転送、シングルステップ、ブレークポイントを、実行エンジンの観測点を通して提供する

完了条件：

| ID | 条件 | 判定 |
|---|---|---|
| S29-1 | GDB からの接続、シングルステップ、ブレークポイント、レジスタの読み書きが動く（テスト `heavy_gdbstub`）。 | 未整備 |

## ISA の実装の着手の条件

コードやテストが資料を ID で参照するとき、およびテストデータを取得するかツールを実行するときは、その資料を台帳に登録する。台帳にある項目は全て確認済みとする（[ADR-0010](../adr/0010-reference-register.md)）。台帳にない資料に依存する作業は始めない。参照も取得もしない資料の登録は必須としない。

LLVM の対応しない ISA（m68k、Alpha、PA-RISC、SuperH、OpenRISC、IA-64、VAX、PDP-11）では、オラクルの逆アセンブラと、テストの命令列を組み立てる手段がない。これらの ISA の命令単位のテストは ISADL から生成したエンコーダで組み立てるので、エンコーダとオペランド入りの逆アセンブラの生成（GAP-0023 の解消）を着手の条件に含める。

## 各段階に共通の完了条件

どの段階でも、次のことを完了の条件に含める。

| ID | 条件 | 判定 |
|---|---|---|
| SC-1 | 追加した ISA と CPU モデルについて、[検証戦略](testing.md) の層 1 から 3 のテストがある。 | 所有者 |
| SC-2 | `task test:full` を実行し、その結果の要点を完了のコミットの本文に記録している（[開発作業とローカル検証](dev-workflow.md)）。 | 所有者 |
| SC-3 | 追加した機能の設計が、設計文書に反映されている。設計を変えた場合は、該当する文書を同じ変更で更新する。 | 所有者 |
| SC-4 | 新たに下した設計判断のうち、元に戻すのに大きな費用がかかるものは、設計文書かコミットの本文に理由が記録されている。 | 所有者 |
