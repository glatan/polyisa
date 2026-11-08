# CPU モデルとバージョンの表現

この文書は、ISA のバージョン、ISA 拡張、CPU の世代、ベンダーごとの差を表現する仕組みを定める。記述は ISADL で行い（[ISA 記述言語](isa-description.md)）、CPU モデルは実行時に選ぶ。

## 差の種類

同じ ISA ファミリの中の CPU どうしの差は、次の五つに分けられる。それぞれ別の仕組みで表現する。

| 差の種類 | 例 | 表現 |
|---|---|---|
| 命令の有無 | SSE2 の有無、RISC-V の Zba、MIPS Release 6 で削除された命令 | 機能 |
| 同じエンコーディングの意味の違い | x86 の `0F 05`、MIPS R6 で割り当て直されたオペコード | 機能を条件とする別の命令の宣言 |
| 同じ命令の振る舞いの違い | x86 の未定義フラグの値、ARMv6 より前の非整列 `LDR` の回転、68000 と 68020 の BCD 命令の V フラグ | 挙動パラメータ |
| 識別情報 | x86 の CPUID、Power の PVR、s390 のファシリティリスト | CPU モデルの識別情報 |
| 実行時間 | 命令のレイテンシ、パイプラインの構成、キャッシュの構成 | タイミングモデルとタイミング表 |

この分け方では、ISA のバージョンは独立した概念にならない。ISA のバージョンは、機能集合（命令の有無とエンコーディング）と挙動パラメータの既定値の組として表す。MIPS32 Release 2 は「MIPS32 Release 1 の機能集合に Release 2 で追加された機能を足したもの」であり、x86-64-v3 は「x86-64-v2 に AVX2 などを足したもの」である。

## 機能

機能は ISA ファミリごとに宣言し、生成器が固定長のビット集合の型を生成する。機能は、他の機能を含意する関係（`implies`）と、同時に有効にできない関係（`conflicts`）を持てる。

```text
feature sse2     "SSE2"                 implies sse;
feature lm       "ロングモード（x86-64）" implies cx8, cmov, fxsr, sse2;
feature mips_r6  "MIPS Release 6"       conflicts branch_likely, lwl_lwr;
feature rv64     "64 ビットの基本整数 ISA" conflicts rv32;
```

機能の粒度は、ISA の仕様が命令の有無を切り替える単位に合わせる。仕様が一つの拡張として定めていても、実在の CPU が一部だけを実装している場合は、実装の単位で機能を分ける。たとえば Alpha の BWX 拡張（バイトとワードのロードストア）は 21164A で追加された一つの拡張なので一つの機能にし、x86 の AVX-512 はサブセットごとに機能を分ける。

ISA のアドレス幅（RV32 と RV64、MIPS32 と MIPS64）も機能として表す。アドレス幅をクレートや型で分けないのは、MIPS64 の CPU が 32 ビットのプログラムを実行するように、同じ ISA ファミリで幅の違うプログラムを扱う場面があり、命令の大半が両方の幅で共通するからである。

## プロファイル

プロファイルは名前の付いた機能集合である。他のプロファイルに機能を足し引きして定義できる。

```text
profile mips1      = base_mips1;
profile mips2      = mips1 + ll_sc + branch_likely + ...;
profile mips32r2   = mips32r1 + ext_ins + rotr + seb_seh + ...;
profile mips32r6   = mips32r5 + mips_r6 - branch_likely - lwl_lwr;
profile x86_64_v2  = x86_64_v1 + cx16 + lahf_lm + popcnt + sse3 + ssse3 + sse4_1 + sse4_2;
profile rva22u64   = rva20u64 + zba + zbb + zbs + zicbom + ...;
profile wasm_2_0   = wasm_1_0 + multi_value + bulk_memory + reference_types + simd128 + ...;
```

生成器は、プロファイルの機能集合を `implies` で閉包し、`conflicts` に違反しないことを検査する。

## CPU モデル

CPU モデルは、実在または仮想の CPU を表す。親（プロファイルか別の CPU モデル）を一つ持ち、機能の足し引き、挙動パラメータの値、識別情報、所属するグループ、タイミングモデルの指定を加える。

```text
model pentium_pro : pentium {
    features   + cmov + pae + ...;
    group      vendor.intel, gen.p6;
    param      bsf_zero_input = dest_unchanged;
    ident cpuid {
        vendor "GenuineIntel"; family 6; model 1; stepping 9;
    }
    timing     approx ooo using p6;           // timing/p6.isadl のタイミング表
}

model sifive_u74 : rv64gc {
    features   + zba + zbb;
    group      vendor.sifive, gen.u7;
    timing     approx inorder using sifive_u74;
}
```

親を持たない仮想の CPU モデルとして、各プロファイルにはそのプロファイルと同名の汎用 CPU モデルを自動で用意する。汎用 CPU モデルの挙動パラメータは既定値をとり、タイミングの忠実度は `none` とする。

### グループ

グループは、CPU モデルを一覧や選択の単位でまとめるための分類である。ベンダー（`vendor.intel`）、世代（`gen.p6`）、製品系列（`line.pentium`）のように、独立した複数の分類軸を持てる。グループは機能集合と別の軸として持つ。機能集合で世代を表そうとすると、同じ世代でも製品によって機能が欠けている場合（同じ世代の廉価版で AVX が無効化されている場合など）に分類が崩れるからである。

グループは、コマンドラインでの一覧表示（`polyisa cpus --group gen.p6`）と、テストの対象の選択（世代ごとに代表の CPU モデルでテストを走らせる）に使う。

## 挙動パラメータ

挙動パラメータは、同じ命令の振る舞いが CPU モデルで異なる箇所を表す型付きの値である。型は真偽値、列挙、整数のいずれかであり、宣言に既定値と説明を持つ。

```text
param bsf_zero_input : enum { dest_unchanged, dest_zero } = dest_unchanged
    "BSF/BSR の入力が 0 のときの宛先レジスタの値";
param unaligned_ldr  : enum { rotate, unaligned, fault } = unaligned
    "非整列アドレスに対する LDR の振る舞い";
param nan_encoding   : enum { legacy, ieee2008 } = ieee2008
    "MIPS の浮動小数点 NaN の符号化";
```

ISA の仕様が「未定義」「実装定義」「UNPREDICTABLE」とする振る舞いは、すべて挙動パラメータとして宣言する。仕様が規定しない振る舞いの再現は、CPU モデルによる差の中でも、ゲストのプログラムが CPU の判別や誤った前提に使う箇所であり、R3 の要件で扱う範囲に含まれる。どの振る舞いを観測したかの出典は、パラメータの値を設定する CPU モデルの定義に残す。資料に基づく値は台帳の ID と節を `ref` に書き（[参照資料の台帳](../references.md)）、実機の計測に基づく値は計測の記録を示す。

## 差の解決をデコード時に行う規則

CPU モデルはゲストプロセスの実行中に変わらないので、CPU モデルによる差の大半は、命令を実行するたびではなく、デコードするときに一度だけ解決できる（[ADR-0006](../adr/0006-resolve-model-differences-at-decode.md)）。解決の方法は差の種類ごとに次のように決める。

1. 命令の有無と、エンコーディングの意味の違いは、デコーダが `when` の述語で解決する。CPU モデルにない命令は未定義命令としてデコードされる。
2. 振る舞いの違いが命令全体に及ぶ場合は、ISADL の `sem` 句で挙動パラメータの値ごとに意味論の関数を切り替える。切り替えはデコード時に行われ、デコードキャッシュには選ばれた関数が入る。

   ```text
   insn bsf : ... {
       sem match param.bsf_zero_input {
           dest_unchanged => bsf_keep_dest;
           dest_zero      => bsf_zero_dest;
       }
   }
   ```

3. 振る舞いの違いが意味論の一部にとどまる場合は、意味論の中でバックエンドから挙動パラメータを読む。インタプリタのバックエンドはその値を返し、IR のバックエンドは定数として扱って畳み込む。

実行モードによる差は、デコーダの入力とブロックキーに実行モードが入っているので、同じ規則で解決される。

## 識別情報

識別情報は、ゲストのプログラムが CPU を判別するために読む値である。x86 の CPUID の各リーフ、Power の PVR、s390 のファシリティリスト（`STFLE`）、ARM の ID レジスタがこれにあたる。

識別情報のうち、機能の有無に対応するビットは、CPU モデルの定義に直接書かず、機能から導出する。ISADL で機能と識別情報のビットの対応表を宣言し、生成器が CPU モデルごとの値を計算する。

```text
cpuid_bit sse2 = leaf 0x1, edx, 26;
cpuid_bit avx2 = leaf 0x7.0, ebx, 5;
```

導出する理由は、利用者が実行時に機能を足し引きしたとき、CPUID の報告と実際に実行できる命令が食い違わないようにするためである。ベンダー名、ファミリ番号、ステッピングのように機能に対応しない値だけを CPU モデルに直接書く。

Linux の `AT_HWCAP` や `/proc/cpuinfo` のように、OS がゲストに見せる情報は、OS パーソナリティが機能と識別情報から導出する。導出の対応表は OS パーソナリティ側に置く（[ユーザーモード](user-mode.md)）。

## 実行時の選択

CPU モデルはコマンドラインで次の形式で指定する。

```text
--cpu <ISA ファミリ>:<CPU モデル>[,+<機能>][,-<機能>][,<パラメータ>=<値>]

--cpu x86:pentium_pro
--cpu riscv:rv64gc,+zba,+zbb
--cpu mips:r3000,nan_encoding=legacy
```

指定した機能集合は、`implies` で閉包してから `conflicts` を検査し、違反があれば実行を始めない。機能を足した結果、CPU モデルのタイミング表にない命令が実行可能になった場合、その命令のタイミングは命令の分類ごとの既定値で数え、タイミングの忠実度が下がったことを実行開始時に表示する。

実行ファイルが要求する機能（ELF の `e_flags` や、RISC-V の属性セクションに書かれた ISA 文字列）が CPU モデルにない場合は、実行を拒否せず警告にとどめる。実機でも、要求を満たさない CPU で実行すると未定義命令の例外が起きるだけであり、その状況の再現も polyisa の用途に含まれるからである。
