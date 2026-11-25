# ソフトウェア浮動小数点と十進演算（`softfloat` / `decimal`）

ゲストの浮動小数点演算と十進演算は、ホストの FPU に頼らずソフトウェアで実装している。

## ホスト FPU を使わない理由

1. **丸めモードと例外フラグの制御**：Rust 標準ライブラリにはホスト FPU の丸めモード切替やスティッキー例外フラグ取得の可搬な手段がない。
2. **ISA 固有の規則差**：アンダーフロー判定時期（丸め前後）、NaN 伝播と符号化（MIPS 旧形式・PA-RISC は IEEE 754-2008 と sNaN/qNaN ビットが逆）、非正規化数フラッシュ（FTZ/DAZ）が ISA ごとに異なる。
3. **非 IEEE 形式の存在**：x87 の 80 ビット拡張精度、68881 拡張精度、IA-64 の 82 ビット形式、IBM 16 進浮動小数点、DEC の F/D/G/H 形式、IEEE 754 十進浮動小数点は一般的なホスト FPU が備えていない。
4. **決定性**：ソフトウェア計算ならホスト CPU の違いに依らずビット単位で同一の結果を得られる。

## `softfloat` が扱う形式と環境

| 形式 | 主な利用 ISA |
|---|---|
| IEEE 754 binary16 / binary32 / binary64 / binary128 | 大半の ISA |
| bfloat16 | x86、AArch64、Power |
| 低精度形式（E4M3・E5M2・E2M1 等） | x86（AVX10.3・ACE） |
| x87 拡張精度（80 ビット） | x86 |
| 68881 拡張精度（96 ビット格納・値 80 ビット） | m68k |
| IA-64 拡張精度（82 ビット：`{sign, exp17, sig64}`） | IA-64 |
| IBM 16 進浮動小数点（32・64・128 ビット） | s390 |
| DEC F・D・G・H 形式（`decfp`） | VAX、PDP-11（FP11・FIS）、Alpha |

`softfloat` 自身は ISA 名を持たない。呼び出し側のゲスト ISA が丸めモード（IEEE 4 種・RMM・奇数丸め）、アンダーフロー判定時期、NaN 伝播・符号化規則、非正規化数処理、精度制御を環境（`FpEnv`）として渡し、結果と例外フラグを受け取る。例外トラップを起こすか累積フラグへ反映するかはゲスト側の意味論が決める。

なお、x87 の超越関数命令（`FSIN`・`FCOS` 等）は `softfloat` 側に未実装である（詳細は [x86](../guests/x86.md) を参照）。

## `decimal` が扱う演算

`decimal` クレートは二種類の十進演算を提供する。

- **パック十進整数（BCD）**：VAX の十進命令・`EDITPC`、s390 のパック十進、x87 の `FBLD`/`FBSTP`、m68k の `ABCD`/`SBCD`、PDP-11 の CIS、Power の `bcdadd.` が使用する。無効ニブルや符号正規化の規則は ISA ごとの環境（`BcdEnv`）で渡す。
- **IEEE 754 十進浮動小数点（decimal32 / decimal64 / decimal128）**：Power・s390 が使う DPD 符号化を実装している。BID 符号化は対象外である。

## 検証状況

- **`decimal`**：`crates/decimal/tests/heavy_conformance_dectest.rs` で公開十進テスト集（decTest）と比較している。
- **非 IEEE 形式・IA-64 82bit**：`crates/softfloat/tests/nonieee_examples.rs` と `ia64ext_examples.rs` で仕様書の例題を検証している。
- **二進 IEEE 形式**：現行では `crates/softfloat/tests/heavy_diff_host.rs` でホスト演算との差分を比較している。Berkeley TestFloat のベクタ比較（`heavy_conformance_testfloat`）はベクタ生成と接続が未完了である（[GAP-0009](../known-issues.md)）。
