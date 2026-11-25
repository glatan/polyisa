// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// PDP-11 の ISADL モデル（段階24）。
//
// 命令語は 16 ビット固定長。形式は二重オペランド（op4 + ソース
// 指定子6 + 宛先指定子6）・単一オペランド（op10 + 宛先指定子6）・
// 分岐（op8 + 変位8）・SOB（op7 + レジスタ3 + 変位6）・JSR/EIS
// （op7 + レジスタ3 + 指定子6）・RTS/FIS（op13 + レジスタ3）・
// 固定（op16）の各フォーマット。指定子は語内の (mode,reg) の対で、
// モード 6/7 のインデックス語や PC 指定子の即値・絶対・相対語は
// 命令語に含まれない —— 拡張語の消費・EA 評価・副作用（オート
// 増減・PC 基準）はゲストの指定子評価器が担う（m68k の ea.rs と
// 同型の分割。PD3 で作る）。
//
// オプション命令群（EIS・FIS・FP11・CIS と MMU 命令）は機能旗の
// `when` で表し、旗を持たないモデルではデコードされず予約
// オペコードの経路に乗る。FP11（17xxxx）と CIS（076nnn）の語彙は
// PD10/PD11 で宣言する。
//
// 出典は SPEC-PDP11-ARCH83（第5章 命令セット・付録 C FIS・
// 付録 B ファミリ差分表）、SPEC-PDP11-LSI11（KD11-F 固有）、
// SPEC-PDP11-HANDBOOK（11/04–11/70 のモデル別の性質）、
// SPEC-PDP11-J11（J-11 固有）である。
// Ref: SPEC-PDP11-ARCH83, SPEC-PDP11-LSI11, SPEC-PDP11-HANDBOOK,
// SPEC-PDP11-J11.

use polyisa_isadl::model::*;
use polyisa_isadl::pattern::Pattern;
use polyisa_isadl::pred::Pred;

/// PDP-11 の検査済みモデルを作る。
pub fn build_model() -> polyisa_isadl::Model {
    let mut m = polyisa_isadl::Model::new();

    // 汎用タイミングの区切り（専用モデルは作らない —— PD2 の計画）。
    // 未較正の汎用タイミング近似
    for class in ["alu", "move", "branch", "fp", "cis", "system", "misc"] {
        m.timing_classes.push(class.to_string());
    }

    // 機能旗。オプション命令群と、モデル間で実装が割れる命令の
    // 有無を表す。`--cpu` の `+機能` でオプション搭載を足せる。
    // - `eis`: mul/div/ash/ashc（KE11-E・KEV11・KEF11 の各オプション
    //   か後期モデルの標準）。
    // - `fis`: 0750xR（fadd/fsub/fmul/fdiv。KEV11 等）。FP11 と
    //   排他（ARCH83 付録 C「not compatible with the FP-11」）。
    // - `fp11`: FP11-A/-C/-E/-F と J-11 の FPJ11（17xxxx。語彙は PD10）。
    // - `cis`: 商業命令群（076nnn。KE44-A 等。語彙は PD11）。
    // - `mmu`: メモリ管理（PAR/PDR・モード別 SP・MFPI/MTPI/MFPD/MTPD）。
    // - `id_split`: 分離 I/D（命令空間とデータ空間の別写像。MMU の
    //   能力として mmu を含む）。
    // - `sm`: スーパーバイザモード（kernel/supervisor/user の
    //   3 モード。MMU のモード別ページ集合が要るので mmu を含む）。
    // - `dual_regset`: 第 2 汎用レジスタセット（PSW<11> が選ぶ
    //   r0′-r5′）。
    // - `mtps`: MTPS/MFPS（PSW を命令で触る。PSW が 177776 に写像
    //   されるだけのモデルでは予約オペコード —— 付録 B 項目 18 で
    //   `psw_mapped` パラメータと反転する）。
    // - `mfpt`: MFPT（プロセッサ型番の読み出し）。
    // - `spl`: SPL（割込み優先度 PSW<7:5> の設定）。
    // - `csm`: CSM（スーパーバイザモード呼出。sm を含む）。
    // - `tstset_wrtlck`: TSTSET/WRTLCK（読み書き不可分のチェック）。
    // - `sob_mark`: SOB・MARK（付録 B 項目 8 —— 11/04・11/05・11/10・
    //   11/15・11/20 は持たない）。
    // - `sxt`: SXT（付録 B 項目 8 —— 同上のモデルが持たない）。
    // - `maint`: 保守命令 000210-000217（付録 B 項目 33 —— LSI-11 系
    //   だけが予約でなく実行する）。
    // Ref: SPEC-PDP11-ARCH83（第5章・付録 B・付録 C）,
    // SPEC-PDP11-LSI11, SPEC-PDP11-J11.
    for (name, implies, conflicts) in [
        ("eis", &[][..], &[][..]),
        ("fis", &[][..], &["fp11"][..]),
        ("fp11", &[][..], &["fis"][..]),
        ("cis", &[][..], &[][..]),
        ("mmu", &[][..], &[][..]),
        ("id_split", &["mmu"][..], &[][..]),
        ("sm", &["mmu"][..], &[][..]),
        ("dual_regset", &[][..], &[][..]),
        ("mtps", &[][..], &[][..]),
        ("mfpt", &[][..], &[][..]),
        ("spl", &[][..], &[][..]),
        ("csm", &["sm"][..], &[][..]),
        ("tstset_wrtlck", &[][..], &[][..]),
        ("sob_mark", &[][..], &[][..]),
        ("sxt", &[][..], &[][..]),
        ("maint", &[][..], &[][..]),
    ] as [(&str, &[&str], &[&str]); 16] {
        m.features.push(Feature {
            name: name.to_string(),
            implies: implies.iter().map(|s| s.to_string()).collect(),
            conflicts: conflicts.iter().map(|s| s.to_string()).collect(),
        });
    }

    // 挙動パラメータ。付録 B のファミリ差分表（項目 1-52）で可観測な
    // 差分はここか機能旗へ写す（棚卸しの全項目対応は docs/guests/pdp11.md
    // に記録。バスサイクル・割込み受理・RESET/停電系の
    // 項目は裸実行モデルでは不可観測なので対象外として残す）。
    // Ref: SPEC-PDP11-ARCH83（付録 B）.
    m.param(
        "odd_addr_trap",
        ParamKind::Bool,
        "true",
        "奇数アドレスのワードアクセスが vector 4 にトラップするか。\
         LSI-11・F-11・T-11 系は未実装（ARCH83 付録 B 項目 15/21）",
    );
    m.param(
        "psw_mapped",
        ParamKind::Bool,
        "true",
        "PSW がアドレス 177776 に見えるか。見えないモデルは \
         MTPS/MFPS で触る（ARCH83 付録 B 項目 18。命令自体の有無は \
         機能旗 mtps が担う）",
    );
    m.param(
        "jmp_reg_trap",
        ParamKind::Enum(vec!["vec004".to_string(), "vec010".to_string()]),
        "vec010",
        "JMP Rn・JSR reg,Rn（宛先がモード 0 の違法指定）のトラップ \
         ベクタ（ARCH83 付録 B 項目 5）",
    );
    m.param(
        "mfpt_code",
        ParamKind::Int(0xFF),
        "0",
        "MFPT が R0<7:0> に返すプロセッサ型番（ARCH83 第5章 MFPT・\
         KDJ11-E UG: 11/44=1・F-11 系=3・T-11=4・J-11 系=5。上位バイトは \
         モデル固有のサブコードで現行全モデル 0）",
    );
    m.param(
        "rti_ttrap",
        ParamKind::Enum(vec!["imm".to_string(), "next".to_string()]),
        "imm",
        "RTI が T ビットを立てたときの trace trap の発火点。imm は RTI \
         直後（次の命令の実行前）、next は次の命令の実行後（ARCH83 \
         付録 B 項目 11 のモデル差）",
    );
    // PD12（メモリ管理）が使うパラメータ。
    m.param(
        "mmu_pa",
        ParamKind::Enum(vec![
            "off".to_string(),
            "p18".to_string(),
            "p22".to_string(),
            "sel22".to_string(),
        ]),
        "off",
        "MMU の物理アドレス幅。off=MMU なし、p18=18 ビット固定、\
         p22=22 ビット固定（11/70）、sel22=MMR3<4> が 22/18 ビットを選ぶ\
         （11/24・11/44・J-11。MMR3 自体もこの 2 系だけが持つ）",
    );
    m.param(
        "mm_trap",
        ParamKind::Bool,
        "false",
        "メモリ管理トラップ（ACF 1/4/5 の trap 条件と MMR0<9><12>）を \
         実装するか。11/45・11/70 だけが持ち、他モデルでは ACF の \
         予約値が nonresident abort に畳まれる",
    );
    m.param(
        "gpr_mapped",
        ParamKind::Bool,
        "false",
        "汎用レジスタが I/O ページの 177700-177717 に写像されるか \
         （セット 0＋セット 1＋モード別 SP。UNIBUS 系モデル）",
    );
    m.param(
        "stack_limit",
        ParamKind::Enum(vec!["none".to_string(), "reg".to_string(), "fixed".to_string()]),
        "none",
        "カーネルスタックの越境検査の形（付録 B 項目 20）。reg は \
         制限レジスタ 177774 を持つ（11/34・11/44・11/45・11/60・\
         11/70）、fixed は 0o400 固定境界（F-11・J-11 —— KDJ11-E \
         UG 1.2.1）、none は検査なし",
    );
    m.param(
        "dual_regset",
        ParamKind::Bool,
        "false",
        "第 2 汎用レジスタセットを持つか。同名の機能旗は命令 \
         デコードを担い、こちらは PSW<11>（RS）の効果 —— \
         RTI・PSW の I/O ページ書き込み・トラップ配送での \
         セット切替 —— を実行時の意味論が読む側",
    );
    // PD13 —— 付録 B 棚卸しで確定した差分パラメータ。
    // Ref: SPEC-PDP11-ARCH83（付録 B 各項目）.
    m.param(
        "opr_same_reg",
        ParamKind::Enum(vec!["inc".to_string(), "init".to_string()]),
        "init",
        "OPR %R,(R)+ / OPR %R,@(R)+（ソースと宛先が同じレジスタ）で \
         R をソース読み出しの前に +2 するか。inc は F-11・11/60・\
         J-11・T-11（と 11/15・11/20・11/35・11/40）、init は \
         それ以外（付録 B 項目 1・2）",
    );
    m.param(
        "pc_stored",
        ParamKind::Enum(vec!["pc2".to_string(), "pc4".to_string()]),
        "pc2",
        "r7 をソースオペランドとして書き出すときの値。pc4 は \
         OPR+4（命令の次の語 —— F-11・11/60・J-11・T-11・11/15・\
         11/20・11/35・11/40）、pc2 は OPR+2（付録 B 項目 3）",
    );
    m.param(
        "jmp_reginc",
        ParamKind::Enum(vec!["inc".to_string(), "init".to_string()]),
        "init",
        "JMP/JSR (R)+・@(R)+ が増分後の R を使うか。inc は \
         11/05・11/10・11/15・11/20 だけ（付録 B 項目 4 —— \
         現モデル集合では全モデル init）",
    );
    m.param(
        "swab_v",
        ParamKind::Enum(vec!["clear".to_string(), "keep".to_string()]),
        "clear",
        "SWAB の V 桁。clear は V=0（全現モデル）、keep は V を変えない \
         （11/15・11/20 のみ —— 付録 B 項目 6）",
    );
    m.param(
        "sp_buserr",
        ParamKind::Enum(vec![
            "halt".to_string(),
            "fatal".to_string(),
            "notrap".to_string(),
        ]),
        "halt",
        "SP が奇数・存在しないアドレスを指したバスエラーの帰結（付録 B \
         項目 15）。halt=CPU 停止（UNIBUS 系と LSI-11）、fatal=fatal \
         trap（新スタックを 0/2 番地から取る）、notrap=T-11（バス \
         エラー自体を持たない）。裸モデルでは halt/fatal とも終端に \
         畳む近似 —— GAP-0086",
    );
    m.param(
        "t_direct",
        ParamKind::Bool,
        "false",
        "PSW への直接参照が T 桁を書けるか（付録 B 項目 14）。true は \
         11/04（と 11/05・11/10・11/15・11/20）だけ —— 他モデルは \
         トラップ経路の暗黙参照だけが T を変える",
    );
    m.param(
        "fetch_nxm",
        ParamKind::Enum(vec!["inc".to_string(), "same".to_string()]),
        "inc",
        "存在しないメモリからの命令フェッチでバスエラーになったとき \
         PC が増分済みか（付録 B 項目 28）。same は 11/35・11/40 \
         （と VAX）だけ —— 11/60・T-11 は表の該当桁が空欄で inc に \
         寄せる（GAP-0086）",
    );
    m.param(
        "ea_fault_reg",
        ParamKind::Enum(vec!["inc".to_string(), "keep".to_string()]),
        "inc",
        "モード 2 オペランド参照の NXM・奇数値バスエラーで増分後の \
         R が残るか（付録 B 項目 29・30）。keep は 11/44・11/04・\
         11/34（奇数値では 11/05・11/10・11/15・11/20 も keep —— \
         現モデル外）。11/60 は表が空欄で inc に寄せる（GAP-0086）",
    );
    m.param(
        "mode_enc",
        ParamKind::Enum(vec![
            "none".to_string(),
            "f11".to_string(),
            "ku".to_string(),
            "ksu".to_string(),
        ]),
        "none",
        "PSW<15:12> のモード集合と予約値の扱い（付録 B 項目 39）。\
         none=モード桁を持たない（11/03・11/04・T-11）、f11=値 01 が \
         トラップ・値 10 がカーネル（F-11）、ku=値 01/10 がトラップ \
         （11/34・11/60 —— 60 は表が空欄で ku に寄せる）、ksu=値 10 \
         がトラップ・01 はスーパーバイザ（11/44・11/70・J-11）",
    );
    m.param(
        "mmr0_maint",
        ParamKind::Bool,
        "false",
        "MMR0<8>（保守/宛先モード桁）を実装するか（付録 B 項目 37）。\
         11/34・11/44・11/45・11/60・11/70 だけが持ち、F-11・J-11 は \
         桁が存在しない（読み出し 0・書き込み無視）",
    );
    m.param(
        "mtps_map",
        ParamKind::Enum(vec!["direct".to_string(), "mapped".to_string()]),
        "direct",
        "ユーザーモードの MTPS/MFPS が PSW の 177776 写像経由で \
         メモリ管理トラップを起こすか（付録 B 項目 40・41）。mapped は \
         11/34 だけ —— ユーザーモードで PS<7:5>+<3:0> を書く",
    );
    m.param(
        "halt_vec",
        ParamKind::Enum(vec![
            "vec004".to_string(),
            "vec010".to_string(),
            "powerup".to_string(),
        ]),
        "vec004",
        "カーネル以外の HALT の帰結（付録 B 項目 43）。vec004=location \
         4（11/44・11/45・11/70・J-11）、vec010=location 10（F-11・\
         11/34・11/60）、powerup=T-11（PS←340・PC←起動ベクタ —— \
         起動ベクタを持たない裸モデルでは終端に畳む。GAP-0086）",
    );
    m.param(
        "pdr_extra",
        ParamKind::Bool,
        "false",
        "PDR<0>（副長フィールド）と PDR<7>（アクセス済み桁）を実装する \
         か（付録 B 項目 44・45）。11/45・11/70 だけが持つ",
    );
    m.param(
        "par_width",
        ParamKind::Enum(vec!["p16".to_string(), "p12".to_string()]),
        "p16",
        "PAR の実装桁数（付録 B 項目 46）。p16 は全桁（F-11・11/44・\
         11/70・J-11）、p12 は <11:0> のみ（11/34・11/35・11/40・\
         11/45・11/60）",
    );
    m.param(
        "mmr2_vec",
        ParamKind::Bool,
        "false",
        "トラップ/割込みのベクタ読み出しを MMR2 に記録するか（付録 B \
         項目 51）。11/45・11/70 だけが追跡し、他モデルは命令 PC のみ",
    );
    m.param(
        "mfp_sp2",
        ParamKind::Enum(vec!["unpred".to_string(), "user".to_string()]),
        "unpred",
        "MFPI/MFPD・MTPI/MTPD の %6（前モード=10 のときどの SP を \
         選ぶか —— 付録 B 項目 52）。J-11 はユーザースタック、他 \
         モデルは不定 → カーネル枠への決定的畳み",
    );
    m.param(
        "wait_t",
        ParamKind::Enum(vec!["seq".to_string(), "hold".to_string()]),
        "seq",
        "T ビットが立っている間の WAIT（付録 B 項目 13）。seq は \
         WAIT が命令として抜けて trace trap へ進む、hold は T が \
         あっても WAIT から出ない（LSI-11・11/45・11/70）",
    );
    m.param(
        "fis_kev11",
        ParamKind::Bool,
        "false",
        "KEV11 の 075040-075377 が R<n> 経由の読み出しを行ってから \
         location 10 にトラップするか（付録 B 項目 32・34。LSI-11+\
         KEV11 だけ —— 他モデルは即 location 10）",
    );
    m.param(
        "mmr3",
        ParamKind::Enum(vec![
            "none".to_string(),
            "m22".to_string(),
            "m22_ds".to_string(),
            "full".to_string(),
        ]),
        "none",
        "MMR3 の実装範囲（付録 B 項目 48-50）。m22=<5:4> のみ（F-11）、\
         m22_ds=さらに <2:0> の D 空間許可（11/70）、full=さらに <3> \
         の CSM 許可（11/44・J-11）。11/34・11/60 は MMR3 を持たない",
    );

    // CPU モデル。版の範囲は 11/03（KD11-F＝LSI-11 チップ）から
    // J-11 まで。オプション搭載（11/03 の KEV11、F-11 系の
    // KEF11/FPF11、11/44 の KE44-A CIS、11/70 の FP11-C 等）は
    // 標準機能に含めず `--cpu` の +機能 で足す。機能集合と
    // パラメータ値は PD13 で ARCH83 付録 B のファミリ差分表と
    // J-11/LSI-11 の各 UG に照合して確定した（GAP-0086 の棚卸し表
    // に全項目の対応を記録）。
    // - pdp11_03: LSI-11（KD11-F）。EIS/FIS は KEV11 オプション。
    //   保守命令 00021x を持つ。モード桁・MMU・奇数アドレス
    //   トラップなし。
    // - pdp11_04: 素の KD11-D。SOB/MARK/SXT を持たず RTT は異なる
    //   動作。PSW は 177776 に写像され T 桁も直接
    //   書ける。MMU なし。
    // - pdp11_34: 2 モード MMU（18 ビット）・MTPS/MFPS・PSW 写像
    //   あり（付録 B 項目 18）。EIS はオプション。
    // - pdp11_44: EIS・3 モード 22 ビット MMU（分離 I/D 付き）・
    //   SPL・MFPT・CSM 標準。MTPS/MFPS・PSW 写像は 177776 直付け
    //   のみ（項目 18）。宣言は KE44-A CISP 装着形を表す（CIS は
    //   オプション —— 未装着形の宣言はモデルを分けるほどの差が
    //   なく に記す）。
    // - pdp11_60: EIS・MMU・FP11-E 標準（項目 8 —— 「F-floating
    //   instructions standard」）。
    // - pdp11_70: EIS・MMU・分離 I/D・スーパーバイザ・第2レジスタ
    //   セット・SPL・スタック制限・MM トラップ・PDR<0>/<7> 標準。
    //   FP11-C はオプション。
    // - pdp11_23/24: F-11（KDF11-A/-B）。MMU（18 ビット系）・
    //   MTPS/MFPS・MFPT・PSW 写像標準、EIS/FIS/FP11/CIS は
    //   オプション。11/24 は MMR3<4> で 22 ビットを選べ
    //   TSTSET/WRTLCK を持つ。
    // - pdp11_73/83/93: J-11（KDJ11-A/-B/-E）。11/70 の全命令＋
    //   EIS・FPJ11・CSM・TSTSET/WRTLCK・MFPT・SPL・3 モード
    //   22 ビット MMU・分離 I/D 標準（KDJ11-E UG 1.2 —— CIS は
    //   J-11 にない）。
    // - t11: T-11（FALCON）。基本命令＋MTPS/MFPS・MFPT。バス
    //   エラー・モード・MMU を持たない（付録 B 各脚注）。
    // Ref: SPEC-PDP11-ARCH83（付録 B）, SPEC-PDP11-LSI11,
    // SPEC-PDP11-HANDBOOK, SPEC-PDP11-J11.
    let j11: &[&str] = &[
        "eis",
        "fp11",
        "mmu",
        "id_split",
        "sm",
        "dual_regset",
        "mtps",
        "mfpt",
        "spl",
        "csm",
        "tstset_wrtlck",
        "sob_mark",
        "sxt",
    ];
    for (name, parent, add, params) in [
        (
            "pdp11_03",
            "",
            &["mtps", "maint", "sob_mark", "sxt"][..],
            &[
                ("odd_addr_trap", "false"),
                ("psw_mapped", "false"),
                ("jmp_reg_trap", "vec010"),
                ("wait_t", "hold"),
                ("fis_kev11", "true"),
                ("halt_vec", "vec010"),
            ][..],
        ),
        (
            "pdp11_04",
            "",
            &[][..],
            &[
                ("jmp_reg_trap", "vec010"),
                ("t_direct", "true"),
                ("ea_fault_reg", "keep"),
                ("halt_vec", "vec010"),
            ][..],
        ),
        // 11/20 系。EIS・MMU・MTPS/MFPS を持たず SOB/MARK/SXT も
        // ない（付録 B 項目 8）。jmp_reginc=inc と t_direct は
        // 全車種共通、opr_same_reg=inc・pc_stored=pc4・swab_v=keep
        // は 11/15・11/20 だけ（付録 B 項目 1-3・6）。11/10・11/15
        // は包装違いで命令面の差が見えないため空の派生とする。
        // ea_fault_reg は奇数値バスエラーで keep（項目 30）。
        (
            "pdp11_05",
            "",
            &[][..],
            &[
                ("jmp_reginc", "inc"),
                ("t_direct", "true"),
                ("ea_fault_reg", "keep"),
            ][..],
        ),
        ("pdp11_10", "pdp11_05", &[][..], &[][..]),
        (
            "pdp11_20",
            "pdp11_05",
            &[][..],
            &[
                ("opr_same_reg", "inc"),
                ("pc_stored", "pc4"),
                ("swab_v", "keep"),
            ][..],
        ),
        ("pdp11_15", "pdp11_20", &[][..], &[][..]),
        // 11/40 系。EIS（KE11-E）・MMU（KT11-D）はオプションなので
        // 標準機能に含めない。fetch_nxm=same（項目 28）が固有の差。
        (
            "pdp11_40",
            "",
            &["sob_mark", "sxt"][..],
            &[
                ("opr_same_reg", "inc"),
                ("pc_stored", "pc4"),
                ("fetch_nxm", "same"),
            ][..],
        ),
        ("pdp11_35", "pdp11_40", &[][..], &[][..]),
        // 11/45 系。EIS・KT11-C MMU（18 ビット）・スーパーバイザ・
        // 第 2 レジスタセット標準。MM トラップとスタック制限
        // レジスタを持つ（mm_trap・stack_limit の項）。FP11 は
        // オプション。分離 I/D は KT11-C にない。11/50・11/55 は
        // メモリ速度違いで命令面の差が見えないため空の派生。
        // halt_vec=vec004 は付録 B 項目 43 の記載どおり（11/45 は
        // vec004 の群）。vec004 はデフォルトと同値だが、項目 43 に
        // 言及のある機種なので明示する。なお 11/05–11/40 系は MMU
        // なしの標準構成ではモードビットを持たず非カーネルモードに
        // 入れないため、非カーネル HALT の帰結である halt_vec は
        // 空問い（vacuous）—— 値はデフォルトのままで実効しない。
        (
            "pdp11_45",
            "",
            &[
                "eis", "mmu", "sm", "dual_regset", "sob_mark", "sxt",
            ][..],
            &[
                ("mmu_pa", "p18"),
                ("mode_enc", "ksu"),
                ("mm_trap", "true"),
                ("dual_regset", "true"),
                ("stack_limit", "reg"),
                ("jmp_reg_trap", "vec004"),
                ("halt_vec", "vec004"),
            ][..],
        ),
        ("pdp11_50", "pdp11_45", &[][..], &[][..]),
        ("pdp11_55", "pdp11_45", &[][..], &[][..]),
        (
            "pdp11_34",
            "",
            &["mmu", "mtps", "sob_mark", "sxt"][..],
            &[
                ("jmp_reg_trap", "vec010"),
                ("mmu_pa", "p18"),
                ("mode_enc", "ku"),
                ("mtps_map", "mapped"),
                ("stack_limit", "reg"),
                ("ea_fault_reg", "keep"),
                ("mmr0_maint", "true"),
                ("par_width", "p12"),
                ("halt_vec", "vec010"),
            ][..],
        ),
        (
            "pdp11_44",
            "",
            &[
                "eis", "mmu", "id_split", "sm", "csm", "spl", "mfpt", "cis",
                "sob_mark", "sxt",
            ][..],
            &[
                ("jmp_reg_trap", "vec004"),
                ("mfpt_code", "1"),
                ("mmu_pa", "sel22"),
                ("mode_enc", "ksu"),
                ("stack_limit", "reg"),
                ("ea_fault_reg", "keep"),
                ("mmr0_maint", "true"),
                ("mmr3", "full"),
            ][..],
        ),
        (
            "pdp11_60",
            "",
            &["eis", "fp11", "mmu", "sob_mark", "sxt"][..],
            &[
                ("jmp_reg_trap", "vec010"),
                ("mmu_pa", "p18"),
                ("mode_enc", "ku"),
                ("stack_limit", "reg"),
                ("mmr0_maint", "true"),
                ("par_width", "p12"),
                ("halt_vec", "vec010"),
                ("sp_buserr", "fatal"),
                ("opr_same_reg", "inc"),
                ("pc_stored", "pc4"),
                ("rti_ttrap", "next"),
            ][..],
        ),
        (
            "pdp11_70",
            "",
            &[
                "eis",
                "mmu",
                "id_split",
                "sm",
                "dual_regset",
                "spl",
                "sob_mark",
                "sxt",
            ][..],
            &[
                ("jmp_reg_trap", "vec004"),
                ("mmu_pa", "p22"),
                ("mode_enc", "ksu"),
                ("mm_trap", "true"),
                ("dual_regset", "true"),
                ("stack_limit", "reg"),
                ("mmr0_maint", "true"),
                ("mmr3", "m22_ds"),
                ("mmr2_vec", "true"),
                ("pdr_extra", "true"),
                ("sp_buserr", "fatal"),
                ("wait_t", "hold"),
                ("rti_ttrap", "next"),
            ][..],
        ),
        (
            "pdp11_23",
            "",
            &["mmu", "mtps", "mfpt", "sob_mark", "sxt"][..],
            &[
                ("odd_addr_trap", "false"),
                ("jmp_reg_trap", "vec010"),
                ("mfpt_code", "3"),
                ("mmu_pa", "p18"),
                ("mode_enc", "f11"),
                ("stack_limit", "fixed"),
                ("mmr3", "m22"),
                ("halt_vec", "vec010"),
                ("sp_buserr", "fatal"),
                ("opr_same_reg", "inc"),
                ("pc_stored", "pc4"),
            ][..],
        ),
        (
            "pdp11_24",
            "pdp11_23",
            &["tstset_wrtlck"][..],
            &[("mmu_pa", "sel22")][..],
        ),
        (
            "pdp11_73",
            "",
            j11,
            &[
                ("jmp_reg_trap", "vec004"),
                ("mfpt_code", "5"),
                ("mmu_pa", "sel22"),
                ("mode_enc", "ksu"),
                ("stack_limit", "fixed"),
                ("dual_regset", "true"),
                ("mmr3", "full"),
                ("halt_vec", "vec004"),
                ("sp_buserr", "fatal"),
                ("opr_same_reg", "inc"),
                ("pc_stored", "pc4"),
                ("mfp_sp2", "user"),
                ("rti_ttrap", "next"),
            ][..],
        ),
        ("pdp11_83", "pdp11_73", &[][..], &[][..]),
        ("pdp11_93", "pdp11_83", &[][..], &[][..]),
        (
            "t11",
            "",
            &["mtps", "mfpt", "sob_mark", "sxt"][..],
            &[
                ("odd_addr_trap", "false"),
                ("psw_mapped", "false"),
                ("jmp_reg_trap", "vec010"),
                ("mfpt_code", "4"),
                ("sp_buserr", "notrap"),
                ("halt_vec", "powerup"),
                ("opr_same_reg", "inc"),
                ("pc_stored", "pc4"),
                ("rti_ttrap", "next"),
            ][..],
        ),
    ] {
        m.models.push(ModelDef {
        timing: None,
        params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            name: name.to_string(),
            parent: parent.to_string(),
            add_features: add.iter().map(|s| s.to_string()).collect(),
            remove_features: vec![],
            ident: vec![],
        });
    }

    // 汎用レジスタ r0-r7。構文上 r6=SP・r7=PC。
    m.regclasses.push(RegClass {
        name: "gr".to_string(),
        dynamic: false,
        prefix: Some(".".to_string()),
    });

    // 16 ビット命令語内の桁。
    //   smode(11-9) sreg(8-6) … ソース指定子
    //   dmode(5-3)  dreg(2-0) … 宛先指定子
    //   reg(8-6)              … JSR/EIS のリンク・被演算レジスタ
    //   rreg(2-0)             … RTS のレジスタ
    //   freg(2-0)             … FIS のスタックスルーレジスタ
    //   off8(7-0)             … 分岐変位・EMT/TRAP のコード
    //   off6(5-0)             … SOB 変位・MARK の個数
    //   n3(2-0)               … SPL の優先度
    //   ccm(3-0)              … 条件コード操作のマスク（NZVC の選択）
    // Ref: SPEC-PDP11-ARCH83（第5章 命令語構成）.
    for (name, hi, lo) in [
        ("smode", 11u32, 9u32),
        ("sreg", 8, 6),
        ("dmode", 5, 3),
        ("dreg", 2, 0),
        ("reg", 8, 6),
        ("rreg", 2, 0),
        ("freg", 2, 0),
        ("off8", 7, 0),
        ("off6", 5, 0),
        ("n3", 2, 0),
        ("ccm", 3, 0),
    ] {
        m.fields.push(Field {
            name: name.to_string(),
            kind: FieldKind::Bits { hi, lo },
        });
    }

    let fmt = |name: &str, fields: &[&str]| Format {
        name: name.to_string(),
        fields: fields.iter().map(|s| s.to_string()).collect(),
        operands: vec![],
    };
    // 二重オペランド（op + ソース指定子 + 宛先指定子）。
    m.formats.push(fmt("FD", &["smode", "sreg", "dmode", "dreg"]));
    // 単一オペランド（op + 指定子）。
    m.formats.push(fmt("FS", &["dmode", "dreg"]));
    // レジスタ + 指定子（JSR・EIS・XOR）。
    m.formats.push(fmt("FRD", &["reg", "dmode", "dreg"]));
    // レジスタ + 変位6（SOB）。
    m.formats.push(fmt("FRN", &["reg", "off6"]));
    // レジスタのみ（RTS）。
    m.formats.push(fmt("FR", &["rreg"]));
    // FIS のスタックスルーレジスタのみ。
    m.formats.push(fmt("FF", &["freg"]));
    // 8 ビット変位・コード（分岐・EMT・TRAP）。
    m.formats.push(fmt("FB", &["off8"]));
    // 6 ビット個数（MARK）。
    m.formats.push(fmt("FN6", &["off6"]));
    // 3 ビット優先度（SPL）。
    m.formats.push(fmt("FN3", &["n3"]));
    // 条件コード操作（op + マスク4）。
    m.formats.push(fmt("FCM", &["ccm"]));
    // オペランドなし（全桁固定の命令）。
    m.formats.push(fmt("F0", &[]));

    // 命令の宣言。パターンは語の上位ビットから書く（16 ビット固定）。
    // (名前, 形式, パターン, タイミング, 機能旗)。
    // Ref: SPEC-PDP11-ARCH83（第5章 命令エンコーディング）.
    let insns: &[(&str, &str, &str, &str, &str)] = &[
        // 二重オペランド。xSSDD（x=1-6 語、11-16 バイト）。
        ("mov", "FD", "0001............", "move", ""),
        ("movb", "FD", "1001............", "move", ""),
        ("cmp", "FD", "0010............", "alu", ""),
        ("cmpb", "FD", "1010............", "alu", ""),
        ("bit", "FD", "0011............", "alu", ""),
        ("bitb", "FD", "1011............", "alu", ""),
        ("bic", "FD", "0100............", "alu", ""),
        ("bicb", "FD", "1100............", "alu", ""),
        ("bis", "FD", "0101............", "alu", ""),
        ("bisb", "FD", "1101............", "alu", ""),
        ("add", "FD", "0110............", "alu", ""),
        ("sub", "FD", "1110............", "alu", ""),
        // 単一オペランド（語）。
        ("jmp", "FS", "0000 0000 01.. ....", "branch", ""),
        ("swab", "FS", "0000 0000 11.. ....", "alu", ""),
        ("clr", "FS", "0000 1010 00.. ....", "alu", ""),
        ("com", "FS", "0000 1010 01.. ....", "alu", ""),
        ("inc", "FS", "0000 1010 10.. ....", "alu", ""),
        ("dec", "FS", "0000 1010 11.. ....", "alu", ""),
        ("neg", "FS", "0000 1011 00.. ....", "alu", ""),
        ("adc", "FS", "0000 1011 01.. ....", "alu", ""),
        ("sbc", "FS", "0000 1011 10.. ....", "alu", ""),
        ("tst", "FS", "0000 1011 11.. ....", "alu", ""),
        ("ror", "FS", "0000 1100 00.. ....", "alu", ""),
        ("rol", "FS", "0000 1100 01.. ....", "alu", ""),
        ("asr", "FS", "0000 1100 10.. ....", "alu", ""),
        ("asl", "FS", "0000 1100 11.. ....", "alu", ""),
        ("mfpi", "FS", "0000 1101 01.. ....", "system", "mmu"),
        ("mtpi", "FS", "0000 1101 10.. ....", "system", "mmu"),
        ("sxt", "FS", "0000 1101 11.. ....", "alu", "sxt"),
        ("csm", "FS", "0000 1110 00.. ....", "system", "csm"),
        ("tstset", "FS", "0000 1110 10.. ....", "system", "tstset_wrtlck"),
        ("wrtlck", "FS", "0000 1110 11.. ....", "system", "tstset_wrtlck"),
        // 単一オペランド（バイト）。
        ("clrb", "FS", "1000 1010 00.. ....", "alu", ""),
        ("comb", "FS", "1000 1010 01.. ....", "alu", ""),
        ("incb", "FS", "1000 1010 10.. ....", "alu", ""),
        ("decb", "FS", "1000 1010 11.. ....", "alu", ""),
        ("negb", "FS", "1000 1011 00.. ....", "alu", ""),
        ("adcb", "FS", "1000 1011 01.. ....", "alu", ""),
        ("sbcb", "FS", "1000 1011 10.. ....", "alu", ""),
        ("tstb", "FS", "1000 1011 11.. ....", "alu", ""),
        ("rorb", "FS", "1000 1100 00.. ....", "alu", ""),
        ("rolb", "FS", "1000 1100 01.. ....", "alu", ""),
        ("asrb", "FS", "1000 1100 10.. ....", "alu", ""),
        ("aslb", "FS", "1000 1100 11.. ....", "alu", ""),
        ("mtps", "FS", "1000 1101 00.. ....", "system", "mtps"),
        ("mfpd", "FS", "1000 1101 01.. ....", "system", "mmu"),
        ("mtpd", "FS", "1000 1101 10.. ....", "system", "mmu"),
        ("mfps", "FS", "1000 1101 11.. ....", "system", "mtps"),
        // JSR・RTS・SOB。
        ("jsr", "FRD", "0000 100. .... ....", "branch", ""),
        ("rts", "FR", "0000 0000 1000 0...", "branch", ""),
        ("sob", "FRN", "0111 111. .... ....", "branch", "sob_mark"),
        // EIS（07xRSS）と XOR（074RDD）。
        ("mul", "FRD", "0111 000. .... ....", "alu", "eis"),
        ("div", "FRD", "0111 001. .... ....", "alu", "eis"),
        ("ash", "FRD", "0111 010. .... ....", "alu", "eis"),
        ("ashc", "FRD", "0111 011. .... ....", "alu", "eis"),
        ("xor", "FRD", "0111 100. .... ....", "alu", ""),
        // FIS（0750xR）。
        ("fadd", "FF", "0111 1010 0000 0...", "fp", "fis"),
        ("fsub", "FF", "0111 1010 0000 1...", "fp", "fis"),
        ("fmul", "FF", "0111 1010 0010 0...", "fp", "fis"),
        ("fdiv", "FF", "0111 1010 0011 0...", "fp", "fis"),
        // ── FP11（ARCH83 6章。17xxxx 空間。FIS とは両立しない）──
        // 固定形（170000-170077 直下の制御群）。
        ("cfcc", "F0", "1111 0000 0000 0000", "fp", "fp11"),
        ("setf", "F0", "1111 0000 0000 0001", "fp", "fp11"),
        ("seti", "F0", "1111 0000 0000 0010", "fp", "fp11"),
        ("setd", "F0", "1111 0000 0000 1001", "fp", "fp11"),
        ("setl", "F0", "1111 0000 0000 1010", "fp", "fp11"),
        // 単オペランド群。LDFPS/STFPS/STST は CPU 番地指定（モード 0
        // は GPR）、CLRF/TSTF/ABSF/NEGF は FP 番地指定（モード 0 は AC）。
        ("ldfps", "FS", "1111 0000 01.. ....", "fp", "fp11"),
        ("stfps", "FS", "1111 0000 10.. ....", "fp", "fp11"),
        ("stst", "FS", "1111 0000 11.. ....", "fp", "fp11"),
        ("clrf", "FS", "1111 0001 00.. ....", "fp", "fp11"),
        ("tstf", "FS", "1111 0001 01.. ....", "fp", "fp11"),
        ("absf", "FS", "1111 0001 10.. ....", "fp", "fp11"),
        ("negf", "FS", "1111 0001 11.. ....", "fp", "fp11"),
        // AC+オペランド群（FRD: reg<8:6> の下位 2 ビットが AC —
        // bit8 は命令対の選択子なので AC = reg & 3）。
        ("mulf", "FRD", "1111 0010 .... ....", "fp", "fp11"),
        ("modf", "FRD", "1111 0011 .... ....", "fp", "fp11"),
        ("addf", "FRD", "1111 0100 .... ....", "fp", "fp11"),
        ("ldf", "FRD", "1111 0101 .... ....", "fp", "fp11"),
        ("subf", "FRD", "1111 0110 .... ....", "fp", "fp11"),
        ("cmpf", "FRD", "1111 0111 .... ....", "fp", "fp11"),
        ("stf", "FRD", "1111 1000 .... ....", "fp", "fp11"),
        ("divf", "FRD", "1111 1001 .... ....", "fp", "fp11"),
        ("stexp", "FRD", "1111 1010 .... ....", "fp", "fp11"),
        ("stcfi", "FRD", "1111 1011 .... ....", "fp", "fp11"),
        ("stcfd", "FRD", "1111 1100 .... ....", "fp", "fp11"),
        ("ldexp", "FRD", "1111 1101 .... ....", "fp", "fp11"),
        ("ldcif", "FRD", "1111 1110 .... ....", "fp", "fp11"),
        ("ldcff", "FRD", "1111 1111 .... ....", "fp", "fp11"),
        // ── CIS（076nnn 空間。KE44-A —— SPEC-PDP11-CIS）──
        // bits<8:3> がグループ（02=L2D・03-07=レジスタ形・
        // 13-17=in-line 形）、bits<2:0> が群内の命令選択（L2D/L3D
        // は記述子ポインタを指すレジスタ r）。
        ("l2d", "FR", "0111 1100 0001 0...", "cis", "cis"),
        ("l3d", "FR", "0111 1100 0011 0...", "cis", "cis"),
        // キャラクタ文字列（レジスタ形 07603X・07604X）。
        ("movc", "F0", "0111 1100 0001 1000", "cis", "cis"),
        ("movrc", "F0", "0111 1100 0001 1001", "cis", "cis"),
        ("movtc", "F0", "0111 1100 0001 1010", "cis", "cis"),
        ("locc", "F0", "0111 1100 0010 0000", "cis", "cis"),
        ("skpc", "F0", "0111 1100 0010 0001", "cis", "cis"),
        ("scanc", "F0", "0111 1100 0010 0010", "cis", "cis"),
        ("spanc", "F0", "0111 1100 0010 0011", "cis", "cis"),
        ("cmpc", "F0", "0111 1100 0010 0100", "cis", "cis"),
        ("matc", "F0", "0111 1100 0010 0101", "cis", "cis"),
        // 数値十進文字列（レジスタ形 07605X）。
        ("addn", "F0", "0111 1100 0010 1000", "cis", "cis"),
        ("subn", "F0", "0111 1100 0010 1001", "cis", "cis"),
        ("cmpn", "F0", "0111 1100 0010 1010", "cis", "cis"),
        ("cvtnl", "F0", "0111 1100 0010 1011", "cis", "cis"),
        ("cvtpn", "F0", "0111 1100 0010 1100", "cis", "cis"),
        ("cvtnp", "F0", "0111 1100 0010 1101", "cis", "cis"),
        ("ashn", "F0", "0111 1100 0010 1110", "cis", "cis"),
        ("cvtln", "F0", "0111 1100 0010 1111", "cis", "cis"),
        // パック十進文字列（レジスタ形 07607X）。
        ("addp", "F0", "0111 1100 0011 1000", "cis", "cis"),
        ("subp", "F0", "0111 1100 0011 1001", "cis", "cis"),
        ("cmpp", "F0", "0111 1100 0011 1010", "cis", "cis"),
        ("cvtpl", "F0", "0111 1100 0011 1011", "cis", "cis"),
        ("mulp", "F0", "0111 1100 0011 1100", "cis", "cis"),
        ("divp", "F0", "0111 1100 0011 1101", "cis", "cis"),
        ("ashp", "F0", "0111 1100 0011 1110", "cis", "cis"),
        ("cvtlp", "F0", "0111 1100 0011 1111", "cis", "cis"),
        // キャラクタ文字列（in-line 形 07613X・07614X）。
        ("movci", "F0", "0111 1100 0101 1000", "cis", "cis"),
        ("movrci", "F0", "0111 1100 0101 1001", "cis", "cis"),
        ("movtci", "F0", "0111 1100 0101 1010", "cis", "cis"),
        ("locci", "F0", "0111 1100 0110 0000", "cis", "cis"),
        ("skpci", "F0", "0111 1100 0110 0001", "cis", "cis"),
        ("scanci", "F0", "0111 1100 0110 0010", "cis", "cis"),
        ("spanci", "F0", "0111 1100 0110 0011", "cis", "cis"),
        ("cmpci", "F0", "0111 1100 0110 0100", "cis", "cis"),
        ("matci", "F0", "0111 1100 0110 0101", "cis", "cis"),
        // 数値十進文字列（in-line 形 07615X）。
        ("addni", "F0", "0111 1100 0110 1000", "cis", "cis"),
        ("subni", "F0", "0111 1100 0110 1001", "cis", "cis"),
        ("cmpni", "F0", "0111 1100 0110 1010", "cis", "cis"),
        ("cvtnli", "F0", "0111 1100 0110 1011", "cis", "cis"),
        ("cvtpni", "F0", "0111 1100 0110 1100", "cis", "cis"),
        ("cvtnpi", "F0", "0111 1100 0110 1101", "cis", "cis"),
        ("ashni", "F0", "0111 1100 0110 1110", "cis", "cis"),
        ("cvtlni", "F0", "0111 1100 0110 1111", "cis", "cis"),
        // パック十進文字列（in-line 形 07617X）。
        ("addpi", "F0", "0111 1100 0111 1000", "cis", "cis"),
        ("subpi", "F0", "0111 1100 0111 1001", "cis", "cis"),
        ("cmppi", "F0", "0111 1100 0111 1010", "cis", "cis"),
        ("cvtpli", "F0", "0111 1100 0111 1011", "cis", "cis"),
        ("mulpi", "F0", "0111 1100 0111 1100", "cis", "cis"),
        ("divpi", "F0", "0111 1100 0111 1101", "cis", "cis"),
        ("ashpi", "F0", "0111 1100 0111 1110", "cis", "cis"),
        ("cvtlpi", "F0", "0111 1100 0111 1111", "cis", "cis"),
        // 分岐（op8 + 変位8）。
        ("br", "FB", "0000 0001 .... ....", "branch", ""),
        ("bne", "FB", "0000 0010 .... ....", "branch", ""),
        ("beq", "FB", "0000 0011 .... ....", "branch", ""),
        ("bge", "FB", "0000 0100 .... ....", "branch", ""),
        ("blt", "FB", "0000 0101 .... ....", "branch", ""),
        ("bgt", "FB", "0000 0110 .... ....", "branch", ""),
        ("ble", "FB", "0000 0111 .... ....", "branch", ""),
        ("bpl", "FB", "1000 0000 .... ....", "branch", ""),
        ("bmi", "FB", "1000 0001 .... ....", "branch", ""),
        ("bhi", "FB", "1000 0010 .... ....", "branch", ""),
        ("blos", "FB", "1000 0011 .... ....", "branch", ""),
        ("bvc", "FB", "1000 0100 .... ....", "branch", ""),
        ("bvs", "FB", "1000 0101 .... ....", "branch", ""),
        ("bcc", "FB", "1000 0110 .... ....", "branch", ""),
        ("bcs", "FB", "1000 0111 .... ....", "branch", ""),
        // トラップ命令（op8 + コード8）。
        ("emt", "FB", "1000 1000 .... ....", "system", ""),
        ("trap", "FB", "1000 1001 .... ....", "system", ""),
        // MARK・SPL。
        ("mark", "FN6", "0000 1101 00.. ....", "misc", "sob_mark"),
        ("spl", "FN3", "0000 0000 1001 1...", "system", "spl"),
        // 固定語。
        ("halt", "F0", "0000 0000 0000 0000", "system", ""),
        ("wait", "F0", "0000 0000 0000 0001", "system", ""),
        ("rti", "F0", "0000 0000 0000 0010", "system", ""),
        ("bpt", "F0", "0000 0000 0000 0011", "system", ""),
        ("iot", "F0", "0000 0000 0000 0100", "system", ""),
        ("reset", "F0", "0000 0000 0000 0101", "system", ""),
        ("rtt", "F0", "0000 0000 0000 0110", "system", ""),
        ("mfpt", "F0", "0000 0000 0000 0111", "system", "mfpt"),
        // LSI-11 の保守命令 000210-000217（付録 B 項目 33 ——
        // 他モデルは予約で location 10）。
        ("maint", "F0", "0000 0000 1000 1...", "misc", "maint"),
    ];
    for &(name, format, pattern, timing, feat) in insns {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: if feat.is_empty() {
                Pred::True
            } else {
                Pred::Flag(feat.to_string())
            },
            wheres: vec![],
            syntax: name.to_string(),
            timing: timing.to_string(),
        });
    }

    // 条件コード操作。「000240 + マスク」族は選択桁を消し（ccc）、
    // 「000260 + マスク」族は立てる（scc）—— マスク <3:0> の各桁が
    // NZVC に対応し、複数桁を一度に触れる（clc/clv/… や sec/sev/…
    // の個別名は ccm=1,2,4,8 の特例、全消し/全立ては ccm=15）。
    // nop は ccc 族のマスク 0 の正準名 —— 範囲の重なりは ccm の
    // wheres で切り分ける（nop が ccm==0、ccc が ccm!=0）。
    // Ref: SPEC-PDP11-ARCH83（第5章 条件コード操作）.
    let eq0 = WhereClause {
        field: "ccm".to_string(),
        op: WhereOp::Eq,
        rhs: WhereRhs::Lit(0),
    };
    let ne0 = WhereClause {
        op: WhereOp::Ne,
        ..eq0.clone()
    };
    for (name, format, pattern, wheres) in [
        ("nop", "F0", "0000 0000 1010 0000", vec![eq0]),
        ("ccc", "FCM", "0000 0000 1010 ....", vec![ne0]),
        ("scc", "FCM", "0000 0000 1011 ....", vec![]),
    ] {
        m.insns.push(Insn {
            name: name.to_string(),
            format: format.to_string(),
            pattern: Pattern::parse(pattern).expect("valid pattern"),
            when: Pred::True,
            wheres,
            syntax: name.to_string(),
            timing: "misc".to_string(),
        });
    }

    m
}
