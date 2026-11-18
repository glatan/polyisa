// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// x86 の機能・CPU モデル・識別情報の宣言と `when` ゲート（段階13、C2a）。
//
// 機能は CPUID の各リーフの報告単位に合わせる。`when` は
// map 記述（`x86map.rs`）と列挙記述（`x86min.rs`）の両経路に
// 適用し、既定経路とフォールバックで命令の有無が変わらないようにする。
// ゲートは機能の不足による `#UD`（未定義命令）を表す。実行モードの
// 違いは `x86map.rs` 側の `when`（`w("m64")` 等）が担う。
// 出典は SPEC-X86-INTEL-SDM Combined v093 (2026-09-24) である。
// Ref: SPEC-X86-INTEL-SDM (v093).

use polyisa_isadl::model::*;
use polyisa_isadl::pred::Pred;

/// 機能の宣言、CPU モデルの定義、識別情報の対応表をモデルに足し、
/// 宣言済みの命令へ `when` ゲートを適用する。`x86map::build_maps`
/// の後に呼ぶ（マップ項目を走査するため）。
pub fn build_cpu(m: &mut Model) {
    declare_features(m);
    declare_params(m);
    declare_models(m);
    declare_ident_bits(m);
    apply_gates(m);
}

fn feat(m: &mut Model, name: &str, implies: &[&str]) {
    m.features.push(Feature {
        name: name.to_string(),
        implies: implies.iter().map(|s| s.to_string()).collect(),
        conflicts: vec![],
    });
}

/// CPUID の報告ビットに対応する機能名の宣言。依存は「その機能が
/// 意味を持つ CPU は下位の拡張も持つ」関係だけを書く。
fn declare_features(m: &mut Model) {
    // 命令ゲート専用で、CPUID のビットを持たないもの。
    feat(m, "cpuid", &[]);
    // 80186 で追加された命令群（PUSHA/POPA/PUSH imm/IMUL3/INS/OUTS/
    // BOUND/シフト即値/ENTER/LEAVE）の世代旗。CPUID のビットは持たない。
    feat(m, "i186", &[]);
    // 80286 の実モードで有効な命令（SMSW/LMSW）の世代旗。
    feat(m, "i286", &[]);
    // 8086/8088 の 0F は POP CS（以降は副表への分岐）。
    feat(m, "pop_cs", &[]);
    // 8086-80286 の実モードでは 0x82 は 0x80 のエイリアスとして実行される。
    // 80286 では仕様外だが実機は実行する（sst-80286 実測）。
    feat(m, "op82", &[]);
    // 既存の列挙記述が持っていた互換用の旗。命令ゲートには使わない。
    feat(m, "i386", &["i186", "i286"]);
    // i486 で追加された命令群（BSWAP/XADD/CMPXCHG/INVD/INVLPG）の
    // 世代旗。CPUID のビットは持たない。
    feat(m, "i486", &["i386"]);
    // Leaf 1 EDX。
    feat(m, "fpu", &[]);
    feat(m, "vme", &[]);
    feat(m, "de", &[]);
    feat(m, "pse", &[]);
    feat(m, "tsc", &[]);
    feat(m, "msr", &[]);
    feat(m, "pae", &[]);
    feat(m, "mce", &[]);
    feat(m, "cx8", &[]);
    feat(m, "apic", &[]);
    feat(m, "sep", &[]);
    feat(m, "mtrr", &[]);
    feat(m, "pge", &[]);
    feat(m, "mca", &[]);
    feat(m, "cmov", &[]);
    feat(m, "pat", &[]);
    feat(m, "pse36", &[]);
    feat(m, "clfsh", &[]);
    feat(m, "mmx", &["fpu"]); // MMX は x87 状態を別名で使う
    feat(m, "fxsr", &[]);
    feat(m, "sse", &[]);
    feat(m, "sse2", &["sse"]);
    feat(m, "htt", &[]);
    // Leaf 1 ECX。
    feat(m, "sse3", &["sse2"]);
    feat(m, "pclmulqdq", &["sse2"]);
    feat(m, "dtes64", &[]);
    feat(m, "monitor", &[]);
    feat(m, "ds_cpl", &[]);
    feat(m, "vmx", &[]);
    feat(m, "smx", &[]);
    feat(m, "eist", &[]);
    feat(m, "tm2", &[]);
    feat(m, "ssse3", &["sse3"]);
    feat(m, "cnxt_id", &[]);
    feat(m, "sdbg", &[]);
    feat(m, "fma", &["avx"]);
    feat(m, "cx16", &[]);
    feat(m, "xtpr", &[]);
    feat(m, "pdcm", &[]);
    feat(m, "pcid", &[]);
    feat(m, "dca", &[]);
    feat(m, "sse4_1", &["ssse3"]);
    feat(m, "sse4_2", &["sse4_1"]);
    feat(m, "x2apic", &[]);
    feat(m, "movbe", &[]);
    feat(m, "popcnt", &[]);
    feat(m, "tsc_deadline", &[]);
    feat(m, "aesni", &["sse2"]);
    feat(m, "xsave", &[]);
    feat(m, "xsaveopt", &["xsave"]);
    feat(m, "osxsave", &["xsave"]);
    feat(m, "avx", &["xsave", "sse4_2"]);
    feat(m, "f16c", &["avx"]);
    feat(m, "rdrnd", &[]);
    feat(m, "hypervisor", &[]);
    // Leaf 7.0 EBX。
    feat(m, "fsgsbase", &[]);
    feat(m, "sgx", &[]);
    feat(m, "bmi1", &[]);
    feat(m, "hle", &[]);
    feat(m, "avx2", &["avx"]);
    feat(m, "smep", &[]);
    feat(m, "bmi2", &[]);
    feat(m, "erms", &[]);
    feat(m, "invpcid", &[]);
    feat(m, "rtm", &[]);
    feat(m, "pku", &[]);
    feat(m, "avx512f", &["avx2"]);
    feat(m, "avx512dq", &["avx512f"]);
    feat(m, "rdseed", &[]);
    feat(m, "adx", &[]);
    feat(m, "smap", &[]);
    feat(m, "avx512ifma", &["avx512f"]);
    feat(m, "clflushopt", &[]);
    feat(m, "clwb", &[]);
    feat(m, "avx512pf", &["avx512f"]);
    feat(m, "avx512er", &["avx512f"]);
    feat(m, "avx512cd", &["avx512f"]);
    feat(m, "sha", &["sse2"]);
    feat(m, "avx512bw", &["avx512f"]);
    feat(m, "avx512vl", &["avx512f"]);
    // Leaf 7.0 ECX。
    feat(m, "prefetchwt1", &[]);
    feat(m, "avx512vbmi", &["avx512f"]);
    feat(m, "umip", &[]);
    feat(m, "ospke", &["pku"]);
    feat(m, "waitpkg", &[]);
    feat(m, "avx512vbmi2", &["avx512f"]);
    feat(m, "cet_ss", &[]);
    feat(m, "gfni", &["sse2"]);
    feat(m, "vaes", &["avx", "aesni"]);
    feat(m, "vpclmulqdq", &["avx", "pclmulqdq"]);
    feat(m, "avx512vnni", &["avx512f"]);
    feat(m, "avx512bitalg", &["avx512f"]);
    feat(m, "avx512vpopcntdq", &["avx512f"]);
    feat(m, "rdpid", &[]);
    feat(m, "movdiri", &[]);
    feat(m, "movdir64b", &[]);
    feat(m, "enqcmd", &[]);
    feat(m, "cldemote", &[]);
    feat(m, "pks", &[]);
    // Leaf 7.0 EDX。
    feat(m, "uintr", &[]);
    feat(m, "hreset", &[]);
    feat(m, "serialize", &[]);
    feat(m, "cet_ibt", &[]);
    feat(m, "amx_bf16", &[]);
    feat(m, "avx512_fp16", &["avx512f"]);
    feat(m, "amx_tile", &[]);
    feat(m, "amx_int8", &[]);
    // Leaf 0x8000_0001 ECX。
    feat(m, "lahf_lm", &[]);
    feat(m, "svm", &[]);
    feat(m, "lzcnt", &[]);
    feat(m, "sse4a", &[]);
    feat(m, "misalignsse", &[]);
    feat(m, "prefetchw", &[]);
    feat(m, "xop", &["avx"]);
    feat(m, "lwp", &[]);
    feat(m, "fma4", &["avx"]);
    feat(m, "tbm", &[]);
    // Leaf 0x8000_0001 EDX。
    feat(m, "syscall", &[]);
    feat(m, "nx", &[]);
    feat(m, "mmxext", &["mmx"]);
    feat(m, "pdpe1gb", &["pae"]);
    feat(m, "rdtscp", &["tsc"]);
    feat(m, "lm", &["cx8", "cmov", "fxsr", "sse2"]);
    feat(m, "dnowext", &["mmxext"]);
    feat(m, "dnow", &["mmx"]);
}

fn intel<'a>(fam: &'a str, model: &'a str, step: &'a str) -> Vec<(&'static str, &'a str)> {
    vec![
        ("cpuid.vendor", "GenuineIntel"),
        ("cpuid.family", fam),
        ("cpuid.model", model),
        ("cpuid.stepping", step),
    ]
}

fn model(
    m: &mut Model,
    name: &str,
    parent: &str,
    add: &[&str],
    remove: &[&str],
    params: &[(&str, &str)],
    ident: Vec<(&str, &str)>,
) {
    m.models.push(ModelDef {
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        name: name.to_string(),
        parent: parent.to_string(),
        add_features: add.iter().map(|s| s.to_string()).collect(),
        remove_features: remove.iter().map(|s| s.to_string()).collect(),
        ident: ident
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    });
}

/// 挙動パラメータの宣言（cpu-models.md の `param` 句）。値は
/// `Params`（生成）で意味論が読む。出典は SDM の未定義記述と
/// AMD 側の観測値の差（GAP-0027 の枠組み）。
fn declare_params(m: &mut Model) {
    m.param(
        "bsf_zero_input",
        ParamKind::Enum(vec!["dest_unchanged".to_string(), "dest_zero".to_string()]),
        "dest_unchanged",
        "BSF/BSR で入力が 0 のときの宛先。Intel は宛先を保ち、AMD は 0 にする",
    );
    m.param(
        "push_sp",
        ParamKind::Enum(vec!["pre".to_string(), "post".to_string()]),
        "pre",
        "PUSH SP が積む値。80186 以降は元の SP、8086/8088 は減算後の SP",
    );
    m.param(
        "shift_count",
        ParamKind::Enum(vec!["masked".to_string(), "full".to_string()]),
        "masked",
        "シフト・回転の回数。80186 以降は下位 5 ビット、8086/8088 は CL 全体",
    );
    m.param(
        "flags_top",
        ParamKind::Enum(vec!["zero".to_string(), "ones".to_string()]),
        "zero",
        "実モードの FLAGS ビット 12-15。80286 以降は 0（書き込み可）、8086/80186 は常に 1",
    );
    m.param(
        "div_fault_ip",
        ParamKind::Enum(vec!["at_insn".to_string(), "next".to_string()]),
        "at_insn",
        "除算例外が積む戻り IP。80286 以降は DIV/IDIV の番地、8086/80186 は次命令の番地",
    );
    m.param(
        "addr_wrap",
        ParamKind::Enum(vec!["m24".to_string(), "m20".to_string()]),
        "m24",
        "実モードの実アドレスの折り返し。80286 以降は 24 ビット、8086/80186 は 20 ビット（1 MiB）",
    );
    m.param(
        "msw",
        ParamKind::Int(0xFFFF),
        "65520",
        "MSW（マシン状態ワード）。80286 のリセット値は 0xFFF0",
    );
    m.param(
        "rand_seed",
        ParamKind::Int(0xFFFF_FFFF),
        "2654435769",
        "RDRAND/RDSEED の決定的乱数列（splitmix64）のシード。真のエントロピー源は持たない",
    );
    m.param(
        "tsx_abort",
        ParamKind::Int(0xFFFF_FFFF),
        "0",
        "XBEGIN が常に失敗するとき EAX に書くアボートコード。トランザクション実行はモデル化しない",
    );
    m.param(
        "seg_limit",
        ParamKind::Enum(vec!["wrap".to_string(), "fault".to_string()]),
        "wrap",
        "実モードで 16 ビットオフセットを越える複数バイトアクセス。80286 以降は #SS/#GP、8086/80186 はオフセットを 64K で折り返す",
    );
    m.param(
        "stack_fault",
        ParamKind::Enum(vec!["ss".to_string(), "gp".to_string()]),
        "ss",
        "実モードのセグメント限界超過で SS 由来アクセスが起こす例外。80286 は SS も含めて #GP(13) に統一、80386 以降は #SS(12)",
    );
    m.param(
        "insn_len",
        ParamKind::Enum(vec!["none".to_string(), "l10".to_string(), "l15".to_string()]),
        "none",
        "1 命令の最大長。80286 は 10 バイト超で #GP、80386 以降は 15 バイト、8086/80186 は制限なし（SST 80286 実測）",
    );
    m.param(
        "stack_wrap",
        ParamKind::Enum(vec!["check".to_string(), "wrap".to_string()]),
        "check",
        "実モードのスタック系挙動まとめ（80386 系は wrap）。RET/RETF/IRET は全ポップを事前検査してからコミットし、PUSH/POP sreg の o32 形は word アクセス＋dword 分の SP 更新、制御移転でロードした EIP が 0xFFFF を越えれば移転自体が #GP（SST 80386 実測）",
    );
    m.param(
        "fault_atomic",
        ParamKind::Enum(vec!["partial".to_string(), "atomic".to_string()]),
        "atomic",
        "実モードのセグメント限界例外で未完了の途中状態を残すか。80286 は SI/DI 更新や追加の CX デクリメントが残り、80386 以降は全アクセスの限界を先に検査して一切残さない（SST 80286/80386 実測）",
    );
    m.param(
        "bcd",
        ParamKind::Enum(vec!["i8088".to_string(), "i286".to_string()]),
        "i286",
        "DAA/DAS/AAA/AAS の補正手続き。80286 以降は AX±0x106 と AL>0x99 判定、8086/8088 は AH±1 と AL+(AF?0:6)>0x9F 判定（SST 実測）",
    );
    m.param(
        "idiv8",
        ParamKind::Enum(vec!["cord".to_string(), "i286".to_string()]),
        "cord",
        "実モードのバイト IDIV の商境界。8086/80186 の CORD は商マグニチュード 128 で常に #DE、80286 以降は符号付き -128 を許容する（SST 80286 実測）",
    );
    m.param(
        "imul_flags",
        ParamKind::Enum(vec!["co".to_string(), "szp".to_string()]),
        "co",
        "IMUL のステータスフラグ。80286 は積の上位語から SF/ZF/PF を報告する（SST 80286 実測）。それ以降の世代は CF/OF のみ確定的で残りは未定義",
    );
    m.param(
        "shift8_over",
        ParamKind::Enum(vec!["zero".to_string(), "edge".to_string()]),
        "zero",
        "バイト SHL/SHR で回数が 8 を超えたときの CF/OF。zero は常に 0、edge は回数が 8 の倍数（16/24）のとき被演算子バイトの端ビットを残す（80386 実測、SST 80386）",
    );
}

fn declare_models(m: &mut Model) {
    // （名前, 親, 追加機能, 削除機能, パラメータ上書き, 識別情報）。
    // 先頭が `--cpu` 省略時の既定。
    // ident のキーは `cpuid.` で始まり、機能から導出できない値だけを書く。

    // 既定モデル。現在の実装がカバーする機能の和（汎用 x86-64）。
    model(
        m,
        "x86_64",
        "",
        &[
            "cpuid", "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep",
            "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clfsh", "mmx", "fxsr", "sse", "sse2",
            "sse3", "ssse3", "sse4_1", "sse4_2", "cx16", "popcnt", "rdtscp", "syscall", "nx",
            "lm", "lahf_lm", "i486", "lzcnt", "adx", "pclmulqdq", "aesni", "sha", "gfni",
            "rdrnd", "rdseed", "serialize", "fsgsbase", "cet_ss",
            "rtm", "pku", "uintr", "movdiri", "movdir64b", "enqcmd", "cldemote",
            "waitpkg", "hreset", "clwb", "clflushopt",
            "xsave", "xsaveopt", "osxsave",
        ],
        &[],
        &[],
        // SSE4.2 のある最古の世代に合わせた Nehalem の署名。
        intel("6", "26", "5"),
    );
    // x86-64 psABI のマイクロアーキテクチャ水準 v2-v4。
    model(
        m,
        "x86_64_v2",
        "x86_64",
        &["cx16", "popcnt"],
        // psABI v2 に LZCNT・ADX・PCLMUL・AES-NI・SHA・GFNI・
        // RDRAND・RDSEED・SERIALIZE は含まれないので既定モデルから
        // 継承した分を削る。XSAVEOPT は Sandy Bridge 以降なので
        // Westmere の版数を名乗る v2 からも削る（XSAVE 本体は
        // Penryn 世代の機能なので残す）。
        &["lzcnt", "adx", "pclmulqdq", "aesni", "sha", "gfni", "rdrnd", "rdseed", "serialize", "fsgsbase", "cet_ss", "rtm", "pku", "uintr", "movdiri", "movdir64b", "enqcmd", "cldemote", "waitpkg", "hreset", "clwb", "clflushopt", "xsaveopt"],
        &[],
        // v2 の水準（SSE4.2+POPCNT+CX16、AVX なし）は Westmere。
        intel("6", "44", "2"),
    );
    model(
        m,
        "x86_64_v3",
        "x86_64_v2",
        &[
            "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe", "osxsave", "adx",
            "pclmulqdq", "aesni", "xsaveopt",
        ],
        &[],
        &[],
        intel("6", "60", "3"),
    );
    model(
        m,
        "x86_64_v4",
        "x86_64_v3",
        &["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"],
        &[],
        &[],
        intel("6", "85", "4"),
    );
    // 実モード世代。CPUID を持つ 486 以降だけ識別情報を持つ。
    // `cpuid.max_basic`/`cpuid.max_ext` は報告する最大リーフ番号で、
    // 省略時は 7 と 0x8000_0008（導出側の既定値）。
    model(
        m,
        "i8088",
        "",
        &["pop_cs", "op82"],
        &[],
        &[
            ("push_sp", "post"),
            ("shift_count", "full"),
            ("flags_top", "ones"),
            ("div_fault_ip", "next"),
            ("addr_wrap", "m20"),
            ("seg_limit", "wrap"),
            ("bcd", "i8088"),
        ],
        vec![],
    );
    model(
        m,
        "i186",
        "i8088",
        &["i186", "op82"],
        &[],
        &[
            ("push_sp", "pre"),
            ("shift_count", "masked"),
            ("flags_top", "ones"),
            ("div_fault_ip", "next"),
            ("addr_wrap", "m20"),
            ("bcd", "i286"),
        ],
        vec![],
    );
    model(
        m,
        "i286",
        "i186",
        &["i286"],
        &["pop_cs"],
        &[
            ("flags_top", "zero"),
            ("div_fault_ip", "at_insn"),
            ("addr_wrap", "m24"),
            ("seg_limit", "fault"),
            ("stack_fault", "gp"),
            ("insn_len", "l10"),
            ("idiv8", "i286"),
            ("imul_flags", "szp"),
            ("fault_atomic", "partial"),
        ],
        vec![],
    );
    model(
        m,
        "i386",
        "",
        // 0x82 の 0x80 別名は 386EX でも実行される（SST 80386 実測）。
        &["fpu", "i386", "op82"],
        &[],
        &[
            ("seg_limit", "fault"),
            ("insn_len", "l15"),
            ("idiv8", "i286"),
            ("stack_wrap", "wrap"),
            ("shift8_over", "edge"),
        ],
        vec![],
    );
    let mut id486 = intel("4", "8", "0");
    id486.extend([("cpuid.max_basic", "1"), ("cpuid.max_ext", "0")]);
    // i486 以降は i386 の挙動パラメータ（stack_wrap=wrap 等）を
    // 継承するが、それらの値は 386EX の SST 実測に基づく近似で、
    // 他世代で同じとは検証されていない。
    model(m, "i486", "i386", &["cpuid", "i486"], &[], &[], id486);
    let mut idp5 = intel("5", "4", "4");
    idp5.extend([("cpuid.max_basic", "1"), ("cpuid.max_ext", "0")]);
    model(
        m,
        "pentium",
        "i486",
        &["vme", "de", "pse", "tsc", "msr", "cx8", "mce", "apic", "mmx"],
        &[],
        &[],
        idp5,
    );
    let mut idp6 = intel("6", "1", "9");
    idp6.extend([("cpuid.max_basic", "2"), ("cpuid.max_ext", "0")]);
    model(
        m,
        "pentium_pro",
        "pentium",
        &["cmov", "pge", "mca", "pae", "mtrr", "pse36"],
        &[],
        &[],
        idp6,
    );
    // Katmai（model 7）は PSN リーフを持つので最大ベーシックリーフは 3。
    let mut idp3 = intel("6", "7", "3");
    idp3.extend([("cpuid.max_basic", "3"), ("cpuid.max_ext", "0")]);
    model(
        m,
        "pentium_iii",
        "pentium_pro",
        &["fxsr", "sse", "sep", "pat"],
        &[],
        &[],
        idp3,
    );
    // 既存の既定名との互換（段階4の `generic32`）。i386 の旗だけを持つ。
    model(m, "generic32", "", &["i386"], &[], &[], vec![]);
}

/// 機能→CPUID ビットの対応表（`cpuid_bit` 宣言）。
fn declare_ident_bits(m: &mut Model) {
    let mut b = |feature: &str, leaf: u32, reg: &str, bit: u8| {
        m.ident_bit(feature, leaf, 0, reg, bit);
    };
    // Leaf 1 EDX。
    for (f, bit) in [
        ("fpu", 0u8),
        ("vme", 1),
        ("de", 2),
        ("pse", 3),
        ("tsc", 4),
        ("msr", 5),
        ("pae", 6),
        ("mce", 7),
        ("cx8", 8),
        ("apic", 9),
        ("sep", 11),
        ("mtrr", 12),
        ("pge", 13),
        ("mca", 14),
        ("cmov", 15),
        ("pat", 16),
        ("pse36", 17),
        ("clfsh", 19),
        ("mmx", 23),
        ("fxsr", 24),
        ("sse", 25),
        ("sse2", 26),
        ("htt", 28),
    ] {
        b(f, 0x1, "edx", bit);
    }
    // Leaf 1 ECX。
    for (f, bit) in [
        ("sse3", 0u8),
        ("pclmulqdq", 1),
        ("dtes64", 2),
        ("monitor", 3),
        ("ds_cpl", 4),
        ("vmx", 5),
        ("smx", 6),
        ("eist", 7),
        ("tm2", 8),
        ("ssse3", 9),
        ("cnxt_id", 10),
        ("sdbg", 11),
        ("fma", 12),
        ("cx16", 13),
        ("xtpr", 14),
        ("pdcm", 15),
        ("pcid", 17),
        ("dca", 18),
        ("sse4_1", 19),
        ("sse4_2", 20),
        ("x2apic", 21),
        ("movbe", 22),
        ("popcnt", 23),
        ("tsc_deadline", 24),
        ("aesni", 25),
        ("xsave", 26),
        ("osxsave", 27),
        ("avx", 28),
        ("f16c", 29),
        ("rdrnd", 30),
        ("hypervisor", 31),
    ] {
        b(f, 0x1, "ecx", bit);
    }
    // Leaf 7.0 EBX。
    for (f, bit) in [
        ("fsgsbase", 0u8),
        ("sgx", 2),
        ("bmi1", 3),
        ("hle", 4),
        ("avx2", 5),
        ("smep", 7),
        ("bmi2", 8),
        ("erms", 9),
        ("invpcid", 10),
        ("rtm", 11),
        ("pku", 15),
        ("avx512f", 16),
        ("avx512dq", 17),
        ("rdseed", 18),
        ("adx", 19),
        ("smap", 20),
        ("avx512ifma", 21),
        ("clflushopt", 23),
        ("clwb", 24),
        ("avx512pf", 26),
        ("avx512er", 27),
        ("avx512cd", 28),
        ("sha", 29),
        ("avx512bw", 30),
        ("avx512vl", 31),
    ] {
        b(f, 0x7, "ebx", bit);
    }
    // Leaf 7.0 ECX。
    for (f, bit) in [
        ("prefetchwt1", 0u8),
        ("avx512vbmi", 1),
        ("umip", 2),
        ("ospke", 4),
        ("waitpkg", 5),
        ("avx512vbmi2", 6),
        ("cet_ss", 7),
        ("gfni", 8),
        ("vaes", 9),
        ("vpclmulqdq", 10),
        ("avx512vnni", 11),
        ("avx512bitalg", 12),
        ("avx512vpopcntdq", 14),
        ("rdpid", 22),
        ("cldemote", 25),
        ("movdiri", 27),
        ("movdir64b", 28),
        ("enqcmd", 29),
        ("pks", 31),
    ] {
        b(f, 0x7, "ecx", bit);
    }
    // Leaf 7.0 EDX。
    for (f, bit) in [
        ("uintr", 5u8),
        ("serialize", 14),
        ("cet_ibt", 20),
        ("amx_bf16", 22),
        ("avx512_fp16", 23),
        ("amx_tile", 24),
        ("amx_int8", 25),
    ] {
        b(f, 0x7, "edx", bit);
    }
    // Leaf 0x8000_0001 ECX。
    for (f, bit) in [
        ("lahf_lm", 0u8),
        ("svm", 2),
        ("lzcnt", 5),
        ("sse4a", 6),
        ("misalignsse", 7),
        ("prefetchw", 8),
        ("xop", 11),
        ("lwp", 15),
        ("fma4", 16),
        ("tbm", 21),
    ] {
        b(f, 0x8000_0001, "ecx", bit);
    }
    // Leaf 0x8000_0001 EDX。
    for (f, bit) in [
        ("syscall", 11u8),
        ("nx", 20),
        ("mmxext", 22),
        ("pdpe1gb", 26),
        ("rdtscp", 27),
        ("lm", 29),
        ("dnowext", 30),
        ("dnow", 31),
    ] {
        b(f, 0x8000_0001, "edx", bit);
    }
    // Leaf 7.1 EAX（HRESET 等）は現行の CPUID 表がサブリーフ行を
    // 持たないので報告しない。HRESET 命令自体は機能旗で解読される。
}

// ---------------------------------------------------------------------------
// `when` ゲート
//
// 命令名の先頭の語（`_` 区切りの最初の要素）をニーモニックとして引く。
// 表は「そのニーモニックのどの形（MMX/XMM/接頭辞違い）でも同じ機能で
// あるもの」だけを載せ、形で機能が変わるものはオペランド由来の
// 判定（`op_features`/`mmx_era`/`f3_sse2`）に任せる。

/// ニーモニックから機能へ。SSE3 以降の拡張とシステム命令。
/// 先勝ち。`{mn}_xv_wv` 等に生成された名前も先頭の語で引ける。
fn named_gate(mn: &str) -> Option<&'static [&'static str]> {
    Some(match mn {
        // SSE4.2。
        "pcmpgtq" | "pcmpestri" | "pcmpestrm" | "pcmpistri" | "pcmpistrm" | "crc32" => {
            &["sse4_2"]
        }
        // SSE4.1。
        "ptest" | "pmuldq" | "pmulld" | "pcmpeqq" | "movntdqa" | "packusdw" | "blendps"
        | "blendpd" | "blendvps" | "blendvpd" | "pblendw" | "pblendvb" | "pextrb" | "pextrd" | "pextrq"
        | "extractps" | "pinsrb" | "pinsrd" | "pinsrq" | "insertps" | "dpps" | "dppd"
        | "roundps" | "roundpd" | "roundss" | "roundsd" | "mpsadbw" | "phminposuw" => {
            &["sse4_1"]
        }
        // pmovsx/pmovzx は 6 形あるので語頭で引く（named_gate へ渡す前に済ませる）。
        _ if mn.starts_with("pmovsx") || mn.starts_with("pmovzx") => &["sse4_1"],
        "pminsb" | "pminsd" | "pminuw" | "pminud" | "pmaxsb" | "pmaxsd" | "pmaxuw"
        | "pmaxud" => &["sse4_1"],
        // SSSE3。
        "pshufb" | "phaddw" | "phaddd" | "phaddsw" | "phsubw" | "phsubd" | "phsubsw"
        | "pmaddubsw" | "pmulhrsw" | "psignb" | "psignw" | "psignd" | "pabsb" | "pabsw"
        | "pabsd" | "palignr" => &["ssse3"],
        // SSE3（`fisttp` は SSE3 由来の x87 命令だが、他の ESC スロットと
        // 同じく世代差を意味論で扱う範囲なのでゲートしない）。
        "movddup" | "movsldup" | "movshdup" | "addsubpd" | "addsubps" | "haddpd" | "haddps"
        | "hsubpd" | "hsubps" | "lddqu" => &["sse3"],
        // SSE1 の変換。構文に xmm が出ない形（GPR 宛て）も拾うため名前で引く。
        "cvtps2pi" | "cvttps2pi" | "cvtpi2ps" | "cvtss2si" | "cvttss2si" | "cvtsi2ss" => {
            &["sse"]
        }
        // SSE2 の変換・転送。同上。
        "cvtsd2si" | "cvttsd2si" | "cvtsd2ss" | "cvtss2sd" | "cvtsi2sd" | "cvtpd2pi"
        | "cvttpd2pi" | "cvtpi2pd" | "cvtpd2ps" | "cvtps2pd" | "cvtdq2ps" | "cvtps2dq"
        | "cvttps2dq" | "cvtdq2pd" | "cvtpd2dq" | "cvttpd2dq" | "movq2dq" | "movdq2q" => {
            &["sse2"]
        }
        // Gap: GAP-0035
        // x87 本体は機能ゲートしない。FPU の無い 8088 では ESC 命令は
        // #UD でなく無視されるので、デコード不能にすると実モードが壊れる。
        // `fisttp`/`fcmov` 等の拡張エンコーディングも同じ ESC スロット
        // であり、世代差（8088 の無視・387 の予約スロット・486SX の
        // INT7・SSE3 以降の FISTTP）は実行段の話で A0/A2 の範囲に留める。
        // その他の拡張。
        "popcnt" => &["popcnt"],
        "movbe" => &["movbe"],
        // ADX 系と POPCNT 系の拡張。
        "lzcnt" => &["lzcnt"],
        "adcx" | "adox" => &["adx"],
        // BMI1/BMI2（VEX の GPR 演算。既定の avx を上書き）。
        "andn" | "blsr" | "blsmsk" | "blsi" | "bextr" => &["bmi1"],
        "bzhi" | "mulx" | "pdep" | "pext" | "rorx" | "sarx" | "shlx" | "shrx" => &["bmi2"],
        // FMA（132/213/231 の ps/pd/ss/sd）と F16C。
        _ if mn.starts_with("vfm") => &["fma"],
        "vcvtph2ps" | "vcvtps2ph" => &["f16c"],
        // AES-NI と PCLMULQDQ。AES-KL 系は別機能（AESKLE）なので
        // 語頭ではなく列挙で引く。
        "aesimc" | "aesenc" | "aesenclast" | "aesdec" | "aesdeclast"
        | "aeskeygenassist" => &["aesni"],
        "pclmulqdq" => &["pclmulqdq"],
        // SHA-NI と GFNI。
        "rdrand" => &["rdrnd"],
        "rdseed" => &["rdseed"],
        "serialize" => &["serialize"],
        _ if mn.starts_with("sha1") || mn.starts_with("sha256") => &["sha"],
        _ if mn.starts_with("gf2p8") => &["gfni"],
        "clflush" => &["clfsh"],
        // MXCSR の読み書きは SSE 付随。
        "ldmxcsr" | "stmxcsr" => &["sse"],
        // i486 で追加された命令（i386 との区別は i486 旗で表す）。
        "bswap" | "xadd" | "cmpxchg" => &["i486"],
        // Pentium の CMPXCHG8B。REX.W 形（CMPXCHG16B）は
        // `cx16` が要るが、REX はデコード時の `when` で表せないので
        // dispatch 側で検査する。`cx16` の参照は FEAT_CX16 定数を
        // 生成させるための恒真述語として `apply_gates` で足す。
        "cmpxchg8b" => &["cx8"],
        // FSGSBASE。
        "rdfsbase" | "rdgsbase" | "wrfsbase" | "wrgsbase" => &["fsgsbase"],
        // CET 影響スタックのユーザ形。
        "rdsspq" | "rdsspd" | "incsspq" | "incsspd" | "wrssq" | "wrssd" | "wrussq"
        | "wrussd" | "rstorssp" | "saveprevssp" | "setssbsy" | "clrssbsy" => &["cet_ss"],
        // TSX（XBEGIN は常にアボートする近似）。
        "xbegin" | "xend" | "xabort" | "xtest" => &["rtm"],
        // ユーザー割り込み。
        "uiret" | "testui" | "clui" | "stui" | "senduipi" => &["uintr"],
        // PKU。
        "rdpkru" | "wrpkru" => &["pku"],
        // キャッシュ制御と MOVDIR。
        "clwb" => &["clwb"],
        "clflushopt" => &["clflushopt"],
        "cldemote" => &["cldemote"],
        "movdiri" => &["movdiri"],
        "movdir64b" => &["movdir64b"],
        "enqcmd" | "enqcmds" => &["enqcmd"],
        "hreset" => &["hreset"],
        // WAITPKG。
        "umonitor" | "umwait" | "tpause" => &["waitpkg"],
        // システム・判定命令。
        // `fwait` は FPU なしでも定義される待機命令なのでゲートしない。
        "fwait" => &[],
        "cpuid" => &["cpuid"],
        "syscall" => &["syscall"],
        "sysenter" | "sysexit" => &["sep"],
        "rdtscp" => &["rdtscp"],
        "monitor" | "mwait" => &["monitor"],
        "rdtsc" => &["tsc"],
        "rdmsr" | "wrmsr" => &["msr"],
        "emms" => &["mmx"],
        "sfence" => &["sse"],
        "mfence" | "lfence" => &["sse2"],
        "fxsave" | "fxrstor" => &["fxsr"],
        "xsave" | "xrstor" => &["xsave"],
        "xsaveopt" => &["xsaveopt"],
        // XGETBV は OS の xsave 許可（OSXSAVE）が要る。XSETBV は
        // XSAVE 機能（+特権。CPL はモデル化しない）。
        "xgetbv" => &["osxsave"],
        "xsetbv" => &["xsave"],
        _ => return None,
    })
}

/// MMX 形のオペランドを持つが MMX ではなく SSE1/SSE2 由来の命令。
fn mmx_era(mn: &str) -> Option<&'static str> {
    Some(match mn {
        // SSE1 で追加された MMX 形（3DNow! 系を除く）。
        "pavgb" | "pavgw" | "pextrw" | "pinsrw" | "pmaxsw" | "pmaxub" | "pminsw"
        | "pminub" | "pmovmskb" | "pmulhuw" | "psadbw" | "pshufw" | "maskmovq"
        | "movntq" => "sse",
        // SSE2 で追加された MMX 形。
        "pmuludq" | "paddq" | "psubq" | "movq2dq" | "movdq2q" => "sse2",
        _ => return None,
    })
}

/// 必須接頭辞 0xF3 の既定は SSE1 だが、例外的に SSE2 の命令。
fn f3_sse2(mn: &str) -> bool {
    matches!(
        mn,
        "movdqu" | "movq" | "pshufhw" | "cvtss2sd" | "cvttps2dq" | "cvtdq2pd" | "movq2dq"
    )
}

/// SSE1 の XMM ニーモニック。列挙経路で XMM オペランドの命令を
/// SSE2 既定から切り分けるのに使う。
fn sse1_mn(mn: &str) -> bool {
    matches!(
        mn,
        "movaps" | "movups" | "movss" | "movhps" | "movlps" | "movhlps" | "movlhps"
        | "movmskps" | "movntps"
            // 単精度のパック・スカラ演算と比較。
            | "addps" | "subps" | "mulps" | "divps" | "minps" | "maxps" | "sqrtps"
            | "rsqrtps" | "rcpps" | "cmpps" | "shufps" | "unpckhps" | "unpcklps"
            | "andps" | "andnps" | "orps" | "xorps" | "comiss" | "ucomiss"
            | "addss" | "subss" | "mulss" | "divss" | "minss" | "maxss" | "sqrtss"
            | "rcpss" | "rsqrtss" | "cmpss"
            // SSE1 の変換。
            | "cvtps2pi" | "cvttps2pi" | "cvtpi2ps" | "cvtss2si" | "cvttss2si"
            | "cvtsi2ss"
            // MXCSR と XMM 形の SSE1 追加分。
            | "ldmxcsr" | "stmxcsr"
    )
}

/// 命令の完全名に対する個別のゲート。同じニーモニックでも符号化で
/// 世代が変わるものだけを拾う（`named_gate` より先に見る）。
fn exact_gate(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        // 0F 3A 起源の PEXTRW は SSE4.1（0F C5 形の PEXTRW は
        // MMX で SSE1、XMM で SSE2 なので名前全体で引く）。
        "pextrw_ew_xv" => &["sse4_1"],
        _ => return None,
    })
}

/// オペランドと必須接頭辞から機能を引く（マップ経路の既定）。
/// XMM は接頭辞で SSE と SSE2 を分け、MMX・ST は対応する機能にする。
fn op_features(ops: &[OpKind], pfx: PfxSel) -> Vec<&'static str> {
    let mut v = Vec::new();
    for op in ops {
        match op {
            OpKind::RegX | OpKind::RmX => v.push(match pfx {
                PfxSel::P66 | PfxSel::PF2 => "sse2",
                _ => "sse",
            }),
            OpKind::RegM | OpKind::RmM => v.push("mmx"),
            // x87 の ST オペランドは `fpu` でゲートしない（`named_gate`
            // のコメントを参照）。
            _ => {}
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

fn flags(feats: &[&str]) -> Pred {
    let mut parts: Vec<Pred> = feats
        .iter()
        .map(|f| Pred::Flag((*f).to_string()))
        .collect();
    match parts.len() {
        1 => parts.pop().unwrap(),
        _ => Pred::All(parts),
    }
}

/// `when` ゲートを両経路の命令に適用する。判定は名前（先勝ち）→
/// オペランド（マップ）/ 構文（列挙）の順で行い、既存の `when`
/// （実行モードの述語）は残して結合する。
fn apply_gates(m: &mut Model) {
    for map in &mut m.maps {
        for item in &mut map.items {
            if let MapItem::Insn(_, mi) = item {
                let mn = mi.name.split('_').next().unwrap_or("");
                let mut feats = match exact_gate(&mi.name).or(named_gate(mn)) {
                    Some(f) => f.to_vec(),
                    // VEX エンコードの既定は AVX。AVX2 以降の
                    // 項目は exact_gate/named_gate で個別に上書きする。
                    None if mi.vex.is_some() => vec!["avx"],
                    None => {
                        let mut f = op_features(&mi.ops, mi.pfx);
                        if f == ["sse"] && f3_sse2(mn) {
                            f = vec!["sse2"];
                        }
                        if f == ["mmx"]
                            && let Some(era) = mmx_era(mn)
                        {
                            f = vec![era];
                        }
                        f
                    }
                };
                // CMOVcc（cmova_gv_ev 等、先頭の語が cmov で始まる）。
                if feats.is_empty() && mn.starts_with("cmov") {
                    feats = vec!["cmov"];
                }
                if feats.is_empty() {
                    continue;
                }
                let gate = flags(&feats);
                mi.when = match &mi.when {
                    Pred::True => gate,
                    existing => Pred::All(vec![existing.clone(), gate]),
                };
                if mi.name == "cmpxchg8b_mq" {
                    // FEAT_CX16 定数を生成させる恒真参照（上記参照）。
                    let cx16 = Pred::Flag("cx16".to_string());
                    let taut = Pred::Any(vec![
                        cx16.clone(),
                        Pred::Not(Box::new(cx16)),
                    ]);
                    mi.when = Pred::All(vec![mi.when.clone(), taut]);
                }
            }
        }
    }
    for insn in &mut m.insns {
        // `en_*` はエントリ名の接頭辞なので、ニーモニックの判定では外す。
        let base = insn.name.strip_prefix("en_").unwrap_or(&insn.name);
        let mn = base.split('_').next().unwrap_or("");
        let feats = match exact_gate(&insn.name).or(named_gate(mn)) {
            Some(f) => f.to_vec(),
            None if insn.name.starts_with("cmov") => vec!["cmov"],
            None if insn.syntax.contains("xmm") => {
                // 構文に XMM が出る列挙命令は SSE 系。SSE3 以降の
                // 拡張名は named_gate が先に拾う。
                vec![if sse1_mn(mn) { "sse" } else { "sse2" }]
            }
            // x87 の列挙記述（`f*`・`x87*`）は `fpu` でゲートしない。
            _ => continue,
        };
        if feats.is_empty() {
            continue;
        }
        let gate = flags(&feats);
        insn.when = match &insn.when {
            Pred::True => gate,
            existing => Pred::All(vec![existing.clone(), gate]),
        };
    }
}
