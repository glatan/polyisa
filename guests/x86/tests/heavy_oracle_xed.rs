// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Intel XED をオラクルに x86 のデコードを差分する（層: oracle、E1b）。
//!
//! heavy_oracle_llvm と同じ方針で、候補の命令バイト列を網羅で生成し、
//! 一つずつ `xed -d` に投げて「オラクルが先頭バイトで命令を認識するか」
//! 「消費バイト長」「ニーモニック（ICLASS）」を polyisa（map 経路→
//! 列挙経路の順）と比較する。i386 と x86-64 の両モードで回す。
//!
//! llvm 版との違い:
//! - XED は消費バイトを canonical 化しない。入力の先頭から何バイトを
//!   1 命令として読んだかがそのまま出るので、長さは接頭辞込みで一致する。
//! - XED は新しい拡張（AVX-512・AMX・APX・AVX10・ACE・XOP・3DNow!）まで
//!   追従するので、コーパスに VEX/EVEX/XOP/REX2 のヘッドも含める。
//! - ニーモニックは ICLASS（大文字）を小文字にして比較。別名は表で吸収。
//!
//! ツールが無ければスキップする（testkit::reqs がフィルタを掛ける）。
//! オペランドの比較はしない。

use polyisa_guest_x86::{
    FEAT_BITS, MODE_ADR_A32, MODE_ADR_A64, MODE_ADR_SHIFT, MODE_M64, MODE_OPD_O32, MODE_OPD_SHIFT,
    decode_map,
};
use std::process::{Command, Stdio};

/// 32 ビットモードの `decode_map` モード値。
const MODES32: u32 = (MODE_OPD_O32 << MODE_OPD_SHIFT) | (MODE_ADR_A32 << MODE_ADR_SHIFT);
/// 64 ビットモード。
const MODES64: u32 = MODE_M64 | (MODE_OPD_O32 << MODE_OPD_SHIFT) | (MODE_ADR_A64 << MODE_ADR_SHIFT);

/// オラクルが返した先頭の命令。
enum Oracle {
    /// 先頭バイトで解読できない。
    Invalid,
    /// (ICLASS の小文字形, 消費バイト数)。
    Insn(String, usize),
}

/// `Insn` 名からニーモニックを取る。構文テンプレは `{0}` の
/// ような穴を持つので、CamelCase の先頭の語を使う。
fn insn_mnemonic(i: polyisa_guest_x86::Insn) -> String {
    let name = format!("{i:?}");
    // x86min の `en_` 系列は `EnSyscall` のような名になる。
    // 次が大文字のときだけ剥がす（`Enter` を壊さない）。
    let name =
        if name.len() > 2 && name.starts_with("En") && name.as_bytes()[2].is_ascii_uppercase() {
            &name[2..]
        } else {
            &name[..]
        };
    let mut end = 0usize;
    for (k, c) in name.char_indices() {
        if k > 0 && c.is_uppercase() {
            break;
        }
        end = k + c.len_utf8();
    }
    name[..end].to_lowercase()
}

/// polyisa 側の結果。(命令名, 消費バイト数)。検査対象は
/// 仕様駆動の `decode_map` だけとする。旧 `decode_model_ex` 列挙
/// 経路はモードを持たず（32/64 ビットの区別ができない）、
/// フォールバックに回すと m64 での INC/DEC 受理のような
/// 永遠に解消しない差分が混ざって分類がずれるため。
/// 列挙経路のカバレッジは heavy_oracle_llvm 側が測る。
fn polyisa_decode(bytes: &[u8], modes: u32, feats: u128) -> Option<(String, usize)> {
    decode_map(bytes, modes, feats).map(|d| (insn_mnemonic(d.insn), usize::from(d.len)))
}

/// `xed -d` に一命令列を渡す。出力は命令ごとに
/// 「残り入力の hex」→ ICLASS 等のブロックが並ぶ。先頭命令の
/// 消費長は、先頭の残り hex と 2 番目の残り hex の長さ差で取る。
/// `mode` は "64" か "32"。
fn oracle_decode(xed: &str, mode: &str, bytes: &[u8]) -> Result<Oracle, String> {
    let hex = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    let out = Command::new(xed)
        .args([format!("-{mode}"), "-d".to_string(), hex])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    // 解読失敗でも XED は終了コード非 0 でエラー行を出すので、
    // ステータスは見ずに標準出力だけを解析する。
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stdout.contains("XED CLIENT ERROR") || stderr.contains("ERROR") {
        return Err("client error".to_string());
    }
    let mut remain: Vec<usize> = Vec::new();
    let mut iclass: Option<String> = None;
    for l in stdout.lines() {
        let t = l.trim();
        if !t.is_empty()
            && t.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        {
            remain.push(t.len() / 2);
        } else if let Some(rest) = t.strip_prefix("ICLASS:") {
            if iclass.is_none() {
                iclass = Some(rest.trim().to_lowercase());
            }
        } else if t.starts_with("ERROR:") && iclass.is_none() {
            return Ok(Oracle::Invalid);
        }
    }
    let Some(mn) = iclass else {
        return Ok(Oracle::Invalid);
    };
    // 残り hex が 2 つあれば差が先頭命令の長さ。1 つなら
    // 先頭命令がバッファをすべて消費した。
    let len = match remain.as_slice() {
        [a, b, ..] => match a.checked_sub(*b) {
            Some(l) => l,
            None => return Ok(Oracle::Invalid),
        },
        [a] => *a,
        _ => return Ok(Oracle::Invalid),
    };
    Ok(Oracle::Insn(mn, len))
}

/// 条件コードを正規形に写す。同一条件の綴り違いを同一視する。
fn canon_cc(cc: &str) -> &str {
    match cc {
        "b" | "c" | "nae" => "b",
        "ae" | "nb" | "nc" => "ae",
        "e" | "z" => "e",
        "ne" | "nz" => "ne",
        "be" | "na" => "be",
        "a" | "nbe" => "a",
        "p" | "pe" => "p",
        "po" | "np" => "po",
        "l" | "nge" => "l",
        "nl" | "ge" => "ge",
        "le" | "ng" => "le",
        "nle" | "g" => "g",
        other => other,
    }
}

/// ニーモニックの一致判定。XED の ICLASS と我々の Insn 名は
/// ほぼ canonical 名で一致する。系統的な別名は規則で吸収する。
fn same_mnemonic(ours: &str, xed: &str) -> bool {
    let ours = ours.trim_end_matches([',', ' ']);
    if ours == xed {
        return true;
    }
    // 文字列命令の REP 系: XED は接頭辞をニーモニックに畳み込む
    // （rep_insb・repne_cmpsb 等）。基底名で比較する。
    for rep in ["repne_", "repe_", "rep_"] {
        if let Some(rest) = xed.strip_prefix(rep)
            && same_mnemonic(ours, rest)
        {
            return true;
        }
    }
    // 条件コード系: j<cc> / setj<cc> vs set<cc> / cmovj<cc> vs cmov<cc>。
    // 綴りの別名（ae/nb、z/e、nbe/a …）は canon_cc で正規形に揃える。
    for (op, xp) in [
        (ours.strip_prefix('j'), Some("j")),
        (ours.strip_prefix("setj"), Some("set")),
        (ours.strip_prefix("cmovj"), Some("cmov")),
        (ours.strip_prefix("set"), Some("set")),
        (ours.strip_prefix("cmov"), Some("cmov")),
    ] {
        if let (Some(rest), Some(pre)) = (op, xp)
            && let Some(xcc) = xed.strip_prefix(pre)
            && !rest.is_empty()
            && canon_cc(rest) == canon_cc(xcc)
        {
            return true;
        }
    }
    // サイズ接尾語: movsb/movsd、insb/insd、pushfd/pushfq 等。
    // 我々は基底名（movs/pushf）に対して XED は要素幅で名を分ける。
    if xed.len() == ours.len() + 1
        && xed.starts_with(ours)
        && matches!(xed.as_bytes()[xed.len() - 1], b'b' | b'w' | b'd' | b'q')
    {
        return true;
    }
    // XED の修飾接尾語: call_near/ret_far、syscall_amd/syscall_intel、
    // movsd_xmm/pextrw_sse4、bextr_xop。基底名が一致すれば同一命令。
    if let Some((base, _)) = xed.split_once('_')
        && base == ours
    {
        return true;
    }
    // （我々の名, XED ICLASS の小文字形）の既知の別名。
    const ALIAS: &[(&str, &str)] = &[
        // 我々は generic 名、XED は far 形を分ける。
        ("callf", "call_far"),
        ("retf", "ret_far"),
        ("jmpf", "jmp_far"),
        // near 形は _near 接尾語で上の base 規則が処理する。
        ("iret", "iretd"),
        ("iret", "iretq"),
        ("iretd", "iret"),
        ("sal", "shl"),
        ("wait", "fwait"),
        ("int", "int1"),
        ("mov", "movabs"),
        ("xlat", "xlat"),
        ("xlatb", "xlat"),
        // サイズ別名。我々は opdsize 非依存の名。
        ("cwde", "cdqe"),
        ("cdq", "cqo"),
        ("cwde", "cbw"),
        ("cdq", "cwd"),
        ("sysret", "sysret64"),
        ("fxsave", "fxsave64"),
        ("fxrstor", "fxrstor64"),
        ("movd", "movq"),
        ("jcxz", "jecxz"),
        ("jcxz", "jrcxz"),
        // 0x90。我々は xchg、XED は nop を canonical にする。
        ("xchg", "nop"),
        // APX NDD の push/pop。XED は pushp/popp と名付ける。
        ("push", "pushp"),
        ("pop", "popp"),
        // x87 の fn- 接頭辞差。
        ("fnstenv", "fstenv"),
        ("fnsave", "fsave"),
        ("fnstsw", "fstsw"),
        ("fnstcw", "fstcw"),
        ("fnclex", "fclex"),
        ("fninit", "finit"),
        ("fndisi", "fdisi"),
        ("fneni", "feni"),
        ("fstp", "fstpnce"),
    ];
    ALIAS.iter().any(|(o, l)| ours == *o && xed == *l)
}

/// 候補の命令バイト列。(head, 全体)。head はオペコード部で、
/// 差分の既知表のキーに使う。
fn corpus() -> Vec<(Vec<u8>, Vec<u8>)> {
    let tail = [0x41u8, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a];
    let modrms = [
        0xC0u8, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8, // mod=11 reg 0-7
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6,
        0xC7, // mod=11 rm 1-7（group_rm 副エンコーディング）
        0x05, 0x40, 0x85, // メモリ形
        0x04, 0x44,
        0x84, // SIB（mod=00/01/10, rm=100。SIB バイトは tail から取る）
    ];
    // VEX/EVEX/XOP 系は数が多いので ModRM を絞る。
    let vmodrms = [0xC0u8, 0xD8, 0x05, 0x44];
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut put_ms = |head: &[u8], ms: &[u8]| {
        for &m in ms {
            let mut v = head.to_vec();
            v.push(m);
            v.extend_from_slice(&tail);
            // `xed -d` の入力は 15 バイトまで（x86 の最長命令）。
            v.truncate(15);
            out.push((head.to_vec(), v));
        }
    };
    for op in 0x00..=0xFFu8 {
        put_ms(&[op], &modrms);
    }
    for op2 in 0x00..=0xFFu8 {
        put_ms(&[0x0F, op2], &modrms);
    }
    // LOCK（F0）は「lockable な命令のメモリ形のみ有効」という
    // 非対称の受理規則を持つので、primary と 0F の全オペコードを
    // F0 付きで回す（modrm の両形で受理/拒否を比較できる）。
    for op in 0x00..=0xFFu8 {
        put_ms(&[0xF0, op], &modrms);
        put_ms(&[0xF0, 0x0F, op], &modrms);
    }
    // 66/F2/F3 + primary（x87 や REP/PAUSE/ヒント系列の
    // 接頭辞受理を検証する）。
    for &pfx in &[0x66u8, 0xF2, 0xF3] {
        for op in 0x00..=0xFFu8 {
            put_ms(&[pfx, op], &modrms);
        }
    }
    // 必須接頭辞付き 0F マップ（66/F2/F3 0F xx）。0x38/0x3A は
    // サブマップの専用ループが全 third バイトを回すので除く。
    for &pfx in &[0x66u8, 0xF2, 0xF3] {
        for op2 in 0x00..=0xFFu8 {
            if op2 != 0x38 && op2 != 0x3A {
                put_ms(&[pfx, 0x0F, op2], &modrms);
            }
        }
    }
    // 0F 38 / 0F 3A サブマップ。NP 形（MOVBE/SHA/MOVRS）もあるので
    // 接頭辞なし・付きの両方を回す。
    for op3 in 0x00..=0xFFu8 {
        put_ms(&[0x0F, 0x38, op3], &modrms);
        put_ms(&[0x0F, 0x3A, op3], &modrms);
    }
    for &pfx in &[0x66u8, 0xF2, 0xF3] {
        for op3 in 0x00..=0xFFu8 {
            put_ms(&[pfx, 0x0F, 0x38, op3], &modrms);
            put_ms(&[pfx, 0x0F, 0x3A, op3], &modrms);
        }
    }
    // VEX 2 バイト（C5）。byte1 = ~R vvvv L pp。vvvv=~0 と L 有無の2形。
    for pp in 0..4u8 {
        for op in 0x00..=0xFFu8 {
            put_ms(&[0xC5, 0xF8 | pp, op], &vmodrms);
            put_ms(&[0xC5, 0xFC | pp, op], &vmodrms); // L=1
        }
    }
    // VEX 3 バイト（C4）。byte1 = ~RXB mmmmm、map 1/2/3。
    // byte2 = W vvvv L pp。W=0/1・vvvv=~0 の2形。
    for map in 1..=3u8 {
        for pp in 0..4u8 {
            for op in 0x00..=0xFFu8 {
                let b1 = 0xE0 | map;
                put_ms(&[0xC4, b1, 0x78 | pp, op], &vmodrms); // W=0 L=0
                put_ms(&[0xC4, b1, 0xF8 | pp, op], &vmodrms); // W=1 L=0
                if map != 1 {
                    put_ms(&[0xC4, b1, 0x7C | pp, op], &vmodrms); // W=0 L=1
                    put_ms(&[0xC4, b1, 0xFC | pp, op], &vmodrms); // W=1 L=1
                }
            }
        }
    }
    // XOP（8F）。byte1 = ~RXB mmmmm、map 8/9/10。
    // byte2 = W vvvv L pp。XOP は pp を持つ（map9 の TBM 系）。
    for map in [8u8, 9, 10] {
        for pp in 0..4u8 {
            for op in 0x00..=0xFFu8 {
                let b1 = 0xE0 | map;
                put_ms(&[0x8F, b1, 0x78 | pp, op], &vmodrms);
            }
        }
    }
    out
}

/// EVEX（62）の候補。64 ビットモードのみ（32 ビットでは EVEX.V'
/// が 1 固定で、我々のデコーダも m64 のみ対応）。
/// P0 = ~RXB~R' 0 mm、P1 = W vvvv 1 pp、P2 = 00。
/// map 1/2/3/5 は L'L=00（x）と 10（z）の2形、map4（APX 昇格）は
/// P2.4=ND の 0/1 を試す。W=0/1 の2形。
fn corpus_evex() -> Vec<(Vec<u8>, Vec<u8>)> {
    let tail = [0x41u8, 0x42, 0x43, 0x44];
    let vmodrms = [0xC0u8, 0xD8, 0x05, 0x44];
    let mut out = Vec::new();
    let mut put = |head: &[u8]| {
        for &m in &vmodrms {
            let mut v = head.to_vec();
            v.push(m);
            v.extend_from_slice(&tail);
            v.truncate(15);
            out.push((head.to_vec(), v));
        }
    };
    for map in 1..=5u8 {
        for pp in 0..4u8 {
            for op in 0x00..=0xFFu8 {
                let p0 = 0xF0 | map;
                let (p1s, p2s): (&[u8], &[u8]) = if map == 4 {
                    // APX 昇格は U（P1.2）と ND/NF（P2.4/P2.2）の
                    // 0/1 の組み合わせが受理に効く（evex_u/nf_ok/
                    // ndd ゲート）。
                    (&[0x7C | pp, 0x78 | pp], &[0x00, 0x10, 0x04])
                } else {
                    (&[0x7C | pp], &[0x00, 0x40])
                };
                for &p2 in p2s {
                    for &p1 in p1s {
                        put(&[0x62, p0, p1, p2, op]); // W=0
                        put(&[0x62, p0, 0x80 | p1, p2, op]); // W=1
                    }
                }
            }
        }
    }
    out
}

/// REX2（D5）の候補。64 ビットモードのみ意味を持つ。
/// ペイロードは `[M0 R4 X4 B4 | W R3 X3 B3]`。M0=0 は map0、
/// M0=1 は map1（0F）。
fn corpus_rex2() -> Vec<(Vec<u8>, Vec<u8>)> {
    let tail = [0x41u8, 0x42, 0x43, 0x44];
    let modrms = [0xC0u8, 0xD8, 0x05, 0x44];
    let mut out = Vec::new();
    let mut put = |head: &[u8]| {
        for &m in &modrms {
            let mut v = head.to_vec();
            v.push(m);
            v.extend_from_slice(&tail);
            v.truncate(15);
            out.push((head.to_vec(), v));
        }
    };
    // 拡張ビットを変えたペイロードで map0 と map1 を回す。
    for op in 0x00..=0xFFu8 {
        for &p in &[0x00u8, 0x18, 0x49, 0x51] {
            put(&[0xD5, p, op]);
        }
        for &p in &[0x80u8, 0x98, 0xC9, 0xD1] {
            put(&[0xD5, p, op]);
        }
    }
    out
}

#[derive(Default)]
struct Diff {
    /// オラクルは解読するが polyisa が拒否。head → (件数, 例)。
    missing: std::collections::BTreeMap<String, (usize, String)>,
    /// polyisa は解読するがオラクルが拒否。
    spurious: std::collections::BTreeMap<String, (usize, String)>,
    /// 長さの不一致。
    len: std::collections::BTreeMap<String, (usize, String)>,
    /// ニーモニックの不一致。
    mnemonic: std::collections::BTreeMap<String, (usize, String)>,
}

fn bump(m: &mut std::collections::BTreeMap<String, (usize, String)>, key: &str, e: String) {
    let v = m.entry(key.to_string()).or_default();
    v.0 += 1;
    if v.1.is_empty() {
        v.1 = e;
    }
}

fn hexs(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_pass(
    xed: &str,
    mode_flag: &str,
    modes: u32,
    feats: u128,
    mode: &str,
    cands: &[(Vec<u8>, Vec<u8>)],
) -> Diff {
    let mut diff = Diff::default();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    // オラクル結果を並列に取る。ツール呼び出しの失敗は
    // Invalid と区別して数え、最後に失敗させる（起動失敗を
    // 「解読不能」と誤認して静かに通過しないため）。
    let errs = std::sync::atomic::AtomicUsize::new(0);
    let mut results: Vec<Option<Oracle>> =
        std::iter::repeat_with(|| None).take(cands.len()).collect();
    std::thread::scope(|s| {
        let errs = &errs;
        let chunk = cands.len().div_ceil(threads);
        let mut hs = Vec::new();
        for (slice, r) in cands.chunks(chunk).zip(results.chunks_mut(chunk)) {
            hs.push(s.spawn(move || {
                for (i, cand) in slice.iter().enumerate() {
                    match oracle_decode(xed, mode_flag, &cand.1) {
                        Ok(o) => r[i] = Some(o),
                        Err(_) => {
                            errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
    });
    let errs = errs.into_inner();
    if errs > 0 {
        panic!("{mode}: xed の呼び出しが {errs} 回失敗");
    }
    for (i, (head, cand)) in cands.iter().enumerate() {
        let oracle = results[i].as_ref().unwrap_or(&Oracle::Invalid);
        let ours = polyisa_decode(cand, modes, feats);
        let h = hexs(&cand[..cand.len().min(8)]);
        // ヘッドのキー。サブマップ・接頭辞付きは全体の先頭数バイトを含める。
        // ModRM.reg で副選択されるグループオペコードは head に
        // ModRM も足し、部分的に宣言済みの族が head キーで丸ごと
        // 隠れないようにする。
        const GROUP0F: &[u8] = &[
            0x00, 0x01, 0x0D, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x71, 0x72, 0x73,
            0x78, 0x79, 0xAE, 0xB9, 0xBA, 0xC7,
        ];
        const GROUP0: &[u8] = &[
            0x80, 0x81, 0x82, 0x83, 0x8F, 0xC0, 0xC1, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6,
            0xF7, 0xFE, 0xFF,
        ];
        let group_head = |head: &[u8]| -> bool {
            let Some(&last) = head.last() else {
                return false;
            };
            let n = head.len();
            if n >= 2 && head[n - 2] == 0x0F {
                GROUP0F.contains(&last)
            } else if n >= 2 && head[n - 2] == 0x38 && head[n - 1] == 0x0F {
                false
            } else if n >= 3 && head[n - 3] == 0x0F && head[n - 2] == 0x38 {
                matches!(last, 0xF0 | 0xF1)
            } else if n == 1 || !matches!(head[0], 0x0F | 0x62 | 0xC4 | 0xC5 | 0xD5 | 0x8F) {
                GROUP0.contains(&last)
            } else {
                false
            }
        };
        let key = match head.as_slice() {
            [0x0F, 0x38] | [0x0F, 0x3A] => hexs(&cand[..3]),
            _ if group_head(head) => hexs(&cand[..head.len() + 1]),
            _ => hexs(head),
        };
        match (ours, oracle) {
            (None, Oracle::Invalid) => {}
            (None, Oracle::Insn(mn, l)) => {
                let e = format!("{h}: oracle {mn} len {l}");
                if !known(&key, "missing", mode) {
                    bump(&mut diff.missing, &key, e);
                }
            }
            (Some((n, ol)), Oracle::Invalid) => {
                let e = format!("{h}: ours {n} len {ol}");
                if !known(&key, "spurious", mode) {
                    bump(&mut diff.spurious, &key, e);
                }
            }
            (Some((n, ol)), Oracle::Insn(mn, l)) => {
                if *l != ol {
                    let e = format!("{h}: ours {n} len {ol} vs {mn} len {l}");
                    if !known(&key, "len", mode) {
                        bump(&mut diff.len, &key, e);
                    }
                } else if !same_mnemonic(&n, mn) && !known(&key, "mnemonic", mode) {
                    bump(&mut diff.mnemonic, &key, format!("{h}: ours {n} vs {mn}"));
                }
            }
        }
    }
    diff
}

/// 既知の差分。(head hex, 種別, モード)。head はオペコードバイト列。
/// 末尾が ` ..` の項目はトークン境界のプレフィックス一致。
/// 宣言の有無が一様な命令族（未宣言の拡張マップなど）だけに
/// 使い、部分的に宣言済みの族には個別キーを残す。
fn known(head: &str, kind: &str, mode: &str) -> bool {
    KNOWN.iter().any(|(h, k, m)| {
        let hm = if let Some(p) = h.strip_suffix(" ..") {
            head == p || head.starts_with(&format!("{p} "))
        } else {
            *h == head
        };
        hm && (*k == kind || *k == "*") && (*m == "*" || *m == mode)
    })
}

/// 既知の差分の一覧。分類は llvm 版と同じ方針（後続ステップの
/// 対象・gate・strict・loose・x87・別名差）。各行は
/// （鍵プレフィックス, 差分種別, モード）。鍵は `head` の
/// 前方一致（末尾 ` ..` はそのプレフィックス全体に展開）。
///
/// 現状の内訳:
/// - `0f 01`/`0f 20-23`/`66 0f 38 80-82` 等の missing: 特権・
///   仮想化命令（ENCLV, MOV_CR/DR, INVEPT/INVVPID/INVPCID,
///   VMRUN 等）。ユーザー空間では使わないので未宣言。
/// - `8f e8/e9/ea`・`c4 e2 7*`・`62 ..` の missing: XOP/FMA4・
///   AVX-512VL・APX など宣言していない命令群。ロードマップの
///   後続ステップで追加する。
/// - `c5 f*`・`c4 e1 *` の missing: AVX-512 マスクレジスタ命令
///   （KMOV/KAND/KTEST/KSHIFT 等）と未宣言の VEX 形。
/// - x87 (`d8`-`df`) の mnemonic/spurious: mod=11 レジスタ形を
///   メモリ形名（FILD/FIADD 等）で返す既知の近似。意味論側は
///   mod を見て正しく FCMOV/FADDP 等を実行する。
/// - `0f 0d`/`0f 18`/`0f 1c`/`f3 0f 1e` の mnemonic: ヒント
///   系列の命名差（XED は PREFETCH/CLDEMOTE/NOP を区別し、
///   我々は nop/cldemote で一括）。
/// - gather (`c4 e2 * 90-93`) の spurious: 宛先・index・
///   マスクの非重複規則（重複は #UD）を XED のみが検査する
///   既知の近似。
/// - AMX (`c4 e2 7* 5c/5e/6c`) の spurious: TDP* の vvvv/形式
///   制約を XED のみが厳密に検査する差。
/// - `66/f2/f3` + x87 reg 形: 我々の mod=11 近似が予約
///   エンコーディングを受理する差（spurious）と、メモリ形名と
///   FCMOV/FADDP 等の実名の差（mnemonic）の既知近似。
/// - gather (`c4 e2 {7d,fd} 90-93`) の spurious: 宛先・index・
///   マスクの非重複規則を XED のみが検査する既知の近似。
/// - `62 f4` 系 missing: APX の CCMP/CTEST・CC 付き CMOV・
///   NDD SHLD/SHRD・ADCX/ADOX の未実装族。
/// - `62` 系 missing: EVEX ベースの未宣言 AVX-512 空間。
const KNOWN: &[(&str, &str, &str)] = &[
    ("62", "missing", "*"),
    ("62 f1 7c 00 ..", "missing", "x86-64"),
    ("62 f1 7d 00 ..", "missing", "x86-64"),
    ("62 f1 7f ..", "missing", "x86-64"),
    ("62 f1 fd 00 ..", "missing", "x86-64"),
    ("62 f1 ff ..", "missing", "x86-64"),
    ("62 f2 7c ..", "missing", "x86-64"),
    ("62 f2 7e ..", "missing", "x86-64"),
    ("62 f2 7f ..", "missing", "x86-64"),
    ("62 f2 fc ..", "missing", "x86-64"),
    ("62 f2 fd ..", "missing", "x86-64"),
    ("62 f2 fe ..", "missing", "x86-64"),
    ("62 f2 ff ..", "missing", "x86-64"),
    ("62 f4 7a ..", "missing", "x86-64"),
    ("62 f4 fa ..", "missing", "x86-64"),
    ("62 f5 7c ..", "missing", "x86-64"),
    ("62 f5 fe ..", "missing", "x86-64"),
    ("62 f5 ff ..", "missing", "x86-64"),
    ("0f 01 c0", "missing", "*"),
    ("0f 01 c1", "missing", "*"),
    ("0f 01 c2", "missing", "*"),
    ("0f 01 c3", "missing", "*"),
    ("0f 01 c4", "missing", "*"),
    ("0f 01 c5", "missing", "*"),
    ("0f 01 c6", "missing", "*"),
    ("0f 01 c7", "missing", "x86-64"),
    ("0f 01 c8", "missing", "*"),
    ("0f 01 d8", "missing", "*"),
    ("0f 01 f8", "missing", "x86-64"),
    ("62 f1 7c 40 14", "missing", "x86-64"),
    ("62 f1 7c 40 15", "missing", "x86-64"),
    ("62 f1 7c 40 54", "missing", "x86-64"),
    ("62 f1 7c 40 55", "missing", "x86-64"),
    ("62 f1 7c 40 56", "missing", "x86-64"),
    ("62 f1 7c 40 57", "missing", "x86-64"),
    ("62 f1 7c 40 c2", "missing", "x86-64"),
    ("62 f1 7c 40 c6", "missing", "x86-64"),
    ("62 f1 7d 40 60", "missing", "x86-64"),
    ("62 f1 7d 40 61", "missing", "x86-64"),
    ("62 f1 7d 40 62", "missing", "x86-64"),
    ("62 f1 7d 40 63", "missing", "x86-64"),
    ("62 f1 7d 40 64", "missing", "x86-64"),
    ("62 f1 7d 40 65", "missing", "x86-64"),
    ("62 f1 7d 40 66", "missing", "x86-64"),
    ("62 f1 7d 40 67", "missing", "x86-64"),
    ("62 f1 7d 40 68", "missing", "x86-64"),
    ("62 f1 7d 40 69", "missing", "x86-64"),
    ("62 f1 7d 40 6a", "missing", "x86-64"),
    ("62 f1 7d 40 6b", "missing", "x86-64"),
    ("62 f1 7d 40 72", "missing", "x86-64"),
    ("62 f1 7d 40 73", "missing", "x86-64"),
    ("62 f1 7d 40 74", "missing", "x86-64"),
    ("62 f1 7d 40 75", "missing", "x86-64"),
    ("62 f1 7d 40 76", "missing", "x86-64"),
    ("62 f1 7d 40 d1", "missing", "x86-64"),
    ("62 f1 7d 40 d2", "missing", "x86-64"),
    ("62 f1 7d 40 d5", "missing", "x86-64"),
    ("62 f1 7d 40 d8", "missing", "x86-64"),
    ("62 f1 7d 40 d9", "missing", "x86-64"),
    ("62 f1 7d 40 da", "missing", "x86-64"),
    ("62 f1 7d 40 dc", "missing", "x86-64"),
    ("62 f1 7d 40 dd", "missing", "x86-64"),
    ("62 f1 7d 40 de", "missing", "x86-64"),
    ("62 f1 7d 40 e0", "missing", "x86-64"),
    ("62 f1 7d 40 e1", "missing", "x86-64"),
    ("62 f1 7d 40 e2", "missing", "x86-64"),
    ("62 f1 7d 40 e3", "missing", "x86-64"),
    ("62 f1 7d 40 e4", "missing", "x86-64"),
    ("62 f1 7d 40 e5", "missing", "x86-64"),
    ("62 f1 7d 40 e8", "missing", "x86-64"),
    ("62 f1 7d 40 e9", "missing", "x86-64"),
    ("62 f1 7d 40 ea", "missing", "x86-64"),
    ("62 f1 7d 40 ec", "missing", "x86-64"),
    ("62 f1 7d 40 ed", "missing", "x86-64"),
    ("62 f1 7d 40 ee", "missing", "x86-64"),
    ("62 f1 7d 40 f1", "missing", "x86-64"),
    ("62 f1 7d 40 f2", "missing", "x86-64"),
    ("62 f1 7d 40 f5", "missing", "x86-64"),
    ("62 f1 7d 40 f6", "missing", "x86-64"),
    ("62 f1 7d 40 f8", "missing", "x86-64"),
    ("62 f1 7d 40 f9", "missing", "x86-64"),
    ("62 f1 7d 40 fc", "missing", "x86-64"),
    ("62 f1 7d 40 fd", "missing", "x86-64"),
    ("62 f1 7e 00 10", "missing", "x86-64"),
    ("62 f1 7e 00 11", "missing", "x86-64"),
    ("62 f1 7e 00 2a", "missing", "x86-64"),
    ("62 f1 7e 00 51", "missing", "x86-64"),
    ("62 f1 7e 00 58", "missing", "x86-64"),
    ("62 f1 7e 00 59", "missing", "x86-64"),
    ("62 f1 7e 00 5a", "missing", "x86-64"),
    ("62 f1 7e 00 5c", "missing", "x86-64"),
    ("62 f1 7e 00 5d", "missing", "x86-64"),
    ("62 f1 7e 00 5e", "missing", "x86-64"),
    ("62 f1 7e 00 5f", "missing", "x86-64"),
    ("62 f1 7e 00 7b", "missing", "x86-64"),
    ("62 f1 7e 00 c2", "missing", "x86-64"),
    ("62 f1 7e 40 10", "missing", "x86-64"),
    ("62 f1 7e 40 11", "missing", "x86-64"),
    ("62 f1 7e 40 2a", "missing", "x86-64"),
    ("62 f1 7e 40 51", "missing", "x86-64"),
    ("62 f1 7e 40 58", "missing", "x86-64"),
    ("62 f1 7e 40 59", "missing", "x86-64"),
    ("62 f1 7e 40 5a", "missing", "x86-64"),
    ("62 f1 7e 40 5c", "missing", "x86-64"),
    ("62 f1 7e 40 5d", "missing", "x86-64"),
    ("62 f1 7e 40 5e", "missing", "x86-64"),
    ("62 f1 7e 40 5f", "missing", "x86-64"),
    ("62 f1 7e 40 7b", "missing", "x86-64"),
    ("62 f1 7e 40 c2", "missing", "x86-64"),
    ("62 f1 fd 40 14", "missing", "x86-64"),
    ("62 f1 fd 40 15", "missing", "x86-64"),
    ("62 f1 fd 40 54", "missing", "x86-64"),
    ("62 f1 fd 40 55", "missing", "x86-64"),
    ("62 f1 fd 40 56", "missing", "x86-64"),
    ("62 f1 fd 40 57", "missing", "x86-64"),
    ("62 f1 fd 40 60", "missing", "x86-64"),
    ("62 f1 fd 40 61", "missing", "x86-64"),
    ("62 f1 fd 40 63", "missing", "x86-64"),
    ("62 f1 fd 40 64", "missing", "x86-64"),
    ("62 f1 fd 40 65", "missing", "x86-64"),
    ("62 f1 fd 40 67", "missing", "x86-64"),
    ("62 f1 fd 40 68", "missing", "x86-64"),
    ("62 f1 fd 40 69", "missing", "x86-64"),
    ("62 f1 fd 40 6c", "missing", "x86-64"),
    ("62 f1 fd 40 6d", "missing", "x86-64"),
    ("62 f1 fd 40 72", "missing", "x86-64"),
    ("62 f1 fd 40 73", "missing", "x86-64"),
    ("62 f1 fd 40 74", "missing", "x86-64"),
    ("62 f1 fd 40 75", "missing", "x86-64"),
    ("62 f1 fd 40 c2", "missing", "x86-64"),
    ("62 f1 fd 40 c6", "missing", "x86-64"),
    ("62 f1 fd 40 d1", "missing", "x86-64"),
    ("62 f1 fd 40 d3", "missing", "x86-64"),
    ("62 f1 fd 40 d5", "missing", "x86-64"),
    ("62 f1 fd 40 d8", "missing", "x86-64"),
    ("62 f1 fd 40 d9", "missing", "x86-64"),
    ("62 f1 fd 40 da", "missing", "x86-64"),
    ("62 f1 fd 40 dc", "missing", "x86-64"),
    ("62 f1 fd 40 dd", "missing", "x86-64"),
    ("62 f1 fd 40 de", "missing", "x86-64"),
    ("62 f1 fd 40 e0", "missing", "x86-64"),
    ("62 f1 fd 40 e1", "missing", "x86-64"),
    ("62 f1 fd 40 e2", "missing", "x86-64"),
    ("62 f1 fd 40 e3", "missing", "x86-64"),
    ("62 f1 fd 40 e4", "missing", "x86-64"),
    ("62 f1 fd 40 e5", "missing", "x86-64"),
    ("62 f1 fd 40 e8", "missing", "x86-64"),
    ("62 f1 fd 40 e9", "missing", "x86-64"),
    ("62 f1 fd 40 ea", "missing", "x86-64"),
    ("62 f1 fd 40 ec", "missing", "x86-64"),
    ("62 f1 fd 40 ed", "missing", "x86-64"),
    ("62 f1 fd 40 ee", "missing", "x86-64"),
    ("62 f1 fd 40 f1", "missing", "x86-64"),
    ("62 f1 fd 40 f3", "missing", "x86-64"),
    ("62 f1 fd 40 f4", "missing", "x86-64"),
    ("62 f1 fd 40 f5", "missing", "x86-64"),
    ("62 f1 fd 40 f6", "missing", "x86-64"),
    ("62 f1 fd 40 f8", "missing", "x86-64"),
    ("62 f1 fd 40 f9", "missing", "x86-64"),
    ("62 f1 fd 40 fc", "missing", "x86-64"),
    ("62 f1 fd 40 fd", "missing", "x86-64"),
    ("62 f1 fe 00 2a", "missing", "x86-64"),
    ("62 f1 fe 00 7b", "missing", "x86-64"),
    ("62 f1 fe 40 2a", "missing", "x86-64"),
    ("62 f1 fe 40 7b", "missing", "x86-64"),
    ("62 f2 7d 00 00", "missing", "x86-64"),
    ("62 f2 7d 00 04", "missing", "x86-64"),
    ("62 f2 7d 00 0b", "missing", "x86-64"),
    ("62 f2 7d 00 0c", "missing", "x86-64"),
    ("62 f2 7d 00 14", "missing", "x86-64"),
    ("62 f2 7d 00 15", "missing", "x86-64"),
    ("62 f2 7d 00 26", "missing", "x86-64"),
    ("62 f2 7d 00 27", "missing", "x86-64"),
    ("62 f2 7d 00 2b", "missing", "x86-64"),
    ("62 f2 7d 00 2c", "missing", "x86-64"),
    ("62 f2 7d 00 2d", "missing", "x86-64"),
    ("62 f2 7d 00 38", "missing", "x86-64"),
    ("62 f2 7d 00 39", "missing", "x86-64"),
    ("62 f2 7d 00 3a", "missing", "x86-64"),
    ("62 f2 7d 00 3b", "missing", "x86-64"),
    ("62 f2 7d 00 3c", "missing", "x86-64"),
    ("62 f2 7d 00 3d", "missing", "x86-64"),
    ("62 f2 7d 00 3e", "missing", "x86-64"),
    ("62 f2 7d 00 3f", "missing", "x86-64"),
    ("62 f2 7d 00 40", "missing", "x86-64"),
    ("62 f2 7d 00 43", "missing", "x86-64"),
    ("62 f2 7d 00 45", "missing", "x86-64"),
    ("62 f2 7d 00 46", "missing", "x86-64"),
    ("62 f2 7d 00 47", "missing", "x86-64"),
    ("62 f2 7d 00 4d", "missing", "x86-64"),
    ("62 f2 7d 00 4f", "missing", "x86-64"),
    ("62 f2 7d 00 50", "missing", "x86-64"),
    ("62 f2 7d 00 51", "missing", "x86-64"),
    ("62 f2 7d 00 52", "missing", "x86-64"),
    ("62 f2 7d 00 53", "missing", "x86-64"),
    ("62 f2 7d 00 64", "missing", "x86-64"),
    ("62 f2 7d 00 65", "missing", "x86-64"),
    ("62 f2 7d 00 66", "missing", "x86-64"),
    ("62 f2 7d 00 67", "missing", "x86-64"),
    ("62 f2 7d 00 71", "missing", "x86-64"),
    ("62 f2 7d 00 73", "missing", "x86-64"),
    ("62 f2 7d 00 75", "missing", "x86-64"),
    ("62 f2 7d 00 76", "missing", "x86-64"),
    ("62 f2 7d 00 77", "missing", "x86-64"),
    ("62 f2 7d 00 7d", "missing", "x86-64"),
    ("62 f2 7d 00 7e", "missing", "x86-64"),
    ("62 f2 7d 00 7f", "missing", "x86-64"),
    ("62 f2 7d 00 8d", "missing", "x86-64"),
    ("62 f2 7d 00 8f", "missing", "x86-64"),
    ("62 f2 7d 00 96", "missing", "x86-64"),
    ("62 f2 7d 00 97", "missing", "x86-64"),
    ("62 f2 7d 00 98", "missing", "x86-64"),
    ("62 f2 7d 00 99", "missing", "x86-64"),
    ("62 f2 7d 00 9a", "missing", "x86-64"),
    ("62 f2 7d 00 9b", "missing", "x86-64"),
    ("62 f2 7d 00 9c", "missing", "x86-64"),
    ("62 f2 7d 00 9d", "missing", "x86-64"),
    ("62 f2 7d 00 9e", "missing", "x86-64"),
    ("62 f2 7d 00 9f", "missing", "x86-64"),
    ("62 f2 7d 00 a6", "missing", "x86-64"),
    ("62 f2 7d 00 a7", "missing", "x86-64"),
    ("62 f2 7d 00 a8", "missing", "x86-64"),
    ("62 f2 7d 00 a9", "missing", "x86-64"),
    ("62 f2 7d 00 aa", "missing", "x86-64"),
    ("62 f2 7d 00 ab", "missing", "x86-64"),
    ("62 f2 7d 00 ac", "missing", "x86-64"),
    ("62 f2 7d 00 ad", "missing", "x86-64"),
    ("62 f2 7d 00 ae", "missing", "x86-64"),
    ("62 f2 7d 00 af", "missing", "x86-64"),
    ("62 f2 7d 00 b6", "missing", "x86-64"),
    ("62 f2 7d 00 b7", "missing", "x86-64"),
    ("62 f2 7d 00 b8", "missing", "x86-64"),
    ("62 f2 7d 00 b9", "missing", "x86-64"),
    ("62 f2 7d 00 ba", "missing", "x86-64"),
    ("62 f2 7d 00 bb", "missing", "x86-64"),
    ("62 f2 7d 00 bc", "missing", "x86-64"),
    ("62 f2 7d 00 bd", "missing", "x86-64"),
    ("62 f2 7d 00 be", "missing", "x86-64"),
    ("62 f2 7d 00 bf", "missing", "x86-64"),
    ("62 f2 7d 00 cb", "missing", "x86-64"),
    ("62 f2 7d 00 cd", "missing", "x86-64"),
    ("62 f2 7d 00 cf", "missing", "x86-64"),
    ("62 f2 7d 00 d2", "missing", "x86-64"),
    ("62 f2 7d 00 d3", "missing", "x86-64"),
    ("62 f2 7d 00 dc", "missing", "x86-64"),
    ("62 f2 7d 00 dd", "missing", "x86-64"),
    ("62 f2 7d 00 de", "missing", "x86-64"),
    ("62 f2 7d 00 df", "missing", "x86-64"),
    ("62 f2 7d 00 e0", "missing", "x86-64"),
    ("62 f2 7d 00 e1", "missing", "x86-64"),
    ("62 f2 7d 00 e2", "missing", "x86-64"),
    ("62 f2 7d 00 e3", "missing", "x86-64"),
    ("62 f2 7d 00 e4", "missing", "x86-64"),
    ("62 f2 7d 00 e5", "missing", "x86-64"),
    ("62 f2 7d 00 e6", "missing", "x86-64"),
    ("62 f2 7d 00 e7", "missing", "x86-64"),
    ("62 f2 7d 00 e8", "missing", "x86-64"),
    ("62 f2 7d 00 e9", "missing", "x86-64"),
    ("62 f2 7d 00 ea", "missing", "x86-64"),
    ("62 f2 7d 00 eb", "missing", "x86-64"),
    ("62 f2 7d 00 ec", "missing", "x86-64"),
    ("62 f2 7d 00 ed", "missing", "x86-64"),
    ("62 f2 7d 00 ee", "missing", "x86-64"),
    ("62 f2 7d 00 ef", "missing", "x86-64"),
    ("62 f2 7d 00 f7", "missing", "x86-64"),
    ("62 f2 7d 40 00", "missing", "x86-64"),
    ("62 f2 7d 40 04", "missing", "x86-64"),
    ("62 f2 7d 40 0b", "missing", "x86-64"),
    ("62 f2 7d 40 0c", "missing", "x86-64"),
    ("62 f2 7d 40 14", "missing", "x86-64"),
    ("62 f2 7d 40 15", "missing", "x86-64"),
    ("62 f2 7d 40 16", "missing", "x86-64"),
    ("62 f2 7d 40 26", "missing", "x86-64"),
    ("62 f2 7d 40 27", "missing", "x86-64"),
    ("62 f2 7d 40 2b", "missing", "x86-64"),
    ("62 f2 7d 40 2c", "missing", "x86-64"),
    ("62 f2 7d 40 2d", "missing", "x86-64"),
    ("62 f2 7d 40 36", "missing", "x86-64"),
    ("62 f2 7d 40 38", "missing", "x86-64"),
    ("62 f2 7d 40 3a", "missing", "x86-64"),
    ("62 f2 7d 40 3c", "missing", "x86-64"),
    ("62 f2 7d 40 3e", "missing", "x86-64"),
    ("62 f2 7d 40 43", "missing", "x86-64"),
    ("62 f2 7d 40 45", "missing", "x86-64"),
    ("62 f2 7d 40 46", "missing", "x86-64"),
    ("62 f2 7d 40 47", "missing", "x86-64"),
    ("62 f2 7d 40 4a", "missing", "x86-64"),
    ("62 f2 7d 40 4d", "missing", "x86-64"),
    ("62 f2 7d 40 4f", "missing", "x86-64"),
    ("62 f2 7d 40 50", "missing", "x86-64"),
    ("62 f2 7d 40 51", "missing", "x86-64"),
    ("62 f2 7d 40 52", "missing", "x86-64"),
    ("62 f2 7d 40 53", "missing", "x86-64"),
    ("62 f2 7d 40 5e", "missing", "x86-64"),
    ("62 f2 7d 40 64", "missing", "x86-64"),
    ("62 f2 7d 40 65", "missing", "x86-64"),
    ("62 f2 7d 40 66", "missing", "x86-64"),
    ("62 f2 7d 40 67", "missing", "x86-64"),
    ("62 f2 7d 40 6d", "missing", "x86-64"),
    ("62 f2 7d 40 71", "missing", "x86-64"),
    ("62 f2 7d 40 73", "missing", "x86-64"),
    ("62 f2 7d 40 75", "missing", "x86-64"),
    ("62 f2 7d 40 76", "missing", "x86-64"),
    ("62 f2 7d 40 77", "missing", "x86-64"),
    ("62 f2 7d 40 7d", "missing", "x86-64"),
    ("62 f2 7d 40 7e", "missing", "x86-64"),
    ("62 f2 7d 40 7f", "missing", "x86-64"),
    ("62 f2 7d 40 8d", "missing", "x86-64"),
    ("62 f2 7d 40 8f", "missing", "x86-64"),
    ("62 f2 7d 40 96", "missing", "x86-64"),
    ("62 f2 7d 40 97", "missing", "x86-64"),
    ("62 f2 7d 40 98", "missing", "x86-64"),
    ("62 f2 7d 40 99", "missing", "x86-64"),
    ("62 f2 7d 40 9a", "missing", "x86-64"),
    ("62 f2 7d 40 9b", "missing", "x86-64"),
    ("62 f2 7d 40 9c", "missing", "x86-64"),
    ("62 f2 7d 40 9d", "missing", "x86-64"),
    ("62 f2 7d 40 9e", "missing", "x86-64"),
    ("62 f2 7d 40 9f", "missing", "x86-64"),
    ("62 f2 7d 40 a6", "missing", "x86-64"),
    ("62 f2 7d 40 a7", "missing", "x86-64"),
    ("62 f2 7d 40 a8", "missing", "x86-64"),
    ("62 f2 7d 40 a9", "missing", "x86-64"),
    ("62 f2 7d 40 aa", "missing", "x86-64"),
    ("62 f2 7d 40 ab", "missing", "x86-64"),
    ("62 f2 7d 40 ac", "missing", "x86-64"),
    ("62 f2 7d 40 ad", "missing", "x86-64"),
    ("62 f2 7d 40 ae", "missing", "x86-64"),
    ("62 f2 7d 40 af", "missing", "x86-64"),
    ("62 f2 7d 40 b6", "missing", "x86-64"),
    ("62 f2 7d 40 b7", "missing", "x86-64"),
    ("62 f2 7d 40 b8", "missing", "x86-64"),
    ("62 f2 7d 40 b9", "missing", "x86-64"),
    ("62 f2 7d 40 ba", "missing", "x86-64"),
    ("62 f2 7d 40 bb", "missing", "x86-64"),
    ("62 f2 7d 40 bc", "missing", "x86-64"),
    ("62 f2 7d 40 bd", "missing", "x86-64"),
    ("62 f2 7d 40 be", "missing", "x86-64"),
    ("62 f2 7d 40 bf", "missing", "x86-64"),
    ("62 f2 7d 40 cb", "missing", "x86-64"),
    ("62 f2 7d 40 cd", "missing", "x86-64"),
    ("62 f2 7d 40 cf", "missing", "x86-64"),
    ("62 f2 7d 40 d2", "missing", "x86-64"),
    ("62 f2 7d 40 d3", "missing", "x86-64"),
    ("62 f2 7d 40 dc", "missing", "x86-64"),
    ("62 f2 7d 40 dd", "missing", "x86-64"),
    ("62 f2 7d 40 de", "missing", "x86-64"),
    ("62 f2 7d 40 df", "missing", "x86-64"),
    ("62 f4 78 04 38", "missing", "x86-64"),
    ("62 f4 78 04 39", "missing", "x86-64"),
    ("62 f4 78 04 3a", "missing", "x86-64"),
    ("62 f4 78 04 3b", "missing", "x86-64"),
    ("62 f4 78 04 84", "missing", "x86-64"),
    ("62 f4 78 04 85", "missing", "x86-64"),
    ("62 f4 78 04 f6", "missing", "x86-64"),
    ("62 f4 78 10 24", "missing", "x86-64"),
    ("62 f4 78 10 2c", "missing", "x86-64"),
    ("62 f4 78 10 40", "missing", "x86-64"),
    ("62 f4 78 10 41", "missing", "x86-64"),
    ("62 f4 78 10 42", "missing", "x86-64"),
    ("62 f4 78 10 43", "missing", "x86-64"),
    ("62 f4 78 10 44", "missing", "x86-64"),
    ("62 f4 78 10 45", "missing", "x86-64"),
    ("62 f4 78 10 46", "missing", "x86-64"),
    ("62 f4 78 10 47", "missing", "x86-64"),
    ("62 f4 78 10 48", "missing", "x86-64"),
    ("62 f4 78 10 49", "missing", "x86-64"),
    ("62 f4 78 10 4a", "missing", "x86-64"),
    ("62 f4 78 10 4b", "missing", "x86-64"),
    ("62 f4 78 10 4c", "missing", "x86-64"),
    ("62 f4 78 10 4d", "missing", "x86-64"),
    ("62 f4 78 10 4e", "missing", "x86-64"),
    ("62 f4 78 10 4f", "missing", "x86-64"),
    ("62 f4 78 10 a5", "missing", "x86-64"),
    ("62 f4 78 10 ad", "missing", "x86-64"),
    ("62 f4 79 04 39", "missing", "x86-64"),
    ("62 f4 79 04 3b", "missing", "x86-64"),
    ("62 f4 79 04 85", "missing", "x86-64"),
    ("62 f4 79 04 f7", "missing", "x86-64"),
    ("62 f4 79 10 24", "missing", "x86-64"),
    ("62 f4 79 10 2c", "missing", "x86-64"),
    ("62 f4 79 10 40", "missing", "x86-64"),
    ("62 f4 79 10 41", "missing", "x86-64"),
    ("62 f4 79 10 42", "missing", "x86-64"),
    ("62 f4 79 10 43", "missing", "x86-64"),
    ("62 f4 79 10 44", "missing", "x86-64"),
    ("62 f4 79 10 45", "missing", "x86-64"),
    ("62 f4 79 10 46", "missing", "x86-64"),
    ("62 f4 79 10 47", "missing", "x86-64"),
    ("62 f4 79 10 48", "missing", "x86-64"),
    ("62 f4 79 10 49", "missing", "x86-64"),
    ("62 f4 79 10 4a", "missing", "x86-64"),
    ("62 f4 79 10 4b", "missing", "x86-64"),
    ("62 f4 79 10 4c", "missing", "x86-64"),
    ("62 f4 79 10 4d", "missing", "x86-64"),
    ("62 f4 79 10 4e", "missing", "x86-64"),
    ("62 f4 79 10 4f", "missing", "x86-64"),
    ("62 f4 79 10 66", "missing", "x86-64"),
    ("62 f4 79 10 a5", "missing", "x86-64"),
    ("62 f4 79 10 ad", "missing", "x86-64"),
    ("62 f4 7c 00 38", "missing", "x86-64"),
    ("62 f4 7c 00 39", "missing", "x86-64"),
    ("62 f4 7c 00 3a", "missing", "x86-64"),
    ("62 f4 7c 00 3b", "missing", "x86-64"),
    ("62 f4 7c 00 84", "missing", "x86-64"),
    ("62 f4 7c 00 85", "missing", "x86-64"),
    ("62 f4 7c 00 f6", "missing", "x86-64"),
    ("62 f4 7c 00 f7", "missing", "x86-64"),
    ("62 f4 7c 04 38", "missing", "x86-64"),
    ("62 f4 7c 04 39", "missing", "x86-64"),
    ("62 f4 7c 04 3a", "missing", "x86-64"),
    ("62 f4 7c 04 3b", "missing", "x86-64"),
    ("62 f4 7c 04 84", "missing", "x86-64"),
    ("62 f4 7c 04 85", "missing", "x86-64"),
    ("62 f4 7c 04 f6", "missing", "x86-64"),
    ("62 f4 7c 04 f7", "missing", "x86-64"),
    ("62 f4 7c 10 24", "missing", "x86-64"),
    ("62 f4 7c 10 2c", "missing", "x86-64"),
    ("62 f4 7c 10 40", "missing", "x86-64"),
    ("62 f4 7c 10 41", "missing", "x86-64"),
    ("62 f4 7c 10 42", "missing", "x86-64"),
    ("62 f4 7c 10 43", "missing", "x86-64"),
    ("62 f4 7c 10 44", "missing", "x86-64"),
    ("62 f4 7c 10 45", "missing", "x86-64"),
    ("62 f4 7c 10 46", "missing", "x86-64"),
    ("62 f4 7c 10 47", "missing", "x86-64"),
    ("62 f4 7c 10 48", "missing", "x86-64"),
    ("62 f4 7c 10 49", "missing", "x86-64"),
    ("62 f4 7c 10 4a", "missing", "x86-64"),
    ("62 f4 7c 10 4b", "missing", "x86-64"),
    ("62 f4 7c 10 4c", "missing", "x86-64"),
    ("62 f4 7c 10 4d", "missing", "x86-64"),
    ("62 f4 7c 10 4e", "missing", "x86-64"),
    ("62 f4 7c 10 4f", "missing", "x86-64"),
    ("62 f4 7c 10 a5", "missing", "x86-64"),
    ("62 f4 7c 10 ad", "missing", "x86-64"),
    ("62 f4 7d 00 39", "missing", "x86-64"),
    ("62 f4 7d 00 3b", "missing", "x86-64"),
    ("62 f4 7d 00 85", "missing", "x86-64"),
    ("62 f4 7d 00 f7", "missing", "x86-64"),
    ("62 f4 7d 04 39", "missing", "x86-64"),
    ("62 f4 7d 04 3b", "missing", "x86-64"),
    ("62 f4 7d 04 85", "missing", "x86-64"),
    ("62 f4 7d 04 f7", "missing", "x86-64"),
    ("62 f4 7d 10 24", "missing", "x86-64"),
    ("62 f4 7d 10 2c", "missing", "x86-64"),
    ("62 f4 7d 10 40", "missing", "x86-64"),
    ("62 f4 7d 10 41", "missing", "x86-64"),
    ("62 f4 7d 10 42", "missing", "x86-64"),
    ("62 f4 7d 10 43", "missing", "x86-64"),
    ("62 f4 7d 10 44", "missing", "x86-64"),
    ("62 f4 7d 10 45", "missing", "x86-64"),
    ("62 f4 7d 10 46", "missing", "x86-64"),
    ("62 f4 7d 10 47", "missing", "x86-64"),
    ("62 f4 7d 10 48", "missing", "x86-64"),
    ("62 f4 7d 10 49", "missing", "x86-64"),
    ("62 f4 7d 10 4a", "missing", "x86-64"),
    ("62 f4 7d 10 4b", "missing", "x86-64"),
    ("62 f4 7d 10 4c", "missing", "x86-64"),
    ("62 f4 7d 10 4d", "missing", "x86-64"),
    ("62 f4 7d 10 4e", "missing", "x86-64"),
    ("62 f4 7d 10 4f", "missing", "x86-64"),
    ("62 f4 7d 10 66", "missing", "x86-64"),
    ("62 f4 7d 10 a5", "missing", "x86-64"),
    ("62 f4 7d 10 ad", "missing", "x86-64"),
    ("62 f4 f8 04 38", "missing", "x86-64"),
    ("62 f4 f8 04 39", "missing", "x86-64"),
    ("62 f4 f8 04 3a", "missing", "x86-64"),
    ("62 f4 f8 04 3b", "missing", "x86-64"),
    ("62 f4 f8 04 84", "missing", "x86-64"),
    ("62 f4 f8 04 85", "missing", "x86-64"),
    ("62 f4 f8 04 f6", "missing", "x86-64"),
    ("62 f4 f8 10 24", "missing", "x86-64"),
    ("62 f4 f8 10 2c", "missing", "x86-64"),
    ("62 f4 f8 10 40", "missing", "x86-64"),
    ("62 f4 f8 10 41", "missing", "x86-64"),
    ("62 f4 f8 10 42", "missing", "x86-64"),
    ("62 f4 f8 10 43", "missing", "x86-64"),
    ("62 f4 f8 10 44", "missing", "x86-64"),
    ("62 f4 f8 10 45", "missing", "x86-64"),
    ("62 f4 f8 10 46", "missing", "x86-64"),
    ("62 f4 f8 10 47", "missing", "x86-64"),
    ("62 f4 f8 10 48", "missing", "x86-64"),
    ("62 f4 f8 10 49", "missing", "x86-64"),
    ("62 f4 f8 10 4a", "missing", "x86-64"),
    ("62 f4 f8 10 4b", "missing", "x86-64"),
    ("62 f4 f8 10 4c", "missing", "x86-64"),
    ("62 f4 f8 10 4d", "missing", "x86-64"),
    ("62 f4 f8 10 4e", "missing", "x86-64"),
    ("62 f4 f8 10 4f", "missing", "x86-64"),
    ("62 f4 f8 10 a5", "missing", "x86-64"),
    ("62 f4 f8 10 ad", "missing", "x86-64"),
    ("62 f4 f9 04 39", "missing", "x86-64"),
    ("62 f4 f9 04 3b", "missing", "x86-64"),
    ("62 f4 f9 04 85", "missing", "x86-64"),
    ("62 f4 f9 10 24", "missing", "x86-64"),
    ("62 f4 f9 10 2c", "missing", "x86-64"),
    ("62 f4 f9 10 40", "missing", "x86-64"),
    ("62 f4 f9 10 41", "missing", "x86-64"),
    ("62 f4 f9 10 42", "missing", "x86-64"),
    ("62 f4 f9 10 43", "missing", "x86-64"),
    ("62 f4 f9 10 44", "missing", "x86-64"),
    ("62 f4 f9 10 45", "missing", "x86-64"),
    ("62 f4 f9 10 46", "missing", "x86-64"),
    ("62 f4 f9 10 47", "missing", "x86-64"),
    ("62 f4 f9 10 48", "missing", "x86-64"),
    ("62 f4 f9 10 49", "missing", "x86-64"),
    ("62 f4 f9 10 4a", "missing", "x86-64"),
    ("62 f4 f9 10 4b", "missing", "x86-64"),
    ("62 f4 f9 10 4c", "missing", "x86-64"),
    ("62 f4 f9 10 4d", "missing", "x86-64"),
    ("62 f4 f9 10 4e", "missing", "x86-64"),
    ("62 f4 f9 10 4f", "missing", "x86-64"),
    ("62 f4 f9 10 66", "missing", "x86-64"),
    ("62 f4 f9 10 a5", "missing", "x86-64"),
    ("62 f4 f9 10 ad", "missing", "x86-64"),
    ("62 f4 fc 00 38", "missing", "x86-64"),
    ("62 f4 fc 00 39", "missing", "x86-64"),
    ("62 f4 fc 00 3a", "missing", "x86-64"),
    ("62 f4 fc 00 3b", "missing", "x86-64"),
    ("62 f4 fc 00 84", "missing", "x86-64"),
    ("62 f4 fc 00 85", "missing", "x86-64"),
    ("62 f4 fc 00 f6", "missing", "x86-64"),
    ("62 f4 fc 00 f7", "missing", "x86-64"),
    ("62 f4 fc 04 38", "missing", "x86-64"),
    ("62 f4 fc 04 39", "missing", "x86-64"),
    ("62 f4 fc 04 3a", "missing", "x86-64"),
    ("62 f4 fc 04 3b", "missing", "x86-64"),
    ("62 f4 fc 04 84", "missing", "x86-64"),
    ("62 f4 fc 04 85", "missing", "x86-64"),
    ("62 f4 fc 04 f6", "missing", "x86-64"),
    ("62 f4 fc 04 f7", "missing", "x86-64"),
    ("62 f4 fc 10 24", "missing", "x86-64"),
    ("62 f4 fc 10 2c", "missing", "x86-64"),
    ("62 f4 fc 10 40", "missing", "x86-64"),
    ("62 f4 fc 10 41", "missing", "x86-64"),
    ("62 f4 fc 10 42", "missing", "x86-64"),
    ("62 f4 fc 10 43", "missing", "x86-64"),
    ("62 f4 fc 10 44", "missing", "x86-64"),
    ("62 f4 fc 10 45", "missing", "x86-64"),
    ("62 f4 fc 10 46", "missing", "x86-64"),
    ("62 f4 fc 10 47", "missing", "x86-64"),
    ("62 f4 fc 10 48", "missing", "x86-64"),
    ("62 f4 fc 10 49", "missing", "x86-64"),
    ("62 f4 fc 10 4a", "missing", "x86-64"),
    ("62 f4 fc 10 4b", "missing", "x86-64"),
    ("62 f4 fc 10 4c", "missing", "x86-64"),
    ("62 f4 fc 10 4d", "missing", "x86-64"),
    ("62 f4 fc 10 4e", "missing", "x86-64"),
    ("62 f4 fc 10 4f", "missing", "x86-64"),
    ("62 f4 fc 10 a5", "missing", "x86-64"),
    ("62 f4 fc 10 ad", "missing", "x86-64"),
    ("62 f4 fd 00 39", "missing", "x86-64"),
    ("62 f4 fd 00 3b", "missing", "x86-64"),
    ("62 f4 fd 00 85", "missing", "x86-64"),
    ("62 f4 fd 00 f7", "missing", "x86-64"),
    ("62 f4 fd 04 39", "missing", "x86-64"),
    ("62 f4 fd 04 3b", "missing", "x86-64"),
    ("62 f4 fd 04 85", "missing", "x86-64"),
    ("62 f4 fd 04 f7", "missing", "x86-64"),
    ("62 f4 fd 10 24", "missing", "x86-64"),
    ("62 f4 fd 10 2c", "missing", "x86-64"),
    ("62 f4 fd 10 40", "missing", "x86-64"),
    ("62 f4 fd 10 41", "missing", "x86-64"),
    ("62 f4 fd 10 42", "missing", "x86-64"),
    ("62 f4 fd 10 43", "missing", "x86-64"),
    ("62 f4 fd 10 44", "missing", "x86-64"),
    ("62 f4 fd 10 45", "missing", "x86-64"),
    ("62 f4 fd 10 46", "missing", "x86-64"),
    ("62 f4 fd 10 47", "missing", "x86-64"),
    ("62 f4 fd 10 48", "missing", "x86-64"),
    ("62 f4 fd 10 49", "missing", "x86-64"),
    ("62 f4 fd 10 4a", "missing", "x86-64"),
    ("62 f4 fd 10 4b", "missing", "x86-64"),
    ("62 f4 fd 10 4c", "missing", "x86-64"),
    ("62 f4 fd 10 4d", "missing", "x86-64"),
    ("62 f4 fd 10 4e", "missing", "x86-64"),
    ("62 f4 fd 10 4f", "missing", "x86-64"),
    ("62 f4 fd 10 66", "missing", "x86-64"),
    ("62 f4 fd 10 a5", "missing", "x86-64"),
    ("62 f4 fd 10 ad", "missing", "x86-64"),
    ("62 f5 7e 00 10", "missing", "x86-64"),
    ("62 f5 7e 00 11", "missing", "x86-64"),
    ("62 f5 7e 00 2a", "missing", "x86-64"),
    ("62 f5 7e 00 51", "missing", "x86-64"),
    ("62 f5 7e 00 58", "missing", "x86-64"),
    ("62 f5 7e 00 59", "missing", "x86-64"),
    ("62 f5 7e 00 5a", "missing", "x86-64"),
    ("62 f5 7e 00 5c", "missing", "x86-64"),
    ("62 f5 7e 00 5d", "missing", "x86-64"),
    ("62 f5 7e 00 5e", "missing", "x86-64"),
    ("62 f5 7e 00 5f", "missing", "x86-64"),
    ("62 f5 7e 00 7b", "missing", "x86-64"),
    ("62 f5 7e 40 10", "missing", "x86-64"),
    ("62 f5 7e 40 11", "missing", "x86-64"),
    ("62 f5 7e 40 2a", "missing", "x86-64"),
    ("62 f5 7e 40 51", "missing", "x86-64"),
    ("62 f5 7e 40 58", "missing", "x86-64"),
    ("62 f5 7e 40 59", "missing", "x86-64"),
    ("62 f5 7e 40 5a", "missing", "x86-64"),
    ("62 f5 7e 40 5c", "missing", "x86-64"),
    ("62 f5 7e 40 5d", "missing", "x86-64"),
    ("62 f5 7e 40 5e", "missing", "x86-64"),
    ("62 f5 7e 40 5f", "missing", "x86-64"),
    ("62 f5 7e 40 7b", "missing", "x86-64"),
    ("66 0f 01 d8", "missing", "*"),
    ("66 0f 01 f8", "missing", "x86-64"),
    ("c4 e2 78 da", "missing", "*"),
    ("c4 e3 f9 df", "missing", "*"),
    ("d5 80 01", "missing", "x86-64"),
    ("d5 80 20", "missing", "x86-64"),
    ("d5 80 21", "missing", "x86-64"),
    ("d5 80 22", "missing", "x86-64"),
    ("d5 80 23", "missing", "x86-64"),
    ("d5 98 01", "missing", "x86-64"),
    ("d5 98 20", "missing", "x86-64"),
    ("d5 98 21", "missing", "x86-64"),
    ("d5 98 22", "missing", "x86-64"),
    ("d5 98 23", "missing", "x86-64"),
    ("d5 c9 01", "missing", "x86-64"),
    ("d5 d1 01", "missing", "x86-64"),
    ("f2 0f 00 f0", "missing", "x86-64"),
    ("f2 0f 01 c6", "missing", "x86-64"),
    ("f2 0f 01 d8", "missing", "*"),
    ("f2 0f 01 e8", "missing", "*"),
    ("f2 0f 01 f8", "missing", "x86-64"),
    ("f3 0f 01 c6", "missing", "x86-64"),
    ("f3 0f 01 d8", "missing", "*"),
    ("f3 0f 01 f8", "missing", "x86-64"),
    ("d5", "mnemonic", "x86-64"),
    ("d5 80 0d", "mnemonic", "x86-64"),
    ("d5 80 18", "mnemonic", "x86-64"),
    ("d5 80 1c", "mnemonic", "x86-64"),
    ("d5 98 0d", "mnemonic", "x86-64"),
    ("d5 98 18", "mnemonic", "x86-64"),
    ("d5 98 1c", "mnemonic", "x86-64"),
    ("d5 c9 0d", "mnemonic", "x86-64"),
    ("d5 c9 18", "mnemonic", "x86-64"),
    ("d5 c9 1c", "mnemonic", "x86-64"),
    ("d5 d1 0d", "mnemonic", "x86-64"),
    ("d5 d1 18", "mnemonic", "x86-64"),
    ("d5 d1 1c", "mnemonic", "x86-64"),
    ("66 d9", "mnemonic", "*"),
    ("66 da", "mnemonic", "*"),
    ("66 db", "mnemonic", "*"),
    ("66 dc", "mnemonic", "*"),
    ("66 dd", "mnemonic", "*"),
    ("66 de", "mnemonic", "*"),
    ("66 df", "mnemonic", "*"),
    ("66 da", "spurious", "*"),
    ("66 db", "spurious", "*"),
    ("66 dd", "spurious", "*"),
    ("66 de", "spurious", "*"),
    ("66 df", "spurious", "*"),
    ("f2 d9", "mnemonic", "*"),
    ("f2 da", "mnemonic", "*"),
    ("f2 db", "mnemonic", "*"),
    ("f2 dc", "mnemonic", "*"),
    ("f2 dd", "mnemonic", "*"),
    ("f2 de", "mnemonic", "*"),
    ("f2 df", "mnemonic", "*"),
    ("f2 da", "spurious", "*"),
    ("f2 db", "spurious", "*"),
    ("f2 dd", "spurious", "*"),
    ("f2 de", "spurious", "*"),
    ("f2 df", "spurious", "*"),
    ("f3 d9", "mnemonic", "*"),
    ("f3 da", "mnemonic", "*"),
    ("f3 db", "mnemonic", "*"),
    ("f3 dc", "mnemonic", "*"),
    ("f3 dd", "mnemonic", "*"),
    ("f3 de", "mnemonic", "*"),
    ("f3 df", "mnemonic", "*"),
    ("f3 da", "spurious", "*"),
    ("f3 db", "spurious", "*"),
    ("f3 dd", "spurious", "*"),
    ("f3 de", "spurious", "*"),
    ("f3 df", "spurious", "*"),
    ("c4 e2 7d 90", "spurious", "*"),
    ("c4 e2 7d 91", "spurious", "*"),
    ("c4 e2 7d 92", "spurious", "*"),
    ("c4 e2 7d 93", "spurious", "*"),
    ("c4 e2 fd 90", "spurious", "*"),
    ("c4 e2 fd 91", "spurious", "*"),
    ("c4 e2 fd 92", "spurious", "*"),
    ("c4 e2 fd 93", "spurious", "*"),
    ("62 f4 78 00 38", "missing", "x86-64"),
    ("62 f4 78 00 39", "missing", "x86-64"),
    ("62 f4 78 00 3a", "missing", "x86-64"),
    ("62 f4 78 00 3b", "missing", "x86-64"),
    ("62 f4 78 00 84", "missing", "x86-64"),
    ("62 f4 78 00 85", "missing", "x86-64"),
    ("62 f4 78 00 f6", "missing", "x86-64"),
    ("62 f4 79 00 39", "missing", "x86-64"),
    ("62 f4 79 00 3b", "missing", "x86-64"),
    ("62 f4 79 00 85", "missing", "x86-64"),
    ("62 f4 79 00 f7", "missing", "x86-64"),
    ("62 f4 f8 00 38", "missing", "x86-64"),
    ("62 f4 f8 00 39", "missing", "x86-64"),
    ("62 f4 f8 00 3a", "missing", "x86-64"),
    ("62 f4 f8 00 3b", "missing", "x86-64"),
    ("62 f4 f8 00 84", "missing", "x86-64"),
    ("62 f4 f8 00 85", "missing", "x86-64"),
    ("62 f4 f8 00 f6", "missing", "x86-64"),
    ("62 f4 f9 00 39", "missing", "x86-64"),
    ("62 f4 f9 00 3b", "missing", "x86-64"),
    ("62 f4 f9 00 85", "missing", "x86-64"),
    ("0f 20", "missing", "*"),
    ("0f 21", "missing", "*"),
    ("0f 22", "missing", "*"),
    ("0f 23", "missing", "*"),
    ("66 0f 20", "missing", "*"),
    ("66 0f 21", "missing", "*"),
    ("66 0f 22", "missing", "*"),
    ("66 0f 23", "missing", "*"),
    ("66 0f 38 80", "missing", "*"),
    ("66 0f 38 81", "missing", "*"),
    ("66 0f 38 82", "missing", "*"),
    ("8f e8 78 85", "missing", "*"),
    ("8f e8 78 86", "missing", "*"),
    ("8f e8 78 87", "missing", "*"),
    ("8f e8 78 8e", "missing", "*"),
    ("8f e8 78 8f", "missing", "*"),
    ("8f e8 78 95", "missing", "*"),
    ("8f e8 78 96", "missing", "*"),
    ("8f e8 78 97", "missing", "*"),
    ("8f e8 78 9e", "missing", "*"),
    ("8f e8 78 9f", "missing", "*"),
    ("8f e8 78 a3", "missing", "*"),
    ("8f e8 78 a6", "missing", "*"),
    ("8f e8 78 b6", "missing", "*"),
    ("8f e8 78 c0", "missing", "*"),
    ("8f e8 78 c1", "missing", "*"),
    ("8f e8 78 c2", "missing", "*"),
    ("8f e8 78 c3", "missing", "*"),
    ("8f e9 78 12", "missing", "*"),
    ("8f e9 78 c1", "missing", "*"),
    ("8f e9 78 c2", "missing", "*"),
    ("8f e9 78 c3", "missing", "*"),
    ("8f e9 78 c6", "missing", "*"),
    ("8f e9 78 c7", "missing", "*"),
    ("8f e9 78 cb", "missing", "*"),
    ("8f e9 78 d1", "missing", "*"),
    ("8f e9 78 d2", "missing", "*"),
    ("8f e9 78 d3", "missing", "*"),
    ("8f e9 78 d6", "missing", "*"),
    ("8f e9 78 d7", "missing", "*"),
    ("8f e9 78 db", "missing", "*"),
    ("8f e9 78 e1", "missing", "*"),
    ("8f e9 78 e2", "missing", "*"),
    ("8f e9 78 e3", "missing", "*"),
    ("8f ea 78 12", "missing", "*"),
    ("c4 e1 78 44", "missing", "*"),
    ("c4 e1 78 90", "missing", "*"),
    ("c4 e1 78 91", "missing", "*"),
    ("c4 e1 78 92", "missing", "*"),
    ("c4 e1 78 93", "missing", "*"),
    ("c4 e1 78 98", "missing", "*"),
    ("c4 e1 78 99", "missing", "*"),
    ("c4 e1 79 44", "missing", "*"),
    ("c4 e1 79 90", "missing", "*"),
    ("c4 e1 79 91", "missing", "*"),
    ("c4 e1 79 92", "missing", "*"),
    ("c4 e1 79 93", "missing", "*"),
    ("c4 e1 79 98", "missing", "*"),
    ("c4 e1 79 99", "missing", "*"),
    ("c4 e1 7b 92", "missing", "*"),
    ("c4 e1 7b 93", "missing", "*"),
    ("c4 e1 f8 44", "missing", "*"),
    ("c4 e1 f8 90", "missing", "*"),
    ("c4 e1 f8 91", "missing", "*"),
    ("c4 e1 f8 98", "missing", "*"),
    ("c4 e1 f8 99", "missing", "*"),
    ("c4 e1 f9 44", "missing", "*"),
    ("c4 e1 f9 90", "missing", "*"),
    ("c4 e1 f9 91", "missing", "*"),
    ("c4 e1 f9 98", "missing", "*"),
    ("c4 e1 f9 99", "missing", "*"),
    ("c4 e1 fb 92", "missing", "*"),
    ("c4 e1 fb 93", "missing", "*"),
    ("c4 e2 78 b0", "missing", "*"),
    ("c4 e2 79 b0", "missing", "*"),
    ("c4 e2 79 b1", "missing", "*"),
    ("c4 e2 79 cf", "missing", "*"),
    ("c4 e2 7a b0", "missing", "*"),
    ("c4 e2 7a b1", "missing", "*"),
    ("c4 e2 7b 50", "missing", "*"),
    ("c4 e2 7b 51", "missing", "*"),
    ("c4 e2 7b b0", "missing", "*"),
    ("c4 e2 f9 28", "missing", "*"),
    ("c4 e2 f9 45", "missing", "*"),
    ("c4 e2 f9 47", "missing", "*"),
    ("c4 e3 79 02", "missing", "*"),
    ("c4 e3 79 30", "missing", "*"),
    ("c4 e3 79 31", "missing", "*"),
    ("c4 e3 79 32", "missing", "*"),
    ("c4 e3 79 33", "missing", "*"),
    ("c4 e3 79 60", "missing", "*"),
    ("c4 e3 79 61", "missing", "*"),
    ("c4 e3 79 62", "missing", "*"),
    ("c4 e3 79 63", "missing", "*"),
    ("c4 e3 79 de", "missing", "*"),
    ("c4 e3 79 df", "missing", "*"),
    ("c4 e3 f9 14", "missing", "*"),
    ("c4 e3 f9 15", "missing", "*"),
    ("c4 e3 f9 17", "missing", "*"),
    ("c4 e3 f9 30", "missing", "*"),
    ("c4 e3 f9 31", "missing", "*"),
    ("c4 e3 f9 32", "missing", "*"),
    ("c4 e3 f9 33", "missing", "*"),
    ("c4 e3 f9 60", "missing", "*"),
    ("c4 e3 f9 61", "missing", "*"),
    ("c4 e3 f9 62", "missing", "*"),
    ("c4 e3 f9 63", "missing", "*"),
    ("c5 f8 44", "missing", "*"),
    ("c5 f8 90", "missing", "*"),
    ("c5 f8 91", "missing", "*"),
    ("c5 f8 92", "missing", "*"),
    ("c5 f8 93", "missing", "*"),
    ("c5 f8 98", "missing", "*"),
    ("c5 f8 99", "missing", "*"),
    ("c5 f9 44", "missing", "*"),
    ("c5 f9 90", "missing", "*"),
    ("c5 f9 91", "missing", "*"),
    ("c5 f9 92", "missing", "*"),
    ("c5 f9 93", "missing", "*"),
    ("c5 f9 98", "missing", "*"),
    ("c5 f9 99", "missing", "*"),
    ("c5 fb 92", "missing", "*"),
    ("c5 fb 93", "missing", "*"),
    ("c5 fc 41", "missing", "*"),
    ("c5 fc 42", "missing", "*"),
    ("c5 fc 45", "missing", "*"),
    ("c5 fc 46", "missing", "*"),
    ("c5 fc 47", "missing", "*"),
    ("c5 fc 4a", "missing", "*"),
    ("c5 fc 4b", "missing", "*"),
    ("c5 fd 41", "missing", "*"),
    ("c5 fd 42", "missing", "*"),
    ("c5 fd 45", "missing", "*"),
    ("c5 fd 46", "missing", "*"),
    ("c5 fd 47", "missing", "*"),
    ("c5 fd 4a", "missing", "*"),
    ("c5 fd 4b", "missing", "*"),
    ("c5 fe 2a", "missing", "*"),
    ("c5 fe 2c", "missing", "*"),
    ("c5 fe 2d", "missing", "*"),
    ("c5 fe 51", "missing", "*"),
    ("c5 fe 52", "missing", "*"),
    ("c5 fe 53", "missing", "*"),
    ("c5 fe 58", "missing", "*"),
    ("c5 fe 59", "missing", "*"),
    ("c5 fe 5a", "missing", "*"),
    ("c5 fe 5c", "missing", "*"),
    ("c5 fe 5d", "missing", "*"),
    ("c5 fe 5e", "missing", "*"),
    ("c5 fe 5f", "missing", "*"),
    ("c5 fe c2", "missing", "*"),
    ("c5 ff 2a", "missing", "*"),
    ("c5 ff 2c", "missing", "*"),
    ("c5 ff 2d", "missing", "*"),
    ("c5 ff 51", "missing", "*"),
    ("c5 ff 58", "missing", "*"),
    ("c5 ff 59", "missing", "*"),
    ("c5 ff 5a", "missing", "*"),
    ("c5 ff 5c", "missing", "*"),
    ("c5 ff 5d", "missing", "*"),
    ("c5 ff 5e", "missing", "*"),
    ("c5 ff 5f", "missing", "*"),
    ("c5 ff c2", "missing", "*"),
    ("f2 0f 20", "missing", "*"),
    ("f2 0f 21", "missing", "*"),
    ("f2 0f 22", "missing", "*"),
    ("f2 0f 23", "missing", "*"),
    ("f3 0f 20", "missing", "*"),
    ("f3 0f 21", "missing", "*"),
    ("f3 0f 22", "missing", "*"),
    ("f3 0f 23", "missing", "*"),
    ("f3 0f 38 d8", "missing", "*"),
    ("f3 0f 38 dc", "missing", "*"),
    ("f3 0f 38 dd", "missing", "*"),
    ("f3 0f 38 de", "missing", "*"),
    ("f3 0f 38 df", "missing", "*"),
    ("f3 0f 38 fa", "missing", "*"),
    ("f3 0f 38 fb", "missing", "*"),
    ("f3 0f a6", "missing", "*"),
    ("f3 0f a7", "missing", "*"),
    ("62 f3 7c ..", "missing", "x86-64"),
    ("62 f3 7d ..", "missing", "x86-64"),
    ("62 f3 7e ..", "missing", "x86-64"),
    ("62 f3 7f ..", "missing", "x86-64"),
    ("62 f3 fd ..", "missing", "x86-64"),
    ("62 f4 7e 10 66", "missing", "x86-64"),
    ("62 f4 fe 10 66", "missing", "x86-64"),
    ("c4 e2 fb 49", "missing", "x86-64"),
    ("f2 0f 38 f8", "missing", "x86-64"),
    ("f3 0f 38 f8", "missing", "x86-64"),
    ("0f 0d ..", "mnemonic", "*"),
    ("0f 18 ..", "mnemonic", "*"),
    ("0f 1c ..", "mnemonic", "*"),
    ("66 0f 0d ..", "mnemonic", "*"),
    ("66 0f 18 ..", "mnemonic", "*"),
    ("66 0f 1c ..", "mnemonic", "*"),
    ("d9", "mnemonic", "*"),
    ("da", "mnemonic", "*"),
    ("db", "mnemonic", "*"),
    ("dc", "mnemonic", "*"),
    ("dd", "mnemonic", "*"),
    ("de", "mnemonic", "*"),
    ("df", "mnemonic", "*"),
    ("f2 0f 0d ..", "mnemonic", "*"),
    ("f2 0f 18 ..", "mnemonic", "*"),
    ("f2 0f 1c ..", "mnemonic", "*"),
    ("f3 0f 0d ..", "mnemonic", "*"),
    ("f3 0f 18 ..", "mnemonic", "*"),
    ("f3 0f 1c ..", "mnemonic", "*"),
    ("f3 0f 1e ..", "mnemonic", "*"),
    ("d5 00 da", "mnemonic", "x86-64"),
    ("d5 00 db", "mnemonic", "x86-64"),
    ("d5 00 dd", "mnemonic", "x86-64"),
    ("d5 00 de", "mnemonic", "x86-64"),
    ("d5 00 df", "mnemonic", "x86-64"),
    ("d5 18 da", "mnemonic", "x86-64"),
    ("d5 18 db", "mnemonic", "x86-64"),
    ("d5 18 dd", "mnemonic", "x86-64"),
    ("d5 18 de", "mnemonic", "x86-64"),
    ("d5 18 df", "mnemonic", "x86-64"),
    ("d5 49 da", "mnemonic", "x86-64"),
    ("d5 49 db", "mnemonic", "x86-64"),
    ("d5 49 dd", "mnemonic", "x86-64"),
    ("d5 49 de", "mnemonic", "x86-64"),
    ("d5 49 df", "mnemonic", "x86-64"),
    ("d5 51 da", "mnemonic", "x86-64"),
    ("d5 51 db", "mnemonic", "x86-64"),
    ("d5 51 dd", "mnemonic", "x86-64"),
    ("d5 51 de", "mnemonic", "x86-64"),
    ("d5 51 df", "mnemonic", "x86-64"),
    ("c4 e2 79 90", "spurious", "*"),
    ("c4 e2 79 91", "spurious", "*"),
    ("c4 e2 79 92", "spurious", "*"),
    ("c4 e2 79 93", "spurious", "*"),
    ("c4 e2 f9 90", "spurious", "*"),
    ("c4 e2 f9 91", "spurious", "*"),
    ("c4 e2 f9 92", "spurious", "*"),
    ("c4 e2 f9 93", "spurious", "*"),
    ("da", "spurious", "*"),
    ("db", "spurious", "*"),
    ("dd", "spurious", "*"),
    ("de", "spurious", "*"),
    ("df", "spurious", "*"),
    ("c4 e2 78 5e", "spurious", "x86-64"),
    ("c4 e2 78 6c", "spurious", "x86-64"),
    ("c4 e2 79 5e", "spurious", "x86-64"),
    ("c4 e2 79 6c", "spurious", "x86-64"),
    ("c4 e2 7a 5c", "spurious", "x86-64"),
    ("c4 e2 7a 5e", "spurious", "x86-64"),
    ("c4 e2 7b 5c", "spurious", "x86-64"),
    ("c4 e2 7b 5e", "spurious", "x86-64"),
    ("d5 00 de", "spurious", "x86-64"),
    ("d5 18 de", "spurious", "x86-64"),
    ("d5 49 de", "spurious", "x86-64"),
    ("d5 51 de", "spurious", "x86-64"),
];

fn report(d: &Diff) -> String {
    let mut msg = String::new();
    for (label, v) in [
        ("missing", &d.missing),
        ("spurious", &d.spurious),
        ("len", &d.len),
        ("mnemonic", &d.mnemonic),
    ] {
        if !v.is_empty() {
            msg.push_str(&format!("\n{label} ({} keys):", v.len()));
            for (k, (n, x)) in v {
                msg.push_str(&format!("\n  {k} x{n}  {x}"));
            }
        }
    }
    msg
}

#[test]
fn oracle_xed_decode_diff() {
    let Some(xed) = ["xed", "/opt/xed/bin/xed", "/usr/bin/xed"]
        .iter()
        .find(|c| {
            Command::new(c)
                .arg("-version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(|s| s.to_string())
    else {
        eprintln!("xed がない。スキップ");
        return;
    };
    let all = FEAT_BITS.iter().fold(0u128, |a, (_, b)| a | b);
    let f32 = all & !polyisa_guest_x86::FEAT_POP_CS;
    let f64 = f32 & !polyisa_guest_x86::FEAT_OP82;
    let legacy = corpus();
    let evex = corpus_evex();
    let rex2 = corpus_rex2();
    let mut all_msg = String::new();
    for (name, flag, modes, feats, cands) in [
        ("i386", "32", MODES32, f32, &legacy[..]),
        ("x86-64", "64", MODES64, f64, &legacy[..]),
        ("x86-64", "64", MODES64, f64, &evex[..]),
        ("x86-64", "64", MODES64, f64, &rex2[..]),
    ] {
        let d = run_pass(&xed, flag, modes, feats, name, cands);
        let msg = report(&d);
        if !msg.is_empty() {
            all_msg.push_str(&format!("[{name}] oracle diff:{msg}\n"));
        }
    }
    assert!(all_msg.is_empty(), "{all_msg}");
}
