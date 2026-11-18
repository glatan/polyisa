// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! llvm-mc をオラクルに x86 のデコードを差分する（層: oracle、E1a）。
//!
//! 候補の命令バイト列を網羅で生成し、一つずつ
//! `llvm-mc -disassemble -show-encoding` に投げて「オラクルが
//! 先頭バイトで命令を認識するか」「消費バイト長」「ニーモニック」を
//! polyisa（map 経路→列挙経路の順）と比較する。i386 と x86-64 の
//! 両モードで回す。比較の扱い:
//!
//! - encoding のバイト値は比べない。llvm は不要な REX・無視される
//!   接頭辞・reg フィールドを canonical 形に正規化して返し、
//!   rel オペランドは `A` で出すため、先頭接頭辞を剥がした後の
//!   長さだけを比較する。
//! - ニーモニックは AT&T の幅接尾辞（b/w/l/q）除去と別名表
//!   （setj*/cmovj*/lcall 等）で正規化して比べる。
//! - 既知の差分は `KNOWN` 表に（オペコード head, 種別, モード）で
//!   列挙する。未対応ファミリ（A3a/A4/B3）、接頭辞剥がし設計由来の
//!   寛容さ、reg/mod 検証不足、x87 副表の未定義スロット受理を分類する。
//!
//! ツールが無ければスキップする（testkit::reqs がフィルタを掛ける）。
//! オペランドの比較はしない（E1b 以降）。

use polyisa_guest_x86::{
    FEAT_BITS, MODE_ADR_A32, MODE_ADR_A64, MODE_ADR_SHIFT, MODE_M64, MODE_OPD_O32, MODE_OPD_SHIFT,
    decode_map, decode_model_ex,
};
use std::io::Write;
use std::process::{Command, Stdio};

/// 32 ビットモードの `decode_map` モード値。
const MODES32: u32 = (MODE_OPD_O32 << MODE_OPD_SHIFT) | (MODE_ADR_A32 << MODE_ADR_SHIFT);
/// 64 ビットモード。
const MODES64: u32 = MODE_M64 | (MODE_OPD_O32 << MODE_OPD_SHIFT) | (MODE_ADR_A64 << MODE_ADR_SHIFT);

/// オラクルが返した先頭の命令。
#[derive(Clone)]
enum Oracle {
    /// 先頭バイトで解読できない。
    Invalid,
    /// (ニーモニック, encoding のバイト列)。
    /// None は fixup プレースホルダ（rel オペランドの `A` 等）で
    /// 任意のバイトに一致する。
    Insn(String, Vec<Option<u8>>),
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

/// polyisa 側の結果。(命令名, 消費したバイト列)。
fn polyisa_decode(bytes: &[u8], modes: u32, feats: u128) -> Option<(String, Vec<u8>)> {
    if let Some(d) = decode_map(bytes, modes, feats) {
        let len = usize::from(d.len);
        return Some((
            insn_mnemonic(d.insn),
            bytes[..len.min(bytes.len())].to_vec(),
        ));
    }
    // 列挙経路。パターンはバイト列の完全一致なので、昇順に
    // 試して最初に解読できた長さを命令長とする。word は
    // 命令バイトを big-endian で詰めたもの。
    for len in 1..=bytes.len().min(15) {
        let word = bytes[..len]
            .iter()
            .fold(0u128, |w, c| (w << 8) | u128::from(*c));
        if let Some(i) = decode_model_ex(word, len as u32 * 8, true, feats) {
            return Some((insn_mnemonic(i), bytes[..len].to_vec()));
        }
    }
    None
}

/// `llvm-mc -disassemble` に一命令だけ渡す。
fn oracle_decode(llvm_mc: &str, triple: &str, bytes: &[u8]) -> Result<Oracle, String> {
    let mut ch = Command::new(llvm_mc)
        .args([
            "-disassemble",
            "-show-encoding",
            &format!("-triple={triple}"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    let line = bytes
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    ch.stdin
        .take()
        .unwrap()
        .write_all(line.as_bytes())
        .map_err(|e| format!("stdin: {e}"))?;
    let out = ch.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        return Err(format!("exit: {}", out.status));
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // 警告の `^` 位置から失敗したバイトを得る。byte k は 4k+1 桁目。
    for l in stderr.lines() {
        if l.contains("invalid instruction encoding") {
            // 次の行の `^` の位置を探るのではなく、stderr の
            // `<stdin>:1:COL` を使う。
            if let Some(c) = l.split(':').nth(2)
                && let Ok(col) = c.trim().parse::<usize>()
                && col <= 4
            {
                return Ok(Oracle::Invalid);
            }
        }
    }
    // 先頭の命令行を取る。# encoding: [...] から消費バイトが分かる。
    // セグメント接頭辞は encoding に現れない（llvm-mc が別扱いする）。
    let stdout = String::from_utf8_lossy(&out.stdout);
    for l in stdout.lines() {
        let l = l.trim_start();
        if l.is_empty() || l.starts_with('#') || l.starts_with('.') {
            continue;
        }
        // `repne incl` のように接頭辞は別トークンで出るので落とす。
        let mn = l
            .split_whitespace()
            .find(|t| {
                !matches!(
                    *t,
                    "lock"
                        | "rep"
                        | "repe"
                        | "repne"
                        | "repz"
                        | "repnz"
                        | "es"
                        | "cs"
                        | "ss"
                        | "ds"
                        | "fs"
                        | "gs"
                        | "data16"
                        | "addr16"
                        | "addr32"
                        | "xacquire"
                        | "xrelease"
                )
            })
            .unwrap_or("");
        if mn.is_empty() {
            // `lock` 単独の行（lock+命令は llvm が2行に分ける）。
            continue;
        }
        let enc = l.rsplit('#').next().unwrap_or("");
        let bytes: Vec<Option<u8>> = enc
            .find('[')
            .and_then(|a| enc.find(']').map(|b| &enc[a + 1..b]))
            .map(|body| {
                body.split(',')
                    .map(|x| {
                        let x = x.trim();
                        // `0xNN` だけを受理。`A` 等の fixup は
                        // ワイルドカード（rel オペランドの実値は
                        // encoding に出ない）。
                        x.strip_prefix("0x")
                            .and_then(|h| u8::from_str_radix(h, 16).ok())
                    })
                    .collect()
            })
            .unwrap_or_default();
        return Ok(Oracle::Insn(mn.to_lowercase(), bytes));
    }
    Ok(Oracle::Invalid)
}

/// 先頭のレガシー接頭辞（seg/66/67/F0/F2/F3）を剥がす。
fn strip_pfx(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < b.len()
        && matches!(
            b[i],
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
        )
    {
        i += 1;
    }
    &b[i..]
}

fn strip_pfx_opt(b: &[Option<u8>]) -> &[Option<u8>] {
    let mut i = 0;
    while i < b.len()
        && b[i].is_some_and(|x| {
            matches!(
                x,
                0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
            )
        })
    {
        i += 1;
    }
    &b[i..]
}

/// ニーモニックの正規化。llvm の AT&T 接尾辞（b/w/l/q）一文字を
/// 落とした一致を許し、系統的な別名は表で吸収する。
fn same_mnemonic(ours: &str, llvm: &str) -> bool {
    let ours = ours.trim_end_matches([',', ' ']);
    if ours == llvm {
        return true;
    }
    // llvm の AT&T 幅接尾辞（b/w/l/q）を落とした形でも比べる。
    let lbase = llvm.strip_suffix(['b', 'w', 'l', 'q']).unwrap_or(llvm);
    if ours == lbase {
        return true;
    }
    // 別名判定は元形と接尾辞除去形の両方に適用する。
    let is = |x: &str| llvm == x || lbase == x;
    // 我々の j 接頭辞（setjle / cmovjae / xchg 名）。
    if let Some(rest) = ours.strip_prefix("setj")
        && is(&format!("set{rest}"))
    {
        return true;
    }
    if let Some(rest) = ours.strip_prefix("cmovj")
        && is(&format!("cmov{rest}"))
    {
        return true;
    }
    if let Some(rest) = ours.strip_prefix('j') {
        // Jcc。`jne` → llvm `jne`。`jnae`/`jpe` 等の別名も通す。
        if is(rest) || is(&format!("j{rest}")) {
            return true;
        }
        const JALIAS: &[(&str, &str)] = &[
            ("nae", "jb"),
            ("ae", "jnb"),
            ("na", "jbe"),
            ("pe", "jp"),
            ("po", "jnp"),
            ("nge", "jl"),
            ("nle", "jg"),
            ("ge", "jnl"),
            ("le", "jng"),
            ("z", "je"),
            ("nz", "jne"),
            ("o", "jo"),
            ("no", "jno"),
            ("s", "js"),
            ("ns", "jns"),
            ("p", "jp"),
            ("b", "jb"),
            ("a", "ja"),
            ("e", "je"),
            ("g", "jg"),
            ("l", "jl"),
            ("c", "jb"),
            ("nc", "jae"),
        ];
        if JALIAS
            .iter()
            .any(|(o, l)| *o == rest && (is(l) || llvm.starts_with(l)))
        {
            return true;
        }
    }
    // x87 のメモリ形は llvm が `fadds` のように s 接尾辞を付ける。
    if ours.starts_with('f') && llvm == format!("{ours}s") {
        return true;
    }
    // （我々の名, llvm の名）の既知の別名。
    const ALIAS: &[(&str, &str)] = &[
        ("callf", "lcall"),
        ("retf", "lret"),
        ("jmpf", "ljmp"),
        ("jcxz", "jcxz"),
        ("jcxz", "jecxz"),
        ("jcxz", "jrcxz"),
        ("movzx", "movzb"),
        ("movzx", "movzw"),
        ("movsx", "movsb"),
        ("movsx", "movsw"),
        ("sal", "shl"),
        ("retn", "ret"),
        ("ret", "retl"),
        ("call", "calll"),
        ("cwde", "cwtl"),
        ("cdq", "cltd"),
        ("cbw", "cbtw"),
        ("cwd", "cwtd"),
        ("xchg", "nop"),
        ("fwait", "wait"),
        ("int3", "int"),
        ("lahf", "lahf"),
        ("movsxd", "movslq"),
        ("mov", "movabs"),
    ];
    ALIAS
        .iter()
        .any(|(o, l)| ours == *o && (is(l) || llvm.starts_with(l)))
}

/// 候補の命令バイト列。(head, 全体)。head はオペコード部で、
/// 差分の既知表のキーに使う。
fn corpus() -> Vec<(Vec<u8>, Vec<u8>)> {
    let tail = [0x41u8, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a];
    let modrms = [
        0xC0u8, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8, // mod=11 reg 0-7
        0xC4, // mod=11 rm=4（reg 形、SIB ではない）
        0x05, 0x40, 0x85, // メモリ形
        0x04, 0x44,
        0x84, // SIB（mod=00/01/10, rm=100。SIB バイトは tail から取る）
    ];
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut put = |head: &[u8]| {
        for &m in &modrms {
            let mut v = head.to_vec();
            v.push(m);
            v.extend_from_slice(&tail);
            out.push((head.to_vec(), v));
        }
    };
    for op in 0x00..=0xFFu8 {
        put(&[op]);
    }
    for op2 in 0x00..=0xFFu8 {
        put(&[0x0F, op2]);
    }
    // 必須接頭辞付き 0F マップ（66/F2/F3 0F xx）。0x38/0x3A は
    // サブマップの専用ループが全 third バイトを回すので除く。
    for &pfx in &[0x66u8, 0xF2, 0xF3] {
        for op2 in 0x00..=0xFFu8 {
            if op2 != 0x38 && op2 != 0x3A {
                put(&[pfx, 0x0F, op2]);
            }
        }
    }
    // 0F 38 / 0F 3A サブマップ。NP 形（MOVBE/SHA/MOVRS）もあるので
    // 接頭辞なし・付きの両方を回す。
    for op3 in 0x00..=0xFFu8 {
        put(&[0x0F, 0x38, op3]);
        put(&[0x0F, 0x3A, op3]);
    }
    for &pfx in &[0x66u8, 0xF2, 0xF3] {
        for op3 in 0x00..=0xFFu8 {
            put(&[pfx, 0x0F, 0x38, op3]);
            put(&[pfx, 0x0F, 0x3A, op3]);
        }
    }
    out
}

#[derive(Default)]
struct Diff {
    /// オラクルは解読するが polyisa が拒否。
    missing: Vec<String>,
    /// polyisa は解読するがオラクルが拒否。
    spurious: Vec<String>,
    /// 長さの不一致。
    len: Vec<String>,
    /// ニーモニックの不一致。
    mnemonic: Vec<String>,
}

fn hexs(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_pass(llvm_mc: &str, triple: &str, modes: u32, feats: u128, mode: &str) -> Diff {
    let mut diff = Diff::default();
    let candidates = corpus();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    // オラクル結果を並列に取る。ツール呼び出しの失敗は
    // Invalid と区別して数え、最後に失敗させる（起動失敗を
    // 「解読不能」と誤認して静かに通過しないため）。
    let errs = std::sync::atomic::AtomicUsize::new(0);
    let mut results: Vec<Option<Oracle>> = vec![None; candidates.len()];
    std::thread::scope(|s| {
        let errs = &errs;
        let chunk = candidates.len().div_ceil(threads);
        let mut hs = Vec::new();
        for (slice, r) in candidates.chunks(chunk).zip(results.chunks_mut(chunk)) {
            hs.push(s.spawn(move || {
                for (i, cand) in slice.iter().enumerate() {
                    match oracle_decode(llvm_mc, triple, &cand.1) {
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
        panic!("{mode}: llvm-mc の呼び出しが {errs} 回失敗");
    }
    for (i, (head, cand)) in candidates.iter().enumerate() {
        let oracle = results[i].as_ref().unwrap_or(&Oracle::Invalid);
        let ours = polyisa_decode(cand, modes, feats);
        let h = hexs(&cand[..cand.len().min(8)]);
        // `0f 38`/`0f 3a` ヘッドはサブマップオペコードが3バイト目
        // にあるのでキーに含める。
        let key = if matches!(head.as_slice(), [0x0F, 0x38] | [0x0F, 0x3A]) {
            hexs(&cand[..3])
        } else {
            hexs(head)
        };
        match (ours, oracle) {
            (None, Oracle::Invalid) => {}
            (None, Oracle::Insn(mn, enc)) => {
                let e = format!("{h}: oracle {mn} len {}", enc.len());
                if !known(&key, "missing", mode) {
                    diff.missing.push(e);
                }
            }
            (Some((n, ob)), Oracle::Invalid) => {
                let e = format!("{h}: ours {n} len {}", ob.len());
                if !known(&key, "spurious", mode) {
                    diff.spurious.push(e);
                }
            }
            (Some((n, ob)), Oracle::Insn(mn, enc)) => {
                // llvm-mc は無視される接頭辞を encoding から落とす
                // （非メモリ命令の seg、バイト命令の 0x66 等）。
                // 両側の先頭接頭辞を剥がして比較する。
                let ours = strip_pfx(&ob);
                let theirs = strip_pfx_opt(enc);
                // バイト値は比べない。llvm は reg フィールド等を
                // canonical 形に正規化して返す（`0f 1f c8` →
                // `[0f,1f,c0]`）。rel オペランドは `A` で出る。
                let same_enc = ours.len() == theirs.len();
                if !same_enc {
                    let e = format!(
                        "{h}: ours {n} len {} vs {mn} len {}",
                        ours.len(),
                        theirs.len()
                    );
                    if !known(&key, "len", mode) {
                        diff.len.push(e);
                    }
                } else if !same_mnemonic(&n, mn) && !known(&key, "mnemonic", mode) {
                    diff.mnemonic.push(format!("{h}: ours {n} vs {mn}"));
                }
            }
        }
    }
    diff
}

/// 既知の差分。(head hex, 種別)。head はオペコードバイト列。
/// Gap: GAP-0037。
/// 差分の理由は `KNOWN_WHY` に一覧する。`mnemonic` は表を通った
/// 個別名の違いだけを許す。
fn known(head: &str, kind: &str, mode: &str) -> bool {
    KNOWN
        .iter()
        .any(|(h, k, m)| *h == head && (*k == kind || *k == "*") && (*m == "*" || *m == mode))
}

/// 既知の差分の一覧。(head, 種別)。種別 `*` は全種別を許す。
///
/// 分類:
/// - A0: 80186/80286 実モード命令（ロードマップ A0）。
/// - A3a/A4/C1/B3: 後続ステップの対象。
/// - gate: 既定機能集合でゲートされる（decode の正しい拒否）。
/// - strict: polyisa 側の reg/mod 検証の不足（HW は受理しない
///   のに解読する）。将来マップ宣言を厳しくする。
/// - loose: オラクルが知らないが HW は受理する（prefetch 等）。
/// - x87: x87 mod=11 副表の未定義スロット受理と別名差。
const KNOWN: &[(&str, &str, &str)] = &[
    // ---- 後続ステップの対象 ----
    // bound（A0）。x86-64 では EVEX 接頭辞なので AVX-512 系も
    // この行に含まれる。
    ("62", "missing", "*"),
    ("6c", "missing", "*"),
    ("6d", "missing", "*"),
    ("6e", "missing", "*"),
    ("6f", "missing", "*"),    // ins/outs（A0）
    ("0f 01", "missing", "*"), // 0F 01 の mod=11 形・/5 /7（VMX/INVLPG/serialize 等、A4 以降）
    ("0f 06", "missing", "*"),
    ("0f 07", "missing", "*"), // clts/sysret（A4）
    ("0f 08", "missing", "*"),
    ("0f 09", "missing", "*"), // invd/wbinvd（A4）
    ("0f 0e", "missing", "*"), // femms（B3、3DNow）
    ("0f 20", "missing", "*"),
    ("0f 21", "missing", "*"),
    ("0f 22", "missing", "*"),
    ("0f 23", "missing", "*"), // mov cr/dr（A4）
    ("0f 30", "missing", "*"),
    ("0f 32", "missing", "*"),
    ("0f 33", "missing", "*"),
    ("0f 37", "missing", "*"), // wrmsr/rdmsr/rdpmc/getsec（A4）
    ("0f 78", "missing", "*"),
    ("0f 79", "missing", "*"), // vmread/vmwrite（A4）
    ("0f a6", "missing", "*"),
    ("0f a7", "missing", "*"), // VIA 拡張（B3）
    ("0f aa", "missing", "*"), // rsm（A4）
    ("0f ae", "missing", "*"), // fxsave 等（C1）
    // lss/lfs/lgs（D2 で実装）。mod=11 形を受理するのは GAP-0037(a)
    // と同じく mod 制約の未宣言が原因（strict）。
    ("0f b2", "spurious", "*"),
    ("0f b4", "spurious", "*"),
    ("0f b5", "spurious", "*"),
    // rdrand/rdseed 等（A4）。/1 のメモリ形（cmpxchg8b/16b）は
    // 宣言済みなので、この行が覆うのは /0,/2-/7 と mod=11。
    ("0f c7", "missing", "*"),
    // SSE1/2 の未宣言残り（別ステップで補完）。
    ("0f 2a", "missing", "*"),  // cvtpi2ps
    ("0f 2a", "mnemonic", "*"), // 列挙経路は F2 剥がし形で cvtsi2sd として解読
    ("0f 2b", "missing", "*"),  // movntps
    ("0f 2c", "missing", "*"),  // cvttps2pi
    ("0f 2c", "mnemonic", "*"), // 同上 cvttsd2si
    ("0f 2d", "missing", "*"),  // cvtps2pi
    ("0f 2d", "mnemonic", "*"), // 同上
    ("0f 52", "missing", "*"),  // rsqrtps
    ("0f 53", "missing", "*"),  // rcpps
    ("0f c3", "missing", "*"),  // movnti
    // 0F 38/3A の未宣言（A3a/A4/将来）。
    ("66 0f 38 80", "missing", "*"),
    ("66 0f 38 81", "missing", "*"),
    ("66 0f 38 82", "missing", "*"), // invept/invvpid/invpcid（A4）
    ("66 0f 38 f5", "missing", "*"), // wruss（mod=11 等の未宣言形）
    ("f2 0f 38 f6", "missing", "*"),
    ("66 0f 38 f6", "missing", "*"),
    ("f3 0f 38 f6", "missing", "*"), // adcx/adox（A3a）
    ("66 0f 38 f8", "missing", "*"),
    ("66 0f 38 f9", "missing", "*"),
    ("f2 0f 38 f8", "missing", "*"),
    ("f2 0f 38 f9", "missing", "*"),
    ("f3 0f 38 f8", "missing", "*"),
    ("f3 0f 38 f9", "missing", "*"), // movdir/enqcmd/uwrmsr（A4）
    ("66 0f 38 fc", "missing", "*"),
    ("f2 0f 38 fc", "missing", "*"),
    ("f3 0f 38 fc", "missing", "*"), // aand/aor/axor（A4）
    ("f3 0f 38 fa", "missing", "*"),
    ("f3 0f 38 fb", "missing", "*"), // encodekey（A4）
    ("f3 0f 38 d8", "missing", "*"),
    ("f3 0f 38 dc", "missing", "*"),
    ("f3 0f 38 dd", "missing", "*"),
    ("f3 0f 38 de", "missing", "*"),
    ("f3 0f 38 df", "missing", "*"), // aes*kl/loadiwkey（A3a）
    ("66 0f 38 c8", "missing", "*"),
    ("66 0f 38 c9", "missing", "*"),
    ("66 0f 38 ca", "missing", "*"),
    ("66 0f 38 cb", "missing", "*"),
    ("66 0f 38 cc", "missing", "*"),
    ("66 0f 38 cd", "missing", "*"),
    ("f2 0f 38 c8", "missing", "*"),
    ("f2 0f 38 c9", "missing", "*"),
    ("f2 0f 38 ca", "missing", "*"),
    ("f2 0f 38 cb", "missing", "*"),
    ("f2 0f 38 cc", "missing", "*"),
    ("f2 0f 38 cd", "missing", "*"),
    ("f3 0f 38 c8", "missing", "*"),
    ("f3 0f 38 c9", "missing", "*"),
    ("f3 0f 38 ca", "missing", "*"),
    ("f3 0f 38 cb", "missing", "*"),
    ("f3 0f 38 cc", "missing", "*"),
    ("f3 0f 38 cd", "missing", "*"), // sha（A3a）
    ("0f 38 8a", "missing", "*"),
    ("0f 38 8b", "missing", "*"), // movrsb/movrsl（新命令群、A4 以降）
    ("0f 38 f6", "missing", "*"), // wrss（mod=11 等の未宣言形）
    ("0f 38 f8", "missing", "*"),
    ("0f 38 f9", "missing", "*"),
    ("0f 38 fc", "missing", "*"), // wrssd/movrs/movdiri/aadd（新命令群、A4 以降）
    ("66 0f 3a cc", "missing", "*"),
    ("f2 0f 3a cc", "missing", "*"),
    ("f3 0f 3a cc", "missing", "*"), // sha1rnds4 の接頭辞付き形（llvm は受理）
    ("f3 0f 3a f0", "missing", "*"), // hreset（A4）
    // ---- 必須接頭辞 0F ヘッド。mod 制約・MMX 寛容（No66/No66F3）
    // 修正で大半は一致する。残りは未宣言の命令群。
    // en 経路が mov sreg の reg6/7 を受理する（map 経路は
    // group で /0-/5 のみ）。
    ("8e", "spurious", "*"),
    // xabort/xbegin（A4）。
    ("c6", "missing", "*"),
    ("c7", "missing", "*"),
    // 66 0F: A4 のシステム系（66 は無視される）と SSE2 の
    // 未宣言 xmm 形（map 未宣言。列挙経路は剥がし形として
    // 一部実装済み）。
    ("66 0f 01", "missing", "*"),
    ("66 0f 05", "missing", "i386"), // syscall（m64 ゲート）
    ("66 0f 06", "missing", "*"),
    ("66 0f 07", "missing", "*"),
    ("66 0f 08", "missing", "*"),
    ("66 0f 0e", "missing", "*"),
    ("66 0f 20", "missing", "*"),
    ("66 0f 21", "missing", "*"),
    ("66 0f 22", "missing", "*"),
    ("66 0f 23", "missing", "*"),
    ("66 0f 30", "missing", "*"),
    ("66 0f 32", "missing", "*"),
    ("66 0f 33", "missing", "*"),
    ("66 0f 37", "missing", "*"),
    ("66 0f 78", "missing", "*"),
    ("66 0f 79", "missing", "*"), // extrq（AMD SSE4a、B3b。sse4a ゲート）
    ("66 0f a6", "missing", "*"),
    ("66 0f a7", "missing", "*"),
    ("66 0f aa", "missing", "*"),
    ("66 0f ae", "missing", "*"), // fxsave/clwb/clflushopt/tpause（C1/A4）
    ("66 0f b2", "spurious", "*"),
    ("66 0f b4", "spurious", "*"),
    ("66 0f b5", "spurious", "*"), // lss/lfs/lgs（D2、strict）
    ("66 0f c3", "missing", "*"),  // movnti
    ("66 0f c7", "missing", "*"),  // rdrand/rdseed（A4）
    // SSE2 xmm 形の未宣言（PACK*/PMULH*/PMULUDQ/PMADDWD/PSADBW/
    // CVTTPD2DQ/CVTPI2PD/MOVNTPD/MOVNTDQ 等）。
    ("66 0f 2a", "missing", "*"),
    ("66 0f 2b", "missing", "*"),
    ("66 0f 2c", "missing", "*"),
    ("66 0f 2d", "missing", "*"),
    ("66 0f 52", "missing", "*"),
    ("66 0f 53", "missing", "*"),
    ("66 0f e4", "missing", "*"),
    ("66 0f e5", "missing", "*"),
    ("66 0f e7", "missing", "*"),
    ("66 0f f4", "missing", "*"),
    ("66 0f f5", "missing", "*"),
    ("66 0f f6", "missing", "*"),
    // F2 0F: A4 のシステム系と未宣言の F2 命令。
    ("f2 0f 00", "missing", "*"), // lkgs（新命令、未対応）
    ("f2 0f 01", "missing", "*"),
    ("f2 0f 05", "missing", "i386"), // syscall（m64 ゲート）
    ("f2 0f 06", "missing", "*"),
    ("f2 0f 07", "missing", "*"),
    ("f2 0f 08", "missing", "*"),
    ("f2 0f 0e", "missing", "*"),
    ("f2 0f 16", "missing", "*"), // movldup
    ("f2 0f 20", "missing", "*"),
    ("f2 0f 21", "missing", "*"),
    ("f2 0f 22", "missing", "*"),
    ("f2 0f 23", "missing", "*"),
    ("f2 0f 2b", "missing", "*"), // movntsd（sse4a ゲート）
    ("f2 0f 30", "missing", "*"),
    ("f2 0f 32", "missing", "*"),
    ("f2 0f 33", "missing", "*"),
    ("f2 0f 37", "missing", "*"),
    ("f2 0f 52", "missing", "*"),
    ("f2 0f 53", "missing", "*"),
    ("f2 0f 5b", "missing", "*"),
    ("f2 0f 78", "missing", "*"),
    ("f2 0f 79", "missing", "*"),
    ("f2 0f a6", "missing", "*"),
    ("f2 0f a7", "missing", "*"),
    ("f2 0f aa", "missing", "*"),
    ("f2 0f ae", "missing", "*"), // fxsave/umwait（C1/A4）
    ("f2 0f b2", "spurious", "*"),
    ("f2 0f b4", "spurious", "*"),
    ("f2 0f b5", "spurious", "*"), // lss/lfs/lgs（D2、strict）
    ("f2 0f c3", "missing", "*"),
    ("f2 0f c7", "missing", "*"), // rdrand/rdseed（A4）
    ("f2 0f d6", "missing", "*"), // movdq2q
    // F3 0F: A4 のシステム系と未宣言の F3 命令。
    ("f3 0f 01", "missing", "*"),
    ("f3 0f 05", "missing", "i386"), // syscall（m64 ゲート）
    ("f3 0f 06", "missing", "*"),
    ("f3 0f 07", "missing", "*"),
    ("f3 0f 08", "missing", "*"),
    ("f3 0f 09", "missing", "*"), // wbnoinvd（A4）
    ("f3 0f 0e", "missing", "*"),
    ("f3 0f 20", "missing", "*"),
    ("f3 0f 21", "missing", "*"),
    ("f3 0f 22", "missing", "*"),
    ("f3 0f 23", "missing", "*"),
    ("f3 0f 2b", "missing", "*"),
    ("f3 0f 30", "missing", "*"),
    ("f3 0f 32", "missing", "*"),
    ("f3 0f 33", "missing", "*"),
    ("f3 0f 37", "missing", "*"),
    ("f3 0f 52", "missing", "*"),
    ("f3 0f 53", "missing", "*"),
    ("f3 0f 78", "missing", "*"),
    ("f3 0f 79", "missing", "*"),
    ("f3 0f a6", "missing", "*"),
    ("f3 0f a7", "missing", "*"),
    ("f3 0f aa", "missing", "*"),
    ("f3 0f ae", "missing", "*"), // umonitor/ptwrite 等（A4d 以降）
    ("f3 0f b2", "spurious", "*"),
    ("f3 0f b4", "spurious", "*"),
    ("f3 0f b5", "spurious", "*"), // lss/lfs/lgs（D2、strict）
    ("f3 0f c3", "missing", "*"),
    ("f3 0f c7", "missing", "*"), // rdrand/rdpid（A4）
    ("f3 0f d6", "missing", "*"), // movq2dq
    // 接頭辞付きのヒント NOP 系。0F 0D/18/1C はオラクルが
    // prefetch/prefetchnta/cldemote 名を返す（mod!=11 のみ）、
    // 19-1D は拒否する（我々は寛容に nop として受理＝HW 準拠）。
    ("66 0f 0d", "mnemonic", "*"),
    ("66 0f 0d", "spurious", "*"),
    ("66 0f 18", "mnemonic", "*"),
    ("66 0f 18", "spurious", "*"),
    ("66 0f 19", "spurious", "*"),
    ("66 0f 1a", "spurious", "*"),
    ("66 0f 1b", "spurious", "*"),
    ("66 0f 1c", "mnemonic", "*"),
    ("66 0f 1c", "spurious", "*"),
    ("66 0f 1d", "spurious", "*"),
    ("f2 0f 0d", "mnemonic", "*"),
    ("f2 0f 0d", "spurious", "*"),
    ("f2 0f 18", "mnemonic", "*"),
    ("f2 0f 18", "spurious", "*"),
    ("f2 0f 19", "spurious", "*"),
    ("f2 0f 1a", "spurious", "*"),
    ("f2 0f 1b", "spurious", "*"),
    ("f2 0f 1c", "mnemonic", "*"),
    ("f2 0f 1c", "spurious", "*"),
    ("f2 0f 1d", "spurious", "*"),
    ("f3 0f 0d", "mnemonic", "*"),
    ("f3 0f 0d", "spurious", "*"),
    ("f3 0f 18", "mnemonic", "*"),
    ("f3 0f 18", "spurious", "*"),
    ("f3 0f 19", "spurious", "*"),
    ("f3 0f 1a", "spurious", "*"),
    ("f3 0f 1b", "spurious", "*"),
    ("f3 0f 1c", "mnemonic", "*"),
    ("f3 0f 1c", "spurious", "*"),
    ("f3 0f 1d", "spurious", "*"),
    // F3 0F 1E: ENDBR64/32 は FA/FB のみ。我々は全 mod=11 を
    // 受理するので残りは spurious、FA/FB は名の差。
    ("f3 0f 1e", "spurious", "*"),
    ("f3 0f 1e", "mnemonic", "*"),
    // TZCNT/LZCNT（BMI1）は bsf/bsr の F3 形。別名として扱う
    // （BMI は後続ファミリ）。
    ("f3 0f bc", "mnemonic", "*"),
    ("f3 0f bd", "mnemonic", "*"),
    // ---- 列挙経路は接頭辞剥がし後の空間を解読する（設計）。
    // 実行時は step_x86 が 66/F3 等を剥がしてから渡すため、
    // 剥がれた形の命令を受理する。オラクルは接頭辞必須と見る。
    ("0f 1e", "spurious", "*"), // rdsspq（F3 剥がし形）
    ("0f 6c", "spurious", "*"),
    ("0f 6d", "spurious", "*"), // punpck*qdq（66 剥がし形）
    ("0f 73", "spurious", "*"), // psrldq/pslldq（66 剥がし形）
    ("0f d6", "spurious", "*"), // movq（66 剥がし形）
    // ---- reg/mod の検証不足（マップ宣言を厳しくする残件）----
    ("f6", "spurious", "*"),
    ("f7", "spurious", "*"), // test /1（HW 受理の別名、llvm は拒否）
    ("c0", "spurious", "*"),
    ("c1", "spurious", "*"),
    ("d0", "spurious", "*"),
    ("d1", "spurious", "*"),
    ("d2", "spurious", "*"),
    ("d3", "spurious", "*"), // shift /6（sal 別名、llvm は拒否）
    // ---- x87 mod=11 副表（GAP-0037b: 未定義スロットを受理、別名も差）----
    ("d9", "spurious", "*"),
    ("da", "spurious", "*"),
    ("db", "spurious", "*"),
    ("dc", "spurious", "*"),
    ("dd", "spurious", "*"),
    ("de", "spurious", "*"),
    ("df", "spurious", "*"),
    ("d9", "mnemonic", "*"),
    ("da", "mnemonic", "*"),
    ("db", "mnemonic", "*"),
    ("dc", "mnemonic", "*"),
    ("dd", "mnemonic", "*"),
    ("de", "mnemonic", "*"),
    ("df", "mnemonic", "*"),
    // ---- オラクルが知らないが HW は受理 ----
    ("0f 0d", "*", "*"), // prefetch（AMD）、我々は nop
    ("0f 18", "*", "*"),
    ("0f 19", "*", "*"),
    ("0f 1a", "*", "*"),
    ("0f 1b", "*", "*"),
    ("0f 1c", "*", "*"),
    ("0f 1d", "*", "*"), // hint nop 系
    // ---- 接頭辞先頭の候補（剥がし・lock 行分割の差）----
    ("f0", "*", "*"),
    ("f2", "*", "*"),
    ("f3", "*", "*"),
    ("26", "*", "*"),
    ("2e", "*", "*"),
    ("36", "*", "*"),
    ("3e", "*", "*"),
    ("64", "*", "*"),
    ("65", "*", "*"),
    ("66", "*", "*"),
    ("67", "*", "*"),
    // 0f 1f の canonical 正規化
    ("0f 1f", "*", "*"),
    // ---- x86-64 固有 ----
    // 0x40-0x4F ヘッドは REX。llvm は効果のない REX を encoding
    // から落とし、列挙経路は剥がし後の空間として inc/dec を返す。
    ("40", "*", "x86-64"),
    ("41", "*", "x86-64"),
    ("42", "*", "x86-64"),
    ("43", "*", "x86-64"),
    ("44", "*", "x86-64"),
    ("45", "*", "x86-64"),
    ("46", "*", "x86-64"),
    ("47", "*", "x86-64"),
    ("48", "*", "x86-64"),
    ("49", "*", "x86-64"),
    ("4a", "*", "x86-64"),
    ("4b", "*", "x86-64"),
    ("4c", "*", "x86-64"),
    ("4d", "*", "x86-64"),
    ("4e", "*", "x86-64"),
    ("4f", "*", "x86-64"),
    // far 転送・iret は 64 ビットでは未宣言（decode の正しい拒否）。
    ("9a", "missing", "x86-64"),
    ("ca", "missing", "x86-64"),
    ("cb", "missing", "x86-64"),
    ("cf", "missing", "x86-64"),
    ("ea", "missing", "x86-64"),
    // D5 は 64 ビットでは予約（llvm は別命令に割当）。我々は拒否。
    ("d5", "*", "x86-64"),
    // movrs 系（新命令、A4 以降）。
    ("66 0f 38 8a", "missing", "x86-64"),
    ("66 0f 38 8b", "missing", "x86-64"),
    ("66 0f 38 f4", "missing", "x86-64"),
    ("f2 0f 38 8a", "missing", "x86-64"),
    ("f2 0f 38 8b", "missing", "x86-64"),
    ("f3 0f 38 8a", "missing", "x86-64"),
    ("f3 0f 38 8b", "missing", "x86-64"),
    ("f2 0f 38 f4", "missing", "x86-64"),
    ("f3 0f 38 f4", "missing", "x86-64"),
];

#[test]
fn oracle_llvm_decode_diff() {
    let Some(llvm_mc) = ["llvm-mc", "/usr/bin/llvm-mc", "/usr/local/bin/llvm-mc"]
        .iter()
        .find(|c| {
            Command::new(c)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(|s| s.to_string())
    else {
        eprintln!("llvm-mc がない。スキップ");
        return;
    };
    // 全機能を有効にして符号化の網羅率を上げる。モード（m64）は
    // FEAT ではなく modes で制御されるので含まれない。
    let all = FEAT_BITS.iter().fold(0u128, |a, (_, b)| a | b);
    // pop_cs は 0F の副表を潰すので両モードで外す。op82 は llvm が
    // i386 でも受理するので i386 では残し、x86-64（m64 非対応の
    // 別名）では外す。
    let f32 = all & !polyisa_guest_x86::FEAT_POP_CS;
    let f64 = f32 & !polyisa_guest_x86::FEAT_OP82;
    for (name, triple, modes, feats) in [
        ("i386", "i386", MODES32, f32),
        ("x86-64", "x86_64", MODES64, f64),
    ] {
        let d = run_pass(&llvm_mc, triple, modes, feats, name);
        let mut msg = String::new();
        for (label, v) in [
            ("missing", &d.missing),
            ("spurious", &d.spurious),
            ("len", &d.len),
            ("mnemonic", &d.mnemonic),
        ] {
            if !v.is_empty() {
                msg.push_str(&format!("\n{label} ({}):", v.len()));
                for x in v {
                    msg.push_str(&format!("\n  {x}"));
                }
            }
        }
        assert!(msg.is_empty(), "[{name}] oracle diff:{msg}");
    }
}
