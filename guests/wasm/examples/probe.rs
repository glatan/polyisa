use polyisa_guest_wasm::wast::Runner;

/// .wast ファイル（または単一ディレクティブ文字列）を1つの Runner で順に走らせ、
/// ディレクティブごとの結果を出す。
fn main() {
    let mut r = Runner::new();
    for s in std::env::args().skip(1) {
        let src = std::fs::read_to_string(&s).unwrap_or(s);
        // トップレベル S 式に分割（コメントと文字列を考慮）。
        let b = src.as_bytes();
        let mut depth = 0i32;
        let mut start = None;
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'(' if i + 1 < b.len() && b[i + 1] == b';' => {
                    // ブロックコメント（入れ子可）は depth に影響しない。
                    let mut n = 1;
                    i += 2;
                    while i < b.len() && n > 0 {
                        if i + 1 < b.len() && b[i] == b'(' && b[i + 1] == b';' {
                            n += 1;
                            i += 2;
                        } else if i + 1 < b.len() && b[i] == b';' && b[i + 1] == b')' {
                            n -= 1;
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                }
                b'(' => {
                    if depth == 0 {
                        start = Some(i);
                    }
                    depth += 1;
                    i += 1;
                }
                b')' => {
                    depth -= 1;
                    i += 1;
                    if depth == 0
                        && let Some(s0) = start.take()
                    {
                        let d = &src[s0..i];
                        let st = r.run_str(d);
                        let head = d.lines().next().unwrap_or("").trim();
                        println!(
                            "{:>5}: pass={} fail={} skip={}  {}",
                            s0, st.passed, st.failed, st.skipped, head
                        );
                        for f in &st.failures {
                            println!("   !! {f}");
                        }
                    }
                }
                b';' if i + 1 < b.len() && b[i + 1] == b';' => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'"' => {
                    i += 1;
                    while i < b.len() && b[i] != b'"' {
                        if b[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                    i += 1;
                }
                _ => i += 1,
            }
        }
    }
}
