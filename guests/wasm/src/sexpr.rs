// Copyright (c) polyisa contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `.wast`/`.wat` の S 式の読み出し。字句と木だけを扱い、
//! wasm の意味には踏み込まない（それは `wat`/`wast` の仕事）。
//!
//! コメントは `;;` 行コメントと `(; ;)` ブロックコメント（入れ子可）。
//! 文字列は wasm テキストのエスケープ規則に従いバイト列として保持する。
//! Ref: SPEC-WASM-CORE 6（テキスト形式）、TEST-WASM-SPEC の wast 文法.

/// 一つの S 式。アトム・文字列・リスト。
#[derive(Clone, Debug)]
pub enum Sx {
    /// キーワード・識別子・数値などの裸の語。
    Atom(String),
    /// `"..."` の中身（エスケープ展開済みのバイト列）。
    Str(Vec<u8>),
    /// `( ... )`。
    List(Vec<Sx>),
}

impl Sx {
    /// リストなら中身を返す。
    #[must_use]
    pub fn list(&self) -> Option<&[Sx]> {
        match self {
            Self::List(v) => Some(v),
            _ => None,
        }
    }

    /// アトムなら語を返す。
    #[must_use]
    pub fn atom(&self) -> Option<&str> {
        match self {
            Self::Atom(s) => Some(s),
            _ => None,
        }
    }

    /// 文字列ならバイト列を返す。
    #[must_use]
    pub fn string(&self) -> Option<&[u8]> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// S 式の読み出しエラー（行・桁付き）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SxError {
    pub msg: String,
    pub line: u32,
    pub col: u32,
}

type R<T> = Result<T, SxError>;

/// トークンの区切り文字（空白・括弧・コメント開始）。
fn is_delim(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')' | b';')
}

/// 文字列中の位置。
struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a [u8]) -> Lexer<'a> {
        Lexer {
            src,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek2(&self) -> Option<u8> {
        self.src.get(self.pos + 1).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    fn err(&self, msg: &str) -> SxError {
        SxError {
            msg: msg.to_string(),
            line: self.line,
            col: self.col,
        }
    }

    /// 文字列や引用識別子の直後は区切り文字が必須
    /// （`"a"0` や `$"l"0` のような接合を拒否する）。
    fn check_delim(&mut self) -> R<()> {
        if let Some(b) = self.peek()
            && !is_delim(b)
        {
            return Err(self.err("unknown operator"));
        }
        Ok(())
    }

    /// 空白とコメントを読み飛ばす。
    fn skip_ws(&mut self) -> R<()> {
        loop {
            match (self.peek(), self.peek2()) {
                (Some(b' ' | b'\t' | b'\n' | b'\r'), _) => {
                    self.bump();
                }
                (Some(b';'), Some(b';')) => {
                    // 行コメントは `\n` または `\r` で終わる
                    // （comments.wast の `;;...\r(return ...)` 形）。
                    while let Some(b) = self.peek() {
                        if b == b'\n' || b == b'\r' {
                            break;
                        }
                        self.bump();
                    }
                }
                (Some(b'('), Some(b'@')) => {
                    // `(@id ...)` 注釈は空白と同じく読み捨てる。
                    self.skip_annotation()?;
                }
                (Some(b'('), Some(b';')) => {
                    self.bump();
                    self.bump();
                    let mut depth = 1u32;
                    while depth > 0 {
                        match (self.peek(), self.peek2()) {
                            (Some(b'('), Some(b';')) => {
                                self.bump();
                                self.bump();
                                depth += 1;
                            }
                            (Some(b';'), Some(b')')) => {
                                self.bump();
                                self.bump();
                                depth -= 1;
                            }
                            (Some(_), _) => {
                                self.bump();
                            }
                            (None, _) => return Err(self.err("unterminated block comment")),
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    /// 注釈内の 1 文字。制御文字と不正 UTF-8 を拒否する。
    /// 有効な UTF-8 でも ASCII 以外は注釈文字ではない。
    fn annot_char(&mut self) -> R<()> {
        let Some(b) = self.bump() else {
            return Err(self.err("unclosed annotation"));
        };
        if (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')) || b == 0x7f {
            return Err(self.err("illegal character"));
        }
        if b >= 0x80 {
            self.utf8_tail(b)?;
            return Err(self.err("illegal character"));
        }
        Ok(())
    }

    /// マルチバイト UTF-8 の後続バイトを検査する。先頭バイト `b` は読み済み。
    fn utf8_tail(&mut self, b: u8) -> R<()> {
        let need = match b {
            0xc2..=0xdf => 1,
            0xe0..=0xef => 2,
            0xf0..=0xf4 => 3,
            _ => return Err(self.err("malformed UTF-8 encoding")),
        };
        for _ in 0..need {
            match self.bump() {
                Some(c) if c & 0xc0 == 0x80 => {}
                _ => return Err(self.err("malformed UTF-8 encoding")),
            }
        }
        Ok(())
    }

    /// 注釈内の文字列（`"..."` または `@"..."` の ID 部）。
    /// エスケープを展開し、結果が UTF-8 でなければ malformed。
    fn annot_string(&mut self) -> R<Vec<u8>> {
        match self.string_lit() {
            Ok(s) => {
                if String::from_utf8(s.clone()).is_err() {
                    return Err(self.err("malformed UTF-8"));
                }
                Ok(s)
            }
            Err(e) if e.msg == "unterminated string" => Err(self.err("unclosed string")),
            Err(e) => Err(e),
        }
    }

    /// `(@id ...)` 注釈を読み捨てる。内部は文字列・入れ子の括弧・
    /// コメントを含められる。
    fn skip_annotation(&mut self) -> R<()> {
        self.bump(); // (
        self.bump(); // @
        // 注釈 ID（必須）: 引用文字列または区切りまでの文字。
        if self.peek() == Some(b'"') {
            let id = self.annot_string()?;
            if id.iter().all(|b| b.is_ascii_whitespace()) {
                return Err(self.err("empty annotation id"));
            }
        } else {
            let start = self.pos;
            loop {
                match self.peek() {
                    None => return Err(self.err("unclosed annotation")),
                    Some(b'"') | Some(b'(') | Some(b')') => break,
                    Some(b' ' | b'\t' | b'\n' | b'\r') => break,
                    Some(_) => self.annot_char()?,
                }
            }
            if self.pos == start {
                return Err(self.err("empty annotation id"));
            }
        }
        // 本体: 対応する `)` まで。入れ子の括弧・文字列・コメントを含められる。
        let mut depth = 1usize;
        loop {
            match (self.peek(), self.peek2()) {
                (None, _) => return Err(self.err("unclosed annotation")),
                (Some(b'('), Some(b';')) => {
                    // 注釈内のブロックコメント。
                    self.bump();
                    self.bump();
                    let mut d = 1u32;
                    while d > 0 {
                        match (self.peek(), self.peek2()) {
                            (Some(b'('), Some(b';')) => {
                                self.bump();
                                self.bump();
                                d += 1;
                            }
                            (Some(b';'), Some(b')')) => {
                                self.bump();
                                self.bump();
                                d -= 1;
                            }
                            (Some(_), _) => {
                                self.bump();
                            }
                            (None, _) => return Err(self.err("unclosed annotation")),
                        }
                    }
                }
                (Some(b';'), Some(b';')) => {
                    // 注釈内の行コメント。
                    while let Some(b) = self.peek() {
                        if b == b'\n' || b == b'\r' {
                            break;
                        }
                        self.bump();
                    }
                }
                (Some(b'('), _) => {
                    self.bump();
                    depth += 1;
                }
                (Some(b')'), _) => {
                    self.bump();
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                (Some(b'"'), _) => {
                    self.annot_string()?;
                }
                (Some(_), _) => self.annot_char()?,
            }
        }
    }

    /// 文字列リテラルをエスケープ展開して読む。
    fn string_lit(&mut self) -> R<Vec<u8>> {
        // 開き引用符。
        self.bump();
        let mut out = Vec::new();
        loop {
            let Some(b) = self.bump() else {
                return Err(self.err("unterminated string"));
            };
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(e) = self.bump() else {
                        return Err(self.err("unterminated escape"));
                    };
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'"' => out.push(b'"'),
                        b'\'' => out.push(b'\''),
                        b'\\' => out.push(b'\\'),
                        b'u' => {
                            // \u{...} 形式。
                            if self.bump() != Some(b'{') {
                                return Err(self.err("bad unicode escape"));
                            }
                            let mut v = 0u32;
                            let mut n = 0;
                            while let Some(c) = self.peek() {
                                if c == b'}' {
                                    break;
                                }
                                let d = (c as char).to_digit(16);
                                let Some(d) = d else {
                                    return Err(self.err("bad unicode escape"));
                                };
                                v = v * 16 + d;
                                n += 1;
                                self.bump();
                            }
                            if self.bump() != Some(b'}') || n == 0 {
                                return Err(self.err("bad unicode escape"));
                            }
                            let Some(ch) = char::from_u32(v) else {
                                // サロゲート・範囲外のコードポイント。
                                return Err(self.err("malformed UTF-8 codepoint"));
                            };
                            let mut tmp = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                        }
                        c if c.is_ascii_hexdigit() => {
                            // \xx 形式（2桁16進）。
                            let Some(e2) = self.bump() else {
                                return Err(self.err("unterminated escape"));
                            };
                            let Some(h2) = (e2 as char).to_digit(16) else {
                                return Err(self.err("bad hex escape"));
                            };
                            out.push(((c as char).to_digit(16).unwrap() * 16 + h2) as u8);
                        }
                        _ => return Err(self.err("bad escape")),
                    }
                }
                _ => out.push(b),
            }
        }
    }

    /// `$"..."` の引用識別子。エスケープを展開し、先頭の `$` を
    /// 付けてアトムとして返す。制御文字の直書きは `empty identifier`、
    /// 展開後が UTF-8 でなければ `malformed UTF-8`。
    fn quoted_ident(&mut self) -> R<String> {
        // 開き引用符。
        self.bump();
        let mut out = Vec::new();
        loop {
            let Some(b) = self.bump() else {
                return Err(self.err("unterminated string"));
            };
            match b {
                b'"' => break,
                b'\\' => {
                    let Some(e) = self.bump() else {
                        return Err(self.err("empty identifier"));
                    };
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'"' => out.push(b'"'),
                        b'\'' => out.push(b'\''),
                        b'\\' => out.push(b'\\'),
                        b'u' => {
                            if self.bump() != Some(b'{') {
                                return Err(self.err("empty identifier"));
                            }
                            let mut v = 0u32;
                            let mut n = 0;
                            while let Some(c) = self.peek() {
                                if c == b'}' {
                                    break;
                                }
                                let Some(d) = (c as char).to_digit(16) else {
                                    return Err(self.err("empty identifier"));
                                };
                                v = v * 16 + d;
                                n += 1;
                                self.bump();
                            }
                            if self.bump() != Some(b'}') || n == 0 {
                                return Err(self.err("empty identifier"));
                            }
                            let Some(ch) = char::from_u32(v) else {
                                return Err(self.err("malformed UTF-8"));
                            };
                            let mut tmp = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                        }
                        c if c.is_ascii_hexdigit() => {
                            let Some(e2) = self.bump() else {
                                return Err(self.err("empty identifier"));
                            };
                            let Some(h2) = (e2 as char).to_digit(16) else {
                                return Err(self.err("empty identifier"));
                            };
                            out.push(((c as char).to_digit(16).unwrap() * 16 + h2) as u8);
                        }
                        _ => return Err(self.err("empty identifier")),
                    }
                }
                // 識別子の中に制御文字の直書きは不可。
                0x00..=0x1f | 0x7f => return Err(self.err("empty identifier")),
                _ => out.push(b),
            }
        }
        if out.is_empty() {
            return Err(self.err("empty identifier"));
        }
        match String::from_utf8(out) {
            Ok(s) => Ok(format!("${s}")),
            Err(_) => Err(self.err("malformed UTF-8")),
        }
    }

    /// アトム（区切りまでの裸の語）を読む。
    fn atom(&mut self) -> String {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')' | b'"')
                || (b == b';' && self.peek2() == Some(b';'))
            {
                break;
            }
            // `(;` はアトムの中でもブロックコメント開始にはならない。
            // `;` 単体はアトムに含める（`;` で終わる語はない）。
            self.bump();
        }
        String::from_utf8_lossy(&self.src[start..self.pos]).into_owned()
    }

    fn sexpr(&mut self) -> R<Sx> {
        self.skip_ws()?;
        match self.peek() {
            None => Err(self.err("unexpected end")),
            Some(b'(') => {
                self.bump();
                let mut items = Vec::new();
                loop {
                    self.skip_ws()?;
                    match self.peek() {
                        None => return Err(self.err("unterminated list")),
                        Some(b')') => {
                            self.bump();
                            return Ok(Sx::List(items));
                        }
                        _ => items.push(self.sexpr()?),
                    }
                }
            }
            Some(b')') => Err(self.err("unexpected token")),
            Some(b'"') => {
                // 文字列は区切り文字（空白・括弧・コメント）の直後のみ
                // 現れ得る。`data"a"` のような接合は不正トークン。
                if self.pos > 0 && !is_delim(self.src[self.pos - 1]) {
                    return Err(self.err("unknown operator"));
                }
                let s = self.string_lit()?;
                self.check_delim()?;
                Ok(Sx::Str(s))
            }
            Some(_) => {
                // 区切り文字以外は必ず 1 字以上読む。空アトムは
                // 無限ループの元なので拒否する。
                let a = self.atom();
                if a.is_empty() {
                    return Err(self.err("unexpected token"));
                }
                if a == "$" {
                    // `$"..."` は引用識別子、裸の `$` は empty identifier。
                    if self.peek() == Some(b'"') {
                        let id = self.quoted_ident()?;
                        self.check_delim()?;
                        return Ok(Sx::Atom(id));
                    }
                    return Err(self.err("empty identifier"));
                }
                Ok(Sx::Atom(a))
            }
        }
    }
}

/// ソース全体を S 式の列として読む。`assert_*` や `module` が並ぶ形。
pub fn parse_all(src: &str) -> R<Vec<Sx>> {
    let mut lx = Lexer::new(src.as_bytes());
    let mut out = Vec::new();
    loop {
        lx.skip_ws()?;
        if lx.peek().is_none() {
            return Ok(out);
        }
        out.push(lx.sexpr()?);
    }
}

/// 単一の S 式を読む（`module quote` の中身など）。
pub fn parse_one(src: &str) -> R<Sx> {
    let mut lx = Lexer::new(src.as_bytes());
    let sx = lx.sexpr()?;
    lx.skip_ws()?;
    if lx.peek().is_some() {
        return Err(lx.err("unexpected token"));
    }
    Ok(sx)
}
