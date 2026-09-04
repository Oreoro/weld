use super::ir::Diagnostic;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Word(String),
    Str(String),
    Int(i64),
    Newline,
    Eof,
    LParen,
    RParen,
    Comma,
    Tilde,
    Arrow,
    Assign,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token::Word(s) => write!(f, "'{}'", s),
            Token::Str(s) => write!(f, "\"{}\"", s),
            Token::Int(n) => write!(f, "{}", n),
            Token::Newline => write!(f, "end of line"),
            Token::Eof => write!(f, "end of file"),
            Token::LParen => write!(f, "'('"),
            Token::RParen => write!(f, "')'"),
            Token::Comma => write!(f, "','"),
            Token::Tilde => write!(f, "'~'"),
            Token::Arrow => write!(f, "'~>'"),
            Token::Assign => write!(f, "'='"),
            Token::Eq => write!(f, "'=='"),
            Token::Ne => write!(f, "'!='"),
            Token::Lt => write!(f, "'<'"),
            Token::Gt => write!(f, "'>'"),
            Token::Le => write!(f, "'<='"),
            Token::Ge => write!(f, "'>='"),
        }
    }
}

pub fn lex(src: &str) -> Result<Vec<(usize, Token)>, Diagnostic> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;

    while i < b.len() {
        let c = b[i] as char;
        match c {
            '\n' => {
                out.push((line, Token::Newline));
                line += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' => i += 1,
            '#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            '"' => {
                let start_line = line;
                let start_col = i + 1;
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= b.len() {
                        return Err(Diagnostic {
                            line: start_line,
                            col: start_col,
                            message: "unterminated string literal".into(),
                            hint: Some("add a closing '\"'".into()),
                        });
                    }
                    if b[i] == b'"' {
                        i += 1;
                        break;
                    }
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 1;
                        s.push(match b[i] as char {
                            'n' => '\n',
                            't' => '\t',
                            '"' => '"',
                            '\\' => '\\',
                            other => other,
                        });
                    } else {
                        s.push(b[i] as char);
                    }
                    i += 1;
                }
                out.push((start_line, Token::Str(s)));
            }
            '~' => {
                if i + 1 < b.len() && b[i + 1] == b'>' {
                    out.push((line, Token::Arrow));
                    i += 2;
                } else if i + 1 < b.len()
                    && (b[i + 1] == b'/' || (b[i + 1] as char).is_alphanumeric())
                {
                    // Path pattern starting with ~ (e.g. ~/dev/{a,b}/**):
                    // scan as one word, brace-aware like the main word arm.
                    let start = i;
                    i += 1;
                    let mut braces = 0usize;
                    while i < b.len() {
                        let ch = b[i] as char;
                        if ch == '{' {
                            braces += 1;
                        } else if ch == '}' {
                            if braces == 0 {
                                break;
                            }
                            braces -= 1;
                        } else if braces == 0 && !is_word_char(ch) {
                            break;
                        }
                        i += 1;
                    }
                    let word = String::from_utf8_lossy(&b[start..i]).into_owned();
                    out.push((line, Token::Word(word)));
                } else {
                    out.push((line, Token::Tilde));
                    i += 1;
                }
            }
            '=' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push((line, Token::Eq));
                i += 2;
            }
            '=' => {
                out.push((line, Token::Assign));
                i += 1;
            }
            '!' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push((line, Token::Ne));
                i += 2;
            }
            '<' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push((line, Token::Le));
                i += 2;
            }
            '>' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push((line, Token::Ge));
                i += 2;
            }
            '<' => {
                out.push((line, Token::Lt));
                i += 1;
            }
            '>' => {
                out.push((line, Token::Gt));
                i += 1;
            }
            '(' => {
                out.push((line, Token::LParen));
                i += 1;
            }
            ')' => {
                out.push((line, Token::RParen));
                i += 1;
            }
            ',' => {
                out.push((line, Token::Comma));
                i += 1;
            }
            '0'..='9' => {
                let start = i;
                while i < b.len() && is_word_char(b[i] as char) {
                    i += 1;
                }
                let text = std::str::from_utf8(&b[start..i]).unwrap_or("0");
                if let Ok(n) = text.parse::<i64>() {
                    out.push((line, Token::Int(n)));
                } else {
                    // Not a pure integer (e.g. versioned id or dotted host
                    // like 127.0.0.1) — treat as a word token instead.
                    out.push((line, Token::Word(text.to_string())));
                }
            }
            _ if is_word_start(c) => {
                let start = i;
                let mut braces = 0usize;
                while i < b.len() {
                    let ch = b[i] as char;
                    if ch == '{' {
                        braces += 1;
                    } else if ch == '}' {
                        if braces == 0 {
                            break;
                        }
                        braces -= 1;
                    } else if braces == 0 && !is_word_char(ch) {
                        break;
                    }
                    i += 1;
                }
                let word = String::from_utf8_lossy(&b[start..i]).into_owned();
                out.push((line, Token::Word(word)));
            }
            other => {
                return Err(Diagnostic {
                    line,
                    col: i + 1,
                    message: format!("unexpected character '{}'", other),
                    hint: None,
                })
            }
        }
    }
    out.push((line, Token::Eof));
    Ok(out)
}

fn is_word_start(c: char) -> bool {
    c.is_alphanumeric() || "_-.*~/{$".contains(c)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || "_-.*{/}$!".contains(c)
}
