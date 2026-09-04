//! Lexer tests: token shapes, path patterns, trace arrows, error paths.

use weld_lang::lexer::{lex, Token};

fn toks(src: &str) -> Vec<Token> {
    lex(src).unwrap().into_iter().map(|(_, t)| t).collect()
}

#[test]
fn lexes_words_strings_and_ints() {
    let t = toks("set foo = \"bar\" 42");
    assert_eq!(
        t,
        vec![
            Token::Word("set".into()),
            Token::Word("foo".into()),
            Token::Assign,
            Token::Str("bar".into()),
            Token::Int(42),
            Token::Eof,
        ]
    );
}

#[test]
fn lexes_trace_arrow_vs_match_tilde() {
    let t = toks("deny a ~> b");
    assert_eq!(
        t,
        vec![
            Token::Word("deny".into()),
            Token::Word("a".into()),
            Token::Arrow,
            Token::Word("b".into()),
            Token::Eof,
        ]
    );
    let t = toks("deny exec(c) if c ~ \"rm *\"");
    assert!(t.iter().any(|t| matches!(t, Token::Tilde)));
}

#[test]
fn lexes_path_pattern_with_braces() {
    // `~` followed by `/` scans as one word token (path pattern).
    let t = toks("set p = ~/dev/{a,b}/**");
    assert_eq!(
        t,
        vec![
            Token::Word("set".into()),
            Token::Word("p".into()),
            Token::Assign,
            Token::Word("~/dev/{a,b}/**".into()),
            Token::Eof,
        ]
    );
}

#[test]
fn lexes_comparison_operators() {
    let t = toks("== != < > <= >=");
    assert_eq!(
        t,
        vec![
            Token::Eq,
            Token::Ne,
            Token::Lt,
            Token::Gt,
            Token::Le,
            Token::Ge,
            Token::Eof,
        ]
    );
}

#[test]
fn dotted_numbers_are_words_not_ints() {
    // 127.0.0.1 must lex as a Word, not Int (regression test).
    let t = toks("set hosts = 127.0.0.1");
    assert_eq!(
        t,
        vec![
            Token::Word("set".into()),
            Token::Word("hosts".into()),
            Token::Assign,
            Token::Word("127.0.0.1".into()),
            Token::Eof,
        ]
    );
}

#[test]
fn comments_and_blank_lines_are_skipped() {
    // Comments produce no tokens; blank lines still produce Newline tokens
    // (which the parser skips).
    let t = toks("# a comment\n\nset x = y  # trailing\n");
    assert_eq!(
        t,
        vec![
            Token::Newline,
            Token::Newline,
            Token::Word("set".into()),
            Token::Word("x".into()),
            Token::Assign,
            Token::Word("y".into()),
            Token::Newline,
            Token::Eof,
        ]
    );
}

#[test]
fn string_escapes() {
    let t = toks(r#"deny a if c ~ "a\"b\\c""#);
    assert!(t.contains(&Token::Str("a\"b\\c".into())));
}

#[test]
fn unterminated_string_is_error() {
    let d = lex("deny a if c ~ \"oops").unwrap_err();
    assert!(d.message.contains("unterminated string"));
}

#[test]
fn unexpected_char_reports_line() {
    let d = lex("set x = y\n@").unwrap_err();
    assert_eq!(d.line, 2);
    assert!(d.message.contains("unexpected character"));
}
