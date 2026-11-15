//! Reading one input line without ever holding more than a stated number of bytes.
//!
//! Both adapters read requests line by line from a pipe they do not control. A peer
//! that never sends a newline must not be able to grow a buffer without bound, and a
//! line over the limit must be skipped to its end so the next request starts cleanly.
use std::io::{self, BufRead};

pub enum Line {
    /// End of input, with nothing pending.
    Eof,
    /// One line, with its newline when it had one. The last line of an input may have none.
    Text(Vec<u8>),
    /// A line longer than the limit. It has been consumed to its end.
    TooLong,
}

pub fn read_line(input: &mut impl BufRead, max_bytes: usize) -> io::Result<Line> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return Ok(if too_long {
                Line::TooLong
            } else if line.is_empty() {
                Line::Eof
            } else {
                Line::Text(line)
            });
        }
        let (take, found) = match buffer.iter().position(|b| *b == b'\n') {
            Some(position) => (position + 1, true),
            None => (buffer.len(), false),
        };
        if !too_long {
            if line.len() + take > max_bytes + 1 {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(&buffer[..take]);
            }
        }
        input.consume(take);
        if found {
            return Ok(if too_long {
                Line::TooLong
            } else {
                Line::Text(line)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1024 * 1024;

    fn lines(bytes: &[u8]) -> Vec<String> {
        let mut input = io::Cursor::new(bytes.to_vec());
        let mut found = Vec::new();
        loop {
            match read_line(&mut input, LIMIT).unwrap() {
                Line::Eof => return found,
                Line::TooLong => found.push("<too long>".to_owned()),
                Line::Text(text) => found.push(String::from_utf8(text).unwrap()),
            }
        }
    }

    #[test]
    fn lines_split_on_newline_and_the_last_may_lack_one() {
        assert_eq!(lines(b"a\nbc\nd"), ["a\n", "bc\n", "d"]);
        assert!(lines(b"").is_empty());
        assert_eq!(lines(b"\n"), ["\n"]);
    }

    #[test]
    fn a_line_over_the_limit_is_skipped_to_its_end_and_the_next_one_is_clean() {
        let mut input = vec![b'x'; LIMIT + 100];
        input.extend_from_slice(b"\nnext\n");
        assert_eq!(lines(&input), ["<too long>", "next\n"]);
    }

    #[test]
    fn a_line_of_exactly_the_limit_is_accepted() {
        let mut input = vec![b'x'; LIMIT];
        input.push(b'\n');
        let found = lines(&input);
        assert_eq!(found.len(), 1);
        assert_ne!(found[0], "<too long>");
    }

    #[test]
    fn an_over_long_last_line_without_a_newline_is_still_reported() {
        let input = vec![b'x'; LIMIT + 5];
        assert_eq!(lines(&input), ["<too long>"]);
    }

    #[test]
    fn the_limit_is_the_callers_not_a_constant() {
        let mut input = io::Cursor::new(b"abcdef\nxy\n".to_vec());
        assert!(matches!(read_line(&mut input, 3).unwrap(), Line::TooLong));
        assert!(matches!(read_line(&mut input, 3).unwrap(), Line::Text(t) if t == b"xy\n"));
    }
}
