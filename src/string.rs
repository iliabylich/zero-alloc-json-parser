use crate::{
    mask::STRING_MASK,
    tlv::{DecodeTLV, RewriteToTLV},
};

// We have 5 bytes after the initial mask, 0b11111 is the max value for 5 bits
//   1 in a leading bit indicates a two-byte length,
//   0 means a single byte length (i.e. out string is VERY short, max 0b1111 = 15 bytes)
// If the string is longer than 15 bytes, we need to shift it to the right
// and use one extra byte to store the length of the string
const MAX_EMBEDDED_LENGTH: usize = 15;
const LONG_STRING_MASK: u8 = 0b10000;

pub(crate) struct String;

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid escape sequence"),
    }
}

impl RewriteToTLV for String {
    type ExtraPayload = ();
    type ReturnType = ();

    fn rewrite_to_tlv(data: &mut [u8], start: usize, mut end: usize, _: ()) {
        let mut write_to = start + 1;
        let mut read_from = start + 1;

        while read_from < end - 1 {
            if data[read_from] == b'\\' {
                match data[read_from + 1] {
                    b'n' => {
                        data[write_to] = b'\n';
                        write_to += 1;
                        read_from += 2;
                    }
                    b't' => {
                        data[write_to] = b'\t';
                        write_to += 1;
                        read_from += 2;
                    }
                    b'\\' => {
                        data[write_to] = b'\\';
                        write_to += 1;
                        read_from += 2;
                    }
                    b'u' => {
                        let byte1 = unhex(data[read_from + 2]);
                        let byte2 = unhex(data[read_from + 3]);
                        let byte3 = unhex(data[read_from + 4]);
                        let byte4 = unhex(data[read_from + 5]);
                        let as_u32 = (byte1 as u32) << 12
                            | (byte2 as u32) << 8
                            | (byte3 as u32) << 4
                            | byte4 as u32;
                        let as_char = char::from_u32(as_u32).unwrap();
                        as_char.encode_utf8(&mut data[write_to..]);
                        write_to += as_char.len_utf8();
                        read_from += 6;
                    }
                    other => panic!(
                        "only \\n, \\t, \\\\, and \\uXXXX are supported, got: \\{}",
                        other as char
                    ),
                }
            } else {
                data[write_to] = data[read_from];
                read_from += 1;
                write_to += 1;
            }
        }
        write_to += 1; // track closing quote

        for byte in data.iter_mut().skip(write_to).take(end - write_to) {
            *byte = 0;
        }
        end = write_to;
        data[end - 1] = b'"';

        // now we have a compact unescaped string with trailing zeroes
        // like "foobar"0000
        //      ^ start
        //              ^ end

        let mut length = end - start - 2;
        if length > 2048 {
            panic!("string is too long, max 2048 bytes allowed")
        }

        if length <= MAX_EMBEDDED_LENGTH {
            data[start] = STRING_MASK | length as u8;
            data[end - 1] = 0;
        } else {
            // long string, needs shifting
            let three_bytes_of_length = (length % 8) as u8;
            length >>= 3;
            data[start] = STRING_MASK | LONG_STRING_MASK | three_bytes_of_length;
            for idx in ((start + 1)..(end - 1)).rev() {
                data[idx + 1] = data[idx];
            }
            data[start + 1] = length as u8;
        }
    }
}

impl<'a> DecodeTLV<'a> for String {
    type ReturnType = Option<&'a [u8]>;

    fn decode_tlv(data: &'a [u8]) -> Self::ReturnType {
        if data[0] & STRING_MASK != STRING_MASK {
            return None;
        }

        let l1 = data[0] & 0b1111;
        let mut l2 = 0;
        let mut offset = 1;
        if data[0] & LONG_STRING_MASK == LONG_STRING_MASK {
            l2 = data[1];
            offset = 2;
        }
        let length = (l2 as usize) << 3 | l1 as usize;
        Some(&data[offset..(offset + length)])
    }
}

#[test]
fn test_string_short() {
    let mut data = *b"\"hello\"";
    String::rewrite_to_tlv(&mut data, 0, 7, ());
    assert_eq!(data, [STRING_MASK | 5, b'h', b'e', b'l', b'l', b'o', 0]);
    let decoded = String::decode_tlv(&data).unwrap();
    assert_eq!(decoded, b"hello");
}

#[test]
fn test_string_long() {
    let mut data = *b"\"abcdefghijklmnopqrstuvwxyz\"";
    String::rewrite_to_tlv(&mut data, 0, 28, ());
    assert_eq!(
        data,
        [
            // length is 26 = 0b11010
            STRING_MASK | LONG_STRING_MASK | 0b010, // 3 trailing bits of length
            0b11,                                   // the rest of the length
            b'a',
            b'b',
            b'c',
            b'd',
            b'e',
            b'f',
            b'g',
            b'h',
            b'i',
            b'j',
            b'k',
            b'l',
            b'm',
            b'n',
            b'o',
            b'p',
            b'q',
            b'r',
            b's',
            b't',
            b'u',
            b'v',
            b'w',
            b'x',
            b'y',
            b'z',
        ]
    );
    let decoded = String::decode_tlv(&data).unwrap();
    assert_eq!(decoded, b"abcdefghijklmnopqrstuvwxyz");
}

#[test]
fn test_escaped() {
    let mut data = *br#""a\nb\tc\u0064\\e"#;
    String::rewrite_to_tlv(&mut data, 0, 18, ());
    assert_eq!(
        data,
        [
            STRING_MASK | 8,
            b'a',
            b'\n',
            b'b',
            b'\t',
            b'c',
            b'd',
            b'\\',
            b'e',
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    );
    let decoded = String::decode_tlv(&data).unwrap();
    assert_eq!(decoded, b"a\nb\tcd\\e");
}
