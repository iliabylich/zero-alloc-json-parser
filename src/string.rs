use crate::{
    bytesize::Bytesize,
    mask::{STRING_MASK, TYPE_MASK},
    tlv::{BitmixToTLV, DecodeTLV, DecodingResult},
};

pub(crate) struct String;

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid escape sequence"),
    }
}

struct UnescapingResult {
    bytes_processed: usize,
    bytes_written: usize,
}

fn rewrite_unescaped_json_string(data: &mut [u8]) -> Option<UnescapingResult> {
    let mut write_to = 1;
    let mut pos = 1;
    let unescaped_bytesize;

    loop {
        if pos >= data.len() {
            return None;
        }

        if data[pos] == b'\\' {
            match data[pos + 1] {
                b'n' => {
                    data[write_to] = b'\n';
                    write_to += 1;
                    pos += 2;
                }
                b't' => {
                    data[write_to] = b'\t';
                    write_to += 1;
                    pos += 2;
                }
                b'\\' => {
                    data[write_to] = b'\\';
                    write_to += 1;
                    pos += 2;
                }
                b'u' => {
                    let byte1 = unhex(data[pos + 2]);
                    let byte2 = unhex(data[pos + 3]);
                    let byte3 = unhex(data[pos + 4]);
                    let byte4 = unhex(data[pos + 5]);
                    let as_u32 = (byte1 as u32) << 12
                        | (byte2 as u32) << 8
                        | (byte3 as u32) << 4
                        | byte4 as u32;
                    let as_char = char::from_u32(as_u32).unwrap();
                    as_char.encode_utf8(&mut data[write_to..]);
                    write_to += as_char.len_utf8();
                    pos += 6;
                }
                other => panic!(
                    "only \\n, \\t, \\\\, and \\uXXXX are supported, got: \\{}",
                    other as char
                ),
            }
        } else if data[pos] == b'"' {
            data[write_to] = b'"';
            write_to += 1;
            unescaped_bytesize = pos + 1;
            break;
        } else {
            data[write_to] = data[pos];
            pos += 1;
            write_to += 1;
        }
    }

    data.iter_mut()
        .skip(write_to)
        .take(unescaped_bytesize - write_to)
        .for_each(|byte| *byte = 0);

    let new_bytesize = write_to;
    data[new_bytesize - 1] = b'"';

    Some(UnescapingResult {
        bytes_processed: unescaped_bytesize,
        bytes_written: new_bytesize,
    })
}

impl BitmixToTLV for String {
    fn bitmix_to_tlv(data: &mut [u8]) -> Option<usize> {
        if data[0] != b'"' {
            return None;
        }
        let UnescapingResult {
            bytes_processed,
            bytes_written,
        } = rewrite_unescaped_json_string(data)?;

        Bytesize::write(&mut data[..bytes_written], bytes_written - 2);
        data[0] |= STRING_MASK;

        Some(bytes_processed)
    }
}

impl<'a> DecodeTLV<'a> for String {
    type ReturnType = &'a [u8];

    fn decode_tlv(data: &'a [u8]) -> Option<DecodingResult<Self::ReturnType>> {
        if data.is_empty() {
            return None;
        }
        if data[0] & TYPE_MASK != STRING_MASK {
            return None;
        }

        let Bytesize { bytesize, offset } = Bytesize::read(data);
        let bytes = &data[offset..(offset + bytesize)];
        Some(DecodingResult {
            value: bytes,
            size: bytesize + offset,
        })
    }
}

#[test]
fn test_string_empty() {
    let mut data = *b"\"\"";
    let rewritten = String::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [STRING_MASK | 0, 0]);
    assert_eq!(rewritten, 2);

    let DecodingResult { value, size } = String::decode_tlv(&data).unwrap();
    assert_eq!(value, b"");
    assert_eq!(size, 1);
}

#[test]
fn test_string_short() {
    let mut data = *b"\"hello\"";
    let rewritten = String::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [STRING_MASK | 5, b'h', b'e', b'l', b'l', b'o', 0]);
    assert_eq!(rewritten, 7);

    let DecodingResult { value, size } = String::decode_tlv(&data).unwrap();
    assert_eq!(value, b"hello");
    assert_eq!(size, 6);
}

#[test]
fn test_string_long() {
    use crate::bytesize::LONG_CONTAINER_MASK;

    let mut data = *b"\"abcdefghijklmnopqrstuvwxyz\"";
    let rewritten = String::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(
        data,
        [
            // length is 26 = 0b11010
            STRING_MASK | LONG_CONTAINER_MASK | 0b010, // 3 trailing bits of length
            0b11,                                      // the rest of the length
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
    assert_eq!(rewritten, 28);

    let DecodingResult { value, size } = String::decode_tlv(&data).unwrap();
    assert_eq!(value, b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(size, 28);
}

#[test]
fn test_escaped() {
    let mut data = *br#""a\nb\tc\u0064\\e""#;
    let rewritten = String::bitmix_to_tlv(&mut data).unwrap();
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
            0,
        ]
    );
    assert_eq!(rewritten, 18);

    let DecodingResult { value, size } = String::decode_tlv(&data).unwrap();
    assert_eq!(value, b"a\nb\tcd\\e");
    assert_eq!(size, 9);
}
