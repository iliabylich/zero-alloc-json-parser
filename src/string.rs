use crate::{
    bytesize::Bytesize,
    mask::{STRING_MASK, TYPE_MASK},
    tlv::{BitmixToTLV, DecodeTLV},
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
    read_bytesize: usize,
    written_bytesize: usize,
}

fn rewrite_unescaped_json_string(data: &mut [u8], pos: usize) -> Option<UnescapingResult> {
    let mut write_to = pos + 1;
    let mut read_from = pos + 1;
    let read_bytesize;
    let written_bytesize;

    loop {
        if read_from >= data.len() {
            return None;
        }

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
        } else if data[read_from] == b'"' {
            data[write_to] = b'"';
            read_bytesize = read_from + 1 - pos;
            written_bytesize = write_to + 1 - pos;
            break;
        } else {
            data[write_to] = data[read_from];
            read_from += 1;
            write_to += 1;
        }
    }

    data.iter_mut()
        .skip(pos + written_bytesize)
        .take(read_bytesize - written_bytesize)
        .for_each(|byte| *byte = 0);

    data[pos + written_bytesize - 1] = b'"';

    Some(UnescapingResult {
        written_bytesize,
        read_bytesize,
    })
}

impl BitmixToTLV for String {
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()> {
        if data[*pos] != b'"' {
            return None;
        }
        let UnescapingResult {
            read_bytesize,
            written_bytesize,
        } = rewrite_unescaped_json_string(data, *pos)?;

        Bytesize::write(data, *pos, *pos + written_bytesize, written_bytesize - 2);
        data[*pos] |= STRING_MASK;

        *pos += read_bytesize;
        Some(())
    }
}

impl<'a> DecodeTLV<'a> for String {
    type ReturnType = &'a [u8];

    fn decode_tlv(data: &'a [u8], pos: &mut usize) -> Option<Self::ReturnType> {
        if *pos >= data.len() {
            return None;
        }
        if data[*pos] & TYPE_MASK != STRING_MASK {
            return None;
        }

        let Bytesize { bytesize, offset } = Bytesize::read(data, *pos);
        let bytes = &data[(*pos + offset)..(*pos + offset + bytesize)];
        *pos += bytesize + offset;
        Some(bytes)
    }
}

#[test]
fn test_string_empty() {
    let mut data = *b" \"\"";
    let mut pos = 1;
    String::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(data, [b' ', STRING_MASK | 0, 0]);

    pos = 1;
    let value = String::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 2);
    assert_eq!(value, b"");
}

#[test]
fn test_string_short() {
    let mut pos = 1;
    let mut data = *b" \"hello\"";
    String::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 8);
    assert_eq!(
        data,
        [b' ', STRING_MASK | 5, b'h', b'e', b'l', b'l', b'o', 0]
    );

    pos = 1;
    let value = String::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 7);
    assert_eq!(value, b"hello");
}

#[test]
fn test_string_long() {
    use crate::bytesize::LONG_CONTAINER_MASK;

    let mut pos = 1;
    let mut data = *b" \"abcdefghijklmnopqrstuvwxyz\"";
    String::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 29);
    assert_eq!(
        data,
        [
            b' ',
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

    pos = 1;
    let value = String::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 29);
    assert_eq!(value, b"abcdefghijklmnopqrstuvwxyz");
}

#[test]
fn test_escaped() {
    let mut pos = 1;
    let mut data = *br#" "a\nb\tc\u0064\\e""#;
    String::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 19);
    assert_eq!(
        data,
        [
            b' ',
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

    pos = 1;
    let value = String::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 10);
    assert_eq!(value, b"a\nb\tcd\\e");
}
