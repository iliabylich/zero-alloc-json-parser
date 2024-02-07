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

impl BitmixToTLV for String {
    type ExtraPayload = ();
    type ReturnType = ();

    fn bitmix_to_tlv(data: &mut [u8], _: ()) -> Option<(Self::ReturnType, usize)> {
        if data[0] != b'"' {
            return None;
        }
        let mut region_size = 1;
        let mut found_end = false;
        while region_size < data.len() {
            if data[region_size] == b'"' {
                found_end = true;
                break;
            } else {
                region_size += 1;
            }
        }
        if !found_end {
            return None;
        }
        region_size += 1;

        let mut write_to = 1;
        let mut read_from = 1;
        while read_from < region_size {
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

        for byte in data.iter_mut().skip(write_to).take(region_size - write_to) {
            *byte = 0;
        }
        let end = write_to;
        data[end - 1] = b'"';

        Bytesize::write(&mut data[..end], end - 2);
        data[0] |= STRING_MASK;

        Some(((), region_size))
    }
}

impl<'a> DecodeTLV<'a> for String {
    type ReturnType = &'a [u8];

    fn decode_tlv(data: &'a [u8]) -> Option<(Self::ReturnType, usize)> {
        if data.is_empty() {
            return None;
        }
        if data[0] & TYPE_MASK != STRING_MASK {
            return None;
        }

        let Bytesize { bytesize, offset } = Bytesize::read(data);
        let bytes = &data[offset..(offset + bytesize)];
        Some((bytes, bytesize + offset))
    }
}

#[test]
fn test_string_empty() {
    let mut data = *b"\"\"";
    let (_, rewritten) = String::bitmix_to_tlv(&mut data, ()).unwrap();
    assert_eq!(data, [STRING_MASK | 0, 0]);
    assert_eq!(rewritten, 2);

    let (decoded, read) = String::decode_tlv(&data).unwrap();
    assert_eq!(decoded, b"");
    assert_eq!(read, 1);
}

#[test]
fn test_string_short() {
    let mut data = *b"\"hello\"";
    let (_, rewritten) = String::bitmix_to_tlv(&mut data, ()).unwrap();
    assert_eq!(data, [STRING_MASK | 5, b'h', b'e', b'l', b'l', b'o', 0]);
    assert_eq!(rewritten, 7);

    let (decoded, read) = String::decode_tlv(&data).unwrap();
    assert_eq!(decoded, b"hello");
    assert_eq!(read, 6);
}

#[test]
fn test_string_long() {
    use crate::bytesize::LONG_CONTAINER_MASK;

    let mut data = *b"\"abcdefghijklmnopqrstuvwxyz\"";
    let (_, rewritten) = String::bitmix_to_tlv(&mut data, ()).unwrap();
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

    let (decoded, read) = String::decode_tlv(&data).unwrap();
    assert_eq!(decoded, b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(read, 28);
}

#[test]
fn test_escaped() {
    let mut data = *br#""a\nb\tc\u0064\\e""#;
    let (_, rewritten) = String::bitmix_to_tlv(&mut data, ()).unwrap();
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

    let (decoded, read) = String::decode_tlv(&data).unwrap();
    assert_eq!(decoded, b"a\nb\tcd\\e");
    assert_eq!(read, 9);
}
