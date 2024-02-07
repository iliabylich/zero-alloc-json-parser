use crate::{
    bytesize::Bytesize,
    mask::{OBJECT_MASK, TYPE_MASK},
    string::String,
    tlv::{BitmixToTLV, DecodeTLV},
    value::Value,
    ws::scan_ws,
};

#[derive(Debug)]
pub struct Object<'a> {
    pub(crate) data: &'a [u8],
}

#[derive(Debug)]
enum State {
    Key,
    Value,
    Colon,
    CommaOrEnd,
}

impl BitmixToTLV for Object<'_> {
    type ReturnType = ();

    fn bitmix_to_tlv(data: &mut [u8]) -> Option<(Self::ReturnType, usize)> {
        if data[0] != b'{' {
            return None;
        }
        let mut region_size = 1;
        let mut found_end = false;
        let mut state = State::Key;
        let mut seen_comma = false;

        while region_size < data.len() {
            if let Some(skip_len) = scan_ws(&mut data[region_size..]) {
                region_size += skip_len;
            }

            match state {
                State::Key => {
                    if let Some((_, len)) = String::bitmix_to_tlv(&mut data[region_size..]) {
                        state = State::Colon;
                        region_size += len;
                    } else if seen_comma {
                        // parse error
                        return None;
                    } else {
                        // empty object
                        state = State::CommaOrEnd;
                        continue;
                    }
                }
                State::Value => {
                    if let Some((_, len)) = Value::bitmix_to_tlv(&mut data[region_size..]) {
                        state = State::CommaOrEnd;
                        region_size += len;
                    } else {
                        return None;
                    }
                }
                State::Colon => {
                    if data[region_size] == b':' {
                        state = State::Value;
                        data[region_size] = 0;
                        region_size += 1;
                    } else {
                        return None;
                    }
                }
                State::CommaOrEnd => {
                    if data[region_size] == b'}' {
                        found_end = true;
                        break;
                    } else if data[region_size] == b',' {
                        state = State::Key;
                        data[region_size] = 0;
                        region_size += 1;
                        seen_comma = true;
                    } else {
                        return None;
                    }
                }
            }
        }
        if !found_end {
            return None;
        }
        region_size += 1;

        data[0] = 0;
        data[region_size - 1] = 0;

        Bytesize::write(&mut data[..region_size], region_size - 2);
        data[0] |= OBJECT_MASK;

        Some(((), region_size))
    }
}

impl<'a> DecodeTLV<'a> for Object<'a> {
    type ReturnType = Self;

    fn decode_tlv(data: &'a [u8]) -> Option<(Self::ReturnType, usize)> {
        if data.is_empty() {
            return None;
        }
        if data[0] & TYPE_MASK != OBJECT_MASK {
            return None;
        }

        let Bytesize { bytesize, offset } = Bytesize::read(data);
        let object = Object {
            data: &data[offset..(offset + bytesize)],
        };
        Some((object, bytesize + offset))
    }
}

#[test]
fn test_object_empty() {
    let mut data = *b"{}";
    let ((), rewritten) = Object::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(rewritten, 2);
    assert_eq!(data, [OBJECT_MASK | 0, 0]);
}

#[test]
fn test_object_small() {
    use crate::mask::STRING_MASK;

    let mut data = *br#"{"a": 1, "b": 2}"#;
    let ((), rewritten) = Object::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(rewritten, 16);
    assert_eq!(
        data,
        [
            // size is 14 = 0b1110
            OBJECT_MASK | 14,
            STRING_MASK | 1,
            b'a',
            0,
            0,
            0,
            0b001_00001,
            0,
            0,
            STRING_MASK | 1,
            b'b',
            0,
            0,
            0,
            0b001_00010,
            0
        ]
    );
}
