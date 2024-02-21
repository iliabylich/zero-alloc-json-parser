use crate::{
    length::Length,
    mask::{OBJECT_MASK, TYPE_MASK},
    skip_zeroes::skip_zeroes,
    string::String,
    tlv::{bitmix_consume_byte, BitmixToTLV, DecodeTLV},
    value::Value,
    ws::skip_ws,
};

#[derive(Debug)]
pub struct Object<'a> {
    pub(crate) data: &'a [u8],
}

fn bitmix_pair(data: &mut [u8], pos: &mut usize) -> Option<()> {
    // key
    String::bitmix_to_tlv(data, pos)?;
    skip_ws(data, pos);

    // ":"
    if !bitmix_consume_byte::<b':'>(data, pos) {
        return None;
    }

    // value
    skip_ws(data, pos);
    Value::bitmix_to_tlv(data, pos)?;

    Some(())
}

fn bitmix_pair_list_and_close(data: &mut [u8], pos: &mut usize, length: &mut usize) -> Option<()> {
    skip_ws(data, pos);

    if bitmix_consume_byte::<b'}'>(data, pos) {
        // empty object
        return Some(());
    }

    bitmix_pair(data, pos)?;
    *length += 1;

    while *pos < data.len() {
        skip_ws(data, pos);

        if bitmix_consume_byte::<b'}'>(data, pos) {
            return Some(());
        } else if data[*pos] == b',' {
            data[*pos] = 0;
            *pos += 1;
            skip_ws(data, pos);

            bitmix_pair(data, pos)?;
            *length += 1;
        }
    }

    None
}

impl BitmixToTLV for Object<'_> {
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()> {
        if data[*pos] != b'{' {
            return None;
        }
        let start = *pos;
        let mut length = 0;
        *pos += 1;
        skip_ws(data, pos);

        if !bitmix_consume_byte::<b'}'>(data, pos) {
            bitmix_pair_list_and_close(data, pos, &mut length)?;
        }

        data[start] = 0;
        data[*pos - 1] = 0;

        Length::write(data, start, *pos, length);
        // Bytesize::write(data, start, *pos, *pos - start - 2);
        data[start] |= OBJECT_MASK;

        Some(())
    }
}

impl<'a> DecodeTLV<'a> for Object<'a> {
    type ReturnType = Self;

    fn decode_tlv(data: &'a [u8], pos: &mut usize) -> Option<Self::ReturnType> {
        if *pos >= data.len() {
            return None;
        }
        if data[*pos] & TYPE_MASK != OBJECT_MASK {
            return None;
        }

        let Length(length) = Length::read(data, *pos);

        *pos += 2;
        let start = *pos;
        for _ in 0..length {
            skip_zeroes(data, pos);

            let at = *pos;
            if !String::skip_tlv(data, pos) {
                panic!("invalid key at {}: {:?}", at, &data[at..]);
            }

            skip_zeroes(data, pos);

            let at = *pos;
            if !Value::skip_tlv(data, pos) {
                panic!("invalid value at {}: {:?}", at, &data[at..]);
            }
        }
        let end = *pos;

        let object = Object {
            data: &data[start..end],
        };
        Some(object)
    }
}

#[test]
fn test_object_empty() {
    let mut pos = 1;
    let mut data = *b" {}";
    Object::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(data, [b' ', OBJECT_MASK | 0, 0]);
}

#[test]
fn test_object_small() {
    use crate::mask::STRING_MASK;

    let mut pos = 1;
    let mut data = *br#" {"a": 1, "b": 2}"#;
    Object::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 17);
    assert_eq!(
        data,
        [
            b' ',
            // size is 2 = 0b10
            OBJECT_MASK | 0b10,
            0,
            STRING_MASK | 1,
            0,
            b'a',
            0,
            0,
            0b001_00001,
            0,
            0,
            STRING_MASK | 1,
            0,
            b'b',
            0,
            0,
            0b001_00010,
        ]
    );

    pos = 1;
    Object::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 17);
}
