use crate::{
    bytesize::Bytesize,
    mask::{OBJECT_MASK, TYPE_MASK},
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

fn bitmix_pair_list_and_close(data: &mut [u8], pos: &mut usize) -> Option<()> {
    skip_ws(data, pos);

    if bitmix_consume_byte::<b'}'>(data, pos) {
        // empty object
        return Some(());
    }

    bitmix_pair(data, pos)?;

    while *pos < data.len() {
        skip_ws(data, pos);

        if bitmix_consume_byte::<b'}'>(data, pos) {
            return Some(());
        } else if data[*pos] == b',' {
            data[*pos] = 0;
            *pos += 1;
            skip_ws(data, pos);

            bitmix_pair(data, pos)?;
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
        *pos += 1;
        skip_ws(data, pos);

        if !bitmix_consume_byte::<b'}'>(data, pos) {
            bitmix_pair_list_and_close(data, pos)?;
        }

        data[start] = 0;
        data[*pos - 1] = 0;

        Bytesize::write(data, start, *pos, *pos - start - 2);
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

        let Bytesize { bytesize, offset } = Bytesize::read(data, *pos);

        let object = Object {
            data: &data[(*pos + offset)..(*pos + offset + bytesize)],
        };
        *pos += offset + bytesize;
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

    pos = 1;
    Object::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, data.len() - 1); // because the object is small, and so closing "}" is 0
}
