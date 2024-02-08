use crate::{
    bytesize::Bytesize,
    mask::{OBJECT_MASK, TYPE_MASK},
    string::String,
    tlv::{bitmix_consume_byte, BitmixToTLV, DecodeTLV, DecodingResult},
    value::Value,
    ws::skip_ws,
};

#[derive(Debug)]
pub struct Object<'a> {
    pub(crate) data: &'a [u8],
}

fn bitmix_pair(data: &mut [u8], pos: &mut usize) -> Option<()> {
    // key
    *pos += String::bitmix_to_tlv(&mut data[*pos..])?;
    skip_ws(data, pos);

    // ":"
    if !bitmix_consume_byte::<b':'>(data, pos) {
        return None;
    }

    // value
    skip_ws(data, pos);
    *pos += Value::bitmix_to_tlv(&mut data[*pos..])?;

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
    fn bitmix_to_tlv(data: &mut [u8]) -> Option<usize> {
        if data[0] != b'{' {
            return None;
        }
        let mut pos = 1;
        skip_ws(data, &mut pos);

        if !bitmix_consume_byte::<b'}'>(data, &mut pos) {
            bitmix_pair_list_and_close(data, &mut pos)?;
        }

        data[0] = 0;
        data[pos - 1] = 0;

        Bytesize::write(&mut data[..pos], pos - 2);
        data[0] |= OBJECT_MASK;

        Some(pos)
    }
}

impl<'a> DecodeTLV<'a> for Object<'a> {
    type ReturnType = Self;

    fn decode_tlv(data: &'a [u8]) -> Option<DecodingResult<Self::ReturnType>> {
        if data.is_empty() {
            return None;
        }
        if data[0] & TYPE_MASK != OBJECT_MASK {
            return None;
        }

        let Bytesize { bytesize, offset } = Bytesize::read(data);

        Some(DecodingResult {
            value: Object {
                data: &data[offset..(offset + bytesize)],
            },
            size: bytesize + offset,
        })
    }
}

#[test]
fn test_object_empty() {
    let mut data = *b"{}";
    let rewritten = Object::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(rewritten, 2);
    assert_eq!(data, [OBJECT_MASK | 0, 0]);
}

#[test]
fn test_object_small() {
    use crate::mask::STRING_MASK;

    let mut data = *br#"{"a": 1, "b": 2}"#;
    let rewritten = Object::bitmix_to_tlv(&mut data).unwrap();
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
