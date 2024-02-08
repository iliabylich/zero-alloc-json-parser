use crate::{
    bytesize::Bytesize,
    mask::{OBJECT_MASK, TYPE_MASK},
    string::String,
    tlv::{bitmix_req_byte_and_nullify, BitmixToTLV, DecodeTLV, DecodingResult},
    value::Value,
    ws::skip_ws,
};

#[derive(Debug)]
pub struct Object<'a> {
    pub(crate) data: &'a [u8],
}

fn bitmix_pair(data: &mut [u8], region_size: &mut usize) -> Option<()> {
    // key
    *region_size += String::bitmix_to_tlv(&mut data[*region_size..])?;
    skip_ws(data, region_size);

    // ":"
    if !bitmix_req_byte_and_nullify::<b':'>(data, region_size) {
        return None;
    }

    // value
    skip_ws(data, region_size);
    *region_size += Value::bitmix_to_tlv(&mut data[*region_size..])?;

    Some(())
}

fn bitmix_pair_list_and_close(data: &mut [u8], region_size: &mut usize) -> Option<()> {
    skip_ws(data, region_size);

    if bitmix_req_byte_and_nullify::<b'}'>(data, region_size) {
        // empty object
        return Some(());
    }

    bitmix_pair(data, region_size)?;

    while *region_size < data.len() {
        skip_ws(data, region_size);

        if bitmix_req_byte_and_nullify::<b'}'>(data, region_size) {
            return Some(());
        } else if data[*region_size] == b',' {
            data[*region_size] = 0;
            *region_size += 1;
            skip_ws(data, region_size);

            bitmix_pair(data, region_size)?;
        }
    }

    None
}

impl BitmixToTLV for Object<'_> {
    fn bitmix_to_tlv(data: &mut [u8]) -> Option<usize> {
        if data[0] != b'{' {
            return None;
        }
        let mut region_size = 1;
        skip_ws(data, &mut region_size);

        if !bitmix_req_byte_and_nullify::<b'}'>(data, &mut region_size) {
            bitmix_pair_list_and_close(data, &mut region_size)?;
        }

        data[0] = 0;
        data[region_size - 1] = 0;

        Bytesize::write(&mut data[..region_size], region_size - 2);
        data[0] |= OBJECT_MASK;

        Some(region_size)
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
