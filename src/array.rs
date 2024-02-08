use crate::{
    bytesize::Bytesize,
    mask::{ARRAY_MASK, TYPE_MASK},
    tlv::{bitmix_consume_byte, BitmixToTLV, DecodeTLV, DecodingResult},
    value::Value,
    ws::skip_ws,
};

#[derive(Debug)]
pub struct Array<'a> {
    pub(crate) data: &'a [u8],
}

fn bitmix_element(data: &mut [u8], pos: &mut usize) -> Option<()> {
    *pos += Value::bitmix_to_tlv(&mut data[*pos..])?;
    Some(())
}

fn bitmix_elements_and_close(data: &mut [u8], pos: &mut usize) -> Option<()> {
    skip_ws(data, pos);

    if bitmix_consume_byte::<b']'>(data, pos) {
        // empty object
        return Some(());
    }

    bitmix_element(data, pos)?;

    while *pos < data.len() {
        skip_ws(data, pos);

        if bitmix_consume_byte::<b']'>(data, pos) {
            return Some(());
        } else if bitmix_consume_byte::<b','>(data, pos) {
            skip_ws(data, pos);
            bitmix_element(data, pos)?;
        }
    }

    None
}

impl BitmixToTLV for Array<'_> {
    fn bitmix_to_tlv(data: &mut [u8]) -> Option<usize> {
        if data[0] != b'[' {
            return None;
        }

        let mut pos = 1;
        skip_ws(data, &mut pos);

        if !bitmix_consume_byte::<b']'>(data, &mut pos) {
            bitmix_elements_and_close(data, &mut pos)?;
        }

        data[0] = 0;
        data[pos - 1] = 0;

        Bytesize::write(&mut data[..pos], pos - 2);
        data[0] |= ARRAY_MASK;

        Some(pos)
    }
}

impl<'a> DecodeTLV<'a> for Array<'a> {
    type ReturnType = Self;

    fn decode_tlv(data: &'a [u8]) -> Option<DecodingResult<Self::ReturnType>> {
        if data.is_empty() {
            return None;
        }
        if data[0] & TYPE_MASK != ARRAY_MASK {
            return None;
        }

        let Bytesize { bytesize, offset } = Bytesize::read(data);

        Some(DecodingResult {
            value: Array {
                data: &data[offset..(offset + bytesize)],
            },
            size: bytesize + offset,
        })
    }
}

#[test]
fn test_array_empty() {
    let mut data = *b"[]";
    let rewritten = Array::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(rewritten, 2);
    assert_eq!(data, [ARRAY_MASK | 0, 0]);

    let decoded = Array::decode_tlv(&data).unwrap().value;
    assert_eq!(decoded.data, &[]);
}

#[test]
fn test_array_short() {
    let mut data = *b"[1, 2, 3]";
    let rewritten = Array::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(rewritten, 9);
    assert_eq!(
        data,
        [
            ARRAY_MASK | 7,
            0b001_00001,
            0,
            0,
            0b001_00010,
            0,
            0,
            0b001_00011,
            0
        ]
    );
}

#[test]
fn test_array_long() {
    use crate::bytesize::LONG_CONTAINER_MASK;

    let mut data = *b"[1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2]";
    let rewritten = Array::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(rewritten, 48);
    assert_eq!(
        data,
        [
            // length is 46 = 0b101110
            ARRAY_MASK | LONG_CONTAINER_MASK | 0b110, // 3 trailing bits of length
            0b101,                                    // the rest of the length
            0b001_00001,                              // 1
            0,
            0,
            0b001_00010, // 2
            0,
            0,
            0b001_00011, // 3
            0,
            0,
            0b001_00100, // 4
            0,
            0,
            0b001_00101, // 5
            0,
            0,
            0b001_00110, // 6
            0,
            0,
            0b001_00111, // 7
            0,
            0,
            0b001_01000, // 8
            0,
            0,
            0b001_01001, // 9
            0,
            0,
            0b001_01000, // 8
            0,
            0,
            0b001_00111, // 7
            0,
            0,
            0b001_00110, // 6
            0,
            0,
            0b001_00101, // 5
            0,
            0,
            0b001_00100, // 4
            0,
            0,
            0b001_00011, // 3
            0,
            0,
            0b001_00010, // 2
        ]
    );
}
