use crate::{
    bytesize::Bytesize,
    mask::{ARRAY_MASK, TYPE_MASK},
    tlv::{bitmix_consume_byte, BitmixToTLV, DecodeTLV},
    value::Value,
    ws::skip_ws,
};

#[derive(Debug)]
pub struct Array<'a> {
    pub(crate) data: &'a [u8],
}

fn bitmix_element(data: &mut [u8], pos: &mut usize) -> Option<()> {
    Value::bitmix_to_tlv(data, pos)?;
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
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()> {
        let start = *pos;

        if data[*pos] != b'[' {
            return None;
        }

        *pos += 1;
        skip_ws(data, pos);

        if !bitmix_consume_byte::<b']'>(data, pos) {
            bitmix_elements_and_close(data, pos)?;
        }

        data[start] = 0;
        data[*pos - 1] = 0;

        Bytesize::write(data, start, *pos, *pos - start - 2);
        data[start] |= ARRAY_MASK;

        Some(())
    }
}

impl<'a> DecodeTLV<'a> for Array<'a> {
    type ReturnType = Self;

    fn decode_tlv(data: &'a [u8], pos: &mut usize) -> Option<Self::ReturnType> {
        if *pos >= data.len() {
            return None;
        }
        if data[*pos] & TYPE_MASK != ARRAY_MASK {
            return None;
        }

        let Bytesize { bytesize, offset } = Bytesize::read(data, *pos);

        let result = Array {
            data: &data[(*pos + offset)..(*pos + offset + bytesize)],
        };
        *pos += offset + bytesize;
        Some(result)
    }
}

#[test]
fn test_array_empty() {
    let mut pos = 1;
    let mut data = *b" []";
    Array::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 3);
    assert_eq!(data, [b' ', ARRAY_MASK | 0, 0]);

    pos = 1;
    let value = Array::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 2);
    assert_eq!(value.data, &[]);
}

#[test]
fn test_array_short() {
    let mut pos = 1;
    let mut data = *b" [1, 2, 3]";
    Array::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 10);
    assert_eq!(
        data,
        [
            b' ',
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

    pos = 1;
    Array::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 9);
}

#[test]
fn test_array_long() {
    use crate::bytesize::LONG_CONTAINER_MASK;

    let mut pos = 1;
    let mut data = *b" [1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2]";
    Array::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 49);
    assert_eq!(
        data,
        [
            b' ',
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

    pos = 1;
    Array::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, data.len());
}
