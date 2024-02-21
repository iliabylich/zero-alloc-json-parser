use crate::{
    length::Length,
    mask::{ARRAY_MASK, TYPE_MASK},
    skip_zeroes::skip_zeroes,
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

fn bitmix_elements_and_close(data: &mut [u8], pos: &mut usize, length: &mut usize) -> Option<()> {
    skip_ws(data, pos);

    if bitmix_consume_byte::<b']'>(data, pos) {
        // empty object
        return Some(());
    }

    bitmix_element(data, pos)?;
    *length += 1;

    while *pos < data.len() {
        skip_ws(data, pos);

        if bitmix_consume_byte::<b']'>(data, pos) {
            return Some(());
        } else if bitmix_consume_byte::<b','>(data, pos) {
            skip_ws(data, pos);
            bitmix_element(data, pos)?;
            *length += 1;
        }
    }

    None
}

impl BitmixToTLV for Array<'_> {
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()> {
        let start = *pos;
        let mut length = 0;

        if data[*pos] != b'[' {
            return None;
        }

        *pos += 1;
        skip_ws(data, pos);

        if !bitmix_consume_byte::<b']'>(data, pos) {
            bitmix_elements_and_close(data, pos, &mut length)?;
        }

        data[start] = 0;
        data[*pos - 1] = 0;

        Length::write(data, start, *pos, length);
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

        let Length(length) = Length::read(data, *pos);

        *pos += 2;
        let start = *pos;
        for _ in 0..length {
            skip_zeroes(data, pos);
            let at = *pos;
            if !Value::skip_tlv(data, pos) {
                panic!("invalid array element at {}: {:?}", at, &data[at..]);
            }
        }
        let end = *pos;

        let result = Array {
            data: &data[start..end],
        };
        Some(result)
    }

    fn skip_tlv(data: &[u8], pos: &mut usize) -> bool {
        if *pos >= data.len() {
            return false;
        }
        if data[*pos] & TYPE_MASK != ARRAY_MASK {
            return false;
        }

        let Length(length) = Length::read(data, *pos);
        *pos += 2;
        for _ in 0..length {
            if !Value::skip_tlv(data, pos) {
                return false;
            }
        }
        true
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
    assert_eq!(pos, 3);
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
            // length = 3 = 0b11
            ARRAY_MASK | 0b11, // 5 trailing bits of length
            0,                 // 8 leading bits of length
            0b001_00001,
            0,
            0,
            0b001_00010,
            0,
            0,
            0b001_00011,
        ]
    );

    pos = 1;
    Array::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 10);
}

#[test]
fn test_array_long() {
    let mut pos = 1;
    let mut data = *b" [1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2]";
    Array::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 49);
    assert_eq!(
        data,
        [
            b' ',
            // length is 16 = 0b10000
            ARRAY_MASK | 0b10000, // 5 trailing bits of length
            0b0,                  // 5 leading bits of length
            0b001_00001,          // 1
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
