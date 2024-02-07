use crate::{
    mask::{FALSE_MASK, NULL_MASK, TRUE_MASK},
    tlv::{BitmixToTLV, DecodeTLV},
};

#[derive(Debug, PartialEq)]
pub(crate) enum TrueFalseNull {
    True,
    False,
    Null,
}

impl BitmixToTLV for TrueFalseNull {
    type ReturnType = ();

    fn bitmix_to_tlv(data: &mut [u8]) -> Option<(Self::ReturnType, usize)> {
        let mut region_size = 0;
        if data.get(0..4) == Some(b"true") {
            data[0] = TRUE_MASK;
            region_size = 4;
        } else if data.get(0..5) == Some(b"false") {
            data[0] = FALSE_MASK;
            region_size = 5;
        } else if data.get(0..4) == Some(b"null") {
            data[0] = NULL_MASK;
            region_size = 4;
        }

        if region_size == 0 {
            return None;
        }

        // nullify the rest
        for byte in data.iter_mut().skip(1).take(region_size - 1) {
            *byte = 0;
        }

        Some(((), region_size))
    }
}

impl DecodeTLV<'_> for TrueFalseNull {
    type ReturnType = Self;

    fn decode_tlv(data: &[u8]) -> Option<(Self::ReturnType, usize)> {
        if data.is_empty() {
            return None;
        }
        match data[0] {
            TRUE_MASK => Some((Self::True, 4)),
            FALSE_MASK => Some((Self::False, 5)),
            NULL_MASK => Some((Self::Null, 4)),
            _ => None,
        }
    }
}

#[test]
fn test_true() {
    let mut data = *b"true";
    let (_, rewritten) = TrueFalseNull::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [TRUE_MASK, 0, 0, 0]);
    assert_eq!(rewritten, 4);

    let (decoded, read) = TrueFalseNull::decode_tlv(&data).unwrap();
    assert_eq!(decoded, TrueFalseNull::True);
    assert_eq!(read, 4);
}

#[test]
fn test_false() {
    let mut data = *b"false";
    let (_, rewritten) = TrueFalseNull::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [FALSE_MASK, 0, 0, 0, 0]);
    assert_eq!(rewritten, 5);

    let (decoded, read) = TrueFalseNull::decode_tlv(&data).unwrap();
    assert_eq!(decoded, TrueFalseNull::False);
    assert_eq!(read, 5);
}

#[test]
fn test_null() {
    let mut data = *b"null";
    let (_, rewritten) = TrueFalseNull::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [NULL_MASK, 0, 0, 0]);
    assert_eq!(rewritten, 4);

    let (decoded, read) = TrueFalseNull::decode_tlv(&data).unwrap();
    assert_eq!(decoded, TrueFalseNull::Null);
    assert_eq!(read, 4);
}
