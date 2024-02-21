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
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()> {
        let region_size = if data.get(*pos..*pos + 4) == Some(b"true") {
            data[*pos] = TRUE_MASK;
            4
        } else if data.get(*pos..*pos + 5) == Some(b"false") {
            data[*pos] = FALSE_MASK;
            5
        } else if data.get(*pos..*pos + 4) == Some(b"null") {
            data[*pos] = NULL_MASK;
            4
        } else {
            return None;
        };

        // nullify the rest
        data.iter_mut()
            .skip(*pos + 1)
            .take(region_size - 1)
            .for_each(|byte| *byte = 0);

        *pos += region_size;
        Some(())
    }
}

impl DecodeTLV<'_> for TrueFalseNull {
    type ReturnType = Self;

    fn decode_tlv(data: &[u8], pos: &mut usize) -> Option<Self::ReturnType> {
        if *pos >= data.len() {
            return None;
        }
        match data[*pos] {
            TRUE_MASK => {
                *pos += 4;
                Some(Self::True)
            }
            FALSE_MASK => {
                *pos += 5;
                Some(Self::False)
            }
            NULL_MASK => {
                *pos += 4;
                Some(Self::Null)
            }
            _ => None,
        }
    }

    fn skip_tlv(data: &[u8], pos: &mut usize) -> bool {
        if *pos >= data.len() {
            return false;
        }
        match data[*pos] {
            TRUE_MASK => {
                *pos += 4;
                true
            }
            FALSE_MASK => {
                *pos += 5;
                true
            }
            NULL_MASK => {
                *pos += 4;
                true
            }
            _ => false,
        }
    }
}

#[test]
fn test_true() {
    let mut pos = 1;
    let mut data = *b" true";
    TrueFalseNull::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 5);
    assert_eq!(data, [b' ', TRUE_MASK, 0, 0, 0]);

    pos = 1;
    let value = TrueFalseNull::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 5);
    assert_eq!(value, TrueFalseNull::True);
}

#[test]
fn test_false() {
    let mut pos = 1;
    let mut data = *b" false";
    TrueFalseNull::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 6);
    assert_eq!(data, [b' ', FALSE_MASK, 0, 0, 0, 0]);

    pos = 1;
    let value = TrueFalseNull::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 6);
    assert_eq!(value, TrueFalseNull::False);
}

#[test]
fn test_null() {
    let mut pos = 1;
    let mut data = *b" null";
    TrueFalseNull::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, 5);
    assert_eq!(data, [b' ', NULL_MASK, 0, 0, 0]);

    pos = 1;
    let value = TrueFalseNull::decode_tlv(&data, &mut pos).unwrap();
    assert_eq!(pos, 5);
    assert_eq!(value, TrueFalseNull::Null);
}
