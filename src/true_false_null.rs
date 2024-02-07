use crate::{
    mask::{FALSE_MASK, NULL_MASK, TRUE_MASK},
    tlv::{DecodeTLV, RewriteToTLV},
};

#[derive(Debug, PartialEq)]
pub(crate) enum TrueFalseNull {
    True,
    False,
    Null,
}

impl RewriteToTLV<'_> for TrueFalseNull {
    type ExtraPayload = ();
    type ReturnType = ();

    fn rewrite_to_tlv(data: &mut [u8], start: usize, end: usize, _: ()) {
        let length = end - start;
        if length == 5 {
            // false
            data[start] = FALSE_MASK;
        } else if data[start] == b't' {
            // true
            data[start] = TRUE_MASK;
        } else if data[start] == b'n' {
            // null
            data[start] = NULL_MASK;
        }
        // nullify the rest
        for byte in data.iter_mut().skip(start + 1).take(end) {
            *byte = 0;
        }
    }
}

impl DecodeTLV<'_> for TrueFalseNull {
    type ReturnType = Option<(Self, usize)>;

    fn decode_tlv(data: &[u8]) -> Self::ReturnType {
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
    TrueFalseNull::rewrite_to_tlv(&mut data, 0, 4, ());
    assert_eq!(data, [TRUE_MASK, 0, 0, 0]);
    let (decoded, length) = TrueFalseNull::decode_tlv(&data).unwrap();
    assert_eq!(decoded, TrueFalseNull::True);
    assert_eq!(length, 4);
}

#[test]
fn test_false() {
    let mut data = *b"false";
    TrueFalseNull::rewrite_to_tlv(&mut data, 0, 5, ());
    assert_eq!(data, [FALSE_MASK, 0, 0, 0, 0]);
    let (decoded, length) = TrueFalseNull::decode_tlv(&data).unwrap();
    assert_eq!(decoded, TrueFalseNull::False);
    assert_eq!(length, 5);
}

#[test]
fn test_null() {
    let mut data = *b"null";
    TrueFalseNull::rewrite_to_tlv(&mut data, 0, 4, ());
    assert_eq!(data, [NULL_MASK, 0, 0, 0]);
    let (decoded, length) = TrueFalseNull::decode_tlv(&data).unwrap();
    assert_eq!(decoded, TrueFalseNull::Null);
    assert_eq!(length, 4);
}
