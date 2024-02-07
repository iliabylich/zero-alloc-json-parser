use crate::{
    number::{DOT, EXPONENT, MINUS, VALUE_MASK},
    tlv::{DecodeTLV, RewriteToTLV},
};

const HAS_LENGTH_MASK: u8 = 0b1000_0000;
const LENGTH_MASK: u8 = 0b0111_0000;

pub(crate) enum NonHeaderByte {
    Digit { char: u8 },
    Dot,
    Exponent,
    Minus,
}

impl<'a> RewriteToTLV<'a> for NonHeaderByte {
    type ExtraPayload = &'a mut usize;

    type ReturnType = ();

    fn rewrite_to_tlv(data: &mut [u8], start: usize, _end: usize, length: &'a mut usize) {
        let length_component = if *length == 0 {
            0
        } else {
            ((*length % (2 << 3)) << 4) as u8 | HAS_LENGTH_MASK
        };
        *length >>= 3;
        let value_component = match data[start] {
            b'-' => MINUS,
            b'e' => EXPONENT,
            b'.' => DOT,
            b'0'..=b'9' => data[start] - b'0',
            _ => panic!("invalid number"),
        };
        data[start] = length_component | value_component;
    }
}

impl DecodeTLV<'_> for NonHeaderByte {
    type ReturnType = (Self, Option<u8>);

    fn decode_tlv(data: &[u8]) -> (Self, Option<u8>) {
        let value = data[0] & VALUE_MASK;
        let length = if data[0] & HAS_LENGTH_MASK == HAS_LENGTH_MASK {
            let l = (data[0] & LENGTH_MASK) >> 4;
            Some(l)
        } else {
            None
        };
        match value {
            MINUS => (Self::Minus, length),
            EXPONENT => (Self::Exponent, length),
            DOT => (Self::Dot, length),
            0..=9 => (Self::Digit { char: b'0' + value }, length),
            _ => panic!("invalid number: {}", value),
        }
    }
}
