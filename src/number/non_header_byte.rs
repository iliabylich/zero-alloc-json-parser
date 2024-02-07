use crate::{
    number::{DOT, EXPONENT, MINUS, VALUE_MASK},
    tlv::{DecodeTLV, RewriteToTLV},
};

const HAS_LENGTH_MASK: u8 = 0b1000_0000;
const LENGTH_MASK: u8 = 0b0111_0000;

pub(crate) enum NonHeaderByte {
    Digit { char: u8, length_part: Option<u8> },
    Dot { length_part: Option<u8> },
    Exponent { length_part: Option<u8> },
    Minus { length_part: Option<u8> },
}

impl NonHeaderByte {
    pub(crate) fn length_part(&self) -> Option<u8> {
        match self {
            Self::Digit { length_part, .. }
            | Self::Dot { length_part }
            | Self::Exponent { length_part }
            | Self::Minus { length_part } => *length_part,
        }
    }
}

impl RewriteToTLV for NonHeaderByte {
    type ExtraPayload = usize;

    type ReturnType = usize;

    fn rewrite_to_tlv(data: &mut [u8], mut length: usize) -> Option<(Self::ReturnType, usize)> {
        let length_component = if length == 0 {
            0
        } else {
            ((length % (2 << 3)) << 4) as u8 | HAS_LENGTH_MASK
        };
        length >>= 3;
        let value_component = match data[0] {
            b'-' => MINUS,
            b'e' => EXPONENT,
            b'.' => DOT,
            b'0'..=b'9' => data[0] - b'0',
            _ => panic!("invalid number"),
        };
        data[0] = length_component | value_component;
        Some((length, 1))
    }
}

impl DecodeTLV<'_> for NonHeaderByte {
    type ReturnType = Self;

    fn decode_tlv(data: &[u8]) -> Option<(Self::ReturnType, usize)> {
        let value = data[0] & VALUE_MASK;
        let length_part = if data[0] & HAS_LENGTH_MASK == HAS_LENGTH_MASK {
            let l = (data[0] & LENGTH_MASK) >> 4;
            Some(l)
        } else {
            None
        };
        match value {
            MINUS => Some((Self::Minus { length_part }, 1)),
            EXPONENT => Some((Self::Exponent { length_part }, 1)),
            DOT => Some((Self::Dot { length_part }, 1)),
            0..=9 => Some((
                Self::Digit {
                    char: b'0' + value,
                    length_part,
                },
                1,
            )),
            _ => panic!("invalid number: {}", value),
        }
    }
}
