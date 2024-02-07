use crate::{
    mask::NUMBER_MASK,
    number::{MINUS, VALUE_MASK},
    tlv::{DecodeTLV, RewriteToTLV},
};

const MULTIBYTE: u8 = 0b10000;

pub(crate) struct HeaderByte {
    pub(crate) multibyte: bool,
    pub(crate) char: u8,
}

impl RewriteToTLV for HeaderByte {
    type ExtraPayload = usize;
    type ReturnType = Self;

    fn rewrite_to_tlv(data: &mut [u8], length: usize) -> Option<(Self::ReturnType, usize)> {
        if length == 1 {
            let header_byte = NUMBER_MASK | (data[0] - b'0');
            data[0] = header_byte;
            return Some((
                Self {
                    multibyte: false,
                    char: header_byte,
                },
                1,
            ));
        }

        let value_component = match data[0] {
            b'-' => MINUS,
            b'0'..=b'9' => data[0] - b'0',
            _ => panic!("invalid number"),
        };
        let header_byte = NUMBER_MASK | MULTIBYTE | value_component;
        data[0] = header_byte;
        Some((
            Self {
                multibyte: true,
                char: header_byte,
            },
            1,
        ))
    }
}

impl DecodeTLV<'_> for HeaderByte {
    type ReturnType = Self;

    fn decode_tlv(data: &[u8]) -> Option<(Self::ReturnType, usize)> {
        if data[0] & NUMBER_MASK != NUMBER_MASK {
            return None;
        }
        if data[0] & MULTIBYTE == 0 {
            return Some((
                Self {
                    multibyte: false,
                    char: b'0' + (data[0] & 0b1111),
                },
                1,
            ));
        }
        let char = match data[0] & VALUE_MASK {
            MINUS => b'-',
            digit @ 0..=9 => b'0' + digit,
            _ => panic!("invalid number"),
        };

        Some((
            Self {
                multibyte: true,
                char,
            },
            1,
        ))
    }
}
