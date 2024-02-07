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

impl RewriteToTLV<'_> for HeaderByte {
    type ExtraPayload = ();
    type ReturnType = Self;

    fn rewrite_to_tlv(data: &mut [u8], start: usize, end: usize, _: ()) -> Self {
        let length = end - start;
        if length == 1 {
            let header_byte = NUMBER_MASK | (data[start] - b'0');
            data[start] = header_byte;
            return Self {
                multibyte: false,
                char: header_byte,
            };
        }

        let value_component = match data[start] {
            b'-' => MINUS,
            b'0'..=b'9' => data[start] - b'0',
            _ => panic!("invalid number"),
        };
        let header_byte = NUMBER_MASK | MULTIBYTE | value_component;
        data[start] = header_byte;
        Self {
            multibyte: true,
            char: header_byte,
        }
    }
}

impl DecodeTLV for HeaderByte {
    type ReturnType = Option<Self>;

    fn decode_tlv(data: &[u8]) -> Option<Self> {
        if data[0] & NUMBER_MASK != NUMBER_MASK {
            return None;
        }
        if data[0] & MULTIBYTE == 0 {
            return Some(Self {
                multibyte: false,
                char: b'0' + (data[0] & 0b1111),
            });
        }
        let char = match data[0] & VALUE_MASK {
            MINUS => b'-',
            digit @ 0..=9 => b'0' + digit,
            _ => panic!("invalid number"),
        };

        Some(Self {
            multibyte: true,
            char,
        })
    }
}
