use crate::number::{DOT, EXPONENT, MINUS, VALUE_MASK};

const HAS_LENGTH_MASK: u8 = 0b1000_0000;
const LENGTH_MASK: u8 = 0b0111_0000;

pub(crate) struct NonHeaderByte;

pub(crate) struct NonHeaderByteWriteResult {
    pub(crate) length_left: usize,
}

pub(crate) struct NonHeaderByteReadResult {
    pub(crate) length_part: Option<u8>,
    pub(crate) char: NonHeaderByteChar,
}

pub(crate) enum NonHeaderByteChar {
    Digit { char: u8 },
    Dot,
    Exponent,
    Minus,
}

impl NonHeaderByte {
    pub(crate) fn write(data: &mut [u8], length: usize) -> NonHeaderByteWriteResult {
        let mut length_component = 0;
        if length != 0 {
            length_component = ((length % (2 << 3)) << 4) as u8 | HAS_LENGTH_MASK
        };
        let value_component = match data[0] {
            b'-' => MINUS,
            b'e' => EXPONENT,
            b'.' => DOT,
            b'0'..=b'9' => data[0] - b'0',
            _ => panic!("invalid number"),
        };
        data[0] = length_component | value_component;
        NonHeaderByteWriteResult {
            length_left: length >> 3,
        }
    }

    pub(crate) fn read(data: &[u8]) -> NonHeaderByteReadResult {
        let value = data[0] & VALUE_MASK;
        let mut length_part = None;
        if data[0] & HAS_LENGTH_MASK == HAS_LENGTH_MASK {
            length_part = Some((data[0] & LENGTH_MASK) >> 4)
        }
        let char = match value {
            MINUS => NonHeaderByteChar::Minus,
            EXPONENT => NonHeaderByteChar::Exponent,
            DOT => NonHeaderByteChar::Dot,
            0..=9 => NonHeaderByteChar::Digit { char: b'0' + value },
            _ => panic!("invalid number: {}", value),
        };
        NonHeaderByteReadResult { length_part, char }
    }
}
