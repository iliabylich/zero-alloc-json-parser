use crate::{
    mask::{NUMBER_MASK, TYPE_MASK},
    number::{MINUS, VALUE_MASK},
};

const MULTIBYTE_FLAG: u8 = 0b10000;

pub(crate) struct HeaderByteWriteResult {
    pub(crate) multibyte: bool,
}

pub(crate) struct HeaderByteReadResult {
    pub(crate) multibyte: bool,
    pub(crate) char: u8,
}

pub(crate) struct HeaderByte;

impl HeaderByte {
    pub(crate) fn write(data: &mut [u8], length: usize) -> Option<HeaderByteWriteResult> {
        if length == 1 {
            data[0] = NUMBER_MASK | char_to_tlv(data[0]);
            return Some(HeaderByteWriteResult { multibyte: false });
        }

        data[0] = NUMBER_MASK | MULTIBYTE_FLAG | char_to_tlv(data[0]);
        Some(HeaderByteWriteResult { multibyte: true })
    }

    pub(crate) fn read(data: &[u8]) -> Option<HeaderByteReadResult> {
        if data[0] & TYPE_MASK != NUMBER_MASK {
            return None;
        }
        if data[0] & MULTIBYTE_FLAG == 0 {
            return Some(HeaderByteReadResult {
                multibyte: false,
                char: singlebyte_tlv_to_char(data[0]),
            });
        }

        Some(HeaderByteReadResult {
            multibyte: true,
            char: multibyte_tlv_to_char(data[0]),
        })
    }
}

fn char_to_tlv(char: u8) -> u8 {
    match char {
        b'-' => MINUS,
        digit @ b'0'..=b'9' => digit - b'0',
        _ => panic!("invalid number"),
    }
}

fn singlebyte_tlv_to_char(tlv: u8) -> u8 {
    b'0' + (tlv & 0b1111)
}

fn multibyte_tlv_to_char(tlv: u8) -> u8 {
    match tlv & VALUE_MASK {
        MINUS => b'-',
        digit @ 0..=9 => b'0' + digit,
        _ => panic!("invalid number"),
    }
}
