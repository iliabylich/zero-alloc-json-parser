#[cfg(test)]
mod tests;

mod int_or_float;
pub(crate) use int_or_float::IntOrFloat;

mod header_byte;
use header_byte::HeaderByte;

mod non_header_byte;
use non_header_byte::NonHeaderByte;

use crate::tlv::{BitmixToTLV, DecodeTLV};

use self::non_header_byte::{NonHeaderByteChar, NonHeaderByteReadResult};

//
// format: 000YVVVV where:
//   1. 000 - 3 bits for variant
//   2. Y - 1 bit to indicate if the number is multibyte
//   3. VVVV - 4 bits for the value (10 digits, "-", ceil(log2(11)) = 4):
//     0-9 = 0-9
//     "-" = 10
//     "e" = 11
//     "." = 12
//
// if Y is 0, the number is a single byte
// if Y is 1, the number is multibyte and the length is a part of the next (1+) byte(s)
//   writed as 0b1LLLVVVV where:
//     1 - 1 bit to indicate if the length is there
//     LLL - 3 bits for the length
//     VVVV - 4 bits for the value
//

pub(crate) const MINUS: u8 = 0b1010; // 10
pub(crate) const EXPONENT: u8 = 0b1011; // 11
pub(crate) const DOT: u8 = 0b1100; // 12

pub(crate) const VALUE_MASK: u8 = 0b0000_1111;

pub(crate) struct Number;

impl BitmixToTLV for Number {
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()> {
        let mut region_size = 0;
        while region_size + *pos < data.len() {
            if matches!(
                data[region_size + *pos],
                b'-' | b'0'..=b'9' | b'.' | b'e' | b'E'
            ) {
                region_size += 1;
            } else {
                break;
            }
        }
        if region_size == 0 {
            return None;
        }

        let header = HeaderByte::write(data, *pos, region_size)?;

        if !header.multibyte {
            *pos += 1;
            return Some(());
        }
        let mut length_left_to_write = region_size;
        for idx in 1..region_size {
            length_left_to_write =
                NonHeaderByte::write(data, *pos + idx, length_left_to_write).length_left;
        }

        *pos += region_size;
        Some(())
    }
}

impl DecodeTLV<'_> for Number {
    type ReturnType = IntOrFloat;

    fn decode_tlv(data: &[u8], pos: &mut usize) -> Option<Self::ReturnType> {
        if *pos >= data.len() {
            return None;
        }

        let header: header_byte::HeaderByteReadResult = HeaderByte::read(data, *pos)?;

        if !header.multibyte {
            *pos += 1;
            return Some(IntOrFloat::Integer {
                value: (header.char - b'0') as i64,
                negative: false,
            });
        }

        let mut result;

        if header.char == b'-' {
            result = IntOrFloat::Integer {
                value: 0,
                negative: true,
            };
        } else {
            result = IntOrFloat::Integer {
                value: (header.char - b'0') as i64,
                negative: false,
            };
        }

        let mut length = 0;
        let mut idx = 1;
        let mut read_total = 1;

        loop {
            let NonHeaderByteReadResult { length_part, char } =
                NonHeaderByte::read(data, *pos + idx);
            read_total += 1;

            if let Some(l) = length_part {
                length |= (l as usize) << (3 * (idx - 1));
            }

            match char {
                NonHeaderByteChar::Minus { .. } => {
                    result.negate();
                }
                NonHeaderByteChar::Exponent { .. } => {
                    panic!("exponents are not supported yet")
                }
                NonHeaderByteChar::Dot { .. } => {
                    result.add_dot();
                }
                NonHeaderByteChar::Digit { char, .. } => {
                    result.append(char - b'0');
                }
            }
            idx += 1;

            if idx >= length {
                break;
            }
        }

        *pos += read_total;
        Some(result)
    }
}
