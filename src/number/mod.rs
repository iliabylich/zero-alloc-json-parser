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
    type ReturnType = ();

    fn bitmix_to_tlv(data: &mut [u8]) -> Option<(Self::ReturnType, usize)> {
        let mut region_size = 0;
        while region_size < data.len() {
            if matches!(data[region_size], b'-' | b'0'..=b'9' | b'.' | b'e' | b'E') {
                region_size += 1;
            } else {
                break;
            }
        }
        if region_size == 0 {
            return None;
        }

        let header = HeaderByte::write(data, region_size)?;

        if !header.multibyte {
            return Some(((), 1));
        }
        let mut length_left_to_write = region_size;
        for idx in 1..region_size {
            length_left_to_write =
                NonHeaderByte::write(&mut data[idx..], length_left_to_write).length_left;
        }

        Some(((), region_size))
    }
}

impl DecodeTLV<'_> for Number {
    type ReturnType = IntOrFloat;

    fn decode_tlv(data: &[u8]) -> Option<(Self::ReturnType, usize)> {
        if data.is_empty() {
            return None;
        }

        let header = HeaderByte::read(data)?;

        if !header.multibyte {
            return Some((IntOrFloat::Integer((header.char - b'0') as i64), 1));
        }

        let mut negative;
        let mut result;

        if header.char == b'-' {
            negative = true;
            result = IntOrFloat::Integer(0);
        } else {
            negative = false;
            result = IntOrFloat::Integer((header.char - b'0') as i64);
        }

        let mut length = 0;
        let mut idx = 1;
        let mut seen_dot = false;
        let mut digits_after_dot = 0;
        let mut read_total = 1;

        loop {
            let NonHeaderByteReadResult { length_part, char } = NonHeaderByte::read(&data[idx..]);
            read_total += 1;

            if let Some(l) = length_part {
                length |= (l as usize) << (3 * (idx - 1));
            }

            match char {
                NonHeaderByteChar::Minus { .. } => {
                    negative = true;
                }
                NonHeaderByteChar::Exponent { .. } => {
                    panic!("exponents are not supported yet")
                }
                NonHeaderByteChar::Dot { .. } => {
                    result = result.make_float();
                    seen_dot = true;
                }
                NonHeaderByteChar::Digit { char, .. } => {
                    result = result.add(char - b'0');
                    if seen_dot {
                        digits_after_dot += 1;
                    }
                }
            }
            idx += 1;

            if idx >= length {
                break;
            }
        }

        if negative {
            result = result.negate();
        }
        if digits_after_dot > 0 {
            result = match result {
                IntOrFloat::Integer(_) => panic!("internal error, integer with dot?"),
                IntOrFloat::Float(value) => {
                    IntOrFloat::Float(value / 10_i32.pow(digits_after_dot) as f64)
                }
            };
        }

        Some((result, read_total))
    }
}
