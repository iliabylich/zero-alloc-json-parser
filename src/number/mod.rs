#[cfg(test)]
mod tests;

mod json_number;
use json_number::JsonNumber;

mod header_byte;
use header_byte::HeaderByte;

mod non_header_byte;
use non_header_byte::NonHeaderByte;

use crate::tlv::{DecodeTLV, RewriteToTLV};

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

pub(crate) struct JsonNumberTLV;

impl RewriteToTLV<'_> for JsonNumberTLV {
    type ExtraPayload = ();
    type ReturnType = ();

    fn rewrite_to_tlv(data: &mut [u8], start: usize, end: usize, _extra: ()) {
        let HeaderByte { multibyte, .. } = HeaderByte::rewrite_to_tlv(data, start, end, ());

        if !multibyte {
            return;
        }
        let mut extra_length_to_write = end - start;
        for idx in (start + 1)..end {
            NonHeaderByte::rewrite_to_tlv(&mut data[idx..], 0, 0, &mut extra_length_to_write);
        }
    }
}

impl DecodeTLV<'_> for JsonNumberTLV {
    type ReturnType = Option<JsonNumber>;

    fn decode_tlv(data: &[u8]) -> Option<JsonNumber> {
        let header = HeaderByte::decode_tlv(data)?;

        if !header.multibyte {
            return Some(JsonNumber::Integer((header.char - b'0') as i64));
        }

        let mut negative;
        let mut result;

        if header.char == b'-' {
            negative = true;
            result = JsonNumber::Integer(0);
        } else {
            negative = false;
            result = JsonNumber::Integer((header.char - b'0') as i64);
        }

        let mut length = 0;
        let mut idx = 1;
        let mut seen_dot = false;
        let mut digits_after_dot = 0;

        loop {
            let (byte, l) = NonHeaderByte::decode_tlv(&data[idx..]);

            if let Some(l) = l {
                length |= (l as usize) << (3 * (idx - 1));
            }

            match byte {
                NonHeaderByte::Minus => {
                    negative = true;
                }
                NonHeaderByte::Exponent => {
                    panic!("exponents are not supported yet")
                }
                NonHeaderByte::Dot => {
                    result = result.make_float();
                    seen_dot = true;
                }
                NonHeaderByte::Digit { char } => {
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
                JsonNumber::Integer(_) => panic!("internal error, integer with dot?"),
                JsonNumber::Float(value) => {
                    JsonNumber::Float(value / 10_i32.pow(digits_after_dot) as f64)
                }
            };
        }
        Some(result)
    }
}
