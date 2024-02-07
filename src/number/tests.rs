use crate::{
    number::{IntOrFloat, Number},
    tlv::{DecodeTLV, RewriteToTLV},
};

#[test]
fn test_0() {
    let mut data = *b"0";
    Number::rewrite_to_tlv(&mut data, 0, 1, ());
    assert_eq!(data, [0b001_00000]);
    assert_eq!(Number::decode_tlv(&data), Some(IntOrFloat::Integer(0)));
}

#[test]
fn test_1() {
    let mut data = *b"1";
    Number::rewrite_to_tlv(&mut data, 0, 1, ());
    assert_eq!(data, [0b001_00001]);
    assert_eq!(Number::decode_tlv(&data), Some(IntOrFloat::Integer(1)));
}

#[test]
fn test_9() {
    let mut data = *b"9";
    Number::rewrite_to_tlv(&mut data, 0, 1, ());
    assert_eq!(data, [0b001_01001]);
    assert_eq!(Number::decode_tlv(&data), Some(IntOrFloat::Integer(9)));
}

#[test]
fn test_69() {
    let mut data = *b"69";
    Number::rewrite_to_tlv(&mut data, 0, 2, ());
    assert_eq!(data, [0b001_10110, 0b1010_1001]);
    assert_eq!(Number::decode_tlv(&data), Some(IntOrFloat::Integer(69)));
}

#[test]
fn test_1234567890987654321() {
    let mut data = *b"1234567890987654321"; // 19 bytes = 0b10_011
    Number::rewrite_to_tlv(&mut data, 0, 19, ());
    assert_eq!(
        data,
        [
            0b001_10001, // 000 = mask, 1 = multibyte, value = 0b001 = 1
            0b1011_0010, // 0b0011 = length, value = 2
            0b1010_0011, // 0b0010 = length, value = 3
            0b0000_0100, // 0b0000 = length, value = 4
            0b0000_0101, // 0b0000 = length, value = 5
            0b0000_0110, // 0b0000 = length, value = 6
            0b0000_0111, // 0b0000 = length, value = 7
            0b0000_1000, // 0b0000 = length, value = 8
            0b0000_1001, // 0b0000 = length, value = 9
            0b0000_0000, // 0b0000 = length, value = 0
            0b0000_1001, // 0b0000 = length, value = 9
            0b0000_1000, // 0b0000 = length, value = 8
            0b0000_0111, // 0b0000 = length, value = 7
            0b0000_0110, // 0b0000 = length, value = 6
            0b0000_0101, // 0b0000 = length, value = 5
            0b0000_0100, // 0b0000 = length, value = 4
            0b0000_0011, // 0b0000 = length, value = 3
            0b0000_0010, // 0b0000 = length, value = 2
            0b0000_0001, // 0b0000 = length, value = 1
        ]
    );
    assert_eq!(
        Number::decode_tlv(&data),
        Some(IntOrFloat::Integer(1234567890987654321))
    );
}

#[test]
fn test_minus_1() {
    let mut data = *b"-1"; // length = 2 = b10
    Number::rewrite_to_tlv(&mut data, 0, 2, ());
    assert_eq!(
        data,
        [
            0b001_11010, // 000 = mask, 1 = multibyte, value = 0b1010 = MINUS
            0b1010_0001, // 0010 = length = 2, value = 1
        ]
    );
    assert_eq!(Number::decode_tlv(&data), Some(IntOrFloat::Integer(-1)));
}

#[test]
fn test_two_point_three() {
    let mut data = *b"2.3"; // length = 3 = 0b11
    Number::rewrite_to_tlv(&mut data, 0, 3, ());
    assert_eq!(
        data,
        [
            0b001_10010, // 000 = mask, 1 = multibyte, value = 0b0010 = 2
            0b1011_1100, // 0011 = length = 3, value = 12 = DOT
            0b0000_0011, // 0000 = length = 0, value = 3
        ]
    );
    assert_eq!(Number::decode_tlv(&data), Some(IntOrFloat::Float(2.3)));
}
