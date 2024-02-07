use crate::{
    number::{IntOrFloat, Number},
    tlv::{BitmixToTLV, DecodeTLV, DecodingResult},
};

#[test]
fn test_0() {
    let mut data = *b"0";
    let rewritten = Number::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [0b001_00000]);
    assert_eq!(rewritten, 1);

    let DecodingResult { value, size } = Number::decode_tlv(&data).unwrap();
    assert_eq!(value, IntOrFloat::Integer(0));
    assert_eq!(size, 1);
}

#[test]
fn test_1() {
    let mut data = *b"1";
    let rewritten = Number::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [0b001_00001]);
    assert_eq!(rewritten, 1);

    let DecodingResult { value, size } = Number::decode_tlv(&data).unwrap();
    assert_eq!(value, IntOrFloat::Integer(1));
    assert_eq!(size, 1);
}

#[test]
fn test_9() {
    let mut data = *b"9";
    let rewritten = Number::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [0b001_01001]);
    assert_eq!(rewritten, 1);

    let DecodingResult { value, size } = Number::decode_tlv(&data).unwrap();
    assert_eq!(value, IntOrFloat::Integer(9));
    assert_eq!(size, 1);
}

#[test]
fn test_69() {
    let mut data = *b"69";
    let rewritten = Number::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(data, [0b001_10110, 0b1010_1001]);
    assert_eq!(rewritten, 2);

    let DecodingResult { value, size } = Number::decode_tlv(&data).unwrap();
    assert_eq!(value, IntOrFloat::Integer(69));
    assert_eq!(size, 2);
}

#[test]
fn test_1234567890987654321() {
    let mut data = *b"1234567890987654321"; // 19 bytes = 0b10_011
    let rewritten = Number::bitmix_to_tlv(&mut data).unwrap();
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
    assert_eq!(rewritten, 19);

    let DecodingResult { value, size } = Number::decode_tlv(&data).unwrap();
    assert_eq!(value, IntOrFloat::Integer(1234567890987654321));
    assert_eq!(size, 19);
}

#[test]
fn test_minus_1() {
    let mut data = *b"-1"; // length = 2 = b10
    let rewritten = Number::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(
        data,
        [
            0b001_11010, // 000 = mask, 1 = multibyte, value = 0b1010 = MINUS
            0b1010_0001, // 0010 = length = 2, value = 1
        ]
    );
    assert_eq!(rewritten, 2);

    let DecodingResult { value, size } = Number::decode_tlv(&data).unwrap();
    assert_eq!(value, IntOrFloat::Integer(-1));
    assert_eq!(size, 2);
}

#[test]
fn test_two_point_three() {
    let mut data = *b"2.3"; // length = 3 = 0b11
    let rewritten = Number::bitmix_to_tlv(&mut data).unwrap();
    assert_eq!(
        data,
        [
            0b001_10010, // 000 = mask, 1 = multibyte, value = 0b0010 = 2
            0b1011_1100, // 0011 = length = 3, value = 12 = DOT
            0b0000_0011, // 0000 = length = 0, value = 3
        ]
    );
    assert_eq!(rewritten, 3);

    let DecodingResult { value, size } = Number::decode_tlv(&data).unwrap();
    assert_eq!(value, IntOrFloat::Float(2.3));
    assert_eq!(size, 3);
}
