use crate::{bytesize::Bytesize, mask::ARRAY_MASK, number::Number, tlv::RewriteToTLV, ws::scan_ws};

struct Array;

impl RewriteToTLV for Array {
    type ExtraPayload = ();

    type ReturnType = ();

    fn rewrite_to_tlv(data: &mut [u8], _: ()) -> Option<(Self::ReturnType, usize)> {
        if data[0] != b'[' {
            return None;
        }
        let mut region_size = 1;
        let mut found_end = false;

        while region_size < data.len() {
            if data[region_size] == b']' {
                found_end = true;
                break;
            } else if data[region_size] == b',' {
                data[region_size] = 0;
                region_size += 1;
            } else if let Some(skip_len) = scan_ws(&mut data[region_size..]) {
                region_size += skip_len;
            } else if let Some((_, len)) = Number::rewrite_to_tlv(&mut data[region_size..], ()) {
                // TODO: change Number to Value once it's ready
                region_size += len;
            } else {
                return None;
            }
        }
        if !found_end {
            return None;
        }

        data[0] = 0;
        data[region_size] = 0;

        Bytesize::write(&mut data[..region_size + 1], region_size + 1);
        data[0] |= ARRAY_MASK;

        Some(((), region_size + 1))
    }
}

#[test]
fn test_array_empty() {
    let mut data = *b"[]";
    let ((), rewritten) = Array::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(rewritten, 2);
    assert_eq!(data, [ARRAY_MASK | 2, 0]);
}

#[test]
fn test_array_short() {
    let mut data = *b"[1, 2, 3]";
    let ((), rewritten) = Array::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(rewritten, 9);
    assert_eq!(
        data,
        [
            ARRAY_MASK | 9,
            0b001_00001,
            0,
            0,
            0b001_00010,
            0,
            0,
            0b001_00011,
            0
        ]
    );
}

#[test]
fn test_array_long() {
    use crate::bytesize::LONG_CONTAINER_MASK;

    let mut data = *b"[1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2]";
    let ((), rewritten) = Array::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(rewritten, 48);
    assert_eq!(
        data,
        [
            // length is 48 = 0b110000
            ARRAY_MASK | LONG_CONTAINER_MASK | 0b000, // 3 trailing bits of length
            0b110,                                    // the rest of the length
            0b001_00001,                              // 1
            0,
            0,
            0b001_00010, // 2
            0,
            0,
            0b001_00011, // 3
            0,
            0,
            0b001_00100, // 4
            0,
            0,
            0b001_00101, // 5
            0,
            0,
            0b001_00110, // 6
            0,
            0,
            0b001_00111, // 7
            0,
            0,
            0b001_01000, // 8
            0,
            0,
            0b001_01001, // 9
            0,
            0,
            0b001_01000, // 8
            0,
            0,
            0b001_00111, // 7
            0,
            0,
            0b001_00110, // 6
            0,
            0,
            0b001_00101, // 5
            0,
            0,
            0b001_00100, // 4
            0,
            0,
            0b001_00011, // 3
            0,
            0,
            0b001_00010, // 2
        ]
    );
}
