use crate::{number::Number, tlv::RewriteToTLV, ws::scan_ws};

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
        // TODO: encode length
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

        Some(((), region_size + 1))
    }
}

#[test]
fn test_array_empty() {
    let mut data = *b"[]";
    let ((), len) = Array::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(len, 2);
    assert_eq!(&data, b"\0\0");
}

#[test]
fn test_array_non_empty() {
    let mut data = *b"[1, 2, 3]";
    let ((), len) = Array::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(len, 9);
    assert_eq!(
        data,
        [0, 0b001_00001, 0, 0, 0b001_00010, 0, 0, 0b001_00011, 0]
    );
}
