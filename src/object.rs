use crate::{
    bytesize::Bytesize, mask::OBJECT_MASK, number::Number, string::String, tlv::RewriteToTLV,
    ws::scan_ws,
};

struct Object;

#[derive(Debug)]
enum State {
    ReadingKey,
    ReadingValue,
    ReadingColon,
    ReadingCommaOrEnd,
}

impl RewriteToTLV for Object {
    type ExtraPayload = ();

    type ReturnType = ();

    fn rewrite_to_tlv(data: &mut [u8], _: ()) -> Option<(Self::ReturnType, usize)> {
        if data[0] != b'{' {
            return None;
        }
        let mut region_size = 1;
        let mut found_end = false;
        let mut state = State::ReadingKey;
        let mut seen_comma = false;

        while region_size < data.len() {
            if let Some(skip_len) = scan_ws(&mut data[region_size..]) {
                region_size += skip_len;
            }

            match state {
                State::ReadingKey => {
                    if let Some((_, len)) = String::rewrite_to_tlv(&mut data[region_size..], ()) {
                        state = State::ReadingColon;
                        region_size += len;
                    } else if seen_comma {
                        // parse error
                        return None;
                    } else {
                        // empty object
                        state = State::ReadingCommaOrEnd;
                        continue;
                    }
                }
                State::ReadingValue => {
                    if let Some((_, len)) = Number::rewrite_to_tlv(&mut data[region_size..], ()) {
                        state = State::ReadingCommaOrEnd;
                        // TODO: change Number to Value once it's ready
                        region_size += len;
                    } else {
                        return None;
                    }
                }
                State::ReadingColon => {
                    if data[region_size] == b':' {
                        state = State::ReadingValue;
                        data[region_size] = 0;
                        region_size += 1;
                    } else {
                        return None;
                    }
                }
                State::ReadingCommaOrEnd => {
                    if data[region_size] == b'}' {
                        found_end = true;
                        break;
                    } else if data[region_size] == b',' {
                        state = State::ReadingKey;
                        data[region_size] = 0;
                        region_size += 1;
                        seen_comma = true;
                    } else {
                        return None;
                    }
                }
            }
        }
        if !found_end {
            return None;
        }

        data[0] = 0;
        data[region_size] = 0;

        Bytesize::write(&mut data[..region_size + 1], region_size + 1);
        data[0] |= OBJECT_MASK;

        Some(((), region_size + 1))
    }
}

#[test]
fn test_object_empty() {
    let mut data = *b"{}";
    let ((), rewritten) = Object::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(rewritten, 2);
    assert_eq!(data, [OBJECT_MASK | 2, 0]);
}

#[test]
fn test_object_small() {
    use crate::{bytesize::LONG_CONTAINER_MASK, mask::STRING_MASK};

    let mut data = *b"{\"a\": 1, \"b\": 2}";
    let ((), rewritten) = Object::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(rewritten, 16);
    assert_eq!(
        data,
        [
            // size is 16 = 10000
            OBJECT_MASK | LONG_CONTAINER_MASK | 0b000, // 3 trailing bits of length
            0b10,                                      // the rest of the length
            STRING_MASK | 1,
            b'a',
            0,
            0,
            0,
            0b001_00001,
            0,
            0,
            STRING_MASK | 1,
            b'b',
            0,
            0,
            0,
            0b001_00010,
        ]
    );
}
