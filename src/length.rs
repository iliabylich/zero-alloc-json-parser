// We have 5 bytes after the initial mask, 0b11111 is the max value for 5 bits
// So we end up having 5 + 8 = 13 bytes for length (i.e. 8192(-1) elements can be stored at max)
const MAX_LENGTH: usize = 2_usize.pow(13);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Length(pub(crate) usize);

impl Length {
    pub(crate) fn write(data: &mut [u8], start: usize, end: usize, length: usize) {
        if length >= MAX_LENGTH {
            panic!(
                "container is too long, max {} bytes allowed",
                MAX_LENGTH - 1
            )
        }

        for idx in ((start)..(end - 1)).rev() {
            data[idx + 1] = data[idx];
        }

        let (l1, l2) = split(length);
        data[start] = l1;
        data[start + 1] = l2;
    }

    pub(crate) fn read(data: &[u8], pos: usize) -> Self {
        let l1 = data[pos] & 0b11111;
        let l2 = data[pos + 1];
        let length = join(l1, l2);
        Self(length)
    }
}

fn split(length: usize) -> (u8, u8) {
    let l1 = length as u8 & 0b11111;
    let l2 = (length >> 5) as u8;
    (l1, l2)
}

fn join(l1: u8, l2: u8) -> usize {
    (l2 as usize) << 5 | l1 as usize
}

#[test]
fn test_length() {
    let mut data = *b" \"hello\"";
    Length::write(&mut data, 1, 8, 5);
    assert_eq!(
        data,
        [
            b' ',  // length = 5 = 0b101
            0b101, // 5 trailing bits
            0b0,   // 8 leading bits
            b'h', b'e', b'l', b'l', b'o'
        ]
    );

    let length = Length::read(&data, 1);
    assert_eq!(length.0, 5);
}
