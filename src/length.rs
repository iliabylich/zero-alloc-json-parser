// We have 5 bytes after the initial mask, 0b11111 is the max value for 5 bits
//   1 in a leading bit indicates a two-byte length,
//   0 means a single byte length (i.e. out container is VERY short, max 0b1111 = 15 bytes)
// If the container is longer than 15 bytes, we need to shift it to the right
// and use one extra byte to store the length of the container
const MAX_EMBEDDED_LENGTH: usize = 15;
pub(crate) const LONG_CONTAINER_MASK: u8 = 0b10000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Length {
    pub(crate) length: usize,
    pub(crate) offset: usize,
}

impl Length {
    pub(crate) fn write(data: &mut [u8], mut length: usize) {
        if length > 2048 {
            panic!("container is too long, max 2048 bytes allowed")
        }

        if length <= MAX_EMBEDDED_LENGTH {
            data[0] = length as u8;
            data[data.len() - 1] = 0;
        } else {
            // long container, needs shifting
            let three_bytes_of_length = (length % 8) as u8;
            length >>= 3;
            data[0] = LONG_CONTAINER_MASK | three_bytes_of_length;
            for idx in (1..(data.len() - 1)).rev() {
                data[idx + 1] = data[idx];
            }
            data[1] = length as u8;
        }
    }

    pub(crate) fn read(data: &[u8]) -> Self {
        let l1 = data[0] & 0b1111;
        let mut l2 = 0;
        let mut offset = 1;
        if data[0] & LONG_CONTAINER_MASK == LONG_CONTAINER_MASK {
            l2 = data[1];
            offset = 2;
        }
        let length = (l2 as usize) << 3 | l1 as usize;
        Self { length, offset }
    }
}
