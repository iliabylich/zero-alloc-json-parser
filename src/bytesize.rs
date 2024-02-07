// We have 5 bytes after the initial mask, 0b11111 is the max value for 5 bits
//   1 in a leading bit indicates a two-byte bytesize,
//   0 means a single byte bytesize (i.e. out container is VERY short, max 0b1111 = 15 bytes)
// If the container is longer than 15 bytes, we need to shift it to the right
// and use one extra byte to store the bytesize of the container
const MAX_EMBEDDED_BYTESIZE: usize = 15;
pub(crate) const LONG_CONTAINER_MASK: u8 = 0b10000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Bytesize {
    pub(crate) bytesize: usize,
    pub(crate) offset: usize,
}

impl Bytesize {
    pub(crate) fn write(data: &mut [u8], mut bytesize: usize) {
        if bytesize > 2048 {
            panic!("container is too long, max 2048 bytes allowed")
        }

        if bytesize <= MAX_EMBEDDED_BYTESIZE {
            data[0] = bytesize as u8;
            data[data.len() - 1] = 0;
        } else {
            // long container, needs shifting
            let three_bytes_of_bytesize = (bytesize % 8) as u8;
            bytesize >>= 3;
            data[0] = LONG_CONTAINER_MASK | three_bytes_of_bytesize;
            for idx in (1..(data.len() - 1)).rev() {
                data[idx + 1] = data[idx];
            }
            data[1] = bytesize as u8;
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
        let bytesize = (l2 as usize) << 3 | l1 as usize;
        Self { bytesize, offset }
    }
}
