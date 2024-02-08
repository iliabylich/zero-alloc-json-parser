// We have 5 bytes after the initial mask, 0b11111 is the max value for 5 bits
//   1 in a leading bit indicates a two-byte bytesize,
//   0 means a single byte bytesize (i.e. out container is VERY short, max 0b1111 = 15 bytes)
// If the container is longer than 15 bytes, we need to shift it to the right
// and use one extra byte to store the bytesize of the container
const MAX_EMBEDDED_BYTESIZE: u8 = 15;
pub(crate) const LONG_CONTAINER_MASK: u8 = 0b10000;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Bytesize {
    pub(crate) bytesize: usize,
    pub(crate) offset: usize,
}

impl Bytesize {
    pub(crate) fn write(data: &mut [u8], start: usize, end: usize, bytesize: usize) {
        if bytesize > 2048 {
            panic!("container is too long, max 2048 bytes allowed")
        }
        let bytesize = bytesize as u8;

        if bytesize <= MAX_EMBEDDED_BYTESIZE {
            data[start] = bytesize;
            data[end - 1] = 0;
        } else {
            // long container, needs shifting
            data[start] = LONG_CONTAINER_MASK | (bytesize % 8);
            for idx in ((start + 1)..(end - 1)).rev() {
                data[idx + 1] = data[idx];
            }
            data[start + 1] = bytesize >> 3;
        }
    }

    pub(crate) fn read(data: &[u8], pos: usize) -> Self {
        let l1 = data[pos] & 0b1111;
        let mut l2 = 0;
        let mut offset = 1;
        if data[pos] & LONG_CONTAINER_MASK == LONG_CONTAINER_MASK {
            l2 = data[pos + 1];
            offset = 2;
        }
        let bytesize = (l2 as usize) << 3 | l1 as usize;
        Self { bytesize, offset }
    }
}
