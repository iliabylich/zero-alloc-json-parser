pub(crate) fn skip_zeroes(data: &[u8]) -> (&[u8], usize) {
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0 {
            i += 1;
        } else {
            break;
        }
    }
    (&data[i..], i)
}
