pub(crate) fn skip_zeroes(data: &[u8], pos: &mut usize) {
    while *pos < data.len() {
        if data[*pos] == 0 {
            *pos += 1;
        } else {
            break;
        }
    }
}
