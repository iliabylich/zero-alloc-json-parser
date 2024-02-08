pub(crate) fn skip_ws(data: &mut [u8], pos: &mut usize) {
    while *pos < data.len() {
        match data[*pos] {
            b' ' | b'\t' | b'\n' | b'\r' => {
                data[*pos] = 0;
                *pos += 1
            }
            _ => break,
        }
    }
}
