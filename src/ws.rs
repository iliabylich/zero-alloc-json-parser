pub(crate) fn skip_ws(data: &mut [u8]) -> usize {
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b' ' | b'\t' | b'\n' | b'\r' => {
                data[i] = 0;
                i += 1
            }
            _ => break,
        }
    }
    i
}
