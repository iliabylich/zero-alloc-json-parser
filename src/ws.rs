pub(crate) fn scan_ws(data: &mut [u8]) -> Option<usize> {
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
    if i == 0 {
        None
    } else {
        Some(i)
    }
}
