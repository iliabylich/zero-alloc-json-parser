pub(crate) trait BitmixToTLV {
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()>;
}

pub(crate) trait DecodeTLV<'a> {
    type ReturnType;

    fn decode_tlv(data: &'a [u8], pos: &mut usize) -> Option<Self::ReturnType>;

    #[must_use]
    fn skip_tlv(data: &'a [u8], pos: &mut usize) -> bool {
        Self::decode_tlv(data, pos).is_some()
    }
}

pub(crate) fn bitmix_consume_byte<const B: u8>(data: &mut [u8], pos: &mut usize) -> bool {
    if data[*pos] == B {
        data[*pos] = 0;
        *pos += 1;
        true
    } else {
        false
    }
}
