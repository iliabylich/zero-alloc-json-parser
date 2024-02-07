pub(crate) trait BitmixToTLV {
    fn bitmix_to_tlv(data: &mut [u8]) -> Option<usize>;
}

pub(crate) trait DecodeTLV<'a> {
    type ReturnType;

    fn decode_tlv(data: &'a [u8]) -> Option<(Self::ReturnType, usize)>;
}
