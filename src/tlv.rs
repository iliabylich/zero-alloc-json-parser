pub(crate) trait BitmixToTLV {
    type ReturnType;

    fn bitmix_to_tlv(data: &mut [u8]) -> Option<(Self::ReturnType, usize)>;
}

pub(crate) trait DecodeTLV<'a> {
    type ReturnType;

    fn decode_tlv(data: &'a [u8]) -> Option<(Self::ReturnType, usize)>;
}
