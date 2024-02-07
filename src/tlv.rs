pub(crate) trait BitmixToTLV {
    type ExtraPayload;
    type ReturnType;

    fn bitmix_to_tlv(
        data: &mut [u8],
        extra: Self::ExtraPayload,
    ) -> Option<(Self::ReturnType, usize)>;
}

pub(crate) trait DecodeTLV<'a> {
    type ReturnType;

    fn decode_tlv(data: &'a [u8]) -> Option<(Self::ReturnType, usize)>;
}
