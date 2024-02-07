pub(crate) trait RewriteToTLV {
    type ExtraPayload;
    type ReturnType;

    fn rewrite_to_tlv(
        data: &mut [u8],
        extra: Self::ExtraPayload,
    ) -> Option<(Self::ReturnType, usize)>;
}

pub(crate) trait DecodeTLV<'a> {
    type ReturnType;

    fn decode_tlv(data: &'a [u8]) -> Self::ReturnType;
}
