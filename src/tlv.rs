pub(crate) trait RewriteToTLV<'a> {
    type ExtraPayload;
    type ReturnType;

    fn rewrite_to_tlv(
        data: &mut [u8],
        start: usize,
        end: usize,
        extra: Self::ExtraPayload,
    ) -> Self::ReturnType;
}

pub(crate) trait DecodeTLV<'a> {
    type ReturnType;

    fn decode_tlv(data: &'a [u8]) -> Self::ReturnType;
}
