use crate::tlv::{DecodeTLV, RewriteToTLV};

pub struct Parser;

impl RewriteToTLV for Parser {
    type ExtraPayload = ();

    type ReturnType = ();

    fn rewrite_to_tlv(
        _data: &mut [u8],
        _extra: Self::ExtraPayload,
    ) -> Option<(Self::ReturnType, usize)> {
        todo!()
    }
}

impl DecodeTLV<'_> for Parser {
    type ReturnType = ();

    fn decode_tlv(_data: &[u8]) -> Self::ReturnType {
        todo!()
    }
}
