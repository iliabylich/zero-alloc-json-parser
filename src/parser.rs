use crate::tlv::{DecodeTLV, RewriteToTLV};

pub struct Parser;

impl RewriteToTLV<'_> for Parser {
    type ExtraPayload = ();

    type ReturnType = ();

    fn rewrite_to_tlv(
        _data: &mut [u8],
        _start: usize,
        _end: usize,
        _extra: Self::ExtraPayload,
    ) -> Self::ReturnType {
        todo!()
    }
}

impl DecodeTLV for Parser {
    type ReturnType = ();

    fn decode_tlv(_data: &[u8]) -> Self::ReturnType {
        todo!()
    }
}
