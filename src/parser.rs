use crate::{
    tlv::{BitmixToTLV, DecodeTLV},
    value::Value,
};

pub struct Parser;

impl Parser {
    pub fn parse(data: &mut [u8]) -> Option<Value<'_>> {
        let mut pos = 0;
        Value::bitmix_to_tlv(data, &mut pos)?;

        pos = 0;
        Value::decode_tlv(data, &mut pos)
    }
}
