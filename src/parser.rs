use crate::{
    tlv::{BitmixToTLV, DecodeTLV},
    value::Value,
};

pub struct Parser;

impl Parser {
    pub fn parse(data: &mut [u8]) -> Option<Value<'_>> {
        Value::bitmix_to_tlv(data, ())?;
        Some(Value::decode_tlv(data)?.0)
    }
}
