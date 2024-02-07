use crate::{tlv::RewriteToTLV, value::Value};

pub struct Parser;

impl Parser {
    pub fn to_tlv(data: &mut [u8]) -> Option<()> {
        Value::rewrite_to_tlv(data, ()).map(|_| ())
    }
}
