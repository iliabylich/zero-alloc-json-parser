use crate::{
    array::Array, number::Number, object::Object, string::String, tlv::RewriteToTLV,
    true_false_null::TrueFalseNull, ws::scan_ws,
};

pub(crate) struct Value;

impl RewriteToTLV for Value {
    type ExtraPayload = ();

    type ReturnType = ();

    fn rewrite_to_tlv(mut data: &mut [u8], _: ()) -> Option<(Self::ReturnType, usize)> {
        if let Some(len) = scan_ws(data) {
            data = &mut data[len..];
        }

        if data[0] == b'{' {
            Object::rewrite_to_tlv(data, ())
        } else if data[0] == b'[' {
            Array::rewrite_to_tlv(data, ())
        } else if data[0] == b'"' {
            String::rewrite_to_tlv(data, ())
        } else if data[0] == b'-' || matches!(data[0], b'0'..=b'9') {
            Number::rewrite_to_tlv(data, ())
        } else if data[0] == b't' || data[0] == b'f' || data[0] == b'n' {
            TrueFalseNull::rewrite_to_tlv(data, ())
        } else {
            None
        }
    }
}
