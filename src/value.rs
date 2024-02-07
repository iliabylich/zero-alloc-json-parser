use crate::{
    array::Array,
    number::{IntOrFloat, Number},
    object::Object,
    skip_zeroes::skip_zeroes,
    string::String,
    tlv::{DecodeTLV, RewriteToTLV},
    true_false_null::TrueFalseNull,
    ws::scan_ws,
};

#[derive(Debug)]
pub enum Value<'a> {
    Object(Object<'a>),
    Array(Array<'a>),
    String(&'a str),
    Integer(i64),
    Float(f64),
    True,
    False,
    Null,
}

impl RewriteToTLV for Value<'_> {
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

impl<'a> DecodeTLV<'a> for Value<'a> {
    type ReturnType = Self;

    fn decode_tlv(mut data: &'a [u8]) -> Option<(Self::ReturnType, usize)> {
        data = skip_zeroes(data);

        if let Some((object, read)) = Object::decode_tlv(data) {
            Some((Value::Object(object), read))
        } else if let Some((array, read)) = Array::decode_tlv(data) {
            Some((Value::Array(array), read))
        } else if let Some((string, read)) = String::decode_tlv(data) {
            Some((Value::String(string), read))
        } else if let Some((number, read)) = Number::decode_tlv(data) {
            match number {
                IntOrFloat::Integer(i) => Some((Value::Integer(i), read)),
                IntOrFloat::Float(f) => Some((Value::Float(f), read)),
            }
        } else if let Some((true_false_null, read)) = TrueFalseNull::decode_tlv(data) {
            match true_false_null {
                TrueFalseNull::True => Some((Value::True, read)),
                TrueFalseNull::False => Some((Value::False, read)),
                TrueFalseNull::Null => Some((Value::Null, read)),
            }
        } else {
            None
        }
    }
}

impl<'a> Value<'a> {
    pub fn from_tlv(data: &'a [u8]) -> Option<Self> {
        let (decoded, _) = Self::decode_tlv(data)?;
        Some(decoded)
    }
}

#[test]
fn test_value() {
    let mut data = *br#"{
        "a": 1,
        "b": "string",
        "c": 2.3,
        "d": [1, "a"],
        "e": {
            "key1": "value",
            "key2": -2
        },
        "f": true,
        "g": false,
        "h": null
    }"#;

    let (_, rewritten) = Value::rewrite_to_tlv(&mut data, ()).unwrap();
    assert_eq!(rewritten, data.len());
}
