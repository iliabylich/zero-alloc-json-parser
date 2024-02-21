use crate::{
    array::Array,
    number::{IntOrFloat, Number},
    object::Object,
    skip_zeroes::skip_zeroes,
    string::String,
    tlv::{BitmixToTLV, DecodeTLV},
    true_false_null::TrueFalseNull,
    ws::skip_ws,
};

#[derive(Debug)]
pub enum Value<'a> {
    Object(Object<'a>),
    Array(Array<'a>),
    String(&'a [u8]),
    Integer(i64),
    Float(f64),
    True,
    False,
    Null,
}

impl<'a> From<Object<'a>> for Value<'a> {
    fn from(object: Object<'a>) -> Self {
        Value::Object(object)
    }
}

impl<'a> From<Array<'a>> for Value<'a> {
    fn from(array: Array<'a>) -> Self {
        Value::Array(array)
    }
}

impl<'a> From<&'a [u8]> for Value<'a> {
    fn from(string: &'a [u8]) -> Self {
        Value::String(string)
    }
}

impl From<IntOrFloat> for Value<'_> {
    fn from(int_or_float: IntOrFloat) -> Self {
        match int_or_float {
            IntOrFloat::Integer { .. } => Value::Integer(int_or_float.unwrap_int()),
            IntOrFloat::Float { .. } => Value::Float(int_or_float.unwrap_float()),
        }
    }
}

impl From<f64> for Value<'_> {
    fn from(float: f64) -> Self {
        Value::Float(float)
    }
}

impl From<TrueFalseNull> for Value<'_> {
    fn from(true_false_null: TrueFalseNull) -> Self {
        match true_false_null {
            TrueFalseNull::True => Value::True,
            TrueFalseNull::False => Value::False,
            TrueFalseNull::Null => Value::Null,
        }
    }
}

impl BitmixToTLV for Value<'_> {
    fn bitmix_to_tlv(data: &mut [u8], pos: &mut usize) -> Option<()> {
        skip_ws(data, pos);

        None.or_else(|| Object::bitmix_to_tlv(data, pos))
            .or_else(|| Array::bitmix_to_tlv(data, pos))
            .or_else(|| String::bitmix_to_tlv(data, pos))
            .or_else(|| Number::bitmix_to_tlv(data, pos))
            .or_else(|| TrueFalseNull::bitmix_to_tlv(data, pos))
    }
}

impl<'a> DecodeTLV<'a> for Value<'a> {
    type ReturnType = Self;

    fn decode_tlv(data: &'a [u8], pos: &mut usize) -> Option<Self::ReturnType> {
        skip_zeroes(data, pos);

        None.or_else(|| Object::decode_tlv(data, pos).map(Value::from))
            .or_else(|| Array::decode_tlv(data, pos).map(Value::from))
            .or_else(|| String::decode_tlv(data, pos).map(Value::from))
            .or_else(|| Number::decode_tlv(data, pos).map(Value::from))
            .or_else(|| TrueFalseNull::decode_tlv(data, pos).map(Value::from))
    }

    fn skip_tlv(data: &[u8], pos: &mut usize) -> bool {
        Object::skip_tlv(data, pos)
            || Array::skip_tlv(data, pos)
            || String::skip_tlv(data, pos)
            || Number::skip_tlv(data, pos)
            || TrueFalseNull::skip_tlv(data, pos)
    }
}

impl<'a> Value<'a> {
    pub fn from_tlv(data: &'a [u8]) -> Option<Self> {
        let mut pos = 0;
        let value = Self::decode_tlv(data, &mut pos)?;
        Some(value)
    }
}

#[test]
fn test_value() {
    let mut pos = 1;
    let mut data = *br#" {
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

    Value::bitmix_to_tlv(&mut data, &mut pos).unwrap();
    assert_eq!(pos, data.len());
}
