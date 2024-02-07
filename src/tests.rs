extern crate std;

use std::{fmt::Write, string::String};

use crate::{value::Value, Parser};

#[test]
fn test_parser() {
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

    Parser::to_tlv(&mut data).unwrap();
    let result = Value::from_tlv(&data).unwrap();

    let mut buf = String::with_capacity(1024);
    visit_and_encode(result, &mut buf).unwrap();

    assert_eq!(
        buf,
        r#"{"a": 1, "b": "string", "c": 2.3, "d": [1, "a", ], "e": {"key1": "value", "key2": -2, }, "f": true, "g": false, "h": null, }"#
    )
}

fn visit_and_encode(something: Value, out: &mut String) -> Result<(), std::fmt::Error> {
    match something {
        Value::Object(object) => {
            write!(out, "{{")?;
            for (key, value) in object.iter() {
                write!(out, "\"{}\": ", std::str::from_utf8(key).unwrap())?;
                visit_and_encode(value, out)?;
                write!(out, ", ")?;
            }
            write!(out, "}}")?;
        }
        Value::Array(array) => {
            write!(out, "[")?;
            for value in array.iter() {
                visit_and_encode(value, out)?;
                write!(out, ", ")?;
            }
            write!(out, "]")?;
        }
        Value::String(string) => {
            write!(out, "\"{}\"", std::str::from_utf8(string).unwrap())?;
        }
        Value::Integer(int) => {
            write!(out, "{}", int)?;
        }
        Value::Float(float) => {
            write!(out, "{}", float)?;
        }
        Value::True => {
            write!(out, "true")?;
        }
        Value::False => {
            write!(out, "false")?;
        }
        Value::Null => {
            write!(out, "null")?;
        }
    }

    Ok(())
}
