use crate::{tlv::RewriteToTLV, value::Value};

// extern crate std;

#[test]
fn test_parse() {
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
