use crate::{
    array::Array,
    object::Object,
    skip_zeroes::skip_zeroes,
    string::String,
    tlv::{DecodeTLV, DecodingResult},
    value::Value,
};

pub struct ArrayIterator<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for ArrayIterator<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.data = skip_zeroes(self.data);
        let DecodingResult {
            value: element,
            size: read,
        } = Value::decode_tlv(self.data)?;
        self.data = &self.data[read..];
        Some(element)
    }
}

impl<'a> Array<'a> {
    pub fn iter(&self) -> ArrayIterator<'a> {
        ArrayIterator { data: self.data }
    }
}

pub struct ObjectIterator<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for ObjectIterator<'a> {
    type Item = (&'a [u8], Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        self.data = skip_zeroes(self.data);
        if self.data.is_empty() {
            return None;
        }
        let DecodingResult {
            value: key,
            size: read,
        } = String::decode_tlv(self.data)?;
        self.data = &self.data[read..];
        self.data = skip_zeroes(self.data);
        let DecodingResult { value, size: read } = Value::decode_tlv(self.data)?;
        self.data = &self.data[read..];
        Some((key, value))
    }
}

impl<'a> Object<'a> {
    pub fn iter(&self) -> ObjectIterator<'a> {
        ObjectIterator { data: self.data }
    }
}
