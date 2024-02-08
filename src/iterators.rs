use crate::{
    array::Array, object::Object, skip_zeroes::skip_zeroes, string::String, tlv::DecodeTLV,
    value::Value,
};

pub struct ArrayIterator<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for ArrayIterator<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        skip_zeroes(self.data, &mut self.pos);
        let value = Value::decode_tlv(self.data, &mut self.pos)?;
        Some(value)
    }
}

impl<'a> Array<'a> {
    pub fn iter(&self) -> ArrayIterator<'a> {
        ArrayIterator {
            data: self.data,
            pos: 0,
        }
    }
}

pub struct ObjectIterator<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for ObjectIterator<'a> {
    type Item = (&'a [u8], Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        skip_zeroes(self.data, &mut self.pos);
        if self.pos >= self.data.len() {
            return None;
        }
        let key = String::decode_tlv(self.data, &mut self.pos)?;
        skip_zeroes(self.data, &mut self.pos);
        let value = Value::decode_tlv(self.data, &mut self.pos)?;
        Some((key, value))
    }
}

impl<'a> Object<'a> {
    pub fn iter(&self) -> ObjectIterator<'a> {
        ObjectIterator {
            data: self.data,
            pos: 0,
        }
    }
}
