#[derive(Debug, PartialEq)]
pub(crate) enum IntOrFloat {
    Integer(i64),
    Float(f64),
}

use IntOrFloat::*;

impl IntOrFloat {
    pub(crate) fn add(self, digit: u8) -> Self {
        match self {
            Integer(value) => Integer(value * 10 + (digit as i64)),
            Float(value) => Float(value * 10.0 + (digit as f64)),
        }
    }

    pub(crate) fn make_float(self) -> Self {
        match self {
            Integer(value) => Float(value as f64),
            Float(_) => panic!("internal error, double dot?"),
        }
    }

    pub(crate) fn negate(self) -> Self {
        match self {
            Integer(value) => Integer(-value),
            Float(value) => Float(-value),
        }
    }
}
