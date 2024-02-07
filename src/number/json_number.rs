#[derive(Debug, PartialEq)]
pub(crate) enum JsonNumber {
    Integer(i64),
    Float(f64),
}

impl JsonNumber {
    pub(crate) fn add(self, digit: u8) -> Self {
        match self {
            Self::Integer(value) => Self::Integer(value * 10 + (digit as i64)),
            Self::Float(value) => Self::Float(value * 10.0 + (digit as f64)),
        }
    }

    pub(crate) fn make_float(self) -> Self {
        match self {
            Self::Integer(value) => Self::Float(value as f64),
            Self::Float(_) => panic!("internal error, double dot?"),
        }
    }

    pub(crate) fn negate(self) -> Self {
        match self {
            Self::Integer(value) => Self::Integer(-value),
            Self::Float(value) => Self::Float(-value),
        }
    }
}
