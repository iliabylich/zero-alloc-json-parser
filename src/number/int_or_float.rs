#[derive(Debug, PartialEq)]
pub(crate) enum IntOrFloat {
    Integer {
        value: i64,
        negative: bool,
    },
    Float {
        value: f64,
        digits_after_dot: Option<u32>,
        negative: bool,
    },
}

use IntOrFloat::*;

impl IntOrFloat {
    pub(crate) fn append(&mut self, digit: u8) {
        match self {
            Integer { value, .. } => *value = *value * 10 + (digit as i64),
            Float {
                value,
                digits_after_dot: Some(digits_after_dot),
                ..
            } => {
                *value += (digit as f64) / (10_i32.pow(*digits_after_dot + 1) as f64);
                *digits_after_dot += 1;
            }
            Float { value, .. } => {
                *value = *value * 10.0 + (digit as f64);
            }
        }
    }

    pub(crate) fn negate(&mut self) {
        match self {
            Integer { negative: true, .. } | Float { negative: true, .. } => {
                panic!("internal error, double negative?")
            }
            Integer { negative, .. } | Float { negative, .. } => *negative = true,
        }
    }

    pub(crate) fn add_dot(&mut self) {
        match *self {
            Integer { value, negative } => {
                *self = Float {
                    value: value as f64,
                    digits_after_dot: Some(0),
                    negative,
                }
            }
            Float { .. } => panic!("internal error, double dot?"),
        }
    }

    pub(crate) fn unwrap_int(self) -> i64 {
        match self {
            Integer {
                value,
                negative: false,
            } => value,
            Integer {
                value,
                negative: true,
            } => -value,
            _ => panic!("not an integer"),
        }
    }

    pub(crate) fn unwrap_float(self) -> f64 {
        match self {
            Float {
                value,
                negative: false,
                ..
            } => value,
            Float {
                value,
                negative: true,
                ..
            } => -value,
            _ => panic!("not a float"),
        }
    }
}
