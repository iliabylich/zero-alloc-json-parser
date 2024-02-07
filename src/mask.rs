// 3 bytes for values (7 variants, ceil(log2(7)) = 3)
pub(crate) const NUMBER_MASK: u8 /* | */ = 0b001_00000;
pub(crate) const STRING_MASK: u8 /* | */ = 0b010_00000;
pub(crate) const _ARRAY_MASK: u8 /*  | */ = 0b011_00000;
pub(crate) const _OBJECT_MASK: u8 /* | */ = 0b100_00000;
pub(crate) const NULL_MASK: u8 /*   | */ = 0b101_00000;
pub(crate) const TRUE_MASK: u8 /*   | */ = 0b110_00000;
pub(crate) const FALSE_MASK: u8 /*  | */ = 0b111_00000;
