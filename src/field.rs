use crate::bn254::Field;
use acir::{AcirField, FieldElement};
use acir_field::FieldElement as FE;
use std::convert::TryInto;

pub type CircuitFieldElement = FieldElement;

pub fn from_be_bytes(bytes: &[u8; 32]) -> CircuitFieldElement {
    FE::from_be_bytes_reduce(bytes)
}

pub fn from_bn254(field: &Field) -> CircuitFieldElement {
    from_be_bytes(field.as_ref())
}

pub fn to_be_bytes(fe: CircuitFieldElement) -> [u8; 32] {
    fe.to_be_bytes().try_into().expect("acir field encodes to 32 bytes")
}
