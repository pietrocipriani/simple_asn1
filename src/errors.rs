use std::str::Utf8Error;

use thiserror::Error;

/// An error that can arise decoding ASN.1 primitive blocks.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ASN1DecodeErr {
    #[error("Encountered an empty buffer decoding ASN1 block.")]
    EmptyBuffer,
    #[error("Bad length field in boolean block: {0}")]
    BadBooleanLength(usize),
    #[error("Length field too large for object type: {0}")]
    LengthTooLarge(usize),
    #[error("UTF8 string failed to properly decode: {0}")]
    UTF8DecodeFailure(Utf8Error),
    #[error("Printable string failed to properly decode.")]
    PrintableStringDecodeFailure,
    #[error("Invalid date value: {0}")]
    InvalidDateValue(String),
    #[error("Invalid length of bit string: {0}")]
    InvalidBitStringLength(isize),
    /// Not a valid ASN.1 class
    #[error("Invalid class value: {0}")]
    InvalidClass(u8),
    /// Expected more input
    ///
    /// Invalid ASN.1 input can lead to this error.
    #[error("Incomplete data or invalid ASN1")]
    Incomplete,
    #[error("Value overflow")]
    Overflow,
}

/// An error that can arise encoding ASN.1 primitive blocks.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ASN1EncodeErr {
    #[error("ASN1 object identifier has too few fields.")]
    ObjectIdentHasTooFewFields,
    #[error("First value in ASN1 OID is too big.")]
    ObjectIdentVal1TooLarge,
    #[error("Second value in ASN1 OID is too big.")]
    ObjectIdentVal2TooLarge,
}

