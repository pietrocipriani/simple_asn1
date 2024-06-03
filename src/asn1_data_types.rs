use num_bigint::{BigInt, BigUint};
use time::PrimitiveDateTime;

use crate::oid::OID;

/// An ASN.1 block class.
///
/// I'm not sure if/when these are used, but here they are in case you want
/// to do something with them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ASN1Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

/// A primitive block from ASN.1.
///
/// Primitive blocks all contain the offset from the beginning of the parsed
/// document, followed by whatever data is associated with the block. The latter
/// should be fairly self-explanatory, so let's discuss the offset.
///
/// The offset is only valid during the reading process. It is ignored for
/// the purposes of encoding blocks into their binary form. It is also
/// ignored for the purpose of comparisons via `==`. It is included entirely
/// to support the parsing of things like X509 certificates, in which it is
/// necessary to know when particular blocks end.
///
/// The [`ASN1Class`] of explicitly tagged blocks is either `Application`,
/// `ContextSpecific` or `Private`. `Unknown` can have any class.
/// The class of all other variants is `Universal`.
///
/// [`ASN1Class`]: enum.ASN1Class.html
#[derive(Clone, Debug)]
pub enum ASN1Block {
    Boolean(usize, bool),
    Integer(usize, BigInt),
    BitString(usize, usize, Vec<u8>),
    OctetString(usize, Vec<u8>),
    Null(usize),
    ObjectIdentifier(usize, OID),
    UTF8String(usize, String),
    PrintableString(usize, String),
    TeletexString(usize, String),
    IA5String(usize, String),
    UTCTime(usize, PrimitiveDateTime),
    GeneralizedTime(usize, PrimitiveDateTime),
    UniversalString(usize, String),
    BMPString(usize, String),
    Sequence(usize, Vec<ASN1Block>),
    Set(usize, Vec<ASN1Block>),
    /// An explicitly tagged block.
    ///
    /// The class can be either `Application`, `ContextSpecific` or `Private`.
    /// The other parameters are `offset`, `tag` and `content`.
    ///
    /// This block is always `constructed`.
    Explicit(ASN1Class, usize, BigUint, Box<ASN1Block>),
    /// An unkown block.
    ///
    /// The parameters are `class`, `constructed`, `offset`, `tag` and
    /// `content`.
    Unknown(ASN1Class, bool, usize, BigUint, Vec<u8>),
}

impl ASN1Block {
    /// Get the class associated with the given ASN1Block, regardless of what
    /// kind of block it is.
    pub fn class(&self) -> ASN1Class {
        match *self {
            ASN1Block::Boolean(_, _) => ASN1Class::Universal,
            ASN1Block::Integer(_, _) => ASN1Class::Universal,
            ASN1Block::BitString(_, _, _) => ASN1Class::Universal,
            ASN1Block::OctetString(_, _) => ASN1Class::Universal,
            ASN1Block::Null(_) => ASN1Class::Universal,
            ASN1Block::ObjectIdentifier(_, _) => ASN1Class::Universal,
            ASN1Block::UTF8String(_, _) => ASN1Class::Universal,
            ASN1Block::PrintableString(_, _) => ASN1Class::Universal,
            ASN1Block::TeletexString(_, _) => ASN1Class::Universal,
            ASN1Block::IA5String(_, _) => ASN1Class::Universal,
            ASN1Block::UTCTime(_, _) => ASN1Class::Universal,
            ASN1Block::GeneralizedTime(_, _) => ASN1Class::Universal,
            ASN1Block::UniversalString(_, _) => ASN1Class::Universal,
            ASN1Block::BMPString(_, _) => ASN1Class::Universal,
            ASN1Block::Sequence(_, _) => ASN1Class::Universal,
            ASN1Block::Set(_, _) => ASN1Class::Universal,
            ASN1Block::Explicit(c, _, _, _) => c,
            ASN1Block::Unknown(c, _, _, _, _) => c,
        }
    }
    /// Get the starting offset associated with the given ASN1Block, regardless
    /// of what kind of block it is.
    pub fn offset(&self) -> usize {
        match *self {
            ASN1Block::Boolean(o, _) => o,
            ASN1Block::Integer(o, _) => o,
            ASN1Block::BitString(o, _, _) => o,
            ASN1Block::OctetString(o, _) => o,
            ASN1Block::Null(o) => o,
            ASN1Block::ObjectIdentifier(o, _) => o,
            ASN1Block::UTF8String(o, _) => o,
            ASN1Block::PrintableString(o, _) => o,
            ASN1Block::TeletexString(o, _) => o,
            ASN1Block::IA5String(o, _) => o,
            ASN1Block::UTCTime(o, _) => o,
            ASN1Block::GeneralizedTime(o, _) => o,
            ASN1Block::UniversalString(o, _) => o,
            ASN1Block::BMPString(o, _) => o,
            ASN1Block::Sequence(o, _) => o,
            ASN1Block::Set(o, _) => o,
            ASN1Block::Explicit(_, o, _, _) => o,
            ASN1Block::Unknown(_, _, o, _, _) => o,
        }
    }
}

impl PartialEq for ASN1Block {
    fn eq(&self, other: &ASN1Block) -> bool {
        match (self, other) {
            (&ASN1Block::Boolean(_, a1), &ASN1Block::Boolean(_, a2)) => a1 == a2,
            (&ASN1Block::Integer(_, ref a1), &ASN1Block::Integer(_, ref a2)) => a1 == a2,
            (&ASN1Block::BitString(_, a1, ref b1), &ASN1Block::BitString(_, a2, ref b2)) => {
                (a1 == a2) && (b1 == b2)
            }
            (&ASN1Block::OctetString(_, ref a1), &ASN1Block::OctetString(_, ref a2)) => a1 == a2,
            (&ASN1Block::Null(_), &ASN1Block::Null(_)) => true,
            (&ASN1Block::ObjectIdentifier(_, ref a1), &ASN1Block::ObjectIdentifier(_, ref a2)) => {
                a1 == a2
            }
            (&ASN1Block::UTF8String(_, ref a1), &ASN1Block::UTF8String(_, ref a2)) => a1 == a2,
            (&ASN1Block::PrintableString(_, ref a1), &ASN1Block::PrintableString(_, ref a2)) => {
                a1 == a2
            }
            (&ASN1Block::TeletexString(_, ref a1), &ASN1Block::TeletexString(_, ref a2)) => {
                a1 == a2
            }
            (&ASN1Block::IA5String(_, ref a1), &ASN1Block::IA5String(_, ref a2)) => a1 == a2,
            (&ASN1Block::UTCTime(_, ref a1), &ASN1Block::UTCTime(_, ref a2)) => a1 == a2,
            (&ASN1Block::GeneralizedTime(_, ref a1), &ASN1Block::GeneralizedTime(_, ref a2)) => {
                a1 == a2
            }
            (&ASN1Block::UniversalString(_, ref a1), &ASN1Block::UniversalString(_, ref a2)) => {
                a1 == a2
            }
            (&ASN1Block::BMPString(_, ref a1), &ASN1Block::BMPString(_, ref a2)) => a1 == a2,
            (&ASN1Block::Sequence(_, ref a1), &ASN1Block::Sequence(_, ref a2)) => a1 == a2,
            (&ASN1Block::Set(_, ref a1), &ASN1Block::Set(_, ref a2)) => a1 == a2,
            (
                &ASN1Block::Explicit(a1, _, ref b1, ref c1),
                &ASN1Block::Explicit(a2, _, ref b2, ref c2),
            ) => (a1 == a2) && (b1 == b2) && (c1 == c2),
            (
                &ASN1Block::Unknown(a1, b1, _, ref c1, ref d1),
                &ASN1Block::Unknown(a2, b2, _, ref c2, ref d2),
            ) => (a1 == a2) && (b1 == b2) && (c1 == c2) && (d1 == d2),
            _ => false,
        }
    }
}

