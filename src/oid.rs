use std::convert::TryFrom;

use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};

use crate::{encode, errors::{ASN1DecodeErr, ASN1EncodeErr}};


/// An ASN.1 OID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OID(pub Vec<BigUint>);

impl OID {
    /// Generate an ASN.1. The vector should be in the obvious format,
    /// with each component going left-to-right.
    pub fn new(x: Vec<BigUint>) -> OID {
        OID(x)
    }

    /// converts the
    pub fn as_raw(&self) -> Result<Vec<u8>, ASN1EncodeErr> {
        match (self.0.first(), self.0.get(1)) {
            (Some(v1), Some(v2)) => {
                let two = BigUint::from_u8(2).unwrap();

                // first, validate that the first two items meet spec
                if v1 > &two {
                    return Err(ASN1EncodeErr::ObjectIdentVal1TooLarge);
                }

                let u175 = BigUint::from_u8(175).unwrap();
                let u39 = BigUint::from_u8(39).unwrap();
                let bound = if v1 == &two { u175 } else { u39 };

                if v2 > &bound {
                    return Err(ASN1EncodeErr::ObjectIdentVal2TooLarge);
                }

                // the following unwraps must be safe, based on the
                // validation above.
                let value1 = v1.to_u8().unwrap();
                let value2 = v2.to_u8().unwrap();
                let byte1 = (value1 * 40) + value2;

                // now we can build all the rest of the body
                let mut body = vec![byte1];
                for num in self.0.iter().skip(2) {
                    let mut local = encode::base127(num);
                    body.append(&mut local);
                }

                Ok(body)
            }
            _ => Err(ASN1EncodeErr::ObjectIdentHasTooFewFields),
        }
    }

    pub fn as_vec<'a, T: TryFrom<&'a BigUint>>(&'a self) -> Result<Vec<T>, ASN1DecodeErr> {
        let mut vec = Vec::new();
        for val in self.0.iter() {
            let ul = match T::try_from(val) {
                Ok(a) => a,
                Err(_) => return Err(ASN1DecodeErr::Overflow),
            };
            vec.push(ul);
        }

        Ok(vec)
    }
}

impl<'a> PartialEq<OID> for &'a OID {
    fn eq(&self, v2: &OID) -> bool {
        let &&OID(ref vec1) = self;
        let &OID(ref vec2) = v2;

        if vec1.len() != vec2.len() {
            return false;
        }

        for i in 0..vec1.len() {
            if vec1[i] != vec2[i] {
                return false;
            }
        }

        true
    }
}

/// A handy macro for generating OIDs from a sequence of `u64`s.
///
/// Usage: oid!(1,2,840,113549,1,1,1) creates an OID that matches
/// 1.2.840.113549.1.1.1. (Coincidentally, this is RSA.)
#[macro_export]
macro_rules! oid {
    ( $( $e: expr ),* ) => {{
        $crate::oid::OID::new(vec![$($crate::BigUint::from($e as u64)),*])
    }};
}
