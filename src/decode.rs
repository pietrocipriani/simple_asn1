use num_bigint::BigUint;
use num_traits::Zero;
use crate::size_of;

use crate::{asn1_data_types::ASN1Class, errors::ASN1DecodeErr};



/// Returns the tag, if the type is constructed and the class.
pub fn tag(i: &[u8], index: &mut usize) -> Result<(BigUint, bool, ASN1Class), ASN1DecodeErr> {
    if *index >= i.len() {
        return Err(ASN1DecodeErr::Incomplete);
    }
    let tagbyte = i[*index];
    let constructed = (tagbyte & 0b0010_0000) != 0;
    let class = class(tagbyte)?;
    let basetag = tagbyte & 0b1_1111;

    *index += 1;

    if basetag == 0b1_1111 {
        let res = base127(i, index)?;
        Ok((res, constructed, class))
    } else {
        Ok((BigUint::from(basetag), constructed, class))
    }
}


pub fn base127(i: &[u8], index: &mut usize) -> Result<BigUint, ASN1DecodeErr> {
    let mut res = BigUint::zero();

    loop {
        if *index >= i.len() {
            return Err(ASN1DecodeErr::Incomplete);
        }

        let nextbyte = i[*index];

        *index += 1;
        res = (res << 7) + BigUint::from(nextbyte & 0x7f);
        if (nextbyte & 0x80) == 0 {
            return Ok(res);
        }
    }
}


pub fn length(i: &[u8], index: &mut usize) -> Result<usize, ASN1DecodeErr> {
    if *index >= i.len() {
        return Err(ASN1DecodeErr::Incomplete);
    }
    let startbyte = i[*index];

    // NOTE: Technically, this size can be much larger than a usize.
    // However, our whole universe starts to break down if we get
    // things that big. So we're boring, and only accept lengths
    // that fit within a usize.
    *index += 1;
    if startbyte >= 0x80 {
        let mut lenlen = (startbyte & 0x7f) as usize;
        let mut res = 0;

        if lenlen > size_of::<usize>() {
            return Err(ASN1DecodeErr::LengthTooLarge(lenlen));
        }

        while lenlen > 0 {
            if *index >= i.len() {
                return Err(ASN1DecodeErr::Incomplete);
            }

            res = (res << 8) + (i[*index] as usize);

            *index += 1;
            lenlen -= 1;
        }

        Ok(res)
    } else {
        Ok(startbyte as usize)
    }
}


pub fn class(i: u8) -> Result<ASN1Class, ASN1DecodeErr> {
    match i >> 6 {
        0b00 => Ok(ASN1Class::Universal),
        0b01 => Ok(ASN1Class::Application),
        0b10 => Ok(ASN1Class::ContextSpecific),
        0b11 => Ok(ASN1Class::Private),
        _ => Err(ASN1DecodeErr::InvalidClass(i)),
    }
}
