use num_bigint::BigUint;
use num_traits::{FromPrimitive, Zero, ToPrimitive};

use crate::{asn1_data_types::ASN1Class, errors::ASN1EncodeErr};


pub(crate) fn asn1_string(
    tag: u8,
    force_chars: bool,
    c: ASN1Class,
    s: &str,
) -> Result<Vec<u8>, ASN1EncodeErr> {
    let mut body = {
        if force_chars {
            let mut out = Vec::new();

            for c in s.chars() {
                out.push(c as u8);
            }
            out
        } else {
            s.to_string().into_bytes()
        }
    };
    let inttag = BigUint::from_u8(tag).unwrap();
    let mut lenbytes = len(body.len());
    let mut tagbytes = crate::encode::tag(c, false, &inttag);

    let mut res = Vec::new();
    res.append(&mut tagbytes);
    res.append(&mut lenbytes);
    res.append(&mut body);
    Ok(res)
}

pub(crate) fn tag(c: ASN1Class, constructed: bool, t: &BigUint) -> Vec<u8> {
    let cbyte = class(c);

    match t.to_u8() {
        Some(mut x) if x < 31 => {
            if constructed {
                x |= 0b0010_0000;
            }
            vec![cbyte | x]
        }
        _ => {
            let mut res = base127(t);
            let mut x = cbyte | 0b0001_1111;
            if constructed {
                x |= 0b0010_0000;
            }
            res.insert(0, x);
            res
        }
    }
}

pub(crate) fn base127(v: &BigUint) -> Vec<u8> {
    let mut acc = v.clone();
    let mut res = Vec::new();
    let u128 = BigUint::from_u8(128).unwrap();
    let zero = BigUint::zero();

    if acc == zero {
        res.push(0);
        return res;
    }

    while acc > zero {
        // we build this vector backwards
        let digit = &acc % &u128;
        acc >>= 7;

        match digit.to_u8() {
            None => panic!("7 bits don't fit into 8, cause ..."),
            Some(x) if res.is_empty() => res.push(x),
            Some(x) => res.push(x | 0x80),
        }
    }

    res.reverse();
    res
}

pub(crate) fn class(c: ASN1Class) -> u8 {
    match c {
        ASN1Class::Universal => 0b0000_0000,
        ASN1Class::Application => 0b0100_0000,
        ASN1Class::ContextSpecific => 0b1000_0000,
        ASN1Class::Private => 0b1100_0000,
    }
}

pub(crate) fn len(x: usize) -> Vec<u8> {
    if x < 128 {
        vec![x as u8]
    } else {
        let mut bstr = Vec::new();
        let mut work = x;

        // convert this into bytes, backwards
        while work > 0 {
            bstr.push(work as u8);
            work >>= 8;
        }

        // encode the front of the length
        let len = bstr.len() as u8;
        bstr.push(len | 0x80);

        // and then reverse it into the right order
        bstr.reverse();
        bstr
    }
}
