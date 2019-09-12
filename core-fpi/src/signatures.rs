use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use sha2::{Sha512, Digest};

use crate::G;

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Copy, Clone)]
pub struct Signature {
    pub c: Scalar,
    pub p: Scalar
}

impl Signature {
    #[allow(non_snake_case)]
    pub fn sign(s: Scalar, P: CompressedRistretto, data: &Vec<Box<[u8]>>) -> Self {
        let mut hasher = Sha512::new()
            .chain(s.as_bytes());
        
        for d in data {
            hasher.input(d);
        }

        let m = Scalar::from_hash(hasher); 
        let M = (m * G).compress();

        let mut hasher = Sha512::new()
            .chain(P.as_bytes())
            .chain(M.as_bytes());
        
        for d in data {
            hasher.input(d);
        }

        let _c = Scalar::from_hash(hasher);

        Signature { c: _c, p: m - _c * s }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, P: CompressedRistretto, data: &Vec<Box<[u8]>>) -> bool {
        let Ps = P.decompress();
        if Ps.is_none() {
            return false;
        }

        let M = self.c * Ps.unwrap() + self.p * G;

        let mut hasher = Sha512::new()
            .chain(P.as_bytes())
            .chain(M.compress().as_bytes());
        
        for d in data {
            hasher.input(d);
        }
        
        let c = Scalar::from_hash(hasher);

        c == self.c
    }
}

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature with PublicKey (Extended Signature)
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Copy, Clone)]
pub struct ExtSignature {
    pub key: CompressedRistretto,
    pub sig: Signature
}

impl ExtSignature {
    #[allow(non_snake_case)]
    pub fn new(s: Scalar, P: CompressedRistretto, data: &Vec<Box<[u8]>>) -> Self {
        let _sig = Signature::sign(s, P, data);
        ExtSignature { key: P, sig: _sig }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, data: &Vec<Box<[u8]>>) -> bool {
        self.sig.verify(self.key, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rnd_scalar;

    #[allow(non_snake_case)]
    #[test]
    fn test_signature() {
        let a = rnd_scalar();
        let Pa = (a * G).compress();

        let data: Vec<Box<[u8]>> = vec![Box::new(rnd_scalar().to_bytes()), Box::new(rnd_scalar().to_bytes())];

        let sig = Signature::sign(a, Pa, &data);
        assert!(sig.verify(Pa, &data) == true);
    }
}