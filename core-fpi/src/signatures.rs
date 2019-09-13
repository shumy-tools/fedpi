use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
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
    pub fn sign(s: &Scalar, P: &CompressedRistretto, data: &[&[u8]]) -> Self {
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

        Self { c: _c, p: m - _c * s }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, P: &CompressedRistretto, BasePoint: &RistrettoPoint, data: &[&[u8]]) -> bool {
        let Ps = P.decompress();
        if Ps.is_none() {
            return false;
        }

        let M = self.c * Ps.unwrap() + self.p * BasePoint;

        let mut hasher = Sha512::new()
            .chain(P.as_bytes())
            .chain(M.compress().as_bytes());
        
        for d in data {
            hasher.input(d);
        }
        
        let c = Scalar::from_hash(hasher);

        c == self.c
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let data: &[&[u8]] = &[self.c.as_bytes(), self.p.as_bytes()];
        data.concat()
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
    pub fn sign(s: &Scalar, P: CompressedRistretto, data: &[&[u8]]) -> Self {
        let _sig = Signature::sign(s, &P, data);
        Self { key: P, sig: _sig }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, data: &[&[u8]]) -> bool {
        self.sig.verify(&self.key, &G, data)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let data: &[&[u8]] = &[self.key.as_bytes(), self.sig.c.as_bytes(), self.sig.p.as_bytes()];
        data.concat()
    }
}

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature referencing a key index
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct IndSignature {
    pub index: usize,               // Key index
    pub sig: Signature,             // Schnorr's signature
}

impl IndSignature {
    #[allow(non_snake_case)]
    pub fn sign(index: usize, s: &Scalar, key: &CompressedRistretto, data: &[&[u8]]) -> Self {
        let sig = Signature::sign(s, key, data);
        Self { index: index, sig: sig }
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, key: &CompressedRistretto, data: &[&[u8]]) -> bool {
        self.sig.verify(&key, &G, data)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let index_bytes = self.index.to_be_bytes();
        let data: &[&[u8]] = &[&index_bytes, self.sig.c.as_bytes(), self.sig.p.as_bytes()];
        data.concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rnd_scalar;

    #[allow(non_snake_case)]
    #[test]
    fn test_correct() {
        let a = rnd_scalar();
        let Pa = (a * G).compress();

        let d0 = rnd_scalar();
        let d1 = rnd_scalar();

        let data: &[&[u8]] = &[d0.as_bytes(), d1.as_bytes()];
        let sig = ExtSignature::sign(&a, Pa, data);
        
        assert!(sig.verify(data) == true);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect() {
        let a = rnd_scalar();
        let Pa = (a * G).compress();

        let d0 = rnd_scalar();
        let d1 = rnd_scalar();
        let d2 = rnd_scalar();
        
        let data1: &[&[u8]] = &[d0.as_bytes(), d1.as_bytes()];
        let sig = ExtSignature::sign(&a, Pa, data1);
        
        let data2: &[&[u8]] = &[d0.as_bytes(), d2.as_bytes()];
        assert!(sig.verify(data2) == false);
    }
}