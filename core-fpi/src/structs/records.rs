use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use crate::crypto::signatures::Signature;

//-----------------------------------------------------------------------------------------------------------
// An anonymous profile record
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct Record {
    pub data: Vec<u8>,
    pub prev: String,
    pub sig: Signature,
    _phantom: () // force use of constructor
}

impl Record {
    pub fn new(data: &[u8], prev: &str, base: &RistrettoPoint, secret: &Scalar, pseudonym: &CompressedRistretto) -> Self {
        let sig_data = &[&data, prev.as_bytes()];
        let sig = Signature::sign(secret, pseudonym, base, sig_data);

        Self { data: data.into(), prev: prev.into(), sig: sig, _phantom: () }
    }

    pub fn check(&self, last: Option<&Record>, base: &RistrettoPoint, pseudonym: &CompressedRistretto) -> Result<(), &'static str> {
        use crate::FIRST;
        
        let prev = match last {
            None => if self.prev != FIRST {
                return Err("Record not marked as First!")
            } else {
                FIRST
            },
            
            Some(last) => if self.prev != last.sig.encoded {
                return Err("Record not part of the chain!")
            } else {
                self.prev.as_ref()
            }
        };
        
        let sig_data = &[&self.data, prev.as_bytes()];
        if !self.sig.verify(pseudonym, base, sig_data) {
            return Err("Invalid record signature!")
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G, FIRST, rnd_scalar};

    #[allow(non_snake_case)]
    #[test]
    fn test_correct() {
        let base = rnd_scalar() * G;
        let secret = rnd_scalar();
        let pseudonym = (secret * base).compress();
        
        let r_data = "record data".as_bytes();
        let record = Record::new(r_data, FIRST, &base, &secret, &pseudonym);
        
        assert!(record.check(None, &base, &pseudonym) == Ok(()));
    }
}