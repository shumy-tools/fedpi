use serde::{Serialize, Deserialize};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use crate::crypto::signatures::Signature;
use crate::{FIRST, Result};

//-----------------------------------------------------------------------------------------------------------
// An anonymous profile record
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    pub prev: String,
    pub data: Vec<u8>,                      // TODO: data fields may release some info connection different streams!
    pub sig: Signature,
    _phantom: () // force use of constructor
}

impl Record {
    pub fn id(&self) -> &String {
        &self.sig.encoded
    }

    pub fn new(prev: &str, data: &[u8], base: &RistrettoPoint, secret: &Scalar, pseudonym: &CompressedRistretto) -> Self {
        let sig_data = &[prev.as_bytes(), &data];
        let sig = Signature::sign(secret, pseudonym, base, sig_data);

        Self { data: data.into(), prev: prev.into(), sig: sig, _phantom: () }
    }

    pub fn check(&self, last: Option<&Record>, base: &RistrettoPoint, pseudonym: &CompressedRistretto) -> Result<()> {
        let prev = match last {
            None => if self.prev != FIRST {
                return Err("Record not marked as First!")
            } else {
                FIRST
            },
            
            Some(last) => {
                if self.prev != *last.id() {
                    return Err("Record not part of the chain!")
                }

                // verify signature of last record with the same key. The chain must have the same key.
                let sig_data = &[last.prev.as_bytes(), &last.data];
                if !self.sig.verify(pseudonym, base, sig_data) {
                    return Err("Last record doesn't match the key for the signature!")
                }

                self.prev.as_ref()
            }
        };
        
        // verify the record signature
        let sig_data = &[prev.as_bytes(), &self.data];
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
        let record = Record::new(FIRST, r_data, &base, &secret, &pseudonym);
        assert!(record.check(None, &base, &pseudonym) == Ok(()));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect() {
        let base = rnd_scalar() * G;
        let secret = rnd_scalar();
        let pseudonym = (secret * base).compress();
        
        let r_data = "record data".as_bytes();
        let record = Record::new(FIRST, r_data, &base, &secret, &pseudonym);
        assert!(record.check(None, &base, &pseudonym) == Ok(()));

        let r_data1 = "next data1".as_bytes();
        let record1 = Record::new(FIRST, r_data1, &base, &secret, &pseudonym);
        assert!(record1.check(Some(&record), &base, &pseudonym) == Err("Record not part of the chain!"));

        let secret1 = rnd_scalar();
        let pseudonym1 = (secret1 * base).compress();

        let r_data2 = "next data2".as_bytes();
        let record2 = Record::new(record.id(), r_data2, &base, &secret1, &pseudonym1);
        assert!(record2.check(Some(&record), &base, &pseudonym) == Err("Last record doesn't match the key for the signature!"));
    }
}