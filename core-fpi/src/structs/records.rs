use serde::{Serialize, Deserialize};

use crate::crypto::signatures::Signature;
use crate::{OPEN, CLOSE, ID, Result, Scalar, RistrettoPoint};

//-----------------------------------------------------------------------------------------------------------
// An anonymous profile record
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    pub prev: String,
    pub data: Vec<u8>,                      // TODO: data fields may release some info connecting different streams!
    pub sig: Signature,
    _phantom: () // force use of constructor
}

impl ID for Record {
    fn id(&self) -> &str {
        &self.sig.encoded
    }
}

impl Record {
    pub fn sign(prev: &str, data: Vec<u8>, base: &RistrettoPoint, secret: &Scalar, pseudonym: &RistrettoPoint) -> Self {
        let sig_data = Self::data(&prev, &data);
        let sig = Signature::sign(secret, pseudonym, base, &sig_data);

        Self { data, prev: prev.into(), sig, _phantom: () }
    }

    pub fn check(&self, last: Option<&Record>, base: &RistrettoPoint, pseudonym: &RistrettoPoint) -> Result<()> {
        let prev = match last {
            None => if self.prev != OPEN {
                return Err("Record not marked as open!".into())
            } else {
                OPEN
            },
            
            Some(last) => {
                // TODO: verify if the stream is not closed?
                if String::from_utf8_lossy(&last.data) == CLOSE {
                    return Err("The stream is closed!".into())
                }

                if self.prev != *last.id() {
                    return Err("Record is not part of the stream!".into())
                }

                // verify signature of last record with the same key. The chain must have the same key.
                let sig_data = Self::data(&last.prev, &last.data);
                if !self.sig.verify(pseudonym, base, &sig_data) {
                    return Err("Last record doesn't match the key for the signature!".into())
                }

                self.prev.as_ref()
            }
        };
        
        // verify the record signature
        let sig_data = Self::data(&prev, &self.data);
        if !self.sig.verify(pseudonym, base, &sig_data) {
            return Err("Invalid record signature!".into())
        }

        Ok(())
    }

    fn data(prev: &str, data: &[u8]) -> [Vec<u8>; 2] {
        let b_prev = bincode::serialize(prev).unwrap();
        let b_data = bincode::serialize(data).unwrap();

        [b_prev, b_data]
    }
}

//--------------------------------------------------------------------
// NewRecord
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewRecord {
    pub record: Record,
    pub key: RistrettoPoint,
    pub base: RistrettoPoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G, OPEN, rnd_scalar};

    #[allow(non_snake_case)]
    #[test]
    fn test_correct() {
        let base = rnd_scalar() * G;
        let secret = rnd_scalar();
        let pseudonym = secret * base;
        
        let r_data = "record data".as_bytes().to_vec();
        let record = Record::sign(OPEN, r_data, &base, &secret, &pseudonym);
        assert!(record.check(None, &base, &pseudonym) == Ok(()));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect() {
        let base = rnd_scalar() * G;
        let secret = rnd_scalar();
        let pseudonym = secret * base;
        
        let r_data = "record data".as_bytes().to_vec();
        let record = Record::sign(OPEN, r_data, &base, &secret, &pseudonym);
        assert!(record.check(None, &base, &pseudonym) == Ok(()));

        let r_data1 = "next data1".as_bytes().to_vec();
        let record1 = Record::sign(OPEN, r_data1, &base, &secret, &pseudonym);
        assert!(record1.check(Some(&record), &base, &pseudonym) == Err("Record is not part of the stream!".into()));

        let secret1 = rnd_scalar();
        let pseudonym1 = secret1 * base;

        let r_data2 = "next data2".as_bytes().to_vec();
        let record2 = Record::sign(record.id(), r_data2, &base, &secret1, &pseudonym1);
        assert!(record2.check(Some(&record), &base, &pseudonym) == Err("Last record doesn't match the key for the signature!".into()));
    }
}