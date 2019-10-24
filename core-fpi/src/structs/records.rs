use serde::{Serialize, Deserialize};

use crate::structs::*;
use crate::crypto::signatures::Signature;
use crate::{Result, Scalar, RistrettoPoint};

pub const OPEN: &str = "OPEN";
pub const CLOSED: &str = "CLOSED";

//-----------------------------------------------------------------------------------------------------------
// An anonymous profile record
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RecordType {
    Owned,                                      // Record inserted by the subject owner
    AnonymousAttach(String),                    // Record inserted by an anonymous subject with a reference to record (sig.encoded)
    IdentifiedAttach(String, String)            // Record inserted by an identified subject (subject-id) with a reference to record (sig.encoded)
    
    /*TODO: --Issues--
      * Attachments can disclose information from a set of streams, i.e.: All streams from a financial institution!
        It's probably better to use some method to conceal this info:
          1) Use a unique stream for each attachment. Requires institutions to have many ProfileKeys!
      * Can IdentifiedAttach be encrypted? What should be the encryption key?
          If the record signature if directly from the subject, the disclosure of Ek will not work!
    */
}

impl RecordType {
    pub fn check(&self) -> Result<()> {
        match self {
            RecordType::AnonymousAttach(attach) => if attach.len() > MAX_HASH_SIZE {
                return Err(format!("Field Constraint - (attach, max-size = {})", MAX_HASH_SIZE))
            },

            RecordType::IdentifiedAttach(sid, attach) => {
                if sid.len() > MAX_SUBJECT_ID_SIZE {
                    return Err(format!("Field Constraint - (sid, max-size = {})", MAX_SUBJECT_ID_SIZE))
                }

                if attach.len() > MAX_HASH_SIZE {
                    return Err(format!("Field Constraint - (attach, max-size = {})", MAX_HASH_SIZE))
                }
            },

            _ => ()
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordData {
    pub format: String,                     // reported data format, i.e: JSON, XML, DICOM, etc. Specifies what goes into the meta/data fields.
    pub meta: Vec<u8>,                      // open access metadata for indexation: DICOM(Modality, Laterality, Columns, Rows, etc)
    pub data: Vec<u8>                       // data that may be in encrypted form. Ek[data] where H(y.Pe) = H(e.Y) = k
}

impl RecordData {
    pub fn check(&self) -> Result<()> {
        if self.format.len() > MAX_FORMAT_SIZE {
            return Err(format!("Field Constraint - (format, max-size = {})", MAX_FORMAT_SIZE))
        }

        if self.meta.len() > MAX_META_SIZE {
            return Err(format!("Field Constraint - (meta, max-size = {})", MAX_META_SIZE))
        }

        if self.data.len() > MAX_DATA_SIZE {
            return Err(format!("Field Constraint - (data, max-size = {})", MAX_DATA_SIZE))
        }

        Ok(())
    }
}

// Records should not have any timestamp associated, cannot use IndSignature.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    pub prev: String,
    pub typ: RecordType,                    // is owned or attached from external entity?
    pub rdata: RecordData,
    
    pub sig: Signature,
    #[serde(skip)] _phantom: () // force use of constructor
}

impl Record {
    pub fn sign(prev: &str, typ: RecordType, rdata: RecordData, base: &RistrettoPoint, secret: &Scalar, pseudonym: &RistrettoPoint) -> Self {
        let sig_data = Self::data(&prev, &typ, &rdata);
        let sig = Signature::sign(secret, pseudonym, base, &sig_data);

        Self { typ, rdata, prev: prev.into(), sig, _phantom: () }
    }

    pub fn check(&self, last: Option<&Record>, base: &RistrettoPoint, pseudonym: &RistrettoPoint) -> Result<()> {
        if self.prev.len() > MAX_HASH_SIZE {
            return Err(format!("Field Constraint - (prev, max-size = {})", MAX_HASH_SIZE))
        }

        self.typ.check()?;

        self.rdata.check()?;

        let prev = match last {
            None => if self.prev != OPEN {
                return Err("Field Constraint - (prev, Record not marked as open)".into())
            } else {
                OPEN
            },
            
            Some(last) => {
                // verify if the stream is not closed
                if last.rdata.format == CLOSED {
                    return Err("The stream is closed!".into())
                }

                // verify the stream chain
                if self.prev != last.sig.encoded {
                    return Err("Field Constraint - (prev, Record is not part of the stream)".into())
                }

                // verify signature of last record with the same key. The chain must have the same key.
                let sig_data = Self::data(&last.prev, &last.typ, &last.rdata);
                if !self.sig.verify(pseudonym, base, &sig_data) {
                    return Err("Last record doesn't match the key for the signature!".into())
                }

                self.prev.as_ref()
            }
        };
        
        // verify the record signature
        let sig_data = Self::data(prev, &self.typ, &self.rdata);
        if !self.sig.verify(pseudonym, base, &sig_data) {
            return Err("Field Constraint - (sig, Invalid signature)".into())
        }

        Ok(())
    }

    fn data(prev: &str, typ: &RecordType, data: &RecordData) -> [Vec<u8>; 3] {
        let b_prev = bincode::serialize(prev).unwrap();
        let b_typ = bincode::serialize(&typ).unwrap();
        let b_data = bincode::serialize(data).unwrap();

        [b_typ, b_prev, b_data]
    }
}

//--------------------------------------------------------------------
// NewRecord
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewRecord {
    pub record: Record,
    pub pseudonym: RistrettoPoint,      // pseudonym or stream identification. Should I use SHA-256(pseudonym) instead?
    pub base: RistrettoPoint            // base-point for signature verification (must be one of the existing master-keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G, rnd_scalar};

    #[allow(non_snake_case)]
    #[test]
    fn test_correct() {
        let base = rnd_scalar() * G;
        let secret = rnd_scalar();
        let pseudonym = secret * base;
        
        let r_data = RecordData { format: "DICOM".into(), meta: "record meta".as_bytes().to_vec(), data: "record data".as_bytes().to_vec() };
        let record = Record::sign(OPEN, RecordType::Owned, r_data, &base, &secret, &pseudonym);
        assert!(record.check(None, &base, &pseudonym) == Ok(()));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect() {
        let base = rnd_scalar() * G;
        let secret = rnd_scalar();
        let pseudonym = secret * base;
        
        let r_data = RecordData { format: "DICOM".into(), meta: "record meta".as_bytes().to_vec(), data: "record data".as_bytes().to_vec() };
        let record = Record::sign(OPEN, RecordType::Owned, r_data, &base, &secret, &pseudonym);
        assert!(record.check(None, &base, &pseudonym) == Ok(()));

        let r_data1 = RecordData { format: "DICOM".into(), meta: "record meta".as_bytes().to_vec(), data: "next data1".as_bytes().to_vec() };
        let record1 = Record::sign(OPEN, RecordType::Owned, r_data1, &base, &secret, &pseudonym);
        assert!(record1.check(Some(&record), &base, &pseudonym) == Err("Record is not part of the stream!".into()));

        let secret1 = rnd_scalar();
        let pseudonym1 = secret1 * base;

        let r_data2 = RecordData { format: "DICOM".into(), meta: "record meta".as_bytes().to_vec(), data: "next data2".as_bytes().to_vec() };
        let record2 = Record::sign(&record.sig.encoded, RecordType::Owned, r_data2, &base, &secret1, &pseudonym1);
        assert!(record2.check(Some(&record), &base, &pseudonym) == Err("Last record doesn't match the key for the signature!".into()));
    }
}