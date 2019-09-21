use std::fs::{File, OpenOptions};
use std::io::{Result, Error, ErrorKind};
use std::io::prelude::*;

use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};

use core_fpi::{G, rnd_scalar, Scalar};
use core_fpi::ids::*;
use core_fpi::messages::Message;

fn read(name: &str) -> Option<Vec<u8>> {
    let file = File::open(name);

    // no problem if it doens't exists
    let mut file = match file {
        Ok(file) => file,
        Err(error) => {
            if let ErrorKind::NotFound = error.kind()  {
                return None
            } else {
                panic!("Problems opening the file ({:?}): {:?}", name, error)
            }
        }
    };
    
    let mut data = Vec::<u8>::new();
    if let Err(e) = file.read_to_end(&mut data) {
        panic!("Problems reading the file ({:?}): {:?}", name, e)
    }
    
    Some(data)
}

fn write(name: &str, data: Vec<u8>, append: bool) -> Result<()> {
    let mut file = OpenOptions::new().append(append).create(true).open(name)?;
    file.write_all(&data)
}

//-----------------------------------------------------------------------------------------------------------
// Wal (Write-ahead logging)
//-----------------------------------------------------------------------------------------------------------
struct Wal {
    file: String,
    update: Option<MySubject>
}

impl Wal {
    fn load(&mut self) {
        if let Some(data) = read(&self.file) {
            //TODO: read what you can and ignore the rest
        }
    }
}

//-----------------------------------------------------------------------------------------------------------
// Store
//-----------------------------------------------------------------------------------------------------------
pub struct Store {
    pub sid: String,
    pub my: Option<MySubject>,
    
    file: String,
    wal: Wal
}

impl Store {
    pub fn new(sid: &str) -> Result<Self> {
        let mut wal = Wal { file: format!("{}.wal", sid), update: None };
        wal.load();

        let file = format!("{}.sid", sid);
        let my = Store::load(&file)?;
        Ok(Self { sid: sid.into(), my: my, file: file, wal: wal })
    }

    pub fn create(&self) -> Result<Message> {
        if let Some(_) = self.my {
            return Err(Error::new(ErrorKind::Other, "You already have a subject in the store!"))
        }

        if let Some(_) = self.wal.update {
            return Err(Error::new(ErrorKind::Other, "There is a pending synchronization in the log!"))
        }

        let secret = rnd_scalar();
        let skey = (secret * G).compress();

        let mut sub = Subject::new(&self.sid);
        sub.keys.push(SubjectKey::new(&self.sid, 0, skey, &secret, &skey));

        let update = MySubject { secret: secret, subject: sub.clone() };
        //TODO: put update in the wal

        Ok(Message::SyncSubject(sub))
    }

    pub fn evolve(&self) -> Result<Message> {
        if let Some(_) = self.wal.update {
            return Err(Error::new(ErrorKind::Other, "There is a pending synchronization in the log!"))
        }

        match &self.my {
            None => return Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let (secret, skey) = my.subject.evolve(my.secret);

                let mut sub = Subject::new(&self.sid);
                sub.keys.push(skey);

                let update = MySubject { secret: secret, subject: sub.clone() };
                //TODO: put update in the wal

                Ok(Message::SyncSubject(sub))
            }
        }
    }

    fn load(file: &str) -> Result<Option<MySubject>> {
        if let Some(data) = read(file) {
            let my: MySubject = deserialize(&data).map_err(|_| Error::new(ErrorKind::Other, "Unable to decode subject!"))?;
            return Ok(Some(my))
        }

        Ok(None)
    }

    fn save(file: &str, my: MySubject) -> Result<()> {
        let data = serialize(&my).map_err(|_| Error::new(ErrorKind::Other, "Unable to encode subject!"))?;
        write(file, data, false)
    }
}

//-----------------------------------------------------------------------------------------------------------
// MySubject
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MySubject {
    secret: Scalar,
    subject: Subject
}