use std::time::Duration;

use crate::{Result, Authenticated};
use crate::structs::authorizations::*;
use crate::structs::disclosures::*;
use crate::structs::ids::*;
use crate::structs::records::*;
use crate::structs::keys::*;

use log::error;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};

pub fn decode<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T> {
    let msg: T = deserialize(data).map_err(|err| {
        error!("{:?} - {:?}", "Unable to decode structure!", err);
        "Unable to decode structure!"
    })?;

    Ok(msg)
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let data = serialize(msg).map_err(|err| {
        error!("{:?} - {:?}", "Unable to encode structure!", err);
        "Unable to encode structure!"
    })?;
    
    Ok(data)
}

/*
-----------------------------------------------
                Message Hierarchy
-----------------------------------------------
|     Request     |   Response   |   Commit   |
-----------------------------------------------
|    Negotiate    |     Vote     |   Evidence |
|      Query      |    QResult   |      X     |
|        X        |       X      |    Value   |
|        X        |    Notify    |      X     |
|  Publish/Send   |       X      |      X     |
-----------------------------------------------
*/

//--------------------------------------------------------------------
// Request
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Negotiate(Negotiate),
    Query(Query)
}


fn request_msg(req: &Request) -> &Authenticated {
    match req {
        Request::Negotiate(neg) => match neg {
            Negotiate::NMasterKeyRequest(req) => req
        },
        Request::Query(query) => match query {
            Query::QDiscloseRequest(req) => req
        }
    }
}

impl Authenticated for Request {
    fn sid(&self) -> &str {
        request_msg(self).sid()
    }

    fn verify(&self, subject: &Subject, threshold: Duration) -> Result<()> {
        request_msg(self).verify(subject, threshold)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Negotiate {
    NMasterKeyRequest(MasterKeyRequest)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Query {
    QDiscloseRequest(DiscloseRequest)
}

//--------------------------------------------------------------------
// Response
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    Vote(Vote),
    QResult(QResult)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Vote {
    VMasterKeyVote(MasterKeyVote)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum QResult {
    QDiscloseResult(DiscloseResult)
}

//--------------------------------------------------------------------
// Commit
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Commit {
    Evidence(Evidence),
    Value(Value)
}

fn commit_msg(req: &Commit) -> &Authenticated {
    match req {
        Commit::Evidence(evd) => match evd {
            Evidence::EMasterKey(req) => req
        },

        Commit::Value(value) => match value {
            Value::VSubject(req) => req,
            Value::VConsent(req) => req,
            _ => unimplemented!()
        }
    }
}

impl Authenticated for Commit {
    fn sid(&self) -> &str {
        commit_msg(self).sid()
    }

    fn verify(&self, subject: &Subject, threshold: Duration) -> Result<()> {
        commit_msg(self).verify(subject, threshold)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Evidence {
    EMasterKey(MasterKey)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Value {
    VSubject(Subject),
    VConsent(Consent),

    VNewRecord(NewRecord)
}