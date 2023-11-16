predicate;

use std::bytes::Bytes;
use std::string::String;
use std::primitive_conversions::u64::*;
use std::{ecr::ec_recover_r1, b512::B512};
use std::result::Result;
use std::ecr::EcRecoverError;
use std::hash::*;
use std::tx::tx_id;

configurable {
	ADDRESS: b256 = 0xe1037e9229115834a823d6eee714f8eb89906a14a83074f4e9515d8a80e63d95,
}

fn main(signature:B512, authid:Bytes, txid:b256, pre:Bytes, post:Bytes, digest0:b256) -> bool {
    sha256(authid) == digest0 && ADDRESS == ADDRESS
}
