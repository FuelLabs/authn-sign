predicate;

use std::bytes::Bytes;
use std::string::String;
use std::primitive_conversions::u64::*;
use std::{ecr::ec_recover_r1, b512::B512};
use std::result::Result;
use std::ecr::EcRecoverError;
use std::hash::*;
use std::tx::tx_id;

pub fn base64_encode(input: Bytes) -> String {
    let mut input = input;
    let c = input.len() % 3;
    let pad_count = if c > 0 { 3 - c } else { 0 };
    let mut i = 0;
    while i < pad_count {
        input.push(0);
        i += 1;
    }
    let mut output = Bytes::new();
    let mut i = 0;
    while i + 2 < input.len() {
        let n: u64 = (input.get(i).unwrap().as_u64() << 16) + (input.get(i + 1).unwrap().as_u64() << 8) + input.get(i + 2).unwrap().as_u64();
        let n0 = (n >> 18) & 63;
        let n1 = (n >> 12) & 63;
        let n2 = (n >> 6) & 63;
        let n3 = n & 63;
        output.push(BASE64_DICT[n0]);
        output.push(BASE64_DICT[n1]);
        output.push(BASE64_DICT[n2]);
        output.push(BASE64_DICT[n3]);
        i += 3;
    }
    let mut i = 0;
    while i < pad_count {
        output.pop();
        i += 1;
    }
    let mut i = 0;
    while i < pad_count {
        output.push(0x3d); // =
        i += 1;
    }
    String::from_ascii(output)
}

pub fn base64_decode(input: String) -> Bytes {
    let mut input = filter_base64_chars(input.as_bytes());
    let mut pad_count = 0;
    if let Some(0x3d) = input.get(input.len() - 1) {
        input.set(input.len() - 1, 0x41); // A
        pad_count += 1;
    }
    if let Some(0x3d) = input.get(input.len() - 2) {
        input.set(input.len() - 2, 0x41); // A
        pad_count += 1;
    }
    let mut output = Bytes::new();
    let mut i = 0;
    while i < input.len() {
        let n = (dict_index(input.get(i).unwrap()).unwrap() << 18) + (dict_index(input.get(i + 1).unwrap()).unwrap() << 12) + (dict_index(input.get(i + 2).unwrap()).unwrap() << 6) + dict_index(input.get(i + 3).unwrap()).unwrap();
        output.push(((n >> 16) & 255).try_as_u8().unwrap());
        output.push(((n >> 8) & 255).try_as_u8().unwrap());
        output.push((n & 255).try_as_u8().unwrap());
        i += 4;
    }
    let mut i = 0;
    while i < pad_count {
        output.pop();
        i += 1;
    }
    output
}

fn filter_base64_chars(input: Bytes) -> Bytes {
    let mut output = Bytes::new();
    let mut i = 0;
    while i < input.len() {
        let c = input.get(i).unwrap();
        if is_base64_char(c) {
            output.push(c);
        }
        i += 1;
    }
    output
}

fn is_base64_char(c: u8) -> bool {
    if c == 0x3d { // =
        return true;
    }
    dict_index(c).is_some()
}

fn dict_index(c: u8) -> Option<u64> {
    let mut i = 0;
    while i < 64 {
        if BASE64_DICT[i] == c {
            return Some(i);
        }
        i += 1;
    }
    None
}

const BASE64_DICT: [u8; 64] = [
    0x41,
    0x42,
    0x43,
    0x44,
    0x45,
    0x46,
    0x47,
    0x48,
    0x49,
    0x4a,
    0x4b,
    0x4c,
    0x4d,
    0x4e,
    0x4f,
    0x50,
    0x51,
    0x52,
    0x53,
    0x54,
    0x55,
    0x56,
    0x57,
    0x58,
    0x59,
    0x5a,
    0x61,
    0x62,
    0x63,
    0x64,
    0x65,
    0x66,
    0x67,
    0x68,
    0x69,
    0x6a,
    0x6b,
    0x6c,
    0x6d,
    0x6e,
    0x6f,
    0x70,
    0x71,
    0x72,
    0x73,
    0x74,
    0x75,
    0x76,
    0x77,
    0x78,
    0x79,
    0x7a,
    0x30,
    0x31,
    0x32,
    0x33,
    0x34,
    0x35,
    0x36,
    0x37,
    0x38,
    0x39,
    0x2d, // 0x2b
    0x5f, // 0x2f
];

// The padding length typically appended by base64 to a 32 byte value.
const BYTE32BASE64PADDING = 1;

// WebAuthn SHA-256 Hash.
pub fn webauthn_hash(
    authenticatorData: Bytes,
    preChallenge: Bytes,
    challenge: Bytes,
    postChallenge: Bytes
) -> b256 {
    // Encode the challenge.
    let challengeData = base64_encode(challenge).as_bytes();
    let (challengeEncoded, challengeEndSlice) = challengeData.split_at(challengeData.len() - BYTE32BASE64PADDING);

    // Build the clientData.
    let mut clientData = preChallenge;
    clientData.append(challengeEncoded);
    clientData.append(postChallenge);

    // Hash the clientData.
    let clientHash = Bytes::from(sha256(clientData));

    // Produce the message.
    let mut message = authenticatorData;
    message.append(clientHash);

    // Hash the message.
    sha256(message)
}

// The address of the predicate.
configurable {
	ADDRESS: b256 = 0xe1037e9229115834a823d6eee714f8eb89906a14a83074f4e9515d8a80e63d95,
}

// WebAuthn P-256 predicate.
fn main(signature:B512, authid:Bytes, txid:b256, pre:Bytes, post:Bytes) -> bool {
    // Compute the digest.
    let digest = webauthn_hash(authid, pre, Bytes::from(txid), post);

    // Derive the public key.
    let public_key = ec_recover_r1(signature, digest).unwrap();

    // Derived address == the Address.
    sha256(public_key.into()) == ADDRESS // sha256(public_key.into()) == ADDRESS && // && txid == tx_id()
}

/*
#[test]
fn test_webauthn() {
    let mut preChallenge = Bytes::from(                0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e67);
                       preChallenge.append(Bytes::from(0x65223a2200000000000000000000000000000000000000000000000000000000));
    let (pre,e0) = preChallenge.split_at(32 + 4);

    let mut postChallenge =Bytes::from(                 0x222c226f726967696e223a2268747470733a2f2f6e6176696761746f722d6976);
                       postChallenge.append(Bytes::from(0x6f72792e76657263656c2e617070222c2263726f73734f726967696e223a6661));
                       postChallenge.append(Bytes::from(0x6c73657d00000000000000000000000000000000000000000000000000000000));
    let (post,e1) = postChallenge.split_at((2 * 32) + 4);
                                       
    let mut authID =       Bytes::from(              0x75a448b91bb82a255757e61ba3eb7afe282c09842485268d4d72a027ec0cffc8);
                           authID.append(Bytes::from(0x0500000000000000000000000000000000000000000000000000000000000000));
    let (authenticationId,e2) = authID.split_at(32 + 5);

    // Maybe needs signature encoding.
    let signature= B512::from((
                       0xaec03df2a7c71bddc29c5593e9a6027b7393918a9342034613857be798a654a0,
                       0x183506c5a3c3f1cfac461a66090993e9e75136aa4664fbd3ddc0c489f2114faa
                       ));

    let txid =         0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;

    assert_eq(main(signature, authenticationId, txid, pre, post), true);
}
*/

/*
// Ensure this all works correctly.
#[test]
fn test_webauthn() {
    let mut preChallenge = Bytes::from(0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e67);
                       preChallenge.append(Bytes::from(0x65223a2200000000000000000000000000000000000000000000000000000000));
    let (pre,e0) = preChallenge.split_at(32 + 4);

    let mut postChallenge =Bytes::from(0x222c226f726967696e223a2268747470733a2f2f617574686e2d7369676e2d66);
                       postChallenge.append(Bytes::from(0x75656c65722d6675656c2d6c6162732e76657263656c2e617070222c2263726f));
                       postChallenge.append(Bytes::from(0x73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f));
                       postChallenge.append(Bytes::from(0x62655f61646465645f68657265223a22646f206e6f7420636f6d706172652063));
                       postChallenge.append(Bytes::from(0x6c69656e74446174614a534f4e20616761696e737420612074656d706c617465));
                       postChallenge.append(Bytes::from(0x2e205365652068747470733a2f2f676f6f2e676c2f796162506578227d000000));
    let (post,e1) = postChallenge.split_at((5 * 32) + 29);

    let mut authID =       Bytes::from(0x69dad030b3fcf6b0918109832cd9045a2c4658a8b9be5d36b7ee830543f15b5d);
                           authID.append(Bytes::from(0x0500000000000000000000000000000000000000000000000000000000000000));
    let (authenticationId,e2) = authID.split_at(32 + 5);

    // Maybe needs signature encoding.
    let signature= B512::from((
                       0xaaf5c8477adb7076d2bf6fe0c8421f2e0bbd170a2a7a8b685990fb321d842d10,
                       0x7a392012a0dc376b01c4a9bb79ab41dfc6db31f2427cbe2244104eaf23a4a1c5
                       ));

    let txid =         0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d;

    assert_eq(main(signature, authenticationId, txid, pre, post), true);
}

#[test]
fn produce_hash() {
    // 32 + 4
    let preHi = 0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e67;
    let preLo = 0x65223a2200000000000000000000000000000000000000000000000000000000;

    let mut preData = Bytes::from(preHi);
    preData.append(Bytes::from(preLo));
    let (pre,_slice2) = preData.split_at(32 + 4);

    // 32 + 11
    /*
    let challengeHi = 0x74505971342d4d335168686f654371495f333242714c3945373263693338304d;
    let challengeLo = 0x634e434b4374776c5a6a30000000000000000000000000000000000000000000;
    */

    // (32 * 5) + 29
    let post1 = 0x222c226f726967696e223a2268747470733a2f2f617574686e2d7369676e2d66;
    let post2 = 0x75656c65722d6675656c2d6c6162732e76657263656c2e617070222c2263726f;
    let post3 = 0x73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f;
    let post4 = 0x62655f61646465645f68657265223a22646f206e6f7420636f6d706172652063;
    let post5 = 0x6c69656e74446174614a534f4e20616761696e737420612074656d706c617465;
    let post6 = 0x2e205365652068747470733a2f2f676f6f2e676c2f796162506578227d000000;

    let mut postData = Bytes::from(post1);
    postData.append(Bytes::from(post2));
    postData.append(Bytes::from(post3));
    postData.append(Bytes::from(post4));
    postData.append(Bytes::from(post5));
    postData.append(Bytes::from(post6));
    let (post,_slice3) = postData.split_at((32 * 5) + 29);

    let authHi = 0x69dad030b3fcf6b0918109832cd9045a2c4658a8b9be5d36b7ee830543f15b5d;
    let authLo = 0x0500000000000000000000000000000000000000000000000000000000000000;
    let mut authData = Bytes::from(authHi);
    authData.append(Bytes::from(authLo));
    let (authenticatorData,_slice3) = authData.split_at(32 + 5);

    let txhash = Bytes::from(0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d);
    let messageHash = webauthn_hash(authenticatorData, pre, txhash, post);

    assert_eq(messageHash, 0x357b03b8d531c05b29482586a6d7bd5cc65a4ba19947862ba117e92038869dc2);
}

#[test]
fn test_secp256r1() {
    let signature: B512 = B512::from((
        0x64f753491eec84d21f239e2cf7a51d29680d37812fc26ee9f2f10468a7cb9e72,
        0xed4dc381b25ae1c2533e8fbd83a9cb39b5b963c2a1ca04a58297c14ddbdf6777
    ));
    let msg_hash = 0x397ce6145d26dc9010fb631a39ead3c91a8a1c1a0397438c89f93b97f0e40aab;
    let pub_hi = 0x43fafac9ad2efb0e79002b5183075d8c383d5e4b3c61b181992e248a924a328c;
    let pub_lo = 0x3e54592cce76231393d72471ac02e39fdc0c4397d46efedfef21d4e000b47772;

    let public_key = ec_recover_r1(signature, msg_hash).unwrap();

    assert_eq(public_key.bytes[0], pub_hi);
    assert_eq(public_key.bytes[1], pub_lo);
}

#[test]
fn test_secp256r1_normalized_s() {
    let signature: B512 = B512::from((
        0xc1ea30b90ea347ca1714e7494a1ef593b220e10849d6b3f6f1cea27070849328,
        0x4746985aa795265fe80e1be14254d7ec18d07594497c38275dc82ef98d141c5c
    ));
    let msg_hash = 0x397ce6145d26dc9010fb631a39ead3c91a8a1c1a0397438c89f93b97f0e40aab;
    let pub_hi = 0xe3bda11d9af81206a68a5b420524a7765d4220a2e4dc3854279fd3977e0c1021;
    let pub_lo = 0x0e1843c5b1e3faf2e964323b9ff6f8bea0660b75d2ecc8bc3a63fdb7440ee51e;

    let public_key = ec_recover_r1(signature, msg_hash).unwrap();

    assert_eq(public_key.bytes[0], pub_hi);
    assert_eq(public_key.bytes[1], pub_lo);
}

#[test]
fn test_encode() {
    let txhash = Bytes::from(0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d);
    let txhashBase64 = base64_encode(txhash).as_bytes();
    let (txhashBase64Sliced,slice3) = txhashBase64.split_at(txhashBase64.len() - 1);

    assert_eq(txhashBase64Sliced, String::from_ascii_str("tPYq4-M3QhhoeCqI_32BqL9E72ci380McNCKCtwlZj0").as_bytes());
    assert_eq(base64_encode(String::from_ascii_str("Man").as_bytes()), String::from_ascii_str("TWFu"));
    assert_eq(base64_encode(String::from_ascii_str("Ma").as_bytes()), String::from_ascii_str("TWE="));
    assert_eq(base64_encode(String::from_ascii_str("M").as_bytes()), String::from_ascii_str("TQ=="));
    assert_eq(base64_encode(String::from_ascii_str("Many hands make light work.").as_bytes()), String::from_ascii_str("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"));
    assert_eq(base64_encode(String::from_ascii_str("Hello world").as_bytes()), String::from_ascii_str("SGVsbG8gd29ybGQ="));
}

#[test]
fn test_decode() {
    assert_eq(base64_decode(String::from_ascii_str("TWFu")), String::from_ascii_str("Man").as_bytes());
    assert_eq(base64_decode(String::from_ascii_str("TWE=")), String::from_ascii_str("Ma").as_bytes());
    assert_eq(base64_decode(String::from_ascii_str("TQ==")), String::from_ascii_str("M").as_bytes());
    assert_eq(base64_decode(String::from_ascii_str("TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")), String::from_ascii_str("Many hands make light work.").as_bytes());
    assert_eq(base64_decode(String::from_ascii_str("SGVsbG8gd29ybGQ=")), String::from_ascii_str("Hello world").as_bytes());
}
*/
