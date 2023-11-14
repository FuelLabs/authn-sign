const { register, sign, verify, utils } = require('./index.js');
import { secp256r1 } from '@noble/curves/p256';
import { expect, test } from "bun:test";
import { Signature, hexlify } from 'ethers';
const webauthn = require('@passwordless-id/webauthn');

// Valid returns from WebAuthn API.
const register_return = JSON.parse('{"username":"username_1","credential":{"id":"YyGacelT6fMR854csLURTauJY_xJXeYeejLHC1KgPZM","publicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnmrlVmWBynUu27IdSVyzBl_lM-XqP1kfNGEABZ9ZPCjyA-MrlyF5IZv-P8652vevZwpAuqOR05VlE53SnTv4Sw==","algorithm":"ES256"},"authenticatorData":"adrQMLP89rCRgQmDLNkEWixGWKi5vl02t-6DBUPxW11FAAAAAK3OAAI1vMYKZIsLJfHwVQMAIGMhmnHpU-nzEfOeHLC1EU2riWP8SV3mHnoyxwtSoD2TpQECAyYgASFYIJ5q5VZlgcp1LtuyHUlcswZf5TPl6j9ZHzRhAAWfWTwoIlgg8gPjK5cheSGb_j_Oudr3r2cKQLqjkdOVZROd0p07-Es=","clientData":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicmFuZG9tLWNoYWxsZW5nZS1iYXNlNjQtZW5jb2RlYyIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aG4tc2lnbi1mdWVsZXItZnVlbC1sYWJzLnZlcmNlbC5hcHAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"}');
const sign_return = JSON.parse('{"credentialId":"YyGacelT6fMR854csLURTauJY_xJXeYeejLHC1KgPZM","authenticatorData":"adrQMLP89rCRgQmDLNkEWixGWKi5vl02t-6DBUPxW10FAAAAAA==","clientData":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidFBZcTQtTTNRaGhvZUNxSV8zMkJxTDlFNzJjaTM4ME1jTkNLQ3R3bFpqMCIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aG4tc2lnbi1mdWVsZXItZnVlbC1sYWJzLnZlcmNlbC5hcHAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==","signature":"MEYCIQCq9chHettwdtK_b-DIQh8uC70XCip6i2hZkPsyHYQtEAIhAIXG3-xfI8iV_jtWRIZUvh_2C8i7ZJrgYq-pfBPYvoOM"}');
const publicKey = '0x049e6ae5566581ca752edbb21d495cb3065fe533e5ea3f591f346100059f593c28f203e32b972179219bfe3fceb9daf7af670a40baa391d39565139dd29d3bf84b';
const signatureCorrect = '0xaaf5c8477adb7076d2bf6fe0c8421f2e0bbd170a2a7a8b685990fb321d842d1085c6dfec5f23c895fe3b56448654be1ff60bc8bb649ae062afa97c13d8be838c';

// Some transaction hash.
const transaction_hash = '0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d';

// Fake WebAuthn client.
const client = {
    register: async function(username, challenge, opts) {
        return register_return;
    },
    authenticate: async function(ids, challenge, opts) {
        return sign_return;
    },
};

test("test register", async () => {
  const account = await register('account_1', { client });

  expect(account.publicKey).toBe(publicKey);
});

test("test sign", async () => {
    const account = await register('account_1', { client });
    const signature = await sign(account, transaction_hash, { client });

    console.log(signature);

    expect(signature.signature).toBe(signatureCorrect);
});

test("test verify", async () => {
    const account = await register('account_1', { client });
    const signature = await sign(account, transaction_hash, { client });
    const is_verified = await verify(signature);

    expect(is_verified).toBe(true);
});

test("test signature (using Noble Crypto)", async () => {
    const account = await register('account_1', { client });
    const signature = await sign(account, transaction_hash, { client });

    console.log(utils.bufferToHex(await utils.sha256(utils.hexToBuffer(signature.clientData.encoded))));

    const isMessageValid = secp256r1.verify(
        signature.signature.slice(2),
        signature.message.slice(2),
        signature.account.publicKey.slice(2),
        { prehash: true }
    ) === true;
    const isHashValid = secp256r1.verify(
        signature.signature.slice(2),
        signature.hash.slice(2),
        signature.account.publicKey.slice(2),
    ) === true;

    expect(isMessageValid).toBe(true);
    expect(isHashValid).toBe(true);
});

/*let msgRaw:Result<[u8; 32],_> = hex::decode("397ce6145d26dc9010fb631a39ead3c91a8a1c1a0397438c89f93b97f0e40aab").unwrap().as_slice().try_into();
        let sigRaw = hex::decode("64f753491eec84d21f239e2cf7a51d29680d37812fc26ee9f2f10468a7cb9e726d4dc381b25ae1c2533e8fbd83a9cb39b5b963c2a1ca04a58297c14ddbdf6777").unwrap();
        let publicKeyRaw = hex::decode("43fafac9ad2efb0e79002b5183075d8c383d5e4b3c61b181992e248a924a328c3e54592cce76231393d72471ac02e39fdc0c4397d46efedfef21d4e000b47772").unwrap();

        let sig = Signature::from_slice(&sigRaw).ok().unwrap();
        let sigEncoded = hex::encode(encode_signature(sig, RecoveryId::new(true, false)));

        println!("{:?}", sigEncoded);

        /*
        let msgRaw:Result<[u8; 32],_> = hex::decode("397ce6145d26dc9010fb631a39ead3c91a8a1c1a0397438c89f93b97f0e40aab").unwrap().as_slice().try_into();
        let sigRaw = hex::decode("c1ea30b90ea347ca1714e7494a1ef593b220e10849d6b3f6f1cea27070849328b8b967a4586ad9a117f1e41ebdab2813a41685195d9b665d95f19bc96f4f08f5").unwrap();
        let publicKeyRaw = hex::decode("e3bda11d9af81206a68a5b420524a7765d4220a2e4dc3854279fd3977e0c10210e1843c5b1e3faf2e964323b9ff6f8bea0660b75d2ecc8bc3a63fdb7440ee51e").unwrap();
*/

// Returns encoded signature.
function encode_signature(signatureCompact = '0x', recovery_id = 1) {
    let buffer = new Uint8Array(utils.hexToBuffer(signatureCompact));

    const v = recovery_id == 0;
    buffer[32] = (v << 7) | (buffer[32] & 0x7f);

    return utils.bufferToHex(buffer);
}

// Decode the signature.
function decode_signature(signatureCompact = '0x') {
    let buffer = new Uint8Array(utils.hexToBuffer(signatureCompact));

    const v = (buffer[32] & 0x80) != 0;
    buffer[32] = buffer[32] & 0x7f;

    return {
        signature: utils.bufferToHex(buffer),
        v,
    };
}

/*
/// Separates recovery id from the signature bytes. See the following link for
/// explanation. https://github.com/FuelLabs/fuel-specs/blob/master/src/protocol/cryptographic_primitives.md#public-key-cryptography
fn decode_signature(mut signature: [u8; 64]) -> Option<(Signature, RecoveryId)> {
    let v = (signature[32] & 0x80) != 0;
    signature[32] &= 0x7f;

    let signature = Signature::from_slice(&signature).ok()?;

    Some((signature, RecoveryId::new(v, false)))
}

fn encode_signature(signature: Signature, recovery_id: RecoveryId) -> [u8; 64] {
    let mut signature: [u8; 64] = signature.to_bytes().into();
    assert!(signature[32] >> 7 == 0, "Non-normalized signature");
    assert!(!recovery_id.is_x_reduced(), "Invalid recovery id");

    let v = recovery_id.is_y_odd() as u8;

    signature[32] = (v << 7) | (signature[32] & 0x7f);
    signature
}
*/

test("back and forth", async () => {
    // This would happen in the browser.
    const account = await register('username_1', { client });
    const transaction_hash = '0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d';
    const signature = await sign(account, transaction_hash, { client });

    // console.log(signature);
    
    // This would happen on chain.
    const signedData = signature.clientData.preChallenge 
      + utils.hexToBase64(transaction_hash).slice(0, -1) // remove last character
      + signature.clientData.postChallenge;
    const clientDataHash = utils.bufferToHex(await utils.sha256(utils.toBuffer(signedData)));

    // console.log(clientDataHash);

    const message = utils.concatHexStrings(signature.authenticatorData, clientDataHash);
    const messageHash = utils.bufferToHex(await utils.sha256(message));

    // console.log(messageHash);
    
    // This P-256 verficiation would also happen on chain.
    /*
    const is_verified = await verify({
      publicKey: account.publicKey,
      message: utils.bufferToHex(message),
      signature: signature.signature,
    });
    
    console.log(is_verified);
    */
});

test("proper encoding / decoding", async () => {
    // Doesn't require normalization (y_off true, x_odd false)
    // const messageRaw = "0x397ce6145d26dc9010fb631a39ead3c91a8a1c1a0397438c89f93b97f0e40aab";
    // const signatureRaw = "0x64f753491eec84d21f239e2cf7a51d29680d37812fc26ee9f2f10468a7cb9e726d4dc381b25ae1c2533e8fbd83a9cb39b5b963c2a1ca04a58297c14ddbdf6777";
    // const public_keyRaw = "0x43fafac9ad2efb0e79002b5183075d8c383d5e4b3c61b181992e248a924a328c3e54592cce76231393d72471ac02e39fdc0c4397d46efedfef21d4e000b47772";

    // Requires Normalization (_y_off false, x_odd false)
    const messageActualRaw = "0x84b2537b96f6127fcc5692292d08ac37995c3c415c46e04a36bb0944703dc082050000000032c2d47464c87eeacf35eac8251c773a2ffa0b6d9184579e0f4a198f0ab4b4d9";
    const messageRaw = "0x397ce6145d26dc9010fb631a39ead3c91a8a1c1a0397438c89f93b97f0e40aab";
    const signatureRaw = "0xc1ea30b90ea347ca1714e7494a1ef593b220e10849d6b3f6f1cea27070849328b8b967a4586ad9a117f1e41ebdab2813a41685195d9b665d95f19bc96f4f08f5";
    const public_keyRaw = "0xe3bda11d9af81206a68a5b420524a7765d4220a2e4dc3854279fd3977e0c10210e1843c5b1e3faf2e964323b9ff6f8bea0660b75d2ecc8bc3a63fdb7440ee51e";
    const public_keyRawL = "0x04e3bda11d9af81206a68a5b420524a7765d4220a2e4dc3854279fd3977e0c10210e1843c5b1e3faf2e964323b9ff6f8bea0660b75d2ecc8bc3a63fdb7440ee51e";

    // let signature = secp256r1.Signature.fromCompact(signatureRaw.slice(2)).normaliseS();

    /*
    let signature = secp256r1.Signature.fromCompact(signatureRaw.slice(2));
    signature = signature.addRecoveryBit(1);
    console.log('sig compac', signature.toCompactHex());
    // let publicKeyPoints = signature.recoverPublicKey(messageRaw.slice(2));
    // const publicKey = publicKeyPoints.toHex(false).slice(2);
    */

    // signature = signature.addRecoveryBit(1);
    // let publicKeyPoints = signature.recoverPublicKey(messageRaw.slice(2));
    // const publicKey = publicKeyPoints.toHex(false).slice(2);

    // console.log('addr', utils.bufferToHex(await utils.sha256(utils.hexToBuffer('0xbbfafcb62ac8c76306f56bdf15490505db31960b95d6c74c10916dd45566d5b3'))));

    const sig2Raw = '0xaaf5c8477adb7076d2bf6fe0c8421f2e0bbd170a2a7a8b685990fb321d842d1085c6dfec5f23c895fe3b56448654be1ff60bc8bb649ae062afa97c13d8be838c';
    let signature2 = secp256r1.Signature.fromCompact(sig2Raw.slice(2)).normalizeS();
    const encoded2 = encode_signature(utils.bufferToHex(signature2.toCompactRawBytes()), 1);

    // console.log('encoded 2', encoded2);

    let signature = secp256r1.Signature.fromCompact(signatureRaw.slice(2)).normalizeS();
    const encoded = encode_signature(utils.bufferToHex(signature.toCompactRawBytes()), 1);

    // console.log('encoded', encoded);

    const decoded = decode_signature(encoded);

    // console.log(decoded);
/*
    let signature = secp256r1.Signature.fromCompact(decoded.signature.slice(2));
    signature = signature.addRecoveryBit(1);
    let publicKeyPoints = signature.recoverPublicKey(messageRaw.slice(2));
    const publicKey = publicKeyPoints.toHex(false).slice(2);
    */

    // c1ea30b90ea347ca1714e7494a1ef593b220e10849d6b3f6f1cea270708493284746985aa795265fe80e1be14254d7ec18d07594497c38275dc82ef98d141c5c

    // let publicKeyPoints = signature.recoverPublicKey(messageRaw.slice(2));
    // const publicKey = publicKeyPoints.toHex(false).slice(2);
    // const publicKey = '0x' + publicKeyPoints.x.toString(16) + publicKeyPoints.y.toString(16);

    // console.log(publicKey == public_keyRaw.slice(2), signature.normalizeS().toCompactHex());

    const isHashValid = secp256r1.verify(
        decoded.signature.slice(2), // signature.toCompactHex().slice(2),
        messageRaw.slice(2),
        public_keyRawL.slice(2), // '04' + publicKey,
        { lowS: false, prehash: false },
    ) === true;

    // console.log(isHashValid);

    // Produce crypto key object.
    const crypto_key = await crypto.subtle.importKey('raw', utils.hexToBuffer(public_keyRawL), {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
    }, true, ['verify']);

    // Return result.
    /*console.log(await crypto.subtle.verify({
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
    }, crypto_key, utils.hexToBuffer(decoded.signature), utils.hexToBuffer(messageActualRaw)));*/
});

test("test signature data from Sway", async () => {
    const account = await register('account_1', { client });
    const signature = await sign(account, transaction_hash, { client });

    // let hi = 0xbd0c9b8792876712afadbff382e1bf31c44437823ed761cc3600d0016de511ac;
    // let lo = 0x44ac566bd156b4fc71a4a4cb2655d3da360c695edb27dc3b64d621e122fea23d;
    // let msg_hash = 0x1e45523606c96c98ba970ff7cf9511fab8b25e1bcd52ced30b81df1e4a9c4323;
        
    // let pub_hi = 0xd6ea577a54ae42411fbc78d686d4abba2150ca83540528e4b868002e346004b2;
    // let pub_lo = 0x62660ecce5979493fe5684526e8e00875b948e507a89a47096bc84064a175452;

    const isHashValid = secp256r1.verify(
        'bd0c9b8792876712afadbff382e1bf31c44437823ed761cc3600d0016de511ac44ac566bd156b4fc71a4a4cb2655d3da360c695edb27dc3b64d621e122fea23d',
        '1e45523606c96c98ba970ff7cf9511fab8b25e1bcd52ced30b81df1e4a9c4323',
        '04d6ea577a54ae42411fbc78d686d4abba2150ca83540528e4b868002e346004b262660ecce5979493fe5684526e8e00875b948e507a89a47096bc84064a175452',
    ) === true;

    // expect(isMessageValid).toBe(true);
    expect(isHashValid).toBe(true);
});