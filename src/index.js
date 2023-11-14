const { client, utils } = require('@passwordless-id/webauthn');

// Convert signature from ASN.1 sequence to "raw" format.
function convertASN1toRaw(signatureBuffer= {}) {
    const usignature = new Uint8Array(signatureBuffer);

    const rStart = usignature[4] === 0 ? 5 : 4;
    const rEnd = rStart + 32;
    const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
    const r = usignature.slice(rStart, rEnd);
    const s = usignature.slice(sStart);

    return new Uint8Array([...r, ...s]);
}

// Prefixed hex string to buffer.
function hexToBuffer(value = "0x") {
    return new Uint8Array(value.slice(2).match(/../g).map(h=>parseInt(h,16))).buffer;
}

// Parse hex string to buffer.
function parseHexString(value = "0x") {
    const error = `Invalid hex value '${value}' should be a 0x hex prefixed value.`;

    if (typeof value !== "string" || value.substring(0, 1) == "0x") {
        throw new Error(error);
    }

    return hexToBuffer(value);
}

// Parse public key from Buffer.
async function parseCryptoKey(publicKey = "") {
    // Parse base64 URL.
    const buffer = utils.parseBase64url(publicKey);

    // Import key and convert to correct key CryptoKey.
    return crypto.subtle.importKey('spki', buffer, {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
    }, true, ['verify']);
}

// Buffer to hex.
function bufferToHex(value = {}) {
    return '0x' + utils.bufferToHex(value);
}

// Crypto key to hex.
async function cryptoKeyToHex(cryptoKey = {}) {
    return bufferToHex(
        await crypto.subtle.exportKey('raw', cryptoKey),
    );
}

// Base64 to hex.
function base64ToHex(value = "") {
    return bufferToHex(utils.parseBase64url(value));
}

// Hex to base64.
function hexToBase64(value = "0x") {
    return utils.toBase64url(parseHexString(value));
}

// Concatenate hex strings.
function concatHexStrings(value1 = "0x", value2 = "0x") {
    return hexToBuffer(value1 + value2.slice(2));
}

// ClientData to JSON.
function clientDataToJSON(clientData) {
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(
        utils.parseBase64url(clientData),
    );
    const json_object = JSON.parse(decodedClientData);

    // Extract the pre and post challenge strings from the UTF-8 encoded JSON.
    const searchString = '"challenge":"';
    const challengeStart = decodedClientData.indexOf(searchString);
    const challengeEnd = decodedClientData.indexOf('"', challengeStart + searchString.length);
    const preChallenge =  decodedClientData.substring(0, challengeStart + searchString.length);
    const postChallenge =  decodedClientData.slice(challengeEnd);
    const encodedChallenge = utils.bufferToHex(utils.toBuffer(json_object.challenge));
    const encoded = bufferToHex(utils.parseBase64url(clientData));
    const prePost = encoded.split(encodedChallenge.slice(2));

    // Parse the string as an object.
    return {
        encoded,
        challengeEncoded: '0x' + encodedChallenge,
        preChallengeEncoded: '0x' + utils.bufferToHex(utils.toBuffer(preChallenge)),
        preChallenge,
        postChallengeEncoded: '0x' + utils.bufferToHex(utils.toBuffer(postChallenge)),
        postChallenge,
        ...json_object,
    };
}

// Register a P256 account using WebAuthn.
async function register(username = "", opts = {}) {
    // Register result.
    const register_result = await (opts.client || client).register(
        username,
        opts.challenge || 'random-challenge-base64-encoded', {
        authenticatorType: "local",
        userVerification: "required",
        attestation: false,
        discoverable: false,
        debug: true,
        ...opts,
    });

    // Result result.
    return {
        authenticatorData: base64ToHex(register_result.authenticatorData),
        clientData: clientDataToJSON(register_result.clientData),
        credentialId: base64ToHex(register_result.credential.id),
        username,
        publicKey: await cryptoKeyToHex(await parseCryptoKey(register_result.credential.publicKey)),
        publicKeyCompact: '0x' + (await cryptoKeyToHex(await parseCryptoKey(register_result.credential.publicKey))).slice(4),
    };
}

// Sign / authenticate a message with P256 using WebAuthn.
async function sign(account = {}, challenge = "0x", opts = {}) {
    // Result from authentication.
    const authenticate_result = await (opts.client || client).authenticate([
        hexToBase64(account.credentialId).slice(0, -1), // remove =
    ], utils.toBase64url(parseHexString(challenge)), opts);

    // Client hash.
    const clientHash = await utils.sha256(utils.parseBase64url(authenticate_result.clientData));

    // Message.
    const message_result = bufferToHex(
        utils.concatenateBuffers(
            utils.parseBase64url(authenticate_result.authenticatorData), 
            clientHash,
        ),
    );

    const sig = bufferToHex(convertASN1toRaw(utils.parseBase64url(authenticate_result.signature)));

    // Return formatted result.
    return {
        account,
        message: message_result,
        hash: bufferToHex(await utils.sha256(parseHexString(message_result))),
        authenticatorData: base64ToHex(authenticate_result.authenticatorData),
        clientData: clientDataToJSON(authenticate_result.clientData),
        credentialId: base64ToHex(authenticate_result.credentialId),
        signature: sig,
        signatureEncoded: sig,
    };
}

// Recover a P256 public key from a signature and message.
async function verify(signature_object = {}) {
    // Parse and check hex data.
    const message = parseHexString(signature_object.message);
    const signature = parseHexString(signature_object.signature);
    const publicKey = parseHexString(signature_object.account 
        ? signature_object.account.publicKey
        : signature_object.publicKey);

    // Produce crypto key object.
    const crypto_key = await crypto.subtle.importKey('raw', publicKey, {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
    }, true, ['verify']);

    // Return result.
    return await crypto.subtle.verify({
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
    }, crypto_key, signature, message);
}

const obj = {
    utils: {
        ...utils,
        hexToBuffer,
        parseHexString,
        parseCryptoKey,
        bufferToHex,
        cryptoKeyToHex,
        base64ToHex,
        hexToBase64,
        clientDataToJSON,
        convertASN1toRaw,
        concatHexStrings,
    },
    register,
    sign,
    verify,
};

// If window.
if (typeof window !== 'undefined') {
    window.authn = obj;
}

// Export functions.
module.exports = obj;