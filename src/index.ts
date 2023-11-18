
import { secp256r1 } from '@noble/curves/p256';

export function randomChallenge() {
    return crypto.randomUUID();
}

export function toBuffer(txt: string) :ArrayBuffer {
    return Uint8Array.from(txt, c => c.charCodeAt(0)).buffer; // @ts-nocheck
}

export function parseBuffer(buffer: ArrayBuffer) :string {
    return String.fromCharCode(...new Uint8Array(buffer));
}

export function isBase64url(txt: string) :boolean {
    return txt.match(/^[a-zA-Z0-9\-_]+=*$/) !== null;
}

export function toBase64url(buffer: ArrayBuffer) :string {
    const txt = btoa(parseBuffer(buffer)); // base64
    return txt.replaceAll('+', '-').replaceAll('/', '_');
}

export function parseBase64url(txt: string) :ArrayBuffer {
    txt = txt.replaceAll('-', '+').replaceAll('_', '/'); // base64url -> base64
    return toBuffer(atob(txt));
}

export async function sha256(buffer: ArrayBuffer | Uint8Array) :Promise<ArrayBuffer> {
    return await crypto.subtle.digest('SHA-256', buffer);
}

export function concatenateBuffers(buffer1 :ArrayBuffer, buffer2  :ArrayBuffer): Uint8Array {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp;
}

// Convert signature from ASN.1 sequence to "raw" format.
export function convertASN1toRaw(signatureBuffer= {}) {
    const usignature = new Uint8Array(signatureBuffer);

    const rStart = usignature[4] === 0 ? 5 : 4;
    const rEnd = rStart + 32;
    const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
    const r = usignature.slice(rStart, rEnd);
    const s = usignature.slice(sStart);

    return new Uint8Array([...r, ...s]);
}

// Prefixed hex string to buffer.
export function hexToBuffer(value: string): ArrayBuffer {
    return new Uint8Array(value.slice(2).match(/../g).map(h=>parseInt(h,16))).buffer;
}

// Parse hex string to buffer.
export function parseHexString(value: string): ArrayBuffer {
    const error = `Invalid hex value '${value}' should be a 0x hex prefixed value.`;

    if (typeof value !== "string" || value.substring(0, 1) == "0x") {
        throw new Error(error);
    }

    return hexToBuffer(value);
}

// Parse public key from Buffer.
export async function parseCryptoKey(publicKey: string): any {
    // Parse base64 URL.
    const buffer = parseBase64url(publicKey);

    // Import key and convert to correct key CryptoKey.
    return crypto.subtle.importKey('spki', buffer, {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
    }, true, ['verify']);
}

// Buffer to hex.
export function bufferToHex (buffer: ArrayBuffer | Uint8Array): string {
    return '0x' + [...new Uint8Array (buffer)]
        .map (b => b.toString (16).padStart (2, "0"))
        .join ("");
}

// Crypto key to hex.
export async function cryptoKeyToHex(cryptoKey: any): Promise<string> {
    return bufferToHex(
        await crypto.subtle.exportKey('raw', cryptoKey),
    );
}

// Base64 to hex.
export function base64ToHex(value:string): string {
    return bufferToHex(parseBase64url(value));
}

// Hex to base64.
export function hexToBase64(value:string): string {
    return toBase64url(parseHexString(value));
}

// Concatenate hex strings.
export function concatHexStrings(value1: string, value2: string): ArrayBuffer {
    return hexToBuffer(value1 + value2.slice(2));
}

// A window object for testing.
const windowObject:any = {
    location: {
        hostname: "",
    },
};

// A fake navigator object for testing.
const navigatorObject:any = {
    credentials: {
        create: async () => {
            return {};
        },
        get: async () => {
            return {};
        },
    },
};

// Returns an EIP-2098 encoded signature.
export function encode_signature(signatureCompact:string = '0x', recovery_id:number = 1): string {
    let buffer = new Uint8Array(hexToBuffer(signatureCompact));

    if(buffer[32] >> 7 !== 0) {
        throw new Error(`Non-normalized signature ${signatureCompact}`);
    }

    const v = recovery_id;
    buffer[32] = (v << 7) | (buffer[32] & 0x7f);

    return bufferToHex(buffer);
}

// Decode a EIP-2098 encoded signature.
export function decode_signature(signatureCompact:string = '0x'): any {
    let buffer = new Uint8Array(hexToBuffer(signatureCompact));

    const v = (buffer[32] & 0x80) != 0;
    buffer[32] = buffer[32] & 0x7f;

    return {
        signature: bufferToHex(buffer),
        v: v ? 1 : 0,
    };
}

// Remove base64 padding.
function removeBase64Padding(data:string): string {
    return data.substring(0, data.indexOf("=", data.length - 2));
}

// ClientData to JSON.
function clientDataToJSON(clientData:string):any {
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(
        parseBase64url(clientData),
    );
    const json_object = JSON.parse(decodedClientData);

    // Extract the pre and post challenge strings from the UTF-8 encoded JSON.
    const searchString = '"challenge":"';
    const challengeStart = decodedClientData.indexOf(searchString);
    const challengeEnd = decodedClientData.indexOf('"', challengeStart + searchString.length);
    const preChallenge =  decodedClientData.substring(0, challengeStart + searchString.length);
    const postChallenge =  decodedClientData.slice(challengeEnd);
    const encodedChallenge = bufferToHex(toBuffer(json_object.challenge));
    const encoded = bufferToHex(parseBase64url(clientData));

    // Parse the string as an object.
    return {
        encoded,
        challengeEncoded: encodedChallenge,
        preChallengeEncoded: bufferToHex(toBuffer(preChallenge)),
        preChallenge,
        postChallengeEncoded: bufferToHex(toBuffer(postChallenge)),
        postChallenge,
        ...json_object,
    };
}

/*
fn main(signature:B512, authid:Bytes, txid:b256, pre:Bytes, post:Bytes) -> bool {
    // Compute the digest.
    let digest = webauthn_hash(authid, pre, Bytes::from(txid), post);

    // Derive the public key.
    let public_key = ec_recover_r1(signature, digest).unwrap();

    // Derived address == the Address.
    sha256(public_key.into()) == ADDRESS // && txid == tx_id()
}
*/

// Simulate what its like for onchain verification.
export async function simulate_onchain_verification(
    publicKey: string = "0x",
    publicKeyCompact: string = "0x",
    address: string = "0x",
    authdata: string = "0x",
    pre: string = "0x",
    challenge: string = "0x",
    post: string = "0x",
    signature: string = "0x",
): Promise<boolean> {
    // Encoded pre + (challenge) + post.
    const clientData = pre
        + bufferToHex(toBuffer(hexToBase64(challenge).slice(0, -1))).slice(2)
        + post.slice(2);

    const clientDataHash = bufferToHex(await sha256(hexToBuffer(clientData)));

    const message = bufferToHex(concatHexStrings(authdata, clientDataHash));
    const computedAddress = bufferToHex(await sha256(hexToBuffer(publicKeyCompact)));

    // Check public key.
    if ((publicKeyCompact.length - 2) / 2 != 64) {
        throw new Error("invalid publicKey length shoudld be 64");
    }

    // Check address.
    if (computedAddress != address) {
        throw new Error("invalid address");
    }

    // Check verification.
    return secp256r1.verify(
        decode_signature(signature).signature.slice(2),
        message.slice(2),
        publicKey.slice(2),
        { lowS: false, prehash: true },
    ) === true;
}

export default class Account {
    #id: string = '';
    #username: string = '';
    #publicKey: string = '';
    #options: any = {
        window: typeof window !== "undefined" ? window : windowObject,
        navigator: typeof navigator !== "undefined" ? navigator : navigatorObject,
    };

    get id(): string { return this.#id; }
    get username(): string { return this.#username; }
    get publicKey(): string { return this.#publicKey; }
    get publicKeyCompact(): string { return '0x' + this.#publicKey.slice(4); }

    async address(): Promise<string> {
        return bufferToHex(await sha256(hexToBuffer(this.publicKeyCompact)));
    }

    /**
     *  The ```constructor``` method for constructing an account.
     *
     *  This allows you to recover an account from a DB to use for authorization.
     */
    constructor(username:string, id:string, pulicKey: string, options?:any) {
        this.#id = id;
        this.#username = username;
        this.#publicKey = pulicKey;
        this.#options = options || this.#options;
    }

    /**
     *  The ```register``` method for signature.
     *
     *  This is the primary account register function for WebAuthn.
     */
    async register(username:string, options?:any): any {
        // Set the username.
        this.#username = username;

        // Setup default options.
        options = options || {};

        // PublicKeyCredentialCreationOptions.
        const publicKeyCredentialCreationOptions = options.creationOptions || {
            challenge: toBuffer(options.challenge || 'random-challenge-base64-encoded'),
            rp: {
                id: this.#options.window.location.hostname,
                name: this.#options.window.location.hostname,
            },
            user: {
                id: options.userHandle
                    ? toBuffer(options.userHandle)
                    : await sha256(new TextEncoder().encode('passwordless.id-user:' + username)), // ID should not be directly "identifiable" for privacy concerns
                name: username,
                displayName: username,
            },
            allowCredentials: [{
                type: 'public-key',
                transports: ["internal", "hybrid"],
            }],
            pubKeyCredParams: [{
                alg: -7, // P-256
                type: "public-key",
            }],
            authenticatorSelection: {
                userVerification: "required",
                authenticatorAttachment: "platform",
                residentKey: "preferred",
                requireResidentKey: false,
            },
            attestation: "none",
            timeout: 60000,
        };

        if(options.debug) console.debug(publicKeyCredentialCreationOptions);

        const credential = await this.#options.navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions,
        }) as any;

        const response = credential.response as any;

        if(options.debug) console.debug(response);

        this.#id = base64ToHex(credential.id);
        this.#publicKey = await cryptoKeyToHex(
            await parseCryptoKey(
                toBase64url(response.getPublicKey())
            )
        );

        return {
            id: this.#id,
            publicKey: this.#publicKey,
            authenticatorData: response.authenticatorData,
            clientData: response.clientDataJSON,
            publicKeyCredentialCreationOptions,
        };
    }

    /**
     *  The ```sign``` authorization signing method.
     *
     *  This uses authorization under the hood to sign a message.
     */
     async sign(challenge: string = "0x", options?:any): Promise<any> {
        // Setup default options.
        options = options || {};

        // Challenge in base64.
        const challengeBase64 = toBase64url(parseHexString(challenge));

        // Authentication options.
        const authOptions: any = {
            challenge: parseBase64url(challengeBase64),
            rpId: this.#options.window.location.hostname,
            allowCredentials: [{
                id: parseBase64url(hexToBase64(this.#id).slice(0, -1)),
                type: 'public-key',
                transports: ['internal'],
            }],
            userVerification: "required",
            timeout: 60000,
        };

        if(options.debug) console.debug(authOptions)

        // Get authentication.
        let authentication = await this.#options.navigator.credentials.get({
            publicKey: authOptions,
            mediation: options.mediation,
        });

        // Compute the client hash.
        const clientData = toBase64url(authentication.response.clientDataJSON);
        const clientHash = await sha256(parseBase64url(clientData));

        // Authenticator data.
        const authenticatorData = parseBase64url(
            toBase64url(
                authentication.response.authenticatorData
            )
        );

        // Message.
        const message = bufferToHex(
            concatenateBuffers(
                authenticatorData, 
                clientHash,
            ),
        );

        // Compute the signature.
        const signature = bufferToHex(
            convertASN1toRaw(
                parseBase64url(
                    toBase64url(
                        authentication.response.signature
                    )
                )
            )
        );

        const digest = bufferToHex(await sha256(parseHexString(message)));

        // Return the signature data.
        return {
            challengePaddingLength: challengeBase64,
            digest,
            authenticatorData: bufferToHex(authenticatorData),
            clientData: clientDataToJSON(clientData),
            message,
            normalized: normalizeSignature(signature, digest, this.publicKeyCompact), // EIP-2098
            signature,
            authOptions,
        };
     }

     verify(message:string = "0x", signature:string = "0x"): boolean {
        return secp256r1.verify(
            signature.slice(2),
            message.slice(2),
            this.#publicKey.slice(2),
            { lowS: false, prehash: true },
        ) === true;
    }
}

function recover(signature = '0x', message = '0x', recoveryBit = 0) {
    const recovered = secp256r1.Signature.fromCompact(
        bufferToHex(
            secp256r1.Signature.fromCompact(
                signature.slice(2)
            )
            .normalizeS()
            .toCompactRawBytes()
        ).slice(2),
    )
    .addRecoveryBit(recoveryBit)
    .recoverPublicKey(
        message.slice(2),
    );

    return '0x' + recovered.x.toString(16) + recovered.y.toString(16);
}

// Normalize a signature and encode a recovery bit based upon the public key.
function normalizeSignature(signature = '0x', digest = "0x", publicKeyCompact = '0x') {
    let check0 = recover(signature, digest, 0) == publicKeyCompact;
    let check1 = recover(signature, digest, 1) == publicKeyCompact;
    let recoveryBit = check0 ? 0 : 1;

    return encode_signature(
        bufferToHex(
            secp256r1.Signature.fromCompact(
                signature.slice(2)
            )
            .normalizeS()
            .toCompactRawBytes()
        ),
        recoveryBit,
    );
}

/*
function test() {
    let publicKey = "0x0491698c5e1d62846f1a42a6e15a3ebef955de429fec5a0b832a94bf4875ef3faba8bdcf29dab9d3238dd4275553d91b34dffd3769ffc5913c730da32d4d96b26d";
    let message = "0x581101f9a2d61f04c1e820151e76d543914e2d0cfa39bcca8a6e8eed2f942f88";
    let signature = '0x01e78d022be11ad407651677eb83ec9bc23cf5f99a0021b5a0e312d0d9b56cce4fb480aab1922cace4598c8bcb9b05166f6d7447cba013855b24661b3dc3269c';

    let normalize = (sig = "0x", bit = 0) => encode_signature(
        bufferToHex(
            secp256r1.Signature.fromCompact(
                sig.slice(2)
            )
            .normalizeS()
            .toCompactRawBytes()
        ),
        bit,
    );

    let check0 = recover(signature, message, 0) == '0x' + publicKey.slice(4);
    let check1 = recover(signature, message, 1) == '0x' + publicKey.slice(4);
    let recoveryBit = check0 ? 0 : 1;

    let normalized = normalize(signature, recoveryBit);

    console.log(normalized);
}
*/

// test();