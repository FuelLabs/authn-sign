// @ts-ignore
import { secp256r1 } from '@noble/curves/p256';

export function toBuffer(txt: string) :ArrayBuffer {
    // @ts-ignore
    return Uint8Array.from(txt, c => c.charCodeAt(0)).buffer;
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

export function concatenateBuffers(buffer1 :ArrayBuffer | Uint8Array, buffer2  :ArrayBuffer | Uint8Array): Uint8Array {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp;
}

// Convert signature from ASN.1 sequence to "raw" format.
export function convertASN1toRaw(signatureBuffer= {}) {
    // @ts-ignore
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
    // @ts-ignore
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
export async function parseCryptoKey(publicKey: string): Promise<any> {
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
export const windowObject:any = {
    location: {
        hostname: "",
    },
};

// A fake navigator object for testing.
export const navigatorObject:any = {
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
export function removeBase64Padding(data:string): string {
    return data.substring(0, data.indexOf("=", data.length - 2));
}

// ClientData to JSON.
export function clientDataToJSON(clientData:string):any {
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

// This is used for getting accounts with minimal information.
const defaultRegistrationChallenge = '0xd71c99459c75101576e1019080db5deef5dbf0669fc8421faf17ff883977ebcb';

// Compute address. 
export async function computeAddress(publicKeyCompact = '0x') {
    return bufferToHex(await sha256(hexToBuffer(publicKeyCompact)));
}

export function buildOptions() {
    return {
        window: typeof window !== "undefined" ? window : windowObject,
        navigator: typeof navigator !== "undefined" ? navigator : navigatorObject,
    };
}

// Primary Account object.
export default class Account {
    #id: string = '';
    #username: string = '';
    #publicKey: string = '';
    #registration: any = {};
    #options: any = buildOptions();

    // Getters & setters.
    get id(): string { return this.#id; }
    get username(): string { return this.#username; }
    get publicKey(): string { return this.#publicKey; }
    get registration(): string { return this.#registration; }
    get publicKeyCompact(): string { return '0x' + this.#publicKey.slice(4); }
    set registration(value:any) {
        this.#registration = value;
    }

    // Return the address based upon sha256.
    async address(): Promise<string> {
        return computeAddress(this.publicKeyCompact);
    }

    /**
     *  The ```constructor``` method for constructing an account.
     *
     *  This allows you to recover an account from a DB to use for authorization.
     */
    constructor(username:string = '0x', id:string = '0x', pulicKey: string = '0x', options?:any) {
        this.#id = id;
        this.#username = username;
        this.#publicKey = pulicKey;
        this.#options = options || this.#options;
    }

    /**
     *  The ```create``` method for the account.
     *
     *  This is the primary account register function for WebAuthn.
     */
    static async create(username:string, options?:any): Promise<Account> {
        const optionsDefaults:any = buildOptions();

        // Setup default options.
        options = Object.assign(buildOptions(), options || {});

        // PublicKeyCredentialCreationOptions.
        const publicKeyCredentialCreationOptions = options.creationOptions || {
            challenge: toBuffer(options.challenge || defaultRegistrationChallenge),
            rp: {
                id: options.window.location.hostname,
                name: options.window.location.hostname,
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
                transports: ["internal"],
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
            attestation: options.attestation ? options.attestation : "none",
            timeout: 60000,
        };

        // Debugging check.
        if(options.debug) console.debug(publicKeyCredentialCreationOptions);

        // Credential creation.
        const credential = await options.navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions,
        }) as any;

        // Gather the response.
        const response = credential.response as any;

        
        // Another debugging check.
        if(options.debug) console.debug(response);

        // New account.
        const account = new Account(
            username,
            base64ToHex(credential.id),
            await cryptoKeyToHex(
                await parseCryptoKey(
                    toBase64url(response.getPublicKey())
                ),
            ),
        );

        // Add key registration details.
        account.registration = {
            authenticatorData: response.authenticatorData,
            clientData: response.clientDataJSON,
            publicKeyCredentialCreationOptions,
        };

        // Return the new account.
        return account;
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

        // Recovery options.
        const recoverOptions = {
            challenge: hexToBuffer(options.challenge || defaultRegistrationChallenge),
            rpId: this.#options.window.location.hostname,
            userVerification: "required",
        };

        // Authentication options.
        const authOptions: any = options.recover ? null : {
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

        if(options.debug) console.debug(recoverOptions, authOptions);

        // Get authentication.
        let authentication = await this.#options.navigator.credentials.get({
            publicKey: options.recover ? recoverOptions : authOptions,
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

        // Prepair the digest.
        const digest = bufferToHex(await sha256(parseHexString(message)));

        // Recover both signatures. 
        const publicKey0 = options.recover ? recover(signature, digest, 0) : this.publicKeyCompact;
        const publicKey1 = options.recover ? recover(signature, digest, 1) : this.publicKeyCompact;

        // Return the signature data.
        return {
            id: authentication.id,
            rawId: authentication.rawId,
            challengePaddingLength: challengeBase64,
            digest,
            authenticatorData: bufferToHex(authenticatorData),
            clientData: clientDataToJSON(clientData),
            message,
            normalized: options.recover ? '0x' : normalizeSignature(signature, digest, this.publicKeyCompact), // EIP-2098
            signature,
            authOptions,
            recovered: options.recover ? {
                publicKey0,
                address0: await computeAddress(publicKey0),
                publicKey1,
                address1: await computeAddress(publicKey1),
            } : null,
        };
    }

    /**
     *  ```recover``` an account from two WebAuthn signatures (dual signature recovery).
     *
     *  This allows a user to recover their WebAuthn account (we need this because WebAuthn doesn't return a public key during the signing process).
     */
     static async recover(username = 'username_1', options:any = {}): Promise<Account> {
        // Attempt a recovery signature.
        const recoverySignatrue = await (new Account()).sign('0x86', { recover: true });

        // Build two potential accounts with different recovery bits.
        const account0 = new Account(
            username,
            recoverySignatrue.id,
            '0x04' + recoverySignatrue.recovered.publicKey0.slice(2),
        );
        const account1 = new Account(
            username,
            recoverySignatrue.id,
            '0x04' + recoverySignatrue.recovered.publicKey1.slice(2),
        );

        // If there is a precheck method.
        const precheck = options.precheck as Function;

        // You can pre-check the accounts before going to a second signature.
        // i.e. you can check for things like account history (an indicator its the right account).
        if (precheck) {
            if (await precheck(account0)) return account0;
            if (await precheck(account1)) return account1;
        }

        // Attempt second signature.
        try {
            // If sign is successful (no invalid bit), then we know this account is the correct one.
            await account0.sign('0x86');

            // We return Account0.
            return account0;
        } catch (account0Error) {
            if ((account0Error as any).message.includes('invalid bit')) {
                // If there was an error signing with the above account, we then assume the second account.
                return account1;
            } else {
                throw new Error('A recovery error has occured: ' + (account0Error as any).message);
            }
        }
    }
}

// Recover a public key from a signature, message and recovery bit.
export function recover(signature = '0x', message = '0x', recoveryBit = 0) {
    // Normalize signature, encode the recovery bit and recover public key.
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

    // Pad Y if uneven.
    let y = recovered.y.toString(16);
    if (y.length == 63) {
        y = '0' + y;
    }

    // Pad x if uneven.
    let x = recovered.x.toString(16);
    if (x.length == 63) {
        x = '0' + x;
    }

    // Return the public key.
    return '0x' + x + y;
}

// Throw invalid.
const throwInvalid = () => { throw new Error('invalid bit'); }

// Normalize a signature and encode a recovery bit based upon the public key.
export function normalizeSignature(signature = '0x', digest = "0x", publicKeyCompact = '0x') {
    // Check both recovery bits, ensure on of them recovers to the public key.
    let check0 = recover(signature, digest, 0) == publicKeyCompact;
    let check1 = recover(signature, digest, 1) == publicKeyCompact;

    // Build the recovery bit based upon the recovery.
    let recoveryBit = check0 ? 0 : (check1 ? 1 : throwInvalid());

    // Normalize signature.
    const normalizedSignature = bufferToHex(
        secp256r1.Signature.fromCompact(
            signature.slice(2)
        )
        .normalizeS()
        .toCompactRawBytes()
    );

    // Encode recovery bit in signature.
    return encode_signature(
        normalizedSignature,
        recoveryBit,
    );
}
