# authn-sign
A simplified browser interface for WebAuthn focused on secp256r1 (P-256) signing.

## Features
- `register`, `sign` (i.e. authenticate) and `recover` from WebAuthn.
- Extremly light with minimal dependancies (just `@noble/curves`).
- Supports compressed and non compressed public keys.
- Supports EIP-2098 encoded and non-encoded signatures.
- Designed for blockchain applications which typically use *prefixed hex data* encoding.
- Address creation using `sha256(publicKeyCompact)`.
- Decoded `pre` and `post` challenge JSON `clientData` strings provided out of the box.

*Warning: this library is in BETA, do not use it for production use.*

A note that WebAuthn local testing requires HTTPS and a `localhost` non IP address.

Try it now: [authn-sign.vercel.app](https://authn-sign.vercel.app)

## Install
```sh
npm install --save authn-sign
```

### CDN (via Module)
```js
import Account from "https://unpkg.com/authn-sign@latest/build/authn-sign.min.js";
```

### CDN (via UMD)
```html
<script type="text/javascript" src="https://unpkg.com/authn-sign@latest/build/authn-sign.umd.js"></script>
```

Export available at `window.authnSign`.

## Build
```sh
# Install Bun.js - https://bun.sh
bun run build
```
Output is set to `./build/[name].[ext]`.

## Test
```
bun run test
```

## Example
```js
import Account from "authn-sign";

// Account 1.
const username = "account_1";

// Authn Account.
const account = new Account(/* username, id, publicKey */);

(async () => {
    // Register account.
    await account.register(username /*, options */);

    // Log the signature.
    console.log('Account', {
        "publicKey": account.publicKey,
        "publicKeyCompact": account.publicKeyCompact,
        "id": account.id,
        "username": username,
    });

    // The challenge (which in blockchain would be the tx id).
    const challenge = '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    // Sign the challenge.
    const signature = await account.sign(challenge /*, options */);

    // Log the signature payload.
    console.log('Signature', signature);
})();
```

### Example Code:
[./example/index.html](./example/index.html)

### Hosted Example:
[authn-sign.vercel.app/](https://authn-sign.vercel.app)

### Wallet Example:
[authn-sign.vercel.app/wallet.html](https://authn-sign.vercel.app/wallet.html)

## Blockchain Verification Check (in NodeJS)
```js
// This would happen in the browser.
const account = new Account();
await account.register('username_1');
const transaction_hash = '0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d';
const signature = await account.sign(account, transaction_hash);

// This would happen on chain.
const signedData = signature.clientData.preChallenge 
  + utils.hexToBase64(transaction_hash).slice(0, -1) // remove last character
  + signature.clientData.postChallenge;
const clientDataHash = utils.bufferToHex(await utils.sha256(utils.toBuffer(signedData)));
const message = utils.concatHexStrings(signature.authenticatorData, clientDataHash);
// const messageHash = utils.bufferToHex(await utils.sha256(message));

// This P-256 verficiation would also happen on chain.
const is_verified = await verify({
  publicKey: account.publicKey,
  message: utils.bufferToHex(message),
  signature: signature.signature,
});

console.log(is_verified);
```

## Size
```
authn-sign.min.js        35.44 KB
authn-sign.js        63.70 KB
```

## Exports
```ts
export declare function toBuffer(txt: string): ArrayBuffer;
export declare function parseBuffer(buffer: ArrayBuffer): string;
export declare function isBase64url(txt: string): boolean;
export declare function toBase64url(buffer: ArrayBuffer): string;
export declare function parseBase64url(txt: string): ArrayBuffer;
export declare function sha256(buffer: ArrayBuffer | Uint8Array): Promise<ArrayBuffer>;
export declare function concatenateBuffers(buffer1: ArrayBuffer, buffer2: ArrayBuffer): Uint8Array;
export declare function convertASN1toRaw(signatureBuffer?: {}): Uint8Array;
export declare function hexToBuffer(value: string): ArrayBuffer;
export declare function parseHexString(value: string): ArrayBuffer;
export declare function parseCryptoKey(publicKey: string): Promise<any>;
export declare function bufferToHex(buffer: ArrayBuffer | Uint8Array): string;
export declare function cryptoKeyToHex(cryptoKey: any): Promise<string>;
export declare function base64ToHex(value: string): string;
export declare function hexToBase64(value: string): string;
export declare function concatHexStrings(value1: string, value2: string): ArrayBuffer;
export declare const windowObject: any;
export declare const navigatorObject: any;
export declare function encode_signature(signatureCompact?: string, recovery_id?: number): string;
export declare function decode_signature(signatureCompact?: string): any;
export declare function removeBase64Padding(data: string): string;
export declare function clientDataToJSON(clientData: string): any;
export declare function simulate_onchain_verification(publicKey?: string, publicKeyCompact?: string, address?: string, authdata?: string, pre?: string, challenge?: string, post?: string, signature?: string): Promise<boolean>;
export default class Account {
    #private;
    get id(): string;
    get username(): string;
    get publicKey(): string;
    get publicKeyCompact(): string;
    address(): Promise<string>;
    /**
     *  The ```constructor``` method for constructing an account.
     *
     *  This allows you to recover an account from a DB to use for authorization.
     */
    constructor(username: string, id: string, pulicKey: string, options?: any);
    /**
     *  The ```register``` method for signature.
     *
     *  This is the primary account register function for WebAuthn.
     */
    register(username: string, options?: any): Promise<any>;
    /**
     *  The ```sign``` authorization signing method.
     *
     *  This uses authorization under the hood to sign a message.
     */
    sign(challenge?: string, options?: any): Promise<any>;
    /**
     *  The ```verify``` a message and signature aligns with this publicKey.
     *
     *  This will enable verification based upon a message and unencoded signature.
     */
    verify(message?: string, signature?: string): boolean;
}
export declare function recover(signature?: string, message?: string, recoveryBit?: number): string;
export declare function normalizeSignature(signature?: string, digest?: string, publicKeyCompact?: string): string;
```

## Todo
- Nits and cleanup for encoding.
- More protective measures against bad values (assertHex etc.).
- Better typing structures (e.g. PublicKey, Signature, CreationOption etc.).
- Make optional the dependancy on node/browser crypto module.
- Final API is still being decided so leave your feedback as an issue!
- Better account recovery from credentials.get.

## Licence
```
MIT License

Copyright (c) 2023 Fuel Labs Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
