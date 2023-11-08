# authn-sign
A simplified browser interface for WebAuthn focused on secp256r1 (P-256) and SHA-256.

## Features
- `register`, `sign` (i.e. authenticate) and `recover` from WebAuthn.
- Designed for blockchain applications which typically use *prefixed hex data* encoding.
- Extremly light with minimal dependancies (just an interface over `@passwordless-id/webauthn`).
- Decoded `pre` and `post` challenge JSON `clientData` strings provided out of the box.

*Warning: this library is in BETA, do not use it for production use.*

A note that WebAuthn local testing requires HTTPS and a `localhost` non IP address.

## Install
```
npm install --save authn-sign
```

### CDN
```
<script src="https://unpkg.com/authn-sign@latest/umd/authn-sign.min.js"></script>
```

### As a Module
```
import authn from "https://unpkg.com/authn-sign@latest/umd/authn-sign.min.js";
```

## Build
```sh
# Install Bun.js - https://bun.sh
bun run build
```

Output is set to `./build`.

## Example
```js
const { register, sign, verify } = require('authn-sign');

const account = await register('account_1');

/* console.log(account);
{
  "authenticatorData": "0x87464bab513aa9e996c81b0a5978b3401271075240eb5a14b6ca84292e10feb74500000000adce000235bcc60a648b0b25f1f0550300205e27f6ac706870b5dc6493f5f5b59b9429e3ae1d40afbc0b4396d1e80cf3b3eda50102032620012158202eefa0642c42401a02c2e787a2f44ef6de964f4d1c115e76806194d48ae7cc1e22582063b2cb9c0ffbd155ed4085bf4a00201689e9ba95a9dfa6302d2c0af67ef5c51c",
  "clientData": {
    "encoded": "0x7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2272616e646f6d2d6368616c6c656e67652d6261736536342d656e636f646563222c226f726967696e223a2268747470733a2f2f6f6c642d703235362d6675656c65722e76657263656c2e617070222c2263726f73734f726967696e223a66616c73657d",
    "preChallenge": "{\"type\":\"webauthn.create\",\"challenge\":\"",
    "postChallenge": "\",\"origin\":\"https://old-p256-fueler.vercel.app\",\"crossOrigin\":false}",
    "type": "webauthn.create",
    "challenge": "random-challenge-base64-encodec",
    "origin": "https://old-p256-fueler.vercel.app",
    "crossOrigin": false
  },
  "credentialId": "0x5e27f6ac706870b5dc6493f5f5b59b9429e3ae1d40afbc0b4396d1e80cf3b3ed",
  "username": "account_1",
  "publicKey": "0x042eefa0642c42401a02c2e787a2f44ef6de964f4d1c115e76806194d48ae7cc1e63b2cb9c0ffbd155ed4085bf4a00201689e9ba95a9dfa6302d2c0af67ef5c51c"
}
*/

const signature = await sign(account, '0xabcd');

/* console.log(signature);
{
  "account": {
    "authenticatorData": "0x87464bab513aa9e996c81b0a5978b3401271075240eb5a14b6ca84292e10feb74500000000adce000235bcc60a648b0b25f1f0550300205e27f6ac706870b5dc6493f5f5b59b9429e3ae1d40afbc0b4396d1e80cf3b3eda50102032620012158202eefa0642c42401a02c2e787a2f44ef6de964f4d1c115e76806194d48ae7cc1e22582063b2cb9c0ffbd155ed4085bf4a00201689e9ba95a9dfa6302d2c0af67ef5c51c",
    "clientData": {
      "encoded": "0x7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2272616e646f6d2d6368616c6c656e67652d6261736536342d656e636f646563222c226f726967696e223a2268747470733a2f2f6f6c642d703235362d6675656c65722e76657263656c2e617070222c2263726f73734f726967696e223a66616c73657d",
      "challengeEncoded": "0x59ca84fb79f2a7447b9e82c7412df58c688910cba202b7d4e9bf329ce07f931c",
      "preChallenge": "{\"type\":\"webauthn.create\",\"challenge\":\"",
      "postChallenge": "\",\"origin\":\"https://old-p256-fueler.vercel.app\",\"crossOrigin\":false}",
      "type": "webauthn.create",
      "challenge": "random-challenge-base64-encodec",
      "origin": "https://old-p256-fueler.vercel.app",
      "crossOrigin": false
    },
    "credentialId": "0x5e27f6ac706870b5dc6493f5f5b59b9429e3ae1d40afbc0b4396d1e80cf3b3ed",
    "username": "account_1",
    "publicKey": "0x042eefa0642c42401a02c2e787a2f44ef6de964f4d1c115e76806194d48ae7cc1e63b2cb9c0ffbd155ed4085bf4a00201689e9ba95a9dfa6302d2c0af67ef5c51c"
  },
  "message": "0x87464bab513aa9e996c81b0a5978b3401271075240eb5a14b6ca84292e10feb70500000000a11f39a2278677c42be4fa15456e247dbf61d563821854e82b4537ebcb1da2fe",
  "hash": "0x58e5be449a8a034972f3938655c50f4e146b19b3484c5266a7147c675a08d2c0",
  "authenticatorData": "0x87464bab513aa9e996c81b0a5978b3401271075240eb5a14b6ca84292e10feb70500000000",
  "clientData": {
    "encoded": "0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22576371452d336e79703052376e6f4c48515333316a47694a454d756941726655366238796e4f425f6b7877222c226f726967696e223a2268747470733a2f2f6f6c642d703235362d6675656c65722e76657263656c2e617070222c2263726f73734f726967696e223a66616c73657d",
    "challengeEncoded": "0x59ca84fb79f2a7447b9e82c7412df58c688910cba202b7d4e9bf329ce07f931c",
    "preChallenge": "{\"type\":\"webauthn.get\",\"challenge\":\"",
    "postChallenge": "\",\"origin\":\"https://old-p256-fueler.vercel.app\",\"crossOrigin\":false}",
    "type": "webauthn.get",
    "challenge": "WcqE-3nyp0R7noLHQS31jGiJEMuiArfU6b8ynOB_kxw",
    "origin": "https://old-p256-fueler.vercel.app",
    "crossOrigin": false
  },
  "credentialId": "0x5e27f6ac706870b5dc6493f5f5b59b9429e3ae1d40afbc0b4396d1e80cf3b3ed",
  "signature": "0xe458c352076f238017111ec3b688af3c5d572378ca08eab142c9a3e5ca0b8f60276fc9c10e65df4a510f21c06ba98276504164943b95ee3b4a4be12f563506b3"
}
*/

const is_valid = await verify(signature);

/* console.log(is_valid);

true
*/
```

## Blockchain Verification Check (in NodeJS)
```js
const { register, sign, verify, utils } = require('authn-sign');

// This would happen in the browser.
const account = await register('username_1');
const transaction_hash = '0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d';
const signature = await sign(account, transaction_hash);

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
auth-sign.min.js        15.49 KB
auth-sign.js            27.25 KB
```

## Exports
```ts
async register(username:String[, opts:Object]): Account;
async sign(account: Account, message: String[, opts:Object]): Signature;
async verify({ publicKey: String, message: String, signature: String } | Signture): Bool;
utils; // See source.
```

## Todo
- Typescript typing.
- Nits and cleanup for encoding.
- Make optional the dependancy on node/browser crypto module.
- Remove dependancy on @passwordless-id/webauthn.

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
