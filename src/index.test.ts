import { expect, test } from "bun:test";
import { bufferToHex, normalizeSignature, encode_signature, decode_signature } from "./index";
import { secp256r1 } from '@noble/curves/p256';

// Fake WebAuthn client.
const client = {
    register: async function(username:string, challenge = '0x', opts = {}): Promise<any> {
        return {};
    },
    authenticate: async function(ids:[string], challenge:string, opts = {}): Promise<any> {
        return {};
    },
};

test("test signature encode and decode", async () => {
    const signature = "0x2a9846856032981d61bcef1a212f965d9a8f95e8679a63283317bb57731f51027154a7b4735ca121f0c05d2bc78c74c93ada4751fe6b880e7fa98803347d3ee8";

    const encoded = encode_signature(signature, 1);
    const decoded = decode_signature(encoded);
    expect(decoded.v).toBe(1);
});

test("test signature normalize and decode", async () => {
    const publicKey = "0x15231791ca4fa91fa23ad1fee0391fe1f22693ec71e17a76e7395011d7322b2037f91a6040866c875d272d7bda4c51d4d2467564eb66e8398a9dc57a27926c67";
    const digest = "0x5e2284e45eb5f5aabce477b913a7bff2a5803784597940652514be637d18e5fc";
    const signature = "0xf38f49a834e82d2383ab27dca6af648beba8f7739d66deaee165265b8aa721da9d24382b202c0e30d19d0a91863954c404fd778aaef785722aab09dc63ddb363";

    const normalize = normalizeSignature(signature, digest, publicKey);

    const decoded = decode_signature(normalize);
    expect(decoded.v).toBe(0);
});