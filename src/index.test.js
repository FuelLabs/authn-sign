const { register, sign, verify } = require('./index.js');
import { expect, test } from "bun:test";

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

    expect(signature.signature).toBe(signatureCorrect);
});

test("test verify", async () => {
    const account = await register('account_1', { client });
    const signature = await sign(account, transaction_hash, { client });
    const is_verified = await verify(signature);

    expect(is_verified).toBe(true);
});
