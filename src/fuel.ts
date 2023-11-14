import { Predicate } from "@fuel-ts";
const sign_return = JSON.parse('{"credentialId":"YyGacelT6fMR854csLURTauJY_xJXeYeejLHC1KgPZM","authenticatorData":"adrQMLP89rCRgQmDLNkEWixGWKi5vl02t-6DBUPxW10FAAAAAA==","clientData":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidFBZcTQtTTNRaGhvZUNxSV8zMkJxTDlFNzJjaTM4ME1jTkNLQ3R3bFpqMCIsIm9yaWdpbiI6Imh0dHBzOi8vYXV0aG4tc2lnbi1mdWVsZXItZnVlbC1sYWJzLnZlcmNlbC5hcHAiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==","signature":"MEYCIQCq9chHettwdtK_b-DIQh8uC70XCip6i2hZkPsyHYQtEAIhAIXG3-xfI8iV_jtWRIZUvh_2C8i7ZJrgYq-pfBPYvoOM"}');

const configurable = { WHITELISTED: newWhitelistedAddress };
// instantiate predicate with configurable constants
const predicate = new Predicate(bin, wallet.provider, abi, configurable);

const signature = '0xaaf5c8477adb7076d2bf6fe0c8421f2e0bbd170a2a7a8b685990fb321d842d107a392012a0dc376b01c4a9bb79ab41dfc6db31f2427cbe2244104eaf23a4a1c5';
const authid =  sign_return.authenticatorData;
const txid = '0xb4f62ae3e337421868782a88ff7d81a8bf44ef6722dfcd0c70d08a0adc25663d';
const pre = sign_return.preChallengeEncoded;
const post = sign_return.postChallengeEncoded;

// set predicate data to be the same as the configurable constant
// signature:B512, authid:Bytes, txid:b256, pre:Bytes, post:Bytes
predicate.setData(
    signature,
    authid,
);
 
// transfering funds to the predicate
const tx1 = await wallet.transfer(predicate.address, 500);
 
await tx1.waitForResult();
 
const destinationWallet = WalletUnlocked.generate({
	provider: wallet.provider,
});
 
const amountToTransfer = 100;
 
// transfering funds from the predicate to destination if predicate returns true
const tx2 = await predicate.transfer(destinationWallet.address, amountToTransfer);
