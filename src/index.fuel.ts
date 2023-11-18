import { Predicate, Provider, arrayify, FUEL_NETWORK_URL, BaseAssetId } from 'fuels';
import type { Bytes, Bits256, Bits512 } from 'fuels';
import { FuelAbi__factory } from './types/index';

export const types = {
    Provider,
    BaseAssetId,
};

export default function buildPredicate(provider:Provider, address:string) {
    const configurable = {
        ADDRESS: address,
    };
    const predicate = FuelAbi__factory.createInstance(provider, configurable);

    return predicate;
}

export function setData(predicate:Predicate, signature:string, authid:string, txid:string, pre:string, post:string) {
    predicate.setData(
        signature,
        Array.from(arrayify(authid)),
        txid,
        Array.from(arrayify(pre)),
        Array.from(arrayify(post)),
    );
}

export async function build_and_try() {
    const provider = await Provider.create('https://beta-4.fuel.network/graphql');
    const predicate = buildPredicate(provider, "0xe1037e9229115834a823d6eee714f8eb89906a14a83074f4e9515d8a80e63d95");
    setData(
        predicate,
        '0xaec03df2a7c71bddc29c5593e9a6027b7393918a9342034613857be798a654a0183506c5a3c3f1cfac461a66090993e9e75136aa4664fbd3ddc0c489f2114faa',
        '0x75a448b91bb82a255757e61ba3eb7afe282c09842485268d4d72a027ec0cffc80500000000',
        '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        '0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22',
        '0x222c226f726967696e223a2268747470733a2f2f6e6176696761746f722d69766f72792e76657263656c2e617070222c2263726f73734f726967696e223a66616c73657d',
    );

    const tx2 = await predicate
        .transfer(predicate.address, 500, BaseAssetId, {
            gasPrice: 1,
            gasLimit: 3_500_000,
        });

    console.log(tx2);
    console.log(await tx2.waitForResult());
}