use fuels::prelude::*;
use fuels::tx::Bytes32;
use fuels::types::Bytes;
use std::str::FromStr;
use fuels::types::Bits256;
use fuels::types::B512;
use fuels::accounts::predicate::Predicate;

abigen!(Predicate(name="AuthnPredicate", abi="out/debug/fuel-abi.json"));

#[tokio::main]
async fn main() {
    // Use the test helper to setup a test provider.
    let wallet = launch_provider_and_get_wallet().await;
    let wallet_2_final_coins = wallet.as_ref().expect("REASON").get_coins(BASE_ASSET_ID).await.unwrap();

    let challenge = Bits256::from_hex_str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").expect("failed to create Bytes32 from string");
    let address = Bits256::from_hex_str("e1037e9229115834a823d6eee714f8eb89906a14a83074f4e9515d8a80e63d95").expect("failed to create Bytes32 from string");
    //let digest = Bits256::from_hex_str("581101f9a2d61f04c1e820151e76d543914e2d0cfa39bcca8a6e8eed2f942f88").expect("failed to create Bytes32 from string");
    // let digest = Bits256::from_hex_str("173d69ea3d0aa050d01ff7cc60ccd4579b567c465cd115c6876c2da4a332fb99").expect("failed to create Bytes32 from string");

    let signature_hi = Bits256::from_hex_str("0xaec03df2a7c71bddc29c5593e9a6027b7393918a9342034613857be798a654a0").unwrap();
    let signature_lo = Bits256::from_hex_str("0x183506c5a3c3f1cfac461a66090993e9e75136aa4664fbd3ddc0c489f2114faa").unwrap();
    let signature = B512::from((signature_hi, signature_lo));
    let authid = Bytes(b"75a448b91bb82a255757e61ba3eb7afe282c09842485268d4d72a027ec0cffc80500000000".to_vec());
    let pre = Bytes(b"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22".to_vec());
    let post = Bytes(b"222c226f726967696e223a2268747470733a2f2f6e6176696761746f722d69766f72792e76657263656c2e617070222c2263726f73734f726967696e223a66616c73657d".to_vec());

    let predicate_data = AuthnPredicateEncoder::encode_data(
        signature,
        authid,
        challenge,
        pre,
        post,
        // digest,
    );
    let code_path = "out/debug/fuel.bin";

    let configurables = AuthnPredicateConfigurables::new()
        .with_ADDRESS(address.clone());

    let predicate: Predicate = Predicate::load_from(code_path).unwrap()
        .with_provider(wallet.as_ref().expect("REASON").try_provider().unwrap().clone())
        .with_data(predicate_data)
        .with_configurables(configurables);

    wallet
        .as_ref()
        .expect("REASON")
        .transfer(predicate.address(), 500, BASE_ASSET_ID, TxParameters::default())
        .await.unwrap();

    let balance0 = predicate.get_asset_balance(&AssetId::default()).await.unwrap();

    println!("Balance before {:?}", balance0);
    
    predicate
        .transfer(
            wallet.as_ref().expect("REASON").address(),
            500,
            BASE_ASSET_ID,
            TxParameters::default()
                .with_gas_limit(100_000_000),
        )
        .await
        .unwrap();

    // Predicate balance is zero.
    let balance1 = predicate.get_asset_balance(&AssetId::default()).await.unwrap();

    println!("Balance after {:?}", balance1);

    // println!("{:?}", wallet_2_final_coins);
}
