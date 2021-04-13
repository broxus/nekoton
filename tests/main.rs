use std::sync::Arc;

use ed25519_dalek::PublicKey;

use common::{StorageImpl,GqlImpl};
use nekoton::core::ton_wallet::{ContractType, TonWallet};
use nekoton::crypto::{DerivedKeyCreateInput, DerivedKeySigner};
use nekoton::external::Storage;
use nekoton::storage::{AccountsStorage, KeyStore,};

mod common;

async fn create_storage() -> KeyStore {
    #[derive(serde::Deserialize)]
    struct Data {
        phrase: String,
    }
    let storage = StorageImpl::new();
    let storage = Arc::new(storage) as Arc<dyn Storage>;
    let signer = DerivedKeySigner::new();
    let keystore = KeyStore::builder(storage)
        .with_signer("derived", signer)
        .unwrap()
        .load()
        .await
        .unwrap();
    let data = std::fs::read_to_string("tests/secret_data.json").unwrap();
    let input: Data = serde_json::from_str(&data).unwrap();
    let input = DerivedKeyCreateInput::Import {
        password: "12345".to_string().into(),
        phrase: input.phrase.into(),
    };
    keystore
        .add_key::<DerivedKeySigner>("main", input)
        .await
        .unwrap();

    keystore
}

#[tokio::test]
async fn key_store_working() {
    let store = create_storage().await;
}

async fn deploy_account() {

    let account = TonWallet::subscribe(GqlImpl::default(),)
}
