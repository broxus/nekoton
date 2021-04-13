use criterion::{black_box, criterion_group, criterion_main, Criterion};

use criterion::async_executor;
use criterion::async_executor::AsyncExecutor;
use nekoton::contracts;
use nekoton::crypto::{
    self, DerivedKeyCreateInput, DerivedKeySignParams, DerivedKeySigner, DerivedKeyUpdateParams,
    EncryptedKey, MnemonicType,
};
use nekoton::storage::{KeyStore, Signer};
use nekoton::utils::*;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("word_exists", |b| {
        b.iter(|| crypto::dict::get_hints(black_box("en")))
    });
    c.bench_function("word_non_exists", |b| {
        b.iter(|| crypto::dict::get_hints(black_box("apwdlkp")))
    });
    c.bench_function("create_function", |b| {
        b.iter(|| create_function(black_box("internalTransferFrom")))
    });
    c.bench_function("derive", |b| {
        b.iter(|| crypto::derive_from_phrase(black_box("pioneer fever hazard scan install wise reform corn bubble leisure amazing note"),MnemonicType::Labs(0)))
    });
    c.bench_function("derive_durov", |b| {
        b.iter(|| crypto::derive_from_phrase(black_box("park remain person kitchen mule spell knee armed position rail grid ankle park remain person kitchen mule spell knee armed position rail grid ankle"),MnemonicType::Legacy))
    });

    c.bench_function("test_decrypt", move |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { from_reader().await })
    });
}

async fn from_reader() {
    let mut signer = DerivedKeySigner::new();
    signer
        .add_key(
            black_box("lol"),
            black_box(DerivedKeyCreateInput::Import {
                phrase:
                    "pioneer fever hazard scan install wise reform corn bubble leisure amazing note"
                        .to_string()
                        .into(),
                password: "123".to_string().into(),
            }),
        )
        .await
        .unwrap();

    signer
        .sign(
            b"memes",
            DerivedKeySignParams {
                account_id: 0,
                password: "123".to_string().into(),
            },
        )
        .await
        .unwrap();
}

fn create_function(name: &str) {
    nekoton::contracts::abi::ton_token_wallet_v3()
        .function(black_box(name))
        .unwrap();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
