use criterion::{black_box, criterion_group, criterion_main, Criterion};

use nekoton::contracts;
use nekoton::crypto::{self, EncryptedKey, MnemonicType};
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
    c.bench_function("test_decrypt", |b| b.iter(|| from_reader()));
}

fn from_reader() {
    let data = r##"{"account_type":"Legacy","name":"Test key","pubkey":"95ec49ee3d37d7b1d92d4136c962725faae3034745ee2bc3202a59ce12ee897e","encrypted_private_key":"3d7bc1056088cd248530f57e75839e7b5201cefe7971240783c80ef0c4b1c3895aefe7e7e79c4bb4908fd3af0b5755ba","private_key_nonce":"b5eff4ac650b63d9fb59815f","encrypted_seed_phrase":"e6e8a33b74c7b80931688d6c56732d130e2912c7c9878b39db7536e6db187e09d3e0456443a6825a85f41aa7cc3703c1deb69ed6f6aacae1a61a5a47996be6634ff45ad41a0159adb13d47e1c79773a23dc87beb8309f9ac92a87938732361b1cc5637ec8efe3748a53803dff06807dbc2902e2a81fd283695f54e1a7c99b8a85f8ac2861506839b5c08cc573c24a24c9aa4ec1e8cfc3c2cbcb140cd509e73063da0","seed_phrase_nonce":"1979d757392dcb2a74d1acfe","salt":"f9a3cc4d0a460ca93103dcc33a514dfa21fcf6cbf4b9f05df80d0d8c02b0f249"}"##;
    let reader = std::io::Cursor::new(data);
    EncryptedKey::from_reader(black_box(reader))
        .unwrap()
        .change_password(
            black_box("123".to_string().into()),
            black_box("321".to_string().into()),
        )
        .trust_me();
}

fn create_function(name: &str) {
    nekoton::contracts::abi::ton_token_wallet_v3()
        .function(name)
        .unwrap();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
