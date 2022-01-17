use std::convert::TryInto;

use anyhow::Error;
use bip39::{Language, Seed};
use tiny_hderive::bip32::ExtendedPrivKey;

use nekoton_utils::TrustMe;

pub fn derive_master_key(phrase: &str) -> anyhow::Result<[u8; 64]> {
    let cnt = phrase.split_whitespace().count();
    anyhow::ensure!(cnt == 12, "Provided {} words instead of 12", cnt);
    let mnemonic = bip39::Mnemonic::from_phrase(phrase, Language::English)?;
    let hd = Seed::new(&mnemonic, "");
    Ok(hd.as_bytes().try_into().trust_me())
}

pub fn derive_from_phrase(phrase: &str, account_id: u16) -> Result<ed25519_dalek::Keypair, Error> {
    let mnemonic = bip39::Mnemonic::from_phrase(phrase, Language::English)?;
    let hd = Seed::new(&mnemonic, "");
    let seed_bytes = hd.as_bytes();

    let derived = ExtendedPrivKey::derive(
        seed_bytes,
        format!("m/44'/396'/0'/0/{}", account_id).as_str(),
    )
    .map_err(|e| Error::msg(format!("{:#?}", e)))?;

    ed25519_keys_from_secret_bytes(&derived.secret()) //todo check me
}

pub fn generate_words(entropy: [u8; 16]) -> Vec<String> {
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy, Language::English)
        .trust_me()
        .phrase()
        .to_string();
    mnemonic.split_whitespace().map(|x| x.to_string()).collect()
}

fn ed25519_keys_from_secret_bytes(bytes: &[u8]) -> Result<ed25519_dalek::Keypair, Error> {
    let secret = ed25519_dalek::SecretKey::from_bytes(bytes)
        .map_err(|e| Error::msg(format!("failed to import ton secret key. {}", e)))?;

    let public = ed25519_dalek::PublicKey::from(&secret);

    Ok(ed25519_dalek::Keypair { secret, public })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_mnemonic() {
        let key = derive_from_phrase(
            "pioneer fever hazard scam install wise reform corn bubble leisure amazing note",
            0,
        );
        assert!(key.is_err());
    }

    #[test]
    fn ton_recovery() {
        let key = derive_from_phrase(
            "pioneer fever hazard scan install wise reform corn bubble leisure amazing note",
            0,
        )
        .unwrap();
        let secret = key.secret;

        let target_secret = ed25519_dalek::SecretKey::from_bytes(
            &hex::decode("e371ef1d7266fc47b30d49dc886861598f09e2e6294d7f0520fe9aa460114e51")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(secret.as_bytes(), target_secret.as_bytes())
    }

    #[test]
    fn master_key_derive() {
        let ph = "pioneer fever hazard scan install wise reform corn bubble leisure amazing note";
        derive_master_key(ph).unwrap();
    }
}
