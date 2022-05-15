use std::collections::HashSet;

use anyhow::Error;
use ed25519_dalek::Keypair;
use hmac::NewMac;
use nekoton_utils::TrustMe;
use pbkdf2::pbkdf2;

use super::dict::BIP39;
use super::utils::{Bits, Bits11, IterExt};

const PBKDF_ITERATIONS: u32 = 100_000;

pub fn derive_from_phrase(phrase: &str) -> Result<Keypair, Error> {
    let phrase: Vec<_> = phrase.split_whitespace().collect();
    phrase_is_ok(&phrase)?;
    let seed = phrase_to_seed(&phrase);
    let secret = ed25519_dalek::SecretKey::from_bytes(&seed[0..32])?;
    let public = ed25519_dalek::PublicKey::from(&secret);
    let keypair = Keypair { secret, public };
    Ok(keypair)
}

pub fn generate_words(entropy: [u8; 32]) -> Vec<String> {
    from_entropy_unchecked(entropy)
}

fn from_entropy_unchecked(entropy: [u8; 256 / 8]) -> Vec<String> {
    #[inline(always)]
    fn sha256_first_byte(input: &[u8]) -> u8 {
        use sha2::Digest;

        sha2::Sha256::digest(input)[0]
    }

    let checksum_byte = sha256_first_byte(&entropy);

    // First, create a byte iterator for the given entropy and the first byte of the
    // hash of the entropy that will serve as the checksum (up to 8 bits for biggest
    // entropy source).
    //
    // Then we transform that into a bits iterator that returns 11 bits at a
    // time (as u16), which we can map to the words on the `wordlist`.
    //
    // Given the entropy is of correct size, this ought to give us the correct word
    // count.
    let phrase: String = entropy
        .iter()
        .chain(Some(&checksum_byte))
        .bits()
        .map(|bits: Bits11| BIP39[bits.bits() as usize])
        .join(" ");

    phrase.split_whitespace().map(|x| x.to_string()).collect()
}

fn phrase_to_entropy(phrase: &[&str]) -> [u8; 64] {
    use hmac::Mac;

    let phrase: String = phrase.join(" ");
    let key = hmac::Hmac::<sha2::Sha512>::new_from_slice(phrase.as_bytes()).trust_me();
    key.finalize().into_bytes().into()
}

fn phrase_to_seed(phrase: &[&str]) -> [u8; 64] {
    let mut storage = [0; 512 / 8];
    pbkdf2::<hmac::Hmac<sha2::Sha512>>(
        phrase_to_entropy(phrase).as_ref(),
        b"TON default seed",
        PBKDF_ITERATIONS,
        &mut storage,
    );
    storage
}

fn phrase_is_ok(phrase: &[&str]) -> Result<(), Error> {
    let words_set: HashSet<_> = BIP39.iter().copied().collect();
    anyhow::ensure!(
        phrase.len() == 24,
        anyhow::anyhow!("Bad words number: {}, 24 expected.", phrase.len())
    );
    let phrase_set: HashSet<_> = phrase.iter().copied().collect();
    let bad: Vec<_> = phrase_set.difference(&words_set).collect();
    match bad.is_empty() {
        true => Ok(()),
        false => {
            anyhow::bail!("Bad words in wordlist: {:?}", bad)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::mnemonic::legacy::{derive_from_phrase, phrase_is_ok};

    #[test]
    fn test_validate() {
        phrase_is_ok(
            &"park remain person kitchen mule spell knee armed position rail grid ankle park remain person kitchen mule spell knee armed position rail grid ankle".split_whitespace().collect::<Vec<&str>>()
        ).unwrap()
    }

    #[test]
    fn test_validate_is_bad() {
        assert!(phrase_is_ok(
            &"spark remain person kitchen mule spell knee armed position rail grid ankle park remain person kitchen mule spell knee armed position rail grid ankle".split_whitespace().collect::<Vec<&str>>()
        ).is_err())
    }

    #[test]
    fn test_derivation() {
        let keypair = derive_from_phrase("unaware face erupt ceiling frost shiver crumble know party before brisk skirt fence boat powder copy plastic until butter fluid property concert say verify").unwrap();
        let expected = "o0kpHL39KRq0KX11zZ0/sCwJL66t+gA4vnfuwBjhAWU=";
        let pub_expecteed = "lHW4ZS8QvCHcgR4uChD7QJWU2kf5JRMtUnZ2p1GSZjg=";
        assert_eq!(base64::encode(&keypair.public.as_bytes()), pub_expecteed);
        let got = base64::encode(&keypair.secret.as_bytes());
        assert_eq!(got, expected);
    }
}
