use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use thiserror::Error as BaseError;

use crypto_box::{
    aead::{generic_array::GenericArray, Aead, Error as AeadError},
    SalsaBox,
};

// Re-export the main structs & constants
pub use crypto_box::{PublicKey, SecretKey, KEY_SIZE};

#[derive(Debug, BaseError)]
pub enum Error {
    #[error("Encrypt/Decrypt error ({0})")]
    CryptError(#[from] AeadError),
    #[error(
        "Malformed ciphertext; Data length should be at least {}, got {0}",
        KEY_SIZE
    )]
    MalformedData(usize),
}

const BOX_NONCELENGTH: usize = 24;
const BOX_OVERHEAD: usize = 16;

// KEY_SIZE = PublicKey length
const SEALEDBOX_OVERHEAD: usize = KEY_SIZE + BOX_OVERHEAD;

/// Generate the nonce for the given public keys
///
/// nonce = `Blake2b(ephemeral_pk + target_pk)`
/// length = 24
fn get_nonce(
    ephemeral_public_key: &PublicKey,
    target_public_key: &PublicKey,
) -> [u8; BOX_NONCELENGTH] {
    let mut hasher = Blake2bVar::new(BOX_NONCELENGTH).unwrap();

    hasher.update(ephemeral_public_key.as_bytes());
    hasher.update(target_public_key.as_bytes());

    let mut nonce = [0_u8; BOX_NONCELENGTH];
    hasher.finalize_variable(&mut nonce).unwrap();
    nonce
}

/// Encrypt the given buffer for the given public key
///
/// overhead: 48 bytes = `KEY_SIZE` (32, ephemeral pk) + 16 (box overhead)
pub fn seal(data: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, Error> {
    let mut result = Vec::with_capacity(SEALEDBOX_OVERHEAD + data.len());

    let ephemeral_secret_key = SecretKey::generate(&mut rand::rngs::OsRng);
    let ephemeral_public_key = ephemeral_secret_key.public_key();
    result.extend_from_slice(ephemeral_public_key.as_bytes());

    let nonce_bytes = get_nonce(&ephemeral_public_key, public_key);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let crypto_box = SalsaBox::new(public_key, &ephemeral_secret_key);

    result.extend_from_slice(&crypto_box.encrypt(nonce, data).map_err(Error::from)?);
    Ok(result)
}

/// Attempt to decrypt the given ciphertext with the given secret key.
/// Will fail if the secret key doesn't match the public key used to
/// encrypt the payload, or if the ciphertext is not long enough.
pub fn open(ciphertext: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>, Error> {
    if ciphertext.len() <= KEY_SIZE {
        // Not long enough
        return Err(Error::MalformedData(ciphertext.len()));
    }

    let ephemeral_pk = {
        let mut array = [0_u8; KEY_SIZE];
        array.copy_from_slice(&ciphertext[..KEY_SIZE]);
        array.into()
    };

    let nonce = get_nonce(&ephemeral_pk, &secret_key.public_key());
    let nonce = GenericArray::from_slice(&nonce);

    let encrypted = &ciphertext[KEY_SIZE..];
    let crypto_box = SalsaBox::new(&ephemeral_pk, secret_key);
    crypto_box.decrypt(nonce, encrypted).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::{SalsaBox, SecretKey};

    const TEST_PAYLOAD: &[u8; 15] = b"sealed_box test";

    #[test]
    fn try_nonce() {
        use sodiumoxide::crypto::box_::Nonce;

        //ephemeral
        let alice = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        //target
        let bob = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        let nonce = get_nonce(&alice.0, &bob.0);
        let sodium_nonce = Nonce::from_slice(&nonce).unwrap();

        assert_eq!(&sodium_nonce[..], &nonce[..])
    }

    #[test]
    fn try_box() {
        use sodiumoxide::crypto::box_::{
            seal as bs_seal, Nonce, PublicKey as SodiumPKey, SecretKey as SodiumSKey,
        };

        // Ephemeral
        let alice = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        // Target
        let bob = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        // Generate nonce
        let nonce = get_nonce(&alice.0, &bob.0);
        let sodium_nonce = Nonce::from_slice(&nonce).unwrap();

        // Encrypt message with crypto_box
        let crypto_box = SalsaBox::new(&bob.0, &alice.1);
        let encrypted = crypto_box
            .encrypt(&GenericArray::from_slice(&nonce), &TEST_PAYLOAD[..])
            .unwrap();

        // Encrypt message with sodiumoxide::box_
        let sbob_pkey = SodiumPKey::from_slice(bob.0.as_bytes()).unwrap();
        let salice_skey = SodiumSKey::from_slice(alice.1.as_bytes()).unwrap();
        let sencrypted = bs_seal(&TEST_PAYLOAD[..], &sodium_nonce, &sbob_pkey, &salice_skey);

        assert_eq!(sencrypted, encrypted);
    }

    #[test]
    fn try_full() {
        use sodiumoxide::crypto::box_::{PublicKey as SodiumPKey, SecretKey as SodiumSKey};
        use sodiumoxide::crypto::sealedbox::{open as sopen, seal as sseal};

        let bob = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        let sbob = (
            SodiumPKey::from_slice(bob.0.as_bytes()).unwrap(),
            SodiumSKey::from_slice(bob.1.as_bytes()).unwrap(),
        );

        // Seal and open local
        let encrypted = seal(&TEST_PAYLOAD[..], &bob.0);
        let decrypted = open(&encrypted.as_ref().unwrap(), &bob.1).unwrap();
        assert_eq!(&decrypted, &TEST_PAYLOAD);

        // Sodiumoxide open local seal
        let sopen_rust = sopen(&encrypted.unwrap(), &sbob.0, &sbob.1).unwrap();
        assert_eq!(&sopen_rust, &TEST_PAYLOAD);

        // local open sodiumoxide seal
        let sencrypted = sseal(&TEST_PAYLOAD[..], &sbob.0);
        let open_sodium = open(&sencrypted, &bob.1).unwrap();
        assert_eq!(&open_sodium, &TEST_PAYLOAD);
    }

    #[test]
    fn bad_ciphertext() {
        let key = SecretKey::generate(&mut rand::thread_rng());
        assert!(open(&[1, 2, 3], &key).is_err())
    }
}
