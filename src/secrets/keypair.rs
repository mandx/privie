use std::convert::{TryFrom, TryInto};

use thiserror::Error as BaseError;

use crate::sealed_box::{PublicKey, SecretKey, KEY_SIZE};

#[derive(Debug, BaseError)]
pub enum KeyPairError {
    #[error("Decoded key length is {0}, but it should be {}", KEY_SIZE)]
    KeyLength(usize),
    #[error("Could not decode `{data}` as Base64")]
    Base64Decoding {
        #[source]
        source: base64::DecodeError,
        data: String,
    },
    #[error("Key pair mismatch for key `{key}`")]
    KeyPairMismatch { key: String },
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    public: PublicKey,
    private: Option<SecretKey>,
}

impl TryFrom<String> for KeyPair {
    type Error = KeyPairError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::decode_public_key(value).map(|public_key| Self {
            public: public_key,
            private: None,
        })
    }
}

impl TryFrom<(String, String)> for KeyPair {
    type Error = KeyPairError;

    fn try_from((public_key, secret_key): (String, String)) -> Result<Self, Self::Error> {
        let public_key = Self::decode_public_key(public_key)?;
        let secret_key = Self::decode_secret_key(secret_key)?;

        if secret_key.public_key() != public_key {
            return Err(Self::Error::KeyPairMismatch {
                key: base64::encode(public_key),
            });
        }

        Ok(Self {
            public: public_key,
            private: Some(secret_key),
        })
    }
}

impl From<SecretKey> for KeyPair {
    fn from(value: SecretKey) -> Self {
        Self {
            public: value.public_key(),
            private: Some(value),
        }
    }
}

impl From<PublicKey> for KeyPair {
    fn from(value: PublicKey) -> Self {
        Self {
            public: value,
            private: None,
        }
    }
}

impl std::fmt::Display for KeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(formatter, "{}", self.key_id())
    }
}

impl KeyPair {
    fn decode_key<S: AsRef<str>>(key: S) -> Result<[u8; KEY_SIZE], KeyPairError> {
        let key = key.as_ref();
        let decoded =
            base64::decode(key.as_bytes()).map_err(|error| KeyPairError::Base64Decoding {
                source: error,
                data: key.to_string(),
            })?;

        let decoded_len = decoded.len();
        decoded
            .try_into()
            .map_err(|_error| KeyPairError::KeyLength(decoded_len))
    }

    fn decode_public_key<S: AsRef<str>>(key: S) -> Result<PublicKey, KeyPairError> {
        Self::decode_key(key).map(PublicKey::from)
    }

    fn decode_secret_key<S: AsRef<str>>(key: S) -> Result<SecretKey, KeyPairError> {
        Self::decode_key(key).map(SecretKey::from)
    }

    pub fn generate() -> Self {
        let secret_key = SecretKey::generate(&mut rand::rngs::OsRng);
        Self {
            public: secret_key.public_key(),
            private: Some(secret_key),
        }
    }

    pub fn to_string_pair(&self) -> (String, Option<String>) {
        (
            self.key_id(),
            self.private
                .as_ref()
                .map(|key| base64::encode(key.as_bytes())),
        )
    }

    pub fn key_id(&self) -> String {
        base64::encode(&self.public)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn private_key(&self) -> Option<&SecretKey> {
        self.private.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checking_wrong_keys() {
        let k1 = KeyPair::generate();
        let k2 = KeyPair::generate();

        let (k1_public, k1_secret) = k1.to_string_pair();

        let (k2_public, k2_secret) = k2.to_string_pair();

        assert!(KeyPair::try_from((k1_public.clone(), k1_secret.clone().unwrap())).is_ok());
        assert!(KeyPair::try_from((k2_public.clone(), k2_secret.clone().unwrap())).is_ok());

        assert!(KeyPair::try_from((k1_public.clone(), k2_secret.clone().unwrap())).is_err());
        assert!(KeyPair::try_from((k2_public.clone(), k1_secret.clone().unwrap())).is_err());

        assert!(KeyPair::try_from((
            k1_public.clone(),
            k1_secret
                .as_ref()
                .map(|sk| (&sk[..(sk.len() - 2)]).into())
                .unwrap(),
        ))
        .is_err());
        assert!(KeyPair::try_from((
            k2_public.clone(),
            k2_secret
                .as_ref()
                .map(|sk| (&sk[..(sk.len() - 2)]).into())
                .unwrap(),
        ))
        .is_err());

        assert!(KeyPair::try_from((
            (&k1_public[..k1_public.len() - 2]).into(),
            k1_secret.clone().unwrap(),
        ))
        .is_err());
        assert!(KeyPair::try_from((
            (&k2_public[..k2_public.len() - 2]).into(),
            k2_secret.clone().unwrap(),
        ))
        .is_err());

        // let mut rng = rand::rngs::OsRng;
        // let mut buf = Vec::with_capacity(KEY_SIZE * 3);
        // rng.fill_bytes(&mut buf);
        // assert!(
        //     Keyring::<ErrorHandlerStub>::check_key_pair(k1_public, &base64::encode(buf)).is_err()
        // );
    }
}
