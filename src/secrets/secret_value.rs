use std::str::FromStr;

use thiserror::Error as BaseError;

#[derive(Debug, BaseError)]
pub enum Error {
    #[error("Encrypted secret `{secret}` does not have a key section")]
    MissingSecretKeyId { secret: String },
    #[error("Encrypted secret `{secret}` does not have a data section")]
    MissingSecretData { secret: String },
    #[error("Decoding `{secret}` as Base64")]
    Base64Decoding {
        secret: String,
        #[source]
        source: base64::DecodeError,
    },
}

pub struct SecretValue {
    encrypted: Vec<u8>,
    key_id: String,
}

impl SecretValue {
    const SEP: char = ':';

    pub fn get_encrypted(&self) -> &[u8] {
        &self.encrypted
    }

    pub fn get_key_id(&self) -> &str {
        &self.key_id
    }
}

impl FromStr for SecretValue {
    type Err = Error;
    fn from_str(data: &str) -> Result<Self, <Self as FromStr>::Err> {
        let mut splitter = data.splitn(2, Self::SEP);

        // TODO: Should we also attempt decoding the key as Base64?
        let key_id = splitter.next().ok_or_else(|| Error::MissingSecretKeyId {
            secret: data.into(),
        })?;

        let encrypted =
            base64::decode(splitter.next().ok_or_else(|| Error::MissingSecretData {
                secret: data.into(),
            })?)
            .map_err(|error| Error::Base64Decoding {
                secret: data.into(),
                source: error,
            })?;

        Ok(Self {
            key_id: key_id.to_string(),
            encrypted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn parse_success() {
        let encrypted = {
            let mut buffer: [u8; 120] = [0; 120];
            rand::rngs::OsRng.fill_bytes(&mut buffer);
            buffer
        };

        let original_key_id = "some-key-id-here";
        let secret_value = format!("{}:{}", original_key_id, base64::encode(encrypted))
            .parse::<SecretValue>()
            .unwrap();
        assert_eq!(secret_value.get_key_id(), original_key_id);
        assert_eq!(secret_value.get_encrypted(), encrypted);
    }

    #[test]
    fn parse_success_empty_payload() {
        let original_key_id = "some-key-id-here";
        let secret_value = format!("{}:", original_key_id)
            .parse::<SecretValue>()
            .unwrap();
        assert_eq!(secret_value.get_key_id(), original_key_id);
        assert_eq!(secret_value.get_encrypted(), Vec::<u8>::new());
    }

    #[test]
    fn parse_failed_no_colon() {
        match "some-key-id-here".parse::<SecretValue>() {
            Err(Error::MissingSecretData { .. }) => {}
            _ => {
                panic!("parse_failed_no_colon didn't fail as expected");
            }
        }
    }

    #[test]
    fn parse_failed_not_base64_data() {
        assert!("some-key-id-here:some-non-64-data"
            .parse::<SecretValue>()
            .is_err());
    }
}
