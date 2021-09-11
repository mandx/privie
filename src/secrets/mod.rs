use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::{Debug, Display, Formatter},
    iter::FromIterator,
    string::FromUtf8Error,
};

use json::{object::Object as JsonObject, JsonValue};
use thiserror::Error as BaseError;

use crate::sealed_box;
use crate::{path_assign::PathAssign, sealed_box::SealedBoxError};

pub trait HandleError {
    // TODO: Add/Pass here some sort of "context", that most importantly
    //       contains the current "JSON path" to `value` in the current document.
    fn decrypt_error<E>(
        &self,
        #[allow(unused_variables)] value: &mut JsonValue,
        error: E,
    ) -> Result<(), E>
    where
        E: Debug,
    {
        Err(error)
    }

    fn key_load_error<E>(
        &self,
        #[allow(unused_variables)] public_key: &str,
        #[allow(unused_variables)] private_key: &str,
        error: E,
    ) -> Result<(), E>
    where
        E: Debug,
    {
        Err(error)
    }
}

#[derive(Debug)]
pub struct DefaultErrorHandler;
impl HandleError for DefaultErrorHandler {}

#[derive(Debug, BaseError)]
pub enum SecretsError {
    #[error("This keyring has no keys")]
    EmptyKeyring,

    #[error("Key `{key_id}` is missing in this keyring")]
    MissingKeyId { key_id: String },

    #[error("Key `{key_id}` is present, but has no corresponding secret key in this keyring")]
    MissingPrivateKey { key_id: String },

    #[error("Can not use `{key_id}` as public key")]
    KeyRead {
        key_id: String,
        #[source]
        source: KeyPairError,
    },

    #[error("Can not directly use `{key_id}` as public key (was not found in this keyring)")]
    DetachedKeyRead {
        key_id: String,
        #[source]
        source: KeyPairError,
    },

    #[error("JSON document is not an object")]
    JsonNotAnObject,

    #[error("Could not encrypt `{secret}`")]
    Encrypt {
        #[source]
        source: SealedBoxError,
        secret: String,
    },

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

    #[error("Could not decrypt `{secret}`")]
    Decrypt {
        secret: String,
        #[source]
        source: SealedBoxError,
    },

    #[error("Decrypting suceeded, but the decrypted data is not valid UTF-8 text")]
    InvalidUtf8Data {
        secret: String,
        #[source]
        source: FromUtf8Error,
    },
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct EncryptedSecrets<'a, H: HandleError + Debug> {
    keyring: &'a Keyring<H>,
    data: JsonValue,
}

impl<'a, H: HandleError + Debug> EncryptedSecrets<'a, H> {
    pub fn from_json(keyring: &'a Keyring<H>, json_data: JsonValue) -> Self {
        Self {
            keyring,
            data: json_data,
        }
    }

    pub fn decrypt(self) -> Result<PlainSecrets, SecretsError> {
        self.keyring.decrypt(self)
    }

    pub fn new(keyring: &'a Keyring<H>) -> Self {
        Self {
            data: JsonValue::new_object(),
            keyring,
        }
    }

    pub fn dump(&self) -> JsonValue {
        self.data.clone()
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct PlainSecrets {
    data: JsonValue,
}

impl PlainSecrets {
    pub fn from_json(json_data: JsonValue) -> Self {
        Self { data: json_data }
    }

    pub fn encrypt_with<S, H>(
        self,
        keyring: &Keyring<H>,
        public_key: Option<S>,
    ) -> Result<EncryptedSecrets<H>, SecretsError>
    where
        S: AsRef<str>,
        H: HandleError + Debug,
    {
        keyring.encrypt(self, public_key)
    }

    pub fn encrypt<H: HandleError + Debug>(
        self,
        keyring: &Keyring<H>,
    ) -> Result<EncryptedSecrets<H>, SecretsError> {
        self.encrypt_with(keyring, None::<&str>)
    }

    pub fn dump(&self) -> JsonValue {
        self.data.clone()
    }
}

mod keypair;
use keypair::KeyPair;

use self::keypair::KeyPairError;

pub struct Keyring<H: HandleError + Debug> {
    keys: HashMap<String, KeyPair>,
    default_public_key: Option<String>,
    error_handler: H,
}

impl<H: HandleError + Debug> std::ops::Add for Keyring<H> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            keys: self.keys.into_iter().chain(rhs.keys.into_iter()).collect(),
            default_public_key: self.default_public_key,
            error_handler: self.error_handler,
        }
    }
}

impl<H: HandleError + Debug> std::ops::AddAssign for Keyring<H> {
    fn add_assign(&mut self, rhs: Self) {
        self.keys.extend(rhs.keys.into_iter());
        if self.default_public_key.is_none() {
            self.default_public_key = rhs.default_public_key;
        }
    }
}

impl<H: HandleError + Debug> std::fmt::Debug for Keyring<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let keys_dbg = &f
            .debug_map()
            .entries(self.keys.iter().map(|(k, _)| (k, "<redacted>")))
            .finish()?;
        f.debug_struct("Keyring").field("keys", keys_dbg).finish()
    }
}

impl Default for Keyring<DefaultErrorHandler> {
    fn default() -> Self {
        Keyring::new(DefaultErrorHandler)
    }
}

impl<H: HandleError + Debug + Default> FromIterator<Keyring<H>> for Keyring<H> {
    fn from_iter<I>(iterable: I) -> Self
    where
        I: IntoIterator<Item = Self>,
    {
        let mut iterator = iterable.into_iter();
        let mut result = Keyring::new(H::default());
        while let Some(keyring) = iterator.next() {
            result += keyring;
        }
        result
    }
}

impl<H: HandleError + Debug> Keyring<H> {
    // TODO: Find a better name for this `const`
    const SEP: char = ':';

    pub fn new(error_handler: H) -> Self {
        Keyring {
            keys: HashMap::new(),
            default_public_key: None,
            error_handler,
        }
    }

    pub fn generate(error_handler: H) -> Self {
        let mut this = Self::new(error_handler);
        let key_pair = KeyPair::generate();
        let key_id = key_pair.to_string();
        this.keys.insert(key_id.clone(), key_pair);
        this.default_public_key = Some(key_id);
        this
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn to_json(&self) -> JsonValue {
        JsonValue::Object(
            self.keys
                .iter()
                .map(|(_key_id, key_pair)| key_pair.to_string_pair())
                .collect::<JsonObject>(),
        )
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn from_json_obj(json_obj: JsonObject, error_handler: H) -> Result<Self, SecretsError> {
        let mut this = Self::new(error_handler);
        for (key_id, value) in json_obj.iter() {
            if let json_string @ (JsonValue::String(_) | JsonValue::Short(_)) = value {
                this.keys.insert(
                    key_id.into(),
                    KeyPair::try_from((
                        key_id.to_string(),
                        json_string.as_str().unwrap().to_string(),
                    ))
                    .map_err(|error| SecretsError::KeyRead {
                        source: error,
                        key_id: key_id.into(),
                    })?,
                );
                // Prefer keys with an associated private key
                this.default_public_key = Some(key_id.into());
            } else {
                this.keys.insert(
                    key_id.into(),
                    KeyPair::try_from(key_id.to_string()).map_err(|error| {
                        SecretsError::KeyRead {
                            source: error,
                            key_id: key_id.into(),
                        }
                    })?,
                );
            }
        }

        // If there's still no default key yet, pick one from the keys hashmap
        if this.default_public_key.is_none() {
            if let Some(key_id) = this.keys.keys().next() {
                this.default_public_key = Some(key_id.into());
            }
        }

        Ok(this)
    }

    pub fn from_json(json_data: JsonValue, error_handler: H) -> Result<Self, SecretsError> {
        match json_data {
            JsonValue::Object(obj) => Self::from_json_obj(obj, error_handler),
            _ => Err(SecretsError::JsonNotAnObject),
        }
    }

    pub fn encrypt_str<K: AsRef<str> + Display, S: AsRef<str>>(
        &self,
        key_id: K,
        data: S,
    ) -> Result<String, SecretsError> {
        let key_id = key_id.as_ref();
        let key_pair = self
            .keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| SecretsError::MissingKeyId {
                key_id: key_id.into(),
            })
            .or_else(|_key_not_found_error| {
                KeyPair::try_from(key_id.to_string()).map_err(|error| {
                    SecretsError::DetachedKeyRead {
                        source: error,
                        key_id: key_id.into(),
                    }
                })
            })?;

        sealed_box::seal(data.as_ref().as_bytes(), key_pair.public_key())
            .map(|encrypted| format!("{}{}{}", key_id, Self::SEP, base64::encode(encrypted)))
            .map_err(|error| SecretsError::Encrypt {
                source: error,
                secret: data.as_ref().into(),
            })
    }

    pub fn encrypt_in_place<S: AsRef<str> + Display>(
        &self,
        key_id: &S,
        data: &mut JsonValue,
    ) -> Result<(), SecretsError> {
        match data {
            JsonValue::Object(obj) => {
                for v in obj
                    .iter_mut()
                    .filter(|(k, _)| !k.starts_with('_'))
                    .map(|(_, v)| v)
                {
                    self.encrypt_in_place(key_id, v)?;
                }
            }
            JsonValue::Array(elems) => {
                for elem in elems.iter_mut() {
                    self.encrypt_in_place(key_id, elem)?;
                }
            }
            json_string @ (JsonValue::String(_) | JsonValue::Short(_)) => {
                let mut encrypted: JsonValue = self
                    .encrypt_str(key_id, json_string.as_str().unwrap())?
                    .into();
                std::mem::swap(json_string, &mut encrypted);
            }
            _ => {}
        }

        Ok(())
    }

    pub fn decrypt_str<S: AsRef<str>>(&self, data: S) -> Result<String, SecretsError> {
        let mut splitter = data.as_ref().splitn(2, Self::SEP);

        let key_id = splitter
            .next()
            .ok_or_else(|| SecretsError::MissingSecretKeyId {
                secret: data.as_ref().into(),
            })?;

        let encrypted =
            base64::decode(
                splitter
                    .next()
                    .ok_or_else(|| SecretsError::MissingSecretData {
                        secret: data.as_ref().into(),
                    })?,
            )
            .map_err(|error| SecretsError::Base64Decoding {
                secret: data.as_ref().into(),
                source: error,
            })?;

        let key_pair = self
            .keys
            .get(key_id)
            .ok_or_else(|| SecretsError::MissingKeyId {
                key_id: key_id.into(),
            })?;

        let secret_key = key_pair
            .private_key()
            .ok_or_else(|| SecretsError::MissingPrivateKey {
                key_id: key_id.into(),
            })?;

        let decrypted =
            sealed_box::open(&encrypted, secret_key).map_err(|error| SecretsError::Decrypt {
                secret: data.as_ref().into(),
                source: error,
            })?;
        String::from_utf8(decrypted).map_err(|error| SecretsError::InvalidUtf8Data {
            source: error,
            secret: data.as_ref().into(),
        })
    }

    pub fn decrypt_in_place(&self, data: &mut JsonValue) -> Result<(), SecretsError> {
        match data {
            JsonValue::Object(obj) => {
                for (_k, v) in obj.iter_mut().filter(|(k, _)| !k.starts_with('_')) {
                    self.decrypt_in_place(v)?;
                }
            }
            JsonValue::Array(elems) => {
                for elem in elems.iter_mut() {
                    self.decrypt_in_place(elem)?;
                }
            }
            json_string @ (JsonValue::String(_) | JsonValue::Short(_)) => {
                let encrypted = json_string.as_str().unwrap();
                let mut decrypted: JsonValue = match self.decrypt_str(encrypted) {
                    Ok(decrypted) => decrypted.into(),
                    Err(error) => {
                        return self.error_handler.decrypt_error(json_string, error);
                    }
                };
                std::mem::swap(json_string, &mut decrypted);
            }
            _ => {}
        }

        Ok(())
    }

    pub fn default_public_key(&self) -> Result<&str, SecretsError> {
        self.default_public_key
            .as_deref()
            .ok_or(SecretsError::EmptyKeyring)
    }

    pub fn set_default_public_key<S: AsRef<str>>(&mut self, key_id: S) -> Result<(), SecretsError> {
        let key_id = key_id.as_ref();
        if self.keys.contains_key(key_id) {
            self.default_public_key = Some(key_id.into());
        } else {
            let key_pair =
                KeyPair::try_from(key_id.to_string()).map_err(|error| SecretsError::KeyRead {
                    source: error,
                    key_id: key_id.into(),
                })?;
            self.default_public_key = Some(key_pair.key_id());
        }

        Ok(())
    }

    pub fn encrypt<S>(
        &self,
        secrets: PlainSecrets,
        key_id: Option<S>,
    ) -> Result<EncryptedSecrets<H>, SecretsError>
    where
        S: AsRef<str>,
    {
        let PlainSecrets { mut data } = secrets;

        let public_key = match key_id {
            Some(public_key) => public_key.as_ref().to_string(),
            None => self.default_public_key().map(ToOwned::to_owned)?,
        };

        self.encrypt_in_place(&public_key, &mut data)?;

        Ok(EncryptedSecrets {
            keyring: self,
            data,
        })
    }

    pub fn decrypt(&self, secrets: EncryptedSecrets<H>) -> Result<PlainSecrets, SecretsError> {
        let EncryptedSecrets {
            mut data,
            keyring: _,
        } = secrets;

        self.decrypt_in_place(&mut data)?;
        Ok(PlainSecrets { data })
    }
}

impl<'k, H: HandleError + Debug> PathAssign<SecretsError> for EncryptedSecrets<'k, H> {
    fn get_assign_target(&mut self) -> &mut JsonValue {
        &mut self.data
    }

    fn preprocess_value<K, J>(
        &self,
        path: K,
        value: Option<J>,
    ) -> Result<Option<JsonValue>, SecretsError>
    where
        K: AsRef<str>,
        J: Into<JsonValue>,
    {
        let path = path.as_ref();
        let dunder = path
            .split('.')
            .last()
            .map_or(false, |last| !last.starts_with('_'));

        let value = value.map(Into::into);
        Ok(match (value, dunder) {
            (Some(json_string @ (JsonValue::String(_) | JsonValue::Short(_))), true) => Some(
                self.keyring
                    .encrypt_str(
                        &self.keyring.default_public_key()?,
                        json_string.as_str().unwrap(),
                    )?
                    .into(),
            ),
            (v, _) => v,
        })
    }
}

impl PathAssign<SecretsError> for PlainSecrets {
    fn get_assign_target(&mut self) -> &mut JsonValue {
        &mut self.data
    }
}

#[cfg(test)]
mod assign_tests {
    use json::object;

    use super::*;
    use crate::path_assign::PathAssign;

    #[test]
    fn plain_secrets_path_assign() {
        let mut secrets = PlainSecrets::from_json(object! {
            a: "1",
            b: "2",
            d: "100",
        });

        assert!(!secrets.data.has_key("c"));
        assert_eq!(secrets.data["d"], JsonValue::from("100"));

        secrets.path_assign("c", Some("3"), false).unwrap();
        secrets.path_assign("d.a", Some("4"), false).unwrap();

        assert_eq!(secrets.data["c"], JsonValue::from("3"));
        assert_eq!(secrets.data["d"]["a"], JsonValue::from("4"));
    }
}

#[cfg(test)]
mod tests {
    use json::object;

    use super::*;

    #[test]
    fn test_encrypted_secrets_new() {
        let keyring = Keyring::default();
        let secrets = EncryptedSecrets::new(&keyring);
        assert!(secrets.data.is_object());
        assert_eq!(secrets.data.len(), 0);
    }

    #[test]
    fn keyring_add_op() {
        let keyring1 = Keyring::generate(DefaultErrorHandler);
        let keyring2 = Keyring::generate(DefaultErrorHandler);

        let key1 = keyring1
            .default_public_key()
            .map(ToOwned::to_owned)
            .unwrap();
        let key2 = keyring2
            .default_public_key()
            .map(ToOwned::to_owned)
            .unwrap();
        assert_ne!(key1, key2);

        let keyring3 = keyring1 + keyring2;

        assert_eq!(keyring3.len(), 2);
        assert_eq!(keyring3.keys.len(), 2);
        assert!(keyring3.keys.contains_key(&key1));
        assert!(keyring3.keys.contains_key(&key2));
    }

    #[test]
    fn keyring_addassign_op() {
        let mut keyring1 = Keyring::generate(DefaultErrorHandler);
        let keyring2 = Keyring::generate(DefaultErrorHandler);

        assert_eq!(keyring1.keys.len(), 1);

        let key1 = keyring1
            .default_public_key()
            .map(ToOwned::to_owned)
            .unwrap();
        let key2 = keyring2
            .default_public_key()
            .map(ToOwned::to_owned)
            .unwrap();
        assert_ne!(key1, key2);

        keyring1 += keyring2;

        assert_eq!(keyring1.len(), 2);
        assert_eq!(keyring1.keys.len(), 2);
        assert!(keyring1.keys.contains_key(&key1));
        assert!(keyring1.keys.contains_key(&key2));
    }

    #[test]
    fn empty_keyring_debug_repr() {
        let debug_repr = format!("{:?}", Keyring::new(DefaultErrorHandler));
        assert_eq!(debug_repr, "{}Keyring { keys: () }");
    }

    #[test]
    fn default_key_with_generate() {
        let keyring = Keyring::generate(DefaultErrorHandler);
        assert_eq!(
            keyring.keys.keys().next().unwrap(),
            keyring.default_public_key().unwrap()
        )
    }

    #[test]
    fn default_key_with_new() {
        let keyring = Keyring::new(DefaultErrorHandler);
        assert!(keyring.default_public_key().is_err());
    }

    #[test]
    fn nonempty_keyring_debug_repr() {
        let keyring = Keyring::generate(DefaultErrorHandler);
        let debug_repr = format!("{:?}", keyring);
        let key_id = keyring.default_public_key().unwrap();

        assert_eq!(
            debug_repr,
            format!("{{{:?}: \"<redacted>\"}}Keyring {{ keys: () }}", key_id)
        );
    }

    #[test]
    fn encrypt_decrypt_str() {
        let keyring = Keyring::generate(DefaultErrorHandler);
        let key_id = keyring.default_public_key().unwrap();
        let msg = "this is a secret string!";
        let encrypted_msg = keyring.encrypt_str(key_id, msg).unwrap();

        assert_ne!(msg, encrypted_msg);
        assert_eq!(
            encrypted_msg
                .split(Keyring::<DefaultErrorHandler>::SEP)
                .map(base64::decode)
                .filter(Result::is_ok)
                .collect::<Vec<_>>()
                .len(),
            2
        );

        let decrypted_msg = keyring.decrypt_str(encrypted_msg).unwrap();
        assert_eq!(decrypted_msg, msg);
    }

    #[test]
    fn encrypt_json_associated_method() {
        let data = object! {
            "a": 1,
            "b": "b",
            "_c": "c",
            "d": {
                "da": 2,
                "db": "b2",
                "_dc": "c2",
            }
        };

        assert!(data.is_object());

        let keyring = Keyring::generate(DefaultErrorHandler);
        let unencrypted_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = unencrypted_secrets.encrypt(&keyring).unwrap();
        let encrypted_data = encrypted_secrets.dump();

        let decrypt_str = |s: &str| keyring.decrypt_str(s).unwrap();

        assert_eq!(data["a"], encrypted_data["a"]);
        assert_eq!(data["_c"], encrypted_data["_c"]);
        assert_eq!(
            data["b"].to_string(),
            decrypt_str(&encrypted_data["b"].to_string())
        );

        assert_eq!(data["d"]["da"], encrypted_data["d"]["da"]);
        assert_eq!(data["d"]["_dc"], encrypted_data["d"]["_dc"]);
        assert_eq!(
            data["d"]["db"].to_string(),
            decrypt_str(&encrypted_data["d"]["db"].to_string())
        );
    }

    #[test]
    fn encrypt_json_associated_method_2() {
        let data = object! {
            "a": 1,
            "b": "b",
            "_c": "c",
            "d": {
                "da": 2,
                "db": "b2",
                "_dc": "c2",
            }
        };

        assert!(data.is_object());

        let keyring = Keyring::generate(DefaultErrorHandler);
        let unencrypted_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = keyring.encrypt::<&str>(unencrypted_secrets, None).unwrap();
        let encrypted_data = encrypted_secrets.dump();

        let decrypt_str = |s: &str| keyring.decrypt_str(s).unwrap();

        assert_eq!(data["a"], encrypted_data["a"]);
        assert_eq!(data["_c"], encrypted_data["_c"]);
        assert_eq!(
            data["b"].to_string(),
            decrypt_str(&encrypted_data["b"].to_string())
        );

        assert_eq!(data["d"]["da"], encrypted_data["d"]["da"]);
        assert_eq!(data["d"]["_dc"], encrypted_data["d"]["_dc"]);
        assert_eq!(
            data["d"]["db"].to_string(),
            decrypt_str(&encrypted_data["d"]["db"].to_string())
        );
    }

    #[test]
    fn encrypt_flat_arrays() {
        let data = json::array!["a", "b", "c", "d",];
        let keyring = Keyring::generate(DefaultErrorHandler);
        let plain_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = plain_secrets.encrypt(&keyring).unwrap();
        let encrypted_data = encrypted_secrets.dump();

        assert!(encrypted_data.is_array());
        assert_eq!(encrypted_data.len(), 4);
        assert!(encrypted_data.members().all(|v| v.is_string()));
        let decrypted_data = EncryptedSecrets::from_json(&keyring, encrypted_data)
            .decrypt()
            .unwrap()
            .dump();
        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn encrypt_flat_arrays_nested_data() {
        let data = json::array!["a", {"b": "b1"}, "c", {"_d": "d1"},];
        let keyring = Keyring::generate(DefaultErrorHandler);
        let plain_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = plain_secrets.encrypt(&keyring).unwrap();
        let encrypted_data = encrypted_secrets.dump();

        assert!(encrypted_data.is_array());
        assert_eq!(encrypted_data.len(), 4);

        let decrypted_data = EncryptedSecrets::from_json(&keyring, encrypted_data)
            .decrypt()
            .unwrap()
            .dump();
        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn from_json_with_one_secret_key() {
        let k1 = KeyPair::generate().to_string_pair();
        let k2 = KeyPair::generate().to_string_pair();
        let mut json_data = json::object! {};
        json_data.insert(&k1.0, JsonValue::Null).unwrap();
        json_data
            .insert(
                &k2.0,
                JsonValue::from(k2.1.as_ref().map(String::as_str).unwrap()),
            )
            .unwrap();

        // This is just to assert that the key with an empty private key comes first when iterated over
        if let JsonValue::Object(obj) = &json_data {
            let mut obj_iter = obj.iter();

            let k1_pair = obj_iter.next().unwrap();
            assert_eq!(k1_pair.0, k1.0);
            assert_eq!(k1_pair.1, &JsonValue::Null);

            let k2_pair = obj_iter.next().unwrap();
            assert_eq!(k2_pair.0, k2.0);
            assert_eq!(
                k2_pair.1,
                &JsonValue::from(k2.1.as_ref().map(String::as_str).unwrap())
            );
        } else {
            panic!("wat");
        }

        let restored = Keyring::from_json(json_data, DefaultErrorHandler).unwrap();
        assert_eq!(restored.default_public_key().unwrap(), k2.0);
    }

    #[test]
    fn from_json_with_no_secret_key() {
        let k1 = KeyPair::generate().to_string_pair();
        let k2 = KeyPair::generate().to_string_pair();

        let mut json_data = json::object! {};
        json_data.insert(&k1.0, JsonValue::Null).unwrap();
        json_data.insert(&k2.0, JsonValue::Null).unwrap();

        // This is just to assert that the key with an empty private key comes first when iterated over
        if let JsonValue::Object(obj) = &json_data {
            let mut obj_iter = obj.iter();

            let k1_pair = obj_iter.next().unwrap();
            assert_eq!(k1_pair.0, k1.0);
            assert_eq!(k1_pair.1, &JsonValue::Null);

            let k2_pair = obj_iter.next().unwrap();
            assert_eq!(k2_pair.0, k2.0);
            assert_eq!(k2_pair.1, &JsonValue::Null);
        } else {
            panic!("wat");
        }

        let restored = Keyring::from_json(json_data, DefaultErrorHandler).unwrap();
        assert!(
            restored.default_public_key().unwrap() == k1.0
                || restored.default_public_key().unwrap() == k2.0
        );
    }

    #[test]
    fn to_json_and_back() {
        let keyring = Keyring::generate(DefaultErrorHandler)
            + Keyring::generate(DefaultErrorHandler)
            + Keyring::generate(DefaultErrorHandler);
        assert_eq!(keyring.len(), 3);
        let dump = keyring.to_json();
        let restored = Keyring::from_json(dump, DefaultErrorHandler).unwrap();
        assert!(restored.default_public_key().is_ok());

        let mut keyring_pairs = keyring
            .keys
            .iter()
            .map(|(key_id, key_pair)| (key_id, (key_pair.public_key(), key_pair.private_key())))
            .collect::<Vec<_>>();
        keyring_pairs.sort_by_key(|(k, _)| *k);
        let mut restored_pairs = restored
            .keys
            .iter()
            .map(|(key_id, key_pair)| (key_id, (key_pair.public_key(), key_pair.private_key())))
            .collect::<Vec<_>>();
        restored_pairs.sort_by_key(|(k, _)| *k);

        for ((k1, (p1, s1)), (k2, (p2, s2))) in keyring_pairs.iter().zip(restored_pairs.iter()) {
            assert_eq!(k1, k2);
            assert_eq!(base64::decode(k1).unwrap(), p1.as_bytes());
            assert_eq!(base64::decode(k2).unwrap(), p2.as_bytes());
            assert_eq!(p1.as_bytes(), s1.as_ref().unwrap().public_key().as_bytes());
            assert_eq!(p2.as_bytes(), s2.as_ref().unwrap().public_key().as_bytes());
            assert_eq!(
                s1.as_ref().unwrap().to_bytes(),
                s2.as_ref().unwrap().to_bytes()
            );
        }
    }

    #[test]
    fn test_default_public_key() {
        let keyring = Keyring::default();
        assert!(keyring.default_public_key().is_err());
        assert_eq!(keyring.keys.keys().count(), 0);

        let keyring = Keyring::new(DefaultErrorHandler);
        assert!(keyring.default_public_key().is_err());
        assert_eq!(keyring.keys.keys().count(), 0);

        let keyring = Keyring::generate(DefaultErrorHandler)
            + Keyring::generate(DefaultErrorHandler)
            + Keyring::generate(DefaultErrorHandler);
        assert!(keyring.default_public_key.is_some());
        assert_eq!(keyring.keys.keys().count(), 3);

        let pub_key = keyring.default_public_key().unwrap();
        assert!(keyring.keys.contains_key(pub_key));
    }

    #[test]
    fn default_public_key_is_stable() {
        let keyring = Keyring::new(DefaultErrorHandler);
        assert!(keyring.default_public_key().is_err());
        assert!(keyring.default_public_key.is_none());

        let mut keyring = Keyring::generate(DefaultErrorHandler);
        assert!(keyring.default_public_key().is_ok());
        assert!(keyring.default_public_key.is_some());

        let key = keyring.default_public_key().unwrap().to_string();
        keyring += Keyring::generate(DefaultErrorHandler);
        assert_eq!(key, keyring.default_public_key().unwrap());
        keyring += Keyring::generate(DefaultErrorHandler);
        assert_eq!(key, keyring.default_public_key().unwrap());

        let keyring2 = keyring + Keyring::generate(DefaultErrorHandler);
        assert_eq!(key, keyring2.default_public_key().unwrap());
    }

    #[test]
    fn encrypt_with_just_public_key() {
        let k1 = KeyPair::generate().to_string_pair();

        let keyring = {
            let mut keyring_json = json::object! {};
            keyring_json.insert(&k1.0, JsonValue::Null).unwrap();
            Keyring::from_json(keyring_json, DefaultErrorHandler).unwrap()
        };

        let data = object! {
            "a": 1,
            "b": "b",
            "_c": "c",
            "d": {
                "da": 2,
                "db": "b2",
                "_dc": "c2",
            }
        };

        let unencrypted_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = unencrypted_secrets.encrypt(&keyring).unwrap();
        let encrypted_data = encrypted_secrets.dump();

        assert_eq!(data["a"], encrypted_data["a"]);
        assert_eq!(data["_c"], encrypted_data["_c"]);
        assert_eq!(data["d"]["da"], encrypted_data["d"]["da"]);
        assert_eq!(data["d"]["_dc"], encrypted_data["d"]["_dc"]);

        match keyring.decrypt_str(&encrypted_data["b"].to_string()) {
            Err(SecretsError::MissingPrivateKey { key_id }) => {
                assert_eq!(key_id, keyring.default_public_key().unwrap());
            }
            _ => {
                panic!("WAT: Keyring has no secret key, it should have failed");
            }
        }
        match keyring.decrypt_str(&encrypted_data["d"]["db"].to_string()) {
            Err(SecretsError::MissingPrivateKey { key_id }) => {
                assert_eq!(key_id, keyring.default_public_key().unwrap());
            }
            _ => {
                panic!("WAT: Keyring has no secret key, it should have failed");
            }
        }

        // Now we construct the keyring that does have the private key
        let keyring = {
            let mut keyring_json = json::object! {};
            keyring_json
                .insert(
                    &k1.0,
                    JsonValue::from(k1.1.as_ref().map(String::as_str).unwrap()),
                )
                .unwrap();
            Keyring::from_json(keyring_json, DefaultErrorHandler).unwrap()
        };

        assert_eq!(
            data["b"].to_string(),
            keyring
                .decrypt_str(&encrypted_data["b"].to_string())
                .unwrap()
        );
        assert_eq!(
            data["d"]["db"].to_string(),
            keyring
                .decrypt_str(&encrypted_data["d"]["db"].to_string())
                .unwrap()
        );
    }

    #[test]
    fn encrypt_with_explicit_detached_public_key() {
        let data = object! {
            "a": 1,
            "b": "b",
            "_c": "c",
            "d": {
                "da": 2,
                "db": "b2",
                "_dc": "c2",
            }
        };

        assert!(data.is_object());

        let keyring = Keyring::generate(DefaultErrorHandler);
        let detached_key = keyring.default_public_key().ok();
        assert!(detached_key.is_some());

        let secretless_keyring = Keyring::new(DefaultErrorHandler);
        assert_eq!(secretless_keyring.keys.iter().count(), 0);
        assert!(secretless_keyring.default_public_key().is_err());

        let unencrypted_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = unencrypted_secrets
            .encrypt_with(&secretless_keyring, detached_key)
            .unwrap();
        let encrypted_data = encrypted_secrets.dump();

        let decrypt_str = |s: &str| keyring.decrypt_str(s).unwrap();

        assert_eq!(data["a"], encrypted_data["a"]);
        assert_eq!(data["_c"], encrypted_data["_c"]);
        assert_eq!(
            data["b"].to_string(),
            decrypt_str(&encrypted_data["b"].to_string())
        );

        assert_eq!(data["d"]["da"], encrypted_data["d"]["da"]);
        assert_eq!(data["d"]["_dc"], encrypted_data["d"]["_dc"]);
        assert_eq!(
            data["d"]["db"].to_string(),
            decrypt_str(&encrypted_data["d"]["db"].to_string())
        );
    }
}
