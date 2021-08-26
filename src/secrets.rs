use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::{Debug, Display, Formatter},
};

use anyhow::{format_err, Context, Error};
use crypto_box::{
    aead::{generic_array::GenericArray, Aead},
    generate_nonce, Box as CryptoBox, PublicKey, SecretKey, KEY_SIZE,
};
use json::{object::Object as JsonObject, JsonValue};

use crate::path_assign::PathAssign;
use crate::sealed_box;

pub trait HandleDecryptError {
    fn on_decrypt_error<E>(
        &self,
        #[allow(unused_variables)] value: &mut JsonValue,
        error: E,
    ) -> Result<(), E>
    where
        E: Debug,
    {
        Err(error)
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct EncryptedSecrets<'a> {
    keyring: &'a Keyring,
    data: JsonValue,
}

impl<'a> EncryptedSecrets<'a> {
    #[allow(clippy::unnecessary_wraps)]
    pub fn from_json(keyring: &'a Keyring, json_data: JsonValue) -> Result<Self, Error> {
        Ok(Self {
            keyring,
            data: json_data,
        })
    }

    pub fn decrypt<H: HandleDecryptError>(
        self,
        decrypt_error_handler: Option<&H>,
    ) -> Result<PlainSecrets, Error> {
        self.keyring.decrypt(self, decrypt_error_handler)
    }

    pub fn new(keyring: &'a Keyring) -> Self {
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

    pub fn encrypt_with<S>(
        self,
        keyring: &Keyring,
        public_key: Option<S>,
    ) -> Result<EncryptedSecrets, Error>
    where
        S: AsRef<str>,
    {
        keyring.encrypt(self, public_key)
    }

    pub fn encrypt(self, keyring: &Keyring) -> Result<EncryptedSecrets, Error> {
        self.encrypt_with(keyring, None::<&str>)
    }

    pub fn dump(&self) -> JsonValue {
        self.data.clone()
    }
}

pub struct Keyring {
    keys: HashMap<String, SecretKey>,
    default_public_key: Option<String>,
}

impl std::ops::Add for Keyring {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut result = Self::new();
        result.keys.extend(self.keys.into_iter());
        result.keys.extend(rhs.keys.into_iter());
        result.default_public_key = self.default_public_key;
        result
    }
}

impl std::ops::AddAssign for Keyring {
    fn add_assign(&mut self, rhs: Self) {
        self.keys.extend(rhs.keys.into_iter());
        if self.default_public_key.is_none() {
            self.default_public_key = rhs.default_public_key;
        }
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let keys_dbg = &f
            .debug_map()
            .entries(self.keys.iter().map(|(k, _)| (k, "<redacted>")))
            .finish()?;
        f.debug_struct("Keyring").field("keys", keys_dbg).finish()
    }
}

impl Default for Keyring {
    fn default() -> Self {
        Keyring::new()
    }
}

impl Keyring {
    const SEP: char = ':';

    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default_public_key: None,
        }
    }

    pub fn generate() -> Self {
        let mut this = Self::new();
        let secret_key = SecretKey::generate(&mut rand::rngs::OsRng);
        let public_key = secret_key.public_key();
        let key_id = base64::encode(public_key.as_bytes());
        this.keys.insert(key_id.clone(), secret_key);
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
                .map(|(key_id, secret_key)| (key_id, base64::encode(secret_key.to_bytes())))
                .collect::<JsonObject>(),
        )
    }

    fn check_keys(public_key: &str, private_key: &str) -> Result<(PublicKey, SecretKey), Error> {
        let private_key_bytes: [u8; KEY_SIZE] = base64::decode(private_key.as_bytes())
            .with_context(|| format_err!("Decoding `{}...` as Base64", &private_key[0..5]))?
            .try_into()
            .map_err(|decoded: Vec<_>| {
                format_err!(
                    "Decoded private key byte length is {}, but it should be {}",
                    decoded.len(),
                    KEY_SIZE
                )
            })
            .with_context(|| {
                format!(
                    "Error decoding {} bytes as a Base64 private key for the `{}` public key ",
                    KEY_SIZE, public_key
                )
            })?;

        let decoded_private_key = SecretKey::from(private_key_bytes);
        let generated_public_key = decoded_private_key.public_key();
        let public_key_bytes = generated_public_key.as_bytes();
        let public_key_bytes_encoded = base64::encode(public_key_bytes);

        if public_key != base64::encode(public_key_bytes) {
            return Err(format_err!(
                "Public key {} doesn't match decoded public_key {}",
                public_key,
                public_key_bytes_encoded
            ));
        }

        Ok((generated_public_key, decoded_private_key))
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn from_json_obj(json_obj: JsonObject) -> Result<Self, Error> {
        let mut this = Self::new();
        for (key_id, v) in json_obj.iter() {
            if let json_string @ (JsonValue::String(_) | JsonValue::Short(_)) = v {
                let (_, secret_key) = Self::check_keys(key_id, json_string.as_str().unwrap())
                    .with_context(|| format!("Error checking public key `{}`", key_id))?;

                if this.default_public_key.is_none() {
                    this.default_public_key = Some(key_id.into());
                }
                this.keys.insert(key_id.into(), secret_key);
            }
        }
        Ok(this)
    }

    pub fn from_json(json_data: JsonValue) -> Result<Self, Error> {
        match json_data {
            JsonValue::Object(obj) => Self::from_json_obj(obj),
            _ => Err(format_err!("JSON data is not a JSON object")),
        }
    }

    pub fn encrypt_str<K: AsRef<str> + Display, S: AsRef<str>>(
        &self,
        key_id: K,
        data: S,
    ) -> Result<String, Error> {
        let key_id = key_id.as_ref();
        let secret_key = self
            .keys
            .get(key_id)
            .ok_or_else(|| format_err!("Public key `{}` is not in this keyring", key_id))?;

        let public_key = secret_key.public_key();
        let nonce = generate_nonce(&mut rand::rngs::OsRng);
        let cryptobox = CryptoBox::new(&public_key, secret_key);
        let encrypted = cryptobox
            .encrypt(
                &nonce,
                data.as_ref().as_bytes(),
                // TODO: Somehow `Payload` doesn't work?
                // crypto_box::aead::Payload {
                //     aad: b"privie-encrypted",
                //     msg: data.as_ref().as_bytes(),
                // },
            )
            .with_context(|| format_err!("Error encrypting secret with key `{}`", key_id))?;

        Ok(format!(
            "{}{}{}{}{}",
            key_id,
            Self::SEP,
            base64::encode(nonce.as_slice()),
            Self::SEP,
            base64::encode(encrypted)
        ))
    }

    pub fn encrypt_in_place<S: AsRef<str> + Display>(
        &self,
        key_id: &S,
        data: &mut JsonValue,
    ) -> Result<(), Error> {
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

    pub fn decrypt_str<S: AsRef<str>>(&self, data: S) -> Result<String, Error> {
        let mut splitter = data.as_ref().splitn(3, Self::SEP);

        let key_id = splitter
            .next()
            .ok_or_else(|| format_err!("No key ID found"))?;

        let nonce = GenericArray::clone_from_slice(
            &base64::decode(
                splitter
                    .next()
                    .ok_or_else(|| format_err!("No nonce found"))?,
            )
            .context("Decoding nonce as Base64")?,
        );

        let encrypted = base64::decode(
            splitter
                .next()
                .ok_or_else(|| format_err!("No encrypted secret found"))?,
        )
        .context("Decoding encrypted secret as Base64")?;

        let secret_key = self
            .keys
            .get(key_id)
            .ok_or_else(|| format_err!("Public key `{}` is not in this keyring", key_id))?;
        let public_key = secret_key.public_key();
        let cryptobox = CryptoBox::new(&public_key, secret_key);
        let decrypted = cryptobox
            .decrypt(&nonce, &encrypted[..])
            .context("Decrypting secret")?;
        String::from_utf8(decrypted).context("Reading decrypted secret as UTF-8")
    }

    pub fn decrypt_in_place<H: HandleDecryptError>(
        &self,
        data: &mut JsonValue,
        decrypt_error_handler: Option<&H>,
    ) -> Result<(), Error> {
        match data {
            JsonValue::Object(obj) => {
                for (_k, v) in obj.iter_mut().filter(|(k, _)| !k.starts_with('_')) {
                    self.decrypt_in_place(v, decrypt_error_handler)?;
                }
            }
            JsonValue::Array(elems) => {
                for elem in elems.iter_mut() {
                    self.decrypt_in_place(elem, decrypt_error_handler)?;
                }
            }
            json_string @ (JsonValue::String(_) | JsonValue::Short(_)) => {
                let encrypted = json_string.as_str().unwrap();
                let mut decrypted: JsonValue = match self.decrypt_str(encrypted) {
                    Ok(decrypted) => decrypted.into(),
                    Err(error) => {
                        return match decrypt_error_handler {
                            None => Err(error),
                            Some(handler) => handler.on_decrypt_error(json_string, error),
                        }
                    }
                };
                std::mem::swap(json_string, &mut decrypted);
            }
            _ => {}
        }

        Ok(())
    }

    pub fn default_public_key(&self) -> Result<&str, Error> {
        self.default_public_key
            .as_deref()
            .ok_or_else(|| format_err!("This keyring has no keys yet"))
    }

    pub fn set_default_public_key<S: AsRef<str>>(&mut self, public_key: S) -> Result<(), Error> {
        let public_key = public_key.as_ref();
        if !self.keys.contains_key(public_key) {
            return Err(format_err!(
                "Public key `{}` is not in this keyring",
                public_key
            ));
        }
        self.default_public_key = Some(public_key.into());
        Ok(())
    }

    pub fn encrypt<S: AsRef<str>>(
        &self,
        secrets: PlainSecrets,
        public_key: Option<S>,
    ) -> Result<EncryptedSecrets, Error> {
        let PlainSecrets { mut data } = secrets;

        let public_key = match public_key {
            Some(public_key) => {
                let public_key = public_key.as_ref();
                if !self.keys.contains_key(public_key) {
                    return Err(format_err!(
                        "Public key `{}` is not in this keyring",
                        public_key
                    ));
                }

                public_key.to_string()
            }
            None => self.default_public_key().map(ToOwned::to_owned)?,
        };

        self.encrypt_in_place(&public_key, &mut data)
            .with_context(|| format_err!("Encrypting secrets with public key `{}`", public_key))?;
        Ok(EncryptedSecrets {
            keyring: self,
            data,
        })
    }

    pub fn decrypt<H: HandleDecryptError>(
        &self,
        secrets: EncryptedSecrets,
        decrypt_error_handler: Option<&H>,
    ) -> Result<PlainSecrets, Error> {
        let EncryptedSecrets {
            mut data,
            keyring: _,
        } = secrets;

        self.decrypt_in_place(&mut data, decrypt_error_handler)?;
        Ok(PlainSecrets { data })
    }
}

impl<'k> PathAssign for EncryptedSecrets<'k> {
    fn get_assign_target(&mut self) -> &mut JsonValue {
        &mut self.data
    }

    fn preprocess_value<K, J>(&self, path: K, value: Option<J>) -> Result<Option<JsonValue>, Error>
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

impl PathAssign for PlainSecrets {
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
    use rand::RngCore;

    use super::*;

    struct DecryptErrorHandlerStub;
    impl HandleDecryptError for DecryptErrorHandlerStub {}

    #[test]
    fn test_encrypted_secrets_new() {
        let keyring = Keyring::default();
        let secrets = EncryptedSecrets::new(&keyring);
        assert!(secrets.data.is_object());
        assert_eq!(secrets.data.len(), 0);
    }

    #[test]
    fn keyring_add_op() {
        let keyring1 = Keyring::generate();
        let keyring2 = Keyring::generate();

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
        let mut keyring1 = Keyring::generate();
        let keyring2 = Keyring::generate();

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
        let debug_repr = format!("{:?}", Keyring::new());
        assert_eq!(debug_repr, "{}Keyring { keys: () }");
    }

    #[test]
    fn default_key_with_generate() {
        let keyring = Keyring::generate();
        assert_eq!(
            keyring.keys.keys().next().unwrap(),
            keyring.default_public_key().unwrap()
        )
    }

    #[test]
    fn default_key_with_new() {
        let keyring = Keyring::new();
        assert!(keyring.default_public_key().is_err());
    }

    #[test]
    fn nonempty_keyring_debug_repr() {
        let keyring = Keyring::generate();
        let debug_repr = format!("{:?}", keyring);
        let key_id = keyring.default_public_key().unwrap();

        assert_eq!(
            debug_repr,
            format!("{{{:?}: \"<redacted>\"}}Keyring {{ keys: () }}", key_id)
        );
    }

    #[test]
    fn encrypt_decrypt_str() {
        let keyring = Keyring::generate();
        let key_id = keyring.default_public_key().unwrap();
        let msg = "this is a secret string!";
        let encrypted_msg = keyring.encrypt_str(key_id, msg).unwrap();

        assert_ne!(msg, encrypted_msg);
        assert_eq!(
            encrypted_msg
                .split(Keyring::SEP)
                .map(base64::decode)
                .filter(Result::is_ok)
                .collect::<Vec<_>>()
                .len(),
            3
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

        let keyring = Keyring::generate();
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

        let keyring = Keyring::generate();
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
        let keyring = Keyring::generate();
        let plain_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = plain_secrets.encrypt(&keyring).unwrap();
        let encrypted_data = encrypted_secrets.dump();

        assert!(encrypted_data.is_array());
        assert_eq!(encrypted_data.len(), 4);
        assert!(encrypted_data.members().all(|v| v.is_string()));
        let decrypted_data = EncryptedSecrets::from_json(&keyring, encrypted_data)
            .unwrap()
            .decrypt(None::<&DecryptErrorHandlerStub>)
            .unwrap()
            .dump();
        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn encrypt_flat_arrays_nested_data() {
        let data = json::array!["a", {"b": "b1"}, "c", {"_d": "d1"},];
        let keyring = Keyring::generate();
        let plain_secrets = PlainSecrets::from_json(data.clone());
        let encrypted_secrets = plain_secrets.encrypt(&keyring).unwrap();
        let encrypted_data = encrypted_secrets.dump();

        assert!(encrypted_data.is_array());
        assert_eq!(encrypted_data.len(), 4);

        let decrypted_data = EncryptedSecrets::from_json(&keyring, encrypted_data)
            .unwrap()
            .decrypt(None::<&DecryptErrorHandlerStub>)
            .unwrap()
            .dump();
        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn to_json_and_back() {
        let keyring = Keyring::generate() + Keyring::generate() + Keyring::generate();
        assert_eq!(keyring.len(), 3);
        let dump = keyring.to_json();
        let restored = Keyring::from_json(dump).unwrap();

        let mut keyring_pairs = keyring.keys.iter().collect::<Vec<_>>();
        keyring_pairs.sort_by_key(|(k, _)| *k);
        let mut restored_pairs = restored.keys.iter().collect::<Vec<_>>();
        restored_pairs.sort_by_key(|(k, _)| *k);

        for ((k1, v1), (k2, v2)) in keyring_pairs.iter().zip(restored_pairs.iter()) {
            assert_eq!(k1, k2);
            assert_eq!(v1.to_bytes(), v2.to_bytes());
        }
    }

    #[test]
    fn test_default_public_key() {
        let keyring = Keyring::default();
        assert!(keyring.default_public_key().is_err());
        assert_eq!(keyring.keys.keys().count(), 0);

        let keyring = Keyring::new();
        assert!(keyring.default_public_key().is_err());
        assert_eq!(keyring.keys.keys().count(), 0);

        let keyring = Keyring::generate() + Keyring::generate() + Keyring::generate();
        assert!(keyring.default_public_key.is_some());
        assert_eq!(keyring.keys.keys().count(), 3);

        let pub_key = keyring.default_public_key().unwrap();
        assert!(keyring.keys.contains_key(pub_key));
    }

    #[test]
    fn default_public_key_is_stable() {
        let keyring = Keyring::new();
        assert!(keyring.default_public_key().is_err());
        assert!(keyring.default_public_key.is_none());

        let mut keyring = Keyring::generate();
        assert!(keyring.default_public_key().is_ok());
        assert!(keyring.default_public_key.is_some());

        let key = keyring.default_public_key().unwrap().to_string();
        keyring += Keyring::generate();
        assert_eq!(key, keyring.default_public_key().unwrap());
        keyring += Keyring::generate();
        assert_eq!(key, keyring.default_public_key().unwrap());

        let keyring2 = keyring + Keyring::generate();
        assert_eq!(key, keyring2.default_public_key().unwrap());
    }

    #[test]
    fn checking_wrong_keys() {
        let k1 = Keyring::generate();
        let k2 = Keyring::generate();

        let k1_public = k1.default_public_key().unwrap();
        let k1_secret = base64::encode(k1.keys.get(k1_public).unwrap().to_bytes());

        let k2_public = k2.default_public_key().unwrap();
        let k2_secret = base64::encode(k2.keys.get(k2_public).unwrap().to_bytes());

        assert!(Keyring::check_keys(k1_public, &k1_secret).is_ok());
        assert!(Keyring::check_keys(k2_public, &k2_secret).is_ok());

        assert!(Keyring::check_keys(k1_public, &k2_secret).is_err());
        assert!(Keyring::check_keys(k2_public, &k1_secret).is_err());

        assert!(Keyring::check_keys(k1_public, &k1_secret[..(k1_secret.len() - 2)]).is_err());
        assert!(Keyring::check_keys(k2_public, &k2_secret[..(k2_secret.len() - 2)]).is_err());
        assert!(Keyring::check_keys(&k1_public[..(k1_public.len() - 2)], &k1_secret).is_err());
        assert!(Keyring::check_keys(&k2_public[..(k2_public.len() - 2)], &k2_secret).is_err());

        let mut rng = rand::rngs::OsRng;
        let mut buf = Vec::with_capacity(KEY_SIZE * 3);
        rng.fill_bytes(&mut buf);
        assert!(Keyring::check_keys(k1_public, &base64::encode(buf)).is_err());
    }
}
