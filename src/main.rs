use std::fmt::Debug;

use anyhow::Error;

use json::JsonValue;
use structopt::StructOpt;

mod path_assign;
mod sealed_box;
mod secrets;
mod utilities;

use crate::path_assign::PathAssign;
use crate::secrets::{EncryptedSecrets, HandleError, Keyring, PlainSecrets};
use crate::utilities::{InputFile, IoUtilsError, OutputFile};

#[derive(Debug, Clone)]
struct CliErrorHandler {
    strict_key_loading: bool,
    strict_decryption: bool,
}

impl HandleError for CliErrorHandler {
    fn decrypt_error<E>(&self, value: &mut json::JsonValue, error: E) -> Result<(), E>
    where
        E: Debug,
    {
        if self.strict_decryption {
            return Err(error);
        }

        // TODO: Colors!
        eprintln!(
            "[Strictness Off] Error decrypting string `{}`: {:?}",
            value, error
        );
        Ok(())
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
        if self.strict_key_loading {
            return Err(error);
        }
        // TODO: Colors!
        eprintln!(
            "[Strictness Off] Error loading keys `{}`: {:?}",
            public_key, error
        );
        Ok(())
    }
}

impl CliErrorHandler {
    fn new(strict_key_loading: bool, strict_decryption: bool) -> Self {
        Self {
            strict_key_loading,
            strict_decryption,
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "Privie", about = "Code secrets management tool")]
enum CliCommands {
    #[structopt(help = "Generate a new keyring file with a single key pair")]
    GenerateKeyring {
        #[structopt(
            short,
            long,
            default_value,
            help = "Where to write the JSON keyring data."
        )]
        output: OutputFile,
    },

    #[structopt(
        help = "Verify a keyring file, like its keys size and that public/secret pair do match."
    )]
    VerifyKeyring {
        #[structopt(short, long, default_value, help = "JSON keyring to verify.")]
        input: InputFile,
    },

    Encrypt {
        #[structopt(
            short,
            long,
            env = "PRIVIE_KEYRING",
            default_value = "./.privie-keyring.json",
            help = "Keyring used for encryption."
        )]
        keyring: InputFile,
        #[structopt(
            long,
            help = "Extra keyrings to use. These will all get merged with the primary one and used as one."
        )]
        extra_keyrings: Vec<InputFile>,
        #[structopt(short, long, default_value, help = "The JSON data to encrypt.")]
        input: InputFile,
        #[structopt(
            short,
            long,
            default_value,
            help = "Where to write the encrypted JSON data."
        )]
        output: OutputFile,
        #[structopt(
            long,
            help = "Use this key to encrypt secrets, instead of the one being picked at random. This key doesn't have to be present in the keyring, though it would have to be present in the keyring (and with its corresponding secret key) when decrypting."
        )]
        key_id: Option<String>,
        #[structopt(
            long,
            help = "Verify the keyring's keys, like their size and that public/secret pair do match."
        )]
        strict_keyring: bool,
    },

    Decrypt {
        #[structopt(
            short,
            long,
            env = "PRIVIE_KEYRING",
            default_value = "./.privie-keyring.json",
            help = "Keyring used for encryption. You will need to make sure all the referenced public keys have their corresponding secret keys to be able to decrypt with them."
        )]
        keyring: InputFile,
        #[structopt(
            long,
            help = "Extra keyrings to use. These will all get merged with the primary one and used as one."
        )]
        extra_keyrings: Vec<InputFile>,
        #[structopt(
            short,
            long,
            default_value,
            help = "The encrypted JSON data to decrypt"
        )]
        input: InputFile,
        #[structopt(
            short,
            long,
            default_value,
            help = "Where to write the decrypted JSON data"
        )]
        output: OutputFile,
        #[structopt(
            long,
            help = "Verify keyring's keys, like their size and that public/secret pair do match."
        )]
        strict_keyring: bool,
        #[structopt(
            long,
            help = "Abort the operation if at least one secret fails to be decrypted"
        )]
        strict_decryption: bool,
    },

    AddSecret {
        #[structopt(
            short,
            long,
            env = "PRIVIE_KEYRING",
            default_value = "./.privie-keyring.json",
            help = "Keyring used for encryption."
        )]
        keyring: InputFile,
        #[structopt(
            long,
            help = "Extra keyrings to use. These will all get merged with the primary one and used as one."
        )]
        extra_keyrings: Vec<InputFile>,
        #[structopt(
            short,
            long,
            default_value,
            help = "The encrypted JSON data to add secrets to."
        )]
        input: InputFile,
        #[structopt(
            short,
            long,
            default_value,
            help = "Where to write the decrypted JSON data."
        )]
        output: OutputFile,
        #[structopt(short, long, help = "Force overwriting existing values.")]
        force: bool,
        #[structopt(
            long,
            help = "Use this key to encrypt secrets, instead of the one being picked at random. This key doesn't have to be present in the keyring, though it would have to be present in the keyring (and with its corresponding secret key) when decrypting."
        )]
        key_id: Option<String>,
        #[structopt(
            long,
            help = "Verify keyring's keys, like their size and that public/secret pair do match."
        )]
        strict_keyring: bool,
        #[structopt(
            long,
            help = "Don't abort if there is no input file, create an empty JSON document and add new secrets to it."
        )]
        create: bool,

        #[structopt(
            help = "JSON path where to set the new value. Currently only simple `object.field.subField` paths are supported."
        )]
        path: String,
        #[structopt(
            help = "The JSON value to set. This will be parsed as a JSON string, and if the parsed valie is a string, it will be encrypted before written to the output. If parsing fails, the entire argument is used as a string and encryptted. If this argument is missing, then the value at this path is removed."
        )]
        value: Option<String>,
    },
}

fn main() -> Result<(), Error> {
    let cli_args = CliCommands::from_args();

    match cli_args {
        CliCommands::VerifyKeyring { input } => {
            Keyring::from_json(input.read_json()?, CliErrorHandler::new(true, true))?;
        }

        CliCommands::GenerateKeyring { output } => {
            output.write_json(Keyring::generate(CliErrorHandler::new(true, true)).to_json())?;
        }

        CliCommands::Encrypt {
            keyring: keyring_file,
            extra_keyrings: extra_keyring_files,
            input,
            output,
            key_id,
            strict_keyring,
        } => {
            InputFile::check_stdin_once([&input, &keyring_file])?;
            let error_handler = CliErrorHandler::new(strict_keyring, true);
            let mut keyring = Keyring::from_json(keyring_file.read_json()?, error_handler.clone())?;
            for extra_keyring_file in extra_keyring_files {
                keyring +=
                    Keyring::from_json(extra_keyring_file.read_json()?, error_handler.clone())?;
            }
            let unencrypted_secrets = PlainSecrets::from_json(input.read_json()?);
            output.write_json(unencrypted_secrets.encrypt_with(&keyring, key_id)?.dump())?;
        }

        CliCommands::Decrypt {
            keyring: keyring_file,
            extra_keyrings: extra_keyring_files,
            input,
            output,
            strict_keyring,
            strict_decryption,
        } => {
            InputFile::check_stdin_once([&input, &keyring_file])?;
            let error_handler = CliErrorHandler::new(strict_keyring, strict_decryption);
            let mut keyring = Keyring::from_json(keyring_file.read_json()?, error_handler.clone())?;
            for extra_keyring_file in extra_keyring_files {
                keyring +=
                    Keyring::from_json(extra_keyring_file.read_json()?, error_handler.clone())?;
            }
            let encrypted_secrets = EncryptedSecrets::from_json(&keyring, input.read_json()?);
            output.write_json(encrypted_secrets.decrypt()?.dump())?;
        }

        CliCommands::AddSecret {
            keyring: keyring_file,
            extra_keyrings: extra_keyring_files,

            input,
            output,
            path: json_path,
            value,
            force,
            key_id,
            create,
            strict_keyring,
        } => {
            InputFile::check_stdin_once([&input, &keyring_file])?;
            let error_handler = CliErrorHandler::new(strict_keyring, true);
            let mut keyring = Keyring::from_json(keyring_file.read_json()?, error_handler.clone())?;
            for extra_keyring_file in extra_keyring_files {
                keyring +=
                    Keyring::from_json(extra_keyring_file.read_json()?, error_handler.clone())?;
            }
            if let Some(key_id) = key_id {
                keyring.set_default_public_key(key_id)?;
            }

            let mut encrypted_secrets = EncryptedSecrets::from_json(
                &keyring,
                input.read_json().or_else(|error| {
                    // TODO: Is there a way to do this this better than with three nested `if`s
                    if create {
                        if let IoUtilsError::Open { ref source, .. } = error {
                            if let std::io::ErrorKind::NotFound = source.kind() {
                                return Ok(JsonValue::new_object());
                            }
                        }
                    }
                    Err(error)
                })?,
            );

            encrypted_secrets.path_assign(
                json_path,
                value.map(|s| json::parse(&s)).transpose()?,
                force,
            )?;

            output.write_json(encrypted_secrets.dump())?;
        }
    }

    Ok(())
}
