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

#[derive(Debug)]
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
#[structopt(about = "Privie")]
enum CliCommands {
    GenerateKeyring {
        #[structopt(short, long, default_value)]
        output: OutputFile,
    },

    VerifyKeyring {
        #[structopt(short, long, default_value)]
        input: InputFile,
        #[structopt(
            long,
            help = "Verify keyring's keys, like their size and that public/secret pair do match."
        )]
        strict_keyring: bool,
    },

    Encrypt {
        #[structopt(short, long, env = "PRIVIE_KEYRING")]
        keyring: InputFile,
        #[structopt(short, long, default_value)]
        input: InputFile,
        #[structopt(short, long, default_value)]
        output: OutputFile,
        #[structopt(long)]
        key_id: Option<String>,
        #[structopt(
            long,
            help = "Verify keyring's keys, like their size and that public/secret pair do match."
        )]
        strict_keyring: bool,
    },

    Decrypt {
        #[structopt(short, long, env = "PRIVIE_KEYRING")]
        keyring: InputFile,
        #[structopt(short, long, default_value)]
        input: InputFile,
        #[structopt(short, long, default_value)]
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
        #[structopt(short, long, env = "PRIVIE_KEYRING")]
        keyring: InputFile,
        #[structopt(short, long, default_value)]
        input: InputFile,
        #[structopt(short, long, default_value)]
        output: OutputFile,
        #[structopt(short, long)]
        force: bool,
        #[structopt(long)]
        key_id: Option<String>,
        #[structopt(
            long,
            help = "Verify keyring's keys, like their size and that public/secret pair do match."
        )]
        strict_keyring: bool,
        #[structopt(long)]
        create: bool,

        path: String,
        value: Option<String>,
    },
}

fn main() -> Result<(), Error> {
    let cli_args = CliCommands::from_args();

    match cli_args {
        CliCommands::VerifyKeyring { input } => {
            Keyring::from_json(input.read_json()?)?;
        CliCommands::VerifyKeyring {
            input,
            strict_keyring,
        } => {
            Keyring::from_json(
                input.read_json()?,
                CliErrorHandler::new(strict_keyring, true),
            )?;
        }

        CliCommands::GenerateKeyring { output } => {
            output.write_json(Keyring::generate(CliErrorHandler::new(true, true)).to_json())?;
        }

        CliCommands::Encrypt {
            keyring: keyring_file,
            input,
            output,
            key_id,
            strict_keyring,
        } => {
            let keyring = Keyring::from_json(
                keyring_file.read_json()?,
                CliErrorHandler::new(strict_keyring, true),
            )?;
            let unencrypted_secrets = PlainSecrets::from_json(input.read_json()?);
            output.write_json(unencrypted_secrets.encrypt_with(&keyring, key_id)?.dump())?;
        }

        CliCommands::Decrypt {
            keyring: keyring_file,
            input,
            output,
            strict_keyring,
            strict_decryption,
        } => {
            let keyring = Keyring::from_json(
                keyring_file.read_json()?,
                CliErrorHandler::new(strict_keyring, strict_decryption),
            )?;
            let encrypted_secrets = EncryptedSecrets::from_json(&keyring, input.read_json()?);
            output.write_json(encrypted_secrets.decrypt()?.dump())?;
        }

        CliCommands::AddSecret {
            keyring: keyring_file,
            input,
            output,
            path: json_path,
            value,
            force,
            key_id,
            create,
            strict_keyring,
        } => {
            let mut keyring = Keyring::from_json(
                keyring_file.read_json()?,
                CliErrorHandler::new(strict_keyring, true),
            )?;
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
