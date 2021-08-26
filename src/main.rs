use std::fmt::Debug;

use anyhow::Error;

use json::JsonValue;
use structopt::StructOpt;

mod path_assign;
mod secrets;
mod utilities;

use crate::path_assign::PathAssign;
use crate::secrets::{EncryptedSecrets, HandleDecryptError, Keyring, PlainSecrets};
use crate::utilities::{InputFile, OutputFile};

struct DecryptErrorHandler {
    strict: bool,
}

impl HandleDecryptError for DecryptErrorHandler {
    fn on_decrypt_error<E>(&self, value: &mut json::JsonValue, error: E) -> Result<(), E>
    where
        E: Debug,
    {
        if self.strict {
            return Err(error);
        }

        // TODO: Colors!
        eprintln!(
            "[Strictness Off] Error decrypting string `{}`: {:?}",
            value, error
        );
        Ok(())
    }
}

impl DecryptErrorHandler {
    fn new(strict: bool) -> Self {
        Self { strict }
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
    },

    Decrypt {
        #[structopt(short, long, env = "PRIVIE_KEYRING")]
        keyring: InputFile,
        #[structopt(short, long, default_value)]
        input: InputFile,
        #[structopt(short, long, default_value)]
        output: OutputFile,
        #[structopt(short, long)]
        strict: bool,
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
        #[structopt(long)]
        create: bool,

        path: String,
        value: Option<String>,
    },
    // ScratchPad,
}

fn main() -> Result<(), Error> {
    let cli_args = CliCommands::from_args();

    match cli_args {
        CliCommands::VerifyKeyring { input } => {
            Keyring::from_json(input.read_json()?)?;
        }

        CliCommands::GenerateKeyring { output } => {
            output.write_json(Keyring::generate().to_json())?;
        }

        CliCommands::Encrypt {
            keyring: keyring_file,
            input,
            output,
            key_id,
        } => {
            let keyring = Keyring::from_json(keyring_file.read_json()?)?;
            let unencrypted_secrets = PlainSecrets::from_json(input.read_json()?)?;
            output.write_json(unencrypted_secrets.encrypt_with(&keyring, key_id)?.dump())?;
        }

        CliCommands::Decrypt {
            keyring: keyring_file,
            input,
            output,
            strict,
        } => {
            let decrypt_error_handler = DecryptErrorHandler::new(strict);
            let keyring = Keyring::from_json(keyring_file.read_json()?)?;
            let encrypted_secrets = EncryptedSecrets::from_json(&keyring, input.read_json()?)?;
            output.write_json(
                encrypted_secrets
                    .decrypt(Some(&decrypt_error_handler))?
                    .dump(),
            )?;
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
        } => {
            let mut keyring = Keyring::from_json(keyring_file.read_json()?)?;
            if let Some(key_id) = key_id {
                keyring.set_default_public_key(key_id)?;
            }
            let mut encrypted_secrets = EncryptedSecrets::from_json(
                &keyring,
                input.read_json().or_else(|error| {
                    // TODO: Inspect `error` and only act on `create` if
                    // it's a "not found"/"does not exist" type of error
                    if create {
                        Ok(JsonValue::new_object())
                    } else {
                        Err(error)
                    }
                })?,
            )?;

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
