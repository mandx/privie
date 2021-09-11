use std::{
    fmt::{Display, Formatter},
    fs::{File, OpenOptions},
    io::{self, stdin, stdout, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum IoUtilsError<P: std::fmt::Debug + Display> {
    #[error("Could not open `{path}`")]
    Open {
        #[source]
        source: io::Error,
        path: P,
    },

    #[error("Could not read from `{path}`")]
    Read {
        #[source]
        source: io::Error,
        path: P,
    },

    #[error("Could not write to `{path}`")]
    Write {
        #[source]
        source: io::Error,
        path: P,
    },

    #[error("Could not parse `{path}` as JSON")]
    JsonParse { source: json::Error, path: P },
}

#[derive(Debug, Clone)]
pub struct InputFile {
    filename: Option<PathBuf>,
}

impl Display for InputFile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self.filename {
            Some(path) => write!(formatter, "{}", path.to_string_lossy()),
            None => write!(formatter, "{}", Self::DISPLAY_STR),
        }
    }
}

impl std::str::FromStr for InputFile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "" | "-" | Self::DISPLAY_STR => Self::use_stdin(),
            s => Self::use_filename(s),
        })
    }
}

impl Default for InputFile {
    fn default() -> Self {
        Self::use_stdin()
    }
}

impl InputFile {
    const DISPLAY_STR: &'static str = "<stdin>";

    pub fn use_stdin() -> Self {
        Self { filename: None }
    }

    pub fn use_filename<P: AsRef<Path>>(filename: P) -> Self {
        Self {
            filename: Some(filename.as_ref().into()),
        }
    }

    pub fn open(&self) -> Result<impl Read, IoUtilsError<Self>> {
        match &self.filename {
            Some(path) => Ok(Box::new(BufReader::new(File::open(path).map_err(|error| {
                IoUtilsError::Open {
                    source: error,
                    path: self.clone(),
                }
            })?)) as Box<dyn Read>),
            None => Ok(Box::new(BufReader::new(stdin())) as Box<dyn Read>),
        }
    }

    pub fn read(&self) -> Result<String, IoUtilsError<Self>> {
        let mut reader = self.open()?;

        let mut buf = String::new();
        reader
            .read_to_string(&mut buf)
            .map_err(|error| IoUtilsError::Read {
                source: error,
                path: self.clone(),
            })?;
        Ok(buf)
    }

    pub fn read_json(&self) -> Result<json::JsonValue, IoUtilsError<Self>> {
        json::parse(&self.read()?).map_err(|error| IoUtilsError::JsonParse {
            source: error,
            path: self.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OutputFile {
    filename: Option<PathBuf>,
}

impl Display for OutputFile {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self.filename {
            Some(path) => write!(formatter, "{}", path.to_string_lossy()),
            None => write!(formatter, "{}", Self::DISPLAY_STR),
        }
    }
}

impl std::str::FromStr for OutputFile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "" | "-" | Self::DISPLAY_STR => Self::use_stdout(),
            s => Self::use_filename(s),
        })
    }
}

impl Default for OutputFile {
    fn default() -> Self {
        Self::use_stdout()
    }
}

impl OutputFile {
    const DISPLAY_STR: &'static str = "<stdout>";

    pub fn use_stdout() -> Self {
        Self { filename: None }
    }

    pub fn use_filename<P: AsRef<Path>>(filename: P) -> Self {
        Self {
            filename: Some(filename.as_ref().into()),
        }
    }

    pub fn open(&self) -> Result<impl Write, IoUtilsError<Self>> {
        match &self.filename {
            Some(path) => Ok(Box::new(BufWriter::new(
                OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(path)
                    .map_err(|error| IoUtilsError::Open {
                        source: error,
                        path: self.clone(),
                    })?,
            )) as Box<dyn Write>),
            None => Ok(Box::new(BufWriter::new(stdout())) as Box<dyn Write>),
        }
    }

    pub fn write<S: AsRef<[u8]>>(&self, content: S) -> Result<(), IoUtilsError<Self>> {
        self.open()?
            .write_all(content.as_ref())
            .map_err(|error| IoUtilsError::Write {
                source: error,
                path: self.clone(),
            })
    }

    pub fn write_json<J: Into<json::JsonValue>>(&self, data: J) -> Result<(), IoUtilsError<Self>> {
        self.write(&json::stringify_pretty(data.into(), 2))
    }
}

pub fn open_input<P: AsRef<Path>>(filename: Option<P>) -> Result<impl Read, io::Error> {
    match filename {
        Some(path) => Ok(Box::new(BufReader::new(File::open(path)?)) as Box<dyn Read>),
        None => Ok(Box::new(BufReader::new(stdin())) as Box<dyn Read>),
    }
}

pub fn open_output<P: AsRef<Path>>(filename: Option<P>) -> Result<impl Write, io::Error> {
    match filename {
        Some(path) => Ok(Box::new(BufWriter::new(
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)?,
        )) as Box<dyn Write>),
        None => Ok(Box::new(BufWriter::new(stdout())) as Box<dyn Write>),
    }
}

pub fn read_input<P: AsRef<Path>>(filename: Option<P>) -> Result<String, io::Error> {
    let mut reader = open_input(filename)?;
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    Ok(buf)
}

pub fn write_output<P: AsRef<Path>, S: AsRef<str>>(
    filename: Option<P>,
    content: S,
) -> Result<(), io::Error> {
    let mut writer = open_output(filename)?;
    writer.write_all(content.as_ref().as_bytes())
}

pub fn load_json<P: AsRef<Path>>(filename: Option<P>) -> Result<json::JsonValue, anyhow::Error> {
    Ok(json::parse(&read_input(filename)?)?)
}

pub fn write_json<P: AsRef<Path>>(
    filename: Option<P>,
    data: json::JsonValue,
) -> Result<(), io::Error> {
    write_output(filename, &json::stringify(data))
}
