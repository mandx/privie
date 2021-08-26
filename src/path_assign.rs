use std::{mem, ops::IndexMut};

use anyhow::Error;
use json::JsonValue;

pub trait PathAssign {
    fn get_assign_target(&mut self) -> &mut JsonValue;

    fn preprocess_value<K, J>(
        &self,
        #[allow(unused_variables)] path: K,
        value: Option<J>,
    ) -> Result<Option<JsonValue>, Error>
    where
        K: AsRef<str>,
        J: Into<JsonValue>,
    {
        Ok(value.map(Into::into))
    }

    fn path_assign<S, J>(
        &mut self,
        path: S,
        value: Option<J>,
        #[allow(unused_variables)] force: bool,
    ) -> Result<(), Error>
    where
        S: AsRef<str>,
        J: Into<JsonValue>,
    {
        fn assign<'is, I>(iter: &'is mut I, location: &mut JsonValue, mut value: JsonValue)
        where
            I: Iterator<Item = &'is str>,
        {
            match iter.next() {
                Some(position) => {
                    dbg!(&position);
                    assign(iter, location.index_mut(position), value);
                }
                None => {
                    mem::swap(location, &mut value);
                }
            }
        }

        let path = path.as_ref();
        let mut path_iter = path.split('.');
        let data = self.get_assign_target();
        assign(&mut path_iter, data, value.into());
        Ok(())
    }
}
