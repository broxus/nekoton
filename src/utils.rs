use anyhow::Error;
use futures::TryStreamExt;

pub trait NoFailure {
    type Output;
    fn convert(self) -> Result<Self::Output, Error>;
}

impl<T> NoFailure for Result<T, failure::Error> {
    type Output = T;
    fn convert(self) -> Result<Self::Output, Error> {
        self.map_err(|e| Error::msg(e.to_string()))
    }
}
