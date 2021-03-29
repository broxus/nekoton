use super::Result;
pub struct AbiParser {
    abi: String,
}

impl AbiParser {
    pub fn new(abi: String) -> Result<Self> {
        serde_json::from_str(&abi)?;
        Ok(Self { abi })
    }

    pub fn parse(&self) {}
}
