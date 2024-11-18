use lazy_static::lazy_static;
use sha2::{Digest, Sha256};
use ton_types::{SliceData, UInt256};

use crate::{load_dict_snake_format, SnakeFormatDict};

pub struct MetaDataField {
    pub key: UInt256,
}

impl MetaDataField {
    fn new(name: &str) -> MetaDataField {
        let key = Self::key_from_str(name);
        MetaDataField { key }
    }

    fn key_from_str(k: &str) -> UInt256 {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(k);
        let slice = &hasher.finalize()[..];
        UInt256::from_slice(slice)
    }

    pub fn use_string_or(&self, src: Option<String>, dict: &SnakeFormatDict) -> Option<String> {
        src.or(dict
            .get(&self.key)
            .cloned()
            .and_then(|vec| String::from_utf8(vec).ok()))
    }
}

lazy_static! {
    pub static ref META_NAME: MetaDataField = MetaDataField::new("name");
    pub static ref META_DESCRIPTION: MetaDataField = MetaDataField::new("description");
    pub static ref META_IMAGE: MetaDataField = MetaDataField::new("image");
    pub static ref META_SYMBOL: MetaDataField = MetaDataField::new("symbol");
    pub static ref META_IMAGE_DATA: MetaDataField = MetaDataField::new("image_data");
    pub static ref META_DECIMALS: MetaDataField = MetaDataField::new("decimals");
    pub static ref META_URI: MetaDataField = MetaDataField::new("uri");
    pub static ref META_CONTENT_URL: MetaDataField = MetaDataField::new("content_url");
    pub static ref META_ATTRIBUTES: MetaDataField = MetaDataField::new("attributes");
    pub static ref META_SOCIAL_LINKS: MetaDataField = MetaDataField::new("social_links");
    pub static ref META_MARKETPLACE: MetaDataField = MetaDataField::new("marketplace");
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum MetaDataContent {
    Internal { dict: SnakeFormatDict },
    Unsupported,
}

impl MetaDataContent {
    pub fn parse(cell: &ton_types::Cell) -> anyhow::Result<MetaDataContent> {
        let mut content = SliceData::load_cell_ref(cell)?;

        let content_representation = content.get_next_byte()?;
        match content_representation {
            0 => {
                let dict = load_dict_snake_format(&mut content)?;
                Ok(MetaDataContent::Internal { dict })
            }
            _ => Ok(MetaDataContent::Unsupported),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct JettonMetaData {
    pub name: Option<String>,
    pub uri: Option<String>,
    pub symbol: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub image_data: Option<Vec<u8>>,
    pub decimals: Option<u8>,
}

impl From<&SnakeFormatDict> for JettonMetaData {
    fn from(dict: &SnakeFormatDict) -> Self {
        JettonMetaData {
            name: META_NAME.use_string_or(None, dict),
            uri: META_URI.use_string_or(None, dict),
            symbol: META_SYMBOL.use_string_or(None, dict),
            description: META_DESCRIPTION.use_string_or(None, dict),
            image: META_IMAGE.use_string_or(None, dict),
            image_data: dict.get(&META_IMAGE_DATA.key).cloned(),
            decimals: META_DECIMALS
                .use_string_or(None, dict)
                .map(|v| v.parse::<u8>().unwrap()),
        }
    }
}
