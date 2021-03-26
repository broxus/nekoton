use ton_block::{Deserializable, Serializable};
use ton_types::UInt256;

use crate::contracts::execution::labs::ClientResult;
use crate::utils::NoFailure;

pub(crate) fn serialize_object_to_cell<S: Serializable>(
    object: &S,
) -> ClientResult<ton_types::Cell> {
    object.serialize().convert()
}

pub(crate) fn deserialize_cell_from_base64(b64: &str) -> ClientResult<(Vec<u8>, ton_types::Cell)> {
    let bytes = base64::decode(&b64)?;

    let cell = ton_types::cells_serialization::deserialize_tree_of_cells(&mut bytes.as_slice())
        .convert()?;
    Ok((bytes, cell))
}

pub(crate) async fn deserialize_cell_from_boc(
    boc: &str,
) -> ClientResult<(DeserializedBoc, ton_types::Cell)> {
    deserialize_cell_from_base64(boc).map(|(bytes, cell)| (DeserializedBoc::Bytes(bytes), cell))
}

pub(crate) async fn deserialize_object_from_boc<S: Deserializable>(
    boc: &str,
) -> ClientResult<DeserializedObject<S>> {
    let (boc, cell) = deserialize_cell_from_boc(boc).await?;

    let object = deserialize_object_from_cell(cell.clone())?;

    Ok(DeserializedObject { boc, cell, object })
}

pub(crate) fn deserialize_object_from_cell<S: Deserializable>(
    cell: ton_types::Cell,
    name: &str,
) -> ClientResult<S> {
    S::construct_from(&mut cell.into())
        .map_err(|err| Error::invalid_boc(format!("cannot deserialize {} from BOC: {}", name, err)))
}

pub(crate) enum DeserializedBoc {
    Cell(ton_types::Cell),
    Bytes(Vec<u8>),
}

impl DeserializedBoc {
    pub fn bytes(self, name: &str) -> ClientResult<Vec<u8>> {
        match self {
            DeserializedBoc::Bytes(vec) => Ok(vec),
            DeserializedBoc::Cell(cell) => serialize_cell_to_bytes(&cell, name),
        }
    }
}
