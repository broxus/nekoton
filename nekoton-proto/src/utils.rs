use anyhow::Result;
use prost::bytes::Bytes;
use ton_block::{Deserializable, MaybeDeserialize, MsgAddressInt};
use ton_types::UInt256;

pub fn addr_to_bytes(address: &MsgAddressInt) -> Bytes {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(address.workchain_id() as u8);
    bytes.extend(address.address().get_bytestring_on_stack(0).to_vec());

    bytes.into()
}

pub fn bytes_to_addr(bytes: &Bytes) -> Result<MsgAddressInt> {
    if bytes.len() != 33 {
        anyhow::bail!("Invalid address")
    }

    let workchain_id = bytes[0] as i8;
    let address = ton_types::AccountId::from(<[u8; 32]>::try_from(&bytes[1..33])?);

    MsgAddressInt::with_standart(None, workchain_id, address)
}

pub fn deserialize_account_stuff(bytes: &Bytes) -> Result<ton_block::AccountStuff> {
    ton_types::deserialize_tree_of_cells(&mut bytes.as_ref()).and_then(|cell| {
        let slice = &mut ton_types::SliceData::load_cell(cell)?;
        Ok(ton_block::AccountStuff {
            addr: Deserializable::construct_from(slice)?,
            storage_stat: Deserializable::construct_from(slice)?,
            storage: ton_block::AccountStorage {
                last_trans_lt: Deserializable::construct_from(slice)?,
                balance: Deserializable::construct_from(slice)?,
                state: Deserializable::construct_from(slice)?,
                init_code_hash: if slice.remaining_bits() > 0 {
                    UInt256::read_maybe_from(slice)?
                } else {
                    None
                },
            },
        })
    })
}
