use anyhow::Result;
use prost::bytes::Bytes;
use ton_block::MsgAddressInt;

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
    let address =
        ton_types::AccountId::from(<[u8; 32]>::try_from(&bytes[1..33])?);

    MsgAddressInt::with_standart(None, workchain_id, address)
}
