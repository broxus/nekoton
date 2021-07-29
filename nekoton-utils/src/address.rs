use std::str::FromStr;

use anyhow::Result;
use base64::URL_SAFE;
use ton_block::{MsgAddrStd, MsgAddressInt};
use ton_types::AccountId;

use crate::crc::crc_16;

///Packs std address to base64 format
/// # Arguments
/// `base64_url` - encode with url friendly charset or not
pub fn pack_std_smc_addr(
    base64_url: bool,
    addr: &MsgAddressInt,
    bounceable: bool,
) -> Result<String> {
    let addr = match addr {
        MsgAddressInt::AddrStd(addr) => addr,
        MsgAddressInt::AddrVar(_) => {
            return Err(AddressConversionError::UnsupportedAddressType.into())
        }
    };

    let testnet = false;
    let mut buffer = [0u8; 36];
    buffer[0] = (0x51 - (bounceable as i32) * 0x40 + (testnet as i32) * 0x80) as u8;
    buffer[1] = addr.workchain_id as u8;
    buffer[2..34].copy_from_slice(&addr.address.storage()[0..32]);
    let crc = crc_16(&buffer[..34]);
    buffer[34] = (crc >> 8) as u8;
    buffer[35] = (crc & 0xff) as u8;
    let b64_enc = if base64_url {
        base64::encode_config(&buffer, URL_SAFE)
    } else {
        base64::encode(&buffer)
    };
    Ok(b64_enc)
}

///Unpacks base64 encoded address to std address
/// # Arguments
/// `base64_url` - encode with url friendly charset or not
pub fn unpack_std_smc_addr(packed: &str, base64_url: bool) -> Result<MsgAddressInt> {
    let unpacked = if base64_url {
        base64::decode_config(packed, URL_SAFE)
    } else {
        base64::decode(packed)
    }
    .map_err(|_| AddressConversionError::InvalidBase64)?;

    if unpacked.len() != 36 {
        return Err(AddressConversionError::InvalidPackedLength.into());
    }

    let crc = crc_16(&unpacked[..34]);
    if unpacked[34] as u16 != (crc >> 8) || unpacked[35] as u16 != (crc & 0xff) {
        return Err(AddressConversionError::InvalidChecksum.into());
    }

    let wc = unpacked[1];
    let address = &unpacked[2..34];
    let address = AccountId::from_raw(address.to_vec(), address.len() * 8);
    Ok(MsgAddressInt::AddrStd(MsgAddrStd {
        workchain_id: wc as i8,
        anycast: None,
        address,
    }))
}

pub fn validate_address(address: &str) -> bool {
    MsgAddressInt::from_str(address).is_ok()
        || unpack_std_smc_addr(address, false).is_ok()
        || unpack_std_smc_addr(address, true).is_ok()
}

/// repacks any `address` to `MsgAddressInt`
pub fn repack_address(address: &str) -> Result<MsgAddressInt> {
    if let Ok(a) = MsgAddressInt::from_str(address) {
        return Ok(a);
    }
    if let Ok(a) = unpack_std_smc_addr(address, false) {
        return Ok(a);
    }
    if let Ok(a) = unpack_std_smc_addr(address, true) {
        return Ok(a);
    }
    Err(AddressConversionError::InvalidAddress.into())
}

#[derive(thiserror::Error, Debug)]
enum AddressConversionError {
    #[error("Unsupported address type")]
    UnsupportedAddressType,
    #[error("Invalid base64")]
    InvalidBase64,
    #[error("Invalid packed address length")]
    InvalidPackedLength,
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid address")]
    InvalidAddress,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ton_block::MsgAddressInt;

    use crate::address::{pack_std_smc_addr, unpack_std_smc_addr};

    fn test_addr() -> MsgAddressInt {
        MsgAddressInt::from_str(
            "0:02e3f2284e68a8106b823ab9f2404f33cc43fccad8e1de835bdd96789254686c",
        )
        .unwrap()
    }

    #[test]
    fn check_pack_std_smc_addr_non_bounce() {
        let addr = test_addr();
        assert_eq!(
            pack_std_smc_addr(false, &addr, false).unwrap(),
            "UQAC4/IoTmioEGuCOrnyQE8zzEP8ytjh3oNb3ZZ4klRobAEx"
        );
    }

    #[test]
    fn check_pack_std_smc_addr_url_non_bounce() {
        let addr = test_addr();
        assert_eq!(
            pack_std_smc_addr(true, &addr, false).unwrap(),
            "UQAC4_IoTmioEGuCOrnyQE8zzEP8ytjh3oNb3ZZ4klRobAEx"
        );
    }

    #[test]
    fn check_pack_std_smc_addr_bounce() {
        let addr = test_addr();
        assert_eq!(
            pack_std_smc_addr(false, &addr, true).unwrap(),
            "EQAC4/IoTmioEGuCOrnyQE8zzEP8ytjh3oNb3ZZ4klRobFz0"
        );
    }

    #[test]
    fn check_pack_std_smc_addr_url_bounce() {
        let addr = test_addr();
        assert_eq!(
            pack_std_smc_addr(true, &addr, true).unwrap(),
            "EQAC4_IoTmioEGuCOrnyQE8zzEP8ytjh3oNb3ZZ4klRobFz0"
        );
    }

    #[test]
    fn unpack_no_bounce() {
        let addr = test_addr();
        let packed = pack_std_smc_addr(false, &addr, false).unwrap();
        let address = unpack_std_smc_addr(&packed, false).unwrap();
        assert_eq!(addr, address);
    }
    #[test]
    fn unpack_bounce() {
        let addr = test_addr();
        let packed = pack_std_smc_addr(false, &addr, true).unwrap();
        let address = unpack_std_smc_addr(&packed, false).unwrap();
        assert_eq!(addr, address);
    }

    #[test]
    pub fn repack_b64_safe() {
        let res = super::repack_address("EQAC4_IoTmioEGuCOrnyQE8zzEP8ytjh3oNb3ZZ4klRobFz0")
            .unwrap()
            .to_string();
        assert_eq!(
            "0:02e3f2284e68a8106b823ab9f2404f33cc43fccad8e1de835bdd96789254686c",
            res
        )
    }

    #[test]
    pub fn repack_b64() {
        let res = super::repack_address("EQAC4/IoTmioEGuCOrnyQE8zzEP8ytjh3oNb3ZZ4klRobFz0")
            .unwrap()
            .to_string();
        assert_eq!(
            "0:02e3f2284e68a8106b823ab9f2404f33cc43fccad8e1de835bdd96789254686c",
            res
        )
    }

    #[test]
    pub fn repack_normal() {
        let res = super::repack_address(
            "0:02e3f2284e68a8106b823ab9f2404f33cc43fccad8e1de835bdd96789254686c",
        )
        .unwrap()
        .to_string();
        assert_eq!(
            "0:02e3f2284e68a8106b823ab9f2404f33cc43fccad8e1de835bdd96789254686c",
            res
        )
    }

    #[test]
    pub fn repack_bad() {
        let res = super::repack_address(
            "0:02e3f2284e68a8106b823ab9f2404f33cc43fccad8e1de835bdd96789254686ca",
        );
        assert!(res.is_err())
    }
}
