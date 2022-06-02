use crate::core::models::{NftTransferRecipient, NftVersion};
use crate::core::ContractSubscription;
use crate::transport::models::{ExistingContract, RawContractState};
use crate::transport::Transport;
use anyhow::Result;
use nekoton_contracts::tip3_1::token_wallet_contract::owner;
use nekoton_contracts::tip4_1::nft_contract::GetInfoOutputs;
use nekoton_contracts::*;
use nekoton_utils::Clock;
use std::sync::Arc;
use ton_abi::contract::ABI_VERSION_2_2;
use ton_abi::{Token, TokenValue};
use ton_block::{MsgAddressInt, Serializable};
use ton_types::{BuilderData, Cell, UInt256};

const NFT_STAMP: &[u8; 3] = b"nft";

pub struct NftCollection {
    clock: Arc<dyn Clock>,
    collection_address: MsgAddressInt,
    nfts: Vec<MsgAddressInt>,
}

impl NftCollection {
    pub fn collection_address(&self) -> &MsgAddressInt {
        &self.collection_address
    }
    pub fn collection_nft_list(&self) -> &Vec<MsgAddressInt> {
        &self.nfts
    }
    pub async fn get(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        owner: MsgAddressInt,
        collection_address: MsgAddressInt,
    ) -> Result<NftCollection> {
        let state = match transport.get_contract_state(&collection_address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => return Err(NftError::InvalidCollectionContract.into()),
        };
        let collection_state = CollectionContractState(&state);

        let nfts = match collection_state.check_collection_supported_interface(clock.as_ref())? {
            Some(NftVersion::Tip4_3) => {
                let index_code = collection_state.resolve_collection_index_code(clock.as_ref())?;
                let code_hash = collection_state.get_collection_code_hash(&owner, index_code)?;
                transport
                    .get_accounts_by_code_hash(&code_hash, 100, &None)
                    .await?
            }
            None => return Err(NftError::InvalidCollectionContract.into()),
            _ => return Err(NftError::UnsupportedInterfaceVersion.into()),
        };

        Ok(Self {
            clock,
            collection_address,
            nfts,
        })
    }

    // pub fn get_wallet_nfts_by_collection(
    //     &self,
    //     owner: MsgAddressInt,
    //     collection: MsgAddressInt,
    // ) -> Result<Vec<MsgAddressInt>> {
    //     //self.contract_subscription.
    //     let index_code = "te6ccgECHQEAA1UAAgaK2zUcAQQkiu1TIOMDIMD/4wIgwP7jAvILGQMCGwOK7UTQ10nDAfhmifhpIds80wABn4ECANcYIPkBWPhC+RDyqN7TPwH4QyG58rQg+COBA+iogggbd0CgufK0+GPTHwHbPPI8DgsEA3rtRNDXScMB+GYi0NMD+kAw+GmpOAD4RH9vcYIImJaAb3Jtb3Nwb3T4ZNwhxwDjAiHXDR/yvCHjAwHbPPI8GBgEAzogggujrde64wIgghAWX5bBuuMCIIIQR1ZU3LrjAhMPBQRCMPhCbuMA+EbycyGT1NHQ3vpA0fhBiMjPjits1szOyds8CxwIBgJqiCFus/LoZiBu8n/Q1PpA+kAwbBL4SfhKxwXy4GT4ACH4a/hs+kJvE9cL/5Mg+GvfMNs88gAHFAA8U2FsdCBkb2Vzbid0IGNvbnRhaW4gYW55IHZhbHVlAhjQIIs4rbNYxwWKiuIJCgEK103Q2zwKAELXTNCLL0pA1yb0BDHTCTGLL0oY1yYg10rCAZLXTZIwbeICFu1E0NdJwgGOgOMNDBcCSnDtRND0BXEhgED0Do6A34kg+Gz4a/hqgED0DvK91wv/+GJw+GMNDgECiQ4AQ4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAD/jD4RvLgTPhCbuMA0x/4RFhvdfhk0ds8I44mJdDTAfpAMDHIz4cgznHPC2FeIMjPkll+WwbOWcjOAcjOzc3NyXCOOvhEIG8TIW8S+ElVAm8RyM+EgMoAz4RAzgH6AvQAcc8LaV4gyPhEbxXPCx/OWcjOAcjOzc3NyfhEbxTi+wAXEhABCOMA8gARACjtRNDT/9M/MfhDWMjL/8s/zsntVAAi+ERwb3KAQG90+GT4S/hM+EoDNjD4RvLgTPhCbuMAIZPU0dDe+kDR2zww2zzyABcVFAA6+Ez4S/hK+EP4QsjL/8s/z4POWcjOAcjOzc3J7VQBMoj4SfhKxwXy6GXIz4UIzoBvz0DJgQCg+wAWACZNZXRob2QgZm9yIE5GVCBvbmx5AELtRNDT/9M/0wAx+kDU0dD6QNTR0PpA0fhs+Gv4avhj+GIACvhG8uBMAgr0pCD0oRsaABRzb2wgMC41OC4yAAAADCD4Ye0e2Q==";
    //
    //     let code_hash = self.get_collection_code_hash(owner, collection)?;
    //     println!("{:x?}", code_hash);
    //     Ok(Vec::new())
    // }
}

pub struct Nft {
    clock: Arc<dyn Clock>,
    address: MsgAddressInt,
    collection_address: MsgAddressInt,
    owner: MsgAddressInt,
    manager: MsgAddressInt,
    json_info: Option<String>,
}

impl Nft {
    pub async fn get(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
    ) -> Result<Nft> {
        let state = match transport.get_contract_state(&address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => return Err(NftError::InvalidNftContact.into()),
        };
        let nft_state = NftContractState(&state);

        let ctx = nft_state.0.as_context(clock.as_ref());
        let tip6_interface = tip6::SidContract(ctx);

        let info = if tip6_interface.supports_interface(tip4_1::nft_contract::INTERFACE_ID)? {
            nft_state.get_info(clock.as_ref()).await?
        } else {
            return Err(NftError::InvalidNftContact.into());
        };

        let json_info =
            if tip6_interface.supports_interface(tip4_2::metadata_contract::INTERFACE_ID)? {
                Some(nft_state.get_json(clock.as_ref()).await?)
            } else {
                None
            };

        Ok(Self {
            clock,
            address,
            collection_address: info.collection,
            owner: info.owner,
            manager: info.manager,
            json_info,
        })
    }
}

trait NftCollectionSubscriptionHandler {}
trait NftSubscriptionHandler {}

#[derive(Debug)]
pub struct CollectionContractState<'a>(pub &'a ExistingContract);

impl<'a> CollectionContractState<'a> {
    fn check_collection_supported_interface(
        &self,
        clock: &dyn Clock,
    ) -> Result<Option<NftVersion>> {
        let ctx = self.0.as_context(clock);
        let tip6_interface = tip6::SidContract(ctx);
        if tip6_interface.supports_interface(tip4_3::collection_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_3));
        }

        if tip6_interface.supports_interface(tip4_1::collection_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_1));
        }

        Ok(None)
    }

    fn resolve_collection_index_code(&self, clock: &dyn Clock) -> Result<ton_types::Cell> {
        let ctx = self.0.as_context(clock);
        let collection = tip4_3::CollectionContract(ctx);
        Ok(collection.index_code()?)
    }
    fn get_collection_code_hash(&self, owner: &MsgAddressInt, code_index: Cell) -> Result<UInt256> {
        let mut builder = BuilderData::new();

        let owner_cell = owner.serialize()?;
        let collection_cell = self.0.account.addr.serialize()?;

        builder.append_raw(collection_cell.data(), collection_cell.bit_length())?;
        builder.append_raw(owner_cell.data(), owner_cell.bit_length())?;

        let mut nft = BuilderData::new();
        nft.append_raw(NFT_STAMP, 24)?;

        builder.append_reference_cell(nft.into_cell()?);

        let salt = builder.into_cell()?;

        //let b64_cell = base64::encode(&ton_types::cells_serialization::serialize_toc(&salt)?);
        //println!("base64_salt: {}", &b64_cell);

        let cell = nekoton_abi::set_cell_salt(salt, code_index)?;
        Ok(cell.hash(0))
    }
}

#[derive(Debug)]
pub struct NftContractState<'a>(pub &'a ExistingContract);

impl<'a> NftContractState<'a> {
    async fn check_nft_supported_interface(&self, clock: &dyn Clock) -> Result<Option<NftVersion>> {
        let ctx = self.0.as_context(clock);
        let tip6_interface = tip6::SidContract(ctx);
        if tip6_interface.supports_interface(tip4_3::nft_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_3));
        }

        if tip6_interface.supports_interface(tip4_2::metadata_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_2));
        }

        if tip6_interface.supports_interface(tip4_1::collection_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_1));
        }

        Ok(None)
    }

    async fn get_json(&self, clock: &dyn Clock) -> Result<String> {
        let ctx = self.0.as_context(clock);
        let tip4_2_interface = tip4_2::MetadataContract(ctx);
        Ok(tip4_2_interface.get_json()?)
    }

    async fn get_info(&self, clock: &dyn Clock) -> Result<GetInfoOutputs> {
        let ctx = self.0.as_context(clock);
        let tip4_1_interface = tip4_1::NftContract(ctx);
        Ok(tip4_1_interface.get_info()?)
    }
}

//#[cfg(test)]
mod tests {
    use crate::core::nft_wallet::NftCollection;
    use std::str::FromStr;
    use ton_block::MsgAddressInt;

    #[test]
    fn compute() {
        let owner_adrr = MsgAddressInt::from_str(
            "0:f083b8f9ba4a104eb83731b22bbbd5f30c51a234eaaa891970f4487cc1631d86",
        )
        .unwrap();
        let coll_addr = MsgAddressInt::from_str(
            "0:ae07f6957e10527dc4835402e68e68521eb6477ebf1737b772a79c66c5c62cc7",
        )
        .unwrap();
        //let x = NftCollection::get_wallet_nfts_by_collection(owner_adrr, coll_addr).unwrap();
    }
}

#[derive(thiserror::Error, Debug)]
enum NftError {
    #[error("Unsupported interface version")]
    UnsupportedInterfaceVersion,
    #[error("Invalid collection contract")]
    InvalidCollectionContract,
    #[error("Invalid nft contract")]
    InvalidNftContact,
    #[error("Non-zero execution result code: {}", .0)]
    NonZeroResultCode(i32),
    #[error("Contract not deployed")]
    ContractNotDeployed,
}
