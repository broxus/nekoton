use crate::core::models::Expiration;
use crate::core::ton_wallet::{multisig, wallet_v3, TonWalletError, WalletType};
use crate::crypto::UnsignedMessage;
use anyhow::Result;
use ed25519_dalek::PublicKey;
use std::borrow::Cow;
use ton_block::MsgAddressInt;
use ton_types::SliceData;

impl super::TonWallet {
    pub fn prepare_deploy(&self, expiration: Expiration) -> Result<Box<dyn UnsignedMessage>> {
        match self.wallet_type {
            WalletType::WalletV3 => wallet_v3::prepare_deploy(&self.public_key, expiration),
            WalletType::Multisig(multisig_type) => multisig::prepare_deploy(
                &self.public_key,
                multisig_type,
                expiration,
                &[self.public_key],
                1,
            ),
        }
    }

    pub fn prepare_deploy_with_multiple_owners(
        &self,
        expiration: Expiration,
        custodians: &[PublicKey],
        req_confirms: u8,
    ) -> Result<Box<dyn UnsignedMessage>> {
        match self.wallet_type {
            WalletType::Multisig(multisig_type) => multisig::prepare_deploy(
                &self.public_key,
                multisig_type,
                expiration,
                custodians,
                req_confirms,
            ),
            WalletType::WalletV3 => Err(TonWalletError::InvalidContractType.into()),
        }
    }

    pub fn prepare_confirm_transaction(
        &self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        transaction_id: u64,
        expiration: Expiration,
    ) -> Result<Box<dyn UnsignedMessage>> {
        match self.wallet_type {
            WalletType::Multisig(multisig_type) => {
                let gen_timings = self.contract_state().gen_timings;
                let last_transaction_id = &self
                    .contract_state()
                    .last_transaction_id
                    .ok_or(TonWalletError::LastTransactionNotFound)?;

                let has_pending_transaction = multisig::find_pending_transaction(
                    multisig_type,
                    Cow::Borrowed(current_state),
                    gen_timings,
                    last_transaction_id,
                    transaction_id,
                )?;
                if !has_pending_transaction {
                    return Err(TonWalletError::PendingTransactionNotFound.into());
                }

                multisig::prepare_confirm_transaction(
                    public_key,
                    self.address().clone(),
                    transaction_id,
                    expiration,
                )
            }
            WalletType::WalletV3 => Err(TonWalletError::PendingTransactionNotFound.into()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_transfer(
        &mut self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        destination: MsgAddressInt,
        amount: u64,
        bounce: bool,
        body: Option<SliceData>,
        expiration: Expiration,
    ) -> Result<TransferAction> {
        match self.wallet_type {
            WalletType::Multisig(_) => {
                match &current_state.storage.state {
                    ton_block::AccountState::AccountFrozen(_) => {
                        return Err(TonWalletError::AccountIsFrozen.into())
                    }
                    ton_block::AccountState::AccountUninit => {
                        return Ok(TransferAction::DeployFirst)
                    }
                    ton_block::AccountState::AccountActive(_) => {}
                };

                self.wallet_data.update(
                    &self.public_key,
                    self.wallet_type,
                    current_state,
                    *self.contract_subscription.contract_state(),
                )?;

                let has_multiple_owners = match &self.wallet_data.custodians {
                    Some(custodians) => custodians.len() > 1,
                    None => return Err(TonWalletError::CustodiansNotFound.into()),
                };

                multisig::prepare_transfer(
                    public_key,
                    has_multiple_owners,
                    self.address().clone(),
                    destination,
                    amount,
                    bounce,
                    body,
                    expiration,
                )
            }
            WalletType::WalletV3 => wallet_v3::prepare_transfer(
                public_key,
                current_state,
                destination,
                amount,
                bounce,
                body,
                expiration,
            ),
        }
    }
}

#[derive(Clone)]
pub enum TransferAction {
    DeployFirst,
    Sign(Box<dyn UnsignedMessage>),
}
