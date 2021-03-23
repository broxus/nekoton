use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use graphql_client::*;
use ton_block::{Account, Deserializable, Message, MsgAddressInt, Serializable};
use ton_types::UInt256;

use crate::core::models::{GenTimings, TransactionId};
use crate::transport::models::*;
use crate::transport::Transport;

pub struct GqlTransport {
    connection: Arc<dyn GqlConnection>,
}

impl GqlTransport {
    pub fn new(connection: Arc<dyn GqlConnection>) -> Self {
        Self { connection }
    }

    async fn fetch<T>(&self, params: T::Variables) -> Result<T::ResponseData>
    where
        T: GraphQLQuery,
    {
        let request_body = T::build_query(params);
        let response = self
            .connection
            .post(&serde_json::to_string(&request_body).expect("Shouldn't fail"))
            .await
            .map_err(api_failure)?;

        match serde_json::from_str::<Response<T::ResponseData>>(&response) {
            Ok(response) => response.data.ok_or_else(|| invalid_response().into()),
            Err(e) => Err(api_failure(format!(
                "Failed parsing api response: {}. Response data: {}",
                e, response
            ))
            .into()),
        }
    }
}

#[async_trait]
impl Transport for GqlTransport {
    async fn send_message(&self, message: &Message) -> Result<()> {
        let cell = message
            .serialize()
            .map_err(|_| NodeClientError::FailedToSerialize)?;
        let id = base64::encode(&cell.repr_hash());
        let boc = base64::encode(
            &cell
                .write_to_bytes()
                .map_err(|_| NodeClientError::FailedToSerialize)?,
        );

        let _ = self
            .fetch::<MutationSendMessage>(mutation_send_message::Variables { id, boc })
            .await?;

        Ok(())
    }

    async fn get_account_state(&self, address: &MsgAddressInt) -> Result<ContractState> {
        #[derive(GraphQLQuery)]
        #[graphql(
            schema_path = "src/transport/gql/schema.graphql",
            query_path = "src/transport/gql/query_account_state.graphql"
        )]
        struct QueryAccountState;

        let account_state = match self
            .fetch::<QueryAccountState>(query_account_state::Variables {
                address: address.to_string(),
            })
            .await?
            .accounts
            .ok_or_else(invalid_response)?
            .into_iter()
            .next()
            .and_then(|item| item.and_then(|account| account.boc))
        {
            Some(account_state) => account_state,
            None => return Ok(ContractState::NotExists),
        };

        match Account::construct_from_base64(&account_state) {
            Ok(Account::Account(account)) => {
                let last_transaction_id = TransactionId {
                    lt: account.storage.last_trans_lt,
                    hash: Default::default(), // there is no way to get it in gql
                };

                Ok(ContractState::Exists {
                    account,
                    timings: GenTimings::Unknown,
                    last_transaction_id,
                })
            }
            Ok(_) => Ok(ContractState::NotExists),
            Err(_) => Err(NodeClientError::InvalidAccountState.into()),
        }
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from: &TransactionId,
        count: u8,
    ) -> Result<Vec<TransactionFull>> {
        #[derive(GraphQLQuery)]
        #[graphql(
            schema_path = "src/transport/gql/schema.graphql",
            query_path = "src/transport/gql/query_account_transactions.graphql"
        )]
        struct QueryAccountTransactions;

        self.fetch::<QueryAccountTransactions>(query_account_transactions::Variables {
            address: address.to_string(),
            last_transaction_lt: from.lt.to_string(),
            limit: count as i64,
        })
        .await?
        .transactions
        .ok_or_else(invalid_response)?
        .into_iter()
        .flatten()
        .map(|transaction| {
            let bytes = base64::decode(&transaction.boc.ok_or_else(invalid_response)?)?;
            let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(bytes))
                .map_err(|_| NodeClientError::InvalidTransaction)?;
            let hash = cell.repr_hash();
            Ok(TransactionFull {
                hash,
                data: ton_block::Transaction::construct_from_cell(cell)
                    .map_err(|_| NodeClientError::InvalidTransaction)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
    }
}

#[async_trait]
pub trait GqlConnection: Send + Sync {
    async fn post(&self, data: &str) -> Result<String>;
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/mutation_send_message.graphql"
)]
struct MutationSendMessage;

fn api_failure<T>(e: T) -> NodeClientError
where
    T: std::fmt::Display,
{
    NodeClientError::ApiFailure {
        reason: e.to_string(),
    }
}

fn invalid_response() -> NodeClientError {
    NodeClientError::InvalidResponse
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NodeClientError {
    #[error("API request failed. {reason}")]
    ApiFailure { reason: String },
    #[error("Invalid response")]
    InvalidResponse,
    #[error("Invalid transaction data")]
    InvalidTransaction,
    #[error("Failed to serialize data")]
    FailedToSerialize,
    #[error("Invalid account state")]
    InvalidAccountState,
}
