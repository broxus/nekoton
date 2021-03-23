use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_ctr::cipher::SyncStreamCipher;
use anyhow::Result;
use async_trait::async_trait;
use rand::{CryptoRng, Rng, RngCore};
use sha2::digest::FixedOutput;
use tokio::sync::Mutex;
use ton_api::{ton, BoxedSerialize, Deserializer, IntoBoxed};
use ton_block::{Deserializable, Message, MsgAddressInt, Serializable};

use crate::core::models::{GenTimings, TransactionId};
use crate::transport::models::*;
use crate::transport::Transport;

const LAST_BLOCK_THRESHOLD: u64 = 1;

pub struct AdnlTransport {
    connection: Arc<dyn AdnlConnection>,
    last_block: Arc<LastBlock>,
}

impl AdnlTransport {
    pub fn new(connection: Arc<dyn AdnlConnection>) -> Self {
        let threshold = std::time::Duration::from_secs(LAST_BLOCK_THRESHOLD);

        Self {
            connection,
            last_block: Arc::new(LastBlock::new(&threshold)),
        }
    }

    async fn query<T>(&self, query: T) -> Result<T::Reply>
    where
        T: ton_api::Function,
    {
        let response = self.connection.query(ton::TLObject::new(query)).await?;
        match response.downcast::<T::Reply>() {
            Ok(reply) => Ok(reply),
            Err(error) => match error.downcast::<ton::lite_server::Error>() {
                Ok(error) => Err(QueryError::LiteServer(error).into()),
                Err(_) => Err(QueryError::Unknown.into()),
            },
        }
    }
}

#[async_trait]
impl Transport for AdnlTransport {
    async fn send_message(&self, message: &Message) -> Result<()> {
        let data = message
            .serialize()
            .and_then(|cell| cell.write_to_bytes())
            .map_err(|_| QuerySendMessageError::FailedToSerialize)?;

        self.query(ton::rpc::lite_server::SendMessage {
            body: ton::bytes(data),
        })
        .await?;
        Ok(())
    }

    async fn get_account_state(&self, address: &MsgAddressInt) -> Result<ContractState> {
        use ton_block::{Deserializable, HashmapAugType};

        let last_block_id = self.last_block.get_last_block(self).await?;

        let response = self
            .query(ton::rpc::lite_server::GetAccountState {
                id: last_block_id,
                account: ton::lite_server::accountid::AccountId {
                    workchain: address.workchain_id(),
                    id: ton::int256(
                        ton_types::UInt256::from(address.address().get_bytestring(0)).into(),
                    ),
                },
            })
            .await?
            .only();

        match ton_block::Account::construct_from_bytes(&response.state.0) {
            Ok(ton_block::Account::Account(account)) => {
                let q_roots =
                    ton_types::deserialize_cells_tree(&mut std::io::Cursor::new(&response.proof.0))
                        .map_err(|_| QueryAccountStateError::InvalidAccountStateProof)?;
                if q_roots.len() != 2 {
                    return Err(QueryAccountStateError::InvalidAccountStateProof.into());
                }

                let merkle_proof = ton_block::MerkleProof::construct_from_cell(q_roots[0].clone())
                    .map_err(|_| QueryAccountStateError::InvalidAccountStateProof)?;
                let proof_root = merkle_proof.proof.virtualize(1);

                let ss = ton_block::ShardStateUnsplit::construct_from(&mut proof_root.into())
                    .map_err(|_| QueryAccountStateError::InvalidAccountStateProof)?;

                let shard_info = ss
                    .read_accounts()
                    .and_then(|accounts| {
                        accounts.get(&ton_types::UInt256::from(
                            address.get_address().get_bytestring(0),
                        ))
                    })
                    .map_err(|_| QueryAccountStateError::InvalidAccountStateProof)?;

                Ok(if let Some(shard_info) = shard_info {
                    ContractState::Exists {
                        account,
                        timings: GenTimings::Known {
                            gen_lt: ss.gen_lt(),
                            gen_utime: ss.gen_time(),
                        },
                        last_transaction_id: TransactionId {
                            lt: shard_info.last_trans_lt(),
                            hash: *shard_info.last_trans_hash(),
                        },
                    }
                } else {
                    ContractState::NotExists
                })
            }
            Ok(_) => Ok(ContractState::NotExists),
            Err(_) => Err(QueryAccountStateError::InvalidAccountState.into()),
        }
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from: &TransactionId,
        count: u8,
    ) -> Result<Vec<TransactionFull>> {
        let response = self
            .query(ton::rpc::lite_server::GetTransactions {
                count: count as i32,
                account: ton::lite_server::accountid::AccountId {
                    workchain: address.workchain_id() as i32,
                    id: ton::int256(
                        ton_types::UInt256::from(address.address().get_bytestring(0)).into(),
                    ),
                },
                lt: from.lt as i64,
                hash: from.hash.into(),
            })
            .await?;
        let transactions = ton_types::deserialize_cells_tree(&mut std::io::Cursor::new(
            &response.transactions().0,
        ))
        .map_err(|_| QueryTransactionsError::InvalidTransactionsList)?;

        let mut result = Vec::with_capacity(transactions.len());
        for item in transactions.into_iter() {
            let hash = item.repr_hash();
            result.push(TransactionFull {
                hash,
                data: ton_block::Transaction::construct_from_cell(item)
                    .map_err(|_| QueryTransactionsError::InvalidTransaction)?,
            });
        }
        Ok(result)
    }
}

struct LastBlock {
    id: Mutex<
        Option<(
            Result<ton::ton_node::blockidext::BlockIdExt, QueryLastBlockError>,
            Instant,
        )>,
    >,
    threshold: Duration,
}

impl LastBlock {
    fn new(threshold: &Duration) -> Self {
        Self {
            id: Mutex::new(None),
            threshold: *threshold,
        }
    }

    async fn get_last_block(
        &self,
        transport: &AdnlTransport,
    ) -> Result<ton::ton_node::blockidext::BlockIdExt, QueryLastBlockError> {
        let mut lock = self.id.lock().await;
        let now = Instant::now();

        let new_id = match &mut *lock {
            Some((result, last)) if now.duration_since(*last) < self.threshold => {
                return result.clone();
            }
            _ => transport
                .query(ton::rpc::lite_server::GetMasterchainInfo)
                .await
                .map(|result| result.only().last)
                .map_err(|e| match e.downcast() {
                    Ok(e) => QueryLastBlockError::QueryError(e),
                    _ => QueryLastBlockError::Unknown,
                }),
        };

        *lock = Some((new_id.clone(), now));
        new_id
    }
}

#[derive(thiserror::Error, Debug)]
pub enum QuerySendMessageError {
    #[error("Failed to serialize message")]
    FailedToSerialize,
}

#[derive(thiserror::Error, Debug)]
pub enum QueryAccountStateError {
    #[error("Invalid account state")]
    InvalidAccountState,
    #[error("Invalid account state proof")]
    InvalidAccountStateProof,
}

#[derive(thiserror::Error, Debug)]
pub enum QueryTransactionsError {
    #[error("Invalid transactions list")]
    InvalidTransactionsList,
    #[error("Invalid transaction data")]
    InvalidTransaction,
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum QueryLastBlockError {
    #[error("Query error: {:?}", .0)]
    QueryError(#[from] QueryError),
    #[error("Unknown")]
    Unknown,
}

#[async_trait]
pub trait AdnlConnection: Send + Sync {
    async fn query(&self, request: ton::TLObject) -> Result<ton::TLObject>;
}

pub struct ClientState {
    crypto: AdnlStreamCrypto,
    buffer: Vec<u8>,
    receiver_state: ReceiverState,
}

impl ClientState {
    pub fn init(server_key: &ExternalKey) -> (Self, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let (crypto, nonce) = AdnlStreamCrypto::new_with_nonce(&mut rng);

        let client = Self {
            crypto,
            buffer: Vec::with_capacity(1024),
            receiver_state: ReceiverState::WaitingLength,
        };
        let init_packet =
            build_adnl_handshake_packet(&nonce, &LocalKey::generate(&mut rng), server_key);

        (client, init_packet)
    }

    pub fn build_ping_query(&mut self) -> Query {
        let mut rng = rand::thread_rng();
        let value = rng.gen();
        let query = ton::TLObject::new(ton::rpc::adnl::Ping { value });
        let (query_id, data) = build_adnl_message(&mut rng, &query);
        let data = self.crypto.pack(&data);
        Query { query_id, data }
    }

    pub fn build_query(&mut self, query: &ton::TLObject) -> Query {
        let mut rng = rand::thread_rng();
        let query_bytes = query.boxed_serialized_bytes().expect("Shouldn't fail");
        let (query_id, data) = build_adnl_message(
            &mut rng,
            &ton::TLObject::new(ton::rpc::lite_server::Query {
                data: ton::bytes(query_bytes),
            }),
        );
        let data = self.crypto.pack(&data);
        Query { query_id, data }
    }

    pub fn handle_init_response(&mut self, data: &mut [u8]) {
        self.crypto.unpack_init_packet(data);
    }

    pub fn handle_query(
        &mut self,
        data: &[u8],
    ) -> Result<Option<Box<ton::adnl::message::message::Answer>>, QueryError> {
        self.buffer.extend(data);
        let mut processed = 0;
        loop {
            match (self.receiver_state, self.buffer.len() - processed) {
                (ReceiverState::WaitingLength, remaining) if remaining >= 4 => {
                    let length = self
                        .crypto
                        .unpack_length(&self.buffer[processed..processed + 4]);

                    processed += 4;
                    if length >= 64 {
                        // SAFETY: length is always greater than zero
                        self.receiver_state = ReceiverState::WaitingPayload(unsafe {
                            NonZeroUsize::new_unchecked(length)
                        });
                    }
                }
                (ReceiverState::WaitingPayload(length), remaining) if remaining >= length.get() => {
                    let data = self.crypto.unpack_payload(
                        length.get(),
                        &mut self.buffer[processed..processed + length.get()],
                    );

                    processed += length.get();
                    self.receiver_state = ReceiverState::WaitingLength;

                    let answer = data
                        .and_then(|data| {
                            Deserializer::new(&mut std::io::Cursor::new(data))
                                .read_boxed::<ton::TLObject>()
                                .ok()
                        })
                        .and_then(|object| object.downcast::<ton::adnl::Message>().ok())
                        .and_then(|message| {
                            if let ton::adnl::Message::Adnl_Message_Answer(answer) = message {
                                Some(answer)
                            } else {
                                None
                            }
                        });

                    return if answer.is_some() {
                        self.buffer.drain(..processed);
                        Ok(answer)
                    } else {
                        Err(QueryError::InvalidResponse)
                    };
                }
                _ => {
                    self.buffer.drain(..processed);
                    return Ok(None);
                }
            }
        }
    }
}

#[derive(Copy, Clone)]
enum ReceiverState {
    WaitingLength,
    WaitingPayload(NonZeroUsize),
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum QueryError {
    #[error("Lite server error. code: {}, reason: {}", .0.code(), .0.message())]
    LiteServer(ton::lite_server::Error),
    #[error("Invalid ADNL response")]
    InvalidResponse,
    #[error("Unknown")]
    Unknown,
}

pub type QueryId = [u8; 32];

pub struct Query {
    pub query_id: [u8; 32],
    pub data: Vec<u8>,
}

fn build_adnl_message<T>(rng: &mut T, data: &ton::TLObject) -> (QueryId, Vec<u8>)
where
    T: RngCore,
{
    let query_id: QueryId = rng.gen();

    let mut query = Vec::new();
    ton_api::Serializer::new(&mut query)
        .write_boxed(data)
        .expect("Shouldn't fail");

    let message = ton::adnl::message::message::Query {
        query_id: ton::int256(query_id),
        query: ton::bytes(query),
    }
    .into_boxed();
    let mut data = Vec::new();
    ton_api::Serializer::new(&mut data)
        .write_boxed(&message)
        .expect("Shouldn't fail");

    (query_id, data)
}

struct AdnlStreamCrypto {
    cipher_receive: aes_ctr::Aes256Ctr,
    cipher_send: aes_ctr::Aes256Ctr,
}

impl AdnlStreamCrypto {
    fn new_with_nonce<T>(rng: &mut T) -> (Self, Vec<u8>)
    where
        T: CryptoRng + RngCore,
    {
        let nonce: Vec<u8> = (0..160).map(|_| rng.gen()).collect();

        // SAFETY: buffer size is always greater than 96
        let crypto = unsafe {
            let rx_key = nonce.as_ptr().offset(0) as *const [u8; 32];
            let rx_ctr = nonce.as_ptr().offset(64) as *const [u8; 16];

            let tx_key = nonce.as_ptr().offset(32) as *const [u8; 32];
            let tx_ctr = nonce.as_ptr().offset(80) as *const [u8; 16];

            Self {
                cipher_receive: build_cipher(&*rx_key, &*rx_ctr),
                cipher_send: build_cipher(&*tx_key, &*tx_ctr),
            }
        };

        (crypto, nonce)
    }

    fn pack(&mut self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;

        let nonce: [u8; 32] = rand::thread_rng().gen();

        let data_len = data.len();
        let mut result = Vec::with_capacity(data_len + 68);
        result.extend(&((data_len + 64) as u32).to_le_bytes());
        result.extend(&nonce);
        result.extend(data);

        let checksum = sha2::Sha256::digest(&result[4..]);
        result.extend(checksum.as_slice());

        self.cipher_send.apply_keystream(result.as_mut());
        result
    }

    fn unpack_init_packet(&mut self, data: &mut [u8]) {
        self.cipher_receive.apply_keystream(data);
    }

    fn unpack_length(&mut self, data: &[u8]) -> usize {
        let mut len = [data[0], data[1], data[2], data[3]];
        self.cipher_receive.apply_keystream(len.as_mut());
        u32::from_le_bytes(len) as usize
    }

    fn unpack_payload<'a>(&mut self, length: usize, data: &'a mut [u8]) -> Option<&'a [u8]> {
        use sha2::Digest;

        const NONCE_LEN: usize = 32;
        const CHECKSUM_LEN: usize = 32;

        let checksum_begin = length - CHECKSUM_LEN;

        self.cipher_receive.apply_keystream(data);

        let checksum = sha2::Sha256::digest(&data[..checksum_begin]);
        if checksum.as_slice() == &data[checksum_begin..length] {
            Some(&data[NONCE_LEN..checksum_begin])
        } else {
            None
        }
    }
}

fn build_adnl_handshake_packet(buffer: &[u8], local: &LocalKey, other: &ExternalKey) -> Vec<u8> {
    use sha2::Digest;

    let checksum = sha2::Sha256::digest(buffer);

    let data_len = buffer.len();
    let mut result = Vec::with_capacity(data_len + 96);
    result.extend(other.id.inner());
    result.extend(&local.public_key);
    result.extend(checksum.as_slice());
    result.extend(buffer);

    let shared_secret = calculate_shared_secret(&local.private_key, &other.public_key);
    build_packet_cipher(&shared_secret, checksum.as_ref()).apply_keystream(&mut result[96..]);
    result
}

#[derive(Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
struct KeyId([u8; 32]);

impl KeyId {
    pub fn new(buffer: &[u8; 32]) -> Self {
        Self(*buffer)
    }

    pub fn inner(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug)]
struct LocalKey {
    id: KeyId,
    public_key: [u8; 32],
    private_key: [u8; 64],
}

impl LocalKey {
    fn generate<T>(rng: &mut T) -> Self
    where
        T: CryptoRng + RngCore,
    {
        Self::from_ed25519_secret_key(&ed25519_dalek::SecretKey::generate(rng))
    }

    fn from_ed25519_secret_key(private_key: &ed25519_dalek::SecretKey) -> Self {
        Self::from_ed25519_expanded_secret_key(&ed25519_dalek::ExpandedSecretKey::from(private_key))
    }

    fn from_ed25519_expanded_secret_key(
        expended_secret_key: &ed25519_dalek::ExpandedSecretKey,
    ) -> Self {
        let public_key = ed25519_dalek::PublicKey::from(expended_secret_key).to_bytes();

        Self {
            id: calculate_id(KEY_ED25519, &public_key),
            public_key,
            private_key: expended_secret_key.to_bytes(),
        }
    }
}

#[derive(Debug)]
pub struct ExternalKey {
    id: KeyId,
    public_key: [u8; 32],
}

impl ExternalKey {
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self {
            id: calculate_id(KEY_ED25519, public_key),
            public_key: *public_key,
        }
    }
}

fn calculate_id(type_id: i32, pub_key: &[u8; 32]) -> KeyId {
    use sha2::Digest;

    let mut buffer = sha2::Sha256::new();
    buffer.update(&type_id.to_le_bytes());
    buffer.update(pub_key);
    KeyId::new(buffer.finalize_fixed().as_ref())
}

fn calculate_shared_secret(private_key: &[u8; 64], public_key: &[u8; 32]) -> [u8; 32] {
    let point = curve25519_dalek::edwards::CompressedEdwardsY(*public_key)
        .decompress()
        .expect("Invalid public key")
        .to_montgomery()
        .to_bytes();

    let mut buffer = [0; 32];
    buffer.copy_from_slice(&private_key[..32]);
    x25519_dalek::x25519(buffer, point)
}

fn build_packet_cipher(shared_secret: &[u8; 32], checksum: &[u8; 32]) -> aes_ctr::Aes256Ctr {
    let mut aes_key_bytes = [0; 32];
    aes_key_bytes[..16].copy_from_slice(&shared_secret[..16]);
    aes_key_bytes[16..].copy_from_slice(&checksum[16..]);

    let mut aes_ctr_bytes = [0; 16];
    aes_ctr_bytes[..4].copy_from_slice(&checksum[..4]);
    aes_ctr_bytes[4..].copy_from_slice(&shared_secret[20..]);

    build_cipher(&aes_key_bytes, &aes_ctr_bytes)
}

fn build_cipher(key: &[u8; 32], ctr: &[u8; 16]) -> aes_ctr::Aes256Ctr {
    use aes_ctr::cipher::NewStreamCipher;
    aes_ctr::Aes256Ctr::new(key.into(), ctr.into())
}

pub const KEY_ED25519: i32 = 1209251014;
