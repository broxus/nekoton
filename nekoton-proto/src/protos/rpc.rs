#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    #[prost(oneof = "request::Call", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11")]
    pub call: ::core::option::Option<request::Call>,
}
/// Nested message and enum types in `Request`.
pub mod request {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetContractState {
        #[prost(bytes = "bytes", tag = "1")]
        pub address: ::prost::bytes::Bytes,
        #[prost(uint64, optional, tag = "2")]
        pub last_transaction_lt: ::core::option::Option<u64>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetTransaction {
        #[prost(bytes = "bytes", tag = "1")]
        pub id: ::prost::bytes::Bytes,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetDstTransaction {
        #[prost(bytes = "bytes", tag = "1")]
        pub message_hash: ::prost::bytes::Bytes,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetTransactionsList {
        #[prost(bytes = "bytes", tag = "1")]
        pub account: ::prost::bytes::Bytes,
        #[prost(uint64, optional, tag = "2")]
        pub last_transaction_lt: ::core::option::Option<u64>,
        #[prost(uint32, tag = "3")]
        pub limit: u32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetAccountsByCodeHash {
        #[prost(bytes = "bytes", tag = "1")]
        pub code_hash: ::prost::bytes::Bytes,
        #[prost(bytes = "bytes", optional, tag = "2")]
        pub continuation: ::core::option::Option<::prost::bytes::Bytes>,
        #[prost(uint32, tag = "3")]
        pub limit: u32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SendMessage {
        #[prost(bytes = "bytes", tag = "1")]
        pub message: ::prost::bytes::Bytes,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Call {
        #[prost(message, tag = "1")]
        GetCapabilities(()),
        #[prost(message, tag = "2")]
        GetLatestKeyBlock(()),
        #[prost(message, tag = "3")]
        GetBlockchainConfig(()),
        #[prost(message, tag = "4")]
        GetStatus(()),
        #[prost(message, tag = "5")]
        GetTimings(()),
        #[prost(message, tag = "6")]
        GetContractState(GetContractState),
        #[prost(message, tag = "7")]
        GetTransaction(GetTransaction),
        #[prost(message, tag = "8")]
        GetDstTransaction(GetDstTransaction),
        #[prost(message, tag = "9")]
        GetTransactionsList(GetTransactionsList),
        #[prost(message, tag = "10")]
        GetAccountsByCodeHash(GetAccountsByCodeHash),
        #[prost(message, tag = "11")]
        SendMessage(SendMessage),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    #[prost(oneof = "response::Result", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10")]
    pub result: ::core::option::Option<response::Result>,
}
/// Nested message and enum types in `Response`.
pub mod response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetRawTransaction {
        #[prost(bytes = "bytes", optional, tag = "1")]
        pub transaction: ::core::option::Option<::prost::bytes::Bytes>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetTransactionsList {
        #[prost(bytes = "bytes", repeated, tag = "1")]
        pub transactions: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    }
    #[derive(Eq)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetTimings {
        #[prost(uint32, tag = "1")]
        pub last_mc_block_seqno: u32,
        #[prost(uint32, tag = "2")]
        pub last_shard_client_mc_block_seqno: u32,
        #[prost(uint32, tag = "3")]
        pub last_mc_utime: u32,
        #[prost(int64, tag = "4")]
        pub mc_time_diff: i64,
        #[prost(int64, tag = "5")]
        pub shard_client_time_diff: i64,
        #[prost(uint64, tag = "6")]
        pub smallest_known_lt: u64,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetStatus {
        #[prost(bool, tag = "1")]
        pub ready: bool,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetCapabilities {
        #[prost(string, repeated, tag = "1")]
        pub capabilities: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetLatestKeyBlock {
        #[prost(bytes = "bytes", tag = "1")]
        pub block: ::prost::bytes::Bytes,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetBlockchainConfig {
        #[prost(int32, tag = "1")]
        pub global_id: i32,
        #[prost(bytes = "bytes", tag = "2")]
        pub config: ::prost::bytes::Bytes,
        #[prost(uint32, tag = "3")]
        pub seqno: u32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetAccountsByCodeHash {
        #[prost(bytes = "bytes", repeated, tag = "1")]
        pub account: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GetContractState {
        #[prost(oneof = "get_contract_state::State", tags = "1, 2, 3")]
        pub state: ::core::option::Option<get_contract_state::State>,
    }
    /// Nested message and enum types in `GetContractState`.
    pub mod get_contract_state {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Timings {
            #[prost(uint64, tag = "1")]
            pub gen_lt: u64,
            #[prost(uint32, tag = "2")]
            pub gen_utime: u32,
        }
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct NotExist {
            #[prost(oneof = "not_exist::GenTimings", tags = "2, 3")]
            pub gen_timings: ::core::option::Option<not_exist::GenTimings>,
        }
        /// Nested message and enum types in `NotExist`.
        pub mod not_exist {
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum GenTimings {
                #[prost(message, tag = "2")]
                Known(super::Timings),
                #[prost(message, tag = "3")]
                Unknown(()),
            }
        }
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Exists {
            #[prost(bytes = "bytes", tag = "1")]
            pub account: ::prost::bytes::Bytes,
            #[prost(message, optional, tag = "2")]
            pub gen_timings: ::core::option::Option<Timings>,
            #[prost(oneof = "exists::LastTransactionId", tags = "3, 4")]
            pub last_transaction_id: ::core::option::Option<exists::LastTransactionId>,
        }
        /// Nested message and enum types in `Exists`.
        pub mod exists {
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Exact {
                #[prost(uint64, tag = "1")]
                pub lt: u64,
                #[prost(bytes = "bytes", tag = "2")]
                pub hash: ::prost::bytes::Bytes,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Inexact {
                #[prost(uint64, tag = "1")]
                pub latest_lt: u64,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum LastTransactionId {
                #[prost(message, tag = "3")]
                Exact(Exact),
                #[prost(message, tag = "4")]
                Inexact(Inexact),
            }
        }
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum State {
            #[prost(message, tag = "1")]
            NotExists(NotExist),
            #[prost(message, tag = "2")]
            Exists(Exists),
            #[prost(message, tag = "3")]
            Unchanged(Timings),
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        GetRawTransaction(GetRawTransaction),
        #[prost(message, tag = "2")]
        GetTransactionsList(GetTransactionsList),
        #[prost(message, tag = "3")]
        GetTimings(GetTimings),
        #[prost(message, tag = "4")]
        GetStatus(GetStatus),
        #[prost(message, tag = "5")]
        GetCapabilities(GetCapabilities),
        #[prost(message, tag = "6")]
        GetLatestKeyBlock(GetLatestKeyBlock),
        #[prost(message, tag = "7")]
        GetBlockchainConfig(GetBlockchainConfig),
        #[prost(message, tag = "8")]
        GetAccounts(GetAccountsByCodeHash),
        #[prost(message, tag = "9")]
        GetContractState(GetContractState),
        #[prost(message, tag = "10")]
        SendMessage(()),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Error {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
