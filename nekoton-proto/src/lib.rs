pub mod models;
pub mod protos;
pub mod utils;

pub use prost;

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::protos;

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct OldGetBlockchainConfig {
        #[prost(int32, tag = "1")]
        pub global_id: i32,
        #[prost(bytes = "bytes", tag = "2")]
        pub config: ::prost::bytes::Bytes,
    }

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NewqGetBlockchainConfig {
        #[prost(int32, tag = "1")]
        pub global_id: i32,
        #[prost(bytes = "bytes", tag = "2")]
        pub config: ::prost::bytes::Bytes,
        #[prost(uint32, tag = "3")]
        pub seqno: u32,
    }

    #[test]
    fn test() {
        let old = OldGetBlockchainConfig {
            global_id: 1,
            config: vec![1, 2, 3].into(),
        };

        let old_data = old.encode_to_vec();
        let new = NewqGetBlockchainConfig::decode(old_data.as_slice()).unwrap();

        assert_eq!(old.global_id, new.global_id);
        assert_eq!(old.config, new.config);
        assert_eq!(new.seqno, 0);
    }

    #[test]
    fn decode_error() {
        let data = base64::decode("CKeB/v///////wESGE1ldGhvZCBgb3RoZXJgIG5vdCBmb3VuZA==").unwrap();
        let res = protos::rpc::Error::decode(data.as_slice()).unwrap();
        println!("{res:?}");
    }
}
