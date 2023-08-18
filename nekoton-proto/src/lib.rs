pub mod rpc {
    include!(concat!(env!("OUT_DIR"), "/rpc.rs"));
}

pub mod models;
pub mod utils;

pub use prost;
