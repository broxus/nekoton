use serde::{Deserialize, Serialize};

pub trait GqlQuery {
    type Variables: serde::Serialize;
    type ResponseData: for<'de> serde::Deserialize<'de>;

    const LONG_QUERY: bool = false;

    fn build_query(variables: &'_ Self::Variables) -> QueryBody<'_>;
}

#[derive(Serialize)]
pub struct QueryBody<'a> {
    pub variables: &'a dyn erased_serde::Serialize,
    pub query: &'static str,
}

macro_rules! declare_queries {
    ($($query:ident => $query_module:tt $((LONG_QUERY = $long_query:literal))?),*$(,)?) => {
        $(pub struct $query;

        impl GqlQuery for $query {
            type Variables = $query_module::Variables;
            type ResponseData = $query_module::ResponseData;

            $(const LONG_QUERY: bool = $long_query;)?

            fn build_query(variables: &'_ Self::Variables) -> QueryBody<'_> {
                QueryBody {
                    variables,
                    query: $query_module::QUERY,
                }
            }
        })*
    };
}

declare_queries! {
    QueryBlock => query_block,
    QueryNextBlock => query_next_block (LONG_QUERY = true),
    QueryBlockAfterSplit => query_block_after_split (LONG_QUERY = true),
    QueryAccountState => query_account_state,
    QueryAccountTransactions => query_account_transactions,
    QueryTransaction => query_transaction,
    QueryDstTransaction => query_dst_transaction,
    QueryAccountsByCodeHash => query_accounts_by_code_hash,
    QueryLatestMasterchainBlock => query_latest_masterchain_block,
    QueryLatestKeyBlock => query_latest_key_block,
    QueryNodeSeConditions => query_node_se_conditions,
    QueryNodeSeLatestBlock => query_node_se_latest_block,
    MutationSendMessage => mutation_send_message,
}

pub mod query_block {
    use super::*;

    pub const QUERY: &str = "query($id:String!){blockchain{block(hash:$id){boc}}}";

    #[derive(Serialize)]
    pub struct Variables {
        pub id: String,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub block: Option<Block>,
    }

    #[derive(Deserialize)]
    pub struct Block {
        pub boc: String,
    }
}

pub mod query_next_block {
    use super::*;

    pub const QUERY: &str = "query($id:String!,$t:Float!){blocks(filter:{prev_ref:{root_hash:{eq:$id}},OR:{prev_alt_ref:{root_hash:{eq:$id}}}},timeout:$t){id gen_utime after_split workchain_id shard}}";

    #[derive(Serialize)]
    pub struct Variables {
        pub id: String,
        #[serde(rename = "t")]
        pub timeout: f64,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blocks: Vec<QueryNextBlockBlocks>,
    }

    #[derive(Deserialize)]
    pub struct QueryNextBlockBlocks {
        pub id: String,
        pub after_split: bool,
        pub workchain_id: i32,
        pub shard: String,
    }
}

pub mod query_block_after_split {
    use super::*;

    pub const QUERY: &str = "query($block_id:String!,$prev_id:String!,$t:Float!){blocks(filter:{prev_ref:{root_hash:{eq:$block_id}},OR:{prev_alt_ref:{root_hash:{eq:$prev_id}}}},timeout:$t){id}}";

    #[derive(Serialize)]
    pub struct Variables {
        pub block_id: String,
        pub prev_id: String,
        pub timeout: f64,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blocks: Vec<QueryBlockAfterSplitBlocks>,
    }

    #[derive(Deserialize)]
    pub struct QueryBlockAfterSplitBlocks {
        pub id: String,
    }
}

pub mod query_account_state {
    use super::*;

    pub const QUERY: &str = "query($a:String!){blockchain{account(address:$a){info{boc}}}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "a")]
        pub address: String,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub account: Account,
    }

    #[derive(Deserialize)]
    pub struct Account {
        pub info: AccountInfo,
    }

    #[derive(Deserialize)]
    pub struct AccountInfo {
        pub boc: Option<String>,
    }
}

pub mod query_account_transactions {
    use super::*;

    pub const QUERY: &str = "query($a:String!,$lt:String!,$l:Int!,$o:Boolean){blockchain{account(address:$a){transactions_by_lt(allow_latest_inconsistent_data:true,last:$l,before:$lt,archive:$o){edges{node{boc}}}}}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "a")]
        pub address: String,
        #[serde(rename = "lt")]
        pub last_transaction_lt: String,
        #[serde(rename = "l")]
        pub limit: u8,
        #[serde(rename = "o")]
        pub archive: bool,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub account: Account,
    }

    #[derive(Deserialize)]
    pub struct Account {
        pub transactions_by_lt: Transactions,
    }

    #[derive(Deserialize)]
    pub struct Transactions {
        pub edges: Vec<Edge>,
    }

    #[derive(Deserialize)]
    pub struct Edge {
        pub node: Transaction,
    }

    #[derive(Deserialize)]
    pub struct Transaction {
        pub boc: String,
    }
}

pub mod query_transaction {
    use super::*;

    pub const QUERY: &str = "query($h:String!){blockchain{transaction(hash:$h,archive:$o){boc}}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "h")]
        pub hash: String,
        #[serde(rename = "o")]
        pub archive: bool,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub transaction: Option<Transaction>,
    }

    #[derive(Deserialize)]
    pub struct Transaction {
        pub boc: String,
    }
}

pub mod query_dst_transaction {
    use super::*;

    pub const QUERY: &str =
        "query($h:String!){blockchain{transactions_by_in_msg(msg_hash:$h,archive:$o){boc}}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "h")]
        pub hash: String,
        #[serde(rename = "0")]
        pub archive: bool,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub transactions_by_in_msg: Vec<Transaction>,
    }

    #[derive(Deserialize)]
    pub struct Transaction {
        pub boc: String,
    }
}

pub mod query_accounts_by_code_hash {
    use super::*;

    pub const QUERY: &str = "query($h:String!,$c:String,$l:Int!){accounts(filter:{code_hash:{eq:$h},id:{gt:$c}},orderBy:[{path:\"id\",direction:ASC}],limit:$l){id}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "h")]
        pub code_hash: String,
        #[serde(rename = "c")]
        pub continuation: Option<String>,
        #[serde(rename = "l")]
        pub limit: u8,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub accounts: Vec<QueryAccountsByCodeHashAccounts>,
    }

    #[derive(Deserialize)]
    pub struct QueryAccountsByCodeHashAccounts {
        pub id: String,
    }
}

pub mod query_latest_masterchain_block {
    use super::*;

    pub const QUERY: &str = "query{blockchain{blocks(allow_latest_inconsistent_data:true,workchain:-1,last:1){edges{node{hash gen_utime end_lt master{shard_hashes{workchain_id shard descr{root_hash gen_utime end_lt}}}}}}}}";

    pub type Variables = ();

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub blocks: Blocks,
    }

    #[derive(Deserialize)]
    pub struct Blocks {
        pub edges: Vec<Edge>,
    }

    #[derive(Deserialize)]
    pub struct Edge {
        pub node: Block,
    }

    #[derive(Deserialize)]
    pub struct Block {
        pub hash: String,
        pub gen_utime: f64,
        pub end_lt: String,
        pub master: BlockMaster,
    }

    #[derive(Deserialize)]
    pub struct BlockMaster {
        pub shard_hashes: Vec<ShardHashes>,
    }

    #[derive(Deserialize)]
    pub struct ShardHashes {
        pub workchain_id: i32,
        pub shard: String,
        pub descr: ShardHashesDescr,
    }

    #[derive(Deserialize)]
    pub struct ShardHashesDescr {
        pub root_hash: String,
        pub gen_utime: f64,
        pub end_lt: String,
    }
}

pub mod query_latest_key_block {
    use super::*;

    pub const QUERY: &str = "query{blockchain{key_blocks(allow_latest_inconsistent_data:true,last:1){edges{node{boc}}}}}";

    pub type Variables = ();

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub key_blocks: KeyBlocks,
    }

    #[derive(Deserialize)]
    pub struct KeyBlocks {
        pub edges: Vec<Edge>,
    }

    #[derive(Deserialize)]
    pub struct Edge {
        pub node: Block,
    }

    #[derive(Deserialize)]
    pub struct Block {
        pub boc: String,
    }
}

pub mod query_node_se_conditions {
    use super::*;

    pub const QUERY: &str = "query($w:Int!){blockchain{blocks(allow_latest_inconsistent_data:true,workchain:$w,last:1){edges{node{after_merge shard}}}}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "w")]
        pub workchain: i32,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub blocks: Blocks,
    }

    #[derive(Deserialize)]
    pub struct Blocks {
        pub edges: Vec<Edge>,
    }

    #[derive(Deserialize)]
    pub struct Edge {
        pub node: Block,
    }

    #[derive(Deserialize)]
    pub struct Block {
        pub after_merge: bool,
        pub shard: String,
    }
}

pub mod query_node_se_latest_block {
    use super::*;

    pub const QUERY: &str = r#"query($w:Int!){blockchain{blocks(allow_latest_inconsistent_data:true,workchain:$w,shard:"8000000000000000",last:1){edges{node{hash end_lt gen_utime}}}}}"#;

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "w")]
        pub workchain: i32,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blockchain: BlockchainData,
    }

    #[derive(Deserialize)]
    pub struct BlockchainData {
        pub blocks: Blocks,
    }

    #[derive(Deserialize)]
    pub struct Blocks {
        pub edges: Vec<Edge>,
    }

    #[derive(Deserialize)]
    pub struct Edge {
        pub node: Block,
    }

    #[derive(Deserialize)]
    pub struct Block {
        pub hash: String,
        pub end_lt: String,
        pub gen_utime: f64,
    }
}

pub mod mutation_send_message {
    use super::*;

    pub const QUERY: &str =
        "mutation($id:String!,$boc:String!){postRequests(requests:[{id:$id,body:$boc}])}";

    #[derive(Serialize)]
    pub struct Variables {
        pub id: String,
        pub boc: String,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {}
}
