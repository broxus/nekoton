use serde::{Deserialize, Serialize, Serializer};

pub trait GqlQuery {
    type Variables: serde::Serialize;
    type ResponseData: for<'de> serde::Deserialize<'de>;

    fn build_query(variables: &'_ Self::Variables) -> QueryBody<'_>;
}

pub struct QueryBody<'a> {
    pub variables: &'a dyn erased_serde::Serialize,
    pub query: &'static str,
}

impl Serialize for QueryBody<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut s = serializer.serialize_struct("QueryBody", 3)?;
        s.serialize_field("variables", self.variables)?;
        s.serialize_field("query", self.query)?;
        s.serialize_field("operationName", &())?;
        s.end()
    }
}

macro_rules! declare_queries {
    ($($query:ident => $query_module:tt),*$(,)?) => {
        $(pub struct $query;

        impl GqlQuery for $query {
            type Variables = $query_module::Variables;
            type ResponseData = $query_module::ResponseData;

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
    QueryNextBlock => query_next_block,
    QueryBlockAfterSplit => query_block_after_split,
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

    pub const QUERY: &str = "query($id:String!){blocks(filter:{id:{eq:$id}},limit:1){boc}}";

    #[derive(Serialize)]
    pub struct Variables {
        pub id: String,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blocks: Vec<QueryBlockBlocks>,
    }

    #[derive(Deserialize)]
    pub struct QueryBlockBlocks {
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

    pub const QUERY: &str = "query($a:String!){accounts(filter:{id:{eq:$a}},limit:1){boc}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "a")]
        pub address: String,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub accounts: Vec<QueryAccountStateAccounts>,
    }

    #[derive(Deserialize)]
    pub struct QueryAccountStateAccounts {
        pub boc: String,
    }
}

pub mod query_account_transactions {
    use super::*;

    pub const QUERY: &str = "query($a:String!,$lt:String!,$l:Int!){transactions(filter:{account_addr:{eq:$a},lt:{le:$lt}},orderBy:[{path:\"lt\",direction:DESC}],limit:$l){boc}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "a")]
        pub address: String,
        #[serde(rename = "lt")]
        pub last_transaction_lt: String,
        #[serde(rename = "l")]
        pub limit: u8,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub transactions: Vec<QueryAccountTransactionsTransactions>,
    }

    #[derive(Deserialize)]
    pub struct QueryAccountTransactionsTransactions {
        pub boc: String,
    }
}

pub mod query_transaction {
    use super::*;

    pub const QUERY: &str = "query($h:String!){transactions(filter:{id:{eq:$h}},limit:1){boc}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "h")]
        pub hash: String,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub transactions: Vec<QueryTransactionTransactions>,
    }

    #[derive(Deserialize)]
    pub struct QueryTransactionTransactions {
        pub boc: String,
    }
}

pub mod query_dst_transaction {
    use super::*;

    pub const QUERY: &str = "query($h:String!){transactions(filter:{in_msg:{eq:$h}},limit:1){boc}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "h")]
        pub hash: String,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub transactions: Vec<QueryTransactionTransactions>,
    }

    #[derive(Deserialize)]
    pub struct QueryTransactionTransactions {
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
        #[serde(rename = "c", skip_serializing_if = "Option::is_none")]
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

    pub const QUERY: &str = "query{blocks(filter:{workchain_id:{eq:-1}},orderBy:[{path:\"seq_no\",direction:DESC}],limit:1){id gen_utime end_lt master{shard_hashes{workchain_id shard descr{root_hash gen_utime end_lt}}}}}";

    pub type Variables = ();

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blocks: Vec<QueryLatestMasterchainBlockBlocks>,
    }

    #[derive(Deserialize)]
    pub struct QueryLatestMasterchainBlockBlocks {
        pub id: String,
        pub gen_utime: f64,
        pub end_lt: String,
        pub master: QueryLatestMasterchainBlockBlocksMaster,
    }

    #[derive(Deserialize)]
    pub struct QueryLatestMasterchainBlockBlocksMaster {
        pub shard_hashes: Vec<QueryLatestMasterchainBlockBlocksMasterShardHashes>,
    }

    #[derive(Deserialize)]
    pub struct QueryLatestMasterchainBlockBlocksMasterShardHashes {
        pub workchain_id: i32,
        pub shard: String,
        pub descr: QueryLatestMasterchainBlockBlocksMasterShardHashesDescr,
    }

    #[derive(Deserialize)]
    pub struct QueryLatestMasterchainBlockBlocksMasterShardHashesDescr {
        pub root_hash: String,
        pub gen_utime: f64,
        pub end_lt: String,
    }
}

pub mod query_latest_key_block {
    use super::*;

    pub const QUERY: &str = "query{blocks(filter:{key_block:{eq:true},workchain_id:{eq:-1}},orderBy:[{path:\"seq_no\",direction:DESC}],limit:1){boc}}";

    pub type Variables = ();

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blocks: Vec<QueryLatestKeyBlockBlocks>,
    }

    #[derive(Deserialize)]
    pub struct QueryLatestKeyBlockBlocks {
        pub boc: String,
    }
}

pub mod query_node_se_conditions {
    use super::*;

    pub const QUERY: &str = "query($w:Int!){blocks(filter:{workchain_id:{eq:$w}},orderBy:[{path:\"seq_no\",direction:DESC}],limit:1){after_merge shard}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "w")]
        pub workchain: i32,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blocks: Vec<QueryNodeSeConditionsBlocks>,
    }

    #[derive(Deserialize)]
    pub struct QueryNodeSeConditionsBlocks {
        pub after_merge: bool,
        pub shard: String,
    }
}

pub mod query_node_se_latest_block {
    use super::*;

    pub const QUERY: &str = "query($w:Int!){blocks(filter:{workchain_id:{eq:$w},shard:{eq:\"8000000000000000\"}},orderBy:[{path:\"seq_no\",direction:DESC}],limit:1){id end_lt gen_utime}}";

    #[derive(Serialize)]
    pub struct Variables {
        #[serde(rename = "w")]
        pub workchain: i32,
    }

    #[derive(Deserialize)]
    pub struct ResponseData {
        pub blocks: Vec<QueryNodeSeLatestBlockBlocks>,
    }

    #[derive(Deserialize)]
    pub struct QueryNodeSeLatestBlockBlocks {
        pub id: String,
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
