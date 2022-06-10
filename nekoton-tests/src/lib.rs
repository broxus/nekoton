#[cfg(test)]
pub mod tests {
    use nekoton::core::models::{NftTransaction, TransactionWithData, TransactionsBatchInfo};
    use nekoton::core::nft_wallet::{NftCollection, NftSubscriptionHandler};
    use nekoton::transport::gql::GqlTransport;
    use nekoton_transport::gql::{GqlClient, GqlNetworkSettings};
    use nekoton_utils::SimpleClock;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use ton_block::MsgAddressInt;

    struct TestHandler {}
    impl NftSubscriptionHandler for TestHandler {
        fn on_manager_changed(&self, owner: MsgAddressInt) {
            println!("on_manager_changed called. {:x?}", owner);
        }

        fn on_owner_changed(&self, manager: MsgAddressInt) {
            println!("on_owner_changed called. {:x?}", manager);
        }

        fn on_transactions_found(
            &self,
            transactions: Vec<TransactionWithData<NftTransaction>>,
            batch_info: TransactionsBatchInfo,
        ) {
            println!(
                "on_transactions_found called. {:?}. Batch: {:?}",
                transactions, batch_info
            );
        }
    }

    #[tokio::test]
    async fn test() {
        let owner_adrr = MsgAddressInt::from_str(
            "0:f083b8f9ba4a104eb83731b22bbbd5f30c51a234eaaa891970f4487cc1631d86",
        )
        .unwrap();
        let coll_addr = MsgAddressInt::from_str(
            "0:1665249efff626483cf199b6cb1cac78b719c8e9aaa2ce70123128635b1b05a3",
        )
        .unwrap();

        let client = GqlClient::new(GqlNetworkSettings {
            endpoints: vec![
                "main2.ton.dev".to_string(),
                "main3.ton.dev".to_string(),
                "main4.ton.dev".to_string(),
            ],
            latency_detection_interval: Duration::from_secs(1),
            ..Default::default()
        })
        .unwrap();
        let clock = Arc::new(SimpleClock);
        let transport = Arc::new(GqlTransport::new(client));

        let collection =
            NftCollection::get(clock.clone(), transport.clone(), owner_adrr, coll_addr)
                .await
                .unwrap();

        println!("Collection: {:?}", collection);

        // for index in collection.collection_nft_list() {
        //     let x = Nft::get_by_index_address(
        //         clock.clone(),
        //         transport.clone(),
        //         index,
        //         Arc::new(TestHandler {}),
        //     )
        //     .await
        //     .unwrap();
        //     println!(
        //         "manger:{}, owner:{}, info: {:?}",
        //         x.manager(),
        //         x.owner(),
        //         x.metadata()
        //     )
        // }
    }
}
