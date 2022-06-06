#[cfg(test)]
pub mod tests {
    use nekoton::core::nft_wallet::{Nft, NftCollection};
    use nekoton::external::GqlConnection;
    use nekoton::transport::gql::GqlTransport;
    use nekoton_transport::gql::{GqlClient, GqlNetworkSettings};
    use nekoton_utils::SimpleClock;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use ton_block::MsgAddressInt;

    #[tokio::test]
    async fn test() {
        let owner_adrr = MsgAddressInt::from_str(
            "0:f083b8f9ba4a104eb83731b22bbbd5f30c51a234eaaa891970f4487cc1631d86",
        )
        .unwrap();
        let coll_addr = MsgAddressInt::from_str(
            "0:ae07f6957e10527dc4835402e68e68521eb6477ebf1737b772a79c66c5c62cc7",
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

        // let collection =
        //     NftCollection::get(clock.clone(), transport.clone(), owner_adrr, coll_addr)
        //         .await
        //         .unwrap();
        //
        // for index in collection.collection_nft_list() {
        //     println!("{}", index);
        //     let x = Nft::get_by_index_address(clock.clone(), transport.clone(), index)
        //         .await
        //         .unwrap();
        //     println!(
        //         "manger:{}, owner:{}, info: {:?}",
        //         x.manager(),
        //         x.owner(),
        //         x.metadata()
        //     )
        // }
        //
        // println!("{:?}", collection.collection_nft_list());
    }
}
