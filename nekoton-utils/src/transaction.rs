pub fn compute_account_lt(transaction: &ton_block::Transaction) -> u64 {
    // TODO: read in_msg and check whether dst has rewrite_pfx
    transaction.lt + 1 + transaction.outmsg_cnt as u64
}

pub fn compute_balance_change(transaction: &ton_block::Transaction) -> i128 {
    let mut diff = 0;

    if let Some(in_msg) = transaction
        .in_msg
        .as_ref()
        .and_then(|data| data.read_struct().ok())
    {
        if let ton_block::CommonMsgInfo::IntMsgInfo(header) = in_msg.header() {
            diff += header.value.grams.as_u128() as i128;
        }
    }

    let _ = transaction.out_msgs.iterate(|out_msg| {
        if let ton_block::CommonMsgInfo::IntMsgInfo(header) = out_msg.0.header() {
            diff -= header.value.grams.as_u128() as i128;
        }
        Ok(true)
    });

    if let Ok(ton_block::TransactionDescr::Ordinary(description)) =
        transaction.description.read_struct()
    {
        diff -= compute_total_transaction_fees(transaction, &description) as i128;
    }

    diff
}

/// Calculate total transaction fee which is charged from the account
pub fn compute_total_transaction_fees(
    transaction: &ton_block::Transaction,
    description: &ton_block::TransactionDescrOrdinary,
) -> u128 {
    let mut total_fees = transaction.total_fees.grams.as_u128();
    if let Some(phase) = &description.action {
        total_fees += phase
            .total_fwd_fees
            .as_ref()
            .map(|grams| grams.as_u128())
            .unwrap_or_default();
        total_fees -= phase
            .total_action_fees
            .as_ref()
            .map(|grams| grams.as_u128())
            .unwrap_or_default();
    };
    if let Some(ton_block::TrBouncePhase::Ok(phase)) = &description.bounce {
        total_fees += phase.fwd_fees.as_u128();
    }
    total_fees
}

#[cfg(test)]
mod tests {
    use ton_block::Deserializable;

    use super::*;

    #[test]
    fn balance_change_for_bounce_tx() {
        let tx = ton_block::Transaction::construct_from_base64("te6ccgECBwEAAXgAA7V7I6v9Bo6UZTcpUTDMPNHomt63V2qkcrrjqlh+9STZH1AAArX2P2tMMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZfQohAAD5gUWEIAwIBAB8ECQ7kyjgBwDAosIMFFhhAAIJykK7Illr6uxbrw8ubQI665xthjXh4i8gNCYQ1k8rJjaSQrsiWWvq7FuvDy5tAjrrnG2GNeHiLyA0JhDWTysmNpAIB4AYEAQHfBQC5WAFkdX+g0dKMpuUqJhmHmj0TW9bq7VSOV1x1Sw/epJsj6wAmfD7CYutxv9bl0y1a1XmYfSoPdQXCpsr6XdmJS4KcONDuLh8ABgosMAAAVr7H7WmIy+hRCH/////AALFoATPh9hMXW43+ty6ZatarzMPpUHuoLhU2V9LuzEpcFOHHACyOr/QaOlGU3KVEwzDzR6Jret1dqpHK646pYfvUk2R9UO5Mo4AGCiwwAABWvsftaYTL6FEIQA==").unwrap();
        let balance_change = compute_balance_change(&tx);
        assert_eq!(balance_change, 0);
    }
}
