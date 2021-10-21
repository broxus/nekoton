pub fn compute_balance_change(transaction: &ton_block::Transaction) -> i128 {
    let mut diff = 0;

    if let Some(in_msg) = transaction
        .in_msg
        .as_ref()
        .and_then(|data| data.read_struct().ok())
    {
        if let ton_block::CommonMsgInfo::IntMsgInfo(header) = in_msg.header() {
            diff += header.value.grams.0 as i128;
        }
    }

    let _ = transaction.out_msgs.iterate(|out_msg| {
        if let ton_block::CommonMsgInfo::IntMsgInfo(header) = out_msg.0.header() {
            diff -= header.value.grams.0 as i128;
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
    let mut total_fees = transaction.total_fees.grams.0;
    if let Some(phase) = &description.action {
        total_fees += phase
            .total_fwd_fees
            .as_ref()
            .map(|grams| grams.0)
            .unwrap_or_default();
        total_fees -= phase
            .total_action_fees
            .as_ref()
            .map(|grams| grams.0)
            .unwrap_or_default();
    };
    total_fees
}
