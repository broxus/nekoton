pub mod token_wallet_contract {
    use ton_abi::{Param, ParamType};

    use crate::utils::declare_function;

    /// Returns the token root address.
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `root: address`
    ///
    pub fn root() -> &'static ton_abi::Function {
        declare_function! {
            name: "root",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("root", ParamType::Address)],
        }
    }

    /// Returns the token wallet balance.
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `balance: uint128`
    ///
    pub fn balance() -> &'static ton_abi::Function {
        declare_function! {
            name: "balance",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("balance", ParamType::Uint(128))],
        }
    }

    /// Returns the token wallet code.
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `walletCode: cell`
    ///
    pub fn wallet_code() -> &'static ton_abi::Function {
        declare_function! {
            name: "walletCode",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("walletCode", ParamType::Cell)],
        }
    }

    /// Called by another token wallet on transfer
    ///
    /// # Type
    /// Internal method
    ///
    /// # Inputs
    /// * `value: uint128` - amount of tokens
    /// * `meta: cell` - additional data (owner or other stuff)
    ///
    pub fn accept_transfer() -> &'static ton_abi::Function {
        declare_function! {
            name: "acceptTransfer",
            inputs: vec![
                Param::new("value", ParamType::Uint(128)),
                Param::new("meta", ParamType::Cell),
            ],
            outputs: Vec::new(),
        }
    }

    /// Called by root token contract on mint
    ///
    /// # Type
    /// Internal method
    ///
    /// # Inputs
    /// * `value: uint128` - amount of tokens
    /// * `meta: cell` - additional data (owner or other stuff)
    ///
    pub fn accept_mint() -> &'static ton_abi::Function {
        declare_function! {
            name: "acceptMint",
            inputs: vec![
                Param::new("value", ParamType::Uint(128)),
                Param::new("meta", ParamType::Cell),
            ],
            outputs: Vec::new(),
        }
    }
}

pub mod root_token_contract {
    use ton_abi::{Param, ParamType};

    use crate::utils::declare_function;

    /// Returns the name of the token - e.g. "MyToken".
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `name: string`
    ///
    pub fn name() -> &'static ton_abi::Function {
        declare_function! {
            name: "name",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("name", ParamType::String)],
        }
    }

    /// Returns the symbol of the token. E.g. "HIX".
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `symbol: string`
    ///
    pub fn symbol() -> &'static ton_abi::Function {
        declare_function! {
            name: "symbol",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("symbol", ParamType::String)],
        }
    }

    /// Returns the number of decimals the token uses - e.g. 8,
    /// means to divide the token amount by 100000000 to get its user representation.
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `decimals: uint8`
    ///
    pub fn decimals() -> &'static ton_abi::Function {
        declare_function! {
            name: "decimals",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("decimals", ParamType::Uint(8))],
        }
    }

    /// Returns the total token supply.
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `totalSupply: string`
    ///
    pub fn total_supply() -> &'static ton_abi::Function {
        declare_function! {
            name: "totalSupply",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("totalSupply", ParamType::Uint(128))],
        }
    }

    /// Returns the token wallet code.
    ///
    /// # Type
    /// Responsible internal method
    ///
    /// # Inputs
    /// * `answerId: uint32` - responsible answer id
    ///
    /// # Outputs
    /// * `walletCode: cell`
    ///
    pub fn wallet_code() -> &'static ton_abi::Function {
        declare_function! {
            name: "walletCode",
            inputs: vec![Param::new("answerId", ParamType::Uint(32))],
            outputs: vec![Param::new("walletCode", ParamType::Cell)],
        }
    }

    /// Called by token wallet on burn
    ///
    /// # Type
    /// Internal method
    ///
    /// # Inputs
    /// * `value: uint128` - amount of tokens
    /// * `meta: cell` - additional data (owner or other stuff)
    ///
    pub fn accept_burn() -> &'static ton_abi::Function {
        declare_function! {
            name: "acceptBurn",
            inputs: vec![
                Param::new("value", ParamType::Uint(128)),
                Param::new("meta", ParamType::Cell),
            ],
            outputs: Vec::new(),
        }
    }
}
