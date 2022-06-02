use anyhow::Result;
use serde::{Deserialize, Serialize};
use ton_types::{BuilderData, Cell, SliceData};

const OLD_CPP_SELECTOR_DATA: &[u8] = &[
    0xff, 0x00, 0x20, 0xc1, 0x01, 0xf4, 0xa4, 0x20, 0x58, 0x92, 0xf4, 0xa0, 0xe0, 0x5f, 0x02, 0x8a,
    0x20, 0xed, 0x53, 0xd9,
];
const OLD_SOL_SELECTOR_DATA: &[u8] = &[
    0xff, 0x00, 0xf4, 0xa4, 0x20, 0x22, 0xc0, 0x01, 0x92, 0xf4, 0xa0, 0xe1, 0x8a, 0xed, 0x53, 0x58,
    0x30, 0xf4, 0xa1,
];
const NEW_SELECTOR_DATA: &[u8] = &[
    0x8a, 0xed, 0x53, 0x20, 0xe3, 0x03, 0x20, 0xc0, 0xff, 0xe3, 0x02, 0x20, 0xc0, 0xfe, 0xe3, 0x02,
    0xf2, 0x0b,
];
const MYCODE_SELECTOR_DATA: &[u8] = &[0x8A, 0xDB, 0x35];

pub fn set_cell_salt(salt: Cell, cell: Cell) -> Result<Cell> {
    let code_data = cell.data().strip_suffix(&[0x80]).unwrap_or(cell.data());
    let cell = match code_data {
        OLD_CPP_SELECTOR_DATA => set_old_selector_salt(cell, salt),
        NEW_SELECTOR_DATA => set_new_selector_salt(cell, salt),
        MYCODE_SELECTOR_DATA => set_mycode_selector_salt(cell, salt),
        OLD_SOL_SELECTOR_DATA => Err(anyhow::Error::msg(
            "the contract doesn't support salt adding",
        )),
        _ => Err(anyhow::Error::msg("unknown contract type")),
    }?;

    let b64_cell = base64::encode(&ton_types::cells_serialization::serialize_toc(&cell)?);
    println!("{}", b64_cell);
    Ok(cell)
}

fn set_salt(cell: Cell, salt: Cell, replace_last_ref: bool) -> Result<Cell> {
    let mut builder: BuilderData = cell.into();
    if replace_last_ref {
        builder.replace_reference_cell(builder.references_used() - 1, salt);
    } else {
        builder.checked_append_reference(salt)?;
    }
    builder.into_cell()
}

fn set_old_selector_salt(code: Cell, salt: Cell) -> Result<Cell> {
    let salt_present = get_old_selector_salt(&code)?.is_some();
    set_salt(code, salt, salt_present)
}

fn get_old_selector_salt(code: &Cell) -> Result<Option<Cell>> {
    Ok(code.reference(2).ok())
}

fn get_new_selector_salt_and_ver(code: &Cell) -> Result<(Option<Cell>, Cell)> {
    let mut private_selector: SliceData = code.reference(0)?.into();
    if private_selector.get_next_bits(13).ok() != Some(vec![0xf4, 0xa0]) {
        return Err(anyhow::Error::msg(
            "invalid private functions selector data",
        ));
    }
    private_selector.get_dictionary_opt();
    let version = private_selector
        .reference_opt(0)
        .ok_or_else(|| anyhow::Error::msg("no compiler version in contract code"))?;
    Ok((private_selector.reference_opt(1), version))
}

fn set_new_selector_salt(code: Cell, salt: Cell) -> Result<Cell> {
    let private_selector = code.reference(0)?;

    let private_selector = set_salt(
        private_selector,
        salt,
        get_new_selector_salt_and_ver(&code)?.0.is_some(),
    )?;

    let mut builder: BuilderData = code.into();
    builder.replace_reference_cell(0, private_selector);
    builder.into_cell()
}

fn set_mycode_selector_salt(code: Cell, salt: Cell) -> Result<Cell> {
    let new_selector = code
        .reference(1)
        .map_err(|_| anyhow::Error::msg("no new selector in mycode selector"))?;
    let new_selector = set_new_selector_salt(new_selector, salt)?;

    let mut builder: BuilderData = code.into();
    builder.replace_reference_cell(1, new_selector);
    builder.into_cell()
}

// fn deserialize_cell_from_base64(b64: &str) -> Result<Cell> {
//     let bytes = base64::decode(&b64)?;
//     let mut bytes = bytes.as_slice();
//     let cell = ton_types::cells_serialization::deserialize_tree_of_cells(&mut bytes)?;
//     Ok(cell)
// }

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct ResultOfSetCodeSalt {
    pub code: String,
}
