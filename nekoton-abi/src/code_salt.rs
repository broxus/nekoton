use anyhow::Result;
use ton_types::{BuilderData, Cell, SliceData};

pub fn set_code_salt(code: Cell, salt: Cell) -> Result<Cell> {
    let code_data = code
        .data()
        .strip_suffix(&[0x80])
        .unwrap_or_else(|| code.data());
    match code_data {
        OLD_CPP_SELECTOR_DATA => set_old_selector_salt(code, salt),
        NEW_SELECTOR_DATA => set_new_selector_salt(code, salt),
        MYCODE_SELECTOR_DATA => set_mycode_selector_salt(code, salt),
        _ => Err(CodeSaltError::UnsupportedSelector.into()),
    }
}

pub fn get_code_salt(code: Cell) -> Result<Option<Cell>> {
    let code_data = code
        .data()
        .strip_suffix(&[0x80])
        .unwrap_or_else(|| code.data());
    match code_data {
        OLD_CPP_SELECTOR_DATA => get_old_selector_salt(&code),
        OLD_SOL_SELECTOR_DATA => Ok(None),
        NEW_SELECTOR_DATA => get_new_selector_salt(&code),
        MYCODE_SELECTOR_DATA => get_mycode_selector_salt(&code),
        _ => Err(CodeSaltError::UnsupportedSelector.into()),
    }
}

fn set_salt(code: Cell, salt: Cell, replace_last_ref: bool) -> Result<Cell> {
    let mut builder: BuilderData = code.into();
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

fn get_new_selector_salt(code: &Cell) -> Result<Option<Cell>> {
    let mut private_selector: SliceData = code.reference(0)?.into();
    if private_selector.get_next_bits(13).ok() != Some(vec![0xf4, 0xa0]) {
        return Err(CodeSaltError::InvalidSelector.into());
    }
    private_selector.get_dictionary_opt();
    Ok(private_selector.reference_opt(1))
}

fn set_new_selector_salt(code: Cell, salt: Cell) -> Result<Cell> {
    let private_selector = code.reference(0)?;

    let private_selector = set_salt(
        private_selector,
        salt,
        get_new_selector_salt(&code)?.is_some(),
    )?;

    let mut builder: BuilderData = code.into();
    builder.replace_reference_cell(0, private_selector);
    builder.into_cell()
}

fn get_mycode_selector_salt(code: &Cell) -> Result<Option<Cell>> {
    let new_selector = code
        .reference(1)
        .map_err(|_| CodeSaltError::NewMycodeSelectorNotFound)?;
    get_new_selector_salt(&new_selector)
}

fn set_mycode_selector_salt(code: Cell, salt: Cell) -> Result<Cell> {
    let new_selector = code
        .reference(1)
        .map_err(|_| CodeSaltError::NewMycodeSelectorNotFound)?;
    let new_selector = set_new_selector_salt(new_selector, salt)?;

    let mut builder: BuilderData = code.into();
    builder.replace_reference_cell(1, new_selector);
    builder.into_cell()
}

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

#[derive(thiserror::Error, Debug)]
enum CodeSaltError {
    #[error("Unsupported selector")]
    UnsupportedSelector,
    #[error("Invalid selector")]
    InvalidSelector,
    #[error("No new selector in MYCODE selector")]
    NewMycodeSelectorNotFound,
}
