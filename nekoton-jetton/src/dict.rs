use std::collections::HashMap;

use ton_types::{HashmapType, SliceData, UInt256};

pub type SnakeFormatDict = HashMap<UInt256, Vec<u8>>;

pub fn load_dict_snake_format(slice: &mut SliceData) -> anyhow::Result<SnakeFormatDict> {
    let content_dict = slice.get_dictionary()?.reference_opt(0);
    let content_map = ton_types::HashmapE::with_hashmap(32 * 8, content_dict);

    let mut dict = HashMap::with_capacity(content_map.len().unwrap());
    for item in content_map.iter() {
        let (k, v) = item.unwrap();

        // Load value
        if let Some(cell) = v.reference_opt(0) {
            let buffer = parse_snake_data(cell).unwrap();
            dict.insert(UInt256::from_slice(k.data()), buffer);
        }
    }

    Ok(dict)
}

fn parse_snake_data(cell: ton_types::Cell) -> anyhow::Result<Vec<u8>> {
    let mut buffer = vec![];

    let mut cell = cell;
    let mut first_cell = true;
    loop {
        let mut slice_data = SliceData::load_cell_ref(&cell)?;
        if first_cell {
            let first_byte = slice_data.get_next_byte()?;

            if first_byte != 0 {
                anyhow::bail!("Invalid snake format")
            }
        }

        buffer.extend(slice_data.remaining_data().data());
        match slice_data.remaining_references() {
            0 => return Ok(buffer),
            1 => {
                cell = cell.reference(0)?;
                first_cell = false;
            }
            n => {
                anyhow::bail!("Invalid snake format string: found cell with {n} references")
            }
        }
    }
}
