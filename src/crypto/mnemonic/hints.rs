use super::legacy::TON_WORDS;

pub fn get_hints(input: &str) -> Vec<String> {
    TON_WORDS
        .iter()
        .filter(|x| x.starts_with(input))
        .map(|x| x.to_string())
        .collect()
}
