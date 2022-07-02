use super::LANGUAGE;

pub fn get_hints(prefix: &str) -> &[&'static str] {
    let wordlist = LANGUAGE.wordlist();
    wordlist.get_words_by_prefix(prefix)
}
