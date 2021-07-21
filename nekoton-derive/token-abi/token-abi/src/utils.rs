use crate::symbol::ABI;

pub fn is_abi(attrs: &[syn::Attribute]) -> bool {
    for attr in attrs {
        if attr.path.segments.len() == 1 && attr.path.segments[0].ident == ABI {
            return true;
        }
    }

    false
}
