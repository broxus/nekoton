#[test]
fn tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/enum.rs");
    t.pass("tests/known_param_type.rs");
    t.pass("tests/map.rs");
    t.pass("tests/pack_with.rs");
    t.pass("tests/plain_struct.rs");
    t.pass("tests/struct.rs");
    t.pass("tests/types.rs");
    t.pass("tests/unpack_with.rs");
    t.pass("tests/vec.rs");
}
