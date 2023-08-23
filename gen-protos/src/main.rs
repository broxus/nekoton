use std::io::Result;
use std::path::Path;

fn main() -> Result<()> {
    let input = ["rpc.proto"];

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let protos_dir = root.join("nekoton-proto").join("src").join("protos");

    prost_build::Config::new()
        .out_dir(&protos_dir)
        .include_file("mod.rs")
        // For old protoc versions. 3.12.4 needs this, but 3.21.12 doesn't.
        .protoc_arg("--experimental_allow_proto3_optional")
        // Replace Vec<u8> to Bytes
        .bytes(["."])
        // Add EQ macro
        .type_attribute("rpc.Response.GetTimings", "#[derive(Eq)]")
        .compile_protos(
            &input
                .into_iter()
                .map(|x| protos_dir.join(x))
                .collect::<Vec<_>>(),
            &[protos_dir],
        )
}
