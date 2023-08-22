fn main() -> std::io::Result<()> {
    let mut prost_build = prost_build::Config::new();

    // Replace Vec<u8> to Bytes
    prost_build.bytes(["."]);

    // Add macro
    prost_build.type_attribute("rpc.Response.GetTimings", "#[derive(Eq)]");

    prost_build.compile_protos(&["src/rpc.proto"], &["src/"])
}
