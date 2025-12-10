# nekoton &emsp; [![Workflow badge]][workflow] [![License Apache badge]][license apache] [![Docs badge]][docs]

## About

Broxus SDK with TIP3 wallets support and a bunch of helpers.

### Prerequisites

- Rust 1.65+
- `wasm-pack` 0.9.1+ (to test build for wasm target)
- protoc 3.12.4+ (to generate .rs files from .proto)

### Modifying protobuffers

Occasionally, you may need to change the `.proto` files that define request/response
data format. In this case, you will need to add a few steps to the above
workflow.

- Install the `protoc` compiler.
- Run `cargo run -p gen-protos` regularly (or after every edit to a `.proto`
  file).  The `gen-protos` binary will use the `prost-build` library to compile the
  `.proto` files into `.rs` files.
- If you are adding a new `.proto` file, you will need to edit the list of
  these files in `gen-protos/src/main.rs`.

The `.rs` files generated from `.proto` files are included in the repository,
and there is a Github CI check that will complain if they do not match.

## Contributing

We welcome contributions to the project! If you notice any issues or errors, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [License Apache].

[workflow badge]: https://img.shields.io/github/actions/workflow/status/broxus/nekoton/master.yml?branch=master
[workflow]: https://github.com/broxus/nekoton/actions?query=workflow%3Amaster
[license apache badge]: https://img.shields.io/github/license/broxus/nekoton
[license apache]: https://opensource.org/licenses/Apache-2.0
[docs badge]: https://img.shields.io/badge/docs-latest-brightgreen
[docs]: https://broxus.github.io/nekoton
