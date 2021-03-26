use thiserror::Error;

#[derive(Error)]
enum TvmError {
    tvm_execution_failed(),
}
