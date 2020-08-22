use thiserror::Error;

#[derive(Debug, Error)]
/// Main Error type of this crate.
///
/// Must be `Send` because it used by async function which might run on different threads.
pub enum Error {
    #[error("BCC failed")]
    BccError {
        #[from]
        source: bcc::BccError,
    },
    #[error("IO failed")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("logging thread failed")]
    ThreadError,
}