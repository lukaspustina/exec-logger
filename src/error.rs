use thiserror::Error;

#[derive(Debug, Error)]
/// Main Error type of this crate.
///
/// Must be `Send` because it used by async function which might run on different threads.
pub enum Error {
    #[error("BCC error")]
    BccError {
        #[from]
        source: bcc::BccError,
    },
    #[error("IO error")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("run time error because {msg}")]
    RunTimeError {
        msg: &'static str,
    },
}