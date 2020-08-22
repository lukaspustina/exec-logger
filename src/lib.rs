mod bpf;
mod error;
mod exec_logger;

pub use crate::error::Error;
pub use crate::exec_logger::{ExecLogger, ExecLoggerArgs};

pub type Result<T> = std::result::Result<T, Error>;