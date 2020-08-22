pub(crate) mod bpf;
pub(crate) mod error;
pub(crate) mod exec_logger;
pub mod output;

pub use crate::error::Error;
pub use crate::exec_logger::{Arg, ExecLogger, ExecLoggerOpts, Return, RunningExecLogger};

pub type Result<T> = std::result::Result<T, Error>;