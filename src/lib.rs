pub mod bpf;
pub mod error;
pub mod exec_logger;
pub mod logging;
pub mod output;

pub use crate::error::Error;
pub use crate::exec_logger::{Arg, ExecLogger, ExecLoggerOpts, Return, RunningExecLogger, Stopper};

pub type Result<T> = std::result::Result<T, Error>;
