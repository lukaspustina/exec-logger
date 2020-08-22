use anyhow::Result;
use exec_logger::ExecLogger;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Debug, Clone)]
pub enum ExitStatus {
    /// All fine.
    Ok = 0,
    /// CLI argument parsing failed.
    CliParsingFailed = 1,
    /// Execution failed,
    Failed = 2,
    /// An unrecoverable error occurred. This is worst case and should not happen.
    UnrecoverableError = 3,
}

fn run() -> Result<ExitStatus> {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    let args = Default::default();
    let exec_logger = ExecLogger::new(runnable, args);

    match exec_logger.run() {
        Ok(_) => Ok(ExitStatus::Ok),
        Err(e) => Err(e.into()),
    }
}

fn main() {
    let exit_status = match run() {
        Ok(exit_status) => exit_status,
        Err(err) => {
            eprintln!("Failed: {:#}", err);
            ExitStatus::Failed
        }
    };

    std::process::exit(exit_status as i32);
}