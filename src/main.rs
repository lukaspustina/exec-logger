use core::sync::atomic::{AtomicBool, Ordering};
use exec_logger::ExecLogger;
use std::sync::Arc;

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    let args = Default::default();
    let exec_logger = ExecLogger::new(runnable, args);
    if let Err(err) = exec_logger.run() {
        eprintln!("Error: {}", err);
        eprintln!("{}", err.backtrace());
        std::process::exit(1);
    }
}
