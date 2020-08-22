use anyhow::{Result, Context};
use exec_logger::ExecLogger;
use log::{error, info};
use std::cell::Cell;
use std::io::{self, Write};
use exec_logger::output::{TableOutput, TableOutputOpts, Output};

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

impl ExitStatus {
    fn exit(self) {
        std::process::exit(self as i32);
    }
}

fn run() -> Result<ExitStatus> {
    let stdout = io::stdout();
    let output_opts = TableOutputOpts::new(stdout);
    let mut output = TableOutput::new(output_opts);
    output.header()?;

    let opts = Default::default();
    let logger = ExecLogger::new(opts, output).run()
        .context("Failed to run logger")?;
    let waiter = logger.waiter();
    let logger_cell = Cell::new(Some(logger));

    ctrlc::set_handler(move || {
        info!("Ctrl-C-Handler activated");
        let res = logger_cell.replace(None).unwrap().stop(); // Safe unwrap
        shutdown(res);
    }).context("Failed to set handler for SIGINT / SIGTERM")?;
    info!("Running.");
    let _ = waiter.wait();
    // Give the ctrl-c-handler time to clean up
    std::thread::park();

    // Unreachable code
    Ok(ExitStatus::UnrecoverableError)
}

fn shutdown(result: exec_logger::Result<()>) {
    info!("Shutting down.");
    let exit_status = match result {
        Ok(_) => ExitStatus::Ok,
        Err(err) => {
            eprintln!("Failed: {:#?}", err);
            ExitStatus::Failed
        }
    };

    info!("Done.");
    exit_status.exit();
}

fn main() {
    let start = std::time::Instant::now();
    env_logger::Builder::from_default_env()
        .format(move |buf, rec| {
            let t = start.elapsed().as_secs_f32();
            let thread_id_string = format!("{:?}", std::thread::current().id());
            let thread_id = &thread_id_string[9..thread_id_string.len() - 1];
            writeln!(buf, "{:.03} [{:5}] ({:}) - {}", t, rec.level(), thread_id, rec.args())
        })
        .init();

    let _ = run();

    error!("Execution error, this code should never run.");
    ExitStatus::UnrecoverableError.exit();
}