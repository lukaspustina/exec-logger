use anyhow::{Result, Context};
use exec_logger::{ExecLogger, Stopper};
use log::{debug, info};
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
}

impl ExitStatus {
    fn exit(self) {
        std::process::exit(self as i32);
    }
}

fn main() {
    start_logging();

    match run() {
        Ok(_) => ExitStatus::Ok,
        Err(err) => {
            eprintln!("Failed: {:?}", err);
            ExitStatus::Failed
        }
    }.exit();
}

fn start_logging() {
    let start = std::time::Instant::now();
    env_logger::Builder::from_default_env()
        .format(move |buf, rec| {
            let t = start.elapsed().as_secs_f32();
            let thread_id_string = format!("{:?}", std::thread::current().id());
            let thread_id = &thread_id_string[9..thread_id_string.len() - 1];
            writeln!(buf, "{:.03} [{:5}] ({:}) - {}", t, rec.level(), thread_id, rec.args())
        })
        .init();
}

fn run() -> Result<()> {
    let stdout = io::stdout();
    let output_opts = TableOutputOpts::new(stdout);
    let mut output = TableOutput::new(output_opts);
    output.header()?;

    let opts = Default::default();
    let logger = ExecLogger::new(opts, output).run()
        .context("Failed to run logger")?;
    info!("Running.");

    let stopper = logger.stopper();
    ctrlc::set_handler(move || {
        debug!("Ctrl-C-Handler activated");
        stopper.stop();
    }).context("Failed to set handler for SIGINT / SIGTERM")?;

    info!("Waiting for event loop to finish.");
    logger.wait()?;
    info!("Finished.");

    Ok(())
}
