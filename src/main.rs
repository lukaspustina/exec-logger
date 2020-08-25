use anyhow::{Result, Context};
use exec_logger::{ExecLogger, Stopper, ExecLoggerOpts};
use exec_logger::logging;
use exec_logger::output::{TableOutput, TableOutputOpts, Output};
use log::{debug, info};
use std::io;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = env!("CARGO_PKG_NAME"), author = env!("CARGO_PKG_AUTHORS"), about = env!("CARGO_PKG_DESCRIPTION"))]
struct Args {
    /// Sets max number of syscall arguments to parse
    #[structopt(long, default_value = "20")]
    pub max_args: i32,
    /// Sets name of ancestor to filter
    #[structopt(long, default_value = "sshd")]
    pub ancestor: String,
    /// Sets max number ancestors to check for ancestor name
    #[structopt(long, default_value = "20")]
    pub max_ancestors: i32,
    /// Sets max number ancestors to check for ancestor name
    #[structopt(long, default_value = "200")]
    pub interval: i32,
    /// Sets kprobe event polling interval
    #[structopt(short, long)]
    pub quiet: bool,
    /// Sets the level of verbosity
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u64,
}

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
    let args = Args::from_args();
    logging::start_logging_for_level(args.verbose);

    info!("Starting {} version {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    match run(&args) {
        Ok(_) => ExitStatus::Ok,
        Err(err) => {
            eprintln!("Failed: {:?}", err);
            ExitStatus::Failed
        }
    }.exit();
}

fn run(args: &Args) -> Result<()> {
    let stdout = io::stdout();
    let output_opts = TableOutputOpts::new(stdout);
    let mut output = TableOutput::new(output_opts);

    if !args.quiet {
        output.header()?;
    }

    let opts = args.into();
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

impl From<&Args> for ExecLoggerOpts {
    fn from(args: &Args) -> Self {
        ExecLoggerOpts {
            max_args: args.max_args,
            ancestor_name: args.ancestor.clone(),
            max_ancestors: args.max_ancestors,
            interval_ms: args.interval,
        }
    }
}
