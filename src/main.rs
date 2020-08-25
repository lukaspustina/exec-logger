// Copyright 2020 Lukas Pustina
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, Result};
use exec_logger::logging;
use exec_logger::output::{JsonLinesOutput, JsonLinesOutputOpts, TableOutput, TableOutputOpts};
use exec_logger::{ExecLogger, ExecLoggerOpts, Stopper};
use log::{debug, info};
use std::io;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = env!("CARGO_PKG_NAME"), author = env!("CARGO_PKG_AUTHORS"), about = env!("CARGO_PKG_DESCRIPTION"))]
struct Args {
    /// Sets max number of syscall arguments to parse
    #[structopt(long, value_name = "NUMBER", default_value = "20")]
    pub max_args: u32,
    /// Sets name of ancestor to filter
    #[structopt(long, value_name = "BINARY NAME", default_value = "sshd")]
    pub ancestor: String,
    /// Sets max number ancestors to check for ancestor name
    #[structopt(long, value_name = "NUMBER", default_value = "20")]
    pub max_ancestors: u32,
    /// Displays only processes with expected ancestor
    #[structopt(long)]
    pub only_ancestor: bool,
    /// Sets event poll timer interval in ms
    #[structopt(long, value_name = "MILLISECONDS", default_value = "200")]
    pub interval: u32,
    /// Sets output format
    #[structopt(long, value_name = "FORMAT  ", default_value = "table", possible_values = &["table", "json"])]
    pub output: String,
    /// Sets numeric output for uid and gid
    #[structopt(short, long)]
    pub numeric: bool,
    /// If set, runs only for set seconds and then terminates
    #[structopt(long, value_name = "SECONDS")]
    pub wait: Option<u64>,
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

    info!(
        "Starting {} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    match run(&args) {
        Ok(_) => ExitStatus::Ok,
        Err(err) => {
            eprintln!("Failed: {:?}", err);
            ExitStatus::Failed
        }
    }
    .exit();
}

fn run(args: &Args) -> Result<()> {
    let opts = args.into();
    let logger = match args.output.to_lowercase().as_str() {
        "json" => {
            debug!("Using JSON Lines output");
            let stdout = io::stdout();
            let output_opts = JsonLinesOutputOpts::new(stdout, args.only_ancestor, args.numeric);
            let output = JsonLinesOutput::new(output_opts);
            ExecLogger::new(opts, output).run()
        }
        _ => {
            debug!("Using table output");
            let stdout = io::stdout();
            let output_opts = TableOutputOpts::new(stdout, args.only_ancestor, args.numeric);
            let output = TableOutput::new(output_opts);
            ExecLogger::new(opts, output).run()
        }
    }
    .context("Failed to run logger")?;

    info!("Running.");

    let stopper = logger.stopper();
    ctrlc::set_handler(move || {
        debug!("Ctrl-C-Handler activated");
        stopper.stop();
    })
    .context("Failed to set handler for SIGINT / SIGTERM")?;

    if let Some(wait) = args.wait {
        info!("Running event loop {} seconds.", wait);
        logger.wait_n_stop(Duration::from_secs(wait))?;
    } else {
        info!("Waiting for event loop to finish.");
        logger.wait()?;
    }
    info!("Finished.");

    Ok(())
}

impl From<&Args> for ExecLoggerOpts {
    fn from(args: &Args) -> Self {
        ExecLoggerOpts {
            quiet: args.quiet,
            max_args: args.max_args,
            ancestor_name: args.ancestor.clone(),
            max_ancestors: args.max_ancestors,
            interval_ms: args.interval,
        }
    }
}
