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

use log::debug;
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;

use crate::output::Output;
use crate::{bpf, Error, Result};
use std::time::Duration;

#[derive(Debug)]
pub enum Event {
    Arg(Arg),
    Return(Return),
}

#[derive(Debug)]
pub struct Arg {
    pub(crate) pid: u32,
    pub(crate) argv: String,
}

#[derive(Debug)]
pub struct Return {
    pub pid: u32,
    pub ppid: u32,
    pub ancestor: bool,
    pub comm: String,
    pub tty: String,
    pub uid: u32,
    pub gid: u32,
    pub ret_val: i32,
}

impl From<bpf::Event> for Event {
    fn from(event: bpf::Event) -> Self {
        match event.r#type {
            bpf::EventType::EVENT_ARG => Event::Arg(Arg {
                pid: event.pid,
                argv: bpf::parse_string(&event.argv),
            }),
            bpf::EventType::EVENT_RET => Event::Return(Return {
                pid: event.pid,
                ppid: event.ppid,
                ancestor: event.ancestor != 0,
                comm: bpf::parse_string(&event.comm),
                tty: bpf::parse_string(&event.tty),
                uid: event.uid,
                gid: event.gid,
                ret_val: event.ret_val,
            }),
        }
    }
}

#[derive(Debug)]
pub struct ExecLoggerOpts {
    pub quiet: bool,
    pub max_args: u32,
    pub ancestor_name: String,
    pub max_ancestors: u32,
    pub interval_ms: u32,
}

impl Default for ExecLoggerOpts {
    fn default() -> Self {
        ExecLoggerOpts {
            quiet: false,
            max_args: 20,
            ancestor_name: "sshd".to_string(),
            max_ancestors: 20,
            interval_ms: 200,
        }
    }
}

#[derive(Debug)]
pub struct ExecLogger<T: Output + Send + 'static> {
    runnable: Arc<AtomicBool>,
    opts: ExecLoggerOpts,
    output: T,
}

impl<T: Output + Send + 'static> ExecLogger<T> {
    pub fn new(opts: ExecLoggerOpts, output: T) -> Self {
        let runnable = Arc::new(AtomicBool::new(true));
        ExecLogger { runnable, opts, output }
    }

    pub fn run(mut self) -> Result<RunningExecLogger> {
        if !self.opts.quiet {
            self.output.header()?;
        }

        let output = Arc::new(Mutex::new(self.output));

        let handler = move |event: bpf::Event| {
            let event: Event = event.into();
            let mut output = output.lock().unwrap();
            match event {
                Event::Arg(a) => {
                    debug!("Entry/Arg event: {:?}", a);
                    output.arg(a).unwrap()
                }
                Event::Return(r) => {
                    debug!("Return event: {:?}", r);
                    output.ret(r).unwrap()
                }
            }
        };

        let kprobe_opts = bpf::KProbeOpts {
            max_args: self.opts.max_args,
            ancestor_name: self.opts.ancestor_name.clone(),
            max_ancestors: self.opts.max_ancestors,
            interval_ms: self.opts.interval_ms,
        };
        let kprobe = bpf::KProbe::new(self.runnable.clone(), handler, kprobe_opts);

        let thread_name = format!("{}-logging", env!("CARGO_PKG_NAME"));
        let thread = thread::Builder::new().name(thread_name);
        let join_handle = thread.spawn(move || {
            debug!("Started logging thread");
            kprobe.run()
        })?;

        Ok(RunningExecLogger::new(self.runnable, join_handle))
    }
}

#[derive(Debug)]
pub struct RunningExecLogger {
    runnable: Arc<AtomicBool>,
    join_handle: JoinHandle<Result<()>>,
}

impl RunningExecLogger {
    pub fn new(runnable: Arc<AtomicBool>, join_handle: JoinHandle<Result<()>>) -> RunningExecLogger {
        RunningExecLogger { runnable, join_handle }
    }

    pub fn stopper(&self) -> Arc<AtomicBool> {
        self.runnable.clone()
    }

    pub fn wait(self) -> Result<()> {
        self.join_handle.join().map_err(|_| Error::RunTimeError {
            msg: "failed to synchronize with logging thread",
        })?
    }

    pub fn wait_n_stop(self, time: Duration) -> Result<()> {
        thread::sleep(time);
        self.runnable.stop();
        self.join_handle.join().map_err(|_| Error::RunTimeError {
            msg: "failed to synchronize with logging thread",
        })?
    }
}

pub trait Stopper {
    fn stop(&self);
}

impl Stopper for Arc<AtomicBool> {
    fn stop(&self) {
        self.store(false, Ordering::SeqCst);
    }
}
