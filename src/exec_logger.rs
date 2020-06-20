use crate::bpf;
use failure::Error;
use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

#[derive(Debug)]
enum Event {
    Arg(Arg),
    Return(Return),
}

#[derive(Debug)]
struct Arg {
    pid: i32,
    argv: String,
}

#[derive(Debug)]
struct Return {
    pid:  i32,
    comm: String,
}

impl From<bpf::Event> for Event {
    fn from(event: bpf::Event) -> Self {
        match event.r#type {
            bpf::EventType::EVENT_ARG => {
                Event::Arg(Arg {
                    pid:  event.pid,
                    argv: bpf::parse_string(&event.argv),
                })
            }
            bpf::EventType::EVENT_RET => {
                Event::Return(Return {
                    pid:  event.pid,
                    comm: bpf::parse_string(&event.comm),
                })
            }
        }
    }
}

pub struct ExecLogger {
    runnable: Arc<AtomicBool>,
    args:     ExecLoggerArgs,
}

trait Output {
    fn header(&self) -> Result<(), Error>;
    fn arg(&self, arg: Arg) -> Result<(), Error>;
    fn ret(&self, ret: Return) -> Result<(), Error>;
}

struct SimpleOutput {
    args: Arc<Mutex<HashMap<i32, Vec<String>>>>,
}

impl SimpleOutput {
    fn new() -> Self { 
        SimpleOutput {
            args: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Output for SimpleOutput {
    fn header(&self) -> Result<(), Error> {
        println!("{:-16} {:-7}", "PCOMM", "PID");
        Ok(())

    }

    fn arg(&self, arg: Arg) -> Result<(), Error> {
        let mut args = self.args.lock().unwrap();
        let value = args.entry(arg.pid).or_insert_with(|| Vec::new());
        value.push(arg.argv);
        Ok(())
    }

    fn ret(&self, ret: Return) -> Result<(), Error> {
        let mut args = self.args.lock().unwrap();
        let value = args.remove(&ret.pid);
        println!("{:?}: {:?}", ret, value);
        Ok(())
    }
}

impl ExecLogger {
    pub fn new(runnable: Arc<AtomicBool>, args: ExecLoggerArgs) -> Self { ExecLogger { runnable, args } }

    pub fn run(self) -> Result<(), Error> {
        let output = SimpleOutput::new();
        output.header()?;
        let output = Arc::new(Mutex::new(output));

        let handler = move |event: bpf::Event| {
            let event: Event = event.into();
            let output = output.lock().unwrap();
            match event {
                Event::Arg(a) => output.arg(a).unwrap(),
                Event::Return(r) => output.ret(r).unwrap(),
            }
        };

        let kprobe_args = bpf::KProbeArgs {
            max_args: self.args.max_args,
        };
        let kprobe = bpf::KProbe::new(self.runnable, handler, kprobe_args);

        kprobe.run()
    }
}

pub struct ExecLoggerArgs {
    max_args: i32,
}

impl Default for ExecLoggerArgs {
    fn default() -> Self { ExecLoggerArgs { max_args: 20 } }
}
