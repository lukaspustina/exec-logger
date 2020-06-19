use crate::bpf;
use failure::Error;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

#[derive(Debug)]
enum Event {
    Arg(Arg),
    Return(Return),
}

#[derive(Debug)]
struct Arg {
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

impl ExecLogger {
    pub fn new(runnable: Arc<AtomicBool>, args: ExecLoggerArgs) -> Self { ExecLogger { runnable, args } }

    pub fn run(self) -> Result<(), Error> {
        let v = Arc::new(Mutex::new(Vec::new()));

        let handler = move |event: bpf::Event| {
            let event: Event = event.into();
            let mut v = v.lock().unwrap();
            v.push(1);
            match event {
                Event::Arg(a) => println!("Arg: {}", a.argv),
                Event::Return(r) => println!("{:-16} {:-7}", r.comm, r.pid),
            }
        };

        let kprobe_args = bpf::KProbeArgs {
            max_args: self.args.max_args,
        };
        let kprobe = bpf::KProbe::new(self.runnable, handler, kprobe_args);
        println!("{:-16} {:-7}", "PCOMM", "PID");
        kprobe.run()
    }
}

pub struct ExecLoggerArgs {
    max_args: i32,
}

impl Default for ExecLoggerArgs {
    fn default() -> Self { ExecLoggerArgs { max_args: 20 } }
}
