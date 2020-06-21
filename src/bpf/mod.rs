use bcc::{
    core::BPF,
    perf::{init_perf_map, PerfMap},
};
use failure::Error;
use std::{
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum EventType {
    EVENT_ARG,
    EVENT_RET,
}

#[repr(C)]
pub struct Event {
    pub pid:    libc::c_int,
    pub ppid:   libc::c_int,
    pub comm:   [u8; 16], // TASK_COMM_LEN, cf. execsnoop.c
    pub r#type: EventType,
    pub argv:   [u8; 128], // ARGSIZE, cf. execsnoop.c
    pub tty:    [u8; 64],  // TTYSIZE, cf. execsnoop.c
    pub uid:    libc::c_int,
    pub gid:    libc::c_int,
    pub ret:    libc::c_int,
}

impl From<&[u8]> for Event {
    fn from(bytes: &[u8]) -> Self { parse_struct(bytes) }
}

pub struct KProbe<F: FnOnce(Event) -> () + Clone + std::marker::Send + 'static> {
    runnable: Arc<AtomicBool>,
    handler:  F,
    args:     KProbeArgs,
}

impl<F: FnOnce(Event) -> () + Clone + std::marker::Send + 'static> KProbe<F> {
    pub fn new(runnable: Arc<AtomicBool>, handler: F, args: KProbeArgs) -> Self {
        KProbe {
            runnable,
            handler,
            args,
        }
    }

    pub fn run(self) -> Result<(), Error> {
        let handler = create_handler(self.handler);
        // It is important, to keep bpf in scope while running the event_loop. Otherwise it gets
        // dropped and we loose the connection to our kprobe
        let bpf = load_bpf(&self.args)?;

        // create events table
        let table = bpf.table("events");
        let perf_map = init_perf_map(table, handler)?;

        event_loop(self.runnable, perf_map)
    }
}

pub struct KProbeArgs {
    pub max_args: i32,
}

impl Default for KProbeArgs {
    fn default() -> Self { KProbeArgs { max_args: 20 } }
}

impl KProbeArgs {
    fn max_args_key(&self) -> &'static str { "MAXARGS" }

    fn max_args_value(&self) -> String { self.max_args.to_string() }
}

fn load_bpf(args: &KProbeArgs) -> Result<BPF, Error> {
    // load and parameterize BPF
    let code = include_str!("execsnoop.c");
    let code = code.replace(args.max_args_key(), &args.max_args_value());
    // compile the above BPF code!
    let mut module = BPF::new(&code)?;
    // load + attach kprobes!
    let entry_probe = module.load_kprobe("syscall__execve")?;
    let return_probe = module.load_kprobe("do_ret_sys_execve")?;
    module.attach_kprobe("sys_execve", entry_probe)?;
    module.attach_kretprobe("sys_execve", return_probe)?;

    Ok(module)
}

fn event_loop(runnable: Arc<AtomicBool>, mut perf_map: PerfMap) -> Result<(), Error> {
    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
    }
    Ok(())
}

type HandlerGenerator = Box<dyn Fn() -> Box<dyn FnMut(&[u8]) + Send>>;

fn create_handler<F>(handler: F) -> HandlerGenerator
where
    F: FnOnce(Event) -> () + Clone + std::marker::Send + 'static,
{
    Box::new(move || {
        let handler = handler.clone();
        Box::new(move |x| {
            let h = handler.clone();
            let event = x.into();
            h(event)
        })
    })
}

pub fn parse_struct<T>(buf: &[u8]) -> T { unsafe { ptr::read(buf.as_ptr() as *const T) } }

pub fn parse_string(buf: &[u8]) -> String {
    // Search has to start from the front, so we find the _first_ 0 in order to prevent
    // reading invalid memory
    match buf.iter().position(|&x| x == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&buf[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(buf).to_string(),
    }
}
