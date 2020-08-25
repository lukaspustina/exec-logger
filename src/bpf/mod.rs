use crate::Result;
use bcc::{
    perf_event::{init_perf_map, PerfMap},
    BPF,
};
use log::info;
use log::trace;
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
    pub pid: libc::c_int,
    pub ppid: libc::c_int,
    pub ancestor: libc::c_int,
    pub comm: [u8; 16], // TASK_COMM_LEN, cf. exec_logger.c
    pub r#type: EventType,
    pub argv: [u8; 128], // ARGSIZE, cf. exec_logger.c
    pub tty: [u8; 64],   // TTYSIZE, cf. exec_logger.c
    pub uid: libc::c_int,
    pub gid: libc::c_int,
    pub ret: libc::c_int,
}

impl From<&[u8]> for Event {
    fn from(bytes: &[u8]) -> Self {
        parse_struct(bytes)
    }
}

#[allow(clippy::unused_unit)]
pub struct KProbe<F: FnOnce(Event) -> () + Clone + std::marker::Send + 'static> {
    runnable: Arc<AtomicBool>,
    handler: F,
    opts: KProbeOpts,
}

#[allow(clippy::unused_unit)]
impl<F: FnOnce(Event) -> () + Clone + std::marker::Send + 'static> KProbe<F> {
    pub fn new(runnable: Arc<AtomicBool>, handler: F, opts: KProbeOpts) -> Self {
        KProbe {
            runnable,
            handler,
            opts,
        }
    }

    pub fn run(self) -> Result<()> {
        info!("Running Kprobe handler: {:?}", &self.opts);
        let handler = create_handler(self.handler);
        // It is important, to keep bpf in scope while running the event_loop. Otherwise it gets
        // dropped and we loose the connection to our kprobe
        let bpf = load_bpf(&self.opts)?;

        // create events table
        let table = bpf.table("events");
        let perf_map = init_perf_map(table, handler)?;

        event_loop(self.runnable, perf_map, self.opts.interval_ms)
    }
}

#[derive(Debug)]
pub struct KProbeOpts {
    pub max_args: i32,
    pub ancestor_name: String,
    pub max_ancestors: i32,
    pub interval_ms: i32,
}

impl Default for KProbeOpts {
    fn default() -> Self {
        KProbeOpts {
            max_args: 20,
            ancestor_name: "sshd".to_string(),
            max_ancestors: 20,
            interval_ms: 200,
        }
    }
}

impl KProbeOpts {
    fn max_args_key(&self) -> &'static str {
        "MAX_ARGS"
    }

    fn max_args_value(&self) -> String {
        self.max_args.to_string()
    }

    fn max_ancestors_key(&self) -> &'static str {
        "MAX_ANCESTORS"
    }

    fn max_ancestors_value(&self) -> String {
        self.max_ancestors.to_string()
    }

    fn ancestor_name_key(&self) -> &'static str {
        "ANCESTOR_NAME"
    }

    fn ancestor_name_value(&self) -> &str {
        self.ancestor_name.as_str()
    }
}

fn load_bpf(opts: &KProbeOpts) -> Result<BPF> {
    // load and parameterize BPF
    let code = include_str!("exec_logger.c");
    let code = code.replace(opts.max_args_key(), &opts.max_args_value());
    let code = code.replace(opts.ancestor_name_key(), opts.ancestor_name_value());
    let code = code.replace(opts.max_ancestors_key(), &opts.max_ancestors_value());
    // compile the above BPF code!
    let mut module = BPF::new(&code)?;
    // load + attach kprobes!
    bcc::Kprobe::new()
        .handler("hld_syscall_execve_entry")
        .function("sys_execve")
        .attach(&mut module)?;
    bcc::Kretprobe::new()
        .handler("hld_syscall_execve_return")
        .function("sys_execve")
        .attach(&mut module)?;

    Ok(module)
}

fn event_loop(runnable: Arc<AtomicBool>, mut perf_map: PerfMap, interval_ms: i32) -> Result<()> {
    while runnable.load(Ordering::SeqCst) {
        trace!("Event loop: polling perf map.");
        perf_map.poll(interval_ms);
    }

    Ok(())
}

type HandlerGenerator = Box<dyn Fn() -> Box<dyn FnMut(&[u8]) + Send>>;

#[allow(clippy::unused_unit)]
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

pub fn parse_struct<T>(buf: &[u8]) -> T {
    unsafe { ptr::read(buf.as_ptr() as *const T) }
}

pub fn parse_string(buf: &[u8]) -> String {
    // Search has to start from the front, so we find the _first_ 0 in order to prevent
    // reading invalid memory
    match buf.iter().position(|&x| x == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&buf[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(buf).to_string(),
    }
}
