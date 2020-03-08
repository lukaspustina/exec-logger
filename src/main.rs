extern crate bcc;
extern crate byteorder;
extern crate failure;
extern crate libc;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use failure::Error;

use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::sync::Arc;

#[repr(C)]
enum EventType {
    EVENT_ARG,
    EVENT_RET,
}

#[repr(C)]
struct Data {
    pid: libc::c_int,
    ppid: libc::c_int,
    comm: [u8; 16],   // TASK_COMM_LEN
    r#type: EventType,
    argv: [u8; 128],   // ARGSIZE
    tty: [u8; 64],   // TTYSIZE
    uid: libc::c_int,
    gid: libc::c_int,
    ret: libc::c_int,
}

impl From<&[u8]> for Data {
    fn from(bytes: &[u8]) -> Self {
        unsafe { ptr::read(bytes.as_ptr() as *const Data) }
    }
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let code = include_str!("execsnoop.c");
    // compile the above BPF code!
    let mut module = BPF::new(code)?;
    // load + attach kprobes!
    let return_probe = module.load_kprobe("syscall__execve")?;
    let entry_probe = module.load_kprobe("do_ret_sys_execve")?;
    module.attach_kprobe("sys_execve", entry_probe)?;
    module.attach_kretprobe("sys_execve", return_probe)?;
    let table = module.table("events");
    let mut perf_map = init_perf_map(table, perf_data_callback)?;
    println!("{:-16} {:-7}", "PCOMM", "PID");

    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
    }
    Ok(())
}

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data: Data = x.into();
        let comm = get_string(&data.comm);
        println!(
            "{:-16} {:-7}",
            comm,
            data.pid,
        );
    })
}

fn parse_struct(x: &[u8]) -> Data {
    unsafe { ptr::read(x.as_ptr() as *const Data) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
        .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}