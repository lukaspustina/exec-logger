use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::{Error, Result};
use crate::{Arg, Return};
use crate::output::Output;

#[derive(Debug)]
pub struct JsonLinesOutputOpts<T: Write> {
    writer: Arc<Mutex<T>>,
    only_ancestor: bool,
}

impl<T: Write> JsonLinesOutputOpts<T> {
    pub fn new(writer: T, only_ancestor: bool) -> JsonLinesOutputOpts<T> {
        JsonLinesOutputOpts {
            writer: Arc::new(Mutex::new(writer)),
            only_ancestor,
        }
    }
}

#[derive(Debug)]
pub struct JsonLinesOutput<T: Write> {
    args: Arc<Mutex<HashMap<i32, Vec<String>>>>,
    opts: JsonLinesOutputOpts<T>,
}

impl<T: Write> JsonLinesOutput<T> {
    pub fn new(opts: JsonLinesOutputOpts<T>) -> Self {
        JsonLinesOutput {
            args: Arc::new(Mutex::new(HashMap::new())),
            opts,
        }
    }
}

impl<T: Write> Output for JsonLinesOutput<T> {
    fn header(&mut self) -> Result<()> {
        Ok(())
    }

    fn arg(&mut self, arg: Arg) -> Result<()> {
        let mut args = self.args.lock()
            .map_err(|_| Error::RunTimeError { msg: "failed to collect for output" })?;
        let value = args.entry(arg.pid).or_insert_with(Vec::new);
        value.push(arg.argv);

        Ok(())
    }

    fn ret(&mut self, ret: Return) -> Result<()> {
        let mut writer = self.opts.writer.lock()
            .map_err(|_| Error::RunTimeError { msg: "failed to write output" })?;

        let mut args = self.args.lock()
            .map_err(|_| Error::RunTimeError { msg: "failed to collect for output" })?;
        let args = args.remove(&ret.pid);
        let args = args.map(|args| args.join(" ")).unwrap_or_else(|| "-".to_string());

        if !self.opts.only_ancestor || (self.opts.only_ancestor && ret.ancestor) {
            let json_line = JsonLine::from_ret_and_args(ret, args);
            let json_line = serde_json::to_string(&json_line)?;
            writeln!(writer, "{}", json_line)?;
        }

        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct JsonLine {
    pid: i32,
    ppid: i32,
    ancestor: bool,
    comm: String,
    tty: String,
    uid: i32,
    gid: i32,
    return_value: i32,
    args: String,
}

impl JsonLine {
    fn from_ret_and_args(ret: Return, args: String) -> JsonLine {
        JsonLine {
            pid: ret.pid,
            ppid: ret.ppid,
            ancestor: ret.ancestor,
            comm: ret.comm,
            tty: ret.tty,
            uid: ret.uid,
            gid: ret.gid,
            return_value: ret.ret,
            args,
        }
    }
}
