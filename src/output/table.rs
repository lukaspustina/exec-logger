use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::output::{Output, ToName};
use crate::{Arg, Return};
use crate::{Error, Result};

#[derive(Debug)]
pub struct TableOutputOpts<T: Write> {
    writer: Arc<Mutex<T>>,
    only_ancestor: bool,
    numeric: bool,
}

impl<T: Write> TableOutputOpts<T> {
    pub fn new(writer: T, only_ancestor: bool, numeric: bool) -> TableOutputOpts<T> {
        TableOutputOpts {
            writer: Arc::new(Mutex::new(writer)),
            only_ancestor,
            numeric,
        }
    }
}

#[derive(Debug)]
pub struct TableOutput<T: Write> {
    args: Arc<Mutex<HashMap<u32, Vec<String>>>>,
    opts: TableOutputOpts<T>,
}

impl<T: Write> TableOutput<T> {
    pub fn new(opts: TableOutputOpts<T>) -> Self {
        TableOutput {
            args: Arc::new(Mutex::new(HashMap::new())),
            opts,
        }
    }
}

impl<T: Write> Output for TableOutput<T> {
    fn header(&mut self) -> Result<()> {
        let mut writer = self.opts.writer.lock().map_err(|_| Error::RunTimeError {
            msg: "failed to write output",
        })?;
        writeln!(
            writer,
            "{:-16} {:-6} {:-6} {:-6} {:-6} {:-6} {:-9} {:-6} Args",
            "PCOMM", "PID", "PPID", "UID", "GID", "RET", "ANCESTOR?", "TTY"
        )?;

        Ok(())
    }

    fn arg(&mut self, arg: Arg) -> Result<()> {
        let mut args = self.args.lock().map_err(|_| Error::RunTimeError {
            msg: "failed to collect for output",
        })?;
        let value = args.entry(arg.pid).or_insert_with(Vec::new);
        value.push(arg.argv);

        Ok(())
    }

    fn ret(&mut self, ret: Return) -> Result<()> {
        let mut writer = self.opts.writer.lock().map_err(|_| Error::RunTimeError {
            msg: "failed to write output",
        })?;

        let mut args = self.args.lock().map_err(|_| Error::RunTimeError {
            msg: "failed to collect for output",
        })?;
        let args = args.remove(&ret.pid);
        let args = args.map(|args| args.join(" ")).unwrap_or_else(|| "-".to_string());

        if !self.opts.only_ancestor || ret.ancestor {
            writeln!(
                writer,
                "{:-16} {:-<6} {:-<6} {:-<6} {:-<6} {:-<6} {:-9} {:-6} {}",
                ret.comm, ret.pid, ret.ppid, ret.uid.to_user(self.opts.numeric), ret.gid.to_group(self.opts.numeric), ret.ret_val, ret.ancestor, ret.tty, args
            )?;
        }

        Ok(())
    }
}
