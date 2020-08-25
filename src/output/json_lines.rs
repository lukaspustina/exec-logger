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

use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::output::{Output, User, Group, ToName};
use crate::{Arg, Return};
use crate::{Error, Result};

#[derive(Debug)]
pub struct JsonLinesOutputOpts<T: Write> {
    writer: Arc<Mutex<T>>,
    only_ancestor: bool,
    numeric: bool,
}

impl<T: Write> JsonLinesOutputOpts<T> {
    pub fn new(writer: T, only_ancestor: bool, numeric: bool) -> JsonLinesOutputOpts<T> {
        JsonLinesOutputOpts {
            writer: Arc::new(Mutex::new(writer)),
            only_ancestor,
            numeric,
        }
    }
}

#[derive(Debug)]
pub struct JsonLinesOutput<T: Write> {
    args: Arc<Mutex<HashMap<u32, Vec<String>>>>,
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
            let json_line = JsonLine::from_ret_and_args(ret, args, self.opts.numeric);
            let json_line = serde_json::to_string(&json_line)?;
            writeln!(writer, "{}", json_line)?;
        }

        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct JsonLine {
    pid: u32,
    ppid: u32,
    ancestor: bool,
    comm: String,
    tty: String,
    uid: User,
    gid: Group,
    return_value: i32,
    args: String,
}

impl JsonLine {
    fn from_ret_and_args(ret: Return, args: String, numeric: bool) -> JsonLine {
        JsonLine {
            pid: ret.pid,
            ppid: ret.ppid,
            ancestor: ret.ancestor,
            comm: ret.comm,
            tty: ret.tty,
            uid: ret.uid.to_user(numeric),
            gid: ret.gid.to_group(numeric),
            return_value: ret.ret_val,
            args,
        }
    }
}
