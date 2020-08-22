use crate::Result;
use crate::{Arg, Return};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

pub trait Output {
    fn header(&self) -> Result<()>;
    fn arg(&self, arg: Arg) -> Result<()>;
    fn ret(&self, ret: Return) -> Result<()>;
}

pub struct SimpleOutput {
    args: Arc<Mutex<HashMap<i32, Vec<String>>>>,
}

impl SimpleOutput {
    pub fn new() -> Self {
        SimpleOutput {
            args: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Output for SimpleOutput {
    fn header(&self) -> Result<()> {
        println!("{:-16} {:-7}", "PCOMM", "PID");
        Ok(())
    }

    fn arg(&self, arg: Arg) -> Result<()> {
        let mut args = self.args.lock().unwrap();
        let value = args.entry(arg.pid()).or_insert_with(Vec::new);
        value.push(arg.argv);
        Ok(())
    }

    fn ret(&self, ret: Return) -> Result<()> {
        let mut args = self.args.lock().unwrap();
        let value = args.remove(&ret.pid());
        println!("{:?}: {:?}", ret, value);
        Ok(())
    }
}

