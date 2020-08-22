use crate::Result;
use crate::{Arg, Return};

mod table_output;

pub use table_output::{TableOutput, TableOutputOpts};

pub trait Output {
    fn header(&mut self) -> Result<()>;
    fn arg(&mut self, arg: Arg) -> Result<()>;
    fn ret(&mut self, ret: Return) -> Result<()>;
}
