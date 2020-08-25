use crate::Result;
use crate::{Arg, Return};

mod json_lines;
mod table;

pub use json_lines::{JsonLinesOutput, JsonLinesOutputOpts};
pub use table::{TableOutput, TableOutputOpts};

pub trait Output {
    fn header(&mut self) -> Result<()>;
    fn arg(&mut self, arg: Arg) -> Result<()>;
    fn ret(&mut self, ret: Return) -> Result<()>;
}
