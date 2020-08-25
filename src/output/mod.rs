use crate::Result;
use crate::{Arg, Return};

mod table;
mod json_lines;

pub use json_lines::{JsonLinesOutput, JsonLinesOutputOpts};
pub use table::{TableOutput, TableOutputOpts};

pub trait Output {
    fn header(&mut self) -> Result<()>;
    fn arg(&mut self, arg: Arg) -> Result<()>;
    fn ret(&mut self, ret: Return) -> Result<()>;
}
