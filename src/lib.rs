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

pub mod bpf;
pub mod error;
pub mod exec_logger;
pub mod logging;
pub mod output;

pub use crate::error::Error;
pub use crate::exec_logger::{Arg, ExecLogger, ExecLoggerOpts, Return, RunningExecLogger, Stopper};

pub type Result<T> = std::result::Result<T, Error>;
