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

use thiserror::Error;

#[derive(Debug, Error)]
/// Main Error type of this crate.
///
/// Must be `Send` because it used by async function which might run on different threads.
pub enum Error {
    #[error("BCC error")]
    BccError {
        #[from]
        source: bcc::BccError,
    },
    #[error("IO error")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("IO error")]
    JsonError {
        #[from]
        source: serde_json::error::Error,
    },
    #[error("run time error because {msg}")]
    RunTimeError { msg: &'static str },
}
