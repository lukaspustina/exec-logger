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

use std::fmt;
use serde::Serialize;

pub use json_lines::{JsonLinesOutput, JsonLinesOutputOpts};
pub use table::{TableOutput, TableOutputOpts};

use crate::{Arg, Return};
use crate::Result;

mod json_lines;
mod table;

pub trait Output {
    fn header(&mut self) -> Result<()>;
    fn arg(&mut self, arg: Arg) -> Result<()>;
    fn ret(&mut self, ret: Return) -> Result<()>;
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum User {
    Name(String),
    Id(u32),
}

impl User {
    pub fn try_from_id(id: u32) -> Option<User> {
        users::get_user_by_uid(id)
            .map(|user| User::Name(user.name().to_string_lossy().to_string()))
    }

    pub fn from_id(id: u32) -> User {
        Self::try_from_id(id).unwrap_or_else(|| User::Id(id))
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            User::Name(name) => f.write_str(&name),
            User::Id(id) => f.write_fmt(format_args!("{}", id)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Group {
    Name(String),
    Id(u32),
}

impl Group {
    pub fn try_from_id(id: u32) -> Option<Group> {
        users::get_group_by_gid(id)
            .map(|user| Group::Name(user.name().to_string_lossy().to_string()))
    }

    pub fn from_id(id: u32) -> Group {
        Self::try_from_id(id).unwrap_or_else(|| Group::Id(id))
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Group::Name(name) => f.write_str(&name),
            Group::Id(id) => f.write_fmt(format_args!("{}", id)),
        }
    }
}

pub trait ToName {
    fn to_user(&self, numeric: bool) -> User;
    fn to_group(&self, numeric: bool) -> Group;
}

impl ToName for u32 {
    fn to_user(&self, numeric: bool) -> User {
        if numeric {
            User::Id(*self)
        } else {
            User::from_id(*self)
        }
    }

    fn to_group(&self, numeric: bool) -> Group {
        if numeric {
            Group::Id(*self)
        } else {
            Group::from_id(*self)
        }
    }
}
