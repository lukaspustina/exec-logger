#!/usr/bin/python
#
# Copyright 2020 Lukas Pustina
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from bcc import BPF

file = open('src/bpf/exec_logger.c', 'r')
bpf_text = file.read()
bpf_text = bpf_text.replace("MAX_ARGS", "20")
bpf_text = bpf_text.replace("ANCESTOR_NAME", "sshd")
bpf_text = bpf_text.replace("MAX_ANCESTORS", "20")

b = BPF(text=bpf_text)

b

