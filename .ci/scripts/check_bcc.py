#!/usr/bin/python
from bcc import BPF

file = open('src/bpf/execsnoop.c', 'r')
bpf_text = file.read()
bpf_text = bpf_text.replace("MAX_ARGS", "20")
bpf_text = bpf_text.replace("ANCESTOR_NAME", "sshd")
bpf_text = bpf_text.replace("MAX_ANCESTORS", "20")

b = BPF(text=bpf_text)

b

