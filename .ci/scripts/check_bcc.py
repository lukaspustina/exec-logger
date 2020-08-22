#!/usr/bin/python
from bcc import BPF

file = open('src/bpf/execsnoop.c', 'r')
bpf_text = file.read()
bpf_text = bpf_text.replace("MAXARGS", "20")

b = BPF(text=bpf_text)

b

