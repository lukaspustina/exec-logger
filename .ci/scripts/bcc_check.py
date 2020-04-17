#!/usr/bin/python
from bcc import BPF

file = open('src/execsnoop.c', 'r')
bpf_text = file.read()
bpf_text = bpf_text.replace("MAXARG", "20")

b = BPF(text=bpf_text)

b

