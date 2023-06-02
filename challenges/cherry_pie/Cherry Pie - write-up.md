## Overview
![[cherry_pie_main.png]]

We have PIE and a canary to bypass

### Vulnerabilities
- Buffer overflow on the string 's' since it's only 32 bytes long but the fgets reads 128 bytes.
- Format string vulnerability at row 14

## Phase 1 - Leak the offset, find the canary
We can bypass PIE by exploiting the format string vulnerability to leak an address, find the offset and then the base address.

The input to leak an address is : `Take this, my grandma made that %39$p %40$p %41$p %42$p %43$p %44$p`

We recognize the leaked address that we need because **it usually starts with the number '5'**, in my case i got `0x564f2f600820`.
Using gdb we can find the base and, therefore, leak the offset, that is `0x820`.

Using the same procedure vulnerability (and the same input) **we leak the canary**. In my case i found the canary at `%15$p` and the address at `%39$p`. 
The offset may be different running the binary in local and remote, in my case they was.

## Phase 2 - Attack
We know the location of the address to leak, we know the location of the canary and the offset, so let's begin.
### Set the base address
We first, again, leak the address and the canary, then we use the address to compute the base address: 
				`base_addr = leaked_addr - leaked_offset
				`exe.address = base_addr`
Now that we have set the base address to our elf, we can access freely its symbols :D
### Build the payload
We now that the 's' string (our buffer) is at `$rbp-0x50`, and the canary is as usual at `$rbp-0x8`.

We set our offset variable to `0x50-0x8`, since we have to stop just before the canary.
So the payload is going to be:
- `b'A' * offset`
- the canary
- `b'A' * 8  // this is just for aligning the stack`
- `rop.ret.address // remeber to set rop = ROP(exe) AFTER setting the base address`
- `exe.sym['win']

After we send this payload to the second `fgets` we get the flag :D
`srdnlen{W3_l0v3_Ch3rry_p1e$}`

[Code](./solve.py)

## Note
I found the canary and the address to leak by using this code:

`for i in range(1, 150):`
           ` r = remote(remote_address, port)`
            `payload = 'Take this, my grandma made that '`
            `payload += "%"+str(i)+'$p'`