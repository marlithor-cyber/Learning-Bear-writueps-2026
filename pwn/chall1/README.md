# Pwn Chall 1

Author: `marlithor-cyber`

Challenge name: `Keep Rolling`

## Summary

The binary is `rollers`, a 64-bit PIE with:

- full RELRO
- stack canary
- NX

At first glance it looks like a random “write or skip bit” game, but the important bugs are:

1. `main()` prints a direct libc base leak.
2. The global write cursor is initialized to `main`'s saved return address.
3. The bit-writing routine has no bounds check.
4. The PRNG is just `srand(time(NULL))`, so the output bit stream is predictable.

Flag:

```text
LB{5tr@ng3_pwn_ppc_t@5k?_ea275cf6a6537ed5170c1fda5486f4c8}
```

## Root Cause

From the disassembly:

### 1. Direct libc leak

`main()` loads the resolved `printf` address from the GOT, subtracts a constant offset, and prints the result as `Libc base: %p`.

So ASLR for libc is effectively gone immediately.

### 2. The write cursor starts on saved RIP

`main()` has a local integer at `[rbp-0xc]`, then does:

```text
lea rax, [rbp-0xc]
add rax, 0x14
mov [current_addr], rax
```

`-0xc + 0x14 = +0x8`, so `current_addr` becomes `rbp+8`, which is `main`'s saved return address.

### 3. Arbitrary sequential bit writes

`write_bit()` sets or clears one bit at `*current_addr`, advances `current_bit`, and every 8 bits increments `current_addr` by one byte.

There is no bounds check at all, so every successful “write bit” action programs the saved return address and then the following stack bytes.

The canary does not help here because the cursor starts above it, directly on the saved RIP.

### 4. Predictable randomness

`setup()` calls:

```c
srand(time(NULL));
```

and `randomize()` uses `rand() % 100` with a mutable global `chance` byte to decide whether the next generated bit is `0` or `1`.

That means the challenge is not “real randomness”; it is a deterministic stream once the seed is known. Since the seed is current Unix time, the exploit can brute-force a small time window around “now”.

## Exploit

The exploit script reproduces the exact PRNG with the matching glibc and chooses menu actions so the generated bit stream matches a desired payload.

The logic is:

1. Parse the leaked libc base from the banner.
2. Build a libc-only ROP chain:
   - `ret`
   - `pop rdi ; ret`
   - pointer to `"/bin/sh"`
   - `system`
   - `exit`
3. Reproduce the same `rand()` sequence locally for a candidate `time(NULL)` seed.
4. For each desired payload bit:
   - send `1` if the next generated bit matches the target bit
   - send `2` otherwise, which skips that bit and advances the PRNG state
5. After enough bits are written, send `3` so `main()` returns into the forged ROP chain.
6. Run `cat /flag-*; exit` through the spawned shell.

Because the payload is written little-endian starting from saved RIP, the stack after `main()` returns is already laid out as a normal ret-chain.

## Libc Note

The important operational detail was the libc version from the pinned image in [Dockerfile](/home/shadowbyte/Downloads/lb/pwn/chall1/attachments/Dockerfile):

```text
ubuntu:26.04@sha256:fed6ddb82c61194e1814e93b59cfcb6759e5aa33c4e41bb3782313c2386ed6df
```

That image ships `glibc 2.42-2ubuntu2`, and the exploit offsets in `solve.py` were updated to match that exact libc. Using offsets from a different archive build breaks the exploit.

## Solve Script

The working exploit is included as [solve.py](/tmp/Learning-Bear-writueps-2026/pwn/chall1/solve.py).

## Notes

- The vulnerability is a stack-based arbitrary bit writer, not a classical overflow on user input.
- The libc leak and the time-seeded PRNG make the challenge much easier than the mitigations suggest.
- The exploit does not need to bypass the canary because it never overwrites it.
