# Pwn Chall 2

Author: `marlithor-cyber`

Challenge name: `new-wave-q`

## Summary

The service is a 64-bit PIE with:

- full RELRO
- stack canary
- NX

The binary implements a tiny XOR-framed note protocol. The intended heap bug is that `CMD_READ` writes directly into the live note object, so the note metadata is attacker-controlled:

- `note->ptr` at `+0x0`
- `note->size` at `+0x8`
- `note->errptr` at `+0x10`
- inline user buffer at `+0x18`

Once those fields are mutable, the rest of the exploit falls out:

1. leak the safe-linking mask from a recycled tcache chunk
2. retarget the note into chosen libc addresses
3. use `CMD_WRITE` as an arbitrary read primitive
4. forge glibc exit handlers and trigger `CMD_EXIT`

Flag:

```text
LB{3nt3r1ng_n3w_g3n3r@t10n_0f_pwn_acf167716da5637092a5ea5ce5c0717e}
```

## Root Cause

### 1. Note metadata is writable

`NoteCreate()` allocates `size + 0x19` bytes for the main note object and stores the note fields inside that same allocation. Later, `NoteReadData()` reads attacker-supplied bytes into the note body, but there is no separation between “user data” and the metadata that controls the note.

That means the attacker can overwrite:

- the pointer later freed by `NoteFree()`
- the pointer later dereferenced by `NoteWriteData()`
- the error-pointer slot used for `LastError`

### 2. `CMD_FREE` gives a useful double-free style primitive

`NoteFree()` does:

1. save `UserNote->ptr`
2. `free(UserNote)`
3. if the saved pointer is non-null, `free(saved_ptr)`

After retargeting `note->ptr`, the second `free()` can be steered into an arbitrary tcache-eligible address. With the heap safe-linking mask leaked, that becomes a reliable tcache poisoning primitive.

### 3. `CMD_WRITE` is an arbitrary read

`NoteWriteData()` trusts the corrupted metadata:

- it treats `note->ptr` as a 3-qword timestamp buffer and sends `Created`, `Changed`, and `Accessed`
- it then calls `strlen(UserNote + 0x18)` and sends that buffer back as an info message

So once the note is moved over an interesting region, `CMD_WRITE` leaks both qwords and raw bytes from that target address.

## Exploit

The bundled exploit in [solve.py](/tmp/Learning-Bear-writueps-2026/pwn/chall2/solve.py) uses the following chain.

### 1. Leak PIE and heap mask

The script first abuses an oversized `create` to recover a PIE-relative `LastError` value, then rebuilds heap state and leaks the safe-linking mask from a stale tcache pointer.

### 2. Leak libc and move the note into libc

The fastest libc leak comes from steering the note into an unsorted-bin-sized chunk and reading the `Changed` timestamp value back. From that single leak the script computes the libc base, then poisons tcache so the next recreated note lands on a writable libc slab at `libc + 0x211010`.

At that point the note is no longer a heap object in practice. It becomes a read/write window into libc data.

### 3. Recover the pointer guard

To hijack glibc exit handlers cleanly, the exploit leaks:

- `__exit_funcs` head
- a writable `ld.so` pointer
- the mangled `_dl_fini` callback

Then it computes:

```text
pointer_guard = ror64(mangled_fini, 0x11) ^ (ld_base + 0x3480)
```

and remangles `system()` with that same guard.

### 4. Forge an exit handler

Instead of building a fresh structure from scratch, the exploit patches the existing exit-function node in libc:

- overwrite the mangled callback with mangled `system`
- overwrite the argument pointer with a writable libc command buffer
- write the command string there, e.g. `cat /f*`

Finally it sends `CMD_EXIT`, so glibc runs the forged exit callback and executes the command.

## Runtime Note

The important operational detail was the runtime from [Dockerfile](/home/shadowbyte/Downloads/lb/pwn/chall2/attachments/Dockerfile):

```text
ubuntu:26.04@sha256:fed6ddb82c61194e1814e93b59cfcb6759e5aa33c4e41bb3782313c2386ed6df
```

The remote service uses Ubuntu 26.04 `libc`/`ld`, and the leaked addresses behave like pseudo-bases for that image layout. The final remote solve only worked after building the local write template against the extracted Ubuntu 26.04 runtime and using the matching relative constants:

- `LIBC_SYSTEM = 0x3a480`
- `LD_DL_FINI = 0x3480`

Using host-library offsets breaks the exit-handler stage even though the heap part still looks correct.

## Solve Script

The working exploit is included as [solve.py](/tmp/Learning-Bear-writueps-2026/pwn/chall2/solve.py).
