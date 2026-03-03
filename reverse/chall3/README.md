# Reverse Chall 3

Author: `marlithor-cyber`

## Summary

The challenge is a giant Python checker:

- `task.py`

It defines `141956` tiny wrapper functions that only implement `==` or `!=`, then transforms the input through repeated compression and Base64 encoding before checking characters of the final transformed string.

Flag:

`LB{0OoO0_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86_0OoO0}`

## Key Observation

The real transform is:

```python
from base64 import b64encode
from zlib import compress

v = lambda a: b64encode(compress(a))
vv = lambda a: v(v(a))
vvv = lambda a: vv(vv(a))
vvvv = lambda a: vvv(vvv(a))
```

The input is wrapped inside `50` nested `vvvv(...)` calls, so the checker applies `400` rounds of:

```text
base64(zlib.compress(x))
```

At the bottom of the file, every condition checks one position of the final transformed string `inp`. Once the wrapper functions are classified as `==` or `!=`, all those checks become direct equality constraints for the whole transformed buffer.

## Solve

1. Parse the wrapper functions and record whether each one is equality or inequality.
2. Parse every `if ... inp[index] ...` check.
3. Reconstruct the full transformed string of length `141956`.
4. Reverse the transformation `400` times:

```python
blob = reconstructed_inp.encode()
for _ in range(400):
    blob = zlib.decompress(base64.b64decode(blob))

print(blob.decode())
```

That produces:

```text
LB{0OoO0_ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_1FAEFB6177B4672DEE07F9D3AFC62588CCD2631EDCF22E8CCC1FB35B501C9C86_0OoO0}
```

## Verification

Running the recovered flag against the original script prints:

```text
Correct
```

## Notes

The challenge looks huge, but the huge size is mostly noise. The checker already leaks the entire transformed string one character at a time, and the repeated encoding/compression pipeline is fully reversible.
