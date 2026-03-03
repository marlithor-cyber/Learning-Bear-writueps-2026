# Reverse Chall 1

## Summary

The challenge is a single Python file:

- `task.py`

At first glance it looks like a hash-preimage problem:

```python
if bytes([v1 ^ v2 for v1, v2 in zip(sha256(flag).digest(), sha256(b64decode(salt)).digest())]).hex() == TARGET:
```

Rearranging that gives:

```text
sha256(flag) = TARGET xor sha256(b64decode(salt))
```

That still does not make SHA-256 invertible, so the intended path is to inspect the huge Base64-encoded `salt` instead of trying to brute-force a preimage.

Flag:

`LB{reading_ascii_art_should_be_easier_for_humans}`

## Key Observation

`b64decode(salt)` is not random data. It is a 19-line ASCII art payload made mostly of spaces plus characters like:

- `#`
- `:`
- `.`

If you print it directly, it is too wide to read comfortably in a terminal, but once rendered as an image or viewed with a monospaced font at the right scale, it clearly spells:

```text
I didn't use AI while developing this challenge. The flag is LB{reading_ascii_art_should_be_easier_for_humans}. Was it?
```

So the flag is literally embedded in the decoded salt.

## Solve

1. Read `task.py`.
2. Notice the hash check depends on `b64decode(salt)`.
3. Decode the salt and inspect the output instead of attacking SHA-256.
4. Rasterize the ASCII art or otherwise visualize it.
5. Read the sentence and extract the flag.

Minimal extraction:

```python
from base64 import b64decode

print(b64decode(salt).decode())
```

The printed art is very wide, so a better practical approach is to convert:

- spaces to white pixels
- non-spaces to black pixels

That reveals the hidden message immediately.

## Verification

Using the recovered flag against the original script:

```bash
printf '%s\n' 'LB{reading_ascii_art_should_be_easier_for_humans}' | python3 task.py
```

Output:

```text
Enter flag: yea
```

## Notes

The hash equation is there to push you toward reversing the surrounding data rather than solving a cryptographic preimage problem. The actual secret is stored in the decoded salt as human-readable ASCII art.
