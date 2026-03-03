# Reverse Chall 2

Author: `marlithor-cyber`

## Summary

The challenge consists of a single HTML file:

- `lol.html`

The page contains a heavily obfuscated JavaScript flag checker. The fastest solution is not to fully deobfuscate the whole script, but to execute it with a fake DOM and inspect the runtime values created by `check()`.

Flag:

`LB{1IIi1l1iIll11IiiIllIiilIlIIlIll11l1lili1lIIIi1l1IillI111l11I1lil}`

## Key Observation

After instrumenting `check()`, the checker reveals the exact transformed string it compares against:

```text
}lil1I11l111IlliI1l1iIIIl1ilil1l11llIlIIlIliiIllIiiI11llIi1l1iII1{BL
```

That string is simply the real flag written backwards.

## Solve

1. Load the script from `lol.html` in Node.js.
2. Stub `document.getElementById` so `check()` can run outside the browser.
3. Instrument `check()` to dump the internal comparison object.
4. Extract the target string.
5. Reverse it.

Minimal logic:

```text
reverse("}lil1I11l111IlliI1l1iIIIl1ilil1l11llIlIIlIliiIllIiiI11llIi1l1iII1{BL")
```

Result:

```text
LB{1IIi1l1iIll11IiiIllIiilIlIIlIll11l1lili1lIIIi1l1IillI111l11I1lil}
```

## Verification

Testing the recovered flag against the original checker returns `Correct`.

## Notes

The intended difficulty comes from the JavaScript obfuscation, but the actual validation logic is simple. Dumping the runtime constants is enough to avoid spending time on a full manual deobfuscation pass.
