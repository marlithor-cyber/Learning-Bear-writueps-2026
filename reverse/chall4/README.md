# Reverse Chall 4

Author: `marlithor-cyber`

## Summary

The challenge ships a huge minified `out.c`. `stockfish.tar` is a decoy; the real checker is entirely inside the C file.

It expects a flag shaped like:

```text
LB{<1000 chars from S/P/R/U/H>}
```

The payload is packed into `19` `__int128` values in base 5, reinterpreted as `148` little-endian `unsigned short` values, mapped through an embedded `65536`-word dictionary, and compared against a hardcoded `148`-word sentence.

Flag:

```text
LB{UUSRHSURRURRSRSUUSUSUSSHSRSSUUHSHUSUSPSPPRSPURPHPRRRHUSRHUHRHHSHURPPUSRPSUUSSUSHSHPPHRPUHUSRHUSRPUPPRHUSPPRRPURRSHRSURPRRRPRHSRPHPPSUPUSHUHSPHSSPURSHRSSPPSUUHRHSPURPPUHRUUSHSURSHPUHHURHRPUPUPSHSUPSPSURSPPSPRURPPHSSHRSRRUPSRPSRHHSHHSSUSHUPSSPHPSSHURHSPHHHHSRHUUUURHPURSSPPHPSRSRRPUPSUPRHRHPURHHUUPRSRHSPRURHRUHURRSRRSHHHHPSSHRUSSPUPPPSPRPRURPPPUUPPUSPPUSSHHHUSHHPPRRRHUUUPPUHPSPPPSSURHRRRHHUHRUHHSHRRRUPPUHRSHHURSPPPPUHUHHSSURSSHHRHHRUPSHUSRPURHHHRURPHPHUSPPPRPRHRHPRSRPHPPPRURPHSHSSUSHURPUSSPUSUUSRRSHPUSRHSRRSHRURPUSHSHPRUSRSPSSRUPUSUHSHRHRUURHPSPHHPRRPRUSHHSRSRPSSPURRHPUSUSSURHPSRHUHHSSSPHUSSPPPUURUPSSPSPRSHRUPPPSHRUPSUUPHUHHSPHHPRSPHURPHURSRHHHHUPRRRPPHPPURSUHRHPRRRSPPRURPHRHRPSSPSHSSPUHSHRURSUHHSPRPPHPUUUSPRURRRRRRPRSUSRHHSPSPRHUHSUUHPHPSPUURRRHSPURRHPSHPPUPPSSHRUURURPSHSSSSSHPRUPPRSSSRPUSSPHRPPRHSSHSPRSRRSSSRURRUHRRPHRPRSSURHHUSHSRPSUSRRSHRHUSPSSPSRRRUPHSHUHSUUPRRRPSSPHSRHPHURUUHHRHPRHSPUSHPPSSUSPHRHSSHSRUPRSRSUSHRSURUPUPRURRRRRRHSUHHPRUHPUUSSHRRHPUPSRPSPSHPSSRSSRPHHUUUHSUHHHUHPHRUUUUSP}
```

## Key Observations

- The prefix check uses `*(short*)buf != 'BL'`. On little-endian this actually matches the bytes `LB`, so the real prefix is still `LB{`.
- The first big loop is just base-5 packing with alphabet:

```text
S = 0
P = 1
R = 2
U = 3
H = 4
```

- For each payload character:

```text
state[i / 55] = state[i / 55] * 5 + digit
```

- The first `18` chunks use `55` digits each. The last chunk only uses the final `10` digits.
- The next loop casts the `__int128[19]` buffer to `unsigned short*` and reads `148` word indices.
- Each index selects the corresponding word from the embedded `65536`-word dictionary. The built sentence is then compared with the hardcoded target.

## Solve

1. Extract the dictionary string from `out.c` and split it into `65536` words.
2. Extract the target sentence from the final `strcmp`.
3. Map every target word to its dictionary index.
4. Pack the indices as little-endian `unsigned short[148]`.
5. Group them into `19` integers:
   - chunks `0..17`: `8` indices each, then convert each 128-bit value to `55` base-5 digits
   - chunk `18`: remaining `4` indices, then convert the resulting value to `10` base-5 digits
6. Map base-5 digits back with `0=S, 1=P, 2=R, 3=U, 4=H`.

## Verification

Running the recovered flag against the original checker prints:

```text
yea:)
```

## Notes

The core trick is that the giant source is mostly noise. Once the three loops are isolated, the challenge becomes a reversible encoding problem:

- base-5 payload -> `__int128` blocks
- `__int128` blocks -> 16-bit dictionary indices
- indices -> fixed target sentence
