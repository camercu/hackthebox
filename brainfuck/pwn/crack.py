#!/usr/bin/env python3
ct = "Qbqquzs - Pnhekxs dpi fca fhf zdmgzt"
pt = "Orestis - Hacking for fun and profit"
pt = ''.join(c for c in pt if c.isalpha())
ct = ''.join(c for c in ct if c.isalpha())
deltas = list(map(lambda x: (ord(x[0]) - ord(x[1])) % 26, zip(ct, pt)))
print(''.join(map(lambda x: chr(ord('A') + x), deltas)))
