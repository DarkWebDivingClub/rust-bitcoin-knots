# The BLAKE2b v2 block header hash

**The specification is [BKIP-0001](https://github.com/DarkWebDivingClub/bkips/blob/master/bkip-0001.md).**
It describes the 164-byte header, all eight stages of the hash, the four
ASIC profiles, activation, and the byte orders — and it has been checked
by implementing it from its own text and comparing every intermediate
against Knots' vectors.

This file used to carry that description. It no longer does: two copies
of an algorithm this fiddly drift, and the drift is silent. What is left
here is what BKIP-0001 should not contain, being specific to this crate.

## Where it lives

| Concern | Where |
|---|---|
| The header type and its serialization | `block.rs` — `HeaderV2`, `Header::v2` |
| The hash, stage by stage | `blake2b_pow.rs` — `components()` |
| Vectors | `tests/blake2b_pow.rs`, `tests/data/block_header_v2.json` |

Everything is behind the `blake2b` feature, off by default.

## Why `components()` returns every intermediate

Not for callers — `block_hash()` is the only thing that needs the
answer. It exists because the vectors expose every intermediate, and a
five-stage construction with four variants is not something to debug
from one mismatched value at the end. A wrong byte in `h1` and a wrong
ASIC profile look identical if all you compare is the final hash.

## The one that bit us

`xor_key_hash` is already a hash when it goes into `h1`. Our own notes
said `SHA256(xor_key_hash)` and were wrong for weeks; the code was right
because it was written from the C++ rather than from the notes. Caught
only when the specification was implemented from its own text.

Which is the argument for having exactly one description, and for
testing it by building from it.

## If Knots moves

Knots is authoritative. If it changes, `blake2b_pow.rs` follows the C++,
and BKIP-0001 is updated separately — it is a description of Knots, not
of this crate.
