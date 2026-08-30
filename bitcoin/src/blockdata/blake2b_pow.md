# The BLAKE2b v2 block header hash

How Bitcoin Knots computes the proof-of-work hash of a version 2 block
header, written down because **there is no BIP**. The specification is
`CBlockHeader::GetHash()` in Knots' `src/primitives/block.cpp`, on the
`__base_29_blake2` branch, proposed in PR `bitcoinknots#359`.

This document exists so our implementation can be read and checked
against the original without holding both in your head at once. If the
two ever disagree, **Knots is correct and this is stale**.

## Scope

A v2 header is 164 bytes and is flagged by **bit 31 of `nVersion` on the
wire**. That bit is not part of the version number: Knots stores the
format separately (`m_header_v2`) and masks the flag off the stored
`nVersion`, re-applying it only when serialising. A v1 header is the
historical 80 bytes and hashes as `SHA256d`; everything below concerns
v2 only.

## Fields

Beyond the six classic fields, a v2 header carries:

| Field | Width | Notes |
|---|---|---|
| `m_height` | 32 | the block's own height |
| `m_txcount` | 32 | transaction count |
| `m_nonce2`, `m_nonce3` | 32 each | extra nonce space beyond `nNonce` |
| `m_extranonce` | 128 | Stratum v1 extranonce |
| `m_time_offset` | 32 | see `GetTimeOnWire` below |
| `m_flags` | 8 | low two bits select the ASIC profile |
| `m_xor_key` | 128 | withheld from the pooling miner |
| `m_xor_key_mask_clear_bits` | 8 | how much of the mask is cleared |
| `m_mm_rhs` | 256 | merge-mining commitment |

Two derived values are used repeatedly:

- **`GetCompleteVersion()`** = `(v2 ? 0x8000_0000 : 0) | (nVersion & ~0x8000_0000)`
  — the version as serialised, with the format flag re-applied.
- **`GetTimeOnWire()`** = `nTime` if `m_flags & UseTimeOffset` is clear,
  otherwise `nTime - m_time_offset` with wrapping subtraction.

## The algorithm

Two primitives are involved, not one. Tagged hashes are BIP340-style
**SHA256**; only the last two stages are **BLAKE2b**.

### 1. XOR key hash

```
xor_key_hash = TaggedHash("Bitcoin block hash PoW XOR key") << m_xor_key
```

A pooling miner is given only this hash, never `m_xor_key` itself, so it
cannot compute the final hash until the block is found. Body is
0x10 bytes; the tag prefix adds 0x40.

### 2. XOR key mask

Zero when `m_xor_key` is null. Otherwise:

```
mask = SHA256(TaggedHash("Bitcoin block hash PoW XOR mask") << m_xor_key)
clear_bytes = m_xor_key_mask_clear_bits / 8
mask[0 .. clear_bytes]  = 0
mask[clear_bytes]      &= 0xff >> (m_xor_key_mask_clear_bits % 8)
```

The leading bits are cleared so the mask cannot affect the difficulty
comparison — the work still has to be real.

### 3. Hidden previous block

```
prevblock_ordered_sane = reverse_bytes(hashPrevBlock)
prevblock_hidden = SHA256(TaggedHash("Bitcoin prevblock header, hashed")
                          << prevblock_ordered_sane)
```

Note the reversal: `hashPrevBlock` is stored in internal order, and the
"sane" ordering is the reverse of it. Getting this backwards is the
easiest way to be wrong everywhere downstream.

### 4. `h1` — the fields the mining machine never sees

```
h1 = TaggedHash("Bitcoin block header 1")
        << GetCompleteVersion()
        << prevblock_ordered_sane
        << m_height
        << hashMerkleRoot
        << GetTimeOnWire()
        << u8(0)                      // reserved for extended 40-bit time
        << nBits
        << u32(m_txcount)
        << m_flags
        << m_xor_key_mask_clear_bits
        << SHA256(xor_key_hash)
```

Body is **119 bytes** — Knots asserts this, and so should we.

Keeping version, time and difficulty out of what the hardware hashes is
deliberate: it means an ASIC cannot be bricked by a future block
version, timestamp or target.

### 5. `h2` — the merge-mining hook

```
h2 = TaggedHash("Merge-mining hook") << SHA256(h1) << zeros_128 << zeros_128 << m_mm_rhs
h2_hash = SHA256(h2)
```

Body is 0x60 bytes.

### 6. First BLAKE2b — the Stratum v1 payload

```
stream = u32(0) || h2_hash || m_extranonce      // exactly 52 bytes
hash   = BLAKE2b(stream)                        // unkeyed, 32-byte output
```

The leading `u32(0)` is the tail of Stratum's `coinb1`; its first byte is
implied by the hasher.

### 7. Second BLAKE2b — the ASIC profile

The layout here **branches on `m_flags & 3`**. This is the part most
likely to be got wrong.

| Profile | Stream |
|---|---|
| **0** | `prevblock_hidden` (first **6 bytes zeroed**) ‖ `nNonce` ‖ `m_nonce2` ‖ `m_time_offset` ‖ `m_nonce3` ‖ `hash` |
| **1** | `nNonce` ‖ `m_nonce2` ‖ `m_nonce3` ‖ `m_time_offset` ‖ `hash` ‖ `h2_hash` |
| **2** | `zeros×3` ‖ `h2_hash` ‖ `nNonce` ‖ `m_nonce2` ‖ `m_time_offset` ‖ `m_nonce3` ‖ `hash` |
| **3** | `zeros×2` ‖ *then exactly profile 2's stream* |

Profile 3 falls through to profile 2 in the C++, so it is profile 2 with
two extra zero blocks prepended. Each `zeros` is a 128-bit zero value.
Note profile 1 orders the nonces differently *and* puts `h2_hash` last.

```
hash = BLAKE2b(stream)
```

### 8. XOR and reverse

```
for i in 0..32:
    final_hash[31 - i] = hash[i] ^ mask[i]
```

The XOR applies the mask from step 2; the index inversion reverses byte
order at the same time. Both happen in one loop in the C++, which is easy
to miss.

`final_hash` is the block hash — the value the chain reports and the one
compared against the target.

## Test vectors

`src/test/data/block_header_v2.json` in Knots, exercised by
`src/test/block_header_tests.cpp`. Five vectors covering all four ASIC
profiles (0-3, plus a second profile-0 case).

They expose **every intermediate**, not just the answer:
`xor_key_hash`, `h1`, `h2`, `blake2b_1`, `blake2b_2`, `mask`,
`asic_input`, `serialized`, `block_hash`.

Assert against all of them. A five-stage construction with four variants
is not something to debug from a single mismatched output at the end.

## Traps

- **Two primitives.** Tagged hashes are SHA256; only steps 6 and 7 are
  BLAKE2b. "The BLAKE2b hash" is a misleading name for the whole thing.
- **Three byte-order reversals** — `prevblock_ordered_sane` in step 3,
  and the index inversion in step 8.
- **Profile 3 is not its own layout**, it is profile 2 with a prefix.
- **`GetTimeOnWire` is conditional** on a flag bit; using `nTime`
  directly is wrong whenever that bit is set.
- **The size assertions are free checks.** 0x10, 119, 0x60 and 52 bytes
  catch a mis-ordered or mis-sized field immediately.
