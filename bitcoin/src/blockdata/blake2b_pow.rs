// SPDX-License-Identifier: CC0-1.0

#![doc = include_str!("blake2b_pow.md")]

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use hashes::{sha256, Hash, HashEngine};

use super::block::{Header, HeaderV2, USE_TIME_OFFSET};
use crate::prelude::*;

/// 16 zero bytes — the `uint128 zeros` of the reference implementation.
const ZEROS: [u8; 16] = [0u8; 16];

/// A BIP340-style tagged SHA256 engine, pre-loaded with `SHA256(tag)` twice.
fn tagged(tag: &str) -> sha256::HashEngine {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine
}

fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Every intermediate of the v2 proof-of-work hash.
///
/// Returned whole because the reference test vectors assert each stage
/// individually, so a mismatch localizes instead of failing at the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Components {
    /// Stage 1 — `SHA256` of the tagged XOR key.
    pub xor_key_hash: [u8; 32],
    /// Stage 2 — the XOR mask, after clearing its leading bits.
    pub mask: [u8; 32],
    /// Stage 4 — the tagged hash of the byte-reversed previous block hash.
    pub prevblock_hidden: [u8; 32],
    /// Stage 5 — the fields hidden from the mining machine.
    pub h1: [u8; 32],
    /// Stage 6 — the merge-mining hook.
    pub h2: [u8; 32],
    /// Stage 7 — BLAKE2b over the Stratum v1 payload.
    pub blake2b_1: [u8; 32],
    /// Stage 7's 52-byte input.
    pub sv1_input: [u8; 52],
    /// Stage 8 — BLAKE2b over the ASIC profile stream.
    pub blake2b_2: [u8; 32],
    /// Stage 8's input, whose layout depends on the ASIC profile.
    pub asic_input: Vec<u8>,
    /// Stage 9 — the block hash: `blake2b_2` XOR `mask`, byte-reversed.
    pub block_hash: [u8; 32],
}

/// Computes the version 2 proof-of-work hash, and every intermediate.
///
/// See the module documentation for what each stage is and why.
pub fn components(header: &Header, v2: &HeaderV2) -> Components {
    // ── 1. XOR key hash ─────────────────────────────────────────────────
    let mut e = tagged("Bitcoin block hash PoW XOR key");
    e.input(&v2.xor_key);
    let xor_key_hash = sha256::Hash::from_engine(e).to_byte_array();

    // ── 2. XOR mask ─────────────────────────────────────────────────────
    // Zero when the key is null. The leading bits are cleared so the mask
    // cannot affect the difficulty comparison.
    let mut mask = [0u8; 32];
    if v2.xor_key != ZEROS {
        let mut e = tagged("Bitcoin block hash PoW XOR mask");
        e.input(&v2.xor_key);
        mask = sha256::Hash::from_engine(e).to_byte_array();
        let clear_bytes = (v2.xor_key_mask_clear_bits / 8) as usize;
        for b in mask.iter_mut().take(clear_bytes) {
            *b = 0;
        }
        if clear_bytes < mask.len() {
            mask[clear_bytes] &= 0xffu8 >> (v2.xor_key_mask_clear_bits % 8);
        }
    }

    // ── 3-4. Hidden previous block ──────────────────────────────────────
    let mut prevblock_sane = header.prev_blockhash.to_byte_array();
    prevblock_sane.reverse();
    let mut e = tagged("Bitcoin prevblock header, hashed");
    e.input(&prevblock_sane);
    let prevblock_hidden = sha256::Hash::from_engine(e).to_byte_array();

    // ── 5. h1 — invisible to the mining machine ─────────────────────────
    let mut e = tagged("Bitcoin block header 1");
    e.input(&header.version_on_wire().to_le_bytes());
    e.input(&prevblock_sane);
    e.input(&v2.height.to_le_bytes());
    e.input(&header.merkle_root.to_byte_array());
    e.input(&header.time_on_wire().to_le_bytes());
    e.input(&[0u8]); // reserved for extended 40-bit time
    e.input(&header.bits.to_consensus().to_le_bytes());
    e.input(&u32::from(v2.txcount).to_le_bytes());
    e.input(&[v2.flags]);
    e.input(&[v2.xor_key_mask_clear_bits]);
    e.input(&xor_key_hash);
    let h1 = sha256::Hash::from_engine(e).to_byte_array();

    // ── 6. h2 — the merge-mining hook ───────────────────────────────────
    let mut e = tagged("Merge-mining hook");
    e.input(&h1);
    e.input(&ZEROS);
    e.input(&ZEROS);
    e.input(&v2.mm_rhs);
    let h2 = sha256::Hash::from_engine(e).to_byte_array();

    // ── 7. First BLAKE2b — the Stratum v1 payload ───────────────────────
    let mut sv1_input = [0u8; 52];
    sv1_input[4..36].copy_from_slice(&h2);
    sv1_input[36..52].copy_from_slice(&v2.extranonce);
    let blake2b_1 = blake2b256(&sv1_input);

    // ── 8. Second BLAKE2b — the ASIC profile ────────────────────────────
    let mut asic_input: Vec<u8> = Vec::new();
    let tail = |out: &mut Vec<u8>| {
        out.extend_from_slice(&header.nonce.to_le_bytes());
        out.extend_from_slice(&v2.nonce2.to_le_bytes());
        out.extend_from_slice(&v2.time_offset.to_le_bytes());
        out.extend_from_slice(&v2.nonce3.to_le_bytes());
        out.extend_from_slice(&blake2b_1);
    };
    match v2.asic_profile() {
        0 => {
            let mut hidden = prevblock_hidden;
            hidden[..6].fill(0);
            asic_input.extend_from_slice(&hidden);
            tail(&mut asic_input);
        }
        1 => {
            asic_input.extend_from_slice(&header.nonce.to_le_bytes());
            asic_input.extend_from_slice(&v2.nonce2.to_le_bytes());
            asic_input.extend_from_slice(&v2.nonce3.to_le_bytes());
            asic_input.extend_from_slice(&v2.time_offset.to_le_bytes());
            asic_input.extend_from_slice(&blake2b_1);
            asic_input.extend_from_slice(&h2);
        }
        profile => {
            // Profile 3 is profile 2 with two extra zero blocks prepended;
            // the reference implementation falls through.
            if profile == 3 {
                asic_input.extend_from_slice(&ZEROS);
                asic_input.extend_from_slice(&ZEROS);
            }
            asic_input.extend_from_slice(&ZEROS);
            asic_input.extend_from_slice(&ZEROS);
            asic_input.extend_from_slice(&ZEROS);
            asic_input.extend_from_slice(&h2);
            tail(&mut asic_input);
        }
    }
    let blake2b_2 = blake2b256(&asic_input);

    // ── 9. XOR with the mask, reversing byte order ──────────────────────
    let mut block_hash = [0u8; 32];
    for i in 0..32 {
        block_hash[31 - i] = blake2b_2[i] ^ mask[i];
    }

    Components {
        xor_key_hash,
        mask,
        prevblock_hidden,
        h1,
        h2,
        blake2b_1,
        sv1_input,
        blake2b_2,
        asic_input,
        block_hash,
    }
}

/// Whether this header's flags select the time-offset encoding.
pub fn uses_time_offset(v2: &HeaderV2) -> bool { v2.flags & USE_TIME_OFFSET != 0 }
