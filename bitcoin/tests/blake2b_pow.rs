// SPDX-License-Identifier: CC0-1.0

//! Version 2 (BLAKE2b) block header vectors.
//!
//! The vectors are Bitcoin Knots' own `src/test/data/block_header_v2.json`,
//! vendored verbatim. They cover all four ASIC profiles and expose every
//! intermediate of the hash, so a mismatch localizes to a stage instead of
//! failing opaquely at the end.
//!
//! Byte order follows the C++ test: `hashPrevBlock`, `hashMerkleRoot`,
//! `m_mm_rhs`, `m_extranonce` and `m_xor_key` are given in display order and
//! reversed into internal order, while `serialized` is forward bytes.

#![cfg(feature = "blake2b")]

use bitcoin::blockdata::blake2b_pow;
use bitcoin::blockdata::block::{Header, HeaderV2, Version};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, TxMerkleNode};

const VECTORS: &str = include_str!("data/block_header_v2.json");

/// Display-ordered hex into internal byte order.
fn rev_hex<const N: usize>(s: &str) -> [u8; N] {
    let mut bytes: Vec<u8> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    assert_eq!(bytes.len(), N, "expected {} bytes, got {}", N, bytes.len());
    bytes.reverse();
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn v2_test_vectors() {
    let data: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let headers = data["headers"].as_array().expect("headers array");
    assert!(!headers.is_empty());

    let mut profiles_seen = std::collections::BTreeSet::new();

    for test in headers {
        let name = test["name"].as_str().unwrap_or("<unnamed>");
        let f = &test["fields"];

        let v2 = HeaderV2 {
            nonce2: f["m_nonce2"].as_u64().unwrap() as u32,
            nonce3: f["m_nonce3"].as_u64().unwrap() as u32,
            extranonce: rev_hex::<16>(f["m_extranonce"].as_str().unwrap()),
            time_offset: f["m_time_offset"].as_u64().unwrap() as u32,
            txcount: f["m_txcount"].as_u64().unwrap() as u16,
            flags: f["m_flags"].as_u64().unwrap() as u8,
            xor_key_mask_clear_bits: f["m_xor_key_mask_clear_bits"].as_u64().unwrap() as u8,
            xor_key: rev_hex::<16>(f["m_xor_key"].as_str().unwrap()),
            height: f["m_height"].as_i64().unwrap() as i32,
            mm_rhs: rev_hex::<32>(f["m_mm_rhs"].as_str().unwrap()),
        };
        let header = Header {
            version: Version::from_consensus(f["nVersion"].as_i64().unwrap() as i32),
            prev_blockhash: BlockHash::from_byte_array(rev_hex::<32>(
                f["hashPrevBlock"].as_str().unwrap(),
            )),
            merkle_root: TxMerkleNode::from_byte_array(rev_hex::<32>(
                f["hashMerkleRoot"].as_str().unwrap(),
            )),
            time: f["nTime"].as_u64().unwrap() as u32,
            bits: CompactTarget::from_consensus(f["nBits"].as_u64().unwrap() as u32),
            nonce: f["nNonce"].as_u64().unwrap() as u32,
            v2: Some(v2),
        };

        let profile = test["asic_profile"].as_u64().unwrap() as u8;
        assert_eq!(v2.asic_profile(), profile, "{name}: asic profile");
        profiles_seen.insert(profile);

        // Serialization must be byte-exact and 164 bytes.
        let encoded = serialize(&header);
        assert_eq!(encoded.len(), 164, "{name}: serialized length");
        assert_eq!(
            encoded.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            test["serialized"].as_str().unwrap(),
            "{name}: serialized bytes"
        );

        // Every intermediate, so a mismatch says which stage.
        let c = blake2b_pow::components(&header, &v2);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        for (label, got, want) in [
            ("xor_key_hash", hex(&c.xor_key_hash), test["xor_key_hash"].as_str()),
            ("h1", hex(&c.h1), test["h1"].as_str()),
            ("h2", hex(&c.h2), test["h2"].as_str()),
            ("blake2b_1", hex(&c.blake2b_1), test["blake2b_1"].as_str()),
            ("blake2b_2", hex(&c.blake2b_2), test["blake2b_2"].as_str()),
            ("mask", hex(&c.mask), test["mask"].as_str()),
            ("asic_input", hex(&c.asic_input), test["asic_input"].as_str()),
        ] {
            if let Some(want) = want {
                assert_eq!(got, want, "{name}: {label}");
            }
        }

        // The block hash, in display order as the chain reports it.
        assert_eq!(
            header.block_hash().to_string(),
            test["block_hash"].as_str().unwrap(),
            "{name}: block_hash"
        );

        // Round-trip: decoding must recover the header, including the time
        // correction that can only be applied after the flags are read.
        let decoded: Header = deserialize(&encoded).expect("decode");
        assert_eq!(decoded.time, header.time, "{name}: time round-trip");
        assert_eq!(decoded, header, "{name}: round-trip");
        assert_eq!(
            decoded.block_hash().to_string(),
            test["block_hash"].as_str().unwrap(),
            "{name}: decoded block_hash"
        );
    }

    assert_eq!(
        profiles_seen,
        [0u8, 1, 2, 3].into_iter().collect(),
        "vectors must cover all four ASIC profiles"
    );
}
