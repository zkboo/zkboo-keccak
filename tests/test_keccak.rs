// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates Keccak-256 (original Keccak, not NIST SHA3-256) and SHAKE256 against known vectors,
//! and multi-block Keccak-256 against the host-side hasher.

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    crypto::{Hasher, Keccak256Hasher},
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_keccak::{keccak256, shake256};

type WP = OwnedFlexibleWordPool<usize>;

struct KeccakCircuit {
    msg: Vec<u8>,
}

impl Circuit for KeccakCircuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let msg = self
            .msg
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let digest = keccak256(frontend.allocator(), msg);
        digest.into_iter().for_each(|w| frontend.output(w));
    }
}

struct Shake256Circuit {
    msg: Vec<u8>,
    output_len: usize,
}

impl Circuit for Shake256Circuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let msg = self
            .msg
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let out = shake256(frontend.allocator(), msg, self.output_len);
        out.into_iter().for_each(|w| frontend.output(w));
    }
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

fn digest(msg: &[u8]) -> String {
    let out = exec::<_, WP>(&KeccakCircuit { msg: msg.to_vec() }).u8;
    assert_eq!(out.len(), 32);
    return to_hex(&out);
}

fn shake(msg: &[u8], output_len: usize) -> String {
    let out = exec::<_, WP>(&Shake256Circuit {
        msg: msg.to_vec(),
        output_len,
    })
    .u8;
    assert_eq!(out.len(), output_len);
    return to_hex(&out);
}

#[test]
fn test_keccak256_empty() {
    assert_eq!(
        digest(b""),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[test]
fn test_keccak256_abc() {
    assert_eq!(
        digest(b"abc"),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

#[test]
fn test_keccak256_multiblock_matches_host_hasher() {
    for len in [135, 136, 137, 300] {
        let msg = (0..len).map(|i| i as u8).collect::<Vec<u8>>();
        let mut hasher = Keccak256Hasher::new();
        hasher.update(&msg);
        let mut expected = [0u8; 32];
        hasher.finalize_into(&mut expected);
        assert_eq!(digest(&msg), to_hex(&expected), "message length {len}");
    }
}

// SHAKE256 vectors generated with Python hashlib.shake_256.

#[test]
fn test_shake256_empty() {
    assert_eq!(
        shake(b"", 32),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
}

#[test]
fn test_shake256_abc() {
    assert_eq!(
        shake(b"abc", 32),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    );
}

#[test]
fn test_shake256_padding_boundary() {
    // 135-byte message: the domain byte is the final byte of the block, so it also carries 0x80.
    let msg = (0..135u8).collect::<Vec<u8>>();
    assert_eq!(
        shake(&msg, 32),
        "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade0"
    );
    // 136-byte message: exactly one full message block, padding adds a second.
    let msg = (0..136u8).collect::<Vec<u8>>();
    assert_eq!(
        shake(&msg, 32),
        "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a"
    );
}

#[test]
fn test_shake256_multiblock_absorb() {
    assert_eq!(
        shake(&[0u8; 300], 32),
        "1c2824e604d1c48747bcd9ddc63743436dc38c1fec0dfa5a24581a6570cee7b0"
    );
}

#[test]
fn test_shake256_multiblock_squeeze() {
    assert_eq!(
        shake(b"abc", 200),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
         d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4\
         1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78\
         dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334\
         e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3\
         3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67\
         7513771af6bfe119"
    );
}
