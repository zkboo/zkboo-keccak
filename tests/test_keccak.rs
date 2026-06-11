// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates Keccak-256 against known vectors (original Keccak, not NIST SHA3-256).

use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_keccak::keccak256;

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

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

fn digest(msg: &[u8]) -> String {
    let out = exec::<_, WP>(&KeccakCircuit { msg: msg.to_vec() }).u8;
    assert_eq!(out.len(), 32);
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
