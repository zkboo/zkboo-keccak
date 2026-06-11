// SPDX-License-Identifier: LGPL-3.0-or-later

//! Keccak-256 (as used by Ethereum) as a [zkboo] circuit.
//!
//! This is the original Keccak (domain-separation byte `0x01`), *not* NIST SHA3-256 (`0x06`).
//! Only single-block messages (`< 136` bytes) are supported, which covers the Ethereum use case
//! (hashing a 64-byte public key).
//!
//! See <https://keccak.team/keccak_specs_summary.html>.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};

/// The Keccak-256 rate in bytes (1088 bits): the number of message bytes absorbed per block.
pub const RATE_BYTES: usize = 136;

/// Keccak lane rotation offsets `r[x][y]` for the ρ step.
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Round constants for the ι step.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// In-place Keccak-f[1600] permutation over a 25-lane state (lane `(x, y)` at index `x + 5y`).
fn keccak_f<B: Backend>(a: &mut [WordRef<B, u64, 1>; 25]) {
    for round in 0..24 {
        // θ
        let c: [WordRef<B, u64, 1>; 5] = core::array::from_fn(|x| {
            a[x].clone() ^ a[x + 5].clone() ^ a[x + 10].clone() ^ a[x + 15].clone()
                ^ a[x + 20].clone()
        });
        let d: [WordRef<B, u64, 1>; 5] =
            core::array::from_fn(|x| c[(x + 4) % 5].clone() ^ c[(x + 1) % 5].clone().rotate_left(1));
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = a[x + 5 * y].clone() ^ d[x].clone();
            }
        }

        // ρ and π: B[y, 2x+3y] = rot(A[x,y], r[x][y]).
        let mut b: [WordRef<B, u64, 1>; 25] = core::array::from_fn(|i| a[i].clone());
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    a[x + 5 * y].clone().rotate_left(RHO[x][y] as usize);
            }
        }

        // χ: A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]).
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y].clone()
                    ^ ((!b[(x + 1) % 5 + 5 * y].clone()) & b[(x + 2) % 5 + 5 * y].clone());
            }
        }

        // ι
        a[0] = a[0].clone() ^ RC[round];
    }
}

/// Computes the Keccak-256 digest of a single-block message (`msg.len() < 136`).
///
/// `msg` is consumed; the 32-byte digest is returned.
pub fn keccak256<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 32] {
    assert!(
        msg.len() < RATE_BYTES,
        "only single-block keccak256 is supported (msg < 136 bytes)"
    );

    // pad10*1 with Keccak domain byte 0x01: P = msg || 0x01 || 0x00.. || (last |= 0x80).
    let mut padded = msg;
    padded.push(allocator.alloc(0x01u8));
    while padded.len() < RATE_BYTES {
        padded.push(allocator.alloc(0x00u8));
    }
    let last = padded.pop().expect("padded block is non-empty");
    padded.push(last ^ 0x80u8);

    // Absorb the single block into the (zero) state: the first 17 lanes are the message lanes
    // (little-endian), the remaining 8 are zero.
    let mut state: [WordRef<B, u64, 1>; 25] = core::array::from_fn(|i| {
        if i < RATE_BYTES / 8 {
            let lane_bytes = padded[8 * i..8 * i + 8].iter().cloned().collect::<Vec<_>>();
            WordRef::<B, u64, 1>::from_le_bytes(lane_bytes).expect("8 bytes per lane")
        } else {
            allocator.alloc(0u64)
        }
    });

    keccak_f(&mut state);

    // Squeeze the first 256 bits: lanes 0..4, little-endian bytes.
    let mut out: Vec<WordRef<B, u8>> = Vec::with_capacity(32);
    for lane in state.into_iter().take(4) {
        out.extend(lane.into_le_bytes());
    }
    return out.try_into().ok().expect("32 output bytes");
}
