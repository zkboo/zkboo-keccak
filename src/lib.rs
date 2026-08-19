// SPDX-License-Identifier: LGPL-3.0-or-later

//! Keccak-based hashing as [zkboo] circuits: Keccak-256 (as used by Ethereum) and the
//! SHAKE256 extendable-output function (as used by SLH-DSA, FIPS 205).
//!
//! Both are sponges over the Keccak-f[1600] permutation with a 136-byte rate, differing only in
//! the domain-separation byte (`0x01` for original Keccak, `0x1F` for SHAKE) and the output
//! length (fixed 32 bytes for Keccak-256, arbitrary for SHAKE256). Messages of arbitrary length
//! are supported, absorbed one 136-byte block at a time.
//!
//! Note that Keccak-256 here is the original Keccak (domain-separation byte `0x01`), *not* NIST
//! SHA3-256 (`0x06`) — Ethereum hashes with Keccak.
//!
//! See <https://keccak.team/keccak_specs_summary.html>.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};

/// The Keccak-256/SHAKE256 rate in bytes (1088 bits): the number of message bytes absorbed (and
/// output bytes squeezed) per block.
pub const RATE_BYTES: usize = 136;

/// The domain-separation byte of the original Keccak (as used by Ethereum).
const KECCAK_DOMAIN: u8 = 0x01;

/// The domain-separation byte of the SHAKE extendable-output functions (FIPS 202).
const SHAKE_DOMAIN: u8 = 0x1F;

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

/// The Keccak sponge at rate 136: pads `msg` with pad10*1 under the given domain-separation byte,
/// absorbs it block by block, and squeezes `output_len` bytes.
fn sponge<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
    domain: u8,
    output_len: usize,
) -> Vec<WordRef<B, u8>> {
    // pad10*1: P = msg || domain || 0x00.. || (last |= 0x80), to a multiple of the rate.
    // The 0x80 is XORed in, which is an OR here since bit 7 of both `domain` and 0x00 is clear.
    let mut padded = msg;
    padded.push(allocator.alloc(domain));
    while padded.len() % RATE_BYTES != 0 {
        padded.push(allocator.alloc(0x00u8));
    }
    let last = padded.pop().expect("padded block is non-empty");
    padded.push(last ^ 0x80u8);

    // Absorb: XOR each 136-byte block into the first 17 lanes (little-endian) and permute.
    let mut state: [WordRef<B, u64, 1>; 25] = core::array::from_fn(|_| allocator.alloc(0u64));
    for block in padded.chunks_exact(RATE_BYTES) {
        for i in 0..RATE_BYTES / 8 {
            let lane_bytes = block[8 * i..8 * i + 8].iter().cloned().collect::<Vec<_>>();
            let lane = WordRef::<B, u64, 1>::from_le_bytes(lane_bytes).expect("8 bytes per lane");
            state[i] = state[i].clone() ^ lane;
        }
        keccak_f(&mut state);
    }

    // Squeeze: read rate-many bytes per block (lanes 0..17, little-endian), permuting between blocks.
    let mut out: Vec<WordRef<B, u8>> = Vec::with_capacity(output_len);
    loop {
        for lane in state.iter().take(RATE_BYTES / 8) {
            for byte in lane.clone().into_le_bytes() {
                if out.len() == output_len {
                    return out;
                }
                out.push(byte);
            }
        }
        keccak_f(&mut state);
    }
}

/// Computes the Keccak-256 digest of a message of arbitrary length.
pub fn keccak256<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 32] {
    return sponge(allocator, msg, KECCAK_DOMAIN, 32)
        .try_into()
        .ok()
        .expect("32 output bytes");
}

/// Computes `output_len` bytes of SHAKE256 output for a message of arbitrary length.
pub fn shake256<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
    output_len: usize,
) -> Vec<WordRef<B, u8>> {
    return sponge(allocator, msg, SHAKE_DOMAIN, output_len);
}
