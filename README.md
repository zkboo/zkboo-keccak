# ZKBoo-Keccak

![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)

Keccak-256 (as used by Ethereum) and SHAKE256 (FIPS 202, as used by SLH-DSA) as [ZKBoo](https://crates.io/crates/zkboo) circuits.

Both are sponges over the full Keccak-f[1600] permutation (θ, ρ, π, χ, ι over 24 rounds) on a 25-lane u64 state at a 136-byte rate, which is bitwise-heavy and therefore a natural fit for ZKBoo.
Messages of arbitrary length are supported, and SHAKE256 squeezes output of arbitrary length.

Keccak-256 here is the **original Keccak** (domain-separation byte `0x01`), *not* NIST SHA3-256 (`0x06`) — Ethereum hashes with Keccak.
SHAKE256 uses the standard FIPS 202 domain-separation byte `0x1F`.

```rust
use zkboo_keccak::{keccak256, shake256};
// inside a Circuit::exec, given `msg: Vec<WordRef<B, u8>>`:
let digest = keccak256(frontend.allocator(), msg); // [WordRef<B, u8>; 32]
let xof = shake256(frontend.allocator(), msg, 64); // Vec<WordRef<B, u8>> of the requested length
```

Validated against Keccak-256 and SHAKE256 known-answer vectors (including padding-boundary and multi-block cases) and against the host-side Keccak-256 hasher.
Used by [`zkboo-bip32`](https://crates.io/crates/zkboo-bip32) for Ethereum address derivation and by `zkboo-slhdsa` for SLH-DSA (SPHINCS+) hashing.

## ⚠️ Unaudited ⚠️

The public API is stable as of 1.0.0, but this implementation has not undergone an external
security review.
Use at your own risk.

## License

[LGPLv3 © contributors.](LICENSE)
