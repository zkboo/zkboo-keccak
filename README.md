# ZKBoo-Keccak

![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)

Keccak-256 (as used by Ethereum) as a [ZKBoo](https://crates.io/crates/zkboo) circuit.

This is the **original Keccak** (domain-separation byte `0x01`), *not* NIST SHA3-256 (`0x06`) —
Ethereum hashes with Keccak. It implements the full Keccak-f[1600] permutation (θ, ρ, π, χ, ι over
24 rounds) on a 25-lane u64 state, which is bitwise-heavy and therefore a natural fit for ZKBoo.

Only single-block messages (`< 136` bytes) are supported, which covers the Ethereum use case of
hashing a 64-byte public key for address derivation.

```rust
use zkboo_keccak::keccak256;
// inside a Circuit::exec, given `msg: Vec<WordRef<B, u8>>`:
let digest = keccak256(frontend.allocator(), msg); // [WordRef<B, u8>; 32]
```

Validated against the empty-string and `"abc"` Keccak-256 vectors. Used by
[`zkboo-bip32`](https://crates.io/crates/zkboo-bip32) for Ethereum address derivation.

## 🚧 Warning 🚧

Work in progress, not yet suitable for production. Security has not been audited.

## License

[LGPLv3 © contributors.](LICENSE)
