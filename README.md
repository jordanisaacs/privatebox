[![PrivateBox](https://github.com/jordanisaacs/privatebox/actions/workflows/rust.yml/badge.svg)](https://github.com/jordanisaacs/privatebox)
[![crates.io](https://img.shields.io/crates/v/privatebox.svg)](https://crates.io/crates/privatebox)
[![docs.rs](https://docs.rs/privatebox/badge.svg)](https://docs.rs/privatebox/)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jordanisaacs/privatebox/blob/master/LICENSE)

# PrivateBox

PrivateBox provides a small and easy to use API to encrypt your data. It is meant to do one thing, be a simple wrapper and validator around the RustCrypto [XChaCha20Poly1305 AEAD](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) encryption algorithm.

PrivateBox is inspired/based off of [Cocoon](https://github.com/fadeevab/cocoon/blob/master/README.md). PrivateBox is meant to be a smaller API, more flexible with associated data, and uses XChaCha for random nonces.

To use add to Cargo.toml:
```
privatebox = "0.1.1"
```

## Generating a key

The examples just use array generation for the key to keep the code duplication down. However, keys should be random or pseudo-random (aka derived from something like a password).

Example:

```rust
use rand_core::{OsRng, RngCore};

let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);
```

## Detached Encryption/Decryption

Detached encryption/decryption methods compute in place to avoid re-allocations. It returns a prefix (the nonce and tag) that is used for decryption. This is suitable for a `no_std` build, when you want to avoid re-allocations of data, and if you want to manage serialization yourself.

Example:

```rust
let mut privatebox = PrivateBox::new(&[1;32], OsRng);

let mut message = *b"secret data";
let assoc_data = *b"plain text";

let detached_prefix = privatebox.encrypt_detached(&mut message, &assoc_data)?;
assert_ne!(&message, b"secret data");

privatebox.decrypt_detached(&mut message, &assoc_data, &detached_prefix)?;
assert_eq!(&message, b"secret data");
```

See the docs for examples and more information.

## PrivateBox Container

The encrypt/decrypt methods handle serialization for you and returns a container. It enables the easy use of stored associated data and separate associated data. It is much simpler to use than detached encryption/decryption. It uses `alloc` (enabled by default).

Example:

```rust
let mut privatebox = PrivateBox::new(&[1; 32], OsRng);
let header = &[5, 4, 3, 2];
let metadata = &[3, 3, 3];

let wrapped = privatebox.encrypt(b"secret data", header, metadata).expect("encrypt");
let (message, authenticated_header) = privatebox.decrypt(&wrapped, metadata).expect("decrypt");

assert_eq!(message, b"secret data");
assert_eq!(&authenticated_header, header);
```

See the docs for examples and more information.
