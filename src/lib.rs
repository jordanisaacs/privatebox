#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]
#![no_std]

//! # PrivateBox
//!
//! PrivateBox provides a small and easy to use API to encrypt your data.
//! It is meant to do one thing, be a simple wrapper and validator around the RustCrypto XChaCha20Poly1305 AEAD encryption algorithm.
//!
//! PrivateBox is inspired/based off of [Cocoon](https://github.com/fadeevab/cocoon/blob/master/README.md).
//! PrivateBox is meant to be a smaller API, more flexible with associated data, and uses XChaCha for random nonces.
//! ## Generating a key
//!
//! The examples just use array generation for the key to keep the code duplication down. However, keys should be random or pseudo-random (aka derived from something like a password).
//!
//! Example:
//!
//! ```
//! use rand_core::{OsRng, RngCore};
//!
//! let mut key = [0u8; 32];
//! OsRng.fill_bytes(&mut key);
//! ```
//!
//! ## Detached Encryption/Decryption
//!
//! The [`PrivateBox::encrypt_detached`]/[`PrivateBox::decrypt_detached`] methods compute in place to avoid re-allocations.
//! It returns a prefix (the nonce and tag) that is used for decryption.
//! This is suitable for a `no_std` build, when you want to avoid re-allocations of data,
//! and if you want to manage serialization yourself.
//!
//! Example:
//!
//! ```
//! # use privatebox::{PrivateBox, PrivateBoxError};
//! # use rand_core::OsRng;
//! #
//! # fn main() -> Result<(), PrivateBoxError> {
//! let mut privatebox = PrivateBox::new(&[1;32], OsRng); 
//!
//! let mut message = *b"secret data";
//! let assoc_data = *b"plain text";
//!
//! let detached_prefix = privatebox.encrypt_detached(&mut message, &assoc_data)?;
//! assert_ne!(&message, b"secret data");
//!
//! privatebox.decrypt_detached(&mut message, &assoc_data, &detached_prefix)?;
//! assert_eq!(&message, b"secret data");
//! # Ok(())
//! # }
//! ```
//!
//! ## PrivateBox Container
//! 
//! The [`PrivateBox::encrypt`]/[`PrivateBox::decrypt`] methods handle serialization for you and returns a container.
//! It enables the use of both attached associated data and detached associated data.
//! It is much simpler to use than detached encryption/decryption.
//! It uses the `alloc` feature (enabled by default).
//! 
//! Example:
//! 
//! ```
//! # use privatebox::{PrivateBox, PrivateBoxError};
//! # use rand_core::OsRng;
//! #
//! # fn main() -> Result<(), PrivateBoxError> {
//! let mut privatebox = PrivateBox::new(&[1; 32], OsRng);
//! 
//! let header = &[5, 4, 3, 2];
//! let metadata = &[3, 3, 3];
//! 
//! let wrapped = privatebox.encrypt(b"secret data", header, metadata).expect("encrypt");
//! let (message, authenticated_header) = privatebox.decrypt(&wrapped, metadata).expect("decrypt");
//! 
//! assert_eq!(message, b"secret data");
//! assert_eq!(&authenticated_header, header);
//! # Ok(())
//! # }
//! ```
//! 

use rand_core::RngCore;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key, Tag};
use chacha20poly1305::aead::{NewAead, AeadInPlace};
use zeroize::Zeroizing;
use core::convert::{TryFrom, TryInto};
use core::usize;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Max size of message and header byte array
pub const MAX_DATA_SIZE: usize = 8;
/// Size of XChaCha nonce
pub const NONCE_SIZE: usize = 24;
/// Size of authentication tag
pub const TAG_SIZE: usize = 16;
/// Size of encryption key
pub const KEY_SIZE: usize = 32;
/// Size of detached prefix
pub const PREFIX_SIZE: usize = NONCE_SIZE + TAG_SIZE;

/// Error variants provided by the PrivateBox API
#[derive(Debug)]
pub enum PrivateBoxError {
    /// Cryptographic error. Integrity is compromised
    Cryptography,
    /// Format is corrupted
    UnrecognizedFormat,
    /// Message size is too large to be processed by architecture
    MessageTooLarge,
    /// Header size is too large to be processed by architecture
    HeaderTooLarge,
}

#[derive(Debug)]
struct PrivateBoxDataSizes {
    header_size: usize,
    message_size: usize,
}
impl PrivateBoxDataSizes {
    const SIZE: usize = MAX_DATA_SIZE + MAX_DATA_SIZE;

    fn new (header_size: usize, message_size: usize) -> Self {
        PrivateBoxDataSizes { header_size, message_size }
    }

    fn header_size(&self) -> usize {
        self.header_size
    }

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        self.serialize_into(&mut buf);
        buf
    }

    fn serialize_into(&self, buf: &mut [u8; Self::SIZE]) {
        let header = u64::try_from(self.header_size).expect("Header too large").to_be_bytes();
        let message = u64::try_from(self.message_size).expect("Message too large").to_be_bytes();
        buf[..MAX_DATA_SIZE].copy_from_slice(&header);
        buf[MAX_DATA_SIZE..Self::SIZE].copy_from_slice(&message);
    }

    fn deserialize(start: &[u8]) -> Result<Self, PrivateBoxError> {
        if start.len() < Self::SIZE {
            return Err(PrivateBoxError::UnrecognizedFormat);
        }

        let mut header_size = [0u8; MAX_DATA_SIZE];
        header_size.copy_from_slice(&start[..MAX_DATA_SIZE]);
        let header_size = u64::from_be_bytes(header_size)
            .try_into()
            .map_err(|_| PrivateBoxError::HeaderTooLarge)?;

        let mut message_size = [0u8; MAX_DATA_SIZE];
        message_size.copy_from_slice(&start[MAX_DATA_SIZE..Self::SIZE]);
        let message_size = u64::from_be_bytes(message_size)
            .try_into()
            .map_err(|_| PrivateBoxError::MessageTooLarge)?;
        
        Ok(PrivateBoxDataSizes { header_size, message_size })
    }
}

#[derive(Debug)]
struct PrivateBoxPrefix {
    nonce: XNonce,
    tag: Tag,
}
impl PrivateBoxPrefix {
    const SIZE: usize = PREFIX_SIZE;

    fn new (nonce: XNonce, tag: Tag) -> Self {
        PrivateBoxPrefix { nonce, tag }
    }

    fn nonce(&self) -> &XNonce {
        &self.nonce
    }

    fn tag(&self) -> &Tag {
        &self.tag
    }

    fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf =  [0u8; Self::SIZE];
        self.serialize_into(&mut buf);
        buf
    }

    fn serialize_into(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= Self::SIZE);

        buf[..NONCE_SIZE].copy_from_slice(&self.nonce);
        buf[NONCE_SIZE..].copy_from_slice(&self.tag);
    }

    fn deserialize(start: &[u8]) -> Result<Self, PrivateBoxError> {
        if start.len() < Self::SIZE {
            return Err(PrivateBoxError::UnrecognizedFormat)
        }

        let nonce = *XNonce::from_slice(&start[..NONCE_SIZE]);
        
        let tag = *Tag::from_slice(&start[NONCE_SIZE..PrivateBoxPrefix::SIZE]);

        Ok(PrivateBoxPrefix {
            nonce,
            tag
        })
    }
}

/// A wrapper around XChaChaPoly1305 for convenient encryption
pub struct PrivateBox<T: RngCore> {
    key: Zeroizing<[u8; KEY_SIZE]>,
    rng: T,
}
/// Generates basic containers that store encrypted data
///
/// # Basic Usage
/// ```
/// # use privatebox::{PrivateBox, PrivateBoxError};
/// # use rand_core::OsRng;
/// #
/// # fn main() -> Result<(), PrivateBoxError> {
/// let mut privatebox = PrivateBox::new(b"0123456789abcdef0123456789abcdef", OsRng);
/// let header = b"stored plain text";
/// let metadata = b"plain text";
///
/// let container = privatebox.encrypt(b"secret data", &*header, &*metadata)?;
/// assert_ne!(&container, b"secret data");
///
/// let (decrypted_message, authenticated_header) = privatebox.decrypt(&container, &*metadata)?;
/// assert_eq!(decrypted_message, b"secret data");
/// assert_eq!(authenticated_header, b"stored plain text");
/// # Ok(())
/// # }
/// ```
///
/// # Associated Data
/// Associated data in an AEAD is data that is authenticated but not encrypted.
/// It is provided during the encryption and decryption stage. It does not
/// necessarily have to be stored with the ciphertext. Hence [`PrivateBox::encrypt`]
/// has an authenticated `header` (stored in container) and `metadata` (stored separately).
/// The metadata thus is provided separately from the container during [`PrivateBox::decrypt`]. When doing
/// detached encryption/decryption there is just `assoc_data` as storage is handled
/// by user. For use cases check out this [stackexchange answer](https://security.stackexchange.com/questions/179273/what-is-the-purpose-of-associated-authenticated-data-in-aead#:~:text=As%20a%20very%20general%20rule,can%20be%20detected%20and%20rejected.)
///
/// # Nonces
/// Nonces are arbitrary numbers used in encryption and are one time use per key.
/// PrivateBox uses XChaChaPoly1305 which is ChaChaPoly1305 with an extended nonce (24 bytes instead of 12).
/// Therefore it is OK ([libsodium ref](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)) to use a random number generator for nonce generation.
/// The random number generator provided upon the creation of PrivateBox is used to generate nonces.
/// The generator is not cloned during encryption so each pass produces a different nonce.
///
/// # Features
/// Enabling `alloc` (on by default) lets you access [`PrivateBox::encrypt`] and [`PrivateBox::decrypt`]
impl<T: RngCore> PrivateBox<T> {
    /// Creates a new [`PrivateBox`]  with a symmetric key and a random number generator
    ///
    /// * `key` - a 32 byte symmetric key
    /// * `rng` - a random number generator that generates nonces, implements [`RngCore`]
    ///
    /// # Examples
    /// ```
    /// use privatebox::PrivateBox;
    /// use rand_core::{RngCore, OsRng};
    ///
    /// // Key must have a length of 32 bytes.
    /// let mut key = [0u8; 32];
    /// OsRng.fill_bytes(&mut key);
    ///
    /// let privatebox = PrivateBox::new(&key, OsRng);
    /// ```
    pub fn new(key: &[u8; 32], rng: T) -> Self {
        let mut k = [0u8; KEY_SIZE];
        k.copy_from_slice(key);

        let key = Zeroizing::new(k);

        PrivateBox {
            key,
            rng
        }
    }

    /// Encrypts message in place with associated data and returns a detached prefix for the data.
    ///
    /// * `message` - data to be encrypted in place
    /// * `assoc_data` - associated data to be used
    ///
    /// The prefix is needed to decrypt the data with [`PrivateBox::decrypt`]
    /// The prefix is an array of bytes with nonce first, tag second.
    ///
    /// This method does not use memory allocation and suitable in the build without [`alloc`]
    ///
    /// # Examples
    /// ```
    /// # use privatebox::{PrivateBox, PrivateBoxError};
    /// # use rand_core::OsRng;
    /// #
    /// # fn main() -> Result<(), PrivateBoxError> {
    /// let mut privatebox = PrivateBox::new(&[1;32], OsRng); 
    ///
    /// let mut message = *b"secret data";
    /// let assoc_data = *b"plain text";
    ///
    /// let detached_prefix = privatebox.encrypt_detached(&mut message, &assoc_data);
    /// assert_ne!(&message, b"secret data");
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt_detached(&mut self, data: &mut [u8], assoc_data: &[u8]) -> Result<[u8; PREFIX_SIZE], PrivateBoxError> {
        let mut nonce = [0_u8; NONCE_SIZE];
        self.rng.fill_bytes(&mut nonce);
        let nonce = XNonce::from_slice(&nonce);

        let key = Key::from_slice(self.key.as_ref());
        let aead = XChaCha20Poly1305::new(key);

        let tag: Tag = aead
            .encrypt_in_place_detached(nonce, assoc_data, data)
            .map_err(|_| PrivateBoxError::Cryptography)?;
        

        let prefix = PrivateBoxPrefix::new(*nonce, tag).serialize();

        Ok(prefix)
    }
 
    /// Decrypts message in place using associated data and prefix returned by the [`PrivateBox::encrypt`] method.
    ///
    /// * `message` - data to be encrypted in place
    /// * `assoc_data` - associated data to be used in decryption
    ///
    /// The method doesn't use memory allocation and is suitable in the build without [`alloc`]
    ///
    /// # Examples
    /// ```
    /// # use privatebox::{PrivateBox, PrivateBoxError};
    /// # use rand_core::OsRng;
    /// #
    /// # fn main() -> Result<(), PrivateBoxError> {
    /// let mut privatebox = PrivateBox::new(&[1;32], OsRng); 
    ///
    /// let mut message = *b"secret data";
    ///
    /// let detached_prefix = privatebox.encrypt_detached(&mut message, &[])?;
    /// assert_ne!(&message, b"secret data");
    ///
    /// privatebox.decrypt_detached(&mut message, &[], &detached_prefix)?;
    /// assert_eq!(&message, b"secret data");
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt_detached(&self, message: &mut [u8], assoc_data: &[u8], detached_prefix: &[u8; PREFIX_SIZE]) -> Result<(), PrivateBoxError> {
        let detached_prefix = PrivateBoxPrefix::deserialize(detached_prefix)?;
        
        self.decrypt_detached_parsed(message, assoc_data, &detached_prefix)?;
        Ok(())
    }

    fn decrypt_detached_parsed(&self, message: &mut [u8], assoc_data: &[u8], detached_prefix: &PrivateBoxPrefix) -> Result<(), PrivateBoxError> {
        let key = Key::from_slice(self.key.as_ref());
        let aead = XChaCha20Poly1305::new(key);

        aead.decrypt_in_place_detached(detached_prefix.nonce(), assoc_data, message, detached_prefix.tag())
            .map_err(|_| PrivateBoxError::Cryptography)?;
        
        Ok(())
    }

    /// Encrypts message and outputs a container with all necessary data to decrypt
    ///
    /// * `message` - data to be encrypted
    /// * `header` - data to be authenticated and stored in the container
    /// * `metadata` - data to be authenticated but not stored
    ///
    /// # Examples
    /// ```
    /// # use privatebox::{PrivateBox, PrivateBoxError};
    /// # use rand_core::OsRng;
    /// #
    /// # fn main() -> Result<(), PrivateBoxError> {
    /// let mut privatebox = PrivateBox::new(&[1;32], OsRng); 
    ///
    /// let message = *b"secret data";
    /// let header = *b"attached data";
    /// let metadata = *b"detached data";
    ///
    /// let container = privatebox.encrypt(&message, &header, &metadata)?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docs_rs, doc(cfg(any(feature = "alloc"))))]
    pub fn encrypt(&mut self, message: &[u8], header: &[u8], metadata: &[u8]) -> Result<Vec<u8>, PrivateBoxError> {
        let sizes = PrivateBoxDataSizes::new(header.len(), message.len());

        let mut container = Vec::with_capacity(PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.message_size() + sizes.header_size());
        container.extend_from_slice(&[0; PrivateBoxPrefix::SIZE]);
        container.extend_from_slice(&sizes.serialize());
        container.extend_from_slice(header);
        container.extend_from_slice(message);

        let body = &mut container[PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.header_size()..];

        let assoc_data = [header, metadata].concat();

        let detached_prefix = self.encrypt_detached(body, &assoc_data)?;

        container[..PrivateBoxPrefix::SIZE].copy_from_slice(&detached_prefix);

        Ok(container)
    }

    /// Decrypts a container and outputs the authenticated header and decrypted message
    ///
    /// During decryption the header and provided `metadata` is concatenated to produce the
    /// full associated data. Successful decryption means that the provided metadata was authenticated.
    ///
    /// * `container` - the container outputed by [`PrivateBox::encrypt`]
    /// * `metadata` - authenticated data not stored in the container
    ///
    /// # Examples
    /// ```
    /// # use privatebox::{PrivateBox, PrivateBoxError};
    /// # use rand_core::OsRng;
    /// #
    /// # fn main() -> Result<(), PrivateBoxError> {
    /// let mut privatebox = PrivateBox::new(&[1;32], OsRng); 
    ///
    /// let message = *b"secret data";
    /// let header = *b"attached data";
    /// let metadata = *b"detached data";
    ///
    /// let container = privatebox.encrypt(&message, &header, &metadata)?;
    ///
    /// // Note only the metadata is required for decryption
    /// let (decrypted_message, authenticated_header) = privatebox.decrypt(&container, &metadata)?;
    /// assert_eq!(&decrypted_message, &message);
    /// assert_eq!(&authenticated_header, &header);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docs_rs, doc(cfg(any(feature = "alloc"))))]
    pub fn decrypt(&self, container: &[u8], metadata: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PrivateBoxError> {
        if container.len() < PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE  {
            return Err(PrivateBoxError::UnrecognizedFormat)
        }

        let sizes = PrivateBoxDataSizes::deserialize(&container[PrivateBoxPrefix::SIZE..])?;
        if container.len() < PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.message_size() + sizes.header_size() {
            return Err(PrivateBoxError::UnrecognizedFormat)
        }

        let prefix = PrivateBoxPrefix::deserialize(&container)?;
        let header_data = &container[PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE..PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.header_size()];

        let mut message = Vec::with_capacity(sizes.message_size());

        message.extend_from_slice(&container[
            PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.header_size()
            ..
            PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.header_size() + sizes.message_size()
        ]);

        let assoc_data = [header_data, metadata].concat();
        self.decrypt_detached_parsed(&mut message, &assoc_data, &prefix)?;
        
        let mut header = Vec::with_capacity(sizes.message_size());
        header.extend_from_slice(&header_data);

        Ok((message, header))
    }

    /// Retrieve the insecure header data from a container
    ///
    /// * `container` - container outputted by [`PrivateBox::encrypt`]
    ///
    /// The header data is not authenticated, it is insecure.
    /// It may have been altered so use at your own risk.
    ///
    /// Examples
    /// ```
    /// # use privatebox::{PrivateBox, PrivateBoxError};
    /// # use rand_core::OsRng;
    /// #
    /// # fn main() -> Result<(), PrivateBoxError> {
    /// let mut privatebox = PrivateBox::new(&[1;32], OsRng); 
    /// let header = &[4, 4, 1, 1];
    ///
    /// let container = privatebox.encrypt(&*b"data", header, &[])?;
    /// let insecure_header = privatebox.parse_insecure_header(&container)?;
    ///
    /// // In this case header and insecure header are the same (but not guranteed)
    /// assert_eq!(&insecure_header, header);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docs_rs, doc(cfg(any(feature = "alloc"))))]
    pub fn parse_insecure_header(&self, container: &[u8]) -> Result<Vec<u8>, PrivateBoxError> {
        if container.len() < PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE {
            return Err(PrivateBoxError::UnrecognizedFormat)
        }

        let sizes = PrivateBoxDataSizes::deserialize(&container[PrivateBoxPrefix::SIZE..])?;

        if container.len() < PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.header_size() {
            return Err(PrivateBoxError::UnrecognizedFormat)
        }

        let header = &container[
            PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE
            ..
            PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + sizes.header_size()
        ];
        Ok(header.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::tests::alloc::borrow::ToOwned;
    extern crate std; 

    #[test]
    fn datasizes_new() {
        let message_size = std::usize::MAX;
        let header_size = std::usize::MAX;

        let sizes = PrivateBoxDataSizes { message_size, header_size };

        assert_eq!(message_size, sizes.message_size());
        assert_eq!(header_size, sizes.header_size());
    }

    #[test]
    fn datasizes_serialize() {
        let message_size = 10;
        let header_size = 50;

        let sizes = PrivateBoxDataSizes::new(header_size, message_size);

        let sizes = sizes.serialize();

        // header size
        assert_eq!(sizes[..MAX_DATA_SIZE], [0, 0, 0, 0, 0, 0, 0, 50]);
        // data size
        assert_eq!(sizes[MAX_DATA_SIZE..], [0, 0, 0, 0, 0, 0, 0, 10])
    }

    #[test]
    fn datasizes_deserialize() {
        // Test a long array
        let sizes = [0, 0, 0, 0, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 10, 5];
        let deserialized = PrivateBoxDataSizes::deserialize(&sizes).expect("Data sizes");
        assert_eq!(10, deserialized.message_size());
        assert_eq!(50, deserialized.header_size());

        PrivateBoxDataSizes::deserialize(&sizes[..sizes.len() - 2]).expect_err("Too short");
    }

    #[test]
    fn prefix_new() {
        let nonce = *XNonce::from_slice(&[2; NONCE_SIZE]);
        // let data_size = 50;
        // let header = PrivateBoxHeader::new(nonce, data_size);

        let tag = *Tag::from_slice(&[1u8; TAG_SIZE]);

        let prefix = PrivateBoxPrefix::new(nonce, tag);

        assert_eq!(nonce, *prefix.nonce());
        assert_eq!(tag, *prefix.tag());
    }

    #[test]
    fn prefix_serialize() {
        let nonce = *XNonce::from_slice(&[2; NONCE_SIZE]);
        // let data_size = core::usize::MAX;
        // let header = PrivateBoxHeader::new(nonce, data_size);

        let tag = *Tag::from_slice(&[1u8; TAG_SIZE]);

        let prefix = PrivateBoxPrefix::new(nonce, tag);
        
        assert_eq!(
            prefix.serialize()[..],
            [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
             1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1][..]
        )
    }

    #[test]
    fn prefix_deserialize() {
        let nonce = *XNonce::from_slice(&[2; NONCE_SIZE]);
        // let data_size = 50;
        // let header = PrivateBoxHeader::new(nonce, data_size);

        let tag = *Tag::from_slice(&[1u8; TAG_SIZE]);

        let prefix = PrivateBoxPrefix::new(nonce, tag);

        let prefix_serialized = prefix.serialize();
        let deserialized = PrivateBoxPrefix::deserialize(&prefix_serialized).expect("Deserialized container's prefix");
        
        // Good deserialize
        assert_eq!(nonce, *deserialized.nonce());
        assert_eq!(tag, *deserialized.tag());

        // Corrupted deserialize, not correct size
        match PrivateBoxPrefix::deserialize(&prefix_serialized[..PrivateBoxPrefix::SIZE - 1]) {
            Err(err) => match err {
                PrivateBoxError::UnrecognizedFormat => (),
                _ => panic!("Invalid error"),
            },
            Ok(_) => panic!("Header should not be parsed"),
        };
    }

    #[test]
    fn privatebox_new() {
        PrivateBox::new(&[1; KEY_SIZE], StdRng::from_seed([1;32]));
    }

    #[test]
    fn privatebox_encrypt_detached() {
        let rng = StdRng::from_seed([1;32]);

        let mut privatebox = PrivateBox::new(&[1; KEY_SIZE], rng);

        let mut message = b"hello world".to_owned();
        let assoc_data = &[0u8; 4];

        let detached_prefix = privatebox.encrypt_detached(&mut message, assoc_data).unwrap();
        
        // nonce | data_size | tag
        assert_eq!(
            &detached_prefix[..],
            &[
                51, 1, 232, 215, 231, 84, 219, 44, 245, 123, 10, 76, 167, 63, 37, 60, 112, 83, 173, 43, 197, 57, 135, 119,
                143, 136, 250, 191, 142, 138, 145, 172, 115, 135, 63, 49, 23, 160, 223, 51
            ][..]
        );

        // data
        assert_eq!(
            &message,
            &[60, 176, 58, 81, 122, 113, 92, 185, 227, 116, 233]
        );

        // assoc_data
        assert_eq!(
            &assoc_data[..],
            &[0u8; 4]
        )
    }

    #[test]
    fn privatebox_decrypt_detached() {
        let rng = StdRng::from_seed([1;32]);
        let privatebox = PrivateBox::new(&[1; KEY_SIZE], rng);

        let detached_prefix = [
            51, 1, 232, 215, 231, 84, 219, 44, 245, 123, 10, 76, 167, 63, 37, 60, 112, 83, 173, 43, 197, 57, 135, 119,
            143, 136, 250, 191, 142, 138, 145, 172, 115, 135, 63, 49, 23, 160, 223, 51
        ];

        let mut data = [60, 176, 58, 81, 122, 113, 92, 185, 227, 116, 233];

        let assoc_data = [0, 0, 0, 0];

        privatebox.decrypt_detached(&mut data, &assoc_data, &detached_prefix)
            .expect("Decrypted data");

        assert_eq!(&data, b"hello world");

        privatebox.decrypt_detached(&mut data, &[0], &detached_prefix)
            .expect_err("Bad associated data");
    }

    #[test]
    fn privatebox_encrypt_decrypt() {
        let mut privatebox = PrivateBox::new(&[1;32], StdRng::from_seed([1; 32])); 

        let mut message = *b"secret data";
        let assoc_data = *b"plain text";

        let detached_prefix = privatebox.encrypt_detached(&mut message, &assoc_data).expect("encrypt");
        assert_ne!(&message, b"secret data");

        privatebox.decrypt_detached(&mut message, &assoc_data, &detached_prefix).expect("decrypt");
        assert_eq!(&message, b"secret data");
    }

    #[test]
    fn privatebox_wrap() {
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1;32]));
        let message = b"data".to_owned();

        let header = &[1; 4];
        let metadata = &[0; 4];

        let container = privatebox.encrypt(b"data", header, metadata).expect("Wrapped container");
        
        // Data sizes attached correctly
        let sizes = PrivateBoxDataSizes::deserialize(&container[PrivateBoxPrefix::SIZE..]).expect("Message size");
        assert_eq!(message.len(), sizes.message_size());
        assert_eq!(header.len(), sizes.header_size());

        // Data encrypted
        assert_eq!(container[container.len() - message.len()..], [48, 180, 34, 92]);

        // Header data attached
        assert_eq!(container[PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE..PrivateBoxPrefix::SIZE + PrivateBoxDataSizes::SIZE + header.len()], [1, 1, 1, 1]);

        // Check tag (header data and metadata combined correctly)
        let prefix = PrivateBoxPrefix::deserialize(&container).expect("Deserialized prefix");

        let mut data = b"data".to_owned();
        let assoc_data = &[1,1,1,1,0,0,0,0];
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1;32]));
        let detached_prefix = privatebox.encrypt_detached(&mut data, assoc_data).expect("Encrypted data");
        let detached_prefix = PrivateBoxPrefix::deserialize(&detached_prefix).expect("Detached prefix");

        assert_eq!(prefix.tag(), detached_prefix.tag());
    }

    #[test]
    fn privatebox_wrap_unwrap() {
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1; 32]));
        let wrapped = privatebox.encrypt(b"secret data", &[5, 4, 3, 2], &[]).expect("Wrapped container");
        let (message1, header1) = privatebox.decrypt(&wrapped, &[]).expect("Unwrapped container");

        assert_eq!(message1, b"secret data");
        assert_eq!(header1, &[5, 4, 3, 2]);

        let container2 = privatebox.encrypt(b"secret data", &[5, 4, 3, 2], &[3, 2, 1]).expect("Wrapped container");
        let (message2, header2) = privatebox.decrypt(&container2, &[3, 2, 1]).expect("Unwrapped container");

        assert_eq!(
            message1,
            message2
        );

        assert_eq!(
            header1,
            header2
        );
    }

    #[test]
    fn privatebox_wrap_unwrap_corrupted() {
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1; 32]));
        let mut wrapped = privatebox.encrypt(b"data", &[], &[]).expect("Wrapped container");

        let last = wrapped.len() - 1;
        wrapped[last] = wrapped[last] + 1;

        privatebox.decrypt(&wrapped, &[]).expect_err("Unwrapped container");
    }

    #[test]
    fn privatebox_unwrap_larger_ok() {
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1; 32]));
        let mut wrapped = privatebox.encrypt(b"data", &[3, 2, 1], &[4, 3, 2]).expect("Wrapped container");

        wrapped.push(0);
        let (data, header) = privatebox.decrypt(&wrapped, &[4, 3, 2]).expect("Unwrapped container");

        assert_eq!(data, b"data");
        assert_eq!(header, &[3, 2, 1])
    }

    #[test]
    fn privatebox_unwrap_short_bad() {
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1; 32]));
        let mut wrapped = privatebox.encrypt(b"data", &[1u8; 54], &[1u8; 38]).expect("Wrapped container");

        wrapped.pop();
        privatebox.decrypt(&wrapped, &[1u8; 38]).expect_err("Too short");
    }

    #[test]
    fn privatebox_decrypt_wrong_sizes() {
        let privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1; 32]));

        let detached_prefix = [
            51, 1, 232, 215, 231, 84, 219, 44, 245, 123, 10, 76, 167, 63, 37, 60, 112, 83, 173, 43, 197, 57, 135, 119,
            143, 136, 250, 191, 142, 138, 145, 172, 115, 135, 63, 49, 23, 160, 223, 51
        ];

        let mut data = [60, 176, 58, 81, 122, 113, 92, 185, 227, 116, 233];

        let assoc_data = [0, 0, 0, 0];

        privatebox.decrypt_detached(&mut data, &assoc_data, &detached_prefix).expect("Decrypted data data");
        assert_eq!(&data, b"hello world");

        privatebox
            .decrypt_detached(&mut data[..4], &assoc_data, &detached_prefix)
            .expect_err("Corrupted sizes");
    }

    #[test]
    fn privatebox_header() {
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1; 32]));

        let header = &[1, 2, 3, 4];

        let container = privatebox.encrypt(&*b"data", header, &[]).expect("encrypted data");

        let parse_header = privatebox.parse_insecure_header(&container).expect("header");

        assert_eq!(&parse_header, header);
    }

    #[test]
    fn readme_test() {
        let mut privatebox = PrivateBox::new(&[1; 32], StdRng::from_seed([1u8; 32]));
        let header = &[5, 4, 3, 2];
        let metadata = &[3, 3, 3];
        let wrapped = privatebox.encrypt(b"secret data", header, metadata).expect("encrypt");
        let (message, authenticated_header) = privatebox.decrypt(&wrapped, metadata).expect("decrypt");

        assert_eq!(message, b"secret data");
        assert_eq!(&authenticated_header, header);
    }
}
