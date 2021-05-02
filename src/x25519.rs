use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use aes::Aes256;

use rand::rngs::OsRng;
use rand::RngCore;

use std::str;

use typenum::U16;

#[cfg_attr(feature = "curve_serde", serde(crate = "c_serde"))]
#[cfg_attr(
    feature = "curve_serde",
    derive(c_serde::Serialize, c_serde::Deserialize)
)]
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct PublicKey(MontgomeryPoint);

impl From<[u8; 32]> for PublicKey {
    // Given a byte array, construct a x25519 `PublicKey`.
    fn from(bytes: [u8; 32]) -> PublicKey {
        PublicKey(MontgomeryPoint(bytes))
    }
}

impl PublicKey {
    // Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    // View this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}
#[cfg_attr(feature = "curve_serde", serde(crate = "c_serde"))]
#[cfg_attr(
    feature = "curve_serde",
    derive(c_serde::Serialize, c_serde::Deserialize)
)]
#[derive(Clone)]
pub struct SecretKey(Scalar);

impl SecretKey {
    // Generate an curve-25519 key.
    // Perform a Diffie-Hellman key agreement between `self` and
    // `their_public` key to produce a `SharedSecret`.

    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(&self.0 * their_public.0)
    }

    pub fn new() -> Self {
        let mut bytes = [0u8; 32];

        OsRng.fill_bytes(&mut bytes);

        SecretKey(clamp_scalar(bytes))
    }

    // Extract this key's bytes for serialization.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<[u8; 32]> for SecretKey {
    // Load a secret key from a byte array.
    fn from(bytes: [u8; 32]) -> SecretKey {
        SecretKey(clamp_scalar(bytes))
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    // Given an x25519 [`SecretKey`] key, compute its corresponding [`PublicKey`].
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey((&ED25519_BASEPOINT_TABLE * &secret.0).to_montgomery())
    }
}

pub struct SharedSecret(MontgomeryPoint);

impl SharedSecret {
    /// Convert this shared secret to a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// View this shared secret key as a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn encrypt(&self, message: String) -> Vec<GenericArray<u8, U16>> {
        let key = GenericArray::from_slice(self.as_bytes());
        let cipher = Aes256::new(&key);
        let message_bytes = message.as_bytes();
        let mut encrypted_blocks: Vec<GenericArray<u8, U16>> = Vec::new();
        for i in 0..message_bytes.len() {
            if i % 16 == 0 && i != 0 {
                let mut block = GenericArray::clone_from_slice(&message_bytes[(i - 16)..i]);
                cipher.encrypt_block(&mut block);
                encrypted_blocks.push(block);
            } else if i == message_bytes.len() - 1 {
                let mut temp = [0u8; 16];
                temp[0..(i % 16) + 1].copy_from_slice(&message_bytes[i - (i % 16)..i + 1]);
                let mut block = GenericArray::clone_from_slice(&temp);
                cipher.encrypt_block(&mut block);
                encrypted_blocks.push(block);
            }
        }
        return encrypted_blocks;
    }
    pub fn decrypt(&self, encrypted_blocks: Vec<GenericArray<u8, U16>>) -> String {
        let key = GenericArray::from_slice(self.as_bytes());
        let cipher = Aes256::new(&key);
        let mut message: String = String::new();
        for encrypted_block in encrypted_blocks.iter() {
            let mut block = encrypted_block.clone();
            cipher.decrypt_block(&mut block);
            message.push_str(str::from_utf8(block.as_slice()).unwrap());
        }
        return message;
    }
}

// "Decode" a scalar from a 32-byte array.

fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}
