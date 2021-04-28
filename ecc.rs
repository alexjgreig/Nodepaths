use bincode;
use curve25519_dalek::montgomery::MontogomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRng;
use rand_core::RngCore;

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct PublicKey(MontgomeryPoint);

impl From<[u8; 32]> for PublicKey {
    /// Given a byte array, construct a x25519 `PublicKey`.
    fn from(bytes: [u8; 32]) -> PublicKey {
        PublicKey(MontgomeryPoint(bytes))
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Clone)]
pub struct StaticSecret(Scalar);

impl StaticSecret {
    /// Generate an curve-25519 key.
    pub fn new<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; 32];

        csprng.fill_bytes(&mut bytes);

        StaticSecret(clamp_scalar(bytes))
    }

    /// Extract this key's bytes for serialization.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<[u8; 32]> for StaticSecret {
    /// Load a secret key from a byte array.
    fn from(bytes: [u8; 32]) -> StaticSecret {
        StaticSecret(clamp_scalar(bytes))
    }
}

impl<'a> From<&'a StaticSecret> for PublicKey {
    /// Given an x25519 [`StaticSecret`] key, compute its corresponding [`PublicKey`].
    fn from(secret: &'a StaticSecret) -> PublicKey {
        PublicKey((&ED25519_BASEPOINT_TABLE * &secret.0).to_montgomery())
    }
}

/// "Decode" a scalar from a 32-byte array.
///
/// By "decode" here, what is really meant is applying key clamping by twiddling
/// some bits.
///
/// # Returns
///
/// A `Scalar`.
fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}
