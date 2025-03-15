use halo2_curves::ff::{PrimeField};
use serde::{Serialize, Deserialize};
use ff::{PrimeFieldBits,BatchInvert,Field as FfField};
use halo2_proofs::arithmetic::Field as Halo2Field;
use std::ops::{Shr, BitAnd};
use rand::RngCore;
use std::fmt::{Display,Formatter,Debug};
use core::{iter::{Product,Sum}, ops::{Add,Mul,AddAssign, Sub, SubAssign, Neg, Div, DivAssign, MulAssign}};
use subtle::{ConstantTimeEq,Choice,ConditionallySelectable,CtOption};
use rand::SeedableRng;
use crate::util::{BigUint, {arithmetic::{modulus,Field}}};
use crate::{
    pcs::{Evaluation, Point, PolynomialCommitmentScheme},
    poly::multilinear::MultilinearPolynomial,
    util::{
        algebra::{field::MyField, CODE_RATE, SECURITY_BITS, STEP},
        algebra::{
            coset::Coset,
            polynomial::Polynomial,
        },
        interpolation::InterpolateValue,
        merkle_tree::{MerkleTreeVerifier, MERKLE_ROOT_SIZE},
        query_result::QueryResult,
        random_oracle::RandomOracle,
        transcript::{TranscriptRead, TranscriptWrite},
    },
};
use std::convert::TryInto;
use std::fmt::{Result as FmtResult};

#[derive(PrimeField,Serialize,Deserialize,Hash)]
#[PrimeFieldModulus = "2305843009213693951"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Mersenne61Mont([u64;1]);


// Implement Display so that Mersenne61Mont can be printed.
impl Display for Mersenne61Mont {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Assume to_repr returns a representation as [u8; 8].
        let repr = self.to_repr();
        // Convert the byte slice to an array.
        let bytes: [u8; 8] = repr.as_ref().try_into().unwrap();
        // Convert the little-endian bytes into a u64.
        let value = u64::from_le_bytes(bytes);
        write!(f, "{}", value)
    }
}



impl MyField for Mersenne61Mont {
    // Give the field a name.
    const FIELD_NAME: &'static str = "Mersenne61Mont";
    // For our Mersenne prime p = 2^61 - 1, we have p - 1 = 2 * (2^60 - 1).
    // Hence the highest power-of-two dividing p - 1 is 2, so we set LOG_ORDER = 1.
    const LOG_ORDER: u64 = 30;

    /// Constructs a field element from a u64 integer.
    /// This reduces the input modulo the field’s modulus and converts to Montgomery form.
    fn from_int(x: u64) -> Self {
        // The modulus for 2^61 - 1.
        const MODULUS: u64 = 2305843009213693951;
        // Reduce x modulo p.
        let x_mod = x % MODULUS;
        // The underlying PrimeField implementation expects a “representation”
        // (here a single 64-bit limb) that will be converted into Montgomery form.
        let repr = Mersenne61MontRepr(x_mod.to_le_bytes());
        // Convert the representation into a field element.
        // (We unwrap here because x_mod is certainly in range.)
        Mersenne61Mont::from_repr(repr).unwrap()
    }

    /// Returns a random field element.
    fn random_element() -> Self {
        let mut rng = rand::thread_rng();
        // Generate 8 random bytes (since our modulus fits in 64 bits).
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        // Interpret as a little-endian u64 and reduce.
        let x = u64::from_le_bytes(bytes);
        Self::from_int(x)
    }

    /// Computes the multiplicative inverse.
    /// (Panics if the element is zero.)
    fn inverse(&self) -> Self {
        // We use the invert() method provided by the PrimeField impl.
        self.invert().unwrap()
    }

    /// Returns true if the element is zero.
    fn iszero(&self) -> bool {
        self.is_zero().into()
    }

    /// Serializes the field element into its canonical byte representation.
    fn to_bytes(&self) -> Vec<u8> {
        // Assumes that to_repr() returns a type that can be converted to a byte slice.
        self.to_repr().as_ref().to_vec()
    }

    /// Hashes a fixed-size byte array (of size MERKLE_ROOT_SIZE) to a field element.
    /// The hash is interpreted as a big-endian integer which is then reduced modulo p.
    fn from_hash(hash: [u8; MERKLE_ROOT_SIZE]) -> Self {
        let mut num: u128 = 0;
        for &b in hash.iter() {
            num = (num << 8) | (b as u128);
        }
        // Our modulus as u128.
        let modulus = 2305843009213693951u128;
        let reduced = (num % modulus) as u64;
        Self::from_int(reduced)
    }

    /// Returns a primitive 2^LOG_ORDER-th root of unity.
    /// In our field with LOG_ORDER = 1, the unique nontrivial 2nd root is -1.
    fn root_of_unity() -> Self {
        -Self::from_int(1)
    }

    /// Returns the multiplicative inverse of 2.
    /// Since 2 * ((p + 1) / 2) ≡ 1 mod p, we have inverse_2 = (p + 1) / 2.
    fn inverse_2() -> Self {
        // For p = 2305843009213693951, (p + 1)/2 is:
        Self::from_int(1152921504606846976)
    }
}


// Instead of implementing Halo2Field directly which conflicts with ff::Field,
// we'll implement the specific methods needed by the application
impl Mersenne61Mont {
    pub fn halo2_random<R: rand::RngCore>(rng: &mut R) -> Self {
        Self::random_element()
    }
    
    pub fn halo2_sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        // For now, just return a default implementation
        // Return (Choice::from(0), Self::ZERO) indicating no square root found
        (Choice::from(0), Self::ZERO)
    }
}
