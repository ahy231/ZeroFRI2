use num_bigint::BigUint;
use p3_bn254_fr::{Bn254Fr, FFBn254Fr};
use p3_commit::Mmcs;
use p3_field::extension::{BinomiallyExtendable, HasTwoAdicBinomialExtension};
use p3_field::integers::QuotientMap;
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, Field, InjectiveMonomial, Packable,
    PackedFieldExtension, PackedValue, PermutationMonomial, Powers, PrimeCharacteristicRing,
    PrimeField, PrimeField32, PrimeField64, TwoAdicField,
};
use p3_merkle_tree::{MerkleTree, MerkleTreeMmcs};
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use rand_9::distr::{Distribution, StandardUniform};
use rand_9::Rng;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{self, Display};
use std::hash::{Hash, Hasher};
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{ConditionallySelectable, ConstantTimeEq};

#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct MyFr(pub Bn254Fr);

impl BinomiallyExtendable<1> for MyFr {
    const W: Self = MyFr::ZERO;

    const DTH_ROOT: Self = MyFr::ONE;

    const EXT_GENERATOR: [Self; 1] = [MyFr(Bn254Fr::GENERATOR)];
}

impl HasTwoAdicBinomialExtension<1> for MyFr {
    const EXT_TWO_ADICITY: usize = 30;

    fn ext_two_adic_generator(bits: usize) -> [Self; 1] {
        [MyFr(Bn254Fr::two_adic_generator(bits))]
    }
}

impl Serialize for MyFr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MyFr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Bn254Fr::deserialize(deserializer)?;
        Ok(MyFr(value))
    }
}

impl ConstantTimeEq for MyFr {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.value.ct_eq(&other.0.value)
    }
}
impl ConditionallySelectable for MyFr {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        MyFr(Bn254Fr {
            value: FFBn254Fr::conditional_select(&a.0.value, &b.0.value, choice),
        })
    }
}

impl ff::Field for MyFr {
    const ZERO: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::ZERO,
    });

    const ONE: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::ONE,
    });

    fn random(rng: impl rand::RngCore) -> Self {
        MyFr(Bn254Fr {
            value: FFBn254Fr::random(rng),
        })
    }

    fn square(&self) -> Self {
        MyFr(Bn254Fr {
            value: FFBn254Fr::square(&self.0.value),
        })
    }

    fn double(&self) -> Self {
        MyFr(Bn254Fr {
            value: FFBn254Fr::double(&self.0.value),
        })
    }

    fn invert(&self) -> subtle::CtOption<Self> {
        subtle::CtOption::new(
            MyFr(Bn254Fr {
                value: FFBn254Fr::invert(&self.0.value).unwrap(),
            }),
            subtle::Choice::from(true as u8),
        )
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (subtle::Choice, Self) {
        let (choice, value) = FFBn254Fr::sqrt_ratio(&num.0.value, &div.0.value);
        (choice, MyFr(Bn254Fr { value }))
    }
}

impl ff::PrimeField for MyFr {
    type Repr = <FFBn254Fr as ff::PrimeField>::Repr;

    fn from_repr(repr: Self::Repr) -> subtle::CtOption<Self> {
        subtle::CtOption::new(
            MyFr(Bn254Fr {
                value: FFBn254Fr::from_repr(repr).unwrap(),
            }),
            subtle::Choice::from(true as u8),
        )
    }

    fn to_repr(&self) -> Self::Repr {
        self.0.value.to_repr()
    }

    fn is_odd(&self) -> subtle::Choice {
        self.0.value.is_odd()
    }

    const MODULUS: &'static str = FFBn254Fr::MODULUS;

    const NUM_BITS: u32 = FFBn254Fr::NUM_BITS;

    const CAPACITY: u32 = FFBn254Fr::CAPACITY;

    const TWO_INV: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::TWO_INV,
    });

    const MULTIPLICATIVE_GENERATOR: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::MULTIPLICATIVE_GENERATOR,
    });

    const S: u32 = FFBn254Fr::S;

    const ROOT_OF_UNITY: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::ROOT_OF_UNITY,
    });

    const ROOT_OF_UNITY_INV: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::ROOT_OF_UNITY_INV,
    });

    const DELTA: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::DELTA,
    });
}

impl TwoAdicField for MyFr {
    const TWO_ADICITY: usize = Bn254Fr::TWO_ADICITY;

    fn two_adic_generator(bits: usize) -> Self {
        MyFr(Bn254Fr::two_adic_generator(bits))
    }
}

impl Mul<&MyFr> for MyFr {
    type Output = MyFr;

    fn mul(self, rhs: &MyFr) -> Self::Output {
        MyFr(self.0 * rhs.0)
    }
}

impl Add<&MyFr> for MyFr {
    type Output = MyFr;

    fn add(self, rhs: &MyFr) -> Self::Output {
        MyFr(self.0 + rhs.0)
    }
}

impl Sub<&MyFr> for MyFr {
    type Output = MyFr;

    fn sub(self, rhs: &MyFr) -> Self::Output {
        MyFr(self.0 - rhs.0)
    }
}

impl Add for MyFr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        MyFr(self.0 + rhs.0)
    }
}

impl Sub for MyFr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        MyFr(self.0 - rhs.0)
    }
}

impl Mul for MyFr {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        MyFr(self.0 * rhs.0)
    }
}

impl Field for MyFr {
    type Packing = MyFr;

    const GENERATOR: Self = MyFr(Bn254Fr {
        value: FFBn254Fr::from_raw([1, 0, 0, 0]),
    });

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn is_one(&self) -> bool {
        self.0.is_one()
    }

    fn try_inverse(&self) -> Option<Self> {
        self.0.try_inverse().map(MyFr)
    }

    fn order() -> BigUint {
        Bn254Fr::order()
    }

    fn div_2exp_u64(&self, exp: u64) -> Self {
        MyFr(self.0.div_2exp_u64(exp))
    }

    fn halve(&self) -> Self {
        MyFr(self.0.div_2exp_u64(1))
    }
}
impl From<u64> for MyFr {
    fn from(value: u64) -> Self {
        MyFr(Bn254Fr {
            value: FFBn254Fr::from_raw([value, 0, 0, 0]),
        })
    }
}

impl Display for MyFr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Div for MyFr {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        MyFr(self.0 / rhs.0)
    }
}

impl MulAssign for MyFr {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0;
    }
}

impl<'a> MulAssign<&'a MyFr> for MyFr {
    fn mul_assign(&mut self, rhs: &'a MyFr) {
        self.0 *= rhs.0;
    }
}

impl AddAssign for MyFr {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<'a> AddAssign<&'a MyFr> for MyFr {
    fn add_assign(&mut self, rhs: &'a MyFr) {
        self.0 += rhs.0;
    }
}

impl SubAssign for MyFr {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl<'a> SubAssign<&'a MyFr> for MyFr {
    fn sub_assign(&mut self, rhs: &'a MyFr) {
        self.0 -= rhs.0;
    }
}

impl Neg for MyFr {
    type Output = Self;

    fn neg(self) -> Self::Output {
        MyFr(-self.0)
    }
}

impl Product for MyFr {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap_or(Self::ONE)
    }
}

impl<'a> Product<&'a MyFr> for MyFr {
    fn product<I: Iterator<Item = &'a MyFr>>(iter: I) -> Self {
        let mut t = Self::ONE;
        for x in iter {
            t *= x;
        }
        t
    }
}

impl Sum for MyFr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::ZERO)
    }
}

impl<'a> Sum<&'a MyFr> for MyFr {
    fn sum<I: Iterator<Item = &'a MyFr>>(iter: I) -> Self {
        let mut t = Self::ZERO;
        for x in iter {
            t += x;
        }
        t
    }
}

impl Packable for MyFr {}

impl QuotientMap<i128> for MyFr {
    fn from_int(value: i128) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: i128) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: i128) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<i64> for MyFr {
    fn from_int(value: i64) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: i64) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: i64) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<i32> for MyFr {
    fn from_int(value: i32) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: i32) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: i32) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<i16> for MyFr {
    fn from_int(value: i16) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: i16) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: i16) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<i8> for MyFr {
    fn from_int(value: i8) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: i8) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: i8) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<u128> for MyFr {
    fn from_int(value: u128) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: u128) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: u128) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<u64> for MyFr {
    fn from_int(value: u64) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: u64) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: u64) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<u32> for MyFr {
    fn from_int(value: u32) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: u32) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: u32) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<u16> for MyFr {
    fn from_int(value: u16) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: u16) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: u16) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl QuotientMap<u8> for MyFr {
    fn from_int(value: u8) -> Self {
        MyFr(Bn254Fr::from_int(value))
    }

    fn from_canonical_checked(value: u8) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value).map(MyFr)
    }

    unsafe fn from_canonical_unchecked(value: u8) -> Self {
        MyFr(Bn254Fr::from_canonical_unchecked(value))
    }
}

impl Ord for MyFr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for MyFr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PrimeCharacteristicRing for MyFr {
    type PrimeSubfield = MyFr;

    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        MyFr(f.0)
    }

    const ZERO: Self = MyFr(Bn254Fr::ZERO);

    const ONE: Self = MyFr(Bn254Fr::ONE);

    const TWO: Self = MyFr(Bn254Fr::TWO);

    const NEG_ONE: Self = MyFr(Bn254Fr::NEG_ONE);
}

impl PrimeField for MyFr {
    fn as_canonical_biguint(&self) -> BigUint {
        self.0.as_canonical_biguint()
    }
}

impl PrimeField32 for MyFr {
    const ORDER_U32: u32 = 0x43E1F593;

    fn as_canonical_u32(&self) -> u32 {
        u32::from_le_bytes(self.0.value.to_bytes()[0..4].try_into().unwrap())
    }
}

impl PrimeField64 for MyFr {
    // BN254's base field modulus is approximately 2^254, so this is not representable as u64
    // Instead, we return a canonical representation of the least significant 64 bits
    const ORDER_U64: u64 = 0x43E1F593F0000001;

    fn as_canonical_u64(&self) -> u64 {
        u64::from_le_bytes(self.0.value.to_bytes()[0..8].try_into().unwrap())
    }
}

impl Distribution<MyFr> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MyFr {
        MyFr(self.sample(rng))
    }
}

impl InjectiveMonomial<5> for MyFr {}

impl PermutationMonomial<5> for MyFr {
    fn injective_exp_root_n(&self) -> Self {
        MyFr(self.0.injective_exp_n())
    }
}
