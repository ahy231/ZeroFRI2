use num_bigint::BigUint;
use p3_bn254_fr::{Bn254Fr, FFBn254Fr};
use p3_commit::Mmcs;
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
// Note: Struct FakeExtension and it's implementation was added by sec-bit to use bn254 field in FRI.
// It is not a part of Plonky3 source code.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FakeExtension {
    pub value: MyFr,
}

unsafe impl Send for FakeExtension {}
unsafe impl Sync for FakeExtension {}

#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct MyFr(pub Bn254Fr);

impl TwoAdicField for MyFr {
    const TWO_ADICITY: usize = Bn254Fr::TWO_ADICITY;

    fn two_adic_generator(bits: usize) -> Self {
        MyFr(Bn254Fr::two_adic_generator(bits))
    }
}

impl fmt::Display for FakeExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value.0)
    }
}

impl Div<FakeExtension> for FakeExtension {
    type Output = FakeExtension;

    fn div(self, rhs: FakeExtension) -> Self::Output {
        FakeExtension {
            value: MyFr(self.value.0 / rhs.value.0),
        }
    }
}

impl BasedVectorSpace<MyFr> for FakeExtension {
    const DIMENSION: usize = 1;

    fn as_basis_coefficients_slice(&self) -> &[MyFr] {
        self.value.as_basis_coefficients_slice()
    }

    fn from_basis_coefficients_fn<F>(mut f: F) -> Self
    where
        F: FnMut(usize) -> MyFr,
    {
        FakeExtension { value: f(0) }
    }

    fn from_basis_coefficients_iter<I: IntoIterator<Item = MyFr>>(iter: I) -> Self {
        FakeExtension {
            value: iter.into_iter().next().unwrap(),
        }
    }
}

impl Add<MyFr> for FakeExtension {
    type Output = Self;
    fn add(self, rhs: MyFr) -> Self {
        FakeExtension {
            value: MyFr(self.value.0 + rhs.0),
        }
    }
}

impl AddAssign<MyFr> for FakeExtension {
    fn add_assign(&mut self, rhs: MyFr) {
        self.value.0 += rhs.0;
    }
}

impl Sub<MyFr> for FakeExtension {
    type Output = Self;
    fn sub(self, rhs: MyFr) -> Self {
        FakeExtension {
            value: MyFr(self.value.0 - rhs.0),
        }
    }
}

impl SubAssign<MyFr> for FakeExtension {
    fn sub_assign(&mut self, rhs: MyFr) {
        self.value.0 -= rhs.0;
    }
}

impl Mul<MyFr> for FakeExtension {
    type Output = Self;
    fn mul(self, rhs: MyFr) -> Self {
        FakeExtension {
            value: MyFr(self.value.0 * rhs.0),
        }
    }
}

impl MulAssign<MyFr> for FakeExtension {
    fn mul_assign(&mut self, rhs: MyFr) {
        self.value.0 *= rhs.0;
    }
}

impl From<MyFr> for FakeExtension {
    fn from(value: MyFr) -> Self {
        FakeExtension { value }
    }
}

impl Algebra<MyFr> for FakeExtension {}

impl PrimeCharacteristicRing for FakeExtension {
    const NEG_ONE: Self = FakeExtension {
        value: MyFr(Bn254Fr::NEG_ONE),
    };

    const ZERO: Self = FakeExtension {
        value: MyFr(Bn254Fr::ZERO),
    };

    const ONE: Self = FakeExtension {
        value: MyFr(Bn254Fr::ONE),
    };

    const TWO: Self = FakeExtension {
        value: MyFr(Bn254Fr::TWO),
    };

    type PrimeSubfield = MyFr;

    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        FakeExtension { value: MyFr(f.0) }
    }
}

impl PackedFieldExtension<MyFr, FakeExtension> for FakeExtension {
    fn from_ext_slice(ext_slice: &[FakeExtension]) -> Self {
        FakeExtension {
            value: MyFr(ext_slice[0].value.0),
        }
    }

    fn packed_ext_powers(base: FakeExtension) -> Powers<Self> {
        let mut current = base;
        let mut powers = vec![current];
        for _ in 1..MyFr::WIDTH {
            current = current * base;
            powers.push(current);
        }
        Powers { base, current }
    }
}

impl ExtensionField<MyFr> for FakeExtension {
    type ExtensionPacking = FakeExtension;

    fn is_in_basefield(&self) -> bool {
        // Check if the element is in the base field by checking if it's equal to its base representation
        if let Some(base) = self.value.as_base() {
            *self == Self::from(base)
        } else {
            false
        }
    }

    fn as_base(&self) -> Option<MyFr> {
        Some(MyFr(self.value.0))
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
impl Packable for FakeExtension {}

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

impl AddAssign for MyFr {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl SubAssign for MyFr {
    fn sub_assign(&mut self, rhs: Self) {
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

impl Sum for MyFr {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::ZERO)
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

// impl PrimeCharacteristicRing for FakeExtension {
//     type PrimeSubfield = FakeExtension;

//     fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
//         FakeExtension { value: f.value }
//     }

//     const ZERO: Self = FakeExtension { value: MyFr::ZERO };
//     const ONE: Self = FakeExtension { value: MyFr::ONE };
//     const TWO: Self = FakeExtension { value: MyFr::TWO };
//     const NEG_ONE: Self = FakeExtension {
//         value: MyFr::NEG_ONE,
//     };
// }

impl Field for FakeExtension {
    type Packing = FakeExtension;
    const GENERATOR: Self = FakeExtension {
        value: MyFr(Bn254Fr {
            value: FFBn254Fr::from_raw([1, 0, 0, 0]),
        }),
    };

    fn is_zero(&self) -> bool {
        self.value.0.is_zero()
    }

    fn is_one(&self) -> bool {
        self.value.0.is_one()
    }

    fn try_inverse(&self) -> Option<Self> {
        self.value
            .0
            .try_inverse()
            .map(|v| FakeExtension { value: MyFr(v) })
    }

    fn order() -> BigUint {
        Bn254Fr::order()
    }

    fn div_2exp_u64(&self, exp: u64) -> Self {
        FakeExtension {
            value: MyFr(self.value.0.div_2exp_u64(exp)),
        }
    }

    fn inverse(&self) -> Self {
        FakeExtension {
            value: MyFr(self.value.0.inverse()),
        }
    }

    fn halve(&self) -> Self {
        FakeExtension {
            value: MyFr(self.value.0.div_2exp_u64(1)),
        }
    }

    fn multiplicative_group_factors() -> Vec<(BigUint, usize)> {
        Bn254Fr::multiplicative_group_factors()
    }

    fn bits() -> usize {
        Bn254Fr::bits()
    }
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

impl Mul<FakeExtension> for FakeExtension {
    type Output = FakeExtension;

    fn mul(self, rhs: FakeExtension) -> Self::Output {
        FakeExtension {
            value: MyFr(self.value.0 * rhs.value.0),
        }
    }
}

impl Sub<FakeExtension> for FakeExtension {
    type Output = FakeExtension;

    fn sub(self, rhs: FakeExtension) -> Self::Output {
        FakeExtension {
            value: MyFr(self.value.0 - rhs.value.0),
        }
    }
}

impl Neg for FakeExtension {
    type Output = FakeExtension;

    fn neg(self) -> Self::Output {
        FakeExtension {
            value: MyFr(-self.value.0),
        }
    }
}

impl Add for FakeExtension {
    type Output = FakeExtension;

    fn add(self, rhs: Self) -> Self::Output {
        FakeExtension {
            value: MyFr(self.value.0 + rhs.value.0),
        }
    }
}

impl Product for FakeExtension {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap()
    }
}

impl Sum for FakeExtension {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap()
    }
}

impl MulAssign<FakeExtension> for FakeExtension {
    fn mul_assign(&mut self, rhs: FakeExtension) {
        self.value *= rhs.value;
    }
}

impl SubAssign<FakeExtension> for FakeExtension {
    fn sub_assign(&mut self, rhs: FakeExtension) {
        self.value -= rhs.value;
    }
}

impl AddAssign<FakeExtension> for FakeExtension {
    fn add_assign(&mut self, rhs: FakeExtension) {
        self.value += rhs.value;
    }
}

impl MulAssign<Bn254Fr> for FakeExtension {
    fn mul_assign(&mut self, rhs: Bn254Fr) {
        self.value.0 *= rhs;
    }
}

impl Mul<Bn254Fr> for FakeExtension {
    type Output = FakeExtension;

    fn mul(self, rhs: Bn254Fr) -> Self::Output {
        FakeExtension {
            value: MyFr(self.value.0 * rhs),
        }
    }
}

impl AddAssign<Bn254Fr> for FakeExtension {
    fn add_assign(&mut self, rhs: Bn254Fr) {
        self.value.0 += rhs;
    }
}

impl Add<Bn254Fr> for FakeExtension {
    type Output = FakeExtension;

    fn add(self, rhs: Bn254Fr) -> Self::Output {
        FakeExtension {
            value: MyFr(self.value.0 + rhs),
        }
    }
}

impl SubAssign<Bn254Fr> for FakeExtension {
    fn sub_assign(&mut self, rhs: Bn254Fr) {
        self.value.0 -= rhs;
    }
}

impl Sub<Bn254Fr> for FakeExtension {
    type Output = FakeExtension;

    fn sub(self, rhs: Bn254Fr) -> Self::Output {
        FakeExtension {
            value: MyFr(self.value.0 - rhs),
        }
    }
}

impl From<Bn254Fr> for FakeExtension {
    fn from(value: Bn254Fr) -> Self {
        FakeExtension { value: MyFr(value) }
    }
}

impl TwoAdicField for FakeExtension {
    const TWO_ADICITY: usize = 27;

    fn two_adic_generator(bits: usize) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::two_adic_generator(bits)),
        }
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

impl PrimeField32 for FakeExtension {
    const ORDER_U32: u32 = 0x43E1F593;

    fn as_canonical_u32(&self) -> u32 {
        u32::from_le_bytes(self.value.0.value.to_bytes()[0..4].try_into().unwrap())
    }
}

impl PrimeField64 for FakeExtension {
    const ORDER_U64: u64 = 0x43E1F593F0000001;

    fn as_canonical_u64(&self) -> u64 {
        u64::from_le_bytes(self.value.0.value.to_bytes()[0..8].try_into().unwrap())
    }
}

impl PrimeField for FakeExtension {
    fn as_canonical_biguint(&self) -> BigUint {
        self.value.0.as_canonical_biguint()
    }
}

impl Ord for FakeExtension {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.0.cmp(&other.value.0)
    }
}

impl PartialOrd for FakeExtension {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl QuotientMap<i128> for FakeExtension {
    fn from_int(value: i128) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: i128) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: i128) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<i64> for FakeExtension {
    fn from_int(value: i64) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: i64) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: i64) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<i32> for FakeExtension {
    fn from_int(value: i32) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: i32) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: i32) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<i16> for FakeExtension {
    fn from_int(value: i16) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: i16) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: i16) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<i8> for FakeExtension {
    fn from_int(value: i8) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: i8) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: i8) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<u128> for FakeExtension {
    fn from_int(value: u128) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: u128) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: u128) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<u64> for FakeExtension {
    fn from_int(value: u64) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: u64) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: u64) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<u32> for FakeExtension {
    fn from_int(value: u32) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: u32) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: u32) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<u16> for FakeExtension {
    fn from_int(value: u16) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: u16) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: u16) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}

impl QuotientMap<u8> for FakeExtension {
    fn from_int(value: u8) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_int(value)),
        }
    }

    fn from_canonical_checked(value: u8) -> Option<Self> {
        Bn254Fr::from_canonical_checked(value)
            .map(MyFr)
            .map(|v| FakeExtension { value: v })
    }

    unsafe fn from_canonical_unchecked(value: u8) -> Self {
        FakeExtension {
            value: MyFr(Bn254Fr::from_canonical_unchecked(value)),
        }
    }
}
