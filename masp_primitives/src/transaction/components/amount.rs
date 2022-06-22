use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Sub, SubAssign, Mul};
use std::collections::BTreeMap;
use crate::transaction::AssetType;
use std::iter::FromIterator;
use crate::serialize::Vector;
use std::io::Read;
use std::io::Write;
use std::convert::TryInto;
use std::ops::Index;
use std::collections::btree_map::Keys;
use std::collections::btree_map::Iter;
use std::cmp::Ordering;
use std::hash::Hash;

const COIN: i64 = 1_0000_0000;
const MAX_MONEY: i64 = 21_000_000 * COIN;

/// A type-safe representation of some quantity of Zcash.
///
/// An Amount can only be constructed from an integer that is within the valid monetary
/// range of `{-MAX_MONEY..MAX_MONEY}` (where `MAX_MONEY` = 21,000,000 × 10⁸ zatoshis).
/// However, this range is not preserved as an invariant internally; it is possible to
/// add two valid Amounts together to obtain an invalid Amount. It is the user's
/// responsibility to handle the result of serializing potentially-invalid Amounts. In
/// particular, a [`Transaction`] containing serialized invalid Amounts will be rejected
/// by the network consensus rules.
///
/// [`Transaction`]: crate::transaction::Transaction
#[derive(
    Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize, Eq, Hash
)]
pub struct Amount<Unit: Hash + Ord + BorshSerialize + BorshDeserialize = AssetType>(BTreeMap<Unit, i64>);

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Amount<Unit> {
    /// Returns a zero-valued Amount.
    pub fn zero() -> Self {
        Amount(BTreeMap::new())
    }

    /// Creates a non-negative Amount from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative<Amt: TryInto<i64>>(
        atype: Unit,
        amount: Amt
    ) -> Result<Self, ()> {
        let amount = amount.try_into().map_err(|_| ())?;
        if amount == 0 {
            Ok(Self::zero())
        } else if 0 <= amount && amount <= MAX_MONEY {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(Amount(ret))
        } else {
            Err(())
        }
    }

    /// Creates an Amount from a type convertible to i64.
    ///
    /// Returns an error if the amount is outside the range `{-MAX_MONEY..MAX_MONEY}`.
    pub fn from<Amt: TryInto<i64>>(
        atype: Unit,
        amount: Amt
    ) -> Result<Self, ()> {
        let amount = amount.try_into().map_err(|_| ())?;
        if amount == 0 {
            Ok(Self::zero())
        } else if -MAX_MONEY <= amount && amount <= MAX_MONEY {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(Amount(ret))
        } else {
            Err(())
        }
    }

    /// Returns an iterator over the amount's non-zero asset-types
    pub fn asset_types(&self) -> Keys<'_, Unit, i64> {
        self.0.keys()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn components(&self) -> Iter<'_, Unit, i64> {
        self.0.iter()
    }

    /// Filters out everything but the given AssetType from this Amount
    pub fn project(&self, index: Unit) -> Self {
        let val = self.0.get(&index).copied().unwrap_or(0);
        Self::from(index, val).unwrap()
    }

    /// Filters out the given AssetType from this Amount
    pub fn reject(&self, index: Unit) -> Self {
        self.clone() - self.project(index)
    }
}

impl Amount<AssetType> {
    /// Deserialize an Amount object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let mut atype = [0; 32];
            let mut value = [0; 8];
            reader.read_exact(&mut atype)?;
            reader.read_exact(&mut value)?;
            let atype = AssetType::from_identifier(&atype)
                .ok_or_else(|| std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid asset type"
                ))?;
            Ok((atype, i64::from_le_bytes(value)))
        })?;
        let mut ret = Self::zero();
        for (atype, amt) in vec {
            ret += Self::from(atype, amt)
                .map_err(|_| std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "amount out of range"
                ))?;
        }
        Ok(ret)
    }

    /// Serialize an Amount object into a list of amounts denominated by
    /// distinct asset types
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec = Vec::<(AssetType, i64)>::from(self.clone());
        Vector::write(writer, vec.as_ref(), |writer, elt| {
            writer.write_all(elt.0.get_identifier())?;
            writer.write_all(elt.1.to_le_bytes().as_ref())?;
            Ok(())
        })
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> PartialOrd for Amount<Unit> {
    /// One Amount is more than or equal to another if each corresponding
    /// coordinate is more than the other's.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut diff = other.clone();
        for (atype, amount) in self.components() {
            let ent = diff[atype] - amount;
            if ent == 0 {
                diff.0.remove(atype);
            } else {
                diff.0.insert(atype.clone(), ent);
            }
        }
        if diff.0.values().all(|x| *x == 0) {
            Some(Ordering::Equal)
        } else if diff.0.values().all(|x| *x >= 0) {
            Some(Ordering::Less)
        } else if diff.0.values().all(|x| *x <= 0) {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize> Index<&Unit> for Amount<Unit> {
    type Output = i64;
    /// Query how much of the given asset this amount contains
    fn index(&self, index: &Unit) -> &Self::Output {
        if let Some(val) = self.0.get(index) {
            val
        } else {
            &0
        }
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize> From<Amount<Unit>> for Vec<(Unit, i64)> {
    fn from(amount: Amount<Unit>) -> Self {
        Vec::from_iter(amount.0.into_iter())
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Mul<i64> for Amount<Unit> {
    type Output = Self;

    fn mul(mut self, rhs: i64) -> Self {
        for (_atype, amount) in self.0.iter_mut() {
            let ent = *amount * rhs;
            if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                *amount = ent;
            } else {
                panic!("multiplication should remain in range");
            }
        }
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Add<Amount<Unit>> for Amount<Unit> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        for (atype, amount) in rhs.components() {
            let ent = self[atype] + amount;
            if ent == 0 {
                self.0.remove(atype);
            } else if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                self.0.insert(atype.clone(), ent);
            } else {
                panic!("addition should remain in range");
            }
        }
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> AddAssign<Amount<Unit>> for Amount<Unit> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Sub<Amount<Unit>> for Amount<Unit> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self {
        for (atype, amount) in rhs.components() {
            let ent = self[atype] - amount;
            if ent == 0 {
                self.0.remove(atype);
            } else if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                self.0.insert(atype.clone(), ent);
            } else {
                panic!("subtraction should remain in range");
            }
        }
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> SubAssign<Amount<Unit>> for Amount<Unit> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Sum for Amount<Unit> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

pub fn zec() -> AssetType {
    AssetType::new(b"ZEC").unwrap()
}

pub fn default_fee() -> Amount {
    Amount::from(zec(), 10000).unwrap()
}

#[cfg(test)]
mod tests {
    use super::{Amount, MAX_MONEY, zec};

    #[test]
    fn amount_in_range() {
        let zero = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(Amount::read(&mut zero.as_ref()).unwrap(), Amount::zero());

        let neg_one = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\xff";
        assert_eq!(
            Amount::read(&mut neg_one.as_ref()).unwrap(),
            Amount::from(zec(), -1).unwrap()
        );

        let max_money = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x40\x07\x5a\xf0\x75\x07\x00";
        assert_eq!(
            Amount::read(&mut max_money.as_ref()).unwrap(),
            Amount::from(zec(), MAX_MONEY).unwrap()
        );

        let max_money_p1 = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x01\x40\x07\x5a\xf0\x75\x07\x00";
        assert!(Amount::read(&mut max_money_p1.as_ref()).is_err());

        let neg_max_money = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\xc0\xf8\xa5\x0f\x8a\xf8\xff";
        assert_eq!(
            Amount::read(&mut neg_max_money.as_ref()).unwrap(),
            Amount::from(zec(), -MAX_MONEY).unwrap()
        );

        let neg_max_money_m1 = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xbf\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(Amount::read(&mut neg_max_money_m1.as_ref()).is_err());
    }

    #[test]
    #[should_panic]
    fn add_panics_on_overflow() {
        let v = Amount::from(zec(), MAX_MONEY).unwrap();
        let _sum = v + Amount::from(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn add_assign_panics_on_overflow() {
        let mut a = Amount::from(zec(), MAX_MONEY).unwrap();
        a += Amount::from(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_panics_on_underflow() {
        let v = Amount::from(zec(), -MAX_MONEY).unwrap();
        let _diff = v - Amount::from(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_assign_panics_on_underflow() {
        let mut a = Amount::from(zec(), -MAX_MONEY).unwrap();
        a -= Amount::from(zec(), 1).unwrap();
    }
}
