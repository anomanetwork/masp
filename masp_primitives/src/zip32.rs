//! Implementation of [ZIP 32] for hierarchical deterministic key management.
//!
//! [ZIP 32]: https://zips.z.cash/zip-0032

use aes::Aes256;
use blake2b_simd::Params as Blake2bParams;
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use fpe::ff1::{BinaryNumeralString, FF1};
use std::convert::TryInto;
use std::ops::AddAssign;
use std::str::FromStr;
use std::io::{Error, ErrorKind};

use serde::{Deserialize, Serialize};
use crate::{
    constants::{PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR},
    primitives::{Diversifier, PaymentAddress, ViewingKey},
};
use std::io::{self, Read, Write};

use crate::keys::{
    prf_expand, prf_expand_vec, ExpandedSpendingKey, FullViewingKey, OutgoingViewingKey,
};

pub const ZIP32_SAPLING_MASTER_PERSONALIZATION: &[u8; 16] = b"MASP_IP32Sapling";
pub const ZIP32_SAPLING_FVFP_PERSONALIZATION: &[u8; 16] = b"MASP_SaplingFVFP";
pub const ZIP32_SAPLING_INT_PERSONALIZATION: &[u8; 16] = b"MASP__SaplingInt";

// Common helper functions

fn derive_child_ovk(parent: &OutgoingViewingKey, i_l: &[u8]) -> OutgoingViewingKey {
    let mut ovk = [0u8; 32];
    ovk.copy_from_slice(&prf_expand_vec(i_l, &[&[0x15], &parent.0]).as_bytes()[..32]);
    OutgoingViewingKey(ovk)
}

// ZIP 32 structures

/// A Sapling full viewing key fingerprint
struct FvkFingerprint([u8; 32]);

impl From<&FullViewingKey> for FvkFingerprint {
    fn from(fvk: &FullViewingKey) -> Self {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(ZIP32_SAPLING_FVFP_PERSONALIZATION)
            .to_state();
        h.update(&fvk.to_bytes());
        let mut fvfp = [0u8; 32];
        fvfp.copy_from_slice(h.finalize().as_bytes());
        FvkFingerprint(fvfp)
    }
}

/// A Sapling full viewing key tag
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FvkTag([u8; 4]);

impl FvkFingerprint {
    fn tag(&self) -> FvkTag {
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&self.0[..4]);
        FvkTag(tag)
    }
}

impl FvkTag {
    fn master() -> Self {
        FvkTag([0u8; 4])
    }
}

/// A child index for a derived key
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "arg")]
pub enum ChildIndex {
    NonHardened(u32),
    Hardened(u32), // Hardened(n) == n + (1 << 31) == n' in path notation
}

impl ChildIndex {
    pub fn from_index(i: u32) -> Self {
        match i {
            n if n >= (1 << 31) => ChildIndex::Hardened(n - (1 << 31)),
            n => ChildIndex::NonHardened(n),
        }
    }

    fn master() -> Self {
        ChildIndex::from_index(0)
    }

    fn value(&self) -> u32 {
        match *self {
            ChildIndex::Hardened(i) => i + (1 << 31),
            ChildIndex::NonHardened(i) => i,
        }
    }
}

/// A chain code
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ChainCode([u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DiversifierIndex(pub [u8; 11]);

impl Default for DiversifierIndex {
    fn default() -> Self {
        DiversifierIndex::new()
    }
}

impl DiversifierIndex {
    pub fn new() -> Self {
        DiversifierIndex([0; 11])
    }

    pub fn increment(&mut self) -> Result<(), ()> {
        for k in 0..11 {
            self.0[k] = self.0[k].wrapping_add(1);
            if self.0[k] != 0 {
                // No overflow
                return Ok(());
            }
        }
        // Overflow
        Err(())
    }
}

/// A key used to derive diversifiers for a particular child key
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DiversifierKey(pub [u8; 32]);

impl DiversifierKey {
    pub fn master(sk_m: &[u8]) -> Self {
        let mut dk_m = [0u8; 32];
        dk_m.copy_from_slice(&prf_expand(sk_m, &[0x10]).as_bytes()[..32]);
        DiversifierKey(dk_m)
    }

    fn derive_child(&self, i_l: &[u8]) -> Self {
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&prf_expand_vec(i_l, &[&[0x16], &self.0]).as_bytes()[..32]);
        DiversifierKey(dk)
    }

    fn try_diversifier_internal(ff: &FF1<Aes256>, j: DiversifierIndex) -> Option<Diversifier> {
        // Generate d_j
        let enc = ff
            .encrypt(&[], &BinaryNumeralString::from_bytes_le(&j.0[..]))
            .unwrap();
        let mut d_j = [0; 11];
        d_j.copy_from_slice(&enc.to_bytes_le());
        let diversifier = Diversifier(d_j);

        // validate that the generated diversifier maps to a jubjub subgroup point.
        diversifier.g_d().map(|_| diversifier)
    }

    /// Attempts to produce a diversifier at the given index. Returns None
    /// if the index does not produce a valid diversifier.
    pub fn diversifier(&self, j: DiversifierIndex) -> Option<Diversifier> {
        let ff = FF1::<Aes256>::new(&self.0, 2).unwrap();
        Self::try_diversifier_internal(&ff, j)
    }

    /// Returns the diversifier index to which this key maps the given diversifier.
    ///
    /// This method cannot be used to verify whether the diversifier was originally
    /// generated with this diversifier key, because all valid diversifiers can be
    /// produced by all diversifier keys.
    pub fn diversifier_index(&self, d: &Diversifier) -> DiversifierIndex {
        let ff = FF1::<Aes256>::new(&self.0, 2).unwrap();
        let dec = ff
            .decrypt(&[], &BinaryNumeralString::from_bytes_le(&d.0[..]))
            .unwrap();
        let mut j = DiversifierIndex::new();
        j.0.copy_from_slice(&dec.to_bytes_le());
        j
    }

    /// Returns the first index starting from j that generates a valid
    /// diversifier, along with the corresponding diversifier. Returns
    /// `None` if the diversifier space contains no valid diversifiers
    /// at or above the specified diversifier index.
    pub fn find_diversifier(
        &self,
        mut j: DiversifierIndex,
    ) -> Option<(DiversifierIndex, Diversifier)> {
        let ff = FF1::<Aes256>::new(&self.0, 2).unwrap();
        loop {
            match Self::try_diversifier_internal(&ff, j) {
                Some(d_j) => return Some((j, d_j)),
                None => {
                    if j.increment().is_err() {
                        return None;
                    }
                }
            }
        }
    }
}

/// Attempt to produce a payment address given the specified diversifier
/// index, and return None if the specified index does not produce a valid
/// diversifier.
pub fn sapling_address(
    fvk: &FullViewingKey,
    dk: &DiversifierKey,
    j: DiversifierIndex,
) -> Option<PaymentAddress> {
    dk.diversifier(j)
        .and_then(|d_j| fvk.vk.to_payment_address(d_j))
}

/// Search the diversifier space starting at diversifier index `j` for
/// one which will produce a valid diversifier, and return the payment address
/// constructed using that diversifier along with the index at which the
/// valid diversifier was found.
pub fn sapling_find_address(
    fvk: &FullViewingKey,
    dk: &DiversifierKey,
    j: DiversifierIndex,
) -> Option<(DiversifierIndex, PaymentAddress)> {
    let (j, d_j) = dk.find_diversifier(j)?;
    fvk.vk.to_payment_address(d_j).map(|addr| (j, addr))
}

/// Returns the payment address corresponding to the smallest valid diversifier
/// index, along with that index.
pub fn sapling_default_address(
    fvk: &FullViewingKey,
    dk: &DiversifierKey,
) -> (DiversifierIndex, PaymentAddress) {
    // This unwrap is safe, if you have to search the 2^88 space of
    // diversifiers it'll never return anyway.
    sapling_find_address(fvk, dk, DiversifierIndex::new()).unwrap()
}

/// Returns the internal full viewing key and diversifier key
/// for the provided external FVK = (ak, nk, ovk) and dk encoded
/// in a [Unified FVK].
///
/// [Unified FVK]: https://zips.z.cash/zip-0316#encoding-of-unified-full-incoming-viewing-keys
pub fn sapling_derive_internal_fvk(
    fvk: &FullViewingKey,
    dk: &DiversifierKey,
) -> (FullViewingKey, DiversifierKey) {
    let i = {
        let mut h = Blake2bParams::new()
            .hash_length(32)
            .personal(crate::zip32::ZIP32_SAPLING_INT_PERSONALIZATION)
            .to_state();
        h.update(&fvk.to_bytes());
        h.update(&dk.0);
        h.finalize()
    };
    let i_nsk = jubjub::Fr::from_bytes_wide(prf_expand(i.as_bytes(), &[0x17]).as_array());
    let r = prf_expand(i.as_bytes(), &[0x18]);
    let r = r.as_bytes();
    // PROOF_GENERATION_KEY_GENERATOR = \mathcal{H}^Sapling
    let nk_internal = PROOF_GENERATION_KEY_GENERATOR * i_nsk + fvk.vk.nk;
    let dk_internal = DiversifierKey(r[..32].try_into().unwrap());
    let ovk_internal = OutgoingViewingKey(r[32..].try_into().unwrap());

    (
        FullViewingKey {
            vk: ViewingKey {
                ak: fvk.vk.ak,
                nk: nk_internal,
            },
            ovk: ovk_internal,
        },
        dk_internal,
    )
}

/// A Sapling extended spending key
#[derive(Serialize, Deserialize, Clone, Eq, Hash, Copy)]
pub struct ExtendedSpendingKey {
    depth: u8,
    parent_fvk_tag: FvkTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    pub expsk: ExpandedSpendingKey,
    dk: DiversifierKey,
}

// A Sapling extended full viewing key
#[derive(Clone)]
pub struct ExtendedFullViewingKey {
    depth: u8,
    parent_fvk_tag: FvkTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    pub fvk: FullViewingKey,
    dk: DiversifierKey,
}

impl std::cmp::PartialEq for ExtendedSpendingKey {
    fn eq(&self, rhs: &ExtendedSpendingKey) -> bool {
        self.depth == rhs.depth
            && self.parent_fvk_tag == rhs.parent_fvk_tag
            && self.child_index == rhs.child_index
            && self.chain_code == rhs.chain_code
            && self.expsk.ask == rhs.expsk.ask
            && self.expsk.nsk == rhs.expsk.nsk
            && self.expsk.ovk == rhs.expsk.ovk
            && self.dk == rhs.dk
    }
}

impl std::fmt::Debug for ExtendedSpendingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "ExtendedSpendingKey(d = {}, tag_p = {:?}, i = {:?})",
            self.depth, self.parent_fvk_tag, self.child_index
        )
    }
}

impl std::cmp::PartialEq for ExtendedFullViewingKey {
    fn eq(&self, rhs: &ExtendedFullViewingKey) -> bool {
        self.depth == rhs.depth
            && self.parent_fvk_tag == rhs.parent_fvk_tag
            && self.child_index == rhs.child_index
            && self.chain_code == rhs.chain_code
            && self.fvk.vk.ak == rhs.fvk.vk.ak
            && self.fvk.vk.nk == rhs.fvk.vk.nk
            && self.fvk.ovk == rhs.fvk.ovk
            && self.dk == rhs.dk
    }
}

impl std::fmt::Debug for ExtendedFullViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "ExtendedFullViewingKey(d = {}, tag_p = {:?}, i = {:?})",
            self.depth, self.parent_fvk_tag, self.child_index
        )
    }
}

impl ExtendedSpendingKey {
    pub fn master(seed: &[u8]) -> Self {
        let i = Blake2bParams::new()
            .hash_length(64)
            .personal(ZIP32_SAPLING_MASTER_PERSONALIZATION)
            .hash(seed);

        let sk_m = &i.as_bytes()[..32];
        let mut c_m = [0u8; 32];
        c_m.copy_from_slice(&i.as_bytes()[32..]);

        ExtendedSpendingKey {
            depth: 0,
            parent_fvk_tag: FvkTag::master(),
            child_index: ChildIndex::master(),
            chain_code: ChainCode(c_m),
            expsk: ExpandedSpendingKey::from_spending_key(sk_m),
            dk: DiversifierKey::master(sk_m),
        }
    }

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let depth = reader.read_u8()?;
        let mut tag = [0; 4];
        reader.read_exact(&mut tag)?;
        let i = reader.read_u32::<LittleEndian>()?;
        let mut c = [0; 32];
        reader.read_exact(&mut c)?;
        let expsk = ExpandedSpendingKey::read(reader)?;
        let mut dk = [0; 32];
        reader.read_exact(&mut dk)?;

        Ok(ExtendedSpendingKey {
            depth,
            parent_fvk_tag: FvkTag(tag),
            child_index: ChildIndex::from_index(i),
            chain_code: ChainCode(c),
            expsk,
            dk: DiversifierKey(dk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.depth)?;
        writer.write_all(&self.parent_fvk_tag.0)?;
        writer.write_u32::<LittleEndian>(self.child_index.value())?;
        writer.write_all(&self.chain_code.0)?;
        writer.write_all(&self.expsk.to_bytes())?;
        writer.write_all(&self.dk.0)?;

        Ok(())
    }

    /// Returns the child key corresponding to the path derived from the master key
    pub fn from_path(master: &ExtendedSpendingKey, path: &[ChildIndex]) -> Self {
        let mut xsk = master.clone();
        for &i in path.iter() {
            xsk = xsk.derive_child(i);
        }
        xsk
    }

    #[must_use]
    pub fn derive_child(&self, i: ChildIndex) -> Self {
        let fvk = FullViewingKey::from_expanded_spending_key(&self.expsk);
        let tmp = match i {
            ChildIndex::Hardened(i) => {
                let mut le_i = [0; 4];
                LittleEndian::write_u32(&mut le_i, i + (1 << 31));
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x11], &self.expsk.to_bytes(), &self.dk.0, &le_i],
                )
            }
            ChildIndex::NonHardened(i) => {
                let mut le_i = [0; 4];
                LittleEndian::write_u32(&mut le_i, i);
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x12], &fvk.to_bytes(), &self.dk.0, &le_i],
                )
            }
        };
        let i_l = &tmp.as_bytes()[..32];
        let mut c_i = [0u8; 32];
        c_i.copy_from_slice(&tmp.as_bytes()[32..]);

        ExtendedSpendingKey {
            depth: self.depth + 1,
            parent_fvk_tag: FvkFingerprint::from(&fvk).tag(),
            child_index: i,
            chain_code: ChainCode(c_i),
            expsk: {
                let mut ask = jubjub::Fr::from_bytes_wide(prf_expand(i_l, &[0x13]).as_array());
                let mut nsk = jubjub::Fr::from_bytes_wide(prf_expand(i_l, &[0x14]).as_array());
                ask.add_assign(&self.expsk.ask);
                nsk.add_assign(&self.expsk.nsk);
                let ovk = derive_child_ovk(&self.expsk.ovk, i_l);
                ExpandedSpendingKey { ask, nsk, ovk }
            },
            dk: self.dk.derive_child(i_l),
        }
    }

    /// Returns the address with the lowest valid diversifier index, along with
    /// the diversifier index that generated that address.
    pub fn default_address(&self) -> (DiversifierIndex, PaymentAddress) {
        ExtendedFullViewingKey::from(self).default_address()
    }

    /// Derives an internal spending key given an external spending key.
    ///
    /// Specified in [ZIP 32](https://zips.z.cash/zip-0032#deriving-a-sapling-internal-spending-key).
    #[must_use]
    pub fn derive_internal(&self) -> Self {
        let i = {
            let fvk = FullViewingKey::from_expanded_spending_key(&self.expsk);
            let mut h = Blake2bParams::new()
                .hash_length(32)
                .personal(crate::zip32::ZIP32_SAPLING_INT_PERSONALIZATION)
                .to_state();
            h.update(&fvk.to_bytes());
            h.update(&self.dk.0);
            h.finalize()
        };
        let i_nsk = jubjub::Fr::from_bytes_wide(prf_expand(i.as_bytes(), &[0x17]).as_array());
        let r = prf_expand(i.as_bytes(), &[0x18]);
        let r = r.as_bytes();
        let nsk_internal = i_nsk + self.expsk.nsk;
        let dk_internal = DiversifierKey(r[..32].try_into().unwrap());
        let ovk_internal = OutgoingViewingKey(r[32..].try_into().unwrap());

        ExtendedSpendingKey {
            depth: self.depth,
            parent_fvk_tag: self.parent_fvk_tag,
            child_index: self.child_index,
            chain_code: self.chain_code,
            expsk: ExpandedSpendingKey {
                ask: self.expsk.ask,
                nsk: nsk_internal,
                ovk: ovk_internal,
            },
            dk: dk_internal,
        }
    }
}

impl FromStr for ExtendedSpendingKey {
    type Err = std::io::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(|x| Error::new(ErrorKind::InvalidData, x))?;
        Ok(ExtendedSpendingKey::master(vec.as_ref()))
    }
}

impl<'a> From<&'a ExtendedSpendingKey> for ExtendedFullViewingKey {
    fn from(xsk: &ExtendedSpendingKey) -> Self {
        ExtendedFullViewingKey {
            depth: xsk.depth,
            parent_fvk_tag: xsk.parent_fvk_tag,
            child_index: xsk.child_index,
            chain_code: xsk.chain_code,
            fvk: FullViewingKey::from_expanded_spending_key(&xsk.expsk),
            dk: xsk.dk,
        }
    }
}

impl ExtendedFullViewingKey {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let depth = reader.read_u8()?;
        let mut tag = [0; 4];
        reader.read_exact(&mut tag)?;
        let i = reader.read_u32::<LittleEndian>()?;
        let mut c = [0; 32];
        reader.read_exact(&mut c)?;
        let fvk = FullViewingKey::read(&mut reader)?;
        let mut dk = [0; 32];
        reader.read_exact(&mut dk)?;

        Ok(ExtendedFullViewingKey {
            depth,
            parent_fvk_tag: FvkTag(tag),
            child_index: ChildIndex::from_index(i),
            chain_code: ChainCode(c),
            fvk,
            dk: DiversifierKey(dk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.depth)?;
        writer.write_all(&self.parent_fvk_tag.0)?;
        writer.write_u32::<LittleEndian>(self.child_index.value())?;
        writer.write_all(&self.chain_code.0)?;
        writer.write_all(&self.fvk.to_bytes())?;
        writer.write_all(&self.dk.0)?;

        Ok(())
    }

    pub fn derive_child(&self, i: ChildIndex) -> Result<Self, ()> {
        let tmp = match i {
            ChildIndex::Hardened(_) => return Err(()),
            ChildIndex::NonHardened(i) => {
                let mut le_i = [0; 4];
                LittleEndian::write_u32(&mut le_i, i);
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x12], &self.fvk.to_bytes(), &self.dk.0, &le_i],
                )
            }
        };
        let i_l = &tmp.as_bytes()[..32];
        let mut c_i = [0u8; 32];
        c_i.copy_from_slice(&tmp.as_bytes()[32..]);

        Ok(ExtendedFullViewingKey {
            depth: self.depth + 1,
            parent_fvk_tag: FvkFingerprint::from(&self.fvk).tag(),
            child_index: i,
            chain_code: ChainCode(c_i),
            fvk: {
                let i_ask = jubjub::Fr::from_bytes_wide(prf_expand(i_l, &[0x13]).as_array());
                let i_nsk = jubjub::Fr::from_bytes_wide(prf_expand(i_l, &[0x14]).as_array());
                let ak = (SPENDING_KEY_GENERATOR * i_ask) + self.fvk.vk.ak;
                let nk = (PROOF_GENERATION_KEY_GENERATOR * i_nsk) + self.fvk.vk.nk;

                FullViewingKey {
                    vk: ViewingKey { ak, nk },
                    ovk: derive_child_ovk(&self.fvk.ovk, i_l),
                }
            },
            dk: self.dk.derive_child(i_l),
        })
    }

    /// Attempt to produce a payment address given the specified diversifier
    /// index, and return None if the specified index does not produce a valid
    /// diversifier.
    pub fn address(&self, j: DiversifierIndex) -> Option<PaymentAddress> {
        sapling_address(&self.fvk, &self.dk, j)
    }

    /// Search the diversifier space starting at diversifier index `j` for
    /// one which will produce a valid diversifier, and return the payment address
    /// constructed using that diversifier along with the index at which the
    /// valid diversifier was found.
    pub fn find_address(&self, j: DiversifierIndex) -> Option<(DiversifierIndex, PaymentAddress)> {
        sapling_find_address(&self.fvk, &self.dk, j)
    }

    /// Returns the payment address corresponding to the smallest valid diversifier
    /// index, along with that index.
    pub fn default_address(&self) -> (DiversifierIndex, PaymentAddress) {
        sapling_default_address(&self.fvk, &self.dk)
    }

    /// Derives an internal full viewing key used for internal operations such
    /// as change and auto-shielding. The internal FVK has the same spend authority
    /// (the private key corresponding to ak) as the original, but viewing authority
    /// only for internal transfers.
    ///
    /// Specified in [ZIP 32](https://zips.z.cash/zip-0032#deriving-a-sapling-internal-full-viewing-key).
    #[must_use]
    pub fn derive_internal(&self) -> Self {
        let (fvk_internal, dk_internal) = sapling_derive_internal_fvk(&self.fvk, &self.dk);

        ExtendedFullViewingKey {
            depth: self.depth,
            parent_fvk_tag: self.parent_fvk_tag,
            child_index: self.child_index,
            chain_code: self.chain_code,
            fvk: fvk_internal,
            dk: dk_internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::PrimeField;
    use group::GroupEncoding;

    #[test]
    fn derive_nonhardened_child() {
        let seed = [0; 32];
        let xsk_m = ExtendedSpendingKey::master(&seed);
        let xfvk_m = ExtendedFullViewingKey::from(&xsk_m);

        let i_5 = ChildIndex::NonHardened(5);
        let xsk_5 = xsk_m.derive_child(i_5);
        let xfvk_5 = xfvk_m.derive_child(i_5);

        assert!(xfvk_5.is_ok());
        assert_eq!(ExtendedFullViewingKey::from(&xsk_5), xfvk_5.unwrap());
    }

    #[test]
    fn derive_hardened_child() {
        let seed = [0; 32];
        let xsk_m = ExtendedSpendingKey::master(&seed);
        let xfvk_m = ExtendedFullViewingKey::from(&xsk_m);

        let i_5h = ChildIndex::Hardened(5);
        let xsk_5h = xsk_m.derive_child(i_5h);
        let xfvk_5h = xfvk_m.derive_child(i_5h);

        // Cannot derive a hardened child from an ExtendedFullViewingKey
        assert!(xfvk_5h.is_err());
        let xfvk_5h = ExtendedFullViewingKey::from(&xsk_5h);

        let i_7 = ChildIndex::NonHardened(7);
        let xsk_5h_7 = xsk_5h.derive_child(i_7);
        let xfvk_5h_7 = xfvk_5h.derive_child(i_7);

        // But we *can* derive a non-hardened child from a hardened parent
        assert!(xfvk_5h_7.is_ok());
        assert_eq!(ExtendedFullViewingKey::from(&xsk_5h_7), xfvk_5h_7.unwrap());
    }

    #[test]
    fn path() {
        let seed = [0; 32];
        let xsk_m = ExtendedSpendingKey::master(&seed);

        let xsk_5h = xsk_m.derive_child(ChildIndex::Hardened(5));
        assert_eq!(
            ExtendedSpendingKey::from_path(&xsk_m, &[ChildIndex::Hardened(5)]),
            xsk_5h
        );

        let xsk_5h_7 = xsk_5h.derive_child(ChildIndex::NonHardened(7));
        assert_eq!(
            ExtendedSpendingKey::from_path(
                &xsk_m,
                &[ChildIndex::Hardened(5), ChildIndex::NonHardened(7)]
            ),
            xsk_5h_7
        );
    }

    #[test]
    fn diversifier() {
        let dk = DiversifierKey([0; 32]);
        let j_0 = DiversifierIndex::new();
        let j_1 = DiversifierIndex([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let j_2 = DiversifierIndex([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let j_3 = DiversifierIndex([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Computed using this Rust implementation
        let d_0 = [220, 231, 126, 188, 236, 10, 38, 175, 214, 153, 140];
        let d_3 = [60, 253, 170, 8, 171, 147, 220, 31, 3, 144, 34];

        // j = 0
        let d_j = dk.diversifier(j_0).unwrap();
        assert_eq!(d_j.0, d_0);
        assert_eq!(dk.diversifier_index(&Diversifier(d_0)), j_0);

        // j = 1
        assert_eq!(dk.diversifier(j_1), None);

        // j = 2
        assert_eq!(dk.diversifier(j_2), None);

        // j = 3
        let d_j = dk.diversifier(j_3).unwrap();
        assert_eq!(d_j.0, d_3);
        assert_eq!(dk.diversifier_index(&Diversifier(d_3)), j_3);
    }

    #[test]
    fn find_diversifier() {
        let dk = DiversifierKey([0; 32]);
        let j_0 = DiversifierIndex::new();
        let j_1 = DiversifierIndex([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let j_2 = DiversifierIndex([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let j_3 = DiversifierIndex([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Computed using this Rust implementation
        let d_0 = [220, 231, 126, 188, 236, 10, 38, 175, 214, 153, 140];
        let d_3 = [60, 253, 170, 8, 171, 147, 220, 31, 3, 144, 34];

        // j = 0
        let (j, d_j) = dk.find_diversifier(j_0).unwrap();
        assert_eq!(j, j_0);
        assert_eq!(d_j.0, d_0);

        // j = 1
        let (j, d_j) = dk.find_diversifier(j_1).unwrap();
        assert_eq!(j, j_3);
        assert_eq!(d_j.0, d_3);

        // j = 2
        let (j, d_j) = dk.find_diversifier(j_2).unwrap();
        assert_eq!(j, j_3);
        assert_eq!(d_j.0, d_3);

        // j = 3
        let (j, d_j) = dk.find_diversifier(j_3).unwrap();
        assert_eq!(j, j_3);
        assert_eq!(d_j.0, d_3);
    }

    #[test]
    fn address() {
        let seed = [0; 32];
        let xsk_m = ExtendedSpendingKey::master(&seed);
        let xfvk_m = ExtendedFullViewingKey::from(&xsk_m);
        let j_0 = DiversifierIndex::new();
        let addr_m = xfvk_m.address(j_0).unwrap();
        assert_eq!(
            addr_m.diversifier().0,
            // Computed using this Rust implementation
            [1, 176, 125, 234, 196, 5, 225, 212, 95, 175, 239]
        );

        let j_1 = DiversifierIndex([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(xfvk_m.address(j_1), None);
    }
    #[test]
    fn default_address() {
        let seed = [0; 32];
        let xsk_m = ExtendedSpendingKey::master(&seed);
        let (j_m, addr_m) = xsk_m.default_address();
        assert_eq!(j_m.0, [0; 11]);
        assert_eq!(
            addr_m.diversifier().0,
            // Computed using ExtendedSpendingKey.master(bytes([0]*32)).diversifier(0) in sapling_zip32.py using MASP personalizations
            [1, 176, 125, 234, 196, 5, 225, 212, 95, 175, 239]
        );
    }

    #[test]
    fn read_write() {
        let seed = [0; 32];
        let xsk = ExtendedSpendingKey::master(&seed);
        let fvk = ExtendedFullViewingKey::from(&xsk);

        let mut ser = vec![];
        xsk.write(&mut ser).unwrap();
        let mut rdr = &ser[..];
        let xsk2 = ExtendedSpendingKey::read(&mut rdr).unwrap();
        assert_eq!(xsk2, xsk);

        let mut ser = vec![];
        fvk.write(&mut ser).unwrap();
        let mut rdr = &ser[..];
        let fvk2 = ExtendedFullViewingKey::read(&mut rdr).unwrap();
        assert_eq!(fvk2, fvk);
    }

    #[test]
    fn test_vectors() {
        struct TestVector {
            ask: Option<[u8; 32]>,
            nsk: Option<[u8; 32]>,
            ovk: [u8; 32],
            dk: [u8; 32],
            c: [u8; 32],
            ak: [u8; 32],
            nk: [u8; 32],
            ivk: [u8; 32],
            xsk: Option<[u8; 169]>,
            xfvk: [u8; 169],
            fp: [u8; 32],
            d0: Option<[u8; 11]>,
            d1: Option<[u8; 11]>,
            d2: Option<[u8; 11]>,
            dmax: Option<[u8; 11]>,
        }

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_zip32.py
        let test_vectors = vec![
            TestVector {
                ask: Some([
                    0xac, 0x4d, 0xa2, 0xa5, 0xe0, 0xa5, 0xe3, 0xec, 0x2d, 0xcb, 0xd7, 0x04, 0xf1,
                    0xb0, 0x8d, 0x85, 0x0f, 0xe1, 0x40, 0xea, 0x61, 0x07, 0x2c, 0xe3, 0xf8, 0x70,
                    0xe2, 0x70, 0xae, 0xcd, 0x8f, 0x05,
                ]),
                nsk: Some([
                    0x47, 0x29, 0x3f, 0xb1, 0xe9, 0x3a, 0x86, 0x63, 0xf9, 0xa9, 0x12, 0x56, 0x52,
                    0xb6, 0xdc, 0x3d, 0x56, 0x17, 0x89, 0xc0, 0x3b, 0x67, 0x4a, 0x4c, 0xc7, 0x38,
                    0xa9, 0x24, 0x9a, 0xaf, 0x08, 0x09,
                ]),
                ovk: [
                    0xcf, 0x6b, 0xed, 0xb6, 0xc5, 0x49, 0x4e, 0xba, 0xb7, 0x7f, 0x58, 0xa8, 0x57,
                    0x35, 0x59, 0xc5, 0xd2, 0x68, 0x3a, 0x25, 0x22, 0x46, 0x49, 0xcb, 0x8d, 0x44,
                    0x80, 0xe8, 0xa0, 0x54, 0x58, 0xd6,
                ],
                dk: [
                    0xab, 0xcb, 0x9e, 0x0a, 0x9b, 0xb0, 0x77, 0xb4, 0x34, 0x50, 0x68, 0x96, 0xde,
                    0x92, 0x9a, 0x7a, 0xc3, 0x7f, 0xea, 0xa8, 0x1b, 0xec, 0x17, 0xe0, 0x3b, 0x60,
                    0xd0, 0x60, 0x5e, 0xf7, 0xbc, 0x42,
                ],
                c: [
                    0xe4, 0xca, 0x49, 0x8a, 0x73, 0x59, 0x2a, 0x72, 0xc6, 0x0c, 0x2e, 0x61, 0x1e,
                    0x79, 0x70, 0x2f, 0x9d, 0xc0, 0x17, 0x60, 0x23, 0x01, 0xdc, 0xb5, 0xcc, 0x3d,
                    0xf0, 0x1d, 0x5c, 0xc0, 0xf0, 0x67,
                ],
                ak: [
                    0xf6, 0x5d, 0x7b, 0x4a, 0xb9, 0x71, 0x5c, 0x07, 0xc6, 0xb7, 0x8b, 0xd8, 0x22,
                    0xac, 0x39, 0xa7, 0x84, 0x81, 0xeb, 0x36, 0x07, 0x9d, 0x06, 0xdc, 0x86, 0x79,
                    0xda, 0xab, 0xab, 0x92, 0x00, 0x55,
                ],
                nk: [
                    0x2b, 0x41, 0x55, 0x3f, 0x32, 0xa2, 0xb6, 0x60, 0xe1, 0x72, 0x6c, 0x31, 0x33,
                    0x19, 0xd3, 0x55, 0x33, 0x16, 0x6c, 0xcf, 0x52, 0xc1, 0x5a, 0xc2, 0x3c, 0xbd,
                    0xe3, 0xd2, 0x0d, 0x55, 0xcb, 0x01,
                ],
                ivk: [
                    0x8c, 0x90, 0xb7, 0x87, 0x36, 0x4d, 0xd1, 0x29, 0x11, 0xb6, 0x4b, 0x1e, 0xbf,
                    0x8b, 0xfc, 0x04, 0xbd, 0xc5, 0x5f, 0x97, 0xae, 0x85, 0x1e, 0xb3, 0x96, 0x27,
                    0x75, 0x56, 0x42, 0x42, 0xa1, 0x02,
                ],
                xsk: Some([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe4, 0xca, 0x49, 0x8a,
                    0x73, 0x59, 0x2a, 0x72, 0xc6, 0x0c, 0x2e, 0x61, 0x1e, 0x79, 0x70, 0x2f, 0x9d,
                    0xc0, 0x17, 0x60, 0x23, 0x01, 0xdc, 0xb5, 0xcc, 0x3d, 0xf0, 0x1d, 0x5c, 0xc0,
                    0xf0, 0x67, 0xac, 0x4d, 0xa2, 0xa5, 0xe0, 0xa5, 0xe3, 0xec, 0x2d, 0xcb, 0xd7,
                    0x04, 0xf1, 0xb0, 0x8d, 0x85, 0x0f, 0xe1, 0x40, 0xea, 0x61, 0x07, 0x2c, 0xe3,
                    0xf8, 0x70, 0xe2, 0x70, 0xae, 0xcd, 0x8f, 0x05, 0x47, 0x29, 0x3f, 0xb1, 0xe9,
                    0x3a, 0x86, 0x63, 0xf9, 0xa9, 0x12, 0x56, 0x52, 0xb6, 0xdc, 0x3d, 0x56, 0x17,
                    0x89, 0xc0, 0x3b, 0x67, 0x4a, 0x4c, 0xc7, 0x38, 0xa9, 0x24, 0x9a, 0xaf, 0x08,
                    0x09, 0xcf, 0x6b, 0xed, 0xb6, 0xc5, 0x49, 0x4e, 0xba, 0xb7, 0x7f, 0x58, 0xa8,
                    0x57, 0x35, 0x59, 0xc5, 0xd2, 0x68, 0x3a, 0x25, 0x22, 0x46, 0x49, 0xcb, 0x8d,
                    0x44, 0x80, 0xe8, 0xa0, 0x54, 0x58, 0xd6, 0xab, 0xcb, 0x9e, 0x0a, 0x9b, 0xb0,
                    0x77, 0xb4, 0x34, 0x50, 0x68, 0x96, 0xde, 0x92, 0x9a, 0x7a, 0xc3, 0x7f, 0xea,
                    0xa8, 0x1b, 0xec, 0x17, 0xe0, 0x3b, 0x60, 0xd0, 0x60, 0x5e, 0xf7, 0xbc, 0x42,
                ]),
                xfvk: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe4, 0xca, 0x49, 0x8a,
                    0x73, 0x59, 0x2a, 0x72, 0xc6, 0x0c, 0x2e, 0x61, 0x1e, 0x79, 0x70, 0x2f, 0x9d,
                    0xc0, 0x17, 0x60, 0x23, 0x01, 0xdc, 0xb5, 0xcc, 0x3d, 0xf0, 0x1d, 0x5c, 0xc0,
                    0xf0, 0x67, 0xf6, 0x5d, 0x7b, 0x4a, 0xb9, 0x71, 0x5c, 0x07, 0xc6, 0xb7, 0x8b,
                    0xd8, 0x22, 0xac, 0x39, 0xa7, 0x84, 0x81, 0xeb, 0x36, 0x07, 0x9d, 0x06, 0xdc,
                    0x86, 0x79, 0xda, 0xab, 0xab, 0x92, 0x00, 0x55, 0x2b, 0x41, 0x55, 0x3f, 0x32,
                    0xa2, 0xb6, 0x60, 0xe1, 0x72, 0x6c, 0x31, 0x33, 0x19, 0xd3, 0x55, 0x33, 0x16,
                    0x6c, 0xcf, 0x52, 0xc1, 0x5a, 0xc2, 0x3c, 0xbd, 0xe3, 0xd2, 0x0d, 0x55, 0xcb,
                    0x01, 0xcf, 0x6b, 0xed, 0xb6, 0xc5, 0x49, 0x4e, 0xba, 0xb7, 0x7f, 0x58, 0xa8,
                    0x57, 0x35, 0x59, 0xc5, 0xd2, 0x68, 0x3a, 0x25, 0x22, 0x46, 0x49, 0xcb, 0x8d,
                    0x44, 0x80, 0xe8, 0xa0, 0x54, 0x58, 0xd6, 0xab, 0xcb, 0x9e, 0x0a, 0x9b, 0xb0,
                    0x77, 0xb4, 0x34, 0x50, 0x68, 0x96, 0xde, 0x92, 0x9a, 0x7a, 0xc3, 0x7f, 0xea,
                    0xa8, 0x1b, 0xec, 0x17, 0xe0, 0x3b, 0x60, 0xd0, 0x60, 0x5e, 0xf7, 0xbc, 0x42,
                ],
                fp: [
                    0x17, 0x27, 0x55, 0xf6, 0x51, 0x82, 0xb4, 0xe4, 0x32, 0x12, 0xe2, 0xe6, 0x4f,
                    0x73, 0xbe, 0xc7, 0x43, 0xd3, 0xa6, 0xbd, 0x75, 0xaf, 0x08, 0xfe, 0xaa, 0x2d,
                    0x6d, 0x65, 0x02, 0x31, 0xdc, 0xb3,
                ],
                d0: Some([
                    0x99, 0x3f, 0x45, 0x5b, 0x74, 0x15, 0x9e, 0x49, 0xf9, 0xcf, 0x33,
                ]),
                d1: None,
                d2: None,
                dmax: Some([
                    0x50, 0xac, 0x45, 0xb9, 0x79, 0xa1, 0x7d, 0x83, 0xa7, 0x49, 0xea,
                ]),
            },
            TestVector {
                ask: Some([
                    0x39, 0xc1, 0x95, 0x8c, 0x62, 0x11, 0x2e, 0x41, 0x35, 0xa2, 0x66, 0xe5, 0x4e,
                    0x92, 0x1b, 0x13, 0xd7, 0xd9, 0x81, 0x43, 0x6e, 0x7f, 0x7a, 0x8c, 0x03, 0xf0,
                    0xd5, 0xb8, 0x2e, 0x57, 0x09, 0x0a,
                ]),
                nsk: Some([
                    0x3b, 0x42, 0x80, 0x25, 0x1e, 0x66, 0x9e, 0xb7, 0xcd, 0x81, 0xe4, 0x52, 0xed,
                    0x95, 0x5e, 0x82, 0xe7, 0xae, 0x02, 0x7c, 0x33, 0x21, 0x82, 0x7c, 0x58, 0x8c,
                    0x91, 0xec, 0xad, 0x56, 0xce, 0x00,
                ]),
                ovk: [
                    0x0c, 0x7b, 0xf0, 0x2a, 0x34, 0xc8, 0x02, 0x81, 0x8f, 0xee, 0xf8, 0x8b, 0x17,
                    0x92, 0x7d, 0xfe, 0xb1, 0x6c, 0x36, 0xea, 0x0b, 0x3b, 0x49, 0xe6, 0x49, 0xb4,
                    0x05, 0x51, 0x13, 0xe7, 0xa2, 0xfb,
                ],
                dk: [
                    0x13, 0x8d, 0x73, 0x3b, 0xa4, 0x20, 0x50, 0x4b, 0xa3, 0x04, 0x3b, 0x26, 0x80,
                    0x4d, 0x69, 0x4c, 0x5c, 0x7a, 0x07, 0xc8, 0xb2, 0x85, 0x43, 0xfd, 0x25, 0xab,
                    0x69, 0xa7, 0x00, 0x7f, 0xd9, 0xe0,
                ],
                c: [
                    0xb9, 0x7e, 0x35, 0x12, 0x19, 0x50, 0x9a, 0xba, 0x1a, 0xb6, 0x3d, 0xfe, 0xdc,
                    0x6e, 0x4b, 0x68, 0x17, 0x60, 0x6e, 0xc3, 0xe1, 0xac, 0x96, 0x51, 0x42, 0xa1,
                    0x90, 0x7b, 0x50, 0xe4, 0x95, 0xfc,
                ],
                ak: [
                    0x82, 0xf1, 0x67, 0x79, 0xcb, 0xf9, 0xad, 0x9a, 0x3d, 0xb2, 0xff, 0x07, 0xea,
                    0x4e, 0xbc, 0x15, 0x9d, 0x0a, 0x31, 0x42, 0x46, 0xbe, 0xd6, 0x39, 0x39, 0x34,
                    0xe1, 0x22, 0x0a, 0xcc, 0xa9, 0x14,
                ],
                nk: [
                    0x97, 0x14, 0x52, 0xc9, 0x62, 0x54, 0xff, 0xa1, 0xed, 0xe7, 0xad, 0x1e, 0x5b,
                    0x66, 0x3e, 0x70, 0x53, 0x1a, 0x8b, 0xfb, 0x1e, 0x91, 0x63, 0x8d, 0xdc, 0x58,
                    0xab, 0xb8, 0xb9, 0x25, 0x48, 0xd2,
                ],
                ivk: [
                    0xcf, 0xa2, 0x2b, 0xb7, 0x3c, 0xc3, 0x66, 0x7c, 0x2f, 0x3b, 0xb4, 0xdc, 0x6f,
                    0x33, 0xde, 0xe6, 0x9c, 0x4d, 0x51, 0xde, 0x5c, 0x25, 0x52, 0x68, 0x7e, 0x18,
                    0xcd, 0x26, 0x78, 0xc9, 0xf7, 0x00,
                ],
                xsk: Some([
                    0x01, 0x17, 0x27, 0x55, 0xf6, 0x01, 0x00, 0x00, 0x00, 0xb9, 0x7e, 0x35, 0x12,
                    0x19, 0x50, 0x9a, 0xba, 0x1a, 0xb6, 0x3d, 0xfe, 0xdc, 0x6e, 0x4b, 0x68, 0x17,
                    0x60, 0x6e, 0xc3, 0xe1, 0xac, 0x96, 0x51, 0x42, 0xa1, 0x90, 0x7b, 0x50, 0xe4,
                    0x95, 0xfc, 0x39, 0xc1, 0x95, 0x8c, 0x62, 0x11, 0x2e, 0x41, 0x35, 0xa2, 0x66,
                    0xe5, 0x4e, 0x92, 0x1b, 0x13, 0xd7, 0xd9, 0x81, 0x43, 0x6e, 0x7f, 0x7a, 0x8c,
                    0x03, 0xf0, 0xd5, 0xb8, 0x2e, 0x57, 0x09, 0x0a, 0x3b, 0x42, 0x80, 0x25, 0x1e,
                    0x66, 0x9e, 0xb7, 0xcd, 0x81, 0xe4, 0x52, 0xed, 0x95, 0x5e, 0x82, 0xe7, 0xae,
                    0x02, 0x7c, 0x33, 0x21, 0x82, 0x7c, 0x58, 0x8c, 0x91, 0xec, 0xad, 0x56, 0xce,
                    0x00, 0x0c, 0x7b, 0xf0, 0x2a, 0x34, 0xc8, 0x02, 0x81, 0x8f, 0xee, 0xf8, 0x8b,
                    0x17, 0x92, 0x7d, 0xfe, 0xb1, 0x6c, 0x36, 0xea, 0x0b, 0x3b, 0x49, 0xe6, 0x49,
                    0xb4, 0x05, 0x51, 0x13, 0xe7, 0xa2, 0xfb, 0x13, 0x8d, 0x73, 0x3b, 0xa4, 0x20,
                    0x50, 0x4b, 0xa3, 0x04, 0x3b, 0x26, 0x80, 0x4d, 0x69, 0x4c, 0x5c, 0x7a, 0x07,
                    0xc8, 0xb2, 0x85, 0x43, 0xfd, 0x25, 0xab, 0x69, 0xa7, 0x00, 0x7f, 0xd9, 0xe0,
                ]),
                xfvk: [
                    0x01, 0x17, 0x27, 0x55, 0xf6, 0x01, 0x00, 0x00, 0x00, 0xb9, 0x7e, 0x35, 0x12,
                    0x19, 0x50, 0x9a, 0xba, 0x1a, 0xb6, 0x3d, 0xfe, 0xdc, 0x6e, 0x4b, 0x68, 0x17,
                    0x60, 0x6e, 0xc3, 0xe1, 0xac, 0x96, 0x51, 0x42, 0xa1, 0x90, 0x7b, 0x50, 0xe4,
                    0x95, 0xfc, 0x82, 0xf1, 0x67, 0x79, 0xcb, 0xf9, 0xad, 0x9a, 0x3d, 0xb2, 0xff,
                    0x07, 0xea, 0x4e, 0xbc, 0x15, 0x9d, 0x0a, 0x31, 0x42, 0x46, 0xbe, 0xd6, 0x39,
                    0x39, 0x34, 0xe1, 0x22, 0x0a, 0xcc, 0xa9, 0x14, 0x97, 0x14, 0x52, 0xc9, 0x62,
                    0x54, 0xff, 0xa1, 0xed, 0xe7, 0xad, 0x1e, 0x5b, 0x66, 0x3e, 0x70, 0x53, 0x1a,
                    0x8b, 0xfb, 0x1e, 0x91, 0x63, 0x8d, 0xdc, 0x58, 0xab, 0xb8, 0xb9, 0x25, 0x48,
                    0xd2, 0x0c, 0x7b, 0xf0, 0x2a, 0x34, 0xc8, 0x02, 0x81, 0x8f, 0xee, 0xf8, 0x8b,
                    0x17, 0x92, 0x7d, 0xfe, 0xb1, 0x6c, 0x36, 0xea, 0x0b, 0x3b, 0x49, 0xe6, 0x49,
                    0xb4, 0x05, 0x51, 0x13, 0xe7, 0xa2, 0xfb, 0x13, 0x8d, 0x73, 0x3b, 0xa4, 0x20,
                    0x50, 0x4b, 0xa3, 0x04, 0x3b, 0x26, 0x80, 0x4d, 0x69, 0x4c, 0x5c, 0x7a, 0x07,
                    0xc8, 0xb2, 0x85, 0x43, 0xfd, 0x25, 0xab, 0x69, 0xa7, 0x00, 0x7f, 0xd9, 0xe0,
                ],
                fp: [
                    0xe5, 0x1f, 0x7b, 0xd0, 0x24, 0x36, 0x88, 0xe3, 0xa7, 0x5f, 0x09, 0xf3, 0x5e,
                    0xe8, 0xee, 0xbc, 0xad, 0x30, 0x69, 0x88, 0xed, 0xb3, 0x80, 0x9f, 0x76, 0xd6,
                    0xd4, 0xbb, 0x53, 0xb6, 0x3f, 0x7c,
                ],
                d0: None,
                d1: Some([
                    0x42, 0xce, 0x67, 0xa3, 0x2d, 0x00, 0xe3, 0xb8, 0xfb, 0x05, 0x13,
                ]),
                d2: None,
                dmax: Some([
                    0xbc, 0x15, 0x9c, 0x91, 0xe7, 0xab, 0x50, 0xb2, 0x52, 0x91, 0x03,
                ]),
            },
            TestVector {
                ask: Some([
                    0xe3, 0x78, 0xd4, 0x24, 0x13, 0x88, 0x99, 0x46, 0xa2, 0x3e, 0x4c, 0x1b, 0x79,
                    0x0e, 0x5d, 0xde, 0xbc, 0xce, 0x31, 0x5f, 0xdc, 0x87, 0xe4, 0x69, 0xfe, 0x21,
                    0xd6, 0x39, 0xf2, 0x82, 0x06, 0x0b,
                ]),
                nsk: Some([
                    0x29, 0x6d, 0x06, 0xb9, 0xda, 0xf7, 0x9d, 0x33, 0xbf, 0xac, 0x3d, 0xaa, 0x13,
                    0x28, 0x3a, 0xd8, 0x0e, 0xf9, 0xb7, 0xc2, 0xab, 0xa2, 0x0b, 0x0b, 0x22, 0x8c,
                    0xc8, 0x33, 0x0c, 0x8d, 0x70, 0x03,
                ]),
                ovk: [
                    0xb1, 0x62, 0x15, 0x54, 0x71, 0x8f, 0xbe, 0xc3, 0xac, 0x3d, 0xb9, 0x4d, 0x23,
                    0xfe, 0x16, 0xd5, 0xbb, 0x13, 0x7f, 0xe3, 0x24, 0xb8, 0x53, 0xa5, 0xa0, 0xee,
                    0xf3, 0x36, 0x23, 0x98, 0x75, 0x4e,
                ],
                dk: [
                    0xad, 0xf8, 0xd1, 0xba, 0x74, 0xf4, 0xdf, 0xdd, 0xe6, 0xb0, 0x44, 0x37, 0x94,
                    0x74, 0xaa, 0xc3, 0xc8, 0xef, 0x00, 0x3e, 0xce, 0xe7, 0x14, 0xdd, 0xcf, 0x4c,
                    0x94, 0x7c, 0xa7, 0x2a, 0xeb, 0xa2,
                ],
                c: [
                    0xdb, 0xaa, 0x2d, 0xde, 0xd8, 0x6b, 0xdb, 0x32, 0xfd, 0x60, 0x5b, 0x5e, 0xa0,
                    0xdb, 0x6a, 0x57, 0xa5, 0xb3, 0x3b, 0x36, 0x20, 0x94, 0x8f, 0x76, 0x9c, 0x12,
                    0x85, 0x88, 0x51, 0xeb, 0x83, 0xca,
                ],
                ak: [
                    0x42, 0xec, 0x8b, 0x50, 0x8d, 0xbb, 0x9a, 0x6d, 0x4a, 0x58, 0xf1, 0xb7, 0xcb,
                    0x96, 0x06, 0xfd, 0x75, 0xdd, 0x1c, 0x0d, 0x03, 0x9c, 0x2c, 0xac, 0x19, 0xb2,
                    0x66, 0x52, 0xcb, 0x3b, 0x27, 0xcd,
                ],
                nk: [
                    0x4f, 0x60, 0x3c, 0x21, 0x05, 0xa4, 0x0f, 0x4f, 0xc3, 0xdf, 0x19, 0x76, 0x18,
                    0x25, 0x7c, 0xa0, 0xfc, 0x4e, 0x8b, 0x73, 0x39, 0xd4, 0x80, 0xcd, 0x73, 0xa1,
                    0x08, 0x38, 0xe5, 0xcd, 0x9d, 0x0f,
                ],
                ivk: [
                    0xc5, 0xb1, 0x73, 0x5b, 0xf7, 0xd2, 0xd7, 0x1d, 0x8e, 0x1f, 0x91, 0x62, 0xaf,
                    0x7c, 0x96, 0xb5, 0x3e, 0x95, 0xa2, 0xdd, 0x12, 0x55, 0x27, 0x4a, 0xf6, 0x2d,
                    0x3a, 0x78, 0xf6, 0xd7, 0x4e, 0x05,
                ],
                xsk: Some([
                    0x02, 0xe5, 0x1f, 0x7b, 0xd0, 0x02, 0x00, 0x00, 0x80, 0xdb, 0xaa, 0x2d, 0xde,
                    0xd8, 0x6b, 0xdb, 0x32, 0xfd, 0x60, 0x5b, 0x5e, 0xa0, 0xdb, 0x6a, 0x57, 0xa5,
                    0xb3, 0x3b, 0x36, 0x20, 0x94, 0x8f, 0x76, 0x9c, 0x12, 0x85, 0x88, 0x51, 0xeb,
                    0x83, 0xca, 0xe3, 0x78, 0xd4, 0x24, 0x13, 0x88, 0x99, 0x46, 0xa2, 0x3e, 0x4c,
                    0x1b, 0x79, 0x0e, 0x5d, 0xde, 0xbc, 0xce, 0x31, 0x5f, 0xdc, 0x87, 0xe4, 0x69,
                    0xfe, 0x21, 0xd6, 0x39, 0xf2, 0x82, 0x06, 0x0b, 0x29, 0x6d, 0x06, 0xb9, 0xda,
                    0xf7, 0x9d, 0x33, 0xbf, 0xac, 0x3d, 0xaa, 0x13, 0x28, 0x3a, 0xd8, 0x0e, 0xf9,
                    0xb7, 0xc2, 0xab, 0xa2, 0x0b, 0x0b, 0x22, 0x8c, 0xc8, 0x33, 0x0c, 0x8d, 0x70,
                    0x03, 0xb1, 0x62, 0x15, 0x54, 0x71, 0x8f, 0xbe, 0xc3, 0xac, 0x3d, 0xb9, 0x4d,
                    0x23, 0xfe, 0x16, 0xd5, 0xbb, 0x13, 0x7f, 0xe3, 0x24, 0xb8, 0x53, 0xa5, 0xa0,
                    0xee, 0xf3, 0x36, 0x23, 0x98, 0x75, 0x4e, 0xad, 0xf8, 0xd1, 0xba, 0x74, 0xf4,
                    0xdf, 0xdd, 0xe6, 0xb0, 0x44, 0x37, 0x94, 0x74, 0xaa, 0xc3, 0xc8, 0xef, 0x00,
                    0x3e, 0xce, 0xe7, 0x14, 0xdd, 0xcf, 0x4c, 0x94, 0x7c, 0xa7, 0x2a, 0xeb, 0xa2,
                ]),
                xfvk: [
                    0x02, 0xe5, 0x1f, 0x7b, 0xd0, 0x02, 0x00, 0x00, 0x80, 0xdb, 0xaa, 0x2d, 0xde,
                    0xd8, 0x6b, 0xdb, 0x32, 0xfd, 0x60, 0x5b, 0x5e, 0xa0, 0xdb, 0x6a, 0x57, 0xa5,
                    0xb3, 0x3b, 0x36, 0x20, 0x94, 0x8f, 0x76, 0x9c, 0x12, 0x85, 0x88, 0x51, 0xeb,
                    0x83, 0xca, 0x42, 0xec, 0x8b, 0x50, 0x8d, 0xbb, 0x9a, 0x6d, 0x4a, 0x58, 0xf1,
                    0xb7, 0xcb, 0x96, 0x06, 0xfd, 0x75, 0xdd, 0x1c, 0x0d, 0x03, 0x9c, 0x2c, 0xac,
                    0x19, 0xb2, 0x66, 0x52, 0xcb, 0x3b, 0x27, 0xcd, 0x4f, 0x60, 0x3c, 0x21, 0x05,
                    0xa4, 0x0f, 0x4f, 0xc3, 0xdf, 0x19, 0x76, 0x18, 0x25, 0x7c, 0xa0, 0xfc, 0x4e,
                    0x8b, 0x73, 0x39, 0xd4, 0x80, 0xcd, 0x73, 0xa1, 0x08, 0x38, 0xe5, 0xcd, 0x9d,
                    0x0f, 0xb1, 0x62, 0x15, 0x54, 0x71, 0x8f, 0xbe, 0xc3, 0xac, 0x3d, 0xb9, 0x4d,
                    0x23, 0xfe, 0x16, 0xd5, 0xbb, 0x13, 0x7f, 0xe3, 0x24, 0xb8, 0x53, 0xa5, 0xa0,
                    0xee, 0xf3, 0x36, 0x23, 0x98, 0x75, 0x4e, 0xad, 0xf8, 0xd1, 0xba, 0x74, 0xf4,
                    0xdf, 0xdd, 0xe6, 0xb0, 0x44, 0x37, 0x94, 0x74, 0xaa, 0xc3, 0xc8, 0xef, 0x00,
                    0x3e, 0xce, 0xe7, 0x14, 0xdd, 0xcf, 0x4c, 0x94, 0x7c, 0xa7, 0x2a, 0xeb, 0xa2,
                ],
                fp: [
                    0xe1, 0x61, 0xbc, 0xa7, 0x4c, 0xac, 0x0b, 0xbd, 0x66, 0xb4, 0xa4, 0xad, 0x12,
                    0x71, 0x32, 0x11, 0x60, 0x52, 0xef, 0xf7, 0x65, 0x96, 0x67, 0xd9, 0xf7, 0xfd,
                    0xad, 0xd0, 0x1f, 0x10, 0x08, 0xa1,
                ],
                d0: Some([
                    0x18, 0x36, 0xc0, 0x6f, 0x69, 0x94, 0x47, 0x49, 0xaa, 0x48, 0x0b,
                ]),
                d1: None,
                d2: None,
                dmax: Some([
                    0x63, 0xea, 0x9f, 0xbb, 0x99, 0x95, 0xc9, 0x39, 0x7a, 0xc2, 0x23,
                ]),
            },
            TestVector {
                ask: None,
                nsk: None,
                ovk: [
                    0xb1, 0x62, 0x15, 0x54, 0x71, 0x8f, 0xbe, 0xc3, 0xac, 0x3d, 0xb9, 0x4d, 0x23,
                    0xfe, 0x16, 0xd5, 0xbb, 0x13, 0x7f, 0xe3, 0x24, 0xb8, 0x53, 0xa5, 0xa0, 0xee,
                    0xf3, 0x36, 0x23, 0x98, 0x75, 0x4e,
                ],
                dk: [
                    0xad, 0xf8, 0xd1, 0xba, 0x74, 0xf4, 0xdf, 0xdd, 0xe6, 0xb0, 0x44, 0x37, 0x94,
                    0x74, 0xaa, 0xc3, 0xc8, 0xef, 0x00, 0x3e, 0xce, 0xe7, 0x14, 0xdd, 0xcf, 0x4c,
                    0x94, 0x7c, 0xa7, 0x2a, 0xeb, 0xa2,
                ],
                c: [
                    0xdb, 0xaa, 0x2d, 0xde, 0xd8, 0x6b, 0xdb, 0x32, 0xfd, 0x60, 0x5b, 0x5e, 0xa0,
                    0xdb, 0x6a, 0x57, 0xa5, 0xb3, 0x3b, 0x36, 0x20, 0x94, 0x8f, 0x76, 0x9c, 0x12,
                    0x85, 0x88, 0x51, 0xeb, 0x83, 0xca,
                ],
                ak: [
                    0x42, 0xec, 0x8b, 0x50, 0x8d, 0xbb, 0x9a, 0x6d, 0x4a, 0x58, 0xf1, 0xb7, 0xcb,
                    0x96, 0x06, 0xfd, 0x75, 0xdd, 0x1c, 0x0d, 0x03, 0x9c, 0x2c, 0xac, 0x19, 0xb2,
                    0x66, 0x52, 0xcb, 0x3b, 0x27, 0xcd,
                ],
                nk: [
                    0x4f, 0x60, 0x3c, 0x21, 0x05, 0xa4, 0x0f, 0x4f, 0xc3, 0xdf, 0x19, 0x76, 0x18,
                    0x25, 0x7c, 0xa0, 0xfc, 0x4e, 0x8b, 0x73, 0x39, 0xd4, 0x80, 0xcd, 0x73, 0xa1,
                    0x08, 0x38, 0xe5, 0xcd, 0x9d, 0x0f,
                ],
                ivk: [
                    0xc5, 0xb1, 0x73, 0x5b, 0xf7, 0xd2, 0xd7, 0x1d, 0x8e, 0x1f, 0x91, 0x62, 0xaf,
                    0x7c, 0x96, 0xb5, 0x3e, 0x95, 0xa2, 0xdd, 0x12, 0x55, 0x27, 0x4a, 0xf6, 0x2d,
                    0x3a, 0x78, 0xf6, 0xd7, 0x4e, 0x05,
                ],
                xsk: None,
                xfvk: [
                    0x02, 0xe5, 0x1f, 0x7b, 0xd0, 0x02, 0x00, 0x00, 0x80, 0xdb, 0xaa, 0x2d, 0xde,
                    0xd8, 0x6b, 0xdb, 0x32, 0xfd, 0x60, 0x5b, 0x5e, 0xa0, 0xdb, 0x6a, 0x57, 0xa5,
                    0xb3, 0x3b, 0x36, 0x20, 0x94, 0x8f, 0x76, 0x9c, 0x12, 0x85, 0x88, 0x51, 0xeb,
                    0x83, 0xca, 0x42, 0xec, 0x8b, 0x50, 0x8d, 0xbb, 0x9a, 0x6d, 0x4a, 0x58, 0xf1,
                    0xb7, 0xcb, 0x96, 0x06, 0xfd, 0x75, 0xdd, 0x1c, 0x0d, 0x03, 0x9c, 0x2c, 0xac,
                    0x19, 0xb2, 0x66, 0x52, 0xcb, 0x3b, 0x27, 0xcd, 0x4f, 0x60, 0x3c, 0x21, 0x05,
                    0xa4, 0x0f, 0x4f, 0xc3, 0xdf, 0x19, 0x76, 0x18, 0x25, 0x7c, 0xa0, 0xfc, 0x4e,
                    0x8b, 0x73, 0x39, 0xd4, 0x80, 0xcd, 0x73, 0xa1, 0x08, 0x38, 0xe5, 0xcd, 0x9d,
                    0x0f, 0xb1, 0x62, 0x15, 0x54, 0x71, 0x8f, 0xbe, 0xc3, 0xac, 0x3d, 0xb9, 0x4d,
                    0x23, 0xfe, 0x16, 0xd5, 0xbb, 0x13, 0x7f, 0xe3, 0x24, 0xb8, 0x53, 0xa5, 0xa0,
                    0xee, 0xf3, 0x36, 0x23, 0x98, 0x75, 0x4e, 0xad, 0xf8, 0xd1, 0xba, 0x74, 0xf4,
                    0xdf, 0xdd, 0xe6, 0xb0, 0x44, 0x37, 0x94, 0x74, 0xaa, 0xc3, 0xc8, 0xef, 0x00,
                    0x3e, 0xce, 0xe7, 0x14, 0xdd, 0xcf, 0x4c, 0x94, 0x7c, 0xa7, 0x2a, 0xeb, 0xa2,
                ],
                fp: [
                    0xe1, 0x61, 0xbc, 0xa7, 0x4c, 0xac, 0x0b, 0xbd, 0x66, 0xb4, 0xa4, 0xad, 0x12,
                    0x71, 0x32, 0x11, 0x60, 0x52, 0xef, 0xf7, 0x65, 0x96, 0x67, 0xd9, 0xf7, 0xfd,
                    0xad, 0xd0, 0x1f, 0x10, 0x08, 0xa1,
                ],
                d0: Some([
                    0x18, 0x36, 0xc0, 0x6f, 0x69, 0x94, 0x47, 0x49, 0xaa, 0x48, 0x0b,
                ]),
                d1: None,
                d2: None,
                dmax: Some([
                    0x63, 0xea, 0x9f, 0xbb, 0x99, 0x95, 0xc9, 0x39, 0x7a, 0xc2, 0x23,
                ]),
            },
            TestVector {
                ask: None,
                nsk: None,
                ovk: [
                    0x83, 0x55, 0xaa, 0x44, 0x4f, 0x48, 0xb7, 0x6c, 0xcd, 0x42, 0x83, 0x5f, 0x5f,
                    0x3d, 0x18, 0x2f, 0x10, 0xf6, 0x7b, 0x3f, 0x9b, 0xd1, 0xa7, 0xab, 0xac, 0x7a,
                    0x02, 0xea, 0x8b, 0xa2, 0x91, 0x4b,
                ],
                dk: [
                    0x64, 0xe8, 0x88, 0x71, 0x4d, 0x39, 0x55, 0x03, 0xe8, 0x34, 0xa7, 0x8e, 0xee,
                    0xb9, 0xf4, 0x29, 0x4d, 0x52, 0xac, 0x55, 0xe0, 0xe9, 0x0e, 0x90, 0xc8, 0x1d,
                    0x12, 0x67, 0x97, 0x86, 0x92, 0x70,
                ],
                c: [
                    0xb5, 0xa0, 0x09, 0xf3, 0xad, 0x52, 0xb0, 0x4f, 0xee, 0xac, 0x65, 0xe7, 0x9a,
                    0x6e, 0x30, 0xd8, 0x94, 0x82, 0x51, 0xb7, 0xa8, 0x82, 0x47, 0xb2, 0xce, 0x96,
                    0x78, 0x22, 0xfe, 0x49, 0xcc, 0xa1,
                ],
                ak: [
                    0xc4, 0x74, 0x8f, 0x3e, 0x63, 0xe9, 0x7f, 0x0a, 0xea, 0xff, 0x39, 0x20, 0x51,
                    0x9b, 0x7c, 0x2c, 0x1e, 0xd8, 0x40, 0xd4, 0xdd, 0x7a, 0xc1, 0x1f, 0xb0, 0x46,
                    0x0e, 0xd5, 0xff, 0x9e, 0x2f, 0xe0,
                ],
                nk: [
                    0x01, 0x7d, 0xee, 0xa7, 0x7c, 0x0f, 0xa6, 0x87, 0xfd, 0x0e, 0x7a, 0x11, 0xff,
                    0xcd, 0x3d, 0x3d, 0x11, 0xb8, 0x5c, 0xf5, 0xc0, 0x53, 0x6f, 0xf8, 0xca, 0xea,
                    0x74, 0x88, 0x37, 0xa5, 0x3a, 0xd6,
                ],
                ivk: [
                    0x2d, 0xf3, 0xe1, 0x49, 0xf6, 0xd3, 0x4e, 0x9f, 0xa9, 0xac, 0x66, 0xbd, 0xdc,
                    0x40, 0xe2, 0xb5, 0x93, 0x66, 0x99, 0x99, 0x87, 0xd7, 0xdf, 0x82, 0x9d, 0xec,
                    0x5d, 0x51, 0x74, 0xab, 0xcd, 0x05,
                ],
                xsk: None,
                xfvk: [
                    0x03, 0xe1, 0x61, 0xbc, 0xa7, 0x03, 0x00, 0x00, 0x00, 0xb5, 0xa0, 0x09, 0xf3,
                    0xad, 0x52, 0xb0, 0x4f, 0xee, 0xac, 0x65, 0xe7, 0x9a, 0x6e, 0x30, 0xd8, 0x94,
                    0x82, 0x51, 0xb7, 0xa8, 0x82, 0x47, 0xb2, 0xce, 0x96, 0x78, 0x22, 0xfe, 0x49,
                    0xcc, 0xa1, 0xc4, 0x74, 0x8f, 0x3e, 0x63, 0xe9, 0x7f, 0x0a, 0xea, 0xff, 0x39,
                    0x20, 0x51, 0x9b, 0x7c, 0x2c, 0x1e, 0xd8, 0x40, 0xd4, 0xdd, 0x7a, 0xc1, 0x1f,
                    0xb0, 0x46, 0x0e, 0xd5, 0xff, 0x9e, 0x2f, 0xe0, 0x01, 0x7d, 0xee, 0xa7, 0x7c,
                    0x0f, 0xa6, 0x87, 0xfd, 0x0e, 0x7a, 0x11, 0xff, 0xcd, 0x3d, 0x3d, 0x11, 0xb8,
                    0x5c, 0xf5, 0xc0, 0x53, 0x6f, 0xf8, 0xca, 0xea, 0x74, 0x88, 0x37, 0xa5, 0x3a,
                    0xd6, 0x83, 0x55, 0xaa, 0x44, 0x4f, 0x48, 0xb7, 0x6c, 0xcd, 0x42, 0x83, 0x5f,
                    0x5f, 0x3d, 0x18, 0x2f, 0x10, 0xf6, 0x7b, 0x3f, 0x9b, 0xd1, 0xa7, 0xab, 0xac,
                    0x7a, 0x02, 0xea, 0x8b, 0xa2, 0x91, 0x4b, 0x64, 0xe8, 0x88, 0x71, 0x4d, 0x39,
                    0x55, 0x03, 0xe8, 0x34, 0xa7, 0x8e, 0xee, 0xb9, 0xf4, 0x29, 0x4d, 0x52, 0xac,
                    0x55, 0xe0, 0xe9, 0x0e, 0x90, 0xc8, 0x1d, 0x12, 0x67, 0x97, 0x86, 0x92, 0x70,
                ],
                fp: [
                    0x16, 0x74, 0xa8, 0x94, 0xa4, 0xf3, 0x4c, 0xcb, 0x76, 0x92, 0x03, 0xa0, 0x1a,
                    0x4f, 0xb7, 0x76, 0xc5, 0xe0, 0x68, 0xde, 0xe2, 0x4b, 0x1a, 0xce, 0x7a, 0x42,
                    0x48, 0x6f, 0x35, 0x8e, 0x94, 0x36,
                ],
                d0: Some([
                    0x1b, 0x9b, 0x96, 0x29, 0xb3, 0x83, 0x1c, 0x12, 0xad, 0x1d, 0x06,
                ]),
                d1: Some([
                    0x7a, 0xa8, 0x22, 0x53, 0x7d, 0x01, 0x5c, 0x19, 0xd8, 0x37, 0x46,
                ]),
                d2: None,
                dmax: None,
            },
        ];

        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        let i1 = ChildIndex::NonHardened(1);
        let i2h = ChildIndex::Hardened(2);
        let i3 = ChildIndex::NonHardened(3);

        let m = ExtendedSpendingKey::master(&seed);
        let m_1 = m.derive_child(i1);
        let m_1_2h = ExtendedSpendingKey::from_path(&m, &[i1, i2h]);
        let m_1_2hv = ExtendedFullViewingKey::from(&m_1_2h);
        let m_1_2hv_3 = m_1_2hv.derive_child(i3).unwrap();

        let xfvks = [
            ExtendedFullViewingKey::from(&m),
            ExtendedFullViewingKey::from(&m_1),
            ExtendedFullViewingKey::from(&m_1_2h),
            m_1_2hv, // Appears twice so we can de-duplicate test code below
            m_1_2hv_3,
        ];
        assert_eq!(test_vectors.len(), xfvks.len());

        let xsks = [m, m_1, m_1_2h];

        for j in 0..xsks.len() {
            let xsk = &xsks[j];
            let tv = &test_vectors[j];

            assert_eq!(xsk.expsk.ask.to_repr().as_ref(), tv.ask.unwrap());
            assert_eq!(xsk.expsk.nsk.to_repr().as_ref(), tv.nsk.unwrap());

            assert_eq!(xsk.expsk.ovk.0, tv.ovk);
            assert_eq!(xsk.dk.0, tv.dk);
            assert_eq!(xsk.chain_code.0, tv.c);

            let mut ser = vec![];
            xsk.write(&mut ser).unwrap();
            assert_eq!(&ser[..], &tv.xsk.unwrap()[..]);
        }

        for (xfvk, tv) in xfvks.iter().zip(test_vectors.iter()) {
            assert_eq!(xfvk.fvk.vk.ak.to_bytes(), tv.ak);
            assert_eq!(xfvk.fvk.vk.nk.to_bytes(), tv.nk);

            assert_eq!(xfvk.fvk.ovk.0, tv.ovk);
            assert_eq!(xfvk.dk.0, tv.dk);
            assert_eq!(xfvk.chain_code.0, tv.c);

            assert_eq!(xfvk.fvk.vk.ivk().to_repr().as_ref(), tv.ivk);

            let mut ser = vec![];
            xfvk.write(&mut ser).unwrap();
            assert_eq!(&ser[..], &tv.xfvk[..]);
            assert_eq!(FvkFingerprint::from(&xfvk.fvk).0, tv.fp);

            // d0
            let mut di = DiversifierIndex::new();
            match xfvk.dk.find_diversifier(di).unwrap() {
                (l, d) if l == di => assert_eq!(d.0, tv.d0.unwrap()),
                (_, _) => assert!(tv.d0.is_none()),
            }

            // d1
            di.increment().unwrap();
            match xfvk.dk.find_diversifier(di).unwrap() {
                (l, d) if l == di => assert_eq!(d.0, tv.d1.unwrap()),
                (_, _) => assert!(tv.d1.is_none()),
            }

            // d2
            di.increment().unwrap();
            match xfvk.dk.find_diversifier(di).unwrap() {
                (l, d) if l == di => assert_eq!(d.0, tv.d2.unwrap()),
                (_, _) => assert!(tv.d2.is_none()),
            }

            // dmax
            let dmax = DiversifierIndex([0xff; 11]);
            match xfvk.dk.find_diversifier(dmax) {
                Some((l, d)) if l == dmax => assert_eq!(d.0, tv.dmax.unwrap()),
                Some((_, _)) => panic!(),
                None => assert!(tv.dmax.is_none()),
            }
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use super::ExtendedSpendingKey;

    prop_compose! {
        pub fn arb_extended_spending_key()(seed in prop::array::uniform32(prop::num::u8::ANY)) -> ExtendedSpendingKey {
            ExtendedSpendingKey::master(&seed)
        }
    }
}
