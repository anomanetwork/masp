//! Types and functions for building MASP shielded transaction components.

use core::fmt;
use std::sync::mpsc::Sender;

use ff::Field;
use ff::PrimeField;
use group::GroupEncoding;
use rand::{seq::SliceRandom, CryptoRng, RngCore};

use crate::MaybeArbitrary;
use crate::{
    asset_type::AssetType,
    consensus::{self, BlockHeight},
    convert::AllowedConversion,
    keys::OutgoingViewingKey,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    sapling::{
        note_encryption::sapling_note_encryption,
        prover::TxProver,
        redjubjub::{PrivateKey, Signature},
        spend_sig_internal,
        util::generate_random_rseed_internal,
        Diversifier, Node, Note, PaymentAddress, ProofGenerationKey, Rseed,
    },
    transaction::{
        builder::Progress,
        components::{
            amount::{I128Sum, ValueSum, MAX_MONEY},
            sapling::{
                fees, Authorization, Authorized, Bundle, ConvertDescription, GrothProofBytes,
                OutputDescription, SpendDescription,
            },
        },
    },
    zip32::{ExtendedKey, ExtendedSpendingKey},
};
use borsh::schema::add_definition;
use borsh::schema::Declaration;
use borsh::schema::Definition;
use borsh::schema::Fields;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Write;
use std::marker::PhantomData;

/// A subset of the parameters necessary to build a transaction
pub trait BuildParams {
    /// Get the commitment value randomness for the ith spend description
    fn spend_rcv(&mut self, i: usize) -> jubjub::Fr;
    /// Get the spend authorization randomizer for the ith spend description
    fn spend_alpha(&mut self, i: usize) -> jubjub::Fr;
    /// Get the commitment value randomness for the ith convert description
    fn convert_rcv(&mut self, i: usize) -> jubjub::Fr;
    /// Get the commitment value randomness for the ith output description
    fn output_rcv(&mut self, i: usize) -> jubjub::Fr;
    /// Get the note RCM for the ith output description
    fn output_rcm(&mut self, i: usize) -> jubjub::Fr;
    /// Get the random seed for the ith output description
    fn output_rseed(&mut self, i: usize) -> [u8; 32];
}

// Allow build parameters to be boxed
impl<B: BuildParams + ?Sized> BuildParams for Box<B> {
    fn spend_rcv(&mut self, i: usize) -> jubjub::Fr {
        (**self).spend_rcv(i)
    }
    fn spend_alpha(&mut self, i: usize) -> jubjub::Fr {
        (**self).spend_alpha(i)
    }
    fn convert_rcv(&mut self, i: usize) -> jubjub::Fr {
        (**self).convert_rcv(i)
    }
    fn output_rcv(&mut self, i: usize) -> jubjub::Fr {
        (**self).output_rcv(i)
    }
    fn output_rcm(&mut self, i: usize) -> jubjub::Fr {
        (**self).output_rcm(i)
    }
    fn output_rseed(&mut self, i: usize) -> [u8; 32] {
        (**self).output_rseed(i)
    }
}

/// Parameters that go into constructing a spend description
#[derive(Clone, Debug, Default)]
pub struct SpendBuildParams {
    /// The commitment value randomness
    pub rcv: jubjub::Fr,
    /// The spend authorization randomizer
    pub alpha: jubjub::Fr,
}

impl BorshSerialize for SpendBuildParams {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Write the commitment value randomness
        writer.write_all(&self.rcv.to_repr())?;
        // Write spend authorization randomizer
        writer.write_all(&self.alpha.to_repr())?;
        Ok(())
    }
}

impl BorshDeserialize for SpendBuildParams {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Read the commitment value randomness
        let rcv_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let rcv = Option::from(jubjub::Fr::from_bytes(&rcv_bytes)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "rcv not in field")
        })?;
        // Read the spend authorization randomizer
        let alpha_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let alpha = Option::from(jubjub::Fr::from_bytes(&alpha_bytes)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "alpha not in field")
        })?;
        // Finally, aggregate the spend parameters
        Ok(SpendBuildParams { rcv, alpha })
    }
}

impl BorshSchema for SpendBuildParams {
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Struct {
            fields: Fields::NamedFields(vec![
                ("rcv".into(), <[u8; 32]>::declaration()),
                ("alpha".into(), <[u8; 32]>::declaration()),
                ("auth_sig".into(), Option::<Signature>::declaration()),
                (
                    "proof_generation_key".into(),
                    Option::<ProofGenerationKey>::declaration(),
                ),
            ]),
        };
        add_definition(Self::declaration(), definition, definitions);
        <[u8; 32]>::add_definitions_recursively(definitions);
        Option::<Signature>::add_definitions_recursively(definitions);
        Option::<ProofGenerationKey>::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        "SpendBuildParams".into()
    }
}

/// Parameters that go into constructing an output description
#[derive(Clone, Copy, Debug, Default)]
pub struct ConvertBuildParams {
    /// The commitment value randomness
    pub rcv: jubjub::Fr,
}

impl BorshSerialize for ConvertBuildParams {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Write the commitment value randomness
        writer.write_all(&self.rcv.to_repr())?;
        Ok(())
    }
}

impl BorshDeserialize for ConvertBuildParams {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Read the commitment value randomness
        let rcv_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let rcv = Option::from(jubjub::Fr::from_bytes(&rcv_bytes)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "rcv not in field")
        })?;
        // Finally, aggregate the convert parameters
        Ok(ConvertBuildParams { rcv })
    }
}

impl BorshSchema for ConvertBuildParams {
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Struct {
            fields: Fields::NamedFields(vec![("rcv".into(), <[u8; 32]>::declaration())]),
        };
        add_definition(Self::declaration(), definition, definitions);
        <[u8; 32]>::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        "ConvertBuildParams".into()
    }
}

/// Parameters that go into constructing an output description
#[derive(Clone, Copy, Debug, Default)]
pub struct OutputBuildParams {
    /// The commitment value randomness
    pub rcv: jubjub::Fr,
    /// The note rcm value
    pub rcm: jubjub::Fr,
    /// The note's random seed
    pub rseed: [u8; 32],
}

impl BorshSerialize for OutputBuildParams {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Write the commitment value randomness
        writer.write_all(&self.rcv.to_repr())?;
        // Write the note rcm value
        writer.write_all(&self.rcm.to_repr())?;
        // Write the note's random seed
        self.rseed.serialize(writer)?;
        Ok(())
    }
}

impl BorshDeserialize for OutputBuildParams {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Read the commitment value randomness
        let rcv_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let rcv = Option::from(jubjub::Fr::from_bytes(&rcv_bytes)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "rcv not in field")
        })?;
        // Read the note rcm value
        let rcm_bytes = <[u8; 32]>::deserialize_reader(reader)?;
        let rcm = Option::from(jubjub::Fr::from_bytes(&rcm_bytes)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "rcm not in field")
        })?;
        // Read the note's random seed
        let rseed = <[u8; 32]>::deserialize_reader(reader)?;
        // Finally, aggregate the output parameters
        Ok(OutputBuildParams { rcv, rcm, rseed })
    }
}

impl BorshSchema for OutputBuildParams {
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Struct {
            fields: Fields::NamedFields(vec![
                ("rcv".into(), <[u8; 32]>::declaration()),
                ("rcm".into(), <[u8; 32]>::declaration()),
                ("rseed".into(), <[u8; 32]>::declaration()),
            ]),
        };
        add_definition(Self::declaration(), definition, definitions);
        <[u8; 32]>::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        "OutputBuildParams".into()
    }
}

/// Pre-generated random parameters for MASPtTransactions
#[derive(Default, Clone, BorshDeserialize, BorshSchema, BorshSerialize, Debug)]
pub struct StoredBuildParams {
    /// The parameters required to construct spend descriptions
    pub spend_params: Vec<SpendBuildParams>,
    /// The parameters required to construct convert descriptions
    pub convert_params: Vec<ConvertBuildParams>,
    /// The parameters required to construct output descriptions
    pub output_params: Vec<OutputBuildParams>,
}

impl BuildParams for StoredBuildParams {
    fn spend_rcv(&mut self, i: usize) -> jubjub::Fr {
        self.spend_params[i].rcv
    }

    fn spend_alpha(&mut self, i: usize) -> jubjub::Fr {
        self.spend_params[i].alpha
    }

    fn convert_rcv(&mut self, i: usize) -> jubjub::Fr {
        self.convert_params[i].rcv
    }

    fn output_rcv(&mut self, i: usize) -> jubjub::Fr {
        self.output_params[i].rcv
    }

    fn output_rcm(&mut self, i: usize) -> jubjub::Fr {
        self.output_params[i].rcm
    }

    fn output_rseed(&mut self, i: usize) -> [u8; 32] {
        self.output_params[i].rseed
    }
}

/// Lazily generated random parameters for MASP transactions
pub struct RngBuildParams<R: CryptoRng + RngCore> {
    /// The RNG used to generate the build parameters
    rng: R,
    /// The parameters required to construct spend descriptions
    spends: BTreeMap<usize, SpendBuildParams>,
    /// The parameters required to construct convert descriptions
    converts: BTreeMap<usize, ConvertBuildParams>,
    /// The parameters required to construct output descriptions
    outputs: BTreeMap<usize, OutputBuildParams>,
}

impl<R: CryptoRng + RngCore> RngBuildParams<R> {
    /// Construct a build parameter generator using the given RNG
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            spends: BTreeMap::new(),
            converts: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }
    }

    /// Convert these build parameters to their stored equivalent
    pub fn to_stored(mut self) -> Option<StoredBuildParams> {
        let mut stored = StoredBuildParams::default();
        // Store the spends
        for i in 0..self.spends.len() {
            stored.spend_params.push(self.spends.remove(&i)?);
        }
        // Store the converts
        for i in 0..self.converts.len() {
            stored.convert_params.push(self.converts.remove(&i)?);
        }
        // Store the outputs
        for i in 0..self.outputs.len() {
            stored.output_params.push(self.outputs.remove(&i)?);
        }
        Some(stored)
    }
}

impl<R: CryptoRng + RngCore> RngBuildParams<R> {
    /// Get the parameters necessary to build the ith spend description
    pub fn spend_params(&mut self, i: usize) -> &SpendBuildParams {
        self.spends.entry(i).or_insert_with(|| SpendBuildParams {
            rcv: jubjub::Fr::random(&mut self.rng),
            alpha: jubjub::Fr::random(&mut self.rng),
        })
    }

    /// Get the parameters necessary to build the ith convert description
    pub fn convert_params(&mut self, i: usize) -> &ConvertBuildParams {
        self.converts
            .entry(i)
            .or_insert_with(|| ConvertBuildParams {
                rcv: jubjub::Fr::random(&mut self.rng),
            })
    }

    /// Get the parameters necessary to build the ith output description
    pub fn output_params(&mut self, i: usize) -> &OutputBuildParams {
        self.outputs.entry(i).or_insert_with(|| OutputBuildParams {
            rcv: jubjub::Fr::random(&mut self.rng),
            rcm: jubjub::Fr::random(&mut self.rng),
            rseed: {
                let mut buffer = [0u8; 32];
                self.rng.fill_bytes(&mut buffer);
                buffer
            },
        })
    }
}

impl<R: CryptoRng + RngCore> BuildParams for RngBuildParams<R> {
    fn spend_rcv(&mut self, i: usize) -> jubjub::Fr {
        self.spend_params(i).rcv
    }

    fn spend_alpha(&mut self, i: usize) -> jubjub::Fr {
        self.spend_params(i).alpha
    }

    fn convert_rcv(&mut self, i: usize) -> jubjub::Fr {
        self.convert_params(i).rcv
    }

    fn output_rcv(&mut self, i: usize) -> jubjub::Fr {
        self.output_params(i).rcv
    }

    fn output_rcm(&mut self, i: usize) -> jubjub::Fr {
        self.output_params(i).rcm
    }

    fn output_rseed(&mut self, i: usize) -> [u8; 32] {
        self.output_params(i).rseed
    }
}

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See <https://github.com/zcash/zcash/issues/3615>.
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    AnchorMismatch,
    BindingSig,
    InvalidAddress,
    InvalidAmount,
    SpendProof,
    ConvertProof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AnchorMismatch => {
                write!(f, "Anchor mismatch (anchors for all spends must be equal)")
            }
            Error::BindingSig => write!(f, "Failed to create bindingSig"),
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::SpendProof => write!(f, "Failed to create MASP spend proof"),
            Error::ConvertProof => write!(f, "Failed to create MASP convert proof"),
        }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq)]
pub struct SpendDescriptionInfo<Key = ExtendedSpendingKey> {
    extsk: Key,
    diversifier: Diversifier,
    note: Note,
    merkle_path: MerklePath<Node>,
}

impl<Key: BorshSchema> BorshSchema for SpendDescriptionInfo<Key> {
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Struct {
            fields: Fields::NamedFields(vec![
                ("extsk".into(), Key::declaration()),
                ("diversifier".into(), Diversifier::declaration()),
                ("note".into(), Note::<Rseed>::declaration()),
                ("merkle_path".into(), MerklePath::<[u8; 32]>::declaration()),
            ]),
        };
        add_definition(Self::declaration(), definition, definitions);
        Key::add_definitions_recursively(definitions);
        Diversifier::add_definitions_recursively(definitions);
        Note::<Rseed>::add_definitions_recursively(definitions);
        MerklePath::<[u8; 32]>::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        format!(r#"SpendDescriptionInfo<{}>"#, Key::declaration())
    }
}

impl<Key: BorshSerialize> BorshSerialize for SpendDescriptionInfo<Key> {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.extsk.serialize(writer)?;
        self.diversifier.serialize(writer)?;
        self.note.serialize(writer)?;
        self.merkle_path.serialize(writer)
    }
}

impl<Key: BorshDeserialize> BorshDeserialize for SpendDescriptionInfo<Key> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let extsk = Key::deserialize_reader(reader)?;
        let diversifier = Diversifier::deserialize_reader(reader)?;
        let note = Note::deserialize_reader(reader)?;
        let merkle_path = MerklePath::<Node>::deserialize_reader(reader)?;
        Ok(SpendDescriptionInfo {
            extsk,
            diversifier,
            note,
            merkle_path,
        })
    }
}

impl<K> fees::InputView<(), K> for SpendDescriptionInfo<K> {
    fn note_id(&self) -> &() {
        // The builder does not make use of note identifiers, so we can just return the unit value.
        &()
    }

    fn value(&self) -> u64 {
        self.note.value
    }

    fn asset_type(&self) -> AssetType {
        self.note.asset_type
    }

    fn key(&self) -> &K {
        &self.extsk
    }

    fn address(&self) -> Option<PaymentAddress> {
        PaymentAddress::from_parts(self.diversifier, self.note.pk_d)
    }
}

/// A struct containing the information required in order to construct a
/// MASP output to a transaction.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct SaplingOutputInfo {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    note: Note<()>,
    memo: MemoBytes,
}

impl SaplingOutputInfo {
    #[allow(clippy::too_many_arguments)]
    fn new_internal(
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<Self, Error> {
        let g_d = to.g_d().ok_or(Error::InvalidAddress)?;
        if value > MAX_MONEY {
            return Err(Error::InvalidAmount);
        }

        let note = Note {
            g_d,
            pk_d: *to.pk_d(),
            value,
            rseed: (),
            asset_type,
        };

        Ok(SaplingOutputInfo {
            ovk,
            to,
            note,
            memo,
        })
    }

    fn build<P: consensus::Parameters, Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
        rcv: jubjub::Fr,
        rseed: Rseed,
    ) -> OutputDescription<GrothProofBytes> {
        let note = Note {
            rseed,
            value: self.note.value,
            g_d: self.note.g_d,
            pk_d: self.note.pk_d,
            asset_type: self.note.asset_type,
        };
        let encryptor = sapling_note_encryption::<P>(self.ovk, note, self.to, self.memo);

        let (zkproof, cv) = prover.output_proof(
            ctx,
            *encryptor.esk(),
            self.to,
            note.rcm(),
            self.note.asset_type,
            self.note.value,
            rcv,
        );

        let cmu = note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, rng);

        let epk = *encryptor.epk();

        OutputDescription {
            cv,
            cmu,
            ephemeral_key: epk.to_bytes().into(),
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        }
    }
}

impl fees::OutputView for SaplingOutputInfo {
    fn value(&self) -> u64 {
        self.note.value
    }

    fn asset_type(&self) -> AssetType {
        self.note.asset_type
    }

    fn address(&self) -> PaymentAddress {
        self.to
    }
}

/// Metadata about a transaction created by a [`SaplingBuilder`].
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct SaplingMetadata {
    spend_indices: Vec<usize>,
    convert_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl SaplingMetadata {
    pub fn empty() -> Self {
        SaplingMetadata {
            spend_indices: vec![],
            convert_indices: vec![],
            output_indices: vec![],
        }
    }

    /// Returns the index within the transaction of the [`SpendDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_spend`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first spend
    /// they added (via the first call to [`SaplingBuilder::add_spend`]) is the first
    /// [`SpendDescription`] in the transaction.
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`SaplingBuilder::add_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
    /// Returns the index within the transaction of the [`ConvertDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_convert`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`SaplingBuilder::add_output`]) is the first
    /// [`ConvertDescription`] in the transaction.
    pub fn convert_index(&self, n: usize) -> Option<usize> {
        self.convert_indices.get(n).copied()
    }
}

#[derive(Clone, Debug)]
pub struct SaplingBuilder<P, Key = ExtendedSpendingKey> {
    params: P,
    spend_anchor: Option<bls12_381::Scalar>,
    target_height: BlockHeight,
    value_balance: I128Sum,
    convert_anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescriptionInfo<Key>>,
    converts: Vec<ConvertDescriptionInfo>,
    outputs: Vec<SaplingOutputInfo>,
}

impl<P: BorshSchema, Key: BorshSchema> BorshSchema for SaplingBuilder<P, Key> {
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Struct {
            fields: Fields::NamedFields(vec![
                ("params".into(), P::declaration()),
                ("spend_anchor".into(), Option::<[u8; 32]>::declaration()),
                ("target_height".into(), BlockHeight::declaration()),
                ("value_balance".into(), I128Sum::declaration()),
                ("convert_anchor".into(), Option::<[u8; 32]>::declaration()),
                (
                    "spends".into(),
                    Vec::<SpendDescriptionInfo<Key>>::declaration(),
                ),
                (
                    "converts".into(),
                    Vec::<ConvertDescriptionInfo>::declaration(),
                ),
                ("outputs".into(), Vec::<SaplingOutputInfo>::declaration()),
            ]),
        };
        add_definition(Self::declaration(), definition, definitions);
        P::add_definitions_recursively(definitions);
        Option::<[u8; 32]>::add_definitions_recursively(definitions);
        BlockHeight::add_definitions_recursively(definitions);
        I128Sum::add_definitions_recursively(definitions);
        Vec::<SpendDescriptionInfo<Key>>::add_definitions_recursively(definitions);
        Vec::<ConvertDescriptionInfo>::add_definitions_recursively(definitions);
        Vec::<SaplingOutputInfo>::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        format!(
            r#"SaplingBuilder<{}, {}>"#,
            P::declaration(),
            Key::declaration()
        )
    }
}

impl<P: BorshSerialize, Key: BorshSerialize> BorshSerialize for SaplingBuilder<P, Key> {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.params.serialize(writer)?;
        self.spend_anchor.map(|x| x.to_bytes()).serialize(writer)?;
        self.target_height.serialize(writer)?;
        self.value_balance.serialize(writer)?;
        self.convert_anchor
            .map(|x| x.to_bytes())
            .serialize(writer)?;
        self.spends.serialize(writer)?;
        self.converts.serialize(writer)?;
        self.outputs.serialize(writer)
    }
}

impl<P: BorshDeserialize, Key: BorshDeserialize> BorshDeserialize for SaplingBuilder<P, Key> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let params = P::deserialize_reader(reader)?;
        let spend_anchor: Option<Option<_>> = Option::<[u8; 32]>::deserialize_reader(reader)?
            .map(|x| bls12_381::Scalar::from_bytes(&x).into());
        let spend_anchor = spend_anchor
            .map(|x| x.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData)))
            .transpose()?;
        let target_height = BlockHeight::deserialize_reader(reader)?;
        let value_balance = I128Sum::deserialize_reader(reader)?;
        let convert_anchor: Option<Option<_>> = Option::<[u8; 32]>::deserialize_reader(reader)?
            .map(|x| bls12_381::Scalar::from_bytes(&x).into());
        let convert_anchor = convert_anchor
            .map(|x| x.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData)))
            .transpose()?;
        let spends = Vec::<SpendDescriptionInfo<Key>>::deserialize_reader(reader)?;
        let converts = Vec::<ConvertDescriptionInfo>::deserialize_reader(reader)?;
        let outputs = Vec::<SaplingOutputInfo>::deserialize_reader(reader)?;
        Ok(SaplingBuilder {
            params,
            spend_anchor,
            target_height,
            value_balance,
            convert_anchor,
            spends,
            converts,
            outputs,
        })
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Unauthorized<K: ExtendedKey> {
    tx_metadata: SaplingMetadata,
    phantom: PhantomData<K>,
}

impl<K: ExtendedKey> std::fmt::Debug for Unauthorized<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Unauthorized")
    }
}

impl<K: ExtendedKey + Clone + Debug + PartialEq + for<'a> MaybeArbitrary<'a>> Authorization
    for Unauthorized<K>
{
    type Proof = GrothProofBytes;
    type AuthSig = SpendDescriptionInfo<K>;
}

impl<P, K> SaplingBuilder<P, K> {
    pub fn new(params: P, target_height: BlockHeight) -> Self {
        SaplingBuilder {
            params,
            spend_anchor: None,
            target_height,
            value_balance: ValueSum::zero(),
            convert_anchor: None,
            spends: vec![],
            converts: vec![],
            outputs: vec![],
        }
    }

    /// Returns the list of Sapling inputs that will be consumed by the transaction being
    /// constructed.
    pub fn inputs(&self) -> &[impl fees::InputView<(), K>] {
        &self.spends
    }

    pub fn converts(&self) -> &[impl fees::ConvertView] {
        &self.converts
    }
    /// Returns the Sapling outputs that will be produced by the transaction being constructed
    pub fn outputs(&self) -> &[impl fees::OutputView] {
        &self.outputs
    }

    /// Returns the net value represented by the spends and outputs added to this builder.
    pub fn value_balance(&self) -> I128Sum {
        self.value_balance.clone()
    }
}

impl<
        P: consensus::Parameters,
        K: ExtendedKey + Debug + Clone + PartialEq + for<'a> MaybeArbitrary<'a>,
    > SaplingBuilder<P, K>
{
    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_spend(
        &mut self,
        extsk: K,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one
        let node = note.commitment();
        if let Some(anchor) = self.spend_anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(node).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.spend_anchor = Some(merkle_path.root(node).into())
        }

        self.value_balance += ValueSum::from_pair(note.asset_type, i128::from(note.value));

        self.spends.push(SpendDescriptionInfo {
            extsk,
            diversifier,
            note,
            merkle_path,
        });

        Ok(())
    }

    /// Adds a convert note to be applied in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous convert notes.
    pub fn add_convert(
        &mut self,
        allowed: AllowedConversion,
        value: u64,
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one

        let node = allowed.commitment();
        if let Some(anchor) = self.convert_anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(node).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.convert_anchor = Some(merkle_path.root(node).into())
        }

        let allowed_amt: I128Sum = allowed.clone().into();
        self.value_balance += I128Sum::from_sum(allowed_amt) * (value as i128);

        self.converts.push(ConvertDescriptionInfo {
            allowed,
            value,
            merkle_path,
        });

        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    #[allow(clippy::too_many_arguments)]
    pub fn add_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<(), Error> {
        let output = SaplingOutputInfo::new_internal(ovk, to, asset_type, value, memo)?;

        self.value_balance -= ValueSum::from_pair(asset_type, i128::from(value));

        self.outputs.push(output);

        Ok(())
    }

    pub fn build<Pr: TxProver>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut (impl CryptoRng + RngCore),
        bparams: &mut impl BuildParams,
        target_height: BlockHeight,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Result<Option<Bundle<Unauthorized<K>>>, Error> {
        // Record initial positions of spends and outputs
        let value_balance = self.value_balance();
        let params = self.params;
        let mut indexed_spends: Vec<_> = self.spends.into_iter().enumerate().collect();
        let mut indexed_converts: Vec<_> = self.converts.into_iter().enumerate().collect();
        let mut indexed_outputs: Vec<_> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| Some((i, o)))
            .collect();

        // Set up the transaction metadata that will be used to record how
        // inputs and outputs are shuffled.
        let mut tx_metadata = SaplingMetadata::empty();
        tx_metadata.spend_indices.resize(indexed_spends.len(), 0);
        tx_metadata
            .convert_indices
            .resize(indexed_converts.len(), 0);
        tx_metadata.output_indices.resize(indexed_outputs.len(), 0);

        // Pad Sapling outputs
        if !indexed_spends.is_empty() {
            while indexed_outputs.len() < MIN_SHIELDED_OUTPUTS {
                indexed_outputs.push(None);
            }
        }

        // Randomize order of inputs and outputs
        indexed_spends.shuffle(rng);
        indexed_converts.shuffle(rng);
        indexed_outputs.shuffle(rng);

        // Keep track of the total number of steps computed
        let total_progress = indexed_spends.len() as u32 + indexed_outputs.len() as u32;
        let mut progress = 0u32;

        // Create Sapling SpendDescriptions
        let shielded_spends: Vec<SpendDescription<Unauthorized<K>>> = if !indexed_spends.is_empty()
        {
            let anchor = self
                .spend_anchor
                .expect("MASP Spend anchor must be set if MASP spends are present.");

            indexed_spends
                .into_iter()
                .enumerate()
                .map(|(i, (pos, spend))| {
                    let proof_generation_key = spend
                        .extsk
                        .to_proof_generation_key()
                        .expect("Proof generation key must be known for each MASP spend.");

                    let nullifier = spend.note.nf(
                        &proof_generation_key.to_viewing_key().nk,
                        spend.merkle_path.position,
                    );

                    let (zkproof, cv, rk) = prover
                        .spend_proof(
                            ctx,
                            proof_generation_key,
                            spend.diversifier,
                            spend.note.rseed,
                            bparams.spend_alpha(i),
                            spend.note.asset_type,
                            spend.note.value,
                            anchor,
                            spend.merkle_path.clone(),
                            bparams.spend_rcv(i),
                        )
                        .map_err(|_| Error::SpendProof)?;

                    // Record the post-randomized spend location
                    tx_metadata.spend_indices[pos] = i;

                    // Update progress and send a notification on the channel
                    progress += 1;
                    if let Some(sender) = progress_notifier {
                        // If the send fails, we should ignore the error, not crash.
                        sender
                            .send(Progress::new(progress, Some(total_progress)))
                            .unwrap_or(());
                    }

                    Ok(SpendDescription {
                        cv,
                        anchor,
                        nullifier,
                        rk,
                        zkproof,
                        spend_auth_sig: spend,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            vec![]
        };

        // Create Sapling ConvertDescriptions
        let shielded_converts: Vec<ConvertDescription<GrothProofBytes>> =
            if !indexed_converts.is_empty() {
                let anchor = self
                    .convert_anchor
                    .expect("MASP convert_anchor must be set if MASP converts are present.");

                indexed_converts
                    .into_iter()
                    .enumerate()
                    .map(|(i, (pos, convert))| {
                        let (zkproof, cv) = prover
                            .convert_proof(
                                ctx,
                                convert.allowed.clone(),
                                convert.value,
                                anchor,
                                convert.merkle_path,
                                bparams.convert_rcv(i),
                            )
                            .map_err(|_| Error::ConvertProof)?;

                        // Record the post-randomized spend location
                        tx_metadata.convert_indices[pos] = i;

                        // Update progress and send a notification on the channel
                        progress += 1;
                        if let Some(sender) = progress_notifier {
                            // If the send fails, we should ignore the error, not crash.
                            sender
                                .send(Progress::new(progress, Some(total_progress)))
                                .unwrap_or(());
                        }

                        Ok(ConvertDescription {
                            cv,
                            anchor,
                            zkproof,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?
            } else {
                vec![]
            };

        // Create Sapling OutputDescriptions
        let shielded_outputs: Vec<OutputDescription<GrothProofBytes>> = indexed_outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                let rseed = generate_random_rseed_internal(
                    &params,
                    target_height,
                    bparams.output_rcm(i),
                    bparams.output_rseed(i),
                );

                let result = if let Some((pos, output)) = output {
                    // Record the post-randomized output location
                    tx_metadata.output_indices[pos] = i;

                    output
                        .clone()
                        .build::<P, _, _>(prover, ctx, rng, bparams.output_rcv(i), rseed)
                } else {
                    // This is a dummy output
                    let (dummy_to, dummy_note) = {
                        let (diversifier, g_d) = {
                            let mut diversifier;
                            let g_d;
                            loop {
                                let mut d = [0; 11];
                                rng.fill_bytes(&mut d);
                                diversifier = Diversifier(d);
                                if let Some(val) = diversifier.g_d() {
                                    g_d = val;
                                    break;
                                }
                            }
                            (diversifier, g_d)
                        };
                        let (pk_d, payment_address) = loop {
                            let mut buf = [0; 64];
                            rng.fill_bytes(&mut buf);
                            let dummy_ivk = jubjub::Fr::from_bytes_wide(&buf);
                            let pk_d = g_d * dummy_ivk;
                            if let Some(addr) = PaymentAddress::from_parts(diversifier, pk_d) {
                                break (pk_d, addr);
                            }
                        };

                        (
                            payment_address,
                            Note {
                                g_d,
                                pk_d,
                                rseed,
                                value: 0,
                                asset_type: AssetType::new(b"dummy").unwrap(),
                            },
                        )
                    };

                    let esk = dummy_note.generate_or_derive_esk_internal(rng);
                    let epk = dummy_note.g_d * esk;

                    let (zkproof, cv) = prover.output_proof(
                        ctx,
                        esk,
                        dummy_to,
                        dummy_note.rcm(),
                        dummy_note.asset_type,
                        dummy_note.value,
                        bparams.output_rcv(i),
                    );

                    let cmu = dummy_note.cmu();

                    let mut enc_ciphertext = [0u8; 580 + 32];
                    let mut out_ciphertext = [0u8; 80];
                    rng.fill_bytes(&mut enc_ciphertext[..]);
                    rng.fill_bytes(&mut out_ciphertext[..]);

                    OutputDescription {
                        cv,
                        cmu,
                        ephemeral_key: epk.to_bytes().into(),
                        enc_ciphertext,
                        out_ciphertext,
                        zkproof,
                    }
                };

                // Update progress and send a notification on the channel
                progress += 1;
                if let Some(sender) = progress_notifier {
                    // If the send fails, we should ignore the error, not crash.
                    sender
                        .send(Progress::new(progress, Some(total_progress)))
                        .unwrap_or(());
                }

                result
            })
            .collect();

        let bundle = if shielded_spends.is_empty() && shielded_outputs.is_empty() {
            None
        } else {
            Some(Bundle {
                shielded_spends,
                shielded_converts,
                shielded_outputs,
                value_balance,
                authorization: Unauthorized {
                    tx_metadata,
                    phantom: PhantomData,
                },
            })
        };

        Ok(bundle)
    }
}

impl<K: ExtendedKey + Debug + Clone + PartialEq + for<'a> MaybeArbitrary<'a>>
    SpendDescription<Unauthorized<K>>
{
    pub fn apply_signature(&self, spend_auth_sig: Signature) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv,
            anchor: self.anchor,
            nullifier: self.nullifier,
            rk: self.rk,
            zkproof: self.zkproof,
            spend_auth_sig,
        }
    }
}

impl<K: ExtendedKey + Debug + Clone + PartialEq + for<'a> MaybeArbitrary<'a>>
    Bundle<Unauthorized<K>>
{
    pub fn apply_signatures<Pr: TxProver, R: RngCore, S: BuildParams>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
        bparams: &mut S,
        sighash_bytes: &[u8; 32],
    ) -> Result<(Bundle<Authorized>, SaplingMetadata), Error> {
        let binding_sig = prover
            .binding_sig(ctx, &self.value_balance, sighash_bytes)
            .map_err(|_| Error::BindingSig)?;

        Ok((
            Bundle {
                shielded_spends: self
                    .shielded_spends
                    .iter()
                    .enumerate()
                    .map(|(i, spend)| {
                        spend.apply_signature(spend_sig_internal(
                            PrivateKey(spend.spend_auth_sig.extsk.to_spending_key().expect("Spend authorization key must be known for each MASP spend.").expsk.ask),
                            bparams.spend_alpha(i),
                            sighash_bytes,
                            rng,
                        ))
                    })
                    .collect(),
                shielded_converts: self.shielded_converts,
                shielded_outputs: self.shielded_outputs,
                value_balance: self.value_balance,
                authorization: Authorized { binding_sig },
            },
            self.authorization.tx_metadata,
        ))
    }
}

/// A struct containing the information required in order to construct a
/// MASP conversion in a transaction.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ConvertDescriptionInfo {
    allowed: AllowedConversion,
    value: u64,
    merkle_path: MerklePath<Node>,
}

impl BorshSchema for ConvertDescriptionInfo {
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Struct {
            fields: Fields::NamedFields(vec![
                ("allowed".into(), AllowedConversion::declaration()),
                ("value".into(), u64::declaration()),
                ("merkle_path".into(), MerklePath::<[u8; 32]>::declaration()),
            ]),
        };
        add_definition(Self::declaration(), definition, definitions);
        AllowedConversion::add_definitions_recursively(definitions);
        u64::add_definitions_recursively(definitions);
        MerklePath::<[u8; 32]>::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        "ConvertDescriptionInfo".into()
    }
}

impl fees::ConvertView for ConvertDescriptionInfo {
    fn value(&self) -> u64 {
        self.value
    }

    fn conversion(&self) -> &AllowedConversion {
        &self.allowed
    }
}

pub trait MapBuilder<P1, K1, P2, K2> {
    fn map_params(&self, s: P1) -> P2;
    fn map_key(&self, s: K1) -> K2;
}

impl<P1, K1> SaplingBuilder<P1, K1> {
    pub fn map_builder<P2, K2, F: MapBuilder<P1, K1, P2, K2>>(
        self,
        f: F,
    ) -> SaplingBuilder<P2, K2> {
        SaplingBuilder::<P2, K2> {
            params: f.map_params(self.params),
            spend_anchor: self.spend_anchor,
            target_height: self.target_height,
            value_balance: self.value_balance,
            convert_anchor: self.convert_anchor,
            converts: self.converts,
            outputs: self.outputs,
            spends: self
                .spends
                .into_iter()
                .map(|x| SpendDescriptionInfo {
                    extsk: f.map_key(x.extsk),
                    diversifier: x.diversifier,
                    note: x.note,
                    merkle_path: x.merkle_path,
                })
                .collect(),
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        consensus::{
            testing::{arb_branch_id, arb_height},
            TEST_NETWORK,
        },
        merkle_tree::{testing::arb_commitment_tree, IncrementalWitness},
        sapling::{
            prover::mock::MockTxProver,
            testing::{arb_node, arb_note, arb_positive_note_value},
            Diversifier,
        },
        transaction::components::{
            amount::MAX_MONEY,
            sapling::{Authorized, Bundle},
        },
        zip32::sapling::testing::arb_extended_spending_key,
    };

    use super::{RngBuildParams, SaplingBuilder};

    prop_compose! {
        fn arb_bundle()(n_notes in 1..30usize)(
            extsk in arb_extended_spending_key(),
            spendable_notes in vec(
                arb_positive_note_value(MAX_MONEY / 10000).prop_flat_map(arb_note),
                n_notes
            ),
            commitment_trees in vec(
                arb_commitment_tree(n_notes, arb_node(), 32).prop_map(
                    |t| IncrementalWitness::from_tree(&t).path().unwrap()
                ),
                n_notes
            ),
            diversifiers in vec(prop::array::uniform11(any::<u8>()).prop_map(Diversifier), n_notes),
            target_height in arb_branch_id().prop_flat_map(|b| arb_height(b, &TEST_NETWORK)),
            rng_seed in prop::array::uniform32(any::<u8>()),
            bparams_seed in prop::array::uniform32(any::<u8>()),
            fake_sighash_bytes in prop::array::uniform32(any::<u8>()),
        ) -> Bundle<Authorized> {
            let mut builder = SaplingBuilder::new(TEST_NETWORK, target_height.unwrap());
            let mut rng = StdRng::from_seed(rng_seed);

            for ((note, path), diversifier) in spendable_notes.into_iter().zip(commitment_trees.into_iter()).zip(diversifiers.into_iter()) {
                builder.add_spend(
                    extsk,
                    diversifier,
                    note,
                    path
                ).unwrap();
            }

            let prover = MockTxProver;
            let mut bparams = RngBuildParams::new(StdRng::from_seed(bparams_seed));

            let bundle = builder.build(
                &prover,
                &mut (),
                &mut rng,
                &mut bparams,
                target_height.unwrap(),
                None,
            ).unwrap().unwrap();

            let (bundle, _) = bundle.apply_signatures(
                &prover,
                &mut (),
                &mut rng,
                &mut bparams,
                &fake_sighash_bytes,
            ).unwrap();

            bundle
        }
    }
}
