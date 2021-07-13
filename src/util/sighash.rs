// Rust Bitcoin Library
// Written in 2021 by
//   The rust-bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Generalized, efficient, signature Hash Implementation
//!
//! Implementation of the algorithm to compute the message to be signed according to [Bip341](https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki),
//! [Bip143](https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki)
//! and legacy
//!

use consensus::Encodable;
use hashes::{sha256, sha256d, Hash};
use std::{error, fmt, io};
use util::taproot::{TapLeafHash, TapSighashHash};
use SigHash;
use {Script, SigHashType, Transaction, TxOut};

/// Efficientlu calculates signature hash message for legacy, segwit and taproot inputs.
pub struct SigHashCache<'a> {
    /// Access to transaction required for various introspection
    tx: &'a Transaction,

    /// Common cache for taproot and segwit inputs. It's an option because it's not needed for legacy inputs
    common_cache: Option<CommonCache>,

    /// Cache for segwit v0 inputs, it's the result of another round of sha256 to `common_cache`
    segwit_cache: Option<SegwitCache>,

    /// Cache for taproot v1 inputs
    taproot_cache: Option<TaprootCache>,
}

/// values cached common between segwit and taproot inputs
pub struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,
    outputs: sha256::Hash, // maybe Option since NONE and SINGLE doesn't need it
}

/// values cached for segwit inputs, it's equal to [CommonCache] plus another round of `sha256`
pub struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    outputs: sha256d::Hash,
}

/// values cached for taproot inputs
pub struct TaprootCache {
    amounts: sha256::Hash,
    script_pubkeys: sha256::Hash,
}

/// Contains outputs of previous transactions.
/// In the case [SigHashType] variant is `ANYONECANPAY`, [Prevouts::Anyone] may be provided
pub enum Prevouts<'u> {
    /// When modifier `ANYONECANPAY` is provided, only prevout of the current input is needed,
    /// the first `usize` argument is the input index this [TxOut] is referring to.
    Anyone(usize, &'u TxOut),
    /// When `ANYONECANPAY` is not provided, or the caller is handy giving all prevouts so he can reuse
    /// the same data structure for multiple inputs
    All(&'u [TxOut]),
}

impl<'u> Prevouts<'u> {
    fn check_all(&self, tx: &Transaction) -> Result<(), Error> {
        if let Prevouts::All(prevouts) = self {
            if prevouts.len() != tx.input.len() {
                return Err(Error::PrevoutsSize);
            }
        }
        Ok(())
    }
}

const LEAF_VERSION_TAPSCRIPT: u8 = 0xc0;

/// Information related to the script path spending
pub struct ScriptPath<'s> {
    script: &'s Script,
    code_separator_pos: u32,
    leaf_version: u8,
}

impl<'s> ScriptPath<'s> {
    /// Create a new ScriptPath structure
    pub fn new(script: &'s Script, code_separator_pos: u32, leaf_version: u8) -> Self {
        ScriptPath {
            script,
            code_separator_pos,
            leaf_version,
        }
    }
    /// Create a new ScriptPath structure using default values for `code_separator_pos` and `leaf_version`
    pub fn with_defaults(script: &'s Script) -> Self {
        Self::new(script, 0xFFFFFFFFu32, LEAF_VERSION_TAPSCRIPT)
    }
}

/// Possible errors in computing the signature message
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// Should never happen since we are always encoding, thus we are avoiding wrap the IO error
    IoError,

    /// Requested input index is greater than the number of inputs in the given transaction
    IndexGreaterThanInputsSize,

    /// There are mismatches in the number of prevouts provided compared with the number of
    /// inputs in the transaction
    PrevoutsSize,

    /// Requested a prevout index which is greater than the number of prevouts provided or a
    /// [Prevouts::Anyone] with different index
    PrevoutIndex,

    /// A single prevout has been provided but all prevouts are needed without `ANYONECANPAY`
    PrevoutKind,

    /// Annex must be at least one byte long and the first bytes must be `0x50`
    WrongAnnex,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IoError => write!(f, "IoError"),
            Error::IndexGreaterThanInputsSize => write!(f, "Requested input index is greater than the number of inputs in the given transaction"),
            Error::PrevoutsSize => write!(f, "Number of supplied prevouts differs from the number of inputs in transaction"),
            Error::PrevoutIndex => write!(f, "The index requested is greater than available prevouts or different from the provided [Provided::Anyone] index"),
            Error::PrevoutKind => write!(f, "A single prevout has been provided but all prevouts are needed without `ANYONECANPAY`"),
            Error::WrongAnnex => write!(f, "Annex must be at least one byte long and the first bytes must be `0x50`"),
        }
    }
}

impl error::Error for Error {}

impl<'u> Prevouts<'u> {
    fn get_all(&self) -> Result<&[TxOut], Error> {
        match self {
            Prevouts::All(prevouts) => Ok(prevouts),
            _ => Err(Error::PrevoutKind),
        }
    }

    fn get(&self, input_index: usize) -> Result<&TxOut, Error> {
        match self {
            Prevouts::Anyone(index, prevout) => {
                if input_index == *index {
                    Ok(prevout)
                } else {
                    Err(Error::PrevoutIndex)
                }
            }
            Prevouts::All(prevouts) => prevouts.get(input_index).ok_or(Error::PrevoutIndex),
        }
    }
}

impl<'a> SigHashCache<'a> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: &'a Transaction) -> Self {
        SigHashCache {
            tx,
            common_cache: None,
            taproot_cache: None,
            segwit_cache: None,
        }
    }

    fn check_index(&self, index: usize) -> Result<(), Error> {
        if index >= self.tx.input.len() {
            Err(Error::IndexGreaterThanInputsSize)
        } else {
            Ok(())
        }
    }

    /// Encode the BIP341 signing data for any flag type into a given object implementing a
    /// std::io::Write trait.
    pub fn taproot_encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        prevouts: &Prevouts,
        annex: Option<Annex>,
        script_path: Option<ScriptPath>,
        sighash_type: SigHashType,
    ) -> Result<(), Error> {
        prevouts.check_all(&self.tx)?;
        self.check_index(input_index)?;

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        // epoch
        0u8.consensus_encode(&mut writer)?;

        // * Control:
        // hash_type (1).
        (sighash_type as u8).consensus_encode(&mut writer)?;

        // * Transaction Data:
        // nVersion (4): the nVersion of the transaction.
        self.tx.version.consensus_encode(&mut writer)?;

        // nLockTime (4): the nLockTime of the transaction.
        self.tx.lock_time.consensus_encode(&mut writer)?;

        // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
        //     sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
        //     sha_amounts (32): the SHA256 of the serialization of all spent output amounts.
        //     sha_scriptpubkeys (32): the SHA256 of the serialization of all spent output scriptPubKeys.
        //     sha_sequences (32): the SHA256 of the serialization of all input nSequence.
        if !anyone_can_pay {
            self.common_cache().prevouts.consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .amounts
                .consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .script_pubkeys
                .consensus_encode(&mut writer)?;
            self.common_cache()
                .sequences
                .consensus_encode(&mut writer)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
        if sighash != SigHashType::None && sighash != SigHashType::Single {
            self.common_cache().outputs.consensus_encode(&mut writer)?;
        }

        // * Data about this input:
        // spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0
        // if no annex is present, or 1 otherwise
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if script_path.is_some() {
            spend_type |= 2u8;
        }
        spend_type.consensus_encode(&mut writer)?;

        // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
        //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
        //      amount (8): value of the previous output spent by this input.
        //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
        //      nSequence (4): nSequence of this input.
        if anyone_can_pay {
            let txin = &self.tx.input[input_index];
            let previous_output = prevouts.get(input_index)?;
            txin.previous_output.consensus_encode(&mut writer)?;
            previous_output.value.consensus_encode(&mut writer)?;
            previous_output
                .script_pubkey
                .consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        } else {
            (input_index as u32).consensus_encode(&mut writer)?;
        }

        // If an annex is present (the lowest bit of spend_type is set):
        //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
        //      includes the mandatory 0x50 prefix.
        if let Some(annex) = annex {
            let mut enc = sha256::Hash::engine();
            annex.as_bytes().to_vec().consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;
        }

        // * Data about this output:
        // If hash_type & 3 equals SIGHASH_SINGLE:
        //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
        if sighash == SigHashType::Single {
            let mut enc = sha256::Hash::engine();
            self.tx.output[input_index].consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;
        }

        //     if (scriptpath):
        //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        //         ss += bytes([0])
        //         ss += struct.pack("<i", codeseparator_pos)
        if let Some(ScriptPath {
            script,
            leaf_version,
            code_separator_pos,
        }) = script_path
        {
            let mut enc = TapLeafHash::engine();
            leaf_version.consensus_encode(&mut enc)?;
            script.consensus_encode(&mut enc)?;
            let hash = TapLeafHash::from_engine(enc);

            hash.into_inner().consensus_encode(&mut writer)?;
            0u8.consensus_encode(&mut writer)?;
            code_separator_pos.consensus_encode(&mut writer)?;
        }

        Ok(())
    }

    /// Compute the BIP341 sighash for any flag type.
    pub fn taproot_sig_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts,
        annex: Option<Annex>,
        script_path: Option<ScriptPath>,
        sighash_type: SigHashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            annex,
            script_path,
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// [std::io::Write] trait.
    pub fn segwit_encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        prevouts: &Prevouts,
        sighash_type: SigHashType,
    ) -> Result<(), Error> {
        prevouts.check_all(&self.tx)?;
        self.check_index(input_index)?;

        let zero_hash = sha256d::Hash::default();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay && sighash != SigHashType::Single && sighash != SigHashType::None {
            self.segwit_cache()
                .sequences
                .consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        {
            let txin = &self.tx.input[input_index];

            txin.previous_output.consensus_encode(&mut writer)?;
            prevouts
                .get(input_index)?
                .script_pubkey
                .consensus_encode(&mut writer)?;
            prevouts
                .get(input_index)?
                .value
                .consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        }

        if sighash != SigHashType::Single && sighash != SigHashType::None {
            self.segwit_cache().outputs.consensus_encode(&mut writer)?;
        } else if sighash == SigHashType::Single && input_index < self.tx.output.len() {
            let mut single_enc = SigHash::engine();
            self.tx.output[input_index].consensus_encode(&mut single_enc)?;
            SigHash::from_engine(single_enc).consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        self.tx.lock_time.consensus_encode(&mut writer)?;
        sighash_type.as_u32().consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Compute the BIP143 sighash for any flag type.
    pub fn segwit_signature_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts,
        sighash_type: SigHashType,
    ) -> Result<SigHash, Error> {
        let mut enc = SigHash::engine();
        self.segwit_encode_signing_data_to(&mut enc, input_index, prevouts, sighash_type)?;
        Ok(SigHash::from_engine(enc))
    }

    fn common_cache(&mut self) -> &CommonCache {
        if self.common_cache.is_none() {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in self.tx.input.iter() {
                txin.previous_output
                    .consensus_encode(&mut enc_prevouts)
                    .unwrap();
                txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
            }
            let cache = CommonCache {
                prevouts: sha256::Hash::from_engine(enc_prevouts),
                sequences: sha256::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256::Hash::engine();
                    for txout in self.tx.output.iter() {
                        txout.consensus_encode(&mut enc).unwrap();
                    }
                    sha256::Hash::from_engine(enc)
                },
            };
            self.common_cache = Some(cache);
        }
        self.common_cache.as_ref().unwrap() // safe to unwrap because we checked is_none()
    }

    fn segwit_cache(&mut self) -> &SegwitCache {
        if self.segwit_cache.is_none() {
            let cache = SegwitCache {
                prevouts: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&self.common_cache().prevouts).into_inner(),
                ),
                sequences: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&self.common_cache().sequences).into_inner(),
                ),
                outputs: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&self.common_cache().outputs).into_inner(),
                ),
            };
            self.segwit_cache = Some(cache);
        }
        self.segwit_cache.as_ref().unwrap() // safe to unwrap because we checked is_none()
    }

    fn taproot_cache(&mut self, prevouts: &[TxOut]) -> &TaprootCache {
        if self.taproot_cache.is_none() {
            let mut enc_amounts = sha256::Hash::engine();
            let mut enc_script_pubkeys = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.value.consensus_encode(&mut enc_amounts).unwrap();
                prevout
                    .script_pubkey
                    .consensus_encode(&mut enc_script_pubkeys)
                    .unwrap();
            }
            let cache = TaprootCache {
                amounts: sha256::Hash::from_engine(enc_amounts),
                script_pubkeys: sha256::Hash::from_engine(enc_script_pubkeys),
            };
            self.taproot_cache = Some(cache);
        }
        self.taproot_cache.as_ref().unwrap() // safe to unwrap because we checked is_none()
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::IoError
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
/// The `Annex` struct is a slice wrapper enforcing first byte to be `0x50`
pub struct Annex<'a>(&'a [u8]);

impl<'a> Annex<'a> {
    /// Creates a new `Annex` struct checking the first byte is `0x50`
    pub fn new(annex_bytes: &'a [u8]) -> Result<Self, Error> {
        if annex_bytes.first() == Some(&0x50) {
            Ok(Annex(annex_bytes))
        } else {
            Err(Error::WrongAnnex)
        }
    }

    /// Returns the Annex bytes data (including first byte `0x50`)
    pub fn as_bytes(&self) -> &[u8] {
        &*self.0
    }
}

#[cfg(test)]
mod tests {
    use consensus::deserialize;
    use hash_types::SigHash;
    use hashes::hex::FromHex;
    use hashes::{Hash, HashEngine};
    use network::constants::Network;
    use std::mem::size_of;
    use util::address::Address;
    use util::bip143;
    use util::ecdsa::PublicKey;
    use util::sighash::{
        Annex, CommonCache, Error, Prevouts, ScriptPath, SegwitCache, SigHashCache, TaprootCache,
    };
    use util::taproot::TapSighashHash;
    use {Script, SigHashType, Transaction, TxIn, TxOut};

    #[test]
    fn test_tap_sighash_hash() {
        let bytes = Vec::from_hex("00011b96877db45ffa23b307e9f0ac87b80ef9a80b4c5f0db3fbe734422453e83cc5576f3d542c5d4898fb2b696c15d43332534a7c1d1255fda38993545882df92c3e353ff6d36fbfadc4d168452afd8467f02fe53d71714fcea5dfe2ea759bd00185c4cb02bc76d42620393ca358a1a713f4997f9fc222911890afb3fe56c6a19b202df7bffdcfad08003821294279043746631b00e2dc5e52a111e213bbfe6ef09a19428d418dab0d50000000000").unwrap();
        let expected =
            Vec::from_hex("04e808aad07a40b3767a1442fead79af6ef7e7c9316d82dec409bb31e77699b0")
                .unwrap();
        let mut enc = TapSighashHash::engine();
        enc.input(&bytes);
        let hash = TapSighashHash::from_engine(enc);
        assert_eq!(expected, hash.into_inner());
    }

    #[test]
    fn test_sighashes_keyspending() {
        // following test case has been taken from bitcoin core test framework
        test_taproot_sighash(
            "0200000002fff49be59befe7566050737910f6ccdc5e749c7f8860ddc140386463d88c5ad0f3000000002cf68eb4a3d67f9d4c079249f7e4f27b8854815cb1ed13842d4fbf395f9e217fd605ee24090100000065235d9203f458520000000000160014b6d48333bb13b4c644e57c43a9a26df3a44b785e58020000000000001976a914eea9461a9e1e3f765d3af3e726162e0229fe3eb688ac58020000000000001976a9143a8869c9f2b5ea1d4ff3aeeb6a8fb2fffb1ad5fe88ac0ad7125c",
            "02591f220000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece48fb310000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece",
            1,
            "626ab955d58c9a8a600a0c580549d06dc7da4e802eb2a531f62a588e430967a8",
            SigHashType::All, None,None,
        );

        test_taproot_sighash(
            "0200000001350005f65aa830ced2079df348e2d8c2bdb4f10e2dde6a161d8a07b40d1ad87dae000000001611d0d603d9dc0e000000000017a914459b6d7d6bbb4d8837b4bf7e9a4556f952da2f5c8758020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88ac58020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88aca71c1f4f",
            "01c4811000000000002251201bf9297d0a2968ae6693aadd0fa514717afefd218087a239afb7418e2d22e65c",
            0,
            "dfa9437f9c9a1d1f9af271f79f2f5482f287cdb0d2e03fa92c8a9b216cc6061c",
            SigHashType::AllPlusAnyoneCanPay, None,None,
        );

        test_taproot_sighash(
            "020000000185bed1a6da2bffbd60ec681a1bfb71c5111d6395b99b3f8b2bf90167111bcb18f5010000007c83ace802ded24a00000000001600142c4698f9f7a773866879755aa78c516fb332af8e5802000000000000160014d38639dfbac4259323b98a472405db0c461b31fa61073747",
            "0144c84d0000000000225120e3f2107989c88e67296ab2faca930efa2e3a5bd3ff0904835a11c9e807458621",
            0,
            "3129de36a5d05fff97ffca31eb75fcccbbbc27b3147a7a36a9e4b45d8b625067",
            SigHashType::None, None,None,
        );

        test_taproot_sighash(
            "eb93dbb901028c8515589dac980b6e7f8e4088b77ed866ca0d6d210a7218b6fd0f6b22dd6d7300000000eb4740a9047efc0e0000000000160014913da2128d8fcf292b3691db0e187414aa1783825802000000000000160014913da2128d8fcf292b3691db0e187414aa178382580200000000000017a9143dd27f01c6f7ef9bb9159937b17f17065ed01a0c875802000000000000160014d7630e19df70ada9905ede1722b800c0005f246641000000",
            "013fed110000000000225120eb536ae8c33580290630fc495046e998086a64f8f33b93b07967d9029b265c55",
            0,
            "2441e8b0e063a2083ee790f14f2045022f07258ddde5ee01de543c9e789d80ae",
            SigHashType::NonePlusAnyoneCanPay, None,None,
        );

        test_taproot_sighash(
            "02000000017836b409a5fed32211407e44b971591f2032053f14701fb5b3a30c0ff382f2cc9c0100000061ac55f60288fb5600000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ac58020000000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ace4000000",
            "01efa558000000000022512007071ea3dc7e331b0687d0193d1e6d6ed10e645ef36f10ef8831d5e522ac9e80",
            0,
            "30239345177cadd0e3ea413d49803580abb6cb27971b481b7788a78d35117a88",
            SigHashType::Single, None,None,
        );

        test_taproot_sighash(
            "0100000001aa6deae89d5e0aaca58714fc76ef6f3c8284224888089232d4e663843ed3ab3eae010000008b6657a60450cb4c0000000000160014a3d42b5413ef0c0701c4702f3cd7d4df222c147058020000000000001976a91430b4ed8723a4ee8992aa2c8814cfe5c3ad0ab9d988ac5802000000000000160014365b1166a6ed0a5e8e9dff17a6d00bbb43454bc758020000000000001976a914bc98c51a84fe7fad5dc380eb8b39586eff47241688ac4f313247",
            "0107af4e00000000002251202c36d243dfc06cb56a248e62df27ecba7417307511a81ae61aa41c597a929c69",
            0,
            "bf9c83f26c6dd16449e4921f813f551c4218e86f2ec906ca8611175b41b566df",
            SigHashType::SinglePlusAnyoneCanPay, None,None,
        );
    }

    #[test]
    fn sizeof() {
        assert_eq!(size_of::<Option<CommonCache>>(), 97);
        assert_eq!(size_of::<Option<TaprootCache>>(), 65);
        assert_eq!(size_of::<Option<SegwitCache>>(), 97);
        assert_eq!(size_of::<&Transaction>(), 8);
        assert_eq!(size_of::<SigHashCache>(), 272);
    }

    #[test]
    fn test_sighashes_with_annex() {
        test_taproot_sighash(
            "0200000001df8123752e8f37d132c4e9f1ff7e4f9b986ade9211267e9ebd5fd22a5e718dec6d01000000ce4023b903cb7b23000000000017a914a18b36ea7a094db2f4940fc09edf154e86de7bd787580200000000000017a914afd0d512a2c5c2b40e25669e9cc460303c325b8b87580200000000000017a914a18b36ea7a094db2f4940fc09edf154e86de7bd787f6020000",
            "01ea49260000000000225120ab5e9800806bf18cb246edcf5fe63441208fe955a4b5a35bbff65f5db622a010",
            0,
            "3b003000add359a364a156e73e02846782a59d0d95ca8c4638aaad99f2ef915c",
            SigHashType::SinglePlusAnyoneCanPay,
            Some("507b979802e62d397acb29f56743a791894b99372872fc5af06a4f6e8d242d0615cda53062bb20e6ec79756fe39183f0c128adfe85559a8fa042b042c018aa8010143799e44f0893c40e1e"),
            None,
        );
    }

    #[test]
    fn test_sighashes_with_script_path() {
        test_taproot_sighash(
            "020000000189fc651483f9296b906455dd939813bf086b1bbe7c77635e157c8e14ae29062195010000004445b5c7044561320000000000160014331414dbdada7fb578f700f38fb69995fc9b5ab958020000000000001976a914268db0a8104cc6d8afd91233cc8b3d1ace8ac3ef88ac580200000000000017a914ec00dcb368d6a693e11986d265f659d2f59e8be2875802000000000000160014c715799a49a0bae3956df9c17cb4440a673ac0df6f010000",
            "011bec34000000000022512028055142ea437db73382e991861446040b61dd2185c4891d7daf6893d79f7182",
            0,
            "d66de5274a60400c7b08c86ba6b7f198f40660079edf53aca89d2a9501317f2e",
            SigHashType::All,
            None,
            Some("20cc4e1107aea1d170c5ff5b6817e1303010049724fb3caa7941792ea9d29b3e2bacab"),
        );
    }

    #[test]
    fn test_sighashes_with_annex_and_script() {
        test_taproot_sighash(
            "020000000132fb72cb8fba496755f027a9743e2d698c831fdb8304e4d1a346ac92cbf51acba50100000026bdc7df044aad34000000000017a9144fa2554ed6174586854fa3bc01de58dcf33567d0875802000000000000160014950367e1e62cdf240b35b883fc2f5e39f0eb9ab95802000000000000160014950367e1e62cdf240b35b883fc2f5e39f0eb9ab958020000000000001600141b31217d48ccc8760dcc0710fade5866d628e733a02d5122",
            "011458360000000000225120a7baec3fb9f84614e3899fcc010c638f80f13539344120e1f4d8b68a9a011a13",
            0,
            "a0042aa434f9a75904b64043f2a283f8b4c143c7f4f7f49a6cbe5b9f745f4c15",
            SigHashType::All,
            Some("50a6272b470e1460e3332ade7bb14b81671c564fb6245761bd5bd531394b28860e0b3808ab229fb51791fb6ae6fa82d915b2efb8f6df83ae1f5ab3db13e30928875e2a22b749d89358de481f19286cd4caa792ce27f9559082d227a731c5486882cc707f83da361c51b7aadd9a0cf68fe7480c410fa137b454482d9a1ebf0f96d760b4d61426fc109c6e8e99a508372c45caa7b000a41f8251305da3f206c1849985ba03f3d9592832b4053afbd23ab25d0465df0bc25a36c223aacf8e04ec736a418c72dc319e4da3e972e349713ca600965e7c665f2090d5a70e241ac164115a1f5639f28b1773327715ca307ace64a2de7f0e3df70a2ffee3857689f909c0dad46d8a20fa373a4cc6eed6d4c9806bf146f0d76baae1"),
            Some("7520ab9160dd8299dc1367659be3e8f66781fe440d52940c7f8d314a89b9f2698d406ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6ead6eadac"),
        );
    }

    #[test]
    fn test_sighash_errors() {
        let dumb_tx = Transaction {
            version: 0,
            lock_time: 0,
            input: vec![TxIn::default()],
            output: vec![],
        };
        let mut sig_hash = SigHashCache::new(&dumb_tx);

        assert_eq!(
            sig_hash.taproot_sig_hash(0, &Prevouts::All(&vec![]), None, None, SigHashType::All),
            Err(Error::PrevoutsSize)
        );
        let two = vec![TxOut::default(), TxOut::default()];
        let too_many_prevouts = Prevouts::All(&two);
        assert_eq!(
            sig_hash.taproot_sig_hash(0, &too_many_prevouts, None, None, SigHashType::All),
            Err(Error::PrevoutsSize)
        );
        let tx_out = TxOut::default();
        let prevout = Prevouts::Anyone(1, &tx_out);
        assert_eq!(
            sig_hash.taproot_sig_hash(0, &prevout, None, None, SigHashType::All),
            Err(Error::PrevoutKind)
        );
        assert_eq!(
            sig_hash.taproot_sig_hash(0, &prevout, None, None, SigHashType::AllPlusAnyoneCanPay),
            Err(Error::PrevoutIndex)
        );
        assert_eq!(
            sig_hash.taproot_sig_hash(10, &prevout, None, None, SigHashType::AllPlusAnyoneCanPay),
            Err(Error::IndexGreaterThanInputsSize)
        );
    }

    #[test]
    fn test_annex_errors() {
        assert_eq!(Annex::new(&vec![]), Err(Error::WrongAnnex));
        assert_eq!(Annex::new(&vec![0x51]), Err(Error::WrongAnnex));
        assert_eq!(Annex::new(&vec![0x51, 0x50]), Err(Error::WrongAnnex));
    }

    fn test_taproot_sighash(
        tx_hex: &str,
        prevout_hex: &str,
        input_index: usize,
        expected_hash: &str,
        sighash_type: SigHashType,
        annex_hex: Option<&str>,
        script_hex: Option<&str>,
    ) {
        let tx_bytes = Vec::from_hex(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        let prevout_bytes = Vec::from_hex(prevout_hex).unwrap();
        let prevouts: Vec<TxOut> = deserialize(&prevout_bytes).unwrap();
        let annex_inner;
        let annex = match annex_hex {
            Some(annex_hex) => {
                annex_inner = Vec::from_hex(annex_hex).unwrap();
                Some(Annex::new(&annex_inner).unwrap())
            }
            None => None,
        };

        let script_inner;
        let script_path = match script_hex {
            Some(script_hex) => {
                script_inner = Script::from_hex(script_hex).unwrap();
                Some(ScriptPath::with_defaults(&script_inner))
            }
            None => None,
        };

        let prevouts = if sighash_type.split_anyonecanpay_flag().1 && tx_bytes[0] % 2 == 0 {
            // for anyonecanpay the `Prevouts::All` variant is good anyway, but sometimes we want to
            // test other codepaths
            Prevouts::Anyone(input_index, &prevouts[input_index])
        } else {
            Prevouts::All(&prevouts)
        };

        let mut sig_hash_cache = SigHashCache::new(&tx);

        let hash = sig_hash_cache
            .taproot_sig_hash(input_index, &prevouts, annex, script_path, sighash_type)
            .unwrap();
        let expected = Vec::from_hex(expected_hash).unwrap();
        assert_eq!(expected, hash.into_inner());
    }

    // segwit v0 tests

    fn p2pkh_hex(pk: &str) -> Script {
        let pk = Vec::from_hex(pk).unwrap();
        let pk = PublicKey::from_slice(pk.as_slice()).unwrap();
        let witness_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();
        witness_script
    }

    fn run_test_sighash_bip143(
        tx: &str,
        script: &str,
        input_index: usize,
        value: u64,
        hash_type: u32,
        expected_result: &str,
    ) {
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx).unwrap()[..]).unwrap();
        let script_pubkey = Script::from(Vec::<u8>::from_hex(script).unwrap());
        let raw_expected = SigHash::from_hex(expected_result).unwrap();
        let expected_result = SigHash::from_slice(&raw_expected[..]).unwrap();
        let mut cache = SigHashCache::new(&tx);
        let sighash_type = SigHashType::from_u32_consensus(hash_type);
        let tx_out = TxOut {
            value,
            script_pubkey,
        };
        let prevout = Prevouts::Anyone(input_index, &tx_out);
        let actual_result = cache
            .segwit_signature_hash(input_index, &prevout, sighash_type)
            .unwrap();
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    #[allow(deprecated)]
    fn bip143_p2wpkh() {
        let tx = deserialize::<Transaction>(
            &Vec::from_hex(
                "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
                0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
                00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093\
                510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
            ).unwrap()[..],
        ).unwrap();

        let witness_script =
            p2pkh_hex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
        let value = 600_000_000;

        let comp = bip143::SighashComponents::new(&tx);

        let expected = "96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37";
        assert_eq!(comp.hash_prevouts, hex_hash!(SigHash, expected));

        let expected = "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b";
        assert_eq!(comp.hash_sequence, hex_hash!(SigHash, expected));

        let expected = "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5";
        assert_eq!(comp.hash_outputs, hex_hash!(SigHash, expected));

        let expected = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
        assert_eq!(
            comp.sighash_all(&tx.input[1], &witness_script, value),
            hex_hash!(SigHash, expected)
        );
    }

    #[test]
    #[allow(deprecated)]
    fn bip143_p2wpkh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(
            &Vec::from_hex(
                "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000\
                0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac00\
                08af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000",
            ).unwrap()[..],
        ).unwrap();

        let witness_script =
            p2pkh_hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        let value = 1_000_000_000;
        let comp = bip143::SighashComponents::new(&tx);

        let expected = "b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a";
        assert_eq!(comp.hash_prevouts, hex_hash!(SigHash, expected));

        let expected = "18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198";
        assert_eq!(comp.hash_sequence, hex_hash!(SigHash, expected));

        let expected = "de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83";
        assert_eq!(comp.hash_outputs, hex_hash!(SigHash, expected));

        let expected = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6";
        assert_eq!(
            comp.sighash_all(&tx.input[0], &witness_script, value),
            hex_hash!(SigHash, expected)
        );
    }

    #[test]
    #[allow(deprecated)]
    fn bip143_p2wsh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(
            &Vec::from_hex(
                "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000\
             ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f\
             05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000").unwrap()[..],
        ).unwrap();

        let witness_script = hex_script!(
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28\
             bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
             9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58\
             c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b1486\
             2c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
             56ae"
        );
        let value = 987654321;

        let comp = bip143::SighashComponents::new(&tx);

        let expected = "74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0";
        assert_eq!(comp.hash_prevouts, hex_hash!(SigHash, expected));

        let expected = "3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044";
        assert_eq!(comp.hash_sequence, hex_hash!(SigHash, expected));

        let expected = "bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc";
        assert_eq!(comp.hash_outputs, hex_hash!(SigHash, expected));

        let expected = "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c";
        assert_eq!(
            comp.sighash_all(&tx.input[0], &witness_script, value),
            hex_hash!(SigHash, expected)
        );
    }
    #[test]
    fn bip143_sighash_flags() {
        // All examples generated via Bitcoin Core RPC using signrawtransactionwithwallet
        // with additional debug printing
        let tx_hex = "0200000001cf309ee0839b8aaa3fbc84f8bd32e9c6357e99b49bf6a3af90308c68e762f1d70100000000feffffff0288528c61000000001600146e8d9e07c543a309dcdeba8b50a14a991a658c5be0aebb0000000000160014698d8419804a5d5994704d47947889ff7620c004db000000";
        let script_hex = "76a91462744660c6b5133ddeaacbc57d2dc2d7b14d0b0688ac";

        let expected = "0a1bc2758dbb5b3a56646f8cafbf63f410cc62b77a482f8b87552683300a7711";
        run_test_sighash_bip143(tx_hex, script_hex, 0, 1648888940, 0x01, expected);

        let expected = "3e275ac8b084f79f756dcd535bffb615cc94a685eefa244d9031eaf22e4cec12";
        run_test_sighash_bip143(tx_hex, script_hex, 0, 1648888940, 0x02, expected);

        let expected = "191a08165ffacc3ea55753b225f323c35fd00d9cc0268081a4a501921fc6ec14";
        run_test_sighash_bip143(tx_hex, script_hex, 0, 1648888940, 0x03, expected);

        let expected = "4b6b612530f94470bbbdef18f57f2990d56b239f41b8728b9a49dc8121de4559";
        run_test_sighash_bip143(tx_hex, script_hex, 0, 1648888940, 0x81, expected);

        let expected = "a7e916d3acd4bb97a21e6793828279aeab02162adf8099ea4f309af81f3d5adb";
        run_test_sighash_bip143(tx_hex, script_hex, 0, 1648888940, 0x82, expected);

        let expected = "d9276e2a48648ddb53a4aaa58314fc2b8067c13013e1913ffb67e0988ce82c78";
        run_test_sighash_bip143(tx_hex, script_hex, 0, 1648888940, 0x83, expected);
    }
}
