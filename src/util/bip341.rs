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

//! BIP341 Implementation
//!
//! Implementation of [Bip341](https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki)
//! signature message
//!

use consensus::Encodable;
use hashes::{sha256, Hash};
use std::{error, fmt, io};
use util::taproot::{TapLeafHash, TapSighashHash};
use {Script, SigHashType, Transaction, TxOut};

/// Contains outputs of previous transactions to provide to the [SigHashCache::signature_hash]
/// method, In the case [SigHashType] variant is `ANYONECANPAY`, [Prevouts::Anyone] may be provided
pub enum Prevouts<'u> {
    /// When modifier `ANYONECANPAY` is provided, only prevout of the current input is needed,
    /// the first `usize` argument is the input index this [TxOut] is referring to.
    Anyone(usize, &'u TxOut),
    /// When `ANYONECANPAY` is not provided, or the caller is handy giving all prevouts so he can reuse
    /// the same data structure for multiple inputs
    All(&'u [TxOut]),
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

/// A replacement for SigHashComponents which supports all sighash modes
pub struct SigHashCache<'a> {
    /// Access to transaction required for various introspection
    tx: &'a Transaction,

    /// Hash of all the previous outputs, computed as required
    hash_prevouts: Option<sha256::Hash>,
    /// Hash of all the input sequence nos, computed as required
    hash_sequence: Option<sha256::Hash>,
    /// Hash of all the outputs in this transaction, computed as required
    hash_outputs: Option<sha256::Hash>,

    /// Hash of all the prevout amounts, computed as required
    hash_amounts: Option<sha256::Hash>,
    /// Hash of all the prevout scriptpubkeys, computed as required
    hash_scriptpubkeys: Option<sha256::Hash>,
}

impl<'a> SigHashCache<'a> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: &'a Transaction) -> Self {
        SigHashCache {
            tx,
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
            hash_amounts: None,
            hash_scriptpubkeys: None,
        }
    }

    /// Encode the BIP341 signing data for any flag type into a given object implementing a
    /// std::io::Write trait.
    pub fn encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        prevouts: &Prevouts,
        annex: Option<Annex>,
        script_path: Option<ScriptPath>,
        sighash_type: SigHashType,
    ) -> Result<(), Error> {
        if let Prevouts::All(prevouts) = prevouts {
            if prevouts.len() != self.tx.input.len() {
                return Err(Error::PrevoutsSize);
            }
        }
        if input_index >= self.tx.input.len() {
            return Err(Error::IndexGreaterThanInputsSize);
        }

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
            self.hash_prevouts().consensus_encode(&mut writer)?;
            self.hash_amounts(prevouts.get_all()?)
                .consensus_encode(&mut writer)?;
            self.hash_scriptpubkeys(prevouts.get_all()?)
                .consensus_encode(&mut writer)?;
            self.hash_sequence().consensus_encode(&mut writer)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
        if sighash != SigHashType::None && sighash != SigHashType::Single {
            self.hash_outputs().consensus_encode(&mut writer)?;
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
    pub fn signature_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts,
        annex: Option<Annex>,
        script_path: Option<ScriptPath>,
        sighash_type: SigHashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            annex,
            script_path,
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Calculate hash for prevouts scriptpubkeys
    pub fn hash_scriptpubkeys(&mut self, prevouts: &[TxOut]) -> sha256::Hash {
        let hash_scriptpubkeys = &mut self.hash_scriptpubkeys;
        *hash_scriptpubkeys.get_or_insert_with(|| {
            let mut enc = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.script_pubkey.consensus_encode(&mut enc).unwrap();
            }
            sha256::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for prevouts amounts
    pub fn hash_amounts(&mut self, prevouts: &[TxOut]) -> sha256::Hash {
        let hash_amounts = &mut self.hash_amounts;
        *hash_amounts.get_or_insert_with(|| {
            let mut enc = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.value.consensus_encode(&mut enc).unwrap();
            }
            sha256::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for prevouts
    pub fn hash_prevouts(&mut self) -> sha256::Hash {
        let hash_prevout = &mut self.hash_prevouts;
        let input = &self.tx.input;
        *hash_prevout.get_or_insert_with(|| {
            let mut enc = sha256::Hash::engine();
            for txin in input {
                txin.previous_output.consensus_encode(&mut enc).unwrap();
            }
            sha256::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for input sequence values
    pub fn hash_sequence(&mut self) -> sha256::Hash {
        let hash_sequence = &mut self.hash_sequence;
        let input = &self.tx.input;
        *hash_sequence.get_or_insert_with(|| {
            let mut enc = sha256::Hash::engine();
            for txin in input {
                txin.sequence.consensus_encode(&mut enc).unwrap();
            }
            sha256::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for outputs
    pub fn hash_outputs(&mut self) -> sha256::Hash {
        let hash_output = &mut self.hash_outputs;
        let output = &self.tx.output;
        *hash_output.get_or_insert_with(|| {
            let mut enc = sha256::Hash::engine();
            for txout in output {
                txout.consensus_encode(&mut enc).unwrap();
            }
            sha256::Hash::from_engine(enc)
        })
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
    use hashes::hex::FromHex;
    use hashes::{Hash, HashEngine};
    use util::bip341::{Annex, Error, Prevouts, ScriptPath, SigHashCache};
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
        test_sighash(
            "0200000002fff49be59befe7566050737910f6ccdc5e749c7f8860ddc140386463d88c5ad0f3000000002cf68eb4a3d67f9d4c079249f7e4f27b8854815cb1ed13842d4fbf395f9e217fd605ee24090100000065235d9203f458520000000000160014b6d48333bb13b4c644e57c43a9a26df3a44b785e58020000000000001976a914eea9461a9e1e3f765d3af3e726162e0229fe3eb688ac58020000000000001976a9143a8869c9f2b5ea1d4ff3aeeb6a8fb2fffb1ad5fe88ac0ad7125c",
            "02591f220000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece48fb310000000000225120f25ad35583ea31998d968871d7de1abd2a52f6fe4178b54ea158274806ff4ece",
            1,
            "626ab955d58c9a8a600a0c580549d06dc7da4e802eb2a531f62a588e430967a8",
            SigHashType::All, None,None,
        );

        test_sighash(
            "0200000001350005f65aa830ced2079df348e2d8c2bdb4f10e2dde6a161d8a07b40d1ad87dae000000001611d0d603d9dc0e000000000017a914459b6d7d6bbb4d8837b4bf7e9a4556f952da2f5c8758020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88ac58020000000000001976a9141dd70e1299ffc2d5b51f6f87de9dfe9398c33cbb88aca71c1f4f",
            "01c4811000000000002251201bf9297d0a2968ae6693aadd0fa514717afefd218087a239afb7418e2d22e65c",
            0,
            "dfa9437f9c9a1d1f9af271f79f2f5482f287cdb0d2e03fa92c8a9b216cc6061c",
            SigHashType::AllPlusAnyoneCanPay, None,None,
        );

        test_sighash(
            "020000000185bed1a6da2bffbd60ec681a1bfb71c5111d6395b99b3f8b2bf90167111bcb18f5010000007c83ace802ded24a00000000001600142c4698f9f7a773866879755aa78c516fb332af8e5802000000000000160014d38639dfbac4259323b98a472405db0c461b31fa61073747",
            "0144c84d0000000000225120e3f2107989c88e67296ab2faca930efa2e3a5bd3ff0904835a11c9e807458621",
            0,
            "3129de36a5d05fff97ffca31eb75fcccbbbc27b3147a7a36a9e4b45d8b625067",
            SigHashType::None, None,None,
        );

        test_sighash(
            "eb93dbb901028c8515589dac980b6e7f8e4088b77ed866ca0d6d210a7218b6fd0f6b22dd6d7300000000eb4740a9047efc0e0000000000160014913da2128d8fcf292b3691db0e187414aa1783825802000000000000160014913da2128d8fcf292b3691db0e187414aa178382580200000000000017a9143dd27f01c6f7ef9bb9159937b17f17065ed01a0c875802000000000000160014d7630e19df70ada9905ede1722b800c0005f246641000000",
            "013fed110000000000225120eb536ae8c33580290630fc495046e998086a64f8f33b93b07967d9029b265c55",
            0,
            "2441e8b0e063a2083ee790f14f2045022f07258ddde5ee01de543c9e789d80ae",
            SigHashType::NonePlusAnyoneCanPay, None,None,
        );

        test_sighash(
            "02000000017836b409a5fed32211407e44b971591f2032053f14701fb5b3a30c0ff382f2cc9c0100000061ac55f60288fb5600000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ac58020000000000001976a9144ea02f6f182b082fb6ce47e36bbde390b6a41b5088ace4000000",
            "01efa558000000000022512007071ea3dc7e331b0687d0193d1e6d6ed10e645ef36f10ef8831d5e522ac9e80",
            0,
            "30239345177cadd0e3ea413d49803580abb6cb27971b481b7788a78d35117a88",
            SigHashType::Single, None,None,
        );

        test_sighash(
            "0100000001aa6deae89d5e0aaca58714fc76ef6f3c8284224888089232d4e663843ed3ab3eae010000008b6657a60450cb4c0000000000160014a3d42b5413ef0c0701c4702f3cd7d4df222c147058020000000000001976a91430b4ed8723a4ee8992aa2c8814cfe5c3ad0ab9d988ac5802000000000000160014365b1166a6ed0a5e8e9dff17a6d00bbb43454bc758020000000000001976a914bc98c51a84fe7fad5dc380eb8b39586eff47241688ac4f313247",
            "0107af4e00000000002251202c36d243dfc06cb56a248e62df27ecba7417307511a81ae61aa41c597a929c69",
            0,
            "bf9c83f26c6dd16449e4921f813f551c4218e86f2ec906ca8611175b41b566df",
            SigHashType::SinglePlusAnyoneCanPay, None,None,
        );
    }

    #[test]
    fn test_sighashes_with_annex() {
        test_sighash(
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
        test_sighash(
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
        test_sighash(
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
            sig_hash.signature_hash(0, &Prevouts::All(&vec![]), None, None, SigHashType::All),
            Err(Error::PrevoutsSize)
        );
        assert_eq!(
            sig_hash.signature_hash(
                0,
                &Prevouts::All(&vec![TxOut::default(), TxOut::default()]),
                None,
                None,
                SigHashType::All
            ),
            Err(Error::PrevoutsSize)
        );
        assert_eq!(
            sig_hash.signature_hash(
                0,
                &Prevouts::Anyone(1, &TxOut::default()),
                None,
                None,
                SigHashType::All
            ),
            Err(Error::PrevoutKind)
        );
        assert_eq!(
            sig_hash.signature_hash(
                0,
                &Prevouts::Anyone(1, &TxOut::default()),
                None,
                None,
                SigHashType::AllPlusAnyoneCanPay
            ),
            Err(Error::PrevoutIndex)
        );
        assert_eq!(
            sig_hash.signature_hash(
                10,
                &Prevouts::Anyone(1, &TxOut::default()),
                None,
                None,
                SigHashType::AllPlusAnyoneCanPay
            ),
            Err(Error::IndexGreaterThanInputsSize)
        );
    }

    #[test]
    fn test_annex_errors() {
        assert_eq!(Annex::new(&vec![]), Err(Error::WrongAnnex));
        assert_eq!(Annex::new(&vec![0x51]), Err(Error::WrongAnnex));
        assert_eq!(Annex::new(&vec![0x51, 0x50]), Err(Error::WrongAnnex));
    }

    fn test_sighash(
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
            .signature_hash(input_index, &prevouts, annex, script_path, sighash_type)
            .unwrap();
        let expected = Vec::from_hex(expected_hash).unwrap();
        assert_eq!(expected, hash.into_inner());
    }
}
