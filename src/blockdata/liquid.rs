#![allow(missing_docs)]

use util::hash::Sha256dHash;
use blockdata::script::Script;
use network::serialize::BitcoinHash;
use network::encodable::ConsensusEncodable;
use network::encodable::ConsensusDecodable;
use network::encodable::VarInt;
use network::serialize::SimpleDecoder;
use network::serialize;
use network::serialize::SimpleEncoder;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Error;
use blockdata::transaction::OutPoint;


/// A liquid block header, which contains all the block's information except
/// the actual transactions
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LiquidBlockHeader {
    /// The protocol version. Should always be 1.
    pub version: u32,
    /// Reference to the previous block in the chain
    pub prev_blockhash: Sha256dHash,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: Sha256dHash,
    /// The timestamp of the block, as claimed by the miner
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub height: u32,

    pub challenge: Script,
    pub proof: Script,
}
impl_consensus_encoding!(LiquidBlockHeader, version, prev_blockhash, merkle_root, time, height, challenge, proof);

impl BitcoinHash for LiquidBlockHeader {
    fn bitcoin_hash(&self) -> Sha256dHash {
        use util::hash::Sha256dEncoder;

        let mut enc = Sha256dEncoder::new();
        self.version.consensus_encode(&mut enc).unwrap();
        self.prev_blockhash.consensus_encode(&mut enc).unwrap();
        self.merkle_root.consensus_encode(&mut enc).unwrap();
        self.time.consensus_encode(&mut enc).unwrap();
        self.height.consensus_encode(&mut enc).unwrap();
        self.challenge.consensus_encode(&mut enc).unwrap();
        enc.into_hash()
    }
}
/// A Bitcoin block, which is a collection of transactions with an attached
/// proof of work.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LiquidBlock {
    /// The block header
    pub header: LiquidBlockHeader,
    /// List of transactions contained in the block
    pub txdata: Vec<LiquidTransaction>
}
impl_consensus_encoding!(LiquidBlock, header, txdata);

impl BitcoinHash for LiquidBlock {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.header.bitcoin_hash()
    }
}


/**
 * Elements transaction serialization format:
 * - int32_t nVersion
 * - unsigned char flags
 *     - bit 1: witness data
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 * - if (flags & 1):
 *   - CTxWitness wit;
 */

/// A Liquid transaction, which describes an authenticated movement of assets
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct LiquidTransaction {
    /// The protocol version
    pub version: u32,
    /// valid immediately.
    pub flag: u8,

    /// List of inputs
    pub input: Vec<LiquidTxIn>,
    /// List of outputs
    pub output: Vec<LiquidTxOut>,
    // Block number before which this transaction is valid, or 0 for
    pub lock_time: u32,
    pub witness: TxWitness,
}

// can't use macro deserializer because  number of input witness and output witness must be read
// from the number of input and output
impl<D: SimpleDecoder> ConsensusDecodable<D> for LiquidTransaction {
    fn consensus_decode(d: &mut D) -> Result<LiquidTransaction, serialize::Error> {
        let version: u32 = ConsensusDecodable::consensus_decode(d)?;
        let flag: u8 = ConsensusDecodable::consensus_decode(d)?;
        let input: Vec<LiquidTxIn> = ConsensusDecodable::consensus_decode(d)?;
        let output: Vec<LiquidTxOut> = ConsensusDecodable::consensus_decode(d)?;
        let lock_time : u32 = ConsensusDecodable::consensus_decode(d)?;

        let mut input_witnesses: Vec<TxInWitness> = Vec::new();
        let mut output_witnesses: Vec<TxOutWitness> = Vec::new();

        if flag != 0 {
            for _ in 0..input.len() {
                let input_witness: TxInWitness = ConsensusDecodable::consensus_decode(d)?;
                input_witnesses.push(input_witness);
            }

            for _ in 0..output.len() {
                let output_witness: TxOutWitness = ConsensusDecodable::consensus_decode(d)?;
                output_witnesses.push(output_witness);
            }
        };

        let witness =  TxWitness{input_witnesses, output_witnesses};

        Ok(LiquidTransaction{
            version,
            flag,
            input,
            output,
            lock_time,
            witness
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for LiquidTransaction {
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        self.version.consensus_encode(s)?;
        self.flag.consensus_encode(s)?;
        self.input.consensus_encode(s)?;
        self.output.consensus_encode(s)?;
        self.lock_time.consensus_encode(s)?;
        if self.flag !=0 {
            for el in &self.witness.input_witnesses {
                el.consensus_encode(s)?;
            }
            for el in &self.witness.output_witnesses {
                el.consensus_encode(s)?;
            }

        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxWitness {
    pub input_witnesses : Vec<TxInWitness>,
    pub output_witnesses : Vec<TxOutWitness>,
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxInWitness {
    pub issuance_amount_range_proof : Vec<u8>,
    pub inflation_keys_range_proof : Vec<u8>,
    pub script_witness : ScriptWitness,
    pub pegin_witness : u8,
}
impl_consensus_encoding!(TxInWitness, issuance_amount_range_proof, inflation_keys_range_proof, script_witness, pegin_witness);

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxOutWitness {
    pub surjection_proof : Vec<u8>,
    pub range_proof : Vec<u8>,
}
impl_consensus_encoding!(TxOutWitness, surjection_proof, range_proof);

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct ScriptWitness {
    pub stack : Vec<u8>,
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for ScriptWitness {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ScriptWitness, serialize::Error> {
        let value_type : u8 = ConsensusDecodable::consensus_decode(d)?;
        match value_type {
            0x01 => {
                let stack : Vec<u8> = ConsensusDecodable::consensus_decode(d)?;
                Ok(ScriptWitness{stack})
            },
            _ => {
                Ok(ScriptWitness{stack:Vec::new()})
            },
        }
    }
}


impl<S: SimpleEncoder> ConsensusEncodable<S> for ScriptWitness {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        if self.stack.is_empty() {
            0x00u8.consensus_encode(s)?;
            return Ok(())
        }
        0x01u8.consensus_encode(s)?;
        self.stack.consensus_encode(s)
    }
}



impl BitcoinHash for LiquidTransaction {
    fn bitcoin_hash(&self) -> Sha256dHash {
        use util::hash::Sha256dEncoder;

        let mut enc = Sha256dEncoder::new();
        self.consensus_encode(&mut enc).unwrap();
        enc.into_hash()
    }
}

impl LiquidTransaction {
    /// Computes the txid. For non-segwit transactions this will be identical
    /// to the output of `BitcoinHash::bitcoin_hash()`, but for segwit transactions,
    /// this will give the correct txid (not including witnesses) while `bitcoin_hash`
    /// will also hash witnesses.
    pub fn txid(&self) -> Sha256dHash {
        use util::hash::Sha256dEncoder;

        let mut enc = Sha256dEncoder::new();
        self.version.consensus_encode(&mut enc).unwrap();
        0u8.consensus_encode(&mut enc).unwrap();
        self.input.consensus_encode(&mut enc).unwrap();
        self.output.consensus_encode(&mut enc).unwrap();
        self.lock_time.consensus_encode(&mut enc).unwrap();

        enc.into_hash()
    }


    /// Gets the "weight" of this transaction, as defined by BIP141. For transactions with an empty
    /// witness, this is simply the consensus-serialized size times 4. For transactions with a
    /// witness, this is the non-witness consensus-serialized size multiplied by 3 plus the
    /// with-witness consensus-serialized size.
    #[inline]
    pub fn get_weight(&self) -> u64 {
        let mut input_weight = 0;
        let inputs_with_witnesses = 0;
        for input in &self.input {
            input_weight += 4*(32 + 4 + 4 + // outpoint (32+4) + nSequence
                VarInt(input.script_sig.len() as u64).encoded_length() +
                input.script_sig.len() as u64);
            // TODO handle witness weight
            /*if !input.witness.is_empty() {
                inputs_with_witnesses += 1;
                input_weight += VarInt(input.witness.len() as u64).encoded_length();
                for elem in &input.witness {
                    input_weight += VarInt(elem.len() as u64).encoded_length() + elem.len() as u64;
                }
            }*/
        }

        let mut output_size = 0;
        for output in &self.output {
            output_size += 8 + // value
                VarInt(output.script_pubkey.len() as u64).encoded_length() +
                output.script_pubkey.len() as u64;
        }
        let non_input_size =
        // version:
            4 +
                // count varints:
                VarInt(self.input.len() as u64).encoded_length() +
                VarInt(self.output.len() as u64).encoded_length() +
                output_size +
                // lock_time
                4;
        if inputs_with_witnesses == 0 {
            non_input_size * 4 + input_weight
        } else {
            non_input_size * 4 + input_weight + self.input.len() as u64 - inputs_with_witnesses + 2
        }
    }
}

pub struct ConfidentialAsset([u8; 33]);
impl_array_newtype!(ConfidentialAsset, u8, 33);
impl_newtype_consensus_encoding!(ConfidentialAsset);

impl Debug for ConfidentialAsset {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        self.0.fmt(f)
    }
}

pub struct BlindedValue([u8; 33]);
impl_array_newtype!(BlindedValue, u8, 33);
impl_newtype_consensus_encoding!(BlindedValue);

impl Debug for BlindedValue {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        self.0.fmt(f)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum ConfidentialValue {
    Blinded(BlindedValue),
    Clear([u8;8]),
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for ConfidentialValue {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ConfidentialValue, serialize::Error> {
        let value_type : u8 = ConsensusDecodable::consensus_decode(d)?;
        match value_type {
            0x01 => {
                let val : [u8;8] = ConsensusDecodable::consensus_decode(d)?;
                Ok(ConfidentialValue::Clear(val))
            },
            _ => {
                let val : [u8;32] = ConsensusDecodable::consensus_decode(d)?;
                let mut result : [u8;33] = [0u8;33];
                result[0]=value_type;
                result[1..].copy_from_slice(&val);
                Ok(ConfidentialValue::Blinded(BlindedValue(result)))
            },
        }
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for ConfidentialValue {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        match self {
            ConfidentialValue::Clear(val) => {
                0x01u8.consensus_encode(s)?;
                val.consensus_encode(s)?;
            },
            ConfidentialValue::Blinded(val) => {
                let BlindedValue(val) = val;
                val.consensus_encode(s)?;
            },
        }
        Ok(())
    }
}

pub struct NonceValue([u8; 33]);
impl_array_newtype!(NonceValue, u8, 33);
impl_newtype_consensus_encoding!(NonceValue);

impl Debug for NonceValue {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        self.0.fmt(f)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum ConfidentialNonce {
    None,
    Some(NonceValue),
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for ConfidentialNonce {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<ConfidentialNonce, serialize::Error> {
        let value_type : u8 = ConsensusDecodable::consensus_decode(d)?;
        match value_type {
            0x00 => {
                Ok(ConfidentialNonce::None)
            },
            _ => {
                let val : [u8;32] = ConsensusDecodable::consensus_decode(d)?;
                let mut result : [u8;33] = [0u8;33];
                result[0]=value_type;
                result[1..].copy_from_slice(&val);
                Ok(ConfidentialNonce::Some(NonceValue(result)))
            },
        }
    }
}
impl<S: SimpleEncoder> ConsensusEncodable<S> for ConfidentialNonce {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        match self {
            ConfidentialNonce::None => {
                0x00u8.consensus_encode(s)?;
            },
            ConfidentialNonce::Some(val) => {
                val.consensus_encode(s)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct LiquidTxOut {
    pub asset: ConfidentialAsset,
    pub value: ConfidentialValue,
    pub nonce: ConfidentialNonce,
    pub script_pubkey: Script,
}
impl_consensus_encoding!(LiquidTxOut, asset, value, nonce, script_pubkey);

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct LiquidTxIn {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
    pub issuance: Option<AssetIssuance>,
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for LiquidTxIn {
    #[inline]
    fn consensus_decode(d: &mut D) -> Result<LiquidTxIn, serialize::Error> {
        let previous_output: OutPoint = ConsensusDecodable::consensus_decode(d)?;
        let script_sig: Script = ConsensusDecodable::consensus_decode(d)?;
        let sequence: u32 = ConsensusDecodable::consensus_decode(d)?;
        let issuance : Option<AssetIssuance> = match previous_output.vout {
            0x80000000u32 => Some(ConsensusDecodable::consensus_decode(d)?),
            _ => None,
        };
        Ok(LiquidTxIn{
            previous_output,
            script_sig,
            sequence,
            issuance
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for LiquidTxIn {
    #[inline]
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        self.previous_output.consensus_encode(s)?;
        self.script_sig.consensus_encode(s)?;
        self.sequence.consensus_encode(s)?;
        if self.issuance.is_some() {
            let val = self.issuance.clone().unwrap();
            val.consensus_encode(s)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct AssetIssuance {
    pub asset_blinding_nonce : [u8;32],
    pub asset_entropy : [u8;32],
    pub amount : ConfidentialValue,
    pub inflation_keys : ConfidentialValue,
}
impl_consensus_encoding!(AssetIssuance, asset_blinding_nonce, asset_entropy, amount, inflation_keys);



#[cfg(test)]
mod tests {
    use util::misc::hex_bytes;
    use blockdata::liquid::LiquidTransaction;
    use network::serialize::deserialize;
    use network::serialize::BitcoinHash;
    use blockdata::liquid::LiquidBlockHeader;
    use blockdata::script::Builder;
    use blockdata::opcodes;
    use blockdata::liquid::ConfidentialAsset;
    use blockdata::liquid::ConfidentialValue;
    use blockdata::liquid::ConfidentialNonce;
    use blockdata::liquid::LiquidTxOut;
    use blockdata::liquid::TxOutWitness;
    use blockdata::liquid::ScriptWitness;
    use blockdata::liquid::TxInWitness;
    use blockdata::liquid::LiquidBlock;
    use blockdata::liquid::AssetIssuance;
    use blockdata::liquid::LiquidTxIn;
    use network::serialize::serialize;
    use blockdata::liquid::BlindedValue;

    #[test]
    fn test_liquid_regtest_header() {
        let t = hex_bytes("0100000000000000000000000000000000000000000000000000000000000000000000000eb17d689e3d7310644dacc37ad46d691782687ab0ee2b6a99355032a459221edae5494d00000000015100").unwrap();
        let t: Result<LiquidBlockHeader, _> = deserialize(&t);
        assert!(t.is_ok());
        let t = t.unwrap();
        assert_eq!(t.version, 1);
        assert_eq!(t.height, 0);
        assert_eq!(t.time, 1296688602);
        assert_eq!(t.bitcoin_hash().be_hex_string(), "997dd1addb13aac407fb7b996ca2f9cb4a9a71338d3ad9432bd62d2302939ac2");
        assert_eq!(t.challenge, Builder::new().push_opcode(opcodes::OP_TRUE).into_script());
        //assert_eq!(t.proof, hex_script!("00"));  // TODO check
        assert_eq!(t.merkle_root.be_hex_string(), "1e2259a4325035996a2beeb07a688217696dd47ac3ac4d6410733d9e687db10e");
    }

    #[test]
    fn test_txin() {
        let t = hex_bytes("0000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff").unwrap();
        let t: Result<LiquidTxIn, _> = deserialize(&t);
        assert!(t.is_ok());
        let t = t.unwrap();
        assert_eq!(t.sequence, 4294967295);

        // with issuance
        let t = hex_bytes("a530c0e71eac524e367c12af33da41f70ac7d2521f53ccea1ed6d0c910c4cd500000008000ffffffff000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f01000775f05a074000010000000000000000").unwrap();
        let t: Result<LiquidTxIn, _> = deserialize(&t);
        assert!(t.is_ok());
        let t = t.unwrap();
        assert!(t.issuance.is_some());

    }

    #[test]
    fn test_vec_txin() {
        let t = hex_bytes("010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff").unwrap();
        let t: Result<Vec<LiquidTxIn>, _> = deserialize(&t);
        assert!(t.is_ok());
        let t = t.unwrap();
        assert_eq!(t[0].sequence, 4294967295);
    }

    #[test]
    fn test_confidential_asset() {
        let liquid_regtest_genesis_txout_ca = hex_bytes("0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a").unwrap();
        let liquid_regtest_genesis_txout_ca: Result<ConfidentialAsset, _> = deserialize(&liquid_regtest_genesis_txout_ca);
        assert!(liquid_regtest_genesis_txout_ca.is_ok());
        let liquid_regtest_genesis_txout_ca = liquid_regtest_genesis_txout_ca.unwrap();
        assert_eq!(liquid_regtest_genesis_txout_ca.0[0], 0x01);
        assert_eq!(liquid_regtest_genesis_txout_ca.0[32], 0x5a);
    }

    #[test]
    fn test_confidential_value() {
        let cv = hex_bytes("010000000000000000").unwrap();
        let cv: Result<ConfidentialValue, _> = deserialize(&cv);
        assert!(cv.is_ok());
        match cv.unwrap() {
            ConfidentialValue::Clear(val) => assert_eq!([0u8;8], val),
            _ => assert!(false),
        };

        let cv_bytes = hex_bytes("088b7d201e04b3081b57df5de2ae7d236758324ff0fec497f7a90bd14b9da1b6b7").unwrap();
        let cv: Result<ConfidentialValue, _> = deserialize(&cv_bytes);
        assert!(cv.is_ok());
        match cv.unwrap() {
            ConfidentialValue::Blinded(val) => {
                let BlindedValue(val) = val;
                assert_eq!(&cv_bytes[..], &val[..])
            },
            _ => assert!(false),
        };
    }

    #[test]
    fn test_confidential_nonce() {
        let liquid_regtest_genesis_txout_cn = hex_bytes("00").unwrap();
        let liquid_regtest_genesis_txout_cn: Result<ConfidentialNonce, _> = deserialize(&liquid_regtest_genesis_txout_cn);
        assert!(liquid_regtest_genesis_txout_cn.is_ok());
        //assert!(liquid_regtest_genesis_txout_cn.unwrap().is_none());

        let txout_cn = hex_bytes("03b2d2987766835a036d050d4d808d3e01a7c9b19833ef77a1a39e0d85d2f7840c").unwrap();
        let txout_cn: Result<ConfidentialNonce, _> = deserialize(&txout_cn);
        assert!(txout_cn.is_ok());
        //assert!(txout_cn.unwrap().is_some());
    }

    #[test]
    fn test_txout() {
        let liquid_regtest_genesis_txout = hex_bytes("0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000016a").unwrap();
        let liquid_regtest_genesis_txout: Result<LiquidTxOut, _> = deserialize(&liquid_regtest_genesis_txout);
        assert!(liquid_regtest_genesis_txout.is_ok());
        let liquid_regtest_genesis_txout = liquid_regtest_genesis_txout.unwrap();
        assert_eq!(liquid_regtest_genesis_txout.script_pubkey, Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script());

        let txout = hex_bytes("0a5e1f4ff15f8e927a886f9c63bbf4e5ac668052e32a83902b0857cba18c36bc99088b7d201e04b3081b57df5de2ae7d236758324ff0fec497f7a90bd14b9da1b6b703b2d2987766835a036d050d4d808d3e01a7c9b19833ef77a1a39e0d85d2f7840c1976a9142f582f95ad0aac8d97b58ff60fe04babb231e59588ac").unwrap();
        let txout: Result<LiquidTxOut, _> = deserialize(&txout);
        assert!(txout.is_ok());

        let txout = hex_bytes("0a5e1f4ff15f8e927a886f9c63bbf4e5ac668052e32a83902b0857cba18c36bc99088b7d201e04b3081b57df5de2ae7d236758324ff0fec497f7a90bd14b9da1b6b703b2d2987766835a036d050d4d808d3e01a7c9b19833ef77a1a39e0d85d2f7840c1976a9142f582f95ad0aac8d97b58ff60fe04babb231e59588ac").unwrap();
        let txout: Result<LiquidTxOut, _> = deserialize(&txout);
        assert!(txout.is_ok());

        let txout = hex_bytes("0a5e1f4ff15f8e927a886f9c63bbf4e5ac668052e32a83902b0857cba18c36bc99088b7d201e04b3081b57df5de2ae7d236758324ff0fec497f7a90bd14b9da1b6b703b2d2987766835a036d050d4d808d3e01a7c9b19833ef77a1a39e0d85d2f7840c1976a9142f582f95ad0aac8d97b58ff60fe04babb231e59588ac").unwrap();
        let txout: Result<LiquidTxOut, _> = deserialize(&txout);
        assert!(txout.is_ok());

    }

    #[test]
    fn test_vec_txout() {
        let liquid_regtest_genesis_vec_txout = hex_bytes("020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000016a0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000266a24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45").unwrap();
        let liquid_regtest_genesis_vec_txout: Result<Vec<LiquidTxOut>, _> = deserialize(&liquid_regtest_genesis_vec_txout);
        assert!(liquid_regtest_genesis_vec_txout.is_ok());
        let liquid_regtest_genesis_vec_txout = liquid_regtest_genesis_vec_txout.unwrap();
        assert_eq!(liquid_regtest_genesis_vec_txout[0].script_pubkey, Builder::new().push_opcode(opcodes::All::OP_RETURN).into_script());
        assert_eq!(liquid_regtest_genesis_vec_txout[1].script_pubkey, hex_script!("6a24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45"));

        let vec_txout = hex_bytes("030a5e1f4ff15f8e927a886f9c63bbf4e5ac668052e32a83902b0857cba18c36bc99088b7d201e04b3081b57df5de2ae7d236758324ff0fec497f7a90bd14b9da1b6b703b2d2987766835a036d050d4d808d3e01a7c9b19833ef77a1a39e0d85d2f7840c1976a9142f582f95ad0aac8d97b58ff60fe04babb231e59588ac0a9f11d80db920f24886242b1714680a51486dbed992a997e0f4604d89259bc3bb08ad8de65b06cd6555c77ab82d3c197ccd13837f7e66120d16f90aabe418bc4a84035e876552dc6a8193d431d37a8ef942078402017f2434b50ed50b81ef273af5af1976a914824143858a92d5f58f98ba7b67c57db2f810735088ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000009d580000").unwrap();
        let vec_txout: Result<Vec<LiquidTxOut>, _> = deserialize(&vec_txout);
        assert!(vec_txout.is_ok());
    }

    #[test]
    fn test_txout_witness() {
        let t = hex_bytes("0000").unwrap();
        let t: Result<TxOutWitness, _> = deserialize(&t);
        assert!(t.is_ok());

        let t = hex_bytes("430100014e3c5f0de499baabd8660a4bcaeac02b475767882c674b95022d3b4e19bc9a2dea22c914d0c9b2125ac7f93a82c1c4787fc6800b518af68e2ae5cf62bf7c313efd2d0e602c000000000000000185c80503eafe13eb93771e5458758973a0260ed728b1565f32b9a814199c759106ad3caed64eeb0ec72eb2d6db3dbe3bd7c6252bcacd909f03ff8a49042603323bcdf398c69487255c502608aee01c4f68de4fa25ace052b3df6495040ca9f8a51b8f7f9a3195dc5cf29941b59e3e1443aea82aff3e382eefc769093a46b19f0baf47e554291af4807c8cd76ea39c2ad6792dd3f065414cbdad22c007c0713a366042c5fab296ab25ad790019d0f1c52f76cd3616daa29ffc40b96dc54ccd4ab9c44e4249905b75cbf95aa58c00f2f4594fccf737edad181c50e7e5ef3dbaf4681e7f5402a916c869bf7aa29d6774383eba9ead48386ceddbe7f1c4ceecf50afefd0ef94ff16080df8b508ab207399f5af788162c1dc64f17fccab89a1e42664afd4c8ad319b0bccd72f142a98d7e9aaf2504c1839fe40383bcedb87e378c8874a533a9f9228839a1ecd2fa18245df6463b576addd2ff0489d3f7de891826a86d752b8c5de7840467a383d73cfc345bf6dfce140fb43002348fd93bb5c0493df0c83c72a126925690cac179a6f11c208f0f1bdae74528db22f41cbe9e046887369f8d5ba308ce23cca4af86c56a8233386ab71d5c43af72330ea38380f98874bf4f6eb05a1b4ad3e09dc1e56ca98937800cf56a993b145445657558d48144c004ac49037d8dff34b4f491d9f88541404aaa3b6f9015f3399277038a9b4347b771a89edaa2d6e3a5dc0bc9a2d35d9b725414ebe7902742df5f656e60acd329f1a91ba1d6b7682347732bc4d6e0e3d592481ca1e4ba81b432aa7750492a958423fca69465b617bd226cf20e9d9f12658cd4a3b0d799752bc4617d4295c794f7ce9916b1cec3ecb4d8f762bcbc0164587bdd40a9d0cb2da97ba53c9e95ff9efc98a3e5a6be04f40e2b00dd54e1bf2881109b82cd23319ec73b9b0866920f1ee8f0ef0e8f61a4cc34694e8099d035dbe515e2d1e43e1310555bc971308b648a49a8b7f6518287731d1c9bb138133bc780cc7f2b395b372c3183a6d76697dae52690de5645baec1125bbc2fff624dc21f5f5fc3824a30fa0ea5cbd8ba28c18c08394d51a4131f87a8a333a0bf94610bbb1672592ebaa9a1f833ddf53a9bd9e4ada6b44080382ed7635d72e6b51f98af3dc809af9ecd07fe206e0c17c8ed73065116192574f6f620a0f5ed8896eed0d8b186ff94fc67ff0ece533750f63e4215e27cf7dd8d302a24cb38c59d80a301005d53ff80599fcb6814b7b630bd97201dd0b8c5f442b1781b49f2554c1479981126f4d791fef909475d723cc4069353e2f9ae4c1831176960b5b36cf05870ed70fda153e35a97b0f214d03a241188d7a0d00b4b8532e938ba6974f634055aa9a87ccc8c43a3bfaa8df88e86ba0fb7bf4b550430e95ce4cd92eb69a1e7f665e4754b7b0f48e06978eb89a13e7ac6aab365da465ac6a2eed8f206fb09d86bb9f2700844562f3f5ac702185166bcc4daef78d7e544c8da330ab57e353ff4d774ddcedb8c1a720911aae37eee5c2520b2491712a4c3a2f3280ff119dfd9666e0d3ca78de763c52f856053a63a6fba11a15b049d3ac22c7536838ef5dd47e7999f156dca9629cb630097311afb5f2d5868577c4e746eafa78b34e512d42358c4133490a3c275bdf39226872b60d5b0fd15c7293e49013564ea1b09a3f3dd9ed1c86a2f1d9f14dfaafa753690461f4ff7c23b82adbbae764359196662c5a9046a84d2259bb8fd1af768b6b752183e59e248e8b45825860d3843dcfc9290433816a3b779abb94428982037cd0eecf440b32f486c2aa51512df8a762d3eaf02cb7f452d617d58b60b1d2bfe430e26356255da58da742cab4241067968797cea89cd090807fa9d1b5b35f51acebae661a81b27c1a968fcd4118665f74310eecf18cedeacaa635430052774b07ac9f1000bfab58dfaf9996abe6aa9e24c9d5c989178c12a742ef72e4a878f270c85e044fe94d4193456c8c9c552c7a36487af1dbc9b102065fd3e8ebc8e155f1d3394a763bf481d376281db7565dfa27e0cef99859f5d69f559541888187308fda24e1102a745d63c391844996188313d3d61091104e1279418c44dde5549fd553078bba36d3775bf8aa6c7a6e56264360ce5751288994e3a1a11ee738b02f88e90286a0c069cd7afcc09eeb8e393e026a9da535e0199f6704f91826d88bc97f37d77ebacb383a2588d8ecb2e2934fbb4f8b9b242f6202aea2ca919c86ddb2f29fd9b3d79a7122d8c16cd5b16c7e12d81787cb05800db4125c77aa13465c25f49fb231438bb6b7d3a93f63cfd15239596be408324654e185d95ff20dd2fa700d111d832215c572ca37356f721429f5ff383260d891aa4a763282f1c8b10d0770584ce0aaefdc5c804944ccb4ad21603415468f83dcc243daa35b33f8fef9eb8f2eb8680ded945e3fdf61f6e36d5a59186a3079f97088284c81fd8658ca5f923433b7db24b3a325f93bba717c5f38ad3cf589e009e321a54582a96ccf70383af6d777e04c907b4381e322c1f6b5004a12889a878b23d9a7ae1afc7a5f41497972939a3f884ed5dc96d3fe5e0af54a53282cda2b7d23cab61558bb935ca1e4cd8e24eb314a6d6491a82ab8ed6c19062d0b1d98a6e76e8e115a6a473f15d34d1623cc5f9cf2f7e19d101f997d0108cc39ca7205823351351812cd527fbba5dc9f48400067be9d35ce09930306a262a1afa84c086424aa4e0ba45bcc7ca71266a38cdceb22915d7e7e58ae9418223bcb3308c56115f2ba4296265ccb0ad10d6613723e0e917603111c37246bcc28496f03be3fcb8eeceece1037e8859797544b0dac16dcb5e7a49d9a0b0a55705634145cb748b5086682737d5e876b6eb7185364e90999b5920121ce8c9629de8946928ea376065693e56a6693924e36f25f521ff03a7f939a28ca751d074fc041b005b549bba21f81b75a660ce4a83a8ec00d1d4499a514f7071bb7b015302212598946a3ab13cf07971fe17183b10d2735b3856a56c4108bdda8538be7be5f372c97572fe27edd29c292c534f243b8dda351e31d6f6fe589fc9acb2b3a836ec8696b54e46d321a82cb64521ad4381f81530be6d70974a53c4b8a19e6ed77d3d24133fe8d6e961742ea25e31a7c91bd0288b7cb7b3f64b75f789e181d7afe9dc4ef6e7939282d1df848aa2a34d873b08422928b4b92b41061ea5e351d5ddfcef06a7c44c921ca414d7098554ca620c255b751db7a1fa0abcce36b1d42bb9052563a9c65e9ed019091da598df22bb38fbfdc482438e941c693628a6f4a4811e629b5a5f72942c40baa26493c5c0b748703450ffd383b6c1153f9b7bbbe23bbb40706c5996dee0614a9560d5321eb11ff8f6d27cdc6033e5b31857a598d627b092950284f030815337be80e56d1ee5cc4c395e77e528f8b3411921da463ae761454784d8a817dddc0abfb6acb273bf67f369713a379486e9c934cddb0f76c153ffe4f8a458c8e28ee4d3c7b1b43eaeb7c0b8ed4bb89a4eecce69cdabc046d972d60b1608fd200c402c8f46c87f35bd7928e3e801dc26b517399aedb9c9e34d839a6706567b0b04c0b8fcb6b90f86738a9d4adbdab61b2742cff0d19b4c7e81f56ea376e3cb53f0c9ab3e904a905e68cde66b0ce4ce2e29ddf0fc88f60945cf3699bc2c5f9556941f188640b22e464af4dc50f035a291a5e5158da210d00e18045bc7b885f11f2bf135e4d856be3a59abbd3edaf21f12045f97ea458d8e7705791711e006561a42f2e8c2546199c9659bff049610e09f1c9445ffaad04e2ab2949ffabad6f7e6184a4ea828f33cf537778b132c85a6e839c0b0c50fde90791b82a5aec546ded446361100e80080fe4149240b5be70bb04adfd07e6e304bcf8fbcb525e8ab13c4f17002371bae7613095e5f050e53d7c3203590ce3f033a5fa88538e54b08364d9c20dcfa587e7f2872632aaac1357b9a0b35828130284efc8e8f3f723e01f9af301e6f095ce0e53b3ca6f336702eafb1c4e6a2e4d15fa37af6fc292e480bddd48c751cf20c3e4370eedf62ea317ddd281b2f9edd66ffa58897cc74061e441395db55f255dbc7eadab53a452f58cf677ffcd08c45107296295f8e8d4d5e75672eb5597c70d2463c7b4c0f47ed38e21e1c75a27d7d18fdde550917dde4c318c2b8d67f5f8d0f5ac94495acb7d6e3415394ce336d7de8da7b0d4b7fac6de38bd923b4b6035d33d380fa948ba975eca660b9693d51ad89760d8178f3f4739f8fe1edb162c92701e084a15ec0bcc3b5bca2df1f648f4189e5a6998ed6edac5a6d223feefd7630c5179006aeded6a19e87a05038bfeff7415b6a36fc8bed0ce2b98185e2b98e6c7975923a9feb868804137eaa7eec017a4ffac8783251d8656dd17089738bbe988a949600dc28d61d0fe54002c5df88143ce8936223c2098bd594dae7fb35a1a591d15cf8fbd5c3d7294c1ff210d2a17f48881c0aac41f9d3053e4ccd11ea4531587bc000d5b1b69674257843b9db3e143830b0ff2524e427acade4d2e7e322e3cea4036064f480981c48c8c073ef171acfb01dd3cad928bdcc2cd91e5cf155983e3811c7caf1dac39f01165243c70fc12258af91bfdc3ec8c87d499c52de0e52cc9cd33faf0c28b241ebe2ef5a52f2523660e0268658935728b5c2c8269c19aa61dc5fd42d20c207927b9684c495c03766b2bc26d163dbea7254ea3e67c9de43b7ed4039d1805a4d48cc20ec2874c4d589922946a96a2397314365f481c9212e34f59e630bde02790062eddec8ba2fe756d77ab2a8b49d29cb6fac0024bae21fdfdfc0f0e3ad53c8c03e612bf9b66135ef2084e0b09acc4f5de6c1904b8ccb2e22503ce46d8611ed1adefba074e653309ba47aab6495eebaadcedfe96346b63011f59c6bb288593012cc5044ff9a25136b06894f49c08ea4ab5232158ce37e2b7abfae32044275e83d43d57328eda050dd008ceff7d300e8c9289e118390a90ced36d03ef2ac3e6316fb2ada6c021c0ac79d58ab3449fc87fec1116c250219e973533fc282f83e2cf04518b6039fc5de4fe6564f9be72813df713d8311fa3942c66b2be96c238f4f942843e5a5d1c6bf8638959d3e43cd7dea9d").unwrap();
        let t: Result<TxOutWitness, _> = deserialize(&t);
        assert!(t.is_ok());
    }

    #[test]
    fn test_script_witness() {
        let t = hex_bytes("00").unwrap();
        let t: Result<ScriptWitness, _> = deserialize(&t);
        assert!(t.is_ok());

        let t = hex_bytes("01200000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let t: Result<ScriptWitness, _> = deserialize(&t);
        assert!(t.is_ok());
    }

    #[test]
    fn test_txin_witness() {
        let t = hex_bytes("00000000").unwrap();
        let t: Result<TxInWitness, _> = deserialize(&t);
        assert!(t.is_ok());

        let t = hex_bytes("00000120000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let t: Result<TxInWitness, _> = deserialize(&t);
        assert!(t.is_ok());
    }

    #[test]
    fn test_issuance() {
        let t = hex_bytes("000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f01000775f05a074000010000000000000000").unwrap();
        let t: Result<AssetIssuance, _> = deserialize(&t);
        assert!(t.is_ok());
    }

    #[test]
    fn test_transaction() {
        use hex::encode as hex_encode;

        let tx_bytes = hex_bytes("0200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03520101ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000016a0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000266a24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let tx: Result<LiquidTransaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(tx.version, 2);
        assert_eq!(tx.input.len(), 1);

        assert_eq!(tx.input[0].previous_output.txid.be_hex_string(),"0000000000000000000000000000000000000000000000000000000000000000".to_string());
        assert_eq!(tx.input[0].previous_output.vout, 4294967295);
        assert_eq!(tx.output.len(), 2);

        assert_eq!(tx_bytes, serialize(&tx).unwrap());

        assert_eq!(tx.bitcoin_hash().be_hex_string(), "6e7630a16e177b6379cbe3a0e24a0b02c7ac7175546b264f89c58778a462327f".to_string());
        assert_eq!(tx.txid().be_hex_string(), "91c0c46e5c404db1b72aeceea801c000fddbe0c8f1e9a1acc69f08ff2ff1bbce".to_string());


        let tx=hex_bytes("020000000101c31650b7ee3350086506c18edd06be852a4b4f87643356e9c2f0e297f83c45393800000000feffffff030a5e1f4ff15f8e927a886f9c63bbf4e5ac668052e32a83902b0857cba18c36bc99088b7d201e04b3081b57df5de2ae7d236758324ff0fec497f7a90bd14b9da1b6b703b2d2987766835a036d050d4d808d3e01a7c9b19833ef77a1a39e0d85d2f7840c1976a9142f582f95ad0aac8d97b58ff60fe04babb231e59588ac0a9f11d80db920f24886242b1714680a51486dbed992a997e0f4604d89259bc3bb08ad8de65b06cd6555c77ab82d3c197ccd13837f7e66120d16f90aabe418bc4a84035e876552dc6a8193d431d37a8ef942078402017f2434b50ed50b81ef273af5af1976a914824143858a92d5f58f98ba7b67c57db2f810735088ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000009d5800000200000000000000430100014e3c5f0de499baabd8660a4bcaeac02b475767882c674b95022d3b4e19bc9a2dea22c914d0c9b2125ac7f93a82c1c4787fc6800b518af68e2ae5cf62bf7c313efd2d0e602c000000000000000185c80503eafe13eb93771e5458758973a0260ed728b1565f32b9a814199c759106ad3caed64eeb0ec72eb2d6db3dbe3bd7c6252bcacd909f03ff8a49042603323bcdf398c69487255c502608aee01c4f68de4fa25ace052b3df6495040ca9f8a51b8f7f9a3195dc5cf29941b59e3e1443aea82aff3e382eefc769093a46b19f0baf47e554291af4807c8cd76ea39c2ad6792dd3f065414cbdad22c007c0713a366042c5fab296ab25ad790019d0f1c52f76cd3616daa29ffc40b96dc54ccd4ab9c44e4249905b75cbf95aa58c00f2f4594fccf737edad181c50e7e5ef3dbaf4681e7f5402a916c869bf7aa29d6774383eba9ead48386ceddbe7f1c4ceecf50afefd0ef94ff16080df8b508ab207399f5af788162c1dc64f17fccab89a1e42664afd4c8ad319b0bccd72f142a98d7e9aaf2504c1839fe40383bcedb87e378c8874a533a9f9228839a1ecd2fa18245df6463b576addd2ff0489d3f7de891826a86d752b8c5de7840467a383d73cfc345bf6dfce140fb43002348fd93bb5c0493df0c83c72a126925690cac179a6f11c208f0f1bdae74528db22f41cbe9e046887369f8d5ba308ce23cca4af86c56a8233386ab71d5c43af72330ea38380f98874bf4f6eb05a1b4ad3e09dc1e56ca98937800cf56a993b145445657558d48144c004ac49037d8dff34b4f491d9f88541404aaa3b6f9015f3399277038a9b4347b771a89edaa2d6e3a5dc0bc9a2d35d9b725414ebe7902742df5f656e60acd329f1a91ba1d6b7682347732bc4d6e0e3d592481ca1e4ba81b432aa7750492a958423fca69465b617bd226cf20e9d9f12658cd4a3b0d799752bc4617d4295c794f7ce9916b1cec3ecb4d8f762bcbc0164587bdd40a9d0cb2da97ba53c9e95ff9efc98a3e5a6be04f40e2b00dd54e1bf2881109b82cd23319ec73b9b0866920f1ee8f0ef0e8f61a4cc34694e8099d035dbe515e2d1e43e1310555bc971308b648a49a8b7f6518287731d1c9bb138133bc780cc7f2b395b372c3183a6d76697dae52690de5645baec1125bbc2fff624dc21f5f5fc3824a30fa0ea5cbd8ba28c18c08394d51a4131f87a8a333a0bf94610bbb1672592ebaa9a1f833ddf53a9bd9e4ada6b44080382ed7635d72e6b51f98af3dc809af9ecd07fe206e0c17c8ed73065116192574f6f620a0f5ed8896eed0d8b186ff94fc67ff0ece533750f63e4215e27cf7dd8d302a24cb38c59d80a301005d53ff80599fcb6814b7b630bd97201dd0b8c5f442b1781b49f2554c1479981126f4d791fef909475d723cc4069353e2f9ae4c1831176960b5b36cf05870ed70fda153e35a97b0f214d03a241188d7a0d00b4b8532e938ba6974f634055aa9a87ccc8c43a3bfaa8df88e86ba0fb7bf4b550430e95ce4cd92eb69a1e7f665e4754b7b0f48e06978eb89a13e7ac6aab365da465ac6a2eed8f206fb09d86bb9f2700844562f3f5ac702185166bcc4daef78d7e544c8da330ab57e353ff4d774ddcedb8c1a720911aae37eee5c2520b2491712a4c3a2f3280ff119dfd9666e0d3ca78de763c52f856053a63a6fba11a15b049d3ac22c7536838ef5dd47e7999f156dca9629cb630097311afb5f2d5868577c4e746eafa78b34e512d42358c4133490a3c275bdf39226872b60d5b0fd15c7293e49013564ea1b09a3f3dd9ed1c86a2f1d9f14dfaafa753690461f4ff7c23b82adbbae764359196662c5a9046a84d2259bb8fd1af768b6b752183e59e248e8b45825860d3843dcfc9290433816a3b779abb94428982037cd0eecf440b32f486c2aa51512df8a762d3eaf02cb7f452d617d58b60b1d2bfe430e26356255da58da742cab4241067968797cea89cd090807fa9d1b5b35f51acebae661a81b27c1a968fcd4118665f74310eecf18cedeacaa635430052774b07ac9f1000bfab58dfaf9996abe6aa9e24c9d5c989178c12a742ef72e4a878f270c85e044fe94d4193456c8c9c552c7a36487af1dbc9b102065fd3e8ebc8e155f1d3394a763bf481d376281db7565dfa27e0cef99859f5d69f559541888187308fda24e1102a745d63c391844996188313d3d61091104e1279418c44dde5549fd553078bba36d3775bf8aa6c7a6e56264360ce5751288994e3a1a11ee738b02f88e90286a0c069cd7afcc09eeb8e393e026a9da535e0199f6704f91826d88bc97f37d77ebacb383a2588d8ecb2e2934fbb4f8b9b242f6202aea2ca919c86ddb2f29fd9b3d79a7122d8c16cd5b16c7e12d81787cb05800db4125c77aa13465c25f49fb231438bb6b7d3a93f63cfd15239596be408324654e185d95ff20dd2fa700d111d832215c572ca37356f721429f5ff383260d891aa4a763282f1c8b10d0770584ce0aaefdc5c804944ccb4ad21603415468f83dcc243daa35b33f8fef9eb8f2eb8680ded945e3fdf61f6e36d5a59186a3079f97088284c81fd8658ca5f923433b7db24b3a325f93bba717c5f38ad3cf589e009e321a54582a96ccf70383af6d777e04c907b4381e322c1f6b5004a12889a878b23d9a7ae1afc7a5f41497972939a3f884ed5dc96d3fe5e0af54a53282cda2b7d23cab61558bb935ca1e4cd8e24eb314a6d6491a82ab8ed6c19062d0b1d98a6e76e8e115a6a473f15d34d1623cc5f9cf2f7e19d101f997d0108cc39ca7205823351351812cd527fbba5dc9f48400067be9d35ce09930306a262a1afa84c086424aa4e0ba45bcc7ca71266a38cdceb22915d7e7e58ae9418223bcb3308c56115f2ba4296265ccb0ad10d6613723e0e917603111c37246bcc28496f03be3fcb8eeceece1037e8859797544b0dac16dcb5e7a49d9a0b0a55705634145cb748b5086682737d5e876b6eb7185364e90999b5920121ce8c9629de8946928ea376065693e56a6693924e36f25f521ff03a7f939a28ca751d074fc041b005b549bba21f81b75a660ce4a83a8ec00d1d4499a514f7071bb7b015302212598946a3ab13cf07971fe17183b10d2735b3856a56c4108bdda8538be7be5f372c97572fe27edd29c292c534f243b8dda351e31d6f6fe589fc9acb2b3a836ec8696b54e46d321a82cb64521ad4381f81530be6d70974a53c4b8a19e6ed77d3d24133fe8d6e961742ea25e31a7c91bd0288b7cb7b3f64b75f789e181d7afe9dc4ef6e7939282d1df848aa2a34d873b08422928b4b92b41061ea5e351d5ddfcef06a7c44c921ca414d7098554ca620c255b751db7a1fa0abcce36b1d42bb9052563a9c65e9ed019091da598df22bb38fbfdc482438e941c693628a6f4a4811e629b5a5f72942c40baa26493c5c0b748703450ffd383b6c1153f9b7bbbe23bbb40706c5996dee0614a9560d5321eb11ff8f6d27cdc6033e5b31857a598d627b092950284f030815337be80e56d1ee5cc4c395e77e528f8b3411921da463ae761454784d8a817dddc0abfb6acb273bf67f369713a379486e9c934cddb0f76c153ffe4f8a458c8e28ee4d3c7b1b43eaeb7c0b8ed4bb89a4eecce69cdabc046d972d60b1608fd200c402c8f46c87f35bd7928e3e801dc26b517399aedb9c9e34d839a6706567b0b04c0b8fcb6b90f86738a9d4adbdab61b2742cff0d19b4c7e81f56ea376e3cb53f0c9ab3e904a905e68cde66b0ce4ce2e29ddf0fc88f60945cf3699bc2c5f9556941f188640b22e464af4dc50f035a291a5e5158da210d00e18045bc7b885f11f2bf135e4d856be3a59abbd3edaf21f12045f97ea458d8e7705791711e006561a42f2e8c2546199c9659bff049610e09f1c9445ffaad04e2ab2949ffabad6f7e6184a4ea828f33cf537778b132c85a6e839c0b0c50fde90791b82a5aec546ded446361100e80080fe4149240b5be70bb04adfd07e6e304bcf8fbcb525e8ab13c4f17002371bae7613095e5f050e53d7c3203590ce3f033a5fa88538e54b08364d9c20dcfa587e7f2872632aaac1357b9a0b35828130284efc8e8f3f723e01f9af301e6f095ce0e53b3ca6f336702eafb1c4e6a2e4d15fa37af6fc292e480bddd48c751cf20c3e4370eedf62ea317ddd281b2f9edd66ffa58897cc74061e441395db55f255dbc7eadab53a452f58cf677ffcd08c45107296295f8e8d4d5e75672eb5597c70d2463c7b4c0f47ed38e21e1c75a27d7d18fdde550917dde4c318c2b8d67f5f8d0f5ac94495acb7d6e3415394ce336d7de8da7b0d4b7fac6de38bd923b4b6035d33d380fa948ba975eca660b9693d51ad89760d8178f3f4739f8fe1edb162c92701e084a15ec0bcc3b5bca2df1f648f4189e5a6998ed6edac5a6d223feefd7630c5179006aeded6a19e87a05038bfeff7415b6a36fc8bed0ce2b98185e2b98e6c7975923a9feb868804137eaa7eec017a4ffac8783251d8656dd17089738bbe988a949600dc28d61d0fe54002c5df88143ce8936223c2098bd594dae7fb35a1a591d15cf8fbd5c3d7294c1ff210d2a17f48881c0aac41f9d3053e4ccd11ea4531587bc000d5b1b69674257843b9db3e143830b0ff2524e427acade4d2e7e322e3cea4036064f480981c48c8c073ef171acfb01dd3cad928bdcc2cd91e5cf155983e3811c7caf1dac39f01165243c70fc12258af91bfdc3ec8c87d499c52de0e52cc9cd33faf0c28b241ebe2ef5a52f2523660e0268658935728b5c2c8269c19aa61dc5fd42d20c207927b9684c495c03766b2bc26d163dbea7254ea3e67c9de43b7ed4039d1805a4d48cc20ec2874c4d589922946a96a2397314365f481c9212e34f59e630bde02790062eddec8ba2fe756d77ab2a8b49d29cb6fac0024bae21fdfdfc0f0e3ad53c8c03e612bf9b66135ef2084e0b09acc4f5de6c1904b8ccb2e22503ce46d8611ed1adefba074e653309ba47aab6495eebaadcedfe96346b63011f59c6bb288593012cc5044ff9a25136b06894f49c08ea4ab5232158ce37e2b7abfae32044275e83d43d57328eda050dd008ceff7d300e8c9289e118390a90ced36d03ef2ac3e6316fb2ada6c021c0ac79d58ab3449fc87fec1116c250219e973533fc282f83e2cf04518b6039fc5de4fe6564f9be72813df713d8311fa3942c66b2be96c238f4f942843e5a5d1c6bf8638959d3e43cd7dea9d43010001bf0cd5b408773f864e4eec769c5b8b60c12b3af17240ce6dc2ad1b882463cdfa09637535b1bb14023cb2c8c700b0b00dedc12f2d770d30ce888f58c18e9ce4b8fd4d0b602300000000000000011a0200479c939142b6149c668147f74cfd1f7cb9c3dd371fa9ee74291f1c965418e5bcf637d99f53fd2fe2e9abc29489a295ac739e8317b4958d31b50c19a48391e0967b0b1e035249e4c9252c2fbaa4c045e0a2832e86454578ea8aba0451560913a0af0276d30f207d7fb0eb210b7e5ddda1bfadd1b4eb25fb3ee889816afae323b13fadba0a75026f08655bd64b23fe991ff8ea4cdc6927b865c80f1ab46316b1e8c8ee7b2e123a0f82c89427ee99b57a856281902e62e1bf2345076b5c54e225f288592ee670f217e751645669852e6c732c6c3f39c29c957ecd8bff60fab23ac7a3e91036485cd4a287e82ec12757bf6f784ad36d9877438afc4d0d8d70385a01917804a9c8027e74e32e0de26a74341bc4279829fb2f7fd27cd2979391911e75a4ed2e6a1a177967b9ca8e5f06a59fb943e8fb2365420f49b161162d786d273ebc5c9b7d73cdf28eddfe095f909d1f7699589d6d9548487ce3b9bfaf7ce3ce17049b1c3ec568ecd3336a4d0a7de7fab9652550997cd960459307c1f469031456eb4645ca32273c6a8dc67ff6ab474016820b1ddf0bfad091b4ab1cb2b551c05029c0cabe5c2ee41dbc885a9cdccd74ed520443c2165715a059751fefdc61d8df8be4438c7c83410aabc2351727dda505403b530ce6541609c71f73b2d4a567e5e1be38c87cab66c237f08410346cd87c4a8ad337319e1512ab1daadf639b8eedf759761f16285a23d8c747f90448fbd00d09e714c8a6b11f95cccb09344442ce7668a85963accf9b9cbe28fa3e59d8b89915ecd90b750d516bcc9e231a6eb25877ea736213c12673896e66afc019dfcd1758033b1c4fb10abee81f380ce185fa7bb35d767cf3699d395bcb3c457998d738229d3cd180ded143e7fde8c0bd46aa59e1306f6bedfc7d480dc8719293e67697b8046a52a3a2578f84ea7afb2ee063fe1bb0abfe3722a53889f79eb0752ad2841abe93aab86e4020844b7c2423291a6a1ecef64aac1eee6dc7003e99e918fe60bfc4df9c5ed54f03feb0c5f69fc92867f4c76bdedd26bacf70ca03be03b672d1e9de8aeba945df446ce2c26cb2ec84d564d5b9c91a56547c6705eb2af4e542fb40bf1651da493617f0332890e07f57259c45e5f9f406862066ecd117b27711c4b5a7b70b30e5d049c49c7dcecca7045393d8b9fd8789dca039514650356fd19c141fbbe6c1f239f89445638ed755f9aec2b50457a8cb3249e465ea1cc75be715719c7b1ab19e4fa5e0319245c6e28b71f8c1ce210ac2fc374af420340dca1f3fda54cae4048447dd2c9069749ddcebc7af56f4b30a89b83c4768b2e31bf66aff7452566bb261229acc198fbda1aff24ac9f250ae2a23054fec0e0834b52b1c362224f86dd78338e194058db51e4d43d988b845ae11999aee62f9719239228c6bb83f301cfe726b2dfde01789bdd5e11c10ae0b5ed3a7a47145219418301692136883f86de583e1576a01f8e1cfb30e9ba812da067a57c818b6ec5ccb4e770832bb57fa5dda61cf99599a790859cf7ceecbf865674d91e603f469650d9e989451ec4a7c88151237a25fab153e9a14434cb27e113c6cdad13cdb61b01d7bc324a3163513523616f928ba61b855e5c63a2e786ea5a3c2c1aed66b69821376f3ecbd914221b9fa0c50cc5589ce3b044c11e72b1ab2a46b7563a91f2753e9f2cad76358cad7d47fdc51c61aed714205b6fa054c9583984ec4aec6d5d9148ae00ee199a948bb7c49257f381c58805dad6cc16c00060aaa97b0f5fca14388d4d81898ef0d5e8d837f8272b8bd1bcb554032d09aeeb33c50c73a9acaea922f87fcaa98417f71f44ea79643f935dda6705c889a0941e9131f248d21046dca21510a9c9e6b4415143c9b085ea0891fdae09c7720db369ba82d66c22bcfe60717eb9be5aa801fe5212f2b7bd285b17763d3cbe7b3b17d726924af339fc8321a6bdfa3039d0e18f51c968378151213a84638786b2b7248a1406e30ce531bc8169774deae514d0924f4a21b55493f6c8ab9b9e76fca43cf499edac18230093e1e4e950b4a2da6c7bac67974f7c2371b497053427bd486789accd5c5568d15e884d9d99ce69704d67b4b2df5dd21c4e90639e0196dcbf9e5569352bfe04fb0eb0d2724d1a80ca9a5ba4484cd13dcd053679fc5a89b4e7ed13542d46801775d98ec4d1cdf38a6e01eefa1d2c0a99fa0e50540a6b2fbb70096d3f16fa627a8601d62f5b81631f76dc3c6c99e95aa263530c5adffc514027a11b92475d743863790b91f68fc4ae5c5393aae6849bc2eb6558889c1a88f4f639c32f6c6ca86a91859287d30075443e3ed70c19f8d951f1d40feb12cd005578dd56f5c92335835636cef6696129d89f17a19f4f6b9f08fc58953cc6f610ae7f896e4e581d03da570d3ef15cf005372f395a8b961ccaed5c7c023915910991799abfd8d0fda8e3412dad54f717c07217a0e3550624069aa2ac0a4191cd3d11478cdd5f9ab659a65f67f8b40ce5a888cb41928aa06ef3df537279a57757367f2b6a208af88d8e49a6aa8e4ae23d2ade9f2195e0d7329f7bd5b8f9c797500fc4a986a9ffaf122cdb18f47d27d8f1de02fd622e2dc6e5faf8fc41cdc2539529192d78101b0282430b5402a2f1fa4dc2854e9cbcfeb2ba2f997e866441060f6d716c5f27a1ece835a68682c68c575520684bf786803e57c63720a39bdf2339dd06b79bbff36939b0c3ad4d4450e9a704b66a6a9b2363fe99de43a7b9c474e3b511539c27fee85082e3fc28901fad868e1c94dcd29cd4c6490ee4ad9d7d40e865bbcb2794f97e1b5f93dd2a31034533901ed09043806606e2659edf496b0f804efb14a9674ca98c6e0bd621ddc6395644b359b524f4ede2ea51baa7742edeaf2712ac4ae4f3d253e1884b926e3c5a3e0d74a91833f0de658c2df82211cab71f03fc483bd408c57d859c6b4e71f1683a9d7ec34ace2969f274ba48b7c808b9cc9f5a5f61ffb9c1f1b9260b5a934c9795bd3be32c55b78196b35af8f257ceebce5baeaf153cf516805d1e8cad50c6ffb17026971f1924f0332cce7490230f821d51ef5798a323230e37113fdf4256697cf87bfe3ff5d20791ed4d56eaf613030f50cffea9edc6fb63bca6aca0d639ce5fdc5209e8e23724c7c073ee29cd9f8a560f10fade6b9cb70e08c1f99081ae771552df313e8468578523cbb4b9bfad15e50f3df7d98c9a271f49de9a2aa9529ffb9f0984727cf77f45017626c1baa1db3f38546fa7fcb6263bb548321cffd2ed0205f0abdf8b60a7dace88e63c32894dd9920b4a40cf15c0b29bec01bff83f92a9ac3d0facdc570e2b88316c279b2bf39397d31dfcd99f28c02e6f9deb23a4dcaebb53abf3eea3b30927208f26319ac91cca8e72ee43233872d17c2e8c3d9740a9eea0ff87b2d1f1279ef793fa88ddc22d81c0d63b72fdd2ca8baea16576ff6df3df22ba4cf1d61b8ca2399edb7be62d802688667c1fc6031039364760f981e1464e9cfd5aadde627672890f1f6dead9511bc013d68669d45f9b223b62ce1e5f5b3f2a1abb07b0ea0ba86b300248d4c48e982ee2a75a05502a206d243aaf5d171b4ab1e565767960fff4d694776e0296807f657c5baaceba622a5e83e03aa15713e91b08d732fb2c4307f3609c84e669d256fa5df6279d279e2f018025dd1839ca63c432a8e5bf2c19fb88091009995b9569848e6d792344c437c5d46481bc4aac663ebb3345b3d0fbfedc2d2312775bcb5bcddb12c0243b462c8b4b2e02ce419d94aab6a99854ba1e588e2ad4bb32e7120a727019c0ceaed2049c466ae5cee911b4687be6ad0fe0edd7a87fedc13bad4847f6d3d7964834afd558d468e84d600efe55914e88cb021569af741a87365c025cd15af8ae94acc46ec88140d7a9135534644353b5251bcbe998dd9ae44adc2fd05e541c10de854fd6937063785ce123d09cf32854091389bf226f33f4335d1b0f8aea7401fe4d07ea8764d43d8c0bffce8bdbb2dd882653a834a35e4fc60838c3362559260054d049aedcbb4a39e16cedf065758289ba8f4d41b258637eaae3463ad0000").unwrap();
        let tx: Result<LiquidTransaction, _> = deserialize(&tx);
        assert!(tx.is_ok());
        let _tx = tx.unwrap();


        // tx 81c9570df1135a6bb7fb0f77a273561fddfd87bc62e7f265e94ffb01474ae578
        let tx=hex_bytes("0100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2120a530c0e71eac524e367c12af33da41f70ac7d2521f53ccea1ed6d0c910c4cd50ffffffff0101000000000000000000000000000000000000000000000000000000000000000001000000000000000000016a00000000").unwrap();
        let tx: Result<LiquidTransaction, _> = deserialize(&tx);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(tx.txid().be_hex_string(), "81c9570df1135a6bb7fb0f77a273561fddfd87bc62e7f265e94ffb01474ae578");


        // tx 39453cf897e2f0c2e9563364874f4b2a85be06dd8ec10665085033eeb75016c3
        let tx_bytes=hex_bytes("010000000001a530c0e71eac524e367c12af33da41f70ac7d2521f53ccea1ed6d0c910c4cd500000008000ffffffff000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f01000775f05a074000010000000000000000640125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a500000015100000000").unwrap();
        let tx: Result<LiquidTransaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(tx_bytes, serialize(&tx).unwrap());
        assert_eq!(tx.txid().be_hex_string(), "39453cf897e2f0c2e9563364874f4b2a85be06dd8ec10665085033eeb75016c3");

        let tx_bytes=hex_bytes("020000000101e9dacb06935da256cd9a74aef37c43168f4096164672d3c98d76292639ef104b000000006a47304402201d1d4eb651e1c250240f7a34e191d778a9a7fd77e7a468ac4f24aa7750cac769022006bb6625f4c63affbba75c56d6eaea4bec419f4276f3a5ce9ffc5f75f47817410121021fe54c3fa31987f97cab44e33019c3d95a8df0838f033a17a8877a38ea08a1d6feffffff030b0c1b8b6332689483d91ff17f6f8d6f321797c0f0d25d7748db41725119ff4ee208e686fe4e8eed6806f1cfbbe6bd81f5658e9383a74b0975228fc750c06cec879c039d9a348d7e1a13f84a7144b58e3ccfc16c68466c1194fdfb7961908077a61d421976a91495e8d756b8324e1397bc399a409ab535ac9a97c888ac0b28ca818e6f9d769486952b8c925b185df23c5e0dc7067639f41f074f3b0f8d2f08d243893c6c5fbe8a396084f378b6882e763b0606303e733e460940abc5422c3d03319ff39b5af118d2e7a72d8e10e52e7c20ae4a46ca50f7e9ffe90cf238753e4d1976a9146619f89af613d6a6ecdd14ce8e1d7428d401cb3b88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000975400000000000000000000430100010ea76391161a682e91e40106658f0a2eb13fdd625889ff7f08bad67d317b4cfafa87b1eeeb4845c92abd2a835d4b488c6d7ecdeb8cf6fbfe070e608bd11aa14bfd4d0b60230000000000000001030301aab8f67ef718da9d087243cee9958b59e269e4b5271ee7ebb16cd32bd1ba00abb93a83c8933838c04cded01ea58b289310669be10e293aae4bec4ff33f101370e8ff27f2cd6c7183ece7a593ffb23692c876946a6be89d287033384d1deca15832eabc948a9e87cd6820b7bdb07b385b5e567a31c64e1426bed26ce086cc48af5b8182321eed17538e9245ad1f37a75129ddf9329a0c20c90f66f44507265cbad146dac38bb53c816ce37002693f8b6304c6db6b7499baba51496fef6a53fc1999ac9236d00696a707785e3e9bffcf1a2e5c5fd9d3dd8b09011b2ef406c09140b21b8e43e839f0f46559195dfdf17f36b7a6d5793fbc0fc83117edc14a1712f423959805c4b8bd8ce3ecf45cbd294f6d62ea4bb088f0643f76b1dabd11a68a5e7c6b189bbafc82d54282560613261ff6fd8780f7a87cae1e5131ff16279df984f4d5fb77b1f7808cc829c47f1d54d897ea3fcbd583d6c6a2d3bd925e9ca1e29c85937ca56ab0ce115f4f7e1a34352207498c25866a1b7ad570555fbab5ae0034cd78f661a3d5970c90d6a5239e0534c39f366902108e1de258639cd361a5d9b43314337387c5b292acbee07c1025ee001d40eb0d946abfa24db851f71a8bc323c4908956942baefa5663b43b822453b59f689d337aaf7faeb0b92702c4830eb4559af50e9d37d56fcdd7ddce12b8a15ca1a42fbaed47a9dbeb64558a8e68513b4c9259a9600a34c502a9f826adf73f01312ba75fec0a4c120ff207604f630ca69d413d0de6df4cf6417efd19899379891ba03023ae5c812a3ca11e6b3ff1b83cff3bdb51d817145f32feac31d40366e818ee0ceb02b3f4af3bc6872ef9ac2c649ae4e4587d9b68483caefc0f9322f926fd294cadcea8168924edb4c873824eb820d2b80e5db58cf36772e530fbb3064bfc5ac41341e7e3dea17567117f598c8e97812a377cc0899992ad3f40e9ffb5598b1347f41c3d2b7497313edeb8bd6dcc84bf6371c5592807622f6fa1a47f59be612d463dc46c3ef3581caddba61779a88250ee0586f1fd49d124cc62c47b52e1352304335615673393ca05b0019dd5703383fab0a8bfa5139c52a9625874363e3582fcc8d9a8b7fe11ebbe4a4857d03a10eb19832a605489fc905fbac3475d69036994bd6597ee8265e99dc91fc880348a957bd20270b9c251e88a645e23bb8573a1eecfe460f92fcbacc4c685137f8f4182a34840009a1d8b53624d66dd363ed6fff4fd182e2cd09c63835c5ef4fa44a1e88f53f3f943ebe35cd076149afdcaf47323f8d05c1fe9f738fd5c99f6d2d5d37fff07c8a8c0cf91c8f7e18c70a21adb22786f783e96cbe48178faaa4a502e76c2c5224252361353c277b54d0783f220459e085fc5ce9dc74e2068b3eb5821cb2e9f07c7709d8d9c3b2f6021f5c6ece0525bee3812f445d9941e2ec4c758ef11f89613ffd280ace6d56bc71ccfc8565ebdb4ab3ad6e35399e05375e8350247c84ee84f604b218d4335945533e4596f564ddf3e5c64d5d7245e06320f96e022d48b1788f0f90c6e3c4e3d1124239eb55a831f33958167e0b0992f895d58afe8ba1a54fe26ed9ca4dacbcc2a92b0faaec86e318db5ca8a8a3d2b21476276d93e43048c4365c9fb342dfb903638386289c72ccfb640770a143947ea894a5c682a46ad0301e24a8e9ddaca295ea26205617494046bc0e45c32cd97f846cde490d0e247dc3089440e960b919006cbf5dedf36db3ae3c78d7388668151b43ce9e18c1973169e67a697cf217eabba8248c2b0d10c5dc03fe0505efeeffb6b6b22b77512e53be8faa67c1983c9ade4885beeee4ddbfe759e5054ba04c4c6bc172a5fffc6524bdbdcbf5e78e831038351def7805c0a70f9d0269540b730a534feb6e6ea59e7898083aac2540555ba69fde6548e34f6dee6d270743881bbe435482ccafce48d2523213856d1772023e259d5c5cf5207459b1017ff5b91420452b823a5f9d75820b8025084dfebe5e17cf7a2f76f7bc830a8713b52c2f2bc6a5352b2122a3aa0f9fa3072dea05a062463d410ab748d89249fef5ff1937269575e2dc2ef5e729cf61f3bb85556f4cc95278d216bf5709751497990bad30075e9d40bedde1bdd69f70f311b6338e18979bd9dbe110e2433b9955b2274a3f615d3b4802e21abaedf8960a919b8887742469f493824b6d8c5e9557550f3e6ce77aed0a99814578c9f31da3e8ae856c3c9c84d16c61128be9311df966799a15590498d9bd47a0e1d37677af92edbf9ba5cb33cf8df282604c344fddb551cafb51fa703da883976b2d0831dd4cc4d69617bc0acc59034226b495a3aa52f9dadce5a1c7b097d09561b78ae19980614ba975853c2a18ae9fdde58e98ad613b387b83eb2f99ea364a3f7ed97decf80e172a80fb517c60b0d296e9a7ce9022419de0cfabc7402f5ce920f219121228e8c5a2aa2f790282e3216e36d2c5e0c1c4d156ffbba78cae25b9a3f1bec13e58ff852ab74125e37ca37f7eb6a175e96ce67a9d6dc514a347f9e62523efaa735ac025b5ced84619f38cb5ab63d50a24e8813d1fa0e145f9a775c6e49f8144f9f649ce51938d966d131deb60241c1959c928ba9eec22dcd811de4d59a0fc00bcbe508120893f0e531281a5e0f91576c2fc85ebab30922815b16711b057c897becea7e398c3ae46e39c6a3c5f68343ec3d3767144443eb72a85b5800460b9d1f2ca150f0ada1f05ece02b54e1620625324ce743578da31f05ee0e8e74c8e6f2d1a3c1079731e9142f3da8868f0e556725e5c14c3da54d532ff26fbbf79d0157ef495339ca515eb5aef7b0b22486fa9c1592465d2bbac1175a1ffef4dd8248c4be789daac82373ee3423e46c9546b7ff3670a107a17cd889710bce1ecbf88259945d6b0e9d40c50c2473626f5b63ec0427adbf7c3ae24b7fff2811c13253363a93e348810481521367a3ce5490191e13df36884867189bcf3cb53f84845b4f0543c18f662e294e384fbdb30803ea3c51e9f5a833906d0afa18719d593fe68bd74a753c4fb268bd030a0bc276a008b6329225969814497c8fc781fde846957f4f891117f386044c98c3a8dd8e25789706421dc754328fc24a8638560f4f67c92d05e268ddd2fefbd897fcd795e17161f441b96bfc31f40c7a6878cf4bf03097be3dc8b2538a25a3741c1ee9c55d6e17f274c3f5979b1d16019aaf930e5ef5fc58553706f8aec602adc87956eac6374350a8a30fcd14f3cccf2c19f985b9c816e0416e82b9ce6c59703c98ef1fbc10e229af30c5bfdea6e9cacc2495f063b977b384862b912dafc10c0208dc502dc3b65dcf7e64372eda9a97096d6166e145f92635d798c20fe7e78ebf410f08478fb58c0d2abbc3773c38609adc4a4a1c5395f2bd08267919fdd0e0c1adb8501e2579152f53924f6fbe6e88525fb95d4e2420b7b51b5cb301fcf7cfada5ad3ae26b8cc05233143c691c4276bd8e51f0cff20386d2af3d79ced8c89b58a08a46d824c009494ea07fa49ae2a2d20ccad66c6b4b3ceb1d0ad776ea6cfe5a69912153435d9dc2ad302c7973c5ab26957cf9ae7260148512aea71f5ce54d295f2b2dc7a9ab91f5d0cbc8b3e8425d94a161b5a585c3d75c32d93a29a8ce5f9456df0056c14ec08116ac75fb09aeb461b68f4f7b1cc1d54bebc09007f6608f7880127000db88d843c42e68195f77751e579c0c1c040b04a97c8b962e0595909face8a2c522bdbded4836b01a6f893604a8742f93fe4e18f7c3cabfd1003b6b9bf83833223ced5f4d299fc160c8037847e3bb33f6414148c1408b9e33f3e42d712cbb32668526409b6a9ad3c92714bd010cc31d2085bca08163047c3632b5094a12a0699456005f9bf04def4cbe1c8b1da49d7e62c158c4416d544c4789382ff94893ad78fb14798f10e23e778fd51b5e0497df9023ee1d51cd64fe91f06bfc0228c08d70d36282cee60f3a56cdd9824b32cb811bcbd9bff2d0a4ac5dbcbdbde5cc16295115e5f0a7f9909d6a2d29b7f62ac0b074abe296fd834db5f1d61bb589e4e6f9ce20c2d20e7388204e0818be015a966d4430100019a52ac191bec8bc202ff16ede7e1e06f447bcf3e5b37fa1ab706cc034363eebeac2a8c32b023729be4a530e91f9d4dadcf3fc1766a88f5d121f77b3692215344fd4d0b6023000000000000000157cd01ec1d034f557752c89dd6443a0e1b99dc327967ae5b940b6312b4754d533b8583d959f3b05b3848dec4078716a8634e4b1f98a45abb38e825a65bac90bad2f0441ef490d02249d39afb3a07c424ae8fd09cbcc063233bb6ad8d358d6fea89c78a46258c5f42d4d8c0119b0f48cdbc87810a701e6a4d1f5f7c8364e715c2ab90b6b3d99db4af2ddc83b2bae0ede7dd0e7e0cadfe594544ad46e5b668ed885643c2c1f45344121cdaa0241d9d89a3f0e630979f813cb9e1b4064f1f9a3d11bddcf43ec484c37c83caf8dbcdb172f47a6aa06fc0076c19759ecbcc2a00db0a8652969e2f9a9e244ca2c7e0b2e9feaf66b547a300ffc2f2cf6611e242259ee97364b127ddacbec8e62d65880e80f4aea73ea5cf130ad8ec8205c6f964d041f89ee4f839f24dcebc6d59975b16a341c43b2cb049c2963b403b5b817a5ce6e9ea3c7eca08047b7587d134d36ae2144c760adfc594aa8459014b7a7dae500d9a17594c4cd47b6b2c7042a903371ea7f78302c4d6c5e1ee565c446f5e5fc836dea484fc533492c7edee2b3613aaf18e73499f06963bd4af00bf62ab562dd8a0e6d88d3c25fb98d7c8c7aca456756f51855612688ef7441a2af10e83bfa7f4faa0dfb232342e8d2c04929abd784e14caef31f5c6be4244baa0b7ad37c805c24b5927445e66069c4fcb94c7e7af0a8f7ab47482a92214cfcda4faa179bdc6965ed37e0094839e647e33e5bb8aae166e5dd7314ae0032378b220b36088dc17742013edf9a2e44dda335f8629820337673dc54897bec0e7299fded570c52a76ce9a17b5d7ab4a9bf3ff17589e1d47fd0873ddbaa73ff89672f4d8cc883db60edfd932bf49b9dee98510261f221cb52d3ec86d9d799af49575e0d8ca95eef91b9d79fdd03e1610fa673721426dee7177d739d8c5e2a3698137c54a432bc12fd151c95b9e4ebe4980eb3b97eb85d8ca3a2daa18abaae28aa7ea228c023418d7d8de52fba74af42cba95ef834b0575d1f9875495c75202bfe7acb5e00c5422193bd38f44a183af9bc8c236466cc25dde157469839d20e7cf0b1d0731a354ebdd88cea0f7820aa59497ffdf39e5436cfc1c30a53da61737426daeb73897a18ee81603d7968b81f1d8d507367d9646658d025e7cc944b52eb35c02bc99a35b12a752083f5a18c648114fdc3ad15237e183ee31ba1795b7e3dea67c2db3d4c60af13f92925d01cd06a9944ccdff1337559e0aaa3ba7010c35475ab9c85e01e2d54b81bd21d4ce054abc7c8a17c2c54933c8fad4120fb9b811e5640a0d137c4bca1a36670a75c48b09e777f3ac733d1d6b2bd268687dd489581133a2fb63bdaaba451100971815a0267840cfe307cc4a1343d71ba5580332dd7d7314f330f0ded8164726310c76318dbaffcb225104dbbab9d6d14ae99fd9225facfb002ce54a14563aba7d94b5915db7f5de8a2a440ab3a0cf189bd39389239fbd157d2f9be9037d2724f830315a6cc6f0b51649576d752453358279bb4c1654c1c8d5eb00bf6f46b6adac1a76ecbd14dbe16d442fd788a6060401470152cd971d2581f1b62698184227e2c204278840a4107ece7422617ab9a3779cd49e3fd4306d64356d7244d8348e7b4360a4d9c89f0014ceb032bf1d626ee5e5158f43e989442a41d09f661f46cddd64569e27506d5bcf9c48dea642133f388fa3499ca8dcd1ec462891419d67d0e51569daefa830906e364926d3a77d22d10865afa2042e41d5ed34c7c8312d59a548b1e6128f3c3e18785c01d40776078441ce4b86830faccedb459fddc880e798af0b548f8138b60104faeac02ba6dcabadd76a253bcd8c80e8155434e9ed0560a65bba31f8767ca31fa6f1430669e789260fb543b72d92e0f1249425a97d4e37c8ad21c5907710bae0fd6d643329a720edf78ee0dc466a462b24cbc2aefd024ff3e028a8be3a5e91d493598182a7d70ae8d91eb86fe1245829c7c07c703261385d204d8bdd51ca8b6679b287130c3ac6add876c2a1e41951df8c408cd643c12af76291f30764e5b9fa00cc165b763ef7bc7dda2c4d911aae02a2dd374bfde18d8cab1b9d1340a38753b8840ec2398aa2028bae2415ba8ed751540c59ea42035b8df7e655f958f50b628f67559d291a76a918fb16f97fb5403647fb1b6550cd2c59a4fbbc9bcd1331931fbe0d966eb1a5c90517cae7a3daf5af37be56e8a17bed91c9411b65cafc5e1889e2627cbd34520e37f2dc4bcc53afc801d984f0e38550284fd0b0341791f8a776fcdb18d60c952c66670bf69e8dc150f11d66d469190b476808b32e4ee6d8db34eb780a5926473cc259a348cac0ce88e01515779bccf978496950f8b15f2fd97274855281e79e3df876043797b705f61031f6b6fa3e2af0eb8b0ace5bfa179335ae76fa402259b29d6c2f4e96c7297af88a6f673d19947be145c4631095f9872852dd97b6f3dbd189b160939f4597d78eddb0831d356919f8894180aa4f6898f4be5a121d819e529e73bb0e9f11e134d3494db0cc17828a291f408fd37cb139685c2c6c91934ce9c378c75e56a92870ced01a851526c833fc8474cf01a32e787ef7665ce10dd3354c49f7cf5f67339b352b8ab8268b583d70cb37887d333cce76f1051e6968138009776abb5d570ec20696cfd360be485b788ace1bf2339fafbf0c46a1240698084c78a6210a7078292858c0d1dd43b2d209b0c006a8cd576480e049bf7ba525a6e90af1ac5b97feb24ce4677f8fe6f35257bb1f0423364c6a48d457a1a6ff6f800da2329c5920f24605b98dd00de63f373f56ba69f34e5220d5f0a6f2ced15c1466eefb0dc5f8450ef63253d45638246fe4a2b82bbe8563411ca580430a699509fdf21331409a0794288e8cef65ed56bb8dcee9700ab9b52819311aa3e97312a1a69f3b21b1f147b3de027a8b092cbe451020799c851e6c4ffd30286143fa4daf70a19888832cc060f36a4c642dad33d4b19ec840adcbbd2adc29aa0aeeb6e4fbf2d9b12a192ec69a0bf49db734b2809f83ae78948f2a718ac4b843b406750e5568ef9b319117ca180ad7d648943b2e6f798ad63acd96ad3269938d1a5f9e380dc9a46da300a28b46def5df9976301dc91c8f5deb0994813aa8d6d926f31a0af09a8b553942452889247a8e42a4fec27f49b3d7f09336af6367d79d44ab1929a674c625c8d11b3855a499b6f02302dd424495ae78b70aef0026cf0fec6d7e7bc321817c7438534c6bcaf699062c2d641b6827737c11ef8bbbf9a5443abcc2c5657affa6a1c30b89de3c991df3ceb858a133ec2685ce37f6c71a98b9954c3831c755e5c5cb2937f531927ea1e73c54151697785b4d04fa9ed1bd67e5894852c052f041ee71aed41633a7bd7d32f4f16ebfede09d7f0f51ac544d87b85db35d6d1e9b02c5d0b6b49f4183e6e3852e5c664fc2a3496fcfdf568dc32e78c27a8d4af55302b6e10a33f2a91c6bfceeaf1ae6cb975fc66b84e2a99393cf7469166a2a23c32db558fd1d9ecaf54a3f0a64fa825575af28407d4a9dcfd9946503b705743c055b28e9e34c88e56487a8f542f049881e42ea62ff42570370a0ca087f63fb893d11b5fa8e65e3452b936304e54b9cc0a6d8a6e361e8bd44893dbbe640efb180e2a9d53e556e562ed1e048c76799cca6f3c8e9d4b4ed6ff290cbe387acf322273cc7037496dbb132f81ac680ffe5107f7b79c949fbc7687f112a9af93e1c95b9df4f0c11726447956456d97b821c75f2dd59cef4077a233a1eb77cb1115007a3a907f2db9e1c20df49af4ba0b902fbf04610cabb993a6aa2d17cb4741a058d70e02374c2b12eeff14a99392a402c353f0d372db3c4f85e212b9afcf9edeab8281053871efaccf65ee8a6ebb51cdf095b7573cd89f05659a707a6697ce047260b84d7cdcd354f7efb6a4cd568c74c352b436b5b1e35c5c51fbe7462f13b266736a927f5860e9bc08e1c90a9c7d743f084d90e5a3691065b82d97daf9948bc724492fbe8efbff965b13dc03f9f6f989f9fd9d82678358c524fcde1e512e003ff698d3dab1e7ffed1714ace403bdce0bd215a78c2f80000").unwrap();
        let tx: Result<LiquidTransaction, _> = deserialize(&tx_bytes);

        assert!(tx.is_ok());
        let tx = tx.unwrap();
        assert_eq!(hex_encode(tx_bytes), hex_encode(serialize(&tx).unwrap()));
        assert_eq!(tx.txid().be_hex_string(), "258208b5f5e3013324ed11f60d834bc136413ca01ed2e92b125848d8c68718d8");



    }

    #[test]
    fn test_block() {

        let block_hex = hex_bytes("0100000000000000000000000000000000000000000000000000000000000000000000000eb17d689e3d7310644dacc37ad46d691782687ab0ee2b6a99355032a459221edae5494d00000000015100020100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2120a530c0e71eac524e367c12af33da41f70ac7d2521f53ccea1ed6d0c910c4cd50ffffffff0101000000000000000000000000000000000000000000000000000000000000000001000000000000000000016a00000000010000000001a530c0e71eac524e367c12af33da41f70ac7d2521f53ccea1ed6d0c910c4cd500000008000ffffffff000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f01000775f05a074000010000000000000000640125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a50000001510125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100001319718a500000015100000000").unwrap();
        let block: Result<LiquidBlock, _> = deserialize(&block_hex);
        assert!(block.is_ok()); //TODO


        let block_hex = hex_bytes("00000020c29a9302232dd62b43d93a8d33719a4acbf9a26c997bfb07c4aa13dbadd17d99ac20a615d9b0d4df3e3ac2cb7018a07bd314d6bb715a57adead7c03e208b365863d27f5b01000000015100010200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000016a0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000266a24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let block: Result<LiquidBlock, _> = deserialize(&block_hex);
        assert!(block.is_ok());

    }

}

