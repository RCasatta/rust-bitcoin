use core::ops::{Add, AddAssign, Mul};
use SerializedLen::*;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
/// TODO
pub enum SerializedLen {
    /// TODO
    Min(usize),

    /// TODO
    Exact(usize),
}

impl SerializedLen {
    pub(crate) fn len(&self) -> usize {
        match self {
            Min(v) => *v,
            Exact(v) => *v,
        }
    }

    pub(crate) fn for_byte_vec(vec: &[u8]) -> Self {
        SerializedLen::Exact( crate::VarInt(vec.len() as u64).len() + vec.len() )
    }
}

impl Add<SerializedLen> for SerializedLen {
    type Output = SerializedLen;

    fn add(self, other: SerializedLen) -> Self::Output {
        match (self, other) {
            (SerializedLen::Min(a), SerializedLen::Min(b)) => SerializedLen::Min(a + b),
            (SerializedLen::Min(a), SerializedLen::Exact(b)) => SerializedLen::Min(a + b),
            (SerializedLen::Exact(a), SerializedLen::Min(b)) => SerializedLen::Min(a + b),
            (SerializedLen::Exact(a), SerializedLen::Exact(b)) => SerializedLen::Exact(a + b),
        }
    }
}

impl AddAssign<SerializedLen> for SerializedLen {
    fn add_assign(&mut self, other: SerializedLen) {
        let r = *self + other;
        *self = r;
    }
}


impl Mul<SerializedLen> for SerializedLen {
    type Output = SerializedLen;

    fn mul(self, other: SerializedLen) -> Self::Output {
        match (self, other) {
            (SerializedLen::Min(a), SerializedLen::Min(b)) => SerializedLen::Min(a * b),
            (SerializedLen::Min(a), SerializedLen::Exact(b)) => SerializedLen::Min(a * b),
            (SerializedLen::Exact(a), SerializedLen::Min(b)) => SerializedLen::Min(a * b),
            (SerializedLen::Exact(a), SerializedLen::Exact(b)) => SerializedLen::Exact(a * b),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::hashes::{Hash, hex::FromHex};

    use crate::{consensus::{Encodable, encode}, Script, SerializedLen, TxOut, TxIn, OutPoint, Txid, Transaction, PackedLockTime, Block, constants::genesis_block, Network};

    #[test]
    fn test_serialized_len_hint() {
        assert_eq!(0u64.serialized_len_hint(), SerializedLen::Exact(8));
        assert_eq!(Script::default().serialized_len_hint(), SerializedLen::Exact(1));
        assert_eq!(Script::from_hex("0000").unwrap().serialized_len_hint(), SerializedLen::Exact(3));

        assert_eq!(TxOut::default().serialized_len_hint(), SerializedLen::Exact(9));

        assert_eq!(0u32.serialized_len_hint(), SerializedLen::Exact(4));
        assert_eq!(Txid::all_zeros().serialized_len_hint(), SerializedLen::Exact(32));
        assert_eq!(OutPoint::default().serialized_len_hint(), SerializedLen::Exact(36));
        assert_eq!(TxIn::default().serialized_len_hint(), SerializedLen::Min(41));

        let tx_out = TxOut::default();
        let vec_tx_out = vec![tx_out.clone(), tx_out];
        assert_eq!(vec_tx_out.serialized_len_hint(), SerializedLen::Min(19));

        let tx1 = Transaction {
            version: 0i32,
            lock_time: PackedLockTime::ZERO,
            input: vec!(),
            output: vec!(),
        };
        assert_eq!(tx1.serialized_len_hint(), SerializedLen::Min(10));
        assert_eq!(Transaction::SERIALIZED_LEN_HINT_SINGLE, SerializedLen::Min(12));

        let tx2 = Transaction {
            version: 0i32,
            lock_time: PackedLockTime::ZERO,
            input: vec!(TxIn::default()),
            output: vec!(),
        };
        assert_eq!(tx2.serialized_len_hint(), SerializedLen::Min(51));

        let tx3 = Transaction {
            version: 0i32,
            lock_time: PackedLockTime::ZERO,
            input: vec!(TxIn::default()),
            output: vec!(TxOut::default()),
        };
        assert_eq!(tx3.serialized_len_hint(), SerializedLen::Min(60));

        assert_eq!(vec![tx1,tx2,tx3].serialized_len_hint(), SerializedLen::Min(1 + 12 * 3 ));

        assert_eq!((Script::from_hex("0000").unwrap(), 0u64).serialized_len_hint(), SerializedLen::Exact(11));

        let genesis_block = genesis_block(Network::Bitcoin);
        assert_eq!(genesis_block.header.serialized_len_hint(), SerializedLen::Exact(80));
        assert_eq!(genesis_block.txdata.len(), 1);
        assert_eq!(genesis_block.serialized_len_hint(), SerializedLen::Min(93));

        let segwit_block = include_bytes!("../test_data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();
        let block: Block = encode::deserialize(&segwit_block).unwrap();
        assert_eq!(block.txdata.len(),15);
        assert_eq!(block.serialized_len_hint(), SerializedLen::Min(80+1+15*12));

    }
}
