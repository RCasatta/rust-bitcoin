use consensus::{Decodable, Encodable, WriteExt};
use VarInt;
use std::io::{Read, Write};
use consensus::encode::Error;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Witness {

    /// contains the witness Vec<Vec<u8>> serialization without the initial varint indicating the
    /// number of elements (which is stored in len)
    content: Vec<u8>,

    /// number of elements in the witness
    len: u64,

    //TODO? consider having the number of witness elements and the len of the content used (both u32),
    // this would allow to avoid some allocations during push
}

pub struct WitnessIterator<'a> {
    witness: &'a Witness,
    cursor: usize,
}

impl From<Vec<Vec<u8>>>  for Witness {
    fn from(vec: Vec<Vec<u8>>) -> Self {
        let len = vec.len() as u64;
        let content = crate::consensus::serialize(&vec);
        let index = VarInt(len).len();
        Witness {
            len,
            content: content[index..].to_vec()
        }
    }
}

impl Decodable for Witness {
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        let witness_elements = VarInt::consensus_decode(&mut d)?;
        if witness_elements.0 == 0 {
            Ok(Witness::default())
        } else {
            let mut cursor = 0;
            let len = witness_elements.0;

            // this number should be determined as high enough to cover most witness, and low enough
            // to avoid wasting space without reallocating
            let mut content = vec![0u8; 128];

            for _ in 0..witness_elements.0 {
                let element_size = VarInt::consensus_decode(&mut d)?;
                resize_if_needed(&mut content, cursor, element_size.len());
                element_size.consensus_encode(&mut content[cursor..cursor+element_size.len()])?;
                cursor += element_size.len();
                let element_size = element_size.0 as usize;
                resize_if_needed(&mut content, cursor, element_size);
                d.read_exact(&mut content[cursor..cursor+element_size])?;
                cursor += element_size;
            }
            content.truncate(cursor);
            Ok(Witness {content, len})
        }
    }
}

fn resize_if_needed(vec: &mut Vec<u8>, cursor: usize, increment: usize) {
    if cursor + increment > vec.len() {
        vec.resize(vec.len()*2, 0);
    }
}

impl Encodable for Witness {
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let len = VarInt(self.len);
        len.consensus_encode(&mut writer)?;
        writer.emit_slice(&self.content[..])?;
        Ok(self.content.len() + len.len())
    }
}

impl Witness {
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> WitnessIterator {
        WitnessIterator {
            witness: &self,
            cursor: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn clear(&mut self) {
        self.content.clear();
        self.len = 0;
    }

    pub fn push(&mut self, el: &[u8]) {
        self.len += 1;
        let el_len = VarInt(el.len() as u64);
        let cursor = self.content.len();
        self.content.resize(self.content.len() + el_len.len() + el.len(), 0);
        let end = cursor + el_len.len();
        el_len.consensus_encode(&mut self.content[cursor..end]).unwrap();
        self.content[end..].copy_from_slice(el);
    }
}

impl Default for Witness {
    fn default() -> Self {
        // from https://doc.rust-lang.org/std/vec/struct.Vec.html#method.new
        // The vector will not allocate until elements are pushed onto it.
        Witness {
            content: Vec::new(),
            len: 0,
        }
    }
}

impl<'a> Iterator for WitnessIterator<'a> {
    type Item = &'a[u8];

    fn next(&mut self) -> Option<Self::Item> {
        let vec = &self.witness.content;
        if self.cursor >= vec.len() {
            None
        } else {
            let var = VarInt::consensus_decode(&vec[self.cursor..]).unwrap();
            let start = self.cursor + var.len();
            let end = start + var.0 as usize;
            self.cursor = end;
            Some(&vec[start..end])
        }
    }
}

#[cfg(test)]
mod test {
    use hashes::hex::{FromHex, ToHex};
    use crate::consensus::{serialize, deserialize};
    use blockdata::witness::Witness;
    use Transaction;

    #[test]
    fn test_push() {
        let mut witness = Witness::default();
        witness.push(&vec![0u8]);
        let expected = Witness {
            len: 1,
            content: vec![1u8,0],
        };
        assert_eq!(witness, expected);
        witness.push(&vec![2u8,3u8]);
        let expected = Witness {
            len: 2,
            content: vec![1u8,0,2,2,3],
        };
        assert_eq!(witness, expected);
    }

    #[test]
    fn test_witness() {
        let w0 = Vec::from_hex("03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105").unwrap();
        let w1 = Vec::from_hex("000000").unwrap();
        let witness_vec = vec![w0, w1];
        let witness_serialized: Vec<u8> = serialize(&witness_vec);
        let witness = Witness {
            content: witness_serialized[1..].to_vec(),
            len: 2,
        };
        for (i,el) in witness.iter().enumerate() {
            assert_eq!(witness_vec[i], el);
        }

        let w_into: Witness = witness_vec.into();
        assert_eq!(w_into, witness);

        assert_eq!(witness_serialized, serialize(&witness));

        assert_eq!(32, std::mem::size_of::<Witness>());

        assert_eq!(24, std::mem::size_of::<Option<Vec<u8>>>());
    }

    #[test]
    fn test_tx() {
        let s = "02000000000102b44f26b275b8ad7b81146ba3dbecd081f9c1ea0dc05b97516f56045cfcd3df030100000000ffffffff1cb4749ae827c0b75f3d0a31e63efc8c71b47b5e3634a4c698cd53661cab09170100000000ffffffff020b3a0500000000001976a9143ea74de92762212c96f4dd66c4d72a4deb20b75788ac630500000000000016001493a8dfd1f0b6a600ab01df52b138cda0b82bb7080248304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c0121026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e950247304402203ef00489a0d549114977df2820fab02df75bebb374f5eee9e615107121658cfa02204751f2d1784f8e841bff6d3bcf2396af2f1a5537c0e4397224873fbd3bfbe9cf012102ae6aa498ce2dd204e9180e71b4fb1260fe3d1a95c8025b34e56a9adf5f278af200000000";
        let tx_bytes = Vec::from_hex(s).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let expected_wit = ["304502210084622878c94f4c356ce49c8e33a063ec90f6ee9c0208540888cfab056cd1fca9022014e8dbfdfa46d318c6887afd92dcfa54510e057565e091d64d2ee3a66488f82c01", "026e181ffb98ebfe5a64c983073398ea4bcd1548e7b971b4c175346a25a1c12e95"];
        for (i,wit_el) in tx.input[0].witness.iter().enumerate() {
            assert_eq!(expected_wit[i], wit_el.to_hex());
        }
        let tx_bytes_back = serialize(&tx);
        assert_eq!(tx_bytes_back, tx_bytes);

    }
}