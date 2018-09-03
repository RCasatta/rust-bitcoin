#![allow(missing_docs)]

use blockdata::script::Script;
use blockdata::transaction::OutPoint;
use rand::distributions::Distribution;
use rand::distributions::Standard;
use blockdata::transaction::TxIn;
use blockdata::script::Builder;
use blockdata::transaction::TxOut;
use blockdata::transaction::Transaction;

#[test]
fn test_transaction_random () {
    use rand;
    use rand::Rng;
    let a : Transaction =  rand::thread_rng().gen();
    println!("{:?}",a);
}

impl Distribution<OutPoint> for Standard {
    fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> OutPoint {
        OutPoint {
            txid: rng.gen(),
            vout: rng.gen(),   //TODO generate particular case more frequently
        }
    }
}

impl Distribution<TxIn> for Standard {
    fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> TxIn {
        let witness : Vec<Vec<u8>> = Vec::new();
        TxIn {
            previous_output: rng.gen(),
            script_sig: rng.gen(),
            sequence: rng.gen(),
            witness,
        }
    }
}


impl Distribution<Script> for Standard {
    fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> Script {
        Builder::new().push_scriptint(rng.gen() ).into_script()
    }
}

impl Distribution<TxOut> for Standard {
    fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> TxOut {
        TxOut {
            value : rng.gen(),
            script_pubkey: rng.gen(),
        }
    }
}

impl Distribution<Transaction> for Standard {
    fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> Transaction {
        let ntxin  = rng.gen_range(1,10);
        let ntxout = rng.gen_range(1,10);
        let mut txin : Vec<TxIn> = Vec::with_capacity(ntxin);
        let mut txout : Vec<TxOut> = Vec::with_capacity(ntxout);
        for _ in 0..ntxin {
            txin.push(rng.gen());
        }
        for _ in 0..ntxout {
            txout.push(rng.gen());
        }

        Transaction {
            version: rng.gen(),
            lock_time: rng.gen(),
            input: txin,
            output: txout,
        }
    }
}