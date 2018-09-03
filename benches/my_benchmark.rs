#[macro_use]
extern crate criterion;

extern crate bitcoin;
extern crate rand;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::serialize::serialize;
use bitcoin::network::serialize::deserialize;
use criterion::Criterion;
use rand::thread_rng;
use rand::Rng;


fn benchmark_serde(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut vec_ser = Vec::new();
    let mut vec_tx = Vec::new();
    for _ in 0..1000 {
        let t : Transaction = rng.gen();
        vec_ser.push(serialize(&t).unwrap() );
        vec_tx.push(t);
    }

    c.bench_function("serialize", move|b| b.iter(|| {
        let t : &Transaction = rng.choose(&vec_tx).unwrap();
        let result = serialize(t).unwrap();
        criterion::black_box(result);
    } ));

    let mut rng = thread_rng();
    c.bench_function("deserialize", move|b| b.iter(|| {
        let bytes : &Vec<u8> = rng.choose(&vec_ser).unwrap();
        let result : Transaction = deserialize(bytes).unwrap();
        criterion::black_box(result);
    } ));

}

criterion_group!{
    name = benches;
    config = Criterion::default();
    //config = Criterion::default().sample_size(2).without_plots();
    targets = benchmark_serde
}

criterion_main!(benches);