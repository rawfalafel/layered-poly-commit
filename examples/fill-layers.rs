use layered_poly_commit::layered_poly_commit::LayeredPolyCommit;
use algebra::Bls12_381;
use rand::RngCore;
use num_traits::pow;
use rand_core::SeedableRng;
use rand_pcg::Pcg32;

use std::time::Instant;

type LayeredPolyCommitBls12_381 = LayeredPolyCommit<Bls12_381>;

fn main() {
    let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut rng = Pcg32::from_seed(seed);
    /*
    // # of keys stored = 2^20 = 1048576
    // # of keys per layer = 2^15 = 32768
    // # of layers = 2^6 = 64
    let num_total_keys = pow(2, 20);
    let num_degree = pow(2, 15);
    let num_poly = pow(2, 10);
    */

    // # of keys stored = 2^14 = 16384
    // # of keys per layer = 2^11 = 2048
    // # of layers = 2^6 = 64
    let num_total_keys = pow(2, 14);
    let num_degree = pow(2, 10);
    let num_poly = pow(2, 5);

    let mut poly_commit = LayeredPolyCommitBls12_381::setup(num_degree, num_poly, &mut rng).unwrap();
    let mut key = [0; 32];
    let mut value = [0; 32];

    let start_time = Instant::now();

    for _ in 0..num_total_keys {
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut value);

        assert!(poly_commit.insert(&key, &value).is_ok());
    }

    println!("fill count by layer");
    for (i, layer) in poly_commit.layers.iter().enumerate() {
        println!("{}: {}", i, layer.fill_count());
    }

    let end_time = Instant::now();

    println!("duration: {:?}", end_time - start_time);
}