use layered_poly_commit::{
    layered_poly_commit::LayeredPolyCommit,
    error::Error,
};
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
        assert!(insert(&mut poly_commit, &mut rng, &mut key, &mut value).is_ok());
    }

    println!("fill count by layer");
    for (i, layer) in poly_commit.layers.iter().enumerate() {
        println!("{}: {}", i, layer.fill_count());
    }

    let end_time = Instant::now();

    println!("duration: {:?}", end_time - start_time);

    println!("updating commitment");
    let start_time = Instant::now();
    assert!(poly_commit.update_commitment().is_ok());
    let end_time = Instant::now();

    println!("duration: {:?}", end_time - start_time);
}

fn insert(poly_commit: &mut LayeredPolyCommitBls12_381, rng: &mut Pcg32, key: &mut [u8; 32], value: &mut [u8; 32]) -> Result<(), Error> {
    rng.fill_bytes(key);
    rng.fill_bytes(value);

    let result = poly_commit.insert(key, value);

    // `insert` returns `Error::BytesNotValidFieldElement` if the key/value pair
    // evaluates to a number that's larger than the modulus. Handle this case by
    // calling `insert` against with a new random key/value pair.
    match result {
        Ok(()) => result,
        Err(error) => match error {
            Error::BytesNotValidFieldElement => insert(poly_commit, rng, key, value),
            _ => Err(error)
        }
    }
}