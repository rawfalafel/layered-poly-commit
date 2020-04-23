#![feature(try_trait, test)]

extern crate test;
extern crate rand;

#[cfg(test)]
mod tests {
    use layered_poly_commit::layered_poly_commit::LayeredPolyCommit;
    use algebra::Bls12_381;
    use rand::RngCore;
    use num_traits::pow;
    use rand_core::SeedableRng;
    use rand_pcg::Pcg32;
    use test::Bencher;

    type LayeredPolyCommitBls12_381 = LayeredPolyCommit<Bls12_381>;

    #[bench]
    fn bench_large_state(b: &mut Bencher) {
        // # of keys stored = 2^10 = 1024
        // # of keys per layer = 2^5 = 32
        // # of layers = 2^5 = 32
        let num_total_keys = pow(2, 10);
        let num_degree = pow(2, 5);
        let num_poly = pow(2, 6);

        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut rng = Pcg32::from_seed(seed);

        let mut poly_commit = LayeredPolyCommitBls12_381::setup(num_degree, num_poly, &mut rng).unwrap();

        b.iter(|| {
            poly_commit.clear_layers();

            // Insert 2^15 random elements
            for _ in 0..num_total_keys {
                let mut key = vec!{0; 32};
                let mut value = vec!{0; 32};

                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut key);
                rng.fill_bytes(&mut value);

                assert!(poly_commit.insert(&key, &value).is_ok());
            }
        })
    }
}