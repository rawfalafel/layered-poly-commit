use algebra_core::{PairingEngine};
use algebra::PrimeField;
use crypto::sha3::Sha3;
use crypto::digest::Digest;
use ff_fft::polynomial::DensePolynomial;
use num_bigint::{BigInt,Sign};
use num_traits::{ToPrimitive,Zero};
use poly_commit::kzg10::{KZG10, Commitment, Powers, UniversalParams};
use rand_core::RngCore;
use std::borrow::Cow;

const NUM_DEGREES: usize = 16777216; // 2^24

pub struct Polynomial<E: PairingEngine> {
    params: UniversalParams<E>,
    points: Vec<(usize, E::Fr)>,
    commitment: Option<Commitment<E>>,
    dirty: bool
}

impl <E: PairingEngine> Polynomial<E> {
    pub fn new(params: UniversalParams<E>, points: Vec<(usize, E::Fr)>) -> Polynomial<E> {
        Polynomial {
            params: params, 
            points: points,
            commitment: None,
            dirty: false
        }
    }
}

pub struct PolyHashMap<E: PairingEngine> {
    polynomials: Vec<Polynomial<E>>,
    num_degrees: usize
}

impl<E: PairingEngine> PolyHashMap<E> {
    // -> setup
    // Generate a vector of polynomials of degree n.
    pub fn setup<R: RngCore>(max_degree: usize, num_poly: usize, rng: &mut R) -> Result<PolyHashMap<E>, String> {
        let mut polynomials = vec!{};

        for _ in 0..num_poly {
            let params = KZG10::setup(max_degree, false, rng);
            if params.is_err() {
                return Err(format!{"{:?}", params.err().unwrap()});
            }

            let params = params.ok();
            if params.is_none() {
                return Err(String::from("Setup failed to generate parameters"));
            }

            let polynomial = Polynomial::new(params.unwrap(), vec!{});
            polynomials.push(polynomial);
        }

        Ok(PolyHashMap{
            polynomials: polynomials,
            num_degrees: max_degree
        })
    }

    // `insert` updates the first polynomial for which `hash(k, i) % n` is empty.
    // Inserts `hash(k, v)` as the value.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
        // TODO: Test if a single hasher should be instantiated for a single PolyHashMap instance.
        let mut hasher = Sha3::sha3_256();
        let mut digest = vec!{0; 32};

        // Find the first polynomial in which `hash(k, i)` is empty
        for (i, polynomial) in self.polynomials.iter_mut().enumerate() {

            // `output` is the digest for `hash(k, i)`
            hasher.reset();
            hasher.input(key);
            hasher.input(&[i as u8]);
            hasher.result(&mut digest);

            // Convert the digest to `hash(k, i) % n`
            let output_mod = BigInt::from_bytes_le(Sign::Plus, &digest) % NUM_DEGREES;
            let poly_x = output_mod.to_usize().unwrap();

            reset_digest(&mut digest);

            let result = polynomial.points.binary_search_by_key(&poly_x, |&(idx,_)| idx);
            
            // Key not found. Insert key into vector.
            if result.is_err() {
                let insertion_idx = result.err().unwrap();

                // `output` is the digest for `hash(k, v)` 
                hasher.reset();
                hasher.input(key);
                hasher.input(value);
                hasher.result(&mut digest);

                // TODO: Check if conversion to E::Fr truncates numbers.
                let poly_y = E::Fr::from_random_bytes(&digest).unwrap();

                reset_digest(&mut digest);

                // See: https://github.com/scipr-lab/zexe/blob/19489db9209cd79e1261370b0b2393b2f1d8c64f/algebra/src/bls12_381/fields/fr.rs#L14
                polynomial.points.insert(insertion_idx, (poly_x, poly_y));
                polynomial.dirty = true;
                return Ok(());
            }
        }

        return Err(String::from("Failed to find an empty polynomial."));
    }

    // -> update_commitment
    // Update commitment for polynomials since last UpdateCommitment call.
    pub fn update_commitment(self) -> Result<(), String>{
        for mut p in self.polynomials {
            if p.points.len() == 0 {
                break;
            }

            if !p.dirty {
                continue;
            }

            let mut polynomial = vec![E::Fr::zero(); self.num_degrees];
            for (x, y) in p.points {
                polynomial[x] = y;
            }

            let polynomial = DensePolynomial::from_coefficients_vec(polynomial);

            let powers = Powers::<E> {
                powers_of_g: Cow::Owned(p.params.powers_of_g),
                powers_of_gamma_g: Cow::Owned(p.params.powers_of_gamma_g)
            };
            
            let result = KZG10::commit(&powers, &polynomial, None, None);
            if result.is_err() {
                return Err(format!("{:?}", result.err().unwrap()));
            }

            let commitment: Commitment<E> = result.ok().unwrap().0;
            p.commitment = Some(commitment);
            p.dirty = false;
        }

        Ok(())
    }

    // -> open
    // Generate a witness for a given set of key/value pairs.

    // -> verify
    // Verify that a given witness is valid.
}

fn reset_digest(digest: &mut [u8]) {
    for v in digest.iter_mut() {
        *v = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::PolyHashMap;

    use algebra::Bls12_381;
    use crypto::sha3::Sha3;
    use crypto::digest::Digest;
    use rand_core::SeedableRng;
    use rand_pcg::Pcg32;

    type PolyHashMapBls12_381 = PolyHashMap<Bls12_381>;

    fn setup(max_degree: usize, num_poly: usize) -> Result<PolyHashMapBls12_381, String> {
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut rng = Pcg32::from_seed(seed);
        PolyHashMapBls12_381::setup(max_degree, num_poly, &mut rng)
    }

    #[test]
    fn test_setup() {
        let result = setup(5, 5);

        assert!(result.is_ok());
        assert!(result.ok().is_some());
    }

    #[test]
    fn test_duplicate() {
        let mut hashmap = setup(1, 1).ok().unwrap();

        let k = [100];
        let v = [100];
        let result = hashmap.insert(&k, &v);
        assert!(result.is_ok());

        let result = hashmap.insert(&k, &v);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash() {
        let mut hasher = Sha3::sha3_256();

        let mut output1 = vec!{0; 256};
        hasher.input(&[100, 100]);
        hasher.result(&mut output1);

        let mut output2 = vec!{0; 256};
        hasher.reset();
        hasher.input(&[100, 100]);
        hasher.result(&mut output2);

        assert_eq!(output1, output2);

        let mut output3 = vec!{0; 256};
        hasher.reset();
        hasher.input(&[100]);
        hasher.input(&[100]);
        hasher.result(&mut output3);

        assert_eq!(output2, output3);

        let mut output4 = vec!{0; 256};
        hasher.reset();
        hasher.input(&[100]);
        hasher.result(&mut output4);

        assert_ne!(output1, output4);

        for v in output2.iter_mut() {
            *v = 0;
        }
        hasher.reset();
        hasher.input(&[100, 100]);
        hasher.result(&mut output2);
    }
}
