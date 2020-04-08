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

struct Polynomial<E: PairingEngine> {
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
                return Err(format!{"{:?}", params.unwrap()});
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

    fn bytes_to_usize(&self, value: &[u8]) -> Result<usize, String> {
        let p = <E::Fr as PrimeField>::from_random_bytes(value);

        if p.is_none() {
            return Err(String::from("Unable to convert to PrimeField"));
        }

        let mut p_u32 = [0; 32];
        p.unwrap().to_bytes(&mut p_u32);

        let p_u32 = BigInt::from_bytes_le(Sign::Plus, &p_u32);

        Ok((p_u32 % self.num_degrees).to_usize().unwrap())
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
            let output_mod = BigInt::from_bytes_le(Sign::Plus, &digest) % self.num_degrees;
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
    pub fn update_commitment(&mut self) -> Result<(), String> {
        for p in self.polynomials.iter_mut() {
            if p.points.len() == 0 {
                break;
            }

            if !p.dirty {
                continue;
            }

            let mut polynomial = vec![E::Fr::zero(); self.num_degrees];
            for (x, y) in p.points.iter() {
                polynomial[*x] = *y;
            }

            let polynomial = DensePolynomial::from_coefficients_vec(polynomial);

            let powers = Powers::<E> {
                powers_of_g: Cow::Owned(p.params.powers_of_g.to_vec()),
                powers_of_gamma_g: Cow::Owned(p.params.powers_of_gamma_g.to_vec())
            };

            let result = KZG10::commit(&powers, &polynomial, None, None);
            if result.is_err() {
                return Err(format!("{:?}", result.err()));
            }

            let commitment: Commitment<E> = result.unwrap().0;

            p.commitment = Some(commitment);
            p.dirty = false;
        }

        Ok(())
    }

    pub fn get_commitment(&self, index: usize) -> Result<Option<Commitment<E>>, String> {
        if index >= self.polynomials.len() {
            return Err(String::from("index out of range"));
        }

        Ok(self.polynomials[index].commitment)
    }

    pub fn get_powers(&self, index: usize) -> Result<Powers<E>, String> {
        if index >= self.polynomials.len() {
            return Err(String::from("index out of range"));
        }

        let p = &self.polynomials[index];
        Ok(Powers::<E> {
            powers_of_g: Cow::Owned(p.params.powers_of_g.to_vec()),
            powers_of_gamma_g: Cow::Owned(p.params.powers_of_gamma_g.to_vec())
        })
    }

    // -> open
    // Generate a witness for a given set of key/value pairs.
    pub fn open(&self, p: E::Fr) -> Result<(), String> {
        // `p` shoud be received as `E::Fr`. The point doesn't have to correspond to [0, n)

        // Iterate over polynomials. Find polynomial for which p exists.

        // Call KZG10::open

        Ok(())
    }

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
    use algebra_core::curves::PairingEngine;
    use algebra_core::fields::PrimeField;
    use crypto::sha3::Sha3;
    use crypto::digest::Digest;
    use rand_core::SeedableRng;
    use rand_pcg::Pcg32;
    use num_bigint::{BigInt,Sign};

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
        let mut hashmap = setup(1, 1).unwrap();

        let k = [100];
        let v = [100];
        let result = hashmap.insert(&k, &v);
        assert!(result.is_ok());

        let result = hashmap.insert(&k, &v);
        assert!(result.is_err());
    }

    #[test]
    fn test_modulus() {
        let mut hasher = Sha3::sha3_256();
        let mut digest = vec!{0; 32};

        hasher.input(&[19, 19]);
        hasher.result(&mut digest);

        let num_bi = BigInt::from_bytes_le(Sign::Plus, &digest);
        let num_field = <<Bls12_381 as PairingEngine>::Fr as PrimeField>::from_random_bytes(&digest).unwrap();

        println!("num_bi: {:?}", num_bi);
        println!("num_field: {:?}", num_field);

        let num_u64: [u64; 4] = (num_field.0).0;
        println!("num_u64: {:?}", num_u64);

        let mut num_u32 = vec!{};
        for n in &num_u64 {
            num_u32.push((0xffffffff & n) as u32);
            num_u32.push((n >> 32) as u32);
        }

        println!("num_u32: {:?}", num_u32);
    }

    #[test]
    fn test_bytes_to_point() {
        let input = [0xf; 32];

        let hashmap = setup(100, 3).unwrap();

        let result = hashmap.bytes_to_usize(&input);
        assert!(result.is_ok());

        let point = result.unwrap();
        assert!(point < 100);
    }

    #[test]
    fn test_commitment() {
        let mut hashmap = setup(100, 3).unwrap();

        assert!(hashmap.polynomials[0].commitment.is_none());

        // Insert initial set of points
        assert!(hashmap.insert(&[1], &[1]).is_ok());
        assert!(hashmap.insert(&[2], &[2]).is_ok());
        assert!(hashmap.insert(&[3], &[3]).is_ok());

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.err().unwrap());

        assert!(hashmap.polynomials[0].commitment.is_some());

        let result = hashmap.get_commitment(0);
        assert!(result.is_ok());

        let c1 = result.unwrap().unwrap();

        // Add an additional point
        assert!(hashmap.insert(&[4], &[4]).is_ok());

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.err().unwrap());

        let result = hashmap.get_commitment(0);
        assert!(result.is_ok());

        let c2 = result.unwrap().unwrap();

        // Assert that a new commitment was grenerated.
        assert_ne!(c1, c2);

        // Check that the commitment is unchanged when an existing k/v pair is inserted.
        assert!(hashmap.insert(&[1], &[1]).is_ok());

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.err().unwrap());

        let c3 = hashmap.get_commitment(0).unwrap().unwrap();

        assert_eq!(c2, c3);
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
