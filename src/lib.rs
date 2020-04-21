#![feature(try_trait)]

use algebra::Field;
use algebra_core::bytes::ToBytes;
use algebra_core::curves::PairingEngine;
use algebra_core::fields::PrimeField;
use crypto::sha3::Sha3;
use crypto::digest::Digest;
use ff_fft::domain::EvaluationDomain;
use ff_fft::evaluations::Evaluations;
use ff_fft::polynomial::DensePolynomial;
use num_bigint::{BigInt,Sign};
use num_traits::{ToPrimitive,Zero};
use poly_commit::PCRandomness;
use poly_commit::kzg10::{KZG10, Randomness, Commitment, Proof, Powers, UniversalParams, VerifierKey};
use poly_commit::error::Error as PolyCommitError;
use rand_core::RngCore;
use std::borrow::Cow;
use std::io::Error as IOError;
use std::option::NoneError;

#[derive(Debug)]
struct Polynomial<E: PairingEngine> {
    params: UniversalParams<E>,
    verifier_key: VerifierKey<E>,
    evaluations: Evaluations<E::Fr>,
    coefficients: Option<DensePolynomial<E::Fr>>,
    commitment: Option<Commitment<E>>,
    dirty: bool
}

impl <E: PairingEngine> Polynomial<E> {
    pub fn new(params: UniversalParams<E>, num_coeffs: usize) -> Result<Polynomial<E>, Error> {
        let domain = EvaluationDomain::new(num_coeffs)?;
        let evaluations = Evaluations::from_vec_and_domain(vec!{}, domain);

        let vk = VerifierKey {
            g: params.powers_of_g[0],
            gamma_g: params.powers_of_gamma_g[0],
            h: params.h,
            beta_h: params.beta_h,
            prepared_h: params.prepared_h.clone(),
            prepared_beta_h: params.prepared_beta_h.clone(),
        };

        Ok(Polynomial {
            params: params,
            verifier_key: vk,
            evaluations: evaluations,
            coefficients: None,
            commitment: None,
            dirty: false
        })
    }
}

#[derive(Debug)]
pub struct PolyHashMap<E: PairingEngine> {
    polynomials: Vec<Polynomial<E>>,
    num_degrees: usize
}

#[derive(Debug)]
pub enum Error {
    PolyCommitError(PolyCommitError),
    IOError(IOError),
    NoneError(NoneError),
    Default(String)
}

impl From<NoneError> for Error {
    fn from(e: NoneError) -> Error {
        Error::NoneError(e)
    }
}

impl From<IOError> for Error {
    fn from(e: IOError) -> Error {
        Error::IOError(e)
    }
}

impl From<PolyCommitError> for Error {
    fn from(e: PolyCommitError) -> Error {
        Error::PolyCommitError(e)
    }
}

impl<E: PairingEngine> PolyHashMap<E> {
    // -> setup
    // Generate a vector of polynomials of degree n.
    pub fn setup<R: RngCore>(max_degree: usize, num_poly: usize, rng: &mut R) -> Result<PolyHashMap<E>, Error> {
        let polynomials = (0..num_poly).map(|_| {
            let params = KZG10::setup(max_degree, false, rng)?;
            Polynomial::new(params, max_degree)
        }).collect::<Result<Vec<Polynomial<E>>, Error>>()?;

        Ok(PolyHashMap{
            polynomials: polynomials,
            num_degrees: max_degree
        })
    }

    fn bytes_to_mod_degrees(&self, value: &[u8]) -> Result<BigInt, Error> {
        // Note: `from_random_bytes` multiplies the integer representation of the raw bytes by `Fr::R`
        let p = <E::Fr>::from_random_bytes(value)?;

        let mut p_u32 = vec!{0; 32};
        p.write(&mut p_u32)?;

        let p_u32 = BigInt::from_bytes_le(Sign::Plus, &p_u32);

        Ok(p_u32 % self.num_degrees)
    }

    fn bytes_to_usize(&self, value: &[u8]) -> Result<usize, Error> {
        let bytes_usize = self.bytes_to_mod_degrees(value)?.to_usize()?;
        Ok(bytes_usize)
    }

    fn bytes_to_fr(&self, value: &[u8]) -> Result<E::Fr, Error> {
        let bi = self.bytes_to_mod_degrees(value)?;

        let bi_bytes = bi.to_bytes_le().1;
        let field = <E::Fr>::from_random_bytes(&bi_bytes)?;
        Ok(field)
    }

    // `insert` updates the first polynomial for which `hash(k, i) % n` is empty.
    // Inserts `hash(k, v)` as the value.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
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
            let poly_x = output_mod.to_usize()?;

            reset_digest(&mut digest);

            // Key not found. Insert key into vector.
            if polynomial.evaluations[poly_x] == E::Fr::zero() {
                // `output` is the digest for `hash(k, v)`
                hasher.reset();
                hasher.input(key);
                hasher.input(value);
                hasher.result(&mut digest);

                let poly_y = <E::Fr>::from_random_bytes(&digest).unwrap();

                reset_digest(&mut digest);

                // See: https://github.com/scipr-lab/zexe/blob/19489db9209cd79e1261370b0b2393b2f1d8c64f/algebra/src/bls12_381/fields/fr.rs#L14
                polynomial.evaluations.evals[poly_x] = poly_y;
                polynomial.dirty = true;
                return Ok(());
            }
        }

        Err(Error::Default(String::from("Failed to find an empty polynomial.")))
    }

    // -> update_commitment
    // Update commitment for polynomials since last UpdateCommitment call.
    pub fn update_commitment(&mut self) -> Result<(), Error> {
        let mut updates = vec!{};

        for (i, p) in self.polynomials.iter().enumerate() {
            if p.evaluations.evals.len() == 0 {
                break;
            }

            if !p.dirty {
                continue;
            }

            let polynomial = self.construct_dense_polynomial(i)?;
            let powers = self.get_powers(i)?;

            let result = KZG10::commit(&powers, &polynomial, None, None)?;

            let commitment: Commitment<E> = result.0;
            updates.push((i, polynomial, Some(commitment)));
        }

        for (i, polynomial, commitment) in updates {
            self.polynomials[i].commitment = commitment;
            self.polynomials[i].coefficients = Some(polynomial);
            self.polynomials[i].dirty = false;
        }

        Ok(())
    }

    fn construct_dense_polynomial(&self, index: usize) -> Result<DensePolynomial<E::Fr>, Error> {
        if index >= self.polynomials.len() {
            return Err(Error::Default(String::from("Index out of range")));
        }

        // TODO: Experiment with `interpolate` over `inerpolate_by_ref`
        Ok(self.polynomials[index].evaluations.interpolate_by_ref())
    }

    pub fn get_commitment(&self, index: usize) -> Result<Commitment<E>, Error> {
        if index >= self.polynomials.len() {
            return Err(Error::Default(String::from("Index out of range")))
        }

        if self.polynomials[index].commitment.is_none() {
            return Err(Error::Default(String::from("Commitment does not exist")))
        }

        Ok(self.polynomials[index].commitment.unwrap())
    }

    fn get_coefficients(&self, index: usize) -> Result<&DensePolynomial<E::Fr>, Error> {
        Ok(self.polynomials[index].coefficients.as_ref()?)
    }

    pub fn get_powers(&self, index: usize) -> Result<Powers<E>, Error> {
        if index >= self.polynomials.len() {
            return Err(Error::Default(String::from("Index out of range")))
        }

        let p = &self.polynomials[index];
        Ok(Powers::<E> {
            powers_of_g: Cow::Owned(p.params.powers_of_g.to_vec()),
            powers_of_gamma_g: Cow::Owned(p.params.powers_of_gamma_g.to_vec())
        })
    }

    // -> open
    // Generate a witness for a given key
    pub fn open(&self, k: &[u8]) -> Result<Proof<E>, Error> {
        // Iterate over polynomials. Find polynomial for which p exists.
        let mut hasher = Sha3::sha3_256();
        let mut digest = [0; 32];

        for (i, polynomial) in self.polynomials.iter().enumerate() {
            hasher.input(k);
            hasher.input(&[i as u8]);
            hasher.result(&mut digest);

            reset_digest(&mut digest);

            let point = self.bytes_to_usize(&digest)?;
            if polynomial.evaluations.evals[point] == E::Fr::zero() {
                continue;
            }

            if polynomial.dirty == true {
                return Err(Error::Default(String::from("Commitment is not up to date.")));
            }

            let powers = self.get_powers(i)?;
            let polynomial = self.get_coefficients(i)?;
            let point = self.bytes_to_fr(&digest)?;
            let rand = Randomness::<E>::empty();

            return Ok(KZG10::open(&powers, &polynomial, point, &rand)?);
        }

        Err(Error::Default(String::from("Key not found")))
    }

    // -> verify
    // Verify that a given witness is valid.
    pub fn verify(&self, k: &[u8], v: &[u8], proof: Proof<E>) -> Result<bool, Error> {
        let mut hasher = Sha3::sha3_256();
        let mut digest = [0; 32];

        for (i, polynomial) in self.polynomials.iter().enumerate() {
            // TODO: Dedupe logic shared with open
            hasher.input(k);
            hasher.input(&[i as u8]);
            hasher.result(&mut digest);

            reset_digest(&mut digest);

            let point = self.bytes_to_usize(&digest)?;
            if polynomial.evaluations.evals[point] == E::Fr::zero() {
                continue;
            }

            if polynomial.dirty || polynomial.commitment.is_none() {
                return Err(Error::Default(String::from("Commitment is not up to date.")));
            }

            // `output` is the digest for `hash(k, v)`
            hasher.reset();
            hasher.input(k);
            hasher.input(v);
            hasher.result(&mut digest);

            let root_of_unity = <E::Fr>::root_of_unity();
            let point = root_of_unity.pow(&[point as u64]);

            let vk = &polynomial.verifier_key;
            let commitment = polynomial.commitment.unwrap();
            let poly_y = <E::Fr>::from_random_bytes(&digest).unwrap();

            return Ok(KZG10::check(vk, &commitment, point, poly_y, &proof)?);
        }

        Err(Error::Default(String::from("Key not found")))
    }
}

fn reset_digest(digest: &mut [u8]) {
    for v in digest.iter_mut() {
        *v = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{PolyHashMap,Error};

    use algebra::Bls12_381;
    use algebra::bls12_381::Fr;
    use algebra_core::curves::PairingEngine;
    use algebra_core::fields::{FpParameters, Field, PrimeField};
    use crypto::sha3::Sha3;
    use crypto::digest::Digest;
    use ff_fft::domain::EvaluationDomain;
    use ff_fft::evaluations::Evaluations;
    use num_traits::pow;
    use num_traits::identities::One;
    use rand_core::SeedableRng;
    use rand_pcg::Pcg32;
    use num_bigint::{BigInt,Sign};

    type PolyHashMapBls12_381 = PolyHashMap<Bls12_381>;

    fn setup(max_degree: usize, num_poly: usize) -> Result<PolyHashMapBls12_381, Error> {
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut rng = Pcg32::from_seed(seed);
        PolyHashMapBls12_381::setup(max_degree, num_poly, &mut rng)
    }

    #[test]
    fn test_setup() {
        let result = setup(5, 5);

        assert!(result.is_ok(), result.unwrap_err());
    }

    #[test]
    fn test_duplicate() {
        let mut hashmap = setup(1, 1).unwrap();

        let k = [100];
        let v = [100];
        let result = hashmap.insert(&k, &v);
        assert!(result.is_ok(), result.unwrap_err());

        let result = hashmap.insert(&k, &v);
        assert!(result.is_err(), result.unwrap());
    }

    #[test]
    fn test_modulus() {
        let mut hasher = Sha3::sha3_256();
        let mut digest = vec!{0; 32};

        hasher.input(&[19, 19]);
        hasher.result(&mut digest);

        let num_bi = BigInt::from_bytes_le(Sign::Plus, &digest);
        let num_field = <<Bls12_381 as PairingEngine>::Fr as Field>::from_random_bytes(&digest).unwrap();

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
    fn test_simple_commitment() {
        // Setup
        let mut hashmap = setup(128, 3).unwrap();

        // Insert three key/value pairs
        assert!(hashmap.insert(&[1], &[1]).is_ok());
        assert!(hashmap.insert(&[2], &[2]).is_ok());
        assert!(hashmap.insert(&[3], &[3]).is_ok());

        // Generate commitment
        assert!(hashmap.update_commitment().is_ok());

        // Open witness
        let result = hashmap.open(&[1]);
        assert!(result.is_ok());

        let proof = result.unwrap();

        // Verify
        assert!(hashmap.verify(&[1], &[2], proof).is_ok());

        assert!(hashmap.verify(&[1], &[3], proof).is_err());

        // TODO: Verify the proof works for the given key/value pair, and not others.
    }

    #[test]
    fn test_ifft() {
        let log_degree_size = 5;
        let num_degrees = pow(2, log_degree_size);

        let domain = EvaluationDomain::<Fr>::new(num_degrees).unwrap();
        let mut evaluations = Evaluations::from_vec_and_domain(vec!{}, domain);

        let mut hasher = Sha3::sha3_256();
        let mut digest = vec!{0; 32};

        for i in 0..num_degrees {
            hasher.input(&[i as u8]);
            hasher.result(&mut digest);
            hasher.reset();

            let k = Fr::from_random_bytes(&digest).unwrap();
            evaluations.evals.push(k);
        }

        let polynomial = evaluations.interpolate_by_ref();
        println!("{:?}", polynomial);

        // Assert that the evaluation for 0th power of the root of unity is correct.
        assert_eq!(evaluations.evals[0], polynomial.evaluate(Fr::one()));

        let mut root_of_unity = Fr::root_of_unity();
        let two_adicity = <Fr as PrimeField>::Params::TWO_ADICITY as usize;
        for _ in log_degree_size..two_adicity {
            root_of_unity.square_in_place();
        }

        // Assert that the evaluation for the root of unity are correct.
        assert_eq!(evaluations.evals[1], polynomial.evaluate(root_of_unity));

        let evaluation_index = num_degrees-1;
        let root_of_unity = root_of_unity.pow(&[evaluation_index as u64]);
        assert_eq!(evaluations.evals[evaluation_index], polynomial.evaluate(root_of_unity));
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
        assert!(result.is_ok(), result.unwrap_err());

        assert!(hashmap.polynomials[0].commitment.is_some());

        let result = hashmap.get_commitment(0);
        assert!(result.is_ok());

        let c1 = result.unwrap();

        // Add an additional point
        assert!(hashmap.insert(&[4], &[4]).is_ok());

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.unwrap_err());

        let result = hashmap.get_commitment(0);
        assert!(result.is_ok());

        let c2 = result.unwrap();

        // Assert that a new commitment was grenerated.
        assert_ne!(c1, c2);

        // Check that the commitment is unchanged when an existing k/v pair is inserted.
        assert!(hashmap.insert(&[1], &[1]).is_ok());

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.unwrap_err());

        let c3 = hashmap.get_commitment(0).unwrap();

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
