use algebra::Field;
use algebra_core::{
    curves::PairingEngine,
    fields::{FpParameters,FftField,PrimeField},
    biginteger::BigInteger
};
use crypto::sha3::Sha3;
use crypto::digest::Digest;
use num_bigint::{BigInt,Sign};
use num_traits::{ToPrimitive,Zero};
use poly_commit::{
    PCRandomness,
    kzg10::{KZG10, Randomness, Commitment, Proof}
};
use rand_core::RngCore;

use crate::layer::Layer;
use crate::error::Error;

#[derive(Debug)]
pub struct LayeredPolyCommit<E: PairingEngine> {
    pub layers: Vec<Layer<E>>,
    num_degrees: usize,
    pub precomputes: Precomputes<E>
}

#[derive(Debug)]
pub struct Precomputes<E: PairingEngine> {
    root_of_unity: E::Fr,
    fr_modulus: BigInt,
    mask_0: BigInt,
    mask_1: BigInt
}

impl<E: PairingEngine> LayeredPolyCommit<E> {
    // Generate a vector of polynomials of degree n.
    pub fn setup<R: RngCore>(num_degree: usize, num_poly: usize, rng: &mut R) -> Result<LayeredPolyCommit<E>, Error> {
        if num_degree != num_degree.next_power_of_two() {
            return Err(Error::SetupInvalidDegree(num_degree));
        }

        let layers = (0..num_poly).map(|_| {
            let params = KZG10::setup(num_degree, false, rng)?;
            Layer::new(params, num_degree)
        }).collect::<Result<Vec<Layer<E>>, Error>>()?;

        Ok(LayeredPolyCommit{
            layers,
            num_degrees: num_degree,
            precomputes: Self::generate_precomputes(num_degree)?
        })
    }

    fn generate_precomputes(num_degree: usize) -> Result<Precomputes<E>, Error> {
        let root_of_unity = <E::Fr>::get_root_of_unity(num_degree)?;

        let fr_modulus = <E::Fr as PrimeField>::Params::MODULUS;
        let mut fr_modulus_bytes = vec!{0u8; 32};
        fr_modulus.write_le(&mut fr_modulus_bytes)?;
        let fr_modulus = BigInt::from_bytes_le(Sign::Plus, &fr_modulus_bytes);

        let repr_shave_bits = <E::Fr as PrimeField>::Params::REPR_SHAVE_BITS as usize;
        let mask = BigInt::from_bytes_le(Sign::Plus, &[0xff; 32]);
        let mask_0 = &mask >> repr_shave_bits;
        let mask_1 = &mask >> repr_shave_bits + 1;

        Ok(Precomputes::<E> {
            root_of_unity,
            fr_modulus,
            mask_0,
            mask_1
        })
    }

    // Inserts `hash(k, v)` as the value.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        // Find the first polynomial in which `hash(k, i)` is empty
        for (i, layer) in self.layers.iter_mut().enumerate() {
            let point = Self::construct_map_key(key, i as u8, &self.precomputes, self.num_degrees)?;

            if layer.has_value(point) {
                continue;
            }

            let poly_y = Self::construct_map_value(key, value)?;

            layer.set_value(point, poly_y);
            return Ok(());
        }

        Err(Error::EmptyLayerNotFound(key.to_vec()))
    }

    // Update commitment for polynomials since last UpdateCommitment call.
    pub fn update_commitment(&mut self) -> Result<(), Error> {
        let mut updates = vec!{};

        for (i, layer) in self.layers.iter().enumerate() {
            if layer.dirty == false {
                continue;
            }

            let coefficients = layer.interpolate();

            let powers = layer.get_powers();
            let result = KZG10::commit(&powers, &coefficients, None, None)?;
            let commitment: Commitment<E> = result.0;
            updates.push((i, coefficients, commitment));
        }

        for (i, coefficients, commitment) in updates {
            self.layers[i].update_commitment(commitment, coefficients);
        }

        Ok(())
    }

    // Generate a witness for a given key
    pub fn open(&self, key: &[u8], value: &[u8]) -> Result<Proof<E>, Error> {
        // First, calculate the field representation of the value stored.
        let poly_y = Self::construct_map_value(key, value)?;

        for (i, layer) in self.layers.iter().enumerate() {
            if layer.dirty == true {
                return Err(Error::CommitmentInvalid);
            }

            let point = Self::construct_map_key(key, i as u8, &self.precomputes, self.num_degrees)?;

            if layer.evaluations.evals[point] == E::Fr::zero() {
                continue;
            }

            if layer.evaluations.evals[point] != poly_y {
                continue;
            }

            let powers = layer.get_powers();
            let coefficients = layer.coefficients.as_ref().unwrap();
            let point = Self::point_to_root_of_unity(self.precomputes.root_of_unity, point);
            let rand = Randomness::<E>::empty();

            return Ok(KZG10::open(&powers, coefficients, point, &rand)?);
        }

        Err(Error::KeyNotFound(key.to_vec()))
    }

    // Verify that a given witness is valid.
    pub fn verify(&self, key: &[u8], value: &[u8], proof: Proof<E>) -> Result<(), Error> {
        for (i, layer) in self.layers.iter().enumerate() {
            let point = Self::construct_map_key(key, i as u8, &self.precomputes, self.num_degrees)?;
            if !layer.has_value(point) {
                continue;
            }

            if layer.dirty || layer.commitment.is_none() {
                return Err(Error::CommitmentInvalid);
            }

            let vk = layer.get_verifier_key();
            let commitment = layer.commitment.unwrap();
            let point = Self::point_to_root_of_unity(self.precomputes.root_of_unity, point);
            let poly_y = Self::construct_map_value(key, value)?;

            let valid = KZG10::check(&vk, &commitment, point, poly_y, &proof)?;
            if valid {
                return Ok(());
            } else {
                return Err(Error::InvalidProof);
            }
        }

        Err(Error::KeyNotFound(key.to_vec()))
    }

    pub fn clear_layers(&mut self) {
        for layer in self.layers.iter_mut() {
            layer.clear();
        }
    }

    pub(crate) fn bytes_to_evaluation_point(bytes: &[u8], precomputes: &Precomputes<E>, modulus: usize) -> Result<usize, Error> {
        let field_element_bigint = BigInt::from_bytes_le(Sign::Plus, bytes);
        let mut field_element_bigint = field_element_bigint & &precomputes.mask_0;

        if field_element_bigint > precomputes.fr_modulus {
            field_element_bigint &= &precomputes.mask_1;
        }

        let point = field_element_bigint % modulus;

        Ok(point.to_usize()?)
    }

    fn point_to_root_of_unity(root_of_unity: E::Fr, point: usize) -> E::Fr {
        root_of_unity.pow(&[point as u64])
    }

    fn construct_map_key(key: &[u8], index: u8, precomputes: &Precomputes<E>, modulus: usize) -> Result<usize, Error> {
        let mut hasher = Sha3::sha3_256();
        let mut digest = [0; 32];

        hasher.input(key);
        hasher.input(&[index]);
        hasher.result(&mut digest);

        Ok(Self::bytes_to_evaluation_point(&digest, precomputes, modulus)?)
    }

    fn construct_map_value(key: &[u8], value: &[u8]) -> Result<E::Fr, Error> {
        let mut hasher = Sha3::sha3_256();
        let mut digest = [0; 32];

        hasher.input(key);
        hasher.input(value);
        hasher.result(&mut digest);

        match <E::Fr>::from_random_bytes(&digest) {
            Some(field_element) => Ok(field_element),
            None => Err(Error::BytesNotValidFieldElement)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LayeredPolyCommit,Error};

    use algebra::Bls12_381;
    use algebra::bls12_381::Fr;
    use algebra_core::curves::PairingEngine;
    use algebra_core::fields::{FftField, Field};
    use crypto::sha3::Sha3;
    use crypto::digest::Digest;
    use ff_fft::domain::{EvaluationDomain,Radix2EvaluationDomain};
    use ff_fft::evaluations::Evaluations;
    use num_traits::pow;
    use num_traits::identities::One;
    use rand_core::SeedableRng;
    use rand_pcg::Pcg32;
    use num_bigint::{BigInt,Sign};

    type LayeredPolyCommitBls12_381 = LayeredPolyCommit<Bls12_381>;

    fn setup(max_degree: usize, num_poly: usize) -> Result<LayeredPolyCommitBls12_381, Error> {
        let seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut rng = Pcg32::from_seed(seed);
        LayeredPolyCommitBls12_381::setup(max_degree, num_poly, &mut rng)
    }

    #[test]
    fn test_setup() {
        let result = setup(8, 5);

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
        let num_degrees = 128;
        let input = [0xff; 32];

        let hashmap = setup(num_degrees, 1).unwrap();

        let result = LayeredPolyCommitBls12_381::bytes_to_evaluation_point(&input, &hashmap.precomputes, num_degrees);
        assert!(result.is_ok());

        let point = result.unwrap();
        assert!(point < num_degrees);
    }

    #[test]
    fn test_open_commitment() {
        // Setup
        let mut hashmap = setup(128, 3).unwrap();

        // Insert three key/value pairs
        assert!(hashmap.insert(&[1], &[1]).is_ok());

        // Generate commitment
        assert!(hashmap.update_commitment().is_ok());

        // Open witness
        let result = hashmap.open(&[1], &[1]);
        assert!(result.is_ok(), format!{"{:?}", result.err()});

        // Attempt to open witness for a point without an evaluation
        let result = hashmap.open(&[1], &[100]);
        assert!(result.is_err(), format!{"{:?}", result.ok()});

        // Attempt to open witness for a non-existing point
        assert!(hashmap.open(&[4], &[4]).is_err());
    }

    #[test]
    fn test_verify_proof() {
        let mut hashmap = setup(128, 3).unwrap();

        assert!(hashmap.insert(&[1], &[1]).is_ok());
        assert!(hashmap.insert(&[2], &[2]).is_ok());
        assert!(hashmap.insert(&[3], &[3]).is_ok());

        assert!(hashmap.update_commitment().is_ok());

        let result = hashmap.open(&[1], &[1]);
        assert!(result.is_ok());

        let proof = result.unwrap();

        let result = hashmap.verify(&[1], &[1], proof);
        assert!(result.is_ok());

        let result = hashmap.open(&[2], &[2]);
        assert!(result.is_ok());

        let proof = result.unwrap();

        let result = hashmap.verify(&[2], &[2], proof);
        assert!(result.is_ok());

        let result = hashmap.verify(&[1], &[2], proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_ifft() {
        let log_degree_size = 5;
        let num_degrees = pow(2, log_degree_size);

        let domain = Radix2EvaluationDomain::<Fr>::new(num_degrees).unwrap();
        let mut evaluations = Evaluations::from_vec_and_domain(vec!{}, domain);

        let mut hasher = Sha3::sha3_256();
        let mut digest = vec!{0; 32};

        for i in 0..num_degrees {
            hasher.input(&[i as u8]);
            hasher.result(&mut digest);

            // Flip higher bits to avoid generating an invalid (i.e. greater than Fr::MODULUS) bytestring
            digest[31] &= 0x0f;
            hasher.reset();

            let k = Fr::from_random_bytes(&digest).unwrap();
            evaluations.evals.push(k);
        }

        let polynomial = evaluations.interpolate_by_ref();
        println!("{:?}", polynomial);

        // Assert that the evaluation for 0th power of the root of unity is correct.
        assert_eq!(evaluations.evals[0], polynomial.evaluate(Fr::one()));

        let root_of_unity = Fr::get_root_of_unity(num_degrees).unwrap();

        // Assert that the evaluation for the root of unity are correct.
        assert_eq!(evaluations.evals[1], polynomial.evaluate(root_of_unity));

        let evaluation_index = num_degrees-1;
        let root_of_unity = root_of_unity.pow(&[evaluation_index as u64]);
        assert_eq!(evaluations.evals[evaluation_index], polynomial.evaluate(root_of_unity));
    }

    #[test]
    fn test_commitment() {
        let mut hashmap = setup(128, 3).unwrap();

        assert!(hashmap.layers[0].commitment.is_none());

        // Insert initial set of points
        assert!(hashmap.insert(&[1], &[1]).is_ok());
        assert!(hashmap.insert(&[2], &[2]).is_ok());
        assert!(hashmap.insert(&[3], &[3]).is_ok());

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.unwrap_err());

        assert!(hashmap.layers[0].commitment.is_some());

        let commitment = hashmap.layers[0].commitment;
        assert!(commitment.is_some());

        let c1 = commitment.unwrap();

        // Add an additional point
        let result = hashmap.insert(&[4], &[4]);
        assert!(result.is_ok(), format!{"{:?}", result});

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.unwrap_err());

        let commitment = hashmap.layers[0].commitment;
        assert!(commitment.is_some());

        let c2 = commitment.unwrap();

        // Assert that a new commitment was grenerated.
        assert_ne!(c1, c2);

        // Check that the commitment is unchanged when an existing k/v pair is inserted.
        assert!(hashmap.insert(&[1], &[1]).is_ok());

        let result = hashmap.update_commitment();
        assert!(result.is_ok(), result.unwrap_err());

        let c3 = hashmap.layers[0].commitment.unwrap();

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