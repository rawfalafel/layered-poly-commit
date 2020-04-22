use algebra_core::curves::PairingEngine;
use ff_fft::domain::EvaluationDomain;
use ff_fft::evaluations::Evaluations;
use ff_fft::polynomial::DensePolynomial;
use poly_commit::kzg10::{Commitment, UniversalParams, VerifierKey, Powers};
use num_traits::Zero;
use std::borrow::Cow;

use crate::error::Error;

#[derive(Debug)]
pub struct Layer<E: PairingEngine> {
    pub evaluations: Evaluations<E::Fr>,
    pub coefficients: Option<DensePolynomial<E::Fr>>,
    pub commitment: Option<Commitment<E>>,
    pub params: UniversalParams<E>,
    pub dirty: bool
}

impl <E: PairingEngine> Layer<E> {
    pub fn new(params: UniversalParams<E>, num_coeffs: usize) -> Result<Layer<E>, Error> {
        let domain = EvaluationDomain::new(num_coeffs)?;
        let evaluations = Evaluations::from_vec_and_domain(vec!{E::Fr::zero(); num_coeffs}, domain);

        Ok(Layer {
            evaluations,
            coefficients: None,
            commitment: None,
            params: params,
            dirty: false
        })
    }

    pub fn update_commitment(&mut self, commitment: Commitment<E>, coefficients: DensePolynomial<E::Fr>) {
        self.commitment = Some(commitment);
        self.coefficients = Some(coefficients);
        self.dirty = false;
    }

    pub fn has_value(&self, point: usize) -> bool {
        self.evaluations.evals[point] != E::Fr::zero()
    }

    pub fn set_value(&mut self, point: usize, value: E::Fr) {
        self.evaluations.evals[point] = value;
        self.dirty = true;
    }

    pub fn interpolate(&self) -> DensePolynomial<E::Fr> {
        self.evaluations.interpolate_by_ref()
    }

    pub fn clear(&mut self) {
        let num_coeffs = self.evaluations.evals.len();
        self.evaluations.evals = vec!{E::Fr::zero(); num_coeffs};
        self.coefficients = None;
        self.commitment = None;
        self.dirty = false;
    }

    pub fn get_powers(&self) -> Powers<E> {
        Powers::<E> {
            powers_of_g: Cow::Borrowed(&self.params.powers_of_g),
            powers_of_gamma_g: Cow::Borrowed(&self.params.powers_of_gamma_g)
        }
    }

    pub fn get_verifier_key(&self) -> VerifierKey<E> {
        VerifierKey {
            g: self.params.powers_of_g[0],
            gamma_g: self.params.powers_of_gamma_g[0],
            h: self.params.h,
            beta_h: self.params.beta_h,
            prepared_h: self.params.prepared_h.clone(),
            prepared_beta_h: self.params.prepared_beta_h.clone()
        }
    }
}