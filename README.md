# layered-poly-commit

This repository contains a prototype for [Multi-layer hashmaps using polynomial commitments](https://ethresear.ch/t/multi-layer-hashmaps-for-state-storage/). The prototype largely relies on https://github.com/scipr-lab/poly-commit and https://github.com/scipr-lab/zexe for lower level operations such as generating and opening polynomial commitments. 

**Build note:** This library only supports the _nightly_ Rust compiler.

## Features
This hashmap can:
 - Setup a series of parameters corresponding to each layer in the "multi-layer hashmap" scheme. 
 - Insert key/value pairs, where both the key and value are byte strings of arbitrary length.
 - Create a commitment for each non-empty polynomial.
 - Generate a proof for a single key/value pair.
 - Verify the proof for a single key/value pair.
 
This does **not** support:
 - Generating batch proofs for multiple key/value pairs.
 - Efficient generation of proofs such as [Fast amortized Kate proofs](https://github.com/khovratovich/Kate/blob/f4e54722f27d6f918c7b6c6d7c7614e3dbfa4c25/Kate_amortized.pdf).

## Example
Test the hashmap by running the provided example:
`cargo run --example fill-layers --release`
