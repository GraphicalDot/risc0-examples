
// // If you want to try std support, also update the guest Cargo.toml file
//  #![no_std]  // std support is experimental


// use risc0_zkvm::guest::env;

// risc0_zkvm::guest::entry!(main);

#![no_main]

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);


pub fn main() {
    // TODO: Implement your guest code here
    let (encoded_verifying_key, message, signature): (EncodedPoint, Vec<u8>, Signature) =
    env::read();
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&message, &signature)
        .expect("ECDSA signature verification failed");

    // Commit to the journal the verifying key and message that was signed.
    env::commit(&(encoded_verifying_key, message));

}













