

// TODO: Update the name of the method loaded by the prover. E.g., if the method
// is `multiply`, replace `METHOD_NAME_ELF` with `MULTIPLY_ELF` and replace


// use methods::{METHOD_NAME_ELF, METHOD_NAME_ID};
// use risc0_zkvm::{
//     default_prover,
//     ExecutorEnv,
//     serde::{from_slice, to_vec},
// };
// use k256::{
//     ecdsa::{signature::Signer, Signature},
//     EncodedPoint, SigningKey, VerifyingKey,
// };

// fn main() {
//     let message = b"Hello, world!"; // Example message
//     let signing_key = SigningKey::random(); // Example random signing key
//     let verifying_key = VerifyingKey::from(&signing_key);
//     let signature = signing_key.sign(message);

//     let encoded_verifying_key = verifying_key.to_encoded_point(false);

//     let env = ExecutorEnv::builder()
//         .add_input(&to_vec(&encoded_verifying_key).unwrap())
//         .add_input(&to_vec(&message).unwrap())
//         .add_input(&to_vec(&signature).unwrap())
//         .build()
//         .unwrap();

//     let prover = default_prover();
//     let receipt = prover.prove_elf(env, METHOD_NAME_ELF).unwrap(); // Assuming the guest program is compiled to "ecdsa_verify.elf"
//     receipt.verify(METHOD_NAME_ID).unwrap();

//     // Extract journal of receipt
//     let (returned_verifying_key, returned_message): (EncodedPoint, Vec<u8>) = from_slice(&receipt.journal).unwrap();

//     assert_eq!(returned_verifying_key, encoded_verifying_key, "Verifying keys mismatch!");
//     assert_eq!(returned_message, message, "Messages mismatch!");

//     println!("Signature verification succeeded for message: {}", String::from_utf8_lossy(&returned_message));
// }

use methods::{METHOD_NAME_ELF, METHOD_NAME_ID};
use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use risc0_zkvm::{
    default_prover,
    serde::{from_slice, to_vec},
    ExecutorEnv, Receipt,
};
use rand_core::OsRng;

/// Given an secp256k1 verifier key (i.e. public key), message and signature,
/// runs the ECDSA verifier inside the zkVM and returns a receipt, including a
/// journal and seal attesting to the fact that the prover knows a valid
/// signature from the committed public key over the committed message.
fn prove_ecdsa_verification(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Receipt {
    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&(verifying_key.to_encoded_point(true), message, signature)).unwrap())
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    prover.prove_elf(env, METHOD_NAME_ELF).unwrap()
}

fn main() {
    // Generate a random secp256k1 keypair and sign the message.
    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
    let message = b"This is a message that will be signed, and verified within the zkVM";
    let signature: Signature = signing_key.sign(message);

    // Run signature verified in the zkVM guest and get the resulting receipt.
    let receipt = prove_ecdsa_verification(signing_key.verifying_key(), message, &signature);

    // Verify the receipt and then access the journal.
    receipt.verify(METHOD_NAME_ID).unwrap();
    let (receipt_verifying_key, receipt_message) =
        from_slice::<(EncodedPoint, Vec<u8>), _>(&receipt.journal)
            .unwrap()
            .try_into()
            .unwrap();

    println!(
        "Verified the signature over message {:?} with key {}",
        std::str::from_utf8(&receipt_message[..]).unwrap(),
        receipt_verifying_key,
    );
}





























