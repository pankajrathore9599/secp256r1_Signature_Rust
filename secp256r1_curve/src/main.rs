use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}};
use p256::ecdsa::Signature;
use rand::rngs::OsRng;
use p256::EncodedPoint;
use bs58;

fn generate_keypair() -> SigningKey {
    // Generate a random signing key
    SigningKey::random(&mut OsRng)
}

fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
    // Sign a message
    signing_key.try_sign(message).expect("signature failed")
}

fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    // Verify the signature of a message
    verifying_key.verify(message, signature).is_ok()
}

fn main() {
    let signing_key = generate_keypair();
    println!("Signing Key: {}", bs58::encode(signing_key.to_bytes()).into_string());

    let verifying_key = VerifyingKey::from(&signing_key);
    println!("Verifying Key: {}", bs58::encode(EncodedPoint::from(&verifying_key).to_bytes()).into_string());

    let message = b"Hello, world!";

    let signature = sign_message(&signing_key, message);
    println!("Signature: {}", bs58::encode(signature.to_bytes()).into_string());

    assert!(verify_signature(&verifying_key, message, &signature));

    println!("Signature is valid!");
}
