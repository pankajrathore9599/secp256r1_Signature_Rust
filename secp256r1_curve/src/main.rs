use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}};
use p256::ecdsa::Signature;
use rand::rngs::OsRng;
use rand::Rng;
use p256::EncodedPoint;
use bs58;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use bincode;


#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    id: String, // Now id is a base58 key
    sender: String,
    receiver: String,
    amount: u64,
}

fn generate_keypair() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

fn derive_public_key(signing_key: &SigningKey) -> VerifyingKey {
    VerifyingKey::from(signing_key)
}

fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Result<Signature, &'static str> {
    signing_key.try_sign(message).map_err(|_| "signature failed")
}

fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

fn verify_transaction_signature(public_key: &VerifyingKey, signature: &Signature, transaction: &Transaction) -> Result<(), &'static str> {
    let encoded_transaction = encode_transaction(&transaction);
    if verify_signature(public_key, &encoded_transaction, signature) {
        Ok(())
    } else {
        Err("Invalid signature")
    }
}

fn print_key_info(owner: &str, signing_key: &SigningKey) {
    println!("{}'s Signing Key: {}", owner, bs58::encode(signing_key.to_bytes()).into_string());

    let verifying_key = derive_public_key(&signing_key);
    println!("{}'s Verifying Key: {}", owner, bs58::encode(EncodedPoint::from(&verifying_key).to_bytes()).into_string());

    let message = format!("Hello, {}!", owner).into_bytes();

    if let Ok(signature) = sign_message(&signing_key, &message) {
        println!("{}'s Signature: {}", owner, bs58::encode(signature.to_bytes()).into_string());
        if verify_signature(&verifying_key, &message, &signature) {
            println!("{}'s Signature is valid!", owner);
        } else {
            println!("{}'s Signature is invalid!", owner);
        }
    } else {
        println!("{}'s Signature generation failed!", owner);
    }
}

fn encode_transaction(transaction: &Transaction) -> Vec<u8> {
    bincode::serialize(transaction).expect("Transaction serialization failed")
}

fn generate_base58_id() -> String {
    let mut rng = rand::thread_rng();
    let id: [u8; 32] = rng.gen();  // Generate a random 32-byte array
    bs58::encode(id).into_string() // Encode the byte array as a base58 string
}

fn main() {
    let mut wallet: HashMap<String, SigningKey> = HashMap::new();

    wallet.insert("Alice".to_string(), generate_keypair());
    wallet.insert("Bob".to_string(), generate_keypair());

    for (owner, signing_key) in &wallet {
        print_key_info(owner, signing_key);
    }

    let transaction = Transaction {
        id: generate_base58_id(), // Now id is a base58 key
        sender: "Alice".to_string(),
        receiver: "Bob".to_string(),
        amount: 100,
    };

    let encoded_transaction = encode_transaction(&transaction);
    if let Ok(signature) = sign_message(&wallet["Alice"], &encoded_transaction) {
        let public_key = derive_public_key(&wallet["Alice"]);
        if let Err(err) = verify_transaction_signature(&public_key, &signature, &transaction) {
            println!("Transaction signature verification failed: {}", err);
        } else {
            println!("Transaction signature is valid!");
        }
    } else {
        println!("Failed to sign the transaction!");
    }
}

#[cfg(test)]
mod secp256r1_tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let signing_key = generate_keypair();
        assert_eq!(signing_key.to_bytes().len(), 32);  // secp256r1 signing key should be 32 bytes
    }

    #[test]
    fn test_derive_public_key() {
        let signing_key = generate_keypair();
        let derived_public_key = derive_public_key(&signing_key);
        let public_key_bytes = EncodedPoint::from(&derived_public_key).to_bytes();
        assert_eq!(public_key_bytes.len(), 65);  // secp256r1 compressed public key should be 65 bytes
    }

    #[test]
    fn test_sign_and_verify_message() {
        let signing_key = generate_keypair();
        let message = b"test message";
        if let Ok(signature) = sign_message(&signing_key, message) {
            let verifying_key = derive_public_key(&signing_key);
            assert!(verify_signature(&verifying_key, message, &signature));
        } else {
            panic!("Failed to sign the message!");
        }
    }

    #[test]
    fn test_encode_transaction() {
        let transaction = Transaction {
            id: generate_base58_id(),
            sender: "Alice".to_string(),
            receiver: "Bob".to_string(),
            amount: 100,
        };
        let encoded_transaction = encode_transaction(&transaction);
        let decoded_transaction: Transaction = bincode::deserialize(&encoded_transaction).unwrap();
        assert_eq!(transaction.sender, decoded_transaction.sender);
        assert_eq!(transaction.receiver, decoded_transaction.receiver);
        assert_eq!(transaction.amount, decoded_transaction.amount);
    }

    #[test]
    fn test_verify_transaction_signature_valid() {
        let signing_key = generate_keypair();
        let public_key = derive_public_key(&signing_key);

        let transaction = Transaction {
            id: generate_base58_id(),
            sender: "Alice".to_string(),
            receiver: "Bob".to_string(),
            amount: 100,
        };

        let encoded_transaction = encode_transaction(&transaction);
        if let Ok(signature) = sign_message(&signing_key, &encoded_transaction) {
            assert!(verify_transaction_signature(&public_key, &signature, &transaction).is_ok());
        } else {
            panic!("Failed to sign the transaction!");
        }
    }

    #[test]
    fn test_verify_transaction_signature_invalid() {
        let signing_key = generate_keypair();
        let public_key = derive_public_key(&signing_key);

        let transaction1 = Transaction {
            id: generate_base58_id(),
            sender: "Alice".to_string(),
            receiver: "Bob".to_string(),
            amount: 100,
        };

        let transaction2 = Transaction {
            id: generate_base58_id(),
            sender: "Alice".to_string(),
            receiver: "Bob".to_string(),
            amount: 200,
        };

        let encoded_transaction1 = encode_transaction(&transaction1);
        let encoded_transaction2 = encode_transaction(&transaction2);
        if let Ok(signature) = sign_message(&signing_key, &encoded_transaction1) {
            // Verify the signature with a different transaction
            assert!(verify_transaction_signature(&public_key, &signature, &transaction2).is_err());
        } else {
            panic!("Failed to sign the transaction!");
        }
    }
}
