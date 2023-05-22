# secp256r1_Signature_Rust
In this repo I am implementing couple of "secp256r1' signature scheme funcctionalities.

# Implementation Lists
1. Develop the secp256r1 signature scheme to generate and authenticate digital signatures.
2. Craft a function that transforms a private key into a public key, to be utilized for transaction signing.
3. Construct a function that generates a unique private key for every wallet owner.
4. Formulate a function to encode transaction data, aiding in signature verification.
5. Incorporate unit tests for both the secp256r1 signature scheme and the encoding function.
6. Create a function that verifies a transaction's signature, encompassing the transaction ID, public key, and the signature itself.
7. Introduce error handling mechanisms for cases of invalid signatures and public keys.
8. Develop comprehensive tests for the signature verification function, which should consider edge cases and scenarios with invalid inputs.
9. Construct a function that validates the wallet policy prior to sanctioning a transaction. This should take into account the number of necessary        signatures and the list of owners.
10. Integrate unit tests for the wallet policy validation function, covering edge cases and scenarios with invalid inputs.
