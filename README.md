# Encryption System

This project implements a secure encryption system that integrates AES, RSA, and ECC for achieving confidentiality, integrity, and non-repudiation.

## Features

- **AES** for fast and authenticated encryption of sensitive data.
- **RSA** for secure key exchange.
- **ECC** as an alternative key exchange mechanism for resource-constrained environments.
- **Digital Signatures** for verifying data integrity and the sender's authenticity.

## Workflow Overview

### Encryption Process

1. **Generate AES Key**: A 256-bit AES symmetric key is randomly generated.
2. **Encrypt Data**:
   - Data is encrypted using AES in OCB mode.
   - A unique nonce is generated for each encryption operation.
   - An authentication tag is produced to verify data integrity.
3. **Encrypt AES Key**:
   - The AES key is encrypted using the recipient's (RSA) public key.
4. **Sign Data**:
   - The encrypted data (or its hash) is signed using the sender's private (ECC) key.
5. **Package Transmission**:
   - The encrypted data, authentication tag, nonce, encrypted AES key, and digital signature are bundled together for transmission.

### Decryption Process

1. **Verify Digital Signature**:
   - The sender's public key (ECC) is used to verify the signature.
   - Ensures data integrity and authenticity.
2. **Decrypt AES Key**:
   - The recipient's private key (RSA) is used to decrypt the AES key.
3. **Decrypt Data**:
   - The decrypted AES key and nonce are used to decrypt the encrypted data.
   - The authentication tag is verified to ensure data integrity.

### Data Structure for Transmission

```json
{
  "encrypted_data": "<AES-OCB encrypted data>",
  "tag": "<Authentication tag>",
  "nonce": "<Nonce value>",
  "encrypted_key": "<RSA encrypted AES key>",
  "signature": "<Digital signature>",
  "sender_public_key": "<Optional: Sender's public key>"
}
```

## Implementation Details

### AES (OCB Mode)

- **Key Length**: 256 bits
- **Nonce Length**: 15 bytes
- **Tag Length**: 16 bytes (default)
- **Mode**: OCB (provides encryption and authentication in a single step)

### RSA

- **Key Length**: 3072 bits
- **Padding Scheme**: OAEP (Optimal Asymmetric Encryption Padding)

### ECC

- **Curve**: secp256r1 (NIST P-256)
- **Key Exchange**: ECDH (Elliptic Curve Diffie-Hellman)

### Digital Signature

- **Algorithm**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Hash Function**: SHA-256
