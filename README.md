# An-Independent-Study-of-Schnorr-s-Signature

## Schnorr Signature Scheme in Python

A simple implementation of a Schnorr-style digital signature scheme in Python.

This project is designed for studying the zero-knowledge proof (ZKP) protocols, as well as the mathematics behind it.

This project demonstrates:

- key generation
- message signing
- signature verification
- invalid signature tests
- optional use of custom `(p, q, g)` parameters
- optional reuse of DSA-generated parameters


# Quick Start
## Basic Usage
```
from schnorr_signature import SchnorrSignature
from cryptography.hazmat.primitives.asymmetric import dsa

# Generate cryptographically secure DSA parameters (2048-bit)
parameters = dsa.generate_parameters(key_size=2048)
p = parameters.parameter_numbers().p
q = parameters.parameter_numbers().q
g = parameters.parameter_numbers().g

# Create Schnorr instance with DSA parameters
schnorr = SchnorrSignature(custom_params={'p': p, 'q': q, 'g': g})

# Generate key pair
private_key, public_key = schnorr.generate_keys()

# Sign a message
message = b"Your message here"
signature = schnorr.sign(message, private_key)

# Verify the signature
is_valid = schnorr.verify(message, public_key, signature)
print(f"Signature valid: {is_valid}")  # True

```

# How it Works?

## Key Generation
 - Choose random private key $x \in \[1, q-1\]$
 - Compute public $ y =  g^x \bmod p$
## Signing
 - Choose random $r \in \[1, q-1\]$
 - Compute commitment $t = g^r \bmod p$
 - Compute challenge $e = H(t \mid\mid message)$
 - Compute response $s = r + e·x \bmod q$
 - Signature: $(e, s)$
## Verification
 - Compute $t = g^s · y^{(-e)} \bmod p$
 - Compute $e' = H(t \mid\mid message)$
 - Accept if $e' == e$


# Potential Security Issues
- Parameters: Always use parameters from established standards or cryptographically secure generation methods, such as the random number generators (RNG).
- Hash Function: Uses SHA-256 for challenge computation.
- Testing Only: Small parameters (less than 5-bit) are for educational purposes only; use 1024+ bit parameters for production


