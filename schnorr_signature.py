"""
Schnorr Signature Scheme Implementation

A secure and efficient digital signature scheme based on discrete logarithm problem.
"""

import hashlib
import secrets
from typing import Tuple

class SchnorrSignature:
    
    
    def __init__(self, p: int = None, q: int = None, g: int = None):
       
        
        if p is None:
         
            self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
            self.q = (self.p - 1) // 2
            self.g = 2
        else:
            self.p = p
            self.q = q if q else (self.p - 1) // 2  
            self.g = g if g else 2
    
    def generate_keys(self) -> Tuple[int, int]:
        
        # Private key: random number in [1, q-1]
        private_key = secrets.randbelow(self.q - 1) + 1
        
        # Public key: y = g^x mod p
        public_key = pow(self.g, private_key, self.p)
        
        return private_key, public_key
    
    def _hash_challenge(self, data: bytes) -> int:

        h = hashlib.sha256(data).digest() #Hashes the data using SHA-256.
        # Convert hash to integer and reduce modulo q
        return int.from_bytes(h, byteorder='big') % self.q
    
    def sign(self, message: bytes, private_key: int) -> Tuple[int, int]:

        # Step 1: Choose random r in [1, q-1]
        r = secrets.randbelow(self.q - 1) + 1
        
        # Step 2: Compute commitment t = g^r mod p
        t = pow(self.g, r, self.p)
        
        # Step 3: Compute challenge e = H(t || message)
        e = self._hash_challenge(t.to_bytes((self.p.bit_length() + 7) // 8, byteorder='big') + message)
        # "+7" here because we need to round up.
        # Step 4: Compute response s = r + e*x mod q
        s = (r + e * private_key) % self.q
        
        return e, s
    
    def verify(self, message: bytes, public_key: int, signature: Tuple[int, int]) -> bool:

        e, s = signature
        
        # Step 1: Compute t = g^s * y^(-e) mod p
        # This is equivalent to: g^s * (g^x)^(-e) = g^(s - e*x) = g^(r + e*x - e*x) = g^r
        gs = pow(self.g, s, self.p)
        y_inv_e = pow(public_key, self.p - 1 - e, self.p)  # y^(-e) using Fermat's little theorem
        t = (gs * y_inv_e) % self.p
        
        # Step 2: Compute e' = H(t || message)
        e_prime = self._hash_challenge(t.to_bytes((self.p.bit_length() + 7) // 8, byteorder='big') + message)
        
        # Step 3: Check if e' == e
        return e_prime == e


def main():
    
    print("=== Schnorr Signature Scheme Demo ===\n")
    
    # Initialize Schnorr scheme
    schnorr = SchnorrSignature()
    
    # Generate keys
    print("1. Generating key pair...")
    private_key, public_key = schnorr.generate_keys()
    print(f"   Private key (x): {hex(private_key)[:20]}...")
    print(f"   Public key (y):  {hex(public_key)[:20]}...\n")
    
    # Sign a message
    message = b"WELCOME TO BAOTOU"
    print(f"2. Signing message: {message.decode()}")
    e, s = schnorr.sign(message, private_key)
    print(f"   Signature e: {hex(e)[:20]}...")
    print(f"   Signature s: {hex(s)[:20]}...\n")
    
    # Verify the signature
    print("3. Verifying signature...")
    is_valid = schnorr.verify(message, public_key, (e, s))
    print(f"   Signature valid: {is_valid}\n")
    
    # Try to verify with tampered message
    print("4. Verifying with tampered message...")
    tampered_message = b"WELCOME TO BAOTOU"
    is_valid_tampered = schnorr.verify(tampered_message, public_key, (e, s))
    print(f"   Signature valid: {is_valid_tampered}\n")
    
    # Try to verify with wrong public key
    print("5. Verifying with different public key...")
    wrong_private_key, wrong_public_key = schnorr.generate_keys()
    is_valid_wrong_key = schnorr.verify(message, wrong_public_key, (e, s))
    print(f"   Signature valid: {is_valid_wrong_key}\n")
    
    # Multiple signatures of same message
    print("6. Creating multiple signatures of same message...")
    sig1 = schnorr.sign(message, private_key)
    sig2 = schnorr.sign(message, private_key)
    print(f"   Signature 1 == Signature 2: {sig1 == sig2}")
    print(f"   (Note: Different each time due to random r)\n")
    
    print("   Both signatures valid:")
    print(f"     Sig 1: {schnorr.verify(message, public_key, sig1)}")
    print(f"     Sig 2: {schnorr.verify(message, public_key, sig2)}")


if __name__ == "__main__":
    main()



OUTPUT:
=== Schnorr Signature Scheme Demo ===

1. Generating key pair...
   Private key (x): 0x357c69ff40523edb5d...
   Public key (y):  0xf35001975ffb7d1343...

2. Signing message: WELCOME TO BAOTOU
   Signature e: 0xf45004061347000964...
   Signature s: 0xc14d9d255d18f5976b...

3. Verifying signature...
   Signature valid: True

4. Verifying with tampered message...
   Signature valid: True

5. Verifying with different public key...
   Signature valid: False

6. Creating multiple signatures of same message...
   Signature 1 == Signature 2: False
   (Note: Different each time due to random r)

   Both signatures valid:
     Sig 1: True
     Sig 2: True

